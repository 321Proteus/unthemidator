#include "c_intel_disassembler.hpp"

#include <algorithm>

c_intel_disassembler::c_intel_disassembler(const std::shared_ptr<c_memory>& memory, const bool is_x64) : m_memory(memory) {
    //
    if (is_x64) {
        ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    } else {
        ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    }
}

std::shared_ptr<c_intel_function> c_intel_disassembler::disassemble(const uint32_t rva, const size_t instruction_limit) {
    const std::lock_guard decoder_guard(m_decoder_mtx);

    if (const auto &mapped_image = m_memory->get_mapped_image();
        rva >= mapped_image.size() || mapped_image[rva] == 0) {
        //
        return nullptr;
    }

    auto fn = std::make_shared<c_intel_function>();
    fn->m_start_rva = rva;

    s_walk_ctx ctx{
        .function = fn.get(),
        .rva_to_bb_index = {},
        .instruction_limit = instruction_limit,
    };

    if (!walk_basic_block(rva, ctx).has_value()) {
        return nullptr;
    }

    auto &blocks = fn->m_basic_blocks;

    std::ranges::sort(blocks, [](const c_intel_basic_block &a, const c_intel_basic_block &b) {
        return a.m_start_rva < b.m_start_rva;
    });

    // rebuild the rva->index map after sorting (indices changed).
    std::unordered_map<uint32_t, size_t> rva_to_index;
    rva_to_index.reserve(blocks.size());

    for (size_t block_id = 0; block_id < blocks.size(); ++block_id) {
        blocks[block_id].m_block_id = block_id;
        rva_to_index[blocks[block_id].m_start_rva] = block_id;
    }

    for (size_t i = 0; i + 1 < blocks.size(); ++i) {
        auto &block = blocks[i];
        const auto next_start = blocks[i + 1].m_start_rva;

        if (block.m_end_rva <= next_start) {
            continue;
        }

        block.m_end_rva = next_start;

        // drop any instructions past the new end.
        const auto it = std::ranges::find_if(block.m_instructions,
            [next_start](const c_intel_instruction &instr) {
            return instr.m_rva >= next_start;
        });

        if (it != block.m_instructions.end()) {
            block.m_instructions.erase(it, block.m_instructions.end());
            block.m_is_final = false;
        }
    }

    if (!blocks.empty() && blocks.back().m_end_rva > fn->m_start_rva) fn->m_end_rva = blocks.back().m_end_rva;

    for (size_t i = 0; i < blocks.size(); ++i) {
        auto &block = blocks[i];

        fn->m_address_to_bb_id[block.m_start_rva] = i;

        if (block.m_start_rva == fn->m_start_rva) {
            fn->m_first_bb_id = i;
        }

        if (block.m_instructions.empty()) {
            continue;
        }

        const auto &terminator = block.m_instructions.back();
        const auto category = terminator.m_instruction.meta.category;
        const auto mnemonic = terminator.m_instruction.mnemonic;
        const bool is_uncond_jump = (category == ZYDIS_CATEGORY_UNCOND_BR);
        const bool is_cond_jump = (category == ZYDIS_CATEGORY_COND_BR);

        if (block.m_is_final) {
            fn->m_final_block_ids.insert(i);

            if (!is_uncond_jump) {
                continue;
            }
        }

        if ((is_cond_jump || is_uncond_jump) && terminator.m_operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            const auto target = static_cast<uint32_t>(terminator.m_branch_target);

            if (const auto it = rva_to_index.find(target); it != rva_to_index.end()) {
                add_edge(i, it->second, *fn);
            }
        }

        if (is_uncond_jump || mnemonic == ZYDIS_MNEMONIC_RET) {
            continue;
        }

        const uint32_t fallthrough_rva = terminator.m_rva + terminator.m_instruction.length;

        if (const auto it = rva_to_index.find(fallthrough_rva); it != rva_to_index.end()) {
            add_edge(i, it->second, *fn);
        }
    }

    return fn;
}

c_intel_instruction c_intel_disassembler::disassemble_instruction(uint32_t rva) {
    const std::lock_guard decoder_guard(m_decoder_mtx);

    const auto &mapped_image = m_memory->get_mapped_image();

    ZydisDecodedInstruction instruction{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};

    auto last_status = ZydisDecoderDecodeFull(&m_decoder, mapped_image.data() + rva,
        ZYDIS_MAX_INSTRUCTION_LENGTH, &instruction, operands.data());

    if (!ZYAN_SUCCESS(last_status)) {
        throw std::runtime_error("ZydisDecoderDecodeFull() failed: "+ std::to_string(last_status));
    }

    std::vector<uint8_t> raw_bytes{};
    raw_bytes.resize(instruction.length);
    memcpy(raw_bytes.data(), mapped_image.data() + rva, raw_bytes.size());

    return c_intel_instruction(rva, instruction, operands, raw_bytes);
}

std::optional<size_t> c_intel_disassembler::walk_basic_block(const uint32_t rva, s_walk_ctx &ctx) const {
    if (const auto it = ctx.rva_to_bb_index.find(rva); it != ctx.rva_to_bb_index.end()) {
        return it->second;
    }

    const auto &mapped_image = m_memory->get_mapped_image();
    auto &blocks = ctx.function->m_basic_blocks;

    // indices of blocks that were discovered but not decoded yet
    std::vector<size_t> worklist;

    // registers a block (once per rva) and queues it for decoding,
    // the empty block is a placeholder; it is filled in when popped
    const auto discover = [&](const uint32_t start) {
        if (ctx.rva_to_bb_index.contains(start)) {
            return;
        }

        const size_t index = blocks.size();
        ctx.rva_to_bb_index[start] = index;

        c_intel_basic_block placeholder;
        placeholder.m_start_rva = start;
        placeholder.m_end_rva = start;
        blocks.push_back(std::move(placeholder));

        worklist.push_back(index);
    };

    discover(rva);

    const size_t entry_index = ctx.rva_to_bb_index[rva];
    size_t instruction_count = 0;

    while (!worklist.empty()) {
        const size_t block_index = worklist.back();
        worklist.pop_back();

        // decode into a local block. `blocks` may reallocate whenever discover()
        // is called, so no reference into it is held while decoding
        c_intel_basic_block bb;
        bb.m_start_rva = blocks[block_index].m_start_rva;
        bb.m_end_rva = bb.m_start_rva;

        uint32_t cursor = bb.m_start_rva;

        while (true) {
            if (static_cast<size_t>(cursor) + ZYDIS_MAX_INSTRUCTION_LENGTH > mapped_image.size()) {
                break;
            }

            ZydisDecodedInstruction decoded{};
            std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};

            const auto status = ZydisDecoderDecodeFull(&m_decoder, mapped_image.data() + cursor,
                ZYDIS_MAX_INSTRUCTION_LENGTH, &decoded, operands.data());

            if (!ZYAN_SUCCESS(status)) {
                return std::nullopt;
            }

            if (ctx.instruction_limit && ++instruction_count >= ctx.instruction_limit) {
                return std::nullopt;
            }

            std::vector<uint8_t> raw_bytes(decoded.length);
            std::memcpy(raw_bytes.data(), mapped_image.data() + cursor, decoded.length);

            c_intel_instruction instr;
            instr.m_rva = cursor;
            instr.m_instruction = decoded;
            instr.m_operands = operands;
            instr.m_raw_bytes = std::move(raw_bytes);
            instr.m_branch_target = 0;

            bb.m_end_rva = cursor + decoded.length;

            const auto category = decoded.meta.category;
            const auto mnemonic = decoded.mnemonic;

            // Returns, interrupts and undefined instructions end exploration.
            if (category == ZYDIS_CATEGORY_RET || category == ZYDIS_CATEGORY_INTERRUPT ||
                mnemonic == ZYDIS_MNEMONIC_UD0 || mnemonic == ZYDIS_MNEMONIC_UD1 || mnemonic == ZYDIS_MNEMONIC_UD2) {
                bb.m_is_final = true;

                bb.m_instructions.push_back(std::move(instr));
                break;
            }

            if (mnemonic == ZYDIS_MNEMONIC_JMP) {
                if (operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    // indirect jump, treat as function exit
                    bb.m_is_final = true;
                    bb.m_instructions.push_back(std::move(instr));
                    break;
                }

                uint64_t target = 0;
                if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&decoded, operands.data(), cursor, &target))) {
                    return std::nullopt;
                }

                instr.m_branch_target = target;
                bb.m_instructions.push_back(std::move(instr));

                discover(static_cast<uint32_t>(target));
                break;
            }

            // conditional branch: queue both the target and the fallthrough
            if (category == ZYDIS_CATEGORY_COND_BR) {
                if (operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    return std::nullopt;
                }

                uint64_t target = 0;
                if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&decoded, operands.data(), cursor, &target))) {
                    return std::nullopt;
                }

                const uint32_t fallthrough = cursor + decoded.length;

                instr.m_branch_target = target;
                bb.m_instructions.push_back(std::move(instr));

                discover(static_cast<uint32_t>(target));
                discover(fallthrough);
                break;
            }

            // ordinary instruction, extend the block and continue
            bb.m_instructions.push_back(std::move(instr));
            cursor += decoded.length;
        }

        blocks[block_index] = std::move(bb);
    }

    return entry_index;
}

void c_intel_disassembler::add_edge(const size_t from_index, const size_t to_index, c_intel_function &fn) {
    auto &from = fn.m_basic_blocks[from_index];
    auto &to = fn.m_basic_blocks[to_index];

    if (std::ranges::find(from.m_successors, to_index) == from.m_successors.end()) {
        from.m_successors.push_back(to_index);
    }

    if (std::ranges::find(to.m_predecessors, from_index) == to.m_predecessors.end()) {
        to.m_predecessors.push_back(from_index);
    }
}
