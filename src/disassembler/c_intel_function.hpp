#ifndef UNTHEMIDATOR_C_INTEL_FUNCTION_HPP
#define UNTHEMIDATOR_C_INTEL_FUNCTION_HPP

#include <array>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <Zydis/Zydis.h>

struct c_intel_instruction {
    uint32_t m_rva = 0;

    ZydisDecodedInstruction m_instruction = {};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> m_operands = {};

    std::vector<uint8_t> m_raw_bytes;

    uint64_t m_branch_target = 0;
};

struct c_intel_basic_block {
    size_t m_block_id = 0;

    uint32_t m_start_rva = 0;
    uint32_t m_end_rva = 0;

    bool m_is_final = false;

    std::vector<c_intel_instruction> m_instructions;

    std::vector<size_t> m_successors;
    std::vector<size_t> m_predecessors;
};

struct c_intel_function {
    uint32_t m_start_rva = 0;
    uint32_t m_end_rva = 0;

    std::vector<c_intel_basic_block> m_basic_blocks{};
    std::unordered_map<uint32_t, size_t> m_address_to_bb_id{};

    size_t m_first_bb_id = 0;

    std::unordered_set<size_t> m_final_block_ids{};

    c_intel_basic_block *find_common_predecessor(const std::vector<const c_intel_basic_block *> &blocks);
};

#endif //UNTHEMIDATOR_C_INTEL_FUNCTION_HPP
