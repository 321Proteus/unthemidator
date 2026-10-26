#ifndef UNTHEMIDATOR_INTEL_DISASSEMBLER_HPP
#define UNTHEMIDATOR_INTEL_DISASSEMBLER_HPP

#include <mutex>

#include "c_intel_function.hpp"
#include "../memory/c_memory_manager.hpp"

#include <map>
#include <optional>
#include <Zydis/Decoder.h>

class c_intel_disassembler final {
public:
    // zero-filled memory decodes as an endless "add [rax], al", so this many zero bytes end a block
    static constexpr size_t K_MAX_ZEROS = 8;

    explicit c_intel_disassembler(const std::shared_ptr<c_memory>& memory, bool is_x64 = true);

    // Zero disables the limit; reaching a nonzero limit fails the whole walk.
    std::shared_ptr<c_intel_function> disassemble(uint32_t rva, size_t instruction_limit = 0);

    c_intel_instruction disassemble_instruction(uint32_t rva);
private:
    struct s_walk_ctx {
        c_intel_function *function;
        std::map<uint32_t, size_t> rva_to_bb_index;
        std::vector<uint32_t> pending;
        size_t instruction_limit;
        size_t instruction_count;
    };

    std::optional<size_t> walk_basic_block(uint32_t rva, s_walk_ctx &ctx) const;
    static std::optional<size_t> find_block_containing(uint32_t rva, const s_walk_ctx &ctx);
    static size_t split_basic_block(size_t block_index, uint32_t rva, s_walk_ctx &ctx);
    static void add_edge(size_t from_index, size_t to_index, c_intel_function &fn);

    std::shared_ptr<c_memory> m_memory;

    ZydisDecoder m_decoder{};
    std::mutex m_decoder_mtx{};
};

#endif //UNTHEMIDATOR_INTEL_DISASSEMBLER_HPP
