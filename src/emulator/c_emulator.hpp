#ifndef UNTHEMIDATOR_EMULATOR_HPP
#define UNTHEMIDATOR_EMULATOR_HPP

#include <memory>
#include <Zydis/Zydis.h>
#include <mutex>

#include "c_emulator_ctx.hpp"

class c_memory_manager;

class c_emulator {
public:
    explicit c_emulator(e_architecture architecture, e_platform platform,
        const std::shared_ptr<c_memory_manager> &memory_manager);

    [[nodiscard]] std::shared_ptr<c_emulator_ctx> create_context();
    [[nodiscard]] e_architecture get_arch() const;

    uint32_t get_instr_length(uint64_t address);
private:
    [[nodiscard]] uc_engine* create_uc_engine() const;

    void setup_windows_env(uc_engine* uc) const;
    void setup_windows_kernel_env(uc_engine* uc) const;

    const e_platform m_platform;
    const e_architecture m_architecture;

    const std::shared_ptr<c_memory_manager> m_memory_manager;

    ZydisDecoder m_decoder{};
    std::mutex m_decoder_mtx{};
};

#endif //UNTHEMIDATOR_EMULATOR_HPP
