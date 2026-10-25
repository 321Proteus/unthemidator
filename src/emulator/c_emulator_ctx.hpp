#ifndef UNTHEMIDATOR_EMULATOR_CTX_HPP
#define UNTHEMIDATOR_EMULATOR_CTX_HPP

#include <unicorn/unicorn.h>
#include <functional>
#include <optional>
#include <unordered_set>
#include <memory>

#include "../helpers/common.hpp"
#include "c_imports.hpp"

using code_callback_t = void(uc_engine *uc, uint64_t address, uint32_t size);
using mem_callback_t = void(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value);

class c_emulator;
class c_emulator_ctx;
class c_memory_manager;
class c_memory;
class c_themida_unpacker;

struct s_hooked_function {
    uint64_t m_address; // original address
    std::string m_name{}; // hook nametag
    std::function<void(c_emulator_ctx*)> m_function; // target function
    uint32_t m_arg_count = 0;
};

class c_emulator_ctx {
public:
    explicit c_emulator_ctx(c_emulator* emulator, uc_engine* uc, const std::shared_ptr<c_memory_manager>& memory_manager);
    ~c_emulator_ctx();

    [[nodiscard]] e_architecture get_arch() const;
    [[nodiscard]] uc_engine* get_uc() const;

    [[nodiscard]] std::shared_ptr<c_memory> get_memory() const;
    [[nodiscard]] std::shared_ptr<c_imports> get_imports() const;
    [[nodiscard]] const std::vector<uint8_t>& get_original_file_mapping() const;

    void set_themida_unpacker(c_themida_unpacker* unpacker);
    [[nodiscard]] c_themida_unpacker* get_themida_unpacker() const;

    [[nodiscard]] uint64_t get_x86_reg_value(uc_x86_reg reg) const;

    void set_x86_reg_value(uc_x86_reg reg, uint64_t value) const;

    [[nodiscard]] uint64_t get_arg(uint32_t index) const;
    void set_arg(uint32_t index, uint64_t value) const;
    void set_result(uint64_t value) const;

    void add_hook(uint64_t address, const std::string &name, const std::function<void(c_emulator_ctx*)> &hook, uint32_t arg_count = 0);
    void remove_hook(uint64_t address);

    void add_mem_hook(uc_hook_type hook_type, std::function<mem_callback_t> callback, uint64_t start_address, uint64_t end_address);
    void remove_mem_hook(uint64_t address);

    struct s_process_snapshot {
        uint32_t m_flags = 0, m_process_id = 0, m_index = 0;
    };

    uint64_t create_process_snapshot(uint32_t flags, uint32_t process_id) const;
    s_process_snapshot* get_process_snapshot(uint64_t handle) const;
    bool close_process_snapshot(uint64_t handle) const;

    void add_exception_handler(uint64_t address);
    void remove_exception_handler(uint64_t address);
    void raise_exception(uint32_t exception_code);

    const s_hooked_function* get_hook(uint64_t address);

    [[nodiscard]] uint64_t map_dummy_module(const std::vector<uint8_t>& image, const std::string &name) const;

    template <typename T>
    [[nodiscard]] std::optional<T> read(const uint64_t address) const {
        static_assert(std::is_trivially_copyable_v<T>, "read<T> requires a trivially copyable type");

        T value{};
        if (uc_mem_read(m_uc, address, &value, sizeof(T)) != UC_ERR_OK) {
            return std::nullopt;
        }

        return value;
    }

    template <typename T>
    [[nodiscard]] bool write(const uint64_t address, T value) const {
        static_assert(std::is_trivially_copyable_v<T>, "write<T> requires a trivially copyable type");

        if (uc_mem_write(m_uc, address, &value, sizeof(T)) != UC_ERR_OK) {
            return false;
        }

        return true;
    }

    void single_step(std::function<mem_callback_t> on_mem = nullptr) const;
    void run(uint64_t start, uint64_t end = 0, std::function<code_callback_t> on_code = nullptr,
        std::function<mem_callback_t> on_mem = nullptr) const;

    [[nodiscard]] uint64_t get_pc() const;
    void set_pc(uint64_t new_pc) const;

    [[nodiscard]] uint64_t allocate_storage(uint32_t size, const std::string &tag = {}) const;

    void initialize_windows_ldr() const;
private:
    static bool fetch_prot_callback(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, c_emulator_ctx* ctx);
    uc_err emulate(uint64_t start, uint64_t end, size_t count) const;

    mutable std::optional<uint64_t> m_hook_resume;

    uc_engine *m_uc;
    c_emulator *m_emulator;

    uc_hook m_int_trace{}, m_cpuid_trace{}, m_fetch_trace{}, m_prot_trace{};

    std::shared_ptr<c_memory_manager> m_memory_manager;
    std::shared_ptr<c_imports> m_imports;

    std::unordered_map<uint64_t, s_hooked_function> m_hooks{};

    std::unordered_set<uint64_t> m_exception_handlers{};

    mutable std::unordered_map<uint64_t, s_process_snapshot> m_process_snapshots{};
    mutable uint64_t m_next_snapshot_handle = 0x10000;

    uint64_t m_exception_stack = 0;
    uint64_t m_exception_return_address = 0;

    c_themida_unpacker *m_themida_unpacker = nullptr;

    struct s_mem_hook {
        uc_hook m_trace{};
        std::function<mem_callback_t> m_hook = nullptr;
    };

    std::unordered_map<uint64_t, s_mem_hook> m_mem_hooks{};
};

#endif //UNTHEMIDATOR_EMULATOR_CTX_HPP
