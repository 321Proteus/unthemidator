#ifndef UNTHEMIDATOR_C_THEMIDA_VM_INSTANCE_HPP
#define UNTHEMIDATOR_C_THEMIDA_VM_INSTANCE_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <Zydis/Register.h>

struct themida_structs {
    uint64_t m_vm_ctx = 0;

    uint32_t m_is_in_vm_offset = 0;

    ZydisRegister m_vm_ctx_register = ZYDIS_REGISTER_NONE;
};

struct s_themida_vm_trampoline {
    uint64_t m_trampoline_address;
    uint64_t m_vm_enter_address;

    std::vector<uint8_t> m_prologue{};

    bool m_is_packed;
    uint64_t m_dispatch_address = 0;
};

struct s_themida_recovered_import {
    uint32_t m_iat_rva;
    uint32_t m_ordinal;

    bool m_is_ordinal;

    std::string m_module;
    std::string m_function;
};

struct s_unpacker_options {
	uint16_t m_max_nested_vms = 0; // how many nested VMs to emulate in one emulation cycle (0 = emulate all)

    bool m_skip_imports = false; // whether to skip imports lookup
    bool m_skip_vm_lookup = false; // whether to skip vm lookup
    bool m_skip_loader = false; // whether to skip fixer stub generation
};

#endif //UNTHEMIDATOR_C_THEMIDA_VM_INSTANCE_HPP
