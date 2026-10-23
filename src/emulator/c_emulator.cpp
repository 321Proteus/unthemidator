#include "c_emulator.hpp"

#include "../memory/c_memory_manager.hpp"
#include "windows.hpp"

#include <algorithm>
#include <array>
#include <mutex>
#include <stdexcept>
#include <vector>

using namespace unthemidator::windows;

namespace {

void setup_x86_segments(uc_engine *uc, c_memory_manager *memory_manager, const uint32_t fs_base, const bool kernel) {
    const auto gdt_base = memory_manager->allocate_helper_stub(0x1000);

    if (gdt_base > UINT32_MAX - 0x1000) {
        throw std::runtime_error("emulator: x86 GDT requires a 32-bit address");
    }

    std::array<uint64_t, 5> gdt{};

    const auto descriptor = [](const uint32_t base, const uint8_t access) -> uint64_t {
        return 0x000F00000000FFFFULL | (static_cast<uint64_t>(base & 0xFFFF) << 16) |
            (static_cast<uint64_t>((base >> 16) & 0xFF) << 32) | (static_cast<uint64_t>(access) << 40) |
            (static_cast<uint64_t>((base >> 24) & 0xFF) << 56) | 0x00C0000000000000ULL;
    };

    gdt[1] = descriptor(0, kernel ? 0x9A : 0xFA);
    gdt[2] = descriptor(0, kernel ? 0x92 : 0xF2);
    gdt[3] = descriptor(fs_base, kernel ? 0x92 : 0xF2);
    gdt[4] = descriptor(0, 0x92);

    auto last_error = uc_mem_map(uc, gdt_base, 0x1000, UC_PROT_READ | UC_PROT_WRITE);

    if (last_error != UC_ERR_OK) {
        throw std::runtime_error("[uc] GDT map failed: " + std::to_string(last_error));
    }

    last_error = uc_mem_write(uc, gdt_base, gdt.data(), sizeof(gdt));

    if (last_error != UC_ERR_OK) {
        throw std::runtime_error("[uc] GDT write failed: " + std::to_string(last_error));
    }

    uc_x86_mmr gdtr{};
    gdtr.base = gdt_base;
    gdtr.limit = sizeof(gdt) - 1;

    if (uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr) != UC_ERR_OK) {
        throw std::runtime_error("[uc] GDTR initialization failed");
    }

    const uint16_t privilege = kernel ? 0 : 3;
    const uint16_t cs = (1 << 3) | privilege;
    const uint16_t ds = (2 << 3) | privilege;
    const uint16_t fs = (3 << 3) | privilege;
    const uint16_t ss = 4 << 3; // unicorn keeps CPL 0 when writing CS

    if (uc_reg_write(uc, UC_X86_REG_CS, &cs) != UC_ERR_OK || uc_reg_write(uc, UC_X86_REG_DS, &ds) != UC_ERR_OK ||
        uc_reg_write(uc, UC_X86_REG_SS, &ss) != UC_ERR_OK || uc_reg_write(uc, UC_X86_REG_ES, &ds) != UC_ERR_OK ||
        uc_reg_write(uc, UC_X86_REG_GS, &ds) != UC_ERR_OK || uc_reg_write(uc, UC_X86_REG_FS, &fs) != UC_ERR_OK) {
        throw std::runtime_error("[uc] x86 segment initialization failed");
    }
}

}

c_emulator::c_emulator(const e_architecture architecture, const e_platform platform,
    const std::shared_ptr<c_memory_manager> &memory_manager) : m_platform(platform),
    m_architecture(architecture), m_memory_manager(memory_manager) {
    //
    switch (m_architecture) {
        case e_architecture::k_x86: {
            ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
            break;
        }

        case e_architecture::k_amd64: {
            ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
            break;
        }

        default:
            throw std::runtime_error("emulator: unsupported architecture");
    }
}

std::shared_ptr<c_emulator_ctx> c_emulator::create_context() {
    const auto uc = create_uc_engine();

    if (m_architecture == e_architecture::k_x86 &&
        (m_memory_manager->get_image_base() > UINT32_MAX ||
            m_memory_manager->get_image_size() > UINT32_MAX - m_memory_manager->get_image_base() ||
         m_memory_manager->get_stack_base() > UINT32_MAX ||
         m_memory_manager->get_stack_size() > UINT32_MAX - m_memory_manager->get_stack_base())) {
        //
        throw std::runtime_error("emulator: x86 memory regions must fit in 32-bit address space");
    }

    // map binary dump
    auto last_error = uc_mem_map(uc, m_memory_manager->get_image_base(),
        m_memory_manager->get_image_size(), UC_PROT_ALL);

    if (last_error != UC_ERR_OK) {
        throw std::runtime_error("[uc] map #1 failed: " + std::to_string(last_error));
    }

    const auto& mapped_image = m_memory_manager->get_mapped_image();

    last_error = uc_mem_write(uc, m_memory_manager->get_image_base(), mapped_image.data(),
        mapped_image.size());

    if (last_error != UC_ERR_OK) {
        throw std::runtime_error("[uc] write #1 failed: " + std::to_string(last_error));
    }

    // map stack dump
    last_error = uc_mem_map(uc, m_memory_manager->get_stack_base(), m_memory_manager->get_stack_size(),
        UC_PROT_READ | UC_PROT_WRITE);

    if (last_error != UC_ERR_OK) {
        throw std::runtime_error("[uc] map #2 failed: " + std::to_string(last_error));
    }

    // initialize registers
    switch (m_architecture) {
        case e_architecture::k_x86: {
            if (m_memory_manager->get_initial_stack_pointer() > UINT32_MAX ||
                m_memory_manager->get_stack_base() > UINT32_MAX) {
                //
                throw std::runtime_error("emulator: x86 stack requires 32-bit addresses");
            }

            const auto esp = static_cast<uint32_t>(m_memory_manager->get_initial_stack_pointer());
            const auto ebp = static_cast<uint32_t>(m_memory_manager->get_stack_base());

            uc_reg_write(uc, UC_X86_REG_ESP, &esp);
            uc_reg_write(uc, UC_X86_REG_EBP, &ebp);

            break;
        }

        case e_architecture::k_amd64: {
            const auto rsp = m_memory_manager->get_initial_stack_pointer();
            const auto rbp = m_memory_manager->get_stack_base();

            uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
            uc_reg_write(uc, UC_X86_REG_RBP, &rbp);

            break;
        }

        default:
            throw std::runtime_error("emulator: unsupported architecture");
    }

    // initialize thread state based on platform type
    switch (m_platform) {
        case e_platform::k_windows: {
            setup_windows_env(uc);
            break;
        }

        case e_platform::k_windows_driver: {
            setup_windows_kernel_env(uc);
            break;
        }

        default:
            throw std::runtime_error("emulator: unsupported platform");
    }

    const auto ctx = std::make_shared<c_emulator_ctx>(this, uc, m_memory_manager);

    if (m_platform == e_platform::k_windows) {
        ctx->initialize_windows_ldr();
    }

    return ctx;
}

e_architecture c_emulator::get_arch() const {
    return m_architecture;
}

uint32_t c_emulator::get_instr_length(const uint64_t address) {
    const std::lock_guard decoder_guard(m_decoder_mtx);

    const auto image_base = m_memory_manager->get_image_base();
    const auto& image = m_memory_manager->get_mapped_image();

    if (address < image_base || address - image_base >= image.size()) {
        throw std::runtime_error("emulator: instruction address outside image");
    }

    const auto offset = address - image_base;

    ZydisDecodedInstruction instruction{};
    std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};

    const auto last_status = ZydisDecoderDecodeFull(&m_decoder,
        image.data() + offset, std::min<std::size_t>(ZYDIS_MAX_INSTRUCTION_LENGTH,
            image.size() - offset), &instruction, operands.data());

    if (!ZYAN_SUCCESS(last_status)) {
        throw std::runtime_error("ZydisDecoderDecodeFull() failed: " + std::to_string(last_status));
    }

    return instruction.length;
}

uc_engine* c_emulator::create_uc_engine() const {
    uc_engine *uc = nullptr;

    // create unicorn engine instance
    switch (m_architecture) {
        case e_architecture::k_x86: {
            if (uc_open(UC_ARCH_X86, UC_MODE_32, &uc) != UC_ERR_OK) {
                throw std::runtime_error("uc_open failed");
            }

            break;
        }

        case e_architecture::k_amd64: {
            if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc) != UC_ERR_OK) {
                throw std::runtime_error("uc_open failed");
            }

            break;
        }

        default:
            throw std::runtime_error("emulator: unsupported architecture");
    }

    // map virtual addresses to physical addresses to allow custom virtual regions mapping
    if (uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL)) {
        throw std::runtime_error("failed to set TLB to virtual");
    }

    uc_ctl_flush_tlb(uc);

    return uc;
}

void c_emulator::setup_windows_env(uc_engine *uc) const {
    if (m_architecture == e_architecture::k_x86) {
        std::array<uint8_t, 0x1000> peb{};
        std::array<uint8_t, 0x1000> teb{};
        std::array<uint8_t, 0x1000> ldr_data{};

        const auto ldr_data_base = m_memory_manager->allocate_helper_stub(0x1000);
        const auto peb_base = m_memory_manager->allocate_helper_stub(0x1000);
        const auto teb_base = m_memory_manager->allocate_helper_stub(0x1000);

        if (ldr_data_base > UINT32_MAX - 0xFFF || peb_base > UINT32_MAX - 0xFFF || teb_base > UINT32_MAX - 0xFFF) {
            throw std::runtime_error("emulator: x86 Windows environment requires 32-bit addresses");
        }

        m_memory_manager->tag_region(peb_base, "PEB");
        m_memory_manager->tag_region(teb_base, "TEB");

        const auto write32 = [](auto &buffer, const std::size_t offset, const uint32_t value) {
            std::memcpy(buffer.data() + offset, &value, sizeof(value));
        };

        write32(peb, 0x08, static_cast<uint32_t>(m_memory_manager->get_image_base()));
        write32(teb, 0x00, UINT32_MAX);
        write32(teb, 0x04, static_cast<uint32_t>(m_memory_manager->get_stack_base() + m_memory_manager->get_stack_size()));
        write32(teb, 0x08, static_cast<uint32_t>(m_memory_manager->get_stack_base()));
        write32(peb, 0x0C, static_cast<uint32_t>(ldr_data_base));
        write32(teb, 0x18, static_cast<uint32_t>(teb_base)); // self ptr (fs:[0x18])
        write32(teb, 0x30, static_cast<uint32_t>(peb_base));
        write32(teb, 0x20, k_process_id);
        write32(teb, 0x24, k_thread_id);

        // allocate memory regions for windows structs in unicorn
        auto last_error = uc_mem_map(uc, ldr_data_base, 0x1000, UC_PROT_READ | UC_PROT_WRITE);

        if (last_error != UC_ERR_OK) {
            throw std::runtime_error("[uc] map #1 failed: " + std::to_string(last_error));
        }

        last_error = uc_mem_map(uc, peb_base, 0x1000, UC_PROT_READ | UC_PROT_WRITE);

        if (last_error != UC_ERR_OK) {
            throw std::runtime_error("[uc] map #2 failed: " + std::to_string(last_error));
        }

        last_error = uc_mem_map(uc, teb_base, 0x1000, UC_PROT_READ | UC_PROT_WRITE);

        if (last_error != UC_ERR_OK) {
            throw std::runtime_error("[uc] map #3 failed: " + std::to_string(last_error));
        }

        uc_mem_write(uc, ldr_data_base, ldr_data.data(), ldr_data.size());
        uc_mem_write(uc, peb_base, peb.data(), peb.size());
        uc_mem_write(uc, teb_base, teb.data(), teb.size());

        setup_x86_segments(uc, m_memory_manager.get(), static_cast<uint32_t>(teb_base), false);
    } else {
        s_peb peb{};
        s_teb teb{};
        s_peb_ldr_data<uint64_t> ldr_data = {};

        constexpr uint64_t peb_size = align_size(sizeof(peb), 0x1000);
        constexpr uint64_t teb_size = align_size(sizeof(teb), 0x1000);

        const auto ldr_data_base = m_memory_manager->allocate_helper_stub(0x1000);
        const auto peb_base = m_memory_manager->allocate_helper_stub(peb_size);
        const auto teb_base = m_memory_manager->allocate_helper_stub(teb_size);

        m_memory_manager->tag_region(peb_base, "PEB");
        m_memory_manager->tag_region(teb_base, "TEB");

        *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(&peb) + 0x120) = 0x200004A65;
        peb.image_base_address = reinterpret_cast<void*>(m_memory_manager->get_image_base());
        peb.ldr = reinterpret_cast<s_peb_ldr_data<uint64_t>*>(ldr_data_base); 

        *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(&teb) + 0x30) = teb_base; // self ptr (gs:[0x30])
        teb.process_environment_block = reinterpret_cast<s_peb*>(peb_base);
        *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(&teb) + 0x40) = k_process_id;
        *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(&teb) + 0x48) = k_thread_id;

        // allocate memory regions for windows structs in unicorn
        auto last_error = uc_mem_map(uc, ldr_data_base, 0x1000, UC_PROT_READ | UC_PROT_WRITE);

        if (last_error != UC_ERR_OK) {
            throw std::runtime_error("[uc] map #1 failed: " + std::to_string(last_error));
        }

        last_error = uc_mem_map(uc, peb_base, peb_size, UC_PROT_READ | UC_PROT_WRITE);

        if (last_error != UC_ERR_OK) {
            throw std::runtime_error("[uc] map #2 failed: " + std::to_string(last_error));
        }

        last_error = uc_mem_map(uc, teb_base, teb_size, UC_PROT_READ | UC_PROT_WRITE);

        if (last_error != UC_ERR_OK) {
            throw std::runtime_error("[uc] map #3 failed: " + std::to_string(last_error));
        }

        uc_mem_write(uc, ldr_data_base, &ldr_data, sizeof(ldr_data));
        uc_mem_write(uc, peb_base, &peb, sizeof(peb));
        uc_mem_write(uc, teb_base, &teb, sizeof(teb));

        // write MSR with TEB base addr
        uc_x86_msr msr{};
        msr.rid = static_cast<uint32_t>(e_msr::k_ia32_gs_base);
        msr.value = teb_base;

        uc_reg_write(uc, UC_X86_REG_MSR, &msr);
    }

    if (m_architecture == e_architecture::k_amd64) {
        // create segment registers
        s_segment_selector cs = {};
        cs.fields.index = 1;
        uc_reg_write(uc, UC_X86_REG_CS, &cs.all);

        s_segment_selector ds = {};
        ds.fields.index = 2;
        uc_reg_write(uc, UC_X86_REG_DS, &ds.all);

        s_segment_selector ss = {};
        ss.fields.index = 2;
        uc_reg_write(uc, UC_X86_REG_SS, &ss.all);

        s_segment_selector es = {};
        es.fields.index = 2;
        uc_reg_write(uc, UC_X86_REG_ES, &es.all);

        s_segment_selector gs = {};
        gs.fields.index = 2;
        uc_reg_write(uc, UC_X86_REG_GS, &gs.all);
    }

    s_flag_register eflags = {};
    eflags.fields.id = 1;
    eflags.fields.intf = 1;
    eflags.fields.reserved1 = 1;

    uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags.all);
}

void c_emulator::setup_windows_kernel_env(uc_engine *uc) const {
    if (m_architecture == e_architecture::k_x86) {
        std::array<uint8_t, 0x1000> kpcr{};
        std::array<uint8_t, 0x1000> kthread{};

        const auto kpcr_base = m_memory_manager->allocate_helper_stub(0x1000);
        const auto kthread_base = m_memory_manager->allocate_helper_stub(0x1000);

        if (kpcr_base > UINT32_MAX - 0xFFF || kthread_base > UINT32_MAX - 0xFFF) {
            throw std::runtime_error("emulator: x86 Windows kernel environment requires 32-bit addresses");
        }

        m_memory_manager->tag_region(kpcr_base, "KPCR");
        m_memory_manager->tag_region(kthread_base, "KTHREAD");

        const auto write32 = [](auto &buffer, const std::size_t offset, const uint32_t value) {
            std::memcpy(buffer.data() + offset, &value, sizeof(value));
        };

        // KPCR.Self at fs:[0x1C] points to the KPCR itself
        write32(kpcr, 0x1C, static_cast<uint32_t>(kpcr_base));
        write32(kpcr, 0x20, static_cast<uint32_t>(kpcr_base + 0x120));

        // KPCR.Prcb.CurrentThread at fs:[0x124]
        write32(kpcr, 0x124, static_cast<uint32_t>(kthread_base));

        // allocate memory regions for kernel structs in unicorn
        auto last_error = uc_mem_map(uc, kpcr_base, 0x1000, UC_PROT_READ | UC_PROT_WRITE);

        if (last_error != UC_ERR_OK) {
            throw std::runtime_error("[uc] map #1 failed: " + std::to_string(last_error));
        }

        last_error = uc_mem_map(uc, kthread_base, 0x1000, UC_PROT_READ | UC_PROT_WRITE);

        if (last_error != UC_ERR_OK) {
            throw std::runtime_error("[uc] map #2 failed: " + std::to_string(last_error));
        }

        uc_mem_write(uc, kpcr_base, kpcr.data(), kpcr.size());
        uc_mem_write(uc, kthread_base, kthread.data(), kthread.size());

        setup_x86_segments(uc, m_memory_manager.get(), static_cast<uint32_t>(kpcr_base), true);
    } else {
        s_kpcr kpcr{};
        s_kthread kthread{};

        constexpr uint64_t kpcr_size = align_size(sizeof(kpcr), 0x1000);
        constexpr uint64_t kthread_size = align_size(sizeof(kthread), 0x1000);

        const auto kpcr_base = m_memory_manager->allocate_helper_stub(kpcr_size);
        const auto kthread_base = m_memory_manager->allocate_helper_stub(kthread_size);

        m_memory_manager->tag_region(kpcr_base, "KPCR");
        m_memory_manager->tag_region(kthread_base, "KTHREAD");

        // KPCR.Self at gs:[0x18] points to the KPCR itself
        *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(&kpcr) + 0x18) = kpcr_base;

        // KPCR.Prcb starts at offset 0x180; Prcb.CurrentThread is at Prcb+0x8 (i.e. gs:[0x188])
        *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(&kpcr) + 0x188) = kthread_base;

        // KTHREAD basic setup — most emulation paths touch these
        *reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(&kthread) + 0x220) = kthread_base;

        // allocate memory regions for kernel structs in unicorn
        auto last_error = uc_mem_map(uc, kpcr_base, kpcr_size, UC_PROT_READ | UC_PROT_WRITE);

        if (last_error != UC_ERR_OK) {
            throw std::runtime_error("[uc] map #1 failed: " + std::to_string(last_error));
        }

        last_error = uc_mem_map(uc, kthread_base, kthread_size, UC_PROT_READ | UC_PROT_WRITE);

        if (last_error != UC_ERR_OK) {
            throw std::runtime_error("[uc] map #2 failed: " + std::to_string(last_error));
        }

        uc_mem_write(uc, kpcr_base, &kpcr, sizeof(kpcr));
        uc_mem_write(uc, kthread_base, &kthread, sizeof(kthread));

        // write MSR with KPCR base addr
        uc_x86_msr msr{};
        msr.rid = static_cast<uint32_t>(e_msr::k_ia32_gs_base);
        msr.value = kpcr_base;

        uc_reg_write(uc, UC_X86_REG_MSR, &msr);
    }

    if (m_architecture == e_architecture::k_amd64) {
        // create segment registers — kernel selectors
        s_segment_selector cs = {};
        cs.fields.index = 1;
        cs.fields.rpl = 0;
        uc_reg_write(uc, UC_X86_REG_CS, &cs.all);

        s_segment_selector ds = {};
        ds.fields.index = 2;
        uc_reg_write(uc, UC_X86_REG_DS, &ds.all);

        s_segment_selector ss = {};
        ss.fields.index = 2;
        uc_reg_write(uc, UC_X86_REG_SS, &ss.all);

        s_segment_selector es = {};
        es.fields.index = 2;
        uc_reg_write(uc, UC_X86_REG_ES, &es.all);

        s_segment_selector gs = {};
        gs.fields.index = 2;
        uc_reg_write(uc, UC_X86_REG_GS, &gs.all);
    }

    s_flag_register eflags = {};
    eflags.fields.id = 1;
    eflags.fields.intf = 1;
    eflags.fields.reserved1 = 1;

    uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags.all);
}
