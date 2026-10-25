#include "c_memory_manager.hpp"

#include <cstring>
#include <stdexcept>

#include "../pe/c_pe_image.hpp"

c_memory_manager::c_memory_manager(const std::shared_ptr<c_pe_image>& pe_image) : c_memory(pe_image) {
    //
}

uint64_t c_memory_manager::allocate_helper_stub(const uint32_t size) {
    // allocate stub on top of the existing dump
    const auto stub_address = m_cursor;

    const auto next_cursor = page_up(m_cursor + size + 0x100, 0x1000);

    if (!m_pe_image->is_x64() && next_cursor > UINT32_MAX) {
        throw std::runtime_error("memory: x86 allocation exceeds 32-bit address space");
    }

    m_cursor = next_cursor;
    m_commited_memory.insert(m_commited_memory.end(), m_cursor - stub_address, 0);

    return stub_address;
}

void c_memory_manager::write_memory(const uint64_t address, const std::vector<uint8_t> &dump) {
    if (address + dump.size() > m_cursor) {
        throw std::runtime_error("memory: attempted out of range write");
    }

    if (address >= m_image_base && address < m_image_base + m_image_size) {
        if (dump.size() > m_mapped_image.size() - address + m_image_base) {
            throw std::runtime_error("memory: attempted out of range write");
        }

        std::memcpy(m_mapped_image.data() + address - m_image_base, dump.data(), dump.size());
        return;
    }

    if (address >= m_commited_memory_start) {
        std::memcpy(m_commited_memory.data() + address - m_commited_memory_start, dump.data(), dump.size());
        return;
    }

    throw std::runtime_error("memory: attempted out of range write (2)");
}

void c_memory_manager::add_const_region(uint64_t start, uint64_t end) {
    m_const_regions.emplace_back(start, end);
}

void c_memory_manager::tag_region(uint64_t address, const std::string& tag) {
    if (!m_tagged_regions.contains(address)) {
        m_tagged_regions.emplace(address, std::vector<std::string>{});
    }

    m_tagged_regions.at(address).emplace_back(tag);
}
