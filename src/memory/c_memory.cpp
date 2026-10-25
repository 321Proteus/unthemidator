#include "c_memory.hpp"

#include <stdexcept>
#include <cstdint>

#include "../pe/c_pe_image.hpp"

constexpr uint32_t stack_size = 0x50000;
constexpr uint64_t page_size = 0x1000;
constexpr uint32_t stack_reserve = 0x10000;

c_memory::c_memory(const std::shared_ptr<c_pe_image>& pe_image) : m_pe_image(pe_image) {
    m_mapped_image = m_pe_image->get_mapped_image();

    m_image_base = m_pe_image->get_image_base();
    m_image_size = static_cast<uint32_t>(m_mapped_image.size());

    m_stack_reserve = stack_reserve;
    m_stack_size = stack_size;

    uint64_t memory_end;

    // decide whether the stack region should be above the mapped image region or below it
    if (m_image_base <= m_stack_size + 0x4000) {
        m_stack_base = page_up(m_image_base + m_image_size + 0x3000, page_size);
        memory_end = page_up(m_stack_base + m_stack_size + 0x1000, page_size);
    } else {
        m_stack_base = page_up(m_image_base - m_stack_size - 0x3000, page_size);
        memory_end = page_up(m_image_base + m_image_size + 0x1000, page_size);
    }

    m_cursor = page_up(memory_end + 0x1000, page_size);

    if (!pe_image->is_x64() && m_cursor > UINT32_MAX) {
        throw std::runtime_error("memory: x86 image exceeds 32-bit address space");
    }

    m_commited_memory_start = m_cursor;
}

const std::vector<uint8_t>& c_memory::get_mapped_image() const {
    return m_mapped_image;
}

std::shared_ptr<c_pe_image> c_memory::get_pe_image() const {
    return m_pe_image;
}

uint64_t c_memory::get_image_base() const {
    return m_image_base;
}

uint32_t c_memory::get_image_size() const {
    return m_image_size;
}

uint64_t c_memory::get_stack_base() const {
    return m_stack_base;
}

uint32_t c_memory::get_stack_size() const {
    return m_stack_size;
}

uint64_t c_memory::get_initial_stack_pointer() const {
    return m_stack_base + m_stack_size - m_stack_reserve;
}

uint32_t c_memory::get_stack_reserve_size() const {
    return m_stack_reserve;
}

uint64_t c_memory::get_committed_memory_start() const {
    return m_commited_memory_start;
}

uint64_t c_memory::get_memory_end() const {
    return m_cursor;
}

bool c_memory::is_in_const_region(const uint64_t address, const uint8_t size) const {
    if (address < m_image_base || address + size >= m_image_base + m_image_size) {
        return false;
    }

    bool is_in_const_region = false;

    for (const auto [start, end] : m_const_regions) {
        if (address >= start && address < end) {
            is_in_const_region = true;
            break;
        }
    }

    return is_in_const_region;
}

bool c_memory::read_executable_byte(const uint64_t address, uint8_t *byte) const {
    if (address >= m_image_base && address < m_image_base + m_image_size) {
        *byte = m_mapped_image.at(address - m_image_base);
        return true;
    }

    if (address >= m_commited_memory_start && address < m_cursor) {
        *byte = m_commited_memory.at(address - m_commited_memory_start);
        return true;
    }

    return false;
}

std::optional<std::string> c_memory::get_address_tag(const uint64_t address) const {
    if (m_tagged_regions.contains(address)) {
        return { *m_tagged_regions.at(address).begin() };
    }

    return std::nullopt;
}

std::optional<uint64_t> c_memory::get_address_by_tag(std::string_view tag) const {
    const auto it = std::ranges::find_if(m_tagged_regions, [&](const auto& kv) {
        return std::ranges::find(kv.second, tag) != kv.second.end();
    });

    if (it == m_tagged_regions.end()) {
        return std::nullopt;
    }

    return it->first;
}
