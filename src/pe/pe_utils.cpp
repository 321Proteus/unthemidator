#include "pe_utils.hpp"

#include <algorithm>
#include <ranges>
#include <stdexcept>
#include <unordered_set>

#include "pe_structs.hpp"

using namespace unthemidator::pe;

namespace {
    constexpr uint32_t k_section_alignment = 0x1000;
    constexpr uint32_t k_file_alignment = 0x200;
    constexpr uint32_t k_nt_offset = 0x80;
    constexpr uint32_t k_text_rva = 0x1000;

    uint32_t checked_u32(const uint64_t value) {
        if (value > std::numeric_limits<uint32_t>::max()) {
            throw std::runtime_error("dummy PE: image too large");
        }

        return static_cast<uint32_t>(value);
    }

    uint32_t align_up(const uint64_t value, const uint32_t alignment) {
        return checked_u32((value + alignment - 1) / alignment * alignment);
    }

    template<typename T>
    void write_at(std::vector<uint8_t> &image, const std::size_t offset, const T &value) {
        if (offset > image.size() || sizeof(T) > image.size() - offset) {
            throw std::runtime_error("dummy PE: invalid write offset");
        }

        std::memcpy(image.data() + offset, &value, sizeof(T));
    }

    void write_string(std::vector<uint8_t> &image, const std::size_t offset, const std::string &value) {
        if (offset > image.size() || value.size() >= image.size() - offset) {
            throw std::runtime_error("dummy PE: invalid string offset");
        }

        std::memcpy(image.data() + offset, value.c_str(), value.size() + 1);
    }
} // namespace

std::vector<uint8_t> pe_utils::create_dummy_dll(const e_architecture architecture,
    const uint64_t image_base, const std::string &module_name, std::vector<s_dummy_export> &exports) {
    //
    const bool is_64bit = architecture == e_architecture::k_amd64;

    if (module_name.empty() || module_name.find('\0') != std::string::npos ||
        (architecture != e_architecture::k_x86 && !is_64bit)) {
        //
        throw std::invalid_argument("dummy PE: invalid module name or architecture");
    }

    std::unordered_set<uint32_t> used_ordinals;
    std::unordered_set<std::string> used_names;

    uint32_t ordinal_base = 1;
    uint32_t max_ordinal = 0;

    if (!exports.empty()) {
        ordinal_base = std::numeric_limits<uint32_t>::max();
    }

    for (auto &[name, mod_name, ordinal, target_fn] : exports) {
        if (!ordinal) {
            throw std::runtime_error("dummy PE: duplicate or invalid export: invalid ordinal");
        }

        if (!used_ordinals.insert(ordinal).second) {
            throw std::runtime_error("dummy PE: duplicate or invalid export: used ordinal");
        }

        if (name.find('\0') != std::string::npos) {
            throw std::runtime_error("dummy PE: duplicate or invalid export: malformed name");
        }

        if (!name.empty() && !used_names.insert(name).second) {
            throw std::runtime_error("dummy PE: duplicate or invalid export: used name " + name);
        }

        ordinal_base = std::min(ordinal_base, static_cast<uint32_t>(ordinal));
        max_ordinal = std::max(max_ordinal, static_cast<uint32_t>(ordinal));
    }

    const auto function_count = exports.empty() ? 0 : max_ordinal - ordinal_base + 1;
    const auto named_count = static_cast<uint32_t>(used_names.size());
    const auto text_size = std::max<uint32_t>(1, checked_u32(exports.size()));
    const auto edata_rva = align_up(static_cast<uint64_t>(k_text_rva) + text_size, k_section_alignment);

    // layout the export directory and tables before allocating the image
    uint64_t cursor = sizeof(s_export_directory);
    const auto eat_offset = checked_u32(cursor);
    cursor += static_cast<uint64_t>(function_count) * sizeof(uint32_t);
    const auto names_offset = checked_u32(cursor);
    cursor += static_cast<uint64_t>(named_count) * sizeof(uint32_t);
    const auto ordinals_offset = checked_u32(cursor);
    cursor += static_cast<uint64_t>(named_count) * sizeof(uint16_t);
    const auto module_offset = checked_u32(cursor);
    cursor += module_name.size() + 1;

    std::vector<std::pair<std::string, uint16_t> > named_exports;
    named_exports.reserve(named_count);

    for (const auto &[name, mod_name, ordinal, target_fn]: exports) {
        if (name.empty()) {
            continue;
        }

        named_exports.emplace_back(name, ordinal);
    }

    std::ranges::sort(named_exports);

    std::vector<uint32_t> name_offsets;
    name_offsets.reserve(named_count);

    for (const auto &name: named_exports | std::views::keys) {
        name_offsets.push_back(checked_u32(cursor));
        cursor += name.size() + 1;
    }

    const auto edata_size = checked_u32(cursor);
    const auto image_size = align_up(static_cast<uint64_t>(edata_rva) + edata_size, k_section_alignment);
    const auto text_raw_size = align_up(text_size, k_file_alignment);
    const auto edata_raw_size = align_up(edata_size, k_file_alignment);
    const auto nt_size = is_64bit ? sizeof(s_nt_headers_64) : sizeof(s_nt_headers_32);
    const auto headers_size = align_up(k_nt_offset + nt_size + 2 * sizeof(s_section_header), k_file_alignment);

    if (image_size > 0x100000 || headers_size > k_text_rva) {
        throw std::runtime_error("dummy PE: invalid image layout");
    }

    std::vector<uint8_t> image(image_size);

    s_dos_header dos{};
    dos.e_magic = 0x5A4D;
    dos.e_lfanew = k_nt_offset;
    write_at(image, 0, dos);

    if (is_64bit) {
        s_nt_headers_64 nt{};

        nt.signature = k_nt_signature;
        nt.file_header.machine = k_machine_amd64;
        nt.file_header.number_of_sections = 2;
        nt.file_header.size_of_optional_header = sizeof(s_optional_header_64);
        nt.file_header.characteristics = 0x0002 | 0x0020 | 0x2000;
        nt.optional_header.magic = k_optional_magic_pe32_plus;
        nt.optional_header.size_of_code = text_raw_size;
        nt.optional_header.size_of_initialized_data = edata_raw_size;
        nt.optional_header.base_of_code = k_text_rva;
        nt.optional_header.image_base = image_base;
        nt.optional_header.section_alignment = k_section_alignment;
        nt.optional_header.file_alignment = k_file_alignment;
        nt.optional_header.major_os_version = 6;
        nt.optional_header.major_subsystem_version = 6;
        nt.optional_header.size_of_image = image_size;
        nt.optional_header.size_of_headers = headers_size;
        nt.optional_header.subsystem = 3;
        nt.optional_header.size_of_stack_reserve = 0x100000;
        nt.optional_header.size_of_stack_commit = 0x1000;
        nt.optional_header.size_of_heap_reserve = 0x100000;
        nt.optional_header.size_of_heap_commit = 0x1000;
        nt.optional_header.number_of_rva_and_sizes = k_num_data_directories;

        nt.optional_header.data_directory[k_directory_entry_export] = {
            .virtual_address = edata_rva,
            .size = edata_size
        };

        write_at(image, k_nt_offset, nt);
    } else {
        s_nt_headers_32 nt{};

        nt.signature = k_nt_signature;
        nt.file_header.machine = k_machine_i386;
        nt.file_header.number_of_sections = 2;
        nt.file_header.size_of_optional_header = sizeof(s_optional_header_32);
        nt.file_header.characteristics = 0x0002 | 0x0100 | 0x2000;
        nt.optional_header.magic = k_optional_magic_pe32;
        nt.optional_header.size_of_code = text_raw_size;
        nt.optional_header.size_of_initialized_data = edata_raw_size;
        nt.optional_header.base_of_code = k_text_rva;
        nt.optional_header.base_of_data = edata_rva;
        nt.optional_header.image_base = static_cast<uint32_t>(image_base);
        nt.optional_header.section_alignment = k_section_alignment;
        nt.optional_header.file_alignment = k_file_alignment;
        nt.optional_header.major_os_version = 6;
        nt.optional_header.major_subsystem_version = 6;
        nt.optional_header.size_of_image = image_size;
        nt.optional_header.size_of_headers = headers_size;
        nt.optional_header.subsystem = 3;
        nt.optional_header.size_of_stack_reserve = 0x100000;
        nt.optional_header.size_of_stack_commit = 0x1000;
        nt.optional_header.size_of_heap_reserve = 0x100000;
        nt.optional_header.size_of_heap_commit = 0x1000;
        nt.optional_header.number_of_rva_and_sizes = k_num_data_directories;

        nt.optional_header.data_directory[k_directory_entry_export] = {
            .virtual_address = edata_rva,
            .size = edata_size
        };

        write_at(image, k_nt_offset, nt);
    }

    s_section_header text_section{};
    std::memcpy(text_section.name, ".text", 5);
    text_section.virtual_size = text_size;
    text_section.virtual_address = k_text_rva;
    text_section.size_of_raw_data = text_raw_size;
    text_section.pointer_to_raw_data = headers_size;
    text_section.characteristics = 0x60000020;

    s_section_header edata_section{};
    std::memcpy(edata_section.name, ".edata", 6);
    edata_section.virtual_size = edata_size;
    edata_section.virtual_address = edata_rva;
    edata_section.size_of_raw_data = edata_raw_size;
    edata_section.pointer_to_raw_data = checked_u32(static_cast<uint64_t>(headers_size) + text_raw_size);
    edata_section.characteristics = 0x40000040;

    const auto sections_offset = k_nt_offset + nt_size;
    write_at(image, sections_offset, text_section);
    write_at(image, sections_offset + sizeof(s_section_header), edata_section);

    for (std::size_t i = 0; i < exports.size(); ++i) {
        const auto offset = static_cast<uint32_t>(k_text_rva + i);

        image[offset] = 0xCC;

        write_at(image, edata_rva + eat_offset + (exports[i].m_ordinal - ordinal_base) * sizeof(uint32_t),
            checked_u32(offset));

        exports[i].m_entry_address = offset;
    }

    if (exports.empty()) {
        image[k_text_rva] = 0xCC;
    }

    s_export_directory directory{};
    directory.name = edata_rva + module_offset;
    directory.base = ordinal_base;
    directory.number_of_functions = function_count;
    directory.number_of_names = named_count;
    directory.address_of_functions = edata_rva + eat_offset;
    directory.address_of_names = named_count ? edata_rva + names_offset : 0;
    directory.address_of_name_ordinals = named_count ? edata_rva + ordinals_offset : 0;

    write_at(image, edata_rva, directory);
    write_string(image, edata_rva + module_offset, module_name);

    for (std::size_t i = 0; i < named_exports.size(); ++i) {
        const auto &[name, ordinal] = named_exports[i];
        const auto name_rva = checked_u32(static_cast<uint64_t>(edata_rva) + name_offsets[i]);
        const auto eat_index = static_cast<uint16_t>(ordinal - ordinal_base);

        write_at(image, edata_rva + names_offset + i * sizeof(uint32_t), name_rva);
        write_at(image, edata_rva + ordinals_offset + i * sizeof(uint16_t), eat_index);

        write_string(image, name_rva, name);
    }

    return image;
}
