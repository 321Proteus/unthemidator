#include "c_pe_image.hpp"

#include <algorithm>
#include <stdexcept>

#include "pe_structs.hpp"

using namespace unthemidator::pe;

c_pe_image::c_pe_image(std::span<const std::uint8_t> bytes) : m_file_binary(bytes.begin(), bytes.end()) {
    parse();
}

uint64_t c_pe_image::get_image_base() const {
    return m_image_base;
}

uint32_t c_pe_image::get_entry_rva() const {
    return m_entry_rva;
}

uint32_t c_pe_image::get_size_of_headers() const {
    return m_size_of_headers;
}

const std::vector<uint8_t>& c_pe_image::get_original_mapping() const {
    return m_file_binary;
}

const std::vector<uint8_t>& c_pe_image::get_mapped_image() const {
    return m_mapped_binary;
}

bool c_pe_image::is_x64() const {
    return m_is_x64;
}

uint16_t c_pe_image::get_ptr_size() const {
    return m_is_x64 ? sizeof(uint64_t) : sizeof(uint32_t);
}

bool c_pe_image::is_rva_in_executable_section(const uint64_t address) const {
    for (const auto &section : m_sections) {
        if (address < section.virtual_address || address >= section.virtual_address + section.virtual_size) {
            continue;
        }

        return section.characteristics & k_scn_mem_execute;
    }

    return false;
}

const std::unordered_map<std::string, std::unordered_map<std::string, uint64_t>>& c_pe_image::get_imports() const {
    return m_imports;
}

void c_pe_image::parse() {
    const auto dos_header = reinterpret_cast<s_dos_header *>(m_file_binary.data());

    if (dos_header->e_magic != k_dos_magic) {
        throw std::runtime_error("PE error: invalid DOS header");
    }

    if (*reinterpret_cast<uint32_t *>(m_file_binary.data() + dos_header->e_lfanew) != k_nt_signature) {
        throw std::runtime_error("PE error: invalid NT/COFF headers");
    }

    // get COFF header
    const auto coff_offset = dos_header->e_lfanew + sizeof(uint32_t);
    const auto coff_header = reinterpret_cast<s_coff_header *>(m_file_binary.data() + coff_offset);

    if (coff_header->machine != k_machine_amd64 && coff_header->machine != k_machine_i386) {
        throw std::runtime_error("PE error: invalid machine type, only x86 and AMD64 (x86_64) binaries are supported");
    }

    m_opt_header_offset = coff_offset + sizeof(s_coff_header);

    if (const auto opt_magic = *reinterpret_cast<const uint16_t *>(m_file_binary.data() + m_opt_header_offset);
        opt_magic == k_optional_magic_pe32) {
        //
        const auto opt_header = reinterpret_cast<s_optional_header_32 *>(m_file_binary.data() + m_opt_header_offset);

        m_mapped_binary.resize(opt_header->size_of_image);

        m_image_base = opt_header->image_base;
        m_entry_rva = opt_header->address_of_entry_point;
        m_size_of_headers = opt_header->size_of_headers;
        m_is_x64 = false;

        // copy image headers
        memcpy(m_mapped_binary.data(), m_file_binary.data(), opt_header->size_of_headers);
    } else if (opt_magic == k_optional_magic_pe32_plus) {
        const auto opt_header = reinterpret_cast<s_optional_header_64 *>(m_file_binary.data() + m_opt_header_offset);

        m_mapped_binary.resize(opt_header->size_of_image);

        m_image_base = opt_header->image_base;
        m_entry_rva = opt_header->address_of_entry_point;
        m_size_of_headers = opt_header->size_of_headers;
        m_is_x64 = true;

        // copy image headers
        memcpy(m_mapped_binary.data(), m_file_binary.data(), opt_header->size_of_headers);
    } else {
        throw std::runtime_error("PE error: invalid magic number in optional header");
    }

    // parse sections
    const auto sections_offset = m_opt_header_offset + coff_header->size_of_optional_header;
    m_sections.reserve(coff_header->number_of_sections);

    for (uint16_t i = 0; i < coff_header->number_of_sections; ++i) {
        const auto section = reinterpret_cast<s_section_header *>(m_mapped_binary.data() +
            sections_offset + i * sizeof(s_section_header));

        if (!section) {
            throw std::runtime_error("PE error: truncated section table");
        }

        m_sections.push_back(s_section{
            .virtual_address = section->virtual_address,
            .virtual_size = section->virtual_size,
            .raw_offset = section->pointer_to_raw_data,
            .raw_size = section->size_of_raw_data,
            .characteristics = section->characteristics,
            .name = std::string(section->name)
        });

        // copy section to mapped binary
        memcpy(m_mapped_binary.data() + section->virtual_address, m_file_binary.data() +
            section->pointer_to_raw_data, section->size_of_raw_data);
    }

    // parse imports
    if (m_is_x64) {
        parse_imports<s_optional_header_64, s_thunk_data_64, k_ordinal_flag_64>();
    } else {
        parse_imports<s_optional_header_32, s_thunk_data_32, k_ordinal_flag_32>();
    }

    // parse exports
    parse_exports();

}

const std::vector<c_pe_image::s_export>& c_pe_image::get_exports() const {
    return m_exports;
}

const std::vector<c_pe_image::s_section> & c_pe_image::get_sections() const {
    return m_sections;
}

void c_pe_image::parse_exports() {
    const auto image_size = m_mapped_binary.size();

    const auto directory_offset = m_opt_header_offset + (m_is_x64 ? offsetof(s_optional_header_64, data_directory) :
        offsetof(s_optional_header_32, data_directory)) + k_directory_entry_export * sizeof(s_data_directory);

    if (directory_offset > image_size || sizeof(s_data_directory) > image_size - directory_offset) {
        throw std::runtime_error("PE error: invalid export data directory");
    }

    s_data_directory directory{};
    std::memcpy(&directory, m_mapped_binary.data() + directory_offset, sizeof(directory));

    if (!directory.virtual_address && !directory.size) {
        return;
    }

    if (!directory.virtual_address || directory.size < sizeof(s_export_directory) ||
        directory.virtual_address >= image_size ||
        directory.size > image_size - directory.virtual_address) {
        throw std::runtime_error("PE error: invalid export directory");
    }

    const auto exports = reinterpret_cast<const s_export_directory*>(m_mapped_binary.data() + directory.virtual_address);

    const auto check_range = [&](const uint32_t rva, const uint64_t size) {
        if (rva >= image_size || size > image_size - rva) {
            throw std::runtime_error("PE error: invalid export table RVA");
        }
    };

    const auto read_string = [&](const uint32_t rva, const size_t limit) -> std::string {
        check_range(rva, 1);

        const auto available = std::min(limit, image_size - static_cast<size_t>(rva));
        const auto ptr = reinterpret_cast<const char*>(m_mapped_binary.data() + rva);
        const auto end = static_cast<const char*>(std::memchr(ptr, 0, available));

        if (!end) {
            throw std::runtime_error("PE error: unterminated export string");
        }

        return {ptr, end};
    };

    if (!exports->number_of_functions) {
        if (exports->number_of_names) {
            throw std::runtime_error("PE error: invalid export counts");
        }

        return;
    }

    if (static_cast<uint64_t>(exports->base) + exports->number_of_functions - 1 > UINT32_MAX ||
        exports->number_of_names > exports->number_of_functions) {
        //
        throw std::runtime_error("PE error: invalid export ordinals");
    }

    check_range(exports->address_of_functions,
        static_cast<uint64_t>(exports->number_of_functions) * sizeof(uint32_t));

    if (exports->number_of_names) {
        check_range(exports->address_of_names,
            static_cast<uint64_t>(exports->number_of_names) * sizeof(uint32_t));

        check_range(exports->address_of_name_ordinals,
            static_cast<uint64_t>(exports->number_of_names) * sizeof(uint16_t));
    }

    const auto read_u32 = [&](const uint64_t offset) {
        uint32_t value = 0;
        std::memcpy(&value, m_mapped_binary.data() + offset, sizeof(value));
        return value;
    };

    const auto read_u16 = [&](const uint64_t offset) {
        uint16_t value = 0;
        std::memcpy(&value, m_mapped_binary.data() + offset, sizeof(value));
        return value;
    };

    const auto first_index = m_exports.size();
    m_exports.reserve(first_index + exports->number_of_functions);

    for (uint32_t i = 0; i < exports->number_of_functions; ++i) {
        const auto function_rva = read_u32(
            static_cast<uint64_t>(exports->address_of_functions) + i * sizeof(uint32_t));

        s_export entry{};
        entry.m_ordinal = exports->base + i;

        if (function_rva) {
            check_range(function_rva, 1);

            if (m_image_base > UINT64_MAX - function_rva) {
                throw std::runtime_error("PE error: export address overflow");
            }

            entry.m_address = m_image_base + function_rva;

            if (function_rva >= directory.virtual_address &&
                static_cast<uint64_t>(function_rva) - directory.virtual_address < directory.size) {
                //
                const auto end = static_cast<uint64_t>(directory.virtual_address) + directory.size;
                entry.m_forwarder = read_string(function_rva, end - function_rva);
            }
        }

        m_exports.push_back(std::move(entry));
    }

    for (uint32_t i = 0; i < exports->number_of_names; ++i) {
        const auto name_rva = read_u32(
            static_cast<uint64_t>(exports->address_of_names) + i * sizeof(uint32_t));

        const auto ordinal_index = read_u16(
            static_cast<uint64_t>(exports->address_of_name_ordinals) + i * sizeof(uint16_t));

        if (ordinal_index >= exports->number_of_functions) {
            throw std::runtime_error("PE error: invalid export ordinal index");
        }

        auto &entry = m_exports[first_index + ordinal_index];

        if (!entry.m_name.empty()) {
            throw std::runtime_error("PE error: duplicate export name ordinal");
        }

        entry.m_name = read_string(name_rva, image_size - static_cast<size_t>(name_rva));
    }
}

template<typename t_optional_header, typename t_thunk, std::uint64_t k_ordinal_flag>
void c_pe_image::parse_imports() {
    const auto image_size = m_mapped_binary.size();

    const auto directory = reinterpret_cast<s_data_directory*>(m_mapped_binary.data() + m_opt_header_offset +
        offsetof(t_optional_header, data_directory) + k_directory_entry_import * sizeof(s_data_directory));

    if (!directory->virtual_address || !directory->size) {
        return;
    }

    if (directory->virtual_address >= image_size || directory->size > image_size - directory->virtual_address) {
        //
        throw std::runtime_error("PE error: invalid import directory");
    }

    const auto descriptor_count = directory->size / sizeof(s_import_descriptor);

    if (!descriptor_count) {
        throw std::runtime_error("PE error: truncated import directory");
    }

    for (size_t i = 0; i < descriptor_count; ++i) {
        const auto descriptor = reinterpret_cast<s_import_descriptor*>(m_mapped_binary.data() +
            static_cast<size_t>(directory->virtual_address) + i * sizeof(s_import_descriptor));

        if (!descriptor->original_first_thunk && !descriptor->forwarder_chain &&
            !descriptor->name && !descriptor->first_thunk) {
            //
            return;
        }

        if (!descriptor->name || !descriptor->first_thunk) {
            throw std::runtime_error("PE error: invalid import descriptor");
        }

        auto module_name = std::string(reinterpret_cast<char*>(m_mapped_binary.data() + descriptor->name));
        std::ranges::transform(module_name, module_name.begin(), tolower);

        const auto lookup_rva = descriptor->original_first_thunk ? descriptor->original_first_thunk :
            descriptor->first_thunk;
        const auto iat_rva = descriptor->first_thunk;

        if (lookup_rva >= image_size || iat_rva >= image_size) {
            throw std::runtime_error("PE: invalid thunk table RVA");
        }

        const auto max_entries = (image_size - lookup_rva) / sizeof(t_thunk);
        const auto max_iat_entries = (image_size - iat_rva) / sizeof(t_thunk);

        bool terminated = false;

        for (size_t j = 0; j < max_entries && j < max_iat_entries; ++j) {
            const auto thunk = reinterpret_cast<t_thunk*>(m_mapped_binary.data() + lookup_rva + j * sizeof(t_thunk));
            const auto value = thunk->address_of_data;

            if (!value) {
                terminated = true;
                break;
            }

            const auto slot_rva = static_cast<uint64_t>(iat_rva) + j * sizeof(t_thunk);

            if (m_image_base > std::numeric_limits<uint64_t>::max() - slot_rva) {
                throw std::runtime_error("PE error: IAT address overflow");
            }

            std::string function_name{};

            if (value & k_ordinal_flag) {
                function_name = std::to_string(value & 0xFFFF);
            } else {
                if (value > std::numeric_limits<std::uint32_t>::max() || value > image_size || sizeof(uint16_t) > image_size -
                    static_cast<std::size_t>(value)) {
                    throw std::runtime_error("PE error: invalid import-by-name RVA");
                }

                function_name = std::string(reinterpret_cast<char*>(m_mapped_binary.data() +
                    value + offsetof(s_import_by_name, name)));
            }

            m_imports[module_name][function_name] = m_image_base + slot_rva;
        }

        if (!terminated) {
            throw std::runtime_error("PE error: unterminated thunk table");
        }
    }
}
