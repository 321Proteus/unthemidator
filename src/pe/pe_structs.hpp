#ifndef UNTHEMIDATOR_PE_STRUCTS_HPP
#define UNTHEMIDATOR_PE_STRUCTS_HPP

#include <cstddef>
#include <cstdint>

namespace unthemidator::pe {

#pragma pack(push, 1)

    struct s_dos_header {
        std::uint16_t e_magic; // "MZ" = 0x5A4D
        std::uint16_t e_cblp;
        std::uint16_t e_cp;
        std::uint16_t e_crlc;
        std::uint16_t e_cparhdr;
        std::uint16_t e_minalloc;
        std::uint16_t e_maxalloc;
        std::uint16_t e_ss;
        std::uint16_t e_sp;
        std::uint16_t e_csum;
        std::uint16_t e_ip;
        std::uint16_t e_cs;
        std::uint16_t e_lfarlc;
        std::uint16_t e_ovno;
        std::uint16_t e_res[4];
        std::uint16_t e_oemid;
        std::uint16_t e_oeminfo;
        std::uint16_t e_res2[10];
        std::uint32_t e_lfanew; // file offset of PE signature
    };

    static_assert(sizeof(s_dos_header) == 64);

    struct s_coff_header {
        std::uint16_t machine; // IMAGE_FILE_MACHINE_*
        std::uint16_t number_of_sections;
        std::uint32_t time_date_stamp;
        std::uint32_t pointer_to_symbol_table;
        std::uint32_t number_of_symbols;
        std::uint16_t size_of_optional_header;
        std::uint16_t characteristics;
    };

    static_assert(sizeof(s_coff_header) == 20);

    constexpr std::uint16_t k_dos_magic = 0x5A4D; // "MZ"
    constexpr std::uint32_t k_nt_signature = 0x00004550; // "PE\0\0"

    constexpr std::uint16_t k_machine_i386 = 0x014C;
    constexpr std::uint16_t k_machine_amd64 = 0x8664;

    constexpr std::uint16_t k_optional_magic_pe32 = 0x010B;
    constexpr std::uint16_t k_optional_magic_pe32_plus = 0x020B;

    struct s_data_directory {
        std::uint32_t virtual_address;
        std::uint32_t size;
    };

    static_assert(sizeof(s_data_directory) == 8);

    constexpr std::size_t k_num_data_directories = 16;

    struct s_optional_header_32 {
        std::uint16_t magic;
        std::uint8_t major_linker_version;
        std::uint8_t minor_linker_version;
        std::uint32_t size_of_code;
        std::uint32_t size_of_initialized_data;
        std::uint32_t size_of_uninitialized_data;
        std::uint32_t address_of_entry_point;
        std::uint32_t base_of_code;
        std::uint32_t base_of_data;
        std::uint32_t image_base;
        std::uint32_t section_alignment;
        std::uint32_t file_alignment;
        std::uint16_t major_os_version;
        std::uint16_t minor_os_version;
        std::uint16_t major_image_version;
        std::uint16_t minor_image_version;
        std::uint16_t major_subsystem_version;
        std::uint16_t minor_subsystem_version;
        std::uint32_t win32_version_value;
        std::uint32_t size_of_image;
        std::uint32_t size_of_headers;
        std::uint32_t checksum;
        std::uint16_t subsystem;
        std::uint16_t dll_characteristics;
        std::uint32_t size_of_stack_reserve;
        std::uint32_t size_of_stack_commit;
        std::uint32_t size_of_heap_reserve;
        std::uint32_t size_of_heap_commit;
        std::uint32_t loader_flags;
        std::uint32_t number_of_rva_and_sizes;
        s_data_directory data_directory[k_num_data_directories];
    };

    static_assert(sizeof(s_optional_header_32) == 224);

    struct s_optional_header_64 {
        std::uint16_t magic;
        std::uint8_t major_linker_version;
        std::uint8_t minor_linker_version;
        std::uint32_t size_of_code;
        std::uint32_t size_of_initialized_data;
        std::uint32_t size_of_uninitialized_data;
        std::uint32_t address_of_entry_point;
        std::uint32_t base_of_code;
        std::uint64_t image_base;
        std::uint32_t section_alignment;
        std::uint32_t file_alignment;
        std::uint16_t major_os_version;
        std::uint16_t minor_os_version;
        std::uint16_t major_image_version;
        std::uint16_t minor_image_version;
        std::uint16_t major_subsystem_version;
        std::uint16_t minor_subsystem_version;
        std::uint32_t win32_version_value;
        std::uint32_t size_of_image;
        std::uint32_t size_of_headers;
        std::uint32_t checksum;
        std::uint16_t subsystem;
        std::uint16_t dll_characteristics;
        std::uint64_t size_of_stack_reserve;
        std::uint64_t size_of_stack_commit;
        std::uint64_t size_of_heap_reserve;
        std::uint64_t size_of_heap_commit;
        std::uint32_t loader_flags;
        std::uint32_t number_of_rva_and_sizes;
        s_data_directory data_directory[k_num_data_directories];
    };

    static_assert(sizeof(s_optional_header_64) == 240);

    template <typename t_optional_header>
    struct s_nt_headers {
        std::uint32_t signature; // "PE\0\0" = 0x00004550
        s_coff_header file_header;
        t_optional_header optional_header;
    };

    using s_nt_headers_32 = s_nt_headers<s_optional_header_32>;
    using s_nt_headers_64 = s_nt_headers<s_optional_header_64>;

    static_assert(sizeof(s_nt_headers_32) == 248);
    static_assert(sizeof(s_nt_headers_64) == 264);
    static_assert(offsetof(s_nt_headers_32, file_header) == 4);
    static_assert(offsetof(s_nt_headers_32, optional_header) == 24);
    static_assert(offsetof(s_nt_headers_64, file_header) == 4);
    static_assert(offsetof(s_nt_headers_64, optional_header) == 24);

    struct s_export_directory {
        std::uint32_t characteristics;
        std::uint32_t time_date_stamp;
        std::uint16_t major_version;
        std::uint16_t minor_version;
        std::uint32_t name;
        std::uint32_t base;
        std::uint32_t number_of_functions;
        std::uint32_t number_of_names;
        std::uint32_t address_of_functions;
        std::uint32_t address_of_names;
        std::uint32_t address_of_name_ordinals;
    };

    static_assert(sizeof(s_export_directory) == 40);

    constexpr std::size_t k_directory_entry_export         = 0;
    constexpr std::size_t k_directory_entry_import         = 1;
    constexpr std::size_t k_directory_entry_resource       = 2;
    constexpr std::size_t k_directory_entry_exception      = 3;
    constexpr std::size_t k_directory_entry_security       = 4;
    constexpr std::size_t k_directory_entry_basereloc      = 5;
    constexpr std::size_t k_directory_entry_debug          = 6;
    constexpr std::size_t k_directory_entry_architecture   = 7;
    constexpr std::size_t k_directory_entry_globalptr      = 8;
    constexpr std::size_t k_directory_entry_tls            = 9;
    constexpr std::size_t k_directory_entry_load_config    = 10;
    constexpr std::size_t k_directory_entry_bound_import   = 11;
    constexpr std::size_t k_directory_entry_iat            = 12;
    constexpr std::size_t k_directory_entry_delay_import   = 13;
    constexpr std::size_t k_directory_entry_com_descriptor = 14;
    constexpr std::size_t k_directory_entry_reserved       = 15;

    struct s_import_descriptor {
        std::uint32_t original_first_thunk;
        std::uint32_t time_date_stamp;
        std::uint32_t forwarder_chain;
        std::uint32_t name;
        std::uint32_t first_thunk;
    };

    static_assert(sizeof(s_import_descriptor) == 20);

    union s_thunk_data_32 {
        std::uint32_t forwarder_string;
        std::uint32_t function;
        std::uint32_t ordinal;
        std::uint32_t address_of_data;
    };

    union s_thunk_data_64 {
        std::uint64_t forwarder_string;
        std::uint64_t function;
        std::uint64_t ordinal;
        std::uint64_t address_of_data;
    };

    static_assert(sizeof(s_thunk_data_32) == 4);
    static_assert(sizeof(s_thunk_data_64) == 8);

    constexpr std::uint32_t k_ordinal_flag_32 = 0x80000000;
    constexpr std::uint64_t k_ordinal_flag_64 = 0x8000000000000000;

    struct s_import_by_name {
        std::uint16_t hint;
        char name[1]; // null-terminated, variable-length string
    };

    static_assert(offsetof(s_import_by_name, name) == 2);

    struct s_section_header {
        char name[8]; // not null-terminated if full 8 bytes used
        std::uint32_t virtual_size;
        std::uint32_t virtual_address; // RVA
        std::uint32_t size_of_raw_data;
        std::uint32_t pointer_to_raw_data; // file offset
        std::uint32_t pointer_to_relocations;
        std::uint32_t pointer_to_line_numbers;
        std::uint16_t number_of_relocations;
        std::uint16_t number_of_line_numbers;
        std::uint32_t characteristics;
    };

    static_assert(sizeof(s_section_header) == 40);

    constexpr std::uint32_t k_scn_mem_execute = 0x20000000;
    constexpr std::uint32_t k_scn_mem_read = 0x40000000;
    constexpr std::uint32_t k_scn_mem_write = 0x80000000;
    constexpr std::uint32_t k_scn_cnt_code = 0x00000020;
    constexpr std::uint32_t k_scn_cnt_initialized_data = 0x00000040;

#pragma pack(pop)

} // namespace unthemidator::pe

#endif //UNTHEMIDATOR_PE_STRUCTS_HPP
