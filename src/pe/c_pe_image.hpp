#ifndef UNTHEMIDATOR_C_PE_FILE_HPP
#define UNTHEMIDATOR_C_PE_FILE_HPP

#include <span>
#include <vector>
#include <string>
#include <unordered_map>

class c_pe_image {
public:
    struct s_export {
        uint32_t m_ordinal;
        uint64_t m_address;

        std::string m_name;
        std::string m_forwarder;
    };

    struct s_section {
        uint32_t virtual_address;
        uint32_t virtual_size;
        uint32_t raw_offset;
        uint32_t raw_size;
        uint32_t characteristics;

        std::string name{};
    };

    explicit c_pe_image(std::span<const std::uint8_t> bytes);

    [[nodiscard]] uint64_t get_image_base() const;
    [[nodiscard]] uint32_t get_entry_rva() const;
    [[nodiscard]] uint32_t get_size_of_headers() const;

    [[nodiscard]] const std::vector<uint8_t>& get_original_mapping() const;
    [[nodiscard]] const std::vector<uint8_t>& get_mapped_image() const;

    [[nodiscard]] bool is_x64() const;
    [[nodiscard]] uint16_t get_ptr_size() const;

    [[nodiscard]] bool is_rva_in_executable_section(uint64_t address) const;

    [[nodiscard]] const std::vector<s_export>& get_exports() const;
    [[nodiscard]] const std::vector<s_section>& get_sections() const;
    [[nodiscard]] const std::unordered_map<std::string, std::unordered_map<std::string, uint64_t>>& get_imports() const;
private:
    void parse();

    template <typename t_optional_header, typename t_thunk, std::uint64_t k_ordinal_flag>
    void parse_imports();

    void parse_exports();

    std::vector<uint8_t> m_file_binary;
    std::vector<uint8_t> m_mapped_binary;


    uint64_t m_image_base = 0;

    uint32_t m_entry_rva = 0;
    uint32_t m_size_of_headers = 0;

    uint64_t m_opt_header_offset{};

    bool m_is_x64 = false;

    std::vector<s_section> m_sections;
    std::vector<s_export> m_exports;

    std::unordered_map<std::string, std::unordered_map<std::string, uint64_t>> m_imports{};
};

#endif //UNTHEMIDATOR_C_PE_FILE_HPP
