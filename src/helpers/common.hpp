#ifndef UNTHEMIDATOR_COMMON_HPP
#define UNTHEMIDATOR_COMMON_HPP

#include <string>

enum class e_architecture {
    k_x86,
    k_amd64,
};

enum class e_platform {
    k_windows,
    k_windows_driver,
};

struct s_dummy_export {
    std::string m_name{};
    std::string m_module{};

    uint32_t m_ordinal = 0;
    uint64_t m_entry_address = 0;
};

#endif //UNTHEMIDATOR_COMMON_HPP
