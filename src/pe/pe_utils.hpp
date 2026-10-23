#ifndef UNTHEMIDATOR_PE_UTILS_HPP
#define UNTHEMIDATOR_PE_UTILS_HPP

#include <string>
#include <vector>

#include "../helpers/common.hpp"

namespace pe_utils {

    std::vector<std::uint8_t> create_dummy_dll(e_architecture architecture, std::uint64_t image_base,
        const std::string &module_name, std::vector<s_dummy_export> &exports);

}

#endif //UNTHEMIDATOR_PE_UTILS_HPP
