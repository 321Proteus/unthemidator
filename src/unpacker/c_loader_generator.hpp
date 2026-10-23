#ifndef UNTHEMIDATOR_C_LOADER_GENERATOR_HPP
#define UNTHEMIDATOR_C_LOADER_GENERATOR_HPP

#include <cstdint>
#include <vector>

#include "../helpers/common.hpp"

class c_loader_generator {
public:
    void generate(e_architecture architecture);
    [[nodiscard]] const std::vector<uint8_t>& get_shellcode() const;
private:
    std::vector<uint8_t> m_shellcode{};
};

#endif //UNTHEMIDATOR_C_LOADER_GENERATOR_HPP
