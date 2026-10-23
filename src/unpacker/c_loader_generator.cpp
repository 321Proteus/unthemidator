#include "c_loader_generator.hpp"

#include <stdexcept>

void c_loader_generator::generate(const e_architecture architecture) {
    switch (architecture) {
        case e_architecture::k_x86:
            m_shellcode = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2, 0x0C, 0x00 };
            break;
        case e_architecture::k_amd64:
            m_shellcode = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
            break;
        default:
            throw std::runtime_error("loader generator: unsupported architecture");
    }
}

const std::vector<uint8_t>& c_loader_generator::get_shellcode() const {
    return m_shellcode;
}
