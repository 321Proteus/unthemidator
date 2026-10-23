#ifndef DEVIRTUALIZER_UTILS_HPP
#define DEVIRTUALIZER_UTILS_HPP

#include <filesystem>
#include <Zydis/Register.h>
#include <fstream>
#include <vector>
#include <iostream>

namespace utils {
    inline uc_x86_reg get_emulator_reg(const ZydisRegister reg) {
        switch (reg) {
            case ZYDIS_REGISTER_RAX:
                return UC_X86_REG_RAX;
            case ZYDIS_REGISTER_RCX:
                return UC_X86_REG_RCX;
            case ZYDIS_REGISTER_RBX:
                return UC_X86_REG_RBX;
            case ZYDIS_REGISTER_RDX:
                return UC_X86_REG_RDX;
            case ZYDIS_REGISTER_RBP:
                return UC_X86_REG_RBP;
            case ZYDIS_REGISTER_RSP:
                return UC_X86_REG_RSP;
            case ZYDIS_REGISTER_RDI:
                return UC_X86_REG_RDI;
            case ZYDIS_REGISTER_RSI:
                return UC_X86_REG_RSI;
            case ZYDIS_REGISTER_R8:
                return UC_X86_REG_R8;
            case ZYDIS_REGISTER_R9:
                return UC_X86_REG_R9;
            case ZYDIS_REGISTER_R10:
                return UC_X86_REG_R10;
            case ZYDIS_REGISTER_R11:
                return UC_X86_REG_R11;
            case ZYDIS_REGISTER_R12:
                return UC_X86_REG_R12;
            case ZYDIS_REGISTER_R13:
                return UC_X86_REG_R13;
            case ZYDIS_REGISTER_R14:
                return UC_X86_REG_R14;
            case ZYDIS_REGISTER_R15:
                return UC_X86_REG_R15;
            case ZYDIS_REGISTER_RIP:
                return UC_X86_REG_RIP;

            case ZYDIS_REGISTER_EAX:
                return UC_X86_REG_EAX;
            case ZYDIS_REGISTER_EIP:
                return UC_X86_REG_EIP;
            case ZYDIS_REGISTER_EBP:
                return UC_X86_REG_EBP;
            case ZYDIS_REGISTER_EDI:
                return UC_X86_REG_EDI;
            case ZYDIS_REGISTER_ESP:
                return UC_X86_REG_ESP;
            case ZYDIS_REGISTER_EDX:
                return UC_X86_REG_EDX;
            case ZYDIS_REGISTER_EBX:
                return UC_X86_REG_EBX;

            case ZYDIS_REGISTER_YMM0:
                return UC_X86_REG_YMM0;
            case ZYDIS_REGISTER_YMM1:
                return UC_X86_REG_YMM1;
            case ZYDIS_REGISTER_YMM2:
                return UC_X86_REG_YMM2;
            case ZYDIS_REGISTER_YMM3:
                return UC_X86_REG_YMM3;
            case ZYDIS_REGISTER_YMM4:
                return UC_X86_REG_YMM4;
            case ZYDIS_REGISTER_YMM5:
                return UC_X86_REG_YMM5;
            case ZYDIS_REGISTER_YMM6:
                return UC_X86_REG_YMM6;
            case ZYDIS_REGISTER_YMM7:
                return UC_X86_REG_YMM7;
            case ZYDIS_REGISTER_YMM8:
                return UC_X86_REG_YMM8;
            case ZYDIS_REGISTER_YMM9:
                return UC_X86_REG_YMM9;
            case ZYDIS_REGISTER_YMM10:
                return UC_X86_REG_YMM10;
            case ZYDIS_REGISTER_YMM11:
                return UC_X86_REG_YMM11;
            case ZYDIS_REGISTER_YMM12:
                return UC_X86_REG_YMM12;
            case ZYDIS_REGISTER_YMM13:
                return UC_X86_REG_YMM13;
            case ZYDIS_REGISTER_YMM14:
                return UC_X86_REG_YMM14;
            case ZYDIS_REGISTER_YMM15:
                return UC_X86_REG_YMM15;
            case ZYDIS_REGISTER_YMM16:
                return UC_X86_REG_YMM16;
            case ZYDIS_REGISTER_YMM17:
                return UC_X86_REG_YMM17;
            case ZYDIS_REGISTER_YMM18:
                return UC_X86_REG_YMM18;
            case ZYDIS_REGISTER_YMM19:
                return UC_X86_REG_YMM19;
            case ZYDIS_REGISTER_YMM20:
                return UC_X86_REG_YMM20;
            case ZYDIS_REGISTER_YMM21:
                return UC_X86_REG_YMM21;
            case ZYDIS_REGISTER_YMM22:
                return UC_X86_REG_YMM22;
            case ZYDIS_REGISTER_YMM23:
                return UC_X86_REG_YMM23;
            case ZYDIS_REGISTER_YMM24:
                return UC_X86_REG_YMM24;
            case ZYDIS_REGISTER_YMM25:
                return UC_X86_REG_YMM25;
            case ZYDIS_REGISTER_YMM26:
                return UC_X86_REG_YMM26;
            case ZYDIS_REGISTER_YMM27:
                return UC_X86_REG_YMM27;
            case ZYDIS_REGISTER_YMM28:
                return UC_X86_REG_YMM28;
            case ZYDIS_REGISTER_YMM29:
                return UC_X86_REG_YMM29;
            case ZYDIS_REGISTER_YMM30:
                return UC_X86_REG_YMM30;
            case ZYDIS_REGISTER_YMM31:
                return UC_X86_REG_YMM31;

            default:
                break;
        }

        throw std::runtime_error("unknown register: "+std::to_string(reg));
    }

    inline std::vector<uint8_t> read_file(const std::string &path) {
        std::ifstream f(path, std::ios::binary);

        if (!f) {
            std::cerr << "failed to open " << path << " for reading\n";
            return {};
        }

        f.seekg(0, std::ios::end);
        std::vector<uint8_t> buf((f.tellg()));
        f.seekg(0, std::ios::beg);
        f.read(reinterpret_cast<char *>(buf.data()), static_cast<std::streamsize>(buf.size()));
        return buf;
    }

}

#endif //DEVIRTUALIZER_UTILS_HPP
