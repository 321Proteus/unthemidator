#ifndef UNTHEMIDATOR_C_THEMIDA_INSTRUCTION_HPP
#define UNTHEMIDATOR_C_THEMIDA_INSTRUCTION_HPP

#include "../disassembler/c_intel_disassembler.hpp"

enum class e_themida_handler_type {
    context_switch,
    unclassified,
};

struct s_themida_handler_decision_point {
    explicit s_themida_handler_decision_point(const uint64_t address) : m_address(address) {
        m_successors = {};
        m_terminating = true;
    }

    explicit s_themida_handler_decision_point(const uint64_t address,
        const std::unordered_map<uint64_t, std::shared_ptr<s_themida_handler_decision_point>>& successors)
        : m_address(address), m_successors(successors) {
        //
        m_terminating = false;
    }

    uint64_t m_address; // VA of decision point

    std::unordered_map<uint64_t, std::shared_ptr<s_themida_handler_decision_point>> m_successors;

    bool m_terminating; // is concluding (like ret)
};

struct s_themida_vm_handler {
    uint64_t m_address;
    e_themida_handler_type m_type;

    std::shared_ptr<c_intel_function> m_disassembled;
    std::shared_ptr<s_themida_handler_decision_point> m_decision_point;
};

#endif //UNTHEMIDATOR_C_THEMIDA_INSTRUCTION_HPP
