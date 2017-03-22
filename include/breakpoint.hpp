#ifndef MINIDBG_BREAKPOINT_HPP
#define MINIDBG_BREAKPOINT_HPP

#include <cstdint>
#include <sys/ptrace.h>

namespace minidbg {
    class breakpoint {
    public:
        breakpoint() = default;
        breakpoint(pid_t pid, std::intptr_t addr) : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{} {}

        void enable() {
            m_saved_data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
            uint64_t int3 = 0xcc;
            uint64_t data_with_int3 = ((m_saved_data & ~0xff) | int3); //set bottom byte to 0xcc
            ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3);

            m_enabled = true;
        }

        void disable() {
            ptrace(PTRACE_POKEDATA, m_pid, m_addr, m_saved_data);
            m_enabled = false;
        }

        bool is_enabled() const { return m_enabled; }

        auto get_address() const -> std::intptr_t { return m_addr; }
    private:
        pid_t m_pid;
        std::intptr_t m_addr;
        bool m_enabled;
        uint64_t m_saved_data; //data which used to be at the breakpoint address
    };
}

#endif
