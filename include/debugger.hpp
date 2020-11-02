#ifndef MINIDBG_DEBUGGER_HPP
#define MINIDBG_DEBUGGER_HPP

#include <utility>
#include <string>
#include <linux/types.h>
#include <unordered_map>

#include "breakpoint.hpp"
#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"

namespace minidbg {
    class debugger {
    public:
        debugger (std::string prog_name, pid_t pid)
             : m_prog_name{std::move(prog_name)}, m_pid{pid} {
            auto fd = open(m_prog_name.c_str(), O_RDONLY);

            m_elf = elf::elf{elf::create_mmap_loader(fd)};
            m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
        }

        void run();
        void set_breakpoint_at_address(std::intptr_t addr);
        void dump_registers();
        void print_source(const std::string& file_name, unsigned line, unsigned n_lines_context=2);

    private:
        void handle_command(const std::string& line);
        void continue_execution();
        auto get_pc() -> uint64_t;
        void set_pc(uint64_t pc);
        void step_over_breakpoint();
        void wait_for_signal();
        auto get_signal_info() -> siginfo_t;

        void handle_sigtrap(siginfo_t info);

        void initialise_load_address();
        uint64_t offset_load_address(uint64_t addr);

        auto get_function_from_pc(uint64_t pc) -> dwarf::die;
        auto get_line_entry_from_pc(uint64_t pc) -> dwarf::line_table::iterator;

        auto read_memory(uint64_t address) -> uint64_t ;
        void write_memory(uint64_t address, uint64_t value);

        std::string m_prog_name;
        pid_t m_pid;
        uint64_t m_load_address = 0;
        std::unordered_map<std::intptr_t,breakpoint> m_breakpoints;
        dwarf::dwarf m_dwarf;
        elf::elf m_elf;
    };
}

#endif
