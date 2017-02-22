#include <string>
#include <fstream>
#include <iostream>
#include <utility>
#include <cstdio>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"

#include "linenoise.h"

class breakpoint {
public:
    breakpoint(pid_t pid, std::intptr_t addr) : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{} {}
    void enable() {
        m_saved_data = ptrace(PTRACE_PEEKTEXT, m_pid, (void*)m_addr, 0);
        auto int3 = 0xcc;
        auto data_with_int3 = (m_saved_data & ~0xff | int3);
        ptrace(PTRACE_POKETEXT, m_pid, (void*)m_addr, data_with_int3);
         
        m_enabled = true;
    }

    void disable() {
        ptrace(PTRACE_POKETEXT, m_pid, (void*)m_addr, m_saved_data);
        m_enabled = false;
    }

    std::intptr_t get_address() { return m_addr; }
private:
    pid_t m_pid;
    std::intptr_t m_addr;
    bool m_enabled;
    unsigned m_saved_data;
};

class debugger {
public:
    debugger (std::string prog_name, pid_t pid)
        : m_prog_name{std::move(prog_name)}, m_pid{pid} {
            auto fd = open(m_prog_name.c_str(), O_RDONLY);

            m_elf = elf::elf{elf::create_mmap_loader(fd)};
            m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
        }

    void run();
    void dump_registers();
    void continue_execution();
    void single_step_instruction();
    siginfo_t get_signal_info();
    void set_breakpoint_at_address(std::intptr_t addr);    
    void set_breakpoint_at_source_line(const std::string& file, unsigned line);
    void print_source(const std::string& file_name, unsigned line, unsigned n_lines_context=2);
    
private:
    void handle_command(const std::string& line);
    void handle_sigtrap(siginfo_t info);
    void wait_for_signal();    
    uint64_t get_pc();
    void set_pc(uint64_t pc);
    void decrement_pc();        
    dwarf::line_table::entry get_current_line_entry();

    std::string m_prog_name;
    pid_t m_pid;
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;
    unsigned m_saved_data;
    std::unique_ptr<breakpoint> m_breakpoint;
};

uint64_t debugger::get_pc() {
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
  return regs.rip;
}

void debugger::set_pc(uint64_t pc) {
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
  regs.rip = pc;
  ptrace(PTRACE_SETREGS, m_pid, nullptr, &regs);      
}

void debugger::decrement_pc() {
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
  regs.rip -= 1;
  ptrace(PTRACE_SETREGS, m_pid, nullptr, &regs);      
}

dwarf::line_table::entry debugger::get_current_line_entry() {
    auto pc = get_pc();

    for (auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(pc)) {
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if (it == lt.end()) {
                throw std::out_of_range{"Cannot find line entry"};
            }
            else {
                return *it;
            }
        }
    }

    throw std::out_of_range{"Cannot find line entry"};
}

void debugger::run() {
    char* line = nullptr;
    while((line = linenoise("minidbg> ")) != nullptr) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void debugger::print_source(const std::string& file_name, unsigned line, unsigned n_lines_context) {
    std::ifstream file {file_name};
    auto start_line = line < n_lines_context ? 0 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;
    
    char c{};
    auto current_line = 1u;
    while (current_line != start_line && file.get(c)) {
        if (c == '\n') {
            ++current_line;
        }
    }
    std::cout << (current_line==line ? "> " : "  ");
    while (current_line != end_line && file.get(c)) {
        std::cout << c;
        if (c == '\n') {
            ++current_line;
            std::cout << (current_line==line ? "> " : "  ");
        }
    }
    std::cout << std::endl;
}

bool is_prefix(const std::string& s, const std::string& of) {
    if (s.size() > of.size()) return false;
    return std::equal(s.begin(), s.end(), of.begin());
}

bool is_suffix(const std::string& s, const std::string& of) {
    if (s.size() > of.size()) return false;
    auto diff = of.size() - s.size();
    return std::equal(s.begin(), s.end(), of.begin() + diff);
}

siginfo_t debugger::get_signal_info() {
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
    return info;
}

void debugger::handle_sigtrap(siginfo_t info) {
    switch (info.si_code) {
    case SI_KERNEL:
    case TRAP_BRKPT:
    {
        std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << std::endl;
        auto line_entry = get_current_line_entry();
        print_source(line_entry.file->path, line_entry.line);
        return;
    }
    case TRAP_TRACE:
        std::cout << "Finished single stepping" << std::endl;
        return;
    default:
        std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
        return;
    }
}

void debugger::wait_for_signal() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);

    auto siginfo = get_signal_info();
    
    switch (siginfo.si_signo) {
    case SIGTRAP:
        handle_sigtrap(siginfo);
        break;
    case SIGSEGV:
        std::cout << "Yay, segfault" << std::endl;
        break;
    default:
        std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
    }
}

void debugger::continue_execution() {
    if (m_breakpoint && m_breakpoint->get_address() == get_pc() - 1) {
        m_breakpoint->disable();
        dump_registers();
        decrement_pc();
        dump_registers();        
//        single_step_instruction();
//        m_breakpoint->enable();
    }
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::single_step_instruction() {
    ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
    m_breakpoint = std::make_unique<breakpoint>(m_pid, addr);
    m_breakpoint->enable();
}

void debugger::set_breakpoint_at_source_line(const std::string& file, unsigned line) {
    for (const auto& cu : m_dwarf.compilation_units()) {
        if (is_suffix(file, at_name(cu.root()))) {
            const auto& lt = cu.get_line_table();

            for (const auto& entry : lt) {
                if (entry.is_stmt && entry.line == line) {
                    set_breakpoint_at_address(entry.address);
                    return;
                }
            }
        }
    }
}

void debugger::dump_registers() {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
    std::cout << "r15" << ' ' << std::hex << regs.r15 << std::endl;
    std::cout << "r14" << ' ' << std::hex << regs.r14 << std::endl;
    std::cout << "r13" << ' ' << std::hex << regs.r13 << std::endl;
    std::cout << "r12" << ' ' << std::hex << regs.r12 << std::endl;
    std::cout << "bp" << ' ' << std::hex << regs.rbp << std::endl;
    std::cout << "bx" << ' ' << std::hex << regs.rbx << std::endl;
    std::cout << "r11" << ' ' << std::hex << regs.r11 << std::endl;
    std::cout << "r10" << ' ' << std::hex << regs.r10 << std::endl;
    std::cout << "r9" << ' ' << std::hex << regs.r9 << std::endl;
    std::cout << "r8" << ' ' << std::hex << regs.r8 << std::endl;
    std::cout << "ax" << ' ' << std::hex << regs.rax << std::endl;
    std::cout << "cx" << ' ' << std::hex << regs.rcx << std::endl;
    std::cout << "dx" << ' ' << std::hex << regs.rdx << std::endl;
    std::cout << "si" << ' ' << std::hex << regs.rsi << std::endl;
    std::cout << "di" << ' ' << std::hex << regs.rdi << std::endl;
    std::cout << "orig_ax" << ' ' << std::hex << regs.orig_rax << std::endl;
    std::cout << "ip" << ' ' << std::hex << regs.rip << std::endl;
    std::cout << "cs" << ' ' << std::hex << regs.cs << std::endl;
    std::cout << "flags" << ' ' << std::hex << regs.eflags << std::endl;
    std::cout << "sp" << ' ' << std::hex << regs.rsp << std::endl;
    std::cout << "ss" << ' ' << std::hex << regs.ss << std::endl;
    std::cout << "fs_base" << ' ' << std::hex << regs.fs_base << std::endl;
    std::cout << "gs_base" << ' ' << std::hex << regs.gs_base << std::endl;
    std::cout << "ds" << ' ' << std::hex << regs.ds << std::endl;
    std::cout << "es" << ' ' << std::hex << regs.es << std::endl;
    std::cout << "fs" << ' ' << std::hex << regs.fs << std::endl;
    std::cout << "gs" << ' ' << std::hex << regs.gs << std::endl;
}

void debugger::handle_command(const std::string& line) {
    if (is_prefix(line, "cont")) {
        continue_execution();
    }
    else if (is_prefix(line, "line")) {
        auto line_entry = get_current_line_entry();
        std::cout << line_entry.file->path << ':' << line_entry.line << std::endl;
    }
    else if (is_prefix(line, "registers")) {
        dump_registers();
    }    
    else if (is_prefix(line, "pc")) {
        std::cout << std::hex << get_pc() << std::endl;
    }
    else if(is_prefix(line, "break")) {
        set_breakpoint_at_source_line("hello.cpp", 4);
    }
    else if(is_prefix(line, "step")) {
        single_step_instruction();
    }
    else {
        std::cerr << "Unknown command\n";
    }
}

void execute_debugger (const std::string& prog_name, pid_t pid) {
    int wait_status;
    wait(&wait_status);

    debugger dbg{prog_name, pid};
    dbg.run();
}

void execute_debugee (const std::string& prog_name) {
  if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
      std::cerr << "Error in ptrace\n";
      return;
  }
  execl(prog_name.c_str(), prog_name.c_str(), nullptr);
}

int main(int argc, char* argv[]) {
    auto prog = argv[1];

    auto pid = fork();
    if (pid == 0) {
        //child
        execute_debugee(prog);

    }
    else if (pid >= 1)  {
        //parent
        execute_debugger(prog, pid);
    }
    else {
        std::cerr << "Error forking";
    }
}
