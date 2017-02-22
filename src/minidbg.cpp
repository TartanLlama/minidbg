#include <string>
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

class debugger {
public:
    debugger (std::string prog_name, pid_t pid)
        : m_prog_name{std::move(prog_name)}, m_pid{pid} {
            auto fd = open(m_prog_name.c_str(), O_RDONLY);

            m_elf = elf::elf{elf::create_mmap_loader(fd)};
            m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
        }

    void run();
    void continue_execution();
    void single_step_instruction();
    siginfo_t get_signal_info();
    void set_breakpoint_at_address(std::intptr_t addr);    
    void set_breakpoint_at_source_line(const std::string& file, std::size_t line);
    
private:
    void handle_command(const std::string& line);
    void handle_sigtrap(siginfo_t info);
    void wait_for_signal();    
    uint64_t get_pc();
    std::string get_current_line_entry();

    std::string m_prog_name;
    pid_t m_pid;
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;
    unsigned m_saved_data;
};

uint64_t debugger::get_pc() {
  struct user_regs_struct regs;
  std::cout << ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs) << std::endl;
  return regs.rip;
}

std::string debugger::get_current_line_entry() {
    auto pc = get_pc();

    for (auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(pc)) {
            return "";//at_name(cu.root());
            // Map PC to a line
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if (it == lt.end()) {
                return "";
            }
            else {
                return it->get_description();
            }
        }
    }

    return "";
}

void debugger::run() {
    char* line = nullptr;
    while((line = linenoise("minidbg> ")) != nullptr) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
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
        std::cout << "Hit breakpoint" << std::endl;
        return;
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
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::single_step_instruction() {
    ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
    m_saved_data = ptrace(PTRACE_PEEKTEXT, m_pid, (void*)addr, 0);
    auto int3 = 0xcc;
    auto data_with_int3 = (m_saved_data & ~0xff | int3);
    ptrace(PTRACE_POKETEXT, m_pid, (void*)addr, data_with_int3);
}

void debugger::set_breakpoint_at_source_line(const std::string& file, std::size_t line) {
    for (const auto& cu : m_dwarf.compilation_units()) {
        std::cerr << at_name(cu.root()) << std::endl;
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

void debugger::handle_command(const std::string& line) {
    if (line == "cont") {
        continue_execution();
    }
    else if (line == "line") {
        std::cout << get_current_line_entry() << std::endl;
    }
    else if (line == "pc") {
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
