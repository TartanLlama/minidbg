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
private:
    void handle_command(const std::string& line);
    uint64_t get_pc();
    std::string get_current_line_entry();

    std::string m_prog_name;
    pid_t m_pid;
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;
};

uint64_t debugger::get_pc() {
  struct user_regs_struct regs;
  std::cout << ptrace(PTRACE_GETREGS, m_pid, NULL, &regs) << std::endl;
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
    while((line = linenoise("minidbg> ")) != NULL) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void debugger::handle_command(const std::string& line) {
    if (line == "cont") {
        ptrace(PTRACE_CONT, m_pid, NULL, NULL);
    }
    else if (line == "line") {
        std::cout << get_current_line_entry() << std::endl;
    }
    else if (line == "pc") {
        std::cout << std::hex << get_pc() << std::endl;
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
  execl(prog_name.c_str(), prog_name.c_str(), NULL);
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
