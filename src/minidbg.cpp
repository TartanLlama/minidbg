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
        : m_prog_name{std::move(prog_name)}, m_pid{pid} {}

    void run();
private:
    void handle_command(const std::string& line);

    std::string m_prog_name;
    pid_t m_pid;
};

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
    else {
        std::cerr << "Unknown command\n";
    }
}

void execute_debugger (const std::string& prog_name, pid_t pid) {
    int wait_status;
    wait(&wait_status);

    auto fd = open(prog_name.c_str(), O_RDONLY);

    elf::elf ef(elf::create_mmap_loader(fd));
    dwarf::dwarf dw(dwarf::elf::create_loader(ef));

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
