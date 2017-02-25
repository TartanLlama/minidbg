#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <iostream>
#include <iomanip>
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
    breakpoint() = default;
    breakpoint(pid_t pid, std::intptr_t addr) : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{} {}
    void enable() {
        m_saved_data = ptrace(PTRACE_PEEKTEXT, m_pid, (void*)m_addr, 0);
        uint64_t int3 = 0xcc;
        uint64_t data_with_int3 = (m_saved_data & ~0xff | int3);
        ptrace(PTRACE_POKETEXT, m_pid, (void*)m_addr, data_with_int3);

        m_enabled = true;
    }

    void disable() {
        ptrace(PTRACE_POKETEXT, m_pid, (void*)m_addr, m_saved_data);
        m_enabled = false;
    }

    bool is_enabled() { return m_enabled; }

    std::intptr_t get_address() { return m_addr; }
private:
    pid_t m_pid;
    std::intptr_t m_addr;
    bool m_enabled;
    uint64_t m_saved_data;
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
    uint64_t read_memory(uint64_t address);
    void print_backtrace();
    void read_variables();
    void continue_execution();
    void single_step_instruction();
    siginfo_t get_signal_info();
    void set_breakpoint_at_function(const std::string& name);
    void set_breakpoint_at_address(std::intptr_t addr);
    void set_breakpoint_at_source_line(const std::string& file, unsigned line);
    void print_source(const std::string& file_name, unsigned line, unsigned n_lines_context=2);

private:
    void unchecked_single_step_instruction();
    void handle_command(const std::string& line);
    void handle_sigtrap(siginfo_t info);
    void wait_for_signal();
    uint64_t get_pc();
    void set_pc(uint64_t pc);
    void decrement_pc();
    dwarf::line_table::entry get_current_line_entry();
    dwarf::compilation_unit get_current_compilation_unit();
    dwarf::die get_function_at_pc(uint64_t pc);

    std::string m_prog_name;
    pid_t m_pid;
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;
    unsigned m_saved_data;
    std::unordered_map<uint64_t,breakpoint> m_breakpoints;
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

dwarf::die debugger::get_function_at_pc(uint64_t pc) {
    auto cu = get_current_compilation_unit();
    for (const auto& die : cu.root()) {
        if (die.tag == dwarf::DW_TAG::subprogram) {
            if (die_pc_range(die).contains(pc)) {
                return die;
            }
        }
    }

    throw std::out_of_range{"Cannot find function"};
}

dwarf::compilation_unit debugger::get_current_compilation_unit() {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(get_pc())) {
            return cu;
        }
    }

    throw std::out_of_range{"Cannot find compilation unit"};
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
    auto start_line = line < n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;

    char c{};
    auto current_line = 1u;
    while (current_line != start_line && file.get(c)) {
        if (c == '\n') {
            ++current_line;
        }
    }
    std::cout << (current_line==line ? "> " : "  ");
    while (current_line <= end_line && file.get(c)) {
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
        decrement_pc();
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
        std::cout << "Yay, segfault. Reason: " << siginfo.si_code << std::endl;
        break;
    default:
        std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
    }
}

void debugger::continue_execution() {
    if (m_breakpoints.count(get_pc())) {
        auto& bp = m_breakpoints[get_pc()];
        bp.disable();
        unchecked_single_step_instruction();
        bp.enable();
    }

    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::unchecked_single_step_instruction() {
    ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::single_step_instruction() {
    if (m_breakpoints.count(get_pc())) {
        auto& bp = m_breakpoints[get_pc()];
        bp.disable();
        unchecked_single_step_instruction();
        bp.enable();
        auto line_entry = get_current_line_entry();
        print_source(line_entry.file->path, line_entry.line);
        return;
    }

    unchecked_single_step_instruction();
    auto line_entry = get_current_line_entry();
    print_source(line_entry.file->path, line_entry.line);
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
    breakpoint bp {m_pid, addr};
    bp.enable();
    m_breakpoints[addr] = bp;
}

void debugger::set_breakpoint_at_function(const std::string& name) {
    for (const auto& cu : m_dwarf.compilation_units()) {
        for (const auto& die : cu.root()) {
            if (at_name(die) == name) {
                set_breakpoint_at_address(at_low_pc(die));
                return;
            }
        }
    }
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
    std::cout << "rax 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.rax << std::endl;
    std::cout << "rbx 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.rbx << std::endl;
    std::cout << "rcx 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.rcx << std::endl;
    std::cout << "rdx 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.rdx << std::endl;
    std::cout << "rdi 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.rdi << std::endl;
    std::cout << "rsi 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.rsi << std::endl;
    std::cout << "rbp 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.rbp << std::endl;
    std::cout << "rsp 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.rsp << std::endl;
    std::cout << "r8 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.r8 << std::endl;
    std::cout << "r9 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.r9 << std::endl;
    std::cout << "r10 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.r10 << std::endl;
    std::cout << "r11 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.r11 << std::endl;
    std::cout << "r12 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.r12 << std::endl;
    std::cout << "r13 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.r13 << std::endl;
    std::cout << "r14 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.r14 << std::endl;
    std::cout << "r15 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.r15 << std::endl;
    std::cout << "rip 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.rip << std::endl;
    std::cout << "rflags 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.eflags << std::endl;
    std::cout << "cs 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.cs << std::endl;
    std::cout << "fs 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.fs << std::endl;
    std::cout << "gs 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.gs << std::endl;
    std::cout << "ss 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.ss << std::endl;
    std::cout << "ds 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.ds << std::endl;
    std::cout << "es 0x" << std::setfill('0') << std::setw(16) << std::hex << regs.es << std::endl;
}

uint64_t get_register_value_from_dwarf_register (pid_t pid, unsigned regnum) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

    switch (regnum) {
    case 0: return regs.rax;
    case 1: return regs.rdx;
    case 2: return regs.rcx;
    case 3: return regs.rbx;
    case 4: return regs.rsi;
    case 5: return regs.rdi;
    case 6: return regs.rbp;
    case 7: return regs.rsp;
    case 8: return regs.r8;
    case 9: return regs.r9;
    case 10: return regs.r10;
    case 11: return regs.r11;
    case 12: return regs.r12;
    case 13: return regs.r13;
    case 14: return regs.r14;
    case 15: return regs.r15;
    case 49: return regs.eflags;
    case 50: return regs.es;
    case 51: return regs.cs;
    case 52: return regs.ss;
    case 53: return regs.fs;
    case 54: return regs.gs;
    default: throw std::out_of_range{"Unknown register " + std::to_string(regnum)};
    }
}


class ptrace_expr_context : public dwarf::expr_context {
public:
    ptrace_expr_context (pid_t pid) : m_pid{pid} {}

    dwarf::taddr reg (unsigned regnum) override {
        return get_register_value_from_dwarf_register(m_pid, regnum);
    }

    dwarf::taddr deref_size (dwarf::taddr address, unsigned size) {
        //TODO take into account size
        return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
    }

private:
    pid_t m_pid;
};

void debugger::read_variables() {
    using namespace dwarf;

    auto func = get_function_at_pc(get_pc());
    for (const auto& die : func) {
        if (die.tag == DW_TAG::variable) {
            auto loc_val = die[DW_AT::location];
            if (loc_val.get_type() == value::type::exprloc) {
                ptrace_expr_context context {m_pid};
                auto result = loc_val.as_exprloc().evaluate(&context);

                switch (result.location_type) {
                case expr_result::type::address:
                {
                    auto value = ptrace(PTRACE_PEEKDATA, m_pid, result.value, nullptr);
                    std::cout << at_name(die) << " (0x" << std::hex << result.value << ") = " << value << std::endl;
                    break;
                }

                case expr_result::type::reg:
                {
                    struct user_regs_struct regs;
                    ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
                    std::cout << "reg is " << result.value << std::endl;
                    std::cout << "value is " << get_register_value_from_dwarf_register(m_pid, result.value);
                    break;
                }

                case expr_result::type::literal: std::cout << at_name(die) << ' ' << " in literal" << std::endl; break;
                case expr_result::type::implicit: std::cout << at_name(die) << ' ' << " in implict" << std::endl; break;
                case expr_result::type::empty: std::cout << at_name(die) << ' ' << " empty" << std::endl; break;
                }
            }
            else {
                throw std::runtime_error{"Unhandled variable location"};
            }
        }
    }
}

uint64_t debugger::read_memory(uint64_t address) {
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

std::vector<std::string> split(const std::string &s, char delimiter) {
    std::vector<std::string> out{};
    std::stringstream ss {s};
    std::string item;

    while (std::getline(ss,item,delimiter)) {
        out.push_back(item);
    }

    return out;
}

void debugger::print_backtrace() {
    auto frame_number = 0;
    auto current_func = get_function_at_pc(get_pc());

    auto output_frame = [&frame_number] (auto&& func) {
        std::cout << "frame #" << frame_number++ << ": 0x" << dwarf::at_low_pc(func)
                  << ' ' << dwarf::at_name(func) << std::endl;
    };

    output_frame(current_func);

    auto frame_pointer = get_register_value_from_dwarf_register(m_pid, 6);
    auto return_address = read_memory(frame_pointer+8);
    while (dwarf::at_name(current_func) != "main") {
        current_func = get_function_at_pc(return_address);
        output_frame(current_func);
        frame_pointer = read_memory(frame_pointer);
        return_address = read_memory(frame_pointer+8);
    }
}

void debugger::handle_command(const std::string& line) {
    auto args = split(line,' ');
    auto command = args[0];

    if (is_prefix(command, "cont")) {
        continue_execution();
    }
    else if (is_prefix(command, "line")) {
        auto line_entry = get_current_line_entry();
        std::cout << line_entry.file->path << ':' << line_entry.line << std::endl;
    }
    else if (is_prefix(command, "registers")) {
        dump_registers();
    }
    else if (is_prefix(command, "pc")) {
        std::cout << std::hex << get_pc() << std::endl;
    }
    else if(is_prefix(command, "break")) {
        if (args[1][0] == '0' && args[1][1] == 'x') {
            std::string addr {args[1], 2};
            set_breakpoint_at_address(std::stoi(addr, 0, 16));
        }
        else if (args[1].find(':') != std::string::npos) {
            auto file_and_line = split(args[1], ':');
            set_breakpoint_at_source_line(file_and_line[0], std::stoi(file_and_line[1]));
        }
        else {
            set_breakpoint_at_function(args[1]);
        }
    }
    else if(is_prefix(command, "step")) {
        single_step_instruction();
    }
    else if(is_prefix(command, "memory")) {
        read_memory(std::stoi(args[1]));
    }
    else if(is_prefix(command, "variables")) {
        read_variables();
    }
    else if(is_prefix(command, "backtrace")) {
        print_backtrace();
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
