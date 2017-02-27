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
        m_saved_data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
        uint64_t int3 = 0xcc;
        uint64_t data_with_int3 = ((m_saved_data & ~0xff) | int3); //set bottom two bytes to 0xcc
        ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3);

        m_enabled = true;
    }

    void disable() {
        ptrace(PTRACE_POKEDATA, m_pid, m_addr, m_saved_data);
        m_enabled = false;
    }

    bool is_enabled() { return m_enabled; }

    auto get_address() -> std::intptr_t { return m_addr; }
private:
    pid_t m_pid;
    std::intptr_t m_addr;
    bool m_enabled;
    uint64_t m_saved_data; //data which used to be at the breakpoint address
};

enum class reg {
    rax, rbx, rcx, rdx,
    rdi, rsi, rbp, rsp,
    r8,  r9,  r10, r11,
    r12, r13, r14, r15,
    rip, rflags,    cs,
    fs, gs, ss, ds, es
};

constexpr std::size_t n_registers = 25;


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
    auto read_memory(uint64_t address) -> uint64_t;
    void write_memory(uint64_t address, uint64_t value);
    void print_backtrace();
    void read_variables();
    void continue_execution();
    void single_step_instruction();
    auto get_signal_info() -> siginfo_t;
    void set_breakpoint_at_function(const std::string& name);
    void set_breakpoint_at_address(std::intptr_t addr);
    void set_breakpoint_at_source_line(const std::string& file, unsigned line);
    void print_source(const std::string& file_name, unsigned line, unsigned n_lines_context=2);

private:
    void unchecked_single_step_instruction(); //single step without checking breakpoints
    void handle_command(const std::string& line);
    void handle_sigtrap(siginfo_t info);
    void wait_for_signal();
    auto get_pc() -> uint64_t;
    void set_pc(uint64_t pc);
    auto get_current_line_entry() -> dwarf::line_table::entry;
    auto get_current_compilation_unit() -> dwarf::compilation_unit;
    auto get_function_at_pc(uint64_t pc) -> dwarf::die;

    std::string m_prog_name;
    pid_t m_pid;
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;
    unsigned m_saved_data;
    std::unordered_map<uint64_t,breakpoint> m_breakpoints;
};

uint64_t get_register_value(pid_t pid, reg r) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    switch (r) {
    case reg::rax: return regs.rax;
    case reg::rbx: return regs.rbx;
    case reg::rcx: return regs.rcx;
    case reg::rdx: return regs.rdx;
    case reg::rdi: return regs.rdi;
    case reg::rsi: return regs.rsi;
    case reg::rbp: return regs.rbp;
    case reg::rsp: return regs.rsp;
    case reg::r8: return regs.r8;
    case reg::r9: return regs.r9;
    case reg::r10: return regs.r10;
    case reg::r11: return regs.r11;
    case reg::r12: return regs.r12;
    case reg::r13: return regs.r13;
    case reg::r14: return regs.r14;
    case reg::r15: return regs.r15;
    case reg::rip: return regs.rip;
    case reg::rflags: return regs.eflags;
    case reg::cs: return regs.cs;
    case reg::fs: return regs.fs;
    case reg::gs: return regs.gs;
    case reg::ss: return regs.ss;
    case reg::ds: return regs.ds;
    case reg::es: return regs.es;
    }
}

void set_register_value(pid_t pid, reg r, uint64_t value) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    switch (r) {
    case reg::rax: regs.rax = value; break;
    case reg::rbx: regs.rbx = value; break;
    case reg::rcx: regs.rcx = value; break;
    case reg::rdx: regs.rdx = value; break;
    case reg::rdi: regs.rdi = value; break;
    case reg::rsi: regs.rsi = value; break;
    case reg::rbp: regs.rbp = value; break;
    case reg::rsp: regs.rsp = value; break;
    case reg::r8: regs.r8 = value; break;
    case reg::r9: regs.r9 = value; break;
    case reg::r10: regs.r10 = value; break;
    case reg::r11: regs.r11 = value; break;
    case reg::r12: regs.r12 = value; break;
    case reg::r13: regs.r13 = value; break;
    case reg::r14: regs.r14 = value; break;
    case reg::r15: regs.r15 = value; break;
    case reg::rip: regs.rip = value; break;
    case reg::rflags: regs.eflags = value; break;
    case reg::cs: regs.cs = value; break;
    case reg::fs: regs.fs = value; break;
    case reg::gs: regs.gs = value; break;
    case reg::ss: regs.ss = value; break;
    case reg::ds: regs.ds = value; break;
    case reg::es: regs.es = value; break;
    }
    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}

uint64_t get_register_value_from_dwarf_register (pid_t pid, unsigned regnum) {
    reg r;

    switch (regnum) {
    case 0: r = reg::rax; break;
    case 1: r = reg::rdx; break;
    case 2: r = reg::rcx; break;
    case 3: r = reg::rbx; break;
    case 4: r = reg::rsi; break;
    case 5: r = reg::rdi; break;
    case 6: r = reg::rbp; break;
    case 7: r = reg::rsp; break;
    case 8: r = reg::r8; break;
    case 9: r = reg::r9; break;
    case 10: r = reg::r10; break;
    case 11: r = reg::r11; break;
    case 12: r = reg::r12; break;
    case 13: r = reg::r13; break;
    case 14: r = reg::r14; break;
    case 15: r = reg::r15; break;
    case 49: r = reg::rflags; break;
    case 50: r = reg::es; break;
    case 51: r = reg::cs; break;
    case 52: r = reg::ss; break;
    case 53: r = reg::fs; break;
    case 54: r = reg::gs; break;
    default: throw std::out_of_range{"Unknown register " + std::to_string(regnum)};
    }

    return get_register_value(pid, r);
}

std::string get_register_name(reg r) {
    switch (r) {
    case reg::rax: return "rax";
    case reg::rbx: return "rbx";
    case reg::rcx: return "rcx";
    case reg::rdx: return "rdx";
    case reg::rdi: return "rdi";
    case reg::rsi: return "rsi";
    case reg::rbp: return "rbp";
    case reg::rsp: return "rsp";
    case reg::r8: return "r8";
    case reg::r9: return "r9";
    case reg::r10: return "r10";
    case reg::r11: return "r11";
    case reg::r12: return "r12";
    case reg::r13: return "r13";
    case reg::r14: return "r14";
    case reg::r15: return "r15";
    case reg::rip: return "rip";
    case reg::rflags: return "rflags";
    case reg::cs: return "cs";
    case reg::fs: return "fs";
    case reg::gs: return "gs";
    case reg::ss: return "ss";
    case reg::ds: return "ds";
    case reg::es: return "es";
    }
}

uint64_t debugger::get_pc() {
    return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc) {
    set_register_value(m_pid, reg::rip, pc);
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
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);

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
    //one of these will be set if a breakpoint was hit
    case SI_KERNEL:
    case TRAP_BRKPT:
    {
        set_pc(get_pc()-1);
        std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << std::endl;
        auto line_entry = get_current_line_entry();
        print_source(line_entry.file->path, line_entry.line);
        return;
    }
    //this will be set if the signal was sent by single stepping
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
    //first, check to see if we need to disable and enable a breakpoint
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
    //first, check to see if we need to disable and enable a breakpoint
    if (m_breakpoints.count(get_pc())) {
        auto& bp = m_breakpoints[get_pc()];
        bp.disable();
        unchecked_single_step_instruction();
        bp.enable();
    }
    else {
        unchecked_single_step_instruction();
    }

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
            if (die.has(dwarf::DW_AT::name) && at_name(die) == name) {
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
    for (auto i = 0; i < n_registers; ++i) {
        auto r = static_cast<reg>(i);
        std::cout << get_register_name(r) << " 0x"
                  << std::setfill('0') << std::setw(16) << std::hex << get_register_value(m_pid, r) << std::endl;
    }
}

class ptrace_expr_context : public dwarf::expr_context {
public:
    ptrace_expr_context (pid_t pid) : m_pid{pid} {}

    dwarf::taddr reg (unsigned regnum) override {
        return get_register_value_from_dwarf_register(m_pid, regnum);
    }

    dwarf::taddr pc() override {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
        return regs.rip;
    }

    dwarf::taddr deref_size (dwarf::taddr address, unsigned size) override {
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

            //only supports exprlocs for now
            if (loc_val.get_type() == value::type::exprloc) {
                ptrace_expr_context context {m_pid};
                auto result = loc_val.as_exprloc().evaluate(&context);

                switch (result.location_type) {
                case expr_result::type::address:
                {
                    auto value = read_memory(result.value);
                    std::cout << at_name(die) << " (0x" << std::hex << result.value << ") = " << value << std::endl;
                    break;
                }

                case expr_result::type::reg:
                {
                    auto value = get_register_value_from_dwarf_register(m_pid, result.value);
                    std::cout << at_name(die) << " (reg " << result.value << ") = " << value << std::endl;
                    break;
                }

                default:
                    throw std::runtime_error{"Unhandled variable location"};
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

void debugger::write_memory(uint64_t address, uint64_t value) {
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
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

    auto frame_pointer = get_register_value(m_pid, reg::rbp);
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
    else if (is_prefix(command, "registers")) {
        dump_registers();
    }
    else if(is_prefix(command, "break")) {
        if (args[1][0] == '0' && args[1][1] == 'x') {
            std::string addr {args[1], 2};
            set_breakpoint_at_address(std::stol(addr, 0, 16));
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
    else if (is_prefix(command, "status")) {
        auto line_entry = get_current_line_entry();
        print_source(line_entry.file->path, line_entry.line);
    }
    else if(is_prefix(command, "memory")) {
        std::string addr {args[1], 2};
        std::cout << read_memory(std::stol(addr, 0, 16)) << std::endl;
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

void execute_debugee (const std::string& prog_name) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        std::cerr << "Error in ptrace\n";
        return;
    }
    execl(prog_name.c_str(), prog_name.c_str(), nullptr);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Program name not specified";
        return -1;
    }

    auto prog = argv[1];

    auto pid = fork();
    if (pid == 0) {
        //child
        execute_debugee(prog);

    }
    else if (pid >= 1)  {
        //parent
        debugger dbg{prog, pid};
        dbg.run();
    }
    else {
        std::cerr << "Error forking";
    }
}
