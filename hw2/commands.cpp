#include "commands.h"

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <cctype>
#include <cstring>
#include <iomanip>

#include "sdb.hpp"
#include "utils.h"

namespace sdb
{

bool command_t::validate() const { return true; }

load_program_t::load_program_t(std::string path) : path(path) {}

bool load_program_t::validate() const
{
    if (path.size() == 0)
    {
        std::cerr << "** the program path is not valid." << std::endl;
        return false;
    }
    return true;
}

std::shared_ptr<program_t> load_program_t::execute(
    std::shared_ptr<program_t> __attribute__((unused)) program)
{
    std::unique_ptr<program_t> program_ptr = nullptr;
    int status;
    pid_t pid;
    if ((pid = fork()) < 0)
    {
        std::cerr << "** fork failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }

    // child process
    if (pid == 0)
    {
        char* const argv[] = {path.data()};
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
        {
            std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
            exit(EXIT_FAILURE);
        }
        execvp(path.c_str(), argv);
        std::cerr << "** exec failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    // parent process
    else
    {
        if (!wait_pid_trapped(pid, &status, 0))
        {
            return nullptr;
        }
        if (ptrace(PTRACE_SETOPTIONS, pid, 0,
                   PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) < 0)
        {
            std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
            kill_and_wait(pid, SIGKILL);
            exit(EXIT_FAILURE);
        }
    }

    program_ptr = std::make_unique<program_t>();
    program_ptr->program = path;
    program_ptr->pid = pid;

    load_maps(pid, program_ptr->maps);
    load_auxvs(pid, program_ptr->auxvs);

    // set the breakpoint at entry point
    auto original_byte =
        replace_address(pid, program_ptr->entry_point_address(), 0xcc);

    // continue until reach the breakpoint
    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    if (!wait_pid_trapped(pid, &status, 0))
    {
        exit(EXIT_FAILURE);
    }

    std::cout << "** program '" << path << "' loaded. entry point: 0x"
              << std::hex << program_ptr->entry_point_address() << "."
              << std::endl;

    // remove the breakpoint, print instructions, and add the breakpoint
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    auto rip = regs.rip - 1;

    replace_address(pid, rip, original_byte);
    print_instructions(pid, rip, 5, program_ptr->maps);

    regs.rip = rip;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }

    return program_ptr;
}

std::shared_ptr<program_t> single_step_t::execute(
    std::shared_ptr<program_t> program)
{
    if (!program)
    {
        std::cerr << "** please load a program first." << std::endl;
        return program;
    }

    auto pid = program->pid;
    int status;

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    if (!wait_pid_trapped(pid, &status, 0))
    {
        return nullptr;
    }

    auto regs = get_registers(pid);
    // single step won't be trapped by the breakpoint.
    // because we always check the next instruction.
    auto hit = program->breakpoints.hit(regs.rip);

    // avoid printing 0xcc instruction
    program->breakpoints.disable_all(pid);
    print_instructions(pid, regs.rip, 5, program->maps);
    program->breakpoints.enable_all(pid);

    if (hit)
    {
        // must disable the hit breakpoint for further execution
        program->breakpoints.disable(pid, regs.rip);
    }

    return program;
}

std::shared_ptr<program_t> continue_t::execute(
    std::shared_ptr<program_t> program)
{
    if (!program)
    {
        std::cerr << "** please load a program first." << std::endl;
        return program;
    }

    auto pid = program->pid;
    int status;

    // if the breakpoint in current rip is disabled and there is a loop among
    // them, we need to do a single step first to re-enable it to keep stateless
    // among commands.
    auto regs = get_registers(pid);
    if (program->breakpoints.exist_by_address(regs.rip) &&
        program->breakpoints.disabled(regs.rip))
    {
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0)
        {
            std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
            exit(EXIT_FAILURE);
        }
        if (!wait_pid_trapped(pid, &status, 0))
        {
            return nullptr;
        }

        // re-enable it
        program->breakpoints.enable(pid, regs.rip);
    }

    // normal continue execution
    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    if (!wait_pid_trapped(pid, &status, 0))
    {
        return nullptr;
    }

    regs = get_registers(pid);

    // restore the rip to the breakpoint
    regs.rip--;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }

    if (!program->breakpoints.hit(regs.rip))
    {
        std::cerr << "** continue failed - stop at the unknown state"
                  << std::endl;
        exit(EXIT_FAILURE);
    }

    // avoid printing 0xcc instruction
    program->breakpoints.disable_all(pid);
    print_instructions(pid, regs.rip, 5, program->maps);
    program->breakpoints.enable_all(pid);

    // must disable the hit breakpoint for further execution
    program->breakpoints.disable(pid, regs.rip);

    return program;
}

std::shared_ptr<program_t> info_regs_t::execute(
    std::shared_ptr<program_t> program)
{
    if (!program)
    {
        std::cerr << "** please load a program first." << std::endl;
        return program;
    }

    auto pid = program->pid;

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }

    print_register("$rax", regs.rax);
    print_register("$rbx", regs.rbx);
    print_register("$rcx", regs.rcx);
    std::cout << std::endl;
    print_register("$rdx", regs.rdx);
    print_register("$rsi", regs.rsi);
    print_register("$rdi", regs.rdi);
    std::cout << std::endl;
    print_register("$rbp", regs.rbp);
    print_register("$rsp", regs.rsp);
    print_register("$r8", regs.r8);
    std::cout << std::endl;
    print_register("$r9", regs.r9);
    print_register("$r10", regs.r10);
    print_register("$r11", regs.r11);
    std::cout << std::endl;
    print_register("$r12", regs.r12);
    print_register("$r13", regs.r13);
    print_register("$r14", regs.r14);
    std::cout << std::endl;
    print_register("$r15", regs.r15);
    print_register("$rip", regs.rip);
    print_register("$eflags", regs.eflags);
    std::cout << std::endl;

    return program;
}

void info_regs_t::print_register(std::string name, uintptr_t content) const
{
    std::cout << name << " 0x" << std::hex << std::setfill('0')
              << std::setw(WORD_SIZE * 2) << content << "\t";
}

add_breakpoint_t::add_breakpoint_t(std::string address_or_offset)
    : address_or_offset(address_or_offset)
{
}

bool add_breakpoint_t::validate() const
{
    if (address_or_offset.size() == 0)
    {
        std::cerr << "** the target address is not valid." << std::endl;
        return false;
    }
    if (is_hex_string(address_or_offset))
    {
        std::cerr << "** the target address is not valid." << std::endl;
        return false;
    }
    return true;
}

std::shared_ptr<program_t> add_breakpoint_t::execute(
    std::shared_ptr<program_t> program)
{
    if (!program)
    {
        std::cerr << "** please load a program first." << std::endl;
        return program;
    }

    auto pid = program->pid;
    uintptr_t __address_or_offset = std::stoul(address_or_offset, nullptr, 16);

    // calculate address
    if (!is_executable(pid, program->maps, __address_or_offset))
    {
        auto base_addr = program->base_address();
        __address_or_offset += base_addr;
    }

    auto id = program->breakpoints.add(pid, __address_or_offset, program->maps);
    if (id < 0)
    {
        return program;
    }

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }

    // if the new breakpoint is set at the current rip, skip it.
    if (regs.rip == __address_or_offset)
    {
        program->breakpoints.disable(pid, __address_or_offset);
    }

    return program;
}

std::shared_ptr<program_t> info_breakpoints_t::execute(
    std::shared_ptr<program_t> program)
{
    if (!program)
    {
        std::cerr << "** please load a program first." << std::endl;
        return program;
    }

    std::cout << program->breakpoints << std::endl;

    return program;
}

remove_breakpoint_t::remove_breakpoint_t(std::string id) : id(id) {}

bool remove_breakpoint_t::validate() const
{
    if (id.size() == 0)
    {
        std::cerr << "** the breakpoint id is not valid." << std::endl;
        return false;
    }
    for (unsigned char digit : id)
    {
        if (!std::isdigit(digit))
        {
            std::cerr << "** the breakpoint id is not valid." << std::endl;
            return false;
        }
    }
    return true;
}

std::shared_ptr<program_t> remove_breakpoint_t::execute(
    std::shared_ptr<program_t> program)
{
    if (!program)
    {
        std::cerr << "** please load a program first." << std::endl;
        return program;
    }

    size_t __id = std::stoul(id);
    program->breakpoints.remove_by_id(program->pid, __id);

    return program;
}

patch_mem_t::patch_mem_t(std::string address, std::string content)
    : address(address), content(content)
{
}

bool patch_mem_t::validate() const
{
    if (address.size() == 0 || !is_hex_string(address))
    {
        std::cerr << "** the target address is not valid." << std::endl;
        return false;
    }
    if (content.size() < 1 || content.size() > 2048 ||
        content.size() % 2 != 0 || !is_hex_string(content))
    {
        std::cerr << "** the patch content is not valid." << std::endl;
        return false;
    }
    return true;
}

std::shared_ptr<program_t> patch_mem_t::execute(
    std::shared_ptr<program_t> program)
{
    if (!program)
    {
        std::cerr << "** please load a program first." << std::endl;
        return program;
    }

    auto pid = program->pid;
    uintptr_t __address = std::stoul(address, nullptr, 16);

    if (!is_valid(pid, program->maps, __address))
    {
        std::cerr << "** the target address is not valid." << std::endl;
        return program;
    }

    auto bytes = to_bytes(content);
    if (!is_valid(pid, program->maps, __address + bytes.size() - 1))
    {
        std::cerr << "** the target address is not valid." << std::endl;
        return program;
    }

    for (size_t i = 0; i < bytes.size(); i++)
    {
        auto target_addr = __address + i;
        auto byte = bytes[i];

        if (program->breakpoints.exist_by_address(target_addr))
        {
            program->breakpoints.patch(pid, target_addr, byte);
        }
        else
        {
            replace_address(pid, target_addr, byte);
        }
    }

    std::cout << "** patch memory at [0x" << std::hex << __address << "]."
              << std::endl;

    return program;
}

std::vector<uint8_t> patch_mem_t::to_bytes(std::string data) const
{
    if (data.at(0) == '0' && data.at(1) == 'x')
    {
        data = data.substr(2);
    }
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < data.size(); i += 2)
    {
        auto byte =
            static_cast<uint8_t>(std::stoul(data.substr(i, 2), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::shared_ptr<program_t> syscall_t::execute(
    std::shared_ptr<program_t> program)
{
    if (!program)
    {
        std::cerr << "** please load a program first." << std::endl;
        return program;
    }

    auto pid = program->pid;
    int status;

    // syscall will act like the continue command, but also be trapped by the
    // syscall. If the breakpoint in current rip is disabled and there is a loop
    // among them, we need to do a single step first to re-enable it to keep
    // stateless among commands.
    auto regs = get_registers(pid);
    if (program->breakpoints.exist_by_address(regs.rip) &&
        program->breakpoints.disabled(regs.rip))
    {
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0)
        {
            std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
            exit(EXIT_FAILURE);
        }
        if (!wait_pid_trapped(pid, &status, 0))
        {
            return nullptr;
        }

        // re-enable it
        program->breakpoints.enable(pid, regs.rip);
    }

    // normal syscall execution
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    if (!wait_pid_trapped(pid, &status, 0))
    {
        return nullptr;
    }

    regs = get_registers(pid);

    auto trapped_by_syscall = (WSTOPSIG(status) & 0x80) == 0x80;
    if (trapped_by_syscall)
    {
        static bool entered = false;
        if (entered)
        {
            std::cout << "** leave a syscall(" << std::dec << regs.orig_rax
                      << ") = " << regs.rax << " at 0x" << std::hex
                      << regs.rip - 2 << "." << std::endl;
        }
        else
        {
            std::cout << "** enter a syscall(" << std::dec << regs.orig_rax
                      << ") at 0x" << std::hex << regs.rip - 2 << "."
                      << std::endl;
        }
        entered = !entered;
    }
    // trapped by a breakpoint
    else
    {
        // restore the rip to the breakpoint
        regs.rip--;
        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0)
        {
            std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
            exit(EXIT_FAILURE);
        }

        if (!program->breakpoints.hit(regs.rip))
        {
            std::cerr << "** continue failed - stop at the unknown state"
                      << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    // avoid printing 0xcc instruction
    program->breakpoints.disable_all(pid);
    print_instructions(pid, regs.rip, 5, program->maps);
    program->breakpoints.enable_all(pid);

    if (!trapped_by_syscall)
    {
        // must disable the hit breakpoint for further execution
        program->breakpoints.disable(pid, regs.rip);
    }

    return program;
}

}  // namespace sdb
