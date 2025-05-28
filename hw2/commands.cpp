#include "commands.h"

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <cstring>

#include "utils.h"

namespace sdb
{

load_program_t::load_program_t(std::string path) : path(path) {}

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
        if (!wait_pid_stopped(pid, &status, 0))
        {
            return nullptr;
        }
        if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL) < 0)
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
    if (!wait_pid_stopped(pid, &status, 0))
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

}  // namespace sdb
