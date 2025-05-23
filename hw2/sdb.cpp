#include "sdb.hpp"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

void add_breakpoint(sdb::program_t& program_ptr, uintptr_t address) {}

void remove_breakpoint(sdb::program_t& program_ptr, uintptr_t address) {}

void print_instructions() {}

// load the program
std::unique_ptr<sdb::program_t> load_program(std::string program)
{
    pid_t pid;
    if ((pid = fork()) < 0)
    {
        std::cerr << "** fork failed - " << strerror(errno) << std::endl;
        return nullptr;
    }

    // child process
    if (pid == 0)
    {
        char* const argv[] = {program.data()};
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
        {
            std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
            exit(EXIT_FAILURE);
        }
        execvp(program.c_str(), argv);
        std::cerr << "** exec failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    // parent process
    else
    {
        int status;
        if (!sdb::wait_pid(pid, &status, 0))
        {
            return nullptr;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status))
        {
            std::cerr << "** waitpid failed - the program is exited."
                      << std::endl;
            return nullptr;
        }
        if (!WIFSTOPPED(status))
        {
            std::cerr << "** waitpid failed - the program is not a tracee."
                      << std::endl;
            return nullptr;
        }
    }

    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        sdb::kill_and_wait(pid, SIGKILL);
        return nullptr;
    }

    auto program_ptr = std::make_unique<sdb::program_t>();
    program_ptr->program = program;
    program_ptr->pid = pid;

    sdb::load_maps(pid, program_ptr->maps);
    sdb::load_auxvs(pid, program_ptr->auxvs);

    // set the breakpoint at entry point
    add_breakpoint(*program_ptr, program_ptr->entry_point_address());

    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        sdb::kill_and_wait(pid, SIGKILL);
        return nullptr;
    }

    // TODO: wait until reach the breakpoint

    // TODO: print 5 instructuions

    return program_ptr;
}

int main(int argc, const char* argv[])
{
    int wait_status;
    std::string line;
    std::unique_ptr<sdb::program_t> program_ptr = nullptr;

    if (argc > 1)
    {
        program_ptr = load_program(argv[1]);
        return 0;
    }

    do
    {
        std::cout << sdb::MSG_PREFIX;
        std::getline(std::cin, line);
        line = sdb::strip(line);
        if (std::cin.eof() || line == "exit" || line == "quit")
        {
            break;
        }
        else if (line.length() == 0)
        {
            continue;
        }

        // TODO: parse the command

        // TODO: handle the command

        if (!sdb::wait_pid(program_ptr->pid, &wait_status, 0))
        {
            return EXIT_FAILURE;
        }
    } while (WIFSTOPPED(wait_status));
    return 0;
}
