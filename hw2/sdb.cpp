#include "sdb.h"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

struct debugger_state
{
    std::string program;
    pid_t pid;
    // TODO: base address
    // TODO: entry point

    // TODO: map from index to breakpoints
    // TODO: unordered_map from address to index/breakpoint
};

// load the program and stopped to wait for the tracer
std::unique_ptr<debugger_state> load_program(std::string program)
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
        char *const argv[] = {program.data()};
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
        if (waitpid(pid, &status, 0) < 0)
        {
            std::cerr << "** waitpid failed - " << strerror(errno) << std::endl;
            return nullptr;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status))
        {
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

    // TODO: find and store the base address, entry point
    // TODO: set the breakpoint at entry point

    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0)
    {
        ptrace(PTRACE_KILL, pid, 0, 0);
        sdb::kill_and_wait(pid, SIGKILL);
        return nullptr;
    }

    auto state_ptr = std::make_unique<debugger_state>();
    state_ptr->program = program;
    state_ptr->pid = pid;
    return state_ptr;
}

int main(int argc, const char *argv[])
{
    std::string line;
    std::unique_ptr<debugger_state> state_ptr = nullptr;

    if (argc > 1)
    {
        state_ptr = load_program(argv[1]);
    }

    while (true)
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

        // TODO: handle load
    }
    return 0;
}
