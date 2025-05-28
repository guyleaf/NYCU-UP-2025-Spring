#include "utils.h"

#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <cctype>
#include <cerrno>
#include <cstring>
#include <iostream>

#include "sdb.hpp"

namespace sdb
{

std::string lstrip(const std::string &string)
{
    for (auto start_iter = string.begin(); start_iter != string.end();
         start_iter++)
    {
        if (!std::isspace(*start_iter))
        {
            return std::string(start_iter, string.end());
        }
    }
    return std::string();
}

std::string rstrip(const std::string &string)
{
    if (string.empty())
    {
        return std::string();
    }

    auto end_iter = string.end() - 1;
    for (; end_iter != string.begin(); end_iter--)
    {
        if (!std::isspace(*end_iter))
        {
            end_iter++;
            return std::string(string.begin(), end_iter);
        }
    }

    if (std::isspace(*end_iter))
    {
        return std::string();
    }
    else
    {
        return string;
    }
}

std::string strip(const std::string &string) { return rstrip(lstrip(string)); }

void kill_and_wait(pid_t pid, int sig)
{
    if (kill(pid, sig) < 0)
    {
        std::cerr << "kill failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    if (!wait_pid(pid, nullptr, 0))
    {
        exit(EXIT_FAILURE);
    }
}

bool wait_pid(pid_t pid, int *status, int options)
{
    if (waitpid(pid, status, options) < 0)
    {
        std::cerr << "** waitpid failed - " << strerror(errno) << std::endl;
        return false;
    }
    return true;
}

bool wait_pid_stopped(pid_t pid, int *status, int options)
{
    if (!sdb::wait_pid(pid, status, options))
    {
        return false;
    }
    if (!WIFSTOPPED(*status))
    {
        std::cerr << "** waitpid failed - the program is terminated."
                  << std::endl;
        return false;
    }
    return true;
}

std::tuple<uintptr_t, uintptr_t> align_address(uintptr_t address)
{
    auto remainder = address % sizeof(uintptr_t);
    return std::make_tuple(address - remainder, remainder);
}

uint8_t replace_address(pid_t pid, uintptr_t address, uint8_t data)
{
    auto [aligned_address, remainder] = align_address(address);

    /*
        Reference: https://man7.org/linux/man-pages/man2/ptrace.2.html
        Since the value returned by a successful PTRACE_PEEK*
        operation may be -1, the caller must clear errno before the call,
        and then check it afterward to determine whether or not an error
        occurred.s
     */
    errno = 0;
    auto word = ptrace(PTRACE_PEEKTEXT, pid, aligned_address, 0);
    if (errno != 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }

    auto bytes = reinterpret_cast<uint8_t *>(&word);
    auto original_data = bytes[remainder];
    bytes[remainder] = data;

    if (ptrace(PTRACE_POKETEXT, pid, aligned_address, word) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    return original_data;
}

}  // namespace sdb
