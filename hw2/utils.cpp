#include "utils.h"

#include <signal.h>
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

}  // namespace sdb
