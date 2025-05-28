#include "sdb.hpp"

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>

#include "auxv.h"
#include "breakpoint.h"
#include "commands.h"
#include "program.h"
#include "ptools.h"
#include "utils.h"

std::unique_ptr<sdb::command_t> parse_cmd(const std::string &line) {}

int main(int argc, const char *argv[])
{
    std::string line;
    std::shared_ptr<sdb::program_t> program_ptr = nullptr;

    if (argc > 1)
    {
        auto command = sdb::load_program_t(argv[1]);
        program_ptr = command.execute(nullptr);
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

        auto command_ptr = parse_cmd(line);
        program_ptr = command_ptr->execute(program_ptr);
    }

    return 0;
}
