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
#include <sstream>
#include <string>
#include <vector>

#include "auxv.h"
#include "breakpoint.h"
#include "commands.h"
#include "program.h"
#include "ptools.h"
#include "utils.h"

std::unique_ptr<sdb::command_t> parse_cmd(const std::string &line)
{
    std::stringstream ss(line);

    // parse command
    std::string cmd;
    ss >> cmd;

    // parse arguments
    std::string tmp;
    std::vector<std::string> args;
    while (ss >> tmp)
    {
        args.push_back(tmp);
    }

    std::unique_ptr<sdb::command_t> cmd_ptr = nullptr;
    if (cmd == "load" && args.size() >= 1)
    {
        cmd_ptr = std::make_unique<sdb::load_program_t>(args[0]);
    }
    else if (cmd == "si")
    {
        cmd_ptr = std::make_unique<sdb::single_step_t>();
    }
    else if (cmd == "cont")
    {
        cmd_ptr = std::make_unique<sdb::continue_t>();
    }
    else if (cmd == "info" && args.size() >= 1)
    {
        cmd = args[0];
        if (cmd == "reg")
        {
            cmd_ptr = std::make_unique<sdb::info_regs_t>();
        }
        else if (cmd == "break")
        {
            cmd_ptr = std::make_unique<sdb::info_breakpoints_t>();
        }
    }
    else if ((cmd == "break" || cmd == "breakrva") && args.size() >= 1)
    {
        cmd_ptr = std::make_unique<sdb::add_breakpoint_t>(args[0]);
    }
    else if (cmd == "delete" && args.size() >= 1)
    {
        cmd_ptr = std::make_unique<sdb::remove_breakpoint_t>(args[0]);
    }
    else if (cmd == "patch" && args.size() >= 2)
    {
        cmd_ptr = std::make_unique<sdb::patch_mem_t>(args[0], args[1]);
    }
    else if (cmd == "syscall")
    {
        cmd_ptr = std::make_unique<sdb::syscall_t>();
    }

    if (!cmd_ptr)
    {
        std::cerr << "** unknown/invalid command." << std::endl;
    }
    else if (!cmd_ptr->validate())
    {
        cmd_ptr = nullptr;
    }
    return cmd_ptr;
}

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
        if (command_ptr)
        {
            program_ptr = command_ptr->execute(program_ptr);
        }
    }

    return 0;
}
