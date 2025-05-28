#include "sdb.hpp"

#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>

void print_instructions(pid_t pid, uintptr_t rip, size_t count,
                        sdb::maps_t &maps)
{
    csh handle;
    cs_insn *insns;
    uint8_t buf[sdb::INSNS_BUF_SIZE] = {0};

    // read the instructions
    auto [aligned_addr, remainder] = sdb::align_address(rip);
    for (uintptr_t addr = aligned_addr; addr < aligned_addr + sizeof(buf);
         addr += sdb::PEEK_SIZE)
    {
        errno = 0;
        auto word = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
        if (errno != 0) break;

        // make sure don't exceed the executable region.
        auto size = sdb::PEEK_SIZE;
        while (size > 0 && !sdb::is_executable(pid, maps, addr + size - 1))
        {
            size--;
        }
        memcpy(buf + addr - aligned_addr, &word, size);
        if (size != sdb::PEEK_SIZE) break;
    }

    // initialize capstone engine
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        std::cerr << "cs_open failed - " << cs_strerror(cs_errno(handle)) << "."
                  << std::endl;
        exit(EXIT_FAILURE);
    }
    // turn on SKIPDATA mode
    if (cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON) != CS_ERR_OK)
    {
        std::cerr << "cs_option failed - " << cs_strerror(cs_errno(handle))
                  << "." << std::endl;
        exit(EXIT_FAILURE);
    }

    size_t code_size = sizeof(buf) - (remainder + 1);
    size_t actual_count =
        cs_disasm(handle, buf + remainder, code_size, rip, count, &insns);
    if (actual_count == 0)
    {
        std::cerr << "cs_disasm failed - Failed to disassemble given code!."
                  << std::endl;
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < actual_count; i++)
    {
        auto insn = insns[i];
        std::cout << "\t" << std::hex << insn.address << ": ";
        for (size_t j = 0; j < insn.size; j++)
        {
            std::cout << std::hex << std::setfill('0') << std::setw(2)
                      << +insn.bytes[j] << " ";
        }
        for (size_t j = insn.size; j <= sdb::MAX_INSN_SIZE; j++)
        {
            std::cout << std::setfill(' ') << std::setw(3) << "";
        }
        std::cout << insn.mnemonic << "\t" << insn.op_str << std::endl;
    }
    if (actual_count != count)
    {
        std::cerr
            << "** the address is out of the range of the executable region."
            << std::endl;
    }

    cs_free(insns, actual_count);
    cs_close(&handle);
}

// load the program
std::unique_ptr<sdb::program_t> load_program(std::string program)
{
    std::unique_ptr<sdb::program_t> program_ptr = nullptr;
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
        if (!sdb::wait_pid_stopped(pid, &status, 0))
        {
            return nullptr;
        }
        if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL) < 0)
        {
            std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
            sdb::kill_and_wait(pid, SIGKILL);
            exit(EXIT_FAILURE);
        }
    }

    program_ptr = std::make_unique<sdb::program_t>();
    program_ptr->program = program;
    program_ptr->pid = pid;

    sdb::load_maps(pid, program_ptr->maps);
    sdb::load_auxvs(pid, program_ptr->auxvs);

    // set the breakpoint at entry point
    auto original_byte =
        sdb::replace_address(pid, program_ptr->entry_point_address(), 0xcc);

    // continue until reach the breakpoint
    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    if (!sdb::wait_pid_stopped(pid, &status, 0))
    {
        exit(EXIT_FAILURE);
    }

    std::cout << "** program '" << program << "' loaded. entry point: 0x"
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

    sdb::replace_address(pid, rip, original_byte);
    print_instructions(pid, rip, 5, program_ptr->maps);

    regs.rip = rip;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }

    return program_ptr;
}

int main(int argc, const char *argv[])
{
    int wait_status;
    std::string line;
    std::unique_ptr<sdb::program_t> program_ptr = nullptr;

    if (argc > 1)
    {
        program_ptr = load_program(argv[1]);
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

        // TODO: handle the command

        if (!sdb::wait_pid(program_ptr->pid, &wait_status, 0))
        {
            return EXIT_FAILURE;
        }
        if (!WIFSTOPPED(wait_status)) break;
    }
    return 0;
}
