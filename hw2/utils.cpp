#include "utils.h"

#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include <cctype>
#include <cerrno>
#include <cstring>
#include <iomanip>
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

bool wait_pid_trapped(pid_t pid, int *status, int options)
{
    if (!wait_pid(pid, status, options))
    {
        exit(EXIT_FAILURE);
    }
    if (!WIFSTOPPED(*status))
    {
        std::cerr << "** the target program terminated." << std::endl;
        return false;
    }
    auto signal = WSTOPSIG(*status) & SIGTRAP;
    if (signal != SIGTRAP)
    {
        std::cerr << "** the program is stopped by the unhandled signal, "
                  << strsignal(signal) << "." << std::endl;
        exit(EXIT_FAILURE);
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

struct user_regs_struct get_registers(pid_t pid)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0)
    {
        std::cerr << "** ptrace failed - " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    return regs;
}

void print_instructions(pid_t pid, uintptr_t rip, size_t count, maps_t &maps)
{
    csh handle;
    cs_insn *insns;
    uint8_t buf[INSNS_BUF_SIZE] = {0};

    // read the instructions
    auto [aligned_addr, remainder] = align_address(rip);
    for (uintptr_t addr = aligned_addr; addr < aligned_addr + sizeof(buf);
         addr += PEEK_SIZE)
    {
        errno = 0;
        auto word = ptrace(PTRACE_PEEKTEXT, pid, addr, 0);
        if (errno != 0) break;

        // make sure don't exceed the executable region.
        // auto size = PEEK_SIZE;
        // while (size > 0 && !is_executable(pid, maps, addr + size - 1))
        // {
        //     size--;
        // }
        memcpy(buf + addr - aligned_addr, &word, PEEK_SIZE);
        // if (size != PEEK_SIZE) break;
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
        if (!is_executable(pid, maps, insn.address))
        {
            std::cerr << "** the address is out of the range of the executable "
                         "region."
                      << std::endl;
            break;
        }

        std::cout << "\t" << std::hex << insn.address << ": ";
        for (size_t j = 0; j < insn.size; j++)
        {
            std::cout << std::hex << std::setfill('0') << std::setw(2)
                      << +insn.bytes[j] << " ";
        }
        for (size_t j = insn.size; j <= MAX_INSN_SIZE; j++)
        {
            std::cout << std::setfill(' ') << std::setw(3) << "";
        }
        std::cout << insn.mnemonic << "\t" << insn.op_str << std::endl;
    }

    cs_free(insns, actual_count);
    cs_close(&handle);
}

bool is_hex_string(std::string content)
{
    if (content.size() == 0)
    {
        return false;
    }

    std::string __content = content;
    if (__content.size() > 2 && __content[0] == '0' && __content[1] == 'x')
    {
        __content = __content.substr(2);
    }
    for (unsigned char letter : __content)
    {
        if (!std::isxdigit(letter))
        {
            return false;
        }
    }
    return true;
}

}  // namespace sdb
