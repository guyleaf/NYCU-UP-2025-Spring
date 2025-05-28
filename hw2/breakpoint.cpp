#include "breakpoint.h"

#include <sys/ptrace.h>

#include <cstring>
#include <iostream>
#include <utility>

#include "utils.h"

namespace sdb
{

bool breakpoints_t::exist_by_id(size_t id) const
{
    return breakpoints.find(id) != breakpoints.end();
}

bool breakpoints_t::exist_by_address(uintptr_t address) const
{
    return addr_to_bp_id.find(address) != addr_to_bp_id.end();
}

ssize_t breakpoints_t::add(pid_t pid, uintptr_t address, maps_t &maps)
{
    // TODO: check the address is the first-byte of the instruction
    if (!is_executable(pid, maps, address))
    {
        std::cerr << "** the target address is not valid." << std::endl;
        return -1;
    }

    auto original_byte = replace_address(pid, address, 0xcc);

    breakpoints[++last_id] = {address, original_byte};
    addr_to_bp_id[address] = last_id;
    std::cout << "** set a breakpoint at [0x" << std::hex << address << "]."
              << std::endl;
    return last_id;
}

void breakpoints_t::remove_by_address(pid_t pid, uintptr_t address)
{
    if (!exist_by_address(address))
    {
        std::cerr << "** breakpoint [0x" << std::hex << address
                  << "] does not exist." << std::endl;
        return;
    }
    auto id = addr_to_bp_id.at(address);
    remove_by_id(pid, id);
}

void breakpoints_t::remove_by_id(pid_t pid, size_t id)
{
    if (!exist_by_id(id))
    {
        std::cerr << "** breakpoint [" << id << "] does not exist."
                  << std::endl;
        return;
    }
    auto &breakpoint = breakpoints.at(id);
    auto address = breakpoint.address;

    replace_address(pid, address, breakpoint.original_byte_code);

    addr_to_bp_id.erase(address);
    breakpoints.erase(id);
}

void breakpoints_t::enable(pid_t pid, uintptr_t address)
{
    if (!exist_by_address(address))
    {
        std::cerr << "** breakpoint [0x" << std::hex << address
                  << "] does not exist." << std::endl;
        return;
    }
    auto id = addr_to_bp_id.at(address);
    auto &breakpoint = breakpoints.at(id);

    replace_address(pid, address, 0xcc);

    breakpoint.enabled = true;
}

void breakpoints_t::disable(pid_t pid, uintptr_t address)
{
    if (!exist_by_address(address))
    {
        std::cerr << "** breakpoint [0x" << std::hex << address
                  << "] does not exist." << std::endl;
        return;
    }
    auto id = addr_to_bp_id.at(address);
    auto &breakpoint = breakpoints.at(id);

    replace_address(pid, address, breakpoint.original_byte_code);

    breakpoint.enabled = false;
}

std::ostream &operator<<(std::ostream &out, const breakpoints_t &breakpoints)
{
    if (breakpoints.breakpoints.size() == 0)
    {
        return out << "** no breakpoints." << std::endl;
    }

    out << "Num\tAddress" << std::endl;
    for (const auto &pair : breakpoints.breakpoints)
    {
        out << std::dec << pair.first << "\t" << std::hex << pair.second.address
            << std::endl;
    }
    return out;
}

}  // namespace sdb
