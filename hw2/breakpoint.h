#ifndef __BREAKPOINT_H__
#define __BREAKPOINT_H__

#include <sys/user.h>
#include <sys/wait.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <map>
#include <unordered_map>

#include "ptools.h"

namespace sdb
{

struct breakpoint_t
{
    uintptr_t address;
    uint8_t original_byte_code;
    bool enabled = true;
};

struct breakpoints_t
{
   public:
    bool exist_by_id(size_t id) const;
    bool exist_by_address(uintptr_t address) const;
    bool hit(uintptr_t address) const;
    bool enabled(uintptr_t address) const;
    bool disabled(uintptr_t address) const;

    ssize_t add(pid_t pid, uintptr_t address, maps_t& maps);

    void remove_by_address(pid_t pid, uintptr_t address);
    void remove_by_id(pid_t pid, size_t id);

    void patch(pid_t pid, uintptr_t address, uint8_t content);

    void enable_all(pid_t pid);
    void enable(pid_t pid, uintptr_t address);
    void disable_all(pid_t pid);
    void disable(pid_t pid, uintptr_t address);

    friend std::ostream& operator<<(std::ostream& out,
                                    const breakpoints_t& breakpoints);

   private:
    ssize_t last_id = -1;

    // map from id to breakpoints
    std::map<size_t, breakpoint_t> breakpoints;
    // unordered_map from address to id
    std::unordered_map<uintptr_t, size_t> addr_to_bp_id;
};

std::ostream& operator<<(std::ostream& out, const breakpoints_t& breakpoints);

}  // namespace sdb

#endif
