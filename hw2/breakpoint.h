#ifndef __BREAKPOINT_H__
#define __BREAKPOINT_H__

#include <cstddef>
#include <cstdint>
#include <map>
#include <unordered_map>

namespace sdb
{

struct breakpoint_t
{
    const uintptr_t address;
    const uint8_t original_byte_code;
};

struct breakpoints_t
{
    size_t last_id = -1;

    // map from id to breakpoints
    std::map<size_t, breakpoint_t> breakpoints;
    // unordered_map from address to id
    std::unordered_map<uintptr_t, size_t> addr_to_bp_id;

    bool exist_by_id(size_t id) const;
    bool exist_by_address(uintptr_t address) const;

    void add(uintptr_t address);
    void remove(uintptr_t address);
};

}  // namespace sdb

#endif
