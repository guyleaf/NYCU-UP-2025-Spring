#ifndef __PTOOLS_H__
#define __PTOOLS_H__

#include <unistd.h>

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>

namespace sdb
{

struct range_t
{
    uintptr_t begin, end;
};

struct map_entry_t
{
    range_t range;
    uint8_t perm;
    uintptr_t offset;
    std::string name;
};

using maps_t = std::map<range_t, map_entry_t>;
using auxvs_t = std::unordered_map<uintptr_t, uintptr_t>;

bool operator<(const range_t& r1, const range_t& r2);
size_t load_maps(pid_t pid, maps_t& loaded);
size_t load_auxvs(pid_t pid, auxvs_t& loaded);

maps_t::iterator find_map(pid_t pid, maps_t& maps, uintptr_t address);
bool is_executable(pid_t pid, maps_t& maps, uintptr_t address);
bool is_valid(pid_t pid, maps_t& maps, uintptr_t address);

}  // namespace sdb

#endif
