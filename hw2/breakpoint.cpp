#include "breakpoint.h"

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

void breakpoints_t::add(uintptr_t address) {}

void breakpoints_t::remove(uintptr_t address) {}

}  // namespace sdb
