#ifndef __PROGRAM_H__
#define __PROGRAM_H__
#include <unistd.h>

#include <string>

#include "auxv.h"
#include "breakpoint.h"
#include "ptools.h"

namespace sdb
{

struct program_t
{
    std::string program;
    pid_t pid;

    sdb::maps_t maps;
    sdb::auxvs_t auxvs;

    breakpoints_t breakpoints;
    bool entered_syscall = false;

    uintptr_t base_address() const;
    uintptr_t entry_point_address() const;
};

}  // namespace sdb

#endif
