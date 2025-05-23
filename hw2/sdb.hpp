#ifndef __SDB_H__
#define __SDB_H__

#include <map>
#include <string>
#include <unordered_map>

#include "auxv.h"
#include "breakpoint.h"
#include "ptools.h"
#include "utils.h"

namespace sdb
{

const std::string MSG_PREFIX = "(sdb) ";

struct program_t
{
    std::string program;
    pid_t pid;

    sdb::maps_t maps;
    sdb::auxvs_t auxvs;

    breakpoints_t breakpoints;

    uintptr_t base_address() { return maps.begin()->first.begin; }
    uintptr_t entry_point_address() { return auxvs.at(AT_ENTRY); }
};

}  // namespace sdb

#endif
