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
const size_t PEEK_SIZE = sizeof(size_t);
const size_t MAX_INSN_SIZE = 16UL;
// 16-byte * (5 + 2)
const size_t INSNS_BUF_SIZE = MAX_INSN_SIZE * 7;

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
