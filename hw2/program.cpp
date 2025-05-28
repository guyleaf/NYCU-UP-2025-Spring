#include "program.h"

namespace sdb
{

uintptr_t program_t::base_address() const { return maps.begin()->first.begin; }

uintptr_t program_t::entry_point_address() const { return auxvs.at(AT_ENTRY); }

bool program_t::is_running() const { return false; }

}  // namespace sdb
