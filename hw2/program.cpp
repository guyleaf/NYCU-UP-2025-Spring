#include "program.h"

#include <filesystem>

namespace sdb
{

uintptr_t program_t::base_address() const
{
    auto path = std::filesystem::canonical(program);
    for (const auto& pair : maps)
    {
        if (pair.second.name == path)
        {
            return pair.first.begin;
        }
    }
    std::cerr << "** base_address failed - the base address is not found."
              << std::endl;
    exit(EXIT_FAILURE);
}

uintptr_t program_t::entry_point_address() const { return auxvs.at(AT_ENTRY); }

}  // namespace sdb
