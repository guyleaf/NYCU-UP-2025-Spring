#include "ptools.h"

#include <libgen.h>
#include <sys/ptrace.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include "utils.h"

namespace sdb
{

bool operator<(const range_t& r1, const range_t& r2)
{
    return r1.begin < r2.begin && r1.end < r2.end;
}

size_t load_maps(pid_t pid, maps_t& loaded)
{
    std::stringstream ss;
    ss << "/proc/" << pid << "/maps";

    std::ifstream ifs(ss.str());
    if (!ifs.is_open())
    {
        std::cerr << "ifstream failed - cannot open the file, " << ss.str()
                  << std::endl;
        exit(EXIT_FAILURE);
    }

    loaded.clear();

    size_t idx;
    std::string line;
    while (std::getline(ifs, line))
    {
        std::vector<std::string> columns;
        ss.str(line);
        ss.clear();
        while (ss >> line)
        {
            columns.push_back(line);
        }

        map_entry_t entry;

        // address range
        line = columns.at(0);
        entry.range.begin = std::stoul(line, &idx, 16);
        idx++;
        entry.range.end = std::stoul(line.c_str() + idx, nullptr, 16);

        // permission
        line = columns.at(1);
        entry.perm = 0;
        if (line[0] == 'r') entry.perm |= 0x04;
        if (line[1] == 'w') entry.perm |= 0x02;
        if (line[2] == 'x') entry.perm |= 0x01;

        // offset
        line = columns.at(2);
        entry.offset = std::stoul(line, nullptr, 16);

        if (columns.size() > 5)
        {
            // name
            entry.name = columns.at(5).data();
        }

        loaded[entry.range] = std::move(entry);
    }

    ifs.close();
    return loaded.size();
}

size_t load_auxvs(pid_t pid, auxvs_t& loaded)
{
    std::stringstream ss;
    ss << "/proc/" << pid << "/auxv";

    std::ifstream ifs(ss.str(), std::ios_base::binary);
    if (!ifs.is_open())
    {
        std::cerr << "ifstream failed - cannot open the file, " << ss.str()
                  << std::endl;
        exit(EXIT_FAILURE);
    }

    loaded.clear();

    uintptr_t key, value;
    while (ifs.read((char*)&key, sizeof(key)))
    {
        ifs.read((char*)&value, sizeof(value));
        loaded[key] = value;
    }

    return loaded.size();
}

maps_t::iterator find_map(pid_t pid, maps_t& maps, uintptr_t address)
{
    // [address, address + 1)
    range_t range{address, address + 1};
    auto iter = maps.find(range);
    if (iter == maps.end())
    {
        load_maps(pid, maps);
        iter = maps.find(range);
    }
    return iter;
}

bool is_executable(pid_t pid, maps_t& maps, uintptr_t address)
{
    auto iter = find_map(pid, maps, address);
    return iter != maps.end() && (iter->second.perm & 0x01) != 0;
}

bool is_valid(pid_t pid, maps_t& maps, uintptr_t address)
{
    auto iter = find_map(pid, maps, address);
    return iter != maps.end();
}

}  // namespace sdb
