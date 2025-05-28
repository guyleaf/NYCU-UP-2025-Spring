#ifndef __UTILS_H__
#define __UTILS_H__

#include <unistd.h>

#include <cstdint>
#include <iostream>
#include <string>
#include <utility>

namespace sdb
{

std::string lstrip(const std::string& string);
std::string rstrip(const std::string& string);
std::string strip(const std::string& string);

void kill_and_wait(pid_t pid, int sig);
bool wait_pid(pid_t pid, int* status, int options);
bool wait_pid_stopped(pid_t pid, int* status, int options);

std::tuple<uintptr_t, uintptr_t> align_address(uintptr_t address);
uint8_t replace_address(pid_t pid, uintptr_t address, uint8_t data);

}  // namespace sdb

#endif
