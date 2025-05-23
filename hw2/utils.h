#ifndef __UTILS_H__
#define __UTILS_H__

#include <unistd.h>

#include <iostream>
#include <string>

namespace sdb
{

std::string lstrip(const std::string& string);
std::string rstrip(const std::string& string);
std::string strip(const std::string& string);

void kill_and_wait(pid_t pid, int sig);
bool wait_pid(pid_t pid, int* status, int options);

}  // namespace sdb

#endif
