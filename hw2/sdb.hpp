#ifndef __SDB_H__
#define __SDB_H__

#include <cstdint>
#include <string>

namespace sdb
{

const std::string MSG_PREFIX = "(sdb) ";
const size_t WORD_SIZE = sizeof(size_t);
const size_t PEEK_SIZE = WORD_SIZE;
const size_t MAX_INSN_SIZE = 16UL;
// 16-byte * (5 + 2)
const size_t INSNS_BUF_SIZE = MAX_INSN_SIZE * 7;

}  // namespace sdb

#endif
