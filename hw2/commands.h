#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include <memory>
#include <string>

#include "program.h"

namespace sdb
{

class command_t
{
   public:
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) = 0;
};

class load_program_t : public command_t
{
   public:
    load_program_t(std::string path);
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) override;

   private:
    std::string path;
};

class single_step_t : public command_t
{
   public:
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) override;
};

class continue_t : public command_t
{
   public:
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) override;
};

class info_regs_t : public command_t
{
   public:
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) override;
};

class add_breakpoint_t : public command_t
{
   public:
    add_breakpoint_t(uintptr_t address);
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) override;

   private:
    uintptr_t address;
};

class info_breakpoints_t : public command_t
{
   public:
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) override;
};

class remove_breakpoint_t : public command_t
{
   public:
    remove_breakpoint_t(size_t id);
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) override;

   private:
    size_t id;
};

class patch_mem_t : public command_t
{
   public:
    patch_mem_t(uintptr_t address, std::string content);
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) override;

   private:
    uintptr_t address;
    std::string content;
};

class syscall_t : public command_t
{
   public:
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) override;
};

}  // namespace sdb

#endif
