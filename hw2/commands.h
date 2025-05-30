#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include <memory>
#include <string>
#include <vector>

#include "program.h"

namespace sdb
{

class command_t
{
   public:
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) = 0;
    inline virtual bool validate() const;
};

class load_program_t : public command_t
{
   public:
    load_program_t(std::string path);
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) override;
    virtual bool validate() const override;

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

   private:
    void print_register(std::string name, uintptr_t content) const;
};

class add_breakpoint_t : public command_t
{
   public:
    add_breakpoint_t(std::string address_or_offset);
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) override;
    virtual bool validate() const override;

   private:
    std::string address_or_offset;
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
    remove_breakpoint_t(std::string id);
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) override;
    virtual bool validate() const override;

   private:
    std::string id;
};

class patch_mem_t : public command_t
{
   public:
    patch_mem_t(std::string address, std::string content);
    virtual std::shared_ptr<program_t> execute(
        std::shared_ptr<program_t> program) override;
    virtual bool validate() const override;

   private:
    std::vector<uint8_t> to_bytes(std::string data) const;

    std::string address;
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
