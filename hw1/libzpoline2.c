#define _GNU_SOURCE
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MSG_PFX "libzpoline: "
#define MEM_MAPS_PATH "/proc/self/maps"
#define SO_FILENAME "libzpoline.so"

#define MMAP_SIZE 1024
#define NUM_NOPS 512

#define SYSCALL_WRITE_ID 0x01

#define MEM_ADDR_WIDTH 0x08
#define UINT8_PTR(x) ((uint8_t *)x)

static void *mem = NULL;
static size_t allocated_mem_size = MMAP_SIZE;

static void *__allocate_mmap(void *addr, size_t *size);
static void __deallocate_mmap(void *ptr, size_t size);

static void __wrap_syscall();
static void *__find_exec_addresses(size_t *num_ranges);
static void __set_mem_permissions(void *addr, size_t size, int perms);

static char *__get_last_token(char *s, const char *delim);
static void __decode_leets(const char *s, size_t length, char *buf);

extern int64_t trigger_syscall(int64_t rdi, int64_t rsi, int64_t rdx,
                               int64_t rcx, int64_t r8, int64_t r9,
                               int64_t syscall_id);

void __raw_asm()
{
    __asm__ volatile(
        "trigger_syscall: \t\n"
        // get syscall id
        "mov 8(%rsp), %rax \t\n"
        // convert arguments from normal function to syscall
        // pass arguments in reversed order (right-to-left)
        "mov %rcx, %r10 \t\n"
        "syscall \t\n"
        "ret \t\n");
}

int64_t handle_syscall(int64_t rdi, int64_t rsi, int64_t rdx, int64_t rcx,
                       int64_t r8, int64_t r9, int64_t syscall_id)
{
#ifdef DEBUG
    if (getenv("ZDEBUG"))
    {
        __asm__("int3");
    }
#endif

    char *buf = NULL;

    // Leetspeak decoding if write & fd == 1
    if (syscall_id == SYSCALL_WRITE_ID && rdi == STDOUT_FILENO)
    {
        const char *ptr = (const char *)rsi;
        size_t length = (size_t)rdx;
        buf = malloc(length);
        __decode_leets(ptr, length, buf);
        rsi = (int64_t)buf;
    }

    int64_t ret = trigger_syscall(rdi, rsi, rdx, rcx, r8, r9, syscall_id);
    free(buf);
    return ret;
}

void trampoline()
{
    __asm__ volatile(
        // following thr x86_64 ABI,
        // preserve all general-purpose registers (caller-saved) before syscall
        // except %rcx,%r11,%rax
        "int3 \t\n"
        "push %r10 \t\n"
        "push %r9 \t\n"
        "push %r8 \t\n"
        "push %rdi \t\n"
        "push %rsi \t\n"
        "push %rdx \t\n"
        // convert arguments from syscall to normal function
        // pass arguments in reversed order (right-to-left)
        "push %rax \t\n"
        "mov %r10, %rcx \t\n"
        "call handle_syscall \t\n"
        // restore stack pointer
        "add $8, %rsp \t\n"
        // restore registers
        "pop %rdx \t\n"
        "pop %rsi \t\n"
        "pop %rdi \t\n"
        "pop %r8 \t\n"
        "pop %r9 \t\n"
        "pop %r10 \t\n");
}

__attribute__((constructor)) static void __libinit()
{
    size_t offset = 0;
    if (mem == NULL)
    {
        mem = __allocate_mmap(0, &allocated_mem_size);
    }

    // assign nop operation to the first 512 bytes
    for (size_t i = 0; i < NUM_NOPS; i++)
    {
        UINT8_PTR(mem)[i] = 0x90;
    }
    offset += NUM_NOPS;

    // preserve redzone
    // sub %rsp, $0x80
    // 48 (REX.W, 64-bit operand mode) 81 ec 80 00 00 00
    // uint8_t sub_inst[] = {0x48, 0x81, 0xec, 0x80, 0, 0, 0};
    // for (size_t i = 0; i < sizeof(sub_inst); i++)
    // {
    //     UINT8_PTR(mem)[offset + i] = sub_inst[i];
    // }
    // offset += sizeof(sub_inst);

    // assign the address of trampoline function
    // mov %r11, addr of trampoline function
    // 49 (REX.W + REX.B) BB (B8+r=B8+3, r => register code) xxxx
    UINT8_PTR(mem)[offset] = 0x49;
    UINT8_PTR(mem)[offset + 0x01] = 0xbb;
    for (size_t i = 0; i < MEM_ADDR_WIDTH; i++)
    {
        UINT8_PTR(mem)
        [offset + 0x02 + i] = ((uintptr_t)trampoline >> (8 * i)) & 0xff;
    }
    offset += (0x02 + MEM_ADDR_WIDTH);

    // jump to the address
    // jmp *%r11
    // 41 (REX.B) FF e3
    UINT8_PTR(mem)[offset] = 0x41;
    UINT8_PTR(mem)[offset + 0x01] = 0xff;
    UINT8_PTR(mem)[offset + 0x02] = 0xe3;

    __wrap_syscall();

    // set readable & executable only
    __set_mem_permissions(mem, allocated_mem_size, PROT_READ | PROT_EXEC);

    fprintf(stderr, MSG_PFX "library loaded.\n");
}

__attribute__((destructor)) static void __libdeinit()
{
    fprintf(stderr, MSG_PFX "library unloaded.\n");

    if (mem != NULL)
    {
        __deallocate_mmap(mem, allocated_mem_size);
    }
}

static void *__allocate_mmap(void *addr, size_t *size)
{
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size == -1)
    {
        fprintf(stderr, MSG_PFX "sysconf failed - %s.\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // align with pages
    *size += (page_size - *size % page_size);
    // allocate memory for trampoline
    void *ptr = mmap(addr, *size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED)
    {
        fprintf(stderr, MSG_PFX "mmap failed - %s.\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return ptr;
}

static void __deallocate_mmap(void *ptr, size_t size)
{
    if (munmap(ptr, size) == -1)
    {
        fprintf(stderr, MSG_PFX "munmap failed - %s.\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void __wrap_syscall()
{
    csh handle;
    cs_insn *insn;
    size_t num_ranges = 0;
    uintptr_t (*addr_ranges)[2] = __find_exec_addresses(&num_ranges);

    // initialize capstone engine
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        fprintf(stderr, MSG_PFX "cs_open failed - %s.\n",
                cs_strerror(cs_errno(handle)));
        exit(EXIT_FAILURE);
    }
    // turn on SKIPDATA mode
    if (cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON) != CS_ERR_OK)
    {
        fprintf(stderr, MSG_PFX "cs_option failed - %s.\n",
                cs_strerror(cs_errno(handle)));
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < num_ranges; i++)
    {
        uintptr_t start_addr = addr_ranges[i][0];
        uintptr_t end_addr = addr_ranges[i][1];
        uintptr_t addr_range_size = end_addr - start_addr;

        __set_mem_permissions((void *)start_addr, addr_range_size,
                              PROT_READ | PROT_WRITE | PROT_EXEC);

        size_t count = cs_disasm(handle, (uint8_t *)start_addr, addr_range_size,
                                 start_addr, 0, &insn);
        if (count == 0)
        {
            fprintf(stderr, MSG_PFX
                    "cs_disasm failed - Failed to disassemble given code!.\n");
            exit(EXIT_FAILURE);
        }

        for (size_t i = 0; i < count; i++)
        {
            if (insn[i].id == X86_INS_SYSCALL)
            {
                // replace with call *%rax
                // little-edian
                *(uint16_t *)insn[i].address = 0xd0ff;
            }
        }

        // release the cache memory when done
        cs_free(insn, count);

        __set_mem_permissions((void *)start_addr, addr_range_size,
                              PROT_READ | PROT_EXEC);
    }

    cs_close(&handle);
    free(addr_ranges);
}

static void *__find_exec_addresses(size_t *num_ranges)
{
    uintptr_t (*addr_ranges)[2] = NULL;
    size_t __num_ranges = 0;

    // parse /proc/self/maps to find executable areas
    FILE *stream = fopen(MEM_MAPS_PATH, "r");
    if (stream == NULL)
    {
        fprintf(stderr, MSG_PFX "fopen failed - %s.\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    char *line = NULL;
    ssize_t num_chars;
    size_t size = 0;
    while ((num_chars = getline(&line, &size, stream)) != -1)
    {
        // first two columns: address range, permission
        char *addr_range = strtok(line, " \t\n");
        char *perms = strtok(NULL, " \t\n");
        char *file = __get_last_token(NULL, " \t\n");

        // skip syscalls in libzpoline
        if (strstr(file, SO_FILENAME) != NULL)
        {
            continue;
        }

        // check permissions have executable flag
        if (strcmp(perms, "r-xp") == 0)
        {
            __num_ranges++;
            addr_ranges =
                realloc(addr_ranges, __num_ranges * sizeof(*addr_ranges));

            // parse address range & store them
            char *addr = strtok(addr_range, "-");
            addr_ranges[__num_ranges - 1][0] = strtoul(addr, NULL, 16);
            addr = strtok(NULL, "-");
            addr_ranges[__num_ranges - 1][1] = strtoul(addr, NULL, 16);
        }

        free(line);
        line = NULL;
    }

    *num_ranges = __num_ranges;
    return addr_ranges;
}

static void __set_mem_permissions(void *addr, size_t size, int perms)
{
    // set readable & executable only
    if (mprotect(addr, size, perms) == -1)
    {
        fprintf(stderr, MSG_PFX "mprotect failed - %s.\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static char *__get_last_token(char *s, const char *delim)
{
    char *prev = NULL, *curr = NULL;
    while ((curr = strtok(s, delim)) != NULL)
    {
        prev = curr;
    }
    return prev;
}

static void __decode_leets(const char *s, size_t length, char *buf)
{
    static const char leet_to_char[] = "oizeasgt";
    ssize_t num_leets = strlen(leet_to_char);

    for (size_t i = 0; i < length; i++)
    {
        ssize_t leet = s[i] - '0';
        if (0 <= leet && leet < num_leets)
        {
            buf[i] = leet_to_char[leet];
        }
        else
        {
            buf[i] = s[i];
        }
    }
}
