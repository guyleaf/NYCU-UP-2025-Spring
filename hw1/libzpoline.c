#define _GNU_SOURCE
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <dlfcn.h>
#include <errno.h>
#include <linux/sched.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MSG_PFX "libzpoline: "
#define MEM_MAPS_PATH "/proc/self/maps"
#define LIBC_PATH "libc.so.6"
#define SO_FILENAME "libzpoline.so"
#define LIBZPHOOK_ENV_VAR "LIBZPHOOK"

#define MMAP_SIZE 1024
#define NUM_NOPS 512

#define SYSCALL_WRITE_ID 0x01

#define MEM_ADDR_WIDTH 0x08
#define UINT8_PTR(x) ((uint8_t *)x)

static void *__allocate_mmap(void *addr, size_t *size);
static void __deallocate_mmap(void *ptr, size_t size);

static void __wrap_syscall(void);
static void *__find_exec_addresses(size_t *num_ranges);
static void __set_mem_permissions(void *addr, size_t size, int perms);

static void *__open_dl(const char *file);
static void __close_dl(void *handler);
static void *__get_func_from_dl(void *handler, const char *name);
static char *__get_last_token(char *s, const char *delim);

extern int64_t trigger_syscall(int64_t rdi, int64_t rsi, int64_t rdx,
                               int64_t rcx, int64_t r8, int64_t r9,
                               int64_t syscall_id);
int64_t handle_syscall(int64_t rdi, int64_t rsi, int64_t rdx, int64_t rcx,
                       int64_t r8, int64_t r9, int64_t syscall_id,
                       int64_t retptr);
extern void trampoline(void);

static void *mem = NULL;
static size_t allocated_mem_size = MMAP_SIZE;

typedef int64_t (*syscall_hook_fn_t)(int64_t, int64_t, int64_t, int64_t,
                                     int64_t, int64_t, int64_t);
typedef void (*hook_init_fn_t)(const syscall_hook_fn_t trigger_syscall,
                               syscall_hook_fn_t *hooked_syscall);

// load from LIBZPHOOK
static void *hook_lib = NULL;
static syscall_hook_fn_t hooked_syscall = trigger_syscall;

void __raw_asm(void)
{
    __asm__ volatile(
        "trigger_syscall: \t\n"
        "push %rbp \t\n"
        "mov %rsp, %rbp \t\n"
        "push %r12 \t\n"

        // perform 16-byte alignment
        "mov $0xfffffffffffffff0, %r11 \t\n"
        "mov %rsp, %r12 \t\n"
        "and %rsp, %r11 \t\n"
        // %r12: mod 16
        "sub %r11, %r12 \t\n"
        "sub %r12, %rsp \t\n"

        // convert arguments from normal function to syscall
        // pass arguments in reversed order (right-to-left)
        // get syscall id
        "mov 16(%rbp), %rax \t\n"
        "mov %rcx, %r10 \t\n"
        "syscall \t\n"

        // restore rsp
        "add %r12, %rsp \t\n"

        "pop %r12 \t\n"
        "leave \t\n"
        "ret \t\n");

    __asm__ volatile(
        "trampoline: \t\n"
        "push %rbp \t\n"
        "mov %rsp, %rbp \t\n"
        // following thr x86_64 ABI,
        // preserve all general-purpose registers (caller-saved) before syscall
        // except %rcx,%r11,%rax
        "push %r10 \t\n"
        "push %r9 \t\n"
        "push %r8 \t\n"
        "push %rdi \t\n"
        "push %rsi \t\n"
        "push %rdx \t\n"
        "push %r12 \t\n"

        // perform 16-byte alignment
        "mov $0xfffffffffffffff0, %r11 \t\n"
        "mov %rsp, %r12 \t\n"
        "and %rsp, %r11 \t\n"
        // %r12: mod 16
        "sub %r11, %r12 \t\n"
        "sub %r12, %rsp \t\n"

        // convert arguments from syscall to normal function
        // pass arguments in reversed order (right-to-left)
        "push 136(%rbp) \t\n"
        "push %rax \t\n"
        "mov %r10, %rcx \t\n"
        "call handle_syscall \t\n"
        "add $16, %rsp \t\n"

        // restore rsp
        "add %r12, %rsp \t\n"

        // restore registers
        "pop %r12 \t\n"
        "pop %rdx \t\n"
        "pop %rsi \t\n"
        "pop %rdi \t\n"
        "pop %r8 \t\n"
        "pop %r9 \t\n"
        "pop %r10 \t\n"
        // mov %rbp, %rsp; pop %rbp
        "leave \t\n"
        // remove redzone
        "add $128, %rsp \n\t"
        "ret \t\n");
}

int64_t handle_syscall(int64_t rdi, int64_t rsi, int64_t rdx, int64_t rcx,
                       int64_t r8, int64_t r9, int64_t syscall_id,
                       int64_t retptr)
{
    // clone-reload syscalls may create a new stack by parent process (share the
    // same address space but diff region) in this case, the new stack will not
    // have valid return address (pushed in trampoline). so, we have to push it
    // to the child stack.
    switch (syscall_id)
    {
        case SYS_clone:
        {
            if (rdi & CLONE_VM)
            {  // pthread creation
                /* push return address to the stack */
                // __asm__("int3");
                rsi -= sizeof(uintptr_t);
                *((uintptr_t *)rsi) = retptr;
            }
            break;
        }
        case SYS_clone3:
        {
            struct clone_args *cargs = (struct clone_args *)rdi;
            if (cargs->flags & CLONE_VM)
            {
                // __asm__("int3");
                cargs->stack_size -= sizeof(uintptr_t);
                *((uintptr_t *)(cargs->stack + cargs->stack_size)) = retptr;
            }
            break;
        }
        default:
            break;
    }

    return hooked_syscall(rdi, rsi, rdx, rcx, r8, r9, syscall_id);
}

__attribute__((constructor)) static void __libinit(void)
{
    size_t offset = 0;
    if (mem == NULL)
    {
        fprintf(stderr, MSG_PFX "allocating memory region...");
        mem = __allocate_mmap(0, &allocated_mem_size);
        fprintf(stderr, " done.\n");
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
    uint8_t sub_inst[] = {0x48, 0x81, 0xec, 0x80, 0, 0, 0};
    for (size_t i = 0; i < sizeof(sub_inst); i++)
    {
        UINT8_PTR(mem)[offset + i] = sub_inst[i];
    }
    offset += sizeof(sub_inst);

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

    char *env;
    syscall_hook_fn_t __hooked_syscall = hooked_syscall;
    if (hook_lib == NULL && (env = getenv(LIBZPHOOK_ENV_VAR)) != NULL)
    {
        hook_init_fn_t hook_init;

        fprintf(stderr, MSG_PFX "loading %s...", env);
        hook_lib = __open_dl(env);
        hook_init = __get_func_from_dl(hook_lib, "__hook_init");
        hook_init(trigger_syscall, &__hooked_syscall);
        fprintf(stderr, " done.\n");
    }
    fprintf(stderr, MSG_PFX "library loaded.\n");
    hooked_syscall = __hooked_syscall;
}

__attribute__((destructor)) static void __libdeinit(void)
{
    // restore hooked_syscall to avoid SIGSEGV
    hooked_syscall = trigger_syscall;

    fprintf(stderr, MSG_PFX "library unloaded.\n");

    if (hook_lib != NULL)
    {
        __close_dl(hook_lib);
    }
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

static void __wrap_syscall(void)
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
        // fprintf(stderr, MSG_PFX "%s\n", line);
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

static void *__open_dl(const char *file)
{
    dlerror();
    void *handler = dlmopen(LM_ID_NEWLM, file, RTLD_LAZY);
    if (handler == NULL)
    {
        fprintf(stderr, MSG_PFX "dlmopen failed - %s.\n", dlerror());
        exit(EXIT_FAILURE);
    }
    return handler;
}

static void __close_dl(void *handler)
{
    if (dlclose(handler) != 0)
    {
        fprintf(stderr, MSG_PFX "dlclose failed - %s.\n", dlerror());
        exit(EXIT_FAILURE);
    }
}

static void *__get_func_from_dl(void *handler, const char *name)
{
    void *func_ptr = dlsym(handler, name);
    if (func_ptr == NULL)
    {
        fprintf(stderr, MSG_PFX "dlsym failed - %s.\n", dlerror());
        exit(EXIT_FAILURE);
    }
    return func_ptr;
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
