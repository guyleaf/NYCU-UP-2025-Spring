#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MSG_PFX "libzpoline: "
#define MMAP_SIZE 1024
#define MEM_MAPS_PATH "/proc/self/maps"
#define LIBC_PATH "libc.so.6"

#define NUM_NOPS 512
#define SYSCALL_CODE 0x050f
#define SYSENTER_CODE 0x340f

#define MEM_ADDR_WIDTH 0x08
#define UINT8_PTR(x) ((uint8_t *)x)

static void *mem = NULL;
static size_t allocated_mem_size = MMAP_SIZE;

static void *__allocate_mmap(void *addr, size_t *size);
static void __deallocate_mmap(void *ptr, size_t size);

static void __wrap_syscall();
static void *__find_exec_addresses(size_t *num_ranges);
static void __set_mem_permissions(void *addr, size_t size, int perms);

static void *__open_dl(const char *file);
static void __close_dl(void *handler);
static void *__get_func_from_dl(void *handler, const char *name);

typedef struct libc_funcs
{
    void *libc_ptr;
    int (*fprintf_ptr)(FILE *__restrict__ __stream,
                       const char *__restrict__ __format, ...);
} libc_funcs_t;

static libc_funcs_t libc;

void trampoline()
{
    // #ifdef DEBUG
    //     __asm__("int3");
    // #endif
    fprintf(stdout, "Hello from trampoline!\n");
    exit(EXIT_SUCCESS);
    return;
}

__attribute__((constructor)) static void __libinit()
{
    if (libc.libc_ptr == NULL)
    {
        libc.libc_ptr = __open_dl(LIBC_PATH);
        libc.fprintf_ptr = __get_func_from_dl(libc.libc_ptr, "fprintf");
    }

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
    // #ifdef DEBUG
    //     UINT8_PTR(mem)[NUM_NOPS - 1] = 0xcc;
    // #endif
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

    libc.fprintf_ptr(stdout, MSG_PFX "library loaded.\n");
}

__attribute__((destructor)) static void __libdeinit()
{
    if (mem != NULL)
    {
        __deallocate_mmap(mem, allocated_mem_size);
    }

    if (libc.libc_ptr != NULL)
    {
        __close_dl(libc.libc_ptr);
    }
    // printf(stderr, MSG_PFX "library unloaded.\n");
}

static void *__allocate_mmap(void *addr, size_t *size)
{
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size == -1)
    {
        libc.fprintf_ptr(stderr, MSG_PFX "sysconf failed - %s.\n",
                         strerror(errno));
        exit(EXIT_FAILURE);
    }

    // align with pages
    *size += (page_size - *size % page_size);
    // allocate memory for trampoline
    void *ptr = mmap(addr, *size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED)
    {
        libc.fprintf_ptr(stderr, MSG_PFX "mmap failed - %s.\n",
                         strerror(errno));
        exit(EXIT_FAILURE);
    }
    return ptr;
}

static void __deallocate_mmap(void *ptr, size_t size)
{
    if (munmap(ptr, size) == -1)
    {
        libc.fprintf_ptr(stderr, MSG_PFX "munmap failed - %s.\n",
                         strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void __wrap_syscall()
{
    uint16_t *ptr;
    size_t num_ranges = 0;
    uintptr_t (*addr_ranges)[2] = __find_exec_addresses(&num_ranges);

    for (size_t i = 0; i < num_ranges; i++)
    {
        uintptr_t start_addr = addr_ranges[i][0];
        uintptr_t end_addr = addr_ranges[i][1];

        __set_mem_permissions((void *)start_addr, end_addr - start_addr,
                              PROT_READ | PROT_WRITE | PROT_EXEC);
        // printf("\t --> %lx-%lx\n", start_addr, end_addr);

        // iterate two-byte to identify syscall
        for (ptr = (uint16_t *)start_addr; (uintptr_t)ptr < end_addr; ptr++)
        {
            if (*ptr == SYSCALL_CODE || *ptr == SYSENTER_CODE)
            {
                // replace with call *%rax
                // FF d0
                // little-edian
                *ptr = 0xd0ff;
                // printf("%p: %x\n", ptr, *ptr);
            }
        }

        __set_mem_permissions((void *)start_addr, end_addr - start_addr,
                              PROT_READ | PROT_EXEC);
    }

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
        libc.fprintf_ptr(stderr, MSG_PFX "fopen failed - %s.\n",
                         strerror(errno));
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
        libc.fprintf_ptr(stderr, MSG_PFX "mprotect failed - %s.\n",
                         strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void *__open_dl(const char *file)
{
    dlerror();
    void *handler = dlmopen(LM_ID_NEWLM, file, RTLD_NOW);
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
