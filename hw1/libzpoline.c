#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define MSG_PFX "libzpoline: "
#define MMAP_SIZE 1024

#define NOP_CODE 0x90

static void *mem;
static size_t allocated_mem_size = MMAP_SIZE;

void trampoline();

__attribute__((constructor)) static void __libinit()
{
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size == -1)
    {
        fprintf(stderr, MSG_PFX "sysconf failed - %s.\n", strerror(errno));
        return;
    }

    // align with pages
    allocated_mem_size += (page_size - allocated_mem_size % page_size);
    // allocate memory for trampoline
    mem = mmap(0, allocated_mem_size, PROT_READ | PROT_WRITE | PROT_EXEC,
               MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED)
    {
        fprintf(stderr, MSG_PFX "mmap failed - %s.\n", strerror(errno));
        return;
    }

    // assign nop operation to the first 512 bytes
    size_t i;
    for (i = 0; i < 512; i++)
    {
        ((uint8_t *)mem)[i] = NOP_CODE;
    }

    // jump to trampoline function


    fprintf(stdout, MSG_PFX "library loaded (%d, %d).\n", getuid(), getgid());
}

__attribute__((destructor)) static void __libdeinit()
{
    if (munmap(mem, allocated_mem_size) == MAP_FAILED)
    {
        fprintf(stderr, MSG_PFX "munmap failed - %s.\n", strerror(errno));
        return;
    }

    fprintf(stderr, MSG_PFX "library unloaded.\n");
}

void trampoline() {
    fprintf(stdout, "Hello from trampoline!\n");
}
