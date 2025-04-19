#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MSG_PFX "libzpoline: "
#define MMAP_SIZE 1024

#define NUM_NOPS 512

#define MEM_ADDR_WIDTH 0x08
#define UINT8_PTR(x) ((uint8_t *)x)

static void *mem = NULL;
static size_t allocated_mem_size = MMAP_SIZE;

void trampoline();
static void *__allocate_mmap(void *addr, size_t *size);
static void __deallocate_mmap(void *ptr, size_t size);

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
#ifdef DEBUG
    UINT8_PTR(mem)[NUM_NOPS - 1] = 0xcc;
#endif
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

    // set readable & executable only
    if (mprotect(mem, allocated_mem_size, PROT_READ | PROT_EXEC) == -1)
    {
        fprintf(stderr, MSG_PFX "mprotect failed - %s.\n", strerror(errno));
        exit(1);
    }

    fprintf(stdout, MSG_PFX "library loaded (%d, %d).\n", getuid(), getgid());
}

__attribute__((destructor)) static void __libdeinit()
{
    if (mem != NULL)
    {
        __deallocate_mmap(mem, allocated_mem_size);
    }

    fprintf(stderr, MSG_PFX "library unloaded.\n");
}

void trampoline()
{
    fprintf(stdout, "Hello from trampoline!\n");
    return;
}

static void *__allocate_mmap(void *addr, size_t *size)
{
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size == -1)
    {
        fprintf(stderr, MSG_PFX "sysconf failed - %s.\n", strerror(errno));
        exit(1);
    }

    // align with pages
    *size += (page_size - *size % page_size);
    // allocate memory for trampoline
    void *ptr = mmap(addr, *size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED)
    {
        fprintf(stderr, MSG_PFX "mmap failed - %s.\n", strerror(errno));
        exit(1);
    }
    return ptr;
}

static void __deallocate_mmap(void *ptr, size_t size)
{
    if (munmap(ptr, size) == -1)
    {
        fprintf(stderr, MSG_PFX "munmap failed - %s.\n", strerror(errno));
        exit(1);
    }
}
