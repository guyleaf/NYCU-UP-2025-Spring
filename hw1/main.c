#include <stdint.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    void (*func)();

    for (uintptr_t i = 0; i < 512; i += 0x84)
    {
        printf("Jump to address: %lu\n", i);
        func = (void *)i;
        func();
    }
    return 0;
}
