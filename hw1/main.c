#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
#ifdef DEBUG
    if (getenv("ZDEBUG"))
    {
        __asm__("int3");
    }
#endif
    printf("Jump to address: test\n");
    return 0;
}
