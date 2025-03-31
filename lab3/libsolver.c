
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <execinfo.h>
#include <time.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/syscall.h>

#define GAMEPFX	"GOTOKU: "

__attribute__((constructor))
static void
__libinit() {
	fprintf(stderr, GAMEPFX "library loaded (%d, %d).\n", getuid(), getgid());
	return;
}

static int _initialized = 0;
static void * __stored_ptr = NULL;

void
game_set_ptr(void *ptr) {
	_initialized = 1;
	__stored_ptr = ptr;
    fprintf(stdout, "Hi~");
}
