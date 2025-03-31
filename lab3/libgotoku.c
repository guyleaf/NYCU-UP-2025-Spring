
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

#include <dlfcn.h>

#include "libgotoku.h"

#define LIBGOTOKU_SO "libgotoku.so"
#define GAMEPFX	"GOTOKU: "

typedef gotoku_t * (*__game_load_t)(const char *fn);

static int _initialized = 0;
static void * __stored_ptr = NULL;

void
game_set_ptr(void *ptr) {
	_initialized = 1;
	__stored_ptr = ptr;
}

void *
game_get_ptr() {
	return __stored_ptr;
}

int
game_init() {
	printf("UP113_GOT_PUZZLE_CHALLENGE\n");
	printf("SOLVER: _main = %p", __stored_ptr);
	return 0;
}

void solve_sudoku(gotoku_t *board)
{

}

gotoku_t *
game_load(const char *fn) {
	void *handle = dlopen(LIBGOTOKU_SO, RTLD_LAZY);
	if (!handle) {
		fprintf(stderr, "%s\n", dlerror());
		exit(EXIT_FAILURE);
	}

	dlerror();    /* Clear any existing error */

	__game_load_t fptr = dlsym(handle, "game_load");
	if (!fptr) {
		fprintf(stderr, "%s\n", dlerror());
		exit(EXIT_FAILURE);
	}

	gotoku_t *board = fptr(fn);
	// TODO: solve sodoku

	dlclose(handle);
	return board;
}
