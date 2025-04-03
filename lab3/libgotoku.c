
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>

#include "libgotoku.h"

#ifdef DEBUG
#include "got_gotoku_local.h"
#else
#include "got_gotoku.h"
#endif

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



int solve_sudoku(gotoku_t *gotoku) {
	if (gotoku->x >= 9 || gotoku->y >= 9) {
		return 0;
	}

	// down
	gotoku->y;

	// right
	return -1;
}

gotoku_t *
game_load_internal(const char *fn) {
	dlerror();    /* Clear any existing error */

	void *handle = dlopen(LIBGOTOKU_SO, RTLD_LAZY);
	if (!handle) {
		fprintf(stderr, GAMEPFX "dlopen failed - %s\n", dlerror());
		return NULL;
	}

	__game_load_t fptr = (__game_load_t)dlsym(handle, "game_load");
	if (!fptr) {
		fprintf(stderr, GAMEPFX "dlsym failed - %s\n", dlerror());
		goto err_quit;
	}

	gotoku_t *gotoku = fptr(fn);
err_quit:
	dlclose(handle);
	return gotoku;
}

gotoku_t *
game_load(const char *fn) {
	gotoku_t *gotoku = game_load_internal(fn);
	if (!gotoku) {
		goto err_quit;
	}

	// solve sodoku
	gotoku_t *solved_gotoku = (gotoku_t*) malloc(sizeof(gotoku_t));
	if(!solved_gotoku) {
		fprintf(stderr, GAMEPFX "alloc failed - %s.\n", strerror(errno));
		goto err_quit;
	}

	solved_gotoku->x = solved_gotoku->y = 0;
	memcpy(solved_gotoku->board, gotoku->board, sizeof(gotoku->board));
	solve_sudoku(solved_gotoku);

	// manipulate gop_### to fill the board

	// void **got_ptr = __stored_ptr + (GOP_1 - MAIN);
	// void *gop_ptr = *got_ptr;
	// printf("%p, %p\n", ptr, gop_ptr);

	free(solved_gotoku);
	return gotoku;
err_quit:
	free(solved_gotoku);
	game_free(gotoku);
	return NULL;
}
