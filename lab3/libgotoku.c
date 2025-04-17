
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/mman.h>

#include "libgotoku.h"

#ifdef DEBUG
#include "got_gotoku_local.h"
#else
#include "got_gotoku.h"
#endif

#define LIBGOTOKU_SO "libgotoku.so"
#define GAMEPFX	"SOLVER: "
#define GOT_PTR(x, y) ((uintptr_t *)(x + *(y++)))

typedef gotoku_t * (*__game_load_t)(const char *fn);

void *__gop_fill(int n) {
	switch (n)
	{
		case 1:
			return gop_fill_1;
		case 2:
			return gop_fill_2;
		case 3:
			return gop_fill_3;
		case 4:
			return gop_fill_4;
		case 5:
			return gop_fill_5;
		case 6:
			return gop_fill_6;
		case 7:
			return gop_fill_7;
		case 8:
			return gop_fill_8;
		case 9:
			return gop_fill_9;
		default:
			fprintf(stderr, GAMEPFX "__gop_fill failed - Unknown filled value, %d.\n", n);
			break;
	}
	return NULL;
}

int __overwrite_GOT_table(gotoku_t *gotoku, gotoku_t *solved_gotoku) {
	long page_size = sysconf(_SC_PAGE_SIZE);
	if (page_size == -1) {
		fprintf(stderr, GAMEPFX "sysconf failed - %s.\n", strerror(errno));
		return -1;
	}

	// calculate min and max address of got table to make GOT table writable
	uintptr_t base_addr = (uintptr_t)game_get_ptr();
	uintptr_t start_addr = base_addr + MIN_GOT_OFFSET;
	uintptr_t end_addr = base_addr + MAX_GOT_OFFSET;
	// align to page boundary
	start_addr -= (start_addr % page_size);
	end_addr += (page_size - end_addr % page_size);
	if (mprotect((void *)start_addr, end_addr - start_addr, PROT_READ | PROT_WRITE) == -1) {
		fprintf(stderr, GAMEPFX "mprotect failed - %s.\n", strerror(errno));
		return -1;
	}

	// overwrite the GOT table entries of gop_###
	uintptr_t *got_offset_ptr = GOT_OFFSETS;
	for (int i = 0; i < 9; i++)
	{
		for (int j = 0; j < 9; j++)
		{
			if (gotoku->board[i][j] == 0)
			{
				// a GOT entry store another address pointing to the function gop_###
				*GOT_PTR(base_addr, got_offset_ptr) = (uintptr_t)__gop_fill(solved_gotoku->board[i][j]);
			}
			*GOT_PTR(base_addr, got_offset_ptr) = (uintptr_t)gop_right;
		}
		*GOT_PTR(base_addr, got_offset_ptr) = (uintptr_t)gop_down;
	}
	return 0;
}

int __check_cell(int board[][9], int x, int y) {
	int cell = board[y][x];

	// row & column
	for (int i = 0; i < 9; i++) {
		if ((i != x && board[y][i] == cell) || (i != y && board[i][x] == cell))
		{
			return -1;
		}
	}

	// box
	int start_x = (x / 3) * 3, start_y = (y / 3) * 3;
	for (int i = start_y; i < start_y + 3; i++)
	{
		for (int j = start_x; j < start_x + 3; j++)
		{
			if (i != y && j != x && board[i][j] == cell)
			{
				return -1;
			}
		}
	}
	return 0;
}

int __solve_sudoku(gotoku_t *gotoku) {
	// base case: stop if out of range
	if (gotoku->x >= 9 || gotoku->y >= 9) {
		return 0;
	}

	// store state & move to next cell
	int x = gotoku->x, y = gotoku->y;
	gotoku->x = (x + 1) % 9;
	if (gotoku->x == 0)
	{
		gotoku->y++;
	}

	if (gotoku->board[y][x] == 0)
	{
		int *cell = &gotoku->board[y][x];
		// backtracking: try all possible values
		for (int value = 1; value < 10; value++)
		{
			*cell = value;
			if (__check_cell(gotoku->board, x, y) == 0 && __solve_sudoku(gotoku) == 0)
			{
				return 0;
			}
		}
		*cell = 0;
	}
	// skip filled cells
	else
	{
		if (__solve_sudoku(gotoku) == 0)
		{
			return 0;
		}
	}

	// backtracking: if all failed, return to previous step.
	// restore state
	gotoku->x = x;
	gotoku->y = y;
	return -1;
}

gotoku_t *
__game_load_internal(const char *fn) {
	gotoku_t *gotoku = NULL;
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

	gotoku = fptr(fn);
err_quit:
	dlclose(handle);
	return gotoku;
}

int
game_init() {
	printf("UP113_GOT_PUZZLE_CHALLENGE\n");
	printf(GAMEPFX "_main = %p\n", game_get_ptr());
	return 0;
}

gotoku_t *
game_load(const char *fn) {
	gotoku_t *solved_gotoku = NULL;
	gotoku_t *gotoku = __game_load_internal(fn);
	if (!gotoku) {
		goto err_quit;
	}

	// solve sodoku
	solved_gotoku = (gotoku_t*) malloc(sizeof(gotoku_t));
	if(!solved_gotoku) {
		fprintf(stderr, GAMEPFX "alloc failed - %s.\n", strerror(errno));
		goto err_quit;
	}

	solved_gotoku->x = solved_gotoku->y = 0;
	memcpy(solved_gotoku->board, gotoku->board, sizeof(gotoku->board));
	__solve_sudoku(solved_gotoku);

	if (__overwrite_GOT_table(gotoku, solved_gotoku) == -1) {
		goto err_quit;
	}

	free(solved_gotoku);
	return gotoku;
err_quit:
	free(solved_gotoku);
	game_free(gotoku);
	return NULL;
}
