/*
 * ring_buffer_test.c	Tests for ring buffers
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#include <freeradius-devel/io/ring_buffer.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/talloc.h>
#include <string.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#define ALLOC_SIZE (8)
#define ARRAY_SIZE (4 * ALLOC_SIZE)

static size_t		used = 0;
static size_t 		array[ARRAY_SIZE];
static uint8_t		*data[ARRAY_SIZE];

static int		debug_lvl = 0;

static char const      	*seed_string = "foo";
static size_t		seed_string_len = 3;

/**********************************************************************/

static void  alloc_blocks(fr_ring_buffer_t *rb, uint32_t *seed, UNUSED int *start, int *end)
{
	int i;
	uint32_t hash;

	for (i = 0; i < ALLOC_SIZE; i++) {
		int index;
		uint8_t *p;

		index = (*end + i) & (ARRAY_SIZE - 1);

		hash = fr_hash_update(seed_string, seed_string_len, *seed);
		*seed = hash;

		hash &= 0x3ff;
		hash += 16;	/* can't have it zero... */

		array[index] = hash;
		p = fr_ring_buffer_reserve(rb, 2048);

		if (!fr_cond_assert(p != NULL)) fr_exit_now(EXIT_FAILURE);

		data[index] = fr_ring_buffer_alloc(rb, hash);
		if (!fr_cond_assert(data[index] == p)) fr_exit_now(EXIT_FAILURE);

		if (debug_lvl > 1) printf("%08x\t", hash);

		used += hash;
		fr_assert(fr_ring_buffer_used(rb) == used);
	}

	*end += ALLOC_SIZE;
}

static void  free_blocks(fr_ring_buffer_t *rb, UNUSED uint32_t *seed, int *start, int *end)
{
	int i;

	for (i = 0; i < ALLOC_SIZE; i++) {
		int index;
		int rcode;

		index = (*start + i) & (ARRAY_SIZE - 1);

		rcode = fr_ring_buffer_free(rb, array[index]);
		if (!fr_cond_assert(rcode == 0)) fr_exit_now(EXIT_FAILURE);

		used -= array[index];
		fr_assert(fr_ring_buffer_used(rb) == used);

		array[index] = 0;
		data[index] = NULL;
	}

	*start += ALLOC_SIZE;
	if (*start > ARRAY_SIZE) {
		*start -= ARRAY_SIZE;
		*end -= ARRAY_SIZE;
	}
}

/*
 *	@todo - mover to acutest framework.
 */
static void verify_start(fr_ring_buffer_t *rb, int start_idx)
{
	uint8_t *p_start;
	size_t p_size;
	int idx = start_idx & (ARRAY_SIZE - 1);

	if (!fr_cond_assert(fr_ring_buffer_start(rb, &p_start, &p_size) == 0)) fr_exit_now(EXIT_FAILURE);

	if (used == 0) {
		if (!fr_cond_assert(p_size == 0)) fr_exit_now(EXIT_FAILURE);
		return;
	}

	/*
	 *	The contiguous block at the start can never exceed
	 *	the total used.
	 */
	if (!fr_cond_assert(p_size > 0)) fr_exit_now(EXIT_FAILURE);
	if (!fr_cond_assert(p_size <= fr_ring_buffer_used(rb))) fr_exit_now(EXIT_FAILURE);

	/*
	 *	The start pointer must match the first un-freed
	 *	block's data pointer.
	 */
	if (data[idx] && !fr_cond_assert(p_start == data[idx])) fr_exit_now(EXIT_FAILURE);
}

static void test_start_basic(TALLOC_CTX *ctx)
{
	fr_ring_buffer_t *rb;
	uint8_t *p, *p2, *p_start;
	size_t p_size;

	rb = fr_ring_buffer_create(ctx, 1024);
	if (!fr_cond_assert(rb != NULL)) fr_exit_now(EXIT_FAILURE);

	/*
	 *	Empty buffer: size must be 0.
	 */
	if (!fr_cond_assert(fr_ring_buffer_start(rb, &p_start, &p_size) == 0)) fr_exit_now(EXIT_FAILURE);
	if (!fr_cond_assert(p_size == 0)) fr_exit_now(EXIT_FAILURE);

	/*
	 *	Single allocation: start points to it, size matches.
	 */
	p = fr_ring_buffer_reserve(rb, 100);
	if (!fr_cond_assert(p != NULL)) fr_exit_now(EXIT_FAILURE);
	p = fr_ring_buffer_alloc(rb, 100);
	if (!fr_cond_assert(p != NULL)) fr_exit_now(EXIT_FAILURE);

	if (!fr_cond_assert(fr_ring_buffer_start(rb, &p_start, &p_size) == 0)) fr_exit_now(EXIT_FAILURE);
	if (!fr_cond_assert(p_start == p)) fr_exit_now(EXIT_FAILURE);
	if (!fr_cond_assert(p_size == 100)) fr_exit_now(EXIT_FAILURE);

	/*
	 *	Second allocation: start still points to first block,
	 *	size covers both contiguous blocks.
	 */
	p2 = fr_ring_buffer_reserve(rb, 50);
	if (!fr_cond_assert(p2 != NULL)) fr_exit_now(EXIT_FAILURE);
	p2 = fr_ring_buffer_alloc(rb, 50);
	if (!fr_cond_assert(p2 != NULL)) fr_exit_now(EXIT_FAILURE);

	if (!fr_cond_assert(fr_ring_buffer_start(rb, &p_start, &p_size) == 0)) fr_exit_now(EXIT_FAILURE);
	if (!fr_cond_assert(p_start == p)) fr_exit_now(EXIT_FAILURE);
	if (!fr_cond_assert(p_size == 150)) fr_exit_now(EXIT_FAILURE);

	/*
	 *	Free the first block: start advances to second block.
	 */
	if (!fr_cond_assert(fr_ring_buffer_free(rb, 100) == 0)) fr_exit_now(EXIT_FAILURE);

	if (!fr_cond_assert(fr_ring_buffer_start(rb, &p_start, &p_size) == 0)) fr_exit_now(EXIT_FAILURE);
	if (!fr_cond_assert(p_start == p2)) fr_exit_now(EXIT_FAILURE);
	if (!fr_cond_assert(p_size == 50)) fr_exit_now(EXIT_FAILURE);

	/*
	 *	Free everything: size must return to 0.
	 */
	if (!fr_cond_assert(fr_ring_buffer_free(rb, 50) == 0)) fr_exit_now(EXIT_FAILURE);

	if (!fr_cond_assert(fr_ring_buffer_start(rb, &p_start, &p_size) == 0)) fr_exit_now(EXIT_FAILURE);
	if (!fr_cond_assert(p_size == 0)) fr_exit_now(EXIT_FAILURE);

	talloc_free(rb);

	if (debug_lvl) printf("test_start_basic: OK\n");
}

static void test_start_wrapped(TALLOC_CTX *ctx)
{
	fr_ring_buffer_t *rb;
	uint8_t *first, *wrapped, *p_start;
	size_t p_size, rb_size;
	size_t tail_size, total_used;

	rb = fr_ring_buffer_create(ctx, 1024);
	if (!fr_cond_assert(rb != NULL)) fr_exit_now(EXIT_FAILURE);

	rb_size = fr_ring_buffer_size(rb);

	/*
	 *	Allocate most of the buffer, leaving a small gap
	 *	at the end.
	 */
	first = fr_ring_buffer_reserve(rb, rb_size - 64);
	if (!fr_cond_assert(first != NULL)) fr_exit_now(EXIT_FAILURE);
	first = fr_ring_buffer_alloc(rb, rb_size - 64);
	if (!fr_cond_assert(first != NULL)) fr_exit_now(EXIT_FAILURE);

	/*
	 *	State: |S*************WE.......|
	 *	  data_start=0, data_end=rb_size-64, write_offset=rb_size-64
	 */

	/*
	 *	Free the first half, advancing data_start.
	 */
	if (!fr_cond_assert(fr_ring_buffer_free(rb, (rb_size - 64) / 2) == 0)) fr_exit_now(EXIT_FAILURE);

	/*
	 *	State: |.....S********WE.......|
	 *	  data_start=(rb_size-64)/2, data_end=rb_size-64, write_offset=rb_size-64
	 */

	/*
	 *	Allocate 128 bytes.  This is larger than the 64-byte gap at the end, so it wraps to the start
	 *	of the buffer.
	 */
	wrapped = fr_ring_buffer_reserve(rb, 128);
	if (!fr_cond_assert(wrapped != NULL)) fr_exit_now(EXIT_FAILURE);
	wrapped = fr_ring_buffer_alloc(rb, 128);
	if (!fr_cond_assert(wrapped != NULL)) fr_exit_now(EXIT_FAILURE);

	/*
	 *	State: |***W.....S****E........|
	 *	  write_offset=128, data_start=(rb_size-64)/2, data_end=rb_size-64
	 *	  Buffer is wrapped.
	 */
	tail_size = (rb_size - 64) - (rb_size - 64) / 2;
	total_used = tail_size + 128;

	if (!fr_cond_assert(fr_ring_buffer_used(rb) == total_used)) fr_exit_now(EXIT_FAILURE);

	if (!fr_cond_assert(fr_ring_buffer_start(rb, &p_start, &p_size) == 0)) fr_exit_now(EXIT_FAILURE);

	/*
	 *	Start points to the tail block (from data_start to data_end), NOT the wrapped block at offset
	 *	0.
	 */
	if (!fr_cond_assert(p_start == first + (rb_size - 64) / 2)) fr_exit_now(EXIT_FAILURE);
	if (!fr_cond_assert(p_size == tail_size)) fr_exit_now(EXIT_FAILURE);

	/*
	 *	The contiguous block at start is strictly less than total_used when wrapped.
	 */
	if (!fr_cond_assert(p_size < total_used)) fr_exit_now(EXIT_FAILURE);

	/*
	 *	Free the tail block.  The buffer unwraps:
	 *	  data_start=0, data_end=128, write_offset=128
	 *
	 *	Now start should point to the wrapped block at offset 0.
	 */
	tail_size = (rb_size - 64) - (rb_size - 64) / 2;
	if (!fr_cond_assert(fr_ring_buffer_free(rb, tail_size) == 0)) fr_exit_now(EXIT_FAILURE);

	if (!fr_cond_assert(fr_ring_buffer_start(rb, &p_start, &p_size) == 0)) fr_exit_now(EXIT_FAILURE);
	if (!fr_cond_assert(p_start == wrapped)) fr_exit_now(EXIT_FAILURE);
	if (!fr_cond_assert(p_size == 128)) fr_exit_now(EXIT_FAILURE);

	/*
	 *	Free the last block: empty.
	 */
	if (!fr_cond_assert(fr_ring_buffer_free(rb, 128) == 0)) fr_exit_now(EXIT_FAILURE);

	if (!fr_cond_assert(fr_ring_buffer_start(rb, &p_start, &p_size) == 0)) fr_exit_now(EXIT_FAILURE);
	if (!fr_cond_assert(p_size == 0)) fr_exit_now(EXIT_FAILURE);

	talloc_free(rb);

	if (debug_lvl) printf("test_start_wrapped: OK\n");
}

static NEVER_RETURNS void usage(void)
{
	fprintf(stderr, "usage: ring_buffer_test [OPTS]\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");
	fprintf(stderr, "  -s <string>            Set random seed to <string>.\n");
	fprintf(stderr, "  -l <length>            Set the iteration number to <length>.\n");

	fr_exit_now(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	int c;

	int i, start, end, length = 1000;
	fr_ring_buffer_t *rb;
	uint32_t	seed;

	TALLOC_CTX	*autofree = talloc_autofree_context();

	while ((c = getopt(argc, argv, "hl:s:x")) != -1) switch (c) {
		case 'l':
			length = strtol(optarg, NULL, 10);
			break;
		case 's':
			seed_string = optarg;
			seed_string_len = strlen(optarg);
			break;

		case 'x':
			debug_lvl++;
			break;

		case 'h':
		default:
			usage();
	}
#if 0
	argc -= (optind - 1);
	argv += (optind - 1);
#endif

	/*
	 *	Run targeted fr_ring_buffer_start() tests first.
	 */
	test_start_basic(autofree);
	test_start_wrapped(autofree);

	rb = fr_ring_buffer_create(autofree, ARRAY_SIZE * 1024);
	if (!rb) {
		fprintf(stderr, "Failed creating ring buffer\n");
		fr_exit_now(EXIT_FAILURE);
	}

	seed = 0xabcdef;
	start = 0;
	end = 0;

	/*
	 *	Allocate the first set of blocks.
	 */
	alloc_blocks(rb, &seed, &start, &end);
	verify_start(rb, start);

	/*
	 *	Do 1000 rounds of alloc / free.
	 */
	for (i = 0; i < length; i++) {
		if (debug_lvl) printf("Loop %d (used %zu) \n", i, used);
		alloc_blocks(rb, &seed, &start, &end);
		verify_start(rb, start);

		free_blocks(rb, &seed, &start, &end);
		verify_start(rb, start);
	}

	free_blocks(rb, &seed, &start, &end);
	verify_start(rb, start);

	fr_assert(used == 0);
	fr_assert(fr_ring_buffer_used(rb) == used);

	fr_exit_now(EXIT_SUCCESS);
}
