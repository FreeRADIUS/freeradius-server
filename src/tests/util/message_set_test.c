/*
 * message_set_test.c	Tests for message sets
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
 * Copyright 2016  Alan DeKok <aland@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/message.h>
#include <string.h>
#include <freeradius-devel/hash.h>
#include <freeradius-devel/rad_assert.h>

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#define MPRINT1 if (debug_lvl) printf
#define MPRINT2 if (debug_lvl > 1) printf

#define ALLOC_SIZE (8)
#define ARRAY_SIZE (4 * ALLOC_SIZE)
#define MY_ARRAY_SIZE (16 * ARRAY_SIZE)

static size_t		used = 0;
static size_t		array[MY_ARRAY_SIZE];
static fr_message_t	*messages[MY_ARRAY_SIZE];
static int		my_alloc_size = ALLOC_SIZE;

static int		debug_lvl = 0;

static char const      	*seed_string = "foo";
static size_t		seed_string_len = 3;

static size_t		reserve_size = 2048;
static size_t		allocation_mask = 0x3ff;

static void  alloc_blocks(fr_message_set_t *ms, uint32_t *seed, UNUSED int *start, int *end)
{
	int i;
	uint32_t hash;

	/*
	 *	We can't allocated the entire array, and we can't
	 *	over-fill the array.
	 */
	rad_assert((size_t) my_alloc_size < MY_ARRAY_SIZE);
	rad_assert((size_t) (my_alloc_size + (*end - *start)) < MY_ARRAY_SIZE);

	MPRINT2("BLOCK ALLOC %d\n", my_alloc_size);

	for (i = 0; i < my_alloc_size; i++) {
		int index;
		fr_message_t *m;

		index = (*end + i) & (MY_ARRAY_SIZE - 1);

		hash = fr_hash_update(seed_string, seed_string_len, *seed);
		*seed = hash;

		hash &= allocation_mask;
		hash++;			/* can't have it zero... */

		array[index] = hash;

		m = fr_message_reserve(ms, reserve_size);
		rad_assert(m != NULL);

		messages[index] = fr_message_alloc(ms, m, hash);
		rad_assert(messages[index] == m);

		if (debug_lvl > 1) printf("%zd\t", hash);

		rad_assert(messages[index]->type == FR_MESSAGE_USED);

		used += hash;
//		rad_assert(fr_ring_buffer_used(rb) == used);
	}

	*end += my_alloc_size;
	rad_assert(*start < *end);
}

static void  free_blocks(fr_message_set_t *ms, UNUSED uint32_t *seed, int *start, int *end)
{
	int i;

	rad_assert(my_alloc_size < MY_ARRAY_SIZE);

	MPRINT2("BLOCK FREE %d\n", my_alloc_size);

	for (i = 0; i < my_alloc_size; i++) {
		int index;
		int rcode;

		index = (*start + i) & (MY_ARRAY_SIZE - 1);

		rad_assert(messages[index]->type == FR_MESSAGE_USED);

		rcode = fr_message_done(ms, messages[index]);
		rad_assert(rcode == 0);

		used -= array[index];

		array[index] = 0;
		messages[index] = NULL;
	}

	*start += my_alloc_size;
	if (*start > MY_ARRAY_SIZE) {
		*start -= MY_ARRAY_SIZE;
		*end -= MY_ARRAY_SIZE;
		rad_assert(*start <= *end);
		rad_assert(*start < MY_ARRAY_SIZE);
	}
}

static void NEVER_RETURNS usage(void)
{
	MPRINT1("usage: message_set_test [OPTS]\n");
	MPRINT1("  -x                     Debugging mode.\n");
	MPRINT1("  -s <string>            Set random seed to <string>.\n");

	exit(1);
}

int main(UNUSED int argc, UNUSED char *argv[])
{
	int c;

	int i, start, end, rcode;
	fr_message_set_t *ms;
	uint32_t	seed;

	TALLOC_CTX	*autofree = talloc_init("main");

	memset(array, 0, sizeof(array));
	memset(messages, 0, sizeof(messages));

	while ((c = getopt(argc, argv, "hs:x")) != EOF) switch (c) {
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
	argc -= (optind - 1);
	argv += (optind - 1);

	ms = fr_message_set_create(autofree, ARRAY_SIZE, ARRAY_SIZE * 1024);
	if (!ms) {
		fprintf(stderr, "Failed creating message set\n");
		exit(1);
	}

	seed = 0xabcdef;
	start = 0;
	end = 0;
	my_alloc_size = ALLOC_SIZE;

	/*
	 *	Allocate the first set of blocks.
	 */
	alloc_blocks(ms, &seed, &start, &end);
	
	/*
	 *	Do 1000 rounds of alloc / free.
	 */
	for (i = 0; i < 4; i++) {
		MPRINT2("Loop %d (used %zd) \n", i, used);
		alloc_blocks(ms, &seed, &start, &end);

		free_blocks(ms, &seed, &start, &end);
	}

	MPRINT1("TEST 1 used %d (%zd)\n", fr_message_set_messages_used(ms), used);

	/*
	 *	Double the size of the allocations
	 */
	reserve_size <<= 1;

	allocation_mask <<= 1;
	allocation_mask |= 1;

	/*
	 *	Do another 1000 rounds of alloc / free.
	 */
	for (i = 0; i < 1000; i++) {
		MPRINT2("Second loop %d (used %zd) \n", i, used);
		alloc_blocks(ms, &seed, &start, &end);

		free_blocks(ms, &seed, &start, &end);
	}

	MPRINT1("TEST 2 used %d\n", fr_message_set_messages_used(ms));

	/*
	 *	Double the size of the allocations
	 */
	reserve_size <<= 1;

	allocation_mask <<= 1;
	allocation_mask |= 1;

	/*
	 *	Do another 1000 rounds of alloc / free.
	 */
	for (i = 0; i < 1000; i++) {
		MPRINT2("Third loop %d (used %zd) \n", i, used);
		alloc_blocks(ms, &seed, &start, &end);

		free_blocks(ms, &seed, &start, &end);
	}
	
	/*
	 *	Double the number of the allocations,
	 *	but decrease the allocation size back to 1K
	 */
	my_alloc_size *= 2;
	reserve_size = 2048;
	allocation_mask = (reserve_size - 1) >> 1;

	MPRINT1("TEST 3 used %d\n", fr_message_set_messages_used(ms));

	/*
	 *	Do another 1000 rounds of alloc / free.
	 */
	for (i = 0; i < 1000; i++) {
		MPRINT2("Fourth loop %d (used %zd) \n", i, used);
		alloc_blocks(ms, &seed, &start, &end);

		free_blocks(ms, &seed, &start, &end);
	}

	MPRINT1("TEST 4 used %d\n", fr_message_set_messages_used(ms));

	/*
	 *	Double the number of the allocations again,
	 *	leaving the allocation size alone.
	 */
	my_alloc_size *= 2;

	/*
	 *	Do another 10000 rounds of alloc / free.
	 */
	for (i = 0; i < 10000; i++) {
		MPRINT2("fifth loop %d (used %zd) \n", i, used);
		alloc_blocks(ms, &seed, &start, &end);

		free_blocks(ms, &seed, &start, &end);
	}

	MPRINT1("TEST 5 used %d\n", fr_message_set_messages_used(ms));

	/*
	 *	Double the number of the allocations again,
	 *	leaving the allocation size alone.
	 */
	my_alloc_size *= 2;

	/*
	 *	Do another 10000 rounds of alloc / free.
	 */
	for (i = 0; i < 10000; i++) {
		MPRINT2("sixth loop %d (used %zd) \n", i, used);
		alloc_blocks(ms, &seed, &start, &end);

		free_blocks(ms, &seed, &start, &end);
	}

	MPRINT1("TEST 6 used %d\n", fr_message_set_messages_used(ms));

	my_alloc_size = end - start;
	free_blocks(ms, &seed, &start, &end);

	rad_assert(used == 0);

	for (i = 0; i < MY_ARRAY_SIZE; i++) {
		rad_assert(messages[i] == NULL);
	}

	/*
	 *	Force all messages to be garbage collected
	 */
	MPRINT1("GC\n");
	fr_message_set_gc(ms);

	/*
	 *	After the garbage collection, all messages marked "done" MUST also be marked "free".
	 */
	rcode = fr_message_set_messages_used(ms);
	rad_assert(rcode == 0);

	talloc_free(autofree);

	return rcode;
}

