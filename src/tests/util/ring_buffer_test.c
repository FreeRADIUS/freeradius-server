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
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/syserror.h>
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
typedef struct rad_request REQUEST;
REQUEST *request_alloc(UNUSED TALLOC_CTX *ctx);
void request_verify(UNUSED char const *file, UNUSED int line, UNUSED REQUEST *request);
int talloc_const_free(void const *ptr);

REQUEST *request_alloc(UNUSED TALLOC_CTX *ctx)
{
	return NULL;
}

void request_verify(UNUSED char const *file, UNUSED int line, UNUSED REQUEST *request)
{
}

int talloc_const_free(void const *ptr)
{
	void *tmp;
	if (!ptr) return;

	memcpy(&tmp, &ptr, sizeof(tmp));
	talloc_free(tmp);
}
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

		if (!fr_cond_assert(p != NULL)) exit(EXIT_FAILURE);

		data[index] = fr_ring_buffer_alloc(rb, hash);
		if (!fr_cond_assert(data[index] == p)) exit(EXIT_FAILURE);

		if (debug_lvl > 1) printf("%08x\t", hash);

		used += hash;
		rad_assert(fr_ring_buffer_used(rb) == used);
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
		if (!fr_cond_assert(rcode == 0)) exit(EXIT_FAILURE);

		used -= array[index];
		rad_assert(fr_ring_buffer_used(rb) == used);

		array[index] = 0;
		data[index] = NULL;
	}

	*start += ALLOC_SIZE;
	if (*start > ARRAY_SIZE) {
		*start -= ARRAY_SIZE;
		*end -= ARRAY_SIZE;
	}
}

static void NEVER_RETURNS usage(void)
{
	fprintf(stderr, "usage: ring_buffer_test [OPTS]\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");
	fprintf(stderr, "  -s <string>            Set random seed to <string>.\n");
	fprintf(stderr, "  -l <lenght>            Set the interation number to <length>.\n");

	exit(EXIT_SUCCESS);
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

	rb = fr_ring_buffer_create(autofree, ARRAY_SIZE * 1024);
	if (!rb) {
		fprintf(stderr, "Failed creating ring buffer\n");
		exit(EXIT_FAILURE);
	}

	seed = 0xabcdef;
	start = 0;
	end = 0;

	/*
	 *	Allocate the first set of blocks.
	 */
	alloc_blocks(rb, &seed, &start, &end);

	/*
	 *	Do 1000 rounds of alloc / free.
	 */
	for (i = 0; i < length; i++) {
		if (debug_lvl) printf("Loop %d (used %zu) \n", i, used);
		alloc_blocks(rb, &seed, &start, &end);

		free_blocks(rb, &seed, &start, &end);
	}

	free_blocks(rb, &seed, &start, &end);

	rad_assert(used == 0);
	rad_assert(fr_ring_buffer_used(rb) == used);

	exit(EXIT_SUCCESS);
}
