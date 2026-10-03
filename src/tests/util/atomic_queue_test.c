/*
 * atomic_queue_test.c	Tests for atomic queues
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

#include <freeradius-devel/io/atomic_queue.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/table.h>
#include <string.h>
#include <sys/time.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#define OFFSET	(1024)

static int		debug_lvl = 0;

/** Which allocator the queue under test comes from
 */
typedef enum {
	QUEUE_TYPE_TALLOC = 0,		//!< #fr_atomic_queue_talloc, queue lives in the talloc hierarchy.
	QUEUE_TYPE_MALLOC,		//!< #fr_atomic_queue_malloc, raw queue owned by a talloc handle.
	QUEUE_TYPE_MAX
} queue_type_t;

static fr_table_num_sorted_t const queue_type_table[] = {
	{ L("malloc"),	QUEUE_TYPE_MALLOC	},
	{ L("talloc"),	QUEUE_TYPE_TALLOC	}
};
static size_t queue_type_table_len = NUM_ELEMENTS(queue_type_table);


/**********************************************************************/
typedef struct request_s request_t;
void request_verify(UNUSED char const *file, UNUSED int line, UNUSED request_t *request);

void request_verify(UNUSED char const *file, UNUSED int line, UNUSED request_t *request)
{
}
/**********************************************************************/


static NEVER_RETURNS void usage(void)
{
	fprintf(stderr, "usage: atomic_queue_test [OPTS]\n");
	fprintf(stderr, "  -s size                set queue size.\n");
	fprintf(stderr, "  -t type                queue type to test, 'talloc' or 'malloc' (default: both).\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

	fr_exit_now(EXIT_SUCCESS);
}

/** Fill the queue to capacity, check it refuses one more, then drain it
 *
 * Exits the process on the first wrong answer.
 */
static void queue_exercise(fr_atomic_queue_t *aq, int size)
{
	int		i;
	intptr_t	val;
	void		*data;

#ifndef NDEBUG
	if (debug_lvl) {
		printf("Start\n");
		fr_atomic_queue_debug(stdout, aq);

		if (debug_lvl > 1) printf("Filling with %d\n", size);
	}

#endif


	for (i = 0; i < size; i++) {
		val = i + OFFSET;
		data = (void *) val;

		if (!fr_atomic_queue_push(aq, data)) {
			fprintf(stderr, "Failed pushing at %d\n", i);
			fr_exit_now(EXIT_FAILURE);
		}

#ifndef NDEBUG
		if (debug_lvl > 1) {
			printf("iteration %d\n", i);
			fr_atomic_queue_debug(stdout, aq);
		}
#endif
	}

	val = size + OFFSET;
	data = (void *) val;

	/*
	 *	Queue is full.  No more pushes are allowed.
	 */
	if (fr_atomic_queue_push(aq, data)) {
		fprintf(stderr, "Pushed an entry past the end of the queue.");
		fr_exit_now(EXIT_FAILURE);
	}

#ifndef NDEBUG
	if (debug_lvl) {
		printf("Full\n");
		fr_atomic_queue_debug(stdout, aq);

		if (debug_lvl > 1) printf("Emptying\n");
	}
#endif

	/*
	 *	And now pop them all.
	 */
	for (i = 0; i < size; i++) {
		if (!fr_atomic_queue_pop(aq, &data)) {
			fprintf(stderr, "Failed popping at %d\n", i);
			fr_exit_now(EXIT_FAILURE);
		}

		val = (intptr_t) data;
		if (val != (i + OFFSET)) {
			fprintf(stderr, "Pop expected %d, got %d\n",
				i + OFFSET, (int) val);
			fr_exit_now(EXIT_FAILURE);
		}

#ifndef NDEBUG
		if (debug_lvl > 1) {
			printf("iteration %d\n", i);
			fr_atomic_queue_debug(stdout, aq);
		}
#endif
	}

	/*
	 *	Queue is empty.  No more pops are allowed.
	 */
	if (fr_atomic_queue_pop(aq, &data)) {
		fprintf(stderr, "Popped an entry past the end of the queue.");
		fr_exit_now(EXIT_FAILURE);
	}

#ifndef NDEBUG
	if (debug_lvl) {
		printf("Empty\n");
		fr_atomic_queue_debug(stdout, aq);
	}
#endif
}

/** Queue allocated inside the talloc hierarchy
 */
static void test_talloc(TALLOC_CTX *ctx, int size)
{
	fr_atomic_queue_t	*aq;

	aq = fr_atomic_queue_talloc(ctx, size);
	if (!aq) {
		fprintf(stderr, "Failed allocating talloc queue\n");
		fr_exit_now(EXIT_FAILURE);
	}

	queue_exercise(aq, size);
	fr_atomic_queue_free(&aq);
}

/** Queue allocated outside talloc, but owned by a talloc context
 *
 * The only talloc'd block is the owner handle, so the context holds
 * exactly one child, and freeing the context releases the raw queue
 * through the handle.
 */
static void test_malloc(TALLOC_CTX *ctx, int size)
{
	fr_atomic_queue_t	*aq;
	TALLOC_CTX		*owner_ctx;

	owner_ctx = talloc_new(ctx);
	aq = fr_atomic_queue_malloc(owner_ctx, size);
	if (!aq) {
		fprintf(stderr, "Failed allocating raw queue\n");
		fr_exit_now(EXIT_FAILURE);
	}

	if (talloc_total_blocks(owner_ctx) != 2) {
		fprintf(stderr, "Expected owner handle to be the only child of ctx, found %zu blocks\n",
			talloc_total_blocks(owner_ctx));
		fr_exit_now(EXIT_FAILURE);
	}

	queue_exercise(aq, size);
	talloc_free(owner_ctx);
}

typedef void (*queue_test_t)(TALLOC_CTX *ctx, int size);

static queue_test_t const queue_tests[QUEUE_TYPE_MAX] = {
	[QUEUE_TYPE_TALLOC]	= test_talloc,
	[QUEUE_TYPE_MALLOC]	= test_malloc
};

int main(int argc, char *argv[])
{
	int			c;
	int			size;
	int			type;
	bool			selected[QUEUE_TYPE_MAX] = {};
	bool			any_selected = false;
	TALLOC_CTX		*autofree = talloc_autofree_context();

	size = 4;

	while ((c = getopt(argc, argv, "hs:t:x")) != -1) switch (c) {
		case 's':
			size = atoi(optarg);
			break;

		case 't':
			type = fr_table_value_by_str(queue_type_table, optarg, -1);
			if (type < 0) {
				fprintf(stderr, "Unknown queue type '%s'\n", optarg);
				usage();
			}
			selected[type] = true;
			any_selected = true;
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

	for (type = 0; type < QUEUE_TYPE_MAX; type++) {
		if (any_selected && !selected[type]) continue;

		if (debug_lvl) printf("Testing %s queue\n", fr_table_str_by_value(queue_type_table, type, "<INVALID>"));
		queue_tests[type](autofree, size);
	}

	return 0;
}

