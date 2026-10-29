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
#include <freeradius-devel/util/strerror.h>
#include <string.h>
#include <sys/time.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

#define OFFSET	(1024)

static int		debug_lvl = 0;

/** Which allocator the queue under test comes from
 */
typedef enum : uint8_t {
	QUEUE_TYPE_TALLOC = 0,		//!< #fr_atomic_queue_talloc, queue lives in the talloc hierarchy.
	QUEUE_TYPE_MALLOC,		//!< #fr_atomic_queue_malloc, raw queue owned by a talloc handle.
	QUEUE_TYPE_MMAP,		//!< #fr_atomic_queue_mmap, shared memory queue owned by a talloc handle.
	QUEUE_TYPE_MAX
} queue_type_t;

static fr_table_num_sorted_t const queue_type_table[] = {
	{ L("malloc"),	QUEUE_TYPE_MALLOC	},
	{ L("mmap"),	QUEUE_TYPE_MMAP		},
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
	fprintf(stderr, "  -t type                queue type to test, 'talloc', 'malloc' or 'mmap' (default: all).\n");
	fprintf(stderr, "  -x                     Debugging mode.\n");

	fr_exit_now(EXIT_SUCCESS);
}

/** Fill the queue to capacity, check it refuses one more, then drain it
 *
 * Exits the process on the first wrong answer.
 */
static void queue_exercise_flavour(fr_atomic_queue_t *aq, int size,
				   bool (*push)(fr_atomic_queue_t *, void const *),
				   bool (*pop)(fr_atomic_queue_t *, void *))
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

		if (!push(aq, &data)) {
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
	if (push(aq, &data)) {
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
		if (!pop(aq, &data)) {
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
	if (pop(aq, &data)) {
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

/** Fill and drain with the many-producer functions, then the single-producer ones
 */
static void queue_exercise(fr_atomic_queue_t *aq, int size)
{
	queue_exercise_flavour(aq, size, fr_atomic_queue_mpmc_push, fr_atomic_queue_mpmc_pop);
	queue_exercise_flavour(aq, size, fr_atomic_queue_spsc_push, fr_atomic_queue_spsc_pop);
}

/** Queue allocated inside the talloc hierarchy
 */
static void test_talloc(TALLOC_CTX *ctx, int size)
{
	fr_atomic_queue_t	*aq;

	aq = fr_atomic_queue_talloc(ctx, size, sizeof(uintptr_t));
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
	aq = fr_atomic_queue_malloc(owner_ctx, size, sizeof(uintptr_t));
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

/** Queue in a shared memory mapping, owned by a talloc handle
 *
 * As test_malloc for the creator.  Then a second queue is attached to
 * the creator's descriptor, as another process would, and elements
 * pushed through one are popped from the other.
 */
static void test_mmap(TALLOC_CTX *ctx, int size)
{
	fr_atomic_queue_t	*aq, *peer;
	TALLOC_CTX		*owner_ctx, *peer_ctx;
	int			fd = -1, peer_fd, bad_fd, i;
	intptr_t		val;
	void			*data;

	owner_ctx = talloc_new(ctx);
	aq = fr_atomic_queue_mmap(owner_ctx, &fd, size, sizeof(uintptr_t));
	if (!aq) {
		fprintf(stderr, "Failed allocating mapped queue: %s\n", fr_strerror());
		fr_exit_now(EXIT_FAILURE);
	}

	if ((talloc_total_blocks(owner_ctx) != 2) || (fd < 0)) {
		fprintf(stderr, "Expected an owner handle as the only child of ctx and a descriptor, "
			"found %zu blocks, fd %d\n", talloc_total_blocks(owner_ctx), fd);
		fr_exit_now(EXIT_FAILURE);
	}

	queue_exercise(aq, size);

	/*
	 *	Attach as a second process would, with its own descriptor.
	 */
	peer_fd = dup(fd);
	if (peer_fd < 0) {
		fprintf(stderr, "Failed duplicating queue descriptor\n");
		fr_exit_now(EXIT_FAILURE);
	}

	peer_ctx = talloc_new(ctx);
	peer = fr_atomic_queue_mmap(peer_ctx, &peer_fd, size, sizeof(uintptr_t));
	if (!peer) {
		fprintf(stderr, "Failed attaching to mapped queue: %s\n", fr_strerror());
		fr_exit_now(EXIT_FAILURE);
	}

	bad_fd = dup(fd);
	if (fr_atomic_queue_mmap(peer_ctx, &bad_fd, size, sizeof(uintptr_t) * 2)) {
		fprintf(stderr, "Attached to a mapped queue with the wrong element size\n");
		fr_exit_now(EXIT_FAILURE);
	}
	close(bad_fd);

	for (i = 0; i < size; i++) {
		val = i + OFFSET;
		data = (void *) val;
		if (!fr_atomic_queue_spsc_push(aq, &data)) {
			fprintf(stderr, "Failed pushing to shared queue at %d\n", i);
			fr_exit_now(EXIT_FAILURE);
		}
	}

	for (i = 0; i < size; i++) {
		if (!fr_atomic_queue_spsc_pop(peer, &data)) {
			fprintf(stderr, "Failed popping from the attached queue at %d\n", i);
			fr_exit_now(EXIT_FAILURE);
		}
		val = (intptr_t) data;
		if (val != (i + OFFSET)) {
			fprintf(stderr, "Attached queue returned %" PRIdPTR " at %d, expected %" PRIdPTR "\n",
				val, i, (intptr_t) (i + OFFSET));
			fr_exit_now(EXIT_FAILURE);
		}
	}

	/*
	 *	The creator going away leaves the attached mapping valid.
	 */
	talloc_free(owner_ctx);
	val = OFFSET;
	data = (void *) val;
	if (!fr_atomic_queue_spsc_push(peer, &data) ||
	    !fr_atomic_queue_spsc_pop(peer, &data) ||
	    ((intptr_t) data != OFFSET)) {
		fprintf(stderr, "Attached queue unusable after the creator freed its mapping\n");
		fr_exit_now(EXIT_FAILURE);
	}
	talloc_free(peer_ctx);
}

typedef void (*queue_test_t)(TALLOC_CTX *ctx, int size);

static queue_test_t const queue_tests[QUEUE_TYPE_MAX] = {
	[QUEUE_TYPE_TALLOC]	= test_talloc,
	[QUEUE_TYPE_MALLOC]	= test_malloc,
	[QUEUE_TYPE_MMAP]	= test_mmap
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

