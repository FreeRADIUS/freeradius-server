/*
 * atomic_ring_test.c	Tests for the segmented SPSC atomic ring
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
 */

RCSID("$Id$")

#include <freeradius-devel/io/atomic_queue.h>
#include <freeradius-devel/util/debug.h>

#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**********************************************************************/
typedef struct request_s request_t;
void request_verify(UNUSED char const *file, UNUSED int line, UNUSED request_t *request);
void request_verify(UNUSED char const *file, UNUSED int line, UNUSED request_t *request) { }
/**********************************************************************/

#define TEST(_name) do { printf("  %-48s ", _name); fflush(stdout); } while (0)
#define OK()         do { printf("ok\n"); } while (0)
#define FAIL(fmt, ...) do { \
	printf("FAIL\n    " fmt "\n", ##__VA_ARGS__); \
	fr_exit_now(EXIT_FAILURE); \
} while (0)

#define CHECK(cond, fmt, ...) do { \
	if (!(cond)) FAIL(fmt, ##__VA_ARGS__); \
} while (0)

/** 1. alloc/free round-trip with nothing ever pushed */
static void test_alloc_free(TALLOC_CTX *ctx)
{
	fr_atomic_ring_t	*ring;

	TEST("alloc/free empty ring");

	ring = fr_atomic_ring_alloc(ctx, 4);
	CHECK(ring != NULL, "fr_atomic_ring_alloc returned NULL");

	fr_atomic_ring_free(&ring);
	CHECK(ring == NULL, "fr_atomic_ring_free did not null the handle");
	OK();
}

/** 2. push/pop within a single segment preserves FIFO */
static void test_push_pop_single_segment(TALLOC_CTX *ctx)
{
	fr_atomic_ring_t	*ring;
	intptr_t		i;
	void			*data;

	TEST("push/pop within one segment preserves FIFO");

	ring = fr_atomic_ring_alloc(ctx, 8);

	for (i = 1; i <= 4; i++) {
		CHECK(fr_atomic_ring_push(ring, (void *)i), "push %" PRIdPTR " failed", i);
	}
	for (i = 1; i <= 4; i++) {
		CHECK(fr_atomic_ring_pop(ring, &data), "pop %" PRIdPTR " failed", i);
		CHECK((intptr_t)data == i, "FIFO broken: expected %" PRIdPTR ", got %" PRIdPTR, i, (intptr_t)data);
	}
	CHECK(!fr_atomic_ring_pop(ring, &data), "pop from empty ring returned true");

	fr_atomic_ring_free(&ring);
	OK();
}

/** 3. push past segment capacity triggers new-segment allocation */
static void test_grow_across_segments(TALLOC_CTX *ctx)
{
	fr_atomic_ring_t	*ring;
	intptr_t		i;
	void			*data;
	size_t const		seg_size = 4;		/* power of 2 */
	size_t const		n = seg_size * 4;	/* force 4 segments */

	TEST("push past segment capacity grows transparently");

	ring = fr_atomic_ring_alloc(ctx, seg_size);

	for (i = 1; i <= (intptr_t)n; i++) {
		CHECK(fr_atomic_ring_push(ring, (void *)i), "push %" PRIdPTR " failed", i);
	}
	for (i = 1; i <= (intptr_t)n; i++) {
		CHECK(fr_atomic_ring_pop(ring, &data), "pop %" PRIdPTR " failed", i);
		CHECK((intptr_t)data == i, "FIFO broken across segments: expected %" PRIdPTR ", got %" PRIdPTR,
		      i, (intptr_t)data);
	}
	CHECK(!fr_atomic_ring_pop(ring, &data), "pop from empty multi-segment ring returned true");

	fr_atomic_ring_free(&ring);
	OK();
}

/** 4. interleaved push/pop keeps FIFO and frees drained segments */
static void test_interleaved(TALLOC_CTX *ctx)
{
	fr_atomic_ring_t	*ring;
	intptr_t		push_seq = 1;
	intptr_t		pop_seq = 1;
	void			*data;
	int			round;

	TEST("interleaved push/pop keeps FIFO across segment advances");

	ring = fr_atomic_ring_alloc(ctx, 4);

	/*
	 *	Push batches larger than segment capacity so we cross
	 *	segment boundaries, then drain.  Many rounds to exercise
	 *	repeated grow-and-retire cycles.
	 */
	for (round = 0; round < 32; round++) {
		int batch = (round % 5) + 6;	/* 6..10 */
		int i;

		for (i = 0; i < batch; i++) {
			CHECK(fr_atomic_ring_push(ring, (void *)push_seq),
			      "push %" PRIdPTR " failed at round %d", push_seq, round);
			push_seq++;
		}
		for (i = 0; i < batch; i++) {
			CHECK(fr_atomic_ring_pop(ring, &data),
			      "pop %" PRIdPTR " failed at round %d", pop_seq, round);
			CHECK((intptr_t)data == pop_seq,
			      "FIFO broken at round %d: expected %" PRIdPTR ", got %" PRIdPTR,
			      round, pop_seq, (intptr_t)data);
			pop_seq++;
		}
		CHECK(!fr_atomic_ring_pop(ring, &data), "ring not empty after round %d", round);
	}

	fr_atomic_ring_free(&ring);
	OK();
}

/** 5. free the ring with items still queued; must not leak/crash */
static void test_free_nonempty(TALLOC_CTX *ctx)
{
	fr_atomic_ring_t	*ring;
	intptr_t		i;

	TEST("free releases all remaining segments");

	ring = fr_atomic_ring_alloc(ctx, 4);

	for (i = 1; i <= 32; i++) {
		CHECK(fr_atomic_ring_push(ring, (void *)i), "push %" PRIdPTR " failed", i);
	}

	fr_atomic_ring_free(&ring);
	OK();
}


/*
 *	Threaded stress test: one producer, one consumer, N items.
 *	Verifies that every pushed item is received in order.
 */

#define STRESS_N	200000

typedef struct {
	fr_atomic_ring_t	*ring;
	size_t			n;
} stress_arg_t;

static void *stress_producer(void *arg)
{
	stress_arg_t	*sa = arg;
	size_t		i;

	for (i = 1; i <= sa->n; i++) {
		while (!fr_atomic_ring_push(sa->ring, (void *)(uintptr_t)i)) {
			/*
			 *	push can only fail on OOM in practice; spin so
			 *	we notice stalls rather than miscounting.
			 */
			sched_yield();
		}
	}
	return NULL;
}

static void *stress_consumer(void *arg)
{
	stress_arg_t	*sa = arg;
	size_t		expect = 1;
	void		*data;
	uintptr_t	*errp;

	errp = malloc(sizeof(*errp));
	*errp = 0;

	while (expect <= sa->n) {
		if (!fr_atomic_ring_pop(sa->ring, &data)) {
			sched_yield();
			continue;
		}
		if ((uintptr_t)data != expect) {
			*errp = expect;
			return errp;
		}
		expect++;
	}

	return errp;	/* 0 on success */
}

static void test_stress_two_thread(TALLOC_CTX *ctx)
{
	fr_atomic_ring_t	*ring;
	pthread_t		prod, cons;
	stress_arg_t		sa;
	void			*cons_ret;
	uintptr_t		err;
	int			rc;

	TEST("producer/consumer stress - 200k items, 4-slot segments");

	ring = fr_atomic_ring_alloc(ctx, 4);
	sa.ring = ring;
	sa.n = STRESS_N;

	rc = pthread_create(&cons, NULL, stress_consumer, &sa);
	CHECK(rc == 0, "pthread_create(consumer) failed: %s", strerror(rc));
	rc = pthread_create(&prod, NULL, stress_producer, &sa);
	CHECK(rc == 0, "pthread_create(producer) failed: %s", strerror(rc));

	pthread_join(prod, NULL);
	pthread_join(cons, &cons_ret);

	err = *(uintptr_t *)cons_ret;
	free(cons_ret);
	CHECK(err == 0, "consumer saw out-of-order item at position %" PRIuPTR, err);

	/*
	 *	Drain anything the producer left behind (shouldn't be any
	 *	at this point since consumer drained through sa.n).
	 */
	{
		void *data;
		CHECK(!fr_atomic_ring_pop(ring, &data), "ring not empty after consumer finished");
	}

	fr_atomic_ring_free(&ring);
	OK();
}


int main(int argc, UNUSED char *argv[])
{
	TALLOC_CTX	*autofree = talloc_autofree_context();

	if (argc > 1) {
		fprintf(stderr, "usage: atomic_ring_test\n");
		return EXIT_FAILURE;
	}

	printf("atomic_ring_test:\n");

	test_alloc_free(autofree);
	test_push_pop_single_segment(autofree);
	test_grow_across_segments(autofree);
	test_interleaved(autofree);
	test_free_nonempty(autofree);
	test_stress_two_thread(autofree);

	printf("  all tests passed\n");
	return EXIT_SUCCESS;
}
