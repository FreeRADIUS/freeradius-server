/*
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

/**
 * $Id$
 *
 * @brief Thread-safe queues.
 * @file io/atomic_queue.c
 *
 * This is an implementation of a bounded MPMC ring buffer with per-slot
 * sequence numbers, described by Dmitry Vyukov.
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 * @copyright 2016 Alister Winfield
 */

RCSID("$Id$")

#include <stdint.h>
#include <stdalign.h>
#include <inttypes.h>

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/io/atomic_queue.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/math.h>

/*
 *	Some macros to make our life easier.
 */
#define atomic_int64_t _Atomic(int64_t)
#define atomic_uint32_t _Atomic(uint32_t)
#define atomic_uint64_t _Atomic(uint64_t)

#define cas_incr(_store, _var)    atomic_compare_exchange_strong_explicit(&_store, &_var, _var + 1, memory_order_release, memory_order_relaxed)
#define cas_decr(_store, _var)    atomic_compare_exchange_strong_explicit(&_store, &_var, _var - 1, memory_order_release, memory_order_relaxed)
#define load(_var)           	atomic_load_explicit(&_var, memory_order_relaxed)
#define acquire(_var)        	atomic_load_explicit(&_var, memory_order_acquire)
#define store(_store, _var)  	atomic_store_explicit(&_store, _var, memory_order_release)

#define CACHE_LINE_SIZE	64

/** Entry in the queue
 *
 * @note This structure is cache line aligned for modern AMD/Intel CPUs.
 * This is to avoid contention when the producer and consumer are executing
 * on different CPU cores.
 */
typedef struct CC_HINT(packed, aligned(CACHE_LINE_SIZE)) {
	atomic_int64_t					seq;		//!< Must be seq then data to ensure
									///< seq is 64bit aligned for 32bit address
									///< spaces.
	void						*data;
} fr_atomic_queue_entry_t;

/** Structure to hold the atomic queue
 *
 * @note DO NOT redorder these fields without understanding how alignas works
 * and maintaining separation. The head and tail must be in different cache lines
 * to reduce contention between producers and consumers. Cold data (size, chunk)
 * can share a line, but must be separated from head and tail and entry.
 */
struct fr_atomic_queue_s {
	alignas(CACHE_LINE_SIZE) atomic_int64_t		head;		//!< Position of the producer.
									///< Cache aligned bytes to ensure it's in a
									///< different cache line to tail to reduce
									///< memory contention.

	alignas(CACHE_LINE_SIZE) atomic_int64_t		tail;		//!< Position of the consumer.
									///< Cache aligned bytes to ensure it's in a
									///< different cache line to tail to reduce
									///< memory contention.
									///< Reads may still need to occur from size
									///< whilst the producer is writing to tail.

	alignas(CACHE_LINE_SIZE) size_t			size;		//!< The length of the queue.  This is static.
									///< Also needs to be cache aligned, otherwise
									///< it can end up directly after tail in memory
									///< and share a cache line.

	void						*chunk;		//!< The start of the talloc chunk to pass to free.
									///< We need to play tricks to get aligned memory
									///< with talloc.

	alignas(CACHE_LINE_SIZE) fr_atomic_queue_entry_t entry[];	//!< The entry array, also aligned
									///< to ensure it's not in the same cache
									///< line as tail and size.
};

/** Create fixed-size atomic queue
 *
 * @note the queue must be freed explicitly by the ctx being freed, or by using
 * the #fr_atomic_queue_free function.
 *
 * @param[in] ctx	The talloc ctx to allocate the queue in.
 * @param[in] size	The number of entries in the queue.
 * @return
 *     - NULL on error.
 *     - fr_atomic_queue_t *, a pointer to the allocated and initialized queue.
 */
fr_atomic_queue_t *fr_atomic_queue_alloc(TALLOC_CTX *ctx, size_t size)
{
	size_t			i;
	int64_t			seq;
	fr_atomic_queue_t	*aq;
	TALLOC_CTX		*chunk;

	if (size == 0) return NULL;

	/*
	 *	Roundup to the next power of 2 so we don't need modulo.
	 */
	size = (size_t)fr_roundup_pow2_uint64((uint64_t)size);

	/*
	 *	Allocate a contiguous blob for the header and queue.
	 *	This helps with memory locality.
	 *
	 *	Since we're allocating a blob, we should also set the
	 *	name of the data, too.
	 */
	chunk = talloc_aligned_array(ctx, (void **)&aq, CACHE_LINE_SIZE,
				     sizeof(*aq) + (size) * sizeof(aq->entry[0]));
	if (!chunk) return NULL;
	aq->chunk = chunk;

	talloc_set_name_const(chunk, "fr_atomic_queue_t");

	/*
	 *	Initialize the array.  Data is NULL, and indexes are
	 *	the array entry number.
	 */
	for (i = 0; i < size; i++) {
		seq = i;

		aq->entry[i].data = NULL;
		store(aq->entry[i].seq, seq);
	}

	aq->size = size;

	/*
	 *	Set the head / tail indexes, and force other cores to
	 *	see the writes.
	 */
	store(aq->head, 0);
	store(aq->tail, 0);
	atomic_thread_fence(memory_order_seq_cst);

	return aq;
}

/** Free an atomic queue if it's not freed by ctx
 *
 * This function is needed because the atomic queue memory
 * must be cache line aligned.
 */
void fr_atomic_queue_free(fr_atomic_queue_t **aq)
{
	if (!*aq) return;

	talloc_free((*aq)->chunk);
	*aq = NULL;
}

/** Push a pointer into the atomic queue
 *
 * @param[in] aq	The atomic queue to add data to.
 * @param[in] data	to push.
 * @return
 *	- true on successful push
 *	- false on queue full
 */
bool fr_atomic_queue_push(fr_atomic_queue_t *aq, void *data)
{
	int64_t head;
	fr_atomic_queue_entry_t *entry;

	if (!data) return false;

	/*
	 *	Here we're essentially racing with other producers
	 *	to find the current head of the queue.
	 *
	 *	1. Load the current head (which may be incremented
	 *	   by another producer before we enter the loop).
	 *	2. Find the head entry, which is head modulo the
	 *	   queue size (keeps head looping through the queue).
	 *	3. Read the sequence number of the entry.
	 *	   The sequence numbers are initialised to the index
	 *	   of the entries in the queue.  Each pass of the
	 *	   producer increments the sequence number by one.
	 *	4.
	 *	   a. If the sequence number is equal to the head,
	 *	   then we can use the entry. Increment the head
	 *	   so other producers know we've used it.
	 *	   b. If it's greater than head, the producer has
	 *         already written to this entry, so we need to re-load
	 *	   the head and race other producers again.
	 *	   c. If it's less than the head, the entry has not yet
	 *	   been consumed, and the queue is full.
	 */
	head = load(aq->head);

	/*
	 *	Try to find the current head.
	 */
	for (;;) {
		int64_t seq, diff;

		/*
		 *	Alloc function guarantees size is a power
		 *	of 2, so we can use this hack to avoid
		 *	modulo.
		 */
		entry = &aq->entry[head & (aq->size - 1)];
		seq = acquire(entry->seq);
		diff = (seq - head);

		/*
		 *	head is larger than the current entry, the
		 *	queue is full.
		 *	The consumer will set entry seq to entry +
		 *	queue size, marking it as free for the
		 *	producer to use.
		 */
		if (diff < 0) {
#if 0
			fr_atomic_queue_debug(stderr, aq);
#endif
			return false;
		}

		/*
		 *	Someone else has already written to this entry
		 *	we lost the race, try again.
		 */
		if (diff > 0) {
			head = load(aq->head);
			continue;
		}

		/*
		 *	See if we can increment the head value
		 *	(and check it's still at its old value).
		 *
		 *	This means no two producers can have the same
		 *	entry in the queue, because they can't exit
		 *	the loop until they've incremented the head
		 *	successfully.
		 *
		 *	When we fail, we don't increment head before
		 *	trying again, because we need to detect queue
		 *	full conditions.
		 */
		if (cas_incr(aq->head, head)) {
			break;
		}
	}

	/*
	 *	Store the data in the queue, and increment the entry
	 *	with the new index, and make the write visible to
	 *	other CPUs.
	 */
	entry->data = data;

	/*
	 *	Technically head can overflow.  Practically, with a
	 *	3GHz CPU, doing nothing but incrementing head
	 *	uncontended it'd take about 100 years for this to
	 *	happen.  But hey, maybe someone invents an optical
	 *	CPU with a significantly higher clock speed, it's ok
	 *	for us to exit every 9 quintillion packets.
	 */
#ifdef __clang_analyzer__
	if (unlikely((head + 1) == INT64_MAX)) exit(1);
#endif

	/*
	 *	Mark up the entry as written to.  Any other producer
	 *	attempting to write will see (diff > 0) and retry.
	 */
	store(entry->seq, head + 1);
	return true;
}


/** Pop a pointer from the atomic queue
 *
 * @param[in] aq	the atomic queue to retrieve data from.
 * @param[out] p_data	where to write the data.
 * @return
 *	- true on successful pop
 *	- false on queue empty
 */
bool fr_atomic_queue_pop(fr_atomic_queue_t *aq, void **p_data)
{
	int64_t			tail, seq;
	fr_atomic_queue_entry_t	*entry;

	if (!p_data) return false;

	tail = load(aq->tail);

	for (;;) {
		int64_t diff;

		entry = &aq->entry[tail % aq->size];
		seq = acquire(entry->seq);

		diff = (seq - (tail + 1));

		/*
		 *	Tail is smaller than the current entry,
		 *	the queue is empty.
		 *
		 *	Tail should now be equal to the head.
		 */
		if (diff < 0) {
			return false;
		}

		/*
		 *	Tail is now ahead of us.
		 *	Something else has consumed it.
		 *	We lost the race with another consumer.
		 */
		if (diff > 0) {
			tail = load(aq->tail);
			continue;
		}

		/*
		 *	Same deal as push.
		 *	After this point we own the entry.
		 */
		if (cas_incr(aq->tail, tail)) {
			break;
		}
	}

	/*
	 *	Copy the pointer to the caller BEFORE updating the
	 *	queue entry.
	 */
	*p_data = entry->data;

	/*
	 *	Set the current entry to past the end of the queue.
	 *	This is equal to what head will be on its next pass
	 *	through the queue.  This marks the entry as free.
	 */
	store(entry->seq, tail + aq->size);

	return true;
}

size_t fr_atomic_queue_size(fr_atomic_queue_t *aq)
{
	return aq->size;
}

#ifdef WITH_VERIFY_PTR
/** Check the talloc chunk is still valid
 *
 */
void fr_atomic_queue_verify(fr_atomic_queue_t *aq)
{
	(void)talloc_get_type_abort(aq->chunk, fr_atomic_queue_t);
}
#endif

#ifndef NDEBUG

#if 0
typedef struct {
	int			status;		//!< status of this message
	size_t			data_size;     	//!< size of the data we're sending

	int			signal;		//!< the signal to send
	uint64_t		ack;		//!< or the endpoint..
	void			*ch;		//!< the channel
} fr_control_message_t;
#endif


/**  Dump an atomic queue.
 *
 * Absolutely NOT thread-safe.
 *
 * @param[in] aq	The atomic queue to debug.
 * @param[in] fp	where the debugging information will be printed.
 */
void fr_atomic_queue_debug(FILE * fp, fr_atomic_queue_t *aq)
{
	size_t i;
	int64_t head, tail;

	head = load(aq->head);
	tail = load(aq->head);

	fprintf(fp, "AQ %p size %zu, head %" PRId64 ", tail %" PRId64 "\n",
		aq, aq->size, head, tail);

	for (i = 0; i < aq->size; i++) {
		fr_atomic_queue_entry_t *entry;

		entry = &aq->entry[i];

		fprintf(fp, "\t[%zu] = { %p, %" PRId64 " }",
			i, entry->data, load(entry->seq));
#if 0
		if (entry->data) {
			fr_control_message_t *c;

			c = entry->data;

			fprintf(fp, "\tstatus %d, data_size %zd, signal %d, ack %zd, ch %p",
				c->status, c->data_size, c->signal, c->ack, c->ch);
		}
#endif
		fprintf(fp, "\n");
	}
}
#endif
