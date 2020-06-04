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

#define CACHE_LINE_SIZE	64

/** Entry in the queue
 *
 * @note This structure is cache line aligned for modern AMD/Intel CPUs.
 * This is to avoid contention when the producer and consumer are executing
 * on different CPU cores.
 */
typedef struct CC_HINT(packed, aligned(CACHE_LINE_SIZE)) {
	void						*data;
	atomic_int64_t					seq;
} fr_atomic_queue_entry_t;

/** Structure to hold the atomic queue
 *
 */
struct fr_atomic_queue_s {
	alignas(CACHE_LINE_SIZE) atomic_int64_t		head;		//!< Head, aligned bytes to ensure
									///< it's in a different cache line to tail
									///< to reduce memory contention.
	atomic_int64_t					tail;

	size_t						size;

	void						*chunk;		//!< To pass to free. The non-aligned address.

	alignas(CACHE_LINE_SIZE) fr_atomic_queue_entry_t entry[0];	//!< The entry array, also aligned
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
	 *	Set the head / tail indexes, and force other CPUs to
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

	head = load(aq->head);

	/*
	 *	Try to find the current head.
	 */
	for (;;) {
		int64_t seq, diff;

		entry = &aq->entry[ head % aq->size ];
		seq = aquire(entry->seq);
		diff = (seq - head);

		/*
		 *	head is larger than the current entry, the queue is full.
		 */
		if (diff < 0) {
#if 0
			fr_atomic_queue_debug(aq, stderr);
#endif
			return false;
		}

		/*
		 *	Someone else has already written to this entry.  Get the new head pointer, and continue.
		 */
		if (diff > 0) {
			head = load(aq->head);
			continue;
		}

		/*
		 *	We have the possibility that we can write to
		 *	this entry.  Try it.  If the write succeeds,
		 *	we're done.  If the write fails, re-load the
		 *	current head entry, and continue.
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

		entry = &aq->entry[ tail % aq->size ];
		seq = aquire(entry->seq);

		diff = (seq - (tail + 1));

		/*
		 *	tail is smaller than the current entry, the queue is full.
		 */
		if (diff < 0) {
			return false;
		}

		if (diff > 0) {
			tail = load(aq->tail);
			continue;
		}

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
	 *	i.e. it's unused.
	 */
	seq = tail + aq->size;
	store(entry->seq, seq);

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
void fr_atomic_queue_debug(fr_atomic_queue_t *aq, FILE *fp)
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
