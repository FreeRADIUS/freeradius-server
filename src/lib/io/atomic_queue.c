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
 * sequence numbers, as described by Dmitry Vyukov, and independently
 * discovered/implemented by Alister Winfield.
 *
 * @copyright 2026 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 * @copyright 2016 Alister Winfield
 */

RCSID("$Id$")

#include <stdint.h>
#include <stdalign.h>
#include <inttypes.h>
#include <stdlib.h>

#include <freeradius-devel/autoconf.h>
#include <freeradius-devel/io/atomic_queue.h>
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

/*
 *	The distance two addresses need to be apart so that one core
 *	writing does not slow another core reading. On Apple silicon
 *      the hardware line is 128 bytes.  On x86 the hardware line is
 *      64 bytes but the adjacent line prefetcher fetches lines in
 *      128 byte pairs, so neighbouring 64 byte lines still appear to
 *      contend in benchmarks.
 */
#define CACHE_LINE_SIZE	128

/** One slot in the queue, holding one queued pointer
 *
 * Must not be packed.  Packing drops the struct's alignment to 1
 * (same as an array of uint8_t), so the compiler has to treat `seq`
 * as possibly unaligned.  The native atomic instructions require an
 * aligned address, so clang stops emitting them and calls the
 * libatomic fallback instead, which takes a mutex.  That turns every
 * push and pop on this lock free queue into a locked operation.  gcc
 * emits the native instruction regardless, and relies on the address
 * being aligned at runtime.  Packing saves nothing here anyway, as the
 * two 8 byte fields have no padding between them.
 */
typedef struct {
	atomic_int64_t					seq;		//!< Must be seq then data to ensure
									///< seq is 64bit aligned for 32bit address
									///< spaces.
	void						*data;
} fr_atomic_queue_slot_t;

/** How many stripes a line contains
 *
 */
#define STRIPES_PER_LINE	(CACHE_LINE_SIZE / sizeof(fr_atomic_queue_slot_t))

/** One cache line of stripes
 *
 * A line is padded and aligned to span exactly ONE cache line.
 * A stripe is the set of slots at the same offset in every line, so
 * it runs the complete length of the queue memory.
 *
 * Stripes let a line hold several slots without the slots sharing a
 * cache line with their neighbours in queue order.  Padding each slot
 * out to a full cache line instead would waste the majority of queue
 * memory for no gain.
 *
 * Slot `i` translates to `line[i % num_lines].stripe[i / num_lines]`, i.e.
 * for stripe 0, slot positions match line positions (slot 0 at line 0),
 * and once the slot number exceeds the number of entries in the array we wrap,
 * and use the next stripe.
 *
 @verbatim
                 stripe[0]  stripe[1]  stripe[2]  ...  stripe[7]
               +----------+----------+----------+     +----------+
     line[0]   |  slot 0  |  slot 4  |  slot 8  | ... |  slot 28 |  <- one cache line
               +----------+----------+----------+     +----------+
     line[1]   |  slot 1  |  slot 5  |  slot 9  | ... |  slot 29 |
               +----------+----------+----------+     +----------+
     line[2]   |  slot 2  |  slot 6  |  slot 10 | ... |  slot 30 |
               +----------+----------+----------+     +----------+
     line[3]   |  slot 3  |  slot 7  |  slot 11 | ... |  slot 31 |
               +----------+----------+----------+     +----------+
                    ^
                    one stripe: slots 0..3, one per line
 @endverbatim
 *
 * A producer at position `p` and a consumer at position `c` share a
 * line only when `p` and `c` are congruent modulo the number of lines,
 * this happens rarely enough that there's not a noticeable impact on
 * performance.
 */
typedef struct CC_HINT(aligned(CACHE_LINE_SIZE)) {
	fr_atomic_queue_slot_t				stripe[STRIPES_PER_LINE];
} fr_atomic_queue_line_t;

/** Structure to hold the atomic queue
 *
 * @note DO NOT redorder these fields without understanding how alignas works
 * and maintaining separation. The head and tail must be in different cache lines
 * to reduce contention between producers and consumers. Cold data (size, chunk)
 * can share a cache line, but must be separated from head, tail and the line array.
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


	size_t						line_mask;	//!< Low bits of a slot index give its line:
									///< `line[slot & line_mask]`.  Set at init to
									///< num_lines - 1.

	uint8_t						line_shift;	//!< High bits of a slot index give its stripe
									///< within that line:
									///< `.stripe[slot >> line_shift]`.  Equal to
									///< log2(num_lines).  Set at init,
									///< so a lookup is a mask and a shift, no
									///< division and no modulo!

	void						*chunk;		//!< The start of the talloc chunk to pass to free,
									///< or NULL if this queue was allocated raw via
									///< #fr_atomic_queue_malloc.  We need to play
									///< tricks to get aligned memory with talloc.

	alignas(CACHE_LINE_SIZE) fr_atomic_queue_line_t line[];	        //!< The line array, aligned with cache lines
									///< to ensure producer and consumers don't conflict.
};

/** Number of cache lines needed to hold `size` slots
 *
 * A queue smaller than one line uses a single, partly filled line.
 *
 * @param[in] size	Slot count, already rounded up to a power of 2.
 */
static inline CC_HINT(always_inline) size_t atomic_queue_num_lines(size_t size)
{
	if (size < STRIPES_PER_LINE) return 1;

	return size / STRIPES_PER_LINE;
}

/** Bytes needed for a queue of `size` slots, header included
 *
 * @param[in] size	Slot count, already rounded up to a power of 2.
 */
static inline CC_HINT(always_inline) size_t atomic_queue_bytes(size_t size)
{
	return sizeof(fr_atomic_queue_t) + (atomic_queue_num_lines(size) * sizeof(fr_atomic_queue_line_t));
}

/** Map a queue position to its slot
 *
 * Positions wrap at `size`.  Within one stripe, consecutive positions increment
 * one line at a time, and move to the next stripe once every line has been
 * visited.
 *
 * @param[in] aq	The queue.
 * @param[in] pos	The head or tail position, unmasked.
 */
static inline CC_HINT(always_inline) fr_atomic_queue_slot_t *atomic_queue_slot(fr_atomic_queue_t *aq, int64_t pos)
{
	size_t	idx = (size_t)pos & (aq->size - 1);

	return &aq->line[idx & aq->line_mask].stripe[idx >> aq->line_shift];
}

/** Initialise the sequence numbers and head/tail on a fresh queue buffer
 *
 * Shared between the talloc and raw allocators.  The buffer must already
 * be cache-line aligned and sized to hold `size` slots.
 *
 * @param[in] aq	The queue buffer to initialise.
 * @param[in] size	Slot count, already rounded up to a power of 2.
 */
static void atomic_queue_init(fr_atomic_queue_t *aq, size_t size)
{
	size_t	i, num_lines;

	num_lines = atomic_queue_num_lines(size);

	aq->size = size;
	aq->line_mask = num_lines - 1;
	/*
	 *	num_lines is a power of two, so the shift is its log2.
	 *	The check here is mostly to quiet clang scan, which
	 *	complained about the potential underflow.
	 */
	if (num_lines > 1) {
		aq->line_shift = fr_high_bit_pos(num_lines) - 1;
	} else {
		aq->line_shift = 0;
	}

	/*
	 *	Initialize the slots.  Data is NULL, and the sequence
	 *	number is the position of the slot.
	 */
	for (i = 0; i < size; i++) {
		fr_atomic_queue_slot_t	*slot = atomic_queue_slot(aq, (int64_t)i);

		slot->data = NULL;
		store(slot->seq, (int64_t)i);
	}

	store(aq->head, 0);
	store(aq->tail, 0);
	atomic_thread_fence(memory_order_seq_cst);
}

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
fr_atomic_queue_t *fr_atomic_queue_talloc(TALLOC_CTX *ctx, size_t size)
{
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
	chunk = talloc_aligned_array(ctx, (void **)&aq, CACHE_LINE_SIZE, atomic_queue_bytes(size));
	if (!chunk) return NULL;
	aq->chunk = chunk;

	talloc_set_name_const(chunk, "fr_atomic_queue_t");

	atomic_queue_init(aq, size);

	return aq;
}

/** Create fixed-size atomic queue outside any talloc hierarchy
 *
 * Backed by `posix_memalign`.  The queue has no owner: `chunk` is NULL
 * and the caller releases it with #fr_atomic_queue_free or plain `free()`.
 *
 * For callers that allocate from threads where talloc is not safe (for
 * example, library-owned callback threads).
 *
 * @param[in] size	The number of entries in the queue.
 * @return
 *	- NULL on error.
 *	- fr_atomic_queue_t *, a pointer to the allocated and initialized queue.
 */
static fr_atomic_queue_t *atomic_queue_malloc_raw(size_t size)
{
	fr_atomic_queue_t	*aq;

	if (size == 0) return NULL;

	size = (size_t)fr_roundup_pow2_uint64((uint64_t)size);

	if (posix_memalign((void **)&aq, CACHE_LINE_SIZE, atomic_queue_bytes(size)) != 0) return NULL;

	aq->chunk = NULL;
	atomic_queue_init(aq, size);

	return aq;
}

/** Owner handle for a raw queue allocation
 *
 * The queue memory stays outside the talloc hierarchy.  This handle is
 * the only talloc'd part, so freeing the context the handle lives in
 * frees the queue.
 */
typedef struct {
	fr_atomic_queue_t	*aq;		//!< The raw allocation to release.
} fr_atomic_queue_owner_t;

static int _atomic_queue_owner_free(fr_atomic_queue_owner_t *owner)
{
	free(owner->aq);

	return 0;
}

/** Create fixed-size atomic queue outside the talloc hierarchy, owned by a talloc context
 *
 * The queue itself is a raw `posix_memalign` allocation, so it can be
 * pushed to and popped from by threads where talloc is not safe, and
 * can later be placed in memory talloc does not manage.  A small owner
 * handle allocated in `ctx` frees the queue when `ctx` is freed, or
 * when the caller calls #fr_atomic_queue_free.
 *
 * @param[in] ctx	The talloc ctx which owns the queue.
 * @param[in] size	The number of entries in the queue.
 * @return
 *	- NULL on error.
 *	- fr_atomic_queue_t *, a pointer to the allocated and initialized queue.
 */
fr_atomic_queue_t *fr_atomic_queue_malloc(TALLOC_CTX *ctx, size_t size)
{
	fr_atomic_queue_t	*aq;
	fr_atomic_queue_owner_t	*owner;

	aq = atomic_queue_malloc_raw(size);
	if (!aq) return NULL;

	owner = talloc(ctx, fr_atomic_queue_owner_t);
	if (!owner) {
		free(aq);
		return NULL;
	}
	owner->aq = aq;
	talloc_set_destructor(owner, _atomic_queue_owner_free);
	aq->chunk = owner;

	return aq;
}

/** Free an atomic queue if it's not freed by ctx
 *
 * The queue memory must be cache line aligned, so it lives in one of
 * three places: a talloc aligned array (`chunk` is the array), a raw
 * allocation owned by a talloc handle (`chunk` is the handle, whose
 * destructor frees the queue), or a raw allocation with no owner
 * (`chunk` is NULL).
 */
void fr_atomic_queue_free(fr_atomic_queue_t **aq)
{
	if (!*aq) return;

	if ((*aq)->chunk) {
		talloc_free((*aq)->chunk);
	} else {
		free(*aq);
	}
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
	fr_atomic_queue_slot_t *slot;

	if (!data) return false;

	/*
	 *	Here we're essentially racing with other producers
	 *	to find the current head of the queue.
	 *
	 *	1. Load the current head (which may be incremented
	 *	   by another producer before we enter the loop).
	 *	2. Find the head slot, which is head modulo the
	 *	   queue size (keeps head looping through the queue).
	 *	3. Read the sequence number of the slot.
	 *	   The sequence numbers are initialised to the index
	 *	   of the slots in the queue.  Each pass of the
	 *	   producer increments the sequence number by one.
	 *	4.
	 *	   a. If the sequence number is equal to the head,
	 *	   then we can use the slot. Increment the head
	 *	   so other producers know we've used it.
	 *	   b. If it's greater than head, the producer has
	 *         already written to this slot, so we need to re-load
	 *	   the head and race other producers again.
	 *	   c. If it's less than the head, the slot has not yet
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
		slot = atomic_queue_slot(aq, head);
		seq = acquire(slot->seq);
		diff = (seq - head);

		/*
		 *	head is larger than the current slot, the
		 *	queue is full.
		 *	The consumer will set slot seq to slot +
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
		 *	Someone else has already written to this slot
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
		 *	slot in the queue, because they can't exit
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
	 *	Store the data in the queue, and increment the slot
	 *	with the new index, and make the write visible to
	 *	other CPUs.
	 */
	slot->data = data;

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
	 *	Mark up the slot as written to.  Any other producer
	 *	attempting to write will see (diff > 0) and retry.
	 */
	store(slot->seq, head + 1);
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
	fr_atomic_queue_slot_t	*slot;

	if (!p_data) return false;

	tail = load(aq->tail);

	for (;;) {
		int64_t diff;

		slot = atomic_queue_slot(aq, tail);
		seq = acquire(slot->seq);

		diff = (seq - (tail + 1));

		/*
		 *	Tail is smaller than the current slot,
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
		 *	After this point we own the slot.
		 */
		if (cas_incr(aq->tail, tail)) {
			break;
		}
	}

	/*
	 *	Copy the pointer to the caller BEFORE updating the
	 *	queue slot.
	 */
	*p_data = slot->data;

	/*
	 *	Set the current slot to past the end of the queue.
	 *	This is equal to what head will be on its next pass
	 *	through the queue.  This marks the slot as free.
	 */
	store(slot->seq, tail + aq->size);

	return true;
}

size_t fr_atomic_queue_size(fr_atomic_queue_t *aq)
{
	return aq->size;
}

/*
 *	Segmented single-producer / single-consumer ring.
 *
 *	Safety argument: one producer owns `head` and writes `seg->next`
 *	exactly once (release).  One consumer owns `tail` and reads
 *	`tail->next` with acquire; by the release/acquire pair plus the
 *	invariant "no push into s after s->next is set" the consumer
 *	cannot advance past a segment that still has an in-flight push
 *	as long as it retries `pop(tail->q)` once more after observing
 *	`tail->next != NULL`.
 */

typedef struct fr_atomic_ring_segment_s fr_atomic_ring_segment_t;

struct fr_atomic_ring_segment_s {
	fr_atomic_queue_t		*q;		//!< Per-segment MPMC ring (used SPSC here).
	_Atomic(fr_atomic_ring_segment_t *)	next;		//!< NULL until the producer seals this segment
							///< because it filled up and moved on to a
							///< fresh one.
};

struct fr_atomic_ring_s {
	size_t				seg_size;	//!< Capacity of each segment.
	_Atomic(fr_atomic_ring_segment_t *)	head;		//!< Producer end.  Writer is the single producer,
							///< reader is also the producer - the consumer
							///< never loads this.
	fr_atomic_ring_segment_t		*tail;		//!< Consumer end.  Touched only by the consumer.
};

/** Allocate a fresh segment and its embedded queue
 *
 * Uses the raw (non-talloc) allocator so this function is safe to call
 * from the producer thread even when that thread cannot safely use talloc.
 */
static fr_atomic_ring_segment_t *atomic_ring_segment_alloc(size_t seg_size)
{
	fr_atomic_ring_segment_t	*s;

	s = malloc(sizeof(*s));
	if (!s) return NULL;

	s->q = atomic_queue_malloc_raw(seg_size);
	if (!s->q) {
		free(s);
		return NULL;
	}
	atomic_init(&s->next, NULL);

	return s;
}

static void atomic_ring_segment_free(fr_atomic_ring_segment_t *s)
{
	fr_atomic_queue_free(&s->q);
	free(s);
}

/** talloc destructor for #fr_atomic_ring_t: walk the chain and free segments */
static int _atomic_ring_free(fr_atomic_ring_t *ring)
{
	fr_atomic_ring_segment_t	*s = ring->tail;

	while (s) {
		fr_atomic_ring_segment_t *next = atomic_load_explicit(&s->next, memory_order_acquire);

		atomic_ring_segment_free(s);
		s = next;
	}

	return 0;
}

/** Allocate an empty SPSC ring
 *
 * @param[in] ctx	talloc ctx that owns the ring handle (segments live
 *			outside talloc; they are freed by the ring's
 *			destructor).
 * @param[in] seg_size	Per-segment capacity.  Rounded up to a power of 2.
 * @return
 *	- NULL on error.
 *	- A ring containing one initial (empty) segment.
 */
fr_atomic_ring_t *fr_atomic_ring_alloc(TALLOC_CTX *ctx, size_t seg_size)
{
	fr_atomic_ring_t	*ring;
	fr_atomic_ring_segment_t	*seg;

	if (seg_size == 0) return NULL;

	ring = talloc(ctx, fr_atomic_ring_t);
	if (!ring) return NULL;

	seg = atomic_ring_segment_alloc(seg_size);
	if (!seg) {
		talloc_free(ring);
		return NULL;
	}

	ring->seg_size = seg_size;
	ring->tail = seg;
	atomic_init(&ring->head, seg);
	talloc_set_destructor(ring, _atomic_ring_free);

	return ring;
}

/** Free the ring and all remaining segments
 *
 * Equivalent to `talloc_free()` on the ring, but nulls the caller's
 * handle in the style of #fr_atomic_queue_free.
 */
void fr_atomic_ring_free(fr_atomic_ring_t **ring_p)
{
	if (!*ring_p) return;

	talloc_free(*ring_p);
	*ring_p = NULL;
}

/** Push a pointer into the ring; allocate a new segment on overflow
 *
 * Single-producer only.  Must not be called concurrently with itself.
 *
 * @param[in] ring	Ring to push into.
 * @param[in] data	Value to push (must be non-NULL).
 * @return
 *	- true on success.
 *	- false if both the current segment is full and a new segment
 *	  could not be allocated.
 */
bool fr_atomic_ring_push(fr_atomic_ring_t *ring, void *data)
{
	fr_atomic_ring_segment_t	*h;
	fr_atomic_ring_segment_t	*n;

	h = atomic_load_explicit(&ring->head, memory_order_relaxed);

	if (likely(fr_atomic_queue_push(h->q, data))) return true;

	n = atomic_ring_segment_alloc(ring->seg_size);
	if (unlikely(!n)) return false;

	/*
	 *	Publish ordering matters: the consumer only inspects `h->next`
	 *	and advances past `h` once it sees a non-NULL value there.
	 *	Release here pairs with acquire in fr_atomic_ring_pop.
	 */
	atomic_store_explicit(&h->next, n, memory_order_release);
	atomic_store_explicit(&ring->head, n, memory_order_relaxed);

	/*
	 *	Coverity doesn't track atomic stores as reference
	 *	publication, so it sees `n` going out of scope and
	 *	flags it as leaked.  It isn't: the two atomic stores
	 *	above have published `n` into both `h->next` and
	 *	`ring->head`, and the consumer will free it via
	 *	atomic_ring_segment_free() once it advances past.
	 */
	/* coverity[leaked_storage] */
	return fr_atomic_queue_push(n->q, data);
}

/** Pop a pointer from the ring, advancing past drained segments
 *
 * Single-consumer only.  Must not be called concurrently with itself.
 *
 * @param[in] ring	Ring to pop from.
 * @param[out] p_data	Where to write the popped value on success.
 * @return
 *	- true if a value was popped.
 *	- false if the ring is currently empty.
 */
bool fr_atomic_ring_pop(fr_atomic_ring_t *ring, void **p_data)
{
	fr_atomic_ring_segment_t	*cur;
	fr_atomic_ring_segment_t	*n;
	fr_atomic_ring_segment_t	*old;

	for (;;) {
		cur = ring->tail;

		if (likely(fr_atomic_queue_pop(cur->q, p_data))) return true;

		/*
		 *	Empty from our point of view.  If the producer hasn't
		 *	sealed this segment there might be pushes in our
		 *	future - return and let the caller come back.
		 */
		n = atomic_load_explicit(&cur->next, memory_order_acquire);
		if (!n) return false;

		/*
		 *	Sealed.  One more pop to drain anything the producer
		 *	committed before sealing but after our first (empty)
		 *	pop observation.  Without this re-check, late commits
		 *	in the (empty-observation, seal-observation) window
		 *	would be stranded when we advance past `cur`.
		 */
		if (fr_atomic_queue_pop(cur->q, p_data)) return true;

		old = cur;
		ring->tail = n;
		atomic_ring_segment_free(old);
		/* loop to pop from the new tail */
	}
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
	tail = load(aq->tail);

	fprintf(fp, "AQ %p size %zu, head %" PRId64 ", tail %" PRId64 "\n",
		aq, aq->size, head, tail);

	for (i = 0; i < aq->size; i++) {
		fr_atomic_queue_slot_t *slot;

		slot = atomic_queue_slot(aq, (int64_t)i);

		fprintf(fp, "\t[%zu] = { %p, %" PRId64 " }",
			i, slot->data, load(slot->seq));
#if 0
		if (slot->data) {
			fr_control_message_t *c;

			c = slot->data;

			fprintf(fp, "\tstatus %d, data_size %zd, signal %d, ack %zd, ch %p",
				c->status, c->data_size, c->signal, c->ack, c->ch);
		}
#endif
		fprintf(fp, "\n");
	}
}
#endif
