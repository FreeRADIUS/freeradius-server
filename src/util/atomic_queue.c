#include <stdint.h>
#include <stdatomic.h>
#include <stdalign.h>
#include <freeradius-devel/util/atomic_queue.h>

/*
 *	Some macros to make our life easier.
 */
#define atomic_int64_t _Atomic(int64_t)

#define cas_incr(_store, _var)    atomic_compare_exchange_strong_explicit(&_store, &_var, _var + 1, memory_order_release, memory_order_relaxed)
#define load(_var)           atomic_load_explicit(&_var, memory_order_relaxed)
#define aquire(_var)         atomic_load_explicit(&_var, memory_order_acquire)
#define store(_store, _var)  atomic_store_explicit(&_store, _var, memory_order_release);


typedef struct fr_atomic_queue_entry_t {
	alignas(128) void *data;
	atomic_int64_t seq;
} fr_atomic_queue_entry_t;

struct fr_atomic_queue_t {
	alignas(128) atomic_int64_t head;
	atomic_int64_t tail;

	int	size;

	fr_atomic_queue_entry_t entry[0];
};

/** Create fixed-size atomic queue.
 *
 * @param[in] ctx the talloc ctx
 * @param[in] size the number of entries in the queue
 * @return
 *     NULL on error
 *     fr_atomic_queue_t *, a pointer to the allocated and initialized queue
 */
fr_atomic_queue_t *fr_atomic_queue_create(TALLOC_CTX *ctx, int size)
{
	int i;
	int64_t seq;
	fr_atomic_queue_t *aq;

	/*
	 *	Allocate a contiguous blob for the header and queue.
	 *	This helps with memory locality.
	 *
	 *	Since we're allocating a blob, we should also set the
	 *	name of the data, too.
	 */
	aq = talloc_size(ctx, sizeof(*aq) + size * sizeof(aq->entry[0]));
	if (!aq) return NULL;

	talloc_set_name(aq, "fr_atomic_queue_t");

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
		 *	head is smaller than the current entry, the queue is full.
		 */
		if (diff < 0) {
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

bool fr_atomic_queue_pop(fr_atomic_queue_t *aq, void **p_data)
{
	int64_t tail, seq;
	fr_atomic_queue_entry_t *entry;

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

#ifndef NDEBUG
/**  Dump an atomic queue.
 *
 *  Absolutely NOT thread-safe.
 */
void fr_atomic_queue_debug(fr_atomic_queue_t *aq, FILE *fp)
{
	int i;
	int64_t head, tail;

	head = load(aq->head);
	tail = load(aq->head);

	fprintf(fp, "AQ %p size %zd, head %zd, tail %zd\n",
		aq, aq->size, head, tail);

	for (i = 0; i < aq->size; i++) {
		fr_atomic_queue_entry_t *entry;

		entry = &aq->entry[i];
		
		fprintf(fp, "\t[%d] = { %p, %zd }\n",
			i, entry->data, load(entry->seq));
	}
}
#endif
