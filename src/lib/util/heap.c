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

/** Functions for a basic binary heaps
 *
 * @file src/lib/util/heap.c
 *
 * @copyright 2005,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/heap.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/debug.h>

/*
 *	A heap entry is made of a pointer to the object, which
 *	contains the key.  The heap itself is an array of pointers.
 *
 *	Heaps normally support only ordered insert, and extraction
 *	of the minimum element.  The heap entry can contain an "int"
 *	field that holds the entries position in the heap.  The offset
 *	of the field is held inside of the heap structure.
 */

struct fr_heap_s {
	unsigned int	size;			//!< Number of nodes allocated.
	size_t		offset;			//!< Offset of heap index in element structure.

	unsigned int	num_elements;		//!< Number of nodes used.

	char const	*type;			//!< Talloc type of elements.
	fr_heap_cmp_t	cmp;			//!< Comparator function.

	void		*p[];			//!< Array of nodes.
};
typedef struct fr_heap_s heap_t;

#define INITIAL_CAPACITY	2048

/*
 *	First node in a heap is element 1. Children of i are 2i and
 *	2i+1.  These macros wrap the logic, so the code is more
 *	descriptive.
 */
#define HEAP_PARENT(_x)	((_x) >> 1)
#define HEAP_LEFT(_x)	(2 * (_x))
/* #define HEAP_RIGHT(_x) (2 * (_x) + 1 ) */
#define	HEAP_SWAP(_a, _b) { void *_tmp = _a; _a = _b; _b = _tmp; }

static void fr_heap_bubble(heap_t *h, fr_heap_index_t child);

/** Return how many bytes need to be allocated to hold a heap of a given size
 *
 * This is useful for passing to talloc[_zero]_pooled_object to avoid additional mallocs.
 *
 * @param[in] count	The initial element count.
 * @return The number of bytes to pre-allocate.
 */
size_t fr_heap_pre_alloc_size(unsigned int count)
{
	return sizeof(fr_heap_t) + sizeof(void *) * count;
}

fr_heap_t *_fr_heap_alloc(TALLOC_CTX *ctx, fr_heap_cmp_t cmp, char const *type, size_t offset, unsigned int init)
{
	fr_heap_t *hp;
	heap_t *h;

	if (!init) init = INITIAL_CAPACITY;

	hp = talloc(ctx, fr_heap_t);
	if (unlikely(!hp)) return NULL;

	/*
	 *	For small heaps (< 40 elements) the
	 *	increase in memory locality gives us
	 *	a 100% performance increase
	 *	(talloc headers are big);
	 */
	h = (heap_t *)talloc_array(ctx, uint8_t, sizeof(heap_t) + (sizeof(void *) * (init + 1)));
	if (unlikely(!h)) return NULL;
	talloc_set_type(h, heap_t);

	*h = (heap_t){
		.size = init,
		.type = type,
		.cmp = cmp,
		.offset = offset
	};

	/*
	 *	As we're using unsigned index values
	 *      index 0 is a special value meaning
	 *      that the data isn't currently inserted
	 *	into the heap.
	 */
	h->p[0] = (void *)UINTPTR_MAX;

	*hp = h;

	return hp;
}

static inline CC_HINT(always_inline, nonnull) fr_heap_index_t index_get(heap_t *h, void *data)
{
	return *((fr_heap_index_t const *)(((uint8_t const *)data) + h->offset));
}

static inline CC_HINT(always_inline, nonnull) void index_set(heap_t *h, void *data, fr_heap_index_t idx)
{
	*((fr_heap_index_t *)(((uint8_t *)data) + h->offset)) = idx;
}

#define OFFSET_SET(_heap, _idx) index_set(_heap, _heap->p[_idx], _idx);
#define OFFSET_RESET(_heap, _idx) index_set(_heap, _heap->p[_idx], 0);

/** Insert a new element into the heap
 *
 * Insert element in heap. Normally, p != NULL, we insert p in a
 * new position and bubble up. If p == NULL, then the element is
 * already in place, and key is the position where to start the
 * bubble-up.
 *
 * Returns -1 on failure (cannot allocate new heap entry)
 *
 * If offset > 0 the position (index, int) of the element in the
 * heap is also stored in the element itself at the given offset
 * in bytes.
 *
 * @param[in] hp	The heap to insert an element into.
 * @param[in] data	Data to insert into the heap.
 * @return
 *	- 0 on success.
 *	- -1 on failure (heap full or malloc error).
 */
int fr_heap_insert(fr_heap_t *hp, void *data)
{
	heap_t *h = *hp;
	fr_heap_index_t child;

	child = index_get(h, data);
	if (fr_heap_entry_inserted(child)) {
		fr_strerror_const("Node is already in the heap");
		return -1;
	}

	child = h->num_elements + 1;	/* Avoid using index 0 */

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (h->type) (void)_talloc_get_type_abort(data, h->type, __location__);
#endif

	/*
	 *	Heap is full.  Double it's size.
	 */
	if (child > h->size) {
		unsigned int	n_size;

		/*
		 *	heap_id is a 32-bit unsigned integer.  If the heap will
		 *	grow to contain more than 4B elements, disallow
		 *	integer overflow.  Tho TBH, that should really never
		 *	happen.
		 */
		if (unlikely(h->size > (UINT_MAX - h->size))) {
			if (h->size == UINT_MAX) {
				fr_strerror_const("Heap is full");
				return -1;
			} else {
				n_size = UINT_MAX;
			}
		} else {
			n_size = h->size * 2;
		}

		h = (heap_t *)talloc_realloc(NULL, h, uint8_t, sizeof(heap_t) + (sizeof(void *) * (n_size + 1)));
		if (unlikely(!h)) {
			fr_strerror_printf("Failed expanding heap to %u elements (%u bytes)",
					   n_size, (n_size * (unsigned int)sizeof(void *)));
			return -1;
		}
		talloc_set_type(h, heap_t);
		h->size = n_size;
		*hp = h;
	}

	h->p[child] = data;
	h->num_elements++;

 	fr_heap_bubble(h, child);

	return 0;
}

static inline CC_HINT(always_inline) void fr_heap_bubble(heap_t *h, fr_heap_index_t child)
{
	if (!fr_cond_assert(child > 0)) return;

	/*
	 *	Bubble up the element.
	 */
	while (child > 1) {
		fr_heap_index_t parent = HEAP_PARENT(child);

		/*
		 *	Parent is smaller than the child.  We're done.
		 */
		if (h->cmp(h->p[parent], h->p[child]) < 0) break;

		/*
		 *	Child is smaller than the parent, repeat.
		 */
		HEAP_SWAP(h->p[child], h->p[parent]);
		OFFSET_SET(h, child);
		child = parent;
	}
	OFFSET_SET(h, child);
}

/** Remove a node from the heap
 *
 * @param[in] hp	The heap to extract an element from.
 * @param[in] data	Data to extract from the heap.
 * @return
 *	- 0 on success.
 *	- -1 on failure (no elements or data not found).
 */
int fr_heap_extract(fr_heap_t *hp, void *data)
{
	heap_t *h = *hp;
	fr_heap_index_t parent, child, max;

	/*
	 *	Extract element.
	 */
	parent = index_get(h, data);

	/*
	 *	Out of bounds.
	 */
	if (unlikely((parent == 0) || (parent > h->num_elements))) {
		fr_strerror_printf("Heap parent (%i) out of bounds (0-%i)", parent, h->num_elements);
		return -1;
	}

	if (unlikely(data != h->p[parent])) {
		fr_strerror_printf("Invalid heap index.  Expected data %p at offset %i, got %p", data,
				   parent, h->p[parent]);
		return -1;
	}
	max = h->num_elements;

	child = HEAP_LEFT(parent);
	OFFSET_RESET(h, parent);
	while (child <= max) {
		/*
		 *	Maybe take the right child.
		 */
		if ((child != max) &&
		    (h->cmp(h->p[child + 1], h->p[child]) < 0)) {
			child = child + 1;
		}
		h->p[parent] = h->p[child];
		OFFSET_SET(h, parent);
		parent = child;
		child = HEAP_LEFT(child);
	}
	h->num_elements--;

	/*
	 *	We didn't end up at the last element in the heap.
	 *	This element has to be re-inserted.
	 */
	if (parent != max) {
		/*
		 *	Fill hole with last entry and bubble up,
		 *	reusing the insert code
		 */
		h->p[parent] = h->p[max];

		fr_heap_bubble(h, parent);
	}

	return 0;
}

void *fr_heap_peek(fr_heap_t *hp)
{
	heap_t *h = *hp;

	if (h->num_elements == 0) return NULL;

	return h->p[1];
}

void *fr_heap_pop(fr_heap_t *hp)
{
	heap_t *h = *hp;

	void *data;

	if (h->num_elements == 0) return NULL;

	data = h->p[1];
	if (unlikely(fr_heap_extract(hp, data) < 0)) return NULL;

	return data;
}

void *fr_heap_peek_tail(fr_heap_t *hp)
{
	heap_t *h = *hp;

	if (h->num_elements == 0) return NULL;

	/*
	 *	If this is NULL, we have a problem.
	 */
	return h->p[h->num_elements];
}

/** Return the number of elements in the heap
 *
 * @param[in] hp	to return the number of elements from.
 */
unsigned int fr_heap_num_elements(fr_heap_t *hp)
{
	heap_t *h = *hp;

	if (h->num_elements == 0) return NULL;

	return h->num_elements;
}

/** Iterate over entries in heap
 *
 * @note If the heap is modified the iterator should be considered invalidated.
 *
 * @param[in] hp	to iterate over.
 * @param[in] iter	Pointer to an iterator struct, used to maintain
 *			state between calls.
 * @return
 *	- User data.
 *	- NULL if at the end of the list.
 */
void *fr_heap_iter_init(fr_heap_t *hp, fr_heap_iter_t *iter)
{
	heap_t *h = *hp;

	*iter = 1;

	if (h->num_elements == 0) return NULL;

	return h->p[1];
}

/** Get the next entry in a heap
 *
 * @note If the heap is modified the iterator should be considered invalidated.
 *
 * @param[in] hp	to iterate over.
 * @param[in] iter	Pointer to an iterator struct, used to maintain
 *			state between calls.
 * @return
 *	- User data.
 *	- NULL if at the end of the list.
 */
void *fr_heap_iter_next(fr_heap_t *hp, fr_heap_iter_t *iter)
{
	heap_t *h = *hp;

	if ((*iter + 1) > h->num_elements) return NULL;
	*iter += 1;

	return h->p[*iter];
}
