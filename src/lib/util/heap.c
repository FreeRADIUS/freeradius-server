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
	size_t		size;			//!< Number of nodes allocated.
	size_t		offset;			//!< Offset of heap index in element structure.

	int32_t		num_elements;		//!< Number of nodes used.

	char const	*type;			//!< Type of elements.
	fr_heap_cmp_t	cmp;			//!< Comparator function.

	void		**p;			//!< Array of nodes.
};

/*
 *	First node in a heap is element 0. Children of i are 2i+1 and
 *	2i+2.  These macros wrap the logic, so the code is more
 *	descriptive.
 */
#define HEAP_PARENT(_x)	(((_x) - 1 ) / 2)
#define HEAP_LEFT(_x)	(2 * (_x) + 1)
/* #define HEAP_RIGHT(_x) (2 * (_x) + 2 ) */
#define	HEAP_SWAP(_a, _b) { void *_tmp = _a; _a = _b; _b = _tmp; }

static void fr_heap_bubble(fr_heap_t *hp, int32_t child);

fr_heap_t *_fr_heap_alloc(TALLOC_CTX *ctx, fr_heap_cmp_t cmp, char const *type, size_t offset)
{
	fr_heap_t *fh;

	if (!cmp) return NULL;

	fh = talloc_zero(ctx, fr_heap_t);
	if (!fh) return NULL;

	fh->size = 2048;
	fh->p = talloc_array(fh, void *, fh->size);
	if (!fh->p) {
		talloc_free(fh);
		return NULL;
	}

	fh->type = type;
	fh->cmp = cmp;
	fh->offset = offset;

	return fh;
}

/*
 *	Insert element in heap. Normally, p != NULL, we insert p in a
 *	new position and bubble up. If p == NULL, then the element is
 *	already in place, and key is the position where to start the
 *	bubble-up.
 *
 *	Returns 1 on failure (cannot allocate new heap entry)
 *
 *	If offset > 0 the position (index, int) of the element in the
 *	heap is also stored in the element itself at the given offset
 *	in bytes.
 */
#define SET_OFFSET(_heap, _node) *((int32_t *)(((uint8_t *)_heap->p[_node]) + _heap->offset)) = _node

/*
 *	RESET_OFFSET is used for sanity checks. It sets offset to an
 *	invalid value.
 */
#define RESET_OFFSET(_heap, _node) *((int32_t *)(((uint8_t *)_heap->p[_node]) + _heap->offset)) = -1

/** Insert a new element into the heap
 *
 * @param[in] hp	The heap to insert an element into.
 * @param[in] data	Data to insert into the heap.
 * @return
 *	- 0 on success.
 *	- -1 on failure (heap full or malloc error).
 */
int fr_heap_insert(fr_heap_t *hp, void *data)
{
	int32_t child;

	/*
	 *	On insert, the heap_id MUST be either:
	 *
	 *	-1 = the node was added / removed from the heap
	 *	     and the heap code set the ID to -1
	 *	0  = the node was just allocated via an "alloc_zero"
	 *	     function
	 */
	child = *((int32_t *)(((uint8_t *)data) + hp->offset));
	if ((child > 0) || ((child == 0) && (data == hp->p[0]))) {
		fr_strerror_printf("Node is already in the heap");
		return -1;
	}

	child = hp->num_elements;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (hp->type) (void)_talloc_get_type_abort(data, hp->type, __location__);
#endif

	/*
	 *	Heap is full.  Double it's size.
	 */
	if ((size_t)child == hp->size) {
		void	**n;
		size_t	n_size = hp->size * 2;

		/*
		 *	heap_id is a 32-bit signed integer.  If the heap will
		 *	grow to contain more than 2B elements, disallow
		 *	integer overflow.  Tho TBH, that should really never
		 *	happen.
		 */
		if (n_size > INT32_MAX) {
			if (hp->size == INT32_MAX) {
				fr_strerror_printf("Heap is full");
				return -1;
			} else {
				n_size = INT32_MAX;
			}
		}

		n = talloc_realloc(hp, hp->p, void *, n_size);
		if (!n) {
			fr_strerror_printf("Failed expanding heap to %zu elements (%zu bytes)",
					   n_size, (n_size * sizeof(void *)));
			return -1;
		}
		hp->size = n_size;
		hp->p = n;
	}

	hp->p[child] = data;
	hp->num_elements++;

 	fr_heap_bubble(hp, child);

	return 0;
}

static void fr_heap_bubble(fr_heap_t *hp, int32_t child)
{
	/*
	 *	Bubble up the element.
	 */
	while (child > 0) {
		int32_t parent = HEAP_PARENT(child);

		/*
		 *	Parent is smaller than the child.  We're done.
		 */
		if (hp->cmp(hp->p[parent], hp->p[child]) < 0) break;

		/*
		 *	Child is smaller than the parent, repeat.
		 */
		HEAP_SWAP(hp->p[child], hp->p[parent]);
		SET_OFFSET(hp, child);
		child = parent;
	}
	SET_OFFSET(hp, child);
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
	int32_t parent, child, max;

	if (unlikely(hp->num_elements == 0)) {
		fr_strerror_printf("Tried to extract element from empty heap");
		return -1;
	}

	max = hp->num_elements - 1;

	/*
	 *	Extract element.  Default is the first one (pop)
	 */
	if (!data) {
		parent = 0;

	} else {		/* extract from the middle */
		parent = *((int32_t *)(((uint8_t *)data) + hp->offset));

		/*
		 *	Out of bounds.
		 */
		if (unlikely((parent < 0) || (parent >= hp->num_elements))) {
			fr_strerror_printf("Heap parent (%i) out of bounds (0-%i)", parent, hp->num_elements);
			return -1;
		}
	}

	RESET_OFFSET(hp, parent);
	child = HEAP_LEFT(parent);
	while (child <= max) {
		/*
		 *	Maybe take the right child.
		 */
		if ((child != max) &&
		    (hp->cmp(hp->p[child + 1], hp->p[child]) < 0)) {
			child = child + 1;
		}
		hp->p[parent] = hp->p[child];
		SET_OFFSET(hp, parent);
		parent = child;
		child = HEAP_LEFT(child);
	}
	hp->num_elements--;

	/*
	 *	We didn't end up at the last element in the heap.
	 *	This element has to be re-inserted.
	 */
	if (parent != max) {
		/*
		 *	Fill hole with last entry and bubble up,
		 *	reusing the insert code
		 */
		hp->p[parent] = hp->p[max];

		fr_heap_bubble(hp, parent);
	}

	return 0;
}


void *fr_heap_peek(fr_heap_t *hp)
{
	if (!hp || (hp->num_elements == 0)) return NULL;

	/*
	 *	If this is NULL, we have a problem.
	 */
	fr_assert(hp->p[0] != NULL);

	return hp->p[0];
}

void *fr_heap_pop(fr_heap_t *hp)
{
	void *data;

	if (hp->num_elements == 0) return NULL;

	data = hp->p[0];
	(void) fr_heap_extract(hp, data);

	return data;
}


void *fr_heap_peek_tail(fr_heap_t *hp)
{
	if (!hp || (hp->num_elements == 0)) return NULL;

	/*
	 *	If this is NULL, we have a problem.
	 */
	return hp->p[hp->num_elements - 1];
}

uint32_t fr_heap_num_elements(fr_heap_t *hp)
{
	if (!hp) return 0;

	return (uint32_t)hp->num_elements;
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
	*iter = 0;

	if (unlikely(!hp) || (hp->num_elements == 0)) return NULL;

	return hp->p[0];
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
	if (unlikely(!hp)) return NULL;

	if ((*iter + 1) >= hp->num_elements) return NULL;
	*iter += 1;

	return hp->p[*iter];
}
