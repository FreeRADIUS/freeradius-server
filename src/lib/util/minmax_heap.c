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

/** Functions for a minmax heap
 *
 * @file src/lib/util/minmax_heap.c
 *
 * @copyright 2021 Network RADIUS SARL (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/minmax_heap.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/debug.h>

/*
 *	The internal representation of minmax heaps is that of plain
 *	binary heaps. They differ in where entries are placed, and how
 *	the operations are done. Also, minmax heaps allow peeking or
 *	popping the maximum value as well as the minimum.
 *
 *	The heap itself is an array of pointers to objects, each of which
 *	contains a key and an fr_minmax_heap_index_t value indicating the
 * 	location in the array holding the pointer to it. To allow 0 to
 *	represent objects not in a heap, the pointers start at element
 *	one of the array rather than element zero. The offset of that
 *	fr_minmax_heap_index_t value is held inside the heap structure.
 *
 *	Minmax heaps are trees, like binary heaps, but the levels (all
 *	values at the same depth) alternate between "min" (starting at
 *	depth 0, i.e. the root) and "max" levels. The operations preserve
 *	these properties:
 *	- A node on a min level will compare as less than or equal to any
 *	  of its descendants.
 *	- A node on a max level will compare as greater than or equal to
 *	  any of its descendants.
 */

struct fr_minmax_heap_s {
	unsigned int		size;		//!< Number of nodes allocated.
	size_t			offset;		//!< Offset of heap index in element structure.

	unsigned int		num_elements;	//!< Number of nodes used.

	char const		*type;		//!< Talloc type of elements.
	fr_minmax_heap_cmp_t	cmp;		//!< Comparator function.

	void			*p[];		//!< Array of nodes.
};

typedef struct fr_minmax_heap_s minmax_heap_t;

#define INITIAL_CAPACITY	2048

/*
 *	First node in a heap is element 1. Children of i are 2i and
 *	2i+1.  These macros wrap the logic, so the code is more
 *	descriptive.
 */
#define HEAP_PARENT(_x)	((_x) >> 1)
#define HEAP_GRANDPARENT(_x)	HEAP_PARENT(HEAP_PARENT(_x))
#define HEAP_LEFT(_x)	(2 * (_x))
#define HEAP_RIGHT(_x) (2 * (_x) + 1 )
#define	HEAP_SWAP(_a, _b) { void *_tmp = _a; _a = _b; _b = _tmp; }

#define is_power_of_2(_n)	((_n) && (((_n) & ((_n) - 1)) == 0))

static bool is_min_level_index(fr_minmax_heap_index_t i)
{
	int8_t	depth = 0;

	while ((1U << depth) < i) depth++;

	/*
	 *	That gives us ceil(log2(i)), but depth is floor(log2(i)), so...
	 */
	if (!is_power_of_2(i)) depth--;

	/*
	 *	min level nodes have even depth, so
	 *	tsome call min and max levels "even" and "odd" respectively.
	 */
	return (depth & 1) == 0;
}

fr_minmax_heap_t *_fr_minmax_heap_alloc(TALLOC_CTX *ctx, fr_minmax_heap_cmp_t cmp, char const *type, size_t offset, unsigned int init)
{
	fr_minmax_heap_t *hp;
	minmax_heap_t *h;

	if (!init) init = INITIAL_CAPACITY;

	hp = talloc(ctx, fr_minmax_heap_t);
	if (unlikely(!hp)) return NULL;

	/*
	 *	For small heaps (< 40 elements) the
	 *	increase in memory locality gives us
	 *	a 100% performance increase
	 *	(talloc headers are big);
	 */
	h = (minmax_heap_t *)talloc_array(hp, uint8_t, sizeof(minmax_heap_t) + (sizeof(void *) * (init + 1)));
	if (unlikely(!h)) return NULL;
	talloc_set_type(h, minmax_heap_t);

	*h = (minmax_heap_t){
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

static int minmax_heap_expand(fr_minmax_heap_t *hp)
{
	minmax_heap_t	*h = *hp;
	unsigned int	n_size;

	/*
	 *	One will almost certainly run out of RAM first,
	 *	but the size must be representable. This form
	 *	of the check avoids overflow.
	 */
	if (unlikely(h->size > UINT_MAX - h->size)) {
		if (h->size == UINT_MAX) {
			fr_strerror_const("Heap is full");
			return -1;
		}
		n_size = UINT_MAX;
	} else {
		n_size = 2 * h->size;
	}

	h = (minmax_heap_t *)talloc_realloc(hp, h, uint8_t, sizeof(minmax_heap_t) + (sizeof(void *) * (n_size + 1)));
	if (unlikely(!h)) {
		fr_strerror_printf("Failed expanding heap to %u elements (%u bytes)",
				   n_size, (n_size * (unsigned int)sizeof(void *)));
		return -1;
	}

	talloc_set_type(h, heap_t);
	h->size = n_size;
	*hp = h;
	return 0;
}


static inline CC_HINT(always_inline, nonnull) fr_minmax_heap_index_t index_get(minmax_heap_t *h, void *data)
{
	return *((fr_minmax_heap_index_t const *)(((uint8_t const *)data) + h->offset));
}

static inline CC_HINT(always_inline, nonnull) void index_set(minmax_heap_t *h, void *data, fr_minmax_heap_index_t idx)
{
	*((fr_minmax_heap_index_t *)(((uint8_t *)data) + h->offset)) = idx;
}

static inline CC_HINT(always_inline, nonnull) bool has_children(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	return HEAP_LEFT(idx) <= h->num_elements;
}

#define OFFSET_SET(_heap, _idx) index_set(_heap, _heap->p[_idx], _idx);
#define OFFSET_RESET(_heap, _idx) index_set(_heap, _heap->p[_idx], 0);

static fr_minmax_heap_index_t min_child_or_grandchild(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	fr_minmax_heap_index_t	min = HEAP_LEFT(idx);
	fr_minmax_heap_index_t  others[] = {
		HEAP_RIGHT(idx),
		HEAP_LEFT(HEAP_LEFT(idx)),
		HEAP_RIGHT(HEAP_LEFT(idx)),
		HEAP_LEFT(HEAP_RIGHT(idx)),
		HEAP_RIGHT(HEAP_RIGHT(idx))
	};

	for (size_t i = 0; i < NUM_ELEMENTS(others) && others[i] <= h->num_elements; i++) {
		if (h->cmp(h->p[others[i]], h->p[min]) < 0) min = others[i];
	}
	return min;
}

static fr_minmax_heap_index_t max_child_or_grandchild(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	fr_minmax_heap_index_t	max = HEAP_LEFT(idx);
	fr_minmax_heap_index_t  others[] = {
		HEAP_RIGHT(idx),
		HEAP_LEFT(HEAP_LEFT(idx)),
		HEAP_RIGHT(HEAP_LEFT(idx)),
		HEAP_LEFT(HEAP_RIGHT(idx)),
		HEAP_RIGHT(HEAP_RIGHT(idx))
	};

	for (size_t i = 0; i < NUM_ELEMENTS(others) && others[i] <= h->num_elements; i++) {
		if (h->cmp(h->p[others[i]], h->p[max]) > 0) max = others[i];
	}
	return max;
}

static void push_down_min(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	fr_minmax_heap_index_t	m;

	for (; has_children(h, idx); idx = m) {
		m = min_child_or_grandchild(h, idx);
		if (h->cmp(h->p[m], h->p[idx]) >= 0) break;
		HEAP_SWAP(h->p[idx], h->p[m]);
		OFFSET_SET(h, idx);
		if (HEAP_PARENT(m) == idx) break;
		if (h->cmp(h->p[m], h->p[HEAP_PARENT(m)]) > 0) {
			HEAP_SWAP(h->p[HEAP_PARENT(m)], h->p[m]);
			OFFSET_SET(h, HEAP_PARENT(m));
		}
	}
	OFFSET_SET(h, idx);
}

static void push_down_max(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	fr_minmax_heap_index_t	m;

	for (; has_children(h, idx); idx = m) {
		m = max_child_or_grandchild(h, idx);
		if (h->cmp(h->p[m], h->p[idx]) <= 0) break;
		HEAP_SWAP(h->p[idx], h->p[m]);
		OFFSET_SET(h, idx);
		if (HEAP_PARENT(m) == idx) break;
		if (h->cmp(h->p[m], h->p[HEAP_PARENT(m)]) < 0) {
			HEAP_SWAP(h->p[HEAP_PARENT(m)], h->p[m]);
			OFFSET_SET(h, HEAP_PARENT(m));
		}
	}
	OFFSET_SET(h, idx);
}

static void push_down(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	if (is_min_level_index(idx)) {
		push_down_min(h, idx);
	} else {
		push_down_max(h, idx);
	}
}

static void push_up_min(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	fr_minmax_heap_index_t	grandparent;

	while (fr_minmax_heap_entry_inserted(grandparent = HEAP_GRANDPARENT(idx)) &&
		h->cmp(h->p[idx], h->p[grandparent]) < 0) {
		HEAP_SWAP(h->p[idx], h->p[grandparent]);
		OFFSET_SET(h, idx);
		idx = grandparent;
	}
	OFFSET_SET(h, idx);
}

static void push_up_max(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	fr_minmax_heap_index_t	grandparent;

	while (fr_minmax_heap_entry_inserted(grandparent = HEAP_GRANDPARENT(idx)) &&
		h->cmp(h->p[idx], h->p[grandparent]) > 0) {
		HEAP_SWAP(h->p[idx], h->p[grandparent]);
		OFFSET_SET(h, idx);
		idx = grandparent;
	}
	OFFSET_SET(h, idx);
}

static void push_up(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	if (idx != 1) {
		fr_minmax_heap_index_t	parent = HEAP_PARENT(idx);
		int8_t	order = h->cmp(h->p[idx], h->p[parent]);
		if (is_min_level_index(idx)) {
			if (order > 0) {
				HEAP_SWAP(h->p[idx], h->p[parent]);
				OFFSET_SET(h, idx);
				push_up_max(h, parent);
			} else {
				push_up_min(h, idx);
			}
		} else {
			if (order < 0) {
				HEAP_SWAP(h->p[idx], h->p[parent]);
				OFFSET_SET(h, idx);
				push_up_min(h, parent);
			} else {
				push_up_max(h, idx);
			}
		}
	}
}

int fr_minmax_heap_insert(fr_minmax_heap_t *hp, void *data)
{
	minmax_heap_t		*h = *hp;
	fr_minmax_heap_index_t	child = index_get(h, data);

	if (unlikely(fr_minmax_heap_entry_inserted(child))) {
		fr_strerror_const("Node is already in a heap");
		return -1;
	}

	child = h->num_elements + 1;
	if (unlikely(child > h->size)) {
		if (unlikely(minmax_heap_expand(hp) < 0)) return -1;
		h = *hp;
	}

	/*
	 *	Add it to the end, and move it up as needed.
	 */
	h->p[child] = data;
	h->num_elements++;
	push_up(h, child);
	OFFSET_SET(h, child);
	return 0;
}

void *fr_minmax_heap_min_peek(fr_minmax_heap_t *hp)
{
	minmax_heap_t	*h = *hp;

	if (h->num_elements == 0) return NULL;
	return h->p[1];
}

void *fr_minmax_heap_min_pop(fr_minmax_heap_t *hp)
{
	void	*data = fr_minmax_heap_min_peek(hp);

	if (!data) return NULL;
	if (unlikely(fr_minmax_heap_extract(hp, data) < 0)) return NULL;
	return data;
}

void *fr_minmax_heap_max_peek(fr_minmax_heap_t *hp)
{
	minmax_heap_t		*h = *hp;
	fr_minmax_heap_index_t	max_index;

	switch (h->num_elements) {
	case 0:
		return NULL;
	case 1:
	case 2:
		max_index = h->num_elements;
		break;
	default:
		max_index = (h->cmp(h->p[2], h->p[3]) < 0) ? 3 : 2;
		break;
	}

	return h->p[max_index];
}

void *fr_minmax_heap_max_pop(fr_minmax_heap_t *hp)
{
	void	*data = fr_minmax_heap_max_peek(hp);

	if (!data) return NULL;
	if (unlikely(fr_minmax_heap_extract(hp, data) < 0)) return NULL;
	return data;
}

int fr_minmax_heap_extract(fr_minmax_heap_t *hp, void *data)
{
	minmax_heap_t		*h = *hp;
	fr_minmax_heap_index_t	idx = index_get(h, data);

	if (h->num_elements < idx) return -1;
	if (!fr_minmax_heap_entry_inserted(index_get(h, data)) || h->p[idx] != data) return -1;

	OFFSET_RESET(h, idx);

	if (h->num_elements == idx) {
		h->num_elements--;
		return 0;
	}

	/*
	 *	Move the last element into the now-available position,
	 *	and then move it down as needed.
	 */
	h->p[idx] = h->p[h->num_elements];
	h->num_elements--;
	push_down(h, idx);
	return 0;
}

/** Return the number of elements in the minmax heap
 *
 * @param[in] hp	to return the number of elements from.
 */
unsigned int fr_minmax_heap_num_elements(fr_minmax_heap_t *hp)
{
	minmax_heap_t *h = *hp;

	return h->num_elements;
}
