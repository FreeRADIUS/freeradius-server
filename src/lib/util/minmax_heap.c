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
#include <freeradius-devel/util/misc.h>

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

static inline uint8_t depth(fr_minmax_heap_index_t i)
{
	return fr_high_bit_pos(i) - 1;
}

static inline bool is_min_level_index(fr_minmax_heap_index_t i)
{
	return (depth(i) & 1) == 0;
}

static inline bool is_descendant(fr_minmax_heap_index_t candidate, fr_minmax_heap_index_t ancestor)
{
	fr_minmax_heap_index_t	level_min;
	uint8_t			candidate_depth = depth(candidate);
	uint8_t			ancestor_depth = depth(ancestor);

	/*
	 *	This will never happen given the its use by fr_minmax_heap_extract(),
	 *	but it's here for safety and to make static analysis happy.
	 */
	if (unlikely(candidate_depth < ancestor_depth)) return false;

	level_min = ((fr_minmax_heap_index_t) 1) << (candidate_depth - ancestor_depth);
	return (candidate - level_min) < level_min;
}

#define is_max_level_index(_i)	(!(is_min_level_index(_i)))

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

static CC_HINT(nonnull) int minmax_heap_expand(fr_minmax_heap_t *hp)
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

	talloc_set_type(h, minmax_heap_t);
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

static inline bool has_grandchildren(minmax_heap_t *h, fr_minmax_heap_index_t i)
{
	return HEAP_LEFT(HEAP_LEFT(i)) <= h->num_elements;
}

#define OFFSET_SET(_heap, _idx) index_set(_heap, _heap->p[_idx], _idx);
#define OFFSET_RESET(_heap, _idx) index_set(_heap, _heap->p[_idx], 0);

/*
 *	The minmax heap has the same basic idea as binary heaps:
 *	1. To insert a value, put it at the bottom and push it up to where it should be.
 * 	2. To remove a value, take it out; if it's not at the bottom, move what is at the
 *	   bottom up to fill the hole, and push it down to where it should be.
 *	The difference is how you push, and the invariants to preserve.
 *
 *	Since we store the index in the item (or zero if it's not in the heap), when we
 *	move an item around, we have to set its index. The general principle is that we
 *	set it when we put the item in the place it will ultimately be when the push_down()
 *	or push_up() is finished.
 */

/** Find the index of the minimum child or grandchild of the entry at a given index.
 *	precondition: has_children(h, idx), i.e. there is stuff in the heap below
 *	idx.
 *
 *	These functions are called by push_down_{min, max}() with idx the index of
 *	an element moved into that position but which may or may not be where it
 *	should ultimately go. The minmax heap property still holds for its (positional,
 *	at least) descendants, though. That lets us cut down on the number of
 *	comparisons over brute force iteration over every child and grandchild.
 *
 * 	In the case where the desired item must be a child, there are at most two,
 *	so we just do it inlne; no loop needed.
 */
static CC_HINT(nonnull) fr_minmax_heap_index_t min_child_or_grandchild(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	fr_minmax_heap_index_t	lwb, upb, min;

	if (is_max_level_index(idx) || !has_grandchildren(h, idx)) {
		/* minimum must be a chld */
		min = HEAP_LEFT(idx);
		upb = HEAP_RIGHT(idx);
		if (upb <= h->num_elements && h->cmp(h->p[upb], h->p[min]) < 0) min = upb;
		return min;
	}

	/* minimum must be a grandchild, unless the right child is childless */
	if (!has_children(h, HEAP_RIGHT(idx))) {
		min = HEAP_RIGHT(idx);
		lwb = HEAP_LEFT(HEAP_LEFT(idx));
	} else {
		min = HEAP_LEFT(HEAP_LEFT(idx));
		lwb = min + 1;
	}
	upb = HEAP_RIGHT(HEAP_RIGHT(idx));

	/* Some grandchildren may not exist. */
	if (upb > h->num_elements) upb = h->num_elements;

	for (fr_minmax_heap_index_t i = lwb; i <= upb; i++) {
		if (h->cmp(h->p[i], h->p[min]) < 0) min = i;
	}
	return min;
}

static CC_HINT(nonnull) fr_minmax_heap_index_t max_child_or_grandchild(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	fr_minmax_heap_index_t	lwb, upb, max;

	if (is_min_level_index(idx) || !has_grandchildren(h, idx)) {
		/* maximum must be a chld */
		max = HEAP_LEFT(idx);
		upb = HEAP_RIGHT(idx);
		if (upb <= h->num_elements && h->cmp(h->p[upb], h->p[max]) > 0) max = upb;
		return max;
	}

	/* minimum must be a grandchild, unless the right child is childless */
	if (!has_children(h, HEAP_RIGHT(idx))) {
		max = HEAP_RIGHT(idx);
		lwb = HEAP_LEFT(HEAP_LEFT(idx));
	} else {
		max = HEAP_LEFT(HEAP_LEFT(idx));
		lwb = max + 1;
	}
	upb = HEAP_RIGHT(HEAP_RIGHT(idx));

	/* Some grandchildren may not exist. */
	if (upb > h->num_elements) upb = h->num_elements;

	for (fr_minmax_heap_index_t i = lwb; i <= upb; i++) {
		if (h->cmp(h->p[i], h->p[max]) > 0) max = i;
	}
	return max;
}

/**
 * precondition: idx is the index of an existing entry on a min level
 */
static inline CC_HINT(always_inline, nonnull) void push_down_min(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	while (has_children(h, idx)) {
		fr_minmax_heap_index_t	m =  min_child_or_grandchild(h, idx);

		/*
		 *	If p[m] doesn't precede p[idx], we're done.
		 */
		if (h->cmp(h->p[m], h->p[idx]) >= 0) break;

		HEAP_SWAP(h->p[idx], h->p[m]);
		OFFSET_SET(h, idx);

		/*
		 *	The entry now at m may belong where the parent is.
		 */
		if (HEAP_GRANDPARENT(m) == idx && h->cmp(h->p[m], h->p[HEAP_PARENT(m)]) > 0) {
			HEAP_SWAP(h->p[HEAP_PARENT(m)], h->p[m]);
			OFFSET_SET(h, HEAP_PARENT(m));
		}
		idx = m;
	}
	OFFSET_SET(h, idx);
}

/**
 * precondition: idx is the index of an existing entry on a max level
 * (Just like push_down_min() save for reversal of ordering, so comments there apply,
 * mutatis mutandis.)
 */
static CC_HINT(nonnull) void push_down_max(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	while (has_children(h, idx)) {
		fr_minmax_heap_index_t	m = max_child_or_grandchild(h, idx);

		if (h->cmp(h->p[m], h->p[idx]) <= 0) break;

		HEAP_SWAP(h->p[idx], h->p[m]);
		OFFSET_SET(h, idx);

		if (HEAP_GRANDPARENT(m) == idx && h->cmp(h->p[m], h->p[HEAP_PARENT(m)]) < 0) {
			HEAP_SWAP(h->p[HEAP_PARENT(m)], h->p[m]);
			OFFSET_SET(h, HEAP_PARENT(m));
		}
		idx = m;
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

	while ((grandparent = HEAP_GRANDPARENT(idx)) > 0 && h->cmp(h->p[idx], h->p[grandparent]) < 0) {
		HEAP_SWAP(h->p[idx], h->p[grandparent]);
		OFFSET_SET(h, idx);
		idx = grandparent;
	}
	OFFSET_SET(h, idx);
}

static void push_up_max(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	fr_minmax_heap_index_t	grandparent;

	while ((grandparent = HEAP_GRANDPARENT(idx)) > 0 && h->cmp(h->p[idx], h->p[grandparent]) > 0) {
		HEAP_SWAP(h->p[idx], h->p[grandparent]);
		OFFSET_SET(h, idx);
		idx = grandparent;
	}
	OFFSET_SET(h, idx);
}

static void push_up(minmax_heap_t *h, fr_minmax_heap_index_t idx)
{
	fr_minmax_heap_index_t	parent;
	int8_t			order;

	/*
	 *	First entry? No need to move; set its index and be done with it.
	 */
	if (idx == 1) {
		OFFSET_SET(h, idx);
		return;
	}

	/*
	 *	Otherwise, move to the next level up if need be.
	 *	Once it's positioned appropriately on an even or odd layer,
	 *	it can percolate up two at a time.
	 */
	parent = HEAP_PARENT(idx);
	order = h->cmp(h->p[idx], h->p[parent]);

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
	return 0;
}

void *fr_minmax_heap_min_peek(fr_minmax_heap_t *hp)
{
	minmax_heap_t	*h = *hp;

	if (unlikely(h->num_elements == 0)) return NULL;
	return h->p[1];
}

void *fr_minmax_heap_min_pop(fr_minmax_heap_t *hp)
{
	void	*data = fr_minmax_heap_min_peek(hp);

	if (unlikely(!data)) return NULL;
	if (unlikely(fr_minmax_heap_extract(hp, data) < 0)) return NULL;
	return data;
}

void *fr_minmax_heap_max_peek(fr_minmax_heap_t *hp)
{
	minmax_heap_t		*h = *hp;

	if (unlikely(h->num_elements == 0)) return NULL;

	if (h->num_elements < 3) return h->p[h->num_elements];

	return h->p[2 + (h->cmp(h->p[2], h->p[3]) < 0)];
}

void *fr_minmax_heap_max_pop(fr_minmax_heap_t *hp)
{
	void	*data = fr_minmax_heap_max_peek(hp);

	if (unlikely(!data)) return NULL;
	if (unlikely(fr_minmax_heap_extract(hp, data) < 0)) return NULL;
	return data;
}

int fr_minmax_heap_extract(fr_minmax_heap_t *hp, void *data)
{
	minmax_heap_t		*h = *hp;
	fr_minmax_heap_index_t	idx = index_get(h, data);

	if (unlikely(h->num_elements < idx)) {
		fr_strerror_printf("data (index %u) exceeds heap size %u", idx, h->num_elements);
		return -1;
	}
	if (unlikely(!fr_minmax_heap_entry_inserted(index_get(h, data)) || h->p[idx] != data)) {
		fr_strerror_printf("data (index %u) not in heap", idx);
		return -1;
	}

	OFFSET_RESET(h, idx);

	/*
	 *	Removing the last element can't break the minmax heap property, so
	 *	decrement the number of elements and be done with it.
	 */
	if (h->num_elements == idx) {
		h->num_elements--;
		return 0;
	}

	/*
	 *	Move the last element into the now-available position,
	 *	and then move it as needed.
	 */
	h->p[idx] = h->p[h->num_elements];
	h->num_elements--;
	/*
	 * If the new position is the root, that's as far up as it gets.
	 * If the old position is a descendant of the new position,
	 * the entry itself remains a descendant of the new position's
	 * parent, and hence by minmax heap property is in the proper
	 * relation to the parent and doesn't need to move up.
	 */
	if (idx > 1 && !is_descendant(h->num_elements, idx)) push_up(h, idx);
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

/** Iterate over entries in a minmax heap
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
void *fr_minmax_heap_iter_init(fr_minmax_heap_t *hp, fr_minmax_heap_iter_t *iter)
{
	minmax_heap_t *h = *hp;

	*iter = 1;

	if (h->num_elements == 0) return NULL;

	return h->p[1];
}

/** Get the next entry in a minmax heap
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
void *fr_minmax_heap_iter_next(fr_minmax_heap_t *hp, fr_minmax_heap_iter_t *iter)
{
	minmax_heap_t *h = *hp;

	if ((*iter + 1) > h->num_elements) return NULL;
	*iter += 1;

	return h->p[*iter];
}

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
void fr_minmax_heap_verify(char const *file, int line, fr_minmax_heap_t const *hp)
{
	minmax_heap_t	*h;

	/*
	 *	The usual start...
	 */
	fr_fatal_assert_msg(hp, "CONSISTENCY CHECK FAILED %s[%i]: fr_minmax_heap_t pointer was NULL", file, line);
	(void) talloc_get_type_abort(hp, fr_minmax_heap_t);

	/*
	 *	Allocating the heap structure and the array holding the heap as described in data structure
	 *	texts together is a respectable savings, but it means adding a level of indirection so the
	 *	fr_heap_t * isn't realloc()ed out from under the user, hence the following (and the use of h
	 *	rather than hp to access anything in the heap structure).
	 */
	h = *hp;
	fr_fatal_assert_msg(h, "CONSISTENCY CHECK FAILED %s[%i]: minmax_heap_t pointer was NULL", file, line);
	(void) talloc_get_type_abort(h, minmax_heap_t);

	fr_fatal_assert_msg(h->num_elements <= h->size,
			    "CONSISTENCY CHECK FAILED %s[%i]: num_elements exceeds size", file, line);

	fr_fatal_assert_msg(h->p[0] == (void *)UINTPTR_MAX,
			    "CONSISTENCY CHECK FAILED %s[%i]: zeroeth element special value overwritten", file, line);

	for (fr_minmax_heap_index_t i = 1; i <= h->num_elements; i++) {
		void	*data = h->p[i];

		fr_fatal_assert_msg(data, "CONSISTENCY CHECK FAILED %s[%i]: node %u was NULL", file, line, i);
		if (h->type) (void)_talloc_get_type_abort(data, h->type, __location__);
		fr_fatal_assert_msg(index_get(h, data) == i,
				    "CONSISTENCY CHECK FAILED %s[%i]: node %u index != %u", file, line, i, i);
	}

	/*
	 *	Verify minmax heap property, which is:
	 *	A node in a min level precedes all its descendants;
	 *	a node in a max level follows all its descencdants.
	 *	(if equal keys are allowed, that should be "doesn't follow" and
	 *	"doesn't precede" respectively)
	 *
	 *	We claim looking at one's children and grandchildren (if any)
	 *	suffices. Why? Induction on floor(depth / 2):
	 *
	 *	Base case:
	 *	   If the depth of the tree is <= 2, that *is* all the
	 *	   descendants, so we're done.
	 *	Induction step:
	 *	   Suppose you're on a min level and the check passes.
	 *	   If the test works on the next min level down, transitivity
	 *	   of <= means the level you're on satisfies the property
	 *	   two levels further down.
	 *	   For max level, >= is transitive, too, so you're good.
	 */

	for (fr_minmax_heap_index_t i = 1; HEAP_LEFT(i) <= h->num_elements; i++) {
		bool			on_min_level = is_min_level_index(i);
		fr_minmax_heap_index_t  others[] = {
			HEAP_LEFT(i),
			HEAP_RIGHT(i),
			HEAP_LEFT(HEAP_LEFT(i)),
			HEAP_RIGHT(HEAP_LEFT(i)),
			HEAP_LEFT(HEAP_RIGHT(i)),
			HEAP_RIGHT(HEAP_RIGHT(i))
		};

		for (size_t j = 0; j < NUM_ELEMENTS(others) && others[j] <= h->num_elements; j++) {
			int8_t	cmp_result = h->cmp(h->p[i], h->p[others[j]]);

			fr_fatal_assert_msg(on_min_level ? (cmp_result <= 0) : (cmp_result >= 0),
					"CONSISTENCY CHECK FAILED %s[%i]: node %u violates %s level condition",
					file, line, i, on_min_level ? "min" : "max");
		}
	}
}
#endif
