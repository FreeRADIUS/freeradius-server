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

/** Functions for a Leftmost Skeleton Tree "instantiated" for an int64_t "key".
 *
 * @file src/lib/util/flst.c
 *
 * @copyright 2021 Network RADIUS SARL (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/flst.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/build.h>

/*
 * Leftmost Skeleton Trees are defined in "Stronger Quickheaps" (Gonzalo Navarro,
 * Rodrigo Paredes, Patricio V. Poblete, and Peter Sanders) International Journal
 * of Foundations of Computer Science, November 2011. As the title suggests, it
 * is inspired by quickheaps, and indeed the underlying representation looks
 * like a quickheap.
 *
 * heap/priority queue operations are defined in the paper in terms of LST
 * operations.
 */

typedef int	stack_index_t;

typedef struct {
	stack_index_t	depth;
	stack_index_t	size;
	fr_flst_index_t	*data;	/* array of indices of the pivots (sometimes called roots) */
}	pivot_stack_t;

struct fr_flst_s {
	fr_flst_index_t	capacity;	//!< Number of elements that will fit
	fr_flst_index_t	idx;		//!< Starting index, initially zero
	fr_flst_index_t	num_elements;	//!< Number of elements in the LST
	size_t		index_offset;	//!< Offset of heap index in element structure.
	size_t		key_offset;	//!< Offset of key index in element structure.
	void		**p;		//!< Array of elements.
	pivot_stack_t	*s;		//!< Stack of pivots, always with depth >= 1.
	fr_fast_rand_t	rand_ctx;	//!< Seed for random choices.
	char const	*type;		//!< Type of elements.
};

#define index_addr(_flst, _data) 		((uint8_t *)(_data) + (_flst)->index_offset)
#define item_index(_flst, _data) 		(*(fr_flst_index_t *)index_addr((_flst), (_data)))

#define key_addr(_flst, _data)			((uint8_t *)(_data) + (_flst)->key_offset)
#define key_value(_flst, _data)			(*(int64_t *)key_addr((_flst), (_data)))

#define is_equivalent(_flst, _index1, _index2)	(index_reduce((_flst), (_index1) - (_index2)) == 0)
#define item(_flst, _index)			((_flst)->p[index_reduce((_flst), (_index))])
#define index_reduce(_flst, _index)		((_index) & ((_flst)->capacity - 1))
#define pivot_item(_flst, _index)		item((_flst), stack_item((_flst)->s, (_index)))

/*
 * The LST as defined in the paper has a fixed size set at creation.
 * Here, as with quickheaps, but we want to allow for expansion.
 */
#define INITIAL_CAPACITY	2048
#define INITIAL_STACK_CAPACITY	32

/*
 * This pseudo "instantiation" of the LST works for data with an int64_t "key";
 * our goal is to avoid a function call for the comparisons...  so here's a
 * function we'll "call" so it can be defined in just one place, but give it
 * attributes that will make sure it's always inlined. (If it's not inlined,
 * you might as well use a plain LST.)
 */
static inline CC_HINT(always_inline, nonnull) int8_t flst_cmp(fr_flst_t *flst, void *data1, void *data2)
{
	int64_t	a = key_value(flst, data1);
	int64_t	b = key_value(flst, data2);

	/*
	 * Perhaps add a bool for max vs min flst, so you'd have
	 * return flst->min ? CMP_PREFER_SMALLER(a, b) : CMP_PREFER_LARGER(a, b);
	 */
	return CMP(a, b);
}

/*
 * The paper defines randomized priority queue operations appropriately for the
 * sum type definition the authors use for LSTs, which are used to implement the
 * RPQ operations. This code, however, deals with the internal representation,
 * including the root/pivot stack, which must change as the LST changes. Also, an
 * insertion or deletion may shift the position of any number of buckets or change
 * the number of buckets.
 *
 * So... for those operations, we will pass in the pointer to the LST, but
 * internally, we'll represent it and its subtrees by that pointer along with
 * the index into the pivot stack of the least pivot that's "greater than or
 * equal to" all the items in the tree, and do the simple recursion elimination
 * so the outside just passes the LST pointer. Immediate consequence: the index
 * is in the half-open interval [0, stack_depth(lst->s)).
 *
 * The fictitious pivot at the bottom of the stack isn't actually in the array,
 * so don't try to refer to what's there.
 *
 * The index is visible for the size and length functions, since they need
 * to know the subtree they're working on.
 */

#define is_bucket(_flst, _stack_index) (flst_length((_flst), (_stack_index)) == 1)

/*
 * First, the canonical stack implementation, customized for LST usage:
 * 1. pop doesn't return a stack value, and even lets you discard multiple
 *    stack items at a time
 * 2. one can fetch and modify arbitrary stack items; when array elements must be
 *    moved to keep them contiguous, the pivot stack entries must change to match.
 */
static pivot_stack_t	*stack_alloc(TALLOC_CTX *ctx)
{
	pivot_stack_t	*s;

	s = talloc_zero(ctx, pivot_stack_t);
	if (!s) return NULL;

	s->data = talloc_array(s, fr_flst_index_t, INITIAL_STACK_CAPACITY);
	if (!s->data) {
		talloc_free(s);
		return NULL;
	}
	s->depth = 0;
	s->size = INITIAL_STACK_CAPACITY;
	return s;
}

static bool stack_expand(pivot_stack_t *s)
{
	fr_flst_index_t	*n;
	size_t		n_size = 2 * s->size;

	n = talloc_realloc(s, s->data, fr_flst_index_t, n_size);
	if (unlikely(!n)) {
		fr_strerror_printf("Failed expanding flst stack to %zu elements (%zu bytes)",
				   n_size, n_size * sizeof(fr_flst_index_t));
		return false;
	}

	s->size = n_size;
	s->data = n;
	return true;
}

static inline CC_HINT(always_inline, nonnull) int stack_push(pivot_stack_t *s, fr_flst_index_t pivot)
{
	if (unlikely(s->depth == s->size && !stack_expand(s))) return -1;

	s->data[s->depth++] = pivot;
	return 0;
}

static inline CC_HINT(always_inline, nonnull) void stack_pop(pivot_stack_t *s, size_t n)
{
	s->depth -= n;
}

static inline CC_HINT(always_inline, nonnull) size_t stack_depth(pivot_stack_t *s)
{
	return s->depth;
}

static inline CC_HINT(always_inline, nonnull) fr_flst_index_t stack_item(pivot_stack_t *s, stack_index_t index)
{
	return s->data[index];
}

static inline CC_HINT(always_inline, nonnull) void stack_set(pivot_stack_t *s, stack_index_t index, fr_flst_index_t new_value)
{
	s->data[index] = new_value;
}

fr_flst_t *_fr_flst_alloc(TALLOC_CTX *ctx, char const *type, size_t index_offset, size_t key_offset)
{
	fr_flst_t	*flst;

	flst = talloc_zero(ctx, fr_flst_t);
	if (!flst) return NULL;

	flst->capacity = INITIAL_CAPACITY;
	flst->p = talloc_array(flst, void *, flst->capacity);
	if (!flst->p) {
	cleanup:
		talloc_free(flst);
		return NULL;
	}

	flst->s = stack_alloc(flst);
	if (!flst->s) goto cleanup;

	/* Initially the LST is empty and we start at the beginning of the array */
	stack_push(flst->s, 0);
	flst->idx = 0;

	/* Prepare for random choices */
	flst->rand_ctx.a = fr_rand();
	flst->rand_ctx.b = fr_rand();

	flst->type = type;
	flst->index_offset = index_offset;
	flst->key_offset = key_offset;

	return flst;
}

/*
 * The length function for LSTs (how many buckets it contains)
 */
static inline CC_HINT(always_inline, nonnull) stack_index_t flst_length(fr_flst_t *flst, stack_index_t stack_index)
{
	return stack_depth(flst->s) - stack_index;
}

/*
 * The size function for LSTs (number of items a (sub)tree contains)
 */
static CC_HINT(nonnull) fr_flst_index_t flst_size(fr_flst_t *flst, stack_index_t stack_index)
{
	fr_flst_index_t	reduced_right, reduced_idx;

	if (stack_index == 0) return flst->num_elements;

	reduced_right = index_reduce(flst, stack_item(flst->s, stack_index));
	reduced_idx = index_reduce(flst, flst->idx);

	if (reduced_idx <= reduced_right) return reduced_right - reduced_idx;	/* No wraparound--easy. */

	return (flst->capacity - reduced_idx) + reduced_right;
}

/*
 * Flatten an LST, i.e. turn it into the base-case one bucket [sub]tree
 * NOTE: so doing leaves the passed stack_index valid--we just add
 * everything once in the left subtree to it.
 */
static inline CC_HINT(always_inline, nonnull) void flst_flatten(fr_flst_t *flst, stack_index_t stack_index)
{
	stack_pop(flst->s, stack_depth(flst->s) - stack_index);
}

/*
 * Move data to a specific location in an LST's array.
 * The caller must have made sure the location is available and exists
 * in said array.
 */
static inline CC_HINT(always_inline, nonnull) void flst_move(fr_flst_t *flst, fr_flst_index_t location, void *data)
{
	item(flst, location) = data;
	item_index(flst, data) = index_reduce(flst, location);
}

/*
 * Add data to the bucket of a specified (sub)tree..
 */
static void bucket_add(fr_flst_t *flst, stack_index_t stack_index, void *data)
{
	fr_flst_index_t	new_space;

	/*
	 * For each bucket to the right, starting from the top,
	 * make a space available at the top and move the bottom item
	 * into it. Since ordering within a bucket doesn't matter, we
	 * can do that, minimizing fiddling with the indices.
	 *
	 * The fictitious pivot doesn't correspond to an actual value,
	 * so we save pivot moving for the end of the loop.
	 */
	for (stack_index_t rindex = 0; rindex < stack_index; rindex++) {
		fr_flst_index_t	prev_pivot_index = stack_item(flst->s, rindex + 1);
		bool		empty_bucket;

		new_space = stack_item(flst->s, rindex);
		empty_bucket = (new_space - prev_pivot_index) == 1;
		stack_set(flst->s, rindex, new_space + 1);

		if (!empty_bucket) flst_move(flst, new_space, item(flst, prev_pivot_index + 1));

		/* move the pivot up, leaving space for the next bucket */
		flst_move(flst, prev_pivot_index + 1, item(flst, prev_pivot_index));
	}

	/*
	 * If the bucket isn't the leftmost, the above loop has made space
	 * available where the pivot used to be.
	 * If it is the leftmost, the loop wasn't executed, but the fictitious
	 * pivot isn't there, which is just as good.
	 */
	new_space = stack_item(flst->s, stack_index);
	stack_set(flst->s, stack_index, new_space + 1);
	flst_move(flst, new_space, data);

	flst->num_elements++;
}

/*
 * Reduce pivot stack indices based on their difference from lst->idx,
 * and then reduce lst->idx.
 */
static void flst_indices_reduce(fr_flst_t *flst)
{
	fr_flst_index_t	reduced_idx = index_reduce(flst, flst->idx);
	stack_index_t	depth = stack_depth(flst->s);

	for (stack_index_t i = 0; i < depth; i++) {
		stack_set(flst->s, i, reduced_idx + stack_item(flst->s, i) - flst->idx);
	}
	flst->idx = reduced_idx;
}

/*
 * Make more space available in an LST.
 * The LST paper only mentions this option in passing, pointing out that it's O(n); the only
 * constructor in the paper lets you hand it an array of items to initially insert
 * in the LST, so elements will have to be removed to make room for more (though it's
 * easy to see how one could specify extra space).
 *
 * Were it not for the circular array optimization, it would be talloc_realloc() and done;
 * it works or it doesn't. (That's still O(n), since it may require copying the data.)
 *
 * With the circular array optimization, if lst->idx refers to something other than the
 * beginning of the array, you have to move the elements preceding it to beginning of the
 * newly-available space so it's still contiguous, and keep pivot stack entries consistent
 * with the positions of the elements.
 */
static bool flst_expand(fr_flst_t *flst)
{
	void 		**n;
	size_t		n_capacity = 2 * flst->capacity;
	fr_flst_index_t	old_capacity = flst->capacity;

	n = talloc_realloc(flst, flst->p, void *, n_capacity);
	if (unlikely(!n)) {
		fr_strerror_printf("Failed expanding flst to %zu elements (%zu bytes)",
				   n_capacity, n_capacity * sizeof(void *));
		return false;
	}

	flst->p = n;
	flst->capacity = n_capacity;

	flst_indices_reduce(flst);

	for (fr_flst_index_t i = 0; i < flst->idx; i++) {
		void		*to_be_moved = item(flst, i);
		fr_flst_index_t	new_index = item_index(flst, to_be_moved) + old_capacity;
		flst_move(flst, new_index, to_be_moved);
	}

	return true;
}

static inline CC_HINT(always_inline, nonnull) fr_flst_index_t bucket_lwb(fr_flst_t *flst, size_t stack_index)
{
	if (is_bucket(flst, stack_index)) return flst->idx;
	return stack_item(flst->s, stack_index + 1) + 1;
}

/*
 * Note: buckets can be empty,
 */
static inline CC_HINT(always_inline, nonnull) fr_flst_index_t bucket_upb(fr_flst_t *flst, size_t stack_index)
{
	return stack_item(flst->s, stack_index) - 1;
}

/*
 * Partition an LST
 * It's only called for trees that are a single nonempty bucket;
 * if it's a subtree, it is thus necessarily the leftmost.
 */
static void partition(fr_flst_t *flst, stack_index_t stack_index)
{
	fr_flst_index_t	low = bucket_lwb(flst, stack_index);
	fr_flst_index_t	high = bucket_upb(flst, stack_index);
	fr_flst_index_t	l, h;
	fr_flst_index_t	pivot_index;
	void		*pivot;
	void		*temp;

	/*
	 * Hoare partition doesn't do the trivial case, so catch it here.
	 */
	if (is_equivalent(flst, low, high)) {
		stack_push(flst->s, low);
		return;
	}

	pivot_index = low + (fr_fast_rand(&flst->rand_ctx) % (high + 1 - low));
	pivot = item(flst, pivot_index);

	if (pivot_index != low) {
		flst_move(flst, pivot_index, item(flst, low));
		flst_move(flst, low, pivot);
	}

	/*
	 * Hoare partition; on the avaerage, it does a third the swaps of
	 * Lomuto.
	 */
	l = low - 1;
	h = high + 1;
	for (;;) {
		while (flst_cmp(flst, item(flst, --h), pivot) > 0) ;
		while (flst_cmp(flst, item(flst, ++l), pivot) < 0) ;
		if (l >= h) break;
		temp = item(flst, l);
		flst_move(flst, l, item(flst, h));
		flst_move(flst, h, temp);
	}

	/*
	 * Hoare partition doesn't guarantee the pivot sits at location h
	 * the way Lomuto does and LST needs, so first get its location...
	 */
	pivot_index = item_index(flst, pivot);
	if (pivot_index >= index_reduce(flst, low)) {
		pivot_index = low + pivot_index - index_reduce(flst, low);
	} else {
		pivot_index = high - (index_reduce(flst, high) - pivot_index);
	}

	/*
	 * ...and then move it if need be.
	 */
	if (pivot_index < h) {
		flst_move(flst, pivot_index, item(flst, h));
		flst_move(flst, h, pivot);
	}
	if (pivot_index > h) {
		h++;
		flst_move(flst, pivot_index, item(flst, h));
		flst_move(flst, h, pivot);
	}

	stack_push(flst->s, h);
}

/*
 * Delete an item from a bucket in an LST
 */
static void bucket_delete(fr_flst_t *flst, stack_index_t stack_index, void *data)
{
	fr_flst_index_t	location = item_index(flst, data);
	fr_flst_index_t	top;

	if (is_equivalent(flst, location, flst->idx)) {
		flst->idx++;
		if (is_equivalent(flst, flst->idx, 0)) flst_indices_reduce(flst);
	} else {
		for (;;) {
			top = bucket_upb(flst, stack_index);
			if (!is_equivalent(flst, location, top)) flst_move(flst, location, item(flst, top));
			stack_set(flst->s, stack_index, top);
			if (stack_index == 0) break;
			flst_move(flst, top, item(flst, top + 1));
			stack_index--;
			location = top + 1;
		}
	}

	flst->num_elements--;
	item_index(flst, data) = -1;
}

/*
 * We precede each function that does the real work with a Pythonish
 * (but colon-free) version of the pseudocode from the paper.
 *
 * clang, in version 13, will have a way to force tail call optimization
 * with a "musttail" attribute. gcc has -f-foptimize-sibling-calls, but
 * it works only with -O[23s]. For now, -O2 will assure TCO. In its absence,
 * the recursion depth is bounded by the number of pivot stack entries, aka
 * the "length" of the LST, which has an expected value proportional to
 * log(number of nodes).
 *
 * NOTE: inlining a recursive function is not advisable, so no
 * always_inline here.
 */

/*
 * ExtractMin(LST T ) // assumes s(T ) > 0
 *	If T = bucket(B) Then
 *		Partition(T ) // O(|B|)
 *	Let T = tree(r, L, B )
 *	If s(L) = 0 Then
 *		Flatten T into bucket(B ) // O(1)
 *		Remove r from bucket B // O(1)
 *		Return r
 *	Else
 *		Return ExtractMin(L)
 */
static inline CC_HINT(nonnull) void *_fr_flst_pop(fr_flst_t *flst, stack_index_t stack_index)
{
	if (is_bucket(flst, stack_index)) partition(flst, stack_index);
	++stack_index;
	if (flst_size(flst, stack_index) == 0) {
		void	*min = pivot_item(flst, stack_index);

		flst_flatten(flst, stack_index);
		bucket_delete(flst, stack_index, min);
		return min;
	}
	return _fr_flst_pop(flst, stack_index);
}

/*
 * FindMin(LST T ) // assumes s(T ) > 0
 * 	If T = bucket(B) Then
 * 		Partition(T ) // O(|B|)
 *	Let T = tree(r, L, B )
 *	If s(L) = 0 Then
 *		Return r
 *	Else
 *		Return FindMin(L)
 */
static inline CC_HINT(nonnull) void *_fr_flst_peek(fr_flst_t *flst, stack_index_t stack_index)
{
	if (is_bucket(flst, stack_index)) partition(flst, stack_index);
	++stack_index;
	if (flst_size(flst, stack_index) == 0) return pivot_item(flst, stack_index);
	return _fr_flst_peek(flst, stack_index);
}

/*
 * Delete(LST T, x ∈ Z)
 *	If T = bucket(B) Then
 *		Remove x from bucket B // O(depth)
 *	Else
 *		Let T = tree(r, L, B′)
 *		If x < r Then
 *			Delete(L, x)
 *		Else If x > r Then
 *			Remove x from bucket B ′ // O(depth)
 *		Else
 *			Flatten T into bucket(B′′) // O(1)
 *			Remove x from bucket B′′ // O(depth)
 */
static inline CC_HINT(nonnull) void _fr_flst_extract(fr_flst_t *flst, stack_index_t stack_index, void *data)
{
	int8_t	cmp;

	if (is_bucket(flst, stack_index)) {
		bucket_delete(flst, stack_index, data);
		return;
	}
	stack_index++;
	cmp = flst_cmp(flst, data, pivot_item(flst, stack_index));
	if (cmp < 0) {
		_fr_flst_extract(flst, stack_index, data);
	} else if (cmp > 0) {
		bucket_delete(flst, stack_index - 1, data);
	} else {
		flst_flatten(flst, stack_index);
		bucket_delete(flst, stack_index, data);
	}
}

/*
 * Insert(LST T, x ∈ Z)
 * 	If T = bucket(B) Then
 * 		Add x to bucket B // O(depth)
 *	Else
 *		Let T = tree(r, L, B)
 *		If random(s(T) + 1) != 1 Then
 *			If x < r Then
 *				Insert(L, x)
 *			Else
 *				Add x to bucket B // O(depth)
 *		Else
 *			Flatten T into bucket(B′) // O(1)
 *			Add x to bucket B′ // O(depth)
 */
static inline CC_HINT(nonnull) void _fr_flst_insert(fr_flst_t *flst, stack_index_t stack_index, void *data)
{
	if (is_bucket(flst, stack_index)) {
		bucket_add(flst, stack_index, data);
		return;
	}
	stack_index++;
	if (fr_fast_rand(&flst->rand_ctx) % (flst_size(flst, stack_index) + 1) != 0) {
		if (flst_cmp(flst, data, pivot_item(flst, stack_index)) < 0) {
			_fr_flst_insert(flst, stack_index, data);
		} else {
			bucket_add(flst, stack_index - 1, data);
		}
	} else {
		flst_flatten(flst, stack_index);
		bucket_add(flst, stack_index, data);
	}
}

/*
 * We represent a (sub)tree with an (lst, stack index) pair, so
 * fr_flst_pop(), fr_flst_peek(), and fr_flst_extract() are minimal
 * wrappers that
 *
 * (1) hide our representation from the user and preserve the interface
 * (2) check preconditions
 */

void *fr_flst_pop(fr_flst_t *flst)
{
	if (unlikely(flst->num_elements == 0)) return NULL;
	return _fr_flst_pop(flst, 0);
}

void *fr_flst_peek(fr_flst_t *flst)
{
	if (unlikely(flst->num_elements == 0)) return NULL;
	return _fr_flst_peek(flst, 0);
}

int fr_flst_extract(fr_flst_t *flst, void *data)
{
	if (unlikely(flst->num_elements == 0)) {
		fr_strerror_const("Tried to extract element from empty LST");
		return -1;
	}

	if (unlikely(item_index(flst, data) < 0)) {
		fr_strerror_const("Tried to extract element not in LST");
		return -1;
	}

	_fr_flst_extract(flst, 0, data);
	return 1;
}

int fr_flst_insert(fr_flst_t *flst, void *data)
{
	fr_flst_index_t	data_index;

	/*
	 * Expand if need be. Not in the paper, but we want the capability.
	 */
	if (unlikely(flst->num_elements == flst->capacity && !flst_expand(flst))) return -1;

	/*
	 * Don't insert something that looks like it's already in an LST.
	 */
	data_index = item_index(flst, data);
	if (unlikely(data_index > 0 ||
	    (data_index == 0 && flst->num_elements > 0 && flst->idx == 0 && item(flst, 0) == data))) {
		fr_strerror_const("Node is already in the LST");
		return -1;
	}

	_fr_flst_insert(flst, 0, data);
	return 1;
}

fr_flst_index_t fr_flst_num_elements(fr_flst_t *flst)
{
	return flst->num_elements;
}

void *fr_flst_iter_init(fr_flst_t *flst, fr_flst_iter_t *iter)
{
	if (unlikely(!flst) || (flst->num_elements == 0)) return NULL;

	*iter = flst->idx;
	return item(flst, *iter);
}

void *fr_flst_iter_next(fr_flst_t *flst, fr_flst_iter_t *iter)
{
	if (unlikely(!flst)) return NULL;

	if ((*iter + 1) >= stack_item(flst->s, 0)) return NULL;
	*iter += 1;

	return item(flst, *iter);
}
