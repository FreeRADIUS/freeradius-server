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

/** Functions for a Leftmost Skeleton Tree
 *
 * @file src/lib/util/lst.c
 *
 * @copyright 2021 Network RADIUS SARL (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/lst.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/strerror.h>

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

/*
 * The LST as defined in the paper has a fixed size set at creation.
 * Here, as with quickheaps, but we want to allow for expansion...
 * though given that, as the paper shows, the expected stack depth
 * is proportion to the log of the number of items in the LST, expanding
 * the pivot stack may be a rare event.
 */
#define INITIAL_CAPACITY	2048

#define is_power_of_2(_n)	((_n) && (((_n) & ((_n) - 1)) == 0))

typedef unsigned int stack_index_t;

typedef struct {
	stack_index_t	depth;		//!< The current stack depth.
	unsigned int	size;		//!< The current stack size (number of frames)
	fr_lst_index_t	*data;		//!< Array of indices of the pivots (sometimes called roots)
} pivot_stack_t;

struct fr_lst_s {
	unsigned int	capacity;	//!< Number of elements that will fit
	fr_lst_index_t	idx;		//!< Starting index, initially zero
	unsigned int	num_elements;	//!< Number of elements in the LST
	size_t		offset;		//!< Offset of heap index in element structure.
	void		**p;		//!< Array of elements.
	pivot_stack_t	s;		//!< Stack of pivots, always with depth >= 1.
	fr_fast_rand_t	rand_ctx;	//!< Seed for random choices.
	char const	*type;		//!< Type of elements.
	fr_lst_cmp_t	cmp;		//!< Comparator function.
};

static inline fr_lst_index_t stack_item(pivot_stack_t const *s, stack_index_t idx) CC_HINT(always_inline, nonnull);
static inline stack_index_t lst_length(fr_lst_t const *lst, stack_index_t stack_index) CC_HINT(always_inline, nonnull);

static inline CC_HINT(always_inline, nonnull) void *index_addr(fr_lst_t const *lst, void *data)
{
	return ((uint8_t *)data) + (lst)->offset;
}

/*
 * Concerning item_index() and item_index_set():
 * To let zero be the value *as stored in an item* that indicates not being in an LST,
 * we add one to the real index when storing it and subtract one when retrieving it.
 *
 * This lets the LST functions use item indices in [0, lst->capacity), important for
 * 1. the circular array, which allows an important optimization for fr_lst_pop()
 * 2. quick reduction of indices
 *
 * fr_item_insert() needs to see the value actually stored, hence raw_item_index().
 */
static inline CC_HINT(always_inline, nonnull) fr_lst_index_t raw_item_index(fr_lst_t const *lst, void *data)
{
	return *(fr_lst_index_t *)index_addr(lst, data);
}

static inline CC_HINT(always_inline, nonnull) fr_lst_index_t item_index(fr_lst_t const *lst, void *data)
{
	return  raw_item_index(lst, data) - 1;
}

static inline CC_HINT(always_inline, nonnull) void item_index_set(fr_lst_t *lst, void *data, fr_lst_index_t idx)
{
	(*(fr_lst_index_t *)index_addr(lst, data)) = idx + 1;
}

static inline CC_HINT(always_inline, nonnull) fr_lst_index_t index_reduce(fr_lst_t const *lst, fr_lst_index_t idx)
{
	return idx & ((lst)->capacity - 1);
}

static inline CC_HINT(always_inline, nonnull)
bool is_equivalent(fr_lst_t const *lst, fr_lst_index_t idx1, fr_lst_index_t idx2)
{
	return (index_reduce(lst, idx1 - idx2) == 0);
}

static inline CC_HINT(always_inline, nonnull) void item_set(fr_lst_t *lst, fr_lst_index_t idx, void *data)
{
	lst->p[index_reduce(lst, idx)] = data;
}

static inline CC_HINT(always_inline, nonnull) void *item(fr_lst_t const *lst, fr_lst_index_t idx)
{
	return (lst->p[index_reduce(lst, idx)]);
}

static inline CC_HINT(always_inline, nonnull) void *pivot_item(fr_lst_t const *lst, stack_index_t idx)
{
	return item(lst, stack_item(&lst->s, idx));
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
 * internally, we'll represent it and its subtrees with an (LST pointer, stack index)
 * pair. The index is that of the least pivot greater than or equal to all items in
 * the subtree (considering the "fictitious" pivot greater than anything, so (lst, 0)
 * represents the entire tree.
 *
 * The fictitious pivot at the bottom of the stack isn't actually in the array,
 * so don't try to refer to what's there.
 *
 * The index is visible for the size and length functions, since they need
 * to know the subtree they're working on.
 */
static inline CC_HINT(always_inline, nonnull) bool is_bucket(fr_lst_t const *lst, stack_index_t idx)
{
	return lst_length(lst, idx) == 1;
}

static bool stack_expand(fr_lst_t *lst, pivot_stack_t *s)
{
	fr_lst_index_t	*n;
	unsigned int	n_size;

#ifndef NDEBUG
	/*
	 *	This likely can't happen, we just include
	 *	the guard to keep static analysis happy.
	 */
	if (unlikely(s->size > (UINT_MAX - s->size))) {
		if (s->size == UINT_MAX) {
			fr_strerror_const("lst stack is full");
			return false;
		} else {
			n_size = UINT_MAX;
		}
	} else {
#endif
		n_size = s->size * 2;
#ifndef NDEBUG
	}
#endif

	n = talloc_realloc(lst, s->data, fr_lst_index_t, n_size);
	if (unlikely(!n)) {
		fr_strerror_printf("Failed expanding lst stack to %u elements (%u bytes)",
				   n_size, n_size * (unsigned int)sizeof(fr_lst_index_t));
		return false;
	}

	s->size = n_size;
	s->data = n;
	return true;
}

static inline CC_HINT(always_inline, nonnull) int stack_push(fr_lst_t *lst, pivot_stack_t *s, fr_lst_index_t pivot)
{
	if (unlikely(s->depth == s->size && !stack_expand(lst, s))) return -1;

	s->data[s->depth++] = pivot;
	return 0;
}

static inline CC_HINT(always_inline, nonnull) void stack_pop(pivot_stack_t *s, unsigned int n)
{
	s->depth -= n;
}

static inline CC_HINT(always_inline, nonnull) stack_index_t stack_depth(pivot_stack_t const *s)
{
	return s->depth;
}

static inline fr_lst_index_t stack_item(pivot_stack_t const *s, stack_index_t idx)
{
	return s->data[idx];
}

static inline CC_HINT(always_inline, nonnull)
void stack_set(pivot_stack_t *s, stack_index_t idx, fr_lst_index_t new_value)
{
	s->data[idx] = new_value;
}

fr_lst_t *_fr_lst_alloc(TALLOC_CTX *ctx, fr_lst_cmp_t cmp, char const *type, size_t offset, fr_lst_index_t init)
{
	fr_lst_t	*lst;
	pivot_stack_t	*s;
	unsigned int	initial_stack_capacity;

	if (!init) {
		init = INITIAL_CAPACITY;
	} else if (!is_power_of_2(init)) {
		init = 1 << fr_high_bit_pos(init);
	}

	for (initial_stack_capacity = 1; (1U << initial_stack_capacity) < init; initial_stack_capacity++) ;

	/*
	 *	Pre-allocate stack memory as it is
	 *	unlikely to need to grow in practice.
	 *
	 *	We don't pre-allocate the array of elements
	 *	If we pre-allocated the array of elements
	 *	we'd end up wasting that memory as soon as
	 *	we needed to expand the array.
	 *
	 *	Pre-allocating three chunks appears to be
	 *	the optimum.
	 */
	lst = talloc_zero_pooled_object(ctx, fr_lst_t, 3, (initial_stack_capacity * sizeof(fr_lst_index_t)));
	if (unlikely(!lst)) return NULL;

	lst->capacity = init;
	lst->p = talloc_array(lst, void *, lst->capacity);
	if (unlikely(!lst->p)) {
	cleanup:
		talloc_free(lst);
		return NULL;
	}

	/*
	 *	Allocate the initial stack
	 */
	s = &lst->s;
	s->data = talloc_array(lst, fr_lst_index_t, initial_stack_capacity);
	if (unlikely(!s->data)) goto cleanup;
	s->depth = 0;
	s->size = initial_stack_capacity;

	/* Initially the LST is empty and we start at the beginning of the array */
	stack_push(lst, &lst->s, 0);

	lst->idx = 0;

	/* Prepare for random choices */
	lst->rand_ctx.a = fr_rand();
	lst->rand_ctx.b = fr_rand();

	lst->type = type;
	lst->cmp = cmp;
	lst->offset = offset;

	return lst;
}

/** The length function for LSTs (how many buckets it contains)
 *
 */
static inline stack_index_t lst_length(fr_lst_t const *lst, stack_index_t stack_index)
{
	return stack_depth(&lst->s) - stack_index;
}

/** The size function for LSTs (number of items a (sub)tree contains)
 *
 */
static CC_HINT(nonnull) fr_lst_index_t lst_size(fr_lst_t *lst, stack_index_t stack_index)
{
	fr_lst_index_t	reduced_right, reduced_idx;

	if (stack_index == 0) return lst->num_elements;

	reduced_right = index_reduce(lst, stack_item(&lst->s, stack_index));
	reduced_idx = index_reduce(lst, lst->idx);

	if (reduced_idx <= reduced_right) return reduced_right - reduced_idx;	/* No wraparound--easy. */

	return (lst->capacity - reduced_idx) + reduced_right;
}

/** Flatten an LST, i.e. turn it into the base-case one bucket [sub]tree
 *
 * NOTE: so doing leaves the passed stack_index valid--we just add
 * everything once in the left subtree to it.
 */
static inline CC_HINT(always_inline, nonnull) void lst_flatten(fr_lst_t *lst, stack_index_t stack_index)
{
	stack_pop(&lst->s, stack_depth(&lst->s) - stack_index);
}

/** Move data to a specific location in an LST's array.
 *
 * The caller must have made sure the location is available and exists
 * in said array.
 */
static inline CC_HINT(always_inline, nonnull) void lst_move(fr_lst_t *lst, fr_lst_index_t location, void *data)
{
	item_set(lst, location, data);
	item_index_set(lst, data, index_reduce(lst, location));
}

/**  Add data to the bucket of a specified (sub)tree..
 *
 */
static void bucket_add(fr_lst_t *lst, stack_index_t stack_index, void *data)
{
	fr_lst_index_t	new_space;
	stack_index_t	ridx;

	/*
	 * For each bucket to the right, starting from the top,
	 * make a space available at the top and move the bottom item
	 * into it. Since ordering within a bucket doesn't matter, we
	 * can do that, minimizing moving and index adjustment.
	 *
	 * The fictitious pivot doesn't correspond to an actual value,
	 * so we save pivot moving for the end of the loop.
	 */
	for (ridx = 0; ridx < stack_index; ridx++) {
		fr_lst_index_t	prev_pivot_index = stack_item(&lst->s, ridx + 1);
		bool		empty_bucket;

		new_space = stack_item(&lst->s, ridx);
		empty_bucket = (new_space - prev_pivot_index) == 1;
		stack_set(&lst->s, ridx, new_space + 1);

		if (!empty_bucket) lst_move(lst, new_space, item(lst, prev_pivot_index + 1));

		/* move the pivot up, leaving space for the next bucket */
		lst_move(lst, prev_pivot_index + 1, item(lst, prev_pivot_index));
	}

	/*
	 * If the bucket isn't the leftmost, the above loop has made space
	 * available where the pivot used to be.
	 * If it is the leftmost, the loop wasn't executed, but the fictitious
	 * pivot isn't there, which is just as good.
	 */
	new_space = stack_item(&lst->s, stack_index);
	stack_set(&lst->s, stack_index, new_space + 1);
	lst_move(lst, new_space, data);

	lst->num_elements++;
}

/** Reduce pivot stack indices based on their difference from lst->idx, and then reduce lst->idx
 *
 */
static void lst_indices_reduce(fr_lst_t *lst)
{
	fr_lst_index_t	reduced_idx = index_reduce(lst, lst->idx);
	stack_index_t	depth = stack_depth(&lst->s), i;

	for (i = 0; i < depth; i++) stack_set(&lst->s, i, reduced_idx + stack_item(&lst->s, i) - lst->idx);

	lst->idx = reduced_idx;
}

/** Make more space available in an LST
 *
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
static bool lst_expand(fr_lst_t *lst)
{
	void 		**n;
	unsigned int	old_capacity = lst->capacity, n_capacity;
	fr_lst_index_t	i;

	if (unlikely(old_capacity > (UINT_MAX - old_capacity))) {
		if (old_capacity == UINT_MAX) {
			fr_strerror_const("lst is full");
			return false;
		} else {
			n_capacity = UINT_MAX;
		}
	} else {
		n_capacity = old_capacity * 2;
	}

	n = talloc_realloc(lst, lst->p, void *, n_capacity);
	if (unlikely(!n)) {
		fr_strerror_printf("Failed expanding lst to %u elements (%u bytes)",
				   n_capacity, n_capacity * (unsigned int)sizeof(void *));
		return false;
	}

	lst->p = n;
	lst->capacity = n_capacity;

	lst_indices_reduce(lst);

	for (i = 0; i < lst->idx; i++) {
		void		*to_be_moved = item(lst, i);
		fr_lst_index_t	new_index = item_index(lst, to_be_moved) + old_capacity;

		lst_move(lst, new_index, to_be_moved);
	}

	return true;
}

static inline CC_HINT(always_inline, nonnull) fr_lst_index_t bucket_lwb(fr_lst_t const *lst, stack_index_t stack_index)
{
	if (is_bucket(lst, stack_index)) return lst->idx;

	return stack_item(&lst->s, stack_index + 1) + 1;
}

/*
 * Note: buckets can be empty,
 */
static inline CC_HINT(always_inline, nonnull) fr_lst_index_t bucket_upb(fr_lst_t const *lst, stack_index_t stack_index)
{
	return stack_item(&lst->s, stack_index) - 1;
}

/*
 * Partition an LST
 * It's only called for trees that are a single nonempty bucket;
 * if it's a subtree, it is thus necessarily the leftmost.
 */
static void partition(fr_lst_t *lst, stack_index_t stack_index)
{
	fr_lst_index_t	low = bucket_lwb(lst, stack_index);
	fr_lst_index_t	high = bucket_upb(lst, stack_index);
	fr_lst_index_t	l, h;
	fr_lst_index_t	pivot_index;
	void		*pivot;
	void		*temp;

	/*
	 * Hoare partition doesn't do the trivial case, so catch it here.
	 */
	if (is_equivalent(lst, low, high)) {
		stack_push(lst, &lst->s, low);
		return;
	}

	pivot_index = low + (fr_fast_rand(&lst->rand_ctx) % (high + 1 - low));
	pivot = item(lst, pivot_index);

	if (pivot_index != low) {
		lst_move(lst, pivot_index, item(lst, low));
		lst_move(lst, low, pivot);
	}

	/*
	 * Hoare partition; on the avaerage, it does a third the swaps of
	 * Lomuto.
	 */
	l = low - 1;
	h = high + 1;
	for (;;) {
		while (lst->cmp(item(lst, --h), pivot) > 0) ;
		while (lst->cmp(item(lst, ++l), pivot) < 0) ;
		if (l >= h) break;
		temp = item(lst, l);
		lst_move(lst, l, item(lst, h));
		lst_move(lst, h, temp);
	}

	/*
	 * Hoare partition doesn't guarantee the pivot sits at location h
	 * the way Lomuto does and LST needs, so first get its location...
	 */
	pivot_index = item_index(lst, pivot);
	if (pivot_index >= index_reduce(lst, low)) {
		pivot_index = low + pivot_index - index_reduce(lst, low);
	} else {
		pivot_index = high - (index_reduce(lst, high) - pivot_index);
	}

	/*
	 * ...and then move it if need be.
	 */
	if (pivot_index < h) {
		lst_move(lst, pivot_index, item(lst, h));
		lst_move(lst, h, pivot);
	}
	if (pivot_index > h) {
		h++;
		lst_move(lst, pivot_index, item(lst, h));
		lst_move(lst, h, pivot);
	}

	stack_push(lst, &lst->s, h);
}

/*
 * Delete an item from a bucket in an LST
 */
static void bucket_delete(fr_lst_t *lst, stack_index_t stack_index, void *data)
{
	fr_lst_index_t	location = item_index(lst, data);
	fr_lst_index_t	top;

	if (is_equivalent(lst, location, lst->idx)) {
		lst->idx++;
		if (is_equivalent(lst, lst->idx, 0)) lst_indices_reduce(lst);
	} else {
		for (;;) {
			top = bucket_upb(lst, stack_index);
			if (!is_equivalent(lst, location, top)) lst_move(lst, location, item(lst, top));
			stack_set(&lst->s, stack_index, top);
			if (stack_index == 0) break;
			lst_move(lst, top, item(lst, top + 1));
			stack_index--;
			location = top + 1;
		}
	}

	lst->num_elements--;
	item_index_set(lst, data, -1);
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
static inline CC_HINT(nonnull) void *_fr_lst_pop(fr_lst_t *lst, stack_index_t stack_index)
{
	if (is_bucket(lst, stack_index)) partition(lst, stack_index);
	++stack_index;
	if (lst_size(lst, stack_index) == 0) {
		void *min = pivot_item(lst, stack_index);

		lst_flatten(lst, stack_index);
		bucket_delete(lst, stack_index, min);
		return min;
	}
	return _fr_lst_pop(lst, stack_index);
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
static inline CC_HINT(nonnull) void *_fr_lst_peek(fr_lst_t *lst, stack_index_t stack_index)
{
	if (is_bucket(lst, stack_index)) partition(lst, stack_index);
	++stack_index;
	if (lst_size(lst, stack_index) == 0) return pivot_item(lst, stack_index);
	return _fr_lst_peek(lst, stack_index);
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
static inline CC_HINT(nonnull) void _fr_lst_extract(fr_lst_t *lst,  stack_index_t stack_index, void *data)
{
	int8_t	cmp;

	if (is_bucket(lst, stack_index)) {
		bucket_delete(lst, stack_index, data);
		return;
	}
	stack_index++;
	cmp = lst->cmp(data, pivot_item(lst, stack_index));
	if (cmp < 0) {
		_fr_lst_extract(lst, stack_index, data);
	} else if (cmp > 0) {
		bucket_delete(lst, stack_index - 1, data);
	} else {
		lst_flatten(lst, stack_index);
		bucket_delete(lst, stack_index, data);
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
static inline CC_HINT(nonnull) void _fr_lst_insert(fr_lst_t *lst, stack_index_t stack_index, void *data)
{
#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (lst->type) (void)_talloc_get_type_abort(data, lst->type, __location__);
#endif

	if (is_bucket(lst, stack_index)) {
		bucket_add(lst, stack_index, data);
		return;
	}
	stack_index++;
	if (fr_fast_rand(&lst->rand_ctx) % (lst_size(lst, stack_index) + 1) != 0) {
		if (lst->cmp(data, pivot_item(lst, stack_index)) < 0) {
			_fr_lst_insert(lst, stack_index, data);
		} else {
			bucket_add(lst, stack_index - 1, data);
		}
	} else {
		lst_flatten(lst, stack_index);
		bucket_add(lst, stack_index, data);
	}
}

/*
 * We represent a (sub)tree with an (lst, stack index) pair, so
 * fr_lst_pop(), fr_lst_peek(), and fr_lst_extract() are minimal
 * wrappers that
 *
 * (1) hide our representation from the user and preserve the interface
 * (2) check preconditions
 */

void *fr_lst_pop(fr_lst_t *lst)
{
	if (unlikely(lst->num_elements == 0)) return NULL;
	return _fr_lst_pop(lst, 0);
}

void *fr_lst_peek(fr_lst_t *lst)
{
	if (unlikely(lst->num_elements == 0)) return NULL;
	return _fr_lst_peek(lst, 0);
}

/** Remove an element from an LST
 *
 * @param[in] lst		the LST to remove an element from
 * @param[in] data		the element to remove
 * @return
 *	- 0 if removal succeeds
 * 	- -1 if removal fails
 */
int fr_lst_extract(fr_lst_t *lst, void *data)
{
	if (unlikely(lst->num_elements == 0)) {
		fr_strerror_const("Tried to extract element from empty LST");
		return -1;
	}

	if (unlikely(raw_item_index(lst, data) == 0)) {
		fr_strerror_const("Tried to extract element not in LST");
		return -1;
	}

	_fr_lst_extract(lst, 0, data);
	return 0;
}

int fr_lst_insert(fr_lst_t *lst, void *data)
{
	/*
	 * Expand if need be. Not in the paper, but we want the capability.
	 */
	if (unlikely((lst->num_elements == lst->capacity) && !lst_expand(lst))) return -1;

	/*
	 * Don't insert something that looks like it's already in an LST.
	 */
	if (unlikely(raw_item_index(lst, data) > 0)) {
		fr_strerror_const("Node is already in the LST");
		return -1;
	}

	_fr_lst_insert(lst, 0, data);
	return 0;
}

unsigned int fr_lst_num_elements(fr_lst_t *lst)
{
	return lst->num_elements;
}

/** Iterate over entries in LST
 *
 * @note If the LST is modified, the iterator should be considered invalidated.
 *
 * @param[in] lst	to iterate over.
 * @param[in] iter	Pointer to an iterator struct, used to maintain
 *			state between calls.
 * @return
 *	- User data.
 *	- NULL if at the end of the list.
 */
void *fr_lst_iter_init(fr_lst_t *lst, fr_lst_iter_t *iter)
{
	if (unlikely(lst->num_elements == 0)) return NULL;

	*iter = lst->idx;
	return item(lst, *iter);
}

/** Get the next entry in an LST
 *
 * @note If the LST is modified, the iterator should be considered invalidated.
 *
 * @param[in] lst	to iterate over.
 * @param[in] iter	Pointer to an iterator struct, used to maintain
 *			state between calls.
 * @return
 *	- User data.
 *	- NULL if at the end of the list.
 */
void *fr_lst_iter_next(fr_lst_t *lst, fr_lst_iter_t *iter)
{
	if ((*iter + 1) >= stack_item(&lst->s, 0)) return NULL;
	*iter += 1;

	return item(lst, *iter);
}

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
void fr_lst_verify(char const *file, int line, fr_lst_t const *lst)
{
	fr_lst_index_t	fake_pivot_index, reduced_fake_pivot_index, reduced_end;
	stack_index_t	depth = stack_depth(&(lst->s));
	int		bucket_size_sum;
	bool		pivots_in_order = true;
	bool		pivot_indices_in_order = true;

	fr_fatal_assert_msg(lst, "CONSISTENCY CHECK FAILED %s[%i]: LST pointer NULL", file, line);
	talloc_get_type_abort(lst, fr_lst_t);

	/*
	 *	There must be at least the fictitious pivot.
	 */
	fr_fatal_assert_msg(depth >= 1, "CONSISTENCY CHECK FAILED %s[%i]: LST pivot stack empty", file, line);

	/*
	 *	Modulo circularity, idx + the number of elements should be the index
	 *	of the fictitious pivot.
	 */
	fake_pivot_index = stack_item(&(lst->s), 0);
	reduced_fake_pivot_index = index_reduce(lst, fake_pivot_index);
	reduced_end = index_reduce(lst, lst->idx + lst->num_elements);
	fr_fatal_assert_msg(reduced_fake_pivot_index == reduced_end,
			    "CONSISTENCY CHECK FAILED %s[%i]: fictitious pivot doesn't point past last element",
			    file, line);

	/*
	 *	Bucket sizes must make sense.
	 */
	if (lst->num_elements) {
		bucket_size_sum = 0;

		for (stack_index_t stack_index = 0; stack_index < depth; stack_index++)  {
			fr_lst_index_t bucket_size = bucket_upb(lst, stack_index) - bucket_lwb(lst, stack_index) + 1;
			fr_fatal_assert_msg(bucket_size <= lst->num_elements,
					    "CONSISTENCY CHECK FAILED %s[%i]: bucket %u size %u is invalid",
					    file, line, stack_index, bucket_size);
			bucket_size_sum += bucket_size;
		}

		fr_fatal_assert_msg(bucket_size_sum + depth - 1 == lst->num_elements,
				    "CONSISTENCY CHECK FAILED %s[%i]: buckets inconsistent with number of elements",
				    file, line);
	}

	/*
	 *	No elements should be NULL;
	 *	they should have the correct index stored,
	 *	and if a type is specified, they should point at something of that type,
	 */
	for (fr_lst_index_t i = 0; i < lst->num_elements; i++) {
		void	*element = item(lst, lst->idx + i);

		fr_fatal_assert_msg(element, "CONSISTENCY CHECK FAILED %s[%i]: null element pointer at %u",
				    file, line, lst->idx + i);
		fr_fatal_assert_msg(is_equivalent(lst, lst->idx + i, item_index(lst, element)),
				    "CONSISTENCY CHECK FAILED %s[%i]: element %u index mismatch", file, line, i);
		if (lst->type)  (void) _talloc_get_type_abort(element, lst->type, __location__);
	}

	/*
	 * There's nothing more to check for a one-bucket tree.
	 */
	if (is_bucket(lst, 0)) return;

	/*
	 * Otherwise, first, pivots from left to right (aside from the fictitious
	 * one) should be in ascending order.
	 */
	for (stack_index_t stack_index = 1; stack_index + 1 < depth; stack_index++) {
		void	*current_pivot = pivot_item(lst, stack_index);
		void	*next_pivot = pivot_item(lst, stack_index + 1);

		if (current_pivot && next_pivot && lst->cmp(current_pivot, next_pivot) < 0) pivots_in_order = false;
	}
	fr_fatal_assert_msg(pivots_in_order, "CONSISTENCY CHECK FAILED %s[%i]: pivots not in ascending order",
			    file, line);

	/*
	 * Next, the stacked pivot indices should decrease as you ascend from
	 * the bottom of the pivot stack. Here we *do* include the fictitious
	 * pivot; we're just comparing indices.
	 */
	for (stack_index_t stack_index = 0; stack_index + 1 < depth; stack_index++) {
		fr_lst_index_t current_pivot_index = stack_item(&(lst->s), stack_index);
		fr_lst_index_t previous_pivot_index = stack_item(&(lst->s), stack_index + 1);

		if (previous_pivot_index >= current_pivot_index) pivot_indices_in_order = false;
	}
	fr_fatal_assert_msg(pivot_indices_in_order, "CONSISTENCY CHECK FAILED %s[%i]: pivots indices not in order",
			    file, line);

	/*
	 * Finally...
	 * values in buckets shouldn't "follow" the pivot to the immediate right (if it exists)
	 * and shouldn't "precede" the pivot to the immediate left (if it exists)
	 */
	for (stack_index_t stack_index = 0; stack_index < depth; stack_index++) {
		fr_lst_index_t	lwb, upb, pivot_index;
		void		*pivot_item, *element;

		if (stack_index > 0) {
			lwb = (stack_index + 1 == depth) ? lst->idx : stack_item(&(lst->s), stack_index + 1);
			pivot_index = upb = stack_item(&(lst->s), stack_index);
			pivot_item = item(lst, pivot_index);
			for (fr_lst_index_t index = lwb; index < upb; index++) {
				element = item(lst, index);
				fr_fatal_assert_msg(!element || !pivot_item || lst->cmp(element, pivot_item) <= 0,
						    "CONSISTENCY CHECK FAILED %s[%i]: element at %u > pivot at %u",
						    file, line, index, pivot_index);
			}
		}
		if (stack_index + 1 < depth) {
			upb = stack_item(&(lst->s), stack_index);
			lwb = pivot_index = stack_item(&(lst->s), stack_index + 1);
			pivot_item = item(lst, pivot_index);
			for (fr_lst_index_t index = lwb; index < upb; index++) {
				element = item(lst, index);
				fr_fatal_assert_msg(!element || !pivot_item || lst->cmp(pivot_item, element) <= 0,
						    "CONSISTENCY CHECK FAILED %s[%i]: element at %u < pivot at %u",
						    file, line, index, pivot_index);
			}
		}
	}
}
#endif
