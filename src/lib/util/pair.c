/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** AVP manipulation and search API
 *
 * @file src/lib/util/pair.c
 *
 * @copyright 2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2000,2006,2015,2020 The FreeRADIUS server project
 */
RCSID("$Id$")

#define _PAIR_PRIVATE 1

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/regex.h>

FR_TLIST_FUNCS(fr_pair_order_list, fr_pair_t, order_entry)

/** Initialise a pair list header
 *
 * @param[in,out] list to initialise
 */
void fr_pair_list_init(fr_pair_list_t *list)
{
	/*
	 *	Initialises the order list.  This
	 *	maintains the overall order of attributes
	 *	in the list and allows us to iterate over
	 *	all of them.
	 */
	fr_pair_order_list_talloc_init(&list->order);

	list->is_child = false;
}

/** Free a fr_pair_t
 *
 * @note Do not call directly, use talloc_free instead.
 *
 * @param vp to free.
 * @return 0
 */
static int _fr_pair_free(fr_pair_t *vp)
{
#ifdef TALLOC_DEBUG
	talloc_report_depth_cb(NULL, 0, -1, fr_talloc_verify_cb, NULL);
#endif

#if 0
	/*
	 *	We would like to enforce that a VP must be removed from a list before it's freed.  However, we
	 *	free pair_lists via talloc_free().  And the talloc code just frees things in (essentially) a
	 *	random order.  So this guarantee can't be enforced.
	 */
	fr_assert(fr_pair_order_list_parent(vp) == NULL);
#endif

	/*
	 *	Pairs with children have the children
	 *	freed explicitly.
	 */
	if (likely(vp->da != NULL)) switch (vp->da->type) {
	case FR_TYPE_STRUCTURAL:
		fr_pair_list_free(&vp->vp_group);
		break;

	default:
		break;
	}

#ifndef NDEBUG
	memset(vp, 0, sizeof(*vp));
#endif

	return 0;
}

/** Allocate a new pair list on the heap
 *
 * @param[in] ctx	to allocate the pair list in.
 * @return
 *	- A new #fr_pair_list_t.
 *	- NULL if an error occurred.
 */
fr_pair_list_t *fr_pair_list_alloc(TALLOC_CTX *ctx)
{
	fr_pair_list_t *pl;

	pl = talloc(ctx, fr_pair_list_t);
	if (unlikely(!pl)) return NULL;

	fr_pair_list_init(pl);

	return pl;
}

/** Initialise fields in an fr_pair_t without assigning a da
 *
 * @note Internal use by the allocation functions only.
 */
static inline CC_HINT(always_inline) void pair_init_null(fr_pair_t *vp)
{
	fr_pair_order_list_entry_init(vp);

	/*
	 *	Legacy cruft
	 */
	vp->op = T_OP_EQ;
}

/** Initialise fields in an fr_pair_t without assigning a da
 *
 *  Used only for temporary value-pairs which are not placed in any list.
 */
void fr_pair_init_null(fr_pair_t *vp)
{
	memset(vp, 0, sizeof(*vp));

	pair_init_null(vp);
}

/** Dynamically allocate a new attribute with no #fr_dict_attr_t assigned
 *
 * This is not the function you're looking for (unless you're binding
 * unknown attributes to pairs, and need to pre-allocate the memory).
 * You probably want #fr_pair_afrom_da instead.
 *
 * @note You must assign a #fr_dict_attr_t before freeing this #fr_pair_t.
 *
 * @param[in] ctx	to allocate the pair list in.
 * @return
 *	- A new #fr_pair_t.
 *	- NULL if an error occurred.
 */
fr_pair_t *fr_pair_alloc_null(TALLOC_CTX *ctx)
{
	fr_pair_t *vp;

	vp = talloc_zero(ctx, fr_pair_t);
	if (!vp) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}
	talloc_set_destructor(vp, _fr_pair_free);

	pair_init_null(vp);

	return vp;
}

/** Continue initialising an fr_pair_t assigning a da
 *
 * @note Internal use by the pair allocation functions only.
 */
static inline CC_HINT(always_inline) void pair_init_from_da(fr_pair_t *vp, fr_dict_attr_t const *da)
{
	/*
	 *	Use the 'da' to initialize more fields.
	 */
	vp->da = da;

	if (likely(fr_type_is_leaf(da->type))) {
		fr_value_box_init(&vp->data, da->type, da, false);
	} else {
		vp->type = da->type; /* overlaps with vp->vp_type, and everyone needs it! */
		fr_pair_list_init(&vp->vp_group);
		vp->vp_group.is_child = true;
		fr_pair_order_list_talloc_init_children(vp, &vp->vp_group.order);
	}
}

/** A special allocation function which disables child autofree
 *
 * This is intended to allocate root attributes for requests.
 * These roots are special in that they do not necessarily own
 * the child attributes and _MUST NOT_ free them when they
 * themselves are freed.  The children are allocated in special
 * ctxs which may be moved between session state entries and
 * requests, or may belong to a parent request.
 *
 * @param[in] ctx	to allocate the pair root in.
 * @param[in] da	The root attribute.
 * @return
 *	- A new root pair on success.
 *	- NULL on failure.
 * @hidecallergraph
 */
fr_pair_t *fr_pair_root_afrom_da(TALLOC_CTX *ctx, fr_dict_attr_t const *da)
{
	fr_pair_t *vp;

#ifndef NDEBUG
	if (da->type != FR_TYPE_GROUP) {
		fr_strerror_const("Root must be a group type");
		return NULL;
	}
#endif

	vp = talloc_zero(ctx, fr_pair_t);
	if (unlikely(!vp)) {
		fr_strerror_const("Out of memory");
		return NULL;
	}

	if (unlikely(da->flags.is_unknown)) {
		fr_strerror_const("Root attribute cannot be unknown");
		return NULL;
	}

	pair_init_from_da(vp, da);

	return vp;
}

/** Dynamically allocate a new attribute and assign a #fr_dict_attr_t
 *
 * @note Will duplicate any unknown attributes passed as the da.
 *
 * @param[in] ctx	for allocated memory, usually a pointer to a #fr_radius_packet_t
 * @param[in] da	Specifies the dictionary attribute to build the #fr_pair_t from.
 *			If unknown, will be duplicated, with the memory being bound to
 *      		the pair.
 * @return
 *	- A new #fr_pair_t.
 *	- NULL if an error occurred.
 * @hidecallergraph
 */
fr_pair_t *fr_pair_afrom_da(TALLOC_CTX *ctx, fr_dict_attr_t const *da)
{
	fr_pair_t *vp;

	vp = fr_pair_alloc_null(ctx);
	if (!vp) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}

	/*
	 *	If we get passed an unknown da, we need to ensure that
	 *	it's parented by "vp".
	 */
	if (da->flags.is_unknown) {
		fr_dict_attr_t const *unknown;

		unknown = fr_dict_unknown_afrom_da(vp, da);
		da = unknown;
	}

	pair_init_from_da(vp, da);

	return vp;
}

/** Allocate a pooled object that can hold a fr_pair_t any unknown attributes and value buffer
 *
 * @param[in] ctx		to allocate the pooled object in.
 * @param[in] da		If unknown, will be duplicated.
 * @param[in] value_len		The expected length of the buffer.  +1 will be added if this
 *				if a FR_TYPE_STRING attribute.
 */
fr_pair_t *fr_pair_afrom_da_with_pool(TALLOC_CTX *ctx, fr_dict_attr_t const *da, size_t value_len)
{
	fr_pair_t *vp;

	unsigned int headers = 1;

	/*
	 *	Dict attributes allocate extensions
	 *      contiguously, so we only need one
	 *	header even though there's a variable
	 *	length name buff.
	 */
	if (da->flags.is_unknown) {
		headers++;
		value_len += talloc_array_length(da);	/* accounts for all extensions */
	}

	switch (da->type) {
	case FR_TYPE_OCTETS:
		headers++;
		break;

	case FR_TYPE_STRING:
		headers++;
		value_len++;
		break;

	default:
		fr_strerror_printf("Pooled fr_pair_t can only be allocated for "
				   "'string' and 'octets' types not '%s'",
				   fr_type_to_str(da->type));
		return NULL;

	}

	vp = talloc_zero_pooled_object(ctx, fr_pair_t, headers, value_len);
	if (unlikely(!vp)) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}
	talloc_set_destructor(vp, _fr_pair_free);

	pair_init_null(vp);

	/*
	 *	If we get passed an unknown da, we need to ensure that
	 *	it's parented by "vp".
	 */
	if (da->flags.is_unknown) {
		fr_dict_attr_t const *unknown;

		unknown = fr_dict_unknown_afrom_da(vp, da);
		da = unknown;
	}

	pair_init_from_da(vp, da);

	return vp;
}

/** Re-initialise an attribute with a different da
 *
 * If the new da has a different type to the old da, we'll attempt to cast
 * the current value in place.
 */
int fr_pair_reinit_from_da(fr_pair_list_t *list, fr_pair_t *vp, fr_dict_attr_t const *da)
{
	fr_dict_attr_t const *to_free;

	/*
	 *	This only works for leaf nodes.
	 */
	if (!fr_type_is_leaf(da->type)) return -1;

	/*
	 *	vp may be created from fr_pair_alloc_null(), in which case it has no da.
	 */
	if (vp->da) {
		if (vp->da == da) return 0;

		if (!fr_type_is_leaf(vp->da->type)) return -1;

		if ((da->type != vp->da->type) && (fr_value_box_cast_in_place(vp, &vp->data, da->type, da) < 0)) return -1;
	} else {
		fr_value_box_init(&vp->data, da->type, da, false);
	}

	to_free = vp->da;

	/*
	 *	Ensure we update the attribute index in the parent.
	 */
	if (list) {
		fr_pair_remove(list, vp);

		vp->da = da;

		fr_pair_append(list, vp);
	} else {
		vp->da = da;
	}

	/*
	 *	Only frees unknown fr_dict_attr_t's
	 */
	fr_dict_unknown_free(&to_free);

	return 0;
}

/** Create a new valuepair
 *
 * If attr and vendor match a dictionary entry then a VP with that #fr_dict_attr_t
 * will be returned.
 *
 * If attr or vendor are uknown will call dict_attruknown to create a dynamic
 * #fr_dict_attr_t of #FR_TYPE_OCTETS.
 *
 * Which type of #fr_dict_attr_t the #fr_pair_t was created with can be determined by
 * checking @verbatim vp->da->flags.is_unknown @endverbatim.
 *
 * @param[in] ctx	for allocated memory, usually a pointer to a #fr_radius_packet_t.
 * @param[in] parent	of the attribute being allocated (usually a dictionary or vendor).
 * @param[in] attr	number.
 * @return
 *	- A new #fr_pair_t.
 *	- NULL on error.
 */
fr_pair_t *fr_pair_afrom_child_num(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, unsigned int attr)
{
	fr_dict_attr_t const	*da;
	fr_pair_t 		*vp;

	vp = fr_pair_alloc_null(ctx);
	if (unlikely(!vp)) return NULL;

	da = fr_dict_attr_child_by_num(parent, attr);
	if (!da) {
		fr_dict_attr_t *unknown;

		unknown = fr_dict_unknown_attr_afrom_num(vp, parent, attr);
		if (!unknown) {
			talloc_free(vp);
			return NULL;
		}
		da = unknown;
	}

	pair_init_from_da(vp, da);

	return vp;
}

/** Copy a single valuepair
 *
 * Allocate a new valuepair and copy the da from the old vp.
 *
 * @param[in] ctx for talloc
 * @param[in] vp to copy.
 * @return
 *	- A copy of the input VP.
 *	- NULL on error.
 */
fr_pair_t *fr_pair_copy(TALLOC_CTX *ctx, fr_pair_t const *vp)
{
	fr_pair_t *n;

	PAIR_VERIFY(vp);

	n = fr_pair_afrom_da(ctx, vp->da);
	if (!n) return NULL;

	n->op = vp->op;
	/*
	 *	Copy the unknown attribute hierarchy
	 */
	if (n->da->flags.is_unknown) {
		n->da = fr_dict_unknown_afrom_da(n, n->da);
		if (!n->da) {
			talloc_free(n);
			return NULL;
		}
	}


	/*
	 *	Groups are special.
	 */
	switch (n->da->type) {
	case FR_TYPE_STRUCTURAL:
		if (fr_pair_list_copy(n, &n->vp_group, &vp->vp_group) < 0) {
			talloc_free(n);
			return NULL;
		}
		return n;

	default:
		break;
	}
	fr_value_box_copy(n, &n->data, &vp->data);

	return n;
}

/** Steal one VP
 *
 * @param[in] ctx to move fr_pair_t into
 * @param[in] vp fr_pair_t to move into the new context.
 */
int fr_pair_steal(TALLOC_CTX *ctx, fr_pair_t *vp)
{
	fr_pair_t *nvp;

	nvp = talloc_steal(ctx, vp);
	if (unlikely(!nvp)) {
		fr_strerror_printf("Failed moving pair %pV to new ctx", vp);
		return -1;
	}

	return 0;
}

#define IN_A_LIST_MSG "Pair %pV is already in a list, and cannot be moved"
#define NOT_IN_THIS_LIST_MSG "Pair %pV is not in the given list"

/** Change a vp's talloc ctx and insert it into a new list
 *
 * @param[in] list_ctx	to move vp into.
 * @param[out] list	to add vp to.
 * @param[in] vp	to move.
 * @return
 *	- 0 on success.
 *      - -1 on failure (already in list).
 */
int fr_pair_steal_append(TALLOC_CTX *list_ctx, fr_pair_list_t *list, fr_pair_t *vp)
{
	if (fr_pair_order_list_in_a_list(vp)) {
		fr_strerror_printf(IN_A_LIST_MSG, vp);
		return -1;
	}

	if (unlikely(fr_pair_steal(list_ctx, vp) < 0)) return -1;

	if (unlikely(fr_pair_append(list, vp) < 0)) return -1;

	return 0;
}

/** Change a vp's talloc ctx and insert it into a new list
 *
 * @param[in] list_ctx	to move vp into.
 * @param[out] list	to add vp to.
 * @param[in] vp	to move.
 * @return
 *	- 0 on success.
 *      - -1 on failure (already in list).
 */
int fr_pair_steal_prepend(TALLOC_CTX *list_ctx, fr_pair_list_t *list, fr_pair_t *vp)
{
	if (fr_pair_order_list_in_a_list(vp)) {
		fr_strerror_printf(IN_A_LIST_MSG, vp);
		return -1;
	}

	if (unlikely(fr_pair_steal(list_ctx, vp) < 0)) return -1;

	if (unlikely(fr_pair_prepend(list, vp) < 0)) return -1;

	return 0;
}

/** Free memory used by a valuepair list.
 *
 * @todo TLV: needs to free all dependents of each VP freed.
 *
 * @hidecallergraph
 */
void fr_pair_list_free(fr_pair_list_t *list)
{
	fr_pair_order_list_talloc_free(&list->order);
}

/** Is a valuepair list empty
 *
 * @param[in] list to check
 * @return true if empty
 *
 * @hidecallergraph
 */
bool fr_pair_list_empty(fr_pair_list_t const *list)
{
	return fr_pair_order_list_empty(&list->order);
}

/** Mark malformed or unrecognised attributed as unknown
 *
 * @param vp to change fr_dict_attr_t of.
 * @return
 *	- 0 on success (or if already unknown).
 *	- -1 on failure.
 */
int fr_pair_to_unknown(fr_pair_t *vp)
{
	fr_dict_attr_t *unknown;

	PAIR_VERIFY(vp);

	if (vp->da->flags.is_unknown) return 0;

	if (!fr_cond_assert(vp->da->parent != NULL)) return -1;

	unknown = fr_dict_unknown_afrom_da(vp, vp->da);
	if (!unknown) return -1;
	unknown->flags.is_raw = 1;

	fr_dict_unknown_free(&vp->da);	/* Only frees unknown attributes */
	vp->da = unknown;

	return 0;
}

/** Iterate over pairs with a specified da
 *
 * @param[in] list	to iterate over.
 * @param[in] to_eval	The fr_pair_t after cursor->current.  Will be checked to
 *			see if it matches the specified fr_dict_attr_t.
 * @param[in] uctx	The fr_dict_attr_t to search for.
 * @return
 *	- Next matching fr_pair_t.
 *	- NULL if not more matching fr_pair_ts could be found.
 */
static void *fr_pair_iter_next_by_da(fr_dlist_head_t *list, void *to_eval, void *uctx)
{
	fr_pair_t	*c;
	fr_dict_attr_t	*da = uctx;

	for (c = to_eval; c; c = fr_dlist_next(list, c)) {
		PAIR_VERIFY(c);
		if (c->da == da) break;
	}

	return c;
}

/** Iterate over pairs which are decedents of the specified da
 *
 * @param[in] list	to itterate over.
 * @param[in] to_eval	The fr_pair_t after cursor->current.  Will be checked to
 *			see if it matches the specified fr_dict_attr_t.
 * @param[in] uctx	The fr_dict_attr_t to search for.
 * @return
 *	- Next matching fr_pair_t.
 *	- NULL if not more matching fr_pair_ts could be found.
 */
static void *fr_pair_iter_next_by_ancestor(fr_dlist_head_t *list, void *to_eval, void *uctx)
{
	fr_pair_t	*c;
	fr_dict_attr_t	*da = uctx;

	for (c = to_eval; c; c = fr_dlist_next(list, c)) {
		PAIR_VERIFY(c);
		if (fr_dict_attr_common_parent(da, c->da, true)) break;
	}

	return c;
}

/** Return the number of instances of a given da in the specified list
 *
 * @param[in] list	to search in.
 * @param[in] da	to look for in the list.
 * @return
 *	- 0 if no instances exist.
 *	- >0 the number of instance of a given attribute.
 */
unsigned int fr_pair_count_by_da(fr_pair_list_t const *list, fr_dict_attr_t const *da)
{
	fr_pair_t	*vp = NULL;
	unsigned int	count = 0;

	if (fr_pair_order_list_empty(&list->order)) return 0;

	while ((vp = fr_pair_order_list_next(&list->order, vp))) if (da == vp->da) count++;

	return count;
}

/** Find a pair with a matching da at a given index
 *
 * @param[in] list	to search in.
 * @param[in] prev	the previous attribute in the list.
 * @param[in] da	the next da to find.
 * @return
 *	- first matching fr_pair_t.
 *	- NULL if no fr_pair_ts match.
 *
 * @hidecallergraph
 */
fr_pair_t *fr_pair_find_by_da(fr_pair_list_t const *list, fr_pair_t const *prev, fr_dict_attr_t const *da)
{
	fr_pair_t *vp = UNCONST(fr_pair_t *, prev);

	if (fr_pair_order_list_empty(&list->order)) return NULL;

	PAIR_LIST_VERIFY(list);

	while ((vp = fr_pair_order_list_next(&list->order, vp))) if (da == vp->da) return vp;

	return NULL;
}

/** Find a pair with a matching da at a given index
 *
 * @param[in] list	to search in.
 * @param[in] da	to look for in the list.
 * @param[in] idx	Instance of the attribute to return.
 * @return
 *	- first matching fr_pair_t.
 *	- NULL if no fr_pair_ts match.
 *
 * @hidecallergraph
 */
fr_pair_t *fr_pair_find_by_da_idx(fr_pair_list_t const *list, fr_dict_attr_t const *da, unsigned int idx)
{
	fr_pair_t *vp = NULL;

	if (fr_pair_order_list_empty(&list->order)) return NULL;

	PAIR_LIST_VERIFY(list);

	while ((vp = fr_pair_list_next(list, vp))) {
		if (da != vp->da) continue;

		if (idx == 0) return vp;

		idx--;
	}
	return NULL;
}

/** Find a pair which has the specified ancestor
 *
 * @param[in] list	to search in.
 * @param[in] prev	attribute to start search from.
 * @param[in] ancestor	to look for in the list.
 * @return
 *	- first matching fr_pair_t.
 *	- NULL if no fr_pair_ts match.
 *
 * @hidecallergraph
 */
fr_pair_t *fr_pair_find_by_ancestor(fr_pair_list_t const *list, fr_pair_t const *prev,
				    fr_dict_attr_t const *ancestor)
{
	fr_pair_t *vp = UNCONST(fr_pair_t *, prev);

	while ((vp = fr_pair_list_next(list, vp))) {
		if (!fr_dict_attr_common_parent(ancestor, vp->da, true)) continue;

		return vp;
	}

	return NULL;
}

/** Find a pair which has the specified ancestor at a given index
 *
 * @param[in] list	to search in.
 * @param[in] ancestor	to look for in the list.
 * @param[in] idx	Instance of the attribute to return.
 * @return
 *	- first matching fr_pair_t.
 *	- NULL if no fr_pair_ts match.
 *
 * @hidecallergraph
 */
fr_pair_t *fr_pair_find_by_ancestor_idx(fr_pair_list_t const *list,
					fr_dict_attr_t const *ancestor, unsigned int idx)
{
	fr_pair_t *vp = NULL;

	while ((vp = fr_pair_list_next(list, vp))) {
		if (!fr_dict_attr_common_parent(ancestor, vp->da, true)) continue;

		if (idx == 0) return vp;
		idx--;
	}

	return NULL;
}

/** Find the pair with the matching child attribute
 *
 * @param[in] list	in which to search.
 * @param[in] prev	attribute to start search from.
 * @param[in] parent	attribute in which to lookup child.
 * @param[in] attr	id of child.
 * @return
 *	- first matching value pair.
 *	- NULL if no pair found.
 */
fr_pair_t *fr_pair_find_by_child_num(fr_pair_list_t const *list, fr_pair_t const *prev,
				     fr_dict_attr_t const *parent, unsigned int attr)
{
	fr_dict_attr_t const	*da;

	/* List head may be NULL if it contains no VPs */
	if (fr_pair_order_list_empty(&list->order)) return NULL;

	PAIR_LIST_VERIFY(list);

	da = fr_dict_attr_child_by_num(parent, attr);
	if (!da) return NULL;

	return fr_pair_find_by_da(list, prev, da);
}

/** Find the pair with the matching child attribute at a given index
 *
 * @param[in] list	in which to search.
 * @param[in] parent	attribute in which to lookup child.
 * @param[in] attr	id of child.
 * @param[in] idx	Instance of the attribute to return.
 * @return
 *	- first matching value pair.
 *	- NULL if no pair found.
 */
fr_pair_t *fr_pair_find_by_child_num_idx(fr_pair_list_t const *list,
					 fr_dict_attr_t const *parent, unsigned int attr, unsigned int idx)
{
	fr_dict_attr_t const	*da;

	/* List head may be NULL if it contains no VPs */
	if (fr_pair_order_list_empty(&list->order)) return NULL;

	PAIR_LIST_VERIFY(list);

	da = fr_dict_attr_child_by_num(parent, attr);
	if (!da) return NULL;

	return fr_pair_find_by_da_idx(list, da, idx);
}

/** Get the child list of a group
 *
 * @param[in] vp	which MUST be of a type
 *			that can contain children.
 * @return
 *	- NULL on error
 *	- pointer to head of the child list.
 */
fr_pair_list_t *fr_pair_children(fr_pair_t *vp)
{
	if (!fr_type_is_structural(vp->da->type)) return NULL;

	return &vp->vp_group;
}

/** Return a pointer to the parent pair list
 *
 */
fr_pair_list_t *fr_pair_parent_list(fr_pair_t const *vp)
{
	FR_TLIST_HEAD(fr_pair_order_list) *parent;

	if (!vp) return NULL;

	parent = fr_pair_order_list_parent(vp);
	if (!parent) return NULL;

	return (fr_pair_list_t *) (UNCONST(uint8_t *, parent) - offsetof(fr_pair_list_t, order));
}

/** Return a pointer to the parent pair.
 *
 */
fr_pair_t *fr_pair_parent(fr_pair_t const *vp)
{
	fr_pair_list_t *list = fr_pair_parent_list(vp);

	if (!list) return NULL;

	if (!list->is_child) return NULL;

	return (fr_pair_t *) (UNCONST(uint8_t *, list) - offsetof(fr_pair_t, vp_group));
}

/** Keep attr tree and sublists synced on cursor insert
 *
 * @param[in] list	Underlying order list from the fr_pair_list_t.
 * @param[in] to_insert	fr_pair_t being inserted.
 * @param[in] uctx	fr_pair_list_t containing the order list.
 * @return
 *	- 0 on success.
 */
static int _pair_list_dcursor_insert(fr_dlist_head_t *list, void *to_insert, UNUSED void *uctx)
{
	fr_pair_t *vp = to_insert;
	fr_tlist_head_t *tlist;

	tlist = fr_tlist_head_from_dlist(list);

	/*
	 *	Mark the pair as inserted into the list.
	 */
	fr_pair_order_list_set_head(tlist, vp);

	PAIR_VERIFY(vp);

	return 0;
}

/** Keep attr tree and sublists synced on cursor insert
 *
 * @param[in] list	Underlying order list from the fr_pair_list_t.
 * @param[in] to_remove	fr_pair_t being removed.
 * @param[in] uctx	fr_pair_list_t containing the order list.
 * @return
 *	- 0 on success.
 */
static int _pair_list_dcursor_remove(NDEBUG_UNUSED fr_dlist_head_t *list, void *to_remove, UNUSED void *uctx)
{
	fr_pair_t *vp = to_remove;

#ifndef NDEBUG
	fr_tlist_head_t *tlist;

	tlist = fr_tlist_head_from_dlist(list);

	fr_assert(vp->order_entry.entry.list_head == tlist);
#endif

	/*
	 *	Mark the pair as removed from the list.
	 */
	fr_pair_order_list_set_head(NULL, vp);

	PAIR_VERIFY(vp);

	return 0;
}

/** Initialises a special dcursor with callbacks that will maintain the attr sublists correctly
 *
 * Filters can be applied later with fr_dcursor_filter_set.
 *
 * @note This is the only way to use a dcursor in non-const mode with fr_pair_list_t.
 *
 * @param[out] cursor	to initialise.
 * @param[in] list	to iterate over.
 * @param[in] iter	Iterator to use when filtering pairs.
 * @param[in] uctx	To pass to iterator.
 * @param[in] is_const	whether the fr_pair_list_t is const.
 * @return
 *	- NULL if src does not point to any items.
 *	- The first pair in the list.
 */
fr_pair_t *_fr_pair_dcursor_iter_init(fr_dcursor_t *cursor, fr_pair_list_t const *list,
				      fr_dcursor_iter_t iter, void const *uctx,
				      bool is_const)
{
	return _fr_dcursor_init(cursor, fr_pair_order_list_dlist_head(&list->order),
				iter, NULL, uctx,
				_pair_list_dcursor_insert, _pair_list_dcursor_remove, list, is_const);
}

/** Initialises a special dcursor with callbacks that will maintain the attr sublists correctly
 *
 * Filters can be applied later with fr_dcursor_filter_set.
 *
 * @note This is the only way to use a dcursor in non-const mode with fr_pair_list_t.
 *
 * @param[out] cursor	to initialise.
 * @param[in] list	to iterate over.
 * @param[in] is_const	whether the fr_pair_list_t is const.
 * @return
 *	- NULL if src does not point to any items.
 *	- The first pair in the list.
 */
fr_pair_t *_fr_pair_dcursor_init(fr_dcursor_t *cursor, fr_pair_list_t const *list,
				 bool is_const)
{
	return _fr_dcursor_init(cursor, fr_pair_order_list_dlist_head(&list->order),
				NULL, NULL, NULL,
				_pair_list_dcursor_insert, _pair_list_dcursor_remove, list, is_const);
}


/** Initialise a cursor that will return only attributes matching the specified #fr_dict_attr_t
 *
 * @param[in] cursor	to initialise.
 * @param[in] list	to iterate over.
 * @param[in] da	to search for.
 * @param[in] is_const	whether the fr_pair_list_t is const.
 * @return
 *	- The first matching pair.
 *	- NULL if no pairs match.
 */
fr_pair_t *_fr_pair_dcursor_by_da_init(fr_dcursor_t *cursor,
				        fr_pair_list_t const *list, fr_dict_attr_t const *da,
				        bool is_const)
{
	return _fr_dcursor_init(cursor, fr_pair_order_list_dlist_head(&list->order),
				fr_pair_iter_next_by_da, NULL, da,
				_pair_list_dcursor_insert, _pair_list_dcursor_remove, list, is_const);
}

/** Initialise a cursor that will return only attributes descended from the specified #fr_dict_attr_t
 *
 * @param[in] cursor	to initialise.
 * @param[in] list	to iterate over.
 * @param[in] da	who's decentness to search for.
 * @param[in] is_const	whether the fr_pair_list_t is const.
 * @return
 *	- The first matching pair.
 *	- NULL if no pairs match.
 */
fr_pair_t *_fr_pair_dcursor_by_ancestor_init(fr_dcursor_t *cursor,
					     fr_pair_list_t const *list, fr_dict_attr_t const *da,
					     bool is_const)
{
	return _fr_dcursor_init(cursor, fr_pair_order_list_dlist_head(&list->order),
				fr_pair_iter_next_by_ancestor, NULL, da,
				_pair_list_dcursor_insert, _pair_list_dcursor_remove, list, is_const);
}

/** Get the head of a valuepair list
 *
 * @param[in] list	to return the head of
 *
 * @return
 *	- NULL if the list is empty
 *	- pointer to the first item in the list.
 * @hidecallergraph
 */
fr_pair_t *fr_pair_list_head(fr_pair_list_t const *list)
{
	return fr_pair_order_list_head(&list->order);
}

/** Get the next item in a valuepair list after a specific entry
 *
 * @param[in] list	to walk
 * @param[in] item	whose "next" item to return
 * @return
 *	- NULL if the end of the list has been reached
 *	- pointer to the next item
 * @hidecallergraph
 */
fr_pair_t *fr_pair_list_next(fr_pair_list_t const *list, fr_pair_t const *item)
{
	return fr_pair_order_list_next(&list->order, item);
}

/** Get the previous item in a valuepair list before a specific entry
 *
 * @param[in] list	to walk
 * @param[in] item	whose "prev" item to return
 * @return
 *	- NULL if the head of the list has been reached
 *	- pointer to the previous item
 */
fr_pair_t *fr_pair_list_prev(fr_pair_list_t const *list, fr_pair_t const *item)
{
	return fr_pair_order_list_prev(&list->order, item);
}

/** Get the tail of a valuepair list
 *
 * @param[in] list	to return the tail of
 *
 * @return
 *	- NULL if the list is empty
 *	- pointer to the last item in the list.
 */
fr_pair_t *fr_pair_list_tail(fr_pair_list_t const *list)
{
	return fr_pair_order_list_tail(&list->order);
}

/** Add a VP to the start of the list.
 *
 * Links an additional VP 'add' at the beginning a list.
 *
 * @param[in] list	VP in linked list. Will add new VP to this list.
 * @param[in] to_add	VP to add to list.
 * @return
 *	- 0 on success.
 *	- -1 on failure (pair already in list).
 */
int fr_pair_prepend(fr_pair_list_t *list, fr_pair_t *to_add)
{
	PAIR_VERIFY(to_add);

	if (fr_pair_order_list_in_a_list(to_add)) {
		fr_strerror_printf(IN_A_LIST_MSG, to_add);
		return -1;
	}

	fr_pair_order_list_insert_head(&list->order, to_add);

	return 0;
}

/** Add a VP to the end of the list.
 *
 * Links an additional VP 'to_add' at the end of a list.
 *
 * @param[in] list	VP in linked list. Will add new VP to this list.
 * @param[in] to_add	VP to add to list.
 * @return
 *	- 0 on success.
 *	- -1 on failure (pair already in list).
 */
int fr_pair_append(fr_pair_list_t *list, fr_pair_t *to_add)
{
	PAIR_VERIFY(to_add);

	if (fr_pair_order_list_in_a_list(to_add)) {
		fr_strerror_printf(IN_A_LIST_MSG, to_add);
		return -1;
	}

	fr_pair_order_list_insert_tail(&list->order, to_add);

	return 0;
}

/** Add a VP after another VP.
 *
 * @param[in] list	VP in linked list. Will add new VP to this list.
 * @param[in] pos	to insert pair after.
 * @param[in] to_add	VP to add to list.
 * @return
 *	- 0 on success.
 *	- -1 on failure (pair already in list).
 */
int fr_pair_insert_after(fr_pair_list_t *list, fr_pair_t *pos, fr_pair_t *to_add)
{
	PAIR_VERIFY(to_add);

	if (fr_pair_order_list_in_a_list(to_add)) {
		fr_strerror_printf(IN_A_LIST_MSG, to_add);
		return -1;
	}

	if (pos && !fr_pair_order_list_in_list(&list->order, pos)) {
		fr_strerror_printf(NOT_IN_THIS_LIST_MSG, pos);
		return -1;
	}

	fr_pair_order_list_insert_after(&list->order, pos, to_add);

	return 0;
}

/** Add a VP before another VP.
 *
 * @param[in] list	VP in linked list. Will add new VP to this list.
 * @param[in] pos	to insert pair after.
 * @param[in] to_add	VP to add to list.
 * @return
 *	- 0 on success.
 *	- -1 on failure (pair already in list).
 */
int fr_pair_insert_before(fr_pair_list_t *list, fr_pair_t *pos, fr_pair_t *to_add)
{
	PAIR_VERIFY(to_add);

	if (fr_pair_order_list_in_a_list(to_add)) {
		fr_strerror_printf(IN_A_LIST_MSG, to_add);
		return -1;
	}

	if (pos && !fr_pair_order_list_in_list(&list->order, pos)) {
		fr_strerror_printf(NOT_IN_THIS_LIST_MSG, pos);
		return -1;
	}

	fr_pair_order_list_insert_before(&list->order, pos, to_add);

	return 0;
}

/** Replace a given VP
 *
 * @note Memory used by the VP being replaced will be freed.
 *
 * @param[in,out] list		pair list containing #to_replace.
 * @param[in] to_replace	pair to replace and free
 * @param[in] vp		New pair to insert.
 */
void fr_pair_replace(fr_pair_list_t *list, fr_pair_t *to_replace, fr_pair_t *vp)
{
	PAIR_VERIFY_WITH_LIST(list, to_replace);
	PAIR_VERIFY(vp);

	fr_pair_insert_after(list, to_replace, vp);
	fr_pair_remove(list, to_replace);
	talloc_free(to_replace);
}

/** Alloc a new fr_pair_t (and append)
 *
 * @param[in] ctx	to allocate new #fr_pair_t in.
 * @param[out] out	Pair we allocated.  May be NULL if the caller doesn't
 *			care about manipulating the fr_pair_t.
 * @param[in,out] list	in search and insert into.
 * @param[in] da	of attribute to update.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_append_by_da(TALLOC_CTX *ctx, fr_pair_t **out, fr_pair_list_t *list, fr_dict_attr_t const *da)
{
	fr_pair_t	*vp;

	vp = fr_pair_afrom_da(ctx, da);
	if (unlikely(!vp)) {
		if (out) *out = NULL;
		return -1;
	}

	fr_pair_append(list, vp);
	if (out) *out = vp;

	return 0;
}

/** Alloc a new fr_pair_t (and prepend)
 *
 * @param[in] ctx	to allocate new #fr_pair_t in.
 * @param[out] out	Pair we allocated.  May be NULL if the caller doesn't
 *			care about manipulating the fr_pair_t.
 * @param[in,out] list	in search and insert into.
 * @param[in] da	of attribute to update.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_prepend_by_da(TALLOC_CTX *ctx, fr_pair_t **out, fr_pair_list_t *list, fr_dict_attr_t const *da)
{
	fr_pair_t	*vp;

	vp = fr_pair_afrom_da(ctx, da);
	if (unlikely(!vp)) {
		if (out) *out = NULL;
		return -1;
	}

	fr_pair_prepend(list, vp);
	if (out) *out = vp;

	return 0;
}

/** Return the first fr_pair_t matching the #fr_dict_attr_t or alloc a new fr_pair_t (and append)
 *
 * @param[in] ctx	to allocate any new #fr_pair_t in.
 * @param[out] out	Pair we allocated or found.  May be NULL if the caller doesn't
 *			care about manipulating the fr_pair_t.
 * @param[in,out] list	to search for attributes in or append attributes to.
 * @param[in] da	of attribute to locate or alloc.
 * @param[in] n		update the n'th instance of this da.
 *			Note: If we can't find the n'th instance the attribute created
 *			won't necessarily be at index n.  So use cases for this are
 *			limited .
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
int fr_pair_update_by_da(TALLOC_CTX *ctx, fr_pair_t **out, fr_pair_list_t *list,
			 fr_dict_attr_t const *da, unsigned int n)
{
	fr_pair_t	*vp;

	vp = fr_pair_find_by_da_idx(list, da, n);
	if (vp) {
		PAIR_VERIFY_WITH_LIST(list, vp);
		if (out) *out = vp;
		return 1;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (unlikely(!vp)) {
		if (out) *out = NULL;
		return -1;
	}

	fr_pair_append(list, vp);
	if (out) *out = vp;

	return 0;
}

/** Delete matching pairs from the specified list
 *
 * @param[in,out] list	to search for attributes in or delete attributes from.
 * @param[in] da	to match.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
int fr_pair_delete_by_da(fr_pair_list_t *list, fr_dict_attr_t const *da)
{
	fr_pair_t	*vp, *next;
	int		cnt = 0;

	for (vp = fr_pair_list_head(list); vp; vp = next) {
		next = fr_pair_list_next(list, vp);
		if (da == vp->da) {
			cnt++;
			fr_pair_delete(list, vp);
		}
	}

	return cnt;
}

/** Delete matching pairs from the specified list
 *
 * @param[in] list	to delete attributes from.
 * @param[in] parent	to match.
 * @param[in] attr	to match.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were delete.
 *	- -1 if we couldn't resolve the attribute number.
 */
int fr_pair_delete_by_child_num(fr_pair_list_t *list, fr_dict_attr_t const *parent, unsigned int attr)
{
	fr_dict_attr_t const	*da;

	da = fr_dict_attr_child_by_num(parent, attr);
	if (!da) return -1;

	return fr_pair_delete_by_da(list, da);
}

/** Remove fr_pair_t from a list without freeing
 *
 * @param[in] list	of value pairs to remove VP from.
 * @param[in] vp	to remove
 * @return previous item in the list to the one being removed.
 */
fr_pair_t *fr_pair_remove(fr_pair_list_t *list, fr_pair_t *vp)
{
	fr_pair_t *prev;

	prev = fr_pair_order_list_prev(&list->order, vp);
	fr_pair_order_list_remove(&list->order, vp);

	return prev;
}

/** Remove fr_pair_t from a list and free
 *
 * @param[in] list	of value pairs to remove VP from.
 * @param[in] vp	to remove
 * @return previous item in the list to the one being removed.
 */
fr_pair_t *fr_pair_delete(fr_pair_list_t *list, fr_pair_t *vp)
{
	fr_pair_t *prev;

	prev = fr_pair_order_list_prev(&list->order, vp);
	fr_pair_order_list_remove(&list->order, vp);
	talloc_free(vp);

	return prev;
}

/** Order attributes by their da, and tag
 *
 * Useful where attributes need to be aggregated, but not necessarily
 * ordered by attribute number.
 *
 * @param[in] a		first dict_attr_t.
 * @param[in] b		second dict_attr_t.
 * @return
 *	- +1 if a > b
 *	- 0 if a == b
 *	- -1 if a < b
 */
int8_t fr_pair_cmp_by_da(void const *a, void const *b)
{
	fr_pair_t const *my_a = a;
	fr_pair_t const *my_b = b;

	PAIR_VERIFY(my_a);
	PAIR_VERIFY(my_b);

	return CMP(my_a->da, my_b->da);
}

/** Order attributes by their attribute number, and tag
 *
 * @param[in] a		first dict_attr_t.
 * @param[in] b		second dict_attr_t.
 * @return
 *	- +1 if a > b
 *	- 0 if a == b
 *	- -1 if a < b
 */
static inline int8_t pair_cmp_by_num(void const *a, void const *b)
{
	fr_pair_t const *my_a = a;
	fr_pair_t const *my_b = b;

	PAIR_VERIFY(my_a);
	PAIR_VERIFY(my_b);

	return CMP(my_a->da->attr, my_b->da->attr);
}

/** Order attributes by their parent(s), attribute number, and tag
 *
 * Useful for some protocols where attributes of the same number should by aggregated
 * within a packet or container TLV.
 *
 * @param[in] a		first dict_attr_t.
 * @param[in] b		second dict_attr_t.
 * @return
 *	- +1 if a > b
 *	- 0 if a == b
 *	- -1 if a < b
 */
int8_t fr_pair_cmp_by_parent_num(void const *a, void const *b)
{
	fr_pair_t const	*vp_a = a;
	fr_pair_t const	*vp_b = b;
	fr_dict_attr_t const	*da_a = vp_a->da;
	fr_dict_attr_t const	*da_b = vp_b->da;
	fr_da_stack_t		da_stack_a;
	fr_da_stack_t		da_stack_b;
	int8_t			cmp;
	int i;

	/*
	 *	Fast path (assuming attributes
	 *	are in the same dictionary).
	 */
	if ((da_a->parent->flags.is_root) && (da_b->parent->flags.is_root)) return pair_cmp_by_num(vp_a, vp_b);

	fr_proto_da_stack_build(&da_stack_a, da_a);
	fr_proto_da_stack_build(&da_stack_b, da_b);

	for (i = 0; (da_a = da_stack_a.da[i]) && (da_b = da_stack_b.da[i]); i++) {
		cmp = CMP(da_a->attr, da_b->attr);
		if (cmp != 0) return cmp;
	}

	/*
	 *	If a has a shallower attribute
	 *	hierarchy than b, it should come
	 *	before b.
	 */
	return (da_a && !da_b) - (!da_a && da_b);
}

/** Compare two pairs, using the operator from "a"
 *
 *	i.e. given two attributes, it does:
 *
 *	(b->data) (a->operator) (a->data)
 *
 *	e.g. "foo" != "bar"
 *
 * @param[in] a the head attribute
 * @param[in] b the second attribute
 * @return
 *	- 1 if true.
 *	- 0 if false.
 *	- -1 on failure.
 */
int fr_pair_cmp(fr_pair_t const *a, fr_pair_t const *b)
{
	if (!a) return -1;

	PAIR_VERIFY(a);
	if (b) PAIR_VERIFY(b);

	switch (a->op) {
	case T_OP_CMP_TRUE:
		return (b != NULL);

	case T_OP_CMP_FALSE:
		return (b == NULL);

		/*
		 *	a is a regex, compile it, print b to a string,
		 *	and then do string comparisons.
		 */
	case T_OP_REG_EQ:
	case T_OP_REG_NE:
#ifndef HAVE_REGEX
		return -1;
#else
		if (!b) return false;

		{
			ssize_t	slen;
			regex_t	*preg;
			char	*value;

			if (!fr_cond_assert(a->vp_type == FR_TYPE_STRING)) return -1;

			slen = regex_compile(NULL, &preg, a->vp_strvalue, talloc_array_length(a->vp_strvalue) - 1,
					     NULL, false, true);
			if (slen <= 0) {
				fr_strerror_printf_push("Error at offset %zu compiling regex for %s", -slen,
							a->da->name);
				return -1;
			}
			fr_pair_aprint(NULL, &value, NULL, b);
			if (!value) {
				talloc_free(preg);
				return -1;
			}

			/*
			 *	Don't care about substring matches, oh well...
			 */
			slen = regex_exec(preg, value, talloc_array_length(value) - 1, NULL);
			talloc_free(preg);
			talloc_free(value);

			if (slen < 0) return -1;
			if (a->op == T_OP_REG_EQ) return (int)slen;
			return !slen;
		}
#endif

	default:		/* we're OK */
		if (!b) return false;
		break;
	}

	return fr_pair_cmp_op(a->op, b, a);
}

/** Determine equality of two lists
 *
 * This is useful for comparing lists of attributes inserted into a binary tree.
 *
 * @param a head list of #fr_pair_t.
 * @param b second list of #fr_pair_t.
 * @return
 *	- -1 if a < b.
 *	- 0 if the two lists are equal.
 *	- 1 if a > b.
 *	- -2 on error.
 */
int fr_pair_list_cmp(fr_pair_list_t const *a, fr_pair_list_t const *b)
{
	fr_pair_t *a_p, *b_p;

	for (a_p = fr_pair_list_head(a), b_p = fr_pair_list_head(b);
	     a_p && b_p;
	     a_p = fr_pair_list_next(a, a_p), b_p = fr_pair_list_next(b, b_p)) {
		int ret;

		/* Same VP, no point doing expensive checks */
		if (a_p == b_p) continue;

		ret = (a_p->da < b_p->da) - (a_p->da > b_p->da);
		if (ret != 0) return ret;

		switch (a_p->da->type) {
		case FR_TYPE_STRUCTURAL:
			ret = fr_pair_list_cmp(&a_p->vp_group, &b_p->vp_group);
			if (ret != 0) return ret;
			break;

		default:
			ret = fr_value_box_cmp(&a_p->data, &b_p->data);
			if (ret != 0) {
				(void)fr_cond_assert(ret >= -1); 	/* Comparison error */
				return ret;
			}
		}

	}

	if (!a_p && !b_p) return 0;
	if (!a_p) return -1;

	/* if(!b_p) */
	return 1;
}

/** Sort a doubly linked list of fr_pair_ts using merge sort
 *
 * @note We use a merge sort (which is a stable sort), making this
 *	suitable for use on lists with things like EAP-Message
 *	fragments where the order of EAP-Message attributes needs to
 *	be maintained.
 *
 * @param[in,out] list head of dlinked fr_pair_ts to sort.
 * @param[in] cmp to sort with
 */
void fr_pair_list_sort(fr_pair_list_t *list, fr_cmp_t cmp)
{
	fr_pair_order_list_sort(&list->order, cmp);
}

/** Write an error to the library errorbuff detailing the mismatch
 *
 * Retrieve output with fr_strerror();
 *
 * @todo add thread specific talloc contexts.
 *
 * @param ctx a hack until we have thread specific talloc contexts.
 * @param failed pair of attributes which didn't match.
 */
void fr_pair_validate_debug(TALLOC_CTX *ctx, fr_pair_t const *failed[2])
{
	fr_pair_t const *filter = failed[0];
	fr_pair_t const *list = failed[1];

	char *value, *str;

	fr_strerror_clear();	/* Clear any existing messages */

	if (!list) {
		if (!filter) {
			(void) fr_cond_assert(filter != NULL);
			return;
		}
		fr_strerror_printf("Attribute \"%s\" not found in list", filter->da->name);
		return;
	}

	if (!filter || (filter->da != list->da)) {
		fr_strerror_printf("Attribute \"%s\" not found in filter", list->da->name);
		return;
	}

	fr_pair_aprint(ctx, &value, NULL, list);
	fr_pair_aprint(ctx, &str, NULL, filter);

#ifdef STATIC_ANALYZER
	if (!value || !str) return;
#endif

	fr_strerror_printf("Attribute value \"%s\" didn't match filter: %s", value, str);

	talloc_free(str);
	talloc_free(value);

	return;
}

/** Uses fr_pair_cmp to verify all fr_pair_ts in list match the filter defined by check
 *
 * @note will sort both filter and list in place.
 *
 * @param failed pointer to an array to write the pointers of the filter/list attributes that didn't match.
 *	  May be NULL.
 * @param filter attributes to check list against.
 * @param list attributes, probably a request or reply
 */
bool fr_pair_validate(fr_pair_t const *failed[2], fr_pair_list_t *filter, fr_pair_list_t *list)
{
	fr_pair_t *check, *match;

	if (fr_pair_order_list_empty(&filter->order) && fr_pair_order_list_empty(&list->order)) return true;

	/*
	 *	This allows us to verify the sets of validate and reply are equal
	 *	i.e. we have a validate rule which matches every reply attribute.
	 *
	 *	@todo this should be removed one we have sets and lists
	 */
	fr_pair_list_sort(filter, fr_pair_cmp_by_da);
	fr_pair_list_sort(list, fr_pair_cmp_by_da);

	check = fr_pair_list_head(filter);
	match = fr_pair_list_head(list);
	while (match || check) {
		/*
		 *	Lists are of different lengths
		 */
		if (!match || !check) goto mismatch;

		/*
		 *	The lists are sorted, so if the head
		 *	attributes aren't of the same type, then we're
		 *	done.
		 */
		if (!ATTRIBUTE_EQ(check, match)) goto mismatch;

		/*
		 *	They're of the same type, but don't have the
		 *	same values.  This is a problem.
		 *
		 *	Note that the RFCs say that for attributes of
		 *	the same type, order is important.
		 */
		switch (check->da->type) {
		case FR_TYPE_STRUCTURAL:
			if (!fr_pair_validate(failed, &check->vp_group, &match->vp_group)) goto mismatch;
			break;

		default:
			/*
			 *	This attribute passed the filter
			 */
			if (!fr_pair_cmp(check, match)) goto mismatch;
			break;
		}

		check = fr_pair_list_next(filter, check);
		match = fr_pair_list_next(list, match);
	}

	return true;

mismatch:
	if (failed) {
		failed[0] = check;
		failed[1] = match;
	}
	return false;
}

/** Uses fr_pair_cmp to verify all fr_pair_ts in list match the filter defined by check
 *
 * @note will sort both filter and list in place.
 *
 * @param failed pointer to an array to write the pointers of the filter/list attributes that didn't match.
 *	  May be NULL.
 * @param filter attributes to check list against.
 * @param list attributes, probably a request or reply
 */
bool fr_pair_validate_relaxed(fr_pair_t const *failed[2], fr_pair_list_t *filter, fr_pair_list_t *list)
{
	fr_pair_t *check, *last_check = NULL, *match = NULL;

	if (fr_pair_order_list_empty(&filter->order) && fr_pair_order_list_empty(&list->order)) return true;

	/*
	 *	This allows us to verify the sets of validate and reply are equal
	 *	i.e. we have a validate rule which matches every reply attribute.
	 *
	 *	@todo this should be removed one we have sets and lists
	 */
	fr_pair_list_sort(filter, fr_pair_cmp_by_da);
	fr_pair_list_sort(list, fr_pair_cmp_by_da);

	for (check = fr_pair_list_head(filter);
	     check;
	     check = fr_pair_list_next(filter, check)) {
		/*
		 *	Were processing check attributes of a new type.
		 */
		if (!ATTRIBUTE_EQ(last_check, check)) {
			/*
			 *	Record the start of the matching attributes in the pair list
			 *	For every other operator we require the match to be present
			 */
			while ((match = fr_pair_list_next(list, match))) {
				if (fr_pair_matches_da(match, check->da)) break;
			}
			if (!match) {
				if (check->op == T_OP_CMP_FALSE) continue;
				goto mismatch;
			}

			last_check = check;
		} else {
			match = fr_pair_list_head(list);
		}

		/*
		 *	Now iterate over all attributes of the same type.
		 */
		for (;
		     ATTRIBUTE_EQ(match, check);
		     match = fr_pair_list_next(list, match)) {
			switch (check->da->type) {
			case FR_TYPE_STRUCTURAL:
				if (!fr_pair_validate_relaxed(failed, &check->vp_group, &match->vp_group)) goto mismatch;
				break;

			default:
				/*
				 *	This attribute passed the filter
				 */
				if (!fr_pair_cmp(check, match)) goto mismatch;
				break;
			}
		}
	}

	return true;

mismatch:
	if (failed) {
		failed[0] = check;
		failed[1] = match;
	}
	return false;
}

/** Duplicate a list of pairs
 *
 * Copy all pairs from 'from' regardless of tag, attribute or vendor.
 *
 * @param[in] ctx	for new #fr_pair_t (s) to be allocated in.
 * @param[in] to	where to copy attributes to.
 * @param[in] from	whence to copy #fr_pair_t (s).
 * @return
 *	- >0 the number of attributes copied.
 *	- 0 if no attributes copied.
 *	- -1 on error.
 */
int fr_pair_list_copy(TALLOC_CTX *ctx, fr_pair_list_t *to, fr_pair_list_t const *from)
{
	fr_pair_t	*vp, *new_vp, *first_added = NULL;
	int		cnt = 0;

	for (vp = fr_pair_list_head(from);
	     vp;
	     vp = fr_pair_list_next(from, vp), cnt++) {
		PAIR_VERIFY_WITH_LIST(from, vp);

		new_vp = fr_pair_copy(ctx, vp);
		if (!new_vp) {
			fr_pair_order_list_talloc_free_to_tail(&to->order, first_added);
			return -1;
		}

		if (!first_added) first_added = new_vp;
		fr_pair_append(to, new_vp);
	}

	return cnt;
}

/** Duplicate pairs in a list matching the specified da
 *
 * Copy all pairs from 'from' matching the specified da.
 *
 * @param[in] ctx		for new #fr_pair_t (s) to be allocated in.
 * @param[in] to		where to copy attributes to.
 * @param[in] from		whence to copy #fr_pair_t (s).
 * @param[in] da		to match.
 * @param[in] count		How many instances to copy.
 *				Use 0 for all attributes.
 * @return
 *	- >0 the number of attributes copied.
 *	- 0 if no attributes copied.
 *	- -1 on error.
 */
int fr_pair_list_copy_by_da(TALLOC_CTX *ctx, fr_pair_list_t *to,
			    fr_pair_list_t const *from, fr_dict_attr_t const *da, unsigned int count)
{
	fr_pair_t	*vp, *new_vp, *first_added = NULL;
	unsigned int	cnt = 0;

	if (count == 0) count = UINT_MAX;

	if (unlikely(!da)) {
		fr_strerror_printf("No search attribute provided");
		return -1;
	}

	for (vp = fr_pair_list_head(from);
	     vp && (cnt < count);
	     vp = fr_pair_list_next(from, vp)) {
		PAIR_VERIFY_WITH_LIST(from, vp);

		if (!fr_pair_matches_da(vp, da)) continue;

		cnt++;
		new_vp = fr_pair_copy(ctx, vp);
		if (!new_vp) {
			fr_pair_order_list_talloc_free_to_tail(&to->order, first_added);
			return -1;
		}

		if (!first_added) first_added = new_vp;
		fr_pair_append(to, new_vp);
	}

	return cnt;
}

/** Duplicate pairs in a list where the da is a descendant of parent_da
 *
 * Copy all pairs from 'from' which are descendants of the specified 'parent_da'.
 * This is particularly useful for copying attributes of a particular vendor, where the vendor
 * da is passed as parent_da.
 *
 * @param[in] ctx		for new #fr_pair_t (s) to be allocated in.
 * @param[in] to		where to copy attributes to.
 * @param[in] from		whence to copy #fr_pair_t (s).
 * @param[in] parent_da		to match.
 * @param[in] count		How many instances to copy.
 *				Use 0 for all attributes.
 * @return
 *	- >0 the number of attributes copied.
 *	- 0 if no attributes copied.
 *	- -1 on error.
 */
int fr_pair_list_copy_by_ancestor(TALLOC_CTX *ctx, fr_pair_list_t *to,
				  fr_pair_list_t const *from, fr_dict_attr_t const *parent_da, unsigned int count)
{
	fr_pair_t	*vp, *new_vp;
	unsigned int	cnt = 0;

	if (count == 0) count = UINT_MAX;

	for (vp = fr_pair_list_head(from);
	     vp && (cnt < count);
	     vp = fr_pair_list_next(from, vp)) {
		if (!fr_dict_attr_common_parent(parent_da, vp->da, true)) continue;
		cnt++;

		PAIR_VERIFY_WITH_LIST(from, vp);
		new_vp = fr_pair_copy(ctx, vp);
		if (unlikely(!new_vp)) return -1;
		fr_pair_append(to, new_vp);
	}

	return cnt;
}

/** Duplicate a list of pairs starting at a particular item
 *
 * Copy all pairs from 'from' regardless of tag, attribute or vendor, starting at 'item'.
 *
 * @param[in] ctx		for new #fr_pair_t (s) to be allocated in.
 * @param[in] to		where to copy attributes to.
 * @param[in] from		whence to copy #fr_pair_t (s).
 * @param[in] start		first pair to start copying from.
 * @param[in] count		How many instances to copy.
 *				Use 0 for all attributes.
 * @return
 *	- >0 the number of attributes copied.
 *	- 0 if no attributes copied.
 *	- -1 on error.
 */
int fr_pair_sublist_copy(TALLOC_CTX *ctx, fr_pair_list_t *to,
			 fr_pair_list_t const *from, fr_pair_t const *start, unsigned int count)
{
	fr_pair_t const	*vp;
	fr_pair_t	*new_vp;
	unsigned int	cnt = 0;

	if (!start) start = fr_pair_list_head(from);

	for (vp = start;
	     vp && ((count == 0) || (cnt < count));
	     vp = fr_pair_list_next(from, vp), cnt++) {
		PAIR_VERIFY_WITH_LIST(from, vp);
		new_vp = fr_pair_copy(ctx, vp);
		if (unlikely(!new_vp)) return -1;
		fr_pair_append(to, new_vp);
	}

	return cnt;
}

/** Free/zero out value (or children) of a given VP
 *
 * @param[in] vp to clear value from.
 */
void fr_pair_value_clear(fr_pair_t *vp)
{
	fr_pair_t *child;

	switch (vp->da->type) {
	default:
		fr_value_box_clear_value(&vp->data);
		break;

	case FR_TYPE_STRUCTURAL:
		if (!fr_pair_order_list_empty(&vp->vp_group.order)) return;

		while ((child = fr_pair_order_list_pop_tail(&vp->vp_group.order))) {
			fr_pair_value_clear(child);
			talloc_free(child);
		}
		break;
	}
}

/** Copy the value from one pair to another
 *
 * @param[out] dst	where to copy the value to.
 *			will clear assigned value.
 * @param[in] src	where to copy the value from
 *			Must have an assigned value.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_copy(fr_pair_t *dst, fr_pair_t *src)
{
	if (!fr_cond_assert(src->data.type != FR_TYPE_NULL)) return -1;

	if (dst->data.type != FR_TYPE_NULL) fr_value_box_clear(&dst->data);
	fr_value_box_copy(dst, &dst->data, &src->data);

	return 0;
}

/** Convert string value to native attribute value
 *
 * @param[in] vp	to assign value to.
 * @param[in] value	string to convert. Binary safe for variable
 *			length values if len is provided.
 * @param[in] inlen	The length of the input string.
 * @param[in] uerules	used to perform unescaping.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_from_str(fr_pair_t *vp, char const *value, size_t inlen,
			   fr_sbuff_unescape_rules_t const *uerules, bool tainted)
{
	/*
	 *	This is not yet supported because the rest of the APIs
	 *	to parse pair names, etc. don't yet enforce "inlen".
	 *	This is likely not a problem in practice, but we
	 *	haven't yet audited the uses of this function for that
	 *	behavior.
	 */
	switch (vp->da->type) {
	case FR_TYPE_STRUCTURAL:
		fr_strerror_printf("Attributes of type '%s' are not yet supported",
				   fr_type_to_str(vp->da->type));
		return -1;

	default:
		break;
	}

	/*
	 *	We presume that the input data is from a double quoted
	 *	string, and needs unescaping
	 */
	if (fr_value_box_from_str(vp, &vp->data, vp->da->type, vp->da,
				  value, inlen,
				  uerules,
				  tainted) < 0) return -1;

	PAIR_VERIFY(vp);

	return 0;
}

/** Copy data into an "string" data type.
 *
 * @note vp->da must be of type FR_TYPE_STRING.
 *
 * @param[in,out] vp	to update
 * @param[in] src	data to copy
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_strdup(fr_pair_t *vp, char const *src, bool tainted)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return -1;

	fr_value_box_clear(&vp->data);	/* Free any existing buffers */
	ret = fr_value_box_strdup(vp, &vp->data, vp->da, src, tainted);
	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Assign a buffer containing a nul terminated string to a vp, but don't copy it
 *
 * @param[in] vp	to assign string to.
 * @param[in] src	to copy string from.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_strdup_shallow(fr_pair_t *vp, char const *src, bool tainted)
{
	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return -1;

	fr_value_box_clear(&vp->data);
	fr_value_box_strdup_shallow(&vp->data, vp->da, src, tainted);

	PAIR_VERIFY(vp);

	return 0;
}

/** Trim the length of the string buffer to match the length of the C string
 *
 * @param[in,out] vp	to trim.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_strtrim(fr_pair_t *vp)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return -1;

	ret = fr_value_box_strtrim(vp, &vp->data);
	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Print data into an "string" data type.
 *
 * @note vp->da must be of type FR_TYPE_STRING.
 *
 * @param[in,out] vp to update
 * @param[in] fmt the format string
 */
int fr_pair_value_aprintf(fr_pair_t *vp, char const *fmt, ...)
{
	int	ret;
	va_list	ap;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return -1;

	fr_value_box_clear(&vp->data);
	va_start(ap, fmt);
	ret = fr_value_box_vasprintf(vp, &vp->data, vp->da, false, fmt, ap);
	va_end(ap);

	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Pre-allocate a memory buffer for a "string" type value pair
 *
 * @note Will clear existing values (including buffers).
 *
 * @param[in,out] vp	to update
 * @param[out] out	If non-null will be filled with a pointer to the
 *			new buffer.
 * @param[in] size	of the data.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *      - 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_bstr_alloc(fr_pair_t *vp, char **out, size_t size, bool tainted)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return -1;

	fr_value_box_clear(&vp->data);	/* Free any existing buffers */
	ret = fr_value_box_bstr_alloc(vp, out, &vp->data, vp->da, size, tainted);
	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Change the length of a buffer for a "string" type value pair
 *
 * @param[in,out] vp	to update
 * @param[out] out	If non-null will be filled with a pointer to the
 *			new buffer.
 * @param[in] size	of the data.
 * @return
 *      - 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_bstr_realloc(fr_pair_t *vp, char **out, size_t size)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return -1;

	ret = fr_value_box_bstr_realloc(vp, out, &vp->data, size);
	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Copy data into a "string" type value pair
 *
 * @note unlike the original strncpy, this function does not stop
 *	if it finds \0 bytes embedded in the string.
 *
 * @note vp->da must be of type FR_TYPE_STRING.
 *
 * @param[in,out] vp	to update.
 * @param[in] src	data to copy.
 * @param[in] len	of data to copy.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *      - 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_bstrndup(fr_pair_t *vp, char const *src, size_t len, bool tainted)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return -1;

	fr_value_box_clear(&vp->data);
	ret = fr_value_box_bstrndup(vp, &vp->data, vp->da, src, len, tainted);
	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Copy a nul terminated talloced buffer a "string" type value pair
 *
 * The buffer must be \0 terminated, or an error will be returned.
 *
 * @param[in,out] vp 	to update.
 * @param[in] src 	a talloced nul terminated buffer.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_bstrdup_buffer(fr_pair_t *vp, char const *src, bool tainted)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return -1;

	fr_value_box_clear(&vp->data);
	ret = fr_value_box_bstrdup_buffer(vp, &vp->data, vp->da, src, tainted);
	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Assign a string to a "string" type value pair
 *
 * @param[in] vp 	to assign new buffer to.
 * @param[in] src 	a string.
 * @param[in] len	of src.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_bstrndup_shallow(fr_pair_t *vp, char const *src, size_t len, bool tainted)
{
	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return -1;

	fr_value_box_clear(&vp->data);
	fr_value_box_bstrndup_shallow(&vp->data, vp->da, src, len, tainted);
	PAIR_VERIFY(vp);

	return 0;
}

/** Assign a string to a "string" type value pair
 *
 * @param[in] vp 	to assign new buffer to.
 * @param[in] src 	a string.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_bstrdup_buffer_shallow(fr_pair_t *vp, char const *src, bool tainted)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return -1;

	fr_value_box_clear(&vp->data);
	ret = fr_value_box_bstrdup_buffer_shallow(NULL, &vp->data, vp->da, src, tainted);
	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Append bytes from a buffer to an existing "string" type value pair
 *
 * @param[in,out] vp	to update.
 * @param[in] src	data to copy.
 * @param[in] len	of data to copy.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 * 	- -1 on failure.
 */
int fr_pair_value_bstrn_append(fr_pair_t *vp, char const *src, size_t len, bool tainted)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return -1;

	ret = fr_value_box_bstrn_append(vp, &vp->data, src, len, tainted);
	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Append a talloced buffer to an existing "string" type value pair
 *
 * @param[in,out] vp	to update.
 * @param[in] src	a talloced nul terminated buffer.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 * 	- -1 on failure.
 */
int fr_pair_value_bstr_append_buffer(fr_pair_t *vp, char const *src, bool tainted)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return -1;

	ret = fr_value_box_bstr_append_buffer(vp, &vp->data, src, tainted);
	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Pre-allocate a memory buffer for a "octets" type value pair
 *
 * @note Will clear existing values (including buffers).
 *
 * @param[in,out] vp	to update
 * @param[out] out	If non-null will be filled with a pointer to the
 *			new buffer.
 * @param[in] size	of the data.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *      - 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_mem_alloc(fr_pair_t *vp, uint8_t **out, size_t size, bool tainted)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_OCTETS)) return -1;

	fr_value_box_clear(&vp->data);	/* Free any existing buffers */
	ret = fr_value_box_mem_alloc(vp, out, &vp->data, vp->da, size, tainted);
	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Change the length of a buffer for a "octets" type value pair
 *
 * @param[in,out] vp	to update
 * @param[out] out	If non-null will be filled with a pointer to the
 *			new buffer.
 * @param[in] size	of the data.
 * @return
 *      - 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_mem_realloc(fr_pair_t *vp, uint8_t **out, size_t size)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_OCTETS)) return -1;

	ret = fr_value_box_mem_realloc(vp, out, &vp->data, size);
	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Copy data into an "octets" data type.
 *
 * @note Will clear existing values (including buffers).
 *
 * @param[in,out] vp	to update
 * @param[in] src	data to copy
 * @param[in] len	of the data.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *      - 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_memdup(fr_pair_t *vp, uint8_t const *src, size_t len, bool tainted)
{
	int ret;

	if (unlikely((len > 0) && !src)) {
		fr_strerror_printf("Invalid arguments to %s.  Len > 0 (%zu) but src was NULL",
				   __FUNCTION__, len);
		return -1;
	}

	if (!fr_cond_assert(vp->da->type == FR_TYPE_OCTETS)) return -1;

	fr_value_box_clear(&vp->data);	/* Free any existing buffers */
	ret = fr_value_box_memdup(vp, &vp->data, vp->da, src, len, tainted);
	if (ret == 0) PAIR_VERIFY(vp);

	return ret;
}

/** Copy data from a talloced buffer into an "octets" data type.
 *
 * @note Will clear existing values (including buffers).
 *
 * @param[in,out] vp	to update
 * @param[in] src	data to copy
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *      - 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_memdup_buffer(fr_pair_t *vp, uint8_t const *src, bool tainted)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_OCTETS)) return -1;

	fr_value_box_clear(&vp->data);	/* Free any existing buffers */
	ret = fr_value_box_memdup_buffer(vp, &vp->data, vp->da, src, tainted);
	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Assign a buffer to a "octets" type value pair
 *
 * @param[in] vp 	to assign new buffer to.
 * @param[in] src 	data to copy.
 * @param[in] len	of src.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_memdup_shallow(fr_pair_t *vp, uint8_t const *src, size_t len, bool tainted)
{
	if (!fr_cond_assert(vp->da->type == FR_TYPE_OCTETS)) return -1;

	fr_value_box_clear(&vp->data);
	fr_value_box_memdup_shallow(&vp->data, vp->da, src, len, tainted);
	PAIR_VERIFY(vp);

	return 0;
}

/** Assign a talloced buffer to a "octets" type value pair
 *
 * @param[in] vp 	to assign new buffer to.
 * @param[in] src 	data to copy.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_memdup_buffer_shallow(fr_pair_t *vp, uint8_t const *src, bool tainted)
{
	if (!fr_cond_assert(vp->da->type == FR_TYPE_OCTETS)) return -1;

	fr_value_box_clear(&vp->data);
	fr_value_box_memdup_buffer_shallow(NULL, &vp->data, vp->da, src, tainted);
	PAIR_VERIFY(vp);

	return 0;
}


/** Append bytes from a buffer to an existing "octets" type value pair
 *
 * @param[in,out] vp	to update.
 * @param[in] src	data to copy.
 * @param[in] len	of data to copy.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 * 	- -1 on failure.
 */
int fr_pair_value_mem_append(fr_pair_t *vp, uint8_t *src, size_t len, bool tainted)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_OCTETS)) return -1;

	ret = fr_value_box_mem_append(vp, &vp->data, src, len, tainted);
	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Append a talloced buffer to an existing "octets" type value pair
 *
 * @param[in,out] vp	to update.
 * @param[in] src	data to copy.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 * 	- -1 on failure.
 */
int fr_pair_value_mem_append_buffer(fr_pair_t *vp, uint8_t *src, bool tainted)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_OCTETS)) return -1;

	ret = fr_value_box_mem_append_buffer(vp, &vp->data, src, tainted);
	if (ret == 0) {
		PAIR_VERIFY(vp);
	}

	return ret;
}

/** Return a const buffer for an enum type attribute
 *
 * Where the vp type is numeric but does not have any enumv, or its value
 * does not map to an enumv, the integer value of the pair will be printed
 * to buff, and a pointer to buff will be returned.
 *
 * @param[in] vp	to print.
 * @param[in] buff	to print integer value to.
 * @return a talloced buffer.
 */
char const *fr_pair_value_enum(fr_pair_t const *vp, char buff[20])
{
	char const		*str;
	fr_dict_enum_value_t const	*enumv = NULL;

	if (!fr_box_is_numeric(&vp->data)) {
		fr_strerror_printf("Pair %s is not numeric", vp->da->name);
		return NULL;
	}

	if (vp->da->flags.has_value) switch (vp->vp_type) {
	case FR_TYPE_BOOL:
		return vp->vp_bool ? "yes" : "no";

	default:
		enumv = fr_dict_enum_by_value(vp->da, &vp->data);
		break;
	}

	if (!enumv) {
		fr_pair_print_value_quoted(&FR_SBUFF_OUT(buff, 20), vp, T_BARE_WORD);
		str = buff;
	} else {
		str = enumv->name;
	}

	return str;
}

/** Get value box of a VP, optionally prefer enum value.
 *
 * Get the data value box of the given VP. If 'e' is set to 1 and the VP has an
 * enum value, this will be returned instead. Otherwise it will be set to the
 * value box of the VP itself.
 *
 * @param[out] out	pointer to a value box.
 * @param[in] vp	to print.
 * @return 1 if the enum value has been used, 0 otherwise, -1 on error.
 */
int fr_pair_value_enum_box(fr_value_box_t const **out, fr_pair_t *vp)
{
	fr_dict_enum_value_t const	*dv;

	if (vp->da && vp->da->flags.has_value &&
	    (dv = fr_dict_enum_by_value(vp->da, &vp->data))) {
		*out = dv->value;
		return 1;
	}

	*out = &vp->data;
	return 0;
}

#ifdef WITH_VERIFY_PTR
/*
 *	Verify a fr_pair_t
 */
void fr_pair_verify(char const *file, int line, fr_pair_list_t const *list, fr_pair_t const *vp)
{
	(void) talloc_get_type_abort_const(vp, fr_pair_t);

	if (!vp->da) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t da pointer was NULL", file, line);
	}

	fr_dict_attr_verify(file, line, vp->da);
	if (vp->data.enumv) fr_dict_attr_verify(file, line, vp->data.enumv);

	if (list) {
		fr_fatal_assert_msg(fr_pair_order_list_parent(vp) == &list->order,
				    "CONSISTENCY CHECK FAILED %s[%u]:  pair does not have the correct parentage "
				    "at \"%s\"",
				    file, line, vp->da->name);
	}

	if (vp->vp_ptr) switch (vp->vp_type) {
	case FR_TYPE_OCTETS:
	{
		size_t len;
		TALLOC_CTX *parent;

		if (!talloc_get_type(vp->vp_ptr, uint8_t)) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" data buffer type should be "
					     "uint8_t but is %s", file, line, vp->da->name, talloc_get_name(vp->vp_ptr));
		}

		len = talloc_array_length(vp->vp_octets);
		if (vp->vp_length > len) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" length %zu is greater than "
					     "uint8_t data buffer length %zu", file, line, vp->da->name, vp->vp_length, len);
		}

		parent = talloc_parent(vp->vp_ptr);
		if (parent != vp) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" char buffer is not "
					     "parented by fr_pair_t %p, instead parented by %p (%s)",
					     file, line, vp->da->name,
					     vp, parent, parent ? talloc_get_name(parent) : "NULL");
		}
	}
		break;

	case FR_TYPE_STRING:
	{
		size_t len;
		TALLOC_CTX *parent;

		if (!talloc_get_type(vp->vp_ptr, char)) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" data buffer type should be "
					     "char but is %s", file, line, vp->da->name, talloc_get_name(vp->vp_ptr));
		}

		len = (talloc_array_length(vp->vp_strvalue) - 1);
		if (vp->vp_length > len) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" length %zu is greater than "
					     "char buffer length %zu", file, line, vp->da->name, vp->vp_length, len);
		}

		if (vp->vp_strvalue[vp->vp_length] != '\0') {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" char buffer not \\0 "
					     "terminated", file, line, vp->da->name);
		}

		parent = talloc_parent(vp->vp_ptr);
		if (parent != vp) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" char buffer is not "
					     "parented by fr_pair_t %p, instead parented by %p (%s)",
					     file, line, vp->da->name,
					     vp, parent, parent ? talloc_get_name(parent) : "NULL");
					     fr_fatal_assert_fail("0");
		}
	}
		break;

	case FR_TYPE_IPV4_ADDR:
		if (vp->vp_ip.af != AF_INET) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" address family is not "
					     "set correctly for IPv4 address.  Expected %i got %i",
					     file, line, vp->da->name,
					     AF_INET, vp->vp_ip.af);
		}
		if (vp->vp_ip.prefix != 32) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" address prefix "
					     "set correctly for IPv4 address.  Expected %i got %i",
					     file, line, vp->da->name,
					     32, vp->vp_ip.prefix);
		}
		break;

	case FR_TYPE_IPV6_ADDR:
		if (vp->vp_ip.af != AF_INET6) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" address family is not "
					     "set correctly for IPv6 address.  Expected %i got %i",
					     file, line, vp->da->name,
					     AF_INET6, vp->vp_ip.af);
		}
		if (vp->vp_ip.prefix != 128) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" address prefix "
					     "set correctly for IPv6 address.  Expected %i got %i",
					     file, line, vp->da->name,
					     128, vp->vp_ip.prefix);
		}
		break;

       case FR_TYPE_STRUCTURAL:
       {
		fr_pair_t	*child;

		for (child = fr_pair_list_head(&vp->vp_group);
		     child;
		     child = fr_pair_list_next(&vp->vp_group, child)) {
			TALLOC_CTX *parent = talloc_parent(child);

			fr_fatal_assert_msg(parent == vp,
					    "CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" should be parented "
					    "by fr_pair_t \"%s\".  Expected talloc parent %p (%s) got %p (%s)",
					    file, line,
					    child->da->name, vp->da->name,
					    vp, talloc_get_name(vp),
					    parent, talloc_get_name(parent));

			fr_pair_verify(file, line, &vp->vp_group, child);
		}
	}
	       break;

	default:
		break;
	}

	if (vp->da->flags.is_unknown || vp->da->flags.is_raw) {
		(void) talloc_get_type_abort_const(vp->da, fr_dict_attr_t);
	} else {
		fr_dict_attr_t const *da;

		da = vp->da;
		if (da != vp->da) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t "
					     "dictionary pointer %p \"%s\" (%s) "
					     "and global dictionary pointer %p \"%s\" (%s) differ",
					     file, line, vp->da, vp->da->name,
					     fr_type_to_str(vp->da->type),
					     da, da->name,
					     fr_type_to_str(da->type));
		}
	}

	if (vp->da->flags.is_raw || vp->da->flags.is_unknown) {
		if ((vp->da->parent->type != FR_TYPE_VSA) && (vp->data.type != FR_TYPE_VSA) && (vp->data.type != FR_TYPE_OCTETS)) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t (raw/unknown) attribute %p \"%s\" "
					     "data type incorrect.  Expected %s, got %s",
					     file, line, vp->da, vp->da->name,
					     fr_type_to_str(FR_TYPE_OCTETS),
					     fr_type_to_str(vp->data.type));
		}
	} else if (!fr_type_is_structural(vp->da->type) && (vp->da->type != vp->data.type)) {
		char data_type_int[10], da_type_int[10];

		snprintf(data_type_int, sizeof(data_type_int), "%i", vp->data.type);
		snprintf(da_type_int, sizeof(da_type_int), "%i", vp->da->type);

		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t attribute %p \"%s\" "
				     "data type (%s) does not match da type (%s)",
				     file, line, vp->da, vp->da->name,
				     fr_table_str_by_value(fr_type_table, vp->data.type, data_type_int),
				     fr_table_str_by_value(fr_type_table, vp->da->type, da_type_int));
	}
}

/** Verify a pair list
 *
 * @param[in] file	from which the verification is called
 * @param[in] line	number in file
 * @param[in] expected	talloc ctx pairs should have been allocated in
 * @param[in] list	of fr_pair_ts to verify
 */
void fr_pair_list_verify(char const *file, int line, TALLOC_CTX const *expected, fr_pair_list_t const *list)
{
	fr_pair_t		*slow, *fast;
	TALLOC_CTX		*parent;

	if (fr_pair_list_empty(list)) return;	/* Fast path */

	for (slow = fr_pair_list_head(list), fast = fr_pair_list_head(list);
	     slow && fast;
	     slow = fr_pair_list_next(list, slow), fast = fr_pair_list_next(list, fast)) {
		PAIR_VERIFY_WITH_LIST(list, slow);

		/*
		 *	Advances twice as fast as slow...
		 */
		fast = fr_pair_list_next(list, fast);
		fr_fatal_assert_msg(fast != slow,
				    "CONSISTENCY CHECK FAILED %s[%u]:  Looping list found.  Fast pointer hit "
				    "slow pointer at \"%s\"",
				    file, line, slow->da->name);

		parent = talloc_parent(slow);
		if (expected && (parent != expected)) {
		bad_parent:
			fr_log_talloc_report(expected);
			if (parent) fr_log_talloc_report(parent);

			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: Expected fr_pair_t \"%s\" to be parented "
					     "by %p (%s), instead parented by %p (%s)\n",
					     file, line, slow->da->name,
					     expected, talloc_get_name(expected),
					     parent, parent ? talloc_get_name(parent) : "NULL");
		}
	}

	/*
	 *	Check the remaining pairs
	 */
	for (; slow; slow = fr_pair_list_next(list, slow)) {
		PAIR_VERIFY_WITH_LIST(list, slow);

		parent = talloc_parent(slow);
		if (expected && (parent != expected)) goto bad_parent;
	}
}
#endif

/** Mark up a list of VPs as tainted.
 *
 */
void fr_pair_list_tainted(fr_pair_list_t *list)
{
	fr_pair_t	*vp;

	if (fr_pair_list_empty(list)) return;

	for (vp = fr_pair_list_head(list);
	     vp;
	     vp = fr_pair_list_next(list, vp)) {
		PAIR_VERIFY_WITH_LIST(list, vp);

		switch (vp->da->type) {
		case FR_TYPE_STRUCTURAL:
			fr_pair_list_tainted(&vp->vp_group);
			break;

		default:
			break;
		}

		vp->vp_tainted = true;
	}
}

/** Appends a list of fr_pair_t from a temporary list to a destination list
 *
 * @param dst list to move pairs into
 * @param src list from which to take pairs
 */
void fr_pair_list_append(fr_pair_list_t *dst, fr_pair_list_t *src)
{
	fr_pair_order_list_move(&dst->order, &src->order);
}

/** Move a list of fr_pair_t from a temporary list to the head of a destination list
 *
 * @param dst list to move pairs into
 * @param src from which to take pairs
 */
void fr_pair_list_prepend(fr_pair_list_t *dst, fr_pair_list_t *src)
{
	fr_pair_order_list_move_head(&dst->order, &src->order);
}

/** Evaluation function for matching if vp matches a given da
 *
 * Can be used as a filter function for fr_dcursor_filter_next()
 *
 * @param item	pointer to a fr_pair_t
 * @param uctx	da to match
 *
 * @return true if the pair matches the da
 */
bool fr_pair_matches_da(void const *item, void const *uctx)
{
	fr_pair_t const		*vp = item;
	fr_dict_attr_t const	*da = uctx;
	return da == vp->da;
}

/** Get the length of a list of fr_pair_t
 *
 * @param[in] list to return the length of
 *
 * @return number of entries in the list
 */
size_t fr_pair_list_len(fr_pair_list_t const *list)
{
	return fr_pair_order_list_num_elements(&list->order);
}

/** Get the dlist head from a pair list
 *
 * @param[in] list to get the head from
 *
 * @return number of entries in the list
 */
fr_dlist_head_t *fr_pair_list_dlist_head(fr_pair_list_t const *list)
{
	return fr_pair_order_list_dlist_head(&list->order);
}

/** Parse a list of VPs from a value box.
 *
 * @param[in] ctx	to allocate new VPs in
 * @param[out] out	list to add new pairs to
 * @param[in] dict	to use in parsing
 * @param[in] box	whose value is to be parsed
 */
void fr_pair_list_afrom_box(TALLOC_CTX *ctx, fr_pair_list_t *out, fr_dict_t const *dict, fr_value_box_t *box)
{
	int comma = 0;
	char *p, *end, *last_comma = NULL;

	fr_assert(box->type == FR_TYPE_STRING);

	/*
	 *	HACK: Replace '\n' with ',' so that
	 *	fr_pair_list_afrom_str() can parse the buffer in
	 *	one go (the proper way would be to
	 *	fix fr_pair_list_afrom_str(), but oh well).
	 *
	 *	Note that we can mangle box->vb_strvalue, as it's
	 *	getting discarded immediately after this modification.
	 */
	memcpy(&p, &box->vb_strvalue, sizeof(p)); /* const issues */
	end = p + talloc_array_length(box->vb_strvalue) - 1;

	while (p < end) {
		/*
		 *	Replace the first \n by a comma, and remaining
		 *	ones by a space.
		 */
		if (*p == '\n') {
			if (comma) {
				*(p++) = ' ';
			} else {
				*p = ',';
				last_comma = p;
				p++;
			}

			comma = 0;
			continue;
		}

		if (*p == ',') {
			comma++;
			last_comma = p;
			p++;
			continue;
		}

		last_comma = NULL;
		p++;
	}

	/*
	 *	Don't end with a trailing comma
	 */
	if (last_comma) *last_comma = '\0';

	if (fr_pair_list_afrom_str(ctx, fr_dict_root(dict), box->vb_strvalue, box->vb_length, out) == T_INVALID) {
		return;
	}

	/*
	 *	Mark the attributes as tainted.
	 */
	fr_pair_list_tainted(out);
}
