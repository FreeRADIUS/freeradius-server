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
 * @copyright 2000,2006,2015 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/pair_legacy.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/regex.h>
#include <freeradius-devel/util/talloc.h>

#include <ctype.h>

#ifndef NDEBUG
#  define FREE_MAGIC (0xF4EEF4EE)
#endif

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

	vp->op = T_OP_EQ;
	vp->type = VT_NONE;

	talloc_set_destructor(vp, _fr_pair_free);

	return vp;
}

/** Dynamically allocate a new attribute and assign a #fr_dict_attr_t
 *
 * @note Will duplicate any unknown attributes passed as the da.
 *
 * @param[in] ctx	for allocated memory, usually a pointer to a #fr_radius_packet_t
 * @param[in] da	Specifies the dictionary attribute to build the #fr_pair_t from.
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

	/*
	 *	Use the 'da' to initialize more fields.
	 */
	vp->da = da;
	fr_value_box_init(&vp->data, da->type, da, false);

	return vp;
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
	vp->da = da;
	fr_value_box_init(&vp->data, da->type, da, false);

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

	if (!vp) return NULL;

	VP_VERIFY(vp);

	n = fr_pair_afrom_da(ctx, vp->da);
	if (!n) return NULL;

	n->op = vp->op;
	n->next = NULL;
	n->type = vp->type;

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
	 *	If it's an xlat, copy the raw string and return
	 *	early, so we don't pre-expand or otherwise mangle
	 *	the fr_pair_t.
	 */
	if (vp->type == VT_XLAT) {
		n->xlat = talloc_typed_strdup(n, vp->xlat);
		return n;
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
void fr_pair_steal(TALLOC_CTX *ctx, fr_pair_t *vp)
{
	(void) talloc_steal(ctx, vp);

	/*
	 *	The DA may be unknown.  If we're stealing the VPs to a
	 *	different context, copy the unknown DA.  We use the VP
	 *	as a context here instead of "ctx", so that when the
	 *	VP is freed, so is the DA.
	 *
	 *	Since we have no introspection into OTHER VPs using
	 *	the same DA, we can't have multiple VPs use the same
	 *	DA.  So we might as well tie it to this VP.
	 */
	if (vp->da->flags.is_unknown) {
		fr_dict_attr_t *da;

		da = fr_dict_unknown_afrom_da(vp, vp->da);

		fr_dict_unknown_free(&vp->da);

		vp->da = da;
	}
}

/** Free memory used by a valuepair list.
 *
 * @todo TLV: needs to free all dependents of each VP freed.
 *
 * @hidecallergraph
 */
void fr_pair_list_free(fr_pair_list_t *vps)
{
	fr_pair_t	*vp, *next;

	if (!vps || !*vps) return;

	for (vp = *vps; vp != NULL; vp = next) {
		next = vp->next;
		VP_VERIFY(vp);
		talloc_free(vp);
	}

	*vps = NULL;
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

	VP_VERIFY(vp);

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
 * @param[in,out] prev	The fr_pair_t before curr. Will be updated to point to the
 *			pair before the one returned, or the last pair in the list
 *			if no matching pairs found.
 * @param[in] to_eval	The fr_pair_t after cursor->current.  Will be checked to
 *			see if it matches the specified fr_dict_attr_t.
 * @param[in] uctx	The fr_dict_attr_t to search for.
 * @return
 *	- Next matching fr_pair_t.
 *	- NULL if not more matching fr_pair_ts could be found.
 */
void *fr_pair_iter_next_by_da(void **prev, void *to_eval, void *uctx)
{
	fr_pair_t	*c, *p;
	fr_dict_attr_t	*da = uctx;

	if (!to_eval) return NULL;

	for (p = *prev, c = to_eval; c; p = c, c = c->next) {
		VP_VERIFY(c);
		if (c->da == da) break;
	}

	*prev = p;

	return c;
}

/** Iterate over pairs which are decedents of the specified da
 *
 * @param[in,out] prev	The fr_pair_t before curr. Will be updated to point to the
 *			pair before the one returned, or the last pair in the list
 *			if no matching pairs found.
 * @param[in] to_eval	The fr_pair_t after cursor->current.  Will be checked to
 *			see if it matches the specified fr_dict_attr_t.
 * @param[in] uctx	The fr_dict_attr_t to search for.
 * @return
 *	- Next matching fr_pair_t.
 *	- NULL if not more matching fr_pair_ts could be found.
 */
void *fr_pair_iter_next_by_ancestor(void **prev, void *to_eval, void *uctx)
{
	fr_pair_t	*c, *p;
	fr_dict_attr_t	*da = uctx;

	if (!to_eval) return NULL;

	for (p = *prev, c = to_eval; c; p = c, c = c->next) {
		VP_VERIFY(c);
		if (fr_dict_attr_common_parent(da, c->da, true)) break;
	}

	*prev = p;

	return c;
}

/** Find the pair with the matching DAs
 *
 * @hidecallergraph
 */
fr_pair_t *fr_pair_find_by_da(fr_pair_list_t *head, fr_dict_attr_t const *da)
{
	fr_pair_t	*vp;

	/* List head may be NULL if it contains no VPs */
	if (!*head) return NULL;

	LIST_VERIFY(head);

	if (!da) return NULL;

	for (vp = *head; vp != NULL; vp = vp->next) if (da == vp->da) return vp;
	return NULL;
}


/** Find the pair with the matching attribute
 *
 * @todo should take DAs and do a pointer comparison.
 */
fr_pair_t *fr_pair_find_by_num(fr_pair_list_t *head, unsigned int vendor, unsigned int attr)
{
	fr_pair_t	*vp;

	/* List head may be NULL if it contains no VPs */
	if (!*head) return NULL;

	LIST_VERIFY(head);

	for (vp = *head; vp != NULL; vp = vp->next) {
		if (!fr_dict_attr_is_top_level(vp->da)) continue;

	     	if (vendor > 0) {
	     		fr_dict_vendor_t const *dv;

	     		dv = fr_dict_vendor_by_da(vp->da);
	     		if (!dv) continue;

	     		if (dv->pen != vendor) continue;
	     	}

		if (attr == vp->da->attr) return vp;
	}

	return NULL;
}

/** Find the pair with the matching attribute
 *
 */
fr_pair_t *fr_pair_find_by_child_num(fr_pair_list_t *head, fr_dict_attr_t const *parent, unsigned int attr)
{
	fr_dict_attr_t const	*da;
	fr_pair_t		*vp;

	/* List head may be NULL if it contains no VPs */
	if (!*head) return NULL;

	LIST_VERIFY(head);

	da = fr_dict_attr_child_by_num(parent, attr);
	if (!da) return NULL;

	for (vp = *head; vp != NULL; vp = vp->next) if (da == vp->da) return vp;

	return NULL;
}

static inline CC_HINT(always_inline) fr_pair_list_t *pair_children(fr_pair_t *vp)
{
	if (!vp) return NULL;

	switch (vp->da->type) {
	case FR_TYPE_STRUCTURAL:
		return &vp->vp_group;

	default:
		return NULL;
	}
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
	return pair_children(vp);
}


/** Add a VP to the end of the list.
 *
 * Locates the end of 'head', and links an additional VP 'add' at the end.
 *
 * @param[in] head VP in linked list. Will add new VP to the end of this list.
 * @param[in] add VP to add to list.
 */
void fr_pair_add(fr_pair_list_t *head, fr_pair_t *add)
{
	fr_pair_t *i;

	if (!add) return;

	VP_VERIFY(add);

	if (*head == NULL) {
		*head = add;
		return;
	}

	for (i = *head; i->next; i = i->next) {
#ifdef WITH_VERIFY_PTR
		VP_VERIFY(i);
		/*
		 *	The same VP should never by added multiple times
		 *	to the same list.
		 */
		(void)fr_cond_assert(i != add);
#endif
	}

	i->next = add;
}

/** Replace all matching VPs
 *
 * Walks over 'head', and replaces the head VP that matches 'replace'.
 *
 * @note Memory used by the VP being replaced will be freed.
 * @note Will not work with unknown attributes.
 *
 * @param[in,out] head VP in linked list. Will search and replace in this list.
 * @param[in] replace VP to replace.
 */
void fr_pair_replace(fr_pair_list_t *head, fr_pair_t *replace)
{
	fr_pair_t *i, *next;
	fr_pair_t **prev = head;

	VP_VERIFY(replace);

	if (*head == NULL) {
		*head = replace;
		return;
	}

	/*
	 *	Not an empty list, so find item if it is there, and
	 *	replace it. Note, we always replace the head one, and
	 *	we ignore any others that might exist.
	 */
	for(i = *head; i; i = next) {
		VP_VERIFY(i);
		next = i->next;

		/*
		 *	Found the head attribute, replace it,
		 *	and return.
		 */
		if (i->da == replace->da) {
			*prev = replace;

			/*
			 *	Should really assert that replace->next == NULL
			 */
			replace->next = next;
			talloc_free(i);
			return;
		}

		/*
		 *	Point to where the attribute should go.
		 */
		prev = &i->next;
	}

	/*
	 *	If we got here, we didn't find anything to replace, so
	 *	stopped at the last item, which we just append to.
	 */
	*prev = replace;
}

/** Delete matching pairs
 *
 * Delete matching pairs from the attribute list.
 *
 * @param[in,out] head	VP in list.
 * @param[in] attr	to match.
 * @param[in] parent	to match.
 */
void fr_pair_delete_by_child_num(fr_pair_list_t *head, fr_dict_attr_t const *parent, unsigned int attr)
{
	fr_pair_t		*i, *next;
	fr_pair_t		**last = head;
	fr_dict_attr_t const	*da;

	da = fr_dict_attr_child_by_num(parent, attr);
	if (!da) return;

	for (i = *head; i; i = next) {
		VP_VERIFY(i);
		next = i->next;
		if (i->da == da) {
			*last = next;
			talloc_free(i);
		} else {
			last = &i->next;
		}
	}
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
int fr_pair_add_by_da(TALLOC_CTX *ctx, fr_pair_t **out, fr_pair_list_t *list, fr_dict_attr_t const *da)
{
	fr_cursor_t	cursor;
	fr_pair_t	*vp;

	(void)fr_cursor_init(&cursor, list);
	vp = fr_pair_afrom_da(ctx, da);
	if (unlikely(!vp)) {
		if (out) *out = NULL;
		return -1;
	}

	fr_cursor_prepend(&cursor, vp);
	if (out) *out = vp;

	return 0;
}

/** Return the first fr_pair_t matching the #fr_dict_attr_t or alloc a new fr_pair_t (and prepend)
 *
 * @param[in] ctx	to allocate any new #fr_pair_t in.
 * @param[out] out	Pair we allocated or found.  May be NULL if the caller doesn't
 *			care about manipulating the fr_pair_t.
 * @param[in,out] list	to search for attributes in or prepend attributes to.
 * @param[in] da	of attribute to locate or alloc.
 * @return
 *	- 1 if attribute already existed.
 *	- 0 if we allocated a new attribute.
 *	- -1 on failure.
 */
int fr_pair_update_by_da(TALLOC_CTX *ctx, fr_pair_t **out, fr_pair_list_t *list, fr_dict_attr_t const *da)
{
	fr_cursor_t	cursor;
	fr_pair_t	*vp;

	vp = fr_cursor_iter_by_da_init(&cursor, list, da);
	if (vp) {
		VP_VERIFY(vp);
		if (out) *out = vp;
		return 1;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (unlikely(!vp)) {
		if (out) *out = NULL;
		return -1;
	}

	fr_cursor_prepend(&cursor, vp);
	if (out) *out = vp;

	return 0;
}

/** Delete matching pairs from the specified list
 *
 * @param[in,out] list	to search for attributes in or prepend attributes to.
 * @param[in] da	to match.
 * @return
 *	- >0 the number of pairs deleted.
 *	- 0 if no pairs were deleted.
 */
int fr_pair_delete_by_da(fr_pair_list_t *list, fr_dict_attr_t const *da)
{
	fr_cursor_t	cursor;
	fr_pair_t	*vp;
	int		cnt;

	for (vp = fr_cursor_iter_by_da_init(&cursor, list, da), cnt = 0;
	     vp;
	     vp = fr_cursor_next(&cursor), cnt++) fr_cursor_free_item(&cursor);

	return cnt;
}

/** Remove fr_pair_t from a list
 *
 * @param[in] list	of value pairs to remove VP from.
 * @param[in] vp	to remove
 */
void fr_pair_delete(fr_pair_list_t *list, fr_pair_t const *vp)
{
	fr_cursor_t	cursor;
	fr_pair_t	*cvp;

	for (cvp = fr_cursor_init(&cursor, list);
	     cvp;
	     cvp = fr_cursor_next(&cursor)) {
		if (cvp == vp) {
			fr_cursor_free_item(&cursor);
			return;
		}
	}
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

	VP_VERIFY(my_a);
	VP_VERIFY(my_b);

	return fr_pointer_cmp(my_a->da, my_b->da);
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

	VP_VERIFY(my_a);
	VP_VERIFY(my_b);

	return (my_a->da->attr < my_b->da->attr) - (my_a->da->attr > my_b->da->attr);
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
		cmp = (da_a->attr > da_b->attr) - (da_a->attr < da_b->attr);
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
int fr_pair_cmp(fr_pair_t *a, fr_pair_t *b)
{
	if (!a) return -1;

	VP_VERIFY(a);
	if (b) VP_VERIFY(b);

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

			slen = regex_compile(NULL, &preg, a->xlat, talloc_array_length(a->xlat) - 1,
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
	fr_cursor_t a_cursor, b_cursor;
	fr_pair_t *a_p, *b_p;

	for (a_p = fr_cursor_init(&a_cursor, a), b_p = fr_cursor_init(&b_cursor, b);
	     a_p && b_p;
	     a_p = fr_cursor_next(&a_cursor), b_p = fr_cursor_next(&b_cursor)) {
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

static void _pair_list_sort_split(fr_pair_list_t *source, fr_pair_list_t *front, fr_pair_list_t *back)
{
	fr_pair_t *fast;
	fr_pair_t *slow;

	/*
	 *	Stopping condition - no more elements left to split
	 */
	if (!*source || !(*source)->next) {
		*front = *source;
		*back = NULL;

		return;
	}

	/*
	 *	Fast advances twice as fast as slow, so when it gets to the end,
	 *	slow will point to the middle of the linked list.
	 */
	slow = *source;
	fast = (*source)->next;

	while (fast) {
		fast = fast->next;
		if (fast) {
			slow = slow->next;
			fast = fast->next;
		}
	}

	*front = *source;
	*back = slow->next;
	slow->next = NULL;
}

static fr_pair_t *_pair_list_sort_merge(fr_pair_list_t *a, fr_pair_list_t *b, fr_cmp_t cmp)
{
	fr_pair_t *result = NULL;

	if (!*a) return *b;
	if (!*b) return *a;

	/*
	 *	Compare the fr_dict_attr_ts and tags
	 */
	if (cmp(*a, *b) <= 0) {
		result = *a;
		result->next = _pair_list_sort_merge(&(*a)->next, b, cmp);
	} else {
		result = *b;
		result->next = _pair_list_sort_merge(a, &(*b)->next, cmp);
	}

	return result;
}

/** Sort a linked list of fr_pair_ts using merge sort
 *
 * @note We use a merge sort (which is a stable sort), making this
 *	suitable for use on lists with things like EAP-Message
 *	fragments where the order of EAP-Message attributes needs to
 *	be maintained.
 *
 * @param[in,out] vps List of fr_pair_ts to sort.
 * @param[in] cmp to sort with
 */
void fr_pair_list_sort(fr_pair_list_t *vps, fr_cmp_t cmp)
{
	fr_pair_t *head = *vps;
	fr_pair_t *a;
	fr_pair_t *b;

	/*
	 *	If there's 0-1 elements it must already be sorted.
	 */
	if (!head || !head->next) return;

	_pair_list_sort_split(&head, &a, &b);	/* Split into sublists */
	fr_pair_list_sort(&a, cmp);		/* Traverse left */
	fr_pair_list_sort(&b, cmp);		/* Traverse right */

	/*
	 *	merge the two sorted lists together
	 */
	*vps = _pair_list_sort_merge(&a, &b, cmp);
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

	(void) fr_strerror();	/* Clear any existing messages */

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
	fr_cursor_t filter_cursor;
	fr_cursor_t list_cursor;

	fr_pair_t *check, *match;

	if (!*filter && !*list) {
		return true;
	}

	/*
	 *	This allows us to verify the sets of validate and reply are equal
	 *	i.e. we have a validate rule which matches every reply attribute.
	 *
	 *	@todo this should be removed one we have sets and lists
	 */
	fr_pair_list_sort(filter, fr_pair_cmp_by_da);
	fr_pair_list_sort(list, fr_pair_cmp_by_da);

	check = fr_cursor_init(&filter_cursor, filter);
	match = fr_cursor_init(&list_cursor, list);
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

		check = fr_cursor_next(&filter_cursor);
		match = fr_cursor_next(&list_cursor);
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
	fr_cursor_t	filter_cursor;
	fr_cursor_t	list_cursor;

	fr_pair_t *check, *last_check = NULL, *match = NULL;

	if (!*filter && !*list) {
		return true;
	}

	/*
	 *	This allows us to verify the sets of validate and reply are equal
	 *	i.e. we have a validate rule which matches every reply attribute.
	 *
	 *	@todo this should be removed one we have sets and lists
	 */
	fr_pair_list_sort(filter, fr_pair_cmp_by_da);
	fr_pair_list_sort(list, fr_pair_cmp_by_da);

	fr_cursor_init(&list_cursor, list);
	for (check = fr_cursor_init(&filter_cursor, filter);
	     check;
	     check = fr_cursor_next(&filter_cursor)) {
		/*
		 *	Were processing check attributes of a new type.
		 */
		if (!ATTRIBUTE_EQ(last_check, check)) {
			/*
			 *	Record the start of the matching attributes in the pair list
			 *	For every other operator we require the match to be present
			 */
			match = fr_cursor_filter_next(&list_cursor, fr_pair_matches_da, check->da);
			if (!match) {
				if (check->op == T_OP_CMP_FALSE) continue;
				goto mismatch;
			}

			fr_cursor_init(&list_cursor, &match);
			last_check = check;
		}

		/*
		 *	Now iterate over all attributes of the same type.
		 */
		for (match = fr_cursor_head(&list_cursor);
		     ATTRIBUTE_EQ(match, check);
		     match = fr_cursor_next(&list_cursor)) {
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
	fr_cursor_t	src, dst, tmp;

	fr_pair_t	*head = NULL;
	fr_pair_t	*vp;
	int		cnt = 0;

	fr_cursor_talloc_init(&tmp, &head, fr_pair_t);
	for (vp = fr_cursor_talloc_init(&src, from, fr_pair_t);
	     vp;
	     vp = fr_cursor_next(&src), cnt++) {
		VP_VERIFY(vp);
		vp = fr_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(&head);
			return -1;
		}
		fr_cursor_append(&tmp, vp); /* fr_pair_list_copy sets next pointer to NULL */
	}

	if (!*to) {	/* Fast Path */
		*to = head;
	} else {
		fr_cursor_talloc_init(&dst, to, fr_pair_t);
		fr_cursor_head(&tmp);
		fr_cursor_tail(&dst);
		fr_cursor_merge(&dst, &tmp);
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
			    fr_pair_list_t *from, fr_dict_attr_t const *da, unsigned int count)
{
	fr_cursor_t	src, dst, tmp;

	fr_pair_t	*head = NULL;
	fr_pair_t	*vp;
	unsigned int	cnt = 0;

	if (count == 0) count = UINT_MAX;

	if (unlikely(!da)) {
		fr_strerror_printf("No search attribute provided");
		return -1;
	}

	fr_cursor_talloc_init(&tmp, &head, fr_pair_t);
	for (vp = fr_cursor_iter_by_da_init(&src, from, da);
	     vp && (cnt < count);
	     vp = fr_cursor_next(&src), cnt++) {
		VP_VERIFY(vp);
		vp = fr_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(&head);
			return -1;
		}
		fr_cursor_append(&tmp, vp); /* fr_pair_list_copy sets next pointer to NULL */
	}

	if (!*to) {	/* Fast Path */
		*to = head;
	} else {
		fr_cursor_talloc_init(&dst, to, fr_pair_t);
		fr_cursor_head(&tmp);
		fr_cursor_merge(&dst, &tmp);
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
				  fr_pair_list_t *from, fr_dict_attr_t const *parent_da, unsigned int count)
{
	fr_cursor_t	src, dst, tmp;

	fr_pair_t	*head = NULL;
	fr_pair_t	*vp;
	unsigned int	cnt = 0;

	if (count == 0) count = UINT_MAX;

	if (unlikely(!parent_da)) {
		fr_strerror_printf("No search attribute provided");
		return -1;
	}

	fr_cursor_talloc_init(&tmp, &head, fr_pair_t);
	for (vp = fr_cursor_iter_by_ancestor_init(&src, from, parent_da);
	     vp && (cnt < count);
	     vp = fr_cursor_next(&src), cnt++) {
		VP_VERIFY(vp);
		vp = fr_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(&head);
			return -1;
		}
		fr_cursor_append(&tmp, vp); /* fr_pair_list_copy sets next pointer to NULL */
	}

	if (!*to) {	/* Fast Path */
		*to = head;
	} else {
		fr_cursor_talloc_init(&dst, to, fr_pair_t);
		fr_cursor_head(&tmp);
		fr_cursor_merge(&dst, &tmp);
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
	fr_cursor_t cursor;

	switch (vp->da->type) {
	default:
		fr_value_box_clear_value(&vp->data);
		break;

	case FR_TYPE_STRUCTURAL:
		if (!vp->vp_group) return;

		for (child = fr_cursor_init(&cursor, &vp->vp_group);
		     child;
		     child = fr_cursor_next(&cursor)) {
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
	if (!fr_cond_assert(src->data.type != FR_TYPE_INVALID)) return -1;

	if (dst->data.type != FR_TYPE_INVALID) fr_value_box_clear(&dst->data);
	fr_value_box_copy(dst, &dst->data, &src->data);

	return 0;
}

/** Convert string value to native attribute value
 *
 * @param[in] vp	to assign value to.
 * @param[in] value	string to convert. Binary safe for variable
 *			length values if len is provided.
 * @param[in] inlen	may be < 0 in which case strlen(len) is used
 *			to determine length, else inlen should be the
 *			length of the string or sub string to parse.
 * @param[in] quote	character used set unescape mode.  @see fr_value_str_unescape.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_from_str(fr_pair_t *vp, char const *value, ssize_t inlen, char quote, bool tainted)
{
	fr_type_t type;

	if (!value) return -1;

	type = vp->da->type;

	/*
	 *	This is not yet supported because the rest of the APIs
	 *	to parse pair names, etc. don't yet enforce "inlen".
	 *	This is likely not a problem in practice, but we
	 *	haven't yet audited the uses of this function for that
	 *	behavior.
	 */
	switch (type) {
	case FR_TYPE_STRUCTURAL:
		fr_strerror_printf("Attributes of type '%s' are not yet supported",
				   fr_table_str_by_value(fr_value_box_type_table, type, "<INVALID>"));
		return -1;

	default:
		break;
	}

	/*
	 *	We presume that the input data is from a double quoted
	 *	string, and needs unescaping
	 */
	if (fr_value_box_from_str(vp, &vp->data, &type, vp->da, value, inlen, quote, tainted) < 0) return -1;

	/*
	 *	If we parsed to a different type than the DA associated with
	 *	the fr_pair_t we now need to fixup the DA.
	 *
	 *	This is for types COMBO_IP.  fr_pair_ts have a fixed
	 *	data type, and not a polymorphic one.  So instead of
	 *	hacking polymorphic crap through the entire server
	 *	code, we have this hack to make them static.
	 */
	if (type != vp->da->type) {
		fr_dict_attr_t const *da;

		da = fr_dict_attr_by_type(vp->da, type);
		if (!da) {
			fr_strerror_printf("Cannot find %s variant of attribute \"%s\"",
					   fr_table_str_by_value(fr_value_box_type_table, type, "<INVALID>"), vp->da->name);
			return -1;
		}
		vp->da = da;
		vp->data.enumv = da;
	}
	vp->type = VT_DATA;

	VP_VERIFY(vp);

	return 0;
}

/** Copy data into an "string" data type.
 *
 * @note vp->da must be of type FR_TYPE_STRING.
 *
 * @param[in,out] vp to update
 * @param[in] src data to copy
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_strdup(fr_pair_t *vp, char const *src)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_STRING)) return -1;

	fr_value_box_clear(&vp->data);	/* Free any existing buffers */
	ret = fr_value_box_strdup(vp, &vp->data, vp->da, src, false);
	if (ret == 0) {
		vp->type = VT_DATA;
		VP_VERIFY(vp);
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

	vp->type = VT_DATA;
	VP_VERIFY(vp);

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
		vp->type = VT_DATA;
		VP_VERIFY(vp);
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
		vp->type = VT_DATA;
		VP_VERIFY(vp);
		return 0;
	}

	return -1;
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
		vp->type = VT_DATA;
		VP_VERIFY(vp);
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
		vp->type = VT_DATA;
		VP_VERIFY(vp);
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
		vp->type = VT_DATA;
		VP_VERIFY(vp);
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
		vp->type = VT_DATA;
		VP_VERIFY(vp);
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
	vp->type = VT_DATA;
	VP_VERIFY(vp);

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
		vp->type = VT_DATA;
		VP_VERIFY(vp);
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
		vp->type = VT_DATA;
		VP_VERIFY(vp);
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
		vp->type = VT_DATA;
		VP_VERIFY(vp);
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
		vp->type = VT_DATA;
		VP_VERIFY(vp);
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
		vp->type = VT_DATA;
		VP_VERIFY(vp);
	}

	return ret;
}

/** Copy data into an "octets" data type.
 *
 * @note Will clear existing values (including buffers).
 *
 * @param[in,out] vp	to update
 * @param[in] src	data to copy
 * @param[in] size	of the data.
 * @param[in] tainted	Whether the value came from a trusted source.
 * @return
 *      - 0 on success.
 *	- -1 on failure.
 */
int fr_pair_value_memdup(fr_pair_t *vp, uint8_t const *src, size_t size, bool tainted)
{
	int ret;

	if (!fr_cond_assert(vp->da->type == FR_TYPE_OCTETS)) return -1;

	fr_value_box_clear(&vp->data);	/* Free any existing buffers */
	ret = fr_value_box_memdup(vp, &vp->data, vp->da, src, size, tainted);
	if (ret == 0) {
		vp->type = VT_DATA;
		VP_VERIFY(vp);
	}

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
		vp->type = VT_DATA;
		VP_VERIFY(vp);
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
	vp->type = VT_DATA;
	VP_VERIFY(vp);

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
	vp->type = VT_DATA;
	VP_VERIFY(vp);

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
		vp->type = VT_DATA;
		VP_VERIFY(vp);
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
		vp->type = VT_DATA;
		VP_VERIFY(vp);
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
	fr_dict_enum_t const	*enumv = NULL;

	switch (vp->vp_type) {
	case FR_TYPE_NUMERIC:
		break;

	default:
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
	fr_dict_enum_t const	*dv;

	if (!out || !vp ) return -1;

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
void fr_pair_verify(char const *file, int line, fr_pair_t const *vp)
{
	if (!vp) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t pointer was NULL", file, line);
	}

	(void) talloc_get_type_abort_const(vp, fr_pair_t);

	if (!vp->da) {
		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t da pointer was NULL", file, line);
	}

	fr_dict_verify(file, line, vp->da);
	if (vp->data.enumv) fr_dict_verify(file, line, vp->data.enumv);

	if (vp->vp_ptr) switch (vp->vp_type) {
	case FR_TYPE_OCTETS:
	{
		size_t len;
		TALLOC_CTX *parent;

		if (!talloc_get_type(vp->vp_ptr, uint8_t)) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" data buffer type should be "
					     "uint8_t but is %s\n", file, line, vp->da->name, talloc_get_name(vp->vp_ptr));
		}

		len = talloc_array_length(vp->vp_octets);
		if (vp->vp_length > len) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" length %zu is greater than "
					     "uint8_t data buffer length %zu\n", file, line, vp->da->name, vp->vp_length, len);
		}

		parent = talloc_parent(vp->vp_ptr);
		if (parent != vp) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t \"%s\" char buffer is not "
					     "parented by fr_pair_t %p, instead parented by %p (%s)\n",
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
	       if (!vp->vp_group) break;

	       fr_pair_list_verify(file, line, vp, &vp->vp_group);
	       break;

	default:
		break;
	}

	if (vp->da->flags.is_unknown || vp->da->flags.is_raw) {
		(void) talloc_get_type_abort_const(vp->da, fr_dict_attr_t);
	} else {
		fr_dict_attr_t const *da;

		da = vp->da;

		if (da->type == FR_TYPE_COMBO_IP_ADDR) {
			da = fr_dict_attr_by_type(vp->da, vp->da->type);
			if (!da) {
				fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t attribute %p \"%s\" "
						     "variant (%s) not found in global dictionary",
						     file, line, vp->da, vp->da->name,
						     fr_table_str_by_value(fr_value_box_type_table,
						     			   vp->da->type, "<INVALID>"));
			}
		}

		if (da != vp->da) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t "
					     "dictionary pointer %p \"%s\" (%s) "
					     "and global dictionary pointer %p \"%s\" (%s) differ",
					     file, line, vp->da, vp->da->name,
					     fr_table_str_by_value(fr_value_box_type_table, vp->da->type, "<INVALID>"),
					     da, da->name,
					     fr_table_str_by_value(fr_value_box_type_table, da->type, "<INVALID>"));
		}
	}

	if (vp->da->flags.is_raw || vp->da->flags.is_unknown) {
		if ((vp->da->parent->type != FR_TYPE_VSA) && (vp->data.type != FR_TYPE_VSA) && (vp->data.type != FR_TYPE_OCTETS)) {
			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t (raw/unknown) attribute %p \"%s\" "
					     "data type incorrect.  Expected %s, got %s",
					     file, line, vp->da, vp->da->name,
					     fr_table_str_by_value(fr_value_box_type_table, FR_TYPE_OCTETS, "<INVALID>"),
					     fr_table_str_by_value(fr_value_box_type_table, vp->data.type, "<INVALID>"));
		}
	} else if (vp->da->type != vp->data.type) {
		char data_type_int[10], da_type_int[10];

		snprintf(data_type_int, sizeof(data_type_int), "%i", vp->data.type);
		snprintf(da_type_int, sizeof(da_type_int), "%i", vp->da->type);

		fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: fr_pair_t attribute %p \"%s\" "
				     "data type (%s) does not match da type (%s)",
				     file, line, vp->da, vp->da->name,
				     fr_table_str_by_value(fr_value_box_type_table, vp->data.type, data_type_int),
				     fr_table_str_by_value(fr_value_box_type_table, vp->da->type, da_type_int));
	}
}

/*
 *	Verify a pair list
 */
void fr_pair_list_verify(char const *file, int line, TALLOC_CTX const *expected, fr_pair_list_t const *vps)
{
	fr_cursor_t		slow_cursor, fast_cursor;
	fr_pair_t		*slow, *fast;
	TALLOC_CTX		*parent;

	if (!*vps) return;	/* Fast path */

	fr_cursor_init(&fast_cursor, vps);

	for (slow = fr_cursor_init(&slow_cursor, vps), fast = fr_cursor_init(&fast_cursor, vps);
	     slow && fast;
	     slow = fr_cursor_next(&fast_cursor), fast = fr_cursor_next(&fast_cursor)) {
		VP_VERIFY(slow);

		/*
		 *	Advances twice as fast as slow...
		 */
		fast = fr_cursor_next(&fast_cursor);
		fr_fatal_assert_msg(fast != slow,
				    "CONSISTENCY CHECK FAILED %s[%u]:  Looping list found.  Fast pointer hit "
				    "slow pointer at \"%s\"",
				    file, line, slow->da->name);

		parent = talloc_parent(slow);
		if (expected && (parent != expected)) {
			fr_log_talloc_report(expected);
			if (parent) fr_log_talloc_report(parent);

			fr_fatal_assert_fail("CONSISTENCY CHECK FAILED %s[%u]: Expected fr_pair_t \"%s\" to be parented "
					     "by %p (%s), instead parented by %p (%s)\n",
					     file, line, slow->da->name,
					     expected, talloc_get_name(expected),
					     parent, parent ? talloc_get_name(parent) : "NULL");
		}
	}
}
#endif

/** Mark up a list of VPs as tainted.
 *
 */
void fr_pair_list_tainted(fr_pair_list_t *vps)
{
	fr_pair_t	*vp;
	fr_cursor_t	cursor;

	if (!*vps) return;

	for (vp = fr_cursor_init(&cursor, vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		VP_VERIFY(vp);

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


/*
 *	Parse a set of VPs from a value box.
 */
fr_pair_t *fr_pair_list_afrom_box(TALLOC_CTX *ctx, fr_dict_t const *dict, fr_value_box_t *box)
{
	int comma = 0;
	char *p, *end, *last_comma = NULL;
	fr_pair_t *vps;

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

	vps = NULL;
	if (fr_pair_list_afrom_str(ctx, dict, box->vb_strvalue, &vps) == T_INVALID) {
		return NULL;
	}

	/*
	 *	Mark the attributes as tainted.
	 */
	fr_pair_list_tainted(&vps);
	return vps;
}

/** Evaluation function for matching if vp matches a given da
 *
 * Can be used as a filter function for fr_cursor_filter_next()
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
