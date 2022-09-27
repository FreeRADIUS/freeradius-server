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
 * @brief #fr_pair_t template functions
 * @file src/lib/server/tmpl_cursor.c
 *
 * @ingroup AVP
 *
 * @copyright 2020-2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/server/exec.h>
#include <freeradius-devel/server/exec_legacy.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/edit.h>

static inline CC_HINT(always_inline)
void _tmpl_cursor_pool_init(tmpl_dcursor_ctx_t *cc)
{
	if (!cc->pool) MEM(cc->pool = talloc_pool(cc->ctx, sizeof(tmpl_dcursor_nested_t) * 5));
}

/** Traverse a list of attributes
 *
 * A dcursor iterator function for matching attributes
 *
 * @param[in] list	being traversed.
 * @param[in] curr	item in the list to start tests from.
 * @param[in] uctx	Context for evaluation - in this instance a #tmpl_nested_dcursor_t
 * @return
 *	- the next matching attribute
 *	- NULL if none found
 */
static void *_tmpl_cursor_child_next(fr_dlist_head_t *list, void *curr, void *uctx)
{
	tmpl_dcursor_nested_t	*ns = uctx;
	fr_pair_t		*vp = curr;

	/*
	 *	Only applies to TMPL_TYPE_LIST - remove when that is gone.
	 */
	if ((!ns->ar) || (!ns->ar->ar_da)) return fr_dlist_next(list, curr);

	while ((vp = fr_dlist_next(list, vp))) {
		if (fr_dict_attr_cmp(ns->ar->ar_da, vp->da) == 0) break;
	}

	return vp;
}

static inline CC_HINT(always_inline) void tmpl_cursor_nested_push(tmpl_dcursor_ctx_t *cc, tmpl_dcursor_nested_t *ns)
{
	fr_dlist_insert_tail(&cc->nested, ns);
}

static inline CC_HINT(always_inline) void tmpl_cursor_nested_pop(tmpl_dcursor_ctx_t *cc)
{
	tmpl_dcursor_nested_t *ns = fr_dlist_pop_tail(&cc->nested);

	if (ns != &cc->leaf) talloc_free(ns);
}

/** Initialise the evaluation context for traversing a group attribute
 *
 */
static inline CC_HINT(always_inline)
void _tmpl_cursor_pair_init(TALLOC_CTX *list_ctx, fr_pair_list_t *list, tmpl_attr_t const *ar, tmpl_dcursor_ctx_t *cc)
{
	tmpl_dcursor_nested_t *ns;

	if (tmpl_attr_list_next(&cc->vpt->data.attribute.ar, ar)) {
		_tmpl_cursor_pool_init(cc);
		MEM(ns = talloc(cc->pool, tmpl_dcursor_nested_t));
	} else {
		ns = &cc->leaf;
	}

	*ns = (tmpl_dcursor_nested_t){
		.ar = ar,
		.list_ctx = list_ctx
	};
	fr_pair_dcursor_iter_init(&ns->cursor, list, _tmpl_cursor_child_next, ns);

	tmpl_cursor_nested_push(cc, ns);
}

/** Evaluates, then, sometimes, pops evaluation contexts from the tmpl stack
 *
 * To pop or not to pop is determined by whether evaluating the context again
 * would/should/could produce another fr_pair_t.
 *
 * @param[in] curr	The pair to evaluate.
 * @param[in] cc	Tracks state between cursor calls.
 * @return the vp evaluated.
 */
static inline CC_HINT(always_inline)
fr_pair_t *_tmpl_cursor_eval(fr_pair_t *curr, tmpl_dcursor_ctx_t *cc)
{
	tmpl_attr_t const	*ar;
	tmpl_dcursor_nested_t	*ns;
	fr_pair_t		*iter = curr, *vp;
	bool			pop = false;

	ns = fr_dlist_tail(&cc->nested);
	ar = ns->ar;
	vp = fr_dcursor_current(&ns->cursor);

	if (ar) switch (ar->ar_num) {
	/*
	 *	Get the first instance
	 */
	case NUM_UNSPEC:
		pop = true;
		break;

	/*
	 *	Get all instances
	 */
	case NUM_ALL:
	case NUM_COUNT:
	all_inst:
		if (!vp) pop = true;	/* pop only when we're done */
		fr_dcursor_next(&ns->cursor);
		break;

	/*
	 *	Get the last instance
	 */
	case NUM_LAST:
		while ((iter = fr_dcursor_next(&ns->cursor))) {
			vp = iter;
		}
		pop = true;
		break;

	/*
	 *	Get the n'th instance
	 */
	default:
	{
		int16_t		i = 0;

		while ((i++ < ar->ar_num) && vp) vp = fr_dcursor_next(&ns->cursor);
		pop = true;
	}
		break;
	} else goto all_inst;	/* Used for TMPL_TYPE_LIST */

	/*
	 *	If no pair was found and there is a fill
	 *	callback, call that, depending on the suffix
	 */
	if (!vp && cc->build && ar) switch (ar->ar_num) {
	case NUM_UNSPEC:
	case NUM_LAST:
	case 0:
		vp = cc->build(ns->list_ctx, &ns->cursor, ar->da, cc->uctx);
		break;

	default:
		break;
	}

	if (pop) tmpl_cursor_nested_pop(cc);

	return vp;
}

static void *_tmpl_cursor_next(UNUSED fr_dlist_head_t *list, void *curr, void *uctx)
{
	tmpl_dcursor_ctx_t	*cc = uctx;
	tmpl_t const		*vpt = cc->vpt;

	fr_pair_t		*vp;

	switch (vpt->type) {
	case TMPL_TYPE_ATTR:
	{
		tmpl_attr_t const	*ar = NULL;
		tmpl_dcursor_nested_t	*ns = NULL;

		/*
		 *	- Continue until there are no evaluation contexts
		 *	- Push a evaluation context if evaluating the head of the
		 *	  stack yields a VP and we're not at the deepest attribute
		 *	  reference.
		 *	- Return if we have a VP and there are no more attribute
		 *	  references to push, i.e. we're at the deepest attribute
		 *	  reference.
		 */
		while ((ns = fr_dlist_tail(&cc->nested))) {
			ar = ns->ar;
			vp = _tmpl_cursor_eval(curr, cc);
			if (!vp) continue;

			ar = tmpl_attr_list_next(&vpt->data.attribute.ar, ar);
			if (ar) {
				fr_pair_list_t		*list_head;

				list_head = &vp->vp_group;
				_tmpl_cursor_pair_init(vp, list_head, ar, cc);
				curr = fr_pair_list_head(list_head);
				continue;
			}

			return vp;
		}

	null_result:
		return NULL;
	}

	/*
	 *	Hacks for evaluating lists
	 *	Hopefully this tmpl type goes away soon...
	 */
	case TMPL_TYPE_LIST:
		if (!fr_dlist_tail(&cc->nested)) goto null_result;	/* end of list */

		vp = _tmpl_cursor_eval(curr, cc);
		if (!vp) goto null_result;

		return vp;

	default:
		fr_assert(0);
	}

	return NULL;
}

#ifdef TMPL_DCURSOR_MOD
static int tmpl_dcursor_insert(UNUSED fr_dlist_head_t *list, void *to_insert, void *uctx)
{
	tmpl_dcursor_ctx_t *cc = uctx;
	tmpl_dcursor_nested_t *ns = fr_dlist_tail(&cc->nested);

	if (!ns) return 0;

	fr_dcursor_insert(&ns->cursor, to_insert);
	return 0;
}

static int tmpl_dcursor_remove(UNUSED fr_dlist_head_t *list, void *to_remove, void *uctx)
{
	tmpl_dcursor_ctx_t *cc = uctx;
	tmpl_dcursor_nested_t *ns = fr_dlist_tail(&cc->nested);
	void *current;

	if (!ns) return 0;

	current = fr_dcursor_current(&ns->cursor);
	if (current == to_remove) {
		fr_dcursor_remove(&ns->cursor);
	} else {
		fr_dcursor_set_current(&ns->cursor, to_remove);
		fr_dcursor_remove(&ns->cursor);
		fr_dcursor_set_current(&ns->cursor, current);
	}
	return 0;
}
#endif

/** Initialise a #fr_dcursor_t at the specified point in a pair tree
 *
 * This makes iterating over the one or more #fr_pair_t specified by a #tmpl_t
 * significantly easier.
 *
 * @param[out] err		May be NULL if no error code is required.
 *				Will be set to:
 *				- 0 on success.
 *				- -1 if no matching #fr_pair_t could be found.
 *				- -2 if list could not be found (doesn't exist in current #request_t).
 *				- -3 if context could not be found (no parent #request_t available).
 * @param[in] ctx		to make temporary allocations under.
 * @param[in] cc		to initialise.  Tracks evaluation state.
 *				Must be explicitly cleared with tmpl_cursor_state_clear
 *				otherwise we will leak memory.
 * @param[in] cursor		to store iterator position.
 * @param[in] request		the current request.
 * @param[in] list		a nested list to start evaluating from.
 *				May be the child list of a pair in the request's pair tree.
 * @param[in] vpt		specifying the #fr_pair_t type or list to iterate over.
 * @return
 *	- First #fr_pair_t specified by the #tmpl_t.
 *	- NULL if no matching #fr_pair_t found, and NULL on error.
 *
 * @see tmpl_cursor_next
 */
fr_pair_t *tmpl_dcursor_init_relative(int *err, TALLOC_CTX *ctx, tmpl_dcursor_ctx_t *cc,
				      fr_dcursor_t *cursor,
				      request_t *request, fr_pair_t *list, tmpl_t const *vpt,
				      tmpl_dcursor_build_t build, void *uctx)
{
	fr_pair_t		*vp = NULL;

	TMPL_VERIFY(vpt);

	/*
	 *	Initialise the temporary cursor context
	 */
	*cc = (tmpl_dcursor_ctx_t){
		.vpt = vpt,
		.ctx = ctx,
		.request = request,
		.list = &list->vp_group,
		.build = build,
		.uctx = uctx
	};
	fr_dlist_init(&cc->nested, tmpl_dcursor_nested_t, entry);

	/*
	 *	Prime the stack!
	 */
	switch (vpt->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_LIST:
		_tmpl_cursor_pair_init(list, cc->list, tmpl_attr_list_head(&vpt->data.attribute.ar), cc);
		break;

	default:
		fr_assert(0);
		break;
	}

	/*
	 *	Get the first entry from the tmpl
	 */
#ifndef TMPL_DCURSOR_MOD
	vp = fr_pair_dcursor_iter_init(cursor, cc->list, _tmpl_cursor_next, cc);
#else
	vp = fr_dcursor_iter_mod_init(cursor, fr_pair_list_to_dlist(cc->list), _tmpl_cursor_next, NULL, cc, tmpl_dcursor_insert, tmpl_dcursor_remove, cc);
#endif
	if (!vp) {
		if (err) {
			*err = -1;
			if (tmpl_is_list(vpt)) {
				fr_strerror_printf("List \"%s\" is empty", vpt->name);
			} else {
				fr_strerror_printf("No matching \"%s\" pairs found", tmpl_da(vpt)->name);
			}
		}
		return NULL;
	}

	return vp;
}

/** Initialise a #fr_dcursor_t to the #fr_pair_t specified by a #tmpl_t
 *
 * This makes iterating over the one or more #fr_pair_t specified by a #tmpl_t
 * significantly easier.
 *
 * @param[out] err		May be NULL if no error code is required.
 *				Will be set to:
 *				- 0 on success.
 *				- -1 if no matching #fr_pair_t could be found.
 *				- -2 if list could not be found (doesn't exist in current #request_t).
 *				- -3 if context could not be found (no parent #request_t available).
 * @param[in] ctx		to make temporary allocations under.
 * @param[in] cc		to initialise.  Tracks evaluation state.
 *				Must be explicitly cleared with tmpl_cursor_state_clear
 *				otherwise we will leak memory.
 * @param[in] cursor		to store iterator position.
 * @param[in] request		The current #request_t.
 * @param[in] vpt		specifying the #fr_pair_t type or list to iterate over.
 * @param[in] build		Callback to build missing pairs.
 * @param[in] uctx		for building new pairs.
 * @return
 *	- First #fr_pair_t specified by the #tmpl_t.
 *	- NULL if no matching #fr_pair_t found, and NULL on error.
 *
 * @see tmpl_cursor_next
 */
fr_pair_t *_tmpl_dcursor_init(int *err, TALLOC_CTX *ctx, tmpl_dcursor_ctx_t *cc,
			      fr_dcursor_t *cursor, request_t *request, tmpl_t const *vpt,
			      tmpl_dcursor_build_t build, void *uctx)
{
	fr_pair_t		*list;

	fr_assert(tmpl_is_attr(vpt) || tmpl_is_list(vpt));

	if (err) *err = 0;

	/*
	 *	Navigate to the correct request context
	 */
	if (tmpl_request_ptr(&request, tmpl_request(vpt)) < 0) {
		if (err) *err = -3;
	error:
		memset(cc, 0, sizeof(*cc));	/* so tmpl_dcursor_clear doesn't explode */
		return NULL;
	}

	/*
	 *	Get the right list in the specified context
	 */
	if (!vpt->rules.attr.list_as_attr) {
		list = tmpl_get_list(request, vpt);
		if (!list) {
			fr_strerror_printf("List \"%s\" not available in this context",
					   fr_table_str_by_value(pair_list_table, tmpl_list(vpt), "<INVALID>"));
			if (err) *err = -2;
			goto error;
		}
	} else {
		list = request->pair_root;
	}

	return tmpl_dcursor_init_relative(err, ctx, cc, cursor, request, list, vpt, build, uctx);
}

/** Clear any temporary state allocations
 *
 */
void tmpl_dcursor_clear(tmpl_dcursor_ctx_t *cc)
{
	/*
	 *	If the pool wasn't created, nothing was talloc'd which
	 *	needs freeing.
	 */
	if (!cc->pool) return;

	fr_dlist_remove(&cc->nested, &cc->leaf);	/* Noop if leaf isn't inserted */
	fr_dlist_talloc_free(&cc->nested);

	TALLOC_FREE(cc->pool);
}

/** Simple pair building callback for use with tmpl_dcursors
 *
 * Which always appends the new pair to the tail of the list
 * since it is only called when no matching pairs were found when
 * walking the list.
 *
 * @param[in] parent		to allocate new pair within.
 * @param[in,out] cursor	to append new pair to.
 * @param[in] da		of new pair.
 * @param[in] uctx		unused.
 * @return
 *	- newly allocated #fr_pair_t.
 *	- NULL on error.
 */
fr_pair_t *tmpl_dcursor_pair_build(fr_pair_t *parent, fr_dcursor_t *cursor, fr_dict_attr_t const *da, UNUSED void *uctx)
{
	fr_pair_t *vp;
	vp = fr_pair_afrom_da(parent, da);
	if (vp) fr_dcursor_append(cursor, vp);
	return vp;
}

#define EXTENT_ADD(_out, _ar, _list_ctx, _list) \
	do { \
		tmpl_attr_extent_t	*_extent; \
		MEM(_extent = talloc(ctx, tmpl_attr_extent_t)); \
		*_extent = (tmpl_attr_extent_t){ \
			.ar = _ar,	\
			.list_ctx = _list_ctx, \
			.list = _list	\
		}; \
		fr_dlist_insert_tail(_out, _extent); \
	} while (0)

/** Determines points where the reference list extends beyond the current pair tree
 *
 * If a particular branch in the VP hierarchy is incomplete, i.e. the chain of attribute
 * refers to nodes deeper than the nodes currently in the tree, then we return the
 * deepest point node in the tree which matched, and the ar that we failed to evaluate.
 *
 * If the reference list resolves to one or more structural pairs, return those as well.
 *
 * This function can be used for a number of different operations, but it's most useful
 * for determining insertion points for new attributes, or determining which attributes
 * need to be updated.
 *
 * @param[in] ctx				to allocate.  It's recommended to pass a pool with space
 *						for at least five extent structures.
 * @param[out] existing				List of extents we discovered by evaluating all
 *						attribute references. May be NULL.
 * @param[out] to_build 			List of extents that need building out, i.e. references
 *						extend beyond pairs. May be NULL.
 * @param[in] request				The current #request_t.
 * @param[in] vpt				specifying the #fr_pair_t type to retrieve or create.
 *						Must be #TMPL_TYPE_ATTR.
 * @return
 *	- 0 on success a pair was found.
 *	- -2 if list could not be found (doesn't exist in current #request_t).
 *	- -3 if context could not be found (no parent #request_t available).
 */
int tmpl_extents_find(TALLOC_CTX *ctx,
		      fr_dlist_head_t *existing, fr_dlist_head_t *to_build,
		      request_t *request, tmpl_t const *vpt)
{
	fr_pair_t		*curr = NULL;
	fr_pair_list_t		*list_head;

	TALLOC_CTX		*list_ctx = NULL;

	tmpl_dcursor_ctx_t	cc;
	tmpl_dcursor_nested_t	*ns = NULL;

	tmpl_attr_t const	*ar = NULL;

	TMPL_VERIFY(vpt);

	fr_assert(tmpl_is_attr(vpt) || tmpl_is_list(vpt));

	/*
	 *	Navigate to the correct request context
	 */
	if (tmpl_request_ptr(&request, tmpl_request(vpt)) < 0) return -3;

	if (!vpt->rules.attr.list_as_attr) {
		/*
		 *	Get the right list in the specified context
		 */
		list_head = tmpl_list_head(request, tmpl_list(vpt));
		if (!list_head) {
			fr_strerror_printf("List \"%s\" not available in this context",
					   fr_table_str_by_value(pair_list_table, tmpl_list(vpt), "<INVALID>"));
			return -2;
		}
		list_ctx = tmpl_list_ctx(request, tmpl_list(vpt));
	} else {
		list_head = &request->pair_root->vp_group;
		list_ctx = request->pair_root;
	}

	/*
	 *	If it's a list, just return the list head
	 */
	if (vpt->type == TMPL_TYPE_LIST) {
	do_list:
		if (existing) EXTENT_ADD(existing, NULL, list_ctx, list_head);
		return 0;
	}

	/*
	 *	If it's a leaf skip all the expensive
	 *      initialisation and just return the list
	 *	it's part of.
	 *
	 *	This is only needed because lists are
	 *	treated specially.  Once lists are groups
	 *	this can be removed.
	 */
	ar = tmpl_attr_list_head(&vpt->data.attribute.ar);
	switch (ar->ar_da->type) {
	case FR_TYPE_STRUCTURAL:
		break;

	default:
		goto do_list;
	}

	/*
	 *	Initialise the temporary cursor context
	 */
	cc = (tmpl_dcursor_ctx_t){
		.vpt = vpt,
		.ctx = ctx,
		.request = request,
		.list = list_head
	};
	fr_dlist_init(&cc.nested, tmpl_dcursor_nested_t, entry);

	/*
	 *	Prime the stack!
	 */
	_tmpl_cursor_pair_init(list_ctx, cc.list, tmpl_attr_list_head(&vpt->data.attribute.ar), &cc);

	/*
	 *	- Continue until there are no evaluation contexts
	 *	- Push a evaluation context if evaluating the head of the
	 *	  stack yields a VP and we're not at the deepest attribute
	 *	  reference.
	 *	- Return if we have a VP and there are no more attribute
	 *	  references to push, i.e. we're at the deepest attribute
	 *	  reference.
	 */
	curr = fr_pair_list_head(list_head);
	while ((ns = fr_dlist_tail(&cc.nested))) {
		tmpl_attr_t const *n_ar;

		list_ctx = ns->list_ctx;
		ar = ns->ar;
		curr = _tmpl_cursor_eval(curr, &cc);
		if (!curr) {
			/*
			 *	References extend beyond current
			 *	pair tree.
			 */
			if (!ar->resolve_only && to_build) EXTENT_ADD(to_build, ar, list_ctx, list_head);
			continue;	/* Rely on _tmpl_cursor_eval popping the stack */
		}

		/*
		 *	Evaluate the next reference
		 */
		n_ar = tmpl_attr_list_next(&vpt->data.attribute.ar, ar);
		if (n_ar) {
			ar = n_ar;
			list_head = &curr->vp_group;
			list_ctx = curr;	/* Allocations are under the group */
			_tmpl_cursor_pair_init(list_ctx, list_head, ar, &cc);
			curr = fr_pair_list_head(list_head);
			continue;
		}

		/*
		 *	Only reached when we can't find an exiting
		 *	part of the pair_root to keep walking.
		 *
		 *	VP tree may extend beyond the reference.
		 *      If the reference was structural, record this
		 *	as an extent.
		 */
		if (existing) EXTENT_ADD(existing, NULL, list_ctx, list_head);

		break;
	}

	return 0;
}

/** Allocate interior pairs
 *
 * Builds out the pair tree to the point where leaf attributes can be added
 *
 * @param[out] existing	List to add built out attributes to.
 * @param[in] to_build	List to remove attributes from.
 * @param[in] vpt	We are evaluating.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
int tmpl_extents_build_to_leaf_parent(fr_dlist_head_t *existing, fr_dlist_head_t *to_build, tmpl_t const *vpt)
{
	tmpl_attr_extent_t	*extent = NULL;

	while ((extent = fr_dlist_head(to_build))) {
		fr_pair_list_t		*list;
		TALLOC_CTX		*list_ctx;
		fr_pair_t		*vp;
		tmpl_attr_t const	*ar;

		fr_assert(extent->ar);	/* Interior extents MUST contain an ar */

		/*
		 *	Try and allocate VPs for the
		 *	rest of the attribute references.
		 */
		for (ar = extent->ar, list = extent->list, list_ctx = extent->list_ctx;
		     ar;
		     ar = tmpl_attr_list_next(&vpt->data.attribute.ar, ar)) {
			switch (ar->type) {
			case TMPL_ATTR_TYPE_NORMAL:
			case TMPL_ATTR_TYPE_UNKNOWN:
				/*
				 *	Don't build leaf attributes
				 */
				if (!fr_type_is_structural(ar->ar_da->type)) continue;

				MEM(vp = fr_pair_afrom_da(list_ctx, ar->ar_da));	/* Copies unknowns */
				fr_pair_append(list, vp);
				list = &vp->vp_group;
				list_ctx = vp;		/* New allocations occur under the VP */
				break;

			default:
				fr_assert_fail("references of this type should have been resolved");
				return -1;
			}
		}

		fr_dlist_remove(to_build, extent);	/* Do this *before* zeroing the dlist headers */
		*extent = (tmpl_attr_extent_t){
			.list = list,
			.list_ctx = list_ctx
		};
		fr_dlist_insert_tail(existing, extent);	/* move between in and out */
	}

	return 0;
}

void tmpl_extents_debug(fr_dlist_head_t *head)
{
	tmpl_attr_extent_t const *extent = NULL;
	fr_pair_t *vp = NULL;

	for (extent = fr_dlist_head(head);
	     extent;
	     extent = fr_dlist_next(head, extent)) {
	     	tmpl_attr_t const *ar = extent->ar;
	     	char const *ctx_name;

	     	if (ar) {
			FR_FAULT_LOG("extent-interior-attr");
			tmpl_attr_ref_debug(extent->ar, 0);
		} else {
			FR_FAULT_LOG("extent-leaf");
		}

		ctx_name = talloc_get_name(extent->list_ctx);
		if (strcmp(ctx_name, "fr_pair_t") == 0) {
			FR_FAULT_LOG("list_ctx     : %p (%s, %s)", extent->list_ctx, ctx_name,
				     ((fr_pair_t *)extent->list_ctx)->da->name);
		} else {
			FR_FAULT_LOG("list_ctx     : %p (%s)", extent->list_ctx, ctx_name);
		}
		FR_FAULT_LOG("list         : %p", extent->list);
		if (fr_pair_list_empty(extent->list)) {
			FR_FAULT_LOG("list (first) : none (%p)", extent->list);
		} else {
			vp = fr_pair_list_head(extent->list);
			FR_FAULT_LOG("list (first) : %s (%p)", vp->da->name, extent->list);
		}
	}

}
