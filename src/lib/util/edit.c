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

/**
 * $Id$
 *
 * @file src/lib/util/edit.c
 * @brief Functions to edit pair lists, and track undo operations
 *
 *  This file implements an "edit list" for changing values of
 *  #fr_pair_t.  After some investigation, it turns out that it's much
 *  easier to have an "undo list" than to track partially applied
 *  transactions.  Tracking partial transactions means that none of
 *  the fr_pair_foo() functions will work, as some pairs are in the
 *  "old" list and some in the "new" list.  Also, a transaction may
 *  still fail when we finalize it by moving the pairs around.
 *
 *  In contrast, an "undo" list means that all of the fr_pair_foo()
 *  functions will work, as any list contains only "active" pairs.
 *  And we never need to "finalize" a transaction, as the lists are
 *  already in their final form.  The only thing needed for
 *  finalization is to free the undo list.  Which can never fail.
 *
 *  Note that the functions here require the input VPs to already have
 *  the correct talloc parent!  The only thing the edit list does is
 *  to record "undo" actions.
 *
 *  The only exception to this is fr_edit_list_apply_list_assignment().
 *  Which does call talloc_steal, and then also frees any pairs which
 *  weren't applied to the LHS.
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/talloc.h>
#include "edit.h"
#include "calc.h"

typedef enum {
	FR_EDIT_INVALID = 0,
	FR_EDIT_DELETE,			//!< delete a VP
	FR_EDIT_VALUE,			//!< edit a VP in place
	FR_EDIT_CLEAR,			//!< clear the children of a structural entry.
	FR_EDIT_INSERT,			//!< insert a VP into a list, after another one.
} fr_edit_op_t;

#if 0
/*
 *	For debugging.
 */
static const char *edit_names[4] = {
	"invalid",
	"delete",
	"value",
	"clear",
	"insert",
};
#endif

/** Track a series of edits.
 *
 */
struct fr_edit_list_s {
	/*
	 *	List of undo changes to be made, in order.
	 */
	fr_dlist_head_t	undo;

	fr_dlist_head_t	ignore;		//!< lists to ignore

	/*
	 *	VPs which were inserted, and then over-written by a
	 *	later edit.
	 */
	fr_pair_list_t	deleted_pairs;
};

/** Track one particular edit.
 */
typedef struct {
	fr_edit_op_t	op;		//!< edit operation to perform
	fr_dlist_t	entry;		//!< linked list of edits

	fr_pair_t	*vp;		//!< pair edited, deleted, or inserted

	union {
		union {
			fr_value_box_t	data;	//!< original data
			fr_pair_list_t	children;  //!< original child list, for "clear"
		};

		struct {
			fr_pair_list_t	*list; //!< parent list
			fr_pair_t	*ref;	//!< reference pair for delete, insert before/after
		};
	};
} fr_edit_t;

typedef struct {
	fr_dlist_t	entry;
	fr_pair_list_t	*list;		//!< list to ignore (never dereferenced)
} fr_edit_ignore_t;


static bool fr_edit_list_empty(fr_edit_list_t *el)
{
	return fr_dlist_empty(&el->undo) && fr_dlist_empty(&el->ignore) && fr_pair_list_empty(&el->deleted_pairs);
}

/** Undo one particular edit.
 */
static int edit_undo(fr_edit_t *e)
{
	fr_pair_t *vp = e->vp;
#ifndef NDEBUG
	int rcode;
#endif

	fr_assert(vp != NULL);
	PAIR_VERIFY(vp);

	switch (e->op) {
	case FR_EDIT_INVALID:
		return -1;

	case FR_EDIT_VALUE:
		fr_assert(fr_type_is_leaf(vp->vp_type));
		if (!fr_type_is_fixed_size(vp->vp_type)) fr_value_box_clear(&vp->data);
		fr_value_box_copy(vp, &vp->data, &e->data);
		break;

	case FR_EDIT_CLEAR:
		fr_assert(fr_type_is_structural(vp->vp_type));

		fr_pair_list_free(&vp->vp_group);
		fr_pair_list_append(&vp->vp_group, &e->children);
		break;

	case FR_EDIT_DELETE:
		fr_assert(e->list != NULL);
#ifndef NDEBUG
		rcode =
#endif
		fr_pair_insert_after(e->list, e->ref, vp);
		fr_assert(rcode == 0);
		break;

	case FR_EDIT_INSERT:
		/*
		 *	We can free the VP here, as any edits to its'
		 *	children MUST come after the creation of the
		 *	VP.  And any deletion of VPs after this one
		 *	must come after this VP was created.
		 */
		fr_pair_delete(e->list, vp);
		break;
	}

	return 0;
}

/** Abort the entries in an edit list.
 *
 *  After this call, the input list(s) are unchanged from before any
 *  edits were made.
 *
 *  the caller does not have to call talloc_free(el);
 */
void fr_edit_list_abort(fr_edit_list_t *el)
{
	fr_edit_t *e;

	if (!el) return;

	/*
	 *      All of these pairs are already in the edit list.  They
	 *      have the correct parent, and will be placed back into
	 *      their correct location by edit_undo()
	 */
	fr_pair_list_init(&el->deleted_pairs);

	/*
	 *	Undo edits in reverse order, as later edits depend on
	 *	earlier ones.  We don't have multiple edits of the
	 *	same VP, but we can create a VP, and then later edit
	 *	its children.
	 */
	while ((e = fr_dlist_pop_tail(&el->undo)) != NULL) {
		edit_undo(e);
		/*
		 *	Don't free "e", it will be cleaned up when we
		 *	talloc_free(el).  That should be somewhat
		 *	faster than doing it incrementally.
		 */
	};

	talloc_free(el);
}

/** Record one particular edit
 *
 *  For INSERT / DELETE, this function will also insert / delete the
 *  VP.
 *
 *  For VALUE changes, this function must be called BEFORE the value
 *  is changed.  Once this function has been called, it is then safe
 *  to edit the value in place.
 *
 *  Note that VALUE changes for structural types are allowed ONLY when
 *  using T_OP_SET, which over-writes previous values.  For every
 *  other modification to structural types, we MUST instead call
 *  insert / delete on the vp_group.
 */
static int edit_record(fr_edit_list_t *el, fr_edit_op_t op, fr_pair_t *vp, fr_pair_list_t *list, fr_pair_t *ref)
{
	fr_edit_t *e;

	fr_assert(el != NULL);
	fr_assert(vp != NULL);

	/*
	 *	When we insert a structural type, we also want to
	 *	not track edits to it's children.  The "ignore list"
	 *	allows us to see which lists don't have edits recorded.
	 *
	 *	Perform the operation.  We're not recording
	 *	it, but we still need to do the work.
	 */
	fr_dlist_foreach(&el->ignore, fr_edit_ignore_t, i) {
		if (i->list != list) continue;

		switch (op) {
			/*
			 *	No need to save the value.
			 */
		case FR_EDIT_VALUE:
			return 0;

			/*
			 *	No need to save the value.
			 */
		case FR_EDIT_DELETE:
			fr_pair_remove(list, vp);
			return 0;

			/*
			 *	Delete all of the children.
			 */
		case FR_EDIT_CLEAR:
			if (!fr_type_is_structural(vp->da->type)) return 0;

			fr_pair_list_free(&vp->vp_group);
			return 0;

			/*
			 *	Insert it, and perhaps save the list
			 *	for a structural VP saying "don't
			 *	record edits to this, either".
			 */
		case FR_EDIT_INSERT:
			if (fr_pair_insert_after(list, ref, vp) < 0) return -1;

			/*
			 *	Non-structural types don't have any other work to do.
			 */
			if (!fr_type_is_structural(vp->da->type)) return 0;

			/*
			 *	Otherwise we're inserting a VP which has a
			 *	child list.  Remember that we need to ignore
			 *	edits to the children of this VP, too.
			 */
			goto insert_ignore;

		default:
			return -1;
		}
	}

	/*
	 *	Catch NOOPs
	 */
	if (op == FR_EDIT_CLEAR) {
		fr_assert(fr_type_is_structural(vp->vp_type));

		if (fr_pair_list_empty(&vp->vp_group)) return 0;
	}

	/*
	 *	Search for previous edits.
	 *
	 *	@todo - if we're modifying values of a child VP, and
	 *	it's parent is marked as INSERT, then we don't need to
	 *	record FR_EDIT_VALUE changes to the children.  It's
	 *	not yet clear how best to track this.
	 */
	for (e = fr_dlist_head(&el->undo);
	     e != NULL;
	     e = fr_dlist_next(&el->undo, e)) {
		fr_assert(e->vp != NULL);

		if (e->vp != vp) continue;

		switch (op) {
		case FR_EDIT_INVALID:
			return -1;

			/*
			 *	We're editing a previous edit.
			 *	There's no need to record anything
			 *	new, as we've already recorded the
			 *	original value.
			 *
			 *	Note that we can insert a pair and
			 *	then edit it.  The undo list only
			 *	saves the insert, as the later edit is
			 *	irrelevant.  If we're undoing, we
			 *	simply delete the new attribute which
			 *	was inserted.
			 */
		case FR_EDIT_VALUE:
			/*
			 *	If we delete a pair, we can't later
			 *	edit it.  That indicates serious
			 *	issues with the code.
			 *
			 *      However, if we previously inserted
			 *      this VP, then we don't need to record
			 *      changes to its value.  Similarly, if
			 *      we had previously changed its value,
			 *      we don't need to record that
			 *      information again.
                         */
			fr_assert(e->op != FR_EDIT_DELETE);
			fr_assert(fr_type_is_leaf(vp->vp_type));
			return 0;

			/*
			 *	We're inserting a new pair.
			 *
			 *	We can't have previously edited this
			 *	pair (inserted, deleted, or updated
			 *	the value), as the pair is new!
			 */
		case FR_EDIT_INSERT:
			fr_assert(0);
			return -1;

		case FR_EDIT_CLEAR:
			/*
			 *	If we're clearing it, we MUST have
			 *	previously inserted it.  So just nuke
			 *	it's children, as merging the
			 *	operations of "insert with stuff" and
			 *	then "clear" is just "insert empty
			 *	pair".
			 *
			 *	However, we don't yet delete the
			 *	children, as there may be other edit
			 *	operations which are referring to
			 *	them.
			 */
			fr_assert(e->op == FR_EDIT_INSERT);
			fr_assert(fr_type_is_structural(vp->vp_type));

			fr_pair_list_append(&el->deleted_pairs, &vp->vp_group);
			break;

			/*
			 *	We're being asked to delete something
			 *	we previously inserted, or previously
			 *	edited.
			 */
		case FR_EDIT_DELETE:
			/*
			 *	We can't delete something which was
			 *	already deleted.
			 */
			fr_assert(e->op != FR_EDIT_DELETE);

			/*
			 *	We had previously inserted it.  So
			 *	just delete the insert operation, and
			 *	delete the VP from the list.
			 *
			 *	Other edits may refer to children of
			 *	this pair.  So we don't free the VP
			 *	immediately, but instead reparent it
			 *	to the edit list.  So that when the
			 *	edit list is freed, the VP will be
			 *	freed.
			 */
			if (e->op == FR_EDIT_INSERT) {
				fr_assert(e->list == list);

				fr_pair_remove(list, vp);
				fr_pair_append(&el->deleted_pairs, vp);

				fr_dlist_remove(&el->undo, e);
				talloc_free(e);
				return 0;
			}

			/*
			 *	We had previously changed the value,
			 *	but now we're going to delete it.
			 *
			 *	Since it had previously existed, we
			 *	have to reset its value to the
			 *	original one, and then track the
			 *	deletion.
			 */
			edit_undo(e);

			/*
			 *	Rewrite the edit to be delete.
			 *
			 *	And move the deletion to the tail of
			 *	the edit list, because edits between
			 *	"here" and the tail of the list may
			 *	refer to "vp".  If we leave the
			 *	deletion in place, then subsequent
			 *	edit list entries will refer to a VP
			 *	which has been deleted!
			 */
			e->op = FR_EDIT_DELETE;
			fr_dlist_remove(&el->undo, e);
			goto delete;
		}
	} /* loop over existing edits */

	/*
	 *	No edit for this pair exists.  Create a new edit entry.
	 */
	e = talloc_zero(el, fr_edit_t);
	if (!e) return -1;

	e->op = op;
	e->vp = vp;

	switch (op) {
	case FR_EDIT_INVALID:
	fail:
		talloc_free(e);
		return -1;

	case FR_EDIT_VALUE:
		fr_assert(list == NULL);
		fr_assert(ref == NULL);

		fr_assert(fr_type_is_leaf(vp->vp_type));
		fr_value_box_copy(e, &e->data, &vp->data);
		break;

	case FR_EDIT_CLEAR:
		fr_assert(list == NULL);
		fr_assert(ref == NULL);

		fr_assert(fr_type_is_structural(vp->vp_type));
		fr_pair_list_init(&e->children);
		fr_pair_list_append(&e->children, &vp->vp_group);
		break;

	case FR_EDIT_INSERT:
		fr_assert(list != NULL);

		/*
		 *	There's no need to record "prev".  On undo, we
		 *	just delete this pair from the list.
		 */
		e->list = list;
		if (fr_pair_insert_after(list, ref, vp) < 0) goto fail;
		break;

	case FR_EDIT_DELETE:
	delete:
		fr_assert(list != NULL);
		fr_assert(ref == NULL);

		e->list = list;
		e->ref = fr_pair_list_prev(list, vp);

		fr_pair_remove(list, vp);
		break;
	}

	fr_dlist_insert_tail(&el->undo, e);

	/*
	 *	Insert an "ignore" entry.
	 */
	if ((op == FR_EDIT_INSERT) && fr_type_is_structural(vp->da->type)) {
		fr_edit_ignore_t *i;

	insert_ignore:
		i = talloc_zero(el, fr_edit_ignore_t);
		if (!i) return 0;

		i->list = &vp->vp_group;
		fr_dlist_insert_tail(&el->ignore, i);
	}

	return 0;
}


/** Insert a new VP after an existing one.
 *
 *  This function mirrors fr_pair_insert_after().
 *
 *  After this function returns, the new VP has been inserted into the
 *  list.
 */
int fr_edit_list_insert_pair_after(fr_edit_list_t *el, fr_pair_list_t *list, fr_pair_t *pos, fr_pair_t *vp)
{
	if (!el) return fr_pair_insert_after(list, pos, vp);

	return edit_record(el, FR_EDIT_INSERT, vp, list, pos);
}

/** Delete a VP
 *
 *  This function mirrors fr_pair_delete()
 *
 *  After this function returns, the VP has been removed from the list.
 */
int fr_edit_list_pair_delete(fr_edit_list_t *el, fr_pair_list_t *list, fr_pair_t *vp)
{
	if (!el) {
		fr_pair_delete(list, vp);
		return 0;
	}

	return edit_record(el, FR_EDIT_DELETE, vp, list, NULL);
}

/** Delete VPs with a matching da
 *
 *  This function mirrors fr_pair_delete_by_da()
 */
int fr_edit_list_pair_delete_by_da(fr_edit_list_t *el, fr_pair_list_t *list, fr_dict_attr_t const *da)
{
	if (!el) {
		fr_pair_delete_by_da(list, da);
		return 0;
	}

	/*
	 *	Delete all VPs with a matching da.
	 */
	fr_pair_list_foreach(list, vp) {
		if (vp->da != da) continue;

		(void) fr_pair_remove(list, vp);

		if (edit_record(el, FR_EDIT_DELETE, vp, list, NULL) < 0) return -1;
	}

	return 0;
}


/** Record the value of a leaf #fr_value_box_t
 *
 *  After this function returns, it's safe to edit the pair.
 */
int fr_edit_list_save_pair_value(fr_edit_list_t *el, fr_pair_t *vp)
{
	if (!el) return 0;

	if (!fr_type_is_leaf(vp->vp_type)) return -1;

	return edit_record(el, FR_EDIT_VALUE, vp, NULL, NULL);
}

/** Write a new value to the #fr_value_box_t
 *
 *  After this function returns, the value has been updated.
 */
int fr_edit_list_replace_pair_value(fr_edit_list_t *el, fr_pair_t *vp, fr_value_box_t *box)
{
	if (!fr_type_is_leaf(vp->vp_type)) return -1;

	if (el && (edit_record(el, FR_EDIT_VALUE, vp, NULL, NULL) < 0)) return -1;

	if (!fr_type_is_fixed_size(vp->vp_type)) fr_value_box_clear(&vp->data);
	fr_value_box_copy_shallow(NULL, &vp->data, box);
	return 0;
}

/** Replace a pair with another one.
 *
 *  This function mirrors fr_pair_replace().
 *
 *  After this function returns, the new VP has replaced the old one,
 *  and the new one can be edited.
 */
int fr_edit_list_replace_pair(fr_edit_list_t *el, fr_pair_list_t *list, fr_pair_t *to_replace, fr_pair_t *vp)
{
	if (to_replace->da != vp->da) return -1;

	if (!el) {
		if (fr_pair_insert_after(list, to_replace, vp) < 0) return -1;
		fr_pair_delete(list, to_replace);
		return -1;
	}

	/*
	 *	We call edit_record() twice, which involves two
	 *	complete passes over the edit list.  That's fine,
	 *	either the edit list is small, OR we will eventially
	 *	put the VPs to be edited into an RB tree.
	 */
	if (edit_record(el, FR_EDIT_INSERT, vp, list, to_replace) < 0) return -1;

	/*
	 *	If deleting the old entry fails, then the new entry
	 *	above MUST be the last member of the edit list.  If
	 *	it's not the last member, then it means that it
	 *	already existed in the list (either VP list of edit
	 *	list).  The edit_record() function checks for that,
	 *	and errors if so.
	 */
	if (edit_record(el, FR_EDIT_DELETE, to_replace, list, NULL) < 0) {
		fr_edit_t *e = fr_dlist_pop_tail(&el->undo);

		fr_assert(e != NULL);
		fr_assert(e->vp == vp);
		talloc_free(e);
		return -1;
	}

	return 0;
}


/** Free children of a structural pair.
 *
 *  This function mirrors fr_pair_replace().
 *
 *  After this function returns, the new VP has replaced the old one,
 *  and the new one can be edited.
 */
int fr_edit_list_free_pair_children(fr_edit_list_t *el, fr_pair_t *vp)
{
	if (!fr_type_is_structural(vp->vp_type)) return -1;

	if (!el) {
		fr_pair_list_free(&vp->children);
		return 0;
	}

	/*
	 *	No children == do nothing.
	 */
	if (fr_pair_list_empty(&vp->vp_group)) return 0;

	/*
	 *	Record the list, even if it's empty.  That way if we
	 *	later add children to it, the "undo" operation can
	 *	reset the children list to be empty.
	 */
	return edit_record(el, FR_EDIT_CLEAR, vp, NULL, NULL);
}

/** Finalize the edits when we destroy the edit list.
 *
 *  Which in large part means freeing the VPs which have been deleted,
 *  or saved, and then deleting the edit list.
 */
static int _edit_list_destructor(fr_edit_list_t *el)
{
	fr_edit_t *e;

	fr_assert(el != NULL);

	for (e = fr_dlist_head(&el->undo);
	     e != NULL;
	     e = fr_dlist_next(&el->undo, e)) {
		switch (e->op) {
		case FR_EDIT_INVALID:
			fr_assert(0);
			break;

		case FR_EDIT_INSERT:
			break;

		case FR_EDIT_DELETE:
			fr_assert(e->vp != NULL);
			talloc_free(e->vp);
			break;

		case FR_EDIT_CLEAR:
			fr_pair_list_free(&e->children);
			break;

		case FR_EDIT_VALUE:
			fr_assert(fr_type_is_leaf(e->vp->vp_type));
			fr_value_box_clear(&e->data);
			break;
		}
	}

	fr_pair_list_free(&el->deleted_pairs);

	talloc_free(el);

	return 0;
}

fr_edit_list_t *fr_edit_list_alloc(TALLOC_CTX *ctx, int hint)
{
	fr_edit_list_t *el;

	el = talloc_zero_pooled_object(ctx, fr_edit_list_t, hint, hint * sizeof(fr_edit_t));
	if (!el) return NULL;

	fr_dlist_init(&el->undo, fr_edit_t, entry);
	fr_dlist_init(&el->ignore, fr_edit_ignore_t, entry);

	fr_pair_list_init(&el->deleted_pairs);

	talloc_set_destructor(el, _edit_list_destructor);

	return el;
}

/** Notes
 *
 *  Unlike "update" sections, edits are _not_ hierarchical.  If we're
 *  editing values a list, then the list has to exist.  If we're
 *  inserting pairs in a list, then we find the lowest existing pair,
 *  and add pairs there.
 *
 *  The functions tmpl_extents_find() and tmpl_extents_build_to_leaf_parent()
 *  should help us figure out where the VPs exist or not.
 *
 *  The overall "update" algorithm is now:
 *
 *	alloc(edit list)
 *
 *	foreach entry in the things to do
 *		expand LHS if needed to local TMPL
 *		expand RHS if needed to local box / cursor / TMPL
 *
 *		use LHS/RHS cursors to find VPs
 *		edit VPs, recording edits
 *
 *	free temporary map
 *	commit(edit list)
 */

/**********************************************************************
 *
 *  Now we have helper functions which use the edit list to get things
 *  done.
 *
 **********************************************************************/

/** Insert a list after a particular point in another list.
 *
 *  This function mirrors fr_pair_list_append(), but with a bit more
 *  control over where the to_insert list ends up.
 *
 *  There's nothing magical about this function, it's just easier to
 *  have it here than in multiple places in the code.
 */
int fr_edit_list_insert_list_after(fr_edit_list_t *el, fr_pair_list_t *list, fr_pair_t *pos, fr_pair_list_t *to_insert)
{
	fr_pair_t *prev, *vp;

	prev = pos;

	if (!el) {
		/*
		 *	@todo - this should really be an O(1) dlist
		 *	operation.
		 */
		while ((vp = fr_pair_list_head(to_insert)) != NULL) {
			(void) fr_pair_remove(to_insert, vp);
			(void) fr_pair_insert_after(list, prev, vp);
			prev = vp;
		}

		return 0;
	}

	/*
	 *	We have to record each individual insert as a separate
	 *	item.  Some later edit may insert pairs in the middle
	 *	of the ones we've added.
	 */
	while ((vp = fr_pair_list_head(to_insert)) != NULL) {
		(void) fr_pair_remove(to_insert, vp);

		if (edit_record(el, FR_EDIT_INSERT, vp, list, prev) < 0) {
			fr_pair_prepend(to_insert, vp); /* don't lose it! */
			return -1;
		}

		prev = vp;
	}

	return 0;
}

/** Removes elements matching a list
 *
 *  O(N^2) unfortunately.
 */
static int fr_edit_list_delete_list(fr_edit_list_t *el, fr_pair_list_t *list, fr_pair_list_t *to_remove)
{
	fr_pair_list_foreach(to_remove, vp) {
		fr_pair_t *found, *next;

		/*
		 *	@todo - do this recursively.
		 */
		if (fr_type_is_structural(vp->da->type)) continue;

		for (found = fr_pair_find_by_da(list, NULL, vp->da);
		     found != NULL;
		     found = next) {
			int rcode;

			next = fr_pair_find_by_da(list, found, vp->da);

			rcode = fr_value_box_cmp_op(vp->op, &vp->data, &found->data);
			if (rcode < 0) return -1;

			if (!rcode) continue;

			if (fr_edit_list_pair_delete(el, list, found) < 0) return -1;
		}
	}

	return 0;
}

/** Apply operators to pairs.
 *
 *  := is "if found vp, call fr_edit_list_pair_replace().  Otherwise call fr_edit_list_insert_pair_tail()
 *   = is "if found vp, do nothing.  Otherwise call fr_edit_list_insert_pair_tail()
 *
 */
int fr_edit_list_apply_pair_assignment(fr_edit_list_t *el, fr_pair_t *vp, fr_token_t op, fr_value_box_t const *in)
{
	if (el && (fr_edit_list_save_pair_value(el, vp) < 0)) return -1;

	return fr_value_calc_assignment_op(vp, &vp->data, op, in);
}

#undef COPY
#define COPY(_x) do { if (copy) { \
		        c = fr_pair_copy(dst, _x); \
			if (!c) return -1; \
                      } else { \
			c = talloc_steal(dst, _x); \
			fr_pair_remove(src, c); \
		      } \
		 } while (0)

#define NEXT_A do { a = an; an = fr_pair_list_next(&dst->children, a); } while (0)
#define NEXT_B do { b = bn; bn = fr_pair_list_next(src, b); } while (0)


/** A UNION B
 *
 */
static int list_union(fr_edit_list_t *el, fr_pair_t *dst, fr_pair_list_t *src, bool copy)
{
	fr_pair_t *a, *an;
	fr_pair_t *b, *bn;
	fr_pair_t *c;

	/*
	 *	Prevent people from doing stupid things.
	 *	While it's technically possible to take a
	 *	UNION of structs, that would work ONLY when
	 *	the two structs had disjoint members.
	 *	e.g. {1, 3, 4} and {2, 5, 6}.  That's too
	 *	complex to check right now, so we punt on the
	 *	problem.
	 */
	if (dst->vp_type == FR_TYPE_STRUCT) {
		fr_strerror_printf("Cannot take union of STRUCT data types, it would break the structure");
		return -1;
	}

	fr_pair_list_sort(&dst->children, fr_pair_cmp_by_parent_num);
	fr_pair_list_sort(src, fr_pair_cmp_by_parent_num);

	PAIR_LIST_VERIFY(&dst->children);
	PAIR_LIST_VERIFY(src);

	a = fr_pair_list_head(&dst->children);
	an = fr_pair_list_next(&dst->children, a);
	b = fr_pair_list_head(src);
	bn = fr_pair_list_next(src, b);

	while (true) {
		int rcode;

		/*
		 *	B is done, so we stop processing.
		 */
		if (!b) break;

		/*
		 *	A is done, so we can add in B at the end of A.
		 */
		if (!a) {
			COPY(b);

			if (fr_edit_list_insert_pair_tail(el, &dst->children, c) < 0) {
				return -1;
			}

			NEXT_B;
			continue;
		}

		/*
		 *	Compare the da's
		 */
		rcode = fr_pair_cmp_by_parent_num(a, b);

		/*
		 *	We've seen things in A which aren't in B, so
		 *	we just increment A.
		 */
		if (rcode < 0) {
			NEXT_A;
			continue;
		}

		/*
		 *	a > b
		 *
		 *	This means that in the ordered set, the
		 *	equivalent to B does not exist.  So we copy B
		 *	to after A.
		 */
		if (rcode > 0) {
			COPY(b);

			if (fr_edit_list_insert_pair_after(el, &dst->children, a, c) < 0) {
				return -1;
			}

			NEXT_B;
			continue;
		}

		fr_assert(rcode == 0);

		/*
		 *	They're the same.
		 */
		fr_assert(a->da == b->da);

		/*
		 *	Union lists recursively.
		 *
		 *	Note that this doesn't mean copying both VPs!  We just merge their contents.
		 */
		if (fr_type_is_structural(a->vp_type)) {
			rcode = list_union(el, a, &b->children, copy);
			if (rcode < 0) return rcode;

			NEXT_A;
			NEXT_B;
			continue;
		}

		/*
		 *	Process all identical attributes, but by
		 *	value.  If the value is the same, we keep only
		 *	one.  If the values are different, we keep
		 *	both.
		 */
		while (a && b && (a->da == b->da)) {
			/*
			 *	Check if the values are the same.  This
			 *	returns 0 for "equal", and non-zero for
			 *	anything else.
			 */
			rcode = fr_value_box_cmp(&a->data, &b->data);
			if (rcode != 0) {
				COPY(b);

				if (fr_edit_list_insert_pair_after(el, &dst->children, a, c) < 0) {
					return -1;
				}
			}

			NEXT_A;
			NEXT_B;
		}
	}

	return 0;
}

/** A MERGE B
 *
 * with priority to A
 */
static int list_merge_lhs(fr_edit_list_t *el, fr_pair_t *dst, fr_pair_list_t *src, bool copy)
{
	fr_pair_t *a, *an;
	fr_pair_t *b, *bn;
	fr_pair_t *c;

	fr_pair_list_sort(&dst->children, fr_pair_cmp_by_parent_num);
	fr_pair_list_sort(src, fr_pair_cmp_by_parent_num);

	PAIR_LIST_VERIFY(&dst->children);
	PAIR_LIST_VERIFY(src);

	a = fr_pair_list_head(&dst->children);
	an = fr_pair_list_next(&dst->children, a);
	b = fr_pair_list_head(src);
	bn = fr_pair_list_next(src, b);

	while (true) {
		int rcode;

		/*
		 *	B is done, so we stop processing.
		 */
		if (!b) break;

		/*
		 *	A is done, so we can add in B at the end of A.
		 */
		if (!a) {
			COPY(b);

			if (fr_edit_list_insert_pair_tail(el, &dst->children, c) < 0) {
				return -1;
			}

			NEXT_B;
			continue;
		}

		/*
		 *	Compare the da's
		 */
		rcode = fr_pair_cmp_by_parent_num(a, b);

		/*
		 *	We've seen things in A which aren't in B, so
		 *	we just increment A.
		 */
		if (rcode < 0) {
			NEXT_A;
			continue;
		}

		/*
		 *	a > b
		 *
		 *	This means that in the ordered set, the
		 *	equivalent to B does not exist.  So we copy B
		 *	to before A.
		 */
		if (rcode > 0) {
			COPY(b);

			if (fr_edit_list_insert_pair_before(el, &dst->children, a, c) < 0) {
				return -1;
			}

			NEXT_B;
			continue;
		}

		fr_assert(rcode == 0);

		/*
		 *	They're the same.
		 */
		fr_assert(a->da == b->da);

		/*
		 *	Merge lists recursively.
		 */
		if (fr_type_is_structural(a->vp_type)) {
			rcode = list_merge_lhs(el, a, &b->children, copy);
			if (rcode < 0) return rcode;

			goto next_both;
		}

		/*
		 *	We have both A and B, so we prefer A, which means just skipping B.
		 */

	next_both:
		NEXT_A;
		NEXT_B;
	}

	return 0;
}

/** A MERGE B
 *
 * with priority to B.
 */
static int list_merge_rhs(fr_edit_list_t *el, fr_pair_t *dst, fr_pair_list_t *src, bool copy)
{
	fr_pair_t *a, *an;
	fr_pair_t *b, *bn;
	fr_pair_t *c;

	fr_pair_list_sort(&dst->children, fr_pair_cmp_by_parent_num);
	fr_pair_list_sort(src, fr_pair_cmp_by_parent_num);

	PAIR_LIST_VERIFY(&dst->children);
	PAIR_LIST_VERIFY(src);

	a = fr_pair_list_head(&dst->children);
	an = fr_pair_list_next(&dst->children, a);
	b = fr_pair_list_head(src);
	bn = fr_pair_list_next(src, b);

	while (true) {
		int rcode;

		/*
		 *	B is done, so we stop processing.
		 */
		if (!b) break;

		/*
		 *	A is done, so we can in B at the end of A.
		 */
		if (!a) {
			COPY(b);

			if (fr_edit_list_insert_pair_tail(el, &dst->children, c) < 0) {
				return -1;
			}

			NEXT_B;
			continue;
		}

		/*
		 *	Compare the da's
		 */
		rcode = fr_pair_cmp_by_parent_num(a, b);

		/*
		 *	We've seen things in A which aren't in B, so
		 *	we just increment A.
		 */
		if (rcode < 0) {
			NEXT_A;
			continue;
		}

		/*
		 *	a > b
		 *
		 *	This means that in the ordered set, the
		 *	equivalent to B does not exist.  So we copy B
		 *	to before A.
		 */
		if (rcode > 0) {
			COPY(b);

			if (fr_edit_list_insert_pair_before(el, &dst->children, a, c) < 0) {
				return -1;
			}

			NEXT_B;
			continue;
		}

		fr_assert(rcode == 0);

		/*
		 *	They're the same.
		 */
		fr_assert(a->da == b->da);

		/*
		 *	Merge lists recursively.
		 */
		if (fr_type_is_structural(a->vp_type)) {
			rcode = list_merge_rhs(el, a, &b->children, copy);
			if (rcode < 0) return rcode;

			goto next_both;
		}

		/*
		 *	We have both A and B, so we prefer B.
		 */
		COPY(b);
		if (fr_edit_list_replace_pair(el, &dst->children, a, c) < 0) {
			return -1;
		}

	next_both:
		NEXT_A;
		NEXT_B;
	}

	return 0;
}

/** A INTERSECTION B
 *
 */
static int list_intersection(fr_edit_list_t *el, fr_pair_t *dst, fr_pair_list_t *src)
{
	fr_pair_t *a, *an;
	fr_pair_t *b, *bn;

	/*
	 *	Prevent people from doing stupid things.
	 */
	if (dst->vp_type == FR_TYPE_STRUCT) {
		fr_strerror_printf("Cannot take intersection of STRUCT data types, it would break the structure");
		return -1;
	}

	fr_pair_list_sort(&dst->children, fr_pair_cmp_by_parent_num);
	fr_pair_list_sort(src, fr_pair_cmp_by_parent_num);

	a = fr_pair_list_head(&dst->children);
	an = fr_pair_list_next(&dst->children, a);
	b = fr_pair_list_head(src);
	bn = fr_pair_list_next(src, b);

	while (true) {
		int rcode;

		/*
		 *	A is done, so we can return.  We don't need to
		 *	delete everything from B, as that will be
		 *	cleaned up by the caller when we exit.
		 */
		if (!a) break;

		/*
		 *	B is done, so we delete everything else in A.
		 */
		if (!b) {
		delete_a:
			if (fr_edit_list_pair_delete(el, &dst->children, a) < 0) return -1;
			NEXT_A;
			continue;
		}

		/*
		 *	Compare the da's
		 */
		rcode = fr_pair_cmp_by_parent_num(a, b);

		/*
		 *	a < b
		 *
		 *	A gets removed.
		 */
		if (rcode < 0) goto delete_a;

		/*
		 *	a > b
		 *
		 *      Skip forward in B until we have it better matching A.
		 */
		if (rcode > 0) {
			NEXT_B;
			continue;
		}

		fr_assert(rcode == 0);

		/*
		 *	INTERSECT the children, and then leave A
		 *	alone, unless it's empty, in which case A
		 *	INTERSECT B is empty, so we also delete A.
		 */
		if (fr_type_is_structural(a->vp_type)) {
			rcode = list_intersection(el, a, &b->children);
			if (rcode < 0) return rcode;

			NEXT_B;

			if (fr_pair_list_empty(&a->children)) goto delete_a;

			NEXT_A;
			continue;
		}

		/*
		 *	Process all identical attributes, but by
		 *	value.
		 */
		while (a && b && (a->da == b->da)) {
			/*
			 *	Check if the values are the same.  This
			 *	returns 0 for "equal", and non-zero for
			 *	anything else.
			 */
			rcode = fr_value_box_cmp(&a->data, &b->data);
			if (rcode != 0) {
				if (fr_edit_list_pair_delete(el, &dst->children, a) < 0) return -1;
			}

			NEXT_A;
			NEXT_B;
		}
	}

	return 0;
}


/** Apply operators to lists.
 *
 *   = is "if found vp, do nothing.  Otherwise call fr_edit_list_insert_pair_tail()
 *
 *  The src list is sorted, but is otherwise not modified.
 */
int fr_edit_list_apply_list_assignment(fr_edit_list_t *el, fr_pair_t *dst, fr_token_t op, fr_pair_list_t *src, bool copy)
{
	fr_pair_list_t list;

	if (!fr_type_is_structural(dst->vp_type)) {
		fr_strerror_printf("Cannot perform list assignment to non-structural type '%s'",
				   fr_type_to_str(dst->vp_type));
		return -1;
	}

#undef COPY
#define COPY do { if (copy) { \
		    fr_pair_list_init(&list); \
		    if (fr_pair_list_copy(dst, &list, src) < 0) return -1;\
                    src = &list; \
                  } else { \
		    fr_pair_list_steal(dst, src); \
	          } \
	} while (0)


	switch (op) {
		/*
		 *	Over-ride existing value (i.e. children) with
		 *	new list.
		 */
	case T_OP_SET:
		if (&dst->children == src) return 0; /* A := A == A */

		if (fr_edit_list_free_pair_children(el, dst) < 0) return -1;
		FALL_THROUGH;

	case T_OP_ADD_EQ:
		if (&dst->children == src) {
			fr_strerror_printf("Cannot append list to itself");
			return -1;
		}

		COPY;
		return fr_edit_list_insert_list_tail(el, &dst->children, src);

	case T_OP_SUB_EQ:
		/*
		 *	foo -= foo --> {}
		 */
		if (&dst->children == src) {
			fr_pair_t *vp;

			while ((vp = fr_pair_list_head(&dst->children)) != NULL) {
				if (fr_edit_list_pair_delete(el, &dst->children, vp) < 0) return -1;
			}

			return 0;
		}

		return fr_edit_list_delete_list(el, &dst->children, src);

	case T_OP_PREPEND:
		if (&dst->children == src) {
			fr_strerror_printf("Cannot prepend list to itself");
			return -1;
		}

		COPY;
		return fr_edit_list_insert_list_head(el, &dst->children, src);

	case T_OP_AND_EQ:
		if (&dst->children == src) return 0; /* A INTERSECTION A == A */

		if (!fr_edit_list_empty(el)) {
		not_empty:
			fr_strerror_printf("Failed to perform %s - undo list is not empty", fr_tokens[op]);
			return -1;
		}

		return list_intersection(el, dst, src);

	case T_OP_OR_EQ:
		if (&dst->children == src) return 0; /* A UNION A == A */

		if (!fr_edit_list_empty(el)) goto not_empty;

		return list_union(el, dst, src, copy);

	case T_OP_GE:
		if (&dst->children == src) return 0; /* A MERGE A == A */

		if (!fr_edit_list_empty(el)) goto not_empty;

		return list_merge_lhs(el, dst, src, copy);

	case T_OP_LE:
		if (&dst->children == src) return 0; /* A MERGE A == A */

		if (!fr_edit_list_empty(el)) goto not_empty;

		return list_merge_rhs(el, dst, src, copy);

	default:
		break;
	}

	fr_strerror_printf("Invalid assignment operator %s for destination type %s",
			   fr_tokens[op],
			   fr_type_to_str(dst->vp_type));
	return -1;
}
