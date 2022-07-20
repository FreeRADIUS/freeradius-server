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
 * @brief fr_pair_t editing
 *
 * @ingroup AVP
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/edit.h>
#include <freeradius-devel/unlang/tmpl.h>
#include <freeradius-devel/unlang/unlang_priv.h>
#include "edit_priv.h"

typedef enum {
	UNLANG_EDIT_INIT = 0,				//!< Start processing a map.
	UNLANG_EDIT_EXPANDED_LHS,			//!< Expand the LHS xlat or exec (if needed).
	UNLANG_EDIT_CHECK_LHS,				//!< check the LHS for things
	UNLANG_EDIT_EXPANDED_RHS,			//!< Expand the RHS xlat or exec (if needed).
	UNLANG_EDIT_CHECK_RHS,				//!< check the LHS for things
} unlang_edit_state_t;

typedef struct {
	fr_value_box_list_t	result;			//!< result of expansion
	tmpl_t const		*vpt;			//!< expanded tmpl
	tmpl_t			*to_free;		//!< tmpl to free.
	fr_pair_t		*vp;			//!< VP referenced by tmpl.  @todo - make it a cursor
	fr_pair_list_t		pair_list;		//!< for structural attributes
} edit_result_t;

typedef struct edit_map_s edit_map_t;

struct edit_map_s {
	fr_edit_list_t		*el;			//!< edit list

	edit_map_t		*parent;
	edit_map_t		*child;

	unlang_edit_state_t	state;			//!< What we're currently doing.
	map_list_t const	*map_head;
	map_t const		*map;			//!< the map to evaluate

	edit_result_t		lhs;			//!< LHS child entries
	edit_result_t		rhs;			//!< RHS child entries
};

/** State of an edit block
 *
 */
typedef struct {
	fr_edit_list_t		*el;				//!< edit list

	edit_map_t		*current;			//!< what we're currently doing.
	edit_map_t		first;
} unlang_frame_state_edit_t;

static int templatize_lhs(TALLOC_CTX *ctx, edit_result_t *out, request_t *request) CC_HINT(nonnull);
static int templatize_rhs(TALLOC_CTX *ctx, edit_result_t *out, fr_pair_t const *lhs, request_t *request) CC_HINT(nonnull);

/*
 *  Convert a value-box list to a LHS #tmpl_t
 */
static int templatize_lhs(TALLOC_CTX *ctx, edit_result_t *out, request_t *request)
{
	ssize_t slen;
	fr_value_box_t *box = fr_dlist_head(&out->result);

	/*
	 *	Mash all of the results together.
	 */
	if (fr_value_box_list_concat_in_place(box, box, &out->result, FR_TYPE_STRING, FR_VALUE_BOX_LIST_FREE, true, SIZE_MAX) < 0) {
		RPEDEBUG("Left side expansion failed");
		return -1;
	}

	/*
	 *	Parse the LHS as an attribute reference.  It can't be
	 *	anything else.
	 */
	slen = tmpl_afrom_attr_str(ctx, NULL, &out->to_free, box->vb_strvalue,
				   &(tmpl_rules_t){
				   	.attr = {
						.dict_def = request->dict,
						.prefix = TMPL_ATTR_REF_PREFIX_NO
					}
				   });
	if (slen <= 0) {
		RPEDEBUG("Left side expansion result \"%s\" is not an attribute reference", box->vb_strvalue);
		return -1;
	}

	out->vpt = out->to_free;
	fr_dlist_talloc_free(&out->result);

	return 0;
}

/*
 *  Convert a value-box list to a RHS #tmpl_t
 *
 *  This doesn't work for structural types.  If "type" is structural,
 *  the calling code should parse the RHS as a set of VPs, and return
 *  that.
 */
static int templatize_rhs(TALLOC_CTX *ctx, edit_result_t *out, fr_pair_t const *lhs, request_t *request)
{
	fr_type_t type = lhs->vp_type;
	fr_type_t cast_type = FR_TYPE_STRING;
	fr_value_box_t *box = fr_dlist_head(&out->result);

	/*
	 *	There's only one box, and it's the correct type.  Just
	 *	return that.  This is the fast path.
	 */
	if (fr_type_is_leaf(type) && (type == box->type) && !fr_dlist_next(&out->result, box)) {
		if (tmpl_afrom_value_box(ctx, &out->to_free, box, false) < 0) return -1;
		goto done;
	}

	if (fr_type_is_structural(type) && (box->type == FR_TYPE_OCTETS)) {
		cast_type = FR_TYPE_OCTETS;
	}

	/*
	 *	Slow path: mash all of the results together as a
	 *	string and then cast it to the correct data type.
	 *
	 *	@todo - if all of the boxes are of the correct type,
	 *	then return a vector.
	 */
	if (fr_value_box_list_concat_in_place(box, box, &out->result, cast_type, FR_VALUE_BOX_LIST_FREE, true, SIZE_MAX) < 0) {
		RPEDEBUG("Right side expansion failed");
		return -1;
	}

	/*
	 *	Leaf types are cast to the correct type.  Either by
	 *	decoding them from octets, or by parsing the string
	 *	values.
	 */
	if (fr_type_is_leaf(type) &&
	    (fr_value_box_cast_in_place(ctx, box, type, lhs->data.enumv) <= 0)) {
		return -1;
	}

	if (tmpl_afrom_value_box(ctx, &out->to_free, box, false) < 0) return -1;

done:
	out->vpt = out->to_free;
	fr_dlist_talloc_free(&out->result);

	return 0;
}

/** Expand a #tmpl_t to a #fr_value_box_list
 *
 *  Which will later be converted by the above functions back to a
 *  "realized" tmpl, which holds a TMPL_TYPE_DATA or TMPL_TYPE_ATTR.
 */
static int template_realize(TALLOC_CTX *ctx, fr_value_box_list_t *list, request_t *request, tmpl_t const *vpt)
{
	switch (vpt->type) {
	case TMPL_TYPE_DATA:
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_LIST:
		return 0;

	case TMPL_TYPE_EXEC:
		if (unlang_tmpl_push(ctx, list, request, vpt, NULL) < 0) return -1;
		return 1;

	case TMPL_TYPE_XLAT:
		if (unlang_xlat_push(ctx, NULL, list, request, tmpl_xlat(vpt), false) < 0) return -1;
		return 1;

	default:
		/*
		 *	The other tmpl types MUST have already been
		 *	converted to the "realized" types.
		 */
		fr_assert(0);
		break;
	}

	return -1;
}

/** Remove VPs for laziness
 *
 */
static int remove_vps(request_t *request, edit_map_t *current)
{
	fr_pair_t *vp, *next, *last;
	fr_pair_list_t *list;
	fr_dict_attr_t const *da;
	int16_t num, count;

	fr_assert(tmpl_is_attr(current->rhs.vpt));
	fr_assert(current->lhs.vp != NULL);
	fr_assert(fr_type_is_structural(current->lhs.vp->vp_type));

	list = &current->lhs.vp->vp_group;
	da = tmpl_da(current->rhs.vpt);

	RDEBUG2("%s %s %s", current->lhs.vpt->name, fr_tokens[T_OP_SUB_EQ], current->rhs.vpt->name);

	num = tmpl_num(current->rhs.vpt);
	count = 0;

	/*
	 *	@todo - tmpl_dcursor, which handles more things.  But
	 *	that isn't done yet.  So we hack stuff here.
	 */
	last = NULL;
	for (vp = fr_pair_list_head(list); vp; vp = next) {
		next = fr_pair_list_next(list, vp);
		if (da == vp->da) {
			if ((num >= 0) && (count == num)) {
				if (fr_edit_list_pair_delete(current->el, list, vp) < 0) return -1;
				break;
			}

			if (num == NUM_ALL) {
				if (fr_edit_list_pair_delete(current->el, list, vp) < 0) return -1;
				continue;
			}

			if (num == NUM_LAST) {
				last = vp;
				continue;
			}

			count++;
		}
	}

	/*
	 *	Delete the last one.
	 */
	if (last) return fr_edit_list_pair_delete(current->el, list, last);

	return 0;
}

/** Apply the edits.  Broken out for simplicity
 *
 *  The edits are applied as:
 *
 *  For leaves, merge RHS #fr_value_box_list_t, so that we have only one #fr_value_box_t
 *
 *  Loop over VPs on the LHS, doing the operation with the RHS.
 *
 *  For now, we only support one VP on the LHS, and one value-box on
 *  the RHS.  Fixing this means updating templatize_rhs() to peek at
 *  the RHS list, and if they're all of the same data type, AND the
 *  same data type as the expected output, leave them alone.  This
 *  lets us do things like:
 *
 *	&Foo-Bar += &Baz[*]
 *
 *  which is an implicit sum over all RHS "Baz" attributes.
 */
static int apply_edits_to_list(request_t *request, edit_map_t *current, map_t const *map)
{
	fr_pair_t *vp;
	fr_pair_list_t *children;
	fr_value_box_t const *rhs_box = NULL;
	bool copy_vps = true;
	int rcode;

	fr_assert(current->lhs.vp != NULL);

#ifdef STATIC_ANALYZER
	if (!current->lhs.vp) return -1;
#endif

	/*
	 *	RHS is a sublist, go apply that.
	 */
	if (!current->rhs.vpt) {
		children = &current->rhs.pair_list;
		copy_vps = false;
		goto apply_list;
	}

	/*
	 *	For RHS of data, it should be a string which contains the pairs to use.
	 */
	if (tmpl_is_data(current->rhs.vpt)) {
		fr_token_t token;
		fr_dict_attr_t const *da;

		rhs_box = tmpl_value(current->rhs.vpt);

		/*
		 *	@todo - just parse the data as a string, and remove it?
		 */
		if (map->op == T_OP_SUB_EQ) {
			REDEBUG("Cannot remove data from a list");
			return -1;
		}

		da = current->lhs.vp->da;
		if (fr_type_is_group(da->type)) da = fr_dict_root(request->dict);

		children = &current->rhs.pair_list;
		copy_vps = false;

		switch (rhs_box->type) {
		case FR_TYPE_STRING:
			/*
			 *	For exec, etc., parse the pair list from a string, in the context of the
			 *	parent VP.  Because we're going to be moving them to the parent VP at some
			 *	point.  The ones which aren't moved will get deleted in this function.
			 *
			 *	@todo - keep parsing until the end.
			 */
			token = fr_pair_list_afrom_str(current->lhs.vp, da, rhs_box->vb_strvalue, rhs_box->length, children);
			if (token == T_INVALID) {
				RPEDEBUG("Failed parsing string as attribute list");
				return -1;
			}

			if (token != T_EOL) {
				REDEBUG("Failed to parse the entire string.");
				return -1;
			}
			break;

		case FR_TYPE_OCTETS:
			/*
			 *	@todo - do something like protocol_decode_xlat / xlat_decode_value_box_list(),
			 *	except all of that requires a decode context :(
			 */


		default:
			fr_strerror_printf("Cannot assign '%s' type to structural type '%s'",
					   fr_type_to_str(rhs_box->type),
					   fr_type_to_str(current->lhs.vp->vp_type));
			return -1;
		}

		goto apply_list;
	}

	/*
	 *	If it's not data, it must be an attribute or a list.
	 */
	if (!tmpl_is_attr(current->rhs.vpt) && !tmpl_is_list(current->rhs.vpt)) {
		REDEBUG("Unknown RHS %s", current->rhs.vpt->name);
		return -1;
	}

	/*
	 *	Remove an attribute from a list.
	 *
	 *	@todo - ensure RHS is only an attribute which is
	 *	parented from the LHS, and that it has no list
	 *	reference?  This probably needs to be done in
	 *	unlang_fixup_edit()
	 */
	if (map->op == T_OP_SUB_EQ) {
		if (!tmpl_is_attr(current->rhs.vpt)) {
			REDEBUG("Cannot remove ??? from list");
			return -1;
		}

		return remove_vps(request, current);
	}

	/*
	 *	Find the RHS attribute / list.
	 *
	 *	@todo - if the LHS is structural, and the operator is
	 *	"-=", then treat the RHS vp as the name of the DA to
	 *	remove from the LHS?  i.e. "remove all DAs of name
	 *	FOO"?
	 */
	if (tmpl_find_vp(&vp, request, current->rhs.vpt) < 0) {
		REDEBUG("Can't find %s", current->rhs.vpt->name);
		return -1;
	}

	fr_assert(current->lhs.vp != NULL);

	/*
	 *	As a special operation, allow "list OP attr", which
	 *	treats the RHS as a one-member list.
	 */
	if (fr_type_is_leaf(vp->vp_type)) {
		fr_pair_t *vp_copy;

		vp_copy = fr_pair_copy(request, vp);
		if (!vp_copy) return -1;

		fr_assert(fr_pair_list_empty(&current->rhs.pair_list));

		fr_pair_append(&current->rhs.pair_list, vp_copy);
		children = &current->rhs.pair_list;
		copy_vps = false;

	} else {
		/*
		 *	List to list operations should be compatible.
		 */
		fr_assert(fr_type_is_structural(vp->vp_type));

		/*
		 *	Forbid copying incompatible structs, TLVs, groups,
		 *	etc.
		 */
		if (!fr_dict_attr_compatible(current->lhs.vp->da, vp->da)) {
			REDEBUG("DAs are incompatible (%s vs %s)",
			       current->lhs.vp->da->name, vp->da->name);
			return -1;
		}

		children = &vp->vp_group; /* and copy_vps for any VP we edit */
	}

	/*
	 *	Apply structural thingies!
	 */
apply_list:
	if (current->rhs.vpt) {
		RDEBUG2("%s %s %s", current->lhs.vpt->name, fr_tokens[map->op], current->rhs.vpt->name);

	} else {
		fr_assert(children != NULL);

		/*
		 *	Print the children before we do the modifications.
		 */
		RDEBUG2("%s %s {", current->lhs.vpt->name, fr_tokens[map->op]);
		if (fr_debug_lvl >= L_DBG_LVL_2) {
			RINDENT();
			xlat_debug_attr_list(request, children);
			REXDENT();
		}

		RDEBUG2("}");
	}

	rcode = fr_edit_list_apply_list_assignment(current->el, current->lhs.vp, map->op, children, copy_vps);
	if (rcode < 0) RPERROR("Failed performing list %s operation", fr_tokens[map->op]);

	/*
	 *	If the child list wasn't copied, then we just created it, and we need to free it.
	 */
	if (!copy_vps) fr_pair_list_free(children);
	return rcode;
}


static int apply_edits_to_leaf(request_t *request, edit_map_t *current, map_t const *map)
{
	fr_pair_t *vp;
	fr_value_box_t const *rhs_box = NULL;

	fr_assert(current->lhs.vp != NULL);

#ifdef STATIC_ANALYZER
	if (!current->lhs.vp) return -1;
#endif

	if (!tmpl_is_attr(current->lhs.vpt)) {
		REDEBUG("The left side of an assignment must be an attribute reference");
		return -1;
	}

	fr_assert(current->rhs.vpt);

	/*
	 *	Any expansions have been turned into data.
	 */
	if (tmpl_is_data(current->rhs.vpt)) {
		rhs_box = tmpl_value(current->rhs.vpt);
		goto assign;

	}

	/*
	 *	If it's not data, it must be an attribute.
	 */
	if (!tmpl_is_attr(current->rhs.vpt)) {
		REDEBUG("Unknown RHS %s", current->rhs.vpt->name);
		return -1;
	}

	/*
	 *	LHS is a leaf.  The RHS must be a leaf.
	 */
	if (!fr_type_is_leaf(tmpl_da(current->rhs.vpt)->type)) {
		REDEBUG("Cannot assign structural %s to leaf %s",
			tmpl_da(current->rhs.vpt)->name, current->lhs.vp->da->name);
		return -1;
	}

	/*
	 *	Find the RHS attribute.
	 */
	if (tmpl_find_vp(&vp, request, current->rhs.vpt) < 0) {
		REDEBUG("Can't find %s", current->rhs.vpt->name);
		return -1;
	}

	rhs_box = &vp->data;

assign:
	RDEBUG2("%s %s %pV", current->lhs.vpt->name, fr_tokens[map->op], rhs_box);

	/*
	 *	The apply function also takes care of
	 *	doing data type upcasting and
	 *	conversion.  So we don't have to check
	 *	for compatibility of the data types on
	 *	the LHS and RHS.
	 */
	if (fr_edit_list_apply_pair_assignment(current->el,
					       current->lhs.vp,
					       map->op,
					       rhs_box) < 0) {
		RPERROR("Failed performing %s operation", fr_tokens[map->op]);
		return -1;
	}

	return 0;
}


/** Create a list of modifications to apply to one or more fr_pair_t lists
 *
 * @param[out] p_result	The rcode indicating what the result
 *      		of the operation was.
 * @param[in] request	The current request.
 * @param[in] frame	Current stack frame.
 * @return
 *	- UNLANG_ACTION_CALCULATE_RESULT changes were applied.
 *	- UNLANG_ACTION_PUSHED_CHILD async execution of an expansion is required.
 */
static unlang_action_t process_edit(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_edit_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_edit_t);
	edit_map_t			*current = state->current;
	map_t const    			*map;
	int				rcode;

redo:
	/*
	 *	Iterate over the maps, expanding the LHS and RHS.
	 */
	for (map = current->map;
	     map != NULL;
	     map = current->map = map_list_next(current->map_head, map)) {
	     	repeatable_set(frame);	/* Call us again when done */

		switch (current->state) {
		case UNLANG_EDIT_INIT:
			fr_assert(fr_dlist_empty(&current->lhs.result));	/* Should have been consumed */
			fr_assert(fr_dlist_empty(&current->rhs.result));	/* Should have been consumed */

			rcode = template_realize(state, &current->lhs.result, request, map->lhs);
			if (rcode < 0) {
			error:
				fr_edit_list_abort(state->el);
				TALLOC_FREE(frame->state);
				repeatable_clear(frame);
				*p_result = RLM_MODULE_NOOP;

				/*
				 *	Expansions, etc. are SOFT
				 *	failures, which simply don't
				 *	apply the operations.
				 */
				return UNLANG_ACTION_CALCULATE_RESULT;
			}

			if (rcode == 1) {
				current->state = UNLANG_EDIT_EXPANDED_LHS;
				return UNLANG_ACTION_PUSHED_CHILD;
			}

			current->state = UNLANG_EDIT_CHECK_LHS; /* data, attr, list */
			current->lhs.vpt = map->lhs;
			goto check_lhs;

		case UNLANG_EDIT_EXPANDED_LHS:
			if (templatize_lhs(state, &current->lhs, request) < 0) goto error;

			current->state = UNLANG_EDIT_CHECK_LHS;
			FALL_THROUGH;

		case UNLANG_EDIT_CHECK_LHS:
		check_lhs:
			if (current->parent) {
				/*
				 *	Child attributes are created in a temporary list.  Any list editing is
				 *	taken care of by the parent map.
				 */
				fr_assert(map->op == T_OP_EQ);

				/*
				 *	We create this VP in the "current" context, so that it's freed on
				 *	error.  If we create it in the LHS VP context, then we have to
				 *	manually free rhs.pair_list on any error.  Creating it in the
				 *	"current" context means we have to reparent it when we move it to the
				 *	parent list, but fr_edit_list_apply_list_assignment() does that
				 *	anyways.
				 */
				MEM(current->lhs.vp = fr_pair_afrom_da(current, tmpl_da(current->lhs.vpt)));
				fr_pair_append(&current->parent->rhs.pair_list, current->lhs.vp);

			} else if (tmpl_find_vp(&current->lhs.vp, request, current->lhs.vpt) < 0) {
				fr_pair_t *parent;

				/*
				 *	Get the list.
				 */
				if ((map->op != T_OP_SET) && (map->op != T_OP_EQ)) {
					REDEBUG("Failed to find %s", current->lhs.vpt->name);
					goto error;
				}

				fr_assert(!tmpl_is_list(current->lhs.vpt));

				/*
				 *	@todo - compile_edit() always sets list_as_attr, and when that
				 *	happens, the tmpl list is _always_ set to 0 (request).
				 *
				 *	What we really need is to create a dcursor, and then do something
				 *	like:
				 *
				 *	vp = tmpl_dcursor_init(&err, request, &cc, &cursor, request, vpt);
				 *	if (!vp) {
				 *		while (tmpl_dcursor_required(&cursor, &vp, &da) == 1) {
				 *			child = fr_pair_afrom_da(vp, da);
				 *			fr_pair_append(&vp->vp_group, child);
				 *		}
				 *		// vp is the pair we need to edit.
				 *	}
				 */
				parent = tmpl_get_list(request, current->lhs.vpt);
				if (!parent) {
					REDEBUG("Failed to find list for %s", current->lhs.vpt->name);
					goto error;
				}

				/*
				 *	Add the new VP to the parent.  The edit list code is safe for multiple
				 *	edits of the same VP, so we don't have to do anything else here.
				 */
				MEM(current->lhs.vp = fr_pair_afrom_da(parent, tmpl_da(current->lhs.vpt)));
				if (fr_edit_list_insert_pair_tail(state->el, &parent->vp_group, current->lhs.vp) < 0) goto error;

			} else if (map->op == T_OP_EQ) {
				/*
				 *	We're setting the value, but the attribute already exists.  This is a
				 *	NOOP.
				 */
				goto next;
			}

			/*
			 *	Leaf attributes MUST have a RHS.
			 *	Structural attributes MAY have a RHS.
			 */
			if (!map->rhs) {
				edit_map_t *child = current->child;

				if (fr_type_is_leaf(current->lhs.vp->vp_type)) {
					REDEBUG("Cannot assign list to a non-list data type");
					goto error;
				}

				/*
				 *	Fast path: child is empty, we don't need to do anything.
				 */
				if (fr_dlist_empty(&map->child.head)) {
					goto check_rhs_list;
				}

				/*
				 *	Allocate a new child structure if necessary.
				 */
				if (!child) {
					MEM(child = talloc_zero(state, edit_map_t));
					current->child = child;
					child->parent = current;
				}

				/*
				 *	Initialize the child structure.  There's no edit list here, as we're
				 *	creating a temporary pair list.  Any edits to this list aren't
				 *	tracked, as it only exists in current->parent->rhs.pair_list.
				 *
				 *	The parent edit_state_t will take care of applying any edits to the
				 *	parent vp.  Any child pairs which aren't used will be freed.
				 */
				child->state = UNLANG_EDIT_INIT;
				child->el = NULL;
				child->map_head = &map->child;
				child->map = map_list_head(child->map_head);

				memset(&child->lhs, 0, sizeof(child->lhs));
				memset(&child->rhs, 0, sizeof(child->rhs));

				fr_pair_list_init(&child->rhs.pair_list);
				fr_value_box_list_init(&child->lhs.result);
				fr_value_box_list_init(&child->rhs.result);

				/*
				 *	Continue back with the expanded RHS when we're done expanding the
				 *	child.  The go process the child.
				 */
				current->state = UNLANG_EDIT_EXPANDED_RHS;
				state->current = child;
				goto redo;
			}

			rcode = template_realize(state, &current->rhs.result, request, map->rhs);
			if (rcode < 0) goto error;

			if (rcode == 1) {
				current->state = UNLANG_EDIT_EXPANDED_RHS;
				return UNLANG_ACTION_PUSHED_CHILD;
			}

			current->state = UNLANG_EDIT_CHECK_RHS;
			current->rhs.vpt = map->rhs;
			goto check_rhs;

		case UNLANG_EDIT_EXPANDED_RHS:
#ifdef STATIC_ANALYZER
			if (!current->lhs.vp) goto error;
#endif

			if (templatize_rhs(state, &current->rhs, current->lhs.vp, request) < 0) goto error;

			current->state = UNLANG_EDIT_CHECK_RHS;
			FALL_THROUGH;

		case UNLANG_EDIT_CHECK_RHS:
		check_rhs:
			fr_assert(current->lhs.vp != NULL);

			if (fr_type_is_leaf(current->lhs.vp->da->type)) {
				if (apply_edits_to_leaf(request, current, map) < 0) goto error;
			} else {
		check_rhs_list:
				if (apply_edits_to_list(request, current, map) < 0) goto error;
			}

		next:
			current->state = UNLANG_EDIT_INIT;
			TALLOC_FREE(current->lhs.to_free);
			TALLOC_FREE(current->rhs.to_free);
			fr_pair_list_free(&current->rhs.pair_list);
			current->lhs.vp = NULL;
			break;
		}

	} /* loop over the map */

	/*
	 *	There's a parent map, go update that.
	 */
	if (current->parent) {
		state->current = current->parent;
		goto redo;
	}

	/*
	 *	Freeing the edit list will automatically commit the edits.
	 */

	*p_result = RLM_MODULE_NOOP;
	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Execute an update block
 *
 * Update blocks execute in two phases, first there's an evaluation phase where
 * each input map is evaluated, outputting one or more modification maps. The modification
 * maps detail a change that should be made to a list in the current request.
 * The request is not modified during this phase.
 *
 * The second phase applies those modification maps to the current request.
 * This re-enables the atomic functionality of update blocks provided in v2.x.x.
 * If one map fails in the evaluation phase, no more maps are processed, and the current
 * result is discarded.
 */
static unlang_action_t unlang_edit_state_init(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_edit_t			*edit = unlang_generic_to_edit(frame->instruction);
	unlang_frame_state_edit_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_edit_t);
	edit_map_t			*current = &state->first;

	state->current = current;
	fr_value_box_list_init(&current->lhs.result);
	fr_value_box_list_init(&current->rhs.result);

	/*
	 *	The edit list creates a local pool which should
	 *	generally be large enough for most edits.
	 */
	MEM(state->el = fr_edit_list_alloc(state, map_list_num_elements(&edit->maps)));

	current->el = state->el;
	current->map_head = &edit->maps;
	current->map = map_list_head(current->map_head);
	fr_pair_list_init(&current->rhs.pair_list);

	/*
	 *	Call process_edit to do all of the work.
	 */
	frame_repeat(frame, process_edit);
	return process_edit(p_result, request, frame);
}


void unlang_edit_init(void)
{
	unlang_register(UNLANG_TYPE_EDIT,
			   &(unlang_op_t){
				.name = "edit",
				.interpret = unlang_edit_state_init,
				.frame_state_size = sizeof(unlang_frame_state_edit_t),
				.frame_state_type = "unlang_frame_state_edit_t",
			   });
}
