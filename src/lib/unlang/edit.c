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

/** State of an edit block
 *
 */
typedef struct {
	fr_edit_list_t		*el;				//!< edit list

	unlang_edit_state_t	state;				//!< What we're currently doing.
	fr_map_list_t const	*map_head;
	map_t const		*map;				//!< the map to evaluate

	edit_result_t		lhs;				//!< LHS child entries
	edit_result_t		rhs;				//!< RHS child entries
} unlang_frame_state_edit_t;

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
					   .dict_def = request->dict,
					   .prefix = TMPL_ATTR_REF_PREFIX_NO
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
	ssize_t slen;
	bool is_string;
	fr_type_t type = lhs->vp_type;
	fr_value_box_t *box = fr_dlist_head(&out->result);

	/*
	 *	There's only one box, and it's the correct type.  Just
	 *	return that.  This is the fast path.
	 */
	if ((type != FR_TYPE_STRING) && (type == box->type) && !fr_dlist_next(&out->result, box)) {
		if (tmpl_afrom_value_box(ctx, &out->to_free, box, false) < 0) return -1;
		goto done;
	}

	/*
	 *	If the first value box is NOT a string, then
	 *	we're pretty darned sure that it's not an attribute
	 *	reference.  In which case don't even bother trying to
	 *	parse it as an attribute reference.
	 */
	is_string = (box->type == FR_TYPE_STRING);

	/*
	 *	Slow path: mash all of the results together as a
	 *	string and then cast it to the correct data type.
	 */
	if (fr_value_box_list_concat_in_place(box, box, &out->result, FR_TYPE_STRING, FR_VALUE_BOX_LIST_FREE, true, SIZE_MAX) < 0) {
		RPEDEBUG("Right side expansion failed");
		return -1;
	}

	/*
	 *	If the LHS is structural, the RHS MAY be an attribute
	 *	reference, or it MAY be an in-place string list.
	 */
	if (fr_type_is_structural(type)) {
		type = FR_TYPE_STRING;
	}

	/*
	 *	If the first box was of type string, AND the
	 *	concatenated string has a leading '&', then it MIGHT
	 *	be an attribute reference.
	 */
	if (is_string && (box->length > 1) && (box->vb_strvalue[0] == '&')) {
		slen = tmpl_afrom_attr_str(ctx, NULL, &out->to_free, box->vb_strvalue,
					   &(tmpl_rules_t){
						   .dict_def = request->dict,
						   .prefix = TMPL_ATTR_REF_PREFIX_NO
					   });
		if (slen > 0) goto done;
	}

	/*
	 *	The concatenated string is not an attribute reference.
	 *	It MUST be parsed as a value of the input data type.
	 */
	if ((fr_value_box_cast_in_place(ctx, box, type, lhs->data.enumv) <= 0) ||
	    (tmpl_afrom_value_box(ctx, &out->to_free, box, false) < 0)) {
		return -1;
	}

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
static int apply_edits(request_t *request, unlang_frame_state_edit_t *state, map_t const *map)
{
	fr_pair_t *vp, *vp_to_free = NULL;
	fr_pair_list_t *children;
	fr_value_box_t const *rhs_box = NULL;

	fr_assert(state->rhs.vpt != NULL);

	/*
	 *	Get the resulting value box.
	 */
	if (tmpl_is_data(state->rhs.vpt)) {
		fr_token_t token;
		fr_dict_attr_t const *da;

		rhs_box = tmpl_value(state->rhs.vpt);

		if (fr_type_is_leaf(state->lhs.vp->vp_type)) {
			goto leaf;
		}

		fr_assert(rhs_box->type == FR_TYPE_STRING);

		da = state->lhs.vp->da;
		if (fr_type_is_group(da->type)) da = fr_dict_root(request->dict);

		children = &state->rhs.pair_list;

		/*
		 *	@todo - keep parsing until the end.
		 */
		token = fr_pair_list_afrom_str(state, da, rhs_box->vb_strvalue, rhs_box->length, children);
		if (token == T_INVALID) {
			RPEDEBUG("Failed parsing string as attribute list");
			return -1;
		}

		goto apply_list;
	}

	/*
	 *	If it's not data, it must be an attribute or a list.
	 */
	if (!tmpl_is_attr(state->rhs.vpt) && !tmpl_is_list(state->rhs.vpt)) {
		RERROR("Unknown RHS %s", state->rhs.vpt->name);
		return -1;
	}

	/*
	 *	Find the RHS attribute / list.
	 *
	 *	@todo - if the LHS is structural, and the operator is
	 *	"-=", then treat the RHS vp as the name of the DA to
	 *	remove from the LHS?  i.e. "remove all DAs of name
	 *	FOO"?
	 */
	if (tmpl_find_vp(&vp, request, state->rhs.vpt) < 0) {
		RERROR("Can't find %s", state->rhs.vpt->name);
		return -1;
	}

	fr_assert(state->lhs.vp != NULL);

	/*
	 *	LHS is a leaf.  The RHS must be a leaf.
	 *
	 *	@todo - or RHS is a list of boxes of the same data
	 *	type.
	 */
	if (fr_type_is_leaf(state->lhs.vp->vp_type)) {
		if (!fr_type_is_leaf(vp->vp_type)) {
			REDEBUG("Cannot assign structural %s to leaf %s",
				vp->da->name, state->lhs.vp->da->name);
			return -1;
		}

		rhs_box = &vp->data;
		goto leaf;
	}

	fr_assert(fr_type_is_structural(state->lhs.vp->vp_type));

	/*
	 *	As a special operation, allow "list OP attr", which
	 *	treats the RHS as a one-member list.
	 */
	if (fr_type_is_leaf(vp->vp_type)) {
		vp_to_free = fr_pair_copy(request, vp);
		if (!vp_to_free) return -1;

		fr_assert(fr_pair_list_empty(&state->rhs.pair_list));

		fr_pair_append(&state->rhs.pair_list, vp_to_free);
		children = &state->rhs.pair_list;

		vp_to_free = NULL; /* it's not in the pair list, and will be freed there */

	} else {
		/*
		 *	List to list operations should be compatible.
		 */
		fr_assert(fr_type_is_structural(vp->vp_type));

		/*
		 *	Forbid copying incompatible structs, TLVs, groups,
		 *	etc.
		 */
		if (!fr_dict_attr_compatible(state->lhs.vp->da, vp->da)) {
			RERROR("DAs are incompatible (%s vs %s)",
			       state->lhs.vp->da->name, vp->da->name);
			return -1;
		}

		children = &vp->children;
	}

	/*
	 *	Apply structural thingies!
	 */
apply_list:
	RDEBUG2("%s %s %s", state->lhs.vpt->name, fr_tokens[map->op], state->rhs.vpt->name);

	if (fr_debug_lvl >= L_DBG_LVL_3) {
		RINDENT();
		fr_pair_list_debug(children);
		REXDENT();
	}

	if (fr_edit_list_apply_list_assignment(state->el,
					       state->lhs.vp,
					       map->op,
					       children) < 0) {
		RPERROR("Failed performing list %s operation", fr_tokens[map->op]);
		talloc_free(vp_to_free);
		return -1;
	}

	talloc_free(vp_to_free);
	return 0;

leaf:
	/*
	 *	The leaf assignment also checks many
	 *	of these, but not all of them.
	 */
	if (!tmpl_is_attr(state->lhs.vpt) || !state->lhs.vp ||
	    !fr_type_is_leaf(state->lhs.vp->vp_type)) {
		RERROR("Cannot assign data to list %s", map->lhs->name);
		return -1;
	}

	RDEBUG2("%s %s %pV", state->lhs.vpt->name, fr_tokens[map->op], rhs_box);

	/*
	 *	The apply function also takes care of
	 *	doing data type upcasting and
	 *	conversion.  So we don't have to check
	 *	for compatibility of the data types on
	 *	the LHS and RHS.
	 */
	if (fr_edit_list_apply_pair_assignment(state->el,
					       state->lhs.vp,
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
	map_t const    			*map;
	int				rcode;

	/*
	 *	Iterate over the maps, expanding the LHS and RHS.
	 */
	for (map = state->map;
	     map != NULL;
	     map = state->map = fr_map_list_next(state->map_head, map)) {
	     	repeatable_set(frame);	/* Call us again when done */

		switch (state->state) {
		case UNLANG_EDIT_INIT:
			fr_assert(fr_dlist_empty(&state->lhs.result));	/* Should have been consumed */
			fr_assert(fr_dlist_empty(&state->rhs.result));	/* Should have been consumed */

			rcode = template_realize(state, &state->lhs.result, request, map->lhs);
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
				state->state = UNLANG_EDIT_EXPANDED_LHS;
				return UNLANG_ACTION_PUSHED_CHILD;
			}

			state->state = UNLANG_EDIT_CHECK_LHS; /* data, attr, list */
			state->lhs.vpt = map->lhs;
			goto check_lhs;

		case UNLANG_EDIT_EXPANDED_LHS:
			if (templatize_lhs(state, &state->lhs, request) < 0) goto error;

			state->state = UNLANG_EDIT_CHECK_LHS;
			FALL_THROUGH;

		case UNLANG_EDIT_CHECK_LHS:
		check_lhs:
			/*
			 *	Find the LHS VP.  If it doesn't exist,
			 *	return an error.  Note that this means
			 *	":=" and "=" don't yet work.
			 *
			 *	@todo - the "find vp" function needs
			 *	to return the parent list, for
			 *	T_OP_SET and T_OP_EQ, so that we can
			 *	add the newly created attribute to the
			 *	parent list.
			 */
			if (tmpl_find_vp(&state->lhs.vp, request, state->lhs.vpt) < 0) {
				if (map->op == T_OP_EQ) goto next;

				REDEBUG("Failed to find %s", state->lhs.vpt->name);
				goto error;
			}

			rcode = template_realize(state, &state->rhs.result, request, map->rhs);
			if (rcode < 0) goto error;

			if (rcode == 1) {
				state->state = UNLANG_EDIT_EXPANDED_RHS;
				return UNLANG_ACTION_PUSHED_CHILD;
			}

			state->state = UNLANG_EDIT_CHECK_RHS;
			state->rhs.vpt = map->rhs;
			goto check_rhs;

		case UNLANG_EDIT_EXPANDED_RHS:
			if (templatize_rhs(state, &state->rhs, state->lhs.vp, request) < 0) goto error;

			state->state = UNLANG_EDIT_CHECK_RHS;
			FALL_THROUGH;

		case UNLANG_EDIT_CHECK_RHS:
		check_rhs:
			if (apply_edits(request, state, map) < 0) goto error;

		next:
			state->state = UNLANG_EDIT_INIT;
			TALLOC_FREE(state->lhs.to_free);
			TALLOC_FREE(state->rhs.to_free);
			fr_pair_list_free(&state->rhs.pair_list);
			state->lhs.vp = NULL;
			break;
		}

	} /* loop over the map */

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

	fr_value_box_list_init(&state->lhs.result);
	fr_value_box_list_init(&state->rhs.result);

	/*
	 *	The edit list creates a local pool which should
	 *	generally be large enough for most edits.
	 */
	MEM(state->el = fr_edit_list_alloc(state, fr_map_list_num_elements(&edit->maps)));

	state->map_head = &edit->maps;
	state->map = fr_map_list_head(state->map_head);
	fr_pair_list_init(&state->rhs.pair_list);

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
