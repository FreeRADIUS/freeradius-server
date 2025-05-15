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
 * @file unlang/foreach.c
 * @brief Unlang "foreach" keyword evaluation.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/unlang/xlat_func.h>

#include "foreach_priv.h"
#include "return_priv.h"
#include "xlat_priv.h"

#define BUFFER_SIZE (256)

/** State of a foreach loop
 *
 */
typedef struct {
	request_t		*request;			//!< The current request.
	fr_dcursor_t		cursor;				//!< Used to track our place in the list
	fr_pair_t		*key;				//!< local variable which contains the key
	fr_pair_t		*value;				//!< local variable which contains the value
	tmpl_t const		*vpt;				//!< pointer to the vpt

	uint32_t		index;				//!< for xlat results
	char			*buffer;			//!< for key values

	bool			success;			//!< for xlat expansion
	fr_value_box_list_t	list;				//!< value box list for looping over xlats

	tmpl_dcursor_ctx_t	cc;				//!< tmpl cursor state

#ifndef NDEBUG
	int			indent;				//!< for catching indentation issues
#endif
} unlang_frame_state_foreach_t;

/*
 *	Brute-force things instead of doing it the "right" way.
 *
 *	We would ideally like to have the local variable be a ref to the current vp from the cursor.  However,
 *	that isn't (yet) supported.  We do have #FR_TYPE_PAIR_CURSOR, but there is no way to save the cursor,
 *	or address it.  See also xlat_expr.c for notes on using '$$' to refer to a cursor.  Maybe we need a
 *	new magic "list", which is called "cursor", or "self"?  That way we can also address parent cursors?
 *
 *	In order to support that, we would have to update a lot of things:
 *
 *	- the foreach code has not just create a local attribute, but mark up that attribute as it's really a cursor".
 *	- maybe we also need to put the cursor into its own stack frame?  Or have it as a common field
 *	  in every frame?
 *	- the tmpl code has to be updated so that when you reference a "cursor attribute", it finds the cursor,
 *	  and edits the pair associated with the cursor
 *	- update tmpl_eval_pair(), because that's what's used in the xlat code.  That gets us all
 *	  references to the _source_ VP.
 *	- we also have to update the edit.c code, which calls tmpl_dcursor_init() to get pairs from
 *	  a tmpl_t of type ATTR.
 *	- for LHS assignment, the edit code has to be updated: apply_edits_to_leaf() and apply_edits_to_list()
 *	  which calls fr_edit_list_apply_pair_assignment() to do the actual work.  But we could likely just
 *	  check current->lhs.vp, and dereference that to get the underlying thing.
 *
 *  What we ACTUALLY do instead is in the compiler when we call define_local_variable(), we clone the "da"
 *  hierarchy via fr_dict_attr_acopy_local().  That function which should go away when we add refs.
 *
 *  Then this horrific function copies the pairs by number, which re-parents them to the correct
 *  destination da.  It's brute-force and expensive, but it's easy.  And for now, it's less work than
 *  re-doing substantial parts of the server core and utility libraries.
 */
static int unlang_foreach_pair_copy(fr_pair_t *to, fr_pair_t *from, fr_dict_attr_t const *from_parent)
{
	fr_assert(fr_type_is_structural(to->vp_type));
	fr_assert(fr_type_is_structural(from->vp_type));

	fr_pair_list_foreach(&from->vp_group, vp) {
		fr_pair_t *child;

		/*
		 *	We only copy children of the parent TLV, but we can copy internal attributes, as they
		 *	can exist anywhere.
		 */
		if (vp->da->parent != from_parent) {
			if (vp->da->flags.internal) {
				child = fr_pair_copy(to, vp);
				if (child) fr_pair_append(&to->vp_group, child);
			}
			continue;
		}

		child = fr_pair_afrom_child_num(to, to->da, vp->da->attr);
		if (!child) continue;

		fr_pair_append(&to->vp_group, child);

		if (fr_type_is_leaf(child->vp_type)) {
			if (fr_value_box_copy(child, &child->data, &vp->data) < 0) return -1;
			continue;
		}

		fr_assert(fr_type_is_structural(vp->vp_type));

		if (unlang_foreach_pair_copy(child, vp, vp->da) < 0) return -1;
	}

	return 0;
}

/** Ensure request data is pulled out of the request if the frame is popped
 *
 */
static int _free_unlang_frame_state_foreach(unlang_frame_state_foreach_t *state)
{
	request_t *request = state->request;
	fr_pair_t *vp;

	fr_assert(state->value);

	if (tmpl_is_xlat(state->vpt)) return 0;

	tmpl_dcursor_clear(&state->cc);

	/*
	 *	Now that we're done, the leaf entries can be changed again.
	 */
	vp = tmpl_dcursor_init(NULL, NULL, &state->cc, &state->cursor, request, state->vpt);
	if (!vp) {
		tmpl_dcursor_clear(&state->cc);
		return 0;
	}
	do {
		vp->vp_edit = false;
	} while ((vp = fr_dcursor_next(&state->cursor)) != NULL);
	tmpl_dcursor_clear(&state->cc);

	return 0;
}

static int unlang_foreach_xlat_key_update(request_t *request, unlang_frame_state_foreach_t *state)
{
	fr_value_box_t box;

	if (!state->key) return 0;

	fr_value_box_clear_value(&state->key->data);

	fr_value_box(&box, state->index, false);

	if (fr_value_box_cast(state->key, &state->key->data, state->key->vp_type, state->key->da, &box) < 0) {
		RDEBUG("Failed casting 'foreach' key variable '%s' from %u", state->key->da->name, state->index);
		return -1;
	}

	return 0;
}


static unlang_action_t unlang_foreach_xlat_next(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_foreach_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_foreach_t);
	fr_value_box_t *box;

next:
	state->index++;

	box = fr_dcursor_next(&state->cursor);
	if (!box) {
		*p_result = frame->result;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	if (unlang_foreach_xlat_key_update(request, state) < 0) goto next;

	fr_value_box_clear_value(&state->value->data);
	if (fr_value_box_cast(state->value, &state->value->data, state->value->vp_type, state->value->da, box) < 0) {
		RDEBUG("Failed casting 'foreach' iteration variable '%s' from %pV", state->value->da->name, box);
		goto next;
	}

	repeatable_set(frame);

	/*
	 *	Push the child, and yield for a later return.
	 */
	return unlang_interpret_push_children(p_result, request, frame->result, UNLANG_NEXT_SIBLING);
}


static unlang_action_t unlang_foreach_xlat_expanded(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_foreach_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_foreach_t);
	fr_value_box_t *box;

	if (!state->success) {
		RDEBUG("Failed expanding 'foreach' list");
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	box = fr_dcursor_init(&state->cursor, fr_value_box_list_dlist_head(&state->list));
	if (!box) {
	done:
		*p_result = RLM_MODULE_NOOP;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	fr_value_box_clear_value(&state->value->data);

next:
	if (fr_value_box_cast(state->value, &state->value->data, state->value->vp_type, state->value->da, box) < 0) {
		RDEBUG("Failed casting 'foreach' iteration variable '%s' from %pV", state->value->da->name, box);
		box = fr_dcursor_next(&state->cursor);
		if (!box) goto done;

		goto next;
	}

	frame->process = unlang_foreach_xlat_next;
	repeatable_set(frame);

	/*
	 *	Push the child, and yield for a later return.
	 */
	return unlang_interpret_push_children(p_result, request, frame->result, UNLANG_NEXT_SIBLING);
}


/*
 *	Loop over an xlat expansion
 */
static unlang_action_t unlang_foreach_xlat_init(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame,
						unlang_frame_state_foreach_t *state)
{
	fr_value_box_list_init(&state->list);

	if (unlang_xlat_push(state, &state->success, &state->list, request, tmpl_xlat(state->vpt), false) < 0) {
		REDEBUG("Failed starting expansion of %s", state->vpt->name);
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	if (unlang_foreach_xlat_key_update(request, state) < 0) {
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

  	frame->process = unlang_foreach_xlat_expanded;
	repeatable_set(frame);

	return UNLANG_ACTION_PUSHED_CHILD;
}

static void unlang_foreach_attr_key_update(UNUSED request_t *request, unlang_frame_state_foreach_t *state)
{
	if (!state->key) return;

	switch (state->key->vp_type) {
	case FR_TYPE_UINT32:
		state->key->vp_uint32++;
		break;

	case FR_TYPE_STRING:
		fr_value_box_clear_value(&state->key->data);
		if (tmpl_dcursor_print(&FR_SBUFF_IN(state->buffer, BUFFER_SIZE), &state->cc) > 0) {
			fr_value_box_strdup(state->key, &state->key->data, NULL, state->buffer, false);
		}
		break;

	default:
		fr_assert(0);
		break;

	}
}

static unlang_action_t unlang_foreach_attr_next(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_foreach_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_foreach_t);
	fr_pair_t			*vp;

	vp = fr_dcursor_current(&state->cursor);
	fr_assert(vp != NULL);

	/*
	 *	If we modified the value, copy it back to the original pair.  Note that the copy does NOT
	 *	check the "immutable" flag.  That flag is for the people using unlang, not for the
	 *	interpreter.
	 */
	if (fr_type_is_leaf(vp->vp_type)) {
		if (vp->vp_type == state->value->vp_type) {
			fr_value_box_clear_value(&vp->data);
			(void) fr_value_box_copy(vp, &vp->data, &state->value->data);
		} else {
			/*
			 *	@todo - this shouldn't happen?
			 */
		}
	} else {
		fr_assert(fr_type_is_structural(vp->vp_type));

		/*
		 *	@todo - copy the pairs back?
		 */
	}

next:
	vp = fr_dcursor_next(&state->cursor);
	if (!vp) {
		*p_result = frame->result;
#ifndef NDEBUG
		fr_assert(state->indent == request->log.indent.unlang);
#endif
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	unlang_foreach_attr_key_update(request, state);

	/*
	 *	Copy the data.
	 */
	if (vp->vp_type == FR_TYPE_GROUP) {
		fr_assert(state->value->vp_type == FR_TYPE_GROUP);

		fr_pair_list_free(&state->value->vp_group);

		if (fr_pair_list_copy(state->value, &state->value->vp_group, &vp->vp_group) < 0) {
			REDEBUG("Failed copying members of %s", state->value->da->name);
			*p_result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

	} else if (fr_type_is_structural(vp->vp_type)) {
		if (state->value->vp_type != vp->vp_type) goto next;

		fr_pair_list_free(&state->value->vp_group);

		if (unlang_foreach_pair_copy(state->value, vp, vp->da) < 0) {
			REDEBUG("Failed copying children of %s", state->value->da->name);
			*p_result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

	} else {
		fr_value_box_clear_value(&state->value->data);
		if (fr_value_box_cast(state->value, &state->value->data, state->value->vp_type, state->value->da, &vp->data) < 0) {
			RDEBUG("Failed casting 'foreach' iteration variable '%s' from %pP", state->value->da->name, vp);
			goto next;
		}

#ifndef NDEBUG
		RDEBUG2("# looping with: %s = %pV", state->value->da->name, &vp->data);
#endif
	}

	repeatable_set(frame);

	/*
	 *	Push the child, and yield for a later return.
	 */
	return unlang_interpret_push_children(p_result, request, frame->result, UNLANG_NEXT_SIBLING);
}

/*
 *	Loop over an attribute
 */
static unlang_action_t unlang_foreach_attr_init(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame,
						unlang_frame_state_foreach_t *state)
{
	fr_pair_t			*vp;

	/*
	 *	No matching attributes, we can't do anything.
	 */
	vp = tmpl_dcursor_init(NULL, NULL, &state->cc, &state->cursor, request, state->vpt);
	if (!vp) {
		tmpl_dcursor_clear(&state->cc);
		*p_result = RLM_MODULE_NOOP;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Before we loop over the variables, ensure that the user can't pull the rug out from
	 *	under us.
	 */
	do {
		if (vp->vp_edit) {
			REDEBUG("Cannot do nested 'foreach' loops over the same attribute %pP", vp);
		fail:
			tmpl_dcursor_clear(&state->cc);
			*p_result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		vp->vp_edit = true;
	} while ((vp = fr_dcursor_next(&state->cursor)) != NULL);
	tmpl_dcursor_clear(&state->cc);

	vp = tmpl_dcursor_init(NULL, NULL, &state->cc, &state->cursor, request, state->vpt);
	fr_assert(vp != NULL);

next:
	/*
	 *	Update the key with the current path.  Attribute indexes start at zero.
	 */
	if (state->key && (state->key->vp_type == FR_TYPE_STRING)) unlang_foreach_attr_key_update(request, state);

	if (vp->vp_type == FR_TYPE_GROUP) {
		fr_assert(state->value->vp_type == FR_TYPE_GROUP);

		if (fr_pair_list_copy(state->value, &state->value->vp_group, &vp->vp_group) < 0) {
			REDEBUG("Failed copying members of %s", state->value->da->name);
			goto fail;
		}

	} else if (fr_type_is_structural(vp->vp_type)) {
		if (state->value->vp_type != vp->vp_type) {
			vp = fr_dcursor_next(&state->cursor);
			if (vp) goto next;

			*p_result = frame->result;
			fr_assert(state->indent == request->log.indent.unlang);
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		if (unlang_foreach_pair_copy(state->value, vp, vp->da) < 0) {
			REDEBUG("Failed copying children of %s", state->value->da->name);
			goto fail;
		}

	} else {
		fr_value_box_clear_value(&state->value->data);
		while (vp && (fr_value_box_cast(state->value, &state->value->data, state->value->vp_type, state->value->da, &vp->data) < 0)) {
			RDEBUG("Failed casting 'foreach' iteration variable '%s' from %pP", state->value->da->name, vp);
			vp = fr_dcursor_next(&state->cursor);
		}

		/*
		 *	Couldn't cast anything, the loop can't be run.
		 */
		if (!vp) {
			tmpl_dcursor_clear(&state->cc);
			*p_result = RLM_MODULE_NOOP;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

	frame->process = unlang_foreach_attr_next;

	repeatable_set(frame);

	/*
	 *	Push the child, and go process it.
	 */
	return unlang_interpret_push_children(p_result, request, frame->result, UNLANG_NEXT_SIBLING);
}


static unlang_action_t unlang_foreach(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	unlang_foreach_t		*gext = unlang_group_to_foreach(g);
	unlang_frame_state_foreach_t	*state;

	MEM(frame->state = state = talloc_zero(request->stack, unlang_frame_state_foreach_t));
	talloc_set_destructor(state, _free_unlang_frame_state_foreach);

	state->request = request;
#ifndef NDEBUG
	state->indent = request->log.indent.unlang;
#endif

	/*
	 *	Get the value.
	 */
	fr_assert(gext->value);

	state->vpt = gext->vpt;

	fr_assert(fr_pair_find_by_da(&request->local_pairs, NULL, gext->value) == NULL);

	/*
	 *	Create the local variable and populate its value.
	 */
	if (fr_pair_append_by_da(request->local_ctx, &state->value, &request->local_pairs, gext->value) < 0) {
		REDEBUG("Failed creating %s", gext->value->name);
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}
	fr_assert(state->value != NULL);

	if (gext->key) {
		fr_assert(fr_pair_find_by_da(&request->local_pairs, NULL, gext->key) == NULL);

		if (fr_pair_append_by_da(request->local_ctx, &state->key, &request->local_pairs, gext->key) < 0) {
			REDEBUG("Failed creating %s", gext->key->name);
			*p_result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
		fr_assert(state->key != NULL);
	}

	if (tmpl_is_attr(gext->vpt)) {
		MEM(state->buffer = talloc_array(state, char, BUFFER_SIZE));
		return unlang_foreach_attr_init(p_result, request, frame, state);
	}

	fr_assert(tmpl_is_xlat(gext->vpt));

	return unlang_foreach_xlat_init(p_result, request, frame, state);
}

static unlang_action_t unlang_break(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_action_t			ua;
	unlang_stack_t			*stack = request->stack;
	unsigned int break_depth;

	RDEBUG2("%s", unlang_ops[frame->instruction->type].name);

	*p_result = frame->result;

	/*
	 *	Stop at the next break point, or if we hit
	 *	the a top frame.
	 */
	ua = unwind_to_op_flag(&break_depth, request->stack, UNLANG_OP_FLAG_BREAK_POINT);
	repeatable_clear(&stack->frame[break_depth]);
	return ua;
}

static unlang_action_t unlang_continue(UNUSED rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_stack_t			*stack = request->stack;

	RDEBUG2("%s", unlang_ops[frame->instruction->type].name);

	return unwind_to_op_flag(NULL, stack, UNLANG_OP_FLAG_CONTINUE_POINT);
}

void unlang_foreach_init(void)
{
	unlang_register(UNLANG_TYPE_FOREACH,
			   &(unlang_op_t){
				.name = "foreach",
				.interpret = unlang_foreach,
				.flag = UNLANG_OP_FLAG_DEBUG_BRACES | UNLANG_OP_FLAG_BREAK_POINT | UNLANG_OP_FLAG_CONTINUE_POINT
			   });

	unlang_register(UNLANG_TYPE_BREAK,
			   &(unlang_op_t){
				.name = "break",
				.interpret = unlang_break,
			   });

	unlang_register(UNLANG_TYPE_CONTINUE,
			   &(unlang_op_t){
				.name = "continue",
				.interpret = unlang_continue,
			   });
}
