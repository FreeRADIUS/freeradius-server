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

#include <freeradius-devel/server/request_data.h>
#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/unlang/xlat_func.h>

#include "foreach_priv.h"
#include "return_priv.h"
#include "xlat_priv.h"

static char const * const xlat_foreach_names[] = {"Foreach-Variable-0",
						  "Foreach-Variable-1",
						  "Foreach-Variable-2",
						  "Foreach-Variable-3",
						  "Foreach-Variable-4",
						  "Foreach-Variable-5",
						  "Foreach-Variable-6",
						  "Foreach-Variable-7",
						  "Foreach-Variable-8",
						  "Foreach-Variable-9"};

static int xlat_foreach_inst[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };	/* up to 10 for foreach */

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

								///< we're iterating over.
	fr_pair_list_t 		vps;				//!< List containing the attribute(s) we're
								///< iterating over.
	int			depth;				//!< Level of nesting of this foreach loop.
#ifndef NDEBUG
	int			indent;				//!< for catching indentation issues
#endif
} unlang_frame_state_foreach_t;

/*
 *	Brute-force things instead of doing it the "right" way.
 *
 *	We would ideally like to have the local variable be a ref to the current vp from the cursor.  However,
 *	that isn't (yet) supported.  In order to support that, we would likely have to add a new data type
 *	FR_TYPE_DCURSOR, and put the cursor into in vp->vp_ptr.  We would then have to update a lot of things:
 *
 *	- the foreach code has to put the dcursor into state->value->vp_ptr.
 *	- the pair code (all of it, perhaps) has to check for "is this thing a cursor), and if so
 *	  return the next pair from the cursor instead of the given pair.  This is a huge change.
 *	- update all of the pair / value-box APIs to handle the new data type
 *	- check performance, etc, and that nothing else breaks.
 *	- also need to ensure that the pair with the cursor _cannot_ be copied, as that would add two
 *	  refs to the cursor.
 *	- if we're lucky, we could perhaps _instead_ update only the tmpl code, but the cursor
 *	  still has to be in the pair.
 *	- we can update tmpl_eval_pair(), because that's what's used in the xlat code.  That gets us all
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

		if (unlang_foreach_pair_copy(child, vp, vp->da) < 0) return -1;
	}

	return 0;
}

static xlat_action_t unlang_foreach_xlat_func(TALLOC_CTX *ctx, fr_dcursor_t *out,
					      xlat_ctx_t const *xctx,
					      request_t *request, UNUSED fr_value_box_list_t *in);

#define FOREACH_REQUEST_DATA (void *)unlang_foreach_xlat_func

/** Ensure request data is pulled out of the request if the frame is popped
 *
 */
static int _free_unlang_frame_state_foreach(unlang_frame_state_foreach_t *state)
{
	if (state->value) {
		fr_pair_t *vp;

		if (tmpl_is_xlat(state->vpt)) return 0;

		tmpl_dcursor_clear(&state->cc);

		/*
		 *	Now that we're done, the leaf entries can be changed again.
		 */
		vp = tmpl_dcursor_init(NULL, NULL, &state->cc, &state->cursor, state->request, state->vpt);
		fr_assert(vp != NULL);

		do {
			vp->vp_edit = false;
		} while ((vp = fr_dcursor_next(&state->cursor)) != NULL);
		tmpl_dcursor_clear(&state->cc);

	} else {
		request_data_get(state->request, FOREACH_REQUEST_DATA, state->depth);
	}

	return 0;
}

static unlang_action_t unlang_foreach_next_old(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_foreach_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_foreach_t);
	fr_pair_t			*vp;

	if (is_stack_unwinding_to_break(request->stack)) return UNLANG_ACTION_CALCULATE_RESULT;

	vp = fr_dcursor_next(&state->cursor);

	/*
	 *	Skip any non-leaf attributes - adds sanity to foreach &request.[*]
	 */
	while (vp) {
		switch (vp->vp_type) {
		case FR_TYPE_LEAF:
			break;
		default:
			vp = fr_dcursor_next(&state->cursor);
			continue;
		}
		break;
	}

	if (!vp) {
		*p_result = frame->result;
#ifndef NDEBUG
		fr_assert(state->indent == request->log.indent.unlang);
#endif
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

#ifndef NDEBUG
	RDEBUG2("# looping with: Foreach-Variable-%d = %pV", state->depth, &vp->data);
#endif

	repeatable_set(frame);

	/*
	 *	Push the child, and yield for a later return.
	 */
	return unlang_interpret_push_children(p_result, request, frame->result, UNLANG_NEXT_SIBLING);
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

	fr_value_box_clear_value(&state->key->data);
	if (tmpl_dcursor_print(&FR_SBUFF_IN(state->buffer, BUFFER_SIZE), &state->cc) > 0) {
		fr_value_box_strdup(state->key, &state->key->data, NULL, state->buffer, false);
	}
}

static unlang_action_t unlang_foreach_attr_next(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_foreach_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_foreach_t);
	fr_pair_t			*vp;

	if (is_stack_unwinding_to_break(request->stack)) return UNLANG_ACTION_CALCULATE_RESULT;

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
		}
	} else {
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
		fr_assert(state->value->vp_type == vp->vp_type);

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
			*p_result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		vp->vp_edit = true;
	} while ((vp = fr_dcursor_next(&state->cursor)) != NULL);
	tmpl_dcursor_clear(&state->cc);

	vp = tmpl_dcursor_init(NULL, NULL, &state->cc, &state->cursor, request, state->vpt);
	fr_assert(vp != NULL);

	/*
	 *	Update the key with the current path or index.
	 */
	unlang_foreach_attr_key_update(request, state);

	if (vp->vp_type == FR_TYPE_GROUP) {
		fr_assert(state->value->vp_type == FR_TYPE_GROUP);

		if (fr_pair_list_copy(state->value, &state->value->vp_group, &vp->vp_group) < 0) {
			REDEBUG("Failed copying members of %s", state->value->da->name);
			*p_result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

	} else if (fr_type_is_structural(vp->vp_type)) {
		if (state->value->vp_type == vp->vp_type) {
			if (unlang_foreach_pair_copy(state->value, vp, vp->da) < 0) {
				REDEBUG("Failed copying children of %s", state->value->da->name);
				*p_result = RLM_MODULE_FAIL;
				return UNLANG_ACTION_CALCULATE_RESULT;
			}
		} else {
			REDEBUG("Failed initializing loop variable %s - expected %s type, but got input (%pP)", state->value->da->name, fr_type_to_str(state->value->vp_type), vp);
			*p_result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
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
	unlang_stack_t			*stack = request->stack;
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	unlang_foreach_t		*gext = unlang_group_to_foreach(g);
	unlang_frame_state_foreach_t	*state;

	int				i, depth = 0;
	fr_pair_list_t			vps;
	fr_pair_t			*vp;

	fr_pair_list_init(&vps);

	/*
	 *	Ensure any breaks terminate here...
	 */
	break_point_set(frame);

	MEM(frame->state = state = talloc_zero(request->stack, unlang_frame_state_foreach_t));
	talloc_set_destructor(state, _free_unlang_frame_state_foreach);

	state->request = request;
#ifndef NDEBUG
	state->indent = request->log.indent.unlang;
#endif

	/*
	 *	We have a key variable, let's use that.
	 */
	if (gext->value) {
		state->vpt = gext->vpt;

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

	/*
	 *	Figure out foreach depth by walking back up the stack
	 */
	if (stack->depth > 0) for (i = (stack->depth - 1); i >= 0; i--) {
			unlang_t const *our_instruction;
			our_instruction = stack->frame[i].instruction;
			if (!our_instruction || (our_instruction->type != UNLANG_TYPE_FOREACH)) continue;
			depth++;
		}

	if (depth >= (int)NUM_ELEMENTS(xlat_foreach_names)) {
		REDEBUG("foreach Nesting too deep!");
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	fr_pair_list_init(&state->vps);

	/*
	 *	Copy the VPs from the original request, this ensures deterministic
	 *	behaviour if someone decides to add or remove VPs in the set we're
	 *	iterating over.
	 */
	if (tmpl_copy_pairs(frame->state, &vps, request, gext->vpt) < 0) {	/* nothing to loop over */
		*p_result = RLM_MODULE_NOOP;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	fr_assert(!fr_pair_list_empty(&vps));

	fr_pair_list_append(&state->vps, &vps);
	fr_pair_dcursor_init(&state->cursor, &state->vps);

	/*
	 *	Skip any non-leaf attributes at the start of the cursor
	 *	Adds sanity to foreach &request.[*]
	 */
	vp = fr_dcursor_current(&state->cursor);
	while (vp) {
		switch (vp->vp_type) {
		case FR_TYPE_LEAF:
			break;
		default:
			vp = fr_dcursor_next(&state->cursor);
			continue;
		}
		break;
	}

	/*
	 *	If no non-leaf attributes found clean up
	 */
	if (!vp) {
		fr_dcursor_free_list(&state->cursor);
		*p_result = RLM_MODULE_NOOP;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	state->depth = depth;

	/*
	 *	Add a (hopefully) faster lookup to get the state.
	 */
	request_data_add(request, FOREACH_REQUEST_DATA, state->depth, state, false, false, false);

	frame->process = unlang_foreach_next_old;

	repeatable_set(frame);

	/*
	 *	Push the child, and go process it.
	 */
	return unlang_interpret_push_children(p_result, request, frame->result, UNLANG_NEXT_SIBLING);
}

static unlang_action_t unlang_break(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	RDEBUG2("%s", unlang_ops[frame->instruction->type].name);

	*p_result = frame->result;

	/*
	 *	Stop at the next break point, or if we hit
	 *	the a top frame.
	 */
	return unwind_to_break(request->stack);
}

/** Implements the Foreach-Variable-X
 *
 * @ingroup xlat_functions
 */
static xlat_action_t unlang_foreach_xlat_func(TALLOC_CTX *ctx, fr_dcursor_t *out,
					      xlat_ctx_t const *xctx,
					      request_t *request, UNUSED fr_value_box_list_t *in)
{
	fr_pair_t			*vp;
	int const			*inst = xctx->inst;
	fr_value_box_t			*vb;
	unlang_frame_state_foreach_t	*state;

	state = request_data_reference(request, FOREACH_REQUEST_DATA, *inst);
	if (!state) return XLAT_ACTION_FAIL;

	vp = fr_dcursor_current(&state->cursor);
	fr_assert(vp != NULL);

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_copy(vb, vb, &vp->data);
	fr_dcursor_append(out, vb);
	return XLAT_ACTION_DONE;
}

void unlang_foreach_init(TALLOC_CTX *ctx)
{
	size_t	i;

	for (i = 0; i < NUM_ELEMENTS(xlat_foreach_names); i++) {
		xlat_t *x;

		x = xlat_func_register(ctx, xlat_foreach_names[i],
				  unlang_foreach_xlat_func, FR_TYPE_VOID);
		fr_assert(x);
		xlat_func_flags_set(x, XLAT_FUNC_FLAG_INTERNAL);
		x->uctx = &xlat_foreach_inst[i];
	}

	unlang_register(UNLANG_TYPE_FOREACH,
			   &(unlang_op_t){
				.name = "foreach",
				.interpret = unlang_foreach,
				.debug_braces = true
			   });

	unlang_register(UNLANG_TYPE_BREAK,
			   &(unlang_op_t){
				.name = "break",
				.interpret = unlang_break,
			   });
}
