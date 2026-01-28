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
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/unlang/action.h>
#include <freeradius-devel/unlang/unlang_priv.h>
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

	unlang_result_t		exp_result;			//!< for xlat expansion
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
			if (unlikely(fr_value_box_copy(child, &child->data, &vp->data) < 0)) return -1;
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


static unlang_action_t unlang_foreach_xlat_next(UNUSED unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_foreach_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_foreach_t);
	fr_value_box_t *box;

next:
	state->index++;

	box = fr_dcursor_next(&state->cursor);
	if (!box) return UNLANG_ACTION_EXECUTE_NEXT;	/* Don't change the section rcode */

	if (unlang_foreach_xlat_key_update(request, state) < 0) goto next;

	fr_value_box_clear_value(&state->value->data);
	if (fr_value_box_cast(state->value, &state->value->data, state->value->vp_type, state->value->da, box) < 0) {
		RPEDEBUG("Failed casting 'foreach' iteration variable '%s' from %pV", state->value->da->name, box);
		goto next;
	}

	repeatable_set(frame);

	/*
	 *	Push the child, and yield for a later return.
	 */
	return unlang_interpret_push_children(NULL, request, RLM_MODULE_NOT_SET, UNLANG_NEXT_SIBLING);
}


static unlang_action_t unlang_foreach_xlat_expanded(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_foreach_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_foreach_t);
	fr_value_box_t *box;

	if (!XLAT_RESULT_SUCCESS(&state->exp_result)) {
		RDEBUG("Failed expanding 'foreach' list");
		RETURN_UNLANG_FAIL;
	}

	box = fr_dcursor_init(&state->cursor, fr_value_box_list_dlist_head(&state->list));
	if (!box) {
	done:
		RETURN_UNLANG_NOOP;
	}

	fr_value_box_clear_value(&state->value->data);

next:
	if (fr_value_box_cast(state->value, &state->value->data, state->value->vp_type, state->value->da, box) < 0) {
		RPEDEBUG("Failed casting 'foreach' iteration variable '%s' from %pV", state->value->da->name, box);
		box = fr_dcursor_next(&state->cursor);
		if (!box) goto done;

		goto next;
	}

	frame_repeat(frame, unlang_foreach_xlat_next);

	/*
	 *	Push the child, and yield for a later return.
	 */
	return unlang_interpret_push_children(NULL, request, RLM_MODULE_NOT_SET, UNLANG_NEXT_SIBLING);
}


/*
 *	Loop over an xlat expansion
 */
static unlang_action_t unlang_foreach_xlat_init(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame,
						unlang_frame_state_foreach_t *state)
{
	fr_value_box_list_init(&state->list);

	if (unlang_xlat_push(state, &state->exp_result, &state->list, request, tmpl_xlat(state->vpt), false) < 0) {
		REDEBUG("Failed starting expansion of %s", state->vpt->name);
		RETURN_UNLANG_FAIL;
	}

	if (unlang_foreach_xlat_key_update(request, state) < 0) {
		RETURN_UNLANG_FAIL;
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
		if (tmpl_dcursor_print(&FR_SBUFF_OUT(state->buffer, BUFFER_SIZE), &state->cc) > 0) {
			fr_value_box_strdup(state->key, &state->key->data, NULL, state->buffer, false);
		}
		break;

	default:
		fr_assert(0);
		break;

	}
}

static unlang_action_t unlang_foreach_attr_next(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
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
			if (unlikely(fr_value_box_copy(vp, &vp->data, &state->value->data) < 0)) {
				RPEDEBUG("Failed copying value from %s to %s", state->value->da->name, vp->da->name);
				return UNLANG_ACTION_FAIL;
			}
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
#ifndef NDEBUG
		fr_assert(state->indent == request->log.indent.unlang);
#endif
		return UNLANG_ACTION_EXECUTE_NEXT;
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
			RETURN_UNLANG_FAIL;
		}

	} else if (fr_type_is_structural(vp->vp_type)) {
		if (state->value->vp_type != vp->vp_type) goto next;

		fr_pair_list_free(&state->value->vp_group);

		if (unlang_foreach_pair_copy(state->value, vp, vp->da) < 0) {
			REDEBUG("Failed copying children of %s", state->value->da->name);
			RETURN_UNLANG_FAIL;
		}

	} else {
		fr_value_box_clear_value(&state->value->data);
		if (fr_value_box_cast(state->value, &state->value->data, state->value->vp_type, state->value->da, &vp->data) < 0) {
			RDEBUG("Failed casting 'foreach' iteration variable '%s' from %pP", state->value->da->name, vp);
			goto next;
		}

#ifndef NDEBUG
		RDEBUG2("# looping with: %s = %pR", state->value->da->name, &vp->data);
#endif
	}

	repeatable_set(frame);

	/*
	 *	Push the child, and yield for a later return.
	 */
	return unlang_interpret_push_children(NULL, request, RLM_MODULE_NOT_SET, UNLANG_NEXT_SIBLING);
}

/*
 *	Loop over an attribute
 */
static unlang_action_t unlang_foreach_attr_init(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame,
						unlang_frame_state_foreach_t *state)
{
	fr_pair_t			*vp;

	/*
	 *	No matching attributes, we can't do anything.
	 */
	vp = tmpl_dcursor_init(NULL, NULL, &state->cc, &state->cursor, request, state->vpt);
	if (!vp) {
		tmpl_dcursor_clear(&state->cc);
		RETURN_UNLANG_NOOP;
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
			RETURN_UNLANG_FAIL;
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

			fr_assert(state->indent == request->log.indent.unlang);
			return UNLANG_ACTION_EXECUTE_NEXT;
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
			RETURN_UNLANG_NOOP;
		}
	}

	frame->process = unlang_foreach_attr_next;

	repeatable_set(frame);

	/*
	 *	Push the child, and go process it.
	 */
	return unlang_interpret_push_children(NULL, request, RLM_MODULE_NOT_SET, UNLANG_NEXT_SIBLING);
}


static unlang_action_t unlang_foreach(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
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
		RETURN_UNLANG_FAIL;
	}
	fr_assert(state->value != NULL);

	if (gext->key) {
		fr_assert(fr_pair_find_by_da(&request->local_pairs, NULL, gext->key) == NULL);

		if (fr_pair_append_by_da(request->local_ctx, &state->key, &request->local_pairs, gext->key) < 0) {
			REDEBUG("Failed creating %s", gext->key->name);
			RETURN_UNLANG_FAIL;
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

static unlang_action_t unlang_break(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_action_t			ua;
	unlang_stack_t			*stack = request->stack;
	unsigned int break_depth;

	RDEBUG2("%s", unlang_ops[frame->instruction->type].name);

	/*
	 *	As we're unwinding intermediary frames we
	 *	won't be taking their rcodes or priorities
	 *	into account.  We do however want to record
	 *	the current section rcode.
	 */
	*p_result = frame->section_result;

	/*
	 *	Stop at the next break point, or if we hit
	 *	the a top frame.
	 */
	ua = unwind_to_op_flag(&break_depth, request->stack, UNLANG_OP_FLAG_BREAK_POINT);
	repeatable_clear(&stack->frame[break_depth]);
	return ua;
}

static unlang_action_t unlang_continue(UNUSED unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_stack_t			*stack = request->stack;

	RDEBUG2("%s", unlang_ops[frame->instruction->type].name);

	return unwind_to_op_flag(NULL, stack, UNLANG_OP_FLAG_CONTINUE_POINT);
}

static unlang_t *unlang_compile_foreach(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION		*cs = cf_item_to_section(ci);
	fr_token_t		token;
	char const		*name2;
	char const		*type_name, *variable_name;
	fr_type_t		type;
	unlang_t		*c;

	fr_type_t		key_type;
	char const		*key_name;

	unlang_group_t		*g;
	unlang_foreach_t	*gext;

	ssize_t			slen;
	tmpl_t			*vpt;
	fr_dict_attr_t const	*da = NULL;

	tmpl_rules_t		t_rules;
	unlang_compile_ctx_t	unlang_ctx2;

	/*
	 *	Ignore empty "foreach" blocks, and don't even sanity check their arguments.
	 */
	if (!cf_item_next(cs, NULL)) {
		return UNLANG_IGNORE;
	}

	/*
	 *	We allow unknown attributes here.
	 */
	t_rules = *(unlang_ctx->rules);
	t_rules.attr.allow_unknown = true;
	t_rules.attr.allow_wildcard = true;
	RULES_VERIFY(&t_rules);

	name2 = cf_section_name2(cs);
	fr_assert(name2 != NULL); /* checked in cf_file.c */

	/*
	 *	Allocate a group for the "foreach" block.
	 */
	g = unlang_group_allocate(parent, cs, UNLANG_TYPE_FOREACH);
	if (!g) return NULL;

	c = unlang_group_to_generic(g);

	/*
	 *	Create the template.  If we fail, AND it's a bare word
	 *	with &Foo-Bar, it MAY be an attribute defined by a
	 *	module.  Allow it for now.  The pass2 checks below
	 *	will fix it up.
	 */
	token = cf_section_name2_quote(cs);
	if (token != T_BARE_WORD) {
		cf_log_err(cs, "Data being looped over in 'foreach' must be an attribute reference or dynamic expansion, not a string");
	print_ref:
		cf_log_err(ci, DOC_KEYWORD_REF(foreach));
	error:
		talloc_free(g);
		return NULL;
	}

	slen = tmpl_afrom_substr(g, &vpt,
				 &FR_SBUFF_IN_STR(name2),
				 token,
				 NULL,
				 &t_rules);
	if (!vpt) {
		cf_canonicalize_error(cs, slen, "Failed parsing argument to 'foreach'", name2);
		goto error;
	}

	/*
	 *	If we don't have a negative return code, we must have a vpt
	 *	(mostly to quiet coverity).
	 */
	fr_assert(vpt);

	if (tmpl_is_attr(vpt)) {
		if (tmpl_attr_tail_num(vpt) == NUM_UNSPEC) {
			cf_log_warn(cs, "Attribute reference should be updated to use %s[*]", vpt->name);
			tmpl_attr_rewrite_leaf_num(vpt, NUM_ALL);
		}

		if (tmpl_attr_tail_num(vpt) != NUM_ALL) {
			cf_log_err(cs, "Attribute references must be of the form ...%s[*]", tmpl_attr_tail_da(vpt)->name);
			goto print_ref;
		}

	} else if (!tmpl_contains_xlat(vpt)) {
		cf_log_err(cs, "Invalid content in 'foreach (...)', it must be an attribute reference or a dynamic expansion");
		goto print_ref;
	}

	gext = unlang_group_to_foreach(g);
	gext->vpt = vpt;

	c->name = "foreach";
	MEM(c->debug_name = talloc_typed_asprintf(c, "foreach %s", name2));

	/*
	 *	Copy over the compilation context.  This is mostly
	 *	just to ensure that retry is handled correctly.
	 *	i.e. reset.
	 */
	unlang_compile_ctx_copy(&unlang_ctx2, unlang_ctx);

	/*
	 *	Then over-write the new compilation context.
	 */
	unlang_ctx2.section_name1 = "foreach";
	unlang_ctx2.section_name2 = name2;
	unlang_ctx2.rules = &t_rules;
	t_rules.parent = unlang_ctx->rules;

	/*
	 *	If we have "type name", then define a local variable of that name.
	 */
	type_name = cf_section_argv(cs, 0); /* AFTER name1, name2 */

	key_name = cf_section_argv(cs, 2);
	if (key_name) {
		key_type = fr_table_value_by_str(fr_type_table, key_name, FR_TYPE_VOID);
	} else {
		key_type = FR_TYPE_VOID;
	}
	key_name = cf_section_argv(cs, 3);

	if (tmpl_is_xlat(vpt)) {
		if (!type_name) {
			cf_log_err(cs, "Dynamic expansions MUST specify a data type for the variable");
			goto print_ref;
		}

		type = fr_table_value_by_str(fr_type_table, type_name, FR_TYPE_VOID);

		/*
		 *	No data type was specified, see if we can get one from the function.
		 */
		if (type == FR_TYPE_NULL) {
			type = xlat_data_type(tmpl_xlat(vpt));
			if (fr_type_is_leaf(type)) goto get_name;

			cf_log_err(cs, "Unable to determine return data type from dynamic expansion");
			goto print_ref;
		}

		if (!fr_type_is_leaf(type)) {
			cf_log_err(cs, "Dynamic expansions MUST specify a non-structural data type for the variable");
			goto print_ref;
		}

		if ((key_type != FR_TYPE_VOID) && !fr_type_is_numeric(key_type)) {
			cf_log_err(cs, "Invalid data type '%s' for 'key' variable - it should be numeric", fr_type_to_str(key_type));
			goto print_ref;
		}

		goto get_name;
	} else {
		fr_assert(tmpl_is_attr(vpt));

		if ((key_type != FR_TYPE_VOID) && (key_type != FR_TYPE_STRING) && (key_type != FR_TYPE_UINT32)) {
			cf_log_err(cs, "Invalid data type '%s' for 'key' variable - it should be 'string' or 'uint32'", fr_type_to_str(key_type));
			goto print_ref;
		}
	}

	if (type_name) {
		unlang_variable_t *var;

		type = fr_table_value_by_str(fr_type_table, type_name, FR_TYPE_VOID);
		fr_assert(type != FR_TYPE_VOID);

		/*
		 *	foreach string foo (&tlv-thing.[*]) { ... }
		 */
		if (tmpl_attr_tail_is_unspecified(vpt)) {
			goto get_name;
		}

		da = tmpl_attr_tail_da(vpt);

		if (type == FR_TYPE_NULL) {
			type = da->type;

		} else if (fr_type_is_leaf(type) != fr_type_is_leaf(da->type)) {
		incompatible:
			cf_log_err(cs, "Incompatible data types in foreach variable (%s), and reference %s being looped over (%s)",
				   fr_type_to_str(type), da->name, fr_type_to_str(da->type));
			goto print_ref;

		} else if (fr_type_is_structural(type) && (type != da->type)) {
			goto incompatible;
		}

	get_name:
		variable_name = cf_section_argv(cs, 1);

		/*
		 *	Define the local variables.
		 */
		g->variables = var = talloc_zero(g, unlang_variable_t);
		if (!var) goto error;

		var->dict = fr_dict_protocol_alloc(unlang_ctx->rules->attr.dict_def);
		if (!var->dict) goto error;

		var->root = fr_dict_root(var->dict);

		var->max_attr = 1;

		if (unlang_define_local_variable(cf_section_to_item(cs), var, &t_rules, type, variable_name, da) < 0) goto error;

		t_rules.attr.dict_def = var->dict;
		t_rules.attr.namespace = NULL;

		/*
		 *	And ensure we have the key.
		 */
		gext->value = fr_dict_attr_by_name(NULL, var->root, variable_name);
		fr_assert(gext->value != NULL);

		/*
		 *	Define the local key variable.  Note that we don't copy any children.
		 */
		if (key_type != FR_TYPE_VOID) {
			if (unlang_define_local_variable(cf_section_to_item(cs), var, &t_rules, key_type, key_name, NULL) < 0) goto error;

			gext->key = fr_dict_attr_by_name(NULL, var->root, key_name);
			fr_assert(gext->key != NULL);
		}
	}

	return unlang_compile_children(g, &unlang_ctx2);
}


static unlang_t *unlang_compile_break(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	unlang_t *unlang;

	for (unlang = parent; unlang != NULL; unlang = unlang->parent) {
		/*
		 *	"break" doesn't go past a return point.
		 */
		if ((unlang_ops[unlang->type].flag & UNLANG_OP_FLAG_RETURN_POINT) != 0) goto error;

		if ((unlang_ops[unlang->type].flag & UNLANG_OP_FLAG_BREAK_POINT) != 0) break;
	}

	if (!unlang) {
	error:
		cf_log_err(ci, "Invalid location for 'break' - it can only be used inside 'foreach' or 'switch'");
		cf_log_err(ci, DOC_KEYWORD_REF(break));
		return NULL;
	}

	parent->closed = true;

	return unlang_compile_empty(parent, unlang_ctx, NULL, UNLANG_TYPE_BREAK);
}

static unlang_t *unlang_compile_continue(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	unlang_t *unlang;

	for (unlang = parent; unlang != NULL; unlang = unlang->parent) {
		/*
		 *	"continue" doesn't go past a return point.
		 */
		if ((unlang_ops[unlang->type].flag & UNLANG_OP_FLAG_RETURN_POINT) != 0) goto error;

		if (unlang->type == UNLANG_TYPE_FOREACH) break;
	}

	if (!unlang) {
	error:
		cf_log_err(ci, "Invalid location for 'continue' - it can only be used inside 'foreach'");
		cf_log_err(ci, DOC_KEYWORD_REF(break));
		return NULL;
	}

	parent->closed = true;

	return unlang_compile_empty(parent, unlang_ctx, NULL, UNLANG_TYPE_CONTINUE);
}

void unlang_foreach_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "foreach",
			.type = UNLANG_TYPE_FOREACH,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES | UNLANG_OP_FLAG_BREAK_POINT | UNLANG_OP_FLAG_CONTINUE_POINT,

			.compile = unlang_compile_foreach,
			.interpret = unlang_foreach,

			.unlang_size = sizeof(unlang_foreach_t),
			.unlang_name = "unlang_foreach_t",

			.pool_headers = TMPL_POOL_DEF_HEADERS,
			.pool_len = TMPL_POOL_DEF_LEN
		});

	unlang_register(&(unlang_op_t){
			.name = "break",
			.type = UNLANG_TYPE_BREAK,
			.flag = UNLANG_OP_FLAG_SINGLE_WORD
,
			.compile = unlang_compile_break,
			.interpret = unlang_break,

			.unlang_size = sizeof(unlang_group_t),
			.unlang_name = "unlang_group_t",
		});

	unlang_register(&(unlang_op_t){
			.name = "continue",
			.type = UNLANG_TYPE_CONTINUE,
			.flag = UNLANG_OP_FLAG_SINGLE_WORD,

			.compile = unlang_compile_continue,
			.interpret = unlang_continue,

			.unlang_size = sizeof(unlang_group_t),
			.unlang_name = "unlang_group_t",
		});
}
