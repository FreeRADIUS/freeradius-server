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
 * @file unlang/transaction.c
 * @brief Allows for edit transactions
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/server/rcode.h>
#include "transaction.h"
#include "transaction_priv.h"

/** Signal a transaction to abort.
 *
 * @param[in] request		The current request.
 * @param[in] frame		being signalled.
 * @param[in] action		to signal.
 */
static void unlang_transaction_signal(UNUSED request_t *request, unlang_stack_frame_t *frame, fr_signal_t action)
{
	unlang_frame_state_transaction_t *state = talloc_get_type_abort(frame->state,
									unlang_frame_state_transaction_t);

	/*
	 *	Ignore everything except cancel.
	 */
	if (action != FR_SIGNAL_CANCEL) return;

	fr_edit_list_abort(state->el);
	state->el = NULL;
}

/** Commit a successful transaction.
 *
 */
static unlang_action_t unlang_transaction_final(UNUSED unlang_result_t *p_result, UNUSED request_t *request,
						unlang_stack_frame_t *frame)
{
	unlang_frame_state_transaction_t *state = talloc_get_type_abort(frame->state,
									unlang_frame_state_transaction_t);

	fr_assert(state->el != NULL);

	/*
	 *	p_result contains OUR result, we want the section
	 *	result from what was just executed on the stack.
	 */
	switch (state->result.rcode) {
	case RLM_MODULE_REJECT:
	case RLM_MODULE_FAIL:
	case RLM_MODULE_INVALID:
	case RLM_MODULE_DISALLOW:
	case RLM_MODULE_NOTFOUND:
	case RLM_MODULE_TIMEOUT:
		fr_edit_list_abort(state->el);
		break;

	case RLM_MODULE_OK:
	case RLM_MODULE_HANDLED:
	case RLM_MODULE_NOOP:
	case RLM_MODULE_UPDATED:
	case RLM_MODULE_NOT_SET:
		fr_edit_list_commit(state->el);
		break;

	case RLM_MODULE_NUMCODES:	/* Do not add default: */
		fr_assert(0);
		return UNLANG_ACTION_FAIL;
	}

	/*
	 *	Allow the interpreter to access
	 *	the result of the child section
	 */
	*p_result = state->result;

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_transaction(UNUSED unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_transaction_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_transaction_t);
	fr_edit_list_t *parent;

	parent = unlang_interpret_edit_list(request);

	MEM(state->el = fr_edit_list_alloc(state, 10, parent));

	frame_repeat(frame, unlang_transaction_final);

	return unlang_interpret_push_children(&state->result, request, RLM_MODULE_NOT_SET, UNLANG_NEXT_SIBLING);
}

fr_edit_list_t *unlang_interpret_edit_list(request_t *request)
{
	unlang_stack_frame_t	*frame;
	unlang_stack_t		*stack = request->stack;
	int			i, depth = stack->depth;

	if (depth == 1) return NULL;

	for (i = depth - 1; i > 0; i--) {
		unlang_frame_state_transaction_t *state;

		frame = &stack->frame[i];
		if (frame->instruction->type != UNLANG_TYPE_TRANSACTION) continue;

		state = talloc_get_type_abort(frame->state, unlang_frame_state_transaction_t);
		fr_assert(state->el != NULL);

		return state->el;
	}

	return NULL;
}

static fr_table_num_sorted_t transaction_keywords[] = {
	{ L("case"),		1 },
	{ L("else"),		1 },
	{ L("elsif"),		1 },
	{ L("foreach"),		1 },
	{ L("group"),		1 },
	{ L("if"),		1 },
	{ L("limit"),		1 },
	{ L("load-balance"),	1 },
	{ L("redundant"), 	1 },
	{ L("redundant-load-balance"), 1 },
	{ L("switch"),		1 },
	{ L("timeout"),		1 },
	{ L("transaction"),	1 },
};
static int transaction_keywords_len = NUM_ELEMENTS(transaction_keywords);

/** Limit the operations which can appear in a transaction.
 */
static bool transaction_ok(CONF_SECTION *cs)
{
	CONF_ITEM *ci = NULL;

	while ((ci = cf_item_next(cs, ci)) != NULL) {
		char const *name;

		if (cf_item_is_section(ci)) {
			CONF_SECTION *subcs;

			subcs = cf_item_to_section(ci);
			name = cf_section_name1(subcs);

			/*
			 *	Allow limited keywords.
			 */
			if ((strcmp(name, "actions") == 0) ||
			    (strcmp(name, "if") == 0) ||
			    (strcmp(name, "else") == 0) ||
			    (strcmp(name, "elsif") == 0)) {
				continue;
			}

			/*
			 *	Ignore edits.
			 */
			if (fr_list_assignment_op[cf_section_name2_quote(subcs)]) continue;

			if (fr_table_value_by_str(transaction_keywords, name, -1) < 0) {
				cf_log_err(ci, "Invalid keyword in 'transaction'");
				return false;
			}

			if (!transaction_ok(subcs)) return false;

			continue;

		} else if (cf_item_is_pair(ci)) {
			CONF_PAIR *cp;

			cp = cf_item_to_pair(ci);
			name = cf_pair_attr(cp);

			/*
			 *	If there's a value then it's not a module call.
			 */
			if (cf_pair_value(cp)) continue;

			/*
			 *	Allow rcodes via the "always" module.
			 */
			if (fr_table_value_by_str(mod_rcode_table, name, -1) >= 0) {
				continue;
			}

			cf_log_err(ci, "Invalid module reference in 'transaction'");
			return false;

		} else {
			continue;
		}
	}

	return true;
}

static unlang_t *unlang_compile_transaction(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION *cs = cf_item_to_section(ci);
	unlang_group_t *g;
	unlang_t *c;
	unlang_compile_ctx_t unlang_ctx2;

	if (cf_section_name2(cs) != NULL) {
		cf_log_err(cs, "Unexpected argument to 'transaction' section");
		cf_log_err(ci, DOC_KEYWORD_REF(transaction));
		return NULL;
	}

	/*
	 *	The transaction is empty, ignore it.
	 */
	if (!cf_item_next(cs, NULL)) return UNLANG_IGNORE;

	if (!transaction_ok(cs)) return NULL;

	g = unlang_group_allocate(parent, cs, UNLANG_TYPE_TRANSACTION);
	if (!g) return NULL;

	c = unlang_group_to_generic(g);
	c->debug_name = c->name = cf_section_name1(cs);

	/*
	 *	The default for a failed transaction is to continue to
	 *	the next instruction on failure.
	 */
	c->actions.actions[RLM_MODULE_FAIL] = MOD_PRIORITY(1);
	c->actions.actions[RLM_MODULE_INVALID] = MOD_PRIORITY(1);
	c->actions.actions[RLM_MODULE_DISALLOW] = MOD_PRIORITY(1);

	/*
	 *	For the children of this keyword, any failure is
	 *	return, not continue.
	 */
	unlang_compile_ctx_copy(&unlang_ctx2, unlang_ctx);

	unlang_ctx2.actions.actions[RLM_MODULE_REJECT] = MOD_ACTION_RETURN;
	unlang_ctx2.actions.actions[RLM_MODULE_FAIL] = MOD_ACTION_RETURN;
	unlang_ctx2.actions.actions[RLM_MODULE_INVALID] = MOD_ACTION_RETURN;
	unlang_ctx2.actions.actions[RLM_MODULE_DISALLOW] = MOD_ACTION_RETURN;

	return unlang_compile_children(g, &unlang_ctx2);
}

void unlang_transaction_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "transaction",
			.type = UNLANG_TYPE_TRANSACTION,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

			.compile = unlang_compile_transaction,
			.interpret = unlang_transaction,
			.signal = unlang_transaction_signal,

			.unlang_size = sizeof(unlang_transaction_t),
			.unlang_name = "unlang_transaction_t",

			.frame_state_size = sizeof(unlang_frame_state_transaction_t),
			.frame_state_type = "unlang_frame_state_transaction_t",
		});
}
