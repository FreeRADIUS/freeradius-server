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
static unlang_action_t unlang_transaction_final(rlm_rcode_t *p_result, UNUSED request_t *request,
						unlang_stack_frame_t *frame)
{
	unlang_frame_state_transaction_t *state = talloc_get_type_abort(frame->state,
									unlang_frame_state_transaction_t);

	fr_assert(state->el != NULL);

	switch (*p_result) {
	case RLM_MODULE_REJECT:
	case RLM_MODULE_FAIL:
	case RLM_MODULE_INVALID:
	case RLM_MODULE_DISALLOW:
		fr_edit_list_abort(state->el);
		break;
	
	case RLM_MODULE_OK:
	case RLM_MODULE_HANDLED:
	case RLM_MODULE_NOOP:
	case RLM_MODULE_UPDATED:
		fr_edit_list_commit(state->el);
		break;

	default:
		fr_assert(0);
		return UNLANG_ACTION_FAIL;
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_transaction(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_transaction_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_transaction_t);
	fr_edit_list_t *parent;

	parent = unlang_interpret_edit_list(request);

	MEM(state->el = fr_edit_list_alloc(state, 10, parent));

	frame_repeat(frame, unlang_transaction_final);

	return unlang_interpret_push_children(p_result, request, frame->result, UNLANG_NEXT_SIBLING);
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

void unlang_transaction_init(void)
{
	unlang_register(UNLANG_TYPE_TRANSACTION,
			   &(unlang_op_t){
				.name = "transaction",
				.interpret = unlang_transaction,
				.signal = unlang_transaction_signal,
				.frame_state_size = sizeof(unlang_frame_state_transaction_t),
				.frame_state_type = "unlang_frame_state_transaction_t",
				.debug_braces = true
			   });
}
