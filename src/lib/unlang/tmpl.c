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
 * @file unlang/tmpl.c
 * @brief Defines functions for calling tmpl__t asynchronously
 *
 * @copyright 2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/unlang/tmpl.h>
#include <freeradius-devel/server/exec.h>
#include <freeradius-devel/util/syserror.h>
#include "tmpl_priv.h"
#include <signal.h>

#if defined(__linux__) || defined(__FreeBSD__)
#include <sys/wait.h>
#endif

/** Send a signal (usually stop) to a request
 *
 * This is typically called via an "async" action, i.e. an action
 * outside of the normal processing of the request.
 *
 * If there is no #fr_unlang_tmpl_signal_t callback defined, the action is ignored.
 *
 * @param[in] request		The current request.
 * @param[in] frame		being signalled.
 * @param[in] action		to signal.
 */
static void unlang_tmpl_signal(request_t *request, unlang_stack_frame_t *frame, fr_state_signal_t action)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state,
								       unlang_frame_state_tmpl_t);

	/*
	 *	If we're cancelled, then kill any child processes
	 */
	if (action == FR_SIGNAL_CANCEL) fr_exec_cleanup(&state->exec, SIGKILL);

	if (!state->signal) return;

	state->signal(request, state->rctx, action);

	/*
	 *	If we're cancelled then disable this signal handler.
	 *	fr_exec_cleanup should handle being called spuriously.
	 */
	if (action == FR_SIGNAL_CANCEL) state->signal = NULL;
}

/** Wrapper to call a resumption function after a tmpl has been expanded
 *
 *  If the resumption function returns YIELD, then this function is
 *  called repeatedly until the resumption function returns a final
 *  value.
 */
static unlang_action_t unlang_tmpl_resume(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_tmpl_t);
	unlang_tmpl_t			*ut = unlang_generic_to_tmpl(frame->instruction);

	if (tmpl_eval_cast(request, &state->list, ut->tmpl) < 0) {
		RPEDEBUG("Failed casting expansion");
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	if (state->out) fr_dlist_move(state->out, &state->list);

	if (state->resume) return state->resume(p_result, request, state->rctx);

	*p_result = RLM_MODULE_OK;

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Wrapper to call exec after the program has finished executing
 *
 */
static unlang_action_t unlang_tmpl_exec_wait_final(rlm_rcode_t *p_result, request_t *request,
						   unlang_stack_frame_t *frame)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state,
								       unlang_frame_state_tmpl_t);

	/*
	 *	The exec failed for some internal reason.  We don't
	 *	care about output, and we don't care about the programs exit status.
	 */
	if (state->exec.failed) {
		fr_dlist_talloc_free(&state->list);
		goto resume;
	}

	fr_assert(state->exec.pid < 0);	/* Assert this has been cleaned up */

	if (!state->args.exec.stdout_on_error && (state->exec.status != 0)) {
		fr_assert(fr_dlist_empty(&state->list));
		goto resume;
	}

	/*
	 *	We might want to just get the status of the program,
	 *	and not care about the output.
	 *
	 *	If we do care about the output, it's unquoted, and tainted.
	 *
	 *	FIXME - It would be much more efficient to just reparent
	 *	the string buffer into the context of the box... but we'd
	 *	need to fix talloc first.
	 */
	if (state->out) {
		fr_type_t type = FR_TYPE_STRING;
		fr_value_box_t *box;

		/*
		 *	Remove any trailing LF / CR
		 */
		fr_sbuff_trim(&state->exec.stdout_buff, sbuff_char_line_endings);

		fr_value_box_list_init(&state->list);
		MEM(box = fr_value_box_alloc(state->ctx, FR_TYPE_STRING, NULL, true));
		if (fr_value_box_from_str(state->ctx, box, type, NULL,
					  fr_sbuff_start(&state->exec.stdout_buff),
					  fr_sbuff_used(&state->exec.stdout_buff),
					  NULL, true) < 0) {
			talloc_free(box);
			*p_result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
		fr_dlist_insert_head(&state->list, box);
	}

resume:
	/*
	 *	Inform the caller of the status if it asked for it
	 */
	if (state->args.exec.status_out) *state->args.exec.status_out = state->exec.status;

	/*
	 *	Ensure that the callers resume function is called.
	 */
	frame->process = unlang_tmpl_resume;
	return unlang_tmpl_resume(p_result, request, frame);
}


/** Wrapper to call exec after a tmpl has been expanded
 *
 */
static unlang_action_t unlang_tmpl_exec_wait_resume(rlm_rcode_t *p_result, request_t *request,
						    unlang_stack_frame_t *frame)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_tmpl_t);

	if (fr_exec_start(state->ctx, &state->exec, request,
			  &state->list,
			  state->args.exec.env, false, false,
			  false,
			  (state->out != NULL), state,
			  state->args.exec.timeout) < 0) {
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	fr_dlist_talloc_free(&state->list); /* this is the xlat expansion, and not the output string we want */
	frame_repeat(frame, unlang_tmpl_exec_wait_final);

	return UNLANG_ACTION_YIELD;
}


static unlang_action_t unlang_tmpl(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_tmpl_t);
	unlang_tmpl_t			*ut = unlang_generic_to_tmpl(frame->instruction);

	/*
	 *	If we're not called from unlang_tmpl_push(), then
	 *	ensure that we clean up the resulting value boxes
	 *	and that the list to write the boxes in is initialised.
	 */
	if (!state->ctx) {
		state->ctx = state;
		fr_value_box_list_init(&state->list);
	}

	/*
	 *	Synchronous tmpls can just be resolved immediately, and directly to the output list.
	 *
	 *	However, xlat expansions (including fully synchronous function calls!) need to be expanded by
	 *	the xlat framework.
	 */
	if (!tmpl_async_required(ut->tmpl) && !tmpl_contains_xlat(ut->tmpl)) {
		if (tmpl_eval(state->ctx, state->out, request, ut->tmpl) < 0) {
			RPEDEBUG("Failed evaluating expansion");
			goto fail;
		}

		*p_result = RLM_MODULE_OK;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	XLAT structs are allowed.
	 */
	if (tmpl_is_xlat(ut->tmpl)) {
		frame_repeat(frame, unlang_tmpl_resume);
		goto push;
	}

	fr_assert(tmpl_is_exec(ut->tmpl));

	/*
	 *	Expand the arguments to the program we're executing.
	 */
	frame_repeat(frame, unlang_tmpl_exec_wait_resume);
push:
	if (unlang_xlat_push(state->ctx, NULL, &state->list, request, tmpl_xlat(ut->tmpl), false) < 0) {
	fail:
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Push a tmpl onto the stack for evaluation
 *
 * @param[in] ctx		To allocate value boxes and values in.
 * @param[out] out		The value_box created from the tmpl.  May be NULL,
 *				in which case the result is discarded.
 * @param[in] request		The current request.
 * @param[in] tmpl		the tmpl to expand
 * @param[in] args		where the status of exited programs will be stored.
 *				Used only for #TMPL_TYPE_EXEC.
 */
int unlang_tmpl_push(TALLOC_CTX *ctx, fr_value_box_list_t *out, request_t *request,
		     tmpl_t const *tmpl, unlang_tmpl_args_t *args)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;
	unlang_frame_state_tmpl_t	*state;

	unlang_tmpl_t			*ut;

	static unlang_t tmpl_instruction = {
		.type = UNLANG_TYPE_TMPL,
		.name = "tmpl",
		.debug_name = "tmpl",
		.actions = {
			.actions = {
				[RLM_MODULE_REJECT]	= 0,
				[RLM_MODULE_FAIL]	= 0,
				[RLM_MODULE_OK]		= 0,
				[RLM_MODULE_HANDLED]	= 0,
				[RLM_MODULE_INVALID]	= 0,
				[RLM_MODULE_DISALLOW]	= 0,
				[RLM_MODULE_NOTFOUND]	= 0,
				[RLM_MODULE_NOOP]	= 0,
				[RLM_MODULE_UPDATED]	= 0
			},
			.retry = RETRY_INIT,
		},
	};

	if (tmpl_needs_resolving(tmpl)) {
		REDEBUG("Expansion %s needs to be resolved before it is used.", tmpl->name);
		return -1;
	}

	fr_assert(!tmpl_contains_regex(tmpl));

	MEM(ut = talloc(stack, unlang_tmpl_t));
	*ut = (unlang_tmpl_t){
		.self = tmpl_instruction,
		.tmpl = tmpl
	};

	/*
	 *	Push a new tmpl frame onto the stack
	 */
	if (unlang_interpret_push(request, unlang_tmpl_to_generic(ut),
				  RLM_MODULE_NOT_SET, UNLANG_NEXT_STOP, false) < 0) return -1;

	frame = &stack->frame[stack->depth];
	state = talloc_get_type_abort(frame->state, unlang_frame_state_tmpl_t);

	*state = (unlang_frame_state_tmpl_t) {
		.out = out,
		.ctx = ctx,
	};
	if (args) state->args = *args;	/* Copy these because they're usually ephemeral/initialised as compound literal */

	/*
	 *	Default to something sensible
	 *	instead of locking the same indefinitely.
	 */
	if (!fr_time_delta_ispos(state->args.exec.timeout)) state->args.exec.timeout = fr_time_delta_from_sec(EXEC_TIMEOUT);

	fr_value_box_list_init(&state->list);

	return 0;
}

void unlang_tmpl_init(void)
{
	unlang_register(UNLANG_TYPE_TMPL,
			   &(unlang_op_t){
				.name = "tmpl",
				.interpret = unlang_tmpl,
				.signal = unlang_tmpl_signal,
				.frame_state_size = sizeof(unlang_frame_state_tmpl_t),
				.frame_state_type = "unlang_frame_state_tmpl_t",
			   });
}
