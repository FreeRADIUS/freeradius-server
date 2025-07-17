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
 * @copyright 2020 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/unlang/tmpl.h>
#include <freeradius-devel/server/exec.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/unlang/mod_action.h>
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
static void unlang_tmpl_signal(request_t *request, unlang_stack_frame_t *frame, fr_signal_t action)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state,
								       unlang_frame_state_tmpl_t);

	/*
	 *	If we're cancelled, then kill any child processes
	 */
	if ((action == FR_SIGNAL_CANCEL) && state->exec_result.request) fr_exec_oneshot_cleanup(&state->exec_result, SIGKILL);

	if (!state->signal) return;

	state->signal(request, state->rctx, action);

	/*
	 *	If we're cancelled then disable this signal handler.
	 *	fr_exec_oneshot_cleanup should handle being called spuriously.
	 */
	if (action == FR_SIGNAL_CANCEL) state->signal = NULL;
}

/** Wrapper to call a resumption function after a tmpl has been expanded
 *
 *  If the resumption function returns YIELD, then this function is
 *  called repeatedly until the resumption function returns a final
 *  value.
 */
static unlang_action_t unlang_tmpl_resume(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_tmpl_t);
	unlang_tmpl_t			*ut = unlang_generic_to_tmpl(frame->instruction);

	if (tmpl_eval_cast_in_place(&state->list, request, ut->tmpl) < 0) {
		RPEDEBUG("Failed casting expansion");
		RETURN_UNLANG_FAIL;
	}

	if (state->out) fr_value_box_list_move(state->out, &state->list);

	if (state->resume) return state->resume(p_result, request, state->rctx);

	RETURN_UNLANG_OK;
}

/** Wrapper to call exec after the program has finished executing
 *
 */
static unlang_action_t unlang_tmpl_exec_wait_final(unlang_result_t *p_result, request_t *request,
						   unlang_stack_frame_t *frame)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state,
								       unlang_frame_state_tmpl_t);

	/*
	 *	The exec failed for some internal reason.  We don't
	 *	care about output, and we don't care about the programs exit status.
	 */
	if (state->exec_result.failed) {
		fr_value_box_list_talloc_free(&state->list);
		goto resume;
	}

	fr_assert(state->exec_result.pid < 0);	/* Assert this has been cleaned up */

	if (!state->args.exec.stdout_on_error && (state->exec_result.status != 0)) {
		fr_assert(fr_value_box_list_empty(&state->list));
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
		fr_sbuff_trim(&state->exec_result.stdout_buff, sbuff_char_line_endings);

		fr_value_box_list_init(&state->list);
		MEM(box = fr_value_box_alloc(state->ctx, FR_TYPE_STRING, NULL));
		if (fr_value_box_from_str(state->ctx, box, type, NULL,
					  fr_sbuff_start(&state->exec_result.stdout_buff),
					  fr_sbuff_used(&state->exec_result.stdout_buff),
					  NULL) < 0) {
			talloc_free(box);
			RETURN_UNLANG_FAIL;
		}
		fr_value_box_list_insert_head(&state->list, box);
	}

resume:
	/*
	 *	Inform the caller of the status if it asked for it
	 */
	if (state->args.exec.status_out) *state->args.exec.status_out = state->exec_result.status;

	/*
	 *	Ensure that the callers resume function is called.
	 */
	frame->process = unlang_tmpl_resume;
	return unlang_tmpl_resume(p_result, request, frame);
}

/** Wrapper to call after an xlat has been expanded
 *
 */
static unlang_action_t unlang_tmpl_xlat_resume(unlang_result_t *p_result, request_t *request,
					       unlang_stack_frame_t *frame)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_tmpl_t);

	if (!XLAT_RESULT_SUCCESS(&state->xlat_result)) RETURN_UNLANG_FAIL;

	/*
	 *	Ensure that the callers resume function is called.
	 */
	frame->process = unlang_tmpl_resume;
	return unlang_tmpl_resume(p_result, request, frame);
}


/** Wrapper to call exec after a tmpl has been expanded
 *
 */
static unlang_action_t unlang_tmpl_exec_wait_resume(unlang_result_t *p_result, request_t *request,
						    unlang_stack_frame_t *frame)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_tmpl_t);

	if (fr_exec_oneshot(state->ctx, &state->exec_result, request,
			  &state->list,
			  state->args.exec.env, false, false,
			  false,
			  (state->out != NULL), state,
			  state->args.exec.timeout) < 0) {
		RPEDEBUG("Failed executing program");
		RETURN_UNLANG_FAIL;
	}

	fr_value_box_list_talloc_free(&state->list); /* this is the xlat expansion, and not the output string we want */
	frame_repeat(frame, unlang_tmpl_exec_wait_final);

	return UNLANG_ACTION_YIELD;
}


static unlang_action_t unlang_tmpl(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
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

		RETURN_UNLANG_OK;
	}

	/*
	 *	XLAT structs are allowed.
	 */
	if (tmpl_is_xlat(ut->tmpl)) {
		frame_repeat(frame, unlang_tmpl_xlat_resume);
		goto push;
	}

	fr_assert(tmpl_is_exec(ut->tmpl));

	/*
	 *	Expand the arguments to the program we're executing.
	 */
	frame_repeat(frame, unlang_tmpl_exec_wait_resume);
push:
	if (unlang_xlat_push(state->ctx, &state->xlat_result, &state->list, request, tmpl_xlat(ut->tmpl), UNLANG_SUB_FRAME) < 0) {
	fail:
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Push a tmpl onto the stack for evaluation
 *
 * @param[in] ctx		To allocate value boxes and values in.
 * @param[out] p_result	        The frame result
 * @param[out] out		The value_box created from the tmpl.  May be NULL,
 *				in which case the result is discarded.
 * @param[in] request		The current request.
 * @param[in] tmpl		the tmpl to expand
 * @param[in] args		additional controls for expanding #TMPL_TYPE_EXEC,
 * 				and where the status of exited programs will be stored.
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int unlang_tmpl_push(TALLOC_CTX *ctx, unlang_result_t *p_result, fr_value_box_list_t *out, request_t *request,
		     tmpl_t const *tmpl, unlang_tmpl_args_t *args)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;
	unlang_frame_state_tmpl_t	*state;

	unlang_tmpl_t			*ut;

	static unlang_t const tmpl_instruction_return = {
		.type = UNLANG_TYPE_TMPL,
		.name = "tmpl",
		.debug_name = "tmpl",
		.actions = MOD_ACTIONS_FAIL_TIMEOUT_RETURN,
	};

	static const unlang_t tmpl_instruction_fail = {
		.type = UNLANG_TYPE_TMPL,
		.name = "tmpl",
		.debug_name = "tmpl",
		.actions = DEFAULT_MOD_ACTIONS,
	};

	if (tmpl_needs_resolving(tmpl)) {
		REDEBUG("Expansion \"%pV\" needs to be resolved before it is used", fr_box_strvalue_len(tmpl->name, tmpl->len));
		return -1;
	}

	/*
	 *	Avoid an extra stack frame and more work.  But only if the caller hands us a result.
	 *	Otherwise, we have to return UNLANG_FAIL.
	 */
	if (p_result && (tmpl_rules_cast(tmpl) == FR_TYPE_NULL) && tmpl_is_xlat(tmpl)) {
		return unlang_xlat_push(ctx, p_result, out, request, tmpl_xlat(tmpl), UNLANG_SUB_FRAME);
	}

	fr_assert(!tmpl_contains_regex(tmpl));

	MEM(ut = talloc(stack, unlang_tmpl_t));
	*ut = (unlang_tmpl_t){
		.self =  p_result ? tmpl_instruction_fail : tmpl_instruction_return,
		.tmpl = tmpl
	};

	/*
	 *	Push a new tmpl frame onto the stack
	 */
	if (unlang_interpret_push(p_result, request, unlang_tmpl_to_generic(ut),
				  FRAME_CONF(RLM_MODULE_NOT_SET, false), UNLANG_NEXT_STOP) < 0) return -1;

	frame = &stack->frame[stack->depth];
	state = talloc_get_type_abort(frame->state, unlang_frame_state_tmpl_t);

	/*
	 *	Set the frame as repeatable so that multiple tmpls can
	 *	be pushed on the stack before returning UNLANG_ACTION_PUSHED_CHILD
	 */
	repeatable_set(frame);

	*state = (unlang_frame_state_tmpl_t) {
		.vpt = tmpl,
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

static void unlang_tmpl_dump(request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_tmpl_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_tmpl_t);

	if (state->vpt) {
		RDEBUG("tmpl           %s", state->vpt->name);
	} else {
		unlang_tmpl_t *ut = unlang_generic_to_tmpl(frame->instruction);
		RDEBUG("tmpl           %s", ut->tmpl->name);
	}
}

void unlang_tmpl_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "tmpl",
			.type = UNLANG_TYPE_TMPL,
			.flag = UNLANG_OP_FLAG_INTERNAL,

			.interpret = unlang_tmpl,
			.signal = unlang_tmpl_signal,
			.dump = unlang_tmpl_dump,

			.unlang_size = sizeof(unlang_tmpl_t),
			.unlang_name = "unlang_tmpl_t",

			.frame_state_size = sizeof(unlang_frame_state_tmpl_t),
			.frame_state_type = "unlang_frame_state_tmpl_t",
		});
}
