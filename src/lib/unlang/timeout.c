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
 * @file unlang/timeout.c
 * @brief Unlang "timeout" keyword evaluation.
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/unlang/timeout.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/server/rcode.h>
#include "group_priv.h"
#include "timeout_priv.h"
#include "mod_action.h"
#include "unlang_priv.h"

typedef struct {
	bool					fired;
	int					depth;
	fr_time_delta_t				timeout;
	request_t				*request;
	rindent_t				indent;
	fr_timer_t				*ev;

	fr_value_box_list_t			result;

	unlang_t				*instruction;	//!< to run on timeout
} unlang_frame_state_timeout_t;

/** Immediately cancel the timeout if the frame is cancelled
 */
static void unlang_timeout_signal(UNUSED request_t *request, unlang_stack_frame_t *frame, fr_signal_t action)
{
	unlang_frame_state_timeout_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_timeout_t);

	if (action == FR_SIGNAL_CANCEL) {
		TALLOC_FREE(state->ev);
	}
}

static void unlang_timeout_handler(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *ctx)
{
	unlang_frame_state_timeout_t	*state = talloc_get_type_abort(ctx, unlang_frame_state_timeout_t);
	request_t			*request = talloc_get_type_abort(state->request, request_t);
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	char const			*module;

	/*
	 *	Don't log in the context of the request
	 */
	module = request->module;
	request->module = NULL;
	RDEBUG("Timeout reached, signalling interpreter to cancel child section.");
	request->module = module;

	/*
	 *	Signal all the frames upto, but not including the timeout
	 *	frame to cancel.
	 *
	 *	unlang_timeout_resume_done then runs, and returns "timeout"
	 */
	unlang_stack_signal(request, FR_SIGNAL_CANCEL, state->depth);

	/*
	 *	If the frame is yielded (needs to be resumed), but was cancelled
	 *	we now need to mark it runnable again so it's unwound.
	 *
	 *	If the frame _isn't_ cancelled, then it's non-cancellable and
	 *	something else will run it to completion, and mark
	 *	the request as complete.
	 */
	if (is_yielded(frame) && is_unwinding(frame) && !unlang_request_is_scheduled(request)) unlang_interpret_mark_runnable(request);
	state->fired = true;

	RINDENT_RESTORE(request, state);

	if (!state->instruction) return;

	/*
	 *	Push something else onto the stack to execute.
	 */
	if (unlikely(unlang_interpret_push_instruction(NULL, request, state->instruction,
						       FRAME_CONF(RLM_MODULE_TIMEOUT, true)) < 0)) {
		unlang_interpret_signal(request, FR_SIGNAL_CANCEL); /* also stops the request and does cleanups */
	}
}

static unlang_action_t unlang_timeout_resume_done(unlang_result_t *p_result, UNUSED request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_timeout_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_timeout_t);

	/*
	 *	No timeout, we go to the next instruction.
	 *
	 *	Unless the next instruction is a "catch timeout", in which case we skip it.
	 */
	if (!state->fired) return UNLANG_ACTION_EXECUTE_NEXT;	/* Don't modify the return code*/

	RETURN_UNLANG_TIMEOUT;
}

static unlang_action_t unlang_timeout_set(UNUSED unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_timeout_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_timeout_t);

	/*
	 *	Save current indentation for the error path.
	 */
	RINDENT_SAVE(state, request);

	if (fr_timer_in(state, unlang_interpret_event_list(request)->tl, &state->ev, state->timeout,
			false, unlang_timeout_handler, state) < 0) {
		RPEDEBUG("Failed inserting event");
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	frame_repeat(frame, unlang_timeout_resume_done);

	return unlang_interpret_push_children(NULL, request, RLM_MODULE_NOT_SET, UNLANG_NEXT_SIBLING);
}

static unlang_action_t unlang_timeout_done(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_timeout_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_timeout_t);
	fr_value_box_t			*box = fr_value_box_list_head(&state->result);

	/*
	 *	compile_timeout() ensures that the tmpl is cast to time_delta, so we don't have to do any more work here.
	 */
	state->timeout = box->vb_time_delta;

	return unlang_timeout_set(p_result, request, frame);
}

static unlang_action_t unlang_timeout(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t			*g;
	unlang_timeout_t		*gext;
	unlang_frame_state_timeout_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_timeout_t);
	unlang_stack_t			*stack = request->stack;

	g = unlang_generic_to_group(frame->instruction);
	gext = unlang_group_to_timeout(g);

	/*
	 *	+1 so we don't mark the timeout frame as cancelled,
	 *	we want unlang_timeout_resume_done to be called.
	 */
	state->depth = stack->depth + 1;
	state->request = request;

	if (!gext->vpt) {
		state->timeout = gext->timeout;
		return unlang_timeout_set(p_result, request, frame);
	}

	fr_value_box_list_init(&state->result);

	if (unlang_tmpl_push(state, &state->result, request, gext->vpt, NULL) < 0) return UNLANG_ACTION_FAIL;

	frame_repeat(frame, unlang_timeout_done);

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** When a timeout fires, run the given section.
 *
 * @param[in] request		to push timeout onto
 * @param[in] timeout      	when to run the timeout
 * @param[in] cs		section to run when the timeout fires.
 * @param[in] top_frame		Set to UNLANG_TOP_FRAME if the interpreter should return.
 *				Set to UNLANG_SUB_FRAME if the interprer should continue.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int unlang_timeout_section_push(request_t *request, CONF_SECTION *cs, fr_time_delta_t timeout, bool top_frame)
{
	/** Static instruction for performing xlat evaluations
	 *
	 */
	static unlang_t timeout_instruction = {
		.type = UNLANG_TYPE_TIMEOUT,
		.name = "timeout",
		.debug_name = "timeout",
		.actions = {
			.actions = {
				[RLM_MODULE_REJECT]	= 0,
				[RLM_MODULE_FAIL]	= MOD_ACTION_RETURN,	/* Exit out of nested levels */
				[RLM_MODULE_OK]		= 0,
				[RLM_MODULE_HANDLED]	= 0,
				[RLM_MODULE_INVALID]	= 0,
				[RLM_MODULE_DISALLOW]	= 0,
				[RLM_MODULE_NOTFOUND]	= 0,
				[RLM_MODULE_NOOP]	= 0,
				[RLM_MODULE_TIMEOUT]	= MOD_ACTION_RETURN,	/* Exit out of nested levels */
				[RLM_MODULE_UPDATED]	= 0
			},
			.retry = RETRY_INIT,
		},
	};

	unlang_frame_state_timeout_t	*state;
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;
	unlang_t			*instruction;

	/*
	 *	Get the instruction we are supposed to run on timeout.
	 */
	instruction = (unlang_t *)cf_data_value(cf_data_find(cs, unlang_group_t, NULL));
	if (!instruction) {
		REDEBUG("Failed to find pre-compiled unlang for section %s { ... }",
			cf_section_name1(cs));
		return -1;
	}

	/*
	 *	Push a new timeout frame onto the stack
	 */
	if (unlang_interpret_push(NULL, request, &timeout_instruction,
				  FRAME_CONF(RLM_MODULE_NOT_SET, top_frame), UNLANG_NEXT_STOP) < 0) return -1;
	frame = &stack->frame[stack->depth];

	/*
	 *	Allocate its state, and set the timeout.
	 */
	MEM(frame->state = state = talloc_zero(stack, unlang_frame_state_timeout_t));

	RINDENT_SAVE(state, request);
	state->depth = stack->depth;
	state->request = request;
	state->timeout = timeout;
	state->instruction = instruction;

	if (fr_timer_in(state, unlang_interpret_event_list(request)->tl, &state->ev, timeout,
			false, unlang_timeout_handler, state) < 0) {
		RPEDEBUG("Failed setting timeout for section %s", cf_section_name1(cs));
		return -1;
	}

	frame_repeat(frame, unlang_timeout_resume_done);

	return 0;

}

static unlang_t *unlang_compile_timeout(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION		*cs = cf_item_to_section(ci);
	char const		*name2;
	unlang_t		*c;
	unlang_group_t		*g;
	unlang_timeout_t	*gext;
	fr_time_delta_t		timeout = fr_time_delta_from_sec(0);
	tmpl_t			*vpt = NULL;
	fr_token_t		token;

	/*
	 *	Timeout <time ref>
	 */
	name2 = cf_section_name2(cs);
	if (!name2) {
		cf_log_err(cs, "You must specify a time value for 'timeout'");
	print_url:
		cf_log_err(ci, DOC_KEYWORD_REF(timeout));
		return NULL;
	}

	if (!cf_item_next(cs, NULL)) return UNLANG_IGNORE;

	g = unlang_group_allocate(parent, cs, UNLANG_TYPE_TIMEOUT);
	if (!g) return NULL;

	gext = unlang_group_to_timeout(g);

	token = cf_section_name2_quote(cs);

	if ((token == T_BARE_WORD) && isdigit((uint8_t) *name2)) {
		if (fr_time_delta_from_str(&timeout, name2, strlen(name2), FR_TIME_RES_SEC) < 0) {
			cf_log_err(cs, "Failed parsing time delta %s - %s",
				   name2, fr_strerror());
			return NULL;
		}
	} else {
		ssize_t		slen;
		tmpl_rules_t	t_rules;

		/*
		 *	We don't allow unknown attributes here.
		 */
		t_rules = *(unlang_ctx->rules);
		t_rules.attr.allow_unknown = false;
		RULES_VERIFY(&t_rules);

		slen = tmpl_afrom_substr(gext, &vpt,
					 &FR_SBUFF_IN(name2, strlen(name2)),
					 token,
					 NULL,
					 &t_rules);
		if (!vpt) {
			cf_canonicalize_error(cs, slen, "Failed parsing argument to 'timeout'", name2);
			talloc_free(g);
			return NULL;
		}

		/*
		 *	Fixup the tmpl so that we know it's somewhat sane.
		 */
		if (!pass2_fixup_tmpl(gext, &vpt, cf_section_to_item(cs), unlang_ctx->rules->attr.dict_def)) {
			talloc_free(g);
			return NULL;
		}

		if (tmpl_is_list(vpt)) {
			cf_log_err(cs, "Cannot use list as argument for 'timeout' statement");
		error:
			talloc_free(g);
			goto print_url;
		}

		if (tmpl_contains_regex(vpt)) {
			cf_log_err(cs, "Cannot use regular expression as argument for 'timeout' statement");
			goto error;
		}

		/*
		 *	Attribute or data MUST be cast to TIME_DELTA.
		 */
		if (tmpl_cast_set(vpt, FR_TYPE_TIME_DELTA) < 0) {
			cf_log_perr(cs, "Failed setting cast type");
			goto error;
		}
	}

	/*
	 *	Compile the contents of a "timeout".
	 */
	c = unlang_compile_section(parent, unlang_ctx, cs, UNLANG_TYPE_TIMEOUT);
	if (!c) return NULL;

	g = unlang_generic_to_group(c);
	gext = unlang_group_to_timeout(g);
	gext->timeout = timeout;
	gext->vpt = vpt;

	return c;
}

void unlang_timeout_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "timeout",
			.type = UNLANG_TYPE_TIMEOUT,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES | UNLANG_OP_FLAG_RCODE_SET,

			.compile = unlang_compile_timeout,
			.interpret = unlang_timeout,
			.signal = unlang_timeout_signal,

			.unlang_size = sizeof(unlang_timeout_t),
			.unlang_name = "unlang_timeout_t",

			.frame_state_size = sizeof(unlang_frame_state_timeout_t),
			.frame_state_type = "unlang_frame_state_timeout_t",
		});
}
