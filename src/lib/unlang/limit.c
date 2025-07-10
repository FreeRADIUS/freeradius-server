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
 * @file unlang/limit.c
 * @brief Unlang "limit" keyword evaluation.
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/rcode.h>
#include "group_priv.h"
#include "limit_priv.h"

typedef struct {
	uint32_t				active_callers;
} unlang_thread_limit_t;

typedef struct {
	unlang_thread_limit_t			*thread;
	uint32_t				limit;
	request_t				*request;

	fr_value_box_list_t			result;
} unlang_frame_state_limit_t;

/** Send a signal (usually stop) to a request
 *
 * @param[in] request		The current request.
 * @param[in] frame		current stack frame.
 * @param[in] action		to signal.
 */
static void unlang_limit_signal(UNUSED request_t *request, unlang_stack_frame_t *frame, fr_signal_t action)
{
	unlang_frame_state_limit_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_limit_t);

	if (action == FR_SIGNAL_CANCEL) {
		state->thread->active_callers--;
	}
}

static unlang_action_t unlang_limit_resume_done(UNUSED unlang_result_t *p_result, UNUSED request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_limit_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_limit_t);

	state->thread->active_callers--;

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_limit_enforce(UNUSED unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_limit_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_limit_t);
	unlang_action_t			action;

	state->thread = unlang_thread_instance(frame->instruction);
	fr_assert(state->thread != NULL);

	if (state->thread->active_callers >= state->limit) return UNLANG_ACTION_FAIL;

	frame_repeat(frame, unlang_limit_resume_done);

	action = unlang_interpret_push_children(NULL, request, RLM_MODULE_NOT_SET, UNLANG_NEXT_STOP);

	state->thread->active_callers += (action == UNLANG_ACTION_PUSHED_CHILD);

	return action;
}

static unlang_action_t unlang_limit_xlat_done(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_limit_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_limit_t);
	fr_value_box_t			*box = fr_value_box_list_head(&state->result);

	if (unlikely(!box)) RETURN_UNLANG_FAIL;
	/*
	 *	compile_limit() ensures that the tmpl is cast to uint32, so we don't have to do any more work here.
	 */
	state->limit = box->vb_uint32;

	return unlang_limit_enforce(p_result, request, frame);
}

static unlang_action_t unlang_limit(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t			*g;
	unlang_limit_t			*gext;
	unlang_frame_state_limit_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_limit_t);

	g = unlang_generic_to_group(frame->instruction);
	gext = unlang_group_to_limit(g);

	state->request = request;

	if (!gext->vpt) {
		state->limit = gext->limit;
		return unlang_limit_enforce(p_result, request, frame);
	}

	fr_value_box_list_init(&state->result);

	if (unlang_tmpl_push(state, NULL, &state->result, request, gext->vpt, NULL) < 0) return UNLANG_ACTION_FAIL;

	frame_repeat(frame, unlang_limit_xlat_done);

	return UNLANG_ACTION_PUSHED_CHILD;
}


static unlang_t *unlang_compile_limit(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION		*cs = cf_item_to_section(ci);
	char const		*name2;
	unlang_t		*c;
	unlang_group_t		*g;
	unlang_limit_t		*gext;
	tmpl_t			*vpt = NULL;
	uint32_t		limit = 0;
	fr_token_t		token;
	ssize_t			slen;
	tmpl_rules_t		t_rules;

	/*
	 *	limit <number>
	 */
	name2 = cf_section_name2(cs);
	if (!name2) {
		cf_log_err(cs, "You must specify a value for 'limit'");
	print_url:
		cf_log_err(ci, DOC_KEYWORD_REF(limit));
		return NULL;
	}

	if (!cf_item_next(cs, NULL)) return UNLANG_IGNORE;

	g = unlang_group_allocate(parent, cs, UNLANG_TYPE_LIMIT);
	if (!g) return NULL;

	gext = unlang_group_to_limit(g);

	token = cf_section_name2_quote(cs);

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
	syntax_error:
		cf_canonicalize_error(cs, slen, "Failed parsing argument to 'foreach'", name2);
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
		cf_log_err(cs, "Cannot use list as argument for 'limit' statement");
	error:
		talloc_free(g);
		goto print_url;
	}

	if (tmpl_contains_regex(vpt)) {
		cf_log_err(cs, "Cannot use regular expression as argument for 'limit' statement");
		goto error;
	}

	if (tmpl_is_data(vpt) && (token == T_BARE_WORD)) {
		fr_value_box_t box;

		if (fr_value_box_cast(NULL, &box, FR_TYPE_UINT32, NULL, tmpl_value(vpt)) < 0) goto syntax_error;

		limit = box.vb_uint32;

	} else {
		/*
		 *	Attribute or data MUST be cast to a 32-bit unsigned number.
		 */
		if (tmpl_cast_set(vpt, FR_TYPE_UINT32) < 0) {
			cf_log_perr(cs, "Failed setting cast type");
			goto syntax_error;
		}
	}

	/*
	 *	Compile the contents of a "limit".
	 */
	c = unlang_compile_section(parent, unlang_ctx, cs, UNLANG_TYPE_LIMIT);
	if (!c) return NULL;

	g = unlang_generic_to_group(c);
	gext = unlang_group_to_limit(g);
	gext->limit = limit;
	gext->vpt = vpt;

	return c;
}

void unlang_limit_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "limit",
			.type = UNLANG_TYPE_LIMIT,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

			.compile = unlang_compile_limit,
			.interpret = unlang_limit,
			.signal = unlang_limit_signal,

			.unlang_size = sizeof(unlang_limit_t),
			.unlang_name = "unlang_limit_t",

			.frame_state_size = sizeof(unlang_frame_state_limit_t),
			.frame_state_type = "unlang_frame_state_limit_t",

			.thread_inst_size = sizeof(unlang_thread_limit_t),
			.thread_inst_type = "unlang_thread_limit_t",
		});
}
