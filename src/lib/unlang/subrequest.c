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
 * @file unlang/subrequest.c
 * @brief Unlang "subrequest" and "detach" keyword evaluation.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "unlang_priv.h"

static fr_dict_t *dict_freeradius;

extern fr_dict_autoload_t subrequest_dict[];
fr_dict_autoload_t subrequest_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_request_lifetime;

extern fr_dict_attr_autoload_t subrequest_dict_attr[];
fr_dict_attr_autoload_t subrequest_dict_attr[] = {
	{ .out = &attr_request_lifetime, .name = "Request-Lifetime", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ NULL }
};

static void unlang_max_request_time(UNUSED fr_event_list_t *el, UNUSED struct timeval *now, void *uctx)
{
	REQUEST *request = talloc_get_type_abort(uctx, REQUEST);

	RDEBUG("Reached Request-Lifetime.  Forcibly stopping request");

	if (request->runnable_id >= 0) {
		rad_assert(request->backlog != NULL);
		(void) fr_heap_extract(request->backlog, request);
	}

	talloc_free(request);
}

/** Send a signal from parent request to subrequest
 *
 */
static void unlang_subrequest_signal(UNUSED REQUEST *request, void *ctx, fr_state_signal_t action)
{
	REQUEST			*child = talloc_get_type_abort(ctx, REQUEST);

	unlang_signal(child, action);
}


/** Resume a subrequest
 *
 */
static unlang_action_t unlang_subrequest_resume(REQUEST *request, rlm_rcode_t *presult, void *rctx)
{
	REQUEST			*child = talloc_get_type_abort(rctx, REQUEST);
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame;
#ifndef NDEBUG
	unlang_resume_t		*mr;
#endif

	/*
	 *	Continue running the child.
	 */
	*presult = unlang_run(child);
	if (*presult != RLM_MODULE_YIELD) {
		frame = &stack->frame[stack->depth];
		rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

		frame->instruction->type = UNLANG_TYPE_SUBREQUEST; /* for debug purposes */
		request_detach(child);
		talloc_free(child);

		return UNLANG_ACTION_CALCULATE_RESULT;
	}

#ifndef NDEBUG
	frame = &stack->frame[stack->depth];
	rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

	mr = unlang_generic_to_resume(frame->instruction);
	(void) talloc_get_type_abort(mr, unlang_resume_t);

	rad_assert(mr->resume == NULL);
	rad_assert(mr->rctx == child);
#endif

	/*
	 *	If the child yields, our current frame is still an
	 *	unlang_resume_t.
	 */

	return UNLANG_ACTION_YIELD;
}

static unlang_action_t unlang_subrequest(REQUEST *request,
					 rlm_rcode_t *presult, int *priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g;
	REQUEST			*child;
	rlm_rcode_t		rcode;
	unlang_resume_t		*mr;

	g = unlang_generic_to_group(instruction);
	rad_assert(g->children != NULL);

	/*
	 *	Allocate the child request.
	 */
	child = unlang_io_child_alloc(request, g->children, frame->result, UNLANG_NEXT_SIBLING, UNLANG_DETACHABLE);
	if (!child) {
		*presult = RLM_MODULE_FAIL;
		*priority = instruction->actions[*presult];
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	RDEBUG2("- creating subrequest (%s)", child->name);

	/*
	 *	Run the child in the same section as the master.  If
	 *	we want to run a different virtual server, we have to
	 *	create a "server" keyword.
	 *
	 *	The only difficult there is setting child->async
	 *	to... some magic value. :( That code should be in a
	 *	virtual server callback, and not directly in the
	 *	interpreter.
	 */
	rcode = unlang_run(child);
	if (rcode != RLM_MODULE_YIELD) {
		request_detach(child);
		talloc_free(child);
		*presult = rcode;
		*priority = instruction->actions[*presult];
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	As a special case, if the child instruction is
	 *	"detach", detach the child, insert the child into the
	 *	runnable queue, and keep going with the parent.
	 *
	 *	The unlang_detach() interpreter function takes care of
	 *	calling request_detach() for the child.
	 */
	{
		unlang_stack_t		*child_stack = child->stack;
		unlang_stack_frame_t	*child_frame = &child_stack->frame[child_stack->depth];
		unlang_t		*child_instruction = child_frame->instruction;

		if (child_instruction->type == UNLANG_TYPE_DETACH) {
			rad_assert(child->backlog != NULL);

			if (fr_heap_insert(child->backlog, child) < 0) {
				RPERROR("Failed inserting child into backlog");
				return UNLANG_ACTION_STOP_PROCESSING;
			}

			RDEBUG2("- detaching child request (%s)", child->name);

			/*
			 *	Tell the interpreter to skip the "detach"
			 *	stack frame when it continues.
			 */
			child_frame->instruction = child_frame->next;
			if (child_frame->instruction) child_frame->next = child_frame->instruction->next;

			*presult = RLM_MODULE_NOOP;
			*priority = 0;
			return UNLANG_ACTION_CALCULATE_RESULT;
		} /* else the child yielded, so we have to yield */
	}

	/*
	 *	Create the "resume" stack frame, and have it replace our stack frame.
	 */
	mr = unlang_resume_alloc(request, NULL, NULL, child);
	if (!mr) {
		*presult = RLM_MODULE_FAIL;
		*priority = instruction->actions[*presult];
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	*presult = RLM_MODULE_YIELD;
	return UNLANG_ACTION_YIELD;
}

static unlang_action_t unlang_detach(REQUEST *request,
				     rlm_rcode_t *presult, int *priority)
{
	VALUE_PAIR		*vp;
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;

	rad_assert(instruction->parent->type == UNLANG_TYPE_SUBREQUEST);
	RDEBUG2("%s", unlang_ops[instruction->type].name);

	rad_assert(request->parent != NULL);

	if (request_detach(request) < 0) {
		ERROR("Failed detaching child");
		*presult = RLM_MODULE_FAIL;
		*priority = 0;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Set Request Lifetime
	 */
	vp = fr_pair_find_by_da(request->control, attr_request_lifetime, TAG_ANY);
	if (!vp || (vp->vp_uint32 > 0)) {
		struct timeval when;
		const fr_event_timer_t **ev_p;

		gettimeofday(&when, NULL);

		if (!vp) {
			when.tv_sec += 30; /* default to 30s if not set */

		} else if (vp->vp_uint32 > 3600) {
			RWARN("Request-Timeout can be no more than 3600");
			when.tv_sec += 3600;

		} else if (vp->vp_uint32 < 5) {
			RWARN("Request-Timeout can be no less than 5");
			when.tv_sec += 5;

		} else {
			when.tv_sec += vp->vp_uint32;
		}

		ev_p = talloc_size(request, sizeof(*ev_p));
		memset(ev_p, 0, sizeof(*ev_p));

		(void) fr_event_timer_insert(request, request->el, ev_p,
					     &when, unlang_max_request_time, request);
	}

	/*
	 *	request_detach() sets the backlog
	 *	it does set the backlog...
	 */
	rad_assert(request->backlog != NULL);

	*presult = RLM_MODULE_YIELD;
	return UNLANG_ACTION_YIELD;
}

int unlang_subrequest_init(void)
{
	if (fr_dict_autoload(subrequest_dict) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}
	if (fr_dict_attr_autoload(subrequest_dict_attr) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}

	unlang_op_register(UNLANG_TYPE_SUBREQUEST,
			   &(unlang_op_t){
				.name = "subrequest",
				.func = unlang_subrequest,
				.signal = unlang_subrequest_signal,
				.resume = unlang_subrequest_resume,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_DETACH,
			   &(unlang_op_t){
				.name = "detach",
				.func = unlang_detach,
			   });

	return 0;
}

void unlang_subrequest_free(void)
{
	fr_dict_autofree(subrequest_dict);
}
