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
 * @file unlang/interpret.c
 * @brief Execute compiled unlang structures using an iterative interpreter.
 *
 * @copyright 2006-2016 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/parser.h>
#include <freeradius-devel/server/xlat.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/util/dlist.h>

#include "unlang_priv.h"

/*
 *	Some functions differ mainly in their parsing
 */
#define unlang_redundant_load_balance unlang_load_balance
#define unlang_policy unlang_group
#define unlang_break unlang_return

static fr_dict_t *dict_freeradius;

extern fr_dict_autoload_t op_dict[];
fr_dict_autoload_t op_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_request_lifetime;

extern fr_dict_attr_autoload_t op_dict_attr[];
fr_dict_attr_autoload_t op_dict_attr[] = {
	{ .out = &attr_request_lifetime, .name = "Request-Lifetime", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ NULL }
};

/*
 *	Recursively collect active callers.  Slow, but correct.
 */
static uint64_t unlang_active_callers(unlang_t *instruction)
{
	uint64_t active_callers;
	unlang_t *child;
	unlang_group_t *g;

	switch (instruction->type) {
	default:
		return 0;

	case UNLANG_TYPE_MODULE:
	{
		module_thread_instance_t *thread;
		unlang_module_t *sp;

		sp = unlang_generic_to_module(instruction);
		rad_assert(sp != NULL);

		thread = module_thread_instance_find(sp->module_instance);
		rad_assert(thread != NULL);

		return thread->active_callers;
	}

	case UNLANG_TYPE_GROUP:
	case UNLANG_TYPE_LOAD_BALANCE:
	case UNLANG_TYPE_REDUNDANT_LOAD_BALANCE:
	case UNLANG_TYPE_IF:
	case UNLANG_TYPE_ELSE:
	case UNLANG_TYPE_ELSIF:
	case UNLANG_TYPE_FOREACH:
	case UNLANG_TYPE_SWITCH:
	case UNLANG_TYPE_CASE:
		g = unlang_generic_to_group(instruction);

		active_callers = 0;
		for (child = g->children;
		     child != NULL;
		     child = child->next) {
			active_callers += unlang_active_callers(child);
		}
		break;
	}

	return active_callers;
}

typedef struct {
	unlang_function_t		func;			//!< To call when going down the stack.
	unlang_function_t		repeat;			//!< To call when going back up the stack.
	void				*uctx;			//!< Uctx to pass to function.
} unlang_frame_state_func_t;

/** Static instruction for allowing modules/xlats to call functions within themselves, or submodules
 *
 */
static unlang_t function_instruction = {
	.type = UNLANG_TYPE_FUNCTION,
	.name = "function",
	.debug_name = "function",
	.actions = {
		[RLM_MODULE_REJECT]	= 0,
		[RLM_MODULE_FAIL]	= 0,
		[RLM_MODULE_OK]		= 0,
		[RLM_MODULE_HANDLED]	= 0,
		[RLM_MODULE_INVALID]	= 0,
		[RLM_MODULE_USERLOCK]	= 0,
		[RLM_MODULE_NOTFOUND]	= 0,
		[RLM_MODULE_NOOP]	= 0,
		[RLM_MODULE_UPDATED]	= 0
	},
};

/** Call a generic function
 *
 * @param[in] request	The current request.
 * @param[out] presult	The frame result.  Always set to RLM_MODULE_OK (fixme?).
 * @param[out] priority of the result.
 */
static unlang_action_t unlang_function_call(REQUEST *request,
					    rlm_rcode_t *presult, int *priority)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_func_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);
	unlang_action_t			ua;
	char const 			*caller;

	/*
	 *	Don't let the callback mess with the current
	 *	module permanently.
	 */
	caller = request->module;
	request->module = NULL;
	if (!frame->repeat) {
		ua = state->func(request, presult, priority, state->uctx);
	} else {
		ua = state->repeat(request, presult, priority, state->uctx);
	}
	request->module = caller;

	return ua;
}

/** Push a generic function onto the unlang stack
 *
 * These can be pushed by any other type of unlang op to allow a submodule or function
 * deeper in the C call stack to establish a new resumption point.
 *
 * @param[in] request	The current request.
 * @param[in] func	to call going up the stack.
 * @param[in] repeat	function to call going back down the stack (may be NULL).
 *			This may be the same as func.
 * @param[in] uctx	to pass to func.
 */
void unlang_push_function(REQUEST *request, unlang_function_t func, unlang_function_t repeat, void *uctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;
	unlang_frame_state_func_t	*state;

	/*
	 *	Push module's function
	 */
	unlang_push(stack, &function_instruction, RLM_MODULE_UNKNOWN, UNLANG_NEXT_STOP, false);
	frame = &stack->frame[stack->depth];

	/*
	 *	Tell the interpreter to call unlang_function_call
	 *	again when going back up the stack.
	 */
	if (repeat) frame->repeat = true;

	/*
	 *	Allocate state
	 */
	MEM(frame->state = state = talloc_zero(stack, unlang_frame_state_func_t));

	state->func = func;
	state->repeat = repeat;
	state->uctx = uctx;
}

static unlang_action_t unlang_load_balance(REQUEST *request,
					   rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_frame_state_redundant_t	*redundant;
	unlang_group_t			*g;

	uint32_t count = 0;

	g = unlang_generic_to_group(instruction);
	rad_assert(g->children != NULL);

	/*
	 *	No frame?  This is the first time we've been called.
	 *	Go find one.
	 */
	if (!frame->repeat) {
		RDEBUG4("%s setting up", frame->instruction->debug_name);

		frame->state = redundant = talloc_zero(stack, unlang_frame_state_redundant_t);

		if (g->vpt) {
			uint32_t hash, start;
			ssize_t slen;
			char const *p = NULL;
			char buffer[1024];

			/*
			 *	Integer data types let the admin
			 *	select which frame is being used.
			 */
			if ((g->vpt->type == TMPL_TYPE_ATTR) &&
			    ((g->vpt->tmpl_da->type == FR_TYPE_UINT8) ||
			     (g->vpt->tmpl_da->type == FR_TYPE_UINT16) ||
			     (g->vpt->tmpl_da->type == FR_TYPE_UINT32) ||
			     (g->vpt->tmpl_da->type == FR_TYPE_UINT64))) {
				VALUE_PAIR *vp;

				slen = tmpl_find_vp(&vp, request, g->vpt);
				if (slen < 0) {
					REDEBUG("Failed finding attribute %s", g->vpt->name);
					goto randomly_choose;
				}

				switch (g->vpt->tmpl_da->type) {
				case FR_TYPE_UINT8:
					start = ((uint32_t) vp->vp_uint8) % g->num_children;
					break;

				case FR_TYPE_UINT16:
					start = ((uint32_t) vp->vp_uint16) % g->num_children;
					break;

				case FR_TYPE_UINT32:
					start = vp->vp_uint32 % g->num_children;
					break;

				case FR_TYPE_UINT64:
					start = (uint32_t) (vp->vp_uint64 % ((uint64_t) g->num_children));
					break;

				default:
					goto randomly_choose;
				}

			} else {
				slen = tmpl_expand(&p, buffer, sizeof(buffer), request, g->vpt, NULL, NULL);
				if (slen < 0) {
					REDEBUG("Failed expanding template");
					goto randomly_choose;
				}

				hash = fr_hash(p, slen);

				start = hash % g->num_children;;
			}

			RDEBUG3("load-balance starting at child %d", (int) start);

			count = 0;
			for (redundant->child = redundant->found = g->children;
			     redundant->child != NULL;
			     redundant->child = redundant->child->next) {
				count++;
				if (count == start) {
					redundant->found = redundant->child;
					break;
				}
			}

		} else {
			int num;
			uint64_t lowest_active_callers;

		randomly_choose:
			lowest_active_callers = ~(uint64_t ) 0;

			/*
			 *	Choose a child at random.
			 */
			for (redundant->child = redundant->found = g->children, num = 0;
			     redundant->child != NULL;
			     redundant->child = redundant->child->next, num++) {
				uint64_t active_callers;
				unlang_t *child = redundant->child;

				if (child->type != UNLANG_TYPE_MODULE) {
					active_callers = unlang_active_callers(child);
					RDEBUG3("load-balance child %d sub-section has %" PRIu64 " active", num, active_callers);

				} else {
					module_thread_instance_t *thread;
					unlang_module_t *sp;

					sp = unlang_generic_to_module(child);
					rad_assert(sp != NULL);

					thread = module_thread_instance_find(sp->module_instance);
					rad_assert(thread != NULL);

					active_callers = thread->active_callers;
					RDEBUG3("load-balance child %d sub-module has %" PRIu64 " active", num, active_callers);
				}


				/*
				 *	Reset the found, and the count
				 *	of children with this level of
				 *	activity.
				 */
				if (active_callers < lowest_active_callers) {
					RDEBUG3("load-balance choosing child %d as active %" PRIu64 " < %" PRIu64 "",
						num, active_callers, lowest_active_callers);

					count = 1;
					lowest_active_callers = active_callers;
					redundant->found = redundant->child;
					continue;
				}

				/*
				 *	Skip callers who are busier
				 *	than the one we found.
				 */
				if (active_callers > lowest_active_callers) {
					RDEBUG3("load-balance skipping child %d, as active %" PRIu64 " > %" PRIu64 "",
						num, active_callers, lowest_active_callers);
					continue;
				}

				count++;
				RDEBUG3("load-balance found %d children with %" PRIu64 " active", count, active_callers);

				if ((count * (fr_rand() & 0xffff)) < (uint32_t) 0x10000) {
					RDEBUG3("load-balance choosing random child %d", num);
					redundant->found = redundant->child;
				}
			}
		}

		if (instruction->type == UNLANG_TYPE_LOAD_BALANCE) {
			unlang_push(stack, redundant->found, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		/*
		 *	redundant-load-balance starts at this one.
		 */
		redundant->child = redundant->found;

	} else {
		RDEBUG4("%s resuming", frame->instruction->debug_name);
		redundant = talloc_get_type_abort(frame->state, unlang_frame_state_redundant_t);

		/*
		 *	We are in a resumed frame.  The module we
		 *	chose failed, so we have to go through the
		 *	process again.
		 */

		rad_assert(instruction->type != UNLANG_TYPE_LOAD_BALANCE); /* this is never called again */

		/*
		 *	We were called again.  See if we're done.
		 */
		if (redundant->child->actions[*presult] == MOD_ACTION_RETURN) {
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		/*
		 *	@todo - track the one we chose, and if it
		 *	fails, do the load-balancing again, except
		 *	this time skipping the failed module.  AND,
		 *	keep track of multiple failed modules.
		 *	Probably in the unlang_resume_t, via a
		 *	uint64_t and bit mask for simplicity.
		 */

		redundant->child = redundant->child->next;
		if (!redundant->child) redundant->child = g->children;

		if (redundant->child == redundant->found) {
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

	/*
	 *	Push the child, and yield for a later return.
	 */
	unlang_push(stack, redundant->child, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);
	frame->repeat = true;

	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_group(REQUEST *request,
				    UNUSED rlm_rcode_t *result, UNUSED int *priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g;

	g = unlang_generic_to_group(instruction);

	/*
	 *	The compiler catches most of these, EXCEPT for the
	 *	top-level 'recv Access-Request' etc.  Which can exist,
	 *	and can be empty.
	 */
	if (!g->children) {
		RDEBUG2("} # %s ... <ignoring empty subsection>", instruction->debug_name);
		return UNLANG_ACTION_CONTINUE;
	}

	unlang_push(stack, g->children, frame->result, UNLANG_NEXT_CONTINUE, UNLANG_SUB_FRAME);
	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Continue after creating a subrequest.
 *
 *  Just run some "unlang", but don't do anything else.
 */
static fr_io_final_t unlang_process_continue(UNUSED void const *instance, REQUEST *request, fr_io_action_t action)
{
	rlm_rcode_t rcode;

	REQUEST_VERIFY(request);

	/*
	 *	Pass this through asynchronously to the module which
	 *	is waiting for something to happen.
	 */
	if (action != FR_IO_ACTION_RUN) {
		unlang_signal(request, (fr_state_signal_t) action);
		return FR_IO_DONE;
	}

	rcode = unlang_interpret_continue(request);

	if (request->master_state == REQUEST_STOP_PROCESSING) return FR_IO_DONE;

	if (rcode == RLM_MODULE_YIELD) return FR_IO_YIELD;

	/*
	 *	Don't bother setting request->reply->code.
	 */
	return FR_IO_DONE;
}

/** Allocate a child request based on the parent.
 *
 */
static REQUEST *unlang_child_alloc(REQUEST *request, unlang_t *instruction, rlm_rcode_t default_rcode, bool do_next_sibling, bool detachable)
{
	REQUEST *child;
	unlang_stack_t *stack;

	if (!detachable) {
		child = request_alloc_fake(request);
	} else {
		child = request_alloc_detachable(request);
	}
	if (!child) return NULL;

	/*
	 *	Push the children, and set it's top frame to be true.
	 */
	stack = child->stack;
	child->log.unlang_indent = request->log.unlang_indent;
	unlang_push(stack, instruction, default_rcode, do_next_sibling, UNLANG_SUB_FRAME);
	stack->frame[stack->depth].top_frame = true;

	/*
	 *	Initialize some basic information for the child.
	 *
	 *	Note that we do NOT initialize child->backlog, as the
	 *	child is never resumable... the parent is resumable.
	 */
	child->number = request->number;
	child->el = request->el;
	child->server_cs = request->server_cs;

	/*
	 *	Initialize all of the async fields.
	 */
	child->async = talloc_zero(child, fr_async_t);

#define COPY_FIELD(_x) child->async->_x = request->async->_x
	COPY_FIELD(listen);
	COPY_FIELD(recv_time);
	child->async->original_recv_time = &child->async->recv_time;

	/*
	 *	Always set the "process" function to the local
	 *	bare-bones function which just runs on section of
	 *	"unlang", and doesn't send replies or anything else.
	 */
	child->async->process = unlang_process_continue;

	/*
	 *	Note that we don't do time tracking on the child.
	 *	Instead, all of it is done in the context of the
	 *	parent.
	 */
	fr_dlist_init(&child->async->tracking.list, fr_time_tracking_t, list.entry);

	/*
	 *	create {...} creates an empty copy.
	 */

	return child;
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

	rad_assert(mr->callback == NULL);
	rad_assert(mr->rctx == child);
#endif

	/*
	 *	If the child yields, our current frame is still an
	 *	unlang_resume_t.
	 */

	return UNLANG_ACTION_YIELD;
}

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
	 *	request_detach() doesn't set the "detached" flag, but
	 *	it does set the backlog...
	 */
	request->async->detached = true;
	rad_assert(request->backlog != NULL);

	*presult = RLM_MODULE_YIELD;
	return UNLANG_ACTION_YIELD;
}

static unlang_action_t unlang_call(REQUEST *request,
				   UNUSED rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g;
	int			indent;
	fr_io_final_t		final;
	unlang_stack_t		*current;
	CONF_SECTION		*server_cs;

	g = unlang_generic_to_group(instruction);
	rad_assert(g->children != NULL);

	/*
	 *	@todo - allow for other process functions.  Mostly
	 *	because we need to save and resume this function, and
	 *	we haven't bothered to do that so far.
	 *
	 *	If we DO allow other functions, we need to replace
	 *	request->async->listener, as we want to pretend this
	 *	is a virtual request which didn't come in from the
	 *	network.  i.e. the other virtual server shouldn't be
	 *	able to access request->async->listener, and muck with
	 *	it's statistics, see it's configuration, etc.
	 */
	rad_assert(request->async->process == unlang_process_continue);

	/*
	 *	@todo - We probably want to just remove the 'stack'
	 *	parameter from the interpreter function arguments.
	 *	It's not needed there.
	 */
	rad_assert(stack == request->stack);

	indent = request->log.unlang_indent;
	request->log.unlang_indent = 0; /* the process function expects this */

	current = request->stack;
	request->stack = talloc_zero(request, unlang_stack_t);

	server_cs = request->server_cs;
	request->server_cs = g->server_cs;

	memcpy(&request->async->process, &g->process, sizeof(request->async->process));

	RDEBUG("server %s {", cf_section_name2(g->server_cs));

	/*
	 *	@todo - we can't change protocols (e.g. RADIUS ->
	 *	DHCP) unless we're in a subrequest.
	 *
	 *	@todo - we can't change packet types
	 *	(e.g. Access-Request -> Accounting-Request) unless
	 *	we're in a subrequest.
	 */
	final = request->async->process(request->async->process_inst, request, FR_IO_ACTION_RUN);

	RDEBUG("} # server %s", cf_section_name2(g->server_cs));

	/*
	 *	All other return codes are semantically equivalent for
	 *	our purposes.  "DONE" means "stopped without reply",
	 *	and REPLY means "finished successfully".  Neither of
	 *	those map well into module rcodes.  Instead, we rely
	 *	on the caller to look at request->reply->code.
	 */
	if (final == FR_IO_YIELD) {
		RDEBUG("Noo yield for you!");
	}

	/*
	 *	@todo - save these in a resume state somewhere...
	 */
	request->log.unlang_indent = indent;
	request->async->process = unlang_process_continue;
	talloc_free(request->stack);
	request->stack = current;
	request->server_cs = server_cs;

	RDEBUG("Continuing with contents of %s { ...", instruction->debug_name);

	/*
	 *	And then call the children to process the answer.
	 */
	unlang_push(stack, g->children, frame->result, UNLANG_NEXT_CONTINUE, UNLANG_SUB_FRAME);
	return UNLANG_ACTION_PUSHED_CHILD;
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
	child = unlang_child_alloc(request, g->children, frame->result, UNLANG_NEXT_CONTINUE, UNLANG_DETACHABLE);
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

/** Parallel children have states
 *
 */
typedef enum unlang_parallel_child_state_t {
	CHILD_INIT = 0,				//!< needs initialization
	CHILD_RUNNABLE,
	CHILD_YIELDED,
	CHILD_DONE
} unlang_parallel_child_state_t;

/** Each parallel child has a state, and an associated request
 *
 */
typedef struct unlang_parallel_child_t {
	unlang_parallel_child_state_t	state;		//!< state of the child
	REQUEST				*child; 	//!< child request
	unlang_t			*instruction;	//!< broken out of g->children
} unlang_parallel_child_t;

typedef struct unlang_parallel_t {
	rlm_rcode_t		result;
	int			priority;

	int			num_children;

	unlang_group_t		*g;

	unlang_parallel_child_t children[];
} unlang_parallel_t;


/** Run one or more sub-sections from the parallel section.
 *
 */
static rlm_rcode_t unlang_parallel_run(REQUEST *request, unlang_parallel_t *state)
{
	int			i, priority;
	rlm_rcode_t		result;
	unlang_parallel_child_state_t done = CHILD_DONE; /* hope that we're done */

	// @todo - rdebug running the request.

	/*
	 *	Loop over all the children.
	 *
	 *	We always service the parallel section from top to
	 *	bottom, and we always service all of it.
	 */
	for (i = 0; i < state->num_children; i++) {
		switch (state->children[i].state) {
			/*
			 *	Not ready to run.
			 */
		case CHILD_YIELDED:
			RDEBUG3("parallel child %d is already YIELDED", i + 1);
			rad_assert(state->children[i].child != NULL);
			rad_assert(state->children[i].instruction != NULL);
			done = CHILD_YIELDED;
			continue;

			/*
			 *	Don't need to call this any more.
			 */
		case CHILD_DONE:
			RDEBUG3("parallel child %d is already DONE", i + 1);
			rad_assert(state->children[i].child == NULL);
			rad_assert(state->children[i].instruction == NULL);
			continue;

			/*
			 *	Create the child and then run it.
			 */
		case CHILD_INIT:
			RDEBUG3("parallel child %d is INIT", i + 1);
			rad_assert(state->children[i].instruction != NULL);
			state->children[i].child = unlang_child_alloc(request, state->children[i].instruction,
								      RLM_MODULE_FAIL, /* @todo - fixme ? */
								      UNLANG_NEXT_STOP, UNLANG_NORMAL_CHILD);
			state->children[i].state = CHILD_RUNNABLE;
			state->children[i].child->packet->code = request->packet->code;

			if (state->g->clone) {
				if ((fr_pair_list_copy(state->children[i].child->packet,
						      &state->children[i].child->packet->vps,
						      request->packet->vps) < 0) ||
				    (fr_pair_list_copy(state->children[i].child->reply,
						      &state->children[i].child->reply->vps,
						      request->reply->vps) < 0) ||
				    (fr_pair_list_copy(state->children[i].child,
						      &state->children[i].child->control,
						      request->control) < 0)) {
					REDEBUG("failed copying lists to clone");
					for (i = 0; i < state->num_children; i++) TALLOC_FREE(state->children[i].child);
					return RLM_MODULE_FAIL;
				}
			}

			/* FALL-THROUGH */

			/*
			 *	Run this entry.
			 */
		case CHILD_RUNNABLE:
			RDEBUG("parallel - running entry %d/%d", i + 1, state->num_children);
			result = unlang_run(state->children[i].child);
			if (result == RLM_MODULE_YIELD) {
				state->children[i].state = CHILD_YIELDED;
				done = CHILD_YIELDED;
				continue;
			}

			RDEBUG3("parallel child %d returns %s", i + 1,
				fr_int2str(mod_rcode_table, result, "<invalid>"));

			/*
			 *	Remember this before we delete the
			 *	reference to 'instruction'.
			 */
			priority = state->children[i].instruction->actions[result];

			/*
			 *	Clean up the state entry.
			 */
			state->children[i].state = CHILD_DONE;
			TALLOC_FREE(state->children[i].child);
			state->children[i].instruction = NULL;

			/*
			 *	return is "stop processing the
			 *	parallel section".
			 */
			if (priority == MOD_ACTION_RETURN) {
				RDEBUG("child %d/%d says 'return' - skipping the remaining children",
				       i + 1, state->num_children);

				/*
				 *	Fall through to processing the
				 *	priorities and return codes.
				 */
				i = state->num_children;
				priority = 0;
				done = CHILD_DONE;
			}

			/*
			 *	Reject is just reject.
			 */
			if (priority == MOD_ACTION_REJECT) {
				priority = 0;
				result = RLM_MODULE_REJECT;
			}

			/*
			 *	Do priority over-ride.
			 */
			if (priority > state->priority) {
				unlang_stack_t *stack = request->stack;

				state->result = result;
				state->priority = priority;

				RDEBUG4("** [%i] %s - over-riding result from higher priority to (%s %d)",
					stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, result, "<invalid>"),
					priority);
			}

			/*
			 *	Another child has yielded, so we
			 *	remember the yield instead of the fact
			 *	that we're done.
			 */
			if (done == CHILD_YIELDED) continue;

			rad_assert(done == CHILD_DONE);
			break;
		}
	}

	/*
	 *	Yield if necessary.
	 */
	if (done == CHILD_YIELDED) {
		return RLM_MODULE_YIELD;
	}

	rad_assert(done == CHILD_DONE);

	/*
	 *	Clean up all of the child requests, because once we
	 *	return, no one can access their data any more.
	 */
	for (i = 0; i < state->num_children; i++) {
		switch (state->children[i].state) {
		case CHILD_RUNNABLE:
			rad_assert(state->children[i].child->backlog == NULL);
			rad_assert(state->children[i].child->runnable_id < 0);

			/*
			 *	Un-detached children are never in the
			 *	runnable queue.
			 */
			/* FALL-THROUGH */

		case CHILD_YIELDED:
			REQUEST_VERIFY(state->children[i].child);
			rad_assert(state->children[i].child->runnable_id < 0);

			/*
			 *	Signal the child that it's going to be
			 *	stopped.  This tells any child modules
			 *	to clean up timers, etc.
			 */
			unlang_signal(state->children[i].child, FR_SIGNAL_CANCEL);
			TALLOC_FREE(state->children[i].child);
			/* FALL-THROUGH */

		default:
			state->children[i].state = CHILD_DONE;
			state->children[i].child = NULL;
			state->children[i].instruction = NULL;
			break;
		}
	}

	/*
	 *	Return the final result.  The caller will take care of
	 *	free'ing "state".
	 */
	return state->result;
}


/** Send a signal from parent request to all of it's children
 *
 */
static void unlang_parallel_signal(UNUSED REQUEST *request, void *rctx, fr_state_signal_t action)
{
	int			i;
	unlang_parallel_t	*state = talloc_get_type_abort(rctx, unlang_parallel_t);

	/*
	 *	Signal all of the children, if they exist.
	 */
	for (i = 0; i < state->num_children; i++) {
		switch (state->children[i].state) {
		case CHILD_INIT:
		case CHILD_DONE:
			break;

		case CHILD_RUNNABLE:
		case CHILD_YIELDED:
			rad_assert(state->children[i].child != NULL);
			unlang_signal(state->children[i].child, action);
			break;
		}
	}
}


static unlang_action_t unlang_parallel_resume(REQUEST *request, rlm_rcode_t *presult, void *rctx)
{
	unlang_parallel_t	*state = talloc_get_type_abort(rctx, unlang_parallel_t);
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];

#ifndef NDEBUG
	unlang_resume_t		*mr;
#endif

	/*
	 *	Continue running the child.
	 */
	*presult = unlang_parallel_run(request, state);
	if (*presult != RLM_MODULE_YIELD) {
		rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

		frame->instruction->type = UNLANG_TYPE_PARALLEL; /* for debug purposes */
		talloc_free(state);
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

#ifndef NDEBUG
	rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

	mr = unlang_generic_to_resume(frame->instruction);
	(void) talloc_get_type_abort(mr, unlang_resume_t);

	rad_assert(mr->callback == NULL);
	rad_assert(mr->rctx == state);
#endif

	/*
	 *	If the child yields, our current frame is still an
	 *	unlang_resume_t.
	 */
	return UNLANG_ACTION_YIELD;
}

static unlang_action_t unlang_parallel(REQUEST *request,
				       rlm_rcode_t *presult, int *priority)
{
	int			i;
	rlm_rcode_t		rcode;
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g;
	unlang_parallel_t	*state;
	unlang_resume_t		*mr;

	g = unlang_generic_to_group(instruction);

	if (!g->num_children) {
		*presult = RLM_MODULE_NOOP;
		*priority = instruction->actions[*presult];
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Allocate an array for the children.
	 */
	state = talloc_zero_size(request, sizeof(unlang_parallel_t) + sizeof(state->children[0]) * g->num_children);
	if (!state) {
		*presult = RLM_MODULE_FAIL;
		*priority = instruction->actions[*presult];
		return UNLANG_ACTION_CALCULATE_RESULT;
	};

	(void) talloc_set_type(state, unlang_parallel_t);
	state->result = RLM_MODULE_FAIL;
	state->priority = -1;				/* as-yet unset */
	state->g = g;
	state->num_children = g->num_children;

	/*
	 *	Initialize all of the children.
	 */
	for (i = 0, instruction = g->children; instruction != NULL; i++, instruction = instruction->next) {
		state->children[i].state = CHILD_INIT;
		state->children[i].instruction = instruction;
	}

	/*
	 *	Reset this...
	 */
	instruction = frame->instruction;

	/*
	 *	Run the various children.  On the off chance they're
	 *	all done, free things, and return.
	 */
	rcode = unlang_parallel_run(request, state);
	if (rcode != RLM_MODULE_YIELD) {
		talloc_free(state);
		*presult = rcode;
		*priority = instruction->actions[*presult];
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Create the "resume" stack frame, and have it replace our stack frame.
	 */
	mr = unlang_resume_alloc(request, NULL, NULL, state);
	if (!mr) {
		*presult = RLM_MODULE_FAIL;
		*priority = instruction->actions[*presult];
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	*presult = RLM_MODULE_YIELD;
	return UNLANG_ACTION_YIELD;
}

static unlang_action_t unlang_case(REQUEST *request,
				   rlm_rcode_t *presult, int *priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t	*g;

	g = unlang_generic_to_group(instruction);

	if (!g->children) {
		*presult = RLM_MODULE_NOOP;
		*priority = 0;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	return unlang_group(request, presult, priority);
}

static unlang_action_t unlang_return(REQUEST *request,
				     rlm_rcode_t *presult, int *priority)
{
	int			i;
	VALUE_PAIR		**copy_p;
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;

	RDEBUG2("%s", unlang_ops[instruction->type].name);

	for (i = 8; i >= 0; i--) {
		copy_p = request_data_get(request, (void *)xlat_fmt_get_vp, i);
		if (copy_p) {
			if (instruction->type == UNLANG_TYPE_BREAK) {
				RDEBUG2("# break Foreach-Variable-%d", i);
				break;
			}
		}
	}

	frame->unwind = instruction->type;

	*presult = frame->result;
	*priority = frame->priority;

	return UNLANG_ACTION_BREAK;
}

static unlang_action_t unlang_foreach(REQUEST *request,
				      rlm_rcode_t *presult, int *priority)
{
	VALUE_PAIR			*vp;
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_frame_state_foreach_t	*foreach = NULL;
	unlang_group_t			*g;

	g = unlang_generic_to_group(instruction);

	if (!frame->repeat) {
		int i, foreach_depth = -1;
		VALUE_PAIR *vps;

		if (stack->depth >= UNLANG_STACK_MAX) {
			ERROR("Internal sanity check failed: module stack is too deep");
			fr_exit(EXIT_FAILURE);
		}

		/*
		 *	Figure out how deep we are in nesting by looking at request_data
		 *	stored previously.
		 *
		 *	FIXME: figure this out by walking up the modcall stack instead.
		 */
		for (i = 0; i < 8; i++) {
			if (!request_data_reference(request, (void *)xlat_fmt_get_vp, i)) {
				foreach_depth = i;
				break;
			}
		}

		if (foreach_depth < 0) {
			REDEBUG("foreach Nesting too deep!");
			*presult = RLM_MODULE_FAIL;
			*priority = 0;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		/*
		 *	Copy the VPs from the original request, this ensures deterministic
		 *	behaviour if someone decides to add or remove VPs in the set we're
		 *	iterating over.
		 */
		if (tmpl_copy_vps(stack, &vps, request, g->vpt) < 0) {	/* nothing to loop over */
			*presult = RLM_MODULE_NOOP;
			*priority = instruction->actions[RLM_MODULE_NOOP];
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		MEM(frame->state = foreach = talloc_zero(stack, unlang_frame_state_foreach_t));

		rad_assert(vps != NULL);

		foreach->depth = foreach_depth;
		foreach->vps = vps;
		fr_cursor_talloc_init(&foreach->cursor, &foreach->vps, VALUE_PAIR);
#ifndef NDEBUG
		foreach->indent = request->log.unlang_indent;
#endif

		vp = fr_cursor_head(&foreach->cursor);
	} else {
		foreach = talloc_get_type_abort(frame->state, unlang_frame_state_foreach_t);

		vp = fr_cursor_next(&foreach->cursor);

		/*
		 *	We've been asked to unwind to the
		 *	enclosing "foreach".  We're here, so
		 *	we can stop unwinding.
		 */
		if (frame->unwind == UNLANG_TYPE_BREAK) {
			frame->unwind = UNLANG_TYPE_NULL;
			vp = NULL;
		}

		/*
		 *	Unwind all the way.
		 */
		if (frame->unwind == UNLANG_TYPE_RETURN) {
			vp = NULL;
		}

		if (!vp) {
			/*
			 *	Free the copied vps and the request data
			 *	If we don't remove the request data, something could call
			 *	the xlat outside of a foreach loop and trigger a segv.
			 */
			fr_pair_list_free(&foreach->vps);
			request_data_get(request, (void *)xlat_fmt_get_vp, foreach->depth);

			*presult = frame->result;
			if (*presult != RLM_MODULE_UNKNOWN) *priority = instruction->actions[*presult];
#ifndef NDEBUG
			rad_assert(foreach->indent == request->log.unlang_indent);
#endif
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

#ifndef NDEBUG
	RDEBUG2("");
	RDEBUG2("# looping with: Foreach-Variable-%d = %pV", foreach->depth, &vp->data);
#endif

	rad_assert(vp);

	/*
	 *	Add the vp to the request, so that
	 *	xlat.c, xlat_foreach() can find it.
	 */
	foreach->variable = vp;
	request_data_add(request, (void *)xlat_fmt_get_vp, foreach->depth, &foreach->variable,
			 false, false, false);

	/*
	 *	Push the child, and yield for a later return.
	 */
	unlang_push(stack, g->children, frame->result, UNLANG_NEXT_CONTINUE, UNLANG_SUB_FRAME);
	frame->repeat = true;

	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_switch(REQUEST *request,
				       UNUSED rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_t		*this, *found, *null_case;
	unlang_group_t		*g, *h;
	fr_cond_t		cond;
	fr_value_box_t		data;
	vp_map_t		map;
	vp_tmpl_t		vpt;

	g = unlang_generic_to_group(instruction);

	memset(&cond, 0, sizeof(cond));
	memset(&map, 0, sizeof(map));

	cond.type = COND_TYPE_MAP;
	cond.data.map = &map;

	map.op = T_OP_CMP_EQ;
	map.ci = cf_section_to_item(g->cs);

	rad_assert(g->vpt != NULL);

	null_case = found = NULL;
	data.datum.ptr = NULL;

	/*
	 *	The attribute doesn't exist.  We can skip
	 *	directly to the default 'case' statement.
	 */
	if ((g->vpt->type == TMPL_TYPE_ATTR) && (tmpl_find_vp(NULL, request, g->vpt) < 0)) {
	find_null_case:
		for (this = g->children; this; this = this->next) {
			rad_assert(this->type == UNLANG_TYPE_CASE);

			h = unlang_generic_to_group(this);
			if (h->vpt) continue;

			found = this;
			break;
		}

		goto do_null_case;
	}

	/*
	 *	Expand the template if necessary, so that it
	 *	is evaluated once instead of for each 'case'
	 *	statement.
	 */
	if ((g->vpt->type == TMPL_TYPE_XLAT_STRUCT) ||
	    (g->vpt->type == TMPL_TYPE_XLAT) ||
	    (g->vpt->type == TMPL_TYPE_EXEC)) {
		char *p;
		ssize_t len;

		len = tmpl_aexpand(request, &p, request, g->vpt, NULL, NULL);
		if (len < 0) goto find_null_case;
		data.vb_strvalue = p;
		tmpl_init(&vpt, TMPL_TYPE_UNPARSED, data.vb_strvalue, len, T_SINGLE_QUOTED_STRING);
	}

	/*
	 *	Find either the exact matching name, or the
	 *	"case {...}" statement.
	 */
	for (this = g->children; this; this = this->next) {
		rad_assert(this->type == UNLANG_TYPE_CASE);

		h = unlang_generic_to_group(this);

		/*
		 *	Remember the default case
		 */
		if (!h->vpt) {
			if (!null_case) null_case = this;
			continue;
		}

		/*
		 *	If we're switching over an attribute
		 *	AND we haven't pre-parsed the data for
		 *	the case statement, then cast the data
		 *	to the type of the attribute.
		 */
		if ((g->vpt->type == TMPL_TYPE_ATTR) &&
		    (h->vpt->type != TMPL_TYPE_DATA)) {
			map.rhs = g->vpt;
			map.lhs = h->vpt;
			cond.cast = g->vpt->tmpl_da;

			/*
			 *	Remove unnecessary casting.
			 */
			if ((h->vpt->type == TMPL_TYPE_ATTR) &&
			    (g->vpt->tmpl_da->type == h->vpt->tmpl_da->type)) {
				cond.cast = NULL;
			}

			/*
			 *	Use the pre-expanded string.
			 */
		} else if ((g->vpt->type == TMPL_TYPE_XLAT_STRUCT) ||
			   (g->vpt->type == TMPL_TYPE_XLAT) ||
			   (g->vpt->type == TMPL_TYPE_EXEC)) {
			map.rhs = h->vpt;
			map.lhs = &vpt;
			cond.cast = NULL;

			/*
			 *	Else evaluate the 'switch' statement.
			 */
		} else {
			map.rhs = h->vpt;
			map.lhs = g->vpt;
			cond.cast = NULL;
		}

		if (cond_eval_map(request, RLM_MODULE_UNKNOWN, 0,
					&cond) == 1) {
			found = this;
			break;
		}
	}

	if (!found) found = null_case;

do_null_case:
	talloc_free(data.datum.ptr);

	/*
	 *	Nothing found.  Just continue, and ignore the "switch"
	 *	statement.
	 */
	if (!found) return UNLANG_ACTION_CONTINUE;

	unlang_push(stack, found, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);
	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_if(REQUEST *request,
				   rlm_rcode_t *presult, int *priority)
{
	int			condition;
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g;

	g = unlang_generic_to_group(instruction);
	rad_assert(g->cond != NULL);

	condition = cond_eval(request, *presult, 0, g->cond);
	if (condition < 0) {
		switch (condition) {
		case -2:
			REDEBUG("Condition evaluation failed because a referenced attribute "
				"was not found in the request");
			break;
		default:
		case -1:
			REDEBUG("Condition evaluation failed because the value of an operand "
				"could not be determined");
			break;
		}
		condition = 0;
	}

	/*
	 *	Didn't pass.  Remember that.
	 */
	if (!condition) {
		RDEBUG2("...");

		if (*presult != RLM_MODULE_UNKNOWN) *priority = instruction->actions[*presult];

		return UNLANG_ACTION_CONTINUE;
	}

	/*
	 *	Tell the main interpreter to skip over the else /
	 *	elsif blocks, as this "if" condition was taken.
	 */
	while (frame->next &&
	       ((frame->next->type == UNLANG_TYPE_ELSE) ||
		(frame->next->type == UNLANG_TYPE_ELSIF))) {
		frame->next = frame->next->next;
	}

	/*
	 *	We took the "if".  Go recurse into its' children.
	 */
	return unlang_group(request, presult, priority);
}

int unlang_op_init(void)
{
	if (fr_dict_autoload(op_dict) < 0) return -1;
	if (fr_dict_attr_autoload(op_dict_attr) < 0) return -1;

	unlang_op_register(UNLANG_TYPE_FUNCTION,
			   &(unlang_op_t){
				.name = "function",
				.func = unlang_function_call,
				.debug_braces = false
			   });

	unlang_op_register(UNLANG_TYPE_GROUP,
			   &(unlang_op_t){
				.name = "group",
				.func = unlang_group,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_LOAD_BALANCE,
			   &(unlang_op_t){
				.name = "load-balance group",
				.func = unlang_load_balance,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_REDUNDANT_LOAD_BALANCE,
			   &(unlang_op_t){
				.name = "redundant-load-balance group",
				.func = unlang_redundant_load_balance,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_PARALLEL,
			   &(unlang_op_t){
				.name = "parallel",
				.func = unlang_parallel,
				.signal = unlang_parallel_signal,
				.resume = unlang_parallel_resume,
				.debug_braces = true
			   });

#ifdef WITH_UNLANG
	unlang_op_register(UNLANG_TYPE_IF,
			   &(unlang_op_t){
				.name = "if",
				.func = unlang_if,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_ELSE,
			   &(unlang_op_t){
				.name = "else",
				.func = unlang_group,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_ELSIF,
			   &(unlang_op_t){
				.name = "elseif",
				.func = unlang_if,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_SWITCH,
			   &(unlang_op_t){
				.name = "switch",
				.func = unlang_switch,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_CASE,
			   &(unlang_op_t){
				.name = "case",
				.func = unlang_case,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_FOREACH,
			   &(unlang_op_t){
				.name = "foreach",
				.func = unlang_foreach,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_BREAK,
			   &(unlang_op_t){
				.name = "break",
				.func = unlang_break,
			   });

	unlang_op_register(UNLANG_TYPE_RETURN,
			   &(unlang_op_t){
				.name = "return",
				.func = unlang_return,
			   });

	unlang_op_register(UNLANG_TYPE_POLICY,
			   &(unlang_op_t){
				.name = "policy",
				.func = unlang_policy,
			   });


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

	unlang_op_register(UNLANG_TYPE_CALL,
			   &(unlang_op_t){
				.name = "call",
				.func = unlang_call,
				.debug_braces = true
			   });

	unlang_map_init();
	unlang_module_init();
#endif

	return 0;
}

void unlang_op_free(void)
{
	fr_dict_autofree(op_dict);
}
