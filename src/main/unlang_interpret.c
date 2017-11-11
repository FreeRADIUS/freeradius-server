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
 * @file unlang_interpret.c
 * @brief Execute compiled unlang structures using an iterative interpreter.
 *
 * @copyright 2006-2016 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/interpreter.h>
#include <freeradius-devel/parser.h>
#include <freeradius-devel/io/listen.h>

static FR_NAME_NUMBER unlang_action_table[] = {
	{ "calculate-result",	UNLANG_ACTION_CALCULATE_RESULT },
	{ "continue",		UNLANG_ACTION_CONTINUE },
	{ "pushed-child",	UNLANG_ACTION_PUSHED_CHILD },
	{ "break", 		UNLANG_ACTION_BREAK },
	{ "yield",		UNLANG_ACTION_YIELD },
	{ "stop",		UNLANG_ACTION_STOP_PROCESSING },
	{ NULL, -1 }
};

#define UNLANG_NEXT_STOP (false)
#define UNLANG_NEXT_CONTINUE (true)

#define UNLANG_TOP_FRAME (true)
#define UNLANG_SUB_FRAME (false)

#define UNLANG_DETACHABLE (true)
#define UNLANG_NORMAL_CHILD (false)

typedef rlm_rcode_t (*unlang_op_resume_func_t)(REQUEST *request,
					       void *instance, void *thread, void *resume_ctx);

/*
 *	Lock the mutex for the module
 */
static inline void safe_lock(module_instance_t *instance)
{
	if (instance->mutex) pthread_mutex_lock(instance->mutex);
}

/*
 *	Unlock the mutex for the module
 */
static inline void safe_unlock(module_instance_t *instance)
{
	if (instance->mutex) pthread_mutex_unlock(instance->mutex);
}

/** Continue after creating a subrequest.
 *
 *  Just run some "unlang", but don't do anything else.
 */
static fr_io_final_t unlang_process_continue(REQUEST *request, fr_io_action_t action)
{
	rlm_rcode_t rcode;

	REQUEST_VERIFY(request);

	/*
	 *	Pass this through asynchronously to the module which
	 *	is waiting for something to happen.
	 */
	if (action != FR_IO_ACTION_RUN) {
		unlang_signal(request, (fr_state_action_t) action);
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

#ifndef NDEBUG
unlang_op_t unlang_ops[];

static void unlang_dump_instruction(REQUEST *request, unlang_t *instruction)
{
	RINDENT();
	if (!instruction) {
		RDEBUG("instruction = NULL");
		REXDENT();
		return;
	}
	RDEBUG("type           %s", unlang_ops[instruction->type].name);
	RDEBUG("name           %s", instruction->name);
	RDEBUG("debug_name     %s", instruction->debug_name);
	REXDENT();
}

static void unlang_dump_frame(REQUEST *request, unlang_stack_frame_t *frame)
{
	unlang_dump_instruction(request, frame->instruction);

	RINDENT();
	if (frame->next) {
		RDEBUG("next           %s", frame->next->debug_name);
	} else {
		RDEBUG("next           <none>");
	}
	RDEBUG("top_frame      %s", frame->top_frame ? "yes" : "no");
	RDEBUG("result         %s", fr_int2str(mod_rcode_table, frame->result, "<invalid>"));
	RDEBUG("priority       %d", frame->priority);
	RDEBUG("unwind         %d", frame->unwind);
	RDEBUG("repeat         %s", frame->repeat ? "yes" : "no");
	REXDENT();
}


static void unlang_dump_stack(REQUEST *request)
{
	int i;
	unlang_stack_t *stack = request->stack;

	RDEBUG("----- Begin stack debug [depth %i] -----", stack->depth);
	for (i = stack->depth; i >= 0; i--) {
		unlang_stack_frame_t *frame = &stack->frame[i];

		RDEBUG("[%d] Frame contents", i);
		unlang_dump_frame(request, frame);
	}

	RDEBUG("----- End stack debug [depth %i] -------", stack->depth);
}
#define DUMP_STACK if (DEBUG_ENABLED5) unlang_dump_stack(request)
#else
#define DUMP_STACK
#endif


/** Push a new frame onto the stack
 *
 * @param[in] stack		to push the frame onto.
 * @param[in] program		One or more unlang_t nodes describing the operations to execute.
 * @param[in] result		The default result.
 * @param[in] do_next_sibling	Whether to only execute the first node in the #unlang_t program
 *				or to execute subsequent nodes.
 * @param[in] top_frame		Return out of the unlang interpreter when popping this frame.
 *				Hands execution back to whatever called the interpreter.
 */
static inline void unlang_push(unlang_stack_t *stack, unlang_t *program,
			       rlm_rcode_t result, bool do_next_sibling, bool top_frame)
{
	unlang_stack_frame_t *frame;

	rad_assert(program || top_frame);

#ifndef NDEBUG
	if (DEBUG_ENABLED5) DEBUG("unlang_push called with instruction %s - args %s %s",
				  program ? program->debug_name : "<none>",
				  do_next_sibling ? "UNLANG_NEXT_CONTINUE" : "UNLANG_NEXT_STOP",
				  top_frame ? "UNLANG_TOP_FRAME" : "UNLANG_SUB_FRAME");
#endif

	if (stack->depth >= (UNLANG_STACK_MAX - 1)) {
		ERROR("Internal sanity check failed: module stack is too deep");
		fr_exit(1);
	}

	stack->depth++;

	/*
	 *	Initialize the next stack frame.
	 */
	frame = &stack->frame[stack->depth];

	if (do_next_sibling) {
		rad_assert(program != NULL);
		frame->next = program->next;
	} else {
		frame->next = NULL;
	}

	frame->top_frame = top_frame;
	frame->instruction = program;
	frame->result = result;
	frame->priority = -1;
	frame->unwind = UNLANG_TYPE_NULL;
	frame->repeat = false;
	frame->state = NULL;
}

/** Pop a stack frame, removing any associated dynamically allocated state
 *
 * @param[in] stack	frame to pop.
 */
static inline void unlang_pop(unlang_stack_t *stack)
{
	unlang_stack_frame_t *frame, *next;

	rad_assert(stack->depth > 1);

	frame = &stack->frame[stack->depth];
	if (frame->state) talloc_free(frame->state);

	frame = &stack->frame[--stack->depth];
	next = frame + 1;

	/*
	 *	Unwind back up the stack
	 */
	if (next->unwind != 0) frame->unwind = next->unwind;
}


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

	case UNLANG_TYPE_MODULE_CALL:
	{
		module_thread_instance_t *thread;
		unlang_module_call_t *sp;

		sp = unlang_generic_to_module_call(instruction);
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

static unlang_action_t unlang_load_balance(REQUEST *request,
					   rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g;

	uint32_t count = 0;

	g = unlang_generic_to_group(instruction);
	rad_assert(g->children != NULL);

	/*
	 *	No frame?  This is the first time we've been called.
	 *	Go find one.
	 */
	if (!frame->repeat) {
		RDEBUG4("%s setting up", frame->instruction->debug_name);

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
			for (frame->redundant.child = frame->redundant.found = g->children;
			     frame->redundant.child != NULL;
			     frame->redundant.child = frame->redundant.child->next) {
				count++;
				if (count == start) {
					frame->redundant.found = frame->redundant.child;
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
			for (frame->redundant.child = frame->redundant.found = g->children, num = 0;
			     frame->redundant.child != NULL;
			     frame->redundant.child = frame->redundant.child->next, num++) {
				uint64_t active_callers;
				unlang_t *child = frame->redundant.child;

				if (child->type != UNLANG_TYPE_MODULE_CALL) {
					active_callers = unlang_active_callers(child);
					RDEBUG3("load-balance child %d sub-section has %" PRIu64 " active", num, active_callers);

				} else {
					module_thread_instance_t *thread;
					unlang_module_call_t *sp;

					sp = unlang_generic_to_module_call(child);
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
					frame->redundant.found = frame->redundant.child;
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
					frame->redundant.found = frame->redundant.child;
				}
			}
		}

		if (instruction->type == UNLANG_TYPE_LOAD_BALANCE) {
			unlang_push(stack, frame->redundant.found, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		/*
		 *	redundant-load-balance starts at this one.
		 */
		frame->redundant.child = frame->redundant.found;

	} else {
		RDEBUG4("%s resuming", frame->instruction->debug_name);

		/*
		 *	We are in a resumed frame.  The module we
		 *	chose failed, so we have to go through the
		 *	process again.
		 */

		rad_assert(instruction->type != UNLANG_TYPE_LOAD_BALANCE); /* this is never called again */

		/*
		 *	We were called again.  See if we're done.
		 */
		if (frame->redundant.child->actions[*presult] == MOD_ACTION_RETURN) {
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

		frame->redundant.child = frame->redundant.child->next;
		if (!frame->redundant.child) frame->redundant.child = g->children;

		if (frame->redundant.child == frame->redundant.found) {
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

	/*
	 *	Push the child, and yield for a later return.
	 */
	unlang_push(stack, frame->redundant.child, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);
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

static rlm_rcode_t unlang_run(REQUEST *request);


/** Allocates and initializes an unlang_resume_t
 *
 * @param[in] request		The current request.
 * @param[in] callback		to call on unlang_resumable().
 * @param[in] signal_callback	to call on unlang_action().
 * @param[in] ctx		to pass to the callbacks.
 * @return
 *	unlang_resume_t on success
 *	NULL on error
 */
static unlang_resume_t *unlang_resume_alloc(REQUEST *request,
					    fr_unlang_resume_callback_t callback,
					    fr_unlang_action_t signal_callback, void *ctx)
{
	unlang_resume_t 		*mr;
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];

	mr = talloc_zero(request, unlang_resume_t);
	if (!mr) return NULL;

	/*
	 *	Remember the parent type.
	 */
	mr->parent_type = frame->instruction->type;

	/*
	 *	Initialize parent ptr, next ptr, name, debug_name,
	 *	type, actions, etc.
	 */
	memcpy(&mr->self, frame->instruction, sizeof(mr->self));

	/*
	 *	But note that we're of type RESUME
	 */
	mr->self.type = UNLANG_TYPE_RESUME;

	/*
	 *	Fill in the signal handlers and resumption ctx
	 */
	mr->callback = callback;
	mr->signal_callback = signal_callback;
	mr->resume_ctx = ctx;

	/*
	 *	Replaces the current stack frame with a RESUME frame.
	 */
	frame->instruction = unlang_resume_to_generic(mr);

	return mr;
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
	COPY_FIELD(original_recv_time);
	COPY_FIELD(recv_time);
	COPY_FIELD(listen);

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
	FR_DLIST_INIT(child->async->time_order);
	FR_DLIST_INIT(child->async->tracking.list);

	/*
	 *	create {...} creates an empty copy.
	 */

	return child;
}


/** Send a signal from parent request to subrequest
 *
 */
static void unlang_subrequest_signal(UNUSED REQUEST *request, UNUSED void *instance, UNUSED void *thread, void *ctx,
			       fr_state_action_t action)
{
	REQUEST			*child = talloc_get_type_abort(ctx, REQUEST);

	unlang_signal(child, action);
}


/** Resume a subrequest
 *
 */
static rlm_rcode_t unlang_subrequest_resume(UNUSED REQUEST *request,
					    UNUSED void *instance, UNUSED void *thread, void *resume_ctx)
{
	REQUEST			*child = talloc_get_type_abort(resume_ctx, REQUEST);
	unlang_stack_t		*stack = request->stack;
	rlm_rcode_t		rcode;
	unlang_stack_frame_t	*frame;
#ifndef NDEBUG
	unlang_resume_t		*mr;
#endif

	/*
	 *	Continue running the child.
	 */
	rcode = unlang_run(child);
	if (rcode != RLM_MODULE_YIELD) {
		frame = &stack->frame[stack->depth];
		rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

		frame->instruction->type = UNLANG_TYPE_SUBREQUEST; /* for debug purposes */
		request_detach(child);
		talloc_free(child);
		return rcode;
	}

#ifndef NDEBUG
	frame = &stack->frame[stack->depth];
	rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

	mr = unlang_generic_to_resume(frame->instruction);
	(void) talloc_get_type_abort(mr, unlang_resume_t);

	rad_assert(mr->callback == NULL);
	rad_assert(mr->signal_callback == unlang_subrequest_signal);
	rad_assert(mr->resume_ctx == child);
#endif

	/*
	 *	If the child yields, our current frame is still an
	 *	unlang_resume_t.
	 */
	return RLM_MODULE_YIELD;
}

static rlm_rcode_t unlang_module_resume(REQUEST *request,
					UNUSED void *instance, UNUSED void *thread, UNUSED void *resume_ctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_resume_t			*mr = unlang_generic_to_resume(instruction);
	unlang_stack_state_modcall_t	*modcall_state = NULL;
	rlm_rcode_t			rcode;

	rad_assert(mr->parent_type == UNLANG_TYPE_MODULE_CALL);

	modcall_state = talloc_get_type_abort(frame->state,
					      unlang_stack_state_modcall_t);

	/*
	 *	Lock is noop unless instance->mutex is set.
	 */
	safe_lock(mr->module_instance);
	rcode = request->rcode = mr->callback(request, instance, mr->thread, mr->resume_ctx);
	safe_unlock(mr->module_instance);

	if (rcode != RLM_MODULE_YIELD) modcall_state->thread->active_callers--;

	RDEBUG2("%s (%s)", instruction->name ? instruction->name : "",
		fr_int2str(mod_rcode_table, rcode, "<invalid>"));

	return rcode;
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

	if (request_detach(request) < 0) {
		ERROR("Failed detaching child");
		*presult = RLM_MODULE_FAIL;
		*priority = 0;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Set Request Lifetime
	 */
	vp = fr_pair_find_by_num(request->control, 0, FR_REQUEST_LIFETIME, TAG_ANY);
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

	request->async->process = g->process;

	RDEBUG("server %s {", cf_section_name2(g->server_cs));

	/*
	 *	@todo - we can't change protocols (e.g. RADIUS ->
	 *	DHCP) unless we're in a subrequest.
	 *
	 *	@todo - we can't change packet types
	 *	(e.g. Access-Request -> Accounting-Request) unless
	 *	we're in a subrequest.
	 */
	final = request->async->process(request, FR_IO_ACTION_RUN);

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
			fr_heap_insert(child->backlog, child);

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
	mr = unlang_resume_alloc(request, NULL, unlang_subrequest_signal, child);
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
				state->children[i].child->packet->vps = fr_pair_list_copy(state->children[i].child->packet,
											  request->packet->vps);
				state->children[i].child->reply->vps = fr_pair_list_copy(state->children[i].child->reply,
											 request->reply->vps);
				state->children[i].child->control = fr_pair_list_copy(state->children[i].child,
										      request->control);
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
static void unlang_parallel_signal(UNUSED REQUEST *request, UNUSED void *instance, UNUSED void *thread, void *ctx,
				   fr_state_action_t action)
{
	int			i;
	unlang_parallel_t	*state = talloc_get_type_abort(ctx, unlang_parallel_t);

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


static rlm_rcode_t unlang_parallel_resume(REQUEST *request,
					  UNUSED void *instance, UNUSED void *thread, void *resume_ctx)
{
	rlm_rcode_t		rcode;
	unlang_parallel_t	*state = talloc_get_type_abort(resume_ctx, unlang_parallel_t);
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];

#ifndef NDEBUG
	unlang_resume_t		*mr;
#endif

	/*
	 *	Continue running the child.
	 */
	rcode = unlang_parallel_run(request, state);
	if (rcode != RLM_MODULE_YIELD) {
		rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

		frame->instruction->type = UNLANG_TYPE_PARALLEL; /* for debug purposes */
		talloc_free(state);
		return rcode;
	}

#ifndef NDEBUG
	rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

	mr = unlang_generic_to_resume(frame->instruction);
	(void) talloc_get_type_abort(mr, unlang_resume_t);

	rad_assert(mr->callback == NULL);
	rad_assert(mr->signal_callback == unlang_parallel_signal);
	rad_assert(mr->resume_ctx == state);
#endif

	/*
	 *	If the child yields, our current frame is still an
	 *	unlang_resume_t.
	 */
	return RLM_MODULE_YIELD;
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
	mr = unlang_resume_alloc(request, NULL, unlang_parallel_signal, state);
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
		copy_p = request_data_get(request, (void *)radius_get_vp, i);
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
	VALUE_PAIR		*vp;
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t	*g;

	g = unlang_generic_to_group(instruction);

	if (!frame->repeat) {
		int i, foreach_depth = -1;
		VALUE_PAIR *vps;

		if (stack->depth >= UNLANG_STACK_MAX) {
			ERROR("Internal sanity check failed: module stack is too deep");
			fr_exit(1);
		}

		/*
		 *	Figure out how deep we are in nesting by looking at request_data
		 *	stored previously.
		 *
		 *	FIXME: figure this out by walking up the modcall stack instead.
		 */
		for (i = 0; i < 8; i++) {
			if (!request_data_reference(request, (void *)radius_get_vp, i)) {
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
		 *	behaviour if someone decides to add or remove VPs in the set were
		 *	iterating over.
		 */
		if (tmpl_copy_vps(request, &vps, request, g->vpt) < 0) {	/* nothing to loop over */
			*presult = RLM_MODULE_NOOP;
			*priority = instruction->actions[RLM_MODULE_NOOP];
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		rad_assert(vps != NULL);
		fr_pair_cursor_init(&frame->foreach.cursor, &vps);

		frame->foreach.depth = foreach_depth;
		frame->foreach.vps = vps;
#ifndef NDEBUG
		frame->foreach.indent = request->log.unlang_indent;
#endif

		vp = fr_pair_cursor_first(&frame->foreach.cursor);

	} else {
		vp = fr_pair_cursor_next(&frame->foreach.cursor);

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
			fr_pair_list_free(&frame->foreach.vps);
			request_data_get(request, (void *)radius_get_vp, frame->foreach.depth);

			*presult = frame->result;
			if (*presult != RLM_MODULE_UNKNOWN) *priority = instruction->actions[*presult];
#ifndef NDEBUG
			rad_assert(frame->foreach.indent == request->log.unlang_indent);
#endif
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

#ifndef NDEBUG
	if (DEBUG_ENABLED2) {
		char buffer[1024];

			fr_pair_value_snprint(buffer, sizeof(buffer), vp, '"');
			RDEBUG2("");
			RDEBUG2("# looping with: Foreach-Variable-%d = %s", frame->foreach.depth, buffer);
		}
#endif

	/*
	 *	Add the vp to the request, so that
	 *	xlat.c, xlat_foreach() can find it.
	 */
	frame->foreach.variable = vp;
	request_data_add(request, (void *)radius_get_vp, frame->foreach.depth, &frame->foreach.variable,
			 false, false, false);

	/*
	 *	Push the child, and yield for a later return.
	 */
	unlang_push(stack, g->children, frame->result, UNLANG_NEXT_CONTINUE, UNLANG_SUB_FRAME);
	frame->repeat = true;
	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_xlat_inline(REQUEST *request,
					  UNUSED rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_xlat_inline_t	*mx = unlang_generic_to_xlat_inline(instruction);
	char buffer[128];

	if (!mx->exec) {
		(void) xlat_eval_compiled(buffer, sizeof(buffer), request, mx->exp, NULL, NULL);
	} else {
		RDEBUG("`%s`", mx->xlat_name);
		radius_exec_program(request, NULL, 0, NULL, request, mx->xlat_name, request->packet->vps,
				    false, true, EXEC_TIMEOUT);
	}

	return UNLANG_ACTION_CONTINUE;
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


static unlang_action_t unlang_update(REQUEST *request,
				     rlm_rcode_t *presult, int *priority)
{
	int rcode;
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g = unlang_generic_to_group(instruction);
	vp_map_t *map;

	for (map = g->map; map != NULL; map = map->next) {
		rcode = map_to_request(request, map, map_to_vp, NULL);
		if (rcode < 0) {
			*presult = (rcode == -2) ? RLM_MODULE_INVALID : RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

	*presult = RLM_MODULE_NOOP;
	*priority = instruction->actions[RLM_MODULE_NOOP];
	return UNLANG_ACTION_CALCULATE_RESULT;
}


static unlang_action_t unlang_map(REQUEST *request,
				  rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g = unlang_generic_to_group(instruction);

	*presult = map_proc(request, g->proc_inst);

	return *presult == RLM_MODULE_YIELD ? UNLANG_ACTION_YIELD : UNLANG_ACTION_CALCULATE_RESULT;
}


static unlang_action_t unlang_module_call(REQUEST *request,
				     	  rlm_rcode_t *presult, int *priority)
{
	unlang_module_call_t		*sp;
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_stack_state_modcall_t	*modcall_state;

#ifndef NDEBUG
	int unlang_indent		= request->log.unlang_indent;
#endif

	/*
	 *	Process a stand-alone child, and fall through
	 *	to dealing with it's parent.
	 */
	sp = unlang_generic_to_module_call(instruction);
	rad_assert(sp);

	RDEBUG4("[%i] %s - %s (%s)", stack->depth, __FUNCTION__,
		sp->module_instance->name, sp->module_instance->module->name);

	/*
	 *	Return administratively configured return code
	 */
	if (sp->module_instance->force) {
		request->rcode = sp->module_instance->code;
		goto done;
	}

	frame->state = modcall_state = talloc_zero(stack, unlang_stack_state_modcall_t);

	/*
	 *	Grab the thread/module specific data if any exists.
	 */
	modcall_state->thread = module_thread_instance_find(sp->module_instance);
	rad_assert(modcall_state->thread != NULL);

	/*
	 *	For logging unresponsive children.
	 */
	request->module = sp->module_instance->name;
	modcall_state->thread->total_calls++;

	/*
	 *	Lock is noop unless instance->mutex is set.
	 */
	safe_lock(sp->module_instance);
	*presult = request->rcode = sp->method(sp->module_instance->dl_inst->data, modcall_state->thread->data, request);
	safe_unlock(sp->module_instance);

	request->module = NULL;

	/*
	 *	Is now marked as "stop" when it wasn't before, we must have been blocked.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) {
		RWARN("Module %s became unblocked",
		      sp->module_instance->module->name);
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	if (*presult == RLM_MODULE_YIELD) {
		modcall_state->thread->active_callers++;
	} else {
		rad_assert(unlang_indent == request->log.unlang_indent);

		rad_assert(*presult >= RLM_MODULE_REJECT);
		rad_assert(*presult < RLM_MODULE_NUMCODES);
		*priority = instruction->actions[*presult];
	}

done:
	*presult = request->rcode;
	RDEBUG2("%s (%s)", instruction->name ? instruction->name : "",
		fr_int2str(mod_rcode_table, *presult, "<invalid>"));

	return *presult == RLM_MODULE_YIELD ? UNLANG_ACTION_YIELD : UNLANG_ACTION_CALCULATE_RESULT;
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

static unlang_op_resume_func_t unlang_ops_resume[] = {
	[UNLANG_TYPE_MODULE_CALL]	= unlang_module_resume,
	[UNLANG_TYPE_SUBREQUEST]       	= unlang_subrequest_resume,
	[UNLANG_TYPE_PARALLEL]		= unlang_parallel_resume,
	[UNLANG_TYPE_MAX]		= NULL
};

/** Callback for handling resumption frames
 *
 * Resumption frames are added to track when a module, or other construct
 * has yielded control back to the interpreter.
 *
 * This function is called when the request has been marked as resumable
 * and a resumption frame was previously placed on the stack, i.e. when
 * the work that caused the request to be yielded initially has completed.
 *
 * @param[in] request	to be resumed.
 * @param[out] presult	the rcode returned by the resume function.
 * @param[out] priority associated with the rcode.
 */
static unlang_action_t unlang_resume(REQUEST *request,
				     rlm_rcode_t *presult, int *priority)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_resume_t			*mr = unlang_generic_to_resume(instruction);
	void 				*instance;

	RDEBUG3("Resuming in %s", mr->self.debug_name);

	if (!unlang_ops_resume[mr->parent_type]) {
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	memcpy(&instance, &mr->instance, sizeof(instance));
	request->module = mr->self.debug_name;

	/*
	 *	Run the resume callback associated with
	 *	the original frame which was used to
	 *	create this resumption frame.
	 */
	*presult = request->rcode = unlang_ops_resume[mr->parent_type](request, instance,
								       mr->thread, mr->resume_ctx);

	request->module = NULL;

	/*
	 *	Leave mr alone, it will be freed when the request is done.
	 */

	/*
	 *	Is now marked as "stop" when it wasn't before, we must have been blocked.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) {
		RWARN("Module %s became unblocked", mr->self.debug_name);
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	if (*presult != RLM_MODULE_YIELD) {
		rad_assert(*presult >= RLM_MODULE_REJECT);
		rad_assert(*presult < RLM_MODULE_NUMCODES);
		*priority = instruction->actions[*presult];
	}

	return *presult == RLM_MODULE_YIELD ? UNLANG_ACTION_YIELD : UNLANG_ACTION_CALCULATE_RESULT;
}

/*
 *	Some functions differ mainly in their parsing
 */
#define unlang_redundant_load_balance unlang_load_balance
#define unlang_policy unlang_group
#define unlang_break unlang_return

unlang_op_t unlang_ops[] = {
	[UNLANG_TYPE_MODULE_CALL] = {
		.name = "module-call",
		.func = unlang_module_call,
		.debug_braces = false
	},
	[UNLANG_TYPE_GROUP] = {
		.name = "group",
		.func = unlang_group,
		.debug_braces = true
	},
	[UNLANG_TYPE_LOAD_BALANCE] = {
		.name = "load-balance group",
		.func = unlang_load_balance,
		.debug_braces = true
	},
	[UNLANG_TYPE_REDUNDANT_LOAD_BALANCE] = {
		.name = "redundant-load-balance group",
		.func = unlang_redundant_load_balance,
		.debug_braces = true
	},
	[UNLANG_TYPE_PARALLEL] = {
		.name = "parallel",
		.func = unlang_parallel,
		.debug_braces = true
	},
#ifdef WITH_UNLANG
	[UNLANG_TYPE_IF] = {
		.name = "if",
		.func = unlang_if,
		.debug_braces = true
	},
	[UNLANG_TYPE_ELSE] = {
		.name = "else",
		.func = unlang_group,
		.debug_braces = true
	},
	[UNLANG_TYPE_ELSIF] = {
		.name = "elsif",
		.func = unlang_if,
		.debug_braces = true
	},
	[UNLANG_TYPE_UPDATE] = {
		.name = "update",
		.func = unlang_update,
		.debug_braces = true
	},
	[UNLANG_TYPE_SWITCH] = {
		.name = "switch",
		.func = unlang_switch,
		.debug_braces = true
	},
	[UNLANG_TYPE_CASE] = {
		.name = "case",
		.func = unlang_case,
		.debug_braces = true
	},
	[UNLANG_TYPE_FOREACH] = {
		.name = "foreach",
		.func = unlang_foreach,
		.debug_braces = true
	},
	[UNLANG_TYPE_BREAK] = {
		.name = "break",
		.func = unlang_break,
		.debug_braces = false
	},
	[UNLANG_TYPE_RETURN] = {
		.name = "return",
		.func = unlang_return,
		.debug_braces = false
	},
	[UNLANG_TYPE_MAP] = {
		.name = "map",
		.func = unlang_map,
		.debug_braces = true
	},
	[UNLANG_TYPE_POLICY] = {
		.name = "policy",
		.func = unlang_policy,
		.debug_braces = true
	},
	[UNLANG_TYPE_SUBREQUEST] = {
		.name = "subrequest",
		.func = unlang_subrequest,
		.debug_braces = true
	},
	[UNLANG_TYPE_DETACH] = {
		.name = "detach",
		.func = unlang_detach,
		.debug_braces = false
	},
	[UNLANG_TYPE_CALL] = {
		.name = "call",
		.func = unlang_call,
		.debug_braces = true
	},
#endif
	[UNLANG_TYPE_XLAT_INLINE] = {
		.name = "xlat_inline",
		.func = unlang_xlat_inline,
		.debug_braces = false
	},
	[UNLANG_TYPE_RESUME] = {
		.name = "resume",
		.func = unlang_resume,
		.debug_braces = false
	},
	[UNLANG_TYPE_MAX] = { NULL, NULL, false }
};

/** Update the current result after each instruction, and after popping each stack frame
 *
 * @param[in] request		The current request.
 * @param[in] frame		The curren stack frame.
 * @param[in,out] result	The current section result.
 * @param[in,out] priority	The current section priority.
 * @return
 *	- UNLANG_FRAME_ACTION_CONTINUE	evaluate more instructions.
 *	- UNLANG_FRAME_ACTION_POP	the final result has been calculated for this frame.
 */
static inline unlang_frame_action_t unlang_calculate_result(REQUEST *request, unlang_stack_frame_t *frame,
							    rlm_rcode_t *result, int *priority)
{
	unlang_t	*instruction = frame->instruction;
	unlang_stack_t	*stack = request->stack;

	RDEBUG4("** [%i] %s - have (%s %d) module returned (%s %d)",
		stack->depth, __FUNCTION__,
		fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
		frame->priority,
		fr_int2str(mod_rcode_table, *result, "<invalid>"),
		*priority);

	/*
	 *	Don't set action or priority if we don't have one.
	 */
	if (*result == RLM_MODULE_UNKNOWN) return UNLANG_FRAME_ACTION_CONTINUE;

	/*
	 *	The child's action says return.  Do so.
	 */
	if (instruction->actions[*result] == MOD_ACTION_RETURN) {
		if (*priority < 0) *priority = 0;

		RDEBUG4("** [%i] %s - action says to return with (%s %d)",
			stack->depth, __FUNCTION__,
			fr_int2str(mod_rcode_table, *result, "<invalid>"),
			*priority);
		frame->result = *result;
		frame->priority = *priority;
		return UNLANG_FRAME_ACTION_POP;
	}

	/*
	 *	If "reject", break out of the loop and return
	 *	reject.
	 */
	if (instruction->actions[*result] == MOD_ACTION_REJECT) {
		if (*priority < 0) *priority = 0;

		RDEBUG4("** [%i] %s - action says to return with (%s %d)",
			stack->depth, __FUNCTION__,
			fr_int2str(mod_rcode_table, RLM_MODULE_REJECT, "<invalid>"),
			*priority);
		frame->result = RLM_MODULE_REJECT;
		frame->priority = *priority;
		return UNLANG_FRAME_ACTION_POP;
	}

	/*
	 *	The array holds a default priority for this return
	 *	code.  Grab it in preference to any unset priority.
	 */
	if (*priority < 0) {
		*priority = instruction->actions[*result];

		RDEBUG4("** [%i] %s - setting priority to (%s %d)",
			stack->depth, __FUNCTION__,
			fr_int2str(mod_rcode_table, *result, "<invalid>"),
			*priority);
	}

	/*
	 *	We're higher than any previous priority, remember this
	 *	return code and priority.
	 */
	if (*priority > frame->priority) {
		frame->result = *result;
		frame->priority = *priority;

		RDEBUG4("** [%i] %s - over-riding result from higher priority to (%s %d)",
			stack->depth, __FUNCTION__,
			fr_int2str(mod_rcode_table, *result, "<invalid>"),
			*priority);
	}

	/*
	 *	If we've been told to stop processing
	 *	it, do so.
	 */
	if (frame->unwind != 0) {
		RDEBUG4("** [%i] %s - unwinding current frame with (%s %d)",
			stack->depth, __FUNCTION__,
			fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
			frame->priority);
		return UNLANG_FRAME_ACTION_POP;
	}

	return frame->next ? UNLANG_FRAME_ACTION_CONTINUE : UNLANG_FRAME_ACTION_POP;
}

/** Evaluates all the unlang nodes in a section
 *
 * @param[in] request		The current request.
 * @param[in] frame		The curren stack frame.
 * @param[in,out] result	The current section result.
 * @param[in,out] priority	The current section priority.
 * @return
 *	- UNLANG_FRAME_ACTION_CONTINUE	evaluate more instructions in the current stack frame
 *					which may not be the same frame as when this function
 *					was called.
 *	- UNLANG_FRAME_ACTION_POP	the final result has been calculated for this frame.
 */
static inline unlang_frame_action_t unlang_frame_eval(REQUEST *request, unlang_stack_frame_t *frame,
						      rlm_rcode_t *result, int *priority)
{
	unlang_stack_t	*stack = request->stack;

	/*
	 *	Loop over all the instructions in this list.
	 */
	while (frame->instruction) {
		REQUEST			*parent;
		unlang_t		*instruction = frame->instruction;
		unlang_action_t		action = UNLANG_ACTION_BREAK;

		DUMP_STACK;

		rad_assert(instruction->debug_name != NULL); /* if this happens, all bets are off. */

		REQUEST_VERIFY(request);

		/*
		 *	We may be multiple layers deep in create{} or
		 *	parallel{}.  Only the top-level request is
		 *	tracked && marked "stop processing".
		 */
		parent = request;
		while (parent->parent) parent = parent->parent;

		/*
		 *	We've been asked to stop.  Do so.
		 */
		if (parent->master_state == REQUEST_STOP_PROCESSING) {
		do_stop:
			frame->result = RLM_MODULE_FAIL;
			frame->priority = 9999;
			frame->unwind = UNLANG_TYPE_RETURN;
			break;
		}

		if (!frame->repeat && (unlang_ops[instruction->type].debug_braces)) {
			RDEBUG2("%s {", instruction->debug_name);
			RINDENT();
		}

		/*
		 *	Execute an operation
		 */
		RDEBUG4("** [%i] %s >> %s", stack->depth, __FUNCTION__,
			unlang_ops[instruction->type].name);

		action = unlang_ops[instruction->type].func(request, result, priority);

		RDEBUG4("** [%i] %s << %s (%d)", stack->depth, __FUNCTION__,
			fr_int2str(unlang_action_table, action, "<INVALID>"), *priority);

		rad_assert(*priority >= -1);
		rad_assert(*priority <= MOD_PRIORITY_MAX);

		switch (action) {
		/*
		 *	The request is now defunct, and we should not
		 *	continue processing it.
		 */
		case UNLANG_ACTION_STOP_PROCESSING:
			goto do_stop;

		/*
		 *	The operation resulted in additional frames
		 *	being pushed onto the stack, execution should
		 *	now continue at the deepest frame.
		 */
		case UNLANG_ACTION_PUSHED_CHILD:
			rad_assert(&stack->frame[stack->depth] > frame);
			*result = frame->result;
			return UNLANG_FRAME_ACTION_CONTINUE;

		/*
		 *	We're in a looping construct and need to stop
		 *	execution of the current section.
		 */
		case UNLANG_ACTION_BREAK:
			if (*priority < 0) *priority = 0;
			frame->result = *result;
			frame->priority = *priority;
			frame->next = NULL;
			return UNLANG_FRAME_ACTION_POP;

		/*
		 *	Yield control back to the scheduler, or whatever
		 *	called the interpreter.
		 */
		case UNLANG_ACTION_YIELD:
		yield:
			*result = RLM_MODULE_YIELD;	/* Fixup rcode */

			/*
			 *	Detach is magic.  The parent "create" function
			 *	takes care of bumping the instruction
			 *	pointer...
			 */
			switch (frame->instruction->type) {
			case UNLANG_TYPE_DETACH:
				RDEBUG4("** [%i] %s - detaching child with current (%s %d)",
					stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
					frame->priority);
				DUMP_STACK;

				return UNLANG_FRAME_ACTION_YIELD;

			case UNLANG_TYPE_RESUME:
				frame->repeat = true;
				RDEBUG4("** [%i] %s - yielding with current (%s %d)", stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
					frame->priority);
				DUMP_STACK;
				return UNLANG_FRAME_ACTION_YIELD;

			default:
				rad_assert(0);
				return UNLANG_FRAME_ACTION_YIELD;
			}
			break;	/* Static analysis tools are stupid */

		/*
		 *	Instruction finished execution,
		 *	check to see what we need to do next, and update
		 *	the section rcode and priority.
		 */
		case UNLANG_ACTION_CALCULATE_RESULT:
			/* Temporary fixup - ops should return the correct code */
			if (frame->result == RLM_MODULE_YIELD) goto yield;

			frame->repeat = false;

			if (unlang_ops[instruction->type].debug_braces) {
				REXDENT();
				RDEBUG2("} # %s (%s)", instruction->debug_name,
					fr_int2str(mod_rcode_table, *result, "<invalid>"));
			}

			if (unlang_calculate_result(request, frame, result, priority) == UNLANG_FRAME_ACTION_POP) {
				return UNLANG_FRAME_ACTION_POP;
			}
			/* FALL-THROUGH */

		/*
		 *	Execute the next instruction in this frame
		 */
		case UNLANG_ACTION_CONTINUE:
			if ((action == UNLANG_ACTION_CONTINUE) && unlang_ops[instruction->type].debug_braces) {
				REXDENT();
				RDEBUG2("}");
			}
			break;
		} /* switch over return code from the interpreter function */

		frame->instruction = frame->next;
		if (frame->instruction) frame->next = frame->instruction->next;
	}

	RDEBUG4("** [%i] %s - done current subsection with (%s %d)",
		stack->depth, __FUNCTION__,
		fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
		frame->priority);

	return UNLANG_FRAME_ACTION_POP;
}

/*
 *	Interpret the various types of blocks.
 */
static rlm_rcode_t unlang_run(REQUEST *request)
{
	int			priority;
	unlang_frame_action_t	fa = UNLANG_FRAME_ACTION_CONTINUE;

	/*
	 *	We don't have a return code yet.
	 */
	rlm_rcode_t		result = RLM_MODULE_UNKNOWN;
	unlang_stack_frame_t	*frame;

	unlang_stack_t		*stack = request->stack;

#ifndef NDEBUG
	if (DEBUG_ENABLED5) DEBUG("###### unlang_run is starting");
	DUMP_STACK;
#endif

	/*
	 *	If we're called from a module, re-set this so that the
	 *	indentation works correctly...
	 *
	 *	@todo - save / restore this across frames?
	 */
	request->module = NULL;
	rad_assert(request->runnable_id < 0);

	RDEBUG4("** [%i] %s - interpreter entered", stack->depth, __FUNCTION__);

	do {
		switch (fa) {
		case UNLANG_FRAME_ACTION_CONTINUE:	/* Evaluate the current frame */
			priority = -1;

			rad_assert(stack->depth > 0);
			rad_assert(stack->depth < UNLANG_STACK_MAX);

			frame = &stack->frame[stack->depth];
			fa = unlang_frame_eval(request, frame, &result, &priority);
			continue;

		case UNLANG_FRAME_ACTION_POP:		/* Pop this frame and check the one beneath it */
			/*
			 *	The result / priority is returned from
			 *	the sub-section, and made into our
			 *	current result / priority, as if we
			 *	had performed a module call.
			 */
			result = frame->result;
			priority = frame->priority;

			/*
			 *	Head on back up the stack
			 */
			unlang_pop(stack);
			frame = &stack->frame[stack->depth];
			DUMP_STACK;

			/*
			 *	Resume a "foreach" loop, or a "load-balance" section
			 *	or anything else that needs to be checked on the way
			 *	back on up the stack.
			 */
			if (frame->repeat) {
				fa = UNLANG_FRAME_ACTION_CONTINUE;
				continue;
			}

			/*
			 *	If we're done, merge the last result / priority in.
			 */
			if (frame->top_frame) break;	/* return */

			/*
			 *	Close out the section we entered earlier
			 */
			if (unlang_ops[frame->instruction->type].debug_braces) {
				REXDENT();
				RDEBUG2("} # %s (%s)", frame->instruction->debug_name,
					fr_int2str(mod_rcode_table, result, "<invalid>"));
			}

			fa = unlang_calculate_result(request, frame, &result, &priority);
			/*
			 *	If we're continuing after popping a frame
			 *	then we advance the instruction else we
			 *	end up executing the same code over and over...
			 */
			if (fa == UNLANG_FRAME_ACTION_CONTINUE) {
				RDEBUG4("** [%i] %s - continuing after subsection with (%s %d)",
					stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, result, "<invalid>"),
					priority);
				frame->instruction = frame->next;
				if (frame->instruction) frame->next = frame->instruction->next;
			/*
			 *	Else if we're really done with this frame
			 *	print some helpful debug...
			 */
			} else {
				RDEBUG4("** [%i] %s - done current subsection with (%s %d)",
					stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
					frame->priority);
			}
			continue;

		case UNLANG_FRAME_ACTION_YIELD:
			rad_assert(frame->result == RLM_MODULE_YIELD);
			return frame->result;
		}
		break;
	} while (!frame->top_frame);

	/*
	 *	Nothing in this section, use the top frame result.
	 */
	if ((priority < 0) || (result == RLM_MODULE_UNKNOWN)) {
		result = frame->result;
		priority = frame->priority;
	}

	if (priority > frame->priority) {
		frame->result = result;
		frame->priority = priority;

		RDEBUG4("** [%i] %s - over-riding result from higher priority to (%s %d)",
			stack->depth, __FUNCTION__,
			fr_int2str(mod_rcode_table, result, "<invalid>"),
			priority);
	}

	/*
	 *	We're at the top frame, return the result from the
	 *	stack, and get rid of the top frame.
	 */
	RDEBUG4("** [%i] %s - interpreter exiting, returning %s", stack->depth, __FUNCTION__,
		fr_int2str(mod_rcode_table, frame->result, "<invalid>"));
	result = frame->result;
	stack->depth--;
	DUMP_STACK;

	return result;
}

static unlang_group_t empty_group = {
	.self = {
		.type = UNLANG_TYPE_GROUP,
		.debug_name = "empty-group",
		.actions = { MOD_ACTION_RETURN, MOD_ACTION_RETURN, MOD_ACTION_RETURN, MOD_ACTION_RETURN,
			     MOD_ACTION_RETURN, MOD_ACTION_RETURN, MOD_ACTION_RETURN, MOD_ACTION_RETURN,
			     MOD_ACTION_RETURN
		},
	},
	.group_type = UNLANG_GROUP_TYPE_SIMPLE,
};

/** Push a configuration section onto the request stack for later interpretation.
 *
 */
void unlang_push_section(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t action)
{
	unlang_t	*instruction = NULL;
	unlang_stack_t	*stack = request->stack;

	/*
	 *	Interpretable unlang instructions are stored as CONF_DATA
	 *	associated with sections.
	 */
	if (cs) {
		instruction = (unlang_t *)cf_data_value(cf_data_find(cs, unlang_group_t, NULL));
		if (!instruction) {
			RPEDEBUG("Failed to find pre-compiled unlang for section %s %s { ... }",
				cf_section_name1(cs), cf_section_name2(cs));
		}
	}

	if (!instruction) instruction = unlang_group_to_generic(&empty_group);

	/*
	 *	Push the default action, and the instruction which has
	 *	no action.
	 */
	unlang_push(stack, NULL, action, UNLANG_NEXT_STOP, UNLANG_TOP_FRAME);
	if (instruction) unlang_push(stack, instruction, RLM_MODULE_UNKNOWN, UNLANG_NEXT_CONTINUE, UNLANG_SUB_FRAME);

	RDEBUG4("** [%i] %s - substack begins", stack->depth, __FUNCTION__);

	DUMP_STACK;
}

/** Continue interpreting after a previous push or yield.
 *
 */
rlm_rcode_t unlang_interpret_continue(REQUEST *request)
{
	return unlang_run(request);
}

/** Call a module, iteratively, with a local stack, rather than recursively
 *
 * What did Paul Graham say about Lisp...?
 */
rlm_rcode_t unlang_interpret(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t action)
{
	/*
	 *	This pushes a new frame onto the stack, which is the
	 *	start of a new unlang section...
	 */
	unlang_push_section(request, cs, action);

	return unlang_run(request);
}

/** Execute an unlang section synchronously
 *
 * Create a temporary event loop and swap it out for the one in the request.
 * Execute unlang operations until we receive a non-yield return code then return.
 *
 * @note The use cases for this are very limited.  If you need to use it, chances
 *	are what you're doing could be done better using one of the thread
 *	event loops.
 *
 * @param[in] request	The current request.
 * @param[in] cs	Section with compiled unlang associated with it.
 * @param[in] action	The default return code to use.
 * @return One of the RLM_MODULE_* macros.
 */
rlm_rcode_t unlang_interpret_synchronous(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t action)
{
	fr_event_list_t *el, *old;
	rlm_rcode_t	rcode;

	/*
	 *	Don't talloc from the request
	 *	as we'll almost certainly leave holes in the memory pool.
	 */
	MEM(el = fr_event_list_alloc(NULL, NULL, NULL));

	old = request->el;
	request->el = el;

	for (rcode = unlang_interpret(request, cs, action);
	     rcode == RLM_MODULE_YIELD;
	     rcode = unlang_interpret_continue(request)) {
		if (fr_event_corral(el, true) < 0) {
			RPERROR("Failed retrieving events");
			rcode = RLM_MODULE_FAIL;
			break;
		}

		fr_event_service(el);
	}

	talloc_free(request->el);
	request->el = old;

	return rcode;
}

/** Wrap an #fr_event_timer_t providing data needed for unlang events
 *
 */
typedef struct unlang_event_t {
	REQUEST				*request;			//!< Request this event pertains to.
	int				fd;				//!< File descriptor to wait on.
	fr_unlang_timeout_callback_t	timeout;			//!< Function to call on timeout.
	fr_unlang_fd_callback_t		fd_read;			//!< Function to call when FD is readable.
	fr_unlang_fd_callback_t		fd_write;			//!< Function to call when FD is writable.
	fr_unlang_fd_callback_t		fd_error;			//!< Function to call when FD has errored.
	void const			*inst;				//!< Module instance to pass to callbacks.
	void				*thread;			//!< Thread specific module instance.
	void const			*ctx;				//!< ctx data to pass to callbacks.
	fr_event_timer_t const		*ev;				//!< Event in this worker's event heap.
} unlang_event_t;

/** Frees an unlang event, removing it from the request's event loop
 *
 * @param[in] ev	The event to free.
 *
 * @return 0
 */
static int _unlang_event_free(unlang_event_t *ev)
{
	if (ev->ev) {
		(void) fr_event_timer_delete(ev->request->el, &(ev->ev));
		return 0;
	}

	if (ev->fd >= 0) {
		(void) fr_event_fd_delete(ev->request->el, ev->fd, FR_EVENT_FILTER_IO);
	}

	return 0;
}

/** Call the callback registered for a timeout event
 *
 * @param[in] el	the event timer was inserted into.
 * @param[in] now	The current time, as held by the event_list.
 * @param[in] ctx	unlang_event_t structure holding callbacks.
 *
 */
static void unlang_event_timeout_handler(UNUSED fr_event_list_t *el, struct timeval *now, void *ctx)
{
	unlang_event_t *ev = talloc_get_type_abort(ctx, unlang_event_t);
	void *mutable_ctx;
	void *mutable_inst;

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->timeout(ev->request, mutable_inst, ev->thread, mutable_ctx, now);
	talloc_free(ev);
}

/** Call the callback registered for a read I/O event
 *
 * @param[in] el	containing the event (not passed to the callback).
 * @param[in] fd	the I/O event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] ctx	unlang_event_t structure holding callbacks.
 */
static void unlang_event_fd_read_handler(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *ctx)
{
	unlang_event_t *ev = talloc_get_type_abort(ctx, unlang_event_t);
	void *mutable_ctx;
	void *mutable_inst;

	rad_assert(ev->fd == fd);

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->fd_read(ev->request, mutable_inst, ev->thread, mutable_ctx, fd);
}

/** Call the callback registered for a write I/O event
 *
 * @param[in] el	containing the event (not passed to the callback).
 * @param[in] fd	the I/O event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] ctx	unlang_event_t structure holding callbacks.
 */
static void unlang_event_fd_write_handler(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *ctx)
{
	unlang_event_t *ev = talloc_get_type_abort(ctx, unlang_event_t);
	void *mutable_ctx;
	void *mutable_inst;

	rad_assert(ev->fd == fd);

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->fd_write(ev->request, mutable_inst, ev->thread, mutable_ctx, fd);
}

/** Call the callback registered for an I/O error event
 *
 * @param[in] el	containing the event (not passed to the callback).
 * @param[in] fd	the I/O event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] fd_errno	from kevent.
 * @param[in] ctx	unlang_event_t structure holding callbacks.
 */
static void unlang_event_fd_error_handler(UNUSED fr_event_list_t *el, int fd,
					  UNUSED int flags, UNUSED int fd_errno, void *ctx)
{
	unlang_event_t *ev = talloc_get_type_abort(ctx, unlang_event_t);
	void *mutable_ctx;
	void *mutable_inst;

	rad_assert(ev->fd == fd);

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->fd_error(ev->request, mutable_inst, ev->thread, mutable_ctx, fd);
}

/** Set a timeout for the request.
 *
 * Used when a module needs wait for an event.  Typically the callback is set, and then the
 * module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_resumable().
 *
 * param[in] request		the current request.
 * param[in] callback		to call.
 * param[in] ctx		for the callback.
 * param[in] timeout		when to call the timeout (i.e. now + timeout).
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_event_timeout_add(REQUEST *request, fr_unlang_timeout_callback_t callback,
			     void const *ctx, struct timeval *when)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_event_t			*ev;
	unlang_module_call_t		*sp;
	unlang_stack_state_modcall_t	*modcall_state = talloc_get_type_abort(frame->state,
									       unlang_stack_state_modcall_t);

	rad_assert(stack->depth > 0);
	rad_assert((frame->instruction->type == UNLANG_TYPE_MODULE_CALL) ||
		   (frame->instruction->type == UNLANG_TYPE_RESUME));
	sp = unlang_generic_to_module_call(frame->instruction);

	ev = talloc_zero(request, unlang_event_t);
	if (!ev) return -1;

	ev->request = request;
	ev->fd = -1;
	ev->timeout = callback;
	ev->inst = sp->module_instance->dl_inst->data;
	ev->thread = modcall_state->thread;
	ev->ctx = ctx;

	if (fr_event_timer_insert(request, request->el, &ev->ev,
				  when, unlang_event_timeout_handler, ev) < 0) {
		RPEDEBUG("Failed inserting event");
		talloc_free(ev);
		return -1;
	}

	(void) request_data_add(request, ctx, -1, ev, true, false, false);

	talloc_set_destructor(ev, _unlang_event_free);

	return 0;
}

/** Delete a previously set timeout callback
 *
 * param[in] request the request
 * param[in] ctx a local context for the callback
 */
int unlang_event_timeout_delete(REQUEST *request, void const *ctx)
{
	unlang_event_t *ev;

	ev = request_data_get(request, ctx, -1);
	if (!ev) return -1;

	talloc_free(ev);
	return 0;
}

/** Set a callback for the request.
 *
 * Used when a module needs to read from an FD.  Typically the callback is set, and then the
 * module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_resumable().
 *
 * @param[in] request		The current request.
 * @param[in] read		callback.  Used for receiving and demuxing/decoding data.
 * @param[in] write		callback.  Used for writing and encoding data.
 *				Where a 3rd party library is used, this should be the function
 *				issuing queries, and writing data to the socket.  This should
 *				not be done in the module itself.
 *				This allows write operations to be retried in some instances,
 *				and means if the write buffer is full, the request is kept in
 *				a suspended state.
 * @param[in] error		callback.  If the fd enters an error state.  Should cleanup any
 *				handles wrapping the file descriptor, and any outstanding requests.
 * @param[in] ctx		for the callback.
 * @param[in] fd		to watch.
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_event_fd_add(REQUEST *request,
			fr_unlang_fd_callback_t read,
			fr_unlang_fd_callback_t write,
			fr_unlang_fd_callback_t error,
			void const *ctx, int fd)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_event_t			*ev;
	unlang_module_call_t		*sp;
	unlang_stack_state_modcall_t	*modcall_state = talloc_get_type_abort(frame->state,
									       unlang_stack_state_modcall_t);

	rad_assert(stack->depth > 0);

	rad_assert((frame->instruction->type == UNLANG_TYPE_MODULE_CALL) ||
		   (frame->instruction->type == UNLANG_TYPE_RESUME));
	sp = unlang_generic_to_module_call(frame->instruction);

	ev = talloc_zero(request, unlang_event_t);
	if (!ev) return -1;

	ev->request = request;
	ev->fd = fd;
	ev->fd_read = read;
	ev->fd_write = write;
	ev->fd_error = error;
	ev->inst = sp->module_instance->dl_inst->data;
	ev->thread = modcall_state->thread;
	ev->ctx = ctx;

	/*
	 *	Register for events on the file descriptor
	 */
	if (fr_event_fd_insert(request, request->el, fd,
			       ev->fd_read ? unlang_event_fd_read_handler : NULL,
			       ev->fd_write ? unlang_event_fd_write_handler : NULL,
			       ev->fd_error ? unlang_event_fd_error_handler: NULL,
			       ev) < 0) {
		talloc_free(ev);
		return -1;
	}

	(void) request_data_add(request, ctx, fd, ev, true, false, false);
	talloc_set_destructor(ev, _unlang_event_free);

	return 0;
}

/** Delete a previously set file descriptor callback
 *
 * param[in] request the request
 * param[in] fd the file descriptor
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_event_fd_delete(REQUEST *request, void const *ctx, int fd)
{
	unlang_event_t *ev;

	ev = request_data_get(request, ctx, fd);
	if (!ev) return -1;

	talloc_free(ev);
	return 0;
}


/** Mark a request as resumable.
 *
 * It's not called "unlang_resume", because it doesn't actually
 * resume the request, it just schedules it for resumption.
 *
 * @note that this schedules the request for resumption.  It does not immediately
 *	start running the request.
 *
 * @param[in] request		The current request.
 */
void unlang_resumable(REQUEST *request)
{
	REQUEST				*parent = request->parent;
	unlang_stack_t			*stack;
	unlang_stack_frame_t		*frame;

	while (parent) {
		int i;
		unlang_resume_t		*mr;
		unlang_parallel_t	*state;
#ifndef NDEBUG
		bool			found = false;
#endif

		/*
		 *	Child requests CANNOT be runnable.  Only the
		 *	parent request can be runnable.  When it runs
		 *	(eventually), the interpreter will walk back
		 *	down the stack, resuming anything that needs resuming.
		 */
		rad_assert(request->backlog == NULL);
		rad_assert(request->runnable_id < 0);

#ifndef NDEBUG
		/*
		 *	Look at the current stack.
		 */
		stack = request->stack;
		frame = &stack->frame[stack->depth];

		/*
		 *	The current request MUST have been yielded in
		 *	order for someone to mark it resumable.
		 */
		rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);
#endif

		/*
		 *	Now look at the parents stack.  It also must
		 *	have been yielded in order for someone to mark
		 *	the child as resumable.
		 */
		stack = parent->stack;
		frame = &stack->frame[stack->depth];
		rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

		mr = unlang_generic_to_resume(frame->instruction);
		(void) talloc_get_type_abort(mr, unlang_resume_t);

		if (mr->parent_type != UNLANG_TYPE_PARALLEL) goto next;

		state = mr->resume_ctx;

		/*
		 *	Find the child and mark it resumable
		 */
		for (i = 0; i < state->num_children; i++) {
			if (state->children[i].state != CHILD_YIELDED) continue;
			if (state->children[i].child != request) continue;

			state->children[i].state = CHILD_RUNNABLE;
#ifndef NDEBUG
			found = true;
#endif
			break;
		}

		/*
		 *	We MUST have found the child here.
		 */
		rad_assert(found == true);

	next:
		request = parent;
		parent = parent->parent;
	}


#ifndef NDEBUG
	/*
	 *	The current request MUST have been yielded in
	 *	order for someone to mark it resumable.
	 */
	stack = request->stack;
	frame = &stack->frame[stack->depth];
	rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);
#endif

	rad_assert(request->backlog != NULL);

	/*
	 *	Multiple child request may mark a request runnable,
	 *	before it is enabled for running.
	 */
	if (request->runnable_id < 0) fr_heap_insert(request->backlog, request);
}

/** Send a signal (usually stop) to a request
 *
 * This is typically called via an "async" action, i.e. an action
 * outside of the normal processing of the request.
 *
 * If there is no #fr_unlang_action_t callback defined, the action is ignored.
 *
 * @param[in] request		The current request.
 * @param[in] action		to signal.
 */
void unlang_signal(REQUEST *request, fr_state_action_t action)
{
	unlang_stack_frame_t		*frame;
	unlang_stack_t			*stack = request->stack;
	unlang_resume_t			*mr;
	void				*instance;

	rad_assert(stack->depth > 0);

	frame = &stack->frame[stack->depth];

	/*
	 *	Be gracious in errors.
	 */
	if (frame->instruction->type != UNLANG_TYPE_RESUME) {
		return;
	}

	mr = unlang_generic_to_resume(frame->instruction);
	if (!mr->signal_callback) return;

	memcpy(&instance, &mr->instance, sizeof(instance));

	mr->signal_callback(request, instance, mr->thread, mr->resume_ctx, action);
}

/** Yield a request back to the interpreter from within a module
 *
 * This passes control of the request back to the unlang interpreter, setting
 * callbacks to execute when the request is 'signalled' asynchronously, or whatever
 * timer or I/O event the module was waiting for occurs.
 *
 * @note The module function which calls #unlang_module_yield should return control
 *	of the C stack to the unlang interpreter immediately after calling #unlang_module_yield.
 *	A common pattern is to use ``return unlang_module_yield(...)``.
 *
 * @param[in] request		The current request.
 * @param[in] callback		to call on unlang_resumable().
 * @param[in] signal_callback	to call on unlang_action().
 * @param[in] ctx		to pass to the callbacks.
 * @return always returns RLM_MODULE_YIELD.
 */
rlm_rcode_t unlang_module_yield(REQUEST *request, fr_unlang_resume_callback_t callback,
				fr_unlang_action_t signal_callback, void *ctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_resume_t			*mr;
	unlang_stack_state_modcall_t	*modcall_state = talloc_get_type_abort(frame->state,
									       unlang_stack_state_modcall_t);

	rad_assert(stack->depth > 0);

	rad_assert((frame->instruction->type == UNLANG_TYPE_MODULE_CALL) ||
		   (frame->instruction->type == UNLANG_TYPE_RESUME));

	if (frame->instruction->type == UNLANG_TYPE_MODULE_CALL) {
		unlang_module_call_t		*sp;

		/*
		 *	Do this BEFORE allocating mr, which replaces
		 *	frame->instruction.
		 */
		sp = unlang_generic_to_module_call(frame->instruction);

		mr = unlang_resume_alloc(request, callback, signal_callback, ctx);
		rad_assert(mr != NULL);

		/*
		 *	Remember module-specific data.
		 */
		mr->module_instance = sp->module_instance;
		mr->instance = sp->module_instance->dl_inst->data;
		mr->thread = modcall_state->thread->data;

	} else {
		mr = talloc_get_type_abort(frame->instruction, unlang_resume_t);
		rad_assert(mr->parent_type == UNLANG_TYPE_MODULE_CALL);

		/*
		 *	Can't change threads...
		 */
		rad_assert(mr->thread == modcall_state->thread->data);

		/*
		 *	Re-use the current RESUME frame, but over-ride
		 *	the callbacks and context.
		 */
		mr->callback = callback;
		mr->signal_callback = signal_callback;
		mr->resume_ctx = ctx;
	}

	return RLM_MODULE_YIELD;
}

/** Get information about the interpreter state
 *
 */
static ssize_t xlat_interpreter(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			   UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
			   REQUEST *request, char const *fmt)
{
	unlang_stack_t		*stack = request->stack;
	int			depth = stack->depth;
	unlang_stack_frame_t	*frame;
	unlang_t		*instruction;

	while (isspace((int) *fmt)) fmt++;

	/*
	 *	Find the correct stack frame.
	 */
	while (*fmt == '.') {
		if (depth <= 1) {
			return snprintf(*out, outlen, "<underflow>");
		}

		fmt++;
		depth--;
	}

	/*
	 *	Get the current instruction.
	 */
	frame = &stack->frame[depth];
	instruction = frame->instruction;

	/*
	 *	Nothing there...
	 */
	if (!instruction) {
		**out = '\0';
		return 0;
	}

	/*
	 *	Name of the instruction.
	 */
	if (strcmp(fmt, "name") == 0) {
		return snprintf(*out, outlen, "%s", instruction->name);
	}

	/*
	 *	Unlang type.
	 */
	if (strcmp(fmt, "type") == 0) {
		return snprintf(*out, outlen, "%s", unlang_ops[instruction->type].name);
	}

	/*
	 *	How deep the current stack is.
	 */
	if (strcmp(fmt, "depth") == 0) {
		return snprintf(*out, outlen, "%d", depth);
	}

	/*
	 *	Line number of the current section.
	 */
	if (strcmp(fmt, "line") == 0) {
		unlang_group_t *g;

		if (!unlang_ops[instruction->type].debug_braces) {
			return snprintf(*out, outlen, "???");
		}

		g = unlang_generic_to_group(instruction);
		rad_assert(g->cs != NULL);

		return snprintf(*out, outlen, "%d", cf_lineno(g->cs));
	}

	/*
	 *	Filename of the current section.
	 */
	if (strcmp(fmt, "filename") == 0) {
		unlang_group_t *g;

		if (!unlang_ops[instruction->type].debug_braces) {
			return snprintf(*out, outlen, "???");
		}

		g = unlang_generic_to_group(instruction);
		rad_assert(g->cs != NULL);

		return snprintf(*out, outlen, "%s", cf_filename(g->cs));
	}

	**out = '\0';
	return 0;
}


/** Initialize the unlang compiler / interpreter.
 *
 *  For now, just register the magic xlat function.
 */
int unlang_initialize(void)
{
	(void) xlat_register(NULL, "interpreter", xlat_interpreter, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, true);

	return 0;
}
