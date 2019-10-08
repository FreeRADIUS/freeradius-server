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

#include <freeradius-devel/server/state.h>
#include "unlang_priv.h"
#include "subrequest_priv.h"

/** Parameters for initialising the subrequest
 *
 * State of one level of nesting within an xlat expansion.
 */
typedef struct {
	rlm_rcode_t			*presult;			//!< Where to store the result.
	REQUEST				*child;				//!< Pre-allocated child request.
	bool				free_child;			//!< Whether we should free the child after
									///< it completes.
	bool				detachable;			//!< Whether the request can be detached.
	unlang_subrequest_session_t		session;			//!< Session configuration.
} unlang_frame_state_subrequest_t;

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

typedef struct {
	rlm_rcode_t	rcode;		//!< frame->result from before detach was called
} unlang_frame_state_detach_t;

static void unlang_max_request_time(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	REQUEST *request = talloc_get_type_abort(uctx, REQUEST);

	RDEBUG("Reached Request-Lifetime.  Forcibly stopping request");

	/*
	 *	The request is scheduled and isn't running.  Remove it
	 *	from the backlog.
	 */
	if (is_scheduled(request)) {
		rad_assert(request->backlog != NULL);
		(void) fr_heap_extract(request->backlog, request);
	}

	talloc_free(request);
}

/** Send a signal from parent request to subrequest
 *
 */
static void unlang_subrequest_signal(REQUEST *request, fr_state_signal_t action)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_subrequest_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_subrequest_t);
	REQUEST				*child = talloc_get_type_abort(state->child, REQUEST);

	unlang_interpret_signal(child, action);
}


/** Process a subrequest until it either detaches, or is done.
 *
 */
static unlang_action_t unlang_subrequest_process(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_subrequest_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_subrequest_t);
	REQUEST				*child = talloc_get_type_abort(state->child, REQUEST);
	rlm_rcode_t			rcode;

	rad_assert(child != NULL);

	rcode = unlang_interpret(child);
	if (rcode != RLM_MODULE_YIELD) {
		if (!fr_cond_assert(rcode < NUM_ELEMENTS(frame->instruction->actions))) return UNLANG_ACTION_STOP_PROCESSING;

		if (state->session.enable) fr_state_store_in_parent(child,
								    state->session.unique_ptr,
								    state->session.unique_int);

		if (state->free_child) {
			unlang_subrequest_free(&child);
			state->child = NULL;
			frame->signal = NULL;
		}

	calculate_result:
		/*
		 *	Pass the result back to the module
		 *	that created the subrequest, or
		 *	use it to modify the current section
		 *	rcode.
		 */
		if (state->presult) *state->presult = rcode;

		*presult = rcode;

		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	The child has yielded, BUT has also detached itself.
	 *	We know this because it has reached into our state,
	 *	and removed itself as a child.  We therefore just keep
	 *	running, and don't return yield.
	 */
	if (!state->child) {
		rcode = RLM_MODULE_NOOP;
		goto calculate_result;
	}

	/*
	 *	Else the child yielded, so we have to yield.  Set up
	 *	the resume frame and continue.
	 */
	return UNLANG_ACTION_YIELD;
}


static unlang_action_t unlang_subrequest_start(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_subrequest_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_subrequest_t);
	REQUEST				*child = state->child;

	/*
	 *	Restore state from the parent to the
	 *	subrequest.
	 */
	if (state->session.enable) fr_state_restore_to_child(child,
							     state->session.unique_ptr,
							     state->session.unique_int);

	RDEBUG2("Creating subrequest (%s)", child->name);
	log_request_pair_list(L_DBG_LVL_1, request, child->packet->vps, NULL);

	frame->interpret = unlang_subrequest_process;
	return unlang_subrequest_process(request, presult);
}


static unlang_action_t unlang_subrequest_state_init(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_frame_state_subrequest_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_subrequest_t);
	REQUEST				*child;

	rlm_rcode_t			rcode;
	VALUE_PAIR			*vp;
	unlang_group_t			*g;

	/*
	 *	Initialize the state
	 */
	g = unlang_generic_to_group(instruction);
	rad_assert(g->children != NULL);

	child = state->child = unlang_io_subrequest_alloc(request, g->dict, UNLANG_DETACHABLE);
	if (!child) {
		rcode = RLM_MODULE_FAIL;

		/*
		 *	Pass the result back to the module
		 *	that created the subrequest, or
		 *	use it to modify the current section
		 *	rcode.
		 */
		if (state->presult) *state->presult = rcode;

		*presult = rcode;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Set the packet type.
	 *
	 *	@todo - this doesn't strictly work for DHCP, which
	 *	uses DHCP-Message-Type, *and* which has message type
	 *	by a uint8.  We should likely have some other mapping
	 *	in the dictionary so that we can find the real
	 *	attribute.
	 */
	MEM(vp = fr_pair_afrom_da(child->packet, g->attr_packet_type));
	child->packet->code = vp->vp_uint32 = g->type_enum->value->vb_uint32;
	fr_pair_add(&child->packet->vps, vp);

	/*
	 *	Push the first instruction the child's
	 *	going to run.
	 */
	unlang_interpret_push(child, g->children, frame->result,
			      UNLANG_NEXT_SIBLING, UNLANG_TOP_FRAME);

	/*
	 *	Probably not a great idea to set state->presult to
	 *	presult, as it could be a pointer to an rlm_rcode_t
	 *	somewhere on the stack which could be invalidated
	 *	between unlang_subrequest being called and
	 *	unlang_subrequest_resume being called.
	 *
	 *	...so we just set it to NULL and interpret
	 *	that as use the presult that was passed
	 *	in to the currently executing function.
	 */
	state->presult = NULL;
	state->free_child = true;
	state->detachable = true;

	/*
	 *	Store/restore session information in the subrequest
	 *	keyed off the exact subrequest keyword.
	 */
	state->session.enable = true;
	state->session.unique_ptr = instruction;
	state->session.unique_int = 0;

	frame->interpret = unlang_subrequest_start;
	return unlang_subrequest_start(request, presult);
}

/** Initialize a detached child
 *
 *  Detach it from the parent, set up it's lifetime, and mark it as
 *  runnable.
 */
int unlang_detached_child_init(REQUEST *request)
{
	VALUE_PAIR		*vp;

	if (request_detach(request, false) < 0) {
		ERROR("Failed detaching child");
		return -1;
	}

	/*
	 *	Set Request Lifetime
	 */
	vp = fr_pair_find_by_da(request->control, attr_request_lifetime, TAG_ANY);
	if (!vp || (vp->vp_uint32 > 0)) {
		fr_time_delta_t when = 0;
		const fr_event_timer_t **ev_p;

		if (!vp) {
			when += fr_time_delta_from_sec(30); /* default to 30s if not set */

		} else if (vp->vp_uint32 > 3600) {
			RWDEBUG("Request-Timeout can be no more than 3600 seconds");
			when += fr_time_delta_from_sec(3600);

		} else if (vp->vp_uint32 < 5) {
			RWDEBUG("Request-Timeout can be no less than 5 seconds");
			when += fr_time_delta_from_sec(5);

		} else {
			when += fr_time_delta_from_sec(vp->vp_uint32);
		}

		ev_p = talloc_size(request, sizeof(*ev_p));
		memset(ev_p, 0, sizeof(*ev_p));

		(void) fr_event_timer_in(request, request->el, ev_p, when, unlang_max_request_time, request);
	}

	/*
	 *	Mark the child as runnable.
	 */
	rad_assert(request->parent == NULL);
	if (fr_heap_insert(request->backlog, request) < 0) {
		RPERROR("Failed inserting ourself into the backlog.");
		return -1;
	}

	return 0;
}

static unlang_action_t unlang_detach(REQUEST *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_detach_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_detach_t);

	unlang_frame_state_subrequest_t	*parent_state;

	/*
	 *	We've detached, yielded, and now are continuing
	 *	processing.  There's nothing more to do, so just
	 *	continue.
	 */
	if (!request->parent) {
		*presult = state->rcode;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	First time through, detach from the parent.
	 */
	RDEBUG2("detach");

	rad_assert(request->parent != NULL);

	/*
	 *	Get the PARENT's stack.
	 */
	stack = request->parent->stack;
	frame = &stack->frame[stack->depth];
	parent_state = talloc_get_type_abort(frame->state, unlang_frame_state_subrequest_t);

	if (!parent_state->detachable) {
		RWDEBUG("Ignoring 'detach' as the request is not detachable");
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	If we can't detach the child OR we can't insert it
	 *	into the backlog, stop processing it.
	 */
	if (unlang_detached_child_init(request) < 0) {
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	/*
	 *	The parent frame no longer has a child, and therefore
	 *	can't be signaled.
	 */
	rad_assert(parent_state->child == request);
	parent_state->child = NULL;
	frame->signal = NULL;

	/*
	 *	Pass through whatever the previous instruction had as
	 *	the result.
	 */
	state->rcode = *presult;

	/*
	 *	Yield to the parent, who will discover that there's no
	 *	child, and return.
	 */
	return UNLANG_ACTION_YIELD;
}

/** Free a child request, detaching it from its parent and freeing allocated memory
 *
 * @param[in] child to free.
 */
void unlang_subrequest_free(REQUEST **child)
{
	request_detach(*child, true);
	talloc_free(*child);
	*child = NULL;
}

static unlang_t subrequest_instruction = {
	.type = UNLANG_TYPE_SUBREQUEST,
	.name = "subrequest",
	.debug_name = "subrequest",
	.actions = {
		[RLM_MODULE_REJECT]	= 0,
		[RLM_MODULE_FAIL]	= MOD_ACTION_RETURN,	/* Exit out of nested levels */
		[RLM_MODULE_OK]		= 0,
		[RLM_MODULE_HANDLED]	= 0,
		[RLM_MODULE_INVALID]	= 0,
		[RLM_MODULE_DISALLOW]	= 0,
		[RLM_MODULE_NOTFOUND]	= 0,
		[RLM_MODULE_NOOP]	= 0,
		[RLM_MODULE_UPDATED]	= 0
	},
};

/** Push a pre-existing child back onto the stack as a subrequest
 *
 * The child *MUST* have been allocated with unlang_io_subrequest_alloc, or something
 * that calls it.
 * Instruction *MUST* belong to the same virtual server as is set in the child.
 *
 * After the child is no longer required it *MUST* be freed with #unlang_subrequest_free.
 * It's not enough to free it with talloc_free.
 *
 * @param[in] out		Where to write the result of the subrequest.
 * @param[in] child		to push.
 * @param[in] top_frame		Set to UNLANG_TOP_FRAME if the interpreter should return.
 *				Set to UNLANG_SUB_FRAME if the interprer should continue.
 */
void unlang_subrequest_push(rlm_rcode_t *out, REQUEST *child,
			    unlang_subrequest_session_t const *session, bool top_frame)
{
	unlang_stack_t			*stack = child->parent->stack;
	unlang_stack_frame_t		*frame;
	unlang_frame_state_subrequest_t	*state;

	/*
	 *	Push a new subrequest frame onto the stack
	 */
	unlang_interpret_push(child->parent, &subrequest_instruction, RLM_MODULE_UNKNOWN, UNLANG_NEXT_STOP, top_frame);
	frame = &stack->frame[stack->depth];

	/*
	 *	Allocate a state for the subrequest
	 *	This lets us override the normal request
	 *      the subrequest instruction would alloc.
	 */
	state = talloc_get_type_abort(frame->state, unlang_frame_state_subrequest_t);
	state->presult = out;
	state->child = child;
	state->free_child = false;
	state->detachable = false;
	if (session) state->session = *session;

	frame->interpret = unlang_subrequest_start;
}

int unlang_subrequest_op_init(void)
{
	if (fr_dict_autoload(subrequest_dict) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}
	if (fr_dict_attr_autoload(subrequest_dict_attr) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}

	unlang_register(UNLANG_TYPE_SUBREQUEST,
			   &(unlang_op_t){
				.name = "subrequest",
				.interpret = unlang_subrequest_state_init,
				.signal = unlang_subrequest_signal,
				.debug_braces = true,
				.frame_state_size = sizeof(unlang_frame_state_subrequest_t),
				.frame_state_name = "unlang_frame_state_subrequest_t",
			   });

	unlang_register(UNLANG_TYPE_DETACH,
			   &(unlang_op_t){
				.name = "detach",
				.interpret = unlang_detach,
				.frame_state_size = sizeof(unlang_frame_state_detach_t),
				.frame_state_name = "unlang_frame_state_detach_t",
			   });

	return 0;
}

void unlang_subrequest_op_free(void)
{
	fr_dict_autofree(subrequest_dict);
}
