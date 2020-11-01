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
 * @file unlang/call.c
 * @brief Unlang "call" keyword evaluation.  Used for calling virtual servers.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/server/state.h>

#include "call.h"
#include "call_priv.h"
#include "unlang_priv.h"

static unlang_action_t unlang_call_process(request_t *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_call_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_call_t);
	unlang_t			*instruction = frame->instruction;
	unlang_group_t			*g = unlang_generic_to_group(instruction);

	rlm_rcode_t			rcode;

	request->request_state = REQUEST_INIT;
	request->server_cs = state->prev_server_cs;	/* So we get correct debug info */

	/*
	 *	Call the process function
	 *
	 *	This is a function in the virtual server's state machine.
	 */
	rcode = state->process(&(module_ctx_t){ .instance = state->instance }, request);
	if (rcode == RLM_MODULE_YIELD) return UNLANG_ACTION_YIELD;

	/*
	 *	Record the rcode and restore the previous virtual server
	 */
	*presult = rcode;
	request->request_state = state->prev_request_state;
	request->server_cs = state->prev_server_cs;

	/*
	 *	Push the contents of the call { } section onto the stack.
	 *	This gets executed after the server returns.
	 */
	if (g->children) {
		unlang_interpret_push(request, g->children, frame->result,
				      UNLANG_NEXT_SIBLING, UNLANG_SUB_FRAME);
		return UNLANG_ACTION_PUSHED_CHILD;
	};

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_call_frame_init(request_t *request, rlm_rcode_t *presult)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_call_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_call_t);
	unlang_t			*instruction = frame->instruction;

	unlang_group_t			*g;
	unlang_call_t			*gext;
	char const			*server;
	fr_dict_enum_t const		*type_enum;

	module_method_t			process_p;
	void				*process_inst;

	/*
	 *	Do not check for children here.
	 *
	 *	Call shouldn't require children to execute as there
	 *	can still be side effects from executing the virtual
	 *	server.
	 */
	g = unlang_generic_to_group(instruction);
	gext = unlang_group_to_call(g);
	server = cf_section_name2(gext->server_cs);

	/*
	 *	Push OUR subsection onto the childs stack frame.
	 */

	/*
	 *	Work out the current request type.
	 */
	type_enum = fr_dict_enum_by_value(gext->attr_packet_type, fr_box_uint32(request->packet->code));
	if (!type_enum) {
		REDEBUG("No such value '%d' of attribute 'Packet-Type' for server %s", request->packet->code, server);
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	...and get the processing function
	 *	which matches that type in the target
	 *	virtual server.
	 */
	if (virtual_server_get_process_by_name(gext->server_cs, type_enum->name, &process_p, &process_inst) < 0) {
		REDEBUG("Cannot call virtual server '%s' - %s", server, fr_strerror());
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	*state = (unlang_frame_state_call_t){
		.instance = process_inst,
		.process = process_p,
		.prev_request_state = request->request_state,
		.prev_server_cs = request->server_cs,
	};

	return unlang_call_process(request, presult);
}

/** Push a call to a virtual server onto the stack for evaluation
 *
 * This does the same work as #unlang_call_frame_init.
 *
 * @param[in] request		The current request.
 * @param[in] server_cs		of the virtual server to run.
 * @param[in] instance		of the state machine.
 * @param[in] entry_point	Where to start in the virtual server state machine.
 * @param[in] top_frame		Set to UNLANG_TOP_FRAME if the interpreter should return.
 *				Set to UNLANG_SUB_FRAME if the interprer should continue.
 */
void unlang_call_push(request_t *request, CONF_SECTION *server_cs,
		      void *instance, module_method_t entry_point, bool top_frame)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;
	unlang_frame_state_call_t	*state;
	unlang_call_t			*c;
	char const			*name;

	/*
	 *	We need to have a unlang_module_t to push on the
	 *	stack.  The only sane way to do it is to attach it to
	 *	the frame state.
	 */
	name = cf_section_name2(server_cs);
	MEM(c = talloc(stack, unlang_call_t));	/* Free at the same time as the state */
	*c = (unlang_call_t){
		.group = {
			.self = {
				.type = UNLANG_TYPE_CALL,
				.name = name,
				.debug_name = name,
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
				}
			}
		}
	};

	/*
	 *	Push a new call frame onto the stack
	 */
	unlang_interpret_push(request, unlang_call_to_generic(c), RLM_MODULE_UNKNOWN, UNLANG_NEXT_STOP, top_frame);

	/*
	 *	And setup the frame.  The memory was
	 *	pre-allocated for us by the interpreter.
	 */
	frame = &stack->frame[stack->depth];
	state = talloc_get_type_abort(frame->state, unlang_frame_state_call_t);
	*state = (unlang_frame_state_call_t){
		.instance = instance,
		.process = entry_point,		/* This mutates */
		.prev_request_state = request->request_state,
		.prev_server_cs = request->server_cs
	};
	frame->process = unlang_call_process;	/* Skip the initialisation */
	talloc_steal(frame, c);			/* Bind our temporary unlang_call_t to the frame */
}


void unlang_call_init(void)
{
	unlang_register(UNLANG_TYPE_CALL,
			   &(unlang_op_t){
				.name			= "call",
				.interpret		= unlang_call_frame_init,
				.debug_braces		= true,
				.frame_state_size	= sizeof(unlang_frame_state_call_t),
				.frame_state_name	= "unlang_frame_state_call_t"
			   });
}

