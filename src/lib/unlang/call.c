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

#include "unlang_priv.h"
#include "subrequest_priv.h"

/** Send a signal from parent request to subrequest in another virtual server
 *
 */
static void unlang_call_signal(UNUSED REQUEST *request, void *ctx, fr_state_signal_t action)
{
	REQUEST			*child = talloc_get_type_abort(ctx, REQUEST);

	unlang_interpret_signal(child, action);
}


/** Resume a subrequest in another virtual server.
 *
 */
static unlang_action_t unlang_call_resume(REQUEST *request, rlm_rcode_t *presult, void *rctx)
{
	REQUEST				*child = talloc_get_type_abort(rctx, REQUEST);
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction->parent;
	rlm_rcode_t			rcode;
#ifndef NDEBUG
	unlang_resume_t			*mr;
#endif

	/*
	 *	Continue running the child.
	 */
	rcode = unlang_interpret_run(child);
	if (rcode == RLM_MODULE_YIELD) {
#ifndef NDEBUG
		rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

		mr = unlang_generic_to_resume(frame->instruction);
		(void) talloc_get_type_abort(mr, unlang_resume_t);

		rad_assert(mr->resume == NULL);
#endif

		/*
		 *	If the child yields, our current frame is still an
		 *	unlang_resume_t.
		 */
		return UNLANG_ACTION_YIELD;
	}

	stack = child->stack;
	if (stack->depth > 0) {
		rcode = unlang_interpret_run(child);
		if (rcode == RLM_MODULE_YIELD) {
			return UNLANG_ACTION_YIELD;
		}
	}

	rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

	*presult = rcode;

	frame->instruction->type = UNLANG_TYPE_SUBREQUEST; /* for debug purposes */

	fr_state_store_in_parent(child, instruction, 0);
	unlang_subrequest_free(&child);

	*presult = rcode;
	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_call(REQUEST *request,
				   rlm_rcode_t *presult, int *ppriority)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	REQUEST				*child;

	rlm_rcode_t			rcode;
	int				priority;
	unlang_resume_t			*mr;

	unlang_group_t			*g;

	char const			*server;
	fr_dict_t const			*dict;
	fr_dict_attr_t const		*attr_packet_type;
	fr_dict_enum_t const		*type_enum;

	fr_io_process_t			*process_p;
	void				*process_inst;
	rlm_rcode_t			final;

	g = unlang_generic_to_group(instruction);
	rad_assert(g->children != NULL);

	server = cf_section_name2(g->server_cs);

	/*
	 *	Check for loops.  We do this by checking the source of
	 *	the call statement.  If any parent is doing the same
	 *	call as we are, then it's a loop.
	 */
	for (child = request->parent;
	     child != NULL;
	     child = child->parent) {
		unlang_stack_t		*child_stack = child->stack;
		unlang_stack_frame_t	*child_frame = &child_stack->frame[child_stack->depth];
		unlang_t		*child_instruction = child_frame->instruction;

		if (child_instruction == instruction) {
			REDEBUG("Suppressing 'call' loop with server %s",
				server);
			*presult = RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

	/*
	 *	Get the server, then the dictionary, then the packet
	 *	type, then the name of the packet type, and then
	 *	process function for that named packet.
	 */
	dict = virtual_server_namespace(server);
	if (!dict) {
		REDEBUG("No 'namespace' in server %s", server);
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	if (dict != request->dict) {
		REDEBUG("Request namespace does not match virtual server %s namespace",
			server);
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	attr_packet_type = fr_dict_attr_by_name(dict, "Packet-Type");
	if (!attr_packet_type) {
		REDEBUG("No such attribute 'Packet-Type' for server %s", server);
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	type_enum = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->packet->code));
	if (!type_enum) {
		REDEBUG("No such value '%d' of attribute 'Packet-Type' for server %s", request->packet->code, server);
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	process_p = (fr_io_process_t *) cf_data_value(cf_data_find(g->server_cs, fr_io_process_t, type_enum->alias));
	if (!process_p) {
		REDEBUG("No such packet type '%s' in server '%s'",
			type_enum->alias, cf_section_name2(g->server_cs));
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	We MUST use _cd_data_find() so that we don't try to
	 *	find the "value" with talloc type "CF_IDENT_ANY".
	 */
	process_inst = cf_data_value(_cf_data_find(cf_section_to_item(g->server_cs), CF_IDENT_ANY, type_enum->alias));
	/* can be NULL */

	child = unlang_io_subrequest_alloc(request, dict, UNLANG_NORMAL_CHILD);
	if (!child) {
		rcode = RLM_MODULE_FAIL;
		priority = instruction->actions[*presult];

	calculate_result:
		*presult = rcode;
		*ppriority = priority;

		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Tell the child how to run.
	 */
	child->server_cs = g->server_cs;
	child->async->process = *process_p;
	child->async->process_inst = process_inst;

	/*
	 *	Expected by the process functions
	 */
	child->log.unlang_indent = 0;

	/*
	 *	Note that we do NOT copy the Session-State list!  That
	 *	contains state information for the parent.
	 */
	if ((fr_pair_list_copy(child->packet,
			       &child->packet->vps,
			       request->packet->vps) < 0) ||
	    (fr_pair_list_copy(child->reply,
			       &child->reply->vps,
			       request->reply->vps) < 0) ||
	    (fr_pair_list_copy(child,
			       &child->control,
			       request->control) < 0)) {
		REDEBUG("failed copying lists to child");
		*presult = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Restore state from the parent to the
	 *	subrequest.
	 *	This is necessary for stateful modules like
	 *	EAP to work.
	 */
	fr_state_restore_to_child(child, instruction, 0);

	/*
	 *	Push OUR subsection onto the childs stack frame.
	 */
	unlang_interpret_push(child, g->children, frame->result,
			      UNLANG_NEXT_SIBLING, UNLANG_TOP_FRAME);

	/*
	 *	@todo - we can't change packet types
	 *	(e.g. Access-Request -> Accounting-Request) unless
	 *	we're in a subrequest.
	 */
	final = child->async->process(child->async->process_inst, child);
	if (final == RLM_MODULE_YIELD) {
	yield:
		/*
		 *	Create the "resume" stack frame, and have it replace our stack frame.
		 */
		mr = unlang_interpret_resume_alloc(request, NULL, NULL, child);
		if (!mr) {
			rcode = RLM_MODULE_FAIL;
			priority = instruction->actions[rcode];
			goto calculate_result;
		}

		*presult = RLM_MODULE_YIELD;
		return UNLANG_ACTION_YIELD;
	}

	/*
	 *	Run the *child* through the "call" section, as a way
	 *	to get post-processing of the packet.
	 */
	rcode = unlang_interpret_run(child);
	if (rcode == RLM_MODULE_YIELD) goto yield;

	*presult = frame->result = rcode;
	fr_state_store_in_parent(child, instruction, 0);
	unlang_subrequest_free(&child);

	return UNLANG_ACTION_CALCULATE_RESULT;
}



void unlang_call_init(void)
{
	unlang_register(UNLANG_TYPE_CALL,
			   &(unlang_op_t){
				.name = "call",
				.func = unlang_call,
				.signal = unlang_call_signal,
				.resume = unlang_call_resume,
				.debug_braces = true
			   });
}

