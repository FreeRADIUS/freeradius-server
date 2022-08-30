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
#include <freeradius-devel/server/pair.h>

#include "call_priv.h"
#include "module_priv.h"

static unlang_action_t unlang_call_finalize(UNUSED rlm_rcode_t *p_result, request_t *request,
					    unlang_stack_frame_t *frame)
{
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	unlang_call_t			*gext = unlang_group_to_call(g);
	fr_pair_t			*packet_type_vp = NULL;

	switch (pair_update_reply(&packet_type_vp, gext->attr_packet_type)) {
	case 0:
		packet_type_vp->vp_uint32 = request->reply->code;
		break;

	case 1:
		break;	/* Don't change */
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_call_children(rlm_rcode_t *p_result, request_t *request,
					    unlang_stack_frame_t *frame)
{
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);

	fr_assert(g->children);

	/*
	 *      Push the contents of the call { } section onto the stack.
	 *      This gets executed after the server returns.
	 */
	if (unlang_interpret_push(request, g->children, frame->result,
				  UNLANG_NEXT_SIBLING, UNLANG_SUB_FRAME) < 0) {
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	frame_repeat(frame, unlang_call_finalize);
	return UNLANG_ACTION_PUSHED_CHILD;
}


static unlang_action_t unlang_call_frame_init(rlm_rcode_t *p_result, request_t *request,
					      unlang_stack_frame_t *frame)
{
	unlang_group_t			*g;
	unlang_call_t			*gext;
	fr_dict_enum_value_t const		*type_enum;
	fr_pair_t			*packet_type_vp = NULL;

	/*
	 *	Do not check for children here.
	 *
	 *	Call shouldn't require children to execute as there
	 *	can still be side effects from executing the virtual
	 *	server.
	 */
	g = unlang_generic_to_group(frame->instruction);
	gext = unlang_group_to_call(g);

	/*
	 *	Work out the current request type.
	 */
	type_enum = fr_dict_enum_by_value(gext->attr_packet_type, fr_box_uint32(request->packet->code));
	if (!type_enum) {
		packet_type_vp = fr_pair_find_by_da(&request->request_pairs, NULL, gext->attr_packet_type);
		if (!packet_type_vp) {
		bad_packet_type:
			REDEBUG("No such value '%d' of attribute 'Packet-Type' for server %s",
				request->packet->code, cf_section_name2(gext->server_cs));
		error:
			*p_result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
		type_enum = fr_dict_enum_by_value(packet_type_vp->da, &packet_type_vp->data);
		if (!type_enum) goto bad_packet_type;

		/*
		 *	Sync up packet->code
		 */
		request->packet->code = packet_type_vp->vp_uint32;
	}

	/*
	 *	Sync up packet codes and attributes
	 *
	 *	Fixme - packet->code needs to die...
	 */
	if (!packet_type_vp) switch (pair_update_request(&packet_type_vp, gext->attr_packet_type)) {
	case 0:
		packet_type_vp->vp_uint32 = request->packet->code;
		break;

	case 1:
		request->packet->code = packet_type_vp->vp_uint32;
		break;

	default:
		goto error;
	}

	/*
	 *	Need to add reply.Packet-Type if it
	 *	wasn't set by the virtual server...
	 *
	 *	AGAIN packet->code NEEDS TO DIE.
	 *	DIE DIE DIE DIE DIE DIE DIE DIE DIE
	 *	DIE DIE DIE DIE DIE DIE DIE DIE DIE.
	 */
	if (!g->children) {
		frame_repeat(frame, unlang_call_finalize);
	} else {
		frame_repeat(frame, unlang_call_children);
	}

	if (virtual_server_push(request, gext->server_cs, UNLANG_SUB_FRAME) < 0) goto error;

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Push a call frame onto the stack
 *
 * This should be used instead of virtual_server_push in the majority of the code
 */
unlang_action_t unlang_call_push(request_t *request, CONF_SECTION *server_cs, bool top_frame)
{
	unlang_stack_t			*stack = request->stack;
	unlang_call_t			*c;
	char const			*name;
	fr_dict_t const			*dict;
	fr_dict_attr_t const		*attr_packet_type;

	/*
	 *	Temporary hack until packet->code is removed
	 */
	dict = virtual_server_dict_by_cs(server_cs);
	if (!dict) {
		REDEBUG("Virtual server \"%s\" not compiled", cf_section_name2(server_cs));
		return UNLANG_ACTION_FAIL;
	}

	attr_packet_type = fr_dict_attr_by_name(NULL, fr_dict_root(dict), "Packet-Type");
	if (!attr_packet_type) {
		REDEBUG("No Packet-Type attribute available");
		return UNLANG_ACTION_FAIL;
	}

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
				.ci = CF_TO_ITEM(server_cs),
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
						[RLM_MODULE_UPDATED]	= 0
					},
					.retry = RETRY_INIT,
				},
			},

			.cs = server_cs,
		},
		.server_cs = server_cs,
		.attr_packet_type = attr_packet_type
	};

	/*
	 *	Push a new call frame onto the stack
	 */
	if (unlang_interpret_push(request, unlang_call_to_generic(c),
				  RLM_MODULE_NOT_SET, UNLANG_NEXT_STOP, top_frame) < 0) {
		talloc_free(c);
		return UNLANG_ACTION_FAIL;
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Return the last virtual server that was called
 *
 * @param[in] request	To return virtual server for.
 * @return
 *	- A virtual server CONF_SECTION on success.
 *	- NULL on failure.
 */
CONF_SECTION *unlang_call_current(request_t *request)
{
	unlang_stack_t	*stack = request->stack;
	unsigned int	depth;

	/*
	 *	Work back from the deepest frame
	 *	looking for modules.
	 */
	for (depth = stack_depth_current(request); depth > 0; depth--) {
		unlang_stack_frame_t	*frame = &stack->frame[depth];

		/*
		 *	Look at the module frames,
		 *	trying to find one that represents
		 *	a process state machine.
		 */
		if (frame->instruction->type != UNLANG_TYPE_CALL) continue;

		return unlang_group_to_call(unlang_generic_to_group(frame->instruction))->server_cs;
	}
	return NULL;
}

void unlang_call_init(void)
{
	unlang_register(UNLANG_TYPE_CALL,
			   &(unlang_op_t){
				.name			= "call",
				.interpret		= unlang_call_frame_init,
				.debug_braces		= true,
			   });
}

