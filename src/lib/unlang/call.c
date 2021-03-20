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
#include "unlang_priv.h"

static unlang_action_t unlang_call_frame_init(rlm_rcode_t *p_result, request_t *request,
					      unlang_stack_frame_t *frame)
{
	unlang_group_t			*g;
	unlang_call_t			*gext;
	fr_dict_enum_t const		*type_enum;
	fr_pair_t			*packet_type_vp;

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
	 *	Push OUR subsection onto the childs stack frame.
	 */

	/*
	 *	Work out the current request type.
	 */
	type_enum = fr_dict_enum_by_value(gext->attr_packet_type, fr_box_uint32(request->packet->code));
	if (!type_enum) {
		REDEBUG("No such value '%d' of attribute 'Packet-Type' for server %s",
			request->packet->code, cf_section_name2(gext->server_cs));
	error:
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Sync up packet codes and attributes
	 *
	 *	Fixme - packet->code needs to die...
	 */
	switch (pair_update_control(&packet_type_vp, gext->attr_packet_type)) {
	case 0:
		packet_type_vp->vp_uint32 = request->packet->code;
		break;

	case 1:
		request->packet->code = packet_type_vp->vp_uint32;
		break;

	default:
		goto error;
	}

	if (virtual_server_push(request, gext->server_cs, UNLANG_SUB_FRAME) < 0) goto error;

	return UNLANG_ACTION_PUSHED_CHILD;
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

