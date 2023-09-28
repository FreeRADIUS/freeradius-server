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
 * @file unlang/group.c
 * @brief Unlang "group" keyword evaluation.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "unlang_priv.h"
#include "group_priv.h"

unlang_action_t unlang_group(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	return unlang_interpret_push_children(p_result, request, frame->result, UNLANG_NEXT_SIBLING);
}

static unlang_action_t unlang_policy(rlm_rcode_t *result, request_t *request, unlang_stack_frame_t *frame)
{
	/*
	 *	Ensure returns stop at the enclosing policy
	 */
	return_point_set(frame);

	return unlang_group(result, request, frame);
}


void unlang_group_init(void)
{
	unlang_register(UNLANG_TYPE_GROUP,
			   &(unlang_op_t){
				.name = "group",
				.interpret = unlang_group,
				.debug_braces = true
			   });

	unlang_register(UNLANG_TYPE_REDUNDANT,
			   &(unlang_op_t){
				.name = "redundant",
				.interpret = unlang_group,
				.debug_braces = true
			   });

	unlang_register(UNLANG_TYPE_POLICY,
			   &(unlang_op_t){
				.name = "policy",
				.interpret = unlang_policy,
				.debug_braces = true
			   });
}
