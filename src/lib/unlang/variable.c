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
 * @file unlang/variable.c
 * @brief Unlang local "variable"s
 *
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include "group_priv.h"
#include "variable_priv.h"

static unlang_action_t unlang_variable(UNUSED rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_variable_t		*var;

	var = unlang_generic_to_variable(frame->instruction);

	RDEBUG3("Creating varible max %d", var->max_attr);

	return UNLANG_ACTION_CALCULATE_RESULT;
}


void unlang_variable_init(void)
{
	unlang_register(UNLANG_TYPE_VARIABLE,
			   &(unlang_op_t){
				.name = "variable",
				.interpret = unlang_variable,
			   });
}
