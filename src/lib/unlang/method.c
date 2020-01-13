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
 * @file unlang/method.c
 * @brief Unlang call module_method_t

 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */
RCSID("$Id$")

#include "unlang_priv.h"
#include "method.h"

typedef struct unlang_method_t {
	void		*instance;
	module_method_t	method;
} unlang_method_t;

/*
 *	Note that the caller gives us NULL for priority.
 */
static unlang_action_t unlang_method_call(REQUEST *request, rlm_rcode_t *presult, UNUSED int *priority, void *uctx)
{
	unlang_method_t *process = talloc_get_type_abort(uctx, unlang_method_t);

	*presult = process->method(process->instance, NULL, request);
	if (*presult == RLM_MODULE_YIELD) {
		return UNLANG_ACTION_YIELD;
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Push a top-level processing section onto the stack.
 *
 *  This function is similar to unlang_module_push(), so it is located here.
 *
 * @param[in] request		The current request.
 * @param[in] instance		Instance of the processing section.
 * @param[in] method		to call.
 */
void unlang_interpret_push_method(REQUEST *request, void *instance, module_method_t method)
{
	unlang_method_t *process;
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;

	MEM(process = talloc_zero(request, unlang_method_t));
	process->instance = instance;
	process->method = method;

	unlang_interpret_push_function(request, unlang_method_call, unlang_method_call, process);

	/*
	 *	The push_function API has no way to set the top frame.
	 *	But this frame IS the top frame.
	 */
	frame = &stack->frame[stack->depth];
	top_frame_set(frame);
}
