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
 * @file unlang/detach.c
 * @brief Unlang detach keyword
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include "unlang_priv.h"

/** Signal a child to detach
 *
 */
static unlang_action_t unlang_detach(rlm_rcode_t *p_result, request_t *request, UNUSED unlang_stack_frame_t *frame)
{
	/*
	 *	Signal all frames in the child's stack
	 *	that it's time to detach.
	 */
	unlang_interpret_signal(request, FR_SIGNAL_DETACH);

	/*
	 *	Detach failed...
	 */
	if (unlikely(request->parent != NULL)) {
		*p_result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Initialise subrequest ops
 *
 */
void unlang_detach_init(void)
{
	unlang_register(UNLANG_TYPE_DETACH,
			&(unlang_op_t){
				.name = "detach",
				.interpret = unlang_detach,
			});
}
