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
static unlang_action_t unlang_detach(unlang_result_t *p_result, request_t *request, UNUSED unlang_stack_frame_t *frame)
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
		RETURN_UNLANG_FAIL;
	}

	p_result->rcode = RLM_MODULE_NOT_SET;
	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_t *unlang_compile_detach(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	unlang_t *subrequest;

	for (subrequest = parent;
	     subrequest != NULL;
	     subrequest = subrequest->parent) {
		if (subrequest->type == UNLANG_TYPE_SUBREQUEST) break;
	}

	if (!subrequest) {
		cf_log_err(ci, "'detach' can only be used inside of a 'subrequest' section.");
		cf_log_err(ci, DOC_KEYWORD_REF(detach));
		return NULL;
	}

	/*
	 *	This really overloads the functionality of
	 *	cf_item_next().
	 */
	if ((parent == subrequest) && !cf_item_next(ci, ci)) {
		cf_log_err(ci, "'detach' cannot be used as the last entry in a section, as there is nothing more to do");
		return NULL;
	}

	return unlang_compile_empty(parent, unlang_ctx, NULL, UNLANG_TYPE_DETACH);
}

/** Initialise subrequest ops
 *
 */
void unlang_detach_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "detach",
			.type = UNLANG_TYPE_DETACH,
			.flag = UNLANG_OP_FLAG_SINGLE_WORD,

			.compile = unlang_compile_detach,
			.interpret = unlang_detach,

			.unlang_size = sizeof(unlang_group_t),
			.unlang_name = "unlang_group_t",	
		});
}
