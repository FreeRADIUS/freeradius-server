#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/**
 * $Id$
 *
 * @file unlang/interpret.h
 * @brief Declarations for the unlang interpreter.
 *
 * @copyright 2019 The FreeRADIUS server project
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/unlang/action.h>

#define UNLANG_TOP_FRAME (true)
#define UNLANG_SUB_FRAME (false)

#define UNLANG_STACK_MAX (64)		//!< The maximum depth of the stack.
#define UNLANG_FRAME_PRE_ALLOC (128)	//!< How much memory we pre-alloc for each frame.

/** Return whether a request is currently scheduled
 *
 */
static inline bool unlang_request_is_scheduled(request_t const *request)
{
	return (request->runnable_id >= 0);
}

int		unlang_interpret_push_section(request_t *request, CONF_SECTION *cs,
					      rlm_rcode_t default_action, bool top_frame)
					      CC_HINT(warn_unused_result);

int		unlang_interpret_push_instruction(request_t *request, void *instruction,
						  rlm_rcode_t default_rcode, bool top_frame)
						  CC_HINT(warn_unused_result);

rlm_rcode_t	unlang_interpret(request_t *request);

rlm_rcode_t	unlang_interpret_section(request_t *request, CONF_SECTION *cs, rlm_rcode_t default_action);

rlm_rcode_t	unlang_interpret_synchronous(request_t *request, CONF_SECTION *cs, rlm_rcode_t action, bool child_el);

void		*unlang_interpret_stack_alloc(TALLOC_CTX *ctx);

void		unlang_interpret_mark_runnable(request_t *request);

bool		unlang_interpret_is_resumable(request_t *request);

void		unlang_interpret_signal(request_t *request, fr_state_signal_t action);

int		unlang_interpret_stack_depth(request_t *request);

rlm_rcode_t	unlang_interpret_stack_result(request_t *request);

TALLOC_CTX	*unlang_interpret_frame_talloc_ctx(request_t *request);

void 		unlang_interpret_init_global(void);
#ifdef __cplusplus
}
#endif
