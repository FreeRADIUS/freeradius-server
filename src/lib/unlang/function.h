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
 * @file unlang/function.h
 * @brief Declarations for generic unlang functions.
 *
 * @copyright 2021 The FreeRADIUS server project
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/signal.h>

/** A generic function pushed by a module or xlat to functions deeper in the C call stack to create resumption points
 *
 * @param[in] request		The current request.
 * @param[in,out] uctx		Provided by whatever pushed the function.  Is opaque to the
 *				interpreter, but should be usable by the function.
 *				All input (args) and output will be done using this structure.
 * @return an #unlang_action_t.
 */
typedef unlang_action_t (*unlang_function_t)(rlm_rcode_t *p_result, int *priority, request_t *request, void *uctx);

/** Function to call if the request was signalled
 *
 * @param[in] request		The current request.
 * @param[in] action		We're being signalled with.
 * @param[in,out] uctx		Provided by whatever pushed the function.  Is opaque to the
 *				interpreter, but should be usable by the function.
 *				All input (args) and output will be done using this structure.
 */
typedef void (*unlang_function_signal_t)(request_t *request, fr_state_signal_t action, void *uctx);

int		unlang_interpret_push_function(request_t *request,
					       unlang_function_t func, unlang_function_t repeat,
					       unlang_function_signal_t signal, void *uctx)
					       CC_HINT(warn_unused_result);

#ifdef __cplusplus
}
#endif
