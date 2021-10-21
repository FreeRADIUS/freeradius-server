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
 * These are a useful alternative to module methods for library code.
 * They're more light weight, and don't require instance data lookups
 * to function.
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

int		unlang_function_clear(request_t *request) CC_HINT(warn_unused_result);

/** Set a new signal function for an existing function frame
 *
 * The function frame being modified must be at the top of the stack.
 *
 * @param[in] request		The current request.
 * @param[in] signal		The signal function to set.
 * @param[in] signal_name	Name of the signal function call (for debugging).
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
#define		unlang_function_signal_set(_request, _signal) \
		_unlang_function_signal_set(_request, _signal, STRINGIFY(_signal))
int		_unlang_function_signal_set(request_t *request, unlang_function_signal_t signal, char const *name)
		CC_HINT(warn_unused_result);

/** Set a new repeat function for an existing function frame
 *
 * The function frame being modified must be at the top of the stack.
 *
 * @param[in] _request		The current request.
 * @param[in] _repeat		the repeat function to set.
 * @return
 *	- 0 on success.
 *      - -1 on failure.
 */
#define		unlang_function_repeat_set(_request, _repeat) \
		_unlang_function_repeat_set(_request, _repeat, STRINGIFY(_repeat))
int		_unlang_function_repeat_set(request_t *request, unlang_function_t repeat, char const *name)
		CC_HINT(warn_unused_result);

/** Push a generic function onto the unlang stack
 *
 * These can be pushed by any other type of unlang op to allow a submodule or function
 * deeper in the C call stack to establish a new resumption point.
 *
 * @param[in] _request		The current request.
 * @param[in] _func		to call going up the stack.
 * @param[in] _repeat		function to call going back down the stack (may be NULL).
 *				This may be the same as func.
 * @param[in] _signal		function to call if the request is signalled.
 * @param[in] _uctx		to pass to func(s).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#define		unlang_function_push(_request, _func, _repeat, _signal, _top_frame, _uctx) \
		_unlang_function_push(_request, \
				      _func, STRINGIFY(_func), \
				      _repeat, STRINGIFY(_repeat), \
				      _signal, STRINGIFY(_signal), \
				      _top_frame, _uctx)
unlang_action_t	_unlang_function_push(request_t *request,
				      unlang_function_t func, char const *func_name,
				      unlang_function_t repeat, char const *repeat_name,
				      unlang_function_signal_t signal, char const *signal_name,
				      bool top_frame, void *uctx)
				      CC_HINT(warn_unused_result);

#ifdef __cplusplus
}
#endif
