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
 * @file unlang/tmpl.h
 *
 * @brief Functions to allow tmpls to push resumption frames onto the stack
 *	  and inform the interpreter about the conditions they need to be
 *	  resumed under (usually an I/O event or timer event).
 *
 * @copyright 2016-2019 The FreeRADIUS server project
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/unlang/tmpl.h>

/** Flags that show the type of arguments included
 *
 */
typedef enum {
	UNLANG_TMPL_ARGS_TYPE_EXEC = 1,				//!< We have arguments for performing an exec.
} unlang_tmpl_args_type_t;

/** Arguments for evaluating different types of tmpls
 *
 */
typedef struct {
	unlang_tmpl_args_type_t		type;			//!< Flags field showing which argument structs
								///< were explicitly populated.  Can help with
								///< setting defaults.

	/** Exec specific arguments
	 *
	 */
	struct {
		fr_pair_list_t		*env;			//!< Environmental variables.
		int			*status_out;		//!< Where to write the exit code or fatal signal
								///< that killed the process.
		fr_time_delta_t		timeout;		//!< How long to wait for the process to finish.
		bool			stdout_on_error;	//!< If true don't clear stdout if we get a non-zero
								///< status code.  This allows more nuanced
								///< interpretation of status codes.
	} exec;
} unlang_tmpl_args_t;

/** Create a temporary argument structure for evaluating an exec type tmpl
 *
 * @param[in] _env			Environmental variables specified as a pair list.
 * @param[in] _timeout			How long to wait for program to complete.
 * @param[in] _stdout_on_error		If true we keep stdout even on non-zero status code.
 * @param[out] _status_out		Where to store the exit code of the program.
 *					- Will be positive if it's an exit code.
 *					- Will be negative if it's a fatal signal.
 */
#define TMPL_ARGS_EXEC(_env, _timeout, _stdout_on_error, _status_out) \
	&(unlang_tmpl_args_t){ \
		.type = UNLANG_TMPL_ARGS_TYPE_EXEC, \
		.exec = { \
			.env = _env, \
			.timeout = _timeout, \
			.stdout_on_error = _stdout_on_error, \
			.status_out = _status_out \
		}, \
	}

/** A callback when the request gets a fr_state_signal_t.
 *
 * A module may call unlang_yeild(), but still need to do something on FR_SIGNAL_DUP.  If so, it's
 * set here.
 *
 * @note The callback is automatically removed on unlang_interpret_mark_runnable().
 *
 * @param[in] rctx		Resume ctx for the callback.
 * @param[in] request		The current request.
 * @param[in] action		which is signalling the request.
 */
typedef void (*fr_unlang_tmpl_signal_t)(request_t *request, void *rctx, fr_state_signal_t action);

/** A callback for when the request is resumed.
 *
 * The resumed request cannot call the normal "authorize", etc. method.  It needs a separate callback.
 *
 * @param[in] request		the current request.
 * @param[in] rctx		a local context for the callback.
 * @return an unlang action.
 */
typedef unlang_action_t (*fr_unlang_tmpl_resume_t)(rlm_rcode_t *p_result, request_t *request, void *rctx);

int		unlang_tmpl_push(TALLOC_CTX *ctx, fr_value_box_list_t *out,
				 request_t *request, tmpl_t const *tmpl, unlang_tmpl_args_t *args)
		CC_HINT(warn_unused_result);

#ifdef __cplusplus
}
#endif
