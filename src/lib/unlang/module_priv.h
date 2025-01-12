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
 * @file unlang/module_priv.h
 * @brief Declarations for the unlang module interface
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
#include "unlang_priv.h"

#ifdef __cplusplus
extern "C" {
#endif

/** A call to a module method
 *
 */
typedef struct {
	unlang_t			self;			//!< Common fields in all #unlang_t tree nodes.
	call_env_t const		*call_env;		//!< The per call parsed call environment.
	module_method_call_t		mmc;			//!< Everything needed to call a module method.
} unlang_module_t;

/** A module stack entry
 *
 * Represents a single module call on the unlang stack.
 */
typedef struct {
	char const			*previous_module;	//!< old request->module
	module_thread_instance_t	*thread;		//!< thread-local data for this module.
								///< Caching is necessary in the frame state
								///< structure because the #unlang_t tree is
								///< shared between all threads, so we can't
								///< cache thread-specific data in the #unlang_t.
	call_env_result_t		env_result;		//!< Result of the previous call environment expansion.
	void				*env_data;		//!< Expanded per call "call environment" tmpls.

#ifndef NDEBUG
	int				unlang_indent;		//!< Record what this was when we entered the module.
#endif

	/** @name rcode output
	 * @{
 	 */
	rlm_rcode_t			*p_result;		//!< Where to store the result.
	rlm_rcode_t			rcode;			//!< the result, only for unlang_module_resume_final.
	bool				rcode_set;		//!< Overwrite the current rcode for the section with
								///< the module rcode.
	/** @} */

	/** @name Resumption and signalling
	 * @{
 	 */
	void				*rctx;			//!< for resume / signal
	module_method_t			resume;			//!< resumption handler
	unlang_module_signal_t		signal;			//!< for signal handlers
	fr_signal_t			sigmask;		//!< Signals to block.

	/** @} */

	/** @name Retry handlers.
	 * @{
	 */
	module_method_t			retry_resume;  		//!< which stops retries on resume
	unlang_module_retry_t       	retry_cb;		//!< callback to run on timeout
	void				*timeout_rctx;		//!< rctx data to pass to timeout callback
	module_instance_t const		*mi;			//!< Module instance to pass to callbacks.
	request_t			*request;

	fr_event_timer_t const		*ev;			//!< retry timer just for this module.
	fr_retry_t			retry;			//!< retry timers, etc.

	/** @} */

} unlang_frame_state_module_t;

static inline unlang_module_t *unlang_generic_to_module(unlang_t const *p)
{
	fr_assert(p->type == UNLANG_TYPE_MODULE);
	return UNCONST(unlang_module_t *, talloc_get_type_abort_const(p, unlang_module_t));
}

static inline unlang_t *unlang_module_to_generic(unlang_module_t *p)
{
	return (unlang_t *)p;
}

#ifdef __cplusplus
}
#endif
