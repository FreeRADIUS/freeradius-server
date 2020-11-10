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
	module_instance_t		*instance;		//!< Global instance of the module we're calling.
	module_method_t			method;			//!< The entry point into the module.
} unlang_module_t;

/** A module stack entry
 *
 * Represents a single module call on the unlang stack.
 */
typedef struct {
	module_thread_instance_t	*thread;		//!< thread-local data for this module.
								///< Caching is necessary in the frame state
								///< structure because the #unlang_t tree is
								///< shared between all threads, so we can't
								///< cache thread-specific data in the #unlang_t.

	/** @name rcode output
	 * @{
 	 */
	rlm_rcode_t			*p_result;		//!< Where to store the result.
	rlm_rcode_t			rcode;			//!< the result, only for unlang_module_resume_final.
	/** @} */

	/** @name Resumption and signalling
	 * @{
 	 */
	void				*rctx;			//!< for resume / signal
	unlang_module_resume_t		resume;			//!< resumption handler
	unlang_module_signal_t		signal;			//!< for signal handlers
	/** @} */
} unlang_frame_state_module_t;

static inline unlang_module_t *unlang_generic_to_module(unlang_t *p)
{
	fr_assert(p->type == UNLANG_TYPE_MODULE);
	return talloc_get_type_abort(p, unlang_module_t);
}

static inline unlang_t *unlang_module_to_generic(unlang_module_t *p)
{
	return (unlang_t *)p;
}

#ifdef __cplusplus
}
#endif
