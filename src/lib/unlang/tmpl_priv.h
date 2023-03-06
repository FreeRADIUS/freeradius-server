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
 * @file unlang/tmpl_priv.h
 * @brief Declarations for the unlang tmpl interface
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
#include "unlang_priv.h"
#include <freeradius-devel/server/exec.h>

#ifdef __cplusplus
extern "C" {
#endif

/** A tmpl stack entry
 *
 * Represents a single tmpl
 */
typedef struct {
	TALLOC_CTX			*ctx;		//!< for allocating value boxes
	fr_value_box_list_t		*out;		//!< output list if the exec succeeds
	fr_value_box_list_t		list;		//!< our intermediate working list

	void				*rctx;		//!< for resume
	fr_unlang_tmpl_resume_t		resume;	       	//!< resumption handler
	fr_unlang_tmpl_signal_t		signal;		//!< signal handler

	union {
		fr_exec_state_t		exec;
	};

	unlang_tmpl_args_t		args;		//!< Arguments that control how the
							///< tmpl is evaluated.
} unlang_frame_state_tmpl_t;

#ifdef __cplusplus
}
#endif
