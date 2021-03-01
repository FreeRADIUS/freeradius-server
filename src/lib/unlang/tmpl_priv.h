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

#ifdef __cplusplus
extern "C" {
#endif

/** A tmpl stack entry
 *
 * Represents a single tmpl
 */
typedef struct {
	TALLOC_CTX			*ctx;		//!< for allocating value boxes
	fr_value_box_list_t		*out;		//!< where the expansion is stored
	fr_value_box_list_t		box;		//!< where the expansion is stored

	void				*rctx;		//!< for resume
	fr_unlang_tmpl_resume_t		resume;	       	//!< resumption handler
	fr_unlang_tmpl_signal_t		signal;		//!< signal handler

	bool				failed;		//!< due to exec timeout or buffer overflow

	pid_t				pid;		//!< child PID
	int				fd;		//!< for reading from the child
	fr_event_timer_t const		*ev;		//!< for timing out the child
	fr_event_pid_t const   		*ev_pid;	//!< for cleaning up the process

	fr_pair_list_t			*vps;		//!< input VPs
	char				*buffer;	//!< for reading the answer
	char				*ptr;		//!< where in the buffer we are writing to
	int				status;		//!< return code of the program
	int				*status_p;	//!< where we write the return status of the program
} unlang_frame_state_tmpl_t;

#ifdef __cplusplus
}
#endif
