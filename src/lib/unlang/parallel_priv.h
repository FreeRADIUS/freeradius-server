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
 * @file unlang/parallel_priv.h
 * @brief Declarations for the unlang "parallel" keyword
 *
 * Should be moved into parallel.c when the parallel stuff is fully extracted
 * from interpret.c
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
#include "unlang_priv.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Parallel child states
 *
 */
typedef enum {
	CHILD_INIT = 0,					//!< Initial state.
	CHILD_RUNNABLE,					//!< Child can continue running.
	CHILD_YIELDED,					//!< Child is yielded waiting on an event.
	CHILD_EXITED,					//!< Child has exited
	CHILD_DONE					//!< The child has completed.
} unlang_parallel_child_state_t;

/** Each parallel child has a state, and an associated request
 *
 */
typedef struct {
	unlang_parallel_child_state_t	state;		//!< State of the child.
	REQUEST				*child; 	//!< Child request.
	unlang_t			*instruction;	//!< broken out of g->children
} unlang_parallel_child_t;

typedef struct {
	rlm_rcode_t		result;
	int			priority;

	int			num_children;		//!< How many children are executing.

	unlang_group_t		*g;

	unlang_parallel_child_t children[];		//!< Array of children.
} unlang_parallel_t;

#ifdef __cplusplus
}
#endif
