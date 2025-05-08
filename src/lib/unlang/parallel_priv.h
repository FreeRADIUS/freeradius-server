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
#include "child_request_priv.h"
#include "unlang_priv.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	rlm_rcode_t			result;
	int				priority;

	unsigned int			num_children;	//!< How many children are executing.
	unsigned int			num_runnable;	//!< How many children are complete.

	bool				detach;		//!< are we creating the child detached
	bool				clone;		//!< are the children cloned

	unlang_t			*instruction;	//!< The instruction the children should
							///< start executing.

	unlang_child_request_t		children[];	//!< Array of children.
} unlang_parallel_state_t;

typedef struct {
	unlang_group_t			group;
	bool				detach;		//!< are we creating the child detached
	bool				clone;
} unlang_parallel_t;

/** Cast a group structure to the parallel keyword extension
 *
 */
static inline unlang_parallel_t *unlang_group_to_parallel(unlang_group_t *g)
{
	return talloc_get_type_abort(g, unlang_parallel_t);
}

/** Cast a parallel keyword extension to a group structure
 *
 */
static inline unlang_group_t *unlang_parallel_to_group(unlang_parallel_t *parallel)
{
	return (unlang_group_t *)parallel;
}

#ifdef __cplusplus
}
#endif
