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
 * @file unlang/parallel.h
 * @brief Private interpreter structures and functions
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

/** Parallel children have states
 *
 */
typedef enum unlang_parallel_child_state_t {
	CHILD_INIT = 0,				//!< needs initialization
	CHILD_RUNNABLE,
	CHILD_YIELDED,
	CHILD_DONE
} unlang_parallel_child_state_t;

/** Each parallel child has a state, and an associated request
 *
 */
typedef struct {
	unlang_parallel_child_state_t	state;		//!< state of the child
	REQUEST				*child; 	//!< child request
	unlang_t			*instruction;	//!< broken out of g->children
} unlang_parallel_child_t;

typedef struct {
	rlm_rcode_t		result;
	int			priority;

	int			num_children;

	unlang_group_t		*g;

	unlang_parallel_child_t children[];
} unlang_parallel_t;

#ifdef __cplusplus
}
#endif
