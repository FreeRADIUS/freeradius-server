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
 * @file unlang/action.h
 * @brief Unlang interpreter actions
 *
 * @copyright 2019 The FreeRADIUS server project
 */

#ifdef __cplusplus
extern "C" {
#endif

/** Returned by #unlang_op_t calls, determine the next action of the interpreter
 *
 * These deal exclusively with control flow.
 */
typedef enum {
	UNLANG_ACTION_CALCULATE_RESULT = 1,	//!< Calculate a new section #rlm_rcode_t value.
	UNLANG_ACTION_EXECUTE_NEXT,    		//!< Execute the next #unlang_t.
	UNLANG_ACTION_PUSHED_CHILD,		//!< #unlang_t pushed a new child onto the stack,
						//!< execute it instead of continuing.
	UNLANG_ACTION_UNWIND,			//!< Break out of the current group.
	UNLANG_ACTION_YIELD,			//!< Temporarily pause execution until an event occurs.
	UNLANG_ACTION_STOP_PROCESSING		//!< Break out of processing the current request (unwind).
} unlang_action_t;

#ifdef __cplusplus
}
#endif
