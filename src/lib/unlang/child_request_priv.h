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
 * @file unlang/subrequest_child_priv.h
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include <freeradius-devel/server/request.h>

#ifdef __cplusplus
extern "C" {
#endif


/** Parallel child states
 *
 */
typedef enum {
	CHILD_INIT = 0,						//!< Initial state, has no request allocated.

	CHILD_RUNNABLE,						//!< Running/runnable.  The request is currently
								///< running, or is yielded but runnable.
	CHILD_EXITED,						//!< Child has run to completion, and is waiting
								///< to be reaped.
	CHILD_DETACHED,						//!< Child has detached, we can't signal it or
								///< communicate with it anymore.  It will be freed
								///< by the interpreter when it completes.
	CHILD_CANCELLED,					//!< Child was cancelled.  The request is still
								///< available, but the result from it should not
								///< be used and it should be free by the parent.
	CHILD_DONE,						//!< The child has been processed by the parent
								///< the request should still exist, and should be freed.

	CHILD_FREED						//!< The child has been freed.  The request is no
								///< longer available, and should not be used.
								///< this is mostly for debugging purposes.
} unlang_child_request_state_t;

extern fr_table_num_ordered_t const unlang_child_states_table[];
extern size_t unlang_child_states_table_len;

/** Each child has a state, a number, a request, and a count of their siblings
 */
typedef struct {
	char const			*name;			//!< Cache the request name.
	int				num;			//!< The child number.
	request_t			*request; 		//!< Child request.  The actual request the child will run.

	unlang_child_request_state_t	state;			//!< State of the child.

	unsigned int			*sibling_count;		//!< Number of siblings.
								///< as a child completes, it decrements this number.
								///< once it reaches zero, the parent is signalled
								///< to resume.

	struct {
		void const		*session_unique_ptr;	//!< Session unique ptr identifier.  If not NULL, the child's
								///< session data will be stored in the parent, and be restored
								///< during a later request.
		bool			free_child;
	} config;

	struct {
		rlm_rcode_t		rcode;			//!< Where to store the result of the child.
		rlm_rcode_t		*p_result;		//!< If not NULL, write the rcode here too.
		int			priority;		//!< Priority of the highest frame on the stack of the child.
	} result;
} unlang_child_request_t;

int		unlang_child_request_init(TALLOC_CTX *ctx, unlang_child_request_t *out, request_t *child,
					  rlm_rcode_t *p_result, unsigned int *sibling_count, void const *unique_session_ptr, bool free_child);

int		unlang_child_request_op_init(void);

#ifdef __cplusplus
}
#endif
