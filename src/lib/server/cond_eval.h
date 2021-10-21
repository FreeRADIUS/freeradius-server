#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/cond_eval.h
 * @brief Structures and prototypes for the condition evaluation code
 *
 * @copyright 2007 The FreeRADIUS server project
 * @copyright 2007 Alan DeKok (aland@deployingradius.com)
 */
RCSIDH(cond_eval_h, "$Id$")

#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/util/value.h>

#ifdef __cplusplus
extern "C" {
#endif

/* evaluate.c */
typedef struct fr_cond_s fr_cond_t;

void	cond_debug(fr_cond_t const *cond);

int	cond_eval(request_t *request, rlm_rcode_t modreturn, fr_cond_t const *c);

typedef struct {
	TALLOC_CTX	*ctx;		//!< for intermediate value boxes
	fr_cond_t const	*c;		//!< the current condition being evaluated
	rlm_rcode_t	modreturn;	//!< the previous module return code;

	tmpl_t const	*tmpl_lhs;	//!< the LHS async template to evaluate
	tmpl_t const	*tmpl_rhs;	//!< the RHS async template to evaluate

	fr_value_box_t	*vb_lhs;	//!< the output of the LHS async evaluation
	fr_value_box_t	*vb_rhs;	//!< the output of the RHS async evaluation

	enum {
		COND_EVAL_STATE_INVALID = 0,
		COND_EVAL_STATE_INIT,
		COND_EVAL_STATE_EXPAND,
		COND_EVAL_STATE_EVAL,
		COND_EVAL_STATE_DONE,
	} state;

	bool		result;		//!< the final conditional result
} fr_cond_async_t;

int cond_eval_async(request_t *request, fr_cond_async_t *a);

int fr_cond_eval_map(request_t *request, map_t const *map);

#ifdef __cplusplus
}
#endif
