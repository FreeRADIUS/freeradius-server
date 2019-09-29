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
 * @file unlang/subrequest_priv.h
 *
 * @copyright 2019 The FreeRADIUS server project
 */
#ifdef __cplusplus
extern "C" {
#endif

/** Parameters for initialising the subrequest
 *
 * State of one level of nesting within an xlat expansion.
 */
typedef struct {
	rlm_rcode_t		*presult;		//!< Where to store the result.
	REQUEST			*child;			//!< Pre-allocated child request.
	bool			persist : 1;		//!< Whether we should free the child after it completes.
	bool			detachable : 1;		//!< Whether the request can be detached.
} unlang_frame_state_subrequest_t;

void	unlang_subrequest_free(REQUEST **child);

void	unlang_subrequest_push(rlm_rcode_t *out, REQUEST *child, bool top_frame);

int unlang_detached_child_init(REQUEST *request);

#ifdef __cplusplus
}
#endif
