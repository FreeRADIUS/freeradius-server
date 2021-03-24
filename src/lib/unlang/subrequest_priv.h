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

#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/util/dict.h>
#include "unlang_priv.h"

typedef struct {
	unlang_group_t		group;
	tmpl_t			*vpt;			//!< Value to expand to find the value to place
							///< into the packet-type attribute.

	tmpl_t			*src;			//!< Pairs to copy into the subrequest request list.
	tmpl_t			*dst;			//!< Where to copy pairs from the reply list in the
							///< subrequest to.

	fr_dict_t const		*dict;			//!< Dictionary of the subrequest protocol.
	fr_dict_attr_t const	*attr_packet_type;	//!< Packet-type attribute in the subrequest protocol.
	fr_dict_enum_t const	*type_enum;		//!< Static enumeration value for attr_packet_type
							///< if the packet-type is static.
} unlang_subrequest_t;

/** Parameters for initialising the subrequest (parent's frame state)
 *
 */
typedef struct {
	rlm_rcode_t			*p_result;			//!< Where to store the result.
	request_t			*child;				//!< Pre-allocated child request.
	bool				free_child;			//!< Whether we should free the child after
									///< it completes.
	bool				detachable;			//!< Whether the request can be detached.
	unlang_subrequest_session_t	session;			//!< Session configuration.
} unlang_frame_state_subrequest_t;

/** Cast a group structure to the subrequest keyword extension
 *
 */
static inline unlang_subrequest_t *unlang_group_to_subrequest(unlang_group_t *g)
{
	return talloc_get_type_abort(g, unlang_subrequest_t);
}

/** Cast a subrequest keyword extension to a group structure
 *
 */
static inline unlang_group_t *unlang_subrequest_to_group(unlang_subrequest_t *subrequest)
{
	return (unlang_group_t *)subrequest;
}

void	unlang_subrequest_free(request_t **child);

int unlang_subrequest_child_push(rlm_rcode_t *out, request_t *child,
			   unlang_subrequest_session_t const *session, bool top_frame)
			   CC_HINT(warn_unused_result);

int unlang_subrequest_detach_child(request_t *request);

#ifdef __cplusplus
}
#endif
