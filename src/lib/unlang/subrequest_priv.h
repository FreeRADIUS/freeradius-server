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

typedef struct {
	tmpl_t			*vpt;			//!< Value to expand to find the value to place
							///< into the packet-type attribute.

	tmpl_t			*src;			//!< Pairs to copy into the subrequest request list.
	tmpl_t			*dst;			//!< Where to copy pairs from the reply list in the
							///< subrequest to.

	fr_dict_t const		*dict;			//!< Dictionary of the subrequest protocol.
	fr_dict_attr_t const	*attr_packet_type;	//!< Packet-type attribute in the subrequest protocol.
	fr_dict_enum_t const	*type_enum;		//!< Static enumeration value for attr_packet_type
							///< if the packet-type is static.
} unlang_subrequest_kctx_t;

void	unlang_subrequest_free(request_t **child);

void unlang_subrequest_push(rlm_rcode_t *out, request_t *child,
			    unlang_subrequest_session_t const *session, bool top_frame);

int unlang_detached_child_init(request_t *request);

#ifdef __cplusplus
}
#endif
