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
 * @file lib/server/rcode.h
 * @brief Return codes returned by modules and virtual server sections
 *
 * @copyright 2018 The FreeRADIUS server project
 */
RCSIDH(rcode_h, "$Id$")

#include <freeradius-devel/util/table.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Return codes indicating the result of the module call
 *
 * All module functions must return one of the codes listed below (apart from
 * RLM_MODULE_NUMCODES, which is used to check for validity).
 */
typedef enum {
	RLM_MODULE_REJECT = 0,				//!< Immediately reject the request.
	RLM_MODULE_FAIL,				//!< Module failed, don't reply.
	RLM_MODULE_OK,					//!< The module is OK, continue.
	RLM_MODULE_HANDLED,				//!< The module handled the request, so stop.
	RLM_MODULE_INVALID,				//!< The module considers the request invalid.
	RLM_MODULE_USERLOCK,				//!< Reject the request (user is locked out).
	RLM_MODULE_NOTFOUND,				//!< User not found.
	RLM_MODULE_NOOP,				//!< Module succeeded without doing anything.
	RLM_MODULE_UPDATED,				//!< OK (pairs modified).
	RLM_MODULE_NUMCODES,				//!< How many valid return codes there are.
	RLM_MODULE_YIELD,				//!< for unlang.
	RLM_MODULE_UNKNOWN,				//!< Error resolving rcode (should not be
							//!< returned by modules).
} rlm_rcode_t;
extern fr_table_num_sorted_t const rcode_table[];
extern size_t rcode_table_len;

/** Rcodes that translate to a user configurable section failing overall
 *
 */
#define RLM_MODULE_USER_SECTION_REJECT	\
	RLM_MODULE_REJECT:		\
	case RLM_MODULE_FAIL:		\
	case RLM_MODULE_INVALID:	\
	case RLM_MODULE_USERLOCK

#ifdef __cplusplus
}
#endif
