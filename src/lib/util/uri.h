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

/** Functions for dealing with URIs
 *
 * @file src/lib/util/uri.c
 *
 * @copyright 2021 The FreeRADIUS server project
 */
RCSIDH(uri_h, "$Id$")

#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/sbuff.h>

#ifdef __cplusplus
extern "C" {
#endif

/** A function used to escape an argument passed to an xlat
 *
 * @param[in,out] vb		to escape
 * @param[in] uctx		a "context" for the escaping
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*fr_uri_escape_func_t)(fr_value_box_t *vb, void *uctx);

/** Definition for a single part of a URI
 *
 */
typedef struct {
	char const		*name;				//!< Name of this part of the URI
	fr_sbuff_term_t const	*terminals;			//!< Characters that mark the end of this part.
	uint8_t const		part_adv[UINT8_MAX + 1];	//!< How many parts to advance for a specific terminal
	size_t			extra_skip;			//!< How many additional characters to skip after
								///< the terminal
	bool			tainted_allowed;		//!< Do we accept tainted values for this part
	fr_uri_escape_func_t	func;				//!< Function to use to escape tainted values
} fr_uri_part_t;

#define XLAT_URI_PART_TERMINATOR { .name = NULL, .terminals = NULL, .tainted_allowed = false, .func = NULL }

int fr_uri_escape(fr_value_box_list_t *uri, fr_uri_part_t const *uri_parts, void *uctx);

#ifdef __cplusplus
}
#endif
