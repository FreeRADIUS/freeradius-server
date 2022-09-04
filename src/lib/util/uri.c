/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Functions for dealing with URIs
 *
 * @file src/lib/util/uri.c
 *
 * @copyright 2021 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "uri.h"

/** Parse a list of value boxes representing a URI
 *
 * Reads a URI from a list of value boxes and parses it according to the
 * definition in uri_parts.  Tainted values, where allowed, are escaped
 * using the function specified for the uri part.
 *
 * @param uri		to parse.  A list of string type value boxes containing
 *			fragments of a URI.
 * @param uri_parts	definition of URI structure
 * @param uctx		to pass to escaping function
 * @return
 * 	- 0 on success
 * 	- -1 on failure
 */
int fr_uri_escape(fr_value_box_list_t *uri, fr_uri_part_t const *uri_parts, void *uctx)
{
	fr_value_box_t		*uri_vb = NULL;
	fr_uri_part_t const	*uri_part;
	fr_sbuff_t		sbuff;

	uri_part = uri_parts;

	fr_strerror_clear();

	while ((uri_vb = fr_dlist_next(uri, uri_vb))){
		if (uri_vb->tainted && !uri_part->tainted_allowed) {
			fr_strerror_printf_push("Tainted value not allowed for %s", uri_part->name);
			return -1;
		}

		/*
		 *	Tainted boxes can only belong to a single part of the URI
		 */
		if (uri_vb->tainted) {
			if (uri_part->func) {
				/*
				 *	Escaping often ends up breaking the vb's list pointers
				 *	so remove it from the list and re-insert after the escaping
				 *	has been done
				 */
				fr_value_box_t	*prev = fr_dlist_remove(uri, uri_vb);
				if (uri_part->func(uri_vb, uctx) < 0) {
					fr_strerror_printf_push("Unable to escape tainted input %pV", uri_vb);
					return -1;
				}
				fr_dlist_insert_after(uri, prev, uri_vb);
			}
			continue;
		}

		/*
		 *	This URI part has no term chars - so no need to look for them
		 */
		if (!uri_part->terminals) continue;

		/*
		 *	Zero length box - no terminators here
		 */
		if (uri_vb->length == 0) continue;

		/*
		 *	Look for URI part terminator
		 */
		fr_sbuff_init_in(&sbuff, uri_vb->vb_strvalue, uri_vb->length);

		do {
			fr_sbuff_adv_until(&sbuff, SIZE_MAX, uri_part->terminals, '\0');

			/*
			 *	We've not found a terminal in the current box
			 */
			if (uri_part->part_adv[fr_sbuff_char(&sbuff, '\0')] == 0) continue;

			/*
			 *	This terminator has trailing characters to skip
			 */
			if (uri_part->extra_skip) fr_sbuff_advance(&sbuff, uri_part->extra_skip);

			/*
			 *	Move to the next part
			 */
			uri_part += uri_part->part_adv[fr_sbuff_char(&sbuff, '\0')];
			if (!uri_part->terminals) break;
		} while (fr_sbuff_advance(&sbuff, 1) > 0);
	}

	return 0;
}
