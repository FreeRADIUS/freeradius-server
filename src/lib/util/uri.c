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

/** Escapes an individual value box that's part of a URI, advancing the pointer to uri_parts
 *
 * @note This function has a signature compatible with fr_uri_escape_func_t.
 *
 * @param[in,out] uri_vb	to escape
 * @param[in] uctx		A fr_uri_escape_ctx_t containing the initial fr_uri_part_t
 *				and the uctx to pass to the escaping function.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_uri_escape(fr_value_box_t *uri_vb, void *uctx)
{
	fr_uri_escape_ctx_t	*ctx = uctx;
	fr_sbuff_t		sbuff;
	uint8_t			adv;

	if (uri_vb->tainted && !ctx->uri_part->tainted_allowed) {
		fr_strerror_printf_push("Tainted value not allowed for %s", ctx->uri_part->name);
		return -1;
	}

	/*
	 *	Ensure boxes are strings before attempting to escape.
	 */
	if (unlikely(uri_vb->type != FR_TYPE_STRING)) {
		if (unlikely(fr_value_box_cast_in_place(uri_vb, uri_vb, FR_TYPE_STRING, uri_vb->enumv) < 0)) {
			fr_strerror_printf_push("Unable to cast %pV to a string", uri_vb);
			return -1;
		}
	}

	/*
	 *	Tainted boxes can only belong to a single part of the URI
	 */
	if (uri_vb->tainted) {
		if (ctx->uri_part->func) {
			/*
			 *	Escaping often ends up breaking the vb's list pointers
			 *	so remove it from the list and re-insert after the escaping
			 *	has been done
			 */
			fr_value_box_entry_t entry = uri_vb->entry;
			if (ctx->uri_part->func(uri_vb, ctx->uctx) < 0) {
				fr_strerror_printf_push("Unable to escape tainted input %pV", uri_vb);
				return -1;
			}
			uri_vb->entry = entry;
		}
		return 0;
	}

	/*
	 *	This URI part has no term chars - so no need to look for them
	 */
	if (!ctx->uri_part->terminals) return 0;

	/*
	 *	Zero length box - no terminators here
	 */
	if (uri_vb->vb_length == 0) return 0;

	/*
	 *	Look for URI part terminator
	 */
	fr_sbuff_init_in(&sbuff, uri_vb->vb_strvalue, uri_vb->vb_length);
	do {
		fr_sbuff_adv_until(&sbuff, SIZE_MAX, ctx->uri_part->terminals, '\0');

		/*
		 *	We've not found a terminal in the current box
		 */
		adv = ctx->uri_part->part_adv[fr_sbuff_char(&sbuff, '\0')];
		if (adv == 0) continue;

		/*
		 *	This terminator has trailing characters to skip
		 */
		if (ctx->uri_part->extra_skip) fr_sbuff_advance(&sbuff, ctx->uri_part->extra_skip);

		/*
		 *	Move to the next part
		 */
		ctx->uri_part += adv;
		if (!ctx->uri_part->terminals) break;
	} while (fr_sbuff_advance(&sbuff, 1) > 0);

	return 0;
}

/** Parse a list of value boxes representing a URI
 *
 * Reads a URI from a list of value boxes and parses it according to the
 * definition in uri_parts.  Tainted values, where allowed, are escaped
 * using the function specified for the uri part.
 *
 * @param uri		to parse.  A list of string type value boxes containing
 *			fragments of a URI.
 * @param uri_parts	definition of URI structure.  Should point to the start
 *			of the array of uri parts.
 * @param uctx		to pass to escaping function
 * @return
 * 	- 0 on success
 * 	- -1 on failure
 */
int fr_uri_escape_list(fr_value_box_list_t *uri, fr_uri_part_t const *uri_parts, void *uctx)
{
	fr_uri_escape_ctx_t ctx = {
		.uri_part = uri_parts,
		.uctx = uctx,
	};

	fr_strerror_clear();

	fr_value_box_list_foreach_safe(uri, uri_vb) {
		if (unlikely(fr_uri_escape(uri_vb, &ctx)) < 0) return -1;
	}}

	return 0;
}
