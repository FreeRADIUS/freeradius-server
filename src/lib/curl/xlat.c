/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file curl/xlat.c
 * @brief Generic xlat functions dependent on libcurl
 *
 * @copyright 2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

#include <freeradius-devel/util/value.h>
#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/curl/base.h>
#include <freeradius-devel/curl/xlat.h>

#include "base.h"

xlat_arg_parser_t const fr_curl_xlat_uri_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

xlat_arg_parser_t const fr_curl_xlat_safe_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** xlat function to escape URI encoded strings
 *
 */
xlat_action_t fr_curl_xlat_uri_escape(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
			       	      UNUSED xlat_ctx_t const *xctx, UNUSED request_t *request,
				      fr_value_box_list_t *in)
{
	fr_value_box_t	*to_escape = fr_value_box_list_pop_head(in);
	char		*escaped;

	escaped = curl_easy_escape(fr_curl_tmp_handle(), to_escape->vb_strvalue, to_escape->vb_length);
	if (!escaped) return XLAT_ACTION_FAIL;

	/*
	 *	Returned string the same length - nothing changed
	 */
	if (strlen(escaped) == to_escape->vb_length) goto done;

	fr_value_box_clear_value(to_escape);
	fr_value_box_strdup(to_escape, to_escape, NULL, escaped, to_escape->tainted);

done:
	curl_free(escaped);
	fr_dcursor_insert(out, to_escape);

	return XLAT_ACTION_DONE;
}

/** xlat function to unescape URI encoded strings
 *
 */
xlat_action_t fr_curl_xlat_uri_unescape(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out,
					UNUSED xlat_ctx_t const *xctx, UNUSED request_t *request,
					fr_value_box_list_t *in)
{
	fr_value_box_t	*to_unescape = fr_value_box_list_pop_head(in);
	int		unescaped_len;
	char		*unescaped;

	unescaped = curl_easy_unescape(fr_curl_tmp_handle(), to_unescape->vb_strvalue, to_unescape->vb_length, &unescaped_len);
	if (!unescaped) {
		talloc_free(to_unescape);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Returned string the same length - nothing changed
	 */
	if ((size_t)unescaped_len == to_unescape->vb_length) {
		curl_free(unescaped);
		fr_dcursor_insert(out, to_unescape);
		return XLAT_ACTION_DONE;
	}

	fr_value_box_clear_value(to_unescape);
	fr_value_box_bstrndup(to_unescape, to_unescape, NULL, unescaped, unescaped_len, to_unescape->tainted);
	curl_free(unescaped);
	fr_dcursor_insert(out, to_unescape);

	return XLAT_ACTION_DONE;
}
