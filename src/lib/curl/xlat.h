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

/** Generic xlat functions dependent on libcurl
 *
 * @file src/lib/curl/xlat.h
 *
 * @copyright 2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(curl_xlat_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <curl/curl.h>
#include <freeradius-devel/unlang/xlat.h>

/** safe for value suitable for all users of the curl library
 *
 */
#define CURL_URI_SAFE_FOR ((fr_value_box_safe_for_t)fr_curl_xlat_uri_escape)

extern xlat_arg_parser_t const fr_curl_xlat_uri_args[];
extern xlat_arg_parser_t const fr_curl_xlat_safe_args[];

xlat_action_t		fr_curl_xlat_uri_escape(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
						UNUSED xlat_ctx_t const *xctx, UNUSED request_t *request,
						fr_value_box_list_t *in);

xlat_action_t		fr_curl_xlat_uri_unescape(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
						  UNUSED xlat_ctx_t const *xctx, UNUSED request_t *request,
						  fr_value_box_list_t *in);

#ifdef __cplusplus
}
#endif
