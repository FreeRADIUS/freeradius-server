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

/** Main include file for our libcurl extension API
 *
 * @file src/lib/curl/base.h
 *
 * @copyright 2019 The FreeRADIUS project
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

RCSIDH(curl_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <curl/curl.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/server/module.h>

#define FR_CURL_SET_OPTION(_x, _y)\
do {\
	if ((ret = curl_easy_setopt(randle->candle, _x, _y)) != CURLE_OK) {\
		char const *_option;\
		_option = STRINGIFY(_x);\
		goto error;\
	}\
} while (0)

/** Uctx data for timer and I/O functions
 *
 * Seems like overkill for a single field, but I'm sure we'll need to
 * pass around other things later.
 */
typedef struct {
	fr_event_list_t		*el;			//!< Event list servicing I/O events.
	fr_event_timer_t const	*ev;			//!< Multi-Handle timer.
	uint64_t		transfers;		//!< How many transfers are current in progress.
	CURLM			*mandle;		//!< The multi handle.
} fr_curl_handle_t;

/** Structure representing an individual request being passed to curl for processing
 *
 */
typedef struct {
	CURL			*candle;		//!< Request specific handle.
	CURLcode		result;			//!< Result of executing the request.
	REQUEST		        *request;		//!< Current request.
	void			*uctx;			//!< Private data for the module using the API.
} fr_curl_io_request_t;

typedef struct {
	char const		*tls_certificate_file;
	char const		*tls_private_key_file;
	char const		*tls_private_key_password;
	char const		*tls_ca_file;
	char const		*tls_ca_issuer_file;
	char const		*tls_ca_path;
	char const		*tls_random_file;
	bool			tls_check_cert;
	bool			tls_check_cert_cn;
	bool			tls_extract_cert_attrs;
} fr_curl_tls_t;

static CONF_PARSER fr_curl_tls_config[] = {
	{ FR_CONF_OFFSET("ca_file", FR_TYPE_FILE_INPUT, fr_curl_tls_t, tls_ca_file) },
	{ FR_CONF_OFFSET("ca_issuer_file", FR_TYPE_FILE_INPUT, fr_curl_tls_t, tls_ca_issuer_file) },
	{ FR_CONF_OFFSET("ca_path", FR_TYPE_FILE_INPUT, fr_curl_tls_t, tls_ca_path) },
	{ FR_CONF_OFFSET("certificate_file", FR_TYPE_FILE_INPUT, fr_curl_tls_t, tls_certificate_file) },
	{ FR_CONF_OFFSET("private_key_file", FR_TYPE_FILE_INPUT, fr_curl_tls_t, tls_private_key_file) },
	{ FR_CONF_OFFSET("private_key_password", FR_TYPE_STRING | FR_TYPE_SECRET, fr_curl_tls_t, tls_private_key_password) },
	{ FR_CONF_OFFSET("random_file", FR_TYPE_STRING, fr_curl_tls_t, tls_random_file) },
	{ FR_CONF_OFFSET("check_cert", FR_TYPE_BOOL, fr_curl_tls_t, tls_check_cert), .dflt = "yes" },
	{ FR_CONF_OFFSET("check_cert_cn", FR_TYPE_BOOL, fr_curl_tls_t, tls_check_cert_cn), .dflt = "yes" },
	{ FR_CONF_OFFSET("extract_cert_attrs", FR_TYPE_BOOL, fr_curl_tls_t, tls_extract_cert_attrs), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

int			fr_curl_io_request_enqueue(fr_curl_handle_t *mhandle,
						   REQUEST *request, fr_curl_io_request_t *creq);

fr_curl_io_request_t	*fr_curl_io_request_alloc(TALLOC_CTX *ctx);

fr_curl_handle_t	*fr_curl_io_init(TALLOC_CTX *ctx, fr_event_list_t *el, bool multiplex);

int			fr_curl_init(void);

void			fr_curl_free(void);

int 				fr_curl_response_certinfo(REQUEST *request, fr_curl_io_request_t *randle);

int 				fr_curl_easy_tls_init (fr_curl_io_request_t *randle, fr_curl_tls_t *conf);

#ifdef __cplusplus
}
#endif
