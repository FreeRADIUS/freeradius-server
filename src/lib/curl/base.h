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

#define CURL_NO_OLDIES 1

#include <curl/curl.h>
#include <freeradius-devel/server/global_lib.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/slab.h>
#include <freeradius-devel/unlang/xlat.h>

DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(disabled-macro-expansion)
DIAG_ON(DIAG_UNKNOWN_PRAGMAS)
#define FR_CURL_SET_OPTION(_x, _y)\
do {\
	int _ret;\
	if ((_ret = curl_easy_setopt(randle->candle, _x, _y)) != CURLE_OK) {\
		char const *_option;\
		_option = STRINGIFY(_x);\
		ERROR("Failed setting curl option %s: %s (%i)", _option, curl_easy_strerror(_ret), _ret);\
		goto error;\
	}\
} while (0)

#define FR_CURL_ROPTIONAL_SET_OPTION(_x, _y)\
do {\
	int _ret;\
	if ((_ret = curl_easy_setopt(randle->candle, _x, _y)) != CURLE_OK) {\
		char const *_option;\
		_option = STRINGIFY(_x);\
		ROPTIONAL(RERROR, ERROR, "Failed setting curl option %s: %s (%i)", _option, curl_easy_strerror(_ret), _ret);\
		goto error;\
	}\
} while (0)

#define FR_CURL_REQUEST_SET_OPTION(_x, _y)\
do {\
	int _ret;\
	if ((_ret = curl_easy_setopt(randle->candle, _x, _y)) != CURLE_OK) {\
		char const *_option;\
		_option = STRINGIFY(_x);\
		RERROR("Failed setting curl option %s: %s (%i)", _option, curl_easy_strerror(_ret), _ret);\
		goto error;\
	}\
} while (0)

/*
 * We have to use this as curl uses lots of enums
 */
#ifndef CURL_AT_LEAST_VERSION
#  define CURL_VERSION_BITS(x, y, z) ((x) << 16 | (y) << 8 | (z))
#  define CURL_AT_LEAST_VERSION(x, y, z) (LIBCURL_VERSION_NUM >= CURL_VERSION_BITS(x, y, z))
#endif

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
	request_t		*request;		//!< Current request.
	void			*uctx;			//!< Private data for the module using the API.
} fr_curl_io_request_t;

typedef struct {
	char const		*certificate_file;
	char const		*private_key_file;
	char const		*private_key_password;
	char const		*ca_file;
	char const		*ca_issuer_file;
	char const		*ca_path;
	char const		*random_file;
	long			*require_cert;
	bool			check_cert;
	bool			check_cert_cn;
	bool			extract_cert_attrs;
	char const		*keylog_file;		//!< Where to log SSL keying material like the pre-master secret.
							///< The log file can then be used to decrypt the SSL session
							///< with Wireshark.
} fr_curl_tls_t;

typedef struct {
	fr_slab_config_t	reuse;
	fr_time_delta_t		connect_timeout;
} fr_curl_conn_config_t;

extern conf_parser_t	 	fr_curl_tls_config[];
extern conf_parser_t		fr_curl_conn_config[];
extern global_lib_autoinst_t	fr_curl_autoinst;

int			fr_curl_io_request_enqueue(fr_curl_handle_t *mhandle,
						   request_t *request, fr_curl_io_request_t *creq);

fr_curl_io_request_t	*fr_curl_io_request_alloc(TALLOC_CTX *ctx);

fr_curl_handle_t	*fr_curl_io_init(TALLOC_CTX *ctx, fr_event_list_t *el, bool multiplex);

int			fr_curl_response_certinfo(request_t *request, fr_curl_io_request_t *randle);

int			fr_curl_easy_tls_init (fr_curl_io_request_t *randle, fr_curl_tls_t const *conf);

CURL			*fr_curl_tmp_handle(void);
#ifdef __cplusplus
}
#endif
