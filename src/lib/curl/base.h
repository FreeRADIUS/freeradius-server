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

int			fr_curl_io_request_enqueue(fr_curl_handle_t *mhandle,
						   REQUEST *request, fr_curl_io_request_t *creq);

fr_curl_io_request_t	*fr_curl_io_request_alloc(TALLOC_CTX *ctx);

fr_curl_handle_t	*fr_curl_io_init(TALLOC_CTX *ctx, fr_event_list_t *el, bool multiplex);

int			fr_curl_init(void);

void			fr_curl_free(void);

#ifdef __cplusplus
}
#endif
