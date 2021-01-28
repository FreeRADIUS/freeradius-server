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
 * @file rlm_rest/io.c
 * @brief Implement asynchronous callbacks for curl
 *
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#include "rest.h"
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/base.h>

/** Handle asynchronous cancellation of a request
 *
 * If we're signalled that the request has been cancelled (FR_SIGNAL_CANCEL).
 * Cleanup any pending state and release the connection handle back into the pool.
 */
void rest_io_module_action(module_ctx_t const *mctx, request_t *request, void *rctx, fr_state_signal_t action)
{
	fr_curl_io_request_t	*randle = talloc_get_type_abort(rctx, fr_curl_io_request_t);
	rlm_rest_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_rest_thread_t);
	CURLMcode		ret;

	if (action != FR_SIGNAL_CANCEL) return;

	RDEBUG2("Forcefully cancelling pending REST request");

	ret = curl_multi_remove_handle(t->mhandle->mandle, randle->candle);	/* Gracefully terminate the request */
	if (ret != CURLM_OK) {
		RERROR("Failed removing curl handle from multi-handle: %s (%i)", curl_multi_strerror(ret), ret);
		/* Not much we can do */
	}
	t->mhandle->transfers--;

	rest_request_cleanup(mctx->instance, randle);
	fr_pool_connection_release(t->pool, request, randle);
}

/** Handle asynchronous cancellation of a request
 *
 * If we're signalled that the request has been cancelled (FR_SIGNAL_CANCEL).
 * Cleanup any pending state and release the connection handle back into the pool.
 */
void rest_io_xlat_signal(request_t *request, UNUSED void *instance, void *thread, void *rctx, fr_state_signal_t action)
{
	rest_xlat_thread_inst_t		*xti = talloc_get_type_abort(thread, rest_xlat_thread_inst_t);
	rlm_rest_t			*mod_inst = xti->inst;
	rlm_rest_thread_t		*t = xti->t;

	rlm_rest_xlat_rctx_t		*our_rctx = talloc_get_type_abort(rctx, rlm_rest_xlat_rctx_t);
	fr_curl_io_request_t		*randle = talloc_get_type_abort(our_rctx->handle, fr_curl_io_request_t);

	rest_io_module_action(&(module_ctx_t){ .instance = mod_inst, .thread = t }, request, randle, action);
}
