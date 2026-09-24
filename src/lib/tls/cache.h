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
#ifdef WITH_TLS
/**
 * $Id$
 *
 * @file lib/tls/cache.h
 * @brief Structures for session-resumption management.
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(cache_h, "$Id$")

#include "openssl_user_macros.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Current store state
 *
 * This tracks what session-resumption data has been provided by
 * OpenSSL so that we can persist it asynchronously at the
 * appropriate time.
 */
typedef enum {
	FR_TLS_CACHE_STORE_INIT = 0,		//!< OpenSSL hasn't passed any cache data over.
	FR_TLS_CACHE_STORE_REQUESTED,		//!< OpenSSL passed us cache data, but we haven't
						///< persisted it yet.
	FR_TLS_CACHE_STORE_PERSISTED,		//!< We've persisted the cached data.
} fr_tls_cache_store_state_t;

/** Current load state
 *
 * This tracks what session-resumption data has been requested
 * by OpenSSL, so that was can load it asynchronously at the
 * appropriate time.
 */
typedef enum {
	FR_TLS_CACHE_LOAD_INIT = 0,		//!< Initial state.
	FR_TLS_CACHE_LOAD_REQUESTED,		//!< OpenSSL has requested session data.
	FR_TLS_CACHE_LOAD_RETRIEVED,		//!< We got the cache data from an external data store.
	FR_TLS_CACHE_LOAD_FAILED,		//!< Loading cache data failed.
} fr_tls_cache_load_state_t;

/** Current delete-state
 *
 * This tracks whether OpenSSL has requested that session data
 * be deleted.
 */
typedef enum {
	FR_TLS_CACHE_CLEAR_INIT = 0,		//!< Initial state.
	FR_TLS_CACHE_CLEAR_REQUESTED,		//!< OpenSSL has requested we delete a cache entry.
} fr_tls_cache_clear_state_t;

/** This structure holds the current cache state for the session
 *
 */
typedef struct {
	struct {
		fr_tls_cache_store_state_t	state;		//!< Tracks store state.
		SSL_SESSION			*sess;		//!< Session to store.
	} store;

	struct {
		fr_tls_cache_load_state_t	state;		//!< Tracks load requests from OpenSSL.
		uint8_t				*id;		//!< Session ID to load.
		SSL_SESSION			*sess;		//!< Deserialized session.
	} load;

	struct {
		fr_tls_cache_clear_state_t	state;		//!< Tracks delete requests from OpenSSL.
		uint8_t				*id;		//!< Session ID to be deleted.
	} clear;
} fr_tls_cache_t;

/** Is any cache operation still waiting to run?
 *
 * fr_tls_cache_pending_push() pushes one operation per call, and a load, a
 * clear and a store can all be queued at the same time.  A caller which drives
 * it therefore has to keep calling until nothing is left.  This says whether
 * anything is left.
 *
 * @param[in] tls_cache	to check, which may be NULL when caching is disabled.
 * @return
 *	- true if at least one operation is still queued.
 *	- false if there is nothing left to do.
 */
static inline bool fr_tls_cache_pending(fr_tls_cache_t const *tls_cache)
{
	if (!tls_cache) return false;

	return (tls_cache->load.state == FR_TLS_CACHE_LOAD_REQUESTED) ||
	       (tls_cache->clear.state == FR_TLS_CACHE_CLEAR_REQUESTED) ||
	       (tls_cache->store.state == FR_TLS_CACHE_STORE_REQUESTED);
}

#ifdef __cplusplus
}
#endif

#include "conf.h"
#include "session.h"

#ifdef __cplusplus
extern "C" {
#endif
uint8_t		*fr_tls_cache_id(TALLOC_CTX *ctx, SSL_SESSION *sess);

unlang_action_t	fr_tls_cache_pending_push(request_t *request, fr_tls_session_t *tls_session);

void		fr_tls_cache_deny(request_t *request, fr_tls_session_t *tls_session);

int		fr_tls_cache_disable_cb(SSL *ssl, int is_forward_secure);

void		fr_tls_cache_session_alloc(fr_tls_session_t *tls_session);

int		fr_tls_cache_ctx_init(SSL_CTX *ctx, fr_tls_cache_conf_t const *cache_conf, bool client);

unlang_action_t	fr_tls_cache_load_client_push(request_t *request, fr_tls_session_t *tls_session);

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
