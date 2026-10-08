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
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(cache_h, "$Id$")

#include "openssl_user_macros.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/** State of one cache operation
 *
 * All policy operations are run the same way.  OpenSSL asks us for
 * something via a callback, and the callback remembers to do it.
 * OpenSSL then returns to us, where then see that there's a policy to
 * be run, and run it.
 *
 * We can't run the interpreter from an OpenSSL callback, so we have
 * to do it via this "back and forth" bounce.
 *
 * Not every operation reaches every state.  A clear has nothing to report
 * back, so it only ever moves between INIT and REQUESTED.
 */
typedef enum {
	FR_TLS_TICKET_STATEFUL_INIT = 0,			//!< Nothing has been asked for.
	FR_TLS_TICKET_STATEFUL_REQUESTED,			//!< OpenSSL has asked for the operation, and the
						///< section which does the work has not run yet.
	FR_TLS_TICKET_STATEFUL_SUCCESS,			//!< The operation completed.  For a load that means
						///< the session came back from the data store, and for
						///< a store it means the session was persisted.
	FR_TLS_TICKET_STATEFUL_FAILED,			//!< The operation did not complete.
} fr_tls_ticket_stateful_state_t;

/** The current state of calling `encode session` or `decode session`
 *
 * A stateless session ticket encodes the contents of the `session-state` list.
 *
 * The `encode session` policy allows the admin to change the list
 * before the ticket is created.
 *
 * The `decode session` policy allows the admin to check the list
 * after a ticket has been received.
 */
typedef enum {
	FR_TLS_TICKET_STATELESS_INIT = 0,				//!< Nothing requested.
	FR_TLS_TICKET_STATELESS_ENCODE_REQUESTED,			//!< `encode session` needs to run.
	FR_TLS_TICKET_STATELESS_DECODE_REQUESTED,			//!< `decode session` needs to run.
	FR_TLS_TICKET_STATELESS_SUCCESS,				//!< The section ran and returned success.
	FR_TLS_TICKET_STATELESS_FAILED				//!< The section ran and did not.
} fr_tls_ticket_stateless_state_t;

/** This structure holds the current cache state for the session
 *
 */
typedef struct {
	struct {
		fr_tls_ticket_stateful_state_t		state;		//!< Tracks store state.
		fr_value_box_t			id;		//!< ID of the session being stored
		SSL_SESSION			*sess;		//!< Session to store.
	} store;

	struct {
		fr_tls_ticket_stateful_state_t		state;		//!< Tracks load requests from OpenSSL.
		fr_value_box_t			id;		//!< Session ID that the peer asked to resume
		SSL_SESSION			*sess;		//!< Deserialized session.
	} load;

	struct {
		fr_tls_ticket_stateful_state_t		state;		//!< Tracks delete requests from OpenSSL.
		fr_value_box_t			id;		//!< Session ID to clear
	} clear;

	fr_value_box_t const *session_id;      		//!< if set, points to tls_session->session_id
							///< sent by the peer in ClientHello.
							///< The various IDs above are _usually_ the same, but
							///< are not _always_ the same.

	bool		loaded;				//!< Whether `load session` ever returned a session.
							///< The load state above is reset as the handshake
							///< moves on, so it cannot answer this later.  A
							///< failed session is only worth clearing when a
							///< session was loaded, because `store session` is
							///< not run on failure, and `load session` does not
							///< remove what it read.
} fr_tls_ticket_stateful_t;

#ifdef _TLS_PRIVATE
/** Is any cache operation still waiting to run?
 *
 * The TLS library pushes one cache operation per call, but pushing a
 * clear will (eventually) cancel any pending load or store.  Return
 * whether there is a pending operation queued.
 *
 * @param[in] tls_cache	to check, which may be NULL when caching is disabled.
 * @return
 *	- true if at least one operation is queued.
 *	- false if there is nothing left to do.
 */
static inline bool fr_tls_ticket_stateful_pending(fr_tls_ticket_stateful_t const *tls_cache)
{
	if (!tls_cache) return false;

	return (tls_cache->load.state == FR_TLS_TICKET_STATEFUL_REQUESTED) ||
	       (tls_cache->clear.state == FR_TLS_TICKET_STATEFUL_REQUESTED) ||
	       (tls_cache->store.state == FR_TLS_TICKET_STATEFUL_REQUESTED);
}
#endif

#ifdef __cplusplus
}
#endif

#include "conf.h"
#include "session.h"

#ifdef __cplusplus
extern "C" {
#endif
/** Cache the session now that the application has decided it's OK.
 *
 * Just finishing the TLS handshake is not always enough.  EAP runs
 * inner methods inside of the TLS tunnel, and those methods can fail.
 * The cache operations are marked as pending during the handshake.
 * Calling this function tells the TLS state machine to actually store
 * the session.
 *
 * All queued cache operations run before this returns.  An
 * application MUST either call this function, or
 * fr_tls_session_fail_session().  Skipping these functions means that
 * either a good session isn't cached, or a bad session isn't cleared.
 * The TLS peer might then be able to resume the session.
 *
 * We don't allow applications to call any cache fail function.  That
 * is instead handled by fr_tls_session_fail_session().  That function
 * both calls `fail session`, and then (if needed) `clear session`.
 */
unlang_action_t	fr_tls_ticket_stateful_store_session(request_t *request, fr_tls_session_t *tls_session);

/*
 *	The only public function is fr_tls_ticket_stateful_store_session(),
 *	which is needed for EAP.  Other applications MUST instead call
 *	the various fr_session_*() functions.
 */
#ifdef _TLS_PRIVATE
void		tls_session_id_cache(fr_tls_session_t *tls_session, SSL_SESSION *sess);

request_t	*tls_subrequest_alloc(request_t *parent, uint32_t packet_type, fr_value_box_t const *id);

unlang_action_t	fr_tls_ticket_stateful_clear_session(request_t *request, fr_tls_session_t *tls_session);

int		fr_tls_ticket_disable_cb(SSL *ssl, int is_forward_secure);

void		fr_tls_ticket_stateful_session_alloc(fr_tls_session_t *tls_session);

int		fr_tls_ticket_ctx_init(SSL_CTX *ctx, fr_tls_ticket_conf_t const *cache_conf, bool client);

unlang_action_t	fr_tls_ticket_stateful_load_client_push(request_t *request, fr_tls_session_t *tls_session);

unlang_action_t	fr_tls_ticket_stateful_pending_push(request_t *request, fr_tls_session_t *tls_session);

unlang_action_t	fr_tls_ticket_stateless_pending_push(request_t *request, fr_tls_session_t *tls_session);
#endif

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
