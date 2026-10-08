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
 * @file lib/tls/ticket.h
 * @brief Session resumption, stateful and stateless
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(ticket_h, "$Id$")

#include "openssl_user_macros.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ticket_stateful.h"
#include "ticket_stateless.h"

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

/*
 *	The types above are what session.h needs.  The prototypes below need
 *	the types that conf.h and session.h define.
 */
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
/*
 *	ticket.c, shared by both kinds of resumption.
 */
void		tls_session_id_cache(fr_tls_session_t *tls_session, SSL_SESSION *sess);

request_t	*tls_subrequest_alloc(request_t *parent, uint32_t packet_type, fr_value_box_t const *id);

int		tls_ticket_id_to_box(TALLOC_CTX *ctx, fr_value_box_t *out, SSL_SESSION *sess);

int		tls_ticket_app_data_set(request_t *request, SSL_SESSION *sess, fr_value_box_t const *session_id);

int		tls_ticket_app_data_get(request_t *request, SSL_SESSION *sess, fr_value_box_t const *session_id);

fr_time_delta_t	tls_ticket_session_lifetime(request_t *request, fr_value_box_t const *session_id,
					    fr_tls_conf_t const *conf, SSL_SESSION *sess);

bool		tls_ticket_session_resumable(request_t *request, fr_value_box_t const *session_id,
					     fr_tls_conf_t const *conf, SSL_SESSION *sess);

int		fr_tls_ticket_disable_cb(SSL *ssl, int is_forward_secure);

int		fr_tls_ticket_ctx_init(SSL_CTX *ctx, fr_tls_ticket_conf_t const *cache_conf, bool client);

/*
 *	ticket_stateful.c
 */
unlang_action_t	fr_tls_ticket_stateful_clear_session(request_t *request, fr_tls_session_t *tls_session);

void		fr_tls_ticket_stateful_session_alloc(fr_tls_session_t *tls_session);

unlang_action_t	fr_tls_ticket_stateful_load_client_push(request_t *request, fr_tls_session_t *tls_session);

unlang_action_t	fr_tls_ticket_stateful_pending_push(request_t *request, fr_tls_session_t *tls_session);

void		fr_tls_ticket_stateful_disable(SSL_CTX *ctx);

void		fr_tls_ticket_stateful_ctx_init(SSL_CTX *ctx, fr_tls_ticket_conf_t const *cache_conf, bool client);

/*
 *	ticket_stateless.c
 */
unlang_action_t	fr_tls_ticket_stateless_pending_push(request_t *request, fr_tls_session_t *tls_session);

void		fr_tls_ticket_stateless_disable(SSL_CTX *ctx);

int		fr_tls_ticket_stateless_ctx_init(SSL_CTX *ctx, fr_tls_ticket_conf_t const *cache_conf);
#endif

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
