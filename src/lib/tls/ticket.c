/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 *
 * @file tls/ticket.c
 * @brief Functions shared by stateful and stateless TLS session resumption
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls"
#define _TLS_PRIVATE 1

#include <freeradius-devel/internal/internal.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/subrequest.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/protocol/tls/freeradius.h>

#include "attrs.h"
#include "base.h"
#include "ticket.h"
#include "log.h"
#include "strerror.h"
#include "verify.h"

#include <openssl/ssl.h>

/** Check if TLS caching is disabled.
 *
 * The TLS cache can be disabled for a host of reasons.  Using a macro
 * lets us check all of them at once:
 *
 * - there is no cache configuration
 * - there is no virtual_server to run when poking the cache
 *
 * This check is only for static configuration.  A particular session
 * can still be marked as !tls_session->allow_session_resumption.  In
 * which case we don't load any cache entries, but we may still clear
 * them.
 */

/** Copy the ID of a session into a box
 *
 * @param[in] ctx	to allocate the ID in.
 * @param[out] out	box to fill.  Left as-is when the session has no ID.
 * @param[in] sess	to retrieve the ID from.
 * @return
 *	- 0 on success.
 *	- -1 if the session had no ID.
 */
int tls_ticket_id_to_box(TALLOC_CTX *ctx, fr_value_box_t *out, SSL_SESSION *sess)
{
	unsigned int	len;
	uint8_t const	*id;

	id = SSL_SESSION_get_id(sess, &len);
	if (unlikely(!id)) return -1;

	MEM(fr_value_box_memdup(ctx, out, NULL, id, len, true) == 0);

	return 0;
}

/** Cache the ID of a session, if it is not cached already
 *
 * A session ID is fixed for the life of the session, so whichever code path
 * sees the session first records the ID, and everything after that logs the
 * cached copy instead of asking OpenSSL again.
 *
 * @param[in] tls_session	to cache the ID in.
 * @param[in] sess		to take the ID from.  May be NULL.
 */
void tls_session_id_cache(fr_tls_session_t *tls_session, SSL_SESSION *sess)
{
	if (!sess || !fr_type_is_null(tls_session->session_id.type)) return;

	if (tls_ticket_id_to_box(tls_session, &tls_session->session_id, sess) < 0) return;

	/*
	 *	Copy the ID to the cache, instead of pointing the cache at the session.
	 */
	if (tls_session->cache) tls_session->cache->session_id = &tls_session->session_id;
}

/** Allocate and initialize a subrequest for one of the TLS policy sections
 *
 * - allocate a subrequest
 * - set the packet type
 * - set the session ID
 *
 * @param[in] parent		both allocation context and holds the subrequest stack frame
 * @param[in] packet_type	which section to run, as an
 *				enum_tls_packet_type_* value.
 * @param[in] id		of the session, or #FR_TYPE_NULL when there is none.
 * @return the child request.
 */
request_t *tls_subrequest_alloc(request_t *parent, uint32_t packet_type, fr_value_box_t const *id)
{
	request_t *request;
	fr_pair_t *vp;

	MEM(request = unlang_subrequest_alloc(parent, dict_tls));

	/*
	 *	Setup the child request for the section being called.
	 */
	MEM(pair_prepend_request(&vp, attr_tls_packet_type) >= 0);
	vp->vp_uint32 = packet_type;

	/*
	 *	Add the session ID, if it exists.  A session gets an
	 *	ID only after it's established.  And it can fail
	 *	before then.  So the ID might not exist.
	 *
	 *	The ID is supplied by the peer, and is therefore
	 *	tainted.
	 */
	if (!fr_type_is_null(id->type)) {
		MEM(pair_append_request(&vp, attr_tls_session_id) >= 0);
		fr_pair_value_memdup(vp, id->vb_octets, id->vb_length, true);
	}

	return request;
}

/** Serialize the session-state list and store it in the SSL_SESSION *
 *
 */
int tls_ticket_app_data_set(request_t *request, SSL_SESSION *sess,
				  fr_value_box_t const *session_id)
{
	fr_dbuff_t		dbuff;
	fr_dbuff_uctx_talloc_t	tctx;
	fr_dcursor_t		dcursor;
	fr_pair_t		*vp;
	ssize_t			slen;
	int			ret;

	if (RDEBUG_ENABLED2) {
		RDEBUG2("Session ID %pV - Adding session-state[*] to data", session_id);
		RINDENT();
		log_request_pair_list(L_DBG_LVL_2, request, NULL, &request->session_state_pairs, NULL);
		REXDENT();
	}

	/*
	 *	Absolute maximum is `0..2^16-1`.
	 *
	 *	We leave OpenSSL 2k to add anything else
	 */
	MEM(fr_dbuff_init_talloc(NULL, &dbuff, &tctx, 1024, 1024 * 62));

	/*
	 *	Encode the session-state contents and add it to the ticket.
	 */
	for (vp = fr_pair_dcursor_init(&dcursor, &request->session_state_pairs);
	     vp;
	     vp = fr_dcursor_current(&dcursor)) {
		slen = fr_internal_encode_pair(&dbuff, &dcursor, NULL);
		if (slen < 0) {
			RPERROR("Session ID %pV - Failed serialising session-state list", session_id);
			fr_dbuff_free_talloc(&dbuff);
			return 0; /* didn't store data */
		}
		if (slen == 0) (void) fr_dcursor_next(&dcursor);
	}

	RHEXDUMP4(fr_dbuff_start(&dbuff), fr_dbuff_used(&dbuff), "session-ticket application data");

	/*
	 *	Pass the serialized session-state list
	 *	over to OpenSSL.
	 */
	ret = SSL_SESSION_set1_ticket_appdata(sess, fr_dbuff_start(&dbuff), fr_dbuff_used(&dbuff));
	fr_dbuff_free_talloc(&dbuff);	/* OpenSSL memdups the data */
	if (ret != 1) {
		fr_tls_log_perror(request, "Session ID %pV - Failed setting application data", session_id);
		return -1;
	}

	return 1;		/* successfully stored data */
}

int tls_ticket_app_data_get(request_t *request, SSL_SESSION *sess,
				  fr_value_box_t const *session_id)
{
	uint8_t			*data;
	size_t			data_len;
	fr_dbuff_t		dbuff;
	fr_pair_list_t		tmp;

	/*
	 *	Extract the session-state list from the ticket.
	 */
	if (SSL_SESSION_get0_ticket_appdata(sess, (void **)&data, &data_len) != 1) {
		fr_tls_log_perror(request, "Session ID %pV - Failed retrieving application data", session_id);
		return -1;
	}

	if (unlikely(!data)) {
		fr_tls_log_perror(request, "Session ID %pV - Got NULL session application data", session_id);
		return -1;
	}

	fr_pair_list_init(&tmp);
	fr_dbuff_init(&dbuff, data, data_len);

	RHEXDUMP4(fr_dbuff_start(&dbuff), fr_dbuff_len(&dbuff), "session application data");

	/*
	 *	Decode the session-state data into a temporary list.
	 *
	 *	It's very important that we decode _all_ attributes,
	 *	or disallow session resumption.
	 */
	while (fr_dbuff_remaining(&dbuff) > 0) {
		if (fr_internal_decode_pair_dbuff(request->session_state_ctx, &tmp,
						  fr_dict_root(request->proto_dict), &dbuff, NULL) < 0) {
			fr_pair_list_free(&tmp);
			RPEDEBUG("Session-ID %pV - Failed decoding session-state", session_id);
			fr_tls_session_error_add(request, FR_ERROR_VALUE_SESSION_DATA_DECODE_FAILED);
			return -1;
		}
	}

	if (RDEBUG_ENABLED2) {
		RDEBUG2("Session-ID %pV - Restoring session-state[*]", session_id);
		RINDENT();
		log_request_pair_list(L_DBG_LVL_2, request, NULL, &tmp, "session-state.");
		REXDENT();
	}

	fr_pair_list_append(&request->session_state_pairs, &tmp);

	return 0;
}

/** Enforce lifetime on a TLS session ticket.
 *
 * There are three limits, and we pick the lowest one.
 *
 * - the lifetime OpenSSL recorded in the session itself,
 * - `lifetime` from the configuration, so that a policy change reaches
 *   sessions which were stored before it,
 * - FR_TLS_MAX_SESSION_LIFETIME (7 days), which is required by RFC
 *   8446 for TLS and by RFC 9190 for EAP-TLS.
 *
 * @param[in] request		for logging.
 * @param[in] session_id	of the session, for logging.
 * @param[in] conf		holding the configured lifetime.
 * @param[in] sess		to examine.
 * @return
 *	- how long the session has left, if it is still live.
 *	- <= 0 if the session has expired.
 */
fr_time_delta_t tls_ticket_session_lifetime(request_t *request, fr_value_box_t const *session_id,
						  fr_tls_conf_t const *conf, SSL_SESSION *sess)
{
	time_t		timeout = SSL_get_timeout(sess);
	time_t		lifetime = (time_t) fr_time_delta_to_sec(conf->cache.lifetime);
	fr_time_t	expires;

	if (lifetime && (lifetime < timeout)) timeout = lifetime;

	if (timeout > FR_TLS_MAX_SESSION_LIFETIME) {
		RWDEBUG("Session ID %pV - Session lifetime %pV is longer than the maximum of %pV, limiting it",
			session_id, fr_box_time_delta(fr_time_delta_from_sec(timeout)),
			fr_box_time_delta(fr_time_delta_from_sec(FR_TLS_MAX_SESSION_LIFETIME)));

		timeout = FR_TLS_MAX_SESSION_LIFETIME;
	}

#if OPENSSL_VERSION_NUMBER >= 0x30400000L
	expires = fr_time_from_sec((time_t)(SSL_SESSION_get_time_ex(sess) + timeout));
#else
	expires = fr_time_from_sec((time_t)(SSL_SESSION_get_time(sess) + timeout));
#endif

	return fr_time_sub(expires, fr_time());
}

/** Is the session ticket resumable?
 *
 * If the ticket is close to expiry, then we just force a full
 * re-authentication.
 *
 * @param[in] request		to log through.
 * @param[in] session_id	of the session, for the log message.
 * @param[in] conf		holding `lifetime` and `min_lifetime`.
 * @param[in] sess		to examine.
 * @return
 *	- true if the session has at least `min_lifetime` left.
 *	- false if it has less, or has expired.
 */
bool tls_ticket_session_resumable(request_t *request, fr_value_box_t const *session_id,
					fr_tls_conf_t const *conf, SSL_SESSION *sess)
{
	fr_time_delta_t left = tls_ticket_session_lifetime(request, session_id, conf, sess);

	if (!fr_time_delta_ispos(left)) return false;

	if (fr_time_delta_lt(left, conf->cache.min_lifetime)) {
		RDEBUG2("Session ID %pV - %pV left is less than min_lifetime of %pV",
			session_id, fr_box_time_delta(left), fr_box_time_delta(conf->cache.min_lifetime));
		return false;
	}

	return true;
}

/** Prevent a TLS session from being resumed in future
 *
 * @note In OpenSSL > 1.1.0 this should not be called directly, but passed as a callback to
 *	SSL_CTX_set_not_resumable_session_callback.
 *
 * @param ssl			The current OpenSSL session.
 * @param is_forward_secure	Whether the cipher is forward secure, pass -1 if unknown.
 * @return
 *	- 0 if session-resumption is allowed.
 *	- 1 if enabling session-resumption was disabled for this session.
 */
int fr_tls_ticket_disable_cb(SSL *ssl, int is_forward_secure)
{
	request_t		*request;

	fr_tls_session_t	*tls_session;
	fr_pair_t		*vp;

	tls_session = fr_tls_session(ssl);
	request = fr_tls_session_request(tls_session->ssl);

	/*
	 *	Request was cancelled, try and get OpenSSL to
	 *	do as little work as possible.
	 */
	if (unlang_request_is_cancelled(request)) return 1;

	{
		fr_tls_conf_t *conf;

		conf = talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF), fr_tls_conf_t);
		if (conf->cache.require_extms && (SSL_get_extms_support(tls_session->ssl) == 0)) {
			RDEBUG2("Client does not support the Extended Master Secret extension, "
				"denying session resumption");
			goto disable;
		}

		if (conf->cache.require_pfs && !is_forward_secure) {
			RDEBUG2("Cipher suite is not forward secure, denying session resumption");
			goto disable;
		}
	}

	/*
	 *	If there's no session resumption, delete the entry
	 *	from the cache.  This means either it's disabled
	 *	globally for this SSL context, OR we were told to
	 *	disable it for this user.
	 *
	 *	This also means you can't turn it on just for one
	 *	user.
	 */
	if (!tls_session->allow_session_resumption) {
		RDEBUG2("Session resumption not enabled for this TLS session, denying session resumption");
		goto disable;
	}

	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_allow_session_resumption);
	if (vp && (vp->vp_uint32 == 0)) {
		RDEBUG2("control.Allow-Session-Resumption == no, denying session resumption");
	disable:
		SSL_CTX_remove_session(tls_session->ctx, tls_session->session);
		tls_session->allow_session_resumption = false;
		return 1;
	}

	RDEBUG2("Allowing future session-resumption");

	return 0;
}

/** Sets callbacks and flags on a SSL_CTX to enable/disable session resumption
 *
 * @param[in] ctx			to modify.
 * @param[in] cache_conf		Session caching configuration.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_tls_ticket_ctx_init(SSL_CTX *ctx, fr_tls_ticket_conf_t const *cache_conf, bool client)
{
	switch (cache_conf->mode) {
	case FR_TLS_TICKET_DISABLED:
		fr_tls_ticket_stateless_disable(ctx);
		fr_tls_ticket_stateful_disable(ctx);
		return 0;

	case FR_TLS_TICKET_AUTO:
	case FR_TLS_TICKET_STATEFUL:
		fr_tls_ticket_stateful_ctx_init(ctx, cache_conf, client);

		/*
		 *	Disables stateless session tickets for TLS 1.3.
		 */
		if (!(cache_conf->mode & FR_TLS_TICKET_STATELESS)) {
			fr_tls_ticket_stateless_disable(ctx);
			break;
		}
		FALL_THROUGH;

	case FR_TLS_TICKET_STATELESS:
	{
		/*
		 *	For stateless session tickets, the server
		 *	doesn't call `load session` or `store
		 *	session`.  Don't register those callbacks.
		 *
		 *	For stateless session tickets, the client has
		 *	to store the ticket somewhere, so that it's
		 *	read back on the next session.
		 *
		 *	The client therefore runs the `store session`
		 *	and `load session` policies, even for
		 *	stateless session resumption.
		 */
		if (!(cache_conf->mode & FR_TLS_TICKET_STATEFUL)) {
			if (!client) {
				fr_tls_ticket_stateful_disable(ctx);
			} else {
				fr_tls_ticket_stateful_ctx_init(ctx, cache_conf, client);
			}
		}

		if (fr_tls_ticket_stateless_ctx_init(ctx, cache_conf) < 0) return -1;
	}
		break;
	}

	SSL_CTX_set_not_resumable_session_callback(ctx, fr_tls_ticket_disable_cb);
	SSL_CTX_set_quiet_shutdown(ctx, 1);

	return 0;
}
#endif /* WITH_TLS */
