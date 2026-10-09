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
 * @file tls/ticket_stateful.c
 * @brief Stateful TLS session resumption, the session cache and its `load session`, `store session` and `clear session` sections
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
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/subrequest.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/protocol/tls/freeradius.h>

#include "attrs.h"
#include "base.h"
#include "log.h"
#include "strerror.h"
#include "ticket.h"
#include "verify.h"

#include <openssl/ssl.h>

#define TLS_TICKET_STATEFUL_DISABLED  (!tls_cache || !conf->virtual_server)

static inline CC_HINT(always_inline, nonnull(2))
void _tls_ticket_stateful_load_state_reset(request_t *request, fr_tls_ticket_stateful_t *cache, char const *func)
{
	if (cache->load.sess) {
		if (ROPTIONAL_ENABLED(RDEBUG_ENABLED3, DEBUG_ENABLED3)) {
			ROPTIONAL(RDEBUG3, DEBUG3, "Session ID %pV - Freeing loaded session in %s", cache->session_id, func);
		}

		SSL_SESSION_free(cache->load.sess);
		cache->load.sess = NULL;
	}
	cache->load.state = FR_TLS_TICKET_STATEFUL_INIT;
}
#define tls_ticket_stateful_load_state_reset(_request, _cache) _tls_ticket_stateful_load_state_reset(_request, _cache, __FUNCTION__)

static inline CC_HINT(always_inline, nonnull(2))
void _tls_ticket_stateful_store_state_reset(request_t *request, fr_tls_ticket_stateful_t *cache, char const *func)
{
	if (cache->store.sess) {
		if (ROPTIONAL_ENABLED(RDEBUG_ENABLED3, DEBUG_ENABLED3)) {
			ROPTIONAL(RDEBUG3, DEBUG3, "Session ID %pV - Freeing session to store in %s", &cache->store.id, func);
		}
		SSL_SESSION_free(cache->store.sess);
		cache->store.sess = NULL;
		fr_value_box_clear(&cache->store.id);
	}
	cache->store.state = FR_TLS_TICKET_STATEFUL_INIT;
}
#define tls_ticket_stateful_store_state_reset(_request, _cache) _tls_ticket_stateful_store_state_reset(_request, _cache, __FUNCTION__)

static inline CC_HINT(always_inline)
void _tls_ticket_stateful_clear_state_reset(request_t *request, fr_tls_ticket_stateful_t *cache, char const *func)
{
	if (!fr_type_is_null(cache->clear.id.type)) {
		if (ROPTIONAL_ENABLED(RDEBUG_ENABLED3, DEBUG_ENABLED3)) {
			ROPTIONAL(RDEBUG3, DEBUG3, "Session ID %pV - Freeing session ID to clear in %s",
				  &cache->clear.id, func);
		}
		fr_value_box_clear(&cache->clear.id);
	}
	cache->clear.state = FR_TLS_TICKET_STATEFUL_INIT;
}
#define tls_ticket_stateful_clear_state_reset(_request, _cache) _tls_ticket_stateful_clear_state_reset(_request, _cache, __FUNCTION__)

/** Request `load session { ... }`, and tell the handshake a cache section is pending
 */
static inline CC_HINT(always_inline) void tls_ticket_stateful_load_state_request(fr_tls_session_t *tls_session)
{
	tls_session->cache->load.state = FR_TLS_TICKET_STATEFUL_REQUESTED;
	TLS_PENDING_SET(tls_session, FR_TLS_PENDING_STATEFUL_TICKET);
}

/** Request `store session { ... }`, and tell the handshake a cache section is pending
 */
static inline CC_HINT(always_inline) void tls_ticket_stateful_store_state_request(fr_tls_session_t *tls_session)
{
	tls_session->cache->store.state = FR_TLS_TICKET_STATEFUL_REQUESTED;
	TLS_PENDING_SET(tls_session, FR_TLS_PENDING_STATEFUL_TICKET);
}

/** Request `clear session { ... }`, and tell the handshake a cache section is pending
 */
static inline CC_HINT(always_inline) void tls_ticket_stateful_clear_state_request(fr_tls_session_t *tls_session)
{
	tls_session->cache->clear.state = FR_TLS_TICKET_STATEFUL_REQUESTED;
	TLS_PENDING_SET(tls_session, FR_TLS_PENDING_STATEFUL_TICKET);
}

/** Delete session data be deleted from the cache
 *
 * @param[in] sess to be deleted.
 */
static void tls_ticket_stateful_delete_request(fr_tls_session_t *tls_session, SSL_SESSION *sess)
{
	fr_tls_ticket_stateful_t		*tls_cache;
	request_t		*request;

	if (!tls_session->cache) return;

	request = fr_tls_session_request(tls_session->ssl);
	tls_cache = tls_session->cache;

	/*
	 *	Request was cancelled just return without doing any work.
	 */
	if (unlang_request_is_cancelled(request)) return;

	fr_assert(tls_cache->clear.state == FR_TLS_TICKET_STATEFUL_INIT);

	/*
	 *	Record the session to delete
	 */
	if (tls_ticket_id_to_box(tls_cache, &tls_cache->clear.id, sess) < 0) {
		RWDEBUG("Error retrieving Session ID");
		return;
	}

	RDEBUG3("Session ID %pV - Requested session clear", &tls_cache->clear.id);

	tls_ticket_stateful_clear_state_request(tls_session);

	/*
	 *	Reset any pending `store session`, so that we skip
	 *	unnecessary work.
	 */
	tls_ticket_stateful_store_state_reset(request, tls_cache);

	/*
	 *	We _usually_ store a copy of the SSL_SESSION in tls_session->session.  If the
	 *	session is being freed, then we invalidate the cached SSL_SESSION.  Note that
	 *	tls_session->session can be NULL sometimes, see tls_ticket_stateful_delete_cb().
	 *
	 *	In any case, if the SSL_SESSION pointer exists, we clear it here to avoid leaving a dangling
	 *	pointer.
	 */
	if (tls_session->session) {
		fr_assert(tls_session->session == sess);
		tls_session->session = NULL;
	}

	/*
	 *	Previously the code called ASYNC_pause_job();
	 *	assuming this callback would always be called
	 *	from SSL_read() or another SSL function.
	 *
	 *	Unfortunately it appears that the call path
	 *	can also be triggered with SSL_CTX_remove_session
	 *	if the reference count on the SSL_SESSION
	 *	drops to zero.
	 *
	 *	We now check the 'can_pause' flag to determine
	 *	if we're inside a yieldable SSL_read call.
	 */
	if (tls_session->can_pause) ASYNC_pause_job();
}

/** Process the result of `load session { ... }`
 */
static unlang_action_t tls_ticket_stateful_load_resume(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_tls_ticket_stateful_t		*tls_cache = tls_session->cache;
	fr_pair_t		*vp;
	uint8_t const		*q, **p;
	SSL_SESSION		*sess;

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_tls_packet_type);
	if (!vp || (vp->vp_uint32 != enum_tls_packet_type_success->vb_uint32)) {
		RWDEBUG("Failed acquiring session data");

		/*
		 *	A cache miss answers `notfound`, and a miss is the
		 *	normal answer on a first connection.  Recording it as
		 *	a failure would put an `Error` in the session-state
		 *	list of every healthy handshake.
		 */
		fr_tls_session_error_add(request->parent,
					 (vp && (vp->vp_uint32 == enum_tls_packet_type_notfound->vb_uint32)) ?
					 FR_ERROR_VALUE_LOAD_SESSION_NOT_FOUND :
					 FR_ERROR_VALUE_LOAD_SESSION_FAILED);
	error:
		tls_cache->load.state = FR_TLS_TICKET_STATEFUL_FAILED;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_tls_session_data);
	if (!vp) {
		RWDEBUG("No cached session found");
		fr_tls_session_error_add(request->parent, FR_ERROR_VALUE_LOAD_SESSION_NOT_FOUND);
		goto error;
	}

	q = vp->vp_octets;	/* openssl will mutate q, so we can't use vp_octets directly */
	p = (unsigned char const **)&q;

	sess = d2i_SSL_SESSION(NULL, p, vp->vp_length);
	if (!sess) {
		fr_tls_log_perror(request, "Failed loading persisted session");
		fr_tls_session_error_add(request->parent, FR_ERROR_VALUE_LOAD_SESSION_MALFORMED);
		goto error;
	}

	tls_session_id_cache(tls_session, sess);		/* the client path has no ID until now */

	if (RDEBUG_ENABLED3) {
		RDEBUG3("Session ID %pV - Read %zu bytes of data.  "
			"Session de-serialized successfully", &tls_session->session_id, vp->vp_length);
		SSL_SESSION_print(fr_tls_request_log_bio(request, L_DBG, L_DBG_LVL_3), sess);
	}

	/*
	 *	Enforce session timeouts.  We don't resume sessions which have exceeded their lifetime.
	 *
	 *	The lifetime is already enforced for `store session`.  The session may exist on disk (or in a
	 *	DB) for long enough that it expires.
	 *
	 *	tls_ticket_session_lifetime() clamps to the lowest of the session's own lifetime, the
	 *	configured `lifetime`, and the RFC maximum.  Clamping to the configured value is what lets
	 *	a policy update reach sessions which were stored before it.
	 */
	{
		fr_tls_conf_t	*conf = tls_session->conf;

		if (!tls_ticket_session_resumable(request, &tls_session->session_id, conf, sess)) {
			RWDEBUG("Session ID %pV - Cached session has too little life left, not resuming",
				&tls_session->session_id);
			fr_tls_session_error_add(request, FR_ERROR_VALUE_LOAD_SESSION_EXPIRED);

			/*
			 *	The session was allocated by d2i_SSL_SESSION(), and it is not yet saved in
			 *	tls_cache->load.sess.  We're the only one who knows about it, so we have to
			 *	free it.
			 */
			SSL_SESSION_free(sess);
			goto error;
		}
	}

	/*
	 *	OpenSSL's API is very inconsistent.
	 *
	 *	We need to set external data here, so it can be
	 *	retrieved in tls_ticket_stateful_delete_cb().
	 *
	 *	ex_data is not serialised in i2d_SSL_SESSION
	 *	so we don't have to bother unsetting it.
	 */
	SSL_SESSION_set_ex_data(sess, fr_tls_session_ex_index, fr_tls_session(tls_session->ssl));

	tls_cache->load.state = FR_TLS_TICKET_STATEFUL_SUCCESS;
	tls_cache->load.sess = sess;	/* This is consumed in tls_ticket_stateful_load_cb */

	/*
	 *	Remember that we loaded an entry from the session
	 *	cache.  If the session eventually fails, we then know
	 *	that we have to remove the failed cache entry.
	 */
	tls_cache->loaded = true;

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Push a `load session { ... }` call into the current request, using a subrequest
 *
 * @param[in] request		The current request.
 * @param[in] tls_session	The current TLS session.
 * @return
 *      - UNLANG_ACTION_CALCULATE_RESULT on noop.
 *	- UNLANG_ACTION_PUSHED_CHILD on success.
 *      - UNLANG_ACTION_FAIL on failure.
 */
static unlang_action_t tls_ticket_stateful_load_push(request_t *request, fr_tls_session_t *tls_session)
{
	fr_tls_ticket_stateful_t		*tls_cache = tls_session->cache;
	fr_tls_conf_t		*conf = tls_session->conf;
	request_t		*child;
	unlang_action_t		ua;

	if (TLS_TICKET_STATEFUL_DISABLED) return UNLANG_ACTION_CALCULATE_RESULT;

	if (tls_cache->load.state != FR_TLS_TICKET_STATEFUL_REQUESTED) return UNLANG_ACTION_CALCULATE_RESULT;

	/*
	 *	Reset any pending `load session` if there is also a
	 *	pending `clear session`, and mark up the load as failed.
	 *
	 *	The load is stuck in an async callback via
	 *	ASYNC_pause_job(), so we can't reset the load state
	 *	here.  When it runs, the callback sees that the load
	 *	failed, tells OpenSSL that there is no session, and the
	 *	peer does a full handshake instead.
	 */
	if (tls_cache->clear.state == FR_TLS_TICKET_STATEFUL_REQUESTED) {
		RDEBUG3("Session ID %pV - Clear is pending, skipping `load session { ... }`",
			&tls_cache->load.id);
		tls_cache->load.state = FR_TLS_TICKET_STATEFUL_FAILED;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	fr_assert(!fr_type_is_null(tls_cache->load.id.type));

	MEM(child = tls_subrequest_alloc(request, enum_tls_packet_type_load_session->vb_uint32,
					 &tls_cache->load.id));

	/*
	 *	Allocate a child, and set it up to call
	 *      the TLS virtual server.
	 */
	ua = fr_tls_call_push(child, tls_ticket_stateful_load_resume, conf, tls_session, true);
	if (ua == UNLANG_ACTION_FAIL) {
		talloc_free(child);
		tls_ticket_stateful_load_state_reset(request, tls_cache);
		return UNLANG_ACTION_FAIL;
	}

	return ua;
}

/** Process the result of `store session { ... }`
 */
static unlang_action_t tls_ticket_stateful_store_resume(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_tls_ticket_stateful_t		*tls_cache = tls_session->cache;
	fr_pair_t		*vp;

	tls_ticket_stateful_store_state_reset(request, tls_cache);

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_tls_packet_type);
	if (vp && (vp->vp_uint32 == enum_tls_packet_type_success->vb_uint32)) {
		tls_cache->store.state = FR_TLS_TICKET_STATEFUL_SUCCESS;	/* Avoid spurious clear calls */
	} else {
		RWDEBUG("Failed storing session data");
		fr_tls_session_error_add(request->parent, FR_ERROR_VALUE_STORE_SESSION_FAILED);
		tls_cache->store.state = FR_TLS_TICKET_STATEFUL_INIT;
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Push a `store session { ... }` call into the current request, using a subrequest
 *
 * @param[in] request		The current request.
 * @param[in] conf		TLS configuration.
 * @param[in] tls_session	The current TLS session.
 * @return
 *      - UNLANG_ACTION_CALCULATE_RESULT on noop.
 *	- UNLANG_ACTION_PUSHED_CHILD on success.
 *      - UNLANG_ACTION_FAIL on failure.
 */
static inline CC_HINT(always_inline)
unlang_action_t tls_ticket_stateful_store_push(request_t *request, fr_tls_conf_t *conf, fr_tls_session_t *tls_session)
{
	fr_tls_ticket_stateful_t		*tls_cache = tls_session->cache;
	size_t			len, ret;
	int			rcode;

	uint8_t			*p, *data = NULL;

	request_t		*child;
	fr_pair_t		*vp;
	SSL_SESSION		*sess = tls_session->cache->store.sess;
	unlang_action_t		ua;
	fr_time_delta_t		ttl;

	if (TLS_TICKET_STATEFUL_DISABLED) return UNLANG_ACTION_CALCULATE_RESULT;

	fr_assert(tls_cache->store.sess);
	fr_assert(tls_cache->store.state == FR_TLS_TICKET_STATEFUL_REQUESTED);

	/*
	 *	If there's a pending clear, then don't push any load /
	 *	save / etc.  This isn't strictly necessary, but is
	 *	good "defense in depth" for any future code changes.
	 *	It also documents / enforces our expectations.
	 */
	if (tls_cache->clear.state == FR_TLS_TICKET_STATEFUL_REQUESTED) {
		RWDEBUG("Session ID %pV - Clear is pending, not storing", &tls_cache->store.id);
		fr_tls_session_error_add(request, FR_ERROR_VALUE_STORE_CANCELLED_BY_CLEAR);
		tls_ticket_stateful_store_state_reset(request, tls_cache);
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	ttl = tls_ticket_session_lifetime(request, &tls_cache->store.id, conf, sess);
	if (!fr_time_delta_ispos(ttl)) {
		RWDEBUG("Session ID %pV - Session has already expired, not storing", &tls_cache->store.id);
		fr_tls_session_error_add(request, FR_ERROR_VALUE_STORE_SESSION_EXPIRED);
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Add the current session-state list
	 *	contents to the ssl-data
	 */
	rcode = tls_ticket_app_data_set(request, sess, &tls_cache->store.id);
	if (rcode < 0) {
		tls_ticket_stateful_store_state_reset(request, tls_cache);
		return UNLANG_ACTION_FAIL;
	}

	if (rcode == 0) return UNLANG_ACTION_CALCULATE_RESULT;

	MEM(child = tls_subrequest_alloc(request, enum_tls_packet_type_store_session->vb_uint32,
					 &tls_cache->store.id));
	request = child;

	/*
	 *	How long the session has to live.  Already clamped, the RFC
	 *	maximum included, by tls_ticket_session_lifetime() above.
	 */
	MEM(pair_update_request(&vp, attr_tls_session_ttl) >= 0);
	vp->vp_time_delta = ttl;

	/*
	 *	Serialize the session
	 */
	ret = i2d_SSL_SESSION(sess, NULL);	/* find out what length data we need */
	if (ret < 1) {
		/* something went wrong */
		fr_tls_strerror_printf(NULL);	/* Drain the OpenSSL error stack */
		RPWDEBUG("Session ID %pV - Serialisation failed, couldn't determine "
			 "required buffer length", &tls_cache->store.id);
	error:
		tls_ticket_stateful_store_state_reset(request, tls_cache);
		talloc_free(child);
		return UNLANG_ACTION_FAIL;
	}
	len = ret;

	MEM(pair_update_request(&vp, attr_tls_session_data) >= 0);
	MEM(data = talloc_array(vp, uint8_t, len));

	/* openssl mutates &p */
	p = data;
	ret = i2d_SSL_SESSION(sess, &p);	/* Serialize as ASN.1 */
	if (ret != len) {
		fr_tls_strerror_printf(NULL);	/* Drain the OpenSSL error stack */
		RPWDEBUG("Session ID %pV - Serialisation failed", &tls_cache->store.id);
		talloc_free(data);
		goto error;
	}
	fr_pair_value_memdup_buffer_shallow(vp, data, true);

	/*
	 *	Allocate a child, and set it up to call
	 *      the TLS virtual server.
	 */
	ua = fr_tls_call_push(child, tls_ticket_stateful_store_resume, conf, tls_session, true);
	if (ua == UNLANG_ACTION_FAIL) goto error;

	return ua;
}

/** Process the result of `clear session { ... }`
 */
static unlang_action_t tls_ticket_stateful_clear_resume(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_tls_ticket_stateful_t		*tls_cache = tls_session->cache;
	fr_pair_t		*vp;

	tls_ticket_stateful_clear_state_reset(request, tls_cache);

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_tls_packet_type);
	if (vp &&
	    ((vp->vp_uint32 == enum_tls_packet_type_success->vb_uint32) ||
	     (vp->vp_uint32 == enum_tls_packet_type_notfound->vb_uint32))) {
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	RWDEBUG("Failed deleting session data - security may be compromised");
	fr_tls_session_error_add(request->parent, FR_ERROR_VALUE_CLEAR_SESSION_FAILED);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Push a `clear session { ... }` call into the current request, using a subrequest
 *
 * @param[in] request		The current request.
 * @param[in] conf		TLS configuration.
 * @param[in] tls_session	The current TLS session.
 * @return
 *      - UNLANG_ACTION_CALCULATE_RESULT on noop.
 *	- UNLANG_ACTION_PUSHED_CHILD on success.
 *      - UNLANG_ACTION_FAIL on failure.
 */
static inline CC_HINT(always_inline)
unlang_action_t tls_ticket_stateful_clear_push(request_t *request, fr_tls_conf_t *conf, fr_tls_session_t *tls_session)
{
	request_t	*child;
	fr_tls_ticket_stateful_t	*tls_cache = tls_session->cache;
	unlang_action_t	ua;

	if (TLS_TICKET_STATEFUL_DISABLED) return UNLANG_ACTION_CALCULATE_RESULT;

	fr_assert(tls_cache->clear.state == FR_TLS_TICKET_STATEFUL_REQUESTED);
	fr_assert(!fr_type_is_null(tls_cache->clear.id.type));

	MEM(child = tls_subrequest_alloc(request, enum_tls_packet_type_clear_session->vb_uint32,
					 &tls_cache->clear.id));

	/*
	 *	Allocate a child, and set it up to call
	 *      the TLS virtual server.
	 */
	ua = fr_tls_call_push(child, tls_ticket_stateful_clear_resume, conf, tls_session, true);
	if (ua == UNLANG_ACTION_FAIL) {
		talloc_free(child);
		tls_ticket_stateful_clear_state_reset(request, tls_cache);
		return UNLANG_ACTION_FAIL;
	}

	return ua;
}

/** Process the result of a client's `load session { ... }` call
 *
 * A client hands the session to OpenSSL before the handshake starts.  The
 * server path differs: OpenSSL hands a server the session ID part way through
 * a handshake, and the server returns the matching session.
 */
static unlang_action_t tls_ticket_stateful_load_client_resume(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_tls_ticket_stateful_t		*tls_cache = tls_session->cache;

	(void) tls_ticket_stateful_load_resume(request, uctx);

	if (tls_cache->load.state != FR_TLS_TICKET_STATEFUL_SUCCESS) {
		RDEBUG2("No session to resume");
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	if (SSL_set_session(tls_session->ssl, tls_cache->load.sess) != 1) {
		fr_tls_log_perror(request, "Failed setting the session to resume");
		tls_ticket_stateful_load_state_reset(request, tls_cache);
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	RDEBUG2("Offering the cached session for resumption");

	/*
	 *	SSL_set_session() takes its own reference, and nothing else
	 *	consumes this one, unlike the server path where the session is
	 *	handed back to OpenSSL from tls_ticket_stateful_load_cb.
	 */
	tls_ticket_stateful_load_state_reset(request, tls_cache);

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Ask the virtual server for a session to resume, as a client
 *
 * Call this before the handshake starts.  A client chooses which session to
 * offer, so the client looks a session up under a key the client already
 * knows, the expansion of `session { name = ... }`.  A server makes no such
 * choice.  OpenSSL hands the server the session ID the peer asked for, so the
 * server path lives in tls_ticket_stateful_load_cb().
 *
 * The policy decides what the key means.  `TLS-Session-Id` holds the expanded
 * name, and the `load session { ... }` section may look the session up by
 * `TLS-Session-Id`, or by any other attribute in the request.
 *
 * @param[in] request		The current request.
 * @param[in] tls_session	The current TLS session.
 * @return
 *	- UNLANG_ACTION_CALCULATE_RESULT if there is nothing to do.
 *	- UNLANG_ACTION_PUSHED_CHILD on success.
 *	- UNLANG_ACTION_FAIL on failure.
 */
unlang_action_t fr_tls_ticket_stateful_load_client_push(request_t *request, fr_tls_session_t *tls_session)
{
	fr_tls_ticket_stateful_t		*tls_cache = tls_session->cache;
	fr_tls_conf_t		*conf = tls_session->conf;
	char			*name;
	request_t		*child;
	unlang_action_t		ua;

	if (TLS_TICKET_STATEFUL_DISABLED) return UNLANG_ACTION_CALCULATE_RESULT;
	if (!tls_session->allow_session_resumption) return UNLANG_ACTION_CALCULATE_RESULT;

	fr_assert(conf->cache.id_name);

	if (tmpl_aexpand(tls_session, &name, request, conf->cache.id_name, NULL, NULL) < 0) {
		RPEDEBUG("Failed expanding the session name");
		return UNLANG_ACTION_FAIL;
	}

	MEM(child = tls_subrequest_alloc(request, enum_tls_packet_type_load_session->vb_uint32,
					 fr_box_octets((uint8_t const *) name, talloc_strlen(name))));

	talloc_free(name);

	ua = fr_tls_call_push(child, tls_ticket_stateful_load_client_resume, conf, tls_session, true);
	if (ua == UNLANG_ACTION_FAIL) {
		talloc_free(child);
		return UNLANG_ACTION_FAIL;
	}

	return ua;
}

/** Push a `store session { ... }` or `clear session { ... }` or `load session { ... }`
 *
 * Depending on what operation is needed.
 *
 * @param[in] request		The current request.
 * @param[in] tls_session	The current TLS session.
 * @return
 *	- UNLANG_ACTION_CALCULATE_RESULT	- No pending actions
 *	- UNLANG_ACTION_PUSHED_CHILD		- Pending operations to evaluate.
 */
unlang_action_t fr_tls_ticket_stateful_pending_push(request_t *request, fr_tls_session_t *tls_session)
{
	fr_tls_ticket_stateful_t *tls_cache = tls_session->cache;
	fr_tls_conf_t *conf = tls_session->conf;
	unlang_action_t ua;

	if (!tls_cache) return UNLANG_ACTION_CALCULATE_RESULT;	/* No caching allowed, nothing to discard */

	/*
	 *	The caller is asking us to push load / store / etc.  Since the cache is disabled, we just
	 *	reset the state (and free resources), then return.  The callers can then check
	 *	fr_tls_ticket_stateful_pending(), which will now return "nope".
	 */
	if (TLS_TICKET_STATEFUL_DISABLED) {
		if (tls_cache->load.state == FR_TLS_TICKET_STATEFUL_REQUESTED) {
			tls_ticket_stateful_load_state_reset(request, tls_cache);
		}
		if (tls_cache->clear.state == FR_TLS_TICKET_STATEFUL_REQUESTED) {
			tls_ticket_stateful_clear_state_reset(request, tls_cache);
		}
		if (tls_cache->store.state == FR_TLS_TICKET_STATEFUL_REQUESTED) {
			tls_ticket_stateful_store_state_reset(request, tls_cache);
		}
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Load stateful session data.
	 *
	 *	tls_ticket_stateful_load_push() may return
	 *	UNLANG_ACTION_CALCULATE_RESULT there's a pending
	 *	`clear session`.  When that happens, we skip the load,
	 *	and run the clear instead.
	 */
	if (tls_cache->load.state == FR_TLS_TICKET_STATEFUL_REQUESTED) {
		ua = tls_ticket_stateful_load_push(request, tls_session);
		if (ua != UNLANG_ACTION_CALCULATE_RESULT) return ua;
	}

	/*
	 *	We only support a single session
	 *	ticket currently...
	 */
	if (tls_cache->clear.state == FR_TLS_TICKET_STATEFUL_REQUESTED) {
		/*
		 *	Enforce that there's no queued store, as it
		 *	should have been cancelled.
		 */
		fr_assert(tls_cache->store.state != FR_TLS_TICKET_STATEFUL_REQUESTED);
		tls_ticket_stateful_store_state_reset(request, tls_cache);

		return tls_ticket_stateful_clear_push(request, conf, tls_session);
	}

	if (tls_cache->store.state == FR_TLS_TICKET_STATEFUL_REQUESTED) {
		return tls_ticket_stateful_store_push(request, conf, tls_session);
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Run all queued cache operations
 *
 * Multiple operations may be pushed at the same time.  We set
 * ourselves as the resume function before each push, so that when the
 * queued operation is done, we can check for another one, and run it.
 *
 * @param[in] request		to run the cache sections in.
 * @param[in] uctx		the #fr_tls_session_t whose queued operations to run.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD	- a cache section is running.
 *	- UNLANG_ACTION_CALCULATE_RESULT - no operation is left.
 */
static unlang_action_t tls_ticket_stateful_drain(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	unlang_action_t		ua;

	if (!fr_tls_ticket_stateful_pending(tls_session->cache)) return UNLANG_ACTION_CALCULATE_RESULT;

	/*
	 *	Set our repeat before any child is pushed.
	 */
	if (unlikely(unlang_function_repeat_set(request, tls_ticket_stateful_drain) < 0)) return UNLANG_ACTION_FAIL;

	ua = fr_tls_ticket_stateful_pending_push(request, tls_session);
	if (ua == UNLANG_ACTION_PUSHED_CHILD) return ua;

	/*
	 *	We didn't push anything.  Clear the repeat.
	 */
	IGNORE(unlang_function_clear(request), int);

	/*
	  *	On error, log the failure and continue.
	 */
	if (ua == UNLANG_ACTION_FAIL) {
		RERROR("Failed running session cache operations");
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	return ua;
}

/** Push a frame which runs every queued cache operation
 *
 * @param[in] request		to run the cache sections in.
 * @param[in] tls_session	whose queued operations to run.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD	- the queued operations are running.
 *	- UNLANG_ACTION_CALCULATE_RESULT - no operation was queued.
 *	- UNLANG_ACTION_FAIL		- the frame could not be pushed.
 */
static unlang_action_t tls_ticket_stateful_drain_push(request_t *request, fr_tls_session_t *tls_session)
{
	if (!fr_tls_ticket_stateful_pending(tls_session->cache)) return UNLANG_ACTION_CALCULATE_RESULT;

	return unlang_function_push(request, tls_ticket_stateful_drain, NULL, NULL, 0, UNLANG_SUB_FRAME, tls_session);
}

/** Store a session after a successful authentication
 *
 * Remember to run `store session { ... }`.
 *
 * Just finishing the TLS handshake is not always enough.  EAP runs
 * inner methods inside of the TLS tunnel which can fail.  So we only
 * run `store session` after the inner method succeeds.
 *
 * @note The caller MUST set the caller's own unlang result before calling
 *	 fr_tls_ticket_stateful_store_session().  A pushed child returns to the caller's
 *	 caller with that result already in place.
 *
 * @param[in] request		to run the cache sections in.
 * @param[in] tls_session	to keep.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD	- cache sections are running.
 *	- UNLANG_ACTION_CALCULATE_RESULT - there was nothing to do.
 *	- UNLANG_ACTION_FAIL		- the frame could not be pushed.
 */
unlang_action_t fr_tls_ticket_stateful_store_session(request_t *request, fr_tls_session_t *tls_session)
{
	return tls_ticket_stateful_drain_push(request, tls_session);
}

/** Clear a session after a failed authentication
 *
 * Cancels any pending `store session`, and if necessary, remember to run `clear session { ... }` as the
 * session might have been loaded from the cache.
 *
 * @note The caller MUST set the caller's own unlang result before calling
 *	 fr_tls_ticket_stateful_clear_session().  A pushed child returns to the
 *	 caller's caller with that result already in place.
 *
 * @param[in] request		to run the cache sections in.
 * @param[in] tls_session	to discard.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD	- cache sections are running.
 *	- UNLANG_ACTION_CALCULATE_RESULT - there was nothing to do.
 *	- UNLANG_ACTION_FAIL		- the frame could not be pushed.
 */
unlang_action_t fr_tls_ticket_stateful_clear_session(request_t *request, fr_tls_session_t *tls_session)
{
	fr_tls_ticket_stateful_t *tls_cache = tls_session->cache;
	bool bound;

	/*
	 *	No caching allowed, so there is nothing to deny, and
	 *	nothing to clear.
	 */
	if (!tls_cache) return UNLANG_ACTION_CALCULATE_RESULT;

	bound = fr_tls_session_request_bound(tls_session->ssl);

	/*
	 *	This is necessary to allow this function to
	 *	be called inside and outside of OpenSSL handshake
	 *	code.
	 */
	if (!bound) {
		fr_tls_session_request_bind(tls_session->ssl, request);

	} else {
		/*
		 *	If there's already a request bound, it better be
		 *      the one passed to this function.
		 */
		fr_assert(fr_tls_session_request(tls_session->ssl) == request);
	}

	/*
	 *	SSL_CTX_remove_session() frees the previously loaded session in tls_session. If the reference
	 *	count reaches zero the SSL_CTX_sess_remove_cb is called, which in our code is
	 *	tls_ticket_stateful_delete_cb.  HOWEVER, we've already set SSL_SESS_CACHE_NO_INTERNAL, which means that
	 *	SSL_CTX_remove_session() largely does nothing, and skips our callback.  These checks are
	 *	largely for paranoia, just in case the internal OpenSSL cache is somehow re-enabled.
	 *
	 *	tls_ticket_stateful_delete_cb calls tls_ticket_stateful_delete_request to record the ID of tls_session->session in
	 *	our pending cache state structure.
	 *
	 *	tls_ticket_stateful_delete_request does NOT immediately call `clear session {}` as that must
	 *	be done in a code area which can return a yield to the interpreter.
	 */
	if (tls_session->session) {
		SSL_CTX_remove_session(tls_session->ctx, tls_session->session);

		/*
		 *	Manually call tls_ticket_stateful_delete_request(), just in case.  That function clears
		 *	tls_session->session, so it's idempotent.  It clears tls_session->session, so it's
		 *	safe to call twice.  If it's called via the above path, then it clears the session
		 *	pointer, which means that we don't call it again.
		 */
		if (tls_session->session && tls_cache->loaded) tls_ticket_stateful_delete_request(tls_session, tls_session->session);
	}
	tls_session->allow_session_resumption = false;

	/*
	 *	Clear any pending store requests.
	 */
	tls_ticket_stateful_store_state_reset(request, tls_cache);

	/*
	 *	The request wasn't bound when we were called, so unbind it now.
	 */
	if (!bound) fr_tls_session_request_unbind(tls_session->ssl);

	return tls_ticket_stateful_drain_push(request, tls_session);
}

/** Write a newly created session data to the tls_session->cache structure
 *
 * @note If you hit an assert in this function, it was likely called twice, which shouldn't happen
 *	so blame OpenSSL.
 *
 * @param[in] ssl session state.
 * @param[in] sess to serialise and write to the cache.
 * @return
 *	- 1.  What we return is not used by OpenSSL to indicate success
 *	or failure, but to indicate whether it should free its copy of
 *	the session data.
 *	In this case we tell it not to free the session data, as we
 */
static int tls_ticket_stateful_store_cb(SSL *ssl, SSL_SESSION *sess)
{
	request_t		*request;
	fr_tls_session_t	*tls_session;
	fr_tls_ticket_stateful_t		*tls_cache;

	/*
	 *	This functions should only be called once during the lifetime
	 *	of the tls_session, as the fields aren't re-populated on
	 *	resumption.
	 */
	tls_session = fr_tls_session(ssl);
	request = fr_tls_session_request(tls_session->ssl);

	/*
	 *	RFC 8446 Section 4.6.1 lets a TLS 1.3 server send NewSessionTicket at any point after its
	 *	Finished message, including part way through application data.  We do not support that.
	 *
	 *	Once application data is moving, we discard any session tickets that we receive.  TLS doesn't
	 *	require us to do this, but we don't know what else to do.  The application is processing it's
	 *	data, and we do not (as yet) have the code to pause the application, and run a subrequest to
	 *	store the new ticket.
	 *
	 *	The current implementation runs the cache sections from the handshake, which is the only place
	 *	the interpreter can yield.  tls_ticket_stateful_store_cb() reaches them through ASYNC_pause_job(), and
	 *	that is only legal while tls_session->can_pause is set.  Fixing this is an issue for the
	 *	future.
	 *
	 *	One possible solution is to spawn a _detached_ subrequest which processes the ticket, and only
	 *	the ticket.  This has to be a subrequest in order to avoid confusing the main application
	 *	request (and state machine) with TLS data.  We don't care if the `store session` succeeded or
	 *	failed, because there's nothing we can really do with that result.  The connection is likely
	 *	to stay up, so we might as well just ignore errors on `store session`.
	 *
	 *	For those reasons and more, we just discard the session ticket.  All this means is that the
	 *	peer (client here) is unable to use that ticket for session resumption.
	 */
	if (tls_session->seen_application_data) {
		ROPTIONAL(RDEBUG2, DEBUG2,
			  "Ignoring session ticket received after application data started");
		return 0;
	}

	/*
	 *	We have a session ticket.  See fr_tls_session_is_init_finished()
	 */
	tls_session->session_ticket_received = true;

	/*
	 *	A server sees this callback once, before anything else has
	 *	recorded a session.
	 *
	 *	A client has already recorded one: SSL_get_session() runs
	 *	when OpenSSL finishes the handshake, which is before the
	 *	NewSessionTicket arrives here.  The ticket's session is the
	 *	one worth keeping, because it is what the client offers
	 *	back, so it supersedes.
	 */
	fr_assert(!tls_session->session || !SSL_is_server(ssl));
	tls_session->session = sess;
	tls_session_id_cache(tls_session, sess);

	tls_cache = tls_session->cache;

	fr_assert(tls_cache);
	fr_assert(tls_session->conf->virtual_server);

	/*
	 *	Request was cancelled, just get OpenSSL to
	 *	free the session data, and don't do any work.
	 */
	if (unlang_request_is_cancelled(request)) return 0;

	/*
	 *	Take a copy of the ID, because "return 0" tells
	 *	OpenSSL that it can delete the session.  Which means
	 *	that the cached pointer to the session ID could be
	 *	freed.
	 *
	 *	We may need to use the ID in the `store session` even
	 *	after the session is gone.
	 */
	if (tls_ticket_id_to_box(tls_cache, &tls_cache->store.id, sess) < 0) {
		RDEBUG3("No Session ID to store");
		return 0;
	}

	RDEBUG3("Session ID %pV - Requested store", &tls_cache->store.id);

	/*
	 *	Store the session blob and session id for writing
	 *	later, once all the authentication phases have completed.
	 */
	tls_cache->store.sess = sess;
	tls_ticket_stateful_store_state_request(tls_session);

	return 1;
}

/** Read session data from the cache
 *
 * @param[in] ssl session state.
 * @param[in] key to retrieve session data for.
 * @param[in] key_len The length of the key.
 * @param[out] copy Indicates whether OpenSSL should increment the reference
 *	count on SSL_SESSION to prevent it being automatically freed.  We always
 *	set this to 0.
 * @return
 *	- Deserialised session data on success.
 *	- NULL on error.
 */
static SSL_SESSION *tls_ticket_stateful_load_cb(SSL *ssl,
						unsigned char const *key,
						int key_len, int *copy)
{
	fr_tls_session_t	*tls_session;
	fr_tls_ticket_stateful_t		*tls_cache;
	request_t		*request;

	tls_session = fr_tls_session(ssl);
	request = fr_tls_session_request(tls_session->ssl);
	tls_cache = tls_session->cache;

	fr_assert(tls_cache);
	fr_assert(tls_session->conf->virtual_server);

	/*
	 *	The request was cancelled.  Do not return a session, and
	 *	let OpenSSL fall back to a full handshake.
	 */
	if (unlang_request_is_cancelled(request)) return NULL;

	/*
	 *	Never return a session when session resumption is
	 *	disallowed.
	 */
	if (!tls_cache || !tls_session->allow_session_resumption) return NULL;

	/*
	 *	OpenSSL runs the handshake, including this callback, on
	 *	one of its fibers (a 32K micro stack by default).
	 *
	 *	So that we don't have silent memory corruption we ensure
	 *	all the heavy lifting and unlang execution occurs on the
	 *	main thread, and never on the fiber.
	 *
	 *	1. On the first call, the callback records the session
	 *	   ID, marks the section as pending, and pauses the
	 *	   handshake.
	 *	2. Control returns to
	 *	   tls_session_async_handshake_cont(), which pushes the
	 *	   section with fr_tls_ticket_stateful_pending_push().
	 *	3. Once the section has finished,
	 *	   tls_session_async_handshake_cont() resumes the
	 *	   handshake, and execution continues after the first
	 *	   ASYNC_pause_job() call below.
	 *	4. The callback jumps back to the switch, where the load
	 *	   state records whether the section found a session.
	 *	   When the section found a session, the callback pauses
	 *	   the handshake a second time, and
	 *	   `verify certificate { ... }` re-validates the peer
	 *	   certificate.
	 */
again:
	switch (tls_cache->load.state) {
	case FR_TLS_TICKET_STATEFUL_INIT:
		fr_assert(fr_type_is_null(tls_cache->load.id.type));

		tls_ticket_stateful_load_state_request(tls_session);
		MEM(fr_value_box_memdup(tls_cache, &tls_cache->load.id, NULL,
					(uint8_t const *)key, key_len, true) == 0);

		/*
		 *	The key is the ID of the session that the peer
		 *	asks to resume, and the key stays the session ID
		 *	for the rest of the handshake.  Caching the key
		 *	here keeps the log lines that print the ID
		 *	working after load.id is cleared.
		 */
		if (fr_type_is_null(tls_session->session_id.type)) {
			MEM(fr_value_box_memdup(tls_session, &tls_session->session_id, NULL,
						(uint8_t const *)key, key_len, true) == 0);
			if (tls_cache) tls_cache->session_id = &tls_session->session_id;
		}

		RDEBUG3("Requested session load - ID %pV", &tls_cache->load.id);

		/*
		 *	Cache functions are only allowed during the
		 *	handshake.
		 *
		 *	FIXME: With TLS 1.3 session tickets can be sent
		 *	later.  Technically every point where we call
		 *	SSL_read() may need to be a yield point.
		 */
		if (unlikely(!tls_session->can_pause)) {
		cant_pause:
			fr_assert_msg("Unexpected call to %s. "
				      "tls_session_async_handshake_cont must be in call stack", __FUNCTION__);
			return NULL;
		}
		/*
		 *	Jumps back to SSL_read() in session.c.
		 *
		 *	If the request is cancelled, whatever was meant
		 *	to be done while the handshake was paused may
		 *	not have been completed.
		 */
		ASYNC_pause_job();

		/*
		 *	`load session { ... }` finished, but the request
		 *	was cancelled.  Free any loaded session, reset
		 *	the load state, and tell OpenSSL that the load
		 *	failed.
		 */
		if (unlang_request_is_cancelled(request)) {
			tls_ticket_stateful_load_state_reset(request, tls_cache);	/* Clears any loaded session data */
			return NULL;

		}
		goto again;

	case FR_TLS_TICKET_STATEFUL_REQUESTED:
		fr_assert(0);				/* Called twice without attempting the load?! */
		tls_cache->load.state = FR_TLS_TICKET_STATEFUL_FAILED;
		break;

	case FR_TLS_TICKET_STATEFUL_SUCCESS:
	{
		SSL_SESSION	*sess;

		/*
		 *	The handshake continues with the loaded session.
		 *	Cache the ID of the loaded session in
		 *	tls_session->session_id now.  load.id is cleared
		 *	below.
		 */
		tls_session_id_cache(tls_session, tls_cache->load.sess);

		RDEBUG3("Setting session data");

		fr_value_box_clear(&tls_cache->load.id);

		/*
		 *	The SSL_SESSION holds a copy of the peer's
		 *	certificate, but not the peer's certificate
		 *	chain.  Re-validation needs the chain.
		 *	tls_ticket_app_data_get() therefore restores the
		 *	session-state list, which holds the certificate
		 *	pairs, from the application data stored with the
		 *	session.
		 */
		if (tls_ticket_app_data_get(request, tls_cache->load.sess, &tls_session->session_id) < 0) {
			REDEBUG("Denying session resumption via session-id");
		verify_error:
			/*
			 *	Request the `delete session { ... }`
			 *	section, which runs the next time the
			 *	handshake pauses.
			 */
			tls_ticket_stateful_delete_request(tls_session, tls_cache->load.sess);
			tls_ticket_stateful_load_state_reset(request, tls_session->cache);	/* Free the session */
			return NULL;
		}

		/*
		 *	Mark `verify certificate { ... }` as pending,
		 *	for tls_session_async_handshake_cont() to push
		 *	once the handshake pauses below.
		 */
		fr_tls_verify_resumed_request(tls_session);

		if (unlikely(!tls_session->can_pause)) goto cant_pause;
		/*
		 *	Jumps back to SSL_read() in session.c.
		 *
		 *	If the request is cancelled, whatever was meant
		 *	to be done while the handshake was paused may
		 *	not have been completed.
		 */
		ASYNC_pause_job();

		/*
		 *	`verify certificate { ... }` finished, but the
		 *	request was cancelled.  Free any loaded session,
		 *	reset the load and verify states, and tell
		 *	OpenSSL that the load failed.
		 */
		if (unlang_request_is_cancelled(request)) {
			tls_ticket_stateful_load_state_reset(request, tls_cache);	/* Clears any loaded session data */
			fr_tls_verify_cert_reset(tls_session);
			return NULL;

		}

		/*
		 *	The callback denies resumption when the peer
		 *	certificate fails re-validation.
		 */
		if (!fr_tls_verify_cert_result(tls_session)) {
			RDEBUG2("Certificate re-validation failed, denying session resumption via session-id");
			goto verify_error;
		}
		sess = tls_cache->load.sess;

		/*
		 *	After we return it's OpenSSL's responsibility
		 *	to free the session data, so set our copy of
		 *	the pointer to NULL, to prevent a double free
		 *	on cleanup.
		 */
		{
			RDEBUG3("Session ID %pV - Session ownership transferred to libssl", &tls_session->session_id);
			*copy = 0;
			tls_cache->load.sess = NULL;
		}
		return sess;
	}


	case FR_TLS_TICKET_STATEFUL_FAILED:
		RDEBUG3("Session data load failed");
		break;
	}

	fr_value_box_clear(&tls_cache->load.id);
	fr_assert(!tls_cache->load.sess);

	return NULL;
}

/** Delete session data from the cache
 *
 * @param[in] ctx Current ssl context.
 * @param[in] sess to be deleted.
 */
static void tls_ticket_stateful_delete_cb(UNUSED SSL_CTX *ctx, SSL_SESSION *sess)
{
	fr_tls_session_t *tls_session;

	/*
	 *	Not sure why this happens, but sometimes SSL_SESSION *s
	 *	make it here without the correct ex data.
	 *
	 *	Maybe it's one OpenSSL created internally?
	 */
	tls_session = SSL_SESSION_get_ex_data(sess, fr_tls_session_ex_index);
	if (!tls_session) return;

	(void) talloc_get_type_abort(tls_session, fr_tls_session_t);

	/*
	 *	Note that tls_session->session CAN be NULL here.  That's because that field is set during the
	 *	TLS negotiation.  If we get a rejection part way though the TLS negotiation, then the field
	 *	isn't set.  But OpenSSL passes the SSL_SESSION to us here, so we use that.
	 */
	tls_ticket_stateful_delete_request(tls_session, sess);
}

/** Cleanup any memory allocated by OpenSSL
 */
static int _tls_ticket_stateful_free(fr_tls_ticket_stateful_t *tls_cache)
{
	tls_ticket_stateful_load_state_reset(NULL, tls_cache);
	tls_ticket_stateful_store_state_reset(NULL, tls_cache);

	return 0;
}

/** Allocate a session cache state structure, and assign it to a tls_session
 *
 * @note This must be called if session caching is enabled for a tls session.
 *
 * @param[in] tls_session	to assign cache structure to.
 */
void fr_tls_ticket_stateful_session_alloc(fr_tls_session_t *tls_session)
{
	fr_assert(!tls_session->cache);

	MEM(tls_session->cache = talloc_zero(tls_session, fr_tls_ticket_stateful_t));
	talloc_set_destructor(tls_session->cache, _tls_ticket_stateful_free);
}

/** Disable stateful session resumption for a given TLS ctx
 *
 * @param[in] ctx to disable stateful session resumption for.
 */
void fr_tls_ticket_stateful_disable(SSL_CTX *ctx)
{
	/*
	 *	Only disables stateful session-resumption.
	 *
	 *	As per Matt Caswell:
	 *
	 *	SSL_SESS_CACHE_OFF, when called on the server,
	 *	disables caching of server side sessions.
	 *	It does not switch off resumption. Resumption can
	 *	still occur if a stateless session ticket is used
	 *	(even in TLSv1.2).
	 */
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
}

/** Install the stateful session cache callbacks on an SSL_CTX
 *
 * The callbacks run `store session`, `load session` and `clear session`.
 * Internal lookups are disabled, so every lookup goes through the
 * callbacks.  OpenSSL calls the store callback only for the role the
 * cache mode names, so a client context sets SSL_SESS_CACHE_CLIENT
 * rather than SSL_SESS_CACHE_SERVER.
 *
 * @param[in] ctx		to install the callbacks on.
 * @param[in] cache_conf	Session caching configuration, for the lifetime.
 * @param[in] client		true when the context is for a client.
 */
void fr_tls_ticket_stateful_ctx_init(SSL_CTX *ctx, fr_tls_ticket_conf_t const *cache_conf, bool client)
{
	SSL_CTX_sess_set_new_cb(ctx, tls_ticket_stateful_store_cb);
	SSL_CTX_sess_set_get_cb(ctx, tls_ticket_stateful_load_cb);
	SSL_CTX_sess_set_remove_cb(ctx, tls_ticket_stateful_delete_cb);

	SSL_CTX_set_session_cache_mode(ctx, (client ? SSL_SESS_CACHE_CLIENT : SSL_SESS_CACHE_SERVER) |
					    SSL_SESS_CACHE_NO_INTERNAL);

	/*
	 *	Controls the validity period of the stateful cache.
	 */
	SSL_CTX_set_timeout(ctx, fr_time_delta_to_sec(cache_conf->lifetime));
}
#endif /* WITH_TLS */
