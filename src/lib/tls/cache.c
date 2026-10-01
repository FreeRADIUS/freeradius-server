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
 * @file tls/cache.c
 * @brief Functions to support TLS session resumption
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
#include "cache.h"
#include "log.h"
#include "strerror.h"
#include "verify.h"

#include <openssl/ssl.h>
#include <openssl/kdf.h>

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
#define TLS_CACHE_DISABLED  (!tls_cache || !conf->virtual_server)


/** Copy the ID of a session into a box
 *
 * @param[in] ctx	to allocate the ID in.
 * @param[out] out	box to fill.  Left as-is when the session has no ID.
 * @param[in] sess	to retrieve the ID from.
 * @return
 *	- 0 on success.
 *	- -1 if the session had no ID.
 */
static inline CC_HINT(always_inline, nonnull)
int tls_cache_id_to_box(TALLOC_CTX *ctx, fr_value_box_t *out, SSL_SESSION *sess)
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

	if (tls_cache_id_to_box(tls_session, &tls_session->session_id, sess) < 0) return;

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

static inline CC_HINT(always_inline, nonnull(2))
void _tls_cache_load_state_reset(request_t *request, fr_tls_cache_t *cache, char const *func)
{
	if (cache->load.sess) {
		if (ROPTIONAL_ENABLED(RDEBUG_ENABLED3, DEBUG_ENABLED3)) {
			ROPTIONAL(RDEBUG3, DEBUG3, "Session ID %pV - Freeing loaded session in %s", cache->session_id, func);
		}

		SSL_SESSION_free(cache->load.sess);
		cache->load.sess = NULL;
	}
	cache->load.state = FR_TLS_CACHE_INIT;
}
#define tls_cache_load_state_reset(_request, _cache) _tls_cache_load_state_reset(_request, _cache, __FUNCTION__)

static inline CC_HINT(always_inline, nonnull(2))
void _tls_cache_store_state_reset(request_t *request, fr_tls_cache_t *cache, char const *func)
{
	if (cache->store.sess) {
		if (ROPTIONAL_ENABLED(RDEBUG_ENABLED3, DEBUG_ENABLED3)) {
			ROPTIONAL(RDEBUG3, DEBUG3, "Session ID %pV - Freeing session to store in %s", &cache->store.id, func);
		}
		SSL_SESSION_free(cache->store.sess);
		cache->store.sess = NULL;
		fr_value_box_clear(&cache->store.id);
	}
	cache->store.state = FR_TLS_CACHE_INIT;
}
#define tls_cache_store_state_reset(_request, _cache) _tls_cache_store_state_reset(_request, _cache, __FUNCTION__)

static inline CC_HINT(always_inline)
void _tls_cache_clear_state_reset(request_t *request, fr_tls_cache_t *cache, char const *func)
{
	if (!fr_type_is_null(cache->clear.id.type)) {
		if (ROPTIONAL_ENABLED(RDEBUG_ENABLED3, DEBUG_ENABLED3)) {
			ROPTIONAL(RDEBUG3, DEBUG3, "Session ID %pV - Freeing session ID to clear in %s",
				  &cache->clear.id, func);
		}
		fr_value_box_clear(&cache->clear.id);
	}
	cache->clear.state = FR_TLS_CACHE_INIT;
}
#define tls_cache_clear_state_reset(_request, _cache) _tls_cache_clear_state_reset(_request, _cache, __FUNCTION__)

/** Serialize the session-state list and store it in the SSL_SESSION *
 *
 */
static int tls_cache_app_data_set(request_t *request, SSL_SESSION *sess,
				  fr_value_box_t const *session_id, uint32_t resumption_type)
{
	fr_dbuff_t		dbuff;
	fr_dbuff_uctx_talloc_t	tctx;
	fr_dcursor_t		dcursor;
	fr_pair_t		*vp, *type_vp;
	ssize_t			slen;
	int			ret;

	/*
	 *	Add a temporary pair for the type of session resumption
	 */
	MEM(pair_append_session_state(&type_vp, attr_tls_session_resume_type) >= 0);
	type_vp->vp_uint32 = resumption_type;

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
	 *	Encode the session-state contents and
	 *	add it to the ticket.
	 */
	for (vp = fr_pair_dcursor_init(&dcursor, &request->session_state_pairs);
	     vp;
	     vp = fr_dcursor_current(&dcursor)) {
		slen = fr_internal_encode_pair(&dbuff, &dcursor, NULL);
		if (slen < 0) {
			RPERROR("Session ID %pV - Failed serialising session-state list", session_id);
			fr_dbuff_free_talloc(&dbuff);
			fr_pair_delete(&request->session_state_pairs, type_vp);
			return 0; /* didn't store data */
		}
	}

	fr_pair_remove(&request->session_state_pairs, type_vp);

	RHEXDUMP4(fr_dbuff_start(&dbuff), fr_dbuff_used(&dbuff), "session-ticket application data");

	/*
	 *	Pass the serialized session-state list
	 *	over to OpenSSL.
	 */
	ret = SSL_SESSION_set1_ticket_appdata(sess, fr_dbuff_start(&dbuff), fr_dbuff_used(&dbuff));
	fr_dbuff_free_talloc(&dbuff);	/* OpenSSL memdups the data */
	if (ret != 1) {
		fr_tls_log(request, "Session ID %pV - Failed setting application data", session_id);
		return -1;
	}

	return 1;		/* successfully stored data */
}

static int tls_cache_app_data_get(request_t *request, SSL_SESSION *sess,
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
		fr_tls_log(request, "Session ID %pV - Failed retrieving application data", session_id);
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

/** Delete session data be deleted from the cache
 *
 * @param[in] sess to be deleted.
 */
static void tls_cache_delete_request(fr_tls_session_t *tls_session, SSL_SESSION *sess)
{
	fr_tls_cache_t		*tls_cache;
	request_t		*request;

	if (!tls_session->cache) return;

	request = fr_tls_session_request(tls_session->ssl);
	tls_cache = tls_session->cache;

	/*
	 *	Request was cancelled just return without doing any work.
	 */
	if (unlang_request_is_cancelled(request)) return;

	fr_assert(tls_cache->clear.state == FR_TLS_CACHE_INIT);

	/*
	 *	Record the session to delete
	 */
	if (tls_cache_id_to_box(tls_cache, &tls_cache->clear.id, sess) < 0) {
		RWDEBUG("Error retrieving Session ID");
		return;
	}

	RDEBUG3("Session ID %pV - Requested session clear", &tls_cache->clear.id);

	tls_cache->clear.state = FR_TLS_CACHE_REQUESTED;

	/*
	 *	Reset any pending `store session`, so that we skip
	 *	unnecessary work.
	 */
	tls_cache_store_state_reset(request, tls_cache);

	/*
	 *	We _usually_ store a copy of the SSL_SESSION in tls_session->session.  If the
	 *	session is being freed, then we invalidate the cached SSL_SESSION.  Note that
	 *	tls_session->session can be NULL sometimes, see tls_cache_delete_cb().
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
static fr_time_delta_t tls_cache_session_lifetime(request_t *request, fr_value_box_t const *session_id,
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

/** Process the result of `load session { ... }`
 */
static unlang_action_t tls_cache_load_resume(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_tls_cache_t		*tls_cache = tls_session->cache;
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
		tls_cache->load.state = FR_TLS_CACHE_FAILED;
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
		fr_tls_log(request, "Failed loading persisted session");
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
	 *	tls_cache_session_lifetime() clamps to the lowest of the session's own lifetime, the
	 *	configured `lifetime`, and the RFC maximum.  Clamping to the configured value is what lets
	 *	a policy update reach sessions which were stored before it.
	 */
	{
		fr_tls_conf_t	*conf = fr_tls_session_conf(tls_session->ssl);

		if (!fr_time_delta_ispos(tls_cache_session_lifetime(request, &tls_session->session_id,
								    conf, sess))) {
			RWDEBUG("Session ID %pV - Cached session has expired, not resuming", &tls_session->session_id);
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
	 *	retrieved in fr_tls_cache_delete.
	 *
	 *	ex_data is not serialised in i2d_SSL_SESSION
	 *	so we don't have to bother unsetting it.
	 */
	SSL_SESSION_set_ex_data(sess, fr_tls_session_ex_index, fr_tls_session(tls_session->ssl));

	tls_cache->load.state = FR_TLS_CACHE_SUCCESS;
	tls_cache->load.sess = sess;	/* This is consumed in tls_cache_load_cb */

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
static unlang_action_t tls_cache_load_push(request_t *request, fr_tls_session_t *tls_session)
{
	fr_tls_cache_t		*tls_cache = tls_session->cache;
	fr_tls_conf_t		*conf = fr_tls_session_conf(tls_session->ssl);
	request_t		*child;
	unlang_action_t		ua;

	if (TLS_CACHE_DISABLED) return UNLANG_ACTION_CALCULATE_RESULT;

	if (tls_cache->load.state != FR_TLS_CACHE_REQUESTED) return UNLANG_ACTION_CALCULATE_RESULT;
       
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
	if (tls_cache->clear.state == FR_TLS_CACHE_REQUESTED) {
		RDEBUG3("Session ID %pV - Clear is pending, skipping `load session { ... }`",
			&tls_cache->load.id);
		tls_cache->load.state = FR_TLS_CACHE_FAILED;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	fr_assert(!fr_type_is_null(tls_cache->load.id.type));

	MEM(child = tls_subrequest_alloc(request, enum_tls_packet_type_load_session->vb_uint32,
					 &tls_cache->load.id));

	/*
	 *	Allocate a child, and set it up to call
	 *      the TLS virtual server.
	 */
	ua = fr_tls_call_push(child, tls_cache_load_resume, conf, tls_session, true);
	if (ua == UNLANG_ACTION_FAIL) {
		talloc_free(child);
		tls_cache_load_state_reset(request, tls_cache);
		return UNLANG_ACTION_FAIL;
	}

	return ua;
}

/** Process the result of `store session { ... }`
 */
static unlang_action_t tls_cache_store_resume(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_tls_cache_t		*tls_cache = tls_session->cache;
	fr_pair_t		*vp;

	tls_cache_store_state_reset(request, tls_cache);

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_tls_packet_type);
	if (vp && (vp->vp_uint32 == enum_tls_packet_type_success->vb_uint32)) {
		tls_cache->store.state = FR_TLS_CACHE_SUCCESS;	/* Avoid spurious clear calls */
	} else {
		RWDEBUG("Failed storing session data");
		fr_tls_session_error_add(request->parent, FR_ERROR_VALUE_STORE_SESSION_FAILED);
		tls_cache->store.state = FR_TLS_CACHE_INIT;
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
unlang_action_t tls_cache_store_push(request_t *request, fr_tls_conf_t *conf, fr_tls_session_t *tls_session)
{
	fr_tls_cache_t		*tls_cache = tls_session->cache;
	size_t			len, ret;
	int			rcode;

	uint8_t			*p, *data = NULL;

	request_t		*child;
	fr_pair_t		*vp;
	SSL_SESSION		*sess = tls_session->cache->store.sess;
	unlang_action_t		ua;
	fr_time_delta_t		ttl;

	if (TLS_CACHE_DISABLED) return UNLANG_ACTION_CALCULATE_RESULT;

	fr_assert(tls_cache->store.sess);
	fr_assert(tls_cache->store.state == FR_TLS_CACHE_REQUESTED);

	/*
	 *	If there's a pending clear, then don't push any load /
	 *	save / etc.  This isn't strictly necessary, but is
	 *	good "defense in depth" for any future code changes.
	 *	It also documents / enforces our expectations.
	 */
	if (tls_cache->clear.state == FR_TLS_CACHE_REQUESTED) {
		RWDEBUG("Session ID %pV - Clear is pending, not storing", &tls_cache->store.id);
		fr_tls_session_error_add(request, FR_ERROR_VALUE_STORE_CANCELLED_BY_CLEAR);
		tls_cache_store_state_reset(request, tls_cache);
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	ttl = tls_cache_session_lifetime(request, &tls_cache->store.id, conf, sess);
	if (!fr_time_delta_ispos(ttl)) {
		RWDEBUG("Session ID %pV - Session has already expired, not storing", &tls_cache->store.id);
		fr_tls_session_error_add(request, FR_ERROR_VALUE_STORE_SESSION_EXPIRED);
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Add the current session-state list
	 *	contents to the ssl-data
	 */
	rcode = tls_cache_app_data_set(request, sess, &tls_cache->store.id,
				       enum_tls_session_resumed_stateful->vb_uint32);
	if (rcode < 0) {
		tls_cache_store_state_reset(request, tls_cache);
		return UNLANG_ACTION_FAIL;
	}

	if (rcode == 0) return UNLANG_ACTION_CALCULATE_RESULT;

	MEM(child = tls_subrequest_alloc(request, enum_tls_packet_type_store_session->vb_uint32,
					 &tls_cache->store.id));
	request = child;

	/*
	 *	How long the session has to live.  Already clamped, the RFC
	 *	maximum included, by tls_cache_session_lifetime() above.
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
		tls_cache_store_state_reset(request, tls_cache);
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
	ua = fr_tls_call_push(child, tls_cache_store_resume, conf, tls_session, true);
	if (ua == UNLANG_ACTION_FAIL) goto error;

	return ua;
}

/** Process the result of `clear session { ... }`
 */
static unlang_action_t tls_cache_clear_resume(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_tls_cache_t		*tls_cache = tls_session->cache;
	fr_pair_t		*vp;

	tls_cache_clear_state_reset(request, tls_cache);

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
unlang_action_t tls_cache_clear_push(request_t *request, fr_tls_conf_t *conf, fr_tls_session_t *tls_session)
{
	request_t	*child;
	fr_tls_cache_t	*tls_cache = tls_session->cache;
	unlang_action_t	ua;

	if (TLS_CACHE_DISABLED) return UNLANG_ACTION_CALCULATE_RESULT;

	fr_assert(tls_cache->clear.state == FR_TLS_CACHE_REQUESTED);
	fr_assert(!fr_type_is_null(tls_cache->clear.id.type));

	MEM(child = tls_subrequest_alloc(request, enum_tls_packet_type_clear_session->vb_uint32,
					 &tls_cache->clear.id));

	/*
	 *	Allocate a child, and set it up to call
	 *      the TLS virtual server.
	 */
	ua = fr_tls_call_push(child, tls_cache_clear_resume, conf, tls_session, true);
	if (ua == UNLANG_ACTION_FAIL) {
		talloc_free(child);
		tls_cache_clear_state_reset(request, tls_cache);
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
static unlang_action_t tls_cache_load_client_resume(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_tls_cache_t		*tls_cache = tls_session->cache;

	(void) tls_cache_load_resume(request, uctx);

	if (tls_cache->load.state != FR_TLS_CACHE_SUCCESS) {
		RDEBUG2("No session to resume");
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	if (SSL_set_session(tls_session->ssl, tls_cache->load.sess) != 1) {
		fr_tls_log(request, "Failed setting the session to resume");
		tls_cache_load_state_reset(request, tls_cache);
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	RDEBUG2("Offering the cached session for resumption");

	/*
	 *	SSL_set_session() takes its own reference, and nothing else
	 *	consumes this one, unlike the server path where the session is
	 *	handed back to OpenSSL from tls_cache_load_cb.
	 */
	tls_cache_load_state_reset(request, tls_cache);

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Ask the virtual server for a session to resume, as a client
 *
 * Call this before the handshake starts.  A client chooses which session to
 * offer, so the client looks a session up under a key the client already
 * knows, the expansion of `session { name = ... }`.  A server makes no such
 * choice.  OpenSSL hands the server the session ID the peer asked for, so the
 * server path lives in tls_cache_load_cb().
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
unlang_action_t fr_tls_cache_load_client_push(request_t *request, fr_tls_session_t *tls_session)
{
	fr_tls_cache_t		*tls_cache = tls_session->cache;
	fr_tls_conf_t		*conf = fr_tls_session_conf(tls_session->ssl);
	char			*name;
	request_t		*child;
	unlang_action_t		ua;

	if (TLS_CACHE_DISABLED) return UNLANG_ACTION_CALCULATE_RESULT;
	if (!tls_session->allow_session_resumption) return UNLANG_ACTION_CALCULATE_RESULT;

	fr_assert(conf->cache.id_name);

	if (tmpl_aexpand(tls_session, &name, request, conf->cache.id_name, NULL, NULL) < 0) {
		RPEDEBUG("Failed expanding the session name");
		return UNLANG_ACTION_FAIL;
	}

	MEM(child = tls_subrequest_alloc(request, enum_tls_packet_type_load_session->vb_uint32,
					 fr_box_octets((uint8_t const *) name, talloc_strlen(name))));

	talloc_free(name);

	ua = fr_tls_call_push(child, tls_cache_load_client_resume, conf, tls_session, true);
	if (ua == UNLANG_ACTION_FAIL) {
		talloc_free(child);
		return UNLANG_ACTION_FAIL;
	}

	return ua;
}

/** Resume after processing `encode session { ... }` or `decode session { ... }`
 *
 * Check the result and return success / fail depending.
 */
static unlang_action_t tls_cache_stateless_resume(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_pair_t		*vp;

	fr_assert((tls_session->ticket == FR_TLS_TICKET_ENCODE_REQUESTED) ||
		  (tls_session->ticket == FR_TLS_TICKET_DECODE_REQUESTED));

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_tls_packet_type);
	if (!vp || (vp->vp_uint32 != enum_tls_packet_type_success->vb_uint32)) {
		tls_session->ticket = FR_TLS_TICKET_FAILED;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	tls_session->ticket = FR_TLS_TICKET_SUCCESS;

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Push `encode session { ... }` or `decode session { ... }`
 *
 * @param[in] request		The current request.
 * @param[in] tls_session	The current TLS session.
 * @param[in] packet_type	Which of the two sections to run.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD on success.
 *	- UNLANG_ACTION_FAIL on failure.
 */
static unlang_action_t tls_cache_stateless_push(request_t *request, fr_tls_session_t *tls_session,
					     uint32_t packet_type)
{
	fr_tls_conf_t	*conf = fr_tls_session_conf(tls_session->ssl);
	request_t	*child;
	unlang_action_t	ua;

	fr_assert(conf->virtual_server);

	MEM(child = tls_subrequest_alloc(request, packet_type, &tls_session->session_id));

	fr_tls_session_extra_pairs_copy_to_child(child, tls_session);

	ua = fr_tls_call_push(child, tls_cache_stateless_resume, conf, tls_session, false);
	if (ua == UNLANG_ACTION_FAIL) {
		PERROR("Failed calling TLS virtual server");
		talloc_free(child);
		return UNLANG_ACTION_FAIL;
	}

	return ua;
}

/** Push `encode session` or `decode session`, depending on what's needed.
 *
 * @param[in] request		The current request.
 * @param[in] tls_session	The current TLS session.
 * @return
 *	- UNLANG_ACTION_CALCULATE_RESULT	- nothing was pending.
 *	- UNLANG_ACTION_PUSHED_CHILD		- a section is running.
 *	- UNLANG_ACTION_FAIL			- the frame could not be pushed.
 */
unlang_action_t fr_tls_cache_stateless_pending_push(request_t *request, fr_tls_session_t *tls_session)
{
	switch (tls_session->ticket) {
	case FR_TLS_TICKET_ENCODE_REQUESTED:
		return tls_cache_stateless_push(request, tls_session,
					     enum_tls_packet_type_encode_session->vb_uint32);

	case FR_TLS_TICKET_DECODE_REQUESTED:
		return tls_cache_stateless_push(request, tls_session,
					     enum_tls_packet_type_decode_session->vb_uint32);

	default:
		return UNLANG_ACTION_CALCULATE_RESULT;
	}
}

/** Set up `encode session { ... }` or `decode session { ... }` from inside an OpenSSL callback
 *
 * We can't run the interpreter inside of a callback, so record what
 * we want to do, and tell OpenSSL to pause its processing.  We then
 * return to session.c, which determines that there's work to do,
 * pushes the section, runs it, and calls us again.  That resumes
 * after the ASYNC_pause_job() call.
 *
 * @param[in] request		bound to the session.
 * @param[in] tls_session	the ticket belongs to.
 * @param[in] decode		true to run `decode session`, false for `encode session`.
 * @return
 *	- true if the section ran and approved the session-state list.
 *	- false if it did not, or if it could not be run at all.
 */
static bool tls_cache_stateless_section_setup(request_t *request, fr_tls_session_t *tls_session, bool decode)
{
	char const *name = decode ? "decode session" : "encode session";

	fr_assert(tls_session->ticket == FR_TLS_TICKET_INIT);

	tls_session->ticket = decode ? FR_TLS_TICKET_DECODE_REQUESTED : FR_TLS_TICKET_ENCODE_REQUESTED;

	/*
	 *	Sections are only allowed during the handshake, as
	 *	with certificate re-validation.  See the FIXME in
	 *	tls_cache_session_ticket_app_data_get().
	 */
	if (unlikely(!tls_session->can_pause)) {
		fr_assert_msg("Unexpected call to %s. "
			      "tls_session_async_handshake_cont must be in call stack", __FUNCTION__);
		tls_session->ticket = FR_TLS_TICKET_INIT;
		return false;
	}

	ASYNC_pause_job();

	/*
	 *	If the request was cancelled, reset the ticket state
	 *	so that we don't do anything.
	 */
	if (unlang_request_is_cancelled(request)) {
		tls_session->ticket = FR_TLS_TICKET_INIT;
		return false;
	}

	if (tls_session->ticket != FR_TLS_TICKET_SUCCESS) {
		REDEBUG("`%s` did not return success", name);
		fr_tls_session_error_add(request, decode ? FR_ERROR_VALUE_DECODE_SESSION_FAILED :
					  FR_ERROR_VALUE_ENCODE_SESSION_FAILED);
		tls_session->ticket = FR_TLS_TICKET_INIT;
		return false;
	}

	tls_session->ticket = FR_TLS_TICKET_INIT;

	return true;
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
unlang_action_t fr_tls_cache_pending_push(request_t *request, fr_tls_session_t *tls_session)
{
	fr_tls_cache_t *tls_cache = tls_session->cache;
	fr_tls_conf_t *conf = fr_tls_session_conf(tls_session->ssl);
	unlang_action_t ua;

	if (!tls_cache) return UNLANG_ACTION_CALCULATE_RESULT;	/* No caching allowed, nothing to discard */

	/*
	 *	The caller is asking us to push load / store / etc.  Since the cache is disabled, we just
	 *	reset the state (and free resources), then return.  The callers can then check
	 *	fr_tls_cache_pending(), which will now return "nope".
	 */
	if (TLS_CACHE_DISABLED) {
		if (tls_cache->load.state == FR_TLS_CACHE_REQUESTED) {
			tls_cache_load_state_reset(request, tls_cache);
		}
		if (tls_cache->clear.state == FR_TLS_CACHE_REQUESTED) {
			tls_cache_clear_state_reset(request, tls_cache);
		}
		if (tls_cache->store.state == FR_TLS_CACHE_REQUESTED) {
			tls_cache_store_state_reset(request, tls_cache);
		}
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Load stateful session data.
	 *
	 *	tls_cache_load_push() may return
	 *	UNLANG_ACTION_CALCULATE_RESULT there's a pending
	 *	`clear session`.  When that happens, we skip the load,
	 *	and run the clear instead.
	 */
	if (tls_cache->load.state == FR_TLS_CACHE_REQUESTED) {
		ua = tls_cache_load_push(request, tls_session);
		if (ua != UNLANG_ACTION_CALCULATE_RESULT) return ua;
	}

	/*
	 *	We only support a single session
	 *	ticket currently...
	 */
	if (tls_cache->clear.state == FR_TLS_CACHE_REQUESTED) {
		/*
		 *	Enforce that there's no queued store, as it
		 *	should have been cancelled.
		 */
		fr_assert(tls_cache->store.state != FR_TLS_CACHE_REQUESTED);
		tls_cache_store_state_reset(request, tls_cache);

		return tls_cache_clear_push(request, conf, tls_session);
	}

	if (tls_cache->store.state == FR_TLS_CACHE_REQUESTED) {
		return tls_cache_store_push(request, conf, tls_session);
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
static unlang_action_t tls_cache_drain(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	unlang_action_t		ua;

	if (!fr_tls_cache_pending(tls_session->cache)) return UNLANG_ACTION_CALCULATE_RESULT;

	/*
	 *	Set our repeat before any child is pushed.
	 */
	if (unlikely(unlang_function_repeat_set(request, tls_cache_drain) < 0)) return UNLANG_ACTION_FAIL;

	ua = fr_tls_cache_pending_push(request, tls_session);
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
static unlang_action_t tls_cache_drain_push(request_t *request, fr_tls_session_t *tls_session)
{
	if (!fr_tls_cache_pending(tls_session->cache)) return UNLANG_ACTION_CALCULATE_RESULT;

	return unlang_function_push(request, tls_cache_drain, NULL, NULL, 0, UNLANG_SUB_FRAME, tls_session);
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
 *	 fr_tls_cache_store_session().  A pushed child returns to the caller's
 *	 caller with that result already in place.
 *
 * @param[in] request		to run the cache sections in.
 * @param[in] tls_session	to keep.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD	- cache sections are running.
 *	- UNLANG_ACTION_CALCULATE_RESULT - there was nothing to do.
 *	- UNLANG_ACTION_FAIL		- the frame could not be pushed.
 */
unlang_action_t fr_tls_cache_store_session(request_t *request, fr_tls_session_t *tls_session)
{
	return tls_cache_drain_push(request, tls_session);
}

/** Clear a session after a failed authentication
 *
 * Cancels any pending `store session`, and if necessary, remember to run `clear session { ... }` as the
 * session might have been loaded from the cache.
 *
 * @note The caller MUST set the caller's own unlang result before calling
 *	 fr_tls_cache_clear_session().  A pushed child returns to the
 *	 caller's caller with that result already in place.
 *
 * @param[in] request		to run the cache sections in.
 * @param[in] tls_session	to discard.
 * @return
 *	- UNLANG_ACTION_PUSHED_CHILD	- cache sections are running.
 *	- UNLANG_ACTION_CALCULATE_RESULT - there was nothing to do.
 *	- UNLANG_ACTION_FAIL		- the frame could not be pushed.
 */
unlang_action_t fr_tls_cache_clear_session(request_t *request, fr_tls_session_t *tls_session)
{
	fr_tls_cache_t *tls_cache = tls_session->cache;
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
	 *	tls_cache_delete_cb.  HOWEVER, we've already set SSL_SESS_CACHE_NO_INTERNAL, which means that
	 *	SSL_CTX_remove_session() largely does nothing, and skips our callback.  These checks are
	 *	largely for paranoia, just in case the internal OpenSSL cache is somehow re-enabled.
	 *
	 *	tls_cache_delete_cb calls tls_cache_delete_request to record the ID of tls_session->session in
	 *	our pending cache state structure.
	 *
	 *	tls_cache_delete_request does NOT immediately call `clear session {}` as that must
	 *	be done in a code area which can return a yield to the interpreter.
	 */
	if (tls_session->session) {
		SSL_CTX_remove_session(tls_session->ctx, tls_session->session);

		/*
		 *	Manually call tls_cache_delete_request(), just in case.  That function clears
		 *	tls_session->session, so it's idempotent.  It clears tls_session->session, so it's
		 *	safe to call twice.  If it's called via the above path, then it clears the session
		 *	pointer, which means that we don't call it again.
		 */
		if (tls_session->session && tls_cache->loaded) tls_cache_delete_request(tls_session, tls_session->session);
	}
	tls_session->allow_session_resumption = false;

	/*
	 *	Clear any pending store requests.
	 */
	tls_cache_store_state_reset(request, tls_cache);

	/*
	 *	The request wasn't bound when we were called, so unbind it now.
	 */
	if (!bound) fr_tls_session_request_unbind(tls_session->ssl);

	return tls_cache_drain_push(request, tls_session);
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
static int tls_cache_store_cb(SSL *ssl, SSL_SESSION *sess)
{
	request_t		*request;
	fr_tls_session_t	*tls_session;
	fr_tls_cache_t		*tls_cache;

	/*
	 *	This functions should only be called once during the lifetime
	 *	of the tls_session, as the fields aren't re-populated on
	 *	resumption.
	 */
	tls_session = fr_tls_session(ssl);

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

	request = fr_tls_session_request(tls_session->ssl);
	tls_cache = tls_session->cache;

	fr_assert(tls_cache);
	fr_assert(fr_tls_session_conf(tls_session->ssl)->virtual_server);

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
	if (tls_cache_id_to_box(tls_cache, &tls_cache->store.id, sess) < 0) {
		RDEBUG3("No Session ID to store");
		return 0;
	}

	RDEBUG3("Session ID %pV - Requested store", &tls_cache->store.id);

	/*
	 *	Store the session blob and session id for writing
	 *	later, once all the authentication phases have completed.
	 */
	tls_cache->store.sess = sess;
	tls_cache->store.state = FR_TLS_CACHE_REQUESTED;

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
static SSL_SESSION *tls_cache_load_cb(SSL *ssl,
				      unsigned char const *key,
				      int key_len, int *copy)
{
	fr_tls_session_t	*tls_session;
	fr_tls_cache_t		*tls_cache;
	request_t		*request;

	tls_session = fr_tls_session(ssl);
	request = fr_tls_session_request(tls_session->ssl);
	tls_cache = tls_session->cache;

	fr_assert(tls_cache);
	fr_assert(fr_tls_session_conf(tls_session->ssl)->virtual_server);

	/*
	 *	Request was cancelled, don't return any session and hopefully
	 *      OpenSSL will return back to SSL_read() soon.
	 */
	if (unlang_request_is_cancelled(request)) return NULL;

	/*
	 *	Ensure if session resumption is disallowed this callback
	 *	will never return session data.
	 */
	if (!tls_cache || !tls_session->allow_session_resumption) return NULL;

	/*
	 *	1. On the first call we return SSL_magic_pending_session_ptr.
	 *	   This causes the current SSL_read() call to error out and
	 *	   for SSL_get_error() to return SSL_ERROR_PENDING_SESSION.
	 *	2. On receiving SSL_ERROR_PENDING_SESSION we asynchronously
	 *	   load session information from a datastore and associated
	 *         it with the SSL session.
	 *	3. We asynchronously validate the certificate information
	 *	   retrieved during the session session load.
	 *	3. We call SSL_read() again, which in turn calls this callback
	 *	   again.
	 */
again:
	switch (tls_cache->load.state) {
	case FR_TLS_CACHE_INIT:
		fr_assert(fr_type_is_null(tls_cache->load.id.type));

		tls_cache->load.state = FR_TLS_CACHE_REQUESTED;
		MEM(fr_value_box_memdup(tls_cache, &tls_cache->load.id, NULL,
					(uint8_t const *)key, key_len, true) == 0);

		/*
		 *	This is the session the peer is asking to resume, so
		 *	it is the session ID for the rest of the handshake.
		 *	Caching it here means the many places which log the
		 *	ID keep working after load.id has been released.
		 */
		if (fr_type_is_null(tls_session->session_id.type)) {
			MEM(fr_value_box_memdup(tls_session, &tls_session->session_id, NULL,
						(uint8_t const *)key, key_len, true) == 0);
			if (tls_cache) tls_cache->session_id = &tls_session->session_id;
		}

		RDEBUG3("Requested session load - ID %pV", &tls_cache->load.id);

		/*
		 *	Cache functions are only allowed during the handshake
		 *	FIXME: With TLS 1.3 session tickets can be sent
		 *	later... Technically every point where we call
		 *	SSL_read() may need to be a yield point.
		 */
		if (unlikely(!tls_session->can_pause)) {
		cant_pause:
			fr_assert_msg("Unexpected call to %s. "
				      "tls_session_async_handshake_cont must be in call stack", __FUNCTION__);
			return NULL;
		}
		/*
		 *	Jumps back to SSL_read() in session.c
		 *
		 *	Be aware that if the request is cancelled
		 *	whatever was meant to be done during the
		 *	time we yielded may not have been completed.
		 */
		ASYNC_pause_job();

		/*
		 *	load cache { ... } returned, but the parent
		 *      request was cancelled, try and get everything
		 *	back into a consistent state and tell OpenSSL
		 *	we failed to load the session.
		 */
		if (unlang_request_is_cancelled(request)) {
			tls_cache_load_state_reset(request, tls_cache);	/* Clears any loaded session data */
			return NULL;

		}
		goto again;

	case FR_TLS_CACHE_REQUESTED:
		fr_assert(0);				/* Called twice without attempting the load?! */
		tls_cache->load.state = FR_TLS_CACHE_FAILED;
		break;

	case FR_TLS_CACHE_SUCCESS:
	{
		SSL_SESSION	*sess;

		/*
		 *	The loaded session becomes the session, so cache
		 *	its ID now.  load.id is freed below, once nothing
		 *	else needs it.
		 */
		tls_session_id_cache(tls_session, tls_cache->load.sess);

		RDEBUG3("Setting session data");

		fr_value_box_clear(&tls_cache->load.id);

		/*
		 *	This restores the contents of &session-state[*]
		 *	which hopefully still contains all the certificate
		 *	pairs.
		 *
		 *	Although the SSL_SESSION does contain a copy of
		 *	the peer's certificate, it does not contain the
		 *	peer's certificate chain, and so isn't reliable
		 *	for performing re-validation.
		 */
		if (tls_cache_app_data_get(request, tls_cache->load.sess, &tls_session->session_id) < 0) {
			REDEBUG("Denying session resumption via session-id");
		verify_error:
			/*
			 *	Request the session be deleted the next
			 *	time something calls cache action pending.
			 */
			tls_cache_delete_request(tls_session, tls_cache->load.sess);
			tls_cache_load_state_reset(request, tls_session->cache);	/* Free the session */
			return NULL;
		}

		/*
		 *	This sets the validation state of the tls_session
		 *	so that when we call ASYNC_pause_job(), and execution
		 *	jumps back to tls_session_async_handshake_cont
		 *	(just under SSL_read())
		 *	the code there knows what job it needs to push onto
		 *	the unlang stack.
		 */
		fr_tls_verify_cert_request(tls_session, true);

		if (unlikely(!tls_session->can_pause)) goto cant_pause;
		/*
		 *	Jumps back to SSL_read() in session.c
		 *
		 *	Be aware that if the request is cancelled
		 *	whatever was meant to be done during the
		 *	time we yielded may not have been completed.
		 */
		ASYNC_pause_job();

		/*
		 *	Certificate validation returned but the request
		 *	was cancelled.  Free any data we have so far
		 *	and reset the states, then let OpenSSL know
		 *	we failed to load the session.
		 */
		if (unlang_request_is_cancelled(request)) {
			tls_cache_load_state_reset(request, tls_cache);	/* Clears any loaded session data */
			fr_tls_verify_cert_reset(tls_session);
			return NULL;

		}

		/*
		 *	If we couldn't validate the client certificate
		 *	then validation overall fails.
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


	case FR_TLS_CACHE_FAILED:
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
static void tls_cache_delete_cb(UNUSED SSL_CTX *ctx, SSL_SESSION *sess)
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
	tls_cache_delete_request(tls_session, sess);
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
int fr_tls_cache_disable_cb(SSL *ssl, int is_forward_secure)
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

/** Cleanup any memory allocated by OpenSSL
 */
static int _tls_cache_free(fr_tls_cache_t *tls_cache)
{
	tls_cache_load_state_reset(NULL, tls_cache);
	tls_cache_store_state_reset(NULL, tls_cache);

	return 0;
}

/** Allocate a session cache state structure, and assign it to a tls_session
 *
 * @note This must be called if session caching is enabled for a tls session.
 *
 * @param[in] tls_session	to assign cache structure to.
 */
void fr_tls_cache_session_alloc(fr_tls_session_t *tls_session)
{
	fr_assert(!tls_session->cache);

	MEM(tls_session->cache = talloc_zero(tls_session, fr_tls_cache_t));
	talloc_set_destructor(tls_session->cache, _tls_cache_free);
}

/** Disable stateless session tickets for a given TLS ctx
 *
 * @param[in] ctx to disable session tickets for.
 */
static inline CC_HINT(always_inline)
void tls_cache_disable_stateless_resumption(SSL_CTX *ctx)
{
	long ctx_options = SSL_CTX_get_options(ctx);

	/*
	 *	Disable session tickets for older TLS versions
	 */
	ctx_options |= SSL_OP_NO_TICKET;
	SSL_CTX_set_options(ctx, ctx_options);

	/*
	 *	This controls the number of stateful or stateless
	 *	tickets generated with TLS 1.3.  In OpenSSL 1.1.0
	 *	it's also required to disable sending session tickets,
	 *	SSL_SESS_CACHE_OFF is not good enough.
	 */
	SSL_CTX_set_num_tickets(ctx, 0);
}

/** Disable stateful session resumption for a given TLS ctx
 *
 * @param[in] ctx to disable stateful session resumption for.
 */
static inline CC_HINT(always_inline)
void tls_cache_disable_statefull_resumption(SSL_CTX *ctx)
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

/** Called when new tickets are being generated
 *
 * This adds additional application data to the session ticket to
 * allow us to perform validation checks when the session is
 * resumed.
 */
static int tls_cache_session_ticket_app_data_set(SSL *ssl, void *arg)
{
	fr_tls_session_t	*tls_session = fr_tls_session(ssl);
	fr_tls_cache_conf_t	*tls_cache_conf = arg;	/* Not talloced */
	SSL_SESSION		*sess;
	request_t		*request;
	fr_tls_conf_t		*conf;

	/*
	 *	Check to see if we have a request bound
	 *	to the session.  If we don't have a
	 *	request there's no application data to
	 *	add.
	 */
	if (!fr_tls_session_request_bound(ssl)) return 1;

	/*
	 *	Encode the complete session state list
	 *	as app data.  Then, when the session is
	 *	resumed, the session-state list is
	 *	repopulated.
	 */
	request = fr_tls_session_request(ssl);

	/*
	 *	Request was cancelled, don't do anything.
	 */
	if (unlang_request_is_cancelled(request)) return 0;

	/*
	 *	Fatal error - We definitely should be
	 *      attempting to generate session tickets
	 *      if it's not permitted.
	 */
	if (!tls_session->allow_session_resumption ||
	    (!(tls_cache_conf->mode & FR_TLS_CACHE_STATELESS))) {
		REDEBUG("Generating session-tickets is not allowed");
		fr_tls_session_error_add(request, FR_ERROR_VALUE_SESSION_TICKET_NOT_ALLOWED);
		return 0;
	}

	sess = SSL_get_session(ssl);
	if (!sess) {
		REDEBUG("Failed retrieving session in session generation callback");
		return 0;
	}

	/*
	 *	Run `encode session` to allow the admin to update the
	 *	`session-state` list, before we encode it into a
	 *	stateless session ticket.
	 */
	conf = fr_tls_session_conf(ssl);

	if (conf->encode_session && !tls_cache_stateless_section_setup(request, tls_session, false)) {
		REDEBUG("Not generating a session-ticket");
		return 0;
	}

	if (tls_cache_app_data_set(request, sess, &tls_session->session_id,
				   enum_tls_session_resumed_stateless->vb_uint32) < 0) return 0;

	return 1;
}

/** Called when new tickets are being decoded
 *
 * This adds the session-state attributes back to the current request.
 */
static SSL_TICKET_RETURN tls_cache_session_ticket_app_data_get(SSL *ssl, SSL_SESSION *sess,
							       UNUSED unsigned char const *keyname,
							       UNUSED size_t keyname_len,
							       SSL_TICKET_STATUS status,
							       void *arg)
{
	fr_tls_session_t	*tls_session = fr_tls_session(ssl);
	fr_tls_conf_t		*conf = fr_tls_session_conf(tls_session->ssl);
	fr_tls_cache_conf_t	*tls_cache_conf = arg;	/* Not talloced */
	request_t		*request = NULL;

	if (fr_tls_session_request_bound(ssl)) {
		request = fr_tls_session_request(ssl);
		if (unlang_request_is_cancelled(request)) return SSL_TICKET_RETURN_ABORT;
	}

	if (!tls_session->allow_session_resumption ||
	    (!(tls_cache_conf->mode & FR_TLS_CACHE_STATELESS))) {
		ROPTIONAL(RDEBUG2, DEBUG2, "Session resumption not enabled for this TLS session, "
			  "denying session resumption via session-ticket");
	    	return SSL_TICKET_RETURN_IGNORE;
	}

	switch (status) {
	case SSL_TICKET_EMPTY:
	case SSL_TICKET_NO_DECRYPT:
	case SSL_TICKET_FATAL_ERR_MALLOC:
	case SSL_TICKET_FATAL_ERR_OTHER:
	case SSL_TICKET_NONE:
#ifdef STATIC_ANALYZER
	default:
#endif
		return SSL_TICKET_RETURN_IGNORE_RENEW;	/* Send a new ticket */

	case SSL_TICKET_SUCCESS:
		if (!request) return SSL_TICKET_RETURN_USE;
		break;

	case SSL_TICKET_SUCCESS_RENEW:
		if (!request) return SSL_TICKET_RETURN_USE_RENEW;
		break;
	}

	/*
	 *	This restores the contents of &session-state[*]
	 *	which hopefully still contains all the certificate
	 *	pairs.
	 *
	 *	Although the SSL_SESSION does contain a copy of
	 *	the peer's certificate, it does not contain the
	 *	peer's certificate chain, and so isn't reliable
	 *	for performing re-validation.
	 *
	 *	The session ticket includes a lifetime.  But we didn't
	 *	generate it, so we don't trust it.  If the ticket has
	 *	passed its lifetime, then we reject it and force full
	 *	reauthentication.
	 */
	if (!fr_time_delta_ispos(tls_cache_session_lifetime(request, &tls_session->session_id, conf, sess))) {
		REDEBUG("Session-ticket has expired, denying session resumption");
		fr_tls_session_error_add(request, FR_ERROR_VALUE_SESSION_TICKET_EXPIRED);
		return SSL_TICKET_RETURN_IGNORE_RENEW;
	}

	if (tls_cache_app_data_get(request, sess, &tls_session->session_id) < 0) {
		REDEBUG("Denying session resumption via session-ticket");
		return SSL_TICKET_RETURN_IGNORE_RENEW;
	}

	/*
	 *	The session-state list is back.  Give policy the chance to
	 *	look at what the ticket carried before anything relies on
	 *	it, certificate re-validation below included.
	 */
	if (conf->decode_session && !tls_cache_stateless_section_setup(request, tls_session, true)) {
		REDEBUG("Denying session resumption via session-ticket");
		return SSL_TICKET_RETURN_IGNORE_RENEW;
	}

	if (conf->virtual_server && tls_session->verify_peer_cert) {
		RDEBUG2("Requesting certificate re-validation for session-ticket");
		/*
		 *	This sets the validation state of the tls_session
		 *	so that when we call ASYNC_pause_job(), and execution
		 *	jumps back to tls_session_async_handshake_cont
		 *	(just under SSL_read())
		 *	the code there knows what job it needs to push onto
		 *	the unlang stack.
		 */
		fr_tls_verify_cert_request(tls_session, true);

		/*
		 *	Cache functions are only allowed during the handshake
		 *	FIXME: With TLS 1.3 session tickets can be sent
		 *	later... Technically every point where we call
		 *	SSL_read() may need to be a yield point.
		 */
		if (unlikely(!tls_session->can_pause)) {
			fr_assert_msg("Unexpected call to %s. "
				      "tls_session_async_handshake_cont must be in call stack", __FUNCTION__);
			return SSL_TICKET_RETURN_IGNORE_RENEW;
		}

		/*
		 *	Jumps back to SSL_read() in session.c
		 *
		 *	Be aware that if the request is cancelled
		 *	whatever was meant to be done during the
		 *	time we yielded may not have been completed.
		 */
		ASYNC_pause_job();

		/*
		 *	If the request was cancelled get everything back into
		 *	a known state.
		 */
		if (unlang_request_is_cancelled(request)) {
			fr_tls_verify_cert_reset(tls_session);
			return SSL_TICKET_RETURN_ABORT;
		}

		/*
		 *	If we couldn't validate the client certificate
		 *	give the client the opportunity to send a new
		 *	one, but _don't_ allow session resumption.
		 */
		if (!fr_tls_verify_cert_result(tls_session)) {
			RDEBUG2("Certificate re-validation failed, denying session resumption via session-ticket");
			return SSL_TICKET_RETURN_IGNORE_RENEW;
		}
	}

	return (status == SSL_TICKET_SUCCESS_RENEW) ? SSL_TICKET_RETURN_USE_RENEW : SSL_TICKET_RETURN_USE;
}

/** Sets callbacks and flags on a SSL_CTX to enable/disable session resumption
 *
 * @param[in] ctx			to modify.
 * @param[in] cache_conf		Session caching configuration.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_tls_cache_ctx_init(SSL_CTX *ctx, fr_tls_cache_conf_t const *cache_conf, bool client)
{
	switch (cache_conf->mode) {
	case FR_TLS_CACHE_DISABLED:
		tls_cache_disable_stateless_resumption(ctx);
		tls_cache_disable_statefull_resumption(ctx);
		return 0;

	case FR_TLS_CACHE_AUTO:
	case FR_TLS_CACHE_STATEFUL:
		/*
		 *	Setup the callbacks for stateful session-resumption
		 *      i.e. where the server stores session information.
		 */
		SSL_CTX_sess_set_new_cb(ctx, tls_cache_store_cb);
		SSL_CTX_sess_set_get_cb(ctx, tls_cache_load_cb);
		SSL_CTX_sess_set_remove_cb(ctx, tls_cache_delete_cb);

		/*
		 *	Controls the stateful cache mode
		 *
		 *      Here we disable internal lookups, and rely on the
		 *	callbacks above.
		 *
		 *	OpenSSL calls the store callback only for the role the
		 *	mode names, so a client context sets
		 *	SSL_SESS_CACHE_CLIENT rather than SSL_SESS_CACHE_SERVER.
		 */
		SSL_CTX_set_session_cache_mode(ctx, (client ? SSL_SESS_CACHE_CLIENT : SSL_SESS_CACHE_SERVER) |
						    SSL_SESS_CACHE_NO_INTERNAL);

		/*
		 *	Controls the validity period of the stateful cache.
		 */
		SSL_CTX_set_timeout(ctx, fr_time_delta_to_sec(cache_conf->lifetime));

		/*
		 *	Disables stateless session tickets for TLS 1.3.
		 */
		if (!(cache_conf->mode & FR_TLS_CACHE_STATELESS)) {
			tls_cache_disable_stateless_resumption(ctx);
			break;
		}
		FALL_THROUGH;

	case FR_TLS_CACHE_STATELESS:
	{
		size_t key_len;
		uint8_t *key_buff;
		EVP_PKEY_CTX *pkey_ctx = NULL;

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
		if (!(cache_conf->mode & FR_TLS_CACHE_STATEFUL)) {
			if (!client) {
				tls_cache_disable_statefull_resumption(ctx);
			} else {
				SSL_CTX_sess_set_new_cb(ctx, tls_cache_store_cb);
				SSL_CTX_sess_set_get_cb(ctx, tls_cache_load_cb);
				SSL_CTX_sess_set_remove_cb(ctx, tls_cache_delete_cb);

				SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT |
								    SSL_SESS_CACHE_NO_INTERNAL);

				SSL_CTX_set_timeout(ctx, fr_time_delta_to_sec(cache_conf->lifetime));
			}
		}

		/*
		 *	If keys is NULL, then OpenSSL returns the expected
		 *	key length, which may be different across different
		 *	flavours/versions of OpenSSL.
		 *
		 *	We could calculate this in conf.c, but, if in future
		 *	OpenSSL decides to use different key lengths based
		 *	on other parameters in the ctx, that'd break.
		 */
		key_len = SSL_CTX_set_tlsext_ticket_keys(ctx, NULL, 0);

		if (unlikely((pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL)) == NULL)) {
			fr_tls_strerror_printf(NULL);
			PERROR("Failed initialising KDF");
		kdf_error:
			if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
			return -1;
		}
		if (unlikely(EVP_PKEY_derive_init(pkey_ctx) != 1)) {
			fr_tls_strerror_printf(NULL);
			PERROR("Failed initialising KDF derivation ctx");
			goto kdf_error;
		}
		if (unlikely(EVP_PKEY_CTX_set_hkdf_md(pkey_ctx, UNCONST(struct evp_md_st *, EVP_sha256())) != 1)) {
			fr_tls_strerror_printf(NULL);
			PERROR("Failed setting KDF MD");
			goto kdf_error;
		}
		if (unlikely(EVP_PKEY_CTX_set1_hkdf_key(pkey_ctx,
							UNCONST(unsigned char *, cache_conf->session_ticket_key),
							talloc_array_length(cache_conf->session_ticket_key)) != 1)) {
			fr_tls_strerror_printf(NULL);
			PERROR("Failed setting KDF key");
			goto kdf_error;
		}
		if (unlikely(EVP_PKEY_CTX_add1_hkdf_info(pkey_ctx,
							 UNCONST(unsigned char *, "freeradius-session-ticket"),
							 sizeof("freeradius-session-ticket") - 1) != 1)) {
			fr_tls_strerror_printf(NULL);
			PERROR("Failed setting KDF label");
			goto kdf_error;
		}

		/*
		 *	SSL_CTX_set_tlsext_ticket_keys memcpys its
		 *	inputs so this is just a temporary buffer.
		 */
		MEM(key_buff = talloc_array(NULL, uint8_t, key_len));
		if (EVP_PKEY_derive(pkey_ctx, key_buff, &key_len) != 1) {
			fr_tls_strerror_printf(NULL);
			PERROR("Failed deriving session ticket key");

		key_buff_error:
			talloc_free(key_buff);
			goto kdf_error;
		}
		EVP_PKEY_CTX_free(pkey_ctx);
		pkey_ctx = NULL;

		fr_assert(talloc_array_length(key_buff) == key_len);

		/*
		 *	Ensure the same keys are used across all threads
		 */
		if (SSL_CTX_set_tlsext_ticket_keys(ctx,
						   key_buff, key_len) != 1) {
			fr_tls_strerror_printf(NULL);
			PERROR("Failed setting session ticket keys");
			goto key_buff_error;
		}

		DEBUG3("Derived session-ticket-key:");
		HEXDUMP3(key_buff, key_len, NULL);
		TALLOC_FREE(key_buff);

		/*
		 *	These callbacks embed and extract the
		 *	session-state list from the session-ticket.
		 */
		if (unlikely(SSL_CTX_set_session_ticket_cb(ctx,
							   tls_cache_session_ticket_app_data_set,
							   tls_cache_session_ticket_app_data_get,
							   UNCONST(fr_tls_cache_conf_t *, cache_conf)) != 1)) {
			fr_tls_strerror_printf(NULL);
			PERROR("Failed setting session ticket callbacks");
			goto kdf_error;
		}

		/*
		 *	Stateless resumption is enabled by default when
		 *	the TLS ctx is created, but OpenSSL sends too
		 *	many session tickets by default (2), and we only
		 *      need one.
		 */
		SSL_CTX_set_num_tickets(ctx, 1);
	}
		break;
	}

	SSL_CTX_set_not_resumable_session_callback(ctx, fr_tls_cache_disable_cb);
	SSL_CTX_set_quiet_shutdown(ctx, 1);

	return 0;
}
#endif /* WITH_TLS */
