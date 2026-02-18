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
 * @copyright 2015-2016 The FreeRADIUS server project
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls"

#include <freeradius-devel/internal/internal.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/subrequest.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/util/debug.h>

#include "attrs.h"
#include "base.h"
#include "cache.h"
#include "log.h"
#include "strerror.h"
#include "verify.h"

#include <openssl/ssl.h>
#include <openssl/kdf.h>

/** Retrieve session ID (in binary form) from the session
 *
 * @param[in] ctx	Where to allocate the array to hold the session id.
 * @param[in] sess	to retrieve the ID for.
 * @return A copy of the session id.
 */
uint8_t *fr_tls_cache_id(TALLOC_CTX *ctx, SSL_SESSION *sess)
{
	unsigned int	len;
	uint8_t const	*id;

	id = SSL_SESSION_get_id(sess, &len);
	if (unlikely(!id)) return NULL;

	return talloc_typed_memdup(ctx, id, len);
}

/** Retrieve session ID (in binary form), and assign it to a box
 *
 * @note Box will be reinitialised
 *
 * @param[out] out	Where to write the session ID.
 * @param[in] sess	to retrieve the ID for.
 */
static inline CC_HINT(always_inline, nonnull)
int fr_tls_cache_id_to_box_shallow(fr_value_box_t *out, SSL_SESSION *sess)
{
	unsigned int	len;
	uint8_t const	*id;

	id = SSL_SESSION_get_id(sess, &len);
	if (unlikely(!id)) return -1;

	fr_value_box_memdup_shallow(out, NULL, id, len, true);

	return 0;
}

/** Create a temporary boxed version of the session ID
 *
 * @param[out] _box to place on the stack.
 * @param[in] _sess to write to box.
 */
#define SESSION_ID(_box, _sess) \
fr_value_box_t _box; \
if (unlikely(fr_tls_cache_id_to_box_shallow(&_box, _sess) < 0)) fr_value_box_init_null(&_box)


/** Add an attribute specifying the session id for the operation to be performed with.
 *
 * Adds the following attributes to the request:
 *
 *	- &request.Session-Id
 *
 * Session identity will contain the binary session key used to create, retrieve
 * and delete cache entries related to the SSL session.
 *
 * @param[in] request		The current request.
 * @param[in] session_id	Identifier for the session.
 */
static inline CC_HINT(always_inline, nonnull(2))
void tls_cache_session_id_to_vp(request_t *request, uint8_t const *session_id)
{
	fr_pair_t	*vp;
	MEM(pair_update_request(&vp, attr_tls_session_id) >= 0);
	fr_pair_value_memdup_buffer(vp, session_id, true);
}

static inline CC_HINT(always_inline, nonnull(2))
void _tls_cache_load_state_reset(request_t *request, fr_tls_cache_t *cache, char const *func)
{
	if (cache->load.sess) {
		if (ROPTIONAL_ENABLED(RDEBUG_ENABLED3, DEBUG_ENABLED3)) {
			SESSION_ID(sess_id, cache->load.sess);
			ROPTIONAL(RDEBUG3, DEBUG3, "Session ID %pV - Freeing loaded session in %s", &sess_id, func);
		}

		SSL_SESSION_free(cache->load.sess);
		cache->load.sess = NULL;
	}
	cache->load.state = FR_TLS_CACHE_LOAD_INIT;
}
#define tls_cache_load_state_reset(_request, _cache) _tls_cache_load_state_reset(_request, _cache, __FUNCTION__)

static inline CC_HINT(always_inline, nonnull(2))
void _tls_cache_store_state_reset(request_t *request, fr_tls_cache_t *cache, char const *func)
{
	if (cache->store.sess) {
		if (ROPTIONAL_ENABLED(RDEBUG_ENABLED3, DEBUG_ENABLED3)) {
			SESSION_ID(sess_id, cache->store.sess);
			ROPTIONAL(RDEBUG3, DEBUG3, "Session ID %pV - Freeing session to store in %s", &sess_id, func);
		}
		SSL_SESSION_free(cache->store.sess);
		cache->store.sess = NULL;
	}
	cache->store.state = FR_TLS_CACHE_STORE_INIT;
}
#define tls_cache_store_state_reset(_request, _cache) _tls_cache_store_state_reset(_request, _cache, __FUNCTION__)

static inline CC_HINT(always_inline)
void _tls_cache_clear_state_reset(request_t *request, fr_tls_cache_t *cache, char const *func)
{
	if (cache->clear.id) {
		if (ROPTIONAL_ENABLED(RDEBUG_ENABLED3, DEBUG_ENABLED3)) {
			ROPTIONAL(RDEBUG3, DEBUG3, "Session ID %pV - Freeing session ID to clear in %s",
				  fr_box_octets_buffer(cache->clear.id), func);
		}
		TALLOC_FREE(cache->clear.id);
	}
	cache->clear.state = FR_TLS_CACHE_CLEAR_INIT;
}
#define tls_cache_clear_state_reset(_request, _cache) _tls_cache_clear_state_reset(_request, _cache, __FUNCTION__)

/** Serialize the session-state list and store it in the SSL_SESSION *
 *
 */
static int tls_cache_app_data_set(request_t *request, SSL_SESSION *sess, uint32_t resumption_type)
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
		SESSION_ID(sess_id, sess);

		RDEBUG2("Session ID %pV - Adding session-state[*] to data", &sess_id);
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
			SESSION_ID(sess_id, sess);

			RPERROR("Session ID %pV - Failed serialising session-state list", &sess_id);
			fr_dbuff_free_talloc(&dbuff);
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
		SESSION_ID(sess_id, sess);

		fr_tls_log(request, "Session ID %pV - Failed setting application data", &sess_id);
		return -1;
	}

	return 1;		/* successfully stored data */
}

static int tls_cache_app_data_get(request_t *request, SSL_SESSION *sess)
{
	uint8_t			*data;
	size_t			data_len;
	fr_dbuff_t		dbuff;
	fr_pair_list_t		tmp;

	/*
	 *	Extract the session-state list from the ticket.
	 */
	if (SSL_SESSION_get0_ticket_appdata(sess, (void **)&data, &data_len) != 1) {
		SESSION_ID(sess_id, sess);

		fr_tls_log(request, "Session ID %pV - Failed retrieving application data", &sess_id);
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
			SESSION_ID(sess_id, sess);

			fr_pair_list_free(&tmp);
			RPEDEBUG("Session-ID %pV - Failed decoding session-state", &sess_id);
			return -1;
		}
	}

	if (RDEBUG_ENABLED2) {
		SESSION_ID(sess_id, sess);

		RDEBUG2("Session-ID %pV - Restoring session-state[*]", &sess_id);
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
static void tls_cache_delete_request(SSL_SESSION *sess)
{
	fr_tls_session_t	*tls_session;
	fr_tls_cache_t		*tls_cache;
	request_t		*request;

	tls_session = talloc_get_type_abort(SSL_SESSION_get_ex_data(sess, FR_TLS_EX_INDEX_TLS_SESSION), fr_tls_session_t);

	if (!tls_session->cache) return;

	request = fr_tls_session_request(tls_session->ssl);
	tls_cache = tls_session->cache;

	/*
	 *	Request was cancelled just return without doing any work.
	 */
	if (unlang_request_is_cancelled(request)) return;

	fr_assert(tls_cache->clear.state == FR_TLS_CACHE_CLEAR_INIT);

	/*
	 *	Record the session to delete
	 */
	tls_cache->clear.id = fr_tls_cache_id(tls_cache, sess);
	if (!tls_cache->clear.id) {
		RWDEBUG("Error retrieving Session ID");
		return;
	}

	RDEBUG3("Session ID %pV - Requested session clear", fr_box_octets_buffer(tls_cache->clear.id));

	tls_cache->clear.state = FR_TLS_CACHE_CLEAR_REQUESTED;

	/*
	 *	We store a copy of the pointer for the session
	 *	in tls_session->session.  If the session is
	 *	being freed then this pointer must be invalid
	 *	so clear it to prevent crashes in other areas
	 *	of the code.
	 */
	if (tls_session->session == sess) tls_session->session = NULL;

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
static unlang_action_t tls_cache_load_result(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_tls_cache_t		*tls_cache = tls_session->cache;
	fr_pair_t		*vp;
	uint8_t const		*q, **p;
	SSL_SESSION		*sess;

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_tls_packet_type);
	if (!vp || (vp->vp_uint32 != enum_tls_packet_type_success->vb_uint32)) {
		RWDEBUG("Failed acquiring session data");
	error:
		tls_cache->load.state = FR_TLS_CACHE_LOAD_FAILED;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_tls_session_data);
	if (!vp) {
		RWDEBUG("No cached session found");
		goto error;
	}

	q = vp->vp_octets;	/* openssl will mutate q, so we can't use vp_octets directly */
	p = (unsigned char const **)&q;

	sess = d2i_SSL_SESSION(NULL, p, vp->vp_length);
	if (!sess) {
		fr_tls_log(request, "Failed loading persisted session");
		goto error;
	}

	if (RDEBUG_ENABLED3) {
		SESSION_ID(sess_id, sess);

		RDEBUG3("Session ID %pV - Read %zu bytes of data.  "
			"Session de-serialized successfully", &sess_id, vp->vp_length);
		SSL_SESSION_print(fr_tls_request_log_bio(request, L_DBG, L_DBG_LVL_3), sess);
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
	SSL_SESSION_set_ex_data(sess, FR_TLS_EX_INDEX_TLS_SESSION, fr_tls_session(tls_session->ssl));

	tls_cache->load.state = FR_TLS_CACHE_LOAD_RETRIEVED;
	tls_cache->load.sess = sess;	/* This is consumed in tls_cache_load_cb */

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
	fr_pair_t		*vp;
	unlang_action_t		ua;

	if (tls_cache->load.state != FR_TLS_CACHE_LOAD_REQUESTED) return UNLANG_ACTION_CALCULATE_RESULT;

	fr_assert(tls_cache->load.id);

	MEM(child = unlang_subrequest_alloc(request, dict_tls));
	request = child;

	/*
	 *	Setup the child request for loading
	 *	session resumption data.
	 */
	MEM(pair_prepend_request(&vp, attr_tls_packet_type) >= 0);
	vp->vp_uint32 = enum_tls_packet_type_load_session->vb_uint32;

	/*
	 *	Add the session identifier we're
	 *	trying to load.
	 */
	tls_cache_session_id_to_vp(child, tls_cache->load.id);

	/*
	 *	Allocate a child, and set it up to call
	 *      the TLS virtual server.
	 */
	ua = fr_tls_call_push(child, tls_cache_load_result, conf, tls_session, true);
	if (ua < 0) {
		talloc_free(child);
		tls_cache_load_state_reset(request, tls_cache);
		return UNLANG_ACTION_FAIL;
	}

	return ua;
}

/** Process the result of `store session { ... }`
 */
static unlang_action_t tls_cache_store_result(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_tls_cache_t		*tls_cache = tls_session->cache;
	fr_pair_t		*vp;

	tls_cache_store_state_reset(request, tls_cache);

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_tls_packet_type);
	if (vp && (vp->vp_uint32 == enum_tls_packet_type_success->vb_uint32)) {
		tls_cache->store.state = FR_TLS_CACHE_STORE_PERSISTED;	/* Avoid spurious clear calls */
	} else {
		RWDEBUG("Failed storing session data");
		tls_cache->store.state = FR_TLS_CACHE_STORE_INIT;
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
#if OPENSSL_VERSION_NUMBER >= 0x30400000L
	fr_time_t		expires = fr_time_from_sec((time_t)(SSL_SESSION_get_time_ex(sess) + SSL_get_timeout(sess)));
#else
	fr_time_t		expires = fr_time_from_sec((time_t)(SSL_SESSION_get_time(sess) + SSL_get_timeout(sess)));
#endif
	fr_time_t		now = fr_time();

	fr_assert(tls_cache->store.sess);
	fr_assert(tls_cache->store.state == FR_TLS_CACHE_STORE_REQUESTED);

	if (fr_time_lteq(expires, now)) {
		fr_value_box_t	id;
 		fr_tls_cache_id_to_box_shallow(&id, sess);

		RWDEBUG("Session ID %pV - Session has already expired, not storing", &id);
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Add the current session-state list
	 *	contents to the ssl-data
	 */
	rcode = tls_cache_app_data_set(request, sess, enum_tls_session_resumed_stateful->vb_uint32);
	if (rcode < 0) return UNLANG_ACTION_FAIL;

	if (rcode == 0) return UNLANG_ACTION_CALCULATE_RESULT;

	MEM(child = unlang_subrequest_alloc(request, dict_tls));
	request = child;

	/*
	 *	Setup the child request for storing
	 *	session resumption data.
	 */
	MEM(pair_prepend_request(&vp, attr_tls_packet_type) >= 0);
	vp->vp_uint32 = enum_tls_packet_type_store_session->vb_uint32;

	/*
	 *	Add the session identifier we're trying
	 *	to store.
	 */
	MEM(pair_update_request(&vp, attr_tls_session_id) >= 0);
	fr_pair_value_memdup_buffer_shallow(vp, fr_tls_cache_id(vp, sess), true);

	/*
	 *	How long the session has to live
	 */
	MEM(pair_update_request(&vp, attr_tls_session_ttl) >= 0);
	vp->vp_time_delta = fr_time_sub(expires, now);

	/*
	 *	Serialize the session
	 */
	len = i2d_SSL_SESSION(sess, NULL);	/* find out what length data we need */
	if (len < 1) {
		fr_value_box_t	id;
 		fr_tls_cache_id_to_box_shallow(&id, sess);

		/* something went wrong */
		fr_tls_strerror_printf(NULL);	/* Drain the OpenSSL error stack */
		RPWDEBUG("Session ID %pV - Serialisation failed, couldn't determine "
			 "required buffer length", &id);
	error:
		tls_cache_store_state_reset(request, tls_cache);
		talloc_free(child);
		return UNLANG_ACTION_FAIL;
	}

	MEM(pair_update_request(&vp, attr_tls_session_data) >= 0);
	MEM(data = talloc_array(vp, uint8_t, len));

	/* openssl mutates &p */
	p = data;
	ret = i2d_SSL_SESSION(sess, &p);	/* Serialize as ASN.1 */
	if (ret != len) {
		fr_value_box_t	id;
 		fr_tls_cache_id_to_box_shallow(&id, sess);

		fr_tls_strerror_printf(NULL);	/* Drain the OpenSSL error stack */
		RPWDEBUG("Session ID %pV - Serialisation failed", &id);
		talloc_free(data);
		goto error;
	}
	fr_pair_value_memdup_buffer_shallow(vp, data, true);

	/*
	 *	Allocate a child, and set it up to call
	 *      the TLS virtual server.
	 */
	ua = fr_tls_call_push(child, tls_cache_store_result, conf, tls_session, true);
	if (ua < 0) goto error;

	return ua;
}

/** Process the result of `clear session { ... }`
 */
static unlang_action_t tls_cache_clear_result(request_t *request, void *uctx)
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
	fr_pair_t	*vp;
	fr_tls_cache_t	*tls_cache = tls_session->cache;
	unlang_action_t	ua;

	fr_assert(tls_cache->clear.state == FR_TLS_CACHE_CLEAR_REQUESTED);
	fr_assert(tls_cache->clear.id);

	MEM(child = unlang_subrequest_alloc(request, dict_tls));
	request = child;

	/*
	 *	Setup the child request for loading
	 *	session resumption data.
	 */
	MEM(pair_prepend_request(&vp, attr_tls_packet_type) >= 0);
	vp->vp_uint32 = enum_tls_packet_type_clear_session->vb_uint32;

	/*
	 *	Add the session identifier we're
	 *	trying to load.
	 */
	tls_cache_session_id_to_vp(child, tls_cache->clear.id);

	/*
	 *	Allocate a child, and set it up to call
	 *      the TLS virtual server.
	 */
	ua = fr_tls_call_push(child, tls_cache_clear_result, conf, tls_session, true);
	if (ua < 0) {
		talloc_free(child);
		tls_cache_clear_state_reset(request, tls_cache);
		return UNLANG_ACTION_FAIL;
	}

	return ua;
}

/** Push a `store session { ... }` or `clear session { ... }` or `load session { ... }` depending on what operations are pending
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

	if (!tls_cache) return UNLANG_ACTION_CALCULATE_RESULT;	/* No caching allowed */

	/*
	 *	Load stateful session data
	 */
	if (tls_cache->load.state == FR_TLS_CACHE_LOAD_REQUESTED) {
		return tls_cache_load_push(request, tls_session);
	}

	/*
	 *	We only support a single session
	 *	ticket currently...
	 */
	if (tls_cache->clear.state == FR_TLS_CACHE_CLEAR_REQUESTED) {
		/*
		 *	Abort any pending store operations
		 *	if they were for the same ID as
		 *	we're now trying to clear.
		 */
		if (tls_cache->store.state == FR_TLS_CACHE_STORE_REQUESTED) {
			unsigned int	len;
			uint8_t const	*id;

			id = SSL_SESSION_get_id(tls_cache->store.sess, &len);
			if ((len == talloc_array_length(tls_cache->clear.id)) &&
			    (memcmp(tls_cache->clear.id, id, len) == 0)) {
				tls_cache_store_state_reset(request, tls_cache);
			}
		}

		return tls_cache_clear_push(request, conf, tls_session);
	}

	if (tls_cache->store.state == FR_TLS_CACHE_STORE_REQUESTED) {
		return tls_cache_store_push(request, conf, tls_session);
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
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
	unsigned int		id_len;
	uint8_t const		*id;

	/*
	 *	This functions should only be called once during the lifetime
	 *	of the tls_session, as the fields aren't re-populated on
	 *	resumption.
	 */
	tls_session = fr_tls_session(ssl);

	/*
	 *	If the session is TLS 1.3, then resumption will be handled by a
	 *	session ticket.  However, if this callback is defined, it still
	 *	gets called.
	 *	To avoid unnecessary entries in the stateful cache just return.
	 */
	if (tls_session->info.version == TLS1_3_VERSION) return 0;

	request = fr_tls_session_request(tls_session->ssl);
	tls_cache = tls_session->cache;

	/*
	 *	Request was cancelled, just get OpenSSL to
	 *	free the session data, and don't do any work.
	 */
	if (unlang_request_is_cancelled(request)) return 0;

	id = SSL_SESSION_get_id(sess, &id_len);
	RDEBUG3("Session ID %pV - Requested store", fr_box_octets(id, id_len));
	/*
	 *	Store the session blob and session id for writing
	 *	later, once all the authentication phases have completed.
	 */
	tls_cache->store.sess = sess;
	tls_cache->store.state = FR_TLS_CACHE_STORE_REQUESTED;

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
	case FR_TLS_CACHE_LOAD_INIT:
		fr_assert(!tls_cache->load.id);

		tls_cache->load.state = FR_TLS_CACHE_LOAD_REQUESTED;
		MEM(tls_cache->load.id = talloc_typed_memdup(tls_cache, (uint8_t const *)key, key_len));

		RDEBUG3("Requested session load - ID %pV", fr_box_octets_buffer(tls_cache->load.id));

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

	case FR_TLS_CACHE_LOAD_REQUESTED:
		fr_assert(0);				/* Called twice without attempting the load?! */
		tls_cache->load.state = FR_TLS_CACHE_LOAD_FAILED;
		break;

	case FR_TLS_CACHE_LOAD_RETRIEVED:
	{
		SSL_SESSION	*sess;

		TALLOC_FREE(tls_cache->load.id);

		RDEBUG3("Setting session data");

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
		if (tls_cache_app_data_get(request, tls_cache->load.sess) < 0) {
			REDEBUG("Denying session resumption via session-id");
		verify_error:
			/*
			 *	Request the session be deleted the next
			 *	time something calls cache action pending.
			 */
			tls_cache_delete_request(tls_cache->load.sess);
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
			SESSION_ID(sess_id, tls_cache->load.sess);

			RDEBUG3("Session ID %pV - Session ownership transferred to libssl", &sess_id);
			*copy = 0;
			tls_cache->load.sess = NULL;
		}
		return sess;
	}


	case FR_TLS_CACHE_LOAD_FAILED:
		RDEBUG3("Session data load failed");
		break;
	}

	TALLOC_FREE(tls_cache->load.id);
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
	/*
	 *	Not sure why this happens, but sometimes SSL_SESSION *s
	 *	make it here without the correct ex data.
	 *
	 *	Maybe it's one OpenSSL created internally?
	 */
	if (!SSL_SESSION_get_ex_data(sess, FR_TLS_EX_INDEX_TLS_SESSION)) return;
	tls_cache_delete_request(sess);
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

/** Prevent a pending TLS session being persisted, and clear any resumed sessions
 *
 * Usually called if authentication has failed for some reason.
 *
 * Will clear any serialized data out of the tls_session structure
 * and should result in tls_cache_delete_cb being called.
 *
 * @note Calling this function will immediately free the memory used
 *   by the session, but not the external persisted copy of the
 *   session.  To clear the persisted copy #fr_tls_cache_pending_push
 *   must be called in a place where the caller is prepared to yield.
 *   In most cases this means whether the handshake is a success or
 *   failure, the last thing the caller of the TLS code should do
 *   is set the result, and call #fr_tls_cache_pending_push.
 *
 * @param[in] request		to use for running any async cache actions.
 * @param[in] tls_session	on which to prevent resumption.
 */
void fr_tls_cache_deny(request_t *request, fr_tls_session_t *tls_session)
{
	fr_tls_cache_t *tls_cache = tls_session->cache;
	bool tmp_bind = !fr_tls_session_request_bound(tls_session->ssl);

	/*
	 *	This is necessary to allow this function to
	 *	be called inside and outside of OpenSSL handshake
	 *	code.
	 */
	if (tmp_bind) {
		fr_tls_session_request_bind(tls_session->ssl, request);
	/*
	 *	If there's already a request bound, it better be
	 *      the one passed to this function.
	 */
	} else {
		fr_assert(fr_tls_session_request(tls_session->ssl) == request);
	}

	/*
	 *	SSL_CTX_remove_session frees the previously loaded
	 *	session in tls_session. If the reference count reaches zero
	 *	the SSL_CTX_sess_remove_cb is called, which in our code is
	 *	tls_cache_delete_cb.
	 *
	 *	tls_cache_delete_cb calls tls_cache_delete_request
	 *	to record the ID of tls_session->session
	 *	in our pending cache state structure.
	 *
	 *	tls_cache_delete_request does NOT immediately call the
	 *	`cache clear {}` section as that must be done in a code area
	 *	which is prepared to yield.
	 *
	 *	#fr_tls_cache_pending_push MUST be called to actually
	 *	clear external data.
	 */
	if (tls_session->session) SSL_CTX_remove_session(tls_session->ctx, tls_session->session);
	tls_session->allow_session_resumption = false;

	/*
	 *	Clear any pending store requests.
	 */
	tls_cache_store_state_reset(fr_tls_session_request(tls_session->ssl), tls_cache);

	/*
	 *	Unbind the request last...
	 */
	if (tmp_bind) fr_tls_session_request_unbind(tls_session->ssl);
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
		return 0;
	}

	sess = SSL_get_session(ssl);
	if (!sess) {
		REDEBUG("Failed retrieving session in session generation callback");
		return 0;
	}

	if (tls_cache_app_data_set(request, sess, enum_tls_session_resumed_stateless->vb_uint32) < 0) return 0;

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
	 */
	if (tls_cache_app_data_get(request, sess) < 0) {
		REDEBUG("Denying session resumption via session-ticket");
		return SSL_TICKET_RETURN_IGNORE_RENEW;
	}

	if (conf->virtual_server && tls_session->verify_client_cert) {
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
int fr_tls_cache_ctx_init(SSL_CTX *ctx, fr_tls_cache_conf_t const *cache_conf)
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
		 */
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL);

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

		if (!(cache_conf->mode & FR_TLS_CACHE_STATEFUL)) tls_cache_disable_statefull_resumption(ctx);

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

			talloc_free(key_buff);
			goto kdf_error;
		}
		EVP_PKEY_CTX_free(pkey_ctx);

		fr_assert(talloc_array_length(key_buff) == key_len);
		/*
		 *	Ensure the same keys are used across all threads
		 */
		if (SSL_CTX_set_tlsext_ticket_keys(ctx,
						   key_buff, key_len) != 1) {
			fr_tls_strerror_printf(NULL);
			PERROR("Failed setting session ticket keys");
			return -1;
		}

		DEBUG3("Derived session-ticket-key:");
		HEXDUMP3(key_buff, key_len, NULL);
		talloc_free(key_buff);

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
			return -1;
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
