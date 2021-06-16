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
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls - "

#include <freeradius-devel/internal/internal.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/util/debug.h>

#include "attrs.h"
#include "base.h"
#include "cache.h"
#include "log.h"
#include "missing.h"

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
static inline CC_HINT(always_inline)
void tls_cache_session_id_to_vp(request_t *request, uint8_t const *session_id)
{
	fr_pair_t	*vp;
	MEM(pair_update_request(&vp, attr_tls_session_id) >= 0);
	fr_pair_value_memdup_buffer(vp, session_id, true);
}

static inline CC_HINT(always_inline)
void tls_cache_load_state_reset(fr_tls_cache_t *cache)
{
	if (cache->load.sess) {
		SSL_SESSION_free(cache->load.sess);
		cache->store.sess = NULL;
	}
	cache->load.state = FR_TLS_CACHE_LOAD_INIT;
}

static inline CC_HINT(always_inline)
void tls_cache_store_state_reset(fr_tls_cache_t *cache)
{
	if (cache->store.sess) {
		SSL_SESSION_free(cache->store.sess);
		cache->store.sess = NULL;
	}
	cache->store.state = FR_TLS_CACHE_STORE_INIT;
}

static inline CC_HINT(always_inline)
void tls_cache_clear_state_reset(fr_tls_cache_t *cache)
{
	TALLOC_FREE(cache->clear.id);
	cache->clear.state = FR_TLS_CACHE_CLEAR_INIT;
}

/** Process the result of `cache store { ... }`
 */
static unlang_action_t tls_cache_store_result(UNUSED rlm_rcode_t *p_result, UNUSED int *priority,
					      request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_tls_cache_t		*tls_cache = tls_session->cache;

	tls_cache_store_state_reset(tls_cache);

	switch (tls_cache->store.rcode) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		tls_cache->store.state = FR_TLS_CACHE_STORE_PERSISTED;	/* Avoid spurious clear calls */
		break;

	default:	/* Every other rcode indicates the cache store ailed */
		RWDEBUG("Failed storing session data");
		tls_cache->store.state = FR_TLS_CACHE_STORE_INIT;
		break;
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Push a `cache store { ... }` call into the current request, using a subrequest
 *
 * @param[in] request		The current request.
 * @param[in] conf		TLS configuration.
 * @Param[in] tls_session	The current TLS session.
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

	uint8_t			*p, *data = NULL;

	request_t		*child;
	fr_pair_t		*vp;
	SSL_SESSION		*sess = tls_session->cache->store.sess;

	fr_assert(tls_cache->store.sess);
	fr_assert(tls_cache->store.state == FR_TLS_CACHE_STORE_REQUESTED);

	MEM(child = unlang_subrequest_alloc(request, dict_tls));
	request = child;

	/*
	 *	Setup the child request for storing
	 *	session resumption data.
	 */
	MEM(pair_prepend_request(&vp, attr_tls_packet_type) >= 0);
	vp->vp_uint32 = enum_tls_packet_type_cache_store->vb_uint32;

	/*
	 *	Add the session identifier we're trying
	 *	to store.
	 */
	MEM(pair_update_request(&vp, attr_tls_session_id) >= 0);
	fr_pair_value_memdup_buffer_shallow(vp, fr_tls_cache_id(vp, sess), true);

	/*
	 *	Serialize the session
	 */
	len = i2d_SSL_SESSION(sess, NULL);	/* find out what length data we need */
	if (len < 1) {
		/* something went wrong */
		fr_tls_log_strerror_printf(NULL);	/* Drain the OpenSSL error stack */
		RPWDEBUG("Session serialisation failed, couldn't determine required buffer length");
	error:
		tls_cache_store_state_reset(tls_cache);
		talloc_free(child);
		return UNLANG_ACTION_FAIL;
	}

	MEM(pair_update_request(&vp, attr_tls_session_data) >= 0);
	MEM(data = talloc_array(vp, uint8_t, len));
	/* openssl mutates &p */
	p = data;
	ret = i2d_SSL_SESSION(sess, &p);	/* Serialize as ASN.1 */
	if (ret != len) {
		fr_tls_log_strerror_printf(NULL);	/* Drain the OpenSSL error stack */
		RPWDEBUG("Session serialisation failed");
		talloc_free(data);
		goto error;
	}
	fr_pair_value_memdup_buffer_shallow(vp, data, true);

	/*
	 *	Allocate a child, and set it up to call
	 *      the TLS virtual server.
	 */
	if (fr_tls_call_push(&tls_cache->store.rcode, child, tls_cache_store_result,
			     request, conf, tls_session) < 0) goto error;

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Process the result of `cache clear { ... }`
 */
static unlang_action_t tls_cache_clear_result(UNUSED rlm_rcode_t *p_result, UNUSED int *priority,
					      request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_tls_cache_t		*tls_cache = tls_session->cache;

	tls_cache_clear_state_reset(tls_cache);

	switch (tls_cache->clear.rcode) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
	case RLM_MODULE_NOTFOUND:
	case RLM_MODULE_NOOP:
		return UNLANG_ACTION_CALCULATE_RESULT;

	default:
		RWDEBUG("Failed deleting session data - security may be compromised");
		return UNLANG_ACTION_CALCULATE_RESULT;
	}
}

/** Push a `cache clear { ... }` call into the current request, using a subrequest
 *
 * @param[in] request		The current request.
 * @param[in] conf		TLS configuration.
 * @Param[in] tls_session	The current TLS session.
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

	fr_assert(tls_cache->clear.state == FR_TLS_CACHE_CLEAR_REQUESTED);
	fr_assert(tls_cache->clear.id);

	MEM(child = unlang_subrequest_alloc(request, dict_tls));
	request = child;

	/*
	 *	We never managed to store the session
	 *	so don't bother trying to clear it.
	 */
	if (tls_cache->store.state != FR_TLS_CACHE_STORE_PERSISTED) {
		tls_cache_clear_state_reset(tls_cache);
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	Setup the child request for loading
	 *	session resumption data.
	 */
	MEM(pair_prepend_request(&vp, attr_tls_packet_type) >= 0);
	vp->vp_uint32 = enum_tls_packet_type_cache_clear->vb_uint32;

	/*
	 *	Add the session identifier we're
	 *	trying to load.
	 */
	tls_cache_session_id_to_vp(child, tls_cache->clear.id);

	/*
	 *	Allocate a child, and set it up to call
	 *      the TLS virtual server.
	 */
	if (fr_tls_call_push(&tls_cache->clear.rcode, child, tls_cache_clear_result,
			     request, conf, tls_session) < 0) {
		talloc_free(child);
		tls_cache_clear_state_reset(tls_cache);
		return UNLANG_ACTION_FAIL;
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Push a `cache clear { ... }` or `cache load { ... }` depending on what operations are pending
 *
 * @param[in] request		The current request.
 * @Param[in] tls_session	The current TLS session.
 * @return
 *	- 1 on noop.
 *	- 0 on success.
 *      - -1 on failure.
 */
int fr_tls_cache_pending_push(request_t *request, fr_tls_session_t *tls_session)
{
	fr_tls_cache_t *tls_cache = tls_session->cache;
	fr_tls_conf_t *conf = fr_tls_session_conf(tls_session->ssl);

	if (!tls_cache) return 1;	/* No caching allowed */

	/*
	 *	We only support a single session
	 *	ticket currently...
	 */
	if (tls_cache->clear.state == FR_TLS_CACHE_CLEAR_REQUESTED) {
		/*
		 *	Abort any pending store operations
		 */
		if (tls_cache->store.state == FR_TLS_CACHE_STORE_REQUESTED) tls_cache_store_state_reset(tls_cache);
		return tls_cache_clear_push(request, conf, tls_session);
	}

	if (tls_cache->store.state == FR_TLS_CACHE_STORE_REQUESTED) {
		return tls_cache_store_push(request, conf, tls_session);
	}

	return 1;
}

/** Process the result of `cache load { ... }`
 */
static unlang_action_t tls_cache_load_result(UNUSED rlm_rcode_t *p_result, UNUSED int *priority,
					     request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_tls_cache_t		*tls_cache = tls_session->cache;
	fr_pair_t		*vp;
	uint8_t const		*q, **p;
	SSL_SESSION		*sess;

	switch (tls_cache->load.rcode) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		break;

	default:	/* Every other rcode indicates the cache load failed */
		RWDEBUG("Failed acquiring session data");
	error:
		tls_cache->load.state = FR_TLS_CACHE_LOAD_FAILED;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	vp = fr_pair_find_by_da(&request->session_state_pairs, attr_tls_session_data, 0);
	if (!vp) {
		RWDEBUG("No cached session found");
		goto error;
	}

	q = vp->vp_octets;	/* openssl will mutate q, so we can't use vp_octets directly */
	p = (unsigned char const **)&q;

	sess = d2i_SSL_SESSION(NULL, p, vp->vp_length);
	if (!sess) {
		fr_tls_log_error(request, "Failed loading persisted session");
		goto error;
	}
	RDEBUG3("Read %zu bytes of session data.  Session deserialized successfully", vp->vp_length);

	/*
	 *	OpenSSL's API is very inconsistent.
	 *
	 *	We need to set external data here, so it can be
	 *	retrieved in fr_tls_cache_delete.
	 *
	 *	ex_data is not serialised in i2d_SSL_SESSION
	 *	so we don't have to bother unsetting it.
	 */
	SSL_SESSION_set_ex_data(sess, FR_TLS_EX_INDEX_TLS_SESSION,
				SSL_get_ex_data(tls_session->ssl, FR_TLS_EX_INDEX_TLS_SESSION));

	tls_cache->load.state = FR_TLS_CACHE_LOAD_RETRIEVED;
	tls_cache->load.sess = sess;	/* This is consumed in tls_cache_load_cb */

#if 0
	/*
	 *	We set the session here temporarily so that
	 *	the certificate validation can run.
	 *
	 *      FIXME - Do ASYNC session cert validation.
	 */
	SSL_set_session(ssl, sess);		/* Increases ref count */

	if (fr_tls_validate_client_cert_chain(ssl) != 1) {
		RWDEBUG("Validation failed, forcefully expiring resumed session");
		SSL_SESSION_set_timeout(sess, 0);
	}

	SSL_remove_session(ssl, sess);		/* Decreases ref count */
#endif

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Push a `cache load { ... }` call into the current request, using a subrequest
 *
 * @param[in] request		The current request.
 * @Param[in] tls_session	The current TLS session.
 * @return
 *      - UNLANG_ACTION_CALCULATE_RESULT on noop.
 *	- UNLANG_ACTION_PUSHED_CHILD on success.
 *      - UNLANG_ACTION_FAIL on failure.
 */
unlang_action_t fr_tls_cache_load_push(request_t *request, fr_tls_session_t *tls_session)
{
	fr_tls_cache_t		*tls_cache = tls_session->cache;
	fr_tls_conf_t		*conf = fr_tls_session_conf(tls_session->ssl);
	request_t		*child;
	fr_pair_t		*vp;

	if (tls_cache->load.state != FR_TLS_CACHE_LOAD_REQUESTED) return UNLANG_ACTION_CALCULATE_RESULT;

	fr_assert(tls_cache->load.id);

	MEM(child = unlang_subrequest_alloc(request, dict_tls));
	request = child;

	/*
	 *	Setup the child request for loading
	 *	session resumption data.
	 */
	MEM(pair_prepend_request(&vp, attr_tls_packet_type) >= 0);
	vp->vp_uint32 = enum_tls_packet_type_cache_load->vb_uint32;

	/*
	 *	Add the session identifier we're
	 *	trying to load.
	 */
	tls_cache_session_id_to_vp(child, tls_cache->load.id);

	/*
	 *	Allocate a child, and set it up to call
	 *      the TLS virtual server.
	 */
	if (fr_tls_call_push(&tls_cache->load.rcode, child, tls_cache_load_result,
			     request, conf, tls_session) < 0) {
		talloc_free(child);
		tls_cache_load_state_reset(tls_cache);
		return UNLANG_ACTION_FAIL;
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
	tls_session = talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_TLS_SESSION), fr_tls_session_t);
	request = fr_tls_session_request(tls_session->ssl);
	tls_cache = tls_session->cache;

	id = SSL_SESSION_get_id(sess, &id_len);
	RDEBUG3("Requested session store - ID %pV", fr_box_octets(id, id_len));
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
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
				      unsigned char const *key,
#else
				      unsigned char *key,
#endif
				      int key_len, int *copy)
{
	fr_tls_session_t	*tls_session;
	fr_tls_cache_t		*tls_cache;
	request_t		*request;
	SSL_SESSION		*sess;

	tls_session = talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_TLS_SESSION), fr_tls_session_t);
	request = fr_tls_session_request(tls_session->ssl);
	tls_cache = tls_session->cache;

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
	 *	   retrieved during the session cache load.
	 *	3. We call SSL_read() again, which in turn calls this callback
	 *	   again.
	 */
again:
	switch (tls_cache->load.state) {
	case FR_TLS_CACHE_LOAD_INIT:
		fr_assert(!tls_cache->load.id);

		tls_cache->load.state = FR_TLS_CACHE_LOAD_REQUESTED;
		MEM(tls_cache->load.id = talloc_memdup(tls_cache, (uint8_t const *)key, key_len));

		RDEBUG3("Requested session load - ID %pV", fr_box_octets_buffer(tls_cache->load.id));
		ASYNC_pause_job();
		goto again;

	case FR_TLS_CACHE_LOAD_REQUESTED:
		fr_assert(0);				/* Called twice without attempting the load?! */
		tls_cache->load.state = FR_TLS_CACHE_LOAD_FAILED;
		break;

	case FR_TLS_CACHE_LOAD_RETRIEVED:
		TALLOC_FREE(tls_cache->load.id);

		RDEBUG3("Setting session data");

		*copy = 0;
		tls_cache->load.state = FR_TLS_CACHE_LOAD_INIT;	/* Reset state */
		sess = tls_cache->load.sess;
		tls_cache->load.sess = NULL;
		return sess;

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
	fr_tls_session_t	*tls_session;
	fr_tls_cache_t		*tls_cache;
	request_t		*request;

	tls_session = talloc_get_type_abort(SSL_SESSION_get_ex_data(sess, FR_TLS_EX_INDEX_TLS_SESSION), fr_tls_session_t);

	if (!tls_session->cache) return;

	request = fr_tls_session_request(tls_session->ssl);
	tls_cache = tls_session->cache;

	fr_assert(tls_cache->clear.state == FR_TLS_CACHE_CLEAR_INIT);

	RDEBUG3("Requested session delete - ID %pV", fr_box_octets_buffer(tls_cache->clear.id));

	/*
	 *	Record the session to delete
	 */
	tls_cache->clear.id = fr_tls_cache_id(tls_cache, sess);
	if (!tls_cache->clear.id) {
		RWDEBUG("Error retrieving Session ID");
		return;
	}

	tls_cache->clear.state = FR_TLS_CACHE_CLEAR_REQUESTED;
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
int fr_tls_cache_disable_cb(SSL *ssl,
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			    UNUSED
#endif
			    int is_forward_secure)
{
	request_t		*request;

	fr_tls_session_t	*tls_session;
	fr_pair_t		*vp;

	tls_session = talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_TLS_SESSION), fr_tls_session_t);
	request = fr_tls_session_request(tls_session->ssl);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	{
		fr_tls_conf_t *conf;

		conf = talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF), fr_tls_conf_t);
		if (conf->cache.require_extms && (SSL_get_extms_support(tls_session->ssl) != 1)) {
			RDEBUG2("Client does not support the Extended Master Secret extension, "
				"denying session resumption");
			goto disable;
		}

		if (conf->cache.require_pfs && !is_forward_secure) {
			RDEBUG2("Cipher suite is not forward secure, denying session resumption");
			goto disable;
		}
	}
#endif

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

	vp = fr_pair_find_by_da(&request->control_pairs, attr_allow_session_resumption, 0);
	if (vp && (vp->vp_uint32 == 0)) {
		RDEBUG2("&control.Allow-Session-Resumption == no, denying session resumption");
	disable:
		SSL_CTX_remove_session(tls_session->ctx, tls_session->session);
		tls_session->allow_session_resumption = false;
		return 1;
	}

	RDEBUG2("Allowing session-resumption");

	return 0;
}

/** Prevent a TLS session from being cached
 *
 * Usually called if the session has failed for some reason.
 *
 * Will clear any serialized data out of the tls_session structure
 * and should result in tls_cache_delete_cb being called.
 *
 * @param[in] tls_session on which to prevent resumption.
 */
void fr_tls_cache_deny(fr_tls_session_t *tls_session)
{
	fr_tls_cache_t *tls_cache = tls_session->cache;

	/*
	 *	Even for 1.1.0 we don't know when this function
	 *	will be called, so better to remove the session
	 *	directly.
	 */
	if (tls_session->session) SSL_CTX_remove_session(tls_session->ctx, tls_session->session);
	tls_session->allow_session_resumption = false;
	tls_cache_store_state_reset(tls_cache);
}

/** Cleanup any memory allocated by OpenSSL
 */
static int _tls_cache_free(fr_tls_cache_t *tls_cache)
{
	tls_cache_load_state_reset(tls_cache);
	tls_cache_store_state_reset(tls_cache);

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

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	/*
	 *	This controls the number of stateful or stateless
	 *	tickets generated with TLS 1.3.  In OpenSSL 1.1.0
	 *	it's also required to disable sending session tickets,
	 *	SSL_SESS_CACHE_OFF is not good enough.
	 */
	SSL_CTX_set_num_tickets(ctx, 0);
#endif
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
	ssize_t			slen;
	fr_dbuff_t		dbuff;
	fr_dbuff_uctx_talloc_t	tctx;
	fr_dcursor_t		dcursor;
	fr_pair_t		*vp;
	int			ret;

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

	RDEBUG2("Adding &session-state[*] to session-ticket");
	RINDENT();
	log_request_pair_list(L_DBG_LVL_2, request, NULL, &request->session_state_pairs, NULL);
	REXDENT();

	/*
	 *	Absolute maximum is `0..2^16-1`.
	 *
	 *	We leave OpenSSL 2k to add anything else
	 */
	fr_dbuff_init_talloc(NULL, &dbuff, &tctx, 1024, 1024 * 62);

	/*
	 *	Encode the session-state contents and
	 *      add it to the ticket.
	 */
	for (vp = fr_dcursor_init(&dcursor, &request->session_state_pairs);
	     vp;
	     vp = fr_dcursor_current(&dcursor)) {
		slen = fr_internal_encode_pair(&dbuff, &dcursor, NULL);
		if (slen < 0) {
			RPERROR("Failed serialising session-state list");
			fr_dbuff_free_talloc(&dbuff);
			return 0;
		}
	}

	if (fr_cond_assert(fr_dbuff_start(&dbuff) != NULL)) {	/* check to quiet clang scan */
		RHEXDUMP4(fr_dbuff_start(&dbuff), fr_dbuff_used(&dbuff), "session-ticket application data");
	}

	/*
	 *	Pass the serialized session-state list
	 *	over to OpenSSL.
	 */
	ret = SSL_SESSION_set1_ticket_appdata(sess, fr_dbuff_start(&dbuff), fr_dbuff_used(&dbuff));
	fr_dbuff_free_talloc(&dbuff);	/* OpenSSL memdups the data */
	if (ret != 1) {
		fr_tls_log_error(request, "Failed setting application data for session-ticket");
		return 0;
	}

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
	fr_tls_cache_conf_t	*tls_cache_conf = arg;	/* Not talloced */
	request_t		*request;
	uint8_t			*data;
	size_t			data_len;
	fr_dbuff_t		dbuff;
	fr_pair_list_t		tmp;
	fr_dcursor_t		cursor;

	request = fr_tls_session_request(ssl);

	if (!tls_session->allow_session_resumption ||
	    (!(tls_cache_conf->mode & FR_TLS_CACHE_STATELESS))) {
		RDEBUG2("Session resumption not enabled for this TLS session, denying session resumption");
	    	return SSL_TICKET_RETURN_IGNORE;
	}

	switch (status) {
	case SSL_TICKET_EMPTY:
	case SSL_TICKET_NO_DECRYPT:
		return SSL_TICKET_RETURN_IGNORE_RENEW;	/* Send a new ticket */

	case SSL_TICKET_SUCCESS:
		if (!fr_tls_session_request_bound(ssl)) return SSL_TICKET_RETURN_USE;
		break;

	case SSL_TICKET_SUCCESS_RENEW:
		if (!fr_tls_session_request_bound(ssl)) return SSL_TICKET_RETURN_USE_RENEW;
		break;
	}

	/*
	 *	Extract the session-state list
	 *	from the ticket.
	 */
	if (SSL_SESSION_get0_ticket_appdata(sess, (void **)&data, &data_len) != 1) {
		fr_tls_log_error(request, "Failed retrieving application data from session-ticket, "
				 "denying session resumption");
		return SSL_TICKET_RETURN_IGNORE_RENEW;
	}

	fr_pair_list_init(&tmp);
	fr_dcursor_init(&cursor, &tmp);
	fr_dbuff_init(&dbuff, data, data_len);

	RHEXDUMP4(fr_dbuff_start(&dbuff), fr_dbuff_len(&dbuff), "session-ticket application data");

	/*
	 *	Decode the session-state data
	 *	into a temporary list.
	 *
	 *	It's very important that we
	 *	decode _all_ attributes, or
	 *	disallow session resumption.
	 */
	while (fr_dbuff_remaining(&dbuff) > 0) {
		if (fr_internal_decode_pair_dbuff(request->session_state_ctx, &cursor,
					    	  request->dict, &dbuff, NULL) < 0) {
			fr_pair_list_free(&tmp);
			RPEDEBUG("Failed decoding session-state, denying session resumption");
			return SSL_TICKET_RETURN_IGNORE_RENEW;
		}
	}

	RDEBUG2("Restoring &session-state[*] from session-ticket");
	RINDENT();
	log_request_pair_list(L_DBG_LVL_2, request, NULL, &tmp, "&session-state.");
	REXDENT();

	fr_pair_list_append(&request->session_state_pairs, &tmp);

	/*
	 *	TODO - Run TLS certificate recv { ... } section
	 */

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
		SSL_CTX_set_timeout(ctx, cache_conf->lifetime);

		/*
		 *	Disables stateless session tickets for TLS 1.3.
		 */
		if (!(cache_conf->mode & FR_TLS_CACHE_STATELESS)) {
			tls_cache_disable_stateless_resumption(ctx);
			break;
		}
		FALL_THROUGH;

	case FR_TLS_CACHE_STATELESS:
		if (!(cache_conf->mode & FR_TLS_CACHE_STATEFUL)) tls_cache_disable_statefull_resumption(ctx);

		/*
		 *	Ensure the same keys are used across all threads
		 */
		if (SSL_CTX_set_tlsext_ticket_keys(ctx,
						   UNCONST(uint8_t *, cache_conf->session_ticket_key_rand),
						   sizeof(cache_conf->session_ticket_key_rand)) != 1) {
			fr_tls_log_strerror_printf(NULL);
			PERROR("Failed setting session ticket keys");
			return -1;
		}

		/*
		 *	These callbacks embed and extract the
		 *	session-state list from the session-ticket.
		 */
		if (SSL_CTX_set_session_ticket_cb(ctx,
						  tls_cache_session_ticket_app_data_set,
						  tls_cache_session_ticket_app_data_get,
						  UNCONST(fr_tls_cache_conf_t *, cache_conf)) != 1) {
			fr_tls_log_strerror_printf(NULL);
			PERROR("Failed setting session ticket callbacks");
		}

		/*
		 *	Stateless resumption is enabled by default when
		 *	the TLS ctx is created, but OpenSSL sends too
		 *	many session tickets by default (2), and we only
		 *      need one.
		 */
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
		SSL_CTX_set_num_tickets(ctx, 1);
#endif
		break;
	}

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	SSL_CTX_set_not_resumable_session_callback(ctx, fr_tls_cache_disable_cb);
#endif
	SSL_CTX_set_quiet_shutdown(ctx, 1);

	return 0;
}
#endif /* WITH_TLS */
