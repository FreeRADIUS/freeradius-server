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
 * @file tls/ticket_stateless.c
 * @brief Stateless TLS session tickets, and the `encode session` and `decode session` sections
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
#include <openssl/kdf.h>

/** Resume after processing `encode session { ... }` or `decode session { ... }`
 *
 * Check the result and return success / fail depending.
 */
static unlang_action_t tls_ticket_stateless_resume(request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_pair_t		*vp;

	fr_assert((tls_session->ticket == FR_TLS_TICKET_STATELESS_ENCODE_REQUESTED) ||
		  (tls_session->ticket == FR_TLS_TICKET_STATELESS_DECODE_REQUESTED));

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_tls_packet_type);
	if (!vp || (vp->vp_uint32 != enum_tls_packet_type_success->vb_uint32)) {
		tls_session->ticket = FR_TLS_TICKET_STATELESS_FAILED;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	tls_session->ticket = FR_TLS_TICKET_STATELESS_SUCCESS;

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
static unlang_action_t tls_ticket_stateless_push(request_t *request, fr_tls_session_t *tls_session,
					     uint32_t packet_type)
{
	fr_tls_conf_t	*conf = fr_tls_session_conf(tls_session->ssl);
	request_t	*child;
	unlang_action_t	ua;

	fr_assert(conf->virtual_server);

	MEM(child = tls_subrequest_alloc(request, packet_type, &tls_session->session_id));

	fr_tls_session_extra_pairs_copy_to_child(child, tls_session);

	ua = fr_tls_call_push(child, tls_ticket_stateless_resume, conf, tls_session, false);
	if (ua == UNLANG_ACTION_FAIL) {
		fr_tls_log_error("Failed calling TLS virtual server");
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
unlang_action_t fr_tls_ticket_stateless_pending_push(request_t *request, fr_tls_session_t *tls_session)
{
	switch (tls_session->ticket) {
	case FR_TLS_TICKET_STATELESS_ENCODE_REQUESTED:
		return tls_ticket_stateless_push(request, tls_session,
					     enum_tls_packet_type_encode_session->vb_uint32);

	case FR_TLS_TICKET_STATELESS_DECODE_REQUESTED:
		return tls_ticket_stateless_push(request, tls_session,
					     enum_tls_packet_type_decode_session->vb_uint32);

	default:
		return UNLANG_ACTION_CALCULATE_RESULT;
	}
}

/** Request `encode session { ... }`, and tell the handshake the section is pending
 */
static inline CC_HINT(always_inline) void tls_ticket_stateless_encode_request(fr_tls_session_t *tls_session)
{
	tls_session->ticket = FR_TLS_TICKET_STATELESS_ENCODE_REQUESTED;
	TLS_PENDING_SET(tls_session, FR_TLS_PENDING_STATELESS_TICKET);
}

/** Request `decode session { ... }`, and tell the handshake the section is pending
 */
static inline CC_HINT(always_inline) void tls_ticket_stateless_decode_request(fr_tls_session_t *tls_session)
{
	tls_session->ticket = FR_TLS_TICKET_STATELESS_DECODE_REQUESTED;
	TLS_PENDING_SET(tls_session, FR_TLS_PENDING_STATELESS_TICKET);
}

/** Pause the handshake for `encode session { ... }` or `decode session { ... }`, and read the result
 *
 * We can't run the interpreter inside of a callback, so the caller records
 * what we want to do, and this function tells OpenSSL to pause its
 * processing.  We then return to session.c, which determines that there's
 * work to do, pushes the section, runs it, and calls us again.  That resumes
 * after the ASYNC_pause_job() call.
 *
 * @param[in] request		bound to the session.
 * @param[in] tls_session	the ticket belongs to.
 * @param[in] name		of the section, for the log.
 * @param[in] error		to record when the section does not return success.
 * @return
 *	- true if the section ran and approved the session-state list.
 *	- false if it did not, or if it could not be run at all.
 */
static inline CC_HINT(always_inline)
bool tls_ticket_stateless_section_run(request_t *request, fr_tls_session_t *tls_session,
				      char const *name, uint32_t error)
{
	/*
	 *	Sections are only allowed during the handshake, as
	 *	with certificate re-validation.  See the FIXME in
	 *	tls_ticket_stateless_app_data_get().
	 */
	if (unlikely(!tls_session->can_pause)) {
		fr_assert_msg("Unexpected call to %s. "
			      "tls_session_async_handshake_cont must be in call stack", __FUNCTION__);
		tls_session->ticket = FR_TLS_TICKET_STATELESS_INIT;
		return false;
	}

	ASYNC_pause_job();

	/*
	 *	If the request was cancelled, reset the ticket state
	 *	so that we don't do anything.
	 */
	if (unlang_request_is_cancelled(request)) {
		tls_session->ticket = FR_TLS_TICKET_STATELESS_INIT;
		return false;
	}

	if (tls_session->ticket != FR_TLS_TICKET_STATELESS_SUCCESS) {
		REDEBUG("`%s` did not return success", name);
		fr_tls_session_error_add(request, error);
		tls_session->ticket = FR_TLS_TICKET_STATELESS_INIT;
		return false;
	}

	tls_session->ticket = FR_TLS_TICKET_STATELESS_INIT;

	return true;
}

/** Run `encode session { ... }` from inside an OpenSSL callback
 *
 * @param[in] request		bound to the session.
 * @param[in] tls_session	the ticket belongs to.
 * @return
 *	- true if the section ran and approved the session-state list.
 *	- false if it did not, or if it could not be run at all.
 */
static bool tls_ticket_stateless_encode_run(request_t *request, fr_tls_session_t *tls_session)
{
	fr_assert(tls_session->ticket == FR_TLS_TICKET_STATELESS_INIT);

	tls_ticket_stateless_encode_request(tls_session);

	return tls_ticket_stateless_section_run(request, tls_session, "encode session",
						FR_ERROR_VALUE_ENCODE_SESSION_FAILED);
}

/** Run `decode session { ... }` from inside an OpenSSL callback
 *
 * @param[in] request		bound to the session.
 * @param[in] tls_session	the ticket belongs to.
 * @return
 *	- true if the section ran and approved the session-state list.
 *	- false if it did not, or if it could not be run at all.
 */
static bool tls_ticket_stateless_decode_run(request_t *request, fr_tls_session_t *tls_session)
{
	fr_assert(tls_session->ticket == FR_TLS_TICKET_STATELESS_INIT);

	tls_ticket_stateless_decode_request(tls_session);

	return tls_ticket_stateless_section_run(request, tls_session, "decode session",
						FR_ERROR_VALUE_DECODE_SESSION_FAILED);
}

/** Disable stateless session tickets for a given TLS ctx
 *
 * @param[in] ctx to disable session tickets for.
 */
void fr_tls_ticket_stateless_disable(SSL_CTX *ctx)
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

/** Called when new tickets are being generated
 *
 * This adds additional application data to the session ticket to
 * allow us to perform validation checks when the session is
 * resumed.
 */
static int tls_ticket_stateless_app_data_set(SSL *ssl, void *arg)
{
	fr_tls_session_t	*tls_session = fr_tls_session(ssl);
	fr_tls_ticket_conf_t	*tls_cache_conf = arg;	/* Not talloced */
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
	    (!(tls_cache_conf->mode & FR_TLS_TICKET_STATELESS))) {
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

	if (conf->encode_session && !tls_ticket_stateless_encode_run(request, tls_session)) {
		REDEBUG("Not generating a session-ticket");
		return 0;
	}

	return tls_ticket_app_data_set(request, sess, &tls_session->session_id);
}

/** Called when new tickets are being decoded
 *
 * This adds the session-state attributes back to the current request.
 */
static SSL_TICKET_RETURN tls_ticket_stateless_app_data_get(SSL *ssl, SSL_SESSION *sess,
							       UNUSED unsigned char const *keyname,
							       UNUSED size_t keyname_len,
							       SSL_TICKET_STATUS status,
							       void *arg)
{
	fr_tls_session_t	*tls_session = fr_tls_session(ssl);
	fr_tls_conf_t		*conf = fr_tls_session_conf(tls_session->ssl);
	fr_tls_ticket_conf_t	*tls_cache_conf = arg;	/* Not talloced */
	request_t		*request = NULL;

	if (fr_tls_session_request_bound(ssl)) {
		request = fr_tls_session_request(ssl);
		if (unlang_request_is_cancelled(request)) return SSL_TICKET_RETURN_ABORT;
	}

	if (!tls_session->allow_session_resumption ||
	    (!(tls_cache_conf->mode & FR_TLS_TICKET_STATELESS))) {
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
	if (!tls_ticket_session_resumable(request, &tls_session->session_id, conf, sess)) {
		REDEBUG("Session-ticket has too little life left, denying session resumption");
		fr_tls_session_error_add(request, FR_ERROR_VALUE_SESSION_TICKET_EXPIRED);
		return SSL_TICKET_RETURN_IGNORE_RENEW;
	}

	if (tls_ticket_app_data_get(request, sess, &tls_session->session_id) < 0) {
		REDEBUG("Denying session resumption via session-ticket");
		return SSL_TICKET_RETURN_IGNORE_RENEW;
	}

	/*
	 *	The session-state list is back.  Give policy the chance to
	 *	look at what the ticket carried before anything relies on
	 *	it, certificate re-validation below included.
	 */
	if (conf->decode_session && !tls_ticket_stateless_decode_run(request, tls_session)) {
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
		fr_tls_verify_resumed_request(tls_session);

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

/** Derive the session ticket key, and install the session ticket callbacks on an SSL_CTX
 *
 * The key the configuration gives is stretched to the length OpenSSL asks
 * for with HKDF.  The callbacks embed the session-state list in each session
 * ticket the server issues, and extract the list again when a ticket is
 * presented.
 *
 * @param[in] ctx		to install the key and callbacks on.
 * @param[in] cache_conf	Session caching configuration, for the key and the callbacks.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_tls_ticket_stateless_ctx_init(SSL_CTX *ctx, fr_tls_ticket_conf_t const *cache_conf)
{
	size_t		key_len;
	uint8_t		*key_buff;
	EVP_PKEY_CTX	*pkey_ctx = NULL;

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
						   tls_ticket_stateless_app_data_set,
						   tls_ticket_stateless_app_data_get,
						   UNCONST(fr_tls_ticket_conf_t *, cache_conf)) != 1)) {
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

	return 0;
}
#endif /* WITH_TLS */
