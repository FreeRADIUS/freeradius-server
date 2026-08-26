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
 * @file lib/tls/session.h
 * @brief Structures for session-resumption management.
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(session_h, "$Id$")

#include "openssl_user_macros.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct fr_tls_session_s fr_tls_session_t;

#include <freeradius-devel/server/request.h>

#include "cache.h"
#include "conf.h"
#include "index.h"
#include "verify.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	A single TLS record may be up to 16384 octets in length, but a
 *	TLS message may span multiple TLS records, and a TLS
 *	certificate message may in principle be as long as 16MB.
 *
 *	However, note that in order to protect against reassembly
 *	lockup and denial of service attacks, it may be desirable for
 *	an implementation to set a maximum size for one such group of
 *	TLS messages.
 *
 *	The TLS Message Length field is four octets, and provides the
 *	total length of the TLS message or set of messages that is
 *	being fragmented; this simplifies buffer allocation.
 */
#define FR_TLS_MAX_RECORD_SIZE 16384

/*
 * FIXME: Dynamic allocation of buffer to overcome FR_TLS_MAX_RECORD_SIZE overflows.
 * 	or configure TLS not to exceed FR_TLS_MAX_RECORD_SIZE.
 */
typedef struct {
	uint8_t		data[FR_TLS_MAX_RECORD_SIZE];
	size_t 		used;
} fr_tls_record_t;

typedef enum {
	TLS_INFO_ORIGIN_RECORD_RECEIVED,
	TLS_INFO_ORIGIN_RECORD_SENT
} fr_tls_info_origin_t;

typedef struct {
	int		origin;
	int		content_type;
	uint8_t		handshake_type;
	uint8_t		alert_level;
	uint8_t		alert_description;
	bool		initialized;

	char 		info_description[256];
	size_t		record_len;
	int		version;
} fr_tls_info_t;

/** Result of the last operation on the session
 *
 * This is needed to record the result of an asynchronous
 */
typedef enum {
	FR_TLS_RESULT_IN_PROGRESS	= 0x00,		//!< Handshake round in progress.
	FR_TLS_RESULT_ERROR		= 0x01,		//!< Handshake failed.
	FR_TLS_RESULT_SUCCESS		= 0x02		//!< Handshake round succeed.
} fr_tls_result_t;

/** Tracks the state of a TLS session
 *
 * Currently used for RADSEC and EAP-TLS + dependents (EAP-TTLS, EAP-PEAP etc...).
 *
 * In the case of EAP-TLS + dependents a #eap_tls_session_t struct is used to track
 * the transfer of TLS records.
 */
struct fr_tls_session_s {
	SSL_CTX			*ctx;				//!< TLS configuration context.
	SSL 			*ssl;				//!< This SSL session.
	SSL_SESSION		*session;			//!< Session resumption data.
	fr_tls_result_t		result;				//!< Result of the last handshake round.
	fr_tls_info_t		info;				//!< Information about the state of the TLS session.

	BIO 			*into_ssl;			//!< Basic I/O input to OpenSSL.
	BIO 			*from_ssl;			//!< Basic I/O output from OpenSSL.
	fr_tls_record_t 	clean_in;			//!< Cleartext data that needs to be encrypted.
	fr_tls_record_t 	clean_out;			//!< Cleartext data that's been encrypted.
	fr_tls_record_t 	dirty_in;			//!< Encrypted data to decrypt.
	fr_tls_record_t 	dirty_out;			//!< Encrypted data that's been decrypted.
	int			last_ret;			//!< Last result returned by SSL_read().

	void 			(*record_init)(fr_tls_record_t *buf);
	void 			(*record_close)(fr_tls_record_t *buf);
	unsigned int 		(*record_from_buff)(fr_tls_record_t *buf, void const *ptr, unsigned int size);
	unsigned int 		(*record_to_buff)(fr_tls_record_t *buf, void *ptr, unsigned int size);

	size_t 			mtu;				//!< Maximum record fragment size.

	void			*opaque;			//!< Used to store module specific data.

	fr_tls_cache_t		*cache;				//!< Current session resumption state.
	bool			allow_session_resumption;	//!< Whether session resumption is allowed.
	bool			verify_client_cert;		//!< Whether client cert verification has been requested.

	fr_tls_verify_t		validate;			//!< Current session certificate validation state.

	bool			invalid;			//!< Whether heartbleed attack was detected.

	bool			client_cert_ok;			//!< whether or not the client certificate was validated
	bool			can_pause;			//!< If true, it's ok to pause the request
								///< using the OpenSSL async API.

	uint8_t			alerts_sent;
	bool			pending_alert;
	uint8_t			pending_alert_level;
	uint8_t			pending_alert_description;

	fr_pair_list_t		extra_pairs;			//!< Pairs to add to cache and certificate validation
								///< calls.  These will be duplicated for every call.
};

/** Return the tls config associated with a tls_session
 *
 * @param[in] ssl	to retrieve the configuration from.
 * @return #fr_tls_conf_t associated with the session.
 */
static inline fr_tls_conf_t *fr_tls_session_conf(SSL *ssl)
{
	return talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF), fr_tls_conf_t);
}

/** Return the tls_session associated with a SSL *
 *
 * @param[in] ssl	to retrieve the configuration from.
 * @return #fr_tls_conf_t associated with the session.
 */
static inline fr_tls_session_t *fr_tls_session(SSL *ssl)
{
	return talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_TLS_SESSION), fr_tls_session_t);
}

/** Check to see if a request is bound to a session
 *
 * @param[in] ssl	session to check for requests.
 * @return
 *	- true if a request is bound to this session.
 *	- false if a request is not bound to this session.
 */
static inline CC_HINT(nonnull) bool fr_tls_session_request_bound(SSL *ssl)
{
	return (SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST) != NULL);
}

/** Return the request associated with a ssl session
 *
 * @param[in] ssl	session to retrieve the configuration from.
 * @return #request associated with the session.
 */
static inline request_t *fr_tls_session_request(SSL const *ssl)
{
	request_t *request = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);

	if (!request) return NULL;

	return talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST), request_t);
}

static inline CC_HINT(nonnull) void _fr_tls_session_request_bind(char const *file, int line,
								 SSL *ssl, request_t *request)
{
	int ret;

	RDEBUG3("%s[%d] - Binding SSL * (%p) to request (%p)", file, line, ssl, request);

#ifndef NDEBUG
	{
		request_t *old;
		old = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);
		if (old) {
			(void)talloc_get_type_abort(old, request_t);
			fr_assert(0);
		}
	}
#endif
	ret = SSL_set_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST, request);
	if (unlikely(ret == 0)) {
		fr_assert(0);
		return;
	}
}
/** Place a request pointer in the SSL * for retrieval by callbacks
 *
 * @note A request must not already be bound to the SSL *
 *
 * @param[in] ssl		to be bound.
 * @param[in] request		to bind to the tls_session.
 */
 #define fr_tls_session_request_bind(_ssl, _request) _fr_tls_session_request_bind(__FILE__, __LINE__, _ssl, _request)

static inline CC_HINT(nonnull) void _fr_tls_session_request_unbind(char const *file, int line, SSL *ssl)
{
	request_t	*request = fr_tls_session_request(ssl);
	int		ret;

#ifndef NDEBUG
	(void)talloc_get_type_abort(request, request_t);
#endif

	RDEBUG3("%s[%d] - Unbinding SSL * (%p) from request (%p)", file, line, ssl, request);
	ret = SSL_set_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST, NULL);
	if (unlikely(ret == 0)) {
		fr_assert(0);
		return;
	}
}
/** Remove a request pointer from the tls_session
 *
 * @note A request must be bound to the tls_session
 *
 * @param[in] ssl	session containing the request pointer.
 */
#define fr_tls_session_request_unbind(_ssl) _fr_tls_session_request_unbind(__FILE__, __LINE__, _ssl)

/** Add extra pairs to the temporary subrequests
 *
 * @param[in] child		to add extra pairs to.
 * @param[in] tls_session	to add extra pairs from.
 */
static inline CC_HINT(nonnull)
void fr_tls_session_extra_pairs_copy_to_child(request_t *child, fr_tls_session_t *tls_session)
{
	if (!fr_pair_list_empty(&tls_session->extra_pairs)) {
		MEM(fr_pair_list_copy(child->request_ctx, &child->request_pairs, &tls_session->extra_pairs) >= 0);
	}
}

/** Add an additional pair (copying it) to the list of extra pairs
 *
 * @param[in] tls_session	to add extra pairs to.
 * @param[in] vp		to add to tls_session.
 */
static inline CC_HINT(nonnull)
void fr_tls_session_extra_pair_add(fr_tls_session_t *tls_session, fr_pair_t *vp)
{
	fr_pair_t	*copy;

	MEM(copy = fr_pair_copy(tls_session, vp));
	fr_pair_append(&tls_session->extra_pairs, copy);
}

/** Add an additional pair to the list of extra pairs
 *
 * @param[in] tls_session	to add extra pairs to.
 * @param[in] vp		to add to tls_session.
 */
static inline CC_HINT(nonnull)
void fr_tls_session_extra_pair_add_shallow(fr_tls_session_t *tls_session, fr_pair_t *vp)
{
	fr_assert(talloc_parent(vp) == tls_session);
	fr_pair_append(&tls_session->extra_pairs, vp);
}


int 		fr_tls_session_password_cb(char *buf, int num, int rwflag, void *userdata);

unsigned int	fr_tls_session_psk_client_cb(SSL *ssl, UNUSED char const *hint,
					     char *identity, unsigned int max_identity_len,
					     unsigned char *psk, unsigned int max_psk_len);

unsigned int	fr_tls_session_psk_server_cb(SSL *ssl, const char *identity,
					     unsigned char *psk, unsigned int max_psk_len);

void 		fr_tls_session_info_cb(SSL const *s, int where, int ret);

void 		fr_tls_session_msg_cb(int write_p, int msg_version, int content_type,
				      void const *buf, size_t len, SSL *ssl, void *arg);

void		fr_tls_session_keylog_cb(const SSL *ssl, const char *line);

int		fr_tls_session_pairs_from_x509_cert(fr_pair_list_t *pair_list, TALLOC_CTX *ctx,
				     		    request_t *request, X509 *cert, bool der_decode) CC_HINT(nonnull);

int		fr_tls_session_client_hello_cb(SSL *ssl, int *al, void *arg);

int		fr_tls_session_recv(request_t *request, fr_tls_session_t *tls_session);

int 		fr_tls_session_send(request_t *request, fr_tls_session_t *tls_session);

int 		fr_tls_session_alert(request_t *request, fr_tls_session_t *tls_session, uint8_t level, uint8_t description);

unlang_action_t	fr_tls_session_async_handshake_push(request_t *request, fr_tls_session_t *tls_session);

fr_tls_session_t *fr_tls_session_alloc_client(TALLOC_CTX *ctx, SSL_CTX *ssl_ctx);

fr_tls_session_t *fr_tls_session_alloc_server(TALLOC_CTX *ctx, SSL_CTX *ssl_ctx, request_t *request, size_t dynamic_mtu, bool client_cert);

unlang_action_t fr_tls_new_session_push(request_t *request, fr_tls_conf_t const *tls_conf);

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
