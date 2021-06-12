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

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "conf.h"
#include "index.h"

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
typedef struct {
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

	void 			(*record_init)(fr_tls_record_t *buf);
	void 			(*record_close)(fr_tls_record_t *buf);
	unsigned int 		(*record_from_buff)(fr_tls_record_t *buf, void const *ptr, unsigned int size);
	unsigned int 		(*record_to_buff)(fr_tls_record_t *buf, void *ptr, unsigned int size);

	bool			invalid;			//!< Whether heartbleed attack was detected.
	size_t 			mtu;				//!< Maximum record fragment size.

	char const		*prf_label;			//!< Input to the TLS pseudo random function.
								//!< Usually set to a well known string describing
								//!< what the key being generated will be used for.

	bool			allow_session_resumption;	//!< Whether session resumption is allowed.
	fr_tls_cache_t		*cache;				//!< Current session resumption state.

	void			*opaque;			//!< Used to store module specific data.

	uint8_t			alerts_sent;
	bool			pending_alert;
	uint8_t			pending_alert_level;
	uint8_t			pending_alert_description;
} fr_tls_session_t;

/** Return the tls config associated with a tls_session
 *
 * @param[in] ssl	to retrieve the configuration from.
 * @return #fr_tls_conf_t associated with the session.
 */
static inline fr_tls_conf_t *fr_tls_session_conf(SSL *ssl)
{
	return talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF), fr_tls_conf_t);
}

/** Place a request pointer in the SSL * for retrieval by callbacks
 *
 * @note A request must not already be bound to the SSL *
 *
 * @param[in] ssl		to be bound.
 * @param[in] request		to bind to the tls_session.
 */
static inline CC_HINT(nonnull) void fr_tls_session_request_bind(SSL *ssl, request_t *request)
{
	int ret;

#ifndef NDEBUG
	request_t *old;
	old = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);
	if (old) {
		(void)talloc_get_type_abort(ssl, request_t);
		fr_assert(0);
	}
#endif
	ret = SSL_set_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST, request);
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
static inline CC_HINT(nonnull) void fr_tls_session_request_unbind(SSL *ssl)
{
	int ret;

#ifndef NDEBUG
	(void)talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST), request_t);
#endif
	ret = SSL_set_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST, NULL);
	if (unlikely(ret == 0)) {
		fr_assert(0);
		return;
	}
}

/** Return the request associated with a ssl session
 *
 * @param[in] ssl	session to retrieve the configuration from.
 * @return #request associated with the session.
 */
static inline request_t *fr_tls_session_request(SSL const *ssl)
{
	return talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST), request_t);
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

int		fr_tls_session_pairs_from_x509_cert(fr_pair_list_t *pair_list, TALLOC_CTX *ctx,
				     		    fr_tls_session_t *session, X509 *cert, int depth);

int		fr_tls_session_recv(request_t *request, fr_tls_session_t *tls_session);

int 		fr_tls_session_send(request_t *request, fr_tls_session_t *tls_session);

int 		fr_tls_session_alert(request_t *request, fr_tls_session_t *tls_session, uint8_t level, uint8_t description);

unlang_action_t	fr_tls_session_async_handshake_push(request_t *request, fr_tls_session_t *tls_session);

fr_tls_session_t *fr_tls_session_alloc_client(TALLOC_CTX *ctx, SSL_CTX *ssl_ctx);

fr_tls_session_t *fr_tls_session_alloc_server(TALLOC_CTX *ctx, SSL_CTX *ssl_ctx, request_t *request, bool client_cert);

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
