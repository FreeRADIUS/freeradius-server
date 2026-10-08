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
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(session_h, "$Id$")

#include "openssl_user_macros.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct fr_tls_session_s fr_tls_session_t;

#include <freeradius-devel/server/request.h>
#include <freeradius-devel/util/dbuff.h>

#include "bio.h"
#include "ticket.h"
#include "conf.h"
#include "index.h"
#include "verify.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	A single TLS record carries at most SSL3_RT_MAX_PLAIN_LENGTH
 *	octets of plaintext, which OpenSSL defines as 16384.  A TLS
 *	message may span multiple TLS records, and a TLS certificate
 *	message may in principle be as long as 16MB.
 *
 *	However, note that in order to protect against reassembly
 *	lockup and denial of service attacks, it may be desirable for
 *	an implementation to set a maximum size for one such group of
 *	TLS messages.
 *
 *	The TLS Message Length field is four octets, and provides the
 *	total length of the TLS message or set of messages that is
 *	being fragmented, which simplifies buffer allocation.
 *
 *	A TLS record adds data on top of the application-layer
 *	plaintext: the TLS header (5 octets); encryption overhead
 *	(SSL3_RT_MAX_ENCRYPTED_OVERHEAD which is 256 octets of padding
 *	plus a 64 octet MAC); where OpenSSL was built with
 *	compression 1024 octets.
 *
 *	SSL3_RT_MAX_PACKET_SIZE therefore depends on the local OpenSSL
 *	build, and build flags.  Generally 17733 with compression,
 *	16709 without.  We round up on general principle.
 */
#define FR_TLS_MAX_PACKET_SIZE ((SSL3_RT_MAX_PACKET_SIZE + 255) & ~255)

/*
 *	Cap the maximum number of handshakes that we receive in a row.
 *	If we don't make progress, then either the certificates are
 *	enormous, or the TLS chunks are deliberately small, or the
 *	other end is trying to catch us in an infinite ACK / ACK loop.
 *
 *	The EAP code also caps the number of rounds it does, but there
 *	are non-TLS EAP methods which can use multiple rounds.  We
 *	need both limits in order to catch all corner cases.  Note
 *	also that TLS-based EAP methods will ACK each _fragment_ of a
 *	TLS record.  So one TLS "round" could map to multple EAP
 *	"rounds".
 */
#define FR_TLS_MAX_ROUNDS 50

/*
 * FIXME: Dynamic allocation of buffer to overcome SSL3_RT_MAX_PLAIN_LENGTH overflows.
 * 	or configure TLS not to exceed SSL3_RT_MAX_PLAIN_LENGTH.
 *
 * clean_in and clean_out are dbuffs over a fixed
 * SSL3_RT_MAX_PLAIN_LENGTH allocation.  The buffers should not be
 * extensible, as doing so could allow the peer to send unlimited data.
 *
 * dirty_in and dirty_out allow for extensions.  We therefore can't
 * call the fill/drain helpers below on those buffers.  Calling
 * fr_tls_record_init() on one would re-init the dbuff and lose the
 * talloc context which lets the buffer extend.
 */

/** Reset a record buffer so that it can be filled again
 *
 * A record buffer is filled, then drained.  While the buffer is filling, the
 * dbuff runs from the start of the buffer to the end of the memory, the
 * current position is where the next octet is written, and fr_dbuff_used()
 * says how many octets are in the buffer.
 *
 * Resetting returns the buffer to the filling state, and discards whatever
 * the buffer held.
 *
 * @param[in] record	to reset.
 */
static inline void fr_tls_record_init(fr_dbuff_t *record)
{
	fr_dbuff_init(record, fr_dbuff_start(record), (size_t) SSL3_RT_MAX_PLAIN_LENGTH);
}

/** Stop filling a record buffer, and start draining it
 *
 * While the buffer is draining, the dbuff runs from the start of the buffer
 * to the end of the data which was written, the current position is where the
 * next octet is read, and fr_dbuff_remaining() says how many octets are left
 * to read.
 *
 * The buffer must not be written to while it is draining.  Call
 * fr_tls_record_init() to fill it again.
 *
 * @param[in] record	to start draining.
 */
static inline void fr_tls_record_drain(fr_dbuff_t *record)
{
	size_t used = fr_dbuff_used(record);

	fr_dbuff_init(record, fr_dbuff_start(record), used);
}

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

	size_t		record_len;
	int		version;			//!< NOT to be trusted!  Use SSL_version(), see session.c

	char 		info_description[256];
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

#ifdef PSK_MAX_IDENTITY_LEN
/** State of the `load psk` call that the PSK callback requested
 *
 */
typedef enum {
	FR_TLS_PSK_INIT = 0,				//!< No call is pending.
	FR_TLS_PSK_REQUESTED,				//!< `load psk` needs to run.  The PSK callback has
							///< paused the handshake until the section finishes.
	FR_TLS_PSK_SUCCESS,				//!< `load psk` returned a key, and `key` holds the key.
	FR_TLS_PSK_FAILED				//!< `load psk` failed, or did not return a usable key.
} fr_tls_psk_state_t;

/** The `load psk` call that the PSK callback requested, and the key that the section returned
 *
 */
typedef struct {
	fr_tls_psk_state_t	state;				//!< Whether the call is pending, finished, or failed.
	unsigned int		max_psk_len;			//!< The longest key that OpenSSL accepts, copied from
								///< the `max_psk_len` argument of the PSK callback.
	uint8_t			*key;				//!< The key from `reply.TLS-PSK-Key`, copied out of the
								///< subrequest before the subrequest is freed.
	size_t			key_len;			//!< Length of `key`.
} fr_tls_psk_t;
#endif

/** Policy sections that an OpenSSL callback has asked the handshake to run
 *
 * A callback cannot run the unlang interpreter, so the callback raises a bit
 * in `pending`, and pauses the handshake.  tls_session_async_handshake_cont()
 * pushes the section for each raised bit, lowest bit first, and only resumes
 * the handshake once no bit is raised.  Each bit is one shot, cleared before
 * the push function for the bit is called.  Each section writes the result
 * of the section to the state for that section (`cache`, `ticket`, `psk`, or
 * `validate`), not to `pending`.
 */
DIAG_OFF(attributes)
typedef enum CC_HINT(flag_enum) : uint64_t {
	FR_TLS_PENDING_STATEFUL_TICKET	= 0x01,		//!< `load session { ... }`, `store session { ... }`
							///< or `clear session { ... }`, for the session cache.
	FR_TLS_PENDING_STATELESS_TICKET	= 0x02,		//!< `encode session { ... }` or `decode session { ... }`,
							///< for a stateless session ticket.
	FR_TLS_PENDING_PSK		= 0x04,		//!< `load psk { ... }`
	FR_TLS_PENDING_VERIFY		= 0x08		//!< `verify certificate { ... }`
} fr_tls_pending_t;
DIAG_ON(attributes)

#ifdef _TLS_PRIVATE
/** Ask the handshake to run a section once the handshake has paused
 */
#define TLS_PENDING_SET(_tls_session, _bit)	((_tls_session)->pending |= (_bit))

/** Clear a bit before the push function for the bit is called
 */
#define TLS_PENDING_CLEAR(_tls_session, _bit)	((_tls_session)->pending &= ~(_bit))
#endif

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
	fr_value_box_t		session_id;			//!< ID of the session

	fr_tls_info_t		info;				//!< Information about the state of the TLS session.

	fr_tls_bio_dbuff_t	*into_ssl;			//!< Encrypted data from the peer, which OpenSSL reads.
	fr_tls_bio_dbuff_t	*from_ssl;			//!< Encrypted data OpenSSL wrote, waiting to be sent.
	fr_dbuff_t 		clean_in;			//!< Cleartext data that needs to be encrypted.
	fr_dbuff_t 		clean_out;			//!< Decrypted cleartext, for the caller to read.
	fr_dbuff_t		*dirty_in;			//!< Encrypted data to decrypt.  The producer
								///< cursor of into_ssl, which the caller fills.
	fr_dbuff_t		*dirty_out;			//!< Encrypted data, ready to send.  The consumer
								///< cursor of from_ssl, which the caller drains.
	int			last_ret;			//!< Last result returned by SSL_read().

	uint32_t		rounds;				//!< Handshake round trips.

	size_t 			mtu;				//!< Maximum record fragment size.

	void			*opaque;			//!< Used to store module specific data.

	unsigned char		*alpn;				//!< Protocol name both ends agreed on, as
								///< SSL_get0_alpn_selected() gives it: the name
								///< alone, with no leading length octet.
	size_t			sizeof_alpn;			//!< Length of `alpn`.

	fr_tls_ticket_stateful_t		*cache;				//!< Current session resumption state.
	bool			allow_session_resumption;	//!< Whether session resumption is allowed.
	bool			verify_peer_cert;		//!< Whether verification of the peer's certificate
								///< has been requested.

	fr_tls_pending_t	pending;			//!< Policy sections that an OpenSSL callback has
								///< asked the handshake to run.

	fr_tls_verify_t		validate;			//!< Current session certificate validation state.

	fr_tls_ticket_stateless_state_t	ticket;				//!< Whether `encode session` or `decode session`
								///< is waiting to run, and what it returned.

#ifdef PSK_MAX_IDENTITY_LEN
	fr_tls_psk_t		psk;				//!< Whether `load psk` is waiting to run, and what
								///< `load psk` returned.
#endif

	bool			invalid;			//!< Whether heartbleed attack was detected.

	bool			write_encrypted;		//!< Whether the records we write are encrypted.
								///< which lets us track if we can send an alert

	bool			peer_cert_ok;			//!< Whether the peer's certificate was validated
	bool			seen_application_data;		//!< Application data has started moving, which
								///< indicates that all session tickets have been sent.

	bool			session_ticket_received;	//!< A client has seen the NewSessionTicket which
								///< a TLS 1.3 server sends after the handshake.

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

	if (!request) return;

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

/** How many octets the datagram at the head of `dirty_out` holds
 *
 * Only meaningful for a datagram session.  A stream session writes everything
 * which is waiting, and never asks.
 *
 * @param[in] tls_session	to read.
 * @return
 *	- the length of the next datagram.
 *	- 0 if no whole datagram is waiting.
 */
static inline CC_HINT(nonnull) size_t fr_tls_session_datagram_len(fr_tls_session_t *tls_session)
{
	return fr_tls_bio_dbuff_datagram_len(tls_session->from_ssl);
}

/** Discard the datagram at the head of `dirty_out`, which has now been sent
 *
 * The caller advances `dirty_out` itself, so the cursor and the boundary move
 * together.
 *
 * @param[in] tls_session	to advance.
 */
static inline CC_HINT(nonnull) void fr_tls_session_datagram_sent(fr_tls_session_t *tls_session)
{
	fr_tls_bio_dbuff_datagram_sent(tls_session->from_ssl);
}

int 		fr_tls_session_password_cb(char *buf, int num, int rwflag, void *userdata);

unsigned int	fr_tls_session_psk_client_cb(SSL *ssl, UNUSED char const *hint,
					     char *identity, unsigned int max_identity_len,
					     unsigned char *psk, unsigned int max_psk_len);

unsigned int	fr_tls_session_psk_server_cb(SSL *ssl, const char *identity,
					     unsigned char *psk, unsigned int max_psk_len);

#ifdef PSK_MAX_IDENTITY_LEN
unlang_action_t	fr_tls_session_psk_pending_push(request_t *request, fr_tls_session_t *tls_session);
#endif

void 		fr_tls_session_info_cb(SSL const *s, int where, int ret);

void 		fr_tls_session_msg_cb(int write_p, int msg_version, int content_type,
				      void const *buf, size_t len, SSL *ssl, void *arg);

void		fr_tls_session_keylog_cb(const SSL *ssl, const char *line);

int		fr_tls_session_pairs_from_x509_cert(fr_pair_list_t *pair_list, TALLOC_CTX *ctx,
				     		    request_t *request, X509 *cert, X509 *issuer,
						    bool der_decode) CC_HINT(nonnull(1,2,3,4));

int		fr_tls_session_client_hello_cb(SSL *ssl, int *al, void *arg);

bool		fr_tls_session_is_init_finished(fr_tls_session_t *tls_session);

int		fr_tls_session_recv(request_t *request, fr_tls_session_t *tls_session);

int 		fr_tls_session_send(request_t *request, fr_tls_session_t *tls_session);

int 		fr_tls_session_alert(request_t *request, fr_tls_session_t *tls_session, uint8_t level, uint8_t description);

void		fr_tls_session_error_alert(request_t *request, fr_tls_session_t *session,
					   uint32_t error, uint8_t description);

void		fr_tls_session_close_send(request_t *request, fr_tls_session_t *session);
void		fr_tls_session_error_add(request_t *request, uint32_t error);

unlang_action_t	fr_tls_session_async_handshake_push(request_t *request, fr_tls_session_t *tls_session);

fr_tls_session_t *fr_tls_session_alloc_client(TALLOC_CTX *ctx, SSL_CTX *ssl_ctx, request_t *request);

fr_tls_session_t *fr_tls_session_alloc_server(TALLOC_CTX *ctx, SSL_CTX *ssl_ctx, request_t *request, bool client_cert);

unlang_action_t fr_tls_new_session_push(request_t *request, fr_tls_conf_t const *tls_conf);

unlang_action_t fr_tls_session_fail_session(request_t *request, fr_tls_session_t *tls_session);

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
