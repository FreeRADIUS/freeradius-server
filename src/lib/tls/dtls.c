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
 * @file lib/tls/dtls.c
 * @brief Datagram Transport Layer Security (DTLS)
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls"

#include <openssl/hmac.h>
#include <openssl/rand.h>

#include "base.h"
#include "dtls.h"
#include "log.h"
#include "strerror.h"

/** The key the DTLS cookies are generated with
 *
 * One per process, generated at startup.  Rotating it would invalidate
 * outstanding cookies, which costs a client one extra round trip, and nothing
 * yet needs that.
 */
static uint8_t		dtls_cookie_key[32];

/** Build the cookie from #fr_socket_t in the #fr_tls_connection_t
 *
 * RFC 6347 section 4.2.1 suggests this construction:
 *
 *	Cookie = HMAC(Secret, Client-IP, Client-Parameters)
 *
 * The application hands DTLS a #fr_socket_t, which identifies a particular network connection.  This should
 * be the same for all DTLS calls, and should point to something which has a lifetime shared with the DTLS
 * connection.
 *
 * OpenSSL does not do this work itself.  It's two pairs of cookie callbacks differ.  For the stateless pair,
 * used by SSL_stateless(), "the integrity of the entire cookie ... is automatically verified by HMAC", while
 * for this pair (used for the DTLS HelloVerifyRequest), "the integrity of the cookie is not verified by
 * OpenSSL.  This is an application responsibility."
 *
 * @param[in] ssl	the cookie is for.
 * @param[out] out	buffer of at least EVP_MAX_MD_SIZE octets.
 * @param[out] out_len	how much of `out` was written.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int dtls_cookie_hmac(SSL *ssl, uint8_t *out, unsigned int *out_len)
{
	fr_tls_session_t	*tls_session = fr_tls_session(ssl);

	/*
	 *	Nothing identifies the peer, so there is nothing to bind the
	 *	cookie to, and a cookie which proves nothing is worse than
	 *	refusing to make one.
	 */
	if (!tls_session->cookie) {
		fr_strerror_const("No cookie value set on the session");
		return -1;
	}

#ifdef __COVERITY__
	/*
	 *	Coverity doesn't see HMAC() write the digest.  Without the
	 *	memset, Coverity reports out as uninitialised in the callers.
	 */
	memset(out, 0, EVP_MAX_MD_SIZE);
#endif

	/*
	 *	Hash the entire #fr_socket_t, as the application should set this once, and then never change
	 *	it.  This method means that we do exactly the same work for IPv4, Ipv6, and (potentially) Unix
	 *	sockets with datagrams.
	 */
	if (!HMAC(EVP_sha256(), dtls_cookie_key, sizeof(dtls_cookie_key),
		  (uint8_t const *) tls_session->cookie, sizeof(*tls_session->cookie),
		  out, out_len)) {
		fr_tls_strerror_printf(NULL);
		return -1;
	}

	return 0;
}

/** Generate the cookie which goes into a HelloVerifyRequest
 *
 * @param[in] ssl		the cookie is for.
 * @param[out] cookie		to write.  At most DTLS1_COOKIE_LENGTH octets.
 * @param[out] cookie_len	how much was written.
 * @return
 *	- 1 on success, which is what OpenSSL wants.
 *	- 0 on failure, which aborts the handshake.
 */
int fr_dtls_cookie_generate_cb(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	uint8_t		hmac[EVP_MAX_MD_SIZE];
	unsigned int	hmac_len;

	static_assert(EVP_MAX_MD_SIZE <= DTLS1_COOKIE_LENGTH,
		      "A SHA256 digest has to fit in a DTLS cookie");

	if (dtls_cookie_hmac(ssl, hmac, &hmac_len) < 0) return 0;

	memcpy(cookie, hmac, hmac_len);
	*cookie_len = hmac_len;

	return 1;
}

/** Check the cookie which came back in the second ClientHello
 *
 * @param[in] ssl		the cookie is for.
 * @param[in] cookie		the client echoed back.
 * @param[in] cookie_len	its length.
 * @return
 *	- 1 when the cookie is ours and is for this peer.
 *	- 0 otherwise, which makes OpenSSL ask for another one.
 */
int fr_dtls_cookie_verify_cb(SSL *ssl, unsigned char const *cookie, unsigned int cookie_len)
{
	uint8_t		hmac[EVP_MAX_MD_SIZE];
	unsigned int	hmac_len;

	if (dtls_cookie_hmac(ssl, hmac, &hmac_len) < 0) return 0;

	if (cookie_len != hmac_len) return 0;

	/*
	 *	A constant time compare, so that a wrong cookie says only
	 *	that it was wrong.
	 */
	return CRYPTO_memcmp(cookie, hmac, hmac_len) == 0;
}

/** Generate the per-process cookie key
 *
 * Called once from fr_openssl_init().
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dtls_cookie_init(void)
{
	if (RAND_bytes(dtls_cookie_key, sizeof(dtls_cookie_key)) != 1) {
		fr_tls_strerror_printf(NULL);
		return -1;
	}

	return 0;
}

/** Set up the parts of a session which only a datagram transport needs
 *
 * Called once per session, after the session knows its MTU, and only when the
 * context was built with DTLS_method().
 *
 * @param[in] tls_session	to configure.
 * @param[in] conf		the configuration
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dtls_session_init(fr_tls_session_t *tls_session, fr_tls_conf_t const *conf)
{
	fr_assert(tls_session->socket_type == SOCK_DGRAM);

	/*
	 *	OpenSSL asks the BIO for the MTU of the socket underneath
	 *	it.  There is no socket under a memory BIO, so the question
	 *	has no answer, and OpenSSL has to be told not to ask and
	 *	given the figure instead.
	 *
	 <*	Without both of these the handshake does not complete.
	 */
	SSL_set_options(tls_session->ssl, SSL_OP_NO_QUERY_MTU);

	/*
	 *	@todo - we should have a way for the application to update the MTU based on expected headers.
	 *	i.e. the MTU here should be the "raw" full-packet MTU, not the MTU of the application-layer
	 *	contents.
	 *
	 *	That's because the admin often can find out the raw MTU, or even guess, but knowing how large
	 *	the application MTU is depends on IP version, etc.
	 */
	tls_session->mtu = conf->fragment_size;
	SSL_set_mtu(tls_session->ssl, tls_session->mtu);

	/*
	 *	OpenSSL writes one datagram per BIO_write(), sized to the
	 *	MTU above.  The buffer those writes land in is a byte
	 *	stream, so without this the boundaries between them are
	 *	lost, and the application would send a whole flight as one
	 *	oversized datagram.
	 */
	if (fr_tls_bio_dbuff_datagram_init(tls_session->from_ssl) < 0) {
		fr_strerror_const("Failed initialising the datagram queue");
		return -1;
	}

	return 0;
}

/** The retransmission timer has fired
 *
 * OpenSSL holds the flight it last sent, and DTLSv1_handle_timeout() puts it
 * back into the outgoing buffer with fresh record sequence numbers.  Writing
 * it is just like any other write.
 *
 * @param[in] tl	the timer fired on.  Unused.
 * @param[in] now	Unused.
 * @param[in] uctx	the fr_tls_connection_t.
 */
static void _fr_dtls_timer_expired(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	fr_tls_connection_t	*conn = talloc_get_type_abort(uctx, fr_tls_connection_t);
	request_t		*request = conn->request;

	ROPTIONAL(RDEBUG2, DEBUG2, "%s - DTLS retransmission timer fired", conn->name);

	/*
	 *	A return of < 0 means the handshake has given up, which
	 *	OpenSSL reports rather than this code deciding it.
	 */
	if (DTLSv1_handle_timeout(conn->tls_session->ssl) < 0) {
		fr_tls_log_perror(request, "DTLS handshake timed out");
		fr_tls_connection_failed(conn, TLS_CONNECTION_FAIL_TLS);
		return;
	}

	if (fr_tls_connection_write(conn) < 0) {
		fr_tls_connection_failed(conn, TLS_CONNECTION_FAIL_APPLICATION);
		return;
	}

	/*
	 *	The interval doubles on each retransmission, so the next one
	 *	is not the same as the last one.
	 */
	fr_dtls_timer_update(conn);
}

/** Arm or disarm the retransmission timer
 *
 * OpenSSL changes the timer value on every round.  When there's
 * nothing outstanding, the timer is disarmed.
 *
 * @param[in] conn	to update the timer for.
 */
void fr_dtls_timer_update(fr_tls_connection_t *conn)
{
	request_t	*request = conn->request;
	struct timeval	tv;

	/*
	 *	A stream connection has no timer list, and nothing to time.
	 */
	if (!conn->tl) return;

	/*
	 *	Anything other than 1 means no timer is wanted.
	 */
	if (DTLSv1_get_timeout(conn->tls_session->ssl, &tv) != 1) {
		FR_TIMER_DELETE(&conn->timer_ev);
		return;
	}

	FR_TIMER_DELETE(&conn->timer_ev);

	if (fr_timer_in(conn, conn->tl, &conn->timer_ev, fr_time_delta_from_timeval(&tv),
			false, _fr_dtls_timer_expired, conn) < 0) {
		ROPTIONAL(RERROR, ERROR, "%s - Failed arming the DTLS retransmission timer", conn->name);
		fr_tls_connection_failed(conn, TLS_CONNECTION_FAIL_APPLICATION);
	}
}

/** Set the DTLS retransmission timer list for this connection.
 *
 * The library runs its own timers rather than running
 * application-layer callbacks.  The only actions taken by a callback
 * would be to set the timer, or send a packet.  And we can do that
 * ourselves once we have a timer list.
 *
 * There will arguably only ever be one timer event, so we don't
 * _technically_ need a separate timer list for DTLS.  But having a
 * separate timer list makes it easier for the application use it for
 * retransmitting application-layer data.
 *
 *  Once the DTLS connection is established, the TLS library no longer
 *  uses conn->tl or conn->timer_ev.
 *
 * @param[in] conn	to give a timer list to.
 * @param[in] parent	list to allocate the sub-list from.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_dtls_timer_list_set(fr_tls_connection_t *conn, fr_timer_list_t *parent)
{
	fr_assert(conn->tls_session->socket_type == SOCK_DGRAM);

	if (conn->tl) return 0;

	conn->tl = fr_timer_list_lst_alloc(conn, parent);
	if (!conn->tl) return -1;

	return 0;
}
#endif /* WITH_TLS */
