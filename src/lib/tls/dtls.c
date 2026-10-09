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

#include "base.h"
#include "dtls.h"
#include "log.h"

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
	 *	Without both of these the handshake does not complete.
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
#endif /* WITH_TLS */
