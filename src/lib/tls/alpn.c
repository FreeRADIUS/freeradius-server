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
 * @file lib/tls/alpn.c
 * @brief Set up Application Layer Protocol Negotiation (ALPN)
 *
 * ALPN allows TLS connections to signal what protocol they are carrying.  This lets applications use multiple
 * different protocols on the same UDP or TCP port.
 *
 * The client sends a list of ALPN strings that it accepts.  The server either chooses one and sends it back,
 * or else sends back nothing to indicate that none have been chosen.  Either end can allow no ALPN, or
 * require that some ALPN string was negotiated.
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#ifdef WITH_TLS
#define LOG_PREFIX "tls"

#define _TLS_PRIVATE 1

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/pair.h>

#include <freeradius-devel/protocol/tls/freeradius.h>

#include "attrs.h"
#include "base.h"
#include "log.h"

/** Validate the ALPN list.
 *
 * The client has not necessarily been authenticated, so we don't trust the data that they sent.
 *
 * The list is in wire format:
 * - one octet length (1..255)
 * - 'length' octets data.
 *
 * Bounded by 'size'.  There is no terminator.
 *
 * @param[in] alpn	list to check.
 * @param[in] len	length of the list.
 * @return
 *	- true if the list is well formed.
 *	- false if the list is empty, holds an empty name, or does not end
 *	  where `len` says it ends.
 */
static bool tls_alpn_valid(unsigned char const *alpn, size_t len)
{
	size_t i = 0;

	if (len == 0) return false;

	while (i < len) {
		if (alpn[i] == 0) return false;

		i += alpn[i] + 1;
	}

	return i == len;
}

/** Select a matching ALPN string.
 *
 * OpenSSL calls this only when the client offered a list, so a client which does not use ALPN never reaches
 * here.  That case is caught after the handshake instead, by fr_tls_session_alpn_check().
 *
 * The servers preference is set by the list order.  SSL_select_next_proto() walks the list, and stops on the
 * first matching name offered by the client.
 *
 * @param[in] ssl	session being negotiated.
 * @param[out] out	the name chosen, pointing into one of the two lists.
 * @param[out] outlen	length of that name.
 * @param[in] in	the client's list.
 * @param[in] inlen	length of the client's list.
 * @param[in] arg	unused, the configuration comes from the SSL *.
 * @return
 *	- SSL_TLSEXT_ERR_OK if a name was chosen.
 *	- SSL_TLSEXT_ERR_ALERT_FATAL if the two lists have nothing in common.
 */
static int tls_session_alpn_select_cb(SSL *ssl, unsigned char const **out, unsigned char *outlen,
				      unsigned char const *in, unsigned int inlen, UNUSED void *arg)
{
	request_t		*request = fr_tls_session_request(ssl);
	fr_tls_conf_t const	*conf = fr_tls_session_conf(ssl);
	unsigned int		i;

	/*
	 *	Check that the list wasn't mangled after the application set it.
	 */
	fr_assert(tls_alpn_valid(conf->alpn, conf->sizeof_alpn));

	if (ROPTIONAL_ENABLED(RDEBUG_ENABLED2, DEBUG_ENABLED2)) {
		for (i = 0; i < inlen; i += in[i] + 1) {
			ROPTIONAL(RDEBUG2, DEBUG2, "ALPN - peer offers \"%.*s\"", in[i], &in[i + 1]);
		}
	}

	/*
	 *	SSL_select_next_proto() writes through a non-const pointer,
	 *	while the callback is handed a const one.  The data it writes
	 *	is a pointer into one of the two lists, not the list itself,
	 *	so nothing const is written through.
	 */
	if (SSL_select_next_proto(UNCONST(unsigned char **, out), outlen,
				  conf->alpn, (unsigned int) conf->sizeof_alpn,
				  in, inlen) != OPENSSL_NPN_NEGOTIATED) {
		ROPTIONAL(REDEBUG, ERROR, "ALPN - no protocol in common with the peer");
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	ROPTIONAL(RDEBUG2, DEBUG2, "ALPN - chose \"%.*s\"", (int) *outlen, *out);

	return SSL_TLSEXT_ERR_OK;
}

/** Set ALPN (or not) for a connection.
 *
 * This is called for both client and server.  A client sends it's list, and verifies that the reply sent back
 * from the server matches one of the ALPN strings it sent.  A server reads the client list, and compares the
 * ALPN strings to the ones that it accepts.
 *
 * @param[in] ctx	to configure.
 * @param[in] conf	holding the protocol list.
 * @param[in] client	true for the client role.
 * @return
 *	- 0 on success, including the case where the application wants no ALPN.
 *	- -1 if the list is malformed, or OpenSSL refused it.
 */
int fr_tls_ctx_alpn_set(SSL_CTX *ctx, fr_tls_conf_t const *conf, bool client)
{
	/*
	 *	No ALPN string.  If ALPN is required, that's a code error.
	 */
	if (!conf->alpn) {
		if (conf->alpn_required) {
			ERROR("ALPN is required, but no protocols were set");
			return -1;
		}

		return 0;
	}

	if (!tls_alpn_valid(conf->alpn, conf->sizeof_alpn)) {
		ERROR("ALPN protocol list is malformed, or does not match sizeof_alpn (%zu)",
		      conf->sizeof_alpn);
		return -1;
	}

	if (client) {
		/*
		 *	Returns zero on success, which is the opposite of
		 *	most of the SSL_CTX_set_* calls around it.
		 */
		if (SSL_CTX_set_alpn_protos(ctx, conf->alpn, (unsigned int) conf->sizeof_alpn) != 0) {
			fr_tls_log_perror(NULL, "Failed setting the ALPN protocol list");
			return -1;
		}
	} else {
		SSL_CTX_set_alpn_select_cb(ctx, tls_session_alpn_select_cb, NULL);
	}

	return 0;
}

/** Get the ALPN string which was selected.
 *
 * @param[in] tls_session to check
 * @return
 *	- true if the two ends agreed on a protocol.
 *	- false if they did not, which includes the case where ALPN was not used.
 */
static bool tls_session_alpn(fr_tls_session_t *tls_session)
{
	unsigned char const	*data;
	unsigned int		len = 0;

	SSL_get0_alpn_selected(tls_session->ssl, &data, &len);
	if (!data || (len == 0)) {
		tls_session->alpn = NULL;
		tls_session->sizeof_alpn = 0;
		return false;
	}

	MEM(tls_session->alpn = talloc_memdup(tls_session, data, len));
	tls_session->sizeof_alpn = len;

	return true;
}

/** Check that we agreed on an ALPN string (or not).
 *
 * Runs once the handshake is done, for both roles.
 *
 * A server catches most failures earlier, in tls_session_alpn_select_cb(), which sends a fatal alert when the
 * two lists have nothing in common.  What that callback cannot catch is a client which offered no list,
 * because it's not called.  A client has no callback at all, and learns what the server chose only from the
 * handshake.
 *
 * @param[in] request		to log through.
 * @param[in] tls_session	to check.
 * @return
 *	- 0 if a protocol was agreed, or if none was needed.
 *	- -1 if one was needed and none was agreed.
 */
int fr_tls_session_alpn_check(request_t *request, fr_tls_session_t *tls_session)
{
	fr_tls_conf_t const	*conf = fr_tls_session_conf(tls_session->ssl);

	if (!conf->alpn) return 0;

	/*
	 *	SSL_get0_alpn_selected() hands back the name on its own, with
	 *	no leading length octet, so the whole of what it gave us is
	 *	the name.
	 */
	if (tls_session_alpn(tls_session)) {
		fr_pair_t *vp;

		ROPTIONAL(RDEBUG2, DEBUG2, "ALPN - agreed on \"%.*s\"",
			  (int) tls_session->sizeof_alpn, tls_session->alpn);

		if (!request) return 0;

		MEM(pair_append_session_state(&vp, attr_tls_alpn) >= 0);
		MEM(fr_pair_value_bstrndup(vp, (char *) tls_session->alpn, tls_session->sizeof_alpn, false) == 0);

		RDEBUG2("session-state.%pP", vp);

		return 0;
	}

	if (!conf->alpn_required) {
		ROPTIONAL(RDEBUG2, DEBUG2, "ALPN - No protocols in common, not using ALPN");
		return 0;
	}

	ROPTIONAL(REDEBUG, ERROR, "ALPN - Failure, no protocols in common");
	fr_tls_session_error_add(request, FR_ERROR_VALUE_ALPN_FAILED);

	return -1;
}
#endif /* WITH_TLS */
