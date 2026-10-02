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
 * @file lib/tls/alpn.h
 * @brief Agree with the peer on what is spoken inside the tunnel.
 *
 * Nothing here is for an application to call.  An application takes part in
 * Application Layer Protocol Negotiation (ALPN) by setting `alpn`,
 * `sizeof_alpn` and `alpn_required` in #fr_tls_conf_t, and by reading `alpn`
 * and `sizeof_alpn` from #fr_tls_session_t once the handshake is done.  The
 * TLS library calls everything below for itself, at the two points where it
 * can: when it builds a context, and when a handshake finishes.
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(alpn_h, "$Id$")

#include "openssl_user_macros.h"

#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _TLS_PRIVATE
int		fr_tls_ctx_alpn_set(SSL_CTX *ctx, fr_tls_conf_t const *conf, bool client);

int		fr_tls_session_alpn_check(request_t *request, fr_tls_session_t *tls_session);
#endif

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
