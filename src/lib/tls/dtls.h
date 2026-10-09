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
 * @file lib/tls/dtls.h
 * @brief Datagram Transport Layer Security (DTLS)
 *
 * Everything here is reached only when the session runs over a datagram
 * transport.  The TLS code which both transports share stays in session.c
 * and connection.c, and branches on the transport where it has to.
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(dtls_h, "$Id$")

#include "openssl_user_macros.h"

#include "session.h"

#ifdef __cplusplus
extern "C" {
#endif

int		fr_dtls_session_init(fr_tls_session_t *tls_session, fr_tls_conf_t const *conf);

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
