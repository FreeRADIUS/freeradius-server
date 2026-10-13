#pragma once
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
 * @file lib/bio/tls.h
 * @brief Binary IO abstractions for TLS and DTLS connections
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_tls_h, "$Id$")

#ifdef WITH_TLS
#include <freeradius-devel/bio/base.h>
#include <freeradius-devel/server/request.h>

#include <openssl/ssl.h>

typedef struct fr_tls_connection_s fr_tls_connection_t;	/* see freeradius-devel/tls/connection.h */
typedef struct fr_bio_tls_s fr_bio_tls_t;

fr_bio_tls_t		*fr_bio_tls_alloc(request_t *request, fr_bio_t *next, SSL_CTX *ssl_ctx,
					  bool client, bool client_cert) CC_HINT(nonnull);

fr_tls_connection_t	*fr_bio_tls_conn(fr_bio_tls_t *my) CC_HINT(nonnull);

int			fr_bio_tls_connect(fr_bio_tls_t *my) CC_HINT(nonnull);
#endif
