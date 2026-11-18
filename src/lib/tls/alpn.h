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
 * Application Layer Protocol Negotiation (ALPN) is configured in one of two ways:
 *
 * 1. The application declares a table of #fr_tls_alpn_t entries, one for each protocol that the application
 *    knows.  It then calls fr_tls_alpn_set() or puts fr_tls_alpn_parse() in an `alpn` subsection rule.  The
 *    TLS library builds the wire list, derives `alpn_required`, and sets `alpn_id` in #fr_tls_session_t once
 *    the handshake is done.  Once the TLS connection is established, the application check the negotiated
 *    `alpn_id`
 *
 * 2. The application manually sets `alpn`, `sizeof_alpn` and `alpn_required` in #fr_tls_conf_t, and reads
 *    `alpn` and `sizeof_alpn` from #fr_tls_session_t once the handshake is done.
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(alpn_h, "$Id$")

#include "openssl_user_macros.h"

#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Value of `alpn_id` when no ALPN name was negotiated, and no entry has #FR_TLS_ALPN_DEFAULT set.
 */
#define FR_TLS_ALPN_ID_NONE	(0)

/** Flags for #fr_tls_alpn_t
 *
 * @{
 */
#define FR_TLS_ALPN_DEFAULT	(1 << 0)	//!< The protocol which both ends use when no ALPN is used.
#define FR_TLS_ALPN_STICKY	(1 << 1)	//!< A session which negotiated ALPN can only be resumed with
						///< the same ALPN string.
/** @} */

/** One protocol that an application can negotiate
 *
 * A table is an array of entries.  The table ends with #FR_TLS_ALPN_TABLE_TERMINATOR
 *
 * The `id` of each entry is its position in the table plus one, so the entry with a given `id` is
 * `table[id - 1]`.  fr_tls_alpn_set() fails when a table does not follow that rule.
 */
typedef struct fr_tls_alpn_s {
	int		id;			//!< The application's value for this protocol.  1 for the first entry,
						///< 2 for the second entry, etc.
	char const	*name;			//!< ALPN string, without the length octet.
	char const	*conf_name;		//!< Name of the item in the `alpn` section.
	unsigned int	flags;			//!< #FR_TLS_ALPN_DEFAULT and #FR_TLS_ALPN_STICKY.
} fr_tls_alpn_t;

#define FR_TLS_ALPN_TABLE_TERMINATOR { .id = FR_TLS_ALPN_ID_NONE }

int		fr_tls_alpn_set(TALLOC_CTX *ctx, fr_tls_conf_t *conf, fr_tls_alpn_t const *table,
				int const *ids, size_t num);

int		fr_tls_alpn_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);

#ifdef _TLS_PRIVATE
int		fr_tls_ctx_alpn_set(SSL_CTX *ctx, fr_tls_conf_t const *conf, bool client);

int		fr_tls_session_alpn_check(request_t *request, fr_tls_session_t *tls_session);
#endif

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
