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
 * @file lib/tls/tls.h
 * @brief Structures and prototypes for TLS wrappers
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(index_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#define FR_TLS_EX_INDEX_EAP_SESSION 		(10)
#define FR_TLS_EX_INDEX_CONF			(11)
#define FR_TLS_EX_INDEX_REQUEST			(12)
#define FR_TLS_EX_INDEX_IDENTITY		(13)
#define FR_TLS_EX_INDEX_OCSP_STORE		(14)
#define FR_TLS_EX_INDEX_TLS_SESSION		(16)

/** ex_data index for the #fr_tls_session_t which owns an SSL_SESSION
 *
 * The indices above are hard-coded, because their information is
 * never duplicated.  However, OpenSSL does duplicate an SSL_SESSION.
 * A TLS 1.3 client does this for every NewSessionTicket that it
 * receives.  This duplication copies the ex_data, but OpenSSL doesn't
 * know about the index, and therefore can't duplicate the data.
 *
 * Therefore, an index used on an SSL_SESSION has to one assigned by
 * OpenSSL.  The namespace is per object type, so this is a different
 * index from the ones above even though hold the same pointer.
 *
 * Allocated by fr_openssl_init().
 */
extern int fr_tls_session_ex_index;

#define FR_TLS_EX_INDEX_CURL_CONF		(30)
#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
