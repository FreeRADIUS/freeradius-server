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
 * @file lib/tls/alpn_id.h
 * @brief Structure for ALPN IDs
 *
 * This file is needed so that the files in src/protocols can define protocol-specific ALPN IDs, without
 * getting confused with the rest of the TLS and request data structures.
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(alpn_id_h, "$Id$")

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

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
