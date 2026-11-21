#ifdef WITH_TLS
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

/**
 * $Id$
 *
 * @file protocols/radius/tls.c
 * @brief Constants for the RADIUS/TLS protocol.
 *
 * @copyright 2026 Network RADIUS SAS <legal@networkradius.com>
 */
RCSID("$Id$")

#include <freeradius-devel/radius/tls.h>

/*
 *	For now, src/lib/tls enforces a minimum of DTLS 1.2 and TLS 1.3 for ALPN.
 *
 *	@todo - move that here, with fields for DTLS and TLS.
 *
 *	@todo - we likely don't need the FR_TLS_ALPN_STICKY flag.  All
 *	ALPN strings should be sticky.  The only relaxation of that is
 *	the FR_TLS_ALPN_DEFAULT string can be used with or without
 *	ALPN.
 */
fr_tls_alpn_t const fr_radius_alpn_table[] = {
	{ .id = FR_RADIUS_ALPN_RADIUS_1_0, .name = "radius/1.0",
	  .conf_name = "radius_v1_0", .flags = FR_TLS_ALPN_DEFAULT },
	{ .id = FR_RADIUS_ALPN_RADIUS_1_1, .name = "radius/1.1",
	  .conf_name = "radius_v1_1", .flags = FR_TLS_ALPN_STICKY },

	FR_TLS_ALPN_TABLE_TERMINATOR
};
#endif
