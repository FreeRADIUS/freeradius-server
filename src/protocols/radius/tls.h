#ifdef WITH_TLS
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

/**
 * $Id$
 *
 * @file protocols/radius/tls.h
 * @brief Constants for the RADIUS/TLS protocol.
 *
 * @copyright 2026 Network RADIUS SAS <legal@networkradius.com>
 */
RCSIDH(radius_tls_h, "$Id$")

#include <freeradius-devel/util/talloc.h>

#include <freeradius-devel/tls/alpn_id.h>

/** ALPN ids, which are the position of the entry in the ALPN table, plus one.
 */
typedef enum {
	/* 0 is FR_TLS_ALPN_ID_NONE */
	FR_RADIUS_ALPN_RADIUS_1_0 = 1,			//!< "radius/1.0", which is also used when ALPN is not negotiated.
	FR_RADIUS_ALPN_RADIUS_1_1,			//!< "radius/1.1", RFC 9765.
} fr_radius_alpn_id_t;

extern fr_tls_alpn_t const fr_radius_alpn_table[];
#endif
