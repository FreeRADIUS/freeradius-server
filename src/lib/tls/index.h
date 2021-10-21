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
#define FR_TLS_EX_INDEX_TALLOC			(17)

#define FR_TLS_EX_CTX_INDEX_VERIFY_STORE	(20)
#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
