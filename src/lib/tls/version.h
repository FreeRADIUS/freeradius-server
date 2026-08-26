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
 * @file lib/tls/version.h
 * @brief Structures for dealing with OpenSSL library versions
 *
 * @copyright 2022 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(tls_version_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include "openssl_user_macros.h"

#ifdef WITH_TLS
#  include <openssl/ssl.h>
#endif

/*
 *	If we're not building with TLS, dummy functions will
 *	be provided.
 */
int 		fr_openssl_version_consistent(void);
char const	*fr_openssl_version_basic(void);
char const	*fr_openssl_version_range(uint32_t low, uint32_t high);
char const	*fr_openssl_version_expanded(void);

#ifdef ENABLE_OPENSSL_VERSION_CHECK
int		fr_openssl_version_check(char const *acknowledged);
#endif

#ifdef __cplusplus
}
#endif
