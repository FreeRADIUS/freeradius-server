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
 * @file lib/tls/utils.h
 * @brief Miscellaneous TLS utility functions
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(utils_h, "$Id$")

#include "openssl_user_macros.h"

#include <openssl/ssl.h>

#include <freeradius-devel/util/time.h>
#include <freeradius-devel/server/request.h>

#ifdef __cplusplus
extern "C" {
#endif

char const	*fr_tls_utils_x509_pkey_type(X509 *cert);

int		fr_tls_utils_keyblock_size_get(request_t *request, SSL *ssl);

int		fr_tls_utils_asn1time_to_epoch(time_t *out, ASN1_TIME const *asn1);

int		fr_utils_get_private_key_password(char *buf, int size, UNUSED int rwflag, void *u);

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
