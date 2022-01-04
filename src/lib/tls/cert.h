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
 * @file lib/tls/cert.h
 * @brief Functions to work with certificates.
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(cert_h, "$Id$")

#include "openssl_user_macros.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <freeradius-devel/util/time.h>

#ifdef __cplusplus
extern "C" {
#endif

int fr_tls_cert_is_valid(fr_unix_time_t *not_before_p, fr_unix_time_t *not_after_p, X509 *cert);

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
