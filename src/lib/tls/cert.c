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
 *
 * @file tls/cert.c
 * @brief Functions to work with certificates.
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls"
#include <freeradius-devel/util/strerror.h>

#include "cert.h"
#include "utils.h"

#include <openssl/ssl.h>

/** Check if a certificate is currently valid
 *
 * @param[out] not_before_p	Where to write the not before time.  May be NULL.
 * @param[out] not_after_p	Where to write the not after time.  May be NULL.
 * @parma[in] cert		The Certificate to validate.
 * @return
 *	- -1 if we can't parse the notBefore or notAfter values in the cert.
 *	- -2 if the cert has expired (not_before_p, not_after_p still populated).
 *	- -3 if the cert is not yet valid (not_before_p, not_after_t still populated).
 */
int fr_tls_cert_is_valid(fr_unix_time_t *not_before_p, fr_unix_time_t *not_after_p, X509 *cert)
{
	fr_time_t	now = fr_time();
	time_t		not_before, not_after;

	/*
	 *	If the cert has a mangled notAfter or
	 *	notBefore timestamps then always fail,
	 *	no matter what the verify mode.
	 */
	if (fr_tls_utils_asn1time_to_epoch(&not_after, X509_get0_notAfter(cert)) < 0) {
		fr_strerror_const_push("Failed parsing notAfter time in certificate");
		return -1;
	}
	if (fr_tls_utils_asn1time_to_epoch(&not_before, X509_get0_notBefore(cert)) < 0) {
		fr_strerror_const_push("Failed parsing notBefore time in certificate");
		return -1;
	}

	if (not_before_p) *not_before_p = fr_unix_time_from_time(not_before);
	if (not_after_p) *not_after_p = fr_unix_time_from_time(not_after);

	/*
	 *	Check the cert hasn't expired
	 */
	if (fr_time_lt(fr_time_from_sec(not_after), now)) {
		fr_strerror_printf("Certificate has expired.  "
				   "Validity period (notAfter) ends %pV, current time is %pV",
				   fr_box_date(fr_unix_time_from_time(not_before)), fr_box_date(fr_time_to_unix_time(now)));
		return -2;
	}

	/*
	 *	Check the cert's validity period
	 *	has started.
	 */
	if (fr_time_gt(fr_time_from_sec(not_before), now)) {
		fr_strerror_printf("Certificate is not yet valid.  "
				   "Validity period (notBefore) starts %pV, current time is %pV",
				   fr_box_date(fr_unix_time_from_time(not_before)), fr_box_date(fr_time_to_unix_time(now)));
		return -3;
	}

	return 0;
}
#endif
