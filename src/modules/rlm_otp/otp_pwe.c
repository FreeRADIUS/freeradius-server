/*
 * $Id$
 *
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
 *
 * Copyright 2001,2002  Google, Inc.
 * Copyright 2005,2006 TRI-D Systems, Inc.
 */

/*
 * This file implements passcode (password) checking functions for each
 * supported encoding (PAP, CHAP, etc.).  The current libradius interface
 * is not sufficient for X9.9 use.
 */

RCSID("$Id$")

#define LOG_PREFIX "rlm_otp - "

/* avoid inclusion of these FR headers which conflict w/ OpenSSL */
#define _FR_MD4_H
#define _FR_SHA1_H
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include "extern.h"

USES_APPLE_DEPRECATED_API
#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include <string.h>

/* Attribute IDs for supported password encodings. */
#define SIZEOF_PWATTR (4 * 2)
fr_dict_attr_t const *pwattr[SIZEOF_PWATTR];


/* Initialize the pwattr array for supported password encodings. */
void
otp_pwe_init(void)
{
	fr_dict_attr_t const *da;

	/*
	 * Setup known password types.  These are pairs.
	 * NB: Increase pwattr array size when adding a type.
	 *     It should be sized as (number of password types * 2)
	 * NB: Array indices must match otp_pwe_t! (see otp.h)
	 */
	(void) memset(pwattr, 0, sizeof(pwattr));

	/* PAP */
	da = fr_dict_attr_by_name(NULL, "User-Password");
	if (da) {
		pwattr[0] = da;
		pwattr[1] = da;
	}

	/* CHAP */
	da = fr_dict_attr_by_name(NULL, "CHAP-Challenge");
	if (da) {
		pwattr[2] = da;

		da = fr_dict_attr_by_name(NULL, "CHAP-Password");
		if (da) {
			pwattr[3] = da;
		} else {
			pwattr[2] = NULL;
		}
	}

#if 0
	/* MS-CHAP (recommended not to use) */
	da = fr_dict_attr_by_name("MS-CHAP-Challenge");
	if (da) {
		pwattr[4] = da;

		da = fr_dict_attr_by_name("MS-CHAP-Response");
		if (da) {
			pwattr[5] = da;
		} else {
			pwattr[4] = NULL;
		}
	}
#endif /* 0 */

	/* MS-CHAPv2 */
	da = fr_dict_attr_by_name(NULL, "MS-CHAP-Challenge");
	if (da) {
		pwattr[6] = da;

		da = fr_dict_attr_by_name(NULL, "MS-CHAP2-Response");
		if (da) {
			pwattr[7] = da;
		} else {
			pwattr[6] = NULL;
		}
	}
}


/*
 * Test for password presence in an Access-Request packet.
 * Returns 0 for "no supported password present", or the
 * password encoding type.
 */
otp_pwe_t otp_pwe_present(REQUEST const *request)
{
	unsigned i;

	for (i = 0; i < SIZEOF_PWATTR; i += 2) {
		if (!pwattr[i]) {
			continue;
		}

		if (fr_pair_find_by_num(request->packet->vps, pwattr[i]->vendor, pwattr[i]->attr, TAG_ANY) &&
		    fr_pair_find_by_num(request->packet->vps, pwattr[i + 1]->vendor, pwattr[i + 1]->attr,
					TAG_ANY)) {
			DEBUG("%s: password attributes %s, %s",
			      __func__, pwattr[i]->name, pwattr[i + 1]->name);

			return i + 1; /* Can't return 0 (indicates failure) */
		}
	}

	DEBUG("%s: no password attributes present", __func__);
	return PWE_NONE;
}
