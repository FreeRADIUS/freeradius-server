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

/** Structures and functions for parsing raw network packets
 *
 * @file src/lib/util/chap.h
 *
 * @author Alan DeKok (aland@networkradius.com)
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(chap_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/md5.h>

#define FR_CHAP_CHALLENGE_LENGTH		(MD5_DIGEST_LENGTH)

void fr_chap_encode(uint8_t out[static 1 + FR_CHAP_CHALLENGE_LENGTH],
		    uint8_t id, uint8_t const *challenge, size_t challenge_len,
		    char const *password, size_t password_len);

#ifdef __cplusplus
}
#endif
