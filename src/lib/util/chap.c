/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 of the
 *   License as published by the Free Software Foundation.
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

/** Functions for parsing raw network packets
 *
 * @file src/lib/util/chap.c
 *
 * @author Alan DeKok (aland@networkradius.com)
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/util/chap.h>

/** Encode a CHAP password
 *
 * @param[out] out		An output buffer of 17 bytes (id + MD5 digest).
 * @param[in] id		CHAP ID, a random ID for request/response matching.
 * @param[in] challenge		the CHAP challenge
 * @param[in] challenge_len	Length of the challenge.
 * @param[in] password		Input password to hash.
 * @param[in] password_len	Length of input password.
 */
void fr_chap_encode(uint8_t out[static 1 + FR_CHAP_CHALLENGE_LENGTH],
		    uint8_t id, uint8_t const *challenge, size_t challenge_len,
		    char const *password, size_t password_len)
{
	fr_md5_ctx_t	*md5_ctx;

	md5_ctx = fr_md5_ctx_alloc_from_list();

	/*
	 *	First ingest the ID and the password.
	 */
	fr_md5_update(md5_ctx, (uint8_t const *)&id, 1);
	fr_md5_update(md5_ctx, (uint8_t const *)password, password_len);

	fr_md5_update(md5_ctx, challenge, challenge_len);
	out[0] = id;
	fr_md5_final(out + 1, md5_ctx);
	fr_md5_ctx_free_from_list(&md5_ctx);
}
