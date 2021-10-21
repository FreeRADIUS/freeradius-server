#pragma once
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

/** Encode/decode binary data using printable characters (base64 format)
 *
 * @see RFC 4648 <http://www.ietf.org/rfc/rfc4648.txt>.
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(base64_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/dbuff.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
 *	This uses that the expression (n+(k-1))/k means the smallest
 *	Integer >= n/k, i.e., the ceiling of n/k.
 */
#define FR_BASE64_ENC_LENGTH(_inlen) ((((_inlen) + 2) / 3) * 4)
#define FR_BASE64_DEC_LENGTH(_inlen) ((3 * ((_inlen) / 4)) + 2)

extern char const fr_base64_alphabet_encode[UINT8_MAX];
extern uint8_t const fr_base64_alphabet_decode[UINT8_MAX];
extern char const fr_base64_url_alphabet_encode[UINT8_MAX];
extern uint8_t const fr_base64_url_alphabet_decode[UINT8_MAX];

/** Check if char is in Base64 alphabet
 *
 * Note that '=' is padding and not considered to be part of the alphabet.
 *
 * @param[in] c		char to check.
 * @param[in] alphabet	to use.
 * @return
 *	- true if c is a character from the Base64 alphabet.
 *	- false if character is not in the Base64 alphabet.
 */
static inline bool fr_is_base64_nstd(char c, uint8_t const alphabet[static UINT8_MAX])
{
	return alphabet[(uint8_t)c] < 64;
}

size_t		fr_base64_encode(char * restrict out, size_t outlen, uint8_t const * restrict in, size_t inlen);
#define		fr_is_base64(_c) fr_is_base64_nstd(_c, fr_base64_alphabet_decode)


ssize_t		fr_base64_encode_nstd(fr_sbuff_t *out, fr_dbuff_t *in,
			      	      bool add_padding, char const alphabet[static UINT8_MAX])
			      	      CC_HINT(nonnull);

#define		fr_base64_encode(_out, _in, _add_padding) \
		fr_base64_encode_nstd(_out, _in, _add_padding, fr_base64_alphabet_encode)

ssize_t		fr_base64_decode_nstd(fr_sbuff_parse_error_t *err, fr_dbuff_t *out, fr_sbuff_t *in,
				      bool expect_padding, bool no_trailing, uint8_t const alphabet[static UINT8_MAX])
				      CC_HINT(nonnull(2,3,6));

#define		fr_base64_decode(_out, _in, _expect_padding, _no_trailing) \
		fr_base64_decode_nstd(NULL, _out,  _in, _expect_padding, _no_trailing, fr_base64_alphabet_decode)

#ifdef __cplusplus
}
#endif
