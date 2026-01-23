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

/** Encode/decode binary data using printable characters (base32 format)
 *
 * @see RFC 4648 <http://www.ietf.org/rfc/rfc4648.txt>.
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(base32_h, "$Id$")

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

extern char const fr_base32_alphabet_encode[SBUFF_CHAR_CLASS];
extern uint8_t const fr_base32_alphabet_decode[SBUFF_CHAR_CLASS];
extern char const fr_base32_hex_alphabet_encode[SBUFF_CHAR_CLASS];
extern uint8_t const fr_base32_hex_alphabet_decode[SBUFF_CHAR_CLASS];

/** Check if char is in base32 alphabet
 *
 * Note that '=' is padding and not considered to be part of the alphabet.
 *
 * @param[in] c		char to check.
 * @param[in] alphabet	to use.
 * @return
 *	- true if c is a character from the base32 alphabet.
 *	- false if character is not in the base32 alphabet.
 */
static inline bool fr_is_base32_nstd(char c, uint8_t const alphabet[static SBUFF_CHAR_CLASS])
{
	return alphabet[(uint8_t)c] < 32;
}

ssize_t		fr_base32_encode_nstd(fr_sbuff_t *out, fr_dbuff_t *in,
				      bool add_padding, char const alphabet[static SBUFF_CHAR_CLASS]);

#define		fr_base32_encode(_out, _in, _add_padding) \
		fr_base32_encode_nstd(_out, _in, _add_padding, fr_base32_alphabet_encode)

ssize_t		fr_base32_decode_nstd(fr_sbuff_parse_error_t *err, fr_dbuff_t *out, fr_sbuff_t *in,
				      bool expect_padding, bool no_trailing, uint8_t const alphabet[static SBUFF_CHAR_CLASS])
				      CC_HINT(nonnull(2,3,6));

#define		fr_base32_decode(_out, _in, _expect_padding, _no_trailing) \
		fr_base32_decode_nstd(NULL, _out,  _in, _expect_padding, _no_trailing, fr_base32_alphabet_decode)

#ifdef __cplusplus
}
#endif

