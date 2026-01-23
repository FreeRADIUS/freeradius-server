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

/** Encode/decode binary data using printable characters (base16 format - hex)
 *
 * @see RFC 4648 <http://www.ietf.org/rfc/rfc4648.txt>.
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(base16_h, "$Id$")

#  ifdef __cplusplus
extern "C" {
#  endif

#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/dbuff.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

extern char const fr_base16_alphabet_encode_lc[SBUFF_CHAR_CLASS];
extern char const fr_base16_alphabet_encode_uc[SBUFF_CHAR_CLASS];
extern uint8_t const fr_base16_alphabet_decode_mc[SBUFF_CHAR_CLASS];	/* mixed case */

/** Check if char is in base16 alphabet
 *
 * @param[in] c		char to check.
 * @param[in] alphabet	to use.
 * @return
 *	- true if c is a character from the base32 alphabet.
 *	- false if character is not in the base32 alphabet.
 */
static inline bool fr_is_base16_nstd(char c, uint8_t const alphabet[static SBUFF_CHAR_CLASS])
{
	return alphabet[(uint8_t)c] < 16;
}

fr_slen_t	fr_base16_encode_nstd(fr_sbuff_t *out, fr_dbuff_t *in, char const alphabet[static SBUFF_CHAR_CLASS]);
#define		fr_base16_encode(_out, _in) \
		fr_base16_encode_nstd(_out, _in, fr_base16_alphabet_encode_lc)

/** Convert binary data to a hex string, allocating the output buffer
 *
 * Ascii encoded hex string will not be prefixed with '0x'
 *
 * @param[in] ctx	to allocate the buffer in.
 * @param[out] out	where to write the new buffer.
 * @param[in] in	input.
 * @return
 *	- >=0 the number of bytes written to out.
 *	- <0 number of bytes we would have needed to print the next hexit.
 */
static inline fr_slen_t fr_base16_aencode(TALLOC_CTX *ctx, char **out, fr_dbuff_t *in)
{
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	tctx;
	ssize_t			slen;

	fr_sbuff_init_talloc(ctx, &sbuff, &tctx,
			     (fr_dbuff_remaining(in) << 1),
			     SIZE_MAX);

	slen = fr_base16_encode(&sbuff, in);
	if (slen < 0) {
		fr_sbuff_trim_talloc(&sbuff, 0);
		*out = sbuff.buff;
		return slen;
	}

	*out = sbuff.buff;

	return (size_t)slen;
}

fr_slen_t	fr_base16_decode_nstd(fr_sbuff_parse_error_t *err, fr_dbuff_t *out, fr_sbuff_t *in,
				      bool no_trailing, uint8_t const alphabet[static SBUFF_CHAR_CLASS]);
#define		fr_base16_decode(_err, _out, _in, _no_trailing) \
		fr_base16_decode_nstd(_err, _out, _in, _no_trailing, fr_base16_alphabet_decode_mc)

#ifdef __cplusplus
}
#endif
