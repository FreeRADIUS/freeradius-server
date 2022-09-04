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
RCSID("$Id$")

#include <freeradius-devel/util/base16.h>
#define us(x) (uint8_t) x

/** lower case encode alphabet for base16
 *
 */
char const fr_base16_alphabet_encode_lc[UINT8_MAX + 1] = {
	[0] = '0',
	[1] = '1',
	[2] = '2',
	[3] = '3',
	[4] = '4',
	[5] = '5',
	[6] = '6',
	[7] = '7',
	[8] = '8',
	[9] = '9',
	[10] = 'a',
	[11] = 'b',
	[12] = 'c',
	[13] = 'd',
	[14] = 'e',
	[15] = 'f'
};

/** lower case encode alphabet for base16
 *
 */
char const fr_base16_alphabet_encode_uc[UINT8_MAX + 1] = {
	[0] = '0',
	[1] = '1',
	[2] = '2',
	[3] = '3',
	[4] = '4',
	[5] = '5',
	[6] = '6',
	[7] = '7',
	[8] = '8',
	[9] = '9',
	[10] = 'A',
	[11] = 'B',
	[12] = 'C',
	[13] = 'D',
	[14] = 'E',
	[15] = 'F'
};

/** Mixed case decode alphabet for base16
 *
 */
uint8_t const fr_base16_alphabet_decode_mc[UINT8_MAX + 1] = {
	F32(0, UINT8_MAX), F16(32, UINT8_MAX),
	['0'] = 0,
	['1'] = 1,
	['2'] = 2,
	['3'] = 3,
	['4'] = 4,
	['5'] = 5,
	['6'] = 6,
	['7'] = 7,
	['8'] = 8,
	['9'] = 9,
	F4(58, UINT8_MAX), F2(62, UINT8_MAX), F1(64, UINT8_MAX),
	['A'] = 10,	/* Uppercase */
	['B'] = 11,
	['C'] = 12,
	['D'] = 13,
	['E'] = 14,
	['F'] = 15,
	F16(71, UINT8_MAX), F8(87, UINT8_MAX), F2(95, UINT8_MAX),
	['a'] = 10,	/* Lowercase */
	['b'] = 11,
	['c'] = 12,
	['d'] = 13,
	['e'] = 14,
	['f'] = 15,
	F128(103, UINT8_MAX), F16(231, UINT8_MAX), F8(247, UINT8_MAX), F1(255, UINT8_MAX)
};

/** Convert binary data to a hex string
 *
 * Ascii encoded hex string will not be prefixed with '0x'
 *
 * @param[out] out		Output buffer to write to.
 * @param[in] in		input.
 * @param[in] alphabet		to use for encode.
 * @return
 *	- >=0 the number of bytes written to out.
 *	- <0 number of bytes we would have needed to print the next hexit.
 */
fr_slen_t fr_base16_encode_nstd(fr_sbuff_t *out, fr_dbuff_t *in, char const alphabet[static UINT8_MAX + 1])
{
	fr_sbuff_t	our_out = FR_SBUFF(out);
	fr_dbuff_t	our_in = FR_DBUFF(in);

	while (fr_dbuff_extend(&our_in)) {
		uint8_t a = *fr_dbuff_current(&our_in);

		FR_SBUFF_IN_CHAR_RETURN(&our_out, alphabet[us(a >> 4)], (alphabet[us(a & 0x0f)]));
		fr_dbuff_advance(&our_in, 1);
	}

	fr_sbuff_terminate(&our_out);	/* Ensure this is terminated, even on zero length input */
	fr_dbuff_set(in, &our_in);
	FR_SBUFF_SET_RETURN(out, &our_out);
}

/** Decode base16 encoded input
 *
 * @param[out] err		If non-null contains any parse errors.
 * @param[out] out		Where to write the decoded binary data.
 * @param[in] in		String to decode.
 * @param[in] no_trailing	Error out if we find non-base16 characters
 *				at the end of the string.
 * @param[in] alphabet		to use for decoding.
 * @return
 *	- < 0 on failure.  The offset where the decoding error occurred as a negative integer.
 *	- Length of decoded data.
 */
fr_slen_t fr_base16_decode_nstd(fr_sbuff_parse_error_t *err, fr_dbuff_t *out, fr_sbuff_t *in,
				bool no_trailing, uint8_t const alphabet[static UINT8_MAX + 1])
{
	fr_sbuff_t	our_in = FR_SBUFF(in);
	fr_dbuff_t	our_out = FR_DBUFF(out);

	while (fr_sbuff_extend_lowat(NULL, &our_in, 2) >= 2) {
		char	*p = fr_sbuff_current(&our_in);
		bool	a, b;

		a = fr_is_base16_nstd(p[0], alphabet);
		b = fr_is_base16_nstd(p[1], alphabet);
		if (!a || !b) {
			if (a && !b && no_trailing) {
		   		if (err) *err = FR_SBUFF_PARSE_ERROR_TRAILING;
		   		FR_SBUFF_ERROR_RETURN(&our_in);
		   	}
		   	break;
		}

		FR_DBUFF_IN_BYTES_RETURN(&our_out, (alphabet[us(p[0])] << 4) | alphabet[us(p[1])]);

		fr_sbuff_advance(&our_in, 2);
	};

	if (err) *err = FR_SBUFF_PARSE_OK;

	fr_sbuff_set(in, &our_in);
	return fr_dbuff_set(out, &our_out);
}
