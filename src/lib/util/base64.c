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
 * @file src/lib/util/base64.c
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include "base64.h"

#include <freeradius-devel/util/value.h>
#define us(x) (uint8_t) x

char const fr_base64_alphabet_encode[UINT8_MAX] = {
	[62] = '+',
	[63] = '/',
	[52] = '0',
	[53] = '1',
	[54] = '2',
	[55] = '3',
	[56] = '4',
	[57] = '5',
	[58] = '6',
	[59] = '7',
	[60] = '8',
	[61] = '9',
	[0] = 'A',
	[1] = 'B',
	[2] = 'C',
	[3] = 'D',
	[4] = 'E',
	[5] = 'F',
	[6] = 'G',
	[7] = 'H',
	[8] = 'I',
	[9] = 'J',
	[10] = 'K',
	[11] = 'L',
	[12] = 'M',
	[13] = 'N',
	[14] = 'O',
	[15] = 'P',
	[16] = 'Q',
	[17] = 'R',
	[18] = 'S',
	[19] = 'T',
	[20] = 'U',
	[21] = 'V',
	[22] = 'W',
	[23] = 'X',
	[24] = 'Y',
	[25] = 'Z',
	[26] = 'a',
	[27] = 'b',
	[28] = 'c',
	[29] = 'd',
	[30] = 'e',
	[31] = 'f',
	[32] = 'g',
	[33] = 'h',
	[34] = 'i',
	[35] = 'j',
	[36] = 'k',
	[37] = 'l',
	[38] = 'm',
	[39] = 'n',
	[40] = 'o',
	[41] = 'p',
	[42] = 'q',
	[43] = 'r',
	[44] = 's',
	[45] = 't',
	[46] = 'u',
	[47] = 'v',
	[48] = 'w',
	[49] = 'x',
	[50] = 'y',
	[51] = 'z'
};

uint8_t const fr_base64_alphabet_decode[UINT8_MAX] = {
	F32(0, UINT8_MAX), F8(32, UINT8_MAX), F2(40, UINT8_MAX),
	['+'] = 62,
	F2(44, UINT8_MAX),
	F1(46, UINT8_MAX),
	['/'] = 63,
	['0'] = 52,
	['1'] = 53,
	['2'] = 54,
	['3'] = 55,
	['4'] = 56,
	['5'] = 57,
	['6'] = 58,
	['7'] = 59,
	['8'] = 60,
	['9'] = 61,
	F4(58, UINT8_MAX), F2(62, UINT8_MAX), F1(64, UINT8_MAX),
	['A'] = 0,
	['B'] = 1,
	['C'] = 2,
	['D'] = 3,
	['E'] = 4,
	['F'] = 5,
	['G'] = 6,
	['H'] = 7,
	['I'] = 8,
	['J'] = 9,
	['K'] = 10,
	['L'] = 11,
	['M'] = 12,
	['N'] = 13,
	['O'] = 14,
	['P'] = 15,
	['Q'] = 16,
	['R'] = 17,
	['S'] = 18,
	['T'] = 19,
	['U'] = 20,
	['V'] = 21,
	['W'] = 22,
	['X'] = 23,
	['Y'] = 24,
	['Z'] = 25,
	F4(91, UINT8_MAX), F2(95, UINT8_MAX),
	['a'] = 26,
	['b'] = 27,
	['c'] = 28,
	['d'] = 29,
	['e'] = 30,
	['f'] = 31,
	['g'] = 32,
	['h'] = 33,
	['i'] = 34,
	['j'] = 35,
	['k'] = 36,
	['l'] = 37,
	['m'] = 38,
	['n'] = 39,
	['o'] = 40,
	['p'] = 41,
	['q'] = 42,
	['r'] = 43,
	['s'] = 44,
	['t'] = 45,
	['u'] = 46,
	['v'] = 47,
	['w'] = 48,
	['x'] = 49,
	['y'] = 50,
	['z'] = 51,
	F128(123, UINT8_MAX),
	F4(251, UINT8_MAX)
};

char const fr_base64_url_alphabet_encode[UINT8_MAX] = {
	[62] = '-',
	[52] = '0',
	[53] = '1',
	[54] = '2',
	[55] = '3',
	[56] = '4',
	[57] = '5',
	[58] = '6',
	[59] = '7',
	[60] = '8',
	[61] = '9',
	[63] = '_',
	[0] = 'A',
	[1] = 'B',
	[2] = 'C',
	[3] = 'D',
	[4] = 'E',
	[5] = 'F',
	[6] = 'G',
	[7] = 'H',
	[8] = 'I',
	[9] = 'J',
	[10] = 'K',
	[11] = 'L',
	[12] = 'M',
	[13] = 'N',
	[14] = 'O',
	[15] = 'P',
	[16] = 'Q',
	[17] = 'R',
	[18] = 'S',
	[19] = 'T',
	[20] = 'U',
	[21] = 'V',
	[22] = 'W',
	[23] = 'X',
	[24] = 'Y',
	[25] = 'Z',
	[26] = 'a',
	[27] = 'b',
	[28] = 'c',
	[29] = 'd',
	[30] = 'e',
	[31] = 'f',
	[32] = 'g',
	[33] = 'h',
	[34] = 'i',
	[35] = 'j',
	[36] = 'k',
	[37] = 'l',
	[38] = 'm',
	[39] = 'n',
	[40] = 'o',
	[41] = 'p',
	[42] = 'q',
	[43] = 'r',
	[44] = 's',
	[45] = 't',
	[46] = 'u',
	[47] = 'v',
	[48] = 'w',
	[49] = 'x',
	[50] = 'y',
	[51] = 'z'
};

uint8_t const fr_base64_url_alphabet_decode[UINT8_MAX] = {
	F32(0, UINT8_MAX), F8(32, UINT8_MAX), F4(40, UINT8_MAX),
	['-'] = 62,
	F2(46, UINT8_MAX),
	['0'] = 52,
	['1'] = 53,
	['2'] = 54,
	['3'] = 55,
	['4'] = 56,
	['5'] = 57,
	['6'] = 58,
	['7'] = 59,
	['8'] = 60,
	['9'] = 61,
	F4(58, UINT8_MAX), F2(62, UINT8_MAX), F1(64, UINT8_MAX),
	['A'] = 0,
	['B'] = 1,
	['C'] = 2,
	['D'] = 3,
	['E'] = 4,
	['F'] = 5,
	['G'] = 6,
	['H'] = 7,
	['I'] = 8,
	['J'] = 9,
	['K'] = 10,
	['L'] = 11,
	['M'] = 12,
	['N'] = 13,
	['O'] = 14,
	['P'] = 15,
	['Q'] = 16,
	['R'] = 17,
	['S'] = 18,
	['T'] = 19,
	['U'] = 20,
	['V'] = 21,
	['W'] = 22,
	['X'] = 23,
	['Y'] = 24,
	['Z'] = 25,
	F4(91, UINT8_MAX),
	['_'] = 63,
	F1(96, UINT8_MAX),
	['a'] = 26,
	['b'] = 27,
	['c'] = 28,
	['d'] = 29,
	['e'] = 30,
	['f'] = 31,
	['g'] = 32,
	['h'] = 33,
	['i'] = 34,
	['j'] = 35,
	['k'] = 36,
	['l'] = 37,
	['m'] = 38,
	['n'] = 39,
	['o'] = 40,
	['p'] = 41,
	['q'] = 42,
	['r'] = 43,
	['s'] = 44,
	['t'] = 45,
	['u'] = 46,
	['v'] = 47,
	['w'] = 48,
	['x'] = 49,
	['y'] = 50,
	['z'] = 51,
	F128(123, UINT8_MAX),
	F4(251, UINT8_MAX)
};

/** Base 64 encode binary data
 *
 * Base64 encode in bytes to base64, writing to out.
 *
 * @param[out] out		Where to write Base64 string.
 * @param[in] in		Data to encode.
 * @param[in] add_padding	Add padding bytes.
 * @param[in] alphabet		to use for encoding.
 * @return
 *	- Amount of data we wrote to the buffer.
 *	- <0 the number of bytes we would have needed in the ouput buffer.
 */
ssize_t fr_base64_encode_nstd(fr_sbuff_t *out, fr_dbuff_t *in,
			      bool add_padding, char const alphabet[static UINT8_MAX])
{
	fr_sbuff_t		our_out = FR_SBUFF(out);
	fr_dbuff_t		our_in = FR_DBUFF(in);

	fr_strerror_const("Insufficient buffer space");

	for (;;) {
		uint8_t a, b, c;

		switch (fr_dbuff_extend_lowat(NULL, &our_in, 3)) {
		/*
		 *	Enough bytes for a 24bit quanta
		 */
		default:
			a = *fr_dbuff_current(&our_in);
			b = *(fr_dbuff_current(&our_in) + 1);
			c = *(fr_dbuff_current(&our_in) + 2);
			FR_SBUFF_IN_CHAR_RETURN(&our_out,
						alphabet[(a >> 2) & 0x3f],
						alphabet[((a << 4) | (b >> 4)) & 0x3f],
						alphabet[((b << 2) | (c >> 6)) & 0x3f],
						alphabet[c & 0x3f]);
			fr_dbuff_advance(&our_in, 3);
			continue;

		case 2:
			a = *fr_dbuff_current(&our_in);
			b = *(fr_dbuff_current(&our_in) + 1);
			FR_SBUFF_IN_CHAR_RETURN(&our_out,
						alphabet[(a >> 2) & 0x3f],
						alphabet[((a << 4) | (b >> 4)) & 0x3f],
						alphabet[(b << 2) & 0x3f]);
			fr_dbuff_advance(&our_in, 2);	/* Place at the end */
			if (add_padding) FR_SBUFF_IN_CHAR_RETURN(&our_out, '=');
			break;

		case 1:
			a = *fr_dbuff_current(&our_in);
			FR_SBUFF_IN_CHAR_RETURN(&our_out,
						alphabet[(a >> 2) & 0x3f],
						alphabet[(a << 4) & 0x3f]);
			fr_dbuff_advance(&our_in, 1);	/* Place at the end */
			if (add_padding) FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "==");
			break;

		case 0:
			break;
		}
		break;
	}

	fr_strerror_clear();

	fr_sbuff_terminate(&our_out);	/* Ensure this is terminated, even on zero length input */
	fr_dbuff_set(in, &our_in);
	FR_SBUFF_SET_RETURN(out, &our_out);
}

/* Decode base64 encoded input array.
 *
 * @param[out] err		If non-null contains any parse errors.
 * @param[out] out		Where to write the decoded binary data.
 * @param[in] in		String to decode.
 * @param[in] expect_padding	Expect, and advanced past, padding characters '=' at
 *				the end of the string.  Produce an error if we find
 *				insufficient padding characters.
 * @param[in] no_trailing	Error out if we find non-base64 characters
 *				at the end of the string.
 * @param[in] alphabet		to use for decoding.
 * @return
 *	- < 0 on failure.  The offset where the decoding error occurred as a negative integer.
 *	- Length of decoded data.
 */
fr_slen_t fr_base64_decode_nstd(fr_sbuff_parse_error_t *err, fr_dbuff_t *out, fr_sbuff_t *in,
				bool expect_padding, bool no_trailing, uint8_t const alphabet[static UINT8_MAX])
{
	fr_sbuff_t		our_in = FR_SBUFF(in);
	fr_dbuff_t		our_out = FR_DBUFF(out);
	fr_sbuff_marker_t	m_final;
	uint8_t			pad;

	/*
	 *	Process complete 24bit quanta
	 */
	while (fr_sbuff_extend_lowat(NULL, &our_in, 4) >= 4) {
		char *p = fr_sbuff_current(&our_in);

		if (!fr_is_base64_nstd(p[0], alphabet) ||
		    !fr_is_base64_nstd(p[1], alphabet) ||
		    !fr_is_base64_nstd(p[2], alphabet) ||
		    !fr_is_base64_nstd(p[3], alphabet)) break;

		if (fr_dbuff_in_bytes(&our_out,
				      ((alphabet[us(p[0])] << 2) | (alphabet[us(p[1])] >> 4)),
				      ((alphabet[us(p[1])] << 4) & 0xf0) | (alphabet[us(p[2])] >> 2),
				      ((alphabet[us(p[2])] << 6) & 0xc0) | alphabet[us(p[3])]) != 3) {
		oob:
			fr_strerror_printf("Output buffer too small, needed at least %zu bytes",
					   fr_dbuff_used(&our_out) + 1);

			if (err) *err = FR_SBUFF_PARSE_ERROR_OUT_OF_SPACE;

			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		fr_sbuff_advance(&our_in, 4);
	}

	fr_sbuff_marker(&m_final, &our_in);

	/*
	 *	Find the first non-base64 char
	 */
	while (fr_sbuff_extend(&our_in) && fr_is_base64_nstd(fr_sbuff_char(&our_in, '\0'), alphabet)) {
		fr_sbuff_advance(&our_in, 1);
	}

	switch (fr_sbuff_behind(&m_final)) {
	case 0:		/* Final quantum is 24 bits */
		pad = 0;
		break;

	case 2:		/* Final quantum is 8 bits */
	{
		char *p = fr_sbuff_current(&m_final);

		if (fr_dbuff_in_bytes(&our_out,
				      (alphabet[us(p[0])] << 2) | (alphabet[us(p[1])] >> 4)) != 1) goto oob;
		pad = 2;
	}
		break;

	case 3:		/* Final quantum is 16 bits */
	{
		char *p = fr_sbuff_current(&m_final);

		if (fr_dbuff_in_bytes(&our_out,
				      ((alphabet[us(p[0])] << 2) | (alphabet[us(p[1])] >> 4)),
				      ((alphabet[us(p[1])] << 4) & 0xf0) | (alphabet[us(p[2])] >> 2)) != 2) goto oob;
		pad = 1;
	}
		break;

	default:
		fr_strerror_const("Invalid base64 padding data");

	bad_format:
		if (err) *err = FR_SBUFF_PARSE_ERROR_FORMAT;

		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	if (expect_padding) {
		uint8_t i;
		for (i = 0; i < pad; i++) {
			if (!fr_sbuff_extend(&our_in)) {
				fr_strerror_printf("Missing padding '=' at end of base64 string.  "
						   "Expected %u padding char(s)", pad);
				goto bad_format;
			}
			if (!fr_sbuff_next_if_char(&our_in, '=')) {
				fr_strerror_printf("Found non-padding char '%c' at end of base64 string",
						   fr_sbuff_char(&our_in, '\0'));
				goto bad_format;
			}
		}
	}

	if (no_trailing && fr_sbuff_extend(&our_in)) {
		fr_strerror_printf("Found trailing garbage '%c' at end of base64 string",
				   fr_sbuff_char(&our_in, '\0'));

		if (err) *err = FR_SBUFF_PARSE_ERROR_TRAILING;

		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	fr_sbuff_set(in, &our_in);
	return fr_dbuff_set(out, &our_out);
}
