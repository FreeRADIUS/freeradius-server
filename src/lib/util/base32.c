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
 * @file src/lib/util/base32.c
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include "base32.h"

#include <freeradius-devel/util/value.h>
#define us(x) (uint8_t) x

char const fr_base32_alphabet_encode[SBUFF_CHAR_CLASS] = {
	[26] = '2',
	[27] = '3',
	[28] = '4',
	[29] = '5',
	[30] = '6',
	[31] = '7',
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
};

uint8_t const fr_base32_alphabet_decode[SBUFF_CHAR_CLASS] = {
	F32(0, UINT8_MAX), F16(32, UINT8_MAX), F2(48, UINT8_MAX),
	['2'] = 26,
	['3'] = 27,
	['4'] = 28,
	['5'] = 29,
	['6'] = 30,
	['7'] = 31,
	F8(56, UINT8_MAX), F1(64, UINT8_MAX),
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
	F128(91, UINT8_MAX), F32(219, UINT8_MAX), F4(251, UINT8_MAX)
};

char const fr_base32_hex_alphabet_encode[SBUFF_CHAR_CLASS] = {
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
	[15] = 'F',
	[16] = 'G',
	[17] = 'H',
	[18] = 'I',
	[19] = 'J',
	[20] = 'K',
	[21] = 'L',
	[22] = 'M',
	[23] = 'N',
	[24] = 'O',
	[25] = 'P',
	[26] = 'Q',
	[27] = 'R',
	[28] = 'S',
	[29] = 'T',
	[30] = 'U',
	[31] = 'V',
};

uint8_t const fr_base32_hex_alphabet_decode[SBUFF_CHAR_CLASS] = {
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
	['A'] = 10,
	['B'] = 11,
	['C'] = 12,
	['D'] = 13,
	['E'] = 14,
	['F'] = 15,
	['G'] = 16,
	['H'] = 17,
	['I'] = 18,
	['J'] = 19,
	['K'] = 20,
	['L'] = 21,
	['M'] = 22,
	['N'] = 23,
	['O'] = 24,
	['P'] = 25,
	['Q'] = 26,
	['R'] = 27,
	['S'] = 28,
	['T'] = 29,
	['U'] = 30,
	['V'] = 31,
	F128(87, UINT8_MAX), F32(215, UINT8_MAX), F8(247, UINT8_MAX)
};

/** Base 64 encode binary data
 *
 * base32 encode in bytes to base32, writing to out.
 *
 * @param[out] out		Where to write base32 string.
 * @param[in] in		Data to encode.
 * @param[in] add_padding	Add padding bytes.
 * @param[in] alphabet		to use for encoding.
 * @return
 *	- Amount of data we wrote to the buffer.
 *	- <0 the number of bytes we would have needed in the ouput buffer.
 */
ssize_t fr_base32_encode_nstd(fr_sbuff_t *out, fr_dbuff_t *in,
			      bool add_padding, char const alphabet[static SBUFF_CHAR_CLASS])
{
	fr_sbuff_t		our_out = FR_SBUFF(out);
	fr_dbuff_t		our_in = FR_DBUFF(in);

	fr_strerror_const("Insufficient buffer space");

	for (;;) {
		uint8_t a, b, c, d, e;

		switch (fr_dbuff_extend_lowat(NULL, &our_in, 5)) {
		/*
		 *	Final quantum is 40 bits
		 */
		default:
			a = *fr_dbuff_current(&our_in);
			b = *(fr_dbuff_current(&our_in) + 1);
			c = *(fr_dbuff_current(&our_in) + 2);
			d = *(fr_dbuff_current(&our_in) + 3);
			e = *(fr_dbuff_current(&our_in) + 4);
			FR_SBUFF_IN_CHAR_RETURN(&our_out,
						alphabet[(a >> 3) & 0x1f],		/* a - 5 bits */
						alphabet[((a << 2) | (b >> 6)) & 0x1f], /* a - 3 bits, b - 2 bits */
						alphabet[(b >> 1) & 0x1f],		/* b - 5 bits */
						alphabet[((b << 4) | (c >> 4)) & 0x1f],	/* b - 1 bit, c - 4 bits */
						alphabet[((c << 1) | (d >> 7)) & 0x1f],	/* c - 4 bits, d - 1 bit */
						alphabet[(d >> 2) & 0x1f],		/* d - 5 bits */
						alphabet[((d << 3) | (e >> 5)) & 0x1f],	/* d - 2 bits, e - 3 bits */
						alphabet[e & 0x1f]);			/* e - 5 bits */
			fr_dbuff_advance(&our_in, 5);
			continue;

		/*
		 *	Final quantum is 32 bits
		 */
		case 4:
			a = *fr_dbuff_current(&our_in);
			b = *(fr_dbuff_current(&our_in) + 1);
			c = *(fr_dbuff_current(&our_in) + 2);
			d = *(fr_dbuff_current(&our_in) + 3);
			FR_SBUFF_IN_CHAR_RETURN(&our_out,
						alphabet[(a >> 3) & 0x1f],		/* a - 5 bits */
						alphabet[((a << 2) | (b >> 6)) & 0x1f], /* a - 3 bits, b - 2 bits */
						alphabet[(b >> 1) & 0x1f],		/* b - 5 bits */
						alphabet[((b << 4) | (c >> 4)) & 0x1f],	/* b - 1 bit, c - 4 bits */
						alphabet[((c << 1) | (d >> 7)) & 0x1f],	/* c - 4 bits, d - 1 bit */
						alphabet[(d >> 2) & 0x1f],		/* d - 5 bits */
						alphabet[(d << 3) & 0x1f]);		/* d - 2 bits */
			fr_dbuff_advance(&our_in, 4);
			if (add_padding) FR_SBUFF_IN_CHAR_RETURN(&our_out, '=');
			break;

		/*
		 *	Final quantum is 24 bits
		 */
		case 3:
			a = *fr_dbuff_current(&our_in);
			b = *(fr_dbuff_current(&our_in) + 1);
			c = *(fr_dbuff_current(&our_in) + 2);
			FR_SBUFF_IN_CHAR_RETURN(&our_out,
						alphabet[(a >> 3) & 0x1f],		/* a - 5 bits */
						alphabet[((a << 2) | (b >> 6)) & 0x1f], /* a - 3 bits, b - 2 bits */
						alphabet[(b >> 1) & 0x1f],		/* b - 5 bits */
						alphabet[((b << 4) | (c >> 4)) & 0x1f],	/* b - 1 bit, c - 4 bits */
						alphabet[(c << 1) & 0x1f]);		/* c - 4 bits */
			fr_dbuff_advance(&our_in, 3);
			if (add_padding) FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "===");
			break;

		/*
		 *	Final quantum is 16 bits
		 */
		case 2:
			a = *fr_dbuff_current(&our_in);
			b = *(fr_dbuff_current(&our_in) + 1);
			FR_SBUFF_IN_CHAR_RETURN(&our_out,
						alphabet[(a >> 3) & 0x1f],		/* a - 5 bits */
						alphabet[((a << 2) | (b >> 6)) & 0x1f], /* a - 3 bits, b - 2 bits */
						alphabet[(b >> 1) & 0x1f],		/* b - 5 bits */
						alphabet[(b << 4) & 0x1f]);		/* b - 1 bit, c - 4 bits */
			fr_dbuff_advance(&our_in, 2);
			if (add_padding) FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "====");
			break;

		/*
		 *	Final quantum is 8 bits
		 */
		case 1:
			a = *fr_dbuff_current(&our_in);
			FR_SBUFF_IN_CHAR_RETURN(&our_out,
						alphabet[(a >> 3) & 0x1f],		/* a - 5 bits */
						alphabet[(a << 2) & 0x1f]); 		/* a - 3 bits, b - 2 bits */
			fr_dbuff_advance(&our_in, 1);
			if (add_padding) FR_SBUFF_IN_STRCPY_LITERAL_RETURN(&our_out, "======");
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

/* Decode base32 encoded input
 *
 * @param[out] err		If non-null contains any parse errors.
 * @param[out] out		Where to write the decoded binary data.
 * @param[in] in		String to decode.
 * @param[in] expect_padding	Expect, and advanced past, padding characters '=' at
 *				the end of the string.  Produce an error if we find
 *				insufficient padding characters.
 * @param[in] no_trailing	Error out if we find non-base32 characters
 *				at the end of the string.
 * @param[in] alphabet		to use for decoding.
 * @return
 *	- < 0 on failure.  The offset where the decoding error occurred as a negative integer.
 *	- Length of decoded data.
 */
fr_slen_t fr_base32_decode_nstd(fr_sbuff_parse_error_t *err, fr_dbuff_t *out, fr_sbuff_t *in,
				bool expect_padding, bool no_trailing, uint8_t const alphabet[static SBUFF_CHAR_CLASS])
{
	fr_sbuff_t		our_in = FR_SBUFF(in);
	fr_dbuff_t		our_out = FR_DBUFF(out);
	fr_sbuff_marker_t	m_final;
	size_t			len;
	uint8_t			pad;

	/*
	 *	Process complete 40bit quanta
	 */
	while (fr_sbuff_extend_lowat(NULL, &our_in, 8) >= 8) {
		char *p = fr_sbuff_current(&our_in);

		if (!fr_is_base32_nstd(p[0], alphabet) ||
		    !fr_is_base32_nstd(p[1], alphabet) ||
		    !fr_is_base32_nstd(p[2], alphabet) ||
		    !fr_is_base32_nstd(p[3], alphabet) ||
		    !fr_is_base32_nstd(p[4], alphabet) ||
		    !fr_is_base32_nstd(p[5], alphabet) ||
		    !fr_is_base32_nstd(p[6], alphabet) ||
		    !fr_is_base32_nstd(p[7], alphabet)) break;

		if (fr_dbuff_in_bytes(&our_out,
				      (alphabet[us(p[0])] << 3) | (alphabet[us(p[1])] >> 2),
				      (alphabet[us(p[1])] << 6) | (alphabet[us(p[2])] << 1) | (alphabet[us(p[3])] >> 4),
				      (alphabet[us(p[3])] << 4) | (alphabet[us(p[4])] >> 1),
				      (alphabet[us(p[4])] << 7) | (alphabet[us(p[5])] << 2) | (alphabet[us(p[6])] >> 3),
				      (alphabet[us(p[6])] << 5) | alphabet[us(p[7])]) != 5) {
		oob:
			fr_strerror_printf("Output buffer too small, needed at least %zu bytes",
					   fr_dbuff_used(&our_out) + 1);

			if (err) *err = FR_SBUFF_PARSE_ERROR_OUT_OF_SPACE;

			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		fr_sbuff_advance(&our_in, 8);
	}

	fr_sbuff_marker(&m_final, &our_in);

	/*
	 *	Find the first non-base32 char
	 */
	while (fr_sbuff_extend(&our_in) && fr_is_base32_nstd(fr_sbuff_char(&our_in, '\0'), alphabet)) {
		fr_sbuff_advance(&our_in, 1);
	}

	len = fr_sbuff_behind(&m_final);
	switch (len) {
	case 0:		/* Final quantum is 40 bits */
		pad = 0;
		break;

	case 2:		/* Final quantum is 8 bits */
	{
		char *p = fr_sbuff_current(&m_final);

		if (fr_dbuff_in_bytes(&our_out,
				      (alphabet[us(p[0])] << 3) | (alphabet[us(p[1])] >> 2)) != 1) goto oob;
		pad = 6;
	}
		break;

	case 4:		/* Final quantum is 16 bits */
	{
		char *p = fr_sbuff_current(&m_final);

		if (fr_dbuff_in_bytes(&our_out,
				      (alphabet[us(p[0])] << 3) | (alphabet[us(p[1])] >> 2),
				      (alphabet[us(p[1])] << 6) | (alphabet[us(p[2])] << 1) | (alphabet[us(p[3])] >> 4))
				      != 2) goto oob;
		pad = 4;
	}
		break;

	case 5:		/* Final quantum is 24 bits */
	{
		char *p = fr_sbuff_current(&m_final);

		if (fr_dbuff_in_bytes(&our_out,
				      (alphabet[us(p[0])] << 3) | (alphabet[us(p[1])] >> 2),
				      (alphabet[us(p[1])] << 6) | (alphabet[us(p[2])] << 1) | (alphabet[us(p[3])] >> 4),
				      (alphabet[us(p[3])] << 4) | (alphabet[us(p[4])] >> 1)) != 3) goto oob;
		pad = 3;
	}
		break;

	case 7:		/* Final quantum is 32 bits */
	{
		char *p = fr_sbuff_current(&m_final);

		if (fr_dbuff_in_bytes(&our_out,
				      (alphabet[us(p[0])] << 3) | (alphabet[us(p[1])] >> 2),
				      (alphabet[us(p[1])] << 6) | (alphabet[us(p[2])] << 1) | (alphabet[us(p[3])] >> 4),
				      (alphabet[us(p[3])] << 4) | (alphabet[us(p[4])] >> 1),
				      (alphabet[us(p[4])] << 7) | (alphabet[us(p[5])] << 2) | (alphabet[us(p[6])] >> 3))
				      != 4) goto oob;
		pad = 1;
	}
		break;

	default:
		fr_strerror_printf("Invalid base32 final quantum length (%zu)", len);

	bad_format:
		if (err) *err = FR_SBUFF_PARSE_ERROR_FORMAT;

		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	if (expect_padding) {
		uint8_t i;
		for (i = 0; i < pad; i++) {
			if (!fr_sbuff_extend(&our_in)) {
				fr_strerror_printf("Missing padding '=' at end of base32 string.  "
						   "Expected %u padding char(s)", pad);

				if (err) *err = FR_SBUFF_PARSE_ERROR_FORMAT;

				goto bad_format;
			}
			if (!fr_sbuff_next_if_char(&our_in, '=')) {
				fr_strerror_printf("Found non-padding char '%c' at end of base32 string",
						   fr_sbuff_char(&our_in, '\0'));

				if (err) *err = FR_SBUFF_PARSE_ERROR_FORMAT;

				goto bad_format;
			}
		}
	}

	if (no_trailing && fr_sbuff_extend(&our_in)) {
		fr_strerror_printf("Found trailing garbage '%c' at end of base32 string",
				   fr_sbuff_char(&our_in, '\0'));

		if (err) *err = FR_SBUFF_PARSE_ERROR_TRAILING;

		FR_SBUFF_ERROR_RETURN(&our_in);
	}

	if (err) *err = FR_SBUFF_PARSE_OK;

	fr_sbuff_set(in, &our_in);
	return fr_dbuff_set(out, &our_out);
}
