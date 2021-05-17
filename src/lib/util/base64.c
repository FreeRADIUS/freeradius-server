/*
 * @copyright 1999, 2000, 2001, 2004, 2005, 2006 Free Software
 * Foundation, Inc.
 *
 * This program is left software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/** Encode/decode binary data using printable characters
 *
 * @see RFC 3548 <http://www.ietf.org/rfc/rfc3548.txt>.
 *
 * @file src/lib/util/base64.c
 * @author Simon Josefsson.
 */
RCSID("$Id$")

#include "base64.h"

#include <freeradius-devel/util/strerror.h>

#define us(x) (uint8_t) x

char const fr_base64_str[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

uint8_t const fr_base64_alphabet_decode[UINT8_MAX] = {
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
	['+'] = 62,
	['.'] = 62,
	['/'] = 63
};

/** Base 64 encode binary data
 *
 * Base64 encode IN array of size INLEN into OUT array of size OUTLEN.
 *
 * @param[out] out	Where to write Base64 string.
 * @param[in] outlen	size of buffer including NULL byte.
 * @param[in] in	Data to encode.
 * @param[in] inlen	Length of data to encode.
 * @return
 *	- Amount of data we wrote to the buffer.
 *	- -1 if output buffer was too small.
 */
size_t fr_base64_encode(char *out, size_t outlen, uint8_t const *in, size_t inlen)
{
	char *p = out;
	size_t need = FR_BASE64_ENC_LENGTH(inlen) + 1;

	if (outlen < need) {
		fr_strerror_printf("Output buffer too small, exected %zu bytes, got %zu bytes", need, outlen);
		*out = '\0';
		return -1;
	}

	while (inlen) {
		*p++ = fr_base64_str[(in[0] >> 2) & 0x3f];
		*p++ = fr_base64_str[((in[0] << 4) + (--inlen ? in[1] >> 4 : 0)) & 0x3f];
		*p++ = (inlen ? fr_base64_str[((in[1] << 2) + (--inlen ? in[2] >> 6 : 0)) & 0x3f] : '=');
		*p++ = inlen ? fr_base64_str[in[2] & 0x3f] : '=';

		if (inlen) inlen--;
		if (inlen) in += 3;
	}

	p[0] = '\0';

	return p - out;
}

/* Decode base64 encoded input array.
 *
 * Decode base64 encoded input array IN of length INLEN to output array OUT that
 * can hold *OUTLEN bytes.  Return true if decoding was successful, i.e.
 * if the input was valid base64 data, -1 otherwise.
 *
 * If *OUTLEN is too small, as many bytes as possible will be written to OUT.
 * On return, *OUTLEN holds the length of decoded bytes in OUT.
 *
 * Note that as soon as any non-alphabet characters are encountered,
 * decoding is stopped and -1 is returned.
 *
 * This means that, when applicable, you must remove any line terminators
 * that is part of the data stream before calling this function.
 *
 * @param[out] out	Where to write the decoded data.
 * @param[in] outlen	The length of the output buffer.
 * @param[in] in	Base64 string to decode.
 * @param[in] inlen	length of Base64 string.
 * @return
 *	- <= 0 on failure.  The offset where the decoding error occurred as a negative integer.
 *	- Length of decoded data.
 */
ssize_t fr_base64_decode_nstd(uint8_t *out, size_t outlen, char const *in, size_t inlen, uint8_t const alphabet[static UINT8_MAX])
{
	uint8_t		*out_p = out;
	uint8_t		*out_end = out + outlen;
	char const	*p = in, *q;
	char const	*end = p + inlen;

	/*
	 *	Process complete 24bit quanta
	 */
	while ((end - p) >= 4) {
		if (!fr_is_base64_nstd(p[0], alphabet) || !fr_is_base64_nstd(p[1], alphabet) ||
		    !fr_is_base64_nstd(p[2], alphabet) || !fr_is_base64_nstd(p[3], alphabet)) break;

		/*
		 *	Check we have enough bytes to write out
		 *	the 24bit quantum.
		 */
		if ((out_end - out_p) <= 3) {
		oob:
			fr_strerror_printf("Output buffer too small, needed at least %zu bytes", outlen + 1);
			return p - end;
		}

		*out_p++ = ((alphabet[us(p[0])] << 2) | (alphabet[us(p[1])] >> 4));
		*out_p++ = ((alphabet[us(p[1])] << 4) & 0xf0) | (alphabet[us(p[2])] >> 2);
		*out_p++ = ((alphabet[us(p[2])] << 6) & 0xc0) | alphabet[us(p[3])];

		p += 4;	/* 32bit input -> 24bit output */
	}

	q = p;

	/*
	 *	Find the first non-base64 char
	 */
	while ((q < end) && fr_is_base64_nstd(*q, alphabet)) q++;

	switch (q - p) {
	case 0:		/* Final quantum is 24 bits */
		break;

	case 2:		/* Final quantum is 8 bits */
		if ((out_end - out_p) < 1) goto oob;
		*out_p++ = ((alphabet[us(p[0])] << 2) | (alphabet[us(p[1])] >> 4));
		p += 2;
		break;

	case 3:		/* Final quantum is 16 bits */
		if ((out_end - out_p) < 2) goto oob;
		*out_p++ = ((alphabet[us(p[0])] << 2) | (alphabet[us(p[1])] >> 4));
		*out_p++ = ((alphabet[us(p[1])] << 4) & 0xf0) | (alphabet[us(p[2])] >> 2);
		p += 3;
		break;

	default:
		fr_strerror_const("Invalid base64 padding data");
		return p - end;
	}

	while (p < end) {
		if (*p != '=') {
			fr_strerror_printf("Found non-padding char '%c' at end of base64 string", *p);
			return p - end;
		}
		p++;
	}

	return out_p - out;
}
