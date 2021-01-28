/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** A generic string buffer structure for string printing and parsing
 *
 * @file src/lib/util/sbuff.c
 *
 * @copyright 2020 Arran Cudbard-Bell \<a.cudbardb@freeradius.org\>
 */
RCSID("$Id$")

#include <freeradius-devel/util/hex.h>

static char const hextab[] = "0123456789abcdef";

/** Convert hex strings to binary data
 *
 * @param[out] err		If non-null contains any parse errors.
 * @param[out] out		Output buffer to write to.
 * @param[in] in		Input string.
 * @param[in] no_trailing	Error and return 0 if we find an odd length hex
 *      			string.
 * @return
 *	- >=0 the number of bytes written to out.
 *	- 0 no input data, or parse error.
 *	- <0 number of bytes we would have needed to copy the next hexit.
 */
ssize_t fr_hex2bin(fr_sbuff_parse_error_t *err, fr_dbuff_t *out, fr_sbuff_t *in, bool no_trailing)
{
	size_t		total = 0;
	fr_sbuff_t	our_in = FR_SBUFF_NO_ADVANCE(in);
	fr_dbuff_t	our_out = FR_DBUFF_NO_ADVANCE(out);

	while (fr_sbuff_extend_lowat(NULL, &our_in, 2) >= 2) {
		char *c1, *c2 = NULL;

		if(!(c1 = memchr(hextab, tolower((int) *fr_sbuff_current(&our_in)), sizeof(hextab))) ||
		   !(c2 = memchr(hextab, tolower((int) *(fr_sbuff_current(&our_in) + 1)), sizeof(hextab)))) {
			if (!c2 && no_trailing) {
			got_trailing:
		   		if (err) *err = FR_SBUFF_PARSE_ERROR_TRAILING;
		   		return 0;
		   	}
			goto done;
		}

		FR_DBUFF_IN_BYTES_RETURN(&our_out, ((c1 - hextab) << 4) + (c2 - hextab));

		fr_sbuff_advance(&our_in, 2);
		total++;
	};

	if (no_trailing && (fr_sbuff_remaining(&our_in) > 0) &&
	    memchr(hextab, tolower((int) *our_in.p), sizeof(hextab))) goto got_trailing;

done:
	fr_sbuff_set(in, &our_in);
	fr_dbuff_set(out, &our_out);

	if (err) *err = FR_SBUFF_PARSE_OK;

	return total;
}

/** Convert binary data to a hex string
 *
 * Ascii encoded hex string will not be prefixed with '0x'
 *
 * @param[out] out	Output buffer to write to.
 * @param[in] in	input.
 * @param[in] len	how many bytes convert to hex.
 *			Pass SIZE_MAX to copy all available data.
 * @return
 *	- >=0 the number of bytes written to out.
 *	- <0 number of bytes we would have needed to print the next hexit.
 */
ssize_t fr_bin2hex(fr_sbuff_t *out, fr_dbuff_t *in, size_t len)
{
	size_t	total = 0;

	while ((fr_dbuff_extend_lowat(NULL, in, 2) > 0) && (total < len)) {
		FR_SBUFF_IN_CHAR_RETURN(out, hextab[((*in->p) >> 4) & 0x0f], hextab[*in->p & 0x0f]);

		fr_dbuff_advance(in, 1);
		total++;
	};
	return total * 2;
}
