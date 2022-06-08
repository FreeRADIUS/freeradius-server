/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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

/** Size printing and parsing functions
 *
 * @file src/lib/util/size.c
 *
 * @copyright 2022 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/sbuff.h>

#include "size.h"

/** Parse a size string with optional unit
 *
 * Default scale with no suffix is bytes.
 *
 * @param[out] out	Parsed and scaled size
 * @param[in] in	sbuff to parse.
 * @return
 *	- >0 on success.
 *	- <0 on error.
 */
fr_slen_t fr_size_from_str(size_t *out, fr_sbuff_t *in)
{
	fr_sbuff_t	our_in = FR_SBUFF(in);
	char		c = '\0';
	uint64_t	size;

	*out = 0;

	if (fr_sbuff_out(NULL, &size, &our_in) < 0) return fr_sbuff_error(&our_in);
	c = tolower(*fr_sbuff_current(&our_in));
	switch (c) {
	case 'n':		/* nibble */
		if (size & 0x01) {
			fr_strerror_const("Sizes specified in nibbles must be an even number");
			fr_sbuff_set_to_start(&our_in);
			return fr_sbuff_error(&our_in);
		}
		size /= 2;
		break;

	case '\0':
	case 'b':		/* byte */
		break;

	case 'k':		/* kibibyte */
		if (!fr_multiply(&size, size, 1024)) {
		overflow:
			fr_strerror_printf("Value must be less than %zu", (size_t)SIZE_MAX);
			fr_sbuff_set_to_start(&our_in);
			return fr_sbuff_error(&our_in);
		}
		(void)fr_sbuff_next_if_char(&our_in, 'b');
		break;

	case 'm':		/* mebibyte */
		if (!fr_multiply(&size, size, ((uint64_t)1024 * 1024))) goto overflow;
		(void)fr_sbuff_next_if_char(&our_in, 'b');
		break;

	case 'g':		/* gibibyte */
		if (!fr_multiply(&size, size, ((uint64_t)1024 * 1024 * 1024))) goto overflow;
		(void)fr_sbuff_next_if_char(&our_in, 'b');
		break;

	case 't':		/* tebibyte */
		if (!fr_multiply(&size, size, ((uint64_t)1024 * 1024 * 1024 * 1024))) goto overflow;
		(void)fr_sbuff_next_if_char(&our_in, 'b');
		break;

	case 'p':		/* pebibyte */
		if (!fr_multiply(&size, size, ((uint64_t)1024 * 1024 * 1024 * 1024 * 1024))) goto overflow;
		(void)fr_sbuff_next_if_char(&our_in, 'b');
		break;

	case 'e':		/* ebibyte */
		if (!fr_multiply(&size, size, ((uint64_t)1024 * 1024 * 1024 * 1024 * 1024 * 1024))) goto overflow;
		(void)fr_sbuff_next_if_char(&our_in, 'b');
		break;

	default:
		fr_strerror_printf("Unknown unit '%c'", c);
		return fr_sbuff_error(&our_in);
	}

	if (size > SIZE_MAX) {
		fr_strerror_printf("Value %" PRIu64 " is greater than the maximum "
				   "file/memory size of this system (%zu)", size, (size_t)SIZE_MAX);

		goto overflow;
	}

	*out = (size_t)size;

	return fr_sbuff_set(in, &our_in);
}

/** Print a size string with unit
 *
 * Suffix is the largest unit possible without losing precision.
 *
 * @param[out] out	To write size to.
 * @param[in] in	size to print.
 * @return
 *	- >0 on success.
 *	- <0 on error.
 */
fr_slen_t fr_size_to_str(fr_sbuff_t *out, size_t in)
{
	fr_sbuff_t	our_out = FR_SBUFF(out);
	uint8_t		pos = fr_low_bit_pos((uint64_t)in);

	/*
	 *	Precision is greater than a kb (byte)
	 */
	if (pos <= 10) {
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%zub", in);
	/*
	 *	Precision is greater than a mb (kibibyte)
	 */
	} else if (pos <= 20) {
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%zuk", in / 1024);
	/*
	 *	Precision is greater than a gb (mebibyte)
	 */
	} else if (pos <= 30) {
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%zum", in / ((uint64_t)1024 * 1024));
	/*
	 *	Precision is greater than a tb (gibibyte)
	 */
	} else if (pos <= 40) {
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%zug", in / ((uint64_t)1024 * 1024 * 1024));
	/*
	 *	Precision is greater than a pb (tebibyte)
	 */
	} else if (pos <= 50) {
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%zut", in / ((uint64_t)1024 * 1024 * 1024 * 1024));
	/*
	 *	Precision is greater than a eb (pebibyte)
	 */
	} else if (pos <= 60) {
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%zup", in / ((uint64_t)1024 * 1024 * 1024 * 1024 * 1024));

	/*
	 *	Precision is greater than a zb (exibyte)
	 */
	} else {
		FR_SBUFF_IN_SPRINTF_RETURN(&our_out, "%zue", in / ((uint64_t)1024 * 1024 * 1024 * 1024 * 1024 * 1024));
	}

	return fr_sbuff_set(out, &our_out);
}
