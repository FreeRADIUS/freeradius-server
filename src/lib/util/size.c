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

#include <freeradius-devel/util/math.h>
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
	static uint64_t	base2_units[]= {
		['k'] = (uint64_t)1024,
		['m'] = (uint64_t)1024 * 1024,
		['g'] = (uint64_t)1024 * 1024 * 1024,
		['t'] = (uint64_t)1024 * 1024 * 1024 * 1024,
		['p'] = (uint64_t)1024 * 1024 * 1024 * 1024 * 1024,
		['e'] = (uint64_t)1024 * 1024 * 1024 * 1024 * 1024 * 1024,
	};
	static size_t base2_units_len = NUM_ELEMENTS(base2_units);

	static uint64_t base10_units[] = {
		['k'] = (uint64_t)1000,
		['m'] = (uint64_t)1000 * 1000,
		['g'] = (uint64_t)1000 * 1000 * 1000,
		['t'] = (uint64_t)1000 * 1000 * 1000 * 1000,
		['p'] = (uint64_t)1000 * 1000 * 1000 * 1000 * 1000,
		['e'] = (uint64_t)1000 * 1000 * 1000 * 1000 * 1000 * 1000,
	};
	static size_t base10_units_len = NUM_ELEMENTS(base10_units);

	fr_sbuff_t	our_in = FR_SBUFF(in);
	char		c = '\0';
	uint64_t	size;

	*out = 0;

	if (fr_sbuff_out(NULL, &size, &our_in) < 0) FR_SBUFF_ERROR_RETURN(&our_in);
	if (!fr_sbuff_extend(&our_in)) goto done;

	c = tolower(fr_sbuff_char(&our_in, '\0'));

	/*
	 *	Special cases first...
	 */
	switch (c) {
	case 'n':		/* nibble */
		fr_sbuff_next(&our_in);
		if (size & 0x01) {
			fr_strerror_const("Sizes specified in nibbles must be an even number");
			fr_sbuff_set_to_start(&our_in);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}
		size /= 2;
		break;

	case '\0':
		break;

	case 'b':		/* byte */
		fr_sbuff_next(&our_in);
		break;

	default:
	{
		uint64_t	*units;
		size_t		units_len;
		bool		is_base2;

		fr_sbuff_next(&our_in);
		is_base2 = fr_sbuff_next_if_char(&our_in, 'i') || fr_sbuff_next_if_char(&our_in, 'I');

		if (!fr_sbuff_next_if_char(&our_in, 'b')) (void)fr_sbuff_next_if_char(&our_in, 'B');	/* Optional */

		if (is_base2) {
			units = base2_units;
			units_len = base2_units_len;
		} else {
			units = base10_units;
			units_len = base10_units_len;
		}

		if (((size_t)c >= units_len) || units[(uint8_t)c] == 0) {
			fr_strerror_printf("Unknown unit '%c'", c);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}

		if (!fr_multiply(&size, size, units[(uint8_t)c])) {
		overflow:
			fr_strerror_printf("Value must be less than %zu", (size_t)SIZE_MAX);
			fr_sbuff_set_to_start(&our_in);
			FR_SBUFF_ERROR_RETURN(&our_in);
		}
	}
	}

	if (size > SIZE_MAX) {
		fr_strerror_printf("Value %" PRIu64 " is greater than the maximum "
				   "file/memory size of this system (%zu)", size, (size_t)SIZE_MAX);

		goto overflow;
	}

done:
	*out = (size_t)size;

	FR_SBUFF_SET_RETURN(in, &our_in);
}

typedef struct {
	char const *suffix;
	uint64_t mul;
} fr_size_unit_t;

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
	fr_sbuff_t		our_out = FR_SBUFF(out);

	static fr_size_unit_t const	base2_units[] = {
					{ "B",		(uint64_t)1 },
					{ "KiB",	(uint64_t)1024 },
					{ "MiB",	(uint64_t)1024 * 1024 },
					{ "GiB",	(uint64_t)1024 * 1024 * 1024},
					{ "TiB",	(uint64_t)1024 * 1024 * 1024 * 1024},
					{ "PiB",	(uint64_t)1024 * 1024 * 1024 * 1024 * 1024},
					{ "EiB",	(uint64_t)1024 * 1024 * 1024 * 1024 * 1024 * 1024},
				};
	static fr_size_unit_t const	base10_units[] = {
					{ "B",		(uint64_t)1 },
					{ "KB",		(uint64_t)1000 },
					{ "MB",		(uint64_t)1000 * 1000 },
					{ "GB",		(uint64_t)1000 * 1000 * 1000},
					{ "TB",		(uint64_t)1000 * 1000 * 1000 * 1000},
					{ "PB",		(uint64_t)1000 * 1000 * 1000 * 1000 * 1000},
					{ "EB",		(uint64_t)1000 * 1000 * 1000 * 1000 * 1000 * 1000},
				};
	fr_size_unit_t const *unit = &base10_units[0];

	uint8_t pos2 = fr_low_bit_pos(in);
	uint8_t pos10;
	size_t tmp;

	/*
	 *	Fast path - Won't be divisible by a power of 1000 or a power of 1024
	 */
	if (pos2 < 3) goto done;
	pos2--;

	/*
	 *	Get a count of trailing decimal zeroes.
	 */
	for (tmp = in, pos10 = 0; tmp && ((tmp % 1000) == 0); pos10++) tmp /= 1000;

	if (pos10 > 0) unit = &base10_units[pos10];
	else if (pos2 >= 10) unit = &base2_units[pos2 / 10];

done:
	return fr_sbuff_in_sprintf(&our_out, "%zu%s", in / unit->mul, unit->suffix);
}
