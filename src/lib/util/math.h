#pragma once
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

/** Various miscellaneous utility functions
 *
 * @file src/lib/util/misc.h
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSIDH(math_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

/** Find the highest order high bit in an unsigned 64 bit integer
 *
 * @return 0-64 indicating the position of the highest bit,
 *	with 0 indicating no high bits, 1 indicating the 1st
 *	bit and 64 indicating the last bit.
 */
static inline uint8_t fr_high_bit_pos(uint64_t num)
{
	if (num == 0) return 0;	/* num being zero is undefined behaviour for __builtin_clzll */

#ifdef HAVE_BUILTIN_CLZLL
	return (64 - __builtin_clzll(num));
#else
	uint8_t ret = 1;
	while (num >>= 1) ret++;
	return ret;
#endif
}

/** Find the lowest order high bit in an unsigned 64 bit integer
 *
 * @return 0-64 indicating the position of the lowest bit,
 *	with 0 indicating no high bits, 1 indicating the 1st
 *	bit and 64 indicating the last bit.
 */
static inline uint8_t fr_low_bit_pos(uint64_t num)
{
	if (num == 0) return 0;

#ifdef HAVE_BUILTIN_CLZLL
	return __builtin_ctzll(num) + 1;
#else
	uint8_t ret = 1;

	do {
		if (num & 0x01) break;
		ret++;
	} while (num >>= 1);

	return ret;
#endif
}

/** Efficient calculation of log10 of a unsigned 64bit integer
 *
 * @param[in] num	to calculate log10 of.
 * @return log10 of the integer
 */
static inline uint8_t fr_log10(uint64_t num)
{
	static uint64_t const pow_of_10[] =
	{
		1ULL,
		10ULL,
		100ULL,
		1000ULL,
		10000ULL,
		100000ULL,
		1000000ULL,
		10000000ULL,
		100000000ULL,
		1000000000ULL,
		10000000000ULL,
		100000000000ULL,
		1000000000000ULL,
		10000000000000ULL,
		100000000000000ULL,
		1000000000000000ULL,
		10000000000000000ULL,
		100000000000000000ULL,
		1000000000000000000ULL,
		10000000000000000000ULL
	};
	uint64_t tmp;

	tmp = (fr_high_bit_pos(num) * 1233) >> 12;
	return tmp - (num < pow_of_10[tmp]);
}

/** Multiplies two integers together
 *
 * @param[in] _out	Where to store the result.
 * @param[in] _a	first argument to multiply.
 * @param[in] _b	second argument to multiply.
 * @return
 *      - false on overflow.
 *      - true if there was no overflow.
 */
#define fr_multiply(_out, _a, _b) !__builtin_mul_overflow(_a, _b, _out)

/** Adds two integers
 *
 * @param[in] _out	Where to store the result.
 * @param[in] _a	first argument to add.
 * @param[in] _b	second argument to add.
 * @return
 *      - false on overflow.
 *      - true if there was no overflow.
 */
#define fr_add(_out, _a, _b) !__builtin_add_overflow(_a, _b, _out)

/** Subtracts two integers
 *
 * @param[in] _out	Where to store the result.
 * @param[in] _a	first argument to subtract.
 * @param[in] _b	second argument to subtract.
 * @return
 *      - false on overflow.
 *      - true if there was no overflow.
 */
#define fr_sub(_out, _a, _b) !__builtin_sub_overflow(_a, _b, _out)

/** Round up - Only works if _mul is a power of 2 but avoids division
 */
#define ROUND_UP_POW2(_num, _mul)	(((_num) + ((_mul) - 1)) & ~((_mul) - 1))

/** Round up - Works in all cases, but is slower
 */
#define ROUND_UP(_num, _mul)		(((((_num) + ((_mul) - 1))) / (_mul)) * (_mul))

/** Get the ceiling value of integer division
 *
 */
#define ROUND_UP_DIV(_x, _y)		(1 + (((_x) - 1) / (_y)))

#ifdef __cplusplus
}
#endif
