#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Structures and functions for converting integers to/from network byte order
 *
 * @file src/lib/util/nbo.h
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2022 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(nbo_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/misc.h>

/** Write out an unsigned 16bit integer in wire format (big endian)
 *
 * @param[out] out	Where to write the integer.
 * @param[in] num	to encode.
 */
static inline void fr_nbo_from_uint16(uint8_t out[static sizeof(uint16_t)], uint16_t num)
{
	out[0] = (num >> 8) & 0xff;
	out[1] = num & 0xff;
}

/** Write out an unsigned 24bit integer in wire format (big endian)
 *
 * @param[out] out	Where to write the integer.
 * @param[in] num	to encode.
 */
static inline void fr_nbo_from_uint24(uint8_t out[static 3], uint32_t num)
{
	out[0] = (num >> 16) & 0xff;
	out[1] = (num >> 8) & 0xff;
	out[2] = num & 0xff;
}

/** Write out an unsigned 32bit integer in wire format (big endian)
 *
 * @param[out] out	Where to write the integer.
 * @param[in] num	to encode.
 */
static inline void fr_nbo_from_uint32(uint8_t out[static sizeof(uint32_t)], uint32_t num)
{
	fr_nbo_from_uint16(out, (uint16_t) (num >> 16));
	fr_nbo_from_uint16(out + sizeof(uint16_t), (uint16_t) num);
}

/** Write out an unsigned 64bit integer in wire format (big endian)
 *
 * @param[out] out	Where to write the integer.
 * @param[in] num	to encode.
 */
static inline void fr_nbo_from_uint64(uint8_t out[static sizeof(uint64_t)], uint64_t num)
{
	fr_nbo_from_uint32(out, (uint32_t)(num >> 32));
	fr_nbo_from_uint32(out + sizeof(uint32_t), (uint32_t)num);
}

/** Write out an signed 16bit integer in wire format (big endian)
 *
 * @param[out] out	Where to write the integer.
 * @param[in] num	to encode.
 */
static inline void fr_nbo_from_int16(uint8_t out[static sizeof(int16_t)], int16_t num)
{
	out[0] = (num >> 8) & 0xff;
	out[1] = num & 0xff;
}

/** Write out an signed 32bit integer in wire format (big endian)
 *
 * @param[out] out	Where to write the integer.
 * @param[in] num	to encode.
 */
static inline void fr_nbo_from_int32(uint8_t out[static sizeof(int32_t)], int32_t num)
{
	fr_nbo_from_uint16(out, (int16_t) (num >> 16));
	fr_nbo_from_uint16(out + sizeof(int16_t), (int16_t) num);
}

/** Write out an signed 64bit integer in wire format (big endian)
 *
 * @param[out] out	Where to write the integer.
 * @param[in] num	to encode.
 */
static inline void fr_nbo_from_int64(uint8_t out[static sizeof(uint64_t)], uint64_t num)
{
	fr_nbo_from_uint32(out, (int32_t)(num >> 32));
	fr_nbo_from_uint32(out + sizeof(int32_t), (int32_t)num);
}

/** Write out an unsigned 64bit integer in wire format using the fewest bytes possible
 *
 * @param[out] out	Where to write big endian encoding of num.
 *			Should be at least 8 bytes.
 * @param[in] num	Number to encode.
 * @return the number of bytes written to out.
 */
static inline size_t fr_nbo_from_uint64v(uint8_t out[static sizeof(uint64_t)], uint64_t num)
{
	size_t ret;
	uint8_t swapped[sizeof(uint64_t)];

	ret = ROUND_UP_DIV((size_t)fr_high_bit_pos(num | 0x80), 8);

	fr_nbo_from_uint64(swapped, num);
	memcpy(out, (swapped + (sizeof(uint64_t) - ret)), ret);	/* aligned */

	return ret;
}

/** Read an unsigned 16bit integer from wire format (big endian)
 *
 * @param[in] data	To convert to a 16bit unsigned integer of native endianness.
 * @return a 16 bit unsigned integer of native endianness.
 */
static inline uint16_t fr_nbo_to_uint16(uint8_t const data[static sizeof(uint16_t)])
{
	return (((uint16_t)data[0]) << 8) | data[1];
}

/** Read an unsigned 24bit integer from wire format (big endian)
 *
 * @param[in] data	To convert to a 24bit unsigned integer of native endianness.
 * @return a 24 bit unsigned integer of native endianness.
 */
static inline uint32_t fr_nbo_to_uint24(uint8_t const data[static 3])
{
	return (((uint32_t)data[0]) << 16) | (((uint32_t)data[1]) << 8) | data[2];
}

/** Read an unsigned 32bit integer from wire format (big endian)
 *
 * @param[in] data	To convert to a 32bit unsigned integer of native endianness.
 * @return a 32 bit unsigned integer of native endianness.
 */
static inline uint32_t fr_nbo_to_uint32(uint8_t const data[static sizeof(uint32_t)])
{
	return ((uint32_t)fr_nbo_to_uint16(data) << 16) | fr_nbo_to_uint16(data + sizeof(uint16_t));
}

/** Read an unsigned 64bit integer from wire format (big endian)
 *
 * @param[in] data	To convert to a 64bit unsigned integer of native endianness.
 * @return a 64 bit unsigned integer of native endianness.
 */
static inline uint64_t fr_nbo_to_uint64(uint8_t const data[static sizeof(uint64_t)])
{
	return ((uint64_t)fr_nbo_to_uint32(data) << 32) | fr_nbo_to_uint32(data + sizeof(uint32_t));
}

/*
 * To get signed integers, simply cast.
 */
#define fr_nbo_to_int16(_x)	((int16_t) fr_nbo_to_uint16(_x))
#define fr_nbo_to_int32(_x)	((int32_t) fr_nbo_to_uint32(_x))
#define fr_nbo_to_int64(_x)	((int64_t) fr_nbo_to_uint64(_x))


/** Read an unsigned 64bit integer from wire format (big endian) with a variable length encoding
 *
 * @param[in] data	Buffer containing the number.
 * @param[in] data_len	Length of number.
 * @return a 64 bit unsigned integer of native endianness.
 */
static inline uint64_t fr_nbo_to_uint64v(uint8_t const *data, size_t data_len)
{
	uint64_t num = 0;
	uint64_t nbo;

	if (unlikely(data_len > sizeof(uint64_t))) return 0;

	/*
	 *	Copy at an offset into memory
	 *	allocated for the uin64_t
	 */
	memcpy(((uint8_t *)&num) + (sizeof(uint64_t) - data_len), data, data_len);	/* aligned */
	fr_nbo_from_uint64((uint8_t *)&nbo, num);

	return nbo;
}

static inline uint64_t fr_nbo_to_int64v(uint8_t const *data, size_t data_len)
{
	int64_t num = 0;
	uint64_t nbo;

	if (unlikely(data_len > sizeof(uint64_t))) return 0;

	/*
	 *	Copy at an offset into memory
	 *	allocated for the uin64_t
	 */
	memcpy(((uint8_t *)&num) + (sizeof(uint64_t) - data_len), data, data_len);	/* aligned */
	if (*data & 0x80) memset(((uint8_t *)&num) + data_len, 0xff, sizeof(num) - data_len);

	fr_nbo_from_uint64((uint8_t *)&nbo, num);

	return nbo;
}

/** Convert bits (as in prefix length) to bytes, rounding up.
 *
 * @param bits number of bits in the prefix
 * @return number of bytes taken to store the prefix
 */
static inline unsigned int fr_bytes_from_bits(unsigned int bits)
{
	return (bits + 7) >> 3;
}

#ifdef __cplusplus
}
#endif
