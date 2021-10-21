#pragma once
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

/**
 * $Id$
 * @file lib/sim/common.h
 * @brief Common code used by multiple SIM algorithms
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Arran Cudbard-Bell \<a.cudbardb@freeradius.org\>
 */

/** Copy a 48bit value from a 64bit integer into a uint8_t buff in big endian byte order
 *
 * There may be fast ways of doing this, but this is the *correct*
 * way, and does not make assumptions about how integers are laid
 * out in memory.
 *
 * @param[out] out	6 byte butter to store value.
 * @param[in] i		integer value.
 * @return pointer to out.
 */
static inline uint8_t *uint48_to_buff(uint8_t out[static 6], uint64_t i)
{
	out[0] = (i & 0xff0000000000) >> 40;
	out[1] = (i & 0x00ff00000000) >> 32;
	out[2] = (i & 0x0000ff000000) >> 24;
	out[3] = (i & 0x000000ff0000) >> 16;
	out[4] = (i & 0x00000000ff00) >> 8;
	out[5] = (i & 0x0000000000ff);

	return out;
}

/** Convert a 48bit big endian value into a unsigned 64bit integer
 *
 */
static inline uint64_t uint48_from_buff(uint8_t const in[6])
{
	uint64_t i = 0;

	i |= ((uint64_t)in[0]) << 40;
	i |= ((uint64_t)in[1]) << 32;
	i |= ((uint32_t)in[2]) << 24;
	i |= ((uint32_t)in[3]) << 16;
	i |= ((uint16_t)in[4]) << 8;
	i |= in[5];

	return i;
}
