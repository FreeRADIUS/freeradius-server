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

/**
 * $Id$
 *
 * @file io/pair.h
 * @brief Encoder/decoder library interface
 *
 * @copyright 2017-2020 The FreeRADIUS project
 */
#include <freeradius-devel/util/dcursor.h>
#include <freeradius-devel/util/value.h>

/** @name Encoder errors
 * @{
 */

/** Encoder skipped encoding an attribute
 */
#define PAIR_ENCODE_SKIPPED	SSIZE_MIN + 1

/** Skipped encoding attribute
 */
#define PAIR_ENCODE_FATAL_ERROR	SSIZE_MIN

/** @} */

/** @name Decode errors
 * @{
 */
/** Fatal error - Out of memory
 */
#define PAIR_DECODE_OOM		FR_VALUE_BOX_NET_OOM

/** Fatal error - Failed decoding the packet
 */
#define PAIR_DECODE_FATAL_ERROR	FR_VALUE_BOX_NET_ERROR

/** Return the correct adjusted slen for errors
 *
 * @param[in] slen	returned from the function we called.
 * @param[in] start	of the buffer.
 * @param[in] p		offset passed to function which returned the slen.
 */
static inline ssize_t fr_pair_decode_slen(ssize_t slen, uint8_t const *start, uint8_t const *p)
{
	if (slen > 0) return slen;

	switch (slen) {
	case PAIR_DECODE_OOM:
	case PAIR_DECODE_FATAL_ERROR:
		return slen;

	default:
		return slen - (p - start);
	}
}

/** Determine if the return code for an encoding function is a fatal error
 *
 */
static inline bool fr_pair_encode_is_error(ssize_t slen)
{
	if (slen == PAIR_ENCODE_FATAL_ERROR) return true;
	return false;
}

/** Checks if we have sufficient buffer space, and returns how much space we'd need as a negative integer
 *
 */
#define FR_PAIR_ENCODE_HAVE_SPACE(_p, _end, _num) if (((_p) + (_num)) > (_end)) return (_end) - ((_p) + (_num));

/** @} */
