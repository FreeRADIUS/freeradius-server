#pragma once
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

/** A generic data buffer structure for encoding and decoding
 *
 * Because doing manual length checks is error prone and a waste of everyone's time.
 *
 * @file src/lib/util/dbuff.h
 *
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(dbuff_h, "$Id$")

#  ifdef __cplusplus
extern "C" {
#  endif

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <limits.h>
#include <errno.h>

typedef struct {
	union {
		uint8_t const *start_i;		//!< Immutable start pointer.
		uint8_t *start;			//!< Mutable start pointer.
	};

	union {
		uint8_t const *end_i;		//!< Immutable end pointer.
		uint8_t *end;			//!< Mutable end pointer.
	};

	union {
		uint8_t const *p_i;		//!< Immutable position pointer.
		uint8_t *p;			//!< Mutable position pointer.
	};
	bool	is_const;			//!< The buffer this dbuff wraps is const.
} fr_dbuff_t;

/** @name utility macros
 * @{
 */
/** Prevent an dbuff being advanced as it's passed into a parsing function
 *
 * @param[in] _dbuff	to make an ephemeral copy of.
 */
#define FR_DBUFF_NO_ADVANCE(_dbuff) (fr_dbuff_t[]){ *(_dbuff) }

/** Does the actual work of initialising a dbuff
 *
 */
static inline void _fr_dbuff_init(fr_dbuff_t *out, uint8_t const *start, uint8_t const *end, bool is_const)
{
	if (unlikely(end < start)) end = start;	/* Could be an assert? */

	out->p_i = out->start_i = start;
	out->end_i = end;
	out->is_const = is_const;
}

/** Initialise an dbuff for encoding or decoding
 *
 * @param[out] _out		Pointer to buffer to parse
 * @param[in] _start		Start of the buffer to parse.
 * @param[in] _len_or_end	Either an end pointer or the length
 *				of the buffer we're parsing.
 */
#define fr_dbuff_init(_out, _start, _len_or_end) \
_fr_dbuff_init(_out, \
	       _start, \
	       _Generic((_len_or_end), \
			size_t		: (uint8_t const *)(_start) + (size_t)(_len_or_end), \
			uint8_t *	: (uint8_t const *)(_len_or_end), \
			uint8_t const *	: (uint8_t const *)(_len_or_end) \
	       ), \
	       _Generic((_start), \
			uint8_t *	: false, \
			uint8_t const *	: true \
	       ))
/** @} */

/** @name dbuff position manipulation
 * @{
 */
/** Reset the current position of the dbuff to the start of the string
 *
 */
static inline uint8_t *fr_dbuff_start(fr_dbuff_t *dbuff)
{
	return dbuff->p = dbuff->start;
}

/** Reset the current position of the dbuff to the end of the string
 *
 */
static inline uint8_t *fr_dbuff_end(fr_dbuff_t *dbuff)
{
	return dbuff->p = dbuff->end;
}
/** @} */

/** @name Length checks
 * @{
 */
/** How many free bytes remain in the buffer
 *
 */
static inline size_t fr_dbuff_freespace(fr_dbuff_t const *dbuff)
{
	return dbuff->end - dbuff->p;
}

/** Return a negative offset indicating how much additional space we would have required for fulfil #_need
 *
 * @param[in] _dbuff	to check.
 * @param[in] _need	how much buffer space we need.
 */
#define FR_DBUFF_CHECK_FREESPACE(_dbuff, _need) \
do { \
	size_t _freespace = fr_dbuff_freespace(_dbuff); \
	if (_need > _freespace) return -(_need - _freespace); \
} while (0)

/** How many bytes we've used in the buffer
 *
 */
static inline size_t fr_dbuff_used(fr_dbuff_t const *dbuff)
{
	return dbuff->p - dbuff->start;
}

/** How many bytes in the buffer total
 *
 */
static inline size_t fr_dbuff_len(fr_dbuff_t const *dbuff)
{
	return dbuff->end - dbuff->start;
}
/** @} */

/** @name copy data to dbuff
 * @{
 */

/** Copy n bytes into dbuff
 *
 * @param[in] dbuff	to copy data to.
 * @param[in] in	Data to copy to dbuff.
 * @param[in] inlen	How much data we need to copy.
 * @return
 *	- 0	no data copied.
 *	- >0	the number of bytes copied to the dbuff.
 *	- <0	the number of bytes required to complete the copy.
 */
static inline ssize_t fr_dbuff_memcpy_in(fr_dbuff_t *dbuff, uint8_t const *in, size_t inlen)
{
	size_t freespace = fr_dbuff_freespace(dbuff);

	fr_assert(!dbuff->is_const);

	if (inlen > freespace) return -(inlen - freespace);

	memcpy(dbuff->p, in, inlen);
	dbuff->p += inlen;

	return inlen;
}

/** Copy n bytes into dbuff and return if there's insufficient buffer space
 *
 */
#define FR_DBUFF_MEMCPY_IN(_dbuff, _in, _inlen) \
do { \
	size_t _slen; \
	_slen = fr_dbuff_memcpy_in(_dbuff, _in, _inlen); \
	if (_slen < 0) return _slen; \
} while (0)

/** @} */

#ifdef __cplusplus
}
#endif
