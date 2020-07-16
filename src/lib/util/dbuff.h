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
 * Because doing manual length checks is error prone and a waste of everyones time.
 *
 * @file src/lib/util/dbuff.h
 *
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(dbuff_h, "$Id$")

#  ifdef __cplusplus
extern "C" {
#  endif

#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/net.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <limits.h>
#include <errno.h>

typedef struct fr_dbuff_s fr_dbuff_t;
struct fr_dbuff_s {
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
	bool		is_const;		//!< The buffer this dbuff wraps is const.
	bool		adv_parent;		//!< Whether we advance the parent
						///< of this dbuff.
	fr_dbuff_t	*parent;
};

/** @name utility macros
 * @{
 */
/** Prevent an dbuff being advanced as it's passed into a parsing function
 *
 * @param[in] _dbuff	to make an ephemeral copy of.
 */
#define FR_DBUFF_NO_ADVANCE(_dbuff) (fr_dbuff_t) \
{ \
	.start	= (_dbuff)->p, \
	.end	= (_dbuff)->end, \
	.p	= (_dbuff)->p, \
	.is_const = (_dbuff)->is_const, \
	.adv_parent = false, \
	.parent = (_dbuff) \
}

#define _FR_DBUFF_RESERVE(_dbuff, _reserve, _adv_parent) \
(fr_dbuff_t){ \
	.start	= (_dbuff)->p, \
	.end	= ((_dbuff)->end - (_reserve)) >= ((_dbuff)->p) ? \
			(_dbuff)->end - (_reserve) : \
			(_dbuff)->p, \
	.p	= (_dbuff)->p, \
	.is_const = (_dbuff)->is_const, \
	.adv_parent = _adv_parent, \
	.parent = (_dbuff) \
}

/** Reserve N bytes in the dbuff when passing it to another function
 *
 @code{.c}
 my_child_encoder(&FR_DBUFF_RESERVE(dbuff, 5), vp);
 @endcode
 *
 * @note Do not use to re-initialise the contents of #_dbuff, i.e. to
 *	permanently shrink the exiting dbuff. The parent pointer will loop.
 *
 * @note Do not modify the "child" dbuff directly.  Use the functions
 *	 supplied as part of this API.
 *
 * @param[in] _dbuff	to reserve bytes in.
 * @param[in] _reserve	The number of bytes to reserve.
 */
#define FR_DBUFF_RESERVE(_dbuff, _reserve) _FR_DBUFF_RESERVE(_dbuff, _reserve, true)

/** Reserve N bytes in the dbuff when passing it to another function
 *
 @code{.c}
 fr_dbuff_t tlv = FR_DBUFF_RESERVE_NO_ADVANCE(dbuff, UINT8_MAX);

 if (my_child_encoder(&tlv, vp) < 0) return -1;

 return fr_dbuff_advance(dbuff, fr_dbuff_used(tlv));
 @endcode
 *
 * @note Do not use to re-initialise the contents of #_dbuff, i.e. to
 *	permanently shrink the exiting dbuff. The parent pointer will loop.
 *
 * @note Do not modify the "child" dbuff directly.  Use the functions
 *	 supplied as part of this API.
 *
 * @param[in] _dbuff	to reserve bytes in.
 * @param[in] _reserve	The number of bytes to reserve.
 */
#define FR_DBUFF_RESERVE_NO_ADVANCE(_dbuff, _reserve) _FR_DBUFF_RESERVE(_dbuff, _reserve, false)

/** Limit the maximum number of bytes available in the dbuff when passing it to another function
 *
 @code{.c}
 my_child_encoder(&FR_DBUFF_MAX(dbuff, 253), vp);
 @endcode
 *
 * @note Do not use to re-initialise the contents of #_dbuff, i.e. to
 *	permanently shrink the exiting dbuff. The parent pointer will loop.
 *
 * @note Do not modify the "child" dbuff directly.  Use the functions
 *	 supplied as part of this API.
 *
 * @param[in] _dbuff	to reserve bytes in.
 * @param[in] _max	The maximum number of bytes the caller is allowed to write to.
 */
#define FR_DBUFF_MAX(_dbuff,  _max) \
	_FR_DBUFF_RESERVE(_dbuff, (fr_dbuff_remaining(_dbuff) > (_max)) ? (fr_dbuff_remaining(_dbuff) - (_max)) : 0, true)

/** Limit the maximum number of bytes available in the dbuff when passing it to another function
 *
 @code{.c}
 fr_dbuff_t tlv = FR_DBUFF_MAX_NO_ADVANCE(dbuff, UINT8_MAX);

 if (my_child_encoder(&tlv, vp) < 0) return -1;

 return fr_dbuff_advance(dbuff, fr_dbuff_used(tlv))
 @endcode
 *
 * @note Do not use to re-initialise the contents of #_dbuff, i.e. to
 *	permanently shrink the exiting dbuff. The parent pointer will loop.
 *
 * @note Do not modify the "child" dbuff directly.  Use the functions
 *	 supplied as part of this API.
 *
 * @param[in] _dbuff	to reserve bytes in.
 * @param[in] _max	The maximum number of bytes the caller is allowed to write to.
 */
#define FR_DBUFF_MAX_NO_ADVANCE(_dbuff,  _max) \
	_FR_DBUFF_RESERVE(_dbuff, (fr_dbuff_remaining(_dbuff) > (_max)) ? (fr_dbuff_remaining(_dbuff) - (_max)) : 0, false)

/** Does the actual work of initialising a dbuff
 *
 */
static inline void _fr_dbuff_init(fr_dbuff_t *out, uint8_t const *start, uint8_t const *end, bool is_const)
{
	if (unlikely(end < start)) end = start;	/* Could be an assert? */

	out->p_i = out->start_i = start;
	out->end_i = end;
	out->is_const = is_const;
	out->parent = NULL;
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

/** Creates a compound literal to pass into functions which accept a dbuff
 *
 * @note This should only be used as a temporary measure when refactoring code.
 *
 * @note The return value of the function should be used to determine how much
 *	 data was written to the buffer.
 *
 * @param[in] _start		of the buffer.
 * @param[in] _len_or_end	Length of the buffer or the end pointer.
 */
#define FR_DBUFF_TMP(_start, _len_or_end) \
(fr_dbuff_t){ \
	.start_i	= _start, \
	.end_i		= _Generic((_len_or_end), \
				size_t		: (uint8_t const *)(_start) + (size_t)(_len_or_end), \
				uint8_t *	: (uint8_t const *)(_len_or_end), \
				uint8_t const *	: (uint8_t const *)(_len_or_end) \
			), \
	.p_i		= _start, \
	.is_const	= _Generic((_start), \
				uint8_t *	: false, \
				uint8_t const *	: true \
	       		) \
}
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
static inline size_t fr_dbuff_remaining(fr_dbuff_t const *dbuff)
{
	return dbuff->end - dbuff->p;
}

/** Return a negative offset indicating how much additional space we would have required for fulfil #_need
 *
 * @param[in] _dbuff	to check.
 * @param[in] _need	how much buffer space we need.
 */
#define FR_DBUFF_CHECK_REMAINING_RETURN(_dbuff, _need) \
do { \
	size_t _freespace = fr_dbuff_remaining(_dbuff); \
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

/** Generic wrapper macro to return if there's insufficient memory to satisfy the request on the dbuff
 *
 */
#define FR_DBUFF_RETURN(_func, ...) \
do { \
	ssize_t _slen = _func(__VA_ARGS__ ); \
	if (_slen < 0) return _slen; \
} while (0)

/** Advance position in dbuff by N bytes without sanity checks
 *
 * @note Do not call this function directly.
 */
static inline ssize_t CC_HINT(nonnull) _fr_dbuff_advance(fr_dbuff_t *dbuff, size_t inlen)
{
	dbuff->p += inlen;

	return dbuff->adv_parent && dbuff->parent ? _fr_dbuff_advance(dbuff->parent, inlen) : (ssize_t)inlen;
}

/** Advance position in dbuff by N bytes
 *
 * @param[in] dbuff	to advance.
 * @param[in] inlen	How much to advance dbuff by.
 * @return
 *	- 0	not advanced.
 *	- >0	the number of bytes the dbuff was advanced by.
 *	- <0	the number of bytes required to complete the copy.
 */
static inline ssize_t fr_dbuff_advance(fr_dbuff_t *dbuff, size_t inlen)
{
	size_t freespace = fr_dbuff_remaining(dbuff);

	if (inlen > freespace) return -(inlen - freespace);

	return _fr_dbuff_advance(dbuff, inlen);
}
#define FR_DBUFF_ADVANCE_RETURN(_dbuff, _inlen) FR_DBUFF_RETURN(fr_dbuff_advance, _dbuff, _inlen)

static inline ssize_t _fr_dbuff_memcpy_in(fr_dbuff_t *dbuff, uint8_t const *in, size_t inlen)
{
	size_t freespace = fr_dbuff_remaining(dbuff);

	fr_assert(!dbuff->is_const);

	if (inlen > freespace) return -(inlen - freespace);

	memcpy(dbuff->p, in, inlen);

	return _fr_dbuff_advance(dbuff, inlen);
}

static inline ssize_t _fr_dbuff_memcpy_in_dbuff(fr_dbuff_t *out, fr_dbuff_t const *in, size_t inlen)
{
	size_t outlen;
	fr_dbuff_t *in_m;

	if (inlen > fr_dbuff_remaining(in)) inlen = fr_dbuff_remaining(in);
	outlen = fr_dbuff_remaining(out);

	/*
	 *	If there's too many bytes, then
	 *	return how many additional bytes
	 *	we would have needed.
	 */
	if (inlen > outlen) return -(inlen - outlen);

	(void)_fr_dbuff_memcpy_in(out, in->p, inlen);

	memcpy(&in_m, &in, sizeof(in_m));	/* Stupid _Generic const issues */
	return _fr_dbuff_advance(in_m, inlen);
}

/** Copy inlen bytes into the dbuff
 *
 * If _in is a dbuff, it will be advanced by the number of bytes
 * written to _out.
 *
 * If _in is a dbuff and _inlen is greater than the
 * number of bytes available in _in, then the copy operation will
 * be truncated, so that we don't read off the end of the buffer.
 *
 * @param[in] _out	to copy data to.
 * @param[in] _in	Data to copy to dbuff.
 * @param[in] _inlen	How much data we need to copy.
 *			If _in is a char * or dbuff * and SIZE_MAX
 *			is passed, then _inlen will be substituted
 *			for the length of the buffer.
 * @return
 *	- 0	no data copied.
 *	- >0	the number of bytes copied to the dbuff.
 *	- <0	the number of bytes we would have needed
 *		to complete the copy operation.
 */
#define fr_dbuff_memcpy_in(_out, _in, _inlen) \
	_Generic((_in), \
		 uint8_t *		: _fr_dbuff_memcpy_in(_out, (uint8_t const *)(_in), _inlen), \
		 uint8_t const *	: _fr_dbuff_memcpy_in(_out, (uint8_t const *)(_in), _inlen), \
		 char *			: _fr_dbuff_memcpy_in(_out, (uint8_t const *)(_in), (size_t)(_inlen) == SIZE_MAX ? strlen((char const *)(_in)) : (_inlen)), \
		 char const *		: _fr_dbuff_memcpy_in(_out, (uint8_t const *)(_in), (size_t)(_inlen) == SIZE_MAX ? strlen((char const *)(_in)) : (_inlen)), \
		 fr_dbuff_t *		: _fr_dbuff_memcpy_in_dbuff(_out, (fr_dbuff_t const *)(_in), _inlen) \
	)

/** Copy exactly n bytes into dbuff
 *
 * @param[in] dbuff	to copy data to.
 * @param[in] in	Data to copy to dbuff.
 * @param[in] inlen	How much data we need to copy.
 * @return
 *	- 0	no data copied.
 *	- >0	the number of bytes copied to the dbuff.
 *	- <0	the number of bytes required to complete the copy.
 */
#define FR_DBUFF_MEMCPY_IN_RETURN(_dbuff, _in, _inlen) FR_DBUFF_RETURN(fr_dbuff_memcpy_in, _dbuff, _in, _inlen)

static inline size_t _fr_dbuff_memcpy_in_partial(fr_dbuff_t *dbuff, uint8_t const *in, size_t inlen)
{
	size_t freespace = fr_dbuff_remaining(dbuff);

	fr_assert(!dbuff->is_const);

	if (inlen > freespace) inlen = freespace;

	memcpy(dbuff->p, in, inlen);

	return _fr_dbuff_advance(dbuff, inlen);
}

static inline size_t _fr_dbuff_memcpy_in_dbuff_partial(fr_dbuff_t *out, fr_dbuff_t const *in, size_t inlen)
{
	size_t outlen;
	fr_dbuff_t *in_m;

	if (inlen > fr_dbuff_remaining(in)) inlen = fr_dbuff_remaining(in);
	outlen = fr_dbuff_remaining(out);

	if (inlen > outlen) inlen = outlen;

	(void)_fr_dbuff_memcpy_in(out, in->p, inlen);

	memcpy(&in_m, &in, sizeof(in_m));	/* Stupid _Generic const issues */
	return _fr_dbuff_advance(in_m, inlen);
}

/** Copy at most inlen bytes into the dbuff
 *
 * Use this variant when writing data to a streaming buffer where
 * partial writes will be tracked.
 *
 * If _in is a dbuff, it will be advanced by the number of bytes
 * written to _out.
 *
 * If _in is a dbuff and _inlen is greater than the
 * number of bytes available in _in, then the copy operation will
 * be truncated, so that we don't read off the end of the buffer.
 *
 * @param[in] _out	to copy data to.
 * @param[in] _in	Data to copy to dbuff.
 * @param[in] _inlen	How much data we need to copy.
 *			If _in is a char * or dbuff * and SIZE_MAX
 *			is passed, then _inlen will be substituted
 *			for the length of the buffer.
 * @return
 *	- 0	no data copied.
 *	- >0	the number of bytes copied to the dbuff.
 */
#define fr_dbuff_memcpy_in_partial(_out, _in, _inlen) \
	_Generic((_in), \
		uint8_t *	: _fr_dbuff_memcpy_in_partial(_out, (uint8_t const *)_in, _inlen), \
		uint8_t const *	: _fr_dbuff_memcpy_in_partial(_out, (uint8_t const *)_in, _inlen), \
		char *		: _fr_dbuff_memcpy_in_partial(_out, (uint8_t const *)_in, _inlen == SIZE_MAX ? strlen((char const *)_in) : _inlen), \
		char const *	: _fr_dbuff_memcpy_in_partial(_out, (uint8_t const *)_in, _inlen == SIZE_MAX ? strlen((char const *)_in) : _inlen), \
		fr_dbuff_t *	: _fr_dbuff_memcpy_in_dbuff_partial(_out, (fr_dbuff_t const *)_in, _inlen) \
	)

/** Copy a partial byte sequence into a dbuff
 *
 * @copybrief fr_dbuff_memcpy_in_partial
 *
 * @param[in] _dbuff	to copy byte sequence into.
 * @param[in] ...	bytes to copy.
 */
#define fr_dbuff_bytes_in_partial(_dbuff, ...) \
	fr_dbuff_memcpy_in_partial(_dbuff, ((uint8_t []){ __VA_ARGS__ }), sizeof((uint8_t []){ __VA_ARGS__ }))

/** Copy a byte sequence into a dbuff
 *
 * @copybrief fr_dbuff_memcpy_in
 *
 * @param[in] _dbuff	to copy byte sequence into.
 * @param[in] ...	bytes to copy.
 */
#define fr_dbuff_bytes_in(_dbuff, ...) \
	fr_dbuff_memcpy_in(_dbuff, ((uint8_t []){ __VA_ARGS__ }), sizeof((uint8_t []){ __VA_ARGS__ }))
#define FR_DBUFF_BYTES_IN_RETURN(_dbuff, ...) \
	FR_DBUFF_MEMCPY_IN_RETURN(_dbuff, ((uint8_t []){ __VA_ARGS__ }), sizeof((uint8_t []){ __VA_ARGS__ }))

/** Set n bytes of a buffer to the provided value
 *
 * @param[in] dbuff	to copy data to.
 * @param[in] c		Value to set.
 * @param[in] inlen	How much data we need to copy.
 * @return
 *	- 0	no data set.
 *	- >0	the number of bytes set in the dbuff.
 *	- <0	the number of bytes required.
 */
static inline ssize_t fr_dbuff_memset(fr_dbuff_t *dbuff, uint8_t c, size_t inlen)
{
	size_t freespace = fr_dbuff_remaining(dbuff);

	fr_assert(!dbuff->is_const);

	if (inlen > freespace) return -(inlen - freespace);

	memset(dbuff->p, c, inlen);

	return _fr_dbuff_advance(dbuff, inlen);
}
#define FR_DBUFF_MEMSET_RETURN(_dbuff, _c, _inlen) FR_DBUFF_RETURN(fr_dbuff_memset, _dbuff, _c, _inlen)

#define FR_DBUFF_NUM_IN_FUNC(_type) \
static inline ssize_t fr_dbuff_##_type##_in(fr_dbuff_t *dbuff, _type##_t num) \
{ \
	size_t	freespace = fr_dbuff_remaining(dbuff); \
	fr_assert(!dbuff->is_const); \
	if (sizeof(_type##_t) > freespace) return -(sizeof(_type##_t) - freespace); \
	fr_net_from_##_type(dbuff->p, num); \
	return _fr_dbuff_advance(dbuff, sizeof(_type##_t)); \
}
FR_DBUFF_NUM_IN_FUNC(uint16)
FR_DBUFF_NUM_IN_FUNC(uint32)
FR_DBUFF_NUM_IN_FUNC(uint64)
FR_DBUFF_NUM_IN_FUNC(int16)
FR_DBUFF_NUM_IN_FUNC(int32)
FR_DBUFF_NUM_IN_FUNC(int64)

/** Copy an unsigned 16-bit integer into a buffer in wire format (big endian)
 *
 * @param[in] dbuff	to copy data to
 * @param[in] num	value to copy
 * @return
 * 	- 0	no data set
 * 	- >0	the number of bytes added to the dbuff (2).
 * 	- <0	the number of bytes required
 */
#define FR_DBUFF_UINT16_IN_RETURN(_dbuff, _num) FR_DBUFF_RETURN(fr_dbuff_uint16_in, _dbuff, _num)

/** Copy an unsigned 32-bit integer into a buffer in wire format (big endian)
 *
 * @param[in] _dbuff	to copy data to
 * @param[in] _num	value to copy
 * @return
 * 	- 0	no data set
 * 	- >0	the number of bytes added to the dbuff (4).
 * 	- <0	the number of bytes required
 */
#define FR_DBUFF_UINT32_IN_RETURN(_dbuff, _num) FR_DBUFF_RETURN(fr_dbuff_uint32_in, _dbuff, _num)

/** Copy an unsigned 64-bit integer into a buffer in wire format (big endian)
 *
 * @param[in] dbuff	to copy data to
 * @param[in] num	value to copy
 * @return
 * 	- 0	no data set
 * 	- >0	the number of bytes added to the dbuff (8).
 * 	- <0	the number of bytes required
 */
#define FR_DBUFF_UINT64_IN_RETURN(_dbuff, _num) FR_DBUFF_RETURN(fr_dbuff_uint64_in, _dbuff, _num)

/** Copy a signed 16-bit integer into a buffer in wire format (big endian)
 *
 * @param[in] dbuff	to copy data to
 * @param[in] num	value to copy
 * @return
 * 	- 0	no data set
 * 	- >0	the number of bytes added to the dbuff (2).
 * 	- <0	the number of bytes required
 */
#define FR_DBUFF_INT16_IN_RETURN(_dbuff, _num) FR_DBUFF_RETURN(fr_dbuff_int16_in, _dbuff, _num)

/** Copy a signed 32-bit integer into a buffer in wire format (big endian)
 *
 * @param[in] dbuff	to copy data to
 * @param[in] num	value to copy
 * @return
 * 	- 0	no data set
 * 	- >0	the number of bytes added to the dbuff (4).
 * 	- <0	the number of bytes required
 */
#define FR_DBUFF_INT32_IN_RETURN(_dbuff, _num) FR_DBUFF_RETURN(fr_dbuff_int32_in,, _dbuff, _num)

/** Copy a signed 64-bit integer into a buffer in wire format (big endian)
 *
 * @param[in] dbuff	to copy data to
 * @param[in] num	value to copy
 * @return
 * 	- 0	no data set
 * 	- >0	the number of bytes added to the dbuff (8).
 * 	- <0	the number of bytes required
 */
#define FR_DBUFF_INT64_IN_RETURN(_dbuff, _num) FR_DBUFF_RETURN(fr_dbuff_int64_in, _dbuff, _num)

#define fr_dbuff_in(dbuff, value) \
	_Generic((value), \
		int16_t		: fr_dbuff_int16_in(dbuff, (int16_t)value), \
		int32_t		: fr_dbuff_int32_in(dbuff, (int32_t)value), \
		int64_t		: fr_dbuff_int64_in(dbuff, (int64_t)value), \
		uint16_t	: fr_dbuff_uint16_in(dbuff, (uint16_t)value), \
		uint32_t	: fr_dbuff_uint32_in(dbuff, (uint32_t)value), \
		uint64_t	: fr_dbuff_uint64_in(dbuff, (uint64_t)value) \
	)

static inline ssize_t fr_dbuff_uint64v_in(fr_dbuff_t *dbuff, uint64_t num)
{
	size_t	ret;

	ret = ROUND_UP_DIV((size_t)fr_high_bit_pos(num | 0x08), 8);
	num = ntohll(num);

	return fr_dbuff_memcpy_in(dbuff, ((uint8_t *)&num) + (sizeof(uint64_t) - ret), ret);
}
/** @} */

#ifdef __cplusplus
}
#endif
