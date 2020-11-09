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
typedef struct fr_dbuff_marker_s fr_dbuff_marker_t;

struct fr_dbuff_marker_s {
	union {
		uint8_t const *p_i;		//!< Immutable position pointer.
		uint8_t *p;			//!< Mutable position pointer.
	};
	fr_dbuff_marker_t	*next;		//!< Next m in the list.
	fr_dbuff_t		*parent;	//!< Owner of the marker.
};

typedef size_t(*fr_dbuff_extend_t)(fr_dbuff_t *dbuff, size_t req_extension);

struct fr_dbuff_s {
	union {
		uint8_t const *buff_i;			//!< Immutable buffer pointer.
		uint8_t *buff;				//!< Mutable buffer pointer.
	};

	union {
		uint8_t const *start_i;			//!< Immutable start pointer.
		uint8_t *start;				//!< Mutable start pointer.
	};

	union {
		uint8_t const *end_i;			//!< Immutable end pointer.
		uint8_t *end;				//!< Mutable end pointer.
	};

	union {
		uint8_t const *p_i;			//!< Immutable position pointer.
		uint8_t *p;				//!< Mutable position pointer.
	};

	uint8_t			is_const:1;	//!< The buffer this dbuff wraps is const.
	uint8_t			adv_parent:1;	//!< Whether we advance the parent
						///< of this dbuff.

	fr_dbuff_extend_t	extend;		//!< Function to re-populate or extend
						///< the buffer.
	void			*uctx;		//!< Extend uctx data.

	fr_dbuff_t		*parent;

	fr_dbuff_marker_t	*m;		//!< Pointers to update if the underlying
						///< buffer changes.
};

/** Talloc tbuff extension structure
 *
 * Holds the data necessary for creating dynamically
 * extensible buffers.
 */
typedef struct {
	TALLOC_CTX		*ctx;			//!< Context to alloc new buffers in.
	size_t			init;			//!< How much to allocate initially.
	size_t			max;			//!< Maximum size of the buffer.
} fr_dbuff_uctx_talloc_t;

void	fr_dbuff_update(fr_dbuff_t *dbuff, uint8_t *new_buff, size_t new_len);

size_t	fr_dbuff_extend_talloc(fr_dbuff_t *dbuff, size_t extension);

#define FR_DBUFF_FLAG_EXTENDABLE		0x01
#define FR_DBUFF_FLAG_EXTENDED			0x02

/** Whether the buffer is currently extendable and whether it was extended
 *
 */
typedef enum {
	FR_DBUFF_NOT_EXTENDABLE			= 0x00,
	FR_DBUFF_EXTENDABLE			= FR_DBUFF_FLAG_EXTENDABLE,
	FR_DBUFF_EXTENDABLE_EXTENDED		= FR_DBUFF_FLAG_EXTENDABLE | FR_DBUFF_FLAG_EXTENDED,
	FR_DBUFF_EXTENDED			= FR_DBUFF_FLAG_EXTENDED
} fr_dbuff_extend_status_t;

#define fr_dbuff_is_extendable(_status)		((_status) & FR_DBUFF_FLAG_EXTENDABLE)
#define fr_dbuff_was_extended(_status)		((_status) & FR_DBUFF_FLAG_EXTENDED)

/** @name utility macros
 * @{
 */
/** Prevent an dbuff being advanced as it's passed into a parsing function
 *
 * @param[in] _dbuff	to make an ephemeral copy of.
 */
#define FR_DBUFF_NO_ADVANCE(_dbuff) (fr_dbuff_t) \
{ \
	.buff		= (_dbuff)->buff, \
	.start		= (_dbuff)->p, \
	.end		= (_dbuff)->end, \
	.p		= (_dbuff)->p, \
	.is_const 	= (_dbuff)->is_const, \
	.adv_parent 	= false, \
	.extend		= (_dbuff)->extend, \
	.uctx		= (_dbuff)->uctx, \
	.parent 	= (_dbuff) \
}

#define _FR_DBUFF_RESERVE(_dbuff, _reserve, _adv_parent) \
(fr_dbuff_t){ \
	.buff		= (_dbuff)->buff, \
	.start		= (_dbuff)->p, \
	.end		= ((_dbuff)->end - (_reserve)) >= ((_dbuff)->p) ? \
				(_dbuff)->end - (_reserve) : \
				(_dbuff)->p, \
	.p		= (_dbuff)->p, \
	.is_const	= (_dbuff)->is_const, \
	.adv_parent	= _adv_parent, \
	.extend		= NULL, \
	.uctx		= NULL, \
	.parent		= (_dbuff) \
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

	*out = (fr_dbuff_t){
		.start_i = start,
		.p_i = start,
		.end_i = end,
		.is_const = is_const
	};
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
	       (uint8_t const *)(_start), \
	       _Generic((_len_or_end), \
			size_t		: (uint8_t const *)(_start) + (size_t)(_len_or_end), \
			long		: (uint8_t const *)(_start) + (size_t)(_len_or_end), \
			int		: (uint8_t const *)(_start) + (size_t)(_len_or_end), \
			unsigned int	: (uint8_t const *)(_start) + (size_t)(_len_or_end), \
			uint8_t *	: (uint8_t const *)(_len_or_end), \
			uint8_t const *	: (uint8_t const *)(_len_or_end), \
			char *		: (uint8_t const *)(_len_or_end), \
			char const *	: (uint8_t const *)(_len_or_end) \
	       ), \
	       _Generic((_start), \
			uint8_t *	: false, \
			uint8_t const *	: true, \
			char *		: false, \
			char const *	: true \
	       ))

/** Initialise a special dbuff which automatically extends as additional data is written
 *
 * @param[in] ctx	to allocate buffer in.
 * @param[out] dbuff	to initialise.
 * @param[out] tctx	to initialise.  Must have a lifetime >= to the dbuff.
 * @param[in] init	The length of the initial buffer.
 * @param[in] max	The maximum length of the buffer.
 * @return
 *	- The passed dbuff on success.
 *	- NULL on failure.
 */
static inline fr_dbuff_t *fr_dbuff_init_talloc(TALLOC_CTX *ctx,
					       fr_dbuff_t *dbuff, fr_dbuff_uctx_talloc_t *tctx,
					       size_t init, size_t max)
{
	uint8_t	*buff;

	*tctx = (fr_dbuff_uctx_talloc_t){
		.ctx = ctx,
		.init = init,
		.max = max
	};

	/*
	 *	Allocate the initial buffer
	 *
	 *	We always allocate a buffer so we don't
	 *	trigger ubsan errors by performing
	 *	arithmetic on NULL pointers.
	 *
	 *	Note that unlike dbuffs, we don't need space for a trailing '\0'.
	 */
	buff = talloc_zero_array(ctx, uint8_t, init);
	if (!buff) {
		fr_strerror_printf("Failed allocating buffer of %zu bytes", init);
		memset(dbuff, 0, sizeof(*dbuff));	/* clang scan */
		return NULL;
	}

	*dbuff = (fr_dbuff_t){
		.buff = buff,
		.start = buff,
		.p = buff,
		.end = buff + init,
		.extend = fr_dbuff_extend_talloc,
		.uctx = tctx
	};

	return dbuff;
}

/** Creates a compound literal to pass into functions which accept a dbuff
 *
 * @note The return value of the function should be used to determine how much
 *	 data was written to the buffer.
 *
 * @param[in] _start		of the buffer.
 * @param[in] _len_or_end	Length of the buffer or the end pointer.
 */
#define FR_DBUFF_TMP(_start, _len_or_end) \
(fr_dbuff_t){ \
	.start_i	= (uint8_t const *)(_start), \
	.end_i		= _Generic((_len_or_end), \
				size_t		: (uint8_t const *)(_start) + (size_t)(_len_or_end), \
				long		: (uint8_t const *)(_start) + (size_t)(_len_or_end), \
				int		: (uint8_t const *)(_start) + (size_t)(_len_or_end), \
				unsigned int	: (uint8_t const *)(_start) + (size_t)(_len_or_end), \
				uint8_t *	: (uint8_t const *)(_len_or_end), \
				uint8_t const *	: (uint8_t const *)(_len_or_end), \
				char *		: (uint8_t const *)(_len_or_end), \
				char const *	: (uint8_t const *)(_len_or_end) \
			), \
	.p_i		= _start, \
	.is_const	= _Generic((_start), \
				uint8_t *	: false, \
				uint8_t const *	: true, \
				char *		: false, \
				char const *	: true \
	       		) \
}
/** @} */

/** @name Length checks
 * @{
 */
/** Return the number of bytes remaining between the dbuff or marker and the end of the buffer
 *
 * @note Do not use this in functions that may be used for stream parsing
 *	 unless you're sure you know what you're doing.
 *	 The value return does not reflect the number of bytes that may
 *	 be potentially read from the stream, only the number of bytes
 *	 until the end of the current chunk.
 *
 * @param[in] _dbuff_or_marker	to return the number of bytes remaining for.
 * @return
 *	- >0 the number of bytes remaining before we reach the end of the buffer.
 *	- -0 we're at the end of the buffer.
 */
#define fr_dbuff_remaining(_dbuff_or_marker) \
	((size_t)(fr_dbuff_end(_dbuff_or_marker) < fr_dbuff_current(_dbuff_or_marker) ? \
		0 : (fr_dbuff_end(_dbuff_or_marker) - fr_dbuff_current(_dbuff_or_marker))))

/** Check if _len bytes are available in the dbuff, and if not return the number of bytes we'd need
 *
 */
#define FR_DBUFF_CHECK_REMAINING_RETURN(_dbuff, _len) \
	if ((_len) > fr_dbuff_remaining(_dbuff)) return -((_len) - fr_dbuff_remaining(_dbuff))

/** Internal function - do not call directly
 */
static inline size_t _fr_dbuff_extend_lowat(fr_dbuff_extend_status_t *status, fr_dbuff_t *in,
					    size_t remaining, size_t lowat)
{
	size_t extended;

	if (status && !fr_dbuff_is_extendable(*status)) {
	not_extendable:
		if (status) *status = FR_DBUFF_NOT_EXTENDABLE;
		return remaining;
	}

	if (remaining >= lowat) {
		if (status) *status = FR_DBUFF_EXTENDABLE;
		return remaining;
	}

	if (!in->extend || !(extended = in->extend(in, lowat - remaining))) goto not_extendable;

	if (status) *status = FR_DBUFF_EXTENDABLE_EXTENDED;

	return remaining + extended;
}

/** Extend a buffer if we're below a specified low water mark
 *
 * @param[out] status		Should be initialised to FR_SBUFF_EXTENDABLE
 *				for the first call to this function if used
 *				as a loop condition.
 *				Will be filled with the result of the previous
 *				call, and can be used to determine if the buffer
 *				was extended.
 * @param[in] _dbuff_or_marker	to extend.
 * @param[in] lowat		If bytes remaining are below the amount, extend.
 * @return
 *	- 0 if there are no bytes left in the buffer and we couldn't extend.
 *	- >0 the number of bytes in the buffer after extending.
 */
#define fr_dbuff_extend_lowat(_status, _dbuff_or_marker, _lowat) \
	_fr_dbuff_extend_lowat(_status, \
			       fr_dbuff_ptr(_dbuff_or_marker), \
			       fr_dbuff_remaining(_dbuff_or_marker), _lowat)

/** Check if _len bytes are available in the dbuff and extend the buffer if possible
 *
 * If we do not have _len bytes in the dbuff after extending, then return.
 *
 * @param[in] _dbuff_or_marker	to extend.
 * @param[in] _len		The minimum amount the dbuff should be extended by.
 * @return The number of bytes we would need to satisfy _len as a negative integer.
 */
#define FR_DBUFF_EXTEND_LOWAT_OR_RETURN(_dbuff_or_marker, _len) \
do { \
	size_t _remaining = fr_dbuff_extend_lowat(NULL, _dbuff_or_marker, _len); \
	if (_remaining < _len) return -(_len - _remaining); \
} while (0)

/** Check if _len bytes are available in the dbuff and extend the buffer if possible
 *
 * If we do not have _len bytes in the dbuff after extending, then return.
 *
 * @note This is intended for internal use within the dbuff API only.
 *
 * @param[in,out] _pos_p	the position pointer to use.
 * @param[in] _dbuff		to extend.
 * @param[in] _len		The minimum amount the dbuff should be extended by.
 * @return The number of bytes we would need to satisfy _len as a negative integer.
 */
#define _FR_DBUFF_EXTEND_LOWAT_POS_OR_RETURN(_pos_p, _dbuff_or_marker, _len) \
do { \
	size_t _remaining = _fr_dbuff_extend_lowat(NULL, \
						  fr_dbuff_ptr(_dbuff_or_marker), \
			       			  fr_dbuff_end(_dbuff_or_marker) - (*(_pos_p)), _len); \
	if (_remaining < _len) return -(_len - _remaining); \
} while (0)

/** Extend a buffer if no space remains
 *
 * @param[in] _dbuff	to extend.
 * @return
 *	- 0 if there are no bytes left in the buffer and we couldn't extend.
 *	- >0 the number of bytes in the buffer after extending.
 */
#define fr_dbuff_extend(_dbuff) fr_dbuff_extend_lowat(NULL, _dbuff, 1)

/** Return the number of bytes remaining between the start of the dbuff or marker and the current position
 *
 */
#define fr_dbuff_used(_dbuff_or_marker) \
	((size_t)(fr_dbuff_start(_dbuff_or_marker) > fr_dbuff_current(_dbuff_or_marker) ? \
		0 : (fr_dbuff_current(_dbuff_or_marker) - fr_dbuff_start(_dbuff_or_marker))))

/** The length of the underlying buffer
 *
 * @param[in] _dbuff_or_marker	to return the length of.
 * @return The length of the underlying buffer.
 */
#define fr_dbuff_len(_dbuff_or_marker) \
	((size_t)(fr_dbuff_end(_dbuff_or_marker) - fr_dbuff_start(_dbuff_or_marker)))
/** @} */

/** @name Accessors
 *
 * Caching the values of these pointers or the pointer values from the dbuff
 * directly is strongly discouraged as they can become invalidated during
 * stream parsing or when printing to an auto-expanding buffer.
 *
 * Using offsets of these pointers is also strongly discouraged as it
 * invalidates many of the protections dbuffs give.
 *
 * These functions should only be used to pass dbuff pointers into 3rd party
 * APIs.
 */

/** Return a pointer to the dbuff
 *
 * @param[in] _dbuff_or_marker	to return a pointer to.
 * @return A pointer to the dbuff.
 */
#define fr_dbuff_ptr(_dbuff_or_marker) \
	_Generic((_dbuff_or_marker), \
		 fr_dbuff_t *			: ((fr_dbuff_t *)(_dbuff_or_marker)), \
		 fr_dbuff_marker_t *		: ((fr_dbuff_marker_t *)(_dbuff_or_marker))->parent \
	)

/** Return a const pointer to the dbuff
 *
 * @param[in] _dbuff_or_marker	to return a pointer to.
 * @return A pointer to the dbuff.
 */
#define fr_dbuff_ptr_const(_dbuff_or_marker) \
	_Generic((_dbuff_or_marker), \
		 fr_dbuff_t *			: ((fr_dbuff_t const *)(_dbuff_or_marker)), \
		 fr_dbuff_t const *		: ((fr_dbuff_t const *)(_dbuff_or_marker)), \
		 fr_dbuff_marker_t *		: ((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent, \
		 fr_dbuff_marker_t const *	: ((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent \
	)

/** Return a pointer to the start of the underlying buffer in a dbuff or one of its markers
 *
 * @param[in] _dbuff_or_marker	to return the buffer for.
 * @return A pointer to the start of the buffer.
 */
#define fr_dbuff_buff(_dbuff_or_marker) \
	_Generic((_dbuff_or_marker), \
		 fr_dbuff_t *			: ((fr_dbuff_t const *)(_dbuff_or_marker))->buff, \
		 fr_dbuff_t const *		: ((fr_dbuff_t const *)(_dbuff_or_marker))->buff, \
		 fr_dbuff_marker_t *		: ((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent->buff, \
		 fr_dbuff_marker_t const *	: ((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent->buff \
	)

/** Return a pointer to the 'start' position of a dbuff or one of its markers
 *
 * The start position is not necessarily the start of the buffer, and is
 * advanced every time a dbuff is copied.
 *
 * @param[in] _dbuff_or_marker	to return the start position of.
 * @return A pointer to the start position of the buffer.
 */
#define fr_dbuff_start(_dbuff_or_marker) \
	(_Generic((_dbuff_or_marker), \
		  fr_dbuff_t *			: ((fr_dbuff_t const *)(_dbuff_or_marker))->start, \
		  fr_dbuff_t const *		: ((fr_dbuff_t const *)(_dbuff_or_marker))->start, \
		  fr_dbuff_marker_t *		: ((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent->start, \
		  fr_dbuff_marker_t const *	: ((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent->start \
	))

/** Return a pointer to the 'current' position of a dbuff or one of its markers
 *
 * @param[in] _dbuff_or_marker	to return the current position of.
 * @return A pointer to the current position of the buffer or marker.
 */
#define fr_dbuff_current(_dbuff_or_marker) \
	(_Generic((_dbuff_or_marker), \
		  fr_dbuff_t *			: ((fr_dbuff_t const *)(_dbuff_or_marker))->p, \
		  fr_dbuff_t const *		: ((fr_dbuff_t const *)(_dbuff_or_marker))->p, \
		  fr_dbuff_marker_t *		: ((fr_dbuff_marker_t const *)(_dbuff_or_marker))->p, \
		  fr_dbuff_marker_t const *	: ((fr_dbuff_marker_t const *)(_dbuff_or_marker))->p \
	))

/** Return a pointer to the position ptr for a dbuff or marker
 *
 * @note This is intended for internal use within the dbuff API only.
 *
 * @param[in] _dbuff_or_marker	to return a pointer to the position pointer for.
 */
#define _fr_dbuff_current_ptr(_dbuff_or_marker) \
	(_Generic((_dbuff_or_marker), \
		  fr_dbuff_t *			: &(((fr_dbuff_t *)(_dbuff_or_marker))->p), \
		  fr_dbuff_marker_t *		: &(((fr_dbuff_marker_t *)(_dbuff_or_marker))->p) \
	))

/** Return a pointer to the 'end' position of a dbuff or one of its markers
 *
 * @param[in] _dbuff_or_marker	to return the end position of.
 * @return A pointer to the end position of the buffer or marker.
 */
#define fr_dbuff_end(_dbuff_or_marker) \
	(_Generic((_dbuff_or_marker), \
		  fr_dbuff_t *			: ((fr_dbuff_t const *)(_dbuff_or_marker))->end, \
		  fr_dbuff_t const *		: ((fr_dbuff_t const *)(_dbuff_or_marker))->end, \
		  fr_dbuff_marker_t *		: ((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent->end, \
		  fr_dbuff_marker_t const *	: ((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent->end \
	))
/** @} */

/** @name Position modification (recursive)
 *
 * Change the current position of pointers in the dbuff and their children.
 * @{
 */

/** Update the position of p in a list of dbuffs
 *
 * @note Do not call directly.
 */
static inline void _fr_dbuff_set_recurse(fr_dbuff_t *dbuff, uint8_t const *p)
{
	dbuff->p_i = p;
	if (dbuff->adv_parent && dbuff->parent) _fr_dbuff_set_recurse(dbuff->parent, p);
}

/** Set a new position for 'p' in an dbuff or marker
 *
 * @param[in,out] pos_p		position pointer to modify.
 * @param[out] dbuff		dbuff to use for constraints checks.
 * @param[in] p			Position to set.
 * @return
 *	- 0	not advanced (p before dbuff start) or after dbuff end.
 *	- >0	the number of bytes the dbuff advanced by.
 *	- <0	the number of bytes the dbuff retreated by.
 */
static inline ssize_t _fr_dbuff_set(uint8_t **pos_p, fr_dbuff_t *dbuff, uint8_t const *p)
{
	uint8_t *c;

	if (unlikely(p > dbuff->end)) return -(p - dbuff->end);
	if (unlikely(p < dbuff->start)) return 0;

	c = *pos_p;
	if (dbuff->adv_parent && dbuff->parent) _fr_dbuff_set_recurse(dbuff->parent, p);
	memcpy(pos_p, &p, sizeof(*pos_p));

	return p - c;
}

/** Set the position in a dbuff or marker using another dbuff or marker, a char pointer, or a length
 *
 * @param[in] _dst	dbuff or marker to set the position for.
 * @param[in] _src	Variable to glean new position from.  Behaviour here
 *			depends on the type of the variable.
 *			- dbuff, the current position of the dbuff.
 *			- marker, the current position of the marker.
 *			- pointer, the position of the pointer.
 *			- size_t, _dst->start + _src.
 * @return
 *	- 0	not advanced.
 *	- >0	the number of bytes the dbuff was advanced by.
 *	- <0	the number of bytes required to complete the advancement
 */
#define fr_dbuff_set(_dst, _src) \
_fr_dbuff_set(\
	_fr_dbuff_current_ptr(_dst), fr_dbuff_ptr(_dst), \
	_Generic((_src), \
		fr_dbuff_t *			: fr_dbuff_current((fr_dbuff_t const *)(_src)), \
		fr_dbuff_marker_t *		: fr_dbuff_current((fr_dbuff_marker_t const *)(_src)), \
		uint8_t const *			: (uint8_t const *)(_src), \
		uint8_t *			: (uint8_t const *)(_src), \
		size_t				: (fr_dbuff_start(_dst) + (uintptr_t)(_src)), \
		long				: (fr_dbuff_start(_dst) + (uintptr_t)(_src)), \
		int				: (fr_dbuff_start(_dst) + (uintptr_t)(_src)) \
	) \
)
#define FR_DBUFF_SET_RETURN(_dst, _src) FR_DBUFF_RETURN(fr_dbuff_set, _dst, _src)

/** Advance position in dbuff or marker by N bytes
 *
 * @param[in] _dbuff_or_marker	to advance.
 * @param[in] n			How much to advance dbuff by.
 * @return
 *	- 0	not advanced.
 *	- >0	the number of bytes the dbuff or marker was advanced by.
 *	- <0	the number of bytes required to complete the advancement
 */
#define fr_dbuff_advance(_dbuff_or_marker, _n)  fr_dbuff_set(_dbuff_or_marker, (fr_dbuff_current(_dbuff_or_marker) + (_n)))
#define FR_DBUFF_ADVANCE_RETURN(_dbuff, _inlen) FR_DBUFF_RETURN(fr_dbuff_advance, _dbuff, _inlen)

/** Reset the current position of the dbuff or marker to the start of the buffer
 *
 */
#define fr_dbuff_set_to_start(_dbuff_or_marker) \
	fr_dbuff_set(_dbuff_or_marker, fr_dbuff_start(_dbuff_or_marker))

/** Reset the current position of the dbuff or marker to the end of the string
 *
 */
#define fr_dbuff_set_to_end(_dbuff_or_marker) \
	fr_dbuff_set(_dbuff_or_marker, fr_dbuff_end(_dbuff_or_marker))
/** @} */

/** @name Add a marker to an dbuff
 *
 * Markers are used to indicate an area of the code is working at a particular
 * point in a dbuff.
 *
 * If the dbuff is performing stream parsing, then markers are used to update
 * any pointers to the buffe as the data in the buffer is shifted to make
 * room for new data from the stream.
 *
 * If the dbuff is being dynamically expanded the markers are updated if the
 * buffer is re-allocated.
 * @{
 */
/** Adds a new pointer to the beginning of the list of pointers to update
 *
 * @param[out] m	to initialise.
 * @param[in] dbuff	to associate marker with.
 * @return The position the marker was set to.
 */
static inline uint8_t *fr_dbuff_marker(fr_dbuff_marker_t *m, fr_dbuff_t *dbuff)
{
	*m = (fr_dbuff_marker_t){
		.next = dbuff->m,	/* Link into the head */
		.p = dbuff->p,		/* Set the current position in the dbuff */
		.parent = dbuff		/* Record which dbuff this marker was associated with */
	};
	dbuff->m = m;

	return dbuff->p;
}

/** Trims the linked list backed to the specified pointer
 *
 * Pointers should be released in the inverse order to allocation.
 *
 * Alternatively the oldest pointer can be released, resulting in any newer pointer
 * also being removed from the list.
 *
 * @param[in] m		to release.
 */
static inline void fr_dbuff_marker_release(fr_dbuff_marker_t *m)
{
	m->parent->m = m->next;

#ifndef NDEBUG
	memset(m, 0, sizeof(*m));	/* Use after release */
#endif
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

static inline ssize_t _fr_dbuff_memcpy_in(uint8_t **pos_p, fr_dbuff_t *out,
					  uint8_t const *in, size_t inlen)
{
	fr_assert(!out->is_const);

	_FR_DBUFF_EXTEND_LOWAT_POS_OR_RETURN(pos_p, out, inlen);

	memcpy((*pos_p), in, inlen);					/* Copy to out */
	return _fr_dbuff_set(pos_p, out, (*pos_p) + inlen);		/* Advance out */
}

static inline ssize_t _fr_dbuff_memcpy_in_dbuff(uint8_t **pos_p, fr_dbuff_t *out,
					        uint8_t * const *in_p, fr_dbuff_t const *in, size_t inlen)
{
	fr_dbuff_t	*our_in;
	uint8_t		**our_in_p;

	memcpy(&our_in, &in, sizeof(our_in));		/* Stupid const issues caused by generics */
	memcpy(&our_in_p, &in_p, sizeof(our_in_p));	/* Stupid const issues caused by generics */

	/*
	 *	Ordering is important here, we need to attempt
	 *	the extension _before_ passing a dereferenced
	 *	in_p to the memcpy function.
	 */
	inlen = _fr_dbuff_extend_lowat(NULL, our_in, fr_dbuff_end(our_in) - (*our_in_p), inlen);
	return _fr_dbuff_memcpy_in(pos_p, out, *our_in_p, inlen);	/* Copy _in to _out */
}

/** Copy inlen bytes into the dbuff
 *
 * If _in is a dbuff and _inlen is greater than the
 * number of bytes available in _in, then the copy operation will
 * be truncated, so that we don't read off the end of the buffer.
 *
 * @note If _in is a dbuff _in will not be advanced.
 *	 If this is required fr_dbuff_move() should be used.
 *
 * @param[in] _out	Where to copy data to.  May be a dbuff or marker.
 * @param[in] _in	Data to copy to dbuff or marker.
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
		uint8_t *		: _fr_dbuff_memcpy_in(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (uint8_t const *)(_in), _inlen), \
		uint8_t const *		: _fr_dbuff_memcpy_in(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (uint8_t const *)(_in), _inlen), \
		char *			: _fr_dbuff_memcpy_in(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (uint8_t const *)(_in), (size_t)(_inlen) == SIZE_MAX ? strlen((char const *)(_in)) : (_inlen)), \
		char const *		: _fr_dbuff_memcpy_in(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (uint8_t const *)(_in), (size_t)(_inlen) == SIZE_MAX ? strlen((char const *)(_in)) : (_inlen)), \
		fr_dbuff_t *		: _fr_dbuff_memcpy_in_dbuff(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), &((fr_dbuff_t const *)(_in))->p, ((fr_dbuff_t const *)(_in)), _inlen), \
		fr_dbuff_marker_t *	: _fr_dbuff_memcpy_in_dbuff(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), &((fr_dbuff_marker_t const *)(_in))->p, ((fr_dbuff_marker_t const *)(_in))->parent, _inlen) \
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

/** Internal function - do not call directly
 */
static inline size_t _fr_dbuff_memcpy_in_partial(uint8_t **pos_p, fr_dbuff_t *out,
						 uint8_t const *in, size_t inlen)
{
	fr_assert(!out->is_const);

	inlen = _fr_dbuff_extend_lowat(NULL, out, fr_dbuff_end(out) - (*pos_p), inlen);

	memcpy((*pos_p), in, inlen);
	return _fr_dbuff_set(pos_p, out, (*pos_p) + inlen);
}

/** Internal function - do not call directly
 */
static inline size_t _fr_dbuff_memcpy_in_dbuff_partial(uint8_t **pos_p, fr_dbuff_t *out,
						       uint8_t * const *in_p, fr_dbuff_t const *in, size_t inlen)
{
	fr_dbuff_t	*our_in;
	uint8_t		**our_in_p;

	memcpy(&our_in, &in, sizeof(our_in));		/* Stupid const issues caused by generics */
	memcpy(&our_in_p, &in_p, sizeof(our_in_p));	/* Stupid const issues caused by generics */

	/*
	 *	Ordering is important here, we need to attempt
	 *	the extension _before_ passing a dereferenced
	 *	in_p to the memcpy function.
	 */
	inlen = _fr_dbuff_extend_lowat(NULL, our_in, fr_dbuff_end(our_in) - (*our_in_p), inlen);
	return _fr_dbuff_memcpy_in_partial(pos_p, out, (*our_in_p), inlen);
}

/** Copy at most inlen bytes into the dbuff
 *
 * Use this variant when writing data to a streaming buffer where
 * partial writes will be tracked.
 *
 * If _in is a dbuff and _inlen is greater than the
 * number of bytes available in _in, then the copy operation will
 * be truncated, so that we don't read off the end of the buffer.
 *
 * @note _in will not be advanced.  If this is required fr_dbuff_move() should be used.
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
		uint8_t *		: _fr_dbuff_memcpy_in_partial(_fr_dbuff_current_ptr(_out), _out, (uint8_t const *)_in, _inlen), \
		uint8_t const *		: _fr_dbuff_memcpy_in_partial(_fr_dbuff_current_ptr(_out), _out, (uint8_t const *)_in, _inlen), \
		char *			: _fr_dbuff_memcpy_in_partial(_fr_dbuff_current_ptr(_out), _out, (uint8_t const *)_in, _inlen == SIZE_MAX ? strlen((char const *)_in) : _inlen), \
		char const *		: _fr_dbuff_memcpy_in_partial(_fr_dbuff_current_ptr(_out), _out, (uint8_t const *)_in, _inlen == SIZE_MAX ? strlen((char const *)_in) : _inlen), \
		fr_dbuff_t *		: _fr_dbuff_memcpy_in_dbuff_partial(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), &((fr_dbuff_t const *)(_in))->p, ((fr_dbuff_t const *)(_in)), _inlen), \
		fr_dbuff_marker_t *	: _fr_dbuff_memcpy_in_dbuff_partial(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), &((fr_dbuff_marker_t const *)(_in))->p, ((fr_dbuff_marker_t const *)(_in))->parent, _inlen) \
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

static inline ssize_t _fr_dbuff_memset(uint8_t **pos_p, fr_dbuff_t *dbuff, uint8_t c, size_t inlen)
{
	fr_assert(!dbuff->is_const);

	_FR_DBUFF_EXTEND_LOWAT_POS_OR_RETURN(pos_p, dbuff, inlen);

	memset((*pos_p), c, inlen);

	return _fr_dbuff_set(pos_p, dbuff, (*pos_p) + inlen);
}

/** Set n bytes of a buffer to the provided value
 *
 * @param[in] _dbuff_or_marker	to copy data to.
 * @param[in] _c		Value to set.
 * @param[in] _inlen		How much data we need to copy.
 * @return
 *	- 0	no data set.
 *	- >0	the number of bytes set in the dbuff.
 *	- <0	the number of bytes required.
 */
#define fr_dbuff_memset(_dbuff_or_marker, _c, _inlen) \
	_fr_dbuff_memset(_fr_dbuff_current_ptr(_dbuff_or_marker), fr_dbuff_ptr(_dbuff_or_marker), _c, _inlen)

/** Set n bytes of a dbuff or marker to the provided value returning if there is insufficient space
 *
 * @param[in] _dbuff_or_marker	to copy data to.
 * @param[in] _c		Value to set.
 * @param[in] _inlen		How much data we need to copy.
 * @return
 *	- 0	no data set.
 *	- >0	the number of bytes set in the dbuff.
 *	- <0	the number of bytes required.
 */
#define FR_DBUFF_MEMSET_RETURN(_dbuff_or_marker, _c, _inlen) FR_DBUFF_RETURN(fr_dbuff_memset, _dbuff_or_marker, _c, _inlen)

#define FR_DBUFF_PARSE_INT_DEF(_type) \
static inline ssize_t _fr_dbuff_##_type##_in(uint8_t **pos_p, fr_dbuff_t *out, _type##_t num) \
{ \
	fr_assert(!out->is_const); \
	_FR_DBUFF_EXTEND_LOWAT_POS_OR_RETURN(pos_p, out, sizeof(_type##_t)); \
	fr_net_from_##_type((*pos_p), num); \
	return _fr_dbuff_set(pos_p, out, (*pos_p) + sizeof(_type##_t)); \
}
FR_DBUFF_PARSE_INT_DEF(uint16)
FR_DBUFF_PARSE_INT_DEF(uint32)
FR_DBUFF_PARSE_INT_DEF(uint64)
FR_DBUFF_PARSE_INT_DEF(int16)
FR_DBUFF_PARSE_INT_DEF(int32)
FR_DBUFF_PARSE_INT_DEF(int64)

#define fr_dbuff_in(_out, _value) \
	_Generic((_value), \
		int8_t		: fr_dbuff_bytes_in(_out, (int8_t)_value), \
		int16_t		: _fr_dbuff_int16_in(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (int16_t)_value), \
		int32_t		: _fr_dbuff_int32_in(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (int32_t)_value), \
		int64_t		: _fr_dbuff_int64_in(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (int64_t)_value), \
		uint8_t		: fr_dbuff_bytes_in(_out, (uint8_t)_value), \
		uint16_t	: _fr_dbuff_uint16_in(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (uint16_t)_value), \
		uint32_t	: _fr_dbuff_uint32_in(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (uint32_t)_value), \
		uint64_t	: _fr_dbuff_uint64_in(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (uint64_t)_value) \
	)
#define FR_DBUFF_IN_RETURN(_dbuff, _value) FR_DBUFF_RETURN(fr_dbuff_in, _dbuff, _value)

static inline ssize_t _fr_dbuff_uint64v_in(uint8_t **pos_p, fr_dbuff_t *dbuff, uint64_t num)
{
	size_t	ret;

	ret = ROUND_UP_DIV((size_t)fr_high_bit_pos(num | 0x08), 8);
	num = ntohll(num);

	return _fr_dbuff_memcpy_in(pos_p, dbuff, ((uint8_t *)&num) + (sizeof(uint64_t) - ret), ret);
}

/** Copy an integer value into a dbuff or marker using our internal variable length encoding
 *
 * @param[out] _dbuff_or_marker		to copy integer value to.
 * @param[in] _num			to copy.
 * @return
 *	- <0 the number of bytes we would have needed to encode the integer value.
 *	- >0 the number of bytes used to represent the integer value.
 */
#define fr_dbuff_uint64v_in(_dbuff_or_marker, _num) \
	_fr_dbuff_uint64v_in(_fr_dbuff_current_ptr(_dbuff_or_marker), fr_dbuff_ptr(_dbuff_or_marker), _num)

/** Internal function - do not call directly
 */
size_t _fr_dbuff_move_dbuff_to_dbuff(fr_dbuff_t *out, fr_dbuff_t *in, size_t len);

/** Internal function - do not call directly
 */
size_t _fr_dbuff_move_marker_to_dbuff(fr_dbuff_t *out, fr_dbuff_marker_t *in, size_t len);

/** Internal function - do not call directly
 */
size_t _fr_dbuff_move_marker_to_marker(fr_dbuff_marker_t *out, fr_dbuff_marker_t *in, size_t len);

/** Internal function - do not call directly
 */
size_t _fr_dbuff_move_dbuff_to_marker(fr_dbuff_marker_t *out, fr_dbuff_t *in, size_t len);

/** Copy in as many bytes as possible from one dbuff or marker to another
 *
 * @param[in] out	to copy into.
 * @param[in] in	to copy from.
 * @param[in] len	The maximum length to copy.
 * @return Number of bytes to copy.
 */
#define fr_dbuff_move(_out, _in, _len) \
	_Generic((_out), \
		fr_dbuff_t *		: \
			_Generic((_in), \
				fr_dbuff_t *		: _fr_dbuff_move_dbuff_to_dbuff((fr_dbuff_t *)_out, \
											(fr_dbuff_t *)_in, _len), \
				fr_dbuff_marker_t *	: _fr_dbuff_move_marker_to_dbuff((fr_dbuff_t *)_out, \
											(fr_dbuff_marker_t *)_in, _len) \
			), \
	       fr_dbuff_marker_t *	: \
			_Generic((_in), \
				fr_dbuff_t *		: _fr_dbuff_move_dbuff_to_marker((fr_dbuff_marker_t *)_out, \
											 (fr_dbuff_t *)_in, _len), \
				fr_dbuff_marker_t *	: _fr_dbuff_move_marker_to_marker((fr_dbuff_marker_t *)_out, \
											  (fr_dbuff_marker_t *)_in, _len) \
			) \
	)
/** @} */

/** @name copy data from dbuff
 * @{
 */

static inline ssize_t _fr_dbuff_memcpy_out(uint8_t *out, fr_dbuff_t *dbuff, size_t outlen)
{
	FR_DBUFF_EXTEND_LOWAT_OR_RETURN(dbuff, outlen);

	memcpy(out, dbuff->p, outlen);

	return _fr_dbuff_set(&dbuff->p, dbuff, dbuff->p + outlen);
}

static inline ssize_t _fr_dbuff_memcpy_out_dbuff(fr_dbuff_t *out, fr_dbuff_t *in, size_t outlen)
{
	if (outlen > fr_dbuff_remaining(in)) outlen = fr_dbuff_remaining(in);

	/*
	 *	If there's too many bytes, then
	 *	return how many additional bytes
	 *	we would have needed.
	 */
	FR_DBUFF_EXTEND_LOWAT_OR_RETURN(out, outlen);

	(void)_fr_dbuff_memcpy_out(out->p, in, outlen);

	return _fr_dbuff_set(&out->p, out, out->p + outlen);
}

#define FR_DBUFF_MEMCPY_OUT_RETURN(_out, _dbuff, _outlen) FR_DBUFF_RETURN(fr_dbuff_memcpy_out, _out, _dbuff, _outlen)

/** Copy outlen bytes from the dbuff
 *
 * If _out is a dbuff, it will be advanced by the number of bytes
 * copied from _in.
 *
 * If _out is a dbuff and _outlen is greater than the
 * number of bytes available in _out, then the copy operation will
 * be truncated, so that we don't write off the end of the buffer.
 *
 * @param[in] _out	to copy data to.
 * @param[in] _in	Data to copy to dbuff.
 * @param[in] _outlen	How much data we need to copy.
 *			If _out is a char * or dbuff * and SIZE_MAX
 *			is passed, then _inlen will be substituted
 *			for the length of the buffer.
 * @return
 *	- 0	no data copied.
 *	- >0	the number of bytes copied.
 *	- <0	the number of bytes we would have needed
 *		to complete the copy operation.
 */
#define fr_dbuff_memcpy_out(_out, _in, _outlen) \
	_Generic((_out), \
		 uint8_t *	: _fr_dbuff_memcpy_out((uint8_t *)(_out), _in, _outlen), \
		 int8_t *	: _fr_dbuff_memcpy_out((uint8_t *)(_out), _in, _outlen), \
		 fr_dbuff_t *	: _fr_dbuff_memcpy_out_dbuff((fr_dbuff_t *)_out, _in, _outlen) \
	)

#define FR_DBUFF_OUT_DEF(_type) \
static inline ssize_t fr_dbuff_##_type##_out(_type##_t *num, fr_dbuff_t *dbuff) \
{ \
	fr_assert(num); \
	FR_DBUFF_EXTEND_LOWAT_OR_RETURN(dbuff, sizeof(_type##_t)); \
	*num = fr_net_to_##_type(dbuff->p); \
	return fr_dbuff_advance(dbuff, sizeof(_type##_t)); \
}

FR_DBUFF_OUT_DEF(uint16)
FR_DBUFF_OUT_DEF(uint32)
FR_DBUFF_OUT_DEF(uint64)
FR_DBUFF_OUT_DEF(int16)
FR_DBUFF_OUT_DEF(int32)
FR_DBUFF_OUT_DEF(int64)

#define fr_dbuff_out(_value, _dbuff) \
	_Generic((_value), \
		uint16_t *	: fr_dbuff_uint16_out((uint16_t *)(_value), _dbuff), \
		uint32_t *	: fr_dbuff_uint32_out((uint32_t *)(_value), _dbuff), \
		uint64_t *	: fr_dbuff_uint64_out((uint64_t *)(_value), _dbuff), \
		int16_t *	: fr_dbuff_int16_out((int16_t *)(_value), _dbuff), \
		int32_t *	: fr_dbuff_int32_out((int32_t *)(_value), _dbuff), \
		int64_t *	: fr_dbuff_int64_out((int64_t *)(_value), _dbuff) \
	)
#define FR_DBUFF_OUT_RETURN(_value, _dbuff) FR_DBUFF_RETURN(fr_dbuff_out, _value, _dbuff)

/** @} */

#ifdef __cplusplus
}
#endif
