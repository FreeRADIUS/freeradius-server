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

#include <errno.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/net.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/** A dbuff
 *
 * dbuffs wrap an underlying buffer, maintaining 'start', 'current', and 'end'
 * position pointers.
 *
 * dbuffs also contain information on if and how the underlying buffer can be
 * extended.
 *
 * For encoding extending means reallocing the underlying buffer so that there's
 * addition space to write data to.
 *
 * For stream decoding extending means shifting out existing data and refilling
 * the underlying buffer from a data source.
 *
 * dbuffs are intended to be organised into hierarchies, with one dbuff per stack
 * frame, initialised from a parent in a higher stack frame.
 *
 * Each time a dbuff is copied (using one of the provided FR_DBUFF_COPY_* macros),
 * the copy's 'start' position is updated to be the 'current' position of its
 * parent.  This ensures length macros report only spaced used/available in the
 * new dbuff and not its parent.
 * Other copy macros may move the 'end' position, to artificially limit the
 * amount of data available.
 */
typedef struct fr_dbuff_s fr_dbuff_t;

/** A position marker associated with a dbuff
 *
 * Markers are used whenever the caller needs to access part of the underlying
 * buffer other than the 'start', 'current' or 'end' positions described by
 * a #fr_dbuff_t.
 *
 * Markers are needed because if a #fr_dbuff_t is extended, pointers into the
 * underlying buffer may be invalidated by a realloc or memmove.
 *
 * Markers are intended to be allocated on the stack and associated with a
 * stack-frame-local `fr_dbuff_t`.  Using a stack-frame-local dbuff ensures
 * markers are automatically released when the stack frame is popped so that
 * markers are not leaked.
 */
typedef struct fr_dbuff_marker_s fr_dbuff_marker_t;

/** dbuff extension callback
 *
 * This callback is used to extend the underlying buffer.
 *
 * - Where the buffer is being used to aggregate data, this callback will
 * usually call realloc to extend the buffer.
 *
 * - Where the buffer is being used for stream decoding, this callback will
 * usually shift the existing data in the buffer to the left, and read in more
 * data from the stream.
 *
 * After performing an operation on the underlying buffer, this callback should
 * call #fr_dbuff_update to fix position pointers in the current dbuff and its
 * parents and markers.
 *
 * Generally the caller will request the minimum amount the buffer should be
 * extended by.  This callback may choose to ignore the request and extend the
 * buffer by more than the requested amount.
 *
 * @param[in] dbuff		to extend.
 * @param[in] req_extension	How much the caller wants to extend the buffer
 *				by.
 * @return How much the buffer was extended by.
 * @see fr_dbuff_update
 */
typedef size_t(*fr_dbuff_extend_t)(fr_dbuff_t *dbuff, size_t req_extension);

/** A position marker associated with a dbuff
 * @private
 */
struct fr_dbuff_marker_s {
	/** @private
	 */
	union {
		uint8_t const *p_i;			//!< Immutable position pointer.
		uint8_t *p;				//!< Mutable position pointer.
	};
	fr_dbuff_marker_t	*next;		//!< Next marker in the list.
	fr_dbuff_t		*parent;	//!< Owner of the marker.
};

/** A dbuff
 * @private
 */
struct fr_dbuff_s {
	/** @private
	 */
	union {
		uint8_t const *buff_i;			//!< Immutable 'buffer' pointer.
		uint8_t *buff;				//!< Mutable 'buffer' pointer.
	};

	/** @private
	 */
	union {
		uint8_t const *start_i;			//!< Immutable 'start' pointer.
		uint8_t *start;				//!< Mutable 'start' pointer.
	};

	/** @private
	 */
	union {
		uint8_t const *end_i;			//!< Immutable 'end' pointer.
		uint8_t *end;				//!< Mutable 'end' pointer.
	};

	/** @private
	 */
	union {
		uint8_t const *p_i;			//!< Immutable 'current' pointer.
		uint8_t *p;				//!< Mutable 'current' pointer.
	};

	uint8_t			is_const:1;	//!< The buffer this dbuff wraps is const.
	uint8_t			adv_parent:1;	//!< Whether we advance the parent
						///< of this dbuff.

	size_t			shifted;	//!< How many bytes this sbuff has been
						///< shifted since its creation.

	fr_dbuff_extend_t	extend;		//!< Function to re-populate or extend
						///< the buffer.
	void			*uctx;		//!< Extend uctx data.

	fr_dbuff_t		*parent;	//!< The #fr_dbuff_t this #fr_dbuff_t was
						///< created from.
						///< This will usually be the #fr_dbuff_t
						///< passed into a function.

	fr_dbuff_marker_t	*m;		//!< Pointers to update if the underlying
						///< buffer changes.
};

/** Generic wrapper macro to return if there's insufficient memory to satisfy the request on the dbuff
 *
 */
#define FR_DBUFF_RETURN(_func, ...) \
do { \
	ssize_t _slen = _func(__VA_ARGS__ ); \
	if (_slen < 0) return _slen; \
} while (0)

/** @name Initialisers
 * @{
 */

/** Prevent an dbuff being advanced by operations on its child
 *
 * @private
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
	.shifted	= (_dbuff)->shifted, \
	.extend		= (_dbuff)->extend, \
	.uctx		= (_dbuff)->uctx, \
	.parent 	= (_dbuff) \
}

/** Let the dbuff be advanced by operations on its child
 *
 *
 * @param[in] _dbuff	to make an ephemeral copy of.
 */
#define FR_DBUFF_COPY(_dbuff) (fr_dbuff_t) \
{ \
	.buff		= (_dbuff)->buff, \
	.start		= (_dbuff)->p, \
	.end		= (_dbuff)->end, \
	.p		= (_dbuff)->p, \
	.is_const 	= (_dbuff)->is_const, \
	.adv_parent 	= true, \
	.shifted	= (_dbuff)->shifted, \
	.extend		= (_dbuff)->extend, \
	.uctx		= (_dbuff)->uctx, \
	.parent 	= (_dbuff) \
}

/** @cond */

/** Limit available bytes in the dbufft to _max when passing it to another function
 *
 * @private
 */
#define _FR_DBUFF_MAX(_dbuff, _max, _adv_parent) \
(fr_dbuff_t){ \
	.buff		= (_dbuff)->buff, \
	.start		= (_dbuff)->p, \
	.end		= (((((_dbuff)->end) - (_max) < (_dbuff)->p)) ? (_dbuff)->end : ((_dbuff)->p + (_max))), \
	.p		= (_dbuff)->p, \
	.is_const	= (_dbuff)->is_const, \
	.adv_parent	= _adv_parent, \
	.shifted	= (_dbuff)->shifted, \
	.extend		= NULL, \
	.uctx		= NULL, \
	.parent		= (_dbuff) \
}
/* @endcond */

/** Limit the maximum number of bytes available in the dbuff when passing it to another function
 *
 @code{.c}
 my_child_encoder(&FR_DBUFF_MAX(dbuff, 253), vp);
 @endcode
 *
 * @note Do not use to re-initialise the contents of _dbuff, i.e. to
 *	permanently shrink the exiting dbuff. The parent pointer will loop.
 *
 * @note Do not modify the "child" dbuff directly.  Use the functions
 *	 supplied as part of this API.
 *
 * @param[in] _dbuff	to reserve bytes in.
 * @param[in] _max	The maximum number of bytes the caller is allowed to write to.
 */
#define FR_DBUFF_MAX(_dbuff,  _max) _FR_DBUFF_MAX(_dbuff, _max, true)

/** Limit the maximum number of bytes available in the dbuff when passing it to another function
 *
 @code{.c}
 fr_dbuff_t tlv = FR_DBUFF_MAX_NO_ADVANCE(dbuff, UINT8_MAX);

 if (my_child_encoder(&tlv, vp) < 0) return -1;

 return fr_dbuff_advance(dbuff, fr_dbuff_used(tlv))
 @endcode
 *
 * @note Do not use to re-initialise the contents of _dbuff, i.e. to
 *	permanently shrink the exiting dbuff. The parent pointer will loop.
 *
 * @note Do not modify the "child" dbuff directly.  Use the functions
 *	 supplied as part of this API.
 *
 * @param[in] _dbuff	to reserve bytes in.
 * @param[in] _max	The maximum number of bytes the caller is allowed to write to.
 */
#define FR_DBUFF_MAX_NO_ADVANCE(_dbuff,  _max) _FR_DBUFF_MAX(_dbuff, _max, false)

/** Does the actual work of initialising a dbuff
 * @private
 */
static inline void _fr_dbuff_init(fr_dbuff_t *out, uint8_t const *start, uint8_t const *end, bool is_const)
{
	if (unlikely(end < start)) end = start;	/* Could be an assert? */

	*out = (fr_dbuff_t){
		.buff_i = start,
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
 *				of the buffer we're deconding.
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

size_t	_fr_dbuff_extend_talloc(fr_dbuff_t *dbuff, size_t extension);

/** Talloc extension structure use by #fr_dbuff_init_talloc
 * @private
 *
 * Holds the data necessary for creating dynamically
 * extensible buffers.
 */
typedef struct {
	TALLOC_CTX		*ctx;			//!< Context to alloc new buffers in.
	size_t			init;			//!< How much to allocate initially.
	size_t			max;			//!< Maximum size of the buffer.
} fr_dbuff_uctx_talloc_t;

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
	 *	We always allocate a buffer so we don't trigger ubsan
	 *	errors by performing arithmetic on NULL pointers.
	 *
	 *	Note that unlike sbuffs, we don't need space for a trailing '\0'.
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
		.extend = _fr_dbuff_extend_talloc,
		.uctx = tctx
	};

	return dbuff;
}

size_t	_fr_dbuff_extend_fd(fr_dbuff_t *dbuff, size_t extension);

/** File sbuff extension structure use by #fr_dbuff_init_fd
 * @private
 *
 * Holds the data necessary for creating dynamically
 * extensible file buffers.
 */
typedef struct {
	int			fd;			//!< fd of file we're reading from.
	uint8_t			*buff_end;		//!< The true end of the buffer.
	size_t			max;			//!< Maximum number of bytes to read.
} fr_dbuff_uctx_fd_t;


/** Initialise a special dbuff which automatically reads in more data as the buffer is exhausted
 *
 * @param[out] dbuff	to initialise.
 * @param[out] fctx	to initialise.  Must have a lifetime >= to the dbuff.
 * @param[in] buff	Temporary buffer to use for storing file contents.
 * @param[in] len	Length of the temporary buffer.
 * @param[in] fd	descriptor of an open file to read from.
 * @param[in] max	The maximum length of data to read from the file.
 * @return
 *	- The passed dbuff on success.
 *	- NULL on failure.
 */
static inline fr_dbuff_t *fr_dbuff_init_fd(fr_dbuff_t *dbuff, fr_dbuff_uctx_fd_t *fctx,
					     uint8_t *buff, size_t len, int fd, size_t max)
{
	*fctx = (fr_dbuff_uctx_fd_t){
		.fd = fd,
		.max = max,
		.buff_end = buff + len		//!< Store the real end
	};

	*dbuff = (fr_dbuff_t){
		.buff = buff,
		.start = buff,
		.p = buff,
		.end = buff,			//!< Starts with 0 bytes available
		.extend = _fr_dbuff_extend_fd,
		.uctx = fctx
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
	.buff_i		= (uint8_t const *)(_start), \
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

/** @name Extension requests
 *
 * These functions/macros may be used to request that the underlying buffer is
 * either extended to accomodate more data, or that data is shifted out of the
 * buffer, and that the buffer is refilled.
 *
 * @{
 */

/** Flag indicating a dbuff is extendable
 */
#define FR_DBUFF_FLAG_EXTENDABLE		0x01

/** Flag indicating that during the last extend call the dbuff was extended
 */
#define FR_DBUFF_FLAG_EXTENDED			0x02

/** Whether the buffer is currently extendable and whether it was extended
 */
typedef enum {
	/** dbuff cannot be extended
	 */
	FR_DBUFF_NOT_EXTENDABLE			= 0x00,

	/** dbuff can be extended
	 */
	FR_DBUFF_EXTENDABLE			= FR_DBUFF_FLAG_EXTENDABLE,

	/** dbuff was extended in the last extend call and may be extended again
	 */
	FR_DBUFF_EXTENDABLE_EXTENDED		= FR_DBUFF_FLAG_EXTENDABLE | FR_DBUFF_FLAG_EXTENDED,

	/** dbuff was extended in the last extend call but cannot be extended again
	 */
	FR_DBUFF_EXTENDED			= FR_DBUFF_FLAG_EXTENDED
} fr_dbuff_extend_status_t;

/** Check if a dbuff can be extended again
 */
#define fr_dbuff_is_extendable(_status)		((_status) & FR_DBUFF_FLAG_EXTENDABLE)

/** Check if the dbuff was extended during the last extend call
 */
#define fr_dbuff_was_extended(_status)		((_status) & FR_DBUFF_FLAG_EXTENDED)

/** Internal function - do not call directly
 * @private
 */
static inline size_t _fr_dbuff_extend_lowat(fr_dbuff_extend_status_t *status, fr_dbuff_t *in,
					    size_t remaining, size_t lowat)
{
	size_t extended = 0;

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

/** Extend if we're below _lowat
 *
 * @param[out] _status		May be NULL.  If fr_dbuff_extend_lowat is used
 *				in a copy loop, the caller should pass a pointer
 *      			to a #fr_dbuff_extend_status_t.  The initial
 *				value of the #fr_dbuff_extend_status_t variable
 *      			should be #FR_DBUFF_EXTENDABLE, and will be updated
 *				to indicate whether the dbuff is extensible,
 *				whether it was extended, and whether it may be
 *				extended again.  This information
 *				is used the loop condition to prevent spurious
 *				extension calls.
 * @param[in] _dbuff_or_marker	to extend.
 * @param[in] _lowat		If bytes remaining are below the amount, extend.
 * @return
 *	- 0 if there are no bytes left in the buffer and we couldn't extend.
 *	- >0 the number of bytes in the buffer after extending.
 */
#define fr_dbuff_extend_lowat(_status, _dbuff_or_marker, _lowat) \
	_fr_dbuff_extend_lowat(_status, \
			       fr_dbuff_ptr(_dbuff_or_marker), \
			       fr_dbuff_remaining(_dbuff_or_marker), _lowat)

/** Extend if we're below _lowat and return if we can't extend above _lowat
 *
 * @param[in] _dbuff_or_marker	to extend.
 * @param[in] _lowat		If bytes remaining are below the amount, extend.
 * @return
 *	- 0 if there are no bytes left in the buffer and we couldn't extend.
 *	- >0 the number of bytes in the buffer after extending.
 */
#define FR_DBUFF_EXTEND_LOWAT_OR_RETURN(_dbuff_or_marker, _lowat) \
do { \
	size_t _remaining = fr_dbuff_extend_lowat(NULL, _dbuff_or_marker, _lowat); \
	if (_remaining < _lowat) return -(_lowat - _remaining); \
} while (0)

/** @cond */
/** Extend if we're below _lowat and return if we can't extend above _lowat
 *
 * @private
 *
 * @param[in,out] _pos_p	the position pointer to use.
 * @param[in] _dbuff_or_marker	to extend.
 * @param[in] _lowat		The minimum amount the dbuff should be extended by.
 * @return The number of bytes we would need to satisfy _lowat as a negative integer.
 */
#define _FR_DBUFF_EXTEND_LOWAT_POS_OR_RETURN(_pos_p, _dbuff_or_marker, _lowat) \
do { \
	size_t _remaining = _fr_dbuff_extend_lowat(NULL, \
						   fr_dbuff_ptr(_dbuff_or_marker), \
			       			   fr_dbuff_end(_dbuff_or_marker) - (*(_pos_p)), _lowat); \
	if (_remaining < _lowat) return -(_lowat - _remaining); \
} while (0)
/** @endcond */

/** Extend if no space remains
 *
 * @param[in] _dbuff	to extend.
 * @return
 *	- 0 if there are no bytes left in the buffer and we couldn't extend.
 *	- >0 the number of bytes in the buffer after extending.
 */
#define fr_dbuff_extend(_dbuff) fr_dbuff_extend_lowat(NULL, _dbuff, 1)
/** @} */

/** @name Extension callback helpers
 *
 * These public functions are intended to be called by extension callbacks
 * to fixup dbuffs after the underlying buffer or its contents has been altered.
 * @{
 */
void	fr_dbuff_update(fr_dbuff_t *dbuff, uint8_t *new_buff, size_t new_len);

size_t	fr_dbuff_shift(fr_dbuff_t *dbuff, size_t shift);
/** @} */

/** @name Length checks
 *
 * These macros return the amount of data used/remaining relative to the dbuff
 * or marker's 'start', 'current', and 'end' pointers.
 *
 * In the majority of cases these macros should not be used and the extension
 * request functions should be used instead.  The only exception to this is if
 * the caller is certain the #fr_dbuff_t is not extensible.
 *
 * @{
 */
/** Return the number of bytes remaining between the dbuff or marker and the end of the buffer
 *
 * @note Do not use this in functions that may be used for stream decoding
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

/** Check if _len bytes are available in the dbuff and if not return the number of bytes we'd need
 *
 * @note Do not use this in functions that may be used for stream decoding
 *	 unless you're sure you know what you're doing.
 *	 The value return does not reflect the number of bytes that may
 *	 be potentially read from the stream, only the number of bytes
 *	 until the end of the current chunk.
 *
 * @param[in] _dbuff_or_marker	to return the number of bytes remaining for.
 * @param[in] _len		Minimum remaining bytes.
 * @return
 *	- >0 the number of bytes remaining before we reach the end of the buffer.
 *	- -0 we're at the end of the buffer.
 */
#define FR_DBUFF_REMAINING_RETURN(_dbuff_or_marker, _len) \
	if ((_len) > fr_dbuff_remaining(_dbuff_or_marker)) return -((_len) - fr_dbuff_remaining(_dbuff_or_marker))

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

/** How many bytes the dbuff or marker is behind its parent
 *
 * @param[in] _dbuff_or_marker
 * @return
 *	- 0 the dbuff or marker is ahead of its parent.
 *	- >0 the number of bytes the marker is behind its parent.
 */
#define fr_dbuff_behind(_dbuff_or_marker) \
	(fr_dbuff_current(_dbuff_or_marker) > fr_dbuff_current((_dbuff_or_marker)->parent) ? \
		0 : fr_dbuff_current((_dbuff_or_marker)->parent) - fr_dbuff_current(_dbuff_or_marker))

/** How many bytes the dbuff or marker is ahead of its parent
 *
 * @return
 *	- 0 the dbuff or marker is behind its parent.
 *	- >0 the number of bytes the marker is ahead of its parent.
 */
#define fr_dbuff_ahead(_dbuff_or_marker) \
	(fr_dbuff_current((_dbuff_or_marker)->parent) > fr_dbuff_current(_dbuff_or_marker) ? \
		0 : fr_dbuff_current(_dbuff_or_marker) - fr_dbuff_current((_dbuff_or_marker)->parent))
/** @} */

/** @name Accessors
 *
 * Caching the pointers returned by the accessors is strongly discouraged.
 * Cached pointers can become invalidated if the #fr_dbuff_t is extended, as
 * the extensions callback may use realloc or memmove on the underlying buffer.
 *
 @code{.c}
 fr_dbuff_t dbuff;
 fr_dbuff_uctx_talloc_t tctx;
 uint8_t *p;

 fr_dbuff_init_talloc(NULL, &dbuff, &tctx, 512, SIZE_MAX);

 p = fr_dbuff_current(&dbuff);			// Cache the start pointer
 fr_dbuff_extend_lowat(&dbuff, 1024);		// Extension call triggers realloc

 printf("%s", p);				// Should print an empty string but may
 						// SEGV as p may now be invalid.
 @endcode
 *
 * If offsets of a #fr_dbuff_t need to be accessed, markers should be used.
 * If a dbuff is extended all markers associated with it will be updated so that the
 * content they point to remains constant.
 *
 @code{.c}
 fr_dbuff_t dbuff;
 fr_dbuff_uctx_talloc_t tctx;
 fr_dbuff_marker_t m;

 fr_dbuff_init_talloc(NULL, &dbuff, &tctx, 512, SIZE_MAX);
 fr_dbuff_marker(&m, &dbuff);

 fr_dbuff_extend_lowat(&dbuff, 1024);		// Extension call triggers realloc

 printf("%s", fr_dbuff_current(&m));		// Marker was updated when the dbuff
 						// was extended.  All is well.
 @endcode
 *
 * Using offsets of the pointers returned by accessor functions is also strongly
 * discouraged as it invalidates many of the protections dbuffs give.
 *
 @code{.c}
 uint8_t buff[2];
 fr_dbuff_t dbuff;

 fr_dbuff_init(&dbuff, buff, sizeof(buff));
 fr_dbuff_current(&dbuff)[2] = 0x00;		// Write to invalid memory
 @endcode
 *
 * @{
 */

/** Return a pointer to the dbuff
 *
 * @param[in] _dbuff_or_marker	to return a pointer to.
 * @return A pointer to the dbuff.
 */
#define fr_dbuff_ptr(_dbuff_or_marker) \
	_Generic((_dbuff_or_marker), \
		 fr_dbuff_t *			: ((fr_dbuff_t *)(_dbuff_or_marker)), \
		 fr_dbuff_marker_t *		: (((fr_dbuff_marker_t *)(_dbuff_or_marker))->parent) \
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
		 fr_dbuff_marker_t *		: (((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent), \
		 fr_dbuff_marker_t const *	: (((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent) \
	)

/** Return the underlying buffer in a dbuff or one of marker
 *
 * @param[in] _dbuff_or_marker	to return the buffer for.
 * @return A pointer to the start of the buffer.
 */
#define fr_dbuff_buff(_dbuff_or_marker) \
	_Generic((_dbuff_or_marker), \
		 fr_dbuff_t *			: (((fr_dbuff_t const *)(_dbuff_or_marker))->buff), \
		 fr_dbuff_t const *		: (((fr_dbuff_t const *)(_dbuff_or_marker))->buff), \
		 fr_dbuff_marker_t *		: (((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent->buff), \
		 fr_dbuff_marker_t const *	: (((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent->buff) \
	)

/** Return the 'start' position of a dbuff or marker
 *
 * The start position is not necessarily the start of the buffer, and is
 * advanced every time a dbuff is copied.
 *
 * @param[in] _dbuff_or_marker	to return the start position of.
 * @return A pointer to the start position of the buffer.
 */
#define fr_dbuff_start(_dbuff_or_marker) \
	(_Generic((_dbuff_or_marker), \
		  fr_dbuff_t *			: (((fr_dbuff_t const *)(_dbuff_or_marker))->start), \
		  fr_dbuff_t const *		: (((fr_dbuff_t const *)(_dbuff_or_marker))->start), \
		  fr_dbuff_marker_t *		: (((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent->start), \
		  fr_dbuff_marker_t const *	: (((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent->start) \
	))

/** Return the 'current' position of a dbuff or marker
 *
 * @param[in] _dbuff_or_marker	to return the current position of.
 * @return A pointer to the current position of the buffer or marker.
 */
#define fr_dbuff_current(_dbuff_or_marker) \
	(_Generic((_dbuff_or_marker), \
		  fr_dbuff_t *			: (((fr_dbuff_t const *)(_dbuff_or_marker))->p), \
		  fr_dbuff_t const *		: (((fr_dbuff_t const *)(_dbuff_or_marker))->p), \
		  fr_dbuff_marker_t *		: (((fr_dbuff_marker_t const *)(_dbuff_or_marker))->p), \
		  fr_dbuff_marker_t const *	: (((fr_dbuff_marker_t const *)(_dbuff_or_marker))->p) \
	))

/** @cond */
/** Return a pointer to the 'current' position in a dbuff or marker
 * @private
 *
 * @param[in] _dbuff_or_marker	to return a pointer to the position pointer for.
 * @return A pointer to the position pointer in the dbuff or marker.
 */
#define _fr_dbuff_current_ptr(_dbuff_or_marker) \
	(_Generic((_dbuff_or_marker), \
		  fr_dbuff_t *			: &(((fr_dbuff_t *)(_dbuff_or_marker))->p), \
		  fr_dbuff_marker_t *		: &(((fr_dbuff_marker_t *)(_dbuff_or_marker))->p) \
	))
/** @endcond */

/** Return the current 'end' position of a dbuff or marker
 *
 * @param[in] _dbuff_or_marker	to return the end position of.
 * @return A pointer to the end position of the buffer or marker.
 */
#define fr_dbuff_end(_dbuff_or_marker) \
	(_Generic((_dbuff_or_marker), \
		  fr_dbuff_t *			: (((fr_dbuff_t const *)(_dbuff_or_marker))->end), \
		  fr_dbuff_t const *		: (((fr_dbuff_t const *)(_dbuff_or_marker))->end), \
		  fr_dbuff_marker_t *		: (((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent->end), \
		  fr_dbuff_marker_t const *	: (((fr_dbuff_marker_t const *)(_dbuff_or_marker))->parent->end) \
	))
/** @} */

/** @name Position modification (recursive)
 *
 * Modify the 'current' position pointer of a dbuff or marker.
 * @{
 */

/** Set a new 'current' position in a dbuff or marker
 * @private
 */
static inline void _fr_dbuff_set_recurse(fr_dbuff_t *dbuff, uint8_t const *p)
{
	dbuff->p_i = p;
	if (dbuff->adv_parent && dbuff->parent) _fr_dbuff_set_recurse(dbuff->parent, p);
}

/** Set a new 'current' position in a dbuff or marker
 * @private
 *
 * @param[in,out] pos_p		position pointer to modify.
 * @param[out] dbuff		dbuff to use for constraints checks.
 * @param[in] p			Position to set.
 * @return
 *	- 0	not advanced (p before dbuff start) or after dbuff end.
 *	- >0	the number of bytes the dbuff advanced by.
 *	- <0	the number of bytes the dbuff retreated by.
 *
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

/** Set the 'current' position in a dbuff or marker using another dbuff or marker, a char pointer, or a length value
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

/** Set the 'current' position in a dbuff or marker returning if _src is out of range
 *
 * @copydetails fr_dbuff_set
 */
#define FR_DBUFF_SET_RETURN(_dst, _src) FR_DBUFF_RETURN(fr_dbuff_set, _dst, _src)

/** Advance 'current' position in dbuff or marker by _len bytes
 *
 * @param[in] _dbuff_or_marker	to advance.
 * @param[in] _len		How much to advance dbuff by.
 *				Must be a positive integer.
 * @return
 *	- 0	not advanced.
 *	- >0	the number of bytes the dbuff or marker was advanced by.
 *	- <0	the number of bytes required to complete the advancement
 */
#define fr_dbuff_advance(_dbuff_or_marker, _len)  \
	fr_dbuff_set(_dbuff_or_marker, \
		     (fr_dbuff_current(_dbuff_or_marker) + \
		     (_Generic((_len), \
			unsigned char : (size_t)(_len), \
			unsigned short : (size_t)(_len), \
			unsigned int : (size_t)(_len), \
			unsigned long : (size_t)(_len), \
			unsigned long long : (size_t)(_len), \
			int : (fr_cond_assert((int)(_len) >= 0) ? (size_t)(_len) : 0) \
		     ))))

/** Advance the 'current' position in dbuff or marker by _len bytes returning if _len is out of range
 *
 * @copydetails fr_dbuff_advance
 */
#define FR_DBUFF_ADVANCE_RETURN(_dbuff_or_marker, _len) FR_DBUFF_RETURN(fr_dbuff_advance, _dbuff_or_marker, _len)

/** Reset the 'current' position of the dbuff or marker to the 'start' of the buffer
 *
 */
#define fr_dbuff_set_to_start(_dbuff_or_marker) \
	fr_dbuff_set(_dbuff_or_marker, fr_dbuff_start(_dbuff_or_marker))

/** Reset the 'current' position of the dbuff or marker to the 'end' of the buffer
 *
 */
#define fr_dbuff_set_to_end(_dbuff_or_marker) \
	fr_dbuff_set(_dbuff_or_marker, fr_dbuff_end(_dbuff_or_marker))
/** @} */

/** @name Marker management
 *
 * Markers serve two purposes:
 *
 * - Markers allow the caller to track content in a dbuff as the dbuff is extended.
 *   If the caller referred to content using a pointer into the underlying buffer,
 *   that pointer may be invalidated if the buffer were extended.
 *
 * - Markers prevent content being shifted out of the buffer during an extension.
 *
 * Most operations that can be performed on an #fr_dbuff_t can also be performed
 * on a #fr_dbuff_marker_t.
 *
 * It is recommended that markers be created against a stack-frame-local dbuff so
 * that they are automatically released when the framed is popped.
 *
 * @see fr_dbuff_marker_t
 *
 * @{
 */

/** Initialises a new marker pointing to the 'current' position of the dbuff
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

/** Releases the specified marker and any markers added before it
 *
 * Pointers should be released in the inverse order to allocation.
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

/** Trims the linked list back to the specified pointer and return how many bytes marker was behind p
 *
 * Pointers should be released in the inverse order to allocation.
 *
 * Alternatively the oldest pointer can be released, resulting in any newer pointer
 * also being removed from the list.
 *
 * @param[in] m		to release.
 * @return
 *	- 0 marker is ahead of p.
 *	- >0 the number of bytes the marker is behind p.
 */
static inline size_t fr_dbuff_marker_release_behind(fr_dbuff_marker_t *m)
{
	size_t len = fr_dbuff_behind(m);
	fr_dbuff_marker_release(m);
	return len;
}

/** Trims the linked list back to the specified pointer and return how many bytes marker was ahead of p
 *
 * Pointers should be released in the inverse order to allocation.
 *
 * Alternatively the oldest pointer can be released, resulting in any newer pointer
 * also being removed from the list.
 *
 * @param[in] m		to release.
 * @return
 *	- 0 marker is ahead of p.
 *	- >0 the number of bytes the marker is behind p.
 */
static inline size_t fr_dbuff_marker_release_ahead(fr_dbuff_marker_t *m)
{
	size_t len = fr_dbuff_ahead(m);
	fr_dbuff_marker_release(m);
	return len;
}
/** @} */

/** @name "in" functions (copy data into a dbuff)
 * @{
 */

/** Internal copy function to switch between memcpy and memmove - do not call directly
 *
 * @private
 *
 * @param[out] o_start		Where to copy data to.
 * @param[in] o_end		end of the output buffer.
 * @param[in] i_start		Where to copy data from.
 * @param[in] i_end		end of the source buffer.
 * @return
 *	- 0 on sanity check error.
 *	- >0 the number of bytes copied.
 */
static inline CC_HINT(always_inline) size_t _fr_dbuff_safecpy(uint8_t *o_start, uint8_t *o_end,
							      uint8_t const *i_start, uint8_t const *i_end)
{
	ssize_t	diff;
	size_t	i_len = i_end - i_start;

	if (unlikely((o_end < o_start) || (i_end < i_start))) return 0;	/* sanity check */

	diff = (o_end - o_start) - (i_len);
	if (diff < 0) return 0;

	if ((i_start > o_end) || (i_end < o_start)) {			/* no-overlap */
		memcpy(o_start,  i_start, i_len);
	} else {							/* overlap */
		memmove(o_start, i_start, i_len);
	}

	return (i_len);
}

/** Internal function - do not call directly
 *
 * @private
 */
static inline ssize_t _fr_dbuff_in_memcpy(uint8_t **pos_p, fr_dbuff_t *out,
					  uint8_t const *in, size_t inlen)
{
	fr_assert(!out->is_const);

	_FR_DBUFF_EXTEND_LOWAT_POS_OR_RETURN(pos_p, out, inlen);

	return _fr_dbuff_set(pos_p, out, (*pos_p) + _fr_dbuff_safecpy((*pos_p), (*pos_p) + inlen, in, in + inlen));		/* Advance out */
}

/** Internal function - do not call directly
 *
 * @private
 */
static inline ssize_t _fr_dbuff_in_memcpy_dbuff(uint8_t **pos_p, fr_dbuff_t *out,
					        uint8_t * const *in_p, fr_dbuff_t const *in, size_t inlen)
{
	fr_dbuff_t	*our_in;
	uint8_t		**our_in_p;
	size_t		ext_len;

	memcpy(&our_in, &in, sizeof(our_in));		/* Stupid const issues caused by generics */
	memcpy(&our_in_p, &in_p, sizeof(our_in_p));	/* Stupid const issues caused by generics */

	if (inlen == SIZE_MAX) {
		ext_len = _fr_dbuff_extend_lowat(NULL, our_in, fr_dbuff_end(our_in) - (*our_in_p), inlen);
		if (ext_len < inlen) inlen = ext_len;
	} else {
		_FR_DBUFF_EXTEND_LOWAT_POS_OR_RETURN(our_in_p, our_in, inlen);		/* Extend in or return */
	}
	return _fr_dbuff_in_memcpy(pos_p, out, *our_in_p, inlen);			/* Copy _in to _out */
}

/** Copy exactly _inlen bytes into a dbuff or marker
 *
 * If _in is a dbuff and _inlen is greater than the number of bytes available
 * in that dbuff, the copy operation will fail.
 *
 * @note _in will not be advanced.  If this is required #fr_dbuff_move should be used.
 *
 * @param[in] _out	Where to copy data to.  May be a dbuff or marker.
 * @param[in] _in	Data to copy to dbuff or marker.
 * @param[in] _inlen	How much data we need to copy.
 *			If _in is a `char *` or `dbuff *` and SIZE_MAX
 *			is passed, then _inlen will be substituted
 *			for the length of the data in the dbuff.
 * @return
 *	- 0	no data copied.
 *	- >0	the number of bytes copied to the dbuff.
 *	- <0	the number of bytes we would have needed
 *		to complete the copy operation.
 */
#define fr_dbuff_in_memcpy(_out, _in, _inlen) \
	_Generic((_in), \
		uint8_t *		: _fr_dbuff_in_memcpy(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (uint8_t const *)(_in), _inlen), \
		uint8_t const *		: _fr_dbuff_in_memcpy(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (uint8_t const *)(_in), _inlen), \
		char *			: _fr_dbuff_in_memcpy(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (uint8_t const *)(_in), (size_t)(_inlen) == SIZE_MAX ? strlen((char const *)(_in)) : (_inlen)), \
		char const *		: _fr_dbuff_in_memcpy(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (uint8_t const *)(_in), (size_t)(_inlen) == SIZE_MAX ? strlen((char const *)(_in)) : (_inlen)), \
		fr_dbuff_t *		: _fr_dbuff_in_memcpy_dbuff(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), &((fr_dbuff_t const *)(_in))->p, ((fr_dbuff_t const *)(_in)), _inlen), \
		fr_dbuff_marker_t *	: _fr_dbuff_in_memcpy_dbuff(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), &((fr_dbuff_marker_t const *)(_in))->p, ((fr_dbuff_marker_t const *)(_in))->parent, _inlen) \
	)

/** Copy exactly _inlen bytes into dbuff or marker returning if there's insufficient space
 * @copydetails fr_dbuff_in_memcpy
 */
#define FR_DBUFF_IN_MEMCPY_RETURN(_out, _in, _inlen) FR_DBUFF_RETURN(fr_dbuff_in_memcpy, _out, _in, _inlen)

/** Internal function - do not call directly
 *
 * @private
 */
static inline size_t _fr_dbuff_in_memcpy_partial(uint8_t **pos_p, fr_dbuff_t *out,
						 uint8_t const *in, size_t inlen)
{
	size_t ext_len;

	fr_assert(!out->is_const);

	ext_len = _fr_dbuff_extend_lowat(NULL, out, fr_dbuff_end(out) - (*pos_p), inlen);
	if (ext_len < inlen) inlen = ext_len;

	return _fr_dbuff_set(pos_p, out, (*pos_p) + _fr_dbuff_safecpy((*pos_p), (*pos_p) + inlen, in, in + inlen));
}

/** Internal function - do not call directly
 *
 * @private
 */
static inline size_t _fr_dbuff_in_memcpy_partial_dbuff(uint8_t **pos_p, fr_dbuff_t *out,
						       uint8_t * const *in_p, fr_dbuff_t const *in, size_t inlen)
{
	fr_dbuff_t	*our_in;
	uint8_t		**our_in_p;
	size_t		ext_len;

	memcpy(&our_in, &in, sizeof(our_in));		/* Stupid const issues caused by generics */
	memcpy(&our_in_p, &in_p, sizeof(our_in_p));	/* Stupid const issues caused by generics */

	ext_len = _fr_dbuff_extend_lowat(NULL, our_in, fr_dbuff_end(our_in) - (*our_in_p), inlen);
	if (ext_len < inlen) inlen = ext_len;

	return _fr_dbuff_in_memcpy_partial(pos_p, out, (*our_in_p), inlen);
}

/** Copy at most _inlen bytes into the dbuff
 *
 * Use this variant when writing data to a streaming buffer where
 * partial writes will be tracked.
 *
 * If _in is a #fr_dbuff_t and _inlen is greater than the number of bytes
 * available in that dbuff, the copy operation will truncated.
 *
 * @note _in will not be advanced.  If this is required #fr_dbuff_move should be used.
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
#define fr_dbuff_in_memcpy_partial(_out, _in, _inlen) \
	_Generic((_in), \
		uint8_t *		: _fr_dbuff_in_memcpy_partial(_fr_dbuff_current_ptr(_out), _out, (uint8_t const *)_in, _inlen), \
		uint8_t const *		: _fr_dbuff_in_memcpy_partial(_fr_dbuff_current_ptr(_out), _out, (uint8_t const *)_in, _inlen), \
		char *			: _fr_dbuff_in_memcpy_partial(_fr_dbuff_current_ptr(_out), _out, (uint8_t const *)_in, _inlen == SIZE_MAX ? strlen((char const *)_in) : _inlen), \
		char const *		: _fr_dbuff_in_memcpy_partial(_fr_dbuff_current_ptr(_out), _out, (uint8_t const *)_in, _inlen == SIZE_MAX ? strlen((char const *)_in) : _inlen), \
		fr_dbuff_t *		: _fr_dbuff_in_memcpy_partial_dbuff(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), &((fr_dbuff_t const *)(_in))->p, ((fr_dbuff_t const *)(_in)), _inlen), \
		fr_dbuff_marker_t *	: _fr_dbuff_in_memcpy_partial_dbuff(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), &((fr_dbuff_marker_t const *)(_in))->p, ((fr_dbuff_marker_t const *)(_in))->parent, _inlen) \
	)

/** Copy a partial byte sequence into a dbuff
 *
 * @copybrief fr_dbuff_in_memcpy_partial
 *
 * @param[in] _dbuff	to copy byte sequence into.
 * @param[in] ...	bytes to copy.
 */
#define fr_dbuff_in_bytes_partial(_dbuff, ...) \
	fr_dbuff_in_memcpy_partial(_dbuff, ((uint8_t []){ __VA_ARGS__ }), sizeof((uint8_t []){ __VA_ARGS__ }))

/** Copy a byte sequence into a dbuff or marker
 *
 * @copybrief fr_dbuff_in_memcpy
 *
 * @param[in] _dbuff_or_marker	to copy byte sequence into.
 * @param[in] ...		bytes to copy.
 */
#define fr_dbuff_in_bytes(_dbuff_or_marker, ...) \
	fr_dbuff_in_memcpy(_dbuff_or_marker, ((uint8_t []){ __VA_ARGS__ }), sizeof((uint8_t []){ __VA_ARGS__ }))

/** Copy a byte sequence into a dbuff or marker returning if there's insufficient space
 *
 * @copydetails fr_dbuff_in_bytes
 */
#define FR_DBUFF_IN_BYTES_RETURN(_dbuff_or_marker, ...) \
	FR_DBUFF_IN_MEMCPY_RETURN(_dbuff_or_marker, ((uint8_t []){ __VA_ARGS__ }), sizeof((uint8_t []){ __VA_ARGS__ }))

/** Internal function - do not call directly
 *
 * @private
 */
static inline ssize_t _fr_dbuff_memset(uint8_t **pos_p, fr_dbuff_t *dbuff, uint8_t c, size_t inlen)
{
	fr_assert(!dbuff->is_const);

	_FR_DBUFF_EXTEND_LOWAT_POS_OR_RETURN(pos_p, dbuff, inlen);

	memset((*pos_p), c, inlen);

	return _fr_dbuff_set(pos_p, dbuff, (*pos_p) + inlen);
}

/** Set _inlen bytes of a dbuff or marker to _c
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

/** Set _inlen bytes of a dbuff or marker to _c returning if there is insufficient space
 *
 * @copydetails fr_dbuff_memset
 */
#define FR_DBUFF_MEMSET_RETURN(_dbuff_or_marker, _c, _inlen) FR_DBUFF_RETURN(fr_dbuff_memset, _dbuff_or_marker, _c, _inlen)

/** @cond */
/** Define integer decoding functions
 * @private
 */
#define FR_DBUFF_PARSE_INT_DEF(_type) \
static inline ssize_t _fr_dbuff_in_##_type(uint8_t **pos_p, fr_dbuff_t *out, _type##_t num) \
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
/** @endcond */

/*

 */

/** Internal function - do not call directly
 *
 * The fr_dbuff_in_<type>() functions take rvalues, so to implement float and
 * double in terms of the same-sized integers, we need a layer that gives us an
 * lvalue whose address we can cast.
 *
 * @private
 */
static inline ssize_t _fr_dbuff_in_float(uint8_t **pos_p, fr_dbuff_t *out, float num)
{
	return _fr_dbuff_in_uint32(pos_p, out, *(uint32_t *)(&num));
}

/** Internal function - do not call directly
 *
 * @copydetails _fr_dbuff_in_float
 *
 * @private
 */
static inline ssize_t _fr_dbuff_in_double(uint8_t **pos_p, fr_dbuff_t *out, double num)
{
	return _fr_dbuff_in_uint64(pos_p, out, *(uint64_t *)(&num));
}

/** Copy data from a fixed sized C type into a dbuff or marker
 *
 * @param[out] _out	dbuff or marker to write to.  Integer types will be automatically
 *			converted to big endian byte order.
 * @param[in] _in	Value to copy.
 * @return
 *	- <0 the number of bytes we would have needed to complete the conversion.
 *	- >0 the number of bytes _in was advanced by.
 */
#define fr_dbuff_in(_out, _in) \
	_Generic((_in), \
		int8_t		: fr_dbuff_in_bytes(_out, (int8_t)_in), \
		int16_t		: _fr_dbuff_in_int16(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (int16_t)_in), \
		int32_t		: _fr_dbuff_in_int32(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (int32_t)_in), \
		int64_t		: _fr_dbuff_in_int64(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (int64_t)_in), \
		uint8_t		: fr_dbuff_in_bytes(_out, (uint8_t)_in), \
		uint16_t	: _fr_dbuff_in_uint16(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (uint16_t)_in), \
		uint32_t	: _fr_dbuff_in_uint32(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (uint32_t)_in), \
		uint64_t	: _fr_dbuff_in_uint64(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (uint64_t)_in), \
		float		: _fr_dbuff_in_float(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (float)_in), \
		double		: _fr_dbuff_in_double(_fr_dbuff_current_ptr(_out), fr_dbuff_ptr(_out), (double)_in) \
	)

/** Copy data from a fixed sized C type into a dbuff returning if there is insufficient space
 *
 * @copydetails fr_dbuff_in
 */
#define FR_DBUFF_IN_RETURN(_out, _in) FR_DBUFF_RETURN(fr_dbuff_in, _out, _in)

/** Internal function - do not call directly
 * @private
 */
static inline ssize_t _fr_dbuff_in_uint64v(uint8_t **pos_p, fr_dbuff_t *dbuff, uint64_t num)
{
	size_t	ret;

	ret = ROUND_UP_DIV((size_t)fr_high_bit_pos(num | 0x08), 8);
	num = ntohll(num);

	return _fr_dbuff_in_memcpy(pos_p, dbuff, ((uint8_t *)&num) + (sizeof(uint64_t) - ret), ret);
}

/** Copy an integer value into a dbuff or marker using our internal variable length encoding
 *
 * @param[out] _dbuff_or_marker		to copy integer value to.
 * @param[in] _num			to copy.
 * @return
 *	- <0 the number of bytes we would have needed to encode the integer value.
 *	- >0 the number of bytes used to represent the integer value.
 */
#define fr_dbuff_in_uint64v(_dbuff_or_marker, _num) \
	_fr_dbuff_in_uint64v(_fr_dbuff_current_ptr(_dbuff_or_marker), fr_dbuff_ptr(_dbuff_or_marker), _num)

/** Copy an integer value into a dbuff or marker using our internal variable length encoding returning if there is insufficient space
 *
 * @copydetails fr_dbuff_in_uint64v
 */
#define FR_DBUFF_IN_UINT64V(_dbuff_or_marker, _num) FR_DBUFF_RETURN(fr_dbuff_in_uint64v, _dbuff_or_marker, _num)
/** @} */

/** @name "move" functions (copy data between dbuffs and markers)
 * @{
 */
/** Internal function - do not call directly
 * @private
 */
size_t _fr_dbuff_move_dbuff_to_dbuff(fr_dbuff_t *out, fr_dbuff_t *in, size_t len);

/** Internal function - do not call directly
 * @private
 */
size_t _fr_dbuff_move_dbuff_to_dbuff_marker(fr_dbuff_marker_t *out, fr_dbuff_t *in, size_t len);

/** Internal function - do not call directly
 * @private
 */
size_t _fr_dbuff_move_dbuff_marker_to_dbuff(fr_dbuff_t *out, fr_dbuff_marker_t *in, size_t len);

/** Internal function - do not call directly
 * @private
 */
size_t _fr_dbuff_move_dbuff_marker_to_dbuff_marker(fr_dbuff_marker_t *out, fr_dbuff_marker_t *in, size_t len);

/** Copy in as many bytes as possible from one dbuff or marker to another
 *
 * @param[in] _out	to copy into.
 * @param[in] _in	to copy from.
 * @param[in] _len	The maximum length to copy.
 * @return Number of bytes to copy.
 */
#define fr_dbuff_move(_out, _in, _len) \
	_Generic((_out), \
		fr_dbuff_t *		: \
		_Generic((_in), \
			fr_dbuff_t *		: _fr_dbuff_move_dbuff_to_dbuff((fr_dbuff_t *)_out, \
										(fr_dbuff_t *)_in, \
										_len), \
			fr_dbuff_marker_t *	: _fr_dbuff_move_dbuff_marker_to_dbuff((fr_dbuff_t *)_out, \
										       (fr_dbuff_marker_t *)_in, \
										       _len) \
		), \
		fr_dbuff_marker_t *	: \
		_Generic((_in), \
			fr_dbuff_t *		: _fr_dbuff_move_dbuff_to_dbuff_marker((fr_dbuff_marker_t *)_out, \
										       (fr_dbuff_t *)_in, \
										       _len), \
			fr_dbuff_marker_t *	: _fr_dbuff_move_dbuff_marker_to_dbuff_marker((fr_dbuff_marker_t *)_out, \
											      (fr_dbuff_marker_t *)_in, \
											      _len) \
		) \
	)
/** @} */

/** @name "out" functions (copy data out of a dbuff)
 * @{
 */

/** Internal function - do not call directly
 *
 * @private
 */
static inline ssize_t _fr_dbuff_out_memcpy(uint8_t *out, uint8_t **pos_p, fr_dbuff_t *in, size_t outlen)
{
	size_t	ext_len, to_copy, remaining;

	for (remaining = outlen; remaining > 0; remaining -= to_copy) {
		to_copy = remaining;
		ext_len = _fr_dbuff_extend_lowat(NULL, in, fr_dbuff_end(in) - (*pos_p), 1);
		if (ext_len == 0) return -remaining;
		if (ext_len < to_copy) to_copy = ext_len;
		out += _fr_dbuff_set(pos_p, in,
				     (*pos_p) + _fr_dbuff_safecpy(out, out + to_copy, (*pos_p), (*pos_p) + to_copy));
	}

	return outlen;
}
/** Internal function - do not call directly
 *
 * @private
 */
static inline ssize_t _fr_dbuff_out_memcpy_dbuff(uint8_t **out_p, fr_dbuff_t *out, uint8_t **pos_p, fr_dbuff_t *in, size_t outlen)
{
	if (outlen == SIZE_MAX) outlen = _fr_dbuff_extend_lowat(NULL, out, fr_dbuff_end(out) - (*out_p), outlen);

	return _fr_dbuff_out_memcpy((*out_p), pos_p, in, outlen);
}

/** Copy exactly _outlen bytes from the dbuff
 *
 * If _out is a dbuff and _outlen is greater than the number of bytes
 * available in that dbuff, the copy operation will fail.
 *
 * @note _out will not be advanced.  If this is required #fr_dbuff_move should be used.
 *
 * @param[in] _out	to copy data to.
 * @param[in] _in	Data to copy to dbuff.
 * @param[in] _outlen	How much data we need to copy.
 *			If _out is `fr_dbuff_t *` and SIZE_MAX
 *			is passed, then _inlen will be substituted
 *			for the length of the buffer.
 * @return
 *	- 0	no data copied.
 *	- >0	the number of bytes copied.
 *	- <0	the number of bytes we would have needed
 *		to complete the copy operation.
 */
#define fr_dbuff_out_memcpy(_out, _in, _outlen) \
	_Generic((_out), \
		 uint8_t *		: _fr_dbuff_out_memcpy((uint8_t *)(_out), _fr_dbuff_current_ptr(_in), fr_dbuff_ptr(_in), _outlen), \
		 fr_dbuff_t *		: _fr_dbuff_out_memcpy_dbuff(_fr_dbuff_current_ptr((fr_dbuff_t *)_out), fr_dbuff_ptr((fr_dbuff_t *)(_out)), _fr_dbuff_current_ptr(_in), fr_dbuff_ptr(_in), _outlen), \
		 fr_dbuff_marker_t *	: _fr_dbuff_out_memcpy_dbuff(_fr_dbuff_current_ptr((fr_dbuff_marker_t *)_out), fr_dbuff_ptr((fr_dbuff_marker_t *)(_out)), _fr_dbuff_current_ptr(_in), fr_dbuff_ptr(_in), _outlen) \
	)

/** Copy outlen bytes from the dbuff returning if there's insufficient data in the dbuff
 *
 * @copydetails fr_dbuff_out_memcpy
 */
#define FR_DBUFF_OUT_MEMCPY_RETURN(_out, _in, _outlen) FR_DBUFF_RETURN(fr_dbuff_out_memcpy, _out, _in, _outlen)

/** @cond */
/** Define integer encoding functions
 * @private
 */
#define FR_DBUFF_OUT_DEF(_type) \
static inline ssize_t _fr_dbuff_out_##_type(_type##_t *out, uint8_t **pos_p, fr_dbuff_t *in) \
{ \
	fr_assert(out); \
	FR_DBUFF_EXTEND_LOWAT_OR_RETURN(in, sizeof(_type##_t)); \
	*out = fr_net_to_##_type((*pos_p)); \
	return _fr_dbuff_set(pos_p, in, (*pos_p) + sizeof(_type##_t)); \
}

FR_DBUFF_OUT_DEF(uint16)
FR_DBUFF_OUT_DEF(uint32)
FR_DBUFF_OUT_DEF(uint64)
FR_DBUFF_OUT_DEF(int16)
FR_DBUFF_OUT_DEF(int32)
FR_DBUFF_OUT_DEF(int64)
/** @endcond */

/** Copy data from a dbuff or marker to a fixed sized C type
 *
 * @param[out] _out	Where to write the data.  If out is an integer type
 *			a byteswap will be performed if native endianess
 *      		is not big endian.
 * @param[in] _in	A dbuff or marker to copy data from.  The dbuff or
 *			marker will be advanced by the number of bytes
 *			consumed.
 * @return
 *	- <0 the number of bytes we would have needed to complete the conversion.
 *	- >0 the number of bytes _in was advanced by.
 */
#define fr_dbuff_out(_out, _in) \
	_Generic((_out), \
		uint8_t *	: _fr_dbuff_out_memcpy((uint8_t *)(_out), _fr_dbuff_current_ptr(_in), fr_dbuff_ptr(_in), 1), \
		uint16_t *	: _fr_dbuff_out_uint16((uint16_t *)(_out), _fr_dbuff_current_ptr(_in), fr_dbuff_ptr(_in)), \
		uint32_t *	: _fr_dbuff_out_uint32((uint32_t *)(_out), _fr_dbuff_current_ptr(_in), fr_dbuff_ptr(_in)), \
		uint64_t *	: _fr_dbuff_out_uint64((uint64_t *)(_out), _fr_dbuff_current_ptr(_in), fr_dbuff_ptr(_in)), \
		int8_t *	: _fr_dbuff_out_memcpy((uint8_t *)(_out), _fr_dbuff_current_ptr(_in), fr_dbuff_ptr(_in), 1), \
		int16_t *	: _fr_dbuff_out_int16((int16_t *)(_out), _fr_dbuff_current_ptr(_in), fr_dbuff_ptr(_in)), \
		int32_t *	: _fr_dbuff_out_int32((int32_t *)(_out), _fr_dbuff_current_ptr(_in), fr_dbuff_ptr(_in)), \
		int64_t *	: _fr_dbuff_out_int64((int64_t *)(_out), _fr_dbuff_current_ptr(_in), fr_dbuff_ptr(_in)), \
		float *		: _fr_dbuff_out_uint32((uint32_t *)(_out), _fr_dbuff_current_ptr(_in), fr_dbuff_ptr(_in)), \
		double *	: _fr_dbuff_out_uint64((uint64_t *)(_out), _fr_dbuff_current_ptr(_in), fr_dbuff_ptr(_in)) \
	)

/** Copy data from a dbuff or marker to a fixed sized C type returning if there is insufficient data
 *
 * @copydetails fr_dbuff_out
 */
#define FR_DBUFF_OUT_RETURN(_out, _in) FR_DBUFF_RETURN(fr_dbuff_out, _out, _in)

/** Internal function - do not call directly
 * @private
 */
static inline ssize_t _fr_dbuff_out_uint64v(uint64_t *num, uint8_t **pos_p, fr_dbuff_t *dbuff, size_t length)
{
	ssize_t		slen;

	fr_assert(length > 0 && length <= sizeof(uint64_t));

	*num = 0;
	slen = _fr_dbuff_out_memcpy(((uint8_t *) num) + (8 - length), pos_p, dbuff, length);
	if (slen <= 0) return slen;

	*num = fr_net_to_uint64((uint8_t const *)num);
	return length;
}

/** Read bytes from a dbuff or marker and interpret them as a network order unsigned integer
 * @param[in] _num		points to a uint64_t to store the integer in
 * @param[in] _dbuff_or_marker	data to copy bytes from
 * @param[in] _len		number of bytes to read (must be positive and less than eight)
 *
 * @return
 *	- 0	no data read.
 *	- >0	the number of bytes read.
 *	- <0	the number of bytes we would have needed
 *		to complete the read operation.
 */
#define fr_dbuff_out_uint64v(_num, _dbuff_or_marker, _len) \
	_fr_dbuff_out_uint64v(_num, _fr_dbuff_current_ptr(_dbuff_or_marker), fr_dbuff_ptr(_dbuff_or_marker), _len)

/** Read bytes from a dbuff or marker and interpret them as a network order unsigned integer
 *
 * @copydetails fr_dbuff_out_uint64v
 */
#define FR_DBUFF_OUT_UINT64V_RETURN(_num, _dbuff_or_marker, _len) FR_DBUFF_RETURN(fr_dbuff_out_uint64v, _num, _dbuff_or_marker, _len)

/** @} */

#ifdef __cplusplus
}
#endif
