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

 /** A generic data buffer structure for encoding and decoding
 *
 * Because doing manual length checks is error prone and a waste of everyone's time.
 *
 * @file src/lib/util/dbuff.c
 *
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

RCSID("$Id$")

#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/syserror.h>

#if defined(__clang_analyzer__) || !defined(NDEBUG)
#  define CHECK_DBUFF_INIT(_sbuff)	if (!(_sbuff)->extend && (unlikely(!(_sbuff)->buff) || unlikely(!(_sbuff)->start) || unlikely(!(_sbuff)->end) || unlikely(!(_sbuff)->p))) return 0;
#else
#  define CHECK_DBUFF_INIT(_sbuff)
#endif

/** Internal macro for defining dbuff move functions
 * @private
 */
#define FR_DBUFF_MOVE_DEF(_out_type, _in_type) \
size_t _fr_dbuff_move_##_in_type##_to_##_out_type(fr_##_out_type##_t *out, fr_##_in_type##_t *in, size_t len) \
{ \
	size_t ext_len, to_copy, remaining = len; \
	while (remaining > 0) { \
		to_copy = remaining; \
		ext_len = fr_dbuff_extend_lowat(NULL, in, to_copy); \
		if (ext_len < to_copy) to_copy = ext_len; \
		ext_len = fr_dbuff_extend_lowat(NULL, out, to_copy); \
		if (ext_len < to_copy) to_copy = ext_len; \
		if (to_copy == 0) break; \
		to_copy = _fr_dbuff_safecpy(fr_dbuff_current(out), fr_dbuff_end(out), \
					    fr_dbuff_current(in), fr_dbuff_current(in) + to_copy); \
		fr_dbuff_advance(out, fr_dbuff_advance(in, to_copy)); \
		remaining -= to_copy; \
	} \
	return len - remaining; \
}

FR_DBUFF_MOVE_DEF(dbuff, dbuff)
FR_DBUFF_MOVE_DEF(dbuff, dbuff_marker)
FR_DBUFF_MOVE_DEF(dbuff_marker, dbuff)
FR_DBUFF_MOVE_DEF(dbuff_marker, dbuff_marker)

static inline CC_HINT(always_inline) size_t min(size_t x, size_t y)
{
	return x < y ? x : y;
}

/** Update all markers and pointers in the set of dbuffs to point to new_buff
 *
 * This function should be used if the underlying buffer is realloced.
 *
 * @param[in] dbuff	to update.
 * @param[in] new_buff	to assign to to sbuff.
 * @param[in] new_len	Length of the new buffer.
 */
void fr_dbuff_update(fr_dbuff_t *dbuff, uint8_t *new_buff, size_t new_len)
{
	fr_dbuff_t		*dbuff_i;
	uint8_t			*old_buff;	/* Current buff */

	old_buff = dbuff->buff;

	/*
	 *	Update pointers to point to positions
	 *	in new buffer based on their relative
	 *	offsets in the old buffer... but not
	 *	past the end of the new buffer.
	 */
	for (dbuff_i = dbuff; dbuff_i; dbuff_i = dbuff_i->parent) {
		fr_dbuff_marker_t	*m_i;

		dbuff_i->buff = new_buff;
		dbuff_i->start = new_buff + min(new_len, dbuff_i->start - old_buff);
		dbuff_i->end = dbuff_i->buff + new_len;
		dbuff_i->p = new_buff + min(new_len, dbuff_i->p - old_buff);

		for (m_i = dbuff_i->m; m_i; m_i = m_i->next) m_i->p = new_buff + min(new_len, m_i->p - old_buff);
	}
}

/** Shift the contents of the sbuff, returning the number of bytes we managed to shift
 *
 * @param[in] dbuff	to shift.
 * @param[in] shift	the number of bytes to shift
 * 			(not necessarily the amount actually shifted, because
 * 			one can't move pointers outside the buffer)
 *
 * @return
 *	- 0 the shift failed due to constraining pointers.
 *	- >0 the number of bytes we managed to shift pointers
 *	  in the dbuff.
 */
size_t fr_dbuff_shift(fr_dbuff_t *dbuff, size_t shift)
{
	uint8_t	*buff;		/* Current start */

	CHECK_DBUFF_INIT(dbuff);

	buff = dbuff->buff;

	/*
	 *	First pass: find the maximum shift, which is the minimum
	 *	of the distances from buff to any of the current pointers
	 *	or current pointers of markers of dbuff and its ancestors.
	 *	(We're also constrained by the requested shift count.)
	 */
	for (fr_dbuff_t *d = dbuff; d && shift; d = d->parent) {
		shift = min(shift, d->p - buff);
		for (fr_dbuff_marker_t *m = d->m; m; m = m->next) shift = min(shift, m->p - buff);
	}

	if (!shift) return 0;

	/*
	 *	Second pass: adjust pointers.
	 *	The first pass means we need only subtract shift from current pointers.
	 *	Start pointers can't constrain shift, or we'd never free any space, so
	 *	they require the added check.
	 *	For d->end, d->buff <= d->p - shift, and d->p shouldn't exceed d->end,
	 *	so d->p - shift <= d->end - shift, hence d->buff <= d->end - shift.
	 */
	for (fr_dbuff_t *d = dbuff; d; d = d->parent) {
		uint8_t	*start = d->start;

		d->start -= min(shift, d->start - buff);
		d->p -= shift;
		d->end -= shift;
		d->shifted += (shift - (start - d->start));
		for (fr_dbuff_marker_t *m = d->m; m; m = m->next) m->p -= shift;
	}

	/*
	 *	Move data to track moved pointers.
	 */
	memmove(buff, buff + shift, ((fr_dbuff_uctx_fd_t *)(dbuff->uctx))->buff_end - (buff + shift));

	return shift;
}

/** Refresh the buffer with more data from the file
 *
 */
size_t _fr_dbuff_extend_fd(fr_dbuff_t *dbuff, size_t extension)
{
	ssize_t			bytes_read;
	size_t			available, total_read;
	fr_dbuff_uctx_fd_t	*fctx;

	CHECK_DBUFF_INIT(dbuff);

	fctx = dbuff->uctx;

	if (extension == SIZE_MAX) extension = 0;

	total_read = dbuff->shifted + (dbuff->end - dbuff->buff);
	if (total_read >= fctx->max) {
		fr_strerror_printf("Can't satisfy extension request for %zu bytes", extension);
		return 0;	/* There's no way we could satisfy the extension request */
	}

	if (fr_dbuff_used(dbuff)) {
		/*
		 *	Try and shift as much as we can out
		 *	of the buffer to make space.
		 *
		 *	Note: p and markers are constraints here.
		 */
		fr_dbuff_shift(dbuff, fr_dbuff_used(dbuff));
	}

	available = min(fctx->buff_end - dbuff->end, fctx->max - total_read);
	if (available < extension) {
		fr_strerror_printf("Can't satisfy extension request for %zu bytes", extension);
		return 0;	/* There's no way we could satisfy the extension request */
	}

	bytes_read = read(fctx->fd, dbuff->end, available);

	/** Check for errors
	 */
	if (bytes_read < 0) {
		fr_strerror_printf("Error extending buffer: %s", fr_syserror(errno));
		return 0;
	}

	/* Question: should extensible ancestors have their ends adjusted? */
	dbuff->end += bytes_read;	/* Advance end, which increases fr_dbuff_remaining() */

	return bytes_read;
}

/** Reallocate the current buffer
 *
 * @private
 *
 * @param[in] dbuff		to be extended.
 * @param[in] extension		How many additional bytes should be allocated
 *				in the buffer.
 * @return
 *	- 0 the extension operation failed.
 *	- >0 the number of bytes the buffer was extended by.
 */
size_t _fr_dbuff_extend_talloc(fr_dbuff_t *dbuff, size_t extension)
{
	fr_dbuff_uctx_talloc_t	*tctx = dbuff->uctx;
	size_t			clen, nlen, elen = extension;
	uint8_t			*new_buff;

	CHECK_DBUFF_INIT(dbuff);

	clen = dbuff->buff ? talloc_array_length(dbuff->buff) : 0;
	/*
	 *	If the current buffer size + the extension
	 *	is less than init, extend the buffer to init.
	 *
	 *	This can happen if the buffer has been
	 *	trimmed, and then additional data is added.
	 */
	if ((clen + elen) < tctx->init) {
		elen = tctx->init - clen;
	/*
	 *	Double the buffer size if it's more than the
	 *	requested amount.
	 */
	} else if (elen < clen){
		elen = clen;
	}

	/*
	 *	Check we don't exceed the maximum buffer
	 *	length.
	 */
	if (tctx->max && ((clen + elen) > tctx->max)) {
		elen = tctx->max - clen;
		if (elen == 0) {
			fr_strerror_printf("Failed extending buffer by %zu bytes to "
					   "%zu bytes, max is %zu bytes",
					   extension, clen + extension, tctx->max);
			return 0;
		}
	}
	nlen = clen + elen;

	new_buff = talloc_realloc(tctx->ctx, dbuff->buff, uint8_t, nlen);
	if (unlikely(!new_buff)) {
		fr_strerror_printf("Failed extending buffer by %zu bytes to %zu bytes", elen, nlen);
		return 0;
	}

	(void)fr_dbuff_update(dbuff, new_buff, nlen);	/* Shouldn't fail as we're extending */

	return elen;
}
