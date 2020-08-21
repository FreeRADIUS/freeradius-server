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

#if defined(__clang_analyzer__) || !defined(NDEBUG)
#  define CHECK_DBUFF_INIT(_sbuff)	if (!(_sbuff)->extend && (unlikely(!(_sbuff)->buff) || unlikely(!(_sbuff)->start) || unlikely(!(_sbuff)->end) || unlikely(!(_sbuff)->p))) return 0;
#else
#  define CHECK_DBUFF_INIT(_sbuff)
#endif

/** start/end flavored mem{cpy,move} wrapper with sanity checks
 */
static inline CC_HINT(always_inline) ssize_t safecpy(uint8_t *o_start, uint8_t *o_end,
						     uint8_t const *i_start, uint8_t const *i_end)
{
	ssize_t	diff;
	size_t	i_len = i_end - i_start;

	if (unlikely((o_end < o_start) || (i_end < i_start))) return 0;	/* sanity check */

	diff = (o_end - o_start) - (i_len);
	if (diff < 0) return diff;

	if ((i_start > o_end) || (i_end < o_start)) {			/* no-overlap */
		memcpy(o_start,  i_start, i_len);
	} else {							/* overlap */
		memmove(o_start, i_start, i_len);
	}

	return (i_len);
}

/** Move data from one dbuff to another
 *
 * @note Do not call this function directly; use #fr_dbuff_move
 *
 * Both in and out will be advanced by
 * min {len, fr_dbuff_remaining(out), fr_dbuff_remaining(in)}; eventually,
 * we'll attempt to extend dbuffs where possible and needed to make len bytes
 * available in both in and out.
 *
 * @param[in] out	dbuff to copy data to.
 * @param[in] in	dbuff to copy data from.
 * @param[in] len	Maximum number of bytes to copy.
 * @return The amount of data copied.
 */
size_t _fr_dbuff_move_dbuff_to_dbuff(fr_dbuff_t *out, fr_dbuff_t *in, size_t len)
{
	size_t o_remaining = fr_dbuff_remaining(out);
	size_t i_remaining = fr_dbuff_remaining(in);
	size_t to_copy = len;
	if (to_copy > o_remaining) to_copy = o_remaining;
	if (to_copy > i_remaining) to_copy = i_remaining;
	safecpy(fr_dbuff_current(out), fr_dbuff_end(out), fr_dbuff_current(in), fr_dbuff_current(in) + to_copy);
	return fr_dbuff_advance(out, fr_dbuff_advance(in, to_copy));
}

/** Move data from a marker to a dbuff
 *
 * @note Do not call this function directly; use #fr_dbuff_move
 *
 * Both in and out will be advanced by
 * min {len, fr_dbuff_remaining(out), fr_dbuff_marker_remaining(in)}; eventually,
 * we'll attempt to extend dbuffs where possible and needed to make len bytes
 * available in both in and out.
 *
 * @param[in] out	dbuff to copy data to.
 * @param[in] in	marker to copy data from.
 * @param[in] len	Maximum number of bytes to copy.
 * @return The amount of data copied.
 */
size_t _fr_dbuff_move_marker_to_dbuff(fr_dbuff_t *out, fr_dbuff_marker_t *in, size_t len)
{
	size_t o_remaining = fr_dbuff_remaining(out);
	size_t i_remaining = fr_dbuff_marker_remaining(in);
	size_t to_copy = len;
	if (to_copy > o_remaining) to_copy = o_remaining;
	if (to_copy > i_remaining) to_copy = i_remaining;
	safecpy(fr_dbuff_current(out), fr_dbuff_end(out), fr_dbuff_marker_current(in),
	        fr_dbuff_marker_current(in) + to_copy);
	return fr_dbuff_advance(out, fr_dbuff_marker_advance(in, to_copy));
}

/** Move data from one marker to another
 *
 * @note Do not call this function directly; use #fr_dbuff_move
 *
 * Both in and out will be advanced by
 * min {len, fr_dbuff_marker_remaining(out), fr_dbuff_marker_remaining(in)}; eventually,
 * we'll attempt to extend dbuffs where possible and needed to make len bytes
 * available in both in and out.
 *
 * @param[in] out	dbuff to copy data to.
 * @param[in] in	marker to copy data from.
 * @param[in] len	Maximum number of bytes to copy.
 * @return The amount of data copied.
 */
size_t _fr_dbuff_move_marker_to_marker(fr_dbuff_marker_t *out, fr_dbuff_marker_t *in, size_t len)
{
	size_t o_remaining = fr_dbuff_marker_remaining(out);
	size_t i_remaining = fr_dbuff_marker_remaining(in);
	size_t to_copy = len;
	if (to_copy > o_remaining) to_copy = o_remaining;
	if (to_copy > i_remaining) to_copy = i_remaining;
	safecpy(fr_dbuff_marker_current(out), fr_dbuff_marker_end(out), fr_dbuff_marker_current(in),
		fr_dbuff_marker_current(in) + to_copy);
	return fr_dbuff_marker_advance(out, fr_dbuff_marker_advance(in, to_copy));
}

/** Move data from a dbuff to a marker
 *
 * @note Do not call this function directly; use #fr_dbuff_move
 *
 * Both in and out will be advanced by
 * min {len, fr_dbuff_marker_remaining(out), fr_dbuff_marker_remaining(in)}; eventually,
 * we'll attempt to extend dbuffs where possible and needed to make len bytes
 * available in both in and out.
 *
 * @param[in] out	dbuff to copy data to.
 * @param[in] in	marker to copy data from.
 * @param[in] len	Maximum number of bytes to copy.
 * @return The amount of data copied.
 */
size_t _fr_dbuff_move_dbuff_to_marker(fr_dbuff_marker_t *out, fr_dbuff_t *in, size_t len)
{
	size_t o_remaining = fr_dbuff_marker_remaining(out);
	size_t i_remaining = fr_dbuff_remaining(in);
	size_t to_copy = len;
	if (to_copy > o_remaining) to_copy = o_remaining;
	if (to_copy > i_remaining) to_copy = i_remaining;
	safecpy(fr_dbuff_marker_current(out), fr_dbuff_marker_end(out), fr_dbuff_current(in),
		fr_dbuff_current(in) + to_copy);
	return fr_dbuff_marker_advance(out, fr_dbuff_advance(in, to_copy));
}

static inline size_t	min(size_t x, size_t y)
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

/** Reallocate the current buffer
 *
 * @param[in] dbuff		to be extended.
 * @param[in] extension		How many additional bytes should be allocated
 *				in the buffer.
 * @return
 *	- 0 the extension operation failed.
 *	- >0 the number of bytes the buffer was extended by.
 */
size_t fr_dbuff_extend_talloc(fr_dbuff_t *dbuff, size_t extension)
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
