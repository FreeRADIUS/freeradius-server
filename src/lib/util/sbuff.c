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

/** A generic string buffer structure for string printing and parsing
 *
 * @file src/lib/util/sbuff.c
 *
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/print.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/thread_local.h>

#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

_Thread_local char *sbuff_scratch;

static_assert(sizeof(long long) >= sizeof(int64_t), "long long must be as wide or wider than an int64_t");
static_assert(sizeof(unsigned long long) >= sizeof(uint64_t), "long long must be as wide or wider than an uint64_t");

fr_table_num_ordered_t const sbuff_parse_error_table[] = {
	{ L("ok"),			FR_SBUFF_PARSE_OK				},
	{ L("token not found"),		FR_SBUFF_PARSE_ERROR_NOT_FOUND			},
	{ L("integer overflow"),	FR_SBUFF_PARSE_ERROR_NUM_OVERFLOW		},
	{ L("integer underflow"),	FR_SBUFF_PARSE_ERROR_NUM_UNDERFLOW		},
};
size_t sbuff_parse_error_table_len = NUM_ELEMENTS(sbuff_parse_error_table);

#if defined(__clang_analyzer__) || !defined(NDEBUG)
#  define CHECK_SBUFF_INIT(_sbuff)	if (!(_sbuff)->extend && (unlikely(!(_sbuff)->buff) || unlikely(!(_sbuff)->start) || unlikely(!(_sbuff)->end) || unlikely(!(_sbuff)->p))) return 0;
#else
#  define CHECK_SBUFF_INIT(_sbuff)
#endif

bool const sbuff_char_class_uint[UINT8_MAX + 1] = {
	SBUFF_CHAR_CLASS_NUM,
	['+'] = true
};

bool const sbuff_char_class_int[UINT8_MAX + 1] = {
	SBUFF_CHAR_CLASS_NUM,
	['+'] = true, ['-'] = true
};

bool const sbuff_char_class_float[UINT8_MAX + 1] = {
	SBUFF_CHAR_CLASS_NUM,
	['-'] = true, ['+'] = true, ['e'] = true, ['E'] = true, ['.'] = true,
};

bool const sbuff_char_class_hex[UINT8_MAX + 1] = { SBUFF_CHAR_CLASS_HEX };
bool const sbuff_char_alpha_num[UINT8_MAX + 1] = { SBUFF_CHAR_CLASS_ALPHA_NUM };

/** Escape rules to use when an escape_rules pointer is NULL
 */
fr_sbuff_escape_rules_t escape_none = {};

/** Copy function that allows overlapping memory ranges to be copied
 *
 * @param[out] o_start		start of output buffer.
 * @param[in] o_end		end of the output buffer.
 * @param[in] i_start		start of the input buffer.
 * @param[in] i_end		end of data to copy.
 * @return
 *	- >0 the number of bytes copied.
 *      - 0 invalid args.
 *      - <0 the number of bytes we'd need to complete the copy.
 */
static inline CC_HINT(always_inline) ssize_t safecpy(char *o_start, char *o_end,
						     char const *i_start, char const *i_end)
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

/** Update all markers and pointers in the set of sbuffs to point to new_buff
 *
 * This function should be used if the underlying buffer is realloced.
 *
 * @param[in] sbuff	to update.
 * @param[in] new_buff	to assign to to sbuff.
 * @param[in] new_len	Length of the new buffer.
 */
void fr_sbuff_update(fr_sbuff_t *sbuff, char *new_buff, size_t new_len)
{
	fr_sbuff_t		*sbuff_i;
	char			*old_buff;	/* Current buff */

#define update_ptr(_old_buff, _new_buff, _new_len, _field) \
	_field = (size_t)((_field) - (_old_buff)) < _new_len ? \
		(_new_buff) + ((_field) - (_old_buff)) : \
		(_new_buff) + (_new_len)

	old_buff = sbuff->buff;

	/*
	 *	Update pointers to point to positions
	 *	in new buffer based on their relative
	 *	offsets in the old buffer.
	 */
	for (sbuff_i = sbuff; sbuff_i; sbuff_i = sbuff_i->parent) {
		fr_sbuff_marker_t	*m_i;

		sbuff_i->buff = new_buff;
		update_ptr(old_buff, new_buff, new_len, sbuff_i->start);
		sbuff_i->end = sbuff_i->buff + new_len;
		*(sbuff_i->end) = '\0';	/* Re-terminate */
		update_ptr(old_buff, new_buff, new_len, sbuff_i->p);

		for (m_i = sbuff_i->m; m_i; m_i = m_i->next) update_ptr(old_buff, new_buff, new_len, m_i->p);
	}
#undef update_ptr
}

/** Shift the contents of the sbuff, returning the number of bytes we managed to shift
 *
 * @param[in] sbuff	to shift.
 * @param[in] shift	the contents of the buffer this many bytes
 *			towards the start of the buffer.
 * @return
 *	- 0 the shift failed due to constraining pointers.
 *	- >0 the number of bytes we managed to shift pointers
 *	  in the sbuff.  memmove should be used to move the
 *	  existing contents of the buffer, and fill the free
 *	  space at the end of the buffer with additional data.
 */
size_t fr_sbuff_shift(fr_sbuff_t *sbuff, size_t shift)
{
	fr_sbuff_t		*sbuff_i;
	char			*buff;		/* Current start */
	size_t			max_shift = shift;
	bool			reterminate = false;

	CHECK_SBUFF_INIT(sbuff);

#define update_ptr(_buff, _shift, _field) _field = ((_field) - (_shift)) <= (_buff) ? (_buff) : ((_field) - (_shift))
#define update_max_shift(_buff, _max_shift, _field) if (((_buff) + (_max_shift)) > (_field)) _max_shift -= (((_buff) + (_max_shift)) - (_field))

	buff = sbuff->start;

	/*
	 *	If the sbuff is already \0 terminated
	 *	and we're not working on a const buffer
	 *	then assume we need to re-terminate
	 *	later.
	 */
	reterminate = (*sbuff->p == '\0') && !sbuff->is_const;

	/*
	 *	Determine the maximum shift amount.
	 *	Shifts are constrained by the position
	 *	of pointers into the buffer.
	 */
	for (sbuff_i = sbuff; sbuff_i; sbuff_i = sbuff_i->parent) {
		fr_sbuff_marker_t	*m_i;

		update_max_shift(buff, max_shift, sbuff_i->p);
		if (!max_shift) return 0;

		for (m_i = sbuff_i->m; m_i; m_i = m_i->next) {
			update_max_shift(buff, max_shift, m_i->p);
			if (!max_shift) return 0;
		}
	}

	for (sbuff_i = sbuff; sbuff_i; sbuff_i = sbuff_i->parent) {
		fr_sbuff_marker_t	*m_i;

		/*
		 *	Current position shifts, but stays the same
		 *	relative to content.
		 */
		update_ptr(buff, max_shift, sbuff_i->p);
		update_ptr(buff, max_shift, sbuff_i->end);
		sbuff_i->shifted += max_shift;

		for (m_i = sbuff_i->m; m_i; m_i = m_i->next) update_ptr(buff, max_shift, m_i->p);
	}

	if (reterminate) *sbuff->p = '\0';

#undef update_ptr
#undef update_max_shift

	return max_shift;
}

/** Refresh the buffer with more data from the file
 *
 */
size_t fr_sbuff_extend_file(fr_sbuff_t *sbuff, size_t extension)
{
	size_t			read, available;
	fr_sbuff_uctx_file_t	*fctx = sbuff->uctx;

	if (extension == SIZE_MAX) extension = 0;

	if (fr_sbuff_used(sbuff)) {
		/*
		 *	Try and shift as much as we can out
		 *	of the buffer to make space.
		 *
		 *	Note: p and markers are constraints here.
		 */
		fr_sbuff_shift(sbuff, fr_sbuff_used(sbuff));
	}

	available = fctx->buff_end - sbuff->end;
	if (available < extension) {
		fr_strerror_printf("Can't satisfy extension request for %zu bytes", extension);
		return 0;	/* There's no way we could satisfy the extension request */
	}

	read = fread(sbuff->end, 1, available, fctx->file);
	sbuff->end += read;	/* Advance end, which increases fr_sbuff_remaining() */

	/** Check for errors
	 */
	if (read < available) {
		if (!feof(fctx->file)) {	/* It's a real error */
			fr_strerror_printf("Error extending buffer: %s", fr_syserror(ferror(fctx->file)));
			return 0;
		}
	}

	return read;
}

/** Reallocate the current buffer
 *
 * @param[in] sbuff		to be extended.
 * @param[in] extension		How many additional bytes should be allocated
 *				in the buffer.
 * @return
 *	- 0 the extension operation failed.
 *	- >0 the number of bytes the buffer was extended by.
 */
size_t fr_sbuff_extend_talloc(fr_sbuff_t *sbuff, size_t extension)
{
	fr_sbuff_uctx_talloc_t	*tctx = sbuff->uctx;
	size_t			clen, nlen, elen = extension;
	char			*new_buff;

	CHECK_SBUFF_INIT(sbuff);

	clen = sbuff->buff ? talloc_array_length(sbuff->buff) : 0;
	/*
	 *	If the current buffer size + the extension
	 *	is less than init, extend the buffer to init.
	 *
	 *	This can happen if the buffer has been
	 *	trimmed, and then additional data is added.
	 */
	if ((clen + elen) < tctx->init) {
		elen = (tctx->init - clen) + 1;	/* add \0 */
	/*
	 *	Double the buffer size if it's more than the
	 *	requested amount.
	 */
	} else if (elen < clen){
		elen = clen - 1;		/* Don't double alloc \0 */
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
		elen += 1;			/* add \0 */
	}
	nlen = clen + elen;

	new_buff = talloc_realloc(tctx->ctx, sbuff->buff, char, nlen);
	if (unlikely(!new_buff)) {
		fr_strerror_printf("Failed extending buffer by %zu bytes to %zu bytes", elen, nlen);
		return 0;
	}

	(void)fr_sbuff_update(sbuff, new_buff, nlen - 1);	/* Shouldn't fail as we're extending */

	return elen;
}

/** Trim a talloced sbuff to the minimum length required to represent the contained string
 *
 * @param[in] sbuff	to trim.
 * @param[in] len	Length to trim to.  Passing SIZE_MAX will
 *			result in the buffer being trimmed to the
 *			length of the content.
 * @return
 *	- 0 on success.
 *	- -1 on failure - markers present pointing past the end of string data.
 */
int fr_sbuff_trim_talloc(fr_sbuff_t *sbuff, size_t len)
{
	size_t			clen = 0, nlen = 1;
	char			*new_buff;
	fr_sbuff_uctx_talloc_t	*tctx = sbuff->uctx;

	CHECK_SBUFF_INIT(sbuff);

	if (sbuff->buff) clen = talloc_array_length(sbuff->buff);

	if (len != SIZE_MAX) {
		nlen += len;
	} else if (sbuff->buff){
		nlen += (sbuff->p - sbuff->start);
	}

	if (nlen != clen) {
		new_buff = talloc_realloc(tctx->ctx, sbuff->buff, char, nlen);
		if (!new_buff) {
			fr_strerror_printf("Failed trimming buffer from %zu to %zu", clen, nlen);
			return -1;
		}
		fr_sbuff_update(sbuff, new_buff, nlen - 1);
	}

	return 0;
}

/** Fill as much of the output buffer we can and break on partial copy
 *
 * @param[in] _out	sbuff to write to.
 * @param[in] _in	sbuff to copy from.
 * @param[in] _len	maximum amount to copy.
 */
#define FILL_OR_GOTO_DONE(_out, _in, _len) \
do { \
	ssize_t _copied = safecpy((_out)->p, (_out)->end, (_in)->p, \
				  ((_in)->p) + ((size_t)(_len) <= fr_sbuff_remaining(_in) ? (size_t)(_len) : fr_sbuff_remaining(_in))); \
	if (_copied < 0) { \
		if ((_out)->extend && ((_out)->extend(_out, _copied * -1) > 0)) continue; \
		fr_sbuff_advance(_out, fr_sbuff_advance(_in, safecpy((_out)->p, (_out)->end, (_in)->p, (_in)->p + ((_len) + _copied)))); \
		goto done;\
	} \
	fr_sbuff_advance(_out, fr_sbuff_advance(_in, _copied)); \
} while(0)

/** Constrain end pointer to prevent advancing more than the amount the called specified
 *
 * @param[in] _sbuff	to constrain.
 * @param[in] _max	maximum amount to advance.
 * @param[in] _used	how much we've advanced so far.
 * @return a temporary end pointer.
 */
#define CONSTRAINED_END(_sbuff, _max, _used) \
	(((_max) - (_used)) > fr_sbuff_remaining(_sbuff) ? (_sbuff)->end : (_sbuff)->p + ((_max) - (_used)))


/** Populate a terminal index
 *
 * @param[out] needle_len	the longest needle.
 * @param[out] idx		to populate.
 * @param[in] term		Terminals to populate the index with.
 */
static inline CC_HINT(always_inline) void fr_sbuff_terminal_idx_init(size_t *needle_len,
								     uint8_t idx[static UINT8_MAX + 1],
								     fr_sbuff_term_t const *term)
{
	size_t i, len, max = 0;

	if (!term) return;

	memset(idx, 0, UINT8_MAX + 1);
	*needle_len = 0;

	for (i = 0; i < term->len; i++) {
		len = term->elem[i].len;
		if (len > max) max = len;

		idx[(uint8_t)term->elem[i].str[0]] = i + 1;
	}

	*needle_len = max;
}

/** Efficient terminal string search
 *
 * Caller should ensure that a buffer extension of needle_len bytes has been requested
 * before calling this function.
 *
 * @param[in] in		Sbuff to search in.
 * @param[in] p			Current position (may be ahead of in->p).
 * @param[in] idx		Fastpath index, populated by
 *				fr_sbuff_terminal_idx_init.
 * @param[in] term		terminals to search in.
 * @return
 *      - true if found.
 *	- false if not.
 */
static inline bool fr_sbuff_terminal_search(fr_sbuff_t *in, char const *p,
					    uint8_t idx[static UINT8_MAX + 1],
					    fr_sbuff_term_t const *term)
{
	uint8_t 	term_idx;

	ssize_t		start = 0;
	ssize_t		end;
	ssize_t		mid;

	size_t		remaining;

	if (!term) return false;			/* If there's no terminals, we don't need to search */

	end = term->len - 1;
	term_idx = idx[(uint8_t)*p];			/* Fast path */
	if (!term_idx) return false;

	remaining = fr_sbuff_remaining(in);
	mid = term_idx - 1;				/* Inform the mid point from the index */

	while (start <= end) {
		char const	*elem;
		size_t		tlen;
		int		ret;

		elem = term->elem[mid].str;
		tlen = strlen(elem);

		ret = strncasecmp(p, elem, tlen < (size_t)remaining ? tlen : (size_t)remaining);
		if (ret == 0) {
			/*
			 *	If we have more text than the table element, that's fine
			 */
			if (remaining >= tlen) return true;

			/*
			 *	If input was shorter than the table element we need to
			 *	keep searching.
			 */
			ret = -1;
		}

		if (ret < 0) {
			end = mid - 1;
		} else {
			start = mid + 1;
		}

		mid = start + ((end - start) / 2);	/* Avoid overflow */
	}

	return false;
}

/** Compare two terminal elements for ordering purposes
 *
 * @param[in] a		first terminal to compare.
 * @param[in] b		second terminal to compare.
 * @return
 *	- >0 	if a > b.
 *	- 0	if a == b.
 *	- <0	if a < b.
 */
static inline int8_t terminal_cmp(void const *a, void const *b)
{
	fr_sbuff_term_elem_t const	*our_a = a;
	fr_sbuff_term_elem_t const	*our_b = b;

	int8_t	ret;
	int	i_ret;

	ret = (our_a->len > our_b->len) - (our_a->len < our_b->len);
	if (ret != 0) return ret;

	i_ret = memcmp(our_a->str, our_b->str, our_a->len);
	return (i_ret > 0) - (i_ret < 0);
}

/** Merge two sets of terminal strings
 *
 * @param[in] ctx	to allocate the new terminal array in.
 * @param[in] a		first set of terminals to merge.
 * @param[in] b		second set of terminals to merge.
 * @return A new set of de-duplicated and sorted terminals.
 */
fr_sbuff_term_t *fr_sbuff_terminals_amerge(TALLOC_CTX *ctx, fr_sbuff_term_t const *a, fr_sbuff_term_t const *b)
{
	size_t				i, j, k;
	fr_sbuff_term_t			*new;
	fr_sbuff_term_elem_t const	*tmp[UINT8_MAX + 1];

	for (i = 0; i < a->len; i++) tmp[i] = &a->elem[i];
	for (j = 0; j < b->len; i++, j++) tmp[i] = &b->elem[j];

	if (likely(i > 1)) {
		fr_quick_sort((void const **)tmp, 0, i, terminal_cmp);

		for (j = 0; j < (i - 1); j++) {
			/*
			 *	Duplicate
			 */
			if (terminal_cmp(&tmp[j], &tmp[j + 1]) == 0) {
				i--;
				tmp[j] = NULL;
			}
		}
	}

	new = talloc_pooled_object(ctx, fr_sbuff_term_t, i, i * sizeof(fr_sbuff_term_elem_t));
	if (unlikely(!new)) return NULL;

	new->elem = talloc_array(new, fr_sbuff_term_elem_t, i);
	if (unlikely(!new->elem)) {
		talloc_free(new);
		return NULL;
	}

	j = 0;	/* Tmp index */
	k = 0;	/* How many non-nulls we've found */
	while (j < i) {
		if (tmp[j] == NULL) {
			j++;
			continue;
		}

		new->elem[k] = *tmp[j];
		j++;
		k++;
	}
	new->len = i;

	return new;
}

/** Copy as many bytes as possible from a sbuff to a sbuff
 *
 * Copy size is limited by available data in sbuff and space in output sbuff.
 *
 * @param[out] out	Where to copy to.
 * @param[in] in	Where to copy from.  Will copy len bytes from current position in buffer.
 * @param[in] len	How many bytes to copy.  If SIZE_MAX the entire buffer will be copied.
 * @return
 *	- 0 no bytes copied.
 *	- >0 the number of bytes copied.
 */
size_t fr_sbuff_out_bstrncpy(fr_sbuff_t *out, fr_sbuff_t *in, size_t len)
{
	fr_sbuff_t 	our_in = FR_SBUFF_COPY(in);
	size_t		remaining;

	CHECK_SBUFF_INIT(in);

	while (fr_sbuff_used_total(&our_in) < len) {
		size_t chunk_len;

		remaining = (len - fr_sbuff_used_total(&our_in));

		if (FR_SBUFF_CANT_EXTEND(&our_in)) break;

		chunk_len = fr_sbuff_remaining(&our_in);
		if (chunk_len > remaining) chunk_len = remaining;

		FILL_OR_GOTO_DONE(out, &our_in, chunk_len);
	}

done:
	*out->p = '\0';
	return fr_sbuff_used_total(&our_in);
}

/** Copy exactly len bytes from a sbuff to a sbuff or fail
 *
 * Copy size is limited by available data in sbuff, space in output sbuff, and length.
 *
 * @param[out] out	Where to copy to.
 * @param[in] in	Where to copy from.  Will copy len bytes from current position in buffer.
 * @param[in] len	How many bytes to copy.  If SIZE_MAX the entire buffer will be copied.
 * @return
 *	- 0 no bytes copied, no token found of sufficient length in input buffer.
 *	- >0 the number of bytes copied.
 *	- <0 the number of additional output bytes we would have needed to
 *	  complete the copy.
 */
ssize_t fr_sbuff_out_bstrncpy_exact(fr_sbuff_t *out, fr_sbuff_t *in, size_t len)
{
	fr_sbuff_t 		our_in = FR_SBUFF_NO_ADVANCE(in);
	size_t			remaining;
	fr_sbuff_marker_t	m;

	CHECK_SBUFF_INIT(in);

	fr_sbuff_marker(&m, out);

	do {
		size_t chunk_len;
		ssize_t copied;

		remaining = (len - fr_sbuff_used_total(&our_in));
		if (remaining && FR_SBUFF_CANT_EXTEND(&our_in)) return 0;

		chunk_len = fr_sbuff_remaining(&our_in);
		if (chunk_len > remaining) chunk_len = remaining;

		copied = fr_sbuff_in_bstrncpy(out, our_in.p, chunk_len);
		if (copied < 0) {
			fr_sbuff_set(out, &m);		/* Reset out */
			*m.p = '\0';			/* Re-terminate */

			/* Amount remaining in input buffer minus the amount we could have copied */
			if (len == SIZE_MAX) return -(fr_sbuff_remaining(in) - (chunk_len + copied));
			/* Amount remaining to copy minus the amount we could have copied */
			return -(remaining - (chunk_len + copied));
		}
		fr_sbuff_advance(&our_in, copied);
	} while (fr_sbuff_used_total(&our_in) < len);

	return fr_sbuff_set(in, &our_in);	/* in was pinned, so this works */
}

/** Copy as many allowed characters as possible from a sbuff to a sbuff
 *
 * Copy size is limited by available data in sbuff and output buffer length.
 *
 * As soon as a disallowed character is found the copy is stopped.
 * The input sbuff will be left pointing at the first disallowed character.
 *
 * @param[out] out		Where to copy to.
 * @param[in] in		Where to copy from.  Will copy len bytes from current position in buffer.
 * @param[in] len		How many bytes to copy.  If SIZE_MAX the entire buffer will be copied.
 * @param[in] allowed		Characters to include the copy.
 * @return
 *	- 0 no bytes copied.
 *	- >0 the number of bytes copied.
 */
size_t fr_sbuff_out_bstrncpy_allowed(fr_sbuff_t *out, fr_sbuff_t *in, size_t len,
				     bool const allowed[static UINT8_MAX + 1])
{
	fr_sbuff_t 	our_in = FR_SBUFF_COPY(in);

	CHECK_SBUFF_INIT(in);

	while (fr_sbuff_used_total(&our_in) < len) {
		char	*p;
		char	*end;

		if (FR_SBUFF_CANT_EXTEND(&our_in)) break;

		p = our_in.p;
		end = CONSTRAINED_END(&our_in, len, fr_sbuff_used_total(&our_in));

		while ((p < end) && allowed[(uint8_t)*p]) p++;

		FILL_OR_GOTO_DONE(out, &our_in, p - our_in.p);

		if (p != end) break;		/* stopped early, break */
	};

done:
	*out->p = '\0';
	return fr_sbuff_used_total(&our_in);
}

/** Copy as many allowed characters as possible from a sbuff to a sbuff
 *
 * Copy size is limited by available data in sbuff and output buffer length.
 *
 * As soon as a disallowed character is found the copy is stopped.
 * The input sbuff will be left pointing at the first disallowed character.
 *
 * @param[out] out		Where to copy to.
 * @param[in] in		Where to copy from.  Will copy len bytes from current position in buffer.
 * @param[in] len		How many bytes to copy.  If SIZE_MAX the entire buffer will be copied.
 * @param[in] tt		Token terminals in the encompassing grammar.
 * @param[in] escape_chr	If not '\0', ignore characters in the until set when
 *				prefixed with this escape character.
 * @return
 *	- 0 no bytes copied.
 *	- >0 the number of bytes copied.
 */
size_t fr_sbuff_out_bstrncpy_until(fr_sbuff_t *out, fr_sbuff_t *in, size_t len,
				   fr_sbuff_term_t const *tt, char escape_chr)
{
	fr_sbuff_t 	our_in = FR_SBUFF_COPY(in);
	bool		do_escape = false;		/* Track state across extensions */

	uint8_t		idx[UINT8_MAX + 1];		/* Fast path index */
	size_t		needle_len = 1;

	CHECK_SBUFF_INIT(in);

	/*
	 *	Initialise the fastpath index and
	 *	figure out the longest needle.
	 */
	fr_sbuff_terminal_idx_init(&needle_len, idx, tt);

	while (fr_sbuff_used_total(&our_in) < len) {
		char	*p;
		char	*end;

		if (FR_SBUFF_CANT_EXTEND_LOWAT(in, needle_len) && (fr_sbuff_remaining(in) < 1)) break;

		p = our_in.p;
		end = CONSTRAINED_END(&our_in, len, fr_sbuff_used_total(&our_in));

		if (escape_chr == '\0') {
			while ((p < end) && !fr_sbuff_terminal_search(in, p, idx, tt)) p++;
		} else {
			while (p < end) {
				if (do_escape) {
					do_escape = false;
				} else if (*p == escape_chr) {
					do_escape = true;
				} else if (fr_sbuff_terminal_search(in, p, idx, tt)) {
					break;
				}
				p++;
			}
		}

		FILL_OR_GOTO_DONE(out, &our_in, p - our_in.p);

		if (p != end) break;		/* stopped early, break */
	};

done:
	*out->p = '\0';
	return fr_sbuff_used_total(&our_in);
}

/** Copy as many allowed characters as possible from a sbuff to a sbuff
 *
 * Copy size is limited by available data in sbuff and output buffer length.
 *
 * As soon as a disallowed character is found the copy is stopped.
 * The input sbuff will be left pointing at the first disallowed character.
 *
 * This de-escapes characters as they're copied out of the sbuff.
 *
 * @param[out] out		Where to copy to.
 * @param[in] in		Where to copy from.  Will copy len bytes from current position in buffer.
 * @param[in] len		How many bytes to copy.  If SIZE_MAX the entire buffer will be copied.
 * @param[in] tt		Token terminal strings in the encompassing grammar.
 * @param[in] rules		for processing escape sequences.
 * @return
 *	- 0 no bytes copied.
 *	- >0 the number of bytes written to out.
 */
size_t fr_sbuff_out_unescape_until(fr_sbuff_t *out, fr_sbuff_t *in, size_t len,
				   fr_sbuff_term_t const *tt,
				   fr_sbuff_escape_rules_t const *rules)
{
	fr_sbuff_t 		our_in;
	bool			do_escape = false;		/* Track state across extensions */
	fr_sbuff_marker_t	o_s;

	uint8_t			idx[UINT8_MAX + 1];		/* Fast path index */
	size_t			needle_len = 1;

	/*
	 *	If we don't need to do unescaping
	 *	call a more suitable function.
	 */
	if (!rules || (rules->chr == '\0')) return fr_sbuff_out_bstrncpy_until(out, in, len, tt, '\0');

	CHECK_SBUFF_INIT(in);

	our_in = FR_SBUFF_COPY(in);
	fr_sbuff_marker(&o_s, out);

	/*
	 *	Initialise the fastpath index and
	 *	figure out the longest needle.
	 */
	fr_sbuff_terminal_idx_init(&needle_len, idx, tt);

	while (fr_sbuff_used_total(&our_in) < len) {
		char	*p;
		char	*end;

		if (FR_SBUFF_CANT_EXTEND_LOWAT(in, needle_len) && (fr_sbuff_remaining(in) < 1)) break;

		p = our_in.p;
		end = CONSTRAINED_END(&our_in, len, fr_sbuff_used_total(&our_in));

		while (p < end) {
			if (do_escape) {
				do_escape = false;

				/*
				 *	Check for \x<hex><hex>
				 */
				if (rules->do_hex && (*p == 'x')) {
					uint8_t			escape;
					fr_sbuff_marker_t	m;

					fr_sbuff_marker(&m, &our_in);		/* allow for backtrack */
					fr_sbuff_set(&our_in, ++p);		/* sync sbuff */

					if (fr_sbuff_out_uint8_hex(NULL, &escape, &our_in, false) != 2) {
						fr_sbuff_set(&our_in, &m);	/* backtrack */
						p = m.p + 1;			/* skip escape char */
						fr_sbuff_marker_release(&m);
						goto check_subs;
					}

					if (fr_sbuff_in_char(out, escape) <= 0) {
						fr_sbuff_set(&our_in, &m);	/* backtrack */
						fr_sbuff_marker_release(&m);
						goto done;
					}
					p = our_in.p;
					continue;
				}

				/*
				 *	Check for \<oct><oct><oct>
				 */
				if (rules->do_oct && isdigit(*p)) {
					uint8_t 		escape;
					fr_sbuff_marker_t	m;

					fr_sbuff_marker(&m, &our_in);		/* allow for backtrack */
					fr_sbuff_set(&our_in, p);		/* sync sbuff */

					if (fr_sbuff_out_uint8_oct(NULL, &escape, &our_in, false) != 3) {
						fr_sbuff_set(&our_in, &m);	/* backtrack */
						p = m.p + 1;			/* skip escape char */
						fr_sbuff_marker_release(&m);
						goto check_subs;
					}

					if (fr_sbuff_in_char(out, escape) <= 0) {
						fr_sbuff_set(&our_in, &m);	/* backtrack */
						fr_sbuff_marker_release(&m);
						goto done;
					}
					p = our_in.p;
					continue;
				}

			check_subs:
				/*
				 *	Not a recognised escape sequence.
				 */
				if (rules->subs[(uint8_t)*p] == '\0') {
					if (rules->skip[(uint8_t)*p] == true) goto next;
					goto next_esc;
				}

				/*
				 *  	We already copied everything up
				 *	to this point, so we can now
				 *	write the substituted char to
				 *	the output buffer.
				 */
				if (fr_sbuff_in_char(out, rules->subs[(uint8_t)*p++]) <= 0) goto done;

				/*
				 *	...and advance past the entire
				 *	escape seq in the input buffer.
				 */
				fr_sbuff_advance(&our_in, 2);
				continue;
			}

		next_esc:
			if (*p == rules->chr) {
				/*
				 *	Copy out any data we got before
				 *	we hit the escape char.
				 *
				 *	We need to do this before we
				 *	can write the escape char to
				 *	the output sbuff.
				 */
				if (p > our_in.p) FILL_OR_GOTO_DONE(out, &our_in, p - our_in.p);

				do_escape = true;
				p++;
				continue;
			}

		next:
			if (fr_sbuff_terminal_search(in, p, idx, tt)) break;
			p++;
		}

		FILL_OR_GOTO_DONE(out, &our_in, p - our_in.p);

		if (p != end) break;		/* stopped early, break */
	};

done:
	*out->p = '\0';
	return fr_sbuff_marker_release_behind(&o_s);
}

/** See if the string contains a truth value
 *
 * @param[out] out	Where to write boolean value.
 * @param[in] in	Where to search for a truth value.
 * @return
 *	- 0 no bytes copied.  Was not a truth value.
 *	- >0 the number of bytes consumed.
 */
size_t fr_sbuff_out_bool(bool *out, fr_sbuff_t *in)
{
	static bool const bool_prefix[UINT8_MAX + 1] = {
		['t'] = true, ['T'] = true,	/* true */
		['f'] = true, ['F'] = true,	/* false */
		['y'] = true, ['Y'] = true,	/* yes */
		['n'] = true, ['N'] = true	/* no */
	};

#define IS_TOKEN(_t) (!FR_SBUFF_CANT_EXTEND_LOWAT(in, sizeof(_t) - 1) && \
		      (strncasecmp(in->p, _t, sizeof(_t) - 1) == 0))

	if (fr_sbuff_is_in_charset(in, bool_prefix)) {
		switch (tolower(*in->p)) {
		default:
			break;

		case 't':
			if (IS_TOKEN("true")) {
				*out = true;
				return fr_sbuff_advance(in, sizeof("true") - 1);
			}
			break;

		case 'f':
			if (IS_TOKEN("false")) {
				*out = false;
				return fr_sbuff_advance(in, sizeof("false") - 1);
			}
			break;

		case 'y':
			if (IS_TOKEN("yes")) {
				*out = true;
				return fr_sbuff_advance(in, sizeof("yes") - 1);
			}
			break;

		case 'n':
			if (IS_TOKEN("no")) {
				*out = false;
				return fr_sbuff_advance(in, sizeof("no") - 1);
			}
			break;
		}
	}

	*out = false;	/* Always initialise out */
	return 0;
}

/** Used to define a number parsing functions for singed integers
 *
 * @param[in] _name	Function suffix.
 * @param[in] _type	Output type.
 * @param[in] _min	value.
 * @param[in] _max	value.
 * @param[in] _max_char	Maximum digits that can be used to represent an integer.
 *			Can't use stringify because of width modifiers like 'u'
 *			used in <stdint.h>.
 */
#define SBUFF_PARSE_INT_DEF(_name, _type, _min, _max, _max_char) \
size_t fr_sbuff_out_##_name(fr_sbuff_parse_error_t *err, _type *out, fr_sbuff_t *in, bool no_trailing) \
{ \
	char		buff[_max_char + 1]; \
	char		*end, *a_end; \
	size_t		len; \
	long long	num; \
	fr_sbuff_t	our_in = FR_SBUFF_NO_ADVANCE(in); \
	len = fr_sbuff_out_bstrncpy(&FR_SBUFF_IN(buff, sizeof(buff)), &our_in, _max_char); \
	if (len == 0) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
		return 0; \
	} \
	num = strtoll(buff, &end, 10); \
	if (end == buff) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_TRAILING; \
		return 0; \
	} \
	if ((num > (_max)) || ((errno == EINVAL) && (num == LLONG_MAX))) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NUM_OVERFLOW; \
		*out = (_type)(_max); \
		return 0; \
	} else if (no_trailing && (((a_end = in->p + (end - buff)) + 1) < in->end)) { \
		if (isdigit(*a_end)) { \
			if (err) *err = FR_SBUFF_PARSE_ERROR_TRAILING; \
			*out = (_type)(_max); \
			return 0; \
		} \
		*out = (_type)(num); \
	} else if (num < (_min) || ((errno == EINVAL) && (num == LLONG_MIN))) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NUM_UNDERFLOW; \
		*out = (_type)(_min); \
		return 0; \
	} else { \
		if (err) *err = FR_SBUFF_PARSE_OK; \
		*out = (_type)(num); \
	} \
	return fr_sbuff_advance(in, end - buff); /* Advance by the length strtoll gives us */ \
}

SBUFF_PARSE_INT_DEF(int8, int8_t, INT8_MIN, INT8_MAX, 4)
SBUFF_PARSE_INT_DEF(int16, int16_t, INT16_MIN, INT16_MAX, 6)
SBUFF_PARSE_INT_DEF(int32, int32_t, INT32_MIN, INT32_MAX, 11)
SBUFF_PARSE_INT_DEF(int64, int64_t, INT64_MIN, INT64_MAX, 20)

/** Used to define a number parsing functions for singed integers
 *
 * @param[in] _name	Function suffix.
 * @param[in] _type	Output type.
 * @param[in] _max	value.
 * @param[in] _max_char	Maximum digits that can be used to represent an integer.
 *			Can't use stringify because of width modifiers like 'u'
 *			used in <stdint.h>.
 */
#define SBUFF_PARSE_UINT_DEF(_name, _type, _max, _max_char, _base) \
size_t fr_sbuff_out_##_name(fr_sbuff_parse_error_t *err, _type *out, fr_sbuff_t *in, bool no_trailing) \
{ \
	char			buff[_max_char + 1]; \
	char			*end, *a_end; \
	size_t			len; \
	unsigned long long	num; \
	fr_sbuff_t		our_in = FR_SBUFF_NO_ADVANCE(in); \
	len = fr_sbuff_out_bstrncpy(&FR_SBUFF_IN(buff, sizeof(buff)), &our_in, _max_char); \
	if (len == 0) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
		return 0; \
	} \
	num = strtoull(buff, &end, _base); \
	if (end == buff) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_TRAILING; \
		return 0; \
	} \
	if ((num > (_max)) || ((errno == EINVAL) && (num == ULLONG_MAX))) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NUM_OVERFLOW; \
		*out = (_type)(_max); \
		return 0; \
	} else if (no_trailing && (((a_end = in->p + (end - buff)) + 1) < in->end)) { \
		if (isdigit(*a_end) || ((_base > 10) && ((tolower(*a_end) >= 'a') && (tolower(*a_end) <= 'f')))) { \
			if (err) *err = FR_SBUFF_PARSE_ERROR_TRAILING; \
			*out = (_type)(_max); \
			return 0; \
		} \
		*out = (_type)(num); \
	} else { \
		if (err) *err = FR_SBUFF_PARSE_OK; \
		*out = (_type)(num); \
	} \
	return fr_sbuff_advance(in, end - buff); /* Advance by the length strtoull gives us */ \
}

SBUFF_PARSE_UINT_DEF(uint8, uint8_t, UINT8_MAX, 3, 10)
SBUFF_PARSE_UINT_DEF(uint16, uint16_t, UINT16_MAX, 4, 10)
SBUFF_PARSE_UINT_DEF(uint32, uint32_t, UINT32_MAX, 10, 10)
SBUFF_PARSE_UINT_DEF(uint64, uint64_t, UINT64_MAX, 19, 10)

SBUFF_PARSE_UINT_DEF(uint8_oct, uint8_t, UINT8_MAX, 3, 8)
SBUFF_PARSE_UINT_DEF(uint16_oct, uint16_t, UINT16_MAX, 6, 8)
SBUFF_PARSE_UINT_DEF(uint32_oct, uint32_t, UINT32_MAX, 11, 8)
SBUFF_PARSE_UINT_DEF(uint64_oct, uint64_t, UINT64_MAX, 22, 8)

SBUFF_PARSE_UINT_DEF(uint8_hex, uint8_t, UINT8_MAX, 2, 16)
SBUFF_PARSE_UINT_DEF(uint16_hex, uint16_t, UINT16_MAX, 4, 16)
SBUFF_PARSE_UINT_DEF(uint32_hex, uint32_t, UINT32_MAX, 8, 16)
SBUFF_PARSE_UINT_DEF(uint64_hex, uint64_t, UINT64_MAX, 16, 16)

/** Used to define a number parsing functions for floats
 *
 * @param[in] _name	Function suffix.
 * @param[in] _type	Output type.
 * @param[in] _func	Parsing function to use.
 * @param[in] _max_char	Maximum digits that can be used to represent an integer.
 *			Can't use stringify because of width modifiers like 'u'
 *			used in <stdint.h>.
 */
#define SBUFF_PARSE_FLOAT_DEF(_name, _type, _func, _max_char) \
size_t fr_sbuff_out_##_name(fr_sbuff_parse_error_t *err, _type *out, fr_sbuff_t *in, bool no_trailing) \
{ \
	char		buff[_max_char + 1]; \
	char		*end; \
	fr_sbuff_t	our_in = FR_SBUFF_NO_ADVANCE(in); \
	size_t		len; \
	_type		res; \
	len = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(buff, sizeof(buff)), &our_in, SIZE_MAX, sbuff_char_class_float); \
	if (len == sizeof(buff)) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_TRAILING; \
		return 0; \
	} else if (len == 0) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
		return 0; \
	} \
	res = _func(buff, &end); \
	if (errno == ERANGE) { \
		if (err) *err = res == 0 ? FR_SBUFF_PARSE_ERROR_NUM_UNDERFLOW : FR_SBUFF_PARSE_ERROR_NUM_OVERFLOW; \
		return 0; \
	} \
	if (no_trailing && (*end != '\0')) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_TRAILING; \
		*out = res; \
		return 0; \
	} \
	return fr_sbuff_advance(in, end - buff); \
}

SBUFF_PARSE_FLOAT_DEF(float32, float, strtof, 100);
SBUFF_PARSE_FLOAT_DEF(float64, double, strtod, 100);

/** Copy bytes into the sbuff up to the first \0
 *
 * @param[in] sbuff	to copy into.
 * @param[in] str	to copy into buffer.
 * @return
 *	- >= 0 the number of bytes copied into the sbuff.
 *	- <0 the number of bytes required to complete the copy operation.
 */
ssize_t fr_sbuff_in_strcpy(fr_sbuff_t *sbuff, char const *str)
{
	size_t len;

	CHECK_SBUFF_INIT(sbuff);

	if (unlikely(sbuff->is_const)) return 0;

	len = strlen(str);
	FR_SBUFF_EXTEND_OR_RETURN(sbuff, len);

	safecpy(sbuff->p, sbuff->end, str, str + len);
	sbuff->p[len] = '\0';

	return fr_sbuff_advance(sbuff, len);
}

/** Copy bytes into the sbuff up to the first \0
 *
 * @param[in] sbuff	to copy into.
 * @param[in] str	to copy into buffer.
 * @param[in] len	number of bytes to copy.
 * @return
 *	- >= 0 the number of bytes copied into the sbuff.
 *	- <0 the number of bytes required to complete the copy operation.
 */
ssize_t fr_sbuff_in_bstrncpy(fr_sbuff_t *sbuff, char const *str, size_t len)
{
	CHECK_SBUFF_INIT(sbuff);

	if (unlikely(sbuff->is_const)) return 0;

	FR_SBUFF_EXTEND_OR_RETURN(sbuff, len);

	safecpy(sbuff->p, sbuff->end, str, str + len);
	sbuff->p[len] = '\0';

	return fr_sbuff_advance(sbuff, len);
}

/** Copy bytes into the sbuff up to the first \0
 *
 * @param[in] sbuff	to copy into.
 * @param[in] str	talloced buffer to copy into sbuff.
 * @return
 *	- >= 0 the number of bytes copied into the sbuff.
 *	- <0 the number of bytes required to complete the copy operation.
 */
ssize_t fr_sbuff_in_bstrcpy_buffer(fr_sbuff_t *sbuff, char const *str)
{
	size_t len;

	CHECK_SBUFF_INIT(sbuff);

	if (unlikely(sbuff->is_const)) return 0;

	len = talloc_array_length(str) - 1;

	FR_SBUFF_EXTEND_OR_RETURN(sbuff, len);

	safecpy(sbuff->p, sbuff->end, str, str + len);
	sbuff->p[len] = '\0';

	return fr_sbuff_advance(sbuff, len);
}

/** Free the scratch buffer used for printf
 *
 */
static void _sbuff_scratch_free(void *arg)
{
	talloc_free(arg);
}

static inline CC_HINT(always_inline) int sbuff_scratch_init(TALLOC_CTX **out)
{
	TALLOC_CTX	*scratch;

	scratch = sbuff_scratch;
	if (!scratch) {
		scratch = talloc_pool(NULL, 4096);
		if (unlikely(!scratch)) {
			fr_strerror_printf("Out of Memory");
			return -1;
		}
		fr_thread_local_set_destructor(sbuff_scratch, _sbuff_scratch_free, scratch);
	}

	*out = scratch;

	return 0;
}

/** Print using a fmt string to an sbuff
 *
 * @param[in] sbuff	to print into.
 * @param[in] fmt	string.
 * @param[in] ap	arguments for format string.
 * @return
 *	- >= 0 the number of bytes printed into the sbuff.
 *	- <0 the number of bytes required to complete the print operation.
 */
ssize_t fr_sbuff_in_vsprintf(fr_sbuff_t *sbuff, char const *fmt, va_list ap)
{
	TALLOC_CTX	*scratch;
	va_list		ap_p;
	char		*tmp;
	ssize_t		slen;

	CHECK_SBUFF_INIT(sbuff);

	if (unlikely(sbuff->is_const)) return 0;

	if (sbuff_scratch_init(&scratch) < 0) return 0;

	va_copy(ap_p, ap);
	tmp = fr_vasprintf(scratch, fmt, ap_p);
	va_end(ap_p);
	if (!tmp) return 0;

	slen = fr_sbuff_in_bstrcpy_buffer(sbuff, tmp);
	talloc_free(tmp);	/* Free the temporary buffer */

	return slen;
}

/** Print using a fmt string to an sbuff
 *
 * @param[in] sbuff	to print into.
 * @param[in] fmt	string.
 * @param[in] ...	arguments for format string.
 * @return
 *	- >= 0 the number of bytes printed into the sbuff.
 *	- <0 the number of bytes required to complete the print operation.
 */
ssize_t fr_sbuff_in_sprintf(fr_sbuff_t *sbuff, char const *fmt, ...)
{
	va_list		ap;
	ssize_t		slen;

	if (unlikely(sbuff->is_const)) return 0;

	va_start(ap, fmt);
	slen = fr_sbuff_in_vsprintf(sbuff, fmt, ap);
	va_end(ap);

	return slen;
}

/** Print an escaped string to an sbuff
 *
 * @param[in] sbuff	to print into.
 * @param[in] in	to escape.
 * @param[in] inlen	of string to escape.
 * @param[in] quote	Which quoting character to escape.  Also controls
 *			which characters are escaped.
 * @return
 *	- >= 0 the number of bytes printed into the sbuff.
 *	- <0 the number of bytes required to complete the print operation.
 */
ssize_t fr_sbuff_in_snprint(fr_sbuff_t *sbuff, char const *in, size_t inlen, char quote)
{
	size_t		len;

	CHECK_SBUFF_INIT(sbuff);

	if (unlikely(sbuff->is_const)) return 0;

	len = fr_snprint_len(in, inlen, quote);
	FR_SBUFF_EXTEND_OR_RETURN(sbuff, len);

	len = fr_snprint(fr_sbuff_current(sbuff), fr_sbuff_remaining(sbuff) + 1, in, inlen, quote);
	fr_sbuff_advance(sbuff, len);

	return len;
}

/** Print an escaped string to an sbuff taking a talloced buffer as input
 *
 * @param[in] sbuff	to print into.
 * @param[in] in	to escape.
 * @param[in] quote	Which quoting character to escape.  Also controls
 *			which characters are escaped.
 * @return
 *	- >= 0 the number of bytes printed into the sbuff.
 *	- <0 the number of bytes required to complete the print operation.
 */
ssize_t fr_sbuff_in_snprint_buffer(fr_sbuff_t *sbuff, char const *in, char quote)
{
	if (unlikely(!in)) return 0;

	if (unlikely(sbuff->is_const)) return 0;

	return fr_sbuff_in_snprint(sbuff, in, talloc_array_length(in) - 1, quote);
}

/** Return true and advance past the end of the needle if needle occurs next in the sbuff
 *
 * @param[in] sbuff		to search in.
 * @param[in] needle		to search for.
 * @param[in] needle_len	of needle. If SIZE_MAX strlen is used
 *				to determine length of the needle.
 * @return how many bytes we advanced
 */
size_t fr_sbuff_adv_past_str(fr_sbuff_t *sbuff, char const *needle, size_t needle_len)
{
	char const *found;

	CHECK_SBUFF_INIT(sbuff);

	if (needle_len == SIZE_MAX) needle_len = strlen(needle);

	/*
	 *	If there's insufficient bytes in the
	 *	buffer currently, try to extend it,
	 *	returning if we can't.
	 */
	if (FR_SBUFF_CANT_EXTEND_LOWAT(sbuff, needle_len)) return 0;

	found = memmem(sbuff->p, needle_len, needle, needle_len);	/* sbuff needle_len and needle needle_len ensures match must be next */
	if (!found) return 0;

	return fr_sbuff_advance(sbuff, needle_len);
}

/** Return true and advance past the end of the needle if needle occurs next in the sbuff
 *
 * This function is similar to fr_sbuff_adv_past_str but is case insensitive.
 *
 * @param[in] sbuff		to search in.
 * @param[in] needle		to search for.
 * @param[in] needle_len	of needle. If SIZE_MAX strlen is used
 *				to determine length of the needle.
 * @return how many bytes we advanced
 */
size_t fr_sbuff_adv_past_strcase(fr_sbuff_t *sbuff, char const *needle, size_t needle_len)
{
	char const *p, *n_p;
	char const *end;

	CHECK_SBUFF_INIT(sbuff);

	if (needle_len == SIZE_MAX) needle_len = strlen(needle);

	/*
	 *	If there's insufficient bytes in the
	 *	buffer currently, try to extend it,
	 *	returning if we can't.
	 */
	if (FR_SBUFF_CANT_EXTEND_LOWAT(sbuff, needle_len)) return 0;

	p = sbuff->p;
	end = p + needle_len;

	for (p = sbuff->p, n_p = needle; p < end; p++, n_p++) {
		if (tolower(*p) != tolower(*n_p)) return 0;
	}

	return fr_sbuff_advance(sbuff, needle_len);
}

/** Wind position to the first non-whitespace character
 *
 * @param[in] sbuff		sbuff to search in.
 * @param[in] len		Maximum amount to advance by. Unconstrained if SIZE_MAX.
 * @return how many bytes we advanced.
 */
size_t fr_sbuff_adv_past_whitespace(fr_sbuff_t *sbuff, size_t len)
{
	size_t		total = 0;
	char const	*p;

	CHECK_SBUFF_INIT(sbuff);

	while (total < len) {
		char *end;

		if (FR_SBUFF_CANT_EXTEND(sbuff)) break;

		end = CONSTRAINED_END(sbuff, len, total);
		p = sbuff->p;
		while ((p < end) && isspace(*p)) p++;

		total += fr_sbuff_set(sbuff, p);
		if (p != end) break;		/* stopped early, break */
	}

	return total;
}

/** Wind position past characters in the allowed set
 *
 * @param[in] sbuff		sbuff to search in.
 * @param[in] len		Maximum amount to advance by. Unconstrained if SIZE_MAX.
 * @param[in] allowed		character set.
 * @return how many bytes we advanced.
 */
size_t fr_sbuff_adv_past_allowed(fr_sbuff_t *sbuff, size_t len, bool const allowed[static UINT8_MAX + 1])
{
	size_t		total = 0;
	char const	*p;

	CHECK_SBUFF_INIT(sbuff);

	while (total < len) {
		char *end;

		if (FR_SBUFF_CANT_EXTEND(sbuff)) break;

		end = CONSTRAINED_END(sbuff, len, total);
		p = sbuff->p;
		while ((p < end) && allowed[(uint8_t)*p]) p++;

		total += fr_sbuff_set(sbuff, p);
		if (p != end) break;	/* stopped early, break */
	};

	return total;
}

/** Wind position until we hit a character in the until set
 *
 * @param[in] sbuff		sbuff to search in.
 * @param[in] len		Maximum amount to advance by. Unconstrained if SIZE_MAX.
 * @param[in] tt		Token terminals in the encompassing grammar.
 * @param[in] escape_chr	If not '\0', ignore characters in the until set when
 *				prefixed with this escape character.
 * @return how many bytes we advanced.
 */
size_t fr_sbuff_adv_until(fr_sbuff_t *sbuff, size_t len, fr_sbuff_term_t const *tt, char escape_chr)
{
	size_t		total = 0;
	char const	*p;
	bool		do_escape = false;		/* Track state across extensions */

	uint8_t		idx[UINT8_MAX + 1];		/* Fast path index */
	size_t		needle_len = 1;

	CHECK_SBUFF_INIT(sbuff);

	/*
	 *	Initialise the fastpath index and
	 *	figure out the longest needle.
	 */
	fr_sbuff_terminal_idx_init(&needle_len, idx, tt);

	while (total < len) {
		char *end;

		if (FR_SBUFF_CANT_EXTEND_LOWAT(sbuff, needle_len) && (fr_sbuff_remaining(sbuff) < 1)) break;

		end = CONSTRAINED_END(sbuff, len, total);
		p = sbuff->p;

		if (escape_chr == '\0') {
			while ((p < end) && !fr_sbuff_terminal_search(sbuff, p, idx, tt)) p++;
		} else {
			while (p < end) {
				if (do_escape) {
					do_escape = false;
				} else if (*p == escape_chr) {
					do_escape = true;
				} else if (fr_sbuff_terminal_search(sbuff, p, idx, tt)) {
					break;
				}
				p++;
			}
		}

		total += fr_sbuff_set(sbuff, p);
		if (p != end) break;	/* stopped early, break */
	};

	return total;
}

/** Wind position to first instance of specified multibyte utf8 char
 *
 * Only use this function if the search char could be multibyte,
 * as there's a large performance penalty.
 *
 * @param[in,out] sbuff		to search in.
 * @param[in] chr		to search for.
 * @return
 *	- NULL, no instances found.
 *	- The position of the first character.
 */
char *fr_sbuff_adv_to_chr_utf8(fr_sbuff_t *sbuff, size_t len, char const *chr)
{
	fr_sbuff_t	our_sbuff = FR_SBUFF_NO_ADVANCE(sbuff);
	size_t		total = 0;
	size_t		clen = strlen(chr);

	CHECK_SBUFF_INIT(sbuff);

	/*
	 *	Needle bigger than haystack
	 */
	if (len < clen) return NULL;

	while (total <= (len - clen)) {
		char const	*found;
		char		*end;

		/*
		 *	Ensure we have enough chars to match
		 *	the needle.
		 */
		if (FR_SBUFF_CANT_EXTEND_LOWAT(&our_sbuff, clen)) break;

		end = CONSTRAINED_END(&our_sbuff, len, total);

		found = fr_utf8_strchr(NULL, our_sbuff.p, end - our_sbuff.p, chr);
		if (found) {
			(void)fr_sbuff_set(sbuff, found);
			return sbuff->p;
		}
		total += fr_sbuff_set(&our_sbuff, (end - clen) + 1);
	}

	return NULL;
}

/** Wind position to first instance of specified char
 *
 * @param[in,out] sbuff		to search in.
 * @param[in] len		Maximum amount to advance by. Unconstrained if SIZE_MAX.
 * @param[in] c			to search for.
 * @return
 *	- NULL, no instances found.
 *	- The position of the first character.
 */
char *fr_sbuff_adv_to_chr(fr_sbuff_t *sbuff, size_t len, char c)
{
	fr_sbuff_t	our_sbuff = FR_SBUFF_NO_ADVANCE(sbuff);
	size_t		total = 0;

	CHECK_SBUFF_INIT(sbuff);

	while (total < len) {
		char const	*found;
		char		*end;

		if (FR_SBUFF_CANT_EXTEND(&our_sbuff)) break;

		end = CONSTRAINED_END(sbuff, len, total);
		found = memchr(our_sbuff.p, c, end - our_sbuff.p);
		if (found) {
			(void)fr_sbuff_set(sbuff, found);
			return sbuff->p;
		}

		total += fr_sbuff_set(&our_sbuff, end);
	}

	return NULL;
}

/** Wind position to the first instance of the specified needle
 *
 * @param[in,out] sbuff		sbuff to search in.
 * @param[in] len		Maximum amount to advance by. Unconstrained if SIZE_MAX.
 * @param[in] needle		to search for.
 * @param[in] needle_len	Length of the needle. SIZE_MAX to used strlen.
 * @return
 *	- NULL, no instances found.
 *	- The position of the first character.
 */
char *fr_sbuff_adv_to_str(fr_sbuff_t *sbuff, size_t len, char const *needle, size_t needle_len)
{
	fr_sbuff_t	our_sbuff = FR_SBUFF_NO_ADVANCE(sbuff);
	size_t		total = 0;

	CHECK_SBUFF_INIT(sbuff);

	if (needle_len == SIZE_MAX) needle_len = strlen(needle);
	if (!needle_len) return 0;

	/*
	 *	Needle bigger than haystack
	 */
	if (len < needle_len) return NULL;

	while (total <= (len - needle_len)) {
		char const	*found;
		char		*end;

		if (FR_SBUFF_CANT_EXTEND_LOWAT(&our_sbuff, needle_len)) break;

		end = CONSTRAINED_END(&our_sbuff, len, total);
		found = memmem(our_sbuff.p, end - our_sbuff.p, needle, needle_len);
		if (found) {
			(void)fr_sbuff_set(sbuff, found);
			return sbuff->p;
		}

		/*
		 *	Partial needle may be in
		 *      the end of the buffer so
		 *	don't advance too far.
		 */
		total += fr_sbuff_set(&our_sbuff, (end - needle_len) + 1);
	}

	return NULL;
}

/** Wind position to the first instance of the specified needle
 *
 * @param[in,out] sbuff		sbuff to search in.
 * @param[in] len		Maximum amount to advance by. Unconstrained if SIZE_MAX.
 * @param[in] needle		to search for.
 * @param[in] needle_len	Length of the needle. SIZE_MAX to used strlen.
 * @return
 *	- NULL, no instances found.
 *	- The position of the first character.
 */
char *fr_sbuff_adv_to_strcase(fr_sbuff_t *sbuff, size_t len, char const *needle, size_t needle_len)
{
	fr_sbuff_t	our_sbuff = FR_SBUFF_NO_ADVANCE(sbuff);
	size_t		total = 0;

	CHECK_SBUFF_INIT(sbuff);

	if (needle_len == SIZE_MAX) needle_len = strlen(needle);
	if (!needle_len) return 0;

	/*
	 *	Needle bigger than haystack
	 */
	if (len < needle_len) return NULL;

	while (total <= (len - needle_len)) {
		char *p, *end;
		char const *n_p;

		if (FR_SBUFF_CANT_EXTEND_LOWAT(&our_sbuff, needle_len)) break;

		for (p = our_sbuff.p, n_p = needle, end = our_sbuff.p + needle_len;
		     (p < end) && (tolower(*p) == tolower(*n_p));
		     p++, n_p++);
		if (p == end) {
			(void)fr_sbuff_set(sbuff, our_sbuff.p);
			return sbuff->p;
		}

		total += fr_sbuff_advance(&our_sbuff, 1);
	}

	return NULL;
}

/** Return true if the current char matches, and if it does, advance
 *
 * @param[in] sbuff	to search for char in.
 * @param[in] c		char to search for.
 * @return
 *	- true and avance if the next character matches.
 *	- false and don't advance if the next character doesn't match.
 */
bool fr_sbuff_next_if_char(fr_sbuff_t *sbuff, char c)
{
	CHECK_SBUFF_INIT(sbuff);

	if (FR_SBUFF_CANT_EXTEND(sbuff)) return false;

	if (*sbuff->p != c) return false;

	fr_sbuff_advance(sbuff, 1);

	return true;
}

/** Return true and advance if the next char does not match
 *
 * @param[in] sbuff	to search for char in.
 * @param[in] c		char to search for.
 * @return
 *	- true and avance unless the character matches.
 *	- false and don't advance if the next character matches.
 */
bool fr_sbuff_next_unless_char(fr_sbuff_t *sbuff, char c)
{
	CHECK_SBUFF_INIT(sbuff);

	if (FR_SBUFF_CANT_EXTEND(sbuff)) return false;

	if (*sbuff->p == c) return false;

	fr_sbuff_advance(sbuff, 1);

	return true;
}


/** Efficient terminal string search
 *
 * Caller should ensure that a buffer extension of needle_len bytes has been requested
 * before calling this function.
 *
 * @param[in] in	Sbuff to search in.
 * @param[in] tt	Token terminals in the encompassing grammar.
 * @return
 *      - true if found.
 *	- false if not.
 */
bool fr_sbuff_is_terminal(fr_sbuff_t *in, fr_sbuff_term_t const *tt)
{
	uint8_t		idx[UINT8_MAX + 1];	/* Fast path index */
	size_t		needle_len = 1;

	if (!tt) return false;

	/*
	 *	Initialise the fastpath index and
	 *	figure out the longest needle.
	 */
	fr_sbuff_terminal_idx_init(&needle_len, idx, tt);

	if (FR_SBUFF_CANT_EXTEND_LOWAT(in, needle_len) && (fr_sbuff_remaining(in) < 1)) return false;

	return fr_sbuff_terminal_search(in, in->p, idx, tt);
}
