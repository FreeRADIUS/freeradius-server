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
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/atexit.h>


static _Thread_local char *sbuff_scratch;

/** When true, prevent use of the scratch space
 *
 * This prevents us from initialising a pool after the thread local destructors have run.
 *
 * The destructors may be called manually before thread exit, and we don't want to re-initialise the pool
 */
static _Thread_local bool sbuff_scratch_freed;

static_assert(sizeof(long long) >= sizeof(int64_t), "long long must be as wide or wider than an int64_t");
static_assert(sizeof(unsigned long long) >= sizeof(uint64_t), "long long must be as wide or wider than an uint64_t");

fr_table_num_ordered_t const sbuff_parse_error_table[] = {
	{ L("ok"),			FR_SBUFF_PARSE_OK				},
	{ L("token not found"),		FR_SBUFF_PARSE_ERROR_NOT_FOUND			},
	{ L("trailing data"),		FR_SBUFF_PARSE_ERROR_TRAILING			},
	{ L("token format invalid"),	FR_SBUFF_PARSE_ERROR_FORMAT			},
	{ L("out of space"),		FR_SBUFF_PARSE_ERROR_OUT_OF_SPACE		},
	{ L("integer overflow"),	FR_SBUFF_PARSE_ERROR_NUM_OVERFLOW		},
	{ L("integer underflow"),	FR_SBUFF_PARSE_ERROR_NUM_UNDERFLOW		}
};
size_t sbuff_parse_error_table_len = NUM_ELEMENTS(sbuff_parse_error_table);

#if defined(STATIC_ANALYZER) || !defined(NDEBUG)
#  define CHECK_SBUFF_INIT(_sbuff)	do { if (!(_sbuff)->extend && (unlikely(!(_sbuff)->buff) || unlikely(!(_sbuff)->start) || unlikely(!(_sbuff)->end) || unlikely(!(_sbuff)->p))) return 0; } while (0)
#  define CHECK_SBUFF_WRITEABLE(_sbuff) do { CHECK_SBUFF_INIT(_sbuff); if (unlikely((_sbuff)->is_const)) return 0; } while (0)

#else
#  define CHECK_SBUFF_INIT(_sbuff)
#  define CHECK_SBUFF_WRITEABLE(_sbuff)
#endif

bool const sbuff_char_class_uint[SBUFF_CHAR_CLASS] = {
	SBUFF_CHAR_CLASS_NUM,
	['+'] = true
};

bool const sbuff_char_class_int[SBUFF_CHAR_CLASS] = {
	SBUFF_CHAR_CLASS_NUM,
	['+'] = true, ['-'] = true
};

bool const sbuff_char_class_float[SBUFF_CHAR_CLASS] = {
	SBUFF_CHAR_CLASS_NUM,
	['-'] = true, ['+'] = true, ['e'] = true, ['E'] = true, ['.'] = true,
};

bool const sbuff_char_class_zero[SBUFF_CHAR_CLASS] = {
	['0'] = true
};

/*
 *	Anything which vaguely resembles an IP address, prefix, or host name.
 */
bool const sbuff_char_class_hostname[SBUFF_CHAR_CLASS] = {
	SBUFF_CHAR_CLASS_ALPHA_NUM,
	['.'] = true,		/* only for IPv4 and host names */
	[':'] = true,		/* only for IPv6 numerical addresses */
	['-'] = true,		/* only for host names */
	['/'] = true,		/* only for prefixes */
	['['] = true,		/* only for IPv6 numerical addresses */
	[']'] = true,		/* only for IPv6 numerical addresses */
	['_'] = true,		/* only for certain host name labels */
	['*'] = true,		/* really only for ipv4 addresses */
};

bool const sbuff_char_class_hex[SBUFF_CHAR_CLASS] = { SBUFF_CHAR_CLASS_HEX };
bool const sbuff_char_alpha_num[SBUFF_CHAR_CLASS] = { SBUFF_CHAR_CLASS_ALPHA_NUM };
bool const sbuff_char_word[SBUFF_CHAR_CLASS] = {
	SBUFF_CHAR_CLASS_ALPHA_NUM,
	['-'] = true, ['_'] = true,
};
bool const sbuff_char_whitespace[SBUFF_CHAR_CLASS] = {
	['\t'] = true, ['\n'] = true, ['\r'] = true, ['\f'] = true, ['\v'] = true, [' '] = true,
};

bool const sbuff_char_line_endings[SBUFF_CHAR_CLASS] = {
	['\n'] = true, ['\r'] = true
};

bool const sbuff_char_blank[SBUFF_CHAR_CLASS] = {
	['\t'] = true, [' '] = true,
};

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

static inline CC_HINT(always_inline) size_t min(size_t x, size_t y)
{
	return x < y ? x : y;
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

	old_buff = sbuff->buff;

	/*
	 *	Update pointers to point to positions
	 *	in new buffer based on their relative
	 *	offsets in the old buffer... but not
	 *	past the end of the new buffer.
	 */
	for (sbuff_i = sbuff; sbuff_i; sbuff_i = sbuff_i->parent) {
		fr_sbuff_marker_t	*m_i;

		sbuff_i->buff = new_buff;
		sbuff_i->start = new_buff + min(new_len, sbuff_i->start - old_buff);
		sbuff_i->end = sbuff_i->buff + new_len;
		*(sbuff_i->end) = '\0';	/* Re-terminate */

		sbuff_i->p = new_buff + min(new_len, sbuff_i->p - old_buff);

		for (m_i = sbuff_i->m; m_i; m_i = m_i->next) m_i->p = new_buff + min(new_len, m_i->p - old_buff);
	}
}

/** Shift the contents of the sbuff, returning the number of bytes we managed to shift
 *
 * @param[in] sbuff	to shift.
 * @param[in] shift	the contents of the buffer this many bytes
 *			towards the start of the buffer.
 * @param[in] move_end	If the buffer is used for reading, then this should be true
 *			so we cannot read passed the end of valid data.
 * @return
 *	- 0 the shift failed due to constraining pointers.
 *	- >0 the number of bytes we managed to shift pointers
 *	  in the sbuff.  memmove should be used to move the
 *	  existing contents of the buffer, and fill the free
 *	  space at the end of the buffer with additional data.
 */
size_t fr_sbuff_shift(fr_sbuff_t *sbuff, size_t shift, bool move_end)
{
	fr_sbuff_t		*sbuff_i;
	char			*buff, *end;		/* Current start */
	size_t			max_shift = shift;
	bool			reterminate = false;

	CHECK_SBUFF_INIT(sbuff);

	buff = sbuff->buff;
	end = sbuff->end;

	/*
	 *	If the sbuff is already \0 terminated
	 *	and we're not working on a const buffer
	 *	then assume we need to re-terminate
	 *	later.
	 */
	reterminate = (sbuff->p < sbuff->end) && (*sbuff->p == '\0') && !sbuff->is_const;

	/*
	 *	First pass: find the maximum shift, which is the minimum
	 *	of the distances from buff to any of the current pointers
	 *	or current pointers of markers of dbuff and its ancestors.
	 *	(We're also constrained by the requested shift count.)
	 */
	for (sbuff_i = sbuff; sbuff_i; sbuff_i = sbuff_i->parent) {
		fr_sbuff_marker_t *m_i;

		max_shift = min(max_shift, sbuff_i->p - buff);
		if (!max_shift) return 0;

		for (m_i = sbuff_i->m; m_i; m_i = m_i->next) {
			max_shift = min(max_shift, m_i->p - buff);
			if (!max_shift) return 0;
		}
	}

	/*
	 *	Second pass: adjust pointers.
	 *	The first pass means we need only subtract shift from
	 *	current pointers.  Start pointers can't constrain shift,
	 *	or we'd never free any space, so they require the added
	 *	check.
	 */
	for (sbuff_i = sbuff; sbuff_i; sbuff_i = sbuff_i->parent) {
		fr_sbuff_marker_t	*m_i;
		char			*start = sbuff_i->start;

		sbuff_i->start -= min(max_shift, sbuff_i->start - buff);
		sbuff_i->p -= max_shift;
		if (move_end) sbuff_i->end -= max_shift;
		sbuff_i->shifted += (max_shift - (start - sbuff_i->start));
		for (m_i = sbuff_i->m; m_i; m_i = m_i->next) m_i->p -= max_shift;
	}

	/*
	 *	Only memmove if the shift wasn't the
	 *      entire contents of the buffer.
	 */
	if ((buff + max_shift) < end) memmove(buff, buff + max_shift, end - (buff + max_shift));

	if (reterminate) *sbuff->p = '\0';

	return max_shift;
}

/** Refresh the buffer with more data from the file
 *
 */
size_t fr_sbuff_extend_file(fr_sbuff_extend_status_t *status, fr_sbuff_t *sbuff, size_t extension)
{
	fr_sbuff_t		*sbuff_i;
	size_t			read, available, total_read, shift;
	fr_sbuff_uctx_file_t	*fctx;

	CHECK_SBUFF_INIT(sbuff);

	fctx = sbuff->uctx;
	if (fctx->eof) return 0;

	if (extension == SIZE_MAX) extension = 0;

	total_read = fctx->shifted + (sbuff->end - sbuff->buff);
	if (total_read >= fctx->max) {
		fr_strerror_const("Can't satisfy extension request, max bytes read");
		return 0;	/* There's no way we could satisfy the extension request */
	}

	/*
	 *	Shift out the maximum number of bytes we can
	 *	irrespective of the amount that was requested
	 *	as the extension.  It's more efficient to do
	 *	this than lots of small shifts, and just
	 *	looking and the number of bytes used in the
	 *	deepest sbuff, and using that as the shift
	 *	amount, might mean we don't shift anything at
	 *	all!
	 *
	 *	fr_sbuff_shift will cap the max shift amount,
	 *	so markers and positions will remain valid for
	 *	all sbuffs in the chain.
	 */
	shift = fr_sbuff_current(sbuff) - fr_sbuff_buff(sbuff);
	if (shift) {
		/*
		 *	Try and shift as much as we can out
		 *	of the buffer to make space.
		 *
		 *	Note: p and markers are constraints here.
		 */
		fctx->shifted += fr_sbuff_shift(sbuff, shift, true);
	}

	available = fctx->buff_end - sbuff->end;
	if (available > (fctx->max - total_read)) available = fctx->max - total_read;
	if (available < extension) {
		fr_strerror_printf("Can't satisfy extension request for %zu bytes", extension);
		return 0;	/* There's no way we could satisfy the extension request */
	}

	read = fread(sbuff->end, 1, available, fctx->file);
	for (sbuff_i = sbuff; sbuff_i; sbuff_i = sbuff_i->parent) {
		sbuff_i->end += read;	/* Advance end, which increases fr_sbuff_remaining() */
	}

	/** Check for errors
	 */
	if (read < available) {
		if (!feof(fctx->file)) {	/* It's a real error */
			fr_strerror_printf("Error extending buffer: %s", fr_syserror(ferror(fctx->file)));
			*status |= FR_SBUFF_FLAG_EXTEND_ERROR;
			return 0;
		}

		fctx->eof = true;
	}

	return read;
}

/** Accessor function for the EOF state of the file extendor
 *
 */
bool fr_sbuff_eof_file(fr_sbuff_t *sbuff)
{
	fr_sbuff_uctx_file_t	*fctx = sbuff->uctx;
	return fctx->eof;
}

/** Reallocate the current buffer
 *
 * @param[in] status		Extend status.
 * @param[in] sbuff		to be extended.
 * @param[in] extension		How many additional bytes should be allocated
 *				in the buffer.
 * @return
 *	- 0 the extension operation failed.
 *	- >0 the number of bytes the buffer was extended by.
 */
size_t fr_sbuff_extend_talloc(fr_sbuff_extend_status_t *status, fr_sbuff_t *sbuff, size_t extension)
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
	} else if (elen < clen) {
		elen = clen - 1;		/* Don't double alloc \0 */
	}

	/*
	 *	Check we don't exceed the maximum buffer
	 *	length, including the NUL byte.
	 */
	if (tctx->max && ((clen + elen + 1) > tctx->max)) {
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
		*status |= FR_SBUFF_FLAG_EXTEND_ERROR;
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
		if (unlikely(!new_buff)) {
			fr_strerror_printf("Failed trimming buffer from %zu to %zu", clen, nlen);
			return -1;
		}
		fr_sbuff_update(sbuff, new_buff, nlen - 1);
	}

	return 0;
}

/** Reset a talloced buffer to its initial length, clearing any data stored
 *
 * @param[in] sbuff to reset.
 * @return
 *	- 0 on success.
 *	- -1 on failure - markers present pointing past the end of string data.
 */
int fr_sbuff_reset_talloc(fr_sbuff_t *sbuff)
{
	fr_sbuff_uctx_talloc_t	*tctx = sbuff->uctx;

	CHECK_SBUFF_INIT(sbuff);

	fr_sbuff_set_to_start(sbuff);	/* Clear data */
	sbuff->m = NULL;		/* Remove any maker references */

	if (fr_sbuff_used(sbuff) != tctx->init) {
		char *new_buff;

		new_buff = talloc_realloc(tctx->ctx, sbuff->buff, char, tctx->init);
		if (!new_buff) {
			fr_strerror_printf("Failed reallocing from %zu to %zu",
					   talloc_array_length(sbuff->buff), tctx->init);
			return -1;
		}
		sbuff->buff = new_buff;
		fr_sbuff_update(sbuff, new_buff, tctx->init - 1);
	}

	return 0;
}

/** Fill as much of the output buffer we can and break on partial copy
 *
 * @param[in] _out	sbuff to write to.
 * @param[in] _in	sbuff to copy from.
 * @param[in] _len	maximum amount to copy.
 */
#define FILL_OR_GOTO_DONE(_out, _in, _len) if (fr_sbuff_move(_out, _in, _len) < (size_t)(_len)) goto done

/** Constrain end pointer to prevent advancing more than the amount the caller specified
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
 * @param[out] needle_len	the longest needle.  Will not be set
 *				if the terminal array is empty.
 * @param[out] idx		to populate.
 * @param[in] term		Terminals to populate the index with.
 */
static inline CC_HINT(always_inline) void fr_sbuff_terminal_idx_init(size_t *needle_len,
								     uint8_t idx[static SBUFF_CHAR_CLASS],
								     fr_sbuff_term_t const *term)
{
	size_t i, len, max = 0;

	if (!term) return;

	memset(idx, 0, SBUFF_CHAR_CLASS);

	for (i = 0; i < term->len; i++) {
		len = term->elem[i].len;
		if (len > max) max = len;

		idx[(uint8_t)term->elem[i].str[0]] = i + 1;
	}

	if (i > 0) *needle_len = max;
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
 * @param[in] needle_len	Length of the longest needle.
 * @return
 *      - true if found.
 *	- false if not.
 */
static inline bool fr_sbuff_terminal_search(fr_sbuff_t *in, char const *p,
					    uint8_t idx[static SBUFF_CHAR_CLASS],
					    fr_sbuff_term_t const *term, size_t needle_len)
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

	/*
	 *	Special case for EOFlike states
	 */
	remaining = fr_sbuff_remaining(in);
	if ((remaining == 0) && !fr_sbuff_is_extendable(in)) {
		if (idx['\0'] != 0) return true;
		return false;
	}

	if (remaining < needle_len) {
		fr_assert_msg(!fr_sbuff_is_extendable(in),
			      "Caller failed to extend buffer by %zu bytes before calling fr_sbuff_terminal_search",
			      needle_len);
		/*
		 *	We can't search for the needle if we don't have
		 *	enough data to match it.
		 */
		return false;
	}

	mid = term_idx - 1;				/* Inform the mid point from the index */

	while (start <= end) {
		fr_sbuff_term_elem_t const 	*elem;
		size_t				tlen;
		int				ret;

		elem = &term->elem[mid];
		tlen = elem->len;

		ret = memcmp(p, elem->str, tlen < (size_t)remaining ? tlen : (size_t)remaining);
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
 * @param[in] a      	first terminal to compare.
 * @param[in] b		second terminal to compare.
 * @return CMP(a,b)
 */
static inline int8_t terminal_cmp(fr_sbuff_term_elem_t const *a, fr_sbuff_term_elem_t const *b)
{
	MEMCMP_RETURN(a, b, str, len);
	return 0;
}

#if 0
static void fr_sbuff_terminal_debug_tmp(fr_sbuff_term_elem_t const *elem[], size_t len)
{
	size_t i;

	FR_FAULT_LOG("Terminal count %zu", len);

	for (i = 0; i < len; i++) FR_FAULT_LOG("\t\"%s\" (%zu)", elem[i] ? elem[i]->str : "NULL", elem[i] ? elem[i]->len : 0);
}
#endif

/** Merge two sets of terminal strings
 *
 * @param[in] ctx	to allocate the new terminal array in.
 * @param[in] a		first set of terminals to merge.
 * @param[in] b		second set of terminals to merge.
 * @return A new set of de-duplicated and sorted terminals.
 */
fr_sbuff_term_t *fr_sbuff_terminals_amerge(TALLOC_CTX *ctx, fr_sbuff_term_t const *a, fr_sbuff_term_t const *b)
{
	size_t				i, j, num;
	fr_sbuff_term_t			*out;
	fr_sbuff_term_elem_t const	*tmp[SBUFF_CHAR_CLASS];

	/*
	 *	Check all inputs are pre-sorted.  It doesn't break this
	 *	function, but it's useful in case the terminal arrays
	 *	are defined elsewhere without merging.
	 */
#if !defined(NDEBUG) && defined(WITH_VERIFY_PTR)
	for (i = 0; i < a->len - 1; i++) fr_assert(terminal_cmp(&a->elem[i], &a->elem[i + 1]) < 0);
	for (i = 0; i < b->len - 1; i++) fr_assert(terminal_cmp(&b->elem[i], &b->elem[i + 1]) < 0);
#endif

	/*
	 *	Since the inputs are sorted, we can just do an O(n+m)
	 *	walk through the arrays, comparing entries across the
	 *	two arrays.
	 *
	 *	If there are duplicates, we prefer "a", for no particular reason.
	 */
	num = i = j = 0;
	while ((i < a->len) && (j < b->len)) {
		int8_t cmp;

		cmp = terminal_cmp(&a->elem[i], &b->elem[j]);
		if (cmp == 0) {
			j++;
			tmp[num++] = &a->elem[i++];

		} else if (cmp < 0) {
			tmp[num++] = &a->elem[i++];

		} else if (cmp > 0) {
			tmp[num++] = &b->elem[j++];
		}

		fr_assert(num <= UINT8_MAX);
	}

	/*
	 *	Only one of these will be hit, and it's simpler than nested "if" statements.
	 */
	while (i < a->len) tmp[num++] = &a->elem[i++];
	while (j < b->len) tmp[num++] = &b->elem[j++];

	out = talloc_pooled_object(ctx, fr_sbuff_term_t, num, num * sizeof(fr_sbuff_term_elem_t));
	if (unlikely(!out)) return NULL;

	out->elem = talloc_array(out, fr_sbuff_term_elem_t, num);
	if (unlikely(!out->elem)) {
		talloc_free(out);
		return NULL;
	}
	out->len = num;

	for (i = 0; i < num; i++) out->elem[i] = *tmp[i]; /* copy merged results back */

#if !defined(NDEBUG) && defined(WITH_VERIFY_PTR)
	for (i = 0; i < num - 1; i++) fr_assert(terminal_cmp(&out->elem[i], &out->elem[i + 1]) < 0);
#endif

	return out;
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
	fr_sbuff_t 	our_in = FR_SBUFF_BIND_CURRENT(in);
	size_t		remaining;

	CHECK_SBUFF_INIT(in);

	while (fr_sbuff_used_total(&our_in) < len) {
		size_t chunk_len;

		remaining = (len - fr_sbuff_used_total(&our_in));

		if (!fr_sbuff_extend(&our_in)) break;

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
	fr_sbuff_t 		our_in = FR_SBUFF(in);
	size_t			remaining;
	fr_sbuff_marker_t	m;

	CHECK_SBUFF_INIT(in);

	fr_sbuff_marker(&m, out);

	do {
		size_t chunk_len;
		ssize_t copied;

		remaining = (len - fr_sbuff_used_total(&our_in));
		if (remaining && !fr_sbuff_extend(&our_in)) {
			fr_sbuff_marker_release(&m);
			return 0;
		}

		chunk_len = fr_sbuff_remaining(&our_in);
		if (chunk_len > remaining) chunk_len = remaining;

		copied = fr_sbuff_in_bstrncpy(out, our_in.p, chunk_len);
		if (copied < 0) {
			fr_sbuff_set(out, &m);		/* Reset out */
			*m.p = '\0';			/* Re-terminate */

			/* Amount remaining in input buffer minus the amount we could have copied */
			if (len == SIZE_MAX) return -(fr_sbuff_remaining(in) - (chunk_len + copied));
			/* Amount remaining to copy minus the amount we could have copied */
			fr_sbuff_marker_release(&m);
			return -(remaining - (chunk_len + copied));
		}
		fr_sbuff_advance(&our_in, copied);
	} while (fr_sbuff_used_total(&our_in) < len);

	FR_SBUFF_SET_RETURN(in, &our_in);	/* in was pinned, so this works */
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
				     bool const allowed[static SBUFF_CHAR_CLASS])
{
	fr_sbuff_t 	our_in = FR_SBUFF_BIND_CURRENT(in);

	CHECK_SBUFF_INIT(in);

	while (fr_sbuff_used_total(&our_in) < len) {
		char	*p;
		char	*end;

		if (!fr_sbuff_extend(&our_in)) break;

		p = fr_sbuff_current(&our_in);
		end = CONSTRAINED_END(&our_in, len, fr_sbuff_used_total(&our_in));

		while ((p < end) && allowed[(uint8_t)*p]) p++;

		FILL_OR_GOTO_DONE(out, &our_in, p - our_in.p);

		if (p != end) break;		/* stopped early, break */
	}

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
 * @param[in] u_rules		If not NULL, ignore characters in the until set when
 *				prefixed with u_rules->chr. FIXME - Should actually evaluate
 *				u_rules fully.
 * @return
 *	- 0 no bytes copied.
 *	- >0 the number of bytes copied.
 */
size_t fr_sbuff_out_bstrncpy_until(fr_sbuff_t *out, fr_sbuff_t *in, size_t len,
				   fr_sbuff_term_t const *tt,
				   fr_sbuff_unescape_rules_t const *u_rules)
{
	fr_sbuff_t 	our_in = FR_SBUFF_BIND_CURRENT(in);
	bool		do_escape = false;		/* Track state across extensions */

	uint8_t		idx[SBUFF_CHAR_CLASS];		/* Fast path index */
	size_t		needle_len = 1;
	char		escape_chr = u_rules ? u_rules->chr : '\0';

	CHECK_SBUFF_INIT(in);

	/*
	 *	Initialise the fastpath index and
	 *	figure out the longest needle.
	 */
	fr_sbuff_terminal_idx_init(&needle_len, idx, tt);

	while (fr_sbuff_used_total(&our_in) < len) {
		char	*p;
		char	*end;

		if (fr_sbuff_extend_lowat(NULL, &our_in, needle_len) == 0) break;

		p = fr_sbuff_current(&our_in);
		end = CONSTRAINED_END(&our_in, len, fr_sbuff_used_total(&our_in));

		if (p == end) break;

		if (escape_chr == '\0') {
			while ((p < end) && !fr_sbuff_terminal_search(in, p, idx, tt, needle_len)) p++;
		} else {
			while (p < end) {
				if (do_escape) {
					do_escape = false;
				} else if (*p == escape_chr) {
					do_escape = true;
				} else if (fr_sbuff_terminal_search(in, p, idx, tt, needle_len)) {
					break;
				}
				p++;
			}
		}

		FILL_OR_GOTO_DONE(out, &our_in, p - our_in.p);

		if (p != end) break;		/* stopped early, break */
	}

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
 * @param[in] u_rules		for processing unescape sequences.
 * @return
 *	- 0 no bytes copied.
 *	- >0 the number of bytes written to out.
 */
size_t fr_sbuff_out_unescape_until(fr_sbuff_t *out, fr_sbuff_t *in, size_t len,
				   fr_sbuff_term_t const *tt,
				   fr_sbuff_unescape_rules_t const *u_rules)
{
	fr_sbuff_t 			our_in;
	bool				do_escape = false;			/* Track state across extensions */
	fr_sbuff_marker_t		o_s;
	fr_sbuff_marker_t		c_s;
	fr_sbuff_marker_t		end;

	uint8_t				idx[SBUFF_CHAR_CLASS];			/* Fast path index */
	size_t				needle_len = 1;
	fr_sbuff_extend_status_t	status = 0;

	/*
	 *	If we don't need to do unescaping
	 *	call a more suitable function.
	 */
	if (!u_rules || (u_rules->chr == '\0')) return fr_sbuff_out_bstrncpy_until(out, in, len, tt, u_rules);

	CHECK_SBUFF_INIT(in);

	our_in = FR_SBUFF(in);

	/*
	 *	Chunk tracking...
	 */
	fr_sbuff_marker(&c_s, &our_in);
	fr_sbuff_marker(&end, &our_in);
	fr_sbuff_marker_update_end(&end, len);

	fr_sbuff_marker(&o_s, out);

	/*
	 *	Initialise the fastpath index and
	 *	figure out the longest needle.
	 */
	fr_sbuff_terminal_idx_init(&needle_len, idx, tt);

	/*
	 *	...while we have remaining data
	 */
	while (fr_sbuff_extend_lowat(&status, &our_in, needle_len) > 0) {
		if (fr_sbuff_was_extended(status)) fr_sbuff_marker_update_end(&end, len);
		if (!fr_sbuff_diff(&our_in, &end)) break;	/* Reached the end */

		if (do_escape) {
			do_escape = false;

			/*
			 *	Check for \x<hex><hex>
			 */
			if (u_rules->do_hex && fr_sbuff_is_char(&our_in, 'x')) {
				uint8_t			escape;
				fr_sbuff_marker_t	m;

				fr_sbuff_marker(&m, &our_in);		/* allow for backtrack */
				fr_sbuff_advance(&our_in, 1);		/* skip over the 'x' */

				if (fr_sbuff_out_uint8_hex(NULL, &escape, &our_in, false) != 2) {
					fr_sbuff_set(&our_in, &m);	/* backtrack */
					fr_sbuff_marker_release(&m);
					goto check_subs;		/* allow sub for \x */
				}

				if (fr_sbuff_in_char(out, escape) <= 0) {
					fr_sbuff_set(&our_in, &m);	/* backtrack */
					fr_sbuff_marker_release(&m);
					break;
				}
				fr_sbuff_marker_release(&m);
				fr_sbuff_set(&c_s, &our_in);
				continue;
			}

			/*
			 *	Check for \<oct><oct><oct>
			 */
			if (u_rules->do_oct && fr_sbuff_is_digit(&our_in)) {
				uint8_t 		escape;
				fr_sbuff_marker_t	m;

				fr_sbuff_marker(&m, &our_in);		/* allow for backtrack */

				if (fr_sbuff_out_uint8_oct(NULL, &escape, &our_in, false) != 3) {
					fr_sbuff_set(&our_in, &m);	/* backtrack */
					fr_sbuff_marker_release(&m);
					goto check_subs;		/* allow sub for \<oct> */
				}

				if (fr_sbuff_in_char(out, escape) <= 0) {
					fr_sbuff_set(&our_in, &m);	/* backtrack */
					fr_sbuff_marker_release(&m);
					break;
				}
				fr_sbuff_marker_release(&m);
				fr_sbuff_set(&c_s, &our_in);
				continue;
			}

		check_subs:
			/*
			 *	Not a recognised hex or octal escape sequence
			 *	may be a substitution or a sequence that
			 *	should be copied to the output buffer.
			 */
			{
				uint8_t c = *fr_sbuff_current(&our_in);

				if (u_rules->subs[c] == '\0') {
					if (u_rules->skip[c] == true) goto next;
					goto next_esc;
				}

				/*
				 *  	We already copied everything up
				 *	to this point, so we can now
				 *	write the substituted char to
				 *	the output buffer.
				 */
				if (fr_sbuff_in_char(out, u_rules->subs[c]) <= 0) break;

				/*
				 *	...and advance past the entire
				 *	escape seq in the input buffer.
				 */
				fr_sbuff_advance(&our_in, 1);
				fr_sbuff_set(&c_s, &our_in);
				continue;
			}
		}

	next_esc:
		if (*fr_sbuff_current(&our_in) == u_rules->chr) {
			/*
			 *	Copy out any data we got before
			 *	we hit the escape char.
			 *
			 *	We need to do this before we
			 *	can write the escape char to
			 *	the output sbuff.
			 */
			FILL_OR_GOTO_DONE(out, &c_s, fr_sbuff_behind(&c_s));

			do_escape = true;
			fr_sbuff_advance(&our_in, 1);
			continue;
		}

	next:
		if (tt && fr_sbuff_terminal_search(&our_in, fr_sbuff_current(&our_in), idx, tt, needle_len)) break;
		fr_sbuff_advance(&our_in, 1);
	}

	/*
	 *	Copy any remaining data over
	 */
	FILL_OR_GOTO_DONE(out, &c_s, fr_sbuff_behind(&c_s));

done:
	fr_sbuff_set(in, &c_s);	/* Only advance by as much as we copied */
	*out->p = '\0';

	return fr_sbuff_marker_release_behind(&o_s);
}

/** See if the string contains a truth value
 *
 * @param[out] out	Where to write boolean value.
 * @param[in] in	Where to search for a truth value.
 * @return
 *	- >0 the number of bytes consumed.
 *	- -1 no bytes copied, was not a truth value.
 */
fr_slen_t fr_sbuff_out_bool(bool *out, fr_sbuff_t *in)
{
	fr_sbuff_t our_in = FR_SBUFF(in);

	static bool const bool_prefix[SBUFF_CHAR_CLASS] = {
		['t'] = true, ['T'] = true,	/* true */
		['f'] = true, ['F'] = true,	/* false */
		['y'] = true, ['Y'] = true,	/* yes */
		['n'] = true, ['N'] = true,	/* no */
	};

	if (fr_sbuff_is_in_charset(&our_in, bool_prefix)) {
		switch (tolower(fr_sbuff_char(&our_in, '\0'))) {
		default:
			break;

		case 't':
			if (fr_sbuff_adv_past_strcase_literal(&our_in, "true")) {
				*out = true;
				FR_SBUFF_SET_RETURN(in, &our_in);
			}
			break;

		case 'f':
			if (fr_sbuff_adv_past_strcase_literal(&our_in, "false")) {
				*out = false;
				FR_SBUFF_SET_RETURN(in, &our_in);
			}
			break;

		case 'y':
			if (fr_sbuff_adv_past_strcase_literal(&our_in, "yes")) {
				*out = true;
				FR_SBUFF_SET_RETURN(in, &our_in);
			}
			break;

		case 'n':
			if (fr_sbuff_adv_past_strcase_literal(&our_in, "no")) {
				*out = false;
				FR_SBUFF_SET_RETURN(in, &our_in);
			}
			break;
		}
	}

	*out = false;	/* Always initialise out */

	fr_strerror_const("Not a valid boolean value.  Accepted values are 'yes', 'no', 'true', 'false'");

	return -1;
}

/** Used to define a number parsing functions for signed integers
 *
 * @param[in] _name	Function suffix.
 * @param[in] _type	Output type.
 * @param[in] _min	value.
 * @param[in] _max	value.
 * @param[in] _max_char	Maximum digits that can be used to represent an integer.
 *			Can't use stringify because of width modifiers like 'u'
 *			used in <stdint.h>.
 * @param[in] _base	to use.
 */
#define SBUFF_PARSE_INT_DEF(_name, _type, _min, _max, _max_char, _base) \
fr_slen_t fr_sbuff_out_##_name(fr_sbuff_parse_error_t *err, _type *out, fr_sbuff_t *in, bool no_trailing) \
{ \
	char		buff[_max_char + 1]; \
	char		*end, *a_end; \
	size_t		len; \
	long long	num; \
	_type		cast_num; \
	fr_sbuff_t	our_in = FR_SBUFF(in); \
	buff[0] = '\0'; /* clang scan */ \
	len = fr_sbuff_out_bstrncpy(&FR_SBUFF_IN(buff, sizeof(buff)), &our_in, _max_char); \
	if (len == 0) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
		return -1; \
	} \
	errno = 0; /* this is needed as strtoll doesn't reset errno */ \
	num = strtoll(buff, &end, _base); \
	cast_num = (_type)(num); \
	if (end == buff) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
		return -1; \
	} \
	if (num > cast_num) { \
	overflow: \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NUM_OVERFLOW; \
		*out = (_type)(_max); \
		return -1; \
	} \
	if (((errno == EINVAL) && (num == 0)) || ((errno == ERANGE) && (num == LLONG_MAX))) goto overflow; \
	if (num < cast_num) { \
	underflow: \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NUM_UNDERFLOW; \
		*out = (_type)(_min); \
		return -1; \
	} \
	if ((errno == ERANGE) && (num == LLONG_MIN)) goto underflow; \
	if (no_trailing && (((a_end = in->p + (end - buff)) + 1) < in->end)) { \
		if (isdigit((uint8_t) *a_end) || (((_base > 10) || ((_base == 0) && (len > 2) && (buff[0] == '0') && (buff[1] == 'x'))) && \
		    ((tolower((uint8_t) *a_end) >= 'a') && (tolower((uint8_t) *a_end) <= 'f')))) { \
			if (err) *err = FR_SBUFF_PARSE_ERROR_TRAILING; \
			*out = (_type)(_max); \
			FR_SBUFF_ERROR_RETURN(&our_in); \
		} \
		*out = cast_num; \
	} else { \
		if (err) *err = FR_SBUFF_PARSE_OK; \
		*out = cast_num; \
	} \
	return fr_sbuff_advance(in, end - buff); /* Advance by the length strtoll gives us */ \
}

SBUFF_PARSE_INT_DEF(int8, int8_t, INT8_MIN, INT8_MAX, 4, 0)
SBUFF_PARSE_INT_DEF(int16, int16_t, INT16_MIN, INT16_MAX, 6, 0)
SBUFF_PARSE_INT_DEF(int32, int32_t, INT32_MIN, INT32_MAX, 11, 0)
SBUFF_PARSE_INT_DEF(int64, int64_t, INT64_MIN, INT64_MAX, 20, 0)
SBUFF_PARSE_INT_DEF(ssize, ssize_t, SSIZE_MIN, SSIZE_MAX, 20, 0)

/** Used to define a number parsing functions for signed integers
 *
 * @param[in] _name	Function suffix.
 * @param[in] _type	Output type.
 * @param[in] _max	value.
 * @param[in] _max_char	Maximum digits that can be used to represent an integer.
 *			Can't use stringify because of width modifiers like 'u'
 *			used in <stdint.h>.
 * @param[in] _base	of the number being parsed, 8, 10, 16 etc...
 */
#define SBUFF_PARSE_UINT_DEF(_name, _type, _max, _max_char, _base) \
fr_slen_t fr_sbuff_out_##_name(fr_sbuff_parse_error_t *err, _type *out, fr_sbuff_t *in, bool no_trailing) \
{ \
	char			buff[_max_char + 1]; \
	char			*end, *a_end; \
	size_t			len; \
	unsigned long long	num; \
	_type			cast_num; \
	fr_sbuff_t		our_in = FR_SBUFF(in); \
	buff[0] = '\0'; /* clang scan */ \
	len = fr_sbuff_out_bstrncpy(&FR_SBUFF_IN(buff, sizeof(buff)), &our_in, _max_char); \
	if (len == 0) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
		return -1; \
	} \
	if (buff[0] == '-') { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NUM_UNDERFLOW; \
		return -1; \
	} \
	errno = 0; /* this is needed as strtoull doesn't reset errno */ \
	num = strtoull(buff, &end, _base); \
	cast_num = (_type)(num); \
	if (end == buff) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
		return -1; \
	} \
	if (num > cast_num) { \
	overflow: \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NUM_OVERFLOW; \
		*out = (_type)(_max); \
		return -1; \
	} \
	if (((errno == EINVAL) && (num == 0)) || ((errno == ERANGE) && (num == ULLONG_MAX))) goto overflow; \
	if (no_trailing && (((a_end = in->p + (end - buff)) + 1) < in->end)) { \
		if (isdigit((uint8_t) *a_end) || (((_base > 10) || ((_base == 0) && (len > 2) && (buff[0] == '0') && (buff[1] == 'x'))) && \
		    ((tolower((uint8_t) *a_end) >= 'a') && (tolower((uint8_t) *a_end) <= 'f')))) { \
			if (err) *err = FR_SBUFF_PARSE_ERROR_TRAILING; \
			*out = (_type)(_max); \
			FR_SBUFF_ERROR_RETURN(&our_in); \
		} \
		if (err) *err = FR_SBUFF_PARSE_OK; \
		*out = cast_num; \
	} else { \
		if (err) *err = FR_SBUFF_PARSE_OK; \
		*out = cast_num; \
	} \
	return fr_sbuff_advance(in, end - buff); /* Advance by the length strtoull gives us */ \
}

/* max chars here is the octal string value with prefix */
SBUFF_PARSE_UINT_DEF(uint8, uint8_t, UINT8_MAX, 4, 0)
SBUFF_PARSE_UINT_DEF(uint16, uint16_t, UINT16_MAX, 7, 0)
SBUFF_PARSE_UINT_DEF(uint32, uint32_t, UINT32_MAX, 12, 0)
SBUFF_PARSE_UINT_DEF(uint64, uint64_t, UINT64_MAX, 23, 0)
SBUFF_PARSE_UINT_DEF(size, size_t, SIZE_MAX, 23, 0)

SBUFF_PARSE_UINT_DEF(uint8_dec, uint8_t, UINT8_MAX, 3, 0)
SBUFF_PARSE_UINT_DEF(uint16_dec, uint16_t, UINT16_MAX, 4, 0)
SBUFF_PARSE_UINT_DEF(uint32_dec, uint32_t, UINT32_MAX, 10, 0)
SBUFF_PARSE_UINT_DEF(uint64_dec, uint64_t, UINT64_MAX, 19, 0)
SBUFF_PARSE_UINT_DEF(size_dec, size_t, SIZE_MAX, 19, 0)


SBUFF_PARSE_UINT_DEF(uint8_oct, uint8_t, UINT8_MAX, 3, 8)
SBUFF_PARSE_UINT_DEF(uint16_oct, uint16_t, UINT16_MAX, 6, 8)
SBUFF_PARSE_UINT_DEF(uint32_oct, uint32_t, UINT32_MAX, 11, 8)
SBUFF_PARSE_UINT_DEF(uint64_oct, uint64_t, UINT64_MAX, 22, 8)
SBUFF_PARSE_UINT_DEF(size_oct, size_t, SIZE_MAX, 22, 8)

SBUFF_PARSE_UINT_DEF(uint8_hex, uint8_t, UINT8_MAX, 2, 16)
SBUFF_PARSE_UINT_DEF(uint16_hex, uint16_t, UINT16_MAX, 4, 16)
SBUFF_PARSE_UINT_DEF(uint32_hex, uint32_t, UINT32_MAX, 8, 16)
SBUFF_PARSE_UINT_DEF(uint64_hex, uint64_t, UINT64_MAX, 16, 16)
SBUFF_PARSE_UINT_DEF(size_hex, size_t, SIZE_MAX, 22, 16)

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
fr_slen_t fr_sbuff_out_##_name(fr_sbuff_parse_error_t *err, _type *out, fr_sbuff_t *in, bool no_trailing) \
{ \
	char		buff[_max_char + 1] = ""; \
	char		*end; \
	fr_sbuff_t	our_in = FR_SBUFF(in); \
	size_t		len; \
	_type		res; \
	len = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(buff, sizeof(buff)), &our_in, SIZE_MAX, sbuff_char_class_float); \
	if (len == sizeof(buff)) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
		return -1; \
	} else if (len == 0) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_NOT_FOUND; \
		return -1; \
	} \
	errno = 0; /* this is needed as parsing functions don't reset errno */ \
	res = _func(buff, &end); \
	if (errno == ERANGE) { \
		if (res > 0) { \
			if (err) *err = FR_SBUFF_PARSE_ERROR_NUM_OVERFLOW; \
		} else { \
			if (err) *err = FR_SBUFF_PARSE_ERROR_NUM_UNDERFLOW; \
		} \
		return -1; \
	} \
	if (no_trailing && (*end != '\0')) { \
		if (err) *err = FR_SBUFF_PARSE_ERROR_TRAILING; \
		FR_SBUFF_ERROR_RETURN(&our_in); \
	} \
	*out = res; \
	return fr_sbuff_advance(in, end - buff); \
}

SBUFF_PARSE_FLOAT_DEF(float32, float, strtof, 100)
SBUFF_PARSE_FLOAT_DEF(float64, double, strtod, 100)

/** Move data from one sbuff to another
 *
 * @note Do not call this function directly use #fr_sbuff_move
 *
 * Both in and out will be advanced by len, with len set to the shortest
 * value between the user specified value, the number of bytes remaining
 * in the input buffer (after extension), and the number of bytes remaining
 * in the output buffer (after extension).
 *
 * @param[in] out	sbuff to copy data to.
 * @param[in] in	sbuff to copy data from.
 * @param[in] len	Maximum length of string to copy.
 * @return The amount of data copied.
 */
size_t _fr_sbuff_move_sbuff_to_sbuff(fr_sbuff_t *out, fr_sbuff_t *in, size_t len)
{
	size_t o_remaining = fr_sbuff_extend_lowat(NULL, out, len);
	size_t i_remaining = fr_sbuff_extend_lowat(NULL, in, len);
	size_t to_copy = len;
	if (to_copy > o_remaining) to_copy = o_remaining;
	if (to_copy > i_remaining) to_copy = i_remaining;
	safecpy(fr_sbuff_current(out), fr_sbuff_end(out), fr_sbuff_current(in), fr_sbuff_current(in) + to_copy);
	return fr_sbuff_advance(out, fr_sbuff_advance(in, to_copy));
}

/** Move data from a marker to an sbuff
 *
 * @note Do not call this function directly use #fr_sbuff_move
 *
 * @param[in] out	sbuff to copy data to.
 * @param[in] in	marker to copy data from.
 * @param[in] len	Maximum length of string to copy.
 * @return The amount of data copied.
 */
size_t _fr_sbuff_move_marker_to_sbuff(fr_sbuff_t *out, fr_sbuff_marker_t *in, size_t len)
{
	size_t o_remaining = fr_sbuff_extend_lowat(NULL, out, len);
	size_t i_remaining = fr_sbuff_extend_lowat(NULL, in, len);
	size_t to_copy = len;
	if (to_copy > o_remaining) to_copy = o_remaining;
	if (to_copy > i_remaining) to_copy = i_remaining;
	safecpy(fr_sbuff_current(out), fr_sbuff_end(out), fr_sbuff_current(in), fr_sbuff_current(in) + to_copy);
	return fr_sbuff_advance(out, fr_sbuff_advance(in, to_copy));
}

/** Move data from one marker to another
 *
 * @note Do not call this function directly use #fr_sbuff_move
 *
 * @param[in] out	marker to copy data to.
 * @param[in] in	marker to copy data from.
 * @param[in] len	Maximum length of string to copy.
 * @return The amount of data copied.
 */
size_t _fr_sbuff_move_marker_to_marker(fr_sbuff_marker_t *out, fr_sbuff_marker_t *in, size_t len)
{
	size_t o_remaining = fr_sbuff_extend_lowat(NULL, out, len);
	size_t i_remaining = fr_sbuff_extend_lowat(NULL, in, len);
	size_t to_copy = len;
	if (to_copy > o_remaining) to_copy = o_remaining;
	if (to_copy > i_remaining) to_copy = i_remaining;
	safecpy(fr_sbuff_current(out), fr_sbuff_end(out), fr_sbuff_current(in), fr_sbuff_current(in) + to_copy);
	return fr_sbuff_advance(out, fr_sbuff_advance(in, to_copy));
}

/** Move data from an sbuff to a marker
 *
 * @note Do not call this function directly use #fr_sbuff_move
 *
 * @param[in] out	marker to copy data to.
 * @param[in] in	sbuff to copy data from.
 * @param[in] len	Maximum length of string to copy.
 * @return The amount of data copied.
 */
size_t _fr_sbuff_move_sbuff_to_marker(fr_sbuff_marker_t *out, fr_sbuff_t *in, size_t len)
{
	size_t o_remaining = fr_sbuff_extend_lowat(NULL, out, len);
	size_t i_remaining = fr_sbuff_extend_lowat(NULL, in, len);
	size_t to_copy = len;
	if (to_copy > o_remaining) to_copy = o_remaining;
	if (to_copy > i_remaining) to_copy = i_remaining;
	safecpy(fr_sbuff_current(out), fr_sbuff_end(out), fr_sbuff_current(in), fr_sbuff_current(in) + to_copy);
	return fr_sbuff_advance(out, fr_sbuff_advance(in, to_copy));
}

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

	CHECK_SBUFF_WRITEABLE(sbuff);

	len = strlen(str);
	FR_SBUFF_EXTEND_LOWAT_OR_RETURN(sbuff, len);

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
	CHECK_SBUFF_WRITEABLE(sbuff);

	FR_SBUFF_EXTEND_LOWAT_OR_RETURN(sbuff, len);

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

	CHECK_SBUFF_WRITEABLE(sbuff);

	len = talloc_array_length(str) - 1;

	FR_SBUFF_EXTEND_LOWAT_OR_RETURN(sbuff, len);

	safecpy(sbuff->p, sbuff->end, str, str + len);
	sbuff->p[len] = '\0';

	return fr_sbuff_advance(sbuff, len);
}

/** Free the scratch buffer used for printf
 *
 */
static int _sbuff_scratch_free(void *arg)
{
	sbuff_scratch_freed = true;
	return talloc_free(arg);
}

static inline CC_HINT(always_inline) int sbuff_scratch_init(TALLOC_CTX **out)
{
	TALLOC_CTX	*scratch;

	if (sbuff_scratch_freed) {
		*out = NULL;
		return 0;
	}

	scratch = sbuff_scratch;
	if (!scratch) {
		scratch = talloc_pool(NULL, 4096);
		if (unlikely(!scratch)) {
			fr_strerror_const("Out of Memory");
			return -1;
		}
		fr_atexit_thread_local(sbuff_scratch, _sbuff_scratch_free, scratch);
	}

	*out = scratch;

	return 0;
}

/** Print using a fmt string to an sbuff
 *
 * @param[in] sbuff	to print into.
 * @param[in] fmt	string.
 * @param[in] ap	arguments for format string.
< * @return
 *	- >= 0 the number of bytes printed into the sbuff.
 *	- <0 the number of bytes required to complete the print operation.
 */
ssize_t fr_sbuff_in_vsprintf(fr_sbuff_t *sbuff, char const *fmt, va_list ap)
{
	TALLOC_CTX	*scratch;
	va_list		ap_p;
	char		*tmp;
	ssize_t		slen;

	CHECK_SBUFF_WRITEABLE(sbuff);

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

	CHECK_SBUFF_WRITEABLE(sbuff);

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
 * @param[in] e_rules	Escaping rules.  Used to escape special characters
 *      		as data is written to the sbuff.  May be NULL.
 * @return
 *	- >= 0 the number of bytes printed into the sbuff.
 *	- <0 the number of bytes required to complete the print operation.
 */
ssize_t fr_sbuff_in_escape(fr_sbuff_t *sbuff, char const *in, size_t inlen, fr_sbuff_escape_rules_t const *e_rules)
{
	char const	*end = in + inlen;
	char const	*p = in;
	fr_sbuff_t	our_sbuff;

	/* Significantly quicker if there are no rules */
	if (!e_rules || (e_rules->chr == '\0')) return fr_sbuff_in_bstrncpy(sbuff, in, inlen);

	CHECK_SBUFF_WRITEABLE(sbuff);

	our_sbuff = FR_SBUFF(sbuff);
	while (p < end) {
		size_t	clen;
		uint8_t	c = (uint8_t)*p;
		char	sub;

		/*
		 *	We don't support escaping UTF8 sequences
		 *	as they're not used anywhere in our
		 *	grammar.
		 */
		if (e_rules->do_utf8 && ((clen = fr_utf8_char((uint8_t const *)p, end - p)) > 1)) {
			FR_SBUFF_IN_BSTRNCPY_RETURN(&our_sbuff, p, clen);
			p += clen;
			continue;
		}

		/*
		 *	Check if there's a special substitution
		 *	like 0x0a -> \n.
		 */
		sub = e_rules->subs[c];
		if (sub != '\0') {
			FR_SBUFF_IN_CHAR_RETURN(&our_sbuff, e_rules->chr, sub);
			p++;
			continue;
		}

		/*
		 *	Check if the character is in the range
		 *	we escape.
		 */
		if (e_rules->esc[c]) {
			/*
			 *	For legacy reasons we prefer
			 *	octal escape sequences.
			 */
			if (e_rules->do_oct) {
				FR_SBUFF_IN_SPRINTF_RETURN(&our_sbuff, "%c%03o", e_rules->chr, (uint8_t)*p++);
				continue;
			} else if (e_rules->do_hex) {
				FR_SBUFF_IN_SPRINTF_RETURN(&our_sbuff, "%cx%02x", e_rules->chr, (uint8_t)*p++);
				continue;
			}
		}

		FR_SBUFF_IN_CHAR_RETURN(&our_sbuff, *p++);
	}

	FR_SBUFF_SET_RETURN(sbuff, &our_sbuff);
}

/** Print an escaped string to an sbuff taking a talloced buffer as input
 *
 * @param[in] sbuff	to print into.
 * @param[in] in	to escape.
 * @param[in] e_rules	Escaping rules.  Used to escape special characters
 *      		as data is written to the sbuff.  May be NULL.
 * @return
 *	- >= 0 the number of bytes printed into the sbuff.
 *	- <0 the number of bytes required to complete the print operation.
 */
ssize_t fr_sbuff_in_escape_buffer(fr_sbuff_t *sbuff, char const *in, fr_sbuff_escape_rules_t const *e_rules)
{
	if (unlikely(!in)) return 0;

	CHECK_SBUFF_WRITEABLE(sbuff);

	return fr_sbuff_in_escape(sbuff, in, talloc_array_length(in) - 1, e_rules);
}

/** Concat an array of strings (NULL terminated), with a string separator
 *
 * @param[out] out	Where to write the resulting string.
 * @param[in] array	of strings to concat.
 * @param[in] sep	to insert between elements.  May be NULL.
 * @return
 *      - >= 0 on success - length of the string created.
 *	- <0 on failure.  How many bytes we would need.
 */
fr_slen_t fr_sbuff_in_array(fr_sbuff_t *out, char const * const *array, char const *sep)
{
	fr_sbuff_t		our_out = FR_SBUFF(out);
	char const * const *	p;
	fr_sbuff_escape_rules_t	e_rules = {
					.name = __FUNCTION__,
					.chr = '\\'
				};

	if (sep) e_rules.subs[(uint8_t)*sep] = *sep;

	CHECK_SBUFF_WRITEABLE(out);

	for (p = array; *p; p++) {
		if (*p) FR_SBUFF_RETURN(fr_sbuff_in_escape, &our_out, *p, strlen(*p), &e_rules);

		if (sep && p[1]) {
			FR_SBUFF_RETURN(fr_sbuff_in_strcpy, &our_out, sep);
		}
	}

	FR_SBUFF_SET_RETURN(out, &our_out);
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
	if (fr_sbuff_extend_lowat(NULL, sbuff, needle_len) < needle_len) return 0;

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
	if (fr_sbuff_extend_lowat(NULL, sbuff, needle_len) < needle_len) return 0;

	p = sbuff->p;
	end = p + needle_len;

	for (p = sbuff->p, n_p = needle; p < end; p++, n_p++) {
		if (tolower((uint8_t) *p) != tolower((uint8_t) *n_p)) return 0;
	}

	return fr_sbuff_advance(sbuff, needle_len);
}

/** Wind position past characters in the allowed set
 *
 * @param[in] sbuff		sbuff to search in.
 * @param[in] len		Maximum amount to advance by. Unconstrained if SIZE_MAX.
 * @param[in] allowed		character set.
 * @param[in] tt		If not NULL, stop if we find a terminal sequence.
 * @return how many bytes we advanced.
 */
size_t fr_sbuff_adv_past_allowed(fr_sbuff_t *sbuff, size_t len, bool
				 const allowed[static SBUFF_CHAR_CLASS], fr_sbuff_term_t const *tt)
{
	size_t		total = 0;
	char const	*p;
	uint8_t		idx[SBUFF_CHAR_CLASS];	/* Fast path index */
	size_t		needle_len = 0;

	CHECK_SBUFF_INIT(sbuff);

	if (tt) fr_sbuff_terminal_idx_init(&needle_len, idx, tt);

	while (total < len) {
		char *end;

		if (!fr_sbuff_extend(sbuff)) break;

		end = CONSTRAINED_END(sbuff, len, total);
		p = sbuff->p;
		while ((p < end) && allowed[(uint8_t)*p]) {
			if (needle_len == 0) {
				p++;
				continue;
			}

		       /*
			*	If this character is allowed, BUT is also listed as a one-character terminal,
			*	then we still allow it.  This decision implements "greedy" parsing.
			*/
		       if (fr_sbuff_terminal_search(sbuff, p, idx, tt, 1)) {
			       p++;
			       continue;
		       }

		       /*
			*	Otherwise if the next *set* of characters) is not in the terminals, then
			*	allow the current character.
			*/
		       if (!fr_sbuff_terminal_search(sbuff, p, idx, tt, needle_len)) {
			       p++;
			       continue;
		       }

		       /*
			*	The character is allowed, and is NOT listed as a terminal character by itself.
			*	However, it is part of a multi-character terminal sequence.  We therefore
			*	stop.
			*
			*	This decision allows us to parse things like "Framed-User", where we might
			*	normally stop at the "-".  However, we will still stop at "Framed-=User", as
			*	"-=" may be a terminal sequence.
			*
			*	There is no perfect solution here, other than to fix the input grammar so that
			*	it has no ambiguity.  Since we can't do that, we choose to err on the side of
			*	allowing the existing grammar, where it makes sense
			*/
		       break;
		}

		total += fr_sbuff_set(sbuff, p);
		if (p != end) break;		/* stopped early, break */
	}

	return total;
}

/** Wind position until we hit a character in the terminal set
 *
 * @param[in] sbuff		sbuff to search in.
 * @param[in] len		Maximum amount to advance by. Unconstrained if SIZE_MAX.
 * @param[in] tt		Token terminals in the encompassing grammar.
 * @param[in] escape_chr	If not '\0', ignore characters in the tt set when
 *				prefixed with this escape character.
 * @return how many bytes we advanced.
 */
size_t fr_sbuff_adv_until(fr_sbuff_t *sbuff, size_t len, fr_sbuff_term_t const *tt, char escape_chr)
{
	size_t		total = 0;
	char const	*p;
	bool		do_escape = false;		/* Track state across extensions */

	uint8_t		idx[SBUFF_CHAR_CLASS];		/* Fast path index */
	size_t		needle_len = 1;

	CHECK_SBUFF_INIT(sbuff);

	/*
	 *	Initialise the fastpath index and
	 *	figure out the longest needle.
	 */
	fr_sbuff_terminal_idx_init(&needle_len, idx, tt);

	while (total < len) {
		char *end;

		if (fr_sbuff_extend_lowat(NULL, sbuff, needle_len) == 0) break;

		end = CONSTRAINED_END(sbuff, len, total);
		p = sbuff->p;

		if (escape_chr == '\0') {
			while ((p < end) && !fr_sbuff_terminal_search(sbuff, p, idx, tt, needle_len)) p++;
		} else {
			while (p < end) {
				if (do_escape) {
					do_escape = false;
				} else if (*p == escape_chr) {
					do_escape = true;
				} else if (fr_sbuff_terminal_search(sbuff, p, idx, tt, needle_len)) {
					break;
				}
				p++;
			}
		}

		total += fr_sbuff_set(sbuff, p);
		if (p != end) break;	/* stopped early, break */
	}

	return total;
}

/** Wind position to first instance of specified multibyte utf8 char
 *
 * Only use this function if the search char could be multibyte,
 * as there's a large performance penalty.
 *
 * @param[in,out] sbuff		to search in.
 * @param[in] len		the maximum number of characters to search in sbuff.
 * @param[in] chr		to search for.
 * @return
 *	- NULL, no instances found.
 *	- The position of the first character.
 */
char *fr_sbuff_adv_to_chr_utf8(fr_sbuff_t *sbuff, size_t len, char const *chr)
{
	fr_sbuff_t	our_sbuff = FR_SBUFF(sbuff);
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
		if (fr_sbuff_extend_lowat(NULL, &our_sbuff, clen) < clen) break;

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
	fr_sbuff_t	our_sbuff = FR_SBUFF(sbuff);
	size_t		total = 0;

	CHECK_SBUFF_INIT(sbuff);

	while (total < len) {
		char const	*found;
		char		*end;

		if (!fr_sbuff_extend(&our_sbuff)) break;

		end = CONSTRAINED_END(&our_sbuff, len, total);
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
	fr_sbuff_t	our_sbuff = FR_SBUFF(sbuff);
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

		/*
		 *	If the needle is longer than
		 *	the remaining buffer, return.
		 */
		if (fr_sbuff_extend_lowat(NULL, &our_sbuff, needle_len) < needle_len) break;

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
	fr_sbuff_t	our_sbuff = FR_SBUFF(sbuff);
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

		if (fr_sbuff_extend_lowat(NULL, &our_sbuff, needle_len) < needle_len) break;

		for (p = our_sbuff.p, n_p = needle, end = our_sbuff.p + needle_len;
		     (p < end) && (tolower((uint8_t) *p) == tolower((uint8_t) *n_p));
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
 *	- true and advance if the next character matches.
 *	- false and don't advance if the next character doesn't match.
 */
bool fr_sbuff_next_if_char(fr_sbuff_t *sbuff, char c)
{
	CHECK_SBUFF_INIT(sbuff);

	if (!fr_sbuff_extend(sbuff)) return false;

	if (*sbuff->p != c) return false;

	fr_sbuff_advance(sbuff, 1);

	return true;
}

/** Return true and advance if the next char does not match
 *
 * @param[in] sbuff	to search for char in.
 * @param[in] c		char to search for.
 * @return
 *	- true and advance unless the character matches.
 *	- false and don't advance if the next character matches.
 */
bool fr_sbuff_next_unless_char(fr_sbuff_t *sbuff, char c)
{
	CHECK_SBUFF_INIT(sbuff);

	if (!fr_sbuff_extend(sbuff)) return false;

	if (*sbuff->p == c) return false;

	fr_sbuff_advance(sbuff, 1);

	return true;
}

/** Trim trailing characters from a string we're composing
 *
 * @param[in] sbuff		to trim trailing characters from.
 * @param[in] to_trim		Charset to trim.
 * @return how many chars we removed.
 */
size_t fr_sbuff_trim(fr_sbuff_t *sbuff, bool const to_trim[static SBUFF_CHAR_CLASS])
{
	char	*p = sbuff->p - 1;
	ssize_t	slen;

	while ((p >= sbuff->start) && to_trim[(uint8_t)*p]) p--;

	slen = fr_sbuff_set(sbuff, p + 1);
	if (slen != 0) fr_sbuff_terminate(sbuff);

	return slen;
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
	uint8_t		idx[SBUFF_CHAR_CLASS];	/* Fast path index */
	size_t		needle_len = 1;

	/*
	 *	No terminal, check for EOF.
	 */
	if (!tt) {
		fr_sbuff_extend_status_t status = 0;

		if ((fr_sbuff_extend_lowat(&status, in, 1) == 0) &&
		    (status & FR_SBUFF_FLAG_EXTEND_ERROR) == 0) {
			return true;
		}

		return false;
	}

	/*
	 *	Initialise the fastpath index and
	 *	figure out the longest needle.
	 */
	fr_sbuff_terminal_idx_init(&needle_len, idx, tt);

	fr_sbuff_extend_lowat(NULL, in, needle_len);

	return fr_sbuff_terminal_search(in, in->p, idx, tt, needle_len);
}

/** Print a char in a friendly format
 *
 */
static char const *sbuff_print_char(char c)
{
	static bool const unprintables[SBUFF_CHAR_CLASS] = {
		SBUFF_CHAR_UNPRINTABLES_LOW,
		SBUFF_CHAR_UNPRINTABLES_EXTENDED
	};

	static _Thread_local char str[10][5];
	static _Thread_local size_t i = 0;

	switch (c) {
	case '\a':
		return "\a";

	case '\b':
		return "\b";

	case '\n':
		return "\n";

	case '\r':
		return "\r";

	case '\t':
		return "\t";

	case '\f':
		return "\f";

	case '\v':
		return "\v";

	default:
		if (i >= NUM_ELEMENTS(str)) i = 0;

		if (unprintables[(uint8_t)c]) {
			snprintf(str[i], sizeof(str[i]), "\\x%x", c);
			return str[i++];
		}

		str[i][0] = c;
		str[i][1] = '\0';
		return str[i++];
	}
}

void fr_sbuff_unescape_debug(FILE *fp, fr_sbuff_unescape_rules_t const *escapes)
{
	uint8_t i;

	fprintf(fp, "Escape rules %s (%p)\n", escapes->name, escapes);
	fprintf(fp, "chr     : %c\n", escapes->chr ? escapes->chr : ' ');
	fprintf(fp, "do_hex  : %s\n", escapes->do_hex ? "yes" : "no");
	fprintf(fp, "do_oct  : %s\n", escapes->do_oct ? "yes" : "no");

	fprintf(fp, "substitutions:\n");
	for (i = 0; i < UINT8_MAX; i++) {
		if (escapes->subs[i]) FR_FAULT_LOG("\t%s -> %s\n",
						   sbuff_print_char((char)i),
						   sbuff_print_char((char)escapes->subs[i]));
	}
	fprintf(fp, "skipes:\n");
	for (i = 0; i < UINT8_MAX; i++) {
		if (escapes->skip[i]) fprintf(fp, "\t%s\n", sbuff_print_char((char)i));
	}
}

void fr_sbuff_terminal_debug(FILE *fp, fr_sbuff_term_t const *tt)
{
	size_t i;

	fprintf(fp, "Terminal count %zu\n", tt->len);

	for (i = 0; i < tt->len; i++) fprintf(fp, "\t\"%s\" (%zu)\n", tt->elem[i].str, tt->elem[i].len);
}

void fr_sbuff_parse_rules_debug(FILE *fp, fr_sbuff_parse_rules_t const *p_rules)
{
	fprintf(fp, "Parse rules %p\n", p_rules);

	FR_FAULT_LOG("Escapes - ");
	if (p_rules->escapes) {
		fr_sbuff_unescape_debug(fp, p_rules->escapes);
	} else {
		fprintf(fp, "<none>\n");
	}

	FR_FAULT_LOG("Terminals - ");
	if (p_rules->terminals) {
		fr_sbuff_terminal_debug(fp, p_rules->terminals);
	} else {
		fprintf(fp, "<none>\n");
	}
}
