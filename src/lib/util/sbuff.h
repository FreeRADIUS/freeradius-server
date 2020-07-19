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

/** A generic string buffer structure for string printing and parsing
 *
 * Because doing manual length checks is error prone and a waste of everyones time.
 *
 * @file src/lib/util/sbuff.h
 *
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(sbuff_h, "$Id$")

#  ifdef __cplusplus
extern "C" {
#  endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <talloc.h>

#include <freeradius-devel/util/table.h>

typedef struct fr_sbuff_s fr_sbuff_t;
typedef struct fr_sbuff_ptr_s fr_sbuff_marker_t;

typedef int(*fr_sbuff_extend_t)(fr_sbuff_t *sbuff, void *uctx);

struct fr_sbuff_ptr_s {
	union {
		char const *p_i;				//!< Immutable position pointer.
		char *p;					//!< Mutable position pointer.
	};
	fr_sbuff_marker_t	*next;			//!< Next m in the list.
	fr_sbuff_t		*parent;		//!< Owner of the marker
};

struct fr_sbuff_s {
	union {
		char const *start_i;				//!< Immutable start pointer.
		char *start;					//!< Mutable start pointer.
	};

	union {
		char const *end_i;				//!< Immutable end pointer.
		char *end;					//!< Mutable end pointer.
	};

	union {
		char const *p_i;				//!< Immutable position pointer.
		char *p;					//!< Mutable position pointer.
	};

	uint8_t			is_const:1;		//!< Can't be modified.
	uint8_t			is_extendable:1;	//!< Dynamically allocated talloc buffer.
	uint8_t			adv_parent:1;		//!< If true, advance the parent.

	fr_sbuff_t		*parent;		//!< sbuff this sbuff was copied from.

	fr_sbuff_marker_t	*m;			//!< Pointers to update if the underlying
							///< buffer changes.
	fr_sbuff_extend_t	extend;			//!< Function to re-populate or extend
							///< the buffer.
};

typedef enum {
	FR_SBUFF_PARSE_OK			= 0,		//!< No error.
	FR_SBUFF_PARSE_ERROR_NOT_FOUND		= -1,		//!< String does not contain a token
								///< matching the output type.
	FR_SBUFF_PARSE_ERROR_TRAILING		= -2,		//!< Trailing characters found.
	FR_SBUFF_PARSE_ERROR_NUM_OVERFLOW	= -3,		//!< Integer type would overflow.
	FR_SBUFF_PARSE_ERROR_NUM_UNDERFLOW	= -4		//!< Integer type would underflow.
} fr_sbuff_parse_error_t;

extern fr_table_num_ordered_t const sbuff_parse_error_table[];
extern size_t sbuff_parse_error_table_len;

/** Generic wrapper macro to return if there's insufficient memory to satisfy the request on the sbuff
 *
 */
#define FR_SBUFF_RETURN(_func, _sbuff, ...) \
do { \
	ssize_t _slen; \
	_slen = _func(_sbuff, ## __VA_ARGS__ ); \
	if (_slen < 0) return _slen; \
} while (0)

/** @name Ephemeral copying macros
 * @{
 */

/** Prevent an sbuff being advanced as it's passed into a printing or parsing function
 *
 * @param[in] _sbuff	to make an ephemeral copy of.
 */
#define FR_SBUFF_NO_ADVANCE(_sbuff) \
(fr_sbuff_t){ \
	.start		= (_sbuff)->p, \
	.end		= (_sbuff)->end, \
	.p		= (_sbuff)->p, \
	.is_const	= (_sbuff)->is_const, \
	.is_extendable	= (_sbuff)->is_extendable, \
	.adv_parent	= 0, \
	.parent		= (_sbuff) \
}

/** Copy all fields in an sbuff except ptrers
 *
 * @param[in] _sbuff	to make an ephemeral copy of.
 */
#define FR_SBUFF_COPY(_sbuff) \
(fr_sbuff_t){ \
	.start		= (_sbuff)->p, \
	.end		= (_sbuff)->end, \
	.p		= (_sbuff)->p, \
	.is_const	= (_sbuff)->is_const, \
	.is_extendable	= (_sbuff)->is_extendable, \
	.adv_parent	= (_sbuff)->adv_parent, \
	.parent		= (_sbuff) \
}

/** Creates a compound literal to pass into functions which accept a sbuff
 *
 * @note This should only be used as a temporary measure when refactoring code.
 *
 * @note The return value of the function should be used to determine how much
 *	 data was written to the buffer.
 *
 * @param[in] _start		of the buffer.
 * @param[in] _len_or_end	Length of the buffer or the end pointer.
 */
#define FR_SBUFF_TMP(_start, _len_or_end) \
(fr_sbuff_t){ \
	.start_i	= _start, \
	.end_i		= _Generic((_len_or_end), \
				size_t		: (char const *)(_start) + (size_t)(_len_or_end), \
				long		: (char const *)(_start) + (size_t)(_len_or_end), \
				char *		: (char const *)(_len_or_end), \
				char const *	: (char const *)(_len_or_end) \
			), \
	.p_i		= _start, \
	.is_const	= _Generic((_start), \
				char *		: false, \
				char const *	: true \
	       		) \
}
/** @} */

/** @name Length calculations
 * @{
 */

/** How many free bytes remain in the buffer
 *
 */
static inline size_t fr_sbuff_remaining(fr_sbuff_t const *sbuff)
{
	return sbuff->end - sbuff->p;
}

/** How many bytes we've used in the buffer
 *
 */
static inline size_t fr_sbuff_used(fr_sbuff_t const *sbuff)
{
	return sbuff->p - sbuff->start;
}

/** How many bytes in the buffer total
 *
 */
static inline size_t fr_sbuff_len(fr_sbuff_t const *sbuff)
{
	return sbuff->end - sbuff->start;
}

/** Return the current position in the sbuff as a negative offset
 *
 */
#define FR_SBUFF_ERROR_RETURN(_sbuff) return -(fr_sbuff_used(_sbuff))

/** Check if _len bytes are available in the sbuff, and if not return the number of bytes we'd need
 *
 */
#define FR_SBUFF_CHECK_REMAINING_RETURN(_sbuff, _len) \
do { \
	if ((_len) > fr_sbuff_remaining(_sbuff)) { \
		return -((_len) - fr_sbuff_remaining(_sbuff));	\
	}\
} while (0)

/** @} */

/** @name Accessors
 *
 * Caching the values of these pointers or the pointer values from the sbuff
 * directly is strongly discouraged as they can become invalidated during
 * stream parsing or when printing to an auto-expanding buffer.
 *
 * These functions should only be used to pass sbuff pointers into 3rd party
 * APIs.
 */
static inline char *fr_sbuff_start(fr_sbuff_t *sbuff)
{
	return sbuff->start;
}

static inline char *fr_sbuff_current(fr_sbuff_t *sbuff)
{
	return sbuff->p;
}

static inline char *fr_sbuff_end(fr_sbuff_t *sbuff)
{
	return sbuff->end;
}
/** @} */

/** @name Position modification (recursive)
 *
 * Change the current position of pointers in the sbuff and their children.
 * @{
 */

/** Update the position of p in a list of sbuffs
 *
 * @note Do not call directly.
 */
static inline void _fr_sbuff_set_recurse(fr_sbuff_t *sbuff, char const *p)
{
	sbuff->p_i = p;
	if (sbuff->adv_parent && sbuff->parent) _fr_sbuff_set_recurse(sbuff->parent, p);
}

/** Advance position in sbuff by N bytes
 *
 * @param[in] sbuff	to advance.
 * @param[in] n		How much to advance sbuff by.
 * @return
 *	- 0	not advanced.
 *	- >0	the number of bytes the sbuff was advanced by.
 *	- <0	the number of bytes required to complete the advancement
 */
static inline ssize_t fr_sbuff_advance(fr_sbuff_t *sbuff, size_t n)
{
	size_t freespace = fr_sbuff_remaining(sbuff);
	if (n > freespace) return -(n - freespace);
	_fr_sbuff_set_recurse(sbuff, sbuff->p + n);
	return n;
}
#define FR_SBUFF_ADVANCE_RETURN(_sbuff, _n) FR_SBUFF_RETURN(fr_sbuff_advance, _sbuff, _n)

/** Set a new position for 'p' in an sbuff
 *
 * @param[out] sbuff	sbuff to set a position in.
 * @param[in] p		Position to set.
 * @return
 *	- 0	not advanced.
 *	- >0	the number of bytes the sbuff was advanced by.
 *	- <0	the number of bytes required to complete the advancement
 */
static inline ssize_t _fr_sbuff_set(fr_sbuff_t *sbuff, char const *p)
{
	char const *c;

	if (unlikely(p > sbuff->end)) return -(p - sbuff->end);
	if (unlikely(p < sbuff->start)) return 0;

	c = sbuff->p;
	_fr_sbuff_set_recurse(sbuff, p);

	return p - c;
}

/** Set the position in a sbuff using another sbuff, a char pointer, or a length
 *
 * @param[out] _dst	sbuff to advance.
 * @param[in] _src	An sbuff, char pointer, or length value to advance
 *			_dst by.
 * @return
 *	- 0	not advanced.
 *	- >0	the number of bytes the sbuff was advanced by.
 *	- <0	the number of bytes required to complete the advancement
 */
#define fr_sbuff_set(_dst, _src) \
_fr_sbuff_set(_dst, \
	      _Generic(_src, \
			fr_sbuff_t *	: (_src)->p, \
			char const *	: (_src), \
			char *		: (_src), \
			size_t		: ((_dst)->p += (uintptr_t)(_src)) \
	      ))


/** Reset the current position of the sbuff to the start of the string
 *
 */
static inline void fr_sbuff_set_to_start(fr_sbuff_t *sbuff)
{
	_fr_sbuff_set_recurse(sbuff, sbuff->start);
}

/** Reset the current position of the sbuff to the end of the string
 *
 */
static inline void fr_sbuff_set_to_end(fr_sbuff_t *sbuff)
{
	_fr_sbuff_set_recurse(sbuff, sbuff->end);
}
/** @} */

/** @name Add a marker to an sbuff
 *
 * Markers are used to indicate an area of the code is working at a particular
 * point in a string buffer.
 *
 * If the sbuff is performing stream parsing, then markers are used to update
 * any pointers to the buffer, as the data in the buffer is shifted to make
 * room for new data from the stream.
 *
 * If the sbuff is being used to create strings, then the markers are updated
 * if the buffer is re-allocated.
 * @{
 */
/** Adds a new pointer to the beginning of the list of pointers to update
 *
 * @param[out] m	to initialise.
 * @param[in] sbuff	to associate marker with.
 * @return The position the marker was set to.
 */
static inline char *fr_sbuff_marker(fr_sbuff_marker_t *m, fr_sbuff_t *sbuff)
{
	*m = (fr_sbuff_marker_t){
		.next = sbuff->m,	/* Link into the head */
		.p = sbuff->p,		/* Set the current position in the sbuff */
		.parent = sbuff		/* Record which sbuff this marker was associated with */
	};
	sbuff->m = m;

	return sbuff->p;
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
static inline void fr_sbuff_marker_release(fr_sbuff_marker_t *m)
{
	m->parent->m = m->next;

#ifndef NDEBUF
	memset(m, 0, sizeof(*m));	/* Use after release */
#endif
}

/** Resets the position in an sbuff to specified marker
 *
 */
static inline void fr_sbuff_set_to_marker(fr_sbuff_marker_t *m)
{
	fr_sbuff_t *sbuff = m->parent;

	_fr_sbuff_set_recurse(sbuff, m->p);
}

/** Return the current position of the marker
 *
 */
static inline char *fr_sbuff_marker_current(fr_sbuff_marker_t *m)
{
	return m->p;
}

/** How many free bytes remain in the buffer (calculated from marker)
 *
 */
static inline size_t fr_sbuff_marker_remaining(fr_sbuff_marker_t *m)
{
	return m->parent->end - m->p;
}

/** How many bytes we've used in the buffer (calculated from marker)
 *
 */
static inline size_t fr_sbuff_marker_used(fr_sbuff_marker_t *m)
{
	return m->p - m->parent->start;
}
/** @} */

/** @name Position modification (non-recursive)
 *
 * Change the current position of pointers in the sbuff
 * @{
 */

/** Set the start pointer to the current value of p
 *
 */
static inline void fr_sbuff_trim_start(fr_sbuff_t *sbuff)
{
	sbuff->start = sbuff->p;
}

/** Set the end pointer to the current value of p
 *
 */
static inline void fr_sbuff_trim_end(fr_sbuff_t *sbuff)
{
	sbuff->end = sbuff->p;
}

/** @} */

/** @name Copy/print data to an sbuff
 *
 * These functions are typically used for printing.
 *
 * @{
 */
/** Initialise an sbuff for a stack allocated buffer
 *
 * Usually used for printing to a buffer
 *
 * @param[out] _out	Pointer to sbuff to initialise.
 * @param[in] _buff	Char buffer to wrap.
 */
#define fr_sbuff_in_init(_out, _buff)	_fr_sbuff_init(_out, _buff, sizeof(_buff), false);

/** Initialise an sbuff for a talloced buffer
 *
 * Usually used for printing to a buffer of variable length
 *
 * @param[out] _out	Pointer to sbuff to initialise.
 * @param[in] _buff	Talloced char buffer to wrap.
 */
#define fr_sbuff_in_talloc_init(_out, _buff) \
do { \
	_fr_sbuff_in_init(_out, _buff, talloc_array_length(_buff) - 1, true); \
	(_out)->is_extendable = true; \
} while (0)

/** Initialise an sbuff and alloc a talloc buffer
 *
 * Usually used for printing to a buffer of variable length
 *
 * @param[out] _out	Pointer to sbuff to initialise.
 * @param[in] _ctx	Talloc ctx to allocate buffer in.
 * @param[in] _len	Length of buffer to initialise, excluding '\0'.
 */
#define fr_sbuff_in_talloc_alloc(_out, _ctx, _len) \
do { \
	char *_buff; \
	MEM(_buff = talloc_array(_ctx, char, (_len) + 1)); \
	_fr_sbuff_in_init(_out, _buff, (_len) + 1, true); \
	(_out)->is_extendable = true; \
} while (0)

static inline void _fr_sbuff_in_init(fr_sbuff_t *out, char *start, char *end, bool extendable)
{
	if (unlikely((end - 1) < start)) end = start;	/* Could be an assert? */

	out->p = out->start = start;
	out->end = (end - 1);				/* Always leave room for \0 byte */
	out->is_const = false;
	out->is_extendable = extendable;
}

ssize_t		fr_sbuff_in_strcpy(fr_sbuff_t *sbuff, char const *str);

ssize_t		fr_sbuff_in_bstrncpy(fr_sbuff_t *sbuff, char const *str, size_t len);

ssize_t		fr_sbuff_in_bstrcpy_buffer(fr_sbuff_t *sbuff, char const *str);

ssize_t		fr_sbuff_in_vsprintf(fr_sbuff_t *sbuff, char const *fmt, va_list ap);

ssize_t		fr_sbuff_in_sprintf(fr_sbuff_t *sbuff, char const *fmt, ...);

ssize_t		fr_sbuff_in_snprint(fr_sbuff_t *sbuff, char const *in, size_t inlen, char quote);

ssize_t		fr_sbuff_in_snprint_buffer(fr_sbuff_t *sbuff, char const *in, char quote);
/** @} */

/** @name Copy data out of an sbuff
 *
 * These functions are typically used for parsing.
 *
 * @{
 */
static inline void _fr_sbuff_out_init(fr_sbuff_t *out, char const *start, char const *end, bool is_const)
{
	if (unlikely(end < start)) end = start;	/* Could be an assert? */

	out->p_i = out->start_i = start;
	out->end_i = end;
	out->is_const = is_const;
	out->is_extendable = false;
}

/** Initialise an sbuff for binary safe string parsing
 *
 * @param[out] _out		Pointer to buffer to parse
 * @param[in] _start		Start of the buffer to parse.
 * @param[in] _len_or_end	Either an end pointer or the length
 *				of the buffer we're parsing.
 */
#define fr_sbuff_out_init(_out, _start, _len_or_end) \
_Generic((_len_or_end), \
	size_t		: _fr_sbuff_out_init(_out, _start, (char const *)(_start) + (size_t)(_len_or_end), true), \
	char *		: _fr_sbuff_out_init(_out, _start, (char const *)(_len_or_end), false), \
	char const *	: _fr_sbuff_out_init(_out, _start, (char const *)(_len_or_end), true) \
)

/** Find the longest prefix in an sbuff
 *
 * @param[out] _match_len	The length of the matched string.
 *				May be NULL.
 * @param[out] _out		The value resolve in the table.
 * @param[in] _table		to find longest match in.
 * @param[in] _sbuff		containing the needle.
 * @param[in] _def		Default value if no match is found.
 */
#define fr_sbuff_out_table_value_by_longest_prefix(_match_len, _out, _table, _sbuff, _def) \
do { \
	size_t		_match_len_tmp; \
	*(_out) = fr_table_value_by_longest_prefix(&_match_len_tmp, _table, \
						   fr_sbuff_current(_sbuff), fr_sbuff_remaining(_sbuff), \
						   _def); \
	(void) fr_sbuff_advance(_sbuff, _match_len_tmp); /* can't fail */ \
	if (_match_len) *(_match_len) = _match_len_tmp; \
} while (0)

size_t	fr_sbuff_out_talloc_bstrncpy_exact(TALLOC_CTX *ctx, char **out, fr_sbuff_t *in, size_t len);

size_t	fr_sbuff_out_talloc_bstrncpy(TALLOC_CTX *ctx, char **out, fr_sbuff_t *in, size_t len);

size_t	fr_sbuff_out_talloc_bstrncpy_allowed(TALLOC_CTX *ctx, char **out, fr_sbuff_t *in, size_t len,
					     bool const allowed_chars[static UINT8_MAX + 1]);

size_t	fr_sbuff_out_talloc_bstrncpy_until(TALLOC_CTX *ctx, char **out, fr_sbuff_t *in, size_t len,
					   bool const until[static UINT8_MAX + 1]);

ssize_t	fr_sbuff_out_bstrncpy_exact(char *out, size_t outlen, fr_sbuff_t *sbuff, size_t len);

size_t	fr_sbuff_out_bstrncpy(char *out, size_t outlen, fr_sbuff_t *sbuff, size_t len);

size_t	fr_sbuff_out_bstrncpy_allowed(char *out, size_t outlen, fr_sbuff_t *sbuff, size_t len,
				      bool const allowed_chars[static UINT8_MAX + 1]);

size_t	fr_sbuff_out_bstrncpy_until(char *out, size_t outlen, fr_sbuff_t *sbuff, size_t len,
				    bool const until[static UINT8_MAX + 1]);
/** @} */

/** @name Look for a token in a particular format, parse it, and write it to the output pointer
 *
 * These functions should not be called directly.  #fr_sbuff_out should be used instead
 * so that if the output variable type changes, the parse rules are automatically changed.
 * @{
 */
size_t fr_sbuff_out_int8(fr_sbuff_parse_error_t *err, int8_t *out, fr_sbuff_t *sbuff, bool no_trailing);

size_t fr_sbuff_out_int16(fr_sbuff_parse_error_t *err, int16_t *out, fr_sbuff_t *sbuff, bool no_trailing);

size_t fr_sbuff_out_int32(fr_sbuff_parse_error_t *err, int32_t *out, fr_sbuff_t *sbuff, bool no_trailing);

size_t fr_sbuff_out_int64(fr_sbuff_parse_error_t *err, int64_t *out, fr_sbuff_t *sbuff, bool no_trailing);

size_t fr_sbuff_out_uint8(fr_sbuff_parse_error_t *err, uint8_t *out, fr_sbuff_t *sbuff, bool no_trailing);

size_t fr_sbuff_out_uint16(fr_sbuff_parse_error_t *err, uint16_t *out, fr_sbuff_t *sbuff, bool no_trailing);

size_t fr_sbuff_out_uint32(fr_sbuff_parse_error_t *err, uint32_t *out, fr_sbuff_t *sbuff, bool no_trailing);

size_t fr_sbuff_out_uint64(fr_sbuff_parse_error_t *err, uint64_t *out, fr_sbuff_t *sbuff, bool no_trailing);

size_t fr_sbuff_out_float32(fr_sbuff_parse_error_t *err, float *out, fr_sbuff_t *sbuff, bool no_trailing);

size_t fr_sbuff_out_float64(fr_sbuff_parse_error_t *err, double *out, fr_sbuff_t *sbuff, bool no_trailing);

/** Parse a value based on the output type
 *
 * @param[out] _err	If not NULL a value describing the parse error
 *			will be written to err.
 * @param[out] _out	Pointer to an integer type.
 * @param[in] _in	Sbuff to parse integer from.
 * @return The number of bytes parsed (even on error).
 */
#define fr_sbuff_out(_err, _out, _in) \
	_Generic((_out), \
		 int8_t *	: fr_sbuff_out_int8(_err, (int8_t *)_out, _in, true), \
		 int16_t *	: fr_sbuff_out_int16(_err, (int16_t *)_out, _in, true), \
		 int32_t *	: fr_sbuff_out_int32(_err, (int32_t *)_out, _in, true), \
		 int64_t *	: fr_sbuff_out_int64(_err, (int64_t *)_out, _in, true), \
		 uint8_t *	: fr_sbuff_out_uint8(_err, (uint8_t *)_out, _in, true), \
		 uint16_t *	: fr_sbuff_out_uint16(_err, (uint16_t *)_out, _in, true), \
		 uint32_t *	: fr_sbuff_out_uint32(_err, (uint32_t *)_out, _in, true), \
		 uint64_t *	: fr_sbuff_out_uint64(_err, (uint64_t *)_out, _in, true), \
		 float *	: fr_sbuff_out_float32(_err, (float *)_out, _in, true), \
		 double *	: fr_sbuff_out_float64(_err, (double *)_out, _in, true), \
	)
/** @} */


/** @name Conditional advancement
 *
 * These functions are typically used for parsing when trying to locate
 * a sequence of characters in the sbuff.
 * @{
 */
bool	fr_sbuff_adv_past_str(fr_sbuff_t *sbuff, char const *needle, size_t len);

#define fr_sbuff_adv_past_str_literal(_sbuff, _needle) fr_sbuff_adv_past_str(_sbuff, _needle, sizeof(_needle) - 1)

bool	fr_sbuff_adv_past_strcase(fr_sbuff_t *sbuff, char const *needle, size_t len);

#define fr_sbuff_adv_past_strcase_literal(_sbuff, _needle) fr_sbuff_adv_past_strcase(_sbuff, _needle, sizeof(_needle) - 1)

size_t	fr_sbuff_adv_past_whitespace(fr_sbuff_t *sbuff);

size_t	fr_sbuff_adv_to_strchr_utf8(fr_sbuff_t *in, char *chr);

size_t	fr_sbuff_adv_to_strchr(fr_sbuff_t *in, char c);

size_t	fr_sbuff_adv_to_strstr(fr_sbuff_t *sbuff, char const *needle, ssize_t len);

#define fr_sbuff_adv_to_strstr_literal(_sbuff, _needle) fr_sbuff_adv_to_strstr(_sbuff, _needle, sizeof(_needle) - 1)

bool	fr_sbuff_next_if_char(fr_sbuff_t *sbuff, char c);

bool	fr_sbuff_next_unless_char(fr_sbuff_t *sbuff, char c);

/** Advance the sbuff by one char
 *
 */
static inline char fr_sbuff_next(fr_sbuff_t *sbuff)
{
	if (sbuff->p >= sbuff->end) return '\0';

	sbuff->p++;

	return *sbuff->p;
}
/** @} */

/** @name Conditions
 *
 * These functions are typically used in recursive decent parsing for
 * look ahead.
 * @{
 */
static inline bool fr_sbuff_is_allowed(fr_sbuff_t *sbuff, bool const allowed_chars[static UINT8_MAX + 1])
{
	if (sbuff->p >= sbuff->end) return false;
	return allowed_chars[(uint8_t)*sbuff->p];
}

static inline bool fr_sbuff_is_char(fr_sbuff_t *sbuff, char c)
{
	if (sbuff->p >= sbuff->end) return false;
	return *sbuff->p == c;
}

static inline bool fr_sbuff_is_digit(fr_sbuff_t *sbuff)
{
	if (sbuff->p >= sbuff->end) return false;
	return isdigit(*sbuff->p);
}

static inline bool fr_sbuff_is_upper(fr_sbuff_t *sbuff)
{
	if (sbuff->p >= sbuff->end) return false;
	return isupper(*sbuff->p);
}

static inline bool fr_sbuff_is_lower(fr_sbuff_t *sbuff)
{
	if (sbuff->p >= sbuff->end) return false;
	return islower(*sbuff->p);
}

static inline bool fr_sbuff_is_alpha(fr_sbuff_t *sbuff)
{
	if (sbuff->p >= sbuff->end) return false;
	return isalpha(*sbuff->p);
}

static inline bool fr_sbuff_is_space(fr_sbuff_t *sbuff)
{
	if (sbuff->p >= sbuff->end) return false;
	return isspace(*sbuff->p);
}
/** @} */

#ifdef __cplusplus
}
#endif
