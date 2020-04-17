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
 * Because doing manual length checks is error prone and a waste of everyone's time.
 *
 * @file src/lib/util/sbuff.h
 *
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(sbuff_h, "$Id$")

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
		char const *start;		//!< Immutable start pointer.
		char *start_m;			//!< Mutable start pointer.
	};

	union {
		char const *end;		//!< Immutable end pointer.
		char *end_m;			//!< Mutable end pointer.
	};

	union {
		char const *p;			//!< Immutable position pointer.
		char *p_m;			//!< Mutable position pointer.
	};

	bool	is_const;			//!< Can't be modified.
	bool	is_extendable;			//!< Dynamically allocated talloc buffer.
} fr_sbuff_t;

typedef enum {
	FR_SBUFF_PARSE_OK			= 0,		//!< No error.
	FR_SBUFF_PARSE_ERROR_NOT_FOUND		= -1,		//!< String does not contain a token
								///< matching the output type.
	FR_SBUFF_PARSE_ERROR_INTEGER_OVERFLOW	= -2,		//!< Integer type would overflow.
	FR_SBUFF_PARSE_ERROR_INTEGER_UNDERFLOW	= -3		//!< Integer type would underflow.
} fr_sbuff_parse_error_t;

/** @name Sbuff position manipulation
 * @{
 */
/** Prevent an sbuff being advanced as it's passed into a parsing function
 *
 * @param[in] _sbuff	to make an ephemeral copy of.
 */
#define FR_SBUFF_NO_ADVANCE(_sbuff) (fr_sbuff_t[]){ *(_sbuff) }

/** Reset the current position of the sbuff to the start of the string
 *
 */
#define fr_sbuff_start(_sbuff) ((_sbuff)->p) = ((_sbuff)->start)

/** Reset the current position of the sbuff to the end of the string
 *
 */
#define fr_sbuff_end(_sbuff) ((_sbuff)->p) = ((_sbuff)->end)

size_t fr_sbuff_strchr_utf8(fr_sbuff_t *in, char *chr);

size_t fr_sbuff_strchr(fr_sbuff_t *in, char c);

size_t fr_sbuff_strstr(fr_sbuff_t *in, char const *needle, ssize_t len);

size_t fr_sbuff_skip_whitespace(fr_sbuff_t *in);
/** @} */

/** @name Copy data out of an sbuff
 * @{
 */
ssize_t fr_sbuff_strncpy_exact(char *out, size_t outlen, fr_sbuff_t *in, size_t len);

size_t fr_sbuff_strncpy(char *out, size_t outlen, fr_sbuff_t *in, size_t len);

size_t fr_sbuff_strncpy_allowed(char *out, size_t outlen, fr_sbuff_t *in, size_t max_len,
				char allowed_chars[static UINT8_MAX + 1]);

size_t fr_sbuff_strncpy_until(char *out, size_t outlen, fr_sbuff_t *in, size_t len,
			      char until[static UINT8_MAX + 1]);
/** @} */

/** @name Look for a token in a particular format, parse it, and write it to the output pointer
 *
 * These functions should not be called directly.  #fr_sbuff_parse should be used instead
 * so that if the output variable type changes, the parse rules are automatically changed.
 * @{
 */
size_t fr_sbuff_parse_int8_t(fr_sbuff_parse_error_t *err, int8_t *out, fr_sbuff_t *in);

size_t fr_sbuff_parse_int16_t(fr_sbuff_parse_error_t *err, int16_t *out, fr_sbuff_t *in);

size_t fr_sbuff_parse_int32_t(fr_sbuff_parse_error_t *err, int32_t *out, fr_sbuff_t *in);

size_t fr_sbuff_parse_int64_t(fr_sbuff_parse_error_t *err, int64_t *out, fr_sbuff_t *in);

size_t fr_sbuff_parse_uint8_t(fr_sbuff_parse_error_t *err, uint8_t *out, fr_sbuff_t *in);

size_t fr_sbuff_parse_uint16_t(fr_sbuff_parse_error_t *err, uint16_t *out, fr_sbuff_t *in);

size_t fr_sbuff_parse_uint32_t(fr_sbuff_parse_error_t *err, uint32_t *out, fr_sbuff_t *in);

size_t fr_sbuff_parse_uint64_t(fr_sbuff_parse_error_t *err, uint64_t *out, fr_sbuff_t *in);


/** Parse a value based on the output type
 *
 * @param[out] _err	If not NULL a value describing the parse error
 *			will be written to err.
 * @param[out] _out	Pointer to an integer type.
 * @param[in] _in	Sbuff to parse integer from.
 * @return The number of bytes parsed (even on error).
 */
#define fr_sbuff_parse(_err, _out, _in) \
	_Generic((_out), \
		 int8_t *	: fr_sbuff_parse_int8_t(_err, _out, _in), \
		 int16_t *	: fr_sbuff_parse_int16_t(_err, _out, _in), \
		 int32_t *	: fr_sbuff_parse_int32_t(_err, _out, _in), \
		 int64_t *	: fr_sbuff_parse_int64_t(_err, _out, _in), \
		 uint8_t *	: fr_sbuff_parse_uint8_t(_err, _out, _in), \
		 uint16_t *	: fr_sbuff_parse_uint16_t(_err, _out, _in), \
		 uint32_t *	: fr_sbuff_parse_uint32_t(_err, _out, _in), \
		 uint64_t *	: fr_sbuff_parse_uint64_t(_err, _out, _in) \
	)
/** @} */

static inline void _fr_sbuff_parse_init(fr_sbuff_t *out, char const *start, char const *end, bool is_const)
{
	if (unlikely(end < start)) end = start;	/* Could be an assert? */

	out->p = out->start = start;
	out->end = end;
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
#define fr_sbuff_parse_init(_out, _start, _len_or_end) \
_Generic((_len_or_end), \
	size_t		: _fr_sbuff_parse_init(_out, _start, (char const *)(_start) + (size_t)(_len_or_end), true), \
	char *		: _fr_sbuff_parse_init(_out, _start, (char const *)(_len_or_end), false), \
	char const *	: _fr_sbuff_parse_init(_out, _start, (char const *)(_len_or_end), true) \
)

/** Initialise an sbuff for a stack allocated buffer
 *
 * Usually used for printing to a buffer
 *
 * @param[out] _out	Pointer to sbuff to initialise.
 * @param[in] _buff	Char buffer to wrap.
 */
#define fr_sbuff_print_init(_out, _buff)	_fr_sbuff_init(_out, _buff, sizeof(_buff), false);

/** Initialise an sbuff for a talloced buffer
 *
 * Usually used for printing to a buffer of variable length
 *
 * @param[out] _out	Pointer to sbuff to initialise.
 * @param[in] _buff	Talloced char buffer to wrap.
 */
#define fr_sbuff_print_talloc_init(_out, _buff) \
do { \
	_fr_sbuff_print_init(_out, _buff, talloc_array_length(_buff) - 1, true); \
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
#define fr_sbuff_aprint_talloc_init(_out, _ctx, _len) \
do { \
	char *_buff; \
	MEM(_buff = talloc_array(_ctx, char, (_len) + 1)); \
	_fr_sbuff_print_init(_out, _buff, (_len) + 1, true); \
	(_out)->is_extendable = true; \
} while (0)

static inline void _fr_sbuff_print_init(fr_sbuff_t *out, char *start, char *end, bool extendable)
{
	if (unlikely((end - 1) < start)) end = start;	/* Could be an assert? */

	out->p_m = out->start_m = start;
	out->end_m = (end - 1);				/* Always leave room for \0 byte */
	out->is_const = false;
	out->is_extendable = extendable;
}

#ifdef __cplusplus
}
#endif
