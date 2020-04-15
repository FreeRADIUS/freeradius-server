#pragma once
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

/** Functions to produce and parse the FreeRADIUS presentation format
 *
 * @file src/lib/util/print.h
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSIDH(print_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <stddef.h>
#include <stdint.h>
#include <talloc.h>

size_t		fr_utf8_char(uint8_t const *str, ssize_t inlen);
ssize_t		fr_utf8_str(uint8_t const *str, ssize_t inlen);
char const     	*fr_utf8_strchr(int *chr_len, char const *str, ssize_t inlen, char const *chr);
size_t		fr_snprint(char *out, size_t outlen, char const *in, ssize_t inlen, char quote);
size_t		fr_snprint_len(char const *in, ssize_t inlen, char quote);
char		*fr_asprint(TALLOC_CTX *ctx, char const *in, ssize_t inlen, char quote);
char		*fr_vasprintf(TALLOC_CTX *ctx, char const *fmt, va_list ap);
char		*fr_asprintf(TALLOC_CTX *ctx, char const *fmt, ...) CC_HINT(format (printf, 2, 3));
ssize_t 	fr_fprintf(FILE *stream, char const *fmt, ...) CC_HINT(format (printf, 2, 3));

#define		is_truncated(_ret, _max) ((_ret) >= (size_t)(_max))
#define		truncate_len(_ret, _max) (((_ret) >= (size_t)(_max)) ? (((size_t)(_max)) - 1) : _ret)

/** Boilerplate for checking truncation
 *
 * If truncation has occurred, advance _p as far as possible without
 * overrunning the output buffer, and \0 terminate.  Then return the length
 * of the buffer and set need to the number of additional bytes we would
 * have needed.
 *
 * If truncation has not occurred, advance _p by whatever the copy or print
 * function returned.
 *
 * @param[out] _need	A pointer to a size_t.  If truncation has occurred
 *			will be set to the number of bytes needed.
 * @param[in] _ret	What the snprintf style function returned.
 * @param[in] _p	The current position in the output buffer.
 * @param[in] _start	of the output buffer.
 * @param[in] _end	of the output buffer.
 */
#define RETURN_IF_TRUNCATED(_need, _ret, _p, _start, _end) \
do { \
	if (is_truncated(_ret, _end - _p)) { \
		size_t _r = (_p - out) + _ret; \
		_p += truncate_len(_ret, _end - _p); \
		*_p = '\0'; \
		if (need) *need = _r; \
		return (_p) - (_start); \
	} \
	_p += _ret; \
} while (0)

/** Boilerplate for checking for sufficient freespace
 *
 * If we don't have sufficient space, set _need to the amount of space needed,
 * '\0' terminate the buffer, and return the amount of data we've written.
 *
 * @param[out] _need	A pointer to a size_t.  If truncation has occurred
 *			will be set to the number of bytes needed.
 * @param[in] _len	How much data we need.
 * @param[in] _p	The current position in the output buffer.
 * @param[in] _start	of the output buffer.
 * @param[in] _end	of the output buffer.
 */
#define RETURN_IF_NO_SPACE(_need, _len, _p, _start, _end) \
do { \
	if ((_len) >= ((_end) - (_p))) { \
		*(_p) = '\0'; \
		if (need) *need = ((_p) - (_start)) + (_len); \
		return (_p) - (_start); \
	} \
} while (0)

/** Boilerplate for checking for sufficient freespace
 *
 * If we don't have sufficient space, set _need to the amount of space needed,
 * '\0' terminate the buffer, and return the amount of data we've written.
 *
 * This should be called at the start of functions that work with a fixed length
 * output buffer, in order to initialise _need.
 *
 * @param[out] _need	A pointer to a size_t.  If truncation has occurred
 *			will be set to the number of bytes needed.
 * @param[in] _len	How much data we need.
 * @param[in] _p	The current position in the output buffer.
 * @param[in] _start	of the output buffer.
 * @param[in] _end	of the output buffer.
 */
#define RETURN_IF_NO_SPACE_INIT(_need, _len, _p, _start, _end) \
do { \
	RETURN_IF_NO_SPACE(_need, _len, _p, _start, _end); \
	if (_need) *(_need) = 0; \
	*((_end) - 1) = '\0'; \
} while (0)

#ifdef __cplusplus
}
#endif
