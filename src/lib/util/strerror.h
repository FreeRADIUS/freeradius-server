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

/** Support functions to allow libraries to provide errors to their callers
 *
 * @file src/lib/util/strerror.h
 *
 * @copyright 2017-2020 The FreeRADIUS server project
 * @copyright 2017-2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(strerror_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <string.h>
#include <stdarg.h>

/** @name Add an error string to the thread local error stack
 *
 * @note printf functions should not be used in decoder libraries as an
 *	 attacker may be able to exploit them to consume excessive amounts
 *	 of CPU time. Use fr_strerror_const_* functions instead.
 *
 * @{
 */

/** @hidecallergraph */
void		fr_strerror_vprintf(char const *fmt, va_list ap);

/** @hidecallergraph */
void		fr_strerror_vprintf_push(char const *fmt, va_list ap);

/** @hidecallergraph */
void		fr_strerror_vprintf_push_head(char const *fmt, va_list ap);

/** Log to thread local error buffer
 *
 * @param[in] fmt	printf style format string.
 *			If NULL clears any existing messages.
 * @param[in] ...	Arguments for the format string.
 *
 * @hidecallergraph
 */
static inline CC_HINT(nonnull) CC_HINT(format (printf, 1, 2))
void		fr_strerror_printf(char const *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	fr_strerror_vprintf(fmt, ap);
	va_end(ap);
}

/** Add a message to an existing stack of messages at the tail
 *
 * @param[in] fmt	printf style format string.
 * @param[in] ...	Arguments for the format string.
 *
 * @hidecallergraph
 */

static inline CC_HINT(nonnull) CC_HINT(format (printf, 1, 2))
void		fr_strerror_printf_push(char const *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	fr_strerror_vprintf_push(fmt, ap);
	va_end(ap);
}

/** Add a message to an existing stack of messages at the head
 *
 * @param[in] fmt	printf style format string.
 * @param[in] ...	Arguments for the format string.
 *
 * @hidecallergraph
 */
static inline CC_HINT(nonnull) CC_HINT(format (printf, 1, 2))
void 		fr_strerror_printf_push_head(char const *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	fr_strerror_vprintf_push_head(fmt, ap);
	va_end(ap);
}
/** @} */

/** @name Add an error string with marker to the thread local error stack
 *
 * @note printf functions should not be used in decoder libraries as an
 *	 attacker may be able to exploit them to consume excessive amounts
 *	 of CPU time. Use fr_strerror_const_* functions instead.
 *
 * @{
 */
/** @hidecallergraph */
void		fr_strerror_marker_vprintf(char const *subject, size_t offset, char const *fmt, va_list ap);

/** @hidecallergraph */
void		fr_strerror_marker_vprintf_push(char const *subject, size_t offset, char const *fmt, va_list ap);

/** @hidecallergraph */
void		fr_strerror_marker_vprintf_push_head(char const *subject, size_t offset, char const *fmt, va_list ap);

/** Add an error marker to an existing stack of messages
 *
 * @param[in] subject	to mark up.
 * @param[in] offset	Positive offset to show where the error
 *			should be positioned.
 * @param[in] fmt	Error string.
 * @param[in] ...	Arguments for the error string.
 *
 * @hidecallergraph
 */
static inline CC_HINT(nonnull) CC_HINT(format (printf, 3, 4))
void		fr_strerror_marker_printf(char const *subject, size_t offset, char const *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	fr_strerror_marker_vprintf(subject, offset, fmt, ap);
	va_end(ap);
}

/** Add an error marker to an existing stack of messages at the tail
 *
 * @param[in] subject	to mark up.
 * @param[in] offset	Positive offset to show where the error
 *			should be positioned.
 * @param[in] fmt	Error string.
 * @param[in] ...	Arguments for the error string.
 *
 * @hidecallergraph
 */
static inline CC_HINT(nonnull) CC_HINT(format (printf, 3, 4))
void		fr_strerror_marker_printf_push(char const *subject, size_t offset, char const *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	fr_strerror_marker_vprintf_push(subject, offset, fmt, ap);
	va_end(ap);
}

/** Add an error marker to an existing stack of messages at the head
 *
 * @param[in] subject	to mark up.
 * @param[in] offset	Positive offset to show where the error
 *			should be positioned.
 * @param[in] fmt	Error string.
 * @param[in] ...	Arguments for the error string.
 *
 * @hidecallergraph
 */
static inline CC_HINT(nonnull) CC_HINT(format (printf, 3, 4))
void		fr_strerror_marker_printf_push_head(char const *subject, size_t offset, char const *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	fr_strerror_marker_vprintf_push_head(subject, offset, fmt, ap);
	va_end(ap);
}
/** @} */

/** @name Add a const error string to the thread local error stack
 *
 * @note This ~30x the speed of the printf variants, and should be used wherever possible
 *
 * @{
 */
/** @hidecallergraph */
void		fr_strerror_const(char const *msg) CC_HINT(nonnull);

/** @hidecallergraph */
void		fr_strerror_const_push(char const *msg) CC_HINT(nonnull);

/** @hidecallergraph */
void		fr_strerror_const_push_head(char const *msg) CC_HINT(nonnull);
/** @} */

/** @name Retrieve errors from the thread local error stack
 *
 * @{
 */
/** @hidecallergraph */
char const	*fr_strerror(void) CC_HINT(warn_unused_result);

/** @hidecallergraph */
void		fr_strerror_clear(void);

/** @hidecallergraph */
char const	*fr_strerror_marker(char const **subject, size_t *offset) CC_HINT(nonnull);

/** @hidecallergraph */
char const	*fr_strerror_peek(void);

/** @hidecallergraph */
char const	*fr_strerror_marker_peek(char const **subject, size_t *offset) CC_HINT(nonnull);

/** @hidecallergraph */
char const	*fr_strerror_pop(void);

/** @hidecallergraph */
char const	*fr_strerror_marker_pop(char const **subject, size_t *offset) CC_HINT(nonnull);

/** @hidecallergraph */
void		fr_perror(char const *, ...) CC_HINT(format (printf, 1, 2));

/** @hidecallergraph */
char const	*fr_perror_to_str(char const *line_sep, char const *fmt, ...) CC_HINT(format (printf, 2, 3));
/** @} */

#ifdef __cplusplus
}
#endif
