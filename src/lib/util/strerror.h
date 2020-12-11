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

/** @name Add an error string to the thread local error stack
 *
 * @note printf functions should not be used in decoder libraries as an
 *	 attacker may be able to exploit them to consume excessive amounts
 *	 of CPU time. Use fr_strerror_const_* functions instead.
 *
 * @{
 */
/** @hidecallergraph */
void		fr_strerror_printf(char const *fmt, ...) CC_HINT(format (printf, 1, 2));

/** @hidecallergraph */
void		fr_strerror_printf_push(char const *fmt, ...)  CC_HINT(format (printf, 1, 2));

/** @hidecallergraph */
void		fr_strerror_printf_push_head(char const *fmt, ...)  CC_HINT(format (printf, 1, 2));
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
void		fr_strerror_marker_printf(char const *subject, size_t offset, char const *fmt, ...) CC_HINT(format (printf, 3, 4));

/** @hidecallergraph */
void		fr_strerror_marker_printf_push(char const *subject, size_t offset, char const *fmt, ...) CC_HINT(format (printf, 3, 4));

/** @hidecallergraph */
void		fr_strerror_marker_printf_push_head(char const *subject, size_t offset, char const *fmt, ...) CC_HINT(format (printf, 3, 4));
/** @} */

/** @name Add a const error string to the thread local error stack
 *
 * @note This ~30x the speed of the printf variants, and should be used wherever possible
 *
 * @{
 */
/** @hidecallergraph */
void		fr_strerror_const(char const *msg);

/** @hidecallergraph */
void		fr_strerror_const_push(char const *msg);

/** @hidecallergraph */
void		fr_strerror_const_push_head(char const *msg);
/** @} */

/** @name Retrieve errors from the thread local error stack
 *
 * @{
 */
/** @hidecallergraph */
char const	*fr_strerror(void);

/** @hidecallergraph */
char const	*fr_strerror_marker(char const **subject, size_t *offset);

/** @hidecallergraph */
char const	*fr_strerror_peek(void);

/** @hidecallergraph */
char const	*fr_strerror_marker_peek(char const **subject, size_t *offset);

/** @hidecallergraph */
char const	*fr_strerror_pop(void);

/** @hidecallergraph */
char const	*fr_strerror_marker_pop(char const **subject, size_t *offset);

/** @hidecallergraph */
void		fr_perror(char const *, ...) CC_HINT(format (printf, 1, 2));
/** @} */

#ifdef __cplusplus
}
#endif
