#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/rad_assert.h
 * @brief Debug assertions, with logging.
 *
 * @copyright 2000,2001,2006  The FreeRADIUS server project
 */
RCSIDH(rad_assert_h, "$Id$")

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NDEBUG
bool fr_assert_exit(char const *file, unsigned int line, char const *expr) CC_HINT(noreturn);
#else
bool fr_assert_exit(char const *file, unsigned int line, char const *expr);
#endif


#ifdef NDEBUG
#  define rad_assert(_expr)
#elif !defined(__clang_analyzer__)
#  define rad_assert(_expr) ((void) ((_expr) ? (void) 0 : (void) fr_assert_exit(__FILE__, __LINE__, #_expr)))
#else
#  include <assert.h>
#  define rad_assert assert
#endif

/** For systems with an old version libc, define static_assert.
 *
 */
#ifndef static_assert
#  define static_assert _Static_assert
# else
#  include <assert.h>
#endif

#ifdef __cplusplus
}
#endif
