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
 * @file lib/server/fr_assert.h
 * @brief Debug assertions, with logging.
 *
 * @copyright 2000,2001,2006 The FreeRADIUS server project
 */
RCSIDH(fr_assert_h, "$Id$")

#include <stdbool.h>
#include <freeradius-devel/util/debug.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef NDEBUG
#  define fr_assert(_expr)
#elif !defined(__clang_analyzer__)
#  define fr_assert(_expr) ((void) ((_expr) ? (void) 0 : (void) fr_assert_exit(__FILE__, __LINE__, #_expr)))
#else
#  include <assert.h>
#  define fr_assert assert
#endif



#ifdef __cplusplus
}
#endif
