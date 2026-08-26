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

/** Integration with the leak sanitizer interface
 *
 * @file src/lib/util/lsan.h
 *
 * @copyright 2018 The FreeRADIUS server project
 */
RCSIDH(lsan_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

/*
 *  clangd doesn't inherit all the implicit includes of clang.
 */
#ifdef __clangd__
#  undef HAVE_SANITIZER_LSAN_INTERFACE_H
#endif

/*
 *	Include both ASAN and LSAN headers if they're defined.
 */
#ifdef HAVE_SANITIZER_LSAN_INTERFACE_H
#  include <sanitizer/lsan_interface.h>
#  include <sanitizer/asan_interface.h>

/*
 *	Run code in an "LSAN disabled" context.
 */
#  define LSAN_DISABLE(_x) __lsan_disable(); _x; __lsan_enable()

#elif defined(FR_ASAN_HARDEN)
/*
 *	Manually wiping memory isn't as good as ASAN, but it can be
 *	done at the byte level.  ASAN poisoning is done on 8 byte
 *	boundaries.
 */
#  define ASAN_POISON_MEMORY_REGION(_start, _end) memset((_start), 0x00, (_end))
#  define ASAN_UNPOISON_MEMORY_REGION(_start, _end)
#  define LSAN_DISABLE(_x) _x
#else
/*
 *	Nothing available, don't use any of the ASAN / LSAN features.
 */
#  define ASAN_POISON_MEMORY_REGION(_start, _size)
#  define ASAN_UNPOISON_MEMORY_REGION(_start, _size)
#  define LSAN_DISABLE(_x) _x
#endif

#ifdef __cplusplus
}
#endif
