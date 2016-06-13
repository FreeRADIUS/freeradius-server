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
#ifndef _FR_VERSION_H
#define _FR_VERSION_H
/**
 * $Id$
 *
 * @file include/version.h
 * @brief Version checking functions
 *
 * @copyright 2016  The FreeRADIUS server project
 */
RCSIDH(version_h, "$Id$")


#ifdef WITHOUT_VERSION_CHECK
#  define RADIUSD_MAGIC_NUMBER	((uint64_t) (0xf4ee4ad3f4ee4ad3))
#  define MAGIC_PREFIX(_x)	((uint8_t) 0x00)
#  define MAGIC_VERSION(_x)	((uint32_t) 0x00000000)
#  define MAGIC_COMMIT(_x)	((uint32_t) 0x00000000)
#else
#  ifdef RADIUSD_VERSION_COMMIT
#    define RADIUSD_MAGIC_NUMBER ((uint64_t) HEXIFY4(f4, RADIUSD_VERSION, RADIUSD_VERSION_COMMIT, 0))
#  else
#    define RADIUSD_MAGIC_NUMBER ((uint64_t) HEXIFY3(f4, RADIUSD_VERSION, 00000000))
#  endif
#  define MAGIC_PREFIX(_x)	((uint8_t) (_x >> 56))
#  define MAGIC_VERSION(_x)	((uint32_t) ((_x >> 32) & 0x00ffffff))
#  define MAGIC_COMMIT(_x)	((uint32_t) (_x & 0xffffffff))
#endif

/*
 *	Version check.
 */
int fr_check_lib_magic(uint64_t magic);

#endif /* _FR_VERSION_H */
