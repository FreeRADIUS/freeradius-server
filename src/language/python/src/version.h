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

/** Version checking functions
 *
 * @file src/version.h
 * @brief Python bindings for major FreeRADIUS libraries
 *
 * @copyright Network RADIUS SAS(legal@networkradius.com)
 * @author 2023 Jorge Pereira (jpereira@freeradius.org)
 */
RCSIDH(src_version_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#ifndef NDEBUG
#  define PYFR_VERSION_DEVELOPER "DEVELOPER BUILD - "
#else
#  define PYFR_VERSION_DEVELOPER ""
#endif

#if !defined(PYFR_VERSION_COMMIT) && defined(RADIUSD_VERSION_COMMIT)
#define PYFR_VERSION_COMMIT RADIUSD_VERSION_COMMIT
#endif

#ifdef PYFR_VERSION_COMMIT
#  define PYFR_VERSION_COMMIT_STRING " (git #" STRINGIFY(PYFR_VERSION_COMMIT) ")"
#else
#  define PYFR_VERSION_COMMIT_STRING ""
#endif

#ifndef ENABLE_REPRODUCIBLE_BUILDS
#  define _PYFR_VERSION_BUILD_TIMESTAMP "built on " __DATE__ " at " __TIME__
#  define PYFR_VERSION_BUILD_TIMESTAMP ", "_PYFR_VERSION_BUILD_TIMESTAMP
#else
#  define PYFR_VERSION_BUILD_TIMESTAMP ""
#endif

/** Create a version string for a utility in the suite of FreeRADIUS utilities
 *
 * @param _x utility name
 */
#define PYFR_VERSION_BUILD() \
	PYFR_VERSION_DEVELOPER \
	"version " \
	STRINGIFY(PYFR_VERSION_MAJOR) "." STRINGIFY(PYFR_VERSION_MINOR) "." STRINGIFY(PYFR_VERSION_INCRM) \
	PYFR_VERSION_COMMIT_STRING \
	", for host " HOSTINFO \
	PYFR_VERSION_BUILD_TIMESTAMP

#ifdef WITHOUT_VERSION_CHECK
#  define PYFR_MAGIC_NUMBER	((uint64_t) (0xf4ee4ad3f4ee4ad3))
#  define MAGIC_PREFIX(_x)	((uint8_t) 0x00)
#  define MAGIC_VERSION(_x)	((uint32_t) 0x00000000)
#else
/*
 *	Mismatch between debug builds between
 *	the modules and the server causes all
 *	kinds of strange issues.
 */
#  ifndef NDEBUG
#    define MAGIC_PREFIX_DEBUG	01
#  else
#    define MAGIC_PREFIX_DEBUG  00
#  endif
#  define PYFR_MAGIC_NUMBER ((uint64_t) HEXIFY2(MAGIC_PREFIX_DEBUG, PYFR_VERSION))
#  define MAGIC_PREFIX(_x)	((uint8_t) ((0xff00000000000000 & (_x)) >> 56))
#  define MAGIC_VERSION(_x)	((uint32_t)((0x00ffffff00000000 & (_x)) >> 32))
#  define MAGIC_COMMIT(_x)	((uint32_t)((0x00000000ffffffff & (_x))))
#endif

#ifdef __cplusplus
}
#endif
