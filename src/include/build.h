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
 * @file include/build.h
 * @brief Source control functions
 *
 * @copyright 2013 The FreeRADIUS server project
 */

#ifdef __cplusplus
extern "C" {
#endif

/** For systems with an old version libc, define static_assert.
 *
 */
#ifndef static_assert
#  define static_assert _Static_assert
# else
#  include <assert.h>
#endif

/*
 *	Reduce spurious errors from clang scan by having
 *	all paths that find the da to be NULL, result
 *	in program exit.
 */
#ifdef __clang_analyzer__
#  define WITH_VERIFY_PTR	1
#endif

/*
 *	GCC uses __SANITIZE_ADDRESS__, clang uses __has_feature, which
 *	GCC complains about.
 */
#ifndef __SANITIZE_ADDRESS__
#ifdef __has_feature
#if __has_feature(address_sanitizer)
#define __SANITIZE_ADDRESS__ (1)
#endif
#endif
#endif

/*
 *	The ubiquitous stringify macros
 */
#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)
#define JOINSTR(x,y) XSTRINGIFY(x ## y)

/*
 *	Helpers for initialising arrays
 *      of string literals.
 */
#define L(_str)		{ _str, sizeof(_str) - 1 }

/*
 *	HEX concatenation macros
 */
#ifndef HEXIFY
#  define XHEXIFY4(b1,b2,b3,b4)	(0x ## b1 ## b2 ## b3 ## b4)
#  define HEXIFY4(b1,b2,b3,b4)	XHEXIFY4(b1, b2, b3, b4)

#  define XHEXIFY3(b1,b2,b3)	(0x ## b1 ## b2 ## b3)
#  define HEXIFY3(b1,b2,b3)	XHEXIFY3(b1, b2, b3)

#  define XHEXIFY2(b1,b2)	(0x ## b1 ## b2)
#  define HEXIFY2(b1,b2)	XHEXIFY2(b1, b2)

#  define XHEXIFY(b1)		(0x ## b1)
#  define HEXIFY(b1)		XHEXIFY(b1)
#endif

/*
 *	Pass caller information to the function
 */
#ifndef NDEBUG
#  define NDEBUG_LOCATION_ARGS			char const *file, int line,
#  define NDEBUG_LOCATION_VALS			file, line,
#  define NDEBUG_LOCATION_EXP			__FILE__, __LINE__,
#  define NDEBUG_LOCATION_NONNULL(_num)		((_num) + 2)
#else
#  define NDEBUG_LOCATION_ARGS
#  define NDEBUG_LOCATION_VALS
#  define NDEBUG_LOCATION_EXP
#  define NDEBUG_LOCATION_NONNULL(_num)		(_num)
#endif

/*
 *	Mark variables as unused
 */
#define UNUSED_VAR(_x) ((void)_x)

/** Pad _x to the next multiple of _y
 *
 */
#define PAD(_x, _y)		(_y - ((_x) % _y))

#define PRINTF_LIKE(n)		CC_HINT(format(printf, n, n+1))
#define NEVER_RETURNS		CC_HINT(noreturn)
#define UNUSED			CC_HINT(unused)

/** clang 10 doesn't recognised the FALL-THROUGH comment anymore
 *
 */
#if (defined(__clang__) && (__clang_major__ >= 10)) || (defined(__GNUC__) && __GNUC__ >= 7)
#  define FALL_THROUGH		CC_HINT(fallthrough)
#else
#  define FALL_THROUGH		((void)0)
#endif

#ifndef NDEBUG
#  define NDEBUG_UNUSED
#else
#  define NDEBUG_UNUSED		UNUSED
#endif

#define BLANK_FORMAT		" "	/* GCC_LINT whines about empty formats */

/*
 *	struct field size
 */
#define SIZEOF_MEMBER(_t, _m) sizeof(((_t *)0)->_m)
#define NUM_ELEMENTS(_t) (sizeof((_t)) / sizeof(*(_t)))

/*
 *	Only use GCC __attribute__ if were building with a GCClike
 *	compiler.
 */
#ifdef __GNUC__
#  define CC_HINT(...)	__attribute__ ((__VA_ARGS__))
#  define likely(_x)	__builtin_expect((_x), 1)
#  define unlikely(_x)	__builtin_expect((_x), 0)
#else
#  define CC_HINT(...)
#  define likely(_x)	_x
#  define unlikely(_x)	_x
#endif

/*
 *	Macros to add pragmas
 */
#define PRAGMA(_x) _Pragma(#_x)

/*
 *	Macros for controlling warnings in GCC >= 4.2 and clang >= 2.8
 */
#if defined(__GNUC__) && ((__GNUC__ * 100) + __GNUC_MINOR__) >= 402
#  define DIAG_PRAGMA(_x) PRAGMA(GCC diagnostic _x)
#  if ((__GNUC__ * 100) + __GNUC_MINOR__) >= 406
#    define DIAG_OFF(_x) DIAG_PRAGMA(push) DIAG_PRAGMA(ignored JOINSTR(-W,_x))
#    define DIAG_ON(_x) DIAG_PRAGMA(pop)
#  else
#    define DIAG_OFF(_x) DIAG_PRAGMA(ignored JOINSTR(-W,_x))
#    define DIAG_ON(_x)  DIAG_PRAGMA(warning JOINSTR(-W,_x))
#  endif
#elif defined(__clang__) && ((__clang_major__ * 100) + __clang_minor__ >= 208)
#  define DIAG_PRAGMA(_x) PRAGMA(clang diagnostic _x)
#  define DIAG_OFF(_x) DIAG_PRAGMA(push) DIAG_PRAGMA(ignored JOINSTR(-W,_x))
#  define DIAG_ON(_x) DIAG_PRAGMA(pop)
#else
#  define DIAG_OFF(_x)
#  define DIAG_ON(_x)
#endif

/*
 *	GCC and clang use different macros
 */
#ifdef __clang__
# define DIAG_OPTIONAL DIAG_OFF(unknown-pragmas)
#else
# define DIAG_OPTIONAL DIAG_OFF(pragmas)
#endif

/*
 *	For dealing with APIs which are only deprecated in OSX (like the OpenSSL API)
 */
#ifdef __APPLE__
#  define USES_APPLE_DEPRECATED_API DIAG_OFF(deprecated-declarations)
#  define USES_APPLE_RST DIAG_ON(deprecated-declarations)
#else
#  define USES_APPLE_DEPRECATED_API
#  define USES_APPLE_RST
#endif

#if defined(__GNUC__)
/* force inclusion of ident keywords in the face of optimization */
#  define RCSID(id) static char const rcsid[] __attribute__ ((used)) = id;
#  define RCSIDH(h, id) static char const rcsid_ ## h [] __attribute__ ((used)) = id;
#elif defined(__SUNPRO_C)
/* put ident keyword into comment section (nicer than gcc way) */
#  define RCSID(id) PRAGMA(sun ident id)
#  define RCSIDH(h, id) PRAGMA(sun ident id)
#else
#  define RCSID(id)
#  define RCSIDH(h, id)
#endif
#ifdef __cplusplus
}
#endif
