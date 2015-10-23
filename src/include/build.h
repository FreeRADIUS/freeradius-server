/**
 * $Id$
 *
 * @brief Source control functions
 *
 * @copyright 2013 The FreeRADIUS server project
 */
#ifndef _BUILD_H
#define _BUILD_H
#ifdef __cplusplus
extern "C" {
#endif
#include <freeradius-devel/autoconf.h> /* Needed for endian macros */

/*
 *	The ubiquitous stringify macros
 */
#define XSTRINGIFY(x) #x
#define STRINGIFY(x) XSTRINGIFY(x)
#define JOINSTR(x,y) XSTRINGIFY(x ## y)

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
 *	struct field size
 */
#define SIZEOF_MEMBER(_t, _m) sizeof(((_t *)0)->_m)

/*
 *	Only use GCC __attribute__ if were building with a GCClike
 *	compiler.
 */
#ifdef __GNUC__
#  define CC_HINT(_x) __attribute__ ((_x))
#else
#  define CC_HINT(_x)
#endif

#ifdef HAVE_ATTRIBUTE_BOUNDED
#  define CC_BOUNDED(_x, ...) CC_HINT(__bounded__(_x, ## __VA_ARGS__))
#else
#  define CC_BOUNDED(...)
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

/*
 *	Try and determine endianness of the target system.
 *
 *	Other projects seem to use endian.h and variants, but these are
 *	in non standard locations, and may mess up cross compiling.
 *
 *	Here at least the endianness can be set explicitly with
 *	-DLITTLE_ENDIAN or -DBIG_ENDIAN.
 */
#if !defined(FR_LITTLE_ENDIAN) && !defined(FR_BIG_ENDIAN)
#  if defined(__LITTLE_ENDIAN__) || \
      (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
#    define FR_LITTLE_ENDIAN 1
#  elif defined(__BIG_ENDIAN__) || \
      (defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__))
#    define FR_BIG_ENDIAN 1
#  else
#    error Failed determining endianness of system
#  endif
#endif

#ifdef __cplusplus
}
#endif
#endif /* _BUILD_H */
