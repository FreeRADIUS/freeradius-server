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
# if __STDC_VERSION__ < 202000
#  define static_assert _Static_assert
# endif
# else
#  include <assert.h>
#endif

/*
 *	Static analyzers don't notice or can't infer some properties
 *	of the code, and hence may give false positives. To deal with
 *	them, there is some conditionally compiled code in various
 *	places. The following lets the code change minimally if and
 *	when new static analyzers are added.
 */
#ifdef __clang_analyzer__
#define STATIC_ANALYZER	1
#endif
#ifdef __COVERITY__
#define STATIC_ANALYZER 1
#endif

/*
 *	Reduce spurious errors from static analyzers by having
 *	all paths that find the da to be NULL, result
 *	in program exit.
 */
#ifdef STATIC_ANALYZER
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
 *	Basic headers we want everywhere
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 *	These are compile time options to toggle whether
 *	we're building with thread support.
 *
 *	With EMSCRIPTEN threading support isn't guaranteed
 *	as many browsers have explicitly disabled support
 *	due to spectre attacks.
 */
#if (defined(__EMSCRIPTEN__) && defined(__EMSCRIPTEN_PTHREADS__)) || !defined(__EMSCRIPTEN__) && defined(HAVE_PTHREAD_H)
#  define HAVE_PTHREADS 1
#endif

/*
 *	GCC will sometimes define "unix" as well as "__unix",
 *	which gets confusing and is unnecessary.
 */
#undef unix

/** Evaluates to +1 for a > b, and -1 for a < b
 */
#define CMP_PREFER_SMALLER(_a,_b)	(((_a) > (_b)) - ((_a) < (_b)))

/** Evaluates to -1 for a > b, and +1 for a < b
 */
#define CMP_PREFER_LARGER(_a,_b)	(((_a) < (_b)) - ((_a) > (_b)))

/** Same as CMP_PREFER_SMALLER use when you don't really care about ordering, you just want _an_ ordering.
 */
#define CMP(_a, _b)			CMP_PREFER_SMALLER(_a, _b)

/** Return if the comparison is not 0 (is unequal)
 *
 * @param[in] _a	pointer to first structure.
 * @param[in] _b	pointer to second structure.
 * @param[in] _field	within the structs to compare.
 * @return The result of the comparison.
 */
#define CMP_RETURN(_a, _b, _field) \
do { \
	int8_t _ret = CMP((_a)->_field, (_b)->_field); \
	if (_ret != 0) return _ret; \
} while (0)

/** memcmp function which has similar behaviour as strncmp
 *
 * @param[in] a			First thing to compare.
 * @param[in] b			Second thing to compare.
 * @param[in] a_len		Length of first thing.
 * @param[in] b_len		Length of second thing.
 * @return
 *	- +1 if a > b
 *	- 0 if a == b
 *	- -1 if a < b
 */
static inline int8_t memcmp_return(void const *a, void const *b, size_t a_len, size_t b_len)
{
	size_t cmp_len = (a_len < b_len) ? a_len : b_len;
	int8_t l_ret = CMP(a_len, b_len);
	int8_t ret;
	ret = CMP(memcmp(a, b, cmp_len), 0);
	if (ret != 0) return ret;
	return l_ret;
}

/** Return if the contents of the specified field is not identical between the specified structures
 *
 * @param[in] _a		pointer to first structure.
 * @param[in] _b		pointer to second structure.
 * @param[in] _field		within the structs to compare.
 * @param[in] _len_field	within the structs, specifying the length of the data.
 * @return The result of the comparison.
 */
#define MEMCMP_RETURN(_a, _b, _field, _len_field) \
do { \
	int8_t _ret = memcmp_return((_a)->_field, (_b)->_field, (_a)->_len_field, (_b)->_len_field); \
	if (_ret != 0) return _ret; \
} while (0)

/** Remove const qualification from a pointer
 *
 * @param[in] _type	The non-const version of the type.
 * @param[in] _ptr	to de-const.
 */
#define UNCONST(_type, _ptr)		((_type)((uintptr_t)(_ptr)))

/** Typeof field
 *
 * @param[in] _type	struct type containing the field.
 * @param[in] _field	to return the type of.
 */
#define typeof_field(_type, _field)	__typeof__(((_type *)NULL)->_field)

/** HEX concatenation macros
 *
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

/** The ubiquitous stringify macros
 *
 */
#define XSTRINGIFY(x)	#x
#define STRINGIFY(x)	XSTRINGIFY(x)
#define JOINSTR(x,y)	XSTRINGIFY(x ## y)

/** Join two values without stringifying
 *
 * Useful for calling different macros based on the output of
*/
#define _JOIN(x,y)	x ## y
#define JOIN(x,y)	_JOIN(x,y)

/** Helper for initialising arrays of string literals
 */
#define L(_str)		{ _str, sizeof(_str) - 1 }

/** Fill macros for array initialisation
 */
#define F1(_idx, _val)		[_idx] = _val
#define F2(_idx, _val)		F1(_idx, _val), F1(_idx + 1, _val)
#define F4(_idx, _val)		F2(_idx, _val), F2(_idx + 2, _val)
#define F8(_idx, _val)		F4(_idx, _val), F4(_idx + 4, _val)
#define F16(_idx, _val)		F8(_idx, _val), F8(_idx + 8, _val)
#define F32(_idx, _val)		F16(_idx, _val), F16(_idx + 16, _val)
#define F64(_idx, _val)		F32(_idx, _val), F32(_idx + 32, _val)
#define F128(_idx, _val)	F64(_idx, _val), F64(_idx + 64, _val)
#define F256(_idx, _val)	F128(_idx, _val), F128(_idx + 128, _val)

/** Variadic macro framework
 */

/**
 * The VA_NARG macro evaluates to the number of arguments that have been
 * passed to it.
 *
 * Laurent Deniau, "__VA_NARG__," 17 January 2006, <comp.std.c> (29 November 2007).
 */
#define VA_ARG_N( \
        _1, _2, _3, _4, _5, _6, _7, _8, _9,_10,  \
        _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
        _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
        _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
        _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
        _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
        _61,_62,_63,N,...) N

#define VA_RSEQ_N() \
        63,62,61,60,                   \
        59,58,57,56,55,54,53,52,51,50, \
        49,48,47,46,45,44,43,42,41,40, \
        39,38,37,36,35,34,33,32,31,30, \
        29,28,27,26,25,24,23,22,21,20, \
        19,18,17,16,15,14,13,12,11,10, \
        9,8,7,6,5,4,3,2,1,0

#define _VA_NARG(...)   VA_ARG_N(__VA_ARGS__)

/** Return the number of variadic arguments up to 64
 *
 * @param[in] ...	Variadic arguments to count.
 */
#define VA_NARG(...)    _VA_NARG(__VA_ARGS__, VA_RSEQ_N())


/** Pass caller information to the function
 *
 */
#ifndef NDEBUG
#  define NDEBUG_LOCATION_ARGS			char const *file, int line,
#  define NDEBUG_LOCATION_VALS			file, line,
#  define NDEBUG_LOCATION_FMT			"%s[%d]: "
#  define NDEBUG_LOCATION_EXP			__FILE__, __LINE__,
#  define NDEBUG_LOCATION_NONNULL(_num)		((_num) + 2)
#else
#  define NDEBUG_LOCATION_ARGS
#  define NDEBUG_LOCATION_VALS
#  define NDEBUG_LOCATION_FMT			""
#  define NDEBUG_LOCATION_EXP
#  define NDEBUG_LOCATION_NONNULL(_num)		(_num)
#endif

/** Check if a given variable is the _const or not
 *
 * @param[in] _type	The base type of the variable (should not be marked const)
 * @param[in] _var	to check.
 */
#define IS_CONST(_type, _var) \
	_Generic((_var), \
		 _type: false, \
		 const _type: true \
	)

/** Check if a given variable is the const or unconst version of a type
 *
 * Expands to _var if _var matches type, otherwise throws a compiler error.
 *
 * Useful for creating typesafe wrapper macros around functions which take
 * void *s.
 *
 * @param[in] _type	The base type of the variable (should not be marked const)
 * @param[in] _var	to check.
 */
#define IS_TYPE(_type, _var) \
	_Generic((_var), \
		 _type: _var, \
		 const _type: _var \
	)
/*
 *	Mark variables as unused
 */
#define UNUSED_VAR(_x) ((void)_x)

/** Pad _x to the next multiple of _y
 *
 */
#define PAD(_x, _y)		(_y - ((_x) % _y))

/** Should be placed before the function return type
 *
 */
#define NEVER_RETURNS		_Noreturn
#define HIDDEN			CC_HINT(visibility("hidden"))
#define UNUSED			CC_HINT(unused)

/** clang 10 doesn't recognised the FALL-THROUGH comment anymore
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
#define NUM_ELEMENTS(_t) (sizeof((_t)) / sizeof((_t)[0]))

/*
 *	For use with multidimensional arrays where
 *	the deeper array element has a size smaller than
 *	a pointer i.e. char foo[n][m]
 */
#define NUM_PTR_ELEMENTS(_t) (sizeof((_t)) / sizeof(void *))

/*
 *	Type checking
 */

/** Check if two types are compatible (the C11 way)
 *
 * Expands to 1 if types are compatible, else 0.
 *
 * @param[in] _x pointer to check.
 * @param[in] _t type to check compatibility with.
 */
#define IS_COMPATIBLE(_x, _t) _Generic(_x, _t:1, default: 0)

/** Check if a field in a struct is compatible (the C11 way)
 *
 * Expands to 1 if types are compatible, else 0.
 *
 * @param[in] _s struct to check.
 * @param[in] _f field in struct.
 * @param[in] _t type to check compatibility with.
 */
#define IS_FIELD_COMPATIBLE(_s, _f, _t) _Generic(((_s *)0)->_f, _t:1, default: 0)

/*
 *	Only use GCC __attribute__ if were building with a GCClike
 *	compiler.
 */
#ifdef __GNUC__
#  define CC_HINT(...)		__attribute__((__VA_ARGS__))
#  define likely(_x)		__builtin_expect((_x), 1)
#  define unlikely(_x)		__builtin_expect((_x), 0)
#  define unpredictable(_x)	__builtin_unpredictable((_x))
#else
#  define CC_HINT(...)
#  define likely(_x) _x
#  define unlikely(_x) _x
#  define unpredictable(_x) _x
#endif

/*
 *	GNU version check
 */
#ifdef __GNUC__
#define	__GNUC_PREREQ__(x, y)						\
	((__GNUC__ == (x) && __GNUC_MINOR__ >= (y)) ||			\
	 (__GNUC__ > (x)))
#else
#define	__GNUC_PREREQ__(x, y)	0
#endif


/*
 *	Macros to add pragmas
 */
#define PRAGMA(_x) _Pragma(#_x)

/*
 *	Handle acquire/release macros
 */
#if defined(__clang__) && (__clang_major__ >= 13)
#  define CC_ACQUIRE_HANDLE(_tag) CC_HINT(acquire_handle(_tag))
#  define CC_USE_HANDLE(_tag) CC_HINT(use_handle(_tag))
#  define CC_RELEASE_HANDLE(_tag) CC_HINT(release_handle(_tag))
#else
#  define CC_ACQUIRE_HANDLE(_tag)
#  define CC_USE_HANDLE(_tag)
#  define CC_RELEASE_HANDLE(_tag)
#endif

/*
 *      Disable various forms of ubsan
 */
#ifndef __has_feature
#  define __has_feature(_x) 0
#endif
#if defined(__clang__) && __has_feature(undefined_behavior_sanitizer)
#  define CC_NO_UBSAN(_sanitize)        __attribute__((no_sanitize(STRINGIFY(_sanitize))))
#elif __GNUC_PREREQ__(4, 9) && defined(__SANITIZE_UNDEFINED__)
#  define CC_NO_UBSAN(_sanitize)        __attribute__((no_sanitize_undefined))
#else
#  define CC_NO_UBSAN(_sanitize)
#endif

/*
 *	Disable sanitizers for undefined behaviour
 */
#if defined(__clang__)
#  define CC_NO_SANITIZE_UNDEFINED(_what) CC_HINT(no_sanitize(_what))
#else
#  define CC_NO_SANITIZE_UNDEFINED(_what)
#endif

/*
 *	Macros for controlling warnings in GCC >= 4.2 and clang >= 2.8
 */
#if defined(__clang__) && ((__clang_major__ * 100) + __clang_minor__ >= 208)
#  define DIAG_UNKNOWN_PRAGMAS unknown-pragmas
#  define DIAG_PRAGMA(_x) PRAGMA(clang diagnostic _x)
#  define DIAG_OFF(_x) DIAG_PRAGMA(ignored JOINSTR(-W,_x))
#  define DIAG_ON(_x) DIAG_PRAGMA(warning JOINSTR(-W,_x))
#  define DIAG_PUSH() DIAG_PRAGMA(push)
#  define DIAG_POP() DIAG_PRAGMA(pop)
#elif !defined(__clang__) && defined(__GNUC__) && ((__GNUC__ * 100) + __GNUC_MINOR__) >= 402
#  define DIAG_UNKNOWN_PRAGMAS pragmas
#  define DIAG_PRAGMA(_x) PRAGMA(GCC diagnostic _x)
#  define DIAG_OFF(_x) DIAG_PRAGMA(ignored JOINSTR(-W,_x))
#  define DIAG_ON(_x)  DIAG_PRAGMA(warning JOINSTR(-W,_x))
#  define DIAG_PUSH() DIAG_PRAGMA(push)
#  define DIAG_POP() DIAG_PRAGMA(pop)
#else
#  define DIAG_UNKNOWN_PRAGMAS
#  define DIAG_OFF(_x)
#  define DIAG_ON(_x)
#  define DIAG_PUSH()
#  define DIAG_POP()
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

/*
 *	For closing macros which open a code block e.g. fr_rb_inorder_foreach
 */
#define endforeach }

/* Explicitly evaluate and ignore an expression
 *
 * Why this macro?
 * 1. gcc will warn about unused return values, even with the traditional cast to void.
 * 2. There are cases in which an error case wants to clean up, but the function to
 *    clean up itself returns a status. In this context you don't care, but then you
 *    have the Scylla of unused return value and the Charybdis of Coverity complaining
 *    about an if that doesn't affect control flow. The following evaluates _expr and
 *    stores it in a variable marked as unused
 * @param _expr		The expression to be evaluated and ignored
 * @param _type		The type of the expression
 */
#define IGNORE(_expr, _type) \
	do { \
		_type ignored UNUSED = (_expr); \
	} while (0)

/** Force a compilation error if strncpy() is used.
 *
 */
extern char *dont_use_strncpy(char *dst, char const *src, size_t len);
#undef strncpy
#define strncpy(_dst, _src, _len) dont_use_strncpy()
