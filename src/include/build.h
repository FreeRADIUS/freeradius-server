/*
 * $Id$
 *
 * @brief Source control functions
 *
 * @copyright 2013 The FreeRADIUS server project
 */
#ifdef __cplusplus
extern "C" {
#endif

#ifdef __clang__
#  define DEPRECATED_OFF _Pragma("clang diagnostic push");_Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"");
#  define DEPRECATED_RST _Pragma("clang diagnostic pop");
#elif __GNUC__
#  define DEPRECATED_OFF _Pragma("gcc diagnostic push");_Pragma("gcc diagnostic ignored \"-Wdeprecated-declarations\"");
#  define DEPRECATED_RST _Pragma("gcc diagnostic pop");
#else
#  define DEPRECATED_OFF
#  define DEPRECATED_RST
#endif

/*
 *	For dealing with APIs which are only deprecated in OSX (like the OpenSSL API)
 */
#ifdef __APPLE__
#  define USES_APPLE_DEPRECATED_API DEPRECATED_OFF
#else
#  define USES_APPLE_DEPRECATED_API
#endif

#if defined(__GNUC__)
/* force inclusion of ident keywords in the face of optimization */
#define RCSID(id) static const char rcsid[] __attribute__ ((used)) = id;
#define RCSIDH(h, id) static const char rcsid_ ## h [] __attribute__ ((used)) = id;
#elif defined(__SUNPRO_C)
/* put ident keyword into comment section (nicer than gcc way) */
#define DO_PRAGMA(x) _Pragma(#x)
#define RCSID(id) DO_PRAGMA(sun ident id)
#define RCSIDH(h, id) DO_PRAGMA(sun ident id)
#else
#define RCSID(id)
#define RCSIDH(h, id)
#endif

#ifdef __cplusplus
}
#endif
