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
#  define W_DEPRECATED_OFF _Pragma("clang diagnostic push");_Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"");
#  define W_LITERALFMT_OFF _Pragma("clang diagnostic push");_Pragma("clang diagnostic ignored \"-Wformat-nonliteral\"");
#  define W_UNEEDEDDEC_OFF _Pragma("clang diagnostic push");_Pragma("clang diagnostic ignored \"-Wunneeded-internal-declaration\"");
#  define W_RST _Pragma("clang diagnostic pop");
#elif __GNUC__
#  define W_DEPRECATED_OFF _Pragma("GCC diagnostic push");_Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"");
#  define W_LITERALFMT_OFF _Pragma("GCC diagnostic push");_Pragma("GCC diagnostic ignored \"-Wformat-nonliteral\"");
#  define W_UNEEDEDDEC_OFF _Pragma("GCC diagnostic push");_Pragma("GCC diagnostic ignored \"-Wunneeded-internal-declaration\"");
#  define W_RST _Pragma("GCC diagnostic pop");
#else
#  define W_DEPRECATED_OFF
#  define W_LITERALFMT_OFF
#  define W_UNEEDEDDEC_OFF
#  define W_RST
#endif

/*
 *	For dealing with APIs which are only deprecated in OSX (like the OpenSSL API)
 */
#ifdef __APPLE__
#  define USES_APPLE_DEPRECATED_API W_DEPRECATED_OFF
#  define USES_APPLE_RST W_RST
#else
#  define USES_APPLE_DEPRECATED_API
#  define USES_APPLE_RST
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
