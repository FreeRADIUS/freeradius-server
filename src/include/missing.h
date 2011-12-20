#ifndef _FR_MISSING_H
#define _FR_MISSING_H

/*
 * missing.h	Replacements for functions that are or can be
 *		missing on some platforms.
 *
 * Version:	$Id$
 *
 */

#include <freeradius-devel/ident.h>
RCSIDH(missing_h, "$Id$")

#include <freeradius-devel/autoconf.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include	<netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include	<arpa/inet.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef HAVE_VSNPRINTF
#include <stdarg.h>
#endif

#ifdef HAVE_SYS_LOCKING_H
#include <sys/locking.h>
#endif

/*
 *  Check for inclusion of <time.h>, versus <sys/time.h>
 *  Taken verbatim from the autoconf manual.
 */
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

/*
 *	Don't look for winsock.h if we're on cygwin.
 */
#ifndef __CYGWIN__
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#endif

#ifdef __APPLE__
#undef DARWIN
#define DARWIN (1)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	Functions from missing.c
 */

#ifndef HAVE_STRNCASECMP
extern int strncasecmp(char *s1, char *s2, int n);
#endif

#ifndef HAVE_STRCASECMP
extern int strcasecmp(char *s1, char *s2);
#endif

#ifndef HAVE_STRSEP
extern char *strsep(char **stringp, const char *delim);
#endif

#ifndef HAVE_LOCALTIME_R
struct tm;
struct tm *localtime_r(const time_t *l_clock, struct tm *result);
#endif

#ifndef HAVE_CTIME_R
char *ctime_r(const time_t *l_clock, char *l_buf);
#endif

#if defined(NEED_DECLARATION_CRYPT) || !defined(HAVE_CRYPT)
char *crypt(char *key, char *salt);
#endif

#ifdef NEED_DECLARATION_STRNCASECMP
int strncasecmp(char *s1, char *s2, int n);
#endif

#ifdef NEED_DECLARATION_STRCASECMP
int strcasecmp(char *s1, char *s2);
#endif

#if defined(NEED_DECLARATION_INET_ATON) || !defined(HAVE_INET_ATON)
struct in_addr;
int inet_aton(const char *cp, struct in_addr *inp);
#endif

#ifndef HAVE_SETLINEBUF
#ifdef HAVE_SETVBUF
#define setlinebuf(x) setvbuf(x, NULL, _IOLBF, 0)
#else
#define setlinebuf(x)     0
#endif
#endif

#ifdef NEED_DECLARATION_SETLINEBUF
#define setlinebuf(x)     0
#endif

#ifdef NEED_DECLARATION_GETUSERSHELL
char *getusershell(void);
#endif

#ifdef NEED_DECLARATION_ENDUSERSHELL
void endusershell(void);
#endif

#ifndef INADDR_ANY
#define INADDR_ANY      ((uint32_t) 0x00000000)
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK ((uint32_t) 0x7f000001) /* Inet 127.0.0.1 */
#endif

#ifndef INADDR_NONE
#define INADDR_NONE     ((uint32_t) 0xffffffff)
#endif

#ifndef INADDRSZ
#define INADDRSZ 4
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#ifndef AF_UNSPEC
#define AF_UNSPEC 0
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

#ifndef HAVE_STRUCT_IN6_ADDR
struct in6_addr
{
	union {
		uint8_t	u6_addr8[16];
		uint16_t u6_addr16[8];
		uint32_t u6_addr32[4];
	} in6_u;
#define s6_addr			in6_u.u6_addr8
#define s6_addr16		in6_u.u6_addr16
#define s6_addr32		in6_u.u6_addr32
};

#ifndef IN6ADDRSZ
#define IN6ADDRSZ 16
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

#ifndef IN6ADDR_ANY_INIT
#define IN6ADDR_ANY_INIT 	{{{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }}}
#endif

#ifndef IN6ADDR_LOOPBACK_INIT
#define IN6ADDR_LOOPBACK_INIT 	{{{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }}}
#endif

#ifndef IN6_IS_ADDR_UNSPECIFIED
#define IN6_IS_ADDR_UNSPECIFIED(a) \
	(((__const uint32_t *) (a))[0] == 0				      \
	 && ((__const uint32_t *) (a))[1] == 0				      \
	 && ((__const uint32_t *) (a))[2] == 0				      \
	 && ((__const uint32_t *) (a))[3] == 0)
#endif

#ifndef IN6_IS_ADDR_LOOPBACK
#define IN6_IS_ADDR_LOOPBACK(a) \
	(((__const uint32_t *) (a))[0] == 0				      \
	 && ((__const uint32_t *) (a))[1] == 0				      \
	 && ((__const uint32_t *) (a))[2] == 0				      \
	 && ((__const uint32_t *) (a))[3] == htonl (1))
#endif

#ifndef IN6_IS_ADDR_MULTICAST
#define IN6_IS_ADDR_MULTICAST(a) (((__const uint8_t *) (a))[0] == 0xff)
#endif

#ifndef IN6_IS_ADDR_LINKLOCAL
#define IN6_IS_ADDR_LINKLOCAL(a) \
	((((__const uint32_t *) (a))[0] & htonl (0xffc00000))		      \
	 == htonl (0xfe800000))
#endif

#ifndef IN6_IS_ADDR_SITELOCAL
#define IN6_IS_ADDR_SITELOCAL(a) \
	((((__const uint32_t *) (a))[0] & htonl (0xffc00000))		      \
	 == htonl (0xfec00000))
#endif

#ifndef IN6_IS_ADDR_V4MAPPED
#define IN6_IS_ADDR_V4MAPPED(a) \
	((((__const uint32_t *) (a))[0] == 0)				      \
	 && (((__const uint32_t *) (a))[1] == 0)			      \
	 && (((__const uint32_t *) (a))[2] == htonl (0xffff)))
#endif

#ifndef IN6_IS_ADDR_V4COMPAT
#define IN6_IS_ADDR_V4COMPAT(a) \
	((((__const uint32_t *) (a))[0] == 0)				      \
	 && (((__const uint32_t *) (a))[1] == 0)			      \
	 && (((__const uint32_t *) (a))[2] == 0)			      \
	 && (ntohl (((__const uint32_t *) (a))[3]) > 1))
#endif

#ifndef IN6_ARE_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL(a,b) \
	((((__const uint32_t *) (a))[0] == ((__const uint32_t *) (b))[0])     \
	 && (((__const uint32_t *) (a))[1] == ((__const uint32_t *) (b))[1])  \
	 && (((__const uint32_t *) (a))[2] == ((__const uint32_t *) (b))[2])  \
	 && (((__const uint32_t *) (a))[3] == ((__const uint32_t *) (b))[3]))
#endif

#endif /* HAVE_STRUCT_IN6_ADDR */

/*
 *	Functions from getaddrinfo.c
 */

#ifndef HAVE_STRUCT_SOCKADDR_STORAGE
struct sockaddr_storage
{
    uint16_t ss_family; 	/* Address family, etc.  */
    char ss_padding[128 - (sizeof(uint16_t))];
};
#endif /* HAVE_STRUCT_SOCKADDR_STORAGE */

#ifndef HAVE_STRUCT_ADDRINFO

/* for old netdb.h */
#ifndef EAI_SERVICE
#define EAI_MEMORY      2
#define EAI_FAMILY      5    /* ai_family not supported */
#define EAI_NONAME      8    /* hostname nor servname provided, or not known */
#define EAI_SERVICE     9   /* servname not supported for ai_socktype */
#endif

/* dummy value for old netdb.h */
#ifndef AI_PASSIVE
#define AI_PASSIVE      1
#define AI_CANONNAME    2
#define AI_NUMERICHOST  4
#define NI_NUMERICHOST  2
#define NI_NAMEREQD     4
#define NI_NUMERICSERV  8

struct addrinfo
{
  int ai_flags;			/* Input flags.  */
  int ai_family;		/* Protocol family for socket.  */
  int ai_socktype;		/* Socket type.  */
  int ai_protocol;		/* Protocol for socket.  */
  socklen_t ai_addrlen;		/* Length of socket address.  */
  struct sockaddr *ai_addr;	/* Socket address for socket.  */
  char *ai_canonname;		/* Canonical name for service location.  */
  struct addrinfo *ai_next;	/* Pointer to next in list.  */
};

#endif /* AI_PASSIVE */

#endif /* HAVE_STRUCT_ADDRINFO */

/* Translate name of a service location and/or a service name to set of
   socket addresses. */
#ifndef HAVE_GETADDRINFO
extern int getaddrinfo (const char *__name,
			const char *__service,
			const struct addrinfo *__req,
			struct addrinfo **__pai);

/* Free `addrinfo' structure AI including associated storage.  */
extern void freeaddrinfo (struct addrinfo *__ai);

/* Convert error return from getaddrinfo() to a string.  */
extern const char *gai_strerror (int __ecode);
#endif

/* Translate a socket address to a location and service name. */
#ifndef HAVE_GETNAMEINFO
extern int getnameinfo (const struct sockaddr *__sa,
			socklen_t __salen, char *__host,
			size_t __hostlen, char *__serv,
			size_t __servlen, unsigned int __flags);
#endif

/*
 *	Functions from snprintf.c
 */

#ifndef HAVE_VSNPRINTF
extern int vsnprintf(char *str, size_t count, const char *fmt, va_list arg);
#endif

#ifndef HAVE_SNPRINTF
extern int snprintf(char *str, size_t count, const char *fmt, ...);
#endif

/*
 *	Functions from strl{cat,cpy}.c
 */

#ifndef HAVE_STRLCPY
extern size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

#ifndef HAVE_STRLCAT
extern size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#ifndef INT16SZ
#define INT16SZ (2)
#endif

#ifndef HAVE_GMTIME_R
struct tm *gmtime_r(const time_t *l_clock, struct tm *result);
#endif

#ifndef HAVE_GETTIMEOFDAY
int gettimeofday (struct timeval *tv, void *tz);
#endif

#ifdef WIN32
#undef interface
#undef mkdir
#define mkdir(_d, _p) mkdir(_d)
#define FR_DIR_SEP '\\'
#define FR_DIR_IS_RELATIVE(p) ((*p && (p[1] != ':')) || ((*p != '\\') && (*p != '\\')))
#else
#define FR_DIR_SEP '/'
#define FR_DIR_IS_RELATIVE(p) ((*p) != '/')
#endif

#ifdef HAVE_SYS_LOCKING_H
#define lockf _locking

#define F_ULOCK _LK_UNLCK /* Unlock locked sections. */
#define F_LOCK  _LK_LOCK  /* Lock a section for exclusive use. */
#define F_TLOCK _LK_NBLCK /* Test and lock a section for exclusive use */
#define F_TEST  _LK_RLCK  /* Test section for locks by other processes. */
#endif

#ifndef offsetof
# define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

void timeval2ntp(const struct timeval *tv, uint8_t *ntp);
void ntp2timeval(struct timeval *tv, const char *ntp);

#ifdef __cplusplus
}
#endif

#endif /* _FR_MISSING_H */
