#ifndef _FR_MISSING_H
#define _FR_MISSING_H

/*
 * missing.h	Replacements for functions that are or can be
 *		missing on some platforms.
 *
 * Version:	$Id$
 *
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
struct tm *localtime_r(const time_t *clock, struct tm *result);
#endif

#ifdef NEED_DECLARATION_CRYPT
char *crypt(char *key, char *salt);
#endif

#ifdef NEED_DECLARATION_STRNCASECMP
int strncasecmp(char *s1, char *s2, int n);
#endif

#ifdef NEED_DECLARATION_STRCASECMP
int strcasecmp(char *s1, char *s2);
#endif

#ifdef NEED_DECLARATION_INET_ATON
struct in_addr;
int inet_aton(char *cp, struct in_addr *inp);
#endif

#ifdef NEED_DECLARATION_GETHOSTNAME
int gethostname(char *name, int len);
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

#endif /* _FR_MISSING_H */
