/*
 * missing.h	Replacements for functions that are or can be
 *		missing on some platforms.
 *
 * Version:	$Id$
 *
 */

#ifndef HAVE_CRYPT
char *crypt(char *key, char *salt);
#endif

#ifndef HAVE_STRNCASECMP
int strncasecmp(char *s1, char *s2, int n);
#endif

#ifndef HAVE_STRCASECMP
int strcasecmp(char *s1, char *s2);
#endif

#ifndef HAVE_INET_ATON
struct in_addr;
int inet_aton(char *cp, struct in_addr *inp);
#endif

#ifndef HAVE_GETHOSTNAME
int gethostname(char *name, int len);
#endif

#ifndef HAVE_SETLINEBUF
#define setlinebuf(x)     0
#endif

