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

#ifdef __EMX__
#define OS2
/* EMX does not have SIGIOT */
#define SIGIOT SIGTERM

/* EMX does not have this functions and must be implemented */
#define strncasecmp    strncmp
#define strcasecmp    strcmp
#define inet_aton(x,y)     0
#define setlinebuf(x)     0
#define gethostname(x,y)  strncpy(x,getenv("HOSTNAME"),y)

#endif

