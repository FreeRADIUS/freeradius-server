/*
 * missing.c	Replacements for functions that are or can be
 *		missing on some platforms.
 *
 * Version:	$Id$
 *
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<sys/socket.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>

#include	"missing.h"

#ifndef HAVE_CRYPT
char *crypt(char *key, char *salt)
{
	/*log(L_ERR, "crypt() called but not implemented");*/
	return "____fnord____";
}
#endif

#ifndef HAVE_STRNCASECMP
int strncasecmp(char *s1, char *s2, int n)
{
	int		dif;
	unsigned char	*p1, *p2;

	p1 = (unsigned char *)s1;
	p2 = (unsigned char *)s2;
	dif = 0;

	while (n != 0) {
		if (*p1 == 0 && *p2 == 0)
			break;
		if ((dif = s1 - s2) != 0)
			break;
		p1++;
		p2++;
		n--;
	}
	return dif;
}
#endif

#ifndef HAVE_STRCASECMP
int strcasecmp(char *s1, char *s2)
{
	int		l1, l2;

	l1 = strlen(s1);
	l2 = strlen(s2);
	if (l2 > l1) l1 = l2;

	return strncasecmp(s1, s2, l1);
}
#endif

#ifndef HAVE_INET_ATON
int inet_aton(char *cp, struct in_addr *inp)
{
	int	a1, a2, a3, a4;

	if (sscanf(cp, "%d.%d.%d.%d", &a1, &a2, &a3, &a4) != 4)
		return 0;

	inp->s_addr = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + a4);
	return 1;
}
#endif

#ifndef HAVE_GETHOSTNAME
int gethostname(char *name, int len)
{
	char		*h;

	h = getenv("HOSTNAME");
	if (strlen(h) + 1 > len)
		return -1;
	strcpy(name, h);
	return 0;
}
#endif

