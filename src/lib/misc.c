/*
 * misc.c	Various miscellaneous functions.
 *
 * Version:	$Id$
 */

static const char rcsid[] =
"$Id$";

#include	"autoconf.h"

#include	<stdio.h>
#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>

#include	<stdlib.h>
#include	<string.h>
#include	<netdb.h>
#include	<time.h>
#include	<ctype.h>
#include	<signal.h>

#include	"libradius.h"
#include	"missing.h"

int		librad_dodns = 1;
int		librad_debug = 0;

/*
 *	Return a printable host name (or IP address in dot notation)
 *	for the supplied IP address.
 */
char * ip_hostname(UINT4 ipaddr)
{
	struct		hostent *hp;
	static char	hstname[128];

	hp = gethostbyaddr((char *)&ipaddr, sizeof (struct in_addr), AF_INET);
	if (hp == 0) {
		ip_ntoa(hstname, ipaddr);
		return(hstname);
	}
	return (char *)hp->h_name;
}


/*
 *	Return an IP address in from a host
 *	name or address in dot notation.
 */
UINT4 ip_getaddr(char *host)
{
	struct hostent	*hp;
	UINT4		a, ip_addr();

	if ((a = ip_addr(host)) != 0)
		return a;

	if ((hp = gethostbyname(host)) == NULL)
		return (UINT4)0;

	return (*(UINT4 *)hp->h_addr);
}


/*
 *	Return an IP address in standard dot notation
 */
char *ip_ntoa(char *buffer, UINT4 ipaddr)
{
	struct in_addr	in;
	char		*r;

	in.s_addr = ipaddr;
	r = inet_ntoa(in);

	if (buffer)
		strcpy(buffer, r);
	return buffer ? buffer : r;
}


/*
 *	Return an IP address from
 *	one supplied in standard dot notation.
 */
UINT4 ip_addr(char *ip_str)
{
	struct in_addr	in;

	if (inet_aton(ip_str, &in) == 0)
		return 0;
	return in.s_addr;
}


/*
 *	Like strncpy, but always adds \0
 */
char *strNcpy(char *dest, char *src, int n)
{
	if (n > 0)
		strncpy(dest, src, n);
	else
		n = 1;
	dest[n - 1] = 0;

	return dest;
}

