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
#include	<netinet/in.h>
#include	<arpa/inet.h>

#include	<stdlib.h>
#include	<string.h>
#include	<netdb.h>
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
char * ip_hostname(char *buf, size_t buflen, uint32_t ipaddr)
{
	struct		hostent *hp;

	/*
	 *	No DNS: don't look up host names
	 */
	if (!librad_dodns) {
		ip_ntoa(buf, ipaddr);
		return buf;
	}

	hp = gethostbyaddr((char *)&ipaddr, sizeof (struct in_addr), AF_INET);
	if ((hp == 0) ||
	    (strlen((char *)hp->h_name) >= buflen)) {
		ip_ntoa(buf, ipaddr);
		return buf;
	}

	strNcpy(buf, (char *)hp->h_name, buflen);
	return buf;
}


/*
 *	Return an IP address in from a host
 *	name or address in dot notation.
 */
uint32_t ip_getaddr(const char *host)
{
	struct hostent	*hp;
	uint32_t	 a;

	if ((a = ip_addr(host)) != 0)
		return a;

	if ((hp = gethostbyname(host)) == NULL)
		return (uint32_t)0;

	return (*(uint32_t *)hp->h_addr);
}


/*
 *	Return an IP address in standard dot notation
 */
char *ip_ntoa(char *buffer, uint32_t ipaddr)
{
	ipaddr = ntohl(ipaddr);

	sprintf(buffer, "%d.%d.%d.%d",
		(ipaddr >> 24) & 0xff,
		(ipaddr >> 16) & 0xff,
		(ipaddr >>  8) & 0xff,
		(ipaddr      ) & 0xff);
	return buffer;
}


/*
 *	Return an IP address from
 *	one supplied in standard dot notation.
 */
uint32_t ip_addr(const char *ip_str)
{
	struct in_addr	in;

	if (inet_aton(ip_str, &in) == 0)
		return 0;
	return in.s_addr;
}


/*
 *	Like strncpy, but always adds \0
 */
char *strNcpy(char *dest, const char *src, int n)
{
	if (n > 0)
		strncpy(dest, src, n);
	else
		n = 1;
	dest[n - 1] = 0;

	return dest;
}

