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
#include	<sys/file.h>
#include	<fcntl.h>

#include	"libradius.h"
#include	"missing.h"

int		librad_dodns = 0;
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

	if ((a = ip_addr(host)) != htonl(INADDR_NONE))
		return a;

	if ((hp = gethostbyname(host)) == NULL)
		return htonl((uint32_t) INADDR_NONE);

	/*
	 *	Paranoia from a Bind vulnerability.  An attacker
	 *	can manipulate DNS entries to change the length of the
	 *	address.  If the length isn't 4, something's wrong.
	 */
	if (hp->h_length != sizeof(uint32_t)) {
		return htonl((uint32_t) INADDR_NONE);
	}

	memcpy(&a, hp->h_addr, sizeof(uint32_t));
	return a;
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
		return INADDR_NONE;
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

/*
 * Lowercase a string
 */
void rad_lowercase(char *str) {
	char *s;

	for (s=str; *s; s++)
		if (isupper(*s)) *s = tolower(*s);
}

/*
 * Remove spaces from a string
 */
void rad_rmspace(char *str) {
	char *s = str;	
	char *ptr = str;

  while(ptr && *ptr!='\0') {
    while(isspace(*ptr))
      ptr++;
    *s = *ptr;
    ptr++;
    s++;
  }
  *s = '\0';
}

/*
 *	Internal wrapper for locking, to minimize the number of ifdef's
 *
 *	Lock an fd, prefer lockf() over flock()
 */
int rad_lockfd(int fd, int lock_len)
{
#if defined(F_LOCK) && !defined(BSD)
	return lockf(fd, F_LOCK, lock_len);
#else
	return flock(fd, LOCK_EX);
#endif
}

/*
 *	Internal wrapper for unlocking, to minimize the number of ifdef's
 *	in the source.
 *
 *	Unlock an fd, prefer lockf() over flock()
 */
int rad_unlockfd(int fd, int lock_len)
{
#if defined(F_LOCK) && !defined(BSD)
	return lockf(fd, F_ULOCK, lock_len);
#else
	return flock(fd, LOCK_UN);
#endif
}
