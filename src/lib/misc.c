/*
 * misc.c	Various miscellaneous functions.
 *
 * Version:	$Id$
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
 *
 * Copyright 2000  The FreeRADIUS server project
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
#include	<unistd.h>

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
#ifdef GETHOSTBYADDRRSTYLE
#if (GETHOSTBYADDRRSTYLE == SYSVSTYLE) || (GETHOSTBYADDRRSTYLE == GNUSTYLE)
	char buffer[2048];
	struct hostent result;
	int error;
#endif
#endif

	/*
	 *	No DNS: don't look up host names
	 */
	if (librad_dodns == 0) {
		ip_ntoa(buf, ipaddr);
		return buf;
	}

#ifdef GETHOSTBYADDRRSTYLE
#if GETHOSTBYADDRRSTYLE == SYSVSTYLE
	hp = gethostbyaddr_r((char *)&ipaddr, sizeof(struct in_addr), AF_INET, &result, buffer, sizeof(buffer), &error);
#elif GETHOSTBYADDRRSTYLE == GNUSTYLE
	if (gethostbyaddr_r((char *)&ipaddr, sizeof(struct in_addr),
			    AF_INET, &result, buffer, sizeof(buffer),
			    &hp, &error) != 0) {
		hp = NULL;
	}
#else
	hp = gethostbyaddr((char *)&ipaddr, sizeof(struct in_addr), AF_INET);
#endif
#else
	hp = gethostbyaddr((char *)&ipaddr, sizeof(struct in_addr), AF_INET);
#endif
	if ((hp == NULL) ||
	    (strlen((char *)hp->h_name) >= buflen)) {
		ip_ntoa(buf, ipaddr);
		return buf;
	}

	strNcpy(buf, (char *)hp->h_name, buflen);
	return buf;
}


/*
 *	Return an IP address from a host
 *	name or address in dot notation.
 */
uint32_t ip_getaddr(const char *host)
{
	struct hostent	*hp;
	uint32_t	 a;
#ifdef GETHOSTBYNAMERSTYLE
#if (GETHOSTBYNAMERSTYLE == SYSVSTYLE) || (GETHOSTBYNAMERSTYLE == GNUSTYLE)
	struct hostent result;
	int error;
	char buffer[2048];
#endif
#endif

	if ((a = ip_addr(host)) != htonl(INADDR_NONE))
		return a;

#ifdef GETHOSTBYNAMERSTYLE
#if GETHOSTBYNAMERSTYLE == SYSVSTYLE
	hp = gethostbyname_r(host, &result, buffer, sizeof(buffer), &error);
#elif GETHOSTBYNAMERSTYLE == GNUSTYLE
	if (gethostbyname_r(host, &result, buffer, sizeof(buffer),
			    &hp, &error) != 0) {
		return htonl(INADDR_NONE);
	}
#else
	hp = gethostbyname(host);
#endif
#else
	hp = gethostbyname(host);
#endif
	if (hp == NULL) {
		return htonl(INADDR_NONE);
	}
	
	/*
	 *	Paranoia from a Bind vulnerability.  An attacker
	 *	can manipulate DNS entries to change the length of the
	 *	address.  If the length isn't 4, something's wrong.
	 */
	if (hp->h_length != 4) {
		return htonl(INADDR_NONE);
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
		if (isupper((int) *s)) *s = tolower((int) *s);
}

/*
 * Remove spaces from a string
 */
void rad_rmspace(char *str) {
	char *s = str;	
	char *ptr = str;

  while(ptr && *ptr!='\0') {
    while(isspace((int) *ptr))
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
#elif defined(LOCK_EX)
	return flock(fd, LOCK_EX);
#else
	struct flock fl;
	fl.l_start = 0;
	fl.l_len = lock_len;
	fl.l_pid = getpid();
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_CUR;
	return fcntl(fd, F_SETLKW, (void *)&fl);
#endif
}

/*
 *	Internal wrapper for locking, to minimize the number of ifdef's
 *
 *	Lock an fd, prefer lockf() over flock()
 *	Nonblocking version.
 */
int rad_lockfd_nonblock(int fd, int lock_len)
{
#if defined(F_LOCK) && !defined(BSD)
	return lockf(fd, F_TLOCK, lock_len);
#elif defined(LOCK_EX)
	return flock(fd, LOCK_EX | LOCK_NB);
#else
	struct flock fl;
	fl.l_start = 0;
	fl.l_len = lock_len;
	fl.l_pid = getpid();
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_CUR;
	return fcntl(fd, F_SETLK, (void *)&fl);
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
#elif defined(LOCK_EX)
	return flock(fd, LOCK_UN);
#else
	struct flock fl;
	fl.l_start = 0;
	fl.l_len = lock_len;
	fl.l_pid = getpid();
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_CUR;
	return fcntl(fd, F_UNLCK, (void *)&fl);
#endif
}
