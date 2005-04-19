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
char *ip_hostname(char *buf, size_t buflen, uint32_t ipaddr)
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
 *
 *	FIXME: DELETE THIS
 */
const char *ip_ntoa(char *buffer, uint32_t ipaddr)
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
 *
 *	FIXME: DELETE THIS
 */
uint32_t ip_addr(const char *ip_str)
{
	struct in_addr	in;

	if (inet_aton(ip_str, &in) == 0)
		return htonl(INADDR_NONE);
	return in.s_addr;
}


/*
 *	Like strncpy, but always adds \0
 */
char *strNcpy(char *dest, const char *src, int n)
{
	char *p = dest;

	while ((n > 1) && (*src)) {
		*(p++) = *(src++);

		n--;
	}
	*p = '\0';

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

/*
 *	Return an interface-id in standard colon notation
 */
char *ifid_ntoa(char *buffer, size_t size, uint8_t *ifid)
{
	snprintf(buffer, size, "%x:%x:%x:%x",
		 (ifid[0] << 8) + ifid[1], (ifid[2] << 8) + ifid[3],
		 (ifid[4] << 8) + ifid[5], (ifid[6] << 8) + ifid[7]);
	return buffer;
}


/*
 *	Return an interface-id from
 *	one supplied in standard colon notation.
 */
uint8_t *ifid_aton(const char *ifid_str, uint8_t *ifid)
{
	static const char xdigits[] = "0123456789abcdef";
	const char *p, *pch;
	int num_id = 0, val = 0, idx = 0;

	for (p = ifid_str; ; ++p) {
		if (*p == ':' || *p == '\0') {
			if (num_id <= 0)
				return NULL;

			/*
			 *	Drop 'val' into the array.
			 */
			ifid[idx] = (val >> 8) & 0xff;
			ifid[idx + 1] = val & 0xff;
			if (*p == '\0') {
				/*
				 *	Must have all entries before
				 *	end of the string.
				 */
				if (idx != 6)
					return NULL;
				break;
			}
			val = 0;
			num_id = 0;
			if ((idx += 2) > 6)
				return NULL;
		} else if ((pch = strchr(xdigits, tolower(*p))) != NULL) {
			if (++num_id > 4)
				return NULL;
			/*
			 *	Dumb version of 'scanf'
			 */
			val <<= 4;
			val |= (pch - xdigits);
		} else
			return NULL;
	}
	return ifid;
}


#ifndef HAVE_INET_PTON
/*
 *	Utility function, so that the rest of the server doesn't
 *	have ifdef's around IPv6 support
 */
int inet_pton(int af, const char *src, void *dst)
{
	if (af != AF_INET) return -1; /* unsupported */

	return inet_aton(src, dst);
}
#endif


#ifndef HAVE_INET_NTOP
/*
 *	Utility function, so that the rest of the server doesn't
 *	have ifdef's around IPv6 support
 */
const char *inet_ntop(int af, const void *src, char *dst, size_t cnt)
{
	if (af == AF_INET) {
		uint32_t ipaddr;

		if (cnt <= 15) return NULL;
		
		ipaddr = *(uint32_t *) src;
		ipaddr = ntohl(ipaddr);
		
		snprintf(dst, cnt, "%d.%d.%d.%d",
			 (ipaddr >> 24) & 0xff,
			 (ipaddr >> 16) & 0xff,
			 (ipaddr >>  8) & 0xff,
			 (ipaddr      ) & 0xff);
		return dst;
	}

	return NULL;		/* don't support IPv6 */
}
#endif


/*
 *	Wrappers for IPv4/IPv6 host to IP address lookup.
 *	This API returns only one IP address, of the specified
 *	address family.
 */
int ip_hton(const char *src, int af, lrad_ipaddr_t *dst)
{
	struct hostent	*hp;
#ifdef GETHOSTBYNAMERSTYLE
#if (GETHOSTBYNAMERSTYLE == SYSVSTYLE) || (GETHOSTBYNAMERSTYLE == GNUSTYLE)
	struct hostent result;
	int error;
	char buffer[2048];
#endif
#endif

	if (af != AF_INET) return -1; /* only IPv4 for now */

	dst->af = af;

	/*
	 *	No DNS lookups, assume it's an IP address.
	 */
	if (!librad_dodns) {
		return inet_pton(af, src, &dst->ipaddr.ip4addr);
	}
	
#ifdef GETHOSTBYNAMERSTYLE
#if GETHOSTBYNAMERSTYLE == SYSVSTYLE
	hp = gethostbyname_r(src, &result, buffer, sizeof(buffer), &error);
#elif GETHOSTBYNAMERSTYLE == GNUSTYLE
	if (gethostbyname_r(src, &result, buffer, sizeof(buffer),
			    &hp, &error) != 0) {
		return htonl(INADDR_NONE);
	}
#else
	hp = gethostbyname(src);
#endif
#else
	hp = gethostbyname(src);
#endif
	if (!hp) return -1;

	if (hp->h_addrtype != af) return -1; /* not the right address family */

	/*
	 *	Paranoia from a Bind vulnerability.  An attacker
	 *	can manipulate DNS entries to change the length of the
	 *	address.  If the length isn't 4, something's wrong.
	 */
	if (hp->h_length != 4) {
		return -1;
	}

	memcpy(&dst->ipaddr.ip4addr.s_addr, hp->h_addr,
	       sizeof(dst->ipaddr.ip4addr.s_addr));
	return 0;
	
}

/*
 *	Look IP addreses up, and print names (depending on DNS config)
 */
const char *ip_ntoh(const lrad_ipaddr_t *src, char *dst, size_t cnt)
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
	if (!librad_dodns) {
		return inet_ntop(src->af, &src->ipaddr, dst, cnt);
	}

	if (src->af != AF_INET) return NULL; /* invalid */

#ifdef GETHOSTBYADDRRSTYLE
#if GETHOSTBYADDRRSTYLE == SYSVSTYLE
	hp = gethostbyaddr_r((const char *)&src->ipaddr.ip4addr.s_addr,
			     sizeof(src->ipaddr.ip4addr.s_addr),
			     src->af, &result, buffer, sizeof(buffer), &error);
#elif GETHOSTBYADDRRSTYLE == GNUSTYLE
	if (gethostbyaddr_r((const char *)&src->ipaddr.ip4addr.s_addr,
			    sizeof(src->ipaddr.ip4addr.s_addr),
			    src->af, &result, buffer, sizeof(buffer),
			    &hp, &error) != 0) {
		hp = NULL;
	}
#else
	hp = gethostbyaddr((const char *)&src->ipaddr.ip4addr.s_addr,
			   sizeof(src->ipaddr.ip4addr.s_addr), src->af);
#endif
#else
	hp = gethostbyaddr((const char *)&src->ipaddr.ip4addr.s_addr,
			   sizeof(src->ipaddr.ip4addr.s_addr), src->af);
#endif
	if ((hp == NULL) ||
	    (strlen((char *)hp->h_name) >= cnt)) {
		return inet_ntop(src->af, &src->ipaddr, dst, cnt);
	}

	strNcpy(dst, (char *)hp->h_name, cnt);
	return dst;
}

static const char *hextab = "0123456789abcdef";

/*
 *	hex2bin
 *
 *	We allow: hex == bin
 */
int lrad_hex2bin(const unsigned char *hex, unsigned char *bin, int len)
{
	int i;
	char *c1, *c2;

	for (i = 0; i < len; i++) {
		if(!(c1 = memchr(hextab, tolower((int) hex[i << 1]), 16)) ||
		   !(c2 = memchr(hextab, tolower((int) hex[(i << 1) + 1]), 16)))
			break;
                 bin[i] = ((c1-hextab)<<4) + (c2-hextab);
	}

	return i;
}


/*
 *	bin2hex
 *
 *	If the output buffer isn't long enough, we have a buffer overflow.
 */
void lrad_bin2hex(const unsigned char *bin, unsigned char *hex, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		hex[0] = hextab[((*bin) >> 4) & 0x0f];
		hex[1] = hextab[*bin & 0x0f];
		hex += 2;
		bin++;
	}
	*hex = '\0';
	return;
}
