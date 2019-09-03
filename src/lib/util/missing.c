/*
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Replacements for functions that are or can be missing on some platforms
 *
 * @file src/lib/util/missing.c
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/missing.h>

#include <ctype.h>
#include <pthread.h>
#include <stdbool.h>

#if !defined(HAVE_CLOCK_GETTIME) && defined(__MACH__)
#  include <mach/mach_time.h>
#endif

#ifndef HAVE_STRNCASECMP
int strncasecmp(char *s1, char *s2, int n)
{
	int		dif;
	unsigned char	*p1, *p2;
	int		c1, c2;

	p1 = (unsigned char *)s1;
	p2 = (unsigned char *)s2;
	dif = 0;

	while (n != 0) {
		if (*p1 == 0 && *p2 == 0)
			break;
		c1 = *p1;
		c2 = *p2;

		if (islower(c1)) c1 = toupper(c1);
		if (islower(c2)) c2 = toupper(c2);

		if ((dif = c1 - c2) != 0)
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


#ifndef HAVE_MEMRCHR
/** GNU libc extension on some platforms
 *
 */
void *memrchr(void const *s, int c, size_t n)
{
	uint8_t *p;

	if (n == 0) return NULL;

	memcpy(&p, &s, sizeof(p));	/* defeat const */
	for (p += (n - 1); p >= (uint8_t const *)s; p--) if (*p == (uint8_t)c) return (void *)p;

	return NULL;
}
#endif

#ifndef HAVE_INET_ATON
int inet_aton(char const *cp, struct in_addr *inp)
{
	int	a1, a2, a3, a4;

	if (sscanf(cp, "%d.%d.%d.%d", &a1, &a2, &a3, &a4) != 4)
		return 0;

	inp->s_addr = htonl((a1 << 24) + (a2 << 16) + (a3 << 8) + a4);
	return 1;
}
#endif

#ifndef HAVE_STRSEP
/*
 *	Get next token from string *stringp, where tokens are
 *	possibly-empty strings separated by characters from delim.
 *
 *	Writes NULs into the string at *stringp to end tokens.
 *	delim need not remain constant from call to call.  On
 *	return, *stringp points past the last NUL written (if there
 *	might be further tokens), or is NULL (if there are
 *	definitely no more tokens).
 *
 *	If *stringp is NULL, strsep returns NULL.
 */
char *
strsep(char **stringp, char const *delim)
{
	char *s;
	char const *spanp;
	int c, sc;
	char *tok;

	if ((s = *stringp) == NULL)
		return (NULL);

	for (tok = s;;) {
		c = *s++;
		spanp = delim;
		do {
			if ((sc = *spanp++) == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*stringp = s;
				return (tok);
			}
		} while (sc != 0);
	}

	return NULL;		/* NOTREACHED, but the compiler complains */
}
#endif

#ifndef HAVE_LOCALTIME_R
/*
 *	We use localtime_r() by default in the server.
 *
 *	For systems which do NOT have localtime_r(), we make the
 *	assumption that localtime() is re-entrant, and returns a
 *	per-thread data structure.
 *
 *	Even if localtime is NOT re-entrant, this function will
 *	lower the possibility of race conditions.
 */
struct tm *localtime_r(time_t const *l_clock, struct tm *result)
{
  memcpy(result, localtime(l_clock), sizeof(*result));

  return result;
}
#endif

#ifndef HAVE_CTIME_R
/*
 *	We use ctime_r() by default in the server.
 *
 *	For systems which do NOT have ctime_r(), we make the
 *	assumption that ctime() is re-entrant, and returns a
 *	per-thread data structure.
 *
 *	Even if ctime is NOT re-entrant, this function will
 *	lower the possibility of race conditions.
 */
char *ctime_r(time_t const *l_clock, char *l_buf)
{
  strcpy(l_buf, ctime(l_clock));

  return l_buf;
}
#endif

#ifndef HAVE_GMTIME_R
/*
 *	We use gmtime_r() by default in the server.
 *
 *	For systems which do NOT have gmtime_r(), we make the
 *	assumption that gmtime() is re-entrant, and returns a
 *	per-thread data structure.
 *
 *	Even if gmtime is NOT re-entrant, this function will
 *	lower the possibility of race conditions.
 */
struct tm *gmtime_r(time_t const *l_clock, struct tm *result)
{
  memcpy(result, gmtime(l_clock), sizeof(*result));

  return result;
}
#endif

#ifndef HAVE_VDPRINTF
int vdprintf (int fd, char const *format, va_list args)
{
	int     ret;
	FILE    *fp;
	int	dup_fd;

	dup_fd = dup(fd);
	if (dup_fd < 0) return -1;

	fp = fdopen(fd, "w");
	if (!fp) {
		close(dup_fd);
		return -1;
	}

	ret = vfprintf(fp, format, args);
	fclose(fp);	/* Also closes dup_fd */

	return ret;
}
#endif


#if !defined(HAVE_CLOCK_GETTIME) && defined(__MACH__)
int clock_gettime(int clk_id, struct timespec *t)
{
	static mach_timebase_info_data_t timebase;
	static bool done_init = false;

	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

	if (!done_init) {
		pthread_mutex_lock(&mutex);
		if (!done_init) {
			mach_timebase_info(&timebase);
			done_init = true;
		}
		pthread_mutex_unlock(&mutex);
	}

	switch (clk_id) {
	case CLOCK_REALTIME:
		return -1;

	case CLOCK_MONOTONIC:
	{
		uint64_t time;
		time = mach_absolute_time();
		double nanoseconds = ((double)time * (double)timebase.numer)/((double)timebase.denom);
		double seconds = ((double)time * (double)timebase.numer)/((double)timebase.denom * 1e9);
		t->tv_sec = seconds;
		t->tv_nsec = nanoseconds;
	}
		return 0;

	default:
		errno = EINVAL;
		return -1;
	}
}
#endif

#if !defined(HAVE_128BIT_INTEGERS) && !defined(WORDS_BIGENDIAN)
/** Swap byte order of 128 bit integer
 *
 * @param num 128bit integer to swap.
 * @return 128bit integer reversed.
 */
uint128_t ntohlll(uint128_t const num)
{
	uint64_t const *p = (uint64_t const *) &num;
	uint64_t ret[2];

	/* swapsies */
	ret[1] = ntohll(p[0]);
	ret[0] = ntohll(p[1]);

	return *(uint128_t *)ret;
}
#endif

/*
 *	Replacements in case we don't have inet_pton
 */
#ifndef HAVE_INET_PTON
static int inet_pton4(char const *src, struct in_addr *dst)
{
	int octet;
	unsigned int num;
	char const *p, *off;
	uint8_t tmp[4];
	static char const digits[] = "0123456789";

	octet = 0;
	p = src;
	while (1) {
		num = 0;
		while (*p && ((off = strchr(digits, *p)) != NULL)) {
			num *= 10;
			num += (off - digits);

			if (num > 255) return 0;

			p++;
		}
		if (!*p) break;

		/*
		 *	Not a digit, MUST be a dot, else we
		 *	die.
		 */
		if (*p != '.') {
			return 0;
		}

		tmp[octet++] = num;
		p++;
	}

	/*
	 *	End of the string.  At the fourth
	 *	octet is OK, anything else is an
	 *	error.
	 */
	if (octet != 3) {
		return 0;
	}
	tmp[3] = num;

	memcpy(dst, &tmp, sizeof(tmp));
	return 1;
}


#  ifdef HAVE_STRUCT_SOCKADDR_IN6
/** Convert presentation level address to network order binary form
 *
 * @note Does not touch dst unless it's returning 1.
 * @note :: in a full address is silently ignored.
 * @note Inspired by Mark Andrews.
 * @author Paul Vixie, 1996.
 *
 * @param src presentation level address.
 * @param dst where to write output address.
 * @return
 *	- 1 if `src' is a valid [RFC1884 2.2] address.
 *	- 0 if `src' in not a valid [RFC1884 2.2] address.
 */
static int inet_pton6(char const *src, unsigned char *dst)
{
	static char const xdigits_l[] = "0123456789abcdef",
			  xdigits_u[] = "0123456789ABCDEF";
	uint8_t tmp[IN6ADDRSZ], *tp, *endp, *colonp;
	char const *xdigits, *curtok;
	int ch, saw_xdigit;
	u_int val;

	memset((tp = tmp), 0, IN6ADDRSZ);
	endp = tp + IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		char const *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			}
			if (tp + INT16SZ > endp)
				return (0);
			*tp++ = (uint8_t) (val >> 8) & 0xff;
			*tp++ = (uint8_t) val & 0xff;
			saw_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + INADDRSZ) <= endp) &&
		    inet_pton4(curtok, (struct in_addr *) tp) > 0) {
			tp += INADDRSZ;
			saw_xdigit = 0;
			break;	/* '\0' was seen by inet_pton4(). */
		}
		return (0);
	}
	if (saw_xdigit) {
		if (tp + INT16SZ > endp)
			return (0);
		*tp++ = (uint8_t) (val >> 8) & 0xff;
		*tp++ = (uint8_t) val & 0xff;
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		int const n = tp - colonp;
		int i;

		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	/* bcopy(tmp, dst, IN6ADDRSZ); */
	memcpy(dst, tmp, IN6ADDRSZ);
	return (1);
}
#  endif

/*
 *	Utility function, so that the rest of the server doesn't
 *	have ifdef's around IPv6 support
 */
int inet_pton(int af, char const *src, void *dst)
{
	if (af == AF_INET) return inet_pton4(src, dst);

#  ifdef HAVE_STRUCT_SOCKADDR_IN6
	if (af == AF_INET6) return inet_pton6(src, dst);
#  endif
	return -1;
}
#endif	/* HAVE_INET_PTON */

#ifndef HAVE_INET_NTOP
/*
 *	Utility function, so that the rest of the server doesn't
 *	have ifdef's around IPv6 support
 */
char const *inet_ntop(int af, void const *src, char *dst, size_t cnt)
{
	if (af == AF_INET) {
		uint8_t const *ipaddr = src;

		if (cnt <= INET_ADDRSTRLEN) return NULL;

		snprintf(dst, cnt, "%d.%d.%d.%d",
			 ipaddr[0], ipaddr[1],
			 ipaddr[2], ipaddr[3]);
		return dst;
	}

	/*
	 *	If the system doesn't define this, we define it
	 *	in missing.h
	 */
	if (af == AF_INET6) {
		struct in6_addr const *ipaddr = src;

		if (cnt <= INET6_ADDRSTRLEN) return NULL;

		snprintf(dst, cnt, "%x:%x:%x:%x:%x:%x:%x:%x",
			 (ipaddr->s6_addr[0] << 8) | ipaddr->s6_addr[1],
			 (ipaddr->s6_addr[2] << 8) | ipaddr->s6_addr[3],
			 (ipaddr->s6_addr[4] << 8) | ipaddr->s6_addr[5],
			 (ipaddr->s6_addr[6] << 8) | ipaddr->s6_addr[7],
			 (ipaddr->s6_addr[8] << 8) | ipaddr->s6_addr[9],
			 (ipaddr->s6_addr[10] << 8) | ipaddr->s6_addr[11],
			 (ipaddr->s6_addr[12] << 8) | ipaddr->s6_addr[13],
			 (ipaddr->s6_addr[14] << 8) | ipaddr->s6_addr[15]);
		return dst;
	}

	return NULL;		/* don't support IPv6 */
}
#endif
