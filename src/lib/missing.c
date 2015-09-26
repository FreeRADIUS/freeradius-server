/*
 * missing.c	Replacements for functions that are or can be
 *		missing on some platforms.
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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include	<freeradius-devel/libradius.h>

#include	<ctype.h>

#if !defined(HAVE_CLOCK_GETTIME) && defined(__MACH__)
#  include <mach/mach_time.h>
#endif

#ifndef HAVE_CRYPT
char *crypt(UNUSED char *key, char *salt)
{
	/*log(L_ERR, "crypt() called but not implemented");*/
	return salt;
}
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

#ifndef HAVE_GETTIMEOFDAY
#ifdef WIN32
/*
 * Number of micro-seconds between the beginning of the Windows epoch
 * (Jan. 1, 1601) and the Unix epoch (Jan. 1, 1970).
 *
 * This assumes all Win32 compilers have 64-bit support.
 */
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS) || defined(__WATCOMC__)
#define DELTA_EPOCH_IN_USEC  11644473600000000Ui64
#else
#define DELTA_EPOCH_IN_USEC  11644473600000000ULL
#endif

static uint64_t filetime_to_unix_epoch (FILETIME const *ft)
{
	uint64_t res = (uint64_t) ft->dwHighDateTime << 32;

	res |= ft->dwLowDateTime;
	res /= 10;		   /* from 100 nano-sec periods to usec */
	res -= DELTA_EPOCH_IN_USEC;  /* from Win epoch to Unix epoch */
	return (res);
}

int gettimeofday (struct timeval *tv, UNUSED void *tz)
{
	FILETIME  ft;
	uint64_t tim;

	if (!tv) {
		errno = EINVAL;
		return (-1);
	}
	GetSystemTimeAsFileTime (&ft);
	tim = filetime_to_unix_epoch (&ft);
	tv->tv_sec  = (long) (tim / 1000000L);
	tv->tv_usec = (long) (tim % 1000000L);
	return (0);
}
#endif
#endif

#if !defined(HAVE_CLOCK_GETTIME) && defined(__MACH__)
int clock_gettime(int clk_id, struct timespec *t)
{
	static mach_timebase_info_data_t timebase;
	static bool done_init = false;

#ifdef HAVE_PTHREAD_H
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

	if (!done_init) {
#ifdef HAVE_PTHREAD_H
		pthread_mutex_lock(&mutex);
		if (!done_init) {
#endif
			mach_timebase_info(&timebase);
#ifdef HAVE_PTHREAD_H
			done_init = true;
		}
		pthread_mutex_unlock(&mutex);
#endif
	}

	switch (clk_id) {
	case CLOCK_REALTIME:
		return -1;

	case CLOCK_MONOTONIC:
	{
		uint64_t time;
		time = mach_absolute_time();
		double nseconds = ((double)time * (double)timebase.numer)/((double)timebase.denom);
		double seconds = ((double)time * (double)timebase.numer)/((double)timebase.denom * 1e9);
		t->tv_sec = seconds;
		t->tv_nsec = nseconds;
	}
		return 0;

	default:
		errno = EINVAL;
		return -1;
	}
}
#endif

#define NTP_EPOCH_OFFSET	2208988800ULL

/*
 *	Convert 'struct timeval' into NTP format (32-bit integer
 *	of seconds, 32-bit integer of fractional seconds)
 */
void
timeval2ntp(struct timeval const *tv, uint8_t *ntp)
{
	uint32_t sec, usec;

	sec = tv->tv_sec + NTP_EPOCH_OFFSET;
	usec = tv->tv_usec * 4295; /* close enough to 2^32 / USEC */
	usec -= ((tv->tv_usec * 2143) >> 16); /*  */

	sec = htonl(sec);
	usec = htonl(usec);

	memcpy(ntp, &sec, sizeof(sec));
	memcpy(ntp + sizeof(sec), &usec, sizeof(usec));
}

/*
 *	Inverse of timeval2ntp
 */
void
ntp2timeval(struct timeval *tv, char const *ntp)
{
	uint32_t sec, usec;

	memcpy(&sec, ntp, sizeof(sec));
	memcpy(&usec, ntp + sizeof(sec), sizeof(usec));

	sec = ntohl(sec);
	usec = ntohl(usec);

	tv->tv_sec = sec - NTP_EPOCH_OFFSET;
	tv->tv_usec = usec / 4295; /* close enough */
}

#if !defined(HAVE_128BIT_INTEGERS) && defined(FR_LITTLE_ENDIAN)
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

/** Call talloc strdup, setting the type on the new chunk correctly
 *
 * For some bizarre reason the talloc string functions don't set the
 * memory chunk type to char, which causes all kinds of issues with
 * verifying VALUE_PAIRs.
 *
 * @param[in] t The talloc context to hang the result off.
 * @param[in] p The string you want to duplicate.
 * @return
 *	- Duplicated string.
 *	- NULL on error.
 */
char *talloc_typed_strdup(void const *t, char const *p)
{
	char *n;

	n = talloc_strdup(t, p);
	if (!n) return NULL;
	talloc_set_type(n, char);

	return n;
}

/** Call talloc vasprintf, setting the type on the new chunk correctly
 *
 * For some bizarre reason the talloc string functions don't set the
 * memory chunk type to char, which causes all kinds of issues with
 * verifying VALUE_PAIRs.
 *
 * @param[in] t The talloc context to hang the result off.
 * @param[in] fmt The format string.
 * @return
 *	- Formatted string.
 *	- NULL on error.
 */
char *talloc_typed_asprintf(void const *t, char const *fmt, ...)
{
	char *n;
	va_list ap;

	va_start(ap, fmt);
	n = talloc_vasprintf(t, fmt, ap);
	va_end(ap);
	if (!n) return NULL;
	talloc_set_type(n, char);

	return n;
}

/** Binary safe strndup function
 *
 * @param[in] t The talloc context o allocate new buffer in.
 * @param[in] in String to dup, may contain embedded '\0'.
 * @param[in] inlen Number of bytes to dup.
 * @return duped string.
 */
char *talloc_bstrndup(void const *t, char const *in, size_t inlen)
{
	char *p;

	p = talloc_array(t, char, inlen + 1);
	if (!p) return NULL;
	memcpy(p, in, inlen);
	p[inlen] = '\0';

	return p;
}

