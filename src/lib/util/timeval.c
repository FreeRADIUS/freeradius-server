/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @brief Platform independent time functions
 * @file util/timeval.c
 *
 * @copyright 2019 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/timeval.h>

/** Convert a time specified in milliseconds to a timeval
 *
 * @param[out] out	Where to write the result.
 * @param[in] ms	To convert to a timeval struct.
 */
void fr_timeval_from_ms(struct timeval *out, uint64_t ms)
{
	out->tv_sec = ms / 1000;
	out->tv_usec = (ms % 1000) * 1000;
}

/** Convert a time specified in microseconds to a timeval
 *
 * @param[out] out	Where to write the result.
 * @param[in] usec	To convert to a timeval struct.
 */
void fr_timeval_from_usec(struct timeval *out, uint64_t usec)
{
	out->tv_sec = usec / USEC;
	out->tv_usec = usec % USEC;
}

/** Subtract one timeval from another
 *
 * @param[out] out Where to write difference.
 * @param[in] end Time closest to the present.
 * @param[in] start Time furthest in the past.
 */
void fr_timeval_subtract(struct timeval *out, struct timeval const *end, struct timeval const *start)
{
	out->tv_sec = end->tv_sec - start->tv_sec;
	if (out->tv_sec > 0) {
		out->tv_sec--;
		out->tv_usec = USEC;
	} else {
		out->tv_usec = 0;
	}
	out->tv_usec += end->tv_usec;
	out->tv_usec -= start->tv_usec;

	if (out->tv_usec >= USEC) {
		out->tv_usec -= USEC;
		out->tv_sec++;
	}
}

/** Add one timeval to another
 *
 * @param[out] out Where to write the sum of the two times.
 * @param[in] a first time to sum.
 * @param[in] b second time to sum.
 */
void fr_timeval_add(struct timeval *out, struct timeval const *a, struct timeval const *b)
{
	uint64_t usec;

	out->tv_sec = a->tv_sec + b->tv_sec;

	usec = a->tv_usec + b->tv_usec;
	if (usec >= USEC) {
		out->tv_sec++;
		usec -= USEC;
	}
	out->tv_usec = usec;
}

/** Divide a timeval by a divisor
 *
 * @param[out] out where to write the result of dividing in by the divisor.
 * @param[in] in Timeval to divide.
 * @param[in] divisor Integer to divide timeval by.
 */
void fr_timeval_divide(struct timeval *out, struct timeval const *in, int divisor)
{
	uint64_t x;

	x = (((uint64_t)in->tv_sec * USEC) + in->tv_usec) / divisor;

	out->tv_sec = x / USEC;
	out->tv_usec = x % USEC;
}

/** Compare two timevals
 *
 * @param[in] a First timeval.
 * @param[in] b Second timeval.
 * @return
 *	- +1 if a > b.
 *	- -1 if a < b.
 *	- 0 if a == b.
 */
int fr_timeval_cmp(struct timeval const *a, struct timeval const *b)
{
	int ret;

	ret = (a->tv_sec > b->tv_sec) - (a->tv_sec < b->tv_sec);
	if (ret != 0) return ret;

	return (a->tv_usec > b->tv_usec) - (a->tv_usec < b->tv_usec);
}

/** Create timeval from a string
 *
 * @param[out] out Where to write timeval.
 * @param[in] in String to parse.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_timeval_from_str(struct timeval *out, char const *in)
{
	int	sec;
	char	*end;
	struct	timeval tv;

	sec = strtoul(in, &end, 10);
	if (in == end) {
		fr_strerror_printf("Failed parsing \"%s\" as float", in);
		return -1;
	}
	tv.tv_sec = sec;
	tv.tv_usec = 0;
	if (*end == '.') {
		size_t len;

		len = strlen(end + 1);

		if (len > 6) {
			fr_strerror_printf("Too much precision for timeval");
			return -1;
		}

		/*
		 *	If they write "0.1", that means
		 *	"10000" microseconds.
		 */
		sec = strtoul(end + 1, &end, 10);
		if (in == end) {
			fr_strerror_printf("Failed parsing fractional component \"%s\" of float", in);
			return -1;
		}
		while (len < 6) {
			sec *= 10;
			len++;
		}
		tv.tv_usec = sec;
	}
	*out = tv;
	return 0;
}

bool fr_timeval_isset(struct timeval const *tv)
{
	if (tv->tv_sec || tv->tv_usec) return true;
	return false;
}
