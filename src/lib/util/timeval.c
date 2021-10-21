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
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/timeval.h>

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
	failed:
		fr_strerror_printf("Failed parsing \"%s\" as timeval", in);
		return -1;
	}
	tv.tv_sec = sec;
	tv.tv_usec = 0;

	if (*end && (*end != '.')) goto failed;

	if (*end == '.') {
		size_t len;

		len = strlen(end + 1);

		if (len > 6) {
			fr_strerror_const("Too much precision for timeval");
			return -1;
		}

		/*
		 *	If they write "0.1", that means
		 *	"10000" microseconds.
		 */
		sec = strtoul(end + 1, &end, 10);
		if (in == end) {
			fr_strerror_printf("Failed parsing fractional component \"%s\" of timeval", in);
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
