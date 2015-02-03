/*
 * radmin.c	RADIUS Administration tool.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2015   The FreeRADIUS server project
 * Copyright 2015   Alan DeKok <aland@deployingradius.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/channel.h>

typedef struct rchannel_t {
	uint32_t	channel;
	uint32_t	length;
} rchannel_t;


static ssize_t lo_read(int fd, void *inbuf, size_t buflen)
{
	size_t total;
	ssize_t r;
	uint8_t *p = inbuf;

	for (total = 0; total < buflen; total += r) {
		r = read(fd, p + total, buflen - total);

		if (r == 0) return 0;

		if (r < 0) {
			if (errno == EINTR) continue;

			return -1;

		}
	}

	return total;
}


/*
 *	A non-blocking copy of fr_channel_read().
 */
ssize_t fr_channel_drain(int fd, fr_channel_type_t *pchannel, void *inbuf, size_t buflen, uint8_t **outbuf, size_t have_read)
{
	ssize_t r;
	size_t data_len;
	uint8_t *buffer = inbuf;
	rchannel_t hdr;

	/*
	 *	If we can't even read a header, die.
	 */
	if (buflen <= sizeof(hdr)) {
		errno = EINVAL;
		return -1;
	}

	/*
	 *	Ensure that we read the header first.
	 */
	if (have_read < sizeof(hdr)) {
		*pchannel = FR_CHANNEL_WANT_MORE;

		r = lo_read(fd, buffer + have_read, sizeof(hdr) - have_read);
		if (r <= 0) return r;

		have_read += r;

		if (have_read < sizeof(hdr)) return have_read;
	}

	/*
	 *	We've read the header.  Figure out how much more data
	 *	we need to read.
	 */
	memcpy(&hdr, buffer, sizeof(hdr));
	data_len = ntohl(hdr.length);

	/*
	 *	The data will overflow the buffer.  Die.
	 */
	if ((sizeof(hdr) + data_len) > buflen) {
		errno = EINVAL;
		return -1;
	}

	/*
	 *	This is how much we really want.
	 */
	buflen = sizeof(hdr) + data_len;

	r = lo_read(fd, buffer + have_read, buflen - have_read);
	if (r <= 0) return r;

	have_read += r;

	if (have_read == buflen) {
		*pchannel = ntohl(hdr.channel);
		*outbuf = buffer + sizeof(hdr);
		return data_len;
	}

	*pchannel = FR_CHANNEL_WANT_MORE;
	return have_read;
}

ssize_t fr_channel_read(int fd, fr_channel_type_t *pchannel, void *inbuf, size_t buflen)
{
	ssize_t r;
	size_t data_len;
	uint8_t *buffer = inbuf;
	rchannel_t hdr;

	/*
	 *	Read the header
	 */
	r = lo_read(fd, &hdr, sizeof(hdr));
	if (r <= 0) return r;

	/*
	 *	Read the data into the buffer.
	 */
	*pchannel = ntohl(hdr.channel);
	data_len = ntohl(hdr.length);

#if 0
	fprintf(stderr, "CHANNEL R %zu length %zu\n", *pchannel, data_len);
#endif

	/*
	 *	Shrink the output buffer to the size of the data we
	 *	have.
	 */
	if (buflen > data_len) buflen = data_len;

	r = lo_read(fd, buffer, buflen);
	if (r <= 0) return r;

	/*
	 *	Read and discard any extra data sent to us.  Sorry,
	 *	caller, you should have used a larger buffer!
	 */
	while (data_len > buflen) {
		size_t discard;
		uint8_t junk[64];

		discard = data_len - buflen;
		if (discard > sizeof(junk)) discard = sizeof(junk);

		r = lo_read(fd, junk, discard);
		if (r <= 0) break;

		data_len -= r;
	}

	return buflen;
}

static ssize_t lo_write(int fd, void const *inbuf, size_t buflen)
{
	size_t total;
	ssize_t r;
	uint8_t const *buffer = inbuf;

	total = buflen;

	while (total > 0) {
		r = write(fd, buffer, total);
		if (r == 0) {
			errno = EAGAIN;
			return -1;
		}

		if (r < 0) {
			if (errno == EINTR) continue;

			return -1;
		}

		buffer += r;
		total -= r;
	}

	return buflen;
}

ssize_t fr_channel_write(int fd, fr_channel_type_t channel, void const *inbuf, size_t buflen)
{
	ssize_t r;
	rchannel_t hdr;
	uint8_t const *buffer = inbuf;

	hdr.channel = htonl(channel);
	hdr.length = htonl(buflen);

#if 0
	fprintf(stderr, "CHANNEL W %zu length %zu\n", channel, buflen);
#endif

	/*
	 *	write the header
	 */
	r = lo_write(fd, &hdr, sizeof(hdr));
	if (r <= 0) return r;

	/*
	 *	write the data directly from the buffer
	 */
	r = lo_write(fd, buffer, buflen);
	if (r <= 0) return r;

	return buflen;
}
