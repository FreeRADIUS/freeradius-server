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
 * @file conduit.c
 * @brief Channels for communicating with radmin
 *
 * @copyright 2015 The FreeRADIUS server project
 * @copyright 2015 Alan DeKok (aland@deployingradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include "conduit.h"

static ssize_t lo_read(int fd, void *out, size_t outlen)
{
	size_t total;
	ssize_t r;
	uint8_t *p = out;

	for (total = 0; total < outlen; total += r) {
		r = read(fd, p + total, outlen - total);

		if (r == 0) return 0;

		if (r < 0) {
			if (errno == EINTR) continue;

			return -1;

		}
	}

	return total;
}


/*
 *	A non-blocking copy of fr_conduit_read().
 */
ssize_t fr_conduit_read_async(int fd, fr_conduit_type_t *pconduit,
			      void *out, size_t outlen, size_t *leftover, bool *want_more)
{
	ssize_t r;
	size_t data_len;
	uint8_t *buffer = out;
	fr_conduit_hdr_t hdr;
	size_t offset = *leftover;

	/*
	 *	If we can't even read a header, die.
	 */
	if (outlen <= sizeof(hdr)) {
		errno = EINVAL;
		return -1;
	}

	*want_more = true;

	/*
	 *	Ensure that we read the header first.
	 */
	if (offset < sizeof(hdr)) {
		r = lo_read(fd, buffer + offset, sizeof(hdr) - offset);
		if (r == 0) return 0; /* closed */

		if (r < 0) {
#ifdef EWOULDBLOCK
			if (errno == EWOULDBLOCK) return 0;
#endif
#ifdef EAGAIN
			if (errno == EAGAIN) return 0;
#endif

			return r;
		}

		*leftover += r;
		offset += r;

		/*
		 *	We have leftover data, but no *packet* to
		 *	return.
		 */
		if (offset < sizeof(hdr)) return 0;
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
	if ((sizeof(hdr) + data_len) > outlen) {
		errno = EINVAL;
		return -1;
	}

	/*
	 *	This is how much we really want.
	 */
	outlen = sizeof(hdr) + data_len;

	r = lo_read(fd, buffer + offset, outlen - offset);
	if (r <= 0) return r;

	offset += r;

	if (offset == outlen) {
		*want_more = false;
		*pconduit = ntohs(hdr.conduit);
		return outlen;
	}

	*leftover = offset;
	return 0;
}

ssize_t fr_conduit_read(int fd, fr_conduit_type_t *pconduit, void *out, size_t outlen)
{
	ssize_t r;
	size_t data_len;
	uint8_t *buffer = out;
	fr_conduit_hdr_t hdr;

	/*
	 *	Read the header
	 */
	r = lo_read(fd, &hdr, sizeof(hdr));
	if (r <= 0) return r;

	/*
	 *	Read the data into the buffer.
	 */
	*pconduit = ntohs(hdr.conduit);
	data_len = ntohl(hdr.length);
	if (data_len == 0) return 0;
	if (data_len > UINT32_MAX) data_len = UINT32_MAX;	/* For Coverity */

#if 0
	fprintf(stderr, "CONDUIT R %zu length %zu\n", *pconduit, data_len);
#endif

	/*
	 *	Shrink the output buffer to the size of the data we
	 *	have.
	 */
	if (outlen > data_len) outlen = data_len;

	r = lo_read(fd, buffer, outlen);
	if (r <= 0) return r;

	/*
	 *	Read and discard any extra data sent to us.  Sorry,
	 *	caller, you should have used a larger buffer!
	 */
	while (data_len > outlen) {
		size_t discard;
		uint8_t junk[64];

		discard = data_len - outlen;
		if (discard > sizeof(junk)) discard = sizeof(junk);

		r = lo_read(fd, junk, discard);
		if (r <= 0) break;

		data_len -= r;
	}

	return outlen;
}

static ssize_t lo_write(int fd, void const *out, size_t outlen)
{
	size_t total;
	ssize_t r;
	uint8_t const *buffer = out;

	total = outlen;

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

	return outlen;
}

ssize_t fr_conduit_write(int fd, fr_conduit_type_t conduit, void const *out, size_t outlen)
{
	ssize_t r;
	fr_conduit_hdr_t hdr;
	uint8_t const *buffer = out;

	if (outlen > UINT32_MAX) {
		fr_strerror_printf("Data to write to conduit (%zu bytes) exceeds maximum length", outlen);
		return -1;
	}

	/*
	 *	Asked to write nothing, suppress it.
	 */
	if (!outlen) return 0;

	hdr.conduit = htons(conduit);
	hdr.length = htonl(outlen);

#if 0
	fprintf(stderr, "CONDUIT W %zu length %zu\n", conduit, outlen);
#endif

	/*
	 *	write the header
	 */
	r = lo_write(fd, &hdr, sizeof(hdr));
	if (r <= 0) return r;

	/*
	 *	write the data directly from the buffer
	 */
	r = lo_write(fd, buffer, outlen);
	if (r <= 0) return r;

	return outlen;
}
