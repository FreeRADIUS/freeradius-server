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
 * @file main/conduit.c
 * @brief Channels for communicating with radmin
 *
 * @copyright 2015   The FreeRADIUS server project
 * @copyright 2015   Alan DeKok <aland@deployingradius.com>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/conduit.h>

typedef struct rconduit_t {
	uint32_t	conduit;
	uint32_t	length;
} rconduit_t;


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
ssize_t fr_conduit_drain(int fd, fr_conduit_type_t *pconduit, void *out, size_t outlen,
			 uint8_t **outbuf, ssize_t *have_read)
{
	ssize_t r;
	size_t data_len;
	uint8_t *buffer = out;
	rconduit_t hdr;
	size_t offset = *have_read;

	/*
	 *	If we can't even read a header, die.
	 */
	if (outlen <= sizeof(hdr)) {
		errno = EINVAL;
		return -1;
	}

	/*
	 *	Ensure that we read the header first.
	 */
	if (offset < sizeof(hdr)) {
		*pconduit = FR_CONDUIT_WANT_MORE;

		r = lo_read(fd, buffer + offset, sizeof(hdr) - offset);
		if (r <= 0) return r;

		*have_read += r;
		offset += r;

		if (offset < sizeof(hdr)) return *have_read;
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
		*pconduit = ntohl(hdr.conduit);
		*outbuf = buffer + sizeof(hdr);
		return data_len;
	}

	*pconduit = FR_CONDUIT_WANT_MORE;
	*have_read = offset;
	return offset;
}

ssize_t fr_conduit_read(int fd, fr_conduit_type_t *pconduit, void *out, size_t outlen)
{
	ssize_t r;
	size_t data_len;
	uint8_t *buffer = out;
	rconduit_t hdr;

	/*
	 *	Read the header
	 */
	r = lo_read(fd, &hdr, sizeof(hdr));
	if (r <= 0) return r;

	/*
	 *	Read the data into the buffer.
	 */
	*pconduit = ntohl(hdr.conduit);
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
	rconduit_t hdr;
	uint8_t const *buffer = out;

	if (outlen > UINT32_MAX) {
		fr_strerror_printf("Data to write to conduit (%zu bytes) exceeds maximum length", outlen);
		return -1;
	}

	hdr.conduit = htonl(conduit);
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
