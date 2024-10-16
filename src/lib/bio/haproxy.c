/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file lib/bio/haproxy.c
 * @brief BIO abstractions for HA proxy protocol interceptors
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/null.h>
#include <freeradius-devel/bio/buf.h>

#include <freeradius-devel/bio/haproxy.h>

#define HAPROXY_HEADER_V1_SIZE (108)

/** The haproxy bio
 *
 */
typedef struct {
	FR_BIO_COMMON;

	fr_bio_haproxy_info_t info;	//!< Information about the "real" client which has connected.
					// @todo - for v2 of the haproxy protocol, add TLS parameters!

	fr_bio_buf_t	buffer;		//!< intermediate buffer to read the haproxy header

	bool		available;	//!< is the haxproxy header available and done
} fr_bio_haproxy_t;

/** Parse the haproxy header, version 1.
 *
 */
static ssize_t fr_bio_haproxy_v1(fr_bio_haproxy_t *my)
{
	int af, argc, port;
	ssize_t rcode;
	uint8_t *p, *end;
	char *eos, *argv[5] = {};

	p = my->buffer.read;
	end = my->buffer.write;

	/*
	 *	We only support v1, and only TCP.
	 */
	if (memcmp(my->buffer.read, "PROXY TCP", 9) != 0) {
	fail:
		fr_bio_shutdown(&my->bio);
		return fr_bio_error(VERIFY);
	}
	p += 9;

	if (*p == '4') {
		af = AF_INET;

	} else if (*p == '6') {
		af = AF_INET6;

	} else {
		goto fail;
	}
	p++;

	if (*(p++) != ' ') goto fail;

	argc = 0;
	rcode = -1;
	while (p < end) {
		if (*p > ' ') {
			if (argc > 4) goto fail;

			argv[argc++] = (char *) p;

			while ((*p > ' ') && (p < end)) p++;
			continue;
		}

		if (*p < ' ') {
			if ((end - p) < 3) goto fail;

			if (memcmp(p, "\r\n", 3) != 0) goto fail;

			*p = '\0';
			end = p + 3;
			rcode = 0;
			break;
		}

		if (*p != ' ') goto fail;

		*(p++) = '\0';
	}
	
	/*
	 *	Didn't end with CRLF and zero.
	 */
	if (rcode < 0) {
		fr_strerror_const("haproxy v1 header did not end with CRLF");
		goto fail;
	}

	/*
	 *
	 */
	if (argc != 4) {
		fr_strerror_const("haproxy v1 header did not have 4 parameters");
		goto fail;
	}

	if (fr_inet_pton(&my->info.socket.inet.src_ipaddr, argv[0], -1, af, false, false) < 0) goto fail;
	if (fr_inet_pton(&my->info.socket.inet.dst_ipaddr, argv[1], -1, af, false, false) < 0) goto fail;

	port = strtoul(argv[2], &eos, 10);
	if (port > 65535) goto fail;
	if (*eos) goto fail;
	my->info.socket.inet.src_port = port;

	port = strtoul(argv[3], &eos, 10);
	if (port > 65535) goto fail;
	if (*eos) goto fail;
	my->info.socket.inet.dst_port = port;

	/*
	 *	Return how many bytes we read.  The remainder are for the application.
	 */
	return (end - my->buffer.read);
}

/** Satisfy reads from the "next" bio
 *
 *  The caveat is that there may be data left in our buffer which is needed for the application.  We can't
 *  unchain ourselves until we've returned that data to the application, and emptied our buffer.
 */
static ssize_t fr_bio_haproxy_read_next(fr_bio_t *bio, UNUSED void *packet_ctx, void *buffer, size_t size)
{
	size_t used;
	fr_bio_haproxy_t *my = talloc_get_type_abort(bio, fr_bio_haproxy_t);

	my->available = true;

	used = fr_bio_buf_used(&my->buffer);

	/*
	 *	Somehow (magically) we can satisfy the read from our buffer.  Do so.  Note that we do NOT run
	 *	the connected callback, as there is still data in our buffer
	 */
	if (size < used) {
		(void) fr_bio_buf_read(&my->buffer, buffer, size);
		return size;
	}

	/*
	 *	We are asked to empty the buffer.  Copy the data to the caller.
	 */
	(void) fr_bio_buf_read(&my->buffer, buffer, used);

	/*
	 *	Call the users "socket is now usable" function, which might remove us from the proxy chain.
	 */
	if (my->cb.connected) my->cb.connected(bio);

	return used;
}

/** Read from the next bio, and determine if we have an haproxy header.
 *
 */
static ssize_t fr_bio_haproxy_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_haproxy_t *my = talloc_get_type_abort(bio, fr_bio_haproxy_t);
	fr_bio_t *next;

	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	fr_assert(fr_bio_buf_write_room(&my->buffer) > 0);

	rcode = next->read(next, NULL, my->buffer.read, fr_bio_buf_write_room(&my->buffer));
	if (rcode <= 0) return rcode;

	/*
	 *	Not enough room for a full v1 header, tell the caller
	 *	that no data was read.  The caller should call us
	 *	again when the underlying FD is readable.
	 */
	if (fr_bio_buf_used(&my->buffer) < 16) return 0;

	/*
	 *	Process haproxy protocol v1 header.
	 */
	rcode = fr_bio_haproxy_v1(my);
	if (rcode <= 0) return rcode;

	/*
	 *	We've read a number of bytes from our buffer.  The remaining ones are for the application.
	 */
	(void) fr_bio_buf_read(&my->buffer, NULL, rcode);
	my->bio.read = fr_bio_haproxy_read_next;

	return fr_bio_haproxy_read_next(bio, packet_ctx, buffer, size);
}

/** Allocate an haproxy bio.
 *
 */
fr_bio_t *fr_bio_haproxy_alloc(TALLOC_CTX *ctx, fr_bio_cb_funcs_t *cb, fr_bio_t *next)
{
	fr_bio_haproxy_t *my;

	my = talloc_zero(ctx, fr_bio_haproxy_t);
	if (!my) return NULL;

	if (fr_bio_buf_alloc(my, &my->buffer, HAPROXY_HEADER_V1_SIZE) < 0) {
		talloc_free(my);
		return NULL;
	}

	my->bio.read = fr_bio_haproxy_read;
	my->bio.write = fr_bio_null_write; /* can't write to this bio */
	my->cb = *cb;

	fr_bio_chain(&my->bio, next);

	talloc_set_destructor((fr_bio_t *) my, fr_bio_destructor);
	return (fr_bio_t *) my;
}

/** Get client information from the haproxy bio.
 *
 */
fr_bio_haproxy_info_t const *fr_bio_haproxy_info(fr_bio_t *bio)
{
	fr_bio_haproxy_t *my = talloc_get_type_abort(bio, fr_bio_haproxy_t);

	if (!my->available) return NULL;

	return &my->info;
}
