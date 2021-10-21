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

/*
 * $Id$
 *
 * @file src/lib/server/udp_queue.c
 * @brief Handle queues of outgoing UDP packets
 *
 * @author Alan DeKok (aland@freeradius.org)
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/syserror.h>

#include <freeradius-devel/util/socket.h>
#include <freeradius-devel/util/udp_queue.h>

struct fr_udp_queue_s {
	fr_udp_queue_config_t const *config;		//!< configuration
	fr_dlist_head_t		queue;			//!< list of queued packets to write, ordered by time

	fr_event_list_t		*el;
	int			fd;
	int			port;
	bool			blocked;		//!< are we blocked?

	fr_udp_queue_resume_t	resume;
};

typedef struct {
	struct sockaddr_storage	sockaddr;
	socklen_t	socklen;

	fr_udp_queue_t	*uq;
	fr_dlist_t	dlist;

	void		*rctx;

	fr_time_t	expires;

	size_t		packet_len;
	uint8_t		packet[];
} fr_udp_queue_entry_t;

static int _udp_queue_free(fr_udp_queue_t *uq)
{
	fr_dlist_foreach_safe(&uq->queue, fr_udp_queue_entry_t, entry) {
		talloc_free(entry);
	}}

	close(uq->fd);

	return 0;
}

static int _udp_queue_entry_free(fr_udp_queue_entry_t *entry)
{
	fr_udp_queue_t *uq = entry->uq;
	void *rctx = entry->rctx;

	fr_dlist_remove(&uq->queue, entry);

	if (uq->resume) uq->resume(false, rctx);

	return 0;
}

/** Allocate an outbound UDP queue.
 *
 * @param ctx	where the structure will be allocated.
 * @param config containing the IPs, ports, etc
 * @param el	the event list for adding events to see if the socket is writable
 * @param resume the function to call after a delayed packet has been written
 * @return
 *	- NULL on error
 *	- !NULL on success
 */
fr_udp_queue_t *fr_udp_queue_alloc(TALLOC_CTX *ctx, fr_udp_queue_config_t const *config, fr_event_list_t *el,
				   fr_udp_queue_resume_t resume)
{
	fr_udp_queue_t *uq;
	int fd;
	uint16_t port = config->port;

	/*
	 *	Open the socket.
	 */
	fd = fr_socket_server_udp(&config->ipaddr, &port, NULL, false);
	if (fd < 0) return NULL;

	/*
	 *	Set SO_REUSEPORT if we're binding to a specific port
	 *	(e.g. DHCP), so that multiple threads can use the same
	 *	port.
	 */
	if (config->port != 0) {
		int on = 1;

		if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
			fr_strerror_printf("SO_REUSEPORT said %s", fr_syserror(errno));
			goto error;
		}
	}

	/*
	 *	Bind to the given interface.
	 */
	if (config->interface &&
	    (fr_socket_bind(fd, &config->ipaddr, &port, config->interface) < 0)) goto error;

#ifdef SO_SNDBUF
	/*
	 *	Set SO_SNDBUF size, if configured to do so.
	 */
	if (config->send_buff_is_set) {
		int opt;

		opt = config->send_buff;

		if (opt < 65536) opt = 65536;
		if (opt > (1 << 30)) opt = 1<<30;

		(void) setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(int));
	}
#endif

#ifdef SO_RCVBUF
	/*
	 *	Set SO_RECVBUFF to 4K, so that the kernel will quickly
	 *	drop incoming packets.  We don't expect replies, and
	 *	we never check the socket for readability, so this is
	 *	fine.
	 */
	{
		int opt = 4096;

		(void) setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(int));
	}
#endif

	uq = talloc_zero(ctx, fr_udp_queue_t);
	if (!uq) {
	error:
		close(fd);
		return NULL;
	}

	*uq = (fr_udp_queue_t) {
		.config = config,
		.el = el,
		.fd = fd,
		.port = port,
		.resume = resume,
	};

	fr_dlist_init(&uq->queue, fr_udp_queue_entry_t, dlist);

	talloc_set_destructor(uq, _udp_queue_free);

	return uq;
}

/** If the socket is writable, then flush packets until either it
 * returns EWOULDBLOCK, or there are no more packets to write.
 *
 */
static void udp_queue_writable(UNUSED fr_event_list_t *el, UNUSED int fd,
			       UNUSED int flags, void *uctx)
{
	fr_udp_queue_t	*uq = talloc_get_type_abort(uctx, fr_udp_queue_t);
	fr_time_t	now = fr_time();

	fr_dlist_foreach_safe(&uq->queue, fr_udp_queue_entry_t, entry) {
		ssize_t rcode;
		int retries = 0;

		/*
		 *	If the entry is expired, tell the caller that
		 *	it wasn't written to the socket.
		 */
		if (fr_time_gteq(now, entry->expires)) {
			void *rctx = entry->rctx;

			talloc_free(entry);
			if (uq->resume) uq->resume(false, rctx);
			continue;
		}

	retry:
		rcode = sendto(uq->fd, entry->packet, entry->packet_len, 0, (struct sockaddr *) &entry->sockaddr, entry->socklen);
		if (rcode >= 0) {
			void *rctx = entry->rctx;

			talloc_free(entry);
			if (uq->resume) uq->resume(true, rctx);
			continue;
		}

		if (rcode < 0) {
			if (errno == EINTR) {
				if (retries++ < 3) goto retry;
				return;
			}

#if EWOULDBLOCK != EAGAIN
			if (!((errno == EWOULDBLOCK) || (errno == EAGAIN))) return;
#else
			if (errno != EWOULDBLOCK) return;
#endif
		}
	}}

	/*
	 *	Nothing more to write, delete the IO handler so that we don't get extraneous signals.
	 */
	if (fr_dlist_num_elements(&uq->queue) == 0) {
		fr_event_fd_delete(uq->el, uq->fd, FR_EVENT_FILTER_IO);
		uq->blocked = false;
	}
}

/** Write packet to socket, OR enqueue it if we get EAGAIN
 *
 *  In most cases, the packet will get written to the socket immediately.
 *
 *  However, if the socket is blocked, then the packet is added to an
 *  outbound queue.  When the socket becomes unblocked, the packets
 *  will be sent.
 *
 * @param ctx	the talloc context for this packet to be saved in, usually request_t
 * @param uq	the local queue to write it to
 * @param packet the packet to write
 * @param packet_len how long the packet is
 * @param ipaddr the IP address we're sending the packet to
 * @param port   the port we're sending the packet to
 * @param rctx   for resumption, usually request_t, or a structure which holds a request_t
 * @return
 *	- <0 for error
 *	- 0 for "didn't write it to socket, but added it to the queue, and the caller should yield"
 *	- 1 for "wrote it to the socket, you're good to go".
 */
int fr_udp_queue_write(TALLOC_CTX *ctx, fr_udp_queue_t *uq, uint8_t const *packet, size_t packet_len,
		       fr_ipaddr_t const *ipaddr, int port, void *rctx)
{
	struct sockaddr_storage	sockaddr;
	socklen_t		socklen;
	fr_udp_queue_entry_t	*entry;

	fr_ipaddr_to_sockaddr(&sockaddr, &socklen, ipaddr, port);

	if (!packet_len || !port) return 1;

	if (!uq->blocked) {
		int retries = 0;
		ssize_t rcode;

retry:
		rcode = sendto(uq->fd, packet, packet_len, 0, (struct sockaddr *) &sockaddr, socklen);
		if (rcode >= 0) return 1;

		if (rcode < 0) {
			if (errno == EINTR) {
				if (retries++ < 3) goto retry;
				return -1;
			}

#if EWOULDBLOCK != EAGAIN
			if (!((errno == EWOULDBLOCK) || (errno == EAGAIN))) return -1;
#else
			if (errno != EWOULDBLOCK) return -1;
#endif
		}

		/*
		 */
		if (fr_event_fd_insert(uq, uq->el, uq->fd, NULL,
				       udp_queue_writable, NULL, uq) < 0) {
			return -1;
		}

		uq->blocked = true;
	}

	/*
	 *	Limit the number of packets in the queue.
	 */
	if (uq->config->max_queued_packets &&
	    (fr_dlist_num_elements(&uq->queue) >= uq->config->max_queued_packets)) {
		return -1;
	}

	entry = (fr_udp_queue_entry_t *) talloc_zero_array(ctx, uint8_t, sizeof(fr_udp_queue_entry_t) + packet_len);
	if (!entry) return -1;

	talloc_set_type(entry, fr_udp_queue_entry_t);
	talloc_set_destructor(entry, _udp_queue_entry_free);

	*entry = (fr_udp_queue_entry_t) {
		.sockaddr = sockaddr,
		.socklen = socklen,
		.uq = uq,
		.expires = fr_time_add(fr_time(), uq->config->max_queued_time),
		.rctx = rctx,
		.packet_len = packet_len,
	};

	memcpy(entry->packet, packet, packet_len);
	fr_dlist_insert_tail(&uq->queue, entry);

	/*
	 *	Didn't do anything, say so.
	 */

	return 0;
}
