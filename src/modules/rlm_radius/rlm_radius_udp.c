// @todo - allow for multiple connections
// * connections have to be in a heap, sorted by most recently sent with reply, followed by # of free packets
// * need to add zombie connections in a zombie list, so that "dead" ones aren't used for new packets
// * need to check if a connection is zombie, and if so, move it to the zombie list
// * add packet retransmission timers
// * add status-server checks

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
 * @file rlm_radius_udp.c
 * @brief RADIUS UDP transport
 *
 * @copyright 2017  Network RADIUS SARL
 */
RCSID("$Id$")

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/udp.h>
#include <freeradius-devel/connection.h>
#include <freeradius-devel/rad_assert.h>

#include "rlm_radius.h"
#include "track.h"

/** Static configuration for the module.
 *
 */
typedef struct rlm_radius_udp_t {
	rlm_radius_t		*parent;		//!< rlm_radius instance

	fr_ipaddr_t		dst_ipaddr;		//!< IP of the home server
	fr_ipaddr_t		src_ipaddr;		//!< IP we open our socket on
	uint16_t		dst_port;		//!< port of the home server
	char const		*secret;		//!< shared secret

	char const		*interface;		//!< Interface to bind to.

	uint32_t		recv_buff;		//!< How big the kernel's receive buffer should be.
	uint32_t		send_buff;		//!< How big the kernel's send buffer should be.

	uint32_t		max_packet_size;	//!< maximum packet size

	bool			recv_buff_is_set;	//!< Whether we were provided with a recv_buf
	bool			send_buff_is_set;	//!< Whether we were provided with a send_buf
} rlm_radius_udp_t;


/** Per-thread configuration for the module.
 *
 *  This data structure holds the connections, etc. for this IO submodule.
 */
typedef struct rlm_radius_udp_thread_t {
	rlm_radius_udp_t	*inst;			//!< IO submodule instance
	fr_event_list_t		*el;			//!< event list

	bool			pending;		//!< are there pending requests?
	fr_dlist_t		queued;			//!< queued requests for some new connection

	fr_dlist_t		active;	       	//!< active connections
	fr_dlist_t		frozen;      	//!< frozen connections
	fr_dlist_t		opening;      	//!< opening connections
} rlm_radius_udp_thread_t;

typedef struct rlm_radius_udp_connection_t {
	rlm_radius_udp_t const	*inst;		//!< our module instance
	rlm_radius_udp_thread_t *thread;       	//!< our thread-specific data
	fr_connection_t		*conn;		//!< Connection to our destination.
	char const     		*name;		//!< from IP PORT to IP PORT

	fr_dlist_t		entry;		//!< in the linked list of connections

	struct timeval		last_sent_with_reply;	//!< most recent sent time which had a reply

	int			num_requests;	//!< number of packets we sent
	int			max_requests;	//!< maximum number of packets we can send

	bool			pending;	//!< are there packets pending?
	fr_dlist_t		queued;		//!< list of packets queued for sending
	fr_dlist_t		sent;		//!< list of sent packets

	uint32_t		max_packet_size; //!< our max packet size. may be different from the parent...
	int			fd;		//!< file descriptor

	fr_ipaddr_t		dst_ipaddr;	//!< IP of the home server. stupid 'const' issues..
	uint16_t		dst_port;	//!< port of the home server
	fr_ipaddr_t		src_ipaddr;	//!< my source IP
	uint16_t	       	src_port;	//!< my source port

	// @todo - track status-server, open, signaling, etc.

	uint8_t			*buffer;	//!< receive buffer
	size_t			buflen;		//!< receive buffer length

	rlm_radius_id_t		*id;		//!< ID tracking
} rlm_radius_udp_connection_t;


/** Link a packet to a connection
 *
 */
typedef struct rlm_radius_udp_request_t {
	fr_dlist_t		entry;		//!< in the connection list of packets

	int			code;		//!< packet code
	rlm_radius_udp_connection_t	*c;     //!< the connection
	rlm_radius_link_t	*link;		//!< more link stuff
	rlm_radius_request_t	*rr;		//!< the ID tracking, resend count, etc.

} rlm_radius_udp_request_t;


static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, rlm_radius_udp_t, dst_ipaddr), },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, rlm_radius_udp_t, dst_ipaddr) },
	{ FR_CONF_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, rlm_radius_udp_t, dst_ipaddr) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, rlm_radius_udp_t, dst_port) },

	{ FR_CONF_OFFSET("secret", FR_TYPE_STRING | FR_TYPE_REQUIRED, rlm_radius_udp_t, secret) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, rlm_radius_udp_t, interface) },

	{ FR_CONF_IS_SET_OFFSET("recv_buff", FR_TYPE_UINT32, rlm_radius_udp_t, recv_buff) },
	{ FR_CONF_IS_SET_OFFSET("send_buff", FR_TYPE_UINT32, rlm_radius_udp_t, send_buff) },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, rlm_radius_udp_t, max_packet_size),
	  .dflt = "4096" },

	{ FR_CONF_OFFSET("src_ipaddr", FR_TYPE_COMBO_IP_ADDR, rlm_radius_udp_t, src_ipaddr) },
	{ FR_CONF_OFFSET("src_ipv4addr", FR_TYPE_IPV4_ADDR, rlm_radius_udp_t, src_ipaddr) },
	{ FR_CONF_OFFSET("src_ipv6addr", FR_TYPE_IPV6_ADDR, rlm_radius_udp_t, src_ipaddr) },

	CONF_PARSER_TERMINATOR
};

static void conn_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, int fd_errno, void *uctx);
static void conn_read(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx);
static void conn_writable(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx);
static void mod_clear_backlog(rlm_radius_udp_thread_t *t);

/** Set the socket to idle
 *
 *  But keep the read event open, just in case the other end sends us
 *  data  That way we can process it.
 *
 * @param[in] c		Connection data structure
 */
static void fd_idle(rlm_radius_udp_connection_t *c)
{
	rlm_radius_udp_thread_t	*t = c->thread;

	DEBUG3("Marking socket %s as idle", c->name);
	if (fr_event_fd_insert(c->conn, t->el, c->fd,
			       conn_read, NULL, conn_error, c) < 0) {
		PERROR("Failed inserting FD event");
		talloc_free(c);
	}
}

/** Set the socket to active
 *
 * We have messages we want to send, so need to know when the socket is writable.
 *
 * @param[in] c		Connection data structure
 */
static void fd_active(rlm_radius_udp_connection_t *c)
{
	rlm_radius_udp_thread_t	*t = c->thread;

	DEBUG3("Marking socket %s as active - Draining requests", c->name);

	if (fr_event_fd_insert(c->conn, t->el, c->fd,
			       conn_read, conn_writable, conn_error, c) < 0) {
		PERROR("Failed inserting FD event");
		talloc_free(c);
	}
}


/** Connection errored
 *
 */
static void conn_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, int fd_errno, void *uctx)
{
	rlm_radius_udp_connection_t *c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);

	ERROR("Connection failed %s: %s", c->name, fr_syserror(fd_errno));

	/*
	 *	Something bad happened... Fix it...
	 */
	fr_connection_reconnect(c->conn);
}


/** Read reply packets.
 *
 */
static void conn_read(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	rlm_radius_udp_connection_t *c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);
	rlm_radius_request_t *rr;
	rlm_radius_link_t *link;
	rlm_radius_udp_request_t *u;
	REQUEST *request;
	decode_fail_t reason;
	size_t packet_len;
	ssize_t data_len;
	uint8_t original[20];

	data_len = read(fd, c->buffer, c->buflen);
	if (data_len == 0) return;

	if (data_len < 0) {
		conn_error(el, fd, 0, errno, c);
		return;
	}

	packet_len = data_len;
	if (!fr_radius_ok(c->buffer, &packet_len, false, &reason)) {
		DEBUG("Ignoring malformed packet");
		return;
	}

	rr = rr_track_find(c->id, c->buffer[1], NULL);
	if (!rr) {
		DEBUG("Ignoring response to request we did not send");
		return;
	}

	original[0] = rr->code;
	original[1] = 0;	/* not looked at by fr_radius_verify() */
	original[2] = 0;
	original[3] = 0;
	memcpy(original + 4, rr->vector, sizeof(rr->vector));

	if (fr_radius_verify(c->buffer, original,
			     (uint8_t const *) c->inst->secret, strlen(c->inst->secret)) < 0) {
		DEBUG("Ignoring response with invalid signature");
		return;
	}

	link = rr->link;
	u = link->request_io_ctx;

	/*
	 *	Track the Most Recently Sent with reply
	 */
	if (timercmp(&rr->start, &c->last_sent_with_reply, >)) {
		c->last_sent_with_reply = rr->start;
	}

	/*
	 *	Delete the tracking table entry, and remove the
	 *	request from the "sent" list for this connection.
	 */
	(void) rr_track_delete(c->id, rr);
	u->rr = NULL;
	fr_dlist_remove(&u->entry);
	rad_assert(c->num_requests > 0);
	c->num_requests--;

	request = link->request;

	// @todo - set rcode based on ACK or NAK
	link->rcode = RLM_MODULE_OK;

	// @todo - update the status of this connection

	unlang_resumable(request);
}

/** There's space available to write data, so do that...
 *
 */
static void conn_writable(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	rlm_radius_udp_connection_t *c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);
	fr_dlist_t *entry, *next;

	/*
	 *	Clear our backlog
	 */
	for (entry = FR_DLIST_FIRST(c->queued);
	     entry != NULL;
	     entry = next) {
		rlm_radius_udp_request_t *u;
		ssize_t packet_len;
		ssize_t rcode;

		next = FR_DLIST_NEXT(c->queued, entry);

		u = fr_ptr_to_type(rlm_radius_udp_request_t, entry, entry);

		packet_len = fr_radius_encode(c->buffer, c->buflen, NULL,
					      c->inst->secret, u->rr->id, u->code, 0,
					      u->link->request->packet->vps);
		if (packet_len <= 0) break;

		/*
		 *	Write the packet to the socket.  If it blocks,
		 *	stop dequeueing packets.
		 */
		rcode = write(fd, c->buffer, packet_len);
		if (rcode < 0) {
			if (errno == EWOULDBLOCK) break;

			conn_error(el, fd, 0, errno, c);
			return;
		}

		fr_dlist_remove(&u->entry);
		fr_dlist_insert_tail(&c->sent, &u->entry);
		c->num_requests++;
	}

	/*
	 *	Check if we have to enable or disable writing on the socket.
	 */
	entry = FR_DLIST_FIRST(c->queued);
	if (!entry) {
		c->pending = false;
		fd_idle(c);

	} else if (!c->pending) {
		/*
		 *	This check is here only for mod_push(), which
		 *	calls us when there are no packets pending on
		 *	a socket.  If the connection is writable, and
		 *	the write succeeds, and there's nothing more
		 *	to write, we don't need to call fd_active().
		 */
		c->pending = true;
		fd_active(c);
	}

	/*
	 *	Else c->pending was already set, and we already have fd_active().
	 */
}

/** Shutdown/close a file descriptor
 *
 */
static void conn_close(int fd, void *uctx)
{
	rlm_radius_udp_connection_t *c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);

	DEBUG3("Closing socket %s", c->name);
	if (shutdown(fd, SHUT_RDWR) < 0) DEBUG3("Shutdown on socket %s failed: %s", c->name, fr_syserror(errno));
	if (close(fd) < 0) DEBUG3("Closing socket %s failed: %s", c->name, fr_syserror(errno));

	c->fd = -1;
}

/** Process notification that fd is open
 *
 */
static fr_connection_state_t conn_open(UNUSED fr_event_list_t *el, UNUSED int fd, void *uctx)
{
	rlm_radius_udp_connection_t *c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);
	rlm_radius_udp_thread_t *t = c->thread;

	talloc_const_free(c->name);
	c->name = talloc_strdup(c, "connected");

	/*
	 *	Remove the connection from the "opening" list, and add
	 *	it to the "active" list.
	 */
	fr_dlist_remove(&c->entry);
	fr_dlist_insert_tail(&t->active, &c->entry);

	/*
	 *	If we have data pending, add the writable event immediately
	 */
	if (c->pending) {
		fd_active(c);
	} else {
		fd_idle(c);
	}

	/*
	 *	Now that we're open, also push pending requests from
	 *	the main thread queue onto the queue for this
	 *	connection.
	 */
	if (t->pending) mod_clear_backlog(t);

	return FR_CONNECTION_STATE_CONNECTED;
}


/** Initialise a new outbound connection
 *
 * @param[out] fd_out	Where to write the new file descriptor.
 * @param[in] uctx	A #rlm_radius_thread_t.
 */
static fr_connection_state_t conn_init(int *fd_out, void *uctx)
{
	int fd;
	rlm_radius_udp_connection_t *c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);

	/*
	 *	Open the outgoing socket.
	 *
	 *	@todo - pass src_ipaddr, and remove later call to fr_socket_bind()
	 *	which does return the src_port, but doesn't set the "don't fragment" bit.
	 */
	fd = fr_socket_client_udp(&c->src_ipaddr, &c->dst_ipaddr, c->dst_port, true);
	if (fd < 0) {
		DEBUG("Failed opening RADIUS client UDP socket: %s", fr_strerror());
		return FR_CONNECTION_STATE_FAILED;
	}

#if 0
	if (fr_socket_bind(fd, &io->src_ipaddr, &io->src_port, inst->interface) < 0) {
		DEBUG("Failed binding RADIUS client UDP socket: %s FD %d %pV port %u interface %s", fr_strerror(), fd, fr_box_ipaddr(io->src_ipaddr),
			io->src_port, inst->interface);
		return FR_CONNECTION_STATE_FAILED;
	}
#endif

	// @todo - set name properly
	c->name = talloc_strdup(c, "connecting...");

	// @todo - set recv_buff and send_buff socket options

	c->fd = fd;

	// @todo - initialize the tracking memory, etc.

	*fd_out = fd;

	return FR_CONNECTION_STATE_CONNECTING;
}

/** Free the connection, and return requests to the thread queue
 *
 */
static int conn_free(rlm_radius_udp_connection_t *c)
{
	fr_dlist_t *entry, *next;
	rlm_radius_udp_thread_t *t = c->thread;

	talloc_free_children(c); /* clears out FD events, timers, etc. */

	/*
	 *	Move "sent" packets back to the main thread queue
	 */
	for (entry = FR_DLIST_FIRST(c->sent);
	     entry != NULL;
	     entry = next) {
		rlm_radius_udp_request_t *u;

		next = FR_DLIST_NEXT(c->sent, entry);

		u = fr_ptr_to_type(rlm_radius_udp_request_t, entry, entry);

		u->rr = NULL;
		fr_dlist_remove(&c->entry);
		fr_dlist_insert_tail(&t->queued, &u->entry);
		t->pending = true;
	}

	/*
	 *	Move "queued" packets back to the main thread queue
	 */
	for (entry = FR_DLIST_FIRST(c->queued);
	     entry != NULL;
	     entry = next) {
		rlm_radius_udp_request_t *u;

		next = FR_DLIST_NEXT(c->queued, entry);

		u = fr_ptr_to_type(rlm_radius_udp_request_t, entry, entry);

		u->rr = NULL;
		fr_dlist_remove(&c->entry);
		fr_dlist_insert_tail(&t->queued, &u->entry);
		t->pending = true;
	}

	return 0;
}


static void mod_connection_alloc(rlm_radius_udp_t *inst, rlm_radius_udp_thread_t *t)
{
	rlm_radius_udp_connection_t *c;

	c = talloc_zero(t, rlm_radius_udp_connection_t);
	c->inst = inst;
	c->thread = t;
	c->dst_ipaddr = inst->dst_ipaddr;
	c->dst_port = inst->dst_port;
	c->src_ipaddr = inst->src_ipaddr;
	c->src_port = 0;
	c->max_packet_size = inst->max_packet_size;

	c->buffer = talloc_array(c, uint8_t, c->max_packet_size);
	if (!c->buffer) {
		talloc_free(c);
		return;
	}
	c->buflen = c->max_packet_size;

	/*
	 *	Note that each connection can have AT MOST 256 packets
	 *	outstanding, no matter what the packet code.  i.e. we
	 *	use a common ID space for all packet codes sent on
	 *	this connection.
	 *
	 *	This is the same behavior as v2 and v3.  In an ideal
	 *	world, we SHOULD be able to have separate ID spaces
	 *	for each packet code.  The problem is that the replies
	 *	don't contain the original packet codes.  Which means
	 *	looking up packets by ID is difficult.
	 */
	c->id = rr_track_create(c);
	if (!c->id) {
		talloc_free(c);
		return;
	}
	c->num_requests = 0;
	c->max_requests = 256;

	c->conn = fr_connection_alloc(c, t->el, &inst->parent->connection_timeout, &inst->parent->reconnection_delay,
				      conn_init, conn_open, conn_close, inst->parent->name, c);
	if (!c->conn) return;

	fr_connection_start(c->conn);

	fr_dlist_insert_head(&t->opening, &c->entry);

	talloc_set_destructor(c, conn_free);
}

/** Get a new connection...
 *
 * For now, there's only one connection.
 */
static rlm_radius_udp_connection_t *connection_get(rlm_radius_udp_thread_t *t, rlm_radius_udp_request_t *u)
{
	rlm_radius_udp_connection_t *c;
	fr_dlist_t *entry;

	entry = FR_DLIST_FIRST(t->active);
	if (!entry) return NULL;

	c = fr_ptr_to_type(rlm_radius_udp_connection_t, entry, entry);
	(void) talloc_get_type_abort(c, rlm_radius_udp_connection_t);

	if (c->num_requests == c->max_requests) return NULL;

	u->rr = rr_track_alloc(c->id, u->link->request, u->code, u->link);
	if (!u->rr) return NULL;

	return c;
}


/** Free an rlm_radius_udp_request_t
 *
 *  Unlink the packet from the connection, and remove any tracking
 *  entries.
 */
static int udp_request_free(rlm_radius_udp_request_t *u)
{
	fr_dlist_remove(&u->entry);

	if (u->rr) (void) rr_track_delete(u->c->id, u->rr);

	return 0;
}


static void mod_clear_backlog(rlm_radius_udp_thread_t *t)
{
	fr_dlist_t *entry, *next;

	entry = FR_DLIST_FIRST(t->active);
	if (!entry) return;

	for (entry = FR_DLIST_FIRST(t->queued);
	     entry != NULL;
	     entry = next) {
		rlm_radius_udp_request_t *u;
		rlm_radius_udp_connection_t *c;

		next = FR_DLIST_NEXT(t->queued, entry);

		u = fr_ptr_to_type(rlm_radius_udp_request_t, entry, entry);
		c = connection_get(t, u);
		if (!c) break;

		/*
		 *	Remove it from the main thread queue, and add
		 *	it to the connection queue.
		 */
		fr_dlist_remove(&u->entry);
		fr_dlist_insert_tail(&c->queued, &u->entry);

		if (!c->pending) {
			c->pending = true;
			fd_active(c);
		}
	}
}


static int mod_push(void *instance, REQUEST *request, rlm_radius_link_t *link, void *thread)
{
	rlm_radius_udp_t *inst = talloc_get_type_abort(instance, rlm_radius_udp_t);
	rlm_radius_udp_thread_t *t = talloc_get_type_abort(thread, rlm_radius_udp_thread_t);
	rlm_radius_udp_request_t *u = link->request_io_ctx;
	rlm_radius_udp_connection_t *c;

	rad_assert(request->packet->code > 0);
	rad_assert(request->packet->code < FR_MAX_PACKET_CODE);

	/*
	 *	Clear the backlog before sending any new packets.
	 *
	 *	@todo - only call mod_clear_backlog() if there are
	 *	active connections.
	 */
	if (t->pending) mod_clear_backlog(t);

	u->link = link;
	u->code = request->packet->code;

	talloc_set_destructor(u, udp_request_free);

	/*
	 *	Get a connection.  If they're all full, try to open a
	 *	new one.
	 */
	c = connection_get(t, u);
	if (!c) {
		fr_dlist_t *entry;

		entry = FR_DLIST_FIRST(t->opening);
		if (!entry) mod_connection_alloc(inst, t);

		/*
		 *	Add the request to the backlog.  It will be
		 *	sent either when the new connection is open,
		 *	or when an existing connection has
		 *	availability.
		 */
		t->pending = true;
		fr_dlist_insert_head(&t->queued, &u->entry);
		return 0;
	}

	/*
	 *	Insert it into the pending queue
	 */
	fr_dlist_insert_head(&c->queued, &u->entry);

	/*
	 *	If there are no active packets, try to write one
	 *	immediately.  This avoids a few context switches in
	 *	the case where the socket is writable.
	 *
	 *	conn_writable() will set c->pending, and call
	 *	fd_active() as necessary.
	 */
	if (!c->pending) {
		conn_writable(t->el, c->fd, 0, c);
	}

	return 0;
}


/** Bootstrap the module
 *
 * Bootstrap I/O and type submodules.
 *
 * @param[in] instance	Ctx data for this module
 * @param[in] conf    our configuration section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_bootstrap(UNUSED void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_radius_udp_t *inst = talloc_get_type_abort(instance, rlm_radius_udp_t);

	(void) talloc_set_type(inst, rlm_radius_udp_t);

	return 0;
}


/** Instantiate the module
 *
 * Instantiate I/O and type submodules.
 *
 * @param[in] instance	Ctx data for this module
 * @param[in] conf	our configuration section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(rlm_radius_t *parent, void *instance, CONF_SECTION *conf)
{
	rlm_radius_udp_t *inst = talloc_get_type_abort(instance, rlm_radius_udp_t);

	inst->parent = parent;

	/*
	 *	Ensure that we have a destination address.
	 */
	if (inst->dst_ipaddr.af == AF_UNSPEC) {
		cf_log_err(conf, "A value must be given for 'ipaddr'");
		return -1;
	}

	/*
	 *	If src_ipaddr isn't set, make sure it's INADDR_ANY, of
	 *	the same address family as dst_ipaddr.
	 */
	if (inst->src_ipaddr.af == AF_UNSPEC) {
		memset(&inst->src_ipaddr, 0, sizeof(inst->src_ipaddr));

		inst->src_ipaddr.af = inst->dst_ipaddr.af;

		if (inst->src_ipaddr.af == AF_INET) {
			inst->src_ipaddr.prefix = 32;
		} else {
			inst->src_ipaddr.prefix = 128;
		}
	}

	else if (inst->src_ipaddr.af != inst->dst_ipaddr.af) {
		cf_log_err(conf, "The 'ipaddr' and 'src_ipaddr' configuration items must be both of the same address family");
		return -1;
	}

	if (!inst->dst_port) {
		cf_log_err(conf, "A value must be given for 'port'");
		return -1;
	}

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, inst->max_packet_size);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, INT_MAX);
	}

	if (inst->send_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, >=, inst->max_packet_size);
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, <=, INT_MAX);
	}

	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 64);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65535);

	return 0;
}


/** Instantiate thread data for the submodule.
 *
 */
static int mod_thread_instantiate(UNUSED CONF_SECTION const *cs, void *instance, fr_event_list_t *el, void *thread)
{
	rlm_radius_udp_thread_t *t = thread;

	(void) talloc_set_type(t, rlm_radius_udp_thread_t);
	t->inst = instance;
	t->el = el;

	t->pending = false;
	FR_DLIST_INIT(t->queued);
	FR_DLIST_INIT(t->active);
	FR_DLIST_INIT(t->frozen);
	FR_DLIST_INIT(t->opening);

	// @todo - get parent, and initialize the list of IDs by code, from what is permitted by rlm_radius

	mod_connection_alloc(t->inst, t);

	return 0;
}

/** Destroy thread data for the IO submodule.
 *
 */
static int mod_thread_detach(void *thread)
{
	rlm_radius_udp_thread_t *t = talloc_get_type_abort(thread, rlm_radius_udp_thread_t);
	fr_dlist_t *entry;

	entry = FR_DLIST_FIRST(t->queued);
	if (entry != NULL) {
		ERROR("There are still queued requests");
		return -1;
	}

	/*
	 *	Free all of the sockets.
	 */
	talloc_free_children(t);

	entry = FR_DLIST_FIRST(t->active);
	if (entry != NULL) {
		ERROR("There are still active sockets");
		return -1;
	}

	entry = FR_DLIST_FIRST(t->opening);
	if (entry != NULL) {
		ERROR("There are still partially open sockets");
		return -1;
	}

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern fr_radius_client_io_t rlm_radius_udp;
fr_radius_client_io_t rlm_radius_udp = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_udp",
	.inst_size	= sizeof(rlm_radius_udp_t),
	.request_inst_size = sizeof(rlm_radius_udp_request_t),
	.thread_inst_size	= sizeof(rlm_radius_udp_thread_t),

	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.thread_instantiate = mod_thread_instantiate,
	.thread_detach	= mod_thread_detach,

	.push		= mod_push,
};
