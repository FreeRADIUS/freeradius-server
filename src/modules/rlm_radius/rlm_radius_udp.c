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
 * @copyright 2017 Network RADIUS SARL
 */
RCSID("$Id$")

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/util/udp.h>
#include <freeradius-devel/util/heap.h>
#include <freeradius-devel/server/connection.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/unlang/base.h>

#include "rlm_radius.h"
#include "track.h"

/** Static configuration for the module.
 *
 */
typedef struct {
	rlm_radius_t		*parent;		//!< rlm_radius instance.
	CONF_SECTION		*config;

	fr_ipaddr_t		dst_ipaddr;		//!< IP of the home server.
	fr_ipaddr_t		src_ipaddr;		//!< IP we open our socket on.
	uint16_t		dst_port;		//!< Port of the home server.
	char const		*secret;		//!< Shared secret.

	char const		*interface;		//!< Interface to bind to.

	uint32_t		recv_buff;		//!< How big the kernel's receive buffer should be.
	uint32_t		send_buff;		//!< How big the kernel's send buffer should be.

	uint32_t		max_packet_size;	//!< Maximum packet size.

	bool			recv_buff_is_set;	//!< Whether we were provided with a recv_buf
	bool			send_buff_is_set;	//!< Whether we were provided with a send_buf
	bool			replicate;		//!< Copied from parent->replicate
} rlm_radius_udp_t;


/** Per-thread configuration for the module.
 *
 *  This data structure holds the connections, etc. for this IO submodule.
 */
typedef struct {
	fr_event_list_t		*el;			//!< Event list.

	fr_heap_t		*queued;		//!< Queued requests for some new connection.

	fr_heap_t		*active;   		//!< Active connections.
	fr_dlist_head_t		blocked;      		//!< blocked connections, waiting for writable
	fr_dlist_head_t		full;      		//!< Full connections.
	fr_dlist_head_t		zombie;      		//!< Zombie connections.
	fr_dlist_head_t		opening;      		//!< Opening connections.

	uint32_t		max_connections;  //!< maximum number of open connections
	fr_time_delta_t		connection_timeout;
	fr_time_delta_t		reconnection_delay;
	fr_time_delta_t		idle_timeout;
	fr_time_delta_t		zombie_period;
} fr_io_connection_thread_t;

typedef enum fr_io_connection_state_t {
	CONN_INIT = 0,					//!< Configured but not started.
	CONN_OPENING,					//!< Trying to connect.
	CONN_ACTIVE,					//!< has free IDs
	CONN_BLOCKED,					//!< blocked, but can't write to the socket
	CONN_FULL,					//!< Live, but has no more IDs to use.
	CONN_ZOMBIE,					//!< Has had a retransmit timeout.
} fr_io_connection_state_t;

typedef struct fr_io_request_t fr_io_request_t;

/** Represents RADIUS-specific things for a connection
 *
 */
typedef struct {
	/*
	 *	The rest of the entries are RADIUS-specific
	 */
	fr_io_request_t		*status_u;    		//!< For Status-Server checks.
	rlm_radius_id_t		*id;			//!< RADIUS ID tracking structure.
	bool			status_check_blocked;	//!< if we blocked writing status check packets
} rlm_radius_udp_connection_t;


/** Represents a generic connection
 *
 */
typedef struct {
	char const     		*name;			//!< From IP PORT to IP PORT.
	char const		*module_name;		//!< the module that opened the connection
	fr_io_connection_state_t state;	//!< State of the connection.

	int			fd;			//!< File descriptor.

	rlm_radius_udp_t const	*inst;			//!< Our module instance.
	fr_io_connection_thread_t *thread;       		//!< Our thread-specific data.
	fr_connection_t		*conn;			//!< Connection to our destination.

	fr_dlist_t		entry;			//!< In the linked list of connections.
	int32_t			heap_id;		//!< For the active heap.

	fr_event_timer_t const	*idle_ev;		//!< Idle timeout event.
	fr_time_t		idle_timeout;		//!< When the idle timeout will fire.

	fr_time_t		mrs_time;		//!< Most recent sent time which had a reply.
	fr_time_t		last_reply;		//!< When we last received a reply.

	fr_event_timer_t const	*zombie_ev;		//!< Zombie timeout.

	fr_dlist_head_t		sent;			//!< List of sent packets.

	uint32_t		max_packet_size;	//!< Our max packet size. may be different from the parent.

	fr_ipaddr_t		dst_ipaddr;		//!< IP of the home server. stupid 'const' issues.
	uint16_t		dst_port;		//!< Port of the home server.
	fr_ipaddr_t		src_ipaddr;		//!< Our source IP.
	uint16_t	       	src_port;		//!< Our source port.

	uint8_t			*buffer;		//!< Receive buffer.
	size_t			buflen;			//!< Receive buffer length.

	int			slots_free;    		//!< larger is better
	void			*ctx;			//!< module-specific context
} fr_io_connection_t;


typedef enum fr_io_request_state_t {
	REQUEST_IO_STATE_INIT = 0,
	REQUEST_IO_STATE_QUEUED,				//!< in the thread queue
	REQUEST_IO_STATE_WRITTEN,				//!< in the connection "sent" heap
	REQUEST_IO_STATE_REPLIED,      			//!< timed out, or received a reply
	REQUEST_IO_STATE_DONE,				//!< and done
} fr_io_request_state_t;


/** Tracking for a REQUEST that is associated with the connection.
 *
 */
struct fr_io_request_t {
	fr_io_request_state_t	state;			//!< state of this request

	REQUEST			*request;		//!< the request we are for, so we can find it from the link

	fr_time_t		time_sent;		//!< when we sent the packet
	fr_time_t		time_recv;		//!< when we received the reply

	rlm_rcode_t		rcode;			//!< from the transport

	fr_dlist_t		entry;			//!< in the connection list of packets.
	int32_t			heap_id;		//!< for the "to be sent" queue.

	fr_io_connection_t	*c;			//!< The outbound connection
	fr_io_connection_thread_t *thread;		//!< the thread data for this request

	bool			yielded;		//!< whether it yielded

	/*
	 *	The rest of the entries are RADIUS-specific
	 */
	bool			manual_delay_time;	//!< Whether or not we manually added an Acct-Delay-Time.
	VALUE_PAIR		*extra;			//!< VPs for debugging, like Proxy-State.

	uint8_t			*acct_delay_time;	//!< in the encoded packet.
	uint32_t		initial_delay_time;	//!< Initial value of Acct-Delay-Time.

	int			code;			//!< Packet code.

	uint8_t			*packet;		//!< Packet we write to the network.
	size_t			packet_len;		//!< Length of the packet.

	rlm_radius_request_t	*rr;			//!< ID tracking, resend count, etc.
	rlm_radius_retransmit_t timer;			//!< retransmission data structures
};


static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("ipaddr", FR_TYPE_COMBO_IP_ADDR, rlm_radius_udp_t, dst_ipaddr), },
	{ FR_CONF_OFFSET("ipv4addr", FR_TYPE_IPV4_ADDR, rlm_radius_udp_t, dst_ipaddr) },
	{ FR_CONF_OFFSET("ipv6addr", FR_TYPE_IPV6_ADDR, rlm_radius_udp_t, dst_ipaddr) },

	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, rlm_radius_udp_t, dst_port) },

	{ FR_CONF_OFFSET("secret", FR_TYPE_STRING | FR_TYPE_REQUIRED, rlm_radius_udp_t, secret) },

	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, rlm_radius_udp_t, interface) },

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, rlm_radius_udp_t, recv_buff) },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, rlm_radius_udp_t, send_buff) },

	{ FR_CONF_OFFSET("max_packet_size", FR_TYPE_UINT32, rlm_radius_udp_t, max_packet_size), .dflt = "4096" },

	{ FR_CONF_OFFSET("src_ipaddr", FR_TYPE_COMBO_IP_ADDR, rlm_radius_udp_t, src_ipaddr) },
	{ FR_CONF_OFFSET("src_ipv4addr", FR_TYPE_IPV4_ADDR, rlm_radius_udp_t, src_ipaddr) },
	{ FR_CONF_OFFSET("src_ipv6addr", FR_TYPE_IPV6_ADDR, rlm_radius_udp_t, src_ipaddr) },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_radius_udp_dict[];
fr_dict_autoload_t rlm_radius_udp_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_acct_delay_time;
static fr_dict_attr_t const *attr_error_cause;
static fr_dict_attr_t const *attr_event_timestamp;
static fr_dict_attr_t const *attr_extended_attribute_1;
static fr_dict_attr_t const *attr_message_authenticator;
static fr_dict_attr_t const *attr_nas_identifier;
static fr_dict_attr_t const *attr_original_packet_code;
static fr_dict_attr_t const *attr_proxy_state;
static fr_dict_attr_t const *attr_response_length;
static fr_dict_attr_t const *attr_user_password;
static fr_dict_attr_t const *attr_packet_type;

extern fr_dict_attr_autoload_t rlm_radius_udp_dict_attr[];
fr_dict_attr_autoload_t rlm_radius_udp_dict_attr[] = {
	{ .out = &attr_acct_delay_time, .name = "Acct-Delay-Time", .type = FR_TYPE_UINT32, .dict = &dict_radius},
	{ .out = &attr_error_cause, .name = "Error-Cause", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_event_timestamp, .name = "Event-Timestamp", .type = FR_TYPE_DATE, .dict = &dict_radius},
	{ .out = &attr_extended_attribute_1, .name = "Extended-Attribute-1", .type = FR_TYPE_EXTENDED, .dict = &dict_radius},
	{ .out = &attr_message_authenticator, .name = "Message-Authenticator", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	{ .out = &attr_nas_identifier, .name = "NAS-Identifier", .type = FR_TYPE_STRING, .dict = &dict_radius},
	{ .out = &attr_original_packet_code, .name = "Original-Packet-Code", .type = FR_TYPE_UINT32, .dict = &dict_radius},
	{ .out = &attr_proxy_state, .name = "Proxy-State", .type = FR_TYPE_OCTETS, .dict = &dict_radius},
	{ .out = &attr_response_length, .name = "Response-Length", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius},
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ NULL }
};

// ATD start
// the code to "end" is free of all RADIUS pollution.

static void conn_error(fr_event_list_t *el, int fd, int flags, int fd_errno, void *uctx);
static void conn_read(fr_event_list_t *el, int fd, int flags, void *uctx);
static void conn_writable(fr_event_list_t *el, int fd, int flags, void *uctx);
static int conn_write(fr_io_connection_t *c, fr_io_request_t *u);
static void conn_transition(fr_io_connection_t *c, fr_io_connection_state_t state);
static void state_transition(fr_io_request_t *u, fr_io_request_state_t state, fr_io_connection_t *c);
static void conn_zombie_timeout(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx);

static int8_t conn_cmp(void const *one, void const *two)
{
	fr_io_connection_t const *a = talloc_get_type_abort_const(one, fr_io_connection_t);
	fr_io_connection_t const *b = talloc_get_type_abort_const(two, fr_io_connection_t);

	if (a->mrs_time < b->mrs_time) return -1;
	if (a->mrs_time > b->mrs_time) return -1;

	if (a->slots_free < b->slots_free) return -1;
	if (a->slots_free > b->slots_free) return +1;

	return 0;
}


/** Compare two packets in the "to be sent" queue.
 *
 *  Status-Server packets are always sorted before other packets, by
 *  virtue of request->async->recv_time always being zero.
 */
static int8_t queue_cmp(void const *one, void const *two)
{
	fr_io_request_t const *a = one;
	fr_io_request_t const *b = two;

	if (a->request->async->recv_time < b->request->async->recv_time) return -1;
	if (a->request->async->recv_time > b->request->async->recv_time) return +1;

	return 0;
}


/** Close a socket due to idle timeout
 *
 */
static void conn_idle_timeout(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_io_connection_t *c = talloc_get_type_abort(uctx, fr_io_connection_t);

	DEBUG("%s - Idle timeout for connection %s", c->module_name, c->name);

	talloc_free(c);
}


/** Check if the connection is idle.
 *
 *  A connection is idle if it hasn't sent or recieved a packet in a
 *  while.  Note that "no response to packet" does NOT set the idle
 *  timeout.
 */
static void conn_check_idle(fr_io_connection_t *c)
{
	fr_time_t when;

	/*
	 *	We set idle (or not) depending on the conneciton
	 *	state.
	 */
	switch (c->state) {
	case CONN_INIT:
	case CONN_OPENING:
		rad_assert(0 == 1);
		return;

		/*
		 *	Active means "alive", and not "has packets".
		 */
	case CONN_ACTIVE:
		/*
		 *	No outstanding packets, we're idle.
		 */
		if (fr_dlist_head(&c->sent) == NULL) {
			break;
		}

		/*
		 *	Has outstanding packets, we're not idle.
		 */
		/* FALL-THROUGH */

		/*
		 *	If a connection is blocked, full, or zombie,
		 *	it's not idle.
		 */
	case CONN_BLOCKED:
	case CONN_FULL:
	case CONN_ZOMBIE:
		if (c->idle_ev) (void) fr_event_timer_delete(c->thread->el, &c->idle_ev);
		return;
	}

	/*
	 *	We've already set an idle timeout.  Don't do it again.
	 */
	if (c->idle_ev) return;

	when = fr_time();
	when += c->thread->idle_timeout;

	if (when > c->idle_timeout) {
		c->idle_timeout = when;

		DEBUG("%s - Setting idle timeout to +%u.%03u for connection %s",
		      c->module_name,
		      (uint32_t) (c->thread->idle_timeout / NSEC),
		      (uint32_t) (c->thread->idle_timeout % NSEC) / 1000000,
		      c->name);
		if (fr_event_timer_at(c, c->thread->el, &c->idle_ev, c->idle_timeout, conn_idle_timeout, c) < 0) {
			ERROR("%s - Failed inserting idle timeout for connection %s",
			      c->module_name, c->name);
		}
	}
}


static int conn_check_zombie(fr_io_connection_t *c)
{
	fr_time_t when, now;

	switch (c->state) {
		/*
		 *	If it's unused, why is there a request for it?
		 */
	case CONN_INIT:
	case CONN_OPENING:
		rad_assert(0 == 1);
		return 0;

		/*
		 *	The connection is already marked "zombie", or
		 *	is doing status checks.  Don't do it again.
		 */
	case CONN_ZOMBIE:
		return 0;

		/*
		 *	It was alive, but it might not be any longer.
		 */
	case CONN_ACTIVE:
	case CONN_FULL:
	case CONN_BLOCKED:
		break;
	}

	/*
	 *	Check if we can mark the connection as "dead".
	 */
	now = fr_time();
	when = c->last_reply;

	/*
	 *	Use the zombie_period for the timeout.
	 *
	 *	Note that we do this check on every packet, which is a
	 *	bit annoying, but oh well.
	 */
	when += c->thread->zombie_period;
	if (when > now) return 0;

	/*
	 *	The home server hasn't responded in a long time.  Mark
	 *	the connection as "zombie".
	 */
	conn_transition(c, CONN_ZOMBIE);

	return 0;
}


/** Set the socket to "nothing to write"
 *
 *  But keep the read event open, just in case the other end sends us
 *  data.  That way we can process it.
 *
 * @param[in] c		Connection data structure
 */
static void fd_idle(fr_io_connection_t *c)
{
	DEBUG3("Marking socket %s as idle", c->name);
	if (fr_event_fd_insert(c->conn, c->thread->el, c->fd,
			       conn_read,
			       NULL,
			       conn_error,
			       c) < 0) {
		PERROR("Failed inserting FD event");
		fr_connection_signal_reconnect(c->conn);
	}
}

/** Set the socket to active
 *
 * We have messages we want to send, so need to know when the socket is writable.
 *
 * @param[in] c		Connection data structure
 */
static void fd_active(fr_io_connection_t *c)
{
	DEBUG3("%s - Activating connection %s", c->module_name, c->name);

	/*
	 *	If we're writing to the connection, it's not idle.
	 */
	if (c->idle_ev) (void) fr_event_timer_delete(c->thread->el, &c->idle_ev);

	if (fr_event_fd_insert(c->conn, c->thread->el, c->fd,
			       conn_read,
			       conn_writable,
			       conn_error,
			       c) < 0) {
		PERROR("Failed inserting FD event");

		/*
		 *	May free the connection!
		 */
		fr_connection_signal_reconnect(c->conn);
	}
}

/** Connection errored
 *
 */
static void conn_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, int fd_errno, void *uctx)
{
	fr_io_connection_t *c = talloc_get_type_abort(uctx, fr_io_connection_t);

	ERROR("%s - Connection failed: %s - %s", c->module_name, fr_syserror(fd_errno), c->name);

	/*
	 *	Something bad happened... Fix it...
	 */
	fr_connection_signal_reconnect(c->conn);
}


/** Shutdown/close a file descriptor
 *
 */
static void _conn_close(int fd, void *uctx)
{
	fr_io_connection_t *c = talloc_get_type_abort(uctx, fr_io_connection_t);

	if (c->idle_ev) fr_event_timer_delete(c->thread->el, &c->idle_ev);

	if (shutdown(fd, SHUT_RDWR) < 0) {
		DEBUG3("%s - Failed shutting down connection %s: %s",
		       c->module_name, c->name, fr_syserror(errno));
	}

	if (close(fd) < 0) {
		DEBUG3("%s - Failed closing connection %s: %s",
		       c->module_name, c->name, fr_syserror(errno));
	}

	c->fd = -1;

	/*
	 *	Reset our state back to init
	 */
	conn_transition(c, CONN_INIT);

	DEBUG("%s - Connection closed - %s", c->module_name, c->name);
}


/** Initialise a new outbound connection
 *
 * @param[out] fd_out	Where to write the new file descriptor.
 * @param[in] uctx	A #fr_io_connection_thread_t.
 */
static fr_connection_state_t _conn_init(int *fd_out, void *uctx)
{
	int				fd;
	fr_io_connection_t		*c = talloc_get_type_abort(uctx, fr_io_connection_t);

	/*
	 *	Open the outgoing socket.
	 */
	fd = fr_socket_client_udp(&c->src_ipaddr, &c->src_port, &c->dst_ipaddr, c->dst_port, true);
	if (fd < 0) {
		PERROR("%s - Failed opening socket", c->module_name);
		return FR_CONNECTION_STATE_FAILED;
	}

	/*
	 *	Set the connection name.
	 *
	 *	@todo - print out application (RADIUS), protocol (UDP), etc.
	 */
	talloc_const_free(c->name);
	c->name = fr_asprintf(c, "connecting from %pV to %pV port %u",
			      fr_box_ipaddr(c->src_ipaddr),
			      fr_box_ipaddr(c->dst_ipaddr), c->dst_port);

#ifdef SO_RCVBUF
	if (c->inst->recv_buff_is_set) {
		int opt;

		opt = c->inst->recv_buff;
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(int)) < 0) {
			WARN("Failed setting 'recv_buf': %s", fr_syserror(errno));
		}
	}
#endif

#ifdef SO_SNDBUF
	if (c->inst->send_buff_is_set) {
		int opt;

		opt = c->inst->send_buff;
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(int)) < 0) {
			WARN("Failed setting 'send_buf': %s", fr_syserror(errno));
		}
	}
#endif

	/*
	 *	Insert the connection into the opening list
	 */
	conn_transition(c, CONN_OPENING);
	c->fd = fd;

	// @todo - initialize the tracking memory, etc.
	// i.e. histograms (or hyperloglog) of packets, so we can see
	// which connections / home servers are fast / slow.

	*fd_out = fd;

	return FR_CONNECTION_STATE_CONNECTING;
}

/** Free the connection, and return requests to the thread queue
 *
 */
static int _conn_free(fr_io_connection_t *c)
{
	fr_io_request_t	*u;
	fr_io_connection_thread_t	*t = talloc_get_type_abort(c->thread, fr_io_connection_thread_t);

	/*
	 *	We're no longer using this connection.
	 */
	while (true) {
		uint32_t num_connections;

		num_connections = load(c->inst->parent->num_connections);
		rad_assert(num_connections > 0);

		if (cas_decr(c->inst->parent->num_connections, num_connections)) break;
	}

	/*
	 *	Explicit free not technically required,
	 *	but may prevent future ordering issues.
	 */
	talloc_free(c->conn);
	c->conn = NULL;

	/*
	 *	Move "sent" packets back to the main thread queue
	 */
	while ((u = fr_dlist_head(&c->sent)) != NULL) {
		state_transition(u, REQUEST_IO_STATE_QUEUED, NULL);
	}

	if (c->zombie_ev) (void) fr_event_timer_delete(c->thread->el, &c->zombie_ev);
	if (c->idle_ev) (void) fr_event_timer_delete(c->thread->el, &c->idle_ev);

	talloc_free_children(c); /* clears out FD events, timers, etc. */

	switch (c->state) {
	default:
		rad_assert(0 == 1);
		break;

	case CONN_INIT:
		break;

	case CONN_OPENING:
		fr_dlist_remove(&c->thread->opening, c);
		break;

	case CONN_FULL:
		fr_dlist_remove(&c->thread->blocked, c);
		break;

	case CONN_ZOMBIE:
		fr_dlist_remove(&c->thread->zombie, c);
		break;

	case CONN_ACTIVE:
		rad_assert(c->heap_id < 0);
		(void) fr_heap_extract(t->active, c);
		break;
	}

	return 0;
}

/** Destroy thread data for the IO submodule.
 *
 */
static int conn_thread_detach(UNUSED fr_event_list_t *el, void *thread)
{
	fr_io_connection_thread_t *t = talloc_get_type_abort(thread, fr_io_connection_thread_t);

	if (fr_heap_num_elements(t->queued) != 0) {
		ERROR("There are still queued requests");
		return -1;
	}

	/*
	 *	Free all of the heaps, lists, and sockets.
	 */
	talloc_free_children(t);

	if (fr_dlist_head(&t->opening) != NULL) {
		ERROR("There are still partially open sockets");
		return -1;
	}

	return 0;
}

static int conn_thread_instantiate(fr_io_connection_thread_t *t, fr_event_list_t *el)
{
	t->el = el;

	t->queued = fr_heap_talloc_create(t, queue_cmp, fr_io_request_t, heap_id);
	fr_dlist_init(&t->blocked, fr_io_connection_t, entry);
	fr_dlist_init(&t->full, fr_io_connection_t, entry);
	fr_dlist_init(&t->zombie, fr_io_connection_t, entry);
	fr_dlist_init(&t->opening, fr_io_connection_t, entry);

	t->active = fr_heap_talloc_create(t, conn_cmp, fr_io_connection_t, heap_id);

	return 0;
}

static rlm_rcode_t conn_request_resume(UNUSED void *instance, UNUSED void *thread, UNUSED REQUEST *request, void *ctx)
{
	fr_io_request_t *u = talloc_get_type_abort(ctx, fr_io_request_t);
	rlm_rcode_t rcode;

	rcode = u->rcode;
	rad_assert(rcode != RLM_MODULE_YIELD);
	talloc_free(u);

	return rcode;
}

static void conn_transition(fr_io_connection_t *c, fr_io_connection_state_t state)
{
	if (c->state == state) return;

	/*
	 *	Get it out of the old state.
	 */
	switch (c->state) {
	case CONN_INIT:
		break;

	case CONN_OPENING:
	case CONN_FULL:
	case CONN_BLOCKED:
		fr_dlist_remove(&c->thread->blocked, c); /* we only need 'offset' from the list */
		break;

	case CONN_ACTIVE:
		rad_assert(c->heap_id >= 0);
		(void) fr_heap_extract(c->thread->active, c);
		if (c->idle_ev) (void) fr_event_timer_delete(c->thread->el, &c->idle_ev);
		break;

	case CONN_ZOMBIE:
		/*
		 *	Don't transition from zombie to blocked when
		 *	we're trying to write status check packets to
		 *	the connection.
		 */
		if (state == CONN_BLOCKED) return;

		fr_dlist_remove(&c->thread->blocked, c);
		if (c->zombie_ev) (void) fr_event_timer_delete(c->thread->el, &c->zombie_ev);
		break;
	}

	/*
	 *	And move it to the new state.
	 */
	c->state = state;
	switch (c->state) {
	case CONN_INIT:
		break;

	case CONN_OPENING:
		fr_dlist_insert_head(&c->thread->opening, c);
		break;

	case CONN_ACTIVE:
		rad_assert(c->heap_id < 0);
		(void) fr_heap_insert(c->thread->active, c);
		conn_check_idle(c);
		break;

	case CONN_BLOCKED:
		if (c->idle_ev) (void) fr_event_timer_delete(c->thread->el, &c->idle_ev);

		fr_dlist_insert_head(&c->thread->blocked, c);
		break;

	case CONN_FULL:
		if (c->idle_ev) (void) fr_event_timer_delete(c->thread->el, &c->idle_ev);

		fr_dlist_insert_head(&c->thread->full, c);
		break;

	case CONN_ZOMBIE:
		if (c->idle_ev) (void) fr_event_timer_delete(c->thread->el, &c->idle_ev);

		fr_dlist_insert_head(&c->thread->zombie, c);

		WARN("%s - Entering Zombie state - connection %s", c->module_name, c->name);

		if (fr_event_timer_in(c, c->thread->el, &c->zombie_ev, c ->thread->zombie_period, conn_zombie_timeout, c) < 0) {
			ERROR("%s - Failed inserting zombie timeout for connection %s",
			      c->module_name, c->name);
		}
		break;
	}
}

static void conn_finished_request(fr_io_connection_t *c, fr_io_request_t *u)
{
	rad_assert(u->state != REQUEST_IO_STATE_DONE);

	if (c) {
		rad_assert(u->state == REQUEST_IO_STATE_WRITTEN);
		state_transition(u, REQUEST_IO_STATE_REPLIED, NULL);

		conn_check_idle(c);

	} else {
		rad_assert(u->state == REQUEST_IO_STATE_QUEUED);
		state_transition(u, REQUEST_IO_STATE_REPLIED, NULL);
	}
}

// ATD END


static int conn_timeout_init(fr_event_list_t *el, fr_io_request_t *u, fr_event_cb_t callback)
{
	u->timer.start = u->time_sent = fr_time();

	if (rr_track_start(&u->timer) < 0) {
		return -1;
	}

	if (fr_event_timer_at(u, el, &u->timer.ev, u->timer.next, callback, u) < 0) {
		return -1;
	}

	return 0;
}

/** Deal with status check timeouts for transmissions, etc.
 *
 */
static void status_check_timeout(fr_event_list_t *el, fr_time_t now, void *uctx)
{
	int				rcode;
	fr_io_request_t			*u = uctx;
	fr_io_connection_t		*c = u->c;
	rlm_radius_udp_connection_t	*radius = c->ctx;
	REQUEST				*request;
	uint32_t			event_time;
	uint8_t				*attr, *end;
	char const			*module_name;

	rad_assert(u == radius->status_u);
	rad_assert(u->timer.ev == NULL);
	rad_assert(!c->inst->parent->synchronous);

	request = u->request;

	RDEBUG("TIMER - response timeout on status check packet reached for try (%d/%d)",
	       u->timer.count, u->timer.retry->mrc);

	/*
	 *	Can we retry this packet?  If not, then maybe the
	 *	connection is zombie.  If we don't have a connection,
	 *	just give up on the request.
	 */
	rcode = rr_track_retry(&u->timer, now);
	if (rcode == 0) {
		REDEBUG("No response to status checks, closing connection %s", c->name);
		talloc_free(c);
		return;
	}

	/*
	 *	Insert the next retransmission timer.
	 */
	if (fr_event_timer_at(u, el, &u->timer.ev, u->timer.next, status_check_timeout, u) < 0) {
		REDEBUG("Failed inserting retransmission timer for status check - closing connection %s", c->name);
		talloc_free(c);
		return;
	}

	rad_assert(u->state == REQUEST_IO_STATE_WRITTEN);

	/*
	 *	If we can retransmit it, do so.  Otherwise, it will
	 *	get retransmitted when we get around to polling
	 *	t->queued
	 */
	RDEBUG("Retransmitting status check ID %d on connection %s", u->rr->id, c->name);

	rad_assert(u->packet != NULL);

	/*
	 *	Always update Event-Timestamp.  Note that the rest of
	 *	the code ensures that the packet always contains an
	 *	Event-Timestamp attribute.
	 */
	attr = u->packet + 20;
	end = u->packet + u->packet_len;

	while (attr < end) {
		if (attr[0] != (uint8_t)attr_event_timestamp->attr) {
			attr += attr[1];
			continue;
		}

		event_time = htonl(time(NULL));
		rad_assert(attr[1] == 6);
		memcpy(attr + 2, &event_time, 4);
		break;
	}

	/*
	 *	Get a new Request Authenticator, if necessary.
	 */
	if ((u->code == FR_CODE_ACCESS_REQUEST) ||
	    (u->code == FR_CODE_STATUS_SERVER)) {
		size_t i;
		uint32_t hash, base;

		base = fr_rand();
		for (i = 0; i < RADIUS_AUTH_VECTOR_LENGTH; i += sizeof(uint32_t)) {
			hash = fr_rand() ^ base;
			memcpy(c->buffer + 4 + i, &hash, sizeof(hash));
		}
	}

	/*
	 *	Free / allocate the ID.  This ensures that the ID changes.
	 */
	(void) rr_track_delete(radius->id, u->rr);
	u->rr = rr_track_alloc(radius->id, u->request, u->code, u, &u->timer);
	c->slots_free = radius->id->num_free;
	rad_assert(u->rr != NULL);

	/*
	 *	This hack cleans up the debug output a bit.
	 */
	module_name = request->module;
	request->module = NULL;

	/*
	 *	Now that we're done mangling the packet, sign it.
	 */
	if (fr_radius_sign(u->packet, NULL, (uint8_t const *) c->inst->secret,
			   talloc_array_length(c->inst->secret) - 1) < 0) {
		request->module = module_name;
		RERROR("Failed signing packet");
		conn_error(c->thread->el, c->fd, 0, errno, c);
		return;
	}

	/*
	 *	Remember the authentication vector, which now has the
	 *	packet signature.
	 */
	memcpy(u->rr->vector, c->buffer + 4, RADIUS_AUTH_VECTOR_LENGTH);

	request->module = module_name;

	/*
	 *	@todo - print out the packet contents, including Message-Authenticator
	 */

	/*
	 *	Write the packet to the socket.  If it works, we're
	 *	done.
	 */
	rcode = write(c->fd, u->packet, u->packet_len);
	if (rcode > 0) {
		radius->status_check_blocked = false;
		return;
	}

	/*
	 *	Blocked?  Try to write it when the socket becomes ready.
	 */
	if ((rcode < 0) && (errno == EWOULDBLOCK)) {
		RDEBUG("Blocked writing for connection %s", c->name);
		conn_transition(c, CONN_BLOCKED);

		/*
		 *	Remember to write status check packets as soon as the
		 *	socket becomes writable.
		 */
		radius->status_check_blocked = true;
	}

	RDEBUG("Failed retransmitting status check packet for connection %s", c->name);

	/*
	 *	If we fail retransmitting the status packet,
	 *	just close the connection.
	 */
	talloc_free(c);
}


/** Mark a connection "zombie" due to zombie timeout.
 *
 */
static void conn_zombie_timeout(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_io_connection_t *c = talloc_get_type_abort(uctx, fr_io_connection_t);
	rlm_radius_udp_connection_t *radius = c->ctx;
	fr_io_request_t *u;
	int rcode;

	ERROR("%s - Zombie timeout for connection %s", c->module_name, c->name);

	if (!radius->status_u) {
		DEBUG2("%s - No status_check response, closing connection %s", c->module_name, c->name);
		talloc_free(c);
		return;
	}

	/*
	 *	If we have Status-Server packets, start sending those now.
	 */
	u = radius->status_u;

	/*
	 *	Re-initialize the timers.
	 */
	u->timer.count = 0;
	radius->status_check_blocked = false;

	/*
	 *	Start the timers for status checks.
	 */
	if (conn_timeout_init(c->thread->el, u, status_check_timeout) < 0) {
		DEBUG("%s - Failed starting retransmit tracking for connection %s",
		      c->module_name, c->name);
		talloc_free(c);
		return;
	}

	/*
	 *	And now write it to the connection.
	 */
	rcode = conn_write(c, u);
	if (rcode < 0) {
		DEBUG2("%s - Failed writing status check, closing connection %s",
		       c->module_name, c->name);
		talloc_free(c);
		return;
	}

	/*
	 *	It returned EWOULDBLOCK.  Wait for the socket to
	 *	become ready, OR for the retransmission timer to fire.
	 */
	if (rcode == 0) {
		radius->status_check_blocked = true;
		DEBUG2("%s - EWOULDBLOCK for status check on connection %s",
		       c->module_name, c->name);
		return;
	}

	/*
	 *	Note that the status check packets not in any
	 *	"sent" list
	 */
	if (rcode == 1) {
		u->state = REQUEST_IO_STATE_WRITTEN;
		u->c = c;
		return;
	}

	/*
	 *	Status check packets are never replicated.
	 */
	rad_assert(0 == 1);
}


static void state_transition(fr_io_request_t *u, fr_io_request_state_t state, fr_io_connection_t *c)
{
	rlm_radius_udp_connection_t *radius;

	if (u->state == state) return;

	switch (u->state) {
	case REQUEST_IO_STATE_INIT:
		rad_assert((state == REQUEST_IO_STATE_QUEUED) || (state == REQUEST_IO_STATE_DONE));
		break;

	case REQUEST_IO_STATE_QUEUED:
		rad_assert(u->heap_id >= 0);
		(void) fr_heap_extract(u->thread->queued, u);
		break;

	case REQUEST_IO_STATE_WRITTEN:
		rad_assert(u->rr != NULL);
		rad_assert(u->c != NULL);

		radius = u->c->ctx;

		/*
		 *      Status check packets are never removed from
		 *      the connection, and their IDs are never
		 *      deallocated.
		 */
		if (u == radius->status_u) {
			u->state = REQUEST_IO_STATE_INIT;
			return;
		}

		(void) rr_track_delete(radius->id, u->rr);
		u->c->slots_free = radius->id->num_free;
		fr_dlist_remove(&u->c->sent, u);
		u->rr = NULL;
		u->c = NULL;
		break;

	case REQUEST_IO_STATE_REPLIED:
		rad_assert(state == REQUEST_IO_STATE_DONE);
		break;

	default:
		rad_assert(0 == 1);
		break;
	}

	u->state = state;
	u->c = c;

	switch (u->state) {
	case REQUEST_IO_STATE_QUEUED:
	queued:
		rad_assert(u->rr == NULL);
		u->c = NULL;
		rad_assert(u->heap_id < 0);
		fr_heap_insert(u->thread->queued, u);
		break;

	case REQUEST_IO_STATE_WRITTEN:
		rad_assert(c != NULL);
		radius = c->ctx;

		/*
		 *	Allocate an ID for the packet.
		 */
		u->rr = rr_track_alloc(radius->id, u->request, u->code, u, &u->timer);
		if (!u->rr) {
			u->state = REQUEST_IO_STATE_QUEUED;
			u->c = NULL;
			conn_transition(c, CONN_FULL);
			goto queued;
		}
		c->slots_free = radius->id->num_free;
		u->c = c;
		fr_dlist_insert_tail(&u->c->sent, u);
		break;

	case REQUEST_IO_STATE_REPLIED:
		rad_assert(u->rr == NULL);
		rad_assert(u->c == NULL);
		if (u->timer.ev) (void) fr_event_timer_delete(u->thread->el, &u->timer.ev);
		if (u->yielded) unlang_interpret_resumable(u->request);
		break;

	case REQUEST_IO_STATE_DONE:
		rad_assert(u->rr == NULL);
		rad_assert(u->c == NULL);
		if (u->timer.ev) (void) fr_event_timer_delete(u->thread->el, &u->timer.ev);
		break;

	default:
		rad_assert(0 == 1);
		break;
	}
}

/* ATD - all of this to "end" is 100% RADIUS only */

/** Turn a reply code into a module rcode;
 *
 */
static rlm_rcode_t code2rcode[FR_RADIUS_MAX_PACKET_CODE] = {
	[FR_CODE_ACCESS_ACCEPT]		= RLM_MODULE_OK,
	[FR_CODE_ACCESS_CHALLENGE]	= RLM_MODULE_OK,
	[FR_CODE_ACCESS_REJECT]		= RLM_MODULE_REJECT,

	[FR_CODE_ACCOUNTING_RESPONSE]	= RLM_MODULE_OK,

	[FR_CODE_COA_ACK]		= RLM_MODULE_OK,
	[FR_CODE_COA_NAK]		= RLM_MODULE_REJECT,

	[FR_CODE_DISCONNECT_ACK]	= RLM_MODULE_OK,
	[FR_CODE_DISCONNECT_NAK]	= RLM_MODULE_REJECT,

	[FR_CODE_PROTOCOL_ERROR]	= RLM_MODULE_FAIL,
};


/** If we get a reply, the request must come from one of a small
 * number of packet types.
 */
static FR_CODE allowed_replies[FR_RADIUS_MAX_PACKET_CODE] = {
	[FR_CODE_ACCESS_ACCEPT]		= FR_CODE_ACCESS_REQUEST,
	[FR_CODE_ACCESS_CHALLENGE]	= FR_CODE_ACCESS_REQUEST,
	[FR_CODE_ACCESS_REJECT]		= FR_CODE_ACCESS_REQUEST,

	[FR_CODE_ACCOUNTING_RESPONSE]	= FR_CODE_ACCOUNTING_REQUEST,

	[FR_CODE_COA_ACK]		= FR_CODE_COA_REQUEST,
	[FR_CODE_COA_NAK]		= FR_CODE_COA_REQUEST,

	[FR_CODE_DISCONNECT_ACK]	= FR_CODE_DISCONNECT_REQUEST,
	[FR_CODE_DISCONNECT_NAK]	= FR_CODE_DISCONNECT_REQUEST,
};


/** Deal with Protocol-Error replies, and possible negotiation
 *
 */
static void protocol_error_reply(fr_io_connection_t *c, REQUEST *request)
{
	VALUE_PAIR *vp, *error_cause;

	error_cause = fr_pair_find_by_da(request->reply->vps, attr_error_cause, TAG_ANY);
	if (!error_cause) return;

	if ((error_cause->vp_uint32 == 601) &&
	    attr_response_length &&
	    ((vp = fr_pair_find_by_da(request->reply->vps, attr_response_length, TAG_ANY)) != NULL)) {

		if (vp->vp_uint32 > c->buflen) {
			request->module = c->module_name;
			RDEBUG("Increasing buffer size to %u for connection %s", vp->vp_uint32, c->name);

			talloc_free(c->buffer);
			c->buflen = vp->vp_uint32;
			MEM(c->buffer = talloc_array(c, uint8_t, c->buflen));
		}
	}
}

/** Deal with Status-Server replies, and possible negotiation
 *
 */
static void status_server_reply(fr_io_connection_t *c, fr_io_request_t *u, REQUEST *request)
{
	VALUE_PAIR *vp;

	/*
	 *	Remove all timers associated with the packet.
	 */
	if (u->timer.ev) (void) fr_event_timer_delete(u->thread->el, &u->timer.ev);

	rad_assert(u->state == REQUEST_IO_STATE_WRITTEN);

	if (u->code != FR_CODE_STATUS_SERVER) return;

	/*
	 *	Allow Response-Length in replies to Status-Server
	 *	packets.
	 */
	if (attr_response_length &&
	    ((vp = fr_pair_find_by_da(request->reply->vps, attr_response_length, TAG_ANY)) != NULL)) {
		if ((vp->vp_uint32 > c->buflen) && (vp->vp_uint32 <= 65536)) {
			request->module = c->module_name;
			RDEBUG("Increasing buffer size to %u for connection %s", vp->vp_uint32, c->name);

			talloc_free(c->buffer);
			c->buflen = vp->vp_uint32;
			MEM(c->buffer = talloc_array(c, uint8_t, c->buflen));
		}
	}

	/*
	 *	Delete the reply VPs, but leave the request VPs in
	 *	place.
	 */
#ifdef __clang_analyzer__
	if (request->reply)
#endif
		fr_pair_list_free(&request->reply->vps);

}

/* ATD END */

/** Read reply packets.
 *
 */
static void conn_read(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_io_connection_t		*c = talloc_get_type_abort(uctx, fr_io_connection_t);
	rlm_radius_request_t		*rr;
	fr_io_request_t	*u;
	rlm_radius_udp_connection_t	*radius = c->ctx;
	int				code;
	decode_fail_t			reason;
	size_t				packet_len;
	ssize_t				data_len;
	REQUEST				*request = NULL;
	uint8_t				original[20];
	bool				reinserted = false;
	bool				activate = false;

	DEBUG3("%s - Reading data for connection %s", c->module_name, c->name);

redo:
	/*
	 *	Drain the socket of all packets.  If we're busy, this
	 *	saves a round through the event loop.  If we're not
	 *	busy, a few extra system calls don't matter.
	 */
	data_len = read(fd, c->buffer, c->buflen);
	if (data_len == 0) {
check_active:
		if (activate && (fr_heap_num_elements(c->thread->queued) > 0)) {
			fd_active(c);
		}
		return;
	}

	if (data_len < 0) {
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) goto check_active;

		conn_error(el, fd, 0, errno, c);
		return;
	}

 { /* RADIUS START - do various protocol-specific validations */

	/*
	 *	Replicating?  Drain the socket, but ignore all responses.
	 *
	 *	Note that if we're replicating, we don't do Status-Server checks.
	 */
	 if (c->inst->replicate) goto redo;

	packet_len = data_len;
	if (!fr_radius_ok(c->buffer, &packet_len, c->inst->parent->max_attributes, false, &reason)) {
		WARN("%s - Ignoring malformed packet", c->module_name);
		goto redo;
	}

	if (DEBUG_ENABLED3) {
		DEBUG3("%s - Read packet", c->module_name);
		fr_log_hex(&default_log, L_DBG, __FILE__, __LINE__, c->buffer, packet_len, NULL);
	}

	rr = rr_track_find(radius->id, c->buffer[1], NULL);
	if (!rr) {
		WARN("%s - Ignoring reply which arrived too late", c->module_name);
		goto redo;
	}

	u = rr->request_io_ctx;
	request = u->request;
	rad_assert(request != NULL);

	original[0] = rr->code;
	original[1] = 0;	/* not looked at by fr_radius_verify() */
	original[2] = 0;
	original[3] = 20;	/* for debugging */
	memcpy(original + 4, rr->vector, sizeof(rr->vector));

	if (fr_radius_verify(c->buffer, original,
			     (uint8_t const *) c->inst->secret, talloc_array_length(c->inst->secret) - 1) < 0) {
		RPWDEBUG("Ignoring response with invalid signature");
		goto redo;
	}

	/*
	 *	We can only get a reply to a sent packet.
	 */
	rad_assert(u->state == REQUEST_IO_STATE_WRITTEN);
	rad_assert(u->c == c);

	code = c->buffer[0];

	/*
	 *	Set request return code based on the packet type.
	 *	Note that we don't care what the sent packet is, we
	 *	presume that the reply is correct for the request,
	 *	because it has been successfully verified.  The reply
	 *	packet code only affects the module return code,
	 *	nothing else.
	 *
	 *	Protocol-Error is special.  It goes through it's own
	 *	set of checks.
	 */
	if (code == FR_CODE_PROTOCOL_ERROR) {
		uint8_t const *attr, *end;

		end = c->buffer + packet_len;
		u->rcode = RLM_MODULE_INVALID;

		for (attr = c->buffer + 20;
		     attr < end;
		     attr += attr[1]) {
			/*
			 *	The attribute containing the
			 *	Original-Packet-Code is an extended
			 *	attribute.
			 */
			if (attr[0] != (uint8_t)attr_extended_attribute_1->attr) continue;

			/*
			 *	ATTR + LEN + EXT-Attr + uint32
			 */
			if (attr[1] != 7) continue;

			/*
			 *	See if there's an Original-Packet-Code.
			 */
			if (attr[2] != (uint8_t)attr_original_packet_code->attr) continue;

			/*
			 *	Has to be an 8-bit number.
			 */
			if ((attr[3] != 0) ||
			    (attr[4] != 0) ||
			    (attr[5] != 0)) {
				REDEBUG("Original-Packet-Code has invalid value > 255");
				break;
			}

			/*
			 *	The value has to match.  We don't
			 *	currently multiplex different codes
			 *	with the same IDs on connections.  So
			 *	this check is just for RFC compliance,
			 *	and for sanity.
			 */
			if (attr[6] != u->code) {
				REDEBUG("Original-Packet-Code %d does not match original code %d",
				        attr[6], u->code);
				break;
			}

			/*
			 *	Allow the Protocol-Error response,
			 *	which returns "fail".
			 */
			u->rcode = RLM_MODULE_FAIL;
			break;
		}

		/*
		 *	Decode and print the reply, so that the caller
		 *	can do something with it.
		 */
		goto decode_reply;

	} else if (!code || (code >= FR_RADIUS_MAX_PACKET_CODE)) {
		REDEBUG("Unknown reply code %d", code);
		u->rcode = RLM_MODULE_INVALID;

		/*
		 *	Different debug message.  The packet is within
		 *	the known bounds, but is one we don't handle.
		 */
	} else if (!allowed_replies[code]) {
		REDEBUG("%s packet received invalid reply code %s", fr_packet_codes[u->code], fr_packet_codes[code]);
		u->rcode = RLM_MODULE_INVALID;

		/*
		 *	Status-Server can accept many kinds of
		 *	replies.
		 */
	} else if (u->code == FR_CODE_STATUS_SERVER) {
		goto check_reply;

		/*
		 *	The reply is a known code, but isn't
		 *	appropriate for the request packet type.
		 */
	} else if (allowed_replies[code] != (FR_CODE) u->code) {
		rad_assert(request != NULL);

		REDEBUG("%s packet received invalid reply code %s", fr_packet_codes[u->code], fr_packet_codes[code]);
		u->rcode = RLM_MODULE_INVALID;

		/*
		 *	<whew>, it's OK.  Choose the correct module
		 *	rcode based on the reply code.  This is either
		 *	OK for an ACK, or FAIL for a NAK.
		 */
	} else {
		VALUE_PAIR *reply, *vp;

check_reply:
		u->rcode = code2rcode[code];

		if (u->rcode == RLM_MODULE_INVALID) {
			REDEBUG("%s packet received invalid reply code %s", fr_packet_codes[u->code], fr_packet_codes[code]);
			goto done;
		}

	decode_reply:
		reply = NULL;

		/*
		 *	Decode the attributes, in the context of the
		 *	reply.  This only fails if the packet is
		 *	malformed, or if we run out of memory.
		 */
		if (fr_radius_decode(request->reply, c->buffer, packet_len, original,
				     c->inst->secret, talloc_array_length(c->inst->secret) - 1, &reply) < 0) {
			REDEBUG("Failed decoding attributes for packet");
			fr_pair_list_free(&reply);
			u->rcode = RLM_MODULE_INVALID;
			goto done;
		}

		RDEBUG("Received %s ID %d length %ld reply packet on connection %s",
		       fr_packet_codes[code], code, packet_len, c->name);
		log_request_pair_list(L_DBG_LVL_2, request, reply, NULL);

		/*
		 *	Delete Proxy-State attributes from the reply.
		 */
		fr_pair_delete_by_da(&reply, attr_proxy_state);

		/*
		 *	If the reply has Message-Authenticator, delete
		 *	it from the proxy reply so that it isn't
		 *	copied over to our reply.  But also create a
		 *	reply:Message-Authenticator attribute, so that
		 *	it ends up in our reply.
		 */
		if (fr_pair_find_by_da(reply, attr_message_authenticator, TAG_ANY)) {
			fr_pair_delete_by_da(&reply, attr_message_authenticator);

			MEM(vp = fr_pair_afrom_da(request->reply, attr_message_authenticator));
			(void) fr_pair_value_memcpy(vp, (uint8_t const *) "", 1, false);
			fr_pair_add(&request->reply->vps, vp);
		}

		/*
		 *	@todo - make this programmatic?  i.e. run a
		 *	separate policy which updates the reply.
		 *
		 *	This is why I wanted to have "recv
		 *	Access-Accept" policies...  so the user could
		 *	programatically decide which attributes to add.
		 */

		request->reply->code = code;
		fr_pair_add(&request->reply->vps, reply);

		/*
		 *	Run hard-coded policies on Protocol-Error
		 */
		if (code == FR_CODE_PROTOCOL_ERROR) {
			protocol_error_reply(c, request);

		} else if (u == radius->status_u) {
			/*
			 *	Run hard-coded policies on packets *we* sent
			 *	as status checks.
			 */
			status_server_reply(c, u, request);

		} else if ((code == FR_CODE_ACCESS_CHALLENGE) && (request->dict == dict_radius) &&
			   (request->packet->code == FR_CODE_ACCESS_REQUEST)) {
			/*
			 *	Mark up the parent request as being an
			 *	Access-Challenge.
			 *
			 *	We don't do this for other packet
			 *	types, because the ok/fail nature of
			 *	the module return code will
			 *	automatically result in it the parent
			 *	request returning an ok/fail packet
			 *	code.
			 */
			vp = fr_pair_find_by_da(request->reply->vps, attr_packet_type, TAG_ANY);
			if (!vp) {
				RDEBUG("  &reply:Packet-Type := Access-Challenge");
				MEM(vp = fr_pair_afrom_da(request->reply, attr_packet_type));
				vp->vp_uint32 = FR_CODE_ACCESS_CHALLENGE;
				fr_pair_add(&request->reply->vps, vp);
			}
		}
	}
} /* RADIUS END */

done:
	rad_assert(request != NULL);
	rad_assert(request->reply != NULL);

	/*
	 *	Mark the request as finished.
	 */
	rad_assert(u->c == c);
	rad_assert(u->rr != NULL);
	rad_assert(u->state == REQUEST_IO_STATE_WRITTEN);
	conn_finished_request(c, u);

	/*
	 *	Remember when we last saw a reply.
	 */
	c->last_reply = fr_time();

	/*
	 *	Track the Most Recently Started with reply.  If we're
	 *	writable or have IDs available, just re-order the list
	 *	instead of doing the transition.  This ensures that
	 *	packets we're going to send will use the best
	 *	connection.
	 */
	switch (c->state) {
	case CONN_ACTIVE:
		if (reinserted) break;

		if (u->timer.start > c->mrs_time) {
			(void) fr_heap_extract(c->thread->active, c);
			c->mrs_time = u->timer.start;
			(void) fr_heap_insert(c->thread->active, c);
			reinserted = true;
		}
		break;

	default:
		if (u->timer.start > c->mrs_time) {
			c->mrs_time = u->timer.start;
		}

		/*
		 *	Transition to active on any one packet.  RFC
		 *	3539 says to wait for N status check
		 *	responses, but we're happy to do it faster.
		 *
		 *	If the connection was FULL, then
		 *	conn_finished_request() will ensure that this
		 *	packet has been removed from the connection,
		 *	before any subsequent writes go to it.
		 */
		conn_transition(c, CONN_ACTIVE);

		/*
		 *	Most connections are symmetrical.  If we've
		 *	read a packet from it, we can probably write
		 *	to it.
		 *
		 *      Note that we don't call fd_active() here, as
		 *      it can fail, and close the connection.  In
		 *      which case subsequent uses of 'c' would cause
		 *      the server to crash.
		 *
		 *	Instead, we activate the connection only when
		 *	we're exiting.
		 */
		activate = true;
		break;
	}

	goto redo;
}

static int retransmit_packet(fr_io_request_t *u, fr_time_t now)
{
	bool				resign = false;
	int				rcode;
	fr_io_connection_t		*c = u->c;
	rlm_radius_udp_connection_t	*radius = c->ctx;
	REQUEST				*request = u->request;

	rad_assert(u->packet != NULL);
	rad_assert(u->packet_len >= 20);
	rad_assert(u != radius->status_u);

	/*
	 *	RADIUS layer fixups for Accounting-Request packets.
	 */
	if (u->code == FR_CODE_ACCOUNTING_REQUEST) {
		/*
		 *	No Acct-Delay-Time, add one manually if
		 *	there's room.
		 */
		if (!u->acct_delay_time && ((u->packet_len + 6) <= u->c->buflen)) {
			int hdr_len;
			uint8_t *packet, *attr;

			MEM(packet = talloc_array(u, uint8_t, u->packet_len + 6));
			memcpy(packet, u->packet, u->packet_len);
			talloc_free(u->packet);
			u->packet = packet;

			attr = u->packet + u->packet_len;
			u->packet_len += 6;

			/*
			 *	Append the attribute.
			 */
			attr[0] = (uint8_t)attr_acct_delay_time->attr;
			attr[1] = 6;
			memset(attr + 2, 0, 4);

			hdr_len = (u->packet[2] << 8) | (u->packet[3]);
			hdr_len += 6;
			u->packet[2] = (hdr_len >> 8) & 0xff;
			u->packet[3] = hdr_len & 0xff;

			/*
			 *     Remember it, and the fact that we added
			 *     it manually.  The manual flag allows us
			 *     to print out the auto-created
			 *     Acct-Delay-Time in debug mode.
			 */
			u->acct_delay_time = attr + 2;
			u->manual_delay_time = true;
		}

		if (u->acct_delay_time) {
			uint32_t delay;

			now -= u->timer.start;
			delay = now / NSEC;
			delay += u->initial_delay_time;
			delay = htonl(delay);
			memcpy(u->acct_delay_time, &delay, 4);

			resign = true;
		}
	}

	/*
	 *	Deallocate the ID and allocate a new one.  Note that
	 *	we MUST be able to allocate a new ID, as we just freed
	 *	the old one!
	 *
	 *	Note that for now, we only change the IDs for some
	 *	packets.  Changing it for Access-Request packets means
	 *	that we would need to change the packet authentication
	 *	vector, and then re-encoding the User-Password, along
	 *	with any other attributes that depend on it.
	 */
	if ((u->code == FR_CODE_ACCOUNTING_REQUEST) ||
	    (u->code == FR_CODE_COA_REQUEST) ||
	    (u->code == FR_CODE_DISCONNECT_REQUEST)) {
		(void) rr_track_delete(radius->id, u->rr);
		u->rr = rr_track_alloc(radius->id, u->request, u->code, u, &u->timer);
		c->slots_free = radius->id->num_free;
		rad_assert(u->rr != NULL);
		resign = true;
	}

	/*
	 *	Recalculate the packet signature.
	 */
	if (resign) {
		if (fr_radius_sign(u->packet, NULL, (uint8_t const *) c->inst->secret,
				   talloc_array_length(c->inst->secret) - 1) < 0) {
			REDEBUG("Failed re-signing packet");
			return -1;
		}

		// @todo - call rr_track_update() when we use the authentication vector for uniqueness
		memcpy(u->rr->vector, u->packet + 4, RADIUS_AUTH_VECTOR_LENGTH);
	}

	RDEBUG("Retransmitting request (%d/%d).  Expecting response within %d.%06ds",
	       u->timer.count, u->timer.retry->mrc, u->timer.rt / USEC, u->timer.rt % USEC);

	/*
	 *	Debug the packet again, including any extra
	 *	Proxy-State or Message-Authenticator we added.
	 */
	RDEBUG("%s %s ID %d length %ld over connection %s",
	       (radius->status_u != u) ? "sending" : "status_check",
	       fr_packet_codes[u->code], u->rr->id, u->packet_len, c->name);
	log_request_pair_list(L_DBG_LVL_2, request, request->packet->vps, NULL);
	if (u->extra) log_request_pair_list(L_DBG_LVL_2, request, u->extra, NULL);

	if (u->manual_delay_time && u->acct_delay_time) {
		uint32_t delay;

		memcpy(&delay, u->acct_delay_time, 4);
		delay = ntohl(delay);

		RINDENT();
		RDEBUG2("&Acct-Delay-Time := %u", delay);
		REXDENT();
	}

	rcode = write(c->fd, u->packet, u->packet_len);
	if (rcode < 0) {
		if (errno == EWOULDBLOCK) {
			return 0;
		}

		/*
		 *	We have to re-encode the packet, so
		 *	don't bother copying it to 'u'.
		 */
		conn_error(c->thread->el, c->fd, 0, errno, c);
		return -1;
	}

	return 1;
}

/** Deal with per-request timeouts for transmissions, etc.
 *
 */
static void response_timeout(fr_event_list_t *el, fr_time_t now, void *uctx)
{
	int				rcode;
	fr_io_request_t			*u = uctx;
	fr_io_connection_t		*c = u->c;
	REQUEST				*request;

	rad_assert(u->timer.ev == NULL);
	rad_assert(!c || !c->inst->parent->synchronous);

	request = u->request;

	RDEBUG("TIMER - response timeout reached for try (%d/%d)",
	       u->timer.count, u->timer.retry->mrc);

	/*
	 *	Can we retry this packet?  If not, then maybe the
	 *	connection is zombie.  If we don't have a connection,
	 *	just give up on the request.
	 */
	rcode = rr_track_retry(&u->timer, now);
	if (rcode == 0) {
		if (c) {
			REDEBUG("No response to proxied request ID %d on connection %s",
				u->rr->id, c->name);
			conn_transition(c, CONN_ZOMBIE);
		} else {
			REDEBUG("No response to proxied request");
		}

		conn_finished_request(c, u);
		return;
	}

	/*
	 *	Insert the next retransmission timer.
	 */
	if (fr_event_timer_at(u, el, &u->timer.ev, u->timer.next, response_timeout, u) < 0) {
		RDEBUG("Failed inserting retransmission timer");
		conn_finished_request(c, u);
		return;
	}

	/*
	 *	The timer hit, and there was no connection for the
	 *	packet.  Try to grab an active connection.  If we do
	 *	have any active connections.
	 */
get_new_connection:
	while (!u->c) {
		rad_assert(u->state == REQUEST_IO_STATE_QUEUED);
		c = fr_heap_peek(u->thread->active);
		if (!c) {
			RDEBUG("No available connections for retransmission.  Waiting %d.%06ds for retry",
			       u->timer.rt / USEC, u->timer.rt % USEC);
			return;
		}

		/*
		 *	We have a connection, try transitioning to it.
		 *	If we can't assign the packet to the current
		 *	connection, we try grabbing a different
		 *	connection.  The transition sets 'u->c = c'
		 *	if it succeeds.
		 */
		state_transition(u, REQUEST_IO_STATE_WRITTEN, c);
	}

	rad_assert(u->state == REQUEST_IO_STATE_WRITTEN);

	/*
	 *	If we can retransmit it, do so.  Otherwise, it will
	 *	get retransmitted when we get around to polling
	 *	t->queued
	 */
	RDEBUG("Retransmitting ID %d on connection %s", u->rr->id, c->name);
	rcode = retransmit_packet(u, fr_time());
	if (rcode < 0) {
		RDEBUG("Failed retransmitting packet for connection %s", c->name);
		state_transition(u, REQUEST_IO_STATE_QUEUED, NULL);
		talloc_free(c);
		goto get_new_connection;
	}

	/*
	 *	If we wrote the packet to the connection, we're done.
	 */
	if (rcode != 0) return;

	/*
	 *	EWOULDBLOCK, move the connection to blocked/
	 */
	RDEBUG("Blocked writing for connection %s", c->name);
	conn_transition(c, CONN_BLOCKED);

	/*
	 *	Move the packet back to the thread queue, and try to
	 *	send the packet on a different connection.
	 */
	state_transition(u, REQUEST_IO_STATE_QUEUED, NULL);
	goto get_new_connection;
}


/** Write a packet to a connection
 *
 * @param c the conneciton
 * @param u the udp_request_t connecting everything
 * @return
 *	- <0 on error
 *	- 0 should retry the write later
 *	- 1 the packet was successfully written to the socket, and we wait for a reply
 *	- 2 the packet was replicated to the socket, and should be resumed immediately.
 */
static int conn_write(fr_io_connection_t *c, fr_io_request_t *u)
{
	int			rcode;
	ssize_t			packet_len;
	uint8_t			*msg = NULL;
	int			require_ma = 0;
	int			proxy_state = 6;
	REQUEST			*request;
	char const		*module_name;
	rlm_radius_udp_connection_t *radius = c->ctx;

	rad_assert(c->inst->parent->allowed[u->code] || (u == radius->status_u));
	if (c->idle_ev) (void) fr_event_timer_delete(c->thread->el, &c->idle_ev);

	request = u->request;

	/*
	 *	Make sure that we print out the actual encoded value
	 *	of the Message-Authenticator attribute.  If the caller
	 *	asked for one, delete theirs (which has a bad value),
	 *	and remember to add one manually when we encode the
	 *	packet.  This is the only editing we do on the input
	 *	request.
	 */
	if (fr_pair_find_by_da(request->packet->vps, attr_message_authenticator, TAG_ANY)) {
		require_ma = 18;
		pair_delete_request(attr_message_authenticator);
	}

	/*
	 *	All proxied Access-Request packets MUST have a
	 *	Message-Authenticator, otherwise they're insecure.
	 *	Same goes for Status-Server.
	 *
	 *	And we set the authentication vector to a random
	 *	number...
	 */
	if ((u->code == FR_CODE_ACCESS_REQUEST) ||
	    (u->code == FR_CODE_STATUS_SERVER)) {
		size_t i;
		uint32_t hash, base;

		require_ma = 18;

		base = fr_rand();
		for (i = 0; i < RADIUS_AUTH_VECTOR_LENGTH; i += sizeof(uint32_t)) {
			hash = fr_rand() ^ base;
			memcpy(c->buffer + 4 + i, &hash, sizeof(hash));
		}
	}

	/*
	 *	Every status check packet has an Event-Timestamp.  The
	 *	timestamp changes every time we send a packet.  Status
	 *	check packets never have Proxy-State, because we
	 *	generated them, and they're not proxied.
	 */
	if (u == radius->status_u) {
		VALUE_PAIR *vp;

		proxy_state = 0;
		vp = fr_pair_find_by_da(request->packet->vps, attr_event_timestamp, TAG_ANY);
		if (vp) vp->vp_uint32 = time(NULL);
	}

	/*
	 *	We should have at mininum 64-byte packets, so don't
	 *	bother doing run-time checks here.
	 */
	rad_assert(c->buflen >= (size_t) (20 + proxy_state + require_ma));

	/*
	 *	Encode it, leaving room for Proxy-State and
	 *	Message-Authenticator if necessary.
	 */
	packet_len = fr_radius_encode(c->buffer, c->buflen - proxy_state - require_ma, NULL,
				      c->inst->secret, talloc_array_length(c->inst->secret) - 1, u->code, u->rr->id,
				      request->packet->vps);
	if (packet_len <= 0) return -1;

	/*
	 *	This hack cleans up the debug output a bit.
	 */
	module_name = request->module;
	request->module = NULL;

	RDEBUG("Sending %s ID %d length %ld over connection %s",
	       fr_packet_codes[u->code], u->rr->id, packet_len, c->name);
	log_request_pair_list(L_DBG_LVL_2, request, request->packet->vps, NULL);

	/*
	 *	Might have been sent and then given up on... free the
	 *	raw data so we can re-encode it.
	 */
	if (u->packet) {
		TALLOC_FREE(u->packet);
		fr_pair_list_free(&u->extra);
	}

	/*
	 *	Add Proxy-State to the tail end of the packet.
	 *	We need to add it here, and NOT in
	 *	request->packet->vps, because multiple modules
	 *	may be sending the packets at the same time.
	 *
	 *	Note that the length check will always pass, due to
	 *	the buflen manipulation done above.
	 */
	if (proxy_state) {
		uint8_t		*attr = c->buffer + packet_len;
		VALUE_PAIR	*vp;
		vp_cursor_t	cursor;
		int		count;

		rad_assert((size_t) (packet_len + proxy_state) <= c->buflen);

		/*
		 *	Count how many Proxy-State attributes have
		 *	*our* magic number.
		 */
		if (fr_debug_lvl) {
			count = 0;
			(void) fr_pair_cursor_init(&cursor, &request->packet->vps);
			while ((vp = fr_pair_cursor_next_by_da(&cursor, attr_proxy_state, TAG_ANY)) != NULL) {
				if ((vp->vp_length == 4) && (memcmp(vp->vp_octets, &c->inst->parent->proxy_state, 4) == 0)) {
					count++;
				}
			}

			/*
			 *	Some configurations may proxy to
			 *	ourselves for tests / simplicity.  But
			 *	warn if there are a large number of
			 *	identical Proxy-State attributes.
			 */
			if (count >= 4) RWARN("Potential proxy loop detected!  Please recheck your configuration.");
		}

		attr[0] = (uint8_t)attr_proxy_state->attr;
		attr[1] = 6;
		memcpy(attr + 2, &c->inst->parent->proxy_state, 4);

		MEM(vp = fr_pair_afrom_da(u, attr_proxy_state));
		fr_pair_value_memcpy(vp, attr + 2, 4, true);
		fr_pair_add(&u->extra, vp);

		RINDENT();
		RDEBUG2("&%pP", vp);
		REXDENT();

		packet_len += 6;
	}

	/*
	 *	Add Message-Authenticator manually.
	 *
	 *	Note that the length check will always pass, due to
	 *	the buflen manipulation done above.
	 */
	if (require_ma) {
		rad_assert((size_t) (packet_len + require_ma) <= c->buflen);

		msg = c->buffer + packet_len;

		msg[0] = (uint8_t)attr_message_authenticator->attr;
		msg[1] = 18;
		memset(msg + 2, 0, 16);

		packet_len += 18;
	}

	/*
	 *	Update the packet header based on the new attributes.
	 */
	c->buffer[2] = (packet_len >> 8) & 0xff;
	c->buffer[3] = packet_len & 0xff;

	/*
	 *	Ensure that we update the Acct-Delay-Time on
	 *	retransmissions.
	 *
	 *	If the accounting packet doesn't have Acct-Delay-Time,
	 *	then we leave well enough alone.
	 */
	if (u->code == FR_CODE_ACCOUNTING_REQUEST) {
		uint8_t *attr, *end;
		uint32_t delay;

		end = c->buffer + packet_len;
		u->acct_delay_time = NULL;

		for (attr = c->buffer + 20;
		     attr < end;
		     attr += attr[1]) {
			if (attr[0] != (uint8_t)attr_acct_delay_time->attr) continue;
			if (attr[1] != 6) continue;

			u->acct_delay_time = attr + 2;
			break;
		}

		/*
		 *	Remember the value if it exists.
		 */
		if (u->acct_delay_time) {
			memcpy(&delay, u->acct_delay_time, 4);
			u->initial_delay_time = htonl(delay);
		}

		u->manual_delay_time = false;
	}

	/*
	 *	Now that we're done mangling the packet, sign it.
	 */
	if (fr_radius_sign(c->buffer, NULL, (uint8_t const *) c->inst->secret,
			   talloc_array_length(c->inst->secret) - 1) < 0) {
		request->module = module_name;
		RERROR("Failed signing packet");
		conn_error(c->thread->el, c->fd, 0, errno, c);
		return -1;
	}

	/*
	 *	Remember the authentication vector, which now has the
	 *	packet signature.
	 */
	memcpy(u->rr->vector, c->buffer + 4, RADIUS_AUTH_VECTOR_LENGTH);

	/*
	 *	Print out the actual value of the Message-Authenticator attribute
	 */
	if (msg) {
		VALUE_PAIR *vp;

		MEM(vp = fr_pair_afrom_da(u, attr_message_authenticator));
		fr_pair_value_memcpy(vp, msg + 2, 16, true);
		fr_pair_add(&u->extra, vp);

		RINDENT();
		RDEBUG2("&%pP", vp);
		REXDENT();
	}

	RHEXDUMP3(c->buffer, packet_len, "Encoded packet");

	request->module = module_name;

	/*
	 *	Write the packet to the socket.  If it blocks, stop
	 *	dequeueing packets.
	 */
	rcode = write(c->fd, c->buffer, packet_len);
	if (rcode < 0) {
		if (errno == EWOULDBLOCK) {
			MEM(u->packet = talloc_memdup(u, c->buffer, packet_len));
			u->packet_len = packet_len;
			return 0;
		}

		/*
		 *	We have to re-encode the packet, so
		 *	don't bother copying it to 'u'.
		 */
		conn_error(c->thread->el, c->fd, 0, errno, c);
		return 0;
	}

	/*
	 *	We're replicating, so we don't care about the
	 *	responses.  Don't do any retransmission timers, don't
	 *	look for replies to status checks, etc.
	 *
	 *	Instead, just set the return code to OK, and return.
	 */
	if (c->inst->replicate) {
		u->rcode = RLM_MODULE_OK;
		return 2;
	}

	/*
	 *	Copy the packet in case it needs retransmitting.
	 *
	 *	@todo - only do this if the packet actually is being
	 *	retransmitted.
	 */
	MEM(u->packet = talloc_memdup(u, c->buffer, packet_len));
	u->packet_len = packet_len;

	/*
	 *	Print out helpful debugging messages for non-status
	 *	checks.
	 */
	if (u != radius->status_u) {
		if (!c->inst->parent->synchronous) {
			RDEBUG("Proxying request.  Expecting response within %d.%06ds",
			       u->timer.rt / USEC, u->timer.rt % USEC);

		} else {
			/*
			 *	If the packet doesn't get a response,
			 *	then udp_request_free() will notice, and run conn_zombie()
			 *
			 *	@todo - set up a response_window which is LESS
			 *	than max_request_time.  That way we
			 *	can return "fail", and process the
			 *	request through a fail handler,
			 *	instead of just freeing it.
			 */
			RDEBUG("Proxying request.  Relying on NAS to perform retransmissions");
		}

		/*
		 *	Status-Server only checks.
		 */
	} else if (u->timer.count == 1) {
		RDEBUG("Sending %s status check.  Expecting response within %d.%06ds for connection %s",
		       fr_packet_codes[u->code],
		       u->timer.rt / USEC, u->timer.rt % USEC,
			c->name);

	} else {
		RDEBUG("Retransmitting %s status check.  Expecting response within %d.%06ds for connection %s",
		       fr_packet_codes[u->code],
		       u->timer.rt / USEC, u->timer.rt % USEC,
			c->name);
	}

	return 1;
}

/** There's space available to write data, so do that...
 *
 */
static void conn_writable(fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	fr_io_connection_t		*c = talloc_get_type_abort(uctx, fr_io_connection_t);
	rlm_radius_udp_connection_t	*radius = c->ctx;
	fr_io_request_t	*u;
	bool				pending = false;
	fr_io_connection_state_t	prev_state = c->state;
	fr_io_connection_t		*next;
	int				rcode;

	DEBUG3("%s - Writing packets for connection %s", c->module_name, c->name);

	/*
	 *	If we have a pending status check packet, write that
	 *	first.
	 */
	if (radius->status_check_blocked) {
		radius->status_check_blocked = false;
		rcode = conn_write(c, radius->status_u);

		/*
		 *	Error, close the connection.
		 */
		if (rcode < 0) {
			talloc_free(c);
			return;
		}

		/*
		 *	Blocked, don't write anything more to the
		 *	connection.
		 */
		if (rcode == 0) {
			radius->status_check_blocked = true;
			conn_transition(c, CONN_BLOCKED);
			return;
		}

		/*
		 *	Written successfully, go write more packets.
		 */
	}

	/*
	 *	Empty the global queue of packets to send.
	 */
	while ((u = fr_heap_peek(c->thread->queued)) != NULL) {
		rad_assert(u->state == REQUEST_IO_STATE_QUEUED);

		/*
		 *	Transition the packet to the connection.  If
		 *	we can't do that, leave it where it is.
		 */
		state_transition(u, REQUEST_IO_STATE_WRITTEN, c);
		if (!u->c) {
			pending = true;
			break;
		}

		/*
		 *	If we're retransmitting the packet, wait for
		 *	the timer to fire.  Otherwise, send the packet now.
		 */
		if (u->timer.count > 1) {
			continue;
		}

		/*
		 *	Encode the packet, and do various magical
		 *	transformations.
		 */
		rcode = conn_write(c, u);

		/*
		 *	The packet was sent, and we should wait for
		 *	the reply.
		 */
		if (rcode == 1) {
			continue;
		}

		/*
		 *	The write returned EWOULDBLOCK.  We re-insert
		 *	the packet back onto the main thread queue,
		 *	and stop writing packets to this connection.
		 */
		if (rcode == 0) {
			pending = true;
			state_transition(u, REQUEST_IO_STATE_QUEUED, NULL);
			conn_transition(c, CONN_BLOCKED);
			break;
		}

		/*
		 *	Can't write a packet to this connection, so we
		 *	close it.
		 *
		 *	We still wake up the "next" connection, as we
		 *	hope that it may be writable.  If it isn't, it
		 *	will shut itself down again.  If it is
		 *	writable (and it usually is), then we've saved
		 *	another round trip through the event loop.
		 */
		if (rcode < 0) {
			fr_io_connection_thread_t *t = c->thread;

			talloc_free(c);

			next = fr_heap_peek(t->active);
			if (!next) return;

			conn_writable(el, next->fd, 0, next);
			return;
		}

		/*
		 *	The packet was replicated, we don't care about
		 *	the reply.  Just mark the request as finished.
		 */
		else {
			rad_assert(rcode == 2);
			state_transition(u, REQUEST_IO_STATE_REPLIED, NULL);
		}
	}

	/*
	 *	There are no more packets to write.  Set ourselves to
	 *	idle.
	 */
	if (!pending) {
		fd_idle(c);
		return;
	}

	next = fr_heap_peek(c->thread->active);

	/*
	 *	There are more packets to write.  Update our status,
	 *	and grab another socket to use.
	 */
	switch (c->state) {
	case CONN_INIT:
	case CONN_OPENING:
	case CONN_ACTIVE:	/* all packets should have been sent! */
		rad_assert(0 == 1);
		break;

	case CONN_BLOCKED:	/* we're still writable */
		if (prev_state != CONN_ACTIVE) fd_active(c);
		break;

	case CONN_FULL:		/* we're no longer writable */
		fd_idle(c);
		break;

	case CONN_ZOMBIE:	/* writable, but other end is not responding */
		break;
	}

	/*
	 *	Wake up the next connection, and see if it can drain
	 *	the input queue.
	 */
	if (!next) return;

	conn_writable(el, next->fd, 0, next);
}

/** Free an fr_io_request_t
 *
 *  Unlink the packet from the connection, and remove any tracking
 *  entries.
 */
static int udp_request_free(fr_io_request_t *u)
{
	state_transition(u, REQUEST_IO_STATE_DONE, NULL);

	/*
	 *	We don't have a connection, so we can't update any of
	 *	the connection timers or states.
	 */
	if (!u->c) return 0;

	/*
	 *	The module is doing async proxying, we don't need to
	 *	do more.
	 */
	if (!u->c->inst->parent->synchronous) return 0;

	/*
	 *	The module is doing synchronous proxying.  i.e. where
	 *	we retransmit only when the NAS retransmits.  Since we
	 *	don't have our own timers, we have to check for zombie
	 *	connections when the request is finished.
	 */
	return conn_check_zombie(u->c);
}

/** Free the status-check fr_io_request_t
 *
 *  Unlink the packet from the connection, and remove any tracking
 *  entries.
 */
static int status_udp_request_free(fr_io_request_t *u)
{
	fr_io_connection_t	*c = u->c;
	rlm_radius_udp_connection_t *radius = c->ctx;

	if (u->rr) {
		DEBUG3("%s - Freeing status check ID %d on connection %s", c->module_name, u->rr->id, c->name);
	} else {
		DEBUG3("%s - Freeing status check on connection %s", c->module_name, c->name);
	}
	radius->status_u = NULL;

	/*
	 *	Status check packets are not in any list, but they do
	 *	have an ID allocated.  We don't call
	 *	state_transition() on them, so we have to clean them
	 *	up ourselves.
	 */
	if (u->timer.ev) (void) fr_event_timer_delete(u->thread->el, &u->timer.ev);

	if (u->rr) {
		(void) rr_track_delete(radius->id, u->rr);
		c->slots_free = radius->id->num_free;
	}
	u->rr = NULL;

	return 0;
}

/** Connection failed
 *
 * @param[in] fd	of connection that failed.
 * @param[in] state	the connection was in when it failed.
 * @param[in] uctx	the connection.
 */
static fr_connection_state_t _conn_failed(UNUSED int fd, fr_connection_state_t state, void *uctx)
{
	fr_io_connection_t	*c = talloc_get_type_abort(uctx, fr_io_connection_t);

	/*
	 *	If the connection was connected when it failed,
	 *	we need to handle any outstanding packers and
	 *	timer events before reconnecting.
	 */
	if (state == FR_CONNECTION_STATE_CONNECTED) {
		fr_io_request_t *u;
		rlm_radius_udp_connection_t *radius = c->ctx;

		/*
		 *	Reset the Status-Server checks.
		 */
		if (radius->status_u) {
			u = radius->status_u;

			if (u->timer.ev) (void) fr_event_timer_delete(c->thread->el, &u->timer.ev);

			memset(&u->timer, 0, sizeof(u->timer));
			u->timer.retry = &c->inst->parent->retry[u->code];

			rad_assert(u->c == c);

			if (u->packet) TALLOC_FREE(u->packet);
			u->packet_len = 0;
		}

		/*
		 *	Delete all timers associated with the connection.
		 */
		if (c->idle_ev) (void) fr_event_timer_delete(c->thread->el, &c->idle_ev);
		if (c->zombie_ev) (void) fr_event_timer_delete(c->thread->el, &c->zombie_ev);

		/*
		 *	Move "sent" packets back to the thread queue,
		 */
		while ((u = fr_dlist_head(&c->sent)) != NULL) {
			state_transition(u, REQUEST_IO_STATE_QUEUED, NULL);
		}
	}

	conn_transition(c, CONN_OPENING);

	return FR_CONNECTION_STATE_INIT;
}

/** Process notification that fd is open
 *
 */
static fr_connection_state_t _conn_open(UNUSED fr_event_list_t *el, int fd, void *uctx)
{
	fr_io_connection_t		*c = talloc_get_type_abort(uctx, fr_io_connection_t);
	fr_io_connection_thread_t	*t = c->thread;
	rlm_radius_udp_connection_t	*radius = c->ctx;

	talloc_const_free(c->name);
	c->name = fr_asprintf(c, "proto udp local %pV port %u remote %pV port %u",
			      fr_box_ipaddr(c->src_ipaddr), c->src_port,
			      fr_box_ipaddr(c->dst_ipaddr), c->dst_port);

	DEBUG("%s - Connection open - %s", c->module_name, c->name);

	/*
	 *	Connection is "active" now.  i.e. we prefer the newly
	 *	opened connection for sending packets.
	 *
	 *	@todo - connection negotiation via Status-Server
	 */
	c->last_reply = c->mrs_time = fr_time();

	/*
	 *	If the connection is open, it must be writable.
	 */
	rad_assert(c->state == CONN_OPENING);

	rad_assert(c->zombie_ev == NULL);
	fr_dlist_init(&c->sent, fr_io_request_t, entry);

{ /* RADIUS start */
	/*
	 *	Status-Server checks.  Manually build the packet, and
	 *	all of it's associated glue.
	 */
	if (c->inst->parent->status_check && !radius->status_u) {
		fr_io_request_t *u;
		REQUEST *request;

		u = talloc_zero(c, fr_io_request_t);

		request = request_alloc(u);
		request->async = talloc_zero(request, fr_async_t);
		talloc_const_free(request->name);
		request->name = talloc_strdup(request, c->module_name);

		request->el = c->thread->el;
		request->packet = fr_radius_alloc(request, false);
		request->reply = fr_radius_alloc(request, false);

		/*
		 *	Create the packet contents.
		 */
		if (c->inst->parent->status_check == FR_CODE_STATUS_SERVER) {
			VALUE_PAIR *vp;

			MEM(pair_add_request(&vp, attr_nas_identifier) >= 0);
			fr_pair_value_strcpy(vp, "status check - are you alive?");

			MEM(pair_add_request(NULL, attr_event_timestamp) >= 0);
		} else {
			vp_map_t *map;

			/*
			 *	Create the VPs, and ignore any errors
			 *	creating them.
			 */
			for (map = c->inst->parent->status_check_map; map != NULL; map = map->next) {
				/*
				 *	Skip things which aren't attributes.
				 */
				if (!tmpl_is_attr(map->lhs)) continue;

				/*
				 *	Disallow signalling attributes.
				 */
				if ((map->lhs->tmpl_da == attr_proxy_state) ||
				    (map->lhs->tmpl_da == attr_event_timestamp) ||
				    (map->lhs->tmpl_da == attr_acct_delay_time) ||
				    (map->lhs->tmpl_da == attr_message_authenticator)) continue;

				/*
				 *	Allow passwords only in Access-Request packets.
				 */
				if ((c->inst->parent->status_check != FR_CODE_ACCESS_REQUEST) &&
				    (map->lhs->tmpl_da == attr_user_password)) continue;

				(void) map_to_request(request, map, map_to_vp, NULL);
			}

			/*
			 *	Always add an Event-Timestamp, which
			 *	will be the time at which the packet
			 *	is sent.
			 */
			MEM(pair_update_request(NULL, attr_event_timestamp) >= 0);
		}

		DEBUG3("Status check packet will be %s", fr_packet_codes[u->code]);
		log_request_pair_list(L_DBG_LVL_3, request, request->packet->vps, NULL);

		/*
		 *	Initialize the request IO ctx.  Note that we don't set
		 *	destructors.
		 */
		u->request = request;
		u->code = c->inst->parent->status_check;
		request->packet->code = u->code;
		u->c = c;
		u->thread = t;

		/*
		 *	Reserve a permanent ID for the packet.  This
		 *	is because we need to be able to send an ID on
		 *	demand.  If the proxied packets use all of the
		 *	IDs, then we can't send a Status-Server check.
		 */
		u->rr = rr_track_alloc(radius->id, request, u->code, u, &u->timer);
		if (!u->rr) {
			ERROR("%s - Failed allocating status_check ID for connection %s",
			      c->module_name, c->name);
			talloc_free(u);

		} else {
			DEBUG2("%s - Allocated %s ID %u for status checks on connection %s",
			       c->module_name, fr_packet_codes[u->code], u->rr->id, c->name);
			talloc_set_destructor(u, status_udp_request_free);
			radius->status_u = u;
			c->slots_free = radius->id->num_free;
		}
	}

	/*
	 *	Reset the timer, retransmission counters, etc.
	 */
	if (radius->status_u) {
		fr_io_request_t *u = radius->status_u;

		if (u->timer.ev) (void) fr_event_timer_delete(u->thread->el, &u->timer.ev);

		memset(&u->timer, 0, sizeof(u->timer));
		u->timer.retry = &c->inst->parent->retry[u->code];
		radius->status_check_blocked = false;
	}
} /* RADIUS end */

	/*
	 *	Now that we're open, assume that the connection is
	 *	writable.
	 */
	if (fr_heap_num_elements(t->queued) > 0) conn_writable(c->thread->el, fd, 0, c);

	/*
	 *	@todo - do negotiation on the connection by sending
	 *	Status-Server with bits of information.  If there's an
	 *	appropriate response, then transition the connection
	 *	to ACTIVE.  Otherwise, leave the connection as
	 *	OPENING, and start the negotiation phase.
	 */
	conn_transition(c, CONN_ACTIVE);

	return FR_CONNECTION_STATE_CONNECTED;
}


/** Allocate a new connection and set it up.
 *
 */
static void conn_alloc(rlm_radius_udp_t *inst, fr_io_connection_thread_t *t)
{
	fr_io_connection_t	*c;
	rlm_radius_udp_connection_t *radius;

	c = talloc_zero(t, fr_io_connection_t);
	c->module_name = inst->parent->name;
	c->heap_id = -1;
	c->inst = inst;
	c->thread = t;
	c->dst_ipaddr = inst->dst_ipaddr;
	c->dst_port = inst->dst_port;
	c->src_ipaddr = inst->src_ipaddr;
	c->src_port = 0;
	c->max_packet_size = inst->max_packet_size;

	c->buffer = talloc_array(c, uint8_t, c->max_packet_size);
	if (!c->buffer) {
		cf_log_err(inst->config, "%s failed allocating memory for new connection",
			   c->module_name);
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
	c->ctx = radius = talloc_zero(c, rlm_radius_udp_connection_t);

	radius->id = rr_track_create(radius);
	if (!radius->id) {
		cf_log_err(inst->config, "%s - Failed allocating ID tracking for new connection",
			   c->module_name);
		talloc_free(c);
		return;
	}
	fr_dlist_init(&c->sent, fr_io_request_t, entry);

	c->conn = fr_connection_alloc(c, t->el, t->connection_timeout, t->reconnection_delay,
				      _conn_init,
				      _conn_open,
				      _conn_close,
				      c->module_name, c);
	if (!c->conn) {
		talloc_free(c);
		cf_log_err(inst->config, "%s - Failed allocating state handler for new connection",
			   c->module_name);
		return;
	}
	fr_connection_failed_func(c->conn, _conn_failed);

	/*
	 *	Enforce max_connections via atomic variables.
	 *
	 *	Note that we're counting connections which are in the
	 *	CONN_OPENING and CONN_ZOMBIE states, too.
	 */
	while (true) {
		uint32_t num_connections;

		num_connections = load(inst->parent->num_connections);

		if (num_connections >= t->max_connections) {
			TALLOC_FREE(c->conn); /* ordering */
			talloc_free(c);
			return;
		}
		if (cas_incr(inst->parent->num_connections, num_connections)) break;
	}

	fr_connection_signal_init(c->conn);

	talloc_set_destructor(c, _conn_free);

	return;
}

static rlm_rcode_t mod_push(void *instance, REQUEST *request, void *request_io_ctx, void *thread)
{
	rlm_rcode_t    			rcode = RLM_MODULE_FAIL;
	rlm_radius_udp_t		*inst = talloc_get_type_abort(instance, rlm_radius_udp_t);
	fr_io_connection_thread_t	*t = talloc_get_type_abort(thread, fr_io_connection_thread_t);
	fr_io_request_t			*u = talloc_get_type_abort(request_io_ctx, fr_io_request_t);
	fr_io_connection_t		*c;

	rad_assert(request->packet->code > 0);
	rad_assert(request->packet->code < FR_RADIUS_MAX_PACKET_CODE);

	/*
	 *	If configured, and we don't have any active
	 *	connections, fail the request.  This lets "parallel"
	 *	sections finish much more quickly than otherwise.
	 */
	if (inst->parent->no_connection_fail && !fr_heap_num_elements(t->active)) {
		REDEBUG("Failing request due to 'no_connection_fail = true', and there are no active connections");
		return RLM_MODULE_FAIL;
	}

	u->state = REQUEST_IO_STATE_INIT;
	u->rr = NULL;
	u->c = NULL;
	u->request = request;
	u->rcode = RLM_MODULE_FAIL;
	u->code = request->packet->code;
	u->thread = t;
	u->heap_id = -1;
	u->timer.retry = &inst->parent->retry[u->code];
	fr_dlist_entry_init(&u->entry);

	talloc_set_destructor(u, udp_request_free);

	/*
	 *	Insert the new packet into the thread queue.
	 */
	state_transition(u, REQUEST_IO_STATE_QUEUED, NULL);

	/*
	 *	If it's synchronous, remember the time we sent this
	 *	packet.  Otherwise, start the retransmission timers.
	 */
	if (inst->parent->synchronous) {
		u->time_sent = fr_time();

	} else if (conn_timeout_init(t->el, u, response_timeout) < 0) {
		RDEBUG("%s - Failed starting retransmit tracking", inst->parent->name);
		talloc_free(u);
		return RLM_MODULE_FAIL;
	}

	/*
	 *	There are OTHER pending writes, wait for the event
	 *	callbacks to wake up a connection and send the packet.
	 */
	if (fr_heap_num_elements(t->queued) > 1) {
		u->yielded = true;
		DEBUG3("Thread has pending packets.  Waiting for socket to be ready");
		return RLM_MODULE_YIELD;
	}

	/*
	 *	There are no pending writes.  Get a waiting
	 *	connection.  If they're all full, try to open a new
	 *	one.
	 */
	c = fr_heap_peek(t->active);
	if (!c) {
		/*
		 *	Only open one new connection at a time.
		 */
		if (!fr_dlist_head(&t->opening)) conn_alloc(inst, t);

		/*
		 *	Add the request to the backlog.  It will be
		 *	sent either when the new connection is open,
		 *	or when an existing connection has
		 *	availability.
		 */
		u->yielded = true;
		return RLM_MODULE_YIELD;
	}

	/*
	 *	The connection is active, so try to write to it.
	 */
	conn_writable(t->el, c->fd, 0, c);

	switch (u->state) {
	case REQUEST_IO_STATE_INIT:
		rad_assert(0 == 1);
		break;

	case REQUEST_IO_STATE_QUEUED:
	case REQUEST_IO_STATE_WRITTEN:
		rcode = RLM_MODULE_YIELD;
		u->yielded = true;
		break;

	case REQUEST_IO_STATE_REPLIED:
		state_transition(u, REQUEST_IO_STATE_DONE, NULL);
		/* FALL-THROUGH */

	case REQUEST_IO_STATE_DONE:
		rcode = RLM_MODULE_OK;
		break;
	}

	return rcode;
}


static void mod_signal(REQUEST *request, void *instance, UNUSED void *thread, void *request_io_ctx, fr_state_signal_t action)
{
	rlm_radius_udp_t *inst = talloc_get_type_abort(instance, rlm_radius_udp_t);
	fr_io_request_t *u = talloc_get_type_abort(request_io_ctx, fr_io_request_t);

	if (action != FR_SIGNAL_DUP) return;

	/*
	 *	Asychronous mode means that we do retransmission, and
	 *	we don't rely on the retransmission from the NAS.
	 */
	if (!inst->parent->synchronous) return;

	RDEBUG("retransmitting proxied request");

	retransmit_packet(u, fr_time());
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
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_radius_udp_t *inst = talloc_get_type_abort(instance, rlm_radius_udp_t);

	(void) talloc_set_type(inst, rlm_radius_udp_t);
	inst->config = conf;

	return 0;
}


/** Instantiate the module
 *
 * Instantiate I/O and type submodules.
 *
 * @param[in] parent    rlm_radius_t
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
	inst->replicate = parent->replicate;

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
		cf_log_err(conf, "The 'ipaddr' and 'src_ipaddr' configuration items must "
			   "be both of the same address family");
		return -1;
	}

	if (!inst->dst_port) {
		cf_log_err(conf, "A value must be given for 'port'");
		return -1;
	}

	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, inst->max_packet_size);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, (1 << 30));
	}

	if (inst->send_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, >=, inst->max_packet_size);
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, <=, (1 << 30));
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
	rlm_radius_udp_t *inst = talloc_get_type_abort(instance, rlm_radius_udp_t);
	fr_io_connection_thread_t *t = talloc_get_type_abort(thread, fr_io_connection_thread_t);
	int rcode;

#define COPY(_x) t->_x = inst->parent->_x
	COPY(max_connections);
	COPY(connection_timeout);
	COPY(reconnection_delay);
	COPY(idle_timeout);
	COPY(zombie_period);

	rcode = conn_thread_instantiate(t, el);
	if (rcode < 0) return rcode;

	conn_alloc(inst, t);
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
	.magic			= RLM_MODULE_INIT,
	.name			= "radius_udp",
	.inst_size		= sizeof(rlm_radius_udp_t),

	.request_inst_size 	= sizeof(fr_io_request_t),
	.request_inst_type	= "fr_io_request_t",

	.thread_inst_size	= sizeof(fr_io_connection_thread_t),
	.thread_inst_type	= "fr_io_connection_thread_t",

	.config			= module_config,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,
	.thread_instantiate 	= mod_thread_instantiate,
	.thread_detach		= conn_thread_detach,

	.push			= mod_push,
	.signal			= mod_signal,
	.resume			= conn_request_resume,
};
