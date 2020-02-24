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

	fr_trunk_conf_t		*trunk_conf;		//!< trunk configuration
} rlm_radius_udp_t;

typedef struct {
	fr_event_list_t		*el;			//!< Event list.

	rlm_radius_udp_t const	*inst;			//!< our instance

	fr_trunk_t		*trunk;			//!< trunk handler
} udp_thread_t;

/** Track the connection, but not the handle.
 *
 */
typedef struct {
	fr_trunk_connection_t	*tconn;
	fr_connection_t		*conn;
} udp_connection_t;

typedef struct udp_request_s udp_request_t;

/** Track the handle, which is tightly correlated with the FD
 *
 */
typedef struct {
	char const     		*name;			//!< From IP PORT to IP PORT.
	char const		*module_name;		//!< the module that opened the connection
	int			fd;			//!< File descriptor.

	rlm_radius_udp_t const	*inst;			//!< Our module instance.
	udp_connection_t	*c;			//!< long-term connection
	udp_thread_t		*thread;

	uint8_t			last_id;		//!< Used when replicating to ensure IDs are distributed
							///< evenly.

	uint32_t		max_packet_size;	//!< Our max packet size. may be different from the parent.

	fr_ipaddr_t		src_ipaddr;		//!< Source IP address.  May be altered on bind
							//!< to be the actual IP address packets will be
							//!< sent on.  This is why we can't use the inst
							//!< src_ipaddr field.
	uint16_t		src_port;		//!< Source port specific to this connection.

	uint8_t			*buffer;		//!< Receive buffer.
	size_t			buflen;			//!< Receive buffer length.

	radius_track_t		*tt;			//!< RADIUS ID tracking structure.

	fr_time_t		mrs_time;		//!< Most recent sent time which had a reply.
	fr_time_t		last_reply;		//!< When we last received a reply.
	fr_time_t		first_sent;		//!< first time we sent a packet since going idle
	fr_time_t		last_sent;		//!< last time we sent a packet.
	fr_time_t		last_idle;		//!< last time we had nothing to do

	fr_event_timer_t const	*zombie_ev;		//!< Zombie timeout.

	bool			status_checking;       	//!< whether we're doing status checks
	udp_request_t		*status_u;		//!< for sending Status-Server packets
	REQUEST			*status_request;

	fr_trunk_connection_event_t trunk_notify;	//!< trunks idea of FD readability
	fr_trunk_connection_event_t status_notify;	//!< our idea of FD readability

} udp_handle_t;

typedef struct {
	fr_trunk_request_t	*treq;
	rlm_rcode_t		rcode;			//!< from the transport
} udp_result_t;


/** Connect REQUEST to local tracking structure
 *
 */
struct udp_request_s {
	uint32_t		priority;		//!< copied from request->async->priority
	fr_time_t		recv_time;		//!< copied from request->async->recv_time

	int			num_replies;		//!< number of reply packets, sent is in retry.count

	bool			synchronous;		//!< cached from inst->parent->synchronous
	bool			require_ma;		//!< saved from the original packet.
	bool			can_retransmit;		//!< can we retransmit this packet?

	VALUE_PAIR		*extra;			//!< VPs for debugging, like Proxy-State.

	int			code;			//!< Packet code.

	uint8_t			*packet;		//!< Packet we write to the network.
	size_t			packet_len;		//!< Length of the packet.

	uint8_t			*authenticator;		//!< Pointer into packet at the location of the
							///< authenticator.

	udp_connection_t       	*c;			//!< The outbound connection
	radius_track_entry_t	*rr;			//!< ID tracking, resend count, etc.
	fr_event_timer_t const	*ev;			//!< timer for retransmissions
	fr_retry_t		retry;			//!< retransmission timers
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


/** Initialise a new outbound connection
 *
 * @param[out] h_out	Where to write the new file descriptor.
 * @param[in] conn	to initialise.
 * @param[in] uctx	A #udp_connection_t
 */
static fr_connection_state_t conn_init(void **h_out, fr_connection_t *conn, void *uctx)
{
	int			fd;
	udp_handle_t		*h;
	udp_thread_t		*thread = talloc_get_type_abort(uctx, udp_thread_t);

	h = talloc_zero(conn, udp_handle_t);
	if (!h) return FR_CONNECTION_STATE_FAILED;

	h->thread = thread;
	h->inst = thread->inst;
	h->module_name = h->inst->parent->name;
	h->src_ipaddr = h->inst->src_ipaddr;
	h->src_port = 0;
	h->max_packet_size = h->inst->max_packet_size;
	h->last_idle = fr_time();

	MEM(h->buffer = talloc_array(h, uint8_t, h->max_packet_size));
	h->buflen = h->max_packet_size;

	if (!h->inst->replicate) MEM(h->tt = radius_track_alloc(h));

	/*
	 *	Open the outgoing socket.
	 */
	fd = fr_socket_client_udp(&h->src_ipaddr, &h->src_port, &h->inst->dst_ipaddr, h->inst->dst_port, true);
	if (fd < 0) {
		ERROR("%s - Failed opening socket", h->module_name);
		talloc_free(h);
		return FR_CONNECTION_STATE_FAILED;
	}

	/*
	 *	Set the connection name.
	 */
	h->name = fr_asprintf(h, "connecting proto udp local %pV port %u remote %pV port %u",
			      fr_box_ipaddr(h->src_ipaddr), h->src_port,
			      fr_box_ipaddr(h->inst->dst_ipaddr), h->inst->dst_port);

#ifdef SO_RCVBUF
	if (h->inst->recv_buff_is_set) {
		int opt;

		opt = h->inst->recv_buff;
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(int)) < 0) {
			WARN("%s - Failed setting 'recv_buf': %s", h->module_name, fr_syserror(errno));
		}
	}
#endif

#ifdef SO_SNDBUF
	if (h->inst->send_buff_is_set) {
		int opt;

		opt = h->inst->send_buff;
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(int)) < 0) {
			WARN("%s - Failed setting 'send_buf': %s", h->module_name, fr_syserror(errno));
		}
	}
#endif

	h->fd = fd;

	/*
	 *	@todo - if all connections are down, then only allow
	 *	one to be open.  And, start Status-Server messages on
	 *	that connection.
	 *
	 *	@todo - connection negotiation via Status-Server.
	 *	This requires different "signal on fd" functions.
	 */
	fr_connection_signal_on_fd(conn, fd);

	*h_out = h;

	// @todo - initialize the tracking memory, etc.
	// i.e. histograms (or hyperloglog) of packets, so we can see
	// which connections / home servers are fast / slow.

	return FR_CONNECTION_STATE_CONNECTING;
}

/*
 *	Status-Server checks.  Manually build the packet, and
 *	all of its associated glue.
 */
static void status_check_alloc(fr_event_list_t *el, udp_handle_t *h)
{
	udp_request_t *u;
	REQUEST *request;
	rlm_radius_udp_t const *inst = h->inst;
	vp_map_t *map;

	u = talloc_zero(h, udp_request_t);

	/*
	 *	Allocate outside of the free list.
	 *	There appears to be an issue where
	 *	the thread destructor runs too
	 *	early, and frees the freelist's
	 *	head before the module destructor
	 *      runs.
	 */
	request = request_local_alloc(h);
	request->async = talloc_zero(request, fr_async_t);
	talloc_const_free(request->name);
	request->name = talloc_strdup(request, h->module_name);

	request->el = el;
	request->packet = fr_radius_alloc(request, false);
	request->reply = fr_radius_alloc(request, false);

	/*
	 *	Create the VPs, and ignore any errors
	 *	creating them.
	 */
	for (map = inst->parent->status_check_map; map != NULL; map = map->next) {
		/*
		 *	Skip things which aren't attributes.
		 */
		if (!tmpl_is_attr(map->lhs)) continue;

		/*
		 *	Ignore internal attributes.
		 */
		if (map->lhs->tmpl_da->flags.internal) continue;

		/*
		 *	Ignore signalling attributes.  They shouldn't exist.
		 */
		if ((map->lhs->tmpl_da == attr_proxy_state) ||
		    (map->lhs->tmpl_da == attr_message_authenticator)) continue;

		/*
		 *	Allow passwords only in Access-Request packets.
		 */
		if ((inst->parent->status_check != FR_CODE_ACCESS_REQUEST) &&
		    (map->lhs->tmpl_da == attr_user_password)) continue;

		(void) map_to_request(request, map, map_to_vp, NULL);
	}

	/*
	 *	Ensure that there's a NAS-Identifier, if one wasn't
	 *	already added.
	 */
	if (!fr_pair_find_by_da(request->packet->vps, attr_nas_identifier, TAG_ANY)) {
		VALUE_PAIR *vp;

		MEM(pair_add_request(&vp, attr_nas_identifier) >= 0);
		fr_pair_value_strcpy(vp, "status check - are you alive?");
	}

	/*
	 *	Always add an Event-Timestamp, which will be the time
	 *	at which the first packet is sent.  Or for
	 *	Status-Server, the time of the current packet.
	 */
	if (!fr_pair_find_by_da(request->packet->vps, attr_event_timestamp, TAG_ANY)) {
		MEM(pair_add_request(NULL, attr_event_timestamp) >= 0);
	}

	DEBUG3("Status check packet will be %s", fr_packet_codes[u->code]);
	log_request_pair_list(L_DBG_LVL_3, request, request->packet->vps, NULL);

	/*
	 *	Initialize the request IO ctx.  Note that we don't set
	 *	destructors.
	 */
	u->code = inst->parent->status_check;
	request->packet->code = u->code;
	u->c = h->c;		/* h can mutate during the lifetime of c */

	/*
	 *	Reserve a permanent ID for the packet.  This
	 *	is because we need to be able to send an ID on
	 *	demand.  If the proxied packets use all of the
	 *	IDs, then we can't send a Status-Server check.
	 */
	u->rr = radius_track_entry_alloc(h->tt, request, u->code, u);
	if (!u->rr) {
		ERROR("%s - Failed allocating status_check ID for connection %s",
		      h->module_name, h->name);
		talloc_free(u);
		return;
	}

	DEBUG2("%s - Allocated %s ID %u for status checks on connection %s",
	       h->module_name, fr_packet_codes[u->code], u->rr->id, h->name);

	h->status_u = u;
	h->status_request = request;
}

/** Process notification that fd is open
 *
 */
static fr_connection_state_t conn_open(fr_event_list_t *el, void *handle, UNUSED void *uctx)
{
	udp_handle_t		*h = talloc_get_type_abort(handle, udp_handle_t);
	rlm_radius_udp_t const *inst = h->inst;

	talloc_const_free(h->name);
	h->name = fr_asprintf(h, "proto udp local %pV port %u remote %pV port %u",
			      fr_box_ipaddr(h->src_ipaddr), h->src_port,
			      fr_box_ipaddr(inst->dst_ipaddr), inst->dst_port);

	DEBUG("%s - Connection open - %s", h->module_name, h->name);

	/*
	 *	Connection is "active" now.  i.e. we prefer the newly
	 *	opened connection for sending packets.
	 */
	if (h->inst->parent->status_check) status_check_alloc(el, h);

	return FR_CONNECTION_STATE_CONNECTED;
}

/** Shutdown/close a file descriptor
 *
 */
static void conn_close(fr_event_list_t *el, void *handle, UNUSED void *uctx)
{
	udp_handle_t *h = talloc_get_type_abort(handle, udp_handle_t);

	fr_event_fd_delete(el, h->fd, FR_EVENT_FILTER_IO);

	if (shutdown(h->fd, SHUT_RDWR) < 0) {
		DEBUG3("%s - Failed shutting down connection %s: %s",
		       h->module_name, h->name, fr_syserror(errno));
	}

	if (close(h->fd) < 0) {
		DEBUG3("%s - Failed closing connection %s: %s",
		       h->module_name, h->name, fr_syserror(errno));
	}

	h->fd = -1;

	DEBUG("%s - Connection closed - %s", h->module_name, h->name);
}

/** Connection failed
 *
 * @param[in] handle   	of connection that failed.
 * @param[in] state	the connection was in when it failed.
 * @param[in] uctx	a #udp_connection_t
 */
static fr_connection_state_t conn_failed(void *handle, fr_connection_state_t state, UNUSED void *uctx)
{
	udp_handle_t	*h = talloc_get_type_abort(handle, udp_handle_t);

	/*
	 *	If the connection was connected when it failed,
	 *	we need to handle any outstanding packets and
	 *	timer events before reconnecting.
	 */
	if (state == FR_CONNECTION_STATE_CONNECTED) {
		/*
		 *	Reset the Status-Server checks.
		 */
		if (h->status_u && h->status_u->ev) {
			(void) fr_event_timer_delete(&h->status_u->ev);
		}
	}

	return FR_CONNECTION_STATE_INIT;
}

static fr_connection_t *thread_conn_alloc(fr_trunk_connection_t *tconn, fr_event_list_t *el,
					  fr_connection_conf_t const *conf,
					  char const *log_prefix, void *uctx)
{
	udp_connection_t	*c;
	udp_thread_t		*thread = talloc_get_type_abort(uctx, udp_thread_t);

	c = talloc_zero(tconn, udp_connection_t);
	if (!c) return NULL;

	c->tconn = tconn;

	c->conn = fr_connection_alloc(c, el,
				      &(fr_connection_funcs_t){
					.init = conn_init,
					.open = conn_open,
					.close = conn_close,
					.failed = conn_failed
				      },
				      conf,
				      log_prefix,
				      thread);
	if (!c->conn) {
		talloc_free(c);
		PERROR("Failed allocating state handler for new connection");
		return NULL;
	}

	return c->conn;
}

/** Read and discard data
 *
 */
static void conn_discard(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);
	uint8_t			buffer[4096];
	ssize_t			slen;

	while ((slen = read(fd, buffer, sizeof(buffer))) > 0);

	if (slen < 0) {
		switch (errno) {
		case EBADF:
		case ECONNRESET:
		case ENOTCONN:
		case ETIMEDOUT:
			fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
			break;

		default:
			break;
		}
	}
}

/** Standard I/O read function
 *
 * Underlying FD in now readable, so call the trunk to read any pending requests
 * from this connection.
 *
 * @param[in] el	The event list signalling.
 * @param[in] fd	that's now readable.
 * @param[in] flags	describing the read event.
 * @param[in] uctx	The trunk connection handle (tconn).
 */
static void conn_readable(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);

	fr_trunk_connection_signal_readable(tconn);
}

/** Standard I/O write function
 *
 * Underlying FD is now writable, so call the trunk to write any pending requests
 * to this connection.
 *
 * @param[in] el	The event list signalling.
 * @param[in] fd	that's now writable.
 * @param[in] flags	describing the write event.
 * @param[in] uctx	The trunk connection handle (tcon).
 */
static void conn_writable(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);

	fr_trunk_connection_signal_writable(tconn);
}

/** Connection errored
 *
 * We were signalled by the event loop that a fatal error occurred on this connection.
 *
 * @param[in] el	The event list signalling.
 * @param[in] fd	that errored.
 * @param[in] flags	El flags.
 * @param[in] fd_errno	The nature of the error.
 * @param[in] uctx	The trunk connection handle (tconn).
 */
static void conn_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, int fd_errno, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);
	fr_connection_t		*conn = tconn->conn;
	udp_handle_t		*h = talloc_get_type_abort(conn->h, udp_handle_t);

	ERROR("%s - Connection %s failed - %s", h->inst->parent->name, h->name, fr_syserror(fd_errno));

	fr_connection_signal_reconnect(conn, FR_CONNECTION_FAILED);
}

static void thread_conn_notify(fr_trunk_connection_t *tconn, fr_connection_t *conn,
			       fr_event_list_t *el,
			       fr_trunk_connection_event_t notify_on, UNUSED void *uctx)
{
	udp_handle_t		*h = talloc_get_type_abort(conn->h, udp_handle_t);
	fr_event_fd_cb_t	read_fn = NULL;
	fr_event_fd_cb_t	write_fn = NULL;

	/*
	 *	Ensure that the FD is still readable if the only event is status-checks.
	 */
	if (h->status_checking && ((notify_on & FR_TRUNK_CONN_EVENT_READ) == 0)) {
		h->trunk_notify = notify_on;
		notify_on |= FR_TRUNK_CONN_EVENT_READ;
		h->status_notify = notify_on;

	} else {
		h->trunk_notify = h->status_notify = notify_on;
	}

	switch (notify_on) {
		/*
		 *	We may have sent multiple requests to the
		 *	other end, so it might be sending us multiple
		 *	replies.  We want to drain the socket, instead
		 *	of letting the packets sit in the UDP receive
		 *	queue.
		 */
	case FR_TRUNK_CONN_EVENT_NONE:
		read_fn = conn_discard;
		write_fn = NULL;
		break;

	case FR_TRUNK_CONN_EVENT_READ:
		read_fn = conn_readable;
		break;

	case FR_TRUNK_CONN_EVENT_WRITE:
		write_fn = conn_writable;
		break;

	case FR_TRUNK_CONN_EVENT_BOTH:
		read_fn = conn_readable;
		write_fn = conn_writable;
		break;

	}

	if (fr_event_fd_insert(h, el, h->fd,
			       read_fn,
			       write_fn,
			       conn_error,
			       tconn) < 0) {
		ERROR("%s - Failed inserting FD event", h->module_name);

		/*
		 *	May free the connection!
		 */
		fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
	}
}

/** A special version of the trunk/event loop glue function which always discards incoming data
 *
 */
static void thread_conn_notify_replicate(fr_trunk_connection_t *tconn, fr_connection_t *conn,
					 fr_event_list_t *el,
					 fr_trunk_connection_event_t notify_on, UNUSED void *uctx)
{
	udp_handle_t		*h = talloc_get_type_abort(conn->h, udp_handle_t);
	fr_event_fd_cb_t	read_fn = NULL;
	fr_event_fd_cb_t	write_fn = NULL;

	switch (notify_on) {
	case FR_TRUNK_CONN_EVENT_NONE:
		read_fn = conn_discard;
		write_fn = NULL;
		break;

	case FR_TRUNK_CONN_EVENT_READ:
	case FR_TRUNK_CONN_EVENT_BOTH:
		rad_assert(0);	/* Should never happen */
		break;

	case FR_TRUNK_CONN_EVENT_WRITE:
		read_fn = conn_discard;
		write_fn = conn_writable;
		break;
	}

	if (fr_event_fd_insert(h, el, h->fd,
			       read_fn,
			       write_fn,
			       conn_error,
			       tconn) < 0) {
		ERROR("%s - Failed inserting FD event", h->module_name);

		/*
		 *	May free the connection!
		 */
		fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
	}
}

/*
 *  Return negative numbers to put 'a' at the top of the heap.
 *  Return positive numbers to put 'b' at the top of the heap.
 *
 *  We want the value with the lowest timestamp to be prioritized at
 *  the top of the heap.
 */
static int8_t request_prioritise(void const *one, void const *two)
{
	udp_request_t const *a = one;
	udp_request_t const *b = two;
	int8_t rcode;

	// @todo - prioritize packets if there's a state?

	/*
	 *	Larger priority is more important.
	 */
	rcode = (a->priority < b->priority) - (a->priority > b->priority);
	if (rcode != 0) return rcode;

	/*
	 *	Smaller timestamp (i.e. earlier) is more important.
	 */
	return (a->recv_time > b->recv_time) - (a->recv_time < b->recv_time);
}

static int encode(rlm_radius_udp_t const *inst, REQUEST *request, udp_request_t *u, uint8_t id, bool status_check)
{
	ssize_t			packet_len;
	uint8_t			*msg = NULL;
	int			message_authenticator = u->require_ma * (RADIUS_MESSAGE_AUTHENTICATOR_LENGTH + 2);
	int			proxy_state = 6;

	rad_assert(inst->parent->allowed[u->code]);
	rad_assert(u->packet == NULL);

	/*
	 *	Might have been sent and then given up on... free the
	 *	raw data so we can re-encode it.
	 */
	if (u->packet) {
		TALLOC_FREE(u->packet);
		fr_pair_list_free(&u->extra);
	}

	/*
	 *	Try to retransmit, unless there are special
	 *	circumstances.
	 */
	u->can_retransmit = true;

	/*
	 *	This is essentially free, as this memory was
	 *	pre-allocated as part of the treq.
	 */
	u->packet_len = inst->max_packet_size;
	MEM(u->packet = talloc_array(u, uint8_t, u->packet_len));

	/*
	 *	All proxied Access-Request packets MUST have a
	 *	Message-Authenticator, otherwise they're insecure.
	 *	Same goes for Status-Server.
	 *
	 *	And we set the authentication vector to a random
	 *	number...
	 */
	switch (u->code) {
	case FR_CODE_ACCESS_REQUEST:
	case FR_CODE_STATUS_SERVER:
	{
		size_t i;
		uint32_t hash, base;

		message_authenticator = RADIUS_MESSAGE_AUTHENTICATOR_LENGTH + 2;

		base = fr_rand();
		for (i = 0; i < RADIUS_AUTH_VECTOR_LENGTH; i += sizeof(uint32_t)) {
			hash = fr_rand() ^ base;
			memcpy(u->packet + RADIUS_AUTH_VECTOR_OFFSET + i, &hash, sizeof(hash));
		}
	}
	default:
		break;
	}


	/*
	 *	If we're sending a status check packet, update any
	 *	necessary timestamps.  Also, don't add Proxy-State, as
	 *	we're originating the packet.
	 */
	if (status_check) {
		VALUE_PAIR *vp;

		proxy_state = 0;
		vp = fr_pair_find_by_da(request->packet->vps, attr_event_timestamp, TAG_ANY);
		if (vp) {
			vp->vp_date = fr_time_to_unix_time(u->retry.updated);
		}

		u->can_retransmit = false;
	}

	/*
	 *	We should have at mininum 64-byte packets, so don't
	 *	bother doing run-time checks here.
	 */
	rad_assert(u->packet_len >= (size_t) (RADIUS_HEADER_LENGTH + proxy_state + message_authenticator));

	/*
	 *	Encode it, leaving room for Proxy-State and
	 *	Message-Authenticator if necessary.
	 */
	packet_len = fr_radius_encode(u->packet, u->packet_len - (proxy_state + message_authenticator), NULL,
				      inst->secret, talloc_array_length(inst->secret) - 1,
				      u->code, id, request->packet->vps);
	if (packet_len <= 0) return -1;

	/*
	 *	Add Proxy-State to the tail end of the packet unless we are
	 *	originating the request.
	 *
	 *	We need to add it here, and NOT in
	 *	request->packet->vps, because multiple modules
	 *	may be sending the packets at the same time.
	 *
	 *	Note that the length check will always pass, due to
	 *	the buflen manipulation done above.
	 */
	if (proxy_state && !inst->parent->originate) {
		uint8_t		*attr = u->packet + packet_len;
		VALUE_PAIR	*vp;
		vp_cursor_t	cursor;
		int		count = 0;

		rad_assert((size_t) (packet_len + proxy_state) <= u->packet_len);

		/*
		 *	Count how many Proxy-State attributes have
		 *	*our* magic number.  Note that we also add a
		 *	counter to each Proxy-State, so we're double
		 *	sure that it's a loop.
		 */
		if (DEBUG_ENABLED) {
			(void) fr_pair_cursor_init(&cursor, &request->packet->vps);
			while ((vp = fr_pair_cursor_next_by_da(&cursor, attr_proxy_state, TAG_ANY)) != NULL) {
				if ((vp->vp_length == 5) && (memcmp(vp->vp_octets, &inst->parent->proxy_state, 4) == 0)) {
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
		attr[1] = 7;
		memcpy(attr + 2, &inst->parent->proxy_state, 4);
		attr[6] = count & 0xff;
		packet_len += 7;

		MEM(vp = fr_pair_afrom_da(u, attr_proxy_state));
		fr_pair_value_memcpy(vp, attr + 2, 5, true);
		fr_pair_add(&u->extra, vp);
	}

	/*
	 *	Add Message-Authenticator manually.
	 *
	 *	Note that the length check will always pass, due to
	 *	the buflen manipulation done above.
	 */
	if (message_authenticator) {
		rad_assert((size_t) (packet_len + message_authenticator) <= u->packet_len);

		msg = u->packet + packet_len;

		msg[0] = (uint8_t) attr_message_authenticator->attr;
		msg[1] = RADIUS_MESSAGE_AUTHENTICATOR_LENGTH + 2;
		memset(msg + 2, 0,  RADIUS_MESSAGE_AUTHENTICATOR_LENGTH);

		packet_len += msg[1];
	}

	/*
	 *	Update the packet header based on the new attributes.
	 */
	u->packet[2] = (packet_len >> 8) & 0xff;
	u->packet[3] = packet_len & 0xff;
	u->packet_len = packet_len;

	/*
	 *	Ensure that we update the Acct-Delay-Time based on the
	 *	time difference between now, and when we originally
	 *	received the request.
	 */
	if ((u->code == FR_CODE_ACCOUNTING_REQUEST) &&
	    (fr_pair_find_by_da(request->packet->vps, attr_acct_delay_time, TAG_ANY) != NULL)) {
		uint8_t *attr, *end;
		uint32_t delay;
		fr_time_t now;

		/*
		 *	Change Acct-Delay-Time in the packet, but not
		 *	in the debug output.  Oh well.  We don't want
		 *	to edit the incoming VPs, and we want to
		 *	update the encoded version of Acct-Delay-Time.
		 *	So we just walk through the packet to find it.
		 */
		end = u->packet + packet_len;

		for (attr = u->packet + RADIUS_HEADER_LENGTH;
		     attr < end;
		     attr += attr[1]) {
			if (attr[0] != attr_acct_delay_time->attr) continue;
			if (attr[1] != 6) continue;

			now = u->retry.updated;

			/*
			 *	Add in the time between when
			 *	we received the packet, and
			 *	when we're sending the packet.
			 */
			memcpy(&delay, attr + 2, 4);
			delay = ntohl(delay);
			delay += fr_time_delta_to_sec(now - u->recv_time);
			delay = htonl(delay);
			memcpy(attr + 2, &delay, 4);
			break;
		}

		u->can_retransmit = false;
	}

	/*
	 *	Now that we're done mangling the packet, sign it.
	 */
	if (fr_radius_sign(u->packet, NULL, (uint8_t const *) inst->secret,
			   talloc_array_length(inst->secret) - 1) < 0) {
		RERROR("Failed signing packet");
		return -1;
	}

	return 0;
}


/** Revive a connection after "revive_interval"
 *
 */
static void revive_timer(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);
	udp_handle_t	 	*h = talloc_get_type_abort(tconn->conn->h, udp_handle_t);

	DEBUG("Shutting down and reviving connection %s", h->name);
	fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
}


/** Run the status check timers.
 *
 */
static void status_check_timer(fr_event_list_t *el, fr_time_t now, void *uctx)
{
	udp_request_t		*u = talloc_get_type_abort(uctx, udp_request_t);
	udp_handle_t	 	*h = talloc_get_type_abort(u->c->conn->h, udp_handle_t);
	fr_retry_state_t	state;
	ssize_t			rcode;
	uint32_t		msec;

	if (!now) {
		/*
		 *	Initialize timers for Status-Server.
		 */
		(void) fr_retry_init(&u->retry, now, &h->inst->parent->retry[u->code]);
		u->num_replies = 0;
		u->recv_time = u->retry.start;

	} else {
		state = fr_retry_next(&u->retry, now);
		if (state == FR_RETRY_MRD) {
			DEBUG("Reached maximum_retransmit_duration for status check, marking connection as dead - %s", h->name);
			goto fail;
		}

		if (state == FR_RETRY_MRC) {
			DEBUG("Reached maximum_retransmit_count for status check, marking connection as dead - %s", h->name);
		fail:

			/*
			 *	Reset the FD handlers before changing
			 *	the connection state.
			 */
			if (h->trunk_notify != h->status_notify) {
				thread_conn_notify(h->c->tconn, h->c->tconn->conn, h->thread->el, h->trunk_notify, h->thread);
			}
			h->status_checking = false;
			fr_trunk_connection_signal_reconnect(h->c->tconn, FR_CONNECTION_FAILED);
			return;
		}
	}

	/*
	 *	No previous packet, OR can't retransmit the existing
	 *	one.  Oh well.
	 */
	if (!u->packet || !u->can_retransmit) {
		rad_assert(u->rr != NULL);

		/*
		 *	Encode the packet.
		 */
		if (encode(h->inst, h->status_request, u, u->rr->id, true) < 0) {
			DEBUG("Failed encoding status check packet for connection %s", h->name);
			goto fail;
		}

		/*
		 *	Remember the authentication vector, which now has the
		 *	packet signature.
		 */
		(void) radius_track_update(h->tt, u->rr, u->packet + RADIUS_AUTH_VECTOR_OFFSET);

		DEBUG("Sending %s ID %d length %ld over connection %s",
		      fr_packet_codes[u->code], u->rr->id, u->packet_len, h->name);
	} else {
		DEBUG("Retransmitting %s ID %d length %lu for status check over connection %s",
		      fr_packet_codes[u->code], u->rr->id, u->packet_len, h->name);
	}

	/*
	 *	Tell the admin when we expect the response.
	 */
	msec = fr_time_delta_to_msec(u->retry.rt);
	DEBUG("Next status check will be sent in %u.%03us",
	      msec / 1000, msec % 1000);

	rcode = write(h->fd, u->packet, u->packet_len);
	if ((rcode < 0) || ((size_t) rcode < u->packet_len)) {
		DEBUG("Failed writing status check packet for connection %s", h->name);
		goto fail;
	}

	if (fr_event_timer_at(u, el, &u->ev, u->retry.next, status_check_timer, u) < 0) {
		ERROR("Failed inserting retransmit timeout for connection %s", h->name);
		goto fail;
	}
}


/** See if the connection is zombied.
 *
 *	We check for zombie when major events happen:
 *
 *	1) request hits its final timeout
 *	2) request timer hits, and it needs to be retransmitted
 *	3) a DUP packet comes in, and the request needs to be retransmitted
 *	4) we're sending a packet.
 *
 *  There MIGHT not be retries configured, so we MUST check for zombie
 *  when any new packet comes in.  Similarly, there MIGHT not be new
 *  packets, but retries are configured, so we have to check there,
 *  too.
 *
 *  Also, the socket might not be writable for a while.  There MIGHT
 *  be a long time between getting the timer / DUP signal, and the
 *  request finally being written to the socket.  So we need to check
 *  for zombie at BOTH the timeout and the mux / write function.
 */
static void check_for_zombie(fr_event_list_t *el, fr_trunk_connection_t *tconn, fr_time_t now)
{
	udp_handle_t	*h = talloc_get_type_abort(tconn->conn->h, udp_handle_t);
	udp_request_t	*u = h->status_u;

	/*
	 *	We're replicating, and don't care about the health of
	 *	the home server, don't do zombie checks.
	 *
	 *	Or there's already a zombie check started, don't do
	 *	another one.
	 *
	 *	Or if we never sent a packet, we don't know (or care)
	 *	if the home server is up.
	 *
	 *	Or if we had sent packets, and then went idle.
	 *
	 *	Or we had replies, and then went idle.
	 *
	 *	We do checks for both sent && replied, because we
	 *	could have sent packets without getting replies (and
	 *	then mark it zombie), or we could have gotten some
	 *	replies which then stopped coming back (and then mark
	 *	it zombie).
	 */
	if (h->zombie_ev || !h->last_sent || (h->last_sent <= h->last_idle) ||
	    (h->last_reply && (h->last_reply <= h->last_idle))) {
		return;
	}

	if (now == 0) now = fr_time();

	/*
	 *	We've sent a packet since we last went idle, and/or
	 *	we've received replies since we last went idle.
	 *
	 *	If we have a reply, then set the zombie timeout from
	 *	when we received the last reply.
	 *
	 *	If we haven't seen a reply, then set the zombie
	 *	timeout from when we first started sending packets.
	 */
	if (h->last_reply) {
		if ((h->last_reply + h->inst->parent->zombie_period) >= now) {
			return;
		}
	} else {
		if ((h->first_sent + h->inst->parent->zombie_period) >= now) {
			return;
		}
	}

	/*
	 *	No status checks: this connection is dead.
	 *
	 *	We will requeue this packet on another
	 *	connection.
	 */
	if (!h->inst->parent->status_check) {
		uint32_t msec = fr_time_delta_to_msec(h->inst->parent->revive_interval);
		fr_time_t when;

		DEBUG("Connection failed.  Reviving it in %u.%03us",
		      msec / 1000, msec % 1000);
		fr_trunk_connection_signal_inactive(tconn);

		when = now + h->inst->parent->revive_interval;
		if (fr_event_timer_at(h, el, &h->zombie_ev, when, revive_timer, tconn) < 0) {
			fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
			return;
		}

		(void) fr_trunk_connection_requests_requeue(tconn, FR_TRUNK_REQUEST_STATE_ALL, 0, false);
		return;
	}

	/*
	 *	Mark the connection as inactive, but keep sending
	 *	packets on it.
	 */
	WARN("%s - Entering Zombie state - connection %s", h->module_name, h->name);
	h->status_checking = true;

	/*
	 *	Move ALL requests to other connections!
	 */
	fr_trunk_connection_signal_inactive(tconn);
	fr_trunk_connection_requests_requeue(tconn, FR_TRUNK_REQUEST_STATE_ALL, 0, false);

	status_check_timer(el, 0, u);
}

static void udp_request_clear(udp_request_t *u, udp_handle_t *h, fr_time_t now)
{
	if (!now) now = fr_time();

	if (u->rr) (void) radius_track_delete(h->tt, u->rr);
	if (h->tt->num_free == (h->status_u != NULL)) h->last_idle = now;
	u->rr = NULL;
	fr_pair_list_free(&u->extra);
}


/** Handle retries for a REQUEST
 *
 */
static void request_timeout(fr_event_list_t *el, fr_time_t now, void *uctx)
{
	fr_trunk_request_t	*treq = talloc_get_type_abort(uctx, fr_trunk_request_t);
	udp_request_t		*u = talloc_get_type_abort(treq->preq, udp_request_t);
	udp_handle_t		*h = talloc_get_type_abort(treq->tconn->conn->h, udp_handle_t);
	udp_result_t		*r = talloc_get_type_abort(treq->rctx, udp_result_t);
	REQUEST			*request = treq->request;
	fr_retry_state_t	state;

	/*
	 *	This call may nuke u->rr
	 */
	check_for_zombie(el, treq->tconn, now);

	/*
	 *	Rely on someone else to do the retransmissions.
	 */
	if (!u->rr) return;

	state = fr_retry_next(&u->retry, now);
	if (state == FR_RETRY_MRD) {
		RDEBUG("Reached maximum_retransmit_duration, failing request");
		goto fail;
	}

	if (state == FR_RETRY_MRC) {
		RDEBUG("Reached maximum_retransmit_count, failing request");

	fail:
		udp_request_clear(u, h, now);
		r->rcode = RLM_MODULE_FAIL;
		u->c = NULL;
		fr_trunk_request_signal_complete(treq);
		return;
	}

	/*
	 *	@todo - set up "next" timer here, instead of in
	 *	request_mux() ?  That way we can catch the case of
	 *	packets sitting in the queue for extended periods of
	 *	time, and still run the timers.
	 */

	/*
	 *	Queue the request for retransmission.
	 */
	fr_trunk_request_requeue(treq);
}


static int write_packet(fr_event_list_t *el, fr_trunk_request_t *treq, uint8_t const *packet, size_t packet_len)
{
	char const		*action;
	ssize_t			slen;
	udp_request_t		*u = talloc_get_type_abort(treq->preq, udp_request_t);
	udp_handle_t		*h = talloc_get_type_abort(treq->tconn->conn->h, udp_handle_t);
	REQUEST			*request = treq->request;
	rlm_radius_udp_t const	*inst = h->inst;

	/*
	 *	Tell the admin what's going on
	 */
	if (u->retry.count == 1) {
		action = inst->parent->originate ? "Originating" : "Proxying";
		h->last_sent = u->retry.start;
		if (h->first_sent <= h->last_idle) h->first_sent = h->last_sent;

	} else {
		action = "Retransmitting";
	}

	if (!inst->parent->synchronous) {
		uint32_t msec = fr_time_delta_to_msec(u->retry.rt);

		RDEBUG("%s request.  Expecting response within %u.%03us",
		       action, msec / 1000, msec % 1000);

		/*
		 *	Set up a timer for retransmits.
		 */
		if (fr_event_timer_at(u, el, &u->ev, u->retry.next, request_timeout, treq) < 0) {
			RERROR("Failed inserting retransmit timeout for connection");
			return -1;
		}
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
		RDEBUG("%s request.  Relying on NAS to perform more retransmissions", action);
	}

	slen = write(h->fd, packet, packet_len);
	if (slen < 0) {
		// @todo - handle EWOULDBLOCK
		REDEBUG("Failed writing packet to %s - %s", h->name, fr_syserror(errno));
		return -1;
	}
	rad_assert((size_t) slen == packet_len);	/* Should never get partial writes with UDP */

	return 0;
}

static void request_mux(fr_event_list_t *el,
			fr_trunk_connection_t *tconn, fr_connection_t *conn, UNUSED void *uctx)
{
	udp_handle_t		*h = talloc_get_type_abort(conn->h, udp_handle_t);
	udp_connection_t	*c = h->c;
	fr_trunk_request_t	*treq;

	check_for_zombie(el, tconn, 0);

	while ((treq = fr_trunk_connection_pop_request(tconn)) != NULL) {
		udp_request_t		*u = talloc_get_type_abort(treq->preq, udp_request_t);
		REQUEST			*request = treq->request;

		/*
		 *	No previous packet, OR can't retransmit the
		 *	existing one.  Oh well.
		 *
		 *	Note that if we can't retransmit the previous
		 *	packet, then u->rr MUST already have been
		 *	deleted in the request_cancel() function, when
		 *	the REQUEUE signal was recevied.
		 */
		if (!u->packet || !u->can_retransmit) {
			rad_assert(!u->rr);

			u->rr = radius_track_entry_alloc(h->tt, request, u->code, treq);
			if (!u->rr) {
			fail:
				u->c = NULL;
				fr_trunk_request_signal_fail(treq);
				continue;
			}

			RDEBUG("Sending %s ID %d length %ld over connection %s",
			       fr_packet_codes[u->code], u->rr->id, u->packet_len, h->name);

			if (encode(h->inst, request, u, u->rr->id, false) < 0) {
			fail_after_alloc:
				udp_request_clear(u, h, 0);
				if (u->ev) (void) fr_event_timer_delete(&u->ev);
				goto fail;
			}
			RHEXDUMP3(u->packet, u->packet_len, "Encoded packet");

			/*
			 *	Remember the authentication vector, which now has the
			 *	packet signature.
			 */
			(void) radius_track_update(h->tt, u->rr, u->packet + RADIUS_AUTH_VECTOR_OFFSET);
		} else {
			RDEBUG("Retransmitting %s ID %d length %ld over connection %s",
			       fr_packet_codes[u->code], u->rr->id, u->packet_len, h->name);
		}

		log_request_pair_list(L_DBG_LVL_2, request, request->packet->vps, NULL);
		if (u->extra) log_request_pair_list(L_DBG_LVL_2, request, u->extra, NULL);

		if (write_packet(el, treq, u->packet, u->packet_len) < 0) goto fail_after_alloc;
		fr_trunk_request_signal_sent(treq);

		/*
		 *	Tell the trunk API that this request is now in
		 *	the "sent" state.  And we don't want to see
		 *	this request again.
		 */
		u->c = c;

		// @todo - if there are no free IDs, call fr_trunk_connection_requests_requeue()
	}
}

static void request_mux_replicate(fr_event_list_t *el,
				  fr_trunk_connection_t *tconn, fr_connection_t *conn, UNUSED void *uctx)
{
	udp_handle_t		*h = talloc_get_type_abort(conn->h, udp_handle_t);
	fr_trunk_request_t	*treq;

	while ((treq = fr_trunk_connection_pop_request(tconn)) != NULL) {
		udp_result_t		*r = talloc_get_type_abort(treq->rctx, udp_result_t);
		udp_request_t		*u = talloc_get_type_abort(treq->preq, udp_request_t);
		REQUEST			*request = treq->request;
		uint8_t			id = h->last_id;

		RDEBUG("Sending %s ID %d length %ld over connection %s",
		       fr_packet_codes[u->code], id, u->packet_len, h->name);

		if (!u->packet) {
			if (encode(h->inst, request, u, id, false) < 0) {
				udp_request_clear(u, h, 0);
				fr_trunk_request_signal_fail(treq);
				return;
			}
			RHEXDUMP3(u->packet, u->packet_len, "Encoded packet");
		}

		/*
		 *	Assume we'll be able to write later, and just break
		 *	out of the loop.
		 */
		if (write_packet(el, treq, u->packet, u->packet_len) < 0) return;

		r->rcode = RLM_MODULE_OK;

		/*
		 *	Signal the request as immediately complete
		 */
		fr_trunk_request_signal_complete(treq);

		h->last_id++;	/* Wraps to zero - Defined behaviour*/
	}
}

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

/** Turn a reply code into a module rcode;
 *
 */
static rlm_rcode_t radius_code_to_rcode[FR_RADIUS_MAX_PACKET_CODE] = {
	[FR_CODE_ACCESS_ACCEPT]		= RLM_MODULE_OK,
	[FR_CODE_ACCESS_CHALLENGE]	= RLM_MODULE_UPDATED,
	[FR_CODE_ACCESS_REJECT]		= RLM_MODULE_REJECT,

	[FR_CODE_ACCOUNTING_RESPONSE]	= RLM_MODULE_OK,

	[FR_CODE_COA_ACK]		= RLM_MODULE_OK,
	[FR_CODE_COA_NAK]		= RLM_MODULE_REJECT,

	[FR_CODE_DISCONNECT_ACK]	= RLM_MODULE_OK,
	[FR_CODE_DISCONNECT_NAK]	= RLM_MODULE_REJECT,

	[FR_CODE_PROTOCOL_ERROR]	= RLM_MODULE_HANDLED,
};

/** Deal with Protocol-Error replies, and possible negotiation
 *
 */
static void protocol_error_reply(udp_request_t *u, udp_result_t *r, udp_handle_t *h)
{
	bool	  	error_601 = false;
	uint32_t  	response_length = 0;
	uint8_t const	*attr, *end;

	end = h->buffer + ((h->buffer[2] << 8) | h->buffer[3]);

	for (attr = h->buffer + RADIUS_HEADER_LENGTH;
	     attr < end;
	     attr += attr[1]) {
		/*
		 *	Error-Cause = Response-Too-Big
		 */
		if ((attr[0] == attr_error_cause->attr) && (attr[1] == 6)) {
			uint32_t error;

			memcpy(&error, attr + 2, 4);
			error = ntohl(error);
			if (error == 601) error_601 = true;
			continue;
		}

		/*
		 *	The other end wants us to increase our Response-Length
		 */
		if ((attr[0] == attr_response_length->attr) && (attr[1] == 6)) {
			memcpy(&response_length, attr + 2, 4);
			continue;
		}

		/*
		 *	Protocol-Error packets MUST contain an
		 *	Original-Packet-Code attribute.
		 *
		 *	The attribute containing the
		 *	Original-Packet-Code is an extended
		 *	attribute.
		 */
		if (attr[0] != attr_extended_attribute_1->attr) continue;

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
				if (r) r->rcode = RLM_MODULE_FAIL;
				return;
			}

			/*
			 *	The value has to match.  We don't
			 *	currently multiplex different codes
			 *	with the same IDs on connections.  So
			 *	this check is just for RFC compliance,
			 *	and for sanity.
			 */
			if (attr[6] != u->code) {
				if (r) r->rcode = RLM_MODULE_FAIL;
				return;
			}
	}

	/*
	 *	Error-Cause = Response-Too-Big
	 *
	 *	The other end says it needs more room to send it's response
	 *
	 *	Limit it to reasonable values.
	 */
	if (error_601 && response_length && (response_length > h->buflen)) {
		if (response_length < 4096) response_length = 4096;
		if (response_length > 65535) response_length = 65535;

		DEBUG("%s - Increasing buffer size to %u for connection %s", h->module_name, response_length, h->name);

		/*
		 *	Make sure to copy the packet over!
		 */
		attr = h->buffer;
		h->buflen = response_length;
		MEM(h->buffer = talloc_array(h, uint8_t, h->buflen));

		memcpy(h->buffer, attr, (attr[2] << 8) | attr[3]);
	}

	/*
	 *	fail - something went wrong internally, or with the connection.
	 *	invalid - wrong response to packet
	 *	handled - best remaining alternative :(
	 *
	 *	i.e. if the response is NOT accept, reject, whatever,
	 *	then we shouldn't allow the caller to do any more
	 *	processing of this packet.  There was a protocol
	 *	error, and the response is valid, but not useful for
	 *	anything.
	 */
	if (r) r->rcode = RLM_MODULE_HANDLED;
}


/** Deal with replies replies to status checks and possible negotiation
 *
 */
static void status_check_reply(udp_request_t *u, udp_handle_t *h)
{
	/*
	 *	@todo - make this configurable
	 */
	if (u->num_replies < 3) {
		DEBUG("Received %d / 3 replies for status check, on connection - %s", u->num_replies, h->name);
		return;
	}

	if (u->ev) (void) fr_event_timer_delete(&u->ev);

	DEBUG("Received enough replies to status check, marking connection as active - %s", h->name);

	/*
	 *	Reset the FD handlers before changing
	 *	the connection state.
	 */
	if (h->trunk_notify != h->status_notify) {
		thread_conn_notify(h->c->tconn, h->c->tconn->conn, h->thread->el, h->trunk_notify, h->thread);
		h->status_checking = false;
	}

	fr_trunk_connection_signal_active(h->c->tconn);

	/*
	 *	@todo - do other negotiation and signaling.
	 */
	if (h->buffer[0] == FR_CODE_PROTOCOL_ERROR) {
		protocol_error_reply(u, NULL, h);
	}
}


static fr_trunk_request_t *read_packet(udp_handle_t *h, udp_connection_t *c)
{
	rlm_radius_udp_t const	*inst = h->thread->inst;
	fr_trunk_request_t	*treq;
	udp_request_t		*u;
	udp_result_t		*r;
	REQUEST			*request;
	ssize_t			data_len;
	size_t			packet_len;
	radius_track_entry_t	*rr;
	decode_fail_t		reason;
	int			code;
	VALUE_PAIR		*reply, *vp;
	uint8_t			original[RADIUS_HEADER_LENGTH];

	/*
	 *	Drain the socket of all packets.  If we're busy, this
	 *	saves a round through the event loop.  If we're not
	 *	busy, a few extra system calls don't matter.
	 */
drain:
	data_len = read(h->fd, h->buffer, h->buflen);
	if (data_len == 0) {
		return NULL;
	}

	if (data_len < 0) {
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) return NULL;

		DEBUG("Failed reading from socket: %s", fr_syserror(errno));
		fr_trunk_connection_signal_reconnect(c->tconn, FR_CONNECTION_FAILED);
		return NULL;
	}

	/*
	 *	We don't care about replies, so just read them and
	 *	ignore them.
	 */
	if (inst->replicate) goto drain;

	packet_len = data_len;
	if (!fr_radius_ok(h->buffer, &packet_len, inst->parent->max_attributes, false, &reason)) {
		WARN("%s - Ignoring malformed packet", h->module_name);
		return NULL;
	}

	if (DEBUG_ENABLED3) {
		DEBUG3("%s - Read packet", h->module_name);
		fr_log_hex(&default_log, L_DBG, __FILE__, __LINE__, h->buffer, packet_len, NULL);
	}

	/*
	 *	Note that we don't care about packet codes.  All
	 *	packet codes share the same ID space.
	 */
	rr = radius_track_find(h->tt, h->buffer[1], NULL);
	if (!rr) {
		WARN("%s - Ignoring reply which arrived too late", h->module_name);
		return NULL;
	}

	if (rr->rctx != h->status_u) {
		treq = talloc_get_type_abort(rr->rctx, fr_trunk_request_t);
		request = treq->request;
		rad_assert(request != NULL);
		u = talloc_get_type_abort(treq->preq, udp_request_t);
		r = talloc_get_type_abort(treq->rctx, udp_result_t);

	} else {
		treq = NULL;
		request = NULL;
		u = talloc_get_type_abort(rr->rctx, udp_request_t);
		r = NULL;
		rad_assert(u == h->status_u);
	}

	original[0] = rr->code;
	original[1] = 0;	/* not looked at by fr_radius_verify() */
	original[2] = 0;
	original[3] = RADIUS_HEADER_LENGTH;	/* for debugging */
	memcpy(original + RADIUS_AUTH_VECTOR_OFFSET, rr->vector, sizeof(rr->vector));

	if (fr_radius_verify(h->buffer, original,
			     (uint8_t const *) inst->secret, talloc_array_length(inst->secret) - 1) < 0) {
		if (request) RPWDEBUG("Ignoring response with invalid signature");
		return NULL;
	}

	// @todo - if we sent multiple requests, wait for multiple replies?
	u->num_replies++;

	/*
	 *	Status-Server can have any reply code, we don't care
	 *	what it is.  So long as it's signed properly, we
	 *	accept it.  This flexibility is because we don't
	 *	expose Status-Server to the admins.  It's only used by
	 *	this module for internal signalling.
	 */
	if (u == h->status_u) {
		status_check_reply(u, h);
		return NULL;
	}

	h->last_reply = fr_time();

	udp_request_clear(u, h, h->last_reply);

	if (u->ev) (void) fr_event_timer_delete(&u->ev);

	if (u->retry.start > h->mrs_time) h->mrs_time = u->retry.start;

	code = h->buffer[0];
	if (!code || (code >= FR_RADIUS_MAX_PACKET_CODE)) {
		REDEBUG("Unknown reply code %d", code);
		r->rcode= RLM_MODULE_INVALID;
		return treq;
	}

	/*
	 *	Handle any state changes, etc. needed by receiving a
	 *	Protocol-Error reply packet.
	 *
	 *	Protocol-Error is permitted as a reply to any
	 *	packet.
	 */
	if (code == FR_CODE_PROTOCOL_ERROR) {
		protocol_error_reply(u, r, h);
		goto decode;
	}

	if (!allowed_replies[code]) {
		REDEBUG("%s packet received invalid reply code %s", fr_packet_codes[u->code], fr_packet_codes[code]);
		r->rcode = RLM_MODULE_INVALID;
		return treq;
	}

	if (allowed_replies[code] != (FR_CODE) u->code) {
		REDEBUG("%s packet received invalid reply code %s", fr_packet_codes[u->code], fr_packet_codes[code]);
		r->rcode = RLM_MODULE_INVALID;
		return treq;
	}

	/*
	 *	Mark up the request as being an Access-Challenge, if
	 *	required.
	 *
	 *	We don't do this for other packet types, because the
	 *	ok/fail nature of the module return code will
	 *	automatically result in it the parent request
	 *	returning an ok/fail packet code.
	 */
	if ((u->code == FR_CODE_ACCESS_REQUEST) && (code == FR_CODE_ACCESS_CHALLENGE)) {
		vp = fr_pair_find_by_da(request->reply->vps, attr_packet_type, TAG_ANY);
		if (!vp) {
			MEM(vp = fr_pair_afrom_da(request->reply, attr_packet_type));
			vp->vp_uint32 = FR_CODE_ACCESS_CHALLENGE;
			fr_pair_add(&request->reply->vps, vp);
		}
	}

	/*
	 *	Set the module return code based on the reply packet.
	 */
	r->rcode = radius_code_to_rcode[h->buffer[0]];

decode:
	reply = NULL;

	/*
	 *	Decode the attributes, in the context of the reply.
	 *	This only fails if the packet is strangely malformed,
	 *	or if we run out of memory.
	 */
	if (fr_radius_decode(request->reply, h->buffer, packet_len, original,
			     inst->secret, talloc_array_length(inst->secret) - 1, &reply) < 0) {
		REDEBUG("Failed decoding attributes for packet");
		fr_pair_list_free(&reply);
		r->rcode = RLM_MODULE_INVALID;
		return treq;
	}

	RDEBUG("Received %s ID %d length %ld reply packet on connection %s",
	       fr_packet_codes[code], code, packet_len, h->name);
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
	 *	Do NOT set request->reply->code.  The caller
	 *	proto_radius_foo will do that for us.
	 */
	fr_pair_add(&request->reply->vps, reply);

	return treq;
}

static void request_demux(UNUSED fr_trunk_connection_t *tconn, fr_connection_t *conn, UNUSED void *uctx)
{
	udp_handle_t		*h = talloc_get_type_abort(conn->h, udp_handle_t);
	udp_connection_t	*c = h->c;
	fr_trunk_request_t	*treq;

	DEBUG3("%s - Reading data for connection %s", h->module_name, h->name);

redo:
	treq = read_packet(h, c);
	if (!treq) return;

	// decode the packet, and do funky stuff with it.
	treq->request->reply->code = h->buffer[0];
	fr_trunk_request_signal_complete(treq);

	goto redo;
}

static void request_complete(REQUEST *request, UNUSED void *preq, UNUSED void *rctx, UNUSED void *uctx)
{
	unlang_interpret_resumable(request);
}

static void request_cancel(fr_connection_t *conn, void *preq_to_reset,
			   fr_trunk_cancel_reason_t reason, UNUSED void *uctx)
{
	udp_request_t	*u = talloc_get_type_abort(preq_to_reset, udp_request_t);
	udp_handle_t	*h = talloc_get_type_abort(conn->h, udp_handle_t);


	switch (reason) {
	/*
	 *	The request is being terminated, and will
	 *	soon be freed.  Let the request_fail function
	 *	handle any cleanup required.
	 */
	case FR_TRUNK_CANCEL_REASON_NONE:
	case FR_TRUNK_CANCEL_REASON_SIGNAL:
		break;

		/*
		 *	Request has been requeued on the same
		 *	connection due to timeout or DUP signal.  We
		 *	keep the same timers, packets etc.
		 */
	case FR_TRUNK_CANCEL_REASON_REQUEUE:
		if (!u->can_retransmit) {
			(void) radius_track_delete(h->tt, u->rr);
			u->rr = NULL;
		}
		break;

		/*
		 *	Request is moving to a different connection,
		 *	for internal trunk reasons.  i.e. the old
		 *	connection is closing.
		 */
	case FR_TRUNK_CANCEL_REASON_MOVE:
		udp_request_clear(u, h, 0);

		if (u->ev) (void) fr_event_timer_delete(&u->ev);

		if (u->packet) TALLOC_FREE(u->packet);

		u->c = NULL;
		u->num_replies = 0;
		break;
	}
}

static rlm_rcode_t request_resume(UNUSED void *instance, UNUSED void *thread, UNUSED REQUEST *request, void *ctx)
{
	udp_result_t	*r = talloc_get_type_abort(ctx, udp_result_t);

	return r->rcode;
}


/** Free a udp_request_t
 */
static int udp_request_free(udp_request_t *u)
{
	if (u->ev) (void) fr_event_timer_delete(&u->ev);

	rad_assert(u->rr == NULL);

	return 0;
}

static rlm_rcode_t mod_enqueue(void **rctx_out, void *instance, void *thread, REQUEST *request)
{
	rlm_radius_udp_t		*inst = talloc_get_type_abort(instance, rlm_radius_udp_t);
	udp_thread_t			*t = talloc_get_type_abort(thread, udp_thread_t);
	udp_result_t			*r;
	udp_request_t			*u;
	fr_trunk_request_t		*treq;

	rad_assert(request->packet->code > 0);
	rad_assert(request->packet->code < FR_RADIUS_MAX_PACKET_CODE);

	/*
	 *	If configured, and we don't have any active
	 *	connections, fail the request.  This lets "parallel"
	 *	sections finish much more quickly than otherwise.
	 */
	if (inst->parent->no_connection_fail &&
	    (fr_trunk_connection_count_by_state(t->trunk, FR_TRUNK_CONN_ACTIVE) == 0)) {
		REDEBUG("Failing request due to 'no_connection_fail = true', and there are no active connections");
		return RLM_MODULE_FAIL;
	}

	if (request->packet->code == FR_CODE_STATUS_SERVER) {
		RWDEBUG("Status-Server is reserved for internal use, and cannot be sent manually.");
		return RLM_MODULE_NOOP;
	}

	MEM(treq = fr_trunk_request_alloc(t->trunk, request));
	MEM(r = talloc_zero(request, udp_result_t));
	MEM(u = talloc_zero(treq, udp_request_t));

	u->rr = NULL;
	u->c = NULL;
	u->code = request->packet->code;
	u->synchronous = inst->parent->synchronous;
	u->priority = request->async->priority;	  /* cached for speed */
	u->recv_time = request->async->recv_time; /* cached for speed */

	r->rcode = RLM_MODULE_FAIL;

	/*
	 *	Make sure that we print out the actual encoded value
	 *	of the Message-Authenticator attribute.  If the caller
	 *	asked for one, delete theirs (which has a bad value),
	 *	and remember to add one manually when we encode the
	 *	packet.  This is the only editing we do on the input
	 *	request.
	 *
	 *	@todo - don't edit the input packet!
	 */
	if (fr_pair_find_by_da(request->packet->vps, attr_message_authenticator, TAG_ANY)) {
		u->require_ma = true;
		pair_delete_request(attr_message_authenticator);
	}

	/*
	 *	@todo - set timers now, instead of when we actually send the packet?
	 */
	if (!inst->replicate) {
		(void) fr_retry_init(&u->retry, fr_time(), &inst->parent->retry[u->code]);
		rad_assert(u->retry.rt > 0);
		rad_assert(u->retry.next > 0);
	}

	if (fr_trunk_request_enqueue(&treq, t->trunk, request, u, r) < 0) {
		talloc_free(treq);
		talloc_free(r);
		return RLM_MODULE_FAIL;
	}

	r->treq = treq;	/* Remember for signalling purposes */
	talloc_set_destructor(u, udp_request_free);

	*rctx_out = r;

	return RLM_MODULE_YIELD;
}


static void mod_signal(UNUSED void *instance, void *thread, UNUSED REQUEST *request,
		       void *rctx, fr_state_signal_t action)
{
	udp_thread_t		*t = talloc_get_type_abort(thread, udp_thread_t);
	udp_result_t		*r = talloc_get_type_abort(rctx, udp_result_t);

	switch (action) {
	/*
	 *	The request is being cancelled, tell the
	 *	trunk so it can clean up the treq.
	 */
	case FR_SIGNAL_CANCEL:
		fr_trunk_request_signal_cancel(r->treq);
		return;

	/*
	 *	Requeue the request on the same connection
	 *      causing a "retransmission" if the request
	 *	has already been sent out.
	 */
	case FR_SIGNAL_DUP:
		fr_trunk_request_requeue(r->treq);
		check_for_zombie(t->el, r->treq->tconn, 0);
		return;

	default:
		return;
	}
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
 * @param[in] instance	Ctx data for this module
 * @param[in] conf	our configuration section parsed to give us instance.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_radius_t		*parent = talloc_get_type_abort(dl_module_parent_data_by_child_data(instance),
								rlm_radius_t);
	rlm_radius_udp_t	*inst = talloc_get_type_abort(instance, rlm_radius_udp_t);

	if (!parent) {
		ERROR("IO module cannot be instantiated directly");
		return -1;
	}

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

	if (!inst->replicate) {
		if (inst->recv_buff_is_set) {
			FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, inst->max_packet_size);
			FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, (1 << 30));
		}
	} else {
		/*
		 *	Replicating: Set the receive buffer to zero.
		 */
		inst->recv_buff_is_set = true;
		inst->recv_buff = 0;
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
static int mod_thread_instantiate(UNUSED CONF_SECTION const *cs, void *instance, fr_event_list_t *el, void *tctx)
{
	rlm_radius_udp_t		*inst = talloc_get_type_abort(instance, rlm_radius_udp_t);
	udp_thread_t			*thread = talloc_get_type_abort(tctx, udp_thread_t);

	static fr_trunk_io_funcs_t	io_funcs = {
						.connection_alloc = thread_conn_alloc,
						.connection_notify = thread_conn_notify,
						.request_prioritise = request_prioritise,
						.request_mux = request_mux,
						.request_demux = request_demux,
						.request_complete = request_complete,
						.request_cancel = request_cancel,
					};

	static fr_trunk_io_funcs_t	io_funcs_replicate = {
						.connection_alloc = thread_conn_alloc,
						.connection_notify = thread_conn_notify_replicate,
						.request_prioritise = request_prioritise,
						.request_mux = request_mux_replicate,
						.request_demux = NULL,
						.request_complete = request_complete,
						.request_cancel = NULL,
					};

	inst->trunk_conf = &inst->parent->trunk_conf;

	inst->trunk_conf->req_pool_headers = 2;	/* One for the request, one for the buffer */
	inst->trunk_conf->req_pool_size = sizeof(udp_request_t) + inst->max_packet_size;

	thread->el = el;
	thread->inst = inst;
	thread->trunk = fr_trunk_alloc(thread, el, inst->replicate ? &io_funcs_replicate : &io_funcs,
				       inst->trunk_conf, inst->parent->name, thread, false);
	if (!thread->trunk) return -1;

	return 0;
}


extern rlm_radius_io_t rlm_radius_udp;
rlm_radius_io_t rlm_radius_udp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "radius_udp",
	.inst_size		= sizeof(rlm_radius_udp_t),

	.thread_inst_size	= sizeof(udp_thread_t),
	.thread_inst_type	= "udp_thread_t",

	.config			= module_config,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,
	.thread_instantiate 	= mod_thread_instantiate,

	.enqueue		= mod_enqueue,
	.signal			= mod_signal,
	.resume			= request_resume,
};
