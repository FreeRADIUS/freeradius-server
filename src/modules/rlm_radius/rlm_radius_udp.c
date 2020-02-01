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
	udp_thread_t		*thread;
	fr_event_list_t		*el;			//!< Event list.
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

	uint32_t		max_packet_size;	//!< Our max packet size. may be different from the parent.

	fr_ipaddr_t		dst_ipaddr;		//!< IP of the home server. stupid 'const' issues.
	uint16_t		dst_port;		//!< Port of the home server.
	fr_ipaddr_t		src_ipaddr;		//!< Our source IP.
	uint16_t	       	src_port;		//!< Our source port.

	uint8_t			*buffer;		//!< Receive buffer.
	size_t			buflen;			//!< Receive buffer length.

	rlm_radius_id_t		*id;			//!< RADIUS ID tracking structure.

	fr_time_t		mrs_time;		//!< Most recent sent time which had a reply.
	fr_time_t		last_reply;		//!< When we last received a reply.

	fr_event_timer_t const	*zombie_ev;		//!< Zombie timeout.
	udp_request_t		*status_u;		//!< for sending Status-Server packets
} udp_handle_t;

/** Connect REQUEST to local tracking structure
 *
 */
struct udp_request_s {
	fr_trunk_request_t	*treq;

	REQUEST			*request;		//!< our request
	uint32_t		priority;		//!< copied from request->async->priority
	fr_time_t		recv_time;		//!< copied from request->async->recv_time

	int			num_replies;		//!< number of reply packets, sent is in retry.count

	rlm_rcode_t		rcode;			//!< from the transport

	bool			synchronous;		//!< cached from inst->parent->synchronous
	bool			require_ma;		//!< saved from the original packet.

	VALUE_PAIR		*extra;			//!< VPs for debugging, like Proxy-State.

	int			code;			//!< Packet code.

	uint8_t			*packet;		//!< Packet we write to the network.
	size_t			packet_len;		//!< Length of the packet.

	udp_connection_t       	*c;			//!< The outbound connection
	rlm_radius_request_t	*rr;			//!< ID tracking, resend count, etc.
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
	udp_connection_t	*c = talloc_get_type_abort(uctx, udp_connection_t);
	udp_handle_t		*h;
	rlm_radius_udp_t const	*inst = c->thread->inst;

	h = talloc_zero(conn, udp_handle_t);
	if (!h) return FR_CONNECTION_STATE_FAILED;

	h->c = c;
	h->module_name = inst->parent->name;
	h->inst = inst;
	h->thread = c->thread;
	h->dst_ipaddr = inst->dst_ipaddr;
	h->dst_port = inst->dst_port;
	h->src_ipaddr = inst->src_ipaddr;
	h->src_port = 0;
	h->max_packet_size = inst->max_packet_size;

	MEM(h->buffer = talloc_array(h, uint8_t, h->max_packet_size));
	h->buflen = h->max_packet_size;

	MEM(h->id = rr_track_create(h));

	/*
	 *	Open the outgoing socket.
	 */
	fd = fr_socket_client_udp(&h->src_ipaddr, &h->src_port, &h->dst_ipaddr, h->dst_port, true);
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
			      fr_box_ipaddr(h->dst_ipaddr), h->dst_port);

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
	 *	one to be open.  And, start Status-Server messages on that connection.
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
	request = request_local_alloc(u);
	request->async = talloc_zero(request, fr_async_t);
	talloc_const_free(request->name);
	request->name = talloc_strdup(request, h->module_name);

	request->el = el;
	request->packet = fr_radius_alloc(request, false);
	request->reply = fr_radius_alloc(request, false);

	// @todo - set up different logging?

	/*
	 *	Create the packet contents.
	 */
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
	u->request = request;
	u->code = inst->parent->status_check;
	request->packet->code = u->code;
	u->c = h->c;		/* h can mutate during the lifetime of c */

	/*
	 *	Reserve a permanent ID for the packet.  This
	 *	is because we need to be able to send an ID on
	 *	demand.  If the proxied packets use all of the
	 *	IDs, then we can't send a Status-Server check.
	 */
	u->rr = rr_track_alloc(h->id, request, u->code, u);
	if (!u->rr) {
		ERROR("%s - Failed allocating status_check ID for connection %s",
		      h->module_name, h->name);
		talloc_free(u);
		return;
	}

	DEBUG2("%s - Allocated %s ID %u for status checks on connection %s",
	       h->module_name, fr_packet_codes[u->code], u->rr->id, h->name);
	h->status_u = u;
}

/** Process notification that fd is open
 *
 */
static fr_connection_state_t conn_open(fr_event_list_t *el, void *handle, UNUSED void *uctx)
{
	udp_handle_t		*h = talloc_get_type_abort(handle, udp_handle_t);

	talloc_const_free(h->name);
	h->name = fr_asprintf(h, "proto udp local %pV port %u remote %pV port %u",
			      fr_box_ipaddr(h->src_ipaddr), h->src_port,
			      fr_box_ipaddr(h->dst_ipaddr), h->dst_port);

	DEBUG("%s - Connection open - %s", h->module_name, h->name);

	/*
	 *	Connection is "active" now.  i.e. we prefer the newly
	 *	opened connection for sending packets.
	 *
	 *	@todo - connection negotiation via Status-Server
	 */
	h->last_reply = h->mrs_time = fr_time();

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
static fr_connection_state_t conn_failed(UNUSED void *handle, fr_connection_state_t state, UNUSED void *uctx)
{
//	udp_handle_t	*h = talloc_get_type_abort(handle, udp_handle_t);

	/*
	 *	If the connection was connected when it failed,
	 *	we need to handle any outstanding packets and
	 *	timer events before reconnecting.
	 */
	if (state == FR_CONNECTION_STATE_CONNECTED) {
		/*
		 *	Reset the Status-Server checks.
		 */

		/*
		 *	Delete idle and zombie timers associated with the connection.
		 */
	}

	return FR_CONNECTION_STATE_INIT;
}

static fr_connection_t *thread_conn_alloc(fr_trunk_connection_t *tconn, fr_event_list_t *el,
					  fr_connection_conf_t const *conf,
					  char const *log_prefix, void *uctx)
{
	udp_connection_t	*c;
	udp_thread_t	*thread = talloc_get_type_abort(uctx, udp_thread_t);

	c = talloc_zero(tconn, udp_connection_t);
	if (!c) return NULL;

	c->el = el;
	c->thread = thread;
	c->tconn = tconn;

	c->conn = fr_connection_alloc(c, el,
				      &(fr_connection_funcs_t){
					.init = conn_init,
					.open = conn_open,
					.close = conn_close,
					.failed = conn_failed
				      },
				      conf,
				      log_prefix, c);
	if (!c->conn) {
		talloc_free(c);
		PERROR("Failed allocating state handler for new connection");
		return NULL;
	}

	return c->conn;
}

static void conn_readable(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	udp_connection_t	*c = talloc_get_type_abort(uctx, udp_connection_t);

	fr_trunk_connection_signal_readable(c->tconn);
}

static void conn_writable(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	udp_connection_t	*c = talloc_get_type_abort(uctx, udp_connection_t);

	fr_trunk_connection_signal_writable(c->tconn);
}

/** Connection errored
 *
 */
static void conn_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, int fd_errno, void *uctx)
{
	udp_connection_t	*c = talloc_get_type_abort(uctx, udp_connection_t);

	/*
	 *	@todo - no access to udp_handle_t handle, so no way to print out the actual
	 *	connection name.  <sigh>
	 */
	ERROR("%s - Connection failed - %s", c->thread->inst->parent->name, fr_syserror(fd_errno));
}

static void thread_conn_notify(fr_trunk_connection_t *tconn, fr_connection_t *conn,
			       fr_event_list_t *el,
			       fr_trunk_connection_event_t notify_on, UNUSED void *uctx)
{
	udp_handle_t		*h = talloc_get_type_abort(fr_connection_get_handle(conn), udp_handle_t);
	fr_event_fd_cb_t	read_fn = NULL;
	fr_event_fd_cb_t	write_fn = NULL;

	switch (notify_on) {
	case FR_TRUNK_CONN_EVENT_NONE:
		fr_event_fd_delete(el, h->fd, FR_EVENT_FILTER_IO);
		return;

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
			       h->c) < 0) {
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

static int encode(REQUEST *request, udp_request_t *u, udp_handle_t *h)
{
	rlm_radius_udp_t const	*inst = h->inst;
	ssize_t			packet_len;
	uint8_t			*msg = NULL;
	int			message_authenticator = u->require_ma * 18;
	int			proxy_state = 6;
	char const		*module_name;
	bool			can_retransmit = true;

	rad_assert(inst->parent->allowed[u->code]);

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

		message_authenticator = 18;

		base = fr_rand();
		for (i = 0; i < RADIUS_AUTH_VECTOR_LENGTH; i += sizeof(uint32_t)) {
			hash = fr_rand() ^ base;
			memcpy(h->buffer + 4 + i, &hash, sizeof(hash));
		}
	}

	/*
	 *	If we're sending a status check packet, update any
	 *	necessary timestamps.  Also, don't add Proxy-State, as
	 *	we're originating the packet.
	 */
	if (u == h->status_u) {
		VALUE_PAIR *vp;

		proxy_state = 0;
		vp = fr_pair_find_by_da(request->packet->vps, attr_event_timestamp, TAG_ANY);
		if (vp) {
			vp->vp_uint32 = time(NULL);
			can_retransmit = false;
		}
	}

	/*
	 *	We should have at mininum 64-byte packets, so don't
	 *	bother doing run-time checks here.
	 */
	rad_assert(h->buflen >= (size_t) (20 + proxy_state + message_authenticator));

	/*
	 *	Encode it, leaving room for Proxy-State and
	 *	Message-Authenticator if necessary.
	 */
	packet_len = fr_radius_encode(h->buffer, h->buflen - proxy_state - message_authenticator, NULL,
				      inst->secret, talloc_array_length(inst->secret) - 1, u->code, u->rr->id,
				      request->packet->vps);
	if (packet_len <= 0) return -1;

	/*
	 *	This hack cleans up the debug output a bit.
	 */
	module_name = request->module;
	request->module = NULL;

	/*
	 *	Might have been sent and then given up on... free the
	 *	raw data so we can re-encode it.
	 */
	if (u->packet) {
		TALLOC_FREE(u->packet);
		fr_pair_list_free(&u->extra);
	}

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
		uint8_t		*attr = h->buffer + packet_len;
		VALUE_PAIR	*vp;
		vp_cursor_t	cursor;
		int		count;

		rad_assert((size_t) (packet_len + proxy_state) <= h->buflen);

		/*
		 *	Count how many Proxy-State attributes have
		 *	*our* magic number.
		 */
		if (fr_debug_lvl) {
			count = 0;
			(void) fr_pair_cursor_init(&cursor, &request->packet->vps);
			while ((vp = fr_pair_cursor_next_by_da(&cursor, attr_proxy_state, TAG_ANY)) != NULL) {
				if ((vp->vp_length == 4) && (memcmp(vp->vp_octets, &inst->parent->proxy_state, 4) == 0)) {
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
		memcpy(attr + 2, &inst->parent->proxy_state, 4);

		MEM(vp = fr_pair_afrom_da(u, attr_proxy_state));
		fr_pair_value_memcpy(vp, attr + 2, 4, true);
		fr_pair_add(&u->extra, vp);
		packet_len += 6;
	}

	/*
	 *	Add Message-Authenticator manually.
	 *
	 *	Note that the length check will always pass, due to
	 *	the buflen manipulation done above.
	 */
	if (message_authenticator) {
		rad_assert((size_t) (packet_len + message_authenticator) <= h->buflen);

		msg = h->buffer + packet_len;

		msg[0] = (uint8_t) attr_message_authenticator->attr;
		msg[1] = 18;
		memset(msg + 2, 0, 16);

		packet_len += 18;
	}

	/*
	 *	Update the packet header based on the new attributes.
	 */
	h->buffer[2] = (packet_len >> 8) & 0xff;
	h->buffer[3] = packet_len & 0xff;

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
		end = h->buffer + packet_len;

		for (attr = h->buffer + 20;
		     attr < end;
		     attr += attr[1]) {
			if (attr[0] != attr_acct_delay_time->attr) continue;
			if (attr[1] != 6) continue;

			now = fr_time();

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

			can_retransmit = false;
			break;
		}
	}

	/*
	 *	Now that we're done mangling the packet, sign it.
	 */
	if (fr_radius_sign(h->buffer, NULL, (uint8_t const *) inst->secret,
			   talloc_array_length(inst->secret) - 1) < 0) {
		request->module = module_name;
		RERROR("Failed signing packet");
		return -1;
	}

	/*
	 *	Remember the authentication vector, which now has the
	 *	packet signature.
	 */
	(void) rr_track_update(h->id, u->rr, h->buffer + 4);

	RDEBUG("Sending %s ID %d length %ld over connection %s",
	       fr_packet_codes[u->code], u->rr->id, packet_len, h->name);
	log_request_pair_list(L_DBG_LVL_2, request, request->packet->vps, NULL);
	if (u->extra) log_request_pair_list(L_DBG_LVL_2, request, u->extra, NULL);

	RHEXDUMP3(h->buffer, packet_len, "Encoded packet");

	request->module = module_name;

	/*
	 *	Save the packet if we can retransmit it.
	 */
	if (can_retransmit) {
		MEM(u->packet = talloc_memdup(u, h->buffer, packet_len));
		u->packet_len = packet_len;
	}

	return 0;
}


static void request_timer(UNUSED fr_event_list_t *el, fr_time_t now, void *uctx)
{
	udp_request_t		*u = talloc_get_type_abort(uctx, udp_request_t);
	udp_handle_t		*h = talloc_get_type_abort(fr_connection_get_handle(u->c->conn), udp_handle_t);
	REQUEST			*request = u->request;
	fr_retry_state_t	state;

	state = fr_retry_next(&u->retry, now);
	if (state == FR_RETRY_MRD) {
		RDEBUG("Reached maximum_retransmit_duration, failing request");
		goto fail;
	}

	if (state == FR_RETRY_MRC) {
		RDEBUG("Reached maximum_retransmit_count, failing request");

	fail:
		(void) rr_track_delete(h->id, u->rr);
		u->rr = NULL;
		u->rcode = RLM_MODULE_FAIL;
		u->c = NULL;
		u->treq = NULL;
		fr_trunk_request_signal_complete(u->treq);
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
	fr_trunk_request_requeue(u->treq);
}


static int write_packet(udp_request_t *u, udp_handle_t *h, uint8_t const *packet, size_t packet_len)
{
	char const *action;
	ssize_t rcode;
	REQUEST *request = u->request;
	rlm_radius_udp_t const *inst = h->inst;

	/*
	 *	Tell the admin what's going on
	 */
	if (u->retry.count == 1) {
		action = inst->parent->originate ? "Originating" : "Proxying";
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
		if (fr_event_timer_at(u, h->thread->el, &u->ev, u->retry.next, request_timer, u) < 0) {
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

	fr_trunk_request_signal_sent(u->treq);

	rcode = write(h->fd, packet, packet_len);
	if (rcode < 0) {
		// @todo - handle EWOULDBLOCK
		REDEBUG("Failed writing packet to %s - %s",
			h->name, fr_syserror(errno));
		return -1;
	}

	return 0;
}


static void request_mux(fr_trunk_connection_t *tconn, fr_connection_t *conn, UNUSED void *uctx)
{
	udp_handle_t		*h = talloc_get_type_abort(fr_connection_get_handle(conn), udp_handle_t);
	udp_connection_t	*c = h->c;
	rlm_radius_udp_t const	*inst = c->thread->inst;
	fr_trunk_request_t	*treq;
	REQUEST			*request;
	udp_request_t		*u;

	while ((treq = fr_trunk_connection_pop_request(&request, (void **) &u, (void **) &u, tconn)) != NULL) {
		/*
		 *	If it's an initial packet, allocate the ID.
		 */
		if (!u->rr) {
			u->rr = rr_track_alloc(h->id, request, u->code, u);
			if (!u->rr) {
			fail:
				u->c = NULL;
				fr_trunk_request_signal_fail(treq);
				continue;
			}
		}


		/*
		 *	If it's a retransmission, then just call write().
		 */
		if (u->packet) {
			if (write_packet(u, h, u->packet, u->packet_len) < 0) {
				goto fail2;
			}
			continue;
		}

		/*
		 *	Encode the request.
		 */
		if (encode(request, u, h) < 0) {
		fail2:
			(void) rr_track_delete(h->id, u->rr);
			u->rr = NULL;
			goto fail;
		}

		if (write_packet(u, h, h->buffer, (h->buffer[2] << 8) | h->buffer[3]) < 0) {
			goto fail2;
		}

		/*
		 *	We're replicating, so we don't care about the
		 *	responses.  Don't do any retransmission timers, don't
		 *	look for replies to status checks, etc.
		 *
		 *	Instead, just set the return code to OK, and return.
		 *
		 *	@todo - if replicating, change the mux()
		 *	routine to allocate a random ID, instead of
		 *	calling a complex API.
		 */
		if (inst->replicate) {
			(void) rr_track_delete(h->id, u->rr);
			u->rr = NULL;
			u->rcode = RLM_MODULE_OK;
			fr_trunk_request_signal_complete(treq);
			continue;
		}

		/*
		 *	Tell the trunk API that this request is now in
		 *	the "sent" state.  And we don't want to see
		 *	this request again.
		 */
		u->treq = treq;
		u->c = c;

		// @todo - if there are no free IDs, call fr_trunk_connection_requests_requeue()
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
static rlm_rcode_t code2rcode[FR_RADIUS_MAX_PACKET_CODE] = {
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
static void protocol_error_reply(udp_request_t *u, udp_handle_t *h)
{
	bool	  	error_601 = false;
	uint32_t  	response_length = 0;
	uint8_t const	*attr, *end;

	end = h->buffer + ((h->buffer[2] << 8) | h->buffer[3]);

	for (attr = h->buffer + 20;
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
				u->rcode = RLM_MODULE_FAIL;
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
				u->rcode = RLM_MODULE_FAIL;
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
	u->rcode = RLM_MODULE_HANDLED;
}

/** Deal with replies replies to status checks and possible negotiation
 *
 */
static void status_check_reply(udp_request_t *u, udp_handle_t *h)
{
	if (u->num_replies < 3) return;

	if (u->ev) (void) fr_event_timer_delete(&u->ev);
	DEBUG("Have enough replies to status check, marking connection as active - %s", h->name);
	fr_trunk_connection_signal_active(h->c->tconn);

	/*
	 *	@todo - do other negotiation and signaling.
	 */
	if (h->buffer[0] == FR_CODE_PROTOCOL_ERROR) {
		protocol_error_reply(u, h);
	}
}

static udp_request_t *read_packet(udp_handle_t *h, udp_connection_t *c)
{
	rlm_radius_udp_t const	*inst = c->thread->inst;
	udp_request_t		*u;
	REQUEST			*request;
	ssize_t			data_len;
	size_t			packet_len;
	rlm_radius_request_t	*rr;
	decode_fail_t		reason;
	int			code;
	VALUE_PAIR		*reply, *vp;
	uint8_t			original[20];

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
	rr = rr_track_find(h->id, h->buffer[1], NULL);
	if (!rr) {
		WARN("%s - Ignoring reply which arrived too late", h->module_name);
		return NULL;
	}

	u = rr->request_io_ctx;
	request = u->request;
	rad_assert(request != NULL);

	original[0] = rr->code;
	original[1] = 0;	/* not looked at by fr_radius_verify() */
	original[2] = 0;
	original[3] = 20;	/* for debugging */
	memcpy(original + 4, rr->vector, sizeof(rr->vector));

	if (fr_radius_verify(h->buffer, original,
			     (uint8_t const *) inst->secret, talloc_array_length(inst->secret) - 1) < 0) {
		RPWDEBUG("Ignoring response with invalid signature");
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

	(void) rr_track_delete(h->id, rr);
	u->rr = NULL;

	if (u->ev) (void) fr_event_timer_delete(&u->ev);
	h->last_reply = fr_time();

	code = h->buffer[0];
	if (!code || (code >= FR_RADIUS_MAX_PACKET_CODE)) {
		REDEBUG("Unknown reply code %d", code);
		u->rcode = RLM_MODULE_INVALID;
		return u;
	}

	/*
	 *	Handle any state changes, etc. needed by receiving a
	 *	Protocol-Error reply packet.
	 *
	 *	Protocol-Error is permitted as a reply to any
	 *	packet.
	 */
	if (code == FR_CODE_PROTOCOL_ERROR) {
		protocol_error_reply(u, h);
		goto decode;
	}

	if (!allowed_replies[code]) {
		REDEBUG("%s packet received invalid reply code %s", fr_packet_codes[u->code], fr_packet_codes[code]);
		u->rcode = RLM_MODULE_INVALID;
		return u;
	}

	if (allowed_replies[code] != (FR_CODE) u->code) {
		REDEBUG("%s packet received invalid reply code %s", fr_packet_codes[u->code], fr_packet_codes[code]);
		u->rcode = RLM_MODULE_INVALID;
		return u;
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
	u->rcode = code2rcode[h->buffer[0]];

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
		u->rcode = RLM_MODULE_INVALID;
		return u;
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

	return u;
}

static void request_demux(UNUSED fr_trunk_connection_t *tconn, fr_connection_t *conn, UNUSED void *uctx)
{
	udp_handle_t		*h = talloc_get_type_abort(fr_connection_get_handle(conn), udp_handle_t);
	udp_connection_t	*c = h->c;
	REQUEST			*request;
	udp_request_t		*u;

	DEBUG3("%s - Reading data for connection %s", h->module_name, h->name);

redo:
	u = read_packet(h, c);
	if (!u) return;

	request = u->request;

	// decode the packet, and do funky stuff with it.
	request->reply->code = h->buffer[0];
	fr_trunk_request_signal_complete(u->treq);

	goto redo;
}

static void request_complete(REQUEST *request, UNUSED void *preq, UNUSED void *rctx, UNUSED void *uctx)
{
	unlang_interpret_resumable(request);
}

static void request_cancel(UNUSED fr_connection_t *conn, fr_trunk_request_t *treq, void *preq,
			   fr_trunk_cancel_reason_t reason, UNUSED void *uctx)
{
	udp_request_t	*u = talloc_get_type_abort(preq, udp_request_t);
	udp_handle_t	*h = talloc_get_type_abort(fr_connection_get_handle(u->c->conn), udp_handle_t);

	/*
	 *	If we've been signaled to cancel, then ACK the cancel.
	 */
	switch (reason) {
		/*
		 *	We've been re-queued, do nothing.
		 */
	case FR_TRUNK_CANCEL_REASON_NONE:
	case FR_TRUNK_CANCEL_REASON_REQUEUE:
		break;

		/*
		 *	If we've been signaled to cancel, then ACK the
		 *	cancel.  Everything will be cleaned up when
		 *	udp_request_free() is called.
		 */
	case FR_TRUNK_CANCEL_REASON_SIGNAL:
		fr_trunk_request_signal_cancel_complete(treq);
		talloc_free(u);
		break;

		/*
		 *	Request is moving to a different connection.
		 *	Free up the resources associated with this
		 *	request.
		 */
	case FR_TRUNK_CANCEL_REASON_MOVE:
		if (u->rr) {
			(void) rr_track_delete(h->id, u->rr);
			u->rr = NULL;
		}

		if (u->packet) TALLOC_FREE(u->packet);

		if (u->ev) (void) fr_event_timer_delete(&u->ev);

		u->rcode = RLM_MODULE_FAIL;
		u->c = NULL;
		u->treq = NULL;
		u->num_replies = 0;
		break;
	}
}


static void status_check_timer(fr_event_list_t *el, fr_time_t now, void *uctx)
{
	udp_request_t		*u = talloc_get_type_abort(uctx, udp_request_t);
	udp_handle_t	 	*h = talloc_get_type_abort(fr_connection_get_handle(u->c->conn), udp_handle_t);
	fr_retry_state_t	state;
	ssize_t			rcode;

	state = fr_retry_next(&u->retry, now);
	if (state == FR_RETRY_MRD) {
		DEBUG("Reached maximum_retransmit_duration for status check, marking connection as dead - %s", h->name);
		goto fail;
	}

	if (state == FR_RETRY_MRC) {
		DEBUG("Reached maximum_retransmit_count for status check, marking connection as dead - %s", h->name);
	fail:
		fr_trunk_connection_signal_reconnect(h->c->tconn, FR_CONNECTION_FAILED);
		return;
	}

	DEBUG("Retransmitting %s ID %d length %ld for status check over connection %s",
	      fr_packet_codes[u->code], u->rr->id, u->packet_len, h->name);

	// @todo - update Event-Timestamp, and re-sign the packet?

	rcode = write(h->fd, u->packet, u->packet_len);
	if ((rcode < 0) || ((size_t) rcode < u->packet_len)) {
		DEBUG("Failed writing status check packet for connection %s", h->name);
		fr_trunk_connection_signal_reconnect(h->c->tconn, FR_CONNECTION_FAILED);
		return;
	}

	if (fr_event_timer_at(u, el, &u->ev, u->retry.next, status_check_timer, u) < 0) {
		ERROR("Failed inserting retransmit timeout for connection %s", h->name);
		fr_trunk_connection_signal_reconnect(h->c->tconn, FR_CONNECTION_FAILED);
		return;
	}
}


/** Mark a connection "zombie" due to zombie timeout.
 *
 */
static void handle_zombie_timeout(fr_event_list_t *el, fr_time_t now, void *uctx)
{
	udp_handle_t *h = talloc_get_type_abort(uctx, udp_handle_t);
	udp_request_t *u = h->status_u;
	ssize_t rcode;

	ERROR("%s - Zombie timeout for connection %s", h->module_name, h->name);

	if (!h->inst->parent->status_check) {
		DEBUG2("No status_check response, closing connection %s", h->name);
		fr_trunk_connection_signal_reconnect(h->c->tconn, FR_CONNECTION_FAILED);
		return;
	}

	/*
	 *	Initialize timers for Status-Server.
	 */
	(void) fr_retry_init(&u->retry, now, &h->inst->parent->retry[u->code]);
	u->num_replies = 0;
	u->recv_time = u->retry.start;

	if (encode(u->request, u, h) < 0) {
		DEBUG("Failed encoding status check packet for connection %s", h->name);
		fr_trunk_connection_signal_reconnect(h->c->tconn, FR_CONNECTION_FAILED);
		return;
	}

	rcode = write(h->fd, u->packet, u->packet_len);
	if ((rcode < 0) || ((size_t) rcode < u->packet_len)) {
		DEBUG("Failed writing status check packet for connection %s", h->name);
		fr_trunk_connection_signal_reconnect(h->c->tconn, FR_CONNECTION_FAILED);
		return;
	}

	if (fr_event_timer_at(u, el, &u->ev, u->retry.next, status_check_timer, u) < 0) {
		ERROR("Failed inserting retransmit timeout for connection %s", h->name);
		fr_trunk_connection_signal_reconnect(h->c->tconn, FR_CONNECTION_FAILED);
		return;
	}
}


/** Request has failed to send.
 *
 */
static void request_fail(UNUSED REQUEST *request, void *preq, UNUSED void *rctx, UNUSED void *uctx)
{
	udp_request_t	*u = talloc_get_type_abort(preq, udp_request_t);
	udp_handle_t	 *h = talloc_get_type_abort(fr_connection_get_handle(u->c->conn), udp_handle_t);
	fr_time_t now, when;

	u->rcode = RLM_MODULE_FAIL;

	/*
	 *	We're replicating, don't do zombie checks.
	 *
	 *	Note that we still do zombie checks if we're doing
	 *	synchronous proxying.  This is so that we can
	 *	determine if a connection is up, even if the NAS
	 *	retransmission behavior is poor.
	 */
	if (h->inst->replicate) return;

	/*
	 *	Already a zombie timer, do nothing.
	 */
	if (h->zombie_ev) return;

	now = fr_time();
	when = h->last_reply;

	/*
	 *	Use the zombie_period for the timeout.
	 *
	 *	Note that we do this check on every packet, which is a
	 *	bit annoying, but oh well.
	 */
	when += h->inst->parent->zombie_period;
	if (when > now) return;

	WARN("%s - Entering Zombie state - connection %s", h->module_name, h->name);

	if (fr_event_timer_in(h, h->c->thread->el, &h->zombie_ev, h->inst->parent->zombie_period, handle_zombie_timeout, h) < 0) {
		ERROR("%s - Failed inserting zombie timeout for connection %s",
		      h->module_name, h->name);
		fr_trunk_connection_signal_reconnect(h->c->tconn, FR_CONNECTION_FAILED);
		return;
	}

	fr_trunk_connection_signal_inactive(h->c->tconn);
}


static fr_trunk_io_funcs_t trunk_funcs = {
	.connection_alloc = thread_conn_alloc,
	.connection_notify = thread_conn_notify,
	.request_prioritise = request_prioritise,
	.request_mux = request_mux,
	.request_demux = request_demux,
	.request_complete = request_complete,
	.request_cancel = request_cancel,
	.request_fail = request_fail,
};


static rlm_rcode_t request_resume(UNUSED void *instance, UNUSED void *thread, UNUSED REQUEST *request, void *ctx)
{
	udp_request_t *u = talloc_get_type_abort(ctx, udp_request_t);
	rlm_rcode_t rcode;

	rcode = u->rcode;
	rad_assert(rcode != RLM_MODULE_YIELD);
	talloc_free(u);

	return rcode;
}


/** Free a udp_request_t
 */
static int udp_request_free(udp_request_t *u)
{
	udp_handle_t *h;

	/*
	 *	We don't have a connection, so we can't update any of
	 *	the connection timers or states.
	 */
	if (!u->c) return 0;

	if (u->ev) (void) fr_event_timer_delete(&u->ev);

	h = talloc_get_type_abort(fr_connection_get_handle(u->c->conn), udp_handle_t);

	/*
	 *	The module is doing async proxying, we don't need to
	 *	do more.
	 */
	if (!u->synchronous) return 0;

	if (u->rr) (void) rr_track_delete(h->id, u->rr);

	return 0;
}

static rlm_rcode_t mod_push(void *instance, REQUEST *request, void *request_io_ctx, void *tctx)
{
	rlm_radius_udp_t		*inst = talloc_get_type_abort(instance, rlm_radius_udp_t);
	udp_request_t			*u = talloc_get_type_abort(request_io_ctx, udp_request_t);
	udp_thread_t			*thread = talloc_get_type_abort(tctx, udp_thread_t);

	rad_assert(request->packet->code > 0);
	rad_assert(request->packet->code < FR_RADIUS_MAX_PACKET_CODE);

	/*
	 *	If configured, and we don't have any active
	 *	connections, fail the request.  This lets "parallel"
	 *	sections finish much more quickly than otherwise.
	 */
	if (inst->parent->no_connection_fail &&
	    (fr_trunk_connection_count_by_state(thread->trunk, FR_TRUNK_CONN_ACTIVE) == 0)) {
		REDEBUG("Failing request due to 'no_connection_fail = true', and there are no active connections");
		return RLM_MODULE_FAIL;
	}

	if (request->packet->code == FR_CODE_STATUS_SERVER) {
		RWDEBUG("Status-Server is reserved for internal use, and cannot be sent manually.");
		return RLM_MODULE_NOOP;
	}

	u->rr = NULL;
	u->c = NULL;
	u->rcode = RLM_MODULE_FAIL;
	u->code = request->packet->code;
	u->synchronous = inst->parent->synchronous;
	u->request = request;
	u->priority = request->async->priority;	  /* cached for speed */
	u->recv_time = request->async->recv_time; /* cached for speed */

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

	if (fr_trunk_request_enqueue(&u->treq, thread->trunk, request, u, u) < 0) {
		talloc_free(u);
		return RLM_MODULE_FAIL;
	}

	talloc_set_destructor(u, udp_request_free);

	return RLM_MODULE_YIELD;
}


static void mod_signal(UNUSED REQUEST *request, void *instance, UNUSED void *thread, void *request_io_ctx, fr_state_signal_t action)
{
	rlm_radius_udp_t *inst = talloc_get_type_abort(instance, rlm_radius_udp_t);
	udp_request_t	*u = talloc_get_type_abort(request_io_ctx, udp_request_t);

	if (action == FR_SIGNAL_CANCEL) {
		fr_trunk_request_signal_cancel(u->treq);
		return;
	}

	if (action != FR_SIGNAL_DUP) return;

	/*
	 *	Asychronous mode means that we do retransmission, and
	 *	we don't rely on the retransmission from the NAS.
	 */
	if (!inst->parent->synchronous) return;

	fr_trunk_request_requeue(u->treq);
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
static int mod_thread_instantiate(UNUSED CONF_SECTION const *cs, void *instance, fr_event_list_t *el, void *tctx)
{
	rlm_radius_udp_t *inst = talloc_get_type_abort(instance, rlm_radius_udp_t);
	udp_thread_t *thread = talloc_get_type_abort(tctx, udp_thread_t);

	inst->trunk_conf = &inst->parent->trunk_conf;

	thread->el = el;
	thread->inst = inst;
	thread->trunk = fr_trunk_alloc(thread, el, &trunk_funcs, inst->trunk_conf,
				       inst->parent->name, thread, false);
	if (!thread->trunk) {
		ERROR("%s - Failed opening trunk API: %s", inst->parent->name, fr_strerror());
	}

	return 0;
}


extern fr_radius_client_io_t rlm_radius_udp;
fr_radius_client_io_t rlm_radius_udp = {
	.magic			= RLM_MODULE_INIT,
	.name			= "radius_udp",
	.inst_size		= sizeof(rlm_radius_udp_t),

	.request_inst_size 	= sizeof(udp_request_t),
	.request_inst_type	= "udp_request_t",

	.thread_inst_size	= sizeof(udp_thread_t),
	.thread_inst_type	= "udp_thread_t",

	.config			= module_config,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,
	.thread_instantiate 	= mod_thread_instantiate,

	.push			= mod_push,
	.signal			= mod_signal,
	.resume			= request_resume,
};
