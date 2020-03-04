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
 * @copyright 2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/server/connection.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/heap.h>
#include <freeradius-devel/util/udp.h>

#include <sys/socket.h>

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
	uint16_t		max_send_coalesce;	//!< Maximum number of packets to coalesce into one mmsg call.

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

typedef struct {
	fr_trunk_request_t	*treq;
	rlm_rcode_t		rcode;			//!< from the transport
} udp_result_t;

typedef struct udp_request_s udp_request_t;

typedef struct {
	struct iovec		out;			//!< Describes buffer to send.
	fr_trunk_request_t	*treq;			//!< Used for signalling.
} udp_coalesced_t;

/** Track the handle, which is tightly correlated with the FD
 *
 */
typedef struct {
	char const     		*name;			//!< From IP PORT to IP PORT.
	char const		*module_name;		//!< the module that opened the connection

	int			fd;			//!< File descriptor.

	struct mmsghdr		*mmsgvec;		//!< Vector of inbound/outbound packets.
	udp_coalesced_t		*coalesced;		//!< Outbound coalesced requests.

	rlm_radius_udp_t const	*inst;			//!< Our module instance.
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
	udp_request_t		*status_u;		//!< for sending status check packets
	udp_result_t		*status_r;		//!< for faking out status checks as real packets
	REQUEST			*status_request;
} udp_handle_t;


/** Connect REQUEST to local tracking structure
 *
 */
struct udp_request_s {
	uint32_t		priority;		//!< copied from request->async->priority
	fr_time_t		recv_time;		//!< copied from request->async->recv_time

	uint32_t		num_replies;		//!< number of reply packets, sent is in retry.count

	bool			synchronous;		//!< cached from inst->parent->synchronous
	bool			require_ma;		//!< saved from the original packet.
	bool			can_retransmit;		//!< can we retransmit this packet?
	bool			status_check;		//!< is this packet a status check?

	VALUE_PAIR		*extra;			//!< VPs for debugging, like Proxy-State.

	uint8_t			code;			//!< Packet code.
	uint8_t			id;			//!< Last ID assigned to this packet.
	uint8_t			*packet;		//!< Packet we write to the network.
	size_t			packet_len;		//!< Length of the packet.

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
	{ FR_CONF_OFFSET("max_send_coalesce", FR_TYPE_UINT16, rlm_radius_udp_t, max_send_coalesce), .dflt = "1024" },

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


/** Clear a UDP request, ready for moving or retransmission
 *
 * @note We don't necessarily have to clear the packet here.
 */
static void udp_request_clear(udp_handle_t *h, udp_request_t *u, fr_time_t now)
{
	if (!now) now = fr_time();
	if (u->rr) (void) radius_track_delete(&u->rr);

	/* Now wrong - We don't keep an entry reserved for the status check */
	if (h && (h->tt->num_free == (h->status_u != NULL))) h->last_idle = now;

	fr_pair_list_free(&u->extra);
}

/** Reset a status_check packet, ready to re-use
 *
 */
static void status_check_reset(udp_handle_t *h, udp_request_t *u)
{
	rad_assert(u->status_check == true);

	h->status_checking = false;
	u->num_replies = 0;	/* Reset */
	u->retry.start = 0;

	if (u->rr) (void) radius_track_delete(&u->rr);	/* Not used for conn status check */
	if (u->ev) (void) fr_event_timer_delete(&u->ev);

	TALLOC_FREE(u->packet);
	fr_pair_list_free(&u->extra);
}

/*
 *	Status-Server checks.  Manually build the packet, and
 *	all of its associated glue.
 */
static void status_check_alloc(fr_event_list_t *el, udp_handle_t *h)
{
	udp_request_t		*u;
	REQUEST			*request;
	rlm_radius_udp_t const	*inst = h->inst;
	vp_map_t		*map;

	u = talloc_zero(h, udp_request_t);

	/*
	 *	Status checks are prioritized over any other packet
	 */
	u->priority = ~(uint32_t) 0;
	u->status_check = true;

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

	MEM(h->status_r = talloc_zero(h, udp_result_t));
	h->status_u = u;
	h->status_request = request;
}

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
	uint16_t		i;

	h = talloc_zero(conn, udp_handle_t);
	if (!h) return FR_CONNECTION_STATE_FAILED;

	h->thread = thread;
	h->inst = thread->inst;
	h->module_name = h->inst->parent->name;
	h->src_ipaddr = h->inst->src_ipaddr;
	h->src_port = 0;
	h->max_packet_size = h->inst->max_packet_size;
	h->last_idle = fr_time();

	/*
	 *	mmsgvec is pre-populated with pointers
	 *	to the iovec structs in coalesced, so we
	 *	just need to setup the iovec, and pass how
	 *      many messages we want to send to sendmmsg.
	 */
	h->mmsgvec = talloc_zero_array(h, struct mmsghdr, h->inst->max_send_coalesce);
	h->coalesced = talloc_zero_array(h, udp_coalesced_t, h->inst->max_send_coalesce);
	for (i = 0; i < h->inst->max_send_coalesce; i++) {
		h->mmsgvec[i].msg_hdr.msg_iov = &h->coalesced[i].out;
		h->mmsgvec[i].msg_hdr.msg_iovlen = 1;
	}

	MEM(h->buffer = talloc_array(h, uint8_t, h->max_packet_size));
	h->buflen = h->max_packet_size;

	if (!h->inst->replicate) MEM(h->tt = radius_track_alloc(h));

	/*
	 *	Open the outgoing socket.
	 */
	fd = fr_socket_client_udp(&h->src_ipaddr, &h->src_port, &h->inst->dst_ipaddr, h->inst->dst_port, true);
	if (fd < 0) {
		PERROR("%s - Failed opening socket", h->module_name);
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
 * @param[in] uctx	UNUSED.
 */
static fr_connection_state_t conn_failed(void *handle, fr_connection_state_t state, UNUSED void *uctx)
{
	switch (state) {
	/*
	 *	If the connection was connected when it failed,
	 *	we need to handle any outstanding packets and
	 *	timer events before reconnecting.
	 */
	case FR_CONNECTION_STATE_CONNECTED:
	{
		udp_handle_t	*h = talloc_get_type_abort(handle, udp_handle_t); /* h only available if connected */

		/*
		 *	Reset the Status-Server checks.
		 */
		if (h->status_u && h->status_u->ev) (void) fr_event_timer_delete(&h->status_u->ev);
	}
		break;

	default:
		break;
	}

	return FR_CONNECTION_STATE_INIT;
}

static fr_connection_t *thread_conn_alloc(fr_trunk_connection_t *tconn, fr_event_list_t *el,
					  fr_connection_conf_t const *conf,
					  char const *log_prefix, void *uctx)
{
	fr_connection_t		*conn;
	udp_thread_t		*thread = talloc_get_type_abort(uctx, udp_thread_t);

	conn = fr_connection_alloc(tconn, el,
				   &(fr_connection_funcs_t){
					.init = conn_init,
					.open = conn_open,
					.close = conn_close,
					.failed = conn_failed
				   },
				   conf,
				   log_prefix,
				   thread);
	if (!conn) {
		talloc_free(conn);
		PERROR("%s - Failed allocating state handler for new connection", thread->inst->parent->name);
		return NULL;
	}

	return conn;
}

/** Read and discard data
 *
 */
static void conn_discard(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);
	udp_handle_t		*h = talloc_get_type_abort(tconn->conn->h, udp_handle_t);
	uint8_t			buffer[4096];
	ssize_t			slen;

	while ((slen = read(fd, buffer, sizeof(buffer))) > 0);

	if (slen < 0) {
		switch (errno) {
		case EBADF:
		case ECONNRESET:
		case ENOTCONN:
		case ETIMEDOUT:
			ERROR("%s - %s failed draining socket: %s",
			      __FUNCTION__, h->module_name, fr_syserror(errno));
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

	ERROR("%s - Connection %s failed - %s", h->module_name, h->name, fr_syserror(fd_errno));

	fr_connection_signal_reconnect(conn, FR_CONNECTION_FAILED);
}

static void thread_conn_notify(fr_trunk_connection_t *tconn, fr_connection_t *conn,
			       fr_event_list_t *el,
			       fr_trunk_connection_event_t notify_on, UNUSED void *uctx)
{
	udp_handle_t		*h = talloc_get_type_abort(conn->h, udp_handle_t);
	fr_event_fd_cb_t	read_fn = NULL;
	fr_event_fd_cb_t	write_fn = NULL;

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
		PERROR("%s - %s failed inserting FD event", h->module_name, __FUNCTION__);

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
		read_fn = conn_discard;
		break;

	case FR_TRUNK_CONN_EVENT_BOTH:
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
		PERROR("%s - %s failed inserting FD event", h->module_name, __FUNCTION__);

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
	 *	Prioritise status check packets
	 */
	rcode = (b->status_check - a->status_check);;
	if (rcode != 0) return rcode;

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

/** Decode response packet data, extracting relevant information and validating the packet
 *
 * @param[in] ctx			to allocate pairs in.
 * @param[out] reply			Pointer to head of pair list to add reply attributes to.
 * @param[out] response_code		The type of response packet.
 * @param[in] request_authenticator	from the original request.
 * @param[in] data			to decode.
 * @param[in] data_len			Length of input data.
 * @return
 *	- DECODE_FAIL_NONE on success.
 *	- DECODE_FAIL_* on failure.
 */
static decode_fail_t decode(TALLOC_CTX *ctx, VALUE_PAIR **reply, uint8_t *response_code,
			    udp_handle_t *h, REQUEST *request, udp_request_t *u,
			    uint8_t const request_authenticator[static RADIUS_AUTH_VECTOR_LENGTH],
			    uint8_t *data, size_t data_len)
{
	rlm_radius_udp_t const *inst = h->thread->inst;
	size_t			packet_len;
	decode_fail_t		reason;
	uint8_t			code;
	uint8_t			original[RADIUS_HEADER_LENGTH];

	*response_code = 0;	/* Initialise to keep the rest of the code happy */

	packet_len = data_len;
	if (!fr_radius_ok(data, &packet_len, inst->parent->max_attributes, false, &reason)) {
		RWARN("Ignoring malformed packet");
		return reason;
	}

	if (RDEBUG_ENABLED3) {
		RDEBUG3("Read packet");
		fr_log_hex(&default_log, L_DBG, __FILE__, __LINE__, data, packet_len, NULL);
	}

	original[0] = u->code;
	original[1] = 0;			/* not looked at by fr_radius_verify() */
	original[2] = 0;
	original[3] = RADIUS_HEADER_LENGTH;	/* for debugging */
	memcpy(original + RADIUS_AUTH_VECTOR_OFFSET, request_authenticator, RADIUS_AUTH_VECTOR_LENGTH);

	if (fr_radius_verify(data, original,
			     (uint8_t const *) inst->secret, talloc_array_length(inst->secret) - 1) < 0) {
		RPWDEBUG("Ignoring response with invalid signature");
		return DECODE_FAIL_MA_INVALID;
	}

	code = data[0];
	if (!code || (code >= FR_RADIUS_MAX_PACKET_CODE)) {
		REDEBUG("Unknown reply code %d", code);
		return DECODE_FAIL_UNKNOWN_PACKET_CODE;
	}

	/*
	 *	Protocol error is allowed as a response to any
	 *	packet code.
	 */
	if (code != FR_CODE_PROTOCOL_ERROR) {
		if (!allowed_replies[code]) {
			REDEBUG("%s packet received invalid reply code %s",
				fr_packet_codes[u->code], fr_packet_codes[code]);
			return DECODE_FAIL_UNKNOWN_PACKET_CODE;
		}

		if (allowed_replies[code] != (FR_CODE) u->code) {
			REDEBUG("%s packet received invalid reply code %s",
				fr_packet_codes[u->code], fr_packet_codes[code]);
			return DECODE_FAIL_UNKNOWN_PACKET_CODE;
		}
	}

	/*
	 *	Decode the attributes, in the context of the reply.
	 *	This only fails if the packet is strangely malformed,
	 *	or if we run out of memory.
	 */
	if (fr_radius_decode(ctx, data, packet_len, original,
			     inst->secret, talloc_array_length(inst->secret) - 1, reply) < 0) {
		REDEBUG("Failed decoding attributes for packet");
		fr_pair_list_free(reply);
		return DECODE_FAIL_UNKNOWN;
	}

	RDEBUG("Received %s ID %d length %ld reply packet on connection %s",
	       fr_packet_codes[code], code, packet_len, h->name);
	log_request_pair_list(L_DBG_LVL_2, request, *reply, NULL);

	*response_code = code;

	/*
	 *	Record the fact we've seen a response
	 */
	u->num_replies++;

	/*
	 *	Fixup retry times
	 */
	if (u->retry.start > h->mrs_time) h->mrs_time = u->retry.start;

	return DECODE_FAIL_NONE;
}

static int encode(rlm_radius_udp_t const *inst, REQUEST *request, udp_request_t *u, uint8_t id)
{
	ssize_t			packet_len;
	uint8_t			*msg = NULL;
	int			message_authenticator = u->require_ma * (RADIUS_MESSAGE_AUTHENTICATOR_LENGTH + 2);
	int			proxy_state = 6;

	rad_assert(inst->parent->allowed[u->code]);

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
	if (u->status_check) {
		VALUE_PAIR *vp;

		proxy_state = 0;
		vp = fr_pair_find_by_da(request->packet->vps, attr_event_timestamp, TAG_ANY);
		if (vp) vp->vp_date = fr_time_to_unix_time(u->retry.updated);

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
		fr_cursor_t	cursor;
		int		count = 0;

		rad_assert((size_t) (packet_len + proxy_state) <= u->packet_len);

		/*
		 *	Count how many Proxy-State attributes have
		 *	*our* magic number.  Note that we also add a
		 *	counter to each Proxy-State, so we're double
		 *	sure that it's a loop.
		 */
		if (DEBUG_ENABLED) {
			for (vp = fr_cursor_iter_by_da_init(&cursor, &request->packet->vps, attr_proxy_state);
			     vp;
			     vp = fr_cursor_next(&cursor)) {
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
	 *	Only certain types of packet, and those with a
	 *	message_authenticator need signing.
	 */
	if (message_authenticator) goto sign;
	switch (u->code) {
	case FR_CODE_ACCOUNTING_REQUEST:
	case FR_CODE_DISCONNECT_REQUEST:
	case FR_CODE_COA_REQUEST:
	sign:
		/*
		 *	Now that we're done mangling the packet, sign it.
		 */
		if (fr_radius_sign(u->packet, NULL, (uint8_t const *) inst->secret,
				   talloc_array_length(inst->secret) - 1) < 0) {
			RERROR("Failed signing packet");
			return -1;
		}
		break;

	default:
		break;

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

	INFO("%s - Shutting down and reviving connection %s", h->module_name, h->name);
	fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
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

	/*
	 *	We're replicating, and don't care about the health of
	 *	the home server, and this function should not be called.
	 */
	rad_assert(!h->inst->replicate);

	/*
	 *	If there's already a zombie check started, don't do
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
	if (h->status_checking || h->zombie_ev || !h->last_sent || (h->last_sent <= h->last_idle) ||
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
		if ((h->last_reply + h->inst->parent->zombie_period) >= now) return;
	} else {
		if ((h->first_sent + h->inst->parent->zombie_period) >= now) return;
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

		WARN("%s - Connection failed.  Reviving it in %u.%03us", h->module_name, msec / 1000, msec % 1000);
		fr_trunk_connection_signal_inactive(tconn);
		(void) fr_trunk_connection_requests_requeue(tconn, FR_TRUNK_REQUEST_STATE_ALL, 0, false);

		when = now + h->inst->parent->revive_interval;
		if (fr_event_timer_at(h, el, &h->zombie_ev, when, revive_timer, tconn) < 0) {
			fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
			return;
		}

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
	(void) fr_trunk_connection_requests_requeue(tconn, FR_TRUNK_REQUEST_STATE_ALL, 0, false);

	/*
	 *	Queue up the status check packet.  It will be sent
	 *	when the connection is writable.
	 */
	h->status_u->retry.start = 0;
	h->status_r->treq = NULL;

	if (fr_trunk_request_enqueue_on_conn(&h->status_r->treq, tconn, h->status_request,
					     h->status_u, h->status_r, true) != FR_TRUNK_ENQUEUE_OK) {
		fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
	}
}

/** Handle retries for a REQUEST
 *
 */
static void request_timeout(fr_event_list_t *el, fr_time_t now, void *uctx)
{
	fr_trunk_request_t	*treq = talloc_get_type_abort(uctx, fr_trunk_request_t);
	udp_handle_t		*h;
	udp_request_t		*u = talloc_get_type_abort(treq->preq, udp_request_t);
	udp_result_t		*r = talloc_get_type_abort(treq->rctx, udp_result_t);
	REQUEST			*request = treq->request;

	rad_assert(u->rr);
	rad_assert(treq->tconn);

	h = talloc_get_type_abort(treq->tconn->conn->h, udp_handle_t);

	if (!u->status_check) {
		check_for_zombie(el, treq->tconn, now);
	/*
	 *	Reset replies to 0 as we only count
	 *	contiguous, good, replies.
	 */
	} else {
		u->num_replies = 0;
	}

	switch (fr_retry_next(&u->retry, now)) {
	/*
	 *	Queue the request for retransmission.
	 *
	 *	@todo - set up "next" timer here, instead of in
	 *	request_mux() ?  That way we can catch the case of
	 *	packets sitting in the queue for extended periods of
	 *	time, and still run the timers.
	 */
	case FR_RETRY_CONTINUE:
		fr_trunk_request_requeue(treq);
		return;

	case FR_RETRY_MRD:
		RDEBUG("Reached maximum_retransmit_duration, failing request");
		break;

	case FR_RETRY_MRC:
		RDEBUG("Reached maximum_retransmit_count, failing request");
		break;
	}

	udp_request_clear(h, u, now);
	r->rcode = RLM_MODULE_FAIL;
	fr_trunk_request_signal_complete(treq);

	if (!u->status_check) return;

	WARN("%s - No response to status check, marking connection as dead - %s", h->module_name, h->name);

	h->status_checking = false;

	/*
	 *	If the request timeout fires, then the treq must
	 *	still be associated with a connection.
	 *
	 *	If the treq is moved off a connection, the timer
	 *	*MUST* be disabled.
	 */
	rad_assert(treq->tconn);
	fr_trunk_connection_signal_reconnect(treq->tconn, FR_CONNECTION_FAILED);
}

static void request_mux(fr_event_list_t *el,
			fr_trunk_connection_t *tconn, fr_connection_t *conn, UNUSED void *uctx)
{
	udp_handle_t		*h = talloc_get_type_abort(conn->h, udp_handle_t);
	rlm_radius_udp_t const	*inst = h->inst;
	int			sent;
	uint16_t		i = 0, queued;

	check_for_zombie(el, tconn, 0);

	/*
	 *	Encode multiple packets in preparation
	 *      for transmission with sendmmsg.
	 */
	for (i = 0; i < inst->max_send_coalesce; i++) {
		fr_trunk_request_t	*treq = fr_trunk_connection_pop_request(tconn);
		udp_request_t		*u;
		REQUEST			*request;

		/*
		 *	No more requests to send
		 */
		if (!treq) break;

		request = treq->request;
		u = talloc_get_type_abort(treq->preq, udp_request_t);

		/*
		 *	Start retransmissions from when the socket is writable.
		 */
		if (!u->retry.start) {
			(void) fr_retry_init(&u->retry, fr_time(), &h->inst->parent->retry[u->code]);
			rad_assert(u->retry.rt > 0);
			rad_assert(u->retry.next > 0);
		}

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
				fr_trunk_request_signal_fail(treq);
				continue;
			}
			u->id = u->rr->id;

			RDEBUG("Sending %s ID %d length %ld over connection %s",
			       fr_packet_codes[u->code], u->id, u->packet_len, h->name);

			if (encode(h->inst, request, u, u->id) < 0) {
				udp_request_clear(h, u, 0);
				if (u->ev) (void) fr_event_timer_delete(&u->ev);
				goto fail;
			}
			RHEXDUMP3(u->packet, u->packet_len, "Encoded packet");

			/*
			 *	Remember the authentication vector, which now has the
			 *	packet signature.
			 */
			(void) radius_track_update(u->rr, u->packet + RADIUS_AUTH_VECTOR_OFFSET);
		} else {
			RDEBUG("Retransmitting %s ID %d length %ld over connection %s",
			       fr_packet_codes[u->code], u->id, u->packet_len, h->name);
		}

		log_request_pair_list(L_DBG_LVL_2, request, request->packet->vps, NULL);
		if (u->extra) log_request_pair_list(L_DBG_LVL_2, request, u->extra, NULL);

		/*
		 *	Record pointers to the buffer we'll be writing
		 *	We store the treq so we can place it back in
		 *      the pending state if the sendmmsg call fails.
		 */
		h->coalesced[i].treq = treq;
		h->coalesced[i].out.iov_base = u->packet;
		h->coalesced[i].out.iov_len = u->packet_len;

		/*
		 *	Tell the trunk API that this request is now in
		 *	the "sent" state.  And we don't want to see
		 *	this request again. The request hasn't actually
		 *	been sent, but it's the only way to get at the
		 *	next entry in the heap.
		 */
		fr_trunk_request_signal_sent(treq);
	}
	queued = i;
	if (queued == 0) return;	/* No work */

	/*
	 *	Send the coalesced datagrams
	 */
	sent = sendmmsg(h->fd, h->mmsgvec, queued, 0);
	if (sent < 0) {		/* Error means no messages were sent */
		sent = 0;

		/*
		 *	Temporary conditions
		 */
		switch (errno) {
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
		case EWOULDBLOCK:	/* No outbound packet buffers, maybe? */
#endif
		case EAGAIN:		/* No outbound packet buffers, maybe? */
		case EINTR:		/* Interrupted by signal */
		case ENOBUFS:		/* No outbound packet buffers, maybe? */
		case ENOMEM:		/* malloc failure in kernel? */
			WARN("%s - Failed sending data over connection %s - %s",
			     h->module_name, h->name, fr_syserror(errno));
			break;

		/*
		 *	Fatal, request specific conditions
		 *
		 *	sendmmsg will only return an error condition if the
		 *	first packet being sent errors.
		 *
		 *	When we get request specific errors, we need to fail
		 *	the first request in the set, and move the rest of
		 *	the packets back to the pending state.
		 */
		case EMSGSIZE:		/* Packet size exceeds max size allowed on socket */
			ERROR("%s - Failed sending data over connection %s - %s",
			      h->module_name, h->name, fr_syserror(errno));
			fr_trunk_request_signal_fail(h->coalesced[i].treq);
			sent = 1;
			break;

		/*
		 *	Will re-queue any 'sent' requests, so we don't
		 *	have to do any cleanup.
		 */
		default:
			ERROR("%s - Failed sending data over connection %s - %s",
			      h->module_name, h->name, fr_syserror(errno));
			fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
			return;
		}
	}

	/*
	 *	For all messages that were actually sent by sendmmsg
	 *	start the request timer.
	 */
	for (i = 0; i < sent; i++) {
		fr_trunk_request_t	*treq = h->coalesced[i].treq;
		udp_request_t		*u;
		REQUEST			*request;
		char const		*action;

		/*
		 *	It's UDP so there should never be partial writes
		 */
		rad_assert((size_t)h->mmsgvec[i].msg_len == h->mmsgvec[i].msg_hdr.msg_iov->iov_len);

		request = treq->request;
		u = talloc_get_type_abort(treq->preq, udp_request_t);

		/*
		 *	Tell the admin what's going on
		 */
		if (u->retry.count == 1) {
			action = inst->parent->originate ? "Originated" : "Proxied";
			h->last_sent = u->retry.start;
			if (h->first_sent <= h->last_idle) h->first_sent = h->last_sent;

		} else {
			action = "Retransmitted";
		}

		if (!inst->parent->synchronous) {
			uint32_t	msec = fr_time_delta_to_msec(u->retry.rt);

			RDEBUG("%s request.  Expecting response within %u.%03us",
			       action, msec / 1000, msec % 1000);

			if (fr_event_timer_at(u, el, &u->ev, u->retry.next, request_timeout, treq) < 0) {
				RERROR("Failed inserting retransmit timeout for connection");
				fr_trunk_request_signal_fail(treq);
				continue;
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
	}

	/*
	 *	Requests that weren't sent get re-enqueued
	 *
	 *	The cancel logic runs as per-normal and cleans up
	 *	the request ready for sending again...
	 */
	for (i = sent; i < queued; i++) fr_trunk_request_requeue(h->coalesced[i].treq);
}

static void request_mux_replicate(UNUSED fr_event_list_t *el,
				  fr_trunk_connection_t *tconn, fr_connection_t *conn, UNUSED void *uctx)
{
	udp_handle_t		*h = talloc_get_type_abort(conn->h, udp_handle_t);
	rlm_radius_udp_t const	*inst = h->inst;

	uint16_t		i = 0, queued;
	int			sent;

	for (i = 0; i < inst->max_send_coalesce; i++) {
		fr_trunk_request_t	*treq = fr_trunk_connection_pop_request(tconn);
		udp_request_t		*u;
		REQUEST			*request;

		/*
		 *	No more requests to send
		 */
		if (!treq) break;

		request = treq->request;
		u = talloc_get_type_abort(treq->preq, udp_request_t);

		if (!u->packet) {
			u->id = h->last_id++;

			if (encode(h->inst, request, u, u->id) < 0) {
				udp_request_clear(h, u, 0);
				fr_trunk_request_signal_fail(treq);
				return;
			}
		}

		RDEBUG("Sending %s ID %d length %ld over connection %s",
		       fr_packet_codes[u->code], u->id, u->packet_len, h->name);
		RHEXDUMP3(u->packet, u->packet_len, "Encoded packet");

		h->coalesced[i].treq = treq;
		h->coalesced[i].out.iov_base = u->packet;
		h->coalesced[i].out.iov_len = u->packet_len;

		fr_trunk_request_signal_sent(treq);
	}
	queued = i;
	if (queued == 0) return;	/* No work */

	sent = sendmmsg(h->fd, h->mmsgvec, queued, 0);
	if (sent < 0) {		/* Error means no messages were sent */
		sent = 0;

		/*
		 *	Temporary conditions
		 */
		switch (errno) {
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
		case EWOULDBLOCK:	/* No outbound packet buffers, maybe? */
#endif
		case EAGAIN:		/* No outbound packet buffers, maybe? */
		case EINTR:		/* Interrupted by signal */
		case ENOBUFS:		/* No outbound packet buffers, maybe? */
		case ENOMEM:		/* malloc failure in kernel? */
			WARN("%s - Failed sending data over connection %s - %s",
			     h->module_name, h->name, fr_syserror(errno));
			break;

		/*
		 *	Fatal, request specific conditions
		 *
		 *	sendmmsg will only return an error condition if the
		 *	first packet being sent errors.
		 *
		 *	When we get request specific errors, we need to fail
		 *	the first request in the set, and move the rest of
		 *	the packets back to the pending state.
		 */
		case EMSGSIZE:		/* Packet size exceeds max size allowed on socket */
			ERROR("%s - Failed sending data over connection %s - %s",
			      h->module_name, h->name, fr_syserror(errno));
			fr_trunk_request_signal_fail(h->coalesced[i].treq);
			sent = 1;
			break;

		/*
		 *	Will re-queue any 'sent' requests, so we don't
		 *	have to do any cleanup.
		 */
		default:
			ERROR("%s - Failed sending data over connection %s - %s",
			      h->module_name, h->name, fr_syserror(errno));
			fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
			return;
		}
	}

	for (i = 0; i < sent; i++) {
		fr_trunk_request_t	*treq = h->coalesced[i].treq;
		udp_result_t		*r = talloc_get_type_abort(treq->rctx, udp_result_t);

		/*
		 *	It's UDP so there should never be partial writes
		 */
		rad_assert((size_t)h->mmsgvec[i].msg_len == h->mmsgvec[i].msg_hdr.msg_iov->iov_len);

		r->rcode = RLM_MODULE_OK;
		fr_trunk_request_signal_complete(treq);
	}

	for (i = sent; i < queued; i++) fr_trunk_request_requeue(h->coalesced[i].treq);
}

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


/** Handle retries for a status check
 *
 */
static void status_check_next(UNUSED fr_event_list_t *el, fr_time_t now, void *uctx)
{
	fr_trunk_connection_t	*tconn = talloc_get_type_abort(uctx, fr_trunk_connection_t);
	udp_handle_t		*h = talloc_get_type_abort(tconn->conn->h, udp_handle_t);
	udp_request_t		*u = h->status_u;
	REQUEST			*request;

	request = h->status_request;

	switch (fr_retry_next(&u->retry, now)) {
	case FR_RETRY_MRD:
		RDEBUG("Reached maximum_retransmit_duration, failing status checks");
		goto fail;

	case FR_RETRY_MRC:
		RDEBUG("Reached maximum_retransmit_count, failing status checks");
	fail:
		fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
		return;

	/*
	 *	Requeue the status check for retransmission.
	 */
	case FR_RETRY_CONTINUE:
		if (fr_trunk_request_enqueue_on_conn(&h->status_r->treq, tconn, h->status_request,
						     h->status_u, h->status_r, true) != FR_TRUNK_ENQUEUE_OK) {
			fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
		}
		return;
	}

	rad_assert(0);
}


/** Deal with replies replies to status checks and possible negotiation
 *
 */
static void status_check_reply(fr_trunk_request_t *treq, fr_time_t now)
{
	udp_handle_t		*h = talloc_get_type_abort(treq->tconn->conn->h, udp_handle_t);
	rlm_radius_t const 	*inst = h->inst->parent;
	udp_request_t		*u = talloc_get_type_abort(treq->preq, udp_request_t);
	udp_result_t		*r = talloc_get_type_abort(treq->rctx, udp_result_t);

	rad_assert(treq->preq == h->status_u);
	rad_assert(treq->rctx == h->status_r);

	r->treq = NULL;

	/*
	 *	@todo - do other negotiation and signaling.
	 */
	if (h->buffer[0] == FR_CODE_PROTOCOL_ERROR) protocol_error_reply(u, NULL, h);

	if (u->num_replies < inst->num_to_alive) {
		uint32_t msec = fr_time_delta_to_msec(u->retry.next - now);

		/*
		 *	Leave the timer in place.  This timer is BOTH when we
		 *	give up on the current status check, AND when we send
		 *	the next status check.
		 */
		DEBUG("Received %d / %u replies for status check, on connection - %s",
		      u->num_replies, inst->num_to_alive, h->name);
		DEBUG("Next status check packet will be in %u.%03us", msec / 1000, msec % 1000);

		/*
		 *	If we're retransmitting, leave the ID alone.
		 *	Otherwise delete it, so that the packet can be
		 *	re-encoded.
		 */
		if (!u->can_retransmit && u->rr) (void) radius_track_delete(&u->rr);

		/*
		 *	Set the timer for the next retransmit.
		 */
		if (fr_event_timer_at(h, h->thread->el, &u->ev, u->retry.next, status_check_next, treq->tconn) < 0) {
			fr_trunk_connection_signal_reconnect(treq->tconn, FR_CONNECTION_FAILED);
		}
		return;
	}

	DEBUG("Received enough replies to status check, marking connection as active - %s", h->name);

	/*
	 *	Set the "last idle" time to now, so that we don't
	 *	restart zombie_period until sufficient time has
	 *	passed.
	 */
	h->last_idle = fr_time();

	/*
	 *	Reset retry interval and retransmission counters
	 */
	status_check_reset(h, u);
	fr_trunk_connection_signal_active(treq->tconn);
}

static void request_demux(fr_trunk_connection_t *tconn, fr_connection_t *conn, UNUSED void *uctx)
{
	udp_handle_t		*h = talloc_get_type_abort(conn->h, udp_handle_t);;

	DEBUG3("%s - Reading data for connection %s", h->module_name, h->name);

	while (true) {
		ssize_t			slen;

		fr_trunk_request_t	*treq;
		REQUEST			*request;
		udp_request_t		*u;
		udp_result_t		*r;
		radius_track_entry_t	*rr;
		decode_fail_t		reason;
		uint8_t			code = 0;
		VALUE_PAIR		*reply = NULL;

		fr_time_t		now;

		/*
		 *	Drain the socket of all packets.  If we're busy, this
		 *	saves a round through the event loop.  If we're not
		 *	busy, a few extra system calls don't matter.
		 */
		slen = read(h->fd, h->buffer, h->buflen);
		if (slen == 0) return;

		if (slen < 0) {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) return;

			ERROR("%s - %s failed reading response from socket: %s",
			      __FUNCTION__, h->module_name, fr_syserror(errno));
			fr_trunk_connection_signal_reconnect(tconn, FR_CONNECTION_FAILED);
			return;
		}

		if (slen < RADIUS_HEADER_LENGTH) {
			ERROR("%s - Packet too short, expected at least %zu bytes got %zd bytes",
			      h->module_name, (size_t)RADIUS_HEADER_LENGTH, slen);
			continue;
		}

		/*
		 *	Note that we don't care about packet codes.  All
		 *	packet codes share the same ID space.
		 */
		rr = radius_track_find(h->tt, h->buffer[1], NULL);
		if (!rr) {
			WARN("%s - Ignoring reply with ID %i that arrived too late",
			     h->module_name, h->buffer[1]);
			continue;
		}

		treq = talloc_get_type_abort(rr->rctx, fr_trunk_request_t);
		request = treq->request;
		rad_assert(request != NULL);
		u = talloc_get_type_abort(treq->preq, udp_request_t);
		r = talloc_get_type_abort(treq->rctx, udp_result_t);

		/*
		 *	Validate and decode the incoming packet
		 */
		reason = decode(request->reply, &reply, &code, h, request, u, rr->vector, h->buffer, (size_t)slen);
		if (reason != DECODE_FAIL_NONE) {
			RWDEBUG("Ignoring invalid response");
			continue;
		}

		/*
		 *	Only valid packets are processed
		 *	Otherwise an attacker could perform
		 *	a DoS attack against the proxying servers
		 *	by sending fake responses for upstream
		 *	servers.
		 */
		h->last_reply = now = fr_time();

		/*
		 *	Status-Server can have any reply code, we don't care
		 *	what it is.  So long as it's signed properly, we
		 *	accept it.  This flexibility is because we don't
		 *	expose Status-Server to the admins.  It's only used by
		 *	this module for internal signalling.
		 */
		if (u == h->status_u) {
			fr_pair_list_free(&reply);	/* Probably want to pass this to status_check_reply? */
			status_check_reply(treq, now);
			fr_trunk_request_signal_complete(treq);
			continue;
		}

		/*
		 *	Disable the response timer, status_check_reply
		 *	does this selectively for status-check packets.
		 */
		(void)fr_event_timer_delete(&u->ev);

		/*
		 *	Clear the original request buffer
		 */
		udp_request_clear(h, u, now);

		/*
		 *	Handle any state changes, etc. needed by receiving a
		 *	Protocol-Error reply packet.
		 *
		 *	Protocol-Error is permitted as a reply to any
		 *	packet.
		 */
		switch (code) {
		case FR_CODE_PROTOCOL_ERROR:
			protocol_error_reply(u, r, h);
			break;

		default:
			break;
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
		switch (u->code) {
		case FR_CODE_ACCESS_REQUEST:
		case FR_CODE_ACCESS_CHALLENGE:
		{
			VALUE_PAIR	*vp;

			vp = fr_pair_find_by_da(request->reply->vps, attr_packet_type, TAG_ANY);
			if (!vp) {
				MEM(vp = fr_pair_afrom_da(request->reply, attr_packet_type));
				vp->vp_uint32 = FR_CODE_ACCESS_CHALLENGE;
				fr_pair_add(&request->reply->vps, vp);
			}
		}
			break;

		default:
			break;
		}

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
			VALUE_PAIR *vp;

			fr_pair_delete_by_da(&reply, attr_message_authenticator);

			MEM(vp = fr_pair_afrom_da(request->reply, attr_message_authenticator));
			(void) fr_pair_value_memcpy(vp, (uint8_t const *) "", 1, false);
			fr_pair_add(&request->reply->vps, vp);
		}

		treq->request->reply->code = code;
		r->rcode = radius_code_to_rcode[code];
		fr_pair_add(&request->reply->vps, reply);
		fr_trunk_request_signal_complete(treq);
	}
}

/** Remove the request from any tracking structures
 *
 * Frees encoded packets if the request is being moved to a new connection
 */
static void request_cancel(fr_connection_t *conn, void *preq_to_reset,
			   fr_trunk_cancel_reason_t reason, UNUSED void *uctx)
{
	udp_request_t	*u = talloc_get_type_abort(preq_to_reset, udp_request_t);
	udp_handle_t	*h = talloc_get_type_abort(conn->h, udp_handle_t);

	/*
	 *	Delete the request_timeout
	 *
	 *	Note: There might not be a request timeout
	 *      set in the case where the request was
	 *	queued for sendmmsg but never actually
	 *	sent.
	 */
	if (u->ev) (void) fr_event_timer_delete(&u->ev);

	switch (reason) {
	/*
	 *	The request is being terminated, and will
	 *	soon be freed.  Let the request_fail function
	 *	handle any cleanup required.
	 */
	case FR_TRUNK_CANCEL_REASON_SIGNAL:
		if (u->rr) (void) radius_track_delete(&u->rr);
		break;

	case FR_TRUNK_CANCEL_REASON_NONE:
		break;

	/*
	 *	Request has been requeued on the same
	 *	connection due to timeout or DUP signal.  We
	 *	keep the same packet to avoid re-encoding it.
	 */
	case FR_TRUNK_CANCEL_REASON_REQUEUE:
		if (!u->can_retransmit) (void) radius_track_delete(&u->rr);
		break;

	/*
	 *	Request is moving to a different connection,
	 *	for internal trunk reasons.  i.e. the old
	 *	connection is closing.
	 */
	case FR_TRUNK_CANCEL_REASON_MOVE:
		udp_request_clear(h, u, 0);
		if (u->packet) TALLOC_FREE(u->packet);

		u->num_replies = 0;
		break;
	}
}

/** Write out a canned failure and resume the request
 *
 */
static void request_fail(REQUEST *request, void *preq, void *rctx, UNUSED void *uctx)
{
	udp_result_t		*r = talloc_get_type_abort(rctx, udp_result_t);
	udp_request_t		*u = talloc_get_type_abort(preq, udp_request_t);

	if (u->status_check) return;

	r->rcode = RLM_MODULE_FAIL;

	unlang_interpret_resumable(request);
}

/** Mark the request as resumable
 *
 */
static void request_complete(REQUEST *request, void *preq, UNUSED void *rctx, UNUSED void *uctx)
{
	udp_request_t *u = talloc_get_type_abort(preq, udp_request_t);

	/*
	 *	Status checks don't run.
	 */
	if (u->status_check) return;

	unlang_interpret_resumable(request);
}

/** Explicitly free resources associated with the protocol request
 *
 */
static void request_free(UNUSED REQUEST *request, void *preq_to_free, UNUSED void *uctx)
{
	udp_request_t		*u = talloc_get_type_abort(preq_to_free, udp_request_t);

	rad_assert(u->rr == NULL);

	if (u->packet) TALLOC_FREE(u->packet);

	/*
	 *	Don't free status check packets.
	 */
	if (u->status_check) return;

	talloc_free(u);
}

/** Resume execution of the request, returning the rcode set during trunk execution
 *
 */
static rlm_rcode_t mod_resume(UNUSED void *instance, UNUSED void *thread, UNUSED REQUEST *request, void *rctx)
{
	udp_result_t	*r = talloc_get_type_abort(rctx, udp_result_t);
	rlm_rcode_t	rcode = r->rcode;

	talloc_free(rctx);

	return rcode;
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
		talloc_free(rctx);	/* Should be freed soon anyway, but better to be explicit */
		return;

	/*
	 *	Requeue the request on the same connection
	 *      causing a "retransmission" if the request
	 *	has already been sent out.
	 */
	case FR_SIGNAL_DUP:
		check_for_zombie(t->el, r->treq->tconn, 0);
		fr_trunk_request_requeue(r->treq);
		return;

	default:
		return;
	}
}

/** Free a udp_request_t
 */
static int _udp_request_free(udp_request_t *u)
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

	if (fr_trunk_request_enqueue(&treq, t->trunk, request, u, r) < 0) {
		rad_assert(!u->rr && !u->packet);	/* Should not have been fed to the muxer */
		fr_trunk_request_free(treq);		/* Return to the free list */
		talloc_free(r);
		return RLM_MODULE_FAIL;
	}

	r->treq = treq;	/* Remember for signalling purposes */
	talloc_set_destructor(u, _udp_request_free);

	*rctx_out = r;

	return RLM_MODULE_YIELD;
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
						.request_fail = request_fail,
						.request_cancel = request_cancel,
						.request_free = request_free
					};

	static fr_trunk_io_funcs_t	io_funcs_replicate = {
						.connection_alloc = thread_conn_alloc,
						.connection_notify = thread_conn_notify_replicate,
						.request_prioritise = request_prioritise,
						.request_mux = request_mux_replicate,
						.request_complete = request_complete,
						.request_fail = request_fail,
						.request_free = request_free
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

/** Instantiate the module
 *
 * Instantiate I/O and type submodules.
 *
 * @param[in] instance	data for this module
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
	 *	Always need at least one mmsgvec
	 */
	if (inst->max_send_coalesce == 0) inst->max_send_coalesce = 1;

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

	/*
	 *	Clamp max_packet_size first before checking recv_buff and send_buff
	 */
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, 64);
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65535);

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
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_radius_udp_t *inst = talloc_get_type_abort(instance, rlm_radius_udp_t);

	(void) talloc_set_type(inst, rlm_radius_udp_t);
	inst->config = conf;

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
	.resume			= mod_resume,
};
