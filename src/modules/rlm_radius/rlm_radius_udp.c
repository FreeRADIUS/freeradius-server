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
typedef struct rlm_radius_udp_t {
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
typedef struct rlm_radius_udp_thread_t {
	rlm_radius_udp_t	*inst;			//!< IO submodule instance.
	fr_event_list_t		*el;			//!< Event list.

	fr_heap_t		*queued;		//!< Queued requests for some new connection.

	fr_heap_t		*active;   		//!< Active connections.
	fr_dlist_head_t		blocked;      		//!< blocked connections, waiting for writable
	fr_dlist_head_t		full;      		//!< Full connections.
	fr_dlist_head_t		zombie;      		//!< Zombie connections.
	fr_dlist_head_t		opening;      		//!< Opening connections.
} rlm_radius_udp_thread_t;

typedef enum rlm_radius_udp_connection_state_t {
	CONN_INIT = 0,					//!< Configured but not started.
	CONN_OPENING,					//!< Trying to connect.
	CONN_ACTIVE,					//!< has free IDs
	CONN_BLOCKED,					//!< blocked, but can't write to the socket
	CONN_FULL,					//!< Live, but has no more IDs to use.
	CONN_ZOMBIE,					//!< Has had a retransmit timeout.
} rlm_radius_udp_connection_state_t;

typedef struct rlm_radius_udp_request_t rlm_radius_udp_request_t;

/** Represents a connection to an external RADIUS server
 *
 */
typedef struct rlm_radius_udp_connection_t {
	rlm_radius_udp_t const	*inst;			//!< Our module instance.
	rlm_radius_udp_thread_t *thread;       		//!< Our thread-specific data.
	fr_connection_t		*conn;			//!< Connection to our destination.
	char const     		*name;			//!< From IP PORT to IP PORT.

	fr_dlist_t		entry;			//!< In the linked list of connections.
	int32_t			heap_id;		//!< For the active heap.
	rlm_radius_udp_connection_state_t state;	//!< State of the connection.

	fr_event_timer_t const	*idle_ev;		//!< Idle timeout event.
	struct timeval		idle_timeout;		//!< When the idle timeout will fire.

	struct timeval		mrs_time;		//!< Most recent sent time which had a reply.
	struct timeval		last_reply;		//!< When we last received a reply.

	fr_event_timer_t const	*zombie_ev;		//!< Zombie timeout.
	struct timeval		zombie_start;		//!< When the zombie period started.

	fr_dlist_head_t		sent;			//!< List of sent packets.

	uint32_t		max_packet_size;	//!< Our max packet size. may be different from the parent.
	int			fd;			//!< File descriptor.

	fr_ipaddr_t		dst_ipaddr;		//!< IP of the home server. stupid 'const' issues.
	uint16_t		dst_port;		//!< Port of the home server.
	fr_ipaddr_t		src_ipaddr;		//!< Our source IP.
	uint16_t	       	src_port;		//!< Our source port.

	uint8_t			*buffer;		//!< Receive buffer.
	size_t			buflen;			//!< Receive buffer length.

	rlm_radius_udp_request_t *status_u;    		//!< For Status-Server checks.

	rlm_radius_id_t		*id;			//!< RADIUS ID tracking structure.
} rlm_radius_udp_connection_t;


typedef enum rlm_radius_request_state_t {
	PACKET_STATE_INIT = 0,
	PACKET_STATE_THREAD,				//!< in the thread queue
	PACKET_STATE_SENT,				//!< in the connection "sent" heap
	PACKET_STATE_RESUMABLE,      			//!< timed out, or received a reply
	PACKET_STATE_FINISHED,				//!< and done
} rlm_radius_request_state_t;


/** An ongoing RADIUS request
 *
 */
struct rlm_radius_udp_request_t {
	rlm_radius_request_state_t state;		//!< state of this request

	fr_dlist_t		entry;			//!< in the connection list of packets.
	int32_t			heap_id;		//!< for the "to be sent" queue.

	VALUE_PAIR		*extra;			//!< VPs for debugging, like Proxy-State.

	uint8_t			*acct_delay_time;	//!< in the encoded packet.
	uint32_t		initial_delay_time;	//!< Initial value of Acct-Delay-Time.
	bool			manual_delay_time;	//!< Whether or not we manually added an Acct-Delay-Time.
	bool			yielded;		//!< whether it yielded

	int			code;			//!< Packet code.
	rlm_radius_udp_connection_t	*c;		//!< The connection state machine.
	rlm_radius_udp_thread_t *thread;		//!< the thread data for this request
	rlm_radius_link_t	*link;			//!< More link stuff.
	rlm_radius_request_t	*rr;			//!< ID tracking, resend count, etc.

	rlm_radius_retransmit_t timer;			//!< retransmission data structures

	uint8_t			*packet;		//!< Packet we write to the network.
	size_t			packet_len;		//!< Length of the packet.
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

static fr_dict_t *dict_radius;

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
	{ NULL }
};

static void conn_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, int fd_errno, void *uctx);
static void conn_read(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx);
static void conn_writable(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx);
static int conn_write(rlm_radius_udp_connection_t *c, rlm_radius_udp_request_t *u);

static int conn_cmp(void const *one, void const *two)
{
	rlm_radius_udp_connection_t const *a = talloc_get_type_abort_const(one, rlm_radius_udp_connection_t);
	rlm_radius_udp_connection_t const *b = talloc_get_type_abort_const(two, rlm_radius_udp_connection_t);

	if (timercmp(&a->mrs_time, &b->mrs_time, <)) return -1;
	if (timercmp(&a->mrs_time, &b->mrs_time, >)) return +1;

	if (a->id->num_free < b->id->num_free) return -1;
	if (a->id->num_free > b->id->num_free) return +1;

	return 0;
}


/** Compare two packets in the "to be sent" queue.
 *
 *  Status-Server packets are always sorted before other packets, by
 *  virtue of request->async->recv_time always being zero.
 */
static int queue_cmp(void const *one, void const *two)
{
	rlm_radius_udp_request_t const *a = one;
	rlm_radius_udp_request_t const *b = two;

	if (a->link->request->async->recv_time < b->link->request->async->recv_time) return -1;
	if (a->link->request->async->recv_time > b->link->request->async->recv_time) return +1;

	return 0;
}


/** Close a socket due to idle timeout
 *
 */
static void conn_idle_timeout(UNUSED fr_event_list_t *el, UNUSED struct timeval *now, void *uctx)
{
	rlm_radius_udp_connection_t *c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);

	DEBUG("%s - Idle timeout for connection %s", c->inst->parent->name, c->name);

	talloc_free(c);
}


/** Check if the connection is idle.
 *
 *  A connection is idle if it hasn't sent or recieved a packet in a
 *  while.  Note that "no response to packet" does NOT set the idle
 *  timeout.
 */
static void conn_check_idle(rlm_radius_udp_connection_t *c)
{
	struct timeval when;

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

	gettimeofday(&when, NULL);
	when.tv_usec += c->inst->parent->idle_timeout.tv_usec;
	when.tv_sec += when.tv_usec / USEC;
	when.tv_usec %= USEC;

	when.tv_sec += c->inst->parent->idle_timeout.tv_sec;
	when.tv_sec += 1;

	if (timercmp(&when, &c->idle_timeout, >)) {
		when.tv_sec--;
		c->idle_timeout = when;

		DEBUG("%s - Setting idle timeout to +%pV for connection %s",
		      c->inst->parent->name, fr_box_timeval(c->inst->parent->idle_timeout), c->name);
		if (fr_event_timer_insert(c, c->thread->el, &c->idle_ev, &c->idle_timeout, conn_idle_timeout, c) < 0) {
			ERROR("%s - Failed inserting idle timeout for connection %s",
			      c->inst->parent->name, c->name);
		}
	}
}


/** Set the socket to "nothing to write"
 *
 *  But keep the read event open, just in case the other end sends us
 *  data.  That way we can process it.
 *
 * @param[in] c		Connection data structure
 */
static void fd_idle(rlm_radius_udp_connection_t *c)
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
static void fd_active(rlm_radius_udp_connection_t *c)
{
	DEBUG3("%s - Activating connection %s", c->inst->parent->name, c->name);

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


/** Mark a connection "zombie" due to zombie timeout.
 *
 */
static void conn_zombie_timeout(UNUSED fr_event_list_t *el, UNUSED struct timeval *now, void *uctx)
{
	rlm_radius_udp_connection_t *c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);

	ERROR("%s - Zombie timeout for connection %s", c->inst->parent->name, c->name);

	/*
	 *	If we have Status-Server packets, start sending those now.
	 */
	if (c->status_u) {
		int rcode;
		rlm_radius_udp_request_t *u = c->status_u;

		/*
		 *	Re-initialize the timers.
		 */
		u->timer.count = 0;

		rcode = conn_write(c, u);
		if (rcode < 0) {
			DEBUG2("%s - Failed writing status check, closing connection %s",
			       c->inst->parent->name, c->name);
			talloc_free(c);
			return;
		}

		/*
		 *	It returned EWOULDBLOCK.  Wait for the
		 *	retransmission timer to fire.
		 */
		if (rcode == 0) {
			DEBUG2("%s - EWOULDBLOCK for status check on connection %s",
			       c->inst->parent->name, c->name);
			return;
		}

		/*
		 *	Note that the status check packets not in any
		 *	"sent" list
		 */
		if (rcode == 1) {
			u->state = PACKET_STATE_SENT;
			u->c = c;
			return;
		}

		/*
		 *	Status check packets are never replicated.
		 */
		rad_assert(0 == 1);
		return;
	}

	DEBUG2("%s - No status_check response, closing connection %s", c->inst->parent->name, c->name);

	talloc_free(c);
}


/** Connection errored
 *
 */
static void conn_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, int fd_errno, void *uctx)
{
	rlm_radius_udp_connection_t *c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);

	ERROR("%s - Connection failed: %s - %s", c->inst->parent->name, fr_syserror(fd_errno), c->name);

	/*
	 *	Something bad happened... Fix it...
	 */
	fr_connection_signal_reconnect(c->conn);
}


static void state_transition(rlm_radius_udp_request_t *u, rlm_radius_request_state_t state)
{
	if (u->state == state) return;

	rad_assert(!u->c || (u != u->c->status_u));

	switch (u->state) {
	case PACKET_STATE_INIT:
		rad_assert(state == PACKET_STATE_THREAD);
		break;

	case PACKET_STATE_THREAD:
		rad_assert(u->heap_id >= 0);
		(void) fr_heap_extract(u->thread->queued, u);
		break;

	case PACKET_STATE_SENT:
		rad_assert(u->rr != NULL);
		rad_assert(u->c != NULL);
		(void) rr_track_delete(u->c->id, u->rr);
		fr_dlist_remove(&u->c->sent, u);
		u->rr = NULL;
		u->c = NULL;
		break;

	case PACKET_STATE_RESUMABLE:
		rad_assert(state == PACKET_STATE_FINISHED);
		break;

	default:
		rad_assert(0 == 1);
		break;
	}

	u->state = state;
	switch (u->state) {
	case PACKET_STATE_THREAD:
		rad_assert(u->rr == NULL);
		rad_assert(u->c == NULL);
		rad_assert(u->heap_id < 0);
		fr_heap_insert(u->thread->queued, u);
		break;

	case PACKET_STATE_SENT:
		rad_assert(u->rr != NULL);
		rad_assert(u->c != NULL);
		fr_dlist_insert_tail(&u->c->sent, u);
		break;

	case PACKET_STATE_RESUMABLE:
		rad_assert(u->rr == NULL);
		rad_assert(u->c == NULL);
		if (u->timer.ev) (void) fr_event_timer_delete(u->thread->el, &u->timer.ev);
		if (u->yielded) unlang_resumable(u->link->request);
		break;

	case PACKET_STATE_FINISHED:
		rad_assert(u->rr == NULL);
		rad_assert(u->c == NULL);
		if (u->timer.ev) (void) fr_event_timer_delete(u->thread->el, &u->timer.ev);
		break;

	default:
		rad_assert(0 == 1);
		break;
	}
}

static void mod_finished_request(rlm_radius_udp_connection_t *c, rlm_radius_udp_request_t *u)
{
	rad_assert(u->state != PACKET_STATE_FINISHED);

	/*
	 *	Delete the tracking table entry, and remove the
	 *	request from the "sent" list for this connection.
	 */
	if (c) {
		/*
		 *	Status check packets are never removed from
		 *	the connection, and their IDs are never
		 *	deallocated.
		 */
		if (u == c->status_u) {
			u->state = PACKET_STATE_INIT;
			return;
		}

		rad_assert(u->state == PACKET_STATE_SENT);
		state_transition(u, PACKET_STATE_RESUMABLE);

		conn_check_idle(c);

	} else {
		rad_assert(u->state == PACKET_STATE_THREAD);
		state_transition(u, PACKET_STATE_RESUMABLE);
	}
}

/** Turn a reply code into a module rcode;
 *
 */
static rlm_rcode_t code2rcode[FR_MAX_PACKET_CODE] = {
	[FR_CODE_ACCESS_ACCEPT]		= RLM_MODULE_OK,
	[FR_CODE_ACCESS_CHALLENGE]	= RLM_MODULE_UPDATED,
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
static FR_CODE allowed_replies[FR_MAX_PACKET_CODE] = {
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
static void protocol_error_reply(rlm_radius_udp_connection_t *c, REQUEST *request)
{
	VALUE_PAIR *vp, *error_cause;

	error_cause = fr_pair_find_by_da(request->reply->vps, attr_error_cause, TAG_ANY);
	if (!error_cause) return;

	if ((error_cause->vp_uint32 == 601) &&
	    attr_response_length &&
	    ((vp = fr_pair_find_by_da(request->reply->vps, attr_response_length, TAG_ANY)) != NULL)) {

		if (vp->vp_uint32 > c->buflen) {
			request->module = c->inst->parent->name;
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
static void status_check_reply(rlm_radius_udp_connection_t *c, rlm_radius_udp_request_t *u, REQUEST *request)
{
	VALUE_PAIR *vp;

	/*
	 *	Remove all timers associated with the packet.
	 */
	if (u->timer.ev) (void) fr_event_timer_delete(u->thread->el, &u->timer.ev);

	rad_assert(u->state == PACKET_STATE_SENT);
	u->state = PACKET_STATE_INIT;

	if (u->code != FR_CODE_STATUS_SERVER) return;

	/*
	 *	Allow Response-Length in replies to Status-Server
	 *	packets.
	 */
	if (attr_response_length &&
	    ((vp = fr_pair_find_by_da(request->reply->vps, attr_response_length, TAG_ANY)) != NULL)) {
		if (vp->vp_uint32 > c->buflen) {
			request->module = c->inst->parent->name;
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

static void conn_transition(rlm_radius_udp_connection_t *c, rlm_radius_udp_connection_state_t state)
{
	struct timeval when;

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

		gettimeofday(&when, NULL);
		c->zombie_start = when;

		fr_timeval_add(&when, &when, &c->inst->parent->zombie_period);
		WARN("%s - Entering Zombie state - connection %s", c->inst->parent->name, c->name);

		if (fr_event_timer_insert(c, c->thread->el, &c->zombie_ev, &when, conn_zombie_timeout, c) < 0) {
			ERROR("%s - Failed inserting zombie timeout for connection %s",
			      c->inst->parent->name, c->name);
		}
		break;
	}
}


/** Read reply packets.
 *
 */
static void conn_read(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	rlm_radius_udp_connection_t	*c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);
	rlm_radius_request_t		*rr;
	rlm_radius_link_t		*link;
	rlm_radius_udp_request_t	*u;
	int				code;
	decode_fail_t			reason;
	size_t				packet_len;
	ssize_t				data_len;
	REQUEST				*request = NULL;
	uint8_t				original[20];
	bool				reinserted = false;
	bool				activate = false;

	DEBUG3("%s - Reading data for connection %s", c->inst->parent->name, c->name);

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

	/*
	 *	Replicating?  Drain the socket, but ignore all responses.
	 */
	 if (c->inst->replicate) goto redo;

	packet_len = data_len;
	if (!fr_radius_ok(c->buffer, &packet_len, c->inst->parent->max_attributes, false, &reason)) {
		WARN("%s - Ignoring malformed packet", c->inst->parent->name);
		goto redo;
	}

	if (DEBUG_ENABLED3) {
		DEBUG3("%s - Read packet", c->inst->parent->name);
		fr_radius_print_hex(fr_log_fp, c->buffer, packet_len);
	}

	rr = rr_track_find(c->id, c->buffer[1], NULL);
	if (!rr) {
		WARN("%s - Ignoring reply which arrived too late", c->inst->parent->name);
		goto redo;
	}

	link = rr->link;
	u = link->request_io_ctx;
	request = link->request;
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
	rad_assert(u->state == PACKET_STATE_SENT);
	rad_assert(u->c == c);

	/*
	 *	Remember when we last saw a reply.
	 */
	gettimeofday(&c->last_reply, NULL);

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

		if (timercmp(&u->timer.start, &c->mrs_time, >)) {
			(void) fr_heap_extract(c->thread->active, c);
			c->mrs_time = u->timer.start;
			(void) fr_heap_insert(c->thread->active, c);
			reinserted = true;
		}
		break;

	default:
		if (timercmp(&u->timer.start, &c->mrs_time, >)) {
			c->mrs_time = u->timer.start;
		}

		/*
		 *	Transition to active on any one packet.  RFC
		 *	3539 says to wait for N status check
		 *	responses, but we're happy to do it faster.
		 *
		 *	If the connection was FULL, then
		 *	mod_finished_request() will ensure that this
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
		link->rcode = RLM_MODULE_INVALID;

		for (attr = c->buffer + 20;
		     attr < end;
		     attr += attr[1]) {
			/*
			 *	Must be an extended attribute.
			 */
			if (attr[0] != (uint8_t)attr_extended_attribute_1->attr) continue;

			/*
			 *	ATTR + LEN + EXT-Attr + uint32
			 */
			if (attr[1] != 7) continue;

			/*
			 *	See if there's an original packet code.
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
			 *	This has to match.  We don't currently
			 *	multiplex different codes with the
			 *	same IDs on connections.  So this
			 *	check is just for RFC compliance, and
			 *	for sanity.
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
			link->rcode = RLM_MODULE_FAIL;
			break;
		}

		/*
		 *	Decode and print the reply, so that the caller
		 *	can do something with it.
		 */
		goto decode_reply;

	} else if (!code || (code >= FR_MAX_PACKET_CODE)) {
		REDEBUG("Unknown reply code %d", code);
		link->rcode = RLM_MODULE_INVALID;

		/*
		 *	Different debug message.  The packet is within
		 *	the known bounds, but is one we don't handle.
		 */
	} else if (!allowed_replies[code]) {
		REDEBUG("%s packet received invalid reply code %s", fr_packet_codes[u->code], fr_packet_codes[code]);
		link->rcode = RLM_MODULE_INVALID;


		/*
		 *	Status-Server packets can accept all possible replies.
		 */
	} else if (u->code == FR_CODE_STATUS_SERVER) {
		link->rcode = code2rcode[code];

		/*
		 *	The reply is a known code, but isn't
		 *	appropriate for the request packet type.
		 */
	} else if (allowed_replies[code] != (FR_CODE) u->code) {
		rad_assert(request != NULL);

		REDEBUG("Invalid reply code %s to request packet %s",
		        fr_packet_codes[code], fr_packet_codes[u->code]);
		link->rcode = RLM_MODULE_INVALID;

		/*
		 *	<whew>, it's OK.  Choose the correct module
		 *	rcode based on the reply code.  This is either
		 *	OK for an ACK, or FAIL for a NAK.
		 */
	} else {
		VALUE_PAIR *vp;

		link->rcode = code2rcode[code];

	decode_reply:
		vp = NULL;

		/*
		 *	Decode the attributes, in the context of the reply.
		 */
		if (fr_radius_decode(request->reply, c->buffer, packet_len, original,
				     c->inst->secret, 0, &vp) < 0) {
			REDEBUG("Failed decoding attributes for packet");
			fr_pair_list_free(&vp);
			link->rcode = RLM_MODULE_INVALID;
			goto done;
		}

		RDEBUG("Received %s ID %d length %ld reply packet on connection %s",
		       fr_packet_codes[code], code, packet_len, c->name);
		log_request_pair_list(L_DBG_LVL_2, request, vp, NULL);

		/*
		 *	@todo - make this programmatic?  i.e. run a
		 *	separate policy which updates the reply.
		 *
		 *	This is why I wanted to have "recv
		 *	Access-Accept" policies...  so the user could
		 *	programatically decide which attributes to add.
		 */

		request->reply->code = code;
		fr_pair_add(&request->reply->vps, vp);

		/*
		 *	Run hard-coded policies on Protocol-Error
		 */
		if (code == FR_CODE_PROTOCOL_ERROR) protocol_error_reply(c, request);
	}

done:
	rad_assert(request != NULL);
	rad_assert(request->reply != NULL);

	/*
	 *	We received the response to a Status-Server
	 *	check.
	 */
	if (u == c->status_u) {
		status_check_reply(c, u, request);

	} else {
		rad_assert(u->c == c);
		rad_assert(u->rr != NULL);
		rad_assert(u->state == PACKET_STATE_SENT);

		/*
		 *	It's a normal request.  Mark it as finished.
		 */
		mod_finished_request(c, u);
	}

	goto redo;
}

static int retransmit_packet(rlm_radius_udp_request_t *u, struct timeval *now)
{
	bool				resign = false;
	int				rcode;
	rlm_radius_udp_connection_t	*c = u->c;
	REQUEST				*request = u->link->request;

	rad_assert(u->packet != NULL);
	rad_assert(u->packet_len >= 20);

	/*
	 *	RADIUS layer fixups for Accounting-Request packets.
	 *
	 *	Note that we don't change the ID.  We can claim that
	 *	we randomly chose the same one again. :(
	 *
	 *	@todo - try to change the ID.
	 */
	if ((u->code == FR_CODE_ACCOUNTING_REQUEST) &&
	    (u != c->status_u)) {
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
			struct timeval diff;

			fr_timeval_subtract(&diff, now, &u->timer.start);
			delay = u->initial_delay_time + diff.tv_sec;
			delay = htonl(delay);
			memcpy(u->acct_delay_time, &delay, 4);

			resign = true;
		}
	}

	/*
	 *	Update the Event-Timestamp for status packets.
	 */
	if (u == c->status_u) {
		uint32_t event_time;
		uint8_t *attr, *end;

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

			resign = true;
			break;
		}
	}

	/*
	 *	Recalculate the packet signature again.
	 */
	if (resign) {
		if (fr_radius_sign(u->packet, NULL, (uint8_t const *) c->inst->secret,
				   strlen(c->inst->secret)) < 0) {
			REDEBUG("Failed re-signing packet");
			return -1;
		}
		memcpy(u->rr->vector, u->packet + 4, AUTH_VECTOR_LEN);
	}

	RDEBUG("Retransmitting request (%d/%d).  Expecting response within %d.%06ds",
	       u->timer.count, u->timer.retry->mrc, u->timer.rt / USEC, u->timer.rt % USEC);

	/*
	 *	Debug the packet again, including any extra
	 *	Proxy-State or Message-Authenticator we added.
	 */
	RDEBUG("%s %s ID %d length %ld over connection %s",
	       (c->status_u != u) ? "sending" : "status_check",
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
static void response_timeout(fr_event_list_t *el, struct timeval *now, void *uctx)
{
	int				rcode;
	rlm_radius_udp_request_t	*u = uctx;
	rlm_radius_udp_connection_t	*c = u->c;
	REQUEST				*request;

	rad_assert(u->timer.ev == NULL);

	request = u->link->request;

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
			if (u == c->status_u) {
				REDEBUG("No response to status checks, closing connection %s", c->name);
				talloc_free(c);
				return;
			}

			REDEBUG("No response to proxied request ID %d on connection %s",
				u->rr->id, c->name);
			conn_transition(c, CONN_ZOMBIE);

		} else {
			REDEBUG("No response to proxied request");
		}

		mod_finished_request(c, u);
		return;
	}

	/*
	 *	Insert the next retransmission timer.
	 */
	if (fr_event_timer_insert(u, el, &u->timer.ev, &u->timer.next, response_timeout, u) < 0) {
		RDEBUG("Failed inserting retransmission timer");
		mod_finished_request(c, u);
		return;
	}

	/*
	 *	The timer hit, but there was no connection for the
	 *	packet.  Try to grab an active connection.  If we do
	 *	have an active connection
	 */
	if (!c) {
	get_new_connection:
		rad_assert(u->state == PACKET_STATE_THREAD);
		c = fr_heap_peek(u->thread->active);
		if (!c) {
			RDEBUG("No available connections for retransmission.  Waiting %d.%06ds for retry",
			       u->timer.rt / USEC, u->timer.rt % USEC);
			return;
		}

		/*
		 *	We just grabbed a new connection, go allocate
		 *	an ID for it.
		 */
		u->rr = rr_track_alloc(c->id, u->link->request, u->code, u->link, &u->timer);
		if (!u->rr) {
			conn_transition(c, CONN_FULL);
			goto get_new_connection;
		}

		/*
		 *	We have a connection, transition to "sent".
		 */
		u->c = c;
		state_transition(u, PACKET_STATE_SENT);
	}

	rad_assert(u->state == PACKET_STATE_SENT);

	/*
	 *	If we can retransmit it, do so.  Otherwise, it will
	 *	get retransmitted when we get around to polling
	 *	t->queued
	 */
	RDEBUG("Retransmitting ID %d on connection %s", u->rr->id, c->name);
	rcode = retransmit_packet(u, now);
	if (rcode < 0) {
		RDEBUG("Failed retransmitting packet for connection %s", c->name);
		state_transition(u, PACKET_STATE_THREAD);
		talloc_free(c);
		goto get_new_connection;
	}

	/*
	 *	EWOULDBLOCK, move the connection to blocked, and move
	 *	the packet back to the thread queue, and try to send
	 *	the packet on yet another connection.
	 */
	if (rcode == 0) {
		RDEBUG("Blocked writing for connection %s", c->name);
		state_transition(u, PACKET_STATE_THREAD);
		conn_transition(c, CONN_BLOCKED);
		goto get_new_connection;
	}

	/* else we successfully managed to write the packet to the connection */
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
static int conn_write(rlm_radius_udp_connection_t *c, rlm_radius_udp_request_t *u)
{
	int			rcode;
	size_t			buflen;
	ssize_t			packet_len;
	uint8_t			*msg = NULL;
	bool			require_ma = false;
	int			proxy_state = 6;
	REQUEST			*request;
	char const		*module_name;

	rad_assert(c->inst->parent->allowed[u->code] || (u == c->status_u));
	if (c->idle_ev) (void) fr_event_timer_delete(c->thread->el, &c->idle_ev);

	request = u->link->request;

	/*
	 *	Make sure that we print out the actual encoded value
	 *	of the Message-Authenticator attribute.  If the caller
	 *	asked for one, delete theirs (which has a bad value),
	 *	and remember to add one manually when we encode the
	 *	packet.  This is the only editing we do on the input
	 *	request.
	 */
	if (fr_pair_find_by_da(request->packet->vps, attr_message_authenticator, TAG_ANY)) {
		require_ma = true;
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

		require_ma = true;

		base = fr_rand();
		for (i = 0; i < AUTH_VECTOR_LEN; i += sizeof(uint32_t)) {
			hash = fr_rand() ^ base;
			memcpy(c->buffer + 4 + i, &hash, sizeof(hash));
		}
	}

	/*
	 *	Every status check packet has an Event-Timestamp.  The
	 *	timestamp changes every time we send a packet.  Status
	 *	check packets never have Proxy-State, because we
	 *	generate them, and they're not proxied.
	 */
	if (u == c->status_u) {
		VALUE_PAIR *vp;

		proxy_state = 0;
		vp = fr_pair_find_by_da(request->packet->vps, attr_event_timestamp, TAG_ANY);
		if (vp) vp->vp_uint32 = time(NULL);
	}

	/*
	 *	Leave room for the Message-Authenticator.
	 */
	if (require_ma) {
		buflen = c->buflen - 18;
	} else {
		buflen = c->buflen;
	}

	/*
	 *	Encode it, leaving room for Proxy-State, too.
	 */
	packet_len = fr_radius_encode(c->buffer, buflen - proxy_state, NULL,
				      c->inst->secret, 0, u->code, u->rr->id,
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
		int		hdr_len;
		VALUE_PAIR	*vp;

		rad_assert((size_t) (packet_len + 6) <= c->buflen);

		attr[0] = (uint8_t)attr_proxy_state->attr;
		attr[1] = 6;
		memcpy(attr + 2, &c->inst->parent->proxy_state, 4);

		hdr_len = (c->buffer[2] << 8) | (c->buffer[3]);
		hdr_len += 6;
		c->buffer[2] = (hdr_len >> 8) & 0xff;
		c->buffer[3] = hdr_len & 0xff;

		vp = fr_pair_afrom_da(u, attr_proxy_state);
		fr_pair_value_memcpy(vp, attr + 2, 4);
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
	if (require_ma &&
	    ((size_t) (packet_len + 18) <= c->buflen)) {
		int hdr_len;

		msg = c->buffer + packet_len;

		msg[0] = (uint8_t)attr_message_authenticator->attr;
		msg[1] = 18;
		memset(msg + 2, 0, 16);

		hdr_len = (c->buffer[2] << 8) | (c->buffer[3]);
		hdr_len += 18;
		c->buffer[2] = (hdr_len >> 8) & 0xff;
		c->buffer[3] = hdr_len & 0xff;

		packet_len += 18;
	}

	/*
	 *	Ensure that we update the Acct-Delay-Time on
	 *	retransmissions.
	 *
	 *	If the accounting packet doesn't have Acct-Delay-Time,
	 *	then we leave well enough alone.
	 */
	if ((u->code == FR_CODE_ACCOUNTING_REQUEST) &&
	    (u != c->status_u)) {
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

	if (fr_radius_sign(c->buffer, NULL, (uint8_t const *) c->inst->secret,
			   strlen(c->inst->secret)) < 0) {
		request->module = module_name;
		RERROR("Failed signing packet");
		conn_error(c->thread->el, c->fd, 0, errno, c);
		return -1;
	}

	memcpy(u->rr->vector, c->buffer + 4, AUTH_VECTOR_LEN);

	/*
	 *	Print out the actual value of the Message-Authenticator attribute
	 */
	if (msg) {
		VALUE_PAIR *vp;

		vp = fr_pair_afrom_da(u, attr_message_authenticator);
		fr_pair_value_memcpy(vp, msg + 2, 16);
		fr_pair_add(&u->extra, vp);

		RINDENT();
		RDEBUG2("&%pP", vp);
		REXDENT();
	}

	RHEXDUMP(L_DBG_LVL_3, c->buffer, packet_len, "Encoded packet");

	request->module = module_name;

	/*
	 *	Write the packet to the socket.  If it blocks,
	 *	stop dequeueing packets.
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
	 *	responses.  Don't do any retransmission
	 *	timers, etc.
	 *
	 *	Instead, just set the return code to OK, and return.
	 */
	if (c->inst->replicate && (u != c->status_u)) {
		u->link->rcode = RLM_MODULE_OK;
		return 2;
	}

	/*
	 *	Copy the packet in case it needs retransmitting.
	 */
	MEM(u->packet = talloc_memdup(u, c->buffer, packet_len));
	u->packet_len = packet_len;

	/*
	 *	Print out helpful debugging messages for non-status
	 *	checks.
	 */
	if (u != c->status_u) {
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

		return 1;
	}

	/*
	 *	Status-Server only checks.
	 */
	if (u->timer.count == 0) {
		u->link->time_sent = fr_time();
		fr_time_to_timeval(&u->timer.start, u->link->time_sent);

		if (rr_track_start(&u->timer) < 0) {
			RDEBUG("%s - Failed starting retransmit tracking for connection %s",
			       c->inst->parent->name, c->name);
			return -1;
		}

		if (fr_event_timer_insert(u, c->thread->el, &u->timer.ev, &u->timer.next,
					  response_timeout, u) < 0) {
			RDEBUG("%s - Failed starting retransmit tracking for connection %s",
			       c->inst->parent->name, c->name);
			return -1;
		}

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
	rlm_radius_udp_connection_t	*c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);
	rlm_radius_udp_request_t	*u;
	bool				pending = false;
	rlm_radius_udp_connection_state_t prev_state = c->state;
	rlm_radius_udp_connection_t	*next;

	DEBUG3("%s - Writing packets for connection %s", c->inst->parent->name, c->name);

	/*
	 *	Empty the global queue of packets to send.
	 */
	while ((u = fr_heap_peek(c->thread->queued)) != NULL) {
		int rcode;

		u->rr = rr_track_alloc(c->id, u->link->request, u->code, u->link, &u->timer);

		/*
		 *	Can't allocate any more IDs, re-insert the
		 *	packet back onto the main thread queue, and
		 *	stop writing packets.
		 */
		if (!u->rr) {
			pending = true;
			conn_transition(c, CONN_FULL);
			break;
		}

		rad_assert(u->state == PACKET_STATE_THREAD);

		u->c = c;
		state_transition(u, PACKET_STATE_SENT);

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
			state_transition(u, PACKET_STATE_THREAD);
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
			rlm_radius_udp_thread_t *t = c->thread;

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
			state_transition(u, PACKET_STATE_RESUMABLE);
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

/** Shutdown/close a file descriptor
 *
 */
static void _conn_close(int fd, void *uctx)
{
	rlm_radius_udp_connection_t *c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);

	if (c->idle_ev) fr_event_timer_delete(c->thread->el, &c->idle_ev);

	if (shutdown(fd, SHUT_RDWR) < 0) {
		DEBUG3("%s - Failed shutting down connection %s: %s",
		       c->inst->parent->name, c->name, fr_syserror(errno));
	}

	if (close(fd) < 0) {
		DEBUG3("%s - Failed closing connection %s: %s",
		       c->inst->parent->name, c->name, fr_syserror(errno));
	}

	c->fd = -1;

	/*
	 *	Reset our state back to init
	 */
	conn_transition(c, CONN_INIT);

	DEBUG("%s - Connection closed - %s", c->inst->parent->name, c->name);
}

/** Free an rlm_radius_udp_request_t
 *
 *  Unlink the packet from the connection, and remove any tracking
 *  entries.
 */
static int udp_request_free(rlm_radius_udp_request_t *u)
{
	struct timeval when, now;

	state_transition(u, PACKET_STATE_FINISHED);

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

	switch (u->c->state) {
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
		 *	It was alive, but likely no longer..
		 */
	case CONN_ACTIVE:
	case CONN_FULL:
	case CONN_BLOCKED:
		break;
	}

	/*
	 *	Check if we can mark the connection as "dead".
	 */
	gettimeofday(&now, NULL);
	when = u->c->last_reply;

	/*
	 *	Use the zombie_period for the timeout.
	 *
	 *	Note that we do this check on every packet, which is a
	 *	bit annoying, but oh well.
	 */
	fr_timeval_add(&when, &when, &u->c->inst->parent->zombie_period);
	if (timercmp(&when, &now, > )) return 0;

	/*
	 *	The home server hasn't responded in a long time.  Mark
	 *	the connection as "zombie".
	 */
	conn_transition(u->c, CONN_ZOMBIE);

	return 0;
}

/** Free the status-check rlm_radius_udp_request_t
 *
 *  Unlink the packet from the connection, and remove any tracking
 *  entries.
 */
static int status_udp_request_free(rlm_radius_udp_request_t *u)
{
	rlm_radius_udp_connection_t	*c = u->c;

	DEBUG3("%s - Freeing status check ID %d on connection %s", c->inst->parent->name, u->rr->id, c->name);
	c->status_u = NULL;

	/*
	 *	Status check packets are not in any list, but they do
	 *	have an ID allocated.
	 */
	if (u->timer.ev) (void) fr_event_timer_delete(u->thread->el, &u->timer.ev);

	if (u->rr) (void) rr_track_delete(u->c->id, u->rr);
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
	rlm_radius_udp_connection_t	*c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);

	/*
	 *	If the connection was connected when it failed,
	 *	we need to handle any outstanding packers and
	 *	timer events before reconnecting.
	 */
	if (state == FR_CONNECTION_STATE_CONNECTED) {
		rlm_radius_udp_request_t *u;

		/*
		 *	Reset the Status-Server checks.
		 */
		if (c->status_u) {
			u = c->status_u;

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
			state_transition(u, PACKET_STATE_THREAD);
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
	rlm_radius_udp_connection_t	*c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);
	rlm_radius_udp_thread_t		*t = c->thread;

	talloc_const_free(c->name);
	c->name = fr_asprintf(c, "proto udp local %pV port %u remote %pV port %u",
			      fr_box_ipaddr(c->src_ipaddr), c->src_port,
			      fr_box_ipaddr(c->dst_ipaddr), c->dst_port);

	DEBUG("%s - Connection open - %s", c->inst->parent->name, c->name);

	/*
	 *	Connection is "active" now.  i.e. we prefer the newly
	 *	opened connection for sending packets.
	 *
	 *	@todo - connection negotiation via Status-Server
	 */
	gettimeofday(&c->mrs_time, NULL);
	c->last_reply = c->mrs_time;

	/*
	 *	If the connection is open, it must be writable.
	 */
	rad_assert(c->state == CONN_OPENING);
	conn_transition(c, CONN_ACTIVE);

	rad_assert(c->zombie_ev == NULL);
	memset(&c->zombie_start, 0, sizeof(c->zombie_start));
	fr_dlist_init(&c->sent, rlm_radius_udp_request_t, entry);

	/*
	 *	Status-Server checks.  Manually build the packet, and
	 *	all of it's associated glue.
	 */
	if (c->inst->parent->status_check && !c->status_u) {
		rlm_radius_link_t *link;
		rlm_radius_udp_request_t *u;
		REQUEST *request;

		link = talloc_zero(c, rlm_radius_link_t);
		u = talloc_zero(c, rlm_radius_udp_request_t);

		request = request_alloc(link);
		request->async = talloc_zero(request, fr_async_t);
		talloc_const_free(request->name);
		request->name = talloc_strdup(request, c->inst->parent->name);

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
		 *	Initialize the link.  Note that we don't set
		 *	destructors.
		 */
		link->request = request;
		link->request_io_ctx = u;

		/*
		 *	Unitialize the UDP link.
		 */
		u->code = c->inst->parent->status_check;
		request->packet->code = u->code;
		u->c = c;
		u->link = link;
		u->thread = t;

		/*
		 *	Reserve a permanent ID for the packet.  This
		 *	is because we need to be able to send an ID on
		 *	demand.  If the proxied packets use all of the
		 *	IDs, then we can't send a Status-Server check.
		 */
		u->rr = rr_track_alloc(c->id, request, u->code, link, &u->timer);
		if (!u->rr) {
			ERROR("%s - Failed allocating status_check ID for connection %s",
			      c->inst->parent->name, c->name);
			talloc_free(u);
			talloc_free(link);

		} else {
			DEBUG2("%s - Allocated %s ID %u for status checks on connection %s",
			       c->inst->parent->name, fr_packet_codes[u->code], u->rr->id, c->name);
			talloc_set_destructor(u, status_udp_request_free);
			c->status_u = u;
		}
	}

	/*
	 *	Reset the timer, retransmission counters, etc.
	 */
	if (c->status_u) {
		rlm_radius_udp_request_t *u = c->status_u;

		memset(&u->timer, 0, sizeof(u->timer));
		u->timer.retry = &c->inst->parent->retry[u->code];
	}

	/*
	 *	Now that we're open, assume that the connection is
	 *	writable.
	 */
	if (fr_heap_num_elements(t->queued) > 0) conn_writable(c->thread->el, fd, 0, c);

	return FR_CONNECTION_STATE_CONNECTED;
}


/** Initialise a new outbound connection
 *
 * @param[out] fd_out	Where to write the new file descriptor.
 * @param[in] uctx	A #rlm_radius_thread_t.
 */
static fr_connection_state_t _conn_init(int *fd_out, void *uctx)
{
	int				fd;
	rlm_radius_udp_connection_t	*c = talloc_get_type_abort(uctx, rlm_radius_udp_connection_t);

	/*
	 *	Open the outgoing socket.
	 */
	fd = fr_socket_client_udp(&c->src_ipaddr, &c->src_port, &c->dst_ipaddr, c->dst_port, true);
	if (fd < 0) {
		PERROR("%s - Failed opening socket", c->inst->parent->name);
		return FR_CONNECTION_STATE_FAILED;
	}

	/*
	 *	Set the connection name.
	 */
	talloc_const_free(c->name);
	c->name = fr_asprintf(c, "connecting proto udp from %pV to %pV port %u",
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
static int _conn_free(rlm_radius_udp_connection_t *c)
{
	rlm_radius_udp_request_t	*u;
	rlm_radius_udp_thread_t		*t = talloc_get_type_abort(c->thread, rlm_radius_udp_thread_t);

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
		rad_assert(u->state == PACKET_STATE_SENT);
		rad_assert(u->c == c);

		state_transition(u, PACKET_STATE_THREAD);
	}

	if (c->status_u) talloc_free(c->status_u);

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
	case CONN_FULL:
	case CONN_ZOMBIE:
		fr_dlist_remove(&c->thread->blocked, c);
		break;

	case CONN_ACTIVE:
		rad_assert(c->heap_id < 0);
		(void) fr_heap_extract(t->active, c);
		break;
	}

	return 0;
}


/** Allocate a new connection and set it up.
 *
 */
static void conn_alloc(rlm_radius_udp_t *inst, rlm_radius_udp_thread_t *t)
{
	rlm_radius_udp_connection_t	*c;

	c = talloc_zero(t, rlm_radius_udp_connection_t);
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
			   inst->parent->name);
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
		cf_log_err(inst->config, "%s - Failed allocating ID tracking for new connection",
			   inst->parent->name);
		talloc_free(c);
		return;
	}
	fr_dlist_init(&c->sent, rlm_radius_udp_request_t, entry);

	c->conn = fr_connection_alloc(c, t->el, &inst->parent->connection_timeout, &inst->parent->reconnection_delay,
				      _conn_init,
				      _conn_open,
				      _conn_close,
				      inst->parent->name, c);
	if (!c->conn) {
		talloc_free(c);
		cf_log_err(inst->config, "%s - Failed allocating state handler for new connection",
			   inst->parent->name);
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

		if (num_connections >= inst->parent->max_connections) {
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

static rlm_rcode_t mod_push(void *instance, REQUEST *request, rlm_radius_link_t *link, void *thread)
{
	rlm_rcode_t    			rcode = RLM_MODULE_FAIL;
	rlm_radius_udp_t		*inst = talloc_get_type_abort(instance, rlm_radius_udp_t);
	rlm_radius_udp_thread_t		*t = talloc_get_type_abort(thread, rlm_radius_udp_thread_t);
	rlm_radius_udp_request_t	*u = link->request_io_ctx;
	rlm_radius_udp_connection_t	*c;

	rad_assert(request->packet->code > 0);
	rad_assert(request->packet->code < FR_MAX_PACKET_CODE);

	/*
	 *	If configured, and we don't have any active
	 *	connections, fail the request.  This lets "parallel"
	 *	sections finish much more quickly than otherwise.
	 */
	if (inst->parent->no_connection_fail && !fr_heap_num_elements(t->active)) {
		REDEBUG("Failing request due to 'no_connection_fail = true', and there are no active connections");
		return RLM_MODULE_FAIL;
	}

	u->state = PACKET_STATE_INIT;
	u->rr = NULL;
	u->c = NULL;
	u->link = link;
	u->code = request->packet->code;
	u->thread = t;
	u->heap_id = -1;
	u->timer.retry = &inst->parent->retry[u->code];
	fr_dlist_entry_init(&u->entry);

	talloc_set_destructor(u, udp_request_free);

	/*
	 *	Insert the new packet into the thread queue.
	 */
	state_transition(u, PACKET_STATE_THREAD);

	/*
	 *	Start the retransmission timers.
	 */
	u->link->time_sent = fr_time();
	fr_time_to_timeval(&u->timer.start, u->link->time_sent);

	if (rr_track_start(&u->timer) < 0) {
		RDEBUG("%s - Failed starting retransmit tracking", inst->parent->name);
		talloc_free(u);
		return RLM_MODULE_FAIL;
	}

	if (fr_event_timer_insert(u, t->el, &u->timer.ev, &u->timer.next,
				  response_timeout, u) < 0) {
		RDEBUG("%s - Failed starting retransmit tracking",
		       inst->parent->name);
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
	case PACKET_STATE_INIT:
		rad_assert(0 == 1);
		break;

	case PACKET_STATE_THREAD:
	case PACKET_STATE_SENT:
		rcode = RLM_MODULE_YIELD;
		u->yielded = true;
		break;

	case PACKET_STATE_RESUMABLE: /* was replicated */
		state_transition(u, PACKET_STATE_FINISHED);
		/* FALL-THROUGH */

	case PACKET_STATE_FINISHED:
		rcode = RLM_MODULE_OK;
		break;
	}

	return rcode;
}


static void mod_signal(REQUEST *request, UNUSED void *instance, UNUSED void *thread, rlm_radius_link_t *link, fr_state_signal_t action)
{
	rlm_radius_udp_request_t *u = link->request_io_ctx;
	struct timeval now;

	if (action != FR_SIGNAL_DUP) return;

	/*
	 *	Sychronous mode means that we don't do any
	 *	retransmission, and instead we rely on the
	 *	retransmission from the NAS.
	 */
	RDEBUG("retransmitting proxied request");

	gettimeofday(&now, NULL);
	retransmit_packet(u, &now);
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
	rlm_radius_udp_thread_t *t = thread;

	(void) talloc_set_type(t, rlm_radius_udp_thread_t);
	t->inst = instance;
	t->el = el;

	t->queued = fr_heap_talloc_create(t, queue_cmp, rlm_radius_udp_request_t, heap_id);
	fr_dlist_init(&t->blocked, rlm_radius_udp_connection_t, entry);
	fr_dlist_init(&t->full, rlm_radius_udp_connection_t, entry);
	fr_dlist_init(&t->zombie, rlm_radius_udp_connection_t, entry);
	fr_dlist_init(&t->opening, rlm_radius_udp_connection_t, entry);

	t->active = fr_heap_talloc_create(t, conn_cmp, rlm_radius_udp_connection_t, heap_id);

	conn_alloc(t->inst, t);

	return 0;
}

/** Destroy thread data for the IO submodule.
 *
 */
static int mod_thread_detach(UNUSED fr_event_list_t *el, void *thread)
{
	rlm_radius_udp_thread_t *t = talloc_get_type_abort(thread, rlm_radius_udp_thread_t);

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

	.request_inst_size 	= sizeof(rlm_radius_udp_request_t),
	.request_inst_type	= "rlm_radius_udp_request_t",

	.thread_inst_size	= sizeof(rlm_radius_udp_thread_t),

	.config			= module_config,
	.bootstrap		= mod_bootstrap,
	.instantiate		= mod_instantiate,
	.thread_instantiate 	= mod_thread_instantiate,
	.thread_detach		= mod_thread_detach,

	.push			= mod_push,
	.signal			= mod_signal,
};
