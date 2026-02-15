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
 * @file rlm_tacacs_tcp.c
 * @brief TACACS+ transport
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/pair.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/server/connection.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/heap.h>

#include <sys/socket.h>
#include <sys/uio.h>

#include "rlm_tacacs.h"

/** Static configuration for the module.
 *
 */
typedef struct {
	rlm_tacacs_t		*parent;		//!< rlm_tacacs instance.
	CONF_SECTION		*config;

	fr_ipaddr_t		dst_ipaddr;		//!< IP of the home server.
	fr_ipaddr_t		src_ipaddr;		//!< IP we open our socket on.
	uint16_t		dst_port;		//!< Port of the home server.
	char const		*secret;		//!< Shared secret.
	size_t			secretlen;		//!< length of secret

	char const		*interface;		//!< Interface to bind to.

	uint32_t		recv_buff;		//!< How big the kernel's receive buffer should be.
	uint32_t		send_buff;		//!< How big the kernel's send buffer should be.

	uint32_t		max_packet_size;	//!< Maximum packet size.
	uint16_t		max_send_coalesce;	//!< Maximum number of packets to coalesce into one mmsg call.

	bool			recv_buff_is_set;	//!< Whether we were provided with a recv_buf
	bool			send_buff_is_set;	//!< Whether we were provided with a send_buf

	fr_pair_list_t		*trigger_args;		//!< Pairs passed to trigger request.
} rlm_tacacs_tcp_t;

typedef struct {
	fr_event_list_t		*el;			//!< Event list.

	rlm_tacacs_tcp_t const	*inst;			//!< our instance

	trunk_conf_t		trunk_conf;		//!< trunk configuration
	trunk_t			*trunk;			//!< trunk handler
} tcp_thread_t;

typedef struct {
	trunk_request_t		*treq;
	rlm_rcode_t		rcode;			//!< from the transport
} tcp_result_t;

typedef struct tcp_request_s tcp_request_t;

typedef struct {
	uint8_t			*read;			//!< where we read data from
	uint8_t			*write;			//!< where we write data to
	uint8_t			*end;			//!< end of the buffer
	uint8_t			*data;			//!< actual data
} tcp_buffer_t;

/** Track the handle, which is tightly correlated with the FD
 *
 */
typedef struct {
	char const     		*name;			//!< From IP PORT to IP PORT.
	char const		*module_name;		//!< the module that opened the connection

	int			fd;			//!< File descriptor.

	trunk_request_t     	**coalesced;		//!< Outbound coalesced requests.

	size_t			send_buff_actual;	//!< What we believe the maximum SO_SNDBUF size to be.
							///< We don't try and encode more packet data than this
							///< in one go.

	rlm_tacacs_tcp_t const	*inst;			//!< Our module instance.
	tcp_thread_t		*thread;

	uint32_t		session_id;		//!< for TACACS+ "security".

	uint32_t		max_packet_size;	//!< Our max packet size. may be different from the parent.

	fr_ipaddr_t		src_ipaddr;		//!< Source IP address.  May be altered on bind
							//!< to be the actual IP address packets will be
							//!< sent on.  This is why we can't use the inst
							//!< src_ipaddr field.
	uint16_t		src_port;		//!< Source port specific to this connection.
							//!< @todo - not set by socket_client_tcp()

	tcp_buffer_t		recv;			//!< receive buffer
	tcp_buffer_t		send;			//!< send buffer

	int			id;			//!< starts at 1.
	int			active;			//!< active packets
	trunk_request_t     	*tracking[UINT8_MAX];	//!< all sequential!

	fr_time_t		mrs_time;		//!< Most recent sent time which had a reply.
	fr_time_t		last_reply;		//!< When we last received a reply.
	fr_time_t		first_sent;		//!< first time we sent a packet since going idle
	fr_time_t		last_sent;		//!< last time we sent a packet.
	fr_time_t		last_idle;		//!< last time we had nothing to do

	fr_timer_t		*zombie_ev;		//!< Zombie timeout.

	trunk_connection_t	*tconn;			//!< trunk connection
} tcp_handle_t;


/** Connect request_t to local tracking structure
 *
 */
struct tcp_request_s {
	uint32_t		priority;		//!< copied from request->async->priority
	fr_time_t		recv_time;		//!< copied from request->async->recv_time

	uint8_t			code;			//!< Packet code.
	uint8_t			id;			//!< Last ID assigned to this packet.
	bool			outstanding;		//!< are we waiting for a reply?

	uint8_t			*packet;		//!< Packet we write to the network.
	size_t			packet_len;		//!< Length of the packet.

	fr_timer_t		*ev;			//!< timer for retransmissions
	fr_retry_t		retry;			//!< retransmission timers
};

static rlm_rcode_t tacacs_code_to_rcode[FR_TACACS_CODE_MAX] = {
	[FR_TACACS_CODE_AUTH_PASS]		= RLM_MODULE_OK,
	[FR_TACACS_CODE_AUTH_FAIL]		= RLM_MODULE_REJECT,
	[FR_TACACS_CODE_AUTH_GETUSER]		= RLM_MODULE_UPDATED,
	[FR_TACACS_CODE_AUTH_GETPASS]		= RLM_MODULE_UPDATED,
	[FR_TACACS_CODE_AUTH_GETDATA]		= RLM_MODULE_UPDATED,
	[FR_TACACS_CODE_AUTH_RESTART]		= RLM_MODULE_HANDLED,
	[FR_TACACS_CODE_AUTH_ERROR]		= RLM_MODULE_FAIL,

	[FR_TACACS_CODE_AUTZ_PASS_ADD]		= RLM_MODULE_OK,
	[FR_TACACS_CODE_AUTZ_PASS_REPLACE]	= RLM_MODULE_UPDATED,
	[FR_TACACS_CODE_AUTZ_FAIL]		= RLM_MODULE_REJECT,
	[FR_TACACS_CODE_AUTZ_ERROR]		= RLM_MODULE_FAIL,

	[FR_TACACS_CODE_ACCT_SUCCESS]		= RLM_MODULE_OK,
	[FR_TACACS_CODE_ACCT_ERROR]		= RLM_MODULE_FAIL,
};

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, rlm_tacacs_tcp_t, dst_ipaddr), },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv4addr", FR_TYPE_IPV4_ADDR, 0, rlm_tacacs_tcp_t, dst_ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("ipv6addr", FR_TYPE_IPV6_ADDR, 0, rlm_tacacs_tcp_t, dst_ipaddr) },

	{ FR_CONF_OFFSET("port", rlm_tacacs_tcp_t, dst_port) },

	{ FR_CONF_OFFSET("secret", rlm_tacacs_tcp_t, secret) }, /* can be NULL */

	{ FR_CONF_OFFSET("interface", rlm_tacacs_tcp_t, interface) },

	{ FR_CONF_OFFSET_IS_SET("recv_buff", FR_TYPE_UINT32, 0, rlm_tacacs_tcp_t, recv_buff) },
	{ FR_CONF_OFFSET_IS_SET("send_buff", FR_TYPE_UINT32, 0, rlm_tacacs_tcp_t, send_buff) },

	{ FR_CONF_OFFSET("max_packet_size", rlm_tacacs_tcp_t, max_packet_size), .dflt = STRINGIFY(FR_MAX_PACKET_SIZE) },
	{ FR_CONF_OFFSET("max_send_coalesce", rlm_tacacs_tcp_t, max_send_coalesce), .dflt = "1024" },

	{ FR_CONF_OFFSET_TYPE_FLAGS("src_ipaddr", FR_TYPE_COMBO_IP_ADDR, 0, rlm_tacacs_tcp_t, src_ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("src_ipv4addr", FR_TYPE_IPV4_ADDR, 0, rlm_tacacs_tcp_t, src_ipaddr) },
	{ FR_CONF_OFFSET_TYPE_FLAGS("src_ipv6addr", FR_TYPE_IPV6_ADDR, 0, rlm_tacacs_tcp_t, src_ipaddr) },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_tacacs;

extern fr_dict_autoload_t rlm_tacacs_tcp_dict[];
fr_dict_autoload_t rlm_tacacs_tcp_dict[] = {
	{ .out = &dict_tacacs, .proto = "tacacs" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_packet_hdr;
static fr_dict_attr_t const *attr_session_id;

extern fr_dict_attr_autoload_t rlm_tacacs_tcp_dict_attr[];
fr_dict_attr_autoload_t rlm_tacacs_tcp_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_tacacs },
	{ .out = &attr_packet_hdr, .name = "Packet", .type = FR_TYPE_STRUCT, .dict = &dict_tacacs },
	{ .out = &attr_session_id, .name = "Packet.Session-ID", .type = FR_TYPE_UINT32, .dict = &dict_tacacs },
	DICT_AUTOLOAD_TERMINATOR
};

/** Clear out any connection specific resources from a tcp request
 *
 */
static void tcp_request_reset(tcp_handle_t *h, tcp_request_t *req)
{
	req->packet = NULL;

	fr_assert(h->active > 0);
	fr_assert(h->tracking[req->id] != NULL);
	fr_assert(h->tracking[req->id]->preq == req);

	h->tracking[req->id] = NULL;
	req->outstanding = false;
	h->active--;

	FR_TIMER_DISARM(req->ev);

	/*
	 *	We've sent 255 packets, and received all replies.  Shut the connection down.
	 *
	 *	Welcome to the insanity that is TACACS+.
	 */
	if ((h->active == 0) && (h->id > 255)) {
		trunk_connection_signal_reconnect(h->tconn, CONNECTION_EXPIRED);
	}
}


/** Free a connection handle, closing associated resources
 *
 */
static int _tcp_handle_free(tcp_handle_t *h)
{
	fr_assert(h->fd >= 0);

	fr_event_fd_delete(h->thread->el, h->fd, FR_EVENT_FILTER_IO);

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

	return 0;
}

/** Initialise a new outbound connection
 *
 * @param[out] h_out	Where to write the new file descriptor.
 * @param[in] conn	to initialise.
 * @param[in] uctx	A #tcp_thread_t
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static connection_state_t conn_init(void **h_out, connection_t *conn, void *uctx)
{
	int			fd;
	tcp_handle_t		*h;
	tcp_thread_t		*thread = talloc_get_type_abort(uctx, tcp_thread_t);

	MEM(h = talloc_zero(conn, tcp_handle_t));
	h->thread = thread;
	h->inst = thread->inst;
	h->module_name = h->inst->parent->name;
	h->src_ipaddr = h->inst->src_ipaddr;
	h->src_port = 0;
	h->max_packet_size = h->inst->max_packet_size;
	h->last_idle = fr_time();

	h->id = 1;		/* clients send odd sequence numbers */
	h->session_id = fr_rand();

	/*
	 *	Initialize the buffer of coalesced packets we're doing to write.
	 */
	h->coalesced = talloc_zero_array(h, trunk_request_t *, h->inst->max_send_coalesce);

	/*
	 *	Open the outgoing socket.
	 */
	fd = fr_socket_client_tcp(NULL, &h->src_ipaddr, &h->inst->dst_ipaddr, h->inst->dst_port, true);
	if (fd < 0) {
		PERROR("%s - Failed opening socket", h->module_name);
		talloc_free(h);
		return CONNECTION_STATE_FAILED;
	}

	/*
	 *	Set the connection name.
	 */
	h->name = fr_asprintf(h, "proto tcp local %pV port %u remote %pV port %u",
			      fr_box_ipaddr(h->src_ipaddr), h->src_port,
			      fr_box_ipaddr(h->inst->dst_ipaddr), h->inst->dst_port);

	talloc_set_destructor(h, _tcp_handle_free);

#ifdef SO_RCVBUF
	if (h->inst->recv_buff_is_set) {
		int opt;

		opt = h->inst->recv_buff;
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(int)) < 0) {
			WARN("%s - Failed setting 'SO_RCVBUF': %s", h->module_name, fr_syserror(errno));
		}
	}
#endif

#ifdef SO_SNDBUF
	{
		int opt;
		socklen_t socklen = sizeof(int);

		if (h->inst->send_buff_is_set) {
			opt = h->inst->send_buff;
			if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(int)) < 0) {
				WARN("%s - Failed setting 'SO_SNDBUF', write performance may be sub-optimal: %s",
				     h->module_name, fr_syserror(errno));
			}
		}

		if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, &socklen) < 0) {
			WARN("%s - Failed getting 'SO_SNDBUF', write performance may be sub-optimal: %s",
			     h->module_name, fr_syserror(errno));

			/*
			 *	This controls how many packets we attempt
			 *	to send at once.  Nothing bad happens if
			 *	we get it wrong, but the user may see
			 *	ENOBUFS errors at high packet rates.
			 *
			 *	Since this is TACACS, we have small
			 *	packets and a maximum of 255 packets
			 *	per connection.  So don't set this too large.
			 */
			if (h->inst->send_buff_is_set) {
				h->send_buff_actual = h->inst->send_buff;
			} else {
				h->send_buff_actual = h->max_packet_size * h->inst->max_send_coalesce;
				if (h->send_buff_actual > 256*1024) h->send_buff_actual = 256*1024;
			}

			WARN("%s - Max coalesced outbound data will be %zu bytes", h->module_name,
			     h->send_buff_actual);
		} else {
#ifdef __linux__
			/*
			 *	Linux doubles the buffer when you set it
			 *	to account for "overhead".
			 */
			h->send_buff_actual = ((size_t)opt) / 2;
#else
			h->send_buff_actual = (size_t)opt;
#endif
		}
	}
#else
	h->send_buff_actual = h->inst->send_buff_is_set ?
			      h->inst_send_buff : h->max_packet_size * h->inst->max_send_coalesce;

	WARN("%s - Modifying 'SO_SNDBUF' value is not supported on this system, "
	     "write performance may be sub-optimal", h->module_name);
	WARN("%s - Max coalesced outbound data will be %zu bytes", h->module_name, h->inst->send_buff_actual);
#endif

	/*
	 *	Allow receiving of 2 max-sized packets.  In practice, most packets will be less than this.
	 */
	MEM(h->recv.data = talloc_array(h, uint8_t, h->max_packet_size * 2));
	h->recv.read = h->recv.write = h->recv.data;
	h->recv.end = h->recv.data + h->max_packet_size * 2;

	/*
	 *	Use the system SO_SNDBUF for how many packets to send at once.  In most circumstances the
	 *	packets are small, and widely separated in time, and we really only need a very small buffer.
	 */
	MEM(h->send.data = talloc_array(h, uint8_t, h->send_buff_actual));
	h->send.read = h->send.write = h->send.data;
	h->send.end = h->send.data + h->send_buff_actual;

	h->fd = fd;

	/*
	 *	Signal the connection
	 *	as open as soon as it becomes writable.
	 */
	connection_signal_on_fd(conn, fd);

	*h_out = h;

	// @todo - initialize the tracking memory, etc.
	// i.e. histograms (or hyperloglog) of packets, so we can see
	// which connections / home servers are fast / slow.

	return CONNECTION_STATE_CONNECTING;
}

/** Shutdown/close a file descriptor
 *
 */
static void conn_close(UNUSED fr_event_list_t *el, void *handle, UNUSED void *uctx)
{
	tcp_handle_t *h = talloc_get_type_abort(handle, tcp_handle_t);

	/*
	 *	There's tracking entries still allocated
	 *	this is bad, they should have all been
	 *	released.
	 */
	fr_assert(!h->active);

	DEBUG4("Freeing rlm_tacacs_tcp handle %p", handle);

	talloc_free(h);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static connection_t *thread_conn_alloc(trunk_connection_t *tconn, fr_event_list_t *el,
					  connection_conf_t const *conf,
					  char const *log_prefix, void *uctx)
{
	connection_t		*conn;
	tcp_thread_t		*thread = talloc_get_type_abort(uctx, tcp_thread_t);

	conn = connection_alloc(tconn, el,
				   &(connection_funcs_t){
					.init = conn_init,
					.close = conn_close,
				   },
				   conf,
				   log_prefix,
				   thread);
	if (!conn) {
		PERROR("%s - Failed allocating state handler for new connection", thread->inst->parent->name);
		return NULL;
	}

	return conn;
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
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	connection_t		*conn = tconn->conn;
	tcp_handle_t		*h = talloc_get_type_abort(conn->h, tcp_handle_t);

	if (fd_errno) ERROR("%s - Connection %s failed: %s", h->module_name, h->name, fr_syserror(fd_errno));

	connection_signal_reconnect(conn, CONNECTION_FAILED);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void thread_conn_notify(trunk_connection_t *tconn, connection_t *conn,
			       fr_event_list_t *el,
			       trunk_connection_event_t notify_on, UNUSED void *uctx)
{
	tcp_handle_t		*h = talloc_get_type_abort(conn->h, tcp_handle_t);
	fr_event_fd_cb_t	read_fn = NULL;
	fr_event_fd_cb_t	write_fn = NULL;

	switch (notify_on) {
	case TRUNK_CONN_EVENT_NONE:
		return;

	case TRUNK_CONN_EVENT_READ:
		read_fn = trunk_connection_callback_readable;
		break;

	case TRUNK_CONN_EVENT_WRITE:
		write_fn = trunk_connection_callback_writable;
		break;

	case TRUNK_CONN_EVENT_BOTH:
		read_fn = trunk_connection_callback_readable;
		write_fn = trunk_connection_callback_writable;
		break;

	}

	if (fr_event_fd_insert(h, NULL, el, h->fd,
			       read_fn,
			       write_fn,
			       conn_error,
			       tconn) < 0) {
		PERROR("%s - Failed inserting FD event", h->module_name);

		/*
		 *	May free the connection!
		 */
		trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
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
	tcp_request_t const *a = one;
	tcp_request_t const *b = two;
	int8_t ret;

	/*
	 *	Larger priority is more important.
	 */
	ret = CMP_PREFER_LARGER(a->priority, b->priority);
	if (ret != 0) return ret;

	/*
	 *	Smaller timestamp (i.e. earlier) is more important.
	 */
	return fr_time_cmp(a->recv_time, b->recv_time);
}

/** Decode response packet data, extracting relevant information and validating the packet
 *
 * @param[in] ctx			to allocate pairs in.
 * @param[out] reply			Pointer to head of pair list to add reply attributes to.
 * @param[out] response_code		The type of response packet.
 * @param[in] h				connection handle.
 * @param[in] request			the request.
 * @param[in] req			TCP request.
 * @param[in] data			to decode.
 * @param[in] data_len			Length of input data.
 * @return
 *	- <0 on error
 *	- >0 for how many bytes were decoded
 */
static ssize_t decode(TALLOC_CTX *ctx, fr_pair_list_t *reply, uint8_t *response_code,
		      tcp_handle_t *h, request_t *request, tcp_request_t *req,
		      uint8_t *data, size_t data_len)
{
	rlm_tacacs_tcp_t const *inst = h->thread->inst;
	ssize_t			packet_len;
	int			code;

	*response_code = 0;	/* Initialise to keep the rest of the code happy */

	/*
	 *	Check the session ID.
	 */
	if (memcmp(data + 4, req->packet + 4, 4) != 0) {
		REDEBUG("Session ID %08x does not match expected number %08x",
			fr_nbo_to_uint32(data + 4), fr_nbo_to_uint32(req->packet + 4));
	}

	/*
	 *	Decode the attributes, in the context of the reply.
	 *	This only fails if the packet is strangely malformed,
	 *	or if we run out of memory.
	 */
	packet_len = fr_tacacs_decode(ctx, reply, NULL, data, data_len, NULL, inst->secret, inst->secretlen, &code);
	if (packet_len < 0) {
		RPEDEBUG("Failed decoding TACACS+ reply packet");
		fr_pair_list_free(reply);
		return -1;
	}

	RDEBUG("Received %s ID %d length %ld reply packet on connection %s",
	       fr_tacacs_packet_names[code], code, packet_len, h->name);
	log_request_pair_list(L_DBG_LVL_2, request, NULL, reply, NULL);

	*response_code = code;

	/*
	 *	Fixup retry times
	 */
	if (fr_time_gt(req->retry.start, h->mrs_time)) h->mrs_time = req->retry.start;

	return packet_len;
}

static int encode(tcp_handle_t *h, request_t *request, tcp_request_t *req)
{
	ssize_t			packet_len;
	rlm_tacacs_tcp_t const *inst = h->inst;
	fr_pair_t		*hdr, *vp;

	fr_assert(inst->parent->allowed[req->code]);
	fr_assert(!req->packet);
	fr_assert(!req->outstanding);

	/*
	 *	Encode the packet in the outbound buffer.
	 */
	req->packet = h->send.write;

	/*
	 *	Set the session ID, if it hasn't already been set.
	 */
	hdr = fr_pair_find_by_da(&request->request_pairs, NULL, attr_packet_hdr);
	if (!hdr) hdr = request->request_ctx;

	vp = fr_pair_find_by_da_nested(&hdr->vp_group, NULL, attr_session_id);
	if (!vp) {
		MEM(vp = fr_pair_afrom_da(hdr, attr_session_id));

		vp->vp_uint32 = h->session_id;
		fr_pair_append(&hdr->vp_group, vp);
		fr_pair_list_sort(&hdr->vp_group, fr_pair_cmp_by_parent_num);
	}

	/*
	 *	Encode the packet.
	 */
	packet_len = fr_tacacs_encode(&FR_DBUFF_TMP(req->packet, (size_t) inst->max_packet_size), NULL,
				      inst->secret, inst->secretlen, request->reply->code, &request->request_pairs);
	if (packet_len < 0) {
		RPERROR("Failed encoding packet");
		return -1;
	}

	/*
	 *	Update the ID and the actual packet length;
	 */
	req->packet[1] = req->id;
	req->packet_len = packet_len;
	req->outstanding = true;

//	fr_tacacs_packet_log_hex(&default_log, u->packet);

	return 0;
}


/** Revive a connection after "revive_interval"
 *
 */
static void revive_timeout(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	tcp_handle_t	 	*h = talloc_get_type_abort(tconn->conn->h, tcp_handle_t);

	INFO("%s - Reviving connection %s", h->module_name, h->name);
	trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
}

/** Mark a connection dead after "zombie_interval"
 *
 */
static void zombie_timeout(fr_timer_list_t *tl, fr_time_t now, void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	tcp_handle_t	 	*h = talloc_get_type_abort(tconn->conn->h, tcp_handle_t);

	INFO("%s - No replies during 'zombie_period', marking connection %s as dead", h->module_name, h->name);

	/*
	 *	Don't use this connection, and re-queue all of its
	 *	requests onto other connections.
	 */
	trunk_connection_signal_inactive(tconn);
	(void) trunk_connection_requests_requeue(tconn, TRUNK_REQUEST_STATE_ALL, 0, false);

	/*
	 *	Revive the connection after a time.
	 */
	if (fr_timer_at(h, tl, &h->zombie_ev,
			fr_time_add(now, h->inst->parent->revive_interval), false, revive_timeout, h) < 0) {
		ERROR("Failed inserting revive timeout for connection");
		trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
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
 *
 * @return
 *	- true if the connection is zombie.
 *	- false if the connection is not zombie.
 */
static bool check_for_zombie(fr_timer_list_t *tl, trunk_connection_t *tconn, fr_time_t now, fr_time_t last_sent)
{
	tcp_handle_t	*h = talloc_get_type_abort(tconn->conn->h, tcp_handle_t);

	/*
	 *	If we're already zombie, don't go to zombie
	 *
	 */
	if (h->zombie_ev) return true;

	if (fr_time_eq(now, fr_time_wrap(0))) now = fr_time();

	/*
	 *	We received a reply since this packet was sent, the connection isn't zombie.
	 */
	if (fr_time_gteq(h->last_reply, last_sent)) return false;

	/*
	 *	If we've seen ANY response in the allowed window, then the connection is still alive.
	 */
	if (fr_time_gt(last_sent, fr_time_wrap(0)) &&
	    (fr_time_lt(fr_time_add(last_sent, h->inst->parent->response_window), now))) return false;

	/*
	 *	Mark the connection as inactive, but keep sending
	 *	packets on it.
	 */
	WARN("%s - Entering Zombie state - connection %s", h->module_name, h->name);
	trunk_connection_signal_inactive(tconn);

	if (fr_timer_at(h, tl, &h->zombie_ev, fr_time_add(now, h->inst->parent->zombie_period),
			false, zombie_timeout, h) < 0) {
		ERROR("Failed inserting zombie timeout for connection");
		trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
	}

	return true;
}

/** Handle retries.
 *
 *  Note that with TCP we don't actually retry on this particular connection, but the retry timer allows us to
 *  fail over from one connection to another when a connection fails.
 */
static void request_retry(fr_timer_list_t *tl, fr_time_t now, void *uctx)
{
	trunk_request_t		*treq = talloc_get_type_abort(uctx, trunk_request_t);
	tcp_request_t		*req = talloc_get_type_abort(treq->preq, tcp_request_t);
	tcp_result_t		*r = talloc_get_type_abort(treq->rctx, tcp_result_t);
	request_t		*request = treq->request;
	trunk_connection_t	*tconn = treq->tconn;

	fr_assert(treq->state == TRUNK_REQUEST_STATE_SENT);		/* No other states should be timing out */
	fr_assert(treq->preq);						/* Must still have a protocol request */
	fr_assert(tconn);

	switch (fr_retry_next(&req->retry, now)) {
	/*
	 *	Queue the request for retransmission.
	 *
	 *	@todo - set up "next" timer here, instead of in
	 *	request_mux() ?  That way we can catch the case of
	 *	packets sitting in the queue for extended periods of
	 *	time, and still run the timers.
	 */
	case FR_RETRY_CONTINUE:
		trunk_request_requeue(treq);
		return;

	case FR_RETRY_MRD:
		REDEBUG("Reached maximum_retransmit_duration (%pVs > %pVs), failing request",
			fr_box_time_delta(fr_time_sub(now, req->retry.start)), fr_box_time_delta(req->retry.config->mrd));
		break;

	case FR_RETRY_MRC:
		REDEBUG("Reached maximum_retransmit_count (%u > %u), failing request",
		        req->retry.count, req->retry.config->mrc);
		break;
	}

	r->rcode = RLM_MODULE_FAIL;
	trunk_request_signal_complete(treq);

	check_for_zombie(tl, tconn, now, req->retry.start);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void request_mux(fr_event_list_t *el,
			trunk_connection_t *tconn, connection_t *conn, UNUSED void *uctx)
{
	tcp_handle_t		*h = talloc_get_type_abort(conn->h, tcp_handle_t);
	rlm_tacacs_tcp_t const	*inst = h->inst;
	ssize_t			sent;
	uint16_t		i, queued;
	uint8_t const		*written;
	uint8_t			*partial;

	/*
	 *	Encode multiple packets in preparation for transmission with write()
	 */
	for (i = 0, queued = 0; (i < inst->max_send_coalesce); i++) {
		trunk_request_t	*treq;
		tcp_request_t	*req;
		request_t	*request;

 		if (unlikely(trunk_connection_pop_request(&treq, tconn) < 0)) return;

		/*
		 *	No more requests to send
		 */
		if (!treq) break;

		/*
		 *	The partial write MUST be the first one popped off of the request list.
		 *
		 *	If we have a partial packet, then we know that there's partial data in the output
		 *	buffer.  However, the request MAY still be freed or timed out before we can write the
		 *	data.  As a result, we ignore the tcp_request_t, and just keep writing the data.
		 */
		if (treq->state == TRUNK_REQUEST_STATE_PARTIAL) {
			fr_assert(h->send.read == h->send.data);
			fr_assert(h->send.write > h->send.read);

			fr_assert(i == 0);

			h->coalesced[0] = treq;
			goto next;
		}

		/*
		 *	The request must still be pending.
		 */
 		fr_assert(treq->state == TRUNK_REQUEST_STATE_PENDING);

		request = treq->request;
		req = talloc_get_type_abort(treq->preq, tcp_request_t);

		/*
		 *	We'd like to retransmit the packet on this connection, but it's TCP so we don't.
		 *
		 *	The retransmission timers are really there to move the packet to a new connection if
		 *	the current connection is dead.
		 */
		if (req->outstanding) continue;

		/*
		 *	Not enough room for a full-sized packet, stop encoding packets
		 */
		if ((h->send.end - h->send.write) < inst->max_packet_size) {
			break;
		}

		/*
		 *	Start retransmissions from when the socket is writable.
		 */
		fr_retry_init(&req->retry, fr_time(), &h->inst->parent->retry);
		fr_assert(fr_time_delta_ispos(req->retry.rt));
		fr_assert(fr_time_gt(req->retry.next, fr_time_wrap(0)));

		/*
		 *	Set up the packet for encoding.
		 */
		req->id = h->id;
		h->tconn = tconn;

		h->tracking[req->id] = treq;
		h->id += 2;
		h->active++;

		RDEBUG("Sending %s ID %d length %ld over connection %s",
		       fr_tacacs_packet_names[req->code], req->id, req->packet_len, h->name);

		if (encode(h, request, req) < 0) {
			/*
			 *	Need to do this because request_conn_release
			 *	may not be called.
			 */
			tcp_request_reset(h, req);
			trunk_request_signal_fail(treq);
			continue;
		}
		RHEXDUMP3(req->packet, req->packet_len, "Encoded packet");

		log_request_pair_list(L_DBG_LVL_2, request, NULL, &request->request_pairs, NULL);

		/*
		 *	Remember that we've encoded this packet.
		 */
		h->coalesced[queued] = treq;
		h->send.write += req->packet_len;

		fr_assert(h->send.write <= h->send.end);

		/*
		 *	If we just hit this limit, stop using the connection.
		 *
		 *	When we've received all replies (or timeouts), we'll close the connections.
		 */
		if (h->id > 255) {
			trunk_connection_signal_inactive(tconn);
		}

	next:
		/*
		 *	Tell the trunk API that this request is now in
		 *	the "sent" state.  And we don't want to see
		 *	this request again. The request hasn't actually
		 *	been sent, but it's the only way to get at the
		 *	next entry in the heap.
		 */
		trunk_request_signal_sent(treq);
		queued++;
	}

	if (queued == 0) return;

	/*
	 *	Verify nothing accidentally freed the connection handle
	 */
	(void)talloc_get_type_abort(h, tcp_handle_t);

	/*
	 *	Send the packets as one system call.
	 */
	sent = write(h->fd, h->send.read, h->send.write - h->send.read);
	if (sent < 0) {		/* Error means no messages were sent */
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
			WARN("%s - Failed sending data over connection %s: %s",
			     h->module_name, h->name, fr_syserror(errno));
			sent = 0;
			break;

		/*
		 *	Will re-queue any 'sent' requests, so we don't
		 *	have to do any cleanup.
		 */
		default:
			ERROR("%s - Failed sending data over connection %s: %s",
			      h->module_name, h->name, fr_syserror(errno));
			trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
			return;
		}
	}

	written = h->send.read + sent;
	partial = h->send.read;

	/*
	 *	For all messages that were actually sent by writev()
	 *	start the request timer.
	 */
	for (i = 0; i < queued; i++) {
		trunk_request_t	*treq = h->coalesced[i];
		tcp_request_t	*req;
		request_t	*request;

		/*
		 *	We *think* we sent this, but we might not had :(
		 */
		fr_assert(treq->state == TRUNK_REQUEST_STATE_SENT);

		request = treq->request;
		req = talloc_get_type_abort(treq->preq, tcp_request_t);

		/*
		 *	This packet ends before the piece we've
		 *	written, so we've written all of it.
		 */
		if (req->packet + req->packet_len <= written) {
			h->last_sent = req->retry.start;
			if (fr_time_lteq(h->first_sent, h->last_idle)) h->first_sent = h->last_sent;

			if (fr_timer_at(req, el->tl, &req->ev, req->retry.next, false, request_retry, treq) < 0) {
				RERROR("Failed inserting retransmit timeout for connection");
				trunk_request_signal_fail(treq);
			}

			/*
			 *	If the packet doesn't get a response, then the timer will hit
			 *	and will retransmit.
			 */
			req->outstanding = true;
			continue;
		}

		/*
		 *	The packet starts before the piece we've written, BUT ends after the written piece.
		 *
		 *	We only wrote part of this packet, remember the partial packet we wrote.  Note that
		 *	we only track the packet data, and not the tcp_request_t.  The underlying request (and
		 *	u) may disappear at any time, even if there's still data in the buffer.
		 *
		 *	Then, signal that isn't a partial packet, and stop processing the queue, as we know
		 *	that the next packet wasn't written.
		 */
		if (req->packet < written) {
			size_t skip = written - req->packet;
			size_t left = req->packet_len - skip;

			fr_assert(req->packet + req->packet_len > written);

			memmove(h->send.data, req->packet, left);

			fr_assert(h->send.read == h->send.data);
			partial = h->send.data + left;
			req->outstanding = true;

			trunk_request_signal_partial(h->coalesced[i]);
			continue;
		}

		/*
		 *	The packet starts after the piece we've written, so we haven't written any of it.
		 *
		 *	Requests that weren't sent get re-enqueued.  Which means that they get re-encoded, but
		 *	oh well.
		 *
		 *	The cancel logic runs as per-normal and cleans up
		 *	the request ready for sending again...
		 */
		trunk_request_requeue(h->coalesced[i]);
		fr_assert(!req->outstanding); /* must have called request_requeue() */
	}

	/*
	 *	Remember where to write the next packet.  Either at the start of the buffer, or after the one
	 *	which was partially written.
	 */
	h->send.write = partial;
}

static void request_demux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn, connection_t *conn, UNUSED void *uctx)
{
	tcp_handle_t		*h = talloc_get_type_abort(conn->h, tcp_handle_t);
	bool			do_read = true;

	DEBUG3("%s - Reading data for connection %s", h->module_name, h->name);

	while (true) {
		ssize_t slen;
		size_t			available, used, packet_len;

		trunk_request_t	*treq;
		request_t		*request;
		tcp_request_t		*req;
		tcp_result_t		*r;
		uint8_t			code = 0;
		fr_pair_list_t		reply;

		/*
		 *	Ensure that we can read at least one max-sized packet.
		 *
		 *	If not, move the trailing bytes to the start of the buffer, and reset the read/write
		 *	pointers to the start of the buffer.  Note that the read buffer has to be at least 2x
		 *	max_packet_size.
		 */
		available = h->recv.end - h->recv.read;
		if (available < h->inst->max_packet_size) {
			fr_assert(h->recv.data + h->inst->max_packet_size < h->recv.read);

			used = h->recv.write - h->recv.read;

			memcpy(h->recv.data, h->recv.read, used);
			h->recv.read = h->recv.data;
			h->recv.write = h->recv.read + used;
		}

		/*
		 *	Read as much data as possible.
		 *
		 *	We don't need to call read() on every round through the loop.  Instead, we call it
		 *	only when this function first gets called, OR if the read stopped at the end of the
		 *	buffer.
		 *
		 *	This allows us to read a large amount of data at once, and then process multiple
		 *	packets without calling read() too many times.
		 */
		if (do_read) {
			slen = read(h->fd, h->recv.write, h->recv.end - h->recv.write);
			if (slen < 0) {
				if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) return;

				ERROR("%s - Failed reading response from socket: %s",
				      h->module_name, fr_syserror(errno));
				trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
				return;
			}

			h->recv.write += slen;
			do_read = (h->recv.write == h->recv.end);
		}

		used = h->recv.write - h->recv.read;

		/*
		 *	We haven't received a full header, read more or return.
		 */
		if (used < sizeof(fr_tacacs_packet_hdr_t)) {
			if (do_read) continue;
			return;
		}

		/*
		 *	The packet contains a 4 octet length in the
		 *	header, but the header bytes aren't included
		 *	in the 4 octet length field.
		 */
		packet_len = fr_nbo_to_uint32(h->recv.read + 8) + FR_HEADER_LENGTH;

		/*
		 *	The packet is too large, reject it.
		 */
		if (packet_len > h->inst->max_packet_size) {
			ERROR("%s - Packet is larger than max_packet_size",
			      h->module_name);
			trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
			return;
		}

		/*
		 *	We haven't received the full packet, read more or return.
		 */
		if (used < packet_len) {
			if (do_read) continue;
			return;
		}

		fr_assert(h->recv.read + packet_len <= h->recv.end);

		/*
		 *	TACACS+ doesn't care about packet codes.  All packet of the codes share the same ID
		 *	space.
		 */
		treq = h->tracking[h->recv.read[1]];
		if (!treq) {
			WARN("%s - Ignoring reply with ID %i that arrived too late",
			     h->module_name, h->recv.data[1]);

			h->recv.read += packet_len;
			continue;
		}

		treq = talloc_get_type_abort(treq, trunk_request_t);
		request = treq->request;
		fr_assert(request != NULL);
		req = talloc_get_type_abort(treq->preq, tcp_request_t);
		r = talloc_get_type_abort(treq->rctx, tcp_result_t);

		fr_pair_list_init(&reply);

		/*
		 *	Validate and decode the incoming packet
		 */
		slen = decode(request->reply_ctx, &reply, &code, h, request, req, h->recv.read, packet_len);
		if (slen < 0) {
			// @todo - give real decode error?
			trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
			return;
		}
		h->recv.read += packet_len;

		/*
		 *	Only valid packets are processed.
		 */
		h->last_reply = fr_time();

		treq->request->reply->code = code;

		r->rcode = tacacs_code_to_rcode[code];
		fr_pair_list_append(&request->reply_pairs, &reply);
		trunk_request_signal_complete(treq);
	}
}

/** Remove the request from any tracking structures
 *
 * Frees encoded packets if the request is being moved to a new connection
 */
static void request_cancel(connection_t *conn, void *preq_to_reset,
			   trunk_cancel_reason_t reason, UNUSED void *uctx)
{
	tcp_request_t	*req = talloc_get_type_abort(preq_to_reset, tcp_request_t);

	/*
	 *	Request has been requeued on the same
	 *	connection due to timeout or DUP signal.
	 */
	if (reason == TRUNK_CANCEL_REASON_REQUEUE) {
		tcp_handle_t		*h = talloc_get_type_abort(conn->h, tcp_handle_t);

		tcp_request_reset(h, req);
	}

	/*
	 *      Other cancellations are dealt with by
	 *      request_conn_release as the request is removed
	 *	from the trunk.
	 */
}

/** Clear out anything associated with the handle from the request
 *
 */
static void request_conn_release(connection_t *conn, void *preq_to_reset, UNUSED void *uctx)
{
	tcp_request_t		*req = talloc_get_type_abort(preq_to_reset, tcp_request_t);
	tcp_handle_t		*h = talloc_get_type_abort(conn->h, tcp_handle_t);

	if (req->packet) tcp_request_reset(h, req);

	/*
	 *	If there are no outstanding tracking entries
	 *	allocated then the connection is "idle".
	 *
	 *	@todo - enable idle timeout?
	 */
	if (!h->active) h->last_idle = fr_time();
}

/** Write out a canned failure
 *
 */
static void request_fail(request_t *request, NDEBUG_UNUSED void *preq, void *rctx,
			 NDEBUG_UNUSED trunk_request_state_t state, UNUSED void *uctx)
{
	tcp_result_t		*r = talloc_get_type_abort(rctx, tcp_result_t);
#ifndef NDEBUG
	tcp_request_t		*req = talloc_get_type_abort(preq, tcp_request_t);
#endif

	fr_assert(!fr_timer_armed(req->ev));	/* Dealt with by request_conn_release */

	fr_assert(state != TRUNK_REQUEST_STATE_INIT);

	r->rcode = RLM_MODULE_FAIL;
	r->treq = NULL;

	unlang_interpret_mark_runnable(request);
}

/** Response has already been written to the rctx at this point
 *
 */
static void request_complete(request_t *request, NDEBUG_UNUSED void *preq, void *rctx, UNUSED void *uctx)
{
	tcp_result_t		*r = talloc_get_type_abort(rctx, tcp_result_t);
#ifndef NDEBUG
	tcp_request_t		*req = talloc_get_type_abort(preq, tcp_request_t);
#endif

	fr_assert(!req->packet && !fr_timer_armed(req->ev));	/* Dealt with by request_conn_release */

	r->treq = NULL;

	unlang_interpret_mark_runnable(request);
}

/** Explicitly free resources associated with the protocol request
 *
 */
static void request_free(UNUSED request_t *request, void *preq_to_free, UNUSED void *uctx)
{
	tcp_request_t		*req = talloc_get_type_abort(preq_to_free, tcp_request_t);

	fr_assert(!req->packet && !fr_timer_armed(req->ev));	/* Dealt with by request_conn_release */

	talloc_free(req);
}

/** Resume execution of the request, returning the rcode set during trunk execution
 *
 */
static unlang_action_t mod_resume(unlang_result_t *p_result, module_ctx_t const *mctx, UNUSED request_t *request)
{
	tcp_result_t	*r = talloc_get_type_abort(mctx->rctx, tcp_result_t);
	rlm_rcode_t	rcode = r->rcode;

	talloc_free(r);

	RETURN_UNLANG_RCODE(rcode);
}

static void mod_signal(module_ctx_t const *mctx, UNUSED request_t *request, fr_signal_t action)
{
//	tcp_thread_t		*t = talloc_get_type_abort(mctx->thread, tcp_thread_t);
	tcp_result_t		*r = talloc_get_type_abort(mctx->rctx, tcp_result_t);

	/*
	 *	If we don't have a treq associated with the
	 *	rctx it's likely because the request was
	 *	scheduled, but hasn't yet been resumed, and
	 *	has received a signal, OR has been resumed
	 *	and immediately cancelled as the event loop
	 *	is exiting, in which case
	 *	unlang_request_is_scheduled will return false
	 *	(don't use it).
	 */
	if (!r->treq) {
		talloc_free(r);
		return;
	}

	switch (action) {
	/*
	 *	The request is being cancelled, tell the
	 *	trunk so it can clean up the treq.
	 */
	case FR_SIGNAL_CANCEL:
		trunk_request_signal_cancel(r->treq);
		r->treq = NULL;
		talloc_free(r);		/* Should be freed soon anyway, but better to be explicit */
		return;

	/*
	 *	Requeue the request on the same connection
	 *      causing a "retransmission" if the request
	 *	has already been sent out.
	 */
	case FR_SIGNAL_DUP:
		/*
		 *	Retransmit the current request on the same connection.
		 *
		 *	If it's zombie, we still resend it.  If the
		 *	connection is dead, then a callback will move
		 *	this request to a new connection.
		 */
		trunk_request_requeue(r->treq);
		return;

	default:
		return;
	}
}

#ifndef NDEBUG
/** Free a tcp_result_t
 *
 * Allows us to set break points for debugging.
 */
static int _tcp_result_free(tcp_result_t *r)
{
	trunk_request_t		*treq;
	tcp_request_t		*req;

	if (!r->treq) return 0;

	treq = talloc_get_type_abort(r->treq, trunk_request_t);
	req = talloc_get_type_abort(treq->preq, tcp_request_t);

	fr_assert_msg(!req->ev, "tcp_result_t freed with active timer");

	return 0;
}
#endif

static unlang_action_t mod_enqueue(unlang_result_t *p_result, void **rctx_out, UNUSED void *instance, void *thread, request_t *request)
{
	tcp_thread_t		*t = talloc_get_type_abort(thread, tcp_thread_t);
	tcp_result_t		*r;
	tcp_request_t		*req;
	trunk_request_t		*treq;
	trunk_enqueue_t		q;

	fr_assert(FR_TACACS_PACKET_CODE_VALID(request->packet->code));

	treq = trunk_request_alloc(t->trunk, request);
	if (!treq) RETURN_UNLANG_FAIL;

	MEM(r = talloc_zero(request, tcp_result_t));
#ifndef NDEBUG
	talloc_set_destructor(r, _tcp_result_free);
#endif

	/*
	 *	Can't use compound literal - const issues.
	 */
	MEM(req = talloc_zero(treq, tcp_request_t));
	req->code = request->packet->code;
	req->priority = request->priority;
	req->recv_time = request->async->recv_time;

	r->rcode = RLM_MODULE_FAIL;

	q = trunk_request_enqueue(&treq, t->trunk, request, req, r);
	if (q < 0) {
		fr_assert(!req->packet);	/* Should not have been fed to the muxer */
		trunk_request_free(&treq);		/* Return to the free list */
	fail:
		talloc_free(r);
		RETURN_UNLANG_FAIL;
	}

	/*
	 *	All destinations are down.
	 */
	if (q == TRUNK_ENQUEUE_IN_BACKLOG) {
		RDEBUG("All destinations are down - cannot send packet");
		goto fail;
	}

	r->treq = treq;	/* Remember for signalling purposes */

	*rctx_out = r;

	return UNLANG_ACTION_YIELD;
}

/** Instantiate thread data for the submodule.
 *
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_tacacs_tcp_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_tacacs_tcp_t);
	tcp_thread_t			*thread = talloc_get_type_abort(mctx->thread, tcp_thread_t);

	static trunk_io_funcs_t	io_funcs = {
						.connection_alloc = thread_conn_alloc,
						.connection_notify = thread_conn_notify,
						.request_prioritise = request_prioritise,
						.request_mux = request_mux,
						.request_demux = request_demux,
						.request_conn_release = request_conn_release,
						.request_complete = request_complete,
						.request_fail = request_fail,
						.request_cancel = request_cancel,
						.request_free = request_free
					};

	thread->el = mctx->el;
	thread->inst = inst;
	thread->trunk = trunk_alloc(thread, mctx->el, &io_funcs,
				    &inst->parent->trunk_conf, inst->parent->name, thread, false, inst->trigger_args);
	if (!thread->trunk) return -1;

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_tacacs_t		*parent = talloc_get_type_abort(mctx->mi->parent->data, rlm_tacacs_t);
	rlm_tacacs_tcp_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_tacacs_tcp_t);
	CONF_SECTION		*conf = mctx->mi->conf;
	char			*server = NULL;

	if (!parent) {
		ERROR("IO module cannot be instantiated directly");
		return -1;
	}

	inst->parent = parent;

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
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, >=, ((255 + (int) sizeof(fr_tacacs_packet_t)) & 0xffffff00));
	FR_INTEGER_BOUND_CHECK("max_packet_size", inst->max_packet_size, <=, 65535);


	if (inst->recv_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, >=, inst->max_packet_size);
		FR_INTEGER_BOUND_CHECK("recv_buff", inst->recv_buff, <=, (1 << 30));
	}

	if (inst->send_buff_is_set) {
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, >=, inst->max_packet_size);
		FR_INTEGER_BOUND_CHECK("send_buff", inst->send_buff, <=, (1 << 30));
	}


	/*
	 *	Empty secrets don't exist
	 */
	if (inst->secret && !*inst->secret) {
		talloc_const_free(inst->secret);
		inst->secret = NULL;
	}

	if (inst->secret) inst->secretlen = talloc_array_length(inst->secret) - 1;

	if (!parent->trunk_conf.conn_triggers) return 0;

	fr_value_box_aprint(inst, &server, fr_box_ipaddr(inst->dst_ipaddr), NULL);

	MEM(inst->trigger_args = fr_pair_list_alloc(inst));
	if (module_trigger_args_build(inst->trigger_args, inst->trigger_args,
				      cf_section_find(cf_item_to_section(cf_parent(conf)), "pool", NULL),
				      &(module_trigger_args_t) {
						.module = mctx->mi->module->name,
						.name = parent->name,
						.server = server,
						.port = inst->dst_port
					}) < 0) return -1;

	return 0;
}

extern rlm_tacacs_io_t rlm_tacacs_tcp;
rlm_tacacs_io_t rlm_tacacs_tcp = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "tacacs_tcp",
		.inst_size		= sizeof(rlm_tacacs_tcp_t),

		.thread_inst_size	= sizeof(tcp_thread_t),
		.thread_inst_type	= "tcp_thread_t",

		.config			= module_config,
		.instantiate		= mod_instantiate,
		.thread_instantiate 	= mod_thread_instantiate,
	},
	.enqueue		= mod_enqueue,
	.signal			= mod_signal,
	.resume			= mod_resume,
};
