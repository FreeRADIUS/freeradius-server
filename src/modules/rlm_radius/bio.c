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
 * @file src/modules/rlm_radius/bio.c
 * @brief RADIUS BIO transport
 *
 * @copyright 2017 Network RADIUS SAS
 * @copyright 2020 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/pair.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/server/connection.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/heap.h>
#include <freeradius-devel/util/rb_expire.h>

#include <sys/socket.h>

//#include "rlm_radius.h"
#include "track.h"

typedef enum {
	LIMIT_PORTS_NONE = 0,			//!< Source port not restricted
	LIMIT_PORTS_STATIC,			//!< Limited source ports for static home servers
	LIMIT_PORTS_DYNAMIC			//!< Limited source ports for dynamic home servers
} bio_limit_ports_t;

typedef struct {
	char const		*module_name;	//!< the module that opened the connection
	rlm_radius_t const	*inst;		//!< our instance
	fr_event_list_t		*el;	       	//!< Event list.
	trunk_t			*trunk;	       	//!< trunk handler
	fr_bio_fd_config_t	fd_config;	//!< for threads or sockets
	fr_bio_fd_info_t const	*fd_info;	//!< status of the FD.
	fr_radius_ctx_t		radius_ctx;	//!< for signing packets
	bio_limit_ports_t	limit_source_ports;	//!< What type of port limit is in use.
} bio_handle_ctx_t;

typedef struct {
	bio_handle_ctx_t	ctx;		//!< common struct for home servers and BIO handles

	struct {
		fr_bio_t *fd;			//!< writing
		uint32_t id;			//!< for replication
		fr_rb_expire_t	expires;       	//!< for proxying / client sending
	} bio;

	int			num_ports;
	connection_t		**connections;
} bio_thread_t;

typedef struct bio_request_s bio_request_t;

/** Track the handle, which is tightly correlated with the FD
 *
 */
typedef struct {
	bio_handle_ctx_t	ctx;		//!< common struct for home servers and BIO handles

	int			fd;			//!< File descriptor.

	struct {
		fr_bio_t		*main;     	//!< what we use for IO
		fr_bio_t		*fd;		//!< raw FD
		fr_bio_t		*mem;		//!< memory wrappers for stream sockets
	} bio;

	connection_t		*conn;

	uint8_t			last_id;		//!< Used when replicating to ensure IDs are distributed
							///< evenly.

	uint32_t		max_packet_size;	//!< Our max packet size. may be different from the parent.

	uint8_t			*buffer;		//!< Receive buffer.
	size_t			buflen;			//!< Receive buffer length.

	radius_track_t		*tt;			//!< RADIUS ID tracking structure.

	fr_time_t		mrs_time;		//!< Most recent sent time which had a reply.
	fr_time_t		last_reply;		//!< When we last received a reply.
	fr_time_t		first_sent;		//!< first time we sent a packet since going idle
	fr_time_t		last_sent;		//!< last time we sent a packet.
	fr_time_t		last_idle;		//!< last time we had nothing to do

	fr_timer_t		*zombie_ev;		//!< Zombie timeout.

	bool			status_checking;       	//!< whether we're doing status checks
	bio_request_t		*status_u;		//!< for sending status check packets
	request_t		*status_request;
} bio_handle_t;


/** Connect request_t to local tracking structure
 *
 */
struct bio_request_s {
	trunk_request_t		*treq;
	rlm_rcode_t		rcode;			//!< from the transport
	bool			is_retry;

	uint32_t		priority;		//!< copied from request->async->priority
	fr_time_t		recv_time;		//!< copied from request->async->recv_time

	uint32_t		num_replies;		//!< number of reply packets, sent is in retry.count

	bool			status_check;		//!< is this packet a status check?
	bool			proxied;		//!< is this request being proxied

	fr_pair_list_t		extra;			//!< VPs for debugging, like Proxy-State.

	uint8_t			code;			//!< Packet code.
	uint8_t			id;			//!< Last ID assigned to this packet.
	uint8_t			*packet;		//!< Packet we write to the network.
	size_t			packet_len;		//!< Length of the packet.
	size_t			partial;		//!< partially sent data

	radius_track_entry_t	*rr;			//!< ID tracking, resend count, etc.
	fr_timer_t	*ev;			//!< timer for retransmissions
	fr_retry_t		retry;			//!< retransmission timers
};

typedef struct {
	bio_handle_ctx_t	ctx;		//!< for copying to bio_handle_t

	fr_rb_expire_node_t	expire;

	int			num_ports;
	connection_t		*connections[];	//!< for tracking outbound connections
} home_server_t;


/** Turn a reply code into a module rcode;
 *
 */
static rlm_rcode_t radius_code_to_rcode[FR_RADIUS_CODE_MAX] = {
	[FR_RADIUS_CODE_ACCESS_ACCEPT]		= RLM_MODULE_OK,
	[FR_RADIUS_CODE_ACCESS_CHALLENGE]	= RLM_MODULE_UPDATED,
	[FR_RADIUS_CODE_ACCESS_REJECT]		= RLM_MODULE_REJECT,

	[FR_RADIUS_CODE_ACCOUNTING_RESPONSE]	= RLM_MODULE_OK,

	[FR_RADIUS_CODE_COA_ACK]		= RLM_MODULE_OK,
	[FR_RADIUS_CODE_COA_NAK]		= RLM_MODULE_REJECT,

	[FR_RADIUS_CODE_DISCONNECT_ACK]	= RLM_MODULE_OK,
	[FR_RADIUS_CODE_DISCONNECT_NAK]	= RLM_MODULE_REJECT,

	[FR_RADIUS_CODE_PROTOCOL_ERROR]	= RLM_MODULE_HANDLED,
};

static void		conn_init_writable(UNUSED fr_event_list_t *el, UNUSED int fd,
					   UNUSED int flags, void *uctx);

static int 		encode(bio_handle_t *h, request_t *request, bio_request_t *u, uint8_t id);

static fr_radius_decode_fail_t	decode(TALLOC_CTX *ctx, fr_pair_list_t *reply, uint8_t *response_code,
			       bio_handle_t *h, request_t *request, bio_request_t *u,
			       uint8_t const request_authenticator[static RADIUS_AUTH_VECTOR_LENGTH],
			       uint8_t *data, size_t data_len);

static void		protocol_error_reply(bio_request_t *u, bio_handle_t *h);

static void mod_write(request_t *request, trunk_request_t *treq, bio_handle_t *h);

static int _bio_request_free(bio_request_t *u);

static int8_t home_server_cmp(void const *one, void const *two);

#ifndef NDEBUG
/** Log additional information about a tracking entry
 *
 * @param[in] te	Tracking entry we're logging information for.
 * @param[in] log	destination.
 * @param[in] log_type	Type of log message.
 * @param[in] file	the logging request was made in.
 * @param[in] line 	logging request was made on.
 */
static void bio_tracking_entry_log(fr_log_t const *log, fr_log_type_t log_type, char const *file, int line,
				   radius_track_entry_t *te)
{
	request_t			*request;

	if (!te->request) return;	/* Free entry */

	request = talloc_get_type_abort(te->request, request_t);

	fr_log(log, log_type, file, line, "request %s, allocated %s:%d", request->name,
	       request->alloc_file, request->alloc_line);

	trunk_request_state_log(log, log_type, file, line, talloc_get_type_abort(te->uctx, trunk_request_t));
}
#endif

/** Clear out any connection specific resources from a udp request
 *
 */
static void bio_request_reset(bio_request_t *u)
{
	TALLOC_FREE(u->packet);
	fr_pair_list_free(&u->extra);

	/*
	 *	Can have packet put no u->rr
	 *	if this is part of a pre-trunk status check.
	 */
	if (u->rr) radius_track_entry_release(&u->rr);

	fr_assert(!fr_timer_armed(u->ev));
}

/** Reset a status_check packet, ready to reuse
 *
 */
static void status_check_reset(bio_handle_t *h, bio_request_t *u)
{
	fr_assert(u->status_check == true);

	h->status_checking = false;
	u->num_replies = 0;	/* Reset */
	u->retry.start = fr_time_wrap(0);

	FR_TIMER_DISARM(u->ev);

	bio_request_reset(u);
}

/*
 *	Status-Server checks.  Manually build the packet, and
 *	all of its associated glue.
 */
static void CC_HINT(nonnull) status_check_alloc(bio_handle_t *h)
{
	bio_request_t		*u;
	request_t		*request;
	rlm_radius_t const	*inst = h->ctx.inst;
	map_t			*map = NULL;

	fr_assert(!h->status_u && !h->status_request);

	MEM(request = request_local_alloc_external(h, (&(request_init_args_t){ .namespace = dict_radius })));
	MEM(u = talloc_zero(request, bio_request_t));
	talloc_set_destructor(u, _bio_request_free);

	h->status_u = u;

	h->status_request = request;
	fr_pair_list_init(&u->extra);

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
	request->async = talloc_zero(request, fr_async_t);
	talloc_const_free(request->name);
	request->name = talloc_strdup(request, h->ctx.module_name);

	request->packet = fr_packet_alloc(request, false);
	request->reply = fr_packet_alloc(request, false);

	/*
	 *	Create the VPs, and ignore any errors
	 *	creating them.
	 */
	while ((map = map_list_next(&inst->status_check_map, map))) {
		(void) map_to_request(request, map, map_to_vp, NULL);
	}

	/*
	 *	Ensure that there's a NAS-Identifier, if one wasn't
	 *	already added.
	 */
	if (!fr_pair_find_by_da(&request->request_pairs, NULL, attr_nas_identifier)) {
		fr_pair_t *vp;

		MEM(pair_append_request(&vp, attr_nas_identifier) >= 0);
		fr_pair_value_strdup(vp, "status check - are you alive?", false);
	}

	/*
	 *	Always add an Event-Timestamp, which will be the time
	 *	at which the first packet is sent.  Or for
	 *	Status-Server, the time of the current packet.
	 */
	if (!fr_pair_find_by_da(&request->request_pairs, NULL, attr_event_timestamp)) {
		MEM(pair_append_request(NULL, attr_event_timestamp) >= 0);
	}

	/*
	 *	Initialize the request IO ctx.  Note that we don't set
	 *	destructors.
	 */
	u->code = inst->status_check;
	request->packet->code = u->code;

	DEBUG3("%s - Status check packet type will be %s", h->ctx.module_name, fr_radius_packet_name[u->code]);
	log_request_proto_pair_list(L_DBG_LVL_3, request, NULL, &request->request_pairs, NULL);
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
static void conn_init_error(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, int fd_errno, void *uctx)
{
	connection_t		*conn = talloc_get_type_abort(uctx, connection_t);
	bio_handle_t		*h;

	/*
	 *	Connection must be in the connecting state when this fires
	 */
	fr_assert(conn->state == CONNECTION_STATE_CONNECTING);

	h = talloc_get_type_abort(conn->h, bio_handle_t);

	ERROR("%s - Connection %s failed: %s", h->ctx.module_name, h->ctx.fd_info->name, fr_syserror(fd_errno));

	connection_signal_reconnect(conn, CONNECTION_FAILED);
}

/** Status check timer when opening the connection for the first time.
 *
 * Setup retries, or fail the connection.
 */
static void conn_init_timeout(UNUSED fr_timer_list_t *tl, fr_time_t now, void *uctx)
{
	connection_t		*conn = talloc_get_type_abort(uctx, connection_t);
	bio_handle_t		*h;
	bio_request_t		*u;

	/*
	 *	Connection must be in the connecting state when this fires
	 */
	fr_assert(conn->state == CONNECTION_STATE_CONNECTING);

	h = talloc_get_type_abort(conn->h, bio_handle_t);
	u = h->status_u;

	/*
	 *	We're only interested in contiguous, good, replies.
	 */
	u->num_replies = 0;

	switch (fr_retry_next(&u->retry, now)) {
	case FR_RETRY_MRD:
		DEBUG("%s - Reached maximum_retransmit_duration (%pVs > %pVs), failing status checks",
		      h->ctx.module_name, fr_box_time_delta(fr_time_sub(now, u->retry.start)),
		      fr_box_time_delta(u->retry.config->mrd));
		goto fail;

	case FR_RETRY_MRC:
		DEBUG("%s - Reached maximum_retransmit_count (%u > %u), failing status checks",
		      h->ctx.module_name, u->retry.count, u->retry.config->mrc);
	fail:
		connection_signal_reconnect(conn, CONNECTION_FAILED);
		return;

	case FR_RETRY_CONTINUE:
		if (fr_event_fd_insert(h, NULL, conn->el, h->fd, conn_init_writable, NULL,
				       conn_init_error, conn) < 0) {
			PERROR("%s - Failed inserting FD event", h->ctx.module_name);
			connection_signal_reconnect(conn, CONNECTION_FAILED);
		}
		return;
	}

	fr_assert(0);
}

/** Perform the next step of init and negotiation.
 *
 */
static void conn_init_next(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	connection_t		*conn = talloc_get_type_abort(uctx, connection_t);
	bio_handle_t		*h = talloc_get_type_abort(conn->h, bio_handle_t);

	if (fr_event_fd_insert(h, NULL, conn->el, h->fd, conn_init_writable, NULL, conn_init_error, conn) < 0) {
		PERROR("%s - Failed inserting FD event", h->ctx.module_name);
		connection_signal_reconnect(conn, CONNECTION_FAILED);
	}
}

/** Read the connection during the init and negotiation stage.
 *
 */
static void conn_init_readable(fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	connection_t		*conn = talloc_get_type_abort(uctx, connection_t);
	bio_handle_t		*h = talloc_get_type_abort(conn->h, bio_handle_t);
	trunk_t			*trunk = h->ctx.trunk;
	rlm_radius_t const 	*inst = h->ctx.inst;
	bio_request_t		*u = h->status_u;
	ssize_t			slen;
	fr_pair_list_t		reply;
	uint8_t			code = 0;

	fr_pair_list_init(&reply);
	slen = fr_bio_read(h->bio.main, NULL, h->buffer, h->buflen);
	if (slen == 0) {
		/*
		 *	@todo - set BIO FD EOF callback, so that we don't have to check it here.
		 */
		if (h->ctx.fd_info->eof) goto failed;
		return;
	}

	/*
	 *	We're done reading, return.
	 */
	if (slen == fr_bio_error(IO_WOULD_BLOCK)) return;

	if (slen < 0) {
		switch (errno) {
		case ECONNREFUSED:
			ERROR("%s - Failed reading response from socket: there is no server listening on outgoing connection %s",
			      h->ctx.module_name, h->ctx.fd_info->name);
			break;

		default:
			ERROR("%s - Failed reading response from socket: %s",
			      h->ctx.module_name, fr_syserror(errno));
			break;
		}

	failed:
		connection_signal_reconnect(conn, CONNECTION_FAILED);
		return;
	}

	/*
	 *	Where we just return in this function, we're letting
	 *	the response timer take care of progressing the
	 *	connection attempt.
	 */
	fr_assert(slen >= RADIUS_HEADER_LENGTH); /* checked in verify */

	if (u->id != h->buffer[1]) {
		ERROR("%s - Received response with incorrect or expired ID.  Expected %u, got %u",
		      h->ctx.module_name, u->id, h->buffer[1]);
		return;
	}

	if (decode(h, &reply, &code,
		   h, h->status_request, h->status_u, u->packet + RADIUS_AUTH_VECTOR_OFFSET,
		   h->buffer, slen) != DECODE_FAIL_NONE) return;

	fr_pair_list_free(&reply);	/* FIXME - Do something with these... */

	/*
	 *	Process the error, and count this as a success.
	 *	This is usually used for dynamic configuration
	 *	on startup.
	 */
	if (code == FR_RADIUS_CODE_PROTOCOL_ERROR) protocol_error_reply(u, h);

	/*
	 *	Last trunk event was a failure, be more careful about
	 *	bringing up the connection (require multiple responses).
	 */
	if ((fr_time_gt(trunk->last_failed, fr_time_wrap(0)) && (fr_time_gt(trunk->last_failed, trunk->last_connected))) &&
	    (u->num_replies < inst->num_answers_to_alive)) {
		/*
		 *	Leave the timer in place.  This timer is BOTH when we
		 *	give up on the current status check, AND when we send
		 *	the next status check.
		 */
		DEBUG("%s - Received %u / %u replies for status check, on connection - %s",
		      h->ctx.module_name, u->num_replies, inst->num_answers_to_alive, h->ctx.fd_info->name);
		DEBUG("%s - Next status check packet will be in %pVs",
		      h->ctx.module_name, fr_box_time_delta(fr_time_sub(u->retry.next, fr_time())));

		/*
		 *	Set the timer for the next retransmit.
		 */
		if (fr_timer_at(h, el->tl, &u->ev, u->retry.next, false, conn_init_next, conn) < 0) {
			connection_signal_reconnect(conn, CONNECTION_FAILED);
		}
		return;
	}

	/*
	 *	It's alive!
	 */
	status_check_reset(h, u);

	DEBUG("%s - Connection open - %s", h->ctx.module_name, h->ctx.fd_info->name);

	connection_signal_connected(conn);
}

/** Send initial negotiation.
 *
 */
static void conn_init_writable(fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	connection_t		*conn = talloc_get_type_abort(uctx, connection_t);
	bio_handle_t		*h = talloc_get_type_abort(conn->h, bio_handle_t);
	bio_request_t		*u = h->status_u;
	ssize_t			slen;

	if (fr_time_eq(u->retry.start, fr_time_wrap(0))) {
		u->id = fr_rand() & 0xff;	/* We don't care what the value is here */
		h->status_checking = true;	/* Ensure this is valid */
		fr_retry_init(&u->retry, fr_time(), &h->ctx.inst->retry[u->code]);

	/*
	 *	Status checks can never be retransmitted
	 *	So increment the ID here.
	 */
	} else {
		bio_request_reset(u);
		u->id++;
	}

	DEBUG("%s - Sending %s ID %d over connection %s",
	      h->ctx.module_name, fr_radius_packet_name[u->code], u->id, h->ctx.fd_info->name);

	if (encode(h, h->status_request, u, u->id) < 0) {
	fail:
		connection_signal_reconnect(conn, CONNECTION_FAILED);
		return;
	}
	DEBUG3("Encoded packet");
	HEXDUMP3(u->packet, u->packet_len, NULL);

	fr_assert(u->packet != NULL);
	fr_assert(u->packet_len >= RADIUS_HEADER_LENGTH);

	slen = fr_bio_write(h->bio.main, NULL, u->packet, u->packet_len);

	if (slen == fr_bio_error(IO_WOULD_BLOCK)) goto blocked;

	if (slen < 0) {
		ERROR("%s - Failed sending %s ID %d length %zu over connection %s: %s",
		      h->ctx.module_name, fr_radius_packet_name[u->code], u->id, u->packet_len, h->ctx.fd_info->name, fr_syserror(errno));


		goto fail;
	}

	/*
	 *	@todo - handle partial packets and blocked writes.
	 */
	if ((size_t)slen < u->packet_len) {
	blocked:
		ERROR("%s - Failed sending %s ID %d length %zu over connection %s: writing is blocked",
		      h->ctx.module_name, fr_radius_packet_name[u->code], u->id, u->packet_len, h->ctx.fd_info->name);
		goto fail;
	}

	/*
	 *	Switch to waiting on read and insert the event
	 *	for the response timeout.
	 */
	if (fr_event_fd_insert(h, NULL, conn->el, h->fd, conn_init_readable, NULL, conn_init_error, conn) < 0) {
		PERROR("%s - Failed inserting FD event", h->ctx.module_name);
		goto fail;
	}

	DEBUG("%s - %s request.  Expecting response within %pVs",
	      h->ctx.module_name, (u->retry.count == 1) ? "Originated" : "Retransmitted",
	      fr_box_time_delta(u->retry.rt));

	if (fr_timer_at(h, el->tl, &u->ev, u->retry.next, false, conn_init_timeout, conn) < 0) {
		PERROR("%s - Failed inserting timer event", h->ctx.module_name);
		goto fail;
	}

	/*
	 *	Save a copy of the header + Authentication Vector for checking the response.
	 */
	MEM(u->packet = talloc_memdup(u, u->packet, RADIUS_HEADER_LENGTH));
}

/** Free a connection handle, closing associated resources
 *
 */
static int _bio_handle_free(bio_handle_t *h)
{
	fr_assert(h != NULL);

	fr_assert(h->fd >= 0);

	if (h->status_u) FR_TIMER_DELETE_RETURN(&h->status_u->ev);

	/*
	 *	The connection code will take care of deleting the FD from the event loop.
	 */

	DEBUG("%s - Connection closed - %s", h->ctx.module_name, h->ctx.fd_info->name);

	return 0;
}

static void bio_connected(fr_bio_t *bio)
{
	bio_handle_t		*h = bio->uctx;

	DEBUG("%s - Connection open - %s", h->ctx.module_name, h->ctx.fd_info->name);

	connection_signal_connected(h->conn);
}

static void bio_error(fr_bio_t *bio)
{
	bio_handle_t		*h = bio->uctx;

	DEBUG("%s - Connection failed - %s - %s", h->ctx.module_name, h->ctx.fd_info->name,
	      fr_syserror(h->ctx.fd_info->connect_errno));

	connection_signal_reconnect(h->conn, CONNECTION_FAILED);
}

static fr_bio_verify_action_t rlm_radius_verify(UNUSED fr_bio_t *bio, void *verify_ctx, UNUSED void *packet_ctx, const void *data, size_t *size)
{
	fr_radius_decode_fail_t	failure;
	size_t		in_buffer = *size;
	bio_handle_t	*h = verify_ctx;
	uint8_t const	*hdr = data;
	size_t		want;

	if (in_buffer < 20) {
		*size = RADIUS_HEADER_LENGTH;
		return FR_BIO_VERIFY_WANT_MORE;
	}

	/*
	 *	Packet is too large, discard it.
	 */
	want = fr_nbo_to_uint16(hdr + 2);
	if (want > h->ctx.inst->max_packet_size) {
		ERROR("%s - Connection %s received too long packet", h->ctx.module_name, h->ctx.fd_info->name);
		return FR_BIO_VERIFY_ERROR_CLOSE;
	}

	/*
	 *	Not a full packet, we want more data.
	 */
	if (want < *size) {
		*size = want;
		return FR_BIO_VERIFY_WANT_MORE;
	}

#define REQUIRE_MA(_h) (((_h)->ctx.inst->require_message_authenticator == FR_RADIUS_REQUIRE_MA_YES) || *(_h)->ctx.inst->received_message_authenticator)

	/*
	 *	See if we need to discard the packet.
	 *
	 *	@todo - rate limit these messages, and find a way to associate them with a request, or even
	 *	the logging destination of the module.
	 */
	if (!fr_radius_ok(data, size, h->ctx.inst->max_attributes, REQUIRE_MA(h), &failure)) {
		if (failure == DECODE_FAIL_UNKNOWN_PACKET_CODE) return FR_BIO_VERIFY_DISCARD;

		PERROR("%s - Connection %s received bad packet", h->ctx.module_name, h->ctx.fd_info->name);

		if (failure == DECODE_FAIL_MA_MISSING) {
			if (h->ctx.inst->require_message_authenticator == FR_RADIUS_REQUIRE_MA_YES) {
				ERROR("We are configured with 'require_message_authenticator = true'");
			} else {
				ERROR("We previously received a packet from this client which included a Message-Authenticator attribute");
			}
		}

		if (h->ctx.fd_config.socket_type == SOCK_DGRAM) return FR_BIO_VERIFY_DISCARD;

		return FR_BIO_VERIFY_ERROR_CLOSE;
	}

	/*
	 *	@todo - check if the reply is allowed.  Bad replies are discarded later, but it might be worth
	 *	checking them here.
	 */

	/*
	 *	On input, *size is how much data we have.  On output, *size is how much data we want.
	 */
	return (in_buffer >= *size) ? FR_BIO_VERIFY_OK : FR_BIO_VERIFY_WANT_MORE;
}


/** Initialise a new outbound connection
 *
 * @param[out] h_out	Where to write the new file descriptor.
 * @param[in] conn	to initialise.
 * @param[in] uctx	A #bio_thread_t
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static connection_state_t conn_init(void **h_out, connection_t *conn, void *uctx)
{
	int			fd;
	bio_handle_t		*h;
	bio_handle_ctx_t	*ctx = uctx; /* thread or home server */
	connection_t		**to_save = NULL;

	MEM(h = talloc_zero(conn, bio_handle_t));
	h->ctx = *ctx;
	h->conn = conn;
	h->max_packet_size = h->ctx.inst->max_packet_size;
	h->last_idle = fr_time();

	MEM(h->buffer = talloc_array(h, uint8_t, h->max_packet_size));
	h->buflen = h->max_packet_size;

	MEM(h->tt = radius_track_alloc(h));

	/*
	 *	We are proxying to multiple home servers, but using a limited port range.  We must track the
	 *	source port for each home server, so that we only can select the right unused source port for
	 *	this home server.
	 */
	switch (ctx->limit_source_ports) {
	case LIMIT_PORTS_NONE:
		break;

	/*
	 *	Dynamic home servers store source port usage in the home_server_t
	 */
	case LIMIT_PORTS_DYNAMIC:
	{
		int i;
		home_server_t *home = talloc_get_type_abort(ctx, home_server_t);

		for (i = 0; i < home->num_ports; i++) {
			if (!home->connections[i]) {
				to_save = &home->connections[i];

				/*
				 *	Set the source port, but also leave the src_port_start and
				 *	src_port_end alone.
				 */
				h->ctx.fd_config.src_port = h->ctx.fd_config.src_port_start + i;
				break;
			}
		}

		if (!to_save) {
			ERROR("%s - Failed opening socket to home server %pV:%u - source port range is full",
			      h->ctx.module_name, fr_box_ipaddr(h->ctx.fd_config.dst_ipaddr), h->ctx.fd_config.dst_port);
			goto fail;
		}
	}
		break;

	/*
	 *	Static home servers store source port usage in bio_thread_t
	 */
	case LIMIT_PORTS_STATIC:
	{
		int i;
		bio_thread_t *thread = talloc_get_type_abort(ctx, bio_thread_t);

		for (i = 0; i < thread->num_ports; i++) {
			if (!thread->connections[i]) {
				to_save = &thread->connections[i];
				h->ctx.fd_config.src_port = h->ctx.fd_config.src_port_start + i;
				break;
			}
		}

		if (!to_save) {
			ERROR("%s - Failed opening socket to home server %pV:%u - source port range is full",
			      h->ctx.module_name, fr_box_ipaddr(h->ctx.fd_config.dst_ipaddr), h->ctx.fd_config.dst_port);
			goto fail;
		}
	}
		break;
	}

	h->bio.fd = fr_bio_fd_alloc(h, &h->ctx.fd_config, 0);
	if (!h->bio.fd) {
		PERROR("%s - failed opening socket", h->ctx.module_name);
	fail:
		talloc_free(h);
		return CONNECTION_STATE_FAILED;
	}

	h->bio.fd->uctx = h;
	h->ctx.fd_info = fr_bio_fd_info(h->bio.fd);

	fd = h->ctx.fd_info->socket.fd;
	fr_assert(fd >= 0);

	/*
	 *	Create a memory BIO for stream sockets.  We want to return only complete packets, and not
	 *	partial packets.
	 *
	 *	@todo - maybe we want to have a fr_bio_verify_t which is independent of fr_bio_mem_t.  That
	 *	way we don't need a memory BIO for UDP sockets, but we can still add a verification layer for
	 *	UDP sockets?
	 */
	h->bio.mem = fr_bio_mem_alloc(h, (h->ctx.fd_config.socket_type == SOCK_DGRAM) ? 0 : h->ctx.inst->max_packet_size * 4,
				      0, h->bio.fd);
	if (!h->bio.mem) {
		PERROR("%s - Failed allocating memory buffer - ", h->ctx.module_name);
		goto fail;
	}

	if (fr_bio_mem_set_verify(h->bio.mem, rlm_radius_verify, h, (h->ctx.fd_config.socket_type == SOCK_DGRAM)) < 0) {
		PERROR("%s - Failed setting validation callback - ", h->ctx.module_name);
		goto fail;
	}

	/*
	 *	Set the BIO read function to be the memory BIO, which will then call the packet verification
	 *	routine.
	 */
	h->bio.main = h->bio.mem;
	h->bio.mem->uctx = h;

	h->fd = fd;

	talloc_set_destructor(h, _bio_handle_free);

	/*
	 *	If the socket isn't connected, then do that first.
	 */
	if (h->ctx.fd_info->state != FR_BIO_FD_STATE_OPEN) {
		int rcode;

		fr_assert(h->ctx.fd_info->state == FR_BIO_FD_STATE_CONNECTING);

		/*
		 *	We don't pass timeouts here because the trunk has it's own connection timeouts.
		 */
		rcode = fr_bio_fd_connect_full(h->bio.fd, conn->el, bio_connected, bio_error, NULL, NULL);
		if (rcode < 0) goto fail;

		*h_out = h;

		if (rcode == 0) return CONNECTION_STATE_CONNECTING;

		fr_assert(rcode == 1);
		return CONNECTION_STATE_CONNECTED;

		/*
		 *	If we're doing status checks, then we want at least
		 *	one positive response before signalling that the
		 *	connection is open.
		 *
		 *	To do this we install special I/O handlers that
		 *	only signal the connection as open once we get a
		 *	status-check response.
		 */
	} if (h->ctx.inst->status_check) {
		status_check_alloc(h);

		/*
		 *	Start status checking.
		 *
		 *	If we've had no recent failures we need exactly
		 *	one response to bring the connection online,
		 *	otherwise we need inst->num_answers_to_alive
		 */
		if (fr_event_fd_insert(h, NULL, conn->el, h->fd, NULL,
				       conn_init_writable, conn_init_error, conn) < 0) goto fail;

		/*
		 *	If we're not doing status-checks, signal the connection
		 *	as open as soon as it becomes writable.
		 */
	} else {
		connection_signal_on_fd(conn, fd);
	}

	*h_out = h;

	if (to_save) *to_save = conn;

	return CONNECTION_STATE_CONNECTING;
}

/** Shutdown/close a file descriptor
 *
 */
static void conn_close(UNUSED fr_event_list_t *el, void *handle, void *uctx)
{
	bio_handle_t *h = talloc_get_type_abort(handle, bio_handle_t);

	/*
	 *	There's tracking entries still allocated
	 *	this is bad, they should have all been
	 *	released.
	 */
	if (h->tt && (h->tt->num_requests != 0)) {
#ifndef NDEBUG
		radius_track_state_log(&default_log, L_ERR, __FILE__, __LINE__, h->tt, bio_tracking_entry_log);
#endif
		fr_assert_fail("%u tracking entries still allocated at conn close", h->tt->num_requests);
	}

	/*
	 *	We have opened a limited number of outbound source ports.  This means that when we close a
	 *	port, we have to mark it unused.
	 */
	switch (h->ctx.limit_source_ports) {
	case LIMIT_PORTS_NONE:
		break;

	case LIMIT_PORTS_DYNAMIC:
	{
		int offset;
		home_server_t *home = talloc_get_type_abort(uctx, home_server_t);

		fr_assert(h->ctx.fd_config.src_port >= h->ctx.fd_config.src_port_start);
		fr_assert(h->ctx.fd_config.src_port < h->ctx.fd_config.src_port_end);

		offset = h->ctx.fd_config.src_port - h->ctx.fd_config.src_port_start;
		fr_assert(offset < home->num_ports);

		fr_assert(home->connections[offset] == h->conn);

		home->connections[offset] = NULL;
	}
		break;

	case LIMIT_PORTS_STATIC:
	{
		int offset;
		bio_thread_t *thread = talloc_get_type_abort(uctx, bio_thread_t);

		fr_assert(h->ctx.fd_config.src_port >= h->ctx.fd_config.src_port_start);
		fr_assert(h->ctx.fd_config.src_port < h->ctx.fd_config.src_port_end);

		offset = h->ctx.fd_config.src_port - h->ctx.fd_config.src_port_start;
		fr_assert(offset < thread->num_ports);

		fr_assert(thread->connections[offset] == h->conn);

		thread->connections[offset] = NULL;
	}
		break;
	}

	DEBUG4("Freeing handle %p", handle);

	talloc_free(h);
}

/** Connection failed
 *
 * @param[in] handle   	of connection that failed.
 * @param[in] state	the connection was in when it failed.
 * @param[in] uctx	UNUSED.
 */
static connection_state_t conn_failed(void *handle, connection_state_t state, UNUSED void *uctx)
{
	switch (state) {
	/*
	 *	If the connection was connected when it failed,
	 *	we need to handle any outstanding packets and
	 *	timer events before reconnecting.
	 */
	case CONNECTION_STATE_CONNECTED:
	{
		bio_handle_t	*h = talloc_get_type_abort(handle, bio_handle_t); /* h only available if connected */

		/*
		 *	Reset the Status-Server checks.
		 */
		if (h->status_u) FR_TIMER_DISARM(h->status_u->ev);
		break;

	default:
		break;
	}
	}

	return CONNECTION_STATE_INIT;
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static connection_t *thread_conn_alloc(trunk_connection_t *tconn, fr_event_list_t *el,
					  connection_conf_t const *conf,
					  char const *log_prefix, void *uctx)
{
	connection_t		*conn;
	bio_handle_ctx_t	*ctx = uctx; /* thread or home server */

	conn = connection_alloc(tconn, el,
				   &(connection_funcs_t){
					.init = conn_init,
					.close = conn_close,
					.failed = conn_failed
				   },
				   conf,
				   log_prefix,
				   uctx);
	if (!conn) {
		PERROR("%s - Failed allocating state handler for new connection", ctx->inst->name);
		return NULL;
	}
	ctx->trunk = tconn->trunk;
	ctx->module_name = log_prefix;

	return conn;
}

/** Read and discard data
 *
 */
static void conn_discard(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	bio_handle_t		*h = talloc_get_type_abort(tconn->conn->h, bio_handle_t);
	uint8_t			buffer[4096];
	ssize_t			slen;

	while ((slen = fr_bio_read(h->bio.main, NULL, buffer, sizeof(buffer))) > 0);

	if (slen < 0) {
		switch (errno) {
		case EBADF:
		case ECONNRESET:
		case ENOTCONN:
		case ETIMEDOUT:
			ERROR("%s - Failed draining socket: %s", h->ctx.module_name, fr_syserror(errno));
			trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
			break;

		default:
			break;
		}
	}
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
	bio_handle_t		*h = talloc_get_type_abort(conn->h, bio_handle_t);

	if (fd_errno) ERROR("%s - Connection %s failed: %s", h->ctx.module_name, h->ctx.fd_info->name, fr_syserror(fd_errno));

	connection_signal_reconnect(conn, CONNECTION_FAILED);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void thread_conn_notify(trunk_connection_t *tconn, connection_t *conn,
			       fr_event_list_t *el,
			       trunk_connection_event_t notify_on, UNUSED void *uctx)
{
	bio_handle_t		*h = talloc_get_type_abort(conn->h, bio_handle_t);
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
	case TRUNK_CONN_EVENT_NONE:
		read_fn = conn_discard;
		break;

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

	/*
	 *	Over-ride read for replication.
	 */
	if (h->ctx.inst->mode == RLM_RADIUS_MODE_REPLICATE) {
		read_fn = conn_discard;

		if (fr_bio_fd_write_only(h->bio.fd) < 0) {
			PERROR("%s - Failed setting socket to write-only", h->ctx.module_name);
			trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
			return;
		}
	}

	if (fr_event_fd_insert(h, NULL, el, h->fd,
			       read_fn,
			       write_fn,
			       conn_error,
			       tconn) < 0) {
		PERROR("%s - Failed inserting FD event", h->ctx.module_name);

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
	bio_request_t const *a = one;
	bio_request_t const *b = two;
	int8_t ret;

	/*
	 *	Prioritise status check packets
	 */
	ret = (b->status_check - a->status_check);
	if (ret != 0) return ret;

	/*
	 *	Larger priority is more important.
	 */
	ret = CMP(a->priority, b->priority);
	if (ret != 0) return ret;

	/*
	 *	Smaller timestamp (i.e. earlier) is more important.
	 */
	return CMP_PREFER_SMALLER(fr_time_unwrap(a->recv_time), fr_time_unwrap(b->recv_time));
}

/** Decode response packet data, extracting relevant information and validating the packet
 *
 * @param[in] ctx			to allocate pairs in.
 * @param[out] reply			Pointer to head of pair list to add reply attributes to.
 * @param[out] response_code		The type of response packet.
 * @param[in] h				connection handle.
 * @param[in] request			the request.
 * @param[in] u				UDP request.
 * @param[in] request_authenticator	from the original request.
 * @param[in] data			to decode.
 * @param[in] data_len			Length of input data.
 * @return
 *	- DECODE_FAIL_NONE on success.
 *	- DECODE_FAIL_* on failure.
 */
static fr_radius_decode_fail_t decode(TALLOC_CTX *ctx, fr_pair_list_t *reply, uint8_t *response_code,
			    bio_handle_t *h, request_t *request, bio_request_t *u,
			    uint8_t const request_authenticator[static RADIUS_AUTH_VECTOR_LENGTH],
			    uint8_t *data, size_t data_len)
{
	rlm_radius_t const	*inst = talloc_get_type_abort_const(h->ctx.inst, rlm_radius_t);
	uint8_t			code;
	fr_radius_decode_ctx_t	decode_ctx;

	*response_code = 0;	/* Initialise to keep the rest of the code happy */

	RHEXDUMP3(data, data_len, "Read packet");

	decode_ctx = (fr_radius_decode_ctx_t) {
		.common = &h->ctx.radius_ctx,
		.request_code = u->code,
		.request_authenticator = request_authenticator,
		.tmp_ctx = talloc(ctx, uint8_t),
		.end = data + data_len,
		.verify = true,
		.require_message_authenticator = REQUIRE_MA(h),
	};

	if (fr_radius_decode(ctx, reply, data, data_len, &decode_ctx) < 0) {
		talloc_free(decode_ctx.tmp_ctx);
		RPEDEBUG("Failed reading packet");
		return DECODE_FAIL_UNKNOWN;
	}
	talloc_free(decode_ctx.tmp_ctx);

	code = data[0];

	RDEBUG("Received %s ID %d length %zu reply packet on connection %s",
	       fr_radius_packet_name[code], data[1], data_len, h->ctx.fd_info->name);
	log_request_pair_list(L_DBG_LVL_2, request, NULL, reply, NULL);

	/*
	 *	This code is for BlastRADIUS mitigation.
	 *
	 *	The scenario where this applies is where we send Message-Authenticator
	 *	but the home server doesn't support it or require it, in which case
	 *	the response can be manipulated by an attacker.
	 */
	if ((u->code == FR_RADIUS_CODE_ACCESS_REQUEST) &&
	    (inst->require_message_authenticator == FR_RADIUS_REQUIRE_MA_AUTO) &&
	    !*(inst->received_message_authenticator) &&
	    fr_pair_find_by_da(reply, NULL, attr_message_authenticator) &&
	    !fr_pair_find_by_da(reply, NULL, attr_eap_message)) {
		RINFO("Packet contained a valid Message-Authenticator.  Setting \"require_message_authenticator = yes\"");
		*(inst->received_message_authenticator) = true;
	}

	*response_code = code;

	/*
	 *	Record the fact we've seen a response
	 */
	u->num_replies++;

	/*
	 *	Fixup retry times
	 */
	if (fr_time_gt(u->retry.start, h->mrs_time)) h->mrs_time = u->retry.start;

	return DECODE_FAIL_NONE;
}

static int encode(bio_handle_t *h, request_t *request, bio_request_t *u, uint8_t id)
{
	ssize_t			packet_len;
	fr_radius_encode_ctx_t	encode_ctx;
	rlm_radius_t const	*inst = h->ctx.inst;

	fr_assert(inst->allowed[u->code]);
	fr_assert(!u->packet);

	u->packet_len = inst->max_packet_size;
	u->packet = h->buffer;

	/*
	 *	We should have at minimum 64-byte packets, so don't
	 *	bother doing run-time checks here.
	 */
	fr_assert(u->packet_len >= (size_t) RADIUS_HEADER_LENGTH);

	encode_ctx = (fr_radius_encode_ctx_t) {
		.common = &h->ctx.radius_ctx,
		.rand_ctx = (fr_fast_rand_t) {
			.a = fr_rand(),
			.b = fr_rand(),
		},
		.code = u->code,
		.id = id,
		.add_proxy_state = u->proxied,
	};

	/*
	 *	If we're sending a status check packet, update any
	 *	necessary timestamps.  Also, don't add Proxy-State, as
	 *	we're originating the packet.
	 */
	if (u->status_check) {
		fr_pair_t *vp;

		vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_event_timestamp);
		if (vp) vp->vp_date = fr_time_to_unix_time(u->retry.updated);

		encode_ctx.add_proxy_state = false;
	}

	/*
	 *	Encode it, leaving room for Proxy-State if necessary.
	 */
	packet_len = fr_radius_encode(&FR_DBUFF_TMP(u->packet, u->packet_len),
				      &request->request_pairs, &encode_ctx);
	if (fr_pair_encode_is_error(packet_len)) {
		RPERROR("Failed encoding packet");

	error:
		TALLOC_FREE(u->packet);
		return -1;
	}

	if (packet_len < 0) {
		size_t have;
		size_t need;

		have = u->packet_len;
		need = have - packet_len;

		if (need > RADIUS_MAX_PACKET_SIZE) {
			RERROR("Failed encoding packet.  Have %zu bytes of buffer, need %zu bytes",
			       have, need);
		} else {
			RERROR("Failed encoding packet.  Have %zu bytes of buffer, need %zu bytes.  "
			       "Increase 'max_packet_size'", have, need);
		}

		goto error;
	}
	/*
	 *	The encoded packet should NOT over-run the input buffer.
	 */
	fr_assert((size_t) packet_len <= u->packet_len);

	/*
	 *	Add Proxy-State to the tail end of the packet.
	 *
	 *	We need to add it here, and NOT in
	 *	request->request_pairs, because multiple modules
	 *	may be sending the packets at the same time.
	 */
	if (encode_ctx.add_proxy_state) {
		fr_pair_t	*vp;

		MEM(vp = fr_pair_afrom_da(u, attr_proxy_state));
		fr_pair_value_memdup(vp, (uint8_t const *) &inst->common_ctx.proxy_state, sizeof(inst->common_ctx.proxy_state), false);
		fr_pair_append(&u->extra, vp);
		packet_len += 2 + sizeof(inst->common_ctx.proxy_state);
	}

	/*
	 *	Update our version of the packet length.
	 */
	u->packet_len = packet_len;

	/*
	 *	Now that we're done mangling the packet, sign it.
	 */
	if (fr_radius_sign(u->packet, NULL, (uint8_t const *) h->ctx.radius_ctx.secret,
			   h->ctx.radius_ctx.secret_length) < 0) {
		RPERROR("Failed signing packet");
		goto error;
	}

	return 0;
}


/** Revive a connection after "revive_interval"
 *
 */
static void revive_timeout(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	bio_handle_t	 	*h = talloc_get_type_abort(tconn->conn->h, bio_handle_t);

	INFO("%s - Reviving connection %s", h->ctx.module_name, h->ctx.fd_info->name);
	trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
}

/** Mark a connection dead after "zombie_interval"
 *
 */
static void zombie_timeout(fr_timer_list_t *tl, fr_time_t now, void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	bio_handle_t	 	*h = talloc_get_type_abort(tconn->conn->h, bio_handle_t);

	INFO("%s - No replies during 'zombie_period', marking connection %s as dead", h->ctx.module_name, h->ctx.fd_info->name);

	/*
	 *	Don't use this connection, and re-queue all of its
	 *	requests onto other connections.
	 */
	(void) trunk_connection_requests_requeue(tconn, TRUNK_REQUEST_STATE_ALL, 0, false);

	/*
	 *	We do have status checks.  Try to reconnect the
	 *	connection immediately.  If the status checks pass,
	 *	then the connection will be marked "alive"
	 */
	if (h->ctx.inst->status_check) {
		trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
		return;
	}

	/*
	 *	Revive the connection after a time.
	 */
	if (fr_timer_at(h, tl, &h->zombie_ev,
			fr_time_add(now, h->ctx.inst->revive_interval), false,
			revive_timeout, tconn) < 0) {
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
static bool check_for_zombie(fr_event_list_t *el, trunk_connection_t *tconn, fr_time_t now, fr_time_t last_sent)
{
	bio_handle_t	*h = talloc_get_type_abort(tconn->conn->h, bio_handle_t);

	/*
	 *	We're replicating, and don't care about the health of
	 *	the home server, and this function should not be called.
	 */
	fr_assert(h->ctx.inst->mode != RLM_RADIUS_MODE_REPLICATE);

	/*
	 *	If we're status checking OR already zombie, don't go to zombie
	 */
	if (h->status_checking || fr_timer_armed(h->zombie_ev)) return true;

	if (fr_time_eq(now, fr_time_wrap(0))) now = fr_time();

	/*
	 *	We received a reply since this packet was sent, the connection isn't zombie.
	 */
	if (fr_time_gteq(h->last_reply, last_sent)) return false;

	/*
	 *	If we've seen ANY response in the allowed window, then the connection is still alive.
	 */
	if ((h->ctx.inst->mode == RLM_RADIUS_MODE_PROXY) && fr_time_gt(last_sent, fr_time_wrap(0)) &&
	    (fr_time_lt(fr_time_add(last_sent, h->ctx.inst->response_window), now))) return false;

	/*
	 *	Stop using it for new requests.
	 */
	WARN("%s - Entering Zombie state - connection %s", h->ctx.module_name, h->ctx.fd_info->name);
	trunk_connection_signal_inactive(tconn);

	if (h->ctx.inst->status_check) {
		h->status_checking = true;

		/*
		 *	Queue up the status check packet.  It will be sent
		 *	when the connection is writable.
		 */
		h->status_u->retry.start = fr_time_wrap(0);
		h->status_u->treq = NULL;

		if (trunk_request_enqueue_on_conn(&h->status_u->treq, tconn, h->status_request,
						     h->status_u, h->status_u, true) != TRUNK_ENQUEUE_OK) {
			trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
		}
	} else {
		if (fr_timer_at(h, el->tl, &h->zombie_ev, fr_time_add(now, h->ctx.inst->zombie_period),
				false, zombie_timeout, tconn) < 0) {
			ERROR("Failed inserting zombie timeout for connection");
			trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
		}
	}

	return true;
}

static void mod_dup(request_t *request, bio_request_t *u)
{
	bio_handle_t *h;

	h = talloc_get_type_abort(u->treq->tconn->conn->h, bio_handle_t);

	if (h->ctx.fd_config.socket_type != SOCK_DGRAM) {
		RDEBUG("Using stream sockets - suppressing retransmission");
		return;
	}

	/*
	 *	Arguably this should never happen for UDP sockets.
	 */
	if (h->ctx.fd_info->write_blocked) {
		RDEBUG("IO is blocked - suppressing retransmission");
		return;
	}
	u->is_retry = true;

	/*
	 *	We are doing synchronous proxying, retransmit
	 *	the current request on the same connection.
	 *
	 *	If it's zombie, we still resend it.  If the
	 *	connection is dead, then a callback will move
	 *	this request to a new connection.
	 */
	mod_write(request, u->treq, h);
}

static void do_retry(rlm_radius_t const *inst, bio_request_t *u, request_t *request, fr_retry_t const *retry);

/** Handle module retries.
 *
 */
static void mod_retry(module_ctx_t const *mctx, request_t *request, fr_retry_t const *retry)
{
	bio_request_t		*u = talloc_get_type_abort(mctx->rctx, bio_request_t);
	rlm_radius_t const     	*inst = talloc_get_type_abort(mctx->mi->data, rlm_radius_t);

	do_retry(inst, u, request, retry);
}

static void do_retry(rlm_radius_t const *inst, bio_request_t *u, request_t *request, fr_retry_t const *retry)
{
	trunk_request_t		*treq;
	trunk_connection_t	*tconn;
	fr_time_t		now;

	if (!u->treq) {
		RDEBUG("Packet was cancelled by the connection handler - ignoring retry");
		return;
	}

	treq = talloc_get_type_abort(u->treq, trunk_request_t);

	fr_assert(request == treq->request);
	fr_assert(treq->preq);						/* Must still have a protocol request */
	fr_assert(treq->preq == u);

	tconn = treq->tconn;
	now = retry->updated;

	switch (retry->state) {
	case FR_RETRY_CONTINUE:
		u->retry = *retry;

		switch (treq->state) {
		case TRUNK_REQUEST_STATE_INIT:
		case TRUNK_REQUEST_STATE_UNASSIGNED:
			fr_assert(0);
			break;

		case TRUNK_REQUEST_STATE_BACKLOG:
			RDEBUG("Packet is still in the backlog queue to be sent - suppressing retransmission");
			return;

		case TRUNK_REQUEST_STATE_PENDING:
			RDEBUG("Packet is still in the pending queue to be sent - suppressing retransmission");
			return;

		case TRUNK_REQUEST_STATE_PARTIAL:
			RDEBUG("Packet was partially written, as IO is blocked - suppressing retransmission");
			return;

		case TRUNK_REQUEST_STATE_SENT:
			fr_assert(tconn);

			mod_dup(request, u);
			return;

		case TRUNK_REQUEST_STATE_REAPABLE:
		case TRUNK_REQUEST_STATE_COMPLETE:
		case TRUNK_REQUEST_STATE_FAILED:
		case TRUNK_REQUEST_STATE_CANCEL:
		case TRUNK_REQUEST_STATE_CANCEL_SENT:
		case TRUNK_REQUEST_STATE_CANCEL_PARTIAL:
		case TRUNK_REQUEST_STATE_CANCEL_COMPLETE:
			fr_assert(0);
			break;
		}
		break;

	case FR_RETRY_MRD:
		REDEBUG("Reached maximum_retransmit_duration (%pVs > %pVs), failing request",
			fr_box_time_delta(fr_time_sub(now, retry->start)), fr_box_time_delta(retry->config->mrd));
		break;

	case FR_RETRY_MRC:
		REDEBUG("Reached maximum_retransmit_count (%u > %u), failing request",
		        retry->count, retry->config->mrc);
		break;
	}

	u->rcode = RLM_MODULE_FAIL;
	trunk_request_signal_fail(treq);

	/*
	 *	We don't do zombie stuff!
	 */
	if (!tconn || (inst->mode == RLM_RADIUS_MODE_REPLICATE)) return;

	check_for_zombie(unlang_interpret_event_list(request), tconn, now, retry->start);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void request_mux(UNUSED fr_event_list_t *el,
			trunk_connection_t *tconn, connection_t *conn, UNUSED void *uctx)
{
	bio_handle_t		*h = talloc_get_type_abort(conn->h, bio_handle_t);
	trunk_request_t		*treq;
	request_t		*request;

	if (unlikely(trunk_connection_pop_request(&treq, tconn) < 0)) return;

	/*
	 *	No more requests to send
	 */
	if (!treq) return;

	request = treq->request;

	mod_write(request, treq, h);
}

static void mod_write(request_t *request, trunk_request_t *treq, bio_handle_t *h)
{
	rlm_radius_t const	*inst = h->ctx.inst;
	bio_request_t		*u;
	char const		*action;
	uint8_t const		*packet;
	size_t			packet_len;
	ssize_t			slen;

	u = treq->preq;

	fr_assert((treq->state == TRUNK_REQUEST_STATE_PENDING) ||
		  (treq->state == TRUNK_REQUEST_STATE_PARTIAL) ||
		  ((u->retry.count > 0) && (treq->state == TRUNK_REQUEST_STATE_SENT)));

	fr_assert(!u->status_check);

	/*
	 *	If it's a partial packet, then write the partial bit.
	 */
	if (u->partial) {
		fr_assert(u->partial < u->packet_len);
		packet = u->packet + u->partial;
		packet_len = u->packet_len - u->partial;
		goto do_write;
	}

	/*
	 *	No previous packet, OR can't retransmit the
	 *	existing one.  Oh well.
	 *
	 *	Note that if we can't retransmit the previous
	 *	packet, then u->rr MUST already have been
	 *	deleted in the request_cancel() function
	 *	or request_release_conn() function when
	 *	the REQUEUE signal was received.
	 */
	if (!u->packet) {
		fr_assert(!u->rr);

		if (unlikely(radius_track_entry_reserve(&u->rr, treq, h->tt, request, u->code, treq) < 0)) {
#ifndef NDEBUG
			radius_track_state_log(&default_log, L_ERR, __FILE__, __LINE__,
					       h->tt, bio_tracking_entry_log);
#endif
			fr_assert_fail("Tracking entry allocation failed: %s", fr_strerror());
			trunk_request_signal_fail(treq);
			return;
		}
		fr_assert(u->rr);
		u->id = u->rr->id;

		RDEBUG("Sending %s ID %d length %zu over connection %s",
		       fr_radius_packet_name[u->code], u->id, u->packet_len, h->ctx.fd_info->name);

		if (encode(h, request, u, u->id) < 0) {
			/*
			 *	Need to do this because request_conn_release
			 *	may not be called.
			 */
			bio_request_reset(u);
			trunk_request_signal_fail(treq);
			return;
		}
		RHEXDUMP3(u->packet, u->packet_len, "Encoded packet");

		/*
		 *	Remember the authentication vector, which now has the
		 *	packet signature.
		 */
		(void) radius_track_entry_update(u->rr, u->packet + RADIUS_AUTH_VECTOR_OFFSET);
	} else {
		RDEBUG("Retransmitting %s ID %d length %zu over connection %s",
		       fr_radius_packet_name[u->code], u->id, u->packet_len, h->ctx.fd_info->name);
	}

	/*
	 *	@todo - When logging Message-Authenticator, don't print its' value.
	 */
	log_request_proto_pair_list(L_DBG_LVL_2, request, NULL, &request->request_pairs, NULL);
	if (!fr_pair_list_empty(&u->extra)) log_request_proto_pair_list(L_DBG_LVL_2, request, NULL, &u->extra, NULL);

	packet = u->packet;
	packet_len = u->packet_len;

do_write:
	fr_assert(packet != NULL);
	fr_assert(packet_len >= RADIUS_HEADER_LENGTH);

	slen = fr_bio_write(h->bio.main, NULL, packet, packet_len);

	/*
	 *	Can't write anything, requeue it on a different socket.
	 */
	if (slen == fr_bio_error(IO_WOULD_BLOCK)) goto requeue;

	if (slen < 0) {
		switch (errno) {
		/*
		 *	There is an error in the request.
		 */
		case EMSGSIZE:		/* Packet size exceeds max size allowed on socket */
			ERROR("%s - Failed sending data over connection %s: %s",
			      h->ctx.module_name, h->ctx.fd_info->name, fr_syserror(errno));
			trunk_request_signal_fail(treq);
			break;

		/*
		 *	There is an error in the connection.  The reconnection will re-queue any pending or
		 *	sent requests, so we don't have to do any cleanup.
		 */
		default:
			ERROR("%s - Failed sending data over connection %s: %s",
			      h->ctx.module_name, h->ctx.fd_info->name, fr_syserror(errno));
			trunk_connection_signal_reconnect(treq->tconn, CONNECTION_FAILED);
			break;
		}

		return;
	}

	/*
	 *	No data to send, ignore the write for partials, but otherwise requeue it.
	 */
	if (slen == 0) {
		if (u->partial) return;

	requeue:
		RWARN("%s - Failed sending data over connection %s: sent zero bytes",
		      h->ctx.module_name, h->ctx.fd_info->name);
		trunk_request_requeue(treq);
		return;
	}

	packet_len += slen;
	if (packet_len < u->packet_len) {
		/*
		 *	The first time around, save a copy of the packet for later writing.
		 */
		if (!u->partial) MEM(u->packet = talloc_memdup(u, u->packet, u->packet_len));

		u->partial = packet_len;
		trunk_request_signal_partial(treq);
		return;
	}

	/*
	 *	For retransmissions.
	 */
	u->partial = 0;

	/*
	 *	Don't print anything extra for replication.
	 */
	if (inst->mode == RLM_RADIUS_MODE_REPLICATE) {
		u->rcode = RLM_MODULE_OK;
		trunk_request_signal_complete(treq);
		return;
	}

	/*
	 *	On first packet, signal it as sent, and update stats.
	 *
	 *	Later packets are just retransmissions to the BIO, and don't need to involve
	 *	the trunk code.
	 */
	if (u->retry.count == 1) {
		h->last_sent = u->retry.start;
		if (fr_time_lteq(h->first_sent, h->last_idle)) h->first_sent = h->last_sent;

		trunk_request_signal_sent(treq);

		action = u->proxied ? "Proxied" : "Originated";

	} else {
		/*
		 *	We don't signal the trunk that it's been sent, it was already senty
		 */
		action = "Retransmitted";
	}

	fr_assert(!u->status_check);

	if (!u->proxied) {
		RDEBUG("%s request.  Expecting response within %pVs", action,
		       fr_box_time_delta(u->retry.rt));

	} else {
		/*
		 *	If the packet doesn't get a response,
		 *	then bio_request_free() will notice, and run conn_zombie()
		 */
		RDEBUG("%s request.  Relying on NAS to perform more retransmissions", action);
	}

	/*
	 *	We don't retransmit over TCP.
	 */
	if (h->ctx.fd_config.socket_type != SOCK_DGRAM) return;

	/*
	 *	If we only send one datagram packet, then don't bother saving it.
	 */
	if (u->retry.config && u->retry.config->mrc == 1) {
		u->packet = NULL;
		return;
	}

	MEM(u->packet = talloc_memdup(u, u->packet, u->packet_len));
}

/** Deal with Protocol-Error replies, and possible negotiation
 *
 */
static void protocol_error_reply(bio_request_t *u, bio_handle_t *h)
{
	bool	  	error_601 = false;
	uint32_t  	response_length = 0;
	uint8_t const	*attr, *end;

	end = h->buffer + fr_nbo_to_uint16(h->buffer + 2);

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

		DEBUG("%s - Increasing buffer size to %u for connection %s", h->ctx.module_name, response_length, h->ctx.fd_info->name);

		/*
		 *	Make sure to copy the packet over!
		 */
		attr = h->buffer;
		h->buflen = response_length;
		MEM(h->buffer = talloc_array(h, uint8_t, h->buflen));

		memcpy(h->buffer, attr, end - attr);
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


/** Handle retries for a status check
 *
 */
static void status_check_next(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t now, void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);
	bio_handle_t		*h = talloc_get_type_abort(tconn->conn->h, bio_handle_t);

	if (trunk_request_enqueue_on_conn(&h->status_u->treq, tconn, h->status_request,
					     h->status_u, h->status_u, true) != TRUNK_ENQUEUE_OK) {
		trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
	}
}


/** Deal with replies replies to status checks and possible negotiation
 *
 */
static void status_check_reply(trunk_request_t *treq, fr_time_t now)
{
	bio_handle_t		*h = talloc_get_type_abort(treq->tconn->conn->h, bio_handle_t);
	rlm_radius_t const 	*inst = h->ctx.inst;
	bio_request_t		*u = talloc_get_type_abort(treq->rctx, bio_request_t);

	fr_assert(treq->preq == h->status_u);
	fr_assert(treq->rctx == h->status_u);

	u->treq = NULL;

	/*
	 *	@todo - do other negotiation and signaling.
	 */
	if (h->buffer[0] == FR_RADIUS_CODE_PROTOCOL_ERROR) protocol_error_reply(u, h);

	if (u->num_replies < inst->num_answers_to_alive) {
		DEBUG("Received %u / %u replies for status check, on connection - %s",
		      u->num_replies, inst->num_answers_to_alive, h->ctx.fd_info->name);
		DEBUG("Next status check packet will be in %pVs", fr_box_time_delta(fr_time_sub(u->retry.next, now)));

		/*
		 *	Set the timer for the next retransmit.
		 */
		if (fr_timer_at(h, h->ctx.el->tl, &u->ev, u->retry.next, false, status_check_next, treq->tconn) < 0) {
			trunk_connection_signal_reconnect(treq->tconn, CONNECTION_FAILED);
		}
		return;
	}

	DEBUG("Received enough replies to status check, marking connection as active - %s", h->ctx.fd_info->name);

	/*
	 *	Set the "last idle" time to now, so that we don't
	 *	restart zombie_period until sufficient time has
	 *	passed.
	 */
	h->last_idle = fr_time();

	/*
	 *	Reset retry interval and retransmission counters
	 *	also frees u->ev.
	 */
	status_check_reset(h, u);
	trunk_connection_signal_active(treq->tconn);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void request_demux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn, connection_t *conn, UNUSED void *uctx)
{
	bio_handle_t		*h = talloc_get_type_abort(conn->h, bio_handle_t);

	DEBUG3("%s - Reading data for connection %s", h->ctx.module_name, h->ctx.fd_info->name);

	while (true) {
		ssize_t			slen;

		trunk_request_t	*treq;
		request_t		*request;
		bio_request_t		*u;
		radius_track_entry_t	*rr;
		fr_radius_decode_fail_t	reason;
		uint8_t			code = 0;
		fr_pair_list_t		reply;
		fr_pair_t		*vp;

		fr_time_t		now;

		fr_pair_list_init(&reply);

		/*
		 *	Drain the socket of all packets.  If we're busy, this
		 *	saves a round through the event loop.  If we're not
		 *	busy, a few extra system calls don't matter.
		 */
		slen = fr_bio_read(h->bio.main, NULL, h->buffer, h->buflen);
		if (slen == 0) {
			/*
			 *	@todo - set BIO FD EOF callback, so that we don't have to check it here.
			 */
			if (h->ctx.fd_info->eof) trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
			return;
		}

		/*
		 *	We're done reading, return.
		 */
		if (slen == fr_bio_error(IO_WOULD_BLOCK)) return;

		if (slen < 0) {
			ERROR("%s - Failed reading response from socket: %s",
			      h->ctx.module_name, fr_syserror(errno));
			trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
			return;
		}

		fr_assert(slen >= RADIUS_HEADER_LENGTH); /* checked in verify */

		/*
		 *	Note that we don't care about packet codes.  All
		 *	packet codes share the same ID space.
		 */
		rr = radius_track_entry_find(h->tt, h->buffer[1], NULL);
		if (!rr) {
			WARN("%s - Ignoring reply with ID %i that arrived too late",
			     h->ctx.module_name, h->buffer[1]);
			continue;
		}

		treq = talloc_get_type_abort(rr->uctx, trunk_request_t);
		request = treq->request;
		fr_assert(request != NULL);
		u = talloc_get_type_abort(treq->rctx, bio_request_t);
		fr_assert(u == treq->preq);

		/*
		 *	Decode the incoming packet.
		 */
		reason = decode(request->reply_ctx, &reply, &code, h, request, u, rr->vector, h->buffer, (size_t)slen);
		if (reason != DECODE_FAIL_NONE) continue;

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
			trunk_request_signal_complete(treq);
			continue;
		}

		/*
		 *	Handle any state changes, etc. needed by receiving a
		 *	Protocol-Error reply packet.
		 *
		 *	Protocol-Error is permitted as a reply to any
		 *	packet.
		 */
		switch (code) {
		case FR_RADIUS_CODE_PROTOCOL_ERROR:
			protocol_error_reply(u, h);

			vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_original_packet_code);
			if (!vp) {
				RWDEBUG("Protocol-Error response is missing Original-Packet-Code");
			} else {
				fr_pair_delete_by_da(&request->reply_pairs, attr_original_packet_code);
			}

			vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_error_cause);
			if (!vp) {
				MEM(vp = fr_pair_afrom_da(request->reply_ctx, attr_error_cause));
				vp->vp_uint32 = FR_ERROR_CAUSE_VALUE_PROXY_PROCESSING_ERROR;
				fr_pair_append(&request->reply_pairs, vp);
			}
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
		if ((u->code == FR_RADIUS_CODE_ACCESS_REQUEST) && (code == FR_RADIUS_CODE_ACCESS_CHALLENGE)) {
			vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_packet_type);
			if (!vp) {
				MEM(vp = fr_pair_afrom_da(request->reply_ctx, attr_packet_type));
				vp->vp_uint32 = FR_RADIUS_CODE_ACCESS_CHALLENGE;
				fr_pair_append(&request->reply_pairs, vp);
			}
		}

		/*
		 *	Delete Proxy-State attributes from the reply.
		 */
		fr_pair_delete_by_da(&reply, attr_proxy_state);

		/*
		 *	If the reply has Message-Authenticator, then over-ride its value with all zeros, so
		 *	that we don't confuse anyone reading the debug output.
		 */
		if ((vp = fr_pair_find_by_da(&reply, NULL, attr_message_authenticator)) != NULL) {
			(void) fr_pair_value_memdup(vp, (uint8_t const *) "", 1, false);
		}

		treq->request->reply->code = code;
		u->rcode = radius_code_to_rcode[code];
		fr_pair_list_append(&request->reply_pairs, &reply);
		trunk_request_signal_complete(treq);
	}
}

/*
 *	This is the same as request_mux(), except that we immediately mark the request as complete.
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void request_replicate_mux(UNUSED fr_event_list_t *el,
				  trunk_connection_t *tconn, connection_t *conn, UNUSED void *uctx)
{
	bio_handle_t		*h = talloc_get_type_abort(conn->h, bio_handle_t);
	trunk_request_t		*treq;

	if (unlikely(trunk_connection_pop_request(&treq, tconn) < 0)) return;

	/*
	 *	No more requests to send
	 */
	if (!treq) return;

	mod_write(treq->request, treq, h);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void request_replicate_demux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn, connection_t *conn, UNUSED void *uctx)
{
	bio_handle_t		*h = talloc_get_type_abort(conn->h, bio_handle_t);

	DEBUG3("%s - Reading data for connection %s", h->ctx.module_name, h->ctx.fd_info->name);

	while (true) {
		ssize_t			slen;

		trunk_request_t	*treq;
		request_t		*request;
		bio_request_t		*u;
		radius_track_entry_t	*rr;
		fr_radius_decode_fail_t	reason;
		uint8_t			code = 0;
		fr_pair_list_t		reply;

		fr_time_t		now;

		fr_pair_list_init(&reply);

		/*
		 *	Drain the socket of all packets.  If we're busy, this
		 *	saves a round through the event loop.  If we're not
		 *	busy, a few extra system calls don't matter.
		 */
		slen = fr_bio_read(h->bio.main, NULL, h->buffer, h->buflen);
		if (slen == 0) {
			/*
			 *	@todo - set BIO FD EOF callback, so that we don't have to check it here.
			 */
			if (h->ctx.fd_info->eof) trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
			return;
		}

		/*
		 *	We're done reading, return.
		 */
		if (slen == fr_bio_error(IO_WOULD_BLOCK)) return;

		if (slen < 0) {
			ERROR("%s - Failed reading response from socket: %s",
			      h->ctx.module_name, fr_syserror(errno));
			trunk_connection_signal_reconnect(tconn, CONNECTION_FAILED);
			return;
		}

		fr_assert(slen >= RADIUS_HEADER_LENGTH); /* checked in verify */

		/*
		 *	We only pay attention to Protocol-Error replies.
		 *
		 *	All other packets are discarded.
		 */
		if (h->buffer[0] != FR_RADIUS_CODE_PROTOCOL_ERROR) {
			continue;
		}

		/*
		 *	Note that we don't care about packet codes.  All
		 *	packet codes share the same ID space.
		 */
		rr = radius_track_entry_find(h->tt, h->buffer[1], NULL);
		if (!rr) {
			WARN("%s - Ignoring reply with ID %i that arrived too late",
			     h->ctx.module_name, h->buffer[1]);
			continue;
		}

		treq = talloc_get_type_abort(rr->uctx, trunk_request_t);
		request = treq->request;
		fr_assert(request != NULL);
		u = talloc_get_type_abort(treq->rctx, bio_request_t);
		fr_assert(u == treq->preq);

		/*
		 *	Decode the incoming packet
		 */
		reason = decode(request->reply_ctx, &reply, &code, h, request, u, rr->vector, h->buffer, (size_t)slen);
		if (reason != DECODE_FAIL_NONE) continue;

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
			trunk_request_signal_complete(treq);
			continue;
		}

		/*
		 *	Handle any state changes, etc. needed by receiving a
		 *	Protocol-Error reply packet.
		 *
		 *	Protocol-Error is also permitted as a reply to any
		 *	packet.
		 */
		protocol_error_reply(u, h);
	}
}


/** Remove the request from any tracking structures
 *
 * Frees encoded packets if the request is being moved to a new connection
 */
static void request_cancel(UNUSED connection_t *conn, void *preq_to_reset,
			   trunk_cancel_reason_t reason, UNUSED void *uctx)
{
	bio_request_t	*u = preq_to_reset;

	/*
	 *	Request has been requeued on the same
	 *	connection due to timeout or DUP signal.  We
	 *	keep the same packet to avoid re-encoding it.
	 */
	if (reason == TRUNK_CANCEL_REASON_REQUEUE) {
		/*
		 *	Delete the request_timeout
		 *
		 *	Note: There might not be a request timeout
		 *	set in the case where the request was
		 *	queued for sendmmsg but never actually
		 *	sent.
		 */
		FR_TIMER_DISARM(u->ev);
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
	bio_request_t		*u = preq_to_reset;
	bio_handle_t		*h = talloc_get_type_abort(conn->h, bio_handle_t);

	FR_TIMER_DISARM(u->ev);
	bio_request_reset(u);

	if (h->ctx.inst->mode == RLM_RADIUS_MODE_REPLICATE) return;

	u->num_replies = 0;

	/*
	 *	If there are no outstanding tracking entries
	 *	allocated then the connection is "idle".
	 */
	if (!h->tt || (h->tt->num_requests == 0)) h->last_idle = fr_time();
}

/** Write out a canned failure
 *
 */
static void request_fail(request_t *request, NDEBUG_UNUSED void *preq, void *rctx,
			 NDEBUG_UNUSED trunk_request_state_t state, UNUSED void *uctx)
{
	bio_request_t		*u = talloc_get_type_abort(rctx, bio_request_t);

	fr_assert(u == preq);

	fr_assert(!u->rr && !u->packet && fr_pair_list_empty(&u->extra) && !u->ev);	/* Dealt with by request_conn_release */

	fr_assert(state != TRUNK_REQUEST_STATE_INIT);

	if (u->status_check) return;

	u->rcode = RLM_MODULE_FAIL;
	u->treq = NULL;

	unlang_interpret_mark_runnable(request);
}

/** Response has already been written to the rctx at this point
 *
 */
static void request_complete(request_t *request, NDEBUG_UNUSED void *preq, void *rctx, UNUSED void *uctx)
{
	bio_request_t		*u = talloc_get_type_abort(rctx, bio_request_t);

	fr_assert(u == preq);

	fr_assert(!u->rr && !u->packet && fr_pair_list_empty(&u->extra) && !u->ev);	/* Dealt with by request_conn_release */

	if (u->status_check) return;

	u->treq = NULL;

	unlang_interpret_mark_runnable(request);
}

/** Resume execution of the request, returning the rcode set during trunk execution
 *
 */
static unlang_action_t mod_resume(unlang_result_t *p_result, module_ctx_t const *mctx, UNUSED request_t *request)
{
	bio_request_t	*u = talloc_get_type_abort(mctx->rctx, bio_request_t);
	rlm_rcode_t	rcode = u->rcode;

	talloc_free(u);

	RETURN_UNLANG_RCODE(rcode);
}

static void do_signal(rlm_radius_t const *inst, bio_request_t *u, request_t *request, fr_signal_t action);

static void mod_signal(module_ctx_t const *mctx, UNUSED request_t *request, fr_signal_t action)
{
	rlm_radius_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_radius_t);

	bio_request_t		*u = talloc_get_type_abort(mctx->rctx, bio_request_t);

	do_signal(inst, u, request, action);
}

static void do_signal(rlm_radius_t const *inst, bio_request_t *u, UNUSED request_t *request, fr_signal_t action)
{
	/*
	 *	We received a duplicate packet, but we're not doing
	 *	synchronous proxying.  Ignore the dup, and rely on the
	 *	IO submodule to time it's own retransmissions.
	 */
	if ((action == FR_SIGNAL_DUP) && (inst->mode != RLM_RADIUS_MODE_PROXY)) return;

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
	if (!u->treq) return;

	switch (action) {
	/*
	 *	The request is being cancelled, tell the
	 *	trunk so it can clean up the treq.
	 */
	case FR_SIGNAL_CANCEL:
		trunk_request_signal_cancel(u->treq);
		u->treq = NULL;
		return;

	/*
	 *	Requeue the request on the same connection
	 *      causing a "retransmission" if the request
	 *	has already been sent out.
	 */
	case FR_SIGNAL_DUP:
		mod_dup(request, u);
		return;

	default:
		return;
	}
}

/** Free a bio_request_t
 *
 * Allows us to set break points for debugging.
 */
static int _bio_request_free(bio_request_t *u)
{
	if (!u->treq) return 0;

#ifndef NDEBUG
	{
		trunk_request_t	*treq;
		treq = talloc_get_type_abort(u->treq, trunk_request_t);
		fr_assert(treq->preq == u);
	}
#endif

	fr_assert_msg(!fr_timer_armed(u->ev), "bio_request_t freed with active timer");

	FR_TIMER_DELETE_RETURN(&u->ev);

	fr_assert(u->rr == NULL);

	return 0;
}

static int mod_enqueue(bio_request_t **p_u, fr_retry_config_t const **p_retry_config,
		       rlm_radius_t const *inst, trunk_t *trunk, request_t *request)
{
	bio_request_t			*u;
	trunk_request_t			*treq;
	fr_retry_config_t const		*retry_config;

	fr_assert(request->packet->code > 0);
	fr_assert(request->packet->code < FR_RADIUS_CODE_MAX);

	/*
	 *	Do any necessary RADIUS level fixups
	 *	- check Proxy-State
	 *	- do CHAP-Challenge fixups
	 */
	if (radius_fixups(inst, request) < 0) return 0;

	treq = trunk_request_alloc(trunk, request);
	if (!treq) {
		REDEBUG("Failed allocating handler for request");
		return -1;
	}

	MEM(u = talloc_zero(request, bio_request_t));
	talloc_set_destructor(u, _bio_request_free);

	/*
	 *	Can't use compound literal - const issues.
	 */
	u->code = request->packet->code;
	u->priority = request->priority;
	u->recv_time = request->async->recv_time;
	fr_pair_list_init(&u->extra);

	u->retry.count = 1;

	u->rcode = RLM_MODULE_FAIL;

	switch(trunk_request_enqueue(&treq, trunk, request, u, u)) {
	case TRUNK_ENQUEUE_OK:
	case TRUNK_ENQUEUE_IN_BACKLOG:
		break;

	case TRUNK_ENQUEUE_NO_CAPACITY:
		REDEBUG("Unable to queue packet - connections at maximum capacity");
	fail:
		fr_assert(!u->rr && !u->packet);	/* Should not have been fed to the muxer */
		trunk_request_free(&treq);		/* Return to the free list */
		talloc_free(u);
		return -1;

	case TRUNK_ENQUEUE_DST_UNAVAILABLE:
		REDEBUG("All destinations are down - cannot send packet");
		goto fail;

	case TRUNK_ENQUEUE_FAIL:
		REDEBUG("Unable to queue packet");
		goto fail;
	}

	u->treq = treq;	/* Remember for signalling purposes */
	fr_assert(treq->rctx == u);

	/*
	 *	Figure out if we're originating the packet or proxying it.  And also figure out if we have to
	 *	retry.
	 */
	switch (inst->mode) {
	case RLM_RADIUS_MODE_INVALID:
	case RLM_RADIUS_MODE_UNCONNECTED_REPLICATE: /* unconnected sockets are UDP, and bypass the trunk */
		REDEBUG("Internal sanity check failed - connection trunking cannot be used for replication");
		return -1;

		/*
		 *	We originate this packet if it was taken from the detail module, which doesn't have a
		 *	real client.  @todo - do a better check here.
		 *
		 *	We originate this packet if the parent request is not compatible with this one
		 *	(i.e. it's from a different protocol).
		 *
		 *	We originate the packet if the parent is from the same dictionary, but has a different
		 *	packet code.  This lets us receive Accounting-Request, and originate
		 *	Disconnect-Request.
		 */
	case RLM_RADIUS_MODE_XLAT_PROXY:
	case RLM_RADIUS_MODE_PROXY:
		if (!request->parent) {
			u->proxied = (request->client && request->client->cs != NULL);

		} else if (!fr_dict_compatible(request->parent->proto_dict, request->proto_dict)) {
			u->proxied = false;

		} else {
			u->proxied = (request->parent->packet->code == request->packet->code);
		}

		/*
		 *	Proxied packets get a final timeout, as we retry only on DUP packets.
		 */
		if (u->proxied) goto timeout_retry;

		FALL_THROUGH;

		/*
		 *	Client packets (i.e. packets we originate) get retries for UDP.  And no retries for TCP.
		 */
	case RLM_RADIUS_MODE_CLIENT:
		if (inst->fd_config.socket_type == SOCK_DGRAM) {
			retry_config = &inst->retry[u->code];
			break;
		}
		FALL_THROUGH;

		/*
		 *	Replicated packets are never retried, but they have a timeout if the socket isn't
		 *	ready for writing.
		 */
	case RLM_RADIUS_MODE_REPLICATE:
	timeout_retry:
		retry_config = &inst->timeout_retry;
		break;
	}

	/*
	 *	The event loop will take care of demux && sending the
	 *	packet, along with any retransmissions.
	 */
	*p_u = u;
	*p_retry_config = retry_config;

	return 1;
}

static void home_server_free(void *data)
{
	home_server_t *home = data;

	talloc_free(home);
}

static const trunk_io_funcs_t	io_funcs = {
	.connection_alloc = thread_conn_alloc,
	.connection_notify = thread_conn_notify,
	.request_prioritise = request_prioritise,
	.request_mux = request_mux,
	.request_demux = request_demux,
	.request_conn_release = request_conn_release,
	.request_complete = request_complete,
	.request_fail = request_fail,
	.request_cancel = request_cancel,
};

static const trunk_io_funcs_t	io_replicate_funcs = {
	.connection_alloc = thread_conn_alloc,
	.connection_notify = thread_conn_notify,
	.request_prioritise = request_prioritise,
	.request_mux = request_replicate_mux,
	.request_demux = request_replicate_demux,
	.request_conn_release = request_conn_release,
	.request_complete = request_complete,
	.request_fail = request_fail,
	.request_cancel = request_cancel,
};

/** Instantiate thread data for the submodule.
 *
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_radius_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_radius_t);
	bio_thread_t		*thread = talloc_get_type_abort(mctx->thread, bio_thread_t);

	thread->ctx.el = mctx->el;
	thread->ctx.inst = inst;
	thread->ctx.fd_config = inst->fd_config;
	thread->ctx.radius_ctx = inst->common_ctx;

	switch (inst->mode) {
	case RLM_RADIUS_MODE_XLAT_PROXY:
		fr_rb_expire_inline_talloc_init(&thread->bio.expires, home_server_t, expire, home_server_cmp, home_server_free,
						inst->home_server_lifetime);
		FALL_THROUGH;

	default:
		/*
		 *	Assign each thread a portion of the available source port range.
		 */
		if (thread->ctx.fd_config.src_port_start) {
			uint16_t	range = inst->fd_config.src_port_end - inst->fd_config.src_port_start + 1;
			thread->num_ports = range / main_config->max_workers;
			thread->ctx.fd_config.src_port_start = inst->fd_config.src_port_start + (thread->num_ports * fr_schedule_worker_id());
			thread->ctx.fd_config.src_port_end = inst->fd_config.src_port_start + (thread->num_ports * (fr_schedule_worker_id() +1)) - 1;
			if (inst->mode != RLM_RADIUS_MODE_XLAT_PROXY) {
				thread->connections = talloc_zero_array(thread, connection_t *, thread->num_ports);
				thread->ctx.limit_source_ports = LIMIT_PORTS_STATIC;
			}
		}

		thread->ctx.trunk = trunk_alloc(thread, mctx->el, &io_funcs,
					    &inst->trunk_conf, inst->name, thread, false, inst->trigger_args);
		if (!thread->ctx.trunk) return -1;
		return 0;

	case RLM_RADIUS_MODE_REPLICATE:
		/*
		 *	We can replicate over TCP, but that uses trunks.
		 */
		if (inst->fd_config.socket_type == SOCK_DGRAM) break;

		thread->ctx.trunk = trunk_alloc(thread, mctx->el, &io_replicate_funcs,
						&inst->trunk_conf, inst->name, thread, false, inst->trigger_args);
		if (!thread->ctx.trunk) return -1;
		return 0;

	case RLM_RADIUS_MODE_UNCONNECTED_REPLICATE:
		break;
	}

	/*
	 *	If we have a port range, allocate the source port based
	 *	on the range start, plus the thread ID.  This means
	 *	that we can avoid "hunt and peck" attempts to open up
	 *	the source port.
	 */
	if (thread->ctx.fd_config.src_port_start) {
		thread->ctx.fd_config.src_port = thread->ctx.fd_config.src_port_start + fr_schedule_worker_id();
	}

	/*
	 *	Allocate an unconnected socket for replication.
	 */
	thread->bio.fd = fr_bio_fd_alloc(thread, &thread->ctx.fd_config, 0);
	if (!thread->bio.fd) {
		PERROR("%s - failed opening socket", inst->name);
		return -1;
	}

	thread->bio.fd->uctx = thread;
	thread->ctx.fd_info = fr_bio_fd_info(thread->bio.fd);
	fr_assert(thread->ctx.fd_info != NULL);

	(void) fr_bio_fd_write_only(thread->bio.fd);

	DEBUG("%s - Opened unconnected replication socket %s", inst->name, thread->ctx.fd_info->name);
	return 0;
}

static xlat_arg_parser_t const xlat_radius_send_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_COMBO_IP_ADDR },
	{ .required = true, .single = true, .type = FR_TYPE_UINT16 },
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/*
 *	%replicate.sendto.ipaddr(ipaddr, port, secret)
 */
static xlat_action_t xlat_radius_replicate(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					   xlat_ctx_t const *xctx,
					   request_t *request, fr_value_box_list_t *args)
{
	bio_thread_t		*thread = talloc_get_type_abort(xctx->mctx->thread, bio_thread_t);
	fr_value_box_t		*ipaddr, *port, *secret;
	ssize_t			packet_len;
	uint8_t			buffer[4096];
	fr_radius_ctx_t		radius_ctx;
	fr_radius_encode_ctx_t	encode_ctx;
	fr_bio_fd_packet_ctx_t	addr;

	XLAT_ARGS(args, &ipaddr, &port, &secret);

	/*
	 *	Can't change IP address families.
	 */
	if (ipaddr->vb_ip.af != thread->ctx.fd_info->socket.af) {
		RPERROR("Invalid destination IP address family in %pV", ipaddr);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Warn if we're not replicating accounting data.  It likely won't wokr/
	 */
	if (request->packet->code != FR_RADIUS_CODE_ACCOUNTING_REQUEST) {
		RWDEBUG("Replication of packets other then Accounting-Request will likely not do what you want.");
	}

	/*
	 *	Set up various context things.
	 */
	radius_ctx = (fr_radius_ctx_t) {
		.secret = secret->vb_strvalue,
		.secret_length = secret->vb_length,
		.proxy_state = 0,
	};

	encode_ctx = (fr_radius_encode_ctx_t) {
		.common = &radius_ctx,
		.rand_ctx = (fr_fast_rand_t) {
			.a = fr_rand(),
			.b = fr_rand(),
		},
		.code = request->packet->code,
		.id = thread->bio.id++ & 0xff,
		.add_proxy_state = false,
	};

	/*
	 *	Encode the entire packet.
	 */
	packet_len = fr_radius_encode(&FR_DBUFF_TMP(buffer, sizeof(buffer)),
				      &request->request_pairs, &encode_ctx);
	if (fr_pair_encode_is_error(packet_len)) {
		RPERROR("Failed encoding packet");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Sign it.
	 */
	if (fr_radius_sign(buffer, NULL, (uint8_t const *) radius_ctx.secret, radius_ctx.secret_length) < 0) {
		RPERROR("Failed signing packet");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Prepare destination address.
	 */
	addr = (fr_bio_fd_packet_ctx_t) {
		.socket = thread->ctx.fd_info->socket,
	};
	addr.socket.inet.dst_ipaddr = ipaddr->vb_ip;
	addr.socket.inet.dst_port = port->vb_uint16;

	RDEBUG("Replicating packet to %pV:%u", ipaddr, port->vb_uint16);

	/*
	 *	We either send it, or fail.
	 */
	packet_len = fr_bio_write(thread->bio.fd, &addr, buffer, packet_len);
	if (packet_len < 0) {
		RPERROR("Failed sending packet to %pV:%u", ipaddr, port->vb_uint16);
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	No return value.
	 */
	return XLAT_ACTION_DONE;
}

// **********************************************************************

/** Dynamic home server code
 *
 */

static int8_t home_server_cmp(void const *one, void const *two)
{
	home_server_t const *a = one;
	home_server_t const *b = two;
	int8_t rcode;

	rcode = fr_ipaddr_cmp(&a->ctx.fd_config.dst_ipaddr, &b->ctx.fd_config.dst_ipaddr);
	if (rcode != 0) return rcode;

	return CMP(a->ctx.fd_config.dst_port, b->ctx.fd_config.dst_port);
}

static xlat_action_t xlat_sendto_resume(TALLOC_CTX *ctx, fr_dcursor_t *out,
					xlat_ctx_t const *xctx,
					request_t *request, UNUSED fr_value_box_list_t *in)
{
	bio_request_t	*u = talloc_get_type_abort(xctx->rctx, bio_request_t);
	fr_value_box_t *dst;

	if (u->rcode == RLM_MODULE_FAIL) return XLAT_ACTION_FAIL;

	MEM(dst = fr_value_box_alloc(ctx, FR_TYPE_UINT32, attr_packet_type));
	dst->vb_uint32 = request->reply->code;

	fr_dcursor_append(out, dst);

	return XLAT_ACTION_DONE;
}

static void xlat_sendto_signal(xlat_ctx_t const *xctx, request_t *request, fr_signal_t action)
{
	rlm_radius_t const     	*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_radius_t);
	bio_request_t   	*u = talloc_get_type_abort(xctx->rctx, bio_request_t);

	do_signal(inst, u, request, action);
}

/*
 *	@todo - change this to mod_retry
 */
static void xlat_sendto_retry(xlat_ctx_t const *xctx, request_t *request, fr_retry_t const *retry)
{
	rlm_radius_t const     	*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_radius_t);
	bio_request_t   	*u = talloc_get_type_abort(xctx->rctx, bio_request_t);

	do_retry(inst, u, request, retry);
}

/*
 *	%proxy.sendto.ipaddr(ipaddr, port, secret)
 */
static xlat_action_t xlat_radius_client(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
					xlat_ctx_t const *xctx,
					request_t *request, fr_value_box_list_t *args)
{
	rlm_radius_t const     	*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_radius_t);
	bio_thread_t		*thread = talloc_get_type_abort(xctx->mctx->thread, bio_thread_t);
	fr_value_box_t		*ipaddr, *port, *secret;
	home_server_t		*home;
	bio_request_t		*u = NULL;
	fr_retry_config_t const	*retry_config = NULL;
	int			rcode;

	XLAT_ARGS(args, &ipaddr, &port, &secret);

	/*
	 *	Can't change IP address families.
	 */
	if (ipaddr->vb_ip.af != thread->ctx.fd_config.src_ipaddr.af) {
		RDEBUG("Invalid destination IP address family in %pV", ipaddr);
		return XLAT_ACTION_DONE;
	}

	home = fr_rb_find(&thread->bio.expires.tree, &(home_server_t) {
			.ctx = {
				.fd_config = (fr_bio_fd_config_t) {
					.dst_ipaddr = ipaddr->vb_ip,
					.dst_port = port->vb_uint16,
				},
			},
		});
	if (!home) {
		/*
		 *	Track which connections are made to this home server from which open ports.
		 */
		MEM(home = (home_server_t *) talloc_zero_array(thread, uint8_t, sizeof(home_server_t) + sizeof(connection_t *) * thread->num_ports));
		talloc_set_type(home, home_server_t);

		*home = (home_server_t) {
			.ctx = (bio_handle_ctx_t) {
				.el = unlang_interpret_event_list(request),
				.module_name = inst->name,
				.inst = inst,
				.limit_source_ports = (thread->num_ports > 0) ? LIMIT_PORTS_DYNAMIC : LIMIT_PORTS_NONE,
			},
			.num_ports = thread->num_ports,
		};

		/*
		 *	Copy the home server configuration from the thread configuration.  Then update it with
		 *	the needs of the home server.
		 */
		home->ctx.fd_config = thread->ctx.fd_config;
		home->ctx.fd_config.type = FR_BIO_FD_CONNECTED;
		home->ctx.fd_config.dst_ipaddr = ipaddr->vb_ip;
		home->ctx.fd_config.dst_port = port->vb_uint32;

		home->ctx.radius_ctx = (fr_radius_ctx_t) {
			.secret = talloc_strdup(home, secret->vb_strvalue),
			.secret_length = secret->vb_length,
			.proxy_state = inst->common_ctx.proxy_state,
		};

		/*
		 *	Allocate the trunk and start it up.
		 */
		home->ctx.trunk = trunk_alloc(home, unlang_interpret_event_list(request), &io_funcs,
					      &inst->trunk_conf, inst->name, home, false, inst->trigger_args);
		if (!home->ctx.trunk) {
		fail:
			talloc_free(home);
			return XLAT_ACTION_FAIL;
		}

		if (!fr_rb_expire_insert(&thread->bio.expires, home, fr_time())) goto fail;
	} else {
		fr_rb_expire_t *expire = &thread->bio.expires;
		fr_time_t now = fr_time();
		home_server_t *old;

		/*
		 *	We can't change secrets on the fly.  The home
		 *	server has to expire first, and then the
		 *	secret can be changed.
		 */
		if ((home->ctx.radius_ctx.secret_length != secret->vb_length) ||
		    (strcmp(home->ctx.radius_ctx.secret, secret->vb_strvalue) != 0)) {
			RWDEBUG("The new secret is not the same as the old secret: Ignoring the new one");
		}

		fr_rb_expire_update(expire, home, now);

		while ((old = fr_dlist_head(&expire->head)) != NULL) {
			(void) talloc_get_type_abort(old, home_server_t);

			fr_assert(old->ctx.trunk);

			/*
			 *	Don't delete the home server we're about to use.
			 */
			if (old == home) break;

			/*
			 *	It still has a request allocated, do nothing.
			 */
			if (old->ctx.trunk->req_alloc) break;

			/*
			 *	Not yet time to expire.
			 */
			if (fr_time_gt(old->expire.when, now)) break;

			fr_dlist_remove(&expire->head, old);
			fr_rb_delete(&expire->tree, old);
		}
	}

	/*
	 *	Enqueue the packet on the per-home-server trunk.
	 */
	rcode = mod_enqueue(&u, &retry_config, inst, home->ctx.trunk, request);
	if (rcode == 0) return XLAT_ACTION_DONE;

	if (rcode < 0) {
		REDEBUG("Failed enqueuing packet");
		return XLAT_ACTION_FAIL;
	}
	fr_assert(u != NULL);
	fr_assert(retry_config != NULL);

	/*
	 *	Start the retry.
	 *
	 *	@todo - change unlang_xlat_timeout_add() to unlang_xlat_retry_add().
	 */
	fr_retry_init(&u->retry, fr_time(), retry_config);

	return unlang_xlat_yield_to_retry(request, xlat_sendto_resume, xlat_sendto_retry,
					  xlat_sendto_signal, ~(FR_SIGNAL_CANCEL | FR_SIGNAL_DUP),
					  u, retry_config);
}
