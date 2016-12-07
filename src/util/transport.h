/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifndef _FR_TRANSPORT_H
#define _FR_TRANSPORT_H
/**
 * $Id$
 *
 * @file util/transport.h
 * @brief Transport-specific functions.
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(transport_h, "$Id$")

#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/channel.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	Hack to get it to build in the short term
 *
 *	@todo fix this!
 */
#ifndef _FR_RADIUSD_H
typedef struct rad_request REQUEST;
#else
#error New code does not yet work with old code
#endif

/**
 *  Tell an async process function if it should run or exit.
 */
typedef enum fr_transport_action_t {
	FR_TRANSPORT_ACTION_RUN,
	FR_TRANSPORT_ACTION_DONE,
} fr_transport_action_t;

/**
 *  Answer from an async process function if the worker should yield,
 *  reply, or drop the request.
 */
typedef enum fr_transport_final_t {
	FR_TRANSPORT_YIELD,
	FR_TRANSPORT_REPLY,
	FR_TRANSPORT_DONE,
} fr_transport_final_t;

typedef struct fr_transport_t fr_transport_t;

/**
 *  Have a bare packet, and decode it to a REQUEST
 */
typedef REQUEST *(*fr_transport_recv_request_t)(fr_transport_t const *transport, void const *packet_ctx, TALLOC_CTX *ctx, uint8_t *const data, size_t data_len);

/**
 *  Have a REQUEST, and encode it to a packet
 */
typedef ssize_t (*fr_transport_send_reply_t)(fr_transport_t const *transport, void const *packet_ctx, uint8_t const *data, size_t data_len, REQUEST *request);

/**
 *  Process a request through the transport async state machine.
 */
typedef	fr_transport_final_t (*fr_transport_process_t)(REQUEST *, fr_transport_action_t);

/**
 *  Data structure describing the transport.
 *
 *  @todo add conf parser, open socket, send_request, recv_reply, send_nak, etc.
 */
typedef struct fr_transport_t {
	char const			*name;		//!< name of this transport
	fr_transport_recv_request_t	recv_request;	//!< function to receive a request (worker -> master)
	fr_transport_send_reply_t	send_reply;	//!< function to send a reply (worker -> master)
	fr_transport_process_t		process;	//!< process a request
} fr_transport_t;


#ifndef _FR_RADIUSD_H
/**
 *	Minimal data structure to use the new code.
 */
struct rad_request {
	int			heap_id;
	uint32_t		priority;
	fr_time_t		recv_time;
	fr_time_t		*original_recv_time;
	fr_event_list_t		*el;
	fr_transport_process_t	process_async;
	fr_time_tracking_t	tracking;
	fr_channel_t		*channel;
	fr_transport_t		*transport;
	fr_heap_t		*backlog;
	fr_dlist_t		list;
};
#endif

#ifdef __cplusplus
}
#endif

#endif /* _FR_TRANSPORT_H */
