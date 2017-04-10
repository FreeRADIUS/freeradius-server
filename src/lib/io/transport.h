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
 * @file io/transport.h
 * @brief Transport-specific functions.
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(transport_h, "$Id$")

#include <freeradius-devel/io/time.h>
#include <freeradius-devel/io/channel.h>
//#include <freeradius-devel/io/io.h>

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
 *  Process raw packets into a form suitable
 */
//typedef int (*fr_transport_send_request_t)(fr_io_buffer_t *io);

/**
 *  Have a raw packet, and decode it to a REQUEST
 */
typedef int (*fr_transport_decode_t)(void const *packet_ctx, uint8_t *const data, size_t data_len, REQUEST *request);

/**
 *  Have a raw packet, and send a NAK.  This function MUST NOT fail.
 *  It must always return some data.
 */
typedef size_t (*fr_transport_nak_t)(void const *packet_ctx, uint8_t *const packet, size_t packet_len,
				      uint8_t *reply, size_t reply_len);

/**
 *  Have a REQUEST, and encode it to raw packet.
 */
typedef ssize_t (*fr_transport_encode_t)(void const *packet_ctx, REQUEST *request, uint8_t *buffer, size_t buffer_len);

/**
 *  Do any worker-specific processing of the request.
 */
typedef int *(*fr_transport_recv_request_t)(REQUEST *);

/**
 *  (Read / write) from a (socket / data buffer) to a (data buffer / socket)
 *
 *  @todo - use IO buffers, which allow for stream sockets to read / write partial data
 */
typedef ssize_t (*fr_transport_io_t)(int sockfd, void *packet_ctx, uint8_t *buffer, size_t buffer_len);

/**
 *  Receive a reply in the master thread.
 */
//typedef int (*fr_transport_recv_reply_t)(fr_io_buffer_t *io);

/**
 *  Have a REQUEST, and encode it to a packet
 */
typedef ssize_t (*fr_transport_send_reply_t)(void const *packet_ctx, uint8_t const *data, size_t data_len, REQUEST *request);

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
	uint32_t			id;		//!< ID of this transport
	size_t				default_message_size; // usually minimum message size
	fr_transport_io_t		read;		//!< read from a socket to a data buffer
	fr_transport_io_t		write;		//!< write from a data buffer to a socket
	fr_transport_recv_request_t	recv_request;	//!< function to receive a request (worker -> master)
	fr_transport_decode_t		decode;		//!< function to decode packet to request (worker)
	fr_transport_encode_t		encode;		//!< function to encode request to packet (worker)
	fr_transport_nak_t		nak;		//!< function to send a NAK
	fr_transport_send_reply_t	send_reply;	//!< function to send a reply (worker -> master)
	fr_transport_process_t		process;	//!< process a request
} fr_transport_t;

typedef enum fr_transport_status_t {
	FR_TRANSPORT_STATUS_INIT = 0,
	FR_TRANSPORT_STATUS_ACTIVE,
	FR_TRANSPORT_STATUS_ZOMBIE,
	FR_TRANSPORT_STATUS_DEAD
} fr_transport_status_t;

typedef struct fr_transport_socket_t {
	int			fd;		       	//!< file descriptor
	fr_transport_status_t	status;			//!< status of this socket
	void			*ctx;		       	//!< transport-specific context
	fr_transport_t		*transport;	       	//!< all transport callbacks
	struct fr_transport_socket_t *parent;		//!< parent (if applicable)
} fr_transport_socket_t;


#ifndef _FR_RADIUSD_H
/**
 *	Minimal data structure to use the new code.
 */
struct rad_request {
	uint64_t		number;
	int			heap_id;

	fr_dlist_t		time_order;		//!< tracking requests by time order
	fr_heap_t		*runnable;		//!< heap of runnable requests

	uint32_t		priority;
	fr_time_t		recv_time;
	fr_time_t		*original_recv_time;
	fr_event_list_t		*el;
	fr_transport_process_t	process_async;
	fr_time_tracking_t	tracking;
	fr_channel_t		*channel;
	void			*packet_ctx;
	void			*io_ctx;
	fr_transport_t		*transport;
};
#endif

#ifdef __cplusplus
}
#endif

#endif /* _FR_TRANSPORT_H */
