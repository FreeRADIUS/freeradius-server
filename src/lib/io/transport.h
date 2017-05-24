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

#include <talloc.h>

#include <freeradius-devel/heap.h>
#include <freeradius-devel/event.h>
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
	FR_TRANSPORT_YIELD,		//!< yielded, request can continue processing
	FR_TRANSPORT_REPLY,		//!< please send a reply
	FR_TRANSPORT_FAIL,		//!< processing failed somehow, cannot send a reply
	FR_TRANSPORT_DONE,		//!< succeeded without a reply
} fr_transport_final_t;

typedef struct fr_transport_t fr_transport_t;

/** Decode a raw packet and convert it into a request.
 *
 *  This function is the opposite of fr_transport_encode_t.
 *
 *  The "decode" function is ONLY for decoding data.  It should be
 *  aware of the protocol (e.g. RADIUS), but it MUST NOT know anything
 *  about the underlying network transport (e.g. UDP), and it MUST NOT
 *  know anything about how the data will be used (e.g. authorize,
 *  authenticate, etc. for Access-Request)
 *
 * @param[in] transport_ctx the context for this function.
 * @param[in] data the raw packet data
 * @param[in] data_len the length of the raw data
 * @param[in,out] request where the decoded VPs should be placed.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
typedef int (*fr_transport_decode_t)(void *transport_ctx, uint8_t *const data, size_t data_len, REQUEST *request);

/** Encode data from a REQUEST into a raw packet.
 *
 *  This function is the opposite of fr_transport_decode_t.
 *
 *  The "encode" function is ONLY for encoding data.  It should be
 *  aware of the protocol (e.g. RADIUS), but it MUST NOT know anything
 *  about the underlying network transport (e.g. UDP), and it MUST NOT
 *  know anything about how the data will be used (e.g. reject delay
 *  on Access-Reject)
 *
 * @param[in] transport_ctx the context for this function.
 * @param[in,out] request where the VPs to be encoded are located
 * @param[in] buffer the buffer where the raw packet will be written
 * @param[in] buffer_len the length of the buffer
 * @return
 *	- <0 on error
 *	- >=0 length of the encoded data in the buffer, will be <=buffer_len
 */
typedef ssize_t (*fr_transport_encode_t)(void *transport_ctx, REQUEST *request, uint8_t *buffer, size_t buffer_len);

/** NAK a packet.
 *
 *  When a worker receives a packet, it sometimes is unable to process
 *  that request.  In order for the channels to work correctly, every
 *  request MUST be met with a response.  This function allows a
 *  worker to NAK a request, but NOT send a response packet on the
 *  network.
 *
 *  This function MUST NOT fail.  It must always return some data.
 *
 *  When the NAK packet is received by the network side, the transport
 *  portion of the network side MUST be able to recognize the NAK and
 *  take the appropriate action.  e.g. for RADIUS, mark a request as
 *  "do not respond", even if duplicates come in.
 *
 * @param[in] transport_ctx the context for this function.
 * @param[in] packet the packet to NAK
 * @param[in] packet_len length of the packet to NAK
 * @param[in] reply the NAK reply
 * @param[in] reply_len length of the buffer where the reply should be placed. 
 * @return length of the data in the reply buffer.
 */
typedef size_t (*fr_transport_nak_t)(void const *transport_ctx, uint8_t *const packet, size_t packet_len,
				      uint8_t *reply, size_t reply_len);

/** Read/write from a socket.
 *
 *  If the socket is a datagram socket, then the function can read or
 *  write directly into the buffer.  Stream sockets are a bit more complicated.
 *
 *  A stream reader can read data into the buffer, and be guaranteed
 *  that the data will not change in between subsequent calls to the
 *  read routine.
 *
 *  A stream writer MUST be prepared for the caller to delete the data
 *  immediately after calling the write routine.  This means that if
 *  the socket is not ready, the writer MUST copy the data to an
 *  internal buffer, usually in transport_ctx.  It MUST then have a
 *  write callback on the socket, which is called when the socket is
 *  ready for writing.  That callback can then write the internal
 *  buffer to the socket.
 *
 *  i.e. this write() function is a way for the network thread to
 *  write packets to the transport context.  The data may or may not
 *  go out to the network right away.
 *
 *  If the writer returns LESS THAN buffer_len, that's a special case
 *  saying "I took saved the data, but the socket wasn't ready, so you
 *  need to call me again at a later point".
 *
 * @param[in] sockfd the file descriptor to use
 * @param[in] transport_ctx the context for this function
 * @param[in,out] buffer the buffer where the raw packet will be written to (or read from)
 * @param[in] buffer_len the length of the buffer
 * @return
 *	- <0 on error
 *	- >=0 length of the data read or written.
 */
typedef ssize_t (*fr_transport_io_t)(int sockfd, void *transport_ctx, uint8_t *buffer, size_t buffer_len);

/**  Handle a close or error on the socket.
 *
 *  In general, the only thing to do on errors is to close the
 *  transport.  But on error, the "error" function will be called
 *  before "close".  On normal finish, the "close" function will be
 *  called.
 *
 * @param[in] sockfd the file descriptor to use
 * @param[in] transport_ctx the context for this function
 * @return
 *	- 0 on success
 *	- <0 on error
 */
typedef int (*fr_transport_signal_t)(int sockfd, void *transport_ctx);

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
	size_t				default_message_size; // usually minimum message size
	fr_transport_decode_t		decode;		//!< function to decode packet to request (worker)
	fr_transport_encode_t		encode;		//!< function to encode request to packet (worker)

	fr_transport_io_t		read;		//!< read from a socket to a data buffer
	fr_transport_io_t		write;		//!< write from a data buffer to a socket
	fr_transport_signal_t		flush;		//!< flush the data when the socket is ready for writing
	fr_transport_signal_t		error;		//!< there was an error on the socket
	fr_transport_signal_t		close;		//!< close the transport
	fr_transport_nak_t		nak;		//!< function to send a NAK
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

	fr_time_t		recv_time;
	fr_time_t		*original_recv_time;
	fr_event_list_t		*el;
	fr_transport_process_t	process_async;
	fr_time_tracking_t	tracking;
	fr_channel_t		*channel;

	fr_packet_io_t		io;
};
#endif

#ifdef __cplusplus
}
#endif

#endif /* _FR_TRANSPORT_H */
