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
#ifndef _FR_IO_H
#define _FR_IO_H
/**
 * $Id$
 *
 * @file io/io.h
 * @brief Transport-specific functions.
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(transport_h, "$Id$")

#include <talloc.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/io/time.h>
#include <freeradius-devel/io/channel.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_listen fr_listen_t;

/**
 *  Tell an async process function if it should run or exit.
 */
typedef enum fr_io_action_t {
	FR_IO_ACTION_RUN,
	FR_IO_ACTION_DUP,
	FR_IO_ACTION_DONE,
} fr_io_action_t;

/**
 *  Answer from an async process function if the worker should yield,
 *  reply, or drop the request.
 */
typedef enum fr_io_final_t {
	FR_IO_YIELD,		//!< yielded, request can continue processing
	FR_IO_REPLY,		//!< please send a reply
	FR_IO_FAIL,		//!< processing failed somehow, cannot send a reply
	FR_IO_DONE,		//!< succeeded without a reply
} fr_io_final_t;

typedef struct fr_channel_t fr_channel_t;

/**  Open an I/O path
 *
 * Open a socket, file, or anything else that can be referenced
 * by a file descriptor.
 *
 * The file descriptor should be made available to the event loop
 * via the selectable_fd callback. It will only be used to determine if the
 * socket is readable/writable/has errored.
 *
 * No data will be read from or written to the fd, except by the io_data callbacks here.
 *
 * @param[in] instance the context for this function
 * @return
 *	- 0 on success
 *	- <0 on error
 */
typedef int (*fr_io_open_t)(void *instance);

/** Return a selectable file descriptor for this I/O path
 *
 * Return the file descriptor associated with this I/O path.
 *
 * @param[in] instance	containing the file descriptor (amongst other things).
 */
typedef int (*fr_io_get_fd_t)(void const *instance);

/** Decode a raw packet and convert it into a request.
 *
 *  This function is the opposite of fr_io_encode_t.
 *
 *  The "decode" function is ONLY for decoding data.  It should be
 *  aware of the protocol (e.g. RADIUS), but it MUST NOT know anything
 *  about the underlying network transport (e.g. UDP), and it MUST NOT
 *  know anything about how the data will be used (e.g. authorize,
 *  authenticate, etc. for Access-Request)
 *
 * @param[in] instance		of the #fr_app_t or #fr_app_io_t.
 * @param[in] data		the raw packet data
 * @param[in] data_len		the length of the raw data
 * @param[in] request		where the decoded VPs should be placed.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
typedef int (*fr_io_decode_t)(void const *instance, REQUEST *request, uint8_t *const data, size_t data_len);

/** Encode data from a REQUEST into a raw packet.
 *
 *  This function is the opposite of fr_io_decode_t.
 *
 *  The "encode" function is ONLY for encoding data.  It should be
 *  aware of the protocol (e.g. RADIUS), but it MUST NOT know anything
 *  about the underlying network transport (e.g. UDP), and it MUST NOT
 *  know anything about how the data will be used (e.g. reject delay
 *  on Access-Reject)
 *
 * @param[in] instance		of the #fr_app_t or #fr_app_io_t.
 * @param[in] request		request where the VPs to be encoded are located
 * @param[out] buffer		the buffer where the raw packet will be written
 * @param[in] buffer_len	the length of the buffer
 * @return
 *	- <0 on error
 *	- >=0 length of the encoded data in the buffer, will be <=buffer_len
 */
typedef ssize_t (*fr_io_encode_t)(void const *instance, REQUEST *request, uint8_t *buffer, size_t buffer_len);

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
 * @param[in] instance		the context for this function.
 * @param[in] packet		the packet to NAK
 * @param[in] packet_len	length of the packet to NAK
 * @param[in] reply		the NAK reply
 * @param[in] reply_len		length of the buffer where the reply should be placed.
 * @return length of the data in the reply buffer.
 */
typedef size_t (*fr_io_nak_t)(void const *instance, uint8_t *const packet, size_t packet_len,
			      uint8_t *reply, size_t reply_len);

/** Read from a socket.
 *
 * The network side guarantees that the read routine can leave partial
 * data in the buffer.  That data will be there on the next call to
 * read.  However, the data MAY have moved, so please do not keep a
 * pointer to 'buffer' around.
 *
 * datagram sockets should always set '*leftover = 0'.
 *
 * stream sockets can read one packet, and set '*leftover' to how many
 * bytes are left in the buffer.  The read routine will be called
 * again, with a (possibly new) buffer, but with 'leftover' bytes left
 * in the buffer.  The value in 'leftover'' will be the same as from
 * the previous call, so the reader does not need to track it.
 *
 * @param[in] instance		the context for this function
 * @param[out] packet_ctx	Where to write a newly allocated packet_ctx struct containing request specific data.
 * @param[in,out] recv_time	A pointer to a time when the packet was received
 * @param[in,out] buffer	the buffer where the raw packet will be written to (or read from)
 * @param[in] buffer_len	the length of the buffer
 * @param[out] leftover		bytes left in the buffer after reading a full packet.
 * @param[out] priority		priority of this packet (0 = low, 65535 = high)
 * @return
 *	- <0 on error
 *	- >=0 length of the data read or written.
 */
typedef ssize_t (*fr_io_data_read_t)(void const *instance, void **packet_ctx, fr_time_t **recv_time, uint8_t *buffer, size_t buffer_len, size_t *leftover, uint32_t *priority);

/** Write a socket.
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
 *  internal buffer, usually in instance.  It MUST then have a
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
 * @param[in] instance		the context for this function
 * @param[in] packet_ctx	Request specific data.
 * @param[in] request_time	when the original request was received
 * @param[in] buffer		the buffer where the raw packet will be written from
 * @param[in] buffer_len	the length of the buffer
 * @return
 *	- <0 on error
 *	- >=0 length of the data read or written.
 */
typedef ssize_t (*fr_io_data_write_t)(void const *instance, void *packet_ctx, fr_time_t request_time,
				      uint8_t *buffer, size_t buffer_len);

/**  Handle a close or error on the socket.
 *
 *  In general, the only thing to do on errors is to close the
 *  transport.  But on error, the "error" function will be called
 *  before "close".  On normal finish, the "close" function will be
 *  called.
 *
 * @param[in] instance		the context for this function
 * @return
 *	- 0 on success
 *	- <0 on error
 */
typedef int (*fr_io_signal_t)(void const *instance);

/** Process a request through the transport async state machine.
 *
 */
typedef	fr_io_final_t (*fr_io_process_t)(REQUEST *request, fr_io_action_t action);
#ifdef __cplusplus
}
#endif

#endif /* _FR_IO_H */
