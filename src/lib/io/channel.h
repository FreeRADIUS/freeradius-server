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
#ifndef _FR_CHANNEL_H
#define _FR_CHANNEL_H
/**
 * $Id$
 *
 * @file io/channel.h
 * @brief 2-way channels based on kqueue and atomic queues.
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(channel_h, "$Id$")

#include <freeradius-devel/io/message.h>
#include <freeradius-devel/io/control.h>

#include <sys/types.h>
#include <sys/event.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  A two-way channel (i.e. pipe) for exchanging information
 *
 *  While the channels are two-way, they are designed to have a
 *  "master" writing requests to the channel, and a "worker" reading
 *  requests, and writing replies back to the master.
 */
typedef struct fr_channel_t fr_channel_t;

typedef enum fr_channel_event_t {
	FR_CHANNEL_ERROR = 0,
	FR_CHANNEL_DATA_READY_WORKER,
	FR_CHANNEL_DATA_READY_RECEIVER,
	FR_CHANNEL_OPEN,
	FR_CHANNEL_CLOSE,

	FR_CHANNEL_NOOP,
	FR_CHANNEL_EMPTY,
} fr_channel_event_t;

/**
 *  Channel information which is added to a message.
 *
 *  The messages are just for exchanging packet data.  The channel
 *  data structure is for exchanging requests and replies.
 */
typedef struct fr_channel_data_t {
	fr_message_t		m;		//!< the message header

	union {
		/*
		 *	Messages have a sequence number / ack while
		 *	they're in a channel.
		 */
		struct {
			uint64_t		sequence;	//!< sequence number
			uint64_t		ack;		//!< ACK of the sequence number from the other end
		} live;

		/*
		 *	Once messages are pulled out of a channel by
		 *	the scheduler, we need to cache the channel
		 *	somewhere.  So we cache it in fields which are now unused.
		 */
		struct {
			fr_channel_t		*ch;		//!< channel where this messages was received
			int			heap_id;	//!< for the various queues
		} channel;
	};

	void			*packet_ctx;	//!< packet context, for per-packet information
	void			*io_ctx; 	//!< context for IO
	uint32_t		transport;	//!< transport ID for this packet
	uint32_t		priority;	//!< priority of this packet.  0=high, 65535=low.

	union {
		struct {
			fr_time_t		*start_time;	//!< time original request started (network -> worker)
			fr_dlist_t		list;		//!< list of unprocessed packets for the worker
		} request;

		struct {
			fr_time_t		cpu_time;	//!<  total CPU time, including predicted work, (only worker -> network)
			fr_time_t		processing_time;  //!< actual processing time for this packet (only worker -> network)
			fr_time_t		request_time;	//!< timestamp of the request packet
	        } reply;
	};

} fr_channel_data_t;

fr_channel_t *fr_channel_create(TALLOC_CTX *ctx, fr_control_t *master, fr_control_t *worker) CC_HINT(nonnull);

int fr_channel_send_request(fr_channel_t *ch, fr_channel_data_t *cm, fr_channel_data_t **p_reply) CC_HINT(nonnull);
fr_channel_data_t *fr_channel_recv_request(fr_channel_t *ch) CC_HINT(nonnull);

int fr_channel_send_reply(fr_channel_t *ch, fr_channel_data_t *cm, fr_channel_data_t **p_request) CC_HINT(nonnull);
fr_channel_data_t *fr_channel_recv_reply(fr_channel_t *ch) CC_HINT(nonnull);

int fr_channel_worker_sleeping(fr_channel_t *ch) CC_HINT(nonnull);

int fr_channel_service_kevent(fr_channel_t *ch, fr_control_t *c, struct kevent const *kev) CC_HINT(nonnull);
fr_channel_event_t fr_channel_service_message(fr_time_t when, fr_channel_t **p_channel, void const *data, size_t data_size) CC_HINT(nonnull);

bool fr_channel_active(fr_channel_t *ch) CC_HINT(nonnull);

int fr_channel_signal_open(fr_channel_t *ch) CC_HINT(nonnull);

int fr_channel_signal_worker_close(fr_channel_t *ch) CC_HINT(nonnull);
int fr_channel_worker_ack_close(fr_channel_t *ch) CC_HINT(nonnull);

void fr_channel_worker_ctx_add(fr_channel_t *ch, void *ctx) CC_HINT(nonnull);
void *fr_channel_worker_ctx_get(fr_channel_t *ch) CC_HINT(nonnull);
void fr_channel_master_ctx_add(fr_channel_t *ch, void *ctx) CC_HINT(nonnull);
void *fr_channel_master_ctx_get(fr_channel_t *ch) CC_HINT(nonnull);


void fr_channel_debug(fr_channel_t *ch, FILE *fp);

#ifdef __cplusplus
}
#endif

#endif /* _FR_CHANNEL_H */
