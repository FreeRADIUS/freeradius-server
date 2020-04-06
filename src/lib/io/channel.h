#pragma once
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

/**
 * $Id$
 *
 * @file io/channel.h
 * @brief 2-way channels based on kqueue and atomic queues.
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(channel_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/table.h>

/**
 *  A two-way channel (i.e. pipe) for exchanging information
 *
 *  While the channels are two-way, they are designed to have a
 *  "frontend" writing requests to the channel, and a "worker" reading
 *  requests, and writing replies back to the frontend.
 */
typedef struct fr_channel_s fr_channel_t;

/*
 *	Forward declaration until such time as we fix the code so that
 *	the network threads can push transports to worker threads.
 */
typedef struct fr_listen fr_listen_t;

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/io/message.h>
#include <freeradius-devel/io/control.h>
#include <freeradius-devel/io/base.h>
#include <freeradius-devel/util/dlist.h>

#include <sys/types.h>
#include <sys/event.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum fr_channel_event_t {
	FR_CHANNEL_ERROR = 0,
	FR_CHANNEL_DATA_READY_RESPONDER,
	FR_CHANNEL_DATA_READY_REQUESTOR,
	FR_CHANNEL_OPEN,
	FR_CHANNEL_CLOSE,

	FR_CHANNEL_NOOP,
	FR_CHANNEL_EMPTY,
} fr_channel_event_t;

/** Statistics for the channel
 *
 */
typedef struct {
	uint64_t       		outstanding; 	//!< Number of outstanding requests with no reply.
	uint64_t		signals;	//!< Number of kevent signals we've sent.
	uint64_t		resignals;	//!< Number of signals resent.

	uint64_t		packets;	//!< Number of actual data packets.

	uint64_t		kevents;	//!< Number of times we've looked at kevents.

	fr_time_t		last_write;	//!< Last write to the channel.
	fr_time_t		last_read_other; //!< Last time we successfully read a message from the other the channel
	fr_time_delta_t		message_interval; //!< Interval between messages.

	fr_time_t		last_sent_signal; //!< The last time when we signaled the other end.
} fr_channel_stats_t;


/**
 *  Channel information which is added to a message.
 *
 *  The messages are just for exchanging packet data.  The channel
 *  data structure is for exchanging requests and replies.
 */
typedef struct {
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
			int32_t			heap_id;	//!< for the various queues
		} channel;
	};

	union {
		struct {
			fr_time_t		recv_time;	//!< time original request was received (network -> worker)
			bool			is_dup;		//!< dup, new, etc.
		} request;

		struct {
			fr_time_delta_t		cpu_time;	//!<  total CPU time, including predicted work, (only worker -> network)
			fr_time_delta_t		processing_time;  //!< actual processing time for this packet (only worker -> network)
			fr_time_t		request_time;	//!< timestamp of the request packet
	        } reply;
	};

	uint32_t	priority;				//!< Priority of this packet.

	void		*packet_ctx;				//!< Packet specific context for holding client
								//!< information, and other proto_* specific information
								//!< that needs to be passed to the request.

	fr_listen_t	*listen;				//!< for tracking packet transport, etc.
} fr_channel_data_t;

#define PRIORITY_NOW    (1 << 16)
#define PRIORITY_HIGH   (1 << 15)
#define PRIORITY_NORMAL (1 << 14)
#define PRIORITY_LOW    (1 << 13)

extern fr_table_num_sorted_t const channel_signals[];
extern size_t channel_signals_len;
extern fr_table_num_sorted_t const channel_packet_priority[];
extern size_t channel_packet_priority_len;

fr_channel_t *fr_channel_create(TALLOC_CTX *ctx, fr_control_t *frontend, fr_control_t *worker, bool same) CC_HINT(nonnull);

int	fr_channel_send_request(fr_channel_t *ch, fr_channel_data_t *cm) CC_HINT(nonnull);
bool	fr_channel_recv_request(fr_channel_t *ch) CC_HINT(nonnull);

int	fr_channel_send_reply(fr_channel_t *ch, fr_channel_data_t *cd) CC_HINT(nonnull);
int	fr_channel_null_reply(fr_channel_t *ch) CC_HINT(nonnull);

bool	fr_channel_recv_reply(fr_channel_t *ch) CC_HINT(nonnull);

typedef void (*fr_channel_recv_callback_t)(void *ctx, fr_channel_t *ch, fr_channel_data_t *cd);
int	fr_channel_set_recv_reply(fr_channel_t *ch, void *ctx, fr_channel_recv_callback_t recv_reply) CC_HINT(nonnull(1,3));
int	fr_channel_set_recv_request(fr_channel_t *ch, void *ctx, fr_channel_recv_callback_t recv_reply) CC_HINT(nonnull(1,3));

int	fr_channel_responder_sleeping(fr_channel_t *ch) CC_HINT(nonnull);

int	fr_channel_service_kevent(fr_channel_t *ch, fr_control_t *c, struct kevent const *kev) CC_HINT(nonnull);
fr_channel_event_t	fr_channel_service_message(fr_time_t when, fr_channel_t **p_channel, void const *data, size_t data_size) CC_HINT(nonnull);

bool	fr_channel_active(fr_channel_t *ch) CC_HINT(nonnull);

int	fr_channel_signal_open(fr_channel_t *ch) CC_HINT(nonnull);

int	fr_channel_signal_responder_close(fr_channel_t *ch) CC_HINT(nonnull);
int	fr_channel_responder_ack_close(fr_channel_t *ch) CC_HINT(nonnull);

void	fr_channel_responder_uctx_add(fr_channel_t *ch, void *ctx) CC_HINT(nonnull);
void	*fr_channel_responder_uctx_get(fr_channel_t *ch) CC_HINT(nonnull);
void	fr_channel_requestor_uctx_add(fr_channel_t *ch, void *ctx) CC_HINT(nonnull);
void	*fr_channel_requestor_uctx_get(fr_channel_t *ch) CC_HINT(nonnull);


void	fr_channel_stats_log(fr_channel_t const *ch, fr_log_t const *log, char const *file, int line);

#ifdef __cplusplus
}
#endif
