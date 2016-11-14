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
 * @file util/channel.h
 * @brief 2-way channels based on kqueue and atomic queues.
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSIDH(channel_h, "$Id$")

#include <freeradius-devel/util/message.h>
#include <freeradius-devel/util/atomic_queue.h>

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

/**
 *  Channel information which is added to a message.
 *
 *  The messages are just for exchanging packet data.  The channel
 *  data structure is for exchanging requests and replies.
 */
typedef struct fr_channel_data_t {
	fr_message_t		m;		//!< the message header

	uint64_t		sequence;	//!< sequence number
	uint64_t		ack;		//!< ACK of the sequence number from the other end

	void			*ctx;		//!< packet context.  Usually socket information

	union {
		struct {
			uint64_t		*start_time;	//!< time original request started (network -> worker)
		} request;

		struct {
			fr_time_t		cpu_time;	//!<  total CPU time, including predicted work, (only worker -> network)
			fr_time_t		processing_time;  //!< actual processing time for this packet (only worker -> network)
	        } reply;
	};

} fr_channel_data_t;

fr_channel_t *fr_channel_create(TALLOC_CTX *ctx, int kq_master, int kq_worker);

int fr_channel_send_request(fr_channel_t *ch, fr_channel_data_t *cm, fr_channel_data_t **p_reply) CC_HINT(nonnull);
fr_channel_data_t *fr_channel_recv_request(fr_channel_t *ch) CC_HINT(nonnull);

int fr_channel_send_reply(fr_channel_t *ch, fr_channel_data_t *cm, fr_channel_data_t **p_request) CC_HINT(nonnull);
fr_channel_data_t *fr_channel_recv_reply(fr_channel_t *ch) CC_HINT(nonnull);

int fr_channel_worker_sleeping(fr_channel_t *ch) CC_HINT(nonnull);
int fr_channel_service_kevent(int kq, struct kevent const *kev, fr_time_t when, fr_channel_t **p_channel) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif

#endif /* _FR_CHANNEL_H */
