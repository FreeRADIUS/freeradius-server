/*
 * channel.c	Two-way thread-safe channels
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2016  Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/channel.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/types.h>
#include <sys/event.h>

#define TO_WORKER (0)
#define FROM_WORKER (1)

#define WHICH_TO_FLAGS(_x)	(((_x) + 1) & 0x03)
#define FLAGS_TO_WHICH(_x)	(((_x) & 0x03) - 1)

/**
 *  One end of a channel, which consists of a kqueue descriptor, and
 *  an atomic queue.  The atomic queue is there to get bulk data
 *  through, because it's more efficient than pushing 1M+ events per
 *  second through a kqueue.
 */
typedef struct fr_channel_end_t {
	int			kq;		//!< the kqueue associated with the channel

	int			num_outstanding; //!< number of outstanding requests with no reply

	uint64_t		sequence;	//!< sequence number for this channel.
	uint64_t		ack;		//!< sequence number of the other end

	fr_time_t		last_write;	//!< last write to the channel
	fr_time_t		last_read_other; //!< last read from the other the channel
	fr_time_t		message_interval; //!< interval between messages

	fr_time_t		last_signal;	//!< the last time when we signaled the other end

	fr_atomic_queue_t	*aq;		//!< the queue of messages
} fr_channel_end_t;

/**
 *  A full channel, which consists of two ends.
 */
typedef struct fr_channel_t {
	fr_time_t		cpu_time;	//!< total time used by the worker for this channel
	fr_time_t		processing_time; //!< time spent by the worker processing requests

	fr_channel_end_t	end[2];		//!< two ends of the channel
} fr_channel_t;


/** Create a new channel
 *
 * @param[in] ctx the talloc_ctx for the channel
 * @param[in] kq_master the KQ of the master
 * @param[in] kq_worker the KQ of the worker
 * @return
 *	- NULL on error
 *	- channel on success
 */
fr_channel_t *fr_channel_create(TALLOC_CTX *ctx, int kq_master, int kq_worker)
{
	fr_channel_t *ch;

	ch = talloc_zero(ctx, fr_channel_t);
	if (!ch) return NULL;

	ch->end[TO_WORKER].aq = fr_atomic_queue_create(ch, 64);
	if (!ch->end[TO_WORKER].aq) {
		talloc_free(ch);
		return NULL;
	}

	ch->end[FROM_WORKER].aq = fr_atomic_queue_create(ch, 64);
	if (!ch->end[FROM_WORKER].aq) {
		talloc_free(ch);
		return NULL;
	}

	ch->end[TO_WORKER].kq = kq_worker;
	ch->end[FROM_WORKER].kq = kq_master;

	return ch;
}

/** Send a message via a kq user signal
 *
 *  Note that the caller doesn't care about data in the event, that is
 *  sent via the atomic queue.  The kevent code takes care of
 *  delivering the signal once, even if it's sent by multiple network
 *  threads.
 *
 *  The thread watching the KQ knows which end it is.  So when it gets
 *  the signal (and the channel pointer) it knows to look at end[0] or
 *  end[1].  We also send which end in 'which' (0, 1) to further help
 *  the recipient.
 *
 * @param[in] ch the channel to signal
 * @param[in] cd the message to signal
 * @param[in] end the end of the channel that the message was written to
 * @param[in] which end of the channel (0/1)
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int fr_channel_data_ready(fr_channel_t *ch, fr_channel_data_t *cd, fr_channel_end_t *end, int which)
{
	struct kevent kev;

	end->last_signal = cd->m.when;

	/*
	 *	The ident is the pointer to the channel.  This is so
	 *	that a thread listening on multiple channels can
	 *	receive events unique to each one.
	 */
	EV_SET(&kev, (uintptr_t) cd, EVFILT_USER, EV_ADD, NOTE_FFOR | WHICH_TO_FLAGS(which), 0, ch);

	return kevent(end->kq, &kev, 1, NULL, 0, NULL);
}

#define IALPHA (8)
#define RTT(_old, _new) ((_old + ((IALPHA - 1) * _new)) / IALPHA)

/** Send a request message into the channel
 *
 *  The message should be initialized, other than "sequence" and "ack".
 *
 * @param[in] ch the channel to signal
 * @param[in] cd the message to signal
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_send_request(fr_channel_t *ch, fr_channel_data_t *cd)
{
	uint64_t sequence;
	fr_time_t when, message_interval;
	fr_channel_end_t *end;

	end = &(ch->end[TO_WORKER]);
	when = cd->m.when;

	sequence = end->sequence + 1;
	cd->sequence = sequence;
	cd->ack = end->ack;

	/*
	 *	Push the message onto the queue for the other end.  If
	 *	the push fails, the caller should try another queue.
	 */
	if (!fr_atomic_queue_push(end->aq, cd)) {
		return -1;
	}

	end->sequence = sequence;
	message_interval = when - end->last_write;
	end->message_interval = RTT(end->message_interval, message_interval);
	end->last_write = when;
	
	/*
	 *	Increment the number of outstanding packets.  If we
	 *	just sent a new one, wake up the other end.
	 *	Otherwise, rely on the other end to poll or signal as
	 *	necessary.
	 */
	end->num_outstanding++;
	if (end->num_outstanding > 1) {
		return 0;
	}

	/*
	 *	Tell the other end that there is new data ready.
	 */
	return fr_channel_data_ready(ch, cd, end, TO_WORKER);
}

/** Receive a reply message from the channel
 *
 * @param[in] ch the channel to signal
 * @param[in] when the time when we're polling this channel
 * @return
 *	- NULL on no data to receive
 *	- the message on success
 */
fr_channel_data_t *fr_channel_recv_reply(fr_channel_t *ch, fr_time_t when)
{
	fr_channel_data_t *cd;
	fr_channel_end_t *end;
	fr_atomic_queue_t *aq;

	aq = ch->end[FROM_WORKER].aq;
	end = &(ch->end[FROM_WORKER]);

	if (!fr_atomic_queue_pop(aq, (void **) &cd)) {
		end->last_read_other = when;
		return NULL;
	}

	/*
	 *	We want an exponential moving average for round trip
	 *	time, where "alpha" is a number between [0,1)
	 *
	 *	RTT_new = alpha * RTT_old + (1 - alpha) * RTT_sample
	 *
	 *	BUT we use fixed-point arithmetic, so we need to use inverse alpha,
	 *	which works out to the following equation:
	 *
	 *	RTT_new = (RTT_old + (ialpha - 1) * RTT_sample) / ialpha
	 */
	ch->processing_time = RTT(ch->processing_time, cd->reply.processing_time);
	ch->cpu_time = cd->reply.cpu_time;

	/*
	 *	Update the outbound channel with the knowledge that
	 *	we've received one more reply, and with the workers
	 *	ACK.
	 */
	rad_assert(end->num_outstanding > 0);
	rad_assert(cd->sequence > end->ack);
	rad_assert(cd->sequence <= end->sequence); /* must have fewer replies than requests */

	end->num_outstanding--;
	end->ack = cd->sequence;
	end->last_read_other = cd->m.when;

	return cd;
}


/** Receive a request message from the channel
 *
 * @param[in] ch the channel to signal
 * @param[in] when the time when we're polling this channel
 * @return
 *	- NULL on no data to receive
 *	- the message on success
 */
fr_channel_data_t *fr_channel_recv_request(fr_channel_t *ch, fr_time_t when)
{
	fr_channel_data_t *cd;
	fr_channel_end_t *end;
	fr_atomic_queue_t *aq;

	aq = ch->end[TO_WORKER].aq;
	end = &(ch->end[FROM_WORKER]);

	if (!fr_atomic_queue_pop(aq, (void **) &cd)) {
		end->last_read_other = when;
		return NULL;
	}

	rad_assert(cd->sequence > end->ack);
	rad_assert(cd->sequence >= end->sequence); /* must have more requests than replies */

	end->num_outstanding++;
	end->ack = cd->sequence;
	end->last_read_other = cd->m.when;

	return cd;
}

/** Send a reply message into the channel
 *
 *  The message should be initialized, other than "sequence" and "ack".
 *
 * @param[in] ch the channel to signal
 * @param[in] cd the message to signal
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_send_reply(fr_channel_t *ch, fr_channel_data_t *cd)
{
	uint64_t sequence;
	fr_time_t when, message_interval;
	fr_channel_end_t *end;

	end = &(ch->end[FROM_WORKER]);

	when = cd->m.when;

	sequence = end->sequence + 1;
	cd->sequence = sequence;
	cd->ack = end->ack;

	if (!fr_atomic_queue_push(end->aq, cd)) {
		return -1;
	}
	
	rad_assert(end->num_outstanding > 0);
	end->num_outstanding--;

	end->sequence = sequence;
	message_interval = when - end->last_write;
	end->message_interval = RTT(end->message_interval, message_interval);
	end->last_write = when;

	/*
	 *	No packets outstanding, we HAVE to signal the network
	 *	thread.
	 */
	if (end->num_outstanding == 0) {
		return fr_channel_data_ready(ch, cd, end, FROM_WORKER);
	}

	/*
	 *	If we've received a new packet in the last
	 *	millisecond, OR we've sent a signal in the last
	 *	millisecond, OR we've sent 3 or fewer replies without
	 *	an ACK, we don't need to send a new signal.
	 *
	 *	FIXME: make these limits configurable...
	 */
	if (((end->last_read_other - when) < (NANOSEC / 1000)) ||
	    ((end->last_signal - when) < (NANOSEC / 1000)) ||
	    ((end->sequence - end->ack) <= 3)) {
		return 0;
	}

	return fr_channel_data_ready(ch, cd, end, FROM_WORKER);
}
