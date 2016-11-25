/*
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
 */

/**
 * $Id$
 *
 * @brief Two-way thread-safe channels
 * @file util/channel.c
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/channel.h>
#include <freeradius-devel/rad_assert.h>

#define TO_WORKER (0)
#define FROM_WORKER (1)

#define WHICH_TO_FLAGS(_x)	(((_x) + 1) & 0x03)
//#define FLAGS_TO_WHICH(_x)	(((_x) & 0x03) - 1)

typedef enum fr_channel_signal_t {
	FR_CHANNEL_SIGNAL_DATA_READY = 0,
	FR_CHANNEL_SIGNAL_WORKER_SLEEPING,
	FR_CHANNEL_SIGNAL_OPEN,
	FR_CHANNEL_SIGNAL_CLOSE,
} fr_channel_signal_t;

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
	fr_time_t		last_read_other; //!< last time we successfully read a message from the other the channel
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
	fr_time_t when;
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

	/*
	 *	Initialize all of the timers to now.
	 */
	when = fr_time();

	ch->end[TO_WORKER].last_write = when;
	ch->end[TO_WORKER].last_read_other = when;
	ch->end[TO_WORKER].last_signal = when;

	ch->end[FROM_WORKER].last_write = when;
	ch->end[FROM_WORKER].last_read_other = when;
	ch->end[FROM_WORKER].last_signal = when;

	return ch;
}


/** Send a message via a kq user signal
 *
 *  Note that the caller doesn't care about data in the event, that is
 *  sent via the atomic queue.  The kevent code takes care of
 *  delivering the signal once, even if it's sent by multiple master
 *  threads.
 *
 *  The thread watching the KQ knows which end it is.  So when it gets
 *  the signal (and the channel pointer) it knows to look at end[0] or
 *  end[1].  We also send which end in 'which' (0, 1) to further help
 *  the recipient.
 *
 * @param[in] ch the channel
 * @param[in] when the time when the data is ready.  Typically taken from the message.
 * @param[in] end the end of the channel that the message was written to
 * @param[in] which end of the channel (0/1)
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int fr_channel_data_ready(fr_channel_t *ch, fr_time_t when, fr_channel_end_t *end, int which)
{
	struct kevent kev;

	end->last_signal = when;

	/*
	 *	The ident is the pointer to the channel.  This is so
	 *	that a thread listening on multiple channels can
	 *	receive events unique to each one.
	 */
	EV_SET(&kev, FR_CHANNEL_SIGNAL_DATA_READY, EVFILT_USER, EV_ADD, NOTE_FFOR | WHICH_TO_FLAGS(which), 0, ch);

	return kevent(end->kq, &kev, 1, NULL, 0, NULL);
}

#define IALPHA (8)
#define RTT(_old, _new) ((_old + ((IALPHA - 1) * _new)) / IALPHA)

/** Send a request message into the channel
 *
 *  The message should be initialized, other than "sequence" and "ack".
 *
 *  No matter what the function returns, the caller should check the
 *  reply pointer.  If the reply pointer is not NULL, the caller
 *  should call fr_channel_recv_reply() until that function returns
 *  NULL.
 *
 * @param[in] ch the channel
 * @param[in] cd the message to send
 * @param[out] p_reply a pointer to a reply message
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_send_request(fr_channel_t *ch, fr_channel_data_t *cd, fr_channel_data_t **p_reply)
{
	uint64_t sequence;
	fr_time_t when, message_interval;
	fr_channel_end_t *end;

	end = &(ch->end[TO_WORKER]);
	when = cd->m.when;

	sequence = end->sequence + 1;
	cd->live.sequence = sequence;
	cd->live.ack = end->ack;

	/*
	 *	Push the message onto the queue for the other end.  If
	 *	the push fails, the caller should try another queue.
	 */
	if (!fr_atomic_queue_push(end->aq, cd)) {
		*p_reply = fr_channel_recv_reply(ch);
		return -1;
	}

	end->sequence = sequence;
	message_interval = when - end->last_write;
	end->message_interval = RTT(end->message_interval, message_interval);

	rad_assert(end->last_write <= when);
	end->last_write = when;

	/*
	 *	Increment the number of outstanding packets.  If we
	 *	just sent a new one, wake up the other end.
	 *	Otherwise, rely on the other end to poll or signal as
	 *	necessary.
	 */
	end->num_outstanding++;
	if (end->num_outstanding > 1) {
		*p_reply = fr_channel_recv_reply(ch);
		return 0;
	}

	/*
	 *	We just sent the first request, so there can't
	 *	possibly be a reply yet.
	 */
	*p_reply = NULL;

	/*
	 *	Tell the other end that there is new data ready.
	 */
	return fr_channel_data_ready(ch, when, end, TO_WORKER);
}

/** Receive a reply message from the channel
 *
 * @param[in] ch the channel
 * @return
 *	- NULL on no data to receive
 *	- the message on success
 */
fr_channel_data_t *fr_channel_recv_reply(fr_channel_t *ch)
{
	fr_channel_data_t *cd;
	fr_channel_end_t *end;
	fr_atomic_queue_t *aq;

	aq = ch->end[FROM_WORKER].aq;
	end = &(ch->end[FROM_WORKER]);

	if (!fr_atomic_queue_pop(aq, (void **) &cd)) return NULL;

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
	rad_assert(cd->live.sequence > end->ack);
	rad_assert(cd->live.sequence <= end->sequence); /* must have fewer replies than requests */

	end->num_outstanding--;
	end->ack = cd->live.sequence;

	rad_assert(end->last_read_other <= cd->m.when);
	end->last_read_other = cd->m.when;

	return cd;
}


/** Receive a request message from the channel
 *
 * @param[in] ch the channel
 * @return
 *	- NULL on no data to receive
 *	- the message on success
 */
fr_channel_data_t *fr_channel_recv_request(fr_channel_t *ch)
{
	fr_channel_data_t *cd;
	fr_channel_end_t *end;
	fr_atomic_queue_t *aq;

	aq = ch->end[TO_WORKER].aq;
	end = &(ch->end[FROM_WORKER]);

	if (!fr_atomic_queue_pop(aq, (void **) &cd)) return NULL;

	rad_assert(cd->live.sequence > end->ack);
	rad_assert(cd->live.sequence >= end->sequence); /* must have more requests than replies */

	end->num_outstanding++;
	end->ack = cd->live.sequence;

	rad_assert(end->last_read_other <= cd->m.when);
	end->last_read_other = cd->m.when;

	return cd;
}

/** Send a reply message into the channel
 *
 *  The message should be initialized, other than "sequence" and "ack".
 *
 *  No matter what the function returns, the caller should check the
 *  request pointer.  If the reply pointer is not NULL, the caller
 *  should call fr_channel_recv_request() until that function returns
 *  NULL.
 *
 * @param[in] ch the channel
 * @param[in] cd the message to send
 * @param[out] p_request a pointer to a request message
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_send_reply(fr_channel_t *ch, fr_channel_data_t *cd, fr_channel_data_t **p_request)
{
	uint64_t sequence;
	fr_time_t when, message_interval;
	fr_channel_end_t *end;

	end = &(ch->end[FROM_WORKER]);

	when = cd->m.when;

	sequence = end->sequence + 1;
	cd->live.sequence = sequence;
	cd->live.ack = end->ack;

	if (!fr_atomic_queue_push(end->aq, cd)) {
		*p_request = fr_channel_recv_request(ch);
		return -1;
	}

	rad_assert(end->num_outstanding > 0);
	end->num_outstanding--;

	end->sequence = sequence;
	message_interval = when - end->last_write;
	end->message_interval = RTT(end->message_interval, message_interval);

	rad_assert(end->last_write <= when);
	end->last_write = when;

	/*
	 *	Even if we think we have no more packets to process,
	 *	the caller may have sent us one.  Go check the input
	 *	channel.
	 */
	*p_request = fr_channel_recv_request(ch);

	/*
	 *	No packets outstanding, we HAVE to signal the master
	 *	thread.
	 */
	if (end->num_outstanding == 0) {
		return fr_channel_data_ready(ch, when, end, FROM_WORKER);
	}

	/*
	 *	If we've received a new packet in the last
	 *	millisecond, OR we've sent a signal in the last
	 *	millisecond, then we don't need to send a new signal.
	 *	But we DO send a signal if we haven't seen an ACK for
	 *	a few packets.
	 *
	 *	FIXME: make these limits configurable, or include
	 *	predictions about packet processing time?
	 */
	if ((((end->last_read_other - when) < 1000) ||
	     ((end->last_signal - when) < 1000)) &&
	    (end->sequence - end->ack) <= 3) {
		return 0;
	}

	return fr_channel_data_ready(ch, when, end, FROM_WORKER);
}


/** Signal a channel that the worker is sleeping.
 *
 *  This function should be called from the workers idle loop.
 *  i.e. only when it has nothing else to do.
 *
 * @param[in] ch the channel
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_worker_sleeping(fr_channel_t *ch)
{
	int which;
	struct kevent kev;
	fr_channel_end_t *end;

	which = FROM_WORKER;
	end = &(ch->end[FROM_WORKER]);

	/*
	 *	We don't have any outstanding requests to process for
	 *	this channel, don't signal the network thread that
	 *	we're sleeping.  It already knows.
	 */
	if (end->num_outstanding == 0) return 0;

	/*
	 *	The ident is the pointer to the channel.  This is so
	 *	that a thread listening on multiple channels can
	 *	receive events unique to each one.
	 */
	EV_SET(&kev, FR_CHANNEL_SIGNAL_WORKER_SLEEPING, EVFILT_USER, EV_ADD, NOTE_FFOR | WHICH_TO_FLAGS(which), end->ack, ch);

	return kevent(end->kq, &kev, 1, NULL, 0, NULL);
}


/** Service an EVFILT_USER event.
 *
 *  The channels use EVFILT_USER events for internal signaling.  A
 *  master / worker should call this function for every EVFILT_USER
 *  event.  Note that the caller does NOT pass the channel into this
 *  function.  Instead, the channel is taken from the kevent.
 *
 * @param[in] kq the kqueue on which the event was received
 * @param[in] kev the event of type EVFILT_USER
 * @param[in] when the current time
 * @param[out] p_channel the channel which should be serviced.
 * @return
 *	- FR_CHANNEL_ERROR on error
 *	- FR_CHANNEL_NOOP, on do nothing
 *	- FR_CHANNEL_DATA_READY on data ready
 *	- FR_CHANNEL_OPEN when a channel has been opened and sent to us
 *	- FR_CHANNEL_CLOSE when a channel should be closed
 */
fr_channel_event_t fr_channel_service_kevent(int kq, struct kevent const *kev, fr_time_t when, fr_channel_t **p_channel)
{
	int rcode;
	uint64_t ack;
	fr_channel_end_t *end;
	fr_channel_t *ch;

	rad_assert(kev->filter == EVFILT_USER);

	*p_channel = NULL;

	ch = kev->udata;

#ifndef NDEBUG
	talloc_get_type_abort(ch, fr_channel_t);
#endif

	/*
	 *	Data is ready on one or both channels.  Non-zero
	 *	idents are just signals that data is ready.  We just
	 *	return the channel to the caller, and rely on it to
	 *	service the channel.
	 */
	if (kev->ident == FR_CHANNEL_SIGNAL_DATA_READY) {
		*p_channel = ch;
		return FR_CHANNEL_DATA_READY;
	}

	/*
	 *	Someone is sending us a new channel.  We MUST be the
	 *	worker.  Return the channel to the worker.
	 */
	if (kev->ident == FR_CHANNEL_SIGNAL_OPEN) {
		rad_assert(kq == ch->end[TO_WORKER].kq);

		*p_channel = ch;
		return FR_CHANNEL_OPEN;
	}

	/*
	 *	Only the master can signal that a channel should be
	 *	closed.
	 */
	if (kev->ident == FR_CHANNEL_SIGNAL_CLOSE) {
		rad_assert(kq == ch->end[TO_WORKER].kq);

		*p_channel = ch;
		return FR_CHANNEL_CLOSE;
	}

	rad_assert(kev->ident == FR_CHANNEL_SIGNAL_WORKER_SLEEPING);

	/*
	 *	"worker sleeping" signals are only allowed from the
	 *	worker to the master thread.
	 */
	rad_assert(kq == ch->end[FROM_WORKER].kq);

	/*
	 *	Run-time sanity check.
	 */
	end = &ch->end[FROM_WORKER];
	if (end->kq != kq) return FR_CHANNEL_ERROR;

	end = &ch->end[TO_WORKER];

	/*
	 *	If the signal is ACKing the last packet we sent, we
	 *	don't do anything else.
	 */
	ack = (uint64_t) kev->data;
	if (ack == end->sequence) {
		return FR_CHANNEL_NOOP;
	}

	rad_assert(ack < end->sequence);

	/*
	 *	The worker hasn't seen our last few packets.  Signal
	 *	that there is data ready.
	 */
	rcode = fr_channel_data_ready(ch, when, end, FROM_WORKER);
	if (rcode < 0) return FR_CHANNEL_ERROR;

	return FR_CHANNEL_NOOP;
}


/** Check if a channel is active.
 *
 *  A channel may be closed by either end.  If so, it stays alive (but
 *  inactive) until both ends acknowledge the close.
 *
 * @param[in] ch the channel
 * @return
 *	- false the channel is closing.
 *	- true the channel is active
 */
bool fr_channel_active(UNUSED fr_channel_t *ch)
{
	return true;

}

/** Signal a channel that it is closing.
 *
 * @param[in] ch the channel
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_signal_close(UNUSED fr_channel_t *ch)
{
	return 0;
}
