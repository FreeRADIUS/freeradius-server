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

/*
 *	Debugging, mainly for channel_test
 */
#if 0
#define MPRINT(...) MPRINT(__VA_ARGS__)
#else
#define MPRINT(...)
#endif

#define TO_WORKER (0)
#define FROM_WORKER (1)

/**
 *	The minimum interval between worker signals.
 */
#define SIGNAL_INTERVAL (1000000)

/**
 *	Size of the atomic queues.
 *
 *	The queue reader MUST service the queue occasionally,
 *	otherwise the writer will not be able to write.  If it's too
 *	low, the writer will fail.  If it's too high, it will
 *	unnecessarily use memory.  So we're better off putting it on
 *	the high side.
 *
 *	The reader SHOULD service the queues at inter-packet latency.
 *	i.e. at 1M pps, the queue will get serviced every microsecond.
 */
#define ATOMIC_QUEUE_SIZE (1024)

typedef enum fr_channel_signal_t {
	FR_CHANNEL_SIGNAL_FAIL = 0,
	FR_CHANNEL_SIGNAL_DATA_TO_WORKER,
	FR_CHANNEL_SIGNAL_DATA_FROM_WORKER,
	FR_CHANNEL_SIGNAL_WORKER_SLEEPING,
	FR_CHANNEL_SIGNAL_OPEN,
	FR_CHANNEL_SIGNAL_CLOSE,
} fr_channel_signal_t;

typedef struct fr_channel_control_t {
	fr_channel_signal_t	signal;		//!< the signal to send
	uint64_t		ack;		//!< or the endpoint..
	fr_channel_t		*ch;		//!< the channel
} fr_channel_control_t;

/**
 *  One end of a channel, which consists of a kqueue descriptor, and
 *  an atomic queue.  The atomic queue is there to get bulk data
 *  through, because it's more efficient than pushing 1M+ events per
 *  second through a kqueue.
 */
typedef struct fr_channel_end_t {
	int			kq;		//!< the kqueue associated with the channel

	fr_atomic_queue_t	*aq_control;   	//!< the control channel queue

	int			num_outstanding; //!< number of outstanding requests with no reply

	size_t			num_signals;

	size_t			num_kevents;

	uint64_t		sequence;	//!< sequence number for this channel.
	uint64_t		ack;		//!< sequence number of the other end

	fr_time_t		last_write;	//!< last write to the channel
	fr_time_t		last_read_other; //!< last time we successfully read a message from the other the channel
	fr_time_t		message_interval; //!< interval between messages

	fr_time_t		last_sent_signal; //!< the last time when we signaled the other end

	fr_atomic_queue_t	*aq;		//!< the queue of messages
} fr_channel_end_t;

/**
 *  A full channel, which consists of two ends.
 */
typedef struct fr_channel_t {
	fr_time_t		cpu_time;	//!< total time used by the worker for this channel
	fr_time_t		processing_time; //!< time spent by the worker processing requests

	bool			active;		//!< is this channel active?

	fr_channel_end_t	end[2];		//!< two ends of the channel
} fr_channel_t;


/*
 *	To make debugging easier...
 */
#define EV_FLAG (EV_ADD | EV_CLEAR)

static int fr_channel_add_kevent_worker(struct kevent *kev, int size)
{
	if (size < 3) return -1;

	EV_SET(&kev[0], FR_CHANNEL_SIGNAL_OPEN, EVFILT_USER, EV_FLAG, NOTE_FFNOP, 0, NULL);
	EV_SET(&kev[1], FR_CHANNEL_SIGNAL_CLOSE, EVFILT_USER, EV_FLAG, NOTE_FFNOP, 0, NULL);
	EV_SET(&kev[2], FR_CHANNEL_SIGNAL_DATA_TO_WORKER, EVFILT_USER, EV_FLAG, NOTE_FFNOP, 0, NULL);

	return 3;
}


static int fr_channel_add_kevent_receiver(struct kevent *kev, int size)
{
	if (size < 3) return -1;

	EV_SET(&kev[0], FR_CHANNEL_SIGNAL_WORKER_SLEEPING, EVFILT_USER, EV_FLAG, NOTE_FFNOP, 0, NULL);
	EV_SET(&kev[1], FR_CHANNEL_SIGNAL_CLOSE, EVFILT_USER, EV_FLAG, NOTE_FFNOP, 0, NULL);
	EV_SET(&kev[2], FR_CHANNEL_SIGNAL_DATA_FROM_WORKER, EVFILT_USER, EV_FLAG, NOTE_FFNOP, 0, NULL);

	return 3;
}


static int fr_channel_kevent_signal(int kq, fr_channel_control_t *cc)
{
	struct kevent kev;

	EV_SET(&kev, cc->signal, EVFILT_USER, 0, NOTE_TRIGGER | NOTE_FFCOPY, cc->ack, cc->ch);

	return kevent(kq, &kev, 1, NULL, 0, NULL);
}


/** Create a new channel
 *
 * @param[in] ctx the talloc_ctx for the channel
 * @param[in] kq_master the KQ of the master
 * @param[in] aq_master the atomic of the master, where control data will be sent
 * @param[in] kq_worker the KQ of the worker
 * @param[in] aq_worker the atomic of the worker, where control data will be sent
 * @return
 *	- NULL on error
 *	- channel on success
 */
fr_channel_t *fr_channel_create(TALLOC_CTX *ctx, int kq_master, fr_atomic_queue_t *aq_master,
				int kq_worker, fr_atomic_queue_t *aq_worker)
{
	fr_time_t when;
	fr_channel_t *ch;
	int num_events;
	struct kevent events[4];

	ch = talloc_zero(ctx, fr_channel_t);
	if (!ch) return NULL;

	ch->end[TO_WORKER].aq = fr_atomic_queue_create(ch, ATOMIC_QUEUE_SIZE);
	if (!ch->end[TO_WORKER].aq) {
		talloc_free(ch);
		return NULL;
	}

	ch->end[FROM_WORKER].aq = fr_atomic_queue_create(ch, ATOMIC_QUEUE_SIZE);
	if (!ch->end[FROM_WORKER].aq) {
		talloc_free(ch);
		return NULL;
	}

	ch->end[TO_WORKER].kq = kq_worker;
	ch->end[TO_WORKER].aq_control = aq_worker;
	ch->end[FROM_WORKER].kq = kq_master;
	ch->end[FROM_WORKER].aq_control = aq_master;

	/*
	 *	Initialize all of the timers to now.
	 */
	when = fr_time();

	ch->end[TO_WORKER].last_write = when;
	ch->end[TO_WORKER].last_read_other = when;
	ch->end[TO_WORKER].last_sent_signal = when;

	ch->end[FROM_WORKER].last_write = when;
	ch->end[FROM_WORKER].last_read_other = when;
	ch->end[FROM_WORKER].last_sent_signal = when;

	ch->active = true;

	num_events = fr_channel_add_kevent_worker(events, 4);
	if (kevent(kq_worker, events, num_events, NULL, 0, NULL) < 0) {
		talloc_free(ch);
		return NULL;
	}

	num_events = fr_channel_add_kevent_receiver(events, 4);
	if (kevent(kq_master, events, num_events, NULL, 0, NULL) < 0) {
		talloc_free(ch);
		return NULL;
	}

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
static int fr_channel_data_ready(fr_channel_t *ch, fr_time_t when, fr_channel_end_t *end, fr_channel_signal_t which)
{
	fr_channel_control_t cc;

	end->last_sent_signal = when;
	end->num_signals++;

	cc.signal = which;
	cc.ack = 0;
	cc.ch = ch;

	return fr_channel_kevent_signal(end->kq, &cc);
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
		MPRINT("QUEUE FULL!\n");
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
	return fr_channel_data_ready(ch, when, end, FR_CHANNEL_SIGNAL_DATA_TO_WORKER);
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
	fr_channel_end_t *master;
	fr_atomic_queue_t *aq;

	aq = ch->end[FROM_WORKER].aq;
	master = &(ch->end[TO_WORKER]);

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
	rad_assert(master->num_outstanding > 0);
	rad_assert(cd->live.sequence > master->ack);
	rad_assert(cd->live.sequence <= master->sequence); /* must have fewer replies than requests */

	master->num_outstanding--;
	master->ack = cd->live.sequence;

	rad_assert(master->last_read_other <= cd->m.when);
	master->last_read_other = cd->m.when;

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
	fr_channel_end_t *end, *other;

	end = &(ch->end[FROM_WORKER]);
	other = &(ch->end[TO_WORKER]);

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
		return fr_channel_data_ready(ch, when, end, FR_CHANNEL_SIGNAL_DATA_FROM_WORKER);
	}

	MPRINT("\twhen - last_read_other = %zd - %zd = %zd\n", when, end->last_read_other, when - end->last_read_other);
	MPRINT("\twhen - ast signal = %zd - %zd = %zd\n", when, end->last_sent_signal, when - end->last_sent_signal);
	MPRINT("\tsequence - ack = %zd - %zd = %zd\n", end->sequence, other->ack, end->sequence - other->ack);

	/*
	 *	If we've received a new packet in the last while, OR
	 *	we've sent a signal in the last while, then we don't
	 *	need to send a new signal.  But we DO send a signal if
	 *	we haven't seen an ACK for a few packets.
	 *
	 *	FIXME: make these limits configurable, or include
	 *	predictions about packet processing time?
	 */
	rad_assert(other->ack <= end->sequence);
	if (((end->sequence - other->ack) <= 100) &&
	    ((when - end->last_read_other < SIGNAL_INTERVAL) ||
	     ((when - end->last_sent_signal) < SIGNAL_INTERVAL))) {
		MPRINT("WORKER SKIPS\n");
		return 0;
	}

	MPRINT("WORKER SIGNALS\n");
	return fr_channel_data_ready(ch, when, end, FR_CHANNEL_SIGNAL_DATA_FROM_WORKER);
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
	fr_channel_end_t *end;
	fr_channel_control_t cc;

	end = &(ch->end[FROM_WORKER]);

	/*
	 *	We don't have any outstanding requests to process for
	 *	this channel, don't signal the network thread that
	 *	we're sleeping.  It already knows.
	 */
	if (end->num_outstanding == 0) return 0;

	end->num_signals++;

	cc.signal = FR_CHANNEL_SIGNAL_WORKER_SLEEPING;
	cc.ack = end->ack;
	cc.ch = ch;

	return fr_channel_kevent_signal(end->kq, &cc);
}


/** Service an EVFILT_USER event.
 *
 *  The channels use EVFILT_USER events for internal signaling.  A
 *  master / worker should call this function for every EVFILT_USER
 *  event.  Note that the caller does NOT pass the channel into this
 *  function.  Instead, the channel is taken from the kevent.
 *
 * @param[in] aq the atomic queue on which we receive control-plane messages
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
fr_channel_event_t fr_channel_service_kevent(fr_atomic_queue_t *aq, struct kevent const *kev, fr_time_t when, fr_channel_t **p_channel)
{
	int rcode;
	uint64_t ack;
	fr_channel_end_t *end;
	fr_channel_t *ch;

	rad_assert(kev->filter == EVFILT_USER);

	*p_channel = NULL;

	ch = kev->udata;

	if (aq == ch->end[TO_WORKER].aq_control) {
		ch->end[TO_WORKER].num_kevents++;
	} else {
		ch->end[FROM_WORKER].num_kevents++;
	}

#ifndef NDEBUG
	talloc_get_type_abort(ch, fr_channel_t);
#endif

	switch (kev->ident) {
		/*
		 *	Data is ready on one or both channels.  Non-zero
		 *	idents are just signals that data is ready.  We just
		 *	return the channel to the caller, and rely on it to
		 *	service the channel.
		 */
	case FR_CHANNEL_SIGNAL_DATA_FROM_WORKER:
		*p_channel = ch;
		return FR_CHANNEL_DATA_READY_RECEIVER;

	case FR_CHANNEL_SIGNAL_DATA_TO_WORKER:
		*p_channel = ch;
		return FR_CHANNEL_DATA_READY_WORKER;

		/*
		 *	Someone is sending us a new channel.  We MUST be the
		 *	worker.  Return the channel to the worker.
		 */
	case FR_CHANNEL_SIGNAL_OPEN:
		*p_channel = ch;
		return FR_CHANNEL_OPEN;

		/*
		 *	Each end can signal the channel to close.
		 */
	case FR_CHANNEL_SIGNAL_CLOSE:
		*p_channel = ch;
		return FR_CHANNEL_CLOSE;

	case FR_CHANNEL_SIGNAL_WORKER_SLEEPING:
		break;
	}

	rad_assert(kev->ident == FR_CHANNEL_SIGNAL_WORKER_SLEEPING);

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
	rcode = fr_channel_data_ready(ch, when, end, FR_CHANNEL_SIGNAL_DATA_FROM_WORKER);
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
bool fr_channel_active(fr_channel_t *ch)
{
	return ch->active;
}

/** Signal a worker that the channel is closing
 *
 * @param[in] ch	The channel.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_signal_worker_close(fr_channel_t *ch)
{
	fr_channel_control_t cc;

	ch->active = false;

	cc.signal = FR_CHANNEL_SIGNAL_CLOSE;
	cc.ack = TO_WORKER;
	cc.ch = ch;

	return fr_channel_kevent_signal(ch->end[TO_WORKER].kq, &cc);
}

/** Acknowledge that the channel is closing
 *
 * @param[in] ch	The channel.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_ack_worker_close(fr_channel_t *ch)
{
	fr_channel_control_t cc;

	ch->active = false;

	cc.signal = FR_CHANNEL_SIGNAL_CLOSE;
	cc.ack = FROM_WORKER;
	cc.ch = ch;

	return fr_channel_kevent_signal(ch->end[FROM_WORKER].kq, &cc);
}

/** Send a channel to a KQ
 *
 * @param[in] ch the channel
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_signal_open(fr_channel_t *ch)
{
	fr_channel_control_t cc;

	cc.signal = FR_CHANNEL_SIGNAL_OPEN;
	cc.ack = 0;
	cc.ch = ch;

	return fr_channel_kevent_signal(ch->end[TO_WORKER].kq, &cc);
}

void fr_channel_debug(fr_channel_t *ch, FILE *fp)
{
	fprintf(fp, "to worker\n");
	fprintf(fp, "\tnum_signals sent = %zd\n", ch->end[TO_WORKER].num_signals);
	fprintf(fp, "\tnum_kevents checked = %zd\n", ch->end[TO_WORKER].num_kevents);
	fprintf(fp, "\tsequence = %zd\n", ch->end[TO_WORKER].sequence);
	fprintf(fp, "\tack = %zd\n", ch->end[TO_WORKER].ack);

	fprintf(fp, "to receive\n");
	fprintf(fp, "\tnum_signals sent = %zd\n", ch->end[FROM_WORKER].num_signals);
	fprintf(fp, "\tnum_kevents checked = %zd\n", ch->end[FROM_WORKER].num_kevents);
	fprintf(fp, "\tsequence = %zd\n", ch->end[FROM_WORKER].sequence);
	fprintf(fp, "\tack = %zd\n", ch->end[FROM_WORKER].ack);
}

/** Receive an "open channel" signal.
 *
 *  Called only by the worker.
 *
 * @param[in] ctx the talloc context for worker messages
 * @param[in] ch the channel
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_worker_receive_open(UNUSED TALLOC_CTX *ctx, UNUSED fr_channel_t *ch)
{
#if 0
#ifndef NDEBUG
	talloc_get_type_abort(ch, fr_channel_t);
#endif

	if (ch->end[FROM_WORKER].control) return -1;

	ch->end[FROM_WORKER].control = fr_control_create(ctx,
							 ch->end[FROM_WORKER].kq,
							 ch->end[FROM_WORKER].aq_control);
	if (!ch->end[FROM_WORKER].control) {
		return -1;
	}
#endif

	return 0;
}
