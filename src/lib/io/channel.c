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
 * @brief Two-way thread-safe channels.
 * @file io/channel.c
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/io/channel.h>
#include <freeradius-devel/io/control.h>
#include <freeradius-devel/util/log.h>
#include <freeradius-devel/server/rad_assert.h>

/*
 *	Debugging, mainly for channel_test
 */
#if 0
#define MPRINT(...) fprintf(stdout, __VA_ARGS__)
#else
#define MPRINT(...)
#endif

/*
 *	We disable this until we fix all of the signaling issues...
 */
#define ENABLE_SKIPS (0)

#define TO_WORKER (0)
#define FROM_WORKER (1)

#if 0
#define SIGNAL_INTERVAL (1000000)	//!< The minimum interval between worker signals.
#endif

/** Size of the atomic queues
 *
 * The queue reader MUST service the queue occasionally,
 * otherwise the writer will not be able to write.  If it's too
 * low, the writer will fail.  If it's too high, it will
 * unnecessarily use memory.  So we're better off putting it on
 * the high side.
 *
 * The reader SHOULD service the queues at inter-packet latency.
 * i.e. at 1M pps, the queue will get serviced every microsecond.
 */
#define ATOMIC_QUEUE_SIZE (1024)

typedef enum fr_channel_signal_t {
	FR_CHANNEL_SIGNAL_ERROR			= FR_CHANNEL_ERROR,
	FR_CHANNEL_SIGNAL_DATA_TO_WORKER	= FR_CHANNEL_DATA_READY_WORKER,
	FR_CHANNEL_SIGNAL_DATA_FROM_WORKER	= FR_CHANNEL_DATA_READY_NETWORK,
	FR_CHANNEL_SIGNAL_OPEN			= FR_CHANNEL_OPEN,
	FR_CHANNEL_SIGNAL_CLOSE			= FR_CHANNEL_CLOSE,

	/*
	 *	The preceding MUST be in the same order as fr_channel_event_t
	 */

	FR_CHANNEL_SIGNAL_DATA_DONE_WORKER,
	FR_CHANNEL_SIGNAL_WORKER_SLEEPING,
} fr_channel_signal_t;

typedef struct {
	fr_channel_signal_t	signal;		//!< the signal to send
	uint64_t		ack;		//!< or the endpoint..
	fr_channel_t		*ch;		//!< the channel
} fr_channel_control_t;

/** One end of a channel
 *
 * Consists of a kqueue descriptor, and an atomic queue.
 * The atomic queue is there to get bulk data through, because it's more efficient
 * than pushing 1M+ events per second through a kqueue.
 */
typedef struct {
	fr_control_t		*control;	//!< The control plane, consisting of an atomic queue and kqueue.

	fr_ring_buffer_t	*rb;		//!< Ring buffer for control-plane messages.

	void			*ctx;		//!< Worker context.

	fr_channel_recv_callback_t recv;	//!< callback for receiving messages
	void			*recv_ctx;	//!< context for receiving messages

	int			num_outstanding; //!< Number of outstanding requests with no reply.
	bool			must_signal;	//!< we need to signal the other end

	size_t			num_signals;	//!< Number of kevent signals we've sent.

	size_t			num_resignals;	//!< Number of signals resent.

	size_t			num_kevents;	//!< Number of times we've looked at kevents.

	uint64_t		sequence;	//!< Sequence number for this channel.
	uint64_t		ack;		//!< Sequence number of the other end.
	uint64_t		their_view_of_my_sequence;	//!< Should be clear.

	uint64_t		sequence_at_last_signal;	//!< When we last signaled.

	uint64_t		num_packets;	//!< Number of actual data packets.

	fr_time_t		last_write;	//!< Last write to the channel.
	fr_time_t		last_read_other; //!< Last time we successfully read a message from the other the channe;
	fr_time_t		message_interval; //!< Interval between messages.

	fr_time_t		last_sent_signal; //!< The last time when we signaled the other end.

	fr_atomic_queue_t	*aq;		//!< The queue of messages - visible only to this channel.
} fr_channel_end_t;

typedef struct fr_channel_s fr_channel_t;

/** A full channel, which consists of two ends
 *
 * A channel consists of the kqueue identifiers and an atomic queue in each
 * direction to allow for bidirectional communication.
 */
struct fr_channel_s {
	fr_time_t		cpu_time;	//!< Total time used by the worker for this channel.
	fr_time_t		processing_time; //!< Time spent by the worker processing requests.

	bool			active;		//!< Whether the channel is active.
	bool			same_thread;	//!< are both ends in the same thread?

	fr_channel_end_t	end[2];		//!< Two ends of the channel.
};

fr_table_num_sorted_t const channel_packet_priority[] = {
	{ "high",	PRIORITY_HIGH		},
	{ "low",	PRIORITY_LOW		},
	{ "normal",	PRIORITY_NORMAL		},
	{ "now",	PRIORITY_NOW		}
};
size_t channel_packet_priority_len = NUM_ELEMENTS(channel_packet_priority);


/** Create a new channel
 *
 * @param[in] ctx	The talloc_ctx to allocate channel data in.
 * @param[in] master	control plane.
 * @param[in] worker	control plane.
 * @param[in] same	whether or not the channel is for the same thread
 * @return
 *	- NULL on error
 *	- channel on success
 */
fr_channel_t *fr_channel_create(TALLOC_CTX *ctx, fr_control_t *master, fr_control_t *worker, bool same)
{
	fr_time_t when;
	fr_channel_t *ch;

	ch = talloc_zero(ctx, fr_channel_t);
	if (!ch) {
	nomem:
		fr_strerror_printf("Failed allocating memory");
		return NULL;
	}

	ch->same_thread = same;

	ch->end[TO_WORKER].aq = fr_atomic_queue_create(ch, ATOMIC_QUEUE_SIZE);
	if (!ch->end[TO_WORKER].aq) {
		talloc_free(ch);
		goto nomem;
	}

	ch->end[FROM_WORKER].aq = fr_atomic_queue_create(ch, ATOMIC_QUEUE_SIZE);
	if (!ch->end[FROM_WORKER].aq) {
		talloc_free(ch);
		goto nomem;
	}

	ch->end[TO_WORKER].control = worker;
	ch->end[FROM_WORKER].control = master;

	/*
	 *	Create the ring buffer for the master to send
	 *	control-plane messages to the worker, and vice-versa.
	 */
	ch->end[TO_WORKER].rb = fr_ring_buffer_create(ch, FR_CONTROL_MAX_MESSAGES * FR_CONTROL_MAX_SIZE);
	if (!ch->end[TO_WORKER].rb) {
	rb_nomem:
		fr_strerror_printf_push("Failed allocating ring buffer");
		talloc_free(ch);
		return NULL;
	}

	ch->end[FROM_WORKER].rb = fr_ring_buffer_create(ch, FR_CONTROL_MAX_MESSAGES * FR_CONTROL_MAX_SIZE);
	if (!ch->end[FROM_WORKER].rb) {
		talloc_free(ch);
		goto rb_nomem;
	}

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

	return ch;
}


/** Send a message via a kq user signal
 *
 * Note that the caller doesn't care about data in the event, that is
 * sent via the atomic queue.  The kevent code takes care of
 * delivering the signal once, even if it's sent by multiple master
 * threads.
 *
 * The thread watching the KQ knows which end it is.  So when it gets
 * the signal (and the channel pointer) it knows to look at end[0] or
 * end[1].  We also send which end in 'which' (0, 1) to further help
 * the recipient.
 *
 * @param[in] ch	the channel.
 * @param[in] when	the data was ready.  Typically taken from the message.
 * @param[in] end	of the channel that the message was written to.
 * @param[in] which	end of the channel (0/1).
 * @return
 *	- <0 on error
 *	- 0 on success
 */
static int fr_channel_data_ready(fr_channel_t *ch, fr_time_t when, fr_channel_end_t *end, fr_channel_signal_t which)
{
	fr_channel_control_t cc;

	end->last_sent_signal = when;
	end->num_signals++;
	end->must_signal = false;

	cc.signal = which;
	cc.ack = end->ack;
	cc.ch = ch;

	return fr_control_message_send(end->control, end->rb, FR_CONTROL_ID_CHANNEL, &cc, sizeof(cc));
}

#define IALPHA (8)
#define RTT(_old, _new) ((_new + ((IALPHA - 1) * _old)) / IALPHA)

/** Send a request message into the channel
 *
 * The message should be initialized, other than "sequence" and "ack".
 *
 * This function automatically calls the recv_reply callback if there is a reply.
 *
 * @param[in] ch	the channel to send the request on.
 * @param[in] cd	the message to send.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_send_request(fr_channel_t *ch, fr_channel_data_t *cd)
{
	uint64_t sequence;
	fr_time_t when, message_interval;
	fr_channel_end_t *master;

	/*
	 *	Same thread?  Just call the "recv" function directly.
	 */
	if (ch->same_thread) {
		ch->end[FROM_WORKER].recv(ch->end[FROM_WORKER].recv_ctx, ch, cd);
		return 0;
	}

	master = &(ch->end[TO_WORKER]);
	when = cd->m.when;

	sequence = master->sequence + 1;
	cd->live.sequence = sequence;
	cd->live.ack = master->ack;

	/*
	 *	Push the message onto the queue for the other end.  If
	 *	the push fails, the caller should try another queue.
	 */
	if (!fr_atomic_queue_push(master->aq, cd)) {
		fr_strerror_printf("Failed pushing to atomic queue");
		while (fr_channel_recv_reply(ch)) {
			/* do nothing */
		}
		return -1;
	}

	master->sequence = sequence;
	message_interval = when - master->last_write;

	if (!master->message_interval) {
		master->message_interval = message_interval;
	} else {
		master->message_interval = RTT(master->message_interval, message_interval);
	}

	rad_assert(master->last_write <= when);
	master->last_write = when;

	master->num_outstanding++;
	master->num_packets++;

	MPRINT("MASTER requests %zd, num_outstanding %zd\n", master->num_packets, master->num_outstanding);

#if ENABLE_SKIPS
	/*
	 *	We just sent the first packet.  There can't possibly be a reply, so don't bother looking.
	 */
	if (master->num_outstanding == 1) {

		/*
		 *	There is at least one old packet which is
		 *	outstanding, look for a reply.
		 */
	} else if (master->num_outstanding > 1) {
		while (fr_channel_recv_reply(ch)) {
			/* do nothing */
		}

		/*
		 *	There's no reply yet, so we still have packets outstanding.
		 *	Or, there is a reply, and there are more packets outstanding.
		 *	Skip the signal.
		 */
		if (!master->must_signal && (!*p_reply || (*p_reply && (master->num_outstanding > 1)))) {
			MPRINT("MASTER SKIPS signal\n");
			return 0;
		}
	}
#endif

	/*
	 *	Tell the other end that there is new data ready.
	 *
	 *	Ignore errors on signalling.  The worker already has
	 *	the packet in its inbound queue, so at some point, it
	 *	will pick up the message.
	 */
	MPRINT("MASTER SIGNALS\n");
	(void) fr_channel_data_ready(ch, when, master, FR_CHANNEL_SIGNAL_DATA_TO_WORKER);
	return 0;
}

/** Receive a reply message from the channel
 *
 * @param[in] ch	the channel to read data from.
 * @return
 *	- true if there was a message received
 *	- false if there are no more messages
 */
bool fr_channel_recv_reply(fr_channel_t *ch)
{
	fr_channel_data_t *cd;
	fr_channel_end_t *master;
	fr_atomic_queue_t *aq;

	rad_assert(ch->end[TO_WORKER].recv != NULL);

	aq = ch->end[FROM_WORKER].aq;
	master = &(ch->end[TO_WORKER]);

	/*
	 *	It's OK for the queue to be empty.
	 */
	if (!fr_atomic_queue_pop(aq, (void **) &cd)) return false;

	/*
	 *	We want an exponential moving average for round trip
	 *	time, where "alpha" is a number between [0,1)
	 *
	 *	RTT_new = alpha * RTT_old + (1 - alpha) * RTT_sample
	 *
	 *	BUT we use fixed-point arithmetic, so we need to use inverse alpha,
	 *	which works out to the following equation:
	 *
	 *	RTT_new = (RTT_sample + (ialpha - 1) * RTT_old) / ialpha
	 *
	 *	NAKs have zero processing time, so we ignore them for
	 *	the purpose of RTT.
	 */
	if (cd->reply.processing_time) {
		ch->processing_time = RTT(ch->processing_time, cd->reply.processing_time);
	}
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
	master->their_view_of_my_sequence = cd->live.ack;

	rad_assert(master->last_read_other <= cd->m.when);
	master->last_read_other = cd->m.when;

	ch->end[TO_WORKER].recv(ch->end[TO_WORKER].recv_ctx, ch, cd);

	return true;
}


/** Receive a request message from the channel
 *
 * @param[in] ch the channel
 * @return
 *	- true if there was a message received
 *	- false if there are no more messages
 */
bool fr_channel_recv_request(fr_channel_t *ch)
{
	fr_channel_data_t *cd;
	fr_channel_end_t *worker;
	fr_atomic_queue_t *aq;

	aq = ch->end[TO_WORKER].aq;
	worker = &(ch->end[FROM_WORKER]);

	/*
	 *	It's OK for the queue to be empty.
	 */
	if (!fr_atomic_queue_pop(aq, (void **) &cd)) return false;

	rad_assert(cd->live.sequence > worker->ack);
	rad_assert(cd->live.sequence >= worker->sequence); /* must have more requests than replies */

	worker->num_outstanding++;
	worker->ack = cd->live.sequence;
	worker->their_view_of_my_sequence = cd->live.ack;

	rad_assert(worker->last_read_other <= cd->m.when);
	worker->last_read_other = cd->m.when;

	ch->end[FROM_WORKER].recv(ch->end[FROM_WORKER].recv_ctx, ch, cd);

	return true;
}

/** Send a reply message into the channel
 *
 * The message should be initialized, other than "sequence" and "ack".
 *
 * @param[in] ch		the channel to send the reply on.
 * @param[in] cd		the message to send
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_send_reply(fr_channel_t *ch, fr_channel_data_t *cd)
{
	uint64_t sequence;
	fr_time_t when, message_interval;
	fr_channel_end_t *worker;

	/*
	 *	Same thread?  Just call the "recv" function directly.
	 */
	if (ch->same_thread) {
		ch->end[TO_WORKER].recv(ch->end[TO_WORKER].recv_ctx, ch, cd);
		return 0;
	}

	worker = &(ch->end[FROM_WORKER]);

	when = cd->m.when;

	sequence = worker->sequence + 1;
	cd->live.sequence = sequence;
	cd->live.ack = worker->ack;

	if (!fr_atomic_queue_push(worker->aq, cd)) {
		fr_strerror_printf("Failed pushing to atomic queue");
		while (fr_channel_recv_request(ch)) {
			/* nothing */
		}
		return -1;
	}

	rad_assert(worker->num_outstanding > 0);
	worker->num_outstanding--;
	worker->num_packets++;

	MPRINT("\tWORKER replies %zd, num_outstanding %zd\n", worker->num_packets, worker->num_outstanding);

	worker->sequence = sequence;
	message_interval = when - worker->last_write;
	worker->message_interval = RTT(worker->message_interval, message_interval);

	rad_assert(worker->last_write <= when);
	worker->last_write = when;

	/*
	 *	Even if we think we have no more packets to process,
	 *	the caller may have sent us one.  Go check the input
	 *	channel.
	 */
	while (fr_channel_recv_request(ch)) {
		/* nothing */
	}

	/*
	 *	No packets outstanding, we HAVE to signal the master
	 *	thread.
	 */
	if (worker->num_outstanding == 0) {
		(void) fr_channel_data_ready(ch, when, worker, FR_CHANNEL_SIGNAL_DATA_DONE_WORKER);
		return 0;
	}

	MPRINT("\twhen - last_read_other = %zd - %zd = %zd\n", when, worker->last_read_other, when - worker->last_read_other);
	MPRINT("\twhen - last signal = %zd - %zd = %zd\n", when, worker->last_sent_signal, when - worker->last_sent_signal);
	MPRINT("\tsequence - ack = %zd - %zd = %zd\n", worker->sequence, worker->their_view_of_my_sequence, worker->sequence - worker->their_view_of_my_sequence);

#ifdef __APPLE__
	/*
	 *	If we've sent them a signal since the last ACK, they
	 *	will receive it, and process the packets.  So we don't
	 *	need to signal them again.
	 *
	 *	But... this doesn't appear to work on the Linux
	 *	libkqueue implementation.
	 */
	if (worker->sequence_at_last_signal > worker->their_view_of_my_sequence) return 0;
#endif

	/*
	 *	If we've received a new packet in the last while, OR
	 *	we've sent a signal in the last while, then we don't
	 *	need to send a new signal.  But we DO send a signal if
	 *	we haven't seen an ACK for a few packets.
	 *
	 *	FIXME: make these limits configurable, or include
	 *	predictions about packet processing time?
	 */
	rad_assert(worker->their_view_of_my_sequence <= worker->sequence);
#if 0
	if (((worker->sequence - worker->their_view_of_my_sequence) <= 1000) &&
	    ((when - worker->last_read_other < SIGNAL_INTERVAL) ||
	     ((when - worker->last_sent_signal) < SIGNAL_INTERVAL))) {
		MPRINT("\tWORKER SKIPS signal\n");
		return 0;
	}
#endif

	MPRINT("\tWORKER SIGNALS num_outstanding %zd\n", worker->num_outstanding);
	(void) fr_channel_data_ready(ch, when, worker, FR_CHANNEL_SIGNAL_DATA_FROM_WORKER);
	return 0;
}


/** Don't send a reply message into the channel
 *
 * The message should be the one we received from the network.
 *
 * @param[in] ch		the channel on which we're dropping a packet
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_null_reply(fr_channel_t *ch)
{
	fr_channel_end_t *worker;

	worker = &(ch->end[FROM_WORKER]);

	worker->sequence++;
	return 0;
}



/** Signal a channel that the worker is sleeping
 *
 * This function should be called from the workers idle loop.
 * i.e. only when it has nothing else to do.
 *
 * @param[in] ch	the channel to signal we're no longer listening on.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_worker_sleeping(fr_channel_t *ch)
{
	fr_channel_end_t *worker;
	fr_channel_control_t cc;

	worker = &(ch->end[FROM_WORKER]);

	/*
	 *	We don't have any outstanding requests to process for
	 *	this channel, don't signal the network thread that
	 *	we're sleeping.  It already knows.
	 */
	if (worker->num_outstanding == 0) return 0;

	worker->num_signals++;

	cc.signal = FR_CHANNEL_SIGNAL_WORKER_SLEEPING;
	cc.ack = worker->ack;
	cc.ch = ch;

	MPRINT("\tWORKER SLEEPING num_outstanding %zd, packets in %zd, packets out %zd\n", worker->num_outstanding,
	       ch->end[TO_WORKER].num_packets, worker->num_packets);
	return fr_control_message_send(worker->control, worker->rb, FR_CONTROL_ID_CHANNEL, &cc, sizeof(cc));
}


/** Service a control-plane message
 *
 * @param[in] when		The current time.
 * @param[out] p_channel	The channel which should be serviced.
 * @param[in] data		The control message.
 * @param[in] data_size		The size of the control message.
 * @return
 *	- FR_CHANNEL_ERROR on error
 *	- FR_CHANNEL_NOOP, on do nothing
 *	- FR_CHANNEL_DATA_READY on data ready
 *	- FR_CHANNEL_OPEN when a channel has been opened and sent to us
 *	- FR_CHANNEL_CLOSE when a channel should be closed
 */
fr_channel_event_t fr_channel_service_message(fr_time_t when, fr_channel_t **p_channel, void const *data, size_t data_size)
{
	int rcode;
#if ENABLE_SKIPS
	uint64_t ack;
#endif
	fr_channel_control_t cc;
	fr_channel_signal_t cs;
	fr_channel_event_t ce = FR_CHANNEL_ERROR;
	fr_channel_end_t *master;
	fr_channel_t *ch;

	rad_assert(data_size == sizeof(cc));
	memcpy(&cc, data, data_size);

	cs = cc.signal;
#if ENABLE_SKIPS
	ack = cc.ack;
#endif
	*p_channel = ch = cc.ch;

	switch (cs) {
	/*
	 *	These all have the same numbers as the channel
	 *	events, and have no extra processing.  We just
	 *	return them as-is.
	 */
	case FR_CHANNEL_SIGNAL_ERROR:
	case FR_CHANNEL_SIGNAL_DATA_TO_WORKER:
	case FR_CHANNEL_SIGNAL_DATA_FROM_WORKER:
	case FR_CHANNEL_SIGNAL_OPEN:
	case FR_CHANNEL_SIGNAL_CLOSE:
		MPRINT("channel got %d\n", cs);
		return (fr_channel_event_t) cs;

	/*
	 *	Only sent by the worker.  Both of these
	 *	situations are largely the same, except for
	 *	return codes.
	 */
	case FR_CHANNEL_SIGNAL_DATA_DONE_WORKER:
		MPRINT("channel got data_done_worker\n");
		ce = FR_CHANNEL_DATA_READY_NETWORK;
		ch->end[TO_WORKER].must_signal = true;
		break;

	case FR_CHANNEL_SIGNAL_WORKER_SLEEPING:
		MPRINT("channel got worker_sleeping\n");
		ce = FR_CHANNEL_NOOP;
		ch->end[TO_WORKER].must_signal = true;
		break;
	}

	/*
	 *	Compare their ACK to the last sequence we
	 *	sent.  If it's different, we signal the worker
	 *	to wake up.
	 */
	master = &ch->end[TO_WORKER];
#if ENABLE_SKIPS
	if (!master->must_signal && (ack == master->sequence)) {
		MPRINT("MASTER SKIPS signal AFTER CE %d num_outstanding %zd\n", cs, master->num_outstanding);
		MPRINT("MASTER has ack %zd, my seq %zd my_view %zd\n", ack, master->sequence, master->their_view_of_my_sequence);
		return ce;
	}

	/*
	 *	The worker is sleeping or done.  There are more
	 *	packets available, so we signal it to wake up again.
	 */
	rad_assert(ack <= master->sequence);
#endif

	/*
	 *	We're signaling it again...
	 */
	master->num_resignals++;

	/*
	 *	The worker hasn't seen our last few packets.  Signal
	 *	that there is data ready.
	 */
	MPRINT("MASTER SIGNALS AFTER CE %d\n", cs);
	rcode = fr_channel_data_ready(ch, when, master, FR_CHANNEL_SIGNAL_DATA_TO_WORKER);
	if (rcode < 0) return FR_CHANNEL_ERROR;

	return ce;
}


/** Service a control-plane event.
 *
 * The channels use control planes for internal signaling.  Note that
 * the caller does NOT pass the channel into this function.  Instead,
 * the channel is taken from the kevent.
 *
 * @param[in] ch	The channel to service.
 * @param[in] c		The control plane on which we received the kev.
 * @param[in] kev	The kevent data, should get passed to the control plane.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_service_kevent(fr_channel_t *ch, fr_control_t *c, UNUSED struct kevent const *kev)
{
	(void) talloc_get_type_abort(ch, fr_channel_t);

	if (c == ch->end[TO_WORKER].control) {
		ch->end[TO_WORKER].num_kevents++;
	} else {
		ch->end[FROM_WORKER].num_kevents++;
	}

	return 0;
}


/** Check if a channel is active.
 *
 * A channel may be closed by either end.  If so, it stays alive (but
 * inactive) until both ends acknowledge the close.
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

	(void) talloc_get_type_abort(ch, fr_channel_t);

	ch->active = false;

	cc.signal = FR_CHANNEL_SIGNAL_CLOSE;
	cc.ack = TO_WORKER;
	cc.ch = ch;

	return fr_control_message_send(ch->end[TO_WORKER].control, ch->end[TO_WORKER].rb, FR_CONTROL_ID_CHANNEL, &cc, sizeof(cc));
}

/** Acknowledge that the channel is closing
 *
 * @param[in] ch	The channel.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_channel_worker_ack_close(fr_channel_t *ch)
{
	fr_channel_control_t cc;

	(void) talloc_get_type_abort(ch, fr_channel_t);

	ch->active = false;

	cc.signal = FR_CHANNEL_SIGNAL_CLOSE;
	cc.ack = FROM_WORKER;
	cc.ch = ch;

	return fr_control_message_send(ch->end[FROM_WORKER].control, ch->end[FROM_WORKER].rb, FR_CONTROL_ID_CHANNEL, &cc, sizeof(cc));
}

/** Add worker-specific data to a channel
 *
 * @param[in] ch	The channel.
 * @param[in] ctx	The context to add.
 */
void fr_channel_worker_ctx_add(fr_channel_t *ch, void *ctx)
{
	(void) talloc_get_type_abort(ch, fr_channel_t);

	ch->end[FROM_WORKER].ctx = ctx;
}


/** Get worker-specific data from a channel
 *
 * @param[in] ch	The channel.
 */
void *fr_channel_worker_ctx_get(fr_channel_t *ch)
{
	(void) talloc_get_type_abort(ch, fr_channel_t);

	return ch->end[FROM_WORKER].ctx;
}


/** Add network-specific data to a channel
 *
 * @param[in] ch	The channel.
 * @param[in] ctx	The context to add.
 */
void fr_channel_network_ctx_add(fr_channel_t *ch, void *ctx)
{
	(void) talloc_get_type_abort(ch, fr_channel_t);

	ch->end[TO_WORKER].ctx = ctx;
}


/** Get network-specific data from a channel
 *
 * @param[in] ch	The channel.
 */
void *fr_channel_network_ctx_get(fr_channel_t *ch)
{
	(void) talloc_get_type_abort(ch, fr_channel_t);

	return ch->end[TO_WORKER].ctx;
}


int fr_channel_set_recv_reply(fr_channel_t *ch, void *ctx, fr_channel_recv_callback_t recv_reply)
{
	ch->end[TO_WORKER].recv = recv_reply;
	ch->end[TO_WORKER].recv_ctx = ctx;

	return 0;
}

int fr_channel_set_recv_request(fr_channel_t *ch, void *ctx, fr_channel_recv_callback_t recv_request)
{
	ch->end[FROM_WORKER].recv = recv_request;
	ch->end[FROM_WORKER].recv_ctx = ctx;
	return 0;
}

/** Send a channel to a worker
 *
 * @param[in] ch	The channel.
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

	return fr_control_message_send(ch->end[TO_WORKER].control, ch->end[TO_WORKER].rb, FR_CONTROL_ID_CHANNEL, &cc, sizeof(cc));
}

void fr_channel_debug(fr_channel_t *ch, FILE *fp)
{
	fprintf(fp, "to worker\n");
	fprintf(fp, "\tnum_signals sent = %zu\n", ch->end[TO_WORKER].num_signals);
	fprintf(fp, "\tnum_signals re-sent = %zu\n", ch->end[TO_WORKER].num_resignals);
	fprintf(fp, "\tnum_kevents checked = %zu\n", ch->end[TO_WORKER].num_kevents);
	fprintf(fp, "\tsequence = %"PRIu64"\n", ch->end[TO_WORKER].sequence);
	fprintf(fp, "\tack = %"PRIu64"\n", ch->end[TO_WORKER].ack);

	fprintf(fp, "to receive\n");
	fprintf(fp, "\tnum_signals sent = %zu\n", ch->end[FROM_WORKER].num_signals);
	fprintf(fp, "\tnum_kevents checked = %zu\n", ch->end[FROM_WORKER].num_kevents);
	fprintf(fp, "\tsequence = %"PRIu64"\n", ch->end[FROM_WORKER].sequence);
	fprintf(fp, "\tack = %"PRIu64"\n", ch->end[FROM_WORKER].ack);
}
