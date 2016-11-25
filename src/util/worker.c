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
 * @brief Worker thread functions.
 * @file util/worker.c
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/worker.h>
#include <freeradius-devel/rad_assert.h>

/**
 *  A worker which takes packets from a master, and processes them.
 */
struct fr_worker_t {
	int			kq;		//!< my kq

	fr_message_set_t	*ms;		//!< replies are allocated from here.

	fr_event_list_t		*el;		//!< our event list

	int			num_channels;	//!< actual number of channels
	int			max_channels;	//!< maximum number of channels

	size_t			talloc_pool_size; //!< for each REQUEST

	fr_time_t		checked_timeout; //!< when we last checked the tails of the queues

	fr_dlist_t		channel_head;
	fr_dlist_t		channel_tail;

	fr_heap_t		*to_decode;	//!< messages from the master, to be decoded or localized
	fr_heap_t		*localized;	//!< localized messages to be decoded
	fr_heap_t		*decoded;	//!< decoded requests which should (eventually) be runnable
	fr_heap_t		*runnable;	//!< current runnable requests which we've spent time processing

	/*
	 *	@todo maybe put the REQUEST into an fr_dlist_t,
	 *	ordered by time?  So that when we need to clean up an
	 *	old request, we just look at the tail of the list,
	 *	which is simple.  Which means we also need to put a
	 *	"worker state" entry into the REQUEST so that we know
	 *	which heap it's in (or not).  Or, maybe just put the
	 *	heap pointer into the request... which exposes it
	 *	unnecessarily, but is easy.
	 */

	fr_time_tracking_t	tracking;	//!< how much time the worker has spent doing things.

	fr_transport_t		**transports;	//!< array of active transports.

	fr_channel_t		*channel[1];	//!< list of channels
};

/** Handle EVFILT_USER events
 *
 */
static void fr_worker_evfilt_user(int kq, struct kevent const *kev, void *ctx)
{
	fr_channel_event_t what;
	fr_channel_t *ch;
	fr_channel_data_t *cd;
	fr_time_t when = fr_time(); /* @todo pass in from caller */
	fr_worker_t *worker = ctx;

	rad_assert(kev->filter == EVFILT_USER);

	what = fr_channel_service_kevent(kq, kev, when, &ch);

	switch (what) {
		/*
		 *	The channel exchanged signaling
		 *	information.  There's nothing for us
		 *	to do.
		 */
	case FR_CHANNEL_NOOP:
		break;

		/*
		 *	Data is ready on this channel.  Drain
		 *	it to the local to_decode heap.
		 */
	case FR_CHANNEL_DATA_READY:
		while ((cd = fr_channel_recv_request(ch)) != NULL) {
			(void) fr_heap_insert(worker->to_decode, cd);
		}
		break;

		/*
		 *	This is a new channel.  Save it.
		 *
		 *	@todo open a new channel
		 */
	case FR_CHANNEL_OPEN:
		break;

		/*
		 *	The channel is closing.  Stop it.
		 *
		 *	@todo Close the channel
		 */
	case FR_CHANNEL_CLOSE:
		break;

		/*
		 *	Oops.  @todo Close the channel
		 */
	case FR_CHANNEL_ERROR:
		return;
	}
}

/** Decode a request from either the localized queue, or the to_decode queue
 *
 * @param[in] worker the worker
 * @return
 *	- NULL on nothing to decode
 *	- REQUEST the decoded request
 */
static REQUEST *fr_worker_decode_request(fr_worker_t *worker)
{
	fr_channel_data_t *cd;
	TALLOC_CTX *ctx;
	REQUEST *request;

	/*
	 *	Find either a localized message, or one which is in
	 *	the "to_decode" queue.
	 */
	cd = fr_heap_pop(worker->localized);
	if (!cd) cd = fr_heap_pop(worker->to_decode);
	if (!cd) return NULL;

	/*
	 *	Get a talloc pool specifically for this packet.
	 */
	ctx = talloc_pool(worker, worker->talloc_pool_size);
	if (!ctx) {
		fr_message_done(&cd->m);
		return NULL;
	}

	/*
	 *	Receive a message to the worker queue, and decode it
	 *	to a to a request.
	 */
	rad_assert(worker->transports[cd->transport] != NULL);
	request = worker->transports[cd->transport]->recv_request(worker->transports[cd->transport], cd->ctx, ctx, cd->m.data, cd->m.data_size);

	if (!request) return NULL;

	/*
	 *	Update the transport-specific fields.
	 *
	 *	Note that the message "when" time MUST be copied from
	 *	the original recv time.  We use "when" here, instead
	 *	of *cd->request.recv_time, on the odd chance that a
	 *	new packet arrived while we were getting aroudn to
	 *	processing this message.
	 */
	request->channel = cd->channel.ch;
	request->transport = worker->transports[cd->transport];
	request->original_recv_time = cd->request.start_time;
	request->recv_time = cd->m.when;
	request->priority = cd->request.priority;

	/*
	 *	We're done with this message.
	 */
	fr_message_done(&cd->m);

	/*
	 *	Bootstrap the async state machine with the initial
	 *	state of the request.  The process_async function will
	 *	take care of pushing the state machine through it's
	 *	transitions.
	 */
	request->process_async = request->transport->process;

	return request;
}

#define fr_ptr_to_type(TYPE, MEMBER, PTR) (TYPE *) (((char *)PTR) - offsetof(TYPE, MEMBER))


/** Check timeouts on the various queues
 *
 *  This function checks and enforces timeouts on the multiple worker
 *  queues.  The high priority events can starve low priority ones.
 *  When that happens, the low priority events will be in the queues for
 *  "too long", and will need to be cleaned up.
 *
 *  @todo We may have medium-priority events which are waiting for too
 *  long, but we may not find them if there are newer low priority
 *  events.  This issue should be addressed.  There is no real fix,
 *  other than walking the entire heap, or re-implementing it so that
 *  each priority level has it's own heap (or fr_dlist_t), and then we
 *  check those.
 *
 * @param[in] worker the worker
 * @param[in] now the current time
 */
static void fr_worker_check_timeouts(fr_worker_t *worker, fr_time_t now)
{
	fr_time_t waiting;
	fr_channel_data_t *cd;
	fr_dlist_t *entry;
	REQUEST *request;

	/*
	 *	Check the "to_decode" queue for old packets.
	 */
	while ((cd = fr_heap_peek_tail(worker->to_decode)) != NULL) {
		fr_message_t *lm;

		waiting = now - cd->m.when;

		if (waiting < (NANOSEC / 10)) break;

		/*
		 *	Waiting too long, delete it.
		 */
		if (waiting > NANOSEC) {
			(void) fr_heap_extract(worker->to_decode, cd);
		nak:
			fr_message_done(&cd->m);
			continue;
		}

		/*
		 *	0.1 to 1s.  Localize it.
		 */
		(void) fr_heap_extract(worker->to_decode, cd);
		lm = fr_message_localize(worker, &cd->m, sizeof(cd));
		if (!lm) goto nak;

		(void) fr_heap_insert(worker->localized, lm);
	}

	/*
	 *	Check the "localized" queue for old packets.
	 */
	while ((cd = fr_heap_peek_tail(worker->localized)) != NULL) {
		waiting = now - cd->m.when;

		if (waiting < NANOSEC) break;

		/*
		 *	Waiting too long, delete it.
		 */
		(void) fr_heap_extract(worker->localized, cd);
		fr_message_done(&cd->m);
	}

	/*
	 *	Check the "decoded" queue for old packets.
	 */
	while ((request = fr_heap_peek_tail(worker->decoded)) != NULL) {
		waiting = now - request->recv_time;

		if (waiting < NANOSEC) break;

		/*
		 *	Waiting too long, delete it.
		 */
		(void) fr_heap_extract(worker->decoded, request);
		talloc_free(request);
	}

	/*
	 *	Check the "runnable" queue for old packets.
	 */
	while ((request = fr_heap_peek_tail(worker->runnable)) != NULL) {
		waiting = now - request->recv_time;

		if (waiting < NANOSEC) break;

		/*
		 *	Waiting too long, delete it.
		 */
		(void) fr_heap_extract(worker->runnable, request);
		talloc_free(request);
	}

	/*
	 *	Check the resumable queue for old packets.
	 */
	for (entry = FR_DLIST_FIRST(worker->tracking.list);
	     entry != NULL;
	     entry = FR_DLIST_NEXT(worker->tracking.list, entry)) {
		request = fr_ptr_to_type(REQUEST, tracking.list, entry);
#ifndef NDEBUG
		(void) talloc_get_type_abort(request, REQUEST);
#endif

		waiting = now - request->recv_time;

		if (waiting < (30 * (fr_time_t) NANOSEC)) break;

		/*
		 *	Waiting too long, delete it.
		 */
		fr_time_tracking_resume(&request->tracking, now);
		fr_time_tracking_end(&request->tracking, now, &worker->tracking);
		talloc_free(request);
	}
}


/** Get a runnable request
 *
 * @param[in] worker the worker
 * @param[in] now the current time
 * @return
 *	- NULL on nothing to run
 *	- REQUEST the runnable request
 */
static REQUEST *fr_worker_get_request(fr_worker_t *worker, fr_time_t now)
{
	REQUEST *request;

	/*
	 *	Grab a runnable request, and resume it.
	 *
	 *	If it was in the resumeable queue, it gets removed.
	 *	Otherwise, nothing happens.
	 */
	request = fr_heap_pop(worker->runnable);
	if (request) {
		fr_time_tracking_resume(&request->tracking, now);
		return request;
	}

	/*
	 *	Grab a decoded request, and start it.
	 *
	 *	The idle loop should take care of decoding new packets
	 *	into requests.
	 */
	request = fr_heap_pop(worker->decoded);
	if (request) goto start_request;

	/*
	 *	Grab a request to decode, and start it.
	 */
	request = fr_worker_decode_request(worker);
	if (request) {
	start_request:
		request->el = worker->el;
		request->backlog = worker->runnable;
		fr_time_tracking_start(&request->tracking, now);
		return request;
	}

	return NULL;
}


/** Run a request
 *
 *  Until it either yields, or is done.
 *
 *  This function is also responsible for sending replies, and
 *  cleaning up the request.
 *
 * @param[in] worker the worker
 * @param[in] request the request to process
 */
static void fr_worker_run_request(fr_worker_t *worker, REQUEST *request)
{
	fr_channel_data_t *reply, *cd;
	fr_channel_t *ch;
	fr_transport_action_t action;
	fr_transport_final_t final;

	/*
	 *	If we still have the same packet, and the channel is
	 *	active, run it.  Otherwise, tell it that it's done.
	 */
	if ((*request->original_recv_time == request->recv_time) &&
	    (fr_channel_active(request->channel))) {
		action = FR_TRANSPORT_ACTION_RUN;
	} else {
		action = FR_TRANSPORT_ACTION_DONE;
	}

	/*
	 *	Process the request.
	 */
	final = request->process_async(request, action);
	switch (final) {
	case FR_TRANSPORT_DONE:
		talloc_free(request);
		return;

	case FR_TRANSPORT_YIELD:
		fr_time_tracking_yield(&request->tracking, fr_time(), &worker->tracking);
		return;

	case FR_TRANSPORT_REPLY:
		break;
	}

	/*
	 *	The request is done.  Track that.
	 */
	fr_time_tracking_end(&request->tracking, fr_time(), &worker->tracking);

	ch = request->channel;

	// @todo allocater a channel_data_t
	// @todo call send_request

	reply = fr_channel_recv_reply(ch); /* HACK for travis, while we're writing the rest of the code */

	/*
	 *	@todo Use a talloc pool for the request.  Clean it up,
	 *	and insert it back into a slab allocator.
	 */
	talloc_free(request);

	/*
	 *	Send the reply, which also polls the request queue.
	 */
	(void) fr_channel_send_reply(ch, reply, &cd);

	/*
	 *	Drain the incoming TO_WORKER queue.  We do this every
	 *	time we're done processing a request.
	 */
	while (cd) {
		fr_heap_insert(worker->to_decode, cd);
		cd = fr_channel_recv_request(ch);
	};
}

/** Run the event loop 'idle' callback
 *
 * @param[in] ctx the worker
 * @param[in] wake the time when the event loop will wake up.
 */
static int fr_worker_idle(void *ctx, struct timeval *wake)
{
	bool found = false;
	fr_worker_t *worker = ctx;
	REQUEST *request;

	/*
	 *	The application is polling the event loop, but has
	 *	other work to do.  Don't bother decoding any packets.
	 */
	if (wake && ((wake->tv_sec == 0) && (wake->tv_usec == 0))) return 0;

	/*
	 *	The event loop will be sleeping for a time.  We might
	 *	as well get some work in.
	 */
	while ((request = fr_worker_decode_request(worker)) != NULL) {
		found =  true;
		(void) fr_heap_insert(worker->decoded, request);
	}

	/*
	 *	Nothing more to do, and the event loop has us sleeping
	 *	for a period of time.  Signal the producers that we're
	 *	sleeping.  The fr_channel_worker_sleeping() function
	 *	will take care of skipping the signal if there are no
	 *	outstanding requests for it.
	 */
	if (!found) {
		int i;

		for (i = 0; i < worker->num_channels; i++) {
			(void) fr_channel_worker_sleeping(worker->channel[i]);
		}
	}

	/*
	 *	Tell the event loop that there is new work to do.  We
	 *	don't want to wait for events, but instead check them,
	 *	and start processing packets immediately.
	 */
	return 1;
}

static int worker_message_cmp(void const *one, void const *two)
{
	fr_channel_data_t const *a = one;
	fr_channel_data_t const *b = two;

	if (a->request.priority < b->request.priority) return -1;
	if (a->request.priority > b->request.priority) return +1;

	if (a->m.when < b->m.when) return -1;
	if (a->m.when > b->m.when) return +1;

	return 0;
}


static int worker_request_cmp(void const *one, void const *two)
{
	REQUEST const *a = one;
	REQUEST const *b = two;

	if (a->priority < b->priority) return -1;
	if (a->priority > b->priority) return +1;

	if (a->recv_time < b->recv_time) return -1;
	if (a->recv_time > b->recv_time) return +1;

	return 0;
}


/** Destroy a worker.
 *
 *  The input channels are signaled, and local messages are cleaned up.
 *
 * @param[in] worker the worker to destroy.
 */
void fr_worker_destroy(fr_worker_t *worker)
{
	int i;
	fr_channel_data_t *cd;

	/*
	 *	These messages aren't in the channel, so we have to
	 *	mark them as unused.
	 */
	while ((cd = fr_heap_pop(worker->to_decode)) != NULL) {
		fr_message_done(&cd->m);
	}

	while ((cd = fr_heap_pop(worker->localized)) != NULL) {
		fr_message_done(&cd->m);
	}

	/*
	 *	Signal the channels that we're closing.
	 *
	 *	The other end owns the channel, and will take care of
	 *	popping messages in the TO_WORKER queue, and marking
	 *	them FR_MESSAGE_DONE.  It will ignore the messages in
	 *	the FROM_WORKER queue, as we own those.  They will be
	 *	automatically freed when our talloc context is freed.
	 */
	for (i = 0; i < worker->num_channels; i++) {
		fr_channel_signal_close(worker->channel[i]);
	}
}


/** Create a worker
 *
 * @param[in] ctx the talloc context
 * @return
 *	- NULL on error
 *	- fr_worker_t on success
 */
fr_worker_t *fr_worker_create(TALLOC_CTX *ctx)
{
	fr_worker_t *worker;

	worker = talloc_zero(ctx, fr_worker_t);

	worker->el = fr_event_list_create(worker, fr_worker_idle, worker);
	if (!worker->el) {
		talloc_free(worker);
		return NULL;
	}

	worker->kq = fr_event_list_kq(worker->el);
	rad_assert(worker->kq >= 0);

	if (fr_event_user_insert(worker->el, fr_worker_evfilt_user, worker) < 0) {
		talloc_free(worker);
		return NULL;
	}

	worker->to_decode = fr_heap_create(worker_message_cmp, offsetof(fr_channel_data_t, channel.heap_id));
	if (!worker->to_decode) {
		talloc_free(worker);
		return NULL;
	}

	worker->localized = fr_heap_create(worker_message_cmp, offsetof(fr_channel_data_t, channel.heap_id));
	if (!worker->localized) {
		talloc_free(worker);
		return NULL;
	}

	worker->decoded = fr_heap_create(worker_request_cmp, offsetof(REQUEST, heap_id));
	if (!worker->decoded) {
		talloc_free(worker);
		return NULL;
	}

	worker->runnable = fr_heap_create(worker_request_cmp, offsetof(REQUEST, heap_id));
	if (!worker->decoded) {
		talloc_free(worker);
		return NULL;
	}

	return worker;
}

/** Get the KQ for the worker
 *
 * @param[in] worker the worker data structure
 */
int fr_worker_kq(fr_worker_t *worker)
{
	return worker->kq;
}

/** The main worker function.
 *
 * @param[in] worker the worker data structure to manage
 */
void fr_worker(fr_worker_t *worker)
{
	while (true) {
		bool wait_for_event;
		int num_events;
		fr_time_t now;
		REQUEST *request;

		/*
		 *	There are runnable requests.  We still service
		 *	the event loop, but we don't wait for events.
		 */
		wait_for_event = (fr_heap_num_elements(worker->runnable) == 0);

		/*
		 *	Check the event list.  If there's an error
		 *	(e.g. exit), we stop looping and clean up.
		 */
		num_events = fr_event_corral(worker->el, wait_for_event);
		if (num_events < 0) break;

		/*
		 *	Service outstanding events.
		 */
		if (num_events > 0) fr_event_service(worker->el);

		now = fr_time();

		/*
		 *	Ten times a second, check for timeouts on incoming packets.
		 */
		if ((now - worker->checked_timeout) > (NANOSEC / 10)) fr_worker_check_timeouts(worker, now);

		request = fr_worker_get_request(worker, now);
		if (!request) continue;

		fr_worker_run_request(worker, request);
	}
}
