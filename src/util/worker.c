/*
 * worker.c	Worker thread functiobns.
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

	fr_heap_t		*to_decode;	//!< messages from the master, to be decoded or localized
	fr_heap_t		*localized;	//!< localized messages to be decoded
	fr_heap_t		*decoded;	//!< decoded requests which should (eventually) be runnable

	uint32_t		highest_priority; //!< highest priority runnable request
	fr_heap_t		*runnable;	//!< current runnable requests which we've spent time processing

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

/** Destroy a worker.
 *
 *  The input channels are signaled, and local messages are cleaned up.
 *
 * @param[in] worker the worker to destroy.
 */
static void fr_worker_destroy(fr_worker_t *worker)
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

	/*
	 *	All other requests are talloc'd from the worker
	 *	context, and will be deleted when it is freed.
	 */
	close(worker->kq);
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
	 *
	 *	@todo: send an empty NAK back, saying we couldn't do
	 *	it.
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

	/*
	 *	@todo Send an empty NAK back, saying "we couldn't do
	 *	anything with this request".
	 */
	if (!request) {
		return NULL;
	}

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
	if (request) {
		fr_time_tracking_start(&request->tracking, now);
		return request;
	}

	/*
	 *	Grab a request to decode, and start it.
	 */
	request = fr_worker_decode_request(worker);
	if (request) {
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


/** Create a worker
 *
 * @param[in] ctx the talloc context
 * @return
 *	- NULL on error
 *	- fr_worker_t on success
 */
static fr_worker_t *fr_worker_create(TALLOC_CTX *ctx)
{
	fr_worker_t *worker;

	worker = talloc_zero(ctx, fr_worker_t);

	worker->el = fr_event_list_create(worker, fr_worker_idle, worker);
	if (!worker->el) {
		talloc_free(worker);
		return NULL;
	}

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

	// @todo register our event loop / KQ with the global KQ system

	return worker;
}


/** The main worker function.
 *
 * @param[in] arg Something from the main server...
 * @return
 *	- NULL, there's nothing else to return.
 */
void *fr_worker(UNUSED void *arg)
{
	fr_worker_t *worker;
	TALLOC_CTX *ctx;

	ctx = talloc_init("fr_worker");

	worker = fr_worker_create(ctx);
	if (!worker) {
		talloc_free(ctx);
		return NULL;
	}

	while (true) {
		bool wait_for_event;
		int num_events;
		fr_time_t now;
		REQUEST *request;

		/*
		 *	@todo check / warn on yielded requests which
		 *	have been sitting around for too long.
		 */

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

		request = fr_worker_get_request(worker, now);
		if (!request) continue;

		fr_worker_run_request(worker, request);
	}

	/*
	 *	Talloc ordering issues. We want to be independent of
	 *	how talloc walks it's children, and ensure that some
	 *	things are freed in a specific order.
	 */
	fr_worker_destroy(worker);

	talloc_free(ctx);

	// @todo ??? single threaded mode does... what, exactly?
	// grab packet, and instead of inserting into a channel and signalling, just
	// puts it into the to_decode queue.
	// we probably want a completely separate function for single-threaded mode...

	return NULL;
}
