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
 * @file io/worker.c
 *
 *  The "worker" thread is the one responsible for the bulk of the
 *  work done when processing a request.  Workers are spawned by the
 *  scheduler, and create a kqueue (KQ) and control-plane
 *  Atomic Queue (AQ) for control-plane communication.
 *
 *  When a network thread discovers that it needs more workers, it
 *  asks the scheduler for a KQ/AQ combination.  The network thread
 *  then creates a channel dedicated to that worker, and sends the
 *  channel to the worker in a "new channel" message.  The worker
 *  receives the channel, and sends an ACK back to the network thread.
 *
 *  The network thread then sends the worker new packets, which the
 *  worker receives and processes.
 *
 *  When a packet is decoded, it is put into the "runnable" heap, and
 *  also into the timeout sublist. The main loop fr_worker() then
 *  pulls new requests off of this heap and runs them.  The main event
 *  loop checks the head of the timeout sublist, and forcefully terminates
 *  any requests which have been running for too long.
 *
 *  If a request is yielded, it is placed onto the yielded list in
 *  the worker "tracking" data structure.
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#define LOG_PREFIX worker->name
#define LOG_DST worker->log

#include <freeradius-devel/io/channel.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/message.h>
#include <freeradius-devel/io/worker.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/unlang/call.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/time_tracking.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/minmax_heap.h>
#include <freeradius-devel/util/slab.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/timer.h>

#include <stdalign.h>

#ifdef WITH_VERIFY_PTR
static void worker_verify(fr_worker_t *worker);
#define WORKER_VERIFY worker_verify(worker)
#else
#define WORKER_VERIFY
#endif

#define CACHE_LINE_SIZE	64
static _Atomic(uint64_t) request_number = 0;

FR_SLAB_TYPES(request, request_t)
FR_SLAB_FUNCS(request, request_t)

static _Thread_local fr_ring_buffer_t *fr_worker_rb;

typedef struct {
	fr_channel_t		*ch;

	/*
	 *	To save time, we don't care about num_elements here.  Which means that we don't
	 *	need to cache or lookup the fr_worker_listen_t when we free a request.
	 */
	fr_dlist_head_t		dlist;
} fr_worker_channel_t;

/**
 *  A worker which takes packets from a master, and processes them.
 */
struct fr_worker_s {
	char const		*name;		//!< name of this worker
	fr_worker_config_t	config;		//!< external configuration

	unlang_interpret_t 	*intp;		//!< Worker's local interpreter.

	pthread_t		thread_id;	//!< my thread ID

	fr_log_t const		*log;		//!< log destination
	fr_log_lvl_t		lvl;		//!< log level

	fr_atomic_queue_t	*aq_control;	//!< atomic queue for control messages sent to me

	fr_control_t		*control;	//!< the control plane

	fr_event_list_t		*el;		//!< our event list

	int			num_channels;	//!< actual number of channels

	fr_heap_t      		*runnable;	//!< current runnable requests which we've spent time processing

	fr_timer_list_t		*timeout;		//!< Track when requests timeout using a dlist.
	fr_timer_list_t		*timeout_custom;	//!< Track when requests timeout using an lst.
							///< requests must always be in one of these lists.
	fr_time_delta_t		max_request_time;	//!< maximum time a request can be processed

	fr_rb_tree_t		*dedup;		//!< de-dup tree

	fr_rb_tree_t		*listeners;    	//!< so we can cancel requests when a listener goes away

	fr_io_stats_t		stats;		//!< input / output stats
	fr_time_elapsed_t	cpu_time;	//!< histogram of total CPU time per request
	fr_time_elapsed_t	wall_clock;	//!< histogram of wall clock time per request

	uint64_t    		num_naks;	//!< number of messages which were nak'd
	uint64_t    		num_active;	//!< number of active requests

	fr_time_delta_t		predicted;	//!< How long we predict a request will take to execute.
	fr_time_tracking_t	tracking;	//!< how much time the worker has spent doing things.

	bool			was_sleeping;	//!< used to suppress multiple sleep signals in a row
	bool			exiting;	//!< are we exiting?

	fr_worker_channel_t	*channel;	//!< list of channels

	request_slab_list_t	*slab;		//!< slab allocator for request_t
};

typedef struct {
	fr_listen_t const	*listener;	//!< incoming packets

	fr_rb_node_t		node;		//!< in tree of listeners

	/*
	 *	To save time, we don't care about num_elements here.  Which means that we don't
	 *	need to cache or lookup the fr_worker_listen_t when we free a request.
	 */
	fr_dlist_head_t		dlist;		//!< of requests associated with this listener.
} fr_worker_listen_t;


static int8_t worker_listener_cmp(void const *one, void const *two)
{
	fr_worker_listen_t const *a = one, *b = two;

	return CMP(a->listener, b->listener);
}


/*
 *	Explicitly cleanup the memory allocated to the ring buffer,
 *	just in case valgrind complains about it.
 */
static int _fr_worker_rb_free(void *arg)
{
	return talloc_free(arg);
}

/** Initialise thread local storage
 *
 * @return fr_ring_buffer_t for messages
 */
static inline fr_ring_buffer_t *fr_worker_rb_init(void)
{
	fr_ring_buffer_t *rb;

	rb = fr_worker_rb;
	if (rb) return rb;

	rb = fr_ring_buffer_create(NULL, FR_CONTROL_MAX_MESSAGES * FR_CONTROL_MAX_SIZE);
	if (!rb) {
		fr_perror("Failed allocating memory for worker ring buffer");
		return NULL;
	}

	fr_atexit_thread_local(fr_worker_rb, _fr_worker_rb_free, rb);

	return rb;
}

static inline bool is_worker_thread(fr_worker_t const *worker)
{
	return (pthread_equal(pthread_self(), worker->thread_id) != 0);
}

static void worker_request_bootstrap(fr_worker_t *worker, fr_channel_data_t *cd, fr_time_t now);
static void worker_send_reply(fr_worker_t *worker, request_t *request, bool do_not_respond, fr_time_t now);

/** Callback which handles a message being received on the worker side.
 *
 * @param[in] ctx the worker
 * @param[in] ch the channel to drain
 * @param[in] cd the message (if any) to start with
 */
static void worker_recv_request(void *ctx, fr_channel_t *ch, fr_channel_data_t *cd)
{
	fr_worker_t *worker = ctx;

	worker->stats.in++;
	DEBUG3("Received request %" PRIu64 "", worker->stats.in);
	cd->channel.ch = ch;
	worker_request_bootstrap(worker, cd, fr_time());
}

static void worker_requests_cancel(fr_worker_channel_t *ch)
{
	request_t *request;

	while ((request = fr_dlist_pop_head(&ch->dlist)) != NULL) {
		unlang_interpret_signal(request, FR_SIGNAL_CANCEL);
	}
}

static void worker_exit(fr_worker_t *worker)
{
	worker->exiting = true;

	/*
	 *	Don't allow the post event to run
	 *	any more requests.  They'll be
	 *	signalled to stop before we exit.
	 *
	 *	This only has an effect in single
	 *	threaded mode.
	 */
	(void)fr_event_post_delete(worker->el, fr_worker_post_event, worker);
}

/** Handle a control plane message sent to the worker via a channel
 *
 * @param[in] ctx	the worker
 * @param[in] data	the message
 * @param[in] data_size	size of the data
 * @param[in] now	the current time
 */
static void worker_channel_callback(void *ctx, void const *data, size_t data_size, fr_time_t now)
{
	int			i;
	bool			ok, was_sleeping;
	fr_channel_t		*ch;
	fr_message_set_t	*ms;
	fr_channel_event_t	ce;
	fr_worker_t		*worker = ctx;

	was_sleeping = worker->was_sleeping;
	worker->was_sleeping = false;

	/*
	 *	We were woken up by a signal to do something.  We're
	 *	not sleeping.
	 */
	ce = fr_channel_service_message(now, &ch, data, data_size);
	DEBUG3("Channel %s",
	       fr_table_str_by_value(channel_signals, ce, "<INVALID>"));
	switch (ce) {
	case FR_CHANNEL_ERROR:
		return;

	case FR_CHANNEL_EMPTY:
		return;

	case FR_CHANNEL_NOOP:
		return;

	case FR_CHANNEL_DATA_READY_REQUESTOR:
		fr_assert(0 == 1);
		break;

	case FR_CHANNEL_DATA_READY_RESPONDER:
		fr_assert(ch != NULL);

		if (!fr_channel_recv_request(ch)) {
			worker->was_sleeping = was_sleeping;

		} else while (fr_channel_recv_request(ch));
		break;

	case FR_CHANNEL_OPEN:
		fr_assert(ch != NULL);

		ok = false;
		for (i = 0; i < worker->config.max_channels; i++) {
			fr_assert(worker->channel[i].ch != ch);

			if (worker->channel[i].ch != NULL) continue;

			worker->channel[i].ch = ch;
			fr_dlist_init(&worker->channel[i].dlist, fr_async_t, entry);

			DEBUG3("Received channel %p into array entry %d", ch, i);

			ms = fr_message_set_create(worker, worker->config.message_set_size,
						   sizeof(fr_channel_data_t),
						   worker->config.ring_buffer_size, false);
			fr_assert(ms != NULL);
			fr_channel_responder_uctx_add(ch, ms);

			worker->num_channels++;
			ok = true;
			break;
		}

		fr_cond_assert(ok);
		break;

	case FR_CHANNEL_CLOSE:
		fr_assert(ch != NULL);

		ok = false;

		/*
		 *	Locate the signalling channel in the list
		 *	of channels.
		 */
		for (i = 0; i < worker->config.max_channels; i++) {
			if (!worker->channel[i].ch) continue;

			if (worker->channel[i].ch != ch) continue;

			worker_requests_cancel(&worker->channel[i]);

			ms = fr_channel_responder_uctx_get(ch);

			fr_assert_msg(fr_dlist_num_elements(&worker->channel[i].dlist) == 0,
				      "Network added messages to channel after sending FR_CHANNEL_CLOSE");

			fr_channel_responder_ack_close(ch);
			fr_assert(ms != NULL);
			fr_message_set_gc(ms);
			talloc_free(ms);

			worker->channel[i].ch = NULL;

			fr_assert(!fr_dlist_head(&worker->channel[i].dlist)); /* we can't look at num_elements */
			fr_assert(worker->num_channels > 0);

			worker->num_channels--;
			ok = true;
			break;
		}

		fr_cond_assert(ok);

		/*
		 *	Our last input channel closed,
		 *	time to die.
		 */
		if (worker->num_channels == 0) worker_exit(worker);
		break;
	}
}

static int fr_worker_listen_cancel_self(fr_worker_t *worker, fr_listen_t const *li)
{
	fr_worker_listen_t *wl;
	request_t *request;

	wl = fr_rb_find(worker->listeners, &(fr_worker_listen_t) { .listener = li });
	if (!wl) return -1;

	while ((request = fr_dlist_pop_head(&wl->dlist)) != NULL) {
		RDEBUG("Canceling request due to socket being closed");
		unlang_interpret_signal(request, FR_SIGNAL_CANCEL);
	}

	(void) fr_rb_delete(worker->listeners, wl);
	talloc_free(wl);

	return 0;
}


/** A socket is going away, so clean up any requests which use this socket.
 *
 * @param[in] ctx	the worker
 * @param[in] data	the message
 * @param[in] data_size	size of the data
 * @param[in] now	the current time
 */
static void worker_listen_cancel_callback(void *ctx, void const *data, NDEBUG_UNUSED size_t data_size, UNUSED fr_time_t now)
{
	fr_listen_t const	*li;
	fr_worker_t		*worker = ctx;

	fr_assert(data_size == sizeof(li));

	memcpy(&li, data, sizeof(li));

	(void) fr_worker_listen_cancel_self(worker, li);
}

/** Send a NAK to the network thread
 *
 * The network thread believes that a worker is running a request until that request has been NAK'd.
 * We typically NAK requests when they've been hanging around in the worker's backlog too long,
 * or there was an error executing the request.
 *
 * @param[in] worker	the worker
 * @param[in] cd	the message to NAK
 * @param[in] now	when the message is NAKd
 */
static void worker_nak(fr_worker_t *worker, fr_channel_data_t *cd, fr_time_t now)
{
	size_t			size;
	fr_channel_data_t	*reply;
	fr_channel_t		*ch;
	fr_message_set_t	*ms;
	fr_listen_t		*listen;

	worker->num_naks++;

	/*
	 *	Cache the outbound channel.  We'll need it later.
	 */
	ch = cd->channel.ch;
	listen = cd->listen;

	/*
	 *	If the channel has been closed, but we haven't
	 *	been informed, that is extremely bad.
	 *
	 *	Try to continue working... but we'll likely
	 *	leak memory or SEGV soon.
	 */
	if (!fr_cond_assert_msg(fr_channel_active(ch), "Wanted to send NAK but channel has been closed")) {
		fr_message_done(&cd->m);
		return;
	}

	ms = fr_channel_responder_uctx_get(ch);
	fr_assert(ms != NULL);

	size = listen->app_io->default_reply_size;
	if (!size) size = listen->app_io->default_message_size;

	/*
	 *	Allocate a default message size.
	 */
	reply = (fr_channel_data_t *) fr_message_reserve(ms, size);
	fr_assert(reply != NULL);

	/*
	 *	Encode a NAK
	 */
	if (listen->app_io->nak) {
		size = listen->app_io->nak(listen, cd->packet_ctx, cd->m.data,
					   cd->m.data_size, reply->m.data, reply->m.rb_size);
	} else {
		size = 1;	/* rely on them to figure it the heck out */
	}

	(void) fr_message_alloc(ms, &reply->m, size);

	/*
	 *	Fill in the NAK.
	 */
	reply->m.when = now;
	reply->reply.cpu_time = worker->tracking.running_total;
	reply->reply.processing_time = fr_time_delta_from_sec(10); /* @todo - set to something better? */
	reply->reply.request_time = cd->request.recv_time;

	reply->listen = cd->listen;
	reply->packet_ctx = cd->packet_ctx;

	/*
	 *	Mark the original message as done.
	 */
	fr_message_done(&cd->m);

	/*
	 *	Send the reply, which also polls the request queue.
	 */
	if (fr_channel_send_reply(ch, reply) < 0) {
		DEBUG2("Failed sending reply to channel");
	}

	worker->stats.out++;
}

/** Signal the unlang interpreter that it needs to stop running the request
 *
 * Signalling is a synchronous operation.  Whatever I/O requests the request
 * is currently performing are immediately cancelled, and all the frames are
 * popped off the unlang stack.
 *
 * Modules and unlang keywords explicitly register signal handlers to deal
 * with their yield points being cancelled/interrupted via this function.
 *
 * The caller should assume the request is no longer viable after calling
 * this function.
 *
 * @param[in] request	request to cancel.  The request may still run to completion.
 */
static void worker_stop_request(request_t *request)
{
	/*
	 *	Also marks the request as done and runs
	 *	the internal/external callbacs.
	 */
	unlang_interpret_signal(request, FR_SIGNAL_CANCEL);
}

/** Enforce max_request_time
 *
 * Run periodically, and tries to clean up requests which were received by the network
 * thread more than max_request_time seconds ago.  In the interest of not adding a
 * timer for every packet, the requests are given a 1 second leeway.
 *
 * @param[in] tl	the worker's timer list.
 * @param[in] when	the current time
 * @param[in] uctx	the request_t timing out.
 */
static void _worker_request_timeout(UNUSED fr_timer_list_t *tl, UNUSED fr_time_t when, void *uctx)
{
	request_t	*request = talloc_get_type_abort(uctx, request_t);

	/*
	 *	Waiting too long, delete it.
	 */
	REDEBUG("Request has reached max_request_time - signalling it to stop");
	worker_stop_request(request);

	/*
	 *	This ensures the finally section can run timeout specific policies
	 */
	request->rcode = RLM_MODULE_TIMEOUT;
}

/** Set, or re-set the request timer
 *
 * Automatically moves requests between the timer lists (timeout, custom_timeout).
 *
 * Can be used to set the initial timeout, or extend the timeout of a request.
 *
 * @param[in] worker	the worker containing the timeout lists.
 * @param[in] request	that we're timing out.
 * @param[in] timeout	the timeout to set.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_worker_request_timeout_set(fr_worker_t *worker, request_t *request, fr_time_delta_t timeout)
{
	fr_timer_list_t *tl = fr_time_delta_eq(worker->config.max_request_time, timeout) ? worker->timeout : worker->timeout_custom;

	/* No need to disarm fr_timer_in does it for us */

	if (unlikely(fr_timer_in(request, tl, &request->timeout, timeout,
				 true, _worker_request_timeout, request) < 0)) {
		RERROR("Failed to create request timeout timer");
		return -1;
	}

	return 0;
}

/** Start time tracking for a request, and mark it as runnable.
 *
 */
static int worker_request_time_tracking_start(fr_worker_t *worker, request_t *request, fr_time_t now)
{
	/*
	 *	New requests are inserted into the time order heap in
	 *	strict time priority.  Once they are in the list, they
	 *	are only removed when the request is done / free'd.
	 */
	fr_assert(!fr_timer_armed(request->timeout));

	if (unlikely(fr_worker_request_timeout_set(worker, request, worker->config.max_request_time) < 0)) {
		RERROR("Failed to set request timeout");
		return -1;
	}

	/*
	 *	Bootstrap the async state machine with the initial
	 *	state of the request.
	 */
	RDEBUG3("Time tracking started in yielded state");
	fr_time_tracking_start(&worker->tracking, &request->async->tracking, now);
	fr_time_tracking_yield(&request->async->tracking, now);
	worker->num_active++;

	fr_assert(!fr_heap_entry_inserted(request->runnable));
	(void) fr_heap_insert(&worker->runnable, request);

	return 0;
}

static void worker_request_time_tracking_end(fr_worker_t *worker, request_t *request, fr_time_t now)
{
	RDEBUG3("Time tracking ended");
	fr_time_tracking_end(&worker->predicted, &request->async->tracking, now);
	fr_assert(worker->num_active > 0);
	worker->num_active--;

	TALLOC_FREE(request->timeout);	/* Disarm the reques timer */
}

/** Send a response packet to the network side
 *
 * @param[in] worker		This worker.
 * @param[in] request		we're sending a reply for.
 * @param[in] send_reply	whether the network side sends a reply
 * @param[in] now		The current time
 */
static void worker_send_reply(fr_worker_t *worker, request_t *request, bool send_reply, fr_time_t now)
{
	fr_channel_data_t *reply;
	fr_channel_t *ch;
	fr_message_set_t *ms;
	size_t size = 1;

	REQUEST_VERIFY(request);

	/*
	 *	If we're sending a reply, then it's no longer runnable.
	 */
	fr_assert(!fr_heap_entry_inserted(request->runnable));

	if (send_reply) {
		size = request->async->listen->app_io->default_reply_size;
		if (!size) size = request->async->listen->app_io->default_message_size;
	}

	/*
	 *	Allocate and send the reply.
	 */
	ch = request->async->channel;
	fr_assert(ch != NULL);

	/*
	 *	If the channel has been closed, but we haven't
	 *	been informed, that is extremely bad.
	 *
	 *	Try to continue working... but we'll likely
	 *	leak memory or SEGV soon.
	 */
	if (!fr_cond_assert_msg(fr_channel_active(ch), "Wanted to send reply but channel has been closed")) {
		return;
	}

	ms = fr_channel_responder_uctx_get(ch);
	fr_assert(ms != NULL);

	reply = (fr_channel_data_t *) fr_message_reserve(ms, size);
	fr_assert(reply != NULL);

	/*
	 *	Encode it, if required.
	 */
	if (send_reply) {
		ssize_t slen = 0;
		fr_listen_t const *listen = request->async->listen;

		if (listen->app_io->encode) {
			slen = listen->app_io->encode(listen->app_io_instance, request,
						      reply->m.data, reply->m.rb_size);
		} else if (listen->app->encode) {
			slen = listen->app->encode(listen->app_instance, request,
						   reply->m.data, reply->m.rb_size);
		}
		if (slen < 0) {
			RPERROR("Failed encoding request");
			*reply->m.data = 0;
			slen = 1;
		}

		/*
		 *	Shrink the buffer to the actual packet size.
		 *
		 *	This will ALWAYS return the same message as we put in.
		 */
		fr_assert((size_t) slen <= reply->m.rb_size);
		(void) fr_message_alloc(ms, &reply->m, slen);
	}

	/*
	 *	Fill in the rest of the fields in the channel message.
	 *
	 *	sequence / ack will be filled in by fr_channel_send_reply()
	 */
	reply->m.when = now;
	reply->reply.cpu_time = worker->tracking.running_total;
	reply->reply.processing_time = request->async->tracking.running_total;
	reply->reply.request_time = request->async->recv_time;

	reply->listen = request->async->listen;
	reply->packet_ctx = request->async->packet_ctx;

	/*
	 *	Update the various timers.
	 */
	fr_time_elapsed_update(&worker->cpu_time, now, fr_time_add(now, reply->reply.processing_time));
	fr_time_elapsed_update(&worker->wall_clock, reply->reply.request_time, now);

	RDEBUG("Finished request");

	/*
	 *	Send the reply, which also polls the request queue.
	 */
	if (fr_channel_send_reply(ch, reply) < 0) {
		/*
		 *	Should only happen if the TO_REQUESTOR
		 *	channel is full, or it's not yet active.
		 *
		 *	Not much we can do except complain
		 *	loudly and cleanup the request.
		 */
		RPERROR("Failed sending reply to network thread");
	}

	worker->stats.out++;

	fr_assert(!fr_timer_armed(request->timeout));
	fr_assert(!fr_heap_entry_inserted(request->runnable));

	fr_dlist_entry_unlink(&request->listen_entry);

#ifndef NDEBUG
	request->async->el = NULL;
	request->async->channel = NULL;
	request->async->packet_ctx = NULL;
	request->async->listen = NULL;
#endif
}

/*
 *	talloc_typed_asprintf() is horrifically slow for printing
 *	simple numbers.
 */
static char *itoa_internal(TALLOC_CTX *ctx, uint64_t number)
{
	char buffer[32];
	char *p;
	char const *numbers = "0123456789";

	p = buffer + 30;
	*(p--) = '\0';

	while (number > 0) {
		*(p--) = numbers[number % 10];
		number /= 10;
	}

	if (p[1]) return talloc_strdup(ctx, p + 1);

	return talloc_strdup(ctx, "0");
}

/** Initialize various request fields needed by the worker.
 *
 */
static inline CC_HINT(always_inline)
void worker_request_init(fr_worker_t *worker, request_t *request, fr_time_t now)
{
	/*
	 *	For internal requests request->packet
	 *	and request->reply are already populated.
	 */
	if (!request->packet) MEM(request->packet = fr_packet_alloc(request, false));
	if (!request->reply) MEM(request->reply = fr_packet_alloc(request, false));

	request->packet->timestamp = now;
	request->async = talloc_zero(request, fr_async_t);
	request->async->recv_time = now;
	request->async->el = worker->el;
	fr_dlist_entry_init(&request->async->entry);
}

static inline CC_HINT(always_inline)
void worker_request_name_number(request_t *request)
{
	request->number = atomic_fetch_add_explicit(&request_number, 1, memory_order_seq_cst);
	if (request->name) talloc_const_free(request->name);
	request->name = itoa_internal(request, request->number);
}

static inline CC_HINT(always_inline)
uint32_t worker_num_requests(fr_worker_t *worker)
{
	return fr_timer_list_num_events(worker->timeout) + fr_timer_list_num_events(worker->timeout_custom);
}

static int _worker_request_deinit(request_t *request, UNUSED void *uctx)
{
	return request_slab_deinit(request);
}

static void worker_request_bootstrap(fr_worker_t *worker, fr_channel_data_t *cd, fr_time_t now)
{
	int			ret = -1;
	request_t		*request;
	TALLOC_CTX		*ctx;
	fr_listen_t		*listen = cd->listen;

	if (worker_num_requests(worker) >= (uint32_t) worker->config.max_requests) {
		RATE_LIMIT_GLOBAL(ERROR, "Worker at max requests");
		goto nak;
	}

	/*
	 *	Receive a message to the worker queue, and decode it
	 *	to a request.
	 */
	fr_assert(listen != NULL);

	ctx = request = request_slab_reserve(worker->slab);
	if (!request) {
		RATE_LIMIT_GLOBAL(ERROR, "Worker failed allocating new request");
		goto nak;
	}
	/*
	 *	Ensures that both the deinit function runs AND
	 *	the request is returned to the slab if something
	 *	calls talloc_free() on it.
	 */
	request_slab_element_set_destructor(request, _worker_request_deinit, worker);

	/*
	 *	Have to initialise the request manually because namspace
	 *	changes based on the listener that allocated it.
	 */
	if (request_init(request, REQUEST_TYPE_EXTERNAL, (&(request_init_args_t){ .namespace = listen->dict })) < 0) {
		request_slab_release(request);
		goto nak;
	}

	/*
	 *	Do normal worker init that's shared between internal
	 *	and external requests.
	 */
	worker_request_init(worker, request, now);
	worker_request_name_number(request);

	/*
	 *	Associate our interpreter with the request
	 */
	unlang_interpret_set(request, worker->intp);

	request->packet->timestamp = cd->request.recv_time; /* Legacy - Remove once everything looks at request->async */

	/*
	 *	Update the transport-specific fields.
	 */
	request->async->channel = cd->channel.ch;

	request->async->recv_time = cd->request.recv_time;

	request->async->listen = listen;
	request->async->packet_ctx = cd->packet_ctx;
	request->priority = cd->priority;

	/*
	 *	Now that the "request" structure has been initialized, go decode the packet.
	 *
	 *	Note that this also sets the "async process" function.
	 */
	if (listen->app->decode) {
		ret = listen->app->decode(listen->app_instance, request, cd->m.data, cd->m.data_size);
	} else if (listen->app_io->decode) {
		ret = listen->app_io->decode(listen->app_io_instance, request, cd->m.data, cd->m.data_size);
	}

	if (ret < 0) {
		talloc_free(ctx);
nak:
		worker_nak(worker, cd, now);
		return;
	}

	/*
	 *	Set the entry point for this virtual server.
	 */
	if (unlang_call_push(NULL, request, cd->listen->server_cs, UNLANG_TOP_FRAME) < 0) {
		RERROR("Protocol failed to set 'process' function");
		worker_nak(worker, cd, now);
		return;
	}

	/*
	 *	We're done with this message.
	 */
	fr_message_done(&cd->m);

	/*
	 *	Look for conflicting / duplicate packets, but only if
	 *	requested to do so.
	 */
	if (request->async->listen->track_duplicates) {
		request_t *old;

		old = fr_rb_find(worker->dedup, request);
		if (!old) {
			goto insert_new;
		}

		fr_assert(old->async->listen == request->async->listen);
		fr_assert(old->async->channel == request->async->channel);

		/*
		 *	There's a new packet.  Do we keep the old one,
		 *	or the new one?  This decision is made by
		 *	checking the recv_time, which is a
		 *	nanosecond-resolution timer.  If the time is
		 *	identical, then the new packet is the same as
		 *	the old one.
		 *
		 *	If the new packet is a duplicate of the old
		 *	one, then we can just discard the new one.  We
		 *	have to tell the channel that we've "eaten"
		 *	this reply, so the sequence number should
		 *	increase.
		 *
		 *	@todo - fix the channel code to do queue
		 *	depth, and not sequence / ack.
		 */
		if (fr_time_eq(old->async->recv_time, request->async->recv_time)) {
			RWARN("Discarding duplicate of request (%"PRIu64")", old->number);

			fr_channel_null_reply(request->async->channel);
			request_slab_release(request);

			/*
			 *	Signal there's a dup, and ignore the
			 *	return code.  We don't bother replying
			 *	here, as an FD event or timer will
			 *	wake up the request, and cause it to
			 *	continue.
			 *
			 *	@todo - the old request is NOT
			 *	running, but is yielded.  It MAY clean
			 *	itself up, or do something...
			 */
			unlang_interpret_signal(old, FR_SIGNAL_DUP);
			worker->stats.dup++;
			return;
		}

		/*
		 *	Stop the old request, and decrement the number
		 *	of active requests.
		 */
		RWARN("Got conflicting packet for request (%" PRIu64 "), telling old request to stop", old->number);

		worker_stop_request(old);
		worker->stats.dropped++;

	insert_new:
		(void) fr_rb_insert(worker->dedup, request);
	}

	worker_request_time_tracking_start(worker, request, now);

	{
		fr_worker_listen_t *wl;

		wl = fr_rb_find(worker->listeners, &(fr_worker_listen_t) { .listener = listen });
		if (!wl) {
			MEM(wl = talloc_zero(worker, fr_worker_listen_t));
			fr_dlist_init(&wl->dlist, request_t, listen_entry);
			wl->listener = listen;

			(void) fr_rb_insert(worker->listeners, wl);
		}

		fr_dlist_insert_tail(&wl->dlist, request);
	}
}

/**
 *  Track a request_t in the "runnable" heap.
 *  Higher priorities take precedence, followed by lower sequence numbers
 */
static int8_t worker_runnable_cmp(void const *one, void const *two)
{
	request_t const *a = one, *b = two;
	int ret;

	ret = CMP(b->priority, a->priority);
	if (ret != 0) return ret;

	ret = CMP(a->sequence, b->sequence);
	if (ret != 0) return ret;

	return fr_time_cmp(a->async->recv_time, b->async->recv_time);
}

/**
 *  Track a request_t in the "dedup" tree
 */
static int8_t worker_dedup_cmp(void const *one, void const *two)
{
	int ret;
	request_t const *a = one, *b = two;

	ret = CMP(a->async->listen, b->async->listen);
	if (ret) return ret;

	return CMP(a->async->packet_ctx, b->async->packet_ctx);
}

/** Destroy a worker
 *
 * The input channels are signaled, and local messages are cleaned up.
 *
 * This should be called to _EXPLICITLY_ destroy a worker, when some fatal
 * error has occurred on the worker side, and we need to destroy it.
 *
 * We signal all pending requests in the backlog to stop, and tell the
 * network side that it should not send us any more requests.
 *
 * @param[in] worker the worker to destroy.
 */
void fr_worker_destroy(fr_worker_t *worker)
{
	int i, count, ret;

//	WORKER_VERIFY;

	/*
	 *	Stop any new requests running with this interpreter
	 */
	unlang_interpret_set_thread_default(NULL);

	/*
	 *	Destroy all of the active requests.  These are ones
	 *	which are still waiting for timers or file descriptor
	 *	events.
	 */
	count = 0;

	/*
	 *	Force the timeout event to fire for all requests that
	 *	are still running.
	 */
	ret = fr_timer_list_force_run(worker->timeout);
	if (unlikely(ret < 0)) {
		fr_assert_msg(0, "Failed to force run the timeout list");
	} else {
		count += ret;
	}

	ret = fr_timer_list_force_run(worker->timeout_custom);
	if (unlikely(ret < 0)) {
		fr_assert_msg(0, "Failed to force run the custom timeout list");
	} else {
		count += ret;
	}
	fr_assert(fr_heap_num_elements(worker->runnable) == 0);

	DEBUG("Worker is exiting - stopped %u requests", count);

	/*
	 *	Signal the channels that we're closing.
	 *
	 *	The other end owns the channel, and will take care of
	 *	popping messages in the TO_RESPONDER queue, and marking
	 *	them FR_MESSAGE_DONE.  It will ignore the messages in
	 *	the TO_REQUESTOR queue, as we own those.  They will be
	 *	automatically freed when our talloc context is freed.
	 */
	for (i = 0; i < worker->config.max_channels; i++) {
		if (!worker->channel[i].ch) continue;

		worker_requests_cancel(&worker->channel[i]);

		fr_assert_msg(fr_dlist_num_elements(&worker->channel[i].dlist) == 0,
			      "Pending messages in channel after cancelling request");

		fr_channel_responder_ack_close(worker->channel[i].ch);
	}

	talloc_free(worker);
}

/** Internal request (i.e. one generated by the interpreter) is now complete
 *
 */
static void _worker_request_internal_init(request_t *request, void *uctx)
{
	fr_worker_t	*worker = talloc_get_type_abort(uctx, fr_worker_t);
	fr_time_t	now = fr_time();

	worker_request_init(worker, request, now);

	/*
	 *	Requests generated by the interpreter
	 *	are always marked up as internal.
	 */
	fr_assert(request_is_internal(request));
	worker_request_time_tracking_start(worker, request, now);
}


/** External request is now complete
 *
 */
static void _worker_request_done_external(request_t *request, UNUSED rlm_rcode_t rcode, void *uctx)
{
	fr_worker_t	*worker = talloc_get_type_abort(uctx, fr_worker_t);
	fr_time_t 	now = fr_time();

	/*
	 *	All external requests MUST have a listener.
	 */
	fr_assert(request_is_external(request));
	fr_assert(request->async->listen != NULL);

	/*
	 *	Only real packets are in the dedup tree.  And even
	 *	then, only some of the time.
	 */
	if (request->async->listen->track_duplicates) {
		(void) fr_rb_delete(worker->dedup, request);
	}

	/*
	 *	If we're running a real request, then the final
	 *	indentation MUST be zero.  Otherwise we skipped
	 *	something!
	 *
	 *	Also check that the request is NOT marked as
	 *	"yielded", but is in fact done.
	 *
	 *	@todo - check that the stack is at frame 0, otherwise
	 *	more things have gone wrong.
	 */
	fr_assert_msg(request_is_internal(request) || request_is_detached(request) || (request->log.indent.unlang == 0),
		      "Request %s bad log indentation - expected 0 got %u", request->name, request->log.indent.unlang);
	fr_assert_msg(!unlang_interpret_is_resumable(request),
		      "Request %s is marked as yielded at end of processing", request->name);
	fr_assert_msg(unlang_interpret_stack_depth(request) == 0,
		      "Request %s stack depth %u > 0", request->name, unlang_interpret_stack_depth(request));
	RDEBUG("Done request");

	/*
	 *	The request is done.  Track that.
	 */
	worker_request_time_tracking_end(worker, request, now);

	/*
	 *	Remove it from the list of requests associated with this channel.
	 */
	if (fr_dlist_entry_in_list(&request->async->entry)) {
		fr_dlist_entry_unlink(&request->async->entry);
	}

	/*
	 *	These conditions are true when the server is
	 *	exiting and we're stopping all the requests.
	 *
	 *	This should never happen otherwise.
	 */
	if (unlikely(!fr_channel_active(request->async->channel))) {
		request_slab_release(request);
		return;
	}

	worker_send_reply(worker, request, !unlang_request_is_cancelled(request), now);
	request_slab_release(request);
}

/** Internal request (i.e. one generated by the interpreter) is now complete
 *
 * Whatever generated the request is now responsible for freeing it.
 */
static void _worker_request_done_internal(request_t *request, UNUSED rlm_rcode_t rcode, void *uctx)
{
	fr_worker_t	*worker = talloc_get_type_abort(uctx, fr_worker_t);

	worker_request_time_tracking_end(worker, request, fr_time());

	fr_assert(!fr_heap_entry_inserted(request->runnable));
	fr_assert(!fr_timer_armed(request->timeout));
	fr_assert(!fr_dlist_entry_in_list(&request->async->entry));
}

/** Detached request (i.e. one generated by the interpreter with no parent) is now complete
 *
 * As the request has no parent, then there's nothing to free it
 * so we have to.
 */
static void _worker_request_done_detached(request_t *request, UNUSED rlm_rcode_t rcode, UNUSED void *uctx)
{
	/*
	 *	No time tracking for detached requests
	 *	so we don't need to call
	 *	worker_request_time_tracking_end.
	 */
	fr_assert(!fr_heap_entry_inserted(request->runnable));

	/*
	 *	Normally worker_request_time_tracking_end
	 *	would remove the request from the time
	 *	order heap, but we need to do that for
	 *	detached requests.
	 */
	TALLOC_FREE(request->timeout);

	fr_assert(!fr_dlist_entry_in_list(&request->async->entry));

	/*
	 *	Detached requests have to be freed by us
	 *	as nothing else can free them.
	 *
	 *	All other requests must be freed by the
	 *	code which allocated them.
	 */
	talloc_free(request);
}


/** Make us responsible for running the request
 *
 */
static void _worker_request_detach(request_t *request, void *uctx)
{
	fr_worker_t	*worker = talloc_get_type_abort(uctx, fr_worker_t);

	RDEBUG4("%s - Request detaching", __FUNCTION__);

	if (request_is_detachable(request)) {
		/*
		*	End the time tracking...  We don't track detached requests,
		*	because they don't contribute for the time consumed by an
		*	external request.
		*/
		if (request->async->tracking.state == FR_TIME_TRACKING_YIELDED) {
			RDEBUG3("Forcing time tracking to running state, from yielded, for request detach");
			fr_time_tracking_resume(&request->async->tracking, fr_time());
		}
		worker_request_time_tracking_end(worker, request, fr_time());

		if (request_detach(request) < 0) RPEDEBUG("Failed detaching request");

		RDEBUG3("Request is detached");
	} else {
		fr_assert_msg(0, "Request is not detachable");
	}

	return;
}

/** Request is now runnable
 *
 */
static void _worker_request_runnable(request_t *request, void *uctx)
{
	fr_worker_t	*worker = uctx;

	RDEBUG4("%s - Request marked as runnable", __FUNCTION__);
	fr_heap_insert(&worker->runnable, request);
}

/** Interpreter yielded request
 *
 */
static void _worker_request_yield(request_t *request, UNUSED void *uctx)
{
	RDEBUG4("%s - Request yielded", __FUNCTION__);
	if (likely(!request_is_detached(request))) fr_time_tracking_yield(&request->async->tracking, fr_time());
}

/** Interpreter is starting to work on request again
 *
 */
static void _worker_request_resume(request_t *request, UNUSED void *uctx)
{
	RDEBUG4("%s - Request resuming", __FUNCTION__);
	if (likely(!request_is_detached(request))) fr_time_tracking_resume(&request->async->tracking, fr_time());
}

/** Check if a request is scheduled
 *
 */
static bool _worker_request_scheduled(request_t const *request, UNUSED void *uctx)
{
	return fr_heap_entry_inserted(request->runnable);
}

/** Update a request's priority
 *
 */
static void _worker_request_prioritise(request_t *request, void *uctx)
{
	fr_worker_t *worker = talloc_get_type_abort(uctx, fr_worker_t);

	RDEBUG4("%s - Request priority changed", __FUNCTION__);

	/* Extract the request from the runnable queue _if_ it's in the runnable queue */
	if (fr_heap_extract(&worker->runnable, request) < 0) return;

	/* Reinsert it to re-evaluate its new priority */
	fr_heap_insert(&worker->runnable, request);
}

/** Run a request
 *
 *  Until it either yields, or is done.
 *
 *  This function is also responsible for sending replies, and
 *  cleaning up the request.
 *
 * @param[in] worker the worker
 * @param[in] start the current time
 */
static inline CC_HINT(always_inline) void worker_run_request(fr_worker_t *worker, fr_time_t start)
{
	request_t	*request;
	fr_time_t	now;

	WORKER_VERIFY;

	now = start;

	/*
	 *	Busy-loop running requests for 1ms.  We still poll the
	 *	event loop 1000 times a second, OR when there's no
	 *	more work to do.  This allows us to make progress with
	 *	ongoing requests, at the expense of sometimes ignoring
	 *	new ones.
	 */
	while (fr_time_delta_lt(fr_time_sub(now, start), fr_time_delta_from_msec(1)) &&
	       ((request = fr_heap_pop(&worker->runnable)) != NULL)) {

		REQUEST_VERIFY(request);
		fr_assert(!fr_heap_entry_inserted(request->runnable));

		/*
		 *	For real requests, if the channel is gone,
		 *	just stop the request and free it.
		 */
		if (request->async->channel && !fr_channel_active(request->async->channel)) {
			worker_stop_request(request);
			return;
		}

		(void)unlang_interpret(request, UNLANG_REQUEST_RESUME);

		now = fr_time();
	}
}

/** Create a worker
 *
 * @param[in] ctx the talloc context
 * @param[in] name the name of this worker
 * @param[in] el the event list
 * @param[in] logger the destination for all logging messages
 * @param[in] lvl log level
 * @param[in] config various configuration parameters
 * @return
 *	- NULL on error
 *	- fr_worker_t on success
 */
fr_worker_t *fr_worker_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, char const *name, fr_log_t const *logger, fr_log_lvl_t lvl,
			     fr_worker_config_t *config)
{
	fr_worker_t *worker;

	worker = talloc_zero(ctx, fr_worker_t);
	if (!worker) {
nomem:
		fr_strerror_const("Failed allocating memory");
		return NULL;
	}

	worker->name = talloc_strdup(worker, name); /* thread locality */

	unlang_thread_instantiate(worker);

	if (config) worker->config = *config;

#define CHECK_CONFIG(_x, _min, _max) do { \
		if (!worker->config._x) worker->config._x = _min; \
		if (worker->config._x < _min) worker->config._x = _min; \
		if (worker->config._x > _max) worker->config._x = _max; \
       } while (0)

#define CHECK_CONFIG_TIME_DELTA(_x, _min, _max) do { \
		if (fr_time_delta_lt(worker->config._x, _min)) worker->config._x = _min; \
		if (fr_time_delta_gt(worker->config._x, _max)) worker->config._x = _max; \
       } while (0)

	CHECK_CONFIG(max_requests,1024,(1 << 30));
	CHECK_CONFIG(max_channels, 64, 1024);
	CHECK_CONFIG(reuse.child_pool_size, 4096, 65536);
	CHECK_CONFIG(message_set_size, 1024, 8192);
	CHECK_CONFIG(ring_buffer_size, (1 << 17), (1 << 20));
	CHECK_CONFIG_TIME_DELTA(max_request_time, fr_time_delta_from_sec(5), fr_time_delta_from_sec(120));

	worker->channel = talloc_zero_array(worker, fr_worker_channel_t, worker->config.max_channels);
	if (!worker->channel) {
		talloc_free(worker);
		goto nomem;
	}

	worker->thread_id = pthread_self();
	worker->el = el;
	worker->log = logger;
	worker->lvl = lvl;

	/*
	 *	The worker thread starts now.  Manually initialize it,
	 *	because we're tracking request time, not the time that
	 *	the worker thread is running.
	 */
	memset(&worker->tracking, 0, sizeof(worker->tracking));

	worker->aq_control = fr_atomic_queue_alloc(worker, 1024);
	if (!worker->aq_control) {
		fr_strerror_const("Failed creating atomic queue");
	fail:
		talloc_free(worker);
		return NULL;
	}

	worker->control = fr_control_create(worker, el, worker->aq_control);
	if (!worker->control) {
		fr_strerror_const_push("Failed creating control plane");
		goto fail;
	}

	if (fr_control_callback_add(worker->control, FR_CONTROL_ID_CHANNEL, worker, worker_channel_callback) < 0) {
		fr_strerror_const_push("Failed adding control channel");
		goto fail;
	}

	if (fr_control_callback_add(worker->control, FR_CONTROL_ID_LISTEN_DEAD, worker, worker_listen_cancel_callback) < 0) {
		fr_strerror_const_push("Failed adding callback for listeners");
		goto fail;
	}

	worker->runnable = fr_heap_talloc_alloc(worker, worker_runnable_cmp, request_t, runnable, 0);
	if (!worker->runnable) {
		fr_strerror_const("Failed creating runnable heap");
		goto fail;
	}

	worker->timeout = fr_timer_list_ordered_alloc(worker, el->tl);
	if (!worker->timeout) {
		fr_strerror_const("Failed creating timeouts list");
		goto fail;
	}

	worker->timeout_custom = fr_timer_list_lst_alloc(worker, el->tl);
	if (!worker->timeout_custom) {
		fr_strerror_const("Failed creating custom timeouts list");
		goto fail;
	}

	worker->dedup = fr_rb_inline_talloc_alloc(worker, request_t, dedup_node, worker_dedup_cmp, NULL);
	if (!worker->dedup) {
		fr_strerror_const("Failed creating de_dup tree");
		goto fail;
	}

	worker->listeners = fr_rb_inline_talloc_alloc(worker, fr_worker_listen_t, node, worker_listener_cmp, NULL);
	if (!worker->listeners) {
		fr_strerror_const("Failed creating listener tree");
		goto fail;
	}

	worker->intp = unlang_interpret_init(worker, el,
					     &(unlang_request_func_t){
							.init_internal = _worker_request_internal_init,

							.done_external = _worker_request_done_external,
							.done_internal = _worker_request_done_internal,
							.done_detached = _worker_request_done_detached,

							.detach = _worker_request_detach,
							.yield = _worker_request_yield,
							.resume = _worker_request_resume,
							.mark_runnable = _worker_request_runnable,

							.scheduled = _worker_request_scheduled,
							.prioritise = _worker_request_prioritise
					     },
					     worker);
	if (!worker->intp){
		fr_strerror_const("Failed initialising interpreter");
		goto fail;
	}

	{
		if (worker->config.reuse.child_pool_size == 0) worker->config.reuse.child_pool_size = REQUEST_POOL_SIZE;
		if (worker->config.reuse.num_children == 0) worker->config.reuse.num_children = REQUEST_POOL_HEADERS;

		if (!(worker->slab = request_slab_list_alloc(worker, el, &worker->config.reuse, NULL, NULL,
							     UNCONST(void *, worker), true, false))) {
			fr_strerror_const("Failed creating request slab list");
			goto fail;
		}
	}

	unlang_interpret_set_thread_default(worker->intp);

	return worker;
}


/** The main loop and entry point of the stand-alone worker thread.
 *
 *  Where there is only one thread, the event loop runs fr_worker_pre_event() and fr_worker_post_event()
 *  instead, And then fr_worker_post_event() takes care of calling worker_run_request() to actually run the
 *  request.
 *
 * @param[in] worker the worker data structure to manage
 */
void fr_worker(fr_worker_t *worker)
{
	WORKER_VERIFY;

	while (true) {
		bool wait_for_event;
		int num_events;

		WORKER_VERIFY;

		/*
		 *	There are runnable requests.  We still service
		 *	the event loop, but we don't wait for events.
		 */
		wait_for_event = (fr_heap_num_elements(worker->runnable) == 0);
		if (wait_for_event) {
			if (worker->exiting && (worker_num_requests(worker) == 0)) break;

			DEBUG4("Ready to process requests");
		}

		/*
		 *	Check the event list.  If there's an error
		 *	(e.g. exit), we stop looping and clean up.
		 */
		DEBUG4("Gathering events - %s", wait_for_event ? "will wait" : "Will not wait");
		num_events = fr_event_corral(worker->el, fr_time(), wait_for_event);
		if (num_events < 0) {
			if (fr_event_loop_exiting(worker->el)) {
				DEBUG4("Event loop exiting");
				break;
			}

			PERROR("Failed retrieving events");
			break;
		}

		DEBUG4("%u event(s) pending", num_events);

		/*
		 *	Service outstanding events.
		 */
		if (num_events > 0) {
			DEBUG4("Servicing event(s)");
			fr_event_service(worker->el);
		}

		/*
		 *	Run any outstanding requests.
		 */
		worker_run_request(worker, fr_time());
	}
}

/** Pre-event handler
 *
 *	This should be run ONLY in single-threaded mode!
 */
int fr_worker_pre_event(UNUSED fr_time_t now, UNUSED fr_time_delta_t wake, void *uctx)
{
	fr_worker_t *worker = talloc_get_type_abort(uctx, fr_worker_t);
	request_t *request;

	request = fr_heap_peek(worker->runnable);
	if (!request) return 0;

	/*
	 *	There's work to do.  Tell the event handler to poll
	 *	for IO / timers, but also immediately return to the
	 *	calling function, which has more work to do.
	 */
	return 1;
}


/** Post-event handler
 *
 *	This should be run ONLY in single-threaded mode!
 */
void fr_worker_post_event(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_worker_t *worker = talloc_get_type_abort(uctx, fr_worker_t);

	worker_run_request(worker, fr_time());	/* Event loop time can be too old, and trigger asserts */
}

/** Print debug information about the worker structure
 *
 * @param[in] worker the worker
 * @param[in] fp the file where the debug output is printed.
 */
void fr_worker_debug(fr_worker_t *worker, FILE *fp)
{
	WORKER_VERIFY;

	fprintf(fp, "\tnum_channels = %d\n", worker->num_channels);
	fprintf(fp, "\tstats.in = %" PRIu64 "\n", worker->stats.in);

	fprintf(fp, "\tcalculated (predicted) total CPU time = %" PRIu64 "\n",
		fr_time_delta_unwrap(worker->predicted) * worker->stats.in);
	fprintf(fp, "\tcalculated (counted) per request time = %" PRIu64 "\n",
		fr_time_delta_unwrap(worker->tracking.running_total) / worker->stats.in);

	fr_time_tracking_debug(&worker->tracking, fp);

}

/** Create a channel to the worker
 *
 * Called by the master (i.e. network) thread when it needs to create
 * a new channel to a particuler worker.
 *
 * @param[in] worker the worker
 * @param[in] master the control plane of the master
 * @param[in] ctx the context in which the channel will be created
 */
fr_channel_t *fr_worker_channel_create(fr_worker_t *worker, TALLOC_CTX *ctx, fr_control_t *master)
{
	fr_channel_t *ch;
	pthread_t id;
	bool same;

	WORKER_VERIFY;

	id = pthread_self();
	same = (pthread_equal(id, worker->thread_id) != 0);

	ch = fr_channel_create(ctx, master, worker->control, same);
	if (!ch) return NULL;

	fr_channel_set_recv_request(ch, worker, worker_recv_request);

	/*
	 *	Tell the worker about the channel
	 */
	if (fr_channel_signal_open(ch) < 0) {
		talloc_free(ch);
		return NULL;
	}

	return ch;
}

int fr_worker_listen_cancel(fr_worker_t *worker, fr_listen_t const *li)
{
	fr_ring_buffer_t *rb;

	/*
	 *	Skip a bunch of work if we're already in the worker thread.
	 */
	if (is_worker_thread(worker)) {
		return fr_worker_listen_cancel_self(worker, li);
	}

	rb = fr_worker_rb_init();
	if (!rb) return -1;

	return fr_control_message_send(worker->control, rb, FR_CONTROL_ID_LISTEN, &li, sizeof(li));
}

#ifdef WITH_VERIFY_PTR
/** Verify the worker data structures.
 *
 * @param[in] worker the worker
 */
static void worker_verify(fr_worker_t *worker)
{
	int i;

	(void) talloc_get_type_abort(worker, fr_worker_t);
	fr_atomic_queue_verify(worker->aq_control);

	fr_assert(worker->control != NULL);
	(void) talloc_get_type_abort(worker->control, fr_control_t);

	fr_assert(worker->el != NULL);
	(void) talloc_get_type_abort(worker->el, fr_event_list_t);

	fr_assert(worker->runnable != NULL);
	(void) talloc_get_type_abort(worker->runnable, fr_heap_t);

	fr_assert(worker->dedup != NULL);
	(void) talloc_get_type_abort(worker->dedup, fr_rb_tree_t);

	for (i = 0; i < worker->config.max_channels; i++) {
		if (!worker->channel[i].ch) continue;

		(void) talloc_get_type_abort(worker->channel[i].ch, fr_channel_t);
	}
}
#endif

int fr_worker_stats(fr_worker_t const *worker, int num, uint64_t *stats)
{
	if (num < 0) return -1;
	if (num == 0) return 0;

	stats[0] = worker->stats.in;
	if (num >= 2) stats[1] = worker->stats.out;
	if (num >= 3) stats[2] = worker->stats.dup;
	if (num >= 4) stats[3] = worker->stats.dropped;
	if (num >= 5) stats[4] = worker->num_naks;
	if (num >= 6) stats[5] = worker->num_active;

	if (num <= 6) return num;

	return 6;
}

static int cmd_stats_worker(FILE *fp, UNUSED FILE *fp_err, void *ctx, fr_cmd_info_t const *info)
{
	fr_worker_t const *worker = ctx;
	fr_time_delta_t when;

	if ((info->argc == 0) || (strcmp(info->argv[0], "count") == 0)) {
		fprintf(fp, "count.in\t\t\t%" PRIu64 "\n", worker->stats.in);
		fprintf(fp, "count.out\t\t\t%" PRIu64 "\n", worker->stats.out);
		fprintf(fp, "count.dup\t\t\t%" PRIu64 "\n", worker->stats.dup);
		fprintf(fp, "count.dropped\t\t\t%" PRIu64 "\n", worker->stats.dropped);
		fprintf(fp, "count.naks\t\t\t%" PRIu64 "\n", worker->num_naks);
		fprintf(fp, "count.active\t\t\t%" PRIu64 "\n", worker->num_active);
		fprintf(fp, "count.runnable\t\t\t%u\n", fr_heap_num_elements(worker->runnable));
	}

	if ((info->argc == 0) || (strcmp(info->argv[0], "cpu") == 0)) {
		when = worker->predicted;
		fprintf(fp, "cpu.request_time_rtt\t\t%.9f\n", fr_time_delta_unwrap(when) / (double)NSEC);

		when = worker->tracking.running_total;
		if (fr_time_delta_ispos(when)) when = fr_time_delta_div(when, fr_time_delta_wrap(worker->stats.in - worker->stats.dropped));
		fprintf(fp, "cpu.average_request_time\t%.9f\n", fr_time_delta_unwrap(when) / (double)NSEC);

		when = worker->tracking.running_total;
		fprintf(fp, "cpu.used\t\t\t%.6f\n", fr_time_delta_unwrap(when) / (double)NSEC);

		when = worker->tracking.waiting_total;
		fprintf(fp, "cpu.waiting\t\t\t%.3f\n", fr_time_delta_unwrap(when) / (double)NSEC);

		fr_time_elapsed_fprint(fp, &worker->cpu_time, "cpu.requests", 4);
		fr_time_elapsed_fprint(fp, &worker->wall_clock, "time.requests", 4);
	}

	return 0;
}

fr_cmd_table_t cmd_worker_table[] = {
	{
		.parent = "stats",
		.name = "worker",
		.help = "Statistics for workers threads.",
		.read_only = true
	},

	{
		.parent = "stats worker",
		.add_name = true,
		.name = "self",
		.syntax = "[(count|cpu)]",
		.func = cmd_stats_worker,
		.help = "Show statistics for a specific worker thread.",
		.read_only = true
	},

	CMD_TABLE_END
};
