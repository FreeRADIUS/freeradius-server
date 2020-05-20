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
 *  also into the "time_order" heap. The main loop fr_worker() then
 *  pulls new requests off of this heap and runs them.  The
 *  worker_check_timeouts() function also checks the tail of the
 *  "time_order" heap, and ages out requests which have been active
 *  for "too long".
 *
 *  A request may return one of RLM_MODULE_YIELD,
 *  RLM_MODULE_OK, or RLM_MODULE_HANDLED.  If a request is
 *  yielded, it is placed onto the yielded list in the worker
 *  "tracking" data structure.
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#define LOG_PREFIX "%s - "
#define LOG_PREFIX_ARGS worker->name
#define LOG_DST worker->log

#include <freeradius-devel/io/time_tracking.h>
#include <freeradius-devel/io/worker.h>
#include <freeradius-devel/io/channel.h>
#include <freeradius-devel/io/message.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/util/dlist.h>

#ifdef WITH_VERIFY_PTR
static void worker_verify(fr_worker_t *worker);
#define WORKER_VERIFY worker_verify(worker)
#else
#define WORKER_VERIFY
#endif

static _Thread_local fr_worker_t *thread_local_worker;

/**
 *  A worker which takes packets from a master, and processes them.
 */
struct fr_worker_s {
	char const		*name;		//!< name of this worker
	fr_worker_config_t	config;		//!< external configuration

	pthread_t		thread_id;	//!< my thread ID

	fr_log_t const		*log;		//!< log destination
	fr_log_lvl_t		lvl;		//!< log level

	fr_atomic_queue_t	*aq_control;	//!< atomic queue for control messages sent to me

	fr_control_t		*control;	//!< the control plane

	fr_event_list_t		*el;		//!< our event list

	uint64_t		number;		//!< Per worker request id.

	int			num_channels;	//!< actual number of channels

	fr_heap_t      		*runnable;	//!< current runnable requests which we've spent time processing
	fr_heap_t		*time_order;	//!< time ordered heap of requests
	rbtree_t		*dedup;		//!< de-dup tree

	fr_io_stats_t		stats;		//!< input / output stats
	fr_time_elapsed_t	cpu_time;	//!< histogram of total CPU time per request
	fr_time_elapsed_t	wall_clock;	//!< histogram of wall clock time per request

	uint64_t    		num_naks;	//!< number of messages which were nak'd
	uint64_t    		num_active;	//!< number of active requests

	fr_time_delta_t		predicted;	//!< How long we predict a request will take to execute.
	fr_time_tracking_t	tracking;	//!< how much time the worker has spent doing things.

	bool			was_sleeping;	//!< used to suppress multiple sleep signals in a row
	bool			exiting;	//!< are we exiting?

	fr_time_t		checked_timeout; //!< when we last checked the tails of the queues

	fr_event_timer_t const	*ev_cleanup;	//!< timer for max_request_time

	fr_channel_t		**channel;	//!< list of channels
};

static void worker_request_bootstrap(fr_worker_t *worker, fr_channel_data_t *cd, fr_time_t now);

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
			fr_assert(worker->channel[i] != ch);

			if (worker->channel[i] != NULL) continue;

			worker->channel[i] = ch;
			DEBUG3("Received channel %p into array entry %d", ch, i);

			ms = fr_message_set_create(worker, worker->config.message_set_size,
						   sizeof(fr_channel_data_t),
						   worker->config.ring_buffer_size);
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
			if (!worker->channel[i]) continue;

			if (worker->channel[i] != ch) continue;

			ms = fr_channel_responder_uctx_get(ch);

			fr_channel_responder_ack_close(ch);
			fr_assert(ms != NULL);
			fr_message_set_gc(ms);
			talloc_free(ms);

			worker->channel[i] = NULL;
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
	reply->reply.processing_time = 10; /* @todo - set to something better? */
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

static void worker_max_request_timer(fr_worker_t *worker);


/** Send a response packet to the network side
 *
 * @param[in] worker		This worker.
 * @param[in] request		we're sending a reply for.
 * @param[in] size		The maximum size of the reply data
 * @param[in] now		The current time
 */
static void worker_send_reply(fr_worker_t *worker, REQUEST *request, size_t size, fr_time_t now)
{
	fr_channel_data_t *reply;
	fr_channel_t *ch;
	fr_message_set_t *ms;

	REQUEST_VERIFY(request);

	/*
	 *	If we're sending a reply, then it's no longer runnable.
	 */
	fr_assert(request->runnable_id < 0);

	/*
	 *	If it's a fake request, or we're exiting, don't send a
	 *	real reply.  Just toss the request.
	 */
	if (request->async->fake || worker->exiting) {
		fr_time_tracking_end(&worker->predicted, &request->async->tracking, now);
		goto finished;
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
	if (size) {
		ssize_t slen = 0;
		fr_listen_t const *listen = request->async->listen;

		if (listen->app->encode) {
			slen = listen->app->encode(listen->app_instance, request,
						   reply->m.data, reply->m.rb_size);
		} else if (listen->app_io->encode) {
			slen = listen->app_io->encode(listen->app_io_instance, request,
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
	 *	The request is done.  Track that.
	 */
	fr_time_tracking_end(&worker->predicted, &request->async->tracking, now);
	fr_assert(worker->num_active > 0);
	worker->num_active--;

	/*
	 *	Fill in the rest of the fields in the channel message.
	 *
	 *	sequence / ack will be filled in by fr_channel_send_reply()
	 */
	reply->m.when = request->async->tracking.last_changed;
	reply->reply.cpu_time = worker->tracking.running_total;
	reply->reply.processing_time = request->async->tracking.running_total;
	reply->reply.request_time = request->async->recv_time;

	reply->listen = request->async->listen;
	reply->packet_ctx = request->async->packet_ctx;

	/*
	 *	Update the various timers.
	 */
	fr_time_elapsed_update(&worker->cpu_time, now, now + reply->reply.processing_time);
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

	/*
	 *	@todo Use a talloc pool for the request.  Clean it up,
	 *	and insert it back into a slab allocator.
	 */
finished:
	if (request->time_order_id >= 0) (void) fr_heap_extract(worker->time_order, request);
	if (request->runnable_id >= 0) (void) fr_heap_extract(worker->runnable, request);

	fr_assert(request->time_order_id < 0);
	fr_assert(request->runnable_id < 0);

#ifndef NDEBUG
	request->async->el = NULL;
	request->async->process = NULL;
	request->async->channel = NULL;
	request->async->packet_ctx = NULL;
	request->async->listen = NULL;
#endif

	DEBUG3("Freeing request %s", request->name);
	talloc_free(request);
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
 * @param[in] worker	running the request.
 * @param[in] request	to cancel.
 * @param[in] now	The current time.
 */
static void worker_stop_request(fr_worker_t *worker, REQUEST *request, fr_time_t now)
{
	if (request->async->tracking.state == FR_TIME_TRACKING_YIELDED) {
		fr_time_tracking_resume(&request->async->tracking, now);
	}

	unlang_interpret_signal(request, FR_SIGNAL_CANCEL);

	/*
	 *	The request is ALWAYS in the time_order list.
	 *
	 *	It MAY be in the runnable list if it has yielded
	 *	but is ready to be resumed.
	 *
	 *	MAY be in the dedup list, but if
	 *	app_io->track_duplicates is true, i.e. we have
	 *	been requested by an application via its public
	 *	interface to track duplicate requests.
	 */
	if (request->time_order_id >= 0) (void) fr_heap_extract(worker->time_order, request);
	if (request->runnable_id >= 0) (void) fr_heap_extract(worker->runnable, request);
	if (request->async->listen && request->async->listen->track_duplicates) rbtree_deletebydata(worker->dedup, request);

#ifndef NDEBUG
	request->async->process = NULL;
#endif
}

/** Enforce max_request_time
 *
 * Run periodically, and tries to clean up requests which were received by the network
 * thread more than max_request_time seconds ago.  In the interest of not adding a
 * timer for every packet, the requests are given a 1 second leeway.
 *
 * @param[in] el	the worker's event list
 * @param[in] when	the current time
 * @param[in] uctx	the fr_worker_t.
 */
static void worker_max_request_time(UNUSED fr_event_list_t *el, UNUSED fr_time_t when, void *uctx)
{
	fr_time_t	now = fr_time();
	REQUEST		*request;
	fr_worker_t	*worker = talloc_get_type_abort(uctx, fr_worker_t);

	/*
	 *	Look at the oldest requests, and see if they need to
	 *	be deleted.
	 */
	while ((request = fr_heap_peek_tail(worker->time_order)) != NULL) {
		fr_time_t cleanup;

		REQUEST_VERIFY(request);

		cleanup = request->async->recv_time;
		cleanup += worker->config.max_request_time;
		if (cleanup > now) break;

		/*
		 *	Waiting too long, delete it.
		 */
		REDEBUG("Request has reached max_request_time - signalling it to stop");
		worker_stop_request(worker, request, now);

		/*
		 *	Tell the network side that this request is
		 *	done.  Also make sure that each time stamp is
		 *	unique.
		 */
		worker_send_reply(worker, request, 1, now);
	}

	/*
	 *	Reset the max request timer.
	 */
	worker_max_request_timer(worker);
}

/** See when we next need to service the time_order heap for "too old" packets
 *
 * Inserts a timer into the event list will will trigger when the packet that
 * was received longest ago, would be older than max_request_time.
 */
static void worker_max_request_timer(fr_worker_t *worker)
{
	fr_time_t	cleanup;
	REQUEST		*request;

	/*
	 *	No more requests, delete the timer.
	 */
	request = fr_heap_peek_tail(worker->time_order);
	if (!request) return;

	cleanup = request->async->recv_time;
	cleanup += worker->config.max_request_time;

	DEBUG2("Resetting cleanup timer to +%pV", fr_box_time_delta(worker->config.max_request_time));
	if (fr_event_timer_at(worker, worker->el, &worker->ev_cleanup,
			      cleanup, worker_max_request_time, worker) < 0) {
		ERROR("Failed inserting max_request_time timer");
	}
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
static void worker_request_init(fr_worker_t *worker, REQUEST *request, fr_time_t now)
{
	request->el = worker->el;
	request->backlog = worker->runnable;
	MEM(request->packet = fr_radius_alloc(request, false));
	request->packet->timestamp = now;

	request->reply = fr_radius_alloc(request, false);
	fr_assert(request->reply != NULL);

	request->number = worker->number++;
	request->name = itoa_internal(request, request->number);

	request->async = talloc_zero(request, fr_async_t);
	request->async->recv_time = now;
	request->async->el = worker->el;
}

/** Start time tracking for a request, and mark it as runnable.
 *
 */
static void worker_request_time_tracking_start(fr_worker_t *worker, REQUEST *request, fr_time_t now)
{
	/*
	 *	New requests are inserted into the time order heap in
	 *	strict time priority.  Once they are in the list, they
	 *	are only removed when the request is done / free'd.
	 */
	fr_assert(request->time_order_id < 0);
	(void) fr_heap_insert(worker->time_order, request);

	/*
	 *	Bootstrap the async state machine with the initial
	 *	state of the request.
	 */
	fr_time_tracking_start(&worker->tracking, &request->async->tracking, now);
	fr_time_tracking_yield(&request->async->tracking, now);
	worker->num_active++;

	fr_assert(request->runnable_id < 0);
	(void) fr_heap_insert(worker->runnable, request);

	if (!worker->ev_cleanup) worker_max_request_timer(worker);
}

static void worker_request_bootstrap(fr_worker_t *worker, fr_channel_data_t *cd, fr_time_t now)
{
	bool			is_dup;
	int			ret = -1;
	REQUEST			*request;
	TALLOC_CTX		*ctx;
	fr_listen_t const	*listen;

	if (fr_heap_num_elements(worker->time_order) >= (uint32_t) worker->config.max_requests) goto nak;

	ctx = request = request_alloc(NULL);
	if (!request) goto nak;

	worker_request_init(worker, request, now);

	request->packet->timestamp = cd->request.recv_time; /* Legacy - Remove once everything looks at request->async */

	/*
	 *	Receive a message to the worker queue, and decode it
	 *	to a request.
	 */
	fr_assert(cd->listen != NULL);
	request->server_cs = cd->listen->server_cs;

	/*
	 *	Update the transport-specific fields.
	 */
	request->async->channel = cd->channel.ch;

	request->async->recv_time = cd->request.recv_time;


	request->async->listen = cd->listen;
	request->async->packet_ctx = cd->packet_ctx;
	listen = request->async->listen;

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
	 *	Call the main protocol handler to set the right async
	 *	process function.
	 */
	listen->app->entry_point_set(listen->app_instance, request);

	if (!request->async->process) {
		RERROR("Protocol failed to set 'process' function");
		worker_nak(worker, cd, now);
		return;
	}

	/*
	 *	We're done with this message.
	 */
	is_dup = cd->request.is_dup;
	fr_message_done(&cd->m);

	/*
	 *	Look for conflicting / duplicate packets, but only if
	 *	requested to do so.
	 */
	if (request->async->listen->track_duplicates) {
		REQUEST *old;

		old = rbtree_finddata(worker->dedup, request);
		if (!old) {
			/*
			 *	Ignore duplicate packets where we've
			 *	already sent the reply.
			 */
			if (is_dup) {
				RDEBUG("Got duplicate packet notice after we had sent a reply - ignoring");
				fr_channel_null_reply(request->async->channel);
				return;
			}
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
		if (old->async->recv_time == request->async->recv_time) {
			RWARN("Discarding duplicate of request (%"PRIu64")", old->number);

			fr_channel_null_reply(request->async->channel);
			talloc_free(request);

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

		worker_stop_request(worker, old, now);
		fr_assert(worker->num_active > 0);
		worker->num_active--;
		worker->stats.dropped++;
		talloc_free(old);

	insert_new:
		(void) rbtree_insert(worker->dedup, request);
	}

	worker_request_time_tracking_start(worker, request, now);
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
static void worker_run_request(fr_worker_t *worker, fr_time_t start)
{
	ssize_t size = 0;
	rlm_rcode_t final;
	REQUEST *request;
	fr_time_t now;

	WORKER_VERIFY;

	now = start;

redo:
	request = fr_heap_pop(worker->runnable);
	if (!request) return;

	REQUEST_VERIFY(request);
	fr_assert(request->runnable_id < 0);
	fr_time_tracking_resume(&request->async->tracking, now);

	fr_assert(request->parent == NULL);
	fr_assert(request->async->process != NULL);
	fr_assert(request->async->fake || (request->async->listen != NULL));
	fr_assert(request->runnable_id < 0); /* removed from the runnable heap */

	RDEBUG("Running request");

	/*
	 *	For real requests, if the channel is gone, just stop
	 *	the request and free it.
	 */
	if (!request->async->fake && !fr_channel_active(request->async->channel)) {
		worker_stop_request(worker, request, now);
		talloc_free(request);
		return;
	}

	/*
	 *	Everything else, run the request.
	 */
	final = request->async->process(request->async->process_inst, NULL, request);

	/*
	 *	Figure out what to do next.
	 */
	switch (final) {
	case RLM_MODULE_HANDLED:
		/*
		 *	Done: don't send a reply.
		 */
		break;

	case RLM_MODULE_FAIL:
	default:
		/*
		 *	Something went wrong.  It's done, but we don't send a reply.
		 */
		break;

	case RLM_MODULE_YIELD:
		now = fr_time();
		fr_time_tracking_yield(&request->async->tracking, now);
		goto keep_going;

	case RLM_MODULE_OK:
		/*
		 *	Don't reply to internally generated request.
		 */
		if (request->parent || request->async->fake) break;

		size = request->async->listen->app_io->default_reply_size;
		if (!size) size = request->async->listen->app_io->default_message_size;
		break;
	}

	RDEBUG("Done request");

	/*
	 *	Only real packets are in the dedup tree.  And even
	 *	then, only some of the time.
	 */
	if (!request->async->fake && request->async->listen->track_duplicates) {
		(void) rbtree_deletebydata(worker->dedup, request);
	}

	now = fr_time();
	worker_send_reply(worker, request, size, now);
	now = fr_time();

keep_going:
	/*
	 *	If this request ran for less than 0.1ms, then go run
	 *	another request.  This change means that the worker
	 *	checks the event loop only 10K times per second, which
	 *	should be good enough.
	 */
	if ((now - start) > (NSEC / 100000)) {
		return;
	}

	goto redo;
}


/**
 *  Track a REQUEST in the "runnable" heap.
 */
static int8_t worker_runnable_cmp(void const *one, void const *two)
{
	REQUEST const *a = one, *b = two;
	int ret;

	ret = (a->async->priority > b->async->priority) - (a->async->priority < b->async->priority);
	if (ret != 0) return ret;

	return (a->async->recv_time > b->async->recv_time) - (a->async->recv_time < b->async->recv_time);
}

/**
 *  Track a REQUEST in the "time_order" heap.
 */
static int8_t worker_time_order_cmp(void const *one, void const *two)
{
	REQUEST const *a = one, *b = two;

	return (a->async->recv_time > b->async->recv_time) - (a->async->recv_time < b->async->recv_time);
}

/**
 *  Track a REQUEST in the "dedup" tree
 */
static int worker_dedup_cmp(void const *one, void const *two)
{
	int ret;
	REQUEST const *a = one, *b = two;

	ret = (a->async->listen > b->async->listen) - (a->async->listen < b->async->listen);
	if (ret) return ret;

	return (a->async->packet_ctx > b->async->packet_ctx) - (a->async->packet_ctx < b->async->packet_ctx);
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
	int i, count;
	REQUEST *request;
	fr_time_t now = fr_time();

//	WORKER_VERIFY;

	/*
	 *	Destroy all of the active requests.  These are ones
	 *	which are still waiting for timers or file descriptor
	 *	events.
	 */
	count = 0;
	while ((request = fr_heap_peek(worker->time_order)) != NULL) {
		if (count < 10) {
			DEBUG("Worker is exiting - telling request %s to stop", request->name);
			count++;
		}
		worker_stop_request(worker, request, now);
		talloc_free(request);
	}
	fr_assert(fr_heap_num_elements(worker->runnable) == 0);

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
		if (!worker->channel[i]) continue;

		fr_channel_responder_ack_close(worker->channel[i]);
	}

	thread_local_worker = NULL;
	talloc_free(worker);
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
fr_worker_t *fr_worker_create(TALLOC_CTX *ctx, fr_event_list_t *el, char const *name, fr_log_t const *logger, fr_log_lvl_t lvl,
			      fr_worker_config_t *config)
{
	fr_worker_t *worker;

	worker = talloc_zero(ctx, fr_worker_t);
	if (!worker) {
nomem:
		fr_strerror_printf("Failed allocating memory");
		return NULL;
	}

	worker->name = talloc_strdup(worker, name); /* thread locality */

	if (config) worker->config = *config;

#define CHECK_CONFIG(_x, _min, _max) do { \
		if (!worker->config._x) worker->config._x = _min; \
		if (worker->config._x < _min) worker->config._x = _min; \
		if (worker->config._x > _max) worker->config._x = _max; \
       } while (0)

	CHECK_CONFIG(max_requests,(1 << 20),(1 << 30));
	CHECK_CONFIG(max_channels, 64, 1024);
	CHECK_CONFIG(talloc_pool_size, 4096, 65536);
	CHECK_CONFIG(message_set_size, 1024, 8192);
	CHECK_CONFIG(ring_buffer_size, (1 << 17), (1 << 20));
	CHECK_CONFIG(max_request_time, fr_time_delta_from_sec(30), fr_time_delta_from_sec(60));

	worker->channel = talloc_zero_array(worker, fr_channel_t *, worker->config.max_channels);
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

	worker->aq_control = fr_atomic_queue_create(worker, 1024);
	if (!worker->aq_control) {
		fr_strerror_printf("Failed creating atomic queue");
	fail:
		talloc_free(worker);
		return NULL;
	}

	worker->control = fr_control_create(worker, el, worker->aq_control);
	if (!worker->control) {
		fr_strerror_printf_push("Failed creating control plane");
		goto fail;
	}

	if (fr_control_callback_add(worker->control, FR_CONTROL_ID_CHANNEL, worker, worker_channel_callback) < 0) {
		fr_strerror_printf_push("Failed adding control channel");
		goto fail;
	}

	worker->runnable = fr_heap_talloc_alloc(worker, worker_runnable_cmp, REQUEST, runnable_id);
	if (!worker->runnable) {
		fr_strerror_printf("Failed creating runnable heap");
		goto fail;
	}

	worker->time_order = fr_heap_talloc_alloc(worker, worker_time_order_cmp, REQUEST, time_order_id);
	if (!worker->time_order) {
		fr_strerror_printf("Failed creating time_order heap");
		goto fail;
	}

	worker->dedup = rbtree_talloc_alloc(worker, worker_dedup_cmp, REQUEST, NULL, RBTREE_FLAG_NONE);
	if (!worker->dedup) {
		fr_strerror_printf("Failed creating de_dup tree");
		goto fail;
	}

	thread_local_worker = worker;

	return worker;
}


/** The main loop and entry point of the worker thread.
 *
 * @param[in] worker the worker data structure to manage
 */
void fr_worker(fr_worker_t *worker)
{
	WORKER_VERIFY;

	while (!worker->exiting) {
		bool wait_for_event;
		int num_events;

		WORKER_VERIFY;

		/*
		 *	There are runnable requests.  We still service
		 *	the event loop, but we don't wait for events.
		 */
		wait_for_event = (fr_heap_num_elements(worker->runnable) == 0);
		if (wait_for_event) {
			DEBUG4("Ready to process requests");
		}

		/*
		 *	Check the event list.  If there's an error
		 *	(e.g. exit), we stop looping and clean up.
		 */
		DEBUG3("Gathering events - %s", wait_for_event ? "will wait" : "Will not wait");
		num_events = fr_event_corral(worker->el, fr_time(), wait_for_event);
		if (num_events < 0) {
			PERROR("Failed retrieving events");
			break;
		}

		DEBUG3("%u event(s) pending%s",
		       num_events == -1 ? 0 : num_events, num_events == -1 ? " - event loop exiting" : "");

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
int fr_worker_pre_event(void *uctx, UNUSED fr_time_t wake)
{
	fr_worker_t *worker = talloc_get_type_abort(uctx, fr_worker_t);
	REQUEST *request;

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

/** Asynchronously add a REQUEST to a worker thread
 *
 *  When we don't know what the worker is...
 */
int fr_worker_request_add(REQUEST *request, module_method_t process, void *ctx)
{
	fr_worker_t *worker;
	fr_time_t now;

	if (!request || !process) {
		fr_strerror_printf("Invalid arguments");
		return -1;
	}

	worker = thread_local_worker;
	if (!worker) {
		fr_strerror_printf("No worker has been defined");
		return -1;
	}

	now = fr_time();

	worker_request_init(worker, request, now);

	request->async->fake = true;
	request->async->process = process;
	request->async->process_inst = ctx;

	worker_request_time_tracking_start(worker, request, now);

	return 0;
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
		worker->predicted * worker->stats.in);
	fprintf(fp, "\tcalculated (counted) per request time = %" PRIu64 "\n",
		worker->tracking.running_total / worker->stats.in);

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

#ifdef WITH_VERIFY_PTR
/** Verify the worker data structures.
 *
 * @param[in] worker the worker
 */
static void worker_verify(fr_worker_t *worker)
{
	int i;

	(void) talloc_get_type_abort(worker, fr_worker_t);
	(void) talloc_get_type_abort(worker->aq_control, fr_atomic_queue_t);

	fr_assert(worker->control != NULL);
	(void) talloc_get_type_abort(worker->control, fr_control_t);

	fr_assert(worker->el != NULL);
	(void) talloc_get_type_abort(worker->el, fr_event_list_t);

	fr_assert(worker->runnable != NULL);
	(void) talloc_get_type_abort(worker->runnable, fr_heap_t);

	fr_assert(worker->dedup != NULL);
	(void) talloc_get_type_abort(worker->dedup, rbtree_t);

	for (i = 0; i < worker->config.max_channels; i++) {
		if (!worker->channel[i]) continue;

		(void) talloc_get_type_abort(worker->channel[i], fr_channel_t);
	}
}
#endif

int fr_worker_stats(fr_worker_t const *worker, int num, uint64_t *stats)
{
	if (num < 0) return -1;
	if (num == 0) return 0;

	if (num >= 1) stats[0] = worker->stats.in;
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
	fr_time_t when;

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
		fprintf(fp, "cpu.request_time_rtt\t\t%u.%09" PRIu64 "\n", (unsigned int) (when / NSEC), when % NSEC);

		when = worker->tracking.running_total;
		if (when > 0) when /= (worker->stats.in - worker->stats.dropped);
		fprintf(fp, "cpu.average_request_time\t%u.%09" PRIu64 "\n", (unsigned int) (when / NSEC), when % NSEC);

		when = worker->tracking.running_total;
		fprintf(fp, "cpu.used\t\t\t%u.%06u\n", (unsigned int) (when / NSEC), (unsigned int) (when % NSEC) / 1000);

		when = worker->tracking.waiting_total;
		fprintf(fp, "cpu.waiting\t\t\t%u.%03u\n", (unsigned int) (when / NSEC), (unsigned int) (when % NSEC) / 1000000);

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
