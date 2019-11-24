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
 *  The lifecycle of a packet MUST be carefully managed.  Initially,
 *  messages are put into the "to_decode" heap.  If the messages sit
 *  in the heap for too long, they are localized and put into the
 *  "localized" heap.  Each heap is ordered by (priority, time), so
 *  that high priority packets take precedence over low priority
 *  packets.
 *
 *  Both queues have linked lists of received packets, ordered by
 *  time.  This list is used to clean up packets which have been in
 *  the heap for "too long", in fr_worker_check_timeouts().
 *
 *  When a packet is decoded, it is put into the "runnable" heap, and
 *  also into the "time_order" heap. The main loop fr_worker() then
 *  pulls new requests off of this heap and runs them.  The
 *  fr_worker_check_timeouts() function also checks the tail of the
 *  "time_order" heap, and ages out requests which have been active
 *  for "too long".
 *
 *  A request may return one of RLM_MODULE_YIELD,
 *  RLM_MODULE_OK, or RLM_MODULE_HANDLED.  If a request is
 *  yeilded, it is placed onto the yielded list in the worker
 *  "tracking" data structure.
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#define LOG_DST worker->log

#include <freeradius-devel/io/worker.h>
#include <freeradius-devel/io/channel.h>
#include <freeradius-devel/io/message.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/util/dlist.h>

/**
 *  Track things by priority and time.
 */
typedef struct {
	fr_dlist_head_t	list;			//!< list of things, ordered by time.
	fr_heap_t	*heap;			//!< heap, ordered by priority
} fr_worker_heap_t;

#ifndef NDEBUG
static void fr_worker_verify(fr_worker_t *worker);
#define WORKER_VERIFY fr_worker_verify(worker)
#else
#define WORKER_VERIFY
#endif


/**
 *  A worker which takes packets from a master, and processes them.
 */
struct fr_worker_t {
	char const		*name;		//!< name of this worker

	int			kq;		//!< my kq
	pthread_t		id;		//!< my thread ID

	fr_log_t const		*log;		//!< log destination
	fr_log_lvl_t		lvl;		//!< log level

	fr_atomic_queue_t	*aq_control;	//!< atomic queue for control messages sent to me

	uintptr_t		aq_ident;	//!< identifier for control-plane events

	fr_control_t		*control;	//!< the control plane

	fr_event_list_t		*el;		//!< our event list

	uint64_t		number;		//!< for requests

	int			num_channels;	//!< actual number of channels
	int			max_channels;	//!< maximum number of channels

	int                     message_set_size; //!< default start number of messages
	int                     ring_buffer_size; //!< default start size for the ring buffers

	fr_time_delta_t		max_request_time; //!< maximum time a request can be processed

	size_t			talloc_pool_size; //!< for each REQUEST


	fr_worker_heap_t	to_decode;	//!< messages from the master, to be decoded or localized
	fr_worker_heap_t       	localized;	//!< localized messages to be decoded

	fr_heap_t      		*runnable;	//!< current runnable requests which we've spent time processing
	fr_heap_t		*time_order;	//!< time ordered heap of requests
	rbtree_t		*dedup;		//!< de-dup tree

	fr_io_stats_t		stats;		//!< input / output stats
	fr_time_elapsed_t	cpu_time;	//!< histogram of total CPU time per request
	fr_time_elapsed_t	wall_clock;	//!< histogram of wall clock time per request

	uint64_t       		num_decoded;	//!< number of messages which have been decoded
	uint64_t    		num_timeouts;	//!< number of messages which timed out
	uint64_t    		num_active;	//!< number of active requests

	fr_time_tracking_t	tracking;	//!< how much time the worker has spent doing things.

	bool			was_sleeping;	//!< used to suppress multiple sleep signals in a row
	bool			exiting;	//!< are we exiting?

	fr_time_t		checked_timeout; //!< when we last checked the tails of the queues
	fr_time_t		last_event;	//!< last time we ran the event loop

	fr_time_t		next_cleanup;	//!< when we next do the max_request_time checks
	fr_event_timer_t const	*ev_cleanup;	//!< timer for max_request_time

	fr_channel_t		**channel;	//!< list of channels
};

static void fr_worker_post_event(fr_event_list_t *el, fr_time_t now, void *uctx);

/*
 *	We need wrapper macros because we have multiple instances of
 *	the same code.
 */
#define WORKER_HEAP_INIT(_name, _func) do { \
		fr_dlist_init(&worker->_name.list, fr_channel_data_t, request.entry); \
		worker->_name.heap = fr_heap_create(worker, _func, fr_channel_data_t, channel.heap_id); \
		if (!worker->_name.heap) { \
			(void) fr_event_user_delete(worker->el, fr_worker_evfilt_user, worker); \
			talloc_free(worker); \
			goto nomem; \
		} \
	} while (0)

#define WORKER_HEAP_INSERT(_name, _var) do { \
		(void) fr_heap_insert(worker->_name.heap, _var);       \
		fr_dlist_insert_head(&worker->_name.list, _var);       \
	} while (0)

#define WORKER_HEAP_POP(_name, _var) do { \
		_var = fr_heap_pop(worker->_name.heap);                \
		if (_var) fr_dlist_remove(&worker->_name.list, _var);  \
	} while (0)

#define WORKER_HEAP_EXTRACT(_name, _var) do { \
               (void) fr_heap_extract(worker->_name.heap, _var);       \
               fr_dlist_remove(&worker->_name.list, _var);	       \
       } while (0)


/** Callback which handles a message being received on the worker side.
 *
 * @param[in] ctx the worker
 * @param[in] ch the channel to drain
 * @param[in] cd the message (if any) to start with
 */
static void fr_worker_recv_request(void *ctx, fr_channel_t *ch, fr_channel_data_t *cd)
{
	fr_worker_t *worker = ctx;

	worker->stats.in++;
	DEBUG3("\t%sreceived request %" PRIu64 "", worker->name, worker->stats.in);
	cd->channel.ch = ch;
	WORKER_HEAP_INSERT(to_decode, cd);
}


/** Handle a worker control message for a channel
 *
 * @param[in] ctx the worker
 * @param[in] data the message
 * @param[in] data_size size of the data
 * @param[in] now the current time
 */
static void fr_worker_channel_callback(void *ctx, void const *data, size_t data_size, fr_time_t now)
{
	int i;
	bool ok, was_sleeping;
	fr_channel_t *ch;
	fr_message_set_t *ms;
	fr_channel_event_t ce;
	fr_worker_t *worker = ctx;

	was_sleeping = worker->was_sleeping;
	worker->was_sleeping = false;

	/*
	 *	We were woken up by a signal to do something.  We're
	 *	not sleeping.
	 */
	ce = fr_channel_service_message(now, &ch, data, data_size);
	switch (ce) {
	case FR_CHANNEL_ERROR:
		DEBUG3("\t--> error");
		return;

	case FR_CHANNEL_EMPTY:
		DEBUG3("\t--> ...");
		return;

	case FR_CHANNEL_NOOP:
		DEBUG3("\t--> noop");
		return;

	case FR_CHANNEL_DATA_READY_NETWORK:
		rad_assert(0 == 1);
		DEBUG3("\t--> ??? network");
		break;

	case FR_CHANNEL_DATA_READY_WORKER:
		rad_assert(ch != NULL);
		DEBUG3("\t--> data");

		if (!fr_channel_recv_request(ch)) {
			worker->was_sleeping = was_sleeping;

		} else while (fr_channel_recv_request(ch)) {
				/* do nothing */
		}
		break;

	case FR_CHANNEL_OPEN:
		DEBUG3("\t--> channel open");

		rad_assert(ch != NULL);

		ok = false;
		for (i = 0; i < worker->max_channels; i++) {
			rad_assert(worker->channel[i] != ch);

			if (worker->channel[i] != NULL) continue;

			worker->channel[i] = ch;
			DEBUG3("\t%sreceived channel %p into array entry %d", worker->name, ch, i);

			ms = fr_message_set_create(worker, worker->message_set_size,
						   sizeof(fr_channel_data_t),
						   worker->ring_buffer_size);
			rad_assert(ms != NULL);
			fr_channel_worker_ctx_add(ch, ms);

			worker->num_channels++;
			ok = true;
			break;
		}

		fr_cond_assert(ok);
		break;

	case FR_CHANNEL_CLOSE:
		DEBUG3("\t--> channel close");

		rad_assert(ch != NULL);

		ok = false;
		for (i = 0; i < worker->max_channels; i++) {
			if (!worker->channel[i]) continue;

			if (worker->channel[i] != ch) continue;

			/*
			 *	@todo check the status, and
			 *	put the channel into a
			 *	"closing" list if we can't
			 *	close it right now.  Then,
			 *	wake up after a time and try
			 *	to close it again.
			 */
			(void) fr_channel_worker_ack_close(ch);

			ms = fr_channel_worker_ctx_get(ch);
			rad_assert(ms != NULL);
			fr_message_set_gc(ms);
			talloc_free(ms);

			worker->channel[i] = NULL;
			rad_assert(worker->num_channels > 0);
			worker->num_channels--;
			ok = true;
			break;
		}

		fr_cond_assert(ok);
		break;
	}
}


/** Service a control-plane event.
 *
 * @param[in] kq the kq to service
 * @param[in] kev the kevent to service
 * @param[in] ctx the fr_worker_t
 */
static void fr_worker_evfilt_user(UNUSED int kq, UNUSED struct kevent const *kev, void *ctx)
{
	fr_time_t now;
	fr_worker_t *worker = ctx;
	char data[256];

	talloc_get_type_abort(worker, fr_worker_t);

	now = fr_time();

	/*
	 *	Service all available control-plane events
	 */
	fr_control_service(worker->control, data, sizeof(data), now);
}


/** Send a NAK to the network thread
 *
 *  The network thread believes that a worker is running a request until that request has been NAK'd.
 *
 * @param[in] worker the worker
 * @param[in] cd the message to NAK
 * @param[in] now when the message is NAKd
 */
static void fr_worker_nak(fr_worker_t *worker, fr_channel_data_t *cd, fr_time_t now)
{
	size_t			size;
	fr_channel_data_t	*reply;
	fr_channel_t		*ch;
	fr_message_set_t	*ms;
	fr_listen_t		*listen;

	worker->num_timeouts++;

	/*
	 *	Cache the outbound channel.  We'll need it later.
	 */
	ch = cd->channel.ch;
	listen = cd->listen;

	ms = fr_channel_worker_ctx_get(ch);
	rad_assert(ms != NULL);

	size = listen->app_io->default_reply_size;
	if (!size) size = listen->app_io->default_message_size;

	/*
	 *	Allocate a default message size.
	 */
	reply = (fr_channel_data_t *) fr_message_reserve(ms, size);
	rad_assert(reply != NULL);

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
	reply->reply.cpu_time = worker->tracking.running;
	reply->reply.processing_time = 10; /* @todo - set to something better? */
	reply->reply.request_time = cd->m.when;

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
		DEBUG2("\t%sfails sending reply to channel", worker->name);
	}

	worker->stats.out++;
}

static void worker_reset_timer(fr_worker_t *worker);


/** Reply to a request
 *
 *  And clean it up.
 *
 * @param[in] worker the worker
 * @param[in] request the request to process
 * @param[in] size maximum size of the reply data
 */
static void fr_worker_send_reply(fr_worker_t *worker, REQUEST *request, size_t size)
{
	fr_channel_data_t *reply;
	fr_channel_t *ch;
	fr_message_set_t *ms;
	fr_time_t now;

	REQUEST_VERIFY(request);

	/*
	 *	If we're sending a reply, then it's no longer runnable.
	 */
	rad_assert(request->runnable_id < 0);

	now = fr_time();

	/*
	 *	If it's a fake request, don't send a real reply.
	 *	Just toss the request.
	 */
	if (request->async->fake) {
		fr_time_tracking_end(&request->async->tracking, now, &worker->tracking);
		goto finished;
	}

	/*
	 *	Allocate and send the reply.
	 */
	ch = request->async->channel;
	rad_assert(ch != NULL);

	ms = fr_channel_worker_ctx_get(ch);
	rad_assert(ms != NULL);

	reply = (fr_channel_data_t *) fr_message_reserve(ms, size);
	rad_assert(reply != NULL);

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
			DEBUG2("\t%sfails encode", worker->name);
			*reply->m.data = 0;
			slen = 1;
		}

		/*
		 *	Shrink the buffer to the actual packet size.
		 *
		 *	This will ALWAYS return the same message as we put in.
		 */
		rad_assert((size_t) slen <= reply->m.rb_size);
		(void) fr_message_alloc(ms, &reply->m, slen);
	}

	/*
	 *	The request is done.  Track that.
	 */
	fr_time_tracking_end(&request->async->tracking, now, &worker->tracking);
	rad_assert(worker->num_active > 0);
	worker->num_active--;

	/*
	 *	Nothing to do, delete max_request_time timers.
	 */
	if (!worker->num_active) {
		talloc_const_free(worker->ev_cleanup);
		worker->ev_cleanup = NULL;
	}

	/*
	 *	Fill in the rest of the fields in the channel message.
	 *
	 *	sequence / ack will be filled in by fr_channel_send_reply()
	 */
	reply->m.when = request->async->tracking.when;
	reply->reply.cpu_time = worker->tracking.running;
	reply->reply.processing_time = request->async->tracking.running;
	reply->reply.request_time = request->async->recv_time;

	reply->listen = request->async->listen;
	reply->packet_ctx = request->async->packet_ctx;

	/*
	 *	Update the various timers.
	 */
	fr_time_elapsed_update(&worker->cpu_time, now, now + reply->reply.processing_time);
	fr_time_elapsed_update(&worker->wall_clock, reply->reply.request_time, now);

	RDEBUG("finished request.");

	/*
	 *	Send the reply, which also polls the request queue.
	 */
	if (fr_channel_send_reply(ch, reply) < 0) {
		DEBUG2("\t%sfails sending reply", worker->name);
	}

	worker->stats.out++;

	/*
	 *	@todo Use a talloc pool for the request.  Clean it up,
	 *	and insert it back into a slab allocator.
	 */
	if (request->time_order_id >= 0) (void) fr_heap_extract(worker->time_order, request);
	if (request->runnable_id >= 0) (void) fr_heap_extract(worker->runnable, request);

finished:
	rad_assert(request->time_order_id < 0);
	rad_assert(request->runnable_id < 0);

#ifndef NDEBUG
	request->async->original_recv_time = NULL;
	request->async->el = NULL;
	request->async->process = NULL;
	fr_dlist_remove(&worker->tracking.list, &request->async->tracking);
	request->async->channel = NULL;
	request->async->packet_ctx = NULL;
	request->async->listen = NULL;
#endif

	DEBUG3("freeing request");
	talloc_free(request);
}


/**  Tell a request that it's stopped.
 *
 */
static void worker_stop_request(fr_worker_t *worker, REQUEST *request, fr_time_t now)
{
	fr_time_tracking_resume(&request->async->tracking, now, &worker->tracking);
	unlang_interpret_signal(request, FR_SIGNAL_CANCEL);

	/*
	 *	The request is ALWAYS in the time_order list.  It MAY
	 *	be in the runnable list, but if not, no worries.  It
	 *	MAY be in the dedup list, but if not, no worries.
	 */
	if (request->time_order_id >= 0) (void) fr_heap_extract(worker->time_order, request);
	if (request->runnable_id >= 0) (void) fr_heap_extract(worker->runnable, request);
	(void) rbtree_deletebydata(worker->dedup, request);

#ifndef NDEBUG
	request->async->process = NULL;
#endif
}

/** Enforce max_request_time
 *
 *  Run periodically, and tries to clean up old requests.  In the
 *  interest of not updating the timer for every packet, the requests
 *  are given a 1 second leeway.
 *
 * @param[in] el the event list
 * @param[in] when the current time
 * @param[in] uctx the fr_worker_t
 */
static void fr_worker_max_request_time(UNUSED fr_event_list_t *el, UNUSED fr_time_t when, void *uctx)
{
	fr_time_t now = fr_time();
	REQUEST *request;
	fr_worker_t *worker = talloc_get_type_abort(uctx, fr_worker_t);

	DEBUG2("TIMER - worker max_request_time - %" PRIu64 " active requests", worker->num_active);

	/*
	 *	Look at the oldest requests, and see if they need to
	 *	be deleted.
	 */
	while ((request = fr_heap_peek_tail(worker->time_order)) != NULL) {
		REQUEST_VERIFY(request);

		/*
		 *	Waiting too long, delete it.
		 */
		RDEBUG("request has reached max_request_time - telling it to stop.");
		worker_stop_request(worker, request, now);

		/*
		 *	Tell the network side that this request is done.
		 */
		fr_worker_send_reply(worker, request, 1);
	}

	/*
	 *	There are still active requests.  Reset the timer.
	 */
	if (worker->num_active) worker_reset_timer(worker);
}

/** See when we next need to service the time_order heap for "too old"
 * packets.
 *
 */
static void worker_reset_timer(fr_worker_t *worker)
{
	fr_time_t	cleanup;
	REQUEST		*request;

	request = fr_heap_peek_tail(worker->time_order);
	if (!request) return;
	rad_assert(worker->num_active > 0);

	cleanup = worker->max_request_time;
	cleanup += request->async->recv_time;

	/*
	 *	Suppress the timer update if it's within 1s of the
	 *	previous one.
	 */
	if (worker->ev_cleanup) {
		if ((cleanup > worker->next_cleanup) &&
		    (cleanup - worker->next_cleanup) <= NSEC) return;
	}

	worker->next_cleanup = cleanup;

	DEBUG2("Resetting worker %s cleanup timer to +%pV",
	       worker->name, fr_box_time_delta(worker->max_request_time));
	if (fr_event_timer_at(worker, worker->el, &worker->ev_cleanup,
			      cleanup, fr_worker_max_request_time, worker) < 0) {
		ERROR("Failed inserting max_request_time timer.");
	}
}


/** Check timeouts on the various queues
 *
 *  This function checks and enforces timeouts on the multiple worker
 *  queues.  The high priority events can starve low priority ones.
 *  When that happens, the low priority events will be in the queues for
 *  "too long", and will need to be cleaned up.
 *
 * @param[in] worker the worker
 * @param[in] now the current time
 */
static void fr_worker_check_timeouts(fr_worker_t *worker, fr_time_t now)
{
	fr_channel_data_t	*cd;
	fr_time_t		waiting;

	/*
	 *	Check the "localized" queue for old packets.
	 *
	 *	We check it before the "to_decode" list, so that we
	 *	don't check packets twice.
	 */
	while ((cd = fr_dlist_tail(&worker->localized.list)) != NULL) {
		waiting = now - cd->m.when;

		if (waiting < (worker->max_request_time - fr_time_delta_from_sec(2))) break;

		/*
		 *	Waiting too long, delete it.
		 */
		WORKER_HEAP_EXTRACT(localized, cd);
		DEBUG3("TIMEOUT: Extracting packet from localized list");
		fr_worker_nak(worker, cd, now);
	}

	/*
	 *	Check the "to_decode" queue for old packets.
	 */
	while ((cd = fr_dlist_tail(&worker->to_decode.list)) != NULL) {
		fr_message_t *lm;

		waiting = now - cd->m.when;

		if (waiting < (NSEC / 100)) break;

		/*
		 *	Waiting too long, delete it.
		 */
		if (waiting > NSEC) {
			WORKER_HEAP_EXTRACT(to_decode, cd);
			DEBUG3("TIMEOUT: Extracting packet from to_decode list");

		nak:
			fr_worker_nak(worker, cd, now);
			continue;
		}

		/*
		 *	0.01 to 1s.  Localize it.
		 */
		WORKER_HEAP_EXTRACT(to_decode, cd);
		lm = fr_message_localize(worker, &cd->m, sizeof(*cd));
		if (!lm) {
			DEBUG3("TIMEOUT: Failed localizing message from to_decode list: %s", fr_strerror());
			goto nak;
		}
		cd = (fr_channel_data_t *) lm;

		WORKER_HEAP_INSERT(localized, cd);
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
	bool			is_dup;
	int			ret = -1;
	fr_channel_data_t	*cd;
	REQUEST			*request;
	fr_listen_t const	*listen;
	TALLOC_CTX		*ctx;

	/*
	 *	Grab a runnable request, and resume it.
	 */
	request = fr_heap_pop(worker->runnable);
	if (request) {
		DEBUG3("%s found runnable request", worker->name);
		REQUEST_VERIFY(request);
		rad_assert(request->runnable_id < 0);
		fr_time_tracking_resume(&request->async->tracking, now, &worker->tracking);
		return request;
	}

	/*
	 *	Find either a localized message, or one which is in
	 *	the "to_decode" queue.
	 */
	do {
		WORKER_HEAP_POP(localized, cd);
		if (!cd) {
			WORKER_HEAP_POP(to_decode, cd);
		}
		if (!cd) {
			DEBUG3("%s localized and decode lists are empty", worker->name);
			return NULL;
		}

		DEBUG3("%s found request to decode", worker->name);
		worker->num_decoded++;
	} while (!cd);

	ctx = request = request_alloc(NULL);
	if (!request) goto nak;

	request->el = worker->el;
	request->backlog = worker->runnable;
	MEM(request->packet = fr_radius_alloc(request, false));
	request->packet->timestamp = *cd->request.recv_time; /* Legacy - Remove once everything looks at request->async */
	request->reply = fr_radius_alloc(request, false);
	rad_assert(request->reply != NULL);

	request->async = talloc_zero(request, fr_async_t);
	request->server_cs = cd->listen->server_cs;

	/*
	 *	Receive a message to the worker queue, and decode it
	 *	to a request.
	 */
	rad_assert(cd->listen != NULL);

	/*
	 *	Update the transport-specific fields.
	 *
	 *	Note that the message "when" time MUST be copied from
	 *	the original recv time.  We use "when" here, instead
	 *	of *cd->request.recv_time, on the odd chance that a
	 *	new packet arrived while we were getting around to
	 *	processing this message.
	 */
	request->async->channel = cd->channel.ch;

	request->async->original_recv_time = cd->request.recv_time;
	request->async->recv_time = *request->async->original_recv_time;
	request->async->el = worker->el;
	request->number = worker->number++;
	request->name = talloc_typed_asprintf(request, "%" PRIu64 , request->number);

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
		fr_worker_nak(worker, cd, now);
		return NULL;
	}

	/*
	 *	Call the main protocol handler to set the right async
	 *	process function.
	 */
	listen->app->entry_point_set(listen->app_instance, request);

	if (!request->async->process) {
		RERROR("Protocol failed to set 'process' function");
		fr_worker_nak(worker, cd, now);
		return NULL;
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
	if (request->async->listen->app_io->track_duplicates) {
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
				return NULL;
			}
			goto insert_new;
		}

		rad_assert(old->async->listen == request->async->listen);
		rad_assert(old->async->channel == request->async->channel);

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
			return NULL;
		}

		/*
		 *	Stop the old request, and decrement the number
		 *	of active requests.
		 */
		RWARN("Got conflicting packet for request (%" PRIu64 "), telling old request to stop", old->number);

		worker_stop_request(worker, old, now);
		rad_assert(worker->num_active > 0);
		worker->num_active--;
		worker->stats.dropped++;
		talloc_free(old);

	insert_new:
		(void) rbtree_insert(worker->dedup, request);
	}

	/*
	 *	New requests are inserted into the time order heap in
	 *	strict time priority.  Once they are in the list, they
	 *	are only removed when the request is done / free'd.
	 */
	rad_assert(request->time_order_id < 0);
	(void) fr_heap_insert(worker->time_order, request);

	/*
	 *	Bootstrap the async state machine with the initial
	 *	state of the request.
	 */
	fr_time_tracking_start(&request->async->tracking, now, &worker->tracking);
	worker->num_active++;
	rad_assert(request->runnable_id < 0);

	worker_reset_timer(worker);
	return request;
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
	ssize_t size = 0;
	rlm_rcode_t final;

	WORKER_VERIFY;

	rad_assert(request->parent == NULL);
	rad_assert(request->async->process != NULL);
	rad_assert(request->async->listen != NULL);
	rad_assert(request->runnable_id < 0); /* removed from the runnable heap */

	RDEBUG("running request");

	/*
	 *	If we still have the same packet, and the channel is
	 *	active, run it.  Otherwise, tell it that it's done.
	 */
	if ((*request->async->original_recv_time == request->async->recv_time) &&
	    (request->async->fake ||
	     fr_channel_active(request->async->channel))) {
		final = request->async->process(request->async->process_inst, request);

	} else {
		unlang_interpret_signal(request, FR_SIGNAL_CANCEL);
		final = RLM_MODULE_HANDLED;
	}

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
		fr_time_tracking_yield(&request->async->tracking, fr_time(), &worker->tracking);
		return;

	case RLM_MODULE_OK:
		/*
		 *	Don't reply to internally generated request.
		 */
		if (request->parent) break;

		size = request->async->listen->app_io->default_reply_size;
		if (!size) size = request->async->listen->app_io->default_message_size;
		break;
	}

	RDEBUG("done request");

	/*
	 *	Only real packets are in the dedup tree.  And even
	 *	then, only some of the time.
	 */
	if (!request->async->fake && request->async->listen->app_io->track_duplicates) {
		(void) rbtree_deletebydata(worker->dedup, request);
	}

	fr_worker_send_reply(worker, request, size);
	if (!worker->num_active) worker_reset_timer(worker);
}

/** Run the event loop 'pre' callback
 *
 *  This function MUST DO NO WORK.  All it does is check if there's
 *  work, and tell the event code to return to the main loop if
 *  there's work to do.
 *
 * @param[in] ctx the worker
 * @param[in] wake the time when the event loop will wake up.
 */
static int fr_worker_pre_event(void *ctx, fr_time_t wake)
{
	bool sleeping;
	int i;
	fr_worker_t *worker = ctx;

	WORKER_VERIFY;

	/*
	 *	See if we need to sleep, because if there's nothing
	 *	more to do, we need to tell the other end of the
	 *	channels that we're sleeping.
	 */
	sleeping = (fr_heap_num_elements(worker->runnable) == 0);
	if (sleeping) sleeping = (fr_heap_num_elements(worker->localized.heap) == 0);
	if (sleeping) sleeping = (fr_heap_num_elements(worker->to_decode.heap) == 0);

	/*
	 *	Tell the event loop that there is new work to do.  We
	 *	don't want to wait for events, but instead check them,
	 *	and start processing packets immediately.
	 */
	if (!sleeping) {
		worker->was_sleeping = false;
		return 1;
	}

	/*
	 *	The application is polling the event loop, but has
	 *	other work to do.  Don't do anything special here, as
	 *	we will get called again on the next round of the
	 *	event loop.
	 */
	if (wake) return 0;

	DEBUG3("\t%s sleeping running %u, localized %u, to_decode %u",
	       worker->name,
	       fr_heap_num_elements(worker->runnable),
	       fr_heap_num_elements(worker->localized.heap),
	       fr_heap_num_elements(worker->to_decode.heap));
	DEBUG3("\t%s requests %" PRIu64 ", decoded %" PRIu64 ", replied %" PRIu64 " active %" PRIu64 "",
	       worker->name, worker->stats.in, worker->num_decoded,
	       worker->stats.out, worker->num_active);

	/*
	 *	We were sleeping, don't send another signal that we
	 *	are still sleeping.
	 */
	if (worker->was_sleeping) {
		DEBUG3("%s was sleeping, not re-signaling", worker->name);
		return 0;
	}

	/*
	 *	Nothing more to do, and the event loop has us sleeping
	 *	for a period of time.  Signal the producers that we're
	 *	sleeping.  The fr_channel_worker_sleeping() function
	 *	will take care of skipping the signal if there are no
	 *	outstanding requests for it.
	 */
	for (i = 0; i < worker->max_channels; i++) {
		if (!worker->channel[i]) continue;

		(void) fr_channel_worker_sleeping(worker->channel[i]);
	}
	worker->was_sleeping = true;

	return 0;
}

/**
 *  Track a channel in the "to_decode" or "localized" heap.
 */
static int8_t worker_message_cmp(void const *one, void const *two)
{
	fr_channel_data_t const *a = one, *b = two;
	int ret;

	ret = (a->priority > b->priority) - (a->priority < b->priority);
	if (ret != 0) return ret;

	return (a->m.when > b->m.when) - (a->m.when < b->m.when);
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

/** Destroy a worker.
 *
 *  The input channels are signaled, and local messages are cleaned up.
 *
 * @param[in] worker the worker to destroy.
 */
void fr_worker_destroy(fr_worker_t *worker)
{
//	int i;
	fr_channel_data_t *cd;
	REQUEST *request;
	fr_time_t now = fr_time();

//	WORKER_VERIFY;

	/*
	 *	These messages aren't in the channel, so we have to
	 *	mark them as unused.
	 */
	while (true) {
		WORKER_HEAP_POP(to_decode, cd);
		if (!cd) break;
		fr_message_done(&cd->m);
	}

	while (true) {
		WORKER_HEAP_POP(localized, cd);
		if (!cd) break;
		fr_message_done(&cd->m);
	}

	/*
	 *	Destroy all of the active requests.  These are ones
	 *	which are still waiting for timers or file descriptor
	 *	events.
	 */
	while ((request = fr_heap_peek(worker->time_order)) != NULL) {
		RDEBUG("server is exiting - telling request to stop.");
		worker_stop_request(worker, request, now);
		talloc_free(request);
	}
	rad_assert(fr_heap_num_elements(worker->runnable) == 0);

#if 0
	/*
	 *	Signal the channels that we're closing.
	 *
	 *	The other end owns the channel, and will take care of
	 *	popping messages in the TO_WORKER queue, and marking
	 *	them FR_MESSAGE_DONE.  It will ignore the messages in
	 *	the FROM_WORKER queue, as we own those.  They will be
	 *	automatically freed when our talloc context is freed.
	 */
	for (i = 0; i < worker->max_channels; i++) {
		if (!worker->channel[i]) continue;

		fr_channel_worker_ack_close(worker->channel[i]);
	}
#endif

	(void) fr_event_pre_delete(worker->el, fr_worker_pre_event, worker);
	(void) fr_event_post_delete(worker->el, fr_worker_post_event, worker);

	talloc_free(worker);
}


/** Create a worker
 *
 * @param[in] ctx the talloc context
 * @param[in] name the name of this worker
 * @param[in] el the event list
 * @param[in] logger the destination for all logging messages
 * @param[in] lvl log level
 * @return
 *	- NULL on error
 *	- fr_worker_t on success
 */
fr_worker_t *fr_worker_create(TALLOC_CTX *ctx, char const *name, fr_event_list_t *el, fr_log_t const *logger, fr_log_lvl_t lvl)
{
	int max_channels = 64;
	fr_worker_t *worker;

	worker = talloc_zero(ctx, fr_worker_t);
	if (!worker) {
nomem:
		fr_strerror_printf("Failed allocating memory");
		return NULL;
	}

	worker->name = talloc_strdup(worker, name); /* thread locality */

	worker->channel = talloc_zero_array(worker, fr_channel_t *, max_channels);
	if (!worker->channel) {
		talloc_free(worker);
		goto nomem;
	}

	worker->id = pthread_self();
	worker->el = el;
	worker->log = logger;
	worker->lvl = lvl;

	/*
	 *	@todo make these configurable
	 */
	worker->max_channels = max_channels;
	worker->talloc_pool_size = 4096; /* at least enough for a REQUEST */
	worker->message_set_size = 1024;
	worker->ring_buffer_size = (1 << 16);
	worker->max_request_time = fr_time_delta_from_sec(30);

	if (fr_event_pre_insert(worker->el, fr_worker_pre_event, worker) < 0) {
		fr_strerror_printf("Failed adding pre-check to event list");
		talloc_free(worker);
		return NULL;
	}

	/*
	 *	The worker thread starts now.  Manually initialize it,
	 *	because we're tracking request time, not the time that
	 *	the worker thread is running.
	 */
	memset(&worker->tracking, 0, sizeof(worker->tracking));
	fr_dlist_init(&worker->tracking.list, fr_time_tracking_t, list.entry);

	worker->kq = fr_event_list_kq(worker->el);
	rad_assert(worker->kq >= 0);

	worker->aq_control = fr_atomic_queue_create(worker, 1024);
	if (!worker->aq_control) {
		fr_strerror_printf("Failed creating atomic queue");
	fail:
		talloc_free(worker);
		return NULL;
	}

	worker->aq_ident = fr_event_user_insert(worker->el, fr_worker_evfilt_user, worker);
	if (!worker->aq_ident) {
		fr_strerror_printf_push("Failed updating event list");
		goto fail;
	}

	worker->control = fr_control_create(worker, worker->kq, worker->aq_control, worker->aq_ident);
	if (!worker->control) {
		fr_strerror_printf_push("Failed creating control plane");
	fail2:
		(void) fr_event_user_delete(worker->el, fr_worker_evfilt_user, worker);
		goto fail;
	}

	if (fr_control_callback_add(worker->control, FR_CONTROL_ID_CHANNEL, worker, fr_worker_channel_callback) < 0) {
		fr_strerror_printf_push("Failed adding control channel");
		goto fail2;
	}

	WORKER_HEAP_INIT(to_decode, worker_message_cmp);
	WORKER_HEAP_INIT(localized, worker_message_cmp);

	worker->runnable = fr_heap_talloc_create(worker, worker_runnable_cmp, REQUEST, runnable_id);
	if (!worker->runnable) {
		fr_strerror_printf("Failed creating runnable heap");
		goto fail;
	}

	worker->time_order = fr_heap_talloc_create(worker, worker_time_order_cmp, REQUEST, time_order_id);
	if (!worker->time_order) {
		fr_strerror_printf("Failed creating time_order heap");
		goto fail;
	}

	worker->dedup = rbtree_talloc_create(worker, worker_dedup_cmp, REQUEST, NULL, RBTREE_FLAG_NONE);
	if (!worker->dedup) {
		fr_strerror_printf("Failed creating de_dup tree");
		goto fail;
	}

	if (fr_event_post_insert(worker->el, fr_worker_post_event, worker) < 0) {
		fr_strerror_printf("Failed inserting post-processing event");
		talloc_free(worker->runnable);
		goto fail2;
	}

	return worker;
}

/** Get the KQ for the worker
 *
 * @param[in] worker the worker data structure
 * @return kq
 */
int fr_worker_kq(fr_worker_t *worker)
{
	WORKER_VERIFY;

	return worker->kq;
}

/** Get the event loop for the worker
 *
 * @param[in] worker the worker data structure
 * @return kq
 */
fr_event_list_t *fr_worker_el(fr_worker_t *worker)
{
	WORKER_VERIFY;

	return worker->el;
}


/** Signal a worker to exit
 *
 *  WARNING: This may be called from another thread!  Care is required.
 *
 * @param[in] worker the worker data structure to manage
 */
void fr_worker_exit(fr_worker_t *worker)
{
	worker->exiting = true;

	fr_event_loop_exit(worker->el, 1);
}


static void fr_worker_post_event(UNUSED fr_event_list_t *el, UNUSED fr_time_t when, void *uctx)
{
	fr_time_t now;
	REQUEST *request;
	fr_worker_t *worker = uctx;

	WORKER_VERIFY;

	now = fr_time();

	/*
	 *      Ten times a second, check for timeouts on incoming packets.
	 *
	 *	@todo - change this to a timer, based on a new field,
	 *	request->async->cleanup_time.  Then round that UP to
	 *	the next nearest second (or 1/10s) so that the
	 *	cleanups are done periodically.
	 */
	if ((now - worker->checked_timeout) > (NSEC / 10)) {
		DEBUG3("\t%s checking timeouts", worker->name);
		fr_worker_check_timeouts(worker, now);
	}

	/*
	 *	Get a runnable request.  If there isn't one, continue.
	 *
	 *	@todo - check for multiple requests, and go process
	 *	many, so long as we haven't ignored the network side
	 *	for too long.
	 */
	request = fr_worker_get_request(worker, now);
	if (!request) return;

	/*
	 *	Run the request, and either track it as
	 *	yielded, or send a reply.
	 */
	fr_worker_run_request(worker, request);
}


/** The main worker function.
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

		worker->last_event = fr_time();

		/*
		 *	There are runnable requests.  We still service
		 *	the event loop, but we don't wait for events.
		 */
		wait_for_event = (fr_heap_num_elements(worker->runnable) == 0);
		if (wait_for_event) {
			DEBUG2("%s ready to process requests", worker->name);
		}

		/*
		 *	Check the event list.  If there's an error
		 *	(e.g. exit), we stop looping and clean up.
		 */
		num_events = fr_event_corral(worker->el, worker->last_event, wait_for_event);
		DEBUG3("\t%sGot num_events %d", worker->name, num_events);
		if (num_events < 0) {
			if (worker->exiting) return; /* don't complain if we're exiting */

			PERROR("Failed corralling events");
			break;
		}

		/*
		 *	Service outstanding events.
		 */
		if (num_events > 0) {
			DEBUG3("\t%sservicing events", worker->name);
			fr_event_service(worker->el);
		}
	}
}


/** Print debug information about the worker structure
 *
 * @param[in] worker the worker
 * @param[in] fp the file where the debug output is printed.
 */
void fr_worker_debug(fr_worker_t *worker, FILE *fp)
{
	WORKER_VERIFY;

	fprintf(fp, "\tkq = %d\n", worker->kq);
	fprintf(fp, "\tnum_channels = %d\n", worker->num_channels);
	fprintf(fp, "\tstats.in = %" PRIu64 "\n", worker->stats.in);

	fprintf(fp, "\tcalculated (predicted) total CPU time = %" PRIu64 "\n",
		worker->tracking.predicted * worker->stats.in);
	fprintf(fp, "\tcalculated (counted) per request time = %" PRIu64 "\n",
		worker->tracking.running / worker->stats.in);

	fr_time_tracking_debug(&worker->tracking, fp);

}

/** Create a channel to the worker
 *
 *  Called by the master (i.e. network) thread when it needs to create
 *  a new channel to a particuler worker.
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
	same = (pthread_equal(id, worker->id) != 0);

	ch = fr_channel_create(ctx, master, worker->control, same);
	if (!ch) return NULL;

	fr_channel_set_recv_request(ch, worker, fr_worker_recv_request);

	/*
	 *	Tell the worker about the channel
	 */
	if (fr_channel_signal_open(ch) < 0) {
		talloc_free(ch);
		return NULL;
	}

	return ch;
}


/** Set the name of a worker.
 *
 *  Called by the master (i.e. network) thread when it needs to create
 *  a new channel to a particuler worker.
 *
 * @param[in] worker the worker
 * @param[in] name the name to set for the worker. (strdup'd by the worker)
 */
void fr_worker_name(fr_worker_t *worker, char const *name)
{
	WORKER_VERIFY;

	worker->name = talloc_strdup(worker, name);
}


#ifndef NDEBUG
/** Verify the worker data structures.
 *
 * @param[in] worker the worker
 */
static void fr_worker_verify(fr_worker_t *worker)
{
	int i;

	(void) talloc_get_type_abort(worker, fr_worker_t);
	(void) talloc_get_type_abort(worker->aq_control, fr_atomic_queue_t);

	rad_assert(worker->control != NULL);
	(void) talloc_get_type_abort(worker->control, fr_control_t);

	rad_assert(worker->el != NULL);
	(void) talloc_get_type_abort(worker->el, fr_event_list_t);

	rad_assert(worker->to_decode.heap != NULL);
	(void) talloc_get_type_abort(worker->to_decode.heap, fr_heap_t);

	rad_assert(worker->localized.heap != NULL);
	(void) talloc_get_type_abort(worker->localized.heap, fr_heap_t);

	rad_assert(worker->runnable != NULL);
	(void) talloc_get_type_abort(worker->runnable, fr_heap_t);

	rad_assert(worker->dedup != NULL);
	(void) talloc_get_type_abort(worker->dedup, rbtree_t);

	for (i = 0; i < worker->max_channels; i++) {
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
	if (num >= 5) stats[4] = worker->num_decoded;
	if (num >= 6) stats[5] = worker->num_timeouts;
	if (num >= 7) stats[6] = worker->num_active;

	if (num <= 7) return num;

	return 7;
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
		fprintf(fp, "count.decoded\t\t\t%" PRIu64 "\n", worker->num_decoded);
		fprintf(fp, "count.timeouts\t\t\t%" PRIu64 "\n", worker->num_timeouts);
		fprintf(fp, "count.active\t\t\t%" PRIu64 "\n", worker->num_active);
		fprintf(fp, "count.runnable\t\t\t%u\n", fr_heap_num_elements(worker->runnable));
	}

	if ((info->argc == 0) || (strcmp(info->argv[0], "cpu") == 0)) {
		when = worker->tracking.predicted;
		fprintf(fp, "cpu.average_request_time\t%u.%03u\n", (unsigned int) (when / NSEC), (unsigned int) (when % NSEC) / 1000000);

		when = worker->tracking.running;
		fprintf(fp, "cpu.used\t\t\t%u.%03u\n", (unsigned int) (when / NSEC), (unsigned int) (when % NSEC) / 1000000);

		when = worker->tracking.waiting;
		fprintf(fp, "cpu.waiting\t\t\t%u.%03u\n", (unsigned int) (when / NSEC), (unsigned int) (when % NSEC) / 1000000);

		when = fr_time() - worker->last_event;
		fprintf(fp, "cpu.event_loop_serviced\t\t-%u.%03u\n", (unsigned int) (when / NSEC), (unsigned int) (when % NSEC) / 1000000);

		fr_time_elapsed_fprint(fp, &worker->cpu_time, "cpu.requests", 1);
		fr_time_elapsed_fprint(fp, &worker->wall_clock, "time.requests", 1);
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
