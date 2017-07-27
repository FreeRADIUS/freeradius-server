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
 *  also into the head of the "time_order" linked list. The main loop
 *  fr_worker() then pulls requests off of this heap and runs them.
 *  The fr_worker_check_timeouts() function also checks the tail of
 *  the "time_order" list, and ages out requests which have been
 *  running for "too long".
 *
 *  A request may return one of FR_IO_YIELD,
 *  FR_IO_REPLY, or FR_IO_DONE.  If a request is
 *  yeilded, it is placed onto the yielded list in the worker
 *  "tracking" data structure.
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/io/worker.h>
#include <freeradius-devel/io/channel.h>
#include <freeradius-devel/io/message.h>
#include <freeradius-devel/io/listen.h>

/**
 *  Track things by priority and time.
 */
typedef struct fr_worker_heap_t {
	fr_dlist_t	list;			//!< list of things, ordered by time.
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

	uint32_t		flags;		//!< various debugging options, etc.

	int			kq;		//!< my kq

	fr_log_t const		*log;		//!< log destination

	fr_atomic_queue_t	*aq_control;	//!< atomic queue for control messages sent to me

	uintptr_t		aq_ident;	//!< identifier for control-plane events

	fr_control_t		*control;	//!< the control plane

	fr_event_list_t		*el;		//!< our event list

	uint64_t		number;		//!< for requests

	int			num_channels;	//!< actual number of channels
	int			max_channels;	//!< maximum number of channels

	int                     message_set_size; //!< default start number of messages
	int                     ring_buffer_size; //!< default start size for the ring buffers

	size_t			talloc_pool_size; //!< for each REQUEST

	fr_time_t		checked_timeout; //!< when we last checked the tails of the queues

	fr_worker_heap_t	to_decode;	//!< messages from the master, to be decoded or localized
	fr_worker_heap_t       	localized;	//!< localized messages to be decoded

	fr_heap_t      		*runnable;	//!< current runnable requests which we've spent time processing
	fr_dlist_t		time_order;	//!< time order of requests

	int			num_requests;	//!< number of requests processed by this worker
	int			num_decoded;	//!< number of messages which have been decoded
	int			num_replies;	//!< number of messages which were replied to
	int			num_timeouts;	//!< number of messages which timed out
	int			num_active;	//!< number of active requests

	fr_time_tracking_t	tracking;	//!< how much time the worker has spent doing things.

	bool			was_sleeping;	//!< used to suppress multiple sleep signals in a row
	bool			exiting;	//!< are we exiting?

	fr_time_t		next_cleanup;	//!< when we next do the max_request_time checks
	fr_event_timer_t const	*ev_cleanup;	//!< timer for max_request_time

	fr_channel_t		**channel;	//!< list of channels
};

static void fr_worker_post_event(fr_event_list_t *el, struct timeval *now, void *uctx);

/*
 *	We need wrapper macros because we have multiple instances of
 *	the same code.
 */
#define WORKER_HEAP_INIT(_name, _func, _type, _member) do { \
		FR_DLIST_INIT(worker->_name.list); \
		worker->_name.heap = fr_heap_create(_func, offsetof(_type, _member)); \
		if (!worker->_name.heap) { \
			(void) fr_event_user_delete(worker->el, fr_worker_evfilt_user, worker); \
			talloc_free(worker); \
			goto nomem; \
		} \
	} while (0)

#define WORKER_HEAP_INSERT(_name, _var, _member) do { \
		fr_dlist_insert_head(&worker->_name.list, &_var->_member); \
		(void) fr_heap_insert(worker->_name.heap, _var);        \
	} while (0)

#define WORKER_HEAP_POP(_name, _var, _member) do { \
		_var = fr_heap_pop(worker->_name.heap); \
		if (_var) fr_dlist_remove(&_var->_member); \
	} while (0)

#define WORKER_HEAP_EXTRACT(_name, _var, _member) do { \
               (void) fr_heap_extract(worker->_name.heap, _var); \
               fr_dlist_remove(&_var->_member);			 \
       } while (0)


/** Drain the input channel
 *
 * @param[in] worker the worker
 * @param[in] ch the channel to drain
 * @param[in] cd the message (if any) to start with
 */
static void fr_worker_drain_input(fr_worker_t *worker, fr_channel_t *ch, fr_channel_data_t *cd)
{
	if (!cd) {
		cd = fr_channel_recv_request(ch);
		if (!cd) {
			fr_log(worker->log, L_DBG, "\t%sno data?", worker->name);
			return;
		}
	}

	do {
		worker->num_requests++;
		fr_log(worker->log, L_DBG, "\t%sreceived request %d", worker->name, worker->num_requests);
		cd->channel.ch = ch;
		WORKER_HEAP_INSERT(to_decode, cd, request.list);
	} while ((cd = fr_channel_recv_request(ch)) != NULL);
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
	bool ok;
	fr_channel_t *ch;
	fr_message_set_t *ms;
	fr_channel_event_t ce;
	fr_worker_t *worker = ctx;

	ce = fr_channel_service_message(now, &ch, data, data_size);
	switch (ce) {
	case FR_CHANNEL_ERROR:
		fr_log(worker->log, L_DBG, "\t%saq error", worker->name);
		return;

	case FR_CHANNEL_EMPTY:
		fr_log(worker->log, L_DBG, "\t%saq empty", worker->name);
		return;

	case FR_CHANNEL_NOOP:
		fr_log(worker->log, L_DBG, "\t%saq noop", worker->name);
		return;

	case FR_CHANNEL_DATA_READY_NETWORK:
		rad_assert(0 == 1);
		fr_log(worker->log, L_DBG, "\t%saq data ready ? MASTER ?", worker->name);
		break;

	case FR_CHANNEL_DATA_READY_WORKER:
		rad_assert(ch != NULL);
		fr_log(worker->log, L_DBG, "\t%saq data ready", worker->name);
		fr_worker_drain_input(worker, ch, NULL);
		break;

	case FR_CHANNEL_OPEN:
		fr_log(worker->log, L_DBG, "\t%saq channel open", worker->name);

		rad_assert(ch != NULL);

		ok = false;
		for (i = 0; i < worker->max_channels; i++) {
			rad_assert(worker->channel[i] != ch);

			if (worker->channel[i] != NULL) continue;

			worker->channel[i] = ch;
			fr_log(worker->log, L_DBG, "\t%sreceived channel %p into array entry %d", worker->name, ch, i);

			ms = fr_message_set_create(worker, worker->message_set_size,
						   sizeof(fr_channel_data_t),
						   worker->ring_buffer_size);
			rad_assert(ms != NULL);
			fr_channel_worker_ctx_add(ch, ms);

			worker->num_channels++;
			ok = true;
			break;
		}

		rad_cond_assert(ok);
		break;

	case FR_CHANNEL_CLOSE:
		fr_log(worker->log, L_DBG, "\t%saq channel close", worker->name);

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

		rad_cond_assert(ok);
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
	fr_listen_t const	*listen;

	worker->num_timeouts++;

	/*
	 *	Cache the outbound channel.  We'll need it later.
	 */
	ch = cd->channel.ch;
	listen = cd->listen;

	ms = fr_channel_worker_ctx_get(ch);
	rad_assert(ms != NULL);

	/*
	 *	Allocate a default message size.
	 */
	reply = (fr_channel_data_t *) fr_message_reserve(ms, listen->app_io->default_message_size);
	rad_assert(reply != NULL);

	/*
	 *	Encode a NAK
	 */
	size = listen->app_io->nak(listen->app_io_instance, cd->m.data,
				   cd->m.data_size, reply->m.data, reply->m.rb_size);

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
	if (fr_channel_send_reply(ch, reply, &cd) < 0) {
		fr_log(worker->log, L_DBG, "\t%sfails sending reply", worker->name);
		cd = NULL;
	}

	worker->num_replies++;

	if (cd) fr_worker_drain_input(worker, ch, cd);
}


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
	fr_channel_data_t *reply, *cd;
	fr_channel_t *ch;
	fr_message_set_t *ms;

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
			fr_log(worker->log, L_DBG, "\t%sfails encode", worker->name);
			slen = 0;
		}

		/*
		 *	Resize the buffer to the actual packet size.
		 */
		cd = (fr_channel_data_t *) fr_message_alloc(ms, &reply->m, slen);
		rad_assert(cd == reply);
	}

	/*
	 *	The request is done.  Track that.
	 */
	fr_time_tracking_end(&request->async->tracking, fr_time(), &worker->tracking);
	rad_assert(worker->num_active > 0);
	worker->num_active--;

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

	fr_log(worker->log, L_DBG, "(%"PRIu64") finished, sending reply", request->number);

	/*
	 *	Send the reply, which also polls the request queue.
	 */
	if (fr_channel_send_reply(ch, reply, &cd) < 0) {
		fr_log(worker->log, L_DBG, "\t%sfails sending reply", worker->name);
		cd = NULL;
	}

	worker->num_replies++;

	/*
	 *	Drain the incoming TO_WORKER queue.  We do this every
	 *	time we're done processing a request.
	 */
	if (cd) fr_worker_drain_input(worker, ch, cd);

	/*
	 *	@todo Use a talloc pool for the request.  Clean it up,
	 *	and insert it back into a slab allocator.
	 */
	fr_dlist_remove(&request->async->time_order);
	talloc_free(request);
}

static void worker_reset_timer(fr_worker_t *worker);

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
static void fr_worker_max_request_time(UNUSED fr_event_list_t *el, UNUSED struct timeval *when, void *uctx)
{
	fr_time_t waiting;
	fr_dlist_t *entry;
	fr_time_t now = fr_time();
	fr_worker_t *worker = talloc_get_type_abort(uctx, fr_worker_t);

	/*
	 *	Look at the oldest requests, and see if they need to
	 *	be deleted.
	 */
	while ((entry = FR_DLIST_TAIL(worker->time_order)) != NULL) {
		REQUEST *request;
		fr_async_t *async;

		async = fr_ptr_to_type(fr_async_t, time_order, entry);
		request = talloc_parent(async);
		waiting = now - request->async->recv_time;

		if (waiting < NANOSEC) break;

		/*
		 *	Waiting too long, delete it.
		 */
		fr_dlist_remove(&request->async->time_order);
		(void) fr_heap_extract(worker->runnable, request);
		fr_time_tracking_resume(&request->async->tracking, now);

		fr_log(worker->log, L_DBG, "(%"PRIu64") taking too long, stopping it", request->number);
		(void) request->async->process(request, FR_IO_ACTION_DONE);

		/*
		 *	Tell the network side that this request is done.
		 */
		fr_worker_send_reply(worker, request, 0);
	}

	worker_reset_timer(worker);
}

static void worker_reset_timer(fr_worker_t *worker)
{
	struct timeval when;
	fr_time_t cleanup;
	fr_dlist_t *entry;
	fr_async_t *async;

	entry = FR_DLIST_TAIL(worker->time_order);
	if (!entry) {
		if (worker->ev_cleanup) fr_event_timer_delete(worker->el, &worker->ev_cleanup);
		worker->next_cleanup = 0;
		return;
	}

	async = fr_ptr_to_type(fr_async_t, time_order, entry);

	cleanup = 30;
	cleanup *= NANOSEC;
	cleanup += async->recv_time;
	fr_time_to_timeval(&when, cleanup);

	/*
	 *	Suppress the timer update if it's within 1s of the
	 *	previous one.
	 */
	if (worker->ev_cleanup) {
		rad_assert(cleanup >= worker->next_cleanup);
		if ((cleanup - worker->next_cleanup) <= NANOSEC) return;
	}

	worker->next_cleanup = cleanup;
	fr_time_to_timeval(&when, cleanup);

	if (fr_event_timer_insert(worker, worker->el, &worker->ev_cleanup,
				  &when, fr_worker_max_request_time, worker) < 0) {
		fr_log(worker->log, L_ERR, "Failed inserting max_request_time timer.");
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
	fr_dlist_t *entry;
	fr_time_t waiting;

	/*
	 *	Check the "localized" queue for old packets.
	 *
	 *	We check it before the "to_decode" list, so that we
	 *	don't check packets twice.
	 */
	while ((entry = FR_DLIST_TAIL(worker->localized.list)) != NULL) {
		fr_channel_data_t *cd;

		cd = fr_ptr_to_type(fr_channel_data_t, request.list, entry);
		waiting = now - cd->m.when;

		if (waiting < NANOSEC) break;

		/*
		 *	Waiting too long, delete it.
		 */
		WORKER_HEAP_EXTRACT(localized, cd, request.list);
		fr_worker_nak(worker, cd, now);
	}

	/*
	 *	Check the "to_decode" queue for old packets.
	 */
	while ((entry = FR_DLIST_TAIL(worker->to_decode.list)) != NULL) {
		fr_message_t *lm;
		fr_channel_data_t *cd;

		cd = fr_ptr_to_type(fr_channel_data_t, request.list, entry);
		waiting = now - cd->m.when;

		if (waiting < (NANOSEC / 100)) break;

		/*
		 *	Waiting too long, delete it.
		 */
		if (waiting > NANOSEC) {
			WORKER_HEAP_EXTRACT(to_decode, cd, request.list);
		nak:
			fr_worker_nak(worker, cd, now);
			continue;
		}

		/*
		 *	0.01 to 1s.  Localize it.
		 */
		WORKER_HEAP_EXTRACT(to_decode, cd, request.list);
		lm = fr_message_localize(worker, &cd->m, sizeof(cd->m));
		if (!lm) goto nak;

		WORKER_HEAP_INSERT(localized, cd, request.list);
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
	int			ret = -1;
	fr_channel_data_t	*cd;
	REQUEST			*request;
	fr_dlist_t		*entry;
	fr_listen_t const	*listen;
#ifndef HAVE_TALLOC_POOLED_OBJECT
	TALLOC_CTX		*ctx;
#endif

	/*
	 *	Grab a runnable request, and resume it.
	 */
	request = fr_heap_pop(worker->runnable);
	if (request) {
		VERIFY_REQUEST(request);
		fr_time_tracking_resume(&request->async->tracking, now);
		return request;
	}

	/*
	 *	Find either a localized message, or one which is in
	 *	the "to_decode" queue.
	 */
	do {
		WORKER_HEAP_POP(localized, cd, request.list);
		if (!cd) {
			WORKER_HEAP_POP(to_decode, cd, request.list);
		}
		if (!cd) return NULL;

		worker->num_decoded++;

		/*
		 *	This message has asynchronously aged out while it was
		 *	in the queue.  Delete it, and go get another one.
		 */
		if (cd->request.recv_time && (cd->m.when != *cd->request.recv_time)) {
			fr_log(worker->log, L_DBG, "\t%sIGNORING old message: was %zd now %zd", worker->name,
				*cd->request.recv_time, cd->m.when);
			fr_worker_nak(worker, cd, fr_time());
			cd = NULL;
		}
	} while (!cd);

	ctx = request = request_alloc(NULL);
	if (!request) goto nak;

	request->el = worker->el;
	request->backlog = worker->runnable;
	request->packet = fr_radius_alloc(request, false);
	rad_assert(request->packet != NULL);
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
	request->async->recv_time = cd->m.when;
	request->async->el = worker->el;
	request->number = worker->number++;

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
		fr_log(worker->log, L_DBG, "\t%sFAILED decode of request %"PRIu64, worker->name, request->number);
		talloc_free(ctx);
nak:
		fr_worker_nak(worker, cd, fr_time());
		return NULL;
	}

	/*
	 *	Call the main protocol handler to set the right async
	 *	process function.
	 */
	listen->app->process_set(listen->app_instance, request);

	if (!request->async->process) {
		fr_log(worker->log, L_DBG, "Protocol failed to set 'process' function");
		fr_worker_nak(worker, cd, fr_time());
		return NULL;
	}

	/*
	 *	Hoist run-time checks here.
	 */
	if (!cd->request.recv_time) request->async->original_recv_time = &request->async->recv_time;

	/*
	 *	We're done with this message.
	 */
	fr_message_done(&cd->m);

	/*
	 *	New requests are inserted into the time order list in
	 *	strict time priority.  Once they are in the list, they
	 *	are only removed when the request is freed.
	 *
	 *	@todo - Right now we're manually ordering the
	 *	list...we should use a priority heap instead.
	 */
	entry = FR_DLIST_FIRST(worker->time_order);
	if (!entry) {
		fr_dlist_insert_head(&worker->time_order, &request->async->time_order);
	} else {
		REQUEST *old;
		fr_dlist_t *prev = &worker->time_order;

		/*
		 *	Requests are orderd by their receive time.
		 *	Requests which are older (i.e. smaller receive
		 *	time) are at the tail of the list.
		 */
		while (entry) {
			fr_async_t *async;

			async = fr_ptr_to_type(fr_async_t, time_order, entry);
			old = talloc_parent(async);

			/*
			 *	If entry is older than the new packet,
			 *	insert the new packet *before* the
			 *	current entry.
			 */
			if (old->async->recv_time < request->async->recv_time) {
				break;
			}

			prev = entry;
			entry = FR_DLIST_NEXT(worker->time_order, entry);
		}

		fr_dlist_insert_head(prev, &request->async->time_order);
	}

	/*
	 *	Bootstrap the async state machine with the initial
	 *	state of the request.
	 */
	fr_time_tracking_start(&request->async->tracking, now);
	worker->num_active++;

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
	fr_io_final_t final;

	WORKER_VERIFY;

	fr_log(worker->log, L_DBG, "\t%s running request (%"PRIu64")", worker->name, request->number);

	/*
	 *	If we still have the same packet, and the channel is
	 *	active, run it.  Otherwise, tell it that it's done.
	 */
	if ((*request->async->original_recv_time == request->async->recv_time) &&
	    fr_channel_active(request->async->channel)) {
		final = request->async->process(request, FR_IO_ACTION_RUN);

	} else {
		final = request->async->process(request, FR_IO_ACTION_DONE);

		rad_assert(final == FR_IO_DONE);
	}

	/*
	 *	Figure out what to do next.
	 */
	switch (final) {
	case FR_IO_DONE:
		/*
		 *	Done: don't send a reply.
		 */
		break;

	case FR_IO_FAIL:
		/*
		 *	Something went wrong.  It's done, but we don't send a reply.
		 */
		break;

	case FR_IO_YIELD:
		fr_time_tracking_yield(&request->async->tracking, fr_time(), &worker->tracking);
		return;

	case FR_IO_REPLY:
		size = request->async->listen->app_io->default_message_size;
		break;
	}

	fr_log(worker->log, L_DBG, "(%"PRIu64") done naturally", request->number);

	fr_worker_send_reply(worker, request, size);
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
static int fr_worker_pre_event(void *ctx, struct timeval *wake)
{
	bool sleeping;
	int i;
	fr_worker_t *worker = ctx;

	WORKER_VERIFY;

	/*
	 *	The application is polling the event loop, but has
	 *	other work to do.  Don't do anything special here, as
	 *	we will get called again on the next round of the
	 *	event loop.
	 */
	if (wake && ((wake->tv_sec == 0) && (wake->tv_usec == 0))) return 0;

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

	fr_log(worker->log, L_DBG, "\t%ssleeping running %zd, localized %zd, to_decode %zd",
	       worker->name,
	       fr_heap_num_elements(worker->runnable),
	       fr_heap_num_elements(worker->localized.heap),
	       fr_heap_num_elements(worker->to_decode.heap));
	fr_log(worker->log, L_DBG, "\t%srequests %d, decoded %d, replied %d active %d",
	       worker->name, worker->num_requests, worker->num_decoded,
	       worker->num_replies, worker->num_active);

	/*
	 *	We were sleeping, don't send another signal that we
	 *	are still sleeping.
	 */
	if (worker->was_sleeping) return 0;

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
static int worker_message_cmp(void const *one, void const *two)
{
	fr_channel_data_t const *a = one, *b = two;
	int ret;

	ret = (a->priority > b->priority) - (a->priority < b->priority);
	if (ret != 0) return ret;

	return (a->m.when > b->m.when) - (a->m.when < b->m.when);
}

/**
 *  Track a REQUEST in the "running" heap.
 */
static int worker_request_cmp(void const *one, void const *two)
{
	REQUEST const *a = one, *b = two;
	int ret;

	ret = (a->async->priority > b->async->priority) - (a->async->priority < b->async->priority);
	if (ret != 0) return ret;

	return (a->async->recv_time > b->async->recv_time) - (a->async->recv_time < b->async->recv_time);
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
	fr_dlist_t *entry;
	REQUEST *request;
	fr_time_t now = fr_time();

//	WORKER_VERIFY;

	/*
	 *	These messages aren't in the channel, so we have to
	 *	mark them as unused.
	 */
	while (true) {
		WORKER_HEAP_POP(to_decode, cd, request.list);
		if (!cd) break;
		fr_message_done(&cd->m);
	}

	while (true) {
		WORKER_HEAP_POP(localized, cd, request.list);
		if (!cd) break;
		fr_message_done(&cd->m);
	}

	/*
	 *	Remove the requests from the "runnable" queue.
	 *
	 *	@todo - set a destructor for the REQUEST which cleans
	 *	it all up.
	 */
	while ((request = fr_heap_pop(worker->runnable)) != NULL) {
		fr_dlist_remove(&request->async->time_order);
		fr_time_tracking_resume(&request->async->tracking, now);
		talloc_free(request);
	}

	/*
	 *	Destroy all of the active requests.  These are ones
	 *	which are still waiting for timers or file descriptor
	 *	events.
	 */
	while ((entry = FR_DLIST_TAIL(worker->time_order)) != NULL) {
		fr_async_t *async;

		async = fr_ptr_to_type(fr_async_t, time_order, entry);
		request = talloc_parent(async);

		(void) request->async->process(request, FR_IO_ACTION_DONE);

		fr_time_tracking_resume(&request->async->tracking, now);
		fr_dlist_remove(&request->async->time_order);
		talloc_free(request);
	}

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
 * @param[in] el the event list
 * @param[in] logger the destination for all logging messages
 * @param[in] flags debug flags
 * @return
 *	- NULL on error
 *	- fr_worker_t on success
 */
fr_worker_t *fr_worker_create(TALLOC_CTX *ctx, fr_event_list_t *el, fr_log_t const *logger, uint32_t flags)
{
	int max_channels = 64;
	fr_worker_t *worker;

	worker = talloc_zero(ctx, fr_worker_t);
	if (!worker) {
nomem:
		fr_strerror_printf("Failed allocating memory");
		return NULL;
	}

	worker->name = "";
	worker->flags = flags;

	worker->channel = talloc_zero_array(worker, fr_channel_t *, max_channels);
	if (!worker->channel) {
		talloc_free(worker);
		goto nomem;
	}

	worker->el = el;
	worker->log = logger;

	/*
	 *	@todo make these configurable
	 */
	worker->max_channels = max_channels;
	worker->talloc_pool_size = 4096; /* at least enough for a REQUEST */
	worker->message_set_size = 1024;
	worker->ring_buffer_size = (1 << 16);

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
	FR_DLIST_INIT(worker->tracking.list);

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
		fr_strerror_printf("Failed updating event list: %s", fr_strerror());
		goto fail;
	}

	worker->control = fr_control_create(worker, worker->kq, worker->aq_control, worker->aq_ident);
	if (!worker->control) {
		fr_strerror_printf("Failed creating control plane: %s", fr_strerror());
	fail2:
		(void) fr_event_user_delete(worker->el, fr_worker_evfilt_user, worker);
		goto fail;
	}

	if (fr_control_callback_add(worker->control, FR_CONTROL_ID_CHANNEL, worker, fr_worker_channel_callback) < 0) {
		fr_strerror_printf("Failed adding control channel: %s", fr_strerror());
		goto fail2;
	}

	WORKER_HEAP_INIT(to_decode, worker_message_cmp, fr_channel_data_t, channel.heap_id);
	WORKER_HEAP_INIT(localized, worker_message_cmp, fr_channel_data_t, channel.heap_id);

	worker->runnable = fr_heap_create(worker_request_cmp, offsetof(REQUEST, heap_id));
	if (!worker->runnable) {
		fr_strerror_printf("Failed creating runnable heap");
		goto fail;
	}
	FR_DLIST_INIT(worker->time_order);

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


static void fr_worker_post_event(UNUSED fr_event_list_t *el, UNUSED struct timeval *when, void *uctx)
{
	fr_time_t now;
	REQUEST *request;
	fr_worker_t *worker = uctx;

	WORKER_VERIFY;

	now = fr_time();

	/*
	 *      Ten times a second, check for timeouts on incoming packets.
	 */
	if ((now - worker->checked_timeout) > (NANOSEC / 10)) {
		fr_log(worker->log, L_DBG, "\t%schecking timeouts", worker->name);
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

	rad_assert(request->async->process != NULL);
	rad_assert(request->async->listen != NULL);

	/*
	 *	Run the request, and either track it as
	 *	yielded, or send a reply.
	 */
	fr_log(worker->log, L_DBG, "\t%srunning request (%"PRIu64")", worker->name, request->number);
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

		/*
		 *	There are runnable requests.  We still service
		 *	the event loop, but we don't wait for events.
		 */
		wait_for_event = (fr_heap_num_elements(worker->runnable) == 0);
		fr_log(worker->log, L_DBG, "\t%sWaiting for events %d", worker->name, wait_for_event);

		/*
		 *	Check the event list.  If there's an error
		 *	(e.g. exit), we stop looping and clean up.
		 */
		num_events = fr_event_corral(worker->el, wait_for_event);
		fr_log(worker->log, L_DBG, "\t%sGot num_events %d", worker->name, num_events);
		if (num_events < 0) {
			if (worker->exiting) break; /* don't complain if we're exiting */

			fr_log(worker->log, L_ERR, "Failed corraling events: %s", fr_strerror());
			break;
		}

		/*
		 *	Service outstanding events.
		 */
		if (num_events > 0) {
			fr_log(worker->log, L_DBG, "\t%sservicing events", worker->name);
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
	fprintf(fp, "\tnum_requests = %d\n", worker->num_requests);

	fprintf(fp, "\tcalculated (predicted) total CPU time = %zd\n", worker->tracking.predicted * worker->num_requests);
	fprintf(fp, "\tcalculated (counted) per request time = %zd\n", worker->tracking.running / worker->num_requests);

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

	WORKER_VERIFY;

	ch = fr_channel_create(ctx, master, worker->control);
	if (!ch) return NULL;

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

	for (i = 0; i < worker->max_channels; i++) {
		if (!worker->channel[i]) continue;

		(void) talloc_get_type_abort(worker->channel[i], fr_channel_t);
	}
}
#endif
