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
 *  scheduler, and create a KQ and control-plane AQ for control-plane
 *  communication.
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
 *  A request may return one of FR_TRANSPORT_YIELD,
 *  FR_TRANSPORT_REPLY, or FR_TRANSPORT_DONE.  If a request is
 *  yeilded, it is placed onto the yielded list in the worker
 *  "tracking" data structure.
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/io/worker.h>
#include <freeradius-devel/io/channel.h>
#include <freeradius-devel/io/message.h>
#include <freeradius-devel/rad_assert.h>

/**
 *  Track things by priority and time.
 */
typedef struct fr_worker_heap_t {
	fr_dlist_t	list;			//!< list of things, ordered by time.
	fr_heap_t	*heap;			//!< heap, ordered by priority
} fr_worker_heap_t;


/**
 *  A worker which takes packets from a master, and processes them.
 */
struct fr_worker_t {
	char const		*name;		//!< name of this worker

	int			kq;		//!< my kq

	fr_log_t		*log;			//!< log destination

	fr_atomic_queue_t	*aq_control;	//!< atomic queue for control messages sent to me

	fr_control_t		*control;	//!< the control plane

	fr_message_set_t	*ms;		//!< replies are allocated from here.

	fr_event_list_t		*el;		//!< our event list

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

	fr_dlist_t		waiting_to_die;	//!< waiting to die

	int			num_requests;	//!< number of requests processed by this worker
	int			num_decoded;	//!< number of messages which have been decoded
	int			num_replies;	//!< number of messages which were replied to
	int			num_timeouts;	//!< number of messages which timed out

	fr_time_tracking_t	tracking;	//!< how much time the worker has spent doing things.

	uint32_t       		num_transports;	//!< how many transport layers we have
	fr_transport_t		**transports;	//!< array of active transports.

	fr_channel_t		**channel;	//!< list of channels
};

/*
 *	We need wrapper macros because we have multiple instances of
 *	the same code.
 */
#define WORKER_HEAP_INIT(_name, _func, _type, _member) do { \
		FR_DLIST_INIT(worker->_name.list); \
		worker->_name.heap = fr_heap_create(_func, offsetof(_type, _member)); \
		if (!worker->_name.heap) { \
			talloc_free(worker); \
			goto nomem; \
		} \
	} while (0)

#define WORKER_HEAP_INSERT(_name, _var, _member) do { \
		FR_DLIST_INSERT_HEAD(worker->_name.list, _var->_member); \
		(void) fr_heap_insert(worker->_name.heap, _var);        \
	} while (0)

#define WORKER_HEAP_POP(_name, _var, _member) do { \
		_var = fr_heap_pop(worker->_name.heap); \
		if (_var) FR_DLIST_REMOVE(_var->_member); \
	} while (0)

#define WORKER_HEAP_EXTRACT(_name, _var, _member) do { \
               (void) fr_heap_extract(worker->_name.heap, _var); \
               FR_DLIST_REMOVE(_var->_member); \
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

	case FR_CHANNEL_DATA_READY_RECEIVER:
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


/** Service an EVFILT_USER event
 *
 * @param[in] kq the kq to service
 * @param[in] kev the kevent to service
 * @param[in] ctx the fr_worker_t
 */
static void fr_worker_evfilt_user(UNUSED int kq, struct kevent const *kev, void *ctx)
{
	fr_time_t now;
	fr_worker_t *worker = ctx;
	char data[256];

#ifndef NDEBUG
	talloc_get_type_abort(worker, fr_worker_t);
#endif

	if (!fr_control_message_service_kevent(worker->control, kev)) {
		fr_log(worker->log, L_DBG, "\t%skevent not for us!", worker->name);
		return;
	}

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
	size_t size;
	fr_channel_data_t *reply;
	fr_channel_t *ch;
	fr_message_set_t *ms;

	worker->num_timeouts++;

	/*
	 *	Cache the outbound channel.  We'll need it later.
	 */
	ch = cd->channel.ch;

	ms = fr_channel_worker_ctx_get(ch);
	rad_assert(ms != NULL);

	/*
	 *	Allocate a default message size.
	 */
	reply = (fr_channel_data_t *) fr_message_reserve(ms, worker->transports[cd->transport]->default_message_size);
	rad_assert(reply != NULL);

	/*
	 *	Encode a NAK
	 */
	size = worker->transports[cd->transport]->nak(cd->packet_ctx, cd->m.data, cd->m.data_size, reply->m.data, reply->m.rb_size);

	(void) fr_message_alloc(ms, &reply->m, size);

	/*
	 *	Fill in the NAK.
	 */
	reply->m.when = now;
	reply->reply.cpu_time = worker->tracking.running;
	reply->reply.processing_time = 10; /* @todo - set to something better? */
	reply->reply.request_time = cd->m.when;

	reply->packet_ctx = cd->packet_ctx;
	reply->io_ctx = cd->io_ctx;
	reply->priority = cd->priority;
	reply->transport = cd->transport;

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
	ch = request->channel;
	rad_assert(ch != NULL);

	ms = fr_channel_worker_ctx_get(ch);
	rad_assert(ms != NULL);

	reply = (fr_channel_data_t *) fr_message_reserve(ms, size);
	rad_assert(reply != NULL);

	/*
	 *	Encode it, if required.
	 */
	if (size) {
		ssize_t encoded;

		encoded = request->transport->encode(request->packet_ctx, request, reply->m.data, reply->m.rb_size);
		if (encoded < 0) {
			fr_log(worker->log, L_DBG, "\t%sfails encode", worker->name);
			encoded = 0;
		}

		/*
		 *	Resize the buffer to the actual packet size.
		 */
		cd = (fr_channel_data_t *) fr_message_alloc(ms, &reply->m, encoded);
		rad_assert(cd == reply);
	}

	/*
	 *	The request is done.  Track that.
	 */
	fr_time_tracking_end(&request->tracking, fr_time(), &worker->tracking);

	/*
	 *	Fill in the rest of the fields in the channel message.
	 *
	 *	sequence / ack will be filled in by fr_channel_send_reply()
	 */
	reply->m.when = request->tracking.when;
	reply->reply.cpu_time = worker->tracking.running;
	reply->reply.processing_time = request->tracking.running;
	reply->reply.request_time = request->recv_time;

	reply->packet_ctx = request->packet_ctx;
	reply->io_ctx = request->io_ctx;
	reply->priority = request->priority;
	reply->transport = request->transport->id;

	fr_log(worker->log, L_DBG, "(%zd) finished, sending reply", request->number);

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
	FR_DLIST_REMOVE(request->time_order);
	talloc_free(request);
}


#define fr_ptr_to_type(TYPE, MEMBER, PTR) (TYPE *) (((char *)PTR) - offsetof(TYPE, MEMBER))

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
	fr_time_t waiting;
	fr_dlist_t *entry;

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
		lm = fr_message_localize(worker, &cd->m, sizeof(cd));
		if (!lm) goto nak;

		WORKER_HEAP_INSERT(localized, cd, request.list);
	}

	/*
	 *	Check the "runnable" queue for old requests.
	 */
	while ((entry = FR_DLIST_TAIL(worker->time_order)) != NULL) {
		REQUEST *request;
		fr_transport_final_t final;

		request = fr_ptr_to_type(REQUEST, time_order, entry);
		waiting = now - request->recv_time;

		if (waiting < NANOSEC) break;

		/*
		 *	Waiting too long, delete it.
		 */
		FR_DLIST_REMOVE(request->time_order);
		(void) fr_heap_extract(worker->runnable, request);

		final = request->process_async(request, FR_TRANSPORT_ACTION_DONE);

		if (final != FR_TRANSPORT_DONE) {
			FR_DLIST_INSERT_TAIL(worker->waiting_to_die, request->time_order);
			continue;
		}

		fr_log(worker->log, L_DBG, "(%zd) taking too long, stopping it", request->number);

		/*
		 *	Tell the network side that this request is done.
		 */
		fr_worker_send_reply(worker, request, 0);
	}

	/*
	 *	Check the waiting_to_die list.
	 */
	for (entry = FR_DLIST_FIRST(worker->waiting_to_die);
	     entry != NULL;
	     entry = FR_DLIST_NEXT(worker->waiting_to_die, entry)) {
		REQUEST *request;
		fr_transport_final_t final;

		request = fr_ptr_to_type(REQUEST, time_order, entry);

		final = request->process_async(request, FR_TRANSPORT_ACTION_DONE);

		if (final == FR_TRANSPORT_DONE) {
			FR_DLIST_REMOVE(worker->waiting_to_die);

			fr_log(worker->log, L_DBG, "(%zd) finally finished", request->number);

			/*
			 *	Tell the network side that this request is done.
			 */
			fr_worker_send_reply(worker, request, 0);
		}
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
	int rcode;
	fr_channel_data_t *cd;
	REQUEST *request;
#ifndef HAVE_TALLOC_POOLED_OBJECT
	TALLOC_CTX *ctx;
#endif

	/*
	 *	Grab a runnable request, and resume it.
	 */
	request = fr_heap_pop(worker->runnable);
	if (request) {
		fr_time_tracking_resume(&request->tracking, now);
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
		if (cd->request.start_time && (cd->m.when != *cd->request.start_time)) {
			fr_log(worker->log, L_DBG, "\t%sIGNORING old message", worker->name);
			fr_worker_nak(worker, cd, fr_time());
			cd = NULL;
		}
	} while (!cd);

#ifndef HAVE_TALLOC_POOLED_OBJECT
	/*
	 *	Get a talloc pool specifically for this packet.
	 */
	ctx = talloc_pool(worker, worker->talloc_pool_size);
	if (!ctx) goto nak;

	talloc_set_name_const(ctx, "REQUEST");

	request = (REQUEST *) ctx;
#else
	request = ctx = talloc_pooled_object(worker, REQUEST, 1, worker->talloc_pool_size);
	if (!request) goto nak;
#endif

	/*
	 *	Receive a message to the worker queue, and decode it
	 *	to a request.
	 */
	rad_assert(cd->transport <= worker->num_transports);
	rad_assert(worker->transports[cd->transport] != NULL);

	/*
	 *	Update the transport-specific fields.
	 *
	 *	Note that the message "when" time MUST be copied from
	 *	the original recv time.  We use "when" here, instead
	 *	of *cd->request.recv_time, on the odd chance that a
	 *	new packet arrived while we were getting around to
	 *	processing this message.
	 */
	memset(request, 0, sizeof(*request));
	request->channel = cd->channel.ch;
	request->transport = worker->transports[cd->transport];
	request->original_recv_time = cd->request.start_time;
	request->recv_time = cd->m.when;
	request->priority = cd->priority;
	request->runnable = worker->runnable;
	request->el = worker->el;
	request->packet_ctx = cd->packet_ctx;
	request->io_ctx = cd->io_ctx;
	request->number = 0;	/* @todo - assigned by someone intelligent... */

	/*
	 *	@todo - call worker->transports[cd->transport]->recv_request()
	 */

	/*
	 *	Now that the "request" structure has been initialized, go decode the packet.
	 */
	rcode = worker->transports[cd->transport]->decode(cd->packet_ctx, cd->m.data, cd->m.data_size, request);
	if (rcode < 0) {
		fr_log(worker->log, L_DBG, "\t%sFAILED decode of request %zd", worker->name, request->number);
		talloc_free(ctx);
nak:
		fr_worker_nak(worker, cd, fr_time());
		return NULL;
	}

	/*
	 *	Hoist run-time checks here.
	 */
	if (!cd->request.start_time) request->original_recv_time = &request->recv_time;

	/*
	 *	We're done with this message.
	 */
	fr_message_done(&cd->m);

	/*
	 *	New requests are inserted into the time order list in
	 *	strict time priority.  Once they are in the list, they
	 *	are only removed when the request is freed.
	 */
	FR_DLIST_INSERT_HEAD(worker->time_order, request->time_order);

	/*
	 *	Bootstrap the async state machine with the initial
	 *	state of the request.  The process_async function will
	 *	take care of pushing the state machine through it's
	 *	transitions.
	 */
	request->process_async = request->transport->process;
	fr_time_tracking_start(&request->tracking, now);

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
	fr_transport_final_t final;

	fr_log(worker->log, L_DBG, "\t%s running request (%zd)", worker->name, request->number);

	/*
	 *	If we still have the same packet, and the channel is
	 *	active, run it.  Otherwise, tell it that it's done.
	 */
	if ((*request->original_recv_time == request->recv_time) &&
	    fr_channel_active(request->channel)) {
		final = request->process_async(request, FR_TRANSPORT_ACTION_RUN);

	} else {
		final = request->process_async(request, FR_TRANSPORT_ACTION_DONE);

		/*
		 *	If the request isn't done, put it into the
		 *	async cleanup queue.
		 */
		if (final != FR_TRANSPORT_DONE) {
			FR_DLIST_REMOVE(request->time_order);
			FR_DLIST_INSERT_TAIL(worker->waiting_to_die, request->time_order);
			return;
		}
	}

	/*
	 *	Figure out what to do next.
	 */
	switch (final) {
	case FR_TRANSPORT_DONE:
		/*
		 *	Done: don't send a reply.
		 */
		break;

	case FR_TRANSPORT_YIELD:
		fr_time_tracking_yield(&request->tracking, fr_time(), &worker->tracking);
		return;

	case FR_TRANSPORT_REPLY:
		size = request->transport->default_message_size;
		break;
	}

	fr_log(worker->log, L_DBG, "(%zd) done naturally", request->number);

	fr_worker_send_reply(worker, request, size);
}

/** Run the event loop 'idle' callback
 *
 *  This function MUST DO NO WORK.  All it does is check if there's
 *  work, and tell the event code to return to the main loop if
 *  there's work to do.
 *
 * @param[in] ctx the worker
 * @param[in] wake the time when the event loop will wake up.
 */
static int fr_worker_idle(void *ctx, struct timeval *wake)
{
	bool sleeping;
	int i;
	fr_worker_t *worker = ctx;

#ifndef NDEBUG
	talloc_get_type_abort(worker, fr_worker_t);
	rad_assert(worker->runnable != NULL);
	rad_assert(worker->to_decode.heap != NULL);
	rad_assert(worker->localized.heap != NULL);
#endif

	/*
	 *	The application is polling the event loop, but has
	 *	other work to do.  Don't bother decoding any packets.
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
	if (!sleeping) return 1;

	fr_log(worker->log, L_DBG, "\t%ssleeping running %zd, localized %zd, to_decode %zd",
	       worker->name,
	       fr_heap_num_elements(worker->runnable),
	       fr_heap_num_elements(worker->localized.heap),
	       fr_heap_num_elements(worker->to_decode.heap));
	fr_log(worker->log, L_DBG, "\t%srequests %d, decoded %d, replied %d",
	       worker->name, worker->num_requests, worker->num_decoded, worker->num_replies);

	/*
	 *	Nothing more to do, and the event loop has us sleeping
	 *	for a period of time.  Signal the producers that we're
	 *	sleeping.  The fr_channel_worker_sleeping() function
	 *	will take care of skipping the signal if there are no
	 *	outstanding requests for it.
	 */
	for (i = 0; i < worker->num_channels; i++) {
		(void) fr_channel_worker_sleeping(worker->channel[i]);
	}

	return 0;
}

/**
 *  Track a channel in the "to_decode" or "localized" heap.
 */
static int worker_message_cmp(void const *one, void const *two)
{
	fr_channel_data_t const *a = one;
	fr_channel_data_t const *b = two;

	if (a->priority < b->priority) return -1;
	if (a->priority > b->priority) return +1;

	if (a->m.when < b->m.when) return -1;
	if (a->m.when > b->m.when) return +1;

	return 0;
}

/**
 *  Track a REQUEST in the "running" heap.
 */
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
	 *	Signal the channels that we're closing.
	 *
	 *	The other end owns the channel, and will take care of
	 *	popping messages in the TO_WORKER queue, and marking
	 *	them FR_MESSAGE_DONE.  It will ignore the messages in
	 *	the FROM_WORKER queue, as we own those.  They will be
	 *	automatically freed when our talloc context is freed.
	 */
	for (i = 0; i < worker->num_channels; i++) {
		fr_channel_worker_ack_close(worker->channel[i]);
	}
}


/** Create a worker
 *
 * @param[in] ctx the talloc context
 * @param[in] logger the destination for all logging messages
 * @param[in] num_transports the number of transports in the transport array
 * @param[in] transports the array of transports.
 * @return
 *	- NULL on error
 *	- fr_worker_t on success
 */
fr_worker_t *fr_worker_create(TALLOC_CTX *ctx, fr_log_t *logger, uint32_t num_transports, fr_transport_t **transports)
{
	int max_channels = 64;
	fr_worker_t *worker;

	if (!num_transports || !transports) {
		fr_strerror_printf("Must specify a transport");
		return NULL;
	}

	worker = talloc_zero(ctx, fr_worker_t);
	if (!worker) {
nomem:
		fr_strerror_printf("Failed allocating memory");
		return NULL;
	}

	worker->name = "";

	worker->channel = talloc_zero_array(worker, fr_channel_t *, max_channels);
	if (!worker->channel) {
		talloc_free(worker);
		goto nomem;
	}

	worker->log = logger;

	/*
	 *	@todo make these configurable
	 */
	worker->max_channels = max_channels;
	worker->talloc_pool_size = 4096; /* at least enough for a REQUEST */
	worker->message_set_size = 1024;
	worker->ring_buffer_size = (1 << 16);

	worker->el = fr_event_list_create(worker, fr_worker_idle, worker);
	if (!worker->el) {
		fr_strerror_printf("Failed creating event list: %s", fr_strerror());
		talloc_free(worker);
		return NULL;
	}

	if (fr_event_user_insert(worker->el, fr_worker_evfilt_user, worker) < 0) {
		fr_strerror_printf("Failed updating event list: %s", fr_strerror());
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
		talloc_free(worker);
		goto nomem;
	}

	worker->control = fr_control_create(worker, worker->kq, worker->aq_control);
	if (!worker->control) {
		talloc_free(worker);
		goto nomem;;
	}

	if (fr_control_callback_add(worker->control, FR_CONTROL_ID_CHANNEL, worker, fr_worker_channel_callback) < 0) {
		fr_strerror_printf("Failed adding control channel: %s", fr_strerror());
		talloc_free(worker);
		return NULL;
	}

	if (fr_event_user_insert(worker->el, fr_worker_evfilt_user, worker) < 0) {
		fr_strerror_printf("Failed updating event list: %s", fr_strerror());
		talloc_free(worker);
		return NULL;
	}

	WORKER_HEAP_INIT(to_decode, worker_message_cmp, fr_channel_data_t, channel.heap_id);
	WORKER_HEAP_INIT(localized, worker_message_cmp, fr_channel_data_t, channel.heap_id);

	worker->runnable = fr_heap_create(worker_request_cmp, offsetof(REQUEST, heap_id));
	if (!worker->runnable) {
		talloc_free(worker);
		goto nomem;;
	}
	FR_DLIST_INIT(worker->time_order);
	FR_DLIST_INIT(worker->waiting_to_die);

	worker->num_transports = num_transports;
	worker->transports = transports;

	return worker;
}

/** Get the KQ for the worker
 *
 * @param[in] worker the worker data structure
 * @return kq
 */
int fr_worker_kq(fr_worker_t *worker)
{
	return worker->kq;
}


/** Signal a worker to exit
 *
 *  WARNING: This may be called from another thread!  Care is required.
 *
 * @param[in] worker the worker data structure to manage
 */
void fr_worker_exit(fr_worker_t *worker)
{
	fr_event_loop_exit(worker->el, 1);
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
		fr_log(worker->log, L_DBG, "\t%sWaiting for events %d", worker->name, wait_for_event);

		/*
		 *	Check the event list.  If there's an error
		 *	(e.g. exit), we stop looping and clean up.
		 */
		num_events = fr_event_corral(worker->el, wait_for_event);
		fr_log(worker->log, L_DBG, "\t%sGot num_events %d", worker->name, num_events);
		if (num_events < 0) {
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

		now = fr_time();

		/*
		 *	Ten times a second, check for timeouts on incoming packets.
		 */
		if ((now - worker->checked_timeout) > (NANOSEC / 10)) {
			fr_log(worker->log, L_DBG, "\t%schecking timeouts", worker->name);
			fr_worker_check_timeouts(worker, now);
		}

		/*
		 *	Get a runnable request.  If there isn't one, continue.
		 */
		request = fr_worker_get_request(worker, now);
		if (!request) continue;

		/*
		 *	Run the request, and either track it as
		 *	yielded, or send a reply.
		 */
		fr_log(worker->log, L_DBG, "\t%srunning request (%zd)", worker->name, request->number);
		fr_worker_run_request(worker, request);
	}
}

#if 0
/*
 *	A local copy of unlang_resume(), so we know what we're supposed to do.
 */
void worker_resume_request(REQUEST *request)
{
	/*
	 *	The request is no longer in the "yielded" list.  But
	 *	it isn't resumed (yet) so we don't add CPU time for
	 *	it.
	 */
	FR_DLIST_REMOVE(request->tracking.list);

	/*
	 *	It's runnable again.
	 */
	(void) fr_heap_insert(request->runnable, request);
}
#endif

/** Print debug information about the worker structure
 *
 * @param[in] worker the worker
 * @param[in] fp the file where the debug output is printed.
 */
void fr_worker_debug(fr_worker_t *worker, FILE *fp)
{
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
fr_channel_t *fr_worker_channel_create(fr_worker_t const *worker, TALLOC_CTX *ctx, fr_control_t *master)
{
	fr_channel_t *ch;

#ifndef NDEBUG
	talloc_get_type_abort(worker, fr_worker_t);
#endif

	rad_assert(worker->control != NULL);

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
#ifndef NDEBUG
	talloc_get_type_abort(worker, fr_worker_t);
#endif

	worker->name = talloc_strdup(worker, name);
}
