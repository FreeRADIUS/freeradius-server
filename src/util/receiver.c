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
 * @brief Receiver of socket data, which sends messages to the workers.
 * @file util/receiver.c
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <talloc.h>

#include <freeradius-devel/event.h>
#include <freeradius-devel/util/queue.h>
#include <freeradius-devel/util/worker.h>
#include <freeradius-devel/util/receiver.h>

#include <freeradius-devel/rad_assert.h>

typedef struct fr_receiver_worker_t {
	int			heap_id;
	fr_time_t		cpu_time;
	fr_time_t		processing_time;

	fr_channel_t		*channel;
	fr_worker_t		*worker;
} fr_receiver_worker_t;

struct fr_receiver_t {
	int			kq;
	fr_event_list_t		*el;

	fr_heap_t		*replies;
	fr_heap_t		*workers;
	fr_heap_t		*closing;

	uint32_t		num_transports;	//!< how many transport layers we have
	fr_transport_t		**transports;	//!< array of active transports.
};

static int worker_cmp(void const *one, void const *two)
{
	fr_receiver_worker_t const *a = one;
	fr_receiver_worker_t const *b = two;

	if (a->cpu_time < b->cpu_time) return -1;
	if (a->cpu_time > b->cpu_time) return +1;

	return 0;
}

static int reply_cmp(void const *one, void const *two)
{
	fr_channel_data_t const *a = one;
	fr_channel_data_t const *b = two;

	if (a->priority < b->priority) return -1;
	if (a->priority > b->priority) return +1;

	if (a->m.when < b->m.when) return -1;
	if (a->m.when > b->m.when) return +1;

	return 0;
}

#if 0
/** Send a message on the "best" channel.
 *
 */
int fr_receiver_send_request(fr_receiver_t *rc, fr_channel_data_t *cd)
{
	fr_receiver_worker_t *worker;
	fr_channel_data_t *reply;

#ifndef NDEBUG
	(void) talloc_get_type_abort(rc, fr_receiver_t);
#endif

	worker = fr_heap_pop(rc->workers);
	if (!worker) return 0;

	/*
	 *	Send the message to the channel.  If we fail, recurse.
	 *	That's easier than manually tracking the channel we
	 *	popped off of the heap.
	 *
	 *	The only practical reason why the channel send will
	 *	fail is because the recipient is not servicing it's
	 *	queue.  When that happens, just hand the request to
	 *	another channel.
	 *
	 *	If we run out of channels to use, the caller needs to
	 *	allocate another one, and hand it to the scheduler.
	 */
	if (fr_channel_send_request(worker->channel, cd, &reply) < 0) {
		int rcode;

		rcode = fr_receiver_send_request(rc, cd);

		/*
		 *	Mark this channel as still busy, for some
		 *	future time.  This process ensures that we
		 *	don't immediately pop it off the heap and try
		 *	to send it another request.
		 */
		worker->cpu_time = cd->m.when + worker->processing_time;
		(void) fr_heap_insert(rc->workers, worker);

		return rcode;
	}

	/*
	 *	We're projecting that the worker will use more CPU
	 *	time to process this request.  The CPU time will be
	 *	updated with a more accurate number when we receive a
	 *	reply from this channel.
	 */
	worker->cpu_time += worker->processing_time;

	/*
	 *	Insert the worker back into the scheduler.
	 */
	(void) fr_heap_insert(rc->workers, worker);

	/*
	 *	If we have a reply, push it onto our local queue, and
	 *	poll for more replies.
	 */
	if (reply) {
		do {
			reply->channel.ch = worker->channel;
			(void) fr_heap_insert(rc->replies, reply);
		} while ((reply = fr_channel_recv_reply(worker->channel)) != NULL);
	}

	return 0;
}
#endif

/** Create a receiver
 *
 * @param[in] ctx the talloc ctx
 * @param[in] num_transports the number of transports in the transport array
 * @param[in] transports the array of transports.
 * @return
 *	- NULL on error
 *	- fr_receiver_t on success
 */
fr_receiver_t *fr_receiver_create(TALLOC_CTX *ctx, uint32_t num_transports, fr_transport_t **transports)
{
	fr_receiver_t *rc;

	if (!num_transports || !transports) return NULL;

	rc = talloc_zero(ctx, fr_receiver_t);
	if (!rc) return NULL;

	rc->el = fr_event_list_create(rc, NULL, NULL);
	if (!rc->el) {
		talloc_free(rc);
		return NULL;
	}

	rc->kq = fr_event_list_kq(rc->el);
	rad_assert(rc->kq >= 0);

	rc->replies = fr_heap_create(reply_cmp, offsetof(fr_channel_data_t, channel.heap_id));
	if (!rc->replies) {
		talloc_free(rc);
		return NULL;
	}

	rc->workers = fr_heap_create(worker_cmp, offsetof(fr_channel_data_t, channel.heap_id));
	if (!rc->workers) {
		talloc_free(rc);
		return NULL;
	}

	rc->closing = fr_heap_create(worker_cmp, offsetof(fr_channel_data_t, channel.heap_id));
	if (!rc->closing) {
		talloc_free(rc);
		return NULL;
	}

	// insert our kevent handler
	// start off with a channel?
	// i.e. get new sockets from that channel?

	rc->num_transports = num_transports;
	rc->transports = transports;

	return rc;
}


/** Destroy a receiver
 *
 * @param[in] rc the receiver
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_receiver_destroy(fr_receiver_t *rc)
{
	fr_receiver_worker_t *worker;
	fr_channel_data_t *cd;

#ifndef NDEBUG
	(void) talloc_get_type_abort(rc, fr_receiver_t);
#endif

	/*
	 *	Pop all of the workers, and signal them that we're
	 *	closing/
	 */
	while ((worker = fr_heap_pop(rc->workers)) != NULL) {
		fr_channel_signal_close(worker->channel);
		(void) fr_heap_insert(rc->closing, worker);
	}

	/*
	 *	@todo wait for all workers to acknowledge the channel
	 *	close.
	 */

	/*
	 *	Clean up all of the replies.
	 */
	while ((cd = fr_heap_pop(rc->replies)) != NULL) {
		fr_message_done(&cd->m);
	}

	talloc_free(rc);

	return 0;
}

void fr_receiver(fr_receiver_t *rc)
{
	while (fr_event_loop(rc->el) == 0) {
		/* nothing */
	}
}
