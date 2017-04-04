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
#include <freeradius-devel/util/channel.h>
#include <freeradius-devel/util/control.h>
#include <freeradius-devel/util/worker.h>
#include <freeradius-devel/util/receiver.h>

#include <freeradius-devel/rad_assert.h>

/*
 *	Debugging, mainly for worker_test
 */
#if 0
#define MPRINT(...) fprintf(stdout, __VA_ARGS__)
#else
#define MPRINT(...)
#endif

typedef struct fr_receiver_worker_t {
	int			heap_id;		//!< workers are in a heap
	fr_time_t		cpu_time;		//!< how much CPU time this worker has spent
	fr_time_t		processing_time;	//!< predicted processing time for one packet

	fr_channel_t		*channel;		//!< channel to the worker
	fr_worker_t		*worker;		//!< worker pointer
} fr_receiver_worker_t;

typedef struct fr_receiver_socket_t {
	int			heap_id;		//!< for the heap

	int			fd;			//!< the file descriptor
	void			*ctx;			//!< transport context
	fr_transport_t		*transport;		//!< the transport

	fr_message_set_t	*ms;			//!< message buffers for this socket.
	fr_channel_data_t	*cd;			//!< cached in case of allocation & read error
} fr_receiver_socket_t;


struct fr_receiver_t {
	int			kq;			//!< our KQ

	fr_atomic_queue_t	*aq_control;		//!< atomic queue for control messages sent to me

	fr_control_t		*control;		//!< the control plane

	fr_ring_buffer_t	*rb;			//!< ring buffer for my control-plane messages

	fr_event_list_t		*el;			//!< our event list

	fr_heap_t		*replies;		//!< replies from the worker, ordered by priority / origin time
	fr_heap_t		*workers;		//!< workers, ordered by total CPU time spent
	fr_heap_t		*closing;		//!< workers which are being closed

	uint64_t		num_requests;		//!< number of requests we sent
	uint64_t		num_replies;		//!< number of replies we received

	fr_heap_t		*sockets;		//!< list of sockets we're managing

	uint32_t		num_transports;		//!< how many transport layers we have
	fr_transport_t		**transports;		//!< array of active transports.
};


static int socket_cmp(void const *one, void const *two)
{
	fr_receiver_socket_t const *a = one;
	fr_receiver_socket_t const *b = two;

	if (a->fd < b->fd) return -1;
	if (a->fd > b->fd) return +1;

	return 0;
}

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

/** Drain the input channel
 *
 * @param[in] rc the receiver
 * @param[in] ch the channel to drain
 * @param[in] cd the message (if any) to start with
 */
static void fr_receiver_drain_input(fr_receiver_t *rc, fr_channel_t *ch, fr_channel_data_t *cd)
{
	if (!cd) {
		cd = fr_channel_recv_reply(ch);
		if (!cd) {
			MPRINT("\tno data?\n");
			return;
		}
	}

	do {
		rc->num_replies++;
		MPRINT("MASTER received reply %zd\n", rc->num_replies);

		cd->channel.ch = ch;
		(void) fr_heap_insert(rc->replies, cd);
	} while ((cd = fr_channel_recv_reply(ch)) != NULL);

	/*
	 *	@todo - get CPU time and processing time from the message, and update the worker.
	 */
}

/** Run the event loop 'idle' callback
 *
 *  This function MUST DO NO WORK.  All it does is check if there's
 *  work, and tell the event code to return to the main loop if
 *  there's work to do.
 *
 * @param[in] ctx the receiver
 * @param[in] wake the time when the event loop will wake up.
 */
static int fr_receiver_idle(void *ctx, struct timeval *wake)
{
	fr_receiver_t *rc = ctx;

#ifndef NDEBUG
	talloc_get_type_abort(rc, fr_receiver_t);
#endif

	rad_cond_assert(rc->el != NULL); /* temporary until we actually use rc here */

	if (!wake) {
		// ready to process requests
		return 0;
	}

	if ((wake->tv_sec != 0) ||
	    (wake->tv_usec >= 100000)) {
#if 0
		DEBUG("Waking up in %d.%01u seconds.",
		      (int) wake->tv_sec, (unsigned int) wake->tv_usec / 100000);
#endif
		return 0;
	}

	return 0;
}


/** Handle a receiver control message callback for a channel
 *
 * @param[in] ctx the receiver
 * @param[in] data the message
 * @param[in] data_size size of the data
 * @param[in] now the current time
 */
static void fr_receiver_channel_callback(void *ctx, void const *data, size_t data_size, fr_time_t now)
{
	fr_channel_event_t ce;
	fr_channel_t *ch;
	fr_receiver_t *rc = ctx;

	ce = fr_channel_service_message(now, &ch, data, data_size);
	switch (ce) {
	case FR_CHANNEL_ERROR:
		MPRINT("MASTER aq error\n");
		return;

	case FR_CHANNEL_EMPTY:
		MPRINT("MASTER aq empty\n");
		return;

	case FR_CHANNEL_NOOP:
		MPRINT("MASTER aq noop\n");
		break;

	case FR_CHANNEL_DATA_READY_RECEIVER:
		rad_assert(ch != NULL);
		MPRINT("MASTER aq data ready\n");
		fr_receiver_drain_input(rc, ch, NULL);
		break;

	case FR_CHANNEL_DATA_READY_WORKER:
		rad_assert(0 == 1);
		MPRINT("MASTER aq data ready ? WORKER ?\n");
		break;

	case FR_CHANNEL_OPEN:
		rad_assert(0 == 1);
		MPRINT("MASTER channel open ?\n");
		break;

	case FR_CHANNEL_CLOSE:
		MPRINT("MASTER aq channel close\n");
		///
		break;
	}
}

/** Send a message on the "best" channel.
 *
 * @param rc the receiver
 * @param cd the message we've received
 */
static int fr_receiver_send_request(fr_receiver_t *rc, fr_channel_data_t *cd)
{
	fr_receiver_worker_t *worker;
	fr_channel_data_t *reply;

#ifndef NDEBUG
	(void) talloc_get_type_abort(rc, fr_receiver_t);
#endif

	/*
	 *	Grab the worker with the least total CPU time.
	 */
	worker = fr_heap_pop(rc->workers);
	if (!worker) {
		fprintf(stderr, "NO WORKERS\n");
		return 0;
	}

	(void) talloc_get_type_abort(worker, fr_receiver_worker_t);

	/*
	 *	Send the message to the channel.  If we fail, recurse.
	 *	That's easier than manually tracking the channel we
	 *	popped off of the heap.
	 *
	 *	The only practical reason why the channel send will
	 *	fail is because the recipient is not servicing it's
	 *	queue.  When that happens, we just hand the request to
	 *	another channel.
	 *
	 *	If we run out of channels to use, the caller needs to
	 *	allocate another one, and hand it to the scheduler.
	 */
	if (fr_channel_send_request(worker->channel, cd, &reply) < 0) {
		int rcode;

		fprintf(stderr, "RECURSING IN SEND_REQUEST\n");
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
	 *	Insert the worker back into the heap of workers.
	 */
	(void) fr_heap_insert(rc->workers, worker);

	/*
	 *	If we have a reply, push it onto our local queue, and
	 *	poll for more replies.
	 */
	if (reply) fr_receiver_drain_input(rc, worker->channel, reply);

	return 1;
}


static fr_time_t start_time = 0;


/** Read a packet from the network.
 *
 * @param el the event list
 * @param sockfd the socket which is ready to read
 * @param ctx the receiver socket context.
 */
static void fr_receiver_read(UNUSED fr_event_list_t *el, int sockfd, void *ctx)
{
	fr_receiver_socket_t *s = ctx;
	fr_receiver_t *rc = talloc_parent(s);
	ssize_t data_size;
	fr_channel_data_t *cd;
	struct sockaddr_storage ss;
	socklen_t salen = sizeof(ss);

	rad_assert(s->fd == sockfd);

	fprintf(stderr, "RECEIVER READ\n");

	if (!s->cd) {
		cd = (fr_channel_data_t *) fr_message_reserve(s->ms, s->transport->default_message_size);
		if (!cd) {
			fprintf(stderr, "Failed allocating message %zd!\n", s->transport->default_message_size);

			/*
			 *	@todo - handle errors via transport callback
			 */
			_exit(1);
		}
	} else {
		cd = s->cd;
	}

	fprintf(stderr, "DATA SIZE %zd %zd\n", cd->m.data_size, cd->m.rb_size);
	rad_assert(cd->m.data != NULL);
	rad_assert(cd->m.rb_size >= 256);

	/*
	 *	@todo - transport->read_request
	 */
	data_size = recvfrom(s->fd, cd->m.data, cd->m.rb_size,
			     0, (struct sockaddr *) &ss, &salen);
	if (data_size == 0) {
		fprintf(stderr, "GOT ZERO FROM RECVFROM %d\n", __LINE__);

		s->cd = cd;

		// UDP: ignore
		// TCP: close socket
		_exit(1);
	}

	if (data_size < 0) {
		fprintf(stderr, "FAIL READ %d of max %zd: %s\n", __LINE__,
			cd->m.rb_size, strerror(errno));

		/*
		 *	@todo - handle errors via transport callback
		 */
		_exit(1);
	}
	s->cd = NULL;

	fprintf(stderr, "Got packet size %zd\n", data_size);

	fprintf(stderr, "READ FROM SOCKET %d - %zd bytes\n", sockfd, data_size);

	/*
	 *	Initialize the rest of the fields of the channel data.
	 */
	cd->m.when = fr_time();
	cd->ctx = s->ctx;
	cd->transport = 0;	/* @todo - set transport number from the transport */
	cd->priority = 0;	/* @todo - set priority based on information from the transport layer  */
	cd->request.start_time = &start_time; /* @todo - set by transport */

	start_time = cd->m.when;

	(void) fr_message_alloc(s->ms, &cd->m, data_size);

	if (!fr_receiver_send_request(rc, cd)) {
		fprintf(stderr, "FAILED SENDING PACKET TO WORKER\n");
		fr_message_done(&cd->m);
	}
}

/** Handle a receiver control message callback for a new socket
 *
 * @param[in] ctx the receiver
 * @param[in] data the message
 * @param[in] data_size size of the data
 * @param[in] now the current time
 */
static void fr_receiver_socket_callback(void *ctx, void const *data, size_t data_size, UNUSED fr_time_t now)
{
	fr_receiver_t *rc = ctx;
	fr_receiver_socket_t *s;

	rad_assert(data_size == sizeof(*s));

	if (data_size != sizeof(*s)) return;

	s = talloc(rc, fr_receiver_socket_t);
	rad_assert(s != NULL);
	memcpy(s, data, sizeof(*s));

#define MIN_MESSAGES (8)

	/*
	 *	@todo - make the default number of messages configurable?
	 */
	s->ms = fr_message_set_create(s, MIN_MESSAGES,
				      sizeof(fr_channel_data_t),
				      s->transport->default_message_size * MIN_MESSAGES);
	if (!s->ms) {
		fprintf(stderr, "FAIL CREATE %d\n", __LINE__);

		/*
		 *	@todo - handle errors via transport callback
		 */
		_exit(1);
	}

	if (fr_event_fd_insert(rc->el, s->fd, fr_receiver_read, NULL, NULL, s) < 0) {
		fprintf(stderr, "FAILED ADDING NEW SOCKET\n");
		close(s->fd);
		return;
	}

	(void) fr_heap_insert(rc->sockets, s);

	fprintf(stderr, "GOT NEW SOCKET\n");
}


/** Handle a receiver control message callback for a new worker
 *
 * @param[in] ctx the receiver
 * @param[in] data the message
 * @param[in] data_size size of the data
 * @param[in] now the current time
 */
static void fr_receiver_worker_callback(void *ctx, void const *data, size_t data_size, UNUSED fr_time_t now)
{
	fr_receiver_t *rc = ctx;
	fr_worker_t *worker;
	fr_receiver_worker_t *w;

	rad_assert(data_size == sizeof(worker));

	memcpy(&worker, data, data_size);
	(void) talloc_get_type_abort(worker, fr_worker_t);

	w = talloc_zero(rc, fr_receiver_worker_t);
	if (!w) _exit(1);

	w->worker = worker;
	w->channel = fr_worker_channel_create(worker, w, rc->control);
	if (!w->channel) _exit(1);

	(void) fr_heap_insert(rc->workers, w);
}


/** Service an EVFILT_USER event
 *
 * @param[in] kq the kq to service
 * @param[in] kev the kevent to service
 * @param[in] ctx the fr_worker_t
 */
static void fr_receiver_evfilt_user(UNUSED int kq, struct kevent const *kev, void *ctx)
{
	fr_time_t now;
	fr_receiver_t *rc = ctx;
	uint8_t data[256];

#ifndef NDEBUG
	talloc_get_type_abort(rc, fr_receiver_t);
#endif

	if (!fr_control_message_service_kevent(rc->control, kev)) {
		MPRINT("MASTER kevent not for us!\n");
		return;
	}

	now = fr_time();

	/*
	 *	Service all available control-plane events
	 */
	fr_control_service(rc->control, data, sizeof(data), now);
}


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

	rc->el = fr_event_list_create(rc, fr_receiver_idle, rc);
	if (!rc->el) {
		talloc_free(rc);
		return NULL;
	}

	rc->kq = fr_event_list_kq(rc->el);
	rad_assert(rc->kq >= 0);

	rc->aq_control = fr_atomic_queue_create(rc, 1024);
	if (!rc->aq_control) {
		talloc_free(rc);
		return NULL;
	}

	rc->control = fr_control_create(rc, rc->kq, rc->aq_control);
	if (!rc->control) {
		talloc_free(rc);
		return NULL;
	}

	rc->rb = fr_ring_buffer_create(rc, FR_CONTROL_MAX_MESSAGES * FR_CONTROL_MAX_SIZE);
	if (!rc->rb) {
		talloc_free(rc);
		return NULL;
	}

	if (fr_control_callback_add(rc->control, FR_CONTROL_ID_CHANNEL, rc, fr_receiver_channel_callback) < 0) {
		talloc_free(rc);
		return NULL;
	}

	if (fr_control_callback_add(rc->control, FR_CONTROL_ID_SOCKET, rc, fr_receiver_socket_callback) < 0) {
		talloc_free(rc);
		return NULL;
	}

	if (fr_control_callback_add(rc->control, FR_CONTROL_ID_WORKER, rc, fr_receiver_worker_callback) < 0) {
		talloc_free(rc);
		return NULL;
	}

	if (fr_event_user_insert(rc->el, fr_receiver_evfilt_user, rc) < 0) {
		talloc_free(rc);
		return NULL;
	}

	/*
	 *	Create the various heaps.
	 */
	rc->sockets = fr_heap_create(socket_cmp, offsetof(fr_receiver_socket_t, heap_id));
	if (!rc->sockets) {
		talloc_free(rc);
		return NULL;
	}

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
		fr_channel_signal_worker_close(worker->channel);
		(void) fr_heap_insert(rc->closing, worker);
	}

	/*
	 *	@todo wait for all workers to acknowledge the channel
	 *	close.
	 */

	/*
	 *	Clean up all of the replies.
	 *
	 *	@todo something with the replies, to clean them up...
	 */
	while ((cd = fr_heap_pop(rc->replies)) != NULL) {
		fr_message_done(&cd->m);
	}

	talloc_free(rc);

	return 0;
}

/** The main network worker function.
 *
 * @param[in] rc the receiver data structure to run.
 */
void fr_receiver(fr_receiver_t *rc)
{
	/*
	 *	The receiver is entirely event driven.
	 */
	while (fr_event_loop(rc->el) == 0) {
		/* nothing */
	}
}

/** Signal a reciever to exit
 *
 *  WARNING: This may be called from another thread!  Care is required.
 *
 * @param[in] rc the receiver data structure to manage
 */
void fr_receiver_exit(fr_receiver_t *rc)
{
	fr_event_loop_exit(rc->el, 1);
}

/** Add a socket to a receiver
 *
 * @param rc the receiver
 * @param fd the file descriptor for the socket
 * @param ctx the context for the transport
 * @param transport the transport
 */
int fr_receiver_socket_add(fr_receiver_t *rc, int fd, void *ctx, fr_transport_t *transport)
{
	fr_receiver_socket_t m;

	memset(&m, 0, sizeof(m));
	m.fd = fd;
	m.ctx = ctx;
	m.transport = transport;

	return fr_control_message_send(rc->control, rc->rb, FR_CONTROL_ID_SOCKET, &m, sizeof(m));
}

/** Add a worker to a receiver
 *
 * @param rc the receiver
 * @param worker the worker
 */
int fr_receiver_worker_add(fr_receiver_t *rc, fr_worker_t *worker)
{
	(void) talloc_get_type_abort(rc, fr_receiver_t);
	(void) talloc_get_type_abort(worker, fr_worker_t);

	return fr_control_message_send(rc->control, rc->rb, FR_CONTROL_ID_WORKER, &worker, sizeof(worker));
}
