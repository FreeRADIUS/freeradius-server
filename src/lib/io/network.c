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
 * @file io/network.c
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <talloc.h>

#include <freeradius-devel/event.h>
#include <freeradius-devel/rbtree.h>
#include <freeradius-devel/io/queue.h>
#include <freeradius-devel/io/channel.h>
#include <freeradius-devel/io/control.h>
#include <freeradius-devel/io/worker.h>
#include <freeradius-devel/io/network.h>
#include <freeradius-devel/io/listen.h>

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#define PTHREAD_MUTEX_LOCK   pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock

#else
#define PTHREAD_MUTEX_LOCK
#define PTHREAD_MUTEX_UNLOCK
#endif

typedef struct fr_network_worker_t {
	int			heap_id;		//!< workers are in a heap
	fr_time_t		cpu_time;		//!< how much CPU time this worker has spent
	fr_time_t		predicted;		//!< predicted processing time for one packet

	fr_channel_t		*channel;		//!< channel to the worker
	fr_worker_t		*worker;		//!< worker pointer
} fr_network_worker_t;

typedef struct fr_network_socket_t {
	fr_listen_t const	*listen;		//!< I/O ctx and functions.

	fr_message_set_t	*ms;			//!< message buffers for this socket.
	fr_channel_data_t	*cd;			//!< cached in case of allocation & read error
} fr_network_socket_t;


struct fr_network_t {
	int			kq;			//!< our KQ

	fr_log_t		*log;			//!< log destination

	fr_atomic_queue_t	*aq_control;		//!< atomic queue for control messages sent to me

	fr_control_t		*control;		//!< the control plane

	fr_ring_buffer_t	*rb;			//!< ring buffer for my control-plane messages

	fr_event_list_t		*el;			//!< our event list

	fr_heap_t		*replies;		//!< replies from the worker, ordered by priority / origin time
	fr_heap_t		*workers;		//!< workers, ordered by total CPU time spent
	fr_heap_t		*closing;		//!< workers which are being closed

	uint64_t		num_requests;		//!< number of requests we sent
	uint64_t		num_replies;		//!< number of replies we received

	rbtree_t		*sockets;		//!< list of sockets we're managing

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		mutex;			//!< for sending us control messages
#endif
};

static void fr_network_post_event(fr_event_list_t *el, struct timeval *now, void *uctx);

static int worker_cmp(void const *one, void const *two)
{
	fr_network_worker_t const *a = one;
	fr_network_worker_t const *b = two;

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

static int socket_cmp(void const *one, void const *two)
{
	fr_network_socket_t const *a = one;
	fr_network_socket_t const *b = two;

	if (a->listen < b->listen) return -1;
	if (a->listen > b->listen) return +1;

	return 0;
}



#define IALPHA (8)
#define RTT(_old, _new) ((_new + ((IALPHA - 1) * _old)) / IALPHA)

/** Drain the input channel
 *
 * @param[in] nr the network
 * @param[in] ch the channel to drain
 * @param[in] cd the message (if any) to start with
 */
static void fr_network_drain_input(fr_network_t *nr, fr_channel_t *ch, fr_channel_data_t *cd)
{
	fr_network_worker_t *w;

	if (!cd) {
		cd = fr_channel_recv_reply(ch);
		if (!cd) {
			return;
		}
	}

	do {
		nr->num_replies++;
		fr_log(nr->log, L_DBG, "received reply %zd", nr->num_replies);

		cd->channel.ch = ch;

		/*
		 *	Update stats for the worker.
		 */
		w = fr_channel_master_ctx_get(ch);
		w->cpu_time = cd->reply.cpu_time;
		if (!w->predicted) {
			w->predicted = cd->reply.processing_time;
		} else {
			w->predicted = RTT(w->predicted, cd->reply.processing_time);
		}

		(void) fr_heap_insert(nr->replies, cd);
	} while ((cd = fr_channel_recv_reply(ch)) != NULL);
}

/** Run the event loop 'idle' callback
 *
 *  This function MUST DO NO WORK.  All it does is check if there's
 *  work, and tell the event code to return to the main loop if
 *  there's work to do.
 *
 * @param[in] ctx the network
 * @param[in] wake the time when the event loop will wake up.
 */
static int fr_network_idle(void *ctx, struct timeval *wake)
{
	fr_network_t *nr = talloc_get_type_abort(ctx, fr_network_t);

	rad_cond_assert(nr->el != NULL); /* temporary until we actually use nr here */

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


/** Handle a network control message callback for a channel
 *
 * @param[in] ctx the network
 * @param[in] data the message
 * @param[in] data_size size of the data
 * @param[in] now the current time
 */
static void fr_network_channel_callback(void *ctx, void const *data, size_t data_size, fr_time_t now)
{
	fr_channel_event_t ce;
	fr_channel_t *ch;
	fr_network_t *nr = ctx;

	ce = fr_channel_service_message(now, &ch, data, data_size);
	switch (ce) {
	case FR_CHANNEL_ERROR:
		fr_log(nr->log, L_DBG_ERR, "aq error");
		return;

	case FR_CHANNEL_EMPTY:
		fr_log(nr->log, L_DBG, "aq empty");
		return;

	case FR_CHANNEL_NOOP:
		fr_log(nr->log, L_DBG, "aq noop");
		break;

	case FR_CHANNEL_DATA_READY_NETWORK:
		rad_assert(ch != NULL);
		fr_log(nr->log, L_DBG, "aq data ready");
		fr_network_drain_input(nr, ch, NULL);
		break;

	case FR_CHANNEL_DATA_READY_WORKER:
		rad_assert(0 == 1);
		fr_log(nr->log, L_DBG_ERR, "aq data ready ? WORKER ?");
		break;

	case FR_CHANNEL_OPEN:
		rad_assert(0 == 1);
		fr_log(nr->log, L_DBG, "channel open ?");
		break;

	case FR_CHANNEL_CLOSE:
		fr_log(nr->log, L_DBG, "aq channel close");
		///
		break;
	}
}

/** Send a message on the "best" channel.
 *
 * @param nr the network
 * @param cd the message we've received
 */
static int fr_network_send_request(fr_network_t *nr, fr_channel_data_t *cd)
{
	fr_network_worker_t *worker;
	fr_channel_data_t *reply;

	(void) talloc_get_type_abort(nr, fr_network_t);

	/*
	 *	Grab the worker with the least total CPU time.
	 */
	worker = fr_heap_pop(nr->workers);
	if (!worker) {
		fr_log(nr->log, L_DBG, "no workers");
		return 0;
	}

	(void) talloc_get_type_abort(worker, fr_network_worker_t);

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

		fr_log(nr->log, L_DBG, "recursing in send_request");
		rcode = fr_network_send_request(nr, cd);

		/*
		 *	Mark this channel as still busy, for some
		 *	future time.  This process ensures that we
		 *	don't immediately pop it off the heap and try
		 *	to send it another request.
		 */
		worker->cpu_time = cd->m.when + worker->predicted;
		(void) fr_heap_insert(nr->workers, worker);

		return rcode;
	}

	/*
	 *	We're projecting that the worker will use more CPU
	 *	time to process this request.  The CPU time will be
	 *	updated with a more accurate number when we receive a
	 *	reply from this channel.
	 */
	worker->cpu_time += worker->predicted;

	/*
	 *	Insert the worker back into the heap of workers.
	 */
	(void) fr_heap_insert(nr->workers, worker);

	/*
	 *	If we have a reply, push it onto our local queue, and
	 *	poll for more replies.
	 */
	if (reply) fr_network_drain_input(nr, worker->channel, reply);

	return 1;
}


static fr_time_t start_time = 0;


/** Read a packet from the network.
 *
 * @param[in] el	the event list.
 * @param[in] sockfd	the socket which is ready to read.
 * @param[in] flags	from kevent.
 * @param[in] ctx	the network socket context.
 */
static void fr_network_read(UNUSED fr_event_list_t *el, int sockfd, UNUSED int flags, void *ctx)
{
	fr_network_socket_t *s = ctx;
	fr_network_t *nr = talloc_parent(s);
	ssize_t data_size;
	fr_channel_data_t *cd;

	rad_assert(s->listen->app_io->fd(s->listen->app_io_instance) == sockfd);

	fr_log(nr->log, L_DBG, "network read");

	if (!s->cd) {
		cd = (fr_channel_data_t *) fr_message_reserve(s->ms, s->listen->app_io->default_message_size);
		if (!cd) {
			fr_log(nr->log, L_ERR, "Failed allocating message size %zd!", s->listen->app_io->default_message_size);

			/*
			 *	@todo - handle errors via transport callback
			 */
			_exit(1);
		}
	} else {
		cd = s->cd;
	}

	rad_assert(cd->m.data != NULL);
	rad_assert(cd->m.rb_size >= 256);

	/*
	 *	Read data from the network.
	 *
	 *	Return of 0 means "no data", which is fine for UDP.
	 *	For TCP, if an underlying read() on the TCP socket
	 *	returns 0, (which signals that the FD is no longer
	 *	usable) this function should return -1, so that the
	 *	network side knows that it needs to close the
	 *	connection.
	 */
	data_size = s->listen->app_io->read(s->listen->app_io_instance, &cd->packet_ctx, cd->m.data, cd->m.rb_size);
	if (data_size == 0) {
		fr_log(nr->log, L_DBG_ERR, "got no data from transport read");

		/*
		 *	Cache the message for later.  This is
		 *	important for stream sockets, which can do
		 *	partial reads into the current buffer.  We
		 *	need to be able to give the same buffer back
		 *	to the stream socket for subsequent reads.
		 *
		 *	Since we have a message set for each
		 *	fr_io_socket_t, no "head of line"
		 *	blocking issues can happen for stream sockets.
		 */
		s->cd = cd;
		return;
	}

	/*
	 *	Error: close the connection, and remove the fr_listen_t
	 */
	if (data_size < 0) {
		fr_log(nr->log, L_DBG_ERR, "error from transport read on socket %d", sockfd);
		talloc_free(s);
		return;
	}
	s->cd = NULL;

	fr_log(nr->log, L_DBG, "got packet size %zd", data_size);

	/*
	 *	Initialize the rest of the fields of the channel data.
	 */
	cd->m.when = fr_time();
	cd->priority = 0;
	cd->listen = s->listen;
	cd->request.start_time = &start_time; /* @todo - set by transport */

	start_time = cd->m.when;

	(void) fr_message_alloc(s->ms, &cd->m, data_size);

	if (!fr_network_send_request(nr, cd)) {
		fr_log(nr->log, L_ERR, "Failed sending packet to worker");
		fr_message_done(&cd->m);
	}
}


/** Write packets to the network.
 *
 * @param el the event list
 * @param sockfd the socket which is ready to write
 * @param flags returned by kevent.
 * @param ctx the network socket context.
 */
static void fr_network_write(UNUSED fr_event_list_t *el, UNUSED int sockfd, UNUSED int flags, void *ctx)
{
	fr_network_socket_t *s = ctx;

	if (s->listen->app_io->flush(s->listen->app_io_instance) < 0) {
		s->listen->app_io->error(s->listen->app_io_instance);
		talloc_free(s);
	}
}

/** Handle errors for a socket.
 *
 * @param el the event list
 * @param sockfd the socket which has a fatal error.
 * @param flags returned by kevent.
 * @param ctx the network socket context.
 */
static void fr_network_error(UNUSED fr_event_list_t *el, UNUSED int sockfd, UNUSED int flags, void *ctx)
{
	fr_network_socket_t *s = ctx;

	s->listen->app_io->error(s->listen->app_io_instance);
	talloc_free(s);
}

static int _network_socket_free(fr_network_socket_t *s)
{
	fr_network_t *nr = talloc_parent(s);

	fr_event_fd_delete(nr->el, s->listen->app_io->fd(s->listen->app_io_instance));

	rbtree_deletebydata(nr->sockets, s);

	if (s->listen->app_io->close) {
		s->listen->app_io->close(s->listen->app_io_instance);
	} else {
		close(s->listen->app_io->fd(s->listen->app_io_instance));
	}

	return 0;
}

/** Handle a network control message callback for a new socket
 *
 * @param[in] ctx the network
 * @param[in] data the message
 * @param[in] data_size size of the data
 * @param[in] now the current time
 */
static void fr_network_socket_callback(void *ctx, void const *data, size_t data_size, UNUSED fr_time_t now)
{
	int fd;
	fr_network_t *nr = ctx;
	fr_network_socket_t *s;
	fr_event_fd_handler_t write_fn, error_fn;

	rad_assert(data_size == sizeof(*s));

	if (data_size != sizeof(*s)) return;

	s = talloc(nr, fr_network_socket_t);
	rad_assert(s != NULL);
	memcpy(s, data, sizeof(*s));

	talloc_set_destructor(s, _network_socket_free);

#define MIN_MESSAGES (8)

	/*
	 *	@todo - make the default number of messages configurable?
	 */
	s->ms = fr_message_set_create(s, MIN_MESSAGES,
				      sizeof(fr_channel_data_t),
				      s->listen->app_io->default_message_size * MIN_MESSAGES);
	if (!s->ms) {
		fr_log(nr->log, L_ERR, "Failed creating message buffers for network IO.");

		/*
		 *	@todo - handle errors via transport callback
		 */
		_exit(1);
	}

	write_fn = error_fn = NULL;

	if (s->listen->app_io->flush) write_fn = fr_network_write;

	if (s->listen->app_io->error) error_fn = fr_network_error;

	fd = s->listen->app_io->fd(s->listen->app_io_instance);

	if (fr_event_fd_insert(nr->el, fd, fr_network_read, write_fn, error_fn, s) < 0) {
		fr_log(nr->log, L_ERR, "Failed adding new socket to event loop: %s", fr_strerror());
		talloc_free(s);
		return;
	}

	(void) rbtree_insert(nr->sockets, s);

	fr_log(nr->log, L_DBG, "Using new socket with FD %d", fd);
}


/** Handle a network control message callback for a new worker
 *
 * @param[in] ctx the network
 * @param[in] data the message
 * @param[in] data_size size of the data
 * @param[in] now the current time
 */
static void fr_network_worker_callback(void *ctx, void const *data, size_t data_size, UNUSED fr_time_t now)
{
	fr_network_t *nr = ctx;
	fr_worker_t *worker;
	fr_network_worker_t *w;

	rad_assert(data_size == sizeof(worker));

	memcpy(&worker, data, data_size);
	(void) talloc_get_type_abort(worker, fr_worker_t);

	w = talloc_zero(nr, fr_network_worker_t);
	if (!w) _exit(1);

	w->worker = worker;
	w->channel = fr_worker_channel_create(worker, w, nr->control);
	if (!w->channel) _exit(1);

	fr_channel_master_ctx_add(w->channel, w);

	(void) fr_heap_insert(nr->workers, w);
}


/** Service a control-plane event.
 *
 * @param[in] kq the kq to service
 * @param[in] kev the kevent to service
 * @param[in] ctx the fr_worker_t
 */
static void fr_network_evfilt_user(UNUSED int kq, struct kevent const *kev, void *ctx)
{
	fr_time_t now;
	fr_network_t *nr = talloc_get_type_abort(ctx, fr_network_t);
	uint8_t data[256];

	if (!fr_control_message_service_kevent(nr->control, kev)) {
		fr_log(nr->log, L_DBG, "kevent not for us: ignoring");
		return;
	}

	now = fr_time();

	/*
	 *	Service all available control-plane events
	 */
	fr_control_service(nr->control, data, sizeof(data), now);
}


/** Create a network
 *
 * @param[in] ctx the talloc ctx
 * @param[in] logger the destination for all logging messages
 * @return
 *	- NULL on error
 *	- fr_network_t on success
 */
fr_network_t *fr_network_create(TALLOC_CTX *ctx, fr_log_t *logger)
{
	fr_network_t *nr;

	nr = talloc_zero(ctx, fr_network_t);
	if (!nr) {
	nomem:
		fr_strerror_printf("Failed allocating memory");
		return NULL;
	}

	nr->el = fr_event_list_alloc(nr, fr_network_idle, nr);
	if (!nr->el) {
		fr_strerror_printf("Failed creating event list: %s", fr_strerror());
		talloc_free(nr);
		return NULL;
	}

	nr->log = logger;

	nr->kq = fr_event_list_kq(nr->el);
	rad_assert(nr->kq >= 0);

	nr->aq_control = fr_atomic_queue_create(nr, 1024);
	if (!nr->aq_control) {
		talloc_free(nr);
		goto nomem;
	}

	nr->control = fr_control_create(nr, nr->kq, nr->aq_control);
	if (!nr->control) {
		fr_strerror_printf("Failed creating control queue: %s", fr_strerror());
		talloc_free(nr);
		return NULL;
	}

	nr->rb = fr_ring_buffer_create(nr, FR_CONTROL_MAX_MESSAGES * FR_CONTROL_MAX_SIZE);
	if (!nr->rb) {
		fr_strerror_printf("Failed creating ring buffer: %s", fr_strerror());
		talloc_free(nr);
		return NULL;
	}

	if (fr_control_callback_add(nr->control, FR_CONTROL_ID_CHANNEL, nr, fr_network_channel_callback) < 0) {
		fr_strerror_printf("Failed adding channel callback: %s", fr_strerror());
		talloc_free(nr);
		return NULL;
	}

	if (fr_control_callback_add(nr->control, FR_CONTROL_ID_SOCKET, nr, fr_network_socket_callback) < 0) {
		fr_strerror_printf("Failed adding socket callback: %s", fr_strerror());
		talloc_free(nr);
		return NULL;
	}

	if (fr_control_callback_add(nr->control, FR_CONTROL_ID_WORKER, nr, fr_network_worker_callback) < 0) {
		fr_strerror_printf("Failed adding worker callback: %s", fr_strerror());
		talloc_free(nr);
		return NULL;
	}

	if (fr_event_user_insert(nr->el, fr_network_evfilt_user, nr) < 0) {
		fr_strerror_printf("Failed updating event list: %s", fr_strerror());
		talloc_free(nr);
		return NULL;
	}

	/*
	 *	Create the various heaps.
	 */
	nr->sockets = rbtree_create(nr, socket_cmp, NULL, RBTREE_FLAG_NONE);
	if (!nr->sockets) {
		talloc_free(nr);
		goto nomem;
	}

	nr->replies = fr_heap_create(reply_cmp, offsetof(fr_channel_data_t, channel.heap_id));
	if (!nr->replies) {
		talloc_free(nr);
		goto nomem;
	}

	nr->workers = fr_heap_create(worker_cmp, offsetof(fr_network_worker_t, heap_id));
	if (!nr->workers) {
		talloc_free(nr);
		goto nomem;
	}

	nr->closing = fr_heap_create(worker_cmp, offsetof(fr_network_worker_t, heap_id));
	if (!nr->closing) {
		talloc_free(nr);
		goto nomem;
	}

#ifdef HAVE_PTHREAD_H
	if (pthread_mutex_init(&nr->mutex, NULL) != 0) {
		fr_strerror_printf("Failed initializing mutex");
		talloc_free(nr);
		return NULL;
	}
#endif

	if (fr_event_post_insert(nr->el, fr_network_post_event, nr) < 0) {
		fr_strerror_printf("Failed inserting post-processing event");
		talloc_free(nr);
		return NULL;
	}

	return nr;
}


/** Destroy a network
 *
 * @param[in] nr the network
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_network_destroy(fr_network_t *nr)
{
	fr_network_worker_t *worker;
	fr_channel_data_t *cd;

	(void) talloc_get_type_abort(nr, fr_network_t);
	rad_assert(nr->closing);

	/*
	 *	Pop all of the workers, and signal them that we're
	 *	closing/
	 */
	while ((worker = fr_heap_pop(nr->workers)) != NULL) {
		fr_channel_signal_worker_close(worker->channel);
		(void) fr_heap_insert(nr->closing, worker);
	}

	/*
	 *	@todo wait for all workers to acknowledge the channel
	 *	close.
	 */

	/*
	 *	Clean up all of the replies.
	 *
	 *	@todo - call transport "done" for the reply, so that
	 *	it knows the replies are done, too.
	 */
	while ((cd = fr_heap_pop(nr->replies)) != NULL) {
		fr_message_done(&cd->m);
	}

	(void) fr_event_post_delete(nr->el, fr_network_post_event, nr);

	talloc_free(nr);

	return 0;
}

/** Handle replies after all FD and timer events have been serviced
 *
 * @param el	the event loop
 * @param now	the current time (mostly)
 * @param uctx	the fr_network_t
 */
static void fr_network_post_event(UNUSED fr_event_list_t *el, UNUSED struct timeval *now, void *uctx)
{
	fr_channel_data_t *cd;
	fr_network_t *nr = talloc_get_type_abort(uctx, fr_network_t);

	while ((cd = fr_heap_pop(nr->replies)) != NULL) {
		ssize_t rcode;
		fr_listen_t const *listen;

		listen = cd->listen;

		/*
		 *	@todo - call transport "recv reply".  And if
		 *	the reply is a NAK, don't write it to the
		 *	network.
		 */
		rcode = listen->app_io->write(listen->app_io_instance, cd->packet_ctx, cd->m.data, cd->m.data_size);
		if (rcode < 0) {
			fr_network_socket_t my_socket, *s;

			/*
			 *	Tell the socket that there was an error.
			 *
			 *	Don't call close, as that will be done
			 *	in the destructor.
			 */
			if (listen->app_io->error) listen->app_io->error(listen->app_io_instance);

			my_socket.listen = listen;
			s = rbtree_finddata(nr->sockets, &my_socket);
			if (s) talloc_free(s);
			continue;
		}

		if ((size_t) rcode < cd->m.data_size) {
			// call write function again at some later date.
		}

		fr_log(nr->log, L_DBG, "Sending reply to socket %d",
		       cd->listen->app_io->fd(cd->listen->app_io_instance));
		fr_message_done(&cd->m);
	}
}


/** The main network worker function.
 *
 * @param[in] nr the network data structure to run.
 */
void fr_network(fr_network_t *nr)
{
	while (true) {
		bool wait_for_event;
		int num_events;

		/*
		 *	There are runnable requests.  We still service
		 *	the event loop, but we don't wait for events.
		 */
		wait_for_event = (fr_heap_num_elements(nr->replies) == 0);
		fr_log(nr->log, L_DBG, "Waiting for events %d", wait_for_event);

		/*
		 *	Check the event list.  If there's an error
		 *	(e.g. exit), we stop looping and clean up.
		 */
		num_events = fr_event_corral(nr->el, wait_for_event);
		fr_log(nr->log, L_DBG, "Got num_events %d", num_events);
		if (num_events < 0) break;

		/*
		 *	Service outstanding events.
		 */
		if (num_events > 0) {
			fr_log(nr->log, L_DBG, "servicing events");
			fr_event_service(nr->el);
		}
	}
}

/** Signal a reciever to exit
 *
 *  WARNING: This may be called from another thread!  Care is required.
 *
 * @param[in] nr the network data structure to manage
 */
void fr_network_exit(fr_network_t *nr)
{
	fr_event_loop_exit(nr->el, 1);
}

/** Add a socket to a network
 *
 * @param nr		the network
 * @param listen	Functions and context.
 */
int fr_network_socket_add(fr_network_t *nr, fr_listen_t const *listen)
{
	int rcode;
	fr_network_socket_t m;

	memset(&m, 0, sizeof(m));
	m.listen = listen;

	PTHREAD_MUTEX_LOCK(&nr->mutex);
	rcode = fr_control_message_send(nr->control, nr->rb, FR_CONTROL_ID_SOCKET, &m, sizeof(m));
	PTHREAD_MUTEX_UNLOCK(&nr->mutex);

	return rcode;
}

/** Add a worker to a network
 *
 * @param nr the network
 * @param worker the worker
 */
int fr_network_worker_add(fr_network_t *nr, fr_worker_t *worker)
{
	int rcode;

	(void) talloc_get_type_abort(nr, fr_network_t);
	(void) talloc_get_type_abort(worker, fr_worker_t);

	PTHREAD_MUTEX_LOCK(&nr->mutex);
	rcode = fr_control_message_send(nr->control, nr->rb, FR_CONTROL_ID_WORKER, &worker, sizeof(worker));
	PTHREAD_MUTEX_UNLOCK(&nr->mutex);

	return rcode;
}
