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

/*
 *	Define our own debugging.
 */
#undef DEBUG
#undef DEBUG2
#undef DEBUG3
#undef ERROR

#define DEBUG(fmt, ...) if (nr->lvl) fr_log(nr->log, L_DBG, fmt, ## __VA_ARGS__)
//#define DEBUG2(fmt, ...) if (nr->lvl >= L_DBG_LVL_2) fr_log(nr->log, L_DBG, fmt, ## __VA_ARGS__)
#define DEBUG3(fmt, ...) if (nr->lvl >= L_DBG_LVL_3) fr_log(nr->log, L_DBG, fmt, ## __VA_ARGS__)
#define ERROR(fmt, ...) fr_log(nr->log, L_ERR, fmt, ## __VA_ARGS__)

#define MAX_WORKERS 32

typedef struct fr_network_worker_t {
	int			heap_id;		//!< workers are in a heap
	fr_time_t		cpu_time;		//!< how much CPU time this worker has spent
	fr_time_t		predicted;		//!< predicted processing time for one packet

	fr_channel_t		*channel;		//!< channel to the worker
	fr_worker_t		*worker;		//!< worker pointer
} fr_network_worker_t;

typedef struct fr_network_socket_t {
	int			fd;			//!< file descriptor

	fr_listen_t const	*listen;		//!< I/O ctx and functions.

	fr_message_set_t	*ms;			//!< message buffers for this socket.
	fr_channel_data_t	*cd;			//!< cached in case of allocation & read error
	size_t			leftover;		//!< leftover data from a previous read

	fr_channel_data_t	*pending;		//!< the currently pending partial packet
	fr_heap_t		*waiting;		//!< packets waiting to be written

	fr_dlist_t		entry;			//!< for deleted sockets
} fr_network_socket_t;

/*
 *	We have an array of workers, so we can index the workers in
 *	O(1) time.  remove the heap of "workers ordered by CPU time"
 *	when we send a packet to a worker, just update the predicted
 *	CPU time in place.  when we receive a reply from a worker,
 *	just update the predicted CPU time in place.
 *
 *	when we need to choose a worker, pick 2 at random, and then
 *	choose the one with the lowe cpu time.  For background, see
 *	"Power of Two-Choices" and
 *	https://www.eecs.harvard.edu/~michaelm/postscripts/mythesis.pdf
 *	https://www.eecs.harvard.edu/~michaelm/postscripts/tpds2001.pdf
 */
struct fr_network_t {
	int			kq;			//!< our KQ

	fr_log_t const		*log;			//!< log destination
	fr_log_lvl_t		lvl;			//!< debug log level

	fr_atomic_queue_t	*aq_control;		//!< atomic queue for control messages sent to me

	uintptr_t		aq_ident;		//!< identifier for control-plane events

	fr_control_t		*control;		//!< the control plane

	fr_ring_buffer_t	*rb;			//!< ring buffer for my control-plane messages

	fr_event_list_t		*el;			//!< our event list

	fr_heap_t		*replies;		//!< replies from the worker, ordered by priority / origin time

	uint64_t		num_requests;		//!< number of requests we sent
	uint64_t		num_replies;		//!< number of replies we received

	rbtree_t		*sockets;		//!< list of sockets we're managing

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		mutex;			//!< for sending us control messages
#endif

	int			num_workers;		//!< number of active workers
	int			max_workers;		//!< maximum number of allowed workers

	fr_network_worker_t	*workers[MAX_WORKERS]; 	//!< each worker
};

static void fr_network_post_event(fr_event_list_t *el, struct timeval *now, void *uctx);

static int reply_cmp(void const *one, void const *two)
{
	fr_channel_data_t const *a = one, *b = two;
	int ret;

	ret = (a->priority > b->priority) - (a->priority < b->priority);
	if (ret != 0) return ret;

	return (a->m.when > b->m.when) - (a->m.when < b->m.when);
}

static int waiting_cmp(void const *one, void const *two)
{
	fr_channel_data_t const *a = one, *b = two;
	int ret;

	ret = (a->priority > b->priority) - (a->priority < b->priority);
	if (ret != 0) return ret;

	return (a->reply.request_time > b->reply.request_time) - (a->reply.request_time < b->reply.request_time);
}

static int socket_cmp(void const *one, void const *two)
{
	fr_network_socket_t const *a = one, *b = two;

	return (a->listen > b->listen) - (a->listen < b->listen);
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
	fr_network_worker_t *worker;

	if (!cd) {
		cd = fr_channel_recv_reply(ch);
		if (!cd) {
			return;
		}
	}

	do {
		nr->num_replies++;
		DEBUG3("received reply %zd", nr->num_replies);

		cd->channel.ch = ch;

		/*
		 *	Update stats for the worker.
		 */
		worker = fr_channel_master_ctx_get(ch);
		worker->cpu_time = cd->reply.cpu_time;
		if (!worker->predicted) {
			worker->predicted = cd->reply.processing_time;
		} else {
			worker->predicted = RTT(worker->predicted, cd->reply.processing_time);
		}

		(void) fr_heap_insert(nr->replies, cd);
	} while ((cd = fr_channel_recv_reply(ch)) != NULL);
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
		DEBUG3("error <--");
		return;

	case FR_CHANNEL_EMPTY:
		DEBUG3("... <--");
		return;

	case FR_CHANNEL_NOOP:
		DEBUG3("noop <--");
		break;

	case FR_CHANNEL_DATA_READY_NETWORK:
		rad_assert(ch != NULL);
		DEBUG3("data <--");
		fr_network_drain_input(nr, ch, NULL);
		break;

	case FR_CHANNEL_DATA_READY_WORKER:
		rad_assert(0 == 1);
		DEBUG3("worker ??? <--");
		break;

	case FR_CHANNEL_OPEN:
		rad_assert(0 == 1);
		DEBUG3("channel open ?");
		break;

	case FR_CHANNEL_CLOSE:
		DEBUG3("close <--");
		///
		break;
	}
}

/** Send a message on the "best" channel.
 *
 * @param nr the network
 * @param cd the message we've received
 */
static bool fr_network_send_request(fr_network_t *nr, fr_channel_data_t *cd)
{
	uint32_t one, two;
	fr_network_worker_t *worker;
	fr_channel_data_t *reply;

	(void) talloc_get_type_abort(nr, fr_network_t);

	one = fr_rand() % nr->num_workers;
	two = fr_rand() % nr->num_workers;

	if (nr->workers[one]->cpu_time < nr->workers[one]->cpu_time) {
		worker = nr->workers[one];
	} else {
		worker = nr->workers[two];
	}

	(void) talloc_get_type_abort(worker, fr_network_worker_t);

	/*
	 *	Send the message to the channel.  If we fail, drop the
	 *	packet.  The only reason for failure is that the
	 *	worker isn't servicing it's input queue.  When that
	 *	happens, we have no idea what to do, and the whole
	 *	thing falls over.
	 */
	if (fr_channel_send_request(worker->channel, cd, &reply) < 0) {
		return false;
	}

	/*
	 *	We're projecting that the worker will use more CPU
	 *	time to process this request.  The CPU time will be
	 *	updated with a more accurate number when we receive a
	 *	reply from this channel.
	 */
	worker->cpu_time += worker->predicted;

	/*
	 *	If we have a reply, push it onto our local queue, and
	 *	poll for more replies.
	 */
	if (reply) fr_network_drain_input(nr, worker->channel, reply);

	return true;
}


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
	fr_channel_data_t *cd, *next;
	fr_time_t *recv_time;

	rad_assert(s->fd == sockfd);

	DEBUG3("network read");

	if (!s->cd) {
		cd = (fr_channel_data_t *) fr_message_reserve(s->ms, s->listen->default_message_size);
		if (!cd) {
			fr_log(nr->log, L_ERR, "Failed allocating message size %zd! - Closing socket", s->listen->default_message_size);
			talloc_free(s);
			return;
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
next_message:
	data_size = s->listen->app_io->read(s->listen->app_io_instance, &cd->packet_ctx, &recv_time,
					    cd->m.data, cd->m.rb_size, &s->leftover, &cd->priority);
	if (data_size == 0) {
//		fr_log(nr->log, L_DBG_ERR, "got no data from transport read");

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

	DEBUG("Network received packet size %zd", data_size);

	/*
	 *	Initialize the rest of the fields of the channel data.
	 *
	 *	We always use "now" as the time of the message, as the
	 *	packet MAY be a duplicate packet magically resurrected
	 *	from the past.
	 */
	cd->m.when = fr_time();
	cd->listen = s->listen;
	cd->request.recv_time = recv_time;

	/*
	 *	Nothing in the buffer yet.  Allocate room for one
	 *	packet.
	 */
	if ((cd->m.data_size == 0) && (!s->leftover)) {

		(void) fr_message_alloc(s->ms, &cd->m, data_size);
		next = NULL;

	} else {
		/*
		 *	There are leftover bytes in the buffer, feed
		 *	them to the next round of reading.
		 */
		next = (fr_channel_data_t *) fr_message_alloc_reserve(s->ms, &cd->m, data_size, s->listen->default_message_size);
		if (!next) {
			fr_log(nr->log, L_ERR, "Failed reserving partial packet.");
			// @todo - probably close the socket...
			rad_assert(0 == 1);
		}
	}

	if (!fr_network_send_request(nr, cd)) {
		fr_log(nr->log, L_ERR, "Failed sending packet to worker");
		fr_message_done(&cd->m);
	}

	/*
	 *	If there is a next message, go read it from the buffer.
	 */
	if (next) {
		cd = next;
		goto next_message;
	}
}


/** Get a notification that a vnode changed
 *
 * @param[in] el	the event list.
 * @param[in] sockfd	the socket which is ready to read.
 * @param[in] fflags	from kevent.
 * @param[in] ctx	the network socket context.
 */
static void fr_network_vnode_extend(UNUSED fr_event_list_t *el, int sockfd, int fflags, void *ctx)
{
	fr_network_socket_t *s = ctx;
	fr_network_t *nr = talloc_parent(s);

	rad_cond_assert(s->fd == sockfd);

	DEBUG3("network vnode");

	/*
	 *	Tell the IO handler that something has happened to the
	 *	file.
	 */
	s->listen->app_io->vnode(s->listen->app_io_instance, fflags);
}


/** Handle errors for a socket.
 *
 * @param[in] el		the event list
 * @param[in] sockfd		the socket which has a fatal error.
 * @param[in] flags		returned by kevent.
 * @param[in] fd_errno		returned by kevent.
 * @param[in] ctx		the network socket context.
 */
static void fr_network_error(UNUSED fr_event_list_t *el, UNUSED int sockfd, UNUSED int flags,
			     UNUSED int fd_errno, void *ctx)
{
	fr_network_socket_t *s = ctx;

	s->listen->app_io->error(s->listen->app_io_instance);
	talloc_free(s);
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
	fr_listen_t const *listen = s->listen;
	fr_network_t *nr;
	fr_channel_data_t *cd;

	nr = talloc_parent(s);
	(void) talloc_get_type_abort(nr, fr_network_t);

	rad_assert(s->pending != NULL);

	/*
	 *	Start with the currently pending message, and then
	 *	work through the priority heap.
	 */
	for (cd = s->pending;
	     cd != NULL;
	     cd = fr_heap_pop(s->waiting)) {
		int rcode;

		rad_assert(listen == cd->listen);

		rcode = listen->app_io->write(listen->app_io_instance, cd->packet_ctx,
					      cd->reply.request_time, cd->m.data, cd->m.data_size);
		if (rcode < 0) {

			/*
			 *	Stop processing the heap, and set the
			 *	pending message to the current one.
			 */
			if (errno == EWOULDBLOCK) {
				s->pending = cd;
				return;
			}

			ERROR("Failed writing to socket %d: %s", s->fd, fr_strerror());
			talloc_free(s);
			return;
		}

		fr_message_done(&cd->m);

		/*
		 *	As a special case, allow write() to return
		 *	"0", which means "close the socket".
		 */
		if (rcode == 0) talloc_free(s);
	}

	/*
	 *	We've successfully written all of the packets.  Remove
	 *	the write callback.
	 */
	if (fr_event_fd_insert(nr, nr->el, s->fd,
			       fr_network_read,
			       NULL,
			       listen->app_io->error ? fr_network_error : NULL,
			       s) < 0) {
		ERROR("Failed adding new socket to event loop: %s", fr_strerror());
		talloc_free(s);
	}
}

static int _network_socket_free(fr_network_socket_t *s)
{
	fr_network_t *nr = talloc_parent(s);
	fr_channel_data_t *cd;

	fr_event_fd_delete(nr->el, s->fd, FR_EVENT_FILTER_IO);

	rbtree_deletebydata(nr->sockets, s);

	if (s->listen->app_io->close) {
		s->listen->app_io->close(s->listen->app_io_instance);
	} else {
		close(s->fd);
	}

	if (s->pending) {
		fr_message_done(&s->pending->m);
		s->pending = NULL;
	}

	/*
	 *	Clean up any queued entries.
	 */
	while ((cd = fr_heap_pop(s->waiting)) != NULL) {
		fr_message_done(&cd->m);
	}

	talloc_free(s->waiting);

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
	fr_network_t		*nr = ctx;
	fr_network_socket_t	*s;
	fr_app_io_t const	*app_io;
	size_t			size;

	rad_assert(data_size == sizeof(*s));

	if (data_size != sizeof(*s)) return;

	s = talloc(nr, fr_network_socket_t);
	rad_assert(s != NULL);
	memcpy(s, data, sizeof(*s));

	MEM(s->waiting = fr_heap_create(waiting_cmp, offsetof(fr_channel_data_t, channel.heap_id)));
	FR_DLIST_INIT(s->entry);

	talloc_set_destructor(s, _network_socket_free);

	/*
	 *	Put reasonable limits on the ring buffer size.  Then
	 *	round it up to the nearest power of 2, which is
	 *	required by the ring buffer code.
	 */
	size = s->listen->default_message_size * s->listen->num_messages;
	if (!size) size = (1 << 17);
	if (size > (1 << 30)) size = (1 << 30);

	size--;
	size |= size >> 1;
	size |= size >> 2;
	size |= size >> 4;
	size |= size >> 8;
	size |= size >> 16;
	size++;

	/*
	 *	Allocate the ring buffer for messages and packets.
	 */
	s->ms = fr_message_set_create(s, s->listen->num_messages,
				      sizeof(fr_channel_data_t),
				      size);
	if (!s->ms) {
		fr_log(nr->log, L_ERR, "Failed creating message buffers for network IO: %s", fr_strerror());
		talloc_free(s);
		return;
	}

	app_io = s->listen->app_io;

	if (app_io->event_list_set) app_io->event_list_set(s->listen->app_io_instance, nr->el);

	rad_assert(app_io->fd);
	s->fd = app_io->fd(s->listen->app_io_instance);

	if (fr_event_fd_insert(nr, nr->el, s->fd,
			       fr_network_read,
			       NULL,
			       app_io->error ? fr_network_error : NULL,
			       s) < 0) {
		ERROR("Failed adding new socket to event loop: %s", fr_strerror());
		talloc_free(s);
		return;
	}

	(void) rbtree_insert(nr->sockets, s);

	DEBUG3("Using new socket with FD %d", s->fd);
}

/** Handle a network control message callback for a new "watch directory"
 *
 * @param[in] ctx the network
 * @param[in] data the message
 * @param[in] data_size size of the data
 * @param[in] now the current time
 */
static void fr_network_directory_callback(void *ctx, void const *data, size_t data_size, UNUSED fr_time_t now)
{
	fr_network_t		*nr = ctx;
	fr_network_socket_t	*s;
	fr_app_io_t const	*app_io;
	fr_event_vnode_func_t	funcs = { .extend = fr_network_vnode_extend };

	rad_assert(data_size == sizeof(*s));

	if (data_size != sizeof(*s)) return;

	s = talloc(nr, fr_network_socket_t);
	rad_assert(s != NULL);
	memcpy(s, data, sizeof(*s));

	MEM(s->waiting = fr_heap_create(waiting_cmp, offsetof(fr_channel_data_t, channel.heap_id)));
	FR_DLIST_INIT(s->entry);

	talloc_set_destructor(s, _network_socket_free);

	/*
	 *	Allocate the ring buffer for messages and packets.
	 */
	s->ms = fr_message_set_create(s, s->listen->num_messages,
				      sizeof(fr_channel_data_t),
				      s->listen->default_message_size * s->listen->num_messages);
	if (!s->ms) {
		fr_log(nr->log, L_ERR, "Failed creating message buffers for directory IO.  Closing socket.");
		talloc_free(s);
		return;
	}

	app_io = s->listen->app_io;

	if (app_io->event_list_set) app_io->event_list_set(s->listen->app_io_instance, nr->el);

	rad_assert(app_io->fd);
	s->fd = app_io->fd(s->listen->app_io_instance);

	if (fr_event_filter_insert(nr, nr->el, s->fd, FR_EVENT_FILTER_VNODE,
				   &funcs,
				   app_io->error ? fr_network_error : NULL,
				   s) < 0) {
		ERROR("Failed adding new socket to event loop: %s", fr_strerror());
		talloc_free(s);
		return;
	}

	(void) rbtree_insert(nr->sockets, s);

	DEBUG3("Using new socket with FD %d", s->fd);
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
	int i;
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

	/*
	 *	Insert the worker into the array of workers.
	 */
	for (i = 0; i < nr->max_workers; i++) {
		if (nr->workers[i]) continue;

		nr->workers[i] = w;
		nr->num_workers++;
		return;
	}

	/*
	 *	Run out of room to put workers!
	 */
	rad_assert(0 == 1);
}


/** Service a control-plane event.
 *
 * @param[in] kq the kq to service
 * @param[in] kev the kevent to service
 * @param[in] ctx the fr_worker_t
 */
static void fr_network_evfilt_user(UNUSED int kq, UNUSED struct kevent const *kev, void *ctx)
{
	fr_time_t now;
	fr_network_t *nr = talloc_get_type_abort(ctx, fr_network_t);
	uint8_t data[256];

	now = fr_time();

	/*
	 *	Service all available control-plane events
	 */
	fr_control_service(nr->control, data, sizeof(data), now);
}


/** Create a network
 *
 * @param[in] ctx the talloc ctx
 * @param[in] el the event list
 * @param[in] logger the destination for all logging messages
 * @param[in] lvl log level
 * @return
 *	- NULL on error
 *	- fr_network_t on success
 */
fr_network_t *fr_network_create(TALLOC_CTX *ctx, fr_event_list_t *el, fr_log_t const *logger, fr_log_lvl_t lvl)
{
	fr_network_t *nr;

	nr = talloc_zero(ctx, fr_network_t);
	if (!nr) {
		fr_strerror_printf("Failed allocating memory");
		return NULL;
	}

	nr->el = el;
	nr->log = logger;
	nr->lvl = lvl;
	nr->max_workers = MAX_WORKERS;
	nr->num_workers = 0;

	nr->kq = fr_event_list_kq(nr->el);
	rad_assert(nr->kq >= 0);

	nr->aq_control = fr_atomic_queue_create(nr, 1024);
	if (!nr->aq_control) {
		talloc_free(nr);
		return NULL;
	}

	nr->aq_ident = fr_event_user_insert(nr->el, fr_network_evfilt_user, nr);
	if (!nr->aq_ident) {
		fr_strerror_printf("Failed updating event list: %s", fr_strerror());
		talloc_free(nr);
		return NULL;
	}


	nr->control = fr_control_create(nr, nr->kq, nr->aq_control, nr->aq_ident);
	if (!nr->control) {
		fr_strerror_printf("Failed creating control queue: %s", fr_strerror());
	fail:
		(void) fr_event_user_delete(nr->el, fr_network_evfilt_user, nr);
		talloc_free(nr);
		return NULL;
	}

	nr->rb = fr_ring_buffer_create(nr, FR_CONTROL_MAX_MESSAGES * FR_CONTROL_MAX_SIZE);
	if (!nr->rb) {
		fr_strerror_printf("Failed creating ring buffer: %s", fr_strerror());
	fail2:
		fr_control_free(nr->control);
		goto fail;
	}

	if (fr_control_callback_add(nr->control, FR_CONTROL_ID_CHANNEL, nr, fr_network_channel_callback) < 0) {
		fr_strerror_printf("Failed adding channel callback: %s", fr_strerror());
		goto fail2;
	}

	if (fr_control_callback_add(nr->control, FR_CONTROL_ID_SOCKET, nr, fr_network_socket_callback) < 0) {
		fr_strerror_printf("Failed adding socket callback: %s", fr_strerror());
		goto fail2;
	}

	if (fr_control_callback_add(nr->control, FR_CONTROL_ID_DIRECTORY, nr, fr_network_directory_callback) < 0) {
		fr_strerror_printf("Failed adding socket callback: %s", fr_strerror());
		goto fail2;
	}

	if (fr_control_callback_add(nr->control, FR_CONTROL_ID_WORKER, nr, fr_network_worker_callback) < 0) {
		fr_strerror_printf("Failed adding worker callback: %s", fr_strerror());
		goto fail2;
	}

	/*
	 *	Create the various heaps.
	 */
	nr->sockets = rbtree_create(nr, socket_cmp, NULL, RBTREE_FLAG_NONE);
	if (!nr->sockets) {
		fr_strerror_printf("Failed creating tree for sockets: %s", fr_strerror());
		goto fail2;
	}

	nr->replies = fr_heap_create(reply_cmp, offsetof(fr_channel_data_t, channel.heap_id));
	if (!nr->replies) {
		fr_strerror_printf("Failed creating heap for replies: %s", fr_strerror());
		goto fail2;
	}

#ifdef HAVE_PTHREAD_H
	if (pthread_mutex_init(&nr->mutex, NULL) != 0) {
		fr_strerror_printf("Failed initializing mutex");
		goto fail2;
	}
#endif

	if (fr_event_post_insert(nr->el, fr_network_post_event, nr) < 0) {
		fr_strerror_printf("Failed inserting post-processing event");
		goto fail2;
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
	int i;
	fr_channel_data_t *cd;

	(void) talloc_get_type_abort(nr, fr_network_t);

	/*
	 *	Pop all of the workers, and signal them that we're
	 *	closing/
	 */
	for (i = 0; i < nr->num_workers; i++) {
		fr_network_worker_t *worker = nr->workers[i];

		fr_channel_signal_worker_close(worker->channel);
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
	fr_dlist_t died, *entry;

	FR_DLIST_INIT(died);

	while ((cd = fr_heap_pop(nr->replies)) != NULL) {
		ssize_t rcode;
		fr_listen_t const *listen;
		fr_message_t *lm;
		fr_network_socket_t my_socket, *s;

		listen = cd->listen;

		/*
		 *	@todo - cache this somewhere so we don't need
		 *	to do an rbtree lookup for every packet.
		 */
		my_socket.listen = listen;
		s = rbtree_finddata(nr->sockets, &my_socket);

		/*
		 *	Socket is dead.  Ignore all packets for it.
		 */
		if (!s) {
			fr_message_done(&cd->m);
			continue;
		}

		/*
		 *	No data to write to the socket, so we skip it.
		 */
		if (!cd->m.data_size) {
			fr_message_done(&cd->m);
			continue;
		}

		/*
		 *	There are queued entries for this socket.
		 *	Append the packet into the list of packets to
		 *	write.
		 *
		 *	For sanity, we localize the message first.
		 *	Doing so ensures that the worker has it's
		 *	message buffers cleaned up quickly.
		 */
		if (s->pending) {
			lm = fr_message_localize(s, &cd->m, sizeof(*cd));
			fr_message_done(&cd->m);

			if (!lm) {
				ERROR("Failed copying packet.  Discarding it.");
				continue;
			}

			cd = (fr_channel_data_t *) lm;
			(void) fr_heap_insert(s->waiting, cd);
			continue;
		}

		/*
		 *	The write function is responsible for ensuring
		 *	that NAKs are not written to the network.
		 */
		rcode = listen->app_io->write(listen->app_io_instance, cd->packet_ctx,
					      cd->reply.request_time, cd->m.data, cd->m.data_size);
		if (rcode < 0) {
			if (errno == EWOULDBLOCK) {
				if (fr_event_fd_insert(nr, nr->el, s->fd,
						       fr_network_read,
						       fr_network_write,
						       listen->app_io->error ? fr_network_error : NULL,
						       s) < 0) {
					ERROR("Failed adding write callback to event loop: %s", fr_strerror());
					goto error;
				}

				/*
				 *	Localize the message, and add
				 *	it as the current pending /
				 *	partially written packet.
				 */
				lm = fr_message_localize(s, &cd->m, sizeof(*cd));
				fr_message_done(&cd->m);
				if (!lm) {
					ERROR("Failed copying packet.  Discarding it.");
					continue;
				}

				cd = (fr_channel_data_t *) lm;
				s->pending = cd;
				continue;
			}

			/*
			 *	Tell the socket that there was an error.
			 *
			 *	Don't call close, as that will be done
			 *	in the destructor.
			 */
			ERROR("Failed writing to socket %d: %s", s->fd, fr_strerror());
		error:
			fr_message_done(&cd->m);
			if (listen->app_io->error) listen->app_io->error(listen->app_io_instance);

			rbtree_deletebydata(nr->sockets, s);
			fr_dlist_insert_tail(&died, &s->entry);
			continue;
		}

		/*
		 *	We MUST have written all of the data.  It is
		 *	up to the app_io->write() function to track
		 *	any partially written data.
		 */
		rad_assert(!rcode || (size_t) rcode == cd->m.data_size);

		DEBUG3("Sending reply to socket %d", s->fd);
		fr_message_done(&cd->m);

		/*
		 *	As a special case, allow write() to return
		 *	"0", which means "close the socket".
		 */
		if (rcode == 0) talloc_free(s);
	}

	/*
	 *	Walk over the dead sockets, and delete them.
	 */
	while ((entry = FR_DLIST_FIRST(died)) != NULL) {
		fr_network_socket_t *s;

		s = fr_ptr_to_type(fr_network_socket_t, entry, entry);
		fr_dlist_remove(&s->entry);
		talloc_free(s);
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
		DEBUG("Waiting for events %d", wait_for_event);

		/*
		 *	Check the event list.  If there's an error
		 *	(e.g. exit), we stop looping and clean up.
		 */
		num_events = fr_event_corral(nr->el, wait_for_event);
		DEBUG3("Got num_events %d", num_events);
		if (num_events < 0) break;

		/*
		 *	Service outstanding events.
		 */
		if (num_events > 0) {
			DEBUG3("servicing events");
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

/** Add a "watch directory" call to a network
 *
 * @param nr		the network
 * @param listen	Functions and context.
 */
int fr_network_directory_add(fr_network_t *nr, fr_listen_t const *listen)
{
	int rcode;
	fr_network_socket_t m;

	memset(&m, 0, sizeof(m));
	m.listen = listen;

	PTHREAD_MUTEX_LOCK(&nr->mutex);
	rcode = fr_control_message_send(nr->control, nr->rb, FR_CONTROL_ID_DIRECTORY, &m, sizeof(m));
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
