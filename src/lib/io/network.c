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
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#define LOG_PREFIX "%s - "
#define LOG_PREFIX_ARGS nr->name

#define LOG_DST nr->log

#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/talloc.h>

#include <freeradius-devel/io/channel.h>
#include <freeradius-devel/io/control.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/network.h>
#include <freeradius-devel/io/queue.h>
#include <freeradius-devel/io/ring_buffer.h>
#include <freeradius-devel/io/worker.h>

#define MAX_WORKERS 64

static _Thread_local fr_ring_buffer_t *fr_network_rb;

typedef struct {
	fr_listen_t		*listen;
	uint8_t			*packet;
	size_t			packet_len;
	fr_time_t		recv_time;
} fr_network_inject_t;

/** Associate a worker thread with a network thread
 *
 */
typedef struct {
	fr_heap_index_t		heap_id;		//!< workers are in a heap
	fr_time_delta_t		cpu_time;		//!< how much CPU time this worker has spent
	fr_time_delta_t		predicted;		//!< predicted processing time for one packet

	bool			blocked;		//!< is this worker blocked?

	fr_channel_t		*channel;		//!< channel to the worker
	fr_worker_t		*worker;		//!< worker pointer
	fr_io_stats_t		stats;
} fr_network_worker_t;

typedef struct {
	fr_rb_node_t		listen_node;		//!< rbtree node for looking up by listener.
	fr_rb_node_t		num_node;		//!< rbtree node for looking up by number.

	fr_network_t		*nr;			//!< O(N) issues in talloc
	int			number;			//!< unique ID
	fr_heap_index_t		heap_id;		//!< for the sockets_by_num heap

	fr_event_filter_t	filter;			//!< what type of filter it is

	bool			dead;			//!< is it dead?
	bool			blocked;		//!< is it blocked?

	size_t			outstanding;		//!< number of outstanding packets sent to the worker
	fr_listen_t		*listen;		//!< I/O ctx and functions.

	fr_message_set_t	*ms;			//!< message buffers for this socket.
	fr_channel_data_t	*cd;			//!< cached in case of allocation & read error
	size_t			leftover;		//!< leftover data from a previous read
	size_t			written;		//!< however much we did in a partial write

	fr_channel_data_t	*pending;		//!< the currently pending partial packet
	fr_heap_t		*waiting;		//!< packets waiting to be written
	fr_io_stats_t		stats;
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
struct fr_network_s {
	char const		*name;			//!< Network ID for logging.

	bool			started;		//!< Set to true when the first worker is added.
	bool			suspended;		//!< whether or not we're suspended.

	fr_log_t const		*log;			//!< log destination
	fr_log_lvl_t		lvl;			//!< debug log level

	fr_atomic_queue_t	*aq_control;		//!< atomic queue for control messages sent to me

	fr_control_t		*control;		//!< the control plane

	fr_ring_buffer_t	*rb;			//!< ring buffer for my control-plane messages

	fr_event_list_t		*el;			//!< our event list

	fr_heap_t		*replies;		//!< replies from the worker, ordered by priority / origin time

	fr_io_stats_t		stats;

	fr_rb_tree_t		*sockets;		//!< list of sockets we're managing, ordered by the listener
	fr_rb_tree_t		*sockets_by_num;       	//!< ordered by number;

	int			num_workers;		//!< number of active workers
	int			num_blocked;		//!< number of blocked workers
	int			num_pending_workers;	//!< number of workers we're waiting to start.
	int			max_workers;		//!< maximum number of allowed workers
	int			num_sockets;		//!< actually a counter...

	int			signal_pipe[2];		//!< Pipe for signalling the worker in an orderly way.
							///< This is more deterministic than using async signals.

	fr_network_config_t	config;			//!< configuration
	fr_network_worker_t	*workers[MAX_WORKERS]; 	//!< each worker
};

static void fr_network_post_event(fr_event_list_t *el, fr_time_t now, void *uctx);
static int fr_network_pre_event(fr_time_t now, fr_time_delta_t wake, void *uctx);
static void fr_network_socket_dead(fr_network_t *nr, fr_network_socket_t *s);
static void fr_network_read(UNUSED fr_event_list_t *el, int sockfd, UNUSED int flags, void *ctx);

static int8_t reply_cmp(void const *one, void const *two)
{
	fr_channel_data_t const *a = one, *b = two;
	int ret;

	ret = CMP(a->priority, b->priority);
	if (ret != 0) return ret;

	return fr_time_cmp(a->m.when, b->m.when);
}

static int8_t waiting_cmp(void const *one, void const *two)
{
	fr_channel_data_t const *a = one, *b = two;
	int ret;

	ret = CMP(a->priority, b->priority);
	if (ret != 0) return ret;

	return fr_time_cmp(a->reply.request_time, b->reply.request_time);
}

static int8_t socket_listen_cmp(void const *one, void const *two)
{
	fr_network_socket_t const *a = one, *b = two;

	return CMP(a->listen, b->listen);
}

static int8_t socket_num_cmp(void const *one, void const *two)
{
	fr_network_socket_t const *a = one, *b = two;

	return CMP(a->number, b->number);
}

/*
 *	Explicitly cleanup the memory allocated to the ring buffer,
 *	just in case valgrind complains about it.
 */
static void _fr_network_rb_free(void *arg)
{
	talloc_free(arg);
}

/** Initialise thread local storage
 *
 * @return fr_ring_buffer_t for messages
 */
static inline fr_ring_buffer_t *fr_network_rb_init(void)
{
	fr_ring_buffer_t *rb;

	rb = fr_network_rb;
	if (rb) return rb;

	rb = fr_ring_buffer_create(NULL, FR_CONTROL_MAX_MESSAGES * FR_CONTROL_MAX_SIZE);
	if (!rb) {
		fr_perror("Failed allocating memory for network ring buffer");
		return NULL;
	}

	fr_atexit_thread_local(fr_network_rb, _fr_network_rb_free, rb);

	return rb;
}

/** Add a fr_listen_t to a network
 *
 * @param nr		the network
 * @param li		the listener
 */
int fr_network_listen_add(fr_network_t *nr, fr_listen_t *li)
{
	fr_ring_buffer_t *rb;

	rb = fr_network_rb_init();
	if (!rb) return -1;

	return fr_control_message_send(nr->control, rb, FR_CONTROL_ID_LISTEN, &li, sizeof(li));
}


/** Delete a socket from a network.  MUST be called only by the listener itself!.
 *
 * @param nr		the network
 * @param li		the listener
 */
int fr_network_listen_delete(fr_network_t *nr, fr_listen_t *li)
{
	fr_network_socket_t *s;

	s = fr_rb_find(nr->sockets, &(fr_network_socket_t){ .listen = li });
	if (!s) return -1;

	fr_network_socket_dead(nr, s);

	return 0;
}

/** Add a "watch directory" call to a network
 *
 * @param nr		the network
 * @param li		the listener
 */
int fr_network_directory_add(fr_network_t *nr, fr_listen_t *li)
{
	fr_ring_buffer_t *rb;

	rb = fr_network_rb_init();
	if (!rb) return -1;

	return fr_control_message_send(nr->control, rb, FR_CONTROL_ID_DIRECTORY, &li, sizeof(li));
}

/** Add a worker to a network
 *
 * @param nr the network
 * @param worker the worker
 */
int fr_network_worker_add(fr_network_t *nr, fr_worker_t *worker)
{
	fr_ring_buffer_t *rb;

	rb = fr_network_rb_init();
	if (!rb) return -1;

	(void) talloc_get_type_abort(nr, fr_network_t);
	(void) talloc_get_type_abort(worker, fr_worker_t);

	return fr_control_message_send(nr->control, rb, FR_CONTROL_ID_WORKER, &worker, sizeof(worker));
}

/** Signal the network to read from a listener
 *
 * @param nr the network
 * @param li the listener to read from
 */
void fr_network_listen_read(fr_network_t *nr, fr_listen_t *li)
{
	fr_network_socket_t *s;

	(void) talloc_get_type_abort(nr, fr_network_t);
	(void) talloc_get_type_abort_const(li, fr_listen_t);

	s = fr_rb_find(nr->sockets, &(fr_network_socket_t){ .listen = li });
	if (!s) return;

	/*
	 *	Go read the socket.
	 */
	fr_network_read(nr->el, s->listen->fd, 0, s);
}


/** Inject a packet for a listener to write
 *
 * @param nr		the network
 * @param li		the listener where the packet is being injected
 * @param packet	the packet to be written
 * @param packet_len	the length of the packet
 * @param packet_ctx	The packet context to write
 * @param request_time	when the packet was received.
 */
void fr_network_listen_write(fr_network_t *nr, fr_listen_t *li, uint8_t const *packet, size_t packet_len,
			     void *packet_ctx, fr_time_t request_time)
{
	fr_message_t *lm;
	fr_channel_data_t cd;

	cd = (fr_channel_data_t) {
		.m = (fr_message_t) {
			.status = FR_MESSAGE_USED,
			.data_size = packet_len,
			.when = request_time,
		},

		.channel = {
			.heap_id = 0,
		},

		.listen = li,
		.priority = PRIORITY_NOW,
		.reply.request_time = request_time,
	};

	memcpy(&cd.m.data, &packet, sizeof(packet)); /* const issues */
	memcpy(&cd.packet_ctx, &packet_ctx, sizeof(packet_ctx)); /* const issues */

	/*
	 *	Localize the message and insert it into the heap of pending messages.
	 */
	lm = fr_message_localize(nr, &cd.m, sizeof(cd));
	if (!lm) return;

	if (fr_heap_insert(nr->replies, lm) < 0) {
		fr_message_done(lm);
	}
}


/** Inject a packet for a listener to read
 *
 * @param nr		the network
 * @param li		the listener where the packet is being injected
 * @param packet	the packet to be injected
 * @param packet_len	the length of the packet
 * @param recv_time	when the packet was received.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_network_listen_inject(fr_network_t *nr, fr_listen_t *li, uint8_t const *packet, size_t packet_len, fr_time_t recv_time)
{
	fr_ring_buffer_t *rb;
	fr_network_inject_t my_inject;

	rb = fr_network_rb_init();
	if (!rb) return -1;

	(void) talloc_get_type_abort(nr, fr_network_t);
	(void) talloc_get_type_abort(li, fr_listen_t);

	/*
	 *	Can't inject to injection-less destinations.
	 */
	if (!li->app_io->inject) return -1;

	my_inject.listen = li;
	my_inject.packet = talloc_memdup(NULL, packet, packet_len);
	my_inject.packet_len = packet_len;
	my_inject.recv_time = recv_time;

	return fr_control_message_send(nr->control, rb, FR_CONTROL_ID_INJECT, &my_inject, sizeof(my_inject));
}

static void fr_network_suspend(fr_network_t *nr)
{
	static fr_event_update_t pause_read[] = {
		FR_EVENT_SUSPEND(fr_event_io_func_t, read),
		{ 0 }
	};
	fr_rb_iter_inorder_t	iter;
	fr_network_socket_t		*socket;

	if (nr->suspended) return;

	for (socket = fr_rb_iter_init_inorder(&iter, nr->sockets);
	     socket;
	     socket = fr_rb_iter_next_inorder(&iter)) {
		fr_event_filter_update(socket->nr->el, socket->listen->fd, FR_EVENT_FILTER_IO, pause_read);
	}
	nr->suspended = true;
}

static void fr_network_unsuspend(fr_network_t *nr)
{
	static fr_event_update_t resume_read[] = {
		FR_EVENT_RESUME(fr_event_io_func_t, read),
		{ 0 }
	};
	fr_rb_iter_inorder_t	iter;
	fr_network_socket_t		*socket;

	if (!nr->suspended) return;

	for (socket = fr_rb_iter_init_inorder(&iter, nr->sockets);
	     socket;
	     socket = fr_rb_iter_next_inorder(&iter)) {
		fr_event_filter_update(socket->nr->el, socket->listen->fd, FR_EVENT_FILTER_IO, resume_read);
	}
	nr->suspended = false;
}

#define IALPHA (8)
#define RTT(_old, _new) fr_time_delta_wrap((fr_time_delta_unwrap(_new) + (fr_time_delta_unwrap(_old) * (IALPHA - 1))) / IALPHA)

/** Callback which handles a message being received on the network side.
 *
 * @param[in] ctx the network
 * @param[in] ch the channel that the message is on.
 * @param[in] cd the message (if any) to start with
 */
static void fr_network_recv_reply(void *ctx, fr_channel_t *ch, fr_channel_data_t *cd)
{
	fr_network_t *nr = ctx;
	fr_network_worker_t *worker;

	cd->channel.ch = ch;

	/*
	 *	Update stats for the worker.
	 */
	worker = fr_channel_requestor_uctx_get(ch);
	worker->stats.out++;
	worker->cpu_time = cd->reply.cpu_time;
	if (!fr_time_delta_ispos(worker->predicted)) {
		worker->predicted = cd->reply.processing_time;
	} else {
		worker->predicted = RTT(worker->predicted, cd->reply.processing_time);
	}

	/*
	 *	Unblock the worker.
	 */
	if (worker->blocked) {
		worker->blocked = false;
		nr->num_blocked--;
		fr_network_unsuspend(nr);
	}

	/*
	 *	Ensure that heap insert works.
	 */
	cd->channel.heap_id = 0;
	if (fr_heap_insert(nr->replies, cd) < 0) {
		fr_message_done(&cd->m);
		fr_assert(0 == 1);
	}
}

/** Handle a network control message callback for a channel
 *
 * This is called from the event loop when we get a notification
 * from the event signalling pipe.
 *
 * @param[in] ctx	the network
 * @param[in] data	the message
 * @param[in] data_size	size of the data
 * @param[in] now	the current time
 */
static void fr_network_channel_callback(void *ctx, void const *data, size_t data_size, fr_time_t now)
{
	fr_channel_event_t	ce;
	fr_channel_t		*ch;
	fr_network_t		*nr = ctx;

	ce = fr_channel_service_message(now, &ch, data, data_size);
	DEBUG3("Channel %s",
	       fr_table_str_by_value(channel_signals, ce, "<INVALID>"));
	switch (ce) {
	case FR_CHANNEL_ERROR:
		return;

	case FR_CHANNEL_EMPTY:
		return;

	case FR_CHANNEL_NOOP:
		break;

	case FR_CHANNEL_DATA_READY_REQUESTOR:
		fr_assert(ch != NULL);
		while (fr_channel_recv_reply(ch));
		break;

	case FR_CHANNEL_DATA_READY_RESPONDER:
		fr_assert(0 == 1);
		break;

	case FR_CHANNEL_OPEN:
		fr_assert(0 == 1);
		break;

	case FR_CHANNEL_CLOSE:
	{
		fr_network_worker_t	*w = talloc_get_type_abort(fr_channel_requestor_uctx_get(ch),
								   fr_network_worker_t);
		int			i;

		/*
		 *	Remove this worker from the array
		 */
		for (i = 0; i < nr->num_workers; i++) {
			DEBUG3("Worker acked our close request");
			if (nr->workers[i] == w) {
				nr->workers[i] = NULL;

				if (i == (nr->num_workers - 1)) break;

				/*
				 *	Close the hole...
				 */
				memcpy(&nr->workers[i], &nr->workers[i + 1], ((nr->num_workers - i) - 1));
				break;
			}
		}
		nr->num_workers--;
	}
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

	(void) talloc_get_type_abort(nr, fr_network_t);

retry:
	if (nr->num_workers == 1) {
		worker = nr->workers[0];
		if (worker->blocked) {
			RATE_LIMIT_GLOBAL(ERROR, "Failed sending packet to worker - "
					  "In single-threaded mode and worker is blocked");
		drop:
			worker->stats.dropped++;
			return -1;
		}

	} else if (nr->num_blocked == 0) {
		uint32_t one, two;

		one = fr_rand() % nr->num_workers;
		do {
			two = fr_rand() % nr->num_workers;
		} while (two == one);

		if (fr_time_delta_lt(nr->workers[one]->cpu_time, nr->workers[two]->cpu_time)) {
			worker = nr->workers[one];
		} else {
			worker = nr->workers[two];
		}
	} else {
		int i;
		fr_time_delta_t cpu_time = fr_time_delta_max();
		fr_network_worker_t *found = NULL;

		/*
		 *	Some workers are blocked.  Pick an active
		 *	worker with low CPU time.
		 */
		for (i = 0; i < nr->num_workers; i++) {
			worker = nr->workers[i];
			if (worker->blocked) continue;

			if (fr_time_delta_lt(worker->cpu_time, cpu_time)) {
				found = worker;
			}
		}

		if (!found) {
			 RATE_LIMIT_GLOBAL(PERROR, "Failed sending packet to worker - Couldn't find active worker, "
			 		   "%u/%u workers are blocked", nr->num_blocked, nr->num_workers);
			 return -1;
		}

		worker = found;
	}

	(void) talloc_get_type_abort(worker, fr_network_worker_t);

	/*
	 *	Too many outstanding packets for this worker.  Drop
	 *	the request.
	 *
	 *	@todo - pick another worker?  Or maybe keep a
	 *	local/temporary set of blacklisted workers.
	 */
	fr_assert(worker->stats.in >= worker->stats.out);
	if (nr->config.max_outstanding &&
	    ((worker->stats.in - worker->stats.out) >= nr->config.max_outstanding)) {
		RATE_LIMIT_GLOBAL(PERROR, "max_outstanding reached - dropping packet");
		goto drop;
	}

	/*
	 *	Send the message to the channel.  If we fail, drop the
	 *	packet.  The only reason for failure is that the
	 *	worker isn't servicing it's input queue.  When that
	 *	happens, we have no idea what to do, and the whole
	 *	thing falls over.
	 */
	if (fr_channel_send_request(worker->channel, cd) < 0) {
		worker->stats.dropped++;
		worker->blocked = true;
		nr->num_blocked++;

		RATE_LIMIT_GLOBAL(PERROR, "Failed sending packet to worker - %u/%u workers are blocked",
				  nr->num_blocked, nr->num_workers);

		if (nr->num_blocked == nr->num_workers) {
			fr_network_suspend(nr);
			return -1;
		}
		goto retry;
	}

	worker->stats.in++;

	/*
	 *	We're projecting that the worker will use more CPU
	 *	time to process this request.  The CPU time will be
	 *	updated with a more accurate number when we receive a
	 *	reply from this channel.
	 */
	worker->cpu_time = fr_time_delta_add(worker->cpu_time, worker->predicted);

	return 0;
}

/*
 *	Mark it as dead, but DON'T free it until all of the replies
 *	have come in.
 */
static void fr_network_socket_dead(fr_network_t *nr, fr_network_socket_t *s)
{
	if (s->dead) return;

	s->dead = true;

	fr_event_fd_delete(nr->el, s->listen->fd, s->filter);

	/*
	 *	If there are no outstanding packets, then we can free
	 *	it now.
	 */
	if (!s->outstanding) {
		talloc_free(s);
		return;
	}

	/*
	 *	There are still outstanding packets.  Leave it in the
	 *	socket tree, so that replies from the worker can find
	 *	it.  When we've received all of the replies, then
	 *	fr_network_post_event() will clean up this socket.
	 */
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
	int			num_messages = 0;
	fr_network_socket_t	*s = ctx;
	fr_network_t		*nr = s->nr;
	ssize_t			data_size;
	fr_channel_data_t	*cd, *next;
#ifndef NDEBUG
	fr_time_t		now;
#endif

	if (!fr_cond_assert_msg(s->listen->fd == sockfd, "Expected listen->fd (%u) to be equal event fd (%u)",
				s->listen->fd, sockfd)) return;

	DEBUG3("Reading data from FD %u", sockfd);

	if (!s->cd) {
		cd = (fr_channel_data_t *) fr_message_reserve(s->ms, s->listen->default_message_size);
		if (!cd) {
			ERROR("Failed allocating message size %zd! - Closing socket",
			      s->listen->default_message_size);
			fr_network_socket_dead(nr, s);
			return;
		}
	} else {
		cd = s->cd;
	}

	fr_assert(cd->m.data != NULL);

next_message:
	/*
	 *	Poll this socket, but not too often.  We have to go
	 *	service other sockets, too.
	 */
	if (num_messages > 16) {
		s->cd = cd;
		return;
	}

	cd->request.is_dup = false;
	cd->priority = PRIORITY_NORMAL;

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
	data_size = s->listen->app_io->read(s->listen, &cd->packet_ctx, &cd->request.recv_time,
					    cd->m.data, cd->m.rb_size, &s->leftover, &cd->priority, &cd->request.is_dup);
	if (data_size == 0) {
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
//		fr_log(nr->log, L_DBG_ERR, "error from transport read on socket %d", sockfd);
		fr_network_socket_dead(nr, s);
		return;
	}
	s->cd = NULL;

	DEBUG3("Read %zd byte(s) from FD %u", data_size, sockfd);
	nr->stats.in++;
	s->stats.in++;

	/*
	 *	Initialize the rest of the fields of the channel data.
	 *
	 *	We always use "now" as the time of the message, as the
	 *	packet MAY be a duplicate packet magically resurrected
	 *	from the past.  i.e. If the read routines are doing
	 *	dedup, then they notice that the packet is a
	 *	duplicate.  In that case, they send over a copy of the
	 *	packet, BUT with the original timestamp.  This
	 *	information tells the worker that the packet is a
	 *	duplicate.
	 */
	cd->m.when = fr_time();
#ifndef NDEBUG
	now = cd->m.when;
#endif
	cd->listen = s->listen;

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
		next = (fr_channel_data_t *) fr_message_alloc_reserve(s->ms, &cd->m, data_size, s->leftover,
								      s->listen->default_message_size);
		if (!next) {
			PERROR("Failed reserving partial packet.");
			// @todo - probably close the socket...
			fr_assert(0 == 1);
		}
	}

	/*
	 *	Ensure this hasn't been somehow corrupted during
	 *	ring buffer allocation.
	 */
	fr_assert(fr_time_eq(cd->m.when, now));

	if (fr_network_send_request(nr, cd) < 0) {
		talloc_free(cd->packet_ctx); /* not sure what else to do here */
		fr_message_done(&cd->m);
		nr->stats.dropped++;
		s->stats.dropped++;

	} else {
		/*
		 *	One more packet sent to a worker.
		 */
		s->outstanding++;
	}

	/*
	 *	If there is a next message, go read it from the buffer.
	 *
	 *	@todo - note that this calls read(), even if the
	 *	app_io has paused the reader.  We likely want to be
	 *	able to check that, too.  We might just remove this
	 *	"goto"...
	 */
	if (next) {
		cd = next;
		num_messages++;
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
	fr_network_t *nr = s->nr;

	fr_cond_assert(s->listen->fd == sockfd);

	DEBUG3("network vnode");

	/*
	 *	Tell the IO handler that something has happened to the
	 *	file.
	 */
	s->listen->app_io->vnode(s->listen, fflags);
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

	if (s->listen->app_io->error) {
		s->listen->app_io->error(s->listen);
	}

	fr_network_socket_dead(s->nr, s);
}


static fr_event_update_t const pause_write[] = {
	FR_EVENT_SUSPEND(fr_event_io_func_t, write),
	{ 0 }
};

static fr_event_update_t const resume_write[] = {
	FR_EVENT_RESUME(fr_event_io_func_t, write),
	{ 0 }
};


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
	fr_listen_t *li = s->listen;
	fr_network_t *nr = s->nr;
	fr_channel_data_t *cd;

	(void) talloc_get_type_abort(nr, fr_network_t);

	/*
	 *	Start with the currently pending message, and then
	 *	work through the priority heap.
	 */
	if (s->pending) {
		cd = s->pending;
		s->pending = NULL;

	} else {
		cd = fr_heap_pop(s->waiting);
	}

	while (cd != NULL) {
		int rcode;

		fr_assert(li == cd->listen);
		rcode = li->app_io->write(li, cd->packet_ctx,
					  cd->reply.request_time,
					  cd->m.data, cd->m.data_size, s->written);

		/*
		 *	As a special case, allow write() to return
		 *	"0", which means "close the socket".
		 */
		if (rcode == 0) goto dead;

		/*
		 *	Or we have a write error.
		 */
		if (rcode < 0) {
			/*
			 *	Stop processing the heap, and set the
			 *	pending message to the current one.
			 */
			if (errno == EWOULDBLOCK) {
			save_pending:
				fr_assert(!s->pending);

				if (cd->m.status != FR_MESSAGE_LOCALIZED) {
					fr_message_t *lm;

					lm = fr_message_localize(s, &cd->m, sizeof(*cd));
					if (!lm) {
						ERROR("Failed saving pending packet");
						goto dead;
					}

					cd = (fr_channel_data_t *) lm;
				}

				if (!s->blocked) {
					if (fr_event_filter_update(nr->el, s->listen->fd, FR_EVENT_FILTER_IO, resume_write) < 0) {
						PERROR("Failed adding write callback to event loop");
						goto dead;
					}

					s->blocked = true;
				}

				s->pending = cd;
				return;
			}

			/*
			 *	As a special hack, check for something
			 *	that will never be returned from a
			 *	real write() routine.  Which then
			 *	signals to us that we have to close
			 *	the socket, but NOT complain about it.
			 */
			if (errno == ECONNREFUSED) goto dead;

			PERROR("Failed writing to socket %s", s->listen->name);
			if (li->app_io->error) li->app_io->error(li);

		dead:
			fr_message_done(&cd->m);
			fr_network_socket_dead(nr, s);
			return;
		}

		/*
		 *	If we've done a partial write, localize the message and continue.
		 */
		if ((size_t) rcode < cd->m.data_size) {
			s->written = rcode;
			goto save_pending;
		}

		s->written = 0;

		/*
		 *	Reset for the next message.
		 */
		fr_message_done(&cd->m);
		nr->stats.out++;
		s->stats.out++;

		/*
		 *	Grab the net entry.
		 */
		cd = fr_heap_pop(s->waiting);
	}

	/*
	 *	We've successfully written all of the packets.  Remove
	 *	the write callback.
	 */
	if (fr_event_filter_update(nr->el, s->listen->fd, FR_EVENT_FILTER_IO, pause_write) < 0) {
		PERROR("Failed removing write callback from event loop");
		fr_network_socket_dead(nr, s);
	}

	s->blocked = false;
}

static int _network_socket_free(fr_network_socket_t *s)
{
	fr_network_t *nr = s->nr;
	fr_channel_data_t *cd;

	fr_rb_delete(nr->sockets, s);
	fr_rb_delete(nr->sockets_by_num, s);

	fr_event_fd_delete(nr->el, s->listen->fd, s->filter);

	if (s->listen->app_io->close) {
		s->listen->app_io->close(s->listen);
	} else {
		close(s->listen->fd);
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

/** Handle a network control message callback for a new listener
 *
 * @param[in] ctx the network
 * @param[in] data the message
 * @param[in] data_size size of the data
 * @param[in] now the current time
 */
static void fr_network_listen_callback(void *ctx, void const *data, size_t data_size, UNUSED fr_time_t now)
{
	fr_network_t		*nr = ctx;
	fr_network_socket_t	*s;
	fr_app_io_t const	*app_io;
	size_t			size;
	int			num_messages;

	fr_assert(data_size == sizeof(s->listen));

	if (data_size != sizeof(s->listen)) return;

	s = talloc_zero(nr, fr_network_socket_t);
	fr_assert(s != NULL);

	s->nr = nr;
	memcpy(&s->listen, data, sizeof(s->listen));
	s->number = nr->num_sockets++;

	MEM(s->waiting = fr_heap_alloc(s, waiting_cmp, fr_channel_data_t, channel.heap_id, 0));

	talloc_set_destructor(s, _network_socket_free);

	/*
	 *	Put reasonable limits on the ring buffer size.  Then
	 *	round it up to the nearest power of 2, which is
	 *	required by the ring buffer code.
	 */
	num_messages = s->listen->num_messages;
	if (num_messages < 8) num_messages = 8;

	size = s->listen->default_message_size * num_messages;
	if (size < (1 << 17)) size = (1 << 17);
	if (size > (100 * 1024 * 1024)) size = (100 * 1024 * 1024);

	/*
	 *	Allocate the ring buffer for messages and packets.
	 */
	s->ms = fr_message_set_create(s, num_messages,
				      sizeof(fr_channel_data_t),
				      size);
	if (!s->ms) {
		PERROR("Failed creating message buffers for network IO");
		talloc_free(s);
		return;
	}

	app_io = s->listen->app_io;
	s->filter = FR_EVENT_FILTER_IO;

	if (fr_event_fd_insert(nr, nr->el, s->listen->fd,
			       fr_network_read,
			       fr_network_write,
			       fr_network_error,
			       s) < 0) {
		PERROR("Failed adding new socket to network event loop");
		talloc_free(s);
		return;
	}

	/*
	 *	Start of with write updates being paused.  We don't
	 *	care about being able to write if there's nothing to
	 *	write.
	 */
	(void) fr_event_filter_update(nr->el, s->listen->fd, FR_EVENT_FILTER_IO, pause_write);

	/*
	 *	Add the listener before calling the app_io, so that
	 *	the app_io can find the listener which we're adding
	 *	here.
	 */
	(void) fr_rb_insert(nr->sockets, s);
	(void) fr_rb_insert(nr->sockets_by_num, s);

	if (app_io->event_list_set) app_io->event_list_set(s->listen, nr->el, nr);

	/*
	 *	We use fr_log() here to avoid the "Network - " prefix.
	 */
	fr_log(nr->log, L_DBG, __FILE__, __LINE__, "Listening on %s bound to virtual server %s",
	      s->listen->name, cf_section_name2(s->listen->server_cs));

	DEBUG3("Using new socket %s with FD %d", s->listen->name, s->listen->fd);
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
	int			num_messages;
	fr_network_t		*nr = ctx;
	fr_network_socket_t	*s;
	fr_app_io_t const	*app_io;
	fr_event_vnode_func_t	funcs = { .extend = fr_network_vnode_extend };

	fr_assert(data_size == sizeof(s->listen));

	if (data_size != sizeof(s->listen)) return;

	s = talloc_zero(nr, fr_network_socket_t);
	fr_assert(s != NULL);

	s->nr = nr;
	memcpy(&s->listen, data, sizeof(s->listen));
	s->number = nr->num_sockets++;

	MEM(s->waiting = fr_heap_alloc(s, waiting_cmp, fr_channel_data_t, channel.heap_id, 0));

	talloc_set_destructor(s, _network_socket_free);

	/*
	 *	Allocate the ring buffer for messages and packets.
	 */
	num_messages = s->listen->num_messages;
	if (num_messages < 8) num_messages = 8;

	s->ms = fr_message_set_create(s, num_messages,
				      sizeof(fr_channel_data_t),
				      s->listen->default_message_size * s->listen->num_messages);
	if (!s->ms) {
		PERROR("Failed creating message buffers for directory IO");
		talloc_free(s);
		return;
	}

	app_io = s->listen->app_io;

	if (app_io->event_list_set) app_io->event_list_set(s->listen, nr->el, nr);

	s->filter = FR_EVENT_FILTER_VNODE;

	if (fr_event_filter_insert(nr, NULL, nr->el, s->listen->fd, s->filter,
				   &funcs,
				   app_io->error ? fr_network_error : NULL,
				   s) < 0) {
		PERROR("Failed adding directory monitor event loop");
		talloc_free(s);
		return;
	}

	(void) fr_rb_insert(nr->sockets, s);
	(void) fr_rb_insert(nr->sockets_by_num, s);

	DEBUG3("Using new socket with FD %d", s->listen->fd);
}

/** Handle a network control message callback for a new worker
 *
 * @param[in] ctx the network
 * @param[in] data the message
 * @param[in] data_size size of the data
 * @param[in] now the current time
 */
static void fr_network_worker_started_callback(void *ctx, void const *data, size_t data_size, UNUSED fr_time_t now)
{
	int i;
	fr_network_t *nr = ctx;
	fr_worker_t *worker;
	fr_network_worker_t *w;

	fr_assert(data_size == sizeof(worker));

	memcpy(&worker, data, data_size);
	(void) talloc_get_type_abort(worker, fr_worker_t);

	MEM(w = talloc_zero(nr, fr_network_worker_t));

	w->worker = worker;
	w->channel = fr_worker_channel_create(worker, w, nr->control);
	fr_fatal_assert_msg(w->channel, "Failed creating new channel");

	fr_channel_requestor_uctx_add(w->channel, w);
	fr_channel_set_recv_reply(w->channel, nr, fr_network_recv_reply);

	nr->num_workers++;
	nr->started = true;

	/*
	 *	Insert the worker into the array of workers.
	 */
	for (i = 0; i < nr->max_workers; i++) {
		if (nr->workers[i]) continue;

		nr->workers[i] = w;
		return;
	}

	/*
	 *	Run out of room to put workers!
	 */
	fr_assert(0 == 1);
}

/** Handle a network control message callback for a packet sent to a socket
 *
 * @param[in] ctx the network
 * @param[in] data the message
 * @param[in] data_size size of the data
 * @param[in] now the current time
 */
static void fr_network_inject_callback(void *ctx, void const *data, size_t data_size, UNUSED fr_time_t now)
{
	fr_network_t *nr = ctx;
	fr_network_inject_t my_inject;
	fr_network_socket_t *s;

	fr_assert(data_size == sizeof(my_inject));

	memcpy(&my_inject, data, data_size);
	s = fr_rb_find(nr->sockets, &(fr_network_socket_t){ .listen = my_inject.listen });
	if (!s) {
		talloc_free(my_inject.packet); /* MUST be it's own TALLOC_CTX */
		return;
	}

	/*
	 *	Inject the packet, and then read it back from the
	 *	network.
	 */
	if (s->listen->app_io->inject(s->listen, my_inject.packet, my_inject.packet_len, my_inject.recv_time) == 0) {
		fr_network_read(nr->el, s->listen->fd, 0, s);
	}

	talloc_free(my_inject.packet);
}

/** Run the event loop 'pre' callback
 *
 *  This function MUST DO NO WORK.  All it does is check if there's
 *  work, and tell the event code to return to the main loop if
 *  there's work to do.
 *
 * @param[in] now	the current time.
 * @param[in] wake	the time when the event loop will wake up.
 * @param[in] uctx	the network
 */
static int fr_network_pre_event(UNUSED fr_time_t now, UNUSED fr_time_delta_t wake, void *uctx)
{
	fr_network_t *nr = talloc_get_type_abort(uctx, fr_network_t);

	if (fr_heap_num_elements(nr->replies) > 0) return 1;

	return 0;
}

/** Handle replies after all FD and timer events have been serviced
 *
 * @param el	the event loop
 * @param now	the current time (mostly)
 * @param uctx	the fr_network_t
 */
static void fr_network_post_event(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_channel_data_t *cd;
	fr_network_t *nr = talloc_get_type_abort(uctx, fr_network_t);

	/*
	 *	Pull the replies off of our global heap, and try to
	 *	push them to the individual sockets.
	 */
	while ((cd = fr_heap_pop(nr->replies)) != NULL) {
		fr_listen_t *li;
		fr_network_socket_t *s;

		li = cd->listen;

		/*
		 *	@todo - cache this somewhere so we don't need
		 *	to do an rbtree lookup for every packet.
		 */
		s = fr_rb_find(nr->sockets, &(fr_network_socket_t){ .listen = li });

		/*
		 *	This shouldn't happen, but be safe...
		 */
		if (!s) {
			fr_message_done(&cd->m);
			continue;
		}

		if (cd->m.status != FR_MESSAGE_LOCALIZED) {
			fr_assert(s->outstanding > 0);
			s->outstanding--;
		}

		/*
		 *	Just mark the message done, and skip it.
		 */
		if (s->dead) {
			fr_message_done(&cd->m);

			/*
			 *	No more packets, it's safe to delete
			 *	the socket.
			 */
			if (!s->outstanding) talloc_free(s);

			continue;
		}

		/*
		 *	No data to write to the socket, so we skip the message.
		 */
		if (!cd->m.data_size) {
			fr_message_done(&cd->m);
			continue;
		}

		/*
		 *	No pending message, let's try writing it.
		 *
		 *	If there is a pending message, then we're
		 *	waiting for IO write to become ready.
		 */
		if (!s->pending) {
			fr_assert(!s->blocked);
			(void) fr_heap_insert(s->waiting, cd);
			fr_network_write(nr->el, s->listen->fd, 0, s);
		}
	}
}

/** Stop a network thread in an orderly way
 *
 * @param[in] nr the network to stop
 */
int fr_network_destroy(fr_network_t *nr)
{
	fr_channel_data_t	*cd;

	(void) talloc_get_type_abort(nr, fr_network_t);

	/*
	 *	Close the network sockets
	 */
	{
		fr_network_socket_t	**sockets;
		size_t			len;
		size_t			i;

		if (fr_rb_flatten_inorder(nr, (void ***)&sockets, nr->sockets) < 0) return -1;
		len = talloc_array_length(sockets);

		for (i = 0; i < len; i++) talloc_free(sockets[i]);

		talloc_free(sockets);
	}


	/*
	 *	Clean up all outstanding replies.
	 *
	 *	We can't do this after signalling the
	 *	workers to close, because they free
	 *	their message sets, and we end up
	 *	getting random use-after-free errors
	 *	as there's a race between the network
	 *	popping replies, and the workers
	 *	freeing their message sets.
	 *
	 *	This isn't perfect, and we might still
	 *	lose some replies, but it's good enough
	 *	for now.
	 *
	 *	@todo - call transport "done" for the reply, so that
	 *	it knows the replies are done, too.
	 */
	while ((cd = fr_heap_pop(nr->replies)) != NULL) {
		fr_message_done(&cd->m);
	}

	/*
	 *	Signal the workers that we're closing
	 *
	 *	nr->num_workers is decremented every
	 *	time a worker closes a socket.
	 *
	 *	When nr->num_workers == 0, the event
	 *	loop (fr_network()) will exit.
	 */
	{
		int i;

		for (i = 0; i < nr->num_workers; i++) {
			fr_network_worker_t *worker = nr->workers[i];

			fr_channel_signal_responder_close(worker->channel);
		}
	}

	(void) fr_event_pre_delete(nr->el, fr_network_pre_event, nr);
	(void) fr_event_post_delete(nr->el, fr_network_post_event, nr);
	fr_event_fd_delete(nr->el, nr->signal_pipe[0], FR_EVENT_FILTER_IO);

	return 0;
}

/** Read handler for signal pipe
 *
 */
static void _signal_pipe_read(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_network_t	*nr = talloc_get_type_abort(uctx, fr_network_t);
	uint8_t		buff;

	if (read(fd, &buff, sizeof(buff)) < 0) {
		ERROR("Failed reading signal - %s", fr_syserror(errno));
		return;
	}

	fr_assert(buff == 1);

	/*
	 *	fr_network_stop() will signal the workers
	 *	to exit (by closing their channels).
	 *
	 *	When we get the ack, we decrement our
	 *	nr->num_workers counter.
	 *
	 *	When the counter reaches 0, the event loop
	 *	exits.
	 */
	DEBUG2("Signalled to exit");
	fr_network_destroy(nr);
}

/** The main network worker function.
 *
 * @param[in] nr the network data structure to run.
 */
void fr_network(fr_network_t *nr)
{
	while (likely(((nr->num_workers > 0) || !nr->started))) {
		bool wait_for_event;
		int num_events;

		/*
		 *	There are runnable requests.  We still service
		 *	the event loop, but we don't wait for events.
		 */
		wait_for_event = (fr_heap_num_elements(nr->replies) == 0);

		/*
		 *	Check the event list.  If there's an error
		 *	(e.g. exit), we stop looping and clean up.
		 */
		DEBUG3("Gathering events - %s", wait_for_event ? "will wait" : "Will not wait");
		num_events = fr_event_corral(nr->el, fr_time(), wait_for_event);
		DEBUG3("%u event(s) pending%s",
		       num_events == -1 ? 0 : num_events, num_events == -1 ? " - event loop exiting" : "");
		if (num_events < 0) break;

		/*
		 *	Service outstanding events.
		 */
		if (num_events > 0) {
			DEBUG4("Servicing event(s)");
			fr_event_service(nr->el);
		}
	}
}

/** Signal a network thread to exit
 *
 * @note Request to exit will be processed asynchronously.
 *
 * @param[in] nr the network data structure to manage
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_network_exit(fr_network_t *nr)
{
	if (write(nr->signal_pipe[1], &(uint8_t){ 0x01 }, 1) < 0) {
		fr_strerror_printf("Failed signalling network thread to exit - %s", fr_syserror(errno));
		return -1;
	}

	return 0;
}

/** Free any resources associated with a network thread
 *
 */
static int _fr_network_free(fr_network_t *nr)
{
	if (nr->signal_pipe[0] >= 0) close(nr->signal_pipe[0]);
	if (nr->signal_pipe[1] >= 0) close(nr->signal_pipe[1]);

	return 0;
}

/** Create a network
 *
 * @param[in] ctx 	The talloc ctx
 * @param[in] el	The event list
 * @param[in] name	Networker identifier.
 * @param[in] logger	The destination for all logging messages
 * @param[in] lvl	Log level
 * @param[in] config	configuration structure.
 * @return
 *	- NULL on error
 *	- fr_network_t on success
 */
fr_network_t *fr_network_create(TALLOC_CTX *ctx, fr_event_list_t *el, char const *name,
				fr_log_t const *logger, fr_log_lvl_t lvl,
				fr_network_config_t const *config)
{
	fr_network_t *nr;

	nr = talloc_zero(ctx, fr_network_t);
	if (!nr) {
		fr_strerror_const("Failed allocating memory");
		return NULL;
	}
	talloc_set_destructor(nr, _fr_network_free);

	nr->name = talloc_strdup(nr, name);
	nr->el = el;
	nr->log = logger;
	nr->lvl = lvl;
	nr->max_workers = MAX_WORKERS;
	nr->num_workers = 0;
	nr->signal_pipe[0] = -1;
	nr->signal_pipe[1] = -1;
	if (config) nr->config = *config;

	nr->aq_control = fr_atomic_queue_alloc(nr, 1024);
	if (!nr->aq_control) {
		talloc_free(nr);
		return NULL;
	}

	nr->control = fr_control_create(nr, el, nr->aq_control);
	if (!nr->control) {
		fr_strerror_const_push("Failed creating control queue");
	fail:
		talloc_free(nr);
		return NULL;
	}

	/*
	 *	@todo - rely on thread-local variables.  And then the
	 *	various users of this can check if (rb == nr->rb), and
	 *	if so, skip the whole control plane / kevent /
	 *	whatever roundabout thing.
	 */
	nr->rb = fr_ring_buffer_create(nr, FR_CONTROL_MAX_MESSAGES * FR_CONTROL_MAX_SIZE);
	if (!nr->rb) {
		fr_strerror_const_push("Failed creating ring buffer");
	fail2:
		talloc_free(nr->control);
		goto fail;
	}

	if (fr_control_callback_add(nr->control, FR_CONTROL_ID_CHANNEL, nr, fr_network_channel_callback) < 0) {
		fr_strerror_const_push("Failed adding channel callback");
		goto fail2;
	}

	if (fr_control_callback_add(nr->control, FR_CONTROL_ID_LISTEN, nr, fr_network_listen_callback) < 0) {
		fr_strerror_const_push("Failed adding socket callback");
		goto fail2;
	}

	if (fr_control_callback_add(nr->control, FR_CONTROL_ID_DIRECTORY, nr, fr_network_directory_callback) < 0) {
		fr_strerror_const_push("Failed adding socket callback");
		goto fail2;
	}

	if (fr_control_callback_add(nr->control, FR_CONTROL_ID_WORKER, nr, fr_network_worker_started_callback) < 0) {
		fr_strerror_const_push("Failed adding worker callback");
		goto fail2;
	}

	if (fr_control_callback_add(nr->control, FR_CONTROL_ID_INJECT, nr, fr_network_inject_callback) < 0) {
		fr_strerror_const_push("Failed adding packet injection callback");
		goto fail2;
	}

	/*
	 *	Create the various heaps.
	 */
	nr->sockets = fr_rb_inline_talloc_alloc(nr, fr_network_socket_t, listen_node, socket_listen_cmp, NULL);
	if (!nr->sockets) {
		fr_strerror_const_push("Failed creating listen tree for sockets");
		goto fail2;
	}

	nr->sockets_by_num = fr_rb_inline_talloc_alloc(nr, fr_network_socket_t, num_node, socket_num_cmp, NULL);
	if (!nr->sockets_by_num) {
		fr_strerror_const_push("Failed creating number tree for sockets");
		goto fail2;
	}

	nr->replies = fr_heap_alloc(nr, reply_cmp, fr_channel_data_t, channel.heap_id, 0);
	if (!nr->replies) {
		fr_strerror_const_push("Failed creating heap for replies");
		goto fail2;
	}

	if (fr_event_pre_insert(nr->el, fr_network_pre_event, nr) < 0) {
		fr_strerror_const("Failed adding pre-check to event list");
		goto fail2;
	}

	if (fr_event_post_insert(nr->el, fr_network_post_event, nr) < 0) {
		fr_strerror_const("Failed inserting post-processing event");
		goto fail2;
	}

	if (pipe(nr->signal_pipe) < 0) {
		fr_strerror_printf("Failed initialising signal pipe - %s", fr_syserror(errno));
		goto fail2;
	}
	if (fr_nonblock(nr->signal_pipe[0]) < 0) goto fail2;
	if (fr_nonblock(nr->signal_pipe[1]) < 0) goto fail2;

	if (fr_event_fd_insert(nr, nr->el, nr->signal_pipe[0], _signal_pipe_read, NULL, NULL, nr) < 0) {
		fr_strerror_const("Failed inserting event for signal pipe");
		goto fail2;
	}

	return nr;
}

int fr_network_stats(fr_network_t const *nr, int num, uint64_t *stats)
{
	if (num < 0) return -1;
	if (num == 0) return 0;

	if (num >= 1) stats[0] = nr->stats.in;
	if (num >= 2) stats[1] = nr->stats.out;
	if (num >= 3) stats[2] = nr->stats.dup;
	if (num >= 4) stats[3] = nr->stats.dropped;
	if (num >= 5) stats[4] = nr->num_workers;

	if (num <= 5) return num;

	return 5;
}

void fr_network_stats_log(fr_network_t const *nr, fr_log_t const *log)
{
	int i;

	/*
	 *	Dump all of the channel statistics.
	 */
	for (i = 0; i < nr->max_workers; i++) {
		if (!nr->workers[i]) continue;

		fr_channel_stats_log(nr->workers[i]->channel, log, __FILE__, __LINE__);
	}
}

static int cmd_stats_self(FILE *fp, UNUSED FILE *fp_err, void *ctx, UNUSED fr_cmd_info_t const *info)
{
	fr_network_t const *nr = ctx;

	fprintf(fp, "count.in\t%" PRIu64 "\n", nr->stats.in);
	fprintf(fp, "count.out\t%" PRIu64 "\n", nr->stats.out);
	fprintf(fp, "count.dup\t%" PRIu64 "\n", nr->stats.dup);
	fprintf(fp, "count.dropped\t%" PRIu64 "\n", nr->stats.dropped);
	fprintf(fp, "count.sockets\t%u\n", fr_rb_num_elements(nr->sockets));

	return 0;
}

static int cmd_socket_list(FILE *fp, UNUSED FILE *fp_err, void *ctx, UNUSED fr_cmd_info_t const *info)
{
	fr_network_t const		*nr = ctx;
	fr_rb_iter_inorder_t	iter;
	fr_network_socket_t		*socket;

	// @todo - note that this isn't thread-safe!

	for (socket = fr_rb_iter_init_inorder(&iter, nr->sockets);
	     socket;
	     socket = fr_rb_iter_next_inorder(&iter)) {
		if (!socket->listen->app_io->get_name) {
			fprintf(fp, "%s\n", socket->listen->app_io->name);
		} else {
			fprintf(fp, "%d\t%s\n", socket->number, socket->listen->app_io->get_name(socket->listen));
		}
	}
	return 0;
}

static int cmd_stats_socket(FILE *fp, FILE *fp_err, void *ctx, fr_cmd_info_t const *info)
{
	fr_network_t const *nr = ctx;
	fr_network_socket_t *s;

	s = fr_rb_find(nr->sockets_by_num, &(fr_network_socket_t){ .number = info->box[0]->vb_uint32 });
	if (!s) {
		fprintf(fp_err, "No such socket number '%s'.\n", info->argv[0]);
		return -1;
	}

	fprintf(fp, "count.in\t%" PRIu64 "\n", s->stats.in);
	fprintf(fp, "count.out\t%" PRIu64 "\n", s->stats.out);
	fprintf(fp, "count.dup\t%" PRIu64 "\n", s->stats.dup);
	fprintf(fp, "count.dropped\t%" PRIu64 "\n", s->stats.dropped);

	return 0;
}


fr_cmd_table_t cmd_network_table[] = {
	{
		.parent = "stats",
		.name = "network",
		.help = "Statistics for network threads.",
		.read_only = true
	},

	{
		.parent = "stats network",
		.add_name = true,
		.name = "self",
		.func = cmd_stats_self,
		.help = "Show statistics for a specific network thread.",
		.read_only = true
	},

	{
		.parent = "stats network",
		.add_name = true,
		.name = "socket",
		.syntax = "INTEGER",
		.func = cmd_stats_socket,
		.help = "Show statistics for a specific socket",
		.read_only = true
	},

	{
		.parent = "show",
		.name = "network",
		.help = "Show information about network threads.",
		.read_only = true
	},

	{
		.parent = "show network",
		.add_name = true,
		.name = "socket",
		.syntax = "list",
		.func = cmd_socket_list,
		.help = "List the sockets associated with this network thread.",
		.read_only = true
	},

	CMD_TABLE_END
};
