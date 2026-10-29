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
 * @brief Control-plane signaling
 * @file io/control.c
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/io/control.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/rand.h>

#ifdef HAVE_STDATOMIC_H
#  include <stdatomic.h>
#else
#  include <freeradius-devel/util/stdatomic.h>
#endif

#include <fcntl.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <poll.h>

/*
 *	Debugging, mainly for channel_test
 */
#if 0
#define MPRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define MPRINT(...)
#endif

/**
 *  Status of control messages
 */
typedef enum fr_control_message_status_t : uint8_t {
	FR_CONTROL_MESSAGE_FREE = 0,			//!< the message is free
	FR_CONTROL_MESSAGE_USED,			//!< the message is used (set only by originator)
	FR_CONTROL_MESSAGE_DONE				//!< the message is done (set only by receiver)
} fr_control_message_status_t;


/**
 *  The header for the control message
 */
typedef struct {
	fr_control_message_status_t	status;		//!< status of this message
	fr_control_eventset_t		es;		//!< event set of this message
	uint16_t			event;		//!< event this message signals, within its event set
	size_t				data_size;     	//!< size of the data we're sending
} fr_control_message_t;


typedef struct {
	fr_control_callback_t		callback;	//!< the function to call
	void				*uctx;		//!< context for the callback
} fr_control_ctx_t;

/**
 *  The dispatch table for one event set
 */
typedef struct {
	uint16_t			num;		//!< the size of the callback array
	fr_control_ctx_t		*events;		//!< callbacks, indexed by event
} fr_control_eventset_table_t;


/**
 *  The control structure.
 */
struct fr_control_s {
	fr_event_list_t		*el;			//!< our event list

	fr_atomic_queue_t	*aq;			//!< destination AQ

	int			fd[2];			//!< wakeup socketpair.  [0] is read by the event loop,
							///< [1] is written by the senders.

	bool			same_thread;		//!< are the two ends in the same thread

	bool			opened;			//!< has the control path been opened.

	atomic_bool		sleeping;		//!< the reader is blocked waiting for a signal.

	fr_control_eventset_table_t	eventsets[FR_CONTROL_EVENTSET_MAX];	//!< one table per event set
};

/** Find the callback registered for a message
 *
 * @param[in] c the control structure
 * @param[in] es the event set of the message
 * @param[in] ev the event, within its event set
 * @return
 *	- NULL if nothing is registered for this event set and event.
 *	- the callback entry otherwise.
 */
static inline fr_control_ctx_t const *control_ctx_find(fr_control_t const *c, fr_control_eventset_t es, uint16_t ev)
{
	fr_control_eventset_table_t const *eventset;

	if (es >= FR_CONTROL_EVENTSET_MAX) return NULL;

	eventset = &c->eventsets[es];
	if (ev >= eventset->num) return NULL;
	if (!eventset->events[ev].callback) return NULL;

	return &eventset->events[ev];
}

static void control_read(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_control_t *c = talloc_get_type_abort(uctx, fr_control_t);
	fr_time_t now;
	char read_buffer[256];
	uint8_t	data[256];
	ssize_t message_size;
	ssize_t slen;
	fr_control_eventset_t es = 0;
	uint16_t ev = 0;

	/*
	 *	Each datagram on the socket announces one message, and
	 *	the loop below pops every message in the atomic queue, so
	 *	empty the socket.  A read returns a single datagram no
	 *	matter how large the buffer is, so keep reading until
	 *	there are none left.  The queue is popped even when the
	 *	read fails, as a complete drain always ends with EAGAIN.
	 */
	do {
		slen = read(fd, read_buffer, sizeof(read_buffer));
	} while ((slen > 0) || ((slen < 0) && (errno == EINTR)));

	now = fr_time();

	while((message_size = fr_control_message_pop(c->aq, &es, &ev, data, sizeof(data)))) {
		fr_control_ctx_t const *cctx = control_ctx_find(c, es, ev);

		if (!cctx) continue;

		cctx->callback(data, message_size, now, cctx->uctx);
	}
}

/** Free a control structure
 *
 *  This function really only calls the underlying "garbage collect".
 *
 * @param[in] c the control structure
 */
static int _control_free(fr_control_t *c)
{
	(void) talloc_get_type_abort(c, fr_control_t);

#ifndef NDEBUG
	(void) fr_event_fd_unarmour(c->el, c->fd[0], FR_EVENT_FILTER_IO, (uintptr_t)c);
#endif
	(void) fr_event_fd_delete(c->el, c->fd[0], FR_EVENT_FILTER_IO);

	close(c->fd[0]);
	close(c->fd[1]);

	return 0;
}

/** Create a control-plane signaling path.
 *
 * @param[in] ctx the talloc context
 * @param[in] el the event list for the control socket
 * @param[in] aq the atomic queue where we will be pushing message data
 * @return
 *	- NULL on error
 *	- fr_control_t on success
 */
fr_control_t *fr_control_create(TALLOC_CTX *ctx, fr_event_list_t *el, fr_atomic_queue_t *aq)
{
	fr_control_t *c;

	MEM(c = talloc_zero(ctx, fr_control_t));
	c->el = el;
	c->aq = aq;

	return c;
}

/** Open the control-plane signalling path
 *
 * @param[in] c the control-plane to open
 * @return
 * 	- 0 on success
 * 	- -1 on failure
 */
int fr_control_open(fr_control_t *c)
{
	/*
	 *	A datagram socketpair rather than a pipe.  The wakeups
	 *	are still single bytes, but a socket can also carry
	 *	descriptors as ancillary data, and the two ends can live
	 *	in different processes.
	 */
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, c->fd) < 0) {
		fr_strerror_printf("Failed opening socketpair for control socket: %s", fr_syserror(errno));
		return -1;
	}
	talloc_set_destructor(c, _control_free);

	/*
	 *	We don't want reads from the socket to be blocking.
	 */
	(void) fr_nonblock(c->fd[0]);
	(void) fr_nonblock(c->fd[1]);
	(void) fr_cloexec(c->fd[0]);
	(void) fr_cloexec(c->fd[1]);

	if (fr_event_fd_insert(c, NULL, c->el, c->fd[0], control_read, NULL, NULL, c) < 0) {
		fr_strerror_const_push("Failed adding FD to event list control socket");
		return -1;
	}

#ifndef NDEBUG
	(void) fr_event_fd_armour(c->el, c->fd[0], FR_EVENT_FILTER_IO, (uintptr_t)c);
#endif
	c->opened = true;

	return 0;
}

/** Clean up messages in a control-plane buffer
 *
 *  Find the oldest messages which are marked FR_CONTROL_MESSAGE_DONE,
 *  and mark them FR_CONTROL_MESSAGE_FREE.
 *
 * @param[in] c the fr_control_t
 * @param[in] rb the callers ring buffer for message allocation.
 * @return
 *	- <0 there are still messages used
 *	- 0 the control list is empty.
 */
int fr_control_gc(UNUSED fr_control_t *c, fr_ring_buffer_t *rb)
{
	while (true) {
		size_t room, message_size;
		fr_control_message_t *m;

		(void) fr_ring_buffer_start(rb, (uint8_t **) &m, &room);
		if (room == 0) break;

		fr_assert(m != NULL);
		fr_assert(room >= sizeof(*m));

		fr_assert(m->status != FR_CONTROL_MESSAGE_FREE);

		if (m->status != FR_CONTROL_MESSAGE_DONE) break;

		m->status = FR_CONTROL_MESSAGE_FREE;

		/*
		 *	Each message is aligned to a 64-byte boundary,
		 *	for cache contention issues.
		 */
		message_size = sizeof(*m);
		message_size += m->data_size;
		message_size += 63;
		message_size &= ~(size_t) 63;
		fr_ring_buffer_free(rb, message_size);
	}

	/*
	 *	Maybe we failed to garbage collect everything?
	 */
	if (fr_ring_buffer_used(rb) > 0) {
		fr_strerror_const("Data still in control buffers");
		return -1;
	}

	return 0;
}


/** Allocate a control message
 *
 * @param[in] c the control structure
 * @param[in] rb the callers ring buffer for message allocation.
 * @param[in] es the event set of this message.
 * @param[in] ev the event this message signals, within its event set.
 * @param[in] data the data to write to the control plane
 * @param[in] data_size the size of the data to write to the control plane.
 * @return
 *	- NULL on error
 *	- fr_message_t on success
 */
static fr_control_message_t *fr_control_message_alloc(fr_control_t *c, fr_ring_buffer_t *rb,
						      fr_control_eventset_t es, uint16_t ev,
						      void *data, size_t data_size)
{
	size_t message_size;
	fr_control_message_t *m;
	uint8_t *p;

	message_size = sizeof(*m);
	message_size += data_size;
	message_size += 63;
	message_size &= ~(size_t) 63;

	m = (fr_control_message_t *) fr_ring_buffer_alloc(rb, message_size);
	if (!m) {
		(void) fr_control_gc(c, rb);
		m = (fr_control_message_t *) fr_ring_buffer_alloc(rb, message_size);
		if (!m) {
			fr_strerror_const_push("Failed allocating from ring buffer");
			return NULL;
		}
	}

	m->status = FR_CONTROL_MESSAGE_USED;
	m->es = es;
	m->event = ev;
	m->data_size = data_size;

	p = (uint8_t *) m;
	memcpy(p + sizeof(*m), data, data_size);

	return m;

}


/** Push a control-plane message
 *
 *  This function is called ONLY from the originating threads.
 *
 * @param[in] c the control structure
 * @param[in] rb the callers ring buffer for message allocation.
 * @param[in] es the event set of this message.
 * @param[in] ev the event this message signals, within its event set.
 * @param[in] data the data to write to the control plane
 * @param[in] data_size the size of the data to write to the control plane.
 * @return
 *	- -2 on ring buffer full
 *	- <0 on error
 *	- 0 on success
 */
int fr_control_message_push(fr_control_t *c, fr_ring_buffer_t *rb, fr_control_eventset_t es, uint16_t ev,
			    void *data, size_t data_size)
{
	fr_control_message_t *m;

	(void) talloc_get_type_abort(c, fr_control_t);

	MPRINT("CONTROL push aq %p\n", c->aq);

	/*
	 *	Get a message.  The alloc call attempts garbage collection
	 *	if there is not enough free space.
	 */
	m = fr_control_message_alloc(c, rb, es, ev, data, data_size);
	if (!m) {
		fr_strerror_const_push("Failed allocating after GC");
		return -2;
	}

	if (!fr_atomic_queue_mpmc_push(c->aq, &m)) {
		m->status = FR_CONTROL_MESSAGE_DONE;
		fr_strerror_const("Failed pushing message to atomic queue.");
		return -1;
	}

	return 0;
}

/** Send a control-plane message
 *
 *  This function is called ONLY from the originating threads.
 *
 * @param[in] c the control structure
 * @param[in] rb the callers ring buffer for message allocation.
 * @param[in] es the event set of this message.
 * @param[in] ev the event this message signals, within its event set.
 * @param[in] data the data to write to the control plane
 * @param[in] data_size the size of the data to write to the control plane.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_control_message_send(fr_control_t *c, fr_ring_buffer_t *rb, fr_control_eventset_t es, uint16_t ev,
			    void *data, size_t data_size)
{
	(void) talloc_get_type_abort(c, fr_control_t);

	if (c->same_thread) {
		fr_control_ctx_t const *cctx = control_ctx_find(c, es, ev);

		if (!cctx) return -1;

		cctx->callback(data, data_size, fr_time(), cctx->uctx);
		return 0;
	}

	if (fr_control_message_push(c, rb, es, ev, data, data_size) < 0) return -1;

redo:
	if (write(c->fd[1], ".", 1) >= 0) return 0;

	if (errno == EINTR) goto redo;

	/*
	 *	The socket is full, so it holds wakeups the reader has
	 *	not consumed yet.  When it drains them it pops every
	 *	message in the queue, including the one just pushed, so
	 *	this wakeup is not needed.  Linux reports a full datagram
	 *	socket as EAGAIN, macOS as ENOBUFS.
	 */
	if (errno == EAGAIN) return 0;
	if (errno == ENOBUFS) return 0;

#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
	if (errno == EWOULDBLOCK) return 0;
#endif

	/*
	 *	Other error, that's an issue.
	 */
	return -1;
}


/** Pop control-plane message
 *
 *  This function is called ONLY from the receiving thread.
 *
 * @param[in] aq the recipients atomic queue for control-plane messages
 * @param[out] p_es the event set of this message.
 * @param[out] p_ev the event this message signals, within its event set.
 * @param[in,out] data where the data is stored
 * @param[in] data_size the size of the buffer where we store the data.
 * @return
 *	- <0 the size of the data we need to read the next message
 *	- 0 this kevent is not for us.
 *	- >0 the amount of data we've read
 */
ssize_t fr_control_message_pop(fr_atomic_queue_t *aq, fr_control_eventset_t *p_es, uint16_t *p_ev,
			       void *data, size_t data_size)
{
	uint8_t *p;
	fr_control_message_t *m;

	MPRINT("CONTROL pop aq %p\n", aq);

	if (!fr_atomic_queue_spsc_pop(aq, &m)) return 0;

	fr_assert_msg(m->status == FR_CONTROL_MESSAGE_USED, "Bad control message state, expected %u got %u",
		      FR_CONTROL_MESSAGE_USED, m->status);

	/*
	 *	There isn't enough room to store the data, die.
	 */
	if (data_size < m->data_size) {
		fr_strerror_printf("Allocation size should be at least %zu", m->data_size);
		m->status = FR_CONTROL_MESSAGE_DONE;
		return -(m->data_size);
	}

	p = (uint8_t *) m;
	data_size = m->data_size;
	memcpy(data, p + sizeof(*m), data_size);

	m->status = FR_CONTROL_MESSAGE_DONE;
	*p_es = m->es;
	*p_ev = m->event;
	return data_size;
}


/** Register a callback for a message
 *
 * @param[in] c the control structure
 * @param[in] es the event set of the message.
 * @param[in] ev the event, within its event set.
 * @param[in] callback the callback function
 * @param[in] uctx the context passed to the callback
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_control_callback_add(fr_control_t *c, fr_control_eventset_t es, uint16_t ev,
			    fr_control_callback_t callback, void *uctx)
{
	fr_control_eventset_table_t	*eventset;

	(void) talloc_get_type_abort(c, fr_control_t);

	if (c->opened) {
		fr_strerror_printf("Cannot add callbacks after the control is opened");
		return -1;
	}

	if (es >= FR_CONTROL_EVENTSET_MAX) {
		fr_strerror_printf("Unknown control event set %" PRIu16, es);
		return -1;
	}
	eventset = &c->eventsets[es];

	/*
	 *	If there is not enough space in the array of callbacks
	 *	re-allocate it with a larger one.  The array is a child
	 *	of the control, so the control itself never moves.
	 */
	if (ev >= eventset->num) {
		MEM(eventset->events = talloc_realloc(c, eventset->events, fr_control_ctx_t, ev + 1));

		/*
		 *	Zero the additional callback entries.
		 */
		memset(eventset->events + eventset->num, 0, (ev + 1 - eventset->num) * sizeof(*eventset->events));
		eventset->num = ev + 1;
	}

	/*
	 *	Re-registering the same thing is OK.
	 */
	if ((eventset->events[ev].uctx == uctx) &&
	    (eventset->events[ev].callback == callback)) {
		return 0;
	}

	if (eventset->events[ev].callback != NULL) {
		fr_strerror_const("Callback is already set");
		return -1;
	}

	eventset->events[ev].uctx = uctx;
	eventset->events[ev].callback = callback;

	return 0;
}

/** Delete a callback for a message
 *
 * @param[in] c the control structure
 * @param[in] es the event set of the message.
 * @param[in] ev the event, within its event set.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_control_callback_delete(fr_control_t *c, fr_control_eventset_t es, uint16_t ev)
{
	fr_control_eventset_table_t	*eventset;

	(void) talloc_get_type_abort(c, fr_control_t);

	if ((es >= FR_CONTROL_EVENTSET_MAX) || (ev >= c->eventsets[es].num)) {
		fr_strerror_printf("Failed deleting unknown event %" PRIu16 " in event set %" PRIu16, ev, es);
		return -1;
	}
	eventset = &c->eventsets[es];

	eventset->events[ev].uctx = NULL;
	eventset->events[ev].callback = NULL;

	return 0;
}

/** Record that the reader of this control plane is about to block
 *
 * Call this before blocking, then check the work queues one last time.  A
 * sender pushes work, then checks this flag.  The seq_cst fences stop either
 * side reordering its store after its load, so one of them always sees the
 * other.  Weaker orderings permit the lost wakeup this exists to prevent.
 *
 * A spurious signal is a wasted wakeup.  A skipped signal is a stall.  Err
 * towards signalling.
 *
 * @param[in] c the control structure.
 */
void fr_control_sleeping(fr_control_t *c)
{
	atomic_store_explicit(&c->sleeping, true, memory_order_seq_cst);
	atomic_thread_fence(memory_order_seq_cst);
}

/** Record that the reader of this control plane is running again
 *
 * Call this as soon as the reader stops blocking, whatever woke it.
 *
 * @param[in] c the control structure.
 */
void fr_control_awake(fr_control_t *c)
{
	atomic_store_explicit(&c->sleeping, false, memory_order_seq_cst);
}

/** Check whether the reader of this control plane is blocked
 *
 * Call this after pushing work, to decide whether a signal is needed.  The
 * fence orders the push before the load.  See fr_control_sleeping().
 *
 * @param[in] c the control structure.
 * @return
 *	- true if the reader is blocked, and must be signalled.
 *	- false if the reader is running, and will find the work itself.
 */
bool fr_control_is_sleeping(fr_control_t *c)
{
	atomic_thread_fence(memory_order_seq_cst);
	return atomic_load_explicit(&c->sleeping, memory_order_seq_cst);
}

int fr_control_same_thread(fr_control_t *c)
{
	c->same_thread = true;
	(void) fr_event_fd_delete(c->el, c->fd[0], FR_EVENT_FILTER_IO);
	close(c->fd[0]);
	close(c->fd[1]);

	/*
	 *	Nothing more to do now that everything is gone.
	 */
	talloc_set_destructor(c, NULL);

	return 0;
}

/** Wait for a plane control to become readable
 *
 * This is a blocking function so only to be used in rare cases such as waiting
 * for another thread to complete a task before proceeding.
 *
 * @param[in] c the control structure.
 */
void fr_control_wait(fr_control_t *c)
{
	struct pollfd	fd;

	fd.fd = c->fd[0];
	fd.events = POLLIN;

	(void) poll(&fd, 1, -1);
}
