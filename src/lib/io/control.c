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

#include <freeradius-devel/io/atomic_queue.h>
#include <freeradius-devel/io/control.h>
#include <freeradius-devel/util/debug.h>
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
 *	A message buffer large enough for any element the queue accepts.
 */
#define CACHE_LINE_BYTES	(128)

/**
 *  The header of every message
 *
 *  A message is this header followed by data_size bytes, copied by
 *  value into the receiver's queue.  The queue places elements 8 byte
 *  aligned, and the header is 8 bytes, so callbacks can read their
 *  structs straight out of the data.
 */
typedef struct {
	fr_control_eventset_t		es;		//!< event set of this message
	uint16_t			event;		//!< event this message signals, within its event set
	uint32_t			data_size;     	//!< size of the data we're sending
} fr_control_header_t;

static_assert(sizeof(fr_control_header_t) == 8, "control message data must stay 8 byte aligned");


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

	uint16_t		slots;			//!< messages the queue holds unread.
	uint16_t		max_size;		//!< the largest payload a message may carry.

	fr_atomic_queue_t	*aq;			//!< the messages, header and data by value.

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

/** The size of one queued message: header and the largest payload
 */
static inline size_t control_message_size(fr_control_t const *c)
{
	return sizeof(fr_control_header_t) + c->max_size;
}

/** Dispatch every queued message
 *
 * Called from the reading thread only.
 *
 * @param[in] c the control structure.
 * @return how many messages were dispatched.
 */
static inline unsigned int control_service(fr_control_t *c)
{
	fr_time_t	now = fr_time();
	uint8_t		rec[CACHE_LINE_BYTES];
	unsigned int	num = 0;

	while (fr_atomic_queue_spsc_pop(c->aq, rec)) {
		fr_control_header_t const	*hdr = (fr_control_header_t const *) rec;
		fr_control_ctx_t const		*cctx = control_ctx_find(c, hdr->es, hdr->event);

		num++;
		if (!cctx) continue;

		cctx->callback(rec + sizeof(*hdr), hdr->data_size, now, cctx->uctx);
	}

	return num;
}

/** Drain the wakeup socket, then dispatch every queued message
 *
 * Each byte on the socket announces that a message was queued while we
 * were asleep.  A read returns a single datagram no matter how large the
 * buffer is, so keep reading until there are none left.
 */
static void control_read(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_control_t	*c = talloc_get_type_abort(uctx, fr_control_t);
	uint8_t		buf[256];
	ssize_t		slen;

	do {
		slen = read(fd, buf, sizeof(buf));
	} while ((slen > 0) || ((slen < 0) && (errno == EINTR)));

	(void) control_service(c);
}

/** Free a control structure
 *
 *  Removes the socket from the event loop, and closes both ends.
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
 * @param[in] slots how many messages the socket holds unread.
 * @param[in] max_size the largest payload a message may carry.
 * @return
 *	- NULL on error
 *	- fr_control_t on success
 */
fr_control_t *fr_control_create(TALLOC_CTX *ctx, fr_event_list_t *el, uint16_t slots, uint16_t max_size)
{
	fr_control_t *c;

	MEM(c = talloc_zero(ctx, fr_control_t));
	c->el = el;
	c->slots = slots;
	c->max_size = max_size;

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
	 *	A datagram socketpair for the wakeups.  Its default buffer
	 *	is small, and that is wanted: once it is full the reader has
	 *	wakeups it has not consumed, and further writes fail cheaply
	 *	instead of queueing.  A socket can also carry descriptors as
	 *	ancillary data, and the two ends can live in different
	 *	processes.
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

	/*
	 *	Room for "slots" unread messages.
	 */
	c->aq = fr_atomic_queue_talloc(c, c->slots, control_message_size(c));
	if (!c->aq) {
		fr_strerror_const("Failed creating control message queue");
		return -1;
	}

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

/** Send a control-plane message
 *
 *  Called from the originating threads.  The message is copied into
 *  the receiver's queue, then a byte is written to the wakeup socket.
 *
 * @param[in] c the control structure
 * @param[in] es the event set of this message.
 * @param[in] ev the event this message signals, within its event set.
 * @param[in] data the data to write to the control plane
 * @param[in] data_size the size of the data to write to the control plane.
 * @return
 *	- <0 on error, including the queue being full.
 *	- 0 on success
 */
int fr_control_message_send(fr_control_t *c, fr_control_eventset_t es, uint16_t ev,
			    void const *data, size_t data_size)
{
	uint8_t			rec[CACHE_LINE_BYTES];
	fr_control_header_t	*hdr = (fr_control_header_t *) rec;
	ssize_t			slen;

	(void) talloc_get_type_abort(c, fr_control_t);

	if (c->same_thread) {
		fr_control_ctx_t const *cctx = control_ctx_find(c, es, ev);

		if (!cctx) return -1;

		cctx->callback(data, data_size, fr_time(), cctx->uctx);
		return 0;
	}

	if (!fr_cond_assert_msg(data_size <= c->max_size, "Control message of %zu bytes exceeds max_size %u",
				data_size, c->max_size)) return -1;

	hdr->es = es;
	hdr->event = ev;
	hdr->data_size = data_size;
	memcpy(rec + sizeof(*hdr), data, data_size);

	if (!fr_atomic_queue_mpmc_push(c->aq, rec)) {
		fr_strerror_const("Control message queue full");
		return -1;
	}

	if (!fr_control_is_sleeping(c)) return 0;

	/*
	 *	Wake the reader.  A full socket means it has wakeups it
	 *	has not consumed, so this one is not needed.  Linux reports
	 *	a full datagram socket as EAGAIN, macOS as ENOBUFS.
	 */
	do {
		slen = write(c->fd[1], ".", 1);
	} while ((slen < 0) && (errno == EINTR));

	if ((slen < 0) && (errno != EAGAIN) && (errno != EWOULDBLOCK) && (errno != ENOBUFS)) {
		fr_strerror_printf("Failed waking control reader: %s", fr_syserror(errno));
		return -1;
	}

	return 0;
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
 * Call this before blocking, then check any other work queues one last
 * time.  A sender pushes work, then checks this flag.  The seq_cst
 * fences stop either side reordering its store after its load, so one
 * of them always sees the other.
 *
 * @param[in] c the control structure.
 * @return
 *	- true if messages were serviced, so the caller must not block.
 *	- false if the queue was empty.
 */
bool fr_control_sleeping(fr_control_t *c)
{
	atomic_store_explicit(&c->sleeping, true, memory_order_seq_cst);
	atomic_thread_fence(memory_order_seq_cst);

	if (control_service(c) == 0) return false;

	fr_control_awake(c);
	return true;
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

	/*
	 *	Senders only wake a reader which announced it is blocking,
	 *	and a message may have arrived before we announced.
	 */
	if (fr_control_sleeping(c)) return;

	fd.fd = c->fd[0];
	fd.events = POLLIN;

	(void) poll(&fd, 1, -1);

	fr_control_awake(c);
}
