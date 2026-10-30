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
#include <pthread.h>
#include <stddef.h>
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

/**
 *  Ancillary data for the one socket a datagram may carry
 *
 *  Used on both sides.  Aligned as the CMSG macros require, without
 *  embedding a cmsghdr, as on Linux that ends in a flexible array and
 *  cannot then sit in an array of these.
 */
typedef struct {
	_Alignas(struct cmsghdr) uint8_t	buf[CMSG_SPACE(sizeof(int))];	//!< one cmsghdr and one int.
} control_socket_cmsg_t;

/*
 *	Datagrams one recvmmsg() takes off the wakeup socket.  Most are
 *	wakeups.  The default buffer holds about 32 on macOS and about
 *	280 on Linux before senders see it as full, so one batch usually
 *	empties it on macOS, and takes a few calls on Linux.
 */
#define CONTROL_SOCKET_MSGS_PER_READ	(64)

/*
 *	Datagrams carrying a socket the wakeup socket should hold.  Linux
 *	doubles a buffer request and clamps it at twice net.core.wmem_max
 *	and rmem_max, so with their default of 212992 this is about the
 *	most that fits there.
 */
#define CONTROL_SOCKET_DATAGRAMS	(512)

/*
 *	What one datagram carrying a socket takes up in a socket buffer,
 *	which is the kernel's own bookkeeping and not the bytes sent.
 *	Measured once, the first time a control is opened.  The initial
 *	value is what Linux was measured at, and is used if the
 *	measurement fails.
 */
static size_t		control_socket_dgram_size_actual = 768;
static pthread_once_t	control_socket_dgram_size_once = PTHREAD_ONCE_INIT;

/** Measure what one datagram carrying a socket takes up in a socket buffer
 *
 */
static void control_socket_dgram_size_measure(void)
{
	int			sv[2];
	int			bufsize = 65536;
	int			sndbuf, rcvbuf;
	socklen_t		len;
	fr_control_header_t	hdr = {};
	control_socket_cmsg_t	cmsg;
	struct iovec		iov;
	struct msghdr		mh;
	struct cmsghdr		*ch;
	unsigned int		num = 0;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) return;

	(void) setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
	(void) setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
	(void) fr_nonblock(sv[0]);
	(void) fr_nonblock(sv[1]);

	iov.iov_base = &hdr;
	iov.iov_len = sizeof(hdr);

	memset(&cmsg, 0, sizeof(cmsg));
	memset(&mh, 0, sizeof(mh));
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = &cmsg;
	mh.msg_controllen = sizeof(cmsg);

	ch = CMSG_FIRSTHDR(&mh);
	ch->cmsg_level = SOL_SOCKET;
	ch->cmsg_type = SCM_RIGHTS;
	ch->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(ch), &sv[1], sizeof(int));

	while (sendmsg(sv[1], &mh, 0) == sizeof(hdr)) num++;

	/*
	 *	Whichever side the kernel counts against, both were asked
	 *	for the same size, so the smaller of what it granted is the
	 *	bound.
	 */
	len = sizeof(sndbuf);
	if (getsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &sndbuf, &len) < 0) sndbuf = bufsize;
	len = sizeof(rcvbuf);
	if (getsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &rcvbuf, &len) < 0) rcvbuf = bufsize;
	if (num > 0) control_socket_dgram_size_actual = ((sndbuf < rcvbuf) ? sndbuf : rcvbuf) / num;

	while (num > 0) {
		int sock = -1;

		mh.msg_controllen = sizeof(cmsg);
		if (recvmsg(sv[0], &mh, 0) < 0) break;
		ch = CMSG_FIRSTHDR(&mh);
		if (ch && (ch->cmsg_level == SOL_SOCKET) && (ch->cmsg_type == SCM_RIGHTS)) {
			memcpy(&sock, CMSG_DATA(ch), sizeof(sock));
			close(sock);
		}
		num--;
	}

	close(sv[0]);
	close(sv[1]);
}

/*
 *	Received sockets must be close-on-exec.  Linux can set that as
 *	they are received, elsewhere it is set just after.
 */
#ifdef MSG_CMSG_CLOEXEC
#  define CONTROL_RECV_FLAGS		MSG_CMSG_CLOEXEC
#else
#  define CONTROL_RECV_FLAGS		0
#endif

typedef struct {
	fr_control_callback_t		callback;	//!< the function to call
	void				*uctx;		//!< context for the callback
} fr_control_ctx_t;

typedef struct {
	fr_control_socket_callback_t	callback;	//!< the function to call
	void				*uctx;		//!< context for the callback
} fr_control_socket_ctx_t;

/**
 *  The dispatch table for one event set
 */
typedef struct {
	uint16_t			events_num;	//!< the size of the callback array
	fr_control_ctx_t		*events;		//!< callbacks, indexed by event

	uint16_t			socket_events_num;	//!< the size of the socket callback array
	fr_control_socket_ctx_t		*socket_events;	//!< callbacks for messages carrying a socket,
							///< indexed by event
} fr_control_eventset_table_t;


/**
 *  The control structure.
 */
struct fr_control_s {
	fr_event_list_t		*el;			//!< our event list

	uint16_t		slots;			//!< messages the queue holds unread.
	uint16_t		max_size;		//!< the largest payload a message may carry.

	fr_atomic_queue_t	*aq;			//!< the messages, header and data by value.

	struct {
		struct mmsghdr		msgs[CONTROL_SOCKET_MSGS_PER_READ];	//!< one per datagram, for recvmmsg().
		struct iovec		iov[CONTROL_SOCKET_MSGS_PER_READ];	//!< one per datagram.
		fr_control_header_t	hdr[CONTROL_SOCKET_MSGS_PER_READ];	//!< where the datagrams land.
		control_socket_cmsg_t	cmsg[CONTROL_SOCKET_MSGS_PER_READ];	//!< where their sockets land.
	} socket;

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
	if (ev >= eventset->events_num) return NULL;
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

/** Dispatch one datagram taken off the wakeup socket
 *
 * @param[in] c the control structure.
 * @param[in] mmh the recvmmsg() slot the datagram landed in.
 * @param[in] hdr the datagram, which should be a bare message header.
 * @param[in] now when the batch was read.
 */
static void control_socket_dispatch(fr_control_t *c, struct mmsghdr *mmh, fr_control_header_t const *hdr,
				    fr_time_t now)
{
	struct msghdr			*mh = &mmh->msg_hdr;
	struct cmsghdr			*ch = CMSG_FIRSTHDR(mh);
	fr_control_socket_ctx_t const	*cctx = NULL;
	int				sock;

	if (!ch || (ch->cmsg_level != SOL_SOCKET) || (ch->cmsg_type != SCM_RIGHTS) ||
	    (ch->cmsg_len != CMSG_LEN(sizeof(int)))) {
		fr_cond_assert_msg(!(mh->msg_flags & MSG_CTRUNC), "Control socket message truncated");
		return;
	}
	memcpy(&sock, CMSG_DATA(ch), sizeof(sock));
#ifndef MSG_CMSG_CLOEXEC
	(void) fr_cloexec(sock);
#endif

	if (!fr_cond_assert_msg(!(mh->msg_flags & (MSG_TRUNC | MSG_CTRUNC)), "Control socket message truncated") ||
	    !fr_cond_assert_msg(mmh->msg_len == sizeof(*hdr), "Malformed control message with socket")) {
		close(sock);
		return;
	}

	if ((hdr->es < FR_CONTROL_EVENTSET_MAX) && (hdr->event < c->eventsets[hdr->es].socket_events_num)) {
		cctx = &c->eventsets[hdr->es].socket_events[hdr->event];
	}
	if (!fr_cond_assert_msg(cctx && cctx->callback, "No callback for socket event %u in event set %u",
				hdr->event, hdr->es)) {
		close(sock);
		return;
	}

	cctx->callback(sock, now, cctx->uctx);
}

/** Take a batch of datagrams off the wakeup socket, then dispatch every queued message
 *
 * Each datagram is a wakeup, announcing that a message was queued while
 * we were asleep, or a message carying file descriptors in its metdata.
 */
static void control_read(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	fr_control_t	*c = talloc_get_type_abort(uctx, fr_control_t);
	int		num, i;

	for (i = 0; i < CONTROL_SOCKET_MSGS_PER_READ; i++) {
		c->socket.msgs[i].msg_hdr.msg_controllen = sizeof(c->socket.cmsg[i]);
		c->socket.msgs[i].msg_hdr.msg_flags = 0;
	}

	do {
		num = recvmmsg(fd, c->socket.msgs, CONTROL_SOCKET_MSGS_PER_READ, CONTROL_RECV_FLAGS, NULL);
	} while ((num < 0) && (errno == EINTR));

	if (num > 0) {
		fr_time_t now = fr_time();

		for (i = 0; i < num; i++) control_socket_dispatch(c, &c->socket.msgs[i], &c->socket.hdr[i], now);
	}

	(void) control_service(c);
}

/** Announce that the reader is about to block, and drain the queue one last time
 *
 * The event list runs this when the loop reading this control is about
 * to idle, so every control read by a loop announces itself, whether or
 * not the loop knows about it.
 *
 * @param[in] uctx the control structure.
 * @return
 *	- 1 if messages were found, so the loop must not block.
 *	- 0 if the queue was empty.
 */
static int control_pre_event(UNUSED fr_time_t now, UNUSED fr_time_delta_t wake, void *uctx)
{
	fr_control_t	*c = talloc_get_type_abort(uctx, fr_control_t);

	return fr_control_sleeping(c) ? 1 : 0;
}

/** The reader is running again
 *
 * @param[in] uctx the control structure.
 */
static void control_post_event(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	fr_control_t	*c = talloc_get_type_abort(uctx, fr_control_t);

	fr_control_awake(c);
}

/** Free a control structure
 *
 *  Removes the socket and the idle callbacks from the event loop, and
 *  closes both ends.
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
	(void) fr_event_pre_delete(c->el, control_pre_event, c);
	(void) fr_event_post_delete(c->el, control_post_event, c);

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
	int	i;
	int	bufsize;

	(void) pthread_once(&control_socket_dgram_size_once, control_socket_dgram_size_measure);

	/*
	 *	A datagram socketpair for the wakeups.  Once it is full the
	 *	reader has wakeups it has not consumed, and further writes
	 *	fail cheaply instead of queueing.  A socket can also carry
	 *	descriptors as ancillary data, and the two ends can live in
	 *	different processes.
	 */
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, c->fd) < 0) {
		fr_strerror_printf("Failed opening socketpair for control socket: %s", fr_syserror(errno));
		return -1;
	}
	talloc_set_destructor(c, _control_free);

	/*
	 *	The default buffer holds a few dozen datagrams.  Wakeups only
	 *	go to a sleeping reader, so they never need more, but a
	 *	datagram carrying a socket is refused when the buffer is
	 *	full, so make room for a reasonable number of those.
	 */
	bufsize = CONTROL_SOCKET_DATAGRAMS * control_socket_dgram_size_actual;
	(void) setsockopt(c->fd[0], SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
	(void) setsockopt(c->fd[1], SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));

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

	/*
	 *	Point each recvmmsg() slot at its own vector, datagram
	 *	buffer, and ancillary buffer.  Everything else in a slot
	 *	stays zero from talloc_zero().
	 */
	for (i = 0; i < CONTROL_SOCKET_MSGS_PER_READ; i++) {
		c->socket.iov[i].iov_base = &c->socket.hdr[i];
		c->socket.iov[i].iov_len = sizeof(c->socket.hdr[i]);
		c->socket.msgs[i].msg_hdr.msg_iov = &c->socket.iov[i];
		c->socket.msgs[i].msg_hdr.msg_iovlen = 1;
		c->socket.msgs[i].msg_hdr.msg_control = &c->socket.cmsg[i];
	}

	if (fr_event_fd_insert(c, NULL, c->el, c->fd[0], control_read, NULL, NULL, c) < 0) {
		fr_strerror_const_push("Failed adding FD to event list control socket");
		return -1;
	}

#ifndef NDEBUG
	(void) fr_event_fd_armour(c->el, c->fd[0], FR_EVENT_FILTER_IO, (uintptr_t)c);
#endif

	/*
	 *	Senders only wake a reader which has announced it is
	 *	blocking.  The event list tells us when that is about
	 *	to happen, and when it is over.
	 */
	if ((fr_event_pre_insert(c->el, control_pre_event, c) < 0) ||
	    (fr_event_post_insert(c->el, control_post_event, c) < 0)) {
		fr_strerror_const_push("Failed adding idle callbacks for control socket");
		return -1;
	}
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

/** Send a control-plane message carrying a socket
 *
 * @param[in] c the control structure
 * @param[in] es the event set of this message.
 * @param[in] ev the event this message signals, within its event set.
 * @param[in] sock the socket to send.
 * @return
 *	- <0 on error, including the wakeup socket being full.
 *	- 0 on success
 */
int fr_control_socket_send(fr_control_t *c, fr_control_eventset_t es, uint16_t ev, int sock)
{
	fr_control_header_t	hdr = {
		.es = es,
		.event = ev
	};
	control_socket_cmsg_t	cmsg;
	struct cmsghdr		*ch;
	struct iovec		iov;
	struct msghdr		mh;
	ssize_t			slen;

	(void) talloc_get_type_abort(c, fr_control_t);

	if (!fr_cond_assert_msg(!c->same_thread, "Control messages with sockets need a socket")) return -1;

	iov.iov_base = &hdr;
	iov.iov_len = sizeof(hdr);

	memset(&cmsg, 0, sizeof(cmsg));
	memset(&mh, 0, sizeof(mh));
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = &cmsg;
	mh.msg_controllen = sizeof(cmsg);

	ch = CMSG_FIRSTHDR(&mh);
	ch->cmsg_level = SOL_SOCKET;
	ch->cmsg_type = SCM_RIGHTS;
	ch->cmsg_len = CMSG_LEN(sizeof(sock));
	memcpy(CMSG_DATA(ch), &sock, sizeof(sock));

	do {
		slen = sendmsg(c->fd[1], &mh, 0);
	} while ((slen < 0) && (errno == EINTR));

	if (slen < 0) {
		fr_strerror_printf("Failed sending control message with socket: %s", fr_syserror(errno));
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
	if (ev >= eventset->events_num) {
		MEM(eventset->events = talloc_realloc(c, eventset->events, fr_control_ctx_t, ev + 1));

		/*
		 *	Zero the additional callback entries.
		 */
		memset(eventset->events + eventset->events_num, 0,
		       (ev + 1 - eventset->events_num) * sizeof(*eventset->events));
		eventset->events_num = ev + 1;
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

/** Register a callback for a message which carries a socket
 *
 *  Socket events are numbered separately from message events within an
 *  event set, so the same number may be registered with both this and
 *  fr_control_callback_add().  They are sent with fr_control_socket_send().
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
int fr_control_socket_callback_add(fr_control_t *c, fr_control_eventset_t es, uint16_t ev,
				   fr_control_socket_callback_t callback, void *uctx)
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
	if (ev >= eventset->socket_events_num) {
		MEM(eventset->socket_events = talloc_realloc(c, eventset->socket_events,
							     fr_control_socket_ctx_t, ev + 1));
		memset(eventset->socket_events + eventset->socket_events_num, 0,
		       (ev + 1 - eventset->socket_events_num) * sizeof(*eventset->socket_events));
		eventset->socket_events_num = ev + 1;
	}

	/*
	 *	Re-registering the same thing is OK.
	 */
	if ((eventset->socket_events[ev].uctx == uctx) &&
	    (eventset->socket_events[ev].callback == callback)) {
		return 0;
	}

	if (eventset->socket_events[ev].callback != NULL) {
		fr_strerror_const("Callback is already set");
		return -1;
	}

	eventset->socket_events[ev].uctx = uctx;
	eventset->socket_events[ev].callback = callback;

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

	if ((es >= FR_CONTROL_EVENTSET_MAX) || (ev >= c->eventsets[es].events_num)) {
		fr_strerror_printf("Failed deleting unknown event %" PRIu16 " in event set %" PRIu16, ev, es);
		return -1;
	}
	eventset = &c->eventsets[es];

	eventset->events[ev].uctx = NULL;
	eventset->events[ev].callback = NULL;

	return 0;
}

/** Delete a callback for a message which carries a socket
 *
 * @param[in] c the control structure
 * @param[in] es the event set of the message.
 * @param[in] ev the event, within its event set.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_control_socket_callback_delete(fr_control_t *c, fr_control_eventset_t es, uint16_t ev)
{
	fr_control_eventset_table_t	*eventset;

	(void) talloc_get_type_abort(c, fr_control_t);

	if ((es >= FR_CONTROL_EVENTSET_MAX) || (ev >= c->eventsets[es].socket_events_num)) {
		fr_strerror_printf("Failed deleting unknown socket event %" PRIu16 " in event set %" PRIu16, ev, es);
		return -1;
	}
	eventset = &c->eventsets[es];

	eventset->socket_events[ev].uctx = NULL;
	eventset->socket_events[ev].callback = NULL;

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
