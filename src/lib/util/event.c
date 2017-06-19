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
 * @file lib/util/event.c
 * @brief Non-thread-safe event handling, specific to a RADIUS server.
 *
 * @note By non-thread-safe we mean multiple threads can't insert/delete events concurrently
 *	without synchronization.
 *
 * @copyright 2007-2016 The FreeRADIUS server project
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2007 Alan DeKok <aland@ox.org>
 */
RCSID("$Id$")

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/heap.h>
#include <freeradius-devel/event.h>
#include <freeradius-devel/io/time.h>

#define FR_EV_BATCH_FDS (256)

#undef USEC
#define USEC (1000000)

#if !defined(SO_GET_FILTER) && defined(SO_ATTACH_FILTER)
#  define SO_GET_FILTER SO_ATTACH_FILTER
#endif

/** A timer event
 *
 */
struct fr_event_timer_t {
	fr_event_callback_t	callback;		//!< Callback to execute when the timer fires.
	void const		*ctx;			//!< Context pointer to pass to the callback.
	struct timeval		when;			//!< When this timer should fire.

	fr_event_timer_t	**parent;		//!< Previous timer.
	int			heap;			//!< Where to store opaque heap data.
};

/** A file descriptor event
 *
 */
typedef struct fr_event_fd_t {
	int			fd;			//!< File descriptor we're listening for events on.

	int                     sock_type;              //!< The type of socket SOCK_STREAM, SOCK_RAW etc...
	bool                    is_file;                //!< Is a file, not a socket.

#ifdef SO_GET_FILTER
	bool                    pf_attached;            //!< Has an attached packet filter (PF) program.
#endif

	fr_event_fd_handler_t	read;			//!< Callback for when data is available.
	fr_event_fd_handler_t	write;			//!< Callback for when we can write data.
	fr_event_fd_handler_t	error;			//!< Callback for when an error occurs on the FD.

	bool			is_registered;		//!< Whether this fr_event_fd_t's FD has been registered with
							//!< kevent.  Mostly for debugging.

	bool			in_handler;		//!< Event is currently being serviced.  Deletes should be
							//!< deferred until after the handlers complete.

	bool			do_delete;		//!< Deferred deletion flag.  Delete this event *after*
							//!< the handlers complete.

	void			*ctx;			//!< Context pointer to pass to each file descriptor callback.
} fr_event_fd_t;

/** Callbacks to perform when the event handler is about to check the events.
 *
 */
typedef struct fr_event_pre_t {
	fr_dlist_t		entry;			//!< linked list of callback
	fr_event_status_t	callback;		//!< the callback to call
	void			*ctx;			//!< context for the callback.
} fr_event_pre_t;


/** Callbacks to perform after all timers and FDs have been checked
 *
 */
typedef struct fr_event_post_t {
	fr_dlist_t		entry;			//!< linked list of callback
	fr_event_callback_t	callback;		//!< the callback to call
	void			*ctx;			//!< context for the callback.
} fr_event_post_t;


/** Callbacks for user events
 *
 */
typedef struct fr_event_user_t {
	fr_dlist_t		entry;			//!< linked list of callback
	uintptr_t		ident;			//!< the identifier of this event
	fr_event_user_handler_t callback;		//!< the callback to call
	void			*ctx;			//!< context for the callback.
} fr_event_user_t;


/** Stores all information relating to an event list
 *
 */
struct fr_event_list_t {
	fr_heap_t		*times;			//!< of timer events to be executed.
	rbtree_t		*fds;			//!< Tree used to track FDs with filters in kqueue.

	int			exit;


	struct timeval  	now;			//!< The last time the event list was serviced.
	bool			dispatch;		//!< Whether the event list is currently dispatching events.

	int			num_fds;		//!< Number of FDs listened to by this event list.
	int			num_fd_events;		//!< Number of events in this event list.

	int			kq;			//!< instance associated with this event list.

	fr_dlist_t		pre_callbacks;		//!< callbacks when we may be idle...
	fr_dlist_t		user_callbacks;		//!< EVFILT_USER callbacks
	fr_dlist_t		post_callbacks;		//!< post-processing callbacks

	struct kevent		events[FR_EV_BATCH_FDS]; /* so it doesn't go on the stack every time */
};

/** Compare two timer events to see which one should occur first
 *
 * @param[in] a the first timer event.
 * @param[in] b the second timer event.
 * @return
 *	- +1 if a should occur later than b.
 *	- -1 if a should occur earlier than b.
 *	- 0 if both events occur at the same time.
 */
static int fr_event_timer_cmp(void const *a, void const *b)
{
	fr_event_timer_t const *ev_a = a;
	fr_event_timer_t const *ev_b = b;

	if (ev_a->when.tv_sec < ev_b->when.tv_sec) return -1;
	if (ev_a->when.tv_sec > ev_b->when.tv_sec) return +1;

	if (ev_a->when.tv_usec < ev_b->when.tv_usec) return -1;
	if (ev_a->when.tv_usec > ev_b->when.tv_usec) return +1;

	return 0;
}

/** Compare two file descriptor handles
 *
 * @param[in] a the first file descriptor handle.
 * @param[in] b the second file descriptor handle.
 * @return
 *	- +1 if a is more than b.
 *	- -1 if a is less than b.
 *	- 0 if both handles refer to the same file descriptor.
 */
static int fr_event_fd_cmp(void const *a, void const *b)
{
	fr_event_fd_t const *ev_a = a;
	fr_event_fd_t const *ev_b = b;
	if (ev_a->fd < ev_b->fd) return -1;
	if (ev_a->fd > ev_b->fd) return +1;

	return 0;
}

/** Return the number of file descriptors is_registered with this event loop
 *
 */
int fr_event_list_num_fds(fr_event_list_t *el)
{
	if (!el) return -1;

	return el->num_fds;
}

/** Return the number of timer events currently scheduled
 *
 * @param[in] el to return timer events for.
 * @return number of timer events.
 */
int fr_event_list_num_elements(fr_event_list_t *el)
{
	if (!el) return -1;

	return fr_heap_num_elements(el->times);
}

/** Return the kq associated with an event list.
 *
 * @param[in] el to return timer events for.
 * @return kq
 */
int fr_event_list_kq(fr_event_list_t *el)
{
	if (!el) return -1;

	return el->kq;
}

/** Get the current time according to the event list
 *
 * If the event list is currently dispatching events, we return the time
 * this iteration of the event list started.
 *
 * If the event list is not currently dispatching events, we return the
 * current system time.
 *
 * @param[out]	when Where to write the time we extracted/acquired.
 * @param[in]	el to get time from.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
int fr_event_list_time(struct timeval *when, fr_event_list_t *el)
{
	if (!when) return -1;

	if (el && el->dispatch) {
		*when = el->now;
	} else {
		gettimeofday(when, NULL);
	}

	return 1;
}

/** Remove a file descriptor from the event loop
 *
 * @param[in] el	to remove file descriptor from.
 * @param[in] fd	to remove.
 * @return
 *	- 0 if file descriptor was removed.
 *	- <0 on error.
 */
int fr_event_fd_delete(fr_event_list_t *el, int fd)
{
	fr_event_fd_t *ef, find;

	memset(&find, 0, sizeof(find));
	find.fd = fd;

	ef = rbtree_finddata(el->fds, &find);
	if (!ef) {
		fr_strerror_printf("No events is_registered for fd %i", fd);
		return -1;
	}

	/*
	 *	Defer the delete, so we don't free
	 *	an ef structure that might still be
	 *	in use within fr_event_service.
	 */
	if (ef->in_handler) {
		ef->do_delete = true;

		return 0;
	}

	/*
	 *	Destructor may prevent ef from being
	 *	freed if kevent de-registration fails.
	 */
	if (talloc_free(ef) < 0) return -1;

	return 0;
}

/** Remove a file descriptor from the event loop
 *
 * @param[in] ef	to remove.
 * @return 0;
 */
static int _fr_event_fd_free(fr_event_fd_t *ef)
{
	int		filter = 0;
	struct kevent	evset;

	fr_event_list_t	*el = talloc_parent(ef);

	if (ef->read) filter |= EVFILT_READ;
	if (ef->write) filter |= EVFILT_WRITE;

	if (ef->is_registered) {
		EV_SET(&evset, ef->fd, filter, EV_DELETE, 0, 0, 0);
		if (kevent(el->kq, &evset, 1, NULL, 0, NULL) < 0) {
			fr_strerror_printf("Failed removing filters for FD %i: %s", ef->fd, fr_syserror(errno));
			return -1;
		}
	}
	rbtree_deletebydata(el->fds, ef);
	ef->is_registered = false;

	el->num_fds--;

	return 0;
}

/** Associate a callback with an file descriptor
 *
 * @param[in] el	to insert fd callback into.
 * @param[in] fd	to read from.
 * @param[in] read_fn	function to call when fd is readable.
 * @param[in] write_fn	function to call when fd is writable.
 * @param[in] error	function to call when an error occurs on the fd.
 * @param[in] ctx	to pass to handler.
 * @return
 *	- 0 on succes.
 *	- -1 on failure.
 */
int fr_event_fd_insert(fr_event_list_t *el, int fd,
		       fr_event_fd_handler_t read_fn,
		       fr_event_fd_handler_t write_fn,
		       fr_event_fd_handler_t error,
		       void *ctx)
{
	int	      	filter = 0;
	struct kevent	evset;
	fr_event_fd_t	*ef, find;
	bool		pre_existing;

	if (!el) {
		fr_strerror_printf("Invalid argument: NULL event list");
		return -1;
	}

	if (!read_fn && !write_fn) {
		fr_strerror_printf("Invalid arguments: NULL read and write callbacks");
		return -1;
	}

	if (fd < 0) {
		fr_strerror_printf("Invalid arguments: Bad FD %i", fd);
		return -1;
	}

	if (el->exit) {
		fr_strerror_printf("Event loop exiting");
		return -1;
	}

	memset(&find, 0, sizeof(find));

	/*
	 *	Get the existing fr_event_fd_t if it exists.
	 */
	find.fd = fd;
	ef = rbtree_finddata(el->fds, &find);
	if (!ef) {
		int             sock_type;
		socklen_t       opt_len = sizeof(sock_type);

		pre_existing = false;

		ef = talloc_zero(el, fr_event_fd_t);
		if (!ef) {
			fr_strerror_printf("Out of memory");
			return -1;
		}
		talloc_set_destructor(ef, _fr_event_fd_free);

		el->num_fds++;

		ef->fd = fd;

                /*
                 *      Retrieve file descriptor metadata
                 */
                if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &sock_type, &opt_len) < 0) {
                        if (errno != ENOTSOCK) {
                                fr_strerror_printf("Failed retrieving socket type: %s", fr_syserror(errno));
                                return -1;
                        }
                        ef->is_file = true;
                }
#ifdef SO_GET_FILTER
                else {
                        opt_len = 0;
                        if (getsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, NULL, &opt_len) < 0) {
                                fr_strerror_printf("Failed determining PF status: %s", fr_syserror(errno));
                                return -1;
                        }
                        if (opt_len) ef->pf_attached = true;
                        ef->sock_type = sock_type;
                }
#endif

		rbtree_insert(el->fds, ef);

	/*
	 *	Existing filters will be overwritten if there's
	 *	a new filter which takes their place.  If there
	 *	is no new filter however, we need to delete the
	 *	existing one.
	 */
	} else {
		pre_existing = true;

		if (ef->read && !read_fn) filter |= EVFILT_READ;
		if (ef->write && !write_fn) filter |= EVFILT_WRITE;

		if (filter) {
			EV_SET(&evset, ef->fd, filter, EV_DELETE, 0, 0, 0);

			/*
			 *	kevent on macOS sierra (and possibly others)
			 *	is broken, and doesn't allow us to perform
			 *	an EVILT_* add and delete in the same
			 *	call.
			 */
			if (kevent(el->kq, &evset, 1, NULL, 0, NULL) < 0) {
				fr_strerror_printf("Failed deleting filter for FD %i: %s", fd, fr_syserror(errno));
				return -1;
			}
			filter = 0;
		}

		/*
		 *	I/O handler may delete an event, then
		 *	re-add it.  To avoid deleting modified
		 *	events we unset the do_delete flag.
		 */
		ef->do_delete = false;
	}

	ef->ctx = ctx;

	if (read_fn) {
		ef->read = read_fn;
		filter |= EVFILT_READ;
	}

	if (write_fn) {
		ef->write = write_fn;
		filter |= EVFILT_WRITE;
	}
	ef->error = error;

	EV_SET(&evset, fd, filter, EV_ADD | EV_ENABLE, 0, 0, ef);
	if (kevent(el->kq, &evset, 1, NULL, 0, NULL) < 0) {
		fr_strerror_printf("Failed adding filter for FD %i: %s", fd, fr_syserror(errno));
		if (!pre_existing) talloc_free(ef);
		return -1;
	}
	ef->is_registered = true;

	return 0;
}


/** Delete a timer event from the event list
 *
 * @param[in] el	to delete event from.
 * @param[in] parent	of the event being deleted.
 */
int fr_event_timer_delete(fr_event_list_t *el, fr_event_timer_t **parent)
{
	int ret;

	fr_event_timer_t *ev;

	if (!el) {
		fr_strerror_printf("Invalid argument: NULL event list");
		return -1;
	}

	if (!parent) {
		fr_strerror_printf("Invalid arguments: NULL event pointer");
		return -1;
	}

	if (!*parent) {
		fr_strerror_printf("Invalid arguments: NULL event");
		return -1;
	}

	/*
	 *  Validate the event_t struct to detect memory issues early.
	 */
	ev = talloc_get_type_abort(*parent, fr_event_timer_t);
	if (ev->parent) {
		(void)fr_cond_assert(*(ev->parent) == ev);
		*ev->parent = NULL;
	}
	*parent = NULL;

	ret = fr_heap_extract(el->times, ev);

	/*
	 *	Events MUST be in the heap
	 */
	if (!fr_cond_assert(ret == 1)) {
		fr_strerror_printf("Event not found in heap");
		talloc_free(ev);
		return -1;
	}
	talloc_free(ev);

	return ret;
}

/** Insert a timer event into an event list
 *
 * @param[in] el	to insert event into.
 * @param[in] callback	function to execute if the event fires.
 * @param[in] ctx	for callback function.
 * @param[in] when	we should run the event.
 * @param[in] parent	If not NULL modify this event instead of creating a new one.  This is a parent
 *			in a temporal sense, not in a memory structure or dependency sense.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_event_timer_insert(fr_event_list_t *el, fr_event_callback_t callback, void const *ctx,
			  struct timeval *when, fr_event_timer_t **parent)
{
	fr_event_timer_t *ev;

	if (!el) {
		fr_strerror_printf("Invalid arguments: NULL event list");
		return -1;
	}

	if (!callback) {
		fr_strerror_printf("Invalid arguments: NULL callback");
		return -1;
	}

	if (!when || (when->tv_usec >= USEC)) {
		fr_strerror_printf("Invalid arguments: time");
		return -1;
	}

	if (!parent) {
		fr_strerror_printf("Invalid arguments: NULL parent");
		return -1;
	}

	if (el->exit) {
		fr_strerror_printf("Event loop exiting");
		return -1;
	}

	/*
	 *	If there is an event, re-use it instead of freeing it
	 *	and allocating a new one.
	 */
	if (*parent) {
		int ret;

		ev = talloc_get_type_abort(*parent, fr_event_timer_t);

		ret = fr_heap_extract(el->times, ev);
		if (!fr_cond_assert(ret == 1)) return -1;	/* events MUST be in the heap */

		memset(ev, 0, sizeof(*ev));
	} else {
		ev = talloc_zero(el, fr_event_timer_t);
		if (!ev) return -1;
	}

	ev->callback = callback;
	ev->ctx = ctx;
	ev->when = *when;
	ev->parent = parent;

	if (!fr_heap_insert(el->times, ev)) {
		fr_strerror_printf("Failed inserting event into heap");
		talloc_free(ev);
		return -1;
	}

	*parent = ev;

	return 0;
}


/** Add a user callback to the event list.
 *
 * @param[in] el	containing the timer events.
 * @param[in] callback	the callback for EVFILT_USER
 * @param[in] uctx	user context for the callback
 * @return
 *	- 0 on error
 *	- uintptr_t ident for EVFILT_USER signaling
 */
uintptr_t fr_event_user_insert(fr_event_list_t *el, fr_event_user_handler_t callback, void *uctx)
{
	fr_event_user_t *user;

	user = talloc(el, fr_event_user_t);
	user->callback = callback;
	user->ctx = uctx;
	user->ident = (uintptr_t) user;

	fr_dlist_insert_tail(&el->user_callbacks, &user->entry);

	return user->ident;;
}


/** Delete a user callback to the event list.
 *
 * @param[in] el	containing the timer events.
 * @param[in] callback	the callback for EVFILT_USER
 * @param[in] uctx	user context for the callback
 * @return
 *	- < 0 on error
 *	- 0 on success
 */
int fr_event_user_delete(fr_event_list_t *el, fr_event_user_handler_t callback, void *uctx)
{
	fr_dlist_t *entry, *next;

	for (entry = FR_DLIST_FIRST(el->user_callbacks);
	     entry != NULL;
	     entry = next) {
		fr_event_user_t *user;

		next = FR_DLIST_NEXT(el->user_callbacks, entry);

		user = fr_ptr_to_type(fr_event_user_t, entry, entry);
		if ((user->callback == callback) &&
		    (user->ctx == uctx)) {
			fr_dlist_remove(entry);
			talloc_free(user);
			return 0;
		}
	}

	return -1;
}


/** Add a pre-event callback to the event list.
 *
 *  Events are serviced in insert order.  i.e. insert A, B, we then
 *  have A running before B.
 *
 * @param[in] el	containing the timer events.
 * @param[in] callback	the pre-processing callback;
 * @param[in] uctx	user context for the callback
 * @return
 *	- < 0 on error
 *	- 0 on success
 */
int fr_event_pre_insert(fr_event_list_t *el, fr_event_status_t callback, void *uctx)
{
	fr_event_pre_t *pre;

	pre = talloc(el, fr_event_pre_t);
	pre->callback = callback;
	pre->ctx = uctx;

	fr_dlist_insert_tail(&el->pre_callbacks, &pre->entry);

	return 0;
}


/** Delete a pre-event callback from the event list.
 *
 * @param[in] el	containing the timer events.
 * @param[in] callback	the pre-processing callback
 * @param[in] uctx	user context for the callback
 * @return
 *	- < 0 on error
 *	- 0 on success
 */
int fr_event_pre_delete(fr_event_list_t *el, fr_event_status_t callback, void *uctx)
{
	fr_dlist_t *entry, *next;

	for (entry = FR_DLIST_FIRST(el->pre_callbacks);
	     entry != NULL;
	     entry = next) {
		fr_event_pre_t *pre;

		next = FR_DLIST_NEXT(el->pre_callbacks, entry);

		pre = fr_ptr_to_type(fr_event_pre_t, entry, entry);
		if ((pre->callback == callback) &&
		    (pre->ctx == uctx)) {
			fr_dlist_remove(entry);
			talloc_free(pre);
			return 0;
		}
	}

	return -1;
}


/** Add a post-event callback to the event list.
 *
 *  Events are serviced in insert order.  i.e. insert A, B, we then
 *  have A running before B.
 *
 * @param[in] el	containing the timer events.
 * @param[in] callback	the post-processing callback;
 * @param[in] uctx	user context for the callback
 * @return
 *	- < 0 on error
 *	- 0 on success
 */
int fr_event_post_insert(fr_event_list_t *el, fr_event_callback_t callback, void *uctx)
{
	fr_event_post_t *post;

	post = talloc(el, fr_event_post_t);
	post->callback = callback;
	post->ctx = uctx;

	fr_dlist_insert_tail(&el->post_callbacks, &post->entry);

	return 0;
}


/** Delete a post-event callback from the event list.
 *
 * @param[in] el	containing the timer events.
 * @param[in] callback	the post-processing callback
 * @param[in] uctx	user context for the callback
 * @return
 *	- < 0 on error
 *	- 0 on success
 */
int fr_event_post_delete(fr_event_list_t *el, fr_event_callback_t callback, void *uctx)
{
	fr_dlist_t *entry, *next;

	for (entry = FR_DLIST_FIRST(el->post_callbacks);
	     entry != NULL;
	     entry = next) {
		fr_event_post_t *post;

		next = FR_DLIST_NEXT(el->post_callbacks, entry);

		post = fr_ptr_to_type(fr_event_post_t, entry, entry);
		if ((post->callback == callback) &&
		    (post->ctx == uctx)) {
			fr_dlist_remove(entry);
			talloc_free(post);
			return 0;
		}
	}

	return -1;
}


/** Run a single scheduled timer event
 *
 * @param[in] el	containing the timer events.
 * @param[in] when	Process events scheduled to run before or at this time.
 * @return
 *	- 0 no timer events fired.
 *	- 1 a timer event fired.
 */
int fr_event_timer_run(fr_event_list_t *el, struct timeval *when)
{
	fr_event_callback_t callback;
	void *ctx;
	fr_event_timer_t *ev;

	if (!el) return 0;

	if (fr_heap_num_elements(el->times) == 0) {
		when->tv_sec = 0;
		when->tv_usec = 0;
		return 0;
	}

	ev = fr_heap_peek(el->times);
	if (!ev) {
		when->tv_sec = 0;
		when->tv_usec = 0;
		return 0;
	}

	/*
	 *	See if it's time to do this one.
	 */
	if ((ev->when.tv_sec > when->tv_sec) ||
	    ((ev->when.tv_sec == when->tv_sec) &&
	     (ev->when.tv_usec > when->tv_usec))) {
		*when = ev->when;
		return 0;
	}

	callback = ev->callback;
	memcpy(&ctx, &ev->ctx, sizeof(ctx));

	/*
	 *	Delete the event before calling it.
	 */
	fr_event_timer_delete(el, ev->parent);

	callback(el, when, ctx);

	return 1;
}

/** Gather outstanding timer and file descriptor events
 *
 * @param[in] el	to process events for.
 * @param[in] wait	if true, block on the kevent() call until a timer or file descriptor event occurs.
 * @return
 *	- <0 error, or the event loop is exiting
 *	- the number of outstanding events.
 */
int fr_event_corral(fr_event_list_t *el, bool wait)
{
	struct timeval when, *wake;
	struct timespec ts_when, *ts_wake;
	fr_dlist_t *entry;

	if (el->exit) {
		fr_strerror_printf("Event loop exiting");
		return -1;
	}

	/*
	 *	Find the first event.  If there's none, we wait
	 *	on the socket forever.
	 */
	when.tv_sec = 0;
	when.tv_usec = 0;
	wake = &when;

	if (wait) {
		if (fr_heap_num_elements(el->times) > 0) {
			fr_event_timer_t *ev;

			ev = fr_heap_peek(el->times);
			if (!fr_cond_assert(ev)) return -1;

			gettimeofday(&el->now, NULL);

			/*
			 *	Next event is in the future, get the time
			 *	between now and that event.
			 */
			if (fr_timeval_cmp(&ev->when, &el->now) > 0) fr_timeval_subtract(&when, &ev->when, &el->now);
		} else {
			wake = NULL;
		}
	}

	/*
	 *	Run the status callbacks.  It may tell us that the
	 *	application has more work to do, in which case we
	 *	re-set the timeout to be instant.
	 */
	for (entry = FR_DLIST_FIRST(el->pre_callbacks);
	     entry != NULL;
	     entry = FR_DLIST_NEXT(el->pre_callbacks, entry)) {
		fr_event_pre_t *pre;

		when = el->now;

		pre = fr_ptr_to_type(fr_event_pre_t, entry, entry);
		if (pre->callback(pre->ctx, wake) > 0) {
			wake = &when;
			when.tv_sec = 0;
			when.tv_usec = 0;
		}
	}

	if (wake) {
		ts_wake = &ts_when;
		ts_when.tv_sec = when.tv_sec;
		ts_when.tv_nsec = when.tv_usec * 1000;
	} else {
		ts_wake = NULL;
	}

	/*
	 *	Populate el->events with the list of I/O events
	 *	that occurred since this function was last called
	 *	or wait for the next timer event.
	 */
	el->num_fd_events = kevent(el->kq, NULL, 0, el->events, FR_EV_BATCH_FDS, ts_wake);

	/*
	 *	Interrupt is different from timeout / FD events.
	 */
	if ((el->num_fd_events < 0) && (errno == EINTR)) el->num_fd_events = 0;

	return el->num_fd_events;
}

/** Service any outstanding timer or file descriptor events
 *
 * @param[in] el containing events to service.
 */
void fr_event_service(fr_event_list_t *el)
{
	int i;
	fr_dlist_t *entry;
	struct timeval when;

	if (el->exit) return;

	/*
	 *	Run all of the file descriptor events.
	 */
	for (i = 0; i < el->num_fd_events; i++) {
		fr_event_fd_t *ev;
		int flags = el->events[i].flags;

		/*
		 *	Process any user events
		 */
		if (el->events[i].filter == EVFILT_USER) {
			fr_event_user_t *user;

			/*
			 *	This is just a "wakeup" event, which
			 *	is always ignored.
			 */
			if (el->events[i].ident == 0) continue;

			user = (fr_event_user_t *) el->events[i].ident;

			(void) talloc_get_type_abort(user, fr_event_user_t);
			rad_assert(user->ident == el->events[i].ident);

			user->callback(el->kq, &el->events[i], user->ctx);
			continue;
		}

		ev = talloc_get_type_abort(el->events[i].udata, fr_event_fd_t);

		if (!fr_cond_assert(ev->is_registered)) continue;

                if (flags & EV_ERROR) {
                ev_error:
                        /*
                         *      Call the error handler which should
                         *      tear down the connection.
                         */
                        if (ev->error) {
                                ev->error(el, ev->fd, flags, ev->ctx);
                                continue;
                        }
                        fr_event_fd_delete(el, ev->fd);
                }

                /*
                 *      EOF can indicate we've actually reached
                 *      the end of a file, but for sockets it usually
                 *      indicates the other end of the connection
                 *      has gone away.
                 */
                if (flags & EV_EOF) {
			/*
			 *	This is fine, the callback will get notified
			 *	via the flags field.
			 */
			if (ev->is_file) goto service;
#if defined(__linux__) && defined(SO_GET_FILTER)
			/*
			 *      There seems to be an issue with the
			 *      ioctl(...SIOCNQ...) call libkqueue
			 *      uses to determine the number of bytes
			 *	readable.  When ioctl returns, the number
			 *	of bytes available is set to zero, which
			 *	libkqueue interprets as EOF.
			 *
			 *      As a workaround, if we're not reading
			 *	a file, and are operating on a raw socket
			 *	with a packet filter attached, we ignore
			 *	the EOF flag and continue.
			 */
			if ((ev->sock_type == SOCK_RAW) && ev->pf_attached) goto service;
#endif
			goto ev_error;
                }

service:
		ev->in_handler = true;
		if (ev->read && (el->events[i].filter == EVFILT_READ)) {
			ev->read(el, ev->fd, flags, ev->ctx);
		}
		if (ev->write && (el->events[i].filter == EVFILT_WRITE) && !ev->do_delete) {
			ev->write(el, ev->fd, flags, ev->ctx);
		}
		ev->in_handler = false;

		/*
		 *	Process any deferred deletes performed
		 *	by the I/O handler.
		 */
		if (ev->do_delete) fr_event_fd_delete(el, ev->fd);
	}

	gettimeofday(&el->now, NULL);

	/*
	 *	Run all of the timer events.
	 */
	if (fr_heap_num_elements(el->times) > 0) {
		do {
			when = el->now;
		} while (fr_event_timer_run(el, &when) == 1);
	}

	/*
	 *	Run all of the post-processing events.
	 */
	for (entry = FR_DLIST_FIRST(el->post_callbacks);
	     entry != NULL;
	     entry = FR_DLIST_NEXT(el->post_callbacks, entry)) {
		fr_event_post_t *post;

		when = el->now;

		post = fr_ptr_to_type(fr_event_post_t, entry, entry);
		post->callback(el, &when, post->ctx);
	}
}

/** Signal an event loop exit with the specified code
 *
 * The event loop will complete its current iteration, and then exit with the specified code.
 *
 * @param[in] el	to signal to exit.
 * @param[in] code	for #fr_event_loop to return.
 */
void fr_event_loop_exit(fr_event_list_t *el, int code)
{
	struct kevent kev;

	if (!el) return;

	el->exit = code;

	/*
	 *	Signal the control plane to exit.
	 */
	EV_SET(&kev, 0, EVFILT_USER, 0, NOTE_TRIGGER | NOTE_FFNOP, 0, NULL);
	(void) kevent(el->kq, &kev, 1, NULL, 0, NULL);
}

/** Check to see whether the event loop is in the process of exiting
 *
 * @param[in] el	to check.
 */
bool fr_event_loop_exiting(fr_event_list_t *el)
{
	return (el->exit != 0);
}

/** Run an event loop
 *
 * @note Will not return until #fr_event_loop_exit is called.
 *
 * @param[in] el to start processing.
 */
int fr_event_loop(fr_event_list_t *el)
{
	el->exit = 0;

	el->dispatch = true;
	while (!el->exit) {
		if (fr_event_corral(el, true) < 0) break;

		fr_event_service(el);
	}
	el->dispatch = false;

	return el->exit;
}

/** Cleanup an event list
 *
 * Frees/destroys any resources associated with an event list
 *
 * @param[in] el to free resources for.
 */
static int _event_list_free(fr_event_list_t *el)
{
	fr_event_timer_t *ev;

	while ((ev = fr_heap_peek(el->times)) != NULL) {
		fr_event_timer_delete(el, &ev);
	}

	talloc_free(el->times);

	close(el->kq);

	return 0;
}

/** Initialise a new event list
 *
 * @param[in] ctx	to allocate memory in.
 * @param[in] status	callback, called on each iteration of the event list.
 * @param[in] status_ctx context for the status callback
 * @return
 *	- A pointer to a new event list on success (free with talloc_free).
 *	- NULL on error.
 */
fr_event_list_t *fr_event_list_alloc(TALLOC_CTX *ctx, fr_event_status_t status, void *status_ctx)
{
	fr_event_list_t *el;
	struct kevent kev;

	el = talloc_zero(ctx, fr_event_list_t);
	if (!fr_cond_assert(el)) {
		return NULL;
	}
	talloc_set_destructor(el, _event_list_free);

	el->times = fr_heap_create(fr_event_timer_cmp, offsetof(fr_event_timer_t, heap));
	if (!el->times) {
		talloc_free(el);
		return NULL;
	}
	el->fds = rbtree_create(el, fr_event_fd_cmp, NULL, 0);

	el->kq = kqueue();
	if (el->kq < 0) {
		talloc_free(el);
		return NULL;
	}

	FR_DLIST_INIT(el->pre_callbacks);
	FR_DLIST_INIT(el->post_callbacks);
	FR_DLIST_INIT(el->user_callbacks);
	
	if (status) (void) fr_event_pre_insert(el, status, status_ctx);

	/*
	 *	Set our "exit" callback as ident 0.
	 */
	EV_SET(&kev, 0, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_FFNOP, 0, NULL);
	if (kevent(el->kq, &kev, 1, NULL, 0, NULL) < 0) {
		talloc_free(el);
		return NULL;
	}

	return el;
}

#ifdef TESTING

/*
 *  cc -g -I .. -c rbtree.c -o rbtree.o && cc -g -I .. -c isaac.c -o isaac.o && cc -DTESTING -I .. -c event.c  -o event_mine.o && cc event_mine.o rbtree.o isaac.o -o event
 *
 *  ./event
 *
 *  And hit CTRL-S to stop the output, CTRL-Q to continue.
 *  It normally alternates printing the time and sleeping,
 *  but when you hit CTRL-S/CTRL-Q, you should see a number
 *  of events run right after each other.
 *
 *  OR
 *
 *   valgrind --tool=memcheck --leak-check=full --show-reachable=yes ./event
 */

static void print_time(void *ctx)
{
	struct timeval *when = ctx;

	printf("%d.%06d\n", when->tv_sec, when->tv_usec);
	fflush(stdout);
}

static fr_randctx rand_pool;

static uint32_t event_rand(void)
{
	uint32_t num;

	num = rand_pool.randrsl[rand_pool.randcnt++];
	if (rand_pool.randcnt == 256) {
		fr_isaac(&rand_pool);
		rand_pool.randcnt = 0;
	}

	return num;
}


#define MAX 100
int main(int argc, char **argv)
{
	int i, rcode;
	struct timeval array[MAX];
	struct timeval now, when;
	fr_event_list_t *el;

	el = fr_event_list_alloc(NULL, NULL);
	if (!el) exit(1);

	memset(&rand_pool, 0, sizeof(rand_pool));
	rand_pool.randrsl[1] = time(NULL);

	fr_randinit(&rand_pool, 1);
	rand_pool.randcnt = 0;

	gettimeofday(&array[0], NULL);
	for (i = 1; i < MAX; i++) {
		array[i] = array[i - 1];

		array[i].tv_usec += event_rand() & 0xffff;
		if (array[i].tv_usec > 1000000) {
			array[i].tv_usec -= 1000000;
			array[i].tv_sec++;
		}
		fr_event_timer_insert(el, print_time, &array[i], &array[i]);
	}

	while (fr_event_list_num_elements(el)) {
		gettimeofday(&now, NULL);
		when = now;
		if (!fr_event_timer_run(el, &when)) {
			int delay = (when.tv_sec - now.tv_sec) * 1000000;
			delay += when.tv_usec;
			delay -= now.tv_usec;

			printf("\tsleep %d\n", delay);
			fflush(stdout);
			usleep(delay);
		}
	}

	talloc_free(el);

	return 0;
}
#endif
