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
struct fr_event_timer {
	struct timeval		when;			//!< When this timer should fire.
	fr_event_callback_t	callback;		//!< Callback to execute when the timer fires.
	void const		*uctx;			//!< Context pointer to pass to the callback.
	TALLOC_CTX		*linked_ctx;		//!< talloc ctx this event was bound to.

	fr_event_timer_t const	**parent;		//!< Previous timer.
	int			heap;			//!< Where to store opaque heap data.
};

/** A file descriptor event
 *
 */
struct fr_event_fd {
	int			fd;			//!< File descriptor we're listening for events on.

	int                     sock_type;              //!< The type of socket SOCK_STREAM, SOCK_RAW etc...
	bool                    is_file;                //!< Is a file, not a socket.

#ifdef SO_GET_FILTER
	bool                    pf_attached;            //!< Has an attached packet filter (PF) program.
#endif

	fr_event_fd_io_t	read;			//!< Callback for when data is available.
	fr_event_fd_io_t	write;			//!< Callback for when we can write data.
	fr_event_fd_error_t	error;			//!< Callback for when an error occurs on the FD.

	bool			is_registered;		//!< Whether this fr_event_fd_t's FD has been registered with
							///< kevent.  Mostly for debugging.

	bool			in_handler;		//!< Event is currently being serviced.  Deletes should be
							///< deferred until after the handlers complete.

	bool			deferred_free;		//!< Deferred deletion flag.  Delete this event *after*
							///< the handlers complete.

	void			*uctx;			//!< Context pointer to pass to each file descriptor callback.
	TALLOC_CTX		*linked_ctx;		//!< talloc ctx this event was bound to.

	fr_event_fd_t		*next;			//!< item in a list of fr_event_fd.
};


struct fr_event_pid {
	pid_t			pid;			//!< child to wait for
	fr_event_list_t		*el;			//!< the event list which this thing is in

	fr_event_pid_callback_t	callback;		//!< callback to run when the child exits
	void			*uctx;			//!< Context pointer to pass to each file descriptor callback.
};

/** Callbacks to perform when the event handler is about to check the events
 *
 */
typedef struct {
	fr_dlist_t		entry;			//!< Linked list of callback.
	fr_event_status_t	callback;		//!< The callback to call.
	void			*uctx;			//!< Context for the callback.
} fr_event_pre_t;

/** Callbacks to perform after all timers and FDs have been checked
 *
 */
typedef struct {
	fr_dlist_t		entry;			//!< Linked list of callback.
	fr_event_callback_t	callback;		//!< The callback to call.
	void			*uctx;			//!< Context for the callback.
} fr_event_post_t;

/** Callbacks for kevent() user events
 *
 */
typedef struct {
	fr_dlist_t		entry;			//!< Linked list of callback.
	uintptr_t		ident;			//!< The identifier of this event.
	fr_event_user_handler_t callback;		//!< The callback to call.
	void			*uctx;			//!< Context for the callback.
} fr_event_user_t;

/** Stores all information relating to an event list
 *
 */
struct fr_event_list {
	fr_heap_t		*times;			//!< of timer events to be executed.
	rbtree_t		*fds;			//!< Tree used to track FDs with filters in kqueue.

	int			exit;			//!< If non-zero, the event loop will exit after its current
							///< iteration, returning this value.

	struct timeval  	now;			//!< The last time the event list was serviced.
	bool			dispatch;		//!< Whether the event list is currently dispatching events.

	int			num_fds;		//!< Number of FDs listened to by this event list.
	int			num_fd_events;		//!< Number of events in this event list.

	int			kq;			//!< instance associated with this event list.

	fr_dlist_t		pre_callbacks;		//!< callbacks when we may be idle...
	fr_dlist_t		user_callbacks;		//!< EVFILT_USER callbacks
	fr_dlist_t		post_callbacks;		//!< post-processing callbacks

	struct kevent		events[FR_EV_BATCH_FDS]; /* so it doesn't go on the stack every time */

	fr_event_fd_t		*fd_to_free;		//!< File descriptor events pending deletion.
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
	fr_event_timer_t const	*ev_a = a, *ev_b = b;

	return fr_timeval_cmp(&ev_a->when, &ev_b->when);
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
	fr_event_fd_t const *ev_a = a, *ev_b = b;

	return (ev_a->fd < ev_b->fd) - (ev_a->fd > ev_b->fd);
}

/** Return the number of file descriptors is_registered with this event loop
 *
 */
int fr_event_list_num_fds(fr_event_list_t *el)
{
	if (unlikely(!el)) return -1;

	return el->num_fds;
}

/** Return the number of timer events currently scheduled
 *
 * @param[in] el to return timer events for.
 * @return number of timer events.
 */
int fr_event_list_num_elements(fr_event_list_t *el)
{
	if (unlikely(!el)) return -1;

	return fr_heap_num_elements(el->times);
}

/** Return the kq associated with an event list.
 *
 * @param[in] el to return timer events for.
 * @return kq
 */
int fr_event_list_kq(fr_event_list_t *el)
{
	if (unlikely(!el)) return -1;

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

/** Remove a file descriptor from the event loop and rbtree but don't free it
 *
 * This is used as the talloc destructor for events, and also called by
 * #fr_event_fd_delete to remove the event in case of deferred deletes.
 *
 * @param[in] ef	to remove.
 * @return
 *	- 0 on success.
 *	- -1 on error;
 */
static int fr_event_fd_delete_internal(fr_event_fd_t *ef)
{
	struct kevent	evset[2];
	int		count = 0;
	fr_event_list_t	*el;

	if (!ef->is_registered) return 0;

	el = talloc_parent(ef);

	if (ef->read) EV_SET(&evset[count++], ef->fd, EVFILT_READ, EV_DELETE, 0, 0, 0);
	if (ef->write) EV_SET(&evset[count++], ef->fd, EVFILT_WRITE, EV_DELETE, 0, 0, 0);

	if (unlikely(kevent(el->kq, evset, count, NULL, 0, NULL) < 0)) {
		fr_strerror_printf("Failed removing filters for FD %i: %s", ef->fd, fr_syserror(errno));
		return -1;
	}

	rbtree_deletebydata(el->fds, ef);
	ef->is_registered = false;

	el->num_fds--;

	return 0;
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
	fr_event_fd_t	*ef, find;

	memset(&find, 0, sizeof(find));
	find.fd = fd;

	ef = rbtree_finddata(el->fds, &find);
	if (unlikely(!ef)) {
		fr_strerror_printf("No events are registered for fd %i", fd);
		return -1;
	}

	/*
	 *	Defer the free, so we don't free
	 *	an ef structure that might still be
	 *	in use within fr_event_service.
	 */
	if (ef->in_handler) {
		if (unlikely(fr_event_fd_delete_internal(ef)) < 0) return -1;	/* Removes from kevent/rbtree, does not free */
		ef->deferred_free = true;
		ef->next = el->fd_to_free;
		el->fd_to_free = ef;
		return 0;
	}

	/*
	 *	Destructor may prevent ef from being
	 *	freed if kevent de-registration fails.
	 */
	if (unlikely(talloc_free(ef) < 0)) return -1;

	return 0;
}

/** Associate a callback with an file descriptor
 *
 * @param[in] ctx	to bind lifetime of the event to.
 * @param[in] el	to insert fd callback into.
 * @param[in] fd	to read from.
 * @param[in] read_fn	function to call when fd is readable.
 * @param[in] write_fn	function to call when fd is writable.
 * @param[in] error	function to call when an error occurs on the fd.
 * @param[in] uctx	to pass to handler.
 * @return
 *	- 0 on succes.
 *	- -1 on failure.
 */
int fr_event_fd_insert(TALLOC_CTX *ctx, fr_event_list_t *el, int fd,
		       fr_event_fd_io_t read_fn,
		       fr_event_fd_io_t write_fn,
		       fr_event_fd_error_t error,
		       void *uctx)
{
	int		count = 0;
	struct kevent	evset[2];
	fr_event_fd_t	*ef, find;

	if (unlikely(!el)) {
		fr_strerror_printf("Invalid argument: NULL event list");
		return -1;
	}

	if (unlikely(!read_fn && !write_fn)) {
		fr_strerror_printf("Invalid arguments: NULL read and write callbacks");
		return -1;
	}

	if (unlikely(fd < 0)) {
		fr_strerror_printf("Invalid arguments: Bad FD %i", fd);
		return -1;
	}

	if (unlikely(el->exit)) {
		fr_strerror_printf("Event loop exiting");
		return -1;
	}

	memset(&find, 0, sizeof(find));

	find.fd = fd;
	ef = rbtree_finddata(el->fds, &find);

	/*
	 *	Need to free the event to change the
	 *	talloc link.
	 *
	 *	This is generally bad.  If you hit this
	 *	code path you probably screwed up
	 *	somewhere.
	 */
	if (unlikely(ef && (ef->linked_ctx != ctx))) {
		if (fr_event_fd_delete(el, fd) < 0) return -1;
		ef = NULL;
	}

	/*
	 *	No pre-existing event.  Allocate an entry
	 *	for insertion into the rbtree, and call
	 *	kevent to register read/write callbacks.
	 */
	if (!ef) {
		int             sock_type;
		socklen_t       opt_len = sizeof(sock_type);

		ef = talloc_zero(el, fr_event_fd_t);
		if (unlikely(!ef)) {
			fr_strerror_printf("Out of memory");
			return -1;
		}
		talloc_set_destructor(ef, fr_event_fd_delete_internal);

		el->num_fds++;

		ef->fd = fd;

                /*
                 *      Retrieve file descriptor metadata
                 */
                if (unlikely(getsockopt(fd, SOL_SOCKET, SO_TYPE, &sock_type, &opt_len) < 0)) {
                        if (errno != ENOTSOCK) {
                                fr_strerror_printf("Failed retrieving socket type: %s", fr_syserror(errno));
                                return -1;
                        }
                        ef->is_file = true;
                }
#ifdef SO_GET_FILTER
                else {
                        opt_len = 0;
                        if (unlikely(getsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, NULL, &opt_len) < 0)) {
                                fr_strerror_printf("Failed determining PF status: %s", fr_syserror(errno));
                                return -1;
                        }
                        if (opt_len) ef->pf_attached = true;
                        ef->sock_type = sock_type;
                }
#endif

		if (read_fn) EV_SET(&evset[count++], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, ef);
		if (write_fn) EV_SET(&evset[count++], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, ef);

		if (unlikely(kevent(el->kq, evset, count, NULL, 0, NULL) < 0)) {
			fr_strerror_printf("Failed adding filter for FD %i: %s", fd, fr_syserror(errno));
			talloc_free(ef);
			return -1;
		}

		rbtree_insert(el->fds, ef);

		ef->uctx = uctx;
		ef->read = read_fn;
		ef->write = write_fn;
		ef->error = error;
		ef->is_registered = true;
		ef->linked_ctx = ctx;

		return 0;
	}

	/*
	 *	Calculate the diff between the filters that
	 *	should be registered and the filters we need.
	 */
	if (ef->read) {
		if (!read_fn) EV_SET(&evset[count++], ef->fd, EVFILT_READ, EV_DELETE, 0, 0, 0);
	} else {
		if (read_fn) EV_SET(&evset[count++], ef->fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, ef);
	}
	if (ef->write) {
		if (!write_fn) EV_SET(&evset[count++], ef->fd, EVFILT_WRITE, EV_DELETE, 0, 0, 0);
	} else {
		if (write_fn) EV_SET(&evset[count++], ef->fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, ef);
	}

	if (count) {
		if (unlikely(kevent(el->kq, evset, count, NULL, 0, NULL) < 0)) {
			fr_strerror_printf("Failed modifying filters for FD %i: %s", fd, fr_syserror(errno));
			return -1;
		}
	}

	ef->deferred_free = false;
	ef->uctx = uctx;
	ef->read = read_fn;
	ef->write = write_fn;
	ef->error = error;

	return 0;
}

/** Delete a timer event from the event list
 *
 * @param[in] el	to delete event from.
 * @param[in] ev_p	of the event being deleted.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_event_timer_delete(fr_event_list_t *el, fr_event_timer_t const **ev_p)
{
	fr_event_timer_t *ev;
	int ret;

	if (unlikely(!*ev_p)) return 0;
	if (!fr_cond_assert(talloc_parent(*ev_p) == el)) return -1;

	memcpy(&ev, ev_p, sizeof(ev));
	ret = talloc_free(ev);
	if (ret == 0) *ev_p = NULL;

	return ret;
}

/** Remove an event from the event loop
 *
 * @param[in] ev	to free.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _event_timer_free(fr_event_timer_t *ev)
{
	fr_event_list_t	*el = talloc_parent(ev);
	int		ret;

	ret = fr_heap_extract(el->times, ev);

	/*
	 *	Events MUST be in the heap
	 */
	if (!fr_cond_assert(ret == 1)) {
		fr_strerror_printf("Event not found in heap");
		return -1;
	}

	return 0;
}

/** Insert a timer event into an event list
 *
 * @note The talloc parent of the memory returned in ev_p must not be changed.
 *	 If the lifetime of the event needs to be bound to another context
 *	 this function should be called with the existing event pointed to by
 *	 ev_p.
 *
 * @param[in] ctx		to bind lifetime of the event to.
 * @param[in] el		to insert event into.
 * @param[in,out] ev_p		If not NULL modify this event instead of creating a new one.  This is a parent
 *				in a temporal sense, not in a memory structure or dependency sense.
 * @param[in] when		we should run the event.
 * @param[in] callback		function to execute if the event fires.
 * @param[in] uctx		user data to pass to the event.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_event_timer_insert(TALLOC_CTX *ctx, fr_event_list_t *el, fr_event_timer_t const **ev_p,
			  struct timeval *when, fr_event_callback_t callback, void const *uctx)
{
	fr_event_timer_t *ev;

	if (unlikely(!el)) {
		fr_strerror_printf("Invalid arguments: NULL event list");
		return -1;
	}

	if (unlikely(!callback)) {
		fr_strerror_printf("Invalid arguments: NULL callback");
		return -1;
	}

	if (unlikely(!when || (when->tv_usec >= USEC))) {
		fr_strerror_printf("Invalid arguments: time");
		return -1;
	}

	if (unlikely(!ev_p)) {
		fr_strerror_printf("Invalid arguments: NULL ev_p");
		return -1;
	}

	if (unlikely(el->exit)) {
		fr_strerror_printf("Event loop exiting");
		return -1;
	}

	/*
	 *	If there is an event, re-use it instead of freeing it
	 *	and allocating a new one.  This is to reduce memory
	 *	churn for repeat events.
	 */
	if (!*ev_p) {
	new_event:
		ev = talloc_zero(el, fr_event_timer_t);
		if (unlikely(!ev)) return -1;

		/*
		 *	Bind the lifetime of the event to the specified
		 *	talloc ctx.  If the talloc ctx is freed, the
		 *	event will also be freed.
		 */
		if (ctx) fr_talloc_link_ctx(ctx, ev);

		talloc_set_destructor(ev, _event_timer_free);
	} else {
		memcpy(&ev, ev_p, sizeof(ev));	/* Not const to us */

		/*
		 *	We can't disarm the linking context due to
		 *	limitations in talloc, so if the linking
		 *	context changes, we need to free the old
		 *	event, and allocate a new one.
		 *
		 *	Freeing the event also removes it from the heap.
		 */
		if (unlikely(ev->linked_ctx != ctx)) {
			talloc_free(ev);
			goto new_event;
		}

		/*
		 *	Event may have fired, in which case the
		 *	event will no longer be in the event loop.
		 */
		(void) fr_heap_extract(el->times, ev);
	}

	ev->when = *when;
	ev->callback = callback;
	ev->uctx = uctx;
	ev->linked_ctx = ctx;
	ev->parent = ev_p;

	if (unlikely(!fr_heap_insert(el->times, ev))) {
		fr_strerror_printf("Failed inserting event into heap");
		talloc_free(ev);
		return -1;
	}

	*ev_p = ev;

	return 0;
}


static int event_pid_free(fr_event_pid_t *ev)
{
	struct kevent evset;

	if (ev->pid == 0) return 0; /* already deleted from kevent */

	EV_SET(&evset, ev->pid, EVFILT_PROC, EV_DELETE, NOTE_EXIT, 0, ev);

	(void) kevent(ev->el->kq, &evset, 1, NULL, 0, NULL);

	return 0;
}

/** Insert a PID event into an event list
 *
 * @note The talloc parent of the memory returned in ev_p must not be changed.
 *	 If the lifetime of the event needs to be bound to another context
 *	 this function should be called with the existing event pointed to by
 *	 ev_p.
 *
 * @param[in] ctx		to bind lifetime of the event to.
 * @param[in] el		to insert event into.
 * @param[in,out] ev_p		If not NULL modify this event instead of creating a new one.  This is a parent
 *				in a temporal sense, not in a memory structure or dependency sense.
 * @param[in] pid		child PID to wait for
 * @param[in] wait_fn		function to execute if the event fires.
 * @param[in] uctx		user data to pass to the event.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_event_pid_wait(TALLOC_CTX *ctx, fr_event_list_t *el, fr_event_pid_t const **ev_p,
		      pid_t pid, fr_event_pid_callback_t wait_fn, void *uctx)
{
	fr_event_pid_t *ev;
	struct kevent evset;

	ev = talloc(ctx, fr_event_pid_t);
	ev->pid = pid;
	ev->callback = wait_fn;
	ev->uctx = uctx;

	EV_SET(&evset, pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, ev);

	if (unlikely(kevent(el->kq, &evset, 1, NULL, 0, NULL) < 0)) {
		fr_strerror_printf("Failed adding waiter for PID %ld", (long) pid);
		return -1;
	}
	talloc_set_destructor(ev, event_pid_free);

	*ev_p = ev;
	return 0;
}



/** Add a user callback to the event list.
 *
 * @param[in] el	Containing the timer events.
 * @param[in] callback	for EVFILT_USER.
 * @param[in] uctx	for the callback.
 * @return
 *	- 0 on error
 *	- uintptr_t ident for EVFILT_USER signaling
 */
uintptr_t fr_event_user_insert(fr_event_list_t *el, fr_event_user_handler_t callback, void *uctx)
{
	fr_event_user_t *user;

	user = talloc(el, fr_event_user_t);
	user->callback = callback;
	user->uctx = uctx;
	user->ident = (uintptr_t) user;

	fr_dlist_insert_tail(&el->user_callbacks, &user->entry);

	return user->ident;;
}

/** Delete a user callback to the event list.
 *
 * @param[in] el	Containing the timer events.
 * @param[in] callback	for EVFILT_USER.
 * @param[in] uctx	for the callback.
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
		    (user->uctx == uctx)) {
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
 * @param[in] el	Containing the timer events.
 * @param[in] callback	The pre-processing callback.
 * @param[in] uctx	for the callback.
 * @return
 *	- < 0 on error
 *	- 0 on success
 */
int fr_event_pre_insert(fr_event_list_t *el, fr_event_status_t callback, void *uctx)
{
	fr_event_pre_t *pre;

	pre = talloc(el, fr_event_pre_t);
	pre->callback = callback;
	pre->uctx = uctx;

	fr_dlist_insert_tail(&el->pre_callbacks, &pre->entry);

	return 0;
}

/** Delete a pre-event callback from the event list.
 *
 * @param[in] el	Containing the timer events.
 * @param[in] callback	The pre-processing callback.
 * @param[in] uctx	for the callback.
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
		    (pre->uctx == uctx)) {
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
 * @param[in] el	Containing the timer events.
 * @param[in] callback	The post-processing callback.
 * @param[in] uctx	for the callback.
 * @return
 *	- < 0 on error
 *	- 0 on success
 */
int fr_event_post_insert(fr_event_list_t *el, fr_event_callback_t callback, void *uctx)
{
	fr_event_post_t *post;

	post = talloc(el, fr_event_post_t);
	post->callback = callback;
	post->uctx = uctx;

	fr_dlist_insert_tail(&el->post_callbacks, &post->entry);

	return 0;
}

/** Delete a post-event callback from the event list.
 *
 * @param[in] el	Containing the timer events.
 * @param[in] callback	The post-processing callback.
 * @param[in] uctx	for the callback.
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
		    (post->uctx == uctx)) {
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
	fr_event_callback_t	callback;
	void			*uctx;
	fr_event_timer_t	*ev;

	if (unlikely(!el)) return 0;

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
	memcpy(&uctx, &ev->uctx, sizeof(uctx));

	/*
	 *	Delete the event before calling it.
	 */
	fr_event_timer_delete(el, ev->parent);

	callback(el, when, uctx);

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
	struct timeval		when, *wake;
	struct timespec		ts_when, *ts_wake;
	fr_dlist_t		*entry;
	int			num_fd_events, num_timer_events;

	el->num_fd_events = 0;
	num_timer_events = 0;

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
			if (!fr_cond_assert(ev)) {
				fr_strerror_printf("Timer heap says it is non-empty, but there are no entries in it");
				return -1;
			}

			gettimeofday(&el->now, NULL);

			/*
			 *	Next event is in the future, get the time
			 *	between now and that event.
			 */
			if (fr_timeval_cmp(&ev->when, &el->now) > 0) fr_timeval_subtract(&when, &ev->when, &el->now);

			wake = &when;
			num_timer_events = 1;
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

		pre = fr_ptr_to_type(fr_event_pre_t, entry, entry);
		if (pre->callback(pre->uctx, wake) > 0) {
			num_timer_events++;
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
	num_fd_events = kevent(el->kq, NULL, 0, el->events, FR_EV_BATCH_FDS, ts_wake);

	/*
	 *	Interrupt is different from timeout / FD events.
	 */
	if (unlikely(num_fd_events < 0)) {
		if (errno == EINTR) {
			return 0;
		} else {
			fr_strerror_printf("Failed calling kevent: %s", fr_syserror(errno));
			return -1;
		}
	}

	el->num_fd_events = num_fd_events;

	return num_fd_events + num_timer_events;
}

/** Service any outstanding timer or file descriptor events
 *
 * @param[in] el containing events to service.
 */
void fr_event_service(fr_event_list_t *el)
{
	int		i;
	fr_dlist_t	*entry;
	struct timeval	when;

	if (unlikely(el->exit)) return;

	/*
	 *	Run all of the file descriptor events.
	 */
	for (i = 0; i < el->num_fd_events; i++) {
		fr_event_fd_t	*ef;
		int		fd_errno = 0;
		int		flags = el->events[i].flags;

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

			user = (fr_event_user_t *)el->events[i].ident;

			(void) talloc_get_type_abort(user, fr_event_user_t);
			rad_assert(user->ident == el->events[i].ident);

			user->callback(el->kq, &el->events[i], user->uctx);
			continue;
		}

		if (el->events[i].filter == EVFILT_PROC) {
			pid_t pid;
			fr_event_pid_t *ev;

			ev = (fr_event_pid_t *) el->events[i].udata;
			(void) talloc_get_type_abort(ev, fr_event_pid_t);

			rad_assert(ev->pid == (pid_t) el->events[i].ident);
			rad_assert((el->events[i].fflags & NOTE_EXIT) != 0);

			pid = ev->pid;
			ev->pid = 0; /* so we won't hit kevent again when it's freed */
			ev->callback(el, pid, (int) el->events[i].data, ev->uctx);
			continue;
		}

		ef = talloc_get_type_abort(el->events[i].udata, fr_event_fd_t);

		if (!fr_cond_assert(ef->is_registered)) continue;
		if (ef->deferred_free) continue;			/* Stale, ignore it */

                if (unlikely(flags & EV_ERROR)) {
                	fd_errno = el->events[i].data;
                ev_error:
                        /*
                         *      Call the error handler
                         */
                        if (ef->error) ef->error(el, ef->fd, flags, fd_errno, ef->uctx);
                        fr_event_fd_delete(el, ef->fd);
                        continue;
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
			if (ef->is_file) goto service;
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
			if ((ef->sock_type == SOCK_RAW) && ef->pf_attached) goto service;
#endif
			fd_errno = el->events[i].fflags;

			goto ev_error;
                }

service:
		ef->in_handler = true;
		if (ef->read && (el->events[i].filter == EVFILT_READ)) {
			ef->read(el, ef->fd, flags, ef->uctx);
		}
		if (ef->write && (el->events[i].filter == EVFILT_WRITE) && !ef->deferred_free) {
			ef->write(el, ef->fd, flags, ef->uctx);
		}
		ef->in_handler = false;
	}

	/*
	 *	Process any deferred frees performed
	 *	by the I/O handlers.
	 *
	 *	The events are removed from the FD rbtree
	 *	and kevent immediately, but frees are
	 *	deferred to allow stale events to be
	 *	skipped sans SEGV.
	 */
	if (el->fd_to_free) {
		fr_event_fd_t *to_free, *next;

		for (to_free = el->fd_to_free; to_free; to_free = next) {
			next = to_free->next;
			talloc_free(to_free);
		}

		el->fd_to_free = NULL;	/* all gone */
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
		post->callback(el, &when, post->uctx);
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

	if (unlikely(!el)) return;

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
		if (unlikely(fr_event_corral(el, true)) < 0) break;
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
	fr_event_timer_t const *ev;

	talloc_free_children(el);

	while ((ev = fr_heap_peek(el->times)) != NULL) fr_event_timer_delete(el, &ev);

	talloc_free(el->times);

	close(el->kq);

	return 0;
}

/** Initialise a new event list
 *
 * @param[in] ctx		to allocate memory in.
 * @param[in] status		callback, called on each iteration of the event list.
 * @param[in] status_uctx	context for the status callback
 * @return
 *	- A pointer to a new event list on success (free with talloc_free).
 *	- NULL on error.
 */
fr_event_list_t *fr_event_list_alloc(TALLOC_CTX *ctx, fr_event_status_t status, void *status_uctx)
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

	if (status) (void) fr_event_pre_insert(el, status, status_uctx);

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
		fr_event_timer_insert(NULL, el, &array[i], print_time, &array[i]);
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
