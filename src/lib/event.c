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
 * @file lib/event.c
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

#define FR_EV_BATCH_FDS (256)

#undef USEC
#define USEC (1000000)

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

	fr_event_fd_handler_t	read;			//!< callback for when data is available.
	fr_event_fd_handler_t	write;			//!< callback for when we can write data.
	fr_event_fd_handler_t	error;			//!< callback for when an error occurs on the FD.

	void			*ctx;			//!< context pointer to pass to each file descriptor callback.
} fr_event_fd_t;

/** Stores all information relating to an event list
 *
 */
struct fr_event_list_t {
	fr_heap_t		*times;			//!< of events to be executed.
	rbtree_t		*fds;			//!< Tree used to track FDs with filters in kqueue.

	int			exit;

	void			*status_ctx;		//!< context for status function
	fr_event_status_t	status;			//!< Function to call on each iteration of the event loop.

	struct timeval  	now;			//!< The last time the event list was serviced.
	bool			dispatch;		//!< Whether the event list is currently dispatching events.

	int			num_fds;		//!< Number of FDs listened to by this event list.
	int			num_fd_events;		//!< Number of events in this event list

	int			kq;			//!< instance association with this event list.

	fr_event_user_handler_t user;			//!< callback for EVFILT_USER events
	void			*user_ctx;		//!< context pointer to pass to the user callback

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

/** Return the number of file descriptors registered with this event loop
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
		fr_strerror_printf("No events registered for fd %i", fd);
		return -1;
	}
	talloc_free(ef);

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

	rbtree_deletebydata(el->fds, ef);

	if (ef->read) filter |= EVFILT_READ;
	if (ef->write) filter |= EVFILT_WRITE;

	EV_SET(&evset, ef->fd, filter, EV_DELETE, 0, 0, NULL);
	(void) kevent(el->kq, &evset, 1, NULL, 0, NULL);

	el->num_fds++;

	return 0;
}

/** Associate a callback with an file descriptor
 *
 * @param[in] el	to insert fd callback into.
 * @param[in] fd	to read from.
 * @param[in] read	function to call when fd is readable.
 * @param[in] write	function to call when fd is writable.
 * @param[in] error	function to call when an error occurs on the fd.
 * @param[in] ctx	to pass to handler.
 * @return a handle to use for future deletion of the file descriptor event.
 */
fr_event_fd_t *fr_event_fd_insert(fr_event_list_t *el, int fd,
				  fr_event_fd_handler_t read,
				  fr_event_fd_handler_t write,
				  fr_event_fd_handler_t error,
				  void *ctx)
{
	int		filter = 0;
	struct kevent	evset;
	fr_event_fd_t	*ef, find;

	if (!el) {
		fr_strerror_printf("Invalid argument: NULL event list");
		return NULL;
	}

	if (!read && !write) {
		fr_strerror_printf("Invalid arguments: NULL read and write callbacks");
		return NULL;
	}

	if (fd < 0) {
		fr_strerror_printf("Invalid arguments: Bad FD %i", fd);
		return NULL;
	}

	memset(&find, 0, sizeof(find));

	/*
	 *	Get the existing fr_event_fd_t if it exists.
	 *
	 *	We don't need to do anything special for kqueue if
	 *	there are new callbacks, as the old filters get
	 *	replaced with the new ones automatically.
	 */
	find.fd = fd;
	ef = rbtree_finddata(el->fds, &find);
	if (!ef) {
		ef = talloc_zero(el, fr_event_fd_t);
		if (!ef) {
			fr_strerror_printf("Failed allocating memory for FD");
			return NULL;
		}
		talloc_set_destructor(ef, _fr_event_fd_free);
		el->num_fds++;
		rbtree_insert(el->fds, ef);
	}

	ef->fd = fd;
	ef->ctx = ctx;

	if (read) {
		ef->read = read;
		filter |= EVFILT_READ;
	}

	if (write) {
		ef->write = write;
		filter |= EVFILT_WRITE;
	}
	ef->error = error;

	EV_SET(&evset, fd, filter, EV_ADD | EV_ENABLE, 0, 0, ef);
	if (kevent(el->kq, &evset, 1, NULL, 0, NULL) < 0) {
		fr_strerror_printf("Failed inserting event for FD %i: %s", fd, fr_syserror(errno));
		talloc_free(ef);
		return NULL;
	}

	return ef;
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

#ifndef NDEBUG
	/*
	 *  Validate the event_t struct to detect memory issues early.
	 */
	ev = talloc_get_type_abort(*parent, fr_event_timer_t);

#else
	ev = *parent;
#endif

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

	/*
	 *	If there is an event, re-use it instead of freeing it
	 *	and allocating a new one.
	 */
	if (*parent) {
		int ret;

#ifndef NDEBUG
		ev = talloc_get_type_abort(*parent, fr_event_timer_t);
#else
		ev = *parent;
#endif

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
 * @param[in] user	the callback for EVFILT_USER
 * @param[in] ctx	user context for the callback
 * @return
 *	- < 0 on error
 *	- 0 on success
 */
int fr_event_user_insert(fr_event_list_t *el, fr_event_user_handler_t user, void *ctx)
{
	el->user = user;
	el->user_ctx = ctx;

	return 0;
}


/** Delete a user callback to the event list.
 *
 * @param[in] el	containing the timer events.
 * @param[in] user	the callback for EVFILT_USER
 * @param[in] ctx	user context for the callback
 * @return
 *	- < 0 on error
 *	- 0 on success
 */
int fr_event_user_delete(fr_event_list_t *el, fr_event_user_handler_t user, void *ctx)
{
	if ((el->user != user) || (el->user_ctx != ctx)) return -1;

	el->user = NULL;
	el->user_ctx = NULL;

	return 0;
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

	callback(ctx, when);

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

	if (el->exit) return -1;

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
	 *	Run the status callback.  It may tell us that the
	 *	application has more work to do, in which case we
	 *	re-set the timeout to be instant.
	 */
	if (el->status) {
		if (el->status(el->status_ctx, wake) > 0) {
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

	/*
	 *	Loop over all of the events, servicing them.
	 */
	for (i = 0; i < el->num_fd_events; i++) {
		fr_event_fd_t *ev = el->events[i].udata;

		if ((el->events[i].flags & EV_EOF) || (el->events[i].flags & EV_ERROR)) {
			/*
			 *	FIXME: delete the handler
			 *	here, and fix process.c to not
			 *	call fr_event_fd_delete().
			 *	It's cleaner.
			 *
			 *	Call the error handler which should
			 *	tear down the connection.
			 */
			if (ev->error) ev->error(el, ev->fd, ev->ctx);
			continue;
		}

		if (ev->read && (el->events[i].flags & EVFILT_READ)) ev->read(el, ev->fd, ev->ctx);
		if (ev->write && (el->events[i].flags & EVFILT_WRITE)) ev->write(el, ev->fd, ev->ctx);
		if (el->user && (el->events[i].flags & EVFILT_USER)) el->user(el->kq, &el->events[i], el->user_ctx);
	}

	if (fr_heap_num_elements(el->times) > 0) {
		struct timeval when;

		do {
			gettimeofday(&el->now, NULL);
			when = el->now;
		} while (fr_event_timer_run(el, &when) == 1);
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
	if (!el) return;

	el->exit = code;
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

	fr_heap_delete(el->times);

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
fr_event_list_t *fr_event_list_create(TALLOC_CTX *ctx, fr_event_status_t status, void *status_ctx)
{
	fr_event_list_t *el;

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

	el->status = status;
	el->status_ctx = status_ctx;

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

	el = fr_event_list_create(NULL, NULL);
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
