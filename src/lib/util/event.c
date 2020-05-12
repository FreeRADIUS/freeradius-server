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

/**  Wrapper around libkqueue to make managing events easier
 *
 * Non-thread-safe event handling specific to FreeRADIUS.
 *
 * By non-thread-safe we mean multiple threads can't insert/delete
 * events concurrently into the same event list without synchronization.
 *
 * @file src/lib/util/event.c
 *
 * @copyright 2007-2016 The FreeRADIUS server project
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2007 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/heap.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/rbtree.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/token.h>

#include <sys/stat.h>
#include <sys/wait.h>

#ifdef NDEBUG
/*
 *	Turn off documentation warnings as file/line
 *	args aren't used for non-debug builds.
 */
DIAG_OPTIONAL
DIAG_OFF(documentation)
#endif

#define FR_EV_BATCH_FDS (256)

DIAG_OFF(unused-macros)
#define fr_time() static_assert(0, "Use el->time for event loop timing")
DIAG_ON(unused-macros)

#if !defined(SO_GET_FILTER) && defined(SO_ATTACH_FILTER)
#  define SO_GET_FILTER SO_ATTACH_FILTER
#endif

#ifdef WITH_EVENT_DEBUG
#  define EVENT_DEBUG(fmt, ...) printf("EVENT:");printf(fmt, ## __VA_ARGS__);printf("\n");fflush(stdout)
#  ifndef EVENT_REPORT_FREQ
#    define EVENT_REPORT_FREQ	5
#  endif
#else
#  define EVENT_DEBUG(...)
#endif

static fr_table_num_sorted_t const kevent_filter_table[] = {
#ifdef EVFILT_AIO
	{ "EVFILT_AIO",		EVFILT_AIO },
#endif
#ifdef EVFILT_EXCEPT
	{ "EVFILT_EXCEPT",	EVFILT_EXCEPT },
#endif
#ifdef EVFILT_MACHPORT
	{ "EVFILT_MACHPORT",	EVFILT_MACHPORT },
#endif
	{ "EVFILT_PROC",	EVFILT_PROC },
	{ "EVFILT_READ",	EVFILT_READ },
	{ "EVFILT_SIGNAL",	EVFILT_SIGNAL },
	{ "EVFILT_TIMER",	EVFILT_TIMER },
	{ "EVFILT_VNODE",	EVFILT_VNODE },
	{ "EVFILT_WRITE",	EVFILT_WRITE }
};
static size_t kevent_filter_table_len = NUM_ELEMENTS(kevent_filter_table);

/** A timer event
 *
 */
struct fr_event_timer {
	fr_event_list_t		*el;			//!< because talloc_parent() is O(N) in number of objects
	fr_time_t		when;			//!< When this timer should fire.
	fr_event_timer_cb_t	callback;		//!< Callback to execute when the timer fires.
	void const		*uctx;			//!< Context pointer to pass to the callback.
	TALLOC_CTX		*linked_ctx;		//!< talloc ctx this event was bound to.

	fr_event_timer_t const	**parent;		//!< Previous timer.
	int32_t			heap_id;	       	//!< Where to store opaque heap data.
	fr_dlist_t		entry;			//!< in linked list of event timers

#ifndef NDEBUG
	char const		*file;			//!< Source file this event was last updated in.
	int			line;			//!< Line this event was last updated on.
#endif
};

typedef enum {
	FR_EVENT_FD_SOCKET	= 1,			//!< is a socket.
	FR_EVENT_FD_FILE	= 2,			//!< is a file.
	FR_EVENT_FD_DIRECTORY	= 4,			//!< is a directory.

#ifdef SO_GET_FILTER
	FR_EVENT_FD_PCAP	= 8,
#endif
} fr_event_fd_type_t;

#ifndef SO_GET_FILTER
#  define FR_EVENT_FD_PCAP	0
#endif

typedef struct {
	size_t			offset;			//!< Offset of function pointer in structure.
	char const		*name;			//!< Name of the event.
	int16_t			filter;			//!< Filter to apply.
	uint16_t		flags;			//!< Flags to use for inserting event.
	uint32_t		fflags;			//!< fflags to pass to filter.
	int			type;			//!< Type this filter applies to.
	bool			coalesce;		//!< Coalesce this map with the next.
} fr_event_func_map_t;

static fr_event_func_map_t io_func_map[] = {
	{
		.offset		= offsetof(fr_event_io_func_t, read),
		.name		= "read",
		.filter		= EVFILT_READ,
		.flags		= EV_ADD | EV_ENABLE,
#ifdef NOTE_NONE
		.fflags		= NOTE_NONE,
#else
		.fflags		= 0,
#endif
		.type		= FR_EVENT_FD_SOCKET | FR_EVENT_FD_FILE | FR_EVENT_FD_PCAP
	},
	{
		.offset		= offsetof(fr_event_io_func_t, write),
		.name		= "write",
		.filter		= EVFILT_WRITE,
		.flags		= EV_ADD | EV_ENABLE,
		.fflags		= 0,
		.type		= FR_EVENT_FD_SOCKET | FR_EVENT_FD_FILE | FR_EVENT_FD_PCAP
	},
	{ 0 }
};

static fr_event_func_map_t vnode_func_map[] = {
	{
		.offset		= offsetof(fr_event_vnode_func_t, delete),
		.name		= "delete",
		.filter		= EVFILT_VNODE,
		.flags		= EV_ADD | EV_ENABLE | EV_CLEAR,
		.fflags		= NOTE_DELETE,
		.type		= FR_EVENT_FD_FILE | FR_EVENT_FD_DIRECTORY,
		.coalesce	= true
	},
	{
		.offset		= offsetof(fr_event_vnode_func_t, write),
		.name		= "write",
		.filter		= EVFILT_VNODE,
		.flags		= EV_ADD | EV_ENABLE | EV_CLEAR,
		.fflags		= NOTE_WRITE,
		.type		= FR_EVENT_FD_FILE,
		.coalesce	= true
	},
	{
		.offset		= offsetof(fr_event_vnode_func_t, extend),
		.name		= "extend",
		.filter		= EVFILT_VNODE,
		.flags		= EV_ADD | EV_ENABLE | EV_CLEAR,
		.fflags		= NOTE_EXTEND,
		.type		= FR_EVENT_FD_FILE | FR_EVENT_FD_DIRECTORY,
		.coalesce	= true
	},
	{
		.offset		= offsetof(fr_event_vnode_func_t, attrib),
		.name		= "attrib",
		.filter		= EVFILT_VNODE,
		.flags		= EV_ADD | EV_ENABLE | EV_CLEAR,
		.fflags		= NOTE_ATTRIB,
		.type		= FR_EVENT_FD_FILE,
		.coalesce	= true
	},
	{
		.offset		= offsetof(fr_event_vnode_func_t, link),
		.name		= "link",
		.filter		= EVFILT_VNODE,
		.flags		= EV_ADD | EV_ENABLE | EV_CLEAR,
		.fflags		= NOTE_LINK,
		.type		= FR_EVENT_FD_FILE,
		.coalesce	= true
	},
	{
		.offset		= offsetof(fr_event_vnode_func_t, rename),
		.name		= "rename",
		.filter		= EVFILT_VNODE,
		.flags		= EV_ADD | EV_ENABLE | EV_CLEAR,
		.fflags		= NOTE_RENAME,
		.type		= FR_EVENT_FD_FILE,
		.coalesce	= true
	},
#ifdef NOTE_REVOKE
	{
		.offset		= offsetof(fr_event_vnode_func_t, revoke),
		.name		= "revoke",
		.filter		= EVFILT_VNODE,
		.flags		= EV_ADD | EV_ENABLE | EV_CLEAR,
		.fflags		= NOTE_REVOKE,
		.type		= FR_EVENT_FD_FILE,
		.coalesce	= true
	},
#endif
#ifdef NOTE_FUNLOCK
	{
		.offset		= offsetof(fr_event_vnode_func_t, funlock),
		.name		= "funlock",
		.filter		= EVFILT_VNODE,
		.flags		= EV_ADD | EV_ENABLE | EV_CLEAR,
		.fflags		= NOTE_FUNLOCK,
		.type		= FR_EVENT_FD_FILE,
		.coalesce	= true
	},
#endif
	{ 0 }
};

static fr_table_num_sorted_t const fr_event_fd_type_table[] = {
	{ "directory",		FR_EVENT_FD_DIRECTORY },
	{ "file",		FR_EVENT_FD_FILE },
	{ "pcap",		FR_EVENT_FD_PCAP },
	{ "socket",		FR_EVENT_FD_SOCKET }
};
static size_t fr_event_fd_type_table_len = NUM_ELEMENTS(fr_event_fd_type_table);

/** A file descriptor/filter event
 *
 */
struct fr_event_fd {
	fr_event_list_t		*el;			//!< because talloc_parent() is O(N) in number of objects
	fr_event_filter_t	filter;
	int			fd;			//!< File descriptor we're listening for events on.

	fr_event_fd_type_t	type;			//!< Type of events we're interested in.

	int			sock_type;		//!< The type of socket SOCK_STREAM, SOCK_RAW etc...

	fr_event_funcs_t	active;			//!< Active filter functions.
	fr_event_funcs_t	stored;			//!< Stored (set, but inactive) filter functions.

	fr_event_error_cb_t	error;			//!< Callback for when an error occurs on the FD.

	fr_event_func_map_t const *map;			//!< Function map between #fr_event_funcs_t and kevent filters.

	bool			is_registered;		//!< Whether this fr_event_fd_t's FD has been registered with
							///< kevent.  Mostly for debugging.
	bool			in_fd_to_free;		//!< Whether this event is in the fd_to_free list.

	void			*uctx;			//!< Context pointer to pass to each file descriptor callback.
	TALLOC_CTX		*linked_ctx;		//!< talloc ctx this event was bound to.

	fr_event_fd_t		*next;			//!< item in a list of fr_event_fd (to free).

#ifndef NDEBUG
	uintptr_t		armour;			//!< protection flag from being deleted.
#endif

#ifndef NDEBUG
	char const		*file;			//!< Source file this event was last updated in.
	int			line;			//!< Line this event was last updated on.
#endif
};

struct fr_event_pid {
	fr_event_list_t		*el;			//!< because talloc_parent() is O(N) in number of objects
	pid_t			pid;			//!< child to wait for

	fr_event_pid_cb_t	callback;		//!< callback to run when the child exits
	void			*uctx;			//!< Context pointer to pass to each file descriptor callback.

#ifndef NDEBUG
	char const		*file;			//!< Source file this event was last updated in.
	int			line;			//!< Line this event was last updated on.
#endif
};

/** Callbacks to perform when the event handler is about to check the events
 *
 */
typedef struct {
	fr_dlist_t		entry;			//!< Linked list of callback.
	fr_event_status_cb_t	callback;		//!< The callback to call.
	void			*uctx;			//!< Context for the callback.
} fr_event_pre_t;

/** Callbacks to perform after all timers and FDs have been checked
 *
 */
typedef struct {
	fr_dlist_t		entry;			//!< Linked list of callback.
	fr_event_timer_cb_t	callback;		//!< The callback to call.
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

	int			will_exit;		//!< Will exit on next call to fr_event_corral.
	int			exit;			//!< If non-zero event loop will prevent the addition
							///< of new events, and will return immediately
							///< from the corral/service function.

	fr_event_time_source_t	time;			//!< Where our time comes from.
	fr_time_t 		now;			//!< The last time the event list was serviced.
	bool			dispatch;		//!< Whether the event list is currently dispatching events.

	int			num_fd_events;		//!< Number of events in this event list.

	int			kq;			//!< instance associated with this event list.

	fr_dlist_head_t		pre_callbacks;		//!< callbacks when we may be idle...
	fr_dlist_head_t		user_callbacks;		//!< EVFILT_USER callbacks
	fr_dlist_head_t		post_callbacks;		//!< post-processing callbacks

	struct kevent		events[FR_EV_BATCH_FDS]; /* so it doesn't go on the stack every time */

	bool			in_handler;		//!< Deletes should be deferred until after the
							///< handlers complete.

	fr_event_fd_t		*fd_to_free;		//!< File descriptor events pending deletion.
	fr_dlist_head_t		ev_to_add;		//!< dlist of events to add

#ifdef WITH_EVENT_DEBUG
	fr_event_timer_t const	*report;		//!< Report event.
#endif
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
static int8_t fr_event_timer_cmp(void const *a, void const *b)
{
	fr_event_timer_t const	*ev_a = a, *ev_b = b;

	return fr_time_cmp(ev_a->when, ev_b->when);
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
	fr_event_fd_t const	*ev_a = a, *ev_b = b;
	int			ret;

	ret = (ev_a->fd < ev_b->fd) - (ev_a->fd > ev_b->fd);
	if (ret != 0) return ret;

	return (ev_a->filter > ev_b->filter) - (ev_a->filter < ev_b->filter);
}

/** Return the number of file descriptors is_registered with this event loop
 *
 */
int fr_event_list_num_fds(fr_event_list_t *el)
{
	if (unlikely(!el)) return -1;

	return rbtree_num_elements(el->fds);
}

/** Return the number of timer events currently scheduled
 *
 * @param[in] el to return timer events for.
 * @return number of timer events.
 */
int fr_event_list_num_timers(fr_event_list_t *el)
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

/** Get the current server time according to the event list
 *
 * If the event list is currently dispatching events, we return the time
 * this iteration of the event list started.
 *
 * If the event list is not currently dispatching events, we return the
 * current system time.
 *
 * @param[in]	el to get time from.
 * @return the current time according to the event list.
 */
fr_time_t fr_event_list_time(fr_event_list_t *el)
{
	if (el->dispatch) {
		return el->now;
	} else {
		return el->time();
	}
}

/** Placeholder callback to avoid branches in service loop
 *
 * This is set in place of any NULL function pointers, so that the event loop doesn't
 * SEGV if a filter callback function is unset between corral and service.
 */
static void fr_event_fd_noop(UNUSED fr_event_list_t *el, UNUSED int fd, UNUSED int flags, UNUSED void *uctx)
{
	return;
}

/** Build a new evset based on function pointers present
 *
 * @note The contents of active functions may be inconsistent if this function errors.  But the
 *	 only time that will occur is if the caller passed invalid arguments.
 *
 * @param[out] out_kev		where to write the evset.
 * @param[in] outlen		length of output buffer.
 * @param[out] active		The set of function pointers with active filters.
 * @param[in] ef		event to insert.
 * @param[in] new		Functions to map to filters.
 * @param[in] prev		Previous set of functions mapped to filters.
 * @return
 *	- >= 0 the number of changes written to out.
 *	- < 0 an error ocurred.
 */
static ssize_t fr_event_build_evset(struct kevent out_kev[], size_t outlen, fr_event_funcs_t *active,
				    fr_event_fd_t *ef,
				    fr_event_funcs_t const *new, fr_event_funcs_t const *prev)
{
	struct kevent			*out = out_kev, *end = out + outlen;
	fr_event_func_map_t const	*map;
	struct kevent			add[10], *add_p = add;
	size_t				i;

	EVENT_DEBUG("Building new evset for FD %i (new %p, prev %p)", ef->fd, new, prev);

	/*
	 *	Iterate over the function map, setting/unsetting
	 *	filters and filter flags.
	 */
	for (map = ef->map; map->name; map++) {
		bool		has_current_func = false;
		bool		has_prev_func = false;
		uint32_t	current_fflags = 0;
		uint32_t	prev_fflags = 0;

		do {
			fr_event_fd_cb_t prev_func;
			fr_event_fd_cb_t new_func;

			/*
			 *	If the previous value was the 'noop'
			 *	callback, it's identical to being unset.
			 */
			prev_func = *(fr_event_fd_cb_t const *)((uint8_t const *)prev + map->offset);
			if (prev_func && (prev_func != fr_event_fd_noop)) {
				EVENT_DEBUG("\t%s prev set (%p)", map->name, prev_func);
				prev_fflags |= map->fflags;
				has_prev_func = true;
			} else {
				EVENT_DEBUG("\t%s prev unset", map->name);
			}

			new_func = *(fr_event_fd_cb_t const *)((uint8_t const *)new + map->offset);
			if (new_func) {
				EVENT_DEBUG("\t%s curr set (%p)", map->name, new_func);
				current_fflags |= map->fflags;
				has_current_func = true;

				/*
				 *	Check the filter will work for the
				 *	type of file descriptor specified.
				 */
				if (!(map->type & ef->type)) {
					fr_strerror_printf("kevent %s (%s), can't be applied to fd of type %s",
							   map->name,
							   fr_table_str_by_value(kevent_filter_table, map->filter, "<INVALID>"),
							   fr_table_str_by_value(fr_event_fd_type_table,
								      map->type, "<INVALID>"));
					return -1;
				}

				/*
				 *	Mark this filter function as active
				 */
				memcpy((uint8_t *)active + map->offset, (uint8_t const *)new + map->offset,
				       sizeof(fr_event_fd_cb_t));
			} else {
				EVENT_DEBUG("\t%s curr unset", map->name);

				/*
				 *	Mark this filter function as inactive
				 *	by setting it to the 'noop' callback.
				 */
				*((fr_event_fd_cb_t *)((uint8_t *)active + map->offset)) = fr_event_fd_noop;
			}

			if (!(map + 1)->coalesce) break;
			map++;
		} while (1);

		if (out > end) {
			fr_strerror_printf("Out of memory to store kevent filters");
			return -1;
		}

		/*
		 *	Upsert if we add a function or change the flags.
		 */
		if (has_current_func &&
		    (!has_prev_func || (current_fflags != prev_fflags))) {
			if ((size_t)(add_p - add) >= (NUM_ELEMENTS(add))) {
		     		fr_strerror_printf("Out of memory to store kevent EV_ADD filters");
		     		return -1;
		     	}
		     	EVENT_DEBUG("\tEV_SET EV_ADD filter %s (%i), flags %i, fflags %i",
		     		    fr_table_str_by_value(kevent_filter_table, map->filter, "<INVALID>"),
		     		    map->filter, map->flags, current_fflags);
			EV_SET(add_p++, ef->fd, map->filter, map->flags, current_fflags, 0, ef);

		/*
		 *	Delete if we remove a function.
		 */
		} else if (!has_current_func && has_prev_func) {
		     	EVENT_DEBUG("\tEV_SET EV_DELETE filter %s (%i), flags %i, fflags %i",
		     		    fr_table_str_by_value(kevent_filter_table, map->filter, "<INVALID>"),
		     		    map->filter, EV_DELETE, 0, 0);
			EV_SET(out++, ef->fd, map->filter, EV_DELETE, 0, 0, 0);
		}
	}

	/*
	 *	kevent is fine with adds/deletes in the same operation
	 *	on the same file descriptor, but libkqueue doesn't do
	 *	any kind of coalescing or ordering so you get an EEXIST
	 *	error.
	 */
	for (i = 0; i < (size_t)(add_p - add); i++) memcpy(out++, &add[i], sizeof(*out));

	return out - out_kev;
}

/** Discover the type of a file descriptor
 *
 * This function writes the result of the discovery to the ef->type,
 * and ef->sock_type fields.
 *
 * @param[out] ef	to write type data to.
 * @param[in] fd	to discover the type of.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int fr_event_fd_type_set(fr_event_fd_t *ef, int fd)
{
	socklen_t       opt_len = sizeof(ef->sock_type);

	/*
	 *      It's a socket or PCAP socket
	 */
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &ef->sock_type, &opt_len) == 0) {
#ifdef SO_GET_FILTER
		opt_len = 0;
		if (unlikely(getsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, NULL, &opt_len) < 0)) {
			fr_strerror_printf("Failed determining PF status: %s", fr_syserror(errno));
			return -1;
		}
		if (opt_len) {
			ef->type = FR_EVENT_FD_PCAP;
		} else
#endif
		{
			ef->type = FR_EVENT_FD_SOCKET;
		}

	/*
	 *	It's a file or directory
	 */
	} else {
		struct stat buf;

		if (errno != ENOTSOCK) {
			fr_strerror_printf("Failed retrieving socket type: %s", fr_syserror(errno));
			return -1;
		}

		if (fstat(fd, &buf) < 0) {
			fr_strerror_printf("Failed calling stat() on file: %s", fr_syserror(errno));
			return -1;
		}

		if (S_ISDIR(buf.st_mode)) {
			ef->type = FR_EVENT_FD_DIRECTORY;
		} else {
			ef->type = FR_EVENT_FD_FILE;
		}
	}
	ef->fd = fd;

	return 0;
}

/** Remove a file descriptor from the event loop and rbtree but don't explicitly free it
 *
 *
 * @param[in] ef	to remove.
 * @return
 *	- 0 on success.
 *	- -1 on error;
 */
static int _event_fd_delete(fr_event_fd_t *ef)
{
	struct kevent		evset[10];
	int			count = 0;
	fr_event_list_t		*el = ef->el;
	fr_event_funcs_t	funcs;

	/*
	 *	Already been removed from the various trees and
	 *	the event loop.
	 */
	if (ef->is_registered) {
		memset(&funcs, 0, sizeof(funcs));

		fr_assert(ef->armour == 0);

		/*
		 *	If this fails, it's a pretty catastrophic error.
		 */
		count = fr_event_build_evset(evset, sizeof(evset)/sizeof(*evset), &ef->active, ef, &funcs, &ef->active);
		if (count > 0) {
			int ret;

			/*
			 *	If this fails, assert on debug builds.
			 */
			ret = kevent(el->kq, evset, count, NULL, 0, NULL);
			if (!fr_cond_assert_msg(ret >= 0,
						"FD %i was closed without being removed from the KQ: %s",
						ef->fd, fr_syserror(errno))) {
				return -1;	/* Prevent the free, and leave the fd in the trees */
			}
		}

		rbtree_deletebydata(el->fds, ef);
		ef->is_registered = false;
	}

	/*
	 *	Insert into the deferred free list, event will be
	 *	freed later.
	 */
	if (el->in_handler) {
		/*
		 *	Don't allow the same event to be
		 *	inserted into the free list multiple
		 *	times.
		 *
		 *	This can happen if the same ef is
		 *	delivered by multiple filters, i.e.
		 *	if EVFILT_READ and EVFILT_WRITE
		 *	were both high, and both handlers
		 *	attempted to delete the event
		 *	we'd need to prevent the event being
		 *	inserted into the free list multiple
		 *	times.
		 */
		if (!ef->in_fd_to_free) {
			ef->next = el->fd_to_free;	/* Link into the deferred free list */
			el->fd_to_free = ef;
			ef->in_fd_to_free = true;
		}
		return -1;				/* Will be freed later */
	}

	return 0;
}

/** Move a file descriptor event from one event list to another
 *
 * FIXME - Move suspended events too.
 *
 * @note Any pending events will not be transferred.
 *
 * @param[in] dst	Event list to move file descriptor event to.
 * @param[in] src	Event list to move file descriptor from.
 * @param[in] fd	of the event to move.
 * @param[in] filter	of the event to move.
 * @return
 *	- 0 on success.
 *      - -1 on failure.  The event will remain active in the src list.
 */
int _fr_event_fd_move(NDEBUG_LOCATION_ARGS
		      fr_event_list_t *dst, fr_event_list_t *src, int fd, fr_event_filter_t filter)
{
	fr_event_fd_t	*ef;
	int		ret;

	if (fr_event_loop_exiting(dst)) {
		fr_strerror_printf("Destination event loop exiting");
		return -1;
	}

	/*
	 *	Ensure this exists
	 */
	ef = rbtree_finddata(src->fds, &(fr_event_fd_t){ .fd = fd, .filter = filter });
	if (unlikely(!ef)) {
		fr_strerror_printf("No events are registered for fd %i", fd);
		return -1;
	}

	ret = _fr_event_filter_insert(NDEBUG_LOCATION_VALS
				      ef->linked_ctx, NULL,
				      dst, ef->fd, ef->filter, &ef->active, ef->error, ef->uctx);
	if (ret < 0) return -1;

	(void)fr_event_fd_delete(src, ef->fd, ef->filter);

	return ret;
}


/** Suspend/resume a subset of filters
 *
 * This function trades producing useful errors for speed.
 *
 * An example of suspending the read filter for an FD would be:
 @code {.c}
   static fr_event_update_t pause_read[] = {
   	FR_EVENT_SUSPEND(fr_event_io_func_t, read),
   	{ 0 }
   }

   fr_event_filter_update(el, fd, FR_EVENT_FILTER_IO, pause_read);
 @endcode
 *
 * @param[in] file	This function is being called from.
 * @param[in] line	This function is being called on.
 * @param[in] el	to update descriptor in.
 * @param[in] fd	to update filters for.
 * @param[in] filter	The type of filter to update.
 * @param[in] updates	An array of updates to toggle filters on/off without removing
 *			the callback function.
 */
int _fr_event_filter_update(NDEBUG_LOCATION_ARGS
			    fr_event_list_t *el, int fd, fr_event_filter_t filter, fr_event_update_t updates[])
{
	fr_event_fd_t		*ef;
	size_t			i;
	fr_event_funcs_t	curr_active, curr_stored;
	struct kevent		evset[10];
	int			count = 0;

	ef = rbtree_finddata(el->fds, &(fr_event_fd_t){ .fd = fd, .filter = filter });
	if (unlikely(!ef)) {
		fr_strerror_printf("No events are registered for fd %i", fd);
		return -1;
	}

#ifndef NDEBUG
	ef->file = file;
	ef->line = line;
#endif

	/*
	 *	Cheapest way of ensuring this function can error without
	 *	leaving everything in an inconsistent state.
	 */
	memcpy(&curr_active, &ef->active, sizeof(curr_active));
	memcpy(&curr_stored, &ef->stored, sizeof(curr_stored));

	/*
	 *	Apply modifications to our copies of the active/stored array.
	 */
	for (i = 0; updates[i].op; i++) {
		switch (updates[i].op) {
		default:
		case FR_EVENT_OP_SUSPEND:
			memcpy((uint8_t *)&ef->stored + updates[i].offset,
			       (uint8_t *)&ef->active + updates[i].offset, sizeof(fr_event_fd_cb_t));
			memset((uint8_t *)&ef->active + updates[i].offset, 0, sizeof(fr_event_fd_cb_t));
			break;

		case FR_EVENT_OP_RESUME:
			memcpy((uint8_t *)&ef->active + updates[i].offset,
			       (uint8_t *)&ef->stored + updates[i].offset, sizeof(fr_event_fd_cb_t));
			memset((uint8_t *)&ef->stored + updates[i].offset, 0, sizeof(fr_event_fd_cb_t));
			break;
		}
	}

	count = fr_event_build_evset(evset, sizeof(evset)/sizeof(*evset), &ef->active,
				     ef, &ef->active, &curr_active);
	if (unlikely(count < 0)) {
	error:
		memcpy(&ef->active, &curr_active, sizeof(curr_active));
		memcpy(&ef->stored, &curr_stored, sizeof(curr_stored));
		return -1;
	}

	if (count && unlikely(kevent(el->kq, evset, count, NULL, 0, NULL) < 0)) {
		fr_strerror_printf("Failed updating filters for FD %i: %s", ef->fd, fr_syserror(errno));
		goto error;
	}

	return 0;
}

/** Insert a filter for the specified fd
 *
 * @param[in] file	This function is being called from.
 * @param[in] line	This function is being called on.
 * @param[in] ctx	to bind lifetime of the event to.
 * @param[out] ef_out	Previously allocated ef, or NULL.
 * @param[in] el	to insert fd callback into.
 * @param[in] fd	to install filters for.
 * @param[in] filter	one of the #fr_event_filter_t values.
 * @param[in] funcs	Structure containing callback functions. If a function pointer
 *			is set, the equivalent kevent filter will be installed.
 * @param[in] error	function to call when an error occurs on the fd.
 * @param[in] uctx	to pass to handler.
 */
int _fr_event_filter_insert(NDEBUG_LOCATION_ARGS
			    TALLOC_CTX *ctx, fr_event_fd_t **ef_out,
			    fr_event_list_t *el, int fd,
			    fr_event_filter_t filter,
			    void *funcs, fr_event_error_cb_t error,
			    void *uctx)
{
	ssize_t			count;
	fr_event_fd_t		*ef;
	fr_event_funcs_t	active;
	struct kevent		evset[10];

	if (unlikely(!el)) {
		fr_strerror_printf("Invalid argument: NULL event list");
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

	if (!ef_out || !*ef_out) {
		ef = rbtree_finddata(el->fds, &(fr_event_fd_t){ .fd = fd, .filter = filter });
	} else {
		ef = *ef_out;
		fr_assert((fd < 0) || (ef->fd == fd));
	}

	/*
	 *	Need to free the event to change the talloc link.
	 *
	 *	This is generally bad.  If you hit this
	 *	code path you probably screwed up somewhere.
	 */
	if (unlikely(ef && (ef->linked_ctx != ctx))) TALLOC_FREE(ef);

	/*
	 *	No pre-existing event.  Allocate an entry
	 *	for insertion into the rbtree.
	 */
	if (!ef) {
		ef = talloc_zero(el, fr_event_fd_t);
		if (unlikely(!ef)) {
			fr_strerror_printf("Out of memory");
			return -1;
		}
		talloc_set_destructor(ef, _event_fd_delete);

		/*
		 *	Bind the lifetime of the event to the specified
		 *	talloc ctx.  If the talloc ctx is freed, the
		 *	event will also be freed.
		 */
		if (ctx != el) talloc_link_ctx(ctx, ef);
		ef->linked_ctx = ctx;
		ef->el = el;

		/*
		 *	Determine what type of file descriptor
		 *	this is.
		 */
		if (fr_event_fd_type_set(ef, fd) < 0) {
		free:
			talloc_free(ef);
			return -1;
		}

		switch (filter) {
		case FR_EVENT_FILTER_IO:
			ef->map = io_func_map;
			break;

		case FR_EVENT_FILTER_VNODE:
			ef->map = vnode_func_map;
			break;

		default:
			fr_strerror_printf("Filter %i not supported", filter);
			goto free;
		}

		count = fr_event_build_evset(evset, sizeof(evset)/sizeof(*evset), &ef->active, ef, funcs, &ef->active);
		if (count < 0) goto free;
		if (count && (unlikely(kevent(el->kq, evset, count, NULL, 0, NULL) < 0))) {
			fr_strerror_printf("Failed inserting filters for FD %i: %s", fd, fr_syserror(errno));
			goto free;
		}

		ef->filter = filter;
		rbtree_insert(el->fds, ef);
		ef->is_registered = true;

	/*
	 *	Pre-existing event, update the filters and
	 *	functions associated with the file descriptor.
	 */
	} else {
		fr_assert(ef->is_registered == true);

		/*
		 *	Take a copy of the current set of active
		 *	functions, so we can error out in a
		 *	consistent state.
		 */
		memcpy(&active, &ef->active, sizeof(ef->active));

		count = fr_event_build_evset(evset, sizeof(evset)/sizeof(*evset), &ef->active, ef, funcs, &ef->active);
		if (count < 0) {
		error:
			memcpy(&ef->active, &active, sizeof(ef->active));
			return -1;
		}
		if (count && (unlikely(kevent(el->kq, evset, count, NULL, 0, NULL) < 0))) {
			fr_strerror_printf("Failed modifying filters for FD %i: %s", fd, fr_syserror(errno));
			goto error;
		}

		/*
		 *	Clear any previously suspended functions
		 */
		memset(&ef->stored, 0, sizeof(ef->stored));
	}

#ifndef NDEBUG
	ef->file = file;
	ef->line = line;
#endif
	ef->error = error;
	ef->uctx = uctx;

	if (ef_out) *ef_out = ef;

	return 0;
}

/** Associate I/O callbacks with a file descriptor
 *
 * @param[in] file	This function is being called from.
 * @param[in] line	This function is being called on.
 * @param[in] ctx	to bind lifetime of the event to.
 * @param[in] el	to insert fd callback into.
 * @param[in] fd	to install filters for.
 * @param[in] read_fn	function to call when fd is readable.
 * @param[in] write_fn	function to call when fd is writable.
 * @param[in] error	function to call when an error occurs on the fd.
 * @param[in] uctx	to pass to handler.
 * @return
 *	- 0 on succes.
 *	- -1 on failure.
 */
int _fr_event_fd_insert(NDEBUG_LOCATION_ARGS
			TALLOC_CTX *ctx, fr_event_list_t *el, int fd,
		        fr_event_fd_cb_t read_fn,
		        fr_event_fd_cb_t write_fn,
		        fr_event_error_cb_t error,
		        void *uctx)
{
	fr_event_io_func_t funcs =  { .read = read_fn, .write = write_fn };

	if (unlikely(!read_fn && !write_fn)) {
		fr_strerror_printf("Invalid arguments: All callbacks are NULL");
		return -1;
	}

	return _fr_event_filter_insert(NDEBUG_LOCATION_VALS
				       ctx, NULL, el, fd, FR_EVENT_FILTER_IO, &funcs, error, uctx);
}

/** Remove a file descriptor from the event loop
 *
 * @param[in] el	to remove file descriptor from.
 * @param[in] fd	to remove.
 * @param[in] filter	The type of filter to remove.
 * @return
 *	- 0 if file descriptor was removed.
 *	- <0 on error.
 */
int fr_event_fd_delete(fr_event_list_t *el, int fd, fr_event_filter_t filter)
{
	fr_event_fd_t	*ef;

	ef = rbtree_finddata(el->fds, &(fr_event_fd_t){ .fd = fd, .filter = filter });
	if (unlikely(!ef)) {
		fr_strerror_printf("No events are registered for fd %i", fd);
		return -1;
	}

	/*
	 *	Free will normally fail if it's
	 *	a deferred free. There is a special
	 *	case for kevent failures though.
	 *
	 *	We distinguish between the two by
	 *	looking to see if the ef is still
	 *	in the even tree.
	 *
	 *	Talloc returning -1 guarantees the
	 *	memory has not been freed.
	 */
	if ((talloc_free(ef) == -1) && ef->is_registered) return -1;

	return 0;
}

#ifndef NDEBUG
/** Armour an FD
 *
 * @param[in] el	to remove file descriptor from.
 * @param[in] fd	to remove.
 * @param[in] filter	The type of filter to remove.
 * @param[in] armour	The armour to add.
 * @return
 *	- 0 if file descriptor was armoured
 *	- <0 on error.
 */
int fr_event_fd_armour(fr_event_list_t *el, int fd, fr_event_filter_t filter, uintptr_t armour)
{
	fr_event_fd_t	*ef;

	ef = rbtree_finddata(el->fds, &(fr_event_fd_t){ .fd = fd, .filter = filter });
	if (unlikely(!ef)) {
		fr_strerror_printf("No events are registered for fd %i", fd);
		return -1;
	}

	if (ef->armour != 0) {
		fr_strerror_printf("FD %i is already armoured", fd);
		return -1;
	}

	ef->armour = armour;

	return 0;
}

/** Unarmour an FD
 *
 * @param[in] el	to remove file descriptor from.
 * @param[in] fd	to remove.
 * @param[in] filter	The type of filter to remove.
 * @param[in] armour	The armour to remove
 * @return
 *	- 0 if file descriptor was unarmoured
 *	- <0 on error.
 */
int fr_event_fd_unarmour(fr_event_list_t *el, int fd, fr_event_filter_t filter, uintptr_t armour)
{
	fr_event_fd_t	*ef;

	ef = rbtree_finddata(el->fds, &(fr_event_fd_t){ .fd = fd, .filter = filter });
	if (unlikely(!ef)) {
		fr_strerror_printf("No events are registered for fd %i", fd);
		return -1;
	}

	fr_assert(ef->armour == armour);

	ef->armour = 0;
	return 0;
}
#endif

/** Remove an event from the event loop
 *
 * @param[in] ev	to free.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _event_timer_free(fr_event_timer_t *ev)
{
	fr_event_list_t	*el = ev->el;
	fr_event_timer_t const **ev_p;
	int		ret;

	if (fr_dlist_entry_in_list(&ev->entry)) {
		(void) fr_dlist_remove(&el->ev_to_add, ev);
		ret = 0;
	} else {
		ret = fr_heap_extract(el->times, ev);
	}

	ev_p = ev->parent;
	fr_assert(*(ev->parent) == ev);
	*ev_p = NULL;

	/*
	 *	Events MUST be in the heap
	 */
	if (!fr_cond_assert(ret == 0)) {
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
 * @param[in] file		This function is being called from.
 * @param[in] line		This function is being called on.
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
int _fr_event_timer_at(NDEBUG_LOCATION_ARGS
		       TALLOC_CTX *ctx, fr_event_list_t *el, fr_event_timer_t const **ev_p,
		       fr_time_t when, fr_event_timer_cb_t callback, void const *uctx)
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
		if (ctx != el) talloc_link_ctx(ctx, ev);

		talloc_set_destructor(ev, _event_timer_free);
	} else {
		memcpy(&ev, ev_p, sizeof(ev));	/* Not const to us */

		fr_assert(*ev_p == ev);

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
		 *	event will no longer be in the event loop,
		 *	but just in case, extract it anyway.
		 */
		(void) fr_heap_extract(el->times, ev);
	}

	ev->el = el;
	ev->when = when;
	ev->callback = callback;
	ev->uctx = uctx;
	ev->linked_ctx = ctx;
	ev->parent = ev_p;
#ifndef NDEBUG
	ev->file = file;
	ev->line = line;
#endif

	if (el->in_handler) {
		fr_dlist_insert_head(&el->ev_to_add, ev);
	} else if (unlikely(fr_heap_insert(el->times, ev) < 0)) {
		fr_strerror_printf_push("Failed inserting event");
		talloc_free(ev);
		return -1;
	}

	*ev_p = ev;

	return 0;
}

/** Insert a timer event into an event list
 *
 * @note The talloc parent of the memory returned in ev_p must not be changed.
 *	 If the lifetime of the event needs to be bound to another context
 *	 this function should be called with the existing event pointed to by
 *	 ev_p.
 *
 * @param[in] file		This function is being called from.
 * @param[in] line		This function is being called on.
 * @param[in] ctx		to bind lifetime of the event to.
 * @param[in] el		to insert event into.
 * @param[in,out] ev_p		If not NULL modify this event instead of creating a new one.  This is a parent
 *				in a temporal sense, not in a memory structure or dependency sense.
 * @param[in] delta		In how many nanoseconds to wait before should we execute the event.
 * @param[in] callback		function to execute if the event fires.
 * @param[in] uctx		user data to pass to the event.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int _fr_event_timer_in(NDEBUG_LOCATION_ARGS
		       TALLOC_CTX *ctx, fr_event_list_t *el, fr_event_timer_t const **ev_p,
		       fr_time_delta_t delta, fr_event_timer_cb_t callback, void const *uctx)
{
	fr_time_t now;

	now = el->time();
	now += delta;

	return _fr_event_timer_at(NDEBUG_LOCATION_VALS
				  ctx, el, ev_p, now, callback, uctx);
}

/** Delete a timer event from the event list
 *
 * @param[in] ev_p	of the event being deleted.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_event_timer_delete(fr_event_timer_t const **ev_p)
{
	fr_event_timer_t *ev;

	if (unlikely(!*ev_p)) return 0;

	memcpy(&ev, ev_p, sizeof(ev));
	return talloc_free(ev);
}

/** Remove PID wait event from kevent if the fr_event_pid_t is freed
 *
 * @param[in] ev	to free.
 * @return 0
 */
static int _event_pid_free(fr_event_pid_t *ev)
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
int _fr_event_pid_wait(NDEBUG_LOCATION_ARGS
		       TALLOC_CTX *ctx, fr_event_list_t *el, fr_event_pid_t const **ev_p,
		       pid_t pid, fr_event_pid_cb_t wait_fn, void *uctx)
{
	fr_event_pid_t *ev;
	struct kevent evset;

	ev = talloc(ctx, fr_event_pid_t);
	ev->pid = pid;
	ev->callback = wait_fn;
	ev->uctx = uctx;
#ifndef NDEBUG
	ev->file = file;
	ev->line = line;
#endif

	EV_SET(&evset, pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, ev);

	if (unlikely(kevent(el->kq, &evset, 1, NULL, 0, NULL) < 0)) {
		pid_t child;
		int status;

		talloc_free(ev);

		/*
		 *	Print this error here, so that the caller gets
		 *	the error from kevent(), and not waitpid().
		 */
		fr_strerror_printf("Failed adding waiter for PID %ld - %s", (long) pid, fr_syserror(errno));

		/*
		 *	If the child exited before kevent() was
		 *	called, we need to get its status via
		 *	waitpid().
		 */
		child = waitpid(pid, &status, WNOHANG);
		if (child == pid) {
			wait_fn(el, pid, status, uctx);
			return 0;
		}

		return -1;
	}
	talloc_set_destructor(ev, _event_pid_free);

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

	fr_dlist_insert_tail(&el->user_callbacks, user);

	return user->ident;
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
	fr_event_user_t *user, *next;

	for (user = fr_dlist_head(&el->user_callbacks);
	     user != NULL;
	     user = next) {
		next = fr_dlist_next(&el->user_callbacks, user);

		if ((user->callback == callback) &&
		    (user->uctx == uctx)) {
			fr_dlist_remove(&el->user_callbacks, user);
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
int fr_event_pre_insert(fr_event_list_t *el, fr_event_status_cb_t callback, void *uctx)
{
	fr_event_pre_t *pre;

	pre = talloc(el, fr_event_pre_t);
	pre->callback = callback;
	pre->uctx = uctx;

	fr_dlist_insert_tail(&el->pre_callbacks, pre);

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
int fr_event_pre_delete(fr_event_list_t *el, fr_event_status_cb_t callback, void *uctx)
{
	fr_event_pre_t *pre, *next;

	for (pre = fr_dlist_head(&el->pre_callbacks);
	     pre != NULL;
	     pre = next) {
		next = fr_dlist_next(&el->pre_callbacks, pre);

		if ((pre->callback == callback) &&
		    (pre->uctx == uctx)) {
			fr_dlist_remove(&el->pre_callbacks, pre);
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
int fr_event_post_insert(fr_event_list_t *el, fr_event_timer_cb_t callback, void *uctx)
{
	fr_event_post_t *post;

	post = talloc(el, fr_event_post_t);
	post->callback = callback;
	post->uctx = uctx;

	fr_dlist_insert_tail(&el->post_callbacks, post);

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
int fr_event_post_delete(fr_event_list_t *el, fr_event_timer_cb_t callback, void *uctx)
{
	fr_event_post_t *post, *next;

	for (post = fr_dlist_head(&el->post_callbacks);
	     post != NULL;
	     post = next) {
		next = fr_dlist_next(&el->post_callbacks, post);

		if ((post->callback == callback) &&
		    (post->uctx == uctx)) {
			fr_dlist_remove(&el->post_callbacks, post);
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
int fr_event_timer_run(fr_event_list_t *el, fr_time_t *when)
{
	fr_event_timer_cb_t	callback;
	void			*uctx;
	fr_event_timer_t	*ev;

	if (unlikely(!el)) return 0;

	if (fr_heap_num_elements(el->times) == 0) {
		*when = 0;
		return 0;
	}

	ev = fr_heap_peek(el->times);
	if (!ev) {
		*when = 0;
		return 0;
	}

	/*
	 *	See if it's time to do this one.
	 */
	if (ev->when > *when) {
		*when = ev->when;
		return 0;
	}

	callback = ev->callback;
	memcpy(&uctx, &ev->uctx, sizeof(uctx));

	fr_assert(*ev->parent == ev);

	/*
	 *	Delete the event before calling it.
	 */
	fr_event_timer_delete(ev->parent);

	callback(el, *when, uctx);

	return 1;
}

/** Gather outstanding timer and file descriptor events
 *
 * @param[in] el	to process events for.
 * @param[in] now	The current time.
 * @param[in] wait	if true, block on the kevent() call until a timer or file descriptor event occurs.
 * @return
 *	- <0 error, or the event loop is exiting
 *	- the number of outstanding I/O events, +1 if at least one timer will fire.
 */
int fr_event_corral(fr_event_list_t *el, fr_time_t now, bool wait)
{
	fr_time_t		when, *wake;
	struct timespec		ts_when, *ts_wake;
	fr_event_pre_t		*pre;
	int			num_fd_events;
	bool			timer_event_ready = false;
	fr_event_timer_t	*ev;

	el->num_fd_events = 0;

	if (el->will_exit || el->exit) {
		el->exit = el->will_exit;

		fr_strerror_printf("Event loop exiting");
		return -1;
	}

	/*
	 *	By default we wait for 0ns, which means returning
	 *	immediately from kevent().
	 */
	when = 0;
	wake = &when;
	el->now = now;

	/*
	 *	See when we have to wake up.  Either now, if the timer
	 *	events are in the past.  Or, we wait for a future
	 *	timer event.
	 */
	ev = fr_heap_peek(el->times);
	if (ev) {
		if (ev->when <= el->now) {
			timer_event_ready = true;

		} else if (wait) {
			when = ev->when - el->now;

		} /* else we're not waiting, leave "when == 0" */

	} else if (wait) {
		/*
		 *	We're asked to wait, but there's no timer
		 *	event.  We can then sleep forever.
		 */
		wake = NULL;
	}

	/*
	 *	Run the status callbacks.  It may tell us that the
	 *	application has more work to do, in which case we
	 *	re-set the timeout to be instant.
	 *
	 *	We only run these callbacks if the caller is otherwise
	 *	idle.
	 */
	if (wait) {
		for (pre = fr_dlist_head(&el->pre_callbacks);
		     pre != NULL;
		     pre = fr_dlist_next(&el->pre_callbacks, pre)) {
			if (pre->callback(pre->uctx, wake ? *wake : 0) > 0) {
				wake = &when;
				when = 0;
			}
		}
	}

	/*
	 *	Wake is the delta between el->now
	 *	(the event loops view of the current time)
	 *	and when the event should occur.
	 */
	if (wake) {
		ts_when = fr_time_delta_to_timespec(when);
		ts_wake = &ts_when;
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

	EVENT_DEBUG("%s - kevent returned %u FD events", __FUNCTION__, el->num_fd_events);

	/*
	 *	If there are no FD events, we must have woken up from a timer
	 */
	if (!num_fd_events) {
		el->now += when;
		if (wait) timer_event_ready = true;
	}
	/*
	 *	The caller doesn't really care what the value of the
	 *	return code is.  Just that it's greater than zero if
	 *	events needs servicing.
	 *
	 *	num_fd_events	  > 0 - if kevent() returns FD events
	 *	timer_event_ready > 0 - if there were timers ready BEFORE or AFTER calling kevent()
	 */
	return num_fd_events + timer_event_ready;
}

/** Service any outstanding timer or file descriptor events
 *
 * @param[in] el containing events to service.
 */
void fr_event_service(fr_event_list_t *el)
{
	int			i;
	fr_event_post_t		*post;
	fr_time_t		when;
	fr_event_timer_t	*ev;

	if (unlikely(el->exit)) return;

	EVENT_DEBUG("%s - Servicing %u FD events", __FUNCTION__, el->num_fd_events);

	/*
	 *	Run all of the file descriptor events.
	 */
	el->in_handler = true;
	for (i = 0; i < el->num_fd_events; i++) {
		fr_event_fd_t	*ef;
		int		fd_errno = 0;
		int		flags = el->events[i].flags;

		/*
		 *	Process any user events
		 */
		switch (el->events[i].filter) {
		case EVFILT_USER:
		{
			fr_event_user_t *user;

			/*
			 *	This is just a "wakeup" event, which
			 *	is always ignored.
			 */
			if (el->events[i].ident == 0) continue;

			user = talloc_get_type_abort((void *)el->events[i].ident, fr_event_user_t);
			fr_assert(user->ident == el->events[i].ident);

			user->callback(el->kq, &el->events[i], user->uctx);
		}
			continue;

		case EVFILT_PROC:
		{
			pid_t pid;
			fr_event_pid_t *pev;

			pev = talloc_get_type_abort((void *)el->events[i].udata, fr_event_pid_t);

			fr_assert(pev->pid == (pid_t) el->events[i].ident);
			fr_assert((el->events[i].fflags & NOTE_EXIT) != 0);

			pid = pev->pid;
			pev->pid = 0; /* so we won't hit kevent again when it's freed */
			pev->callback(el, pid, (int) el->events[i].data, pev->uctx);
		}
			continue;

		default:
			break;
		}

		ef = talloc_get_type_abort(el->events[i].udata, fr_event_fd_t);
		if (!ef->is_registered) continue;	/* Was deleted between corral and service */

		if (unlikely(flags & EV_ERROR)) {
			fd_errno = el->events[i].data;
		ev_error:
			/*
			 *      Call the error handler
			 */
			if (ef->error) ef->error(el, ef->fd, flags, fd_errno, ef->uctx);
			TALLOC_FREE(ef);
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
			if (ef->type == FR_EVENT_FD_FILE) goto service;
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
			if ((ef->sock_type == SOCK_RAW) && (ef->type == FR_EVENT_FD_PCAP)) goto service;
#endif
			fd_errno = el->events[i].fflags;

			goto ev_error;
		}

service:
		/*
		 *	If any of these callbacks are NULL, then
		 *	there's a logic error somewhere.
		 *	Filters are only installed if there's a
		 *	callback to handle them.
		 */
		switch (ef->filter) {
		case FR_EVENT_FILTER_IO:
			/*
			 *	io.read can delete the event, in which case
			 *	we *DON'T* want to call the write event.
			 */
			if (el->events[i].filter == EVFILT_READ) {
				ef->active.io.read(el, ef->fd, flags, ef->uctx);
			}
			else if (el->events[i].filter == EVFILT_WRITE) {
				ef->active.io.write(el, ef->fd, flags, ef->uctx);
			}
			break;

		case FR_EVENT_FILTER_VNODE:
			if (unlikely(!fr_cond_assert(el->events[i].filter == EVFILT_VNODE))) break;

			if ((el->events[i].fflags & NOTE_DELETE) != 0) {
				ef->active.vnode.delete(el, ef->fd, flags, ef->uctx);
				el->events[i].fflags &= ~NOTE_DELETE;
			}

			if ((el->events[i].fflags & NOTE_WRITE) != 0) {
				ef->active.vnode.write(el, ef->fd, flags, ef->uctx);
				el->events[i].fflags &= ~NOTE_WRITE;
			}

			if ((el->events[i].fflags & NOTE_EXTEND) != 0) {
				ef->active.vnode.extend(el, ef->fd, flags, ef->uctx);
				el->events[i].fflags &= ~NOTE_EXTEND;
			}

			if ((el->events[i].fflags & NOTE_ATTRIB) != 0) {
				ef->active.vnode.attrib(el, ef->fd, flags, ef->uctx);
				el->events[i].fflags &= ~NOTE_ATTRIB;
			}

			/*
			 *	NOTE_LINK is sometimes added even if we didn't ask for it.
			 */
			if ((el->events[i].fflags & NOTE_LINK) != 0) {
				if (ef->active.vnode.link) ef->active.vnode.link(el, ef->fd, flags, ef->uctx);
				el->events[i].fflags &= ~NOTE_LINK;
			}

			if ((el->events[i].fflags & NOTE_RENAME) != 0) {
				ef->active.vnode.rename(el, ef->fd, flags, ef->uctx);
				el->events[i].fflags &= ~NOTE_RENAME;
			}

#ifdef NOTE_REVOKE
			if ((el->events[i].fflags & NOTE_REVOKE) != 0) {
				ef->active.vnode.revoke(el, ef->fd, flags, ef->uctx);
				el->events[i].fflags &= ~NOTE_REVOKE;
			}
#endif

#ifdef NOTE_FUNLOCK
			if ((el->events[i].fflags & NOTE_FUNLOCK) != 0) {
				ef->active.vnode.funlock(el, ef->fd, flags, ef->uctx);
				el->events[i].fflags &= ~NOTE_FUNLOCK;
			}
#endif

			if (unlikely(!fr_cond_assert(el->events[i].fflags == 0))) break;
			break;

		default:
			break;
		}
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
	talloc_list_free(&el->fd_to_free);

	/*
	 *	We must call el->time() again here, else the event
	 *	list's time gets updated too infrequently, and we
	 *	can end up with a situation where timers are
	 *	serviced much later than they should be, which can
	 *	cause strange interaction effects, spurious calls
	 *	to kevent, and busy loops.
	 */
	el->now = el->time();

	/*
	 *	Run all of the timer events.  Note that these can add
	 *	new timers!
	 */
	if (fr_heap_num_elements(el->times) > 0) {
		do {
			when = el->now;
		} while (fr_event_timer_run(el, &when) == 1);
	}

	/*
	 *	New timers can be added while running the timer
	 *	callback. Instead of being added to the main timer
	 *	heap, they are instead added to the "to do" list.
	 *	Once we're finished running the callbacks, we walk
	 *	through the "to do" list, and add the callbacks to the
	 *	timer heap.
	 *
	 *	Doing it this way prevents the server from running
	 *	into an infinite loop.  The timer callback MAY add a
	 *	new timer which is in the past.  The loop above would
	 *	then immediately run the new callback, which could
	 *	also add an event in the past...
	 */
	while ((ev = fr_dlist_head(&el->ev_to_add)) != NULL) {
		(void)fr_dlist_remove(&el->ev_to_add, ev);
		if (unlikely(fr_heap_insert(el->times, ev) < 0)) {
			talloc_free(ev);
			fr_assert_msg(0, "failed inserting heap event: %s", fr_strerror());	/* Die in debug builds */
		}
	}

	el->in_handler = false;
	el->now = el->time();

	/*
	 *	Run all of the post-processing events.
	 */
	for (post = fr_dlist_head(&el->post_callbacks);
	     post != NULL;
	     post = fr_dlist_next(&el->post_callbacks, post)) {
		post->callback(el, el->now, post->uctx);
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
	if (unlikely(!el)) return;

	el->will_exit = code;
}

/** Check to see whether the event loop is in the process of exiting
 *
 * @param[in] el	to check.
 */
bool fr_event_loop_exiting(fr_event_list_t *el)
{
	return ((el->will_exit != 0) || (el->exit != 0));
}

/** Run an event loop
 *
 * @note Will not return until #fr_event_loop_exit is called.
 *
 * @param[in] el to start processing.
 */
CC_HINT(flatten) int fr_event_loop(fr_event_list_t *el)
{
	el->will_exit = el->exit = 0;

	el->dispatch = true;
	while (!el->exit) {
		if (unlikely(fr_event_corral(el, el->time(), true)) < 0) break;
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

	while ((ev = fr_heap_peek(el->times)) != NULL) fr_event_timer_delete(&ev);

	talloc_free_children(el);

	if (el->kq >= 0) close(el->kq);

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
fr_event_list_t *fr_event_list_alloc(TALLOC_CTX *ctx, fr_event_status_cb_t status, void *status_uctx)
{
	fr_event_list_t		*el;
	struct kevent		kev;

	el = talloc_zero(ctx, fr_event_list_t);
	if (!fr_cond_assert(el)) {
		fr_strerror_printf("Out of memory");
		return NULL;
	}
	el->time = fr_time;
	el->kq = -1;	/* So destructor can be used before kqueue() provides us with fd */
	talloc_set_destructor(el, _event_list_free);

	el->times = fr_heap_talloc_create(el, fr_event_timer_cmp, fr_event_timer_t, heap_id);
	if (!el->times) {
		fr_strerror_printf("Failed allocating event heap");
	error:
		talloc_free(el);
		return NULL;
	}

	el->fds = rbtree_talloc_create(el, fr_event_fd_cmp, fr_event_fd_t, NULL, 0);
	if (!el->fds) {
		fr_strerror_printf("Failed allocating FD tree");
		goto error;
	}

	el->kq = kqueue();
	if (el->kq < 0) {
		fr_strerror_printf("Failed allocating kqueue: %s", fr_syserror(errno));
		goto error;
	}

	fr_dlist_talloc_init(&el->pre_callbacks, fr_event_pre_t, entry);
	fr_dlist_talloc_init(&el->post_callbacks, fr_event_post_t, entry);
	fr_dlist_talloc_init(&el->user_callbacks, fr_event_user_t, entry);
	fr_dlist_talloc_init(&el->ev_to_add, fr_event_timer_t, entry);
	if (status) (void) fr_event_pre_insert(el, status, status_uctx);

	/*
	 *	Set our "exit" callback as ident 0.
	 */
	EV_SET(&kev, 0, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_FFNOP, 0, NULL);
	if (kevent(el->kq, &kev, 1, NULL, 0, NULL) < 0) {
		fr_strerror_printf("Failed adding exit callback to kqueue: %s", fr_syserror(errno));
		goto error;
	}

#ifdef WITH_EVENT_DEBUG
	fr_event_timer_in(el, el, &el->report, fr_time_delta_from_sec(EVENT_REPORT_FREQ), fr_event_report, NULL);
#endif

	return el;
}

/** Override event list time source
 *
 * @param[in] el	to set new time function for.
 * @param[in] func	to set.
 */
void fr_event_list_set_time_func(fr_event_list_t *el, fr_event_time_source_t func)
{
	el->time = func;
}

/** Return whether the event loop has any active events
 *
 */
bool fr_event_list_empty(fr_event_list_t *el)
{
	return !fr_heap_num_elements(el->times) && !rbtree_num_elements(el->fds);
}

#ifdef WITH_EVENT_DEBUG
/** Print out information about the number of events in the event loop
 *
 */
void fr_event_report(fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	EVENT_DEBUG("Event list %p", el);
	EVENT_DEBUG("   fd events        : %u", fr_event_list_num_fds(el));
	EVENT_DEBUG("   events last iter : %u", el->num_fd_events);
	EVENT_DEBUG("   num timer events : %u", fr_event_list_num_timers(el));

	fr_event_timer_in(el, el, &el->report, fr_time_delta_from_sec(EVENT_REPORT_FREQ), fr_event_report, uctx);
}

#ifndef NDEBUG
void fr_event_timer_dump(fr_event_list_t *el)
{
	fr_heap_iter_t		iter;
	fr_event_timer_t 	*ev;
	fr_time_t		now;

	now = el->time();

	EVENT_DEBUG("Time is now %"PRId64"", now);

	for (ev = talloc_get_type_abort(fr_heap_iter_init(el->times, &iter), fr_event_timer_t);
	     ev;
	     ev = talloc_get_type_abort(fr_heap_iter_next(el->times, &iter), fr_event_timer_t)) {
		EVENT_DEBUG("%s[%u]: %p time=%" PRId64 " (%c), callback=%p",
			    ev->file, ev->line, ev, ev->when, now > ev->when ? '<' : '>', ev->callback);
	}
}
#endif
#endif

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
	fr_time_t when;
	int64_t usec;

	when = *(fr_time_t *) ctx;
	usec = fr_time_to_usec(when);

	printf("%d.%06d\n", usec / USEC, usec % USEC);
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
	fr_time_t array[MAX];
	fr_time_t now, when;
	fr_event_list_t *el;

	el = fr_event_list_alloc(NULL, NULL);
	if (!el) fr_exit_now(1);

	memset(&rand_pool, 0, sizeof(rand_pool));
	rand_pool.randrsl[1] = time(NULL);

	fr_rand_init(&rand_pool, 1);
	rand_pool.randcnt = 0;

	array[0] = el->time();
	for (i = 1; i < MAX; i++) {
		array[i] = array[i - 1];
		array[i] += event_rand() & 0xffff;

		fr_event_timer_at(NULL, el, array[i], print_time, array[i]);
	}

	while (fr_event_list_num_timers(el)) {
		now = el->time();
		when = now;
		if (!fr_event_timer_run(el, &when)) {
			int delay = (when - now) / 1000;	/* nanoseconds to microseconds */

			printf("\tsleep %d microseconds\n", delay);
			fflush(stdout);
			usleep(delay);
		}
	}

	talloc_free(el);

	return 0;
}
#endif
