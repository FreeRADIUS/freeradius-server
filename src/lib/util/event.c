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

#define _EVENT_LIST_PRIVATE 1
typedef struct fr_event_list_s fr_event_list_t;

#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/token.h>
#include <freeradius-devel/util/atexit.h>

#include <sys/stat.h>
#include <sys/wait.h>

#ifdef NDEBUG
/*
 *	Turn off documentation warnings as file/line
 *	args aren't used for non-debug builds.
 */
DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(documentation)
DIAG_ON(DIAG_UNKNOWN_PRAGMAS)
#endif

#define FR_EV_BATCH_FDS (256)

DIAG_OFF(unused-macros)
#define fr_time() static_assert(0, "Use el->time for event loop timing")
DIAG_ON(unused-macros)

#if !defined(SO_GET_FILTER) && defined(SO_ATTACH_FILTER)
#  define SO_GET_FILTER SO_ATTACH_FILTER
#endif

static fr_table_num_sorted_t const kevent_filter_table[] = {
#ifdef EVFILT_AIO
	{ L("EVFILT_AIO"),	EVFILT_AIO },
#endif
#ifdef EVFILT_EXCEPT
	{ L("EVFILT_EXCEPT"),	EVFILT_EXCEPT },
#endif
#ifdef EVFILT_MACHPORT
	{ L("EVFILT_MACHPORT"),	EVFILT_MACHPORT },
#endif
	{ L("EVFILT_PROC"),	EVFILT_PROC },
	{ L("EVFILT_READ"),	EVFILT_READ },
	{ L("EVFILT_SIGNAL"),	EVFILT_SIGNAL },
	{ L("EVFILT_TIMER"),	EVFILT_TIMER },
	{ L("EVFILT_VNODE"),	EVFILT_VNODE },
	{ L("EVFILT_WRITE"),	EVFILT_WRITE }
};
static size_t kevent_filter_table_len = NUM_ELEMENTS(kevent_filter_table);

#ifdef EVFILT_LIBKQUEUE
static int log_conf_kq;
#endif

typedef enum {
	FR_EVENT_FD_SOCKET	= 1,			//!< is a socket.
	FR_EVENT_FD_FILE	= 2,			//!< is a file.
	FR_EVENT_FD_DIRECTORY	= 4,			//!< is a directory.

#ifdef SO_GET_FILTER
	FR_EVENT_FD_PCAP	= 8,
#endif
} fr_event_fd_type_t;

typedef enum {
	FR_EVENT_FUNC_IDX_NONE = 0,

	FR_EVENT_FUNC_IDX_FILTER,			//!< Sign flip is performed i.e. -1 = 0The filter is used
							//// as the index in the ev to func index.
	FR_EVENT_FUNC_IDX_FFLAGS			//!< The bit position of the flags in FFLAGS
							///< is used to provide the index.
							///< i.e. 0x01 -> 0, 0x02 -> 1, 0x08 -> 3 etc..
} fr_event_func_idx_type_t;

#ifndef SO_GET_FILTER
#  define FR_EVENT_FD_PCAP	0
#endif

/** Specifies a mapping between a function pointer in a structure and its respective event
 *
 * If the function pointer at the specified offset is set, then a matching event
 * will be added.
 *
 * If the function pointer is NULL, then any existing events will be removed.
 */
typedef struct {
	size_t			offset;			//!< Offset of function pointer in structure.
	char const		*name;			//!< Name of the event.
	int16_t			filter;			//!< Filter to apply.
	uint16_t		flags;			//!< Flags to use for inserting event.
	uint32_t		fflags;			//!< fflags to pass to filter.
	int			type;			//!< Type this filter applies to.
	bool			coalesce;		//!< Coalesce this map with the next.
} fr_event_func_map_entry_t;

typedef struct {
	fr_event_func_idx_type_t	idx_type;	//!< What type of index we use for
							///< event to function mapping.
	fr_event_func_map_entry_t	*func_to_ev;	//!< Function -> Event maps coalesced, out of order.
	fr_event_func_map_entry_t	**ev_to_func;	//!< Function -> Event maps in index order.
} fr_event_func_map_t;

static fr_event_func_map_t filter_maps[] = {
	[FR_EVENT_FILTER_IO] = {
		.idx_type = FR_EVENT_FUNC_IDX_FILTER,
		.func_to_ev = (fr_event_func_map_entry_t[]){
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
		}
	},
	[FR_EVENT_FILTER_VNODE] = {
		.idx_type = FR_EVENT_FUNC_IDX_FFLAGS,
		.func_to_ev = (fr_event_func_map_entry_t[]){
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
		}
	}
};

static fr_table_num_sorted_t const fr_event_fd_type_table[] = {
	{ L("directory"),	FR_EVENT_FD_DIRECTORY },
	{ L("file"),		FR_EVENT_FD_FILE },
	{ L("pcap"),		FR_EVENT_FD_PCAP },
	{ L("socket"),		FR_EVENT_FD_SOCKET }
};
static size_t fr_event_fd_type_table_len = NUM_ELEMENTS(fr_event_fd_type_table);

/** A file descriptor/filter event
 *
 */
struct fr_event_fd {
	fr_rb_node_t		node;			//!< Entry in the tree of file descriptor handles.
							///< this should really go away and we should pass around
							///< handles directly.

	fr_event_list_t		*el;			//!< Event list this event belongs to.
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

	void			*uctx;			//!< Context pointer to pass to each file descriptor callback.
	TALLOC_CTX		*linked_ctx;		//!< talloc ctx this event was bound to.

	fr_dlist_t		entry;			//!< Entry in free list.

#ifndef NDEBUG
	uintptr_t		armour;			//!< protection flag from being deleted.
#endif

#ifndef NDEBUG
	char const		*file;			//!< Source file this event was last updated in.
	int			line;			//!< Line this event was last updated on.
#endif
};

struct fr_event_pid {
	fr_event_list_t		*el;			//!< Event list this event belongs to.

	bool			is_registered;		//!< Whether this user event has been registered
							///< with the event loop.

	pid_t			pid;			//!< child to wait for
	fr_event_pid_t const	**parent;

	fr_event_pid_cb_t	callback;		//!< callback to run when the child exits
	void			*uctx;			//!< Context pointer to pass to each file descriptor callback.

	/** Fields that are only used if we're being triggered by a user event
	 */
	struct {
		fr_event_user_t		*ev;		//!< Fallback user event we use to raise a PID event when
							///< a race occurs with kevent.
		int			status;		//!< Status we got from waitid.
	} early_exit;
#ifndef NDEBUG
	char const		*file;			//!< Source file this event was last updated in.
	int			line;			//!< Line this event was last updated on.
#endif
};

/** Hold additional information for automatically reaped PIDs
 */
typedef struct {
	fr_event_list_t		*el;			//!< Event list this event belongs to.
	fr_event_pid_t const	*pid_ev;		//!< pid_ev this reaper is bound to.

	fr_dlist_t		entry;		        //!< If the fr_event_pid is in the detached, reap state,
							///< it's inserted into a list associated with the event.
							//!< We then send SIGKILL, and forcefully reap the process
							///< on exit.

	fr_event_pid_cb_t	callback;		//!< callback to run when the child exits
	void			*uctx;			//!< Context pointer to pass to each file descriptor callback.
} fr_event_pid_reap_t;

/** Callbacks for kevent() user events
 *
 */
struct fr_event_user_s {
	fr_event_list_t		*el;			//!< Event list this event belongs to.

	bool			is_registered;		//!< Whether this user event has been registered
							///< with the event loop.

	fr_event_user_cb_t 	callback;		//!< The callback to call.
	void			*uctx;			//!< Context for the callback.

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
	fr_event_post_cb_t	callback;		//!< The callback to call.
	void			*uctx;			//!< Context for the callback.
} fr_event_post_t;

/** Stores all information relating to an event list
 *
 */
struct fr_event_list_s {
	struct fr_event_list_pub_s	pub;			//!< Next event list in the chain.
	fr_rb_tree_t			*fds;			//!< Tree used to track FDs with filters in kqueue.

	int				will_exit;		//!< Will exit on next call to fr_event_corral.
	int				exit;			//!< If non-zero event loop will prevent the addition
								///< of new events, and will return immediately
								///< from the corral/service function.

	bool				dispatch;		//!< Whether the event list is currently dispatching events.

	int				num_fd_events;		//!< Number of events in this event list.

	int				kq;			//!< instance associated with this event list.

	fr_dlist_head_t			pre_callbacks;		//!< callbacks when we may be idle...
	fr_dlist_head_t			post_callbacks;		//!< post-processing callbacks

	fr_dlist_head_t			pid_to_reap;		//!< A list of all orphaned child processes we're
								///< waiting to reap.

	struct kevent			events[FR_EV_BATCH_FDS]; /* so it doesn't go on the stack every time */

	bool				in_handler;		//!< Deletes should be deferred until after the
								///< handlers complete.

	fr_dlist_head_t			fd_to_free;		//!< File descriptor events pending deletion.

#ifdef WITH_EVENT_DEBUG
	fr_timer_t			*report;		//!< Report event.
#endif
};

static void event_fd_func_index_build(fr_event_func_map_t *map)
{
	switch (map->idx_type) {
	default:
		return;

	/*
	 *	- Figure out the lowest filter value
	 *      - Invert it
	 *      - Allocate an array
	 *	- Populate the array
	 */
	case FR_EVENT_FUNC_IDX_FILTER:
	{
		int				low = 0;
		fr_event_func_map_entry_t	*entry;

		for (entry = map->func_to_ev; entry->name; entry++) if (entry->filter < low) low = entry->filter;

		map->ev_to_func = talloc_zero_array(NULL, fr_event_func_map_entry_t *, ~low + 1);
		if (unlikely(!map->ev_to_func)) abort();

		for (entry = map->func_to_ev; entry->name; entry++) map->ev_to_func[~entry->filter] = entry;
	}
		break;

	/*
	 *	- Figure out the highest bit position
	 *	- Allocate an array
	 *	- Populate the array
	 */
	case FR_EVENT_FUNC_IDX_FFLAGS:
	{
		uint8_t				high = 0, pos;
		fr_event_func_map_entry_t	*entry;

		for (entry = map->func_to_ev; entry->name; entry++) {
			pos = fr_high_bit_pos(entry->fflags);
			if (pos > high) high = pos;
		}

		map->ev_to_func = talloc_zero_array(NULL, fr_event_func_map_entry_t *, high);
		if (unlikely(!map->ev_to_func)) abort();

		for (entry = map->func_to_ev; entry->name; entry++) {
			typeof_field(fr_event_func_map_entry_t, fflags) fflags = entry->fflags;

			/*
			 *	Multiple notes can be associated
			 *	with the same function.
			 */
			while ((pos = fr_high_bit_pos(fflags))) {
				pos -= 1;
				map->ev_to_func[pos] = entry;
				/*
				 * 	Coverity thinks that after this decrement, pos
				 * 	can be 255 even though the loop condition precludes
				 * 	it. Adding a Coverity-only check won't change that,
				 * 	so we're stuck with annotation.
				 */
				/* coverity[overflow_const] */
				fflags &= ~(1 << pos);
			}
		}
	}
		break;
	}
}

/** Figure out which function to call given a kevent
 *
 * This function should be called in a loop until it returns NULL.
 *
 * @param[in] ef		File descriptor state handle.
 * @param[in] filter		from the kevent.
 * @param[in,out] fflags	from the kevent.  Each call will return the function
 *				from the next most significant NOTE_*, with each
 *				NOTE_* before unset from fflags.
 * @return
 *	- NULL there are no more callbacks to call.
 *	- The next callback to call.
 */
static inline CC_HINT(always_inline) fr_event_fd_cb_t event_fd_func(fr_event_fd_t *ef, int *filter, int *fflags)
{
	fr_event_func_map_t const *map = ef->map;

#define GET_FUNC(_ef, _offset) *((fr_event_fd_cb_t const *)((uint8_t const *)&(_ef)->active + _offset))

	switch (map->idx_type) {
	default:
		fr_assert_fail("Invalid index type %u", map->idx_type);
		return NULL;

	case FR_EVENT_FUNC_IDX_FILTER:
	{
		int idx;

		if (!*filter) return NULL;

		idx = ~*filter;				/* Consume the filter */
		*filter = 0;

		return GET_FUNC(ef, map->ev_to_func[idx]->offset);
	}

	case FR_EVENT_FUNC_IDX_FFLAGS:
	{
		int			our_fflags = *fflags;
		uint8_t			pos = fr_high_bit_pos(our_fflags);

		if (!pos) return NULL;			/* No more fflags to consume */
		pos -= 1;				/* Saves an array element */

		*fflags = our_fflags & ~(1 << pos);	/* Consume the knote */

		return GET_FUNC(ef, map->ev_to_func[pos]->offset);
	}
	}
}

/** Compare two file descriptor handles
 *
 * @param[in] one the first file descriptor handle.
 * @param[in] two the second file descriptor handle.
 * @return CMP(one, two)
 */
static int8_t fr_event_fd_cmp(void const *one, void const *two)
{
	fr_event_fd_t const	*a = one, *b = two;

	CMP_RETURN(a, b, fd);

	return CMP(a->filter, b->filter);
}

/** Return the number of file descriptors is_registered with this event loop
 *
 */
uint64_t fr_event_list_num_fds(fr_event_list_t *el)
{
	if (unlikely(!el)) return -1;

	return fr_rb_num_elements(el->fds);
}

/** Return the number of timer events currently scheduled
 *
 * @param[in] el to return timer events for.
 * @return number of timer events.
 */
uint64_t fr_event_list_num_timers(fr_event_list_t *el)
{
	if (unlikely(!el)) return -1;

	return fr_timer_list_num_events(el->pub.tl);
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
	return el->pub.tl->time();
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
 * @param[in] el		we're building events for.
 * @param[out] out_kev		where to write the evset.
 * @param[in] outlen		length of output buffer.
 * @param[out] active		The set of function pointers with active filters.
 * @param[in] ef		event to insert.
 * @param[in] new		Functions to map to filters.
 * @param[in] prev		Previous set of functions mapped to filters.
 * @return
 *	- >= 0 the number of changes written to out.
 *	- < 0 an error occurred.
 */
static ssize_t fr_event_build_evset(
#ifndef WITH_EVENT_DEBUG
				    UNUSED
#endif
				    fr_event_list_t *el,
				    struct kevent out_kev[], size_t outlen, fr_event_funcs_t *active,
				    fr_event_fd_t *ef,
				    fr_event_funcs_t const *new, fr_event_funcs_t const *prev)
{
	struct kevent			*out = out_kev, *end = out + outlen;
	fr_event_func_map_entry_t const *map;
	struct kevent			add[10], *add_p = add;
	size_t				i;

	EVENT_DEBUG("%p - Building new evset for FD %i (new %p, prev %p)", el, ef->fd, new, prev);

	/*
	 *	Iterate over the function map, setting/unsetting
	 *	filters and filter flags.
	 */
	for (map = ef->map->func_to_ev; map->name; map++) {
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
			if (new_func && (new_func != fr_event_fd_noop)) {
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
			fr_strerror_const("Out of memory to store kevent filters");
			return -1;
		}

		/*
		 *	Upsert if we add a function or change the flags.
		 */
		if (has_current_func &&
		    (!has_prev_func || (current_fflags != prev_fflags))) {
			if ((size_t)(add_p - add) >= (NUM_ELEMENTS(add))) {
		     		fr_strerror_const("Out of memory to store kevent EV_ADD filters");
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
		     		    map->filter, EV_DELETE, 0);
			EV_SET(out++, ef->fd, map->filter, EV_DELETE, 0, 0, ef);
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
		count = fr_event_build_evset(el, evset, sizeof(evset)/sizeof(*evset),
					     &ef->active, ef, &funcs, &ef->active);
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

		fr_rb_delete(el->fds, ef);
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
		if (!fr_dlist_entry_in_list(&ef->entry)) fr_dlist_insert_tail(&el->fd_to_free, ef);
		return -1;				/* Will be freed later */
	} else if (fr_dlist_entry_in_list(&ef->entry)) {
		fr_dlist_remove(&el->fd_to_free, ef);
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
		fr_strerror_const("Destination event loop exiting");
		return -1;
	}

	/*
	 *	Ensure this exists
	 */
	ef = fr_rb_find(src->fds, &(fr_event_fd_t){ .fd = fd, .filter = filter });
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
 * @param[in] el	to update descriptor in.
 * @param[in] fd	to update filters for.
 * @param[in] filter	The type of filter to update.
 * @param[in] updates	An array of updates to toggle filters on/off without removing
 *			the callback function.
 */
int _fr_event_filter_update(NDEBUG_LOCATION_ARGS
			    fr_event_list_t *el, int fd, fr_event_filter_t filter, fr_event_update_t const updates[])
{
	fr_event_fd_t		*ef;
	size_t			i;
	fr_event_funcs_t	curr_active, curr_stored;
	struct kevent		evset[10];
	int			count = 0;

	ef = fr_rb_find(el->fds, &(fr_event_fd_t){ .fd = fd, .filter = filter });
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
			fr_assert(ef->armour == 0); /* can't suspect protected FDs */
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

	count = fr_event_build_evset(el, evset, sizeof(evset)/sizeof(*evset), &ef->active,
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
		fr_strerror_const("Invalid argument: NULL event list");
		return -1;
	}

	if (unlikely(fd < 0)) {
		fr_strerror_printf("Invalid arguments: Bad FD %i", fd);
		return -1;
	}

	if (unlikely(el->exit)) {
		fr_strerror_const("Event loop exiting");
		return -1;
	}

	if (!ef_out || !*ef_out) {
		ef = fr_rb_find(el->fds, &(fr_event_fd_t){ .fd = fd, .filter = filter });
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
			fr_strerror_const("Out of memory");
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

		/*
		 *	Check the filter value is valid
		 */
		if ((filter > (NUM_ELEMENTS(filter_maps) - 1))) {
		not_supported:
			fr_strerror_printf("Filter %u not supported", filter);
			goto free;
		}
		ef->map = &filter_maps[filter];
		if (ef->map->idx_type == FR_EVENT_FUNC_IDX_NONE) goto not_supported;

		count = fr_event_build_evset(el, evset, sizeof(evset)/sizeof(*evset),
					     &ef->active, ef, funcs, &ef->active);
		if (count < 0) goto free;
		if (count && (unlikely(kevent(el->kq, evset, count, NULL, 0, NULL) < 0))) {
			fr_strerror_printf("Failed inserting filters for FD %i: %s", fd, fr_syserror(errno));
			goto free;
		}

		ef->filter = filter;
		fr_rb_insert(el->fds, ef);
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

		fr_assert((ef->armour == 0) || ef->active.io.read);

		count = fr_event_build_evset(el, evset, sizeof(evset)/sizeof(*evset),
					     &ef->active, ef, funcs, &ef->active);
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
 * @param[in] ctx	to bind lifetime of the event to.
 * @param[out] ef_out	Where to store the output event
 * @param[in] el	to insert fd callback into.
 * @param[in] fd	to install filters for.
 * @param[in] read_fn	function to call when fd is readable.
 * @param[in] write_fn	function to call when fd is writable.
 * @param[in] error	function to call when an error occurs on the fd.
 * @param[in] uctx	to pass to handler.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int _fr_event_fd_insert(NDEBUG_LOCATION_ARGS
			TALLOC_CTX *ctx, fr_event_fd_t **ef_out, fr_event_list_t *el, int fd,
		        fr_event_fd_cb_t read_fn,
		        fr_event_fd_cb_t write_fn,
		        fr_event_error_cb_t error,
		        void *uctx)
{
	fr_event_io_func_t funcs =  { .read = read_fn, .write = write_fn };

	if (unlikely(!read_fn && !write_fn)) {
		fr_strerror_const("Invalid arguments: All callbacks are NULL");
		return -1;
	}

	return _fr_event_filter_insert(NDEBUG_LOCATION_VALS
				       ctx, ef_out, el, fd, FR_EVENT_FILTER_IO, &funcs, error, uctx);
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

	ef = fr_rb_find(el->fds, &(fr_event_fd_t){ .fd = fd, .filter = filter });
	if (unlikely(!ef)) {
		fr_strerror_printf("No events are registered for fd %d, filter %u", fd, filter);
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

/** Get the opaque event handle from a file descriptor
 *
 * @param[in] el	to search for fd/filter in.
 * @param[in] fd	to search for.
 * @param[in] filter	to search for.
 * @return
 *	- NULL if no event could be found.
 *	- The opaque handle representing an fd event.
 */
fr_event_fd_t *fr_event_fd_handle(fr_event_list_t *el, int fd, fr_event_filter_t filter)
{
	fr_event_fd_t *ef;

	ef = fr_rb_find(el->fds, &(fr_event_fd_t){ .fd = fd, .filter = filter });
	if (unlikely(!ef)) {
		fr_strerror_printf("No events are registered for fd %i", fd);
		return NULL;
	}

	return ef;
}

/** Returns the appropriate callback function for a given event
 *
 * @param[in] ef	the event filter fd handle.
 * @param[in] kq_filter	If the callbacks are indexed by filter.
 * @param[in] kq_fflags If the callbacks are indexed by NOTES (fflags).
 * @return
 *	- NULL if no event it associated with the given ef/kq_filter or kq_fflags combo.
 *	- The callback that would be called if an event with this filter/fflag combo was received.
 */
fr_event_fd_cb_t fr_event_fd_cb(fr_event_fd_t *ef, int kq_filter, int kq_fflags)
{
	return event_fd_func(ef, &kq_filter, &kq_fflags);
}

/** Returns the uctx associated with an fr_event_fd_t handle
 *
 */
void *fr_event_fd_uctx(fr_event_fd_t *ef)
{
	return ef->uctx;
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

	ef = fr_rb_find(el->fds, &(fr_event_fd_t){ .fd = fd, .filter = filter });
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

	ef = fr_rb_find(el->fds, &(fr_event_fd_t){ .fd = fd, .filter = filter });
	if (unlikely(!ef)) {
		fr_strerror_printf("No events are registered for fd %i", fd);
		return -1;
	}

	fr_assert(ef->armour == armour);

	ef->armour = 0;
	return 0;
}
#endif

/** Remove PID wait event from kevent if the fr_event_pid_t is freed
 *
 * @param[in] ev	to free.
 * @return 0
 */
static int _event_pid_free(fr_event_pid_t *ev)
{
	struct kevent evset;

	if (ev->parent) *ev->parent = NULL;
	if (!ev->is_registered || (ev->pid < 0)) return 0; /* already deleted from kevent */

	EVENT_DEBUG("%p - Disabling event for PID %u - %p was freed", ev->el, (unsigned int)ev->pid, ev);

	EV_SET(&evset, ev->pid, EVFILT_PROC, EV_DELETE, NOTE_EXIT, 0, ev);

	(void) kevent(ev->el->kq, &evset, 1, NULL, 0, NULL);

	return 0;
}

/** Evaluate a EVFILT_PROC event
 *
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - Public/private version of fr_event_list_t trips -fsanitize=function */
static inline CC_HINT(always_inline)
void event_pid_eval(fr_event_list_t *el, struct kevent *kev)
{
	pid_t			pid;
	fr_event_pid_t		*ev;
	fr_event_pid_cb_t	callback;
	void			*uctx;

	EVENT_DEBUG("%p - PID %u exited with status %i",
		    el, (unsigned int)kev->ident, (unsigned int)kev->data);

	ev = talloc_get_type_abort((void *)kev->udata, fr_event_pid_t);

	fr_assert(ev->pid == (pid_t) kev->ident);
	fr_assert((kev->fflags & NOTE_EXIT) != 0);

	pid = ev->pid;
	callback = ev->callback;
	uctx = ev->uctx;

	ev->is_registered = false;	/* so we won't hit kevent again when it's freed */

	/*
	 *	Delete the event before calling it.
	 *
	 *	This also sets the parent pointer
	 *	to NULL, so the thing that started
	 *	monitoring the process knows the
	 *	handle is no longer valid.
	 *
	 *	EVFILT_PROC NOTE_EXIT events are always
	 *	oneshot no matter what flags we pass,
	 *	so we're just reflecting the state of
	 *	the kqueue.
	 */
	talloc_free(ev);

	if (callback) callback(el, pid, (int) kev->data, uctx);
}

/** Called on the next loop through the event loop when inserting an EVFILT_PROC event fails
 *
 * This is just a trampoleen function which takes the user event and simulates
 * an EVFILT_PROC event from it.
 *
 * @param[in] el	That received the event.
 * @param[in] uctx	An fr_event_pid_t to process.
 */
static void _fr_event_pid_early_exit(fr_event_list_t *el, void *uctx)
{
	fr_event_pid_t *ev = talloc_get_type_abort(uctx, fr_event_pid_t);

	EVENT_DEBUG("%p - PID %ld exited early, triggered through user event", el, (long)ev->pid);

	/*
	 *	Simulate a real struct kevent with the values we
	 *	recorded in fr_event_pid_wait.
	 */
	event_pid_eval(el, &(struct kevent){ .ident = ev->pid, .data = ev->early_exit.status, .fflags = NOTE_EXIT, .udata = ev });
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
 * @param[in] callback		function to execute if the event fires.
 * @param[in] uctx		user data to pass to the event.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int _fr_event_pid_wait(NDEBUG_LOCATION_ARGS
		       TALLOC_CTX *ctx, fr_event_list_t *el, fr_event_pid_t const **ev_p,
		       pid_t pid, fr_event_pid_cb_t callback, void *uctx)
{
	fr_event_pid_t *ev;
	struct kevent evset;

	ev = talloc(ctx, fr_event_pid_t);
	if (unlikely(ev == NULL)) {
		fr_strerror_const("Out of memory");
		return -1;
	}
	*ev = (fr_event_pid_t) {
		.el = el,
		.pid = pid,
		.callback = callback,
		.uctx = uctx,
		.parent = ev_p,
#ifndef NDEBUG
		.file = file,
		.line = line,
#endif
	};
	talloc_set_destructor(ev, _event_pid_free);

	/*
	 *	macOS only, on FreeBSD NOTE_EXIT always provides
	 *	the status anyway.
	 */
#ifndef NOTE_EXITSTATUS
#define NOTE_EXITSTATUS (0)
#endif

	EVENT_DEBUG("%p - Adding exit waiter for PID %u", el, (unsigned int)pid);

	EV_SET(&evset, pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT | NOTE_EXITSTATUS, 0, ev);
	ev->is_registered = true;

	/*
	 *	This deals with the race where the process exited
	 *	before we could add it to the kqueue.
	 *
	 *	Unless our caller is broken, the process should
	 *	still be available for reaping, so we check
	 *	waitid to see if there is a pending process and
	 *	then call the callback as kqueue would have done.
	 */
	if (unlikely(kevent(el->kq, &evset, 1, NULL, 0, NULL) < 0)) {
    		siginfo_t	info;
		int ret;

		/*
		 *	Ensure we don't accidentally pick up the error
		 *	from kevent.
		 */
		fr_strerror_clear();

		ev->is_registered = false;

		/*
		 *	If the child exited before kevent() was
		 *	called, we need to get its status via
		 *	waitid().
		 *
		 *	We don't reap the process here to emulate
		 *	what kqueue does (notify but not reap).
		 *
		 *	waitid returns >0 on success, 0 if the
		 *	process is still running, and -1 on failure.
		 *
		 *	If we get a 0, then that's extremely strange
		 *	as adding the kevent failed for a reason
		 *	other than the process already having exited.
		 *
		 *	On Linux waitid will always return 1 to
		 *	indicate the process exited.
		 *
		 *	On macOS we seem to get a mix of 1 or 0,
		 *	even if the si_code is one of the values
		 *	we'd consider to indicate that the process
		 *	had completed.
		 */
		ret = waitid(P_PID, pid, &info, WEXITED | WNOHANG | WNOWAIT);
		if (ret > 0) {
			static fr_table_num_sorted_t const si_codes[] = {
				{ L("exited"),	CLD_EXITED },
				{ L("killed"),	CLD_KILLED },
				{ L("dumped"),	CLD_DUMPED },
				{ L("trapped"), CLD_TRAPPED },
				{ L("stopped"), CLD_STOPPED },
				{ L("continued"), CLD_CONTINUED }
			};
			static size_t si_codes_len = NUM_ELEMENTS(si_codes);

			switch (info.si_code) {
			case CLD_EXITED:
			case CLD_KILLED:
			case CLD_DUMPED:
				EVENT_DEBUG("%p - PID %ld early exit - code %s (%d), status %d",
					    el, (long)pid, fr_table_str_by_value(si_codes, info.si_code, "<UNKOWN>"),
					    info.si_code, info.si_status);

				/*
				 *	Record the status for later
				 */
				ev->early_exit.status = info.si_status;

				/*
				 *	The user event acts as a surrogate for
				 *	an EVFILT_PROC event, and will be evaluated
				 *	during the next loop through the event loop.
				 *
				 *	It will be automatically deleted when the
				 *	fr_event_pid_t is freed.
				 *
				 *	Previously we tried to evaluate the proc
				 *	callback here directly, but this lead to
				 *	multiple problems, the biggest being that
				 *	setting requests back to resumable failed
				 *	because they were not yet yielded,
				 *	leading to hangs.
				 */
			early_exit:
				if (fr_event_user_insert(ev, el, &ev->early_exit.ev, true, _fr_event_pid_early_exit, ev) < 0) {
					fr_strerror_printf_push("Failed adding wait for PID %ld, and failed adding "
								"backup user event", (long) pid);
				error:
					talloc_free(ev);
					return -1;
				}
				break;

			default:
				fr_strerror_printf("Unexpected code %s (%d) whilst waiting on PID %ld",
						   fr_table_str_by_value(si_codes, info.si_code, "<UNKOWN>"),
						   info.si_code, (long) pid);

				goto error;
			}
		/*
		 *	Failed adding waiter for process, but process has not completed...
		 *
		 *	This weird, but seems to happen on macOS occasionally.
		 *
		 *	Add an event to run early exit...
		 *
		 *	Man pages for waitid say if it returns 0 the info struct can be in
		 *	a nondeterministic state, so there's nothing more to do.
		 */
		} else if (ret == 0) {
			goto early_exit;
		} else {
			/*
			*	Print this error here, so that the caller gets
			*	the error from kevent(), and not waitpid().
			*/
			fr_strerror_printf("Failed adding waiter for PID %ld - kevent %s, waitid %s",
					   (long) pid, fr_syserror(evset.flags), fr_syserror(errno));

			goto error;
		}
	}

	/*
	 *	Sometimes the caller doesn't care about getting the
	 *	PID.  But we still want to clean it up.
	 */
	if (ev_p) *ev_p = ev;

	return 0;
}

/** Saves some boilerplate...
 *
 */
static inline CC_HINT(always_inline)
void event_list_reap_run_callback(fr_event_pid_reap_t *reap, pid_t pid, int status)
{
	if (reap->callback) reap->callback(reap->el, pid, status, reap->uctx);
}

/** Does the actual reaping of PIDs
 *
 */
static void _fr_event_pid_reap_cb(UNUSED fr_event_list_t *el, pid_t pid, int status, void *uctx)
{
	fr_event_pid_reap_t	*reap = talloc_get_type_abort(uctx, fr_event_pid_reap_t);

	waitpid(pid, &status, WNOHANG);	/* Don't block the process if there's a logic error somewhere */

	EVENT_DEBUG("%s - Reaper reaped PID %u, status %u - %p", __FUNCTION__, pid, status, reap);

	event_list_reap_run_callback(reap, pid, status);

	talloc_free(reap);
}

static int _fr_event_reap_free(fr_event_pid_reap_t *reap)
{
	/*
	 *	Clear out the entry in the pid_to_reap
	 *	list if the event was inserted.
	 */
	if (fr_dlist_entry_in_list(&reap->entry)) {
		EVENT_DEBUG("%s - Removing entry from pid_to_reap %i - %p", __FUNCTION__,
			    reap->pid_ev ? reap->pid_ev->pid : -1, reap);
		fr_dlist_remove(&reap->el->pid_to_reap, reap);
	}

	return 0;
}

/** Asynchronously wait for a PID to exit, then reap it
 *
 * This is intended to be used when we no longer care about a process
 * exiting, but we still want to clean up its state so we don't have
 * zombie processes sticking around.
 *
 * @param[in] el		to use to reap the process.
 * @param[in] pid		to reap.
 * @param[in] callback		to call when the process is reaped.
 *				May be NULL.
 * @param[in] uctx		to pass to callback.
 * @return
 *	- -1 if we couldn't find the process or it has already exited/been reaped.
 *      - 0 on success (we setup a process handler).
 */
int _fr_event_pid_reap(NDEBUG_LOCATION_ARGS fr_event_list_t *el, pid_t pid, fr_event_pid_cb_t callback, void *uctx)
{
	int			ret;
	fr_event_pid_reap_t	*reap;

	reap = talloc_zero(NULL, fr_event_pid_reap_t);
	if (unlikely(!reap)) {
		fr_strerror_const("Out of memory");
		return -1;
	}
	talloc_set_destructor(reap, _fr_event_reap_free);

	ret = _fr_event_pid_wait(NDEBUG_LOCATION_VALS reap, el, &reap->pid_ev, pid, _fr_event_pid_reap_cb, reap);
	if (ret < 0) {
		talloc_free(reap);
		return ret;
	}

	reap->el = el;
	reap->callback = callback;
	reap->uctx = uctx;

	EVENT_DEBUG("%s - Adding reaper for PID %u - %p", __FUNCTION__, pid, reap);

	fr_dlist_insert_tail(&el->pid_to_reap, reap);

	return ret;
}

/** Send a signal to all the processes we have in our reap list, and reap them
 *
 * @param[in] el	containing the processes to reap.
 * @param[in] timeout	how long to wait before we signal the processes.
 * @param[in] signal	to send to processes.  Should be a fatal signal.
 * @return The number of processes reaped.
 */
unsigned int fr_event_list_reap_signal(fr_event_list_t *el, fr_time_delta_t timeout, int signal)
{
	unsigned int processed = fr_dlist_num_elements(&el->pid_to_reap);
	fr_event_pid_reap_t *reap = NULL;

	/*
	 *	If we've got a timeout, our best option
	 *	is to use a kqueue instance to monitor
	 *	for process exit.
	 */
	if (fr_time_delta_ispos(timeout) && fr_dlist_num_elements(&el->pid_to_reap)) {
		int		status;
		struct kevent	evset;
		int		waiting = 0;
		int 		kq = kqueue();
		fr_time_t	now, start = el->pub.tl->time(), end = fr_time_add(start, timeout);

		if (unlikely(kq < 0)) goto force;

		fr_dlist_foreach(&el->pid_to_reap, fr_event_pid_reap_t, i) {
			if (!i->pid_ev) {
				EVENT_DEBUG("%p - %s - Reaper already called (logic error)... - %p",
					    el, __FUNCTION__, i);

				event_list_reap_run_callback(i, -1, SIGKILL);
				talloc_free(i);
				continue;
			}

			/*
			 *	See if any processes have exited already
			 */
			if (waitpid(i->pid_ev->pid, &status, WNOHANG) == i->pid_ev->pid) { /* reap */
				EVENT_DEBUG("%p - %s - Reaper PID %u already exited - %p",
					    el, __FUNCTION__, i->pid_ev->pid, i);
				event_list_reap_run_callback(i, i->pid_ev->pid, SIGKILL);
				talloc_free(i);
				continue;
			}

			/*
			 *	Add the rest to a temporary event loop
			 */
			EV_SET(&evset, i->pid_ev->pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, i);
			if (kevent(kq, &evset, 1, NULL, 0, NULL) < 0) {
				EVENT_DEBUG("%p - %s - Failed adding reaper PID %u to tmp event loop - %p",
					    el, __FUNCTION__, i->pid_ev->pid, i);
				event_list_reap_run_callback(i, i->pid_ev->pid, SIGKILL);
				talloc_free(i);
				continue;
			}
			waiting++;
		}

		/*
		 *	Keep draining process exits as they come in...
		 */
		while ((waiting > 0) && fr_time_gt(end, (now = el->pub.tl->time()))) {
			struct kevent	kev;
			int		ret;

			ret = kevent(kq, NULL, 0, &kev, 1, &fr_time_delta_to_timespec(fr_time_sub(end, now)));
			switch (ret) {
			default:
				EVENT_DEBUG("%p - %s - Reaper tmp loop error %s, forcing process reaping",
					    el, __FUNCTION__, fr_syserror(errno));
				close(kq);
				goto force;

			case 0:
				EVENT_DEBUG("%p - %s - Reaper timeout waiting for process exit, forcing process reaping",
					    el, __FUNCTION__);
				close(kq);
				goto force;

			case 1:
				reap = talloc_get_type_abort(kev.udata, fr_event_pid_reap_t);

				EVENT_DEBUG("%p - %s - Reaper reaped PID %u, status %u - %p",
					    el, __FUNCTION__, (unsigned int)kev.ident, (unsigned int)kev.data, reap);
				waitpid(reap->pid_ev->pid, &status, WNOHANG);	/* reap */

				event_list_reap_run_callback(reap, reap->pid_ev->pid, status);
				talloc_free(reap);
				break;
			}
			waiting--;
		}

		close(kq);
	}

force:
	/*
	 *	Deal with any lingering reap requests
	 */
	while ((reap = fr_dlist_head(&el->pid_to_reap))) {
		int status;

		EVENT_DEBUG("%s - Reaper forcefully reaping PID %u - %p", __FUNCTION__, reap->pid_ev->pid, reap);

		if (kill(reap->pid_ev->pid, signal) < 0) {
			/*
			 *	Make sure we don't hang if the
			 *	process has actually exited.
			 *
			 *	We could check for ESRCH but it's
			 *	not clear if that'd be returned
			 *	for a PID in the unreaped state
			 *	or not...
			 */
			waitpid(reap->pid_ev->pid, &status, WNOHANG);
			event_list_reap_run_callback(reap, reap->pid_ev->pid, status);
			talloc_free(reap);
			continue;
		}

		/*
		 *	Wait until the child process exits
		 */
		waitpid(reap->pid_ev->pid, &status, 0);
		event_list_reap_run_callback(reap, reap->pid_ev->pid, status);
		talloc_free(reap);
	}

	return processed;
}

/** Memory will not be freed if we fail to remove the event from the kqueue
 *
 * It's easier to debug memory leaks with modern tooling than it is
 * to determine why we get random failures and event leaks inside of kqueue.
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _event_user_delete(fr_event_user_t *ev)
{
	if (ev->is_registered) {
		struct kevent evset;

		EV_SET(&evset, (uintptr_t)ev, EVFILT_USER, EV_DELETE, 0, 0, 0);

		if (unlikely(kevent(ev->el->kq, &evset, 1, NULL, 0, NULL) < 0)) {
			fr_strerror_printf("Failed removing user event - kevent %s", fr_syserror(evset.flags));
			return -1;
		}
		ev->is_registered = false;
	}

	return 0;
}

static inline CC_HINT(always_inline)
void event_user_eval(fr_event_list_t *el, struct kevent *kev)
{
	fr_event_user_t *ev;

	/*
	 *	This is just a "wakeup" event, which
	 *	is always ignored.
	 */
	if (kev->ident == 0) return;

	ev = talloc_get_type_abort((void *)kev->ident, fr_event_user_t);
	fr_assert((uintptr_t)ev == kev->ident);

	ev->callback(el, ev->uctx);
}

/** Add a user callback to the event list.
 *
 * @param[in] ctx	to allocate the event in.
 * @param[in] el	Containing the timer events.
 * @param[out] ev_p	Where to write a pointer.
 * @param[in] trigger	Whether the user event is triggered initially.
 * @param[in] callback	for EVFILT_USER.
 * @param[in] uctx	for the callback.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
int _fr_event_user_insert(NDEBUG_LOCATION_ARGS
			  TALLOC_CTX *ctx, fr_event_list_t *el, fr_event_user_t **ev_p,
			  bool trigger, fr_event_user_cb_t callback, void *uctx)
{
	fr_event_user_t *ev;
	struct kevent evset;

	ev = talloc(ctx, fr_event_user_t);
	if (unlikely(ev == NULL)) {
		fr_strerror_const("Out of memory");
		return -1;
	}
	*ev = (fr_event_user_t) {
		.el = el,
		.callback = callback,
		.uctx = uctx,
#ifndef NDEBUG
		.file = file,
		.line = line,
#endif
	};

	EV_SET(&evset, (uintptr_t)ev,
	       EVFILT_USER, EV_ADD | EV_DISPATCH, (trigger * NOTE_TRIGGER), 0, ev);

	if (unlikely(kevent(el->kq, &evset, 1, NULL, 0, NULL) < 0)) {
		fr_strerror_printf("Failed adding user event - kevent %s", fr_syserror(evset.flags));
		talloc_free(ev);
		return -1;
	}
	ev->is_registered = true;
	talloc_set_destructor(ev, _event_user_delete);

	if (ev_p) *ev_p = ev;

	return 0;
}

/** Trigger a user event
 *
 * @param[in] ev	Handle for the user event.
 * @return
 *	- 0 on success.
 *	- -1 on error.
 */
int fr_event_user_trigger(fr_event_user_t *ev)
{
	struct kevent evset;

	EV_SET(&evset, (uintptr_t)ev, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);

	if (unlikely(kevent(ev->el->kq, &evset, 1, NULL, 0, NULL) < 0)) {
		fr_strerror_printf("Failed triggering user event - kevent %s", fr_syserror(evset.flags));
		return -1;
	}

	return 0;
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
int fr_event_post_insert(fr_event_list_t *el, fr_event_post_cb_t callback, void *uctx)
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
int fr_event_post_delete(fr_event_list_t *el, fr_event_post_cb_t callback, void *uctx)
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
	fr_time_delta_t		when, *wake;
	struct timespec		ts_when, *ts_wake;
	fr_event_pre_t		*pre;
	int			num_fd_events;
	bool			timer_event_ready = false;
	fr_time_t		next;

	el->num_fd_events = 0;

	if (el->will_exit || el->exit) {
		el->exit = el->will_exit;

		fr_strerror_const("Event loop exiting");
		return -1;
	}

	/*
	 *	By default we wait for 0ns, which means returning
	 *	immediately from kevent().
	 */
	when = fr_time_delta_wrap(0);
	wake = &when;

	/*
	 *	See when we have to wake up.  Either now, if the timer
	 *	events are in the past.  Or, we wait for a future
	 *	timer event.
	 */
	next = fr_timer_list_when(el->pub.tl);
	if (fr_time_neq(next, fr_time_wrap(0))) {
		if (fr_time_lteq(next, now)) {
			timer_event_ready = true;

		} else if (wait) {
			when = fr_time_sub(next, now);

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
			if (pre->callback(now, wake ? *wake : fr_time_delta_wrap(0), pre->uctx) > 0) {
				wake = &when;
				when = fr_time_delta_wrap(0);
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

	EVENT_DEBUG("%p - %s - kevent returned %u FD events", el, __FUNCTION__, el->num_fd_events);

	/*
	 *	If there are no FD events, we must have woken up from a timer
	 */
	if (!num_fd_events) {
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

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private fr_event_list_t trips --fsanitize=function*/
static inline CC_HINT(always_inline)
void event_callback(fr_event_list_t *el, fr_event_fd_t *ef, int *filter, int flags, int *fflags)
{
	fr_event_fd_cb_t	fd_cb;

	while ((fd_cb = event_fd_func(ef, filter, fflags))) {
		fd_cb(el, ef->fd, flags, ef->uctx);
	}
}

/** Service any outstanding timer or file descriptor events
 *
 * @param[in] el containing events to service.
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - Public/private version of fr_event_list_t trips -fsanitize=function */
void fr_event_service(fr_event_list_t *el)
{
	fr_timer_list_t	*etl = el->pub.tl;
	int			i;
	fr_event_post_t		*post;
	fr_time_t		when, now;

	if (unlikely(el->exit)) return;

	EVENT_DEBUG("%p - %s - Servicing %u FD events", el, __FUNCTION__, el->num_fd_events);

	/*
	 *	Run all of the file descriptor events.
	 */
	el->in_handler = true;
	for (i = 0; i < el->num_fd_events; i++) {
		/*
		 *	Process any user events
		 */
		switch (el->events[i].filter) {
		case EVFILT_USER:
			event_user_eval(el, &el->events[i]);
			continue;

		/*
		 *	Process proc events
		 */
		case EVFILT_PROC:
			event_pid_eval(el, &el->events[i]);
			continue;

		/*
		 *	Process various types of file descriptor events
		 */
		default:
		{
			fr_event_fd_t		*ef = talloc_get_type_abort(el->events[i].udata, fr_event_fd_t);
			int			fd_errno = 0;

			int			fflags = el->events[i].fflags;	/* mutable */
			int			filter = el->events[i].filter;
			int			flags = el->events[i].flags;

			if (!ef->is_registered) continue;	/* Was deleted between corral and service */

			if (unlikely(flags & EV_ERROR)) {
				fd_errno = el->events[i].data;
			ev_error:
				/*
				 *      Call the error handler, but only if the socket hasn't been deleted at EOF
				 *	below.
				 */
				if (ef->is_registered && ef->error) ef->error(el, ef->fd, flags, fd_errno, ef->uctx);
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

				/*
				 *	If we see an EV_EOF flag that means the
				 *	read side of the socket has been closed
				 *	but there may still be pending data.
				 *
				 *	Dispatch the read event and then error.
				 */
				if ((el->events[i].filter == EVFILT_READ) && (el->events[i].data > 0)) {
					event_callback(el, ef, &filter, flags, &fflags);
				}

				fd_errno = el->events[i].fflags;

				goto ev_error;
			}

		service:
#ifndef NDEBUG
			EVENT_DEBUG("Running event for fd %d, from %s[%d]", ef->fd, ef->file, ef->line);
#endif

			/*
			 *	Service the event_fd events
			 */
			event_callback(el, ef, &filter, flags, &fflags);
		}
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
	el->in_handler = false;	/* Allow events to be deleted */
	{
		fr_event_fd_t *ef;

		while ((ef = fr_dlist_head(&el->fd_to_free))) talloc_free(ef);
	}

	/*
	 *	We must call el->time() again here, else the event
	 *	list's time gets updated too infrequently, and we
	 *	can end up with a situation where timers are
	 *	serviced much later than they should be, which can
	 *	cause strange interaction effects, spurious calls
	 *	to kevent, and busy loops.
	 */
	now = etl->time();

	/*
	 *	Run all of the timer events.  Note that these can add
	 *	new timers!
	 */
	if (fr_time_neq(fr_timer_list_when(el->pub.tl), fr_time_wrap(0))) {
		int ret;

		when = now;

		ret = fr_timer_list_run(etl, &when);
		if (!fr_cond_assert(ret >= 0)) {	/* catastrophic error, trigger event loop exit */
			el->exit = 1;
			return;
		}

		EVENT_DEBUG("%p - %s - Serviced %u timer(s)", el, __FUNCTION__, (unsigned int)ret);
	}

	now = etl->time();

	/*
	 *	Run all of the post-processing events.
	 */
	for (post = fr_dlist_head(&el->post_callbacks);
	     post != NULL;
	     post = fr_dlist_next(&el->post_callbacks, post)) {
		post->callback(el, now, post->uctx);
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
		if (unlikely(fr_event_corral(el, el->pub.tl->time(), true)) < 0) break;
		fr_event_service(el);
	}

	/*
	 *	Give processes five seconds to exit.
	 *	This means any triggers that we may
	 *	have issued when the server exited
	 *	have a chance to complete.
	 */
	fr_event_list_reap_signal(el, fr_time_delta_from_sec(5), SIGKILL);
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
	fr_event_list_reap_signal(el, fr_time_delta_wrap(0), SIGKILL);

	talloc_free_children(el);

	if (el->kq >= 0) close(el->kq);

	return 0;
}

/** Free any memory we allocated for indexes
 *
 */
static int _event_free_indexes(UNUSED void *uctx)
{
	unsigned int i;

	for (i = 0; i < NUM_ELEMENTS(filter_maps); i++) if (talloc_free(filter_maps[i].ev_to_func) < 0) return -1;
	return 0;
}

static int _event_build_indexes(UNUSED void *uctx)
{
	unsigned int i;

	for (i = 0; i < NUM_ELEMENTS(filter_maps); i++) event_fd_func_index_build(&filter_maps[i]);
	return 0;
}

#ifdef EVFILT_LIBKQUEUE
/** kqueue logging wrapper function
 *
 */
static CC_HINT(format (printf, 1, 2)) CC_HINT(nonnull)
void _event_kqueue_log(char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fr_vlog(&default_log, L_DBG, __FILE__, __LINE__, fmt, ap);
	va_end(ap);
}

/** If we're building with libkqueue, and at debug level 4 or higher, enable libkqueue debugging output
 *
 * This requires a debug build of libkqueue
 */
static int _event_kqueue_logging(UNUSED void *uctx)
{
	struct kevent kev, receipt;

	log_conf_kq = kqueue();
	if (unlikely(log_conf_kq < 0)) {
		fr_strerror_const("Failed initialising logging configuration kqueue");
		return -1;
	}

	EV_SET(&kev, 0, EVFILT_LIBKQUEUE, EV_ADD, NOTE_DEBUG_FUNC, (intptr_t)_event_kqueue_log, NULL);
	if (kevent(log_conf_kq, &kev, 1, &receipt, 1, &(struct timespec){}) != 1) {
		close(log_conf_kq);
		log_conf_kq = -1;
		return 1;
	}

	if (fr_debug_lvl >= L_DBG_LVL_3) {
		EV_SET(&kev, 0, EVFILT_LIBKQUEUE, EV_ADD, NOTE_DEBUG, 1, NULL);
		if (kevent(log_conf_kq, &kev, 1, &receipt, 1, &(struct timespec){}) != 1) {
			fr_strerror_const("Failed enabling libkqueue debug logging");
			close(log_conf_kq);
			log_conf_kq = -1;
			return -1;
		}
	}

	return 0;
}

static int _event_kqueue_logging_stop(UNUSED void *uctx)
{
	struct kevent kev, receipt;

	EV_SET(&kev, 0, EVFILT_LIBKQUEUE, EV_ADD, NOTE_DEBUG_FUNC, 0, NULL);
	(void)kevent(log_conf_kq, &kev, 1, &receipt, 1, &(struct timespec){});

	close(log_conf_kq);
	log_conf_kq = -1;

	return 0;
}
#endif

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
	int			ret;

	/*
	 *	Build the map indexes the first time this
	 *	function is called.
	 */
	fr_atexit_global_once_ret(&ret, _event_build_indexes, _event_free_indexes, NULL);
#ifdef EVFILT_LIBKQUEUE
	fr_atexit_global_once_ret(&ret, _event_kqueue_logging, _event_kqueue_logging_stop, NULL);
#endif

	el = talloc_zero(ctx, fr_event_list_t);
	if (!fr_cond_assert(el)) {
		fr_strerror_const("Out of memory");
		return NULL;
	}
	el->kq = -1;	/* So destructor can be used before kqueue() provides us with fd */
	talloc_set_destructor(el, _event_list_free);

	el->pub.tl = fr_timer_list_lst_alloc(el, NULL);
	if (!el->pub.tl) {
		fr_strerror_const("Failed allocating timer list");
	error:
		talloc_free(el);
		return NULL;
	}

	el->fds = fr_rb_inline_talloc_alloc(el, fr_event_fd_t, node, fr_event_fd_cmp, NULL);
	if (!el->fds) {
		fr_strerror_const("Failed allocating FD tree");
		goto error;
	}

	el->kq = kqueue();
	if (el->kq < 0) {
		fr_strerror_printf("Failed allocating kqueue: %s", fr_syserror(errno));
		goto error;
	}

	fr_dlist_talloc_init(&el->pre_callbacks, fr_event_pre_t, entry);
	fr_dlist_talloc_init(&el->post_callbacks, fr_event_post_t, entry);
	fr_dlist_talloc_init(&el->pid_to_reap, fr_event_pid_reap_t, entry);
	fr_dlist_talloc_init(&el->fd_to_free, fr_event_fd_t, entry);
	if (status) (void) fr_event_pre_insert(el, status, status_uctx);

	/*
	 *	Set our "exit" callback as ident 0.
	 */
	EV_SET(&kev, 0, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_FFNOP, 0, NULL);
	if (kevent(el->kq, &kev, 1, NULL, 0, NULL) < 0) {
		fr_strerror_printf("Failed adding exit callback to kqueue: %s", fr_syserror(errno));
		goto error;
	}

	return el;
}

/** Return whether the event loop has any active events
 *
 */
bool fr_event_list_empty(fr_event_list_t *el)
{
	return fr_time_eq(fr_timer_list_when(el->pub.tl), fr_time_wrap(0)) && (fr_rb_num_elements(el->fds) == 0);
}
#ifdef TESTING
/*
 *  cc -g -I .. -c rb.c -o rbtree.o && cc -g -I .. -c isaac.c -o isaac.o && cc -DTESTING -I .. -c event.c  -o event_mine.o && cc event_mine.o rbtree.o isaac.o -o event
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

		fr_timer_at(NULL, el, array[i], false, print_time, array[i]);
	}

	while (fr_event_list_num_timers(el)) {
		now = el->time();
		when = now;
		if (!fr_timer_run(el, &when)) {
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
