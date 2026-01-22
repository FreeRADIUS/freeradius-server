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

/** Various types of event timer list
 *
 * @file src/lib/util/timer.c
 *
 * @copyright 2025 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

#define _TIMER_PRIVATE 1
typedef struct fr_timer_list_s fr_timer_list_t;

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/lst.h>
#include <freeradius-devel/util/rb.h>

FR_DLIST_TYPES(timer)
FR_DLIST_TYPEDEFS(timer, fr_timer_head_t, fr_timer_entry_t)

/** What type of event list the timer is inserted into
 *
 */
typedef enum {
	TIMER_LIST_TYPE_LST = 1,			//!< Self-sorting timer list based on a left leaning skeleton tree.
	TIMER_LIST_TYPE_ORDERED = 2,			//!< Strictly ordered list of events in a dlist.
	TIMER_LIST_TYPE_SHARED = 3			//!< all events share one event callback
} timer_list_type_t;

/** An event timer list
 *
 */
struct fr_timer_list_s {
	struct fr_timer_list_pub_s	pub;		//!< Public interface to the event timer list.

	union {
		fr_lst_t		*lst;			//!< of timer events to be executed.
		timer_head_t		ordered;		//!< A list of timer events to be executed.
		struct {
			fr_rb_tree_t   		*rb;		//!< a tree of raw pointers
			fr_rb_tree_t   		*deferred;     	//!< a tree of deferred things
			size_t			time_offset;   	//!< offset from uctx to the fr_time_t it contains
			size_t			node_offset;   	//!< offset from uctx to the fr_rb_node it contains
			fr_timer_cb_t		callback;	//!< the callback to run
		} shared;
	};
	timer_list_type_t		type;
	bool				in_handler;	//!< Whether we're currently in a callback.
	bool				disarmed;	//!< the entire timer list is disarmed

	timer_head_t	   	deferred;		//!< A list of timer events to be inserted, after
							///< the current batch has been processed.
							///< This prevents "busy" timer loops, where
							///< other events may starve, or we may never exit.

	fr_timer_list_t		*parent;		//!< Parent list to insert event into (if any).
	fr_timer_t		*parent_ev;		//!< Event in the parent's event loop.

#ifdef WITH_EVENT_DEBUG
	fr_timer_t		*report;		//!< Used to trigger periodic reports about the event timer list.
#endif
};

/** A timer event
 *
 */
struct fr_timer_s {
	fr_time_t		when;			//!< When this timer should fire.

	fr_timer_cb_t		callback;		//!< Callback to execute when the timer fires.
	void const		*uctx;			//!< Context pointer to pass to the callback.

	TALLOC_CTX		*linked_ctx;		//!< talloc ctx this event was bound to.

	fr_timer_t 		**parent;		//!< A pointer to the parent structure containing the timer
							///< event.

	fr_timer_entry_t  	entry;			//!< Entry in a list of timer events.
	union {
		fr_dlist_t		ordered_entry;		//!< Entry in an ordered list of timer events.
		fr_lst_index_t		lst_idx;	     	//!< Where to store opaque lst data, not used for ordered lists.
	};
	bool			free_on_fire;		//!< Whether to free the event when it fires.

	fr_timer_list_t   	*tl;			//!< The event list this timer is part of.
							///< This is set to NULL when an event is disarmed,
							///< but all other fields are left intact.

#ifndef NDEBUG
	char const		*file;			//!< Source file this event was last updated in.
	int			line;			//!< Line this event was last updated on.
#endif
};

FR_DLIST_FUNCS(timer, fr_timer_t, entry)

#define CHECK_PARENT(_ev) \
	fr_assert_msg(!(_ev)->parent || (*(_ev)->parent == ev), \
		      "Event %p, allocd %s[%d], parent field points to %p", (_ev), (_ev)->file, (_ev)->line, *(_ev)->parent);

#define TIMER_UCTX_TO_TIME(_tl, _x) ((fr_time_t *)(((uintptr_t) (_x)) + (_tl)->shared.time_offset))

/** Specialisation function to insert a timer
 *
 * @param[in] tl	Timer list to insert into.
 * @param[in] ev	Timer event to insert.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*timer_insert_t)(fr_timer_list_t *tl, fr_timer_t *ev);

/** Specialisation function to delete a timer
 *
 * @param[in] ev	Timer event to delete.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*timer_disarm_t)(fr_timer_t *ev);

/** Specialisation function to execute any pending timers
 *
 * @param[in] tl	Timer list to execute.
 * @param[in,out] when	Our current time, updated to the next event time (i.e. the next time we'll need to run something)
 * @return
 *	- 0 no timer events fired.
 *	- 1 a timer event fired.
 */
typedef int (*timer_list_run_t)(fr_timer_list_t *tl, fr_time_t *when);

/** Return the soonest timer event
 *
 * @param[in] tl	to get the head of.
 * @return
 *	- The head of the list.
 *	- NULL if the list is empty.
 */
typedef fr_timer_t *(*timer_list_head_t)(fr_timer_list_t *tl);

/** Process any deferred timer events
 *
 * @param[in] tl	to process deferred events for.
 * @return
 *	- The head of the list.
 *	- NULL if the list is empty.
 */
typedef int (*timer_list_deferred_t)(fr_timer_list_t *tl);

/** Return the number of elements in the list
 *
 * @param[in] tl	to get the number of elements from.
 * @return
 *	- The number of elements in the list.
 */
typedef uint64_t (*timer_list_num_elements_t)(fr_timer_list_t *tl);

typedef struct {
	timer_insert_t			insert;		//!< Function to insert a timer event.
	timer_disarm_t			disarm;		//!< Function to delete a timer event.

	timer_list_run_t		run;		//!< Function to run a timer event.
	timer_list_head_t		head;		//!< Function to get the head of the list.
	timer_list_deferred_t		deferred;	//!< Function to process deferred events.
	timer_list_num_elements_t	num_events;	//!< Function to get the number of elements in the list.
} timer_list_funcs_t;

#define EVENT_ARMED(_ev) ((_ev)->tl != NULL)

static fr_time_t *timer_list_when(fr_timer_list_t *tl);

static int timer_lst_insert_at(fr_timer_list_t *tl, fr_timer_t *ev);
static int timer_ordered_insert_at(fr_timer_list_t *tl, fr_timer_t *ev);

static int timer_lst_disarm(fr_timer_t *ev);
static int timer_ordered_disarm(fr_timer_t *ev);

static int timer_list_lst_run(fr_timer_list_t *tl, fr_time_t *when);
static int timer_list_ordered_run(fr_timer_list_t *tl, fr_time_t *when)
;static int timer_list_shared_run(fr_timer_list_t *tl, fr_time_t *when);

static fr_timer_t *timer_list_lst_head(fr_timer_list_t *tl);
static fr_timer_t *timer_list_ordered_head(fr_timer_list_t *tl);

static int timer_list_lst_deferred(fr_timer_list_t *tl);
static int timer_list_ordered_deferred(fr_timer_list_t *tl);
static int timer_list_shared_deferred(fr_timer_list_t *tl);

static uint64_t timer_list_lst_num_events(fr_timer_list_t *tl);
static uint64_t timer_list_ordered_num_events(fr_timer_list_t *tl);
static uint64_t timer_list_shared_num_events(fr_timer_list_t *tl);

/** Functions for performing operations on various types of timer list
 *
 */
static timer_list_funcs_t const timer_funcs[] = {
	[TIMER_LIST_TYPE_LST] = {
		.insert = timer_lst_insert_at,
		.disarm = timer_lst_disarm,

		.run = timer_list_lst_run,
		.head = timer_list_lst_head,
		.deferred = timer_list_lst_deferred,
		.num_events = timer_list_lst_num_events
	},
	[TIMER_LIST_TYPE_ORDERED] = {
		.insert = timer_ordered_insert_at,
		.disarm = timer_ordered_disarm,

		.run = timer_list_ordered_run,
		.head = timer_list_ordered_head,
		.deferred = timer_list_ordered_deferred,
		.num_events = timer_list_ordered_num_events
	},
	[TIMER_LIST_TYPE_SHARED] = {
//		.insert = timer_shared_insert_at,
//		.disarm = timer_shared_disarm,

		.run = timer_list_shared_run,
//		.head = timer_list_shared_head,
		.deferred = timer_list_shared_deferred,
		.num_events = timer_list_shared_num_events
	},
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
static int8_t timer_cmp(void const *a, void const *b)
{
	fr_timer_t const *ev_a = a, *ev_b = b;

	return fr_time_cmp(ev_a->when, ev_b->when);
}


/** This callback fires in the parent to execute events in this sublist
 *
 * @param[in] parent_tl	Parent event timer list.
 * @param[in] when		When the parent timer fired.
 * @param[in] uctx		Sublist to execute.
 */
static void _parent_timer_cb(UNUSED fr_timer_list_t *parent_tl, fr_time_t when, void *uctx)
{
	fr_timer_list_t *tl = talloc_get_type_abort(uctx, fr_timer_list_t);

	fr_assert(!tl->disarmed);

	/*
	 *	We're in the parent timer, so we need to run the
	 *	events in the child timer list.
	 */
	(void)fr_timer_list_run(tl, &when);
}

/** Utility function to update parent timers
 *
 * @param[in] tl	to update parent timers for.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(always_inline) int timer_list_parent_update(fr_timer_list_t *tl)
{
	fr_time_t *when;

	if (!tl->parent) return 0;

	when = timer_list_when(tl);

	/*
	 *	No events, disarm the timer
	 */
	if (!when) {
		/*
		 *	Disables the timer in the parent, does not free the memory
		 */
		if (tl->parent) FR_TIMER_DISARM_RETURN(tl->parent_ev);
		return 0;
	}

	/*
	 *	We have an active event, we can suppress changes which have no effect.
	 */
	if (tl->parent_ev && EVENT_ARMED(tl->parent_ev)) {
		fr_assert(!tl->disarmed); /* fr_timer_list_disarm() must disarm it */

		if (fr_time_eq(*when, tl->parent_ev->when)) {
			return 0;
		}
	}

	/*
	 *	This is a child list which is disabled.  Don't update the parent.
	 */
	if (tl->disarmed) {
		fr_assert(tl->parent);

		fr_assert(!tl->parent_ev || !EVENT_ARMED(tl->parent_ev));
		return 0;
	}

	/*
	 *	The list is armed and the head has changed, so we change the event in the parent list.
	 */
	if (fr_timer_at(tl, tl->parent, &tl->parent_ev,
		       *when, false, _parent_timer_cb, tl) < 0) return -1;

	return 0;
}

/** Insert a timer event into a single event timer list
 *
 * @param[in] tl	to insert the event into.
 * @param[in] ev	to insert.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int timer_lst_insert_at(fr_timer_list_t *tl, fr_timer_t *ev)
{
	if (unlikely(fr_lst_insert(tl->lst, ev) < 0)) {
		fr_strerror_const_push("Failed inserting timer into lst");
		return -1;
	}

	return 0;
}

/** Insert an event into an ordered timer list
 *
 * Timer must be in order, i.e. either before first event, or after last event
 *
 * @param[in] tl	to insert the event into.
 * @param[in] ev	to insert.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int timer_ordered_insert_at(fr_timer_list_t *tl, fr_timer_t *ev)
{
	fr_timer_t	*tail;

	tail = timer_tail(&tl->ordered);
	if (tail && fr_time_lt(ev->when, tail->when)) {
		fr_strerror_const("Event being inserted must occurr _after_ the last event");
		return -1;
	}

	if (unlikely(timer_insert_tail(&tl->ordered, ev) < 0)) {
		fr_strerror_const_push("Failed inserting timer into ordered list");
		return -1;
	}

	return 0;
}

/** Remove an event from the event loop
 *
 * @param[in] ev	to free.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _timer_free(fr_timer_t *ev)
{
	fr_timer_t	**ev_p;
	int		ret;

	ret = fr_timer_disarm(ev);	/* Is a noop if ev->tl == NULL */
	if (ret < 0) return ret;

	CHECK_PARENT(ev);
	ev_p = ev->parent;
	*ev_p = NULL;

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
 * @param[in] tl		to insert event into.
 * @param[in,out] ev_p		If not NULL modify this event instead of creating a new one.  This is a parent
 *				in a temporal sense, not in a memory structure or dependency sense.
 * @param[in] when		we should run the event.
 * @param[in] free_on_fire	Whether event memory should be freed if the event fires.
 * @param[in] callback		function to execute if the event fires.
 * @param[in] uctx		user data to pass to the event.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int _fr_timer_at(NDEBUG_LOCATION_ARGS
		 TALLOC_CTX *ctx, fr_timer_list_t *tl, fr_timer_t **ev_p,
		 fr_time_t when,
		 bool free_on_fire, fr_timer_cb_t callback, void const *uctx)
{
	fr_timer_t *ev;

	fr_assert(tl->type != TIMER_LIST_TYPE_SHARED);

	/*
	 *	If there is an event, reuse it instead of freeing it
	 *	and allocating a new one.  This is to reduce memory
	 *	churn for repeat events.
	 */
	if (!*ev_p) {
	new_event:
		ev = talloc_zero(tl, fr_timer_t);
		if (unlikely(!ev)) {
			fr_strerror_const("Out of memory");
			return -1;
		}

		EVENT_DEBUG("%p - " NDEBUG_LOCATION_FMT "Added new timer %p", tl, NDEBUG_LOCATION_VALS ev);
		/*
		 *	Bind the lifetime of the event to the specified
		 *	talloc ctx.  If the talloc ctx is freed, the
		 *	event will also be freed.
		 */
		if (ctx != tl) talloc_link_ctx(ctx, ev);

		talloc_set_destructor(ev, _timer_free);
	} else {
		ev = talloc_get_type_abort(UNCONST(fr_timer_t *, *ev_p), fr_timer_t);

		EVENT_DEBUG("%p - " NDEBUG_LOCATION_FMT "Re-armed timer %p", tl, NDEBUG_LOCATION_VALS ev);

		/*
		 *	We can't disarm the linking context due to
		 *	limitations in talloc, so if the linking
		 *	context changes, we need to free the old
		 *	event, and allocate a new one.
		 *
		 *	Freeing the event also removes it from the lst.
		 */
		if (unlikely(ev->linked_ctx != ctx)) {
			talloc_free(ev);
			goto new_event;
		}

		/*
		 *	If the event is associated with a list, we need
		 *	to disarm it, before we can rearm it.
		 */
		if (EVENT_ARMED(ev)) {
			int		ret;
			char const	*err_file;
			int		err_line;

			/*
			 *	Removed event from the event list or the
			 *	deferred list.
			 */
			ret = fr_timer_disarm(ev);
#ifndef NDEBUG
			err_file = ev->file;
			err_line = ev->line;
#else
			err_file = "not-available";
			err_line = 0;
#endif

			/*
			 *	Events MUST be in the lst (or the insertion list).
			 */
			if (!fr_cond_assert_msg(ret == 0,
						"Event %p, allocd %s[%d], was not found in the event "
						"list or deferred list when re-armed: %s", ev,
						err_file, err_line, fr_strerror())) return -1;
		}
	}

	ev->tl = tl;	/* This indicates the event memory is bound to an event loop */
	ev->when = when;
	ev->free_on_fire = free_on_fire;
	ev->callback = callback;
	ev->uctx = uctx;
	ev->linked_ctx = ctx;
	ev->parent = ev_p;
#ifndef NDEBUG
	ev->file = file;
	ev->line = line;
#endif

	/*
	 *	No updating needed as the events are deferred
	 */
	if (tl->in_handler) {
		/*
		 *	...a little hacky, but we need to verify that
		 *	we're not inserting an event that's earlier
		 *	than the last event in the list for ordered
		 *	lists.
		 *
		 *	Otherwise we'd end up doing this when we tried
		 *	to move all the deferred events into the timer
		 *	list, and end up making that O(n) instead of O(1).
		 */
		if (tl->type == TIMER_LIST_TYPE_ORDERED) {
			fr_timer_t *head = timer_list_ordered_head(tl);

			if (head && fr_time_lt(ev->when, head->when)) {
				fr_strerror_const("Event being inserted must occurr _after_ the last event");

			insert_failed:
				talloc_set_destructor(ev, NULL);
				talloc_free(ev);
				*ev_p = NULL;
				return -1;
			}
		}

		if (!fr_cond_assert_msg(timer_insert_tail(&tl->deferred, ev) == 0,
					"Failed inserting event into deferred list")) {
			goto insert_failed;
		}
	} else {
		int ret;

		ret = timer_funcs[tl->type].insert(tl, ev);
		if (unlikely(ret < 0)) goto insert_failed;

		/*
		 *	We need to update the parent timer
		 *	to ensure it fires at the correct time.
		 */
		if (unlikely(timer_list_parent_update(tl) < 0)) return -1;
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
 * @param[in] ctx		to bind lifetime of the event to.
 * @param[in] tl		to insert event into.
 * @param[in,out] ev_p		If not NULL modify this event instead of creating a new one.  This is a parent
 *				in a temporal sense, not in a memory structure or dependency sense.
 * @param[in] delta		In how many nanoseconds to wait before should we execute the event.
 * @param[in] free_on_fire	Whether event memory should be freed if the event fires.
 * @param[in] callback		function to execute if the event fires.
 * @param[in] uctx		user data to pass to the event.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int _fr_timer_in(NDEBUG_LOCATION_ARGS
		 TALLOC_CTX *ctx, fr_timer_list_t *tl, fr_timer_t **ev_p,
		 fr_time_delta_t delta,
		 bool free_on_fire, fr_timer_cb_t callback, void const *uctx)
{
	return _fr_timer_at(NDEBUG_LOCATION_VALS
			    ctx, tl, ev_p, fr_time_add(tl->pub.time(), delta),
			    free_on_fire, callback, uctx);
}

static int timer_lst_disarm(fr_timer_t *ev)
{
	fr_timer_list_t *tl = ev->tl;

	if (timer_in_list(&tl->deferred,ev)) {
		(void)timer_remove(&tl->deferred, ev);
	} else {
		int		ret = fr_lst_extract(tl->lst, ev);
		char const	*err_file;
		int		err_line;

#ifndef NDEBUG
		err_file = ev->file;
		err_line = ev->line;
#else
		err_file = "not-available";
		err_line = 0;
#endif


		/*
		 *	Events MUST be in the lst (or the insertion list).
		*/
		if (!fr_cond_assert_msg(ret == 0,
					"Event %p, lst_id %u, allocd %s[%d], was not found in the event lst or "
					"insertion list when freed: %s", ev, ev->lst_idx, err_file, err_line,
					fr_strerror())) return -1;
	}

	return 0;
}

/** Remove a timer from a timer list, but don't free it
 *
 * @param[in] ev to remove.
 */
static int timer_ordered_disarm(fr_timer_t *ev)
{
	/*
	 *	Check the check is still valid (sanity check)
	 */
	(void)talloc_get_type_abort(ev, fr_timer_t);;

	/*
	 *	Already dissassociated from a list, nothing to do.
	 */
	if (!ev->tl) return 0;

	/*
	 *	This *MUST* be in a timer list if it has a non-NULL tl pointer.
	 */
	if (unlikely(!fr_cond_assert(timer_in_list(&ev->tl->ordered, ev)))) return -1;

	(void)timer_remove(&ev->tl->ordered, ev);

	return 0;
}

/** Remove an event from the event list, but don't free the memory
 *
 * @param[in] ev	to remove from the event list.
 */
int fr_timer_disarm(fr_timer_t *ev)
{
	fr_timer_list_t *tl;

	if (!ev || !EVENT_ARMED(ev)) {
		EVENT_DEBUG("Asked to disarm inactive timer %p (noop)", ev);
		return 0; /* Noop */
	}

	tl = ev->tl;

	EVENT_DEBUG("Disarming timer %p", ev);

	CHECK_PARENT(ev);

	/*
	 *	If the event is deferred, it's not in the event list proper
	 *	so just remove it, and set the tl pointer to NULL.
	 */
	if (timer_in_list(&tl->deferred,ev)) {
		(void)timer_remove(&tl->deferred, ev);
	} else {
		int ret = timer_funcs[ev->tl->type].disarm(ev);
		if (ret < 0) return ret;
	}
	ev->tl = NULL;

	return timer_list_parent_update(tl);
}

/** Delete a timer event and free its memory
 *
 * @param[in] ev_p	of the event being deleted.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_timer_delete(fr_timer_t **ev_p)
{
	fr_timer_t *ev;
	int ret;

	if (unlikely(!*ev_p)) return 0;

	ev = *ev_p;
	ret = talloc_free(ev);	/* Destructor removed event from any lists */

	/*
	 *	Don't leave a garbage pointer value
	 *	if parent is not ev_p.
	 */
	if (likely(ret == 0)) {
		*ev_p = NULL;
	} else {
		EVENT_DEBUG("Deleting timer %p failed: %s", ev, fr_strerror_peek());
	}

	return 0;
}

/** Internal timestamp representing when the timer should fire
 *
 * @return When the timestamp should fire.
 */
fr_time_t fr_timer_when(fr_timer_t *ev)
{
	if (!fr_timer_armed(ev)) return fr_time_wrap(0);
	return ev->when;
}

/** Return time delta between now and when the timer should fire
 *
 * @param[in] ev to get the time delta for.
 */
fr_time_delta_t fr_timer_remaining(fr_timer_t *ev)
{
	if (!fr_timer_armed(ev)) return fr_time_delta_wrap(0);
	return fr_time_sub(ev->tl->pub.time(), ev->when);
}

/** Check if a timer event is armed
 *
 * @param[in] ev to check.
 * @return
 *	- true if the event is armed.
 *	- false if the event is not armed.
 */
bool _fr_timer_armed(fr_timer_t *ev)
{
	return EVENT_ARMED(ev);
}

/** Run all scheduled timer events in a lst
 *
 * @param[in] tl	containing the timer events.
 * @param[in] when	Process events scheduled to run before or at this time.
 *			- Set to 0 if no more events.
 *			- Set to the next event time if there are more events.
 * @return
 *	- 0 no timer events fired.
 *	- 1 a timer event fired.
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private fr_timer_list_t trips --fsanitize=function*/
static int timer_list_lst_run(fr_timer_list_t *tl, fr_time_t *when)
{
	fr_timer_cb_t	callback;
	void		*uctx;
	fr_timer_t	*ev;
	int		fired = 0;

	while (fr_lst_num_elements(tl->lst) > 0) {
		ev = talloc_get_type_abort(fr_lst_peek(tl->lst), fr_timer_t);

		/*
		 *	See if it's time to do this one.
		 */
		if (fr_time_gt(ev->when, *when)) {
			*when = ev->when;
		done:
			return fired;
		}

		callback = ev->callback;
		memcpy(&uctx, &ev->uctx, sizeof(uctx));

		CHECK_PARENT(ev);

		/*
		 *	Disarm the event before calling it.
		 *
		 *	This leaves the memory in place,
		 *	but dissassociates it from the list.
		 *
		 *	We use the public function as it
		 *	handles more cases.
		 */
		if (!fr_cond_assert(fr_timer_disarm(ev) == 0)) return -2;
		EVENT_DEBUG("Running timer %p", ev);
		if (ev->free_on_fire) talloc_free(ev);

		callback(tl, *when, uctx);

		fired++;
	}

	*when = fr_time_wrap(0);

	goto done;
}

/** Run all scheduled events in an ordered list
 *
 * @param[in] tl	containing the timer events.
 * @param[in] when	Process events scheduled to run before or at this time.
 *			- Set to 0 if no more events.
 *			- Set to the next event time if there are more events.
 * @return
 *	- < 0 if we failed to updated the parent list.
 *	- 0 no timer events fired.
 *	- >0 number of timer event fired.
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private fr_timer_list_t trips --fsanitize=function*/
static int timer_list_ordered_run(fr_timer_list_t *tl, fr_time_t *when)
{
	fr_timer_cb_t	callback;
	void		*uctx;
	fr_timer_t	*ev;
	unsigned int	fired = 0;

	while ((ev = timer_head(&tl->ordered))) {
		(void)talloc_get_type_abort(ev, fr_timer_t);

		/*
		 *	See if it's time to do this one.
		 */
		if (fr_time_gt(ev->when, *when)) {
			*when = ev->when;
		done:
			return fired;
		}

		callback = ev->callback;
		memcpy(&uctx, &ev->uctx, sizeof(uctx));

		CHECK_PARENT(ev);

		/*
		 *	Disarm the event before calling it.
		 *
		 *	This leaves the memory in place,
		 *	but dissassociates it from the list.
		 *
		 *	We use the public function as it
		 *	handles more cases.
		 */
		if (!fr_cond_assert(fr_timer_disarm(ev) == 0)) return -2;
		EVENT_DEBUG("Running timer %p", ev);
		if (ev->free_on_fire) talloc_free(ev);

		callback(tl, *when, uctx);

		fired++;
	}

	*when = fr_time_wrap(0);

	goto done;
}

/** Run all scheduled events in an ordered list
 *
 * @param[in] tl	containing the timer events.
 * @param[in] when	Process events scheduled to run before or at this time.
 *			- Set to 0 if no more events.
 *			- Set to the next event time if there are more events.
 * @return
 *	- < 0 if we failed to updated the parent list.
 *	- 0 no timer events fired.
 *	- >0 number of timer event fired.
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private fr_timer_list_t trips --fsanitize=function*/
static int timer_list_shared_run(fr_timer_list_t *tl, fr_time_t *when)
{
	void		*uctx;
	unsigned int	fired = 0;

	while ((uctx = fr_rb_first(tl->shared.rb)) != NULL) {
		fr_time_t const *next;

		next = TIMER_UCTX_TO_TIME(tl, uctx);

		/*
		 *	See if it's time to do this one.
		 */
		if (fr_time_gt(*next, *when)) {
			*when = *next;
		done:
			return fired;
		}

		fr_rb_remove(tl->shared.rb, uctx);

		tl->shared.callback(tl, *when, uctx);

		fired++;
	}

	*when = fr_time_wrap(0);

	goto done;
}


/** Forcibly run all events in an event loop.
 *
 * This is used to forcefully run every event in the event loop.
 *
 * We pass in the real time, which may theoretically cause issues if timer
 * callbacks are checking...  But the uses of this function are very limited.
 *
 * @return
 *	- < 0 if we failed to update the parent list.
 *	- 0 no timer events fired.
 *	- > 0 number of timer event fired.
 */
int fr_timer_list_force_run(fr_timer_list_t *tl)
{
	fr_time_t when = fr_time_max();

	return fr_timer_list_run(tl, &when);
}

/** Execute any pending events in the event loop
 *
 * @param[in] tl	to execute events in.
 * @param[in] when	Process events scheduled to run before or at this time.
 *			- Set to 0 if no more events.
 *			- Set to the next event time if there are more events.
 * @return
 *	- < 0 if we failed to update the parent list.
 *	- 0 no timer events fired.
 *	- >0 number of timer event fired.
 */
int fr_timer_list_run(fr_timer_list_t *tl, fr_time_t *when)
{
	int ret;
	bool in_handler = tl->in_handler;	/* allow nested timer execution */

	tl->in_handler = true;
	ret = timer_funcs[tl->type].run(tl, when);
	tl->in_handler = in_handler;

	/*
	 *	Now we've executed all the pending events,
	 *	now merge the deferred events into the main
	 *	event list.
	 *
	 *	The events don't need to be modified as they
	 *	were initialised completely before being
	 *	placed in the deferred list.
	 */
	if (timer_num_elements(&tl->deferred) > 0) {
		if (unlikely(timer_funcs[tl->type].deferred(tl) < 0)) return -1;
		if (unlikely(timer_list_parent_update(tl) < 0)) return -1;
	/*
	 *	We ran some events, and have no deferred
	 *	events to insert, so we need to forcefully
	 *	update the parent timer.
	 */
	} else if(ret > 0) {
		if (unlikely(timer_list_parent_update(tl) < 0)) return -1;
	}

	return ret;
}

/** Return the head of the lst
 *
 * @param[in] tl	to get the head of.
 * @return
 *	- The head of the trie.
 *	- NULL, if there's no head.
 */
static fr_timer_t *timer_list_lst_head(fr_timer_list_t *tl)
{
	return fr_lst_peek(tl->lst);
}

/** Return the head of the ordered list
 *
 * @param[in] tl	to get the head of.
 * @return
 *	- The head of the trie.
 *	- NULL, if there's no head.
 */
static fr_timer_t *timer_list_ordered_head(fr_timer_list_t *tl)
{
	return timer_head(&tl->ordered);
}


/** Move all deferred events into the lst
 *
 * @param[in] tl	to move events in.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int timer_list_lst_deferred(fr_timer_list_t *tl)
{
	fr_timer_t *ev;

	while((ev = timer_pop_head(&tl->deferred))) {
		if (unlikely(timer_lst_insert_at(tl, ev)) < 0) {
			timer_insert_head(&tl->deferred, ev);	/* Don't lose track of events we failed to insert */
			return -1;
		}
	}

	return 0;
}

/** Move all deferred events into the ordered event list
 *
 * This operation is O(1).
 *
 * @param[in] tl	to move events in.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int timer_list_ordered_deferred(fr_timer_list_t *tl)
{
	fr_timer_t *ev;
#ifndef NDEBUG
	{
		fr_timer_t *head, *tail;

		head = timer_head(&tl->deferred);
		tail = timer_tail(&tl->ordered);

		/*
		*	Something has gone catastrophically wrong if the
		*	deferred event is earlier than the last event in
		*	the ordered list, given all the checks we do.
		*/
		fr_cond_assert_msg(!head || !tail || fr_time_gteq(head->when, tail->when),
				"Deferred event is earlier than the last event in the ordered list");
	}
#endif

	/*
	 *	Can't use timer_move_head as entry positions
	 *	for the two lists are different.
	 */
	while ((ev = timer_pop_head((&tl->deferred)))) {
		timer_insert_tail(&tl->ordered, ev);
	}

	return 0;
}

/** Move all deferred events into the shared list
 *
 * @param[in] tl	to move events in.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int timer_list_shared_deferred(fr_timer_list_t *tl)
{
	void *uctx;

	while((uctx = fr_rb_first(tl->shared.deferred)) != NULL) {
		fr_rb_remove_by_inline_node(tl->shared.deferred,
					    (fr_rb_node_t *) (((uintptr_t) (uctx)) + tl->shared.node_offset));

		fr_rb_insert(tl->shared.deferred, uctx);
	}

	return 0;
}

static uint64_t timer_list_lst_num_events(fr_timer_list_t *tl)
{
	return fr_lst_num_elements(tl->lst);
}

static uint64_t timer_list_ordered_num_events(fr_timer_list_t *tl)
{
	return timer_num_elements(&tl->ordered);
}

static uint64_t timer_list_shared_num_events(fr_timer_list_t *tl)
{
	return fr_rb_num_elements(tl->shared.rb);
}

/** Disarm a timer list
 *
 * @param[in] tl	Timer list to disarm
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_timer_list_disarm(fr_timer_list_t *tl)
{
	if (!tl->parent) {
		fr_strerror_const("Timer list does not have a parent");
		return -1;
	}

	tl->disarmed = true;

	FR_TIMER_DISARM_RETURN(tl->parent_ev);

	return 0;
}

/** Arm (or re-arm) a timer list
 *
 * @param[in] tl	Timer list to (re)-arm
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_timer_list_arm(fr_timer_list_t *tl)
{
	if (!tl->parent) {
		fr_strerror_const("Timer list does not have a parent");
		return -1;
	}

	if (!tl->disarmed) return 0;

	tl->disarmed = false;

	/*
	 *	Run any timer events which were missed during the time that the list was disarmed.
	 */
	_parent_timer_cb(tl->parent, fr_time(), tl);

	return timer_list_parent_update(tl);
}

/** Return number of pending events
 *
 * @note This includes deferred events, i.e. those yet to be inserted into the main list
 *
 * @param[in] tl to get the number of events from.
 * @return
 *	- The number of events in the list.
 */
uint64_t fr_timer_list_num_events(fr_timer_list_t *tl)
{
	uint64_t num = timer_funcs[tl->type].num_events(tl);

	return num + timer_num_elements(&tl->deferred);
}

static fr_time_t *timer_list_when(fr_timer_list_t *tl)
{
	fr_timer_t *ev;

	switch (tl->type) {
	default:
		ev = timer_funcs[tl->type].head(tl);
		if (ev) return &ev->when;
		break;

	case TIMER_LIST_TYPE_SHARED: {
		void *uctx;

		uctx = fr_rb_first(tl->shared.rb);
		if (!uctx) break;

		return TIMER_UCTX_TO_TIME(tl, uctx);
	}
	}

	return NULL;
}

/** Return the time of the next event
 *
 * @param[in] tl	to get the next event time from.
 * @return
 *	- >0 the time of the next event.
 *	- 0 if there are no more events.
 */
fr_time_t fr_timer_list_when(fr_timer_list_t *tl)
{
	fr_time_t const *when = timer_list_when(tl);

	if (when) return *when;

	return fr_time_wrap(0);
}

/** Override event list time source
 *
 * @param[in] tl	to set new time function for.
 * @param[in] func	to set.
 */
void fr_timer_list_set_time_func(fr_timer_list_t *tl, fr_event_time_source_t func)
{
	tl->pub.time = func;
}

/** Cleanup all timers currently in the list
 *
 * @param[in] tl	to cleanup.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _timer_list_free(fr_timer_list_t *tl)
{
	fr_timer_t *ev;

	if (unlikely(tl->in_handler)) {
		fr_strerror_const("Cannot free event timer list while in handler");
		return -1;
	}

	if (tl->parent_ev) if (unlikely(fr_timer_delete(&tl->parent_ev) < 0)) return -1;

	if (tl->type == TIMER_LIST_TYPE_SHARED) return 0;

	while ((ev = timer_funcs[tl->type].head(tl))) {
		if (talloc_free(ev) < 0) return -1;
	}

	return 0;
}

static fr_timer_list_t *timer_list_alloc(TALLOC_CTX *ctx, fr_timer_list_t *parent)
{
	fr_timer_list_t *tl;

	fr_assert(!parent || (parent->type != TIMER_LIST_TYPE_SHARED));

	tl = talloc_zero(ctx, fr_timer_list_t);
	if (unlikely(tl == NULL)) {
		fr_strerror_const("Out of memory");
		return NULL;
	}

	timer_talloc_init(&tl->deferred);
	if (parent) {
		tl->parent = parent;
		tl->pub.time = parent->pub.time;
	} else {
		tl->pub.time = fr_time;
	}
	talloc_set_destructor(tl, _timer_list_free);

	return tl;
}

/** Allocate a new lst based timer list
 *
 * @note Entries may be inserted in any order.
 *
 * @param[in] ctx	to insert head timer event into.
 * @param[in] parent	to insert the head timer event into.
 */
fr_timer_list_t *fr_timer_list_lst_alloc(TALLOC_CTX *ctx, fr_timer_list_t *parent)
{
	fr_timer_list_t *tl;

	if (unlikely((tl = timer_list_alloc(ctx, parent)) == NULL)) return NULL;

	tl->lst = fr_lst_talloc_alloc(tl, timer_cmp, fr_timer_t, lst_idx, 0);
	if (unlikely(tl->lst == NULL)) {
		fr_strerror_const("Failed allocating timer list");
		talloc_free(tl);
		return NULL;
	}
	tl->type = TIMER_LIST_TYPE_LST;

#ifdef WITH_EVENT_REPORT
	fr_timer_in(tl, tl, &tl->report, fr_time_delta_from_sec(EVENT_REPORT_FREQ), false, fr_timer_report, NULL);
#endif

	return tl;
}

/** Allocate a new sorted event timer list
 *
 * @note Entries must be inserted in the order that they will fire.
 *
 * @param[in] ctx	to allocate the event timer list from.
 * @param[in] parent	to insert the head timer event into.
 */
fr_timer_list_t *fr_timer_list_ordered_alloc(TALLOC_CTX *ctx, fr_timer_list_t *parent)
{
	fr_timer_list_t *tl;

	if (unlikely((tl = timer_list_alloc(ctx, parent)) == NULL)) return NULL;

	fr_dlist_talloc_init((fr_dlist_head_t *)&tl->ordered, fr_timer_t, ordered_entry);
	tl->type = TIMER_LIST_TYPE_ORDERED;

	return tl;
}

/** Allocate a new shared event timer list
 *
 * @param[in] ctx	to allocate the event timer list from.
 * @param[in] parent	to insert the head timer event into.
 * @param[in] cmp	comparison routine (smaller times are earlier)
 * @param[in] callback  to run on timer event
 * @param[in] node_offset offset from uctx to the fr_rb_node_t it contains
 * @param[in] time_offset offset from uctx to the fr_time_t it contains
 */
fr_timer_list_t *fr_timer_list_shared_alloc(TALLOC_CTX *ctx, fr_timer_list_t *parent, fr_cmp_t cmp,
					    fr_timer_cb_t callback, size_t node_offset, size_t time_offset)
{
	fr_timer_list_t *tl;

	if (unlikely((tl = timer_list_alloc(ctx, parent)) == NULL)) return NULL;

	tl->type = TIMER_LIST_TYPE_SHARED;

	tl->shared.time_offset = time_offset;
	tl->shared.node_offset = node_offset;
	tl->shared.callback = callback;

	tl->shared.rb = _fr_rb_alloc(tl, node_offset, NULL, cmp, NULL);
	if (!tl->shared.rb) {
		talloc_free(tl);
		return NULL;
	}

	tl->shared.deferred = _fr_rb_alloc(tl, node_offset, NULL, cmp, NULL);
	if (!tl->shared.deferred) {
		talloc_free(tl);
		return NULL;
	}

	return tl;
}

/** Insert a uctx into a shared timer, and update the timer.
 *
 * @param[in] tl	Timer list to insert into.
 * @param[in] uctx	to insert
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_timer_uctx_insert(fr_timer_list_t *tl, void *uctx)
{
	fr_assert(tl->type == TIMER_LIST_TYPE_SHARED);

	if (tl->in_handler) {
		if (!fr_rb_insert(tl->shared.deferred, uctx)) return -1;

		return 0;
	}

	if (!fr_rb_insert(tl->shared.rb, uctx)) return -1;

	return timer_list_parent_update(tl);
}

/** Remove a uctx from a shared timer
 *
 * @param[in] tl	Timer list to insert into.
 * @param[in] uctx	to remove
 * @return
 *	- 0 uctx was successfully removed.
 *	- -1 uctx was removed, but the parent timer was not updated
 */
int fr_timer_uctx_remove(fr_timer_list_t *tl, void *uctx)
{
	fr_assert(tl->type == TIMER_LIST_TYPE_SHARED);

	fr_rb_remove_by_inline_node(tl->shared.rb,
				    (fr_rb_node_t *) (((uintptr_t) (uctx)) + tl->shared.node_offset));

	return timer_list_parent_update(tl);
}

void *fr_timer_uctx_peek(fr_timer_list_t *tl)
{
	fr_assert(tl->type == TIMER_LIST_TYPE_SHARED);

	return fr_rb_first(tl->shared.rb);
}


#if defined(WITH_EVENT_DEBUG) && !defined(NDEBUG)
static const fr_time_delta_t decades[18] = {
	{ 1 }, { 10 }, { 100 },
	{ 1000 }, { 10000 }, { 100000 },
	{ 1000000 }, { 10000000 }, { 100000000 },
	{ 1000000000 }, { 10000000000 }, { 100000000000 },
	{ 1000000000000 }, { 10000000000000 }, { 100000000000000 },
	{ 1000000000000000 }, { 10000000000000000 }, { 100000000000000000 },
};

static const char *decade_names[18] = {
	"1ns", "10ns", "100ns",
	"1us", "10us", "100us",
	"1ms", "10ms", "100ms",
	"1s", "10s", "100s",
	"1Ks", "10Ks", "100Ks",
	"1Ms", "10Ms", "100Ms",	/* 1 year is 300Ms */
};

typedef struct {
	fr_rb_node_t	node;
	char const	*file;
	int		line;
	uint32_t	count;
} fr_event_counter_t;

static int8_t timer_location_cmp(void const *one, void const *two)
{
	fr_event_counter_t const	*a = one;
	fr_event_counter_t const	*b = two;

	CMP_RETURN(a, b, file);

	return CMP(a->line, b->line);
}

static int _event_report_process(fr_rb_tree_t **locations, size_t array[], fr_time_t now, fr_timer_t *ev)
{
	fr_time_delta_t diff = fr_time_sub(ev->when, now);
	size_t i;

	for (i = 0; i < NUM_ELEMENTS(decades); i++) {
		if ((fr_time_delta_cmp(diff, decades[i]) <= 0) || (i == NUM_ELEMENTS(decades) - 1)) {
			fr_event_counter_t find = { .file = ev->file, .line = ev->line };
			fr_event_counter_t *counter;

			counter = fr_rb_find(locations[i], &find);
			if (!counter) {
				counter = talloc(locations[i], fr_event_counter_t);
				if (!counter) {
					EVENT_DEBUG("Can't do report, out of memory");
					return -1;
				}
				counter->file = ev->file;
				counter->line = ev->line;
				counter->count = 1;
				fr_rb_insert(locations[i], counter);
			} else {
				counter->count++;
			}

			array[i]++;
			break;
		}
	}

	return 0;
}

/** Print out information about timer events in the event loop
 *
 */
void fr_timer_report(fr_timer_list_t *tl, fr_time_t now, void *uctx)
{
	fr_lst_iter_t		iter;
	fr_timer_t		*ev;
	size_t			i;

	size_t			array[NUM_ELEMENTS(decades)] = { 0 };
	fr_rb_tree_t		*locations[NUM_ELEMENTS(decades)];
	TALLOC_CTX		*tmp_ctx;
	static pthread_mutex_t	print_lock = PTHREAD_MUTEX_INITIALIZER;

	if (tl->type == TIMER_LIST_TYPE_SHARED) {
		EVENT_DEBUG("Cannot (yet) do timer report for TIMER_LIST_TYPE_SHARED");
		return;
	}

	tmp_ctx = talloc_init_const("temporary stats");
	if (!tmp_ctx) {
	oom:
		EVENT_DEBUG("Can't do report, out of memory");
		talloc_free(tmp_ctx);
		return;
	}

	for (i = 0; i < NUM_ELEMENTS(decades); i++) {
		locations[i] = fr_rb_inline_alloc(tmp_ctx, fr_event_counter_t, node, timer_location_cmp, NULL);
		if (!locations[i]) goto oom;
	}

	switch (tl->type) {
	case TIMER_LIST_TYPE_LST:
		/*
		 *	Show which events are due, when they're due,
		 *	and where they were allocated
		 */
		for (ev = fr_lst_iter_init(tl->lst, &iter);
		     ev != NULL;
		     ev = fr_lst_iter_next(tl->lst, &iter)) {
			if (_event_report_process(locations, array, now, ev) < 0) goto oom;
		}
		break;

	case TIMER_LIST_TYPE_ORDERED:
		/*
		 *	Show which events are due, when they're due,
		 *	and where they were allocated
		 */
		for (ev = timer_head(&tl->ordered);
		     ev != NULL;
		     ev = timer_next(&tl->ordered, ev)) {
			if (_event_report_process(locations, array, now, ev) < 0) goto oom;
		}
		break;

	case TIMER_LIST_TYPE_SHARED:
		fr_assert(0);
		return;
	}

	pthread_mutex_lock(&print_lock);
	EVENT_DEBUG("num timer events: %"PRIu64, fr_timer_list_num_events(tl));

	for (i = 0; i < NUM_ELEMENTS(decades); i++) {
		fr_rb_iter_inorder_t	event_iter;
		void			*node;

		if (!array[i]) continue;

		if (i == 0) {
			EVENT_DEBUG("    events <= %5s      : %zu", decade_names[i], array[i]);
		} else if (i == (NUM_ELEMENTS(decades) - 1)) {
			EVENT_DEBUG("    events > %5s       : %zu", decade_names[i - 1], array[i]);
		} else {
			EVENT_DEBUG("    events %5s - %5s : %zu", decade_names[i - 1], decade_names[i], array[i]);
		}

		for (node = fr_rb_iter_init_inorder(locations[i], &event_iter);
		     node;
		     node = fr_rb_iter_next_inorder(locations[i], &event_iter)) {
			fr_event_counter_t	*counter = talloc_get_type_abort(node, fr_event_counter_t);

			EVENT_DEBUG("                         : %u allocd at %s[%d]",
				    counter->count, counter->file, counter->line);
		}
	}
	pthread_mutex_unlock(&print_lock);

	fr_timer_in(tl, tl, &tl->report, fr_time_delta_from_sec(EVENT_REPORT_FREQ), false, fr_timer_report, uctx);
	talloc_free(tmp_ctx);
}

void fr_timer_dump(fr_timer_list_t *tl)
{
	fr_lst_iter_t		iter;
	fr_timer_t 		*ev;
	fr_time_t		now = tl->pub.time();	/* Get the current time */

#define TIMER_DUMP(_ev) \
	EVENT_DEBUG("%s[%d]: %p time=%" PRId64 " (%c), callback=%p", \
		    (_ev)->file, (_ev)->line, _ev, fr_time_unwrap((_ev)->when), \
		    fr_time_gt(now, (_ev)->when) ? '<' : '>', (_ev)->callback);

	EVENT_DEBUG("Time is now %"PRId64"", fr_time_unwrap(now));

	switch (tl->type) {
	case TIMER_LIST_TYPE_LST:
		EVENT_DEBUG("Dumping lst timer list");

		for (ev = fr_lst_iter_init(tl->lst, &iter);
		     ev;
		     ev = fr_lst_iter_next(tl->lst, &iter)) {
			(void)talloc_get_type_abort(ev, fr_timer_t);
			TIMER_DUMP(ev);
		}
		break;

	case TIMER_LIST_TYPE_ORDERED:
		EVENT_DEBUG("Dumping ordered timer list");

		for (ev = timer_head(&tl->ordered);
		     ev;
		     ev = timer_next(&tl->ordered, ev)) {
			(void)talloc_get_type_abort(ev, fr_timer_t);
			TIMER_DUMP(ev);
		}
		break;

	case TIMER_LIST_TYPE_SHARED:
		EVENT_DEBUG("Dumping shared timer list");

		fr_rb_inorder_foreach(tl->shared.rb, void, uctx) {
			EVENT_DEBUG("time %" PRIu64" uctx %p", fr_time_unwrap(*TIMER_UCTX_TO_TIME(tl, uctx)), uctx);
		}}
		break;
	}
}
#endif
