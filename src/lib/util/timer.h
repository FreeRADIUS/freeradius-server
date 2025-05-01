#pragma once

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Timer lists with event callbacks
 *
 * @file src/lib/util/event.h
 *
 * @copyright 2025 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(timer_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/time.h>
#include <freeradius-devel/util/talloc.h>

/*
 *	Allow public and private versions of the same structures
 */
#ifdef _CONST
#  error _CONST can only be defined in the local header
#endif
#ifndef _TIMER_PRIVATE
typedef struct fr_timer_list_pub_s fr_timer_list_t;
#  define _CONST const
#else
#  define _CONST
#endif

/** Alternative time source, useful for testing
 *
 * @return the current time in nanoseconds past the epoch.
 */
typedef fr_time_t (*fr_event_time_source_t)(void);

/** Public event timer list structure
 *
 * Make the current list time, and time source available, but nothing else.
 *
 * This allows us to access these values without the cost of a function call.
 */
struct fr_timer_list_pub_s {
	fr_event_time_source_t _CONST time;	//!< Time source this list uses to get the current time
						///< when calculating deltas (fr_timer_in).
};

/** An opaque timer handle
 */
typedef struct fr_timer_s fr_timer_t;

/** Called when a timer event fires
 *
 * @param[in] tl	timer list event was inserted into.
 * @param[in] now	The current time.
 * @param[in] uctx	User ctx passed to #fr_timer_in or #fr_timer_at.
 */
typedef	void (*fr_timer_cb_t)(fr_timer_list_t *tl, fr_time_t now, void *uctx);

int			_fr_timer_at(NDEBUG_LOCATION_ARGS
				     TALLOC_CTX *ctx, fr_timer_list_t *tl, fr_timer_t **ev,
				     fr_time_t when, bool free_on_fire, fr_timer_cb_t callback, void const *uctx)
				     CC_HINT(nonnull(NDEBUG_LOCATION_NONNULL(2), NDEBUG_LOCATION_NONNULL(3), NDEBUG_LOCATION_NONNULL(6)));
#define			fr_timer_at(...) _fr_timer_at(NDEBUG_LOCATION_EXP __VA_ARGS__)

int			_fr_timer_in(NDEBUG_LOCATION_ARGS
				     TALLOC_CTX *ctx, fr_timer_list_t *tl, fr_timer_t **ev,
				     fr_time_delta_t delta, bool free_on_fire, fr_timer_cb_t callback, void const *uctx)
				     CC_HINT(nonnull(NDEBUG_LOCATION_NONNULL(2), NDEBUG_LOCATION_NONNULL(3), NDEBUG_LOCATION_NONNULL(6)));
#define			fr_timer_in(...) _fr_timer_in(NDEBUG_LOCATION_EXP __VA_ARGS__)

int			fr_timer_disarm(fr_timer_t *ev);			/* disarms but does not free */

#define			FR_TIMER_DISARM(_ev) \
			do { \
				if (likely((_ev) != NULL) && unlikely(fr_timer_disarm(_ev) < 0)) { \
					fr_assert_msg(0, "Failed to disarm timer %p", (_ev)); \
				} \
			} while (0)

#define			FR_TIMER_DISARM_RETURN(_ev) \
				if ((likely(((_ev)) != NULL) && unlikely(!fr_cond_assert_msg(fr_timer_disarm(_ev) == 0, "Failed to disarm timer %p", (_ev))))) return -1;

int			fr_timer_delete(fr_timer_t **ev_p) CC_HINT(nonnull);	/* disarms AND frees */

#define			FR_TIMER_DELETE(_ev_p) \
			do { \
				if ((likely((*(_ev_p)) != NULL) && unlikely(fr_timer_delete(_ev_p) < 0))) { \
					fr_assert_msg(0, "Failed to delete timer %p", *(_ev_p)); \
				} \
			} while (0)

#define			FR_TIMER_DELETE_RETURN(_ev_p) \
				if ((likely((*(_ev_p)) != NULL) && unlikely(!fr_cond_assert_msg(fr_timer_delete(_ev_p) == 0, "Failed to delete timer %p", *(_ev_p))))) return -1;

fr_time_t		fr_timer_when(fr_timer_t *ev) CC_HINT(nonnull);

bool			_fr_timer_armed(fr_timer_t *ev);

/* Wrapper to avoid overhead of function call on NULL */
#define			fr_timer_armed(_ev) ((_ev) && _fr_timer_armed(_ev))	/* returns true if the timer is armed */

int			fr_timer_list_force_run(fr_timer_list_t *tl) CC_HINT(nonnull);

int			fr_timer_list_run(fr_timer_list_t *tl, fr_time_t *when);

int			fr_timer_list_disarm(fr_timer_list_t *tl) CC_HINT(nonnull);

int			fr_timer_list_arm(fr_timer_list_t *tl) CC_HINT(nonnull);

uint64_t		fr_timer_list_num_events(fr_timer_list_t *tl) CC_HINT(nonnull);

fr_time_t		fr_timer_list_when(fr_timer_list_t *tl) CC_HINT(nonnull);

void			fr_timer_list_set_time_func(fr_timer_list_t *tl, fr_event_time_source_t func) CC_HINT(nonnull);

fr_timer_list_t		*fr_timer_list_lst_alloc(TALLOC_CTX *ctx, fr_timer_list_t *parent);

fr_timer_list_t		*fr_timer_list_ordered_alloc(TALLOC_CTX *ctx, fr_timer_list_t *parent);

#ifdef WITH_EVENT_DEBUG
void 			fr_timer_report(fr_timer_list_t *tl, fr_time_t now, void *uctx);
void			fr_timer_dump(fr_timer_list_t *tl);
#endif

#undef _CONST

#ifdef __cplusplus
}
#endif
