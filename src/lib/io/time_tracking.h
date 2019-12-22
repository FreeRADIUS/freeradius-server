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

/**
 * $Id$
 *
 * @file lib/io/time_tracking.h
 * @brief Request time tracking
 *
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(time_tracking_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/util/time.h>

typedef enum {
	FR_TIME_TRACKING_STOPPED = 0,				//!< Time tracking is not running.
	FR_TIME_TRACKING_RUNNING,				//!< We're currently tracking time in the
								///< running state.
	FR_TIME_TRACKING_YIELDED				//!< We're currently tracking time in the
								///< yielded state.
} fr_time_tracking_state_t;

/** A structure to track the time spent processing a request.
 *
 * The same structure is used by threads to track when they are
 * running / waiting.  The functions modifying fr_time_tracking_t all
 * take an explicit "when" parameter.  This parameter allows the
 * thread to update a requests tracking structure, and then use that
 * same fr_time_t to update the threads tracking structure.
 *
 * While fr_time() is fast, it is also called very often.  We should
 * therefore be careful to call it only when necessary.
 */
typedef struct fr_time_tracking_s fr_time_tracking_t;
struct fr_time_tracking_s {
	fr_time_tracking_state_t	state;			//!< What state we're currently in.
								///< only used for the leaf node.
	fr_time_t			last_changed;		//!< last time we changed a field

	fr_time_t			started;		//!< Last time this tracked entity or a child
								///< entered the running state, or entered
								///< a time tracked parent.

	fr_time_t			last_yielded;		//!< Last time this tracked entity or a child
								///< yielded.

	fr_time_t			last_resumed;		//!< Last time this tracked entity or a child
								///< resumed;

	fr_time_t			ended;			//!< Last time this tracked entity or a child
								///< left the running state, or popped a time
								///< tracked parent.

	fr_time_delta_t			running_total;		//!< total time spent running
	fr_time_delta_t			waiting_total;		//!< total time spent waiting

	fr_time_tracking_t		*parent;		//!< To update with our time tracking data when
								///< tracking is complete.
};

/** We use a monotonic time source
 *
 */
#define ASSERT_ON_TIME_TRAVEL(_tt, _now) \
do { \
	rad_assert((_tt)->last_changed <= (_now)); \
	rad_assert((_tt)->started <= (_now)); \
	rad_assert((_tt)->ended <= (_now)); \
	rad_assert((_tt)->last_yielded <= (_now)); \
	rad_assert((_tt)->last_resumed <= (_now)); \
} while(0);

/** Set the last time a tracked entity started in its list of parents
 *
 */
#define UPDATE_PARENT_START_TIME(_tt, _now) \
do { \
	fr_time_tracking_t	*_parent; \
	for (_parent = (_tt)->parent; _parent; _parent = _parent->parent) { \
		_parent->started = _now; \
		_parent->last_changed = _now; \
	} \
} while (0)

/** Update total run time up the list of parents
 *
 */
#define UPDATE_PARENT_RUN_TIME(_tt, _run_time, _event, _now) \
do { \
	fr_time_tracking_t	*_parent; \
	for (_parent = (_tt)->parent; _parent; _parent = _parent->parent) { \
		_parent->_event = _now; \
		_parent->last_changed = _now; \
		_parent->running_total += _run_time; \
	} \
} while (0)

/** Update total wait time up the list of parents
 *
 */
#define UPDATE_PARENT_WAIT_TIME(_tt, _wait_time, _event, _now) \
do { \
	fr_time_tracking_t	*_parent; \
	for (_parent = (_tt)->parent; _parent; _parent = _parent->parent){ \
		_parent->_event = _now; \
		_parent->last_changed = _now; \
		_parent->waiting_total += _wait_time; \
	} \
} while (0)

/** Initialise a time tracking structure
 *
 */
static inline CC_HINT(nonnull) void fr_time_tracking_init(fr_time_tracking_t *tt)
{
	memset(tt, 0, sizeof(*tt));
}

/** Start time tracking for a tracked entity
 *
 * Should be called when the tracked entity starts running.
 *
 * @param[in] parent		to update when time tracking ends.
 * @param[in] tt		the time tracked entity.
 * @param[in] now		the current time.
 */
static inline CC_HINT(nonnull) void fr_time_tracking_start(fr_time_tracking_t *parent,
							   fr_time_tracking_t *tt, fr_time_t now)
{
	rad_assert(tt->state == FR_TIME_TRACKING_STOPPED);
	rad_assert(!tt->parent);

	ASSERT_ON_TIME_TRAVEL(tt, now);

	tt->state = FR_TIME_TRACKING_RUNNING;
	tt->started = tt->last_changed = tt->last_resumed = now;

	tt->parent = parent;

	UPDATE_PARENT_START_TIME(tt, now);
}

/** Tracked entity entered a deeper time tracked code area
 *
 * @param[in] parent	we entered.  Must be a direct descendent of the
 *      		current tt->parent.
 * @param[in] tt	the time tracked entity.
 * @param[in] now	the current time.
 */
static inline CC_HINT(nonnull) void fr_time_tracking_push(fr_time_tracking_t *parent,
							  fr_time_tracking_t *tt, fr_time_t now)
{
	fr_time_delta_t		run_time;

	rad_assert(parent->parent = tt->parent);

	rad_assert(tt->state == FR_TIME_TRACKING_RUNNING);
	run_time = now - tt->last_changed;
	tt->last_changed = parent->started = now;

	UPDATE_PARENT_RUN_TIME(tt, run_time, last_changed, now);

	tt->parent = parent;
}

/** Tracked entity left a tracked nested code area
 *
 * Updates parent to point to the current time tracking parent.
 *
 * @param[in] tt	the time tracked entity.
 * @param[in] now	the current time.
 */
static inline CC_HINT(nonnull) void fr_time_tracking_pop(fr_time_tracking_t *tt, fr_time_t now)
{
	fr_time_delta_t		run_time;

	rad_assert(tt->state == FR_TIME_TRACKING_RUNNING);
	run_time = now - tt->last_changed;
	tt->last_changed = tt->parent->ended = now;

	tt->running_total += run_time;
	UPDATE_PARENT_RUN_TIME(tt, run_time, last_changed, now);

	tt->parent = tt->parent->parent;
}

/** Transition to the yielded state, recording the time we just spent running
 *
 * @param[in] tt	the time tracked entity.
 * @param[in] now	the current time.
 */
static inline CC_HINT(nonnull) void fr_time_tracking_yield(fr_time_tracking_t *tt, fr_time_t now)
{
	fr_time_delta_t		run_time;

	ASSERT_ON_TIME_TRAVEL(tt, now);

	rad_assert(tt->state == FR_TIME_TRACKING_RUNNING);
	tt->state = FR_TIME_TRACKING_YIELDED;
	tt->last_yielded = tt->last_changed = now;

	run_time = now - tt->last_resumed;
	tt->running_total += run_time;
	UPDATE_PARENT_RUN_TIME(tt, run_time, last_yielded, now);
}

/** Track that a request resumed.
 *
 * @param[in] tt	the time tracked entity.
 * @param[in] now	the current time.
 */
static inline CC_HINT(nonnull) void fr_time_tracking_resume(fr_time_tracking_t *tt, fr_time_t now)
{
	fr_time_delta_t		wait_time;

	ASSERT_ON_TIME_TRAVEL(tt, now);

	rad_assert(tt->state == FR_TIME_TRACKING_YIELDED);
	tt->state = FR_TIME_TRACKING_RUNNING;
	tt->last_resumed = tt->last_changed = now;

	wait_time = now - tt->last_yielded;
	tt->waiting_total += wait_time;
	UPDATE_PARENT_WAIT_TIME(tt, wait_time, last_resumed, now);
}

#define IALPHA (8)
#define RTT(_old, _new) ((_new + ((IALPHA - 1) * _old)) / IALPHA)

/** End time tracking for this entity
 *
 * @param[in,out] predicted	Update our prediction of how long requests should run for.
 * @param[in] tt		the time tracking structure.
 * @param[in] now		the current time.
 */
static inline void fr_time_tracking_end(fr_time_delta_t *predicted,
					fr_time_tracking_t *tt, fr_time_t now)
{
	fr_time_delta_t		run_time;

	rad_assert(tt->state == FR_TIME_TRACKING_RUNNING);
	ASSERT_ON_TIME_TRAVEL(tt, now);

	tt->state = FR_TIME_TRACKING_STOPPED;
	tt->ended = tt->last_changed = now;

	run_time = now - tt->last_resumed;
	tt->running_total += run_time;
	UPDATE_PARENT_RUN_TIME(tt, run_time, ended, now);

	if (predicted) *predicted = !(*predicted) ? tt->running_total : RTT((*predicted), tt->running_total);

	tt->parent = NULL;
}

/** Print debug information about the time tracking structure
 *
 * @param[in] tt the time tracking structure
 * @param[in] fp the file where the debug output is printed.
 */
static inline CC_HINT(nonnull) void fr_time_tracking_debug(fr_time_tracking_t *tt, FILE *fp)
{
#define DPRINT(_x) fprintf(fp, "\t" #_x " = %"PRIu64"\n", tt->_x);

	DPRINT(started);
	DPRINT(ended);
	DPRINT(last_changed);

	DPRINT(last_yielded);
	DPRINT(last_resumed);

	DPRINT(running_total);
	DPRINT(waiting_total);
}

#ifdef __cplusplus
}
#endif
