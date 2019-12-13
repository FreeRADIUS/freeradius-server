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
 * @brief Time tracking for requests
 * @file lib/util/time_tracking.c
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/io/time_tracking.h>

/** Start time tracking for a request.
 *
 * @param[in] tt the time tracking structure.
 * @param[in] when the event happened
 * @param[out] worker time tracking for the worker thread
 */
void fr_time_tracking_start(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker)
{
	memset(tt, 0, sizeof(*tt));

	tt->when = when;
	tt->start = when;
	tt->resumed = when;

	fr_dlist_init(&worker->list, fr_time_tracking_t, list.entry);
	fr_dlist_init(&(tt->list), fr_time_tracking_t, list.entry);
}


#define IALPHA (8)
#define RTT(_old, _new) ((_new + ((IALPHA - 1) * _old)) / IALPHA)

/** End time tracking for this request.
 *
 * After this call, all request processing should be finished.
 *
 * @param[in] tt the time tracking structure.
 * @param[in] when the event happened
 * @param[out] worker time tracking for the worker thread
 */
void fr_time_tracking_end(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker)
{
	tt->when = when;
	tt->end = when;
	tt->running += (tt->end - tt->resumed);

	/*
	 *	This request cannot be in any list.
	 */
	rad_assert(!fr_dlist_entry_in_list(&tt->list.entry));

	/*
	 *	Update the time that the worker spent processing the request.
	 */
	worker->running += tt->running;
	worker->waiting += tt->waiting;

	if (!worker->predicted) {
		worker->predicted = tt->running;
	} else {
		worker->predicted = RTT(worker->predicted, tt->running);
	}
}


/** Track that a request yielded.
 *
 * @param[in] tt the time tracking structure.
 * @param[in] when the event happened
 * @param[out] worker time tracking for the worker thread
 */
void fr_time_tracking_yield(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker)
{
	tt->when = when;
	tt->yielded = when;

	rad_assert(tt->resumed <= tt->yielded);
	tt->running += (tt->yielded - tt->resumed);

	/*
	 *	Insert this request into the TAIL of the worker's list
	 *	of waiting requests.
	 */
	fr_dlist_insert_head(&worker->list, tt);
}


/** Track that a request resumed.
 *
 * @param[in] tt the time tracking structure.
 * @param[in] when the event happened
 * @param[out] worker time tracking for the worker thread
 */
void fr_time_tracking_resume(fr_time_tracking_t *tt, fr_time_t when, fr_time_tracking_t *worker)
{
	tt->when = when;
	tt->resumed = when;

	rad_assert(tt->resumed >= tt->yielded);

	tt->waiting += (tt->resumed - tt->yielded);

	/*
	 *	Remove this request into the workers list of waiting
	 *	requests.
	 */
	fr_dlist_remove(&worker->list, tt);
}


/** Print debug information about the time tracking structure
 *
 * @param[in] tt the time tracking structure
 * @param[in] fp the file where the debug output is printed.
 */
void fr_time_tracking_debug(fr_time_tracking_t *tt, FILE *fp)
{
#define DPRINT(_x) fprintf(fp, "\t" #_x " = %"PRIu64"\n", tt->_x);

	DPRINT(start);
	DPRINT(end);
	DPRINT(when);

	DPRINT(yielded);
	DPRINT(resumed);

	DPRINT(predicted);
	DPRINT(running);
	DPRINT(waiting);
}
