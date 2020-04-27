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
 * @file io/schedule.h
 * @brief Scheduler communication.
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(schedule_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_schedule_s fr_schedule_t;

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/io/channel.h>
#include <freeradius-devel/io/network.h>
#include <freeradius-devel/io/worker.h>
#include <freeradius-devel/util/log.h>

#ifdef __cplusplus
extern "C" {
#endif
/** Setup a new thread
 *
 * @param[in] ctx	to allocate any thread specific memory in.
 * @param[in] el	Event list used by the thread.
 * @param[in] uctx	User data passed to callback.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int (*fr_schedule_thread_instantiate_t)(TALLOC_CTX *ctx, fr_event_list_t *el, void *uctx);

/** Explicitly free resources allocated by #fr_schedule_thread_instantiate_t
 *
 * @param[in] uctx	User data passed to callback.
 */
typedef void (*fr_schedule_thread_detach_t)(void *uctx);

typedef struct {
	uint32_t	max_networks;		//!< number of network threads
	uint32_t	max_workers;		//!< number of network threads

	fr_time_delta_t	stats_interval;		//!< print channel statistics
} fr_schedule_config_t;

int			fr_schedule_worker_id(void);

int			fr_schedule_pthread_create(pthread_t *thread, void *(*func)(void *), void *arg);
fr_schedule_t		*fr_schedule_create(TALLOC_CTX *ctx, fr_event_list_t *el, fr_log_t *log, fr_log_lvl_t lvl,
					    fr_schedule_thread_instantiate_t worker_thread_instantiate,
					    fr_schedule_thread_detach_t worked_thread_detach,
					    fr_schedule_config_t *config) CC_HINT(nonnull(3));
/* schedulers are async, so there's no fr_schedule_run() */
int			fr_schedule_destroy(fr_schedule_t **sc);

fr_network_t		*fr_schedule_listen_add(fr_schedule_t *sc, fr_listen_t *li) CC_HINT(nonnull);
fr_network_t		*fr_schedule_directory_add(fr_schedule_t *sc, fr_listen_t *li) CC_HINT(nonnull);
#ifdef __cplusplus
}
#endif
