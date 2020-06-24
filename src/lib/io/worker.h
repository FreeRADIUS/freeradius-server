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
 * @file io/worker.h
 * @brief Functions and data structures for worker threads.
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(worker_h, "$Id$")


#ifdef __cplusplus
extern "C" {
#endif

/**
 *  A data structure to track the worker.
 *
 *  Once spawned, workers exist until they choose to exit.
 */
typedef struct fr_worker_s fr_worker_t;

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/io/base.h>
#include <freeradius-devel/server/command.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/util/heap.h>
#include <freeradius-devel/util/log.h>

#include <talloc.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif
extern fr_cmd_table_t cmd_worker_table[];

typedef struct {
	int		max_requests;		//!< max requests this worker will handlex

	int		max_channels;		//!< maximum number of channels

	int             message_set_size;	//!< default start number of messages
	int             ring_buffer_size;	//!< default start size for the ring buffers

	fr_time_delta_t	max_request_time;	//!< maximum time a request can be processed

	size_t		talloc_pool_size;	//!< for each request
} fr_worker_config_t;

fr_worker_t	*fr_worker_create(TALLOC_CTX *ctx, fr_event_list_t *el, char const *name,
				  fr_log_t const *logger, fr_log_lvl_t lvl, fr_worker_config_t *config) CC_HINT(nonnull(2,3,4));

void		fr_worker_destroy(fr_worker_t *worker) CC_HINT(nonnull);

void		fr_worker(fr_worker_t *worker) CC_HINT(nonnull);

void		fr_worker_debug(fr_worker_t *worker, FILE *fp) CC_HINT(nonnull);

int		fr_worker_pre_event(void *uctx, fr_time_t wake);

void		fr_worker_post_event(fr_event_list_t *el, fr_time_t now, void *uctx);

fr_channel_t	*fr_worker_channel_create(fr_worker_t *worker, TALLOC_CTX *ctx, fr_control_t *master) CC_HINT(nonnull);

int		fr_worker_stats(fr_worker_t const *worker, int num, uint64_t *stats) CC_HINT(nonnull);

int		fr_worker_request_add(REQUEST *request, module_method_t process, void *ctx);

#ifdef __cplusplus
}
#endif
