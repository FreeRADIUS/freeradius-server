#pragma once

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file lib/redis/pipeline.h
 * @brief Redis asynchronous command pipelining
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Network RADIUS SAS (legal@networkradius.com)
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(redis_pipeline_h, "$Id$")

#include <freeradius-devel/server/connection.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/server/trunk.h>
#include <freeradius-devel/redis/io.h>
#include <hiredis/async.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	FR_REDIS_PIPELINE_OK	= 0,			//!< No failure.
	FR_REDIS_PIPELINE_BAD_CMDS,			//!< Malformed command set.
	FR_REDIS_PIPELINE_DST_UNAVAILABLE,		//!< Cluster or host is down.
	FR_REDIS_PIPELINE_TOO_MANY_REDIRECTS,		//!< Redirected too many times.
	FR_REDIS_PIPELINE_FAIL				//!< Generic failure.
} fr_redis_pipeline_status_t;

typedef struct fr_redis_cluster_thread_s fr_redis_cluster_thread_t;
typedef struct fr_redis_command_s fr_redis_command_t;
typedef struct fr_redis_command_set_s fr_redis_command_set_t;
typedef struct fr_redis_trunk_s fr_redis_trunk_t;

/** Process the reply from a single command
 *
 */
typedef void (*fr_redis_command_complete_t)(request_t *request, fr_redis_command_t *cmd, redisReply *reply, void *rctx);

/** Do something meaningful with the replies to the commands previously issued
 *
 */
typedef void (*fr_redis_command_set_complete_t)(request_t *request, fr_dlist_head_t *completed, void *rctx);

/** Write a failure result to the rctx so that the module is aware that the request failed
 *
 */
typedef void (*fr_redis_command_set_fail_t)(request_t *request, fr_dlist_head_t *completed, void *rctx);

fr_redis_pipeline_status_t	fr_redis_command_preformatted_add(fr_redis_command_set_t *cmds, char const *cmd_str,
								  fr_redis_command_complete_t complete, void *rctx);

fr_redis_pipeline_status_t	fr_redis_command_argv_add(fr_redis_command_set_t *cmds, size_t argc,
							  char const **argv, size_t *argv_len,
							  fr_redis_command_complete_t complete, void *rctx);

char const			*fr_redis_command_get_cmd(fr_redis_command_t *cmd);

/*
 *	TEMPORARY
 */
fr_redis_pipeline_status_t redis_command_set_enqueue(fr_redis_trunk_t *rtrunk, fr_redis_command_set_t *cmds);

fr_redis_command_set_t		*fr_redis_command_set_alloc(TALLOC_CTX *ctx,
							    request_t *request,
							    fr_redis_command_set_complete_t complete,
							    fr_redis_command_set_fail_t fail,
							    void *rctx);

fr_redis_trunk_t		*fr_redis_trunk_alloc(fr_redis_cluster_thread_t *rtcluster,
						      fr_redis_io_conf_t const *conf);

fr_redis_cluster_thread_t	*fr_redis_cluster_thread_alloc(TALLOC_CTX *ctx, fr_event_list_t *el,
							       trunk_conf_t const *tconf);

#ifdef __cplusplus
}
#endif
