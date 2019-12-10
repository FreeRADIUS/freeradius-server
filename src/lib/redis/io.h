#pragma once

/*
 *   This program is is free software; you can redistribute it and/or modify
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
 * @file lib/redis/io.h
 * @brief Redis asynchronous I/O connection allocation
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Network RADIUS SARL (legal@networkradius.com)
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(redis_io_h, "$Id$")

#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/util/event.h>
#include <freeradius-devel/server/connection.h>

#include <hiredis/async.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char			*hostname;
	uint16_t		port;
	uint32_t		database;	//!< number on Redis server.

	char const		*password;	//!< to authenticate to Redis.
	fr_time_delta_t		connection_timeout;
	fr_time_delta_t		reconnection_delay;
	char const		*log_prefix;
} fr_redis_io_conf_t;

typedef struct fr_redis_handle_s fr_redis_handle_t;

fr_connection_t		*fr_redis_connection_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, fr_redis_io_conf_t const *conf);

redisAsyncContext	*fr_redis_connection_get_async_ctx(fr_connection_t *conn);

#ifdef __cplusplus
}
#endif
