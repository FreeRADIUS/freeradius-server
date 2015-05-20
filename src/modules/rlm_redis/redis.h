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
 * @file redis.h
 * @brief Common functions for interacting with Redis via hiredis
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2000,2006,2015  The FreeRADIUS server project
 * @copyright 2011 TekSavvy Solutions <gabe@teksavvy.com>
 */

#ifndef LIBFREERADIUS_REDIS_H
#define	LIBFREERADIUS_REDIS_H

RCSIDH(redis_h, "$Id$")

#include <freeradius-devel/radiusd.h>
#include <hiredis/hiredis.h>

#include "config.h"

#define MAX_REDIS_COMMAND_LEN	4096
#define MAX_REDIS_ARGS		16

extern const FR_NAME_NUMBER redis_reply_types[];

/** Connection handle, holding a redis context
 */
typedef struct redis_socket {
	redisContext		*handle;	//!< hiredis context used when issuing commands.
} redis_conn_t;

/** Configuration parameters for a redis connection
 *
 * @note should be passed as instance data to #fr_connection_pool_module_init.
 */
typedef struct redis_socket_conf {
	char const		*prefix;	//!< Logging prefix for errors in #fr_redis_conn_create.
	char const		*hostname;	//!< of Redis server.
	uint16_t		port;		//!< of Redis daemon.
	uint32_t		database;	//!< number on Redis server.
	char const		*password;	//!< to authenticate to Redis.
} redis_conn_conf_t;

/*
 *	Connection pool functions
 */
void	*fr_redis_conn_create(TALLOC_CTX *ctx, void *instance);

/*
 *	Command and resulting parsing
 */
int	fr_redis_command_status(redis_conn_t *conn, redisReply *reply);

void	fr_redis_response_print(log_lvl_t lvl, redisReply *reply, REQUEST *request, int idx);

int	fr_redis_reply_to_value_data(TALLOC_CTX *ctx, value_data_t *out, redisReply *reply,
				     PW_TYPE dst_type, DICT_ATTR const *dst_enumv);

int	fr_redis_reply_to_map(TALLOC_CTX *ctx, vp_map_t **out,
			      REQUEST *request, redisReply *key, redisReply *op, redisReply *value);

int	fr_redis_tuple_from_map(TALLOC_CTX *pool, char const *out[], size_t out_len[], vp_map_t *map);

void	fr_redis_version_print(void);
