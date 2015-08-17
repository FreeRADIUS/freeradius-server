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

#define MAX_REDIS_COMMAND_LEN		4096
#define MAX_REDIS_ARGS			16

#define REDIS_ERROR_MOVED_STR		"MOVED"
#define REDIS_ERROR_ASK_STR		"ASK"
#define REDIS_ERROR_TRY_AGAIN_STR	"TRYAGAIN"
#define REDIS_ERROR_NO_SCRIPT_STR	"NOSCRIPT"
#define REDIS_DEFAULT_PORT		6379

/** Wrap freeReplyObject so we consistently check for NULL pointers
 *
 * Older versions such as 0.10 (which ship with Ubuntu <= 14.10)
 * don't check for NULL pointer before attempting to free, so we
 * get a NULL pointer dereference in some cases.
 *
 * Rather than go back through the many calls to freeReplyObject
 * and attempt to determine code paths that may result in it being
 * called on a NULL pointer, we use this to always check.
 */
#define fr_redis_reply_free(_p) if (_p) freeReplyObject(_p)

extern const FR_NAME_NUMBER redis_reply_types[];
extern const FR_NAME_NUMBER redis_rcodes[];

/** Codes are ordered inversely by priority
 *
 * To simplify handling the return codes from pipelined commands,
 * the lowest status code, and the reply which accompanies it should
 * be returned to the redis cluster code.
 */
typedef enum {
	REDIS_RCODE_SUCCESS = 0,		//!< Operation was successfull.
	REDIS_RCODE_ERROR = -1,			//!< Unrecoverable library/server error.
	REDIS_RCODE_TRY_AGAIN = -2,		//!< Try the operation again.
	REDIS_RCODE_RECONNECT = -3,		//!< Transitory error, caller should retry the operation
						//!< with a new connection.
	REDIS_RCODE_ASK = -4,			//!< Attempt operation on an alternative node.
	REDIS_RCODE_MOVE = -5,			//!< Attempt operation on an alternative node with remap.
	REDIS_RCODE_NO_SCRIPT = -6,		//!< Script doesn't exist.
} fr_redis_rcode_t;

/** Connection handle, holding a redis context
 */
typedef struct redis_conn {
	redisContext		*handle;	//!< Hiredis context used when issuing commands.
} fr_redis_conn_t;

/** Configuration parameters for a redis connection
 *
 * @note should be passed as instance data to #fr_connection_pool_module_init.
 */
typedef struct redis_common_conf {
	char const		*prefix;	//!< Logging prefix for errors in #fr_redis_cluster_conn_create.

	char const		*hostname;	//!< of Redis server.
	uint16_t		port;		//!< of Redis daemon.
	uint32_t		database;	//!< number on Redis server.

	char const		*password;	//!< to authenticate to Redis.

	uint8_t			max_nodes;	//!< Maximum number of cluster nodes to connect to.
	uint32_t		max_redirects;	//!< Maximum number of times we can be redirected.
	uint32_t		max_retries;	//!< Maximum number of times we attempt a command
						//!< when receiving successive -TRYAGAIN messages.
	uint32_t		max_alt;	//!< Maximum alternative nodes to try.
	struct timeval		retry_delay;	//!< How long to wait when we received a -TRYAGAIN
						//!< message.
} fr_redis_conf_t;

#define REDIS_COMMON_CONFIG \
	{ "server", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, fr_redis_conf_t, hostname), NULL }, \
	{ "port", FR_CONF_OFFSET(PW_TYPE_SHORT, fr_redis_conf_t, port), "6379" }, \
	{ "database", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_redis_conf_t, database), "0" }, \
	{ "password", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, fr_redis_conf_t, password), NULL }, \
	{ "max_nodes", FR_CONF_OFFSET(PW_TYPE_BYTE, fr_redis_conf_t, max_nodes), "20" }, \
	{ "max_alt", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_redis_conf_t, max_alt), "3" }, \
	{ "max_redirects", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_redis_conf_t, max_redirects), "2" }

void		fr_redis_version_print(void);

/*
 *	Command and resulting parsing
 */
fr_redis_rcode_t	fr_redis_command_status(fr_redis_conn_t *conn, redisReply *reply);

void		fr_redis_reply_print(log_lvl_t lvl, redisReply *reply, REQUEST *request, int idx);

int		fr_redis_reply_to_value_data(TALLOC_CTX *ctx, value_data_t *out, redisReply *reply,
					     PW_TYPE dst_type, DICT_ATTR const *dst_enumv);

int		fr_redis_reply_to_map(TALLOC_CTX *ctx, vp_map_t **out,
				      REQUEST *request, redisReply *key, redisReply *op, redisReply *value);

int		fr_redis_tuple_from_map(TALLOC_CTX *pool, char const *out[], size_t out_len[], vp_map_t *map);
#endif /* LIBFREERADIUS_REDIS_H */
