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
 * @file lib/redis/base.h
 * @brief Common functions for interacting with Redis via hiredis
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000,2006,2015 The FreeRADIUS server project
 * @copyright 2011 TekSavvy Solutions (gabe@teksavvy.com)
 */

#ifndef LIBFREERADIUS_REDIS_H
#define	LIBFREERADIUS_REDIS_H

RCSIDH(redis_h, "$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/server/module.h>

#include <hiredis/hiredis.h>

#define MAX_REDIS_COMMAND_LEN		4096
#define MAX_REDIS_ARGS			32

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
static inline void fr_redis_reply_free(redisReply **reply)
{
	if (*reply) freeReplyObject(*reply);
	*reply = NULL;
}

static inline void fr_redis_pipeline_free(redisReply *reply[], size_t num)
{
	size_t i;
	for (i = 0; i < num; i++) fr_redis_reply_free(&(reply[i]));
}

extern fr_table_num_sorted_t const redis_reply_types[];
extern size_t redis_reply_types_len;
extern fr_table_num_sorted_t const redis_rcodes[];
extern size_t redis_rcodes_len;

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
typedef struct {
	redisContext		*handle;	//!< Hiredis context used when issuing commands.
} fr_redis_conn_t;

/** Configuration parameters for a redis connection
 *
 * @note should be passed as instance data to #module_connection_pool_init.
 */
typedef struct {
	char const		**hostname;	//!< of Redis server.
	uint16_t		port;		//!< of Redis daemon.
	uint32_t		database;	//!< number on Redis server.

	char const		*password;	//!< to authenticate to Redis.

	uint8_t			max_nodes;	//!< Maximum number of cluster nodes to connect to.
	uint32_t		max_redirects;	//!< Maximum number of times we can be redirected.
	uint32_t		max_retries;	//!< Maximum number of times we attempt a command
						//!< when receiving successive -TRYAGAIN messages.
	uint32_t		max_alt;	//!< Maximum alternative nodes to try.
	fr_time_delta_t		retry_delay;	//!< How long to wait when we received a -TRYAGAIN
						//!< message.
} fr_redis_conf_t;

#define REDIS_COMMON_CONFIG \
	{ FR_CONF_OFFSET("server", FR_TYPE_STRING | FR_TYPE_REQUIRED | FR_TYPE_MULTI, fr_redis_conf_t, hostname) }, \
	{ FR_CONF_OFFSET("port", FR_TYPE_UINT16, fr_redis_conf_t, port), .dflt = "6379" }, \
	{ FR_CONF_OFFSET("database", FR_TYPE_UINT32, fr_redis_conf_t, database), .dflt = "0" }, \
	{ FR_CONF_OFFSET("password", FR_TYPE_STRING | FR_TYPE_SECRET, fr_redis_conf_t, password) }, \
	{ FR_CONF_OFFSET("max_nodes", FR_TYPE_UINT8, fr_redis_conf_t, max_nodes), .dflt = "20" }, \
	{ FR_CONF_OFFSET("max_alt", FR_TYPE_UINT32, fr_redis_conf_t, max_alt), .dflt = "3" }, \
	{ FR_CONF_OFFSET("max_redirects", FR_TYPE_UINT32, fr_redis_conf_t, max_redirects), .dflt = "2" }

void		fr_redis_version_print(void);

/*
 *	Command and resulting parsing
 */
fr_redis_rcode_t	fr_redis_command_status(fr_redis_conn_t *conn, redisReply *reply);

void			fr_redis_reply_print(fr_log_lvl_t lvl, redisReply *reply, REQUEST *request, int idx);

int			fr_redis_reply_to_value_box(TALLOC_CTX *ctx, fr_value_box_t *out, redisReply *reply,
						    fr_type_t dst_type, fr_dict_attr_t const *dst_enumv);

int			fr_redis_reply_to_map(TALLOC_CTX *ctx, vp_map_t **out,
					      REQUEST *request, redisReply *key, redisReply *op, redisReply *value);

int			fr_redis_tuple_from_map(TALLOC_CTX *pool, char const *out[], size_t out_len[], vp_map_t *map);

fr_redis_rcode_t	fr_redis_get_version(char *out, size_t out_len, fr_redis_conn_t *conn);

uint32_t		fr_redis_version_num(char const *version);

/*
 *	Process response from pipelined command.
 */
fr_redis_rcode_t	fr_redis_pipeline_result(unsigned int *pipelined, fr_redis_rcode_t *rcode,
						 redisReply *out[], size_t out_len,
						 fr_redis_conn_t *conn) CC_HINT(nonnull);
#endif /* LIBFREERADIUS_REDIS_H */
