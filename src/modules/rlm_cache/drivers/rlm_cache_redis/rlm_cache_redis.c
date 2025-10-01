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
 * @file rlm_cache_redis.c
 * @brief redis based cache.
 *
 * @copyright 2014 The FreeRADIUS server project
 */

#include <hiredis/hiredis.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include "../../rlm_cache.h"
#include "../../serialize.h"

typedef struct rlm_cache_redis_handle {
	redisContext	*conn;
} rlm_cache_redis_handle_t;

typedef struct rlm_cache_redis {
	fr_connection_pool_t	*pool;
	char const		*hostname;
	char const		*password;
	uint32_t		database;
	uint16_t		port;
	uint16_t		query_timeout;
} rlm_cache_redis_t;

static const CONF_PARSER driver_config[] = {
	{ "server", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_cache_redis_t, hostname), NULL },
	{ "port", FR_CONF_OFFSET(PW_TYPE_SHORT, rlm_cache_redis_t, port), "6379" },
	{ "database", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_cache_redis_t, database), "0" },
	{ "password", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, rlm_cache_redis_t, password), NULL },
	{ "query_timeout", FR_CONF_OFFSET(PW_TYPE_SHORT, rlm_cache_redis_t, query_timeout), "5" },
	CONF_PARSER_TERMINATOR
};

/** Free a connection handle
 *
 * @param randle to free.
 */
static int _mod_conn_free(rlm_cache_redis_handle_t *randle)
{
	if (randle->conn) {
		redisFree(randle->conn);
		randle->conn = NULL;
	}

	return 0;
}

/** Create a new redis handle
 *
 * @param ctx to allocate handle in.
 * @param instance data.
 */
static void *mod_conn_create(TALLOC_CTX *ctx, void *instance)
{
	rlm_cache_t			*inst = instance;
	rlm_cache_redis_t		*driver = inst->driver;
	rlm_cache_redis_handle_t	*randle;
	redisContext *conn;
	redisReply *reply = NULL;
	char buffer[1024];
	struct timeval tv;

	tv.tv_sec = driver->query_timeout;
	tv.tv_usec = 0;
	conn = redisConnectWithTimeout(driver->hostname, driver->port, tv);
	if (!conn) {
		ERROR("rlm_cache (%s): Failed calling redisConnectWithTimeout('%s', %d, %d)",
		      inst->name, driver->hostname, driver->port, driver->query_timeout);
		return NULL;
	}

#ifndef redisReplyReaderGetError
#define redisReplyReaderGetError redisReaderGetError
#endif

	if (conn && conn->err) {
		ERROR("rlm_cache (%s): Problems with redisConnectWithTimeout('%s', %d, %d), %s",
		      inst->name, driver->hostname, driver->port, driver->query_timeout, redisReplyReaderGetError(conn));
		redisFree(conn);
		return NULL;
	}

	if (driver->password) {
		snprintf(buffer, sizeof(buffer), "AUTH %s", driver->password);
		reply = redisCommand(conn, buffer);
		if (!reply) {
			ERROR("rlm_redis (%s): Failed to run AUTH", inst->name);

		do_close:
			if (reply) freeReplyObject(reply);
			redisFree(conn);
			return NULL;
		}

		switch (reply->type) {
		case REDIS_REPLY_STATUS:
			if (strcmp(reply->str, "OK") != 0) {
				ERROR("rlm_redis (%s): Failed authentication: reply %s",
				       inst->name, reply->str);
				goto do_close;
			}
			break;	/* else it's OK */

		default:
			ERROR("rlm_redis (%s): Unexpected reply to AUTH",
			       inst->name);
			goto do_close;
		}

		freeReplyObject(reply);
	}

	randle = talloc_zero(ctx, rlm_cache_redis_handle_t);
	randle->conn = conn;
	talloc_set_destructor(randle, _mod_conn_free);

	return randle;
}

/** Cleanup a rlm_cache_redis instance
 *
 * @param driver to free.
 * @return 0
 */
static int _mod_detach(rlm_cache_redis_t *driver)
{
	fr_connection_pool_free(driver->pool);
	return 0;
}

/** Create a new rlm_cache_redis instance
 *
 * @param conf redis specific conf section.
 * @param inst main rlm_cache instance.
 * @return 0 on success, -1 on failure.
 */
static int mod_instantiate(CONF_SECTION *conf, rlm_cache_t *inst)
{
	rlm_cache_redis_t *driver;
	char buffer[256];
	static bool version_done;

	buffer[0] = '\0';

	/*
	 *	Get version info from the libredis API.
	 */
	if (!version_done) {
		version_done = true;
		INFO("rlm_cache_redis: libhires version: %d.%d.%d", HIREDIS_MAJOR, HIREDIS_MINOR, HIREDIS_PATCH);
	}

	driver = talloc_zero(inst, rlm_cache_redis_t);
	talloc_set_destructor(driver, _mod_detach);
	if (cf_section_parse(conf, driver, driver_config) < 0) return -1;

	inst->driver = driver;
	snprintf(buffer, sizeof(buffer), "rlm_cache (%s)", inst->name);
	driver->pool = fr_connection_pool_module_init(conf, inst, mod_conn_create, NULL, buffer);
	if (!driver->pool) return -1;

	if (inst->max_entries > 0) WARN("rlm_cache_redis: max_entries is not supported by this driver");

	return 0;
}

static void cache_entry_free(rlm_cache_entry_t *c)
{
	talloc_free(c);
}

/** Locate a cache entry in redis
 *
 * @param out Where to write the pointer to the cach entry.
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Pointer to redis handle.
 * @param key to search for.
 * @return CACHE_OK on success CACHE_MISS if no entry found, CACHE_ERROR on error.
 */
static cache_status_t cache_entry_find(rlm_cache_entry_t **out, UNUSED rlm_cache_t *inst, REQUEST *request,
				       rlm_cache_handle_t **handle, char const *key)
{
	rlm_cache_redis_handle_t *randle = *handle;
	redisReply *reply;
	rlm_cache_entry_t *c;
	int ret;

	reply = redisCommand(randle->conn,"GET %s", key);
	if (!reply) {
		RERROR("Failed talking to database for key \"%s\"", key);
		return CACHE_RECONNECT;
	}

	c = talloc_zero(NULL,  rlm_cache_entry_t);
	switch (reply->type) {
	case REDIS_REPLY_STRING:
		ret = cache_deserialize(c, reply->str, reply->len);
		if (ret < 0) {
			RERROR("%s", fr_strerror());
		error:
			talloc_free(c);
			freeReplyObject(reply);
			return CACHE_ERROR;
		}
		break;
	case REDIS_REPLY_NIL:
		talloc_free(c);
		freeReplyObject(reply);
		return CACHE_MISS;
	case REDIS_REPLY_ERROR:
		RERROR("Failed retrieving entry for key \"%s\": %s", key, reply->str);
		goto error;
	default:
		RERROR("Failed retrieving entry for key \"%s\": invalid type", key);
		goto error;
	}

	freeReplyObject(reply);
	c->key = talloc_strdup(c, key);
	*out = c;

	return CACHE_OK;
}

/** Insert a new entry into the data store
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Pointer to redis handle.
 * @param c entry to insert.
 * @return CACHE_OK on success else CACHE_ERROR on error.
 */
static cache_status_t cache_entry_insert(UNUSED rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle,
					 rlm_cache_entry_t *c)
{
	rlm_cache_redis_handle_t *randle = *handle;
	redisReply *reply = NULL;
	TALLOC_CTX *pool;
	char *to_store;

	pool = talloc_pool(NULL, 1024);
	if (!pool) return CACHE_ERROR;

	if (cache_serialize(pool, &to_store, c) < 0) {
	error:
		if (reply) freeReplyObject(reply);
		talloc_free(pool);
		return CACHE_ERROR;
	}

	reply = redisCommand(
			randle->conn,
			"SET %b %b EX %d",
			c->key,
			talloc_array_length(c->key) - 1,
			to_store ? to_store : "",
			to_store ? talloc_array_length(to_store) - 1 : 0,
			c->expires - c->created);

	if (!reply) {
		RERROR("Failed talking to database for key \"%s\"", c->key);
		if (reply) freeReplyObject(reply);
		talloc_free(pool);
		return CACHE_RECONNECT;
	}

	switch (reply->type) {
	case REDIS_REPLY_STATUS:
		break;
	case REDIS_REPLY_ERROR:
		RERROR("Failed insert for key \"%s\": %s", c->key, reply->str);
		goto error;
	default:
		RERROR("Failed insert for key \"%s\" %d", c->key, reply->type);
		goto error;
	}

	freeReplyObject(reply);
	talloc_free(pool);

	return CACHE_OK;
}

/** Call delete the cache entry from redis
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Pointer to redis handle.
 * @param c entry to expire.
 * @return CACHE_OK on success else CACHE_ERROR.
 */
static cache_status_t cache_entry_expire(UNUSED rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle,
					 rlm_cache_entry_t *c)
{
	rlm_cache_redis_handle_t *randle = *handle;
	redisReply *reply = NULL;

	reply = redisCommand( randle->conn, "DEL %b", c->key, talloc_array_length(c->key) - 1);
	if (!reply) {
		RERROR("Failed expire for key \"%s\"", c->key);
		if (reply) freeReplyObject(reply);
		return CACHE_RECONNECT;
	}

	switch (reply->type) {
	default:
		RERROR("Failed expire for key \"%s\"", c->key);
	error:
		if (reply) freeReplyObject(reply);
		return CACHE_ERROR;
	case REDIS_REPLY_ERROR:
		RERROR("Failed expire for key \"%s\": %s", c->key, reply->str);
		goto error;
	case REDIS_REPLY_INTEGER:
		if (reply->integer == 0) RWARN("key \"%s\" is already expired", c->key);
		break;
	}

	freeReplyObject(reply);

	return CACHE_OK;
}

/** Get a redis handle
 *
 * @param out Where to write the handle.
 * @param inst rlm_cache instance.
 * @param request The current request.
 */
static int mod_conn_get(rlm_cache_handle_t **out, rlm_cache_t *inst, UNUSED REQUEST *request)
{
	rlm_cache_redis_t *driver = inst->driver;
	rlm_cache_handle_t *randle;

	*out = NULL;
	randle = fr_connection_get(driver->pool);
	if (!randle) {
		*out = NULL;
		return -1;
	}

	*out = randle;

	return 0;
}

/** Release a socket
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Pointer to the handle to release (will be set to NULL).
 */
static void mod_conn_release(rlm_cache_t *inst, UNUSED REQUEST *request, rlm_cache_handle_t **handle)
{
	rlm_cache_redis_t *driver = inst->driver;

	fr_connection_release(driver->pool, *handle);
	*handle = NULL;
}

/** Reconnect a socket
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Pointer to the handle to reconnect (will be set to NULL if reconnection fails).
 */
static int mod_conn_reconnect(rlm_cache_t *inst, UNUSED REQUEST *request, rlm_cache_handle_t **handle)
{
	rlm_cache_redis_t *driver = inst->driver;
	rlm_cache_handle_t *randle;

	randle = fr_connection_reconnect(driver->pool, *handle);
	if (!randle) {
		*handle = NULL;
		return -1;
	}

	*handle = randle;

	return 0;
}

extern cache_module_t rlm_cache_redis;
cache_module_t rlm_cache_redis = {
	.name		= "rlm_cache_redis",
	.instantiate	= mod_instantiate,
	.free		= cache_entry_free,

	.find		= cache_entry_find,
	.insert		= cache_entry_insert,
	.expire		= cache_entry_expire,

	.acquire	= mod_conn_get,
	.release	= mod_conn_release,
	.reconnect	= mod_conn_reconnect
};
