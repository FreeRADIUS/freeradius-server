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
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include "../../rlm_cache.h"
#include "../../../rlm_redis/redis.h"

typedef struct rlm_cache_redis {
	redis_conn_conf_t	server;		//!< Connection parameters for the Redis server.
						//!< Must be first field in this struct.

	vp_tmpl_t		created_attr;	//!< LHS of the Cache-Created map.
	vp_tmpl_t		expires_attr;	//!< LHS of the Cache-Expires map.

	fr_connection_pool_t	*pool;
} rlm_cache_redis_t;

static const CONF_PARSER driver_config[] = {
	{ "server", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, redis_conn_conf_t, hostname), NULL },
	{ "port", FR_CONF_OFFSET(PW_TYPE_SHORT, redis_conn_conf_t, port), "6379" },
	{ "database", FR_CONF_OFFSET(PW_TYPE_INTEGER, redis_conn_conf_t, database), "0" },
	{ "password", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, redis_conn_conf_t, password), NULL },

	{NULL, -1, 0, NULL, NULL}
};

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
 * @copydetails cache_instantiate_t
 */
static int mod_instantiate(CONF_SECTION *conf, rlm_cache_config_t const *config, void *driver_inst)
{
	rlm_cache_redis_t	*driver = driver_inst;
	char			buffer[256];

	buffer[0] = '\0';

	fr_redis_version_print();

	talloc_set_destructor(driver, _mod_detach);

	if (cf_section_parse(conf, driver, driver_config) < 0) return -1;

	snprintf(buffer, sizeof(buffer), "rlm_cache (%s)", config->name);

	driver->pool = fr_connection_pool_module_init(conf, &driver->server, fr_redis_conn_create, NULL, buffer);
	if (!driver->pool) {
		ERROR("rlm_cache_redis: Connection pool failure");
		return -1;
	}

	/*
	 *	These never change, so do it once on instantiation
	 */
	if (tmpl_from_attr_str(&driver->created_attr, "&Cache-Created",
			       REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false) < 0) {
		ERROR("rlm_cache_redis: Cache-Created attribute not defined");
		return -1;
	}

	if (tmpl_from_attr_str(&driver->expires_attr, "&Cache-Expires",
			       REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false) < 0) {
		ERROR("rlm_cache_redis: Cache-Expires attribute not defined");
		return -1;
	}

	return 0;
}

static void cache_entry_free(rlm_cache_entry_t *c)
{
	talloc_free(c);
}

/** Locate a cache entry in redis
 *
 * @copydetails cache_entry_find_t
 */
static cache_status_t cache_entry_find(rlm_cache_entry_t **out,
				       UNUSED rlm_cache_config_t const *config, UNUSED void *driver_inst,
				       REQUEST *request, void *handle, uint8_t const *key, size_t key_len)
{
	redis_conn_t		*randle = talloc_get_type_abort(handle, redis_conn_t);

	size_t			i;

	redisReply		*reply;
	vp_map_t		*head = NULL, **last = &head;
#ifdef HAVE_TALLOC_POOLED_OBJECT
	size_t			pool_size = 0;
#endif
	rlm_cache_entry_t	*c;

	/*
	 *	Grab all the data for this hash, should return an array
	 *	of alternating keys/values which we then convert into maps.
	 */
	if (RDEBUG_ENABLED3) {
		char *p;

		p = fr_aprints(NULL, (char const *)key, key_len, '"');
		RDEBUG3("LRANGE %s 0 -1", key);
		talloc_free(p);
	}
	reply = redisCommand(randle->handle, "LRANGE %b 0 -1", key, key_len);
	switch (fr_redis_command_status(randle, reply)) {
	case 0:
		if (reply->type != REDIS_REPLY_ARRAY) {
			REDEBUG("Bad result type, expected array, got %s",
				fr_int2str(redis_reply_types, reply->type, "<UNKNOWN>"));
			freeReplyObject(reply);
			return CACHE_ERROR;
		}
		break;

	default:
		rad_assert(0);
		/* FALL-THROUGH */

	case -1:
		RERROR("Failed retrieving entry: %s", fr_strerror());
		freeReplyObject(reply);
		return CACHE_ERROR;

	case -2:
		RERROR("Connection error: %s.  Asking for handle to be reconnected..", fr_strerror());
		/* No replies to free on connection errors */
		return CACHE_RECONNECT;
	}

	if (reply->elements == 0) {
		freeReplyObject(reply);
		return CACHE_MISS;
	}

	if (reply->elements % 3) {
		REDEBUG("Invalid number of reply elements (%zu).  "
			"Reply must contain triplets of keys operators and values",
			reply->elements);
		freeReplyObject(reply);
		return CACHE_ERROR;
	}

#ifdef HAVE_TALLOC_POOLED_OBJECT
	/*
	 *	We can get a pretty good idea of the required size of the pool
	 */
	for (i = 0; i < reply->elements; i += 3) {
		pool_size += sizeof(vp_map_t) + (sizeof(vp_tmpl_t) * 2);
		if (reply->element[i]->type == REDIS_REPLY_STRING) pool_size += reply->element[i]->len + 1;
	}

	/*
	 *	reply->elements gives us the number of chunks, as the maps are triplets, and there
	 *	are three chunks per map
	 */

	c = talloc_pooled_object(NULL,  rlm_cache_entry_t, reply->elements, pool_size);
	memset(&pool, 0, sizeof(rlm_cache_entry_t));
#else
	c = talloc_zero(NULL, rlm_cache_entry_t);
#endif
	/*
	 *	Convert the key/value pairs back into maps
	 */
	for (i = 0; i < reply->elements; i += 3) {
		if (fr_redis_reply_to_map(c, last, request,
					  reply->element[i], reply->element[i + 1], reply->element[i + 2]) < 0) {
			talloc_free(c);
			freeReplyObject(reply);
			return CACHE_ERROR;
		}
		last = &(*last)->next;
	}
	freeReplyObject(reply);

	/*
	 *	Pull out the cache created date
	 */
	if ((head->lhs->tmpl_da->vendor == 0) && (head->lhs->tmpl_da->attr == PW_CACHE_CREATED)) {
		vp_map_t *map;

		c->created = head->rhs->tmpl_data_value.date;

		map = head;
		head = head->next;
		talloc_free(map);
	}

	/*
	 *	Pull out the cache expires date
	 */
	if ((head->lhs->tmpl_da->vendor == 0) && (head->lhs->tmpl_da->attr == PW_CACHE_EXPIRES)) {
		vp_map_t *map;

		c->expires = head->rhs->tmpl_data_value.date;

		map = head;
		head = head->next;
		talloc_free(map);
	}

	c->key = talloc_memdup(c, key, key_len);
	c->key_len = key_len;
	c->maps = head;
	*out = c;

	return CACHE_OK;
}


/** Insert a new entry into the data store
 *
 * @copydetails cache_entry_insert_t
 */
static cache_status_t cache_entry_insert(UNUSED rlm_cache_config_t const *config, void *driver_inst,
					 REQUEST *request, void *handle, const rlm_cache_entry_t *c)
{
	rlm_cache_redis_t	*driver = driver_inst;
	redis_conn_t		*randle = talloc_get_type_abort(handle, redis_conn_t);
	TALLOC_CTX		*pool;

	vp_map_t		*map;

	static char const	command[] = "RPUSH";
	char const		**argv;
	size_t			*argv_len;
	char const		**argv_p;
	size_t			*argv_len_p;

	cache_status_t		rcode = CACHE_OK;

	int			pipelined = 0;	/* How many commands pending in the pipeline */
	redisReply		*reply = NULL;

	char			*p;
	int			cnt, i;

	vp_tmpl_t		expires_value;
	vp_map_t		expires = {
					.op	= T_OP_SET,
					.lhs	= &driver->expires_attr,
					.rhs	= &expires_value,
				};

	vp_tmpl_t		created_value;
	vp_map_t		created = {
					.op	= T_OP_SET,
					.lhs	= &driver->created_attr,
					.rhs	= &created_value,
					.next	= &expires
				};

	/*
	 *	Encode the entry created date
	 */
	tmpl_init(&created_value, TMPL_TYPE_DATA, "<TEMP>", 6);
	created_value.tmpl_data_type = PW_TYPE_DATE;
	created_value.tmpl_data_length = sizeof(created_value.tmpl_data_value.date);
	created_value.tmpl_data_value.date = c->created;

	/*
	 *	Encode the entry expiry time
	 *
	 *	Although Redis objects expire on their own, we still need this
	 *	to ignore entries that were created before the last epoch.
	 */
	tmpl_init(&expires_value, TMPL_TYPE_DATA, "<TEMP>", 6);
	expires_value.tmpl_data_type = PW_TYPE_DATE;
	expires_value.tmpl_data_length = sizeof(expires_value.tmpl_data_value.date);
	expires_value.tmpl_data_value.date = c->expires;
	expires.next = c->maps;	/* Head of the list */

	for (cnt = 0, map = &created; map; cnt++, map = map->next);

	/*
	 *	The majority of serialized entries should be under 1k.
	 *
	 * @todo We should really calculate this using some sort of moving average.
	 */
	pool = talloc_pool(randle, 1024);
	if (!pool) return CACHE_ERROR;

	argv_p = argv = talloc_array(pool, char const *, (cnt * 3)+ 2);
	argv_len_p = argv_len = talloc_array(pool, size_t, (cnt * 3) + 2);

	*argv_p++ = command;
	*argv_len_p++ = sizeof(command) - 1;

	*argv_p++ = (char const *)c->key;
	*argv_len_p++ = c->key_len;

	/*
	 *	Add the maps to the command string in reverse order
	 */
	for (map = &created; map; map = map->next) {
		if (fr_redis_tuple_from_map(pool, argv_p, argv_len_p, map) < 0) {
			REDEBUG("Failed encoding map as Redis K/V pair");
			talloc_free(pool);
			return CACHE_ERROR;
		}
		argv_p += 3;
		argv_len_p += 3;
	}

	RDEBUG3("Pipelining commands");
	RINDENT();
	/*
	 *	Start the transaction, as we need to set an expiry time too.
	 */
	if (c->expires > 0) {
		RDEBUG3("MULTI");
		if (redisAppendCommand(randle->handle, "MULTI") != REDIS_OK) {
		append_error:
			REXDENT();
			RERROR("Failed appending Redis command to output buffer: %s", randle->handle->errstr);
			talloc_free(pool);
			return CACHE_ERROR;
		}
		pipelined++;
	}

	if (RDEBUG_ENABLED3) {
		p = fr_aprints(request, (char const *)c->key, c->key_len, '\0');
		RDEBUG3("DEL \"%s\"", p);
		talloc_free(p);

	}
	if (redisAppendCommand(randle->handle, "DEL %b", c->key, c->key_len) != REDIS_OK) goto append_error;
	pipelined++;

	if (RDEBUG_ENABLED3) {
		RDEBUG3("argv command");
		RINDENT();
		for (i = 0; i < (int)talloc_array_length(argv); i++) {
			p = fr_aprints(request, argv[i], argv_len[i], '\0');
			RDEBUG3("%s", p);
			talloc_free(p);
		}
		REXDENT();
	}
	redisAppendCommandArgv(randle->handle, talloc_array_length(argv), argv, argv_len);
	pipelined++;

	/*
	 *	Set the expiry time and close out the transaction.
	 */
	if (c->expires > 0) {
		if (RDEBUG_ENABLED3) {
			p = fr_aprints(request, (char const *)c->key, c->key_len, '\"');
			RDEBUG3("EXPIREAT \"%s\" %li", p, (long)c->expires);
			talloc_free(p);
		}
		if (redisAppendCommand(randle->handle, "EXPIREAT %b %i", c->key,
				       c->key_len, c->expires) != REDIS_OK) goto append_error;
		pipelined++;
		RDEBUG3("EXEC");
		if (redisAppendCommand(randle->handle, "EXEC") != REDIS_OK) goto append_error;
		pipelined++;
	}
	REXDENT();
	talloc_free(pool);

	/*
	 *	Looks like hiredis may leak memory if we pass in a NULL reply argument
	 *	so we always get the reply, and free it if it wasn't needed.
	 */
	RDEBUG3("Command results");
	RINDENT();
	for (i = 0; i < pipelined; i++) {
		redisGetReply(randle->handle, (void **)&reply);
		fr_redis_response_print(L_DBG_LVL_3, reply, request, i);
		switch (fr_redis_command_status(randle, reply)) {
		case 0:
			break;

		default:
			rad_assert(0);
			/* FALL-THROUGH */

		case -1:
			rcode = CACHE_ERROR;
			break;

		case -2:
			rcode = CACHE_RECONNECT;
			break;
		}
		freeReplyObject(reply);
		reply = NULL;
	}
	switch (rcode) {
	case CACHE_ERROR:
		RERROR("Failed storing entry");
		break;

	case CACHE_RECONNECT:
		REDEBUG2("Asking for handle to be reconnected...");
		break;

	default:
		break;
	}
	REXDENT();

	return rcode;
}

/** Call delete the cache entry from redis
 *
 * @copydetails cache_entry_expire_t
 */
static cache_status_t cache_entry_expire(UNUSED rlm_cache_config_t const *config, UNUSED void *driver_inst,
					 REQUEST *request, void *handle, rlm_cache_entry_t *c)
{
	redis_conn_t	*randle = talloc_get_type_abort(handle, redis_conn_t);
	redisReply	*reply;

	reply = redisCommand(randle->handle, "DEL %b", c->key, c->key_len);
	switch (fr_redis_command_status(randle, reply)) {
	case 0:
		if (reply->type == REDIS_REPLY_INTEGER) {
			if (reply->integer) {
				RDEBUG2("Entry successfully removed");
			} else {
				RDEBUG2("Entry already removed");
			}
			freeReplyObject(reply);
			return CACHE_OK;
		} else {
			REDEBUG("Bad result type, expected integer, got %s",
				fr_int2str(redis_reply_types, reply->type, "<UNKNOWN>"));
			freeReplyObject(reply);
			return CACHE_ERROR;
		}

	default:
		rad_assert(0);
		/* FALL-THROUGH */

	case -1:
		RERROR("Failed expiring entry: %s", fr_strerror());
		freeReplyObject(reply);
		return CACHE_ERROR;

	case -2:
		RERROR("Connection error: %s.  Asking for handle to be reconnected..", fr_strerror());
		/* No replies to free on connection errors */
		return CACHE_RECONNECT;
	}
}

/** Get a redis handle
 *
 * @copydetails cache_acquire_t
 */
static int mod_conn_get(void **handle, UNUSED rlm_cache_config_t const *config, void *driver_inst,
			UNUSED REQUEST *request)
{
	rlm_cache_redis_t	*driver = driver_inst;
	rlm_cache_handle_t	*randle;

	*handle = NULL;

	randle = fr_connection_get(driver->pool);
	if (!randle) {
		*handle = NULL;
		return -1;
	}
	*handle = randle;

	return 0;
}

/** Release a redis handle
 *
 * @copydetails cache_release_t
 */
static void mod_conn_release(UNUSED rlm_cache_config_t const *config, void *driver_inst,
			     UNUSED REQUEST *request, void *handle)
{
	rlm_cache_redis_t *driver = driver_inst;

	fr_connection_release(driver->pool, handle);
}

/** Reconnect a redis handle
 *
 * @copydetails cache_reconnect_t
 */
static int mod_conn_reconnect(void **handle, UNUSED rlm_cache_config_t const *config, void *driver_inst,
			      UNUSED REQUEST *request)
{
	rlm_cache_redis_t *driver = driver_inst;
	rlm_cache_handle_t *randle;

	randle = fr_connection_reconnect(driver->pool, *handle);
	if (!randle) {
		*handle = NULL;
		return -1;
	}
	*handle = randle;

	return 0;
}

extern cache_driver_t rlm_cache_redis;
cache_driver_t rlm_cache_redis = {
	.name		= "rlm_cache_redis",
	.instantiate	= mod_instantiate,
	.inst_size	= sizeof(rlm_cache_redis_t),
	.free		= cache_entry_free,

	.find		= cache_entry_find,
	.insert		= cache_entry_insert,
	.expire		= cache_entry_expire,

	.acquire	= mod_conn_get,
	.release	= mod_conn_release,
	.reconnect	= mod_conn_reconnect
};
