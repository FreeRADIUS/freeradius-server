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
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#define LOG_PREFIX "rlm_cache_redis - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include "../../rlm_cache.h"
#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/redis/cluster.h>
static CONF_PARSER driver_config[] = {
	REDIS_COMMON_CONFIG,
	CONF_PARSER_TERMINATOR
};

typedef struct {
	fr_redis_conf_t		conf;		//!< Connection parameters for the Redis server.
						//!< Must be first field in this struct.

	vp_tmpl_t		*created_attr;	//!< LHS of the Cache-Created map.
	vp_tmpl_t		*expires_attr;	//!< LHS of the Cache-Expires map.

	fr_redis_cluster_t	*cluster;
} rlm_cache_redis_t;

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_cache_redis_dict[];
fr_dict_autoload_t rlm_cache_redis_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_cache_created;
static fr_dict_attr_t const *attr_cache_expires;

extern fr_dict_attr_autoload_t rlm_cache_redis_dict_attr[];
fr_dict_attr_autoload_t rlm_cache_redis_dict_attr[] = {
	{ .out = &attr_cache_created, .name = "Cache-Created", .type = FR_TYPE_DATE, .dict = &dict_freeradius },
	{ .out = &attr_cache_expires, .name = "Cache-Expires", .type = FR_TYPE_DATE, .dict = &dict_freeradius },
	{ NULL }
};

/** Create a new rlm_cache_redis instance
 *
 * @param instance	A uint8_t array of inst_size if inst_size > 0, else NULL,
 *			this should contain the result of parsing the driver's
 *			CONF_PARSER array that it specified in the interface struct.
 * @param conf		section holding driver specific #CONF_PAIR (s).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_cache_redis_t		*driver = instance;
	char				buffer[256];
	rlm_cache_config_t const	*config = dl_module_parent_data_by_child_data(instance);

	fr_assert(config);

	buffer[0] = '\0';

	if (cf_section_rules_push(conf, driver_config) < 0) return -1;
	if (cf_section_parse(driver, driver, conf) < 0) return -1;

	snprintf(buffer, sizeof(buffer), "rlm_cache (%s)", config->name);

	driver->cluster = fr_redis_cluster_alloc(driver, conf, &driver->conf, true,
						 buffer, "modules.cache.pool", NULL);
	if (!driver->cluster) {
		ERROR("Cluster failure");
		return -1;
	}

	/*
	 *	These never change, so do it once on instantiation
	 */
	if (tmpl_afrom_attr_str(driver, NULL, &driver->created_attr, "&Cache-Created", NULL) < 0) {
		ERROR("Cache-Created attribute not defined");
		return -1;
	}

	if (tmpl_afrom_attr_str(driver, NULL, &driver->expires_attr, "&Cache-Expires", NULL) < 0) {
		ERROR("Cache-Expires attribute not defined");
		return -1;
	}

	return 0;
}

static int mod_load(void)
{
	fr_redis_version_print();
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
				       UNUSED rlm_cache_config_t const *config, void *instance,
				       REQUEST *request, UNUSED void *handle, uint8_t const *key, size_t key_len)
{
	rlm_cache_redis_t		*driver = instance;
	size_t				i;

	fr_redis_cluster_state_t	state;
	fr_redis_conn_t			*conn;
	fr_redis_rcode_t		status;
	redisReply			*reply = NULL;
	int				s_ret;

	vp_map_t			*head = NULL, **last = &head;
#ifdef HAVE_TALLOC_ZERO_POOLED_OBJECT
	size_t				pool_size = 0;
#endif
	rlm_cache_entry_t		*c;

	for (s_ret = fr_redis_cluster_state_init(&state, &conn, driver->cluster, request, key, key_len, false);
	     s_ret == REDIS_RCODE_TRY_AGAIN;	/* Continue */
	     s_ret = fr_redis_cluster_state_next(&state, &conn, driver->cluster, request, status, &reply)) {
		/*
		 *	Grab all the data for this hash, should return an array
		 *	of alternating keys/values which we then convert into maps.
		 */
		RDEBUG3("LRANGE %pV 0 -1", fr_box_strvalue_len((char const *)key, key_len));
		reply = redisCommand(conn->handle, "LRANGE %b 0 -1", key, key_len);
		status = fr_redis_command_status(conn, reply);
	}
	if (s_ret != REDIS_RCODE_SUCCESS) {
		RERROR("Failed retrieving entry for key \"%pV\"", fr_box_strvalue_len((char const *)key, key_len));

	error:
		fr_redis_reply_free(&reply);
		return CACHE_ERROR;
	}

	if (!fr_cond_assert(reply)) goto error;

	if (reply->type != REDIS_REPLY_ARRAY) {
		REDEBUG("Bad result type, expected array, got %s",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		goto error;
	}

	RDEBUG3("Entry contains %zu elements", reply->elements);

	if (reply->elements == 0) {
		fr_redis_reply_free(&reply);
		return CACHE_MISS;
	}

	if (reply->elements % 3) {
		REDEBUG("Invalid number of reply elements (%zu).  "
			"Reply must contain triplets of keys operators and values",
			reply->elements);
		goto error;
	}

#ifdef HAVE_TALLOC_ZERO_POOLED_OBJECT
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

	c = talloc_zero_pooled_object(NULL, rlm_cache_entry_t, reply->elements, pool_size);
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
			fr_redis_reply_free(&reply);
			return CACHE_ERROR;
		}
		last = &(*last)->next;
	}
	fr_redis_reply_free(&reply);

	/*
	 *	Pull out the cache created date
	 */
	if (tmpl_da(head->lhs) == attr_cache_created) {
		vp_map_t *map;

		c->created = tmpl_value(head->rhs)->vb_date;

		map = head;
		head = head->next;
		talloc_free(map);
	}

	/*
	 *	Pull out the cache expires date
	 */
	if (tmpl_da(head->lhs) == attr_cache_expires) {
		vp_map_t *map;

		c->expires = tmpl_value(head->rhs)->vb_date;

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
static cache_status_t cache_entry_insert(UNUSED rlm_cache_config_t const *config, void *instance,
					 REQUEST *request, UNUSED void *handle, const rlm_cache_entry_t *c)
{
	rlm_cache_redis_t	*driver = instance;
	TALLOC_CTX		*pool;

	vp_map_t		*map;

	fr_redis_conn_t		*conn;
	fr_redis_cluster_state_t	state;
	fr_redis_rcode_t	status;
	redisReply		*reply = NULL;
	int			s_ret;

	static char const	command[] = "RPUSH";
	char const		**argv;
	size_t			*argv_len;
	char const		**argv_p;
	size_t			*argv_len_p;

	unsigned int		pipelined = 0;	/* How many commands pending in the pipeline */
	redisReply		*replies[5];	/* Should have the same number of elements as pipelined commands */
	size_t			reply_cnt = 0, i;

	int			cnt;

	vp_tmpl_t		expires_value;
	vp_map_t		expires = {
					.op	= T_OP_SET,
					.lhs	= driver->expires_attr,
					.rhs	= &expires_value,
				};

	vp_tmpl_t		created_value;
	vp_map_t		created = {
					.op	= T_OP_SET,
					.lhs	= driver->created_attr,
					.rhs	= &created_value,
					.next	= &expires
				};

	/*
	 *	Encode the entry created date
	 */
	tmpl_init(&created_value, TMPL_TYPE_DATA, "<TEMP>", 6, T_BARE_WORD);
	fr_value_box_init(&created_value.data.literal, FR_TYPE_DATE, NULL, true);
	tmpl_value(&created_value)->vb_date = c->created;

	/*
	 *	Encode the entry expiry time
	 *
	 *	Although Redis objects expire on their own, we still need this
	 *	to ignore entries that were created before the last epoch.
	 */
	tmpl_init(&expires_value, TMPL_TYPE_DATA, "<TEMP>", 6, T_BARE_WORD);
	fr_value_box_init(&expires_value.data.literal, FR_TYPE_DATE, NULL, true);
	tmpl_value(&expires_value)->vb_date = c->expires;
	expires.next = c->maps;	/* Head of the list */

	for (cnt = 0, map = &created; map; cnt++, map = map->next);

	/*
	 *	The majority of serialized entries should be under 1k.
	 *
	 * @todo We should really calculate this using some sort of moving average.
	 */
	pool = talloc_pool(request, 1024);
	if (!pool) return CACHE_ERROR;

	argv_p = argv = talloc_array(pool, char const *, (cnt * 3) + 2);	/* pair = 3 + cmd + key */
	argv_len_p = argv_len = talloc_array(pool, size_t, (cnt * 3) + 2);	/* pair = 3 + cmd + key */

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

	for (s_ret = fr_redis_cluster_state_init(&state, &conn, driver->cluster, request, c->key, c->key_len, false);
	     s_ret == REDIS_RCODE_TRY_AGAIN;	/* Continue */
	     s_ret = fr_redis_cluster_state_next(&state, &conn, driver->cluster, request, status, &reply)) {
		/*
		 *	Start the transaction, as we need to set an expiry time too.
		 */
		if (c->expires > 0) {
			RDEBUG3("MULTI");
			if (redisAppendCommand(conn->handle, "MULTI") != REDIS_OK) {
			append_error:
				REXDENT();
				RERROR("Failed appending Redis command to output buffer: %s", conn->handle->errstr);
				talloc_free(pool);
				return CACHE_ERROR;
			}
			pipelined++;
		}

		RDEBUG3("DEL \"%pV\"", fr_box_strvalue_len((char const *)c->key, c->key_len));

		if (redisAppendCommand(conn->handle, "DEL %b", c->key, c->key_len) != REDIS_OK) goto append_error;
		pipelined++;

		if (RDEBUG_ENABLED3) {
			RDEBUG3("argv command");
			RINDENT();
			for (i = 0; i < talloc_array_length(argv); i++) {
				RDEBUG3("%pV", fr_box_strvalue_len(argv[i], argv_len[i]));
			}
			REXDENT();
		}
		redisAppendCommandArgv(conn->handle, talloc_array_length(argv), argv, argv_len);
		pipelined++;

		/*
		 *	Set the expiry time and close out the transaction.
		 */
		if (c->expires > 0) {
			RDEBUG3("EXPIREAT \"%pV\" %" PRIu64,
				fr_box_strvalue_len((char const *)c->key, c->key_len),
				fr_unix_time_to_sec(c->expires));
			if (redisAppendCommand(conn->handle, "EXPIREAT %b %" PRIu64, c->key,
					       c->key_len,
					       fr_unix_time_to_sec(c->expires)) != REDIS_OK) goto append_error;
			pipelined++;
			RDEBUG3("EXEC");
			if (redisAppendCommand(conn->handle, "EXEC") != REDIS_OK) goto append_error;
			pipelined++;
		}

		reply_cnt = fr_redis_pipeline_result(&pipelined, &status,
						     replies, NUM_ELEMENTS(replies),
						     conn);
		reply = replies[0];
	}
	talloc_free(pool);

	if (s_ret != REDIS_RCODE_SUCCESS) {
		RPERROR("Failed inserting entry");
		return CACHE_ERROR;
	}

	RDEBUG3("Command results");
	RINDENT();
	if (RDEBUG_ENABLED3) for (i = 0; i < reply_cnt; i++) fr_redis_reply_print(L_DBG_LVL_3, replies[i], request, i);
	fr_redis_pipeline_free(replies, reply_cnt);
	REXDENT();

	return CACHE_OK;
}

/** Call delete the cache entry from redis
 *
 * @copydetails cache_entry_expire_t
 */
static cache_status_t cache_entry_expire(UNUSED rlm_cache_config_t const *config, void *instance,
					 REQUEST *request, UNUSED void *handle, uint8_t const *key, size_t key_len)
{
	rlm_cache_redis_t		*driver = instance;
	fr_redis_cluster_state_t	state;
	fr_redis_conn_t			*conn;
	fr_redis_rcode_t			status;
	redisReply			*reply = NULL;
	int				s_ret;
	cache_status_t			cache_status;

	for (s_ret = fr_redis_cluster_state_init(&state, &conn, driver->cluster, request, key, key_len, false);
	     s_ret == REDIS_RCODE_TRY_AGAIN;	/* Continue */
	     s_ret = fr_redis_cluster_state_next(&state, &conn, driver->cluster, request, status, &reply)) {
	     	reply = redisCommand(conn->handle, "DEL %b", key, key_len);
	     	status = fr_redis_command_status(conn, reply);
	}

	if (s_ret != REDIS_RCODE_SUCCESS) {
		RERROR("Failed expiring entry");
	error:
		fr_redis_reply_free(&reply);
		return CACHE_ERROR;
	}
	if (!fr_cond_assert(reply)) goto error;

	if (reply->type == REDIS_REPLY_INTEGER) {
		cache_status = CACHE_MISS;
		if (reply->integer) cache_status = CACHE_OK;    /* Affected */
		fr_redis_reply_free(&reply);
		return cache_status;
	}

	REDEBUG("Bad result type, expected integer, got %s",
		fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
	fr_redis_reply_free(&reply);

	return CACHE_ERROR;
}

extern rlm_cache_driver_t rlm_cache_redis;
rlm_cache_driver_t rlm_cache_redis = {
	.name		= "rlm_cache_redis",
	.magic		= RLM_MODULE_INIT,
	.onload		= mod_load,
	.instantiate	= mod_instantiate,
	.inst_size	= sizeof(rlm_cache_redis_t),
	.config		= driver_config,
	.free		= cache_entry_free,

	.find		= cache_entry_find,
	.insert		= cache_entry_insert,
	.expire		= cache_entry_expire,
};
