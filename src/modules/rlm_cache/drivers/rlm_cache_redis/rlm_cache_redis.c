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
 * @file rlm_cache_redis.c
 * @brief redis based cache.
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#define LOG_PREFIX "cache - redis"

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include "../../rlm_cache.h"
#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/redis/cluster_async.h>
#include <freeradius-devel/io/coord_pair.h>

static conf_parser_t driver_config[] = {
	REDIS_COMMON_CONFIG,
	CONF_PARSER_TERMINATOR
};

typedef struct {
	fr_redis_conf_t		conf;		//!< Connection parameters for the Redis server.
						//!< Must be first field in this struct.

	CONF_SECTION 		*tls_conf;	//!< TLS CONF_SECTION

	tmpl_t		*created_attr;	//!< LHS of the Cache-Created map.
	tmpl_t		*expires_attr;	//!< LHS of the Cache-Expires map.

	module_instance_t const	*mi;				//!< Module instance.

	fr_coord_reg_t		*coord_reg;			//!< Coordinator registration.
	fr_coord_pair_reg_t	*coord_pair_reg;		//!< Coord pair registration.
} rlm_cache_redis_t;

typedef struct {
	rlm_cache_redis_t const		*inst;			//!< Module instance.
	fr_redis_ct_t			*rtcluster;		//!< Per thread Redis cluster.
	fr_coord_worker_t		*cw;			//!< Coord-worker for fetching cluster map.
} rlm_cache_redis_thread_t;

typedef struct {
	fr_value_box_t const		*key;
	fr_redis_command_set_t		*cmds;
	char				**cmd_str;
	fr_redis_async_cmd_t		*cmd;
	rlm_cache_entry_t		*entry;
	cache_status_t			rcode;
} rlm_cache_redis_rctx_t;

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_redis;

extern fr_dict_autoload_t rlm_cache_redis_dict[];
fr_dict_autoload_t rlm_cache_redis_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_redis, .proto = "redis" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_cache_created;
static fr_dict_attr_t const *attr_cache_expires;

extern fr_dict_attr_autoload_t rlm_cache_redis_dict_attr[];
fr_dict_attr_autoload_t rlm_cache_redis_dict_attr[] = {
	{ .out = &attr_cache_created, .name = "Cache-Created", .type = FR_TYPE_DATE, .dict = &dict_freeradius },
	{ .out = &attr_cache_expires, .name = "Cache-Expires", .type = FR_TYPE_DATE, .dict = &dict_freeradius },
	DICT_AUTOLOAD_TERMINATOR
};

REDIS_ASYNC_COORD_CALLBACKS(rlm_cache_redis_thread_t);

/** Create a new rlm_cache_redis instance
 *
 * @param[in] mctx		Data required for instantiation.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_cache_redis_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_cache_redis_t);
	char				buffer[256];

	snprintf(buffer, sizeof(buffer), "rlm_cache (%s)", mctx->mi->parent->name);

	inst->mi = mctx->mi;
	inst->conf.log_prefix = talloc_asprintf(inst, "rlm_cache (%s)", mctx->mi->parent->name);
	inst->conf.module_name = mctx->mi->parent->module->name;
	inst->conf.inst_name = mctx->mi->parent->name;

	if (inst->conf.use_tls) {
		inst->tls_conf = cf_section_find(mctx->mi->conf, "tls", CF_IDENT_ANY);

		if (!inst->tls_conf) {
			cf_log_err(mctx->mi->conf, "Missing tls section");
			return -1;
		}
	}

	/*
	 *	These never change, so do it once on instantiation
	 */
	if (tmpl_afrom_attr_str(inst, NULL, &inst->created_attr, "Cache-Created", NULL) <= 0) {
		ERROR("Cache-Created attribute not defined");
		return -1;
	}

	if (tmpl_afrom_attr_str(inst, NULL, &inst->expires_attr, "Cache-Expires", NULL) <= 0) {
		ERROR("Cache-Expires attribute not defined");
		return -1;
	}

	if (!inst->conf.use_cluster_map) return 0;

	if (inst->conf.database) {
		cf_log_err(mctx->mi->conf, "Cannot set Redis database number when cluster in use");
		return -1;
	}

	inst->coord_pair_reg = fr_coord_pair_register(&(fr_coord_pair_reg_ctx_t) {
			.name = mctx->mi->name,
			.worker_cb = worker_pair_callbacks,
			.cb_id = REDIS_COORD_PAIR_CALLBACK_ID,
			.root = fr_dict_root(dict_redis),
			.cs = mctx->mi->conf,
		}
	);
	if (!inst->coord_pair_reg) return -1;

	FR_COORD_PAIR_CB_CTX_SET(coord_callbacks, worker_callbacks, inst->coord_pair_reg);

	inst->coord_reg = fr_coord_register(&(fr_coord_reg_ctx_t) {
			.name = mctx->mi->name,
			.coord_cb = coord_callbacks,
			.worker_cb = worker_callbacks,
			.mi = mctx->mi
		});

	if (!inst->coord_reg) return -1;

	return 0;
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_cache_redis_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_cache_redis_thread_t);
	rlm_cache_redis_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_cache_redis_t);

	t->rtcluster = fr_redis_ct_alloc(t, inst->tls_conf, mctx->el, &inst->conf, NULL, NULL, false);
	if (!t->rtcluster) return -1;
	t->inst = inst;

	return 0;
}

static int mod_coord_attach(module_thread_inst_ctx_t const *mctx)
{
	rlm_cache_redis_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_cache_redis_thread_t);
	rlm_cache_redis_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_cache_redis_t);

	if (!inst->conf.use_cluster_map) return 0;

	t->cw = fr_coord_attach(t, mctx->el, inst->coord_reg);

	if (!t->cw) {
		ERROR("Failed to attach to coordinator");
		return -1;
	}

	if ((inst->conf.trunk_conf.start == 0) || (fr_schedule_worker_id() != 0)) return 0;

	return fr_redis_ct_map_bootstrap(t->rtcluster, t->cw, inst->coord_pair_reg);
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_cache_redis_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_cache_redis_thread_t);

	if (!t->cw) return 0;

	fr_coord_detach(t->cw, true);
	t->cw = NULL;
	return 0;
}

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_cache_redis_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_cache_redis_t);

	if (!inst->conf.use_cluster_map) return 0;

	fr_coord_deregister(inst->coord_reg);
	talloc_free(inst->coord_pair_reg);
	return 0;
}

static int mod_load(void)
{
	fr_redis_version_print();
	return redis_dict_init();
}

static void cache_entry_free(rlm_cache_entry_t *c)
{
	talloc_free(c);
}

static int cache_redis_rctx_free(rlm_cache_redis_rctx_t *rctx)
{
	size_t i;
	for (i = 0; i < talloc_array_length(rctx->cmd_str); i++) {
		if (!rctx->cmd_str[i]) continue;
		redisFreeCommand(rctx->cmd_str[i]);
	}
	return 0;
}

/** Process the results of Redis cache commands
 *
 * Initiating a cluster remap and query redirection if needed.
 *
 */
static cache_status_t cache_redis_results(request_t *request, rlm_cache_redis_t *inst, fr_redis_command_set_t *cmds,
					  fr_redis_async_cmd_t *cmd, cache_status_t rcode)
{
	switch (fr_redis_command_set_rcode(cmds)) {
	case REDIS_ASYNC_RCODE_SUCCESS:
		return rcode;

	case REDIS_ASYNC_RCODE_MOVE:
	{
		rlm_cache_redis_thread_t	*thread = talloc_get_type_abort(module_thread(inst->mi)->data,
										rlm_cache_redis_thread_t);

		if (inst->conf.use_cluster_map) fr_redis_ct_map_get(thread->rtcluster, thread->cw,
								    inst->coord_pair_reg, false);
	}
		FALL_THROUGH;

	case REDIS_ASYNC_RCODE_ASK:
		if (fr_redis_async_cmd_redirect(cmd) != REDIS_ASYNC_RCODE_SUCCESS) return CACHE_ERROR;
		return CACHE_YIELD;

	case REDIS_ASYNC_RCODE_TRY_AGAIN:
		if (fr_redis_async_cmd_resend(cmd) != REDIS_ASYNC_RCODE_SUCCESS) return CACHE_ERROR;
		return CACHE_YIELD;

	case REDIS_ASYNC_RCODE_ERROR:
		RPERROR("Server returned error");
		return CACHE_ERROR;

	default:
		return CACHE_ERROR;
	}
}

static void cache_redis_cancel(UNUSED rlm_cache_config_t const *config, UNUSED void *instance, request_t *request,
			       UNUSED void *handle, void *rctx)
{
	rlm_cache_redis_rctx_t	*cache_rctx = talloc_get_type_abort(rctx, rlm_cache_redis_rctx_t);

	RDEBUG2("Forcibly cancelling pending redis cache request");
	fr_redis_async_cmd_cancel(cache_rctx->cmd);
}

static cache_status_t cache_entry_find_resume(rlm_cache_entry_t **out, UNUSED rlm_cache_config_t const *config,
					      void *instance, UNUSED request_t *request,
					      UNUSED void *handle, void *rctx)
{
	rlm_cache_redis_t		*driver = instance;
	rlm_cache_redis_rctx_t		*cache_rctx = talloc_get_type_abort(rctx, rlm_cache_redis_rctx_t);

	*out = cache_rctx->entry;
	return cache_redis_results(request, driver, cache_rctx->cmds, cache_rctx->cmd, cache_rctx->rcode);
}

static void cache_entry_find_results(request_t *request, UNUSED fr_redis_command_t *cmd, redisReply *reply, void *rctx)
{
	rlm_cache_redis_rctx_t		*cache_rctx = talloc_get_type_abort(rctx, rlm_cache_redis_rctx_t);
	size_t				i;
#ifdef HAVE_TALLOC_ZERO_POOLED_OBJECT
	size_t				pool_size = 0;
#endif
	map_list_t			head;
	rlm_cache_entry_t		*c;

	if (reply->type != REDIS_REPLY_ARRAY) {
		REDEBUG("Bad result type, expected array, got %s",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
	error:
		cache_rctx->rcode = CACHE_ERROR;
		return;
	}

	RDEBUG3("Entry contains %zu elements", reply->elements);

	if (reply->elements == 0) {
		cache_rctx->rcode = CACHE_MISS;
		return;
	}

	if (reply->elements % 3) {
		REDEBUG("Invalid number of reply elements (%zu).  "
			"Reply must contain triplets of keys operators and values",
			reply->elements);
		goto error;
	}

	map_list_init(&head);

#ifdef HAVE_TALLOC_ZERO_POOLED_OBJECT
	/*
	 *	We can get a pretty good idea of the required size of the pool
	 */
	for (i = 0; i < reply->elements; i += 3) {
		pool_size += sizeof(map_t) + (sizeof(tmpl_t) * 2);
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
	map_list_init(&c->maps);
	/*
	 *	Convert the key/value pairs back into maps
	 */
	for (i = 0; i < reply->elements; i += 3) {
		if (fr_redis_reply_to_map(c, &head, request,
					  reply->element[i], reply->element[i + 1], reply->element[i + 2]) < 0) {
			talloc_free(c);
			cache_rctx->rcode = CACHE_ERROR;
			return;
		}
	}

	/*
	 *	Pull out the cache created date
	 */
	if (tmpl_attr_tail_da(map_list_head(&head)->lhs) == attr_cache_created) {
		map_t *map;

		c->created = tmpl_value(map_list_head(&head)->rhs)->vb_date;

		map = map_list_pop_head(&head);
		talloc_free(map);
	}

	/*
	 *	Pull out the cache expires date
	 */
	if (tmpl_attr_tail_da(map_list_head(&head)->lhs) == attr_cache_expires) {
		map_t *map;

		c->expires = tmpl_value(map_list_head(&head)->rhs)->vb_date;

		map = map_list_pop_head(&head);
		talloc_free(map);
	}

	if (unlikely(fr_value_box_copy(c, &c->key, cache_rctx->key) < 0)) goto error;

	map_list_move(&c->maps, &head);
	cache_rctx->entry = c;
}

/** Locate a cache entry in redis
 *
 * @copydetails cache_entry_find_t
 */
static cache_status_t cache_entry_find(UNUSED rlm_cache_entry_t **out, void **rctx_out,
				       UNUSED rlm_cache_config_t const *config, void *instance,
				       request_t *request, UNUSED void *handle, fr_value_box_t const *key)
{
	rlm_cache_redis_t		*driver = instance;
	rlm_cache_redis_thread_t	*thread = talloc_get_type_abort(module_thread(driver->mi)->data, rlm_cache_redis_thread_t);
	rlm_cache_redis_rctx_t		*rctx;
	fr_redis_command_set_t		*cmds;
	int				cmd_len;
	fr_redis_async_rcode_t		ret;

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), rlm_cache_redis_rctx_t));
	MEM(cmds = fr_redis_command_set_alloc(rctx, request, NULL, NULL, NULL, false));
	rctx->cmds = cmds;
	rctx->key = key;
	rctx->cmd_str = talloc_zero_array(rctx, char *, 1);
	talloc_set_destructor(rctx, cache_redis_rctx_free);

	RDEBUG3("LRANGE %pV 0 -1", key);
	cmd_len = redisFormatCommand(&rctx->cmd_str[0], "LRANGE %b 0 -1", key->vb_strvalue, key->vb_length);
	if (cmd_len < 0) {
		RERROR("Failed formatting redis command");
	error:
		talloc_free(rctx);
		return CACHE_ERROR;
	}
	if (fr_redis_command_preformatted_add(cmds, rctx->cmd_str[0], cmd_len, cache_entry_find_results,
					      rctx) != FR_REDIS_PIPELINE_OK) goto error;

	rctx->cmd = fr_redis_async_cmd_start(rctx, request, &ret, thread->rtcluster, (uint8_t const *)key->vb_strvalue,
					     key->vb_length, cmds, false, NULL);
	REDIS_ASYNC_START_RCODE_PROCESS(ret, thread->rtcluster, thread->cw, thread->inst->coord_pair_reg,
					"Failed to enqueue Redis cache find commands", CACHE_ERROR)

	*rctx_out = rctx;
	return CACHE_YIELD;
}

static cache_status_t cache_entry_insert_resume(rlm_cache_entry_t **out, UNUSED rlm_cache_config_t const *config,
						void *instance, UNUSED request_t *request,
						UNUSED void *handle, void *rctx)
{
	rlm_cache_redis_t		*driver = instance;
	rlm_cache_redis_rctx_t		*cache_rctx = talloc_get_type_abort(rctx, rlm_cache_redis_rctx_t);

	*out = cache_rctx->entry;

	return cache_redis_results(request, driver, cache_rctx->cmds, cache_rctx->cmd, cache_rctx->rcode);
}

static void cache_entry_insert_results(request_t *request, UNUSED fr_redis_command_t *cmd, redisReply *reply, void *rctx)
{
	rlm_cache_redis_rctx_t		*cache_rctx = talloc_get_type_abort(rctx, rlm_cache_redis_rctx_t);

	RDEBUG3("Command results");
	RINDENT();
	fr_redis_reply_print(L_DBG_LVL_3, reply, request, 0, REDIS_RCODE_SUCCESS);
	REXDENT();

	cache_rctx->rcode = CACHE_OK;
}

/** Insert a new entry into the data store
 *
 * @copydetails cache_entry_insert_t
 */
static cache_status_t cache_entry_insert(UNUSED void **rctx_out, UNUSED rlm_cache_config_t const *config, void *instance,
					 request_t *request, UNUSED void *handle, const rlm_cache_entry_t *c)
{
	rlm_cache_redis_t		*driver = instance;
	rlm_cache_redis_thread_t	*thread = talloc_get_type_abort(module_thread(driver->mi)->data, rlm_cache_redis_thread_t);
	rlm_cache_redis_rctx_t		*rctx;
	fr_redis_command_set_t		*cmds;
	int				cmd_len;
	fr_redis_async_rcode_t		ret;

	TALLOC_CTX		*pool;

	map_t			*map = NULL;

	static char const	command[] = "RPUSH";
	char const		**argv;
	size_t			*argv_len;
	char const		**argv_p;
	size_t			*argv_len_p;
	size_t			i;

	int			cnt;

	tmpl_t		expires_value;
	map_t		expires = {
					.op	= T_OP_SET,
					.lhs	= driver->expires_attr,
					.rhs	= &expires_value,
				};

	tmpl_t		created_value;
	map_t		created = {
					.op	= T_OP_SET,
					.lhs	= driver->created_attr,
					.rhs	= &created_value,
				};

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), rlm_cache_redis_rctx_t));
	rctx->entry = UNCONST(rlm_cache_entry_t *, c);

	/*
	 *	Encode the entry created date
	 */
	tmpl_init_shallow(&created_value, TMPL_TYPE_DATA, T_BARE_WORD, "<TEMP>", 6, NULL);
	fr_value_box_init(&created_value.data.literal, FR_TYPE_DATE, NULL, true);
	tmpl_value(&created_value)->vb_date = c->created;

	/*
	 *	Encode the entry expiry time
	 *
	 *	Although Redis objects expire on their own, we still need this
	 *	to ignore entries that were created before the last epoch.
	 */
	tmpl_init_shallow(&expires_value, TMPL_TYPE_DATA, T_BARE_WORD, "<TEMP>", 6, NULL);
	fr_value_box_init(&expires_value.data.literal, FR_TYPE_DATE, NULL, true);
	tmpl_value(&expires_value)->vb_date = c->expires;

	cnt = map_list_num_elements(&c->maps) + 2;

	/*
	 *	The majority of serialized entries should be under 1k.
	 *
	 * @todo We should really calculate this using some sort of moving average.
	 */
	pool = talloc_pool(rctx, 1024);
	if (!pool) return CACHE_ERROR;

	argv_p = argv = talloc_array(pool, char const *, (cnt * 3) + 2);	/* pair = 3 + cmd + key */
	argv_len_p = argv_len = talloc_array(pool, size_t, (cnt * 3) + 2);	/* pair = 3 + cmd + key */

	*argv_p++ = command;
	*argv_len_p++ = sizeof(command) - 1;

	*argv_p++ = (char const *)c->key.vb_strvalue;
	*argv_len_p++ = c->key.vb_length;

	/*
	 *	Add the maps to the command string in reverse order
	 */
	if (fr_redis_tuple_from_map(pool, argv_p, argv_len_p, &created) < 0) {
		REDEBUG("Failed encoding map as Redis K/V pair");
		talloc_free(rctx);
		return CACHE_ERROR;
	}
	argv_p += 3;
	argv_len_p += 3;
	if (fr_redis_tuple_from_map(pool, argv_p, argv_len_p, &expires) < 0) {
		REDEBUG("Failed encoding map as Redis K/V pair");
		talloc_free(rctx);
		return CACHE_ERROR;
	}
	argv_p += 3;
	argv_len_p += 3;
	while ((map = map_list_next(&c->maps, map))) {
		if (fr_redis_tuple_from_map(pool, argv_p, argv_len_p, map) < 0) {
			REDEBUG("Failed encoding map as Redis K/V pair");
			talloc_free(rctx);
			return CACHE_ERROR;
		}
		argv_p += 3;
		argv_len_p += 3;
	}

	MEM(cmds = fr_redis_command_set_alloc(rctx, request, NULL, NULL, NULL, false));
	rctx->cmds = cmds;
	rctx->key = &c->key;
	MEM(rctx->cmd_str = talloc_zero_array(rctx, char *, 3));
	talloc_set_destructor(rctx, cache_redis_rctx_free);

	RDEBUG3("Pipelining commands");

	if (fr_unix_time_ispos(c->expires)) {
		RDEBUG3("MULTI");
		if (fr_redis_command_literal_add(cmds, "MULTI", NULL, NULL) != FR_REDIS_PIPELINE_OK) {
		error:
			talloc_free(rctx);
			return CACHE_ERROR;
		};
	}

	RDEBUG3("DEL \"%pV\"", &c->key);
	cmd_len = redisFormatCommand(&rctx->cmd_str[0], "DEL %b", (uint8_t const *)c->key.vb_strvalue, c->key.vb_length);
	if (cmd_len < 0) {
	format_error:
		RERROR("Failed formatting redis command");
		goto error;
	}
	if (fr_redis_command_preformatted_add(cmds, rctx->cmd_str[0], cmd_len, NULL,
					      NULL) != FR_REDIS_PIPELINE_OK) goto error;

	if (RDEBUG_ENABLED3) {
		RDEBUG3("argv command");
		RINDENT();
		for (i = 0; i < talloc_array_length(argv); i++) {
			RDEBUG3("%pV", fr_box_strvalue_len(argv[i], argv_len[i]));
		}
		REXDENT();
	}
	cmd_len = redisFormatCommandArgv(&rctx->cmd_str[1], talloc_array_length(argv), argv, argv_len);
	if (cmd_len < 0) goto format_error;

	if (fr_unix_time_ispos(c->expires)) {
		if (fr_redis_command_preformatted_add(cmds, rctx->cmd_str[1], cmd_len, NULL,
						      NULL) != FR_REDIS_PIPELINE_OK) goto error;

		RDEBUG3("EXPIREAT \"%pV\" %" PRIu64, &c->key, fr_unix_time_to_sec(c->expires));
		cmd_len = redisFormatCommand(&rctx->cmd_str[2], "EXPIREAT %b %" PRIu64,
					     (uint8_t const *)c->key.vb_strvalue, (size_t)c->key.vb_length,
					     fr_unix_time_to_sec(c->expires));
		if (cmd_len < 0) goto format_error;
		if (fr_redis_command_preformatted_add(cmds, rctx->cmd_str[2], cmd_len, NULL,
						      NULL) != FR_REDIS_PIPELINE_OK) goto error;

		RDEBUG3("EXEC");
		if (fr_redis_command_literal_add(cmds, "EXEC", cache_entry_insert_results,
						 rctx) != FR_REDIS_PIPELINE_OK) goto error;
	} else {
		if (fr_redis_command_preformatted_add(cmds, rctx->cmd_str[1], cmd_len, cache_entry_insert_results,
						      rctx) != FR_REDIS_PIPELINE_OK) goto error;
	}

	rctx->cmd = fr_redis_async_cmd_start(rctx, request, &ret, thread->rtcluster, (uint8_t const *)c->key.vb_strvalue,
					     c->key.vb_length, cmds, false, NULL);
	REDIS_ASYNC_START_RCODE_PROCESS(ret, thread->rtcluster, thread->cw, thread->inst->coord_pair_reg,
					"Failed to enqueue Redis cache insert commands", CACHE_ERROR)

	*rctx_out = rctx;
	return CACHE_YIELD;
}

static cache_status_t cache_entry_expire_resume(UNUSED rlm_cache_config_t const *config, void *instance,
						UNUSED request_t *request, UNUSED void *handle, void *rctx)
{
	rlm_cache_redis_t	*driver = instance;
	rlm_cache_redis_rctx_t	*cache_rctx = talloc_get_type_abort(rctx, rlm_cache_redis_rctx_t);

	return cache_redis_results(request, driver, cache_rctx->cmds, cache_rctx->cmd, cache_rctx->rcode);
}

static void cache_entry_expire_results(request_t *request, UNUSED fr_redis_command_t *cmd, redisReply *reply, void *rctx)
{
	rlm_cache_redis_rctx_t	*cache_rctx = talloc_get_type_abort(rctx, rlm_cache_redis_rctx_t);

	if (reply->type == REDIS_REPLY_INTEGER) {
		cache_rctx->rcode = (reply->integer) ? CACHE_OK : CACHE_MISS;
		return;
	}

	REDEBUG("Bad result type, expected integer, got %s",
		fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));

	cache_rctx->rcode = CACHE_ERROR;
}

/** Call delete the cache entry from redis
 *
 * @copydetails cache_entry_expire_t
 */
static cache_status_t cache_entry_expire(UNUSED void **rctx_out, UNUSED rlm_cache_config_t const *config, void *instance,
					 request_t *request, UNUSED void *handle, fr_value_box_t const *key)
{
	rlm_cache_redis_t		*driver = instance;
	rlm_cache_redis_thread_t	*thread = talloc_get_type_abort(module_thread(driver->mi)->data, rlm_cache_redis_thread_t);
	rlm_cache_redis_rctx_t		*rctx;
	fr_redis_command_set_t		*cmds;
	int				cmd_len;
	fr_redis_async_rcode_t		ret;

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), rlm_cache_redis_rctx_t));
	MEM(cmds = fr_redis_command_set_alloc(rctx, request, NULL, NULL, NULL, false));
	rctx->cmds = cmds;
	rctx->key = key;
	rctx->cmd_str = talloc_zero_array(rctx, char *, 1);
	talloc_set_destructor(rctx, cache_redis_rctx_free);

	cmd_len = redisFormatCommand(&rctx->cmd_str[0], "DEL %b", (uint8_t const *)key->vb_strvalue, key->vb_length);
	if (cmd_len < 0) {
		RERROR("Failed formatting redis command");
	error:
		talloc_free(rctx);
		return CACHE_ERROR;
	}
	if (fr_redis_command_preformatted_add(cmds, rctx->cmd_str[0], cmd_len, cache_entry_expire_results,
					      rctx) != FR_REDIS_PIPELINE_OK) goto error;

	rctx->cmd = fr_redis_async_cmd_start(rctx, request, &ret, thread->rtcluster, (uint8_t const *)key->vb_strvalue,
					     key->vb_length, cmds, false, NULL);
	REDIS_ASYNC_START_RCODE_PROCESS(ret, thread->rtcluster, thread->cw, thread->inst->coord_pair_reg,
					"Failed to enqueue Redis cache expire command", CACHE_ERROR)

	*rctx_out = rctx;
	return CACHE_YIELD;
}

extern rlm_cache_driver_t rlm_cache_redis;
rlm_cache_driver_t rlm_cache_redis = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "cache_redis",
		.onload		= mod_load,
		.instantiate	= mod_instantiate,
		.coord_attach	= mod_coord_attach,
		.detach		= mod_detach,
		.inst_size	= sizeof(rlm_cache_redis_t),
		MODULE_THREAD_INST(rlm_cache_redis_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
		.config		= driver_config,
	},
	.free		= cache_entry_free,
	.find		= cache_entry_find,
	.find_resume	= cache_entry_find_resume,
	.find_cancel	= cache_redis_cancel,
	.insert		= cache_entry_insert,
	.insert_resume	= cache_entry_insert_resume,
	.insert_cancel	= cache_redis_cancel,
	.expire		= cache_entry_expire,
	.expire_resume	= cache_entry_expire_resume,
	.expire_cancel	= cache_redis_cancel,
};
