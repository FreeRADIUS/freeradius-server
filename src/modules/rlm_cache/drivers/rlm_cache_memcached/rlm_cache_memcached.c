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
 * @file rlm_cache_memcached.c
 * @brief memcached based cache.
 *
 * @copyright 2014 The FreeRADIUS server project
 */

#define LOG_PREFIX "cache - memcached"

#include <libmemcached/memcached.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/slab.h>
#include <freeradius-devel/util/value.h>

#include "../../rlm_cache.h"
#include "../../serialize.h"

typedef struct {
	memcached_st *handle;
} rlm_cache_memcached_handle_t;

FR_SLAB_TYPES(memcached, rlm_cache_memcached_handle_t)
FR_SLAB_FUNCS(memcached, rlm_cache_memcached_handle_t)

typedef struct {
	char const 		*options;	//!< Connection options
	module_instance_t const	*mi;
	fr_time_delta_t		timeout;
	fr_slab_config_t	reuse;
} rlm_cache_memcached_t;

typedef struct {
	rlm_cache_memcached_t const	*inst;
	memcached_slab_list_t		*slab;
} rlm_cache_memcached_thread_t;

static conf_parser_t reuse_memcached_config[] = {
	FR_SLAB_CONFIG_CONF_PARSER
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t driver_config[] = {
	{ FR_CONF_OFFSET("options", rlm_cache_memcached_t, options), .dflt = "--SERVER=localhost" },
	{ FR_CONF_OFFSET("timeout", rlm_cache_memcached_t, timeout), .dflt = "3.0" },
	{ FR_CONF_OFFSET_SUBSECTION("reuse", 0, rlm_cache_memcached_t, reuse, reuse_memcached_config) },
	CONF_PARSER_TERMINATOR
};

/** Free a connection handle
 *
 * @param mandle to free.
 */
static int _mod_conn_free(rlm_cache_memcached_handle_t *mandle)
{
	if (mandle->handle) memcached_free(mandle->handle);

	return 0;
}

/** Create a new memcached handle
 *
 */
static int memcached_conn_init(rlm_cache_memcached_handle_t *mandle, void *uctx)
{
	rlm_cache_memcached_t	*driver = talloc_get_type_abort(uctx, rlm_cache_memcached_t);
	memcached_st		*sandle;
	memcached_return_t	ret;

	sandle = memcached(driver->options, talloc_array_length(driver->options) -1);
	if (!sandle) {
		ERROR("Failed creating memcached connection");
		return -1;
	}

	ret = memcached_behavior_set(sandle, MEMCACHED_BEHAVIOR_CONNECT_TIMEOUT, fr_time_delta_to_msec(driver->timeout));
	if (ret != MEMCACHED_SUCCESS) {
		ERROR("%s: %s", memcached_strerror(sandle, ret), memcached_last_error_message(sandle));
	error:
		memcached_free(sandle);
		return -1;
	}

	ret = memcached_version(sandle);
	if (ret != MEMCACHED_SUCCESS) {
		ERROR("%s: %s", memcached_strerror(sandle, ret), memcached_last_error_message(sandle));
		goto error;
	}

	mandle->handle = sandle;
	talloc_set_destructor(mandle, _mod_conn_free);

	return 0;
}

/** Create a new rlm_cache_memcached instance
 *
 * @param[in] mctx		Data required for instantiation.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_cache_memcached_t		*driver = talloc_get_type_abort(mctx->mi->data, rlm_cache_memcached_t);
	memcached_return_t		ret;
	char				buffer[256];
	rlm_cache_t const		*inst = talloc_get_type_abort(mctx->mi->parent->data, rlm_cache_t);

	ret = libmemcached_check_configuration(driver->options, talloc_array_length(driver->options) -1,
					       buffer, sizeof(buffer));
	if (ret != MEMCACHED_SUCCESS) {
		ERROR("%s", buffer);
		return -1;
	}

	if (inst->config.max_entries > 0) {
		ERROR("max_entries is not supported by this driver");
		return -1;
	}

	driver->mi = mctx->mi;
	return 0;
}

static int mod_load(void)
{
	INFO("%s", memcached_lib_version());
	return 0;
}

/** Locate a cache entry in memcached
 *
 * @copydetails cache_entry_free_t
 */
static void cache_entry_free(rlm_cache_entry_t *c)
{
	talloc_free(c);
}

/** Locate a cache entry in memcached
 *
 * @copydetails cache_entry_find_t
 */
static cache_status_t cache_entry_find(rlm_cache_entry_t **out,
				       UNUSED rlm_cache_config_t const *config, UNUSED void *instance,
				       request_t *request, void *handle, fr_value_box_t const *key)
{
	rlm_cache_memcached_handle_t *mandle = handle;

	memcached_return_t	mret;
	size_t			len;
	int			ret;
	uint32_t		flags;

	char			*from_store;

	rlm_cache_entry_t	*c;

	from_store = memcached_get(mandle->handle, (char const *)key->vb_strvalue, key->vb_length, &len, &flags, &mret);
	if (!from_store) {
		if (mret == MEMCACHED_NOTFOUND) return CACHE_MISS;

		RERROR("Failed retrieving entry: %s: %s", memcached_strerror(mandle->handle, mret),
		       memcached_last_error_message(mandle->handle));

		return memcached_fatal(mret) ? CACHE_RECONNECT : CACHE_ERROR;
	}
	RDEBUG2("Retrieved %zu bytes from memcached", len);
	RDEBUG2("%s", from_store);

	MEM(c = talloc_zero(NULL, rlm_cache_entry_t));
	map_list_init(&c->maps);
	ret = cache_deserialize(request, c, request->dict, from_store, len);
	free(from_store);
	if (ret < 0) {
		RPERROR("Invalid entry");
	error:
		talloc_free(c);
		return CACHE_ERROR;
	}
	if (unlikely(fr_value_box_copy(c, &c->key, key) < 0)) {
		RERROR("Failed copying key");
		goto error;
	}

	*out = c;

	return CACHE_OK;
}

/** Insert a new entry into the data store
 *
 * @copydetails cache_entry_insert_t
 */
static cache_status_t cache_entry_insert(UNUSED rlm_cache_config_t const *config, UNUSED void *instance,
					 request_t *request, void *handle, const rlm_cache_entry_t *c)
{
	rlm_cache_memcached_handle_t *mandle = handle;

	memcached_return_t ret;

	TALLOC_CTX *pool;
	char *to_store;

	pool = talloc_pool(NULL, 1024);
	if (!pool) return CACHE_ERROR;

	if (cache_serialize(pool, &to_store, c) < 0) {
		talloc_free(pool);

		return CACHE_ERROR;
	}

	ret = memcached_set(mandle->handle, (char const *)c->key.vb_strvalue, c->key.vb_length,
		            to_store ? to_store : "",
		            to_store ? talloc_array_length(to_store) - 1 : 0, fr_unix_time_to_sec(c->expires), 0);
	talloc_free(pool);
	if (ret != MEMCACHED_SUCCESS) {
		RERROR("Failed storing entry: %s: %s", memcached_strerror(mandle->handle, ret),
		       memcached_last_error_message(mandle->handle));

		return memcached_fatal(ret) ? CACHE_RECONNECT : CACHE_ERROR;
	}

	return CACHE_OK;
}

/** Call delete the cache entry from memcached
 *
 * @copydetails cache_entry_expire_t
 */
static cache_status_t cache_entry_expire(UNUSED rlm_cache_config_t const *config, UNUSED void *instance,
					 request_t *request, void *handle, fr_value_box_t const *key)
{
	rlm_cache_memcached_handle_t *mandle = handle;

	memcached_return_t ret;

	ret = memcached_delete(mandle->handle, (char const *)key->vb_strvalue, key->vb_length, 0);
	switch (ret) {
	case MEMCACHED_SUCCESS:
		return CACHE_OK;

	case MEMCACHED_DATA_DOES_NOT_EXIST:
		return CACHE_MISS;

	default:
		RERROR("Failed deleting entry: %s", memcached_last_error_message(mandle->handle));
		return memcached_fatal(ret) ? CACHE_RECONNECT : CACHE_ERROR;
	}
}

/** Get a memcached handle
 *
 * @copydetails cache_acquire_t
 */
static int mod_conn_get(void **handle, UNUSED rlm_cache_config_t const *config, void *instance,
			UNUSED request_t *request)
{
	rlm_cache_memcached_t		*driver = instance;
	rlm_cache_handle_t		*mandle;
	rlm_cache_memcached_thread_t	*t = talloc_get_type_abort(module_thread(driver->mi)->data, rlm_cache_memcached_thread_t);

	mandle = memcached_slab_reserve(t->slab);
	if (!mandle) {
		*handle = NULL;
		return -1;
	}
	*handle = mandle;

	return 0;
}

/** Release a memcached handle
 *
 * @copydetails cache_release_t
 */
static void mod_conn_release(UNUSED rlm_cache_config_t const *config, UNUSED void *instance,
			     UNUSED request_t *request, rlm_cache_handle_t *handle)
{
	memcached_slab_release(handle);
}

/** Reconnect a memcached handle
 *
 * @copydetails cache_reconnect_t
 */
static int mod_conn_reconnect(void **handle, UNUSED rlm_cache_config_t const *config, void *instance,
			      UNUSED request_t *request)
{
	rlm_cache_memcached_t		*driver = instance;
	rlm_cache_memcached_thread_t	*t = talloc_get_type_abort(module_thread(driver->mi)->data, rlm_cache_memcached_thread_t);
	rlm_cache_handle_t		*mandle;

	talloc_free(*handle);
	mandle = memcached_slab_reserve(t->slab);
	if (!mandle) {
		*handle = NULL;
		return -1;
	}
	*handle = mandle;

	return 0;
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_cache_memcached_t const	*inst = talloc_get_type_abort(mctx->mi->data, rlm_cache_memcached_t);
	rlm_cache_memcached_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_cache_memcached_thread_t);

	t->inst = inst;
	if (!(t->slab = memcached_slab_list_alloc(t, mctx->el, &inst->reuse, memcached_conn_init, NULL,
						  UNCONST(void *, inst), false, false))) {
		ERROR("Connection handle pool instantiation failed");
		return -1;
	}

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_cache_memcached_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_cache_memcached_thread_t);
	talloc_free(t->slab);
	return 0;
}

extern rlm_cache_driver_t rlm_cache_memcached;
rlm_cache_driver_t rlm_cache_memcached = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "cache_memcached",
		.inst_size	= sizeof(rlm_cache_memcached_t),
		.config		= driver_config,

		.onload		= mod_load,
		.instantiate	= mod_instantiate,
		.thread_inst_size	= sizeof(rlm_cache_memcached_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
	},

	.free		= cache_entry_free,

	.find		= cache_entry_find,
	.insert		= cache_entry_insert,
	.expire		= cache_entry_expire,

	.acquire	= mod_conn_get,
	.release	= mod_conn_release,
	.reconnect	= mod_conn_reconnect
};
