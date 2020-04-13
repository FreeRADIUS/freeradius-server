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

#define LOG_PREFIX "rlm_cache_memcached - "

#include <libmemcached/memcached.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/util/debug.h>

#include "../../rlm_cache.h"
#include "../../serialize.h"

typedef struct {
	memcached_st *handle;
} rlm_cache_memcached_handle_t;

typedef struct {
	char const 		*options;	//!< Connection options
	fr_pool_t	*pool;
} rlm_cache_memcached_t;

static const CONF_PARSER driver_config[] = {
	{ FR_CONF_OFFSET("options", FR_TYPE_STRING | FR_TYPE_REQUIRED, rlm_cache_memcached_t, options), .dflt = "--SERVER=localhost" },
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
static void *mod_conn_create(TALLOC_CTX *ctx, void *instance, fr_time_delta_t timeout)
{
	rlm_cache_memcached_t		*driver = instance;
	rlm_cache_memcached_handle_t	*mandle;

	memcached_st			*sandle;
	memcached_return_t		ret;

	sandle = memcached(driver->options, talloc_array_length(driver->options) -1);
	if (!sandle) {
		ERROR("Failed creating memcached connection");

		return NULL;
	}

	ret = memcached_behavior_set(sandle, MEMCACHED_BEHAVIOR_CONNECT_TIMEOUT, fr_time_delta_to_msec(timeout));
	if (ret != MEMCACHED_SUCCESS) {
		ERROR("%s: %s", memcached_strerror(sandle, ret), memcached_last_error_message(sandle));
	error:
		memcached_free(sandle);
		return NULL;
	}

	ret = memcached_version(sandle);
	if (ret != MEMCACHED_SUCCESS) {
		ERROR("%s: %s", memcached_strerror(sandle, ret), memcached_last_error_message(sandle));
		goto error;
	}

	mandle = talloc_zero(ctx, rlm_cache_memcached_handle_t);
	mandle->handle = sandle;
	talloc_set_destructor(mandle, _mod_conn_free);

	return mandle;
}

/** Create a new rlm_cache_memcached instance
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
	rlm_cache_memcached_t		*driver = instance;
	memcached_return_t		ret;
	char				buffer[256];
	rlm_cache_config_t const	*config = dl_module_parent_data_by_child_data(instance);

	fr_assert(config);

	snprintf(buffer, sizeof(buffer), "rlm_cache (%s)", config->name);

	ret = libmemcached_check_configuration(driver->options, talloc_array_length(driver->options) -1,
					       buffer, sizeof(buffer));
	if (ret != MEMCACHED_SUCCESS) {
		ERROR("%s", buffer);
		return -1;
	}

	driver->pool = module_connection_pool_init(conf, driver, mod_conn_create, NULL,
						   buffer, "modules.rlm_cache.pool", NULL);
	if (!driver->pool) return -1;

	talloc_link_ctx(driver, driver->pool);	/* Ensure pool is freed */

	if (config->max_entries > 0) {
		ERROR("max_entries is not supported by this driver");
		return -1;
	}
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
				       REQUEST *request, void *handle, uint8_t const *key, size_t key_len)
{
	rlm_cache_memcached_handle_t *mandle = handle;

	memcached_return_t	mret;
	size_t			len;
	int			ret;
	uint32_t		flags;

	char			*from_store;

	rlm_cache_entry_t	*c;

	from_store = memcached_get(mandle->handle, (char const *)key, key_len, &len, &flags, &mret);
	if (!from_store) {
		if (mret == MEMCACHED_NOTFOUND) return CACHE_MISS;

		RERROR("Failed retrieving entry: %s: %s", memcached_strerror(mandle->handle, mret),
		       memcached_last_error_message(mandle->handle));

		return CACHE_ERROR;
	}
	RDEBUG2("Retrieved %zu bytes from memcached", len);
	RDEBUG2("%s", from_store);

	c = talloc_zero(NULL, rlm_cache_entry_t);
	ret = cache_deserialize(c, request->dict, from_store, len);
	free(from_store);
	if (ret < 0) {
		RPERROR("Invalid entry");
		talloc_free(c);
		return CACHE_ERROR;
	}
	c->key = talloc_memdup(c, key, key_len);
	c->key_len = key_len;

	*out = c;

	return CACHE_OK;
}

/** Insert a new entry into the data store
 *
 * @copydetails cache_entry_insert_t
 */
static cache_status_t cache_entry_insert(UNUSED rlm_cache_config_t const *config, UNUSED void *instance,
					 REQUEST *request, void *handle, const rlm_cache_entry_t *c)
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

	ret = memcached_set(mandle->handle, (char const *)c->key, c->key_len,
		            to_store ? to_store : "",
		            to_store ? talloc_array_length(to_store) - 1 : 0, c->expires, 0);
	talloc_free(pool);
	if (ret != MEMCACHED_SUCCESS) {
		RERROR("Failed storing entry: %s: %s", memcached_strerror(mandle->handle, ret),
		       memcached_last_error_message(mandle->handle));

		return CACHE_ERROR;
	}

	return CACHE_OK;
}

/** Call delete the cache entry from memcached
 *
 * @copydetails cache_entry_expire_t
 */
static cache_status_t cache_entry_expire(UNUSED rlm_cache_config_t const *config, UNUSED void *instance,
					 REQUEST *request, void *handle, uint8_t const *key, size_t key_len)
{
	rlm_cache_memcached_handle_t *mandle = handle;

	memcached_return_t ret;

	ret = memcached_delete(mandle->handle, (char const *)key, key_len, 0);
	switch (ret) {
	case MEMCACHED_SUCCESS:
		return CACHE_OK;

	case MEMCACHED_DATA_DOES_NOT_EXIST:
		return CACHE_MISS;

	default:
		RERROR("Failed deleting entry: %s", memcached_last_error_message(mandle->handle));
		return CACHE_ERROR;
	}
}

/** Get a memcached handle
 *
 * @copydetails cache_acquire_t
 */
static int mod_conn_get(void **handle, UNUSED rlm_cache_config_t const *config, void *instance,
			REQUEST *request)
{
	rlm_cache_memcached_t *driver = instance;
	rlm_cache_handle_t *mandle;

	*handle = NULL;

	mandle = fr_pool_connection_get(driver->pool, request);
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
static void mod_conn_release(UNUSED rlm_cache_config_t const *config, void *instance,
			     REQUEST *request, rlm_cache_handle_t *handle)
{
	rlm_cache_memcached_t *driver = instance;

	fr_pool_connection_release(driver->pool, request, handle);
}

/** Reconnect a memcached handle
 *
 * @copydetails cache_reconnect_t
 */
static int mod_conn_reconnect(void **handle, UNUSED rlm_cache_config_t const *config, void *instance,
			      REQUEST *request)
{
	rlm_cache_memcached_t *driver = instance;
	rlm_cache_handle_t *mandle;

	mandle = fr_pool_connection_reconnect(driver->pool, request, *handle);
	if (!mandle) {
		*handle = NULL;
		return -1;
	}
	*handle = mandle;

	return 0;
}

extern rlm_cache_driver_t rlm_cache_memcached;
rlm_cache_driver_t rlm_cache_memcached = {
	.name		= "rlm_cache_memcached",
	.magic		= RLM_MODULE_INIT,
	.inst_size	= sizeof(rlm_cache_memcached_t),
	.config		= driver_config,

	.onload		= mod_load,
	.instantiate	= mod_instantiate,

	.free		= cache_entry_free,

	.find		= cache_entry_find,
	.insert		= cache_entry_insert,
	.expire		= cache_entry_expire,

	.acquire	= mod_conn_get,
	.release	= mod_conn_release,
	.reconnect	= mod_conn_reconnect
};
