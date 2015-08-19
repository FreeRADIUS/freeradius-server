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
#include <libmemcached/memcached.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include "../../rlm_cache.h"
#include "../../serialize.h"

typedef struct rlm_cache_memcached_handle {
	memcached_st *handle;
} rlm_cache_memcached_handle_t;

typedef struct rlm_cache_memcached {
	char const 		*options;	//!< Connection options
	fr_connection_pool_t	*pool;
} rlm_cache_memcached_t;

static const CONF_PARSER driver_config[] = {
	{ "options", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_cache_memcached_t, options), "--SERVER=localhost" },
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
 * @param ctx to allocate handle in.
 * @param instance data.
 */
static void *mod_conn_create(TALLOC_CTX *ctx, void *instance)
{
	rlm_cache_t			*inst = instance;
	rlm_cache_memcached_t		*driver = inst->driver;
	rlm_cache_memcached_handle_t	*mandle;

	memcached_st			*sandle;
	memcached_return_t		ret;

	sandle = memcached(driver->options, talloc_array_length(driver->options) -1);
	if (!sandle) {
		ERROR("rlm_cache_memcached: Failed creating memcached connection");

		return NULL;
	}

	ret = memcached_version(sandle);
	if (ret != MEMCACHED_SUCCESS) {
		ERROR("rlm_cache_memcached: Failed getting server info: %s: %s", memcached_strerror(sandle, ret),
		      memcached_last_error_message(sandle));
		memcached_free(sandle);
		return NULL;
	}

	mandle = talloc_zero(ctx, rlm_cache_memcached_handle_t);
	mandle->handle = sandle;
	talloc_set_destructor(mandle, _mod_conn_free);

	return mandle;
}

/** Cleanup a rlm_cache_memcached instance
 *
 * @param driver to free.
 * @return 0
 */
static int _mod_detach(rlm_cache_memcached_t *driver)
{
	fr_connection_pool_free(driver->pool);
	return 0;
}

/** Create a new rlm_cache_memcached instance
 *
 * @param conf memcached specific conf section.
 * @param inst main rlm_cache instance.
 * @return 0 on success, -1 on failure.
 */
static int mod_instantiate(CONF_SECTION *conf, rlm_cache_t *inst)
{
	rlm_cache_memcached_t *driver;
	memcached_return_t ret;

	char buffer[256];

	static bool version_done;

	buffer[0] = '\0';

	/*
	 *	Get version info from the libmemcached API.
	 */
	if (!version_done) {
		version_done = true;

		INFO("rlm_cache_memcached: libmemcached version: %s", memcached_lib_version());
	}

	driver = talloc_zero(inst, rlm_cache_memcached_t);
	talloc_set_destructor(driver, _mod_detach);

	if (cf_section_parse(conf, driver, driver_config) < 0) return -1;

	ret = libmemcached_check_configuration(driver->options, talloc_array_length(driver->options) -1,
					       buffer, sizeof(buffer));
	if (ret != MEMCACHED_SUCCESS) {
		ERROR("rlm_cache_memcached: Failed validating options string: %s", buffer);
		return -1;
	}

	inst->driver = driver;

	snprintf(buffer, sizeof(buffer), "rlm_cache (%s)", inst->name);

	driver->pool = fr_connection_pool_module_init(conf, inst, mod_conn_create, NULL, buffer);
	if (!driver->pool) return -1;

	if (inst->max_entries > 0) WARN("rlm_cache_memcached: max_entries is not supported by this driver");

	return 0;
}

static void cache_entry_free(rlm_cache_entry_t *c)
{
	talloc_free(c);
}

/** Locate a cache entry in memcached
 *
 * @param out Where to write the pointer to the cach entry.
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Pointer to memcached handle.
 * @param key to search for.
 * @return CACHE_OK on success CACHE_MISS if no entry found, CACHE_ERROR on error.
 */
static cache_status_t cache_entry_find(rlm_cache_entry_t **out, UNUSED rlm_cache_t *inst, REQUEST *request,
				       rlm_cache_handle_t **handle, char const *key)
{
	rlm_cache_memcached_handle_t *mandle = *handle;

	memcached_return_t mret;
	size_t len;
	int ret;
	uint32_t flags;

	char *from_store;

	rlm_cache_entry_t *c;

	from_store = memcached_get(mandle->handle, key, strlen(key), &len, &flags, &mret);
	if (!from_store) {
		if (mret == MEMCACHED_NOTFOUND) return CACHE_MISS;

		RERROR("Failed retrieving entry for key \"%s\": %s: %s", key, memcached_strerror(mandle->handle, mret),
		       memcached_last_error_message(mandle->handle));

		return CACHE_ERROR;
	}
	RDEBUG2("Retrieved %zu bytes from memcached", len);
	RDEBUG2("%s", from_store);

	c = talloc_zero(NULL,  rlm_cache_entry_t);
	ret = cache_deserialize(c, from_store, len);
	free(from_store);
	if (ret < 0) {
		RERROR("%s", fr_strerror());
		talloc_free(c);
		return CACHE_ERROR;
	}
	c->key = talloc_strdup(c, key);
	*out = c;

	return CACHE_OK;
}

/** Insert a new entry into the data store
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Pointer to memcached handle.
 * @param c entry to insert.
 * @return CACHE_OK on success else CACHE_ERROR on error.
 */
static cache_status_t cache_entry_insert(UNUSED rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle,
					 rlm_cache_entry_t *c)
{
	rlm_cache_memcached_handle_t *mandle = *handle;

	memcached_return_t ret;

	TALLOC_CTX *pool;
	char *to_store;

	pool = talloc_pool(NULL, 1024);
	if (!pool) return CACHE_ERROR;

	if (cache_serialize(pool, &to_store, c) < 0) {
		talloc_free(pool);

		return CACHE_ERROR;
	}

	ret = memcached_set(mandle->handle, c->key, talloc_array_length(c->key) - 1,
		            to_store ? to_store : "",
		            to_store ? talloc_array_length(to_store) - 1 : 0, c->expires, 0);
	talloc_free(pool);
	if (ret != MEMCACHED_SUCCESS) {
		RERROR("Failed storing entry with key \"%s\": %s: %s", c->key,
		       memcached_strerror(mandle->handle, ret),
		       memcached_last_error_message(mandle->handle));

		return CACHE_ERROR;
	}

	return CACHE_OK;
}

/** Call delete the cache entry from memcached
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Pointer to memcached handle.
 * @param c entry to expire.
 * @return CACHE_OK on success else CACHE_ERROR.
 */
static cache_status_t cache_entry_expire(UNUSED rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle,
					 rlm_cache_entry_t *c)
{
	rlm_cache_memcached_handle_t *mandle = *handle;

	memcached_return_t ret;

	ret = memcached_delete(mandle->handle, c->key, talloc_array_length(c->key) - 1, 0);
	if (ret != MEMCACHED_SUCCESS) {
		RERROR("Failed deleting entry with key \"%s\": %s", c->key,
		       memcached_last_error_message(mandle->handle));

		return CACHE_ERROR;
	}

	return CACHE_OK;
}

/** Get a memcached handle
 *
 * @param out Where to write the handle.
 * @param inst rlm_cache instance.
 * @param request The current request.
 */
static int mod_conn_get(rlm_cache_handle_t **out, rlm_cache_t *inst, UNUSED REQUEST *request)
{
	rlm_cache_memcached_t *driver = inst->driver;
	rlm_cache_handle_t *mandle;

	*out = NULL;

	mandle = fr_connection_get(driver->pool);
	if (!mandle) {
		*out = NULL;
		return -1;
	}
	*out = mandle;

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
	rlm_cache_memcached_t *driver = inst->driver;

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
	rlm_cache_memcached_t *driver = inst->driver;
	rlm_cache_handle_t *mandle;

	mandle = fr_connection_reconnect(driver->pool, *handle);
	if (!mandle) {
		*handle = NULL;
		return -1;
	}
	*handle = mandle;

	return 0;
}

extern cache_module_t rlm_cache_memcached;
cache_module_t rlm_cache_memcached = {
	.name		= "rlm_cache_memcached",
	.instantiate	= mod_instantiate,
	.free		= cache_entry_free,

	.find		= cache_entry_find,
	.insert		= cache_entry_insert,
	.expire		= cache_entry_expire,

	.acquire	= mod_conn_get,
	.release	= mod_conn_release,
	.reconnect	= mod_conn_reconnect
};
