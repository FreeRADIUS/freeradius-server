/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
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

typedef struct rlm_cache_memcached_handle {
	memcached_st *handle;
} rlm_cache_memcached_handle_t;

typedef struct rlm_cache_memcached {
	char const 		*options;	//!< Connection options
	fr_connection_pool_t	*pool;
} rlm_cache_memcached_t;

static const CONF_PARSER driver_config[] = {
	{ "options", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_cache_memcached_t, options), "--SERVER=localhost" },

	{NULL, -1, 0, NULL, NULL}
};

static int _mod_conn_free(rlm_cache_memcached_handle_t *mandle)
{
	if (mandle->handle) memcached_free(mandle->handle);

	return 0;
}

/** Create a new memcached handle
 *
 *
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

	ret = memcached_version(mandle->handle);
	if (ret != MEMCACHED_SUCCESS) {
		ERROR("rlm_cache_memcached: Failed getting server info: %s: %s", memcached_strerror(sandle, ret),
		      memcached_last_error_message(mandle->handle));
		memcached_free(sandle);
		return NULL;
	}

	mandle = talloc_zero(ctx, rlm_cache_memcached_handle_t);
	mandle->handle = sandle;
	talloc_set_destructor(mandle, _mod_conn_free);

	return mandle;
}

/** Cleanup a cache_memcached instance
 *
 * @param driver to free.
 * @return 0
 */
static int _mod_detach(rlm_cache_memcached_t *driver)
{
	return 0;
}

/** Create a new cache_memcached instance
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

	snprintf(buffer, sizeof(buffer), "rlm_cache (%s)", inst->xlat_name);

	driver->pool = fr_connection_pool_module_init(conf, inst, mod_conn_create, NULL, buffer);
	if (!driver->pool) return -1;

	if (inst->max_entries > 0) WARN("rlm_cache_memcached: max_entries is not supported by this driver");

	return 0;
}

/** Locate a cache entry
*
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Dummy handle (not used).
 * @param key to search for.
 * @return CACHE_OK on success CACHE_MISS if no entry found, CACHE_ERROR on error.
 */
static cache_status_t cache_entry_find(rlm_cache_entry_t **out, rlm_cache_t *inst, REQUEST *request,
				       rlm_cache_handle_t **handle, char const *key)
{
	rlm_cache_memcached_t *driver = inst->driver;
	rlm_cache_memcached_handle_t *mandle = *handle;

	size_t len;
	ssize_t slen;

	memcached_return_t ret;
	uint32_t flags;
	value_pair_tmpl_t *tmpl;

	TALLOC_CTX *store = NULL;
	char *from_store, const *p;

	rlm_cache_entry_t *c;

	from_store = memcached_get(mandle->handle, key, strlen(key), len, &flags, &ret);
	if (!from_store) {
		RERROR("Failed retrieving entry for key \"%s\": %s: %s", libmemcached_strerror(ret),
		       memcached_last_error_message(mandle->handle));

		return CACHE_ERROR;
	}



	c = talloc_zero(request, rlm_cache_entry_t);
	if (!c) return CACHE_ERROR;

	store = talloc_pool(c, 1024);
	if (!store) return CACHE_ERROR;

	p = from_store;
	while ((p - from_store) <  len) {
		map_afrom_attr_str(
		slen = tmpl_from_attr_substr(&vpt, p, REQUEST_CURRENT, PAIR_LIST_REQUEST);
		if (slen < 0) {
			REMARKER(from_store, slen * -1, fr_strerror());
			talloc_free(c);

			return CACHE_ERROR;
		}
		rad_assert(vpt->type == TMPL_TYPE_ATTR);

		switch (vpt->tmpl_) {
		case
		}

		return CACHE_ERROR;
	}
	*out = c;



	return CACHE_OK;
}

/** Insert a new entry into the data store
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Dummy handle (not used).
 * @param c entry to insert.
 * @return CACHE_OK on success else CACHE_ERROR on error.
 */
static cache_status_t cache_entry_insert(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle,
					 rlm_cache_entry_t *c)
{
	rlm_cache_memcached_t *driver = inst->driver;
	rlm_cache_memcached_handle_t *mandle = *handle;

	memcached_return_t ret;
	cache_status_t rcode;

	TALLOC_CTX *pairs = NULL;
	TALLOC_CTX *store = NULL;

	vp_cursor_t cursor;
	VALUE_PAIR *vp;

	char *to_store = NULL, *pair;

	store = talloc_pool(request, 1024);
	if (!store) goto error;

	to_store = talloc_strdup(store, "&Cache-Expires = %i\n&Cache-Created = %i", c->expires, c->created));
	if (!to_store) goto error;

	/*
	 *	It's valid to have an empty cache entry (save allocing the
	 *	pairs pool)
	 */
	if (!c->control && !c->packet && !c->reply) goto insert;

	/*
	 *  In the majority of cases using these pools reduces the number of mallocs
	 *  to two, except in the case where the total serialized pairs length is
	 *  greater than the pairs pool, or the total serialized string is greater
	 *  than the store pool.
	 */
	pairs = talloc_pool(request, 512);
	if (!pairs) {
	error:
		rcode = CACHE_ERROR;
		goto finish;
	}

	if (c->control) {
		for (vp = fr_cursor_init(&cursor, &c->control);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			pair = vp_aprints(pairs, vp, '\'');
			if (!pair) goto error;

			to_store = talloc_asprintf_append_buffer(to_store, "&control:%s\n", pair);
			if (!to_store) goto error;
		}
	}

	if (c->packet) {
		for (vp = fr_cursor_init(&cursor, &c->packet);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			pair = vp_aprints(pairs, vp, '\'');
			if (!pair) goto error;

			to_store = talloc_asprintf_append_buffer(to_store, "&%s\n", pair);
			if (!to_store) goto error;
		}
	}

	if (c->reply) {
		for (vp = fr_cursor_init(&cursor, &c->reply);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			pair = vp_aprints(pairs, vp, '\'');
			if (!pair) goto error;

			to_store = talloc_asprintf_append_buffer(to_store, "&reply:%s\n", pair);
			if (!to_store) goto error;
		}
	}

insert:
	ret = memcached_set(mandle->handle, c->key, talloc_array_length(c->key) - 1,
		            to_store ? to_store : "",
		            to_store ? talloc_array_length(to_store) - 1 : 0, c->expires, 0);
	if (ret != MEMCACHED_SUCCESS) {
		RERROR("Failed storing entry with key \"%s\": %s: %s", libmemcached_strerror(ret),
		       memcached_last_error_message(mandle->handle));

		goto error;
	}
	rcode = CACHE_OK;

finish:
	talloc_free(pairs);
	talloc_free(store);

	return rcode;

}

/** Free an entry and remove it from the data store
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Dummy handle (not used).
 * @param c entry to expire. Must be freed by caller.
 * @return CACHE_OK.
 */
static cache_status_t cache_entry_expire(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle,
					 rlm_cache_entry_t *c)
{
	rlm_cache_memcached_t *driver = inst->driver;
	rlm_cache_memcached_handle_t *mandle = *handle;

	memcached_return_t ret;

	ret = memcached_delete(mandle->handle, c->key, c->key, talloc_array_length(c->key) - 1, 0);
	if (ret != MEMCACHED_SUCCESS) {
		RERROR("Failed deleting entry with key \"%s\": %s: %s", libmemcached_strerror(ret),
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
static int mod_conn_get(rlm_cache_handle_t **out, rlm_cache_t *inst, REQUEST *request)
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
static void mod_conn_release(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle)
{
	rlm_cache_memcached_t *driver = inst->driver;

	fr_connection_release(driver->pool, *handle);
	*handle = NULL;
}

/** Reconnect a socket
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle The dummy handle created by cache_acquire.
 */
static int mod_conn_reconnect(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle)
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

cache_module_t rlm_cache_memcached = {
	"rlm_cache_memcached",
	mod_instantiate,
	NULL,			/* alloc */
	cache_entry_find,
	cache_entry_insert,
	cache_entry_expire,
	NULL,			/* count */

	mod_conn_get,
	mod_conn_release,
	mod_conn_reconnect
};
