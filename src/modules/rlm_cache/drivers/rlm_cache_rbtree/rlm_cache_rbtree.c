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
 * @file rlm_cache_rbtree.c
 * @brief Simple rbtree based cache.
 *
 * @copyright 2014 The FreeRADIUS server project
 */
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/heap.h>
#include <freeradius-devel/rad_assert.h>
#include "../../rlm_cache.h"

typedef struct rlm_cache_rbtree {
	rbtree_t		*cache;		//!< Tree for looking up cache keys.
	fr_heap_t		*heap;		//!< For managing entry expiry.

	pthread_mutex_t		mutex;		//!< Protect the tree from multiple readers/writers.
} rlm_cache_rbtree_t;

typedef struct rlm_cache_rbtree_entry {
	rlm_cache_entry_t	fields;		//!< Entry data.
	size_t			offset;		//!< Offset used for heap.
} rlm_cache_rbtree_entry_t;

/** Compare two entries by key
 *
 * There may only be one entry with the same key.
 */
static int cache_entry_cmp(void const *one, void const *two)
{
	rlm_cache_entry_t const *a = one, *b = two;
	int ret;

	ret = (a->key_len > b->key_len) - (a->key_len < b->key_len);
	if (ret != 0) return ret;

	return memcmp(a->key, b->key, a->key_len);
}

/** Compare two entries by expiry time
 *
 * There may be multiple entries with the same expiry time.
 */
static int cache_heap_cmp(void const *one, void const *two)
{
	rlm_cache_entry_t const *a = one, *b = two;

	return (a->expires > b->expires) - (a->expires < b->expires);
}

/** Walk over the cache rbtree
 *
 * Used to free any entries left in the tree on detach.
 *
 * @param ctx unused.
 * @param data to free.
 * @return 2
 */
static int _cache_entry_free(UNUSED void *ctx, void *data)
{
	talloc_free(data);

	return 2;
}

/** Cleanup a cache_rbtree instance
 *
 */
static int mod_detach(void *instance)
{
	rlm_cache_rbtree_t *driver = talloc_get_type_abort(instance, rlm_cache_rbtree_t);

	if (driver->heap) talloc_free(driver->heap);
	if (driver->cache) {
		rbtree_walk(driver->cache, RBTREE_DELETE_ORDER, _cache_entry_free, NULL);
		talloc_free(driver->cache);
	}

	pthread_mutex_destroy(&driver->mutex);

	return 0;
}

/** Create a new cache_rbtree instance
 *
 * @copydetails cache_instantiate_t
 */
static int mod_instantiate(UNUSED rlm_cache_config_t const *config, void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_cache_rbtree_t *driver = talloc_get_type_abort(instance, rlm_cache_rbtree_t);

	/*
	 *	The cache.
	 */
	driver->cache = rbtree_create(NULL, cache_entry_cmp, NULL, 0);
	if (!driver->cache) {
		ERROR("Failed to create cache");
		return -1;
	}
	fr_talloc_link_ctx(driver, driver->cache);

	/*
	 *	The heap of entries to expire.
	 */
	driver->heap = fr_heap_create(cache_heap_cmp, offsetof(rlm_cache_rbtree_entry_t, offset));
	if (!driver->heap) {
		ERROR("Failed to create heap for the cache");
		return -1;
	}

	if (pthread_mutex_init(&driver->mutex, NULL) < 0) {
		ERROR("Failed initializing mutex: %s", fr_syserror(errno));
		return -1;
	}

	return 0;
}

/** Custom allocation function for the driver
 *
 * Allows allocation of cache entry structures with additional fields.
 *
 * @copydetails cache_entry_alloc_t
 */
static rlm_cache_entry_t *cache_entry_alloc(UNUSED rlm_cache_config_t const *config, UNUSED void *instance,
					    REQUEST *request)
{
	rlm_cache_rbtree_entry_t *c;

	c = talloc_zero(NULL, rlm_cache_rbtree_entry_t);
	if (!c) {
		RERROR("Failed allocating cache entry");
		return NULL;
	}

	return (rlm_cache_entry_t *)c;
}

/** Locate a cache entry
 *
 * @note handle not used except for sanity checks.
 *
 * @copydetails cache_entry_find_t
 */
static cache_status_t cache_entry_find(rlm_cache_entry_t **out,
				       UNUSED rlm_cache_config_t const *config, void *instance,
				       REQUEST *request, UNUSED void *handle, uint8_t const *key, size_t key_len)
{
	rlm_cache_rbtree_t *driver = talloc_get_type_abort(instance, rlm_cache_rbtree_t);

	rlm_cache_entry_t *c, my_c;

	rad_assert(driver->cache);

	/*
	 *	Clear out old entries
	 */
	c = fr_heap_peek(driver->heap);
	if (c && (c->expires < request->packet->timestamp.tv_sec)) {
		fr_heap_extract(driver->heap, c);
		rbtree_deletebydata(driver->cache, c);
		talloc_free(c);
	}

	/*
	 *	Is there an entry for this key?
	 */
	my_c.key = key;
	my_c.key_len = key_len;
	c = rbtree_finddata(driver->cache, &my_c);
	if (!c) {
		*out = NULL;
		return CACHE_MISS;
	}
	*out = c;

	return CACHE_OK;
}

/** Free an entry and remove it from the data store
 *
 * @note handle not used except for sanity checks.
 *
 * @copydetails cache_entry_expire_t
 */
static cache_status_t cache_entry_expire(UNUSED rlm_cache_config_t const *config, void *instance,
					 REQUEST *request, UNUSED void *handle,
					 uint8_t const *key, size_t key_len)
{
	rlm_cache_rbtree_t *driver = talloc_get_type_abort(instance, rlm_cache_rbtree_t);
	rlm_cache_entry_t *c, my_c;

	if (!request) return CACHE_ERROR;

	my_c.key = key;
	my_c.key_len = key_len;
	c = rbtree_finddata(driver->cache, &my_c);
	if (!c) return CACHE_MISS;

	fr_heap_extract(driver->heap, c);
	rbtree_deletebydata(driver->cache, c);
	talloc_free(c);

	return CACHE_OK;
}

/** Insert a new entry into the data store
 *
 * @note handle not used except for sanity checks.
 *
 * @copydetails cache_entry_insert_t
 */
static cache_status_t cache_entry_insert(rlm_cache_config_t const *config, void *instance,
					 REQUEST *request, void *handle,
					 rlm_cache_entry_t const *c)
{
	cache_status_t status;

	rlm_cache_rbtree_t *driver = talloc_get_type_abort(instance, rlm_cache_rbtree_t);
	rlm_cache_entry_t *my_c;

	rad_assert(handle == request);

	if (!request) return CACHE_ERROR;

	memcpy(&my_c, &c, sizeof(my_c));

	/*
	 *	Allow overwriting
	 */
	if (!rbtree_insert(driver->cache, my_c)) {
		status = cache_entry_expire(config, instance, request, handle, c->key, c->key_len);
		if ((status != CACHE_OK) && !rad_cond_assert(0)) return CACHE_ERROR;

		if (!rbtree_insert(driver->cache, my_c)) {
			RERROR("Failed adding entry");

			return CACHE_ERROR;
		}
	}

	if (!fr_heap_insert(driver->heap, my_c)) {
		rbtree_deletebydata(driver->cache, my_c);
		RERROR("Failed adding entry to expiry heap");

		return CACHE_ERROR;
	}

	return CACHE_OK;
}

/** Update the TTL of an entry
 *
 * @note handle not used except for sanity checks.
 *
 * @copydetails cache_entry_set_ttl_t
 */
static cache_status_t cache_entry_set_ttl(UNUSED rlm_cache_config_t const *config, void *instance,
					  REQUEST *request, UNUSED void *handle,
					  rlm_cache_entry_t *c)
{
	rlm_cache_rbtree_t *driver = talloc_get_type_abort(instance, rlm_cache_rbtree_t);
	int ret;

#ifdef NDEBUG
	if (!request) return CACHE_ERROR;
#endif

	ret = fr_heap_extract(driver->heap, c);
	rad_assert(ret == 1);
	if (ret != 1) {					/* Need this check if we're not building with asserts */
		RERROR("Entry not in heap");
		return CACHE_ERROR;
	}

	if (!fr_heap_insert(driver->heap, c)) {
		rbtree_deletebydata(driver->cache, c);	/* make sure we don't leak entries... */
		RERROR("Failed updating entry TTL.  Entry was forcefully expired");
		return CACHE_ERROR;
	}
	return CACHE_OK;
}

/** Return the number of entries in the cache
 *
 * @note handle not used except for sanity checks.
 *
 * @copydetails cache_entry_count_t
 */
static uint32_t cache_entry_count(UNUSED rlm_cache_config_t const *config, void *instance,
				  REQUEST *request, UNUSED void *handle)
{
	rlm_cache_rbtree_t *driver = talloc_get_type_abort(instance, rlm_cache_rbtree_t);

	if (!request) return CACHE_ERROR;

	return rbtree_num_elements(driver->cache);
}

/** Lock the rbtree
 *
 * @note handle not used except for sanity checks.
 *
 * @copydetails cache_acquire_t
 */
static int cache_acquire(void **handle, UNUSED rlm_cache_config_t const *config, void *instance,
			 REQUEST *request)
{
	rlm_cache_rbtree_t *driver = talloc_get_type_abort(instance, rlm_cache_rbtree_t);

	pthread_mutex_lock(&driver->mutex);

	*handle = request;		/* handle is unused, this is just for sanity checking */

	RDEBUG3("Mutex acquired");

	return 0;
}

/** Release an entry unlocking any mutexes
 *
 * @note handle not used except for sanity checks.
 *
 * @copydetails cache_release_t
 */
static void cache_release(UNUSED rlm_cache_config_t const *config, void *instance, REQUEST *request,
			  UNUSED rlm_cache_handle_t *handle)
{
	rlm_cache_rbtree_t *driver = talloc_get_type_abort(instance, rlm_cache_rbtree_t);

	pthread_mutex_unlock(&driver->mutex);

	RDEBUG3("Mutex released");
}

extern cache_driver_t rlm_cache_rbtree;
cache_driver_t rlm_cache_rbtree = {
	.name		= "rlm_cache_rbtree",
	.magic		= RLM_MODULE_INIT,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.inst_size	= sizeof(rlm_cache_rbtree_t),
	.alloc		= cache_entry_alloc,

	.find		= cache_entry_find,
	.insert		= cache_entry_insert,
	.expire		= cache_entry_expire,
	.set_ttl	= cache_entry_set_ttl,
	.count		= cache_entry_count,

	.acquire	= cache_acquire,
	.release	= cache_release,
};
