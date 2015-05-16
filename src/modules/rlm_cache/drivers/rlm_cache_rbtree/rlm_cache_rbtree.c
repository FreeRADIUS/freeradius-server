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

#ifdef HAVE_PTHREAD_H
#  define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#  define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock
#else
#  define PTHREAD_MUTEX_LOCK(_x)
#  define PTHREAD_MUTEX_UNLOCK(_x)
#endif

typedef struct rlm_cache_rbtree {
	rbtree_t		*cache;		//!< Tree for looking up cache keys.
	fr_heap_t		*heap;		//!< For managing entry expiry.

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		mutex;		//!< Protect the tree from multiple readers/writers.
#endif
} rlm_cache_rbtree_t;

typedef struct rlm_cache_rbtree_entry {
	rlm_cache_entry_t	fields;		//!< Entry data.
	size_t			offset;		//!< Offset used for heap.
} rlm_cache_rbtree_entry_t;

/*
 *	Compare two entries by key.  There may only be one entry with
 *	the same key.
 */
static int cache_entry_cmp(void const *one, void const *two)
{
	rlm_cache_entry_t const *a = one;
	rlm_cache_entry_t const *b = two;

	return strcmp(a->key, b->key);
}

/*
 *	Compare two entries by expiry time.  There may be multiple
 *	entries with the same expiry time.
 */
static int cache_heap_cmp(void const *one, void const *two)
{
	rlm_cache_entry_t const *a = one;
	rlm_cache_entry_t const *b = two;

	if (a->expires < b->expires) return -1;
	if (a->expires > b->expires) return +1;

	return 0;
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
 * @param driver to free.
 * @return 0
 */
static int _mod_detach(rlm_cache_rbtree_t *driver)
{
	if (driver->heap) fr_heap_delete(driver->heap);
	if (driver->cache) {
		rbtree_walk(driver->cache, RBTREE_DELETE_ORDER, _cache_entry_free, NULL);
		rbtree_free(driver->cache);
	}

#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy(&driver->mutex);
#endif
	return 0;
}

/** Create a new cache_rbtree instance
 *
 * @param conf rbtree specific conf section.
 * @param inst main rlm_cache instance.
 * @return 0 on success, -1 on failure.
 */
static int mod_instantiate(UNUSED CONF_SECTION *conf, rlm_cache_t *inst)
{
	rlm_cache_rbtree_t *driver;

	driver = talloc_zero(inst, rlm_cache_rbtree_t);
	talloc_set_destructor(driver, _mod_detach);
	/*
	 *	The cache.
	 */
	driver->cache = rbtree_create(NULL, cache_entry_cmp, NULL, 0);
	if (!driver->cache) {
		ERROR("Failed to create cache");
		return -1;
	}
	fr_link_talloc_ctx_free(driver, driver->cache);

	/*
	 *	The heap of entries to expire.
	 */
	driver->heap = fr_heap_create(cache_heap_cmp, offsetof(rlm_cache_rbtree_entry_t, offset));
	if (!driver->heap) {
		ERROR("Failed to create heap for the cache");
		return -1;
	}

#ifdef HAVE_PTHREAD_H
	if (pthread_mutex_init(&driver->mutex, NULL) < 0) {
		ERROR("Failed initializing mutex: %s", fr_syserror(errno));
		return -1;
	}
#endif

	inst->driver = driver;

	return 0;
}

/** Custom allocation function for the driver
 *
 * Allows allocation of cache entry structures with additional fields.
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @return 0 on success, -1 on failure.
 */
static rlm_cache_entry_t *cache_entry_alloc(UNUSED rlm_cache_t *inst, REQUEST *request)
{
	rlm_cache_rbtree_entry_t *c;

	c = talloc_zero(NULL, rlm_cache_rbtree_entry_t);
	if (!c) {
		REDEBUG("Failed allocating cache entry");
		return NULL;
	}

	return (rlm_cache_entry_t *)c;
}

/** Locate a cache entry
 *
 * @param out Where to write the search result.
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Dummy handle (not used).
 * @param key to search for.
 * @return CACHE_OK on success CACHE_MISS if no entry found.
 */
static cache_status_t cache_entry_find(rlm_cache_entry_t **out, rlm_cache_t *inst, REQUEST *request,
				       rlm_cache_handle_t **handle, char const *key)
{
	rlm_cache_rbtree_t *driver = inst->driver;

	rlm_cache_entry_t *c, my_c;

	rad_assert(*handle == request);

	/*
	 *	Clear out old entries
	 */
	c = fr_heap_peek(driver->heap);
	if (c && (c->expires < request->timestamp)) {
		fr_heap_extract(driver->heap, c);
		rbtree_deletebydata(driver->cache, c);
		talloc_free(c);
	}

	/*
	 *	Is there an entry for this key?
	 */
	my_c.key = key;
	c = rbtree_finddata(driver->cache, &my_c);
	if (!c) {
		*out = NULL;
		return CACHE_MISS;
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
	rlm_cache_rbtree_t *driver = inst->driver;

	rad_assert(*handle == request);

	if (!rbtree_insert(driver->cache, c)) {
		REDEBUG("Failed adding entry for key \"%s\"", c->key);

		return CACHE_ERROR;
	}

	if (!fr_heap_insert(driver->heap, c)) {
		rbtree_deletebydata(driver->cache, c);
		REDEBUG("Failed adding entry for key \"%s\"", c->key);

		return CACHE_ERROR;
	}

	return CACHE_OK;
}

/** Free an entry and remove it from the data store
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Dummy handle (not used).
 * @param c entry to expire
 * @return CACHE_OK.
 */
static cache_status_t cache_entry_expire(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle,
					 rlm_cache_entry_t *c)
{
	rlm_cache_rbtree_t *driver = inst->driver;

	rad_assert(*handle == request);

	fr_heap_extract(driver->heap, c);
	rbtree_deletebydata(driver->cache, c);
	talloc_free(c);

	return CACHE_OK;
}

/** Return the number of entries in the cache
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Dummy handle (not used).
 * @return the number of entries in the cache.
 */
static uint32_t cache_entry_count(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle)
{
	rlm_cache_rbtree_t *driver = inst->driver;

	rad_assert(*handle == request);

	return rbtree_num_elements(driver->cache);
}

/** Lock the rbtree
 *
 * @param out Where to write the dummy handle.
 * @param inst rlm_cache instance.
 * @param request The current request.
 */

#ifdef HAVE_PTHREAD_H
static int cache_acquire(rlm_cache_handle_t **out, rlm_cache_t *inst, REQUEST *request)
#else
static int cache_acquire(rlm_cache_handle_t **out, UNUSED rlm_cache_t *inst, REQUEST *request)
#endif
{
#ifdef HAVE_PTHREAD_H
	rlm_cache_rbtree_t *driver = inst->driver;
#endif

	PTHREAD_MUTEX_LOCK(&driver->mutex);

	*out = request;		/* handle is unused, this is just for sanity checking */

	RDEBUG3("Mutex acquired");

	return 0;
}

/** Release an entry unlocking any mutexes
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle The dummy handle created by cache_acquire.
 */
#ifdef HAVE_PTHREAD_H
static void cache_release(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle)
#else
static void cache_release(UNUSED rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle)
#endif
{
#ifdef HAVE_PTHREAD_H
	rlm_cache_rbtree_t *driver = inst->driver;
#endif

	rad_assert(*handle == request);

	PTHREAD_MUTEX_UNLOCK(&driver->mutex);

	RDEBUG3("Mutex released");

	*handle = NULL;
}

extern cache_module_t rlm_cache_rbtree;
cache_module_t rlm_cache_rbtree = {
	.name		= "rlm_cache_rbtree",
	.instantiate	= mod_instantiate,
	.alloc		= cache_entry_alloc,

	.find		= cache_entry_find,
	.insert		= cache_entry_insert,
	.expire		= cache_entry_expire,
	.count		= cache_entry_count,

	.acquire	= cache_acquire,
	.release	= cache_release,
};
