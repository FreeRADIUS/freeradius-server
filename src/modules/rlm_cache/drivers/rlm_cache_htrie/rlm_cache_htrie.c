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
 * @file rlm_cache_htrie.c
 * @brief Simple htrie based cache.
 *
 * @copyright 2024 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2014 The FreeRADIUS server project
 */
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/heap.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/htrie.h>
#include "../../rlm_cache.h"
#include "lib/server/cf_parse.h"
#include "lib/server/tmpl.h"
#include "lib/util/types.h"

static int cf_htrie_type_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int cf_htrie_key_parse(TALLOC_CTX *ctx, void *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci,
			      void const *data, UNUSED call_env_parser_t const *rule);

typedef struct {
	fr_htrie_t		*cache;		//!< Tree for looking up cache keys.
	fr_heap_t		*heap;		//!< For managing entry expiry.

	fr_type_t		ktype;		//!< When htrie is "auto", we use this type to decide
						///< what type of tree to use.

	fr_htrie_type_t		htype;		//!< The htrie type we'll be using
	bool			htrie_auto;	//!< Whether the user wanted to automatically configure
						///< the htrie.

	pthread_mutex_t		mutex;		//!< Protect the tree from multiple readers/writers.
} rlm_cache_htrie_t;

typedef struct {
	rlm_cache_entry_t	fields;		//!< Entry data.
	fr_heap_index_t		heap_id;	//!< Offset used for expiry heap.
} rlm_cache_htrie_entry_t;

static conf_parser_t driver_config[] = {
	{ FR_CONF_OFFSET("type", rlm_cache_htrie_t, htype), .dflt = "auto",
	  .func = cf_htrie_type_parse,
	  .uctx = &(cf_table_parse_ctx_t){ .table = fr_htrie_type_table, .len = &fr_htrie_type_table_len }  },
	CONF_PARSER_TERMINATOR
};

/** Custom htrie type parsing function
 *
 * Sets a bool, so we known if the original type was "auto", so we can constantly re-evaluate
 * the htrie type based on the key type.
 */
int cf_htrie_type_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	rlm_cache_htrie_t	*inst = talloc_get_type_abort(parent, rlm_cache_htrie_t);
	int ret;

	ret = cf_table_parse_int(ctx, out, parent, ci, rule);
	if (unlikely(ret < 0)) return ret;

	/*
	 *	Record this now, so when we overwrite this
	 *	value later, we know to keep checking the
	 *	htrie type value for consistency.
	 */
	if (*(int *)out == FR_HTRIE_AUTO) inst->htrie_auto = true;

	return 0;
}

/** Custom key parsing function for checking compatibility of key types
 *
 * This function does two things:
 * - It selects a htrie type based on the key type.
 * - It checks that all keys are compatible with each other.
 */
static int cf_htrie_key_parse(TALLOC_CTX *ctx, void *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci,
			      void const *data, UNUSED call_env_parser_t const *rule)
{
	rlm_cache_htrie_t	*inst = talloc_get_type_abort_const(data, rlm_cache_htrie_t);
	tmpl_t			*key_tmpl;
	fr_type_t		our_ktype, old_ktype;

	/*
	 *	Call the standard pair parsing function
	 */
	if (unlikely(call_env_parse_pair(ctx, &key_tmpl, t_rules, ci, data, rule) < 0)) return -1;
	our_ktype = tmpl_expanded_type(key_tmpl);

	/*
	 *	We need the user to tell us what the key type is for ambiguous expansions
	 */
	if (fr_type_is_void(our_ktype)) {
		cf_log_err(ci, "Key type is unspecified.  Add a cast to set a specific type");
		return -1;
	}

	/*
	 *	If we don't have a key type already, then just set it to the first key type we see
	 */
	if (fr_type_is_void(inst->ktype)) {
		inst->ktype = our_ktype;
	/*
	 *	Check if we can cast this key type, to the key type we've already seen
	 */
	} else if (!fr_type_cast(our_ktype, inst->ktype)) {
		cf_log_err(ci, "Incompatible key types '%s' and '%s', cast to a more broadly compatible "
			   "type such as 'string'", fr_type_to_str(inst->ktype), fr_type_to_str(our_ktype));
		return -1;
	}

	/*
	 *	See if we should promote inst->ktype
	 */
	old_ktype = inst->ktype;
	inst->ktype = fr_type_promote(inst->ktype, our_ktype);
	fr_assert(!fr_type_is_void(inst->ktype));

	/*
	 *	If we're not automatically determining the htrie type,
	 *	or the ktype hasn't changed, then don't bother figuring
	 *	out the htrie type.
	 */
	if (!inst->htrie_auto || (old_ktype == inst->ktype)) return 0;

	/*
	 *	We need to figure out the htrie type based on the key type
	 */
	inst->htype = fr_htrie_hint(inst->ktype);
	if (inst->htype == FR_HTRIE_INVALID) {
		cf_log_err(ci, "Invalid data type '%s' for htrie key.  "
			   "Cast to another type, or manually specify 'type", fr_type_to_str(inst->ktype));
		return -1;
	}

	cf_log_info(ci, "Automatically setting htrie type to '%s' based on key type '%s'",
		    fr_htrie_type_to_str(inst->htype), fr_type_to_str(inst->ktype));

	*(void **)out = key_tmpl;
	return 0;
}

/** Compare two entries by expiry time
 *
 * There may be multiple entries with the same expiry time.
 */
static int8_t cache_heap_cmp(void const *one, void const *two)
{
	rlm_cache_entry_t const *a = one, *b = two;

	return fr_unix_time_cmp(a->expires, b->expires);
}

/** Custom allocation function for the driver
 *
 * Allows allocation of cache entry structures with additional fields.
 *
 * @copydetails cache_entry_alloc_t
 */
static rlm_cache_entry_t *cache_entry_alloc(UNUSED rlm_cache_config_t const *config, UNUSED void *instance,
					    request_t *request)
{
	rlm_cache_htrie_entry_t *c;

	c = talloc_zero(NULL, rlm_cache_htrie_entry_t);
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
				       request_t *request, UNUSED void *handle, fr_value_box_t const *key)
{
	rlm_cache_htrie_t *driver = talloc_get_type_abort(instance, rlm_cache_htrie_t);
	rlm_cache_entry_t find = {};

	rlm_cache_entry_t *c;

	fr_assert(driver->cache);

	/*
	 *	Clear out old entries
	 */
	c = fr_heap_peek(driver->heap);
	if (c && (fr_unix_time_lt(c->expires, fr_time_to_unix_time(request->packet->timestamp)))) {
		fr_heap_extract(&driver->heap, c);
		fr_htrie_delete(driver->cache, c);
		talloc_free(c);
	}

	fr_value_box_copy_shallow(NULL, &find.key, key);

	/*
	 *	Is there an entry for this key?
	 */
	c = fr_htrie_find(driver->cache, &find);
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
					 request_t *request, UNUSED void *handle,
					 fr_value_box_t const *key)
{
	rlm_cache_htrie_t *driver = talloc_get_type_abort(instance, rlm_cache_htrie_t);
	rlm_cache_entry_t find = {};
	rlm_cache_entry_t *c;

	if (!request) return CACHE_ERROR;

	fr_value_box_copy_shallow(NULL, &find.key, key);

	c = fr_htrie_find(driver->cache, &find);
	if (!c) return CACHE_MISS;

	fr_heap_extract(&driver->heap, c);
	fr_htrie_delete(driver->cache, c);
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
					 request_t *request, void *handle,
					 rlm_cache_entry_t const *c)
{
	cache_status_t status;

	rlm_cache_htrie_t *driver = talloc_get_type_abort(instance, rlm_cache_htrie_t);

	fr_assert(handle == request);

	if (!request) return CACHE_ERROR;

	/*
	 *	Allow overwriting
	 */
	if (!fr_htrie_insert(driver->cache, c)) {
		status = cache_entry_expire(config, instance, request, handle, &c->key);
		if ((status != CACHE_OK) && !fr_cond_assert(0)) return CACHE_ERROR;

		if (!fr_htrie_insert(driver->cache, c)) {
			RERROR("Failed adding entry");

			return CACHE_ERROR;
		}
	}

	if (fr_heap_insert(&driver->heap, UNCONST(rlm_cache_entry_t *, c)) < 0) {
		fr_htrie_delete(driver->cache, c);
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
					  request_t *request, UNUSED void *handle,
					  rlm_cache_entry_t *c)
{
	rlm_cache_htrie_t *driver = talloc_get_type_abort(instance, rlm_cache_htrie_t);

#ifdef NDEBUG
	if (!request) return CACHE_ERROR;
#endif

	if (!fr_cond_assert(fr_heap_extract(&driver->heap, c) == 0)) {
		RERROR("Entry not in heap");
		return CACHE_ERROR;
	}

	if (fr_heap_insert(&driver->heap, c) < 0) {
		fr_htrie_delete(driver->cache, c);	/* make sure we don't leak entries... */
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
static uint64_t cache_entry_count(UNUSED rlm_cache_config_t const *config, void *instance,
				  request_t *request, UNUSED void *handle)
{
	rlm_cache_htrie_t *driver = talloc_get_type_abort(instance, rlm_cache_htrie_t);

	if (!request) return CACHE_ERROR;

	return fr_htrie_num_elements(driver->cache);
}

/** Lock the htrie
 *
 * @note handle not used except for sanity checks.
 *
 * @copydetails cache_acquire_t
 */
static int cache_acquire(void **handle, UNUSED rlm_cache_config_t const *config, void *instance,
			 request_t *request)
{
	rlm_cache_htrie_t *driver = talloc_get_type_abort(instance, rlm_cache_htrie_t);

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
static void cache_release(UNUSED rlm_cache_config_t const *config, void *instance, request_t *request,
			  UNUSED rlm_cache_handle_t *handle)
{
	rlm_cache_htrie_t *driver = talloc_get_type_abort(instance, rlm_cache_htrie_t);

	pthread_mutex_unlock(&driver->mutex);

	RDEBUG3("Mutex released");
}

/** Cleanup a cache_htrie instance
 *
 */
static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_cache_htrie_t *driver = talloc_get_type_abort(mctx->mi->data, rlm_cache_htrie_t);

	if (driver->cache) {
		fr_rb_iter_inorder_t	iter;
		void			*data;

		for (data = fr_rb_iter_init_inorder(&iter, driver->cache);
		     data;
		     data = fr_rb_iter_next_inorder(&iter)) {
			fr_rb_iter_delete_inorder(&iter);
			talloc_free(data);
		}
	}

	pthread_mutex_destroy(&driver->mutex);

	return 0;
}

/** Create a new cache_htrie instance
 *
 * @param[in] mctx		Data required for instantiation.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_cache_htrie_t *driver = talloc_get_type_abort(mctx->mi->data, rlm_cache_htrie_t);
	int ret;

	/*
	 *	The cache.
	 */
	driver->cache = fr_htrie_alloc(driver, driver->htype,
				       (fr_hash_t)fr_value_box_hash,
				       (fr_cmp_t)fr_value_box_cmp,
				       (fr_trie_key_t)fr_value_box_to_key, NULL);
	if (!driver->cache) {
		PERROR("Failed to create cache");
		return -1;
	}

	/*
	 *	The heap of entries to expire.
	 */
	driver->heap = fr_heap_talloc_alloc(driver, cache_heap_cmp, rlm_cache_htrie_entry_t, heap_id, 0);
	if (!driver->heap) {
		ERROR("Failed to create heap for the cache");
		return -1;
	}

	if ((ret = pthread_mutex_init(&driver->mutex, NULL)) < 0) {
		ERROR("Failed initializing mutex: %s", fr_syserror(ret));
		return -1;
	}

	return 0;
}

extern rlm_cache_driver_t rlm_cache_htrie;
rlm_cache_driver_t rlm_cache_htrie = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "cache_htrie",
		.config		= driver_config,
		.instantiate	= mod_instantiate,
		.detach		= mod_detach,
		.inst_size	= sizeof(rlm_cache_htrie_t),
		.inst_type	= "rlm_cache_htrie_t",
	},
	.alloc		= cache_entry_alloc,

	.find		= cache_entry_find,
	.insert		= cache_entry_insert,
	.expire		= cache_entry_expire,
	.set_ttl	= cache_entry_set_ttl,
	.count		= cache_entry_count,

	.acquire	= cache_acquire,
	.release	= cache_release,

	.key_parse	= cf_htrie_key_parse
};
