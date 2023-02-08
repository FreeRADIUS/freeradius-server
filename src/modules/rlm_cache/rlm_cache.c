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
 * @file rlm_cache.c
 * @brief Cache values and merge them back into future requests.
 *
 * @copyright 2012-2014 The FreeRADIUS server project
 */
RCSID("$Id$")

#define LOG_PREFIX mctx->inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/util/debug.h>

#include "rlm_cache.h"

extern module_rlm_t rlm_cache;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("driver", FR_TYPE_VOID, rlm_cache_t, driver_submodule), .dflt = "rbtree",
			 .func = module_rlm_submodule_parse },
	{ FR_CONF_OFFSET("key", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_cache_config_t, key) },
	{ FR_CONF_OFFSET("ttl", FR_TYPE_TIME_DELTA, rlm_cache_config_t, ttl), .dflt = "500s" },
	{ FR_CONF_OFFSET("max_entries", FR_TYPE_UINT32, rlm_cache_config_t, max_entries), .dflt = "0" },

	/* Should be a type which matches time_t, @fixme before 2038 */
	{ FR_CONF_OFFSET("epoch", FR_TYPE_INT32, rlm_cache_config_t, epoch), .dflt = "0" },
	{ FR_CONF_OFFSET("add_stats", FR_TYPE_BOOL, rlm_cache_config_t, stats), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_cache_dict[];
fr_dict_autoload_t rlm_cache_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_cache_merge_new;
static fr_dict_attr_t const *attr_cache_status_only;
static fr_dict_attr_t const *attr_cache_allow_merge;
static fr_dict_attr_t const *attr_cache_allow_insert;
static fr_dict_attr_t const *attr_cache_ttl;
static fr_dict_attr_t const *attr_cache_entry_hits;

extern fr_dict_attr_autoload_t rlm_cache_dict_attr[];
fr_dict_attr_autoload_t rlm_cache_dict_attr[] = {
	{ .out = &attr_cache_merge_new, .name = "Cache-Merge-New", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_cache_status_only, .name = "Cache-Status-Only", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_cache_allow_merge, .name = "Cache-Allow-Merge", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_cache_allow_insert, .name = "Cache-Allow-Insert", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_cache_ttl, .name = "Cache-TTL", .type = FR_TYPE_INT32, .dict = &dict_freeradius },
	{ .out = &attr_cache_entry_hits, .name = "Cache-Entry-Hits", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ NULL }
};

/** Get exclusive use of a handle to access the cache
 *
 */
static int cache_acquire(rlm_cache_handle_t **out, rlm_cache_t const *inst, request_t *request)
{
	if (!inst->driver->acquire) {
		*out = NULL;
		return 0;
	}

	return inst->driver->acquire(out, &inst->config, inst->driver_submodule->dl_inst->data, request);
}

/** Release a handle we previously acquired
 *
 */
static void cache_release(rlm_cache_t const *inst, request_t *request, rlm_cache_handle_t **handle)
{
	if (!inst->driver->release) return;
	if (!handle || !*handle) return;

	inst->driver->release(&inst->config, inst->driver_submodule->dl_inst->data, request, *handle);
	*handle = NULL;
}

/** Reconnect an suspected inviable handle
 *
 */
static int cache_reconnect(rlm_cache_handle_t **handle, rlm_cache_t const *inst, request_t *request)
{
	fr_assert(inst->driver->reconnect);

	return inst->driver->reconnect(handle, &inst->config, inst->driver_submodule->dl_inst->data, request);
}

/** Allocate a cache entry
 *
 *  This is used so that drivers may use their own allocation functions
 *  to allocate structures larger than the normal rlm_cache_entry_t.
 *
 *  If the driver doesn't specify a custom allocation function, the cache
 *  entry is talloced in the NULL ctx.
 */
static rlm_cache_entry_t *cache_alloc(rlm_cache_t const *inst, request_t *request)
{
	if (inst->driver->alloc) return inst->driver->alloc(&inst->config, inst->driver_submodule->dl_inst->data, request);

	return talloc_zero(NULL, rlm_cache_entry_t);
}

/** Free memory associated with a cache entry
 *
 * This does not necessarily remove the entry from the cache, cache_expire
 * should be used for that.
 *
 * This function should be called when an entry that is known to have been
 * retrieved or inserted into a data store successfully, is no longer needed.
 *
 * Some drivers (like rlm_cache_rbtree) don't register a free function.
 * This means that the cache entry never needs to be explicitly freed.
 *
 * @param[in] inst Module instance.
 * @param[in,out] c Cache entry to free.
 */
static void cache_free(rlm_cache_t const *inst, rlm_cache_entry_t **c)
{
	if (!c || !*c || !inst->driver->free) return;

	inst->driver->free(*c);
	*c = NULL;
}

/** Merge a cached entry into a #request_t
 *
 * @return
 *	- #RLM_MODULE_OK if no entries were merged.
 *	- #RLM_MODULE_UPDATED if entries were merged.
 */
static rlm_rcode_t cache_merge(rlm_cache_t const *inst, request_t *request, rlm_cache_entry_t *c) CC_HINT(nonnull);
static rlm_rcode_t cache_merge(rlm_cache_t const *inst, request_t *request, rlm_cache_entry_t *c)
{
	fr_pair_t	*vp;
	map_t		*map = NULL;
	int		merged = 0;

	RDEBUG2("Merging cache entry into request");
	RINDENT();
	while ((map = map_list_next(&c->maps, map))) {
		/*
		 *	The only reason that the application of a map entry
		 *	can fail, is if the destination list or request
		 *	isn't valid. For now we don't consider this fatal
		 *	and continue merging the rest of the maps.
		 */
		if (map_to_request(request, map, map_to_vp, NULL) < 0) {
			char buffer[1024];

			map_print(&FR_SBUFF_OUT(buffer, sizeof(buffer)), map);
			REXDENT();
			RDEBUG2("Skipping %s", buffer);
			RINDENT();
			continue;
		}
		merged++;
	}
	REXDENT();

	if (inst->config.stats) {
		fr_assert(request->packet != NULL);
		MEM(pair_update_request(&vp, attr_cache_entry_hits) >= 0);
		vp->vp_uint32 = c->hits;
	}

	return merged > 0 ?
		RLM_MODULE_UPDATED :
		RLM_MODULE_OK;
}

/** Find a cached entry.
 *
 * @return
 *	- #RLM_MODULE_OK on cache hit.
 *	- #RLM_MODULE_FAIL on failure.
 *	- #RLM_MODULE_NOTFOUND on cache miss.
 */
static unlang_action_t cache_find(rlm_rcode_t *p_result, rlm_cache_entry_t **out,
				  rlm_cache_t const *inst, request_t *request,
				  rlm_cache_handle_t **handle, uint8_t const *key, size_t key_len)
{
	cache_status_t ret;

	rlm_cache_entry_t *c;

	*out = NULL;

	for (;;) {
		ret = inst->driver->find(&c, &inst->config, inst->driver_submodule->dl_inst->data, request, *handle, key, key_len);
		switch (ret) {
		case CACHE_RECONNECT:
			RDEBUG2("Reconnecting...");
			if (cache_reconnect(handle, inst, request) == 0) continue;
			RETURN_MODULE_FAIL;

		case CACHE_OK:
			break;

		case CACHE_MISS:
			RDEBUG2("No cache entry found for \"%pV\"", fr_box_strvalue_len((char const *)key, key_len));
			RETURN_MODULE_NOTFOUND;

		default:
			RETURN_MODULE_FAIL;

		}

		break;
	}

	/*
	 *	Yes, but it expired, OR the "forget all" epoch has
	 *	passed.  Delete it, and pretend it doesn't exist.
	 */
	if (fr_unix_time_lt(c->expires, fr_time_to_unix_time(request->packet->timestamp))) {
		RDEBUG2("Found entry for \"%pV\", but it expired %pV ago at %pV (packet received %pV).  Removing it",
			fr_box_strvalue_len((char const *)key, key_len),
			fr_box_time_delta(fr_unix_time_sub(fr_time_to_unix_time(request->packet->timestamp), c->expires)),
			fr_box_date(c->expires),
			fr_box_time(request->packet->timestamp));

	expired:
		inst->driver->expire(&inst->config, inst->driver_submodule->dl_inst->data, request, handle, c->key, c->key_len);
		cache_free(inst, &c);
		RETURN_MODULE_NOTFOUND;	/* Couldn't find a non-expired entry */
	}

	if (fr_unix_time_lt(c->created, fr_unix_time_from_sec(inst->config.epoch))) {
		RDEBUG2("Found entry for \"%pV\", but it was created before the current epoch.  Removing it",
			fr_box_strvalue_len((char const *)key, key_len));
		goto expired;
	}
	RDEBUG2("Found entry for \"%pV\"", fr_box_strvalue_len((char const *)key, key_len));

	c->hits++;
	*out = c;

	RETURN_MODULE_OK;
}

/** Expire a cache entry (removing it from the datastore)
 *
 * @return
 *	- #RLM_MODULE_OK on success.
 *	- #RLM_MODULE_NOTFOUND if no entry existed.
 *	- #RLM_MODULE_FAIL on failure.
 */
static unlang_action_t cache_expire(rlm_rcode_t *p_result,
				    rlm_cache_t const *inst, request_t *request,
				    rlm_cache_handle_t **handle, uint8_t const *key, size_t key_len)
{
	RDEBUG2("Expiring cache entry");
	for (;;) switch (inst->driver->expire(&inst->config, inst->driver_submodule->dl_inst->data, request,
					      *handle, key, key_len)) {
	case CACHE_RECONNECT:
		if (cache_reconnect(handle, inst, request) == 0) continue;
		FALL_THROUGH;

	default:
		RETURN_MODULE_FAIL;

	case CACHE_OK:
		RETURN_MODULE_OK;

	case CACHE_MISS:
		RETURN_MODULE_NOTFOUND;
	}
}

/** Create and insert a cache entry
 *
 * @return
 *	- #RLM_MODULE_OK on success.
 *	- #RLM_MODULE_UPDATED if we merged the cache entry.
 *	- #RLM_MODULE_FAIL on failure.
 */
static unlang_action_t cache_insert(rlm_rcode_t *p_result,
				    rlm_cache_t const *inst, request_t *request, rlm_cache_handle_t **handle,
				    uint8_t const *key, size_t key_len, fr_time_delta_t ttl)
{
	map_t			const *map = NULL;
	map_t			*c_map;

	fr_pair_t		*vp;
	bool			merge = false;
	rlm_cache_entry_t	*c;

	TALLOC_CTX		*pool;

	if ((inst->config.max_entries > 0) && inst->driver->count &&
	    (inst->driver->count(&inst->config, inst->driver_submodule->dl_inst->data, request, handle) > inst->config.max_entries)) {
		RWDEBUG("Cache is full: %d entries", inst->config.max_entries);
		RETURN_MODULE_FAIL;
	}

	c = cache_alloc(inst, request);
	if (!c) {
		RETURN_MODULE_FAIL;
	}
	map_list_init(&c->maps);
	c->key = talloc_memdup(c, key, key_len);
	c->key_len = key_len;

	/*
	 *	All in NSEC resolution
	 */
	c->created = c->expires = fr_time_to_unix_time(request->packet->timestamp);
	c->expires = fr_unix_time_add(c->expires, ttl);

	RDEBUG2("Creating new cache entry");

	/*
	 *	Alloc a pool so we don't have excessive allocs when
	 *	gathering fr_pair_ts to cache.
	 */
	pool = talloc_pool(NULL, 2048);
	while ((map = map_list_next(&inst->maps, map))) {
		fr_pair_list_t	to_cache;

		fr_pair_list_init(&to_cache);
		fr_assert(map->lhs && map->rhs);

		/*
		 *	Calling map_to_vp gives us exactly the same result,
		 *	as if this were an update section.
		 */
		if (map_to_vp(pool, &to_cache, request, map, NULL) < 0) {
			RDEBUG2("Skipping %s", map->rhs->name);
			continue;
		}

		for (vp = fr_pair_list_head(&to_cache);
		     vp;
		     vp = fr_pair_list_next(&to_cache, vp)) {
			/*
			 *	Prevent people from accidentally caching
			 *	cache control attributes.
			 */
			if (tmpl_is_list(map->rhs)) switch (vp->da->attr) {
			case FR_CACHE_TTL:
			case FR_CACHE_STATUS_ONLY:
			case FR_CACHE_MERGE_NEW:
			case FR_CACHE_ENTRY_HITS:
				RDEBUG2("Skipping %s", vp->da->name);
				continue;

			default:
				break;
			}
			RINDENT();
			if (RDEBUG_ENABLED2) map_debug_log(request, map, vp);
			REXDENT();

			MEM(c_map = talloc_zero(c, map_t));
			c_map->op = map->op;
			map_list_init(&c_map->child);

			/*
			 *	Now we turn the fr_pair_ts into maps.
			 */
			switch (map->lhs->type) {
			/*
			 *	Attributes are easy, reuse the LHS, and create a new
			 *	RHS with the fr_value_box_t from the fr_pair_t.
			 */
			case TMPL_TYPE_ATTR:
			{
				fr_token_t	quote;
				/*
				 *	If the LHS is structural, we need a new template
				 *	which is the combination of the existing LHS and
				 *	the attribute.
				 */
				if (tmpl_attr_tail_da_is_structural(map->lhs)) {
					tmpl_attr_afrom_list(c_map, &c_map->lhs, map->lhs, vp->da);
				} else {
					c_map->lhs = map->lhs;	/* lhs shouldn't be touched, so this is ok */
				}

				if (vp->vp_type == FR_TYPE_STRING) {
					quote = is_printable(vp->vp_strvalue, vp->vp_length) ?
							     T_SINGLE_QUOTED_STRING : T_DOUBLE_QUOTED_STRING;
				} else {
					quote = T_BARE_WORD;
				}

				MEM(c_map->rhs = tmpl_alloc(c_map,
							    TMPL_TYPE_DATA, quote, map->rhs->name, map->rhs->len));
				if (fr_value_box_copy(c_map->rhs, tmpl_value(c_map->rhs), &vp->data) < 0) {
					REDEBUG("Failed copying attribute value");
					talloc_free(pool);
					talloc_free(c);
					RETURN_MODULE_FAIL;
				}
			}
				break;

			default:
				fr_assert(0);
			}
			MAP_VERIFY(c_map);
			map_list_insert_tail(&c->maps, c_map);
		}
		talloc_free_children(pool); /* reset pool state */
	}
	talloc_free(pool);

	/*
	 *	Check to see if we need to merge the entry into the request
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_cache_merge_new);
	if (vp && vp->vp_bool) merge = true;

	if (merge) cache_merge(inst, request, c);

	for (;;) {
		cache_status_t ret;

		ret = inst->driver->insert(&inst->config, inst->driver_submodule->dl_inst->data, request, *handle, c);
		switch (ret) {
		case CACHE_RECONNECT:
			if (cache_reconnect(handle, inst, request) == 0) continue;
			RETURN_MODULE_FAIL;

		case CACHE_OK:
			RDEBUG2("Committed entry, TTL %pV seconds", fr_box_time_delta(ttl));
			cache_free(inst, &c);
			RETURN_MODULE_RCODE(merge ? RLM_MODULE_UPDATED : RLM_MODULE_OK);

		default:
			talloc_free(c);	/* Failed insertion - use talloc_free not the driver free */
			RETURN_MODULE_FAIL;
		}
	}
}

/** Update the TTL of an entry
 *
 * @return
 *	- #RLM_MODULE_OK on success.
 *	- #RLM_MODULE_FAIL on failure.
 */
static unlang_action_t cache_set_ttl(rlm_rcode_t *p_result,
				     rlm_cache_t const *inst, request_t *request,
				     rlm_cache_handle_t **handle, rlm_cache_entry_t *c)
{
	/*
	 *	Call the driver's insert method to overwrite the old entry
	 */
	if (!inst->driver->set_ttl) for (;;) {
		cache_status_t ret;

		ret = inst->driver->insert(&inst->config, inst->driver_submodule->dl_inst->data, request, *handle, c);
		switch (ret) {
		case CACHE_RECONNECT:
			if (cache_reconnect(handle, inst, request) == 0) continue;
			RETURN_MODULE_FAIL;

		case CACHE_OK:
			RDEBUG2("Updated entry TTL");
			RETURN_MODULE_OK;

		default:
			RETURN_MODULE_FAIL;
		}
	}

	/*
	 *	Or call the set ttl method if the driver can do this more
	 *	efficiently.
	 */
	for (;;) {
		cache_status_t ret;

		ret = inst->driver->set_ttl(&inst->config, inst->driver_submodule->dl_inst->data, request, *handle, c);
		switch (ret) {
		case CACHE_RECONNECT:
			if (cache_reconnect(handle, inst, request) == 0) continue;
			RETURN_MODULE_FAIL;

		case CACHE_OK:
			RDEBUG2("Updated entry TTL");
			RETURN_MODULE_OK;

		default:
			RETURN_MODULE_FAIL;
		}
	}
}

/** Verify that a map in the cache section makes sense
 *
 */
static int cache_verify(map_t *map, void *ctx)
{
	if (unlang_fixup_update(map, ctx) < 0) return -1;

	if (!tmpl_is_attr(map->lhs)) {
		cf_log_err(map->ci, "Destination must be an attribute ref or a list");
		return -1;
	}

	return 0;
}

/** Do caching checks
 *
 * Since we can update ANY VP list, we do exactly the same thing for all sections
 * (autz / auth / etc.)
 *
 * If you want to cache something different in different sections, configure
 * another cache module.
 */
static unlang_action_t CC_HINT(nonnull) mod_cache_it(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_cache_entry_t	*c = NULL;
	rlm_cache_t const	*inst = talloc_get_type_abort_const(mctx->inst->data, rlm_cache_t);

	rlm_cache_handle_t	*handle;

	fr_dcursor_t		cursor;
	fr_pair_t		*vp;

	bool			merge = true, insert = true, expire = false, set_ttl = false;
	int			exists = -1;

	uint8_t			buffer[1024];
	uint8_t const		*key;
	ssize_t			key_len;
	rlm_rcode_t		rcode = RLM_MODULE_NOOP;

	fr_time_delta_t		ttl = inst->config.ttl;

	key_len = tmpl_expand((char const **)&key, (char *)buffer, sizeof(buffer),
			      request, inst->config.key, NULL, NULL);
	if (key_len < 0) {
		RETURN_MODULE_FAIL;
	}

	if (key_len == 0) {
		REDEBUG("Zero length key string is invalid");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	If Cache-Status-Only == yes, only return whether we found a
	 *	valid cache entry
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_cache_status_only);
	if (vp && vp->vp_bool) {
		RINDENT();
		RDEBUG3("status-only: yes");
		REXDENT();

		if (cache_acquire(&handle, inst, request) < 0) {
			RETURN_MODULE_FAIL;
		}

		cache_find(&rcode, &c, inst, request, &handle, key, key_len);
		if (rcode == RLM_MODULE_FAIL) goto finish;
		fr_assert(!inst->driver->acquire || handle);

		rcode = c ? RLM_MODULE_OK:
			    RLM_MODULE_NOTFOUND;
		goto finish;
	}

	/*
	 *	Figure out what operation we're doing
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_cache_allow_merge);
	if (vp) merge = vp->vp_bool;

	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_cache_allow_insert);
	if (vp) insert = vp->vp_bool;

	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_cache_ttl);
	if (vp) {
		if (vp->vp_int32 == 0) {
			expire = true;
		} else if (vp->vp_int32 < 0) {
			expire = true;
			ttl = fr_time_delta_from_sec(-(vp->vp_int32));
		/* Updating the TTL */
		} else {
			set_ttl = true;
			ttl = fr_time_delta_from_sec(vp->vp_int32);
		}
	}

	RINDENT();
	RDEBUG3("merge  : %s", merge ? "yes" : "no");
	RDEBUG3("insert : %s", insert ? "yes" : "no");
	RDEBUG3("expire : %s", expire ? "yes" : "no");
	RDEBUG3("ttl    : %pV", fr_box_time_delta(ttl));
	REXDENT();
	if (cache_acquire(&handle, inst, request) < 0) {
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Retrieve the cache entry and merge it with the current request
	 *	recording whether the entry existed.
	 */
	if (merge) {
		cache_find(&rcode, &c, inst, request, &handle, key, key_len);
		switch (rcode) {
		case RLM_MODULE_FAIL:
			goto finish;

		case RLM_MODULE_OK:
			rcode = cache_merge(inst, request, c);
			exists = 1;
			break;

		case RLM_MODULE_NOTFOUND:
			rcode = RLM_MODULE_NOTFOUND;
			exists = 0;
			break;

		default:
			fr_assert(0);
		}
		fr_assert(!inst->driver->acquire || handle);
	}

	/*
	 *	Expire the entry if told to, and we either don't know whether
	 *	it exists, or we know it does.
	 *
	 *	We only expire if we're not inserting, as driver insert methods
	 *	should perform upserts.
	 */
	if (expire && ((exists == -1) || (exists == 1))) {
		if (!insert) {
			rlm_rcode_t tmp;

			fr_assert(!set_ttl);
			cache_expire(&tmp, inst, request, &handle, key, key_len);
			switch (tmp) {
			case RLM_MODULE_FAIL:
				rcode = RLM_MODULE_FAIL;
				goto finish;

			case RLM_MODULE_OK:
				if (rcode == RLM_MODULE_NOOP) rcode = RLM_MODULE_OK;
				break;

			case RLM_MODULE_NOTFOUND:
				if (rcode == RLM_MODULE_NOOP) rcode = RLM_MODULE_NOTFOUND;
				break;

			default:
				fr_assert(0);
				break;
			}
			/* If it previously existed, it doesn't now */
		}
		/* Otherwise use insert to overwrite */
		exists = 0;
	}

	/*
	 *	If we still don't know whether it exists or not
	 *	and we need to do an insert or set_ttl operation
	 *	determine that now.
	 */
	if ((exists < 0) && (insert || set_ttl)) {
		rlm_rcode_t tmp;

		cache_find(&tmp, &c, inst, request, &handle, key, key_len);
		switch (tmp) {
		case RLM_MODULE_FAIL:
			rcode = RLM_MODULE_FAIL;
			goto finish;

		case RLM_MODULE_OK:
			exists = 1;
			if (rcode != RLM_MODULE_UPDATED) rcode = RLM_MODULE_OK;
			break;

		case RLM_MODULE_NOTFOUND:
			exists = 0;
			break;

		default:
			fr_assert(0);
		}
		fr_assert(!inst->driver->acquire || handle);
	}

	/*
	 *	We can only alter the TTL on an entry if it exists.
	 */
	if (set_ttl && (exists == 1)) {
		rlm_rcode_t tmp;

		fr_assert(c);

		c->expires = fr_unix_time_add(fr_time_to_unix_time(request->packet->timestamp), ttl);

		cache_set_ttl(&tmp, inst, request, &handle, c);
		switch (tmp) {
		case RLM_MODULE_FAIL:
			rcode = RLM_MODULE_FAIL;
			goto finish;

		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
			if (rcode != RLM_MODULE_UPDATED) rcode = RLM_MODULE_OK;
			goto finish;

		default:
			fr_assert(0);
		}
	}

	/*
	 *	Inserts are upserts, so we don't care about the
	 *	entry state, just that we're not meant to be
	 *	setting the TTL, which precludes performing an
	 *	insert.
	 */
	if (insert && (exists == 0)) {
		rlm_rcode_t tmp;

		cache_insert(&tmp, inst, request, &handle, key, key_len, ttl);
		switch (tmp) {
		case RLM_MODULE_FAIL:
			rcode = RLM_MODULE_FAIL;
			goto finish;

		case RLM_MODULE_OK:
			if (rcode != RLM_MODULE_UPDATED) rcode = RLM_MODULE_OK;
			break;

		case RLM_MODULE_UPDATED:
			rcode = RLM_MODULE_UPDATED;
			break;

		default:
			fr_assert(0);
		}
		fr_assert(!inst->driver->acquire || handle);
		goto finish;
	}


finish:
	cache_free(inst, &c);
	cache_release(inst, request, &handle);

	/*
	 *	Clear control attributes
	 */
	for (vp = fr_pair_dcursor_init(&cursor, &request->control_pairs);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
	     again:
		if (!fr_dict_attr_is_top_level(vp->da)) continue;

		switch (vp->da->attr) {
		case FR_CACHE_TTL:
		case FR_CACHE_STATUS_ONLY:
		case FR_CACHE_ALLOW_MERGE:
		case FR_CACHE_ALLOW_INSERT:
		case FR_CACHE_MERGE_NEW:
			RDEBUG2("Removing &control.%s", vp->da->name);
			vp = fr_dcursor_remove(&cursor);
			talloc_free(vp);
			vp = fr_dcursor_current(&cursor);
			if (!vp) break;
			goto again;
		}
	}

	RETURN_MODULE_RCODE(rcode);
}

static xlat_arg_parser_t const cache_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Allow single attribute values to be retrieved from the cache
 *
 * @ingroup xlat_functions
 */
static CC_HINT(nonnull)
xlat_action_t cache_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
			 xlat_ctx_t const *xctx,
			 request_t *request, FR_DLIST_HEAD(fr_value_box_list) *in)
{
	rlm_cache_entry_t 		*c = NULL;
	rlm_cache_t			*inst = talloc_get_type_abort(xctx->mctx->inst->data, rlm_cache_t);
	rlm_cache_handle_t		*handle = NULL;

	ssize_t				slen;

	fr_value_box_t			*attr = fr_value_box_list_head(in);
	uint8_t				buffer[1024];
	uint8_t const			*key;
	ssize_t				key_len;
	fr_value_box_t			*vb;

	tmpl_t				*target = NULL;
	map_t				*map = NULL;
	rlm_rcode_t			rcode = RLM_MODULE_NOOP;

	key_len = tmpl_expand((char const **)&key, (char *)buffer, sizeof(buffer),
			      request, inst->config.key, NULL, NULL);
	if (key_len < 0) return XLAT_ACTION_FAIL;

	slen = tmpl_afrom_attr_substr(ctx, NULL, &target,
				      &FR_SBUFF_IN(attr->vb_strvalue, attr->vb_length),
				      NULL,
				      &(tmpl_rules_t){
				      	.attr = {
				      		.dict_def = request->dict,
						.list_def = PAIR_LIST_REQUEST,
				      		.prefix = TMPL_ATTR_REF_PREFIX_AUTO
				      	}
				      });
	if (slen <= 0) {
		RPEDEBUG("Invalid key");
		return XLAT_ACTION_FAIL;
	}

	if (cache_acquire(&handle, inst, request) < 0) {
		talloc_free(target);
		return XLAT_ACTION_FAIL;
	}

	cache_find(&rcode, &c, inst, request, &handle, key, key_len);
	switch (rcode) {
	case RLM_MODULE_OK:		/* found */
		break;

	case RLM_MODULE_NOTFOUND:	/* not found */
		return XLAT_ACTION_FAIL;

	default:
		talloc_free(target);
		return XLAT_ACTION_FAIL;
	}

	while ((map = map_list_next(&c->maps, map))) {
		if ((tmpl_attr_tail_da(map->lhs) != tmpl_attr_tail_da(target)) ||
		    (tmpl_list(map->lhs) != tmpl_list(target))) continue;

		MEM(vb = fr_value_box_alloc_null(ctx));
		fr_value_box_copy(ctx, vb, tmpl_value(map->rhs));
		fr_dcursor_append(out, vb);
		break;
	}

	talloc_free(target);

	cache_free(inst, &c);
	cache_release(inst, request, &handle);

	/*
	 *	Check if we found a matching map
	 */
	if (!map) return XLAT_ACTION_FAIL;

	return XLAT_ACTION_DONE;
}

/** Release the allocated resources and cleanup the avps
 */
static void cache_unref(request_t *request, rlm_cache_t const *inst, rlm_cache_entry_t *entry,
			rlm_cache_handle_t *handle)
{
	fr_dcursor_t	cursor;
	fr_pair_t	*vp;

	/*
	 *	Release the driver calls
	 */
	cache_free(inst, &entry);
	cache_release(inst, request, &handle);

	/*
	 *	Clear control attributes
	 */
	for (vp = fr_pair_dcursor_init(&cursor, &request->control_pairs);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
	     again:
		if (!fr_dict_attr_is_top_level(vp->da)) continue;

		switch (vp->da->attr) {
		case FR_CACHE_TTL:
		case FR_CACHE_STATUS_ONLY:
		case FR_CACHE_ALLOW_MERGE:
		case FR_CACHE_ALLOW_INSERT:
		case FR_CACHE_MERGE_NEW:
			RDEBUG2("Removing &control:%s", vp->da->name);
			vp = fr_dcursor_remove(&cursor);
			TALLOC_FREE(vp);
			vp = fr_dcursor_current(&cursor);
			if (!vp) break;
			goto again;
		}
	}
}

/** Free any memory allocated under the instance
 *
 */
static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_cache_t *inst = talloc_get_type_abort(mctx->inst->data, rlm_cache_t);

	/*
	 *	We need to explicitly free all children, so if the driver
	 *	parented any memory off the instance, their destructors
	 *	run before we unload the bytecode for them.
	 *
	 *	If we don't do this, we get a SEGV deep inside the talloc code
	 *	when it tries to call a destructor that no longer exists.
	 */
	talloc_free_children(inst);

	return 0;
}

/** Register module xlats
 *
 */
static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_cache_t 	*inst = talloc_get_type_abort(mctx->inst->data, rlm_cache_t );
	xlat_t		*xlat;

	inst->driver = (rlm_cache_driver_t const *)inst->driver_submodule->dl_inst->module->common;

	/*
	 *	Non optional fields and callbacks
	 */
	fr_assert(inst->driver->common.name);
	fr_assert(inst->driver->find);
	fr_assert(inst->driver->insert);
	fr_assert(inst->driver->expire);

	/*
	 *	Register the cache xlat function
	 */
	xlat = xlat_register_module(inst, mctx, mctx->inst->name, cache_xlat, FR_TYPE_VOID, 0);
	xlat_func_args(xlat, cache_xlat_args);

	return 0;
}

/** Create a new rlm_cache_instance
 *
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_cache_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_cache_t);
	CONF_SECTION	*conf = mctx->inst->conf;
	CONF_SECTION	*update;

	fr_assert(inst->config.key);

	if (!fr_time_delta_ispos(inst->config.ttl)) {
		cf_log_err(conf, "Must set 'ttl' to non-zero");
		return -1;
	}

	if (inst->config.epoch != 0) {
		cf_log_err(conf, "Must not set 'epoch' in the configuration files");
		return -1;
	}

	update = cf_section_find(conf, "update", CF_IDENT_ANY);
	if (!update) {
		cf_log_err(conf, "Must have an 'update' section in order to cache anything");
		return -1;
	}

	/*
	 *	Make sure the users don't screw up too badly.
	 */
	{
		tmpl_rules_t	parse_rules = {
			.attr = {
				.list_def = PAIR_LIST_REQUEST,
				.allow_wildcard = true,
				.allow_foreign = true	/* Because we don't know where we'll be called */
			}
		};

		map_list_init(&inst->maps);
		if (map_afrom_cs(inst, &inst->maps, update,
				 &parse_rules, &parse_rules, cache_verify, NULL, MAX_ATTRMAP) < 0) {
			return -1;
		}
	}

	if (map_list_empty(&inst->maps)) {
		cf_log_err(conf, "Cache config must contain an update section, and "
			      "that section must not be empty");
		return -1;
	}

	return 0;
}

/** Get the status by ${key} (without load)
 *
 * @return
 *	- #RLM_MODULE_OK on success.
 *	- #RLM_MODULE_NOTFOUND on cache miss.
 *	- #RLM_MODULE_FAIL on failure.
 */
static unlang_action_t CC_HINT(nonnull) mod_method_status(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_cache_t const	*inst = talloc_get_type_abort(mctx->inst->data, rlm_cache_t);
	rlm_rcode_t		rcode = RLM_MODULE_NOOP;
	uint8_t			buffer[1024];
	uint8_t const		*key;
	ssize_t			key_len;
	rlm_cache_entry_t 	*entry = NULL;
	rlm_cache_handle_t 	*handle = NULL;

	DEBUG3("Calling %s.status", mctx->inst->name);

	key_len = tmpl_expand((char const **)&key, (char *)buffer, sizeof(buffer),
			      request, inst->config.key, NULL, NULL);
	if (key_len < 0) {
		RETURN_MODULE_FAIL;
	}

	if (key_len == 0) {
		REDEBUG("Zero length key string is invalid");
		RETURN_MODULE_FAIL;
	}

	/* Good to go? */
	if (cache_acquire(&handle, inst, request) < 0) {
		RETURN_MODULE_FAIL;
	}

	fr_assert(!inst->driver->acquire || handle);

	cache_find(&rcode, &entry, inst, request, &handle, key, key_len);
	if (rcode == RLM_MODULE_FAIL) goto finish;

	rcode = (entry) ? RLM_MODULE_OK : RLM_MODULE_NOTFOUND;

finish:
	cache_unref(request, inst, entry, handle);

	RETURN_MODULE_RCODE(rcode);
}

/** Load the avps by ${key}.
 *
 * @return
 *	- #RLM_MODULE_UPDATED on success.
 *	- #RLM_MODULE_NOTFOUND on cache miss.
 *	- #RLM_MODULE_FAIL on failure.
 */
static unlang_action_t CC_HINT(nonnull) mod_method_load(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_cache_t const	*inst = talloc_get_type_abort(mctx->inst->data, rlm_cache_t);
	rlm_rcode_t		rcode = RLM_MODULE_NOOP;
	uint8_t			buffer[1024];
	uint8_t const		*key;
	ssize_t			key_len;
	rlm_cache_entry_t 	*entry = NULL;
	rlm_cache_handle_t 	*handle = NULL;

	DEBUG3("Calling %s.load", mctx->inst->name);

	key_len = tmpl_expand((char const **)&key, (char *)buffer, sizeof(buffer),
			      request, inst->config.key, NULL, NULL);
	if (key_len < 0) {
		RETURN_MODULE_FAIL;
	}

	if (key_len == 0) {
		REDEBUG("Zero length key string is invalid");
		RETURN_MODULE_FAIL;
	}

	/* Good to go? */
	if (cache_acquire(&handle, inst, request) < 0) {
		RETURN_MODULE_FAIL;
	}

	cache_find(&rcode, &entry, inst, request, &handle, key, key_len);
	if (rcode == RLM_MODULE_FAIL) goto finish;

	if (!entry) {
		WARN("Entry not found to be load");
		rcode = RLM_MODULE_NOTFOUND;
		goto finish;
	}

	rcode = cache_merge(inst, request, entry);

finish:
	cache_unref(request, inst, entry, handle);

	RETURN_MODULE_RCODE(rcode);
}

/** Create and insert a cache entry
 *
 * @return
 *	- #RLM_MODULE_OK on success.
 *	- #RLM_MODULE_UPDATED if we merged the cache entry.
 *	- #RLM_MODULE_FAIL on failure.
 */
static unlang_action_t CC_HINT(nonnull) mod_method_store(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_cache_t const	*inst = talloc_get_type_abort(mctx->inst->data, rlm_cache_t);
	rlm_rcode_t		rcode = RLM_MODULE_NOOP;
	uint8_t			buffer[1024];
	uint8_t const		*key;
	ssize_t			key_len;
	fr_time_delta_t		ttl;
	bool 			expire = false;
	rlm_cache_entry_t 	*entry = NULL;
	rlm_cache_handle_t 	*handle = NULL;
	fr_pair_t		*vp;

	DEBUG3("Calling %s.store", mctx->inst->name);

	key_len = tmpl_expand((char const **)&key, (char *)buffer, sizeof(buffer),
			      request, inst->config.key, NULL, NULL);
	if (key_len < 0) {
		RETURN_MODULE_FAIL;
	}

	if (key_len == 0) {
		REDEBUG("Zero length key string is invalid");
		RETURN_MODULE_FAIL;
	}

	/* Good to go? */
	if (cache_acquire(&handle, inst, request) < 0) {
		RETURN_MODULE_FAIL;
	}

	/* Process the TTL */
	ttl = inst->config.ttl; /* Set the default value from cache { ttl=... } */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_cache_ttl);
	if (vp) {
		if (vp->vp_int32 == 0) {
			expire = true;
		} else if (vp->vp_int32 < 0) {
			ttl = fr_time_delta_from_sec(-(vp->vp_int32));
		/* Updating the TTL */
		} else {
			ttl = fr_time_delta_from_sec(vp->vp_int32);
		}

		DEBUG3("Overwriting the default TTL %pV -> %d", fr_box_time_delta(ttl), vp->vp_int32);
	}

	/*
	 *	We can only alter the TTL on an entry if it exists.
	 */
	cache_find(&rcode, &entry, inst, request, &handle, key, key_len);
	if (rcode == RLM_MODULE_FAIL) goto finish;

	if (rcode == RLM_MODULE_OK) {
		fr_assert(entry != NULL);

		DEBUG3("Updating the TTL -> %pV", fr_box_time_delta(ttl));

		entry->expires = fr_unix_time_add(fr_time_to_unix_time(request->packet->timestamp), ttl);

		cache_set_ttl(&rcode, inst, request, &handle, entry);
		if (rcode == RLM_MODULE_FAIL) goto finish;
	}

	/*
	 *	Expire the entry if told to, and we either don't know whether
	 *	it exists, or we know it does.
	 *
	 *	We only expire if we're not inserting, as driver insert methods
	 *	should perform upserts.
	 */
	if (expire) {
		DEBUG4("Set the cache expire");

		cache_expire(&rcode, inst, request, &handle, key, key_len);
		if (rcode == RLM_MODULE_FAIL) goto finish;
	}

	/*
	 *	Inserts are upserts, so we don't care about the
	 *	entry state, just that we're not meant to be
	 *	setting the TTL, which precludes performing an
	 *	insert.
	 */
	cache_insert(&rcode, inst, request, &handle, key, key_len, ttl);
	if (rcode == RLM_MODULE_OK) rcode = RLM_MODULE_UPDATED;

finish:
	cache_unref(request, inst, entry, handle);

	RETURN_MODULE_RCODE(rcode);
}

/** Delete the entries by ${key}
 *
 * @return
 *	- #RLM_MODULE_OK on success.
 *	- #RLM_MODULE_NOTFOUND on cache miss.
 *	- #RLM_MODULE_FAIL on failure.
 */
static unlang_action_t CC_HINT(nonnull) mod_method_clear(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_cache_t const	*inst = talloc_get_type_abort(mctx->inst->data, rlm_cache_t);
	rlm_rcode_t		rcode = RLM_MODULE_NOOP;
	uint8_t			buffer[1024];
	uint8_t const		*key;
	ssize_t			key_len;
	rlm_cache_entry_t 	*entry = NULL;
	rlm_cache_handle_t 	*handle = NULL;

	DEBUG3("Calling %s.clear", mctx->inst->name);

	key_len = tmpl_expand((char const **)&key, (char *)buffer, sizeof(buffer),
			      request, inst->config.key, NULL, NULL);
	if (key_len < 0) {
		RETURN_MODULE_FAIL;
	}

	if (key_len == 0) {
		REDEBUG("Zero length key string is invalid");
		RETURN_MODULE_FAIL;
	}

	/* Good to go? */
	if (cache_acquire(&handle, inst, request) < 0) {
		RETURN_MODULE_FAIL;
	}

	cache_find(&rcode, &entry, inst, request, &handle, key, key_len);
	if (rcode == RLM_MODULE_FAIL) goto finish;

	if (!entry) {
		WARN("Entry not found to be deleted");
		rcode = RLM_MODULE_NOTFOUND;
		goto finish;
	}

	cache_expire(&rcode, inst, request, &handle, key, key_len);

finish:
	cache_unref(request, inst, entry, handle);

	RETURN_MODULE_RCODE(rcode);
}

/** Change the TTL on an existing entry.
 *
 * @return
 *	- #RLM_MODULE_UPDATED on success.
 *	- #RLM_MODULE_NOTFOUND on cache miss.
 *	- #RLM_MODULE_FAIL on failure.
 */
static unlang_action_t CC_HINT(nonnull) mod_method_ttl(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_cache_t const	*inst = talloc_get_type_abort(mctx->inst->data, rlm_cache_t);
	rlm_rcode_t		rcode = RLM_MODULE_NOOP;
	uint8_t			buffer[1024];
	uint8_t const		*key;
	ssize_t			key_len;
	fr_time_delta_t		ttl;
	rlm_cache_entry_t 	*entry = NULL;
	rlm_cache_handle_t 	*handle = NULL;
	fr_pair_t		*vp;

	DEBUG3("Calling %s.ttl", mctx->inst->name);

	key_len = tmpl_expand((char const **)&key, (char *)buffer, sizeof(buffer),
			      request, inst->config.key, NULL, NULL);
	if (key_len < 0) {
		RETURN_MODULE_FAIL;
	}

	if (key_len == 0) {
		REDEBUG("Zero length key string is invalid");
		RETURN_MODULE_FAIL;
	}

	/* Good to go? */
	if (cache_acquire(&handle, inst, request) < 0) {
		RETURN_MODULE_FAIL;
	}

	/* Process the TTL */
	ttl = inst->config.ttl; /* Set the default value from cache { ttl=... } */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_cache_ttl);
	if (vp) {
		if (vp->vp_int32 < 0) {
			ttl = fr_time_delta_from_sec(-(vp->vp_int32));
		/* Updating the TTL */
		} else {
			ttl = fr_time_delta_from_sec(vp->vp_int32);
		}

		DEBUG3("Overwriting the default TTL %pV -> %d", fr_box_time_delta(inst->config.ttl), vp->vp_int32);
	}

	/*
	 *	We can only alter the TTL on an entry if it exists.
	 */
	cache_find(&rcode, &entry, inst, request, &handle, key, key_len);
	if (rcode == RLM_MODULE_FAIL) goto finish;

	if (rcode == RLM_MODULE_OK) {
		fr_assert(entry != NULL);

		DEBUG3("Updating the TTL -> %pV", fr_box_time_delta(ttl));

		entry->expires = fr_unix_time_add(fr_time_to_unix_time(request->packet->timestamp), ttl);

		cache_set_ttl(&rcode, inst, request, &handle, entry);
		if (rcode == RLM_MODULE_FAIL) goto finish;

		rcode = RLM_MODULE_UPDATED;
	}

finish:
	cache_unref(request, inst, entry, handle);

	RETURN_MODULE_RCODE(rcode);
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_rlm_t rlm_cache = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "cache",
		.inst_size	= sizeof(rlm_cache_t),
		.config		= module_config,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate,
		.detach		= mod_detach
	},
	.method_names = (module_method_name_t[]){
		{ .name1 = "status", .name2 = CF_IDENT_ANY,		.method = mod_method_status },
		{ .name1 = "load", .name2 = CF_IDENT_ANY,		.method = mod_method_load   },
		{ .name1 = "store", .name2 = CF_IDENT_ANY,		.method = mod_method_store  },
		{ .name1 = "clear", .name2 = CF_IDENT_ANY,		.method = mod_method_clear  },
		{ .name1 = "ttl", .name2 = CF_IDENT_ANY,		.method = mod_method_ttl    },
		{ .name1 = CF_IDENT_ANY, .name2 = CF_IDENT_ANY,		.method = mod_cache_it      },
		MODULE_NAME_TERMINATOR
	}
};
