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

#define LOG_PREFIX "%s - "
#define LOG_PREFIX_ARGS inst->config.name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/util/debug.h>

#include "rlm_cache.h"

extern module_t rlm_cache;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("driver", FR_TYPE_STRING, rlm_cache_config_t, driver_name), .dflt = "rlm_cache_rbtree" },
	{ FR_CONF_OFFSET("key", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_cache_config_t, key) },
	{ FR_CONF_OFFSET("ttl", FR_TYPE_UINT32, rlm_cache_config_t, ttl), .dflt = "500" },
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
static int cache_acquire(rlm_cache_handle_t **out, rlm_cache_t const *inst, REQUEST *request)
{
	if (!inst->driver->acquire) {
		*out = NULL;
		return 0;
	}

	return inst->driver->acquire(out, &inst->config, inst->driver_inst->dl_inst->data, request);
}

/** Release a handle we previously acquired
 *
 */
static void cache_release(rlm_cache_t const *inst, REQUEST *request, rlm_cache_handle_t **handle)
{
	if (!inst->driver->release) return;
	if (!handle || !*handle) return;

	inst->driver->release(&inst->config, inst->driver_inst->dl_inst->data, request, *handle);
	*handle = NULL;
}

/** Reconnect an suspected inviable handle
 *
 */
static int cache_reconnect(rlm_cache_handle_t **handle, rlm_cache_t const *inst, REQUEST *request)
{
	fr_assert(inst->driver->reconnect);

	return inst->driver->reconnect(handle, &inst->config, inst->driver_inst->dl_inst->data, request);
}

/** Allocate a cache entry
 *
 *  This is used so that drivers may use their own allocation functions
 *  to allocate structures larger than the normal rlm_cache_entry_t.
 *
 *  If the driver doesn't specify a custom allocation function, the cache
 *  entry is talloced in the NULL ctx.
 */
static rlm_cache_entry_t *cache_alloc(rlm_cache_t const *inst, REQUEST *request)
{
	if (inst->driver->alloc) return inst->driver->alloc(&inst->config, inst->driver_inst->dl_inst->data, request);

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

/** Merge a cached entry into a #REQUEST
 *
 * @return
 *	- #RLM_MODULE_OK if no entries were merged.
 *	- #RLM_MODULE_UPDATED if entries were merged.
 */
static rlm_rcode_t cache_merge(rlm_cache_t const *inst, REQUEST *request, rlm_cache_entry_t *c) CC_HINT(nonnull);
static rlm_rcode_t cache_merge(rlm_cache_t const *inst, REQUEST *request, rlm_cache_entry_t *c)
{
	VALUE_PAIR	*vp;
	vp_map_t	*map;
	int		merged = 0;

	RDEBUG2("Merging cache entry into request");
	RINDENT();
	for (map = c->maps; map; map = map->next) {
		/*
		 *	The only reason that the application of a map entry
		 *	can fail, is if the destination list or request
		 *	isn't valid. For now we don't consider this fatal
		 *	and continue merging the rest of the maps.
		 */
		if (map_to_request(request, map, map_to_vp, NULL) < 0) {
			char buffer[1024];

			map_snprint(NULL, buffer, sizeof(buffer), map);
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
static rlm_rcode_t cache_find(rlm_cache_entry_t **out, rlm_cache_t const *inst, REQUEST *request,
			      rlm_cache_handle_t **handle, uint8_t const *key, size_t key_len)
{
	cache_status_t ret;

	rlm_cache_entry_t *c;

	*out = NULL;

	for (;;) {
		ret = inst->driver->find(&c, &inst->config, inst->driver_inst->dl_inst->data, request, *handle, key, key_len);
		switch (ret) {
		case CACHE_RECONNECT:
			RDEBUG2("Reconnecting...");
			if (cache_reconnect(handle, inst, request) == 0) continue;
			return RLM_MODULE_FAIL;

		case CACHE_OK:
			break;

		case CACHE_MISS:
			RDEBUG2("No cache entry found for \"%pV\"", fr_box_strvalue_len((char const *)key, key_len));
			return RLM_MODULE_NOTFOUND;

		/* FALL-THROUGH */
		default:
			return RLM_MODULE_FAIL;

		}

		break;
	}

	/*
	 *	Yes, but it expired, OR the "forget all" epoch has
	 *	passed.  Delete it, and pretend it doesn't exist.
	 */
	if ((c->expires < fr_time_to_unix_time(request->packet->timestamp)) ||
	    (c->created < fr_unix_time_from_sec(inst->config.epoch))) {
		RDEBUG2("Found entry for \"%pV\", but it expired %pV seconds ago.  Removing it",
			fr_box_strvalue_len((char const *)key, key_len),
			fr_box_date(fr_time_to_unix_time(request->packet->timestamp -
							 fr_time_delta_from_sec(c->expires))));

		inst->driver->expire(&inst->config, inst->driver_inst->dl_inst->data, request, handle, c->key, c->key_len);
		cache_free(inst, &c);
		return RLM_MODULE_NOTFOUND;	/* Couldn't find a non-expired entry */
	}

	RDEBUG2("Found entry for \"%pV\"", fr_box_strvalue_len((char const *)key, key_len));

	c->hits++;
	*out = c;

	return RLM_MODULE_OK;
}

/** Expire a cache entry (removing it from the datastore)
 *
 * @return
 *	- #RLM_MODULE_OK on success.
 *	- #RLM_MODULE_NOTFOUND if no entry existed.
 *	- #RLM_MODULE_FAIL on failure.
 */
static rlm_rcode_t cache_expire(rlm_cache_t const *inst, REQUEST *request,
				rlm_cache_handle_t **handle, uint8_t const *key, size_t key_len)
{
	RDEBUG2("Expiring cache entry");
	for (;;) switch (inst->driver->expire(&inst->config, inst->driver_inst->dl_inst->data, request,
					      *handle, key, key_len)) {
	case CACHE_RECONNECT:
		if (cache_reconnect(handle, inst, request) == 0) continue;

	/* FALL-THROUGH */
	default:
		return RLM_MODULE_FAIL;

	case CACHE_OK:
		return RLM_MODULE_OK;

	case CACHE_MISS:
		return RLM_MODULE_NOTFOUND;
	}
}

/** Create and insert a cache entry
 *
 * @return
 *	- #RLM_MODULE_OK on success.
 *	- #RLM_MODULE_UPDATED if we merged the cache entry.
 *	- #RLM_MODULE_FAIL on failure.
 */
static rlm_rcode_t cache_insert(rlm_cache_t const *inst, REQUEST *request, rlm_cache_handle_t **handle,
				uint8_t const *key, size_t key_len, int ttl)
{
	vp_map_t		const *map;
	vp_map_t		**last, *c_map;

	VALUE_PAIR		*vp;
	bool			merge = false;
	rlm_cache_entry_t	*c;

	TALLOC_CTX		*pool;

	if ((inst->config.max_entries > 0) && inst->driver->count &&
	    (inst->driver->count(&inst->config, inst->driver_inst->dl_inst->data, request, handle) > inst->config.max_entries)) {
		RWDEBUG("Cache is full: %d entries", inst->config.max_entries);
		return RLM_MODULE_FAIL;
	}

	c = cache_alloc(inst, request);
	if (!c) return RLM_MODULE_FAIL;

	c->key = talloc_memdup(c, key, key_len);
	c->key_len = key_len;

	/*
	 *	All in NSEC resolution
	 */
	c->created = c->expires = fr_time_to_unix_time(request->packet->timestamp);
	c->expires += fr_time_delta_from_sec(ttl);

	last = &c->maps;

	RDEBUG2("Creating new cache entry");

	/*
	 *	Alloc a pool so we don't have excessive allocs when
	 *	gathering VALUE_PAIRs to cache.
	 */
	pool = talloc_pool(NULL, 2048);
	for (map = inst->maps; map != NULL; map = map->next) {
		VALUE_PAIR	*to_cache = NULL;
		fr_cursor_t	cursor;

		fr_assert(map->lhs && map->rhs);

		/*
		 *	Calling map_to_vp gives us exactly the same result,
		 *	as if this were an update section.
		 */
		if (map_to_vp(pool, &to_cache, request, map, NULL) < 0) {
			RDEBUG2("Skipping %s", map->rhs->name);
			continue;
		}

		for (vp = fr_cursor_init(&cursor, &to_cache);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
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

			MEM(c_map = talloc_zero(c, vp_map_t));
			c_map->op = map->op;

			/*
			 *	Now we turn the VALUE_PAIRs into maps.
			 */
			switch (map->lhs->type) {
			/*
			 *	Attributes are easy, reuse the LHS, and create a new
			 *	RHS with the fr_value_box_t from the VALUE_PAIR.
			 */
			case TMPL_TYPE_ATTR:
			{
				fr_token_t	quote;
				c_map->lhs = map->lhs;	/* lhs shouldn't be touched, so this is ok */
			do_rhs:
				if (vp->vp_type == FR_TYPE_STRING) {
					quote = is_printable(vp->vp_strvalue, vp->vp_length) ?
							     T_SINGLE_QUOTED_STRING : T_DOUBLE_QUOTED_STRING;
				} else {
					quote = T_BARE_WORD;
				}

				MEM(c_map->rhs = tmpl_alloc(c_map,
							    TMPL_TYPE_DATA, map->rhs->name, map->rhs->len, quote));
				if (fr_value_box_copy(c_map->rhs, tmpl_value(c_map->rhs), &vp->data) < 0) {
					REDEBUG("Failed copying attribute value");
				error:
					talloc_free(pool);
					talloc_free(c);
					return RLM_MODULE_FAIL;
				}
				tmpl_value_type(c_map->rhs) = vp->vp_type;

			}
				break;

			/*
			 *	Lists are weird... We need to fudge a new LHS template,
			 *	which is a combination of the LHS list and the attribute.
			 */
			case TMPL_TYPE_LIST:
				if (tmpl_attr_afrom_list(c_map, &c_map->lhs, map->lhs, vp->da, vp->tag) < 0) {
					RPERROR("Failed attribute -> list copy");
					goto error;
				}
				goto do_rhs;

			default:
				fr_assert(0);
			}
			MAP_VERIFY(c_map);
			*last = c_map;
			last = &(*last)->next;
		}
		talloc_free_children(pool); /* reset pool state */
	}
	talloc_free(pool);

	/*
	 *	Check to see if we need to merge the entry into the request
	 */
	vp = fr_pair_find_by_da(request->control, attr_cache_merge_new, TAG_ANY);
	if (vp && vp->vp_bool) merge = true;

	if (merge) cache_merge(inst, request, c);

	for (;;) {
		cache_status_t ret;

		ret = inst->driver->insert(&inst->config, inst->driver_inst->dl_inst->data, request, *handle, c);
		switch (ret) {
		case CACHE_RECONNECT:
			if (cache_reconnect(handle, inst, request) == 0) continue;
			return RLM_MODULE_FAIL;

		case CACHE_OK:
			RDEBUG2("Committed entry, TTL %d seconds", ttl);
			cache_free(inst, &c);
			return merge ? RLM_MODULE_UPDATED :
				       RLM_MODULE_OK;

		default:
			talloc_free(c);	/* Failed insertion - use talloc_free not the driver free */
			return RLM_MODULE_FAIL;
		}
	}
}

/** Update the TTL of an entry
 *
 * @return
 *	- #RLM_MODULE_OK on success.
 *	- #RLM_MODULE_FAIL on failure.
 */
static rlm_rcode_t cache_set_ttl(rlm_cache_t const *inst, REQUEST *request,
				 rlm_cache_handle_t **handle, rlm_cache_entry_t *c)
{
	/*
	 *	Call the driver's insert method to overwrite the old entry
	 */
	if (!inst->driver->set_ttl) for (;;) {
		cache_status_t ret;

		ret = inst->driver->insert(&inst->config, inst->driver_inst->dl_inst->data, request, *handle, c);
		switch (ret) {
		case CACHE_RECONNECT:
			if (cache_reconnect(handle, inst, request) == 0) continue;
			return RLM_MODULE_FAIL;

		case CACHE_OK:
			RDEBUG2("Updated entry TTL");
			return RLM_MODULE_OK;

		default:
			return RLM_MODULE_FAIL;
		}
	}

	/*
	 *	Or call the set ttl method if the driver can do this more
	 *	efficiently.
	 */
	for (;;) {
		cache_status_t ret;

		ret = inst->driver->set_ttl(&inst->config, inst->driver_inst->dl_inst->data, request, *handle, c);
		switch (ret) {
		case CACHE_RECONNECT:
			if (cache_reconnect(handle, inst, request) == 0) continue;
			return RLM_MODULE_FAIL;

		case CACHE_OK:
			RDEBUG2("Updated entry TTL");
			return RLM_MODULE_OK;

		default:
			return RLM_MODULE_FAIL;
		}
	}
}

/** Verify that a map in the cache section makes sense
 *
 */
static int cache_verify(vp_map_t *map, void *ctx)
{
	if (unlang_fixup_update(map, ctx) < 0) return -1;

	if (!tmpl_is_attr(map->lhs) &&
	    !tmpl_is_list(map->lhs)) {
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
static rlm_rcode_t mod_cache_it(void *instance, UNUSED void *thread, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_cache_it(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_cache_entry_t	*c = NULL;
	rlm_cache_t const	*inst = instance;

	rlm_cache_handle_t	*handle;

	fr_cursor_t		cursor;
	VALUE_PAIR		*vp;

	bool			merge = true, insert = true, expire = false, set_ttl = false;
	int			exists = -1;

	uint8_t			buffer[1024];
	uint8_t const		*key;
	ssize_t			key_len;
	rlm_rcode_t		rcode = RLM_MODULE_NOOP;

	int			ttl = inst->config.ttl;

	key_len = tmpl_expand((char const **)&key, (char *)buffer, sizeof(buffer),
			      request, inst->config.key, NULL, NULL);
	if (key_len < 0) return RLM_MODULE_FAIL;

	if (key_len == 0) {
		REDEBUG("Zero length key string is invalid");
		return RLM_MODULE_INVALID;
	}

	/*
	 *	If Cache-Status-Only == yes, only return whether we found a
	 *	valid cache entry
	 */
	vp = fr_pair_find_by_da(request->control, attr_cache_status_only, TAG_ANY);
	if (vp && vp->vp_bool) {
		RINDENT();
		RDEBUG3("status-only: yes");
		REXDENT();

		if (cache_acquire(&handle, inst, request) < 0) return RLM_MODULE_FAIL;

		rcode = cache_find(&c, inst, request, &handle, key, key_len);
		if (rcode == RLM_MODULE_FAIL) goto finish;
		fr_assert(!inst->driver->acquire || handle);

		rcode = c ? RLM_MODULE_OK:
			    RLM_MODULE_NOTFOUND;
		goto finish;
	}

	/*
	 *	Figure out what operation we're doing
	 */
	vp = fr_pair_find_by_da(request->control, attr_cache_allow_merge, TAG_ANY);
	if (vp) merge = vp->vp_bool;

	vp = fr_pair_find_by_da(request->control, attr_cache_allow_insert, TAG_ANY);
	if (vp) insert = vp->vp_bool;

	vp = fr_pair_find_by_da(request->control, attr_cache_ttl, TAG_ANY);
	if (vp) {
		if (vp->vp_int32 == 0) {
			expire = true;
		} else if (vp->vp_int32 < 0) {
			expire = true;
			ttl = -(vp->vp_int32);
		/* Updating the TTL */
		} else {
			set_ttl = true;
			ttl = vp->vp_int32;
		}
	}

	RINDENT();
	RDEBUG3("merge  : %s", merge ? "yes" : "no");
	RDEBUG3("insert : %s", insert ? "yes" : "no");
	RDEBUG3("expire : %s", expire ? "yes" : "no");
	RDEBUG3("ttl    : %i", ttl);
	REXDENT();
	if (cache_acquire(&handle, inst, request) < 0) return RLM_MODULE_FAIL;

	/*
	 *	Retrieve the cache entry and merge it with the current request
	 *	recording whether the entry existed.
	 */
	if (merge) {
		rcode = cache_find(&c, inst, request, &handle, key, key_len);
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
			fr_assert(!set_ttl);
			switch (cache_expire(inst, request, &handle, key, key_len)) {
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
		switch (cache_find(&c, inst, request, &handle, key, key_len)) {
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
		fr_assert(c);

		c->expires = fr_time_to_unix_time(request->packet->timestamp) + fr_unix_time_from_sec(ttl);

		switch (cache_set_ttl(inst, request, &handle, c)) {
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
		switch (cache_insert(inst, request, &handle, key, key_len, ttl)) {
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
	for (vp = fr_cursor_init(&cursor, &request->control);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
	     again:
		if (!fr_dict_attr_is_top_level(vp->da)) continue;

		switch (vp->da->attr) {
		case FR_CACHE_TTL:
		case FR_CACHE_STATUS_ONLY:
		case FR_CACHE_ALLOW_MERGE:
		case FR_CACHE_ALLOW_INSERT:
		case FR_CACHE_MERGE_NEW:
			RDEBUG2("Removing &control:%s", vp->da->name);
			vp = fr_cursor_remove(&cursor);
			talloc_free(vp);
			vp = fr_cursor_current(&cursor);
			if (!vp) break;
			goto again;
		}
	}

	return rcode;
}

/** Allow single attribute values to be retrieved from the cache
 *
 * @ingroup xlat_functions
 */
static ssize_t cache_xlat(TALLOC_CTX *ctx, char **out, UNUSED size_t freespace,
			  void const *mod_inst, UNUSED void const *xlat_inst,
			  REQUEST *request, char const *fmt) CC_HINT(nonnull);
static ssize_t cache_xlat(TALLOC_CTX *ctx, char **out, UNUSED size_t freespace,
			  void const *mod_inst, UNUSED void const *xlat_inst,
			  REQUEST *request, char const *fmt)
{
	rlm_cache_entry_t 	*c = NULL;
	rlm_cache_t const	*inst = mod_inst;
	rlm_cache_handle_t	*handle = NULL;

	ssize_t			slen;
	ssize_t			ret = 0;

	uint8_t			buffer[1024];
	uint8_t const		*key;
	ssize_t			key_len;

	vp_tmpl_t		*target = NULL;
	vp_map_t		*map = NULL;

	key_len = tmpl_expand((char const **)&key, (char *)buffer, sizeof(buffer),
			      request, inst->config.key, NULL, NULL);
	if (key_len < 0) return -1;

	slen = tmpl_afrom_attr_substr(ctx, NULL, &target, fmt, -1,
				      &(vp_tmpl_rules_t){
				      		.dict_def = request->dict,
				      		.prefix = VP_ATTR_REF_PREFIX_AUTO
				      });
	if (slen <= 0) {
		RPEDEBUG("Invalid key");
		return -1;
	}

	if (cache_acquire(&handle, mod_inst, request) < 0) {
		talloc_free(target);
		return -1;
	}

	switch (cache_find(&c, mod_inst, request, &handle, key, key_len)) {
	case RLM_MODULE_OK:		/* found */
		break;

	case RLM_MODULE_NOTFOUND:	/* not found */
		return 0;

	default:
		talloc_free(target);
		return -1;
	}

	for (map = c->maps; map; map = map->next) {
		if ((tmpl_da(map->lhs) != tmpl_da(target)) ||
		    (tmpl_tag(map->lhs) != tmpl_tag(target)) ||
		    (tmpl_list(map->lhs) != tmpl_list(target))) continue;

		*out = fr_value_box_asprint(request, tmpl_value(map->rhs), '\0');
		ret = talloc_array_length(*out) - 1;
		break;
	}

	talloc_free(target);

	/*
	 *	Check if we found a matching map
	 */
	if (!map) return 0;

	cache_free(mod_inst, &c);
	cache_release(mod_inst, request, &handle);

	return ret;
}

/** Free any memory allocated under the instance
 *
 */
static int mod_detach(void *instance)
{
	rlm_cache_t *inst = instance;

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
static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_cache_t 	*inst = instance;
	CONF_SECTION	*driver_cs;
	char const 	*name;

	inst->cs = conf;

	inst->config.name = cf_section_name2(conf);
	if (!inst->config.name) inst->config.name = cf_section_name1(conf);

	name = strrchr(inst->config.driver_name, '_');
	if (!name) {
		name = inst->config.driver_name;
	} else {
		name++;
	}

	driver_cs = cf_section_find(conf, name, NULL);
	if (!driver_cs) {
		driver_cs = cf_section_alloc(conf, conf, name, NULL);
		if (!driver_cs) return -1;
	}

	/*
	 *	Load the appropriate driver for our backend
	 */
	inst->driver_inst = module_bootstrap(module_by_data(inst), driver_cs);
	if (!inst->driver_inst) {
		cf_log_err(driver_cs, "Failed loading driver");
		return -1;
	}
	inst->driver = (rlm_cache_driver_t const *)inst->driver_inst->dl_inst->module->common;

	/*
	 *	Sanity check for crazy people.
	 */
	if (strncmp(inst->config.driver_name, "rlm_cache_", 10) != 0) {
		cf_log_err(conf, "\"%s\" is NOT an Cache driver!", inst->config.driver_name);
		return -1;
	}

	/*
	 *	Non optional fields and callbacks
	 */
	fr_assert(inst->driver->name);
	fr_assert(inst->driver->find);
	fr_assert(inst->driver->insert);
	fr_assert(inst->driver->expire);

	/*
	 *	Register the cache xlat function
	 */
	xlat_register(inst, inst->config.name, cache_xlat, NULL, NULL, 0, 0, true);

	return 0;
}

/** Create a new rlm_cache_instance
 *
 */
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_cache_t	*inst = instance;
	CONF_SECTION	*update;

	inst->cs = conf;

	fr_assert(inst->config.key);

	if (inst->config.ttl == 0) {
		cf_log_err(conf, "Must set 'ttl' to non-zero");
		return -1;
	}

	if (inst->config.epoch != 0) {
		cf_log_err(conf, "Must not set 'epoch' in the configuration files");
		return -1;
	}

	update = cf_section_find(inst->cs, "update", CF_IDENT_ANY);
	if (!update) {
		cf_log_err(conf, "Must have an 'update' section in order to cache anything");
		return -1;
	}

	/*
	 *	Make sure the users don't screw up too badly.
	 */
	{
		vp_tmpl_rules_t	parse_rules = {
			.allow_foreign = true	/* Because we don't know where we'll be called */
		};

		if (map_afrom_cs(inst, &inst->maps, update,
				 &parse_rules, &parse_rules, cache_verify, NULL, MAX_ATTRMAP) < 0) {
			return -1;
		}
	}

	if (!inst->maps) {
		cf_log_err(inst->cs, "Cache config must contain an update section, and "
			      "that section must not be empty");
		return -1;
	}

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_cache = {
	.magic		= RLM_MODULE_INIT,
	.name		= "cache",
	.inst_size	= sizeof(rlm_cache_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHORIZE]		= mod_cache_it,
		[MOD_PREACCT]		= mod_cache_it,
		[MOD_ACCOUNTING]	= mod_cache_it,
		[MOD_PRE_PROXY]		= mod_cache_it,
		[MOD_POST_PROXY]	= mod_cache_it,
		[MOD_POST_AUTH]		= mod_cache_it
	},
};
