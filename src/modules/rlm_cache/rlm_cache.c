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

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/modcall.h>
#include <freeradius-devel/rad_assert.h>

#include "rlm_cache.h"

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
	{ "driver", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_cache_config_t, driver_name), "rlm_cache_rbtree" },
	{ "key", FR_CONF_OFFSET(PW_TYPE_TMPL | PW_TYPE_REQUIRED, rlm_cache_config_t, key), NULL },
	{ "ttl", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_cache_config_t, ttl), "500" },
	{ "max_entries", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_cache_config_t, max_entries), "0" },

	/* Should be a type which matches time_t, @fixme before 2038 */
	{ "epoch", FR_CONF_OFFSET(PW_TYPE_SIGNED, rlm_cache_config_t, epoch), "0" },
	{ "add_stats", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_cache_config_t, stats), "no" },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};

/** Get exclusive use of a handle to access the cache
 *
 */
static int cache_acquire(rlm_cache_handle_t **out, rlm_cache_t *inst, REQUEST *request)
{
	if (!inst->driver->acquire) return 0;

	return inst->driver->acquire(out, &inst->config, inst->driver_inst, request);
}

/** Release a handle we previously acquired
 *
 */
static void cache_release(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle)
{
	if (!inst->driver->release) return;
	if (!handle || !*handle) return;

	inst->driver->release(&inst->config, inst->driver_inst, request, *handle);
	*handle = NULL;
}

/** Reconnect an suspected inviable handle
 *
 */
static int cache_reconnect(rlm_cache_handle_t **handle, rlm_cache_t *inst, REQUEST *request)
{
	rad_assert(inst->driver->reconnect);

	return inst->driver->reconnect(handle, &inst->config, inst->driver_inst, request);
}

/** Allocate a cache entry
 *
 *  This is used so that drivers may use their own allocation functions
 *  to allocate structures larger than the normal rlm_cache_entry_t.
 *
 *  If the driver doesn't specify a custom allocation function, the cache
 *  entry is talloced in the NULL ctx.
 */
static rlm_cache_entry_t *cache_alloc(rlm_cache_t *inst, REQUEST *request)
{
	if (inst->driver->alloc) return inst->driver->alloc(&inst->config, inst->driver_inst, request);

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
static void cache_free(rlm_cache_t *inst, rlm_cache_entry_t **c)
{
	if (!c || !*c || !inst->driver->free) return;

	inst->driver->free(*c);
	*c = NULL;
}

/** Merge a cached entry into a #REQUEST
 *
 */
static void cache_merge(rlm_cache_t *inst, REQUEST *request, rlm_cache_entry_t *c) CC_HINT(nonnull);
static void cache_merge(rlm_cache_t *inst, REQUEST *request, rlm_cache_entry_t *c)
{
	VALUE_PAIR	*vp;
	vp_map_t	*map;

	vp = pairfind(request->config, PW_CACHE_MERGE, 0, TAG_ANY);
	if (vp && (vp->vp_integer == 0)) {
		RDEBUG2("Told not to merge entry into request");
		return;
	}

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

			map_prints(buffer, sizeof(buffer), map);
			REXDENT();
			RDEBUG("Skipping %s", buffer);
			RINDENT();
			continue;
		}
	}
	REXDENT();

	if (inst->config.stats) {
		rad_assert(request->packet != NULL);
		vp = pairfind(request->packet->vps, PW_CACHE_ENTRY_HITS, 0, TAG_ANY);
		if (!vp) {
			vp = paircreate(request->packet, PW_CACHE_ENTRY_HITS, 0);
			rad_assert(vp != NULL);
			pairadd(&request->packet->vps, vp);
		}
		vp->vp_integer = c->hits;
	}
}

/** Find a cached entry.
 *
 * @return
 *	- #RLM_MODULE_OK on cache hit.
 *	- #RLM_MODULE_FAIL on failure.
 *	- #RLM_MODULE_NOTFOUND on cache miss.
 */
static rlm_rcode_t cache_find(rlm_cache_entry_t **out, rlm_cache_t *inst, REQUEST *request,
			      rlm_cache_handle_t **handle, uint8_t const *key, size_t key_len)
{
	cache_status_t ret;

	rlm_cache_entry_t *c;

	*out = NULL;

	for (;;) {
		ret = inst->driver->find(&c, &inst->config, inst->driver_inst, request, *handle, key, key_len);
		switch (ret) {
		case CACHE_RECONNECT:
			RDEBUG("Reconnecting...");
			if (cache_reconnect(handle, inst, request) == 0) continue;
			return RLM_MODULE_FAIL;

		case CACHE_OK:
			break;

		case CACHE_MISS:
			if (RDEBUG_ENABLED2) {
				char *p;

				p = fr_aprints(request, (char const *)key, key_len, '"');
				RDEBUG("No cache entry found for \"%s\"", p);
				talloc_free(p);
			}
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
	if ((c->expires < request->timestamp) || (c->created < inst->config.epoch)) {
		if (RDEBUG_ENABLED2) {
			char *p;

			p = fr_aprints(request, (char const *)key, key_len, '"');
			RDEBUG2("Found entry for \"%s\", but it expired %li seconds ago.  Removing it", p,
				request->timestamp - c->expires);
			talloc_free(p);
		}

		inst->driver->expire(&inst->config, inst->driver_inst, request, handle, c);
		cache_free(inst, &c);
		return RLM_MODULE_NOTFOUND;	/* Couldn't find a non-expired entry */
	}

	if (RDEBUG_ENABLED2) {
		char *p;

		p = fr_aprints(request, (char const *)key, key_len, '"');
		RDEBUG2("Found entry for \"%s\"", p);
		talloc_free(p);
	}

	c->hits++;
	*out = c;

	return RLM_MODULE_OK;
}

/** Expire a cache entry (removing it from the datastore)
 *
 */
static void cache_expire(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle, rlm_cache_entry_t **c)
{
	rad_assert(*c);

	for (;;) switch (inst->driver->expire(&inst->config, inst->driver_inst, request, handle, *c)) {
	case CACHE_RECONNECT:
		if (cache_reconnect(handle, inst, request) == 0) continue;

	/* FALL-THROUGH */
	default:
		cache_free(inst, c);
		*c = NULL;
		return;
	}
}

/** Create and insert a cache entry
 *
 * @return
 *	- #RLM_MODULE_OK on success.
 *	- #RLM_MODULE_UPDATED if we merged the cache entry.
 *	- #RLM_MODULE_FAIL on failure.
 */
static rlm_rcode_t cache_insert(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle,
				uint8_t const *key, size_t key_len, int ttl)
{
	vp_map_t		const *map;
	vp_map_t		**last, *c_map;

	VALUE_PAIR		*vp;
	bool			merge = false;
	rlm_cache_entry_t	*c;

	TALLOC_CTX		*pool;

	if ((inst->config.max_entries > 0) && inst->driver->count &&
	    (inst->driver->count(&inst->config, inst->driver_inst, request, handle) > inst->config.max_entries)) {
		RWDEBUG("Cache is full: %d entries", inst->config.max_entries);
		return RLM_MODULE_FAIL;
	}

	c = cache_alloc(inst, request);
	if (!c) return RLM_MODULE_FAIL;

	c->key = talloc_memdup(c, key, key_len);
	c->key_len = key_len;
	c->created = c->expires = request->timestamp;
	c->expires += ttl;

	last = &c->maps;

	RDEBUG("Creating new cache entry");

	/*
	 *	Alloc a pool so we don't have excessive mallocs when
	 *	gathering VALUE_PAIRs to cache.
	 */
	pool = talloc_pool(NULL, 1024);
	for (map = inst->maps; map != NULL; map = map->next) {
		VALUE_PAIR	*to_cache = NULL;
		vp_cursor_t	cursor;

		rad_assert(map->lhs && map->rhs);

		/*
		 *	Calling map_to_vp gives us exactly the same result,
		 *	as if this were an update section.
		 */
		if (map_to_vp(pool, &to_cache, request, map, NULL) < 0) {
			RDEBUG("Skipping %s", map->rhs->name);
			continue;
		}

		for (vp = fr_cursor_init(&cursor, &to_cache);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			/*
			 *	Prevent people from accidentally caching
			 *	cache control attributes.
			 */
			if (map->rhs->type == TMPL_TYPE_LIST) switch (vp->da->attr) {
			case PW_CACHE_TTL:
			case PW_CACHE_STATUS_ONLY:
			case PW_CACHE_READ_ONLY:
			case PW_CACHE_MERGE:
			case PW_CACHE_ENTRY_HITS:
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
			 *	RHS with the value_data_t from the VALUE_PAIR.
			 */
			case TMPL_TYPE_ATTR:
				c_map->lhs = map->lhs;	/* lhs shouldn't be touched, so this is ok */
			do_rhs:
				MEM(c_map->rhs = tmpl_init(talloc(c_map, vp_tmpl_t),
							   TMPL_TYPE_DATA, map->rhs->name, map->rhs->len));
				if (value_data_copy(c_map->rhs, &c_map->rhs->tmpl_data_value,
						    vp->da->type, &vp->data) < 0) {
					REDEBUG("Failed copying attribute value");
					talloc_free(pool);
					talloc_free(c);
					return RLM_MODULE_FAIL;
				}
				c_map->rhs->tmpl_data_type = vp->da->type;
				if (vp->da->type == PW_TYPE_STRING) {
					c_map->rhs->quote = is_printable(vp->vp_strvalue, vp->vp_length) ? '\'' : '"';
				}
				break;

			/*
			 *	Lists are weird... We need to fudge a new LHS template,
			 *	which is a combination of the LHS list and the attribute.
			 */
			case TMPL_TYPE_LIST:
			{
				char attr[256];

				MEM(c_map->lhs = tmpl_init(talloc(c_map, vp_tmpl_t),
							   TMPL_TYPE_ATTR, map->lhs->name, map->lhs->len));
				c_map->lhs->tmpl_da = vp->da;
				c_map->lhs->tmpl_tag = vp->tag;
				c_map->lhs->tmpl_list = map->lhs->tmpl_list;
				c_map->lhs->tmpl_num = map->lhs->tmpl_num;
				c_map->lhs->tmpl_request = map->lhs->tmpl_request;

				/*
				 *	We need to rebuild the attribute name, to be the
				 *	one we copied from the source list.
				 */
				c_map->lhs->len = tmpl_prints(attr, sizeof(attr), c_map->lhs, NULL);
				c_map->lhs->name = talloc_strdup(map->lhs, attr);
			}
				goto do_rhs;

			default:
				rad_assert(0);
			}
			*last = c_map;
			last = &(*last)->next;
		}
		talloc_free_children(pool); /* reset pool state */
	}
	talloc_free(pool);

	/*
	 *	Check to see if we need to merge the entry into the request
	 */
	vp = pairfind(request->config, PW_CACHE_MERGE, 0, TAG_ANY);
	if (vp && (vp->vp_integer > 0)) merge = true;

	if (merge) cache_merge(inst, request, c);

	for (;;) {
		cache_status_t ret;

		ret = inst->driver->insert(&inst->config, inst->driver_inst, request, *handle, c);
		switch (ret) {
		case CACHE_RECONNECT:
			if (cache_reconnect(handle, inst, request) == 0) continue;
			return RLM_MODULE_FAIL;

		case CACHE_OK:
			RDEBUG("Commited entry, TTL %d seconds", ttl);
			cache_free(inst, &c);
			return merge ? RLM_MODULE_UPDATED :
				       RLM_MODULE_OK;

		default:
			talloc_free(c);	/* Failed insertion - use talloc_free not the driver free */
			return RLM_MODULE_FAIL;
		}
	}
}

/** Verify that a map in the cache section makes sense
 *
 */
static int cache_verify(vp_map_t *map, void *ctx)
{
	if (modcall_fixup_update(map, ctx) < 0) return -1;

	if ((map->lhs->type != TMPL_TYPE_ATTR) &&
	    (map->lhs->type != TMPL_TYPE_LIST)) {
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
static rlm_rcode_t mod_cache_it(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_cache_it(void *instance, REQUEST *request)
{
	rlm_cache_entry_t	*c;
	rlm_cache_t		*inst = instance;

	rlm_cache_handle_t	*handle;

	vp_cursor_t		cursor;
	VALUE_PAIR		*vp;
	uint8_t			buffer[1024];
	uint8_t const		*key;
	ssize_t			key_len;
	rlm_rcode_t		rcode;

	int ttl = inst->config.ttl;

	key_len = tmpl_expand((char const **)&key, (char *)buffer, sizeof(buffer),
			     request, inst->config.key, NULL, NULL);
	if (key_len < 0) return RLM_MODULE_FAIL;

	if (key_len == 0) {
		REDEBUG("Zero length key string is invalid");
		return RLM_MODULE_INVALID;
	}

	if (cache_acquire(&handle, inst, request) < 0) return RLM_MODULE_FAIL;

	rcode = cache_find(&c, inst, request, &handle, key, key_len);
	if (rcode == RLM_MODULE_FAIL) goto finish;
	rad_assert(handle);

	/*
	 *	If Cache-Status-Only == yes, only return whether we found a
	 *	valid cache entry
	 */
	vp = pairfind(request->config, PW_CACHE_STATUS_ONLY, 0, TAG_ANY);
	if (vp && vp->vp_integer) {
		rcode = c ? RLM_MODULE_OK:
			    RLM_MODULE_NOTFOUND;
		goto finish;
	}

	/*
	 *	Update the expiry time based on the TTL.
	 *	A TTL of 0 means "delete from the cache".
	 *	A TTL < 0 means "delete from the cache and recreate the entry".
	 */
	vp = pairfind(request->config, PW_CACHE_TTL, 0, TAG_ANY);
	if (vp) ttl = vp->vp_signed;

	/*
	 *	If there's no existing cache entry, go and create a new one.
	 */
	if (!c) {
		if (ttl <= 0) ttl = inst->config.ttl;
		goto insert;
	}

	/*
	 *	Expire the entry if requested to do so
	 */
	if (vp) {
		if (ttl == 0) {
			cache_expire(inst, request, handle, &c);
			RDEBUG("Forcing expiry of entry");
			rcode = RLM_MODULE_OK;
			goto finish;
		}

		if (ttl < 0) {
			RDEBUG("Forcing expiry of existing entry");
			cache_expire(inst, request, handle, &c);
			ttl *= -1;
			goto insert;
		}
		c->expires = request->timestamp + ttl;
		RDEBUG("Setting TTL to %d", ttl);
	}

	/*
	 *	Cache entry was still valid, so we merge it into the request
	 *	and return. No need to add a new entry.
	 */
	cache_merge(inst, request, c);
	rcode = RLM_MODULE_UPDATED;

	goto finish;

insert:
	/*
	 *	If Cache-Read-Only == yes, then we only allow already cached entries
	 *	to be merged into the request
	 */
	vp = pairfind(request->config, PW_CACHE_READ_ONLY, 0, TAG_ANY);
	if (vp && vp->vp_integer) {
		rcode = RLM_MODULE_NOTFOUND;
		goto finish;
	}

	/*
	 *	Create a new entry.
	 */
	rcode = cache_insert(inst, request, &handle, key, key_len, ttl);
	rad_assert(handle);

finish:
	cache_free(inst, &c);
	cache_release(inst, request, &handle);

	/*
	 *	Clear control attributes
	 */
	for (vp = fr_cursor_init(&cursor, &request->config);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (vp->da->vendor == 0) switch (vp->da->attr) {
		case PW_CACHE_TTL:
		case PW_CACHE_STATUS_ONLY:
		case PW_CACHE_READ_ONLY:
		case PW_CACHE_MERGE:
			vp = fr_cursor_remove(&cursor);
			talloc_free(vp);
			break;
		}
	}

	return rcode;
}

/** Allow single attribute values to be retrieved from the cache
 *
 */
static ssize_t cache_xlat(void *instance, REQUEST *request, char const *fmt, char *out, size_t freespace)
			  CC_HINT(nonnull);
static ssize_t cache_xlat(void *instance, REQUEST *request, char const *fmt, char *out, size_t freespace)
{
	rlm_cache_entry_t 	*c = NULL;
	rlm_cache_t		*inst = instance;
	rlm_cache_handle_t	*handle = NULL;

	size_t			slen;
	ssize_t			ret = 0;

	uint8_t			buffer[1024];
	uint8_t const		*key;
	ssize_t			key_len;

	vp_tmpl_t		target;
	vp_map_t		*map = NULL;

	key_len = tmpl_expand((char const **)&key, (char *)buffer, sizeof(buffer),
			      request, inst->config.key, NULL, NULL);
	if (key_len < 0) return -1;

	slen = tmpl_from_attr_substr(&target, fmt, REQUEST_CURRENT, PAIR_LIST_REQUEST, false, false);
	if (slen <= 0) {
		REDEBUG("%s", fr_strerror());
		return -1;
	}

	if (cache_acquire(&handle, inst, request) < 0) return -1;

	switch (cache_find(&c, inst, request, handle, key, key_len)) {
	case RLM_MODULE_OK:		/* found */
		break;

	case RLM_MODULE_NOTFOUND:	/* not found */
		*out = '\0';
		return 0;

	default:
		return -1;
	}

	for (map = c->maps; map; map = map->next) {
		if ((map->lhs->tmpl_da != target.tmpl_da) ||
		    (map->lhs->tmpl_tag != target.tmpl_tag) ||
		    (map->lhs->tmpl_list != target.tmpl_list)) continue;

		ret = value_data_prints(out, freespace, map->rhs->tmpl_data_type,
					map->lhs->tmpl_da, &map->rhs->tmpl_data_value, '\0');
		if (is_truncated(slen, freespace)) {
			REDEBUG("Insufficient buffer space to write cached value");
			ret = -1;
			goto finish;
		}
		break;
	}

	/*
	 *	Check if we found a matching map
	 */
	if (!map) {
		*out = '\0';
		return 0;
	}

finish:
	cache_free(inst, &c);
	cache_release(inst, request, &handle);

	return ret;
}

/** Free any memory allocated under the instance
 *
 */
static int mod_detach(void *instance)
{
	rlm_cache_t *inst = instance;

	talloc_free(inst->maps);

	/*
	 *  We need to explicitly free all children, so if the driver
	 *  parented any memory off the instance, their destructors
	 *  run before we unload the bytecode for them.
	 *
	 *  If we don't do this, we get a SEGV deep inside the talloc code
	 *  when it tries to call a destructor that no longer exists.
	 */
	talloc_free_children(inst);

	/*
	 *  Decrements the reference count. The driver object won't be unloaded
	 *  until all instances of rlm_cache that use it have been destroyed.
	 */
	if (inst->handle) dlclose(inst->handle);

	return 0;
}

/** Register module xlats
 *
 */
static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_cache_t *inst = instance;

	inst->cs = conf;

	inst->config.name = cf_section_name2(conf);
	if (!inst->config.name) inst->config.name = cf_section_name1(conf);

	/*
	 *	Register the cache xlat function
	 */
	xlat_register(inst->config.name, cache_xlat, NULL, inst);

	return 0;
}

/** Create a new rlm_cache_instance
 *
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_cache_t	*inst = instance;
	CONF_SECTION	*update;

	inst->cs = conf;

	/*
	 *	Sanity check for crazy people.
	 */
	if (strncmp(inst->config.driver_name, "rlm_cache_", 8) != 0) {
		cf_log_err_cs(conf, "\"%s\" is NOT an Cache driver!", inst->config.driver_name);
		return -1;
	}

	/*
	 *	Load the appropriate driver for our database
	 */
	inst->handle = lt_dlopenext(inst->config.driver_name);
	if (!inst->handle) {
		cf_log_err_cs(conf, "Could not link driver %s: %s", inst->config.driver_name, dlerror());
		cf_log_err_cs(conf, "Make sure it (and all its dependent libraries!) are in the search path"
			      "of your system's ld");
		return -1;
	}

	inst->driver = (cache_driver_t *) dlsym(inst->handle, inst->config.driver_name);
	if (!inst->driver) {
		cf_log_err_cs(conf, "Could not link symbol %s: %s", inst->config.driver_name, dlerror());
		return -1;
	}

	INFO("rlm_cache (%s): Driver %s loaded and linked", inst->config.name, inst->driver->name);

	/*
	 *	Non optional fields and callbacks
	 */
	rad_assert(inst->driver->name);
	rad_assert(inst->driver->find);
	rad_assert(inst->driver->insert);
	rad_assert(inst->driver->expire);

	if (inst->driver->instantiate) {
		CONF_SECTION *cs;
		char const *name;

		name = strrchr(inst->config.driver_name, '_');
		if (!name) {
			name = inst->config.driver_name;
		} else {
			name++;
		}

		cs = cf_section_sub_find(conf, name);
		if (!cs) {
			cs = cf_section_alloc(conf, name, NULL);
			if (!cs) return -1;
		}

		/*
		 *	It's up to the driver to register a destructor (using talloc)
		 *
		 *	Should write its instance data in inst->driver,
		 *	and parent it off of inst.
		 */
		if (inst->driver->inst_size) MEM(inst->driver_inst = talloc_zero_array(inst, uint8_t,
										       inst->driver->inst_size));
		if (inst->driver->instantiate(cs, &inst->config, inst->driver_inst) < 0) return -1;
	}

	if (inst->config.ttl == 0) {
		cf_log_err_cs(conf, "Must set 'ttl' to non-zero");
		return -1;
	}

	if (inst->config.epoch != 0) {
		cf_log_err_cs(conf, "Must not set 'epoch' in the configuration files");
		return -1;
	}

	update = cf_section_sub_find(inst->cs, "update");
	if (!update) {
		cf_log_err_cs(conf, "Must have an 'update' section in order to cache anything.");
		return -1;
	}

	/*
	 *	Make sure the users don't screw up too badly.
	 */
	if (map_afrom_cs(&inst->maps, update,
			 PAIR_LIST_REQUEST, PAIR_LIST_REQUEST, cache_verify, NULL, MAX_ATTRMAP) < 0) {
		return -1;
	}

	if (!inst->maps) {
		cf_log_err_cs(inst->cs, "Cache config must contain an update section, and "
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
extern module_t rlm_cache;
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
