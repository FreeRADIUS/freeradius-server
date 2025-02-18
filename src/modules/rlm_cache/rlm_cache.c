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
	{ "driver", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_cache_t, driver_name), "rlm_cache_rbtree" },
	{ "key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED | PW_TYPE_XLAT, rlm_cache_t, key), NULL },
	{ "ttl", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_cache_t, ttl), "500" },
	{ "max_entries", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_cache_t, max_entries), "0" },

	/* Should be a type which matches time_t, @fixme before 2038 */
	{ "epoch", FR_CONF_OFFSET(PW_TYPE_SIGNED, rlm_cache_t, epoch), "0" },
	{ "add_stats", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_cache_t, stats), "no" },
	CONF_PARSER_TERMINATOR
};

static int cache_acquire(rlm_cache_handle_t **out, rlm_cache_t *inst, REQUEST *request)
{
	if (!inst->module->acquire) return 0;

	return inst->module->acquire(out, inst, request);
}

static void cache_release(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle)
{
	if (!inst->module->release) return;
	if (!handle || !*handle) return;

	inst->module->release(inst, request, handle);
}

static int cache_reconnect(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle)
{
	rad_assert(inst->module->reconnect);

	return inst->module->reconnect(inst, request, handle);
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
	if (inst->module->alloc) return inst->module->alloc(inst, request);

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
 * @param c Cache entry to free.
 * @param inst Module instance.
 */
static void cache_free(rlm_cache_t *inst, rlm_cache_entry_t **c)
{
	if (!c || !*c || !inst->module->free) return;

	inst->module->free(*c);
	*c = NULL;
}

/*
 *	Merge a cached entry into a REQUEST.
 */
static void CC_HINT(nonnull) cache_merge(rlm_cache_t *inst, REQUEST *request, rlm_cache_entry_t *c)
{
	VALUE_PAIR *vp;

	vp = fr_pair_find_by_num(request->config, PW_CACHE_MERGE, 0, TAG_ANY);
	if (vp && (vp->vp_integer == 0)) {
		RDEBUG2("Told not to merge entry into request");
		return;
	}

	RDEBUG2("Merging cache entry into request");

	if (c->packet && request->packet) {
		rdebug_pair_list(L_DBG_LVL_2, request, c->packet, "&request:");
		radius_pairmove(request, &request->packet->vps, fr_pair_list_copy(request->packet, c->packet), false);
	}

	if (c->reply && request->reply) {
		rdebug_pair_list(L_DBG_LVL_2, request, c->reply, "&reply:");
		radius_pairmove(request, &request->reply->vps, fr_pair_list_copy(request->reply, c->reply), false);
	}

	if (c->control) {
		rdebug_pair_list(L_DBG_LVL_2, request, c->control, "&control:");
		radius_pairmove(request, &request->config, fr_pair_list_copy(request, c->control), false);
	}

	if (c->state) {
		rdebug_pair_list(L_DBG_LVL_2, request, c->state, "&session-state:");

		fr_pair_list_mcopy_by_num(request->state_ctx, &request->state, &c->state, 0, 0, TAG_ANY);
	}

	if (inst->stats) {
		rad_assert(request->packet != NULL);
		vp = fr_pair_find_by_num(request->packet->vps, PW_CACHE_ENTRY_HITS, 0, TAG_ANY);
		if (!vp) {
			vp = fr_pair_afrom_num(request->packet, PW_CACHE_ENTRY_HITS, 0);
			rad_assert(vp != NULL);
			fr_pair_add(&request->packet->vps, vp);
		}
		vp->vp_integer = c->hits;
	}
}


/** Find a cached entry.
 *
 * @return RLM_MODULE_OK on success, RLM_MODULE_FAIL on failure, RLM_MODULE_NOTFOUND if notfound.
 */
static rlm_rcode_t cache_find(rlm_cache_entry_t **out, rlm_cache_t *inst, REQUEST *request,
			      rlm_cache_handle_t **handle, char const *key)
{
	cache_status_t ret;

	rlm_cache_entry_t *c;

	*out = NULL;

	for (;;) {
		ret = inst->module->find(&c, inst, request, handle, key);
		switch (ret) {
		case CACHE_RECONNECT:
			RDEBUG("Reconnecting...");
			if (cache_reconnect(inst, request, handle) == 0) continue;
			return RLM_MODULE_FAIL;

		case CACHE_OK:
			break;

		case CACHE_MISS:
			RDEBUG("No cache entry found for \"%s\"", key);
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
	if ((c->expires < request->timestamp) || (c->created < inst->epoch)) {
		RDEBUG("Removing expired entry");

		inst->module->expire(inst, request, handle, c);
		cache_free(inst, &c);
		return RLM_MODULE_NOTFOUND;	/* Couldn't find a non-expired entry */
	}

	RDEBUG("Found entry for \"%s\"", key);

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

	for (;;) switch (inst->module->expire(inst, request, handle, *c)) {
	case CACHE_RECONNECT:
		if (cache_reconnect(inst, request, handle) == 0) continue;

	/* FALL-THROUGH */
	default:
		cache_free(inst, c);
		*c = NULL;
		return;
	}
}

/** Create and insert a cache entry.
 *
 * @return RLM_MODULE_OK on success, RLM_MODULE_UPDATED if we merged the cache entry and RLM_MODULE_FAIL on failure.
 */
static rlm_rcode_t cache_insert(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle,
				char const *key, int ttl)
{
	VALUE_PAIR *vp, *to_cache;
	vp_cursor_t src_list, packet, reply, control, state;

	vp_map_t const *map;

	bool merge = true;
	rlm_cache_entry_t *c;

	if ((inst->max_entries > 0) && inst->module->count &&
	    (inst->module->count(inst, request, handle) > inst->max_entries)) {
		RWDEBUG("Cache is full: %d entries", inst->max_entries);
		return RLM_MODULE_FAIL;
	}

	c = cache_alloc(inst, request);
	if (!c) return RLM_MODULE_FAIL;

	c->key = talloc_typed_strdup(c, key);
	c->created = c->expires = request->timestamp;
	c->expires += ttl;

	RDEBUG("Creating new cache entry");

	fr_cursor_init(&packet, &c->packet);
	fr_cursor_init(&reply, &c->reply);
	fr_cursor_init(&control, &c->control);
	fr_cursor_init(&state, &c->state);

	for (map = inst->maps; map != NULL; map = map->next) {
		rad_assert(map->lhs && map->rhs);

		if (map_to_vp(c, &to_cache, request, map, NULL) < 0) {
			RDEBUG("Skipping %s", map->rhs->name);
			continue;
		}

		for (vp = fr_cursor_init(&src_list, &to_cache);
		     vp;
		     vp = fr_cursor_next(&src_list)) {
			VERIFY_VP(vp);

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

			vp->op = map->op;

			switch (map->lhs->tmpl_list) {
			case PAIR_LIST_REQUEST:
				fr_cursor_insert(&packet, vp);
				break;

			case PAIR_LIST_REPLY:
				fr_cursor_insert(&reply, vp);
				break;

			case PAIR_LIST_CONTROL:
				fr_cursor_insert(&control, vp);
				break;

			case PAIR_LIST_STATE:
				fr_cursor_insert(&state, vp);
				break;

			default:
				rad_assert(0);	/* should have been caught by validation */
			}
		}
	}

	/*
	 *	Check to see if we need to merge the entry into the request
	 */
	vp = fr_pair_find_by_num(request->config, PW_CACHE_MERGE, 0, TAG_ANY);
	if (vp && (vp->vp_integer == 0)) merge = false;

	if (merge) cache_merge(inst, request, c);

	for (;;) {
		cache_status_t ret;

		ret = inst->module->insert(inst, request, handle, c);
		switch (ret) {
		case CACHE_RECONNECT:
			if (cache_reconnect(inst, request, handle) == 0) continue;
			return RLM_MODULE_FAIL;

		case CACHE_OK:
			RDEBUG("Committed entry, TTL %d seconds", ttl);
			cache_free(inst, &c);
			return RLM_MODULE_UPDATED;

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

	switch (map->lhs->tmpl_list) {
	case PAIR_LIST_REQUEST:
	case PAIR_LIST_REPLY:
	case PAIR_LIST_CONTROL:
	case PAIR_LIST_STATE:
		break;

	default:
		cf_log_err(map->ci, "Destination list must be one of request, reply, control or session-state");
		return -1;
	}

	if (map->lhs->tmpl_request != REQUEST_CURRENT) {
		cf_log_err(map->ci, "Cached attributes can only be inserted into the current request");
		return -1;
	}

	switch (map->rhs->type) {
	case TMPL_TYPE_EXEC:
		cf_log_err(map->ci, "Exec values are not allowed");
		return -1;
	/*
	 *	Only =, :=, += and -= operators are supported for
	 *	cache entries.
	 */
	case TMPL_TYPE_LITERAL:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_ATTR:
		switch (map->op) {
		case T_OP_SET:
		case T_OP_EQ:
		case T_OP_SUB:
		case T_OP_ADD:
			break;

		default:
			cf_log_err(map->ci, "Operator \"%s\" not allowed for %s values",
				   fr_int2str(fr_tokens, map->op, "<INVALID>"),
				   fr_int2str(tmpl_names, map->rhs->type, "<INVALID>"));
			return -1;
		}
		break;

	case TMPL_TYPE_ATTR_UNDEFINED:
		cf_log_err(map->ci, "Unknown attribute '%s'", map->rhs->name);
		return -1;

	default:
		break;
	}

	return 0;
}

/*
 *	Do caching checks.  Since we can update ANY VP list, we do
 *	exactly the same thing for all sections (autz / auth / etc.)
 *
 *	If you want to cache something different in different sections,
 *	configure another cache module.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_cache_it(void *instance, REQUEST *request)
{
	rlm_cache_entry_t *c;
	rlm_cache_t *inst = instance;

	rlm_cache_handle_t *handle;

	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	char buffer[1024];
	rlm_rcode_t rcode;

	int ttl = inst->ttl;

	if (radius_xlat(buffer, sizeof(buffer), request, inst->key, NULL, NULL) < 0) return RLM_MODULE_FAIL;

	if (buffer[0] == '\0') {
		REDEBUG("Zero length key string is invalid");
		return RLM_MODULE_INVALID;
	}

	if (cache_acquire(&handle, inst, request) < 0) return RLM_MODULE_FAIL;

	rcode = cache_find(&c, inst, request, &handle, buffer);
	if (rcode == RLM_MODULE_FAIL) goto finish;
	rad_assert(handle);

	/*
	 *	If Cache-Status-Only == yes, only return whether we found a
	 *	valid cache entry
	 */
	vp = fr_pair_find_by_num(request->config, PW_CACHE_STATUS_ONLY, 0, TAG_ANY);
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
	vp = fr_pair_find_by_num(request->config, PW_CACHE_TTL, 0, TAG_ANY);
	if (vp) ttl = vp->vp_signed;

	/*
	 *	If there's no existing cache entry, go and create a new one.
	 */
	if (!c) {
		if (ttl == 0) {
			ttl = inst->ttl;

		} else if (ttl < 0) {
			ttl = -ttl;
		}
		goto insert;
	}

	/*
	 *	Expire the entry if requested to do so
	 */
	if (vp) {
		if (ttl == 0) {
			cache_expire(inst, request, &handle, &c);
			RDEBUG("Forcing expiry of entry");
			rcode = RLM_MODULE_OK;
			goto finish;
		}

		if (ttl < 0) {
			RDEBUG("Forcing expiry of existing entry");
			cache_expire(inst, request, &handle, &c);
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
	rcode = RLM_MODULE_OK;

	goto finish;

insert:
	/*
	 *	If Cache-Read-Only == yes, then we only allow already cached entries
	 *	to be merged into the request
	 */
	vp = fr_pair_find_by_num(request->config, PW_CACHE_READ_ONLY, 0, TAG_ANY);
	if (vp && vp->vp_integer) {
		rcode = RLM_MODULE_NOTFOUND;
		goto finish;
	}

	/*
	 *	Create a new entry.
	 */
	rcode = cache_insert(inst, request, &handle, buffer, ttl);
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

static ssize_t CC_HINT(nonnull) cache_xlat(void *instance, REQUEST *request,
					   char const *fmt, char *out, size_t freespace);

/*
 *	Allow single attribute values to be retrieved from the cache.
 */
static ssize_t cache_xlat(void *instance, REQUEST *request,
			  char const *fmt, char *out, size_t freespace)
{
	rlm_cache_entry_t 	*c = NULL;
	rlm_cache_t		*inst = instance;
	rlm_cache_handle_t	*handle = NULL;

	VALUE_PAIR		*vp, *vps;
	pair_lists_t		list;
	DICT_ATTR const		*target;
	char const		*p = fmt;
	size_t			len;
	int			ret = 0;

	p += radius_list_name(&list, p, PAIR_LIST_REQUEST);
	if (list == PAIR_LIST_UNKNOWN) {
		REDEBUG("Unknown list qualifier in \"%s\"", fmt);
		ret = -1;
		goto finish;
	}

	target = dict_attrbyname(p);
	if (!target) {
		REDEBUG("Unknown attribute \"%s\"", p);
		return -1;
	}

	if (cache_acquire(&handle, inst, request) < 0) return -1;

	switch (cache_find(&c, inst, request, &handle, fmt)) {
	case RLM_MODULE_OK:		/* found */
		break;

	case RLM_MODULE_NOTFOUND:	/* not found */
		*out = '\0';
		return 0;

	default:
		return -1;
	}

	switch (list) {
	case PAIR_LIST_REQUEST:
		vps = c->packet;
		break;

	case PAIR_LIST_REPLY:
		vps = c->reply;
		break;

	case PAIR_LIST_CONTROL:
		vps = c->control;
		break;

	case PAIR_LIST_STATE:
		vps = c->state;
		break;

	default:
		REDEBUG("Unsupported list \"%s\"", fr_int2str(pair_lists, list, "<UNKNOWN>"));
		ret = -1;
		goto finish;
	}

	vp = fr_pair_find_by_num(vps, target->attr, target->vendor, TAG_ANY);
	if (!vp) {
		RDEBUG("No instance of this attribute has been cached");
		*out = '\0';
		goto finish;
	}

	len = vp_prints_value(out, freespace, vp, 0);
	if (is_truncated(len, freespace)) {
		REDEBUG("Insufficient buffer space to write cached value");
		ret = -1;
		goto finish;
	}

finish:
	cache_free(inst, &c);
	cache_release(inst, request, &handle);

	return ret;
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
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


static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_cache_t *inst = instance;

	inst->cs = conf;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	/*
	 *	Register the cache xlat function
	 */
	xlat_register(inst->name, cache_xlat, NULL, inst);

	return 0;
}


/*
 *	Instantiate the module.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_cache_t *inst = instance;
	CONF_SECTION *update;

	inst->cs = conf;

	/*
	 *	Sanity check for crazy people.
	 */
	if (strncmp(inst->driver_name, "rlm_cache_", 10) != 0) {
		cf_log_err_cs(conf, "\"%s\" is NOT an Cache driver!", inst->driver_name);
		return -1;
	}

	/*
	 *	Load the appropriate driver for our database
	 */
	inst->handle = fr_dlopenext(inst->driver_name);
	if (!inst->handle) {
		cf_log_err_cs(conf, "Could not link driver %s: %s", inst->driver_name, dlerror());
		cf_log_err_cs(conf, "Make sure it (and all its dependent libraries!) are in the search path"
			      " of your system's ld");
		return -1;
	}

	inst->module = (cache_module_t *) dlsym(inst->handle, inst->driver_name);
	if (!inst->module) {
		cf_log_err_cs(conf, "Could not link symbol %s: %s", inst->driver_name, dlerror());
		return -1;
	}

	DEBUG("rlm_cache (%s): Driver %s (module %s) loaded and linked", inst->name,
	      inst->driver_name, inst->module->name);

	/*
	 *	Non optional fields and callbacks
	 */
	rad_assert(inst->module->name);
	rad_assert(inst->module->find);
	rad_assert(inst->module->insert);
	rad_assert(inst->module->expire);

	if (inst->module->instantiate) {
		CONF_SECTION *cs;
		char const *name;

		name = strrchr(inst->driver_name, '_');
		if (!name) {
			name = inst->driver_name;
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
		if (inst->module->instantiate(cs, inst) < 0) return -1;
	}

	rad_assert(inst->key && *inst->key);

	if (inst->ttl == 0) {
		cf_log_err_cs(conf, "Must set 'ttl' to non-zero");
		return -1;
	}

	if (inst->epoch != 0) {
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
		[MOD_AUTHENTICATE]     	= mod_cache_it,
		[MOD_PREACCT]		= mod_cache_it,
		[MOD_ACCOUNTING]	= mod_cache_it,
		[MOD_PRE_PROXY]		= mod_cache_it,
		[MOD_POST_PROXY]	= mod_cache_it,
		[MOD_POST_AUTH]		= mod_cache_it
	},
};
