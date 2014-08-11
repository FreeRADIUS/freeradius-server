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
 * @file rlm_cache.c
 * @brief Cache values and merge them back into future requests.
 *
 * @copyright 2012-2013  The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/heap.h>
#include <freeradius-devel/rad_assert.h>

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_cache_t {
	char const		*xlat_name;
	char const		*key;
	uint32_t		ttl;
	uint32_t		max_entries;
	int32_t			epoch;
	bool			stats;
	CONF_SECTION		*cs;
	rbtree_t		*cache;
	fr_heap_t		*heap;

	value_pair_map_t	*maps;	//!< Attribute map applied to users
					//!< and profiles.
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t	cache_mutex;
#endif
} rlm_cache_t;

typedef struct rlm_cache_entry_t {
	char const	*key;
	int		offset;
	long long int	hits;
	time_t		created;
	time_t		expires;
	VALUE_PAIR	*control;
	VALUE_PAIR	*packet;
	VALUE_PAIR	*reply;
} rlm_cache_entry_t;

#ifdef HAVE_PTHREAD_H
#define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock
#else
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)
#endif

#define MAX_ATTRMAP	128

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
	{ "key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_cache_t, key), NULL },
	{ "ttl", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_cache_t, ttl), "500" },
	{ "max_entries", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_cache_t, max_entries), "16384" },

	/* Should be a type which matches time_t, @fixme before 2038 */
	{ "epoch", FR_CONF_OFFSET(PW_TYPE_SIGNED, rlm_cache_t, epoch), "0" },
	{ "add_stats", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_cache_t, stats), "no" },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};


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

static void cache_entry_free(void *data)
{
	rlm_cache_entry_t *c = data;

	pairfree(&c->control);
	pairfree(&c->packet);
	pairfree(&c->reply);

	talloc_free(c);
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

/*
 *	Merge a cached entry into a REQUEST.
 */
static void CC_HINT(nonnull) cache_merge(rlm_cache_t *inst, REQUEST *request, rlm_cache_entry_t *c)
{
	VALUE_PAIR *vp;

	vp = pairfind(request->config_items, PW_CACHE_MERGE, 0, TAG_ANY);
	if (vp && (vp->vp_integer == 0)) {
		RDEBUG2("Told not to merge entry into request");
		return;
	}

	if (c->control) {
		RDEBUG2("Merging cached control list:");
		rdebug_pair_list(2, request, c->control);

		pairadd(&request->config_items, paircopy(request, c->control));
	}

	if (c->packet && request->packet) {
		RDEBUG2("Merging cached request list:");
		rdebug_pair_list(2, request, c->packet);

		pairadd(&request->packet->vps,
			paircopy(request->packet, c->packet));
	}

	if (c->reply && request->reply) {
		RDEBUG2("Merging cached reply list:");
		rdebug_pair_list(2, request, c->reply);

		pairadd(&request->reply->vps,
			paircopy(request->reply, c->reply));
	}

	if (inst->stats) {
		vp = paircreate(request->packet, PW_CACHE_ENTRY_HITS, 0);
		rad_assert(vp != NULL);

		vp->vp_integer = c->hits;

		pairadd(&request->packet->vps, vp);
	}
}


/*
 *	Find a cached entry.
 */
static rlm_cache_entry_t *cache_find(rlm_cache_t *inst, REQUEST *request,
				     char const *key)
{
	int ttl;
	rlm_cache_entry_t *c, my_c;
	VALUE_PAIR *vp;

	/*
	 *	Look at the expiry heap.
	 */
	c = fr_heap_peek(inst->heap);
	if (!c) {
		rad_assert(rbtree_num_elements(inst->cache) == 0);
		return NULL;
	}

	/*
	 *	If it's time to expire an old entry, do so now.
	 */
	if (c->expires < request->timestamp) {
		fr_heap_extract(inst->heap, c);
		rbtree_deletebydata(inst->cache, c);
	}

	/*
	 *	Is there an entry for this key?
	 */
	my_c.key = key;
	c = rbtree_finddata(inst->cache, &my_c);
	if (!c) return NULL;

	/*
	 *	Yes, but it expired, OR the "forget all" epoch has
	 *	passed.  Delete it, and pretend it doesn't exist.
	 */
	if ((c->expires < request->timestamp) ||
	    (c->created < inst->epoch)) {
	delete:
		RDEBUG("Entry has expired, removing");

		fr_heap_extract(inst->heap, c);
		rbtree_deletebydata(inst->cache, c);

		return NULL;
	}

	RDEBUG("Found entry for \"%s\"", key);

	/*
	 *	Update the expiry time based on the TTL.
	 *	A TTL of 0 means "delete from the cache".
	 *	A TTL < 0 means "delete from the cache and recreate the entry".
	 */
	vp = pairfind(request->config_items, PW_CACHE_TTL, 0, TAG_ANY);
	if (vp) {
		if (vp->vp_signed <= 0) goto delete;

		ttl = vp->vp_signed;
		c->expires = request->timestamp + ttl;
		RDEBUG("Adding %d to the TTL", ttl);
	}
	c->hits++;

	return c;
}


/** Callback for map_to_request
 *
 * Simplifies merging VALUE_PAIRs into the current request.
 */
static int _cache_add(VALUE_PAIR **out, REQUEST *request, UNUSED value_pair_map_t const *map, void *ctx)
{
	VALUE_PAIR *vp;

	vp = talloc_get_type_abort(ctx, VALUE_PAIR);
	/* map_to_request will reparent */
	*out = paircopy(request, vp);

	if (!*out) return -1;
	return 0;
}

/*
 *	Add an entry to the cache.
 */
static rlm_cache_entry_t *cache_add(rlm_cache_t *inst, REQUEST *request, char const *key)
{
	int ttl;
	VALUE_PAIR *vp, *to_cache;
	vp_cursor_t src_list, cached_request, cached_reply, cached_control;

	bool merge = true;

	value_pair_map_t const *map;

	rlm_cache_entry_t *c;

	if (rbtree_num_elements(inst->cache) >= inst->max_entries) {
		RDEBUG("Cache is full: %d entries", inst->max_entries);
		return NULL;
	}

	/*
	 *	TTL of 0 means "don't cache this entry"
	 */
	vp = pairfind(request->config_items, PW_CACHE_TTL, 0, TAG_ANY);
	if (vp && (vp->vp_signed == 0)) return NULL;

	c = talloc_zero(NULL, rlm_cache_entry_t);
	c->key = talloc_typed_strdup(c, key);
	c->created = c->expires = request->timestamp;

	/*
	 *	Use per-entry TTL if > 0, or globally defined one.
	 */
	ttl = vp && (vp->vp_signed > 0) ? vp->vp_integer : inst->ttl;
	c->expires += ttl;

	RDEBUG("Creating entry for \"%s\"", key);

	/*
	 *	Check to see if we need to merge the entry into the request
	 */
	vp = pairfind(request->config_items, PW_CACHE_MERGE, 0, TAG_ANY);
	if (vp && (vp->vp_integer == 0)) {
		merge = false;
		RDEBUG2("Told not to merge new entry into request");
	}

	fr_cursor_init(&cached_request, &c->packet);
	fr_cursor_init(&cached_reply, &c->reply);
	fr_cursor_init(&cached_control, &c->control);

	for (map = inst->maps; map != NULL; map = map->next) {
		bool do_merge = merge;

		rad_assert(map->dst && map->src);

		if (map_to_vp(&to_cache, request, map, NULL) < 0) {
			RDEBUG("Skipping %s", map->src->name);
			continue;
		}

		/*
		 *	Merge attributes into the current request if:
		 *	  - Map specifies an xlat'd string.
		 *	  - Map specifies a literal string.
		 *	  - Map specifies an exec.
		 *	  - Map src and dst lists differ.
		 *	  - Map src and dst attributes differ
		 *
		 *	 Unless Cache-Merge = no
		 */
		if (do_merge) switch (map->src->type) {
		case TMPL_TYPE_LITERAL:
		case TMPL_TYPE_XLAT:
		case TMPL_TYPE_EXEC:
			break;

		case TMPL_TYPE_LIST:
			if (map->src->tmpl_list == map->dst->tmpl_list) do_merge = false;
			break;

		case TMPL_TYPE_ATTR:
			if (map->src->tmpl_da == map->dst->tmpl_da) do_merge = false;
			break;

		default:
			do_merge = false;
		}

		/*
		 *	Reparent the VPs map_to_vp may return multiple.
		 */
		for (vp = fr_cursor_init(&src_list, &to_cache);
		     vp;
		     vp = fr_cursor_next(&src_list)) {
			VERIFY_VP(vp);

			/*
			 *	Prevent people from accidentally caching
			 *	cache control attributes.
			 */
			if (map->src->type == TMPL_TYPE_LIST) switch (vp->da->attr) {
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

			if (debug_flag) map_debug_log(request, map, vp);
			(void) talloc_steal(c, vp);

			vp->op = map->op;

			switch (map->dst->tmpl_list) {
			case PAIR_LIST_REQUEST:
				fr_cursor_insert(&cached_request, vp);
				break;

			case PAIR_LIST_REPLY:
				fr_cursor_insert(&cached_reply, vp);
				break;

			case PAIR_LIST_CONTROL:
				fr_cursor_insert(&cached_control, vp);
				break;

			default:
				rad_assert(0);	/* should have been caught by validation */
			}

			if (do_merge && map_dst_valid(request, map)) {
				/* There's no reason for this to fail (we checked the dst was valid) */
				RDEBUG2("Adding to request:");
				if (map_to_request(request, map, _cache_add, vp) < 0) rad_assert(0);
			}
		}
	}

	if (!rbtree_insert(inst->cache, c)) {
		REDEBUG("FAILED adding entry for key %s", key);
		cache_entry_free(c);
		return NULL;
	}

	if (!fr_heap_insert(inst->heap, c)) {
		REDEBUG("FAILED adding entry for key %s", key);
		rbtree_deletebydata(inst->cache, c);
		return NULL;
	}

	RDEBUG("Inserted entry, TTL %d seconds", ttl);

	return c;
}

/*
 *	Verify that the cache section makes sense.
 */
static int cache_verify(rlm_cache_t *inst, value_pair_map_t **head)
{
	value_pair_map_t *map;

	if (map_from_cs(cf_section_sub_find(inst->cs, "update"),
			   head, PAIR_LIST_REQUEST,
			   PAIR_LIST_REQUEST, MAX_ATTRMAP) < 0) {
		return -1;
	}

	if (!*head) {
		cf_log_err_cs(inst->cs,
			   "Cache config must contain an update section, and "
			   "that section must not be empty");

		return -1;
	}

	for (map = *head; map != NULL; map = map->next) {
		if ((map->dst->type != TMPL_TYPE_ATTR) &&
		    (map->dst->type != TMPL_TYPE_LIST)) {
			cf_log_err(map->ci, "Left operand must be an attribute "
				   "ref or a list");

			return -1;
		}

		/*
		 *	Can't copy an xlat expansion or literal into a list,
		 *	we don't know what type of attribute we'd need
		 *	to create.
		 *
		 *	The only exception is where were using a unary
		 *	operator like !*.
		 */
		if ((map->dst->type == TMPL_TYPE_LIST) &&
		    (map->op != T_OP_CMP_FALSE) &&
		    ((map->src->type == TMPL_TYPE_XLAT) || (map->src->type == TMPL_TYPE_LITERAL))) {
			cf_log_err(map->ci, "Can't copy value into list (we don't know which attribute to create)");

			return -1;
		}

		switch (map->src->type) {
		case TMPL_TYPE_EXEC:
			cf_log_err(map->ci, "Exec values are not allowed");

			return -1;

		/*
		 *	Only =, :=, += and -= operators are supported for
		 *	cache entries.
		 */
		case TMPL_TYPE_LITERAL:
			/*
			 *	@fixme: This should be moved into a common function
			 *	with the check in do_compile_modupdate.
			 */
			if (map->dst->type == TMPL_TYPE_ATTR) {
				VALUE_PAIR *vp;
				int ret;

				MEM(vp = pairalloc(map->dst, map->dst->tmpl_da));
				vp->op = map->op;

				ret = pairparsevalue(vp, map->src->name, 0);
				talloc_free(vp);
				if (ret < 0) {
					cf_log_err(map->ci, "%s", fr_strerror());
					return -1;
				}
			}
			/* FALL-THROUGH */

		case TMPL_TYPE_XLAT:
		case TMPL_TYPE_ATTR:
			switch (map->op) {
			case T_OP_SET:
			case T_OP_EQ:
			case T_OP_SUB:
			case T_OP_ADD:
				break;

			default:
				cf_log_err(map->ci, "Operator \"%s\" not "
					   "allowed for %s values",
					   fr_int2str(fr_tokens, map->op,
						      "<INVALID>"),
					   fr_int2str(vpt_types, map->src->type,
						      "<INVALID>"));
				return -1;
			}
		default:
			break;
		}
	}
	return 0;
}

/*
 *	Allow single attribute values to be retrieved from the cache.
 */
static ssize_t cache_xlat(void *instance, REQUEST *request,
			  char const *fmt, char *out, size_t freespace)
{
	rlm_cache_entry_t 	*c;
	rlm_cache_t		*inst = instance;
	VALUE_PAIR		*vp, *vps;
	pair_lists_t		list;
	DICT_ATTR const		*target;
	char const		*p = fmt;
	size_t			len;
	int			ret = 0;

	list = radius_list_name(&p, PAIR_LIST_REQUEST);

	target = dict_attrbyname(p);
	if (!target) {
		REDEBUG("Unknown attribute \"%s\"", p);
		return -1;
	}

	PTHREAD_MUTEX_LOCK(&inst->cache_mutex);
	c = cache_find(inst, request, fmt);

	if (!c) {
		RDEBUG("No cache entry for key \"%s\"", fmt);
		*out = '\0';
		goto done;
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

	case PAIR_LIST_UNKNOWN:
		PTHREAD_MUTEX_UNLOCK(&inst->cache_mutex);
		REDEBUG("Unknown list qualifier in \"%s\"", fmt);
		return -1;

	default:
		PTHREAD_MUTEX_UNLOCK(&inst->cache_mutex);
		REDEBUG("Unsupported list \"%s\"",
			fr_int2str(pair_lists, list, "<UNKNOWN>"));
		return -1;
	}

	vp = pairfind(vps, target->attr, target->vendor, TAG_ANY);
	if (!vp) {
		RDEBUG("No instance of this attribute has been cached");
		*out = '\0';
		goto done;
	}

	len = vp_prints_value(out, freespace, vp, 0);
	if (is_truncated(len, freespace)) {
		PTHREAD_MUTEX_UNLOCK(&inst->cache_mutex);
		REDEBUG("Insufficient buffer space to write cached value");
		return -1;
	}
done:
	PTHREAD_MUTEX_UNLOCK(&inst->cache_mutex);

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

	fr_heap_delete(inst->heap);
	rbtree_free(inst->cache);

#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy(&inst->cache_mutex);
#endif
	return 0;
}


/*
 *	Instantiate the module.
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_cache_t *inst = instance;

	inst->cs = conf;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}

	/*
	 *	Register the cache xlat function
	 */
	xlat_register(inst->xlat_name, cache_xlat, NULL, inst);

	rad_assert(inst->key && *inst->key);

	if (inst->ttl == 0) {
		cf_log_err_cs(conf, "Must set 'ttl' to non-zero");
		return -1;
	}

	if (inst->epoch != 0) {
		cf_log_err_cs(conf, "Must not set 'epoch' in the configuration files");
		return -1;
	}

#ifdef HAVE_PTHREAD_H
	if (pthread_mutex_init(&inst->cache_mutex, NULL) < 0) {
		ERROR("Failed initializing mutex: %s",
		       fr_syserror(errno));
		return -1;
	}
#endif

	/*
	 *	The cache.
	 */

	inst->cache = rbtree_create(NULL, cache_entry_cmp, cache_entry_free, 0);
	if (!inst->cache) {
		ERROR("Failed to create cache");
		return -1;
	}
	fr_link_talloc_ctx_free(inst, inst->cache);

	/*
	 *	The heap of entries to expire.
	 */
	inst->heap = fr_heap_create(cache_heap_cmp,
				    offsetof(rlm_cache_entry_t, offset));
	if (!inst->heap) {
		ERROR("Failed to create heap for the cache");
		return -1;
	}

	/*
	 *	Make sure the users don't screw up too badly.
	 */
	if (cache_verify(inst, &inst->maps) < 0) {
		return -1;
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
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	char buffer[1024];
	rlm_rcode_t rcode;

	if (radius_xlat(buffer, sizeof(buffer), request, inst->key, NULL, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	PTHREAD_MUTEX_LOCK(&inst->cache_mutex);
	c = cache_find(inst, request, buffer);

	/*
	 *	If yes, only return whether we found a valid cache entry
	 */
	vp = pairfind(request->config_items, PW_CACHE_STATUS_ONLY, 0, TAG_ANY);
	if (vp && vp->vp_integer) {
		rcode = c ? RLM_MODULE_OK:
			    RLM_MODULE_NOTFOUND;
		goto done;
	}

	if (c) {
		cache_merge(inst, request, c);

		rcode = RLM_MODULE_OK;
		goto done;
	}

	vp = pairfind(request->config_items, PW_CACHE_READ_ONLY, 0, TAG_ANY);
	if (vp && vp->vp_integer) {
		rcode = RLM_MODULE_NOTFOUND;
		goto done;
	}

	c = cache_add(inst, request, buffer);
	if (!c) {
		rcode = RLM_MODULE_NOOP;
		goto done;
	}

	rcode = RLM_MODULE_UPDATED;

done:
	PTHREAD_MUTEX_UNLOCK(&inst->cache_mutex);

	/*
	 *	Reset control attributes
	 */
	for (vp = fr_cursor_init(&cursor, &request->config_items);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
		if (vp->da->vendor == 0) switch (vp->da->attr) {
		case PW_CACHE_TTL:
		case PW_CACHE_READ_ONLY:
		case PW_CACHE_MERGE:
			vp = fr_cursor_remove(&cursor);
			talloc_free(vp);
			break;
		}
	}

	return rcode;
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
	RLM_MODULE_INIT,
	"cache",
	0,				/* type */
	sizeof(rlm_cache_t),
	module_config,
	mod_instantiate,		/* instantiation */
	mod_detach,			/* detach */
	{
		NULL,			/* authentication */
		mod_cache_it,		/* authorization */
		mod_cache_it,		/* preaccounting */
		mod_cache_it,		/* accounting */
		NULL,			/* checksimul */
		mod_cache_it,	      	/* pre-proxy */
		mod_cache_it,	       	/* post-proxy */
		mod_cache_it,		/* post-auth */
	},
};
