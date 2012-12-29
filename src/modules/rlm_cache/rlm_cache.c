/*
 * rlm_cache.c
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2012  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
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
	const char	*xlat_name;
	char		*key;
	int		ttl;
	int		epoch;
	int		stats;
	CONF_SECTION	*cs;
	rbtree_t	*cache;
	fr_heap_t	*heap;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t	cache_mutex;
#endif
} rlm_cache_t;

typedef struct rlm_cache_entry_t {
	const char	*key;
	int		offset;
	long long int	hits;
	time_t		created;
	time_t		expires;
	VALUE_PAIR	*control;
	VALUE_PAIR	*request;
	VALUE_PAIR	*reply;
} rlm_cache_entry_t;

#ifdef HAVE_PTHREAD_H
#define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock
#else
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)
#endif

/*
 *	Compare two entries by key.  There may only be one entry with
 *	the same key.
 */
static int cache_entry_cmp(const void *one, const void *two)
{
	const rlm_cache_entry_t *a = one;
	const rlm_cache_entry_t *b = two;

	return strcmp(a->key, b->key);
}

static void cache_entry_free(void *data)
{
	rlm_cache_entry_t *c = data;

	rad_cfree(c->key);
	pairfree(&c->control);
	pairfree(&c->request);
	pairfree(&c->reply);
	free(c);
}

/*
 *	Compare two entries by expiry time.  There may be multiple
 *	entries with the same expiry time.
 */
static int cache_heap_cmp(const void *one, const void *two)
{
	const rlm_cache_entry_t *a = one;
	const rlm_cache_entry_t *b = two;

	if (a->expires < b->expires) return -1;
	if (a->expires > b->expires) return +1;

	return 0;
}

/*
 *	Merge a cached entry into a REQUEST.
 */
static void cache_merge(rlm_cache_t *inst, REQUEST *request,
			rlm_cache_entry_t *c)
{
	VALUE_PAIR *vp;

	rad_assert(request != NULL);
	rad_assert(c != NULL);

	if (c->control) {
		vp = paircopy(c->control);
		pairmove(&request->config_items, &vp);
		pairfree(&vp);
	}

	if (c->request && request->packet) {
		vp = paircopy(c->request);
		pairmove(&request->packet->vps, &vp);
		pairfree(&vp);
	}

	if (c->reply && request->reply) {
		vp = paircopy(c->reply);
		pairmove(&request->reply->vps, &vp);
		pairfree(&vp);
	}
	
	if (inst->stats) {
		vp = paircreate(PW_CACHE_ENTRY_HITS, 0, PW_TYPE_INTEGER);
		rad_assert(vp != NULL);
		
		vp->vp_integer = c->hits;

		pairadd(&request->packet->vps, vp);
	}
}


/*
 *	Find a cached entry.
 */
static rlm_cache_entry_t *cache_find(rlm_cache_t *inst, REQUEST *request,
				     const char *key)
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
		DEBUG("rlm_cache: Entry has expired, removing");

		fr_heap_extract(inst->heap, c);
		rbtree_deletebydata(inst->cache, c);
		
		return NULL;
	}

	DEBUG("rlm_cache: Found entry for \"%s\"", key);

	/*
	 *	Update the expiry time based on the TTL.
	 *	A TTL of 0 means "delete from the cache".
	 */
	vp = pairfind(request->config_items, PW_CACHE_TTL, 0, TAG_ANY);
	if (vp) {
		if (vp->vp_integer == 0) goto delete;
		
		ttl = vp->vp_integer;
		c->expires = request->timestamp + ttl;
		DEBUG("rlm_cache: Adding %d to the TTL", ttl);
	}
	c->hits++;

	return c;
}


/*
 *	Add an entry to the cache.
 */
static rlm_cache_entry_t *cache_add(rlm_cache_t *inst, REQUEST *request,
				    const char *key)
{
	int ttl;
	const char *attr, *p;
	VALUE_PAIR *vp, **vps;
	CONF_ITEM *ci;
	CONF_PAIR *cp;
	rlm_cache_entry_t *c;
	char buffer[1024];

	/*
	 *	TTL of 0 means "don't cache this entry"
	 */
	vp = pairfind(request->config_items, PW_CACHE_TTL, 0, TAG_ANY);
	if (vp && (vp->vp_integer == 0)) return NULL;

	c = rad_malloc(sizeof(*c));
	memset(c, 0, sizeof(*c));

	c->key = strdup(key);
	c->created = c->expires = request->timestamp;

	/*
	 *	Use per-entry TTL, or globally defined one.
	 */
	if (vp) {
		ttl = vp->vp_integer;
	} else {
		ttl = inst->ttl;
	}
	c->expires += ttl;

	/*
	 *	Walk over the attributes to cache, dynamically
	 *	expanding them, and adding them to the correct list.
	 */
	for (ci = cf_item_find_next(inst->cs, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(inst->cs, ci)) {
		rad_assert(cf_item_is_pair(ci));

		cp = cf_itemtopair(ci);
		attr = p = cf_pair_attr(cp);
		
		switch (radius_list_name(&p, PAIR_LIST_REQUEST))
		{
			case PAIR_LIST_REQUEST:
				vps = &c->request;
				break;
				
			case PAIR_LIST_REPLY:
				vps = &c->reply;
				break;
				
			case PAIR_LIST_CONTROL:
				vps = &c->control;
				break;

			default:
				rad_assert(0); 
				return NULL;		
		}

		/*
		 *	Repeat much of cf_pairtovp here...
		 *	but we take list prefixes, and it doesn't.
		 *	I don't want to make that change for 2.0.
		 */
		radius_xlat(buffer, sizeof(buffer), cf_pair_value(cp),
			    request, NULL, NULL);

		vp = pairmake(p, buffer, cf_pair_operator(cp));
		pairadd(vps, vp);
	}

	if (!rbtree_insert(inst->cache, c)) {
		DEBUG("rlm_cache: FAILED adding entry for key %s", key);
		cache_entry_free(c);
		return NULL;
	}

	if (!fr_heap_insert(inst->heap, c)) {
		DEBUG("rlm_cache: FAILED adding entry for key %s", key);
		rbtree_deletebydata(inst->cache, c);
		return NULL;
	}

	DEBUG("rlm_cache: Adding entry for \"%s\", with TTL of %d",
	      key, ttl);

	return c;
}

/*
 *	Verify that the cache section makes sense.
 */
static int cache_verify(rlm_cache_t *inst)
{
	const char *attr, *p;
	pair_lists_t list;
	CONF_ITEM *ci;
	CONF_PAIR *cp;

	for (ci = cf_item_find_next(inst->cs, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(inst->cs, ci)) {
		if (!cf_item_is_pair(ci)) {
			cf_log_err(ci, "rlm_cache: Entry is not in \"attribute = value\" format");
			return 0;
		}

		cp = cf_itemtopair(ci);
		attr = p = cf_pair_attr(cp);
		
		list = radius_list_name(&p, PAIR_LIST_REQUEST);
		
		switch (list)
		{
			case PAIR_LIST_REQUEST:
			case PAIR_LIST_REPLY:
			case PAIR_LIST_CONTROL:
				break;
				
			case PAIR_LIST_UNKNOWN:
				cf_log_err(ci, "rlm_cache: Unknown list qualifier in \"%s\"", attr);
				return 0;
			default:
				cf_log_err(ci, "rlm_cache: Unsupported list \"%s\"", fr_int2str(pair_lists, list, "¿Unknown?"));
				return 0;
		}

		/*
		 *	FIXME: Can't do tags for now...
		 */
		if (!dict_attrbyname(p)) {
			cf_log_err(ci, "rlm_cache: Unknown attribute \"%s\"", p);
			return 0;
		}

		if (!cf_pair_value(cp)) {
			cf_log_err(ci, "rlm_cache: Attribute has no value");
			return 0;
		}
	}

	return 1;
}

/*
 *	Allow single attribute values to be retrieved from the cache.
 */
static size_t cache_xlat(void *instance, REQUEST *request,
			 const char *fmt, char *out, size_t freespace)
{
	rlm_cache_entry_t *c;
	rlm_cache_t *inst = instance;
	VALUE_PAIR *vp, *vps;
	pair_lists_t list;
	DICT_ATTR *target;
	const char *p = fmt;
	char buffer[1024];
	int ret = 0;

	radius_xlat(buffer, sizeof(buffer), inst->key, request, NULL, NULL);

	PTHREAD_MUTEX_LOCK(&inst->cache_mutex);
	c = cache_find(inst, request, buffer);
	
	if (!c) {
		RDEBUG("No cache entry for key \"%s\"", buffer);
		goto done;
	}
	
	list = radius_list_name(&p, PAIR_LIST_REQUEST);
	switch (list)
	{
		case PAIR_LIST_REQUEST:
			vps = c->request;
			break;
			
		case PAIR_LIST_REPLY:
			vps = c->reply;
			break;
			
		case PAIR_LIST_CONTROL:
			vps = c->control;
			break;
			
		case PAIR_LIST_UNKNOWN:
			radlog(L_ERR, "rlm_cache: Unknown list qualifier in \"%s\"", fmt);
			return 0;
			
		default:
			radlog(L_ERR, "rlm_cache: Unsupported list \"%s\"", fr_int2str(pair_lists, list, "¿Unknown?"));
			return 0;
	}
	
	target = dict_attrbyname(p);
	if (!target) {
		radlog(L_ERR, "rlm_cache: Unknown attribute \"%s\"", p);
		goto done;
	}
	
	vp = pairfind(vps, target->attr, target->vendor, TAG_ANY);
	if (!vp) {
		RDEBUG("No instance of this attribute has been cached");
		goto done;
	}
	
	ret = vp_prints_value(out, freespace, vp, 0);
done:
	PTHREAD_MUTEX_UNLOCK(&inst->cache_mutex);
	
	return ret;
}

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
	{ "key",  PW_TYPE_STRING_PTR,
	  offsetof(rlm_cache_t, key), NULL, NULL},
	{ "ttl", PW_TYPE_INTEGER,
	  offsetof(rlm_cache_t, ttl), NULL, "500" },
	{ "epoch", PW_TYPE_INTEGER,
	  offsetof(rlm_cache_t, epoch), NULL, "0" },
	{ "add-stats", PW_TYPE_BOOLEAN,
	  offsetof(rlm_cache_t, stats), NULL, "no" },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};


/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int cache_detach(void *instance)
{
	rlm_cache_t *inst = instance;

	free(inst->key);
	rad_cfree(inst->xlat_name);

	fr_heap_delete(inst->heap);
	rbtree_free(inst->cache);
#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy(&inst->cache_mutex);
#endif
	free(instance);
	return 0;
}


/*
 *	Instantiate the module.
 */
static int cache_instantiate(CONF_SECTION *conf, void **instance)
{
	const char *xlat_name;
	rlm_cache_t *inst;

	inst = rad_malloc(sizeof(*inst));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof(*inst));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	xlat_name = cf_section_name2(conf);
	if (xlat_name == NULL) {
		xlat_name = cf_section_name1(conf);
	}
	
	rad_assert(xlat_name);

	/*
	 *	Register the cache xlat function
	 */
	inst->xlat_name = strdup(xlat_name);
	xlat_register(xlat_name, cache_xlat, inst);

	if (!inst->key || !*inst->key) {
		radlog(L_ERR, "rlm_cache: You must specify a key");
		cache_detach(inst);
		return -1;
	}

	if (inst->ttl == 0) {
		radlog(L_ERR, "rlm_cache: TTL must be greater than zero");
		cache_detach(inst);
		return -1;
	}
	
	if (inst->epoch != 0){
		radlog(L_ERR, "rlm_cache: Epoch should only be set dynamically");
		cache_detach(inst);
		return -1;
	}

#ifdef HAVE_PTHREAD_H
	if (pthread_mutex_init(&inst->cache_mutex, NULL) < 0) {
		radlog(L_ERR, "rlm_cache: Failed initializing mutex: %s", strerror(errno));
		cache_detach(inst);
		return -1;
	}
#endif

	/*
	 *	The cache.
	 */
	inst->cache = rbtree_create(cache_entry_cmp, cache_entry_free, 0);
	if (!inst->cache) {
		radlog(L_ERR, "rlm_cache: Failed to create cache");
		cache_detach(inst);
		return -1;
	}

	/*
	 *	The heap of entries to expire.
	 */
	inst->heap = fr_heap_create(cache_heap_cmp,
				    offsetof(rlm_cache_entry_t, offset));
	if (!inst->heap) {
		radlog(L_ERR, "rlm_cache: Failed to create cache");
		cache_detach(inst);
		return -1;
	}
	

	inst->cs = cf_section_sub_find(conf, "update");
	if (!inst->cs) {
		radlog(L_ERR, "rlm_cache: Failed to find \"update\" subsection");
		cache_detach(inst);
		return -1;
	}

	/*
	 *	Make sure the users don't screw up too badly.
	 */
	if (!cache_verify(inst)) {
		cache_detach(inst);
		return -1;
	}

	*instance = inst;

	return 0;
}

/*
 *	Do caching checks.  Since we can update ANY VP list, we do
 *	exactly the same thing for all sections (autz / auth / etc.)
 *
 *	If you want to cache something different in different sections,
 *	configure another cache module.
 */
static int cache_it(void *instance, REQUEST *request)
{
	rlm_cache_entry_t *c;
	rlm_cache_t *inst = instance;
	VALUE_PAIR *vp;
	char buffer[1024];
	int rcode;

	radius_xlat(buffer, sizeof(buffer), inst->key, request, NULL, NULL);

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

	c = cache_add(inst, request, buffer);
	if (!c) {
		rcode = RLM_MODULE_NOOP;
		goto done;
	}

	cache_merge(inst, request, c);
	rcode = RLM_MODULE_UPDATED;
	
done:
	PTHREAD_MUTEX_UNLOCK(&inst->cache_mutex);
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
	cache_instantiate,		/* instantiation */
	cache_detach,			/* detach */
	{
		NULL,			/* authentication */
		cache_it,		/* authorization */
		cache_it,		/* preaccounting */
		cache_it,		/* accounting */
		NULL,			/* checksimul */
		cache_it,	      	/* pre-proxy */
		cache_it,	       	/* post-proxy */
		cache_it,		/* post-auth */
	},
};
