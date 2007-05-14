/*
 * rlm_caching.c
 *
 * Version:  $Id$
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
 * Copyright 2001,2006  The FreeRADIUS server project
 * Copyright 2001  Alan DeKok <aland@ox.org>
 * Copyright 2001-3  Kostas Kalevras <kkalev@noc.ntua.gr>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <ctype.h>

#include "config.h"

#include <gdbm.h>
#include <time.h>

#ifdef NEEDS_GDBM_SYNC
#	define GDBM_SYNCOPT GDBM_SYNC
#else
#	define GDBM_SYNCOPT 0
#endif

#ifdef GDBM_NOLOCK
#define GDBM_COUNTER_OPTS (GDBM_SYNCOPT | GDBM_NOLOCK)
#else
#define GDBM_COUNTER_OPTS (GDBM_SYNCOPT)
#endif

#ifndef HAVE_GDBM_FDESC
#define gdbm_fdesc(foo) (-1)
#endif

#define UNIQUEID_MAX_LEN 32

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_caching_t {
	char *filename;		/* name of the database file */
	char *key;		/* An xlated string to use as key for the records */
	char *post_auth;	/* If set and we find a cached entry, set Post-Auth to this value */
	char *cache_ttl_str;	/* The string represantation of the TTL */
	int cache_ttl;		/* The cache TTL */
	int hit_ratio;		/* Show cache hit ratio every so many queries */
	int cache_rejects;	/* Do we also cache rejects? */
	int cache_size;		/* The cache size to pass to GDBM */
	uint32_t cache_queries;	/* The number of cache requests */
	uint32_t cache_hits;	/* The number of cache hits */
	GDBM_FILE gdbm;		/* The gdbm file handle */
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t mutex;	/* A mutex to lock the gdbm file for only one reader/writer */
#endif
} rlm_caching_t;

#define MAX_RECORD_LEN 750
#define MAX_AUTH_TYPE 32

#define show_hit_ratio \
	if (data->hit_ratio && (data->cache_queries % data->hit_ratio) == 0) \
		radlog(L_INFO, "rlm_caching: Cache Queries: %7d, Cache Hits: %7d, Hit Ratio: %.2f%%", \
			data->cache_queries,data->cache_hits,hit_ratio)

typedef struct rlm_caching_data {
	time_t creation;
	char data[MAX_RECORD_LEN];
	char auth_type[MAX_AUTH_TYPE];
	int len;
} rlm_caching_data;

#ifndef HAVE_PTHREAD_H
/*
 *	This is a lot simpler than putting ifdef's around
 *	every use of the pthread functions.
 */
#define pthread_mutex_lock(a)
#define pthread_mutex_unlock(a)
#define pthread_mutex_init(a,b)
#define pthread_mutex_destroy(a)
#endif

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
  { "filename", PW_TYPE_STRING_PTR, offsetof(rlm_caching_t,filename), NULL, NULL },
  { "key", PW_TYPE_STRING_PTR, offsetof(rlm_caching_t,key), NULL, "%{Acct-Unique-Session-Id}" },
  { "post-auth", PW_TYPE_STRING_PTR, offsetof(rlm_caching_t,post_auth), NULL,  NULL },
  { "cache-ttl", PW_TYPE_STRING_PTR, offsetof(rlm_caching_t,cache_ttl_str), NULL, "1d" },
  { "cache-size", PW_TYPE_INTEGER, offsetof(rlm_caching_t,cache_size), NULL, "1000" },
  { "hit-ratio", PW_TYPE_INTEGER, offsetof(rlm_caching_t,hit_ratio), NULL, "0" },
  { "cache-rejects", PW_TYPE_BOOLEAN, offsetof(rlm_caching_t,cache_rejects), NULL, "yes" },
  { NULL, -1, 0, NULL, NULL }
};

static int caching_detach(void *instance);

static int find_ttl(char *ttl)
{
	unsigned len = 0;
	char last = 's';

	if (isdigit((int) ttl[0])){
		len = strlen(ttl);
		if (len == 0)
			return -1;
		last = ttl[len - 1];
		if (!isalpha((int) last))
			last = 's';
		len = atoi(ttl);
		DEBUG("rlm_caching::find_ttl: num=%d, last=%c",len,last);
	}
	switch (last){
		case 's':
		default:
			break;
		case 'm':
			len *= 60;
			break;
		case 'h':
			len *= 3600;
			break;
		case 'd':
			len *= 86400;
			break;
		case 'w':
			len *= 604800;
			break;
	}

	DEBUG("rlm_caching::find_ttl: Returning '%d'",len);

	return len;
}

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 */
static int caching_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_caching_t *data;
	int cache_size;

	/*
	 *	Set up a storage area for instance data
	 */
	data = rad_malloc(sizeof(*data));
	if (!data) {
		radlog(L_ERR, "rlm_caching: rad_malloc() failed.");
		return -1;
	}
	memset(data, 0, sizeof(*data));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, data, module_config) < 0) {
		free(data);
		return -1;
	}
	cache_size = data->cache_size;

	/*
	 *	Discover the attribute number of the key.
	 */
	if (data->key == NULL) {
		radlog(L_ERR, "rlm_caching: 'key' must be set.");
		caching_detach(data);
		return -1;
	}
	if (data->cache_ttl_str == NULL) {
		radlog(L_ERR, "rlm_caching: 'cache-ttl' must be set.");
		caching_detach(data);
		return -1;
	}
	else {
		data->cache_ttl = find_ttl(data->cache_ttl_str);
		if (data->cache_ttl == 0) {
			radlog(L_ERR, "rlm_caching: 'cache-ttl' is invalid.");
			caching_detach(data);
			return -1;
		}
	}

	if (data->filename == NULL) {
		radlog(L_ERR, "rlm_caching: 'filename' must be set.");
		caching_detach(data);
		return -1;
	}
	data->gdbm = gdbm_open(data->filename, sizeof(int),
			GDBM_WRCREAT | GDBM_COUNTER_OPTS, 0600, NULL);
	if (data->gdbm == NULL) {
		radlog(L_ERR, "rlm_caching: Failed to open file %s: %s",
				data->filename, strerror(errno));
		caching_detach(data);
		return -1;
	}
	if (gdbm_setopt(data->gdbm, GDBM_CACHESIZE, &cache_size, sizeof(int)) == -1)
		radlog(L_ERR, "rlm_caching: Failed to set cache size");

	/*
	 * Init the mutex
	 */
	pthread_mutex_init(&data->mutex, NULL);

	*instance = data;

	return 0;
}

/*
 *	Cache the reply items and the Auth-Type
 */
static int caching_postauth(void *instance, REQUEST *request)
{
	rlm_caching_t *data = (rlm_caching_t *)instance;
	char key[MAX_STRING_LEN];
	datum key_datum;
	datum data_datum;
	VALUE_PAIR *reply_vp;
	VALUE_PAIR *auth_type;
	rlm_caching_data cache_data;
	int count = 0;
	int ret = 0;
	int size = 0;
	int rcode = 0;

	if (pairfind(request->packet->vps, PW_CACHE_NO_CACHING) != NULL){
		DEBUG("rlm_caching: Cache-No-Caching is set. Returning NOOP");
		return RLM_MODULE_NOOP;
	}
	if ((auth_type = pairfind(request->config_items, PW_AUTH_TYPE)) != NULL){
		DEBUG("rlm_caching: Found Auth-Type, value: '%s'",auth_type->vp_strvalue);
		if (strcmp(auth_type->vp_strvalue,"Reject") == 0 && data->cache_rejects == 0){
			DEBUG("rlm_caching: No caching of Rejects. Returning NOOP");
			return RLM_MODULE_NOOP;
		}
		if (strlen(auth_type->vp_strvalue) > MAX_AUTH_TYPE - 1){
			DEBUG("rlm_caching: Auth-Type value too large");
			return RLM_MODULE_NOOP;
		}
	}
	else{
		DEBUG("rlm_caching: No Auth-Type found. Returning NOOP");
		return RLM_MODULE_NOOP;
	}

	reply_vp = request->reply->vps;

	if (reply_vp == NULL) {
		DEBUG("rlm_caching: The Request does not contain any reply attributes");
		return RLM_MODULE_NOOP;
	}
	if (!radius_xlat(key,sizeof(key), data->key, request, NULL)){
		radlog(L_ERR, "rlm_caching: xlat on key '%s' failed.",data->key);
		return RLM_MODULE_FAIL;
	}

	memset(&cache_data,0,sizeof(rlm_caching_data));

	cache_data.creation = time(NULL);
	strcpy(cache_data.auth_type,auth_type->vp_strvalue);

	size = MAX_RECORD_LEN;

	while(reply_vp) {
		if (size <= 1){
			DEBUG("rlm_caching: Not enough space.");
			return RLM_MODULE_NOOP;
		}
		ret = vp_prints(cache_data.data + count,size,reply_vp);
		if (ret == 0) {
			DEBUG("rlm_caching: Record is too large, will not store it.");
			return RLM_MODULE_NOOP;
		}
		count += (ret + 1);
		size -= (ret + 1);
		DEBUG("rlm_caching: VP=%s,VALUE=%s,length=%d,cache record length=%d, space left=%d",
			reply_vp->name,reply_vp->vp_strvalue,ret,count,size);
		reply_vp = reply_vp->next;
	}
	cache_data.len = count;

	DEBUG("rlm_caching: Storing cache for Key='%s'",key);
	data_datum.dptr = (rlm_caching_data *) &cache_data;
	data_datum.dsize = sizeof(rlm_caching_data);

	key_datum.dptr = (char *) key;
	key_datum.dsize = strlen(key);

	pthread_mutex_lock(&data->mutex);
	rcode = gdbm_store(data->gdbm, key_datum, data_datum, GDBM_REPLACE);
	pthread_mutex_unlock(&data->mutex);
	if (rcode < 0) {
		radlog(L_ERR, "rlm_caching: Failed storing data to %s: %s",
				data->filename, gdbm_strerror(gdbm_errno));
		return RLM_MODULE_FAIL;
	}
	DEBUG("rlm_caching: New value stored successfully.");

	return RLM_MODULE_OK;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static int caching_authorize(void *instance, REQUEST *request)
{
	rlm_caching_t *data = (rlm_caching_t *) instance;
	char key[MAX_STRING_LEN];
	datum key_datum;
	datum data_datum;
	rlm_caching_data cache_data;
	VALUE_PAIR *reply_item;
	VALUE_PAIR *item;
	char *tmp;
	int len = 0;
	int delete_cache = 0;
	float hit_ratio = 0.0;

	/* quiet the compiler */
	instance = instance;
	request = request;

	if (pairfind(request->packet->vps, PW_CACHE_NO_CACHING) != NULL){
		DEBUG("rlm_caching: Cache-No-Caching is set. Returning NOOP");
		return RLM_MODULE_NOOP;
	}
	if (pairfind(request->packet->vps, PW_CACHE_DELETE_CACHE) != NULL){
		DEBUG("rlm_caching: Found Cache-Delete-Cache. Will delete record if found");
		delete_cache = 1;
	}

	if (!radius_xlat(key,sizeof(key), data->key, request, NULL)){
		radlog(L_ERR, "rlm_caching: xlat on key '%s' failed.",data->key);
		return RLM_MODULE_FAIL;
	}

	key_datum.dptr = key;
	key_datum.dsize = strlen(key);


	DEBUG("rlm_caching: Searching the database for key '%s'",key);
	pthread_mutex_lock(&data->mutex);
	data_datum = gdbm_fetch(data->gdbm, key_datum);
	pthread_mutex_unlock(&data->mutex);
	data->cache_queries++;
	if (data_datum.dptr != NULL){
		DEBUG("rlm_caching: Key Found.");
		data->cache_hits++;
		hit_ratio = (float)data->cache_hits / data->cache_queries;
		hit_ratio *= 100.0;
		memcpy(&cache_data, data_datum.dptr, sizeof(rlm_caching_data));
		free(data_datum.dptr);

		if (delete_cache == 0 && cache_data.creation + data->cache_ttl <= time(NULL)){
			DEBUG("rlm_caching: Cache entry has expired");
			DEBUG("rlm_caching: Cache Queries: %7d, Cache Hits: %7d, Hit Ratio: %.2f%%",
			data->cache_queries,data->cache_hits,hit_ratio);
			show_hit_ratio;
			delete_cache = 1;
		}
		if (delete_cache){
			DEBUG("rlm_caching: Deleting record");

			pthread_mutex_lock(&data->mutex);
			gdbm_delete(data->gdbm, key_datum);
			pthread_mutex_unlock(&data->mutex);

			return RLM_MODULE_NOOP;
		}
		tmp = cache_data.data;
		if (tmp){
			pairfree(&request->reply->vps);
			while(tmp && len < cache_data.len){
				reply_item = NULL;
				if (userparse(tmp, &reply_item) > 0 && reply_item != NULL)
					pairadd(&request->reply->vps, reply_item);
				len += (strlen(tmp) + 1);
				DEBUG("rlm_caching: VP='%s',VALUE='%s',lenth='%d',cache record length='%d'",
				reply_item->name,reply_item->vp_strvalue,reply_item->length,len);
				tmp = cache_data.data + len;
			}
		}
		else{
			DEBUG("rlm_caching: No reply items found. Returning NOOP");
			return RLM_MODULE_NOOP;
		}
		if (cache_data.auth_type){
			DEBUG("rlm_caching: Adding Auth-Type '%s'",cache_data.auth_type);

			if ((item = pairfind(request->config_items, PW_AUTH_TYPE)) == NULL){
				item = pairmake("Auth-Type", cache_data.auth_type, T_OP_SET);
				pairadd(&request->config_items, item);
			}
			else{
				strcmp(item->vp_strvalue, cache_data.auth_type);
				item->length = strlen(cache_data.auth_type);
			}
		}
		if (data->post_auth){
			DEBUG("rlm_caching: Adding Post-Auth-Type '%s'",data->post_auth);

			if ((item = pairfind(request->config_items, PW_POST_AUTH_TYPE)) == NULL){
				item = pairmake("Post-Auth-Type", data->post_auth, T_OP_SET);
				pairadd(&request->config_items, item);
			}
			else{
				strcmp(item->vp_strvalue, data->post_auth);
				item->length = strlen(data->post_auth);
			}
		}
		item = pairmake("Cache-No-Caching", "YES", T_OP_EQ);
		pairadd(&request->packet->vps, item);

		DEBUG("rlm_caching: Cache Queries: %7d, Cache Hits: %7d, Hit Ratio: %.2f%%",
			data->cache_queries,data->cache_hits,hit_ratio);
		show_hit_ratio;

		return RLM_MODULE_OK;
	}
	else{
		DEBUG("rlm_caching: Could not find the requested key in the database.");
		DEBUG("rlm_caching: Cache Queries: %7d, Cache Hits: %7d, Hit Ratio: %.2f%%",
			data->cache_queries,data->cache_hits,hit_ratio);
		show_hit_ratio;
	}

	return RLM_MODULE_NOOP;
}

static int caching_detach(void *instance)
{
	rlm_caching_t *data = (rlm_caching_t *) instance;

	if (data->gdbm)
		gdbm_close(data->gdbm);
	pthread_mutex_destroy(&data->mutex);

	free(instance);
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
module_t rlm_caching = {
	RLM_MODULE_INIT,
	"Caching",
	RLM_TYPE_THREAD_SAFE,		/* type */
	caching_instantiate,		/* instantiation */
	caching_detach,			/* detach */
	{
		NULL,			/* authentication */
		caching_authorize, 	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		caching_postauth	/* post-auth */
	},
};
