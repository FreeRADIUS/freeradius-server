/*
 * rlm_counter.c
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001  The FreeRADIUS server project
 * Copyright 2001  Alan DeKok <aland@ox.org>
 * Copyright 2001  Kostas Kalevras <kkalev@noc.ntua.gr>
 */

#include "config.h"
#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"

#include <gdbm.h>
#include <time.h>

#ifdef NEEDS_GDBM_SYNC
#	define GDBM_SYNCOPT GDBM_SYNC
#else
#	define GDBM_SYNCOPT 0
#endif


static const char rcsid[] = "$Id$";

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_counter_t {
	char *filename;  /* name of the database file */
	char *reset;  /* daily, weekly, monthly, never */
	char *key_name;  /* User-Name */
	char *count_attribute;  /* Acct-Session-Time */
	char *counter_name;  /* Daily-Session-Time */
	char *check_name;  /* Daily-Max-Session */
	char *service_type;  /* Service-Type to search for */
	int cache_size;
	int service_val;
	int key_attr;
	int count_attr;
	time_t reset_time;
	time_t last_reset;
	int dict_attr;  /* attribute number for the counter. */
	GDBM_FILE gdbm;
} rlm_counter_t;

/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static CONF_PARSER module_config[] = {
  { "filename", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,filename), NULL, NULL },
  { "key", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,key_name), NULL, NULL },
  { "reset", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,reset), NULL,  NULL },
  { "count-attribute", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,count_attribute), NULL, NULL },
  { "counter-name", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,counter_name), NULL,  NULL },
  { "check-name", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,check_name), NULL, NULL },
  { "allowed-servicetype", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,service_type),NULL, NULL },
  { "cache-size", PW_TYPE_INTEGER, offsetof(rlm_counter_t,cache_size), NULL, "1000" },
  { NULL, -1, 0, NULL, NULL }
};


/*
 *	See if the counter matches.
 */
static int counter_cmp(void *instance, REQUEST *req, VALUE_PAIR *request, VALUE_PAIR *check,
		VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	rlm_counter_t *data = (rlm_counter_t *) instance;
	datum key_datum;
	datum count_datum;
	VALUE_PAIR *key_vp;
	int counter;

	check_pairs = check_pairs; /* shut the compiler up */
	reply_pairs = reply_pairs;

	/*
	 *	Find the key attribute.
	 */
	key_vp = pairfind(request, data->key_attr);
	if (key_vp == NULL) {
		return RLM_MODULE_NOOP;
	}

	key_datum.dptr = key_vp->strvalue;
	key_datum.dsize = key_vp->length;

	count_datum = gdbm_fetch(data->gdbm, key_datum);
	if (count_datum.dptr == NULL) {
		return -1;
	}
	memcpy(&counter, count_datum.dptr, sizeof(int));
	free(count_datum.dptr);

	return counter - check->lvalue;
}


static int find_next_reset(rlm_counter_t *data, time_t timeval)
{
	int ret=0;
	struct tm *tm=NULL;

	tm = localtime(&timeval);
	tm->tm_sec = tm->tm_min = 0;

	if (strcmp(data->reset, "hourly") == 0) {
		/*
		 *  Round up to the next nearest hour.
		 */
		tm->tm_hour++;
		data->reset_time = mktime(tm);
	} else if (strcmp(data->reset, "daily") == 0) {
		/*
		 *  Round up to the next nearest day.
		 */
		tm->tm_hour = 0;
		tm->tm_mday++;
		data->reset_time = mktime(tm);
	} else if (strcmp(data->reset, "weekly") == 0) {
		/*
		 *  Round up to the next nearest week.
		 */
		tm->tm_hour = 0;
		tm->tm_mday += (7 - tm->tm_wday);
		data->reset_time = mktime(tm);
	} else if (strcmp(data->reset, "monthly") == 0) {
		tm->tm_hour = 0;
		tm->tm_mday = 1;
		tm->tm_mon++;
		data->reset_time = mktime(tm);
	} else if (strcmp(data->reset, "never") == 0) {
		data->reset_time = 0;
	} else {
		radlog(L_ERR, "rlm_counter: Unknown reset timer \"%s\"",
				data->reset);
		ret=-1;
	}

	return ret;
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
static int counter_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_counter_t *data;
	DICT_ATTR *dattr;
	DICT_VALUE *dval;
	ATTR_FLAGS flags;
	time_t now;
	int cache_size;
	
	/*
	 *	Set up a storage area for instance data
	 */
	data = rad_malloc(sizeof(*data));

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
	if (data->key_name == NULL) {
		radlog(L_ERR, "rlm_counter: 'key' must be set.");
		exit(0);
	}
	dattr = dict_attrbyname(data->key_name);
	if (dattr == NULL) {
		radlog(L_ERR, "rlm_counter: No such attribute %s",
				data->key_name);
		return -1;
	}
	data->key_attr = dattr->attr;
	
	/*
	 *	Discover the attribute number of the counter. 
	 */
	if (data->count_attribute == NULL) {
		radlog(L_ERR, "rlm_counter: 'count-attribute' must be set.");
		exit(0);
	}
	dattr = dict_attrbyname(data->count_attribute);
	if (dattr == NULL) {
		radlog(L_ERR, "rlm_counter: No such attribute %s",
				data->count_attribute);
		return -1;
	}
	data->count_attr = dattr->attr;

	/*
	 *  Create a new attribute for the counter.
	 */
	if (data->counter_name == NULL) {
		radlog(L_ERR, "rlm_counter: 'counter-name' must be set.");
		exit(0);
	}

	memset(&flags, 0, sizeof(flags));
	dict_addattr(data->counter_name, 0, PW_TYPE_INTEGER, -1, flags);
	dattr = dict_attrbyname(data->counter_name);
	if (dattr == NULL) {
		radlog(L_ERR, "rlm_counter: Failed to create counter attribute %s",
				data->counter_name);
		return -1;
	}
	data->dict_attr = dattr->attr;
	DEBUG2("rlm_counter: Counter attribute %s is number %d",
			data->counter_name, data->dict_attr);

	/*
	 * Create a new attribute for the check item.
	 */
	if (data->check_name == NULL) {
		radlog(L_ERR, "rlm_counter: 'check-name' must be set.");
		exit(0);
	}
	dict_addattr(data->check_name, 0, PW_TYPE_INTEGER, -1, flags);
	dattr = dict_attrbyname(data->check_name);
	if (dattr == NULL) {
		radlog(L_ERR, "rlm_counter: Failed to create check attribute %s",
				data->counter_name);
		return -1;
	}

	/*
	 * Find the attribute for the allowed protocol
	 */
	if (data->service_type != NULL) {
		if ((dval = dict_valbyname(PW_SERVICE_TYPE, data->service_type)) == NULL) {
			radlog(L_ERR, "rlm_counter: Failed to find attribute number for %s",
					data->service_type);
			return -1;
		}
		data->service_val = dval->value;
	}	

	/*
	 *  Discover when next to reset the database.
	 */
	if (data->reset == NULL) {
		radlog(L_ERR, "rlm_counter: 'reset' must be set.");
		exit(0);
	}
	now = time(NULL);
	data->reset_time = 0;

	if (find_next_reset(data,now) == -1)
		return -1;
	DEBUG2("rlm_counter: Next reset %d", (int)data->reset_time);

	if (data->filename == NULL) {
		radlog(L_ERR, "rlm_counter: 'filename' must be set.");
		exit(0);
	}
	data->gdbm = gdbm_open(data->filename, sizeof(int),
			GDBM_WRCREAT | GDBM_SYNCOPT, 0600, NULL);
	if (data->gdbm == NULL) {
		radlog(L_ERR, "rlm_counter: Failed to open file %s: %s",
				data->filename, strerror(errno));
		return -1;
	}
	if (gdbm_setopt(data->gdbm, GDBM_CACHESIZE, &cache_size, sizeof(int)) == -1)
		radlog(L_ERR, "rlm_counter: Failed to set cache size");


	/*
	 *	Register the counter comparison operation.
	 */
	paircompare_register(data->dict_attr, 0, counter_cmp, data);

	*instance = data;
	
	return 0;
}

/*
 *	Write accounting information to this modules database.
 */
static int counter_accounting(void *instance, REQUEST *request)
{
	rlm_counter_t *data = (rlm_counter_t *)instance;
	datum key_datum;
	datum count_datum;
	VALUE_PAIR *key_vp, *count_vp, *proto_vp;
	int counter;
	int rcode;
	time_t diff;

	/*
	 *	Before doing anything else, see if we have to reset
	 *	the counters.
	 */
	if (data->reset_time && (data->reset_time <= request->timestamp)) {
		int cache_size = data->cache_size;

		gdbm_close(data->gdbm);

		/*
		 *	Re-set the next time to clean the database.
		 */
		data->last_reset = data->reset_time;
		find_next_reset(data,request->timestamp);

		/*
		 *	Open a completely new database.
		 */
		data->gdbm = gdbm_open(data->filename, sizeof(int),
				GDBM_NEWDB | GDBM_SYNCOPT, 0600, NULL);
		if (data->gdbm == NULL) {
			radlog(L_ERR, "rlm_counter: Failed to open file %s: %s",
					data->filename, strerror(errno));
			return RLM_MODULE_FAIL;
		}
		if (gdbm_setopt(data->gdbm, GDBM_CACHESIZE, &cache_size, sizeof(int)) == -1)
			radlog(L_ERR, "rlm_counter: Failed to set cache size");
	}
	/*
	 * Check if we need to watch out for a specific service-type. If yes then check it
	 */
	if (data->service_type != NULL) {
		if ((proto_vp = pairfind(request->packet->vps, PW_SERVICE_TYPE)) == NULL)
			return RLM_MODULE_NOOP;
		if (proto_vp->lvalue != data->service_val)
			return RLM_MODULE_NOOP;

	}	
	

	/*
	 *	Look for the key.  User-Name is special.  It means
	 *	The REAL username, after stripping.
	 */
	key_vp = (data->key_attr == PW_USER_NAME) ? request->username : pairfind(request->packet->vps, data->key_attr);
	if (key_vp == NULL)
		return RLM_MODULE_NOOP;

	/*
	 *	Look for the attribute to use as a counter.
	 */
	count_vp = pairfind(request->packet->vps, data->count_attr);
	if (count_vp == NULL)
		return RLM_MODULE_NOOP;

	key_datum.dptr = key_vp->strvalue;
	key_datum.dsize = key_vp->length;

	count_datum = gdbm_fetch(data->gdbm, key_datum);
	if (count_datum.dptr == NULL)
		counter = 0;
	else{
		memcpy(&counter, count_datum.dptr, sizeof(int));
		free(count_datum.dptr);
	}

	/*
	 * if session time < diff then the user got in after the last reset. So add his session time
	 * else add the diff.
	 * That way if he logged in at 23:00 and we reset the daily counter at 24:00 and he logged out
	 * at 01:00 then we will only count one hour (the one in the new day). That is the right thing
	 */

	diff = request->timestamp - data->last_reset;
	counter += (count_vp->lvalue < diff) ? count_vp->lvalue : diff;
	count_datum.dptr = (char *) &counter;
	count_datum.dsize = sizeof(int);

	rcode = gdbm_store(data->gdbm, key_datum, count_datum, GDBM_REPLACE);
	if (rcode < 0) {
		radlog(L_ERR, "rlm_counter: Failed storing data to %s: %s",
				data->filename, gdbm_strerror(gdbm_errno));
		return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static int counter_authorize(void *instance, REQUEST *request)
{
	rlm_counter_t *data = (rlm_counter_t *) instance;
	int ret=RLM_MODULE_NOOP;
	datum key_datum;
	datum count_datum;
	int counter=0;
	int res=0;
	DICT_ATTR *dattr;
	VALUE_PAIR *key_vp, *check_vp;
	VALUE_PAIR *reply_item;
	char msg[128];

	/* quiet the compiler */
	instance = instance;
	request = request;

	/*
	 *	Before doing anything else, see if we have to reset
	 *	the counters.
	 */
	if (data->reset_time && (data->reset_time <= request->timestamp)) {
		int cache_size = data->cache_size;

		gdbm_close(data->gdbm);

		/*
		 *	Re-set the next time to clean the database.
		 */
		data->last_reset = data->reset_time;
		find_next_reset(data,request->timestamp);

		/*
		 *	Open a completely new database.
		 */
		data->gdbm = gdbm_open(data->filename, sizeof(int),
				GDBM_NEWDB | GDBM_SYNCOPT, 0600, NULL);
		if (data->gdbm == NULL) {
			radlog(L_ERR, "rlm_counter: Failed to open file %s: %s",
					data->filename, strerror(errno));
			return RLM_MODULE_FAIL;
		}
		if (gdbm_setopt(data->gdbm, GDBM_CACHESIZE, &cache_size, sizeof(int)) == -1)
			radlog(L_ERR, "rlm_counter: Failed to set cache size");
	}


	/*
	*      Look for the key.  User-Name is special.  It means
	*      The REAL username, after stripping.
	*/
	DEBUG2("rlm_counter: Entering module authorize code");
	key_vp = (data->key_attr == PW_USER_NAME) ? request->username : pairfind(request->packet->vps, data->key_attr);
	if (key_vp == NULL) {
		DEBUG2("rlm_counter: Could not find Key value pair");
		return ret;
	}

	/*
	*      Look for the check item
	*/
	
	if ((dattr = dict_attrbyname(data->check_name)) == NULL)
		return ret;
	if ((check_vp= pairfind(request->config_items, dattr->attr)) == NULL) {
		DEBUG2("rlm_counter: Could not find Check item value pair");
		return ret;
	}

	key_datum.dptr = key_vp->strvalue;
	key_datum.dsize = key_vp->length;
	
	count_datum = gdbm_fetch(data->gdbm, key_datum);
	if (count_datum.dptr != NULL){
		memcpy(&counter, count_datum.dptr, sizeof(int));
		free(count_datum.dptr);
	}
		

	/*
	 * Check if check item > counter
	 */
	res=check_vp->lvalue - counter;
	if (res > 0) {
		/*
		 * We are assuming that simultaneous-use=1. But even if that does
		 * not happen then our user could login at max for 2*max-usage-time
		 * Is that acceptable?
		 */

		/*
		 *  User is allowed, but set Session-Timeout.
		 *  Stolen from main/auth.c
		 */

		/*
		 * If we are near a reset then add the next limit, so that the user will
		 * not need to login again
		 */

		if (data->reset_time && res >= (data->reset_time - request->timestamp))
			res += check_vp->lvalue;

		DEBUG2("rlm_counter: (Check item - counter) is greater than zero");
		if ((reply_item = pairfind(request->reply->vps, PW_SESSION_TIMEOUT)) != NULL) {
			if (reply_item->lvalue > res)
				reply_item->lvalue = res;
		} else {
			if ((reply_item = paircreate(PW_SESSION_TIMEOUT, PW_TYPE_INTEGER)) == NULL) {
				radlog(L_ERR|L_CONS, "no memory");
				return RLM_MODULE_NOOP;
			}
			reply_item->lvalue = res;
			pairadd(&request->reply->vps, reply_item);
		}

		ret=RLM_MODULE_OK;

		DEBUG2("rlm_counter: Authorized user %s, check_item=%d, counter=%d",
				key_vp->strvalue,check_vp->lvalue,counter);
		DEBUG2("rlm_counter: Sent Reply-Item for user %s, Type=Session-Timeout, value=%d",
				key_vp->strvalue,res);
	}
	else{
		char module_msg[MAX_STRING_LEN];
		VALUE_PAIR *module_msg_vp;

		/*
		 * User is denied access, send back a reply message
		*/
		sprintf(msg, "Your maximum %s usage time has been reached", data->reset);
		reply_item=pairmake("Reply-Message", msg, T_OP_EQ);
		pairadd(&request->reply->vps, reply_item);

		snprintf(module_msg, sizeof(module_msg), "rlm_counter: Maximum %s usage time reached", data->reset);
		module_msg_vp = pairmake("Module-Message", module_msg, T_OP_EQ);
		pairadd(&request->packet->vps, module_msg_vp);	

		ret=RLM_MODULE_REJECT;

		DEBUG2("rlm_counter: Rejected user %s, check_item=%d, counter=%d",
				key_vp->strvalue,check_vp->lvalue,counter);
	}

	return ret;
}

static int counter_detach(void *instance)
{
	rlm_counter_t *data = (rlm_counter_t *) instance;

	paircompare_unregister(data->dict_attr, counter_cmp);
	gdbm_close(data->gdbm);
	free(data->filename);
	free(data->reset);
	free(data->key_name);
	free(data->count_attribute);
	free(data->counter_name);

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
module_t rlm_counter = {
	"Counter",	
	RLM_TYPE_THREAD_UNSAFE,		/* type */
	NULL,				/* initialization */
	counter_instantiate,		/* instantiation */
	{
		NULL,			/* authentication */
		counter_authorize, 	/* authorization */
		NULL,			/* preaccounting */
		counter_accounting,	/* accounting */
		NULL			/* checksimul */
	},
	counter_detach,			/* detach */
	NULL,				/* destroy */
};
