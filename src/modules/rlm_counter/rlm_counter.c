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
typedef struct rlm_counter_t {
	char *filename;		/* name of the database file */
	char *reset;		/* daily, weekly, monthly, never or user defined */
	char *key_name;		/* User-Name */
	char *count_attribute;	/* Acct-Session-Time */
	char *counter_name;	/* Daily-Session-Time */
	char *check_name;	/* Daily-Max-Session */
	char *reply_name;	/* Session-Timeout */
	char *service_type;	/* Service-Type to search for */
	int cache_size;
	int service_val;
	int key_attr;
	int count_attr;
	int check_attr;
	int reply_attr;
	time_t reset_time;	/* The time of the next reset. */
	time_t last_reset;	/* The time of the last reset. */
	int dict_attr;		/* attribute number for the counter. */
	GDBM_FILE gdbm;		/* The gdbm file handle */
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t mutex;	/* A mutex to lock the gdbm file for only one reader/writer */
#endif
} rlm_counter_t;

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

typedef struct rad_counter {
	unsigned int user_counter;
	char uniqueid[UNIQUEID_MAX_LEN];
} rad_counter;

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
  { "filename", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,filename), NULL, NULL },
  { "key", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,key_name), NULL, NULL },
  { "reset", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,reset), NULL,  NULL },
  { "count-attribute", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,count_attribute), NULL, NULL },
  { "counter-name", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,counter_name), NULL,  NULL },
  { "check-name", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,check_name), NULL, NULL },
  { "reply-name", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,reply_name), NULL, NULL },
  { "allowed-servicetype", PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,service_type),NULL, NULL },
  { "cache-size", PW_TYPE_INTEGER, offsetof(rlm_counter_t,cache_size), NULL, "1000" },
  { NULL, -1, 0, NULL, NULL }
};

static int counter_detach(void *instance);


/*
 *	See if the counter matches.
 */
static int counter_cmp(void *instance,
		       REQUEST *req UNUSED,
		       VALUE_PAIR *request, VALUE_PAIR *check,
		       VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	rlm_counter_t *data = (rlm_counter_t *) instance;
	datum key_datum;
	datum count_datum;
	VALUE_PAIR *key_vp;
	rad_counter counter;

	check_pairs = check_pairs; /* shut the compiler up */
	reply_pairs = reply_pairs;
	req = req;

	/*
	 *	Find the key attribute.
	 */
	key_vp = pairfind(request, data->key_attr, 0);
	if (key_vp == NULL) {
		return RLM_MODULE_NOOP;
	}

	key_datum.dptr = key_vp->vp_strvalue;
	key_datum.dsize = key_vp->length;

	count_datum = gdbm_fetch(data->gdbm, key_datum);

	if (count_datum.dptr == NULL) {
		return -1;
	}
	memcpy(&counter, count_datum.dptr, sizeof(rad_counter));
	free(count_datum.dptr);

	return counter.user_counter - check->vp_integer;
}


static int add_defaults(rlm_counter_t *data)
{
	datum key_datum;
	datum time_datum;
	const char *default1 = "DEFAULT1";
	const char *default2 = "DEFAULT2";

	DEBUG2("rlm_counter: add_defaults: Start");

	key_datum.dptr = (char *) default1;
	key_datum.dsize = strlen(default1);
	time_datum.dptr = (char *) &data->reset_time;
	time_datum.dsize = sizeof(time_t);

	if (gdbm_store(data->gdbm, key_datum, time_datum, GDBM_REPLACE) < 0){
		radlog(L_ERR, "rlm_counter: Failed storing data to %s: %s",
				data->filename, gdbm_strerror(gdbm_errno));
		return RLM_MODULE_FAIL;
	}
	DEBUG2("rlm_counter: DEFAULT1 set to %d",(int)data->reset_time);

	key_datum.dptr = (char *) default2;
	key_datum.dsize = strlen(default2);
	time_datum.dptr = (char *) &data->last_reset;
	time_datum.dsize = sizeof(time_t);

	if (gdbm_store(data->gdbm, key_datum, time_datum, GDBM_REPLACE) < 0){
		radlog(L_ERR, "rlm_counter: Failed storing data to %s: %s",
				data->filename, gdbm_strerror(gdbm_errno));
		return RLM_MODULE_FAIL;
	}
	DEBUG2("rlm_counter: DEFAULT2 set to %d",(int)data->last_reset);
	DEBUG2("rlm_counter: add_defaults: End");

	return RLM_MODULE_OK;
}

static int reset_db(rlm_counter_t *data)
{
	int cache_size = data->cache_size;
	int ret;

	DEBUG2("rlm_counter: reset_db: Closing database");
	gdbm_close(data->gdbm);

	/*
	 *	Open a completely new database.
	 */
	data->gdbm = gdbm_open(data->filename, sizeof(int),
			GDBM_NEWDB | GDBM_COUNTER_OPTS, 0600, NULL);
	if (data->gdbm == NULL) {
		radlog(L_ERR, "rlm_counter: Failed to open file %s: %s",
				data->filename, strerror(errno));
		return RLM_MODULE_FAIL;
	}
	if (gdbm_setopt(data->gdbm, GDBM_CACHESIZE, &cache_size, sizeof(int)) == -1)
		radlog(L_ERR, "rlm_counter: Failed to set cache size");
	DEBUG2("rlm_counter: reset_db: Opened new database");

	/*
	 * Add defaults
	 */
	ret = add_defaults(data);
	if (ret != RLM_MODULE_OK)
		return ret;

	DEBUG2("rlm_counter: reset_db ended");

	return RLM_MODULE_OK;
}

static int find_next_reset(rlm_counter_t *data, time_t timeval)
{
	int ret = 0;
	size_t len;
	unsigned int num = 1;
	char last = '\0';
	struct tm *tm, s_tm;
	char sCurrentTime[40], sNextTime[40];

	tm = localtime_r(&timeval, &s_tm);
	len = strftime(sCurrentTime, sizeof(sCurrentTime), "%Y-%m-%d %H:%M:%S", tm);
	if (len == 0) *sCurrentTime = '\0';
	tm->tm_sec = tm->tm_min = 0;

	if (data->reset == NULL)
		return -1;
	if (isdigit((int) data->reset[0])){
		len = strlen(data->reset);
		if (len == 0)
			return -1;
		last = data->reset[len - 1];
		if (!isalpha((int) last))
			last = 'd';
		num = atoi(data->reset);
		DEBUG("rlm_counter: num=%d, last=%c",num,last);
	}
	if (strcmp(data->reset, "hourly") == 0 || last == 'h') {
		/*
		 *  Round up to the next nearest hour.
		 */
		tm->tm_hour += num;
		data->reset_time = mktime(tm);
	} else if (strcmp(data->reset, "daily") == 0 || last == 'd') {
		/*
		 *  Round up to the next nearest day.
		 */
		tm->tm_hour = 0;
		tm->tm_mday += num;
		data->reset_time = mktime(tm);
	} else if (strcmp(data->reset, "weekly") == 0 || last == 'w') {
		/*
		 *  Round up to the next nearest week.
		 */
		tm->tm_hour = 0;
		tm->tm_mday += (7 - tm->tm_wday) +(7*(num-1));
		data->reset_time = mktime(tm);
	} else if (strcmp(data->reset, "monthly") == 0 || last == 'm') {
		tm->tm_hour = 0;
		tm->tm_mday = 1;
		tm->tm_mon += num;
		data->reset_time = mktime(tm);
	} else if (strcmp(data->reset, "never") == 0) {
		data->reset_time = 0;
	} else {
		radlog(L_ERR, "rlm_counter: Unknown reset timer \"%s\"",
			data->reset);
		return -1;
	}

	len = strftime(sNextTime, sizeof(sNextTime), "%Y-%m-%d %H:%M:%S", tm);
	if (len == 0) *sNextTime = '\0';
	DEBUG2("rlm_counter: Current Time: %li [%s], Next reset %li [%s]",
		timeval, sCurrentTime, data->reset_time, sNextTime);

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
	int ret;
	datum key_datum;
	datum time_datum;
	const char *default1 = "DEFAULT1";
	const char *default2 = "DEFAULT2";

	/*
	 *	Set up a storage area for instance data
	 */
	data = rad_malloc(sizeof(*data));
	if (!data) {
		radlog(L_ERR, "rlm_counter: rad_malloc() failed.");
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
	if (data->key_name == NULL) {
		radlog(L_ERR, "rlm_counter: 'key' must be set.");
		counter_detach(data);
		return -1;
	}
	dattr = dict_attrbyname(data->key_name);
	if (dattr == NULL) {
		radlog(L_ERR, "rlm_counter: No such attribute %s",
				data->key_name);
		counter_detach(data);
		return -1;
	}
	data->key_attr = dattr->attr;

	/*
	 *	Discover the attribute number of the counter.
	 */
	if (data->count_attribute == NULL) {
		radlog(L_ERR, "rlm_counter: 'count-attribute' must be set.");
		counter_detach(data);
		return -1;
	}
	dattr = dict_attrbyname(data->count_attribute);
	if (dattr == NULL) {
		radlog(L_ERR, "rlm_counter: No such attribute %s",
				data->count_attribute);
		counter_detach(data);
		return -1;
	}
	data->count_attr = dattr->attr;

	/*
	 * Discover the attribute number of the reply attribute.
	 */
	if (data->reply_name != NULL) {
		dattr = dict_attrbyname(data->reply_name);
		if (dattr == NULL) {
			radlog(L_ERR, "rlm_counter: No such attribute %s",
					data->reply_name);
			counter_detach(data);
			return -1;
		}
		if (dattr->type != PW_TYPE_INTEGER) {
			radlog(L_ERR, "rlm_counter: Reply attribute %s is not of type integer",
				data->reply_name);
			counter_detach(data);
			return -1;
		}
		data->reply_attr = dattr->attr;
	}


	/*
	 *  Create a new attribute for the counter.
	 */
	if (data->counter_name == NULL) {
		radlog(L_ERR, "rlm_counter: 'counter-name' must be set.");
		counter_detach(data);
		return -1;
	}

	memset(&flags, 0, sizeof(flags));
	dict_addattr(data->counter_name, -1, 0, PW_TYPE_INTEGER, flags);
	dattr = dict_attrbyname(data->counter_name);
	if (dattr == NULL) {
		radlog(L_ERR, "rlm_counter: Failed to create counter attribute %s",
				data->counter_name);
		counter_detach(data);
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
		counter_detach(data);
		return -1;
	}
	dict_addattr(data->check_name, 0, PW_TYPE_INTEGER, -1, flags);
	dattr = dict_attrbyname(data->check_name);
	if (dattr == NULL) {
		radlog(L_ERR, "rlm_counter: Failed to create check attribute %s",
				data->counter_name);
		counter_detach(data);
		return -1;
	}
	data->check_attr = dattr->attr;

	/*
	 * Find the attribute for the allowed protocol
	 */
	if (data->service_type != NULL) {
		if ((dval = dict_valbyname(PW_SERVICE_TYPE, 0, data->service_type)) == NULL) {
			radlog(L_ERR, "rlm_counter: Failed to find attribute number for %s",
					data->service_type);
			counter_detach(data);
			return -1;
		}
		data->service_val = dval->value;
	}

	/*
	 * Find when to reset the database.
	 */
	if (data->reset == NULL) {
		radlog(L_ERR, "rlm_counter: 'reset' must be set.");
		counter_detach(data);
		return -1;
	}
	now = time(NULL);
	data->reset_time = 0;
	data->last_reset = now;

	if (find_next_reset(data,now) == -1){
		radlog(L_ERR, "rlm_counter: find_next_reset() returned -1. Exiting.");
		counter_detach(data);
		return -1;
	}

	if (data->filename == NULL) {
		radlog(L_ERR, "rlm_counter: 'filename' must be set.");
		counter_detach(data);
		return -1;
	}
	data->gdbm = gdbm_open(data->filename, sizeof(int),
			GDBM_WRCREAT | GDBM_COUNTER_OPTS, 0600, NULL);
	if (data->gdbm == NULL) {
		radlog(L_ERR, "rlm_counter: Failed to open file %s: %s",
				data->filename, strerror(errno));
		counter_detach(data);
		return -1;
	}
	if (gdbm_setopt(data->gdbm, GDBM_CACHESIZE, &cache_size, sizeof(int)) == -1)
		radlog(L_ERR, "rlm_counter: Failed to set cache size");

	/*
	 * Look for the DEFAULT1 entry. This entry if it exists contains the
	 * time of the next database reset. This time is set each time we reset
	 * the database. If next_reset < now then we reset the database.
	 * That way we can overcome the problem where radiusd is down during a database
	 * reset time. If we did not keep state information in the database then the reset
	 * would be extended and that would create problems.
	 *
	 * We also store the time of the last reset in the DEFAULT2 entry.
	 *
	 * If DEFAULT1 and DEFAULT2 do not exist (new database) we add them to the database
	 */

	key_datum.dptr = (char *)default1;
	key_datum.dsize = strlen(default1);

	time_datum = gdbm_fetch(data->gdbm, key_datum);
	if (time_datum.dptr != NULL){
		time_t next_reset = 0;

		memcpy(&next_reset, time_datum.dptr, sizeof(time_t));
		free(time_datum.dptr);
		if (next_reset && next_reset <= now){

			data->last_reset = now;
			ret = reset_db(data);
			if (ret != RLM_MODULE_OK){
				radlog(L_ERR, "rlm_counter: reset_db() failed");
				counter_detach(data);
				return -1;
			}
		}
		else
			data->reset_time = next_reset;
		key_datum.dptr = (char *)default2;
		key_datum.dsize = strlen(default2);

		time_datum = gdbm_fetch(data->gdbm, key_datum);
		if (time_datum.dptr != NULL){
			memcpy(&data->last_reset, time_datum.dptr, sizeof(time_t));
			free(time_datum.dptr);
		}
	}
	else{
		ret = add_defaults(data);
		if (ret != RLM_MODULE_OK){
			radlog(L_ERR, "rlm_counter: add_defaults() failed");
			counter_detach(data);
			return -1;
		}
	}


	/*
	 *	Register the counter comparison operation.
	 */
	paircompare_register(data->dict_attr, 0, counter_cmp, data);

	/*
	 * Init the mutex
	 */
	pthread_mutex_init(&data->mutex, NULL);

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
	VALUE_PAIR *key_vp, *count_vp, *proto_vp, *uniqueid_vp;
	rad_counter counter;
	int rcode;
	int acctstatustype = 0;
	time_t diff;

	if ((key_vp = pairfind(request->packet->vps, PW_ACCT_STATUS_TYPE, 0)) != NULL)
		acctstatustype = key_vp->vp_integer;
	else {
		DEBUG("rlm_counter: Could not find account status type in packet.");
		return RLM_MODULE_NOOP;
	}
	if (acctstatustype != PW_STATUS_STOP){
		DEBUG("rlm_counter: We only run on Accounting-Stop packets.");
		return RLM_MODULE_NOOP;
	}
	uniqueid_vp = pairfind(request->packet->vps, PW_ACCT_UNIQUE_SESSION_ID, 0);
	if (uniqueid_vp != NULL)
		DEBUG("rlm_counter: Packet Unique ID = '%s'",uniqueid_vp->vp_strvalue);

	/*
	 *	Before doing anything else, see if we have to reset
	 *	the counters.
	 */
	if (data->reset_time && (data->reset_time <= request->timestamp)) {
		int ret;

		DEBUG("rlm_counter: Time to reset the database.");
		data->last_reset = data->reset_time;
		find_next_reset(data,request->timestamp);
		pthread_mutex_lock(&data->mutex);
		ret = reset_db(data);
		pthread_mutex_unlock(&data->mutex);
		if (ret != RLM_MODULE_OK)
			return ret;
	}
	/*
	 * Check if we need to watch out for a specific service-type. If yes then check it
	 */
	if (data->service_type != NULL) {
		if ((proto_vp = pairfind(request->packet->vps, PW_SERVICE_TYPE, 0)) == NULL){
			DEBUG("rlm_counter: Could not find Service-Type attribute in the request. Returning NOOP.");
			return RLM_MODULE_NOOP;
		}
		if ((unsigned)proto_vp->vp_integer != data->service_val){
			DEBUG("rlm_counter: This Service-Type is not allowed. Returning NOOP.");
			return RLM_MODULE_NOOP;
		}
	}
	/*
	 * Check if request->timestamp - {Acct-Delay-Time} < last_reset
	 * If yes reject the packet since it is very old
	 */
	key_vp = pairfind(request->packet->vps, PW_ACCT_DELAY_TIME, 0);
	if (key_vp != NULL){
		if (key_vp->vp_integer != 0 &&
		    (request->timestamp - key_vp->vp_integer) < data->last_reset){
			DEBUG("rlm_counter: This packet is too old. Returning NOOP.");
			return RLM_MODULE_NOOP;
		}
	}



	/*
	 *	Look for the key.  User-Name is special.  It means
	 *	The REAL username, after stripping.
	 */
	key_vp = (data->key_attr == PW_USER_NAME) ? request->username : pairfind(request->packet->vps, data->key_attr, 0);
	if (key_vp == NULL){
		DEBUG("rlm_counter: Could not find the key-attribute in the request. Returning NOOP.");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Look for the attribute to use as a counter.
	 */
	count_vp = pairfind(request->packet->vps, data->count_attr, 0);
	if (count_vp == NULL){
		DEBUG("rlm_counter: Could not find the count-attribute in the request.");
		return RLM_MODULE_NOOP;
	}

	key_datum.dptr = key_vp->vp_strvalue;
	key_datum.dsize = key_vp->length;

	DEBUG("rlm_counter: Searching the database for key '%s'",key_vp->vp_strvalue);
	pthread_mutex_lock(&data->mutex);
	count_datum = gdbm_fetch(data->gdbm, key_datum);
	pthread_mutex_unlock(&data->mutex);
	if (count_datum.dptr == NULL){
		DEBUG("rlm_counter: Could not find the requested key in the database.");
		counter.user_counter = 0;
		if (uniqueid_vp != NULL)
			strlcpy(counter.uniqueid,uniqueid_vp->vp_strvalue,
				sizeof(counter.uniqueid));
		else
			memset((char *)counter.uniqueid,0,UNIQUEID_MAX_LEN);
	}
	else{
		DEBUG("rlm_counter: Key found.");
		memcpy(&counter, count_datum.dptr, sizeof(rad_counter));
		free(count_datum.dptr);
		if (counter.uniqueid)
			DEBUG("rlm_counter: Counter Unique ID = '%s'",counter.uniqueid);
		if (uniqueid_vp != NULL){
			if (counter.uniqueid != NULL &&
				strncmp(uniqueid_vp->vp_strvalue,counter.uniqueid, UNIQUEID_MAX_LEN - 1) == 0){
				DEBUG("rlm_counter: Unique IDs for user match. Droping the request.");
				return RLM_MODULE_NOOP;
			}
			strlcpy(counter.uniqueid,uniqueid_vp->vp_strvalue,
				sizeof(counter.uniqueid));
		}
		DEBUG("rlm_counter: User=%s, Counter=%d.",request->username->vp_strvalue,counter.user_counter);
	}

	if (data->count_attr == PW_ACCT_SESSION_TIME) {
		/*
		 *	If session time < diff then the user got in after the
		 *	last reset. So add his session time, otherwise add the
		 *	diff.
		 *
		 *	That way if he logged in at 23:00 and we reset the
		 *	daily counter at 24:00 and he logged out at 01:00
		 *	then we will only count one hour (the one in the new
		 *	day). That is the right thing
		 */
		diff = request->timestamp - data->last_reset;
		counter.user_counter += (count_vp->vp_integer < diff) ? count_vp->vp_integer : diff;

	} else if (count_vp->type == PW_TYPE_INTEGER) {
		/*
		 *	Integers get counted, without worrying about
		 *	reset dates.
		 */
		counter.user_counter += count_vp->vp_integer;

	} else {
		/*
		 *	The attribute is NOT an integer, just count once
		 *	more that we've seen it.
		 */
		counter.user_counter++;
	}

	DEBUG("rlm_counter: User=%s, New Counter=%d.",request->username->vp_strvalue,counter.user_counter);
	count_datum.dptr = (char *) &counter;
	count_datum.dsize = sizeof(rad_counter);

	DEBUG("rlm_counter: Storing new value in database.");
	pthread_mutex_lock(&data->mutex);
	rcode = gdbm_store(data->gdbm, key_datum, count_datum, GDBM_REPLACE);
	pthread_mutex_unlock(&data->mutex);
	if (rcode < 0) {
		radlog(L_ERR, "rlm_counter: Failed storing data to %s: %s",
				data->filename, gdbm_strerror(gdbm_errno));
		return RLM_MODULE_FAIL;
	}
	DEBUG("rlm_counter: New value stored successfully.");

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
	rad_counter counter;
	int res=0;
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
		int ret2;

		data->last_reset = data->reset_time;
		find_next_reset(data,request->timestamp);
		pthread_mutex_lock(&data->mutex);
		ret2 = reset_db(data);
		pthread_mutex_unlock(&data->mutex);
		if (ret2 != RLM_MODULE_OK)
			return ret2;
	}


	/*
	 *      Look for the key.  User-Name is special.  It means
	 *      The REAL username, after stripping.
	 */
	DEBUG2("rlm_counter: Entering module authorize code");
	key_vp = (data->key_attr == PW_USER_NAME) ? request->username : pairfind(request->packet->vps, data->key_attr, 0);
	if (key_vp == NULL) {
		DEBUG2("rlm_counter: Could not find Key value pair");
		return ret;
	}

	/*
	 *      Look for the check item
	 */
	if ((check_vp= pairfind(request->config_items, data->check_attr, 0)) == NULL) {
		DEBUG2("rlm_counter: Could not find Check item value pair");
		return ret;
	}

	key_datum.dptr = key_vp->vp_strvalue;
	key_datum.dsize = key_vp->length;


	/*
	 * Init to be sure
	 */

	counter.user_counter = 0;

	DEBUG("rlm_counter: Searching the database for key '%s'",key_vp->vp_strvalue);
	pthread_mutex_lock(&data->mutex);
	count_datum = gdbm_fetch(data->gdbm, key_datum);
	pthread_mutex_unlock(&data->mutex);
	if (count_datum.dptr != NULL){
		DEBUG("rlm_counter: Key Found.");
		memcpy(&counter, count_datum.dptr, sizeof(rad_counter));
		free(count_datum.dptr);
	}
	else
		DEBUG("rlm_counter: Could not find the requested key in the database.");

	/*
	 * Check if check item > counter
	 */
	DEBUG("rlm_counter: Check item = %d, Count = %d",check_vp->vp_integer,counter.user_counter);
	res=check_vp->vp_integer - counter.user_counter;
	if (res > 0) {
		DEBUG("rlm_counter: res is greater than zero");
		if (data->count_attr == PW_ACCT_SESSION_TIME) {
			/*
			 * Do the following only if the count attribute is
			 * AcctSessionTime
			 */

			/*
		 	*	We are assuming that simultaneous-use=1. But
		 	*	even if that does not happen then our user
		 	*	could login at max for 2*max-usage-time Is
		 	*	that acceptable?
		 	*/

			/*
		 	*	User is allowed, but set Session-Timeout.
		 	*	Stolen from main/auth.c
		 	*/

			/*
		 	*	If we are near a reset then add the next
		 	*	limit, so that the user will not need to
		 	*	login again
			*	Before that set the return value to the time
			*	remaining to next reset
		 	*/
			if (data->reset_time && (
				res >= (data->reset_time - request->timestamp))) {
				res = data->reset_time - request->timestamp;
				res += check_vp->vp_integer;
			}

			if ((reply_item = pairfind(request->reply->vps, PW_SESSION_TIMEOUT, 0)) != NULL) {
				if (reply_item->vp_integer > res)
					reply_item->vp_integer = res;
			} else {
				reply_item = radius_paircreate(request, &request->reply->vps, PW_SESSION_TIMEOUT, 0, PW_TYPE_INTEGER);
				reply_item->vp_integer = res;
			}
		}
		else if (data->reply_attr) {
			if ((reply_item = pairfind(request->reply->vps, data->reply_attr, 0)) != NULL) {
				if (reply_item->vp_integer > res)
					reply_item->vp_integer = res;
			}
			else {
				reply_item = radius_paircreate(request, &request->reply->vps, data->reply_attr, 0, PW_TYPE_INTEGER);
				reply_item->vp_integer = res;
			}
		}

		ret=RLM_MODULE_OK;

		DEBUG2("rlm_counter: (Check item - counter) is greater than zero");
		DEBUG2("rlm_counter: Authorized user %s, check_item=%d, counter=%d",
				key_vp->vp_strvalue,check_vp->vp_integer,counter.user_counter);
		DEBUG2("rlm_counter: Sent Reply-Item for user %s, Type=Session-Timeout, value=%d",
				key_vp->vp_strvalue,res);
	}
	else{
		char module_fmsg[MAX_STRING_LEN];
		VALUE_PAIR *module_fmsg_vp;

		/*
		 * User is denied access, send back a reply message
		*/
		sprintf(msg, "Your maximum %s usage time has been reached", data->reset);
		reply_item=pairmake("Reply-Message", msg, T_OP_EQ);
		pairadd(&request->reply->vps, reply_item);

		snprintf(module_fmsg,sizeof(module_fmsg), "rlm_counter: Maximum %s usage time reached", data->reset);
		module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
		pairadd(&request->packet->vps, module_fmsg_vp);

		ret=RLM_MODULE_REJECT;

		DEBUG2("rlm_counter: Rejected user %s, check_item=%d, counter=%d",
				key_vp->vp_strvalue,check_vp->vp_integer,counter.user_counter);
	}

	return ret;
}

static int counter_detach(void *instance)
{
	rlm_counter_t *data = (rlm_counter_t *) instance;

	paircompare_unregister(data->dict_attr, counter_cmp);
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
module_t rlm_counter = {
	 RLM_MODULE_INIT,
	"counter",
	RLM_TYPE_THREAD_SAFE,		/* type */
	counter_instantiate,		/* instantiation */
	counter_detach,			/* detach */
	{
		NULL,			/* authentication */
		counter_authorize, 	/* authorization */
		NULL,			/* preaccounting */
		counter_accounting,	/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
