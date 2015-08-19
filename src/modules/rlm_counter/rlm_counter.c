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
 * @file rlm_counter.c
 * @brief Provides a packet counter to track data usage and other values.
 *
 * @copyright 2001,2006  The FreeRADIUS server project
 * @copyright 2001  Alan DeKok <aland@ox.org>
 * @copyright 2001-2003  Kostas Kalevras <kkalev@noc.ntua.gr>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

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
	char const *filename;		/* name of the database file */
	char const *reset;		/* daily, weekly, monthly, never or user defined */
	char const *key_name;		/* User-Name */
	char const *count_attribute;	/* Acct-Session-Time */
	char const *counter_name;	/* Daily-Session-Time */
	char const *check_name;		/* Daily-Max-Session */
	char const *reply_name;		/* Session-Timeout */
	char const *service_type;	/* Service-Type to search for */

	uint32_t cache_size;
	uint32_t service_val;

	DICT_ATTR const *key_attr;
	DICT_ATTR const *count_attr;
	DICT_ATTR const *check_attr;
	DICT_ATTR const *reply_attr;
	DICT_ATTR const *dict_attr;		/* attribute number for the counter. */

	time_t reset_time;	/* The time of the next reset. */
	time_t last_reset;	/* The time of the last reset. */

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
	{ "filename", FR_CONF_OFFSET(PW_TYPE_FILE_OUTPUT | PW_TYPE_REQUIRED, rlm_counter_t, filename), NULL },
	{ "key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_ATTRIBUTE, rlm_counter_t, key_name), NULL },
	{ "reset", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_counter_t, reset), NULL },

	{ "count-attribute", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, rlm_counter_t, count_attribute), NULL },
	{ "count_attribute", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_ATTRIBUTE, rlm_counter_t, count_attribute), NULL },

	{ "counter-name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, rlm_counter_t, counter_name), NULL },
	{ "counter_name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_counter_t, counter_name), NULL },

	{ "check-name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, rlm_counter_t, check_name), NULL },
	{ "check_name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_counter_t, check_name), NULL },

	{ "reply-name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, rlm_counter_t, reply_name), NULL },
	{ "reply_name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_ATTRIBUTE, rlm_counter_t, reply_name), NULL },

	{ "allowed-servicetype", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, rlm_counter_t, service_type), NULL },
	{ "allowed_service_type", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_counter_t, service_type), NULL },

	{ "cache-size", FR_CONF_OFFSET(PW_TYPE_INTEGER | PW_TYPE_DEPRECATED, rlm_counter_t, cache_size), NULL },
	{ "cache_size", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_counter_t, cache_size), "1000" },
	CONF_PARSER_TERMINATOR
};


/*
 *	Work around compiler "const" issues.
 */
#define ASSIGN(_x,_y) memcpy(&_x, &_y, sizeof(_x))


/*
 *	See if the counter matches.
 */
static int counter_cmp(void *instance, UNUSED REQUEST *req, VALUE_PAIR *request, VALUE_PAIR *check,
		       UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	rlm_counter_t *inst = instance;
	datum key_datum;
	datum count_datum;
	VALUE_PAIR *key_vp;
	rad_counter counter;

	/*
	 *	Find the key attribute.
	 */
	key_vp = fr_pair_find_by_da(request, inst->key_attr, TAG_ANY);
	if (!key_vp) {
		return RLM_MODULE_NOOP;
	}

	ASSIGN(key_datum.dptr,key_vp->vp_strvalue);
	key_datum.dsize = key_vp->vp_length;

	count_datum = gdbm_fetch(inst->gdbm, key_datum);

	if (!count_datum.dptr) {
		return -1;
	}
	memcpy(&counter, count_datum.dptr, sizeof(rad_counter));
	free(count_datum.dptr);

	return counter.user_counter - check->vp_integer;
}


static rlm_rcode_t add_defaults(rlm_counter_t *inst)
{
	datum key_datum;
	datum time_datum;
	static char const *default1 = "DEFAULT1";
	static char const *default2 = "DEFAULT2";

	DEBUG2("rlm_counter: add_defaults: Start");

	memcpy(&key_datum.dptr, &default1, sizeof(key_datum.dptr));
	key_datum.dsize = strlen(key_datum.dptr);
	time_datum.dptr = (char *) &inst->reset_time;
	time_datum.dsize = sizeof(time_t);

	if (gdbm_store(inst->gdbm, key_datum, time_datum, GDBM_REPLACE) < 0) {
		ERROR("rlm_counter: Failed storing data to %s: %s", inst->filename, gdbm_strerror(gdbm_errno));
		return RLM_MODULE_FAIL;
	}
	DEBUG2("rlm_counter: DEFAULT1 set to %u", (unsigned int) inst->reset_time);

	memcpy(&key_datum.dptr, &default2, sizeof(key_datum.dptr));
	key_datum.dsize = strlen(key_datum.dptr);
	key_datum.dsize = strlen(default2);
	time_datum.dptr = (char *) &inst->last_reset;
	time_datum.dsize = sizeof(time_t);

	if (gdbm_store(inst->gdbm, key_datum, time_datum, GDBM_REPLACE) < 0) {
		ERROR("rlm_counter: Failed storing data to %s: %s", inst->filename, gdbm_strerror(gdbm_errno));
		return RLM_MODULE_FAIL;
	}
	DEBUG2("rlm_counter: DEFAULT2 set to %u", (unsigned int) inst->last_reset);
	DEBUG2("rlm_counter: add_defaults: End");

	return RLM_MODULE_OK;
}

static rlm_rcode_t reset_db(rlm_counter_t *inst)
{
	int cache_size = inst->cache_size;
	rlm_rcode_t rcode;

	DEBUG2("rlm_counter: reset_db: Closing database");
	gdbm_close(inst->gdbm);

	/*
	 *	Open a completely new database.
	 */
	{
		char *filename;

		memcpy(&filename, &inst->filename, sizeof(filename));
		inst->gdbm = gdbm_open(filename, sizeof(int), GDBM_NEWDB | GDBM_COUNTER_OPTS, 0600, NULL);
	}
	if (!inst->gdbm) {
		ERROR("rlm_counter: Failed to open file %s: %s", inst->filename, fr_syserror(errno));
		return RLM_MODULE_FAIL;
	}
	if (gdbm_setopt(inst->gdbm, GDBM_CACHESIZE, &cache_size, sizeof(cache_size)) == -1) {
		ERROR("rlm_counter: Failed to set cache size");
	}

	DEBUG2("rlm_counter: reset_db: Opened new database");

	/*
	 * Add defaults
	 */
	rcode = add_defaults(inst);
	if (rcode != RLM_MODULE_OK)
		return rcode;

	DEBUG2("rlm_counter: reset_db ended");

	return RLM_MODULE_OK;
}

static int find_next_reset(rlm_counter_t *inst, time_t timeval)
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

	if (!inst->reset)
		return -1;
	if (isdigit((int) inst->reset[0])) {
		len = strlen(inst->reset);
		if (len == 0)
			return -1;
		last = inst->reset[len - 1];
		if (!isalpha((int) last))
			last = 'd';
		num = atoi(inst->reset);
		DEBUG("rlm_counter: num=%d, last=%c",num,last);
	}
	if (strcmp(inst->reset, "hourly") == 0 || last == 'h') {
		/*
		 *  Round up to the next nearest hour.
		 */
		tm->tm_hour += num;
		inst->reset_time = mktime(tm);
	} else if (strcmp(inst->reset, "daily") == 0 || last == 'd') {
		/*
		 *  Round up to the next nearest day.
		 */
		tm->tm_hour = 0;
		tm->tm_mday += num;
		inst->reset_time = mktime(tm);
	} else if (strcmp(inst->reset, "weekly") == 0 || last == 'w') {
		/*
		 *  Round up to the next nearest week.
		 */
		tm->tm_hour = 0;
		tm->tm_mday += (7 - tm->tm_wday) +(7*(num-1));
		inst->reset_time = mktime(tm);
	} else if (strcmp(inst->reset, "monthly") == 0 || last == 'm') {
		tm->tm_hour = 0;
		tm->tm_mday = 1;
		tm->tm_mon += num;
		inst->reset_time = mktime(tm);
	} else if (strcmp(inst->reset, "never") == 0) {
		inst->reset_time = 0;
	} else {
		ERROR("rlm_counter: Unknown reset timer \"%s\"",
			inst->reset);
		return -1;
	}

	len = strftime(sNextTime, sizeof(sNextTime), "%Y-%m-%d %H:%M:%S", tm);
	if (len == 0) *sNextTime = '\0';
	DEBUG2("rlm_counter: Current Time: %" PRId64 " [%s], Next reset %" PRId64 " [%s]",
	       (int64_t) timeval, sCurrentTime, (int64_t) inst->reset_time, sNextTime);

	return ret;
}


static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_counter_t *inst = instance;
	ATTR_FLAGS flags;
	DICT_ATTR const *da;

	memset(&flags, 0, sizeof(flags));
	flags.compare = 1;	/* ugly hack */
	da = dict_attrbyname(inst->counter_name);
	if (da && (da->type != PW_TYPE_INTEGER)) {
		cf_log_err_cs(conf, "Counter attribute %s MUST be integer", inst->counter_name);
		return -1;
	}

	if (!da && (dict_addattr(inst->counter_name, -1, 0, PW_TYPE_INTEGER, flags) < 0)) {
		cf_log_err_cs(conf, "Failed to create counter attribute %s: %s", inst->counter_name, fr_strerror());
		return -1;
	}

	if (paircompare_register_byname(inst->counter_name, NULL, true, counter_cmp, inst) < 0) {
		cf_log_err_cs(conf, "Failed to create counter attribute %s: %s", inst->counter_name, fr_strerror());
		return -1;
	}


	da = dict_attrbyname(inst->counter_name);
	if (!da) {
		cf_log_err_cs(conf, "Failed to find counter attribute %s", inst->counter_name);
		return -1;
	}
	inst->dict_attr = da;

	/*
	 *	Create a new attribute for the check item.
	 */
	flags.compare = 0;
	if (dict_addattr(inst->check_name, -1, 0, PW_TYPE_INTEGER, flags) < 0) {
		cf_log_err_cs(conf, "Failed to create check attribute %s: %s", inst->counter_name, fr_strerror());
		return -1;

	}

	da = dict_attrbyname(inst->check_name);
	if (!da) {
		cf_log_err_cs(conf, "Failed to find check attribute %s", inst->counter_name);
		return -1;
	}
	inst->check_attr = da;

	return 0;
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
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_counter_t *inst = instance;
	DICT_ATTR const *da;
	DICT_VALUE *dval;
	time_t now;
	int cache_size;
	int ret;
	datum key_datum;
	datum time_datum;
	char const *default1 = "DEFAULT1";
	char const *default2 = "DEFAULT2";

	cache_size = inst->cache_size;

	da = dict_attrbyname(inst->key_name);
	rad_assert(da != NULL);
	inst->key_attr = da;

	/*
	 *	Discover the attribute number of the counter.
	 */
	da = dict_attrbyname(inst->count_attribute);
	rad_assert(da != NULL);
	inst->count_attr = da;

	/*
	 * Discover the attribute number of the reply attribute.
	 */
	if (inst->reply_name != NULL) {
		da = dict_attrbyname(inst->reply_name);
		if (!da) {
			cf_log_err_cs(conf, "No such attribute %s", inst->reply_name);
			return -1;
		}
		if (da->type != PW_TYPE_INTEGER) {
			cf_log_err_cs(conf, "Reply attribute' %s' is not of type integer", inst->reply_name);
			return -1;
		}
		inst->reply_attr = da;
	} else {
		inst->reply_attr = NULL;
	}

	/*
	 * Find the attribute for the allowed protocol
	 */
	if (inst->service_type != NULL) {
		if ((dval = dict_valbyname(PW_SERVICE_TYPE, 0, inst->service_type)) == NULL) {
			ERROR("rlm_counter: Failed to find attribute number for %s", inst->service_type);
			return -1;
		}
		inst->service_val = dval->value;
	}

	/*
	 * Find when to reset the database.
	 */
	rad_assert(inst->reset && *inst->reset);
	now = time(NULL);
	inst->reset_time = 0;
	inst->last_reset = now;

	if (find_next_reset(inst,now) == -1) {
		ERROR("rlm_counter: find_next_reset() returned -1. Exiting");
		return -1;
	}

	{
		char *filename;

		memcpy(&filename, &inst->filename, sizeof(filename));
		inst->gdbm = gdbm_open(filename, sizeof(int), GDBM_NEWDB | GDBM_COUNTER_OPTS, 0600, NULL);
	}
	if (!inst->gdbm) {
		ERROR("rlm_counter: Failed to open file %s: %s", inst->filename, fr_syserror(errno));
		return -1;
	}
	if (gdbm_setopt(inst->gdbm, GDBM_CACHESIZE, &cache_size, sizeof(cache_size)) == -1) {
		ERROR("rlm_counter: Failed to set cache size");
	}

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

	memcpy(&key_datum.dptr, &default1, sizeof(key_datum.dptr));
	key_datum.dsize = strlen(key_datum.dptr);

	time_datum = gdbm_fetch(inst->gdbm, key_datum);
	if (time_datum.dptr != NULL) {
		time_t next_reset = 0;

		memcpy(&next_reset, time_datum.dptr, sizeof(time_t));
		free(time_datum.dptr);
		time_datum.dptr = NULL;
		if (next_reset && next_reset <= now) {

			inst->last_reset = now;
			ret = reset_db(inst);
			if (ret != RLM_MODULE_OK) {
				ERROR("rlm_counter: reset_db() failed");
				return -1;
			}
		} else {
			inst->reset_time = next_reset;
		}

		memcpy(&key_datum.dptr, &default2, sizeof(key_datum.dptr));
		key_datum.dsize = strlen(key_datum.dptr);

		time_datum = gdbm_fetch(inst->gdbm, key_datum);
		if (time_datum.dptr != NULL) {
			memcpy(&inst->last_reset, time_datum.dptr, sizeof(time_t));
			free(time_datum.dptr);
		}
	} else {
		ret = add_defaults(inst);
		if (ret != RLM_MODULE_OK) {
			ERROR("rlm_counter: add_defaults() failed");
			return -1;
		}
	}

	/*
	 * Init the mutex
	 */
	pthread_mutex_init(&inst->mutex, NULL);

	return 0;
}

/*
 *	Write accounting information to this modules database.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, REQUEST *request)
{
	rlm_counter_t *inst = instance;
	datum key_datum;
	datum count_datum;
	VALUE_PAIR *key_vp, *count_vp, *proto_vp, *uniqueid_vp;
	rad_counter counter;
	rlm_rcode_t rcode;
	int ret;
	int acctstatustype = 0;
	time_t diff;

	if ((key_vp = fr_pair_find_by_num(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY)) != NULL)
		acctstatustype = key_vp->vp_integer;
	else {
		DEBUG("rlm_counter: Could not find account status type in packet");
		return RLM_MODULE_NOOP;
	}
	if (acctstatustype != PW_STATUS_STOP) {
		DEBUG("rlm_counter: We only run on Accounting-Stop packets");
		return RLM_MODULE_NOOP;
	}
	uniqueid_vp = fr_pair_find_by_num(request->packet->vps, PW_ACCT_UNIQUE_SESSION_ID, 0, TAG_ANY);
	if (uniqueid_vp != NULL)
		DEBUG("rlm_counter: Packet Unique ID = '%s'",uniqueid_vp->vp_strvalue);

	/*
	 *	Before doing anything else, see if we have to reset
	 *	the counters.
	 */
	if (inst->reset_time && (inst->reset_time <= request->timestamp)) {
		DEBUG("rlm_counter: Time to reset the database");
		inst->last_reset = inst->reset_time;
		find_next_reset(inst,request->timestamp);
		pthread_mutex_lock(&inst->mutex);
		rcode = reset_db(inst);
		pthread_mutex_unlock(&inst->mutex);
		if (rcode != RLM_MODULE_OK)
			return rcode;
	}
	/*
	 * Check if we need to watch out for a specific service-type. If yes then check it
	 */
	if (inst->service_type != NULL) {
		if ((proto_vp = fr_pair_find_by_num(request->packet->vps, PW_SERVICE_TYPE, 0, TAG_ANY)) == NULL) {
			DEBUG("rlm_counter: Could not find Service-Type attribute in the request. Returning NOOP");
			return RLM_MODULE_NOOP;
		}
		if ((unsigned)proto_vp->vp_integer != inst->service_val) {
			DEBUG("rlm_counter: This Service-Type is not allowed. Returning NOOP");
			return RLM_MODULE_NOOP;
		}
	}
	/*
	 * Check if request->timestamp - {Acct-Delay-Time} < last_reset
	 * If yes reject the packet since it is very old
	 */
	key_vp = fr_pair_find_by_num(request->packet->vps, PW_ACCT_DELAY_TIME, 0, TAG_ANY);
	if (key_vp != NULL) {
		if ((key_vp->vp_integer != 0) && (request->timestamp - (time_t) key_vp->vp_integer) < inst->last_reset) {
			DEBUG("rlm_counter: This packet is too old. Returning NOOP");
			return RLM_MODULE_NOOP;
		}
	}



	/*
	 *	Look for the key.  User-Name is special.  It means
	 *	The REAL username, after stripping.
	 */
	key_vp = (inst->key_attr->attr == PW_USER_NAME) ? request->username :
					fr_pair_find_by_da(request->packet->vps, inst->key_attr, TAG_ANY);
	if (!key_vp) {
		DEBUG("rlm_counter: Could not find the key-attribute in the request. Returning NOOP");
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Look for the attribute to use as a counter.
	 */
	count_vp = fr_pair_find_by_da(request->packet->vps, inst->count_attr, TAG_ANY);
	if (!count_vp) {
		DEBUG("rlm_counter: Could not find the count_attribute in the request");
		return RLM_MODULE_NOOP;
	}

	ASSIGN(key_datum.dptr, key_vp->vp_strvalue);
	key_datum.dsize = key_vp->vp_length;

	DEBUG("rlm_counter: Searching the database for key '%s'",key_vp->vp_strvalue);
	pthread_mutex_lock(&inst->mutex);
	count_datum = gdbm_fetch(inst->gdbm, key_datum);
	if (!count_datum.dptr) {
		DEBUG("rlm_counter: Could not find the requested key in the database");
		counter.user_counter = 0;
		if (uniqueid_vp != NULL)
			strlcpy(counter.uniqueid,uniqueid_vp->vp_strvalue, sizeof(counter.uniqueid));
		else
			memset((char *)counter.uniqueid,0,UNIQUEID_MAX_LEN);
	} else {
		DEBUG("rlm_counter: Key found");
		memcpy(&counter, count_datum.dptr, sizeof(rad_counter));
		free(count_datum.dptr);
		DEBUG("rlm_counter: Counter Unique ID = '%s'",counter.uniqueid);
		if (uniqueid_vp != NULL) {
			if (strncmp(uniqueid_vp->vp_strvalue,counter.uniqueid, UNIQUEID_MAX_LEN - 1) == 0) {
				DEBUG("rlm_counter: Unique IDs for user match. Droping the request");
				pthread_mutex_unlock(&inst->mutex);
				return RLM_MODULE_NOOP;
			}
			strlcpy(counter.uniqueid,uniqueid_vp->vp_strvalue, sizeof(counter.uniqueid));
		}
		DEBUG("rlm_counter: User=%s, Counter=%d.",request->username->vp_strvalue,counter.user_counter);
	}

	if (inst->count_attr->attr == PW_ACCT_SESSION_TIME) {
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
		diff = request->timestamp - inst->last_reset;
		counter.user_counter += ((time_t) count_vp->vp_integer < diff) ? count_vp->vp_integer : diff;

	} else if (count_vp->da->type == PW_TYPE_INTEGER) {
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

	DEBUG("rlm_counter: Storing new value in database");
	ret = gdbm_store(inst->gdbm, key_datum, count_datum, GDBM_REPLACE);
	pthread_mutex_unlock(&inst->mutex);
	if (ret < 0) {
		ERROR("rlm_counter: Failed storing data to %s: %s", inst->filename, gdbm_strerror(gdbm_errno));
		return RLM_MODULE_FAIL;
	}
	DEBUG("rlm_counter: New value stored successfully");

	return RLM_MODULE_OK;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
	rlm_counter_t *inst = instance;
	rlm_rcode_t rcode = RLM_MODULE_NOOP;
	datum key_datum;
	datum count_datum;
	rad_counter counter;
	VALUE_PAIR *key_vp, *check_vp;
	VALUE_PAIR *reply_item;
	char msg[128];

	/*
	 *	Before doing anything else, see if we have to reset
	 *	the counters.
	 */
	if (inst->reset_time && (inst->reset_time <= request->timestamp)) {
		rlm_rcode_t rcode2;

		inst->last_reset = inst->reset_time;
		find_next_reset(inst,request->timestamp);
		pthread_mutex_lock(&inst->mutex);
		rcode2 = reset_db(inst);
		pthread_mutex_unlock(&inst->mutex);
		if (rcode2 != RLM_MODULE_OK) {
			return rcode2;
		}
	}


	/*
	 *      Look for the key.  User-Name is special.  It means
	 *      The REAL username, after stripping.
	 */
	DEBUG2("rlm_counter: Entering module authorize code");
	key_vp = (inst->key_attr->attr == PW_USER_NAME) ? request->username :
		 fr_pair_find_by_da(request->packet->vps, inst->key_attr, TAG_ANY);
	if (!key_vp) {
		DEBUG2("rlm_counter: Could not find Key value pair");
		return rcode;
	}

	/*
	 *      Look for the check item
	 */
	if ((check_vp = fr_pair_find_by_da(request->config, inst->check_attr, TAG_ANY)) == NULL) {
		DEBUG2("rlm_counter: Could not find Check item value pair");
		return rcode;
	}

	ASSIGN(key_datum.dptr, key_vp->vp_strvalue);
	key_datum.dsize = key_vp->vp_length;


	/*
	 * Init to be sure
	 */

	counter.user_counter = 0;

	DEBUG("rlm_counter: Searching the database for key '%s'",key_vp->vp_strvalue);
	pthread_mutex_lock(&inst->mutex);
	count_datum = gdbm_fetch(inst->gdbm, key_datum);
	pthread_mutex_unlock(&inst->mutex);
	if (count_datum.dptr != NULL) {
		DEBUG("rlm_counter: Key Found");
		memcpy(&counter, count_datum.dptr, sizeof(rad_counter));
		free(count_datum.dptr);
	}
	else
		DEBUG("rlm_counter: Could not find the requested key in the database");

	/*
	 * Check if check item > counter
	 */
	DEBUG("rlm_counter: Check item = %d, Count = %d",check_vp->vp_integer,counter.user_counter);
	if (check_vp->vp_integer > counter.user_counter) {
		unsigned int res;

		res = check_vp->vp_integer - counter.user_counter;

		DEBUG("rlm_counter: res is greater than zero");
		if (inst->count_attr->attr == PW_ACCT_SESSION_TIME) {
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
			if (inst->reset_time && (res >= (inst->reset_time - request->timestamp))) {
				res = inst->reset_time - request->timestamp;
				res += check_vp->vp_integer;
			}

			reply_item = fr_pair_find_by_num(request->reply->vps, PW_SESSION_TIMEOUT, 0, TAG_ANY);
			if (reply_item) {
				if (reply_item->vp_integer > res) {
					reply_item->vp_integer = res;
				}
			} else {
				reply_item = radius_pair_create(request->reply, &request->reply->vps, PW_SESSION_TIMEOUT, 0);
				reply_item->vp_integer = res;
			}
		} else if (inst->reply_attr) {
			reply_item = fr_pair_find_by_da(request->reply->vps, inst->reply_attr, TAG_ANY);
			if (reply_item) {
				if (reply_item->vp_integer > res) {
					reply_item->vp_integer = res;
				}
			} else {
				reply_item = radius_pair_create(request->reply, &request->reply->vps, inst->reply_attr->attr,
							       inst->reply_attr->vendor);
				reply_item->vp_integer = res;
			}
		}

		rcode = RLM_MODULE_OK;

		DEBUG2("rlm_counter: (Check item - counter) is greater than zero");
		DEBUG2("rlm_counter: Authorized user %s, check_item=%d, counter=%d",
				key_vp->vp_strvalue,check_vp->vp_integer,counter.user_counter);
		DEBUG2("rlm_counter: Sent Reply-Item for user %s, Type=Session-Timeout, value=%d", key_vp->vp_strvalue,res);
	} else {
		/*
		 * User is denied access, send back a reply message
		*/
		sprintf(msg, "Your maximum %s usage time has been reached", inst->reset);
		pair_make_reply("Reply-Message", msg, T_OP_EQ);

		REDEBUG("Maximum %s usage time reached", inst->reset);
		rcode = RLM_MODULE_REJECT;

		DEBUG2("rlm_counter: Rejected user %s, check_item=%d, counter=%d",
				key_vp->vp_strvalue,check_vp->vp_integer,counter.user_counter);
	}

	return rcode;
}

static int mod_detach(void *instance)
{
	rlm_counter_t *inst = instance;

	if (inst->gdbm) {
		gdbm_close(inst->gdbm);
	}

	pthread_mutex_destroy(&inst->mutex);

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
extern module_t rlm_counter;
module_t rlm_counter = {
	.magic		= RLM_MODULE_INIT,
	.name		= "counter",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_counter_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_ACCOUNTING]	= mod_accounting
	},
};
