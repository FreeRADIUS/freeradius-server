/*
 * rlm_counter.c
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2001  The FreeRADIUS server project
 * Copyright 2001  Alan DeKok <aland@ox.org>
 */

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"

#include <gdbm.h>

static const char rcsid[] = "$Id$";

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_counter_t {
	char	*filename;	/* name of the database file */
	char    *reset;		/* daily, weekly, monthly */
	char	*key_name;	/* User-Name */
	char	*count_name;    /* Acct-Session-Time */
	int     key_attr;
	int     count_attr;
	time_t	reset_time;
	time_t  reset_count;
	int     dict_attr;	/* attribute number for the counter. */
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
  { "filename",  PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,filename), NULL,  NULL},
  { "key",       PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,key_name), NULL,  NULL},
  { "reset",     PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,reset), NULL,  NULL},
  { "count-attribute",  PW_TYPE_STRING_PTR, offsetof(rlm_counter_t,count_name), NULL,  NULL},
  { NULL, -1, 0, NULL, NULL }		/* end the list */
};

#define SECONDS_PER_WEEK (SECONDS_PER_DAY * 7)
#define COUNTER_ATTR (1055)

/*
 *	See if the counter matches.
 */
static int counter_cmp(void *instance, VALUE_PAIR *request, VALUE_PAIR *check,
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
	if (!key_vp) {
		return RLM_MODULE_NOOP;
	}

	key_datum.dptr = key_vp->strvalue;
	key_datum.dsize = key_vp->length;

	count_datum = gdbm_fetch(data->gdbm, key_datum);
	if (count_datum.dptr == NULL) {
		return -1;
	}
	memcpy(&counter, count_datum.dptr, sizeof(int));

	return counter - check->lvalue;
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
	time_t now;
	
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

	/*
	 *	Discover the attribute number of the key. 
	 */
	dattr = dict_attrbyname(data->key_name);
	if (!dattr) {
		radlog(L_ERR, "rlm_counter: No such attribute %s",
		       data->key_name);
		return -1;
	}
	data->key_attr = dattr->attr;
	
	/*
	 *	Discover the attribute number of the counter. 
	 */
	dattr = dict_attrbyname(data->count_name);
	if (!dattr) {
		radlog(L_ERR, "rlm_counter: No such attribute %s",
		       data->count_name);
		return -1;
	}
	data->count_attr = dattr->attr;


	/*
	 *  Discover when next to reset the database.
	 */
	now = time(NULL);
	data->reset_time = 0;
	data->reset_count = 0;
	if (strcmp(data->reset, "hourly") == 0) {
		/*
		 *  Round up to the next nearest hour.
		 */
		data->reset_count = 3600;
		data->reset_time = (now + 3600 - 1);
		data->reset_time -= (data->reset_time % 3600);
		
	} else if (strcmp(data->reset, "daily") == 0) {
		/*
		 *  Round up to the next nearest day.
		 */
		data->reset_count = SECONDS_PER_DAY;
		data->reset_time = (now + SECONDS_PER_DAY - 1);
		data->reset_time -= (data->reset_time % SECONDS_PER_DAY);
	} else if (strcmp(data->reset, "weekly") == 0) {
		/*
		 *  Round up to the next nearest week.
		 */
		data->reset_count = SECONDS_PER_WEEK;
		data->reset_time = (now + SECONDS_PER_WEEK - 1);
		data->reset_time -= (data->reset_time % SECONDS_PER_WEEK);
	} else if (strcmp(data->reset, "monthly") == 0) {
		/*
		 *  Yuck.  This involves more work.
		 */
	} else {
		radlog(L_ERR, "rlm_counter: Unknown reset timer \"%s\"",
		       data->reset);
		return -1;
	}


	data->gdbm = gdbm_open(data->filename, sizeof(int),
				   GDBM_WRCREAT | GDBM_SYNC, 0600, NULL);
	if (data->gdbm == NULL) {
		radlog(L_ERR, "rlm_counter: Failed to open file %s: %s",
		       data->filename, strerror(errno));
		return -1;
	}

	/*
	 *  Create a new attribute for the counter.
	 */
	//	dict_addattr("Counter", 0, PW_TYPE_INTEGER, COUNTER_ATTR);
	data->dict_attr = COUNTER_ATTR;

	/*
	 *	Register the huntgroup comparison operation.
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
	rlm_counter_t *data = (rlm_counter_t *) instance;
	datum key_datum;
	datum count_datum;
	VALUE_PAIR *key_vp, *count_vp;
	int counter;
	int rcode;

	/*
	 *	Before doing anything else, see if we have to reset
	 *	the counters.
	 */
	if (data->reset_time &&
	    (data->reset_time < request->timestamp)) {
		gdbm_close(data->gdbm);

		/*
		 *	Re-set the next time to clean the database.
		 */
		data->reset_time += data->reset_count;

		/*
		 *	Open a completely new database.
		 */
		data->gdbm = gdbm_open(data->filename, sizeof(int),
				       GDBM_NEWDB | GDBM_SYNC, 0600, NULL);
		if (data->gdbm == NULL) {
			radlog(L_ERR, "rlm_counter: Failed to open file %s: %s",
			       data->filename, strerror(errno));
			return RLM_MODULE_FAIL;
		}
	}

	/*
	 *	Look for the key.  User-Name is special.  It means
	 *	The REAL username, after stripping.
	 */
	if (data->key_attr == PW_USER_NAME) {
		key_vp = request->username;
	} else {
		key_vp = pairfind(request->packet->vps, data->key_attr);
	}
	if (!key_vp) {
		return RLM_MODULE_NOOP;
	}

	/*
	 *	Look for the attribute to use as a counter.
	 */
	count_vp = pairfind(request->packet->vps, data->count_attr);
	if (!count_vp) {
		return RLM_MODULE_NOOP;
	}

	key_datum.dptr = key_vp->strvalue;
	key_datum.dsize = key_vp->length;

	count_datum = gdbm_fetch(data->gdbm, key_datum);
	if (count_datum.dptr == NULL) {
		counter = 0;
	} else {
		memcpy(&counter, count_datum.dptr, sizeof(int));
	}

	counter += count_vp->lvalue;
	count_datum.dptr = (char *) &counter;
	count_datum.dsize = sizeof(int);

	rcode = gdbm_store(data->gdbm, key_datum, count_datum, GDBM_REPLACE);
	if (rcode < 0) {
		radlog(L_ERR, "rlm_counter: Failed storing data to %s: %s",
		       data->filename, gdbm_strerror(gdbm_errno));
		return RLM_MODULE_FAIL;
	}

	DEBUG2("rlm_counter: Added %d, New value for %s = %d",
	       count_vp->lvalue, key_vp->strvalue, counter);
	       
	
	return RLM_MODULE_OK;
}

static int counter_detach(void *instance)
{
	rlm_counter_t *data = (rlm_counter_t *) instance;

	paircompare_unregister(data->dict_attr, counter_cmp);
	gdbm_close(data->gdbm);
	free(data->filename);
	free(data->reset);
	free(data->key_name);
	free(data->count_name);

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
	"Count",	
	RLM_TYPE_THREAD_UNSAFE,		/* type */
	NULL,				/* initialization */
	counter_instantiate,		/* instantiation */
	{
		NULL,			/* authentication */
		NULL,			/* authorization */
		NULL,			/* preaccounting */
		counter_accounting,	/* accounting */
		NULL			/* checksimul */
	},
	counter_detach,			/* detach */
	NULL,				/* destroy */
};
