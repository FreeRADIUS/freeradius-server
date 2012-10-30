/*
 * rlm_logintime.c
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
 * Copyright 2004  Kostas Kalevras <kkalev@noc.ntua.gr>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <ctype.h>

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_logintime_t {
	char *msg;		/* The Reply-Message passed back to the user
				 * if the account is outside allowed timestamp */
	int min_time;
} rlm_logintime_t;

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
  { "reply-message", PW_TYPE_STRING_PTR, offsetof(rlm_logintime_t,msg), NULL,
	"You are calling outside your allowed timespan\r\n"},
  { "minimum-timeout", PW_TYPE_INTEGER, offsetof(rlm_logintime_t,min_time), NULL, "60" },
  { NULL, -1, 0, NULL, NULL }
};

static int logintime_detach(void *instance);

/*
 *      Compare the current time to a range.
 */
static int timecmp(void *instance,
		REQUEST *req,
		VALUE_PAIR *request, VALUE_PAIR *check,
		VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	instance = instance;
	request = request;      /* shut the compiler up */
	check_pairs = check_pairs;
	reply_pairs = reply_pairs;

	/*
	 *      If there's a request, use that timestamp.
	 */
	if (timestr_match((char *)check->vp_strvalue,
	req ? req->timestamp : time(NULL)) >= 0)
		return 0;

	return -1;
}


/*
 *	Time-Of-Day support
 */
static int time_of_day(void *instance,
		       REQUEST *req,
		       VALUE_PAIR *request, VALUE_PAIR *check,
		       VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	int scan;
	int hhmmss, when;
	char *p;
	struct tm *tm, s_tm;

	instance = instance;
	request = request;      /* shut the compiler up */
	check_pairs = check_pairs;
	reply_pairs = reply_pairs;

	/*
	 *	Must be called with a request pointer.
	 */
	if (!req) return -1;

	if (strspn(check->vp_strvalue, "0123456789: ") != strlen(check->vp_strvalue)) {
		DEBUG("rlm_logintime: Bad Time-Of-Day value \"%s\"",
		      check->vp_strvalue);
		return -1;
	}

	tm = localtime_r(&req->timestamp, &s_tm);
	hhmmss = (tm->tm_hour * 3600) + (tm->tm_min * 60) + tm->tm_sec;

	/*
	 *	Time of day is a 24-hour clock
	 */
	p = check->vp_strvalue;
	scan = atoi(p);
	p = strchr(p, ':');
	if ((scan > 23) || !p) {
		DEBUG("rlm_logintime: Bad Time-Of-Day value \"%s\"",
		      check->vp_strvalue);
		return -1;
	}
	when = scan * 3600;
	p++;

	scan = atoi(p);
	if (scan > 59) {
		DEBUG("rlm_logintime: Bad Time-Of-Day value \"%s\"",
		      check->vp_strvalue);
		return -1;
	}
	when += scan * 60;

	p = strchr(p, ':');
	if (p) {
		scan = atoi(p + 1);
		if (scan > 59) {
			DEBUG("rlm_logintime: Bad Time-Of-Day value \"%s\"",
			      check->vp_strvalue);
			return -1;
		}
		when += scan;
	}

	fprintf(stderr, "returning %d - %d\n",
		hhmmss, when);

	return hhmmss - when;
}

/*
 *      Check if account has expired, and if user may login now.
 */
static int logintime_authorize(void *instance, REQUEST *request)
{
	rlm_logintime_t *data = (rlm_logintime_t *)instance;
	VALUE_PAIR *check_item = NULL;
	int r;

	if ((check_item = pairfind(request->config_items, PW_LOGIN_TIME, 0)) != NULL) {

		/*
	 	 *      Authentication is OK. Now see if this
	 	 *      user may login at this time of the day.
	 	 */
		DEBUG("rlm_logintime: Checking Login-Time: '%s'",check_item->vp_strvalue);
		r = timestr_match((char *)check_item->vp_strvalue,
		request->timestamp);
		if (r == 0) {   /* unlimited */
			/*
		 	 *      Do nothing: login-time is OK.
		 	 */

		/*
	 	 *      Session-Timeout needs to be at least
	 	 *      60 seconds, some terminal servers
	 	 *      ignore smaller values.
	 	 */
			DEBUG("rlm_logintime: timestr returned unlimited");
		} else if (r < data->min_time) {
			char logstr[MAX_STRING_LEN];
			VALUE_PAIR *module_fmsg_vp;

			/*
		 	 *      User called outside allowed time interval.
		 	 */

			DEBUG("rlm_logintime: timestr returned reject");
			if (data->msg && data->msg[0]){
				char msg[MAX_STRING_LEN];
				VALUE_PAIR *tmp;

				if (!radius_xlat(msg, sizeof(msg), data->msg, request, NULL, NULL)) {
					radlog(L_ERR, "rlm_logintime: xlat failed.");
					return RLM_MODULE_FAIL;
				}
				pairfree(&request->reply->vps);
				tmp = pairmake("Reply-Message", msg, T_OP_SET);
				request->reply->vps = tmp;
			}

			snprintf(logstr, sizeof(logstr), "Outside allowed timespan (time allowed %s)",
			check_item->vp_strvalue);
			module_fmsg_vp = pairmake("Module-Failure-Message", logstr, T_OP_EQ);
			pairadd(&request->packet->vps, module_fmsg_vp);

			return RLM_MODULE_REJECT;

		} else if (r > 0) {
			VALUE_PAIR *reply_item;

			/*
		 	 *      User is allowed, but set Session-Timeout.
		 	 */
			DEBUG("rlm_logintime: timestr returned accept");
			if ((reply_item = pairfind(request->reply->vps, PW_SESSION_TIMEOUT, 0)) != NULL) {
				if (reply_item->vp_integer > (unsigned) r)
					reply_item->vp_integer = r;
			} else {
				reply_item = radius_paircreate(request,
							       &request->reply->vps,
							       PW_SESSION_TIMEOUT, 0,
							       PW_TYPE_INTEGER);
				reply_item->vp_integer = r;
			}
			DEBUG("rlm_logintime: Session-Timeout set to: %d",r);
		}
	}
	else
		return RLM_MODULE_NOOP;

	return RLM_MODULE_OK;
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
static int logintime_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_logintime_t *data;

	/*
	 *	Set up a storage area for instance data
	 */
	data = rad_malloc(sizeof(*data));
	if (!data) {
		radlog(L_ERR, "rlm_logintime: rad_malloc() failed.");
		return -1;
	}
	memset(data, 0, sizeof(*data));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, data, module_config) < 0) {
		free(data);
		radlog(L_ERR, "rlm_logintime: Configuration parsing failed.");
		return -1;
	}

	if (data->min_time == 0){
		radlog(L_ERR, "rlm_logintime: Minimum timeout should be non zero.");
		free(data);
		return -1;
	}

	/*
	 * Register a Current-Time comparison function
	 */
	paircompare_register(PW_CURRENT_TIME, 0, timecmp, data);
	paircompare_register(PW_TIME_OF_DAY, 0, time_of_day, data);

	*instance = data;

	return 0;
}

static int logintime_detach(void *instance)
{
	paircompare_unregister(PW_CURRENT_TIME, timecmp);
	paircompare_unregister(PW_TIME_OF_DAY, time_of_day);
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
module_t rlm_logintime = {
	RLM_MODULE_INIT,
	"logintime",
	RLM_TYPE_CHECK_CONFIG_SAFE,   	/* type */
	logintime_instantiate,		/* instantiation */
	logintime_detach,		/* detach */
	{
		NULL,			/* authentication */
		logintime_authorize, 	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};
