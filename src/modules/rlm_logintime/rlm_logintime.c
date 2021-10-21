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
 * @file rlm_logintime.c
 * @brief Allow login only during a given timeslot.
 *
 * @copyright 2001,2006 The FreeRADIUS server project
 * @copyright 2004 Kostas Kalevras (kkalev@noc.ntua.gr)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>

#include <ctype.h>

/* timestr.c */
int timestr_match(fr_time_delta_t *out, char const *tmstr, fr_time_t when);

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct {
	fr_time_delta_t	min_time;
} rlm_logintime_t;

static const CONF_PARSER module_config[] = {
  { FR_CONF_OFFSET("minimum_timeout", FR_TYPE_TIME_DELTA, rlm_logintime_t, min_time), .dflt = "60s" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_logintime_dict[];
fr_dict_autoload_t rlm_logintime_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_current_time;
static fr_dict_attr_t const *attr_login_time;
static fr_dict_attr_t const *attr_time_of_day;

static fr_dict_attr_t const *attr_session_timeout;

extern fr_dict_attr_autoload_t rlm_logintime_dict_attr[];
fr_dict_attr_autoload_t rlm_logintime_dict_attr[] = {
	{ .out = &attr_current_time, .name = "Current-Time", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_login_time, .name = "Login-Time", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_time_of_day, .name = "Time-Of-Day", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_session_timeout, .name = "Session-Timeout", .type = FR_TYPE_UINT32, .dict = &dict_radius },

	{ NULL }
};

/*
 *      Compare the current time to a range.
 */
static int timecmp(UNUSED void *instance, request_t *request, UNUSED fr_pair_list_t *request_list, fr_pair_t const *check)
{
	fr_time_delta_t left;

	if (timestr_match(&left, check->vp_strvalue, request->packet->timestamp) < 0) return -1;

	/*
	 *	0 is a special case meaning "allowed".
	 */
	if (fr_time_delta_gteq(left, fr_time_delta_wrap(0))) return 0;

	return -1;
}


/*
 *	Time-Of-Day support
 */
static int time_of_day(UNUSED void *instance, request_t *request,
		       UNUSED fr_pair_list_t *request_list, fr_pair_t const *check)
{
	int		scan;
	int		hhmmss, when;
	char const	*p;
	struct tm	*tm, s_tm;
	time_t		now;

	if (strspn(check->vp_strvalue, "0123456789: ") != strlen(check->vp_strvalue)) {
		RDEBUG2("Bad Time-Of-Day value \"%pV\"", &check->data);
		return -1;
	}

	now = fr_time_to_sec(request->packet->timestamp);
	tm = localtime_r(&now, &s_tm);
	hhmmss = (tm->tm_hour * 3600) + (tm->tm_min * 60) + tm->tm_sec;

	/*
	 *	Time of day is a 24-hour clock
	 */
	p = check->vp_strvalue;
	scan = atoi(p);
	p = strchr(p, ':');
	if ((scan > 23) || !p) {
		RDEBUG2("Bad Time-Of-Day value \"%pV\"", &check->data);
		return -1;
	}
	when = scan * 3600;
	p++;

	scan = atoi(p);
	if (scan > 59) {
		RDEBUG2("Bad Time-Of-Day value \"%pV\"", &check->data);
		return -1;
	}
	when += scan * 60;

	p = strchr(p, ':');
	if (p) {
		scan = atoi(p + 1);
		if (scan > 59) {
			RDEBUG2("Bad Time-Of-Day value \"%pV\"", &check->data);
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
static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_logintime_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_logintime_t);
	fr_pair_t		*ends, *vp;
	fr_time_delta_t		left;

	ends = fr_pair_find_by_da(&request->control_pairs, attr_login_time, 0);
	if (!ends) RETURN_MODULE_NOOP;

	/*
	 *      Authentication is OK. Now see if this user may login at this time of the day.
	 */
	RDEBUG2("Checking Login-Time");

	/*
	 *	Compare the time the request was received with the current Login-Time value
	 */
	if (timestr_match(&left, ends->vp_strvalue, request->packet->timestamp) < 0) {
		RETURN_MODULE_DISALLOW; /* outside of the allowed time */
	}

	/*
	 *      Do nothing, login time is not controlled (unended).
	 */
	if (fr_time_delta_eq(left, fr_time_delta_wrap(0))) RETURN_MODULE_OK;

	/*
	 *      The min_time setting is to deal with NAS that won't allow Session-vp values below a certain value
	 *	For example some Alcatel Lucent products won't allow a Session-vp < 300 (5 minutes).
	 *
	 *	We don't know were going to get another chance to lock out the user, so we need to do it now.
	 */
	if (fr_time_delta_lt(left, inst->min_time)) {
		REDEBUG("Login outside of allowed time-slot (session end %s, with lockout %i seconds before)",
			ends->vp_strvalue, (int) fr_time_delta_to_sec(inst->min_time));

		RETURN_MODULE_DISALLOW;
	}

	/* else left > inst->min_time */

	/*
	 *	There's time left in the users session, inform the NAS by including a Session-Timeout
	 *	attribute in the reply, or modifying the existing one.
	 */
	RDEBUG2("Login within allowed time-slot, %d seconds left in this session", (int) fr_time_delta_to_sec(left));

	switch (pair_update_reply(&vp, attr_session_timeout)) {
	case 1:
		/* just update... */
		if (vp->vp_uint32 > fr_time_delta_to_sec(left)) {
			vp->vp_uint32 = fr_time_delta_to_sec(left);
			RDEBUG2("&reply.Session-Timeout := %pV", &vp->data);
		}
		break;

	case 0:	/* no pre-existing */
		vp->vp_uint32 = fr_time_delta_to_sec(left);
		RDEBUG2("&reply.Session-Timeout := %pV", &vp->data);
		break;

	case -1: /* malloc failure */
		MEM(NULL);
	}

	RETURN_MODULE_OK;
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
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_logintime_t *inst = instance;

	if (!fr_time_delta_ispos(inst->min_time)) {
		cf_log_err(conf, "Invalid value '0' for minimum_timeout");
		return -1;
	}

	/*
	 * Register a Current-Time comparison function
	 */
	paircmp_register(attr_current_time, NULL, true, timecmp, inst);
	paircmp_register(attr_time_of_day, NULL, true, time_of_day, inst);

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
extern module_t rlm_logintime;
module_t rlm_logintime = {
	.magic		= RLM_MODULE_INIT,
	.name		= "logintime",
	.inst_size	= sizeof(rlm_logintime_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_POST_AUTH]		= mod_authorize
	},
};
