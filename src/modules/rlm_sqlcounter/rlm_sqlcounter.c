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
 * @file rlm_sqlcounter.c
 * @brief Tracks data usage and other counters using SQL.
 *
 * @copyright 2001,2006  The FreeRADIUS server project
 * @copyright 2001  Alan DeKok <aland@ox.org>
 */
RCSID("$Id$")

#define LOG_PREFIX "rlm_sqlcounter - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/server/rad_assert.h>

#include <ctype.h>

#define MAX_QUERY_LEN 1024

/*
 *	Note: When your counter spans more than 1 period (ie 3 months
 *	or 2 weeks), this module probably does NOT do what you want! It
 *	calculates the range of dates to count across by first calculating
 *	the End of the Current period and then subtracting the number of
 *	periods you specify from that to determine the beginning of the
 *	range.
 *
 *	For example, if you specify a 3 month counter and today is June 15th,
 *	the end of the current period is June 30. Subtracting 3 months from
 *	that gives April 1st. So, the counter will sum radacct entries from
 *	April 1st to June 30. Then, next month, it will sum entries from
 *	May 1st to July 31st.
 *
 *	To fix this behavior, we need to add some way of storing the Next
 *	Reset Time.
 */

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_sqlcounter_t {
	vp_tmpl_t	*paircmp_attr;	//!< Daily-Session-Time.
	vp_tmpl_t	*limit_attr;  	//!< Max-Daily-Session.
	vp_tmpl_t	*reply_attr;  	//!< Session-Timeout.
	vp_tmpl_t	*key_attr;  	//!< User-Name

	char const	*sqlmod_inst;	//!< Instance of SQL module to use, usually just 'sql'.
	char const	*query;		//!< SQL query to retrieve current session time.
	char const	*reset;  	//!< Daily, weekly, monthly, never or user defined.

	time_t		reset_time;
	time_t		last_reset;
} rlm_sqlcounter_t;

static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("sql_module_instance", FR_TYPE_STRING | FR_TYPE_REQUIRED, rlm_sqlcounter_t, sqlmod_inst) },


	{ FR_CONF_OFFSET("query", FR_TYPE_STRING | FR_TYPE_XLAT | FR_TYPE_REQUIRED, rlm_sqlcounter_t, query) },
	{ FR_CONF_OFFSET("reset", FR_TYPE_STRING | FR_TYPE_REQUIRED, rlm_sqlcounter_t, reset) },

	{ FR_CONF_OFFSET("key", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE, rlm_sqlcounter_t, key_attr), .dflt = "&request:User-Name", .quote = T_BARE_WORD },

	/* Just used to register a paircmp against */
	{ FR_CONF_OFFSET("counter_name", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE | FR_TYPE_REQUIRED, rlm_sqlcounter_t, paircmp_attr) },
	{ FR_CONF_OFFSET("check_name", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE | FR_TYPE_REQUIRED, rlm_sqlcounter_t, limit_attr) },

	/* Attribute to write remaining session to */
	{ FR_CONF_OFFSET("reply_name", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE, rlm_sqlcounter_t, reply_attr) },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;

extern fr_dict_autoload_t rlm_sqlcounter_dict[];
fr_dict_autoload_t rlm_sqlcounter_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_reply_message;
static fr_dict_attr_t const *attr_session_timeout;

extern fr_dict_attr_autoload_t rlm_sqlcounter_dict_attr[];
fr_dict_attr_autoload_t rlm_sqlcounter_dict_attr[] = {
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_reply_message, .name = "Reply-Message", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_session_timeout, .name = "Session-Timeout", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ NULL }
};

static int find_next_reset(rlm_sqlcounter_t *inst, time_t timeval)
{
	int		ret = 0;
	size_t		len;
	unsigned int	num = 1;
	char		last = '\0';
	struct tm	*tm, s_tm;
	char		sCurrentTime[40], sNextTime[40];

	tm = localtime_r(&timeval, &s_tm);
	len = strftime(sCurrentTime, sizeof(sCurrentTime), "%Y-%m-%d %H:%M:%S", tm);
	if (len == 0) *sCurrentTime = '\0';
	tm->tm_sec = tm->tm_min = 0;

	rad_assert(inst->reset != NULL);

	if (isdigit((int) inst->reset[0])){
		len = strlen(inst->reset);
		if (len == 0)
			return -1;
		last = inst->reset[len - 1];
		if (!isalpha((int) last))
			last = 'd';
		num = atoi(inst->reset);
		DEBUG("num=%d, last=%c",num,last);
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
		return -1;
	}

	len = strftime(sNextTime, sizeof(sNextTime),"%Y-%m-%d %H:%M:%S",tm);
	if (len == 0) *sNextTime = '\0';
	DEBUG2("Current Time: %" PRId64 " [%s], Next reset %" PRId64 " [%s]",
	       (int64_t) timeval, sCurrentTime, (int64_t) inst->reset_time, sNextTime);

	return ret;
}


/*  I don't believe that this routine handles Daylight Saving Time adjustments
    properly.  Any suggestions?
*/
static int find_prev_reset(rlm_sqlcounter_t *inst, time_t timeval)
{
	int		ret = 0;
	size_t		len;
	unsigned	int num = 1;
	char		last = '\0';
	struct		tm *tm, s_tm;
	char		sCurrentTime[40], sPrevTime[40];

	tm = localtime_r(&timeval, &s_tm);
	len = strftime(sCurrentTime, sizeof(sCurrentTime), "%Y-%m-%d %H:%M:%S", tm);
	if (len == 0) *sCurrentTime = '\0';
	tm->tm_sec = tm->tm_min = 0;

	rad_assert(inst->reset != NULL);

	if (isdigit((int) inst->reset[0])){
		len = strlen(inst->reset);
		if (len == 0)
			return -1;
		last = inst->reset[len - 1];
		if (!isalpha((int) last))
			last = 'd';
		num = atoi(inst->reset);
		DEBUG("num=%d, last=%c",num,last);
	}
	if (strcmp(inst->reset, "hourly") == 0 || last == 'h') {
		/*
		 *  Round down to the prev nearest hour.
		 */
		tm->tm_hour -= num - 1;
		inst->last_reset = mktime(tm);
	} else if (strcmp(inst->reset, "daily") == 0 || last == 'd') {
		/*
		 *  Round down to the prev nearest day.
		 */
		tm->tm_hour = 0;
		tm->tm_mday -= num - 1;
		inst->last_reset = mktime(tm);
	} else if (strcmp(inst->reset, "weekly") == 0 || last == 'w') {
		/*
		 *  Round down to the prev nearest week.
		 */
		tm->tm_hour = 0;
		tm->tm_mday -= tm->tm_wday +(7*(num-1));
		inst->last_reset = mktime(tm);
	} else if (strcmp(inst->reset, "monthly") == 0 || last == 'm') {
		tm->tm_hour = 0;
		tm->tm_mday = 1;
		tm->tm_mon -= num - 1;
		inst->last_reset = mktime(tm);
	} else if (strcmp(inst->reset, "never") == 0) {
		inst->reset_time = 0;
	} else {
		return -1;
	}
	len = strftime(sPrevTime, sizeof(sPrevTime), "%Y-%m-%d %H:%M:%S", tm);
	if (len == 0) *sPrevTime = '\0';
	DEBUG2("Current Time: %" PRId64 " [%s], Prev reset %" PRId64 " [%s]",
	       (int64_t) timeval, sCurrentTime, (int64_t) inst->last_reset, sPrevTime);

	return ret;
}


/*
 *	Replace %<whatever> in a string.
 *
 *	%b	last_reset
 *	%e	reset_time
 *	%k	key_name
 *	%S	sqlmod_inst
 *
 */
static size_t sqlcounter_expand(char *out, int outlen, rlm_sqlcounter_t const *inst, REQUEST *request, char const *fmt)
{
	int freespace;
	char const *p;
	char *q;
	char tmpdt[40]; /* For temporary storing of dates */

	q = out;
	p = fmt;
	while (*p) {
		/* Calculate freespace in output */
		freespace = outlen - (q - out);
		if (freespace <= 1) {
			return -1;
		}

		/*
		 *	Non-% get copied as-is.
		 */
		if (*p != '%') {
			*q++ = *p++;
			continue;
		}
		p++;
		if (!*p) {	/* % and then EOS --> % */
			*q++ = '%';
			break;
		}

		if (freespace <= 2) return -1;

		/*
		 *	We need TWO %% in a row before we do our expansions.
		 *	If we only get one, just copy the %s as-is.
		 */
		if (*p != '%') {
			*q++ = '%';
			*q++ = *p++;
			continue;
		}
		p++;
		if (!*p) {
			*q++ = '%';
			*q++ = '%';
			break;
		}

		if (freespace <= 3) return -1;

		switch (*p) {
			case 'b': /* last_reset */
				snprintf(tmpdt, sizeof(tmpdt), "%" PRId64, (int64_t) inst->last_reset);
				strlcpy(q, tmpdt, freespace);
				q += strlen(q);
				p++;
				break;
			case 'e': /* reset_time */
				snprintf(tmpdt, sizeof(tmpdt), "%" PRId64, (int64_t) inst->reset_time);
				strlcpy(q, tmpdt, freespace);
				q += strlen(q);
				p++;
				break;

			case 'k': /* Key Name */
			{
				VALUE_PAIR *vp;

				WARN("Please replace '%%k' with '%%{${key}}'");
				tmpl_find_vp(&vp, request, inst->key_attr);
				if (vp) {
					fr_pair_value_snprint(q, freespace, vp, '"');
					q += strlen(q);
				}
				p++;
			}
				break;

				/*
				 *	%%s gets copied over as-is.
				 */
			default:
				*q++ = '%';
				*q++ = '%';
				*q++ = *p++;
				break;
		}
	}
	*q = '\0';

	DEBUG2("sqlcounter_expand: '%s'", out);

	return strlen(out);
}


/*
 *	See if the counter matches.
 */
static int counter_cmp(void *instance, REQUEST *request, UNUSED VALUE_PAIR *req , VALUE_PAIR *check,
		       UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	rlm_sqlcounter_t const *inst = instance;
	uint64_t counter;

	char query[MAX_QUERY_LEN], subst[MAX_QUERY_LEN];
	char *expanded = NULL;
	size_t len;

	/* First, expand %k, %b and %e in query */
	if (sqlcounter_expand(subst, sizeof(subst), inst, request, inst->query) <= 0) {
		REDEBUG("Insufficient query buffer space");

		return RLM_MODULE_FAIL;
	}

	/* Then combine that with the name of the module were using to do the query */
	len = snprintf(query, sizeof(query), "%%{%s:%s}", inst->sqlmod_inst, subst);
	if (len >= sizeof(query) - 1) {
		REDEBUG("Insufficient query buffer space");

		return RLM_MODULE_FAIL;
	}

	/* Finally, xlat resulting SQL query */
	if (xlat_aeval(request, &expanded, request, query, NULL, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	if (sscanf(expanded, "%" PRIu64, &counter) != 1) {
		RDEBUG2("No integer found in string \"%s\"", expanded);
	}
	talloc_free(expanded);

	if (counter < check->vp_uint64) return -1;
	if (counter > check->vp_uint64) return 1;
	return 0;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_sqlcounter_t	*inst = instance;
	uint64_t		counter, res;
	VALUE_PAIR		*key_vp, *limit;
	VALUE_PAIR		*reply_item;
	char			msg[128];
	int			ret;

	char query[MAX_QUERY_LEN], subst[MAX_QUERY_LEN];
	char *expanded = NULL;

	size_t len;

	/*
	 *	Before doing anything else, see if we have to reset
	 *	the counters.
	 */
	if (inst->reset_time && (inst->reset_time <= request->packet->timestamp.tv_sec)) {
		/*
		 *	Re-set the next time and prev_time for this counters range
		 */
		inst->last_reset = inst->reset_time;
		find_next_reset(inst,request->packet->timestamp.tv_sec);
	}

	/*
	 *      Look for the key.  User-Name is special.  It means
	 *      The REAL username, after stripping.
	 */
	if ((inst->key_attr->tmpl_list == PAIR_LIST_REQUEST) &&
	    (inst->key_attr->tmpl_da == attr_user_name)) {
		key_vp = request->username;
	} else {
		tmpl_find_vp(&key_vp, request, inst->key_attr);
	}
	if (!key_vp) {
		RWDEBUG2("Couldn't find key attribute, %s, doing nothing...", inst->key_attr->tmpl_da->name);
		return RLM_MODULE_NOOP;
	}

	if (tmpl_find_vp(&limit, request, inst->limit_attr) < 0) {
		RWDEBUG2("Couldn't find limit attribute, %s, doing nothing...", inst->limit_attr->name);
		return RLM_MODULE_NOOP;
	}

	/* First, expand %k, %b and %e in query */
	if (sqlcounter_expand(subst, sizeof(subst), inst, request, inst->query) <= 0) {
		REDEBUG("Insufficient query buffer space");

		return RLM_MODULE_FAIL;
	}

	/* Then combine that with the name of the module were using to do the query */
	len = snprintf(query, sizeof(query), "%%{%s:%s}", inst->sqlmod_inst, subst);
	if (len >= (sizeof(query) - 1)) {
		REDEBUG("Insufficient query buffer space");

		return RLM_MODULE_FAIL;
	}

	/* Finally, xlat resulting SQL query */
	if (xlat_aeval(request, &expanded, request, query, NULL, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}
	talloc_free(expanded);

	if (sscanf(expanded, "%" PRIu64, &counter) != 1) {
		RDEBUG2("No integer found in result string \"%s\".  May be first session, setting counter to 0",
			expanded);
		counter = 0;
	}

	/*
	 *	Check if check item > counter
	 */
	if (limit->vp_uint64 <= counter) {
		VALUE_PAIR *vp;

		/* User is denied access, send back a reply message */
		snprintf(msg, sizeof(msg), "Your maximum %s usage time has been reached", inst->reset);

		MEM(pair_update_reply(&vp, attr_reply_message) >= 0);
		fr_pair_value_strcpy(vp, msg);

		REDEBUG2("Maximum %s usage time reached", inst->reset);
		REDEBUG2("Rejecting user, %s value (%" PRIu64 ") is less than counter value (%" PRIu64 ")",
			 inst->limit_attr->name, limit->vp_uint64, counter);

		return RLM_MODULE_REJECT;
	}

	res = limit->vp_uint64 - counter;
	RDEBUG2("Allowing user, %s value (%" PRIu64 ") is greater than counter value (%" PRIu64 ")",
		inst->limit_attr->name, limit->vp_uint64, counter);

	/*
	 *	We are assuming that simultaneous-use=1. But
	 *	even if that does not happen then our user
	 *	could login at max for 2*max-usage-time Is
	 *	that acceptable?
	 */
	if (inst->reply_attr) {
		/*
		 *	If we are near a reset then add the next
		 *	limit, so that the user will not need to login
		 *	again.  Do this only for Session-Timeout.
		 */
		if ((inst->reply_attr->tmpl_da == attr_session_timeout) &&
		    inst->reset_time && (res >= (uint64_t)(inst->reset_time - request->packet->timestamp.tv_sec))) {
			uint64_t to_reset = inst->reset_time - request->packet->timestamp.tv_sec;

			RDEBUG2("Time remaining (%" PRIu64 "s) is greater than time to reset (%" PRIu64 "s).  "
				"Adding %" PRIu64 "s to reply value", to_reset, res, to_reset);
			res = to_reset + limit->vp_uint32;
		}

		/*
		 *	Limit the reply attribute to the minimum of the existing value, or this new one.
		 */
		ret = tmpl_find_or_add_vp(&reply_item, request, inst->reply_attr);
		switch (ret) {
		case 1:		/* new */
			break;

		case 0:		/* found */
			if (reply_item->vp_uint64 <= res) {
				RDEBUG2("Leaving existing %s value of %" PRIu64, inst->reply_attr->name,
					reply_item->vp_uint64);
				return RLM_MODULE_OK;
			}
			break;

		case -1:	/* alloc failed */
			REDEBUG("Error allocating attribute %s", inst->reply_attr->name);
			return RLM_MODULE_FAIL;

		default:	/* request or list unavailable */
			RDEBUG2("List or request context not available for %s, skipping...", inst->reply_attr->name);
			return RLM_MODULE_OK;
		}
		reply_item->vp_uint64 = res;
		RDEBUG2("&%pP", reply_item);

		return RLM_MODULE_UPDATED;
	}

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
static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_sqlcounter_t	*inst = instance;
	time_t			now;

	rad_assert(inst->query && *inst->query);

	now = time(NULL);
	inst->reset_time = 0;

	if (find_next_reset(inst, now) == -1) {
		cf_log_err(conf, "Invalid reset '%s'", inst->reset);
		return -1;
	}

	/*
	 *  Discover the beginning of the current time period.
	 */
	inst->last_reset = 0;

	if (find_prev_reset(inst, now) < 0) {
		cf_log_err(conf, "Invalid reset '%s'", inst->reset);
		return -1;
	}

	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_sqlcounter_t		*inst = instance;
	fr_dict_attr_flags_t		flags;

	/*
	 *	Create a new attribute for the counter.
	 */
	rad_assert(inst->paircmp_attr);
	rad_assert(inst->limit_attr);

	memset(&flags, 0, sizeof(flags));
	flags.compare = 1;	/* ugly hack */
	if (tmpl_define_undefined_attr(dict_freeradius, inst->paircmp_attr, FR_TYPE_UINT64, &flags) < 0) {
		cf_log_perr(conf, "Failed defining counter attribute");
		return -1;
	}

	flags.compare = 0;
	if (tmpl_define_undefined_attr(dict_freeradius, inst->limit_attr, FR_TYPE_UINT64, &flags) < 0) {
		cf_log_perr(conf, "Failed defining check attribute");
		return -1;
	}

	if (inst->paircmp_attr->tmpl_da->type != FR_TYPE_UINT64) {
		cf_log_err(conf, "Counter attribute %s MUST be uint64", inst->paircmp_attr->tmpl_da->name);
		return -1;
	}
	if (paircmp_register_by_name(inst->paircmp_attr->tmpl_da->name, NULL, true,
					counter_cmp, inst) < 0) {
		cf_log_perr(conf, "Failed registering comparison function for counter attribute %s",
			    inst->paircmp_attr->tmpl_da->name);
		return -1;
	}

	if (inst->limit_attr->tmpl_da->type != FR_TYPE_UINT64) {
		cf_log_err(conf, "Check attribute %s MUST be uint64", inst->limit_attr->tmpl_da->name);
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
extern rad_module_t rlm_sqlcounter;
rad_module_t rlm_sqlcounter = {
	.magic		= RLM_MODULE_INIT,
	.name		= "sqlcounter",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_sqlcounter_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize
	},
};

