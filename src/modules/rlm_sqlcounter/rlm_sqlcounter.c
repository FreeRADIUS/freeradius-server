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

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>

#define MAX_QUERY_LEN 2048

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
	char const	*counter_name;  //!< Daily-Session-Time.
	char const	*limit_name;  	//!< Max-Daily-Session.
	char const	*reply_name;  	//!< Session-Timeout.
	char const	*key_name;  	//!< User-Name.
	char const	*sqlmod_inst;	//!< Instance of SQL module to use,
					//!< usually just 'sql'.
	char const	*query;		//!< SQL query to retrieve current
					//!< session time.
	char const	*reset;  	//!< Daily, weekly, monthly,
					//!< never or user defined.
	time_t		reset_time;
	time_t		last_reset;
	DICT_ATTR const	*key_attr;	//!< Attribute number for key field.
	DICT_ATTR const	*dict_attr;	//!< Attribute number for the counter.
	DICT_ATTR const	*reply_attr;	//!< Attribute number for the reply.
} rlm_sqlcounter_t;

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
	{ "sql-module-instance", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, rlm_sqlcounter_t, sqlmod_inst), NULL },
	{ "sql_module_instance", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_sqlcounter_t, sqlmod_inst), NULL },

	{ "key", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_ATTRIBUTE, rlm_sqlcounter_t, key_name), NULL },
	{ "query", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_XLAT | PW_TYPE_REQUIRED, rlm_sqlcounter_t, query), NULL },
	{ "reset", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_sqlcounter_t, reset), NULL },

	{ "counter-name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, rlm_sqlcounter_t, counter_name), NULL },
	{ "counter_name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_sqlcounter_t, counter_name), NULL },

	{ "check-name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, rlm_sqlcounter_t, limit_name), NULL },
	{ "check_name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, rlm_sqlcounter_t, limit_name), NULL },

	{ "reply-name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, rlm_sqlcounter_t, reply_name), NULL },
	{ "reply_name", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_ATTRIBUTE, rlm_sqlcounter_t, reply_name), "Session-Timeout" },
	CONF_PARSER_TERMINATOR
};

static int find_next_reset(rlm_sqlcounter_t *inst, REQUEST *request, time_t timeval)
{
	int ret = 0;
	size_t len;
	unsigned int num = 1;
	char last = '\0';
	struct tm *tm, s_tm;
	char sCurrentTime[40], sNextTime[40];

	tm = localtime_r(&timeval, &s_tm);
	tm->tm_sec = tm->tm_min = 0;

	rad_assert(inst->reset != NULL);

	/*
	 *	Reset every N hours, days, weeks, months.
	 */
	if (isdigit((int) inst->reset[0])){
		len = strlen(inst->reset);
		if (len == 0) return -1;

		last = inst->reset[len - 1];
		if (!isalpha((int) last)) {
			last = 'd';
		}

		num = atoi(inst->reset);
		DEBUG("rlm_sqlcounter: num=%d, last=%c",num,last);
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

	if (!request || (rad_debug_lvl < 2)) return ret;

	len = strftime(sCurrentTime, sizeof(sCurrentTime), "%Y-%m-%d %H:%M:%S", tm);
	if (len == 0) *sCurrentTime = '\0';

	len = strftime(sNextTime, sizeof(sNextTime),"%Y-%m-%d %H:%M:%S",tm);
	if (len == 0) *sNextTime = '\0';
	RDEBUG2("rlm_sqlcounter: Current Time: %" PRId64 " [%s], Next reset %" PRId64 " [%s]",
		(int64_t) timeval, sCurrentTime, (int64_t) inst->reset_time, sNextTime);

	return ret;
}


/*  I don't believe that this routine handles Daylight Saving Time adjustments
    properly.  Any suggestions?
*/

static int find_prev_reset(rlm_sqlcounter_t *inst, time_t timeval)
{
	int ret = 0;
	size_t len;
	unsigned int num = 1;
	char last = '\0';
	struct tm *tm, s_tm;
	char sCurrentTime[40], sPrevTime[40];

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
		DEBUG("rlm_sqlcounter: num=%d, last=%c",num,last);
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
	DEBUG2("rlm_sqlcounter: Current Time: %" PRId64 " [%s], Prev reset %" PRId64 " [%s]",
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

static size_t sqlcounter_expand(char *out, int outlen, char const *fmt, rlm_sqlcounter_t *inst)
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
				WARN("Please replace '%%k' with '${key}'");
				strlcpy(q, inst->key_name, freespace);
				q += strlen(q);
				p++;
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
static int sqlcounter_cmp(void *instance, REQUEST *request, UNUSED VALUE_PAIR *req , VALUE_PAIR *check,
			  UNUSED VALUE_PAIR *check_pairs, UNUSED VALUE_PAIR **reply_pairs)
{
	rlm_sqlcounter_t *inst = instance;
	uint64_t counter;

	char query[MAX_QUERY_LEN], subst[MAX_QUERY_LEN];
	char *expanded = NULL;
	size_t len;

	/* First, expand %k, %b and %e in query */
	if (sqlcounter_expand(subst, sizeof(subst), inst->query, inst) <= 0) {
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
	if (radius_axlat(&expanded, request, query, NULL, NULL) < 0) {
		return RLM_MODULE_FAIL;
	}

	if (sscanf(expanded, "%" PRIu64, &counter) != 1) {
		RDEBUG2("No integer found in string \"%s\"", expanded);
	}
	talloc_free(expanded);

	if (counter < check->vp_integer64) {
		return -1;
	}
	if (counter > check->vp_integer64) {
		return 1;
	}
	return 0;
}

static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_sqlcounter_t *inst = instance;
	DICT_ATTR const *da;
	ATTR_FLAGS flags;

	memset(&flags, 0, sizeof(flags));
	flags.compare = 1;	/* ugly hack */
	da = dict_attrbyname(inst->counter_name);
	if (da && (da->type != PW_TYPE_INTEGER64)) {
		cf_log_err_cs(conf, "Counter attribute %s MUST be integer64", inst->counter_name);
		return -1;
	}

	if (!da && (dict_addattr(inst->counter_name, -1, 0, PW_TYPE_INTEGER64, flags) < 0)) {
		cf_log_err_cs(conf, "Failed to create counter attribute %s: %s", inst->counter_name, fr_strerror());
		return -1;
	}

	/*
	 *  Register the counter comparison operation.
	 */
	if (paircompare_register_byname(inst->counter_name, NULL, true, sqlcounter_cmp, inst) < 0) {
		cf_log_err_cs(conf, "Failed registering counter attribute %s: %s", inst->counter_name, fr_strerror());
		return -1;
	}

	inst->dict_attr = dict_attrbyname(inst->counter_name);
	if (!inst->dict_attr) {
		cf_log_err_cs(conf, "Failed to find counter attribute %s", inst->counter_name);
		return -1;
	}

	/*
	 *  Create a new attribute for the check item.
	 */
	flags.compare = 0;
	if ((dict_addattr(inst->limit_name, -1, 0, PW_TYPE_INTEGER64, flags) < 0) ||
	    !dict_attrbyname(inst->limit_name)) {
		cf_log_err_cs(conf, "Failed to create check attribute %s: %s", inst->limit_name, fr_strerror());
		return -1;
	}

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
	rlm_sqlcounter_t *inst = instance;
	DICT_ATTR const *da;
	time_t now;

	rad_assert(inst->query && *inst->query);

	da = dict_attrbyname(inst->key_name);
	if (!da) {
		cf_log_err_cs(conf, "Invalid attribute '%s'", inst->key_name);
		return -1;
	}
	inst->key_attr = da;

	da = dict_attrbyname(inst->reply_name);
	if (!da) {
		cf_log_err_cs(conf, "Invalid attribute '%s'", inst->reply_name);
		return -1;
	}
	inst->reply_attr = da;

	now = time(NULL);
	inst->reset_time = 0;

	if (find_next_reset(inst, NULL, now) < 0) {
		cf_log_err_cs(conf, "Invalid reset '%s'", inst->reset);
		return -1;
	}

	/*
	 *  Discover the beginning of the current time period.
	 */
	inst->last_reset = 0;

	if (find_prev_reset(inst, now) < 0) {
		cf_log_err_cs(conf, "Invalid reset '%s'", inst->reset);
		return -1;
	}

	return 0;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
	rlm_sqlcounter_t *inst = instance;
	int rcode = RLM_MODULE_NOOP;
	uint64_t counter, res;
	DICT_ATTR const *da;
	VALUE_PAIR *key_vp, *limit;
	VALUE_PAIR *reply_item;
	char msg[128];

	char query[MAX_QUERY_LEN], subst[MAX_QUERY_LEN];
	char *expanded = NULL;

	size_t len;

	/*
	 *	Before doing anything else, see if we have to reset
	 *	the counters.
	 */
	if (inst->reset_time && (inst->reset_time <= request->timestamp)) {
		/*
		 *	Re-set the next time and prev_time for this counters range
		 */
		inst->last_reset = inst->reset_time;
		find_next_reset(inst, request, request->timestamp);
	}

	/*
	 *      Look for the key.  User-Name is special.  It means
	 *      The REAL username, after stripping.
	 */
	if ((inst->key_attr->vendor == 0) && (inst->key_attr->attr == PW_USER_NAME)) {
		key_vp = request->username;
	} else {
		key_vp = fr_pair_find_by_da(request->packet->vps, inst->key_attr, TAG_ANY);
	}
	if (!key_vp) {
		RWDEBUG2("Couldn't find key attribute, request:%s, doing nothing...", inst->key_attr->name);
		return rcode;
	}

	/*
	 *      Look for the check item
	 */
	if ((da = dict_attrbyname(inst->limit_name)) == NULL) {
		return rcode;
	}

	limit = fr_pair_find_by_da(request->config, da, TAG_ANY);
	if (limit == NULL) {
		/* Yes this really is 'check' as distinct from control */
		RWDEBUG2("Couldn't find check attribute, control:%s, doing nothing...", inst->limit_name);
		return rcode;
	}

	/* First, expand %k, %b and %e in query */
	if (sqlcounter_expand(subst, sizeof(subst), inst->query, inst) <= 0) {
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
	if (radius_axlat(&expanded, request, query, NULL, NULL) < 0) {
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
	if (limit->vp_integer64 <= counter) {
		/* User is denied access, send back a reply message */
		snprintf(msg, sizeof(msg), "Your maximum %s usage time has been reached", inst->reset);
		pair_make_reply("Reply-Message", msg, T_OP_EQ);

		REDEBUG2("Maximum %s usage time reached", inst->reset);
		REDEBUG2("Rejecting user, &control:%s value (%" PRIu64 ") is less than counter value (%" PRIu64 ")",
			 inst->limit_name, limit->vp_integer64, counter);

		return RLM_MODULE_REJECT;
	}

	res = limit->vp_integer64 - counter;
	RDEBUG2("Allowing user, &control:%s value (%" PRIu64 ") is greater than counter value (%" PRIu64 ")",
		inst->limit_name, limit->vp_integer64, counter);
	/*
	 *	We are assuming that simultaneous-use=1. But
	 *	even if that does not happen then our user
	 *	could login at max for 2*max-usage-time Is
	 *	that acceptable?
	 */

	/*
	 *	If we are near a reset then add the next
	 *	limit, so that the user will not need to login
	 *	again.  Do this only for Session-Timeout.
	 */
	if (((inst->reply_attr->vendor == 0) && (inst->reply_attr->attr == PW_SESSION_TIMEOUT)) &&
	    inst->reset_time && (res >= (uint64_t)(inst->reset_time - request->timestamp))) {
	    	uint64_t to_reset = inst->reset_time - request->timestamp;

		RDEBUG2("Time remaining (%" PRIu64 "s) is greater than time to reset (%" PRIu64 "s).  "
			"Adding %" PRIu64 "s to reply value", to_reset, res, to_reset);
		res = to_reset + limit->vp_integer;
	}

	/*
	 *	Limit the reply attribute to the minimum of the existing value, or this new one.
	 */
	reply_item = fr_pair_find_by_da(request->reply->vps, inst->reply_attr, TAG_ANY);
	if (reply_item) {
		if (reply_item->vp_integer64 <= res) {
			RDEBUG2("Leaving existing &reply:%s value of %" PRIu64, inst->reply_attr->name,
				reply_item->vp_integer64);

			return RLM_MODULE_OK;
		}
	} else {
		reply_item = radius_pair_create(request->reply, &request->reply->vps, inst->reply_attr->attr,
					       inst->reply_attr->vendor);
	}
	reply_item->vp_integer64 = res;

	RDEBUG2("Setting &reply:%s value to %" PRIu64, inst->reply_name, reply_item->vp_integer64);

	return RLM_MODULE_OK;
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
extern module_t rlm_sqlcounter;
module_t rlm_sqlcounter = {
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

