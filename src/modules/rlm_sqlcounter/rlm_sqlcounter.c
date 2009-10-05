/*
 * rlm_sqlcounter.c
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
 */

/* This module is based directly on the rlm_counter module */


#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <ctype.h>

#define MAX_QUERY_LEN 1024

static int sqlcounter_detach(void *instance);

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
	char *counter_name;  	/* Daily-Session-Time */
	char *check_name;  	/* Max-Daily-Session */
	char *reply_name;  	/* Session-Timeout */
	char *key_name;  	/* User-Name */
	char *sqlmod_inst;	/* instance of SQL module to use, usually just 'sql' */
	char *query;		/* SQL query to retrieve current session time */
	char *reset;  		/* daily, weekly, monthly, never or user defined */
	char *allowed_chars;	/* safe characters list for SQL queries */
	time_t reset_time;
	time_t last_reset;
	DICT_ATTR *key_attr;		/* attribute number for key field */
	DICT_ATTR *dict_attr;		/* attribute number for the counter. */
	DICT_ATTR *reply_attr;	/* attribute number for the reply */
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
  { "counter-name", PW_TYPE_STRING_PTR, offsetof(rlm_sqlcounter_t,counter_name), NULL,  NULL },
  { "check-name", PW_TYPE_STRING_PTR, offsetof(rlm_sqlcounter_t,check_name), NULL, NULL },
  { "reply-name", PW_TYPE_STRING_PTR, offsetof(rlm_sqlcounter_t,reply_name), NULL, NULL },
  { "key", PW_TYPE_STRING_PTR, offsetof(rlm_sqlcounter_t,key_name), NULL, NULL },
  { "sqlmod-inst", PW_TYPE_STRING_PTR, offsetof(rlm_sqlcounter_t,sqlmod_inst), NULL, NULL },
  { "query", PW_TYPE_STRING_PTR, offsetof(rlm_sqlcounter_t,query), NULL, NULL },
  { "reset", PW_TYPE_STRING_PTR, offsetof(rlm_sqlcounter_t,reset), NULL,  NULL },
  { "safe-characters", PW_TYPE_STRING_PTR, offsetof(rlm_sqlcounter_t,allowed_chars), NULL, "@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_: /"},
  { NULL, -1, 0, NULL, NULL }
};

static char *allowed_chars = NULL;

/*
 *	Translate the SQL queries.
 */
static size_t sql_escape_func(char *out, size_t outlen, const char *in)
{
	int len = 0;

	while (in[0]) {
		/*
		 *	Non-printable characters get replaced with their
		 *	mime-encoded equivalents.
		 */
		if ((in[0] < 32) ||
		    strchr(allowed_chars, *in) == NULL) {
			/*
			 *	Only 3 or less bytes available.
			 */
			if (outlen <= 3) {
				break;
			}

			snprintf(out, outlen, "=%02X", (unsigned char) in[0]);
			in++;
			out += 3;
			outlen -= 3;
			len += 3;
			continue;
		}

		/*
		 *	Only one byte left.
		 */
		if (outlen <= 1) {
			break;
		}

		/*
		 *	Allowed character.
		 */
		*out = *in;
		out++;
		in++;
		outlen--;
		len++;
	}
	*out = '\0';
	return len;
}

static int find_next_reset(rlm_sqlcounter_t *data, time_t timeval)
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
		DEBUG("rlm_sqlcounter: num=%d, last=%c",num,last);
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
		radlog(L_ERR, "rlm_sqlcounter: Unknown reset timer \"%s\"",
			data->reset);
		return -1;
	}

	len = strftime(sNextTime, sizeof(sNextTime),"%Y-%m-%d %H:%M:%S",tm);
	if (len == 0) *sNextTime = '\0';
	DEBUG2("rlm_sqlcounter: Current Time: %li [%s], Next reset %li [%s]",
		timeval, sCurrentTime, data->reset_time, sNextTime);

	return ret;
}


/*  I don't believe that this routine handles Daylight Saving Time adjustments
    properly.  Any suggestions?
*/

static int find_prev_reset(rlm_sqlcounter_t *data, time_t timeval)
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
		DEBUG("rlm_sqlcounter: num=%d, last=%c",num,last);
	}
	if (strcmp(data->reset, "hourly") == 0 || last == 'h') {
		/*
		 *  Round down to the prev nearest hour.
		 */
		tm->tm_hour -= num - 1;
		data->last_reset = mktime(tm);
	} else if (strcmp(data->reset, "daily") == 0 || last == 'd') {
		/*
		 *  Round down to the prev nearest day.
		 */
		tm->tm_hour = 0;
		tm->tm_mday -= num - 1;
		data->last_reset = mktime(tm);
	} else if (strcmp(data->reset, "weekly") == 0 || last == 'w') {
		/*
		 *  Round down to the prev nearest week.
		 */
		tm->tm_hour = 0;
		tm->tm_mday -= (7 - tm->tm_wday) +(7*(num-1));
		data->last_reset = mktime(tm);
	} else if (strcmp(data->reset, "monthly") == 0 || last == 'm') {
		tm->tm_hour = 0;
		tm->tm_mday = 1;
		tm->tm_mon -= num - 1;
		data->last_reset = mktime(tm);
	} else if (strcmp(data->reset, "never") == 0) {
		data->reset_time = 0;
	} else {
		radlog(L_ERR, "rlm_sqlcounter: Unknown reset timer \"%s\"",
			data->reset);
		return -1;
	}
	len = strftime(sPrevTime, sizeof(sPrevTime), "%Y-%m-%d %H:%M:%S", tm);
	if (len == 0) *sPrevTime = '\0';
	DEBUG2("rlm_sqlcounter: Current Time: %li [%s], Prev reset %li [%s]",
	       timeval, sCurrentTime, data->last_reset, sPrevTime);

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

static int sqlcounter_expand(char *out, int outlen, const char *fmt, void *instance)
{
	rlm_sqlcounter_t *data = (rlm_sqlcounter_t *) instance;
	int c,freespace;
	const char *p;
	char *q;
	char tmpdt[40]; /* For temporary storing of dates */

	q = out;
	for (p = fmt; *p ; p++) {
	/* Calculate freespace in output */
	freespace = outlen - (q - out);
		if (freespace <= 1)
			break;
		c = *p;
		if ((c != '%') && (c != '\\')) {
			*q++ = *p;
			continue;
		}
		if (*++p == '\0') break;
		if (c == '\\') switch(*p) {
			case '\\':
				*q++ = *p;
				break;
			case 't':
				*q++ = '\t';
				break;
			case 'n':
				*q++ = '\n';
				break;
			default:
				*q++ = c;
				*q++ = *p;
				break;

		} else if (c == '%') switch(*p) {

			case '%':
				*q++ = *p;
				break;
			case 'b': /* last_reset */
				snprintf(tmpdt, sizeof(tmpdt), "%lu", data->last_reset);
				strlcpy(q, tmpdt, freespace);
				q += strlen(q);
				break;
			case 'e': /* reset_time */
				snprintf(tmpdt, sizeof(tmpdt), "%lu", data->reset_time);
				strlcpy(q, tmpdt, freespace);
				q += strlen(q);
				break;
			case 'k': /* Key Name */
				strlcpy(q, data->key_name, freespace);
				q += strlen(q);
				break;
			case 'S': /* SQL module instance */
				strlcpy(q, data->sqlmod_inst, freespace);
				q += strlen(q);
				break;
			default:
				*q++ = '%';
				*q++ = *p;
				break;
		}
	}
	*q = '\0';

	DEBUG2("sqlcounter_expand:  '%s'", out);

	return strlen(out);
}


/*
 *	See if the counter matches.
 */
static int sqlcounter_cmp(void *instance, REQUEST *req,
			  UNUSED VALUE_PAIR *request, VALUE_PAIR *check,
			  VALUE_PAIR *check_pairs, VALUE_PAIR **reply_pairs)
{
	rlm_sqlcounter_t *data = (rlm_sqlcounter_t *) instance;
	int counter;
	char querystr[MAX_QUERY_LEN];
	char responsestr[MAX_QUERY_LEN];

	check_pairs = check_pairs; /* shut the compiler up */
	reply_pairs = reply_pairs;

	/* first, expand %k, %b and %e in query */
	sqlcounter_expand(querystr, MAX_QUERY_LEN, data->query, instance);

	/* second, xlat any request attribs in query */
	radius_xlat(responsestr, MAX_QUERY_LEN, querystr, req, sql_escape_func);

	/* third, wrap query with sql module call & expand */
	snprintf(querystr, sizeof(querystr), "%%{%%S:%s}", responsestr);
	sqlcounter_expand(responsestr, MAX_QUERY_LEN, querystr, instance);

	/* Finally, xlat resulting SQL query */
	radius_xlat(querystr, MAX_QUERY_LEN, responsestr, req, sql_escape_func);

	counter = atoi(querystr);

	return counter - check->vp_integer;
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
static int sqlcounter_instantiate(CONF_SECTION *conf, void **instance)
{
	rlm_sqlcounter_t *data;
	DICT_ATTR *dattr;
	ATTR_FLAGS flags;
	time_t now;
	char buffer[MAX_STRING_LEN];

	/*
	 *	Set up a storage area for instance data
	 */
	data = rad_malloc(sizeof(*data));
	if (!data) {
		radlog(L_ERR, "rlm_sqlcounter: Not enough memory.");
		return -1;
	}
	memset(data, 0, sizeof(*data));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, data, module_config) < 0) {
		radlog(L_ERR, "rlm_sqlcounter: Unable to parse parameters.");
		sqlcounter_detach(data);
		return -1;
	}

	/*
	 *	No query, die.
	 */
	if (data->query == NULL) {
		radlog(L_ERR, "rlm_sqlcounter: 'query' must be set.");
		sqlcounter_detach(data);
		return -1;
	}

	/*
	 *	Safe characters list for sql queries. Everything else is
	 *	replaced with their mime-encoded equivalents.
	 */
	allowed_chars = data->allowed_chars;

	/*
	 *	Discover the attribute number of the key.
	 */
	if (data->key_name == NULL) {
		radlog(L_ERR, "rlm_sqlcounter: 'key' must be set.");
		sqlcounter_detach(data);
		return -1;
	}
	sql_escape_func(buffer, sizeof(buffer), data->key_name);
	if (strcmp(buffer, data->key_name) != 0) {
		radlog(L_ERR, "rlm_sqlcounter: The value for option 'key' is too long or contains unsafe characters.");
		sqlcounter_detach(data);
		return -1;
	}
	dattr = dict_attrbyname(data->key_name);
	if (dattr == NULL) {
		radlog(L_ERR, "rlm_sqlcounter: No such attribute %s",
				data->key_name);
		sqlcounter_detach(data);
		return -1;
	}
	data->key_attr = dattr;

	/*
	 *	Discover the attribute number of the reply.
	 *	If not set, set it to Session-Timeout
	 *	for backward compatibility.
	 */
	if (data->reply_name == NULL) {
		DEBUG2("rlm_sqlcounter: Reply attribute set to Session-Timeout.");
		data->reply_attr = dict_attrbyvalue(PW_SESSION_TIMEOUT, 0);
		data->reply_name = strdup("Session-Timeout");
	}
	else {
		dattr = dict_attrbyname(data->reply_name);
		if (dattr == NULL) {
			radlog(L_ERR, "rlm_sqlcounter: No such attribute %s",
			       data->reply_name);
			sqlcounter_detach(data);
			return -1;
		}
		data->reply_attr = dattr;
		DEBUG2("rlm_sqlcounter: Reply attribute %s is number %d",
		       data->reply_name, dattr->attr);
	}

	/*
	 *	Check the "sqlmod-inst" option.
	 */
	if (data->sqlmod_inst == NULL) {
		radlog(L_ERR, "rlm_sqlcounter: 'sqlmod-inst' must be set.");
		sqlcounter_detach(data);
		return -1;
	}
	sql_escape_func(buffer, sizeof(buffer), data->sqlmod_inst);
	if (strcmp(buffer, data->sqlmod_inst) != 0) {
		radlog(L_ERR, "rlm_sqlcounter: The value for option 'sqlmod-inst' is too long or contains unsafe characters.");
		sqlcounter_detach(data);
		return -1;
	}

	/*
	 *  Create a new attribute for the counter.
	 */
	if (data->counter_name == NULL) {
		radlog(L_ERR, "rlm_sqlcounter: 'counter-name' must be set.");
		sqlcounter_detach(data);
		return -1;
	}

	memset(&flags, 0, sizeof(flags));
	dict_addattr(data->counter_name, -1, 0, PW_TYPE_INTEGER, flags);
	dattr = dict_attrbyname(data->counter_name);
	if (dattr == NULL) {
		radlog(L_ERR, "rlm_sqlcounter: Failed to create counter attribute %s",
				data->counter_name);
		sqlcounter_detach(data);
		return -1;
	}
	if (dattr->vendor != 0) {
		radlog(L_ERR, "Counter attribute must not be a VSA");
		sqlcounter_detach(data);
		return -1;
	}
	data->dict_attr = dattr;

	/*
	 * Create a new attribute for the check item.
	 */
	if (data->check_name == NULL) {
		radlog(L_ERR, "rlm_sqlcounter: 'check-name' must be set.");
		sqlcounter_detach(data);
		return -1;
	}
	dict_addattr(data->check_name, 0, PW_TYPE_INTEGER, -1, flags);
	dattr = dict_attrbyname(data->check_name);
	if (dattr == NULL) {
		radlog(L_ERR, "rlm_sqlcounter: Failed to create check attribute %s",
				data->check_name);
		sqlcounter_detach(data);
		return -1;
	}
	DEBUG2("rlm_sqlcounter: Check attribute %s is number %d",
			data->check_name, dattr->attr);

	/*
	 *  Discover the end of the current time period.
	 */
	if (data->reset == NULL) {
		radlog(L_ERR, "rlm_sqlcounter: 'reset' must be set.");
		sqlcounter_detach(data);
		return -1;
	}
	now = time(NULL);
	data->reset_time = 0;

	if (find_next_reset(data,now) == -1) {
		radlog(L_ERR, "rlm_sqlcounter: Failed to find the next reset time.");
		sqlcounter_detach(data);
		return -1;
	}

	/*
	 *  Discover the beginning of the current time period.
	 */
	data->last_reset = 0;

	if (find_prev_reset(data,now) == -1) {
		radlog(L_ERR, "rlm_sqlcounter: Failed to find the previous reset time.");
		sqlcounter_detach(data);
		return -1;
	}

	/*
	 *	Register the counter comparison operation.
	 */
	paircompare_register(data->dict_attr->attr, 0, sqlcounter_cmp, data);

	*instance = data;

	return 0;
}

/*
 *	Find the named user in this modules database.  Create the set
 *	of attribute-value pairs to check and reply with for this user
 *	from the database. The authentication code only needs to check
 *	the password, the rest is done here.
 */
static int sqlcounter_authorize(void *instance, REQUEST *request)
{
	rlm_sqlcounter_t *data = (rlm_sqlcounter_t *) instance;
	int ret=RLM_MODULE_NOOP;
	unsigned int counter;
	DICT_ATTR *dattr;
	VALUE_PAIR *key_vp, *check_vp;
	VALUE_PAIR *reply_item;
	char msg[128];
	char querystr[MAX_QUERY_LEN];
	char responsestr[MAX_QUERY_LEN];

	/* quiet the compiler */
	instance = instance;
	request = request;

	/*
	 *	Before doing anything else, see if we have to reset
	 *	the counters.
	 */
	if (data->reset_time && (data->reset_time <= request->timestamp)) {

		/*
		 *	Re-set the next time and prev_time for this counters range
		 */
		data->last_reset = data->reset_time;
		find_next_reset(data,request->timestamp);
	}


	/*
	 *      Look for the key.  User-Name is special.  It means
	 *      The REAL username, after stripping.
	 */
	DEBUG2("rlm_sqlcounter: Entering module authorize code");
	key_vp = ((data->key_attr->vendor == 0) && (data->key_attr->attr == PW_USER_NAME)) ? request->username : pairfind(request->packet->vps, data->key_attr->attr, data->key_attr->vendor);
	if (key_vp == NULL) {
		DEBUG2("rlm_sqlcounter: Could not find Key value pair");
		return ret;
	}

	/*
	 *      Look for the check item
	 */
	if ((dattr = dict_attrbyname(data->check_name)) == NULL) {
		return ret;
	}
	/* DEBUG2("rlm_sqlcounter: Found Check item attribute %d", dattr->attr); */
	if ((check_vp= pairfind(request->config_items, dattr->attr, dattr->vendor)) == NULL) {
		DEBUG2("rlm_sqlcounter: Could not find Check item value pair");
		return ret;
	}

	/* first, expand %k, %b and %e in query */
	sqlcounter_expand(querystr, MAX_QUERY_LEN, data->query, instance);

	/* second, xlat any request attribs in query */
	radius_xlat(responsestr, MAX_QUERY_LEN, querystr, request, sql_escape_func);

	/* third, wrap query with sql module & expand */
	snprintf(querystr, sizeof(querystr), "%%{%%S:%s}", responsestr);
	sqlcounter_expand(responsestr, MAX_QUERY_LEN, querystr, instance);

	/* Finally, xlat resulting SQL query */
	radius_xlat(querystr, MAX_QUERY_LEN, responsestr, request, sql_escape_func);

	if (sscanf(querystr, "%u", &counter) != 1) {
		DEBUG2("rlm_sqlcounter: No integer found in string \"%s\"",
		       querystr);
		return RLM_MODULE_NOOP;
	}

	/*
	 * Check if check item > counter
	 */
	if (check_vp->vp_integer > counter) {
		unsigned int res = check_vp->lvalue - counter;

		DEBUG2("rlm_sqlcounter: Check item is greater than query result");
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
		 */
		if (data->reset_time &&
		    (res >= (data->reset_time - request->timestamp))) {
			res = data->reset_time - request->timestamp;
			res += check_vp->vp_integer;
		}

		if ((reply_item = pairfind(request->reply->vps, data->reply_attr->attr, data->reply_attr->vendor)) != NULL) {
			if (reply_item->vp_integer > res)
				reply_item->vp_integer = res;
		} else {
			reply_item = radius_paircreate(request,
						       &request->reply->vps,
						       data->reply_attr->attr,
						       data->reply_attr->vendor,
						       PW_TYPE_INTEGER);
			reply_item->vp_integer = res;
		}

		ret=RLM_MODULE_OK;

		DEBUG2("rlm_sqlcounter: Authorized user %s, check_item=%u, counter=%u",
				key_vp->vp_strvalue,check_vp->vp_integer,counter);
		DEBUG2("rlm_sqlcounter: Sent Reply-Item for user %s, Type=%s, value=%u",
				key_vp->vp_strvalue,data->reply_name,reply_item->vp_integer);
	}
	else{
		char module_fmsg[MAX_STRING_LEN];
		VALUE_PAIR *module_fmsg_vp;

		DEBUG2("rlm_sqlcounter: (Check item - counter) is less than zero");

		/*
		 * User is denied access, send back a reply message
		 */
		snprintf(msg, sizeof(msg), "Your maximum %s usage time has been reached", data->reset);
		reply_item=pairmake("Reply-Message", msg, T_OP_EQ);
		pairadd(&request->reply->vps, reply_item);

		snprintf(module_fmsg, sizeof(module_fmsg), "rlm_sqlcounter: Maximum %s usage time reached", data->reset);
		module_fmsg_vp = pairmake("Module-Failure-Message", module_fmsg, T_OP_EQ);
		pairadd(&request->packet->vps, module_fmsg_vp);

		ret=RLM_MODULE_REJECT;

		DEBUG2("rlm_sqlcounter: Rejected user %s, check_item=%u, counter=%u",
				key_vp->vp_strvalue,check_vp->vp_integer,counter);
	}

	return ret;
}

static int sqlcounter_detach(void *instance)
{
	int i;
	char **p;
	rlm_sqlcounter_t *inst = (rlm_sqlcounter_t *)instance;

	allowed_chars = NULL;
	paircompare_unregister(inst->dict_attr->attr, sqlcounter_cmp);

	/*
	 *	Free up dynamically allocated string pointers.
	 */
	for (i = 0; module_config[i].name != NULL; i++) {
		if (module_config[i].type != PW_TYPE_STRING_PTR) {
			continue;
		}

		/*
		 *	Treat 'config' as an opaque array of bytes,
		 *	and take the offset into it.  There's a
		 *      (char*) pointer at that offset, and we want
		 *	to point to it.
		 */
		p = (char **) (((char *)inst) + module_config[i].offset);
		if (!*p) { /* nothing allocated */
			continue;
		}
		free(*p);
		*p = NULL;
	}
	free(inst);
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
module_t rlm_sqlcounter = {
	RLM_MODULE_INIT,
	"SQL Counter",
	RLM_TYPE_THREAD_SAFE,		/* type */
	sqlcounter_instantiate,		/* instantiation */
	sqlcounter_detach,		/* detach */
	{
		NULL,			/* authentication */
		sqlcounter_authorize, 	/* authorization */
		NULL,			/* preaccounting */
		NULL,			/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
	},
};

