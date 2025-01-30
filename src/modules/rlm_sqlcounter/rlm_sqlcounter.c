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
 * @copyright 2001,2006 The FreeRADIUS server project
 * @copyright 2001 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#define LOG_PREFIX "sqlcounter"

#include <rlm_sql.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/unlang/function.h>

#include <ctype.h>

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
typedef struct {
	tmpl_t	*start_attr;		//!< &control.${.:instance}-Start
	tmpl_t	*end_attr;		//!< &control.${.:instance}-End

	tmpl_t	*counter_attr;		//!< Daily-Session-Time.
	tmpl_t	*limit_attr;  		//!< Max-Daily-Session.
	tmpl_t	*key;  			//!< User-Name

	char const	*sql_name;	//!< Instance of SQL module to use, usually just 'sql'.
	char const	*query;		//!< SQL query to retrieve current session time.
	char const	*reset;  	//!< Daily, weekly, monthly, never or user defined.
	bool		auto_extend;	//!< If the remaining allowance is sufficient to reach the next
					///< period allow for that in setting the reply attribute.
	bool		utc;		//!< Use UTC time.

	fr_time_t	reset_time;
	fr_time_t	last_reset;
} rlm_sqlcounter_t;

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET_FLAGS("sql_module_instance", CONF_FLAG_REQUIRED, rlm_sqlcounter_t, sql_name) },


	{ FR_CONF_OFFSET_FLAGS("query", CONF_FLAG_XLAT | CONF_FLAG_REQUIRED, rlm_sqlcounter_t, query) },
	{ FR_CONF_OFFSET_FLAGS("reset", CONF_FLAG_REQUIRED, rlm_sqlcounter_t, reset) },
	{ FR_CONF_OFFSET_FLAGS("auto_extend", CONF_FLAG_OK_MISSING, rlm_sqlcounter_t, auto_extend) },
	{ FR_CONF_OFFSET_FLAGS("utc", CONF_FLAG_OK_MISSING, rlm_sqlcounter_t, utc) },

	{ FR_CONF_OFFSET_FLAGS("key", CONF_FLAG_NOT_EMPTY, rlm_sqlcounter_t, key), .dflt = "%{%{Stripped-User-Name} || %{User-Name}}", .quote = T_DOUBLE_QUOTED_STRING },

	{ FR_CONF_OFFSET_FLAGS("reset_period_start_name", CONF_FLAG_ATTRIBUTE, rlm_sqlcounter_t, start_attr),
	  .dflt = "&control.${.:instance}-Reset-Start", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET_FLAGS("reset_period_end_name", CONF_FLAG_ATTRIBUTE, rlm_sqlcounter_t, end_attr),
	  .dflt = "&control.${.:instance}-Reset-End", .quote = T_BARE_WORD },

	/* Attribute to write counter value to*/
	{ FR_CONF_OFFSET_FLAGS("counter_name", CONF_FLAG_ATTRIBUTE | CONF_FLAG_REQUIRED, rlm_sqlcounter_t, counter_attr) },
	{ FR_CONF_OFFSET_FLAGS("check_name", CONF_FLAG_ATTRIBUTE | CONF_FLAG_REQUIRED, rlm_sqlcounter_t, limit_attr) },

	CONF_PARSER_TERMINATOR
};

typedef struct {
	xlat_exp_head_t	*query_xlat;		//!< Tokenized xlat to run query.
	tmpl_t		*reply_attr;		//!< Attribute to write timeout to.
	tmpl_t		*reply_msg_attr;	//!< Attribute to write reply message to.
} sqlcounter_call_env_t;

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_sqlcounter_dict[];
fr_dict_autoload_t rlm_sqlcounter_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static int find_next_reset(rlm_sqlcounter_t *inst, fr_time_t now)
{
	int		ret = 0;
	size_t		len;
	unsigned int	num = 1;
	char		last = '\0';
	struct tm	*tm, s_tm;
	time_t		time_s = fr_time_to_sec(now);

	if (inst->utc) {
		tm = gmtime_r(&time_s, &s_tm);
	} else {
		tm = localtime_r(&time_s, &s_tm);
	}
	tm->tm_sec = tm->tm_min = 0;

	fr_assert(inst->reset != NULL);

	if (isdigit((uint8_t) inst->reset[0])){
		len = strlen(inst->reset);
		if (len == 0)
			return -1;
		last = inst->reset[len - 1];
		if (!isalpha((uint8_t) last))
			last = 'd';
		num = atoi(inst->reset);
		DEBUG3("num=%d, last=%c",num,last);
	}
	if (strcmp(inst->reset, "hourly") == 0 || last == 'h') {
		/*
		 *  Round up to the next nearest hour.
		 */
		tm->tm_hour += num;
		inst->reset_time = fr_time_from_sec(inst->utc ? timegm(tm) : mktime(tm));
	} else if (strcmp(inst->reset, "daily") == 0 || last == 'd') {
		/*
		 *  Round up to the next nearest day.
		 */
		tm->tm_hour = 0;
		tm->tm_mday += num;
		inst->reset_time = fr_time_from_sec(inst->utc ? timegm(tm) : mktime(tm));
	} else if (strcmp(inst->reset, "weekly") == 0 || last == 'w') {
		/*
		 *  Round up to the next nearest week.
		 */
		tm->tm_hour = 0;
		tm->tm_mday += (7 - tm->tm_wday) +(7*(num-1));
		inst->reset_time = fr_time_from_sec(inst->utc ? timegm(tm) : mktime(tm));
	} else if (strcmp(inst->reset, "monthly") == 0 || last == 'm') {
		tm->tm_hour = 0;
		tm->tm_mday = 1;
		tm->tm_mon += num;
		inst->reset_time = fr_time_from_sec(inst->utc ? timegm(tm) : mktime(tm));
	} else if (strcmp(inst->reset, "never") == 0) {
		inst->reset_time = fr_time_wrap(0);
	} else {
		return -1;
	}

	DEBUG2("Current Time: %pV, Next reset %pV", fr_box_time(now), fr_box_time(inst->reset_time));

	return ret;
}


/*  I don't believe that this routine handles Daylight Saving Time adjustments
    properly.  Any suggestions?
*/
static int find_prev_reset(rlm_sqlcounter_t *inst, fr_time_t now)
{
	int		ret = 0;
	size_t		len;
	unsigned	int num = 1;
	char		last = '\0';
	struct		tm *tm, s_tm;
	time_t		time_s = fr_time_to_sec(now);

	if (inst->utc) {
		tm = gmtime_r(&time_s, &s_tm);
	} else {
		tm = localtime_r(&time_s, &s_tm);
	}
	tm->tm_sec = tm->tm_min = 0;

	fr_assert(inst->reset != NULL);

	if (isdigit((uint8_t) inst->reset[0])){
		len = strlen(inst->reset);
		if (len == 0)
			return -1;
		last = inst->reset[len - 1];
		if (!isalpha((uint8_t) last))
			last = 'd';
		num = atoi(inst->reset);
		DEBUG3("num=%d, last=%c", num, last);
	}
	if (strcmp(inst->reset, "hourly") == 0 || last == 'h') {
		/*
		 *  Round down to the prev nearest hour.
		 */
		tm->tm_hour -= num - 1;
		inst->last_reset = fr_time_from_sec(inst->utc ? timegm(tm) : mktime(tm));
	} else if (strcmp(inst->reset, "daily") == 0 || last == 'd') {
		/*
		 *  Round down to the prev nearest day.
		 */
		tm->tm_hour = 0;
		tm->tm_mday -= num - 1;
		inst->last_reset = fr_time_from_sec(inst->utc ? timegm(tm) : mktime(tm));
	} else if (strcmp(inst->reset, "weekly") == 0 || last == 'w') {
		/*
		 *  Round down to the prev nearest week.
		 */
		tm->tm_hour = 0;
		tm->tm_mday -= tm->tm_wday +(7*(num-1));
		inst->last_reset = fr_time_from_sec(inst->utc ? timegm(tm) : mktime(tm));
	} else if (strcmp(inst->reset, "monthly") == 0 || last == 'm') {
		tm->tm_hour = 0;
		tm->tm_mday = 1;
		tm->tm_mon -= num - 1;
		inst->last_reset = fr_time_from_sec(inst->utc ? timegm(tm) : mktime(tm));
	} else if (strcmp(inst->reset, "never") == 0) {
		inst->reset_time = fr_time_wrap(0);
	} else {
		return -1;
	}

	DEBUG2("Current Time: %pV, Prev reset %pV", fr_box_time(now), fr_box_time(inst->last_reset));

	return ret;
}

typedef struct {
	bool			last_success;
	fr_value_box_list_t	result;
	rlm_sqlcounter_t	*inst;
	sqlcounter_call_env_t	*env;
	fr_pair_t		*limit;
} sqlcounter_rctx_t;

/** Handle the result of calling the SQL query to retrieve the `counter` value.
 *
 * Create / update the `counter` attribute in the control list
 * If `counter` > `limit`, optionally populate a reply message and return RLM_MODULE_REJECT.
 * Otherwise, optionally populate a reply attribute with the value of `limit` - `counter` and return RLM_MODULE_UPDATED.
 * If no reply attribute is set, return RLM_MODULE_OK.
 */
static unlang_action_t mod_authorize_resume(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	sqlcounter_rctx_t	*rctx = talloc_get_type_abort(uctx, sqlcounter_rctx_t);
	rlm_sqlcounter_t	*inst = rctx->inst;
	sqlcounter_call_env_t	*env = rctx->env;
	fr_value_box_t		*sql_result = fr_value_box_list_pop_head(&rctx->result);
	uint64_t		counter, res;
	fr_pair_t		*vp, *limit = rctx->limit;
	int			ret;
	char			msg[128];

	if (!sql_result || (sscanf(sql_result->vb_strvalue, "%" PRIu64, &counter) != 1)) {
		RDEBUG2("No integer found in result string \"%pV\".  May be first session, setting counter to 0",
			sql_result);
		counter = 0;
	}

	/*
	 *	Add the counter to the control list
	 */
	MEM(pair_update_control(&vp, tmpl_attr_tail_da(inst->counter_attr)) >= 0);
	vp->vp_uint64 = counter;

	/*
	 *	Check if check item > counter
	 */
	if (limit->vp_uint64 <= counter) {
		if (env->reply_msg_attr) {
			/* User is denied access, send back a reply message */
			snprintf(msg, sizeof(msg), "Your maximum %s usage has been reached", inst->reset);

			MEM(pair_update_reply(&vp, tmpl_attr_tail_da(env->reply_msg_attr)) >= 0);
			fr_pair_value_strdup(vp, msg, false);
		}

		REDEBUG2("Maximum %s usage reached", inst->reset);
		REDEBUG2("Rejecting user, %s value (%" PRIu64 ") is less than counter value (%" PRIu64 ")",
			 inst->limit_attr->name, limit->vp_uint64, counter);

		RETURN_MODULE_REJECT;
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
	if (env->reply_attr) {
		fr_value_box_t	vb;

		/*
		 *	If we are near a reset then add the next
		 *	limit, so that the user will not need to login
		 *	again.  Do this only if auto_extend is set.
		 */
		if (inst->auto_extend &&
		    fr_time_gt(inst->reset_time, fr_time_wrap(0)) &&
		    ((int64_t)res >= fr_time_delta_to_sec(fr_time_sub(inst->reset_time, request->packet->timestamp)))) {
			fr_time_delta_t to_reset = fr_time_sub(inst->reset_time, request->packet->timestamp);

			RDEBUG2("Time remaining (%pV) is greater than time to reset (%" PRIu64 "s).  "
				"Adding %pV to reply value",
				fr_box_time_delta(to_reset), res, fr_box_time_delta(to_reset));
			res = fr_time_delta_to_sec(to_reset) + limit->vp_uint64;
		}

		fr_value_box_init(&vb, FR_TYPE_UINT64, NULL, false);
		vb.vb_uint64 = res;

		/*
		 *	Limit the reply attribute to the minimum of the existing value, or this new one.
		 */
		ret = tmpl_find_or_add_vp(&vp, request, env->reply_attr);
		switch (ret) {
		case 1:		/* new */
			break;

		case 0:		/* found */
		{
			fr_value_box_t	existing;
			fr_value_box_cast(NULL, &existing, FR_TYPE_UINT64, NULL, &vp->data);
			if (fr_value_box_cmp(&vb, &existing) == 1) {
				RDEBUG2("Leaving existing %s value of %pV" , env->reply_attr->name,
					&vp->data);
				RETURN_MODULE_OK;
			}
		}
			break;

		case -1:	/* alloc failed */
			REDEBUG("Error allocating attribute %s", env->reply_attr->name);
			RETURN_MODULE_FAIL;

		default:	/* request or list unavailable */
			RDEBUG2("List or request context not available for %s, skipping...", env->reply_attr->name);
			RETURN_MODULE_OK;
		}

		fr_value_box_cast(vp, &vp->data, vp->data.type, NULL, &vb);

		RDEBUG2("%pP", vp);

		RETURN_MODULE_UPDATED;
	}

	RETURN_MODULE_OK;
}

/** Check the value of a `counter` retrieved from an SQL query with a `limit`
 *
 * Module specific attributes containing the start / end times are created / updated,
 * the query is tokenized as an xlat call to the relevant SQL module and then
 * pushed on the stack for evaluation.
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sqlcounter_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_sqlcounter_t);
	sqlcounter_call_env_t	*env = talloc_get_type_abort(mctx->env_data, sqlcounter_call_env_t);
	fr_pair_t		*limit, *vp;
	sqlcounter_rctx_t	*rctx;

	/*
	 *	Before doing anything else, see if we have to reset
	 *	the counters.
	 */
	if (fr_time_neq(inst->reset_time, fr_time_wrap(0)) &&
	    (fr_time_lteq(inst->reset_time, request->packet->timestamp))) {
		/*
		 *	Re-set the next time and prev_time for this counters range
		 */
		inst->last_reset = inst->reset_time;
		find_next_reset(inst, request->packet->timestamp);
	}

	if (tmpl_find_vp(&limit, request, inst->limit_attr) < 0) {
		RWDEBUG2("Couldn't find %s, doing nothing...", inst->limit_attr->name);
		RETURN_MODULE_NOOP;
	}

	/*
	 *	Populate start and end attributes for use in query expansion
	 */
	if (tmpl_find_or_add_vp(&vp, request, inst->start_attr) < 0) {
		REDEBUG("Couldn't create %s", inst->start_attr->name);
		RETURN_MODULE_FAIL;
	}
	vp->vp_uint64 = fr_time_to_sec(inst->last_reset);

	if (tmpl_find_or_add_vp(&vp, request, inst->end_attr) < 0) {
		REDEBUG2("Couldn't create %s", inst->end_attr->name);
		RETURN_MODULE_FAIL;
	}
	vp->vp_uint64 = fr_time_to_sec(inst->reset_time);

	MEM(rctx = talloc(unlang_interpret_frame_talloc_ctx(request), sqlcounter_rctx_t));
	*rctx = (sqlcounter_rctx_t) {
		.inst = inst,
		.env = env,
		.limit = limit
	};

	if (unlang_function_push(request, NULL, mod_authorize_resume, NULL, 0, UNLANG_SUB_FRAME, rctx) < 0) {
	error:
		talloc_free(rctx);
		RETURN_MODULE_FAIL;
	}

	fr_value_box_list_init(&rctx->result);
	if (unlang_xlat_push(rctx, &rctx->last_success, &rctx->result, request, env->query_xlat, UNLANG_SUB_FRAME) < 0) goto error;

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Custom call_env parser to tokenize the SQL query xlat used for counter retrieval
 */
static int call_env_query_parse(TALLOC_CTX *ctx, void *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci,
				call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	rlm_sqlcounter_t const	*inst = talloc_get_type_abort_const(cec->mi->data, rlm_sqlcounter_t);
	CONF_PAIR const		*to_parse = cf_item_to_pair(ci);
	char			*query;
	xlat_exp_head_t		*ex;

	query = talloc_asprintf(NULL, "%%%s(\"%s\")", inst->sql_name, cf_pair_value(to_parse));

	if (xlat_tokenize(ctx, &ex,
		  &FR_SBUFF_IN(query, talloc_array_length(query)),
		  &(fr_sbuff_parse_rules_t){
			.escapes = &(fr_sbuff_unescape_rules_t) {
				.name = "xlat",
				.chr = '\\',
				.subs = {
					['%'] = '%',
					['\\'] = '\\',
				},
		  }}, t_rules, 0) < 0) {
		talloc_free(query);
		return -1;
	}
	talloc_free(query);

	if (xlat_needs_resolving(ex) &&
	    (xlat_resolve(ex, &(xlat_res_rules_t){ .allow_unresolved = false }) < 0)) {
		talloc_free(ex);
		return -1;
	}

	*(void**)out = ex;
	return 0;
}

static const call_env_method_t sqlcounter_call_env = {
	FR_CALL_ENV_METHOD_OUT(sqlcounter_call_env_t),
	.env = (call_env_parser_t[]){
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("query", FR_TYPE_VOID, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_PARSE_ONLY, sqlcounter_call_env_t, query_xlat),
		  .pair.func = call_env_query_parse },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("reply_name", FR_TYPE_VOID, CALL_ENV_FLAG_PARSE_ONLY, sqlcounter_call_env_t, reply_attr) },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("reply_message_name", FR_TYPE_VOID, CALL_ENV_FLAG_PARSE_ONLY, sqlcounter_call_env_t, reply_msg_attr) },
		CALL_ENV_TERMINATOR
	}
};


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
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_sqlcounter_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_sqlcounter_t);
	CONF_SECTION    	*conf = mctx->mi->conf;
	module_instance_t const	*sql_inst;
	fr_assert(inst->query && *inst->query);

	sql_inst = module_rlm_static_by_name(NULL, inst->sql_name);
	if (!sql_inst) {
		cf_log_err(conf, "Module \"%s\" not found", inst->sql_name);
		return -1;
	}

	if (!talloc_get_type(sql_inst->data, rlm_sql_t)) {
		cf_log_err(conf, "\"%s\" is not an instance of rlm_sql", inst->sql_name);
		return -1;
	}

	inst->reset_time = fr_time_wrap(0);

	if (find_next_reset(inst, fr_time()) == -1) {
		cf_log_err(conf, "Invalid reset '%s'", inst->reset);
		return -1;
	}

	/*
	 *  Discover the beginning of the current time period.
	 */
	inst->last_reset = fr_time_wrap(0);

	if (find_prev_reset(inst, fr_time()) < 0) {
		cf_log_err(conf, "Invalid reset '%s'", inst->reset);
		return -1;
	}

	return 0;
}

static inline int attr_check(CONF_SECTION *conf, tmpl_t *tmpl, char const *name, fr_dict_attr_flags_t *flags)
{
	if (tmpl_is_attr_unresolved(tmpl) && !fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), tmpl_attr_tail_unresolved(tmpl))) {
		if (fr_dict_attr_add_name_only(fr_dict_unconst(dict_freeradius), fr_dict_root(dict_freeradius),
					       tmpl_attr_tail_unresolved(tmpl), FR_TYPE_UINT64, flags) < 0) {
			cf_log_perr(conf, "Failed defining %s attribute", name);
			return -1;
		}
	} else if (tmpl_is_attr(tmpl)) {
		if (tmpl_attr_tail_da(tmpl)->type != FR_TYPE_UINT64) {
			cf_log_err(conf, "%s attribute %s must be uint64", name, tmpl_attr_tail_da(tmpl)->name);
			return -1;
		}
	}

	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_sqlcounter_t const	*inst = talloc_get_type_abort(mctx->mi->data, rlm_sqlcounter_t);
	CONF_SECTION    	*conf = mctx->mi->conf;
	fr_dict_attr_flags_t	flags = { .internal = 1, .length = 8, .name_only = 1 };

	if (unlikely(attr_check(conf, inst->start_attr, "reset_period_start", &flags) < 0)) return -1;
	if (unlikely(attr_check(conf, inst->end_attr, "reset_period_end", &flags) < 0)) return -1;
	if (unlikely(attr_check(conf, inst->counter_attr, "counter", &flags) < 0)) return -1;
	if (unlikely(attr_check(conf, inst->limit_attr, "check", &flags) < 0)) return -1;

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_sqlcounter;
module_rlm_t rlm_sqlcounter = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "sqlcounter",
		.inst_size	= sizeof(rlm_sqlcounter_t),
		.config		= module_config,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate,
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = mod_authorize, .method_env = &sqlcounter_call_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
