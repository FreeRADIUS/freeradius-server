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
 * @file rlm_sql.c
 * @brief Implements SQL 'users' file, and SQL accounting.
 *
 * @copyright 2012-2014 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Mike Machado (mike@innercite.com)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */

RCSID("$Id$")

#define LOG_PREFIX mctx->mi->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/exfile.h>
#include <freeradius-devel/server/map_proc.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/pairmove.h>
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/server/trigger.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/skip.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/unlang/action.h>
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/unlang/module.h>
#include <freeradius-devel/unlang/map.h>

#include <sys/stat.h>

#include "rlm_sql.h"

#define SQL_SAFE_FOR (fr_value_box_safe_for_t)inst->driver

extern module_rlm_t rlm_sql;

static int submodule_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);

typedef struct {
	fr_dict_attr_t const *group_da;
	fr_dict_attr_t const *query_number_da;
} rlm_sql_boot_t;

static const conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("driver", FR_TYPE_VOID, 0, rlm_sql_t, driver_submodule), .dflt = "null",
			 .func = submodule_parse },
	{ FR_CONF_OFFSET("server", rlm_sql_config_t, sql_server), .dflt = "" },	/* Must be zero length so drivers can determine if it was set */
	{ FR_CONF_OFFSET("port", rlm_sql_config_t, sql_port), .dflt = "0" },
	{ FR_CONF_OFFSET("login", rlm_sql_config_t, sql_login), .dflt = "" },
	{ FR_CONF_OFFSET_FLAGS("password", CONF_FLAG_SECRET, rlm_sql_config_t, sql_password), .dflt = "" },
	{ FR_CONF_OFFSET("radius_db", rlm_sql_config_t, sql_db), .dflt = "radius" },
	{ FR_CONF_OFFSET("read_groups", rlm_sql_config_t, read_groups), .dflt = "yes" },
	{ FR_CONF_OFFSET("group_attribute", rlm_sql_config_t, group_attribute) },
	{ FR_CONF_OFFSET("cache_groups", rlm_sql_config_t, cache_groups) },
	{ FR_CONF_OFFSET("read_profiles", rlm_sql_config_t, read_profiles), .dflt = "yes" },
	{ FR_CONF_OFFSET("open_query", rlm_sql_config_t, connect_query) },
	{ FR_CONF_OFFSET("query_number_attribute", rlm_sql_config_t, query_number_attribute) },

	{ FR_CONF_OFFSET("safe_characters", rlm_sql_config_t, allowed_chars), .dflt = "@abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_: /" },

	/*
	 *	This only works for a few drivers.
	 */
	{ FR_CONF_OFFSET("query_timeout", rlm_sql_config_t, query_timeout), .dflt = "5" },

	/*
	 *	The pool section is used for trunk config
	 */
	{ FR_CONF_OFFSET_SUBSECTION("pool", 0, rlm_sql_config_t, trunk_conf, trunk_config) },

	{ FR_CONF_OFFSET_FLAGS("expand_rhs", CONF_FLAG_HIDDEN, rlm_sql_config_t, expand_rhs) },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_sql_dict[];
fr_dict_autoload_t rlm_sql_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_fall_through;
static fr_dict_attr_t const *attr_sql_user_name;
static fr_dict_attr_t const *attr_user_profile;
static fr_dict_attr_t const *attr_expr_bool_enum;

extern fr_dict_attr_autoload_t rlm_sql_dict_attr[];
fr_dict_attr_autoload_t rlm_sql_dict_attr[] = {
	{ .out = &attr_fall_through, .name = "Fall-Through", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_sql_user_name, .name = "SQL-User-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_user_profile, .name = "User-Profile", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_expr_bool_enum, .name = "Expr-Bool-Enum", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	DICT_AUTOLOAD_TERMINATOR
};

typedef struct {
	fr_value_box_t	user;			//!< Expansion of the sql_user_name
	tmpl_t		*check_query;		//!< Tmpl to expand to form authorize_check_query
	tmpl_t		*reply_query;		//!< Tmpl to expand to form authorize_reply_query
	tmpl_t		*membership_query;	//!< Tmpl to expand to form group_membership_query
	tmpl_t		*group_check_query;	//!< Tmpl to expand to form authorize_group_check_query
	tmpl_t		*group_reply_query;	//!< Tmpl to expand to form authorize_group_reply_query
} sql_autz_call_env_t;

static int logfile_call_env_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out, tmpl_rules_t const *t_rules, CONF_ITEM *cc,
				  call_env_ctx_t const *cec, call_env_parser_t const *rule);

static int query_call_env_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out, tmpl_rules_t const *t_rules, CONF_ITEM *cc,
				call_env_ctx_t const *cec, call_env_parser_t const *rule);

typedef struct {
	fr_value_box_t	filename;
} sql_xlat_call_env_t;

static const call_env_method_t xlat_method_env = {
	FR_CALL_ENV_METHOD_OUT(sql_xlat_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("logfile", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT, sql_xlat_call_env_t, filename),
		  .pair.escape = {
			  .box_escape = {
				  .func = rad_filename_box_make_safe,
				  .safe_for = (fr_value_box_safe_for_t)rad_filename_box_make_safe,
				  .always_escape = false,
			  },
			  .mode = TMPL_ESCAPE_PRE_CONCAT
		  },
		  .pair.literals_safe_for = (fr_value_box_safe_for_t)rad_filename_box_make_safe,
		},
		CALL_ENV_TERMINATOR
	}
};

typedef struct rlm_sql_grouplist_s rlm_sql_grouplist_t;

/** Status of the authorization process
 */
typedef enum {
	SQL_AUTZ_CHECK			= 0x12,		//!< Running user `check` query
	SQL_AUTZ_CHECK_RESUME		= 0x13,		//!< Completed user `check` query
	SQL_AUTZ_REPLY			= 0x14,		//!< Running user `reply` query
	SQL_AUTZ_REPLY_RESUME		= 0x15,		//!< Completed user `reply` query
	SQL_AUTZ_GROUP_MEMB		= 0x20,		//!< Running group membership query
	SQL_AUTZ_GROUP_MEMB_RESUME	= 0x21,		//!< Completed group membership query
	SQL_AUTZ_GROUP_CHECK		= 0x22,		//!< Running group `check` query
	SQL_AUTZ_GROUP_CHECK_RESUME	= 0x23,		//!< Completed group `check` query
	SQL_AUTZ_GROUP_REPLY		= 0x24,		//!< Running group `reply` query
	SQL_AUTZ_GROUP_REPLY_RESUME	= 0x25,		//!< Completed group `reply` query
	SQL_AUTZ_PROFILE_START		= 0x40,		//!< Starting processing user profiles
	SQL_AUTZ_PROFILE_CHECK		= 0x42,		//!< Running profile `check` query
	SQL_AUTZ_PROFILE_CHECK_RESUME	= 0x43,		//!< Completed profile `check` query
	SQL_AUTZ_PROFILE_REPLY		= 0x44,		//!< Running profile `reply` query
	SQL_AUTZ_PROFILE_REPLY_RESUME	= 0x45,		//!< Completed profile `reply` query
} sql_autz_status_t;

#define SQL_AUTZ_STAGE_GROUP 0x20
#define SQL_AUTZ_STAGE_PROFILE 0x40

/** Context for group membership query evaluation
 */
typedef struct {
	rlm_sql_t const		*inst;		//!< Module instance.
	fr_value_box_t		*query;		//!< Query string used for evaluating group membership.
	fr_sql_query_t		*query_ctx;	//!< Query context.
	rlm_sql_grouplist_t	*groups;	//!< List of groups retrieved.
	int			num_groups;	//!< How many groups have been retrieved.
} sql_group_ctx_t;

/** Context for SQL authorization
 */
typedef struct {
	rlm_sql_t const		*inst;		//!< Module instance.
	request_t		*request;	//!< Request being processed.
	rlm_rcode_t		rcode;		//!< Module return code.
	trunk_t			*trunk;		//!< Trunk connection for current authorization.
	sql_autz_call_env_t	*call_env;	//!< Call environment data.
	map_list_t		check_tmp;	//!< List to store check items before processing.
	map_list_t		reply_tmp;	//!< List to store reply items before processing.
	sql_autz_status_t	status;		//!< Current status of the authorization.
	fr_value_box_list_t	query;		//!< Where expanded query tmpls will be written.
	bool			user_found;	//!< Has the user been found anywhere?
	rlm_sql_grouplist_t	*group;		//!< Current group being processed.
	fr_pair_t		*sql_group;	//!< Pair to update with group being processed.
	fr_pair_t		*profile;	//!< Current profile being processed.
	fr_sql_map_ctx_t	*map_ctx;	//!< Context used for retrieving attribute value pairs as a map list.
	sql_group_ctx_t		*group_ctx;	//!< Context used for retrieving user group membership.
} sql_autz_ctx_t;

typedef struct {
	fr_value_box_t		user;		//!< Expansion of sql_user_name.
	fr_value_box_t		filename;	//!< File name to write SQL logs to.
	tmpl_t			**query;	//!< Array of tmpls for list of queries to run.
} sql_redundant_call_env_t;

static const call_env_method_t accounting_method_env = {
	FR_CALL_ENV_METHOD_OUT(sql_redundant_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("sql_user_name", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_NULLABLE, sql_redundant_call_env_t, user) },
		{ FR_CALL_ENV_SUBSECTION_FUNC(CF_IDENT_ANY, CF_IDENT_ANY, CALL_ENV_FLAG_SUBSECTION, logfile_call_env_parse) },
		{ FR_CALL_ENV_SUBSECTION_FUNC("accounting", CF_IDENT_ANY, CALL_ENV_FLAG_SUBSECTION, query_call_env_parse) },
		CALL_ENV_TERMINATOR
	}
};

static const call_env_method_t send_method_env = {
	FR_CALL_ENV_METHOD_OUT(sql_redundant_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("sql_user_name", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_NULLABLE, sql_redundant_call_env_t, user) },
		{ FR_CALL_ENV_SUBSECTION_FUNC(CF_IDENT_ANY, CF_IDENT_ANY, CALL_ENV_FLAG_SUBSECTION, logfile_call_env_parse) },
		{ FR_CALL_ENV_SUBSECTION_FUNC("send", CF_IDENT_ANY, CALL_ENV_FLAG_SUBSECTION, query_call_env_parse) },
		CALL_ENV_TERMINATOR
	}
};

/** Context for tracking redundant SQL query sets
 */
typedef struct {
	rlm_sql_t const			*inst;		//!< Module instance.
	request_t			*request;	//!< Request being processed.
	trunk_t				*trunk;		//!< Trunk connection for queries.
	sql_redundant_call_env_t	*call_env;	//!< Call environment data.
	size_t				query_no;	//!< Current query number.
	fr_value_box_list_t		query;		//!< Where expanded query tmpl will be written.
	fr_value_box_t			*query_vb;	//!< Current query string.
	fr_sql_query_t			*query_ctx;	//!< Query context for current query.
} sql_redundant_ctx_t;

typedef struct {
	fr_value_box_t	user;
	tmpl_t		*membership_query;
} sql_group_xlat_call_env_t;

static const call_env_method_t group_xlat_method_env = {
	FR_CALL_ENV_METHOD_OUT(sql_group_xlat_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("sql_user_name", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_NULLABLE, sql_group_xlat_call_env_t, user) },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("group_membership_query", FR_TYPE_STRING, CALL_ENV_FLAG_PARSE_ONLY, sql_group_xlat_call_env_t, membership_query) },
		CALL_ENV_TERMINATOR
	}
};

int submodule_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	rlm_sql_t		*inst = talloc_get_type_abort(parent, rlm_sql_t);
	module_instance_t	*mi;
	int ret;

	if (unlikely(ret = module_rlm_submodule_parse(ctx, out, parent, ci, rule) < 0)) return ret;

	mi = talloc_get_type_abort(*((void **)out), module_instance_t);
	inst->driver = (rlm_sql_driver_t const *)mi->exported; /* Public symbol exported by the submodule */

	return 0;
}

static int _sql_escape_uxtx_free(void *uctx)
{
	return talloc_free(uctx);
}

/*
 *	Create a thread local uctx which is used in SQL value box escaping
 *	so that an already reserved connection can be used.
 */
static void *sql_escape_uctx_alloc(UNUSED request_t *request, void const *uctx)
{
	static _Thread_local rlm_sql_escape_uctx_t	*t_ctx;

	if (unlikely(t_ctx == NULL)) {
		rlm_sql_escape_uctx_t *ctx;

		MEM(ctx = talloc_zero(NULL, rlm_sql_escape_uctx_t));
		fr_atexit_thread_local(t_ctx, _sql_escape_uxtx_free, ctx);
	}
	t_ctx->sql = uctx;

	return t_ctx;
}

/*
 *	Fall-Through checking function from rlm_files.c
 */
static sql_fall_through_t fall_through(map_list_t *maps)
{
	bool rcode;
	map_t *map, *next;

	for (map = map_list_head(maps);
	     map != NULL;
	     map = next) {
		next = map_list_next(maps, map);

		fr_assert(tmpl_is_attr(map->lhs));

		if (tmpl_attr_tail_da(map->lhs) == attr_fall_through) {
			(void) map_list_remove(maps, map);

			if (tmpl_is_data(map->rhs)) {
				fr_assert(tmpl_value_type(map->rhs) == FR_TYPE_BOOL);

				rcode = tmpl_value(map->rhs)->vb_bool;
			} else {
				rcode = false;
			}

			talloc_free(map);
			return rcode;
		}
	}

	return  FALL_THROUGH_DEFAULT;
}

/*
 *	Yucky prototype.
 */
static ssize_t sql_escape_func(request_t *, char *out, size_t outlen, char const *in, void *arg);

/** Escape a tainted VB used as an xlat argument
 *
 */
static int CC_HINT(nonnull(2,3)) sql_xlat_escape(request_t *request, fr_value_box_t *vb, void *uctx)
{
	fr_sbuff_t			sbuff;
	fr_sbuff_uctx_talloc_t		sbuff_ctx;

	ssize_t				len;
	void				*arg = NULL;
	rlm_sql_escape_uctx_t		*ctx = uctx;
	rlm_sql_t const			*inst = talloc_get_type_abort_const(ctx->sql, rlm_sql_t);
	rlm_sql_thread_t		*thread = talloc_get_type_abort(module_thread(inst->mi)->data, rlm_sql_thread_t);

	/*
	 *	If it's already safe, don't do anything.
	 */
	if (fr_value_box_is_safe_for(vb, inst->driver)) return 0;

	/*
	 *	Don't print "::" for enum names.  Instead we convert
	 *	the box to a string which contains the enum name, and
	 *	then see if we need to escape it.
	 */
	if (vb->enumv && vb->enumv->flags.has_value) {
		char const *name;

		name = fr_dict_enum_name_by_value(vb->enumv, vb);
		if (name) {
			int rcode;

			/*
			 *	Store list pointers to restore later - fr_value_box_cast clears them
			 */
			fr_value_box_entry_t entry = vb->entry;

			rcode = fr_value_box_strdup(vb, vb, NULL, name, false);
			vb->entry = entry;

			if (rcode < 0) return rcode;

			goto check_escape_arg;
		}
	}

	/*
	 *	No need to escape types with inherently safe data
	 */
	switch (vb->type) {
	case FR_TYPE_NUMERIC:
	case FR_TYPE_IP:
	case FR_TYPE_ETHERNET:
		fr_value_box_mark_safe_for(vb, inst->driver);
		return 0;

	default:
		break;
	}

check_escape_arg:
	if (inst->sql_escape_arg) {
		arg = inst->sql_escape_arg;
	} else if (thread->sql_escape_arg) {
		arg = thread->sql_escape_arg;
	}
	if (!arg) {
	error:
		fr_value_box_clear_value(vb);
		return -1;
	}

	/*
	 *	Escaping functions work on strings - ensure the box is a string
	 */
	if ((vb->type != FR_TYPE_STRING) && (fr_value_box_cast_in_place(vb, vb, FR_TYPE_STRING, NULL) < 0)) goto error;

	/*
	 *	Maximum escaped length is 3 * original - if every character needs escaping
	 */
	if (!fr_sbuff_init_talloc(vb, &sbuff, &sbuff_ctx, vb->vb_length * 3, vb->vb_length * 3)) {
		fr_strerror_printf_push("Failed to allocate buffer for escaped sql argument");
		return -1;
	}

	len = inst->sql_escape_func(request, fr_sbuff_buff(&sbuff), vb->vb_length * 3 + 1, vb->vb_strvalue, arg);
	if (len < 0) goto error;

	fr_sbuff_trim_talloc(&sbuff, len);
	fr_value_box_strdup_shallow_replace(vb, fr_sbuff_buff(&sbuff), len);

	/*
	 *	Different databases have slightly different ideas as
	 *	to what is safe.  So we track the database type in the
	 *	safe value.  This means that we don't
	 *	cross-contaminate "safe" values across databases.
	 */
	fr_value_box_mark_safe_for(vb, inst->driver);

	return 0;
}

static int sql_box_escape(fr_value_box_t *vb, void *uctx)
{
	return sql_xlat_escape(NULL, vb, uctx);
}

/** Escape a value to make it SQL safe.
 *
@verbatim
%sql.escape(<value>)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t sql_escape_xlat(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
				     request_t *request, fr_value_box_list_t *in)
{
	rlm_sql_t const		*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_sql_t);
	fr_value_box_t		*vb;
	rlm_sql_escape_uctx_t	*escape_uctx = NULL;

	while ((vb = fr_value_box_list_pop_head(in))) {
		if (fr_value_box_is_safe_for(vb, inst->driver)) goto append;
		if (!escape_uctx) escape_uctx = sql_escape_uctx_alloc(request, inst);
		sql_box_escape(vb, escape_uctx);
	append:
		fr_dcursor_append(out, vb);
	}
	return XLAT_ACTION_DONE;
}

static xlat_action_t sql_xlat_query_resume(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
					   request_t *request, UNUSED fr_value_box_list_t *in)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(xctx->rctx, fr_sql_query_t);
	rlm_sql_t const		*inst = query_ctx->inst;
	fr_value_box_t		*vb;
	xlat_action_t		ret = XLAT_ACTION_DONE;
	int			numaffected;

	fr_assert(query_ctx->type == SQL_QUERY_OTHER);

	switch (query_ctx->rcode) {
	case RLM_SQL_QUERY_INVALID:
	case RLM_SQL_ERROR:
	case RLM_SQL_RECONNECT:
		RERROR("SQL query failed: %s", fr_table_str_by_value(sql_rcode_description_table,
								     query_ctx->rcode, "<INVALID>"));
		rlm_sql_print_error(inst, request, query_ctx, false);
		ret = XLAT_ACTION_FAIL;
		goto finish;

	default:
		break;
	}

	numaffected = (inst->driver->sql_affected_rows)(query_ctx, &inst->config);
	if (numaffected < 1) {
		RDEBUG2("SQL query affected no rows");
		numaffected = 0;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_uint32(vb, NULL, (uint32_t)numaffected, false);
	fr_dcursor_append(out, vb);

finish:
	talloc_free(query_ctx);

	return ret;
}

static xlat_action_t sql_xlat_select_resume(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
					    request_t *request, UNUSED fr_value_box_list_t *in)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(xctx->rctx, fr_sql_query_t);
	rlm_sql_t const		*inst = query_ctx->inst;
	fr_value_box_t		*vb;
	xlat_action_t		ret = XLAT_ACTION_DONE;
	unlang_result_t		p_result;
	rlm_sql_row_t		row;
	bool			fetched = false;

	fr_assert(query_ctx->type == SQL_QUERY_SELECT);

	if (query_ctx->rcode != RLM_SQL_OK) {
	query_error:
		RERROR("SQL query failed: %s", fr_table_str_by_value(sql_rcode_description_table,
								     query_ctx->rcode, "<INVALID>"));
		rlm_sql_print_error(inst, request, query_ctx, false);
		ret = XLAT_ACTION_FAIL;
		goto finish;
	}

	do {
		inst->fetch_row(&p_result, request, query_ctx);
		row = query_ctx->row;
		switch (query_ctx->rcode) {
		case RLM_SQL_OK:
			if (row[0]) break;

			RDEBUG2("NULL value in first column of result");
			goto finish;

		case RLM_SQL_NO_MORE_ROWS:
			if (!fetched) RDEBUG2("SQL query returned no results");
			goto finish;

		default:
			goto query_error;
		}

		fetched = true;

		MEM(vb = fr_value_box_alloc_null(ctx));
		fr_value_box_strdup(vb, vb, NULL, row[0], false);
		fr_dcursor_append(out, vb);

	} while (1);

finish:
	talloc_free(query_ctx);

	return ret;
}

/** Execute an arbitrary SQL query
 *
 * For SELECTs, the values of the first column will be returned.
 * For INSERTS, UPDATEs and DELETEs, the number of rows affected will
 * be returned instead.
 *
@verbatim
%sql(<sql statement>)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t sql_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
			      xlat_ctx_t const *xctx,
			      request_t *request, fr_value_box_list_t *in)
{
	sql_xlat_call_env_t	*call_env = talloc_get_type_abort(xctx->env_data, sql_xlat_call_env_t);
	rlm_sql_t const		*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_sql_t);
	rlm_sql_thread_t	*thread = talloc_get_type_abort(xctx->mctx->thread, rlm_sql_thread_t);
	char const		*p;
	fr_value_box_t		*arg = fr_value_box_list_head(in);
	fr_sql_query_t		*query_ctx = NULL;
	unlang_action_t		query_ret = UNLANG_ACTION_CALCULATE_RESULT;

	if (call_env->filename.type == FR_TYPE_STRING && call_env->filename.vb_length > 0) {
		rlm_sql_query_log(inst, call_env->filename.vb_strvalue, arg->vb_strvalue);
	}

	p = arg->vb_strvalue;

	/*
	 *	Trim whitespace for the prefix check
	 */
	fr_skip_whitespace(p);

	/*
	 *	If the query starts with any of the following prefixes,
	 *	then return the number of rows affected
	 */
	if ((strncasecmp(p, "insert", 6) == 0) ||
	    (strncasecmp(p, "update", 6) == 0) ||
	    (strncasecmp(p, "delete", 6) == 0)) {
		MEM(query_ctx = fr_sql_query_alloc(unlang_interpret_frame_talloc_ctx(request), inst, request,
						   thread->trunk, arg->vb_strvalue, SQL_QUERY_OTHER));

		unlang_xlat_yield(request, sql_xlat_query_resume, NULL, 0, query_ctx);

		/* Modify current frame's rcode directly */
		query_ret = inst->query(unlang_interpret_result(request), request, query_ctx);
		if (query_ret == UNLANG_ACTION_PUSHED_CHILD) return XLAT_ACTION_PUSH_UNLANG;

		return sql_xlat_query_resume(ctx, out, &(xlat_ctx_t){.rctx = query_ctx, .inst = inst}, request, in);
	} /* else it's a SELECT statement */

	MEM(query_ctx = fr_sql_query_alloc(unlang_interpret_frame_talloc_ctx(request), inst, request,
					   thread->trunk, arg->vb_strvalue, SQL_QUERY_SELECT));

	unlang_xlat_yield(request, sql_xlat_select_resume, NULL, 0, query_ctx);

	if (unlang_function_push_with_result(/* discard, sql_xlat_select_resume just uses query_ctx->rcode */ NULL,
					     request,
					     inst->select,
					     NULL,
					     NULL, 0,
					     UNLANG_SUB_FRAME, query_ctx) == UNLANG_ACTION_FAIL) return XLAT_ACTION_FAIL;
	return XLAT_ACTION_PUSH_UNLANG;
}

/** Execute an arbitrary SQL query, expecting results to be returned
 *
@verbatim
%sql.fetch(<sql statement>)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t sql_fetch_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out, xlat_ctx_t const *xctx,
				    request_t *request, fr_value_box_list_t *in)
{
	sql_xlat_call_env_t	*call_env = talloc_get_type_abort(xctx->env_data, sql_xlat_call_env_t);
	rlm_sql_t const		*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_sql_t);
	rlm_sql_thread_t	*thread = talloc_get_type_abort(xctx->mctx->thread, rlm_sql_thread_t);
	fr_value_box_t		*arg = fr_value_box_list_head(in);
	fr_sql_query_t		*query_ctx = NULL;

	if (call_env->filename.type == FR_TYPE_STRING && call_env->filename.vb_length > 0) {
		rlm_sql_query_log(inst, call_env->filename.vb_strvalue, arg->vb_strvalue);
	}

	MEM(query_ctx = fr_sql_query_alloc(unlang_interpret_frame_talloc_ctx(request), inst, request,
					   thread->trunk, arg->vb_strvalue, SQL_QUERY_SELECT));

	unlang_xlat_yield(request, sql_xlat_select_resume, NULL, 0, query_ctx);
	if (unlang_function_push_with_result(/* discard, sql_xlat_select_resume just uses query_ctx->rcode */NULL,
					     request,
					     inst->select,
					     NULL,
					     NULL, 0,
					     UNLANG_SUB_FRAME, query_ctx) != UNLANG_ACTION_PUSHED_CHILD) return XLAT_ACTION_FAIL;
	return XLAT_ACTION_PUSH_UNLANG;
}

/** Execute an arbitrary SQL query, returning the number of rows affected
 *
@verbatim
%sql.modify(<sql statement>)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t sql_modify_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
				     request_t *request, fr_value_box_list_t *in)
{
	sql_xlat_call_env_t	*call_env = talloc_get_type_abort(xctx->env_data, sql_xlat_call_env_t);
	rlm_sql_t const		*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_sql_t);
	rlm_sql_thread_t	*thread = talloc_get_type_abort(xctx->mctx->thread, rlm_sql_thread_t);
	fr_value_box_t		*arg = fr_value_box_list_head(in);
	fr_sql_query_t		*query_ctx = NULL;

	if (call_env->filename.type == FR_TYPE_STRING && call_env->filename.vb_length > 0) {
		rlm_sql_query_log(inst, call_env->filename.vb_strvalue, arg->vb_strvalue);
	}

	MEM(query_ctx = fr_sql_query_alloc(unlang_interpret_frame_talloc_ctx(request), inst, request,
					   thread->trunk, arg->vb_strvalue, SQL_QUERY_OTHER));

	unlang_xlat_yield(request, sql_xlat_query_resume, NULL, 0, query_ctx);
	/* Write out the result directly to this frame's rcode */
	if (inst->query(unlang_interpret_result(request), request, query_ctx) == UNLANG_ACTION_PUSHED_CHILD) return XLAT_ACTION_PUSH_UNLANG;

	return sql_xlat_query_resume(ctx, out, &(xlat_ctx_t){.rctx = query_ctx, .inst = inst}, request, in);
}

/** Converts a string value into a #fr_pair_t
 *
 * @param[in,out] ctx to allocate #fr_pair_t (s).
 * @param[out] out where to write the resulting #fr_pair_t.
 * @param[in] request The current request.
 * @param[in] map to process.
 * @param[in] uctx The value to parse.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int _sql_map_proc_get_value(TALLOC_CTX *ctx, fr_pair_list_t *out,
				   request_t *request, map_t const *map, void *uctx)
{
	fr_pair_t	*vp;
	char const	*value = uctx;

	vp = fr_pair_afrom_da(ctx, tmpl_attr_tail_da(map->lhs));
	if (!vp) return -1;

	/*
	 *	Buffer not always talloced, sometimes it's
	 *	just a pointer to a field in a result struct.
	 */
	if (fr_pair_value_from_str(vp, value, strlen(value), NULL, true) < 0) {
		RPEDEBUG("Failed parsing value \"%pV\" for attribute %s",
			 fr_box_strvalue_buffer(value), vp->da->name);
		talloc_free(vp);
		return -1;
	}
	fr_pair_append(out, vp);

	return 0;
}

/*
 *	Verify the result of the map.
 */
static int sql_map_verify(CONF_SECTION *cs, UNUSED void const *mod_inst, UNUSED void *proc_inst,
			  tmpl_t const *src, UNUSED map_list_t const *maps)
{
	if (!src) {
		cf_log_err(cs, "Missing SQL query");

		return -1;
	}

	return 0;
}

#define MAX_SQL_FIELD_INDEX (64)

/** Process the results of an SQL map query
 *
 * @param p_result	Result of map expansion:
 *			- #RLM_MODULE_NOOP no rows were returned or columns matched.
 *			- #RLM_MODULE_UPDATED if one or more #fr_pair_t were added to the #request_t.
 *			- #RLM_MODULE_FAIL if a fault occurred.
 * @param mpctx		Map context, containing the module instance.
 * @param request	The current request.
 * @param query		string to execute.
 * @param maps		Head of the map list.
 * @return UNLANG_ACTION_CALCULATE_RESULT
 */
static unlang_action_t mod_map_resume(unlang_result_t *p_result, map_ctx_t const *mpctx, request_t *request,
				      UNUSED fr_value_box_list_t *query, map_list_t const *maps)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(mpctx->rctx, fr_sql_query_t);
	rlm_sql_t const		*inst = mpctx->moi;
	map_t const		*map;
	rlm_rcode_t		rcode = RLM_MODULE_UPDATED;
	sql_rcode_t		ret;
	char const		**fields = NULL, *map_rhs;
	rlm_sql_row_t		row;
	int			i, j, field_cnt, rows = 0;
	int			field_index[MAX_SQL_FIELD_INDEX];
	char			map_rhs_buff[128];
	bool			found_field = false;	/* Did we find any matching fields in the result set ? */

	if (query_ctx->rcode != RLM_SQL_OK) {
		RERROR("SQL query failed: %s", fr_table_str_by_value(sql_rcode_description_table, query_ctx->rcode, "<INVALID>"));
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	/*
	 *	Not every driver provides an sql_num_rows function
	 */
	if (inst->driver->sql_num_rows) {
		ret = inst->driver->sql_num_rows(query_ctx, &inst->config);
		if (ret == 0) {
			RDEBUG2("Server returned an empty result");
			rcode = RLM_MODULE_NOTFOUND;
			goto finish;
		}

		if (ret < 0) {
			RERROR("Failed retrieving row count");
		error:
			rcode = RLM_MODULE_FAIL;
			goto finish;
		}
	}

	for (i = 0; i < MAX_SQL_FIELD_INDEX; i++) field_index[i] = -1;

	/*
	 *	Map proc only registered if driver provides an sql_fields function
	 */
	ret = (inst->driver->sql_fields)(&fields, query_ctx, &inst->config);
	if (ret != RLM_SQL_OK) {
		RERROR("Failed retrieving field names: %s", fr_table_str_by_value(sql_rcode_description_table, ret, "<INVALID>"));
		goto error;
	}
	fr_assert(fields);
	field_cnt = talloc_array_length(fields);

	if (RDEBUG_ENABLED3) for (j = 0; j < field_cnt; j++) RDEBUG3("Got field: %s", fields[j]);

	/*
	 *	Iterate over the maps, it's O(N2)ish but probably
	 *	faster than building a radix tree each time the
	 *	map set is evaluated (map->rhs can be dynamic).
	 */
	for (map = map_list_head(maps), i = 0;
	     map && (i < MAX_SQL_FIELD_INDEX);
	     map = map_list_next(maps, map), i++) {
		/*
		 *	Expand the RHS to get the name of the SQL field
		 */
		if (tmpl_expand(&map_rhs, map_rhs_buff, sizeof(map_rhs_buff),
				request, map->rhs) < 0) {
			RPERROR("Failed getting field name");
			goto error;
		}

		for (j = 0; j < field_cnt; j++) {
			if (strcasecmp(fields[j], map_rhs) != 0) continue;
			field_index[i] = j;
			found_field = true;
		}
	}

	/*
	 *	Couldn't resolve any map RHS values to fields
	 *	in the result set.
	 */
	if (!found_field) {
		RDEBUG2("No fields matching map found in query result");
		rcode = RLM_MODULE_NOOP;
		goto finish;
	}

	/*
	 *	We've resolved all the maps to result indexes, now convert
	 *	the values at those indexes into fr_pair_ts.
	 *
	 *	Note: Not all SQL client libraries provide a row count,
	 *	so we have to do the count here.
	 */
	while ((inst->fetch_row(p_result, request, query_ctx) == UNLANG_ACTION_CALCULATE_RESULT) &&
	       (query_ctx->rcode == RLM_SQL_OK)) {
		row = query_ctx->row;
		rows++;
		for (map = map_list_head(maps), j = 0;
		     map && (j < MAX_SQL_FIELD_INDEX);
		     map = map_list_next(maps, map), j++) {
			if (field_index[j] < 0) continue;	/* We didn't find the map RHS in the field set */
			if (!row[field_index[j]]) {
				RDEBUG2("Database returned NULL for %s", fields[j]);
				continue;
			}
			if (map_to_request(request, map, _sql_map_proc_get_value, row[field_index[j]]) < 0) goto error;
		}
	}

	if (query_ctx->rcode == RLM_SQL_ERROR) goto error;

	if (rows == 0) {
		RDEBUG2("SQL query returned no results");
		rcode = RLM_MODULE_NOTFOUND;
	}

finish:
	talloc_free(fields);
	talloc_free(query_ctx);

	RETURN_UNLANG_RCODE(rcode);
}

/** Executes a SELECT query and maps the result to server attributes
 *
 * @param p_result	Result of map expansion:
 *			- #RLM_MODULE_NOOP no rows were returned or columns matched.
 *			- #RLM_MODULE_UPDATED if one or more #fr_pair_t were added to the #request_t.
 *			- #RLM_MODULE_FAIL if a fault occurred.
 * @param mpctx		Map context, containing the module instance.
 * @param request	The current request.
 * @param query		string to execute.
 * @param maps		Head of the map list.
 * @return UNLANG_ACTION_CALCULATE_RESULT
 */
static unlang_action_t mod_map_proc(unlang_result_t *p_result, map_ctx_t const *mpctx, request_t *request,
				    fr_value_box_list_t *query, UNUSED map_list_t const *maps)
{
	rlm_sql_t const		*inst = talloc_get_type_abort_const(mpctx->moi, rlm_sql_t);
	rlm_sql_thread_t	*thread = talloc_get_type_abort(module_thread(inst->mi)->data, rlm_sql_thread_t);
	fr_value_box_t		*query_head = fr_value_box_list_head(query);
	fr_sql_query_t		*query_ctx = NULL;
	fr_value_box_t		*vb = NULL;
	rlm_sql_escape_uctx_t	*escape_uctx = NULL;

	fr_assert(inst->driver->sql_fields);		/* Should have been caught during validation... */

	if (!query_head) {
		REDEBUG("Query cannot be (null)");
		RETURN_UNLANG_FAIL;
	}

	while ((vb = fr_value_box_list_next(query, vb))) {
		if (fr_value_box_is_safe_for(vb, inst->driver)) continue;
		if (!escape_uctx) escape_uctx = sql_escape_uctx_alloc(request, inst);
		sql_box_escape(vb, escape_uctx);
	}

	if (fr_value_box_list_concat_in_place(request,
					      query_head, query, FR_TYPE_STRING,
					      FR_VALUE_BOX_LIST_FREE, true,
					      SIZE_MAX) < 0) {
		RPEDEBUG("Failed concatenating input string");
		RETURN_UNLANG_FAIL;
	}

	query_ctx = fr_sql_query_alloc(unlang_interpret_frame_talloc_ctx(request), inst, request,
				       thread->trunk, query_head->vb_strvalue, SQL_QUERY_SELECT);

	if (unlang_map_yield(request, mod_map_resume, NULL, 0, query_ctx) != UNLANG_ACTION_YIELD) RETURN_UNLANG_FAIL;
	return unlang_function_push_with_result(/* discard, mod_map_resume just uses query_ctx->rcode */ NULL,
						request,
						inst->select,
						NULL,
						NULL,
						0, UNLANG_SUB_FRAME,
						query_ctx);
}

/** xlat escape function for drivers which do not provide their own
 *
 */
static ssize_t sql_escape_func(UNUSED request_t *request, char *out, size_t outlen, char const *in, void *arg)
{
	rlm_sql_t const		*inst = talloc_get_type_abort_const(arg, rlm_sql_t);
	size_t			len = 0;

	while (in[0]) {
		size_t utf8_len;

		/*
		 *	Allow all multi-byte UTF8 characters.
		 */
		utf8_len = fr_utf8_char((uint8_t const *) in, -1);
		if (utf8_len > 1) {
			if (outlen <= utf8_len) break;

			memcpy(out, in, utf8_len);
			in += utf8_len;
			out += utf8_len;

			outlen -= utf8_len;
			len += utf8_len;
			continue;
		}

		/*
		 *	Because we register our own escape function
		 *	we're now responsible for escaping all special
		 *	chars in an xlat expansion or attribute value.
		 */
		switch (in[0]) {
		case '\n':
			if (outlen <= 2) break;
			out[0] = '\\';
			out[1] = 'n';

			in++;
			out += 2;
			outlen -= 2;
			len += 2;
			break;

		case '\r':
			if (outlen <= 2) break;
			out[0] = '\\';
			out[1] = 'r';

			in++;
			out += 2;
			outlen -= 2;
			len += 2;
			break;

		case '\t':
			if (outlen <= 2) break;
			out[0] = '\\';
			out[1] = 't';

			in++;
			out += 2;
			outlen -= 2;
			len += 2;
			break;
		}

		/*
		 *	Non-printable characters get replaced with their
		 *	mime-encoded equivalents.
		 */
		if ((in[0] < 32) ||
		    strchr(inst->config.allowed_chars, *in) == NULL) {
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

/*
 *	Set the SQL user name.
 *
 *	We don't call the escape function here. The resulting string
 *	will be escaped later in the queries xlat so we don't need to
 *	escape it twice. (it will make things wrong if we have an
 *	escape candidate character in the username)
 */
static void sql_set_user(rlm_sql_t const *inst, request_t *request, fr_value_box_t *user)
{
	fr_pair_t *vp = NULL;

	fr_assert(request->packet != NULL);

	MEM(pair_update_request(&vp, inst->sql_user) >= 0);
	if(!user || (user->type != FR_TYPE_STRING)) {
		pair_delete_request(vp);
		return;
	}

	/*
	 *	Replace any existing SQL-User-Name with new value
	 */
	fr_pair_value_bstrdup_buffer(vp, user->vb_strvalue, user->tainted);
	RDEBUG2("SQL-User-Name set to '%pV'", &vp->data);
}

/*
 *	Do a set/unset user, so it's a bit clearer what's going on.
 */
#define sql_unset_user(_i, _r) fr_pair_delete_by_da(&_r->request_pairs, _i->sql_user)


struct rlm_sql_grouplist_s {
	char			*name;
	rlm_sql_grouplist_t	*next;
};

static unlang_action_t sql_get_grouplist_resume(unlang_result_t *p_result, request_t *request, void *uctx)
{
	sql_group_ctx_t		*group_ctx = talloc_get_type_abort(uctx, sql_group_ctx_t);
	fr_sql_query_t		*query_ctx = group_ctx->query_ctx;
	rlm_sql_t const		*inst = group_ctx->inst;
	rlm_sql_row_t		row;
	rlm_sql_grouplist_t	*entry = group_ctx->groups;

	if (query_ctx->rcode != RLM_SQL_OK) {
	error:
		rlm_sql_print_error(inst, request, query_ctx, false);
		talloc_free(query_ctx);
		RETURN_UNLANG_FAIL;
	}

	while ((inst->fetch_row(p_result, request, query_ctx) == UNLANG_ACTION_CALCULATE_RESULT) &&
		(query_ctx->rcode == RLM_SQL_OK)) {
		row = query_ctx->row;
		if (!row[0]){
			RDEBUG2("row[0] returned NULL");
			goto error;
		}

		if (!entry) {
			group_ctx->groups = talloc_zero(group_ctx, rlm_sql_grouplist_t);
			entry = group_ctx->groups;
		} else {
			entry->next = talloc_zero(group_ctx, rlm_sql_grouplist_t);
			entry = entry->next;
		}
		entry->next = NULL;
		entry->name = talloc_typed_strdup(entry, row[0]);

		group_ctx->num_groups++;
	}

	talloc_free(query_ctx);
	RETURN_UNLANG_OK;
}

static unlang_action_t sql_get_grouplist(unlang_result_t *p_result, sql_group_ctx_t *group_ctx, trunk_t *trunk, request_t *request)
{
	rlm_sql_t const		*inst = group_ctx->inst;

	/* NOTE: sql_set_user should have been run before calling this function */

	if (!group_ctx->query || (group_ctx->query->vb_length == 0)) return UNLANG_ACTION_CALCULATE_RESULT;

	MEM(group_ctx->query_ctx = fr_sql_query_alloc(group_ctx, inst, request, trunk,
						      group_ctx->query->vb_strvalue, SQL_QUERY_SELECT));

	if (unlang_function_push_with_result(/* sql_get_grouplist_resume translates the query_ctx->rocde into a module rcode */p_result,
					     request,
				 NULL,
				 sql_get_grouplist_resume,
				 NULL,
				 0, UNLANG_SUB_FRAME,
				 group_ctx) < 0) return UNLANG_ACTION_FAIL;

	return unlang_function_push_with_result(/* discard, sql_get_grouplist_resume translates rcodes */NULL,
						request,
						inst->select,
						NULL,
						NULL, 0,
						UNLANG_SUB_FRAME, group_ctx->query_ctx);
}

typedef struct {
	fr_value_box_list_t	query;
	sql_group_ctx_t		*group_ctx;
} sql_group_xlat_ctx_t;

/**  Compare list of groups returned from SQL query to xlat argument.
 *
 * Called after the SQL query has completed and group list has been built.
 */
static xlat_action_t sql_group_xlat_query_resume(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
						 UNUSED request_t *request, fr_value_box_list_t *in)
{
	sql_group_xlat_ctx_t	*xlat_ctx = talloc_get_type_abort(xctx->rctx, sql_group_xlat_ctx_t);
	sql_group_ctx_t		*group_ctx = talloc_get_type_abort(xlat_ctx->group_ctx, sql_group_ctx_t);
	fr_value_box_t		*arg = fr_value_box_list_head(in);
	char const		*name = arg->vb_strvalue;
	fr_value_box_t		*vb;
	rlm_sql_grouplist_t	*entry;

	fr_skip_whitespace(name);

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, attr_expr_bool_enum));
	for (entry = group_ctx->groups; entry != NULL; entry = entry->next) {
		if (strcmp(entry->name, name) == 0) {
			vb->vb_bool = true;
			break;
		}
	}
	fr_dcursor_append(out, vb);

	talloc_free(xlat_ctx);

	return XLAT_ACTION_DONE;
}

/** Run SQL query for group membership to return list of groups
 *
 * Called after group membership query tmpl is expanded
 */
static xlat_action_t sql_group_xlat_resume(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out, xlat_ctx_t const *xctx,
					   request_t *request, UNUSED fr_value_box_list_t *in)
{
	sql_group_xlat_ctx_t	*xlat_ctx = talloc_get_type_abort(xctx->rctx, sql_group_xlat_ctx_t);
	rlm_sql_t const		*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_sql_t);
	rlm_sql_thread_t	*thread = talloc_get_type_abort(xctx->mctx->thread, rlm_sql_thread_t);
	fr_value_box_t		*query;

	query = fr_value_box_list_head(&xlat_ctx->query);
	if (!query) return XLAT_ACTION_FAIL;

	MEM(xlat_ctx->group_ctx = talloc(xlat_ctx, sql_group_ctx_t));

	*xlat_ctx->group_ctx = (sql_group_ctx_t) {
		.inst = inst,
		.query = query,
	};

	if (unlang_xlat_yield(request, sql_group_xlat_query_resume, NULL, 0, xlat_ctx) != XLAT_ACTION_YIELD) return XLAT_ACTION_FAIL;

	if (sql_get_grouplist(NULL, xlat_ctx->group_ctx, thread->trunk, request) != UNLANG_ACTION_PUSHED_CHILD) {
		return XLAT_ACTION_FAIL;
	}

	return XLAT_ACTION_PUSH_UNLANG;
}


/** Check if the user is a member of a particular group
 *
@verbatim
%sql.group(<name>)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t sql_group_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out, xlat_ctx_t const *xctx,
				    request_t *request, UNUSED fr_value_box_list_t *in)
{
	sql_group_xlat_call_env_t	*call_env = talloc_get_type_abort(xctx->env_data, sql_group_xlat_call_env_t);
	sql_group_xlat_ctx_t		*xlat_ctx;
	rlm_sql_t const			*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_sql_t);

	if (!call_env->membership_query) {
		RWARN("Cannot check group membership - group_membership_query not set");
		return XLAT_ACTION_FAIL;
	}

	/*
	 *	Set the user attr here
	 */
	sql_set_user(inst, request, &call_env->user);

	MEM(xlat_ctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), sql_group_xlat_ctx_t));
	fr_value_box_list_init(&xlat_ctx->query);

	if (unlang_xlat_yield(request, sql_group_xlat_resume, NULL, 0, xlat_ctx) != XLAT_ACTION_YIELD) return XLAT_ACTION_FAIL;
	if (unlang_tmpl_push(xlat_ctx, NULL, &xlat_ctx->query, request, call_env->membership_query, NULL, UNLANG_SUB_FRAME) < 0) return XLAT_ACTION_FAIL;
	return XLAT_ACTION_PUSH_UNLANG;
}

/**  Process a "check" map
 *
 * Any entries using an assignment operator will be moved to the reply map
 * for later merging into the request.
 *
 * @param request	Current request.
 * @param check_map	to process.
 * @param reply_map	where any assignment entries will be moved.
 * @return
 *	- 0 if all the check entries pass.
 *	- -1 if the checks fail.
 */
static int check_map_process(request_t *request, map_list_t *check_map, map_list_t *reply_map)
{
	map_t *map, *next;

	for (map = map_list_head(check_map);
	     map != NULL;
	     map = next) {
		next = map_list_next(check_map, map);

		if (fr_assignment_op[map->op]) {
			(void) map_list_remove(check_map, map);
			map_list_insert_tail(reply_map, map);
			continue;
		}

		if (!fr_comparison_op[map->op]) {
			REDEBUG("Invalid operator '%s'", fr_tokens[map->op]);
			goto fail;
		}

		if (fr_type_is_structural(tmpl_attr_tail_da(map->lhs)->type) &&
		    (map->op != T_OP_CMP_TRUE) && (map->op != T_OP_CMP_FALSE)) {
			REDEBUG("Invalid comparison for structural type");
			goto fail;
		}

		RDEBUG2("    &%s %s %s", map->lhs->name, fr_tokens[map->op], map->rhs->name);
		if (radius_legacy_map_cmp(request, map) != 1) {
		fail:
			map_list_talloc_free(check_map);
			map_list_talloc_free(reply_map);
			RDEBUG2("failed match: skipping this entry");
			return -1;
		}
	}
	return 0;
}

static int sql_autz_ctx_free(sql_autz_ctx_t *to_free)
{
	if (!to_free->inst->sql_escape_arg) (void) request_data_get(to_free->request, (void *)sql_escape_uctx_alloc, 0);
	map_list_talloc_free(&to_free->check_tmp);
	map_list_talloc_free(&to_free->reply_tmp);
	sql_unset_user(to_free->inst, to_free->request);

	return 0;
}

/** Resume function called after authorization group / profile expansion of check / reply query tmpl
 *
 * Groups and profiles are treated almost identically except:
 *   - groups are read from an SQL query
 *   - profiles are read from &control.User-Profile
 *   - if `cache_groups` is set, groups populate &control.SQL-Group
 *
 * Profiles are handled after groups, and will not happend if the last group resulted in `Fall-Through = no`
 *
 * Before each query is run, &request.SQL-Group is populated with the value of the group being evaluated.
 *
 * @param p_result	Result of current authorization.
 * @param mctx		Current request.
 * @param request	Current authorization context.
 * @return one of the RLM_MODULE_* values.
 */
static unlang_action_t CC_HINT(nonnull)  mod_autz_group_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	sql_autz_ctx_t		*autz_ctx = talloc_get_type_abort(mctx->rctx, sql_autz_ctx_t);
	sql_autz_call_env_t	*call_env = autz_ctx->call_env;
	sql_group_ctx_t		*group_ctx = autz_ctx->group_ctx;
	fr_sql_map_ctx_t	*map_ctx = autz_ctx->map_ctx;
	rlm_sql_t const		*inst = autz_ctx->inst;
	fr_value_box_t		*query = fr_value_box_list_pop_head(&autz_ctx->query);
	sql_fall_through_t	do_fall_through = FALL_THROUGH_DEFAULT;
	fr_pair_t		*vp;

	switch (p_result->rcode) {
	case RLM_MODULE_USER_SECTION_REJECT:
		return UNLANG_ACTION_CALCULATE_RESULT;

	default:
		break;
	}

	switch(autz_ctx->status) {
	case SQL_AUTZ_GROUP_MEMB:
		if (!query) RETURN_UNLANG_FAIL;
		if (unlang_module_yield(request, mod_autz_group_resume, NULL, 0, mctx->rctx) == UNLANG_ACTION_FAIL) RETURN_UNLANG_FAIL;
		MEM(autz_ctx->group_ctx = talloc(autz_ctx, sql_group_ctx_t));
		*autz_ctx->group_ctx = (sql_group_ctx_t) {
			.inst = inst,
			.query = query,
		};

		if (sql_get_grouplist(p_result, autz_ctx->group_ctx, autz_ctx->trunk, request) == UNLANG_ACTION_PUSHED_CHILD) {
			autz_ctx->status = SQL_AUTZ_GROUP_MEMB_RESUME;
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		group_ctx = autz_ctx->group_ctx;

		FALL_THROUGH;

	case SQL_AUTZ_GROUP_MEMB_RESUME:
		talloc_free(group_ctx->query);

		if (group_ctx->num_groups == 0) {
			RDEBUG2("User not found in any groups");
			break;
		}
		fr_assert(group_ctx->groups);

		RDEBUG2("User found in the group table");
		autz_ctx->user_found = true;
		autz_ctx->group = group_ctx->groups;
		MEM(pair_update_request(&autz_ctx->sql_group, inst->group_da) >= 0);

	next_group:
		fr_pair_value_strdup(autz_ctx->sql_group, autz_ctx->group->name, true);
		autz_ctx->status = SQL_AUTZ_GROUP_CHECK;
		FALL_THROUGH;

	case SQL_AUTZ_PROFILE_START:
	next_profile:
		if (autz_ctx->status & SQL_AUTZ_STAGE_PROFILE) {
			fr_pair_value_strdup(autz_ctx->sql_group, autz_ctx->profile->vp_strvalue, true);
			autz_ctx->status = SQL_AUTZ_PROFILE_CHECK;
		}
		RDEBUG3("Processing %s %pV",
			autz_ctx->status & SQL_AUTZ_STAGE_GROUP ? "group" : "profile", &autz_ctx->sql_group->data);
		if (inst->config.cache_groups && autz_ctx->status & SQL_AUTZ_STAGE_GROUP) {
			MEM(pair_append_control(&vp, inst->group_da) >= 0);
			fr_pair_value_strdup(vp, autz_ctx->group->name, true);
		}

		if (call_env->group_check_query) {
			if (unlang_module_yield(request, mod_autz_group_resume, NULL, 0, mctx->rctx) == UNLANG_ACTION_FAIL) RETURN_UNLANG_FAIL;
			if (unlang_tmpl_push(autz_ctx, NULL, &autz_ctx->query, request,
					     call_env->group_check_query, NULL, UNLANG_SUB_FRAME) < 0) RETURN_UNLANG_FAIL;
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		if (call_env->group_reply_query) goto group_reply_push;

		break;

	case SQL_AUTZ_GROUP_CHECK:
	case SQL_AUTZ_PROFILE_CHECK:
		if (!query) RETURN_UNLANG_FAIL;
		*autz_ctx->map_ctx = (fr_sql_map_ctx_t) {
			.ctx = autz_ctx,
			.inst = inst,
			.out = &autz_ctx->check_tmp,
			.list = request_attr_request,
			.query = query,
		};

		if (unlang_module_yield(request, mod_autz_group_resume, NULL, 0, mctx->rctx) == UNLANG_ACTION_FAIL) RETURN_UNLANG_FAIL;
		if (sql_get_map_list(p_result, request, map_ctx, autz_ctx->trunk) == UNLANG_ACTION_PUSHED_CHILD) {
			autz_ctx->status = autz_ctx->status & SQL_AUTZ_STAGE_GROUP ? SQL_AUTZ_GROUP_CHECK_RESUME : SQL_AUTZ_PROFILE_CHECK_RESUME;
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		FALL_THROUGH;

	case SQL_AUTZ_GROUP_CHECK_RESUME:
	case SQL_AUTZ_PROFILE_CHECK_RESUME:
		talloc_free(map_ctx->query);

		/*
		 *	If we got check rows we need to process them before we decide to
		 *	process the reply rows
		 */
		if (map_ctx->rows > 0) {
			if (check_map_process(request, &autz_ctx->check_tmp, &autz_ctx->reply_tmp) < 0) {
				map_list_talloc_free(&autz_ctx->check_tmp);
				goto next_group_find;
			}
			RDEBUG2("%s \"%pV\": Conditional check items matched",
				autz_ctx->status & SQL_AUTZ_STAGE_GROUP ? "Group" : "Profile", &autz_ctx->sql_group->data);
		} else {
			RDEBUG2("%s \"%pV\": Conditional check items matched (empty)",
				autz_ctx->status & SQL_AUTZ_STAGE_GROUP ? "Group" : "Profile", &autz_ctx->sql_group->data);
		}

		if (autz_ctx->rcode == RLM_MODULE_NOOP) autz_ctx->rcode = RLM_MODULE_OK;

		map_list_talloc_free(&autz_ctx->check_tmp);

		if (call_env->group_reply_query) {
		group_reply_push:
			if (unlang_module_yield(request, mod_autz_group_resume, NULL, 0, mctx->rctx) == UNLANG_ACTION_FAIL) RETURN_UNLANG_FAIL;
			if (unlang_tmpl_push(autz_ctx, NULL, &autz_ctx->query, request,
					     call_env->group_reply_query, NULL, UNLANG_SUB_FRAME) < 0) RETURN_UNLANG_FAIL;
			autz_ctx->status = autz_ctx->status & SQL_AUTZ_STAGE_GROUP ? SQL_AUTZ_GROUP_REPLY : SQL_AUTZ_PROFILE_REPLY;
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		if (map_list_num_elements(&autz_ctx->reply_tmp)) goto group_attr_cache;

		goto next_group_find;

	case SQL_AUTZ_GROUP_REPLY:
	case SQL_AUTZ_PROFILE_REPLY:
		if (!query) RETURN_UNLANG_FAIL;
		*autz_ctx->map_ctx = (fr_sql_map_ctx_t) {
			.ctx = autz_ctx,
			.inst = inst,
			.out = &autz_ctx->reply_tmp,
			.list = request_attr_reply,
			.query = query,
			.expand_rhs = true,
		};

		if (unlang_module_yield(request, mod_autz_group_resume, NULL, 0, mctx->rctx) == UNLANG_ACTION_FAIL) RETURN_UNLANG_FAIL;
		if (sql_get_map_list(p_result, request, map_ctx, autz_ctx->trunk) == UNLANG_ACTION_PUSHED_CHILD) {
			autz_ctx->status = autz_ctx->status & SQL_AUTZ_STAGE_GROUP ? SQL_AUTZ_GROUP_REPLY_RESUME : SQL_AUTZ_PROFILE_REPLY_RESUME;
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		FALL_THROUGH;

	case SQL_AUTZ_GROUP_REPLY_RESUME:
	case SQL_AUTZ_PROFILE_REPLY_RESUME:
		talloc_free(map_ctx->query);

		if (map_ctx->rows == 0) {
			do_fall_through = FALL_THROUGH_DEFAULT;
			goto group_attr_cache;
		}

		fr_assert(!map_list_empty(&autz_ctx->reply_tmp)); /* coverity, among others */
		do_fall_through = fall_through(&autz_ctx->reply_tmp);

	group_attr_cache:
		if (inst->config.cache_groups && autz_ctx->status & SQL_AUTZ_STAGE_GROUP) {
			MEM(pair_append_control(&vp, inst->group_da) >= 0);
			fr_pair_value_strdup(vp, autz_ctx->group->name, true);
		}

		if (map_list_num_elements(&autz_ctx->reply_tmp) == 0) goto next_group_find;
		RDEBUG2("%s \"%pV\": Merging control and reply items",
			autz_ctx->status & SQL_AUTZ_STAGE_GROUP ? "Group" : "Profile", &autz_ctx->sql_group->data);
		autz_ctx->rcode = RLM_MODULE_UPDATED;

		RINDENT();
		if (radius_legacy_map_list_apply(request, &autz_ctx->reply_tmp, NULL) < 0) {
			RPEDEBUG("Failed applying reply item");
			REXDENT();
			RETURN_UNLANG_FAIL;
		}
		REXDENT();
		map_list_talloc_free(&autz_ctx->reply_tmp);

	next_group_find:
		if (do_fall_through != FALL_THROUGH_YES) break;
		if (autz_ctx->status & SQL_AUTZ_STAGE_PROFILE) {
			autz_ctx->profile = fr_pair_find_by_da(&request->control_pairs, autz_ctx->profile, attr_user_profile);
			if (autz_ctx->profile) goto next_profile;
			break;
		}
		autz_ctx->group = autz_ctx->group->next;
		if (autz_ctx->group) goto next_group;

		break;

	default:
		fr_assert(0);
	}

	/*
	 *	If group processing has completed, check to see if profile processing should be done
	 */
	if ((autz_ctx->status & SQL_AUTZ_STAGE_GROUP) &&
	    ((do_fall_through == FALL_THROUGH_YES) ||
	     (inst->config.read_profiles && (do_fall_through == FALL_THROUGH_DEFAULT)))) {
		RDEBUG3("... falling-through to profile processing");

		autz_ctx->profile = fr_pair_find_by_da(&request->control_pairs, NULL, attr_user_profile);
		if (autz_ctx->profile) {
			MEM(pair_update_request(&autz_ctx->sql_group, inst->group_da) >= 0);
			autz_ctx->status = SQL_AUTZ_PROFILE_START;
			goto next_profile;
		}
	}

	if (!autz_ctx->user_found) RETURN_UNLANG_NOTFOUND;

	RETURN_UNLANG_RCODE(autz_ctx->rcode);
}

/** Resume function called after authorization check / reply tmpl expansion
 *
 * @param p_result	Result of current authorization.
 * @param mctx		Module call ctx.
 * @param request	Current request.
 * @return one of the RLM_MODULE_* values.
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	sql_autz_ctx_t		*autz_ctx = talloc_get_type_abort(mctx->rctx, sql_autz_ctx_t);
	sql_autz_call_env_t	*call_env = autz_ctx->call_env;
	rlm_sql_t const		*inst = autz_ctx->inst;
	fr_value_box_t		*query = fr_value_box_list_pop_head(&autz_ctx->query);
	sql_fall_through_t	do_fall_through = FALL_THROUGH_DEFAULT;
	fr_sql_map_ctx_t	*map_ctx = autz_ctx->map_ctx;

	/*
	 *	If a previous async call returned one of the "failure" results just return.
	 */
	switch (p_result->rcode) {
	case RLM_MODULE_USER_SECTION_REJECT:
		return UNLANG_ACTION_CALCULATE_RESULT;

	default:
		break;
	}

	switch(autz_ctx->status) {
	case SQL_AUTZ_CHECK:
		if (!query) RETURN_UNLANG_FAIL;
		*autz_ctx->map_ctx = (fr_sql_map_ctx_t) {
			.ctx = autz_ctx,
			.inst = inst,
			.out = &autz_ctx->check_tmp,
			.list = request_attr_request,
			.query = query,
		};

		if (unlang_module_yield(request, mod_authorize_resume, NULL, 0, autz_ctx) == UNLANG_ACTION_FAIL) RETURN_UNLANG_FAIL;
		if (sql_get_map_list(p_result, request, map_ctx, autz_ctx->trunk) == UNLANG_ACTION_PUSHED_CHILD){
			autz_ctx->status = SQL_AUTZ_CHECK_RESUME;
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		FALL_THROUGH;

	case SQL_AUTZ_CHECK_RESUME:
		talloc_free(map_ctx->query);

		if (map_ctx->rows == 0) goto skip_reply;	/* Don't need to handle map entries we don't have */

		/*
		 *	Only do this if *some* check pairs were returned
		 */
		RDEBUG2("User found in radcheck table");
		autz_ctx->user_found = true;

		if (check_map_process(request, &autz_ctx->check_tmp, &autz_ctx->reply_tmp) < 0) goto skip_reply;
		RDEBUG2("Conditional check items matched");

		autz_ctx->rcode = RLM_MODULE_OK;
		map_list_talloc_free(&autz_ctx->check_tmp);

		if (!call_env->reply_query) goto skip_reply;

		if (unlang_module_yield(request, mod_authorize_resume, NULL, 0, autz_ctx) == UNLANG_ACTION_FAIL) RETURN_UNLANG_FAIL;
		if (unlang_tmpl_push(autz_ctx, NULL, &autz_ctx->query, request, call_env->reply_query, NULL, UNLANG_SUB_FRAME) < 0) RETURN_UNLANG_FAIL;
		autz_ctx->status = SQL_AUTZ_REPLY;
		return UNLANG_ACTION_PUSHED_CHILD;

	case SQL_AUTZ_REPLY:
		if (!query) RETURN_UNLANG_FAIL;
		*autz_ctx->map_ctx = (fr_sql_map_ctx_t) {
			.ctx = autz_ctx,
			.inst = inst,
			.out = &autz_ctx->reply_tmp,
			.list = request_attr_reply,
			.query = query,
			.expand_rhs = true,
		};

		if (unlang_module_yield(request, mod_authorize_resume, NULL, 0, autz_ctx) == UNLANG_ACTION_FAIL) RETURN_UNLANG_FAIL;
		if (sql_get_map_list(p_result, request, map_ctx, autz_ctx->trunk) == UNLANG_ACTION_PUSHED_CHILD){
			autz_ctx->status = SQL_AUTZ_REPLY_RESUME;
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		FALL_THROUGH;

	case SQL_AUTZ_REPLY_RESUME:
		talloc_free(map_ctx->query);

		if (map_ctx->rows == 0) goto skip_reply;

		do_fall_through = fall_through(&autz_ctx->reply_tmp);

		RDEBUG2("User found in radreply table");
		autz_ctx->user_found = true;

	skip_reply:
		if (map_list_num_elements(&autz_ctx->reply_tmp)) {
			RDEBUG2("Merging control and reply items");
			RINDENT();
			if (radius_legacy_map_list_apply(request, &autz_ctx->reply_tmp, NULL) < 0) {
				RPEDEBUG("Failed applying item");
				REXDENT();
				RETURN_UNLANG_FAIL;
			}
			REXDENT();

			autz_ctx->rcode = RLM_MODULE_UPDATED;
			map_list_talloc_free(&autz_ctx->reply_tmp);
		}

		if ((do_fall_through == FALL_THROUGH_YES) ||
		    (inst->config.read_groups && (do_fall_through == FALL_THROUGH_DEFAULT))) {
			RDEBUG3("... falling-through to group processing");

			if (!call_env->membership_query) {
				RWARN("Cannot check groups when group_membership_query is not set");
				break;
			}

			if (!call_env->group_check_query && !call_env->group_reply_query) {
				RWARN("Cannot process groups when neither authorize_group_check_query nor authorize_group_check_query are set");
				break;
			}

			if (unlang_module_yield(request, mod_autz_group_resume, NULL, 0, autz_ctx) == UNLANG_ACTION_FAIL) RETURN_UNLANG_FAIL;
			if (unlang_tmpl_push(autz_ctx, NULL, &autz_ctx->query, request,
					     call_env->membership_query, NULL, UNLANG_SUB_FRAME) < 0) RETURN_UNLANG_FAIL;
			autz_ctx->status = SQL_AUTZ_GROUP_MEMB;
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		if ((do_fall_through == FALL_THROUGH_YES) ||
		    (inst->config.read_profiles && (do_fall_through == FALL_THROUGH_DEFAULT))) {
			RDEBUG3("... falling-through to profile processing");

			if (!call_env->group_check_query && !call_env->group_reply_query) {
				RWARN("Cannot process profiles when neither authorize_group_check_query nor authorize_group_check_query are set");
				break;
			}

			autz_ctx->profile = fr_pair_find_by_da(&request->control_pairs, NULL, attr_user_profile);
			if (!autz_ctx->profile) break;

			MEM(pair_update_request(&autz_ctx->sql_group, inst->group_da) >= 0);
			autz_ctx->status = SQL_AUTZ_PROFILE_START;
			return mod_autz_group_resume(p_result, mctx, request);
		}
		break;

	default:
		fr_assert_msg(0, "Invalid status %d in mod_authorize_resume", autz_ctx->status);
	}

	if (!autz_ctx->user_found) RETURN_UNLANG_NOTFOUND;
	RETURN_UNLANG_RCODE(autz_ctx->rcode);
}

/** Start of module authorize method
 *
 * Pushes the tmpl relating to the first required query for evaluation
 */
static unlang_action_t CC_HINT(nonnull) mod_authorize(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sql_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_sql_t);
	rlm_sql_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_sql_thread_t);
	sql_autz_call_env_t	*call_env = talloc_get_type_abort(mctx->env_data, sql_autz_call_env_t);
	sql_autz_ctx_t		*autz_ctx;

	fr_assert(request->packet != NULL);
	fr_assert(request->reply != NULL);

	if (!call_env->check_query && !call_env->reply_query && !(inst->config.read_groups && call_env->membership_query)) {
		RWDEBUG("No authorization checks configured, returning noop");
		RETURN_UNLANG_NOOP;
	}

	/*
	 *	Set and check the user attr here
	 */
	sql_set_user(inst, request, &call_env->user);

	MEM(autz_ctx = talloc(unlang_interpret_frame_talloc_ctx(request), sql_autz_ctx_t));
	*autz_ctx = (sql_autz_ctx_t) {
		.inst = inst,
		.call_env = call_env,
		.request = request,
		.trunk = thread->trunk,
		.rcode = RLM_MODULE_NOOP
	};
	map_list_init(&autz_ctx->check_tmp);
	map_list_init(&autz_ctx->reply_tmp);
	MEM(autz_ctx->map_ctx = talloc_zero(autz_ctx, fr_sql_map_ctx_t));
	talloc_set_destructor(autz_ctx, sql_autz_ctx_free);

	if (unlang_module_yield(request,
				(call_env->check_query || call_env->reply_query) ? mod_authorize_resume : mod_autz_group_resume,
				NULL, 0, autz_ctx) == UNLANG_ACTION_FAIL) {
	error:
		talloc_free(autz_ctx);
		RETURN_UNLANG_FAIL;
	}

	fr_value_box_list_init(&autz_ctx->query);

	/*
	 *	Query the check table to find any conditions associated with this user/realm/whatever...
	 */
	if (call_env->check_query) {
		if (unlang_tmpl_push(autz_ctx, NULL, &autz_ctx->query, request, call_env->check_query, NULL, UNLANG_SUB_FRAME) < 0) goto error;
		autz_ctx->status = SQL_AUTZ_CHECK;
		return UNLANG_ACTION_PUSHED_CHILD;
	}

	if (call_env->reply_query) {
		if (unlang_tmpl_push(autz_ctx, NULL, &autz_ctx->query, request, call_env->reply_query, NULL, UNLANG_SUB_FRAME) < 0) goto error;
		autz_ctx->status = SQL_AUTZ_REPLY;
		return UNLANG_ACTION_PUSHED_CHILD;
	}

	/*
	 *	Neither check nor reply queries were set, so we must be doing group stuff
	 */
	if (unlang_tmpl_push(autz_ctx, NULL, &autz_ctx->query, request, call_env->membership_query, NULL, UNLANG_SUB_FRAME) < 0) goto error;
	autz_ctx->status = SQL_AUTZ_GROUP_MEMB;
	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Tidy up when freeing an SQL redundant context
 *
 * Release the connection handle and unset the SQL-User attribute.
 */
static int sql_redundant_ctx_free(sql_redundant_ctx_t *to_free)
{
	if (!to_free->inst->sql_escape_arg) (void) request_data_get(to_free->request, (void *)sql_escape_uctx_alloc, 0);
	sql_unset_user(to_free->inst, to_free->request);

	return 0;
}

static unlang_action_t mod_sql_redundant_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request);

/** Resume function called after executing an SQL query in a redundant list of queries.
 *
 * @param p_result	Result of current module call.
 * @param mctx		Current module ctx.
 * @param request	Current request.
 * @return one of the RLM_MODULE_* values.
 */
static unlang_action_t mod_sql_redundant_query_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	sql_redundant_ctx_t		*redundant_ctx = talloc_get_type_abort(mctx->rctx, sql_redundant_ctx_t);
	sql_redundant_call_env_t	*call_env = redundant_ctx->call_env;
	rlm_sql_t const			*inst = redundant_ctx->inst;
	fr_sql_query_t			*query_ctx = redundant_ctx->query_ctx;
	int				numaffected = 0;

	RDEBUG2("SQL query returned: %s", fr_table_str_by_value(sql_rcode_description_table, query_ctx->rcode, "<INVALID>"));

	switch (query_ctx->rcode) {
	/*
	 *	Query was a success! Now we just need to check if it did anything.
	 */
	case RLM_SQL_OK:
		break;

	/*
	 *	A general, unrecoverable server fault.
	 */
	case RLM_SQL_ERROR:
	/*
	 *	If we get RLM_SQL_RECONNECT it means all connections in the pool
	 *	were exhausted, and we couldn't create a new connection,
	 *	so we do not need to call fr_pool_connection_release.
	 */
	case RLM_SQL_RECONNECT:
		rlm_sql_print_error(inst, request, query_ctx, false);
		RETURN_UNLANG_FAIL;

	/*
	 *	Query was invalid, this is a terminal error.
	 */
	case RLM_SQL_QUERY_INVALID:
		rlm_sql_print_error(inst, request, query_ctx, false);
		RETURN_UNLANG_INVALID;

	/*
	 *	Driver found an error (like a unique key constraint violation)
	 *	that hinted it might be a good idea to try an alternative query.
	 */
	case RLM_SQL_ALT_QUERY:
		goto next;

	case RLM_SQL_NO_MORE_ROWS:
		break;
	}

	/*
	 *	We need to have updated something for the query to have been
	 *	counted as successful.
	 */
	numaffected = (inst->driver->sql_affected_rows)(query_ctx, &inst->config);
	TALLOC_FREE(query_ctx);
	RDEBUG2("%i record(s) updated", numaffected);

	if (numaffected > 0) {
		if (inst->query_number_da) {
			fr_pair_t	*vp;
			if (unlikely(pair_update_control(&vp, inst->query_number_da) < 0)) RETURN_UNLANG_FAIL;
			vp->vp_uint32 = redundant_ctx->query_no + 1;
			RDEBUG2("control.%pP", vp);
		}
		RETURN_UNLANG_OK;	/* A query succeeded, were done! */
	}
next:
	/*
	 *	Look to see if there are any more queries to expand
	 */
	talloc_free(query_ctx);
	redundant_ctx->query_no++;
	if (redundant_ctx->query_no >= talloc_array_length(call_env->query)) RETURN_UNLANG_NOOP;
	if (unlang_module_yield(request, mod_sql_redundant_resume, NULL, 0, redundant_ctx) == UNLANG_ACTION_FAIL) RETURN_UNLANG_FAIL;
	if (unlang_tmpl_push(redundant_ctx, NULL, &redundant_ctx->query, request, call_env->query[redundant_ctx->query_no], NULL, UNLANG_SUB_FRAME) < 0) RETURN_UNLANG_FAIL;

	RDEBUG2("Trying next query...");

	return UNLANG_ACTION_PUSHED_CHILD;
}


/** Resume function called after expansion of next query in a redundant list of queries
 *
 * @param p_result	Result of current module call.
 * @param mctx		Current module ctx.
 * @param request	Current request.
 * @return one of the RLM_MODULE_* values.
 */
static unlang_action_t mod_sql_redundant_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	sql_redundant_ctx_t		*redundant_ctx = talloc_get_type_abort(mctx->rctx, sql_redundant_ctx_t);
	sql_redundant_call_env_t	*call_env = redundant_ctx->call_env;
	rlm_sql_t const			*inst = redundant_ctx->inst;

	redundant_ctx->query_vb = fr_value_box_list_pop_head(&redundant_ctx->query);
	if (!redundant_ctx->query_vb) RETURN_UNLANG_FAIL;

	if ((call_env->filename.type == FR_TYPE_STRING) && (call_env->filename.vb_length > 0)) {
		rlm_sql_query_log(inst, call_env->filename.vb_strvalue, redundant_ctx->query_vb->vb_strvalue);
	}

	MEM(redundant_ctx->query_ctx = fr_sql_query_alloc(redundant_ctx, inst, request, redundant_ctx->trunk,
							  redundant_ctx->query_vb->vb_strvalue, SQL_QUERY_OTHER));

	unlang_module_yield(request, mod_sql_redundant_query_resume, NULL, 0, redundant_ctx);
	return unlang_function_push_with_result(/* discard, mod_sql_redundant_query_resume uses query_ctx->rcode*/ NULL,
						request,
						inst->query,
						NULL,
						NULL,
						0, UNLANG_SUB_FRAME,
						redundant_ctx->query_ctx);
}

/**  Generic module call for failing between a bunch of queries.
 *
 * Used for `accounting` and `send` module calls
 *
 */
static unlang_action_t CC_HINT(nonnull) mod_sql_redundant(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sql_t const			*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_sql_t);
	rlm_sql_thread_t		*thread = talloc_get_type_abort(mctx->thread, rlm_sql_thread_t);
	sql_redundant_call_env_t	*call_env = talloc_get_type_abort(mctx->env_data, sql_redundant_call_env_t);
	sql_redundant_ctx_t		*redundant_ctx;

	/*
	 *	No query to expand - do nothing.
	 */
	if (!call_env->query) {
		RWARN("No query configured");
		RETURN_UNLANG_NOOP;
	}

	MEM(redundant_ctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), sql_redundant_ctx_t));
	*redundant_ctx = (sql_redundant_ctx_t) {
		.inst = inst,
		.request = request,
		.trunk = thread->trunk,
		.call_env = call_env,
		.query_no = 0
	};
	talloc_set_destructor(redundant_ctx, sql_redundant_ctx_free);

	sql_set_user(inst, request, &call_env->user);

	fr_value_box_list_init(&redundant_ctx->query);

	return unlang_module_yield_to_tmpl(request, &redundant_ctx->query, request, *call_env->query,
					   NULL, mod_sql_redundant_resume, NULL, 0, redundant_ctx);
}

static int logfile_call_env_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out, tmpl_rules_t const *t_rules,
				  CONF_ITEM *ci,
				  call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	CONF_SECTION const	*subcs = NULL, *subsubcs = NULL;
	CONF_PAIR const		*to_parse = NULL;
	tmpl_t			*parsed_tmpl;
	call_env_parsed_t	*parsed_env;
	tmpl_rules_t		our_rules;
	char			*section2, *p;

	fr_assert(cec->type == CALL_ENV_CTX_TYPE_MODULE);

	/*
	 *	The call env subsection which calls this has CF_IDENT_ANY as its name
	 *	which results in finding the first child section of the module config.
	 *	We actually want the whole module config - so go to the parent.
	 */
	ci = cf_parent(ci);

	/*
	 *	Find the instance of "logfile" to parse
	 *
	 *	If the module call is from `accounting Start` then first is
	 *		<module> { accounting { start { logfile } } }
	 *	then
	 *		<module> { accounting { logfile } }
	 *	falling back to
	 *		<module> { logfile }
	 */
	subcs = cf_section_find(cf_item_to_section(ci), cec->asked->name1, CF_IDENT_ANY);
	if (subcs) {
		if (cec->asked->name2) {
			section2 = talloc_strdup(NULL, cec->asked->name2);
			p = section2;
			while (*p != '\0') {
				*(p) = tolower((uint8_t)*p);
				p++;
			}
			subsubcs = cf_section_find(subcs, section2, CF_IDENT_ANY);
			talloc_free(section2);
			if (subsubcs) to_parse = cf_pair_find(subsubcs, "logfile");
		}
		if (!to_parse) to_parse = cf_pair_find(subcs, "logfile");
	}

	if (!to_parse) to_parse = cf_pair_find(cf_item_to_section(ci), "logfile");

	if (!to_parse) return 0;

	/*
	 *	Use filename safety escape functions
	 */
	our_rules = *t_rules;
	our_rules.escape.box_escape = (fr_value_box_escape_t) {
		.func = rad_filename_box_make_safe,
		.safe_for = (fr_value_box_safe_for_t)rad_filename_box_make_safe,
		.always_escape = false,
	};
	our_rules.escape.mode = TMPL_ESCAPE_PRE_CONCAT;
	our_rules.literals_safe_for = our_rules.escape.box_escape.safe_for;

	MEM(parsed_env = call_env_parsed_add(ctx, out,
					     &(call_env_parser_t){ FR_CALL_ENV_OFFSET("logfile", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT, sql_redundant_call_env_t, filename)}));

	if (tmpl_afrom_substr(parsed_env, &parsed_tmpl,
			      &FR_SBUFF_IN(cf_pair_value(to_parse), talloc_array_length(cf_pair_value(to_parse)) - 1),
			      cf_pair_value_quote(to_parse), value_parse_rules_quoted[cf_pair_value_quote(to_parse)],
			      &our_rules) < 0) {
	error:
		call_env_parsed_free(out, parsed_env);
		return -1;
	}
	if (tmpl_needs_resolving(parsed_tmpl) &&
	    (tmpl_resolve(parsed_tmpl, &(tmpl_res_rules_t){ .dict_def = our_rules.attr.dict_def }) < 0)) goto error;

	call_env_parsed_set_tmpl(parsed_env, parsed_tmpl);

	return 0;
}

static int query_call_env_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out, tmpl_rules_t const *t_rules,
				CONF_ITEM *ci,
				call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	rlm_sql_t const		*inst = talloc_get_type_abort_const(cec->mi->data, rlm_sql_t);
	CONF_SECTION const	*subcs = NULL;
	CONF_PAIR const		*to_parse = NULL;
	tmpl_t			*parsed_tmpl;
	call_env_parsed_t	*parsed_env;
	tmpl_rules_t		our_rules;
	char			*section2, *p;
	ssize_t			count, slen, multi_index = 0;

	fr_assert(cec->type == CALL_ENV_CTX_TYPE_MODULE);

	/*
	 *	Find the instance(s) of "query" to parse
	 *
	 *	If the module call is from `accounting Start` then it should be
	 *		<module> { accounting { start { query } } }
	 */
	section2 = talloc_strdup(NULL, section_name_str(cec->asked->name2));
	p = section2;
	while (*p != '\0') {
		*(p) = tolower((uint8_t)*p);
		p++;
	}
	subcs = cf_section_find(cf_item_to_section(ci), section2, CF_IDENT_ANY);
	if (!subcs) {
	no_query:
		cf_log_warn(ci, "No query found for \"%s.%s\", this query will be disabled",
			    section_name_str(cec->asked->name1), section2);
		talloc_free(section2);
		return 0;
	}
	count = cf_pair_count(subcs, "query");
	if (count == 0) goto no_query;

	talloc_free(section2);

	/*
	 *	Use module specific escape functions
	 */
	our_rules = *t_rules;
	our_rules.escape = (tmpl_escape_t) {
		.box_escape = (fr_value_box_escape_t) {
			.func = sql_box_escape,
			.safe_for = SQL_SAFE_FOR,
			.always_escape = false,
		},
		.uctx = { .func = { .uctx = inst, .alloc = sql_escape_uctx_alloc }, .type = TMPL_ESCAPE_UCTX_ALLOC_FUNC },
		.mode = TMPL_ESCAPE_PRE_CONCAT,
	};
	our_rules.literals_safe_for = our_rules.escape.box_escape.safe_for;

	while ((to_parse = cf_pair_find_next(subcs, to_parse, "query"))) {
		MEM(parsed_env = call_env_parsed_add(ctx, out,
						     &(call_env_parser_t){
							FR_CALL_ENV_PARSE_ONLY_OFFSET("query", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_MULTI,
										      sql_redundant_call_env_t, query)
						     }));

		slen = tmpl_afrom_substr(parsed_env, &parsed_tmpl,
					 &FR_SBUFF_IN(cf_pair_value(to_parse), talloc_array_length(cf_pair_value(to_parse)) - 1),
					 cf_pair_value_quote(to_parse), value_parse_rules_quoted[cf_pair_value_quote(to_parse)],
					 &our_rules);
		if (slen <= 0) {
			cf_canonicalize_error(to_parse, slen, "Failed parsing query", cf_pair_value(to_parse));
		error:
			call_env_parsed_free(out, parsed_env);
			return -1;
		}
		if (tmpl_needs_resolving(parsed_tmpl) &&
		    (tmpl_resolve(parsed_tmpl, &(tmpl_res_rules_t){ .dict_def = our_rules.attr.dict_def }) < 0)) {
			cf_log_perr(to_parse, "Failed resolving query");
			goto error;
		}

		call_env_parsed_set_multi_index(parsed_env, count, multi_index++);
		call_env_parsed_set_data(parsed_env, parsed_tmpl);
	}

	return 0;
}

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_sql_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_sql_t);

	/*
	 *	We need to explicitly free all children, so if the driver
	 *	parented any memory off the instance, their destructors
	 *	run before we unload the bytecode for them.
	 *
	 *	If we don't do this, we get a SEGV deep inside the talloc code
	 *	when it tries to call a destructor that no longer exists.
	 */
	talloc_free_children(inst);

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_sql_boot_t const	*boot = talloc_get_type_abort(mctx->mi->boot, rlm_sql_boot_t);
	rlm_sql_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_sql_t);
	CONF_SECTION		*conf = mctx->mi->conf;

	/*
	 *	We can't modify the inst field in bootstrap, and there's no
	 *	point in making rlm_sql_boot_t available everywhere.
	 */
	inst->group_da = boot->group_da;
	inst->query_number_da = boot->query_number_da;

	inst->name = mctx->mi->name;	/* Need this for functions in sql.c */
	inst->mi = mctx->mi;		/* For looking up thread instance data */

	/*
	 *	We need authorize_group_check_query or authorize_group_reply_query
	 *	if group_membership_query is set.
	 *
	 *	Or we need group_membership_query if authorize_group_check_query or
	 *	authorize_group_reply_query is set.
	 */
	if (!cf_pair_find(conf, "group_membership_query")) {
		if (cf_pair_find(conf, "authorize_group_check_query")) {
			WARN("Ignoring authorize_group_check_query as group_membership_query is not configured");
		}

		if (cf_pair_find(conf, "authorize_group_reply_query")) {
			WARN("Ignoring authorize_group_reply_query as group_membership_query is not configured");
		}

		if (!inst->config.read_groups) {
			WARN("Ignoring read_groups as group_membership_query is not configured");
			inst->config.read_groups = false;
		}
	} /* allow the group check / reply queries to be NULL */

	/*
	 *	Cache the SQL-User-Name fr_dict_attr_t, so we can be slightly
	 *	more efficient about creating SQL-User-Name attributes.
	 */
	inst->sql_user = attr_sql_user_name;

	/*
	 *	Export these methods, too.  This avoids RTDL_GLOBAL.
	 */
	inst->query		= rlm_sql_trunk_query;
	inst->select		= rlm_sql_trunk_query;
	inst->fetch_row		= rlm_sql_fetch_row;
	inst->query_alloc	= fr_sql_query_alloc;

	/*
	 *	Either use the module specific escape function
	 *	or our default one.
	 */
	if (inst->driver->sql_escape_func) {
		inst->sql_escape_func = inst->driver->sql_escape_func;
	} else {
		inst->sql_escape_func = sql_escape_func;
		inst->sql_escape_arg = inst;
	}
	inst->box_escape = (fr_value_box_escape_t) {
		.func = sql_box_escape,
		.safe_for = SQL_SAFE_FOR,
		.always_escape = false,
	};

	inst->ef = module_rlm_exfile_init(inst, conf, 256, fr_time_delta_from_sec(30), true, false, NULL, NULL);
	if (!inst->ef) {
		cf_log_err(conf, "Failed creating log file context");
		return -1;
	}

	/*
	 *	Most SQL trunks can only have one running request per connection.
	 */
	if (!(inst->driver->flags & RLM_SQL_MULTI_QUERY_CONN)) {
		inst->config.trunk_conf.target_req_per_conn = 1;
		inst->config.trunk_conf.max_req_per_conn = 1;
	}
	if (!inst->driver->trunk_io_funcs.connection_notify) {
		inst->config.trunk_conf.always_writable = true;
	}

	/*
	 *	Instantiate the driver module
	 */
	if (unlikely(module_instantiate(inst->driver_submodule) < 0)) {
		cf_log_err(conf, "Failed instantiating driver module");
		return -1;
	}

	if (!inst->config.trunk_conf.conn_triggers) return 0;

	MEM(inst->trigger_args = fr_pair_list_alloc(inst));
	return module_trigger_args_build(inst->trigger_args, inst->trigger_args, cf_section_find(conf, "pool", NULL),
					&(module_trigger_args_t) {
						.module = inst->mi->module->name,
						.name = inst->name,
						.server = inst->config.sql_server,
						.port = inst->config.sql_port
					});
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_sql_boot_t		*boot = talloc_get_type_abort(mctx->mi->boot, rlm_sql_boot_t);
	rlm_sql_t const		*inst = talloc_get_type_abort(mctx->mi->data, rlm_sql_t);
	CONF_SECTION		*conf = mctx->mi->conf;
	xlat_t			*xlat;
	xlat_arg_parser_t	*sql_xlat_arg;
	rlm_sql_escape_uctx_t	*uctx;

	/*
	 *	Register the group comparison attribute
	 */
	if (cf_pair_find(conf, "group_membership_query")) {
		char const *group_attribute;
		char buffer[256];

		if (inst->config.group_attribute) {
			group_attribute = inst->config.group_attribute;
		} else if (cf_section_name2(conf)) {
			snprintf(buffer, sizeof(buffer), "%s-SQL-Group", mctx->mi->name);
			group_attribute = buffer;
		} else {
			group_attribute = "SQL-Group";
		}

		boot->group_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius), group_attribute);
		if (!boot->group_da) {
			if (fr_dict_attr_add_name_only(fr_dict_unconst(dict_freeradius), fr_dict_root(dict_freeradius), group_attribute, FR_TYPE_STRING, NULL) < 0) {
				cf_log_perr(conf, "Failed defining group attribute");
				return -1;
			}

			boot->group_da = fr_dict_attr_search_by_qualified_oid(NULL, dict_freeradius, group_attribute,
									false, false);
			if (!boot->group_da) {
				cf_log_perr(conf, "Failed resolving group attribute");
				return -1;
			}
		}

		/*
		 *	Define the new %sql.group(name) xlat.  The
		 *	register function automatically adds the
		 *	module instance name as a prefix.
		 */
		xlat = module_rlm_xlat_register(boot, mctx, "group", sql_group_xlat, FR_TYPE_BOOL);
		if (!xlat) {
			cf_log_perr(conf, "Failed registering %s expansion", group_attribute);
			return -1;
		}
		xlat_func_call_env_set(xlat, &group_xlat_method_env);

		/*
		 *	The xlat escape function needs access to inst - so
		 *	argument parser details need to be defined here
		 */
		sql_xlat_arg = talloc_zero_array(xlat, xlat_arg_parser_t, 2);
		sql_xlat_arg[0] = (xlat_arg_parser_t){
			.type = FR_TYPE_STRING,
			.required = true,
			.concat = true
		};
		sql_xlat_arg[1] = (xlat_arg_parser_t)XLAT_ARG_PARSER_TERMINATOR;

		xlat_func_args_set(xlat, sql_xlat_arg);
	}

	/*
	 *	If we need to record which query from a redundant set succeeds, find / create the attribute to use.
	 */
	if (inst->config.query_number_attribute) {
		boot->query_number_da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_freeradius),
							     inst->config.query_number_attribute);
		if (!boot->query_number_da) {
			if (fr_dict_attr_add_name_only(fr_dict_unconst(dict_freeradius), fr_dict_root(dict_freeradius),
			    inst->config.query_number_attribute, FR_TYPE_UINT32, NULL) < 0) {
				ERROR("Failed defining query number attribute \"%s\"", inst->config.query_number_attribute);
				return -1;
			}

			boot->query_number_da = fr_dict_attr_search_by_qualified_oid(NULL, dict_freeradius,
										     inst->config.query_number_attribute,
										     false, false);
			if (!boot->query_number_da) {
				ERROR("Failed resolving query number attribute \"%s\"", inst->config.query_number_attribute);
				return -1;
			}
		} else {
			if (boot->query_number_da->type != FR_TYPE_UINT32) {
				ERROR("Query number attribute \"%s\" is type \"%s\", needs to be uint32",
				      inst->config.query_number_attribute, fr_type_to_str(boot->query_number_da->type));
				return -1;
			}
		}
	}

	/*
	 *	Register the SQL xlat function
	 */
	xlat = module_rlm_xlat_register(boot, mctx, NULL, sql_xlat, FR_TYPE_VOID);	/* Returns an integer sometimes */
	if (!xlat) {
		cf_log_perr(conf, "Failed registering %s expansion", mctx->mi->name);
		return -1;
	}
	xlat_func_call_env_set(xlat, &xlat_method_env);

	/*
	 *	The xlat escape function needs access to inst - so
	 *	argument parser details need to be defined here.
	 *	Parented off the module instance "boot" so it can be shared
	 *	between three xlats.
	 */
	MEM(sql_xlat_arg = talloc_zero_array(boot, xlat_arg_parser_t, 2));
	MEM(uctx = talloc_zero(sql_xlat_arg, rlm_sql_escape_uctx_t));
	*uctx = (rlm_sql_escape_uctx_t){ .sql = inst };
	sql_xlat_arg[0] = (xlat_arg_parser_t){
		.type = FR_TYPE_STRING,
		.required = true,
		.concat = true,
		.func = sql_xlat_escape,
		.safe_for = SQL_SAFE_FOR,
		.uctx = uctx
	};
	sql_xlat_arg[1] = (xlat_arg_parser_t)XLAT_ARG_PARSER_TERMINATOR;

	xlat_func_args_set(xlat, sql_xlat_arg);

	/*
	 *	Register instances of the SQL xlat with pre-determined output types
	 */
	if (unlikely(!(xlat = module_rlm_xlat_register(boot, mctx, "fetch", sql_fetch_xlat, FR_TYPE_VOID)))) return -1;
	xlat_func_call_env_set(xlat, &xlat_method_env);
	xlat_func_args_set(xlat, sql_xlat_arg);

	if (unlikely(!(xlat = module_rlm_xlat_register(boot, mctx, "modify", sql_modify_xlat, FR_TYPE_UINT32)))) return -1;
	xlat_func_call_env_set(xlat, &xlat_method_env);
	xlat_func_args_set(xlat, sql_xlat_arg);

	if (unlikely(!(xlat = module_rlm_xlat_register(boot, mctx, "escape", sql_escape_xlat, FR_TYPE_STRING)))) return -1;
	sql_xlat_arg = talloc_zero_array(xlat, xlat_arg_parser_t, 2);
	sql_xlat_arg[0] = (xlat_arg_parser_t){
		.type = FR_TYPE_STRING,
		.variadic = true,
		.concat = true,
	};
	sql_xlat_arg[1] = (xlat_arg_parser_t)XLAT_ARG_PARSER_TERMINATOR;
	xlat_func_args_set(xlat, sql_xlat_arg);
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE);
	xlat_func_safe_for_set(xlat, SQL_SAFE_FOR);

	if (unlikely(!(xlat = module_rlm_xlat_register(boot, mctx, "safe", xlat_transparent, FR_TYPE_STRING)))) return -1;
	sql_xlat_arg = talloc_zero_array(xlat, xlat_arg_parser_t, 2);
	sql_xlat_arg[0] = (xlat_arg_parser_t){
		.type = FR_TYPE_STRING,
		.variadic = true,
		.concat = true
	};
	sql_xlat_arg[1] = (xlat_arg_parser_t)XLAT_ARG_PARSER_TERMINATOR;
	xlat_func_args_set(xlat, sql_xlat_arg);
	xlat_func_flags_set(xlat, XLAT_FUNC_FLAG_PURE);
	xlat_func_safe_for_set(xlat, SQL_SAFE_FOR);

	/*
	 *	Register the SQL map processor function
	 */
	if (inst->driver->sql_fields) map_proc_register(mctx->mi->boot, inst, mctx->mi->name, mod_map_proc, sql_map_verify, 0, SQL_SAFE_FOR);

	return 0;
}

/** Initialise thread specific data structure
 *
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_sql_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_sql_thread_t);
	rlm_sql_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_sql_t);

	if (inst->driver->sql_escape_arg_alloc) {
		thread->sql_escape_arg = inst->driver->sql_escape_arg_alloc(thread, mctx->el, inst);
		if (!thread->sql_escape_arg) return -1;
	}

	thread->inst = inst;

	thread->trunk = trunk_alloc(thread, mctx->el, &inst->driver->trunk_io_funcs,
			       &inst->config.trunk_conf, inst->name, thread, false, inst->trigger_args);
	if (!thread->trunk) return -1;

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_sql_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_sql_thread_t);
	rlm_sql_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_sql_t);

	if (inst->driver->sql_escape_arg_free) inst->driver->sql_escape_arg_free(thread->sql_escape_arg);

	return 0;
}

/** Custom parser for sql call env queries
 *
 * Needed as the escape function needs to reference the correct SQL driver
 */
static int sql_call_env_parse(TALLOC_CTX *ctx, void *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci,
			      call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	rlm_sql_t const		*inst = talloc_get_type_abort_const(cec->mi->data, rlm_sql_t);
	tmpl_t			*parsed_tmpl;
	CONF_PAIR const		*to_parse = cf_item_to_pair(ci);
	tmpl_rules_t		our_rules = *t_rules;

	/*
	 *	Set the sql module instance data as the uctx for escaping
	 *	and use the same "safe_for" as the sql module.
	 */
	our_rules.escape.box_escape = (fr_value_box_escape_t) {
		.func = sql_box_escape,
		.safe_for = SQL_SAFE_FOR,
		.always_escape = false,
	};
	our_rules.escape.uctx.func.uctx = inst;
	our_rules.literals_safe_for = SQL_SAFE_FOR;

	if (tmpl_afrom_substr(ctx, &parsed_tmpl,
			      &FR_SBUFF_IN(cf_pair_value(to_parse), talloc_array_length(cf_pair_value(to_parse)) - 1),
			      cf_pair_value_quote(to_parse), value_parse_rules_quoted[cf_pair_value_quote(to_parse)],
			      &our_rules) < 0) return -1;
	*(void **)out = parsed_tmpl;
	return 0;
}

#define QUERY_ESCAPE .pair.escape = { \
	.mode = TMPL_ESCAPE_PRE_CONCAT, \
	.uctx = { .func = { .alloc = sql_escape_uctx_alloc }, .type = TMPL_ESCAPE_UCTX_ALLOC_FUNC }, \
}, .pair.func = sql_call_env_parse

static const call_env_method_t authorize_method_env = {
	FR_CALL_ENV_METHOD_OUT(sql_autz_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("sql_user_name", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_NULLABLE, sql_autz_call_env_t, user) },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("authorize_check_query", FR_TYPE_STRING, CALL_ENV_FLAG_PARSE_ONLY, sql_autz_call_env_t, check_query), QUERY_ESCAPE },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("authorize_reply_query", FR_TYPE_STRING, CALL_ENV_FLAG_PARSE_ONLY, sql_autz_call_env_t, reply_query), QUERY_ESCAPE },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("group_membership_query", FR_TYPE_STRING, CALL_ENV_FLAG_PARSE_ONLY, sql_autz_call_env_t, membership_query), QUERY_ESCAPE },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("authorize_group_check_query", FR_TYPE_STRING, CALL_ENV_FLAG_PARSE_ONLY, sql_autz_call_env_t, group_check_query), QUERY_ESCAPE },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("authorize_group_reply_query", FR_TYPE_STRING, CALL_ENV_FLAG_PARSE_ONLY, sql_autz_call_env_t, group_reply_query), QUERY_ESCAPE },
		CALL_ENV_TERMINATOR
	}
};

/* globally exported name */
module_rlm_t rlm_sql = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "sql",
		.boot_size	= sizeof(rlm_sql_boot_t),
		.boot_type	= "rlm_sql_boot_t",
		.inst_size	= sizeof(rlm_sql_t),
		.config		= module_config,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate,
		.detach		= mod_detach,
		.thread_inst_size	= sizeof(rlm_sql_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			/*
			 *	Hack to support old configurations
			 */
			{ .section = SECTION_NAME("accounting", CF_IDENT_ANY), .method = mod_sql_redundant, .method_env = &accounting_method_env },
			{ .section = SECTION_NAME("authorize", CF_IDENT_ANY), .method = mod_authorize, .method_env = &authorize_method_env },

			{ .section = SECTION_NAME("recv", CF_IDENT_ANY), .method = mod_authorize, .method_env = &authorize_method_env },
			{ .section = SECTION_NAME("send", CF_IDENT_ANY), .method = mod_sql_redundant, .method_env = &send_method_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
