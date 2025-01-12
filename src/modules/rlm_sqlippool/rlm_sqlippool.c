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
 * @file rlm_sqlippool.c
 * @brief Allocates an IPv4 address from pools stored in SQL.
 *
 * @copyright 2002 Globe.Net Communications Limited
 * @copyright 2006 The FreeRADIUS server project
 * @copyright 2006 Suntel Communications
 */
RCSID("$Id$")

#define LOG_PREFIX inst->name

#include <rlm_sql.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/unlang/function.h>

#include <ctype.h>

/*
 *	Define a structure for our module configuration.
 */
typedef struct {
	char const      *name;
	char const	*sql_name;

	rlm_sql_t const	*sql;
} rlm_sqlippool_t;

/**  Call environment used by module alloc method
 */
typedef struct {
	fr_value_box_t	pool_name;			//!< Name of pool address will be allocated from.
	tmpl_t		*pool_name_tmpl;		//!< Tmpl used to expand pool_name
	fr_value_box_t	requested_address;		//!< IP address being requested by client.
	tmpl_t		*allocated_address_attr;	//!< Attribute to populate with allocated IP.
	fr_value_box_t	allocated_address;		//!< Existing value for allocated IP.
	fr_value_box_t	begin;				//!< SQL query to begin transaction.
	tmpl_t		*existing;			//!< tmpl to expand as query for finding the existing IP.
	tmpl_t		*requested;			//!< tmpl to expand as query for finding the requested IP.
	tmpl_t		*find;				//!< tmpl to expand as query for finding an unused IP.
	tmpl_t		*update;			//!< tmpl to expand as query for updating the found IP.
	tmpl_t		*pool_check;			//!< tmpl to expand as query for checking for existence of the pool.
	fr_value_box_t	commit;				//!< SQL query to commit transaction.
} ippool_alloc_call_env_t;

/**  Call environment used by all other module methods
 */
typedef struct {
	fr_value_box_t	free;			//!< SQL query to clear other offered IPs.  Only used in "update" method.
	fr_value_box_t	update;			//!< SQL query to update an IP record.
} ippool_common_call_env_t;

/** Current step in IP allocation state machine
 */
typedef enum {
	IPPOOL_ALLOC_BEGIN_RUN,			//!< Run the "begin" query
	IPPOOL_ALLOC_EXISTING,			//!< Expanding the "existing" query
	IPPOOL_ALLOC_EXISTING_RUN,		//!< Run the "existing" query
	IPPOOL_ALLOC_REQUESTED,			//!< Expanding the "requested" query
	IPPOOL_ALLOC_REQUESTED_RUN,		//!< Run the "requested" query
	IPPOOL_ALLOC_FIND,			//!< Expanding the "find" query
	IPPOOL_ALLOC_FIND_RUN,			//!< Run the "find" query
	IPPOOL_ALLOC_NO_ADDRESS,		//!< No address was found
	IPPOOL_ALLOC_POOL_CHECK,		//!< Expanding the "pool_check" query
	IPPOOL_ALLOC_POOL_CHECK_RUN,		//!< Run the "pool_check" query
	IPPOOL_ALLOC_MAKE_PAIR,			//!< Make the pair.
	IPPOOL_ALLOC_UPDATE,			//!< Expanding the "update" query
	IPPOOL_ALLOC_UPDATE_RUN,		//!< Run the "update" query
	IPPOOL_ALLOC_COMMIT_RUN,		//!< RUn the "commit" query
} ippool_alloc_status_t;

/**  Resume context for IP allocation
 */
typedef struct {
	request_t		*request;	//!< Current request.
	ippool_alloc_status_t	status;		//!< Status of the allocation.
	ippool_alloc_call_env_t	*env;		//!< Call environment for the allocation.
	trunk_t			*trunk;		//!< Trunk connection for queries.
	rlm_sql_t const		*sql;		//!< SQL module instance.
	fr_value_box_list_t	values;		//!< Where to put the expanded queries ready for execution.
	fr_value_box_t		*query;		//!< Current query being run.
	fr_sql_query_t		*query_ctx;	//!< Query context for allocation queries.
	rlm_rcode_t		rcode;		//!< Result code to return after running "commit".
} ippool_alloc_ctx_t;

/** Resume context for IP update / release
 */
typedef struct {
	request_t			*request;	//!< Current request.
	ippool_common_call_env_t	*env;		//!< Call environment for the update.
	rlm_sql_t const			*sql;		//!< SQL module instance.
	fr_sql_query_t			*query_ctx;	//!< Query context for allocation queries.
} ippool_common_ctx_t;

static conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("sql_module_instance", rlm_sqlippool_t, sql_name), .dflt = "sql" },

	CONF_PARSER_TERMINATOR
};

static int _sql_escape_uxtx_free(void *uctx)
{
	return talloc_free(uctx);
}

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
 *	Process the results of an SQL query expected to return a single row
 */
static int sqlippool_result_process(char *out, int outlen, fr_sql_query_t *query_ctx)
{
	rlm_rcode_t	p_result;
	int		rlen, retval = 0;
	rlm_sql_row_t	row;
	request_t	*request = query_ctx->request;

	*out = '\0';

	query_ctx->inst->fetch_row(&p_result, NULL, query_ctx->request, query_ctx);
	if (query_ctx->rcode < 0) {
		REDEBUG("Failed fetching query_result");
		goto finish;
	}

	row = query_ctx->row;
	if (!row) {
		RDEBUG2("SQL query did not return any results");
		goto finish;
	}

	if (!row[0]) {
		REDEBUG("The first column of the result was NULL");
		goto finish;
	}

	rlen = strlen(row[0]);
	if (rlen >= outlen) {
		REDEBUG("The first column of the result was too long (%d)", rlen);
		goto finish;
	}

	strcpy(out, row[0]);
	retval = rlen;

finish:
	query_ctx->inst->driver->sql_finish_select_query(query_ctx, &query_ctx->inst->config);
	return retval;
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
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	module_instance_t	*sql;
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_sqlippool_t);
	CONF_SECTION		*conf = mctx->mi->conf;

	inst->name = talloc_asprintf(inst, "%s - %s", mctx->mi->name, inst->sql_name);

	sql = module_rlm_static_by_name(NULL, inst->sql_name);
	if (!sql) {
		cf_log_err(conf, "failed to find sql instance named %s",
			   inst->sql_name);
		return -1;
	}

	inst->sql = (rlm_sql_t *) sql->data;

	if (strcmp(talloc_get_name(inst->sql), "rlm_sql_t") != 0) {
		cf_log_err(conf, "Module \"%s\" is not an instance of the rlm_sql module",
			      inst->sql_name);
		return -1;
	}

	return 0;
}

/** Release SQL pool connections when alloc context is freed.
 */
static int sqlippool_alloc_ctx_free(ippool_alloc_ctx_t *to_free)
{
	if (!to_free->sql->sql_escape_arg) (void) request_data_get(to_free->request, (void *)sql_escape_uctx_alloc, 0);
	return 0;
}

#define REPEAT_MOD_ALLOC_RESUME if (unlang_function_repeat_set(request, mod_alloc_resume) < 0) RETURN_MODULE_FAIL
#define SUBMIT_QUERY(_query_str, _new_status, _type, _function) do { \
	alloc_ctx->status = _new_status; \
	REPEAT_MOD_ALLOC_RESUME; \
	query_ctx->query_str = _query_str; \
	query_ctx->type = _type; \
	query_ctx->status = SQL_QUERY_PREPARED; \
	alloc_ctx->query = query; \
	return unlang_function_push(request, sql->_function, NULL, NULL, 0, UNLANG_SUB_FRAME, query_ctx); \
} while (0)

/** Resume function called after each IP allocation query is expanded
 *
 * Executes the query and, if appropriate, pushes the next tmpl for expansion
 *
 * Following the final (successful) query, the destination attribute is populated.
 *
 * @param p_result	Result of IP allocation.
 * @param priority	Unused.
 * @param request	Current request.
 * @param uctx		Current allocation context.
 * @return One of the UNLANG_ACTION_* values.
 */
static unlang_action_t mod_alloc_resume(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	ippool_alloc_ctx_t	*alloc_ctx = talloc_get_type_abort(uctx, ippool_alloc_ctx_t);
	ippool_alloc_call_env_t	*env = alloc_ctx->env;
	int			allocation_len = 0;
	char			allocation[FR_MAX_STRING_LEN];
	rlm_sql_t const		*sql = alloc_ctx->sql;
	fr_value_box_t		*query = fr_value_box_list_pop_head(&alloc_ctx->values);
	fr_sql_query_t		*query_ctx = alloc_ctx->query_ctx;

	/*
	 *	If a previous async call returned one of the "failure" results just return.
	 */
	switch (*p_result) {
	case RLM_MODULE_USER_SECTION_REJECT:
		return UNLANG_ACTION_CALCULATE_RESULT;

	default:
		break;
	}

	switch (alloc_ctx->status) {
	case IPPOOL_ALLOC_BEGIN_RUN:
		if ((env->begin.type == FR_TYPE_STRING) &&
		    env->begin.vb_length) sql->driver->sql_finish_query(query_ctx, &query_ctx->inst->config);

		/*
		 *	The first call of this function will always land here, whether or not a "begin" query is actually run.
		 *
		 *	Having (possibly) run the "begin" query, establish which tmpl needs expanding
		 *
		 *	If there is a query for finding the existing IP expand that first
		 */
		if (env->existing) {
			alloc_ctx->status = IPPOOL_ALLOC_EXISTING;
			REPEAT_MOD_ALLOC_RESUME;
			if (unlang_tmpl_push(alloc_ctx, &alloc_ctx->values, request, env->existing, NULL) < 0) {
			error:
				talloc_free(alloc_ctx);
				RETURN_MODULE_FAIL;
			}
			return UNLANG_ACTION_PUSHED_CHILD;
		}
		goto expand_requested;

	case IPPOOL_ALLOC_EXISTING:
		if (query && query->vb_length) SUBMIT_QUERY(query->vb_strvalue, IPPOOL_ALLOC_EXISTING_RUN, SQL_QUERY_SELECT, select);
		goto expand_requested;

	case IPPOOL_ALLOC_EXISTING_RUN:
		TALLOC_FREE(alloc_ctx->query);
		if (query_ctx->rcode != RLM_SQL_OK) goto error;

		allocation_len = sqlippool_result_process(allocation, sizeof(allocation), query_ctx);
		if (allocation_len > 0) goto make_pair;

		/*
		 *	If there's a requested address and associated query, expand that
		 */
	expand_requested:
		if (env->requested && (env->requested_address.type != FR_TYPE_NULL)) {
			alloc_ctx->status = IPPOOL_ALLOC_REQUESTED;
			REPEAT_MOD_ALLOC_RESUME;
			if (unlang_tmpl_push(alloc_ctx, &alloc_ctx->values, request, env->requested, NULL) < 0) goto error;
			return UNLANG_ACTION_PUSHED_CHILD;
		}
		goto expand_find;

	case IPPOOL_ALLOC_REQUESTED:
		if (query && query->vb_length) SUBMIT_QUERY(query->vb_strvalue, IPPOOL_ALLOC_REQUESTED_RUN, SQL_QUERY_SELECT, select);

		goto expand_find;

	case IPPOOL_ALLOC_REQUESTED_RUN:
		TALLOC_FREE(alloc_ctx->query);
		if (query_ctx->rcode != RLM_SQL_OK) goto error;

		allocation_len = sqlippool_result_process(allocation, sizeof(allocation), query_ctx);
		if (allocation_len > 0) goto make_pair;

	expand_find:
		/*
		 *	Neither "existing" nor "requested" found an address, expand "find" query
		 */
		alloc_ctx->status = IPPOOL_ALLOC_FIND;
		REPEAT_MOD_ALLOC_RESUME;
		if (unlang_tmpl_push(alloc_ctx, &alloc_ctx->values, request, env->find, NULL) < 0) goto error;
		return UNLANG_ACTION_PUSHED_CHILD;

	case IPPOOL_ALLOC_FIND:
		SUBMIT_QUERY(query->vb_strvalue, IPPOOL_ALLOC_FIND_RUN, SQL_QUERY_SELECT, select);

	case IPPOOL_ALLOC_FIND_RUN:
		TALLOC_FREE(alloc_ctx->query);
		if (query_ctx->rcode != RLM_SQL_OK) goto error;

		allocation_len = sqlippool_result_process(allocation, sizeof(allocation), query_ctx);

		if (allocation_len > 0) goto make_pair;

		/*
		 *  Nothing found
		 */
		if ((env->commit.type == FR_TYPE_STRING) &&
		    env->commit.vb_length) SUBMIT_QUERY(env->commit.vb_strvalue, IPPOOL_ALLOC_NO_ADDRESS, SQL_QUERY_OTHER, query);
		FALL_THROUGH;

	case IPPOOL_ALLOC_NO_ADDRESS:
		if ((env->commit.type == FR_TYPE_STRING) &&
		    env->commit.vb_length) sql->driver->sql_finish_query(query_ctx, &query_ctx->inst->config);

		/*
		 *  Should we perform pool-check?
		 */
		if (env->pool_check) {
			alloc_ctx->status = IPPOOL_ALLOC_POOL_CHECK;
			REPEAT_MOD_ALLOC_RESUME;
			if (unlang_tmpl_push(alloc_ctx, &alloc_ctx->values, request, env->pool_check, NULL) < 0) goto error;
			return UNLANG_ACTION_PUSHED_CHILD;
		}
	no_address:
		RWDEBUG("IP address could not be allocated");
		RETURN_MODULE_NOOP;

	case IPPOOL_ALLOC_MAKE_PAIR:
	{
		tmpl_t	ip_rhs;
		map_t	ip_map;

	make_pair:
		/*
		 *	See if we can create the VP from the returned data.  If not,
		 *	error out.  If so, add it to the list.
		 */
		ip_map = (map_t) {
			.lhs = env->allocated_address_attr,
			.op = T_OP_SET,
			.rhs = &ip_rhs
		};

		tmpl_init_shallow(&ip_rhs, TMPL_TYPE_DATA, T_BARE_WORD, "", 0, NULL);
		fr_value_box_bstrndup_shallow(&ip_map.rhs->data.literal, NULL, allocation, allocation_len, false);
		if (map_to_request(request, &ip_map, map_to_vp, NULL) < 0) {
			alloc_ctx->rcode = RLM_MODULE_FAIL;

			REDEBUG("Invalid IP address [%s] returned from database query.", allocation);
			goto finish;
		}

		RDEBUG2("Allocated IP %s", allocation);
		alloc_ctx->rcode = RLM_MODULE_UPDATED;

		/*
		 *	If we have an update query expand it
		 */
		if (env->update) {
			alloc_ctx->status = IPPOOL_ALLOC_UPDATE;
			REPEAT_MOD_ALLOC_RESUME;
			if (unlang_tmpl_push(alloc_ctx, &alloc_ctx->values, request, env->update, NULL) < 0) goto error;
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		goto finish;
	}

	case IPPOOL_ALLOC_POOL_CHECK:
		/*
		 *	Ok, so the allocate-find query found nothing ...
		 *	Let's check if the pool exists at all
		 */
		if (query && query->vb_length) SUBMIT_QUERY(query->vb_strvalue, IPPOOL_ALLOC_POOL_CHECK_RUN, SQL_QUERY_SELECT, select);
		goto no_address;

	case IPPOOL_ALLOC_POOL_CHECK_RUN:
		TALLOC_FREE(alloc_ctx->query);
		allocation_len = sqlippool_result_process(allocation, sizeof(allocation), query_ctx);

		if (allocation_len) {
			/*
			 *	Pool exists after all... So,
			 *	the failure to allocate the IP
			 *	address was most likely due to
			 *	the depletion of the pool. In
			 *	that case, we should return
			 *	NOTFOUND
			 */
			RWDEBUG("Pool \"%pV\" appears to be full", &env->pool_name);
			RETURN_MODULE_NOTFOUND;
		}

		/*
		 *	Pool doesn't exist in the table. It
		 *	may be handled by some other instance of
		 *	sqlippool, so we should just ignore this
		 *	allocation failure and return NOOP
		 */
		RWDEBUG("IP address could not be allocated as no pool exists with the name \"%pV\"",
			&env->pool_name);
		RETURN_MODULE_NOOP;

	case IPPOOL_ALLOC_UPDATE:
		if (query && query->vb_length) SUBMIT_QUERY(query->vb_strvalue, IPPOOL_ALLOC_UPDATE_RUN, SQL_QUERY_OTHER, query);

		goto finish;

	case IPPOOL_ALLOC_UPDATE_RUN:
		TALLOC_FREE(alloc_ctx->query);
		if (env->update) sql->driver->sql_finish_query(query_ctx, &query_ctx->inst->config);

	finish:
		if ((env->commit.type == FR_TYPE_STRING) &&
		    env->commit.vb_length) SUBMIT_QUERY(env->commit.vb_strvalue, IPPOOL_ALLOC_COMMIT_RUN, SQL_QUERY_OTHER, query);

		FALL_THROUGH;

	case IPPOOL_ALLOC_COMMIT_RUN:
	{
		rlm_rcode_t	rcode = alloc_ctx->rcode;
		talloc_free(alloc_ctx);
		RETURN_MODULE_RCODE(rcode);
	}
	}

	/*
	 *	All return paths are handled within the switch statement.
	 */
	fr_assert(0);
	RETURN_MODULE_FAIL;
}

/** Initiate the allocation of an IP address from the pool.
 *
 * Based on configured queries and attributes which exist, determines the first
 * query tmpl to expand.
 *
 * @param p_result	Result of the allocation (if it fails).
 * @param mctx		Module context.
 * @param request	Current request.
 * @return One of the UNLANG_ACTION_* values.
 */
static unlang_action_t CC_HINT(nonnull) mod_alloc(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_sqlippool_t);
	ippool_alloc_call_env_t	*env = talloc_get_type_abort(mctx->env_data, ippool_alloc_call_env_t);
	rlm_sql_t const		*sql = inst->sql;
	ippool_alloc_ctx_t	*alloc_ctx = NULL;
	rlm_sql_thread_t	*thread = talloc_get_type_abort(module_thread(sql->mi)->data, rlm_sql_thread_t);

	/*
	 *	If the allocated IP attribute already exists, do nothing
	 */
	if (env->allocated_address.type) {
		RDEBUG2("%s already exists (%pV)", env->allocated_address_attr->name, &env->allocated_address);
		RETURN_MODULE_NOOP;
	}

	if (env->pool_name.type == FR_TYPE_NULL) {
		RDEBUG2("No %s defined", env->pool_name_tmpl->name);
		RETURN_MODULE_NOOP;
	}

	MEM(alloc_ctx = talloc(unlang_interpret_frame_talloc_ctx(request), ippool_alloc_ctx_t));
	*alloc_ctx = (ippool_alloc_ctx_t) {
		.env = env,
		.trunk = thread->trunk,
		.sql = inst->sql,
		.request = request,
	};
	talloc_set_destructor(alloc_ctx, sqlippool_alloc_ctx_free);

	/*
	 *	Allocate a query_ctx which will be used for all queries in the allocation.
	 *	Since they typically form an SQL transaction, they all need to be on the same
	 *	connection, and use the same trunk request if using trunks.
	 */
	MEM(alloc_ctx->query_ctx = sql->query_alloc(alloc_ctx, sql, request, thread->trunk, "", SQL_QUERY_OTHER));

	fr_value_box_list_init(&alloc_ctx->values);
	if (unlang_function_push(request, NULL, mod_alloc_resume, NULL, 0, UNLANG_SUB_FRAME, alloc_ctx) < 0 ) {
		talloc_free(alloc_ctx);
		RETURN_MODULE_FAIL;
	}

	if ((env->begin.type == FR_TYPE_STRING) && env->begin.vb_length) {
		alloc_ctx->query_ctx->query_str = env->begin.vb_strvalue;
		return unlang_function_push(request, sql->query, NULL, NULL, 0, UNLANG_SUB_FRAME, alloc_ctx->query_ctx);
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Resume function called after mod_common "update" query has completed
 */
static unlang_action_t mod_common_update_resume(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	ippool_common_ctx_t	*common_ctx = talloc_get_type_abort(uctx, ippool_common_ctx_t);
	fr_sql_query_t		*query_ctx = common_ctx->query_ctx;
	rlm_sql_t const		*sql = common_ctx->sql;
	int			affected = 0;

	switch (*p_result) {
	case RLM_MODULE_USER_SECTION_REJECT:
		return UNLANG_ACTION_CALCULATE_RESULT;

	default:
		break;
	}

	affected = sql->driver->sql_affected_rows(query_ctx, &sql->config);

	talloc_free(common_ctx);

	if (affected > 0) RETURN_MODULE_UPDATED;
	RETURN_MODULE_NOTFOUND;
}

/** Resume function called after mod_common "free" query has completed
 */
static unlang_action_t mod_common_free_resume(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	ippool_common_ctx_t	*common_ctx = talloc_get_type_abort(uctx, ippool_common_ctx_t);
	fr_sql_query_t		*query_ctx = common_ctx->query_ctx;
	rlm_sql_t const		*sql = common_ctx->sql;

	switch (*p_result) {
	case RLM_MODULE_USER_SECTION_REJECT:
		return UNLANG_ACTION_CALCULATE_RESULT;

	default:
		break;
	}
	if (common_ctx->env->update.type != FR_TYPE_STRING) RETURN_MODULE_NOOP;

	sql->driver->sql_finish_query(query_ctx, &sql->config);

	if (unlang_function_push(request, NULL, mod_common_update_resume, NULL, 0, UNLANG_SUB_FRAME, common_ctx) < 0) {
		talloc_free(common_ctx);
		RETURN_MODULE_FAIL;
	}

	common_ctx->query_ctx->query_str = common_ctx->env->update.vb_strvalue;
	query_ctx->status = SQL_QUERY_PREPARED;
	return unlang_function_push(request, sql->query, NULL, NULL, 0, UNLANG_SUB_FRAME, query_ctx);
}

/** Common function used by module methods which perform an optional "free" then "update"
 *	- update
 *	- release
 *	- bulk_release
 *	- mark
 */
static unlang_action_t CC_HINT(nonnull) mod_common(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sqlippool_t			*inst = talloc_get_type_abort(mctx->mi->data, rlm_sqlippool_t);
	ippool_common_call_env_t	*env = talloc_get_type_abort(mctx->env_data, ippool_common_call_env_t);
	rlm_sql_t const			*sql = inst->sql;
	rlm_sql_thread_t		*thread = talloc_get_type_abort(module_thread(sql->mi)->data, rlm_sql_thread_t);
	ippool_common_ctx_t		*common_ctx = NULL;

	if ((env->free.type != FR_TYPE_STRING) && (env->update.type != FR_TYPE_STRING)) RETURN_MODULE_NOOP;

	MEM(common_ctx = talloc(unlang_interpret_frame_talloc_ctx(request), ippool_common_ctx_t));
	*common_ctx = (ippool_common_ctx_t) {
		.request = request,
		.env = env,
		.sql = sql,
	};

	MEM(common_ctx->query_ctx = sql->query_alloc(common_ctx, sql, request, thread->trunk, "", SQL_QUERY_OTHER));

	/*
	 *  An optional query which can be used to tidy up before updates
	 *  primarily intended for multi-server setups sharing a common database
	 *  allowing for tidy up of multiple offered addresses in a DHCP context.
	 */
	if (env->free.type == FR_TYPE_STRING) {
		common_ctx->query_ctx->query_str = env->free.vb_strvalue;
		if (unlang_function_push(request, NULL, mod_common_free_resume, NULL, 0, UNLANG_SUB_FRAME, common_ctx) < 0) {
			talloc_free(common_ctx);
			RETURN_MODULE_FAIL;
		}
		return unlang_function_push(request, sql->query, NULL, NULL, 0, UNLANG_SUB_FRAME, common_ctx->query_ctx);
	}

	common_ctx->query_ctx->query_str = env->update.vb_strvalue;
	if (unlang_function_push(request, NULL, mod_common_update_resume, NULL, 0, UNLANG_SUB_FRAME, common_ctx) < 0) {
		talloc_free(common_ctx);
		RETURN_MODULE_FAIL;
	}
	return unlang_function_push(request, sql->query, NULL, NULL, 0, UNLANG_SUB_FRAME, common_ctx->query_ctx);
}

/** Call SQL module box_escape_func to escape tainted values
 */
static int sqlippool_box_escape(fr_value_box_t *vb, void *uctx) {
	rlm_sql_escape_uctx_t	*ctx = talloc_get_type_abort(uctx, rlm_sql_escape_uctx_t);

	return ctx->sql->box_escape_func(vb, uctx);
}

/** Custom parser for sqlippool call env
 *
 * Needed as the escape function needs to reference
 * the correct instance of the SQL module since escaping functions
 * are dependent on the driver used by a given module instance.
 */
static int call_env_parse(TALLOC_CTX *ctx, void *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci,
			  call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	rlm_sqlippool_t const	*inst = talloc_get_type_abort_const(cec->mi->data, rlm_sqlippool_t);
	module_instance_t const	*sql_inst;
	rlm_sql_t const		*sql;
	tmpl_t			*parsed_tmpl;
	CONF_PAIR const		*to_parse = cf_item_to_pair(ci);
	tmpl_rules_t		our_rules = *t_rules;

	/*
	 *	Lookup the sql module instance.
	 */
	sql_inst = module_rlm_static_by_name(NULL, inst->sql_name);
	if (!sql_inst) return -1;
	sql = talloc_get_type_abort(sql_inst->data, rlm_sql_t);

	/*
	 *	Set the sql module instance data as the uctx for escaping
	 *	and use the same "safe_for" as the sql module.
	 */
	our_rules.escape.uctx.func.uctx = sql;
	our_rules.escape.safe_for = (fr_value_box_safe_for_t)sql->driver;
	our_rules.literals_safe_for = (fr_value_box_safe_for_t)sql->driver;

	if (tmpl_afrom_substr(ctx, &parsed_tmpl,
			      &FR_SBUFF_IN(cf_pair_value(to_parse), talloc_array_length(cf_pair_value(to_parse)) - 1),
			      cf_pair_value_quote(to_parse), value_parse_rules_quoted[cf_pair_value_quote(to_parse)],
			      &our_rules) < 0) return -1;
	*(void **)out = parsed_tmpl;
	return 0;
}

#define QUERY_ESCAPE .pair.escape = { \
	.func = sqlippool_box_escape, \
	.mode = TMPL_ESCAPE_PRE_CONCAT, \
	.uctx = { .func = { .alloc = sql_escape_uctx_alloc }, .type = TMPL_ESCAPE_UCTX_ALLOC_FUNC }, \
}, .pair.func = call_env_parse

static const call_env_method_t sqlippool_alloc_method_env = {
	FR_CALL_ENV_METHOD_OUT(ippool_alloc_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_PARSE_OFFSET("pool_name", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_NULLABLE,
	     				   ippool_alloc_call_env_t, pool_name, pool_name_tmpl),
					   .pair.dflt = "&control.IP-Pool.Name", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_OFFSET("requested_address", FR_TYPE_VOID, CALL_ENV_FLAG_NULLABLE,
				     ippool_alloc_call_env_t, requested_address) },
		{ FR_CALL_ENV_PARSE_OFFSET("allocated_address_attr", FR_TYPE_VOID,
					   CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE,
					   ippool_alloc_call_env_t, allocated_address, allocated_address_attr) },
		{ FR_CALL_ENV_OFFSET("alloc_begin", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_NULLABLE,
				     ippool_alloc_call_env_t, begin), QUERY_ESCAPE,
				     .pair.dflt = "START TRANSACTION", .pair.dflt_quote = T_SINGLE_QUOTED_STRING },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("alloc_existing", FR_TYPE_STRING, CALL_ENV_FLAG_PARSE_ONLY,
						ippool_alloc_call_env_t, existing), QUERY_ESCAPE },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("alloc_requested", FR_TYPE_STRING, CALL_ENV_FLAG_PARSE_ONLY,
						ippool_alloc_call_env_t, requested), QUERY_ESCAPE },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("alloc_find", FR_TYPE_STRING, CALL_ENV_FLAG_PARSE_ONLY | CALL_ENV_FLAG_REQUIRED,
						ippool_alloc_call_env_t, find), QUERY_ESCAPE },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("alloc_update", FR_TYPE_STRING, CALL_ENV_FLAG_PARSE_ONLY,
						ippool_alloc_call_env_t, update), QUERY_ESCAPE },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("pool_check", FR_TYPE_STRING, CALL_ENV_FLAG_PARSE_ONLY,
						ippool_alloc_call_env_t, pool_check), QUERY_ESCAPE },
		{ FR_CALL_ENV_OFFSET("alloc_commit", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_NULLABLE,
				     ippool_alloc_call_env_t, commit), QUERY_ESCAPE,
				     .pair.dflt = "COMMIT", .pair.dflt_quote = T_SINGLE_QUOTED_STRING },
		CALL_ENV_TERMINATOR
	}
};

static const call_env_method_t sqlippool_update_method_env = {
	FR_CALL_ENV_METHOD_OUT(ippool_common_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("update_free", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_NULLABLE,
				     ippool_common_call_env_t, free), QUERY_ESCAPE },
		{ FR_CALL_ENV_OFFSET("update_update", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_NULLABLE,
				     ippool_common_call_env_t, update), QUERY_ESCAPE },
		CALL_ENV_TERMINATOR
	}
};

static const call_env_method_t sqlippool_release_method_env = {
	FR_CALL_ENV_METHOD_OUT(ippool_common_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("release_clear", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_NULLABLE,
				     ippool_common_call_env_t, update), QUERY_ESCAPE },
		CALL_ENV_TERMINATOR
	}
};

static const call_env_method_t sqlippool_bulk_release_method_env = {
	FR_CALL_ENV_METHOD_OUT(ippool_common_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("bulk_release_clear", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_NULLABLE,
				     ippool_common_call_env_t, update), QUERY_ESCAPE },
		CALL_ENV_TERMINATOR
	}
};

static const call_env_method_t sqlippool_mark_method_env = {
	FR_CALL_ENV_METHOD_OUT(ippool_common_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("mark_clear", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_NULLABLE,
				     ippool_common_call_env_t, update), QUERY_ESCAPE },
		CALL_ENV_TERMINATOR
	}
};

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_sqlippool;
module_rlm_t rlm_sqlippool = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "sqlippool",
		.inst_size	= sizeof(rlm_sqlippool_t),
		.config		= module_config,
		.instantiate	= mod_instantiate
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			/*
			*	RADIUS specific
			*/
			{ .section = SECTION_NAME("recv", "Access-Request"), .method = mod_alloc, .method_env = &sqlippool_alloc_method_env },
			{ .section = SECTION_NAME("accounting", "Start"), .method = mod_common, .method_env = &sqlippool_update_method_env },
			{ .section = SECTION_NAME("accounting", "Alive"), .method = mod_common, .method_env = &sqlippool_update_method_env },
			{ .section = SECTION_NAME("accounting", "Stop"), .method = mod_common, .method_env = &sqlippool_release_method_env },
			{ .section = SECTION_NAME("accounting", "Accounting-On"), .method = mod_common, .method_env = &sqlippool_bulk_release_method_env },
			{ .section = SECTION_NAME("accounting", "Accounting-Off"), .method = mod_common, .method_env = &sqlippool_bulk_release_method_env },

			/*
			*	DHCPv4
			*/
			{ .section = SECTION_NAME("recv", "Discover"), .method = mod_alloc, .method_env = &sqlippool_alloc_method_env },
			{ .section = SECTION_NAME("recv", "Request"), .method = mod_common, .method_env = &sqlippool_update_method_env },
			{ .section = SECTION_NAME("recv", "Confirm"), .method = mod_common, .method_env = &sqlippool_update_method_env },
			{ .section = SECTION_NAME("recv", "Rebind"), .method = mod_common, .method_env = &sqlippool_update_method_env },
			{ .section = SECTION_NAME("recv", "Renew"), .method = mod_common, .method_env = &sqlippool_update_method_env },
			{ .section = SECTION_NAME("recv", "Release"), .method = mod_common, .method_env = &sqlippool_release_method_env },
			{ .section = SECTION_NAME("recv", "Decline"), .method = mod_common, .method_env = &sqlippool_mark_method_env },

			/*
			*	Generic
			*/
			{ .section = SECTION_NAME("recv", CF_IDENT_ANY), .method = mod_common, .method_env = &sqlippool_update_method_env },
			{ .section = SECTION_NAME("send", CF_IDENT_ANY),.method = mod_alloc, .method_env = &sqlippool_alloc_method_env },

			/*
			*	Named methods matching module operations
			*/
			{ .section = SECTION_NAME("allocate", NULL), .method = mod_alloc, .method_env = &sqlippool_alloc_method_env },
			{ .section = SECTION_NAME("update", NULL), .method = mod_common, .method_env = &sqlippool_update_method_env },
			{ .section = SECTION_NAME("renew", NULL), .method = mod_common, .method_env = &sqlippool_update_method_env },
			{ .section = SECTION_NAME("release", NULL), .method = mod_common, .method_env = &sqlippool_release_method_env },
			{ .section = SECTION_NAME("bulk-release", NULL), .method = mod_common, .method_env = &sqlippool_bulk_release_method_env },
			{ .section = SECTION_NAME("mark", NULL),.method = mod_common,.method_env = &sqlippool_mark_method_env },

			MODULE_BINDING_TERMINATOR
		}
	}
};
