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
	IPPOOL_ALLOC_EXISTING,			//!< Expanding the "existing" query
	IPPOOL_ALLOC_REQUESTED,			//!< Expanding the "requested" query
	IPPOOL_ALLOC_FIND,			//!< Expanding the "find" query
	IPPOOL_ALLOC_POOL_CHECK,		//!< Expanding the "pool_check" query
	IPPOOL_ALLOC_UPDATE			//!< Expanding the "update" query
} ippool_alloc_status_t;

/**  Resume context for IP allocation
 */
typedef struct {
	request_t		*request;	//!< Current request.
	ippool_alloc_status_t	status;		//!< Status of the allocation.
	ippool_alloc_call_env_t	*env;		//!< Call environment for the allocation.
	rlm_sql_handle_t	*handle;	//!< SQL handle being used for queries.
	rlm_sql_t const		*sql;		//!< SQL module instance.
	fr_value_box_list_t	values;		//!< Where to put the expanded queries ready for execution.
} ippool_alloc_ctx_t;

static conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("sql_module_instance", rlm_sqlippool_t, sql_name), .dflt = "sql" },

	CONF_PARSER_TERMINATOR
};

static int _sql_escape_uxtx_free(void *uctx)
{
	return talloc_free(uctx);
}

static void *sql_escape_uctx_alloc(request_t *request, void const *uctx)
{
	static _Thread_local rlm_sql_escape_uctx_t	*t_ctx;

	if (unlikely(t_ctx == NULL)) {
		rlm_sql_escape_uctx_t *ctx;

		MEM(ctx = talloc_zero(NULL, rlm_sql_escape_uctx_t));
		fr_atexit_thread_local(t_ctx, _sql_escape_uxtx_free, ctx);
	}
	t_ctx->sql = uctx;
	t_ctx->handle = request_data_reference(request, (void *)sql_escape_uctx_alloc, 0);

	return t_ctx;
}

/** Perform a single sqlippool query
 *
 * Mostly wrapper around sql_query which returns the number of affected rows.
 *
 * @param[in] query sql query to execute.
 * @param[in] handle sql connection handle.
 * @param[in] sql Instance of rlm_sql.
 * @param[in] request Current request.
 * @return
 *	- number of affected rows on success.
 *	- < 0 on error.
 */
static int sqlippool_command(char const *query, rlm_sql_handle_t **handle,
			     rlm_sql_t const *sql, request_t *request)
{
	int	ret, affected;

	/*
	 *	If we don't have a command, do nothing.
	 */
	if (!query || !*query) return 0;

	/*
	 *	No handle?  That's an error.
	 */
	if (!handle || !*handle) return -1;

	ret = sql->query(sql, request, handle, query);
	if (ret < 0) return -1;

	/*
	 *	No handle, we can't continue.
	 */
	if (!*handle) return -1;

	affected = (sql->driver->sql_affected_rows)(*handle, &sql->config);

	(sql->driver->sql_finish_query)(*handle, &sql->config);

	return affected;
}

/*
 *	Don't repeat yourself
 */
#define DO_PART(_x) if(env->_x.type == FR_TYPE_STRING) { \
	if(sqlippool_command(env->_x.vb_strvalue, &handle, sql, request) <0) goto error; \
}
#define DO_AFFECTED(_x, _affected) if (env->_x.type == FR_TYPE_STRING) { \
	_affected = sqlippool_command(env->_x.vb_strvalue, &handle, sql, request); if (_affected < 0) goto error; \
}
#define RESERVE_CONNECTION(_handle, _pool, _request) _handle = fr_pool_connection_get(_pool, _request); \
	if (!_handle) { \
		REDEBUG("Failed reserving SQL connection"); \
		RETURN_MODULE_FAIL; \
	}


/*
 * Query the database expecting a single result row
 */
static int CC_HINT(nonnull (1, 3, 4, 5)) sqlippool_query1(char *out, int outlen, char const *query,
							  rlm_sql_handle_t **handle, rlm_sql_t const *sql,
							  request_t *request)
{
	int		rlen, retval;
	rlm_sql_row_t	row;

	*out = '\0';

	retval = sql->select(sql, request, handle, query);

	if ((retval != 0) || !*handle) {
		REDEBUG("database query error on '%s'", query);
		return 0;
	}

	if (sql->fetch_row(&row, sql, request, handle) < 0) {
		REDEBUG("Failed fetching query result");
		goto finish;
	}

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
	(sql->driver->sql_finish_select_query)(*handle, &sql->config);

	return retval;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_sqlippool_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	inst->name = talloc_asprintf(inst, "%s - %s", mctx->inst->name, inst->sql_name);

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
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	module_instance_t	*sql;
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	CONF_SECTION		*conf = mctx->inst->conf;

	sql = module_rlm_by_name(NULL, inst->sql_name);
	if (!sql) {
		cf_log_err(conf, "failed to find sql instance named %s",
			   inst->sql_name);
		return -1;
	}

	inst->sql = (rlm_sql_t *) sql->dl_inst->data;

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
	(void) request_data_get(to_free->request, (void *)sql_escape_uctx_alloc, 0);
	if (to_free->handle) fr_pool_connection_release(to_free->sql->pool, to_free->request, to_free->handle);
	return 0;
}

#define REPEAT_MOD_ALLOC_RESUME if (unlang_function_repeat_set(request, mod_alloc_resume) < 0) RETURN_MODULE_FAIL

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
	rlm_sql_handle_t	*handle = alloc_ctx->handle;
	rlm_sql_t const		*sql = alloc_ctx->sql;
	fr_value_box_t		*query = fr_value_box_list_pop_head(&alloc_ctx->values);

	switch (alloc_ctx->status) {
	case IPPOOL_ALLOC_EXISTING:
		if (query) {
			allocation_len = sqlippool_query1(allocation, sizeof(allocation), query->vb_strvalue, &handle,
							  alloc_ctx->sql, request);
			talloc_free(query);
			if (!handle) {
			error:
				talloc_free(alloc_ctx);
				RETURN_MODULE_FAIL;
			}
			if (allocation_len > 0) goto make_pair;
		}

		/*
		 *	If there's a requested address and associated query, expand that
		 */
		if (env->requested && (env->requested_address.type != FR_TYPE_NULL)) {
			alloc_ctx->status = IPPOOL_ALLOC_REQUESTED;
			REPEAT_MOD_ALLOC_RESUME;
			if (unlang_tmpl_push(alloc_ctx, &alloc_ctx->values, request, env->requested, NULL) < 0) goto error;
			return UNLANG_ACTION_PUSHED_CHILD;
		}
		goto expand_find;

	case IPPOOL_ALLOC_REQUESTED:
		if (query) {
			allocation_len = sqlippool_query1(allocation, sizeof(allocation), query->vb_strvalue, &handle,
							  alloc_ctx->sql, request);
			talloc_free(query);
			if (!handle) goto error;
			if (allocation_len > 0) goto make_pair;
		}

	expand_find:
		/*
		 *	Neither "existing" nor "requested" found an address, expand "find" query
		 */
		alloc_ctx->status = IPPOOL_ALLOC_FIND;
		REPEAT_MOD_ALLOC_RESUME;
		if (unlang_tmpl_push(alloc_ctx, &alloc_ctx->values, request, env->find, NULL) < 0) goto error;
		return UNLANG_ACTION_PUSHED_CHILD;

	case IPPOOL_ALLOC_FIND:
	{
		tmpl_t	ip_rhs;
		map_t	ip_map;

		allocation_len = sqlippool_query1(allocation, sizeof(allocation), query->vb_strvalue, &handle,
						  alloc_ctx->sql, request);
		talloc_free(query);
		if (!handle) goto error;

		if (allocation_len == 0) {
			/*
			 *  Nothing found
			 */
			DO_PART(commit);

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
		}

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
			DO_PART(commit);

			REDEBUG("Invalid IP address [%s] returned from database query.", allocation);
			goto error;
		}

		RDEBUG2("Allocated IP %s", allocation);

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
		if (query) {
			/*
			 *Ok, so the allocate-find query found nothing ...
			 *Let's check if the pool exists at all
			 */
			allocation_len = sqlippool_query1(allocation, sizeof(allocation),
							  query->vb_strvalue, &handle, sql, request);
			talloc_free(query);
			if (!handle) RETURN_MODULE_FAIL;

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
		}
		goto no_address;

	case IPPOOL_ALLOC_UPDATE:
		if (query) {
			if (sqlippool_command(query->vb_strvalue, &handle, sql, request) < 0) goto error;
			talloc_free(query);
		}

	finish:
		DO_PART(commit);

		talloc_free(alloc_ctx);
		RETURN_MODULE_UPDATED;
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
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	ippool_alloc_call_env_t	*env = talloc_get_type_abort(mctx->env_data, ippool_alloc_call_env_t);
	rlm_sql_t const		*sql = inst->sql;
	rlm_sql_handle_t	*handle;
	ippool_alloc_ctx_t	*alloc_ctx = NULL;

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

	RESERVE_CONNECTION(handle, inst->sql->pool, request);
	request_data_add(request, (void *)sql_escape_uctx_alloc, 0, handle, false, false, false);

	DO_PART(begin);

	MEM(alloc_ctx = talloc(unlang_interpret_frame_talloc_ctx(request), ippool_alloc_ctx_t));
	*alloc_ctx = (ippool_alloc_ctx_t) {
		.env = env,
		.handle = handle,
		.sql = inst->sql,
		.request = request,
	};
	talloc_set_destructor(alloc_ctx, sqlippool_alloc_ctx_free);
	fr_value_box_list_init(&alloc_ctx->values);
	if (unlang_function_push(request, NULL, mod_alloc_resume, NULL, 0, UNLANG_SUB_FRAME, alloc_ctx) < 0 ) {
	error:
		talloc_free(alloc_ctx);
		RETURN_MODULE_FAIL;
	}

	/*
	 *	Establish which tmpl needs expanding first.
	 *
	 *	If there is a query for finding the existing IP expand that first
	 */
	if (env->existing) {
		alloc_ctx->status = IPPOOL_ALLOC_EXISTING;
		if (unlang_tmpl_push(alloc_ctx, &alloc_ctx->values, request, env->existing, NULL) < 0) goto error;
		return UNLANG_ACTION_PUSHED_CHILD;
	}

	/*
	 *	If have a requested IP address and a query to find whether it is available then try that
	 */
	if (env->requested && (env->requested_address.type != FR_TYPE_NULL)) {
		alloc_ctx->status = IPPOOL_ALLOC_REQUESTED;
		if (unlang_tmpl_push(alloc_ctx, &alloc_ctx->values, request, env->requested, NULL) < 0) goto error;
		return UNLANG_ACTION_PUSHED_CHILD;
	}

	/*
	 *	If neither of the previous two queries were defined, first expand the "find" query
	 */
	alloc_ctx->status = IPPOOL_ALLOC_FIND;
	if (unlang_tmpl_push(alloc_ctx, &alloc_ctx->values, request, env->find, NULL) < 0) goto error;
	return UNLANG_ACTION_PUSHED_CHILD;
}

/** Common function used by module methods which perform an optional "free" then "update"
 *	- update
 *	- release
 *	- bulk_release
 *	- mark
 */
static unlang_action_t CC_HINT(nonnull) mod_common(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sqlippool_t			*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	ippool_common_call_env_t	*env = talloc_get_type_abort(mctx->env_data, ippool_common_call_env_t);
	rlm_sql_t const			*sql = inst->sql;
	rlm_sql_handle_t		*handle;
	int				affected = 0;

	RESERVE_CONNECTION(handle, inst->sql->pool, request);

	/*
	 *  An optional query which can be used to tidy up before updates
	 *  primarily intended for multi-server setups sharing a common database
	 *  allowing for tidy up of multiple offered addresses in a DHCP context.
	 */
	DO_PART(free);

	DO_AFFECTED(update, affected);

	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);

	if (affected > 0) RETURN_MODULE_UPDATED;
	RETURN_MODULE_NOTFOUND;

error:
	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
	RETURN_MODULE_FAIL;
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
static int call_env_parse(TALLOC_CTX *ctx, void *out, tmpl_rules_t const *t_rules, CONF_ITEM *ci, void const *data, UNUSED call_env_parser_t const *rule)
{
	rlm_sqlippool_t const	*inst = talloc_get_type_abort_const(data, rlm_sqlippool_t);
	module_instance_t const	*sql_inst;
	rlm_sql_t const		*sql;
	tmpl_t			*parsed_tmpl;
	CONF_PAIR const		*to_parse = cf_item_to_pair(ci);
	tmpl_rules_t		our_rules = *t_rules;

	/*
	 *	Lookup the sql module instance.
	 */
	sql_inst = module_rlm_by_name(NULL, inst->sql_name);
	if (!sql_inst) return -1;
	sql = talloc_get_type_abort(sql_inst->dl_inst->data, rlm_sql_t);

	/*
	 *	Set the sql module instance data as the uctx for escaping
	 *	and use the same "safe_for" as the sql module.
	 */
	our_rules.escape.uctx.func.uctx = sql;
	our_rules.escape.safe_for = (fr_value_box_safe_for_t)sql->driver;
	our_rules.literal.safe_for = (fr_value_box_safe_for_t)sql->driver;

	if (tmpl_afrom_substr(ctx, &parsed_tmpl,
			      &FR_SBUFF_IN(cf_pair_value(to_parse), talloc_array_length(cf_pair_value(to_parse)) - 1),
			      cf_pair_value_quote(to_parse), NULL, &our_rules) < 0) return -1;
	*(void **)out = parsed_tmpl;
	return 0;
};

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
				     ippool_alloc_call_env_t, begin), QUERY_ESCAPE },
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
				     ippool_alloc_call_env_t, commit), QUERY_ESCAPE },
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
		.flags		= MODULE_TYPE_THREAD_SAFE,
		.inst_size	= sizeof(rlm_sqlippool_t),
		.config		= module_config,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate
	},
	.method_names = (module_method_name_t[]){
		/*
		 *	RADIUS specific
		 */
		{ .name1 = "recv",		.name2 = "access-request",	.method = mod_alloc,
		  .method_env = &sqlippool_alloc_method_env },
		{ .name1 = "accounting",	.name2 = "start",		.method = mod_common,
		  .method_env = &sqlippool_update_method_env },
		{ .name1 = "accounting",	.name2 = "alive",		.method = mod_common,
		  .method_env = &sqlippool_update_method_env },
		{ .name1 = "accounting",	.name2 = "stop",		.method = mod_common,
		  .method_env = &sqlippool_release_method_env },
		{ .name1 = "accounting",	.name2 = "accounting-on",	.method = mod_common,
		  .method_env = &sqlippool_bulk_release_method_env },
		{ .name1 = "accounting",	.name2 = "accounting-off",	.method = mod_common,
		  .method_env = &sqlippool_bulk_release_method_env },

		/*
		 *	DHCPv4
		 */
		{ .name1 = "recv",		.name2 = "Discover",		.method = mod_alloc,
		  .method_env = &sqlippool_alloc_method_env },
		{ .name1 = "recv",		.name2 = "Request",		.method = mod_common,
		  .method_env = &sqlippool_update_method_env },
		{ .name1 = "recv",		.name2 = "Confirm",		.method = mod_common,
		  .method_env = &sqlippool_update_method_env },
		{ .name1 = "recv",		.name2 = "Rebind",		.method = mod_common,
		  .method_env = &sqlippool_update_method_env },
		{ .name1 = "recv",		.name2 = "Renew",		.method = mod_common,
		  .method_env = &sqlippool_update_method_env },
		{ .name1 = "recv",		.name2 = "Release",		.method = mod_common,
		  .method_env = &sqlippool_release_method_env },
		{ .name1 = "recv",		.name2 = "Decline",		.method = mod_common,
		  .method_env = &sqlippool_mark_method_env },

		/*
		 *	Generic
		 */
		{ .name1 = "recv",		.name2 = CF_IDENT_ANY,		.method = mod_common,
		  .method_env = &sqlippool_update_method_env },
		{ .name1 = "send",		.name2 = CF_IDENT_ANY,		.method = mod_alloc,
		  .method_env = &sqlippool_alloc_method_env },

		/*
		 *	Named methods matching module operations
		 */
		{ .name1 = "allocate",		.name2 = CF_IDENT_ANY,		.method = mod_alloc,
		  .method_env = &sqlippool_alloc_method_env },
		{ .name1 = "update",		.name2 = CF_IDENT_ANY,		.method = mod_common,
		  .method_env = &sqlippool_update_method_env },
		{ .name1 = "renew",		.name2 = CF_IDENT_ANY,		.method = mod_common,
		  .method_env = &sqlippool_update_method_env },
		{ .name1 = "release",		.name2 = CF_IDENT_ANY,		.method = mod_common,
		  .method_env = &sqlippool_release_method_env },
		{ .name1 = "bulk-release",	.name2 = CF_IDENT_ANY,		.method = mod_common,
		  .method_env = &sqlippool_bulk_release_method_env },
		{ .name1 = "mark",		.name2 = CF_IDENT_ANY,		.method = mod_common,
		  .method_env = &sqlippool_mark_method_env },

		MODULE_NAME_TERMINATOR
	}

};
