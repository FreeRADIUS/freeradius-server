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

#include <ctype.h>

/*
 *	Define a structure for our module configuration.
 */
typedef struct {
	char const      *name;
	char const	*sql_name;

	rlm_sql_t const	*sql;

	tmpl_t		*requested_address;	//!< name of the requested IP address attribute

						/* Alloc sequence */
	char const	*alloc_begin;		//!< SQL query to begin.
	char const	*alloc_existing;	//!< SQL query to find existing IP.
	char const	*alloc_requested;	//!< SQL query to find requested IP.
	char const	*alloc_find;		//!< SQL query to find an unused IP.
	char const	*alloc_update;		//!< SQL query to mark an IP as used.
	char const	*alloc_commit;		//!< SQL query to commit.

	char const	*pool_check;		//!< Query to check for the existence of the pool.

						/* Update sequence */
	char const	*update_free;		//!< SQL query to clear offered IPs
	char const	*update_update;		//!< SQL query to update an IP entry.

						/* Release sequence */
	char const	*release_clear;       	//!< SQL query to clear an IP entry.

						/* Bulk release sequence */
	char const	*bulk_release_clear;	//!< SQL query to bulk clear several IPs.

						/* Mark sequence */
	char const	*mark_update;		//!< SQL query to mark an IP.
} rlm_sqlippool_t;

typedef struct {
	fr_value_box_t	pool_name;			//!< Name of pool address will be allocated from.
	tmpl_t		*pool_name_tmpl;		//!< Tmpl used to expand pool_name
	tmpl_t		*allocated_address_attr;	//!< Attribute to populate with allocated IP.
	fr_value_box_t	allocated_address;		//!< Existing value for allocated IP.
} ippool_alloc_call_env_t;

static conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("sql_module_instance", rlm_sqlippool_t, sql_name), .dflt = "sql" },

	{ FR_CONF_OFFSET("requested_address", rlm_sqlippool_t, requested_address) },


	{ FR_CONF_OFFSET_FLAGS("alloc_begin", CONF_FLAG_XLAT, rlm_sqlippool_t, alloc_begin), .dflt = "START TRANSACTION" },

	{ FR_CONF_OFFSET_FLAGS("alloc_existing", CONF_FLAG_XLAT, rlm_sqlippool_t, alloc_existing) },

	{ FR_CONF_OFFSET_FLAGS("alloc_requested", CONF_FLAG_XLAT, rlm_sqlippool_t, alloc_requested) },

	{ FR_CONF_OFFSET_FLAGS("alloc_find", CONF_FLAG_XLAT | CONF_FLAG_REQUIRED, rlm_sqlippool_t, alloc_find) },

	{ FR_CONF_OFFSET_FLAGS("alloc_update", CONF_FLAG_XLAT, rlm_sqlippool_t, alloc_update) },

	{ FR_CONF_OFFSET_FLAGS("alloc_commit", CONF_FLAG_XLAT, rlm_sqlippool_t, alloc_commit), .dflt = "COMMIT" },


	{ FR_CONF_OFFSET_FLAGS("pool_check", CONF_FLAG_XLAT, rlm_sqlippool_t, pool_check) },


	{ FR_CONF_OFFSET_FLAGS("update_free", CONF_FLAG_XLAT, rlm_sqlippool_t, update_free) },

	{ FR_CONF_OFFSET_FLAGS("update_update", CONF_FLAG_XLAT, rlm_sqlippool_t, update_update) },


	{ FR_CONF_OFFSET_FLAGS("release_clear", CONF_FLAG_XLAT, rlm_sqlippool_t, release_clear) },


	{ FR_CONF_OFFSET_FLAGS("bulk_release_clear", CONF_FLAG_XLAT, rlm_sqlippool_t, bulk_release_clear) },


	{ FR_CONF_OFFSET_FLAGS("mark_update", CONF_FLAG_XLAT, rlm_sqlippool_t, mark_update) },

	CONF_PARSER_TERMINATOR
};

/** Perform a single sqlippool query
 *
 * Mostly wrapper around sql_query which does some special sqlippool sequence substitutions and expands
 * the format string.
 *
 * @param[in] fmt sql query to expand.
 * @param[in] handle sql connection handle.
 * @param[in] data Instance of rlm_sqlippool.
 * @param[in] request Current request.
 * @return
 *	- number of affected rows on success.
 *	- < 0 on error.
 */
static int sqlippool_command(char const *fmt, rlm_sql_handle_t **handle,
			     rlm_sqlippool_t const *data, request_t *request)
{
	char *expanded = NULL;

	int ret;
	int affected;

	/*
	 *	If we don't have a command, do nothing.
	 */
	if (!fmt || !*fmt) return 0;

	/*
	 *	No handle?  That's an error.
	 */
	if (!handle || !*handle) return -1;

	if (xlat_aeval(request, &expanded, request, fmt, data->sql->sql_escape_func, *handle) < 0) return -1;

	ret = data->sql->query(data->sql, request, handle, expanded);
	talloc_free(expanded);
	if (ret < 0){
		return -1;
	}

	/*
	 *	No handle, we can't continue.
	 */
	if (!*handle) return -1;

	affected = (data->sql->driver->sql_affected_rows)(*handle, &data->sql->config);

	(data->sql->driver->sql_finish_query)(*handle, &data->sql->config);

	return affected;
}

/*
 *	Don't repeat yourself
 */
#define DO_PART(_x) if(sqlippool_command(inst->_x, &handle, inst, request) <0) goto error
#define RESERVE_CONNECTION(_handle, _pool, _request) _handle = fr_pool_connection_get(_pool, _request); \
	if (!_handle) { \
		REDEBUG("Failed reserving SQL connection"); \
		RETURN_MODULE_FAIL; \
	}


/*
 * Query the database expecting a single result row
 */
static int CC_HINT(nonnull (1, 3, 4, 5)) sqlippool_query1(char *out, int outlen, char const *fmt,
							  rlm_sql_handle_t **handle, rlm_sqlippool_t *data,
							  request_t *request)
{
	char *expanded = NULL;

	int rlen, retval;

	rlm_sql_row_t row;

	*out = '\0';

	/*
	 *	Do an xlat on the provided string
	 */
	if (xlat_aeval(request, &expanded, request, fmt, data->sql->sql_escape_func, *handle) < 0) {
		return 0;
	}
	retval = data->sql->select(data->sql, request, handle, expanded);
	talloc_free(expanded);

	if ((retval != 0) || !*handle) {
		REDEBUG("database query error on '%s'", fmt);
		return 0;
	}

	if (data->sql->fetch_row(&row, data->sql, request, handle) < 0) {
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
	(data->sql->driver->sql_finish_select_query)(*handle, &data->sql->config);

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

	if (inst->requested_address) {
		if (!tmpl_is_xlat(inst->requested_address)) {
			cf_log_err(conf, "requested_address must be a double quoted expansion, not %s",
				   tmpl_type_to_str(inst->requested_address->type));
		}
	}

	inst->sql = (rlm_sql_t *) sql->dl_inst->data;

	if (strcmp(talloc_get_name(inst->sql), "rlm_sql_t") != 0) {
		cf_log_err(conf, "Module \"%s\" is not an instance of the rlm_sql module",
			      inst->sql_name);
		return -1;
	}

	return 0;
}

/*
 *	Allocate an IP address from the pool.
 */
static unlang_action_t CC_HINT(nonnull) mod_alloc(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	ippool_alloc_call_env_t	*env = talloc_get_type_abort(mctx->env_data, ippool_alloc_call_env_t);
	char			allocation[FR_MAX_STRING_LEN];
	int			allocation_len;
	rlm_sql_handle_t	*handle;
	tmpl_t			ip_rhs;
	map_t			ip_map;

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

	DO_PART(alloc_begin);

	/*
	 *	If there is a query for finding the existing IP
	 *	run that first
	 */
	if (inst->alloc_existing && *inst->alloc_existing) {
		allocation_len = sqlippool_query1(allocation, sizeof(allocation),
						  inst->alloc_existing, &handle,
						  inst, request);
		if (!handle) RETURN_MODULE_FAIL;
	} else {
		allocation_len = 0;
	}

	/*
	 *	If no existing IP was found and we have a requested IP address
	 *	and a query to find whether it is available then try that
	 */
	if ((allocation_len == 0) && inst->alloc_requested && *inst->alloc_requested) {
		char buffer[128];
		char *ip = NULL;
		ssize_t slen;

		slen = tmpl_expand(&ip, buffer, sizeof(buffer), request, inst->requested_address, NULL, NULL);
		if (slen < 0) RETURN_MODULE_FAIL;

		if (slen > 0) {
			allocation_len = sqlippool_query1(allocation, sizeof(allocation),
							  inst->alloc_requested, &handle,
							  inst, request);
			if (!handle) RETURN_MODULE_FAIL;
		}
	}

	/*
	 *	If no existing IP was found (or no query was run),
	 *	run the query to find a free IP
	 */
	if (allocation_len == 0) {
		allocation_len = sqlippool_query1(allocation, sizeof(allocation),
						  inst->alloc_find, &handle,
						  inst, request);
		if (!handle) RETURN_MODULE_FAIL;
	}

	/*
	 *	Nothing found...
	 */
	if (allocation_len == 0) {
		DO_PART(alloc_commit);

		/*
		 *Should we perform pool-check ?
		 */
		if (inst->pool_check && *inst->pool_check) {

			/*
			 *Ok, so the allocate-find query found nothing ...
			 *Let's check if the pool exists at all
			 */
			allocation_len = sqlippool_query1(allocation, sizeof(allocation),
							  inst->pool_check, &handle, inst, request);
			if (!handle) RETURN_MODULE_FAIL;

			fr_pool_connection_release(inst->sql->pool, request, handle);

			if (allocation_len) {

				/*
				 *	Pool exists after all... So,
				 *	the failure to allocate the IP
				 *	address was most likely due to
				 *	the depletion of the pool. In
				 *	that case, we should return
				 *	NOTFOUND
				 */
				RDEBUG2("pool appears to be full");
				RETURN_MODULE_NOTFOUND;
			}

			/*
			 *	Pool doesn't exist in the table. It
			 *	may be handled by some other instance of
			 *	sqlippool, so we should just ignore this
			 *	allocation failure and return NOOP
			 */
			RDEBUG2("IP address could not be allocated as no pool exists with that name");
			RETURN_MODULE_NOOP;

		}

		fr_pool_connection_release(inst->sql->pool, request, handle);

		RDEBUG2("IP address could not be allocated");
		RETURN_MODULE_NOOP;
	}

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
		DO_PART(alloc_commit);

		RDEBUG2("Invalid IP address [%s] returned from database query.", allocation);
		fr_pool_connection_release(inst->sql->pool, request, handle);
		RETURN_MODULE_NOOP;
	}

	/*
	 *	UPDATE
	 */
	if (sqlippool_command(inst->alloc_update, &handle, inst, request) < 0) {
	error:
		if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
		RETURN_MODULE_FAIL;
	}

	DO_PART(alloc_commit);

	RDEBUG2("Allocated IP %s", allocation);

	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);

	RETURN_MODULE_OK;
}

/*
 *	Update a lease.
 */
static unlang_action_t CC_HINT(nonnull) mod_update(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	rlm_sql_handle_t	*handle;
	int			affected;

	RESERVE_CONNECTION(handle, inst->sql->pool, request);

	/*
	 *  An optional query which can be used to tidy up before updates
	 *  primarily intended for multi-server setups sharing a common database
	 *  allowing for tidy up of multiple offered addresses in a DHCP context.
	 */
	DO_PART(update_free);

	affected = sqlippool_command(inst->update_update, &handle, inst, request);

	if (affected < 0) {
	error:
		if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
		RETURN_MODULE_FAIL;
	}

	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);

	if (affected > 0) {
		/*
		 * The lease has been updated - return OK
		 */
		RETURN_MODULE_OK;
	} else {
		/*
		 * The lease could not be updated - return notfound
		 */
		RETURN_MODULE_NOTFOUND;
	}
}

/*
 *	Release a lease.
 */
static unlang_action_t CC_HINT(nonnull) mod_release(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	rlm_sql_handle_t	*handle;

	RESERVE_CONNECTION(handle, inst->sql->pool, request);

	DO_PART(release_clear);

	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
	RETURN_MODULE_OK;

	error:
	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
	RETURN_MODULE_FAIL;
}

/*
 *	Release a collection of leases.
 */
static unlang_action_t CC_HINT(nonnull) mod_bulk_release(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	rlm_sql_handle_t	*handle;

	RESERVE_CONNECTION(handle, inst->sql->pool, request);

	DO_PART(bulk_release_clear);

	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
	RETURN_MODULE_OK;

	error:
	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
	RETURN_MODULE_FAIL;
}

/*
 *	Mark a lease.  Typically for DHCP Decline where IPs need to be marked
 *	as invalid
 */
static unlang_action_t CC_HINT(nonnull) mod_mark(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_sqlippool_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_sqlippool_t);
	rlm_sql_handle_t	*handle;

	RESERVE_CONNECTION(handle, inst->sql->pool, request);

	DO_PART(mark_update);

	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
	RETURN_MODULE_OK;

	error:
	if (handle) fr_pool_connection_release(inst->sql->pool, request, handle);
	RETURN_MODULE_FAIL;
}

static const call_env_method_t sqlippool_alloc_method_env = {
	FR_CALL_ENV_METHOD_OUT(ippool_alloc_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_PARSE_OFFSET("pool_name", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_NULLABLE,
	     				   ippool_alloc_call_env_t, pool_name, pool_name_tmpl),
					   .pair.dflt = "&control.IP-Pool.Name", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_PARSE_OFFSET("allocated_address_attr", FR_TYPE_VOID,
					   CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE,
					   ippool_alloc_call_env_t, allocated_address, allocated_address_attr) },
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
		{ .name1 = "accounting",	.name2 = "start",		.method = mod_update },
		{ .name1 = "accounting",	.name2 = "alive",		.method = mod_update },
		{ .name1 = "accounting",	.name2 = "stop",		.method = mod_release },
		{ .name1 = "accounting",	.name2 = "accounting-on",	.method = mod_bulk_release },
		{ .name1 = "accounting",	.name2 = "accounting-off",	.method = mod_bulk_release },

		/*
		 *	DHCPv4
		 */
		{ .name1 = "recv",		.name2 = "Discover",		.method = mod_alloc,
		  .method_env = &sqlippool_alloc_method_env },
		{ .name1 = "recv",		.name2 = "Request",		.method = mod_update },
		{ .name1 = "recv",		.name2 = "Confirm",		.method = mod_update },
		{ .name1 = "recv",		.name2 = "Rebind",		.method = mod_update },
		{ .name1 = "recv",		.name2 = "Renew",		.method = mod_update },
		{ .name1 = "recv",		.name2 = "Release",		.method = mod_release },
		{ .name1 = "recv",		.name2 = "Decline",		.method = mod_mark },

		/*
		 *	Generic
		 */
		{ .name1 = "recv",		.name2 = CF_IDENT_ANY,		.method = mod_update },
		{ .name1 = "send",		.name2 = CF_IDENT_ANY,		.method = mod_alloc,
		  .method_env = &sqlippool_alloc_method_env },

		/*
		 *	Named methods matching module operations
		 */
		{ .name1 = "allocate",		.name2 = CF_IDENT_ANY,		.method = mod_alloc,
		  .method_env = &sqlippool_alloc_method_env },
		{ .name1 = "update",		.name2 = CF_IDENT_ANY,		.method = mod_update },
		{ .name1 = "renew",		.name2 = CF_IDENT_ANY,		.method = mod_update },
		{ .name1 = "release",		.name2 = CF_IDENT_ANY,		.method = mod_release },
		{ .name1 = "bulk-release",	.name2 = CF_IDENT_ANY,		.method = mod_bulk_release },
		{ .name1 = "mark",		.name2 = CF_IDENT_ANY,		.method = mod_mark },

		MODULE_NAME_TERMINATOR
	}

};
