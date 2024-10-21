/*
 *  sql.c		rlm_sql - FreeRADIUS SQL Module
 *		Main code directly taken from ICRADIUS
 *
 * Version:	$Id$
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
 * @copyright 2001,2006 The FreeRADIUS server project
 * @copyright 2000 Mike Machado (mike@innercite.com)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 * @copyright 2001 Chad Miller (cmiller@surfsouth.com)
 */

RCSID("$Id$")

#define LOG_PREFIX inst->name

#include	<freeradius-devel/server/base.h>
#include	<freeradius-devel/util/debug.h>

#include	<sys/file.h>
#include	<sys/stat.h>

#include	<ctype.h>

#include	"rlm_sql.h"

/*
 *	Translate rlm_sql rcodes to humanly
 *	readable reason strings.
 */
fr_table_num_sorted_t const sql_rcode_description_table[] = {
	{ L("need alt query"),	RLM_SQL_ALT_QUERY	},
	{ L("no connection"),	RLM_SQL_RECONNECT	},
	{ L("no more rows"),	RLM_SQL_NO_MORE_ROWS	},
	{ L("query invalid"),	RLM_SQL_QUERY_INVALID	},
	{ L("server error"),	RLM_SQL_ERROR		},
	{ L("success"),		RLM_SQL_OK		}
};
size_t sql_rcode_description_table_len = NUM_ELEMENTS(sql_rcode_description_table);

fr_table_num_sorted_t const sql_rcode_table[] = {
	{ L("alternate"),	RLM_SQL_ALT_QUERY	},
	{ L("empty"),		RLM_SQL_NO_MORE_ROWS	},
	{ L("error"),		RLM_SQL_ERROR		},
	{ L("invalid"),		RLM_SQL_QUERY_INVALID	},
	{ L("ok"),		RLM_SQL_OK		},
	{ L("reconnect"),	RLM_SQL_RECONNECT	}
};
size_t sql_rcode_table_len = NUM_ELEMENTS(sql_rcode_table);

void *sql_mod_conn_create(TALLOC_CTX *ctx, void *instance, fr_time_delta_t timeout)
{
	int rcode;
	rlm_sql_t *inst = talloc_get_type_abort(instance, rlm_sql_t);
	rlm_sql_handle_t *handle;

	/*
	 *	Connections cannot be alloced from the inst or
	 *	pool contexts due to threading issues.
	 */
	handle = talloc_zero(ctx, rlm_sql_handle_t);
	if (!handle) return NULL;

	handle->log_ctx = talloc_pool(handle, 2048);
	if (!handle->log_ctx) {
		talloc_free(handle);
		return NULL;
	}

	/*
	 *	Handle requires a pointer to the SQL inst so the
	 *	destructor has access to the module configuration.
	 */
	handle->inst = inst;

	rcode = (inst->driver->sql_socket_init)(handle, &inst->config, timeout);
	if (rcode != 0) {
	fail:
		/*
		 *	Destroy any half opened connections.
		 */
		talloc_free(handle);
		return NULL;
	}

	if (inst->config.connect_query) {
		fr_sql_query_t	*query_ctx;
		rlm_rcode_t	p_result;
		MEM(query_ctx = fr_sql_query_alloc(ctx, inst, NULL, handle, NULL, inst->config.connect_query, SQL_QUERY_OTHER));
		inst->query(&p_result, NULL, NULL, query_ctx);
		if (query_ctx->rcode != RLM_SQL_OK) {
			talloc_free(query_ctx);
			goto fail;
		}
		talloc_free(query_ctx);
	}

	return handle;
}

#if 0
/*************************************************************************
 *
 *	Function: sql_pair_afrom_row
 *
 *	Purpose: Convert one rlm_sql_row_t to a fr_pair_t, and add it to "out"
 *
 *************************************************************************/
static int sql_pair_afrom_row(TALLOC_CTX *ctx, request_t *request, fr_pair_list_t *out, rlm_sql_row_t row, fr_pair_t **relative_vp)
{
	fr_pair_t		*vp;
	char const		*ptr, *value;
	char			buf[FR_MAX_STRING_LEN];
	fr_dict_attr_t const	*da;
	fr_token_t		token, op = T_EOL;
	fr_pair_list_t		*my_list;
	TALLOC_CTX		*my_ctx;

	/*
	 *	Verify the 'Attribute' field
	 */
	if (!row[2] || row[2][0] == '\0') {
		REDEBUG("Attribute field is empty or NULL, skipping the entire row");
		return -1;
	}

	/*
	 *	Verify the 'op' field
	 */
	if (row[4] != NULL && row[4][0] != '\0') {
		ptr = row[4];
		op = gettoken(&ptr, buf, sizeof(buf), false);
		if (!fr_assignment_op[op] && !fr_comparison_op[op]) {
			REDEBUG("Invalid op \"%s\" for attribute %s", row[4], row[2]);
			return -1;
		}

	} else {
		/*
		 *  Complain about empty or invalid 'op' field
		 */
		op = T_OP_CMP_EQ;
		REDEBUG("The op field for attribute '%s = %s' is NULL, or non-existent.", row[2], row[3]);
		REDEBUG("You MUST FIX THIS if you want the configuration to behave as you expect");
	}

	/*
	 *	The 'Value' field may be empty or NULL
	 */
	if (!row[3]) {
		REDEBUG("Value field is empty or NULL, skipping the entire row");
		return -1;
	}

	RDEBUG3("Found row[%s]: %s %s %s", row[0], row[2], fr_table_str_by_value(fr_tokens_table, op, "<INVALID>"), row[3]);

	value = row[3];

	/*
	 *	If we have a string, where the *entire* string is
	 *	quoted, do xlat's.
	 */
	if (row[3] != NULL &&
	   ((row[3][0] == '\'') || (row[3][0] == '`') || (row[3][0] == '"')) &&
	   (row[3][0] == row[3][strlen(row[3])-1])) {

		token = gettoken(&value, buf, sizeof(buf), false);
		switch (token) {
		/*
		 *	Take the unquoted string.
		 */
		case T_BACK_QUOTED_STRING:
		case T_SINGLE_QUOTED_STRING:
		case T_DOUBLE_QUOTED_STRING:
			value = buf;
			break;

		/*
		 *	Keep the original string.
		 */
		default:
			value = row[3];
			break;
		}
	}

	/*
	 *	Check for relative attributes
	 *
	 *	@todo - allow "..foo" to mean "grandparent of
	 *	relative_vp", and it should also update relative_vp
	 *	with the new parent.  However, doing this means
	 *	walking the list of the current relative_vp, finding
	 *	the dlist head, and then converting that into a
	 *	fr_pair_t pointer.  That's complex, so we don't do it
	 *	right now.
	 */
	if (row[2][0] == '.') {
		char const *p = row[2];

		if (!*relative_vp) {
			REDEBUG("Relative attribute '%s' can only be used immediately after an attribute of type 'group'", row[2]);
			return -1;
		}

		da = fr_dict_attr_by_oid(NULL, (*relative_vp)->da, p + 1);
		if (!da) goto unknown;

		my_list = &(*relative_vp)->vp_group;
		my_ctx = *relative_vp;

		MEM(vp = fr_pair_afrom_da(my_ctx, da));
		fr_pair_append(my_list, vp);
	} else {
		/*
		 *	Search in our local dictionary
		 *	falling back to internal.
		 */
		da = fr_dict_attr_by_oid(NULL, fr_dict_root(request->dict), row[2]);
		if (!da) {
			da = fr_dict_attr_by_oid(NULL, fr_dict_root(fr_dict_internal()), row[2]);
			if (!da) {
			unknown:
				RPEDEBUG("Unknown attribute '%s'", row[2]);
				return -1;
			}
		}

		my_list = out;
		my_ctx = ctx;

		MEM(vp = fr_pair_afrom_da_nested(my_ctx, my_list, da));
	}

	vp->op = op;

	if ((vp->vp_type == FR_TYPE_TLV) && !*value) {
		/*
		 *	Allow empty values for TLVs: we just create the value.
		 *
		 *	fr_pair_value_from_str() is not yet updated to
		 *	handle TLVs.  Until such time as we know what
		 *	to do there, we will just do a hack here,
		 *	specific to the SQL module.
		 */
	} else {
		if (fr_pair_value_from_str(vp, value, strlen(value), NULL, true) < 0) {
			RPEDEBUG("Error parsing value");
			return -1;
		}
	}

	/*
	 *	Update the relative vp.
	 */
	if (my_list == out) switch (da->type) {
	case FR_TYPE_STRUCTURAL:
		*relative_vp = vp;
		break;

	default:
		break;
	}

	/*
	 *	If there's a relative VP, and it's not the one
	 *	we just added above, and we're not adding this
	 *	VP to the relative one, then nuke the relative
	 *	VP.
	 */
	if (*relative_vp && (vp != *relative_vp) && (my_ctx != *relative_vp)) {
		*relative_vp = NULL;
	}

	return 0;
}
#endif

/** Call the driver's sql_fetch_row function
 *
 * Calls the driver's sql_fetch_row logging any errors. On success, will
 * write row data to ``uctx->row``.
 *
 * The rcode within the query context is updated to
 *	- #RLM_SQL_OK on success.
 *	- other #sql_rcode_t constants on error.
 *
 * @param p_result	Result of current module call.
 * @param priority	Unused.
 * @param request	Current request.
 * @param uctx		query context containing query to execute.
 * @return an unlang_action_t.
 */
unlang_action_t rlm_sql_fetch_row(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	fr_sql_query_t	*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_t const	*inst = query_ctx->inst;

	if ((inst->driver->uses_trunks && !query_ctx->tconn) ||
	    (!inst->driver->uses_trunks && (!query_ctx->handle || !query_ctx->handle->conn))) {
		ROPTIONAL(RERROR, ERROR, "Invalid connection");
		query_ctx->rcode = RLM_SQL_ERROR;
		RETURN_MODULE_FAIL;
	}

	/*
	 *	We can't implement reconnect logic here, because the caller
	 *	may require the original connection to free up queries or
	 *	result sets associated with that connection.
	 */
	(inst->driver->sql_fetch_row)(p_result, NULL, request, query_ctx);
	switch (query_ctx->rcode) {
	case RLM_SQL_OK:
		fr_assert(query_ctx->row != NULL);
		RETURN_MODULE_OK;

	case RLM_SQL_NO_MORE_ROWS:
		fr_assert(query_ctx->row == NULL);
		RETURN_MODULE_OK;

	default:
		ROPTIONAL(RERROR, ERROR, "Error fetching row");
		rlm_sql_print_error(inst, request, query_ctx, false);
		RETURN_MODULE_FAIL;
	}
}

/** Retrieve any errors from the SQL driver
 *
 * Retrieves errors from the driver from the last operation and writes them to
 * to request/global log, in the ERROR, WARN, INFO and DEBUG categories.
 *
 * @param inst Instance of rlm_sql.
 * @param request Current request, may be NULL.
 * @param query_ctx Query context to retrieve errors for.
 * @param force_debug Force all errors to be logged as debug messages.
 */
void rlm_sql_print_error(rlm_sql_t const *inst, request_t *request, fr_sql_query_t *query_ctx, bool force_debug)
{
	char const	*driver = inst->driver_submodule->name;
	sql_log_entry_t	log[20];
	size_t		num, i;
	TALLOC_CTX	*log_ctx = talloc_new(NULL);

	num = (inst->driver->sql_error)(log_ctx, log, (NUM_ELEMENTS(log)), query_ctx, &inst->config);
	if (num == 0) {
		ROPTIONAL(RERROR, ERROR, "Unknown error");
		talloc_free(log_ctx);
		return;
	}

	for (i = 0; i < num; i++) {
		if (force_debug) goto debug;

		switch (log[i].type) {
		case L_ERR:
			ROPTIONAL(RERROR, ERROR, "%s: %s", driver, log[i].msg);
			break;

		case L_WARN:
			ROPTIONAL(RWARN, WARN, "%s: %s", driver, log[i].msg);
			break;

		case L_INFO:
			ROPTIONAL(RINFO, INFO, "%s: %s", driver, log[i].msg);
			break;

		case L_DBG:
		default:
		debug:
			ROPTIONAL(RDEBUG2, DEBUG2, "%s: %s", driver, log[i].msg);
			break;
		}
	}

	talloc_free(log_ctx);
}

/** Automatically run the correct `finish` function when freeing an SQL query
 *
 * And mark any associated trunk request as complete.
 */
static int fr_sql_query_free(fr_sql_query_t *to_free)
{
	if (to_free->status > 0) {
		if (to_free->type == SQL_QUERY_SELECT) {
			(to_free->inst->driver->sql_finish_select_query)(to_free, &to_free->inst->config);
		} else {
			(to_free->inst->driver->sql_finish_query)(to_free, &to_free->inst->config);
		}
	}
	if (to_free->treq) trunk_request_signal_complete(to_free->treq);
	return 0;
}

/** Allocate an sql query structure
 *
 */
fr_sql_query_t *fr_sql_query_alloc(TALLOC_CTX *ctx, rlm_sql_t const *inst, request_t *request, rlm_sql_handle_t *handle,
				   trunk_t *trunk, char const *query_str, fr_sql_query_type_t type)
{
	fr_sql_query_t	*query;
	MEM(query = talloc(ctx, fr_sql_query_t));
	*query = (fr_sql_query_t) {
		.inst = inst,
		.handle = handle,
		.request = request,
		.trunk = trunk,
		.query_str = query_str,
		.type = type
	};
	talloc_set_destructor(query, fr_sql_query_free);
	return query;
}

/** Call the driver's sql_query method, reconnecting if necessary.
 *
 * @note Caller must call ``(inst->driver->sql_finish_query)(handle, &inst->config);``
 *	after they're done with the result.
 *
 * The rcode within the query context is updated to
 *	- #RLM_SQL_OK on success.
 *	- #RLM_SQL_RECONNECT if a new handle is required (also sets the handle to NULL).
 *	- #RLM_SQL_QUERY_INVALID, #RLM_SQL_ERROR on invalid query or connection error.
 *	- #RLM_SQL_ALT_QUERY on constraints violation.
 *
 * @param p_result	Result of current module call.
 * @param priority	Unused.
 * @param request	Current request.
 * @param uctx		query context containing query to execute.
 * @return an unlang_action_t.
 */
unlang_action_t rlm_sql_query(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	fr_sql_query_t	*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_t const	*inst = query_ctx->inst;
	int		i, count;

	/* Caller should check they have a valid handle */
	fr_assert(query_ctx->handle);

	/* There's no query to run, return an error */
	if (query_ctx->query_str[0] == '\0') {
		if (request) REDEBUG("Zero length query");
		RETURN_MODULE_INVALID;
	}

	/*
	 *  inst->pool may be NULL is this function is called by sql_mod_conn_create.
	 */
	count = inst->pool ? fr_pool_state(inst->pool)->num : 0;

	/*
	 *  Here we try with each of the existing connections, then try to create
	 *  a new connection, then give up.
	 */
	for (i = 0; i < (count + 1); i++) {
		ROPTIONAL(RDEBUG2, DEBUG2, "Executing query: %s", query_ctx->query_str);

		(inst->driver->sql_query)(p_result, NULL, request, query_ctx);
		query_ctx->status = SQL_QUERY_SUBMITTED;
		switch (query_ctx->rcode) {
		case RLM_SQL_OK:
			RETURN_MODULE_OK;

		/*
		 *	Run through all available sockets until we exhaust all existing
		 *	sockets in the pool and fail to establish a *new* connection.
		 */
		case RLM_SQL_RECONNECT:
			query_ctx->handle = fr_pool_connection_reconnect(inst->pool, request, query_ctx->handle);
			/* Reconnection failed */
			if (!query_ctx->handle) RETURN_MODULE_FAIL;
			/* Reconnection succeeded, try again with the new handle */
			continue;

		/*
		 *	These are bad and should make rlm_sql return invalid
		 */
		case RLM_SQL_QUERY_INVALID:
			rlm_sql_print_error(inst, request, query_ctx, false);
			(inst->driver->sql_finish_query)(query_ctx, &inst->config);
			RETURN_MODULE_INVALID;

		/*
		 *	Server or client errors.
		 *
		 *	If the driver claims to be able to distinguish between
		 *	duplicate row errors and other errors, and we hit a
		 *	general error treat it as a failure.
		 *
		 *	Otherwise rewrite it to RLM_SQL_ALT_QUERY.
		 */
		case RLM_SQL_ERROR:
			if (inst->driver->flags & RLM_SQL_RCODE_FLAGS_ALT_QUERY) {
				rlm_sql_print_error(inst, request, query_ctx, false);
				(inst->driver->sql_finish_query)(query_ctx, &inst->config);
				RETURN_MODULE_FAIL;
			}
			FALL_THROUGH;

		/*
		 *	Driver suggested using an alternative query
		 */
		case RLM_SQL_ALT_QUERY:
			rlm_sql_print_error(inst, request, query_ctx, true);
			(inst->driver->sql_finish_query)(query_ctx, &inst->config);
			break;

		default:
			break;
		}

		RETURN_MODULE_OK;
	}

	ROPTIONAL(RERROR, ERROR, "Hit reconnection limit");

	query_ctx->rcode = RLM_SQL_ERROR;
	RETURN_MODULE_FAIL;
}

/** Yield processing after submitting a trunk request.
 */
static unlang_action_t sql_trunk_query_start(UNUSED rlm_rcode_t *p_result, UNUSED int *priority,
				       UNUSED request_t *request, UNUSED void *uctx)
{
	return UNLANG_ACTION_YIELD;
}

/** Cancel an SQL query submitted on a trunk
 */
static void sql_trunk_query_cancel(UNUSED request_t *request, UNUSED fr_signal_t action, void *uctx)
{
	fr_sql_query_t	*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);

	if (!query_ctx->treq) return;

	/*
	 *	The query_ctx needs to be parented by the treq so that it still exists
	 *	when the cancel_mux callback is run.
	 */
	talloc_steal(query_ctx->treq, query_ctx);

	trunk_request_signal_cancel(query_ctx->treq);

	query_ctx->treq = NULL;
}

/** Submit an SQL query using a trunk connection.
 *
 * @param p_result	Result of current module call.
 * @param priority	Unused.
 * @param request	Current request.
 * @param uctx		query context containing query to execute.
 * @return an unlang_action_t.
 */
unlang_action_t rlm_sql_trunk_query(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	fr_sql_query_t	*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	trunk_enqueue_t	status;

	fr_assert(query_ctx->trunk);

	/* There's no query to run, return an error */
	if (query_ctx->query_str[0] == '\0') {
		if (request) REDEBUG("Zero length query");
		RETURN_MODULE_INVALID;
	}

	/*
	 *	If the query already has a treq, and that is not in the "init" state
	 *	then this is part of an ongoing transaction and needs requeueing
	 *	to submit on the same connection.
	 */
	if (query_ctx->treq && query_ctx->treq->state != TRUNK_REQUEST_STATE_INIT) {
		status = trunk_request_requeue(query_ctx->treq);
	} else {
		status = trunk_request_enqueue(&query_ctx->treq, query_ctx->trunk, request, query_ctx, NULL);
	}
	switch (status) {
	case TRUNK_ENQUEUE_OK:
	case TRUNK_ENQUEUE_IN_BACKLOG:
		/*
		 *	Drivers such as SQLite which are synchronous run the query immediately
		 *	on queueing.  If the query fails then the trunk request will be failed
		 *	in which case the query_ctx will no longer have a trunk request.
		 */
		if (!query_ctx->treq) RETURN_MODULE_FAIL;

		/*
		 *	Synchronous drivers will have processed the query and set the
		 *	state of the trunk request to reapable - so in that case don't
		 *	yield (in sql_trunk_query_start)
		 */
		if (unlang_function_push(request,
					 query_ctx->treq->state == TRUNK_REQUEST_STATE_REAPABLE ?
					 	NULL : sql_trunk_query_start,
					 query_ctx->type == SQL_QUERY_SELECT ?
					 	query_ctx->inst->driver->sql_select_query_resume :
						query_ctx->inst->driver->sql_query_resume,
					 sql_trunk_query_cancel, ~FR_SIGNAL_CANCEL,
					 UNLANG_SUB_FRAME, query_ctx) < 0) RETURN_MODULE_FAIL;
		*p_result = RLM_MODULE_OK;
		return UNLANG_ACTION_PUSHED_CHILD;

	default:
		REDEBUG("Unable to enqueue SQL query");
		query_ctx->status = SQL_QUERY_FAILED;
		query_ctx->rcode = RLM_SQL_ERROR;
		RETURN_MODULE_FAIL;
	}
}

/** Call the driver's sql_select_query method, reconnecting if necessary.
 *
 * @note Caller must call ``(inst->driver->sql_finish_select_query)(handle, &inst->config);``
 *	after they're done with the result.
 *
 * The rcode within the query context is updated to
 *	- #RLM_SQL_OK on success.
 *	- #RLM_SQL_RECONNECT if a new handle is required (also sets the handle to NULL).
 *	- #RLM_SQL_QUERY_INVALID, #RLM_SQL_ERROR on invalid query or connection error.
 *	- #RLM_SQL_ALT_QUERY on constraints violation.
 *
 * @param p_result	Result of current module call.
 * @param priority	Unused.
 * @param request	Current request.
 * @param uctx		query context containing query to execute.
 * @return an unlang_action_t.
 */
unlang_action_t rlm_sql_select_query(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	fr_sql_query_t	*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_t const	*inst = query_ctx->inst;
	int i, count;

	/* Caller should check they have a valid handle */
	fr_assert(query_ctx->handle);

	/* There's no query to run, return an error */
	if (query_ctx->query_str[0] == '\0') {
		if (request) REDEBUG("Zero length query");
		query_ctx->rcode = RLM_SQL_QUERY_INVALID;
		RETURN_MODULE_INVALID;
	}

	/*
	 *  inst->pool may be NULL is this function is called by sql_mod_conn_create.
	 */
	count = inst->pool ? fr_pool_state(inst->pool)->num : 0;

	/*
	 *  For sanity, for when no connections are viable, and we can't make a new one
	 */
	for (i = 0; i < (count + 1); i++) {
		ROPTIONAL(RDEBUG2, DEBUG2, "Executing select query: %s", query_ctx->query_str);

		(inst->driver->sql_select_query)(p_result, NULL, request, query_ctx);
		query_ctx->status = SQL_QUERY_SUBMITTED;
		switch (query_ctx->rcode) {
		case RLM_SQL_OK:
			RETURN_MODULE_OK;

		/*
		 *	Run through all available sockets until we exhaust all existing
		 *	sockets in the pool and fail to establish a *new* connection.
		 */
		case RLM_SQL_RECONNECT:
			query_ctx->handle = fr_pool_connection_reconnect(inst->pool, request, query_ctx->handle);
			/* Reconnection failed */
			if (!query_ctx->handle) RETURN_MODULE_FAIL;
			/* Reconnection succeeded, try again with the new handle */
			continue;

		case RLM_SQL_QUERY_INVALID:
		case RLM_SQL_ERROR:
		default:
			rlm_sql_print_error(inst, request, query_ctx, false);
			(inst->driver->sql_finish_select_query)(query_ctx, &inst->config);
			if (query_ctx->rcode == RLM_SQL_QUERY_INVALID) RETURN_MODULE_INVALID;
			RETURN_MODULE_FAIL;
		}
	}

	ROPTIONAL(RERROR, ERROR, "Hit reconnection limit");

	query_ctx->rcode = RLM_SQL_ERROR;
	RETURN_MODULE_FAIL;
}

/** Process the results of an SQL query to produce a map list.
 *
 */
static unlang_action_t sql_get_map_list_resume(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	fr_sql_map_ctx_t	*map_ctx = talloc_get_type_abort(uctx, fr_sql_map_ctx_t);
	tmpl_rules_t		lhs_rules = (tmpl_rules_t) {
		.attr = {
			.dict_def = request->dict,
			.prefix = TMPL_ATTR_REF_PREFIX_AUTO,
			.list_def = map_ctx->list,
			.list_presence = TMPL_ATTR_LIST_ALLOW
		}
	};
	tmpl_rules_t	rhs_rules = lhs_rules;
	fr_sql_query_t	*query_ctx = map_ctx->query_ctx;
	rlm_sql_row_t	row;
	map_t		*parent = NULL;
	rlm_sql_t const	*inst = map_ctx->inst;

	rhs_rules.attr.prefix = TMPL_ATTR_REF_PREFIX_YES;
	rhs_rules.attr.list_def = request_attr_request;

	if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL;

	while ((inst->fetch_row(p_result, NULL, request, query_ctx) == UNLANG_ACTION_CALCULATE_RESULT) &&
	       (query_ctx->rcode == RLM_SQL_OK)) {
		map_t *map;

		row = query_ctx->row;
		if (!row[2] || !row[3] || !row[4]) {
			RPERROR("SQL query returned NULL values");
			RETURN_MODULE_FAIL;
		}
		if (map_afrom_fields(map_ctx->ctx, &map, &parent, request, row[2], row[4], row[3], &lhs_rules, &rhs_rules) < 0) {
			RPEDEBUG("Error parsing user data from database result");
			RETURN_MODULE_FAIL;
		}
		if (!map->parent) map_list_insert_tail(map_ctx->out, map);

		map_ctx->rows++;
	}
	talloc_free(query_ctx);

	RETURN_MODULE_OK;
}

/** Submit the query to get any user / group check or reply pairs
 *
 */
unlang_action_t sql_get_map_list(request_t *request, fr_sql_map_ctx_t *map_ctx, rlm_sql_handle_t **handle,
				 trunk_t *trunk)
{
	rlm_sql_t const	*inst = map_ctx->inst;

	fr_assert(request);

	MEM(map_ctx->query_ctx = fr_sql_query_alloc(map_ctx->ctx, inst, request, *handle, trunk,
						    map_ctx->query->vb_strvalue, SQL_QUERY_SELECT));

	if (unlang_function_push(request, NULL, sql_get_map_list_resume, NULL, 0, UNLANG_SUB_FRAME, map_ctx) < 0) return UNLANG_ACTION_FAIL;

	return unlang_function_push(request, inst->select, NULL, NULL, 0, UNLANG_SUB_FRAME, map_ctx->query_ctx);
}

/*
 *	Log the query to a file.
 */
void rlm_sql_query_log(rlm_sql_t const *inst, char const *filename, char const *query)
{
	int fd;
	size_t len;
	bool failed = false;	/* Write the log message outside of the critical region */

	fd = exfile_open(inst->ef, filename, 0640, NULL);
	if (fd < 0) {
		ERROR("Couldn't open logfile '%s': %s", filename, fr_syserror(errno));

		/* coverity[missing_unlock] */
		return;
	}

	len = strlen(query);
	if ((write(fd, query, len) < 0) || (write(fd, ";\n", 2) < 0)) failed = true;

	if (failed) ERROR("Failed writing to logfile '%s': %s", filename, fr_syserror(errno));

	exfile_close(inst->ef, fd);
}
