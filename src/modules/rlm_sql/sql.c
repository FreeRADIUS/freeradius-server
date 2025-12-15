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
 * @param request	Current request.
 * @param uctx		query context containing query to execute.
 * @return an unlang_action_t.
 */
unlang_action_t rlm_sql_fetch_row(unlang_result_t *p_result, request_t *request, void *uctx)
{
	fr_sql_query_t	*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_t const	*inst = query_ctx->inst;

	if (!query_ctx->tconn) {
		ROPTIONAL(RERROR, ERROR, "Invalid connection");
		query_ctx->rcode = RLM_SQL_ERROR;
		RETURN_UNLANG_FAIL;
	}

	/*
	 *	We can't implement reconnect logic here, because the caller
	 *	may require the original connection to free up queries or
	 *	result sets associated with that connection.
	 */
	(inst->driver->sql_fetch_row)(p_result, request, query_ctx);
	switch (query_ctx->rcode) {
	case RLM_SQL_OK:
		fr_assert(query_ctx->row != NULL);
		RETURN_UNLANG_OK;

	case RLM_SQL_NO_MORE_ROWS:
		fr_assert(query_ctx->row == NULL);
		RETURN_UNLANG_OK;

	default:
		ROPTIONAL(RERROR, ERROR, "Error fetching row");
		rlm_sql_print_error(inst, request, query_ctx, false);
		RETURN_UNLANG_FAIL;
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

	num = (inst->driver->sql_error)(log_ctx, log, (NUM_ELEMENTS(log)), query_ctx);
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
fr_sql_query_t *fr_sql_query_alloc(TALLOC_CTX *ctx, rlm_sql_t const *inst, request_t *request,
				   trunk_t *trunk, char const *query_str, fr_sql_query_type_t type)
{
	fr_sql_query_t	*query;
	MEM(query = talloc(ctx, fr_sql_query_t));
	*query = (fr_sql_query_t) {
		.inst = inst,
		.request = request,
		.trunk = trunk,
		.query_str = query_str,
		.type = type
	};
	talloc_set_destructor(query, fr_sql_query_free);
	return query;
}

/** Yield processing after submitting a trunk request.
 */
static unlang_action_t sql_trunk_query_start(UNUSED unlang_result_t *p_result,
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
	 *	A reapable trunk request has already completed.
	 */
	if (unlikely(query_ctx->treq->state == TRUNK_REQUEST_STATE_REAPABLE)) {
		trunk_request_signal_complete(query_ctx->treq);
		query_ctx->treq = NULL;
		return;
	}

	/*
	 *	The query_ctx needs to be parented by the treq so that it still exists
	 *	when the cancel_mux callback is run.
	 */
	if (query_ctx->inst->driver->trunk_io_funcs.request_cancel_mux) talloc_steal(query_ctx->treq, query_ctx);

	trunk_request_signal_cancel(query_ctx->treq);

	query_ctx->treq = NULL;
}

/** Submit an SQL query using a trunk connection.
 *
 * @param p_result	Result of current module call.
 * @param request	Current request.
 * @param uctx		query context containing query to execute.
 * @return an unlang_action_t.
 */
unlang_action_t rlm_sql_trunk_query(unlang_result_t *p_result, request_t *request, void *uctx)
{
	fr_sql_query_t	*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	trunk_enqueue_t	status;

	fr_assert(query_ctx->trunk);

	/* There's no query to run, return an error */
	if (query_ctx->query_str[0] == '\0') {
		if (request) REDEBUG("Zero length query");
		RETURN_UNLANG_INVALID;
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
		if (!query_ctx->treq) RETURN_UNLANG_FAIL;

		/*
		 *	Synchronous drivers will have processed the query and set the
		 *	state of the trunk request to reapable - so in that case don't
		 *	yield (in sql_trunk_query_start)
		 */
		if (unlang_function_push_with_result(/* allow the caller of rlm_sql_trunk_query to get at the rcode */p_result,
						     request,
						     query_ctx->treq->state == TRUNK_REQUEST_STATE_REAPABLE ?
							NULL : sql_trunk_query_start,
						     query_ctx->type == SQL_QUERY_SELECT ?
							query_ctx->inst->driver->sql_select_query_resume :
							query_ctx->inst->driver->sql_query_resume,
						     sql_trunk_query_cancel, ~FR_SIGNAL_CANCEL,
						     UNLANG_SUB_FRAME, query_ctx) < 0) RETURN_UNLANG_FAIL;
		p_result->rcode = RLM_MODULE_OK;
		return UNLANG_ACTION_PUSHED_CHILD;

	default:
		REDEBUG("Unable to enqueue SQL query");
		query_ctx->status = SQL_QUERY_FAILED;
		query_ctx->rcode = RLM_SQL_ERROR;
		RETURN_UNLANG_FAIL;
	}
}

/** Process the results of an SQL query to produce a map list.
 *
 */
static unlang_action_t sql_get_map_list_resume(unlang_result_t *p_result, request_t *request, void *uctx)
{
	fr_sql_map_ctx_t	*map_ctx = talloc_get_type_abort(uctx, fr_sql_map_ctx_t);
	tmpl_rules_t		lhs_rules = (tmpl_rules_t) {
		.attr = {
			.dict_def = request->local_dict,
			.list_def = map_ctx->list,
			.list_presence = TMPL_ATTR_LIST_ALLOW
		}
	};
	tmpl_rules_t	rhs_rules = lhs_rules;
	fr_sql_query_t	*query_ctx = map_ctx->query_ctx;
	rlm_sql_row_t	row;
	map_t		*parent = NULL;
	rlm_sql_t const	*inst = map_ctx->inst;

	rhs_rules.attr.list_def = request_attr_request;

	if (query_ctx->rcode != RLM_SQL_OK) {
		rlm_sql_print_error(inst, request, query_ctx, false);
		RETURN_UNLANG_FAIL;
	}

	while ((inst->fetch_row(p_result, request, query_ctx) == UNLANG_ACTION_CALCULATE_RESULT) &&
	       (query_ctx->rcode == RLM_SQL_OK)) {
		map_t *map;

		row = query_ctx->row;
		if (!row[2] || !row[3] || !row[4]) {
			RPERROR("SQL query returned NULL values");
			RETURN_UNLANG_FAIL;
		}
		if (map_afrom_fields(map_ctx->ctx, &map, &parent, request, row[2], row[4], row[3],
				     &lhs_rules, &rhs_rules,
				     !(inst->config.expand_rhs || map_ctx->expand_rhs)) < 0) {
			RPEDEBUG("Data read from SQL cannot be parsed.");
			REDEBUG("    %s", row[2]);
			REDEBUG("    %s", row[4]);
			REDEBUG("    %s", row[3]);
			RETURN_UNLANG_FAIL;
		}
		if (!map->parent) map_list_insert_tail(map_ctx->out, map);

		map_ctx->rows++;
	}
	talloc_free(query_ctx);

	RETURN_UNLANG_OK;
}

/** Submit the query to get any user / group check or reply pairs
 *
 */
unlang_action_t sql_get_map_list(unlang_result_t *p_result, request_t *request, fr_sql_map_ctx_t *map_ctx, trunk_t *trunk)
{
	rlm_sql_t const	*inst = map_ctx->inst;

	fr_assert(request);
	fr_assert(map_ctx->query);

	MEM(map_ctx->query_ctx = fr_sql_query_alloc(map_ctx->ctx, inst, request, trunk,
						    map_ctx->query->vb_strvalue, SQL_QUERY_SELECT));

	if (unlang_function_push_with_result(p_result,
					     request,
					     NULL,
					     sql_get_map_list_resume,
					     NULL, 0,
					     UNLANG_SUB_FRAME,
					    map_ctx) < 0) return UNLANG_ACTION_FAIL;

	return unlang_function_push_with_result(/* discard, sql_get_map_list_resume uses query_ctx->rcode */ NULL,
						request,
						inst->select,
						NULL,
						NULL, 0,
						UNLANG_SUB_FRAME,
						map_ctx->query_ctx);
}

/*
 *	Log the query to a file.
 */
void rlm_sql_query_log(rlm_sql_t const *inst, char const *filename, char const *query)
{
	int fd;
	size_t len;
	bool failed = false;	/* Write the log message outside of the critical region */

	fd = exfile_open(inst->ef, filename, 0640, 0, NULL);
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
