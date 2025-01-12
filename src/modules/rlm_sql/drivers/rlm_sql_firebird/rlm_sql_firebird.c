/*
 * sql_firebird.c Part of Firebird rlm_sql driver
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * @copyright 2006 The FreeRADIUS server project
 * @copyright 2006 Vitaly Bodzhgua (vitaly@eastera.net)
 */
RCSID("$Id$")

#define LOG_PREFIX "sql - firebird"

#include "sql_fbapi.h"
#include <freeradius-devel/util/debug.h>
#include "rlm_sql_trunk.h"

static char tpb[] = {isc_tpb_version3, isc_tpb_wait, isc_tpb_write,
		     isc_tpb_read_committed, isc_tpb_no_rec_version};

/** Establish connection to the db
 *
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static connection_state_t _sql_connection_init(void **h, connection_t *conn, void *uctx)
{
	rlm_sql_t const		*sql = talloc_get_type_abort_const(uctx, rlm_sql_t);
	rlm_sql_firebird_conn_t	*c;

	MEM(c = talloc_zero(conn, rlm_sql_firebird_conn_t));

	/*
	 *	Firebird uses a client assigned structure to write info about output data.
	 *	Based on standard authorize queries, we pre-allocate a structure
	 *	for 5 columns in SELECT queries.
	 */
	MEM(c->sqlda_out = (XSQLDA *)_talloc_array(conn, 1, XSQLDA_LENGTH(5), "XSQLDA"));
	c->sqlda_out->sqln = 5;
	c->sqlda_out->version =  SQLDA_VERSION1;
	c->sql_dialect = 3;

	/*
	 *	Set tpb to read_committed/wait/no_rec_version
	 */
	c->tpb = tpb;
	c->tpb_len = NUM_ELEMENTS(tpb);

	if (fb_connect(c, &sql->config)) {
		ERROR("Connection failed: %s", c->error);
		return CONNECTION_STATE_FAILED;
	}

	*h = c;
	return CONNECTION_STATE_CONNECTED;
}

static void _sql_connection_close(UNUSED fr_event_list_t *el, void *h, UNUSED void *uctx)
{
	rlm_sql_firebird_conn_t	*c = talloc_get_type_abort(h, rlm_sql_firebird_conn_t);

	DEBUG2("Socket destructor called, closing socket");

	fb_commit(c);
	if (c->dbh) {
		fb_free_statement(c);
		isc_detach_database(c->status, &(c->dbh));

		if (fb_error(c)) WARN("Got error when closing socket: %s", c->error);
	}

	talloc_free_children(c);
}

SQL_TRUNK_CONNECTION_ALLOC

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static void sql_trunk_request_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn,
				  connection_t *conn, UNUSED void *uctx)
{
	rlm_sql_firebird_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_firebird_conn_t);
	trunk_request_t		*treq;
	request_t		*request;
	fr_sql_query_t		*query_ctx;
	bool			deadlock = false;

	if (trunk_connection_pop_request(&treq, tconn) != 0) return;
	if (!treq) return;

	query_ctx = talloc_get_type_abort(treq->preq, fr_sql_query_t);
	request = query_ctx->request;
	query_ctx->tconn = tconn;

	ROPTIONAL(RDEBUG2, DEBUG2, "Executing query: %s", query_ctx->query_str);

	try_again:
	/*
	 *	Try again query when deadlock, because in any case it
	 *	will be retried.
	 */
	if (fb_sql_query(sql_conn, query_ctx->query_str)) {
		/* but may be lost for short sessions */
		if ((sql_conn->sql_code == DEADLOCK_SQL_CODE) && !deadlock) {
			ROPTIONAL(RWARN, WARN, "SQL deadlock. Retry query %s", query_ctx->query_str);

			/*
			 *	@todo For non READ_COMMITED transactions put
			 *	rollback here
			 *	fb_rollback(conn);
			 */
			deadlock = true;
			goto try_again;
		}

		if (sql_conn->sql_code == DUPLICATE_KEY_SQL_CODE) {
			query_ctx->rcode = RLM_SQL_ALT_QUERY;
			goto finish;
		}

		ROPTIONAL(RERROR, ERROR, "conn_id rlm_sql_firebird,sql_query error: sql_code=%li, error='%s', query=%s",
		      (long int) sql_conn->sql_code, sql_conn->error, query_ctx->query_str);

		query_ctx->status = SQL_QUERY_FAILED;
		trunk_request_signal_fail(treq);

		if (sql_conn->sql_code == DOWN_SQL_CODE) {
		reconnect:
			query_ctx->rcode = RLM_SQL_RECONNECT;
			connection_signal_reconnect(conn, CONNECTION_FAILED);
			return;
		}

		/* Free problem query */
		if (fb_rollback(sql_conn)) {
			//assume the network is down if rollback had failed
			ROPTIONAL(RERROR, ERROR, "Fail to rollback transaction after previous error: %s", sql_conn->error);

			goto reconnect;
		}

		query_ctx->rcode = RLM_SQL_ERROR;
		return;
	}

	query_ctx->rcode = RLM_SQL_OK;
finish:
	query_ctx->status = SQL_QUERY_RETURNED;
	trunk_request_signal_reapable(treq);
	if (request) unlang_interpret_mark_runnable(request);
}

SQL_QUERY_RESUME

static void sql_request_complete(UNUSED request_t *request, void *preq, UNUSED void *rctx, UNUSED void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(preq, fr_sql_query_t);
	rlm_sql_firebird_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_firebird_conn_t);

	fb_commit(conn);
}

static void sql_request_fail(UNUSED request_t *request, void *preq, UNUSED void *rctx,
			     UNUSED trunk_request_state_t state, UNUSED void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(preq, fr_sql_query_t);

	query_ctx->treq = NULL;
	if (query_ctx->rcode == RLM_SQL_OK) query_ctx->rcode = RLM_SQL_ERROR;
}

/** Returns name of fields.
 *
 */
static sql_rcode_t sql_fields(char const **out[], fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_firebird_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_firebird_conn_t);

	int		fields, i;
	char const	**names;

	fields = conn->sqlda_out->sqld;
	if (fields <= 0) return RLM_SQL_ERROR;

	MEM(names = talloc_array(query_ctx, char const *, fields));

	for (i = 0; i < fields; i++) names[i] = conn->sqlda_out->sqlvar[i].sqlname;
	*out = names;

	return RLM_SQL_OK;
}

/** Returns an individual row.
 *
 */
static unlang_action_t sql_fetch_row(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_firebird_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_firebird_conn_t);
	int res;

	query_ctx->row = NULL;

	if (conn->statement_type != isc_info_sql_stmt_exec_procedure) {
		res = fb_fetch(conn);
		if (res == 100) {
			query_ctx->rcode = RLM_SQL_NO_MORE_ROWS;
			RETURN_MODULE_OK;
		}

		if (res) {
			ERROR("Fetch problem: %s", conn->error);

			query_ctx->rcode = RLM_SQL_ERROR;
			RETURN_MODULE_FAIL;
		}
	} else {
		conn->statement_type = 0;
	}

	TALLOC_FREE(conn->row);
	query_ctx->rcode = fb_store_row(conn);
	if (query_ctx->rcode == RLM_SQL_OK) query_ctx->row = conn->row;

	RETURN_MODULE_OK;
}

/** End the query, such as freeing memory or result.
 *
 */
static sql_rcode_t sql_finish_query(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_firebird_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_firebird_conn_t);

	fb_free_statement(conn);
	talloc_free_children(conn->sqlda_out);
	TALLOC_FREE(conn->row);
	query_ctx->status = SQL_QUERY_PREPARED;

	return 0;
}

/** Frees memory allocated for a result set.
 *
 */
static sql_rcode_t sql_free_result(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_firebird_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_firebird_conn_t);

	TALLOC_FREE(conn->row);
	return 0;
}

/** Retrieves any errors associated with the query context
 *
 * @note Caller will free any memory allocated in ctx.
 *
 * @param ctx to allocate temporary error buffers in.
 * @param out Array of sql_log_entrys to fill.
 * @param outlen Length of out array.
 * @param query_ctx Query context to retrieve error for.
 * @return number of errors written to the #sql_log_entry_t array.
 */
static size_t sql_error(UNUSED TALLOC_CTX *ctx, sql_log_entry_t out[], NDEBUG_UNUSED size_t outlen,
			fr_sql_query_t *query_ctx)
{
	rlm_sql_firebird_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_firebird_conn_t);

	fr_assert(conn);
	fr_assert(outlen > 0);

	if (!conn->error) return 0;

	out[0].type = L_ERR;
	out[0].msg = conn->error;

	return 1;
}

/** Return the number of rows affected by the query (update, or insert)
 *
 */
static int sql_affected_rows(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_firebird_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_firebird_conn_t);

	return fb_affected_rows(conn);
}

/* Exported to rlm_sql */
extern rlm_sql_driver_t rlm_sql_firebird;
rlm_sql_driver_t rlm_sql_firebird = {
	.common = {
		.name				= "sql_firebird",
		.magic				= MODULE_MAGIC_INIT
	},
	.flags				= RLM_SQL_RCODE_FLAGS_ALT_QUERY,
	.sql_query_resume		= sql_query_resume,
	.sql_select_query_resume	= sql_query_resume,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fetch_row			= sql_fetch_row,
	.sql_fields			= sql_fields,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_query,
	.trunk_io_funcs = {
		.connection_alloc 	= sql_trunk_connection_alloc,
		.request_mux		= sql_trunk_request_mux,
		.request_complete	= sql_request_complete,
		.request_fail		= sql_request_fail
	}
};
