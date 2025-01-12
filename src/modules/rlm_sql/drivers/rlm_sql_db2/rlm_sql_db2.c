/*
 * sql_db2.c		IBM DB2 rlm_sql driver
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
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Mike Machado (mike@innercite.com)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 * @copyright 2001 Joerg Wendland (wendland@scan-plus.de)
 */

/*
 * Modification of rlm_sql_db2 to handle IBM DB2 UDB V7
 * by Joerg Wendland <wendland@scan-plus.de>
 */
RCSID("$Id$")

#define LOG_PREFIX "sql - db2"

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <sys/stat.h>

#include <sqlcli1.h>
#include <sqlstate.h>
#include "rlm_sql.h"
#include "rlm_sql_trunk.h"

typedef struct {
	SQLHANDLE dbc_handle;
	SQLHANDLE env_handle;
	SQLHANDLE stmt;
} rlm_sql_db2_conn_t;

static void _sql_connection_close(UNUSED fr_event_list_t *el, void *h, UNUSED void *uctx)
{
	rlm_sql_db2_conn_t	*conn = talloc_get_type_abort(h, rlm_sql_db2_conn_t);

	DEBUG2("Socket destructor called, closing socket");

	if (conn->dbc_handle) {
		SQLDisconnect(conn->dbc_handle);
		SQLFreeHandle(SQL_HANDLE_DBC, conn->dbc_handle);
	}

	if (conn->env_handle) SQLFreeHandle(SQL_HANDLE_ENV, conn->env_handle);

	talloc_free(h);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static connection_state_t _sql_connection_init(void **h, connection_t *conn, void *uctx)
{
	rlm_sql_db2_conn_t	*c;
	rlm_sql_t const		*sql = talloc_get_type_abort_const(uctx, rlm_sql_t);
	rlm_sql_config_t const	*config = &sql->config;
	uint32_t		timeout_ms = fr_time_delta_to_msec(config->trunk_conf.conn_conf->connection_timeout);
	SQLRETURN		ret;

	MEM(c = talloc_zero(conn, rlm_sql_db2_conn_t));

	/* Allocate handles */
	SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &(c->env_handle));
	SQLAllocHandle(SQL_HANDLE_DBC, c->env_handle, &(c->dbc_handle));

	/* Set the connection timeout */
	SQLSetConnectAttr(c->dbc_handle, SQL_ATTR_LOGIN_TIMEOUT, &timeout_ms, SQL_IS_UINTEGER);

	/*
	 *	We probably want to use SQLDriverConnect, which connects
	 *	to a remote server.
	 *
	 *	http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.apdv.cli.doc/doc/r0000584.html
	 *	http://stackoverflow.com/questions/27167070/connection-string-to-a-remote-db2-db-in-another-server
	 *
	 *	And probably synthesise the retarded connection string ourselves,
	 *	probably via config file expansions:
	 *
	 *	Driver={IBM DB2 ODBC Driver};Database=testDb;Hostname=remoteHostName.com;UID=username;PWD=mypasswd;PORT=50000
	 */
	ret = SQLConnect(c->dbc_handle,
			 UNCONST(SQLCHAR *, config->sql_server), SQL_NTS,
			 UNCONST(SQLCHAR *, config->sql_login), SQL_NTS,
			 UNCONST(SQLCHAR *, config->sql_password), SQL_NTS);
	if (ret != SQL_SUCCESS) {
		ERROR("could not connect to DB2 server %s", config->sql_server);

		return CONNECTION_STATE_FAILED;
	}

	*h = c;
	return CONNECTION_STATE_CONNECTED;
}

SQL_TRUNK_CONNECTION_ALLOC

SQL_QUERY_RESUME

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static void sql_trunk_request_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn,
				  connection_t *conn, UNUSED void *uctx)
{
	rlm_sql_db2_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_db2_conn_t);
	trunk_request_t		*treq;
	request_t		*request;
	fr_sql_query_t		*query_ctx;
	SQLRETURN		ret;
	SQLCHAR			*db2_query;

	if (trunk_connection_pop_request(&treq, tconn) != 0) return;
	if (!treq) return;

	query_ctx = talloc_get_type_abort(treq->preq, fr_sql_query_t);
	request = query_ctx->request;
	query_ctx->tconn = tconn;

	ROPTIONAL(RDEBUG2, DEBUG2, "Executing query: %s", query_ctx->query_str);

	/* allocate handle for statement */
	SQLAllocHandle(SQL_HANDLE_STMT, sql_conn->dbc_handle, &(sql_conn->stmt));

	/* execute query */
	memcpy(&db2_query, &query_ctx->query_str, sizeof(query_ctx->query_str));

	ret = SQLExecDirect(sql_conn->stmt, db2_query, SQL_NTS);
	if (ret != SQL_SUCCESS) {
		SQLCHAR		state[6];
		SQLSMALLINT	len;

		SQLGetDiagField(SQL_HANDLE_STMT, sql_conn->dbc_handle, 1, SQL_DIAG_SQLSTATE, state, sizeof(state), &len);

		if (strncmp((char *)state, SQL_CONSTR_INDEX_UNIQUE, 5)) {
			query_ctx->rcode = RLM_SQL_ALT_QUERY;
			goto finish;
		}

		/* XXX Check if ret means we should return RLM_SQL_RECONNECT */
		ERROR("Could not execute statement \"%s\"", query_ctx->query_str);
		query_ctx->rcode = RLM_SQL_ERROR;
		trunk_request_signal_fail(treq);
		return;
	}

	query_ctx->rcode = RLM_SQL_OK;
finish:
	query_ctx->status = SQL_QUERY_RETURNED;
	trunk_request_signal_reapable(treq);
	if (request) unlang_interpret_mark_runnable(request);
}

static sql_rcode_t sql_fields(char const **out[], fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_db2_conn_t *conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_db2_conn_t);

	SQLSMALLINT	fields, len, i;

	char const	**names;
	char		field[128];

	SQLNumResultCols(conn->stmt, &fields);
	if (fields == 0) return RLM_SQL_ERROR;

	MEM(names = talloc_array(query_ctx, char const *, fields));

	for (i = 0; i < fields; i++) {
		char *p;

		switch (SQLColAttribute(conn->stmt, i, SQL_DESC_BASE_COLUMN_NAME,
					field, sizeof(field), &len, NULL)) {
		case SQL_INVALID_HANDLE:
		case SQL_ERROR:
			ERROR("Failed retrieving field name at index %i", i);
			talloc_free(names);
			return RLM_SQL_ERROR;

		default:
			break;
		}

		MEM(p = talloc_array(names, char, (size_t)len + 1));
		strlcpy(p, field, (size_t)len + 1);
		names[i] = p;
	}
	*out = names;

	return RLM_SQL_OK;
}

static unlang_action_t sql_fetch_row(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	int			i;
	SQLINTEGER		len, slen;
	SQLSMALLINT		c;
	rlm_sql_row_t		row;
	rlm_sql_db2_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_db2_conn_t);

	TALLOC_FREE(query_ctx->row);

	SQLNumResultCols(conn->stmt, &c);

	/* advance cursor */
	if (SQLFetch(conn->stmt) == SQL_NO_DATA_FOUND) {
		query_ctx->rcode = RLM_SQL_NO_MORE_ROWS;
		RETURN_MODULE_OK;
	}

	MEM(row = (rlm_sql_row_t)talloc_zero_array(query_ctx, char *, c + 1));
	for (i = 0; i < c; i++) {
		/* get column length */
		SQLColAttribute(conn->stmt, i + 1, SQL_DESC_DISPLAY_SIZE, NULL, 0, NULL, &len);

		MEM(row[i] = talloc_array(row, char, len + 1));

		/* get the actual column */
		SQLGetData(conn->stmt, i + 1, SQL_C_CHAR, row[i], len + 1, &slen);
		if (slen == SQL_NULL_DATA) row[i][0] = '\0';
	}

	query_ctx->row = row;

	query_ctx->rcode = RLM_SQL_OK;
	RETURN_MODULE_OK;
}

static sql_rcode_t sql_free_result(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_db2_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_db2_conn_t);

	TALLOC_FREE(query_ctx->row);
	SQLFreeHandle(SQL_HANDLE_STMT, conn->stmt);

	return RLM_SQL_OK;
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
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], NDEBUG_UNUSED size_t outlen,
			fr_sql_query_t *query_ctx)
{
	char			state[6];
	char			errbuff[1024];
	SQLINTEGER		err;
	SQLSMALLINT		rl;
	rlm_sql_db2_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_db2_conn_t);

	fr_assert(conn);
	fr_assert(outlen > 0);

	errbuff[0] = '\0';
	SQLGetDiagRec(SQL_HANDLE_STMT, conn->stmt, 1, (SQLCHAR *) state, &err,
		      (SQLCHAR *) errbuff, sizeof(errbuff), &rl);
	if (errbuff[0] == '\0') return 0;

	out[0].type = L_ERR;
	out[0].msg = talloc_typed_asprintf(ctx, "%s: %s", state, errbuff);

	return 1;
}

static sql_rcode_t sql_finish_query(UNUSED fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	return RLM_SQL_OK;
}

static int sql_affected_rows(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	SQLINTEGER c;
	rlm_sql_db2_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_db2_conn_t);

	SQLRowCount(conn->stmt, &c);

	return c;
}

static void sql_request_fail(request_t *request, void *preq, UNUSED void *rctx,
			     UNUSED trunk_request_state_t state, UNUSED void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(preq, fr_sql_query_t);

	query_ctx->treq = NULL;
	if (query_ctx->rcode == RLM_SQL_OK) query_ctx->rcode = RLM_SQL_ERROR;
	if (request) unlang_interpret_mark_runnable(request);
}

/* Exported to rlm_sql */
extern rlm_sql_driver_t rlm_sql_db2;
rlm_sql_driver_t rlm_sql_db2 = {
	.common = {
		.magic				= MODULE_MAGIC_INIT,
		.name				= "sql_db2",
	},
	.flags				= RLM_SQL_RCODE_FLAGS_ALT_QUERY,
	.sql_query_resume		= sql_query_resume,
	.sql_select_query_resume	= sql_query_resume,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fields			= sql_fields,
	.sql_fetch_row			= sql_fetch_row,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_query,
	.trunk_io_funcs = {
		.connection_alloc	= sql_trunk_connection_alloc,
		.request_mux		= sql_trunk_request_mux,
		.request_fail		= sql_request_fail,
	}
};
