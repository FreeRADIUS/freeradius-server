/*
 * sql_unixodbc.c	unixODBC rlm_sql driver
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
 * @copyright 2000 Dmitri Ageev (d_ageev@ortcc.ru)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API

#define LOG_PREFIX "sql - unixodbc"

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <sqltypes.h>
#include "rlm_sql.h"

typedef struct {
	SQLHENV env;
	SQLHDBC dbc;
	SQLHSTMT stmt;
	rlm_sql_row_t row;
	void *conn;
} rlm_sql_unixodbc_conn_t;

USES_APPLE_DEPRECATED_API
#include <sql.h>
#include <sqlext.h>

/* Forward declarations */
static int sql_check_error(long err_handle, rlm_sql_handle_t *handle, rlm_sql_config_t const *config);
static sql_rcode_t sql_free_result(fr_sql_query_t *query_ctx, rlm_sql_config_t const *config);
static int sql_num_fields(rlm_sql_handle_t *handle, rlm_sql_config_t const *config);

static int _sql_socket_destructor(rlm_sql_unixodbc_conn_t *conn)
{
	DEBUG2("Socket destructor called, closing socket");

	if (conn->stmt) SQLFreeStmt(conn->stmt, SQL_DROP);

	if (conn->dbc) {
		SQLDisconnect(conn->dbc);
		SQLFreeConnect(conn->dbc);
	}

	if (conn->env) SQLFreeEnv(conn->env);

	return 0;
}

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t const *config,
				   fr_time_delta_t timeout)
{
	rlm_sql_unixodbc_conn_t *conn;
	long err_handle;
	uint32_t timeout_ms = fr_time_delta_to_msec(timeout);

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_unixodbc_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	/* 1. Allocate environment handle and register version */
	err_handle = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &conn->env);
	if (sql_check_error(err_handle, handle, config)) {
		ERROR("Can't allocate environment handle");
		return RLM_SQL_ERROR;
	}

	err_handle = SQLSetEnvAttr(conn->env, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0);
	if (sql_check_error(err_handle, handle, config)) {
		ERROR("Can't register ODBC version");
		return RLM_SQL_ERROR;
	}

	/* 2. Allocate connection handle */
	err_handle = SQLAllocHandle(SQL_HANDLE_DBC, conn->env, &conn->dbc);
	if (sql_check_error(err_handle, handle, config)) {
		ERROR("Can't allocate connection handle");
		return RLM_SQL_ERROR;
	}

	/* Set the connection timeout */
	SQLSetConnectAttr(conn->dbc, SQL_ATTR_LOGIN_TIMEOUT, &timeout_ms, SQL_IS_UINTEGER);

	/* 3. Connect to the datasource */
	err_handle = SQLConnect(conn->dbc,
				UNCONST(SQLCHAR *, config->sql_server), strlen(config->sql_server),
				UNCONST(SQLCHAR *, config->sql_login), strlen(config->sql_login),
				UNCONST(SQLCHAR *, config->sql_password), strlen(config->sql_password));

	if (sql_check_error(err_handle, handle, config)) {
		ERROR("Connection failed");
		return RLM_SQL_ERROR;
	}

	/* 4. Allocate the stmt */
	err_handle = SQLAllocHandle(SQL_HANDLE_STMT, conn->dbc, &conn->stmt);
	if (sql_check_error(err_handle, handle, config)) {
		ERROR("Can't allocate the stmt");
		return RLM_SQL_ERROR;
	}

    return RLM_SQL_OK;
}

static unlang_action_t sql_query(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_unixodbc_conn_t *conn = query_ctx->handle->conn;
	long err_handle;

	/* Executing query */
	err_handle = SQLExecDirect(conn->stmt, UNCONST(SQLCHAR *, query_ctx->query_str), strlen(query_ctx->query_str));
	if ((query_ctx->rcode = sql_check_error(err_handle, query_ctx->handle, &query_ctx->inst->config))) {
		if(query_ctx->rcode == RLM_SQL_RECONNECT) {
			DEBUG("rlm_sql will attempt to reconnect");
		}
		RETURN_MODULE_FAIL;
	}
	RETURN_MODULE_OK;
}

static unlang_action_t sql_select_query(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_unixodbc_conn_t *conn = query_ctx->handle->conn;
	SQLINTEGER i;
	SQLLEN len;
	int colcount;

	/* Only state = 0 means success */
	if ((sql_query(p_result, NULL, request, query_ctx) == UNLANG_ACTION_CALCULATE_RESULT) &&
	    (query_ctx->rcode != RLM_SQL_OK)) RETURN_MODULE_FAIL;

	colcount = sql_num_fields(query_ctx->handle, &query_ctx->inst->config);
	if (colcount < 0) {
		query_ctx->rcode = RLM_SQL_ERROR;
		RETURN_MODULE_FAIL;
	}

	/* Reserving memory for result */
	conn->row = talloc_zero_array(conn, char *, colcount + 1); /* Space for pointers */

	for (i = 1; i <= colcount; i++) {
		len = 0;
		SQLColAttributes(conn->stmt, ((SQLUSMALLINT) i), SQL_DESC_LENGTH, NULL, 0, NULL, &len);
		conn->row[i - 1] = talloc_array(conn->row, char, ++len);
		SQLBindCol(conn->stmt, i, SQL_C_CHAR, (SQLCHAR *)conn->row[i - 1], len, NULL);
	}

	RETURN_MODULE_OK;
}

static int sql_num_fields(rlm_sql_handle_t *handle, rlm_sql_config_t const *config)
{
	rlm_sql_unixodbc_conn_t *conn = handle->conn;
	long err_handle;
	SQLSMALLINT num_fields = 0;

	err_handle = SQLNumResultCols(conn->stmt,&num_fields);
	if (sql_check_error(err_handle, handle, config)) return -1;

	return num_fields;
}

static sql_rcode_t sql_fields(char const **out[], rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_unixodbc_conn_t *conn = handle->conn;

	SQLSMALLINT	fields, len, i;

	char const	**names;
	char		field[128];

	SQLNumResultCols(conn->stmt, &fields);
	if (fields == 0) return RLM_SQL_ERROR;

	MEM(names = talloc_array(handle, char const *, fields));

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
	rlm_sql_handle_t	*handle = query_ctx->handle;
	rlm_sql_unixodbc_conn_t *conn = handle->conn;
	long			err_handle;

	query_ctx->row = NULL;

	err_handle = SQLFetch(conn->stmt);
	if (err_handle == SQL_NO_DATA_FOUND) {
		query_ctx->rcode = RLM_SQL_NO_MORE_ROWS;
		RETURN_MODULE_OK;
	}

	query_ctx->rcode = sql_check_error(err_handle, handle, &query_ctx->inst->config);
	if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL;

	query_ctx->row = conn->row;

	query_ctx->rcode = RLM_SQL_OK;
	RETURN_MODULE_OK;
}

static sql_rcode_t sql_finish_select_query(fr_sql_query_t *query_ctx, rlm_sql_config_t const *config)
{
	rlm_sql_unixodbc_conn_t *conn = query_ctx->handle->conn;

	sql_free_result(query_ctx, config);

	/*
	 *	SQL_CLOSE - The cursor (if any) associated with the statement
	 *	handle (StatementHandle) is closed and all pending results are
	 *	discarded. The application can reopen the cursor by calling
	 *	SQLExecute() with the same or different values in the
	 *	application variables (if any) that are bound to StatementHandle.
	 *	If no cursor has been associated with the statement handle,
	 *	this option has no effect (no warning or error is generated).
	 *
	 *	So, this call does NOT free the statement at all, it merely
	 *	resets it for the next call. This is terrible terrible naming.
	 */
	SQLFreeStmt(conn->stmt, SQL_CLOSE);

	return 0;
}

static sql_rcode_t sql_finish_query(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_unixodbc_conn_t *conn = query_ctx->handle->conn;

	SQLFreeStmt(conn->stmt, SQL_CLOSE);

	return 0;
}

static sql_rcode_t sql_free_result(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_unixodbc_conn_t *conn = query_ctx->handle->conn;

	TALLOC_FREE(conn->row);

	return 0;
}

/** Retrieves any errors associated with the query context
 *
 * @note Caller will free any memory allocated in ctx.
 *
 * @param ctx to allocate temporary error buffers in.
 * @param out Array of #sql_log_entry_t to fill.
 * @param outlen Length of out array.
 * @param query_ctx Query context to retrieve error for.
 * @param config rlm_sql config.
 * @return number of errors written to the #sql_log_entry_t array.
 */
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], NDEBUG_UNUSED size_t outlen,
			fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_unixodbc_conn_t		*conn = query_ctx->handle->conn;
	SQLCHAR				state[256];
	SQLCHAR				errbuff[256];
	SQLINTEGER			errnum = 0;
	SQLSMALLINT			length = 255;

	fr_assert(outlen > 0);

	errbuff[0] = state[0] = '\0';
	SQLError(conn->env, conn->dbc, conn->stmt, state, &errnum,
		 errbuff, sizeof(errbuff), &length);
	if (errnum == 0) return 0;

	out[0].type = L_ERR;
	out[0].msg = talloc_typed_asprintf(ctx, "%s: %s", state, errbuff);

	return 1;
}

/** Checks the error code to determine if the connection needs to be re-esttablished
 *
 * @param error_handle Return code from a failed unixodbc call.
 * @param handle rlm_sql connection handle.
 * @param config rlm_sql config.
 * @return
 *	- #RLM_SQL_OK on success.
 *	- #RLM_SQL_RECONNECT if reconnect is needed.
 *	- #RLM_SQL_ERROR on error.
 */
static sql_rcode_t sql_check_error(long error_handle, rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	SQLCHAR state[256];
	SQLCHAR error[256];
	SQLINTEGER errornum = 0;
	SQLSMALLINT length = 255;
	int res = -1;

	rlm_sql_unixodbc_conn_t *conn = handle->conn;

	if (SQL_SUCCEEDED(error_handle)) return 0; /* on success, just return 0 */

	error[0] = state[0] = '\0';

	SQLError(conn->env, conn->dbc, conn->stmt, state, &errornum,
		 error, sizeof(error), &length);

	if (state[0] == '0') {
		switch (state[1]) {
		/* SQLSTATE 01 class contains info and warning messages */
		case '1':
			INFO("%s %s", state, error);
			FALL_THROUGH;
		case '0':		/* SQLSTATE 00 class means success */
			res = RLM_SQL_OK;
			break;

		/* SQLSTATE 08 class describes various connection errors */
		case '8':
			ERROR("SQL down %s %s", state, error);
			res = RLM_SQL_RECONNECT;
			break;

		/* any other SQLSTATE means error */
		default:
			ERROR("%s %s", state, error);
			res = RLM_SQL_ERROR;
			break;
		}
	} else {
		ERROR("%s %s", state, error);
	}

	return res;
}

/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: Return the number of rows affected by the query (update,
 *	       or insert)
 *
 *************************************************************************/
static int sql_affected_rows(fr_sql_query_t *query_ctx, rlm_sql_config_t const *config)
{
	rlm_sql_unixodbc_conn_t *conn = query_ctx->handle->conn;
	long error_handle;
	SQLLEN affected_rows;

	error_handle = SQLRowCount(conn->stmt, &affected_rows);
	if (sql_check_error(error_handle, query_ctx->handle, config)) return -1;

	return affected_rows;
}


/* Exported to rlm_sql */
extern rlm_sql_driver_t rlm_sql_unixodbc;
rlm_sql_driver_t rlm_sql_unixodbc = {
	.common = {
		.magic				= MODULE_MAGIC_INIT,
		.name				= "sql_unixodbc"
	},
	.sql_socket_init		= sql_socket_init,
	.sql_query			= sql_query,
	.sql_select_query		= sql_select_query,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fields			= sql_fields,
	.sql_fetch_row			= sql_fetch_row,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_select_query
};
