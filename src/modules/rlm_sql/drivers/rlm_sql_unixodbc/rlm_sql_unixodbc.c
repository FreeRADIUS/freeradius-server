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

#define LOG_PREFIX "rlm_sql_unixodbc - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>

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
static int sql_check_error(long err_handle, rlm_sql_handle_t *handle, rlm_sql_config_t *config);
static sql_rcode_t sql_free_result(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
static int sql_affected_rows(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
static int sql_num_fields(rlm_sql_handle_t *handle, rlm_sql_config_t *config);

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

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config,
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
	{
		SQLCHAR *odbc_server, *odbc_login, *odbc_password;

		memcpy(&odbc_server, &config->sql_server, sizeof(odbc_server));
		memcpy(&odbc_login, &config->sql_login, sizeof(odbc_login));
		memcpy(&odbc_password, &config->sql_password, sizeof(odbc_password));
		err_handle = SQLConnect(conn->dbc,
					odbc_server, strlen(config->sql_server),
					odbc_login, strlen(config->sql_login),
					odbc_password, strlen(config->sql_password));
	}

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

static sql_rcode_t sql_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char const *query)
{
	rlm_sql_unixodbc_conn_t *conn = handle->conn;
	long err_handle;
	int state;

	/* Executing query */
	{
		SQLCHAR *odbc_query;

		memcpy(&odbc_query, &query, sizeof(odbc_query));
		err_handle = SQLExecDirect(conn->stmt, odbc_query, strlen(query));
	}
	if ((state = sql_check_error(err_handle, handle, config))) {
		if(state == RLM_SQL_RECONNECT) {
			DEBUG("rlm_sql will attempt to reconnect");
		}
		return state;
	}
	return 0;
}

static sql_rcode_t sql_select_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char const *query)
{
	rlm_sql_unixodbc_conn_t *conn = handle->conn;
	SQLINTEGER i;
	SQLLEN len;
	int colcount;
	int state;

	/* Only state = 0 means success */
	if ((state = sql_query(handle, config, query))) {
		return state;
	}

	colcount = sql_num_fields(handle, config);
	if (colcount < 0) {
		return RLM_SQL_ERROR;
	}

	/* Reserving memory for result */
	conn->row = talloc_zero_array(conn, char *, colcount + 1); /* Space for pointers */

	for (i = 1; i <= colcount; i++) {
		len = 0;
		SQLColAttributes(conn->stmt, ((SQLUSMALLINT) i), SQL_COLUMN_LENGTH, NULL, 0, NULL, &len);
		conn->row[i - 1] = talloc_array(conn->row, char, ++len);
		SQLBindCol(conn->stmt, i, SQL_C_CHAR, (SQLCHAR *)conn->row[i - 1], len, NULL);
	}

	return RLM_SQL_OK;
}

static int sql_num_fields(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_unixodbc_conn_t *conn = handle->conn;
	long err_handle;
	SQLSMALLINT num_fields = 0;

	err_handle = SQLNumResultCols(conn->stmt,&num_fields);
	if (sql_check_error(err_handle, handle, config)) return -1;

	return num_fields;
}

static sql_rcode_t sql_fields(char const **out[], rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
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

static sql_rcode_t sql_fetch_row(rlm_sql_row_t *out, rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_unixodbc_conn_t *conn = handle->conn;
	long err_handle;
	int state;

	*out = NULL;

	handle->row = NULL;

	err_handle = SQLFetch(conn->stmt);
	if (err_handle == SQL_NO_DATA_FOUND) return RLM_SQL_NO_MORE_ROWS;

	if ((state = sql_check_error(err_handle, handle, config))) return state;

	*out = handle->row = conn->row;

	return RLM_SQL_OK;
}

static sql_rcode_t sql_finish_select_query(rlm_sql_handle_t * handle, rlm_sql_config_t *config)
{
	rlm_sql_unixodbc_conn_t *conn = handle->conn;

	sql_free_result(handle, config);

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

static sql_rcode_t sql_finish_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_unixodbc_conn_t *conn = handle->conn;

	SQLFreeStmt(conn->stmt, SQL_CLOSE);

	return 0;
}

static sql_rcode_t sql_free_result(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_unixodbc_conn_t *conn = handle->conn;

	TALLOC_FREE(conn->row);

	return 0;
}

/** Retrieves any errors associated with the connection handle
 *
 * @note Caller will free any memory allocated in ctx.
 *
 * @param ctx to allocate temporary error buffers in.
 * @param out Array of #sql_log_entry_t to fill.
 * @param outlen Length of out array.
 * @param handle rlm_sql connection handle.
 * @param config rlm_sql config.
 * @return number of errors written to the #sql_log_entry_t array.
 */
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], NDEBUG_UNUSED size_t outlen,
			rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_unixodbc_conn_t		*conn = handle->conn;
	SQLCHAR				state[256];
	SQLCHAR				errbuff[256];
	SQLINTEGER			errnum = 0;
	SQLSMALLINT			length = 255;

	rad_assert(outlen > 0);

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
static sql_rcode_t sql_check_error(long error_handle, rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
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
			/* FALL-THROUGH */
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
static int sql_affected_rows(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_unixodbc_conn_t *conn = handle->conn;
	long error_handle;
	SQLLEN affected_rows;

	error_handle = SQLRowCount(conn->stmt, &affected_rows);
	if (sql_check_error(error_handle, handle, config)) return -1;

	return affected_rows;
}


/* Exported to rlm_sql */
extern rlm_sql_driver_t rlm_sql_unixodbc;
rlm_sql_driver_t rlm_sql_unixodbc = {
	.name				= "rlm_sql_unixodbc",
	.magic				= RLM_MODULE_INIT,
	.sql_socket_init		= sql_socket_init,
	.sql_query			= sql_query,
	.sql_select_query		= sql_select_query,
	.sql_num_fields			= sql_num_fields,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fields			= sql_fields,
	.sql_fetch_row			= sql_fetch_row,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_select_query
};
