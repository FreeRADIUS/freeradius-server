/*
 * sql_iodbc.c	iODBC support for FreeRadius
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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Jeff Carneal <jeff@apex.net>
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/stat.h>

#include <isql.h>
#include <isqlext.h>
#include <sqltypes.h>

#include "rlm_sql.h"

#define IODBC_MAX_ERROR_LEN 256

typedef struct rlm_sql_iodbc_conn {
	HENV    env_handle;
	HDBC    dbc_handle;
	HSTMT   stmt_handle;
	int	id;

	rlm_sql_row_t row;

	struct sql_socket *next;

	void	*conn;
} rlm_sql_iodbc_conn_t;

static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config);
static int sql_num_fields(rlm_sql_handle_t *handle, rlm_sql_config_t *config);

static int _sql_socket_destructor(rlm_sql_iodbc_conn_t *conn)
{
	DEBUG2("rlm_sql_iodbc: Socket destructor called, closing socket");

	if (conn->stmt_handle) {
		SQLFreeStmt(conn->stmt_handle, SQL_DROP);
	}

	if (conn->dbc_handle) {
		SQLDisconnect(conn->dbc_handle);
		SQLFreeConnect(conn->dbc_handle);
	}

	if (conn->env_handle) {
		SQLFreeEnv(conn->env_handle);
	}

	return 0;
}

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{

	rlm_sql_iodbc_conn_t *conn;
	SQLRETURN rcode;
	sql_log_entry_t entry;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_iodbc_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	rcode = SQLAllocEnv(&conn->env_handle);
	if (!SQL_SUCCEEDED(rcode)) {
		ERROR("rlm_sql_iodbc: SQLAllocEnv failed");
		if (sql_error(NULL, &entry, 1, handle, config) > 0) ERROR("rlm_sql_iodbc: %s", entry.msg);

		return -1;
	}

	rcode = SQLAllocConnect(conn->env_handle,
				&conn->dbc_handle);
	if (!SQL_SUCCEEDED(rcode)) {
		ERROR("rlm_sql_iodbc: SQLAllocConnect failed");
		if (sql_error(NULL, &entry, 1, handle, config) > 0) ERROR("rlm_sql_iodbc: %s", entry.msg);

		return -1;
	}

	/*
	 *	The iodbc API doesn't qualify arguments as const even when they should be.
	 */
	{
		SQLCHAR *server, *login, *password;

		memcpy(&server, &config->sql_server, sizeof(server));
		memcpy(&login, &config->sql_login, sizeof(login));
		memcpy(&password, &config->sql_password, sizeof(password));

		rcode = SQLConnect(conn->dbc_handle, server, SQL_NTS, login, SQL_NTS, password, SQL_NTS);
	}
	if (!SQL_SUCCEEDED(rcode)) {
		ERROR("rlm_sql_iodbc: SQLConnectfailed");
		if (sql_error(NULL, &entry, 1, handle, config) > 0) ERROR("rlm_sql_iodbc: %s", entry.msg);

		return -1;
	}

	return 0;
}

static sql_rcode_t sql_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config, char const *query)
{
	rlm_sql_iodbc_conn_t *conn = handle->conn;
	SQLRETURN rcode;

	rcode = SQLAllocStmt(conn->dbc_handle, &conn->stmt_handle);
	if (!SQL_SUCCEEDED(rcode)) return -1;

	if (!conn->dbc_handle) {
		ERROR("rlm_sql_iodbc: Socket not connected");
		return -1;
	}

	{
		SQLCHAR *statement;

		memcpy(&statement, &query, sizeof(statement));
		rcode = SQLExecDirect(conn->stmt_handle, statement, SQL_NTS);
	}

	if (!SQL_SUCCEEDED(rcode)) return -1;

	return 0;
}

static sql_rcode_t sql_select_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char const *query)
{
	int numfields = 0;
	int i = 0;
	char **row = NULL;
	long len = 0;
	rlm_sql_iodbc_conn_t *conn = handle->conn;

	if(sql_query(handle, config, query) < 0) {
		return -1;
	}

	numfields = sql_num_fields(handle, config);

	row = (char **) rad_malloc(sizeof(char *) * (numfields+1));
	memset(row, 0, (sizeof(char *) * (numfields)));
	row[numfields] = NULL;

	for(i=1; i<=numfields; i++) {
		SQLColAttributes(conn->stmt_handle, ((SQLUSMALLINT) i), SQL_COLUMN_LENGTH, NULL, 0, NULL, &len);
		len++;

		/*
		 * Allocate space for each column
		 */
		row[i - 1] = rad_malloc((size_t) len);

		/*
		 * This makes me feel dirty, but, according to Microsoft, it works.
		 * Any ODBC datatype can be converted to a 'char *' according to
		 * the following:
		 *
		 * http://msdn.microsoft.com/library/psdk/dasdk/odap4o4z.htm
		 */
		SQLBindCol(conn->stmt_handle, i, SQL_C_CHAR, (SQLCHAR *)row[i-1], len, 0);
	}

	conn->row = row;

	return 0;
}

static sql_rcode_t sql_store_result(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	return 0;
}

static int sql_num_fields(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{

	SQLSMALLINT count=0;
	rlm_sql_iodbc_conn_t *conn = handle->conn;

	SQLNumResultCols(conn->stmt_handle, &count);

	return (int)count;
}

static int sql_num_rows(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	/*
	 * I presume this function is used to determine the number of
	 * rows in a result set *before* fetching them.  I don't think
	 * this is possible in ODBC 2.x, but I'd be happy to be proven
	 * wrong.  If you know how to do this, email me at jeff@apex.net
	 */
	return 0;
}

static sql_rcode_t sql_fetch_row(rlm_sql_row_t *out, rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	SQLRETURN rc;
	rlm_sql_iodbc_conn_t *conn = handle->conn;

	*out = handle->row = NULL;

	if ((rc = SQLFetch(conn->stmt_handle)) == SQL_NO_DATA_FOUND) return 0;
	/* XXX Check rc for database down, if so, return RLM_SQL_RECONNECT */

	*out = handle->row = conn->row;
	return 0;
}

static sql_rcode_t sql_free_result(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	int i = 0;
	rlm_sql_iodbc_conn_t *conn = handle->conn;

	for (i = 0; i < sql_num_fields(handle, config); i++) free(conn->row[i]);
	free(conn->row);
	conn->row = NULL;

	SQLFreeStmt(conn->stmt_handle, SQL_DROP);

	return 0;
}

/** Retrieves any errors associated with the connection handle
 *
 * @note Caller will free any memory allocated in ctx.
 *
 * @param ctx to allocate temporary error buffers in.
 * @param out Array of sql_log_entrys to fill.
 * @param outlen Length of out array.
 * @param handle rlm_sql connection handle.
 * @param config rlm_sql config.
 * @return number of errors written to the #sql_log_entry_t array.
 */
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_iodbc_conn_t	*conn = handle->conn;
	SQLINTEGER		errornum = 0;
	SQLSMALLINT		length = 0;
	SQLCHAR			state[256] = "";
	SQLCHAR			errbuff[IODBC_MAX_ERROR_LEN];

	rad_assert(outlen > 0);

	errbuff[0] = '\0';
	SQLError(conn->env_handle, conn->dbc_handle, conn->stmt_handle,
		 state, &errornum, errbuff, IODBC_MAX_ERROR_LEN, &length);
	if (errbuff[0] == '\0') return 0;

	out[0].type = L_ERR;
	out[0].msg = talloc_asprintf(ctx, "%s: %s", state, errbuff);

	return 1;
}

static sql_rcode_t sql_finish_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	return sql_free_result(handle, config);
}

static sql_rcode_t sql_finish_select_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	return sql_free_result(handle, config);
}

static int sql_affected_rows(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	long count;
	rlm_sql_iodbc_conn_t *conn = handle->conn;

	SQLRowCount(conn->stmt_handle, &count);
	return (int)count;
}

/* Exported to rlm_sql */
extern rlm_sql_module_t rlm_sql_iodbc;
rlm_sql_module_t rlm_sql_iodbc = {
	.name				= "rlm_sql_iodbc",
	.sql_socket_init		= sql_socket_init,
	.sql_query			= sql_query,
	.sql_select_query		= sql_select_query,
	.sql_store_result		= sql_store_result,
	.sql_num_fields			= sql_num_fields,
	.sql_num_rows			= sql_num_rows,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fetch_row			= sql_fetch_row,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_select_query
};
