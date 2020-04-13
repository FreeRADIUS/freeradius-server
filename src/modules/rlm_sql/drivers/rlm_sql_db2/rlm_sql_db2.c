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

#define LOG_PREFIX "rlm_sql_db2 - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <sys/stat.h>

#include <sqlcli.h>
#include "rlm_sql.h"

typedef struct {
	SQLHANDLE dbc_handle;
	SQLHANDLE env_handle;
	SQLHANDLE stmt;
} rlm_sql_db2_conn_t;

static int _sql_socket_destructor(rlm_sql_db2_conn_t *conn)
{
	DEBUG2("Socket destructor called, closing socket");

	if (conn->dbc_handle) {
		SQLDisconnect(conn->dbc_handle);
		SQLFreeHandle(SQL_HANDLE_DBC, conn->dbc_handle);
	}

	if (conn->env_handle) SQLFreeHandle(SQL_HANDLE_ENV, conn->env_handle);

	return RLM_SQL_OK;
}

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config,
				   UNUSED fr_time_delta_t timeout)
{
	SQLRETURN row;
#if 0
	uint32_t timeout_ms = FR_TIMEVAL_TO_MS(timeout);
#endif
	rlm_sql_db2_conn_t *conn;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_db2_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	/* Allocate handles */
	SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &(conn->env_handle));
	SQLAllocHandle(SQL_HANDLE_DBC, conn->env_handle, &(conn->dbc_handle));

	/* Set the connection timeout */
#if 0
	/* Not suported ? */
	SQLSetConnectAttr(conn->dbc_handle, SQL_ATTR_LOGIN_TIMEOUT, &timeout_ms, SQL_IS_UINTEGER);
#endif
	/*
	 *	The db2 API doesn't qualify arguments as const even when they should be.
	 */
	{
		SQLCHAR *server, *login, *password;

		memcpy(&server, &config->sql_server, sizeof(server));
		memcpy(&login, &config->sql_login, sizeof(login));
		memcpy(&password, &config->sql_password, sizeof(password));

		/*
		 *	We probably want to use SQLDriverConnect, which connects
		 *	to a remote server.
		 *
		 *	http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.apdv.cli.doc/doc/r0000584.html
		 *	http://stackoverflow.com/questions/27167070/connection-string-to-a-remote-db2-db-in-another-server
		 *
		 *	And probably synthesis the retarded connection string ourselves,
		 *	probably via config file expansions:
		 *
		 *	Driver={IBM DB2 ODBC Driver};Database=testDb;Hostname=remoteHostName.com;UID=username;PWD=mypasswd;PORT=50000
		 */
		row = SQLConnect(conn->dbc_handle,
				    server, SQL_NTS,
				    login, SQL_NTS,
				    password, SQL_NTS);
	}

	if (row != SQL_SUCCESS) {
		ERROR("could not connect to DB2 server %s", config->sql_server);

		return RLM_SQL_ERROR;
	}

	return RLM_SQL_OK;
}

static sql_rcode_t sql_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config, char const *query)
{
	SQLRETURN row;
	rlm_sql_db2_conn_t *conn;

	conn = handle->conn;

	/* allocate handle for statement */
	SQLAllocHandle(SQL_HANDLE_STMT, conn->dbc_handle, &(conn->stmt));

	/* execute query */
	{
		SQLCHAR *db2_query;
		memcpy(&db2_query, &query, sizeof(query));

		row = SQLExecDirect(conn->stmt, db2_query, SQL_NTS);
		if(row != SQL_SUCCESS) {
			/* XXX Check if row means we should return RLM_SQL_RECONNECT */
			ERROR("Could not execute statement \"%s\"", query);
			return RLM_SQL_ERROR;
		}
	}

	return RLM_SQL_OK;
}

static sql_rcode_t sql_select_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char const *query)
{
	return sql_query(handle, config, query);
}

static int sql_num_fields(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	SQLSMALLINT c;
	rlm_sql_db2_conn_t *conn;

	conn = handle->conn;
	SQLNumResultCols(conn->stmt, &c);
	return c;
}

static sql_rcode_t sql_fields(char const **out[], rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_db2_conn_t *conn = handle->conn;

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
	int			c, i;
	SQLINTEGER		len, slen;
	rlm_sql_row_t		row;
	rlm_sql_db2_conn_t	*conn;

	*out = NULL;

	TALLOC_FREE(handle->row);

	conn = handle->conn;
	c = sql_num_fields(handle, config);

	/* advance cursor */
	if (SQLFetch(conn->stmt) == SQL_NO_DATA_FOUND) return RLM_SQL_NO_MORE_ROWS;

	MEM(row = (rlm_sql_row_t)talloc_zero_array(handle, char *, c + 1));
	for (i = 0; i < c; i++) {
		/* get column length */
		SQLColAttribute(conn->stmt, i + 1, SQL_DESC_DISPLAY_SIZE, NULL, 0, NULL, &len);

		MEM(row[i] = talloc_array(row, char, len + 1));

		/* get the actual column */
		SQLGetData(conn->stmt, i + 1, SQL_C_CHAR, row[i], len + 1, &slen);
		if (slen == SQL_NULL_DATA) row[i][0] = '\0';
	}

	*out = handle->row = row;

	return RLM_SQL_OK;
}

static sql_rcode_t sql_free_result(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_db2_conn_t *conn;

	conn = handle->conn;
	TALLOC_FREE(handle->row);
	SQLFreeHandle(SQL_HANDLE_STMT, conn->stmt);

	return RLM_SQL_OK;
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
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], NDEBUG_UNUSED size_t outlen,
			rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	char			state[6];
	char			errbuff[1024];
	SQLINTEGER		err;
	SQLSMALLINT		rl;
	rlm_sql_db2_conn_t	*conn = handle->conn;

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

static sql_rcode_t sql_finish_query(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	return RLM_SQL_OK;
}

static sql_rcode_t sql_finish_select_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	return sql_finish_query(handle, config);
}

static int sql_affected_rows(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	SQLINTEGER c;
	rlm_sql_db2_conn_t *conn = handle->conn;

	SQLRowCount(conn->stmt, &c);

	return c;
}

/* Exported to rlm_sql */
extern rlm_sql_driver_t rlm_sql_db2;
rlm_sql_driver_t rlm_sql_db2 = {
	.name				= "rlm_sql_db2",
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
