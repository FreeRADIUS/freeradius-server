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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Mike Machado <mike@innercite.com>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2001  Joerg Wendland <wendland@scan-plus.de>
 */

/*
 * Modification of rlm_sql_db2 to handle IBM DB2 UDB V7
 * by Joerg Wendland <wendland@scan-plus.de>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/stat.h>

#include <sql.h>
#include <sqlcli.h>
#include "rlm_sql.h"

typedef struct rlm_sql_conn {
	SQLHANDLE dbc_handle;
	SQLHANDLE env_handle;
	SQLHANDLE stmt;
} rlm_sql_db2_conn_t;

static int _sql_socket_destructor(rlm_sql_db2_conn_t *conn)
{
	DEBUG2("rlm_sql_db2: Socket destructor called, closing socket");

	if (conn->dbc_handle) {
		SQLDisconnect(conn->dbc_handle);
		SQLFreeHandle(SQL_HANDLE_DBC, conn->dbc_handle);
	}

	if (conn->env_handle) SQLFreeHandle(SQL_HANDLE_ENV, conn->env_handle);

	return RLM_SQL_OK;
}

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	SQLRETURN retval;
	rlm_sql_db2_conn_t *conn;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_db2_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	/* Allocate handles */
	SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &(conn->env_handle));
	SQLAllocHandle(SQL_HANDLE_DBC, conn->env_handle, &(conn->dbc_handle));

	/*
	 *	The db2 API doesn't qualify arguments as const even when they should be.
	 */
	{
		SQLCHAR *server, *login, *password;

		memcpy(&server, &config->sql_server, sizeof(server));
		memcpy(&login, &config->sql_login, sizeof(login));
		memcpy(&password, &config->sql_password, sizeof(password));

		retval = SQLConnect(conn->dbc_handle,
				    server, SQL_NTS,
				    login,  SQL_NTS,
				    password, SQL_NTS);
	}

	if (retval != SQL_SUCCESS) {
		ERROR("could not connect to DB2 server %s", config->sql_server);

		return RLM_SQL_ERROR;
	}

	return RLM_SQL_OK;
}

static sql_rcode_t sql_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config, char const *query)
{
	SQLRETURN retval;
	rlm_sql_db2_conn_t *conn;

	conn = handle->conn;

	/* allocate handle for statement */
	SQLAllocHandle(SQL_HANDLE_STMT, conn->dbc_handle, &(conn->stmt));

	/* execute query */
	{
		SQLCHAR *db2_query;
		memcpy(&db2_query, &query, sizeof(query));

		retval = SQLExecDirect(conn->stmt, db2_query, SQL_NTS);
		if(retval != SQL_SUCCESS) {
			/* XXX Check if retval means we should return RLM_SQL_RECONNECT */
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

static sql_rcode_t sql_fetch_row(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	int c, i;
	SQLINTEGER len, slen;
	rlm_sql_row_t retval;
	rlm_sql_db2_conn_t *conn;

	conn = handle->conn;

	c = sql_num_fields(handle, config);
	retval = (rlm_sql_row_t)rad_malloc(c*sizeof(char*)+1);
	memset(retval, 0, c*sizeof(char*)+1);

	/* advance cursor */
	if (SQLFetch(conn->stmt) == SQL_NO_DATA_FOUND) {
		handle->row = NULL;
		for (i = 0; i < c; i++) free(retval[i]);
		free(retval);
		return RLM_SQL_NO_MORE_ROWS;
	}

	for (i = 0; i < c; i++) {
		/* get column length */
		SQLColAttribute(conn->stmt, i+1, SQL_DESC_DISPLAY_SIZE, NULL, 0, NULL, &len);

		retval[i] = rad_malloc(len+1);

		/* get the actual column */
		SQLGetData(conn->stmt, i + 1, SQL_C_CHAR, retval[i], len+1, &slen);
		if(slen == SQL_NULL_DATA) {
			retval[i][0] = '\0';
		}
	}

	handle->row = retval;
	return RLM_SQL_OK;
}

static sql_rcode_t sql_free_result(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_db2_conn_t *conn;
	conn = handle->conn;
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
 * @return number of errors written to the sql_log_entry array.
 */
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	char			state[6];
	char			errbuff[1024];
	SQLINTEGER		err;
	SQLSMALLINT		rl;
	rlm_sql_db2_conn_t	*conn = handle->conn;

	rad_assert(conn);
	rad_assert(outlen > 0);

	errbuff[0] = '\0';
	SQLGetDiagRec(SQL_HANDLE_STMT, conn->stmt, 1, (SQLCHAR *) state, &err,
		      (SQLCHAR *) errbuff, sizeof(errbuff), &rl);
	if (errbuff[0] == '\0') return 0;

	out[0].type = L_ERR;
	out[0].msg = talloc_asprintf(ctx, "%s: %s", state, errbuff);

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
extern rlm_sql_module_t rlm_sql_db2;
rlm_sql_module_t rlm_sql_db2 = {
	.name				= "rlm_sql_db2",
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
