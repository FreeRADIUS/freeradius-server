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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <sys/stat.h>

#include <isql.h>
#include <isqlext.h>
#include <sqltypes.h>

#include "rlm_sql.h"

typedef struct rlm_sql_iodbc_sock {
	HENV    env_handle;
	HDBC    dbc_handle;
	HSTMT   stmt_handle;
	int		id;
	SQL_ROW row;

	struct sql_socket *next;

	void	*conn;
} rlm_sql_iodbc_sock;;

static const char *sql_error(SQLSOCK *sqlsocket, SQL_CONFIG *config);
static int sql_num_fields(SQLSOCK *sqlsocket, SQL_CONFIG *config);

/*************************************************************************
 *
 *	Function: sql_init_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
static int sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	rlm_sql_iodbc_sock *iodbc_sock;
	SQLRETURN rcode;

	if (!sqlsocket->conn) {
		sqlsocket->conn = (rlm_sql_iodbc_sock *)rad_malloc(sizeof(rlm_sql_iodbc_sock));
		if (!sqlsocket->conn) {
			return -1;
		}
	}
	iodbc_sock = sqlsocket->conn;
	memset(iodbc_sock, 0, sizeof(*iodbc_sock));

	rcode = SQLAllocEnv(&iodbc_sock->env_handle);
	if (!SQL_SUCCEEDED(rcode)) {
		radlog(L_CONS|L_ERR, "sql_create_socket: SQLAllocEnv failed:  %s",
				sql_error(sqlsocket, config));
		return -1;
	}

	rcode = SQLAllocConnect(iodbc_sock->env_handle,
				&iodbc_sock->dbc_handle);
	if (!SQL_SUCCEEDED(rcode)) {
		radlog(L_CONS|L_ERR, "sql_create_socket: SQLAllocConnect failed:  %s",
				sql_error(sqlsocket, config));
		return -1;
	}

	rcode = SQLConnect(iodbc_sock->dbc_handle, config->sql_db,
			   SQL_NTS, config->sql_login, SQL_NTS,
			   config->sql_password, SQL_NTS);
	if (!SQL_SUCCEEDED(rcode)) {
		radlog(L_CONS|L_ERR, "sql_create_socket: SQLConnectfailed:  %s",
				sql_error(sqlsocket, config));
		return -1;
	}

	return 0;
}

/*************************************************************************
 *
 *	Function: sql_destroy_socket
 *
 *	Purpose: Free socket and private connection data
 *
 *************************************************************************/
static int sql_destroy_socket(SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config)
{
	free(sqlsocket->conn);
	sqlsocket->conn = NULL;
	return 0;
}

/*************************************************************************
 *
 *	Function: sql_query
 *
 *	Purpose: Issue a non-SELECT query (ie: update/delete/insert) to
 *               the database.
 *
 *************************************************************************/
static int sql_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr) {

	rlm_sql_iodbc_sock *iodbc_sock = sqlsocket->conn;
	SQLRETURN rcode;

	rcode = SQLAllocStmt(iodbc_sock->dbc_handle,
			     &iodbc_sock->stmt_handle);
	if (!SQL_SUCCEEDED(rcode)) {
		radlog(L_CONS|L_ERR, "sql_create_socket: SQLAllocStmt failed:  %s",
				sql_error(sqlsocket, config));
		return -1;
	}

	if (config->sqltrace)
		radlog(L_DBG, "rlm_sql:  %s", querystr);
	if (iodbc_sock->dbc_handle == NULL) {
		radlog(L_ERR, "sql_query:  Socket not connected");
		return -1;
	}

	rcode = SQLExecDirect(iodbc_sock->stmt_handle, querystr, SQL_NTS);
	if (!SQL_SUCCEEDED(rcode)) {
		radlog(L_CONS|L_ERR, "sql_query: failed:  %s",
				sql_error(sqlsocket, config));
		return -1;
	}

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_select_query
 *
 *	Purpose: Issue a select query to the database
 *
 *************************************************************************/
static int sql_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr) {

	int numfields = 0;
	int i=0;
	char **row=NULL;
	SQLINTEGER len=0;
	rlm_sql_iodbc_sock *iodbc_sock = sqlsocket->conn;

	if(sql_query(sqlsocket, config, querystr) < 0) {
		return -1;
	}

	numfields = sql_num_fields(sqlsocket, config);

	row = (char **) rad_malloc(sizeof(char *) * (numfields+1));
	memset(row, 0, (sizeof(char *) * (numfields)));
	row[numfields] = NULL;

	for(i=1; i<=numfields; i++) {
		SQLColAttributes(iodbc_sock->stmt_handle, ((SQLUSMALLINT) i), SQL_COLUMN_LENGTH,
										NULL, 0, NULL, &len);
		len++;

		/*
		 * Allocate space for each column
		 */
		row[i-1] = (SQLCHAR*)rad_malloc((int)len);

		/*
		 * This makes me feel dirty, but, according to Microsoft, it works.
		 * Any ODBC datatype can be converted to a 'char *' according to
		 * the following:
		 *
		 * http://msdn.microsoft.com/library/psdk/dasdk/odap4o4z.htm
		 */
		SQLBindCol(iodbc_sock->stmt_handle, i, SQL_C_CHAR, (SQLCHAR *)row[i-1], len, 0);
	}

	iodbc_sock->row = row;

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_store_result
 *
 *	Purpose: database specific store_result function. Returns a result
 *               set for the query.
 *
 *************************************************************************/
static int sql_store_result(UNUSED SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config) {

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_num_fields
 *
 *	Purpose: database specific num_fields function. Returns number
 *               of columns from query
 *
 *************************************************************************/
static int sql_num_fields(SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config) {

	SQLSMALLINT count=0;
	rlm_sql_iodbc_sock *iodbc_sock = sqlsocket->conn;

	SQLNumResultCols(iodbc_sock->stmt_handle, &count);

	return (int)count;
}

/*************************************************************************
 *
 *	Function: sql_num_rows
 *
 *	Purpose: database specific num_rows. Returns number of rows in
 *               query
 *
 *************************************************************************/
static int sql_num_rows(UNUSED SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config) {
	/*
	 * I presume this function is used to determine the number of
	 * rows in a result set *before* fetching them.  I don't think
	 * this is possible in ODBC 2.x, but I'd be happy to be proven
	 * wrong.  If you know how to do this, email me at jeff@apex.net
	 */
	return 0;
}


/*************************************************************************
 *
 *	Function: sql_fetch_row
 *
 *	Purpose: database specific fetch_row. Returns a SQL_ROW struct
 *               with all the data for the query in 'sqlsocket->row'. Returns
 *		 0 on success, -1 on failure, SQL_DOWN if 'database is down'
 *
 *************************************************************************/
static int sql_fetch_row(SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config) {

	SQLRETURN rc;
	rlm_sql_iodbc_sock *iodbc_sock = sqlsocket->conn;

	sqlsocket->row = NULL;

	if((rc = SQLFetch(iodbc_sock->stmt_handle)) == SQL_NO_DATA_FOUND) {
		return 0;
	}
	/* XXX Check rc for database down, if so, return SQL_DOWN */

	sqlsocket->row = iodbc_sock->row;
	return 0;
}



/*************************************************************************
 *
 *	Function: sql_free_result
 *
 *	Purpose: database specific free_result. Frees memory allocated
 *               for a result set
 *
 *************************************************************************/
static int sql_free_result(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	int i=0;
	rlm_sql_iodbc_sock *iodbc_sock = sqlsocket->conn;

	for(i=0; i<sql_num_fields(sqlsocket, config); i++) {
		free(iodbc_sock->row[i]);
	}
	free(iodbc_sock->row);
	iodbc_sock->row=NULL;

	SQLFreeStmt( iodbc_sock->stmt_handle, SQL_DROP );

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_error
 *
 *	Purpose: database specific error. Returns error associated with
 *               connection
 *
 *************************************************************************/
static const char *sql_error(SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config) {

	SQLINTEGER errornum = 0;
	SQLSMALLINT length = 0;
	SQLCHAR state[256] = "";
	static SQLCHAR error[256] = "";
	rlm_sql_iodbc_sock *iodbc_sock = sqlsocket->conn;

	SQLError(iodbc_sock->env_handle, iodbc_sock->dbc_handle, iodbc_sock->stmt_handle,
		state, &errornum, error, 256, &length);
	return error;
}


/*************************************************************************
 *
 *	Function: sql_close
 *
 *	Purpose: database specific close. Closes an open database
 *               connection and cleans up any open handles.
 *
 *************************************************************************/
static int sql_close(SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config) {

	rlm_sql_iodbc_sock *iodbc_sock = sqlsocket->conn;

	SQLFreeStmt(iodbc_sock->stmt_handle, SQL_DROP);
	SQLDisconnect(iodbc_sock->dbc_handle);
	SQLFreeConnect(iodbc_sock->dbc_handle);
	SQLFreeEnv(iodbc_sock->env_handle);

	iodbc_sock->stmt_handle = NULL;
	iodbc_sock->dbc_handle = NULL;
	iodbc_sock->env_handle = NULL;

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
static int sql_finish_query(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	return sql_free_result(sqlsocket, config);
}



/*************************************************************************
 *
 *	Function: sql_finish_select_query
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
static int sql_finish_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
	return sql_free_result(sqlsocket, config);
}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: Return the number of rows affected by the query (update,
 *               or insert)
 *
 *************************************************************************/
static int sql_affected_rows(SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config) {

	SQLINTEGER count;
	rlm_sql_iodbc_sock *iodbc_sock = sqlsocket->conn;

	SQLRowCount(iodbc_sock->stmt_handle, &count);
	return (int)count;
}

/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_iodbc = {
	"rlm_sql_iodbc",
	sql_init_socket,
	sql_destroy_socket,
	sql_query,
	sql_select_query,
	sql_store_result,
	sql_num_fields,
	sql_num_rows,
	sql_fetch_row,
	sql_free_result,
	sql_error,
	sql_close,
	sql_finish_query,
	sql_finish_select_query,
	sql_affected_rows
};
