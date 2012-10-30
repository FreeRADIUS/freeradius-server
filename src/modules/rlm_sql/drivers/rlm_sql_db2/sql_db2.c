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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <sys/stat.h>

#include <sql.h>
#include <sqlcli.h>
#include "rlm_sql.h"

typedef struct rlm_sql_db2_sock {
	SQLHANDLE hdbc;
	SQLHANDLE henv;
	SQLHANDLE stmt;
} rlm_sql_db2_sock;

/*************************************************************************
 *
 *	Function: sql_create_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
static int sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config)
{
	SQLRETURN retval;
	rlm_sql_db2_sock *sock;

	/* allocate socket */
	if (!sqlsocket->conn) {
		sqlsocket->conn = (rlm_sql_db2_sock*)rad_malloc(sizeof(rlm_sql_db2_sock));
		if (!sqlsocket->conn) {
			return -1;
		}
	}
	sock = sqlsocket->conn;
	memset(sock, 0, sizeof(*sock));

	/* allocate handles */
	SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &(sock->henv));
	SQLAllocHandle(SQL_HANDLE_DBC, sock->henv, &(sock->hdbc));

	/* connect to database */
	retval = SQLConnect(sock->hdbc,
			config->sql_server, SQL_NTS,
			config->sql_login,  SQL_NTS,
			config->sql_password, SQL_NTS);
	if(retval != SQL_SUCCESS) {
		radlog(L_ERR, "could not connect to DB2 server %s\n", config->sql_server);
		SQLDisconnect(sock->hdbc);
		SQLFreeHandle(SQL_HANDLE_DBC, sock->hdbc);
		SQLFreeHandle(SQL_HANDLE_ENV, sock->henv);
		return -1;
	}

	return 0;
}


/*************************************************************************
 *
 *      Function: sql_destroy_socket
 *
 *      Purpose: Free socket and private connection data
 *
 *************************************************************************/
static int sql_destroy_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config)
{
	free(sqlsocket->conn);
	sqlsocket->conn = NULL;
	return 0;
}

/*************************************************************************
 *
 *	Function: sql_query
 *
 *	Purpose: Issue a query to the database
 *
 *************************************************************************/
static int sql_query(SQLSOCK * sqlsocket, SQL_CONFIG *config, char *querystr)
{
	SQLRETURN retval;
	rlm_sql_db2_sock *sock;

	sock = sqlsocket->conn;

	/* allocate handle for statement */
	SQLAllocHandle(SQL_HANDLE_STMT, sock->hdbc,
			&(sock->stmt));

	/* execute query */
	retval = SQLExecDirect(sock->stmt, querystr, SQL_NTS);
	if(retval != SQL_SUCCESS) {
		/* XXX Check if retval means we should return SQL_DOWN */
		radlog(L_ERR, "could not execute statement \"%s\"\n", querystr);
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
static int sql_select_query(SQLSOCK * sqlsocket, SQL_CONFIG *config, char *querystr)
{
	return sql_query(sqlsocket, config, querystr);
}


/*************************************************************************
 *
 *	Function: sql_store_result
 *
 *	Purpose: database specific store_result function. Returns a result
 *               set for the query.
 *
 *************************************************************************/
static int sql_store_result(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
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
static int sql_num_fields(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	SQLSMALLINT c;
	rlm_sql_db2_sock *sock;

	sock = sqlsocket->conn;
	SQLNumResultCols(sock->stmt, &c);
	return c;
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
static int sql_fetch_row(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	int c, i;
	SQLINTEGER len, slen;
	SQL_ROW retval;
	rlm_sql_db2_sock *sock;

	sock = sqlsocket->conn;

	c = sql_num_fields(sqlsocket, config);
	retval = (SQL_ROW)rad_malloc(c*sizeof(char*)+1);
	/* advance cursor */
	if(SQLFetch(sock->stmt) == SQL_NO_DATA_FOUND) {
		sqlsocket->row = NULL;
		return 0;
	}

	for(i = 0; i < c; i++) {
		/* get column length */
		SQLColAttribute(sock->stmt,
				i+1, SQL_DESC_DISPLAY_SIZE,
				NULL, 0, NULL, &len);
		retval[i] = (char*)rad_malloc(len+1);
		/* get the actual column */
		SQLGetData(sock->stmt,
				i+1, SQL_C_CHAR, retval[i], len+1, &slen);
		if(slen == SQL_NULL_DATA)
			retval[i][0] = '\0';
	}

	sqlsocket->row = retval;
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
static int sql_free_result(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	rlm_sql_db2_sock *sock;
	sock = sqlsocket->conn;
	SQLFreeHandle(SQL_HANDLE_STMT, sock->stmt);
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
static char *sql_error(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	/* this should really be enough, if not, you still got the sqlstate */
#define MSGLEN 512
	char sqlstate[6];
	char msg[MSGLEN];
	char *retval;
	SQLINTEGER err;
	SQLSMALLINT rl;
	rlm_sql_db2_sock *sock;

	sock = sqlsocket->conn;

	SQLGetDiagRec(SQL_HANDLE_STMT, sock->stmt,
			1, sqlstate, &err, msg, MSGLEN, &rl);
	retval = (char*)rad_malloc(strlen(msg)+20);
	sprintf(retval, "SQLSTATE %s: %s", sqlstate, msg);
	return retval;
}


/*************************************************************************
 *
 *	Function: sql_close
 *
 *	Purpose: database specific close. Closes an open database
 *               connection
 *
 *************************************************************************/
static int sql_close(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	rlm_sql_db2_sock *sock;

	sock = sqlsocket->conn;

	SQLFreeHandle(SQL_HANDLE_DBC, sock->hdbc);
	SQLFreeHandle(SQL_HANDLE_ENV, sock->henv);
	return 0;
}


/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
static int sql_finish_query(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	return 0;
}



/*************************************************************************
 *
 *	Function: sql_finish_select_query
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
static int sql_finish_select_query(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	return sql_finish_query(sqlsocket, config);
}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: Return the number of rows affected by the last query.
 *
 *************************************************************************/
static int sql_affected_rows(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	SQLINTEGER c;
	rlm_sql_db2_sock *sock;

	sock = sqlsocket->conn;

	SQLRowCount(sock->stmt, &c);
	return c;
}


static int
not_implemented(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	radlog(L_ERR, "sql_db2: calling unimplemented function");
	exit(1);
}


/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_db2 = {
	"rlm_sql_db2",
	sql_init_socket,
	sql_destroy_socket, /* sql_destroy_socket*/
	sql_query,
	sql_select_query,
	not_implemented, /* sql_store_result */
	sql_num_fields,
	not_implemented, /* sql_num_rows */
	sql_fetch_row,
	sql_free_result,
	sql_error,
	sql_close,
	sql_finish_query,
	sql_finish_select_query,
	sql_affected_rows,
};
