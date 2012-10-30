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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Dmitri Ageev <d_ageev@ortcc.ru>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <sqltypes.h>
#include "rlm_sql.h"

typedef struct rlm_sql_unixodbc_sock {
	SQLHENV env_handle;
	SQLHDBC dbc_handle;
	SQLHSTMT stmt_handle;
	SQL_ROW row;
	void *conn;
} rlm_sql_unixodbc_sock;


#include <sql.h>
#include <sqlext.h>

/* Forward declarations */
static const char *sql_error(SQLSOCK *sqlsocket, SQL_CONFIG *config);
static int sql_state(long err_handle, SQLSOCK *sqlsocket, SQL_CONFIG *config);
static int sql_free_result(SQLSOCK *sqlsocket, SQL_CONFIG *config);
static int sql_affected_rows(SQLSOCK *sqlsocket, SQL_CONFIG *config);
static int sql_num_fields(SQLSOCK *sqlsocket, SQL_CONFIG *config);


/*************************************************************************
 *
 *	Function: sql_init_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
static int sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
    rlm_sql_unixodbc_sock *unixodbc_sock;
    long err_handle;

	if (!sqlsocket->conn) {
		sqlsocket->conn = (rlm_sql_unixodbc_sock *)rad_malloc(sizeof(rlm_sql_unixodbc_sock));
		if (!sqlsocket->conn) {
			return -1;
		}
	}
	unixodbc_sock = sqlsocket->conn;
	memset(unixodbc_sock, 0, sizeof(*unixodbc_sock));

    /* 1. Allocate environment handle and register version */
    err_handle = SQLAllocHandle(SQL_HANDLE_ENV,SQL_NULL_HANDLE,&unixodbc_sock->env_handle);
    if (sql_state(err_handle, sqlsocket, config))
    {
	radlog(L_ERR, "rlm_sql_unixodbc: Can't allocate environment handle\n");
	return -1;
    }
    err_handle = SQLSetEnvAttr(unixodbc_sock->env_handle, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0);
    if (sql_state(err_handle, sqlsocket, config))
    {
	radlog(L_ERR, "rlm_sql_unixodbc: Can't register ODBC version\n");
	SQLFreeHandle(SQL_HANDLE_ENV, unixodbc_sock->env_handle);
	return -1;
    }
    /* 2. Allocate connection handle */
    err_handle = SQLAllocHandle(SQL_HANDLE_DBC, unixodbc_sock->env_handle, &unixodbc_sock->dbc_handle);
    if (sql_state(err_handle, sqlsocket, config))
    {
	radlog(L_ERR, "rlm_sql_unixodbc: Can't allocate connection handle\n");
	SQLFreeHandle(SQL_HANDLE_ENV, unixodbc_sock->env_handle);
	return -1;
    }

    /* 3. Connect to the datasource */
    err_handle = SQLConnect(unixodbc_sock->dbc_handle,
	(SQLCHAR*) config->sql_server, strlen(config->sql_server),
	(SQLCHAR*) config->sql_login, strlen(config->sql_login),
	(SQLCHAR*) config->sql_password, strlen(config->sql_password));
    if (sql_state(err_handle, sqlsocket, config))
    {
	radlog(L_ERR, "rlm_sql_unixodbc: Connection failed\n");
	SQLFreeHandle(SQL_HANDLE_DBC, unixodbc_sock->dbc_handle);
	SQLFreeHandle(SQL_HANDLE_ENV, unixodbc_sock->env_handle);
	return -1;
    }

    /* 4. Allocate the statement */
    err_handle = SQLAllocStmt(unixodbc_sock->dbc_handle, &unixodbc_sock->stmt_handle);
    if (sql_state(err_handle, sqlsocket, config))
    {
	radlog(L_ERR, "rlm_sql_unixodbc: Can't allocate the statement\n");
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
    rlm_sql_unixodbc_sock *unixodbc_sock = sqlsocket->conn;
    long err_handle;
    int state;

    /* Executing query */
    err_handle = SQLExecDirect(unixodbc_sock->stmt_handle, (SQLCHAR *)querystr, strlen(querystr));
    if ((state = sql_state(err_handle, sqlsocket, config))) {
	if(state == SQL_DOWN)
	    radlog(L_INFO, "rlm_sql_unixodbc: rlm_sql will attempt to reconnect\n");
	return state;
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
    rlm_sql_unixodbc_sock *unixodbc_sock = sqlsocket->conn;
    SQLINTEGER column;
    SQLLEN len;
    int numfields;
    int state;

    /* Only state = 0 means success */
    if((state = sql_query(sqlsocket, config, querystr)))
	return state;

    numfields=sql_num_fields(sqlsocket, config);
    if(numfields < 0)
	return -1;

    /* Reserving memory for result */
    unixodbc_sock->row = (char **) rad_malloc((numfields+1)*sizeof(char *));
    unixodbc_sock->row[numfields] = NULL;

    for(column=1; column<=numfields; column++) {
    	SQLColAttributes(unixodbc_sock->stmt_handle,((SQLUSMALLINT) column),SQL_COLUMN_LENGTH,NULL,0,NULL,&len);
	unixodbc_sock->row[column-1] = (char*)rad_malloc((int)++len);
	SQLBindCol(unixodbc_sock->stmt_handle, column, SQL_C_CHAR, (SQLCHAR *)unixodbc_sock->row[column-1], len, NULL);
    }
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
  /* Not used */
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
static int sql_num_fields(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
    rlm_sql_unixodbc_sock *unixodbc_sock = sqlsocket->conn;
    long err_handle;
    SQLSMALLINT num_fields = 0;

    err_handle = SQLNumResultCols(unixodbc_sock->stmt_handle,&num_fields);
    if (sql_state(err_handle, sqlsocket, config))
	return -1;

    return num_fields;
}


/*************************************************************************
 *
 *	Function: sql_num_rows
 *
 *	Purpose: database specific num_rows. Returns number of rows in
 *               query
 *
 *************************************************************************/
static int sql_num_rows(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
    return sql_affected_rows(sqlsocket, config);
}


/*************************************************************************
 *
 *	Function: sql_fetch_row
 *
 *	Purpose: database specific fetch_row. Returns a SQL_ROW struct
 *               with all the data for the query in 'sqlsocket->row'. Returns
 *		 0 on success, -1 on failure, SQL_DOWN if 'database is down'.
 *
 *************************************************************************/
static int sql_fetch_row(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
    rlm_sql_unixodbc_sock *unixodbc_sock = sqlsocket->conn;
    long err_handle;
    int state;

    sqlsocket->row = NULL;

    err_handle = SQLFetch(unixodbc_sock->stmt_handle);
    if(err_handle == SQL_NO_DATA_FOUND)
	return 0;
    if ((state = sql_state(err_handle, sqlsocket, config))) {
	if(state == SQL_DOWN)
	    radlog(L_INFO, "rlm_sql_unixodbc: rlm_sql will attempt to reconnect\n");
	return state;
    }
    sqlsocket->row = unixodbc_sock->row;
    return 0;
}


/*************************************************************************
 *
 *	Function: sql_finish_select_query
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
static int sql_finish_select_query(SQLSOCK * sqlsocket, SQL_CONFIG *config) {
    rlm_sql_unixodbc_sock *unixodbc_sock = sqlsocket->conn;

    sql_free_result(sqlsocket, config);
    SQLFreeStmt(unixodbc_sock->stmt_handle, SQL_CLOSE);
    return 0;
}

/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
static int sql_finish_query(SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config) {
    rlm_sql_unixodbc_sock *unixodbc_sock = sqlsocket->conn;

    SQLFreeStmt(unixodbc_sock->stmt_handle, SQL_CLOSE);
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
    rlm_sql_unixodbc_sock *unixodbc_sock = sqlsocket->conn;
    int column, numfileds=sql_num_fields(sqlsocket, config);

    /* Freeing reserved memory */
    if(unixodbc_sock->row != NULL) {
	for(column=0; column<numfileds; column++) {
	    if(unixodbc_sock->row[column] != NULL) {
		free(unixodbc_sock->row[column]);
		unixodbc_sock->row[column] = NULL;
	    }
	}
        free(unixodbc_sock->row);
	unixodbc_sock->row = NULL;
    }
    return 0;
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
    rlm_sql_unixodbc_sock *unixodbc_sock = sqlsocket->conn;

    SQLFreeStmt(unixodbc_sock->stmt_handle, SQL_DROP);
    SQLDisconnect(unixodbc_sock->dbc_handle);
    SQLFreeConnect(unixodbc_sock->dbc_handle);
    SQLFreeEnv(unixodbc_sock->env_handle);

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
    SQLCHAR state[256];
    SQLCHAR error[256];
    SQLINTEGER errornum = 0;
    SQLSMALLINT length = 255;
    static char result[1024];	/* NOT thread-safe! */

    rlm_sql_unixodbc_sock *unixodbc_sock = sqlsocket->conn;

    error[0] = state[0] = '\0';

    SQLError(
	unixodbc_sock->env_handle,
	unixodbc_sock->dbc_handle,
	unixodbc_sock->stmt_handle,
	state,
	&errornum,
	error,
	256,
	&length);

    sprintf(result, "%s %s", state, error);
    result[sizeof(result) - 1] = '\0'; /* catch idiot thread issues */
    return result;
}

/*************************************************************************
 *
 *	Function: sql_state
 *
 *	Purpose: Returns 0 for success, SQL_DOWN if the error was
 *               connection related or -1 for other errors
 *
 *************************************************************************/
static int sql_state(long err_handle, SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config) {
    SQLCHAR state[256];
    SQLCHAR error[256];
    SQLINTEGER errornum = 0;
    SQLSMALLINT length = 255;
    int res = -1;

    rlm_sql_unixodbc_sock *unixodbc_sock = sqlsocket->conn;

    if(SQL_SUCCEEDED(err_handle))
	return 0;		/* on success, just return 0 */

    error[0] = state[0] = '\0';

    SQLError(
	unixodbc_sock->env_handle,
    	unixodbc_sock->dbc_handle,
    	unixodbc_sock->stmt_handle,
    	state,
	&errornum,
    	error,
    	256,
    	&length);

    if(state[0] == '0') {
	switch(state[1]) {
	case '1':		/* SQLSTATE 01 class contains info and warning messages */
	    radlog(L_INFO, "rlm_sql_unixodbc: %s %s\n", state, error);
	case '0':		/* SQLSTATE 00 class means success */
	    res = 0;
	    break;
	case '8':		/* SQLSTATE 08 class describes various connection errors */
	    radlog(L_ERR, "rlm_sql_unixodbc: SQL down %s %s\n", state, error);
	    res = SQL_DOWN;
	    break;
	default:		/* any other SQLSTATE means error */
	    radlog(L_ERR, "rlm_sql_unixodbc: %s %s\n", state, error);
	    res = -1;
	    break;
	}
    }

    return res;
}

/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: Return the number of rows affected by the query (update,
 *               or insert)
 *
 *************************************************************************/
static int sql_affected_rows(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
    rlm_sql_unixodbc_sock *unixodbc_sock = sqlsocket->conn;
    long err_handle;
    SQLLEN affected_rows;

    err_handle = SQLRowCount(unixodbc_sock->stmt_handle, &affected_rows);
    if (sql_state(err_handle, sqlsocket, config))
	return -1;

    return affected_rows;
}


/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_unixodbc = {
	"rlm_sql_unixodbc",
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
