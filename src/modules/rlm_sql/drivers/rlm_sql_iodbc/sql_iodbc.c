/***************************************************************************
*  iODBC support for FreeRadius
*  www.iodbc.org   - iODBC info
*  Jeff Carneal    - Author
***************************************************************************/
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#include 	"radiusd.h"
#include	"rlm_sql.h"

/*************************************************************************
 *
 *	Function: sql_create_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
SQLSOCK *sql_create_socket(SQL_INST *inst)
{
	SQLSOCK *socket;

	if((socket = malloc(sizeof(SQLSOCK))) == NULL) {
		radlog(L_CONS|L_ERR, "sql_create_socket: no memory");
		exit(1);
	}

	if(SQLAllocEnv(&socket->env_handle) != SQL_SUCCESS) {
		radlog(L_CONS|L_ERR, "sql_create_socket: SQLAllocEnv failed:  %s", 
				sql_error(socket));
		exit(1);
	}

	if(SQLAllocConnect(socket->env_handle, &socket->dbc_handle) != SQL_SUCCESS) {
		radlog(L_CONS|L_ERR, "sql_create_socket: SQLAllocConnect failed:  %s", 
				sql_error(socket));
		exit(1);
	}

	if (SQLConnect(socket->dbc_handle, inst->config->sql_db, SQL_NTS, 
				inst->config->sql_login, SQL_NTS, inst->config->sql_password, 
				SQL_NTS) != SQL_SUCCESS) {
		radlog(L_CONS|L_ERR, "sql_create_socket: SQLConnectfailed:  %s", 
				sql_error(socket));
		exit(1);
	}

	if(SQLAllocStmt(socket->dbc_handle, &socket->stmt_handle) != SQL_SUCCESS) {
		radlog(L_CONS|L_ERR, "sql_create_socket: SQLAllocStmt failed:  %s", 
				sql_error(socket));
		exit(1);
	}

	return socket;
}

/*************************************************************************
 *
 *	Function: sql_query
 *
 *	Purpose: Issue a non-SELECT query (ie: update/delete/insert) to
 *               the database.
 *
 *************************************************************************/
int sql_query(SQL_INST *inst, SQLSOCK *socket, char *querystr)
{
	if (inst->config->sqltrace)
		DEBUG(querystr);
	if (socket->dbc_handle == NULL) {
		radlog(L_ERR, "sql_query:  Socket not connected");
		return 0;
	}

	if(SQLExecDirect(socket->stmt_handle, querystr, SQL_NTS) != SQL_SUCCESS) {
		radlog(L_CONS|L_ERR, "sql_query: failed:  %s", 
				sql_error(socket));
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
int sql_select_query(SQL_INST *inst, SQLSOCK *socket, char *querystr)
{
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
int sql_store_result(SQLSOCK *socket) {
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
int sql_num_fields(SQLSOCK *socket) {
	return 0;
}

/*************************************************************************
 *
 *	Function: sql_num_rows
 *
 *	Purpose: database specific num_rows. Returns number of rows in
 *               query
 *
 *************************************************************************/
int sql_num_rows(SQLSOCK *socket) {
	return 0;
}


/*************************************************************************
 *
 *	Function: sql_fetch_row
 *
 *	Purpose: database specific fetch_row. Returns a SQL_ROW struct
 *               with all the data for the query
 *
 *************************************************************************/
SQL_ROW sql_fetch_row(SQLSOCK *socket)
{
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
void sql_free_result(SQLSOCK *socket) {
}



/*************************************************************************
 *
 *	Function: sql_error
 *
 *	Purpose: database specific error. Returns error associated with
 *               connection
 *
 *************************************************************************/
char *sql_error(SQLSOCK *socket)
{
	SQLINTEGER errornum = 0;
	SQLSMALLINT length = 0;
	SQLCHAR state[256] = "";
	static SQLCHAR error[256] = "";

	SQLError(socket->env_handle, socket->dbc_handle, socket->stmt_handle, 
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
void sql_close(SQLSOCK *socket)
{

	SQLFreeStmt(socket->stmt_handle, SQL_DROP);
	SQLDisconnect(socket->dbc_handle);
	SQLFreeConnect(socket->dbc_handle);
	SQLFreeEnv(socket->env_handle);

	socket->stmt_handle = NULL;
	socket->dbc_handle = NULL;
	socket->env_handle = NULL;
}


/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
void sql_finish_query(SQLSOCK *socket)
{
}



/*************************************************************************
 *
 *	Function: sql_finish_select_query
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
void sql_finish_select_query(SQLSOCK *socket)
{
}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: Return the number of rows affected by the query (update,
 *               or insert)
 *
 *************************************************************************/
int sql_affected_rows(SQLSOCK *socket) {
	SQLINTEGER count;

	SQLRowCount(socket->stmt_handle, &count);
	return (int)count;
}


/*************************************************************************
 *
 *      Function: sql_escape_string
 *
 *      Purpose: Esacpe "'" and any other wierd charactors
 *
 *************************************************************************/
int sql_escape_string(char *to, char *from, int length)
{
	int x, y;

	for(x=0, y=0; (x < length) && (from[x]!='\0'); x++) {
    switch (from[x]) {
    case 0:				
      to[y++]= '\\';
      to[y++]= '0';
      break;
    case '\n':				
      to[y++]= '\\';
      to[y++]= 'n';
      break;
    case '\r':
      to[y++]= '\\';
      to[y++]= 'r';
      break;
    case '\\':
      to[y++]= '\\';
      to[y++]= '\\';
      break;
    case '\'':
      to[y++]= '\\';
      to[y++]= '\'';
      break;
    case '"':				
      to[y++]= '\\';
      to[y++]= '"';
      break;
    case '\032':			
      to[y++]= '\\';
      to[y++]= 'Z';
      break;
    default:
      to[y++]= from[x];
    }
  }
	to[y]=0;

	return 1;
}

