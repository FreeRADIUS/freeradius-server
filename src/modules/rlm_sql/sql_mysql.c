/*
 * sql_mysql.c		SQL Module
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Mike Machado <mike@innercite.com>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */



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
SQLSOCK *sql_create_socket(SQL_INST *inst) {
	SQLSOCK *socket;

	if ((socket = malloc(sizeof(SQLSOCK))) == NULL) {
		radlog(L_CONS|L_ERR, "sql_create_socket: no memory");
		exit(1);
	}

	mysql_init(&(socket->conn));
	if (!(socket->sock = mysql_real_connect(&(socket->conn), inst->config->sql_server, inst->config->sql_login, inst->config->sql_password, inst->config->sql_db, 0, NULL, CLIENT_FOUND_ROWS))) {
		radlog(L_ERR, "rlm_sql: Couldn't connect socket to MySQL server %s@%s:%s", inst->config->sql_login, inst->config->sql_server, inst->config->sql_db);
		radlog(L_ERR, "rlm_sql:  Mysql error '%s'", mysql_error(&socket->conn));
		socket->sock = NULL;
		return NULL;
	}
	return socket;
}

/*************************************************************************
 *
 *	Function: sql_query
 *
 *	Purpose: Issue a query to the database
 *
 *************************************************************************/
int sql_query(SQL_INST *inst, SQLSOCK *socket, char *querystr) {

	if (inst->config->sqltrace)
		DEBUG(querystr);
	 if (socket->sock == NULL) {
		radlog(L_ERR, "Socket not connected");
		return 0;
	}
	return mysql_query(socket->sock, querystr);
}


/*************************************************************************
 *
 *	Function: sql_select_query
 *
 *	Purpose: Issue a select query to the database
 *
 *************************************************************************/
int sql_select_query(SQL_INST *inst, SQLSOCK *socket, char *querystr) {

	if (inst->config->sqltrace)
		DEBUG(querystr);
	if (socket->sock == NULL) {
		radlog(L_ERR, "Socket not connected");
		return 0;
	}
	mysql_query(socket->sock, querystr);
	if (sql_store_result(socket) && sql_num_fields(socket)) 
		return 1;
	else
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

	if (socket->sock == NULL) {
		radlog(L_ERR, "Socket not connected");
		return 0;
	}
	if (!(socket->result = mysql_store_result(socket->sock))) {
		radlog(L_ERR,"MYSQL Error: Cannot get result");
		radlog(L_ERR,"MYSQL Error: %s",mysql_error(socket->sock));
		return 0;
	}
	return 1;

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

	int	num = 0;
#if MYSQL_VERSION_ID >= 32224
	if (!(num = mysql_field_count(socket->sock))) {
#else
	if (!(num = mysql_num_fields(socket->sock))) {
#endif
		radlog(L_ERR,"MYSQL Error: Cannot get result");
		radlog(L_ERR,"MYSQL error: %s",mysql_error(socket->sock));
	}
	return num;
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

	return mysql_num_rows(socket->result);
}


/*************************************************************************
 *
 *	Function: sql_fetch_row
 *
 *	Purpose: database specific fetch_row. Returns a SQL_ROW struct
 *               with all the data for the query
 *
 *************************************************************************/
SQL_ROW sql_fetch_row(SQLSOCK *socket) {

	return mysql_fetch_row(socket->result);
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

	mysql_free_result(socket->result);
}



/*************************************************************************
 *
 *	Function: sql_error
 *
 *	Purpose: database specific error. Returns error associated with
 *               connection
 *
 *************************************************************************/
char *sql_error(SQLSOCK *socket) {

	return mysql_error(socket->sock);
}


/*************************************************************************
 *
 *	Function: sql_close
 *
 *	Purpose: database specific close. Closes an open database
 *               connection
 *
 *************************************************************************/
void sql_close(SQLSOCK *socket) {

	mysql_close(socket->sock);
	socket->sock = NULL;
}


/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
void sql_finish_query(SQLSOCK *socket) {

}



/*************************************************************************
 *
 *	Function: sql_finish_select_query
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
void sql_finish_select_query(SQLSOCK *socket) {

	sql_free_result(socket);
}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
int sql_affected_rows(SQLSOCK *socket) {

	return mysql_affected_rows(socket->sock);
}


/*************************************************************************
 *
 *      Function: sql_escape_string
 *
 *      Purpose: Esacpe "'" and any other wierd charactors
 *
 *************************************************************************/
int sql_escape_string(char *to, char *from, int length) {

	mysql_escape_string(to, from, length);
	return 1;
}
