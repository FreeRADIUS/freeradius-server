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
#include	"sql_mysql.h"


/*************************************************************************
 *
 *	Function: sql_create_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
int sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	rlm_sql_mysql_sock *mysql_sock;

	sqlsocket->conn = (rlm_sql_mysql_sock *)rad_malloc(sizeof(rlm_sql_mysql_sock));

	mysql_sock = sqlsocket->conn;

	mysql_init(&(mysql_sock->conn));
	if (!(mysql_sock->sock = mysql_real_connect(&(mysql_sock->conn), config->sql_server, config->sql_login, config->sql_password,
													config->sql_db, 0, NULL, CLIENT_FOUND_ROWS))) {
		radlog(L_ERR, "rlm_sql: Couldn't connect socket to MySQL server %s@%s:%s", config->sql_login, config->sql_server, config->sql_db);
		radlog(L_ERR, "rlm_sql:  Mysql error '%s'", mysql_error(&mysql_sock->conn));
		mysql_sock->sock = NULL;
		return -1;
	}


	return 0;
}


/*************************************************************************
 *
 *	Function: sql_destroy_socket
 *
 *	Purpose: Free socket and any private connection data
 *
 *************************************************************************/
int sql_destroy_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	free(mysql_sock);
	free(sqlsocket);

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_query
 *
 *	Purpose: Issue a query to the database
 *
 *************************************************************************/
int sql_query(SQLSOCK * sqlsocket, SQL_CONFIG *config, char *querystr) {

	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	if (config->sqltrace)
		radlog(L_DBG,"query:  %s", querystr);
	if (mysql_sock->sock == NULL) {
		radlog(L_ERR, "Socket not connected");
		return -1;
	}
	if (mysql_query(mysql_sock->sock, querystr) == 0) {
		return 0;
	} else {
		return -1;
	}
}


/*************************************************************************
 *
 *	Function: sql_select_query
 *
 *	Purpose: Issue a select query to the database
 *
 *************************************************************************/
int sql_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr) {

	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	if (config->sqltrace)
		radlog(L_DBG,querystr);
	if (mysql_sock->sock == NULL) {
		radlog(L_ERR, "Socket not connected");
		return -1;
	}
	mysql_query(mysql_sock->sock, querystr);
	if (sql_store_result(sqlsocket, config) < 0 || sql_num_fields(sqlsocket, config) < 0)
		return -1;
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
int sql_store_result(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	if (mysql_sock->sock == NULL) {
		radlog(L_ERR, "Socket not connected");
		return -1;
	}
	if (!(mysql_sock->result = mysql_store_result(mysql_sock->sock))) {
		radlog(L_ERR, "MYSQL Error: Cannot get result");
		radlog(L_ERR, "MYSQL Error: %s", mysql_error(mysql_sock->sock));
		return -1;
	}
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
int sql_num_fields(SQLSOCK * sqlsocket, SQL_CONFIG *config) {


	int     num = 0;
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

#if MYSQL_VERSION_ID >= 32224
	if (!(num = mysql_field_count(mysql_sock->sock))) {
#else
	if (!(num = mysql_num_fields(mysql_sock->sock))) {
#endif
		radlog(L_ERR, "MYSQL Error: Cannot get result");
		radlog(L_ERR, "MYSQL error: %s", mysql_error(mysql_sock->sock));
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
int sql_num_rows(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	return mysql_num_rows(mysql_sock->result);
}


/*************************************************************************
 *
 *	Function: sql_fetch_row
 *
 *	Purpose: database specific fetch_row. Returns a SQL_ROW struct
 *               with all the data for the query
 *
 *************************************************************************/
SQL_ROW sql_fetch_row(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	return mysql_fetch_row(mysql_sock->result);
}



/*************************************************************************
 *
 *	Function: sql_free_result
 *
 *	Purpose: database specific free_result. Frees memory allocated
 *               for a result set
 *
 *************************************************************************/
int sql_free_result(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	if (mysql_sock->result) {
		mysql_free_result(mysql_sock->result);
	}

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
char *sql_error(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	return mysql_error(mysql_sock->sock);
}


/*************************************************************************
 *
 *	Function: sql_close
 *
 *	Purpose: database specific close. Closes an open database
 *               connection
 *
 *************************************************************************/
int sql_close(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	mysql_close(mysql_sock->sock);
	mysql_sock->sock = NULL;

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
int sql_finish_query(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	return 0;
}



/*************************************************************************
 *
 *	Function: sql_finish_select_query
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
int sql_finish_select_query(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	sql_free_result(sqlsocket, config);

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
int sql_affected_rows(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	return mysql_affected_rows(mysql_sock->sock);
}


/*************************************************************************
 *
 *      Function: sql_escape_string
 *
 *      Purpose: Esacpe "'" and any other wierd charactors
 *
 *************************************************************************
 * Unused.  Now provided in rlm_sql main module.
 * But left in here just in case...
 *
int sql_escape_string(SQLSOCK * sqlsocket, SQL_CONFIG *config, char *to, char *from, int length) {

	mysql_escape_string(to, from, length);
	return 0;
}
*/


/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_mysql = {
	"rlm_sql_mysql",
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
