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

#include <mysql/errmsg.h>

#include 	"radiusd.h"

#include	<mysql/mysql.h>
#include	"rlm_sql.h"

typedef struct rlm_sql_mysql_sock {
	MYSQL conn;
	MYSQL *sock;
	MYSQL_RES *result;
	SQL_ROW row;
} rlm_sql_mysql_sock;

/*************************************************************************
 *
 *	Function: sql_create_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
static int sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config)
{
	rlm_sql_mysql_sock *mysql_sock;

	sqlsocket->conn = (rlm_sql_mysql_sock *)rad_malloc(sizeof(rlm_sql_mysql_sock));

	mysql_sock = sqlsocket->conn;
	memset(mysql_sock, 0, sizeof(*mysql_sock));

	radlog(L_INFO, "rlm_sql_mysql: Starting connect to MySQL server for #%d",
			sqlsocket->id);

	mysql_init(&(mysql_sock->conn));
	if (!(mysql_sock->sock = mysql_real_connect(&(mysql_sock->conn),
						    config->sql_server,
						    config->sql_login,
						    config->sql_password,
						    config->sql_db,
						    atoi(config->sql_port),
						    NULL,
						    CLIENT_FOUND_ROWS))) {
		radlog(L_ERR, "rlm_sql_mysql: Couldn't connect socket to MySQL server %s@%s:%s", config->sql_login, config->sql_server, config->sql_db);
		radlog(L_ERR, "rlm_sql_mysql: Mysql error '%s'", mysql_error(&mysql_sock->conn));
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
static int sql_destroy_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config)
{
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	free(mysql_sock);
	free(sqlsocket);

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_check_error
 *
 *	Purpose: check the error to see if the server is down
 *
 *************************************************************************/
static int sql_check_error(int error)
{
	switch(error) {
	case CR_SERVER_GONE_ERROR:
	case CR_SERVER_LOST:
	case -1:
		radlog(L_DBG, "rlm_sql_mysql: MYSQL check_error: %d, returning SQL_DOWN", error);
		return SQL_DOWN;
		break;
	case 0:
		return 0;
		break;
	case CR_OUT_OF_MEMORY:
	case CR_COMMANDS_OUT_OF_SYNC:
	case CR_UNKNOWN_ERROR:
	default:
		radlog(L_DBG, "rlm_sql_mysql: MYSQL check_error: %d received", error);
		return -1;
		break;
	}
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
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	if (config->sqltrace)
		radlog(L_DBG,"rlm_sql_mysql: query:  %s", querystr);
	if (mysql_sock->sock == NULL) {
		radlog(L_ERR, "rlm_sql_mysql: Socket not connected");
		return SQL_DOWN;
	}

	mysql_query(mysql_sock->sock, querystr);
	return sql_check_error(mysql_errno(mysql_sock->sock));
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
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	if (mysql_sock->sock == NULL) {
		radlog(L_ERR, "rlm_sql_mysql: Socket not connected");
		return SQL_DOWN;
	}
	if (!(mysql_sock->result = mysql_store_result(mysql_sock->sock))) {
		radlog(L_ERR, "rlm_sql_mysql: MYSQL Error: Cannot get result");
		radlog(L_ERR, "rlm_sql_mysql: MYSQL Error: %s",
		       mysql_error(mysql_sock->sock));
		return sql_check_error(mysql_errno(mysql_sock->sock));
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
static int sql_num_fields(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	int     num = 0;
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

#if MYSQL_VERSION_ID >= 32224
	if (!(num = mysql_field_count(mysql_sock->sock))) {
#else
	if (!(num = mysql_num_fields(mysql_sock->sock))) {
#endif
		radlog(L_ERR, "rlm_sql_mysql: MYSQL Error: No Fields");
		radlog(L_ERR, "rlm_sql_mysql: MYSQL error: %s",
		       mysql_error(mysql_sock->sock));
	}
	return num;
}


/*************************************************************************
 *
 *	Function: sql_select_query
 *
 *	Purpose: Issue a select query to the database
 *
 *************************************************************************/
static int sql_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config,
			    char *querystr)
{
	int ret;

	ret = sql_query(sqlsocket, config, querystr);
	if(ret)
		return ret;
	ret = sql_store_result(sqlsocket, config);
	if (ret) {
		return ret;
	}

	/* Why? Per http://www.mysql.com/doc/n/o/node_591.html,
	 * this cannot return an error.  Perhaps just to complain if no
	 * fields are found?
	 */
	sql_num_fields(sqlsocket, config);

	return ret;
}


/*************************************************************************
 *
 *	Function: sql_num_rows
 *
 *	Purpose: database specific num_rows. Returns number of rows in
 *               query
 *
 *************************************************************************/
static int sql_num_rows(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	if (mysql_sock->result)
		return mysql_num_rows(mysql_sock->result);

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_fetch_row
 *
 *	Purpose: database specific fetch_row. Returns a SQL_ROW struct
 *               with all the data for the query in 'sqlsocket->row'. Returns
 *		 0 on success, -1 on failure, SQL_DOWN if database is down.
 *
 *************************************************************************/
static int sql_fetch_row(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	sqlsocket->row = mysql_fetch_row(mysql_sock->result);

	if (sqlsocket->row == NULL) {
		return sql_check_error(mysql_errno(mysql_sock->sock));
	}
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
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	if (mysql_sock->result) {
		mysql_free_result(mysql_sock->result);
		mysql_sock->result = NULL;
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
static char *sql_error(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	if (mysql_sock == NULL || mysql_sock->sock == NULL) {
		return "rlm_sql_mysql: no connection to db";
	}
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
static int sql_close(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	if (mysql_sock && mysql_sock->sock){
		mysql_close(mysql_sock->sock);
		mysql_sock->sock = NULL;
	}

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
static int sql_affected_rows(SQLSOCK * sqlsocket, SQL_CONFIG *config)
{
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

	return mysql_affected_rows(mysql_sock->sock);
}


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
