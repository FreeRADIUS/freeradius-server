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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000-2007  The FreeRADIUS server project
 * Copyright 2000  Mike Machado <mike@innercite.com>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <sys/stat.h>

#include "config.h"

#ifdef HAVE_MYSQL_MYSQL_H
#include <mysql/mysql_version.h>
#include <mysql/errmsg.h>
#include <mysql/mysql.h>
#else
#ifdef HAVE_MYSQL_H
#include <mysql_version.h>
#include <errmsg.h>
#include <mysql.h>
#endif
#endif

#include	"rlm_sql.h"

typedef struct rlm_sql_mysql_sock {
	MYSQL conn;
	MYSQL *sock;
	MYSQL_RES *result;
	SQL_ROW row;
} rlm_sql_mysql_sock;

/* Prototypes */
static int sql_free_result(SQLSOCK*, SQL_CONFIG*);

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
	unsigned long sql_flags;

	if (!sqlsocket->conn) {
		sqlsocket->conn = (rlm_sql_mysql_sock *)rad_malloc(sizeof(rlm_sql_mysql_sock));
		if (!sqlsocket->conn) {
			return -1;
		}
	}
	mysql_sock = sqlsocket->conn;
	memset(mysql_sock, 0, sizeof(*mysql_sock));

	radlog(L_INFO, "rlm_sql_mysql: Starting connect to MySQL server");

	mysql_init(&(mysql_sock->conn));
	mysql_options(&(mysql_sock->conn), MYSQL_READ_DEFAULT_GROUP, "freeradius");

#if (MYSQL_VERSION_ID >= 50000)
	if (config->query_timeout) {
		unsigned int timeout = config->query_timeout;

		/*
		 *	3 retries are hard-coded into the MySQL library.
		 *	We ensure that the REAL timeout is what the user
		 *	set by accounting for that.
		 */
		if (timeout > 3) timeout /= 3;

		mysql_options(&(mysql_sock->conn), MYSQL_OPT_CONNECT_TIMEOUT,
			      &timeout);
		mysql_options(&(mysql_sock->conn), MYSQL_OPT_READ_TIMEOUT,
			      &timeout);
		mysql_options(&(mysql_sock->conn), MYSQL_OPT_WRITE_TIMEOUT,
			      &timeout);
	}
#endif

#if (MYSQL_VERSION_ID >= 40100)
	sql_flags = CLIENT_MULTI_RESULTS | CLIENT_FOUND_ROWS;
#else
	sql_flags = CLIENT_FOUND_ROWS;
#endif

#ifdef CLIENT_MULTI_STATEMENTS
	sql_flags |= CLIENT_MULTI_STATEMENTS;
#endif
	if (!(mysql_sock->sock = mysql_real_connect(&(mysql_sock->conn),
						    config->sql_server,
						    config->sql_login,
						    config->sql_password,
						    config->sql_db,
						    atoi(config->sql_port),
						    NULL,
						    sql_flags))) {
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
static int sql_destroy_socket(SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config)
{
	free(sqlsocket->conn);
	sqlsocket->conn = NULL;

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
static int sql_query(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config,
		     char *querystr)
{
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;

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
 *               set for the query. In case of multiple results, get the
 *               first non-empty one.
 *
 *************************************************************************/
static int sql_store_result(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;
	int status;

	if (mysql_sock->sock == NULL) {
		radlog(L_ERR, "rlm_sql_mysql: Socket not connected");
		return SQL_DOWN;
	}
retry_store_result:
	if (!(mysql_sock->result = mysql_store_result(mysql_sock->sock))) {
		status = sql_check_error(mysql_errno(mysql_sock->sock));
		if (status != 0) {
			radlog(L_ERR, "rlm_sql_mysql: Cannot store result");
			radlog(L_ERR, "rlm_sql_mysql: MySQL error '%s'",
			       mysql_error(mysql_sock->sock));
			return status;
		}
#if (MYSQL_VERSION_ID >= 40100)
		status = mysql_next_result(mysql_sock->sock);
		if (status == 0) {
			/* there are more results */
			goto retry_store_result;
		} else if (status > 0) {
			radlog(L_ERR, "rlm_sql_mysql: Cannot get next result");
			radlog(L_ERR, "rlm_sql_mysql: MySQL error '%s'",
			       mysql_error(mysql_sock->sock));
			return sql_check_error(status);
		}
#endif
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
static int sql_num_fields(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
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
static int sql_num_rows(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
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
static int sql_fetch_row(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;
	int status;

	/*
	 *  Check pointer before de-referencing it.
	 */
	if (!mysql_sock->result) {
		return SQL_DOWN;
	}

retry_fetch_row:
	sqlsocket->row = mysql_fetch_row(mysql_sock->result);

	if (sqlsocket->row == NULL) {
		status = sql_check_error(mysql_errno(mysql_sock->sock));
		if (status != 0) {
			radlog(L_ERR, "rlm_sql_mysql: Cannot fetch row");
			radlog(L_ERR, "rlm_sql_mysql: MySQL error '%s'",
			       mysql_error(mysql_sock->sock));
			return status;
		}
#if (MYSQL_VERSION_ID >= 40100)
		sql_free_result(sqlsocket, config);
		status = mysql_next_result(mysql_sock->sock);
		if (status == 0) {
			/* there are more results */
			if ((sql_store_result(sqlsocket, config) == 0)
			 && (mysql_sock->result != NULL))
				goto retry_fetch_row;
		} else if (status > 0) {
			radlog(L_ERR, "rlm_sql_mysql: Cannot get next result");
			radlog(L_ERR, "rlm_sql_mysql: MySQL error '%s'",
			       mysql_error(mysql_sock->sock));
			return sql_check_error(status);
		}
#endif
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
static int sql_free_result(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
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
static const char *sql_error(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
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
static int sql_close(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
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
 *	Purpose: As a single SQL statement may return multiple results
 *	sets, (for example stored procedures) it is necessary to check
 *	whether more results exist and process them in turn if so.
 *
 *************************************************************************/
static int sql_finish_query(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
#if (MYSQL_VERSION_ID >= 40100)
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;
	int status;

skip_next_result:
	status = sql_store_result(sqlsocket, config);
	if (status != 0) {
		return status;
	} else if (mysql_sock->result != NULL) {
		radlog(L_DBG, "rlm_sql_mysql: SQL statement returned unexpected result");
		sql_free_result(sqlsocket, config);
	}
	status = mysql_next_result(mysql_sock->sock);
	if (status == 0) {
		/* there are more results */
		goto skip_next_result;
	}  else if (status > 0) {
		radlog(L_ERR, "rlm_sql_mysql: Cannot get next result");
		radlog(L_ERR, "rlm_sql_mysql: MySQL error '%s'",
		       mysql_error(mysql_sock->sock));
		return sql_check_error(status);
	}
#endif
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
#if (MYSQL_VERSION_ID >= 40100)
	int status;
	rlm_sql_mysql_sock *mysql_sock = sqlsocket->conn;
#endif
	sql_free_result(sqlsocket, config);
#if (MYSQL_VERSION_ID >= 40100)
	status = mysql_next_result(mysql_sock->sock);
	if (status == 0) {
		/* there are more results */
		sql_finish_query(sqlsocket, config);
	}  else if (status > 0) {
		radlog(L_ERR, "rlm_sql_mysql: Cannot get next result");
		radlog(L_ERR, "rlm_sql_mysql: MySQL error '%s'",
		       mysql_error(mysql_sock->sock));
		return sql_check_error(status);
	}
#endif
	return 0;
}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
static int sql_affected_rows(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
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
