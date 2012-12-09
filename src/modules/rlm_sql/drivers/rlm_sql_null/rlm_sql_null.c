/*
 * sql_null.c		SQL Module
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
 * Copyright 2012  Alan DeKok <aland@freeradius.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include	"rlm_sql.h"


/* Prototypes */
static int sql_free_result(SQLSOCK*, SQL_CONFIG*);

static const void *fake = "fake";

/*************************************************************************
 *
 *	Function: sql_create_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
static int sql_init_socket(SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config)
{
	memcpy(&sqlsocket->conn, &fake, sizeof(sqlsocket->conn));
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
static int sql_query(UNUSED SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config, UNUSED char *querystr)
{
	return 0;
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
static int sql_store_result(UNUSED SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
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
static int sql_num_fields(UNUSED SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
	return 0;
}


/*************************************************************************
 *
 *	Function: sql_select_query
 *
 *	Purpose: Issue a select query to the database
 *
 *************************************************************************/
static int sql_select_query(UNUSED SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config,
			    UNUSED char *querystr)
{
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
static int sql_num_rows(UNUSED SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
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
static int sql_fetch_row(UNUSED SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
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
static int sql_free_result(UNUSED SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
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
static const char *sql_error(UNUSED SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
	return "Unknown error";
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
	sqlsocket->conn = NULL;
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
static int sql_finish_query(UNUSED SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
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
static int sql_finish_select_query(UNUSED SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
	return 0;
}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
static int sql_affected_rows(UNUSED SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
	return 1;
}


/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_null = {
	"rlm_sql_null",
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
