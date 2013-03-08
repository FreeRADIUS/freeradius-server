/*
 *  sql_freetds.c
 *  freeradius
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License version 2 only, as published by
 *   the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License version 2
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2009 Gabriel Blanchard gabe@teksavvy.com
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <sybdb.h>
#include <sybfront.h>

#include <sys/time.h>
#include <sys/stat.h>

#include "rlm_sql.h"
static int query_timeout_handler(void *dbproc);
static int err_handler(UNUSED DBPROCESS *dbproc, UNUSED int severity, UNUSED int dberr, UNUSED int oserr, char *dberrstr, char *oserrstr);

// As defined in tds.h
#define TDS_INT_CONTINUE 1
#define TDS_INT_CANCEL 2
#define TDS_INT_TIMEOUT 3

typedef struct rlm_sql_freetds_conn {
	DBPROCESS *dbproc;
} rlm_sql_freetds_conn_t;

/*
 * FreeTDS calls this handler when dbsqlexec() or dbsqlok() blocks every seconds
 * This ensures that FreeTDS doesn't stay stuck on the same query for ever.
 */
static int query_timeout_handler(UNUSED void *dbproc) {
	return TDS_INT_CONTINUE;
}

static int err_handler(UNUSED DBPROCESS *dbproc, UNUSED int severity, UNUSED int dberr, UNUSED int oserr, char *dberrstr, char *oserrstr)
{	
		radlog(L_ERR, "rlm_sql_freetds: FreeTDS error: %s\n", dberrstr);
		radlog(L_ERR, "rlm_sql_freetds: OS error: %s\n", oserrstr);
		return 0;
}

static int sql_socket_destructor(void *c)
{
	rlm_sql_freetds_conn_t *conn = c;
	
	DEBUG2("rlm_sql_freetds: Socket destructor called, closing socket");
	
	if (conn->dbproc){
		dbclose(conn->dbproc);
	}
	
	return 0;
}


/*************************************************************************
 *
 *	Function: sql_create_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
static int sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	LOGINREC *login;
	rlm_sql_freetds_conn_t *conn;
	
	if (dbinit() == FAIL) {
		radlog(L_ERR, "rlm_sql_freetds: Unable to init FreeTDS");
		return -1;		
	}
	
	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_freetds_conn_t));
	talloc_set_destructor((void *) conn, sql_socket_destructor);
	
	dbsetversion(DBVERSION_80);
	dberrhandle(err_handler);
	
	// Timeout so that FreeTDS doesn't wait for ever.
	dbsetlogintime((unsigned long)config->query_timeout);
	dbsettime((unsigned long)config->query_timeout);
	
	DEBUG("rlm_sql_freetds (%s): Starting connect to FreeTDS/MSSQL server", config->xlat_name);
	
	if (!(login = dblogin())) {
		radlog(L_ERR, "rlm_sql_freetds (%s): Unable to allocate login record", config->xlat_name);
		return -1;
	}
	
	DBSETLUSER(login, config->sql_login);
	DBSETLPWD(login, config->sql_password);
	
	if ((conn->dbproc = dbopen(login, config->sql_server)) == FAIL) {
		radlog(L_ERR, "rlm_sql_freetds (%s): Unable to connect to FreeTDS/MSSQL server %s@%s", 
			   config->xlat_name, config->sql_login, config->sql_server);
		dbloginfree(login);
		return -1;
	}
	
	dbloginfree(login);
	
	if ((dbuse(conn->dbproc, config->sql_db)) == FAIL) {
		radlog(L_ERR, "rlm_sql_freetds (%s): Unable to select database on FreeTDS/MSSQL server %s@%s:%s", 
			   config->xlat_name, config->sql_login, config->sql_server, config->sql_db);
		return -1;
	}
	
	/* I know this may look strange, but it sets a pointer to
	 the conn struct so that it can be used within the
	 query_timeout_handler function to be able to timeout properly */
	dbsetinterrupt(conn->dbproc, query_timeout_handler, query_timeout_handler);
	dbsetuserdata(conn->dbproc, (BYTE *)conn);
	
	return 0;
}

/*************************************************************************
 *
 *	Function: sql_query
 *
 *	Purpose: Issue a query to the database
 *
 *************************************************************************/
static int sql_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char *querystr)
{
	rlm_sql_freetds_conn_t *conn = handle->conn;
	
	if (conn->dbproc == NULL || DBDEAD(conn->dbproc)) {
		radlog(L_ERR, "rlm_sql_freetds (%s): Socket not connected", config->xlat_name);
		return SQL_DOWN;
	}
	
	if ((dbcmd(conn->dbproc, querystr)) == FAIL) {
		radlog(L_ERR, "rlm_sql_freetds (%s): Unable to allocate SQL query", config->xlat_name);
		return -1;
	}
	
	if ((dbsqlexec(conn->dbproc)) == FAIL) {
		radlog(L_ERR, "rlm_sql_freetds (%s): SQL query failed", config->xlat_name);
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
static int sql_select_query(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config, UNUSED char *querystr)
{	
	radlog(L_ERR, "rlm_sql_freetds sql_select_query(): unsupported");
	return -1;
}


/*************************************************************************
 *
 *	Function: sql_store_result
 *
 *	Purpose: database specific store_result function. Returns a result
 *               set for the query.
 *
 *************************************************************************/
static int sql_store_result(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	radlog(L_ERR, "rlm_sql_freetds sql_store_result(): unsupported");
	return -1;
}


/*************************************************************************
 *
 *	Function: sql_num_fields
 *
 *	Purpose: database specific num_fields function. Returns number
 *               of columns from query
 *
 *************************************************************************/
static int sql_num_fields(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_freetds_conn_t *conn = handle->conn;
	
	return dbnumcols(conn->dbproc);
}


/*************************************************************************
 *
 *	Function: sql_num_rows
 *
 *	Purpose: database specific num_rows. Returns number of rows in
 *               query
 *
 *************************************************************************/
static int sql_num_rows(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	
	return 0;
}

/*************************************************************************
 *
 *	Function: sql_fetch_row
 *
 *	Purpose: database specific fetch_row. Returns a rlm_sql_row_t struct
 *               with all the data for the query in 'handle->row'. Returns
 *		 0 on success, -1 on failure, SQL_DOWN if database is down.
 *
 *************************************************************************/
static int sql_fetch_row(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
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
static int sql_free_result(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
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
static const char *sql_error(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	return NULL;
}

/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
static int sql_finish_query(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
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
static int sql_finish_select_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	return sql_finish_query(handle, config);
}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
static int sql_affected_rows(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_freetds_conn_t *conn = handle->conn;
	
	return dbcount(conn->dbproc);
}


/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_freetds = {
	"rlm_sql_freetds",
	NULL,
	sql_socket_init,
	sql_query,
	sql_select_query,
	sql_store_result,
	sql_num_fields,
	sql_num_rows,
	sql_fetch_row,
	sql_free_result,
	sql_error,
	sql_finish_query,
	sql_finish_select_query,
	sql_affected_rows
};
