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

typedef struct rlm_sql_freetds_sock {
	DBPROCESS *dbproc;
} rlm_sql_freetds_sock;

/*
 * FreeTDS calls this handler when dbsqlexec() or dbsqlok() blocks every seconds
 * This ensures that FreeTDS doesn't stay stuck on the same query for ever.
 */
static int query_timeout_handler(void *dbproc) {
	return TDS_INT_CONTINUE;
}

static int err_handler(UNUSED DBPROCESS *dbproc, UNUSED int severity, UNUSED int dberr, UNUSED int oserr, char *dberrstr, char *oserrstr)
{	
		radlog(L_ERR, "rlm_sql_freetds: FreeTDS error: %s\n", dberrstr);
		radlog(L_ERR, "rlm_sql_freetds: OS error: %s\n", oserrstr);
}
	
/*************************************************************************
 *
 *	Function: sql_create_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
static int sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config)
{
	LOGINREC *login;
	rlm_sql_freetds_sock *freetds_sock;
	
	if (!sqlsocket->conn) {
		sqlsocket->conn = (rlm_sql_freetds_sock *)rad_malloc(sizeof(struct rlm_sql_freetds_sock));
		if (!sqlsocket->conn) {
			return -1;
		}
	}
	
	if (dbinit() == FAIL) {
		radlog(L_ERR, "rlm_sql_freetds: Unable to init FreeTDS");
		return -1;		
	}
	
	dbsetversion(DBVERSION_80);
	dberrhandle(err_handler);
	
	// Timeout so that FreeTDS doesn't wait for ever.
	dbsetlogintime((unsigned long)config->query_timeout);
	dbsettime((unsigned long)config->query_timeout);
	
	freetds_sock = sqlsocket->conn;
	memset(freetds_sock, 0, sizeof(*freetds_sock));
	
	radlog(L_INFO, "rlm_sql_freetds (%s): Starting connect to FreeTDS/MSSQL server", config->xlat_name);
	
	if (!(login = dblogin())) {
		radlog(L_ERR, "rlm_sql_freetds (%s): Unable to allocate login record", config->xlat_name);
		return -1;
	}
	
	DBSETLUSER(login, config->sql_login);
	DBSETLPWD(login, config->sql_password);
	
	if ((freetds_sock->dbproc = dbopen(login, config->sql_server)) == FAIL) {
		radlog(L_ERR, "rlm_sql_freetds (%s): Unable to connect to FreeTDS/MSSQL server %s@%s", 
			   config->xlat_name, config->sql_login, config->sql_server);
		dbloginfree(login);
		return -1;
	}
	
	dbloginfree(login);
	
	if ((dbuse(freetds_sock->dbproc, config->sql_db)) == FAIL) {
		radlog(L_ERR, "rlm_sql_freetds (%s): Unable to select database on FreeTDS/MSSQL server %s@%s:%s", 
			   config->xlat_name, config->sql_login, config->sql_server, config->sql_db);
		return -1;
	}
	
	/* I know this may look strange, but it sets a pointer to
	 the freetds_sock struct so that it can be used within the
	 query_timeout_handler function to be able to timeout properly */
	dbsetinterrupt(freetds_sock->dbproc, query_timeout_handler, query_timeout_handler);
	dbsetuserdata(freetds_sock->dbproc, (BYTE *)freetds_sock);
	
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
 *	Function: sql_query
 *
 *	Purpose: Issue a query to the database
 *
 *************************************************************************/
static int sql_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr)
{
	rlm_sql_freetds_sock *freetds_sock = sqlsocket->conn;
	
	if (config->sqltrace)
		radlog(L_DBG,"rlm_sql_freetds: query:  %s", querystr);
	
	if (freetds_sock->dbproc == NULL || DBDEAD(freetds_sock->dbproc)) {
		radlog(L_ERR, "rlm_sql_freetds (%s): Socket not connected", config->xlat_name);
		return SQL_DOWN;
	}
	
	if ((dbcmd(freetds_sock->dbproc, querystr)) == FAIL) {
		radlog(L_ERR, "rlm_sql_freetds (%s): Unable to allocate SQL query", config->xlat_name);
		return -1;
	}
	
	if ((dbsqlexec(freetds_sock->dbproc)) == FAIL) {
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
static int sql_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr)
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
static int sql_store_result(UNUSED SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config)
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
static int sql_num_fields(SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config)
{
	rlm_sql_freetds_sock *freetds_sock = sqlsocket->conn;
	
	return dbnumcols(freetds_sock->dbproc);
}


/*************************************************************************
 *
 *	Function: sql_num_rows
 *
 *	Purpose: database specific num_rows. Returns number of rows in
 *               query
 *
 *************************************************************************/
static int sql_num_rows(UNUSED SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config)
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
static int sql_fetch_row(UNUSED SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config)
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
static int sql_free_result(UNUSED SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config)
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
static const char *sql_error(UNUSED SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config)
{
	return NULL;
}


/*************************************************************************
 *
 *	Function: sql_close
 *
 *	Purpose: database specific close. Closes an open database
 *               connection
 *
 *************************************************************************/
static int sql_close(SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config)
{
	rlm_sql_freetds_sock *freetds_sock = sqlsocket->conn;
	
	if (freetds_sock && freetds_sock->dbproc){
		dbclose(freetds_sock->dbproc);
		freetds_sock->dbproc = NULL;
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
static int sql_finish_query(UNUSED SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config)
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
static int sql_finish_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config)
{
	return sql_finish_query(sqlsocket, config);
}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
static int sql_affected_rows(SQLSOCK *sqlsocket, UNUSED SQL_CONFIG *config)
{
	rlm_sql_freetds_sock *freetds_sock = sqlsocket->conn;
	
	return dbcount(freetds_sock->dbproc);
}


/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_freetds = {
	"rlm_sql_freetds",
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
