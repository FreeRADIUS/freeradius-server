/*
 *  sql_sqlite.c
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
 * Copyright 2007 Apple Inc.
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <sys/stat.h>

#include <sqlite3.h>

#include "rlm_sql.h"

typedef struct rlm_sql_sqlite_sock {
	sqlite3 *pDb;
	sqlite3_stmt *pStmt;
	int columnCount;
} rlm_sql_sqlite_sock;


/*************************************************************************
 *
 *	Function: sql_create_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
static int sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config)
{
	int status;
	rlm_sql_sqlite_sock *sqlite_sock;
	char *filename;
	char buffer[2048];
	
	if (!sqlsocket->conn) {
		sqlsocket->conn = (rlm_sql_sqlite_sock *)rad_malloc(sizeof(rlm_sql_sqlite_sock));
		if (!sqlsocket->conn) {
			return -1;
		}
	}
	sqlite_sock = sqlsocket->conn;
	memset(sqlite_sock, 0, sizeof(rlm_sql_sqlite_sock));
	
	filename = config->sql_file;
	if (!filename) {
		snprintf(buffer, sizeof(buffer), "%s/sqlite_radius_client_database",
			 radius_dir);
		filename = buffer;
	}
	radlog(L_INFO, "rlm_sql_sqlite: Opening sqlite database %s for #%d",
	       filename, sqlsocket->id);
	
	status = sqlite3_open(filename, &sqlite_sock->pDb);
	radlog(L_INFO, "rlm_sql_sqlite: sqlite3_open() = %d\n", status);
	return (status != SQLITE_OK) * -1;
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
	int status = 0;
	rlm_sql_sqlite_sock *sqlite_sock = sqlsocket->conn;

	if (sqlite_sock && sqlite_sock->pDb) {
		status = sqlite3_close(sqlite_sock->pDb);
		radlog(L_INFO, "rlm_sql_sqlite: sqlite3_close() = %d\n", status);
	}
	else {
		radlog(L_INFO, "rlm_sql_sqlite: sql_destroy_socket noop.\n");
	}
	
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
	int status;
	rlm_sql_sqlite_sock *sqlite_sock = sqlsocket->conn;
	const char *zTail;
	
	if (config->sqltrace)
		radlog(L_DBG,"rlm_sql_sqlite: query:  %s", querystr);
	if (sqlite_sock->pDb == NULL) {
		radlog(L_ERR, "rlm_sql_sqlite: Socket not connected");
		return SQL_DOWN;
	}
	
	status = sqlite3_prepare(sqlite_sock->pDb, querystr, strlen(querystr), &sqlite_sock->pStmt, &zTail);
	radlog(L_DBG, "rlm_sql_sqlite: sqlite3_prepare() = %d\n", status);
	sqlite_sock->columnCount = 0;
	
	return (status == SQLITE_OK) ? 0 : SQL_DOWN;
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
static int sql_num_fields(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
	rlm_sql_sqlite_sock *sqlite_sock = sqlsocket->conn;
	
	if (sqlite_sock->pStmt)
		return sqlite3_column_count(sqlite_sock->pStmt);
	
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
static int sql_num_rows(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
	rlm_sql_sqlite_sock *sqlite_sock = sqlsocket->conn;
	
	if (sqlite_sock->pStmt)
		return sqlite3_data_count(sqlite_sock->pStmt);
	
	return 0;
}


/*************************************************************************
 *	Function: sql_free_rowdata
 *************************************************************************/
static void sql_free_rowdata(SQLSOCK * sqlsocket, int colcount)
{
	char **rowdata = sqlsocket->row;
	int colindex;
	
	if (rowdata != NULL) {
		for (colindex = 0; colindex < colcount; colindex++) {
			if (rowdata[colindex] != NULL) {
				free(rowdata[colindex]);
				rowdata[colindex] = NULL;
			}
		}
		free(sqlsocket->row);
		sqlsocket->row = NULL;
	}
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
	int returnCode = -1;
	rlm_sql_sqlite_sock *sqlite_sock = sqlsocket->conn;
	const char *blob;
	int blobLen;
	int status;
	int colindex = 0;
	int colcount = 0;
	int coltype = 0;
	int colintvalue = 0;
	int ret_blob_size = 0;
	char **rowdata = NULL;
	const unsigned char *textStr;
	char intStr[256];
	
	status = sqlite3_step(sqlite_sock->pStmt);
	radlog(L_DBG, "rlm_sql_sqlite: sqlite3_step = %d\n", status);
	if (status == SQLITE_DONE) {
		sql_free_rowdata(sqlsocket, sqlite_sock->columnCount);
		return 0;
	}
	else if (status == SQLITE_ROW) {
		if (sqlite_sock->columnCount == 0) {
			sqlite_sock->columnCount = sql_num_fields(sqlsocket, config);
		}
		colcount = sqlite_sock->columnCount;
		if (colcount == 0)
			return -1;
		
		sql_free_rowdata(sqlsocket, colcount);
		
		ret_blob_size = sizeof(char *) * (colcount+1);
		rowdata = (char **)rad_malloc(ret_blob_size);		/* Space for pointers */
		if (rowdata != NULL) {
			memset(rowdata, 0, ret_blob_size);				/* NULL-pad the pointers */
			sqlsocket->row = rowdata;
		}
		
		for (colindex = 0; colindex < colcount; colindex++)
		{
			coltype = sqlite3_column_type(sqlite_sock->pStmt, colindex);
			switch (coltype)
			{
				case SQLITE_INTEGER:
					colintvalue = sqlite3_column_int(sqlite_sock->pStmt, colindex);
					snprintf(intStr, sizeof(intStr), "%d", colintvalue);
					rowdata[colindex] = strdup(intStr);
					break;
					
				case SQLITE_TEXT:
					textStr = sqlite3_column_text(sqlite_sock->pStmt, colindex);
					if (textStr != NULL)
						rowdata[colindex] = strdup((const char *)textStr);
					break;
					
				case SQLITE_BLOB:
					blob = sqlite3_column_blob(sqlite_sock->pStmt, colindex);
					if (blob != NULL) {
						blobLen = sqlite3_column_bytes(sqlite_sock->pStmt, colindex);
						rowdata[colindex] = (char *)rad_malloc(blobLen + 1);
						if (rowdata[colindex] != NULL) {
							memcpy(rowdata[colindex], blob, blobLen);
						}
					}
					break;
					
				default:
					break;
			}
		}
		
		returnCode = 0;
	}
	
	return returnCode;
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
	int status = 0;
	rlm_sql_sqlite_sock *sqlite_sock = sqlsocket->conn;
	
	if (sqlite_sock->pStmt != NULL) {
		sql_free_rowdata(sqlsocket, sqlite_sock->columnCount);
		status = sqlite3_finalize(sqlite_sock->pStmt);
		sqlite_sock->pStmt = NULL;
		radlog(L_DBG, "rlm_sql_sqlite: sqlite3_finalize() = %d\n", status);
	}
	
	return status;
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
	rlm_sql_sqlite_sock *sqlite_sock = sqlsocket->conn;

	if (sqlite_sock->pDb != NULL) {
		return sqlite3_errmsg(sqlite_sock->pDb);
	}

	radlog(L_ERR, "rlm_sql_sqlite: Socket not connected");
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
static int sql_close(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
	int status = 0;
	rlm_sql_sqlite_sock *sqlite_sock = sqlsocket->conn;
	
	if (sqlite_sock && sqlite_sock->pDb) {
		status = sqlite3_close(sqlite_sock->pDb);
		sqlite_sock->pDb = NULL;
	}
	
	return status;
}


/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
static int sql_finish_query(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
	int status = 0;
	rlm_sql_sqlite_sock *sqlite_sock = sqlsocket->conn;

	if (sqlite_sock->pStmt) {
		status = sqlite3_finalize(sqlite_sock->pStmt);
		sqlite_sock->pStmt = NULL;
		radlog(L_DBG, "rlm_sql_sqlite: sqlite3_finalize() = %d\n", status);
	}
	
	return status;
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
 *	Purpose: Requests the number of rows affected by the last executed 
 *		 statement 
 *
 *************************************************************************/
static int sql_affected_rows(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
	int result = -1;

	rlm_sql_sqlite_sock *sqlite_sock = sqlsocket->conn;
  
	if (sqlite_sock->pDb != NULL) {
		result = sqlite3_changes(sqlite_sock->pDb);	
		DEBUG3("rlm_sql_sqlite: sql_affected_rows() = %i\n", result);
	}  

	return result;
}


/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_sqlite = {
	"rlm_sql_sqlite",
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
