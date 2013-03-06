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

typedef struct rlm_sql_conn {
	sqlite3 *db;
	sqlite3_stmt *statement;
	int col_count;
} rlm_sql_conn;


static int sql_check_error(sqlite3 *db)
{
	int error = sqlite3_errcode(db);
	/*
	 *	Only check the first byte of error code, extended
	 *	result codes occupy the second byte.
	 */
	switch(error) {
	/*
	 *	Not errors
	 */
	case SQLITE_OK:
	case SQLITE_DONE:
	case SQLITE_ROW:
		return 0;
	/*
	 *	User/transient errors
	 */
	case SQLITE_FULL:
	case SQLITE_CONSTRAINT:
	case SQLITE_MISMATCH:
		radlog(L_ERR, "rlm_sql_sqlite: SQLite error (%d): %s", error,
		       sqlite3_errmsg(db));
		
		return -1;
		break;
		
	/*
	 *	Errors with the handle, that probably require reinitialisation
	 */
	default:
		radlog(L_ERR, "rlm_sql_sqlite: Handle is unusable, SQLite "
		       "error  (%d): %s", error, sqlite3_errmsg(db));
		return SQL_DOWN;
		break;
	}
}

/*************************************************************************
 *
 *	Function: sql_create_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
static int sql_init_socket(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_conn *conn;
	int status;
	const char *filename;
	char buffer[2048];

	if (!conn) {
		MEM(handle->conn = talloc_zero(NULL, rlm_sql_conn));
	}
	
	conn = handle->conn;
	
	filename = config->sql_file;
	if (!filename) {
		snprintf(buffer, sizeof(buffer), "%s/sqlite_radius_client_database",
			 radius_dir);
		filename = buffer;
	}
	
	DEBUG("rlm_sql_sqlite: Opening SQLite database %s", filename);
	
	status = sqlite3_open(filename, &(conn->db));
	if (status != SQLITE_OK) {
		return sql_check_error(conn->db);
	}
	
	/*
	 *	Enable extended return codes for extra debugging info.
	 */
	status = sqlite3_extended_result_codes(conn->db, 1);
	
	return sql_check_error(conn->db);
}


/*************************************************************************
 *
 *	Function: sql_destroy_socket
 *
 *	Purpose: Free socket and any private connection data
 *
 *************************************************************************/
static int sql_destroy_socket(rlm_sql_handle_t *handle,
			      UNUSED rlm_sql_config_t *config)
{
	if (!handle->conn) {
		return 0;
	}

	TALLOC_FREE(handle->conn);
	
	return 0;
}


/*************************************************************************
 *
 *	Function: sql_query
 *
 *	Purpose: Prepare a query for execution.
 *
 *************************************************************************/
static int sql_query(rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t *config,
		     char *querystr)
{
	int status;
	rlm_sql_conn *conn = handle->conn;
	const char *z_tail;
	
	status = sqlite3_prepare_v2(conn->db, querystr,
				    strlen(querystr), &conn->statement,
				    &z_tail);
				 
	if (status != SQLITE_OK) {
		conn->col_count = 0;
	}
		
	return sql_check_error(conn->db);
}

/*************************************************************************
 *
 *	Function: sql_store_result
 *
 *	Purpose: database specific store_result function. Returns a result
 *               set for the query.
 *
 *************************************************************************/
static int sql_store_result(UNUSED rlm_sql_handle_t * handle,
			    UNUSED rlm_sql_config_t *config)
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
static int sql_num_fields(rlm_sql_handle_t * handle,
			  UNUSED rlm_sql_config_t *config)
{
	rlm_sql_conn *conn = handle->conn;
	
	if (conn->statement) {
		return sqlite3_column_count(conn->statement);
	}
	
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
static int sql_num_rows(rlm_sql_handle_t * handle,
			UNUSED rlm_sql_config_t *config)
{
	rlm_sql_conn *conn = handle->conn;
	
	if (conn->statement) {
		return sqlite3_data_count(conn->statement);
	}
	
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
static int sql_fetch_row(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	int status;
	rlm_sql_conn *conn = handle->conn;
	
	int i = 0;
	
	char **row;

	/*
	 *	Executes the SQLite query and interates over the results
	 */
	status = sqlite3_step(conn->statement);
	
	/*
	 *	Error getting next row
	 */
	if (sql_check_error(conn->db)) {
		return -1;
	}

	/*
	 *	No more rows to process (were done)
	 */
	if (status == SQLITE_DONE) {
		return 1;
	}
	
	/*
	 *	We only need to do this once per result set, because
	 *	the number of columns won't change.
	 */
	if (conn->col_count == 0) {
		conn->col_count = sql_num_fields(handle, config);
		if (conn->col_count == 0) {
			return -1;
		}
	}

	/*
	 *	Free the previous result (also gets called on finish_query)
	 */
	if (handle->row) {
		talloc_free(handle->row);	
	}
	
	MEM(row = handle->row = talloc_zero_array(handle->conn, char *,
					    	  conn->col_count + 1));
	
	for (i = 0; i < conn->col_count; i++)
	{
		switch (sqlite3_column_type(conn->statement, i))
		{
		case SQLITE_INTEGER:	   
			row[i] = talloc_asprintf(row, "%d",
						 sqlite3_column_int(conn->statement, i));
			break;
			
		case SQLITE_FLOAT:
			row[i] = talloc_asprintf(row, "%f",
						 sqlite3_column_double(conn->statement, i));
			break;
			
		case SQLITE_TEXT:
			{
				const char *p;
				p = (const char *) sqlite3_column_text(conn->statement, i);
				
				if (p) {
					row[i] = talloc_strdup(row, p);
				}
			}
			break;
			
		case SQLITE_BLOB:
			{
				const uint8_t *p;
				size_t len;

				p = sqlite3_column_blob(conn->statement, i);
				if (p) {
					len = sqlite3_column_bytes(conn->statement, i);
					
					MEM(row[i] = talloc_zero_array(row, char, len + 1));
					memcpy(row[i], p, len);		          
				}
			}
			break;
			
		default:
			break;
		}
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
static int sql_free_result(rlm_sql_handle_t *handle,
			   UNUSED rlm_sql_config_t *config)
{
	rlm_sql_conn *conn = handle->conn;
	
	if (conn->statement) {
		TALLOC_FREE(handle->row);
		
		(void) sqlite3_finalize(conn->statement);
		conn->statement = NULL;
		conn->col_count = 0;
	}
	
	/*
	 *	There's no point in checking the code returned by finalize
	 *	as it'll have already been encountered elsewhere in the code.
	 *
	 *	It's just the last error that occurred processing the
	 *	statement.
	 */
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
static const char *sql_error(rlm_sql_handle_t *handle,
			     UNUSED rlm_sql_config_t *config)
{
	rlm_sql_conn *conn = handle->conn;

	if (conn->db) {
		return sqlite3_errmsg(conn->db);
	}

	return "Invalid handle";
}


/*************************************************************************
 *
 *	Function: sql_close
 *
 *	Purpose: database specific close. Closes an open database
 *               connection
 *
 *************************************************************************/
static int sql_close(rlm_sql_handle_t *handle,
		     UNUSED rlm_sql_config_t *config)
{
	int status = 0;
	rlm_sql_conn *conn = handle->conn;
	
	if (conn && conn->db) {
		status = sqlite3_close(conn->db);
		conn->db = NULL;
	}
	
	return sql_check_error(conn->db);
}


/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
static int sql_finish_query(rlm_sql_handle_t *handle,
			    UNUSED rlm_sql_config_t *config)
{
	return sql_free_result(handle, config);
}

/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: Requests the number of rows affected by the last executed 
 *		 statement 
 *
 *************************************************************************/
static int sql_affected_rows(rlm_sql_handle_t *handle,
			     UNUSED rlm_sql_config_t *config)
{
	rlm_sql_conn *conn = handle->conn;
  
	if (conn->db) {
		return sqlite3_changes(conn->db);	
	}  

	return -1;
}


/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_sqlite = {
	"rlm_sql_sqlite",
	sql_instantiate,
	sql_init_socket,
	sql_destroy_socket,
	sql_query,
	sql_query,
	sql_store_result,
	sql_num_fields,
	sql_num_rows,
	sql_fetch_row,
	sql_free_result,
	sql_error,
	sql_close,
	sql_finish_query,
	sql_finish_query,
	sql_affected_rows
};
