/*
 * sql_oracle.c	Oracle (OCI) routines for rlm_sql
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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  David Kerry <davidk@snti.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <sys/stat.h>

#include <oci.h>
#include "rlm_sql.h"

typedef struct rlm_sql_oracle_conn_t {
	OCIEnv		*env;
	OCIError	*errHandle;
	OCISvcCtx	*ctx;
	OCIStmt		*queryHandle;
	sb2		*indicators;
	char		**results;
	int		id;
	int		in_use;
	struct timeval	tv;
} rlm_sql_oracle_conn_t;

#define	MAX_DATASTR_LEN	64


/*************************************************************************
 *
 *	Function: sql_error
 *
 *	Purpose: database specific error. Returns error associated with
 *               connection
 *
 *************************************************************************/
static const char *sql_error(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {

	static char	msgbuf[512];
	sb4		errcode = 0;
	rlm_sql_oracle_conn_t *conn = handle->conn;

	if (!conn) return "rlm_sql_oracle: no connection to db";

	memset((void *) msgbuf, (int)'\0', sizeof(msgbuf));

	OCIErrorGet((dvoid *) conn->errHandle, (ub4) 1, (text *) NULL,
		&errcode, msgbuf, (ub4) sizeof(msgbuf), (ub4) OCI_HTYPE_ERROR);
	if (errcode) {
		return msgbuf;
	}
	else {
		return NULL;
	}
}

/*************************************************************************
 *
 *	Function: sql_check_error
 *
 *	Purpose: check the error to see if the server is down
 *
 *************************************************************************/
static int sql_check_error(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {

	if (strstr(sql_error(handle, config), "ORA-03113") ||
			strstr(sql_error(handle, config), "ORA-03114")) {
		radlog(L_ERR,"rlm_sql_oracle: OCI_SERVER_NOT_CONNECTED");
		return SQL_DOWN;
	}
	else {
		radlog(L_ERR,"rlm_sql_oracle: OCI_SERVER_NORMAL");
		return -1;
	}
}

static int sql_socket_destructor(void *c)
{
	rlm_sql_oracle_conn_t *conn = c;
	
	DEBUG2("rlm_sql_mysql: Socket destructor called, closing socket");
	
	if (conn->ctx) {
		OCILogoff (conn->ctx, conn->errHandle);
	}

	if (conn->queryHandle) {
		OCIHandleFree((dvoid *)conn->queryHandle, (ub4) OCI_HTYPE_STMT);
	}
	
	if (conn->errHandle) {
		OCIHandleFree((dvoid *)conn->errHandle, (ub4) OCI_HTYPE_ERROR);
	}
	
	if (conn->env) {
		OCIHandleFree((dvoid *)conn->env, (ub4) OCI_HTYPE_ENV);
	}
	
	return 0;
}

/*************************************************************************
 *
 *	Function: sql_socket_init
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
static int sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {

	rlm_sql_oracle_conn_t *conn;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_oracle_conn_t));
	talloc_set_destructor((void *) conn, sql_socket_destructor);

	if (OCIEnvCreate(&conn->env, OCI_DEFAULT|OCI_THREADED, (dvoid *)0,
		(dvoid * (*)(dvoid *, size_t)) 0,
		(dvoid * (*)(dvoid *, dvoid *, size_t))0,
		(void (*)(dvoid *, dvoid *)) 0,
		0, (dvoid **)0 )) {
		radlog(L_ERR,"rlm_sql_oracle: Couldn't init Oracle OCI environment (OCIEnvCreate())");
		return -1;
	}

	if (OCIHandleAlloc((dvoid *) conn->env, (dvoid **) &conn->errHandle,
		(ub4) OCI_HTYPE_ERROR, (size_t) 0, (dvoid **) 0))
	{
		radlog(L_ERR,"rlm_sql_oracle: Couldn't init Oracle ERROR handle (OCIHandleAlloc())");
		return -1;
	}

	/* Allocate handles for select and update queries */
	if (OCIHandleAlloc((dvoid *)conn->env, (dvoid **) &conn->queryHandle,
				(ub4)OCI_HTYPE_STMT, (CONST size_t) 0, (dvoid **) 0))
	{
		radlog(L_ERR,"rlm_sql_oracle: Couldn't init Oracle query handles: %s",
			sql_error(handle, config));
		return -1;
	}


	if (OCILogon(conn->env, conn->errHandle, &conn->ctx,
			config->sql_login, strlen(config->sql_login),
			config->sql_password,  strlen(config->sql_password),
			config->sql_db, strlen(config->sql_db)))
	{
		radlog(L_ERR,"rlm_sql_oracle: Oracle logon failed: '%s'", sql_error(handle, config));
		sql_close(handle,config);
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
static int sql_num_fields(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {

	ub4		count;
	rlm_sql_oracle_conn_t *conn = handle->conn;

	/* get the number of columns in the select list */
	if (OCIAttrGet ((dvoid *)conn->queryHandle,
			(ub4)OCI_HTYPE_STMT,
			(dvoid *) &count,
			(ub4 *) 0,
			(ub4)OCI_ATTR_PARAM_COUNT,
			conn->errHandle)) {
		radlog(L_ERR,"rlm_sql_oracle: Error retrieving column count in sql_num_fields: %s",
			sql_error(handle, config));
		return -1;
	}
	return count;
}

/*************************************************************************
 *
 *	Function: sql_query
 *
 *	Purpose: Issue a non-SELECT query (ie: update/delete/insert) to
 *               the database.
 *
 *************************************************************************/
static int sql_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char *querystr) {

	int	x;
	rlm_sql_oracle_conn_t *conn = handle->conn;

	if (conn->ctx == NULL) {
		radlog(L_ERR, "rlm_sql_oracle: Socket not connected");
		return SQL_DOWN;
	}

	if (OCIStmtPrepare (conn->queryHandle, conn->errHandle,
				querystr, strlen(querystr),
				OCI_NTV_SYNTAX, OCI_DEFAULT))  {
		radlog(L_ERR,"rlm_sql_oracle: prepare failed in sql_query: %s",sql_error(handle, config));
		return -1;
	}

	x = OCIStmtExecute(conn->ctx,
				conn->queryHandle,
				conn->errHandle,
				(ub4) 1,
				(ub4) 0,
				(OCISnapshot *) NULL,
				(OCISnapshot *) NULL,
				(ub4) OCI_COMMIT_ON_SUCCESS);

	if (x == OCI_SUCCESS) {
		return 0;
	}

	if (x == OCI_ERROR) {
		radlog(L_ERR,"rlm_sql_oracle: execute query failed in sql_query: %s",
				sql_error(handle, config));
		return sql_check_error(handle, config);
	}
	else {
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
static int sql_select_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char *querystr) {

	int		x;
	int		y;
	int		colcount;
	OCIParam	*param;
	OCIDefine	*define;
	ub2		dtype;
	ub2		dsize;
	char		**rowdata=NULL;
	sb2		*indicators;
	rlm_sql_oracle_conn_t *conn = handle->conn;

	if (conn->ctx == NULL) {
		radlog(L_ERR, "rlm_sql_oracle: Socket not connected");
		return SQL_DOWN;
	}

	if (OCIStmtPrepare (conn->queryHandle, conn->errHandle,
				querystr, strlen(querystr),
				OCI_NTV_SYNTAX, OCI_DEFAULT))  {
		radlog(L_ERR,"rlm_sql_oracle: prepare failed in sql_select_query: %s",sql_error(handle, config));
		return -1;
	}

	/* Query only one row by default (for now) */
	x = OCIStmtExecute(conn->ctx,
				conn->queryHandle,
				conn->errHandle,
				(ub4) 0,
				(ub4) 0,
				(OCISnapshot *) NULL,
				(OCISnapshot *) NULL,
				(ub4) OCI_DEFAULT);

	if (x == OCI_NO_DATA) {
		/* Nothing to fetch */
		return 0;
	}

	if (x != OCI_SUCCESS) {
		radlog(L_ERR,"rlm_sql_oracle: query failed in sql_select_query: %s",
				sql_error(handle, config));
		return sql_check_error(handle, config);
	}

	/*
	 * Define where the output from fetch calls will go
	 *
	 * This is a gross hack, but it works - we convert
	 * all data to strings for ease of use.  Fortunately, most
	 * of the data we deal with is already in string format.
	 */
	colcount = sql_num_fields(handle, config);

	/* DEBUG2("sql_select_query(): colcount=%d",colcount); */

	/*
	 *	FIXME: These malloc's can probably go, as the schema
	 *	is fixed...
	 */
	rowdata=(char **)rad_malloc(sizeof(char *) * (colcount+1) );
	memset(rowdata, 0, (sizeof(char *) * (colcount+1) ));
	indicators = (sb2 *) rad_malloc(sizeof(sb2) * (colcount+1) );
	memset(indicators, 0, sizeof(sb2) * (colcount+1));

	for (y=1; y <= colcount; y++) {
		x=OCIParamGet(conn->queryHandle, OCI_HTYPE_STMT,
				conn->errHandle,
				(dvoid **)&param,
				(ub4) y);
		if (x != OCI_SUCCESS) {
			radlog(L_ERR,"rlm_sql_oracle: OCIParamGet() failed in sql_select_query: %s",
				sql_error(handle, config));
			goto error;
		}

		x=OCIAttrGet((dvoid*)param, OCI_DTYPE_PARAM,
			   (dvoid*)&dtype, (ub4*)0, OCI_ATTR_DATA_TYPE,
			   conn->errHandle);
		if (x != OCI_SUCCESS) {
			radlog(L_ERR,"rlm_sql_oracle: OCIAttrGet() failed in sql_select_query: %s",
				sql_error(handle, config));
			goto error;
		}

		dsize=MAX_DATASTR_LEN;

		/*
		 * Use the retrieved length of dname to allocate an output
		 * buffer, and then define the output variable (but only
		 * for char/string type columns).
		 */
		switch(dtype) {
#ifdef SQLT_AFC
		case SQLT_AFC:	/* ansii fixed char */
#endif
#ifdef SQLT_AFV
		case SQLT_AFV:	/* ansii var char */
#endif
		case SQLT_VCS:	/* var char */
		case SQLT_CHR:	/* char */
		case SQLT_STR:	/* string */
			x=OCIAttrGet((dvoid*)param, (ub4) OCI_DTYPE_PARAM,
				   (dvoid*) &dsize, (ub4 *)0, (ub4) OCI_ATTR_DATA_SIZE,
				   conn->errHandle);
			if (x != OCI_SUCCESS) {
				radlog(L_ERR,"rlm_sql_oracle: OCIAttrGet() failed in sql_select_query: %s",
					sql_error(handle, config));
				goto error;
			}
			rowdata[y-1]=rad_malloc(dsize+1);
			memset(rowdata[y-1], 0, dsize+1);
			break;
		case SQLT_DAT:
		case SQLT_INT:
		case SQLT_UIN:
		case SQLT_FLT:
		case SQLT_PDN:
		case SQLT_BIN:
		case SQLT_NUM:
			rowdata[y-1]=rad_malloc(dsize+1);
			memset(rowdata[y-1], 0, dsize+1);
			break;
		default:
			dsize=0;
			rowdata[y-1]=NULL;
			break;
		}

		indicators[y-1] = 0;
		x=OCIDefineByPos(conn->queryHandle,
				&define,
				conn->errHandle,
				y,
				(ub1 *) rowdata[y-1],
				dsize+1,
				SQLT_STR,
				&indicators[y-1],
				(dvoid *) 0,
				(dvoid *) 0,
				OCI_DEFAULT);

		if (x != OCI_SUCCESS) {
			radlog(L_ERR,"rlm_sql_oracle: OCIDefineByPos() failed in sql_select_query: %s",
				sql_error(handle, config));
			goto error;
		}
	}

	conn->results=rowdata;
	conn->indicators=indicators;

	return 0;

 error:
	for (y=0; y < colcount; y++) {
		free(rowdata[y]);
	}

	free(rowdata);
	free(indicators);

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
static int sql_store_result(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {
	/* Not needed for Oracle */
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
static int sql_num_rows(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {

	ub4	rows=0;
	rlm_sql_oracle_conn_t *conn = handle->conn;

	OCIAttrGet((CONST dvoid *)conn->queryHandle,
			OCI_HTYPE_STMT,
			(dvoid *)&rows,
			(ub4 *) sizeof(ub4),
			OCI_ATTR_ROW_COUNT,
			conn->errHandle);

	return rows;
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
static int sql_fetch_row(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {

	int	x;
	rlm_sql_oracle_conn_t *conn = handle->conn;

	if (conn->ctx == NULL) {
		radlog(L_ERR, "rlm_sql_oracle: Socket not connected");
		return SQL_DOWN;
	}

	handle->row = NULL;

	x=OCIStmtFetch(conn->queryHandle,
			conn->errHandle,
			1,
			OCI_FETCH_NEXT,
			OCI_DEFAULT);

	if (x == OCI_SUCCESS) {
		handle->row = conn->results;
		return 0;
	}

	if (x == OCI_ERROR) {
		radlog(L_ERR,"rlm_sql_oracle: fetch failed in sql_fetch_row: %s",
				sql_error(handle, config));
		return sql_check_error(handle, config);
	}
	else {
		return -1;
	}
}



/*************************************************************************
 *
 *	Function: sql_free_result
 *
 *	Purpose: database specific free_result. Frees memory allocated
 *               for a result set
 *
 *************************************************************************/
static int sql_free_result(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {

	int x;
	int num_fields;

	rlm_sql_oracle_conn_t *conn = handle->conn;

	/* Cancel the cursor first */
	x=OCIStmtFetch(conn->queryHandle,
			conn->errHandle,
			0,
			OCI_FETCH_NEXT,
			OCI_DEFAULT);

	num_fields = sql_num_fields(handle, config);
	if (num_fields >= 0) {
		for(x=0; x < num_fields; x++) {
			free(conn->results[x]);
		}
		free(conn->results);
		free(conn->indicators);
	}
	conn->results=NULL;
	return 0;
}



/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
static int sql_finish_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
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
static int sql_finish_select_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {

	int 	x=0;
	rlm_sql_oracle_conn_t *conn = handle->conn;

	if (conn->results) {
		while(conn->results[x]) free(conn->results[x++]);
		free(conn->results);
		free(conn->indicators);
		conn->results=NULL;
	}

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: Return the number of rows affected by the query (update,
 *               or insert)
 *
 *************************************************************************/
static int sql_affected_rows(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {

	return sql_num_rows(handle, config);
}


/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_oracle = {
	"rlm_sql_oracle",
	NULL,
	sql_socket_init,
	NULL,
	sql_query,
	sql_select_query,
	sql_store_result,
	sql_num_fields,
	sql_num_rows,
	sql_fetch_row,
	sql_free_result,
	sql_error,
	NULL,
	sql_finish_query,
	sql_finish_select_query,
	sql_affected_rows
};
