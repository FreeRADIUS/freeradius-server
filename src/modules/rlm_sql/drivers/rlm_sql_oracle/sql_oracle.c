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

typedef struct rlm_sql_oracle_sock {
	OCIEnv		*env;
	OCIError	*errHandle;
	OCISvcCtx	*conn;
	OCIStmt		*queryHandle;
	sb2		*indicators;
	char		**results;
	int		id;
	int		in_use;
	struct timeval	tv;
} rlm_sql_oracle_sock;

#define	MAX_DATASTR_LEN	64


/*************************************************************************
 *
 *	Function: sql_error
 *
 *	Purpose: database specific error. Returns error associated with
 *               connection
 *
 *************************************************************************/
static const char *sql_error(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	static char	msgbuf[512];
	sb4		errcode = 0;
	rlm_sql_oracle_sock *oracle_sock = sqlsocket->conn;

	if (!oracle_sock) return "rlm_sql_oracle: no connection to db";

	memset((void *) msgbuf, (int)'\0', sizeof(msgbuf));

	OCIErrorGet((dvoid *) oracle_sock->errHandle, (ub4) 1, (text *) NULL,
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
static int sql_check_error(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	if (strstr(sql_error(sqlsocket, config), "ORA-03113") ||
			strstr(sql_error(sqlsocket, config), "ORA-03114")) {
		radlog(L_ERR,"rlm_sql_oracle: OCI_SERVER_NOT_CONNECTED");
		return SQL_DOWN;
	}
	else {
		radlog(L_ERR,"rlm_sql_oracle: OCI_SERVER_NORMAL");
		return -1;
	}
}

/*************************************************************************
 *
 *	Function: sql_close
 *
 *	Purpose: database specific close. Closes an open database
 *               connection and cleans up any open handles.
 *
 *************************************************************************/
static int sql_close(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	rlm_sql_oracle_sock *oracle_sock = sqlsocket->conn;

	if (oracle_sock->conn) {
		OCILogoff (oracle_sock->conn, oracle_sock->errHandle);
	}

	if (oracle_sock->queryHandle) {
		OCIHandleFree((dvoid *)oracle_sock->queryHandle, (ub4) OCI_HTYPE_STMT);
	}
	if (oracle_sock->errHandle) {
		OCIHandleFree((dvoid *)oracle_sock->errHandle, (ub4) OCI_HTYPE_ERROR);
	}
	if (oracle_sock->env) {
		OCIHandleFree((dvoid *)oracle_sock->env, (ub4) OCI_HTYPE_ENV);
	}

	oracle_sock->conn = NULL;
	free(oracle_sock);
	sqlsocket->conn = NULL;

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_init_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
static int sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	rlm_sql_oracle_sock *oracle_sock;

	if (!sqlsocket->conn) {
		sqlsocket->conn = (rlm_sql_oracle_sock *)rad_malloc(sizeof(rlm_sql_oracle_sock));
		if (!sqlsocket->conn) {
			return -1;
		}
	}
	memset(sqlsocket->conn,0,sizeof(rlm_sql_oracle_sock));

	oracle_sock = sqlsocket->conn;

	if (OCIEnvCreate(&oracle_sock->env, OCI_DEFAULT|OCI_THREADED, (dvoid *)0,
		(dvoid * (*)(dvoid *, size_t)) 0,
		(dvoid * (*)(dvoid *, dvoid *, size_t))0,
		(void (*)(dvoid *, dvoid *)) 0,
		0, (dvoid **)0 )) {
		radlog(L_ERR,"rlm_sql_oracle: Couldn't init Oracle OCI environment (OCIEnvCreate())");
		return -1;
	}

	if (OCIHandleAlloc((dvoid *) oracle_sock->env, (dvoid **) &oracle_sock->errHandle,
		(ub4) OCI_HTYPE_ERROR, (size_t) 0, (dvoid **) 0))
	{
		radlog(L_ERR,"rlm_sql_oracle: Couldn't init Oracle ERROR handle (OCIHandleAlloc())");
		return -1;
	}

	/* Allocate handles for select and update queries */
	if (OCIHandleAlloc((dvoid *)oracle_sock->env, (dvoid **) &oracle_sock->queryHandle,
				(ub4)OCI_HTYPE_STMT, (CONST size_t) 0, (dvoid **) 0))
	{
		radlog(L_ERR,"rlm_sql_oracle: Couldn't init Oracle query handles: %s",
			sql_error(sqlsocket, config));
		return -1;
	}


	if (OCILogon(oracle_sock->env, oracle_sock->errHandle, &oracle_sock->conn,
			config->sql_login, strlen(config->sql_login),
			config->sql_password,  strlen(config->sql_password),
			config->sql_db, strlen(config->sql_db)))
	{
		radlog(L_ERR,"rlm_sql_oracle: Oracle logon failed: '%s'", sql_error(sqlsocket, config));
		sql_close(sqlsocket,config);
		return -1;
	}

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_destroy_socket
 *
 *	Purpose: Free socket and private connection data
 *
 *************************************************************************/
static int sql_destroy_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config)
{
	free(sqlsocket->conn);
	sqlsocket->conn = NULL;
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
static int sql_num_fields(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	ub4		count;
	rlm_sql_oracle_sock *oracle_sock = sqlsocket->conn;

	/* get the number of columns in the select list */
	if (OCIAttrGet ((dvoid *)oracle_sock->queryHandle,
			(ub4)OCI_HTYPE_STMT,
			(dvoid *) &count,
			(ub4 *) 0,
			(ub4)OCI_ATTR_PARAM_COUNT,
			oracle_sock->errHandle)) {
		radlog(L_ERR,"rlm_sql_oracle: Error retrieving column count in sql_num_fields: %s",
			sql_error(sqlsocket, config));
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
static int sql_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr) {

	int	x;
	rlm_sql_oracle_sock *oracle_sock = sqlsocket->conn;

	if (config->sqltrace)
		DEBUG(querystr);
	if (oracle_sock->conn == NULL) {
		radlog(L_ERR, "rlm_sql_oracle: Socket not connected");
		return SQL_DOWN;
	}

	if (OCIStmtPrepare (oracle_sock->queryHandle, oracle_sock->errHandle,
				querystr, strlen(querystr),
				OCI_NTV_SYNTAX, OCI_DEFAULT))  {
		radlog(L_ERR,"rlm_sql_oracle: prepare failed in sql_query: %s",sql_error(sqlsocket, config));
		return -1;
	}

	x = OCIStmtExecute(oracle_sock->conn,
				oracle_sock->queryHandle,
				oracle_sock->errHandle,
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
				sql_error(sqlsocket, config));
		return sql_check_error(sqlsocket, config);
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
static int sql_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr) {

	int		x;
	int		y;
	int		colcount;
	OCIParam	*param;
	OCIDefine	*define;
	ub2		dtype;
	ub2		dsize;
	char		**rowdata=NULL;
	sb2		*indicators;
	rlm_sql_oracle_sock *oracle_sock = sqlsocket->conn;

	if (config->sqltrace)
		DEBUG(querystr);
	if (oracle_sock->conn == NULL) {
		radlog(L_ERR, "rlm_sql_oracle: Socket not connected");
		return SQL_DOWN;
	}

	if (OCIStmtPrepare (oracle_sock->queryHandle, oracle_sock->errHandle,
				querystr, strlen(querystr),
				OCI_NTV_SYNTAX, OCI_DEFAULT))  {
		radlog(L_ERR,"rlm_sql_oracle: prepare failed in sql_select_query: %s",sql_error(sqlsocket, config));
		return -1;
	}

	/* Query only one row by default (for now) */
	x = OCIStmtExecute(oracle_sock->conn,
				oracle_sock->queryHandle,
				oracle_sock->errHandle,
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
				sql_error(sqlsocket, config));
		return sql_check_error(sqlsocket, config);
	}

	/*
	 * Define where the output from fetch calls will go
	 *
	 * This is a gross hack, but it works - we convert
	 * all data to strings for ease of use.  Fortunately, most
	 * of the data we deal with is already in string format.
	 */
	colcount = sql_num_fields(sqlsocket, config);

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
		x=OCIParamGet(oracle_sock->queryHandle, OCI_HTYPE_STMT,
				oracle_sock->errHandle,
				(dvoid **)&param,
				(ub4) y);
		if (x != OCI_SUCCESS) {
			radlog(L_ERR,"rlm_sql_oracle: OCIParamGet() failed in sql_select_query: %s",
				sql_error(sqlsocket, config));
			return -1;
		}

		x=OCIAttrGet((dvoid*)param, OCI_DTYPE_PARAM,
			   (dvoid*)&dtype, (ub4*)0, OCI_ATTR_DATA_TYPE,
			   oracle_sock->errHandle);
		if (x != OCI_SUCCESS) {
			radlog(L_ERR,"rlm_sql_oracle: OCIAttrGet() failed in sql_select_query: %s",
				sql_error(sqlsocket, config));
			return -1;
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
				   oracle_sock->errHandle);
			if (x != OCI_SUCCESS) {
				radlog(L_ERR,"rlm_sql_oracle: OCIAttrGet() failed in sql_select_query: %s",
					sql_error(sqlsocket, config));
				return -1;
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
		x=OCIDefineByPos(oracle_sock->queryHandle,
				&define,
				oracle_sock->errHandle,
				y,
				(ub1 *) rowdata[y-1],
				dsize+1,
				SQLT_STR,
				&indicators[y-1],
				(dvoid *) 0,
				(dvoid *) 0,
				OCI_DEFAULT);

		/*
		 *	FIXME: memory leaks of indicators & rowdata?
		 */
		if (x != OCI_SUCCESS) {
			radlog(L_ERR,"rlm_sql_oracle: OCIDefineByPos() failed in sql_select_query: %s",
				sql_error(sqlsocket, config));
			return -1;
		}
	}

	oracle_sock->results=rowdata;
	oracle_sock->indicators=indicators;

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
static int sql_store_result(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
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
static int sql_num_rows(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	ub4	rows=0;
	rlm_sql_oracle_sock *oracle_sock = sqlsocket->conn;

	OCIAttrGet((CONST dvoid *)oracle_sock->queryHandle,
			OCI_HTYPE_STMT,
			(dvoid *)&rows,
			(ub4 *) sizeof(ub4),
			OCI_ATTR_ROW_COUNT,
			oracle_sock->errHandle);

	return rows;
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
static int sql_fetch_row(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	int	x;
	rlm_sql_oracle_sock *oracle_sock = sqlsocket->conn;

	if (oracle_sock->conn == NULL) {
		radlog(L_ERR, "rlm_sql_oracle: Socket not connected");
		return SQL_DOWN;
	}

	sqlsocket->row = NULL;

	x=OCIStmtFetch(oracle_sock->queryHandle,
			oracle_sock->errHandle,
			1,
			OCI_FETCH_NEXT,
			OCI_DEFAULT);

	if (x == OCI_SUCCESS) {
		sqlsocket->row = oracle_sock->results;
		return 0;
	}

	if (x == OCI_ERROR) {
		radlog(L_ERR,"rlm_sql_oracle: fetch failed in sql_fetch_row: %s",
				sql_error(sqlsocket, config));
		return sql_check_error(sqlsocket, config);
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
static int sql_free_result(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	int x;
	int num_fields;

	rlm_sql_oracle_sock *oracle_sock = sqlsocket->conn;

	/* Cancel the cursor first */
	x=OCIStmtFetch(oracle_sock->queryHandle,
			oracle_sock->errHandle,
			0,
			OCI_FETCH_NEXT,
			OCI_DEFAULT);

	num_fields = sql_num_fields(sqlsocket, config);
	if (num_fields >= 0) {
		for(x=0; x < num_fields; x++) {
			free(oracle_sock->results[x]);
		}
		free(oracle_sock->results);
		free(oracle_sock->indicators);
	}
	oracle_sock->results=NULL;
	return 0;
}



/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
static int sql_finish_query(SQLSOCK *sqlsocket, SQL_CONFIG *config)
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
static int sql_finish_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	int 	x=0;
	rlm_sql_oracle_sock *oracle_sock = sqlsocket->conn;

	if (oracle_sock->results) {
		while(oracle_sock->results[x]) free(oracle_sock->results[x++]);
		free(oracle_sock->results);
		free(oracle_sock->indicators);
		oracle_sock->results=NULL;
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
static int sql_affected_rows(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	return sql_num_rows(sqlsocket, config);
}


/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_oracle = {
	"rlm_sql_oracle",
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
