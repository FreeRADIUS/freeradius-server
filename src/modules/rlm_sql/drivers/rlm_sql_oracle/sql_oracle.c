/***************************************************************************
*  sql_oracle.c                        rlm_sql - FreeRADIUS SQL Module     *
*                                                                          *
*      Oracle (OCI) routines for rlm_sql                                   *
*                                                                          *
*                                     David Kerry <davidk@snti.com>        *
***************************************************************************/
#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#include 	"radiusd.h"
#include	"rlm_sql.h"

#define	MAX_DATASTR_LEN	64

/*************************************************************************
 *
 *	Function: sql_create_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
SQLSOCK *sql_create_socket(SQL_INST *inst)
{
	SQLSOCK *socket;

	socket = rad_malloc(sizeof(SQLSOCK));

	if (OCIEnvCreate(&socket->env, OCI_DEFAULT, (dvoid *)0,
		(dvoid * (*)(dvoid *, size_t)) 0,
		(dvoid * (*)(dvoid *, dvoid *, size_t))0, 
		(void (*)(dvoid *, dvoid *)) 0,
		0, (dvoid **)0 )) {
		radlog(L_ERR,"Init: Couldn't init Oracle OCI environment (OCIEnvCreate())");
		return NULL;
	}

	if (OCIHandleAlloc((dvoid *) socket->env, (dvoid **) &socket->errHandle,
		(ub4) OCI_HTYPE_ERROR, (size_t) 0, (dvoid **) 0))
	{
		radlog(L_ERR,"Init: Couldn't init Oracle ERROR handle (OCIHandleAlloc())");
		return NULL;
	}

	/* Allocate handles for select and update queries */
	if (OCIHandleAlloc((dvoid *)socket->env, (dvoid **) &socket->queryHandle,
				(ub4)OCI_HTYPE_STMT, (CONST size_t) 0, (dvoid **) 0)
	    ||  OCIHandleAlloc((dvoid *)socket->env, (dvoid **) &socket->queryHandle,
				(ub4)OCI_HTYPE_STMT, (CONST size_t) 0, (dvoid **) 0))
	{
		radlog(L_ERR,"Init: Couldn't init Oracle query handles: %s",
			sql_error(socket));
		return NULL;
	}


	if (OCILogon(socket->env, socket->errHandle, &socket->conn,
			inst->config->sql_login, strlen(inst->config->sql_login),
			inst->config->sql_password,  strlen(inst->config->sql_password),
			inst->config->sql_db, strlen(inst->config->sql_db)))
	{
		radlog(L_ERR,"Init: Oracle logon failed: '%s'", sql_error(socket));
		return NULL;
	}

	return socket;
}

/*************************************************************************
 *
 *	Function: sql_query
 *
 *	Purpose: Issue a non-SELECT query (ie: update/delete/insert) to
 *               the database.
 *
 *************************************************************************/
int sql_query(SQL_INST *inst, SQLSOCK *socket, char *querystr)
{
	int	x;

	if (inst->config->sqltrace)
		DEBUG(querystr);
	 if (socket->conn == NULL) {
		radlog(L_ERR, "Socket not connected");
		return 0;
	}

	if (OCIStmtPrepare (socket->queryHandle, socket->errHandle,
				querystr, strlen(querystr),
				OCI_NTV_SYNTAX, OCI_DEFAULT))  {
		radlog(L_ERR,"sql_query: prepare failed: %s",sql_error(socket));
		return -1;
	}

	x = OCIStmtExecute(socket->conn,
				socket->queryHandle,
				socket->errHandle,
				(ub4) 1,
				(ub4) 0,
				(OCISnapshot *) NULL,
				(OCISnapshot *) NULL,
				(ub4) OCI_DEFAULT);

	if ((x != OCI_NO_DATA) && (x != OCI_SUCCESS)) {
		return -1;
	}

	x = OCITransCommit(socket->conn, socket->errHandle, (ub4) 0);
	if (x != OCI_SUCCESS)
		return -1;

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_select_query
 *
 *	Purpose: Issue a select query to the database
 *
 *************************************************************************/
int sql_select_query(SQL_INST *inst, SQLSOCK *socket, char *querystr)
{
	int		x;
	int		y;
	int		colcount;
	OCIParam	*param;
	OCIDefine	*define;
	ub2		dtype;
	ub4		dsize;
	char		**rowdata=NULL;

	if (inst->config->sqltrace)
		DEBUG(querystr);
	 if (socket->conn == NULL) {
		radlog(L_ERR, "Socket not connected");
		return -1;
	}

	if (OCIStmtPrepare (socket->queryHandle, socket->errHandle,
				querystr, strlen(querystr),
				OCI_NTV_SYNTAX, OCI_DEFAULT))  {
		radlog(L_ERR,"sql_select_query: prepare failed: %s",sql_error(socket));
		return -1;
	}

	/* Query only one row by default (for now) */
	x = OCIStmtExecute(socket->conn,
				socket->queryHandle,
				socket->errHandle,
				(ub4) 0,
				(ub4) 0,
				(OCISnapshot *) NULL,
				(OCISnapshot *) NULL,
				(ub4) OCI_DEFAULT);

	if (x == OCI_NO_DATA) {
		/* Nothing to fetch */
		return 0;
	}
	else if (x != OCI_SUCCESS) {
		return -1;
	}

	/*
	 * Define where the output from fetch calls will go
	 *
	 * This is a gross hack, but it works - we convert
	 * all data to strings for ease of use.  Fortunately, most
	 * of the data we deal with is already in string format.
	 */
	colcount=sql_num_fields(socket);

	/* DEBUG2("sql_select_query(): colcount=%d",colcount); */

	rowdata=(char **)rad_malloc(sizeof(char *) * (colcount+1) );
	memset(rowdata, 0, (sizeof(char *) * (colcount+1) ));

	for (y=1; y <= colcount; y++) {
		x=OCIParamGet(socket->queryHandle, OCI_HTYPE_STMT,
				socket->errHandle,
				(dvoid **)&param,
				(ub4) y);
		if (x != OCI_SUCCESS) {
			radlog(L_ERR,"sql_select_query: OCIParamGet() failed: %s",
				sql_error(socket));
			return -1;
		}

		x=OCIAttrGet((dvoid*)param, OCI_DTYPE_PARAM, 
			   (dvoid*)&dtype, (ub4*)0, OCI_ATTR_DATA_TYPE,
			   socket->errHandle);
		if (x != OCI_SUCCESS) {
			radlog(L_ERR,"sql_select_query: OCIAttrGet() failed: %s",
				sql_error(socket));
			return -1;
		}

		dsize=MAX_DATASTR_LEN;

		/*
		 * Use the retrieved length of dname to allocate an output
		 * buffer, and then define the output variable (but only
		 * for char/string type columns).
		 */
		switch(dtype) {
		case SQLT_CHR:
		case SQLT_STR:
			x=OCIAttrGet((dvoid*)param, (ub4) OCI_DTYPE_PARAM,
				   (dvoid*) &dsize, (ub4 *)0, (ub4) OCI_ATTR_DATA_SIZE,
				   socket->errHandle);
			if (x != OCI_SUCCESS) {
				radlog(L_ERR,"sql_select_query: OCIAttrGet() failed: %s",
					sql_error(socket));
				return -1;
			}
			rowdata[y-1]=rad_malloc(dsize+1);
			break;
		case SQLT_DAT:
		case SQLT_INT:
		case SQLT_UIN:
		case SQLT_FLT:
		case SQLT_PDN:
		case SQLT_BIN:
		case SQLT_NUM:
			rowdata[y-1]=rad_malloc(dsize+1);
			break;
		default:
			dsize=0;
			rowdata[y-1]=NULL;
			break;
		}

		x=OCIDefineByPos(socket->queryHandle,
				&define,
				socket->errHandle,
				y,
				(ub1 *) rowdata[y-1],
				dsize,
				SQLT_STR,
				(dvoid *) 0,
				(dvoid *) 0,
				(dvoid *) 0,
				OCI_DEFAULT);
		if (x != OCI_SUCCESS) {
			radlog(L_ERR,"sql_select_query: OCIDefineByPos() failed: %s",
				sql_error(socket));
			return -1;
		}
	}

	rowdata[y-1]=NULL; /* Terminate the array */

	socket->results=rowdata;

	return 1;
}


/*************************************************************************
 *
 *	Function: sql_store_result
 *
 *	Purpose: database specific store_result function. Returns a result
 *               set for the query.
 *
 *************************************************************************/
int sql_store_result(SQLSOCK *socket) {
	/* Not needed for Oracle */
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
int sql_num_fields(SQLSOCK *socket) {

	ub4		count;

	/* get the number of columns in the select list */ 
	if (OCIAttrGet ((dvoid *)socket->queryHandle,
			(ub4)OCI_HTYPE_STMT,
			(dvoid *) &count,
			(ub4 *) 0,
			(ub4)OCI_ATTR_PARAM_COUNT,
			socket->errHandle)) {
		radlog(L_ERR,"sql_num_fields: error retrieving colun count: %s",
			sql_error(socket));
		return -1;
	}
	return count;
}

/*************************************************************************
 *
 *	Function: sql_num_rows
 *
 *	Purpose: database specific num_rows. Returns number of rows in
 *               query
 *
 *************************************************************************/
int sql_num_rows(SQLSOCK *socket) {

	ub4	rows=0;

	OCIAttrGet((CONST dvoid *)socket->queryHandle,
			OCI_HTYPE_STMT,
			(dvoid *)&rows, 
			(ub4 *) sizeof(ub4),
			OCI_ATTR_ROW_COUNT,
			socket->errHandle);

	return rows;
}


/*************************************************************************
 *
 *	Function: sql_fetch_row
 *
 *	Purpose: database specific fetch_row. Returns a SQL_ROW struct
 *               with all the data for the query
 *
 *************************************************************************/
SQL_ROW sql_fetch_row(SQLSOCK *socket)
{
	int	x;

	x=OCIStmtFetch(socket->queryHandle,
			socket->errHandle,
			1,
			OCI_FETCH_NEXT,
			OCI_DEFAULT);
	if (x == OCI_NO_DATA) {
		return NULL;
	}
	else if (x != OCI_SUCCESS) {
		radlog(L_ERR,"sql_fetch_row: fetch failed: %s",
				sql_error(socket));
		return NULL;
	}

	return socket->results;
}



/*************************************************************************
 *
 *	Function: sql_free_result
 *
 *	Purpose: database specific free_result. Frees memory allocated
 *               for a result set
 *
 *************************************************************************/
void sql_free_result(SQLSOCK *socket) {
	int i=0;

	for(i=0; i<sql_num_fields(socket); i++) {
		free(socket->results[i]);
	}
	free(socket->results);
	socket->results=NULL;
}



/*************************************************************************
 *
 *	Function: sql_error
 *
 *	Purpose: database specific error. Returns error associated with
 *               connection
 *
 *************************************************************************/
char *sql_error(SQLSOCK *socket)
{
	static char	msgbuf[512];
	int		errcode = 0;
 
	memset((void *) msgbuf, (int)'\0', sizeof(msgbuf));

	OCIErrorGet((dvoid *) socket->errHandle, (ub4) 1, (text *) NULL,
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
 *	Function: sql_close
 *
 *	Purpose: database specific close. Closes an open database
 *               connection and cleans up any open handles.
 *
 *************************************************************************/
void sql_close(SQLSOCK *socket)
{

	if (socket->conn) {
		OCILogoff (socket->conn, socket->errHandle);
	}

	if (socket->queryHandle) {
		OCIHandleFree((dvoid *)socket->queryHandle, (ub4) OCI_HTYPE_STMT);
	}
	if (socket->errHandle) {
		OCIHandleFree((dvoid *)socket->errHandle, (ub4) OCI_HTYPE_ERROR);
	}
	if (socket->env) {
		OCIHandleFree((dvoid *)socket->env, (ub4) OCI_HTYPE_ENV);
	}

	socket->conn = NULL;
}


/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
void sql_finish_query(SQLSOCK *socket)
{
	/* Nothing to do here for Oracle */
	sql_free_result(socket);
}



/*************************************************************************
 *
 *	Function: sql_finish_select_query
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
void sql_finish_select_query(SQLSOCK *socket)
{
	int 	x=0;

	if (socket->results) {
		while(socket->results[x]) free(socket->results[x++]);
		free(socket->results);
		socket->results=NULL;
	}

}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: Return the number of rows affected by the query (update,
 *               or insert)
 *
 *************************************************************************/
int sql_affected_rows(SQLSOCK *socket) {
	return sql_num_rows(socket);
}


/*************************************************************************
 *
 *      Function: sql_escape_string
 *
 *      Purpose: Esacpe "'" and any other wierd charactors
 *
 *************************************************************************/
int sql_escape_string(char *to, char *from, int length)
{
	int x;
	int y;

	for(x=0, y=0; x < length; x++) {
		if (from[x] == '\'') {
			to[y++]='\'';
		}
		to[y++]=from[x];
	}
	to[y]=0;

	return 1;
}

/*************************************************************************
 *
 *      Function: check_error
 *
 *      Purpose: Check query return value for potential errors
 *
 *************************************************************************/
static void checkerr(SQLSOCK *socket, sword status)
{
	switch (status)	{
	case OCI_SUCCESS: break;
	case OCI_SUCCESS_WITH_INFO:
		printf("status = OCI_SUCCESS_WITH_INFO\n");
		printf("OCI err: %s\n",sql_error(socket));
		break;
	case OCI_NEED_DATA:
		printf("status = OCI_NEED_DATA\n");
		break;
	case OCI_NO_DATA:
		printf("status = OCI_NO_DATA\n");
		break;
	case OCI_ERROR:
		printf("status = OCI_ERROR\n");
		printf("OCI err: %s\n",sql_error(socket));
		break;
	case OCI_INVALID_HANDLE:
		printf("status = OCI_INVALID_HANDLE\n");
		break;
	case OCI_STILL_EXECUTING:
		printf("status = OCI_STILL_EXECUTE\n");
		break;
	case OCI_CONTINUE:
		printf("status = OCI_CONTINUE\n");
		break;
	default:
		break;
	}
}

