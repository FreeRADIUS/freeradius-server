/*
 * sql_postgresql.c		Postgresql rlm_sql driver
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

/* Modification of rlm_sql_mysql to handle postgres */

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#include 	"radiusd.h"
#include	"sql_postgresql.h"


/*************************************************************************
 *
 *	Function: sql_create_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
int sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
	char connstring[2048];

	rlm_sql_postgres_sock *pg_sock;

        sqlsocket->conn = (rlm_sql_postgres_sock *)rad_malloc(sizeof(rlm_sql_postgres_sock));

	pg_sock = sqlsocket->conn;
   
	snprintf(connstring, sizeof(connstring),"dbname=%s host=%s user=%s password=%s", config->sql_db, config->sql_server, config->sql_login, config->sql_password);

	pg_sock->row=NULL;
	pg_sock->result=NULL;
	pg_sock->conn=PQconnectdb(connstring);

	if (PQstatus(sqlsocket->conn) == CONNECTION_BAD) {
		radlog(L_ERR, "rlm_sql: Couldn't connect socket to PostgreSQL server %s@%s:%s", config->sql_login, config->sql_server, config->sql_db);
		radlog(L_ERR, "rlm_sql: Postgresql error '%s'", PQerrorMessage(pg_sock->conn));
		PQfinish(pg_sock->conn);
		return -1;
	}

	PQsetnonblocking(pg_sock->conn, 1);
	return 0;
}

/*************************************************************************
 *
 *	Function: sql_destroy_socket
 *
 *	Purpose: Free socket and any private connection data
 *
 *************************************************************************/
int sql_destroy_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	rlm_sql_postgres_sock *postgres_sock = sqlsocket->conn;

	free(postgres_sock);
	free(sqlsocket);

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_query
 *
 *	Purpose: Issue a query to the database
 *
 *************************************************************************/
int sql_query(SQLSOCK * sqlsocket, SQL_CONFIG *config, char *querystr) {


	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;

	if (config->sqltrace)
		radlog(L_DBG,"query:  %s", querystr);

	if (pg_sock->conn == NULL) {
		radlog(L_ERR, "Socket not connected");
		return -1;
	}

	while (pg_sock->result!=NULL) 
		pg_sock->result=PQgetResult(pg_sock->conn);

	return PQsendQuery(pg_sock->conn, querystr);
}


/*************************************************************************
 *
 *	Function: sql_select_query
 *
 *	Purpose: Issue a select query to the database
 *
 *************************************************************************/
int sql_select_query(SQLSOCK * sqlsocket, SQL_CONFIG *config, char *querystr) {

	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;

	if (config->sqltrace)
		radlog(L_DBG, querystr);

	if (pg_sock->conn == NULL) {
		radlog(L_ERR, "Socket not connected");
		return -1;
	}

	while (pg_sock->result!=NULL) 
		pg_sock->result=PQgetResult(pg_sock->conn);
		PQsendQuery(pg_sock->conn, querystr);

	if (sql_store_result(sqlsocket, config) && sql_num_fields(sqlsocket, config))
		return 0;
	else
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
int sql_store_result(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	int status;
	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;

	if (pg_sock->conn == NULL) {
		radlog(L_ERR, "Socket not connected");
		return -1;
	}

	pg_sock->cur_row = 0;
	pg_sock->result = PQgetResult(pg_sock->conn);
	status=PQresultStatus(pg_sock->result);

	if ((status!=PGRES_COMMAND_OK) && (status!=PGRES_TUPLES_OK)) {
		radlog(L_ERR, "PostgreSQL Error: Cannot get result");
		radlog(L_ERR, "PostgreSQL Error: %s", PQerrorMessage(pg_sock->conn));
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
int sql_num_fields(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	int     num = 0;
	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;

	if (!(num = PQnfields(pg_sock->result))) {
		radlog(L_ERR, "PostgreSQL Error: Cannot get result");
		radlog(L_ERR, "PostgreSQL error: %s", PQerrorMessage(pg_sock->conn));
	}
	return num;
}


/*************************************************************************
 *
 *	Function: sql_num_rows
 *
 *	Purpose: database specific num_rows. Returns number of rows in
 *               query
 *
 *************************************************************************/
int sql_num_rows(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;

	return PQntuples(pg_sock->result);
}


/*************************************************************************
 *
 *	Function: sql_fetch_row
 *
 *	Purpose: database specific fetch_row. Returns a SQL_ROW struct
 *               with all the data for the query
 *
 *************************************************************************/
SQL_ROW sql_fetch_row(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	int records, i, len;
	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;

	if (pg_sock->cur_row >= PQntuples(pg_sock->result))
		return NULL;

	if (pg_sock->row != NULL) {
		for (i = pg_sock->num_fields-1; i >= 0; i--) {
			if (pg_sock->row[i] != NULL) {
				xfree(pg_sock->row[i]);
			}
		}
		if (pg_sock->row != NULL) {
			xfree(pg_sock->row);
			pg_sock->row = NULL;
		}
		pg_sock->num_fields = 0;
	}

	records = PQnfields(pg_sock->result);
	pg_sock->num_fields = records;

	if ((PQntuples(pg_sock->result) > 0) && (records > 0)) {
		pg_sock->row = (char **)rad_malloc(records*sizeof(char *)+1);
		memset(pg_sock->row, '\0', records*sizeof(char *)+1);

		for (i = 0; i < records; i++) {
			len = PQgetlength(pg_sock->result, pg_sock->cur_row, i);
			pg_sock->row[i] = (char *)rad_malloc(len+1);
			memset(pg_sock->row[i], '\0', len+1);
			strncpy(pg_sock->row[i], PQgetvalue(pg_sock->result, pg_sock->cur_row,i),len);
		}
		pg_sock->cur_row++;
		return pg_sock->row;
	} else {
		return NULL;
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
int sql_free_result(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;

	if (pg_sock->result) {
		PQclear(pg_sock->result);
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
char *sql_error(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;

	return PQerrorMessage(pg_sock->conn);
}


/*************************************************************************
 *
 *	Function: sql_close
 *
 *	Purpose: database specific close. Closes an open database
 *               connection
 *
 *************************************************************************/
int sql_close(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;

	PQfinish(pg_sock->conn);
	pg_sock->conn = NULL;

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
int sql_finish_query(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	return sql_free_result(sqlsocket, config);
}



/*************************************************************************
 *
 *	Function: sql_finish_select_query
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
int sql_finish_select_query(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	return sql_free_result(sqlsocket, config);
}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
int sql_affected_rows(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;

	return atoi(PQcmdTuples(pg_sock->result));
}


/*************************************************************************
 *
 *      Function: sql_escape_string
 *
 *      Purpose: Esacpe "'" and any other wierd charactors
 *
 *************************************************************************/
int sql_escape_string(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *to, char *from, int length) {

	int x, y;

	for(x=0, y=0; x < length; x++) {
		if (from[x] == '\'') {
			to[y++]='\'';
		}
		to[y++]=from[x];
	}

	to[y]=0;

	return 0;
}

/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_postgresql = {
        "rlm_sql_postgresql",
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
        sql_affected_rows,
        sql_escape_string
};
