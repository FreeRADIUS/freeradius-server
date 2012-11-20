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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Mike Machado <mike@innercite.com>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

/*
 * April 2001:
 *
 * Use blocking queries and delete unused functions. In
 * rlm_sql_postgresql replace all functions that are not really used
 * with the not_implemented function.
 *
 * Add a new field to the rlm_sql_postgres_sock struct to store the
 * number of rows affected by a query because the sql module calls
 * finish_query before it retrieves the number of affected rows from the
 * driver
 *
 * Bernhard Herzog <bh@intevation.de>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <sys/stat.h>

#include <libpq-fe.h>
#include "rlm_sql.h"
#include "sql_postgresql.h"

typedef struct rlm_sql_postgres_sock {
   PGconn          *conn;
   PGresult        *result;
   int             cur_row;
   int             num_fields;
   int		   affected_rows;
   char            **row;
} rlm_sql_postgres_sock;

/* Prototypes */
static int sql_close(SQLSOCK *sqlsocket, SQL_CONFIG *config);

/* Internal function. Return true if the postgresql status value
 * indicates successful completion of the query. Return false otherwise
static int
status_is_ok(ExecStatusType status)
{
	return status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK;
}
*/


/* Internal function. Return the number of affected rows of the result
 * as an int instead of the string that postgresql provides */
static int
affected_rows(PGresult * result)
{
	return atoi(PQcmdTuples(result));
}

/* Internal function. Free the row of the current result that's stored
 * in the pg_sock struct. */
static void
free_result_row(rlm_sql_postgres_sock * pg_sock)
{
	int i;
	if (pg_sock->row != NULL) {
		for (i = pg_sock->num_fields-1; i >= 0; i--) {
			if (pg_sock->row[i] != NULL) {
				free(pg_sock->row[i]);
			}
		}
		free((char*)pg_sock->row);
		pg_sock->row = NULL;
		pg_sock->num_fields = 0;
	}
}


/*************************************************************************
*	Function: check_fatal_error
*
*	Purpose:  Check error type and behave accordingly
*
*************************************************************************/

static int check_fatal_error (char *errorcode)
{
	int x = 0;

	/*
	Check the error code to see if we should reconnect or not
	Error Code table taken from
	http://www.postgresql.org/docs/8.1/interactive/errcodes-appendix.html
	*/

	if (!errorcode) return -1;

	while(errorcodes[x].errorcode != NULL){
		if (strcmp(errorcodes[x].errorcode, errorcode) == 0){
			radlog(L_DBG, "rlm_sql_postgresql: Postgresql Fatal Error: [%s: %s] Occurred!!", errorcode, errorcodes[x].meaning);
			if (errorcodes[x].shouldreconnect == 1)
				return SQL_DOWN;
			else
				return -1;
		}
		x++;
	}

	radlog(L_DBG, "rlm_sql_postgresql: Postgresql Fatal Error: [%s] Occurred!!", errorcode);
	/*	We don't seem to have a matching error class/code */
	return -1;
}



/*************************************************************************
 *
 *	Function: sql_create_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
static int sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
	char connstring[2048];
	const char *port, *host;
	rlm_sql_postgres_sock *pg_sock;

#ifdef HAVE_OPENSSL_CRYPTO_H
	static int ssl_init = 0;

	if (!ssl_init) {
		PQinitSSL(0);
		ssl_init = 1;
	}

#endif

	if (config->sql_server[0] != '\0') {
		host = " host=";
	} else {
		host = "";
	}

	if (config->sql_port[0] != '\0') {
		port = " port=";
	} else {
		port = "";
	}

	if (!sqlsocket->conn) {
		sqlsocket->conn = (rlm_sql_postgres_sock *)rad_malloc(sizeof(rlm_sql_postgres_sock));
		if (!sqlsocket->conn) {
			return -1;
		}
	}

	pg_sock = sqlsocket->conn;
	memset(pg_sock, 0, sizeof(*pg_sock));

	snprintf(connstring, sizeof(connstring),
			"dbname=%s%s%s%s%s user=%s password=%s",
			config->sql_db, host, config->sql_server,
			port, config->sql_port,
			config->sql_login, config->sql_password);
	pg_sock->row=NULL;
	pg_sock->result=NULL;
	pg_sock->conn=PQconnectdb(connstring);

	if (PQstatus(pg_sock->conn) != CONNECTION_OK) {
		radlog(L_ERR, "rlm_sql_postgresql: Couldn't connect socket to PostgreSQL server %s@%s:%s", config->sql_login, config->sql_server, config->sql_db);
		/*radlog(L_ERR, "rlm_sql_postgresql: Postgresql error '%s'", PQerrorMessage(pg_sock->conn));*/
		sql_close(sqlsocket, config);
		return SQL_DOWN;
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
static int sql_query(SQLSOCK * sqlsocket, SQL_CONFIG *config, char *querystr) {

	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;
	int numfields = 0;
	char *errorcode;
	char *errormsg;

	if (pg_sock->conn == NULL) {
		radlog(L_ERR, "rlm_sql_postgresql: Socket not connected");
		return SQL_DOWN;
	}

	pg_sock->result = PQexec(pg_sock->conn, querystr);
		/*
		 * Returns a PGresult pointer or possibly a null pointer.
		 * A non-null pointer will generally be returned except in
		 * out-of-memory conditions or serious errors such as inability
		 * to send the command to the server. If a null pointer is
		 * returned, it should be treated like a PGRES_FATAL_ERROR
		 * result.
		 */
	if (!pg_sock->result)
	{
		radlog(L_ERR, "rlm_sql_postgresql: PostgreSQL Query failed Error: %s",
				PQerrorMessage(pg_sock->conn));
		/* As this error COULD be a connection error OR an out-of-memory
		 * condition return value WILL be wrong SOME of the time regardless!
		 * Pick your poison....
		 */
		return  SQL_DOWN;
	} else {
		ExecStatusType status = PQresultStatus(pg_sock->result);
		radlog(L_DBG, "rlm_sql_postgresql: Status: %s", PQresStatus(status));

		switch (status){

			case PGRES_COMMAND_OK:
				/*Successful completion of a command returning no data.*/

				/*affected_rows function only returns
				the number of affected rows of a command
				returning no data...
				*/
				pg_sock->affected_rows	= affected_rows(pg_sock->result);
				radlog(L_DBG, "rlm_sql_postgresql: query affected rows = %i", pg_sock->affected_rows);
				return 0;

			break;

			case PGRES_TUPLES_OK:
				/*Successful completion of a command returning data (such as a SELECT or SHOW).*/

				pg_sock->cur_row = 0;
 				pg_sock->affected_rows = PQntuples(pg_sock->result);
				numfields = PQnfields(pg_sock->result); /*Check row storing functions..*/
				radlog(L_DBG, "rlm_sql_postgresql: query affected rows = %i , fields = %i", pg_sock->affected_rows, numfields);
				return 0;

			break;

			case PGRES_BAD_RESPONSE:
				/*The server's response was not understood.*/
				radlog(L_DBG, "rlm_sql_postgresql: Bad Response From Server!!");
				return -1;

			break;

			case PGRES_NONFATAL_ERROR:
				/*A nonfatal error (a notice or warning) occurred. Possibly never returns*/

				return -1;

			break;

			case PGRES_FATAL_ERROR:
#if defined(PG_DIAG_SQLSTATE) && defined(PG_DIAG_MESSAGE_PRIMARY)
				/*A fatal error occurred.*/

				errorcode = PQresultErrorField(pg_sock->result, PG_DIAG_SQLSTATE);
				errormsg  = PQresultErrorField(pg_sock->result, PG_DIAG_MESSAGE_PRIMARY);
				radlog(L_DBG, "rlm_sql_postgresql: Error %s", errormsg);
				return check_fatal_error(errorcode);
#endif

			break;

			default:
				/* FIXME: An unhandled error occurred.*/

				/* PGRES_EMPTY_QUERY PGRES_COPY_OUT PGRES_COPY_IN */

				return -1;

			break;


		}

		/*
			Note to self ... sql_store_result returns 0 anyway
			after setting the sqlsocket->affected_rows..
			sql_num_fields returns 0 at worst case which means the check below
			has a really small chance to return false..
			lets remove it then .. yuck!!
		*/
		/*
		} else {
			if ((sql_store_result(sqlsocket, config) == 0)
					&& (sql_num_fields(sqlsocket, config) >= 0))
				return 0;
			else
				return -1;
		}
		*/
	}
	return -1;
}


/*************************************************************************
 *
 *	Function: sql_select_query
 *
 *	Purpose: Issue a select query to the database
 *
 *************************************************************************/
static int sql_select_query(SQLSOCK * sqlsocket, SQL_CONFIG *config, char *querystr) {
	return sql_query(sqlsocket, config, querystr);
}


/*************************************************************************
 *
 *      Function: sql_destroy_socket
 *
 *      Purpose: Free socket and private connection data
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
 *	Function: sql_fetch_row
 *
 *	Purpose: database specific fetch_row. Returns a SQL_ROW struct
 *	with all the data for the query in 'sqlsocket->row'. Returns
 *	0 on success, -1 on failure, SQL_DOWN if 'database is down'.
 *
 *************************************************************************/
static int sql_fetch_row(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config) {

	int records, i, len;
	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;

	sqlsocket->row = NULL;

	if (pg_sock->cur_row >= PQntuples(pg_sock->result))
		return 0;

	free_result_row(pg_sock);

	records = PQnfields(pg_sock->result);
	pg_sock->num_fields = records;

	if ((PQntuples(pg_sock->result) > 0) && (records > 0)) {
		pg_sock->row = (char **)rad_malloc((records+1)*sizeof(char *));
		memset(pg_sock->row, '\0', (records+1)*sizeof(char *));

		for (i = 0; i < records; i++) {
			len = PQgetlength(pg_sock->result, pg_sock->cur_row, i);
			pg_sock->row[i] = (char *)rad_malloc(len+1);
			memset(pg_sock->row[i], '\0', len+1);
			strlcpy(pg_sock->row[i], PQgetvalue(pg_sock->result, pg_sock->cur_row,i),len + 1);
		}
		pg_sock->cur_row++;
		sqlsocket->row = pg_sock->row;
	}

	return 0;
}

/*************************************************************************
 *
 *      Function: sql_num_fields
 *
 *      Purpose: database specific num_fields. Returns number of rows in
 *               query
 *
 *************************************************************************/
static int sql_num_fields(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
        rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;
        
        pg_sock->affected_rows = PQntuples(pg_sock->result);
        if (pg_sock->result)
                return PQnfields(pg_sock->result);

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
static int sql_free_result(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config) {

	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;

	if (pg_sock->result) {
		PQclear(pg_sock->result);
		pg_sock->result = NULL;
	}

	free_result_row(pg_sock);

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
static const char *sql_error(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config) {

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
static int sql_close(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config) {

	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;

	if (!pg_sock->conn) return 0;

	/* PQfinish also frees the memory used by the PGconn structure */
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
static int sql_finish_query(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	return sql_free_result(sqlsocket, config);
}



/*************************************************************************
 *
 *	Function: sql_finish_select_query
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
static int sql_finish_select_query(SQLSOCK * sqlsocket, SQL_CONFIG *config) {

	return sql_free_result(sqlsocket, config);
}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: Return the number of rows affected by the last query.
 *
 *************************************************************************/
static int sql_affected_rows(SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config) {
	rlm_sql_postgres_sock *pg_sock = sqlsocket->conn;

	return pg_sock->affected_rows;
}


static int NEVER_RETURNS
not_implemented(UNUSED SQLSOCK * sqlsocket, UNUSED SQL_CONFIG *config)
{
	radlog(L_ERR, "sql_postgresql: calling unimplemented function");
	exit(1);
}


/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_postgresql = {
	"rlm_sql_postgresql",
	sql_init_socket,
	sql_destroy_socket,
	sql_query,
	sql_select_query,
	not_implemented, /* sql_store_result */
	sql_num_fields,
	not_implemented, /* sql_num_rows */
	sql_fetch_row,
	not_implemented, /* sql_free_result */
	sql_error,
	sql_close,
	sql_finish_query,
	sql_finish_select_query,
	sql_affected_rows,
};
