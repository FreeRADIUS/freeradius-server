/*
 * sql_module.c	- MySQL routines for FreeRADIUS SQL module 
 *
 * Mike Machado <mike@innercite.com>
 */

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>

#include 	"radiusd.h"
#include	"rlm_sql.h"


/*************************************************************************
 *
 *	Function: sql_connect
 *
 *	Purpose: Connect to the sql server
 *
 *************************************************************************/
int sql_connect(void) {

	MYSQL MyAuthConn;
	MYSQL MyAcctConn;

        /* Connect to the database server */
        mysql_init(&MyAuthConn);
        if (!(sql->AuthSock->conn = mysql_real_connect(&MyAuthConn, sql->config.sql_server, sql->config.sql_login, sql->config.sql_password, sql->config.sql_db, 0, NULL, 0))) {
             log(L_ERR, "Init: Couldn't connect authentication socket to MySQL server on %s as %s", sql->config.sql_server, sql->config.sql_login);
             sql->AuthSock->conn = NULL;
        }
        mysql_init(&MyAcctConn);
        if (!(sql->AcctSock->conn = mysql_real_connect(&MyAcctConn, sql->config.sql_server, sql->config.sql_login, sql->config.sql_password, sql->config.sql_db, 0, NULL, 0))) {
             log(L_ERR, "Init: Couldn't connect accounting socket to MySQL server on %s as %s", sql->config.sql_server, sql->config.sql_login);
             sql->AcctSock->conn = NULL;
        }
           
       return 0;
}

 

/*************************************************************************
 *
 *	Function: sql_checksocket
 *
 *	Purpose: Make sure our database connection is up
 *
 *************************************************************************/
int sql_checksocket(const char *facility) {

	if ((strncmp(facility, "Auth", 4) == 0)) {
		if (sql->AuthSock->conn == NULL) {

			MYSQL MyAuthConn;
			if (sql->config.sql_keepopen)
				log(L_ERR, "%s: Keepopen set but had to reconnect to MySQL", facility);
			/* Connect to the database server */
			mysql_init(&MyAuthConn);
			if (!(sql->AuthSock->conn = mysql_real_connect(&MyAuthConn, sql->config.sql_server, sql->config.sql_login, sql->config.sql_password, sql->config.sql_db, 0, NULL, 0))) {
				log(L_ERR, "Auth: Couldn't connect authentication socket to MySQL server on %s as %s", sql->config.sql_server, sql->config.sql_login);
				sql->AuthSock->conn = NULL;
				return 0;
			}
		}

	} else {
		if (sql->AcctSock->conn == NULL) {
			MYSQL MyAcctConn;
			if (sql->config.sql_keepopen)
				log(L_ERR, "%s: Keepopen set but had to reconnect to MySQL", facility);
			/* Connect to the database server */
			mysql_init(&MyAcctConn);
			if (!(sql->AcctSock->conn = mysql_real_connect(&MyAcctConn, sql->config.sql_server, sql->config.sql_login, sql->config.sql_password, sql->config.sql_db, 0, NULL, 0))) {
				log(L_ERR, "Acct: Couldn't connect accounting socket to MySQL server on %s as %s", sql->config.sql_server, sql->config.sql_login);
				sql->AcctSock->conn = NULL;
				return 0;
			}
		}

	}

	return 1;

}


/*************************************************************************
 *
 *	Function: sql_query
 *
 *	Purpose: Issue a query to the database
 *
 *************************************************************************/
int sql_query(SQLSOCK *socket, char *querystr) {

 if (sql->config.sqltrace)
	DEBUG(querystr);
 return mysql_query(socket->conn, querystr);

}


/*************************************************************************
 *
 *	Function: sql_select_query
 *
 *	Purpose: Issue a select query to the database
 *
 *************************************************************************/
int sql_select_query(SQLSOCK *socket, char *querystr) {

 if (sql->config.sqltrace)
	DEBUG(querystr);
 mysql_query(socket->conn, querystr);
 if (sql_store_result(socket) && sql_num_fields(socket)) 
	return 0;
 else
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

	if (!(socket->result = mysql_store_result(socket->conn))) {
		log(L_ERR,"MYSQL Error: Cannot get result");
		log(L_ERR,"MYSQL error: %s",mysql_error(socket->conn));
		sql_close(socket);
		return 0;
	}
	return 1;

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

	int	num = 0;
	if (!(num = mysql_num_fields(socket->conn))) {
		log(L_ERR,"MYSQL Error: Cannot get result");
		log(L_ERR,"MYSQL error: %s",mysql_error(socket->conn));
		sql_close(socket);
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
int sql_num_rows(SQLSOCK *socket) {

    return mysql_num_rows(socket->result);

}


/*************************************************************************
 *
 *	Function: sql_fetch_row
 *
 *	Purpose: database specific fetch_row. Returns a SQL_RES struct
 *               with all the data for the query
 *
 *************************************************************************/
SQL_ROW sql_fetch_row(SQLSOCK *socket) {

   return mysql_fetch_row(socket->result);

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

   mysql_free_result(socket->result);

}



/*************************************************************************
 *
 *	Function: sql_error
 *
 *	Purpose: database specific error. Returns error associated with
 *               connection
 *
 *************************************************************************/
char *sql_error(SQLSOCK *socket) {

  return (mysql_error(socket->conn));

}


/*************************************************************************
 *
 *	Function: sql_close
 *
 *	Purpose: database specific close. Closes an open database
 *               connection
 *
 *************************************************************************/
void sql_close(SQLSOCK *socket) {

   mysql_close(socket->conn);

}


/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
void sql_finish_query(SQLSOCK *socket) {

}



/*************************************************************************
 *
 *	Function: sql_finish_select_query
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
void sql_finish_select_query(SQLSOCK *socket) {

   sql_free_result(socket);
}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: End the select quh as freeing memory or result
 *
 *************************************************************************/
int sql_affected_rows(SQLSOCK *socket) {
   int rows;

   rows = mysql_affected_rows(socket->conn);
   return rows;
}
