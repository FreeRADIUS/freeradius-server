/*
 * sql_postgresql.c		SQL Module
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

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>

#include        "radiusd.h"
#include        "rlm_sql.h"



/*************************************************************************
 *
 *      Function: sql_connect
 *
 *      Purpose: Connect to the sql server
 *
 *************************************************************************/
int sql_connect(void) {

        /* Connect to the database server */
        if (!(sql->AuthSock->conn = PQsetdbLogin(
                sql->config.sql_server,
                NULL,
                NULL,
                NULL,
                sql->config.sql_db,
                sql->config.sql_login,
                sql->config.sql_password))) {
             radlog(L_ERR, "Init: Couldn't connect authentication socket to Postgres SQL server on %s as %s",
                        sql->config.sql_server, sql->config.sql_login);
             sql->AuthSock->conn = NULL;
        }
        if (!(sql->AcctSock->conn = PQsetdbLogin(
                sql->config.sql_server,
                NULL,
                NULL,
                NULL,
                sql->config.sql_db,
                sql->config.sql_login,
                sql->config.sql_password))) {
             radlog(L_ERR, "Init: Couldn't connect accounting socket to Postgres SQL server on %s as %s",
                        sql->config.sql_server, sql->config.sql_login);
             sql->AcctSock->conn = NULL;
        }
           
       return 0;
}

 

/*************************************************************************
 *
 *      Function: sql_checksocket
 *
 *      Purpose: Make sure our database connection is up
 *
 *************************************************************************/
int sql_checksocket(const char *facility) {
        if ((strncmp(facility, "Auth", 4) == 0)) {
                if (sql->AuthSock->conn == NULL) {
                        if (sql->config.sql_keepopen)
                                radlog(L_ERR, "%s: Keepopen set but had to reconnect to Postgres SQL", facility);
                        /* Connect to the database server */
                        if (!(sql->AuthSock->conn = PQsetdbLogin(
                                sql->config.sql_server,
                                NULL,
                                NULL,
                                NULL,
                                sql->config.sql_login,
                                sql->config.sql_password,
                                sql->config.sql_db))) {
                                radlog(L_ERR, "Auth: Couldn't connect authentication socket to Postgres SQL server on %s as %s",
                                sql->config.sql_server, sql->config.sql_login);
                                sql->AuthSock->conn = NULL;
                                return 0;
                        }
                }
        } else {
                if (sql->AcctSock->conn == NULL) {
                        if (sql->config.sql_keepopen)
                                radlog(L_ERR, "%s: Keepopen set but had to reconnect to Postgres SQL", facility);
                        /* Connect to the database ******/
SQL_ROW sql_fetch_row(SQLSOCK *socket) {
        int fields,tuples;
        int i,j;
        char *key,*value;

        tuples = PQntuples(socket->result);
        fields = PQnfields(socket->result);
        for(i=0;i<tuples;i++) {
                for(j=0;j<fields;j++) {
                        value = PQgetvalue(socket->result,i,j);
                        key = PQfname(j);
                        /* what now we have no row structure to insert into? */
                }
        }
        return NULL; /* ? */

}



/*************************************************************************
 *
 *      Function: sql_free_result
 *
 *      Purpose: database specific free_result. Frees memory allocated
 *               for a result set
 *
 *************************************************************************/
void sql_free_result(SQLSOCK *socket) {

   PQclear(socket->result);

}



/*************************************************************************
 *
 *      Function: sql_error
 *
 *      Purpose: database specific error. Returns error associated with
 *               connection
 *
 *************************************************************************/
char *sql_error(SQLSOCK *socket) {

        radlog(L_ERR,"PQSQL error: %s",PQerrorMessage(socket->conn));

}


/*************************************************************************
 *
 *      Function: sql_close
 *
 *      Purpose: database specific close. Closes an open database
 *               connection
 *
 *************************************************************************/
void sql_close(SQLSOCK *socket) {

   PQfinish(socket->conn);

}


/*************************************************************************
 *
 *      Function: sql_finish_query
 *
 *      Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
void sql_finish_query(SQLSOCK *socket) {

        PQclear(socket->result);

}



/*************************************************************************
 *
 *      Function: sql_finish_select_query
 *
 *      Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
void sql_finish_select_query(SQLSOCK *socket) {

   PQclear(socket->result);
}


/*************************************************************************
 *
 *      Function: sql_affected_rows
 *
 *      Purpose: End the select quh as freeing memory or result
 *
 *************************************************************************/
int sql_affected_rows(SQLSOCK *socket) {
   int rows;

        rows = PQntuples(socket->result);
        return rows;
}


