/*****************************************************
 * rlm_sql IBM DB2 driver                            *
 *                                                   *
 *****************************************************/

#include <sql.h>
#include <sqlcli.h>
#include "rlm_sql.h"

typedef struct rlm_sql_db2_sock {
	SQLHANDLE hdbc;
	SQLHANDLE henv;
	SQLHANDLE stmt;
} rlm_sql_db2_sock;


int sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int sql_destroy_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int sql_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr);
int sql_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr);
int sql_store_result(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int sql_num_fields(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int sql_num_rows(SQLSOCK * sqlsocket, SQL_CONFIG *config);
SQL_ROW sql_fetch_row(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int sql_free_result(SQLSOCK * sqlsocket, SQL_CONFIG *config);
char *sql_error(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int sql_close(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int sql_finish_query(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int sql_finish_select_query(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int sql_affected_rows(SQLSOCK * sqlsocket, SQL_CONFIG *config);
