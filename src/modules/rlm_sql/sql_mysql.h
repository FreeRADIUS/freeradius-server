/*
 * sql_module.h - MySQL header for FreeRADIUS SQL module
 *
 * Mike Machado <mike@innercite.com>
 */

#include	<mysql/mysql.h>

typedef MYSQL_ROW	SQL_ROW;
typedef MYSQL_RES	SQL_RES;

typedef struct {
	MYSQL		*conn;
	MYSQL_RES	*result;
} SQLSOCK;


int sql_connect(void);
int sql_checksocket(const char *facility);
int sql_query(SQLSOCK *socket, char *querystr);
int sql_select_query(SQLSOCK *socket, char *querystr);
int sql_store_result(SQLSOCK *socket);
int sql_num_fields(SQLSOCK *socket);
int sql_num_rows(SQLSOCK *socket);
SQL_ROW sql_fetch_row(SQLSOCK *socket);
void sql_free_result(SQLSOCK *socket);
char *sql_error(SQLSOCK *socket);
void sql_close(SQLSOCK *socket);
void sql_finish_query(SQLSOCK *socket);
void sql_finish_select_query(SQLSOCK *socket);
int sql_affected_rows(SQLSOCK *socket);
char *sql_escape_string(const char *from);
