/***************************************************************************
*  iODBC support for FreeRadius
*  www.iodbc.org   - iODBC info
*  Jeff Carneal    - Author
***************************************************************************/
#include <isql.h>
#include <isqlext.h>
#include <sqltypes.h>
#include "rlm_sql.h"

typedef char** SQL_ROW;

typedef struct rlm_sql_iodbc_sock {
	HENV    env_handle;
	HDBC    dbc_handle;
	HSTMT   stmt_handle;
	int		id;
	SQL_ROW row;
	
	struct sql_socket *next;

	viod	*conn;
} rlm_sql_iodbc_sock;;


int	sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int	sql_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr);
int	sql_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr);
int	sql_store_result(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int	sql_num_fields(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int	sql_num_rows(SQLSOCK *sqlsocket, SQL_CONFIG *config);
SQL_ROW sql_fetch_row(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int	sql_free_result(SQLSOCK *sqlsocket, SQL_CONFIG *config);
char	*sql_error(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int	sql_close(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int	sql_finish_query(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int	sql_finish_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int	sql_affected_rows(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int	sql_escape_string(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *to, char *from, int length);
