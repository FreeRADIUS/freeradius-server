/*
 * Sybase ctlib definitions and local datastructure(s)
 */

#include <ctpublic.h>
#include "rlm_sql.h"


typedef struct rlm_sql_sybase_sock {
	CS_CONTEXT	*context;
	CS_CONNECTION	*connection;
	CS_COMMAND	*command;
	char		**results;
	int		id;
	int		in_use;
	struct timeval	tv;
} rlm_sql_sybase_sock;

int	sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int	sql_destroy_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int     sql_checksocket(const char *facility);
int	sql_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr);
int	sql_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr);
int	sql_store_result(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int	sql_num_fields(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int	sql_num_rows(SQLSOCK * sqlsocket, SQL_CONFIG *config);
SQL_ROW	sql_fetch_row(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int	sql_free_result(SQLSOCK * sqlsocket, SQL_CONFIG *config);
char	*sql_error(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int	sql_close(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int	sql_finish_query(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int	sql_finish_select_query(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int	sql_affected_rows(SQLSOCK * sqlsocket, SQL_CONFIG *config);
