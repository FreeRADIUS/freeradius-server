/************************************************************************** 
 *	sql_unixodbc.h	unixODBC headers for rlm_sql                      * 
 *                                                                        * 
 *                                                                        * 
 *                      Dmitri Ageev <d_ageev@ortcc.ru>                   * 
 **************************************************************************/
 
#ifndef SQL_UNIXODBC_H
#define SQL_UNIXODBC_H

#include <sql.h>
#include <sqlext.h>
#include <sqltypes.h>
#include "rlm_sql.h"

typedef struct rlm_sql_unixodbc_sock {
	SQLHENV env_handle;
	SQLHDBC dbc_handle;
	SQLHSTMT stmt_handle;
	SQL_ROW row;
	void *conn;
} rlm_sql_unixodbc_sock;;


SQLSOCK *sql_create_socket(SQL_INST *inst);
int	sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int	sql_destroy_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config);
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

#endif /* SQL_UNIXODBC_H */
