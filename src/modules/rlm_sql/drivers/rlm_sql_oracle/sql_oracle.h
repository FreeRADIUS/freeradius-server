/*
 * $Id$
 *
 * Oracle 8i OCI interface abstraction definitions and structures.
 */
#ifndef SQL_ORACLE_H
#define SQL_ORACLE_H

#include <oci.h>
#include "rlm_sql.h"

//typedef char**	SQL_ROW;

typedef struct rlm_sql_oracle_sock {
	OCIEnv		*env;
	OCIError	*errHandle;
	OCISvcCtx	*conn;
	OCIStmt		*queryHandle;
	char		**results;
	int		id;
	int		in_use;
	struct timeval	tv;
} rlm_sql_oracle_sock;

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

/*
 * Unused.  Now provided in rlm_sql main module.
 * But left in here just in case...
 *
int     sql_escape_string(char *to, char *from, int length);
 */
#endif /* SQL_ORACLE_H */
