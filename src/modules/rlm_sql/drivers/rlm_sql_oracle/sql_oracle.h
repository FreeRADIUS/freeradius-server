/*
 * $Id$
 *
 * Oracle 8i OCI interface abstraction definitions and structures.
 */
#ifndef SQL_ORACLE_H
#define SQL_ORACLE_H

#include <oci.h>
#include "rlm_sql.h"

typedef char**	SQL_ROW;

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

<<<<<<< sql_oracle.h
typedef struct sql {
	SQL_CONFIG *config;
	SQLSOCK *sqlpool;
#if HAVE_PTHREAD_H
	pthread_mutex_t *lock;
	pthread_cond_t *notfull;
#endif
} SQL_INST;
 
SQLSOCK *sql_create_socket(SQL_INST *inst);
int     sql_checksocket(const char *facility);
int     sql_query(SQL_INST *inst, SQLSOCK * socket, char *querystr);
int     sql_select_query(SQL_INST *inst, SQLSOCK * socket, char *querystr);
int     sql_store_result(SQLSOCK * socket);
int     sql_num_fields(SQLSOCK * socket);
int     sql_num_rows(SQLSOCK * socket);
SQL_ROW sql_fetch_row(SQLSOCK * socket);
void    sql_free_result(SQLSOCK * socket);
char   *sql_error(SQLSOCK * socket);
void    sql_close(SQLSOCK * socket);
void    sql_finish_query(SQLSOCK * socket);
void    sql_finish_select_query(SQLSOCK * socket);
int     sql_affected_rows(SQLSOCK * socket);
/*
 * Unused.  Now provided in rlm_sql main module.
 * But left in here just in case...
 *
int     sql_escape_string(char *to, char *from, int length);
 */
#endif /* SQL_ORACLE_H */
