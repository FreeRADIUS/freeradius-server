/***************************************************************************
*  sql_module.h                       rlm_sql - FreeRADIUS SQL Module      *
*                                                                          *
*      MySQL headers for rlm_sql                                           *
*                                                                          *
*                                     Mike Machado <mike@innercite.com>    *
***************************************************************************/
#if HAVE_PTHREAD_H
#include	<pthread.h>
#include	<semaphore.h>
#endif
#include	<mysql/mysql.h>
#include	"conf.h"

typedef MYSQL_ROW SQL_ROW;

typedef struct sql_socket {
	int     id;
#if HAVE_PTHREAD_H
	sem_t  *semaphore;
#else
	int     in_use;
#endif
	struct sql_socket *next;

	MYSQL  *sock;
	MYSQL   conn;
	MYSQL_RES *result;
} SQLSOCK;

typedef struct sql_inst {
	int     used;
	SQLSOCK *sqlpool;
	SQL_CONFIG *config;
#if HAVE_PTHREAD_H
	pthread_mutex_t *lock;
	pthread_cond_t *notfull;
#endif
} SQL_INST;

SQLSOCK *sql_create_socket(SQL_INST * inst);
int     sql_checksocket(const char *facility);
int     sql_query(SQL_INST * inst, SQLSOCK * sqlsocket, char *querystr);
int     sql_select_query(SQL_INST * inst, SQLSOCK * sqlsocket,
												 char *querystr);
int     sql_store_result(SQLSOCK * sqlsocket);
int     sql_num_fields(SQLSOCK * sqlsocket);
int     sql_num_rows(SQLSOCK * sqlsocket);
SQL_ROW sql_fetch_row(SQLSOCK * sqlsocket);
void    sql_free_result(SQLSOCK * sqlsocket);
char   *sql_error(SQLSOCK * sqlsocket);
void    sql_close(SQLSOCK * sqlsocket);
void    sql_finish_query(SQLSOCK * sqlsocket);
void    sql_finish_select_query(SQLSOCK * sqlsocket);
int     sql_affected_rows(SQLSOCK * sqlsocket);
int     sql_escape_string(char *to, char *from, int length);
