/***************************************************************************
*  rlm_sql.h                          rlm_sql - FreeRADIUS SQL Module      *
*                                                                          *
*      Header for main SQL module file                                     *
*                                                                          *
*                                     Mike Machado <mike@innercite.com>    *
***************************************************************************/
#if HAVE_PTHREAD_H
#include        <pthread.h>
#include        <semaphore.h>
#endif

#include <ltdl.h>

#include "conf.h"
#include "conffile.h"

#define SQLSOCK_LOCKED		0
#define SQLSOCK_UNLOCKED	1

#define PW_VP_USERDATA		1
#define PW_VP_GROUPDATA		2
#define PW_VP_REALMDATA		3

#define PW_ITEM_CHECK			0
#define PW_ITEM_REPLY			1

typedef char** SQL_ROW;

typedef struct sql_socket {
	int     id;
#if HAVE_PTHREAD_H
	sem_t  *semaphore;
#else
	int     in_use;
#endif
	struct sql_socket *next;

	void	*conn;
} SQLSOCK;

typedef struct rlm_sql_module_t {
	const char *name;
	int (*sql_init_socket)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_destroy_socket)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_query)(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *query);
	int (*sql_select_query)(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *query);
	int (*sql_store_result)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_num_fields)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_num_rows)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	SQL_ROW (*sql_fetch_row)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_free_result)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	char *(*sql_error)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_close)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_finish_query)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_finish_select_query)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_affected_rows)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_escape_string)(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *to, char *from, int length);
} rlm_sql_module_t;

typedef struct sql_inst {
	int		used;
	SQLSOCK		*sqlpool;
	SQL_CONFIG	*config;
#if HAVE_PTHREAD_H
	pthread_mutex_t	*lock;
	pthread_cond_t	*notfull;
#endif

	rlm_sql_module_t *module;
} SQL_INST;


int     sql_init_socketpool(SQL_INST * inst);
void    sql_poolfree(SQL_INST * inst);
int     sql_close_socket(SQL_INST *inst, SQLSOCK * sqlsocket);
SQLSOCK *sql_get_socket(SQL_INST * inst);
int     sql_release_socket(SQL_INST * inst, SQLSOCK * sqlsocket);
int     sql_userparse(VALUE_PAIR ** first_pair, SQL_ROW row, int mode, int itemtype);
int     sql_read_realms(SQLSOCK * sqlsocket);
int     sql_getvpdata(SQL_INST * inst, SQLSOCK * sqlsocket, VALUE_PAIR ** check, VALUE_PAIR ** reply, char *query, int mode);
int     sql_check_multi(SQL_INST * inst, SQLSOCK * sqlsocket, char *name, VALUE_PAIR * request, int maxsimul);
int     sql_read_naslist(SQLSOCK * sqlsocket);
int     sql_read_clients(SQLSOCK * sqlsocket);
int     sql_dict_init(SQLSOCK * sqlsocket);
void    query_log(SQL_INST * inst, char *querystr);
VALUE_PAIR *set_userattr(SQL_INST *inst, SQLSOCK *sqlsocket, VALUE_PAIR * first, char *username, char *saveuser, int *savelen);
void    restore_userattr(VALUE_PAIR * uservp, char *saveuser, int savelen);
