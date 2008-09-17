/***************************************************************************
*  rlm_sql.h                          rlm_sql - FreeRADIUS SQL Module      *
*                                                                          *
*      Header for main SQL module file                                     *
*                                                                          *
*                                     Mike Machado <mike@innercite.com>    *
***************************************************************************/
#ifndef _RLM_SQL_H
#define _RLM_SQL_H

#include <freeradius-devel/ident.h>
RCSIDH(rlm_sql_h, "$Id$")

#ifdef HAVE_PTHREAD_H
#include        <pthread.h>
#endif

#include	<ltdl.h>

#include "conf.h"

#define SQLSOCK_LOCKED		0
#define SQLSOCK_UNLOCKED	1

#define PW_ITEM_CHECK			0
#define PW_ITEM_REPLY			1

typedef char** SQL_ROW;

typedef struct sql_socket {
	int     id;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t mutex;
#endif
	struct sql_socket *next;
	enum { sockconnected, sockunconnected } state;

	void	*conn;
	SQL_ROW row;
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
	int (*sql_fetch_row)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_free_result)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	const char *(*sql_error)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_close)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_finish_query)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_finish_select_query)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
	int (*sql_affected_rows)(SQLSOCK *sqlsocket, SQL_CONFIG *config);
} rlm_sql_module_t;

typedef struct sql_inst SQL_INST;

struct sql_inst {
	time_t		connect_after;
	SQLSOCK		*sqlpool;
	SQLSOCK		*last_used;
	SQL_CONFIG	*config;

	lt_dlhandle handle;
	rlm_sql_module_t *module;

	int (*sql_set_user)(SQL_INST *inst, REQUEST *request, char *sqlusername, const char *username);
	SQLSOCK *(*sql_get_socket)(SQL_INST * inst);
	int (*sql_release_socket)(SQL_INST * inst, SQLSOCK * sqlsocket);
	size_t (*sql_escape_func)(char *out, size_t outlen, const char *in);
};

typedef struct sql_grouplist {
	char			groupname[MAX_STRING_LEN];
	struct sql_grouplist	*next;
} SQL_GROUPLIST;


int     sql_init_socketpool(SQL_INST * inst);
void    sql_poolfree(SQL_INST * inst);
int     sql_close_socket(SQL_INST *inst, SQLSOCK * sqlsocket);
SQLSOCK *sql_get_socket(SQL_INST * inst);
int     sql_release_socket(SQL_INST * inst, SQLSOCK * sqlsocket);
int     sql_userparse(VALUE_PAIR ** first_pair, SQL_ROW row);
int     sql_read_realms(SQLSOCK * sqlsocket);
int     sql_getvpdata(SQL_INST * inst, SQLSOCK * sqlsocket, VALUE_PAIR **pair, char *query);
int     sql_read_naslist(SQLSOCK * sqlsocket);
int     sql_read_clients(SQLSOCK * sqlsocket);
int     sql_dict_init(SQLSOCK * sqlsocket);
void    query_log(REQUEST *request, SQL_INST * inst, char *querystr);
int	rlm_sql_select_query(SQLSOCK *sqlsocket, SQL_INST *inst, char *query);
int	rlm_sql_query(SQLSOCK *sqlsocket, SQL_INST *inst, char *query);
int	rlm_sql_fetch_row(SQLSOCK *sqlsocket, SQL_INST *inst);
int	sql_set_user(SQL_INST *inst, REQUEST *request, char *sqlusername, const char *username);
#endif
