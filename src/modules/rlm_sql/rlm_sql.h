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

#include	<freeradius-devel/connection.h>
#include	<freeradius-devel/modpriv.h>

#include "conf.h"

#define PW_ITEM_CHECK		0
#define PW_ITEM_REPLY		1

typedef char** SQL_ROW;

/*
 *  Sections where we dynamically resolve the config entry to use,
 *  by xlating reference.
 */
typedef struct sql_acct_section {
	CONF_SECTION	*cs;
	
	const char *reference;
	
	const char *logfile;
} sql_acct_section_t;

typedef struct sql_config {
	const char 	*xlat_name;

	const char 	*sql_driver;
	const char 	*sql_server;
	const char 	*sql_port;
	const char 	*sql_login;
	const char 	*sql_password;
	const char 	*sql_db;
	const char 	*sql_file;	/* for sqlite */

	
	const char	*query_user;
	const char	*default_profile;
	
	const char	*nas_query;
	const char	*authorize_check_query;
	const char 	*authorize_reply_query;
	const char	*authorize_group_check_query;
	const char	*authorize_group_reply_query;
	const char	*simul_count_query;
	const char	*simul_verify_query;
	const char 	*groupmemb_query;
	
	int const	do_clients;
	int const	read_groups;
	const char	*logfile;

	int const	deletestalesessions;
	const char	*allowed_chars;
	int const	query_timeout;
	void		*localcfg;	/* individual driver config */
	
	/* 
	 * TODO: The rest of the queries should also be moved into their own
	 * sections.
	 */
	
	/* Section configurations */
	sql_acct_section_t	*postauth;
	sql_acct_section_t	*accounting;
} SQL_CONFIG;

typedef struct sql_socket {
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
	fr_connection_pool_t *pool;
	SQL_CONFIG	*config;
	CONF_SECTION	*cs;

	const DICT_ATTR	*sql_user;	//!< Cached pointer to SQL-User-Name
					//!< dictionary attribute.
					
	lt_dlhandle handle;
	rlm_sql_module_t *module;

	int (*sql_set_user)(SQL_INST *inst, REQUEST *request, const char *username);
	SQLSOCK *(*sql_get_socket)(SQL_INST * inst);
	int (*sql_release_socket)(SQL_INST * inst, SQLSOCK * sqlsocket);
	size_t (*sql_escape_func)(REQUEST *, char *out, size_t outlen, const char *in, void *arg);
	int (*sql_query)(SQLSOCK **sqlsocket, SQL_INST *inst, char *query);
	int (*sql_select_query)(SQLSOCK **sqlsocket, SQL_INST *inst, char *query);
	int (*sql_fetch_row)(SQLSOCK **sqlsocket, SQL_INST *inst);
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
int     sql_getvpdata(SQL_INST * inst, SQLSOCK ** sqlsocket, VALUE_PAIR **pair, char *query);
int     sql_read_naslist(SQLSOCK * sqlsocket);
int     sql_read_clients(SQLSOCK * sqlsocket);
int     sql_dict_init(SQLSOCK * sqlsocket);
void 	rlm_sql_query_log(SQL_INST *inst, REQUEST *request,
	       		  sql_acct_section_t *section, char *querystr);
int	rlm_sql_select_query(SQLSOCK **sqlsocket, SQL_INST *inst, char *query);
int	rlm_sql_query(SQLSOCK **sqlsocket, SQL_INST *inst, char *query);
int	rlm_sql_fetch_row(SQLSOCK **sqlsocket, SQL_INST *inst);
int	sql_set_user(SQL_INST *inst, REQUEST *request, const char *username);
#endif
