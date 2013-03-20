/***************************************************************************
* rlm_sql.h			  rlm_sql - FreeRADIUS SQL Module      *
*									 *
*     Header for main SQL module file				     *
*									 *
*				    Mike Machado <mike@innercite.com>    *
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

typedef char** rlm_sql_row_t;

/*
 * Sections where we dynamically resolve the config entry to use,
 * by xlating reference.
 */
typedef struct sql_acct_section {
	CONF_SECTION	*cs;
	
	const char	*reference;
	
	const char	*logfile;
} sql_acct_section_t;

typedef struct sql_config {
	const char 	*xlat_name;

	const char 	*sql_driver_name;
	const char 	*sql_server;
	const char 	*sql_port;
	const char 	*sql_login;
	const char 	*sql_password;
	const char 	*sql_db;
	const char 	*sql_file;	/*for sqlite */

	
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
	
	void		*driver;	//!< Where drivers should write a
					//!< pointer to their configurations.
	
	/*
	 *	@todo The rest of the queries should also be moved into
	 *	their own sections.
	 */
	
	/*
	 *	Section configurations
	 */
	sql_acct_section_t	*postauth;
	sql_acct_section_t	*accounting;
} rlm_sql_config_t;

typedef struct sql_inst rlm_sql_t;

typedef struct rlm_sql_handle {
	void	*conn;
	rlm_sql_row_t row;
	rlm_sql_t *inst;
} rlm_sql_handle_t;

typedef struct rlm_sql_module_t {
	const char *name;

	int (*mod_instantiate)(CONF_SECTION *conf, rlm_sql_config_t *config);	
	int (*sql_socket_init)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	int (*sql_query)(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char *query);
	int (*sql_select_query)(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char *query);
	int (*sql_store_result)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	int (*sql_num_fields)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	int (*sql_num_rows)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	int (*sql_fetch_row)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	int (*sql_free_result)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	const char *(*sql_error)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	int (*sql_finish_query)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	int (*sql_finish_select_query)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	int (*sql_affected_rows)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
} rlm_sql_module_t;

struct sql_inst {
	fr_connection_pool_t	*pool;
	rlm_sql_config_t	*config;
	CONF_SECTION		*cs;

	const DICT_ATTR		*sql_user;	//!< Cached pointer to SQL-User-Name
						//!< dictionary attribute.
					
	void *handle;
	rlm_sql_module_t *module;

	int (*sql_set_user)(rlm_sql_t *inst, REQUEST *request, const char *username);
	rlm_sql_handle_t *(*sql_get_socket)(rlm_sql_t *inst);
	int (*sql_release_socket)(rlm_sql_t *inst, rlm_sql_handle_t *handle);
	size_t (*sql_escape_func)(REQUEST *, char *out, size_t outlen, const char *in, void *arg);
	int (*sql_query)(rlm_sql_handle_t **handle, rlm_sql_t *inst, char *query);
	int (*sql_select_query)(rlm_sql_handle_t **handle, rlm_sql_t *inst, char *query);
	int (*sql_fetch_row)(rlm_sql_handle_t **handle, rlm_sql_t *inst);
};

typedef struct sql_grouplist {
	char			name[MAX_STRING_LEN];
	struct sql_grouplist	*next;
} rlm_sql_grouplist_t;

int     sql_socket_pool_init(rlm_sql_t *inst);
void    sql_poolfree(rlm_sql_t *inst);
int     sql_close_socket(rlm_sql_t *inst, rlm_sql_handle_t *handle);
rlm_sql_handle_t *sql_get_socket(rlm_sql_t *inst);
int     sql_release_socket(rlm_sql_t *inst, rlm_sql_handle_t *handle);
int     sql_userparse(TALLOC_CTX *ctx, VALUE_PAIR **first_pair, rlm_sql_row_t row);
int     sql_read_realms(rlm_sql_handle_t *handle);
int     sql_getvpdata(rlm_sql_t *inst, rlm_sql_handle_t **handle, TALLOC_CTX *ctx, VALUE_PAIR **pair, char *query);
int     sql_read_naslist(rlm_sql_handle_t *handle);
int     sql_read_clients(rlm_sql_handle_t *handle);
int     sql_dict_init(rlm_sql_handle_t *handle);
void 	rlm_sql_query_log(rlm_sql_t *inst, REQUEST *request,
	       		  sql_acct_section_t *section, char *querystr);
int	rlm_sql_select_query(rlm_sql_handle_t **handle, rlm_sql_t *inst, char *query);
int	rlm_sql_query(rlm_sql_handle_t **handle, rlm_sql_t *inst, char *query);
int	rlm_sql_fetch_row(rlm_sql_handle_t **handle, rlm_sql_t *inst);
int	sql_set_user(rlm_sql_t *inst, REQUEST *request, const char *username);
#endif
