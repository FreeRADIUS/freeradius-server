/***************************************************************************
* rlm_sql.h			  rlm_sql - FreeRADIUS SQL Module      *
*									 *
*     Header for main SQL module file				     *
*									 *
*				    Mike Machado <mike@innercite.com>    *
***************************************************************************/
#ifndef _RLM_SQL_H
#define _RLM_SQL_H

RCSIDH(rlm_sql_h, "$Id$")

#include	<freeradius-devel/radiusd.h>
#include	<freeradius-devel/connection.h>
#include	<freeradius-devel/modpriv.h>

#define PW_ITEM_CHECK		0
#define PW_ITEM_REPLY		1


/* SQL Errors */
typedef enum {
	RLM_SQL_QUERY_ERROR = -3,	//!< Query syntax error
	RLM_SQL_ERROR = -2,		//!< General connection/server error
	RLM_SQL_OK = 0,			//!< Success
	RLM_SQL_RECONNECT = 1,		//!< Stale connection, should reconnect
	RLM_SQL_DUPLICATE = 2		//!< Key constraint violation
} sql_rcode_t;

typedef enum {
	FALL_THROUGH_DEFAULT = 0,
	FALL_THROUGH_YES,
	FALL_THROUGH_NO
} sql_fall_through_t;


typedef char **rlm_sql_row_t;

/*
 * Sections where we dynamically resolve the config entry to use,
 * by xlating reference.
 */
typedef struct sql_acct_section {
	CONF_SECTION	*cs;

	char const	*reference;

	char const	*logfile;
} sql_acct_section_t;

typedef struct sql_config {
	char const 	*xlat_name;

	char const 	*sql_driver_name;
	char const 	*sql_server;
	char const 	*sql_port;
	char const 	*sql_login;
	char const 	*sql_password;
	char const 	*sql_db;

	char const	*query_user;
	char const	*default_profile;

	char const	*client_query;

	char const	*open_query;
	char const	*authorize_check_query;
	char const 	*authorize_reply_query;
	char const	*authorize_group_check_query;
	char const	*authorize_group_reply_query;
	char const	*simul_count_query;
	char const	*simul_verify_query;
	char const 	*groupmemb_query;

	bool		do_clients;
	bool		read_groups;
	bool		read_profiles;
	char const	*logfile;

	bool		deletestalesessions;
	char const	*allowed_chars;
	uint32_t	query_timeout;

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
	void		*conn;	//!< Database specific connection handle.
	rlm_sql_row_t	row;	//!< Row data from the last query.
	rlm_sql_t	*inst;	//!< The rlm_sql instance this connection belongs to.
} rlm_sql_handle_t;

typedef struct rlm_sql_module_t {
	char const *name;

	sql_rcode_t (*mod_instantiate)(CONF_SECTION *conf, rlm_sql_config_t *config);
	sql_rcode_t (*sql_socket_init)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	sql_rcode_t (*sql_query)(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char const *query);
	sql_rcode_t (*sql_select_query)(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char const *query);
	sql_rcode_t (*sql_store_result)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	int (*sql_num_fields)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	int (*sql_num_rows)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	sql_rcode_t (*sql_fetch_row)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	sql_rcode_t (*sql_free_result)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	char const *(*sql_error)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	sql_rcode_t (*sql_finish_query)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	sql_rcode_t (*sql_finish_select_query)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	int (*sql_affected_rows)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
} rlm_sql_module_t;

struct sql_inst {
	rlm_sql_config_t	myconfig; /* HACK */
	fr_connection_pool_t	*pool;
	rlm_sql_config_t	*config;
	CONF_SECTION		*cs;

	DICT_ATTR const		*sql_user;	//!< Cached pointer to SQL-User-Name
						//!< dictionary attribute.
	fr_logfile_t		*lf;

	void *handle;
	rlm_sql_module_t *module;

	int (*sql_set_user)(rlm_sql_t *inst, REQUEST *request, char const *username);
	rlm_sql_handle_t *(*sql_get_socket)(rlm_sql_t *inst);
	int (*sql_release_socket)(rlm_sql_t *inst, rlm_sql_handle_t *handle);
	size_t (*sql_escape_func)(REQUEST *, char *out, size_t outlen, char const *in, void *arg);
	sql_rcode_t (*sql_query)(rlm_sql_handle_t **handle, rlm_sql_t *inst, char const *query);
	sql_rcode_t (*sql_select_query)(rlm_sql_handle_t **handle, rlm_sql_t *inst, char const *query);
	sql_rcode_t (*sql_fetch_row)(rlm_sql_handle_t **handle, rlm_sql_t *inst);
};

typedef struct sql_grouplist {
	char			*name;
	struct sql_grouplist	*next;
} rlm_sql_grouplist_t;

int		sql_socket_pool_init(rlm_sql_t *inst);
void		sql_poolfree(rlm_sql_t *inst);
int		sql_close_socket(rlm_sql_t *inst, rlm_sql_handle_t *handle);
rlm_sql_handle_t *sql_get_socket(rlm_sql_t *inst);
int		sql_release_socket(rlm_sql_t *inst, rlm_sql_handle_t *handle);
int		sql_userparse(TALLOC_CTX *ctx, VALUE_PAIR **first_pair, rlm_sql_row_t row);
int		sql_read_realms(rlm_sql_handle_t *handle);
int		sql_getvpdata(rlm_sql_t *inst, rlm_sql_handle_t **handle, TALLOC_CTX *ctx, VALUE_PAIR **pair, char const *query);
int		sql_read_naslist(rlm_sql_handle_t *handle);
int		sql_read_clients(rlm_sql_handle_t *handle);
int		sql_dict_init(rlm_sql_handle_t *handle);
void 		CC_HINT(nonnull (1, 2, 4)) rlm_sql_query_log(rlm_sql_t *inst, REQUEST *request, sql_acct_section_t *section, char const *query);
sql_rcode_t	CC_HINT(nonnull) rlm_sql_select_query(rlm_sql_handle_t **handle, rlm_sql_t *inst, char const *query);
sql_rcode_t	CC_HINT(nonnull) rlm_sql_query(rlm_sql_handle_t **handle, rlm_sql_t *inst, char const *query);
int		rlm_sql_fetch_row(rlm_sql_handle_t **handle, rlm_sql_t *inst);
int		sql_set_user(rlm_sql_t *inst, REQUEST *request, char const *username);
#endif
