#pragma once
/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file rlm_sql.h
 * @brief Prototypes and functions for the SQL module
 *
 * @copyright 2012-2014  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Mike Machado <mike@innercite.com>
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */
RCSIDH(rlm_sql_h, "$Id$")

#ifndef LOG_PREFIX
#  define LOG_PREFIX "rlm_sql (%s) - "
#  define LOG_PREFIX_ARGS inst->name
#endif

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/pool.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/exfile.h>

#define FR_ITEM_CHECK 0
#define FR_ITEM_REPLY 1


/* SQL Errors */
typedef enum {
	RLM_SQL_QUERY_INVALID = -3,	//!< Query syntax error.
	RLM_SQL_ERROR = -2,		//!< General connection/server error.
	RLM_SQL_OK = 0,			//!< Success.
	RLM_SQL_RECONNECT = 1,		//!< Stale connection, should reconnect.
	RLM_SQL_ALT_QUERY,		//!< Key constraint violation, use an alternative query.
	RLM_SQL_NO_MORE_ROWS,		//!< No more rows available
} sql_rcode_t;

typedef enum {
	FALL_THROUGH_NO = 0,
	FALL_THROUGH_YES,
	FALL_THROUGH_DEFAULT,
} sql_fall_through_t;


typedef char **rlm_sql_row_t;

typedef struct sql_log_entry {
	fr_log_type_t	type;		//!< Type of log entry L_ERR, L_WARN, L_INFO, L_DBG etc..
	char const	*msg;		//!< Log message.
} sql_log_entry_t;

/*
 * Sections where we dynamically resolve the config entry to use,
 * by xlating reference.
 */
typedef struct sql_acct_section {
	CONF_SECTION		*cs;				//!< The CONF_SECTION representing the group
								//!< of queries to process.

	char const		*reference;			//!< Reference string, expanded to point to
								//!< a group of queries.
	bool			reference_cp;

	char const		*logfile;

	char const		**query;			/* for xlat parsing */
} sql_acct_section_t;

typedef struct sql_config {
	char const 		*sql_driver_name;		//!< SQL driver module name e.g. rlm_sql_sqlite.
	char const 		*sql_server;			//!< Server to connect to.
	uint32_t 		sql_port;			//!< Port to connect to.
	char const 		*sql_login;			//!< Login credentials to use.
	char const 		*sql_password;			//!< Login password to use.
	char const 		*sql_db;			//!< Database to run queries against.

	char const		*query_user;			//!< xlat expansion used to specify the user
								//!< to use as the subject of queries.

	char const		*group_attribute;		//!< Name of the group attribute.

	char const		*default_profile;		//!< Default profile to use if no other
								//!< profiles were configured.

	char const		*authorize_check_query;		//!< Query used get check VPs for a user.
	char const 		*authorize_reply_query;		//!< Query used get reply VPs for a user.
	char const		*authorize_group_check_query;	//!< Query used get check VPs for a group.
	char const		*authorize_group_reply_query;	//!< Query used get reply VPs for a group.
	char const 		*groupmemb_query;		//!< Query to determine group membership.

	bool			read_groups;			//!< Read user groups by default.
								//!< If false, Fall-Through = yes is required
								//!< in the previous reply list to process
								//!< groups.
	bool			read_profiles;			//!< Read user profiles by default.
								//!< If false, Fall-Through = yes is required
								//!< in the previous reply list to process
								//!< profiles.
	char const		*logfile;			//!< Keep a log of all SQL queries executed
								//!< Useful for batch insertion with the
								//!< NULL drivers.

	char const		*allowed_chars;			//!< Chars which done need escaping..
	uint32_t		query_timeout;			//!< How long to allow queries to run for.

	char const		*connect_query;			//!< Query executed after establishing
								//!< new connection.

	void			*driver;			//!< Where drivers should write a
								//!< pointer to their configurations.

	/*
	 *	@todo The rest of the queries should also be moved into
	 *	their own sections.
	 */

	/*
	 *	Section configurations
	 */
	sql_acct_section_t	postauth;
	sql_acct_section_t	accounting;
} rlm_sql_config_t;

typedef struct sql_inst rlm_sql_t;

typedef struct rlm_sql_handle {
	void			*conn;				//!< Database specific connection handle.
	rlm_sql_row_t		row;				//!< Row data from the last query.
	rlm_sql_t const		*inst;				//!< The rlm_sql instance this connection belongs to.
	TALLOC_CTX		*log_ctx;			//!< Talloc pool used to avoid allocing memory
								//!< when log strings need to be copied.
} rlm_sql_handle_t;

extern const FR_NAME_NUMBER sql_rcode_table[];
/*
 *	Capabilities flags for drivers
 */
#define RLM_SQL_RCODE_FLAGS_ALT_QUERY	1			//!< Can distinguish between other errors and those
								//!< resulting from a unique key violation.

/** Retrieve errors from the last query operation
 *
 * @note Buffers allocated in the context provided will be automatically freed. The driver
 *	should not free these buffers explicitly.
 * @note If the driver uses its own buffers to aggregate messages, they should be cleared
 *	on sql_query_finish, and after each call to sql_error, to prevent the same messages
 *	being printed multiple times.
 *
 * @param[in,out] ctx to allocate any buffers required. If static buffers are provided by the
 *	driver they need not be talloc_strdupd, just write the pointer to those buffers to the
 *	.msg field of a sql_log_entry_t element.
 * @param[out] out a pre-allocated array of log entries to fill. Need not be NULL terminated.
 * @param[in] outlen Number of log entries available for populating. Do not write to index
 *	out[outlen] or higher.
 * @param[in] handle to retrieve errors from.
 * @param[in] config of the SQL instance.
 * @return
 *	0  - If no error messages are available.
 *	>0 - Number of log entries
 */
typedef size_t (*sql_error_t)(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen, rlm_sql_handle_t *handle,
			      rlm_sql_config_t *config);

typedef struct rlm_sql_driver_t {
	RAD_MODULE_COMMON;				//!< Common fields to all loadable modules.

	int		flags;

	sql_rcode_t (*mod_instantiate)(rlm_sql_config_t const *config, void *instance, CONF_SECTION *cs);
	sql_rcode_t (*sql_socket_init)(rlm_sql_handle_t *handle, rlm_sql_config_t *config,
				       struct timeval const *timeout);

	sql_rcode_t (*sql_query)(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char const *query);
	sql_rcode_t (*sql_select_query)(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char const *query);
	sql_rcode_t (*sql_store_result)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);

	int (*sql_num_fields)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	int (*sql_num_rows)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	int (*sql_affected_rows)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);

	sql_rcode_t (*sql_fetch_row)(rlm_sql_row_t *out, rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	sql_rcode_t (*sql_fields)(char const **out[], rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	sql_rcode_t (*sql_free_result)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);

	sql_error_t	sql_error;				//!< Get any errors from the previous query.

	sql_rcode_t (*sql_finish_query)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);
	sql_rcode_t (*sql_finish_select_query)(rlm_sql_handle_t *handle, rlm_sql_config_t *config);

	xlat_escape_t	sql_escape_func;
} rlm_sql_driver_t;

struct sql_inst {
	rlm_sql_config_t	myconfig; /* HACK */
	fr_pool_t		*pool;
	rlm_sql_config_t	*config;
	CONF_SECTION		*cs;

	fr_dict_attr_t const	*sql_user;		//!< Cached pointer to SQL-User-Name
							//!< dictionary attribute.
	exfile_t		*ef;

	dl_instance_t		*driver_inst;		//!< Driver's instance data.
	rlm_sql_driver_t const	*driver;		//!< Driver's exported interface.

	int (*sql_set_user)(rlm_sql_t const *inst, REQUEST *request, char const *username);
	xlat_escape_t sql_escape_func;
	sql_rcode_t (*sql_query)(rlm_sql_t const *inst, REQUEST *request, rlm_sql_handle_t **handle, char const *query);
	sql_rcode_t (*sql_select_query)(rlm_sql_t const *inst, REQUEST *request, rlm_sql_handle_t **handle, char const *query);
	sql_rcode_t (*sql_fetch_row)(rlm_sql_row_t *out, rlm_sql_t const *inst, REQUEST *request, rlm_sql_handle_t **handle);

	char const		*name;			//!< Module instance name.
	fr_dict_attr_t const	*group_da;		//!< Group dictionary attribute.
};

typedef struct sql_grouplist {
	char			*name;
	struct sql_grouplist	*next;
} rlm_sql_grouplist_t;

void		*mod_conn_create(TALLOC_CTX *ctx, void *instance, struct timeval const *timeout);
int		sql_fr_pair_list_afrom_str(TALLOC_CTX *ctx, REQUEST *request, VALUE_PAIR **first_pair, rlm_sql_row_t row);
int		sql_read_realms(rlm_sql_handle_t *handle);
int		sql_getvpdata(TALLOC_CTX *ctx, rlm_sql_t const *inst, REQUEST *request, rlm_sql_handle_t **handle, VALUE_PAIR **pair, char const *query);
int		sql_read_clients(rlm_sql_handle_t *handle);
int		sql_dict_init(rlm_sql_handle_t *handle);
void 		rlm_sql_query_log(rlm_sql_t const *inst, REQUEST *request, sql_acct_section_t *section, char const *query) CC_HINT(nonnull (1, 2, 4));
sql_rcode_t	rlm_sql_select_query(rlm_sql_t const *inst, REQUEST *request, rlm_sql_handle_t **handle, char const *query) CC_HINT(nonnull (1, 3, 4));
sql_rcode_t	rlm_sql_query(rlm_sql_t const *inst, REQUEST *request, rlm_sql_handle_t **handle, char const *query) CC_HINT(nonnull (1, 3, 4));
int		rlm_sql_fetch_row(rlm_sql_row_t *out, rlm_sql_t const *inst, REQUEST *request, rlm_sql_handle_t **handle);
void		rlm_sql_print_error(rlm_sql_t const *inst, REQUEST *request, rlm_sql_handle_t *handle, bool force_debug);
int		sql_set_user(rlm_sql_t const *inst, REQUEST *request, char const *username);
