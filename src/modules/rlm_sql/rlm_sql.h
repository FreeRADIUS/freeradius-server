#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @copyright 2012-2014 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Mike Machado (mike@innercite.com)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(rlm_sql_h, "$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/pool.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/exfile.h>
#include <freeradius-devel/server/trunk.h>
#include <freeradius-devel/unlang/function.h>

#define FR_ITEM_CHECK 0
#define FR_ITEM_REPLY 1


/** Action to take at end of an SQL query
 *
 */
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

typedef struct {
	fr_log_type_t		type;				//!< Type of log entry L_ERR, L_WARN, L_INFO,
								///< L_DBG etc.
	char const		*msg;				//!< Log message.
} sql_log_entry_t;

typedef struct {
	char const		*sql_state;			//!< 2-5 char error code.
	char const		*meaning;			//!< Verbose description.
	sql_rcode_t 		rcode;				//!< What should happen if we receive this error.
} sql_state_entry_t;

typedef struct {
	char const 		*sql_server;			//!< Server to connect to.
	uint32_t 		sql_port;			//!< Port to connect to.
	char const 		*sql_login;			//!< Login credentials to use.
	char const 		*sql_password;			//!< Login password to use.
	char const 		*sql_db;			//!< Database to run queries against.

	char const		*group_attribute;		//!< Name of the group attribute.

	bool			cache_groups;			//!< cache group names in &control.SQL-Group

	bool			read_groups;			//!< Read user groups by default.
								//!< If false, Fall-Through = yes is required
								//!< in the previous reply list to process
								//!< groups.
	bool			read_profiles;			//!< Read user profiles by default.
								//!< If false, Fall-Through = yes is required
								//!< in the previous reply list to process
								//!< profiles.

	bool			expand_rhs;			//!< expand the RHS for check / reply tables

	char const		*allowed_chars;			//!< Chars which done need escaping..
	fr_time_delta_t		query_timeout;			//!< How long to allow queries to run for.

	char const		*connect_query;			//!< Query executed after establishing
								//!< new connection.

	trunk_conf_t		trunk_conf;			//!< Configuration for trunk connections.
} rlm_sql_config_t;

typedef struct sql_inst rlm_sql_t;

/*
 *	Per-thread instance data structure
 */
typedef struct {
	trunk_t			*trunk;				//!< Trunk connection for this thread.
	rlm_sql_t const		*inst;				//!< Module instance data.
	void			*sql_escape_arg;		//!< Thread specific argument to be passed to escape function.
} rlm_sql_thread_t;

typedef enum {
	SQL_QUERY_SELECT,
	SQL_QUERY_OTHER
} fr_sql_query_type_t;

/** Status of an SQL query
 */
typedef enum {
	SQL_QUERY_FAILED = -1,					//!< Failed to submit.
	SQL_QUERY_PREPARED = 0,					//!< Ready to submit.
	SQL_QUERY_SUBMITTED,					//!< Submitted for execution.
	SQL_QUERY_RETURNED,					//!< Query has executed.
	SQL_QUERY_FETCHING_RESULTS,				//!< Fetching results from server.
	SQL_QUERY_RESULTS_FETCHED,				//!< Results fetched from the server.
	SQL_QUERY_CANCELLED					//!< A cancellation has been sent to the server.
} fr_sql_query_status_t;

typedef struct {
	rlm_sql_t const		*inst;				//!< Module instance for this query.
	request_t		*request;			//!< Request this query relates to.
	trunk_t			*trunk;				//!< Trunk this query is being run on.
	trunk_connection_t	*tconn;				//!< Trunk connection this query is being run on.
	trunk_request_t		*treq;				//!< Trunk request for this query.
	char const		*query_str;			//!< Query string to run.
	fr_sql_query_type_t	type;				//!< Type of query.
	fr_sql_query_status_t	status;				//!< Status of the query.
	sql_rcode_t		rcode;				//!< Result code.
	rlm_sql_row_t		row;				//!< Row data from the last query.
	void			*uctx;				//!< Driver specific data.
} fr_sql_query_t;

/** Context used when fetching attribute value pairs as a map list
 */
typedef struct {
	TALLOC_CTX		*ctx;				//!< To allocate map entries in.
	rlm_sql_t const		*inst;				//!< Module instance data.
	fr_value_box_t		*query;				//!< Query string used for fetching pairs.
	fr_sql_query_t		*query_ctx;			//!< Query context.
	fr_dict_attr_t const	*list;				//!< Default list for pair evaluation.
	map_list_t		*out;				//!< List to append entries to.
	int			rows;				//!< How many rows the query returned.
	bool			expand_rhs;			//!< for reply items
} fr_sql_map_ctx_t;

extern fr_table_num_sorted_t const sql_rcode_description_table[];
extern size_t sql_rcode_description_table_len;
extern fr_table_num_sorted_t const sql_rcode_table[];
extern size_t sql_rcode_table_len;

/*
 *	Capabilities flags for drivers
 */
#define RLM_SQL_RCODE_FLAGS_ALT_QUERY	1			//!< Can distinguish between other errors and those
								//!< resulting from a unique key violation.
#define RLM_SQL_MULTI_QUERY_CONN	2			//!< Can support multiple queries on a single connection.

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
 * @param[in] query_ctx to retrieve errors from.
 * @return
 *	0  - If no error messages are available.
 *	>0 - Number of log entries
 */
typedef size_t (*sql_error_t)(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen, fr_sql_query_t *query_ctx);

typedef struct {
	rlm_sql_t const		*sql;
} rlm_sql_escape_uctx_t;

typedef struct {
	module_t	common;				//!< Common fields for all loadable modules.

	int		flags;

	unlang_function_t	sql_query_resume;		//!< Callback run after an SQL trunk query is run.
	unlang_function_t	sql_select_query_resume;	//!< Callback run after an SQL select trunk query is run.

	int		(*sql_num_rows)(fr_sql_query_t *query_ctx, rlm_sql_config_t const *config);
	int		(*sql_affected_rows)(fr_sql_query_t *query_ctx, rlm_sql_config_t const *config);

	unlang_function_t	sql_fetch_row;
	sql_rcode_t	(*sql_fields)(char const **out[], fr_sql_query_t *query_ctx, rlm_sql_config_t const *config);
	sql_rcode_t	(*sql_free_result)(fr_sql_query_t *query_ctx, rlm_sql_config_t const *config);

	sql_error_t	sql_error;				//!< Get any errors from the previous query.

	sql_rcode_t	(*sql_finish_query)(fr_sql_query_t *query_ctx, rlm_sql_config_t const *config);
	sql_rcode_t	(*sql_finish_select_query)(fr_sql_query_t *query_ctx, rlm_sql_config_t const *config);

	xlat_escape_legacy_t	sql_escape_func;
	void		*(*sql_escape_arg_alloc)(TALLOC_CTX *ctx, fr_event_list_t *el, void *uctx);
	void		(*sql_escape_arg_free)(void *uctx);

	trunk_io_funcs_t	trunk_io_funcs;		//!< Trunk callback functions for this driver.
} rlm_sql_driver_t;

struct sql_inst {
	rlm_sql_config_t	config; /* HACK */

	fr_dict_attr_t const	*sql_user;		//!< Cached pointer to SQL-User-Name
							//!< dictionary attribute.
	exfile_t		*ef;

	module_instance_t	*driver_submodule;	//!< Driver's submodule.
	rlm_sql_driver_t const	*driver;		//!< Driver's exported interface.

	xlat_escape_legacy_t	sql_escape_func;
	fr_value_box_escape_t	box_escape_func;
	void			*sql_escape_arg;	//!< Instance specific argument to be passed to escape function.
	unlang_function_t	query;
	unlang_function_t	select;
	unlang_function_t	fetch_row;
	fr_sql_query_t		*(*query_alloc)(TALLOC_CTX *ctx, rlm_sql_t const *inst, request_t *request, trunk_t *trunk, char const *query_str, fr_sql_query_type_t type);

	char const		*name;			//!< Module instance name.
	fr_dict_attr_t const	*group_da;		//!< Group dictionary attribute.
	module_instance_t const	*mi;			//!< Module instance data for thread lookups.
};

unlang_action_t	sql_get_map_list(request_t *request, fr_sql_map_ctx_t *map_ctx, trunk_t *trunk);
void 		rlm_sql_query_log(rlm_sql_t const *inst, char const *filename, char const *query) CC_HINT(nonnull);
unlang_action_t rlm_sql_trunk_query(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx);
unlang_action_t rlm_sql_fetch_row(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx);
void		rlm_sql_print_error(rlm_sql_t const *inst, request_t *request, fr_sql_query_t *query_ctx, bool force_debug);
fr_sql_query_t *fr_sql_query_alloc(TALLOC_CTX *ctx, rlm_sql_t const *inst, request_t *request, trunk_t *trunk, char const *query_str, fr_sql_query_type_t type);

/*
 *	sql_state.c
 */
fr_trie_t	*sql_state_trie_alloc(TALLOC_CTX *ctx);
int		sql_state_entries_from_table(fr_trie_t *states, sql_state_entry_t const table[]);
int		sql_state_entries_from_cs(fr_trie_t *states, CONF_SECTION *overrides);
sql_state_entry_t const		*sql_state_entry_find(fr_trie_t const *states, char const *sql_state);
