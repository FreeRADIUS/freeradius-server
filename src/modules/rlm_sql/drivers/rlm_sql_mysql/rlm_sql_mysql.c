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
 * @file rlm_sql_mysql.c
 * @brief MySQL driver.
 *
 * @copyright 2014-2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000-2007,2015 The FreeRADIUS server project
 * @copyright 2000 Mike Machado (mike@innercite.com)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#define LOG_PREFIX log_prefix

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <sys/stat.h>

#include "config.h"

#ifdef HAVE_MYSQL_MYSQL_H
#  include <mysql/errmsg.h>
DIAG_OFF(strict-prototypes)	/* Seen with homebrew mysql client 5.7.13 */
#  include <mysql/mysql.h>
DIAG_ON(strict-prototypes)
#  include <mysql/mysqld_error.h>
#elif defined(HAVE_MYSQL_H)
#  include <errmsg.h>
DIAG_OFF(strict-prototypes)	/* Seen with homebrew mysql client 5.7.13 */
#  include <mysql.h>
DIAG_ON(strict-prototypes)
#  include <mysqld_error.h>
#endif

#include "rlm_sql.h"
#include "rlm_sql_trunk.h"

typedef enum {
	SERVER_WARNINGS_AUTO = 0,
	SERVER_WARNINGS_YES,
	SERVER_WARNINGS_NO
} rlm_sql_mysql_warnings;

static fr_table_num_sorted_t const server_warnings_table[] = {
	{ L("auto"),	SERVER_WARNINGS_AUTO	},
	{ L("no"),		SERVER_WARNINGS_NO	},
	{ L("yes"),	SERVER_WARNINGS_YES	}
};
static size_t server_warnings_table_len = NUM_ELEMENTS(server_warnings_table);

typedef struct {
	MYSQL		db;			//!< Structure representing connection details.
	MYSQL		*sock;			//!< Connection details as returned by connection init functions.
	MYSQL_RES	*result;		//!< Result from most recent query.
	connection_t	*conn;			//!< Generic connection structure for this connection.
	int		fd;			//!< fd for this connection's I/O events.
	fr_sql_query_t	*query_ctx;		//!< Current query running on this connection.
	int		status;			//!< returned by the most recent non-blocking function call.
} rlm_sql_mysql_conn_t;

typedef struct {
	char const	*tls_ca_file;		//!< Path to the CA used to validate the server's certificate.
	char const	*tls_ca_path;		//!< Directory containing CAs that may be used to validate the
						//!< servers certificate.
	char const	*tls_certificate_file;	//!< Public certificate we present to the server.
	char const	*tls_private_key_file;	//!< Private key for the certificate we present to the server.

	char const	*tls_crl_file;		//!< Public certificate we present to the server.
	char const	*tls_crl_path;		//!< Private key for the certificate we present to the server.

	char const	*tls_cipher;		//!< Colon separated list of TLS ciphers for TLS <= 1.2.

	bool		tls_required;		//!< Require that the connection is encrypted.
	bool		tls_check_cert;		//!< Verify there's a trust relationship between the server's
						///< cert and one of the CAs we have configured.
	bool		tls_check_cert_cn;	//!< Verify that the CN in the server cert matches the host
						///< we passed to mysql_real_connect().

	char const	*warnings_str;		//!< Whether we always query the server for additional warnings.
	rlm_sql_mysql_warnings	warnings;	//!< mysql_warning_count() doesn't
						//!< appear to work with NDB cluster

	char const	*character_set;		//!< Character set to use on connections.
} rlm_sql_mysql_t;

static conf_parser_t tls_config[] = {
	{ FR_CONF_OFFSET_FLAGS("ca_file", CONF_FLAG_FILE_INPUT, rlm_sql_mysql_t, tls_ca_file) },
	{ FR_CONF_OFFSET_FLAGS("ca_path", CONF_FLAG_FILE_INPUT, rlm_sql_mysql_t, tls_ca_path) },
	{ FR_CONF_OFFSET_FLAGS("certificate_file", CONF_FLAG_FILE_INPUT, rlm_sql_mysql_t, tls_certificate_file) },
	{ FR_CONF_OFFSET_FLAGS("private_key_file", CONF_FLAG_FILE_INPUT, rlm_sql_mysql_t, tls_private_key_file) },
	{ FR_CONF_OFFSET_FLAGS("crl_file", CONF_FLAG_FILE_INPUT, rlm_sql_mysql_t, tls_crl_file) },
	{ FR_CONF_OFFSET_FLAGS("crl_path", CONF_FLAG_FILE_INPUT, rlm_sql_mysql_t, tls_crl_path) },
	/*
	 *	MySQL Specific TLS attributes
	 */
	{ FR_CONF_OFFSET("cipher", rlm_sql_mysql_t, tls_cipher) },

	/*
	 *	The closest thing we have to these options in other modules is
	 *	in rlm_rest.  rlm_ldap has its own bizarre option set.
	 *
	 *	There, the options can be toggled independently, here they can't
	 *	but for consistency we break them out anyway, and warn if the user
	 *	has provided an invalid list of flags.
	 */
	{ FR_CONF_OFFSET("tls_required", rlm_sql_mysql_t, tls_required) },
	{ FR_CONF_OFFSET("check_cert", rlm_sql_mysql_t, tls_check_cert) },
	{ FR_CONF_OFFSET("check_cert_cn", rlm_sql_mysql_t, tls_check_cert_cn) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t driver_config[] = {
	{ FR_CONF_POINTER("tls", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) tls_config },

	{ FR_CONF_OFFSET("warnings", rlm_sql_mysql_t, warnings_str), .dflt = "auto" },
	{ FR_CONF_OFFSET("character_set", rlm_sql_mysql_t, character_set) },
	CONF_PARSER_TERMINATOR
};

/* Prototypes */
static sql_rcode_t sql_free_result(fr_sql_query_t *, rlm_sql_config_t const *);

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_sql_mysql_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_sql_mysql_t);
	int			warnings;
	char const		*log_prefix = mctx->mi->name;

	warnings = fr_table_value_by_str(server_warnings_table, inst->warnings_str, -1);
	if (warnings < 0) {
		ERROR("Invalid warnings value \"%s\", must be yes, no, or auto", inst->warnings_str);
		return -1;
	}
	inst->warnings = (rlm_sql_mysql_warnings)warnings;

	if (inst->tls_check_cert && !inst->tls_required) {
		WARN("Implicitly setting tls_required = yes, as tls_check_cert = yes");
		inst->tls_required = true;
	}
	if (inst->tls_check_cert_cn) {
		if (!inst->tls_required) {
			WARN("Implicitly setting tls_required = yes, as check_cert_cn = yes");
			inst->tls_required = true;
		}

		if (!inst->tls_check_cert) {
			WARN("Implicitly setting check_cert = yes, as check_cert_cn = yes");
			inst->tls_check_cert = true;
		}
	}
	return 0;
}

static void mod_unload(void)
{
	mysql_library_end();
}

static int mod_load(void)
{
	char const	*log_prefix = "rlm_sql_mysql";
	if (mysql_library_init(0, NULL, NULL)) {
		ERROR("libmysql initialisation failed");

		return -1;
	}

	INFO("libmysql version: %s", mysql_get_client_info());

	return 0;
}

/** Callback for I/O events in response to mysql_real_connect_start()
 */
static void _sql_connect_io_notify(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	rlm_sql_mysql_conn_t	*c = talloc_get_type_abort(uctx, rlm_sql_mysql_conn_t);
	char const		*log_prefix = c->conn->name;

	fr_event_fd_delete(el, fd, FR_EVENT_FILTER_IO);

	if (c->status == 0) goto connected;
	c->status = mysql_real_connect_cont(&c->sock, &c->db, c->status);

	/*
	 *	If status is not zero, we're still waiting for something.
	 *	The event will be fired again when that happens.
	 */
	if (c->status != 0) {
		(void) fr_event_fd_insert(c, NULL, c->conn->el, c->fd,
				          c->status & MYSQL_WAIT_READ ? _sql_connect_io_notify : NULL,
					  c->status & MYSQL_WAIT_WRITE ? _sql_connect_io_notify : NULL, NULL, c);
		return;
	}

connected:
	if (!c->sock) {
		ERROR("MySQL error: %s", mysql_error(&c->db));
		connection_signal_reconnect(c->conn, CONNECTION_FAILED);
		return;
	}

	DEBUG2("Connected to database on %s, server version %s, protocol version %i",
	       mysql_get_host_info(c->sock),
	       mysql_get_server_info(c->sock), mysql_get_proto_info(c->sock));

	connection_signal_connected(c->conn);
}

static void _sql_connect_query_run(connection_t *conn, UNUSED connection_state_t prev,
				   UNUSED connection_state_t state, void *uctx)
{
	rlm_sql_t const		*sql = talloc_get_type_abort_const(uctx, rlm_sql_t);
	rlm_sql_mysql_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_mysql_conn_t);
	char const		*log_prefix = conn->name;
	int			ret;
	MYSQL_RES		*result;

	DEBUG2("Executing \"%s\"", sql->config.connect_query);

	ret = mysql_real_query(sql_conn->sock, sql->config.connect_query, strlen(sql->config.connect_query));
	if (ret != 0) {
		char const *info;
		ERROR("Failed running \"open_query\"");
		info = mysql_info(sql_conn->sock);
		if (info) ERROR("%s", info);
		connection_signal_reconnect(conn, CONNECTION_FAILED);
		return;
	}

	/*
	 *	These queries should not return any results - but let's be safe
	 */
	result = mysql_store_result(sql_conn->sock);
	if (result) mysql_free_result(result);
	while ((mysql_next_result(sql_conn->sock) == 0) &&
	       (result = mysql_store_result(sql_conn->sock))) {
		mysql_free_result(result);
	}
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static connection_state_t _sql_connection_init(void **h, connection_t *conn, void *uctx)
{
	rlm_sql_t const		*sql = talloc_get_type_abort_const(uctx, rlm_sql_t);
	rlm_sql_mysql_t const	*inst = talloc_get_type_abort(sql->driver_submodule->data, rlm_sql_mysql_t);
	char const		*log_prefix = conn->name;
	rlm_sql_mysql_conn_t	*c;
	rlm_sql_config_t const	*config = &sql->config;

	unsigned long		sql_flags;
	enum mysql_option	ssl_mysql_opt;
	unsigned int		ssl_mode = 0;
	bool			ssl_mode_isset = false;

	MEM(c = talloc_zero(conn, rlm_sql_mysql_conn_t));
	c->conn = conn;
	c->fd = -1;

	DEBUG("Starting connect to MySQL server");

	mysql_init(&c->db);

	/*
	 *	If any of the TLS options are set, configure TLS
	 *
	 *	According to MySQL docs this function always returns 0, so we won't
	 *	know if ssl setup succeeded until mysql_real_connect is called below.
	 */
	if (inst->tls_ca_file || inst->tls_ca_path ||
	    inst->tls_certificate_file || inst->tls_private_key_file) {
		mysql_ssl_set(&(c->db), inst->tls_private_key_file, inst->tls_certificate_file,
			      inst->tls_ca_file, inst->tls_ca_path, inst->tls_cipher);
	}

#ifdef MARIADB_BASE_VERSION
	if (inst->tls_required || inst->tls_check_cert || inst->tls_check_cert_cn) {
		ssl_mode_isset = true;
		/**
		 * For MariaDB, It should be true as can be seen in
		 * https://github.com/MariaDB/server/blob/mariadb-5.5.68/sql-common/client.c#L4338
		 */
		ssl_mode = true;
		ssl_mysql_opt = MYSQL_OPT_SSL_VERIFY_SERVER_CERT;
	}
#else
	ssl_mysql_opt = MYSQL_OPT_SSL_MODE;
	if (inst->tls_required) {
		ssl_mode = SSL_MODE_REQUIRED;
		ssl_mode_isset = true;
	}
	if (inst->tls_check_cert) {
		ssl_mode = SSL_MODE_VERIFY_CA;
		ssl_mode_isset = true;
	}
	if (inst->tls_check_cert_cn) {
		ssl_mode = SSL_MODE_VERIFY_IDENTITY;
		ssl_mode_isset = true;
	}
#endif
	if (ssl_mode_isset) mysql_options(&(c->db), ssl_mysql_opt, &ssl_mode);

	if (inst->tls_crl_file) mysql_options(&(c->db), MYSQL_OPT_SSL_CRL, inst->tls_crl_file);
	if (inst->tls_crl_path) mysql_options(&(c->db), MYSQL_OPT_SSL_CRLPATH, inst->tls_crl_path);

	mysql_options(&(c->db), MYSQL_READ_DEFAULT_GROUP, "freeradius");

	if (inst->character_set) mysql_options(&(c->db), MYSQL_SET_CHARSET_NAME, inst->character_set);

#if MYSQL_VERSION_ID < 80034
	/*
	 *	We need to know about connection errors, and are capable
	 *	of reconnecting automatically.
	 *
	 *	This deprecated as of 8.0.34.
	 */
	{
		bool reconnect = 0;
		mysql_options(&(c->db), MYSQL_OPT_RECONNECT, &reconnect);
	}
#endif

	sql_flags = CLIENT_MULTI_RESULTS | CLIENT_FOUND_ROWS;

#ifdef CLIENT_MULTI_STATEMENTS
	sql_flags |= CLIENT_MULTI_STATEMENTS;
#endif

 	mysql_options(&c->db, MYSQL_OPT_NONBLOCK, 0);

	c->status = mysql_real_connect_start(&c->sock, &c->db,
					     config->sql_server,
					     config->sql_login,
					     config->sql_password,
					     config->sql_db,
					     config->sql_port, NULL, sql_flags);

	c->fd = mysql_get_socket(&c->db);

	if (c->fd <= 0) {
		ERROR("Could't connect to MySQL server %s@%s:%s", config->sql_login,
		      config->sql_server, config->sql_db);
		ERROR("MySQL error: %s", mysql_error(&c->db));
	error:
		talloc_free(c);
		return CONNECTION_STATE_FAILED;
	}

	if (c->status == 0) {
		DEBUG2("Connected to database '%s' on %s, server version %s, protocol version %i",
		       config->sql_db, mysql_get_host_info(c->sock),
		       mysql_get_server_info(c->sock), mysql_get_proto_info(c->sock));
		goto finish;
	}

	if (fr_event_fd_insert(c, NULL, c->conn->el, c->fd,
			       c->status & MYSQL_WAIT_READ ? _sql_connect_io_notify : NULL,
			       c->status & MYSQL_WAIT_WRITE ? _sql_connect_io_notify : NULL, NULL, c) != 0) goto error;

	DEBUG2("Connecting to database '%s' on %s:%d, fd %d",
	       config->sql_db, config->sql_server, config->sql_port, c->fd);

finish:
	*h = c;

	if (config->connect_query) connection_add_watch_post(conn, CONNECTION_STATE_CONNECTED,
							     _sql_connect_query_run, true, sql);

	return c->status == 0 ? CONNECTION_STATE_CONNECTED : CONNECTION_STATE_CONNECTING;
}

static void _sql_connection_close(fr_event_list_t *el, void *h, UNUSED void *uctx)
{
	rlm_sql_mysql_conn_t	*c = talloc_get_type_abort(h, rlm_sql_mysql_conn_t);

	if (c->fd >= 0) {
		fr_event_fd_delete(el, c->fd, FR_EVENT_FILTER_IO);
		c->fd = -1;
	}
	mysql_close(&c->db);
	c->query_ctx = NULL;
	talloc_free(h);
}

/** Analyse the last error that occurred on the socket, and determine an action
 *
 * @param server Socket from which to extract the server error. May be NULL.
 * @param client_errno Error from the client.
 * @return an action for #rlm_sql_t to take.
 */
static sql_rcode_t sql_check_error(MYSQL *server, int client_errno)
{
	int sql_errno = 0;

	/*
	 *	The client and server error numbers are in the
	 *	same numberspace.
	 */
	if (server) sql_errno = mysql_errno(server);
	if ((sql_errno == 0) && (client_errno != 0)) sql_errno = client_errno;

	if (sql_errno > 0) switch (sql_errno) {
	case CR_SERVER_GONE_ERROR:
	case CR_SERVER_LOST:
		return RLM_SQL_RECONNECT;

	case CR_OUT_OF_MEMORY:
	case CR_COMMANDS_OUT_OF_SYNC:
	case CR_UNKNOWN_ERROR:
	default:
		return RLM_SQL_ERROR;

	/*
	 *	Constraints errors that signify a duplicate, or that we might
	 *	want to try an alternative query.
	 *
	 *	Error constants not found in the 3.23/4.0/4.1 manual page
	 *	are checked for.
	 *	Other error constants should always be available.
	 */
	case ER_DUP_UNIQUE:			/* Can't write, because of unique constraint, to table '%s'. */
	case ER_DUP_KEY:			/* Can't write; duplicate key in table '%s' */

	case ER_DUP_ENTRY:			/* Duplicate entry '%s' for key %d. */
	case ER_NO_REFERENCED_ROW:		/* Cannot add or update a child row: a foreign key constraint fails */
	case ER_ROW_IS_REFERENCED:		/* Cannot delete or update a parent row: a foreign key constraint fails */
#ifdef ER_FOREIGN_DUPLICATE_KEY
	case ER_FOREIGN_DUPLICATE_KEY: 		/* Upholding foreign key constraints for table '%s', entry '%s', key %d would lead to a duplicate entry. */
#endif
#ifdef ER_DUP_ENTRY_WITH_KEY_NAME
	case ER_DUP_ENTRY_WITH_KEY_NAME:	/* Duplicate entry '%s' for key '%s' */
#endif
#ifdef ER_NO_REFERENCED_ROW_2
	case ER_NO_REFERENCED_ROW_2:
#endif
#ifdef ER_ROW_IS_REFERENCED_2
	case ER_ROW_IS_REFERENCED_2:
#endif
		return RLM_SQL_ALT_QUERY;

	/*
	 *	Constraints errors that signify an invalid query
	 *	that can never succeed.
	 */
	case ER_BAD_NULL_ERROR:			/* Column '%s' cannot be null */
	case ER_NON_UNIQ_ERROR:			/* Column '%s' in %s is ambiguous */
		return RLM_SQL_QUERY_INVALID;

	/*
	 *	Constraints errors that signify no data returned.
	 *
	 *	This is considered OK as the caller may look for the next result set.
	 */
	case ER_SP_FETCH_NO_DATA:
		return RLM_SQL_OK;

	}

	return RLM_SQL_OK;
}

static sql_rcode_t sql_store_result(rlm_sql_mysql_conn_t *conn, UNUSED rlm_sql_config_t const *config)
{
	sql_rcode_t rcode;
	int ret;

retry_store_result:
	conn->result = mysql_store_result(conn->sock);
	if (!conn->result) {
		rcode = sql_check_error(conn->sock, 0);
		if (rcode != RLM_SQL_OK) return rcode;
		ret = mysql_next_result(conn->sock);
		if (ret == 0) {
			/* there are more results */
			goto retry_store_result;
		} else if (ret > 0) return sql_check_error(NULL, ret);
		/* ret == -1 signals no more results */
	}
	return RLM_SQL_OK;
}

static int sql_num_rows(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mysql_conn_t *conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_mysql_conn_t);

	if (conn->result) return mysql_num_rows(conn->result);

	return 0;
}

static sql_rcode_t sql_fields(char const **out[], fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mysql_conn_t *conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_mysql_conn_t);

	unsigned int	fields, i;
	MYSQL_FIELD	*field_info;
	char const	**names;

	/*
	 *	Use our internal function to abstract out the API call.
	 *	Different versions of SQL use different functions,
	 *	and some don't like NULL pointers.
	 */
	fields = mysql_field_count(conn->sock);
	if (fields == 0) return RLM_SQL_ERROR;

	/*
	 *	https://bugs.mysql.com/bug.php?id=32318
	 * 	Hints that we don't have to free field_info.
	 */
	field_info = mysql_fetch_fields(conn->result);
	if (!field_info) return RLM_SQL_ERROR;

	MEM(names = talloc_array(query_ctx, char const *, fields));

	for (i = 0; i < fields; i++) names[i] = field_info[i].name;
	*out = names;

	return RLM_SQL_OK;
}

static unlang_action_t sql_fetch_row(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_mysql_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_mysql_conn_t);
	MYSQL_ROW		row;
	int			ret;
	unsigned int		num_fields, i;
	unsigned long		*field_lens;

	/*
	 *  Check pointer before de-referencing it.
	 *  Lack of conn->result is either an error, or no result returned.
	 */
	if (!conn->result) {
		query_ctx->rcode = sql_check_error(conn->sock, 0);
		if (query_ctx->rcode == RLM_SQL_OK) {
			query_ctx->rcode = RLM_SQL_NO_MORE_ROWS;
			RETURN_MODULE_OK;
		}
		RETURN_MODULE_FAIL;
	}

	TALLOC_FREE(query_ctx->row);		/* Clear previous row set */

retry_fetch_row:
	row = mysql_fetch_row(conn->result);
	if (!row) {
		query_ctx->rcode = sql_check_error(conn->sock, 0);
		if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL;

		mysql_free_result(conn->result);
		conn->result = NULL;

		ret = mysql_next_result(conn->sock);
		if (ret == 0) {
			/* there are more results */
			if ((sql_store_result(conn, &query_ctx->inst->config) == 0) && (conn->result != NULL)) {
				goto retry_fetch_row;
			}
		} else if (ret > 0) {
			query_ctx->rcode = sql_check_error(NULL, ret);
			if (query_ctx->rcode == RLM_SQL_OK) RETURN_MODULE_OK;
			RETURN_MODULE_FAIL;
		}
		/* If ret is -1 then there are no more rows */

		query_ctx->rcode = RLM_SQL_NO_MORE_ROWS;
		RETURN_MODULE_OK;
	}

	num_fields = mysql_field_count(conn->sock);
	if (!num_fields) {
		query_ctx->rcode = RLM_SQL_NO_MORE_ROWS;
		RETURN_MODULE_OK;
	}

 	field_lens = mysql_fetch_lengths(conn->result);

	MEM(query_ctx->row = talloc_zero_array(query_ctx, char *, num_fields + 1));
	for (i = 0; i < num_fields; i++) {
		if (!row[i]) continue;
		MEM(query_ctx->row[i] = talloc_bstrndup(query_ctx->row, row[i], field_lens[i]));
	}

	query_ctx->rcode = RLM_SQL_OK;
	RETURN_MODULE_OK;
}

static sql_rcode_t sql_free_result(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mysql_conn_t *conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_mysql_conn_t);

	if (conn->result) {
		mysql_free_result(conn->result);
		conn->result = NULL;
	}
	TALLOC_FREE(query_ctx->row);

	return RLM_SQL_OK;
}

/** Retrieves any warnings associated with the last query
 *
 * MySQL stores a limited number of warnings associated with the last query
 * executed. These can be very useful in diagnosing issues, or in some cases
 * working around bugs in MySQL which causes it to return the wrong error.
 *
 * @note Caller should free any memory allocated in ctx (talloc_free_children()).
 *
 * @param ctx to allocate temporary error buffers in.
 * @param out Array of sql_log_entrys to fill.
 * @param outlen Length of out array.
 * @param conn MySQL connection the query was run on.
 * @return
 *	- Number of errors written to the #sql_log_entry_t array.
 *	- -1 on failure.
 */
static size_t sql_warnings(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			   rlm_sql_mysql_conn_t *conn)
{
	MYSQL_RES		*result;
	MYSQL_ROW		row;
	unsigned int		num_fields;
	size_t			i = 0;
	char const		*log_prefix = conn->conn->name;

	if (outlen == 0) return 0;

	/*
	 *	Retrieve any warnings associated with the previous query
	 *	that were left lingering on the server.
	 */
	if (mysql_query(conn->sock, "SHOW WARNINGS") != 0) return -1;
	result = mysql_store_result(conn->sock);
	if (!result) return -1;

	/*
	 *	Fields should be [0] = Level, [1] = Code, [2] = Message
	 */
	num_fields = mysql_field_count(conn->sock);
	if (num_fields < 3) {
		WARN("Failed retrieving warnings, expected 3 fields got %u", num_fields);
		mysql_free_result(result);

		return -1;
	}

	while ((row = mysql_fetch_row(result))) {
		char *msg = NULL;
		fr_log_type_t type;

		/*
		 *	Translate the MySQL log level into our internal
		 *	log levels, so they get colourised correctly.
		 */
		if (strcasecmp(row[0], "warning") == 0)	type = L_WARN;
		else if (strcasecmp(row[0], "note") == 0) type = L_DBG;
		else type = L_ERR;

		msg = talloc_typed_asprintf(ctx, "%s: %s", row[1], row[2]);
		out[i].type = type;
		out[i].msg = msg;
		if (++i == outlen) break;
	}

	mysql_free_result(result);

	return i;
}

/** Retrieves any errors associated with the query context
 *
 * @note Caller should free any memory allocated in ctx (talloc_free_children()).
 *
 * @param ctx to allocate temporary error buffers in.
 * @param out Array of sql_log_entrys to fill.
 * @param outlen Length of out array.
 * @param query_ctx Query context to retrieve error for.
 * @return number of errors written to the #sql_log_entry_t array.
 */
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			fr_sql_query_t *query_ctx)
{
	rlm_sql_mysql_t const	*inst = talloc_get_type_abort_const(query_ctx->inst->driver_submodule->data, rlm_sql_mysql_t);
	rlm_sql_mysql_conn_t	*conn;
	char const		*error;
	size_t			i = 0;
	char const		*log_prefix;

	if (!query_ctx->tconn) return 0;
	conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_mysql_conn_t);
	log_prefix = conn->conn->name;

	fr_assert(outlen > 0);

	error = mysql_error(conn->sock);

	/*
	 *	Grab the error now in case it gets cleared on the next operation.
	 */
	if (error && (error[0] != '\0')) {
		error = talloc_typed_asprintf(ctx, "ERROR %u (%s): %s", mysql_errno(conn->sock), error,
					      mysql_sqlstate(conn->sock));
	} else {
		error = NULL;
	}

	/*
	 *	Don't attempt to get errors from the server, if the last error
	 *	was that the server was unavailable.
	 */
	if ((outlen > 1) && (sql_check_error(conn->sock, 0) != RLM_SQL_RECONNECT)) {
		size_t ret;
		unsigned int msgs;

		switch (inst->warnings) {
		case SERVER_WARNINGS_AUTO:
			/*
			 *	Check to see if any warnings can be retrieved from the server.
			 */
			msgs = mysql_warning_count(conn->sock);
			if (msgs == 0) {
				DEBUG3("No additional diagnostic info on server");
				break;
			}

		FALL_THROUGH;
		case SERVER_WARNINGS_YES:
			ret = sql_warnings(ctx, out, outlen - 1, conn);
			if (ret > 0) i += ret;
			break;

		case SERVER_WARNINGS_NO:
			break;

		default:
			fr_assert(0);
		}
	}

	if (error) {
		out[i].type = L_ERR;
		out[i].msg = error;
		i++;
	}

	return i;
}

/** Finish query
 *
 * As a single SQL statement may return multiple results
 * sets, (for example stored procedures) it is necessary to check
 * whether more results exist and process them in turn if so.
 *
 */
static sql_rcode_t sql_finish_query(fr_sql_query_t *query_ctx, rlm_sql_config_t const *config)
{
	rlm_sql_mysql_conn_t	*conn;
	int			ret;
	MYSQL_RES		*result;

	/*
	 *	If the query is not in a state which would return results, then do nothing.
	 */
	if (query_ctx->treq && !(query_ctx->treq->state &
	    (TRUNK_REQUEST_STATE_SENT | TRUNK_REQUEST_STATE_REAPABLE | TRUNK_REQUEST_STATE_COMPLETE))) return RLM_SQL_OK;

	/*
	 *	If the connection doesn't exist there's nothing to do
	 */
	if (!query_ctx->tconn || !query_ctx->tconn->conn || !query_ctx->tconn->conn->h) return RLM_SQL_ERROR;

	conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_mysql_conn_t);

	/*
	 *	If the connection is not active, then all that we can do is free any stored results
	 */
	if (query_ctx->tconn->conn->state != CONNECTION_STATE_CONNECTED) {
		sql_free_result(query_ctx, config);
		return RLM_SQL_OK;
	}

	/*
	 *	If there's no result associated with the
	 *	connection handle, assume the first result in the
	 *	result set hasn't been retrieved.
	 *
	 *	MySQL docs says there's no performance penalty for
	 *	calling mysql_store_result for queries which don't
	 *	return results.
	 */
	if (conn->result == NULL) {
		result = mysql_store_result(conn->sock);
		if (result) mysql_free_result(result);
	/*
	 *	...otherwise call sql_free_result to free an
	 *	already stored result.
	 */
	} else {
		sql_free_result(query_ctx, config);	/* sql_free_result sets conn->result to NULL */
	}

	/*
	 *	Drain any other results associated with the handle
	 *
	 *	mysql_next_result advances the result cursor so that
	 *	the next call to mysql_store_result will retrieve
	 *	the next result from the server.
	 *
	 *	Unfortunately this really does appear to be the
	 *	only way to return the handle to a consistent state.
	 */
	while (((ret = mysql_next_result(conn->sock)) == 0) &&
	       (result = mysql_store_result(conn->sock))) {
		mysql_free_result(result);
	}
	if (ret > 0) return sql_check_error(NULL, ret);

	return RLM_SQL_OK;
}

static int sql_affected_rows(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mysql_conn_t *conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_mysql_conn_t);

	return mysql_affected_rows(conn->sock);
}

static ssize_t sql_escape_func(request_t *request, char *out, size_t outlen, char const *in, void *arg)
{
	size_t			inlen;
	connection_t		*c = talloc_get_type_abort(arg, connection_t);
	rlm_sql_mysql_conn_t	*conn;
	char const		*log_prefix = c->name;

	if ((c->state == CONNECTION_STATE_HALTED) || (c->state == CONNECTION_STATE_CLOSED)) {
		ROPTIONAL(RERROR, ERROR, "Connection not available for escaping");
		return -1;
	}

	conn = talloc_get_type_abort(c->h, rlm_sql_mysql_conn_t);

	/* Check for potential buffer overflow */
	inlen = strlen(in);
	if ((inlen * 2 + 1) > outlen) return 0;
	/* Prevent integer overflow */
	if ((inlen * 2 + 1) <= inlen) return 0;

	return mysql_real_escape_string(&conn->db, out, in, inlen);
}

SQL_TRUNK_CONNECTION_ALLOC

#undef LOG_PREFIX
#define LOG_PREFIX "rlm_sql_mysql"

TRUNK_NOTIFY_FUNC(sql_trunk_connection_notify, rlm_sql_mysql_conn_t)

#undef LOG_PREFIX
#define LOG_PREFIX log_prefix

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void sql_trunk_request_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn,
				  connection_t *conn, UNUSED void *uctx)
{
	rlm_sql_mysql_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_mysql_conn_t);
	char const		*log_prefix = conn->name;
	request_t		*request;
	trunk_request_t		*treq;
	fr_sql_query_t		*query_ctx;
	char const		*info;
	int			err;

	if (trunk_connection_pop_request(&treq, tconn) != 0) return;
	if (!treq) return;

	query_ctx = talloc_get_type_abort(treq->preq, fr_sql_query_t);
	request = query_ctx->request;

	/*
	 *	Each of the MariaDB async "start" calls returns a non-zero value
	 *	if they are waiting on I/O.
	 *	A return value of zero means that the operation completed.
	 */

	switch (query_ctx->status) {
	case SQL_QUERY_PREPARED:
		ROPTIONAL(RDEBUG2, DEBUG2, "Executing query: %s", query_ctx->query_str);
		sql_conn->status = mysql_real_query_start(&err, sql_conn->sock, query_ctx->query_str, strlen(query_ctx->query_str));
		query_ctx->tconn = tconn;

		if (sql_conn->status) {
			ROPTIONAL(RDEBUG3, DEBUG3, "Waiting for IO");
			query_ctx->status = SQL_QUERY_SUBMITTED;
			sql_conn->query_ctx = query_ctx;
			trunk_request_signal_sent(treq);
			return;
		}

		if (err) {
			/*
			 *	Need to check what kind of error this is - it may
			 *	be a unique key conflict, we run the next query.
			 */
			info = mysql_info(sql_conn->sock);
			query_ctx->rcode = sql_check_error(sql_conn->sock, 0);
			if (info) ERROR("%s", info);
			switch (query_ctx->rcode) {
			case RLM_SQL_OK:
			case RLM_SQL_ALT_QUERY:
				break;

			default:
				query_ctx->status = SQL_QUERY_FAILED;
				trunk_request_signal_fail(treq);
				if (request) unlang_interpret_mark_runnable(request);
				return;
			}
		} else {
			query_ctx->rcode = RLM_SQL_OK;
		}
		query_ctx->status = SQL_QUERY_RETURNED;

		break;

	case SQL_QUERY_RETURNED:
		ROPTIONAL(RDEBUG2, DEBUG2, "Fetching results");
		fr_assert(query_ctx->tconn == tconn);
		sql_conn->status = mysql_store_result_start(&sql_conn->result, sql_conn->sock);

		if (sql_conn->status) {
			ROPTIONAL(RDEBUG3, DEBUG3, "Waiting for IO");
			query_ctx->status = SQL_QUERY_FETCHING_RESULTS;
			sql_conn->query_ctx = query_ctx;
			trunk_request_signal_sent(treq);
			return;
		}
		query_ctx->status = SQL_QUERY_RESULTS_FETCHED;
		query_ctx->rcode = RLM_SQL_OK;

		break;

	default:
		/*
		 *	The request outstanding on this connection returned
		 *	immediately, so we are not actually waiting for I/O.
		 */
		return;
	}

	/*
	 *	The current request is not waiting for I/O so the request can run
	 */
	ROPTIONAL(RDEBUG3, DEBUG3, "Got immediate response");
	trunk_request_signal_reapable(treq);
	if (request) unlang_interpret_mark_runnable(request);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void sql_trunk_request_demux(UNUSED fr_event_list_t *el, UNUSED trunk_connection_t *tconn,
				    connection_t *conn, UNUSED void *uctx)
{
	rlm_sql_mysql_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_mysql_conn_t);
	char const		*log_prefix = conn->name;
	fr_sql_query_t		*query_ctx;
	char const		*info;
	int			err = 0;
	request_t		*request;

	/*
	 *	Lookup the outstanding SQL query for this connection.
	 *	There will only ever be one per tconn.
	 */
	query_ctx = sql_conn->query_ctx;

	/*
	 *	No outstanding query on this connection.
	 *	Should not happen, but added for safety.
	 */
	if (unlikely(!query_ctx)) return;

	switch (query_ctx->status) {
	case SQL_QUERY_SUBMITTED:
		sql_conn->status = mysql_real_query_cont(&err, sql_conn->sock, sql_conn->status);
		break;

	case SQL_QUERY_FETCHING_RESULTS:
		sql_conn->status = mysql_store_result_cont(&sql_conn->result, sql_conn->sock, sql_conn->status);
		break;

	default:
		/*
		 *	The request outstanding on this connection returned
		 *	immediately, so we are not actually waiting for I/O.
		 */
		return;
	}

	/*
	 *	Are we still waiting for any further I/O?
	 */
	if (sql_conn->status != 0) return;

	sql_conn->query_ctx = NULL;

	switch (query_ctx->status) {
	case SQL_QUERY_SUBMITTED:
		query_ctx->status = SQL_QUERY_RETURNED;
		break;

	case SQL_QUERY_FETCHING_RESULTS:
		query_ctx->status = SQL_QUERY_RESULTS_FETCHED;
		break;

	default:
		fr_assert(0);
	}

	request = query_ctx->request;
	if (request) unlang_interpret_mark_runnable(request);

	if (err) {
		info = mysql_info(sql_conn->sock);
		query_ctx->rcode = sql_check_error(sql_conn->sock, 0);
		if (info) ROPTIONAL(RERROR, ERROR, "%s", info);
		return;
	}

	query_ctx->rcode = RLM_SQL_OK;
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void sql_request_cancel(connection_t *conn, void *preq, trunk_cancel_reason_t reason,
			       UNUSED void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(preq, fr_sql_query_t);
	rlm_sql_mysql_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_mysql_conn_t);

	if (!query_ctx->treq) return;
	if (reason != TRUNK_CANCEL_REASON_SIGNAL) return;
	if (sql_conn->query_ctx == query_ctx) sql_conn->query_ctx = NULL;
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void sql_request_cancel_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn,
				   connection_t *conn, UNUSED void *uctx)
{
	trunk_request_t	*treq;

	/*
	 *	The MariaDB non-blocking API doesn't have any cancellation functions -
	 *	rather you are expected to close the connection.
	 */
	if ((trunk_connection_pop_cancellation(&treq, tconn)) == 0) {
		trunk_request_signal_cancel_complete(treq);
		connection_signal_reconnect(conn, CONNECTION_FAILED);
	}
}

SQL_QUERY_FAIL
SQL_QUERY_RESUME

static unlang_action_t sql_select_query_resume(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);

	if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL;

	if (query_ctx->status == SQL_QUERY_RETURNED) {
		trunk_request_requeue(query_ctx->treq);

		if (unlang_function_repeat_set(request, sql_select_query_resume) < 0) {
			query_ctx->rcode = RLM_SQL_ERROR;
			RETURN_MODULE_FAIL;
		}

		return UNLANG_ACTION_YIELD;
	}

	RETURN_MODULE_OK;
}

/** Allocate the argument used for the SQL escape function
 *
 * In this case, a dedicated connection to allow the escape
 * function to have access to server side parameters, though
 * no packets ever flow after the connection is made.
 */
static void *sql_escape_arg_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, void *uctx)
{
	rlm_sql_t const	*inst = talloc_get_type_abort(uctx, rlm_sql_t);
	connection_t *conn;
	char const	*log_prefix = inst->name;

	conn = connection_alloc(ctx, el,
				    &(connection_funcs_t){
					.init = _sql_connection_init,
					.close = _sql_connection_close,
				    },
				    inst->config.trunk_conf.conn_conf,
				    inst->name, inst);

	if (!conn) {
		PERROR("Failed allocating state handler for SQL escape connection");
		return NULL;
	}

	connection_signal_init(conn);
	return conn;
}

static void sql_escape_arg_free(void *uctx)
{
	connection_t	*conn = talloc_get_type_abort(uctx, connection_t);
	connection_signal_halt(conn);
}

/* Exported to rlm_sql */
extern rlm_sql_driver_t rlm_sql_mysql;
rlm_sql_driver_t rlm_sql_mysql = {
	.common = {
		.name				= "sql_mysql",
		.magic				= MODULE_MAGIC_INIT,
		.inst_size			= sizeof(rlm_sql_mysql_t),
		.onload				= mod_load,
		.unload				= mod_unload,
		.config				= driver_config,
		.instantiate			= mod_instantiate
	},
	.flags				= RLM_SQL_RCODE_FLAGS_ALT_QUERY,
	.sql_query_resume		= sql_query_resume,
	.sql_select_query_resume	= sql_select_query_resume,
	.sql_num_rows			= sql_num_rows,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fields			= sql_fields,
	.sql_fetch_row			= sql_fetch_row,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_query,
	.sql_escape_func		= sql_escape_func,
	.sql_escape_arg_alloc		= sql_escape_arg_alloc,
	.sql_escape_arg_free		= sql_escape_arg_free,
	.trunk_io_funcs = {
		.connection_alloc	= sql_trunk_connection_alloc,
		.connection_notify	= sql_trunk_connection_notify,
		.request_mux		= sql_trunk_request_mux,
		.request_demux		= sql_trunk_request_demux,
		.request_cancel_mux	= sql_request_cancel_mux,
		.request_cancel		= sql_request_cancel,
		.request_fail		= sql_request_fail,
	}
};
