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

#define LOG_PREFIX "sql - mysql"

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
	MYSQL		db;
	MYSQL		*sock;
	MYSQL_RES	*result;
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
	CONF_PARSER_TERMINATOR
};

/* Prototypes */
static sql_rcode_t sql_free_result(fr_sql_query_t *, rlm_sql_config_t const *);

static int _sql_socket_destructor(rlm_sql_mysql_conn_t *conn)
{
	DEBUG2("Socket destructor called, closing socket");

	if (conn->sock) {
		mysql_close(conn->sock);
		conn->sock = NULL;
	}

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_sql_mysql_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_sql_mysql_t);
	int			warnings;

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
	if (mysql_library_init(0, NULL, NULL)) {
		ERROR("libmysql initialisation failed");

		return -1;
	}

	INFO("libmysql version: %s", mysql_get_client_info());

	return 0;
}

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t const *config, fr_time_delta_t timeout)
{
	rlm_sql_mysql_t *inst = talloc_get_type_abort(handle->inst->driver_submodule->data, rlm_sql_mysql_t);
	rlm_sql_mysql_conn_t *conn;

	unsigned int connect_timeout = (unsigned int)fr_time_delta_to_sec(timeout);
	unsigned long sql_flags;

	enum mysql_option	ssl_mysql_opt;
	unsigned int		ssl_mode = 0;
	bool			ssl_mode_isset = false;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_mysql_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	DEBUG("Starting connect to MySQL server");

	mysql_init(&(conn->db));

	/*
	 *	If any of the TLS options are set, configure TLS
	 *
	 *	According to MySQL docs this function always returns 0, so we won't
	 *	know if ssl setup succeeded until mysql_real_connect is called below.
	 */
	if (inst->tls_ca_file || inst->tls_ca_path ||
	    inst->tls_certificate_file || inst->tls_private_key_file) {
		mysql_ssl_set(&(conn->db), inst->tls_private_key_file, inst->tls_certificate_file,
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
	if (ssl_mode_isset) mysql_options(&(conn->db), ssl_mysql_opt, &ssl_mode);

	if (inst->tls_crl_file) mysql_options(&(conn->db), MYSQL_OPT_SSL_CRL, inst->tls_crl_file);
	if (inst->tls_crl_path) mysql_options(&(conn->db), MYSQL_OPT_SSL_CRLPATH, inst->tls_crl_path);

	mysql_options(&(conn->db), MYSQL_READ_DEFAULT_GROUP, "freeradius");

	/*
	 *	We need to know about connection errors, and are capable
	 *	of reconnecting automatically.
	 */
	{
		bool reconnect = 0;
		mysql_options(&(conn->db), MYSQL_OPT_RECONNECT, &reconnect);
	}

	mysql_options(&(conn->db), MYSQL_OPT_CONNECT_TIMEOUT, &connect_timeout);

	if (fr_time_delta_ispos(config->query_timeout)) {
		unsigned int read_timeout = fr_time_delta_to_sec(config->query_timeout);
		unsigned int write_timeout = fr_time_delta_to_sec(config->query_timeout);

		/*
		 *	The timeout in seconds for each attempt to read from the server.
		 *	There are retries if necessary, so the total effective timeout
		 *	value is three times the option value.
		 */
		if (read_timeout >= 3) read_timeout /= 3;

		/*
		 *	The timeout in seconds for each attempt to write to the server.
		 *	There is a retry if necessary, so the total effective timeout
		 *	value is two times the option value.
		 */
		if (write_timeout >= 2) write_timeout /= 2;

		/*
		 *	Connect timeout is actually connect timeout (according to the
		 *	docs) there are no automatic retries.
		 */
		mysql_options(&(conn->db), MYSQL_OPT_READ_TIMEOUT, &read_timeout);
		mysql_options(&(conn->db), MYSQL_OPT_WRITE_TIMEOUT, &write_timeout);
	}

	sql_flags = CLIENT_MULTI_RESULTS | CLIENT_FOUND_ROWS;

#ifdef CLIENT_MULTI_STATEMENTS
	sql_flags |= CLIENT_MULTI_STATEMENTS;
#endif
	conn->sock = mysql_real_connect(&(conn->db),
					config->sql_server,
					config->sql_login,
					config->sql_password,
					config->sql_db,
					config->sql_port,
					NULL,
					sql_flags);
	if (!conn->sock) {
		ERROR("Couldn't connect to MySQL server %s@%s:%s", config->sql_login,
		      config->sql_server, config->sql_db);
		ERROR("MySQL error: %s", mysql_error(&conn->db));

		conn->sock = NULL;
		return RLM_SQL_ERROR;
	}

	DEBUG2("Connected to database '%s' on %s, server version %s, protocol version %i",
	       config->sql_db, mysql_get_host_info(conn->sock),
	       mysql_get_server_info(conn->sock), mysql_get_proto_info(conn->sock));

	return RLM_SQL_OK;
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

	}

	return RLM_SQL_OK;
}

static unlang_action_t sql_query(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_mysql_conn_t	*conn = talloc_get_type_abort(query_ctx->handle->conn, rlm_sql_mysql_conn_t);
	char const *info;

	mysql_query(conn->sock, query_ctx->query_str);
	query_ctx->rcode = sql_check_error(conn->sock, 0);
	if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL;

	/* Only returns non-null string for INSERTS */
	info = mysql_info(conn->sock);
	if (info) DEBUG2("%s", info);

	RETURN_MODULE_OK;
}

static sql_rcode_t sql_store_result(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mysql_conn_t *conn = talloc_get_type_abort(handle->conn, rlm_sql_mysql_conn_t);
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

static int sql_num_fields(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mysql_conn_t *conn = talloc_get_type_abort(handle->conn, rlm_sql_mysql_conn_t);

	/*
	 *	Count takes a connection handle
	 */
	return mysql_field_count(conn->sock);
}

static unlang_action_t sql_select_query(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	fr_sql_query_t	*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);

	sql_query(p_result, NULL, request, query_ctx);
	if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL;

	query_ctx->rcode = sql_store_result(query_ctx->handle, &query_ctx->inst->config);
	if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL;
	RETURN_MODULE_OK;
}

static int sql_num_rows(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mysql_conn_t *conn = talloc_get_type_abort(query_ctx->handle->conn, rlm_sql_mysql_conn_t);

	if (conn->result) return mysql_num_rows(conn->result);

	return 0;
}

static sql_rcode_t sql_fields(char const **out[], rlm_sql_handle_t *handle, rlm_sql_config_t const *config)
{
	rlm_sql_mysql_conn_t *conn = talloc_get_type_abort(handle->conn, rlm_sql_mysql_conn_t);

	unsigned int	fields, i;
	MYSQL_FIELD	*field_info;
	char const	**names;

	/*
	 *	Use our internal function to abstract out the API call.
	 *	Different versions of SQL use different functions,
	 *	and some don't like NULL pointers.
	 */
	fields = sql_num_fields(handle, config);
	if (fields == 0) return RLM_SQL_ERROR;

	/*
	 *	https://bugs.mysql.com/bug.php?id=32318
	 * 	Hints that we don't have to free field_info.
	 */
	field_info = mysql_fetch_fields(conn->result);
	if (!field_info) return RLM_SQL_ERROR;

	MEM(names = talloc_array(handle, char const *, fields));

	for (i = 0; i < fields; i++) names[i] = field_info[i].name;
	*out = names;

	return RLM_SQL_OK;
}

static unlang_action_t sql_fetch_row(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_handle_t	*handle = query_ctx->handle;
	rlm_sql_mysql_conn_t	*conn = talloc_get_type_abort(handle->conn, rlm_sql_mysql_conn_t);
	MYSQL_ROW		row;
	int			ret;
	unsigned int		num_fields, i;
	unsigned long		*field_lens;

	/*
	 *  Check pointer before de-referencing it.
	 */
	if (!conn->result) {
		query_ctx->rcode = RLM_SQL_RECONNECT;
		RETURN_MODULE_FAIL;
	}

	TALLOC_FREE(query_ctx->row);		/* Clear previous row set */

retry_fetch_row:
	row = mysql_fetch_row(conn->result);
	if (!row) {
		query_ctx->rcode = sql_check_error(conn->sock, 0);
		if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL;

		sql_free_result(query_ctx, &query_ctx->inst->config);

		ret = mysql_next_result(conn->sock);
		if (ret == 0) {
			/* there are more results */
			if ((sql_store_result(handle, &query_ctx->inst->config) == 0) && (conn->result != NULL)) {
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

	num_fields = mysql_num_fields(conn->result);
	if (!num_fields) {
		query_ctx->rcode = RLM_SQL_NO_MORE_ROWS;
		RETURN_MODULE_OK;
	}

 	field_lens = mysql_fetch_lengths(conn->result);

	MEM(query_ctx->row = talloc_zero_array(query_ctx, char *, num_fields + 1));
	for (i = 0; i < num_fields; i++) {
		MEM(query_ctx->row[i] = talloc_bstrndup(query_ctx->row, row[i], field_lens[i]));
	}

	query_ctx->rcode = RLM_SQL_OK;
	RETURN_MODULE_OK;
}

static sql_rcode_t sql_free_result(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_mysql_conn_t *conn = talloc_get_type_abort(query_ctx->handle->conn, rlm_sql_mysql_conn_t);

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
 * @param config rlm_sql config.
 * @return
 *	- Number of errors written to the #sql_log_entry_t array.
 *	- -1 on failure.
 */
static size_t sql_warnings(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			   rlm_sql_mysql_conn_t *conn, UNUSED rlm_sql_config_t const *config)
{
	MYSQL_RES		*result;
	MYSQL_ROW		row;
	unsigned int		num_fields;
	size_t			i = 0;

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
 * @param config rlm_sql config.
 * @return number of errors written to the #sql_log_entry_t array.
 */
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			fr_sql_query_t *query_ctx, rlm_sql_config_t const *config)
{
	rlm_sql_mysql_t const	*inst = talloc_get_type_abort_const(query_ctx->inst->driver_submodule->data, rlm_sql_mysql_t);
	rlm_sql_mysql_conn_t	*conn = talloc_get_type_abort(query_ctx->handle->conn, rlm_sql_mysql_conn_t);
	char const		*error;
	size_t			i = 0;

	fr_assert(outlen > 0);

	error = mysql_error(conn->sock);

	/*
	 *	Grab the error now in case it gets cleared on the next operation.
	 */
	if (error && (error[0] != '\0')) {
		error = talloc_typed_asprintf(ctx, "ERROR %u (%s): %s", mysql_errno(conn->sock), error,
					      mysql_sqlstate(conn->sock));
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
			ret = sql_warnings(ctx, out, outlen - 1, conn, config);
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
	}
	i++;

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
	rlm_sql_mysql_conn_t	*conn = talloc_get_type_abort(query_ctx->handle->conn, rlm_sql_mysql_conn_t);
	int			ret;
	MYSQL_RES		*result;

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
	rlm_sql_mysql_conn_t *conn = talloc_get_type_abort(query_ctx->handle->conn, rlm_sql_mysql_conn_t);

	return mysql_affected_rows(conn->sock);
}

static size_t sql_escape_func(UNUSED request_t *request, char *out, size_t outlen, char const *in, void *arg)
{
	size_t			inlen;
	rlm_sql_handle_t	*handle = talloc_get_type_abort(arg, rlm_sql_handle_t);
	rlm_sql_mysql_conn_t	*conn = talloc_get_type_abort(handle->conn, rlm_sql_mysql_conn_t);

	/* Check for potential buffer overflow */
	inlen = strlen(in);
	if ((inlen * 2 + 1) > outlen) return 0;
	/* Prevent integer overflow */
	if ((inlen * 2 + 1) <= inlen) return 0;

	return mysql_real_escape_string(conn->sock, out, in, inlen);
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
	.sql_socket_init		= sql_socket_init,
	.sql_query			= sql_query,
	.sql_select_query		= sql_select_query,
	.sql_num_fields			= sql_num_fields,
	.sql_num_rows			= sql_num_rows,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fields			= sql_fields,
	.sql_fetch_row			= sql_fetch_row,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_query,
	.sql_escape_func		= sql_escape_func
};
