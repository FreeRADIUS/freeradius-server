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
 * @copyright 2014-2015  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2000-2007,2015  The FreeRADIUS server project
 * @copyright 2000  Mike Machado <mike@innercite.com>
 * @copyright 2000  Alan DeKok <aland@ox.org>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/stat.h>

#include "config.h"

#ifdef HAVE_MYSQL_MYSQL_H
#  include <mysql/mysql_version.h>
#  include <mysql/errmsg.h>
#  include <mysql/mysql.h>
#  include <mysql/mysqld_error.h>
#elif defined(HAVE_MYSQL_H)
#  include <mysql_version.h>
#  include <errmsg.h>
#  include <mysql.h>
#  include <mysqld_error.h>
#endif

#include "rlm_sql.h"

static int mysql_instance_count = 0;

typedef enum {
	SERVER_WARNINGS_AUTO = 0,
	SERVER_WARNINGS_YES,
	SERVER_WARNINGS_NO
} rlm_sql_mysql_warnings;

static const FR_NAME_NUMBER server_warnings_table[] = {
	{ "auto",	SERVER_WARNINGS_AUTO	},
	{ "yes",	SERVER_WARNINGS_YES	},
	{ "no",		SERVER_WARNINGS_NO	},
	{ NULL, 0 }
};

typedef struct rlm_sql_mysql_conn {
	MYSQL		db;
	MYSQL		*sock;
	MYSQL_RES	*result;
} rlm_sql_mysql_conn_t;

typedef struct rlm_sql_mysql_config {
	char const *tls_ca_file;		//!< Path to the CA used to validate the server's certificate.
	char const *tls_ca_path;		//!< Directory containing CAs that may be used to validate the
						//!< servers certificate.
	char const *tls_certificate_file;	//!< Public certificate we present to the server.
	char const *tls_private_key_file;	//!< Private key for the certificate we present to the server.
	char const *tls_cipher;

	char const *warnings_str;		//!< Whether we always query the server for additional warnings.
	rlm_sql_mysql_warnings	warnings;	//!< mysql_warning_count() doesn't
						//!< appear to work with NDB cluster
} rlm_sql_mysql_config_t;

static CONF_PARSER tls_config[] = {
	{ "ca_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_sql_mysql_config_t, tls_ca_file), NULL },
	{ "ca_path", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_sql_mysql_config_t, tls_ca_path), NULL },
	{ "certificate_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_sql_mysql_config_t, tls_certificate_file), NULL },
	{ "private_key_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_sql_mysql_config_t, tls_private_key_file), NULL },

	/*
	 *	MySQL Specific TLS attributes
	 */
	{ "cipher", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_sql_mysql_config_t, tls_cipher), NULL },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER driver_config[] = {
	{ "tls", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) tls_config },

	{ "warnings", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_sql_mysql_config_t, warnings_str), "auto" },
	CONF_PARSER_TERMINATOR
};

/* Prototypes */
static sql_rcode_t sql_free_result(rlm_sql_handle_t*, rlm_sql_config_t*);

static int _sql_socket_destructor(rlm_sql_mysql_conn_t *conn)
{
	DEBUG2("rlm_sql_mysql: Socket destructor called, closing socket");

	if (conn->sock){
		mysql_close(conn->sock);
	}

	return 0;
}

static int _mod_destructor(UNUSED rlm_sql_mysql_config_t *driver)
{
	if (--mysql_instance_count == 0) mysql_library_end();

	return 0;
}

static int mod_instantiate(CONF_SECTION *conf, rlm_sql_config_t *config)
{
	rlm_sql_mysql_config_t *driver;
	int warnings;

	static bool version_done = false;

	if (!version_done) {
		version_done = true;

		INFO("rlm_sql_mysql: libmysql version: %s", mysql_get_client_info());
	}

	if (mysql_instance_count == 0) {
		if (mysql_library_init(0, NULL, NULL)) {
			ERROR("rlm_sql_mysql: libmysql initialisation failed");

			return -1;
		}
	}
	mysql_instance_count++;

	MEM(driver = config->driver = talloc_zero(config, rlm_sql_mysql_config_t));
	talloc_set_destructor(driver, _mod_destructor);

	if (cf_section_parse(conf, driver, driver_config) < 0) {
		return -1;
	}

	warnings = fr_str2int(server_warnings_table, driver->warnings_str, -1);
	if (warnings < 0) {
		ERROR("rlm_sql_mysql: Invalid warnings value \"%s\", must be yes, no, or auto", driver->warnings_str);
		return -1;
	}
	driver->warnings = (rlm_sql_mysql_warnings)warnings;

	return 0;
}

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_mysql_conn_t *conn;
	rlm_sql_mysql_config_t *driver = config->driver;
	unsigned long sql_flags;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_mysql_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	DEBUG("rlm_sql_mysql: Starting connect to MySQL server");

	mysql_init(&(conn->db));

	/*
	 *	If any of the TLS options are set, configure TLS
	 *
	 *	According to MySQL docs this function always returns 0, so we won't
	 *	know if ssl setup succeeded until mysql_real_connect is called below.
	 */
	if (driver->tls_ca_file || driver->tls_ca_path ||
	    driver->tls_certificate_file || driver->tls_private_key_file) {
		mysql_ssl_set(&(conn->db), driver->tls_private_key_file, driver->tls_certificate_file,
			      driver->tls_ca_file, driver->tls_ca_path, driver->tls_cipher);
	}

	mysql_options(&(conn->db), MYSQL_READ_DEFAULT_GROUP, "freeradius");

	/*
	 *	We need to know about connection errors, and are capable
	 *	of reconnecting automatically.
	 */
#ifdef MYSQL_OPT_RECONNECT
	{
		my_bool reconnect = 0;
		mysql_options(&(conn->db), MYSQL_OPT_RECONNECT, &reconnect);
	}
#endif

#if (MYSQL_VERSION_ID >= 50000)
	if (config->query_timeout) {
		unsigned int connect_timeout = config->query_timeout;
		unsigned int read_timeout = config->query_timeout;
		unsigned int write_timeout = config->query_timeout;

		/*
		 *	The timeout in seconds for each attempt to read from the server.
		 *	There are retries if necessary, so the total effective timeout
		 *	value is three times the option value.
		 */
		if (config->query_timeout >= 3) read_timeout /= 3;

		/*
		 *	The timeout in seconds for each attempt to write to the server.
		 *	There is a retry if necessary, so the total effective timeout
		 *	value is two times the option value.
		 */
		if (config->query_timeout >= 2) write_timeout /= 2;

		/*
		 *	Connect timeout is actually connect timeout (according to the
		 *	docs) there are no automatic retries.
		 */
		mysql_options(&(conn->db), MYSQL_OPT_CONNECT_TIMEOUT, &connect_timeout);
		mysql_options(&(conn->db), MYSQL_OPT_READ_TIMEOUT, &read_timeout);
		mysql_options(&(conn->db), MYSQL_OPT_WRITE_TIMEOUT, &write_timeout);
	}
#endif

#if (MYSQL_VERSION_ID >= 40100)
	sql_flags = CLIENT_MULTI_RESULTS | CLIENT_FOUND_ROWS;
#else
	sql_flags = CLIENT_FOUND_ROWS;
#endif

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
		ERROR("rlm_sql_mysql: Couldn't connect to MySQL server %s@%s:%s", config->sql_login,
		      config->sql_server, config->sql_db);
		ERROR("rlm_sql_mysql: MySQL error: %s", mysql_error(&conn->db));

		conn->sock = NULL;
		return RLM_SQL_ERROR;
	}

	DEBUG2("rlm_sql_mysql: Connected to database '%s' on %s, server version %s, protocol version %i",
	       config->sql_db, mysql_get_host_info(conn->sock),
	       mysql_get_server_info(conn->sock), mysql_get_proto_info(conn->sock));

	return RLM_SQL_OK;
}

/** Analyse the last error that occurred on the socket, and determine an action
 *
 * @param server Socket from which to extract the server error. May be NULL.
 * @param client_errno Error from the client.
 * @return an action for rlm_sql to take.
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
	case -1:
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

static sql_rcode_t sql_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config, char const *query)
{
	rlm_sql_mysql_conn_t *conn = handle->conn;
	sql_rcode_t rcode;
	char const *info;

	if (!conn->sock) {
		ERROR("rlm_sql_mysql: Socket not connected");
		return RLM_SQL_RECONNECT;
	}

	mysql_query(conn->sock, query);
	rcode = sql_check_error(conn->sock, 0);
	if (rcode != RLM_SQL_OK) {
		return rcode;
	}

	/* Only returns non-null string for INSERTS */
	info = mysql_info(conn->sock);
	if (info) DEBUG2("rlm_sql_mysql: %s", info);

	return RLM_SQL_OK;
}

static sql_rcode_t sql_store_result(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_mysql_conn_t *conn = handle->conn;
	sql_rcode_t rcode;
	int ret;

	if (!conn->sock) {
		ERROR("rlm_sql_mysql: Socket not connected");
		return RLM_SQL_RECONNECT;
	}

retry_store_result:
	conn->result = mysql_store_result(conn->sock);
	if (!conn->result) {
		rcode = sql_check_error(conn->sock, 0);
		if (rcode != RLM_SQL_OK) return rcode;
#if (MYSQL_VERSION_ID >= 40100)
		ret = mysql_next_result(conn->sock);
		if (ret == 0) {
			/* there are more results */
			goto retry_store_result;
		} else if (ret > 0) return sql_check_error(NULL, ret);
		/* ret == -1 signals no more results */
#endif
	}
	return RLM_SQL_OK;
}

static int sql_num_fields(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	int num = 0;
	rlm_sql_mysql_conn_t *conn = handle->conn;

#if MYSQL_VERSION_ID >= 32224
	/*
	 *	Count takes a connection handle
	 */
	if (!(num = mysql_field_count(conn->sock))) {
#else
	/*
	 *	Fields takes a result struct
	 */
	if (!(num = mysql_num_fields(conn->result))) {
#endif
		return -1;
	}
	return num;
}

static sql_rcode_t sql_select_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char const *query)
{
	sql_rcode_t rcode;

	rcode = sql_query(handle, config, query);
	if (rcode != RLM_SQL_OK) {
		return rcode;
	}

	rcode = sql_store_result(handle, config);
	if (rcode != RLM_SQL_OK) {
		return rcode;
	}

	/* Why? Per http://www.mysql.com/doc/n/o/node_591.html,
	 * this cannot return an error.  Perhaps just to complain if no
	 * fields are found?
	 */
	sql_num_fields(handle, config);

	return rcode;
}

static int sql_num_rows(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_mysql_conn_t *conn = handle->conn;

	if (conn->result) {
		return mysql_num_rows(conn->result);
	}

	return 0;
}

static sql_rcode_t sql_fields(char const **out[], rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_mysql_conn_t *conn = handle->conn;

	unsigned int	fields, i;
	MYSQL_FIELD	*field_info;
	char const	**names;

	fields = mysql_num_fields(conn->result);
	if (fields == 0) return RLM_SQL_ERROR;

	/*
	 *	https://bugs.mysql.com/bug.php?id=32318
	 * 	Hints that we don't have to free field_info.
	 */
	field_info = mysql_fetch_fields(conn->result);
	if (!field_info) return RLM_SQL_ERROR;

	MEM(names = talloc_zero_array(handle, char const *, fields + 1));

	for (i = 0; i < fields; i++) names[i] = field_info[i].name;
	*out = names;

	return RLM_SQL_OK;
}

static sql_rcode_t sql_fetch_row(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_mysql_conn_t	*conn = handle->conn;
	sql_rcode_t		rcode;
	MYSQL_ROW		row;
	int			ret;
	unsigned int		num_fields, i;
	unsigned long		*field_lens;

	/*
	 *  Check pointer before de-referencing it.
	 */
	if (!conn->result) {
		return RLM_SQL_RECONNECT;
	}

	TALLOC_FREE(handle->row);		/* Clear previous row set */

retry_fetch_row:
	row = mysql_fetch_row(conn->result);
	if (!row) {
		rcode = sql_check_error(conn->sock, 0);
		if (rcode != RLM_SQL_OK) return rcode;

#if (MYSQL_VERSION_ID >= 40100)
		sql_free_result(handle, config);

		ret = mysql_next_result(conn->sock);
		if (ret == 0) {
			/* there are more results */
			if ((sql_store_result(handle, config) == 0) && (conn->result != NULL)) {
				goto retry_fetch_row;
			}
		} else if (ret > 0) return sql_check_error(NULL, ret);
		/* If ret is -1 then there are no more rows */
#endif
		return RLM_SQL_NO_MORE_ROWS;
	}

	num_fields = mysql_num_fields(conn->result);
	if (!num_fields) return RLM_SQL_NO_MORE_ROWS;

	field_lens = mysql_fetch_lengths(conn->result);

	MEM(handle->row = talloc_zero_array(handle, char *, num_fields + 1));
	for (i = 0; i < num_fields; i++) {
		MEM(handle->row[i] = talloc_bstrndup(handle->row, row[i], field_lens[i]));
	}

	return RLM_SQL_OK;
}

static sql_rcode_t sql_free_result(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_mysql_conn_t *conn = handle->conn;

	if (conn->result) {
		mysql_free_result(conn->result);
		conn->result = NULL;
	}
	TALLOC_FREE(handle->row);

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
 * @param handle rlm_sql connection handle.
 * @param config rlm_sql config.
 * @return number of errors written to the sql_log_entry array or -1 on error.
 */
static size_t sql_warnings(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			   rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_mysql_conn_t	*conn = handle->conn;

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
		WARN("rlm_sql_mysql: Failed retrieving warnings, expected 3 fields got %u", num_fields);
		mysql_free_result(result);

		return -1;
	}

	while ((row = mysql_fetch_row(result))) {
		char *msg = NULL;
		log_type_t type;

		/*
		 *	Translate the MySQL log level into our internal
		 *	log levels, so they get colourised correctly.
		 */
		if (strcasecmp(row[0], "warning") == 0)	type = L_WARN;
		else if (strcasecmp(row[0], "note") == 0) type = L_DBG;
		else type = L_ERR;

		msg = talloc_asprintf(ctx, "%s: %s", row[1], row[2]);
		out[i].type = type;
		out[i].msg = msg;
		if (++i == outlen) break;
	}

	mysql_free_result(result);

	return i;
}

/** Retrieves any errors associated with the connection handle
 *
 * @note Caller should free any memory allocated in ctx (talloc_free_children()).
 *
 * @param ctx to allocate temporary error buffers in.
 * @param out Array of sql_log_entrys to fill.
 * @param outlen Length of out array.
 * @param handle rlm_sql connection handle.
 * @param config rlm_sql config.
 * @return number of errors written to the sql_log_entry array.
 */
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_mysql_conn_t	*conn = handle->conn;
	rlm_sql_mysql_config_t	*driver = config->driver;
	char const		*error;
	size_t			i = 0;

	rad_assert(conn && conn->sock);
	rad_assert(outlen > 0);

	error = mysql_error(conn->sock);

	/*
	 *	Grab the error now in case it gets cleared on the next operation.
	 */
	if (error && (error[0] != '\0')) {
		error = talloc_asprintf(ctx, "ERROR %u (%s): %s", mysql_errno(conn->sock), error,
					mysql_sqlstate(conn->sock));
	}

	/*
	 *	Don't attempt to get errors from the server, if the last error
	 *	was that the server was unavailable.
	 */
	if ((outlen > 1) && (sql_check_error(conn->sock, 0) != RLM_SQL_RECONNECT)) {
		size_t ret;
		unsigned int msgs;

		switch (driver->warnings) {
		case SERVER_WARNINGS_AUTO:
			/*
			 *	Check to see if any warnings can be retrieved from the server.
			 */
			msgs = mysql_warning_count(conn->sock);
			if (msgs == 0) {
				DEBUG3("rlm_sql_mysql: No additional diagnostic info on server");
				break;
			}

		/* FALL-THROUGH */
		case SERVER_WARNINGS_YES:
			ret = sql_warnings(ctx, out, outlen - 1, handle, config);
			if (ret > 0) i += ret;
			break;

		case SERVER_WARNINGS_NO:
			break;

		default:
			rad_assert(0);
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
static sql_rcode_t sql_finish_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
#if (MYSQL_VERSION_ID >= 40100)
	rlm_sql_mysql_conn_t	*conn = handle->conn;
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
		sql_free_result(handle, config);	/* sql_free_result sets conn->result to NULL */
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
#endif
	return RLM_SQL_OK;
}

static int sql_affected_rows(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_mysql_conn_t *conn = handle->conn;

	return mysql_affected_rows(conn->sock);
}


/* Exported to rlm_sql */
extern rlm_sql_module_t rlm_sql_mysql;
rlm_sql_module_t rlm_sql_mysql = {
	.name				= "rlm_sql_mysql",
	.flags				= RLM_SQL_RCODE_FLAGS_ALT_QUERY,
	.mod_instantiate		= mod_instantiate,
	.sql_socket_init		= sql_socket_init,
	.sql_query			= sql_query,
	.sql_select_query		= sql_select_query,
	.sql_store_result		= sql_store_result,
	.sql_num_fields			= sql_num_fields,
	.sql_num_rows			= sql_num_rows,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fields			= sql_fields,
	.sql_fetch_row			= sql_fetch_row,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_query
};
