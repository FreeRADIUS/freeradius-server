/**
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * For more information, please refer to <http://unlicense.org>
 */

/**
 * $Id$
 * @file rlm_sql_cassandra.c
 * @brief Cassandra SQL driver
 *
 * @author Linnaea Von Lavia <le.concorde.4590@gmail.com>
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <cassandra.h>

#include "rlm_sql.h"

static int rlm_sql_cass_instances = 0;

/** Cassandra cluster connection
 *
 */
typedef struct rlm_sql_cassandra_conn {
	CassCluster		*cluster;		//!< Configuration of the cassandra cluster connection.
	CassSession		*session;		//!< Connection to the cassandra cluster.

	const CassResult	*result;		//!< Result from executing a query.
	CassIterator		*iterator;		//!< Row set iterator.

	TALLOC_CTX		*log_ctx;		//!< Prevent unneeded memory allocation by keeping a
							//!< permanent pool, to store log entries.
	sql_log_entry_t		last_error;
} rlm_sql_cassandra_conn_t;

/** Cassandra driver instance
 *
 */
typedef struct rlm_sql_cassandra_config {
	char const		*consistency_str;	//!< Level of consistency required.
	CassConsistency		consistency;		//!< Level of consistency converted to a constant.
} rlm_sql_cassandra_config_t;

static const CONF_PARSER driver_config[] = {
	{ "consistency", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_sql_cassandra_config_t, consistency_str), "quorum" },
	{ NULL, -1, 0, NULL, NULL}
};

static const FR_NAME_NUMBER consistency_levels[] = {
	{ "any",		CASS_CONSISTENCY_ANY },
	{ "one",		CASS_CONSISTENCY_ONE },
	{ "two",		CASS_CONSISTENCY_TWO },
	{ "three",		CASS_CONSISTENCY_THREE },
	{ "quorum",		CASS_CONSISTENCY_QUORUM	},
	{ "all",		CASS_CONSISTENCY_ALL },
	{ "each_quorum",	CASS_CONSISTENCY_EACH_QUORUM },
	{ "local_quorum",	CASS_CONSISTENCY_LOCAL_QUORUM },
	{ "local_one",		CASS_CONSISTENCY_LOCAL_ONE },
	{ NULL, 0 }
};

/** Log callback for libcassandra
 *
 * libcassandra seems to use this to log global events in the library, other messages
 * like query errors are not logged here, and should be retrieved with functions like
 * cass_future_error_message();
 *
 * Messages here do not need to be made available via sql_error.
 *
 * @param message Contains the log message and information about its source.
 * @param data user data (not used).
 */
static void _rlm_sql_cassandra_log(CassLogMessage const *message, UNUSED void *data)
{
	switch (message->severity) {
	case CASS_LOG_CRITICAL:
	case CASS_LOG_ERROR:
		if (DEBUG_ENABLED3) {
			ERROR("rlm_sql_cassandra: %s[%d] %s: %s",
			       message->file, message->line, message->function, message->message);
		} else {
			ERROR("rlm_sql_cassandra: %s", message->message);
		}
		return;

	case CASS_LOG_WARN:
		if (DEBUG_ENABLED3) {
			WARN("rlm_sql_cassandra: %s[%d] %s: %s",
			     message->file, message->line, message->function, message->message);
		} else {
			WARN("rlm_sql_cassandra: %s", message->message);
		}
		return;

	case CASS_LOG_INFO:
	case CASS_LOG_DISABLED:
	case CASS_LOG_LAST_ENTRY:
		if (DEBUG_ENABLED3) {
			INFO("rlm_sql_cassandra: %s[%d] %s: %s",
			     message->file, message->line, message->function, message->message);
		} else {
			INFO("rlm_sql_cassandra: %s", message->message);
		}
		return;

	case CASS_LOG_DEBUG:
	case CASS_LOG_TRACE:
	default:
		if (DEBUG_ENABLED3) {
			DEBUG3("rlm_sql_cassandra: %s[%d] %s: %s",
			       message->file, message->line, message->function, message->message);
		} else {
			DEBUG2("rlm_sql_cassandra: %s", message->message);
		}
		return;
	}
}

/** Replace the last error messages associated with the connection
 *
 * This could be modified in future to maintain a circular buffer of log entries,
 * but it's not required for now.
 *
 * @param conn to replace log message in.
 * @param message from libcassandra.
 * @param len of message.
 */
static void sql_set_last_error(rlm_sql_cassandra_conn_t *conn, char const *message, size_t len)
{
	talloc_free_children(conn->log_ctx);

	conn->last_error.msg = fr_aprints(conn->log_ctx, message, len, '\0');
	conn->last_error.type = L_ERR;
}


/** Replace the last error messages associated with the connection
 *
 * This could be modified in future to maintain a circular buffer of log entries,
 * but it's not required for now.
 *
 * @param conn to replace log message in.
 * @param fmt of message.
 * @param ... args.
 */
static void sql_set_last_error_printf(rlm_sql_cassandra_conn_t *conn, char const *fmt, ...)
	CC_HINT(format (printf, 2, 3));
static void sql_set_last_error_printf(rlm_sql_cassandra_conn_t *conn, char const *fmt, ...)
{
	va_list ap;

	talloc_free_children(conn->log_ctx);

	va_start(ap, fmt);
	conn->last_error.msg = talloc_vasprintf(conn->log_ctx, fmt, ap);
	va_end(ap);
	conn->last_error.type = L_ERR;
}

static int _mod_destructor(UNUSED rlm_sql_cassandra_config_t *conf)
{
	if (--rlm_sql_cass_instances == 0) cass_log_cleanup();	/* must be last call to libcassandra */
	return 0;
}

static int mod_instantiate(CONF_SECTION *conf, rlm_sql_config_t *config)
{
	static bool version_done = false;

	rlm_sql_cassandra_config_t *driver;
	int consistency;

	if (!version_done) {
		version_done = true;

		INFO("rlm_sql_cassandra: Built against libcassandra version %d.%d.%d%s",
		     CASS_VERSION_MAJOR, CASS_VERSION_MINOR, CASS_VERSION_PATCH, CASS_VERSION_SUFFIX);
	}

	MEM(driver = config->driver = talloc_zero(config, rlm_sql_cassandra_config_t));
	talloc_set_destructor(driver, _mod_destructor);

	if (cf_section_parse(conf, driver, driver_config) < 0) return -1;

	consistency = fr_str2int(consistency_levels, driver->consistency_str, -1);
	if (consistency < 0) {
		ERROR("rlm_sql_cassandra: Invalid consistency level \"%s\"", driver->consistency_str);
		return -1;
	}

	driver->consistency = (CassConsistency)consistency;

	cass_log_set_level(CASS_LOG_INFO);
	cass_log_set_callback(_rlm_sql_cassandra_log, driver);

	rlm_sql_cass_instances++;

	return 0;
}

static int _sql_socket_destructor(rlm_sql_cassandra_conn_t *conn)
{
	DEBUG2("rlm_sql_cassandra: Socket destructor called, closing socket");

	if (conn->iterator) cass_iterator_free(conn->iterator);
	if (conn->result) cass_result_free(conn->result);
	if (conn->session) cass_session_free(conn->session);
	if (conn->cluster) cass_cluster_free(conn->cluster);

	return 0;
}

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_cassandra_conn_t	*conn;
	CassCluster			*cluster;
	CassSession			*session;
	CassFuture			*future;
	CassError			ret;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_cassandra_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	DEBUG4("rlm_sql_cassandra: Configuring driver's CassCluster structure");
	cluster = conn->cluster = cass_cluster_new();
	if (!cluster) return RLM_SQL_ERROR;

	cass_cluster_set_contact_points(cluster, config->sql_server);
	cass_cluster_set_port(cluster, atoi(config->sql_port));
	if (config->connect_timeout_ms) cass_cluster_set_connect_timeout(cluster, config->connect_timeout_ms);
	if (config->query_timeout) cass_cluster_set_request_timeout(cluster, config->query_timeout * 1000);
	if (config->sql_login && config->sql_password) cass_cluster_set_credentials(cluster, config->sql_login,
										    config->sql_password);

	DEBUG2("rlm_sql_cassandra: Connecting to Cassandra cluster");
	session = conn->session = cass_session_new();
	if (!session) return RLM_SQL_ERROR;

	future = cass_session_connect_keyspace(session, cluster, config->sql_db);
	ret = cass_future_error_code(future);
	if (ret != CASS_OK) {
		const char	*msg;
		size_t		msg_len;

		cass_future_error_message(future, &msg, &msg_len);
		ERROR("rlm_sql_cassandra: Unable to connect: [%x] %s", (int)ret, msg);
		cass_future_free(future);

		return RLM_SQL_ERROR;
	}
	cass_future_free(future);

	conn->log_ctx = talloc_pool(conn, 1024);	/* Pre-allocate some memory for log messages */

	return RLM_SQL_OK;
}

static sql_rcode_t sql_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char const *query)
{
	rlm_sql_cassandra_conn_t	*conn = handle->conn;
	rlm_sql_cassandra_config_t	*conf = config->driver;
	CassStatement			*statement;
	CassFuture			*future;
	CassError			ret;

	statement = cass_statement_new_n(query, talloc_array_length(query) - 1, 0);
	cass_statement_set_consistency(statement, conf->consistency);

	future = cass_session_execute(conn->session, statement);
	cass_statement_free(statement);

	ret = cass_future_error_code(future);
	if (ret != CASS_OK) {
		char const	*error;
		size_t		len;

		cass_future_error_message(future, &error, &len);
		sql_set_last_error(conn, error, len);
		cass_future_free(future);

		switch (ret) {
		case CASS_ERROR_SERVER_SYNTAX_ERROR:
		case CASS_ERROR_SERVER_INVALID_QUERY:
			return RLM_SQL_QUERY_INVALID;

		default:
			return RLM_SQL_ERROR;
		}
	}

	conn->result = cass_future_get_result(future);
	cass_future_free(future);

	return RLM_SQL_OK;
}

static int sql_num_fields(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_cassandra_conn_t *conn = handle->conn;

	return conn->result ? cass_result_column_count(conn->result) : 0;
}

static int sql_num_rows(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_cassandra_conn_t *conn = handle->conn;

	return conn->result ? cass_result_row_count(conn->result) : 0;
}

static sql_rcode_t sql_fields(char const **out[], rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_cassandra_conn_t *conn = handle->conn;

	unsigned int	fields, i;
	char const	**names;

	fields = sql_num_fields(handle, config);
	if (fields == 0) return RLM_SQL_ERROR;

	MEM(names = talloc_array(handle, char const *, fields));

	for (i = 0; i < fields; i++) {
		const char *col_name;
		size_t	   col_name_len;

		/* Writes out a pointer to a buffer in the result */
		cass_result_column_name(conn->result, i, &col_name, &col_name_len);
		names[i] = col_name;
	}

	*out = names;

	return RLM_SQL_OK;
}

static sql_rcode_t sql_fetch_row(rlm_sql_row_t *out, rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{

	rlm_sql_cassandra_conn_t 	*conn = handle->conn;
	CassRow	const 			*cass_row;
	int				fields, i;
	char				**row;

#define RLM_CASS_ERR_DATA_RETRIVE(_t) \
do {\
	char const *_col_name;\
	size_t _col_name_len;\
	CassError _ret;\
	if ((_ret = cass_result_column_name(conn->result, i, &_col_name, &_col_name_len)) != CASS_OK) {\
		_col_name = "<INVALID>";\
	}\
	sql_set_last_error_printf(conn, "Failed to retrieve " _t " data at column %s (%d): %s", \
				  _col_name, i, cass_error_desc(_ret));\
	TALLOC_FREE(handle->row);\
	return RLM_SQL_ERROR;\
} while(0)

	if (!conn->result) return RLM_SQL_OK;				/* no result */

	*out = NULL;

	/*
	 *	Start of the result set, initialise the iterator.
	 */
	if (!conn->iterator) conn->iterator = cass_iterator_from_result(conn->result);
	if (!conn->iterator) return RLM_SQL_OK;				/* no result */

	if (!cass_iterator_next(conn->iterator)) return RLM_SQL_OK;	/* no more rows */

	cass_row = cass_iterator_get_row(conn->iterator);		/* this shouldn't fail ? */
	fields = sql_num_fields(handle, config);			/* get the number of fields... */

	/*
	 *	Free the previous result (also gets called on finish_query)
	 */
	talloc_free(handle->row);
	MEM(row = handle->row = talloc_zero_array(handle, char *, fields + 1));

	for (i = 0; i < fields; i++) {
		CassValue const	*value;
		CassValueType	type;

		value = cass_row_get_column(cass_row, i);

		if (cass_value_is_null(value) == cass_true) continue;

		type = cass_value_type(value);
		switch (type) {
		case CASS_VALUE_TYPE_ASCII:
		case CASS_VALUE_TYPE_TEXT:
		case CASS_VALUE_TYPE_VARCHAR:
		{
			const char	*str;
			size_t		len;

			if (cass_value_get_string(value, &str, &len) != CASS_OK) RLM_CASS_ERR_DATA_RETRIVE("string");

			MEM(row[i] = talloc_array(row, char, len + 1));
			memcpy(row[i], str, len);
			row[i][len] = '\0';
		}
			break;

		case CASS_VALUE_TYPE_BOOLEAN:
		{
			cass_bool_t bv;

			if (cass_value_get_bool(value, &bv) != CASS_OK) RLM_CASS_ERR_DATA_RETRIVE("bool");

			MEM(row[i] = talloc_zero_array(row, char, 2));
			row[i][0] = (bv == cass_false) ? '0' : '1';
		}
			break;

		case CASS_VALUE_TYPE_INT:
		{
			cass_int32_t i32v;

			if (cass_value_get_int32(value, &i32v) != CASS_OK) RLM_CASS_ERR_DATA_RETRIVE("int32");

			MEM(row[i] = talloc_asprintf(row, "%"PRId32, (int32_t)i32v));
		}
			break;

		case CASS_VALUE_TYPE_TIMESTAMP:
		case CASS_VALUE_TYPE_BIGINT:
		{
			cass_int64_t i64v;

			if (cass_value_get_int64(value, &i64v) != CASS_OK) RLM_CASS_ERR_DATA_RETRIVE("int64");

			MEM(row[i] = talloc_asprintf(row, "%"PRId64, (int64_t)i64v));
		}
			break;

		case CASS_VALUE_TYPE_UUID:
		case CASS_VALUE_TYPE_TIMEUUID:
		{
			CassUuid uuid;

			if (cass_value_get_uuid(value, &uuid) != CASS_OK) RLM_CASS_ERR_DATA_RETRIVE("UUID");
			MEM(row[i] = talloc_array(row, char, CASS_UUID_STRING_LENGTH));
			cass_uuid_string(uuid, row[i]);
		}
			break;

		default:
		{
			const char *col_name;
			size_t	   col_name_len;

			if (cass_result_column_name(conn->result, i, &col_name,
						    &col_name_len) != CASS_OK) col_name = "<INVALID>";

			sql_set_last_error_printf(conn,
						  "Failed to retrieve data at column %s (%d): Unsupported data type",
						  col_name, i);
			talloc_free(handle->row);
			return RLM_SQL_ERROR;
		}
		}
	}
	*out = row;

	return RLM_SQL_OK;
}

static sql_rcode_t sql_free_result(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_cassandra_conn_t *conn = handle->conn;

	if (handle->row) TALLOC_FREE(handle->row);

	if (conn->iterator) {
		cass_iterator_free(conn->iterator);
		conn->iterator = NULL;
	}

	if (conn->result) {
		cass_result_free(conn->result);
		conn->result = NULL;
	}

	return RLM_SQL_OK;
}

static size_t sql_error(UNUSED TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_cassandra_conn_t *conn = handle->conn;

	if (conn->last_error.msg && (outlen >= 1)) {
		out[0].msg = conn->last_error.msg;
		out[0].type = conn->last_error.type;
		conn->last_error.msg = NULL;

		return 1;
	}

	return 0;
}

static sql_rcode_t sql_finish_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_cassandra_conn_t *conn = handle->conn;

	/*
	 *	Clear our local log buffer, and free any messages which weren't
	 *	reparented (so we don't leak memory).
	 */
	talloc_free_children(conn->log_ctx);
	memset(&conn->last_error, 0, sizeof(conn->last_error));

	return sql_free_result(handle, config);
}

/*
 *	The cassandra model is different, as it's distributed, and does
 *	upserts instead of inserts...
 *
 *	There's a good article on it here:
 *		http://planetcassandra.org/blog/how-to-do-an-upsert-in-cassandra/
 */
static int sql_affected_rows(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	return 1;
}

/* Exported to rlm_sql */
extern rlm_sql_module_t rlm_sql_cassandra;
rlm_sql_module_t rlm_sql_cassandra = {
	.name				= "rlm_sql_cassandra",
	.mod_instantiate		= mod_instantiate,
	.sql_socket_init		= sql_socket_init,
	.sql_query			= sql_query,
	.sql_select_query		= sql_query,
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
