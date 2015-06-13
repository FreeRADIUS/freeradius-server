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
	sql_log_entry_t		log_entry[20];		//!< How many log entries to keep.
	int			log_idx;		//!< Next idx to write log entry at.
	int			log_count;		//!< Number of log entries written.
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

static void _rlm_sql_cassandra_log(CassLogMessage const *message, void *data)
{
	rlm_sql_cassandra_conn_t *conn = data;

	conn->log_idx = conn->log_count % (sizeof(conn->log_entry) / sizeof(*conn->log_entry));

	switch (message->severity) {
	case CASS_LOG_CRITICAL:
	case CASS_LOG_ERROR:
		conn->log_entry[conn->log_idx].type = L_ERR;
		break;

	case CASS_LOG_WARN:
		conn->log_entry[conn->log_idx].type = L_WARN;
		break;

	case CASS_LOG_INFO:
	case CASS_LOG_DISABLED:
	case CASS_LOG_LAST_ENTRY:
		conn->log_entry[conn->log_idx].type = L_INFO;
		break;

	case CASS_LOG_DEBUG:
	case CASS_LOG_TRACE:
	default:
		conn->log_entry[conn->log_idx].type = L_DBG;
		break;
	}

	/*
	 *	If we've wrapped, start freeing old entries
	 */
	if (conn->log_entry[conn->log_idx].msg) rad_const_free(conn->log_entry[conn->log_idx].msg);

	/*
	 *	Add the log entry to the buffer
	 */
	MEM(conn->log_entry[conn->log_idx].msg = talloc_asprintf(conn->log_ctx, "(%i) At %" PRId64 "ms, in file %s, "
								 "function %s, line %d: %s",
								 conn->log_count,
								 (int64_t)message->time_ms,
								 message->file,
								 message->function,
								 message->line,
								 message->message));
	conn->log_count++;
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

	if (conn->iterator) {
		cass_iterator_free(conn->iterator);
		conn->iterator = NULL;
	}

	if (conn->result) {
		cass_result_free(conn->result);
		conn->result = NULL;
	}

	if (conn->session) {
		cass_session_free(conn->session);
		conn->session = NULL;
	}

	if (conn->cluster) {
		cass_cluster_free(conn->cluster);
		conn->cluster = NULL;
	}

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

	conn->cluster = cluster = cass_cluster_new();
	if (!cluster) {
		return RLM_SQL_ERROR;
	}
	cass_cluster_set_contact_points(cluster, config->sql_server);
	cass_cluster_set_port(cluster, atoi(config->sql_port));
	cass_cluster_set_connect_timeout(cluster, config->connect_timeout_ms);
	cass_cluster_set_request_timeout(cluster, config->query_timeout);
	cass_cluster_set_credentials(cluster, config->sql_login, config->sql_password);

	DEBUG2("rlm_sql_cassandra: Connecting to Cassandra cluster");
	session = conn->session = cass_session_new();
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

#define RLM_CASS_ERR_DATA_RETRIVE(_t) \
{\
	char const *_col_name;\
	size_t _col_name_len;\
	if (cass_result_column_name(conn->result, i, &_col_name, &_col_name_len) != CASS_OK) {\
		_col_name = "<INVALID>";\
	}\
	ERROR("rlm_sql_cassandra: failed to retrive "_t " data at column (%d)%s", i, _col_name);\
	TALLOC_FREE(handle->row);\
	return RLM_SQL_ERROR;\
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

	if (!conn->result) return RLM_SQL_OK;				/* no result */

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
		CassValue const *value;
		CassValueType type;

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

			row[i] = NULL;

			if (cass_result_column_name(conn->result, i, &col_name,
						    &col_name_len) != CASS_OK) col_name = "<INVALID>";

			WARN("rlm_sql_cassandra: column %s (%d): Unsupported type %d", col_name, i, (int)type);
			break;
		}
		}
	}
	*out = NULL;

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

static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_cassandra_conn_t *conn = handle->conn;
	size_t i, idx;

	/*
	 *	Move the log entries out of our circular buffer
	 */
	for (i = 0, idx = conn->log_idx;
	     (i < (sizeof(conn->log_entry) / sizeof(*conn->log_entry))) && (i < outlen);
	     i++) {
		sql_log_entry_t	*entry;

		entry = &conn->log_entry[i % (sizeof(conn->log_entry) / sizeof(*conn->log_entry))];
		if (entry->msg == NULL) break;

		out[i].type = entry->type;
		out[i].msg = talloc_steal(ctx, entry->msg);
	}

	/*
	 *	Clear our local log buffer, and free any messages which weren't
	 *	reparented (so we don't leak memory).
	 */
	talloc_free_children(conn->log_ctx);
	memset(conn->log_entry, 0, sizeof(conn->log_entry));

	return i;
}

static sql_rcode_t sql_finish_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_cassandra_conn_t *conn = handle->conn;

	/*
	 *	Clear our local log buffer, and free any messages which weren't
	 *	reparented (so we don't leak memory).
	 */
	talloc_free_children(conn->log_ctx);
	memset(conn->log_entry, 0, sizeof(conn->log_entry));

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
