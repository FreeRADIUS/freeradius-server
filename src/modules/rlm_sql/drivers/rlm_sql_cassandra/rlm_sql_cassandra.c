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
 * @author Linnaea Von Lavia (le.concorde.4590@gmail.com)
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
#define LOG_PREFIX "rlm_sql_cassandra - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>

#include <cassandra.h>

#include "rlm_sql.h"

/** Cassandra cluster connection
 *
 */
typedef struct {
	CassResult const	*result;			//!< Result from executing a query.
	CassIterator		*iterator;			//!< Row set iterator.

	TALLOC_CTX		*log_ctx;			//!< Prevent unneeded memory allocation by keeping a
								//!< permanent pool, to store log entries.
	sql_log_entry_t		last_error;
} rlm_sql_cassandra_conn_t;

/** Cassandra driver instance
 *
 */
typedef struct {
	CassCluster		*cluster;			//!< Configuration of the cassandra cluster connection.
	CassSession		*session;			//!< Cluster's connection pool.
	CassSsl			*ssl;				//!< Connection's SSL context.
	bool			done_connect_keyspace;		//!< Whether we've connected to a keyspace.

	pthread_mutex_t		connect_mutex;			//!< Mutex to prevent multiple connections attempting
								//!< to connect a keyspace concurrently.

	/*
	 *	Configuration options
	 */
	char const		*consistency_str;		//!< Level of consistency required.
	CassConsistency		consistency;			//!< Level of consistency converted to a constant.

	uint32_t		protocol_version;		//!< The protocol version.

	uint32_t		connections_per_host;		//!< Number of connections to each server in each
								//!< IO thread.
	uint32_t		connections_per_host_max;	//!< Maximum  number of connections to each server
								//!< in each IO threads.
	uint32_t		io_threads;			//!< Number of IO threads.

	uint32_t		io_queue_size;			//!< Size of the the fixed size queue that stores
								//!< pending requests.

	uint32_t		io_flush_requests_max;		//!< Maximum number of requests processed by an
								//!< IO worker per flush.

	uint32_t		pending_requests_high;		//!< Sets the high water mark for the number of requests
								//!< queued waiting for a connection in a connection
								//!< pool. Disables writes to a host on an IO worker
								//!< if the number of requests queued exceed this value.

	uint32_t		pending_requests_low;		//!< Sets the low water mark for the number of requests
								//!< queued waiting for a connection in a connection
								//!< pool. After exceeding high water mark requests,
								//!< writes to a host will only resume once the number
								//!< of requests fall below this value.

	uint32_t		write_bytes_high;		//!< High water mark for the number of bytes
								//!< outstanding on a connection. Disables writes to
								//!< a connection if the number of bytes queued exceed
								//!< this value.

	uint32_t		write_bytes_low;		//!< Low water mark for number of bytes outstanding on
								//!< a connection. After exceeding high water mark
								//!< bytes, writes will only resume once the number of
								//!< bytes fall below this value.

	uint32_t		event_queue_size;		//!< Sets the size of the the fixed size queue
								//!< that stores events.

	uint32_t		spawn_threshold;		//!< Threshold for the maximum number of concurrent
								//!< requests in-flight on a connection before creating
								//!< a new connection.
	uint32_t		spawn_max;			//!< The maximum number of connections that
								//!< will be created concurrently.

	fr_time_delta_t		spawn_retry_delay;		//!< Amount of time to wait before attempting
								//!< to reconnect.
	bool			spawn_retry_delay_is_set;

	bool			load_balance_round_robin;	//!< Enable round robin load balancing.

	bool			token_aware_routing;		//!< Whether to use token aware routing.

	char const		*lbdc_local_dc;			//!< The primary data center to try first.
	uint32_t		lbdc_hosts_per_remote_dc;	//!< The number of host used in each remote DC if
								//!< no hosts are available in the local dc

	bool			lbdc_allow_remote_dcs_for_local_cl;	//!< Allows remote hosts to be used if no local
								//!< dc hosts are available and the consistency level
								//!< is LOCAL_ONE or LOCAL_QUORUM.

	fr_time_delta_t		lar_exclusion_threshold;	//!< How much worse the latency me be, compared to
								//!< the average latency of the best performing node
								//!< before it's penalized.
								//!< This gets mangled to a double.

	fr_time_delta_t		lar_scale;			//!< Weight given to older latencies when calculating
								//!< the average latency of a node. A bigger scale will
								//!< give more weight to older latency measurements.

	fr_time_delta_t		lar_retry_period;		//!< The amount of time a node is penalized by the
								//!< policy before being given a second chance when
								//!< the current average latency exceeds the calculated
								//!< threshold
								//!< (exclusion_threshold * best_average_latency).

	fr_time_delta_t		lar_update_rate;		//!< The rate at which the best average latency is
								//!< recomputed.
	uint64_t		lar_min_measured;		//!< The minimum number of measurements per-host
								//!< required to be considered by the policy.

	uint32_t		tcp_keepalive;			//!< How often to send TCP keepalives.
	bool			tcp_nodelay;			//!< Disable TCP naggle algorithm.

	char const 		*tls_ca_file;			//!< Path to the CA used to validate the server's
								//!< certificate.
	char const 		*tls_certificate_file;		//!< Public certificate we present to the server.
	char const 		*tls_private_key_file;		//!< Private key for the certificate we present to the
								//!< server.
	char const		*tls_private_key_password;	//!< String to decrypt private key.
	char const 		*tls_verify_cert_str;		//!< Whether we validate the cert provided by the
								//!< server.
} rlm_sql_cassandra_t;

static fr_table_num_sorted_t const consistency_levels[] = {
	{ "all",		CASS_CONSISTENCY_ALL		},
	{ "any",		CASS_CONSISTENCY_ANY		},
	{ "each_quorum",	CASS_CONSISTENCY_EACH_QUORUM	},
	{ "local_one",		CASS_CONSISTENCY_LOCAL_ONE	},
	{ "local_quorum",	CASS_CONSISTENCY_LOCAL_QUORUM	},
	{ "one",		CASS_CONSISTENCY_ONE		},
	{ "quorum",		CASS_CONSISTENCY_QUORUM		},
	{ "three",		CASS_CONSISTENCY_THREE		},
	{ "two",		CASS_CONSISTENCY_TWO		}
};
static size_t consistency_levels_len = NUM_ELEMENTS(consistency_levels);

static fr_table_num_sorted_t const verify_cert_table[] = {
	{ "identity",		CASS_SSL_VERIFY_PEER_IDENTITY	},
	{ "no",			CASS_SSL_VERIFY_NONE		},
	{ "yes",		CASS_SSL_VERIFY_PEER_CERT	}
};
static size_t verify_cert_table_len = NUM_ELEMENTS(verify_cert_table);

static CONF_PARSER load_balance_dc_aware_config[] = {
	{ FR_CONF_OFFSET("local_dc", FR_TYPE_STRING, rlm_sql_cassandra_t, lbdc_local_dc) },
	{ FR_CONF_OFFSET("hosts_per_remote_dc", FR_TYPE_UINT32, rlm_sql_cassandra_t, lbdc_hosts_per_remote_dc), .dflt = "0" },
	{ FR_CONF_OFFSET("allow_remote_dcs_for_local_cl", FR_TYPE_BOOL, rlm_sql_cassandra_t, lbdc_allow_remote_dcs_for_local_cl), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER latency_aware_routing_config[] = {
	{ FR_CONF_OFFSET("exclusion_threshold", FR_TYPE_FLOAT64, rlm_sql_cassandra_t, lar_exclusion_threshold), .dflt = "2.0" },
	{ FR_CONF_OFFSET("scale", FR_TYPE_TIME_DELTA, rlm_sql_cassandra_t, lar_scale), .dflt = "0.1" },
	{ FR_CONF_OFFSET("retry_period", FR_TYPE_TIME_DELTA, rlm_sql_cassandra_t, lar_retry_period), .dflt = "10" },
	{ FR_CONF_OFFSET("update_rate", FR_TYPE_TIME_DELTA, rlm_sql_cassandra_t, lar_update_rate), .dflt = "0.1" },
	{ FR_CONF_OFFSET("min_measured", FR_TYPE_UINT64, rlm_sql_cassandra_t, lar_min_measured), .dflt = "50" },
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER tls_config[] = {
	{ FR_CONF_OFFSET("ca_file", FR_TYPE_FILE_INPUT, rlm_sql_cassandra_t, tls_ca_file) },
	{ FR_CONF_OFFSET("certificate_file", FR_TYPE_FILE_INPUT, rlm_sql_cassandra_t, tls_certificate_file) },
	{ FR_CONF_OFFSET("private_key_file", FR_TYPE_FILE_INPUT, rlm_sql_cassandra_t, tls_private_key_file) },
	{ FR_CONF_OFFSET("private_key_password", FR_TYPE_STRING | FR_TYPE_SECRET, rlm_sql_cassandra_t, tls_private_key_password) },

	{ FR_CONF_OFFSET("verify_cert", FR_TYPE_STRING, rlm_sql_cassandra_t, tls_verify_cert_str) },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER driver_config[] = {
	{ FR_CONF_OFFSET("consistency", FR_TYPE_STRING, rlm_sql_cassandra_t, consistency_str), .dflt = "quorum" },

	{ FR_CONF_OFFSET("protocol_version", FR_TYPE_UINT32, rlm_sql_cassandra_t, protocol_version) },

	{ FR_CONF_OFFSET("connections_per_host", FR_TYPE_UINT32, rlm_sql_cassandra_t, connections_per_host) },

/*
 * The below functions was deprecated in 2.10
 */
#if (CASS_VERSION_MAJOR >= 2 && CASS_VERSION_MINOR >= 10)
	{ FR_CONF_DEPRECATED("connections_per_host_max", FR_TYPE_UINT32, rlm_sql_cassandra_t, connections_per_host_max) },
	{ FR_CONF_DEPRECATED("io_flush_requests_max", FR_TYPE_UINT32, rlm_sql_cassandra_t, io_flush_requests_max) },

	{ FR_CONF_DEPRECATED("pending_requests_high", FR_TYPE_UINT32, rlm_sql_cassandra_t, pending_requests_high) },
	{ FR_CONF_DEPRECATED("pending_requests_low", FR_TYPE_UINT32, rlm_sql_cassandra_t, pending_requests_low) },

	{ FR_CONF_DEPRECATED("write_bytes_high", FR_TYPE_UINT32, rlm_sql_cassandra_t, write_bytes_high) },
	{ FR_CONF_DEPRECATED("write_bytes_low", FR_TYPE_UINT32, rlm_sql_cassandra_t, write_bytes_low) },

	{ FR_CONF_DEPRECATED("spawn_threshold", FR_TYPE_UINT32, rlm_sql_cassandra_t, spawn_threshold) },
	{ FR_CONF_DEPRECATED("spawn_max", FR_TYPE_UINT32, rlm_sql_cassandra_t, spawn_max) },
	{ FR_CONF_OFFSET_IS_SET("spawn_retry_delay", FR_TYPE_TIME_DELTA | FR_TYPE_DEPRECATED, rlm_sql_cassandra_t, spawn_retry_delay) },
#else
	{ FR_CONF_OFFSET("connections_per_host_max", FR_TYPE_UINT32, rlm_sql_cassandra_t, connections_per_host_max) },
	{ FR_CONF_OFFSET("io_flush_requests_max", FR_TYPE_UINT32, rlm_sql_cassandra_t, io_flush_requests_max) },

	{ FR_CONF_OFFSET("pending_requests_high", FR_TYPE_UINT32, rlm_sql_cassandra_t, pending_requests_high) },
	{ FR_CONF_OFFSET("pending_requests_low", FR_TYPE_UINT32, rlm_sql_cassandra_t, pending_requests_low) },

	{ FR_CONF_OFFSET("write_bytes_high", FR_TYPE_UINT32, rlm_sql_cassandra_t, write_bytes_high) },
	{ FR_CONF_OFFSET("write_bytes_low", FR_TYPE_UINT32, rlm_sql_cassandra_t, write_bytes_low) },

	{ FR_CONF_OFFSET("spawn_threshold", FR_TYPE_UINT32, rlm_sql_cassandra_t, spawn_threshold) },
	{ FR_CONF_OFFSET("spawn_max", FR_TYPE_UINT32, rlm_sql_cassandra_t, spawn_max) },
	{ FR_CONF_OFFSET_IS_SET("spawn_retry_delay", FR_TYPE_TIME_DELTA, rlm_sql_cassandra_t, spawn_retry_delay) },
#endif

	{ FR_CONF_OFFSET("io_threads", FR_TYPE_UINT32, rlm_sql_cassandra_t, io_threads) },
	{ FR_CONF_OFFSET("io_queue_size", FR_TYPE_UINT32, rlm_sql_cassandra_t, io_queue_size) },

	{ FR_CONF_OFFSET("event_queue_size", FR_TYPE_UINT32, rlm_sql_cassandra_t, event_queue_size) },

	{ FR_CONF_POINTER("load_balance_dc_aware", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) load_balance_dc_aware_config },
	{ FR_CONF_OFFSET("load_balance_round_robin", FR_TYPE_BOOL, rlm_sql_cassandra_t, load_balance_round_robin), .dflt = "no" },

	{ FR_CONF_OFFSET("token_aware_routing", FR_TYPE_BOOL, rlm_sql_cassandra_t, token_aware_routing), .dflt = "yes" },
	{ FR_CONF_POINTER("latency_aware_routing", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) latency_aware_routing_config },

	{ FR_CONF_OFFSET("tcp_keepalive", FR_TYPE_UINT32, rlm_sql_cassandra_t, tcp_keepalive) },
	{ FR_CONF_OFFSET("tcp_nodelay", FR_TYPE_BOOL, rlm_sql_cassandra_t, tcp_nodelay), .dflt = "no" },

	{ FR_CONF_POINTER("tls", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) tls_config },
	CONF_PARSER_TERMINATOR
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
			ERROR("%s[%d] %s: %s",
			       message->file, message->line, message->function, message->message);
		} else {
			ERROR("%s", message->message);
		}
		return;

	case CASS_LOG_WARN:
		if (DEBUG_ENABLED3) {
			WARN("%s[%d] %s: %s",
			     message->file, message->line, message->function, message->message);
		} else {
			WARN("%s", message->message);
		}
		return;

	case CASS_LOG_INFO:
	case CASS_LOG_DISABLED:
	case CASS_LOG_LAST_ENTRY:
		if (DEBUG_ENABLED3) {
			INFO("%s[%d] %s: %s",
			     message->file, message->line, message->function, message->message);
		} else {
			INFO("%s", message->message);
		}
		return;

	case CASS_LOG_DEBUG:
	case CASS_LOG_TRACE:
	default:
		if (DEBUG_ENABLED3) {
			DEBUG3("%s[%d] %s: %s",
			       message->file, message->line, message->function, message->message);
		} else {
			DEBUG2("%s", message->message);
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

	conn->last_error.msg = fr_asprint(conn->log_ctx, message, len, '\0');
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

static int _sql_socket_destructor(rlm_sql_cassandra_conn_t *conn)
{
	DEBUG2("Socket destructor called, closing socket");

	if (conn->iterator) cass_iterator_free(conn->iterator);
	if (conn->result) cass_result_free(conn->result);

	return 0;
}

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config, fr_time_delta_t timeout)
{
	rlm_sql_cassandra_conn_t	*conn;
	rlm_sql_cassandra_t		*inst = config->driver;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_cassandra_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	/*
	 *	We do this one inside sql_socket_init, to allow pool.start = 0 to
	 *	work as expected (allow the server to start if Cassandra is
	 *	unavailable).
	 */
	if (!inst->done_connect_keyspace) {
		CassFuture	*future;
		CassError	ret;

		pthread_mutex_lock(&inst->connect_mutex);
		if (!inst->done_connect_keyspace) {
			/*
			 *	Easier to do this here instead of mod_instantiate
			 *	as we don't have a pointer to the pool.
			 */
			cass_cluster_set_connect_timeout(inst->cluster, fr_time_delta_to_msec(timeout));

			DEBUG2("Connecting to Cassandra cluster");
			future = cass_session_connect_keyspace(inst->session, inst->cluster, config->sql_db);
			ret = cass_future_error_code(future);
			if (ret != CASS_OK) {
				const char	*msg;
				size_t		msg_len;

				cass_future_error_message(future, &msg, &msg_len);
				ERROR("Unable to connect: [%x] %s", (int)ret, msg);
				cass_future_free(future);
				pthread_mutex_unlock(&inst->connect_mutex);

				return RLM_SQL_ERROR;
			}
			cass_future_free(future);
			inst->done_connect_keyspace = true;
		}
		pthread_mutex_unlock(&inst->connect_mutex);
	}
	conn->log_ctx = talloc_pool(conn, 1024);	/* Pre-allocate some memory for log messages */

	return RLM_SQL_OK;
}

static sql_rcode_t sql_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char const *query)
{
	rlm_sql_cassandra_conn_t	*conn = handle->conn;
	rlm_sql_cassandra_t	*conf = config->driver;
	CassStatement			*statement;
	CassFuture			*future;
	CassError			ret;

	statement = cass_statement_new_n(query, talloc_array_length(query) - 1, 0);
	if (conf->consistency_str) cass_statement_set_consistency(statement, conf->consistency);

	future = cass_session_execute(conf->session, statement);
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
		if (cass_result_column_name(conn->result, i, &col_name, &col_name_len) != CASS_OK) {
			col_name = "<INVALID>";
		}
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

	if (!cass_iterator_next(conn->iterator)) return RLM_SQL_NO_MORE_ROWS;	/* no more rows */

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

			MEM(row[i] = talloc_typed_asprintf(row, "%"PRId32, (int32_t)i32v));
		}
			break;

		case CASS_VALUE_TYPE_TIMESTAMP:
		case CASS_VALUE_TYPE_BIGINT:
		{
			cass_int64_t i64v;

			if (cass_value_get_int64(value, &i64v) != CASS_OK) RLM_CASS_ERR_DATA_RETRIVE("int64");

			MEM(row[i] = talloc_typed_asprintf(row, "%"PRId64, (int64_t)i64v));
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
	 *	reconfiged (so we don't leak memory).
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

static int mod_detach(void *instance)
{
	rlm_sql_cassandra_t *inst = instance;

	if (inst->ssl) cass_ssl_free(inst->ssl);
	if (inst->session) cass_session_free(inst->session);	/* also synchronously closes the session */
	if (inst->cluster) cass_cluster_free(inst->cluster);

	pthread_mutex_destroy(&inst->connect_mutex);

	return 0;
}

static int mod_instantiate(rlm_sql_config_t const *config, void *instance, CONF_SECTION *cs)
{
	bool				do_tls = false;
	bool				do_latency_aware_routing = false;
	rlm_sql_cassandra_t		*inst = instance;

	CassCluster *cluster;

#define DO_CASS_OPTION(_opt, _x) \
do {\
	CassError _ret;\
	if ((_ret = (_x)) != CASS_OK) {\
		ERROR("Error setting " _opt ": %s", cass_error_desc(_ret));\
		return RLM_SQL_ERROR;\
	}\
} while (0)

	if (pthread_mutex_init(&inst->connect_mutex, NULL) < 0) {
		ERROR("Failed initializing mutex: %s", fr_syserror(errno));
		TALLOC_FREE(inst);
		return -1;
	}

	/*
	 *	This has to be done before we call cf_section_parse
	 *	as it sets default values, and creates the section.
	 */
	if (cf_section_find(cs, "tls", NULL)) do_tls = true;
	if (cf_section_find(cs, "latency_aware_routing", NULL)) do_latency_aware_routing = true;

	DEBUG4("Configuring CassCluster structure");
	cluster = inst->cluster = cass_cluster_new();
	if (!cluster) return RLM_SQL_ERROR;

	/*
	 *	Parameters inherited from the top level SQL module config
	 */
	DO_CASS_OPTION("sql_server", cass_cluster_set_contact_points(cluster, config->sql_server));
	if (config->sql_port) DO_CASS_OPTION("sql_port", cass_cluster_set_port(cluster, config->sql_port));
	/* Can't fail */
	if (config->query_timeout) cass_cluster_set_request_timeout(cluster, config->query_timeout * 1000);
	/* Can't fail */
	if (config->sql_login && config->sql_password) cass_cluster_set_credentials(cluster, config->sql_login,
										    config->sql_password);

	/*
	 *	inst specific parameters
	 */
	if (inst->consistency_str) {
		int consistency;

		consistency = fr_table_value_by_str(consistency_levels, inst->consistency_str, -1);
		if (consistency < 0) {
			ERROR("Invalid consistency level \"%s\"", inst->consistency_str);
			return -1;
		}
		inst->consistency = (CassConsistency)consistency;
	}

	if (inst->protocol_version) {
		DO_CASS_OPTION("protocol_version",
			       cass_cluster_set_protocol_version(inst->cluster, inst->protocol_version));
	}

	if (inst->connections_per_host) {
		DO_CASS_OPTION("connections_per_host",
			       cass_cluster_set_core_connections_per_host(inst->cluster,
			       						  inst->connections_per_host));
	}

	/*
	 *	The below functions was deprecated in 2.10
	 */
#if (CASS_VERSION_MAJOR <= 2 && CASS_VERSION_MINOR < 10)
	if (inst->connections_per_host_max) {
		DO_CASS_OPTION("connections_per_host_max",
				cass_cluster_set_max_connections_per_host(inst->cluster,
									  inst->connections_per_host_max));
	}

	if (inst->io_flush_requests_max) {
		DO_CASS_OPTION("io_flush_requests_max",
			       cass_cluster_set_max_requests_per_flush(inst->cluster,
			       					       inst->io_flush_requests_max));
	}

	if (inst->pending_requests_high) {
		DO_CASS_OPTION("pending_requests_high",
			       cass_cluster_set_pending_requests_high_water_mark(inst->cluster,
			       							 inst->pending_requests_high));
	}

	if (inst->pending_requests_low) {
		DO_CASS_OPTION("pending_requests_low",
			       cass_cluster_set_pending_requests_high_water_mark(inst->cluster,
			       							 inst->pending_requests_low));
	}

	if (inst->write_bytes_high) {
		DO_CASS_OPTION("write_bytes_high",
			       cass_cluster_set_write_bytes_high_water_mark(inst->cluster,
			       						    inst->write_bytes_high));
	}

	if (inst->write_bytes_low) {
		DO_CASS_OPTION("write_bytes_low",
			       cass_cluster_set_write_bytes_low_water_mark(inst->cluster,
			       						   inst->write_bytes_low));
	}

	if (inst->spawn_threshold) {
		DO_CASS_OPTION("spawn_threshold",
			       cass_cluster_set_max_concurrent_requests_threshold(inst->cluster,
			       							  inst->spawn_threshold));
	}

	if (inst->spawn_max) {
		DO_CASS_OPTION("spawn_max",
			       cass_cluster_set_max_concurrent_creation(inst->cluster, inst->spawn_max));
	}

	if (inst->spawn_retry_delay_is_set) {
		cass_cluster_set_reconnect_wait_time(inst->cluster, fr_time_delta_to_msec(inst->spawn_retry_delay));
	}
#endif

	if (inst->event_queue_size) {
		DO_CASS_OPTION("event_queue_size",
			       cass_cluster_set_num_threads_io(inst->cluster, inst->event_queue_size));
	}

	if (inst->io_queue_size) {
		DO_CASS_OPTION("io_queue_size",
			       cass_cluster_set_num_threads_io(inst->cluster, inst->io_queue_size));
	}

	if (inst->io_threads) {
		DO_CASS_OPTION("io_threads", cass_cluster_set_num_threads_io(inst->cluster, inst->io_threads));
	}

	if (inst->load_balance_round_robin) cass_cluster_set_load_balance_round_robin(inst->cluster);

	cass_cluster_set_token_aware_routing(inst->cluster, inst->token_aware_routing);

	if (inst->lbdc_local_dc) {
		DO_CASS_OPTION("load_balance_dc_aware",
			       cass_cluster_set_load_balance_dc_aware(inst->cluster,
			       					      inst->lbdc_local_dc,
			       					      inst->lbdc_hosts_per_remote_dc,
			       					      inst->lbdc_allow_remote_dcs_for_local_cl));
	}

	if (do_latency_aware_routing) {
		/* Can't fail */
		cass_cluster_set_latency_aware_routing(inst->cluster, true);

		/* Can't fail */
		cass_cluster_set_latency_aware_routing_settings(inst->cluster,
							        (cass_double_t)inst->lar_exclusion_threshold,
							        fr_time_delta_to_msec(inst->lar_scale),
							        fr_time_delta_to_msec(inst->lar_retry_period),
							        fr_time_delta_to_msec(inst->lar_update_rate),
							        inst->lar_min_measured);
	}

	if (inst->tcp_keepalive) cass_cluster_set_tcp_keepalive(inst->cluster, true, inst->tcp_keepalive);
	cass_cluster_set_tcp_nodelay(inst->cluster, inst->tcp_nodelay);

	if (do_tls) {
		CassSsl	*ssl;

		ssl = inst->ssl = cass_ssl_new();
		if (!ssl) return RLM_SQL_ERROR;

		if (inst->tls_verify_cert_str) {
			int	verify_cert;

			verify_cert = fr_table_value_by_str(verify_cert_table, inst->tls_verify_cert_str, -1);
			if (verify_cert < 0) {
				ERROR("Invalid certificate validation type \"%s\", "
				      "must be one of 'yes', 'no', 'identity'", inst->tls_verify_cert_str);
				return -1;
			}
			cass_ssl_set_verify_flags(ssl, verify_cert);
		}

		DEBUG2("Enabling TLS");

		if (inst->tls_ca_file) {
			DO_CASS_OPTION("ca_file", cass_ssl_add_trusted_cert(ssl, inst->tls_ca_file));
		}

		if (inst->tls_certificate_file) {
			DO_CASS_OPTION("certificate_file", cass_ssl_set_cert(ssl, inst->tls_certificate_file));
		}

		if (inst->tls_private_key_file) {
			DO_CASS_OPTION("private_key", cass_ssl_set_private_key(ssl, inst->tls_private_key_file,
				       					       inst->tls_private_key_password));
		}

		cass_cluster_set_ssl(cluster, ssl);
	}

	inst->session = cass_session_new();
	if (!inst->session) return RLM_SQL_ERROR;

	return 0;
}

static void mod_unload(void)
{
	/*
	 *	The function cass_log_cleanup() was deprecated in 2.0.1
	 */
#if (CASS_VERSION_MAJOR <= 2 && CASS_VERSION_MINOR <= 0)
	cass_log_cleanup();	/* must be last call to libcassandra */
#endif
}

static int mod_load(void)
{
	INFO("Built against libcassandra version %d.%d.%d%s",
	     CASS_VERSION_MAJOR, CASS_VERSION_MINOR, CASS_VERSION_PATCH, CASS_VERSION_SUFFIX);

	/*
	 *	Setup logging callbacks (only needs to be done once)
	 */
	cass_log_set_level(CASS_LOG_INFO);
	cass_log_set_callback(_rlm_sql_cassandra_log, NULL);

	return 0;
}

/* Exported to rlm_sql */
extern rlm_sql_driver_t rlm_sql_cassandra;
rlm_sql_driver_t rlm_sql_cassandra = {
	.name				= "rlm_sql_cassandra",
	.magic				= RLM_MODULE_INIT,
	.inst_size			= sizeof(rlm_sql_cassandra_t),
	.onload				= mod_load,
	.unload				= mod_unload,
	.config				= driver_config,
	.mod_instantiate		= mod_instantiate,
	.detach				= mod_detach,
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
