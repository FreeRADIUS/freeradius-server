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
	CassResult const	*result;			//!< Result from executing a query.
	CassIterator		*iterator;			//!< Row set iterator.

	TALLOC_CTX		*log_ctx;			//!< Prevent unneeded memory allocation by keeping a
								//!< permanent pool, to store log entries.
	sql_log_entry_t		last_error;
} rlm_sql_cassandra_conn_t;

/** Cassandra driver instance
 *
 */
typedef struct rlm_sql_cassandra_config {
	CassCluster		*cluster;			//!< Configuration of the cassandra cluster connection.
	CassSession		*session;			//!< Cluster's connection pool.
	CassSsl			*ssl;				//!< Connection's SSL context.
	bool			done_connect_keyspace;		//!< Whether we've connected to a keyspace.

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		connect_mutex;			//!< Mutex to prevent multiple connections attempting
								//!< to connect a keyspace concurrently.
#endif

	/*
	 *	Configuration options
	 */
	char const		*consistency_str;		//!< Level of consistency required.
	CassConsistency		consistency;			//!< Level of consistency converted to a constant.

	uint32_t		connections_per_host;		//!< Number of connections to each server in each
								//!< IO thread.
	uint32_t		connections_per_host_max;	//!< Maximum  number of connections to each server
								//!< in each IO threads.
	uint32_t		io_threads;			//!< Number of IO threads.

	uint32_t		spawn_threshold;		//!< Threshold for the maximum number of concurrent
								//!< requests in-flight on a connection before creating
								//!< a new connection.
	uint32_t		spawn_max;			//!< The maximum number of connections that
								//!< will be created concurrently.

	bool			load_balance_round_robin;	//!< Enable round robin load balancing.

	bool			token_aware_routing;		//!< Whether to use token aware routing.

	char const		*lbdc_local_dc;			//!< The primary data center to try first.
	uint32_t		lbdc_hosts_per_remote_dc;	//!< The number of host used in each remote DC if
								//!< no hosts are available in the local dc

	bool			lbdc_allow_remote_dcs_for_local_cl;	//!< Allows remote hosts to be used if no local
								//!< dc hosts are available and the consistency level
								//!< is LOCAL_ONE or LOCAL_QUORUM.

	struct timeval		lar_exclusion_threshold;	//!< How much worse the latency me be, compared to
								//!< the average latency of the best performing node
								//!< before it's penalized.
								//!< This gets mangled to a double.

	struct timeval		lar_scale;			//!< Weight given to older latencies when calculating
								//!< the average latency of a node. A bigger scale will
								//!< give more weight to older latency measurements.

	struct timeval		lar_retry_period;		//!< The amount of time a node is penalized by the
								//!< policy before being given a second chance when
								//!< the current average latency exceeds the calculated
								//!< threshold
								//!< (exclusion_threshold * best_average_latency).

	struct timeval		lar_update_rate;		//!< The rate at which the best average latency is
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
} rlm_sql_cassandra_config_t;

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

static const FR_NAME_NUMBER verify_cert_table[] = {
	{ "no",			CASS_SSL_VERIFY_NONE },
	{ "yes",		CASS_SSL_VERIFY_PEER_CERT },
	{ "identity",		CASS_SSL_VERIFY_PEER_IDENTITY },
	{ NULL, 0 }
};

static CONF_PARSER load_balance_dc_aware_config[] = {
	{ "local_dc", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_sql_cassandra_config_t, lbdc_local_dc), NULL },
	{ "hosts_per_remote_dc" , FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_sql_cassandra_config_t, lbdc_hosts_per_remote_dc), NULL },
	{ "allow_remote_dcs_for_local_cl", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_sql_cassandra_config_t, lbdc_allow_remote_dcs_for_local_cl), NULL}
};

static CONF_PARSER latency_aware_routing_config[] = {
	{ "exclusion_threshold", FR_CONF_OFFSET(PW_TYPE_TIMEVAL, rlm_sql_cassandra_config_t, lar_exclusion_threshold), NULL },
	{ "scale", FR_CONF_OFFSET(PW_TYPE_TIMEVAL, rlm_sql_cassandra_config_t, lar_scale), NULL },
	{ "retry_period", FR_CONF_OFFSET(PW_TYPE_TIMEVAL, rlm_sql_cassandra_config_t, lar_retry_period), NULL },
	{ "update_rate", FR_CONF_OFFSET(PW_TYPE_TIMEVAL, rlm_sql_cassandra_config_t, lar_update_rate), NULL },
	{ "min_measured", FR_CONF_OFFSET(PW_TYPE_INTEGER64, rlm_sql_cassandra_config_t, lar_min_measured), NULL }
};

static CONF_PARSER tls_config[] = {
	{ "ca_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_sql_cassandra_config_t, tls_ca_file), NULL },
	{ "certificate_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_sql_cassandra_config_t, tls_certificate_file), NULL },
	{ "private_key_file", FR_CONF_OFFSET(PW_TYPE_FILE_INPUT, rlm_sql_cassandra_config_t, tls_private_key_file), NULL },
	{ "private_key_password", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, rlm_sql_cassandra_config_t, tls_private_key_password), NULL },

	{ "verify_cert", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_sql_cassandra_config_t, tls_verify_cert_str), NULL },

	{ NULL, -1, 0, NULL, NULL }
};

static const CONF_PARSER driver_config[] = {
	{ "consistency", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_sql_cassandra_config_t, consistency_str), "quorum" },

	{ "connections_per_host", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_sql_cassandra_config_t, connections_per_host), NULL },
	{ "connections_per_host_max", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_sql_cassandra_config_t, connections_per_host_max), NULL },

	{ "io_threads", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_sql_cassandra_config_t, io_threads), NULL },

	{ "spawn_threshold", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_sql_cassandra_config_t, spawn_threshold), NULL },
	{ "spawn_max", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_sql_cassandra_config_t, spawn_max), NULL },

	{ "load_balance_dc_aware", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) load_balance_dc_aware_config },
	{ "load_balance_round_robin", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_sql_cassandra_config_t, load_balance_round_robin), "no" },

	{ "token_aware_routing", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_sql_cassandra_config_t, token_aware_routing), "yes" },
	{ "latency_aware_routing", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) latency_aware_routing_config },

	{ "tcp_keepalive", FR_CONF_OFFSET(PW_TYPE_INTEGER, rlm_sql_cassandra_config_t, tcp_keepalive), NULL },
	{ "tcp_nodelay", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rlm_sql_cassandra_config_t, tcp_nodelay), "no" },

	{ "tls", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) tls_config },

	{ NULL, -1, 0, NULL, NULL}
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

static int _mod_destructor(rlm_sql_cassandra_config_t *config)
{
	if (config->ssl) cass_ssl_free(config->ssl);
	if (config->session) cass_session_free(config->session);	/* also synchronously closes the session */
	if (config->cluster) cass_cluster_free(config->cluster);

#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy(&config->connect_mutex);
#endif
	if (--rlm_sql_cass_instances == 0) cass_log_cleanup();	/* must be last call to libcassandra */

	return 0;
}

static int mod_instantiate(CONF_SECTION *conf, rlm_sql_config_t *config)
{
	static bool version_done = false;
	bool do_tls = false;
	bool do_latency_aware_routing = false;

	CassCluster *cluster;

	rlm_sql_cassandra_config_t *driver;

#define DO_CASS_OPTION(_opt, _x) \
do {\
	CassError _ret;\
	if ((_ret = (_x)) != CASS_OK) {\
		ERROR("rlm_sql_cassandra: Error setting " _opt ": %s", cass_error_desc(_ret));\
		return RLM_SQL_ERROR;\
	}\
} while (0)

	if (!version_done) {
		version_done = true;

		INFO("rlm_sql_cassandra: Built against libcassandra version %d.%d.%d%s",
		     CASS_VERSION_MAJOR, CASS_VERSION_MINOR, CASS_VERSION_PATCH, CASS_VERSION_SUFFIX);

		/*
		 *	Setup logging callbacks (only needs to be done once)
		 */
		cass_log_set_level(CASS_LOG_INFO);
		cass_log_set_callback(_rlm_sql_cassandra_log, NULL);
	}

	MEM(driver = config->driver = talloc_zero(config, rlm_sql_cassandra_config_t));
#ifdef HAVE_PTHREAD_H
	if (pthread_mutex_init(&driver->connect_mutex, NULL) < 0) {
		ERROR("Failed initializing mutex: %s", fr_syserror(errno));
		TALLOC_FREE(driver);
		return -1;
	}
#endif
	talloc_set_destructor(driver, _mod_destructor);

	/*
	 *	This has to be done before we call cf_section_parse
	 *	as it sets default values, and creates the section.
	 */
	if (cf_section_sub_find(conf, "tls")) do_tls = true;
	if (cf_section_sub_find(conf, "latency_aware_routing")) do_latency_aware_routing = true;

	if (cf_section_parse(conf, driver, driver_config) < 0) return -1;

	DEBUG4("rlm_sql_cassandra: Configuring driver's CassCluster structure");
	cluster = driver->cluster = cass_cluster_new();
	if (!cluster) return RLM_SQL_ERROR;

	/*
	 *	Parameters inherited from the top level SQL module config
	 */
	DO_CASS_OPTION("sql_server", cass_cluster_set_contact_points(cluster, config->sql_server));
	if (config->sql_port) DO_CASS_OPTION("sql_port", cass_cluster_set_port(cluster, config->sql_port));
	/* Can't fail */
	if (config->connect_timeout_ms) cass_cluster_set_connect_timeout(cluster, config->connect_timeout_ms);
	/* Can't fail */
	if (config->query_timeout) cass_cluster_set_request_timeout(cluster, config->query_timeout * 1000);
	/* Can't fail */
	if (config->sql_login && config->sql_password) cass_cluster_set_credentials(cluster, config->sql_login,
										    config->sql_password);

	/*
	 *	Driver specific parameters
	 */
	if (driver->consistency_str) {
		int consistency;

		consistency = fr_str2int(consistency_levels, driver->consistency_str, -1);
		if (consistency < 0) {
			ERROR("rlm_sql_cassandra: Invalid consistency level \"%s\"", driver->consistency_str);
			return -1;
		}
		driver->consistency = (CassConsistency)consistency;
	}

	if (driver->connections_per_host) {
		DO_CASS_OPTION("connections_per_host",
			       cass_cluster_set_core_connections_per_host(driver->cluster,
			       						  driver->connections_per_host));
	}

	if (driver->connections_per_host_max) {
		DO_CASS_OPTION("connections_per_host_max",
				cass_cluster_set_max_connections_per_host(driver->cluster,
									  driver->connections_per_host_max));
	}

	if (driver->io_threads) {
		DO_CASS_OPTION("io_threads", cass_cluster_set_num_threads_io(driver->cluster, driver->io_threads));
	}

	if (driver->spawn_threshold) {
		DO_CASS_OPTION("spawn_threshold",
			       cass_cluster_set_max_concurrent_requests_threshold(driver->cluster,
			       							  driver->spawn_threshold));
	}

	if (driver->spawn_max) {
		DO_CASS_OPTION("spawn_max",
			       cass_cluster_set_max_concurrent_creation(driver->cluster, driver->spawn_max));
	}

	if (driver->load_balance_round_robin) cass_cluster_set_load_balance_round_robin(driver->cluster);

	cass_cluster_set_token_aware_routing(driver->cluster, driver->token_aware_routing);

	if (driver->lbdc_local_dc) {
		DO_CASS_OPTION("load_balance_dc_aware",
			       cass_cluster_set_load_balance_dc_aware(driver->cluster,
			       					      driver->lbdc_local_dc,
			       					      driver->lbdc_hosts_per_remote_dc,
			       					      driver->lbdc_allow_remote_dcs_for_local_cl));
	}

	if (do_latency_aware_routing) {
		cass_double_t	exclusion_threshold;
		uint64_t	scale_ms, retry_period_ms, update_rate_ms;

		exclusion_threshold = driver->lar_exclusion_threshold.tv_sec +
				      (driver->lar_exclusion_threshold.tv_usec / 1000000);

		scale_ms = (driver->lar_scale.tv_sec * (uint64_t)1000) + (driver->lar_scale.tv_usec / 1000);
		retry_period_ms = (driver->lar_retry_period.tv_sec * (uint64_t)1000) +
				  (driver->lar_retry_period.tv_usec / 1000);
		update_rate_ms = (driver->lar_update_rate.tv_sec * (uint64_t)1000) +
				 (driver->lar_update_rate.tv_usec / 1000);

		/* Can't fail */
		cass_cluster_set_latency_aware_routing(driver->cluster, true);

		/* Can't fail */
		cass_cluster_set_latency_aware_routing_settings(driver->cluster,
							        exclusion_threshold,
							        scale_ms,
							        retry_period_ms,
							        update_rate_ms,
							        driver->lar_min_measured);
	}

	if (driver->tcp_keepalive) cass_cluster_set_tcp_keepalive(driver->cluster, true, driver->tcp_keepalive);
	cass_cluster_set_tcp_nodelay(driver->cluster, driver->tcp_nodelay);

	if (do_tls) {
		CassSsl	*ssl;

		ssl = driver->ssl = cass_ssl_new();
		if (!ssl) return RLM_SQL_ERROR;

		if (driver->tls_verify_cert_str) {
			int	verify_cert;

			verify_cert = fr_str2int(verify_cert_table, driver->tls_verify_cert_str, -1);
			if (verify_cert < 0) {
				ERROR("rlm_sql_cassandra: Invalid certificate validation type \"%s\", "
				      "must be one of 'yes', 'no', 'identity'", driver->tls_verify_cert_str);
				return -1;
			}
			cass_ssl_set_verify_flags(ssl, verify_cert);
		}

		DEBUG2("rlm_sql_cassandra: Enabling SSL");


		if (driver->tls_ca_file) {
			DO_CASS_OPTION("ca_file", cass_ssl_add_trusted_cert(ssl, driver->tls_ca_file));
		}

		if (driver->tls_certificate_file) {
			DO_CASS_OPTION("certificate_file", cass_ssl_set_cert(ssl, driver->tls_certificate_file));
		}

		if (driver->tls_private_key_file) {
			DO_CASS_OPTION("private_key", cass_ssl_set_private_key(ssl, driver->tls_private_key_file,
				       					       driver->tls_private_key_password));
		}

		cass_cluster_set_ssl(cluster, ssl);
	}

	driver->session = cass_session_new();
	if (!driver->session) return RLM_SQL_ERROR;

	rlm_sql_cass_instances++;

	return 0;
}

static int _sql_socket_destructor(rlm_sql_cassandra_conn_t *conn)
{
	DEBUG2("rlm_sql_cassandra: Socket destructor called, closing socket");

	if (conn->iterator) cass_iterator_free(conn->iterator);
	if (conn->result) cass_result_free(conn->result);

	return 0;
}

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_cassandra_conn_t	*conn;
	rlm_sql_cassandra_config_t	*driver = config->driver;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_cassandra_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	/*
	 *	We do this one inside sql_socket_init, to allow pool.start = 0 to
	 *	work as expected (allow the server to start if Cassandra is
	 *	unavailable).
	 */
	if (!driver->done_connect_keyspace) {
		CassFuture	*future;
		CassError	ret;

#ifdef HAVE_PTHREAD_H
		pthread_mutex_lock(&driver->connect_mutex);
#endif
		if (!driver->done_connect_keyspace) {
			DEBUG2("rlm_sql_cassandra: Connecting to Cassandra cluster");
			future = cass_session_connect_keyspace(driver->session, driver->cluster, config->sql_db);
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
			driver->done_connect_keyspace = true;
		}
#ifdef HAVE_PTHREAD_H
		pthread_mutex_unlock(&driver->connect_mutex);
#endif
	}
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
