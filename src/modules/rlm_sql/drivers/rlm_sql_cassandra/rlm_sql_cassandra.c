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
#define LOG_PREFIX "sql - cassandra"

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#ifdef HAVE_WDOCUMENTATION
DIAG_OFF(documentation)
#endif
DIAG_OFF(strict-prototypes)  /* Seen with homebrew cassandra-cpp-driver 2.15.3 */
#include <cassandra.h>
DIAG_ON(strict-prototypes)
#ifdef HAVE_WDOCUMENTATION
DIAG_ON(documentation)
#endif

#include "rlm_sql.h"
#include "rlm_sql_trunk.h"

typedef struct {
	bool			done_connect_keyspace;		//!< Whether we've connected to a keyspace.
	pthread_mutex_t		connect_mutex;			//!< Mutex to prevent multiple connections attempting
								///< to connect to a keyspace concurrently.
} rlm_sql_cassandra_mutable_t;

/** Cassandra driver instance
 *
 */
typedef struct {
	CassCluster		*cluster;			//!< Configuration of the cassandra cluster connection.
	CassSession		*session;			//!< Cluster's connection pool.
	CassSsl			*ssl;				//!< Connection's SSL context.
	rlm_sql_cassandra_mutable_t	*mutable;		//!< Instance data which needs to change post instantiation.

	/*
	 *	Configuration options
	 */
	char const		*consistency_str;		//!< Level of consistency required.
	CassConsistency		consistency;			//!< Level of consistency converted to a constant.

	uint32_t		protocol_version;		//!< The protocol version.

	uint32_t		connections_per_host;		//!< Number of connections to each server in each
								//!< IO thread.
	uint32_t		io_threads;			//!< Number of IO threads.

	uint32_t		io_queue_size;			//!< Size of the the fixed size queue that stores
								//!< pending requests.

	uint32_t		event_queue_size;		//!< Sets the size of the the fixed size queue
								//!< that stores events.

	bool			load_balance_round_robin;	//!< Enable round robin load balancing.

	bool			token_aware_routing;		//!< Whether to use token aware routing.

	char const		*lbdc_local_dc;			//!< The primary data center to try first.
	uint32_t		lbdc_hosts_per_remote_dc;	//!< The number of host used in each remote DC if
								//!< no hosts are available in the local dc

	bool			lbdc_allow_remote_dcs_for_local_cl;	//!< Allows remote hosts to be used if no local
								//!< dc hosts are available and the consistency level
								//!< is LOCAL_ONE or LOCAL_QUORUM.

	double			lar_exclusion_threshold;	//!< How much worse the latency me be, compared to
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

/** Cassandra cluster connection
 *
 */
typedef struct {
	connection_t		*conn;				//!< Generic connection structure for managing this handle.
	rlm_sql_cassandra_t const	*inst;			//!< Module instance for this connection.
	rlm_sql_config_t const	*config;			//!< SQL instance config
	CassIterator		*iterator;			//!< Row set iterator.

	TALLOC_CTX		*log_ctx;			//!< Prevent unneeded memory allocation by keeping a
								//!< permanent pool, to store log entries.
	fr_dlist_head_t		queries;			//!< Outstanding queries on this connection.
	fr_event_timer_t const	*read_ev;			//!< Polling event for reading query results.
	fr_event_timer_t const	*write_ev;			//!< Polling event for sending queries.
	uint			poll_interval;			//!< Interval between read polling.
	uint			poll_count;			//!< How many consecutive polls had no available results.
} rlm_sql_cassandra_conn_t;

/** Structure for tracking outstanding queries
 *
 */
typedef struct {
	fr_dlist_t		entry;				//!< Entry in list of outstanding queries.
	fr_sql_query_t		*query_ctx;			//!< SQL query ctx.
	CassFuture		*future;			//!< Future produced when submitting query.
} cassandra_query_t;

/** Driver specific data to attach to the query ctx
 *
 */
typedef struct {
	CassResult const	*result;			//!< Cassandra result handle
	sql_log_entry_t		error;				//!< Most recent Cassandra error message for this query.
} cassandra_query_ctx_t;

static fr_table_num_sorted_t const consistency_levels[] = {
	{ L("all"),		CASS_CONSISTENCY_ALL		},
	{ L("any"),		CASS_CONSISTENCY_ANY		},
	{ L("each_quorum"),	CASS_CONSISTENCY_EACH_QUORUM	},
	{ L("local_one"),	CASS_CONSISTENCY_LOCAL_ONE	},
	{ L("local_quorum"),	CASS_CONSISTENCY_LOCAL_QUORUM	},
	{ L("one"),		CASS_CONSISTENCY_ONE		},
	{ L("quorum"),		CASS_CONSISTENCY_QUORUM		},
	{ L("three"),		CASS_CONSISTENCY_THREE		},
	{ L("two"),		CASS_CONSISTENCY_TWO		}
};
static size_t consistency_levels_len = NUM_ELEMENTS(consistency_levels);

static fr_table_num_sorted_t const verify_cert_table[] = {
	{ L("identity"),		CASS_SSL_VERIFY_PEER_IDENTITY	},
	{ L("no"),			CASS_SSL_VERIFY_NONE		},
	{ L("yes"),		CASS_SSL_VERIFY_PEER_CERT	}
};
static size_t verify_cert_table_len = NUM_ELEMENTS(verify_cert_table);

static conf_parser_t load_balance_dc_aware_config[] = {
	{ FR_CONF_OFFSET("local_dc", rlm_sql_cassandra_t, lbdc_local_dc) },
	{ FR_CONF_OFFSET("hosts_per_remote_dc", rlm_sql_cassandra_t, lbdc_hosts_per_remote_dc), .dflt = "0" },
	{ FR_CONF_OFFSET("allow_remote_dcs_for_local_cl", rlm_sql_cassandra_t, lbdc_allow_remote_dcs_for_local_cl), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static conf_parser_t latency_aware_routing_config[] = {
	{ FR_CONF_OFFSET("exclusion_threshold", rlm_sql_cassandra_t, lar_exclusion_threshold), .dflt = "2.0" },
	{ FR_CONF_OFFSET("scale", rlm_sql_cassandra_t, lar_scale), .dflt = "0.1" },
	{ FR_CONF_OFFSET("retry_period", rlm_sql_cassandra_t, lar_retry_period), .dflt = "10" },
	{ FR_CONF_OFFSET("update_rate", rlm_sql_cassandra_t, lar_update_rate), .dflt = "0.1" },
	{ FR_CONF_OFFSET("min_measured", rlm_sql_cassandra_t, lar_min_measured), .dflt = "50" },
	CONF_PARSER_TERMINATOR
};

static conf_parser_t tls_config[] = {
	{ FR_CONF_OFFSET_FLAGS("ca_file", CONF_FLAG_FILE_INPUT, rlm_sql_cassandra_t, tls_ca_file) },
	{ FR_CONF_OFFSET_FLAGS("certificate_file", CONF_FLAG_FILE_INPUT, rlm_sql_cassandra_t, tls_certificate_file) },
	{ FR_CONF_OFFSET_FLAGS("private_key_file", CONF_FLAG_FILE_INPUT, rlm_sql_cassandra_t, tls_private_key_file) },
	{ FR_CONF_OFFSET_FLAGS("private_key_password", CONF_FLAG_SECRET, rlm_sql_cassandra_t, tls_private_key_password) },

	{ FR_CONF_OFFSET("verify_cert", rlm_sql_cassandra_t, tls_verify_cert_str) },
	CONF_PARSER_TERMINATOR
};

static const conf_parser_t driver_config[] = {
	{ FR_CONF_OFFSET("consistency", rlm_sql_cassandra_t, consistency_str), .dflt = "quorum" },

	{ FR_CONF_OFFSET("protocol_version", rlm_sql_cassandra_t, protocol_version) },

	{ FR_CONF_OFFSET("connections_per_host", rlm_sql_cassandra_t, connections_per_host) },

	{ FR_CONF_OFFSET("io_threads", rlm_sql_cassandra_t, io_threads) },
	{ FR_CONF_OFFSET("io_queue_size", rlm_sql_cassandra_t, io_queue_size) },

	{ FR_CONF_OFFSET("event_queue_size", rlm_sql_cassandra_t, event_queue_size) },

	{ FR_CONF_POINTER("load_balance_dc_aware", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) load_balance_dc_aware_config },
	{ FR_CONF_OFFSET("load_balance_round_robin", rlm_sql_cassandra_t, load_balance_round_robin), .dflt = "no" },

	{ FR_CONF_OFFSET("token_aware_routing", rlm_sql_cassandra_t, token_aware_routing), .dflt = "yes" },
	{ FR_CONF_POINTER("latency_aware_routing", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) latency_aware_routing_config },

	{ FR_CONF_OFFSET("tcp_keepalive", rlm_sql_cassandra_t, tcp_keepalive) },
	{ FR_CONF_OFFSET("tcp_nodelay", rlm_sql_cassandra_t, tcp_nodelay), .dflt = "no" },

	{ FR_CONF_POINTER("tls", 0, CONF_FLAG_SUBSECTION | CONF_FLAG_OK_MISSING, NULL), .subcs = (void const *) tls_config },
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

/** Store the last error associated with a query
 *
 * @param ctx to allocate message in
 * @param cass_query_ctx cassandra query context to write error message into.
 * @param message from libcassandra.
 * @param len of message.
 */
static void sql_set_query_error(TALLOC_CTX *ctx, cassandra_query_ctx_t *cass_query_ctx, char const *message, size_t len)
{
	talloc_const_free(cass_query_ctx->error.msg);
	cass_query_ctx->error.msg = fr_asprint(ctx, message, len, '\0');
	cass_query_ctx->error.type = L_ERR;
}


/** Store the last error associated with a query, using a format string
 *
 * @param ctx to allocate messate in.
 * @param cass_query_ctx to replace log message in.
 * @param fmt of message.
 * @param ... args.
 */
static void sql_set_query_error_printf(TALLOC_CTX *ctx, cassandra_query_ctx_t *cass_query_ctx, char const *fmt, ...)
	CC_HINT(format (printf, 3, 4));
static void sql_set_query_error_printf(TALLOC_CTX *ctx, cassandra_query_ctx_t *cass_query_ctx, char const *fmt, ...)
{
	va_list ap;

	talloc_const_free(cass_query_ctx->error.msg);
	va_start(ap, fmt);
	cass_query_ctx->error.msg = talloc_vasprintf(ctx, fmt, ap);
	va_end(ap);
	cass_query_ctx->error.type = L_ERR;
}

static void _sql_connection_close(UNUSED fr_event_list_t *el, void *h, UNUSED void *uctx)
{
	rlm_sql_cassandra_conn_t *conn = talloc_get_type_abort(h, rlm_sql_cassandra_conn_t);

	DEBUG2("Socket destructor called, closing socket");

	if (conn->iterator) cass_iterator_free(conn->iterator);
	talloc_free(h);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static connection_state_t _sql_connection_init(void **h, connection_t *conn, void *uctx)
{
	rlm_sql_t const			*sql = talloc_get_type_abort_const(uctx, rlm_sql_t);
	rlm_sql_config_t const		*config = &sql->config;
	rlm_sql_cassandra_t		*inst = talloc_get_type_abort(sql->driver_submodule->data, rlm_sql_cassandra_t);
	rlm_sql_cassandra_conn_t	*c;

	MEM(c = talloc_zero(conn, rlm_sql_cassandra_conn_t));
	*c = (rlm_sql_cassandra_conn_t) {
		.conn = conn,
		.inst = inst,
		.config = config,
		.log_ctx = talloc_pool(c, 2048),		/* Pre-allocate some memory for log messages */
		.poll_interval = 1000
	};

	*h = c;

	/*
	 *	We do this one inside sql_socket_init, to allow pool.start = 0 to
	 *	work as expected (allow the server to start if Cassandra is
	 *	unavailable).
	 */
	if (!inst->mutable->done_connect_keyspace) {
		CassFuture	*future;
		CassError	ret;

		pthread_mutex_lock(&inst->mutable->connect_mutex);
		if (!inst->mutable->done_connect_keyspace) {
			/*
			 *	Easier to do this here instead of mod_instantiate
			 *	as we don't have a pointer to the pool.
			 */
			cass_cluster_set_connect_timeout(inst->cluster, fr_time_delta_to_msec(config->trunk_conf.conn_conf->connection_timeout));

			DEBUG2("Connecting to Cassandra cluster");
			future = cass_session_connect_keyspace(inst->session, inst->cluster, config->sql_db);
			ret = cass_future_error_code(future);
			if (ret != CASS_OK) {
				const char	*msg;
				size_t		msg_len;

				cass_future_error_message(future, &msg, &msg_len);
				ERROR("Unable to connect: [%x] %s", (int)ret, msg);
				cass_future_free(future);
				pthread_mutex_unlock(&inst->mutable->connect_mutex);

				return CONNECTION_STATE_FAILED;
			}
			cass_future_free(future);
			inst->mutable->done_connect_keyspace = true;
		}
		pthread_mutex_unlock(&inst->mutable->connect_mutex);
	}

	fr_dlist_init(&c->queries, cassandra_query_t, entry);

	return CONNECTION_STATE_CONNECTED;
}

SQL_TRUNK_CONNECTION_ALLOC

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static void sql_trunk_request_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn,
				  connection_t *conn, UNUSED void *uctx)
{
	rlm_sql_cassandra_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_cassandra_conn_t);
	rlm_sql_cassandra_t const	*inst = sql_conn->inst;
	request_t			*request;
	trunk_request_t			*treq;
	fr_sql_query_t			*query_ctx;
	CassStatement			*statement;
	cassandra_query_t		*cass_query;
	cassandra_query_ctx_t		*cass_query_ctx;

	while (trunk_connection_pop_request(&treq, tconn) == 0) {
		if (!treq) return;

		query_ctx = talloc_get_type_abort(treq->preq, fr_sql_query_t);
		request = query_ctx->request;

		switch (query_ctx->status) {
		case SQL_QUERY_PREPARED:
			ROPTIONAL(RDEBUG2, DEBUG2, "Executing query: %s", query_ctx->query_str);
			statement = cass_statement_new_n(query_ctx->query_str, talloc_array_length(query_ctx->query_str) - 1, 0);
			if (inst->consistency_str) cass_statement_set_consistency(statement, inst->consistency);

			/*
			 *	Allocate tracking and driver specific structures.
			 */
			MEM(cass_query = talloc_zero(conn, cassandra_query_t));
			MEM(cass_query_ctx = talloc_zero(query_ctx, cassandra_query_ctx_t));
			query_ctx->uctx = cass_query_ctx;

			/*
			 *	Executing the query returns a future which will later be polled for its result.
			 *	Failures are not visible at this point.
			 */
			cass_query->future = cass_session_execute(inst->session, statement);
			cass_query->query_ctx = query_ctx;
			cass_statement_free(statement);

			/*
			 *	Insert the tracking structure into the list of outstanding queries.
			 */
			fr_dlist_insert_tail(&sql_conn->queries, cass_query);
			query_ctx->status = SQL_QUERY_SUBMITTED;
			query_ctx->tconn = tconn;
			trunk_request_signal_sent(treq);
			return;

		default:
			return;
		}
	}
}

static void sql_trunk_connection_read_poll(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	rlm_sql_cassandra_conn_t	*c = talloc_get_type_abort(uctx, rlm_sql_cassandra_conn_t);
	cassandra_query_t		*cass_query, *next_query = NULL;
	fr_sql_query_t			*query_ctx;
	cassandra_query_ctx_t		*cass_query_ctx;
	CassError			ret;
	request_t			*request;
	bool				handled = false;

	next_query = fr_dlist_head(&c->queries);
	while (next_query) {
		/*
		 *	If the future is not ready, move to the next.
		 */
		if (!cass_future_ready(next_query->future)) goto next;

		cass_query = next_query;
		next_query = fr_dlist_remove(&c->queries, cass_query);

		query_ctx = cass_query->query_ctx;
		request = query_ctx->request;
		handled = true;
		cass_query_ctx = talloc_get_type_abort(query_ctx->uctx, cassandra_query_ctx_t);

		ret = cass_future_error_code(cass_query->future);
		if (ret != CASS_OK) {
			char const	*error;
			size_t		len;

			cass_future_error_message(cass_query->future, &error, &len);
			sql_set_query_error(c->log_ctx, cass_query_ctx, error, len);

			switch (ret) {
			case CASS_ERROR_SERVER_SYNTAX_ERROR:
			case CASS_ERROR_SERVER_INVALID_QUERY:
				query_ctx->rcode = RLM_SQL_QUERY_INVALID;
				break;

			default:
				query_ctx->rcode = RLM_SQL_ERROR;
			}
			trunk_request_signal_fail(query_ctx->treq);
			cass_future_free(cass_query->future);
			talloc_free(cass_query);
			goto next;
		}

		query_ctx->rcode = RLM_SQL_OK;
		cass_query_ctx->result = cass_future_get_result(cass_query->future);
		cass_future_free(cass_query->future);
		if (request) unlang_interpret_mark_runnable(request);
		talloc_free(cass_query);
	next:
		next_query = fr_dlist_next(&c->queries, next_query);
	}

	/*
	 *	Adjust poll interval.  The aim is to return results as fast as
	 *	possible, but without over polling.
	 */
	if (!handled) {
		/*
		 *	Nothing was ready - increase the interval
		 */
		if (c->poll_interval < fr_time_delta_to_usec(c->config->query_timeout)/2) c->poll_interval += 100;
		c->poll_count ++;
	} else {
		/*
		 *	Results were immediately available - decrease the interval
		 */
		if (c->poll_count == 0) {
			c->poll_interval /= 2;
		}
		c->poll_count = 0;
	}

	/*
	 *	There are still outstanding queries, add another polling event
	 */
	if (fr_dlist_num_elements(&c->queries)) {
		if (fr_event_timer_in(c, el, &c->read_ev, fr_time_delta_from_usec(c->poll_interval),
				      sql_trunk_connection_read_poll, c) < 0) {
			ERROR("Unable to insert polling event");
		}
	}
}

static void sql_trunk_connection_write_poll(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);

	trunk_connection_signal_writable(tconn);
}

/*
 *	While libcassandra support installing callbacks to handle futures being set,
 *	in testing, in the callback attempting to retrieve the error status of the
 *	future locked up.  So we have to resort to polling.
 *
 *	This "notify" callback sets up the appropriate polling events.
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static void sql_trunk_connection_notify(UNUSED trunk_connection_t *tconn, connection_t *conn, UNUSED fr_event_list_t *el,
					trunk_connection_event_t notify_on, UNUSED void *uctx)
{
	rlm_sql_cassandra_conn_t	*c = talloc_get_type_abort(conn->h, rlm_sql_cassandra_conn_t);

	switch (notify_on) {
	case TRUNK_CONN_EVENT_NONE:
		if (c->read_ev) fr_event_timer_delete(&c->read_ev);
		if (c->write_ev) fr_event_timer_delete(&c->write_ev);
		return;

	case TRUNK_CONN_EVENT_BOTH:
	case TRUNK_CONN_EVENT_READ:
		if (fr_dlist_num_elements(&c->queries)) {
			if (fr_event_timer_in(c, el, &c->read_ev, fr_time_delta_from_usec(c->poll_interval),
					      sql_trunk_connection_read_poll, c) < 0) {
				ERROR("Unable to insert polling event");
			}
		}
		if (notify_on == TRUNK_CONN_EVENT_READ) return;

		FALL_THROUGH;

	case TRUNK_CONN_EVENT_WRITE:
		if (fr_event_timer_in(c, el, &c->write_ev, fr_time_delta_from_usec(0),
				      sql_trunk_connection_write_poll, tconn) < 0) {
			ERROR("Unable to insert polling event");
		}
		return;
	}
}

SQL_QUERY_RESUME
SQL_QUERY_FAIL

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static void sql_request_cancel(connection_t *conn, void *preq, trunk_cancel_reason_t reason,
			       UNUSED void *uctx)
{
	fr_sql_query_t			*query_ctx = talloc_get_type_abort(preq, fr_sql_query_t);
	rlm_sql_cassandra_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_cassandra_conn_t);
	cassandra_query_t		*cass_query = NULL;

	if (!query_ctx->treq) return;
	if (reason != TRUNK_CANCEL_REASON_SIGNAL) return;

	/*
	 *	There is no query cancellation for Cassandra.
	 *	So, remove the query from the list of outstanding queries so
	 *	if it does return, we don't do anything.
	 */
	while ((cass_query = fr_dlist_next(&sql_conn->queries, cass_query))) {
		if (cass_query->query_ctx == query_ctx) {
			fr_dlist_remove(&sql_conn->queries, cass_query);
			cass_future_free(cass_query->future);
			return;
		}
	}
}

static int sql_num_rows(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	cassandra_query_ctx_t	*cass_query_ctx = query_ctx->uctx;

	return cass_query_ctx->result ? cass_result_row_count(cass_query_ctx->result) : 0;
}

static sql_rcode_t sql_fields(char const **out[], fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	cassandra_query_ctx_t	*cass_query_ctx = query_ctx->uctx;
	CassResult const	*result = cass_query_ctx->result;

	unsigned int	fields, i;
	char const	**names;

	fields = result ? cass_result_column_count(result) : 0;
	if (fields == 0) return RLM_SQL_ERROR;

	MEM(names = talloc_array(query_ctx, char const *, fields));

	for (i = 0; i < fields; i++) {
		const char *col_name;
		size_t	   col_name_len;

		/* Writes out a pointer to a buffer in the result */
		if (cass_result_column_name(result, i, &col_name, &col_name_len) != CASS_OK) {
			col_name = "<INVALID>";
		}
		names[i] = col_name;
	}

	*out = names;

	return RLM_SQL_OK;
}

static unlang_action_t sql_fetch_row(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t			*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_cassandra_conn_t 	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_cassandra_conn_t);
	CassRow	const 			*cass_row;
	cassandra_query_ctx_t		*cass_query_ctx = query_ctx->uctx;
	CassResult const		*result = cass_query_ctx->result;
	int				fields, i;
	char				**row;

#define RLM_CASS_ERR_DATA_RETRIVE(_t) \
do {\
	char const *_col_name;\
	size_t _col_name_len;\
	CassError _ret;\
	if ((_ret = cass_result_column_name(result, i, &_col_name, &_col_name_len)) != CASS_OK) {\
		_col_name = "<INVALID>";\
	}\
	sql_set_query_error_printf(conn->log_ctx, cass_query_ctx, "Failed to retrieve " _t " data at column %s (%d): %s", \
				  _col_name, i, cass_error_desc(_ret));\
	TALLOC_FREE(query_ctx->row);\
	query_ctx->rcode = RLM_SQL_ERROR;\
	RETURN_MODULE_FAIL;\
} while(0)

	query_ctx->rcode = RLM_SQL_OK;
	if (!result) RETURN_MODULE_OK;					/* no result */

	/*
	 *	Start of the result set, initialise the iterator.
	 */
	if (!conn->iterator) conn->iterator = cass_iterator_from_result(result);
	if (!conn->iterator) RETURN_MODULE_OK;				/* no result */

	/*
	 *	Free the previous result (also gets called on finish_query)
	 */
	TALLOC_FREE(query_ctx->row);

	if (!cass_iterator_next(conn->iterator)) {
		query_ctx->rcode = RLM_SQL_NO_MORE_ROWS;		/* no more rows */
		RETURN_MODULE_OK;
	}

	cass_row = cass_iterator_get_row(conn->iterator);		/* this shouldn't fail ? */
	fields = cass_result_column_count(result);			/* get the number of fields... */

	MEM(row = query_ctx->row = talloc_zero_array(query_ctx, char *, fields + 1));

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

			if (cass_result_column_name(result, i, &col_name,
						    &col_name_len) != CASS_OK) col_name = "<INVALID>";

			sql_set_query_error_printf(conn->log_ctx, cass_query_ctx,
						  "Failed to retrieve data at column %s (%d): Unsupported data type",
						  col_name, i);
			talloc_free(query_ctx->row);
			query_ctx->rcode = RLM_SQL_ERROR;
			RETURN_MODULE_FAIL;
		}
		}
	}

	RETURN_MODULE_OK;
}

static sql_rcode_t sql_free_result(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_cassandra_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_cassandra_conn_t);

	if (query_ctx->row) TALLOC_FREE(query_ctx->row);

	if (conn->iterator) {
		cass_iterator_free(conn->iterator);
		conn->iterator = NULL;
	}

	if (query_ctx->uctx) {
		cassandra_query_ctx_t *cass_query_ctx = talloc_get_type_abort(query_ctx->uctx, cassandra_query_ctx_t);
		if (cass_query_ctx->result) cass_result_free(cass_query_ctx->result);
		cass_query_ctx->result = NULL;
	}

	return RLM_SQL_OK;
}

static size_t sql_error(UNUSED TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			fr_sql_query_t *query_ctx)
{
	cassandra_query_ctx_t	*cass_query_ctx = talloc_get_type_abort(query_ctx->uctx, cassandra_query_ctx_t);

	if (cass_query_ctx->error.msg && (outlen >= 1)) {
		out[0].msg = cass_query_ctx->error.msg;
		out[0].type = cass_query_ctx->error.type;

		return 1;
	}

	return 0;
}

static sql_rcode_t sql_finish_query(fr_sql_query_t *query_ctx, rlm_sql_config_t const *config)
{
	cassandra_query_ctx_t	*cass_query_ctx = talloc_get_type_abort(query_ctx->uctx, cassandra_query_ctx_t);

	cass_result_free(cass_query_ctx->result);
	talloc_const_free(cass_query_ctx->error.msg);

	return sql_free_result(query_ctx, config);
}

/*
 *	The cassandra model is different, as it's distributed, and does
 *	upserts instead of inserts...
 *
 *	There's a good article on it here:
 *		http://planetcassandra.org/blog/how-to-do-an-upsert-in-cassandra/
 */
static int sql_affected_rows(UNUSED fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	return 1;
}

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_sql_cassandra_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_sql_cassandra_t);

	if (inst->ssl) cass_ssl_free(inst->ssl);
	if (inst->session) cass_session_free(inst->session);	/* also synchronously closes the session */
	if (inst->cluster) cass_cluster_free(inst->cluster);

	pthread_mutex_destroy(&inst->mutable->connect_mutex);
	talloc_free(inst->mutable);

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_sql_t const		*parent = talloc_get_type_abort(mctx->mi->parent->data, rlm_sql_t);
	rlm_sql_config_t const	*config = &parent->config;
	rlm_sql_cassandra_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_sql_cassandra_t);
	bool			do_tls = false;
	bool			do_latency_aware_routing = false;
	CassCluster 		*cluster;
	int			ret;

#define DO_CASS_OPTION(_opt, _x) \
do {\
	CassError _ret;\
	if ((_ret = (_x)) != CASS_OK) {\
		ERROR("Error setting " _opt ": %s", cass_error_desc(_ret));\
		return -1;\
	}\
} while (0)

	MEM(inst->mutable = talloc_zero(NULL, rlm_sql_cassandra_mutable_t));
	if ((ret = pthread_mutex_init(&inst->mutable->connect_mutex, NULL)) < 0) {
		ERROR("Failed initializing mutex: %s", fr_syserror(ret));
		TALLOC_FREE(inst);
		return -1;
	}

	/*
	 *	This has to be done before we call cf_section_parse
	 *	as it sets default values, and creates the section.
	 */
	if (cf_section_find(mctx->mi->conf, "tls", NULL)) do_tls = true;
	if (cf_section_find(mctx->mi->conf, "latency_aware_routing", NULL)) do_latency_aware_routing = true;

	DEBUG4("Configuring CassCluster structure");
	cluster = inst->cluster = cass_cluster_new();
	if (!cluster) return -1;

	/*
	 *	Parameters inherited from the top level SQL module config
	 */
	DO_CASS_OPTION("sql_server", cass_cluster_set_contact_points(cluster, config->sql_server));
	if (config->sql_port) DO_CASS_OPTION("sql_port", cass_cluster_set_port(cluster, config->sql_port));
	/* Can't fail */
	if (fr_time_delta_ispos(config->query_timeout)) {
		cass_cluster_set_request_timeout(cluster, fr_time_delta_to_msec(config->query_timeout));
	}

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
		if (!ssl) return -1;

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
	if (!inst->session) return -1;

	return 0;
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
	.common = {
		.name				= "sql_cassandra",
		.magic				= MODULE_MAGIC_INIT,
		.inst_size			= sizeof(rlm_sql_cassandra_t),
		.onload				= mod_load,
		.config				= driver_config,
		.instantiate			= mod_instantiate,
		.detach				= mod_detach
	},
	.flags				= RLM_SQL_MULTI_QUERY_CONN,
	.sql_query_resume		= sql_query_resume,
	.sql_select_query_resume	= sql_query_resume,
	.sql_num_rows			= sql_num_rows,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fields			= sql_fields,
	.sql_fetch_row			= sql_fetch_row,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_query,
	.trunk_io_funcs = {
		.connection_alloc	= sql_trunk_connection_alloc,
		.connection_notify	= sql_trunk_connection_notify,
		.request_mux		= sql_trunk_request_mux,
		.request_cancel		= sql_request_cancel,
		.request_fail		= sql_request_fail
	}
};
