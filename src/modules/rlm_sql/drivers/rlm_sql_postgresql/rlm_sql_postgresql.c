/*
 * sql_postgresql.c		Postgresql rlm_sql driver
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Mike Machado (mike@innercite.com)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 */

/*
 * April 2001:
 *
 * Use blocking queries and delete unused functions. In
 * rlm_sql_postgresql replace all functions that are not really used
 * with the not_implemented function.
 *
 * Add a new field to the rlm_sql_postgres_conn_t struct to store the
 * number of rows affected by a query because the sql module calls
 * finish_query before it retrieves the number of affected rows from the
 * driver
 *
 * Bernhard Herzog <bh@intevation.de>
 */

RCSID("$Id$")

#define LOG_PREFIX "sql - postgresql"

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <sys/stat.h>

#include <libpq-fe.h>
#include <postgres_ext.h>

#include "config.h"
#include "rlm_sql.h"
#include "rlm_sql_trunk.h"

#ifndef NAMEDATALEN
#  define NAMEDATALEN 64
#endif

/** PostgreSQL configuration
 *
 */
typedef struct {
	char const	*db_string;		//!< Text based configuration string.
	bool		send_application_name;	//!< Whether we send the application name to PostgreSQL.
	fr_trie_t	*states;		//!< sql state trie.
} rlm_sql_postgresql_t;

typedef struct {
	PGconn		*db;
	PGresult	*result;
	int		cur_row;
	int		num_fields;
	int		affected_rows;
	char		**row;
	connection_t	*conn;			//!< Generic connection structure for this connection.
	int		fd;			//!< fd for this connection's I/O events.
	fr_sql_query_t	*query_ctx;		//!< Current query running on this connection.
} rlm_sql_postgres_conn_t;

static conf_parser_t driver_config[] = {
	{ FR_CONF_OFFSET("send_application_name", rlm_sql_postgresql_t, send_application_name), .dflt = "yes" },
	CONF_PARSER_TERMINATOR
};

/** These are PostgreSQL specific error codes which are not covered in SQL 2011
 *
 */
static sql_state_entry_t sql_state_table[] = {
	{ "03", "SQL statement not yet complete",			RLM_SQL_OK },
	{ "0B", "Invalid transaction initiation",			RLM_SQL_ERROR },
	{ "53", "Insufficient resources",				RLM_SQL_ERROR },
	/*
	 *	54000	program_limit_exceeded
	 *	54001	statement_too_complex
	 *	54011	too_many_columns
	 *	54023	too_many_arguments
	 */
	{ "54", "Program limit exceeded",				RLM_SQL_QUERY_INVALID },

	{ "55", "Object not in prerequisite state",			RLM_SQL_ERROR },

	/*
	 *	Error seen when NOWAIT is used to abort queries that involve rows
	 *	which are already locked.
	 *
	 *	Listed specifically for efficiency.
	 */
	{ "55P03", "Lock not available",				RLM_SQL_ERROR },

	{ "57", "Operator intervention",				RLM_SQL_ERROR },

	/*
	 *	This is really 'statement_timeout' or the error which is returned when
	 *	'statement_timeout' is hit.
	 *
	 *	It's unlikely that this has been caused by a connection failure, and
	 *	most likely to have been caused by a long running query.
	 *
	 *	If the query is persistently long running then the database/query should
	 *	be optimised, or 'statement_timeout' should be increased.
	 *
	 *	Forcing a reconnect here only eats more resources on the DB so we will
	 *	no longer do so as of 3.0.4.
	 */
	{ "57014", "Query cancelled",					RLM_SQL_ERROR },
	{ "57P01", "Admin shutdown",					RLM_SQL_RECONNECT },
	{ "57P02", "Crash shutdown",					RLM_SQL_RECONNECT },
	{ "57P03", "Cannot connect now",				RLM_SQL_RECONNECT },
	{ "58", "System error",						RLM_SQL_RECONNECT },
	{ "72", "Snapshot failure",					RLM_SQL_ERROR },
	{ "F0", "Configuration file error",				RLM_SQL_ERROR },
	{ "P0", "PL/PGSQL error",					RLM_SQL_ERROR },
	{ "XX", "Internal error",					RLM_SQL_ERROR },
	{ NULL, NULL,							RLM_SQL_ERROR }		/* Default code */
};

/** Return the number of affected rows of the result as an int instead of the string that postgresql provides
 *
 */
static int affected_rows(PGresult * result)
{
	return atoi(PQcmdTuples(result));
}

/** Free the row of the current result that's stored in the conn struct
 *
 */
static void free_result_row(rlm_sql_postgres_conn_t *conn)
{
	TALLOC_FREE(conn->row);
	conn->num_fields = 0;
}

#if defined(PG_DIAG_SQLSTATE) && defined(PG_DIAG_MESSAGE_PRIMARY)
static sql_rcode_t sql_classify_error(rlm_sql_postgresql_t *inst, ExecStatusType status, PGresult const *result)
{
	char const		*error_code;
	char const		*error_msg;
	sql_state_entry_t const	*entry;

	error_code = PQresultErrorField(result, PG_DIAG_SQLSTATE);
	if (!error_code) {
		switch (status){
		/*
		 *  Successful completion of a command returning no data.
		 */
		case PGRES_COMMAND_OK:
	#ifdef HAVE_PGRES_SINGLE_TUPLE
		case PGRES_SINGLE_TUPLE:
	#endif
	#ifdef HAVE_PGRES_TUPLES_CHUNK
		case PGRES_TUPLES_CHUNK:
	#endif
		case PGRES_TUPLES_OK:
	#ifdef HAVE_PGRES_COPY_BOTH
		case PGRES_COPY_BOTH:
	#endif
		case PGRES_COPY_OUT:
		case PGRES_COPY_IN:
			error_code = "00000";
			break;

		case PGRES_EMPTY_QUERY:	/* Shouldn't happen */
			error_code = "42000";
			break;

	#ifdef HAVE_PGRES_PIPELINE_SYNC
		case PGRES_PIPELINE_SYNC:
		case PGRES_PIPELINE_ABORTED:
			ERROR("libpq reported aborted pipeline");
			return RLM_SQL_ERROR;
	#endif

		case PGRES_BAD_RESPONSE:
		case PGRES_NONFATAL_ERROR:
		case PGRES_FATAL_ERROR:
			ERROR("libpq provided no error code");
			return RLM_SQL_ERROR;
		}
	}

	entry = sql_state_entry_find(inst->states, error_code);
	if (!entry) {
		ERROR("Can't classify: %s", error_code);
		return RLM_SQL_ERROR;
	}

	DEBUG3("sqlstate %s matched %s: %s (%s)", error_code,
	       entry->sql_state, entry->meaning, fr_table_str_by_value(sql_rcode_table, entry->rcode, "<DEFAULT>"));

	/*
	 *	WARNING error class.
	 */
	if ((entry->sql_state[0] == '0') && (entry->sql_state[1] == '1')) {
		error_msg = PQresultErrorField(result, PG_DIAG_MESSAGE_PRIMARY);
		if (error_msg) WARN("%s", error_msg);
	}

	return entry->rcode;
}
#  else
static sql_rcode_t sql_classify_error(UNUSED PGresult const *result)
{
	ERROR("Error occurred, no more information available, rebuild with newer libpq");
	return RLM_SQL_ERROR;
}
#endif

static void _sql_connect_io_notify(fr_event_list_t *el, int fd, UNUSED int flags, void *uctx)
{
	rlm_sql_postgres_conn_t		*c = talloc_get_type_abort(uctx, rlm_sql_postgres_conn_t);
	PostgresPollingStatusType	status;

	fr_event_fd_delete(el, fd, FR_EVENT_FILTER_IO);

	status = PQconnectPoll(c->db);

	/*
	 *	Documentation says:
	 *		Caution: do not assume that the socket remains the same across PQconnectPoll calls.
	 *	So we get the socket again.
	 */
	c->fd = PQsocket(c->db);
	switch (status) {
	case PGRES_POLLING_OK:
		DEBUG2("Connected to database '%s' on '%s' server version %i, protocol version %i, backend PID %i ",
		       PQdb(c->db), PQhost(c->db), PQserverVersion(c->db), PQprotocolVersion(c->db),
		       PQbackendPID(c->db));
		PQsetnonblocking(c->db, 1);
		connection_signal_connected(c->conn);
		return;

	case PGRES_POLLING_FAILED:
	error:
		ERROR("Connection failed: %s", PQerrorMessage(c->db));
		connection_signal_reconnect(c->conn, CONNECTION_FAILED);
		return;

	case PGRES_POLLING_READING:
		if (fr_event_fd_insert(c, NULL, c->conn->el, c->fd, _sql_connect_io_notify, NULL, NULL, c) != 0) goto error;
		return;

	case PGRES_POLLING_WRITING:
		if (fr_event_fd_insert(c, NULL, c->conn->el, c->fd, NULL, _sql_connect_io_notify, NULL, c) != 0) goto error;
		return;

	default:
		goto error;

	}
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static connection_state_t _sql_connection_init(void **h, connection_t *conn, void *uctx)
{
	rlm_sql_t const			*sql = talloc_get_type_abort_const(uctx, rlm_sql_t);
	rlm_sql_postgresql_t const	*inst = talloc_get_type_abort(sql->driver_submodule->data, rlm_sql_postgresql_t);
	rlm_sql_postgres_conn_t		*c;
	PostgresPollingStatusType	status;

	MEM(c = talloc_zero(conn, rlm_sql_postgres_conn_t));
	c->conn = conn;
	c->fd = -1;

	DEBUG2("Starting connection to PostgreSQL server using parameters: %s", inst->db_string);

	c->db = PQconnectStart(inst->db_string);
	if (!c->db) {
		ERROR("Connection failed: Out of memory");
		talloc_free(c);
		return CONNECTION_STATE_FAILED;
	}

	switch (PQstatus(c->db)) {
	case CONNECTION_OK:
		c->fd = PQsocket(c->db);
		DEBUG2("Connected to database '%s' on '%s' server version %i, protocol version %i, backend PID %i ",
		       PQdb(c->db), PQhost(c->db), PQserverVersion(c->db), PQprotocolVersion(c->db),
		       PQbackendPID(c->db));
		PQsetnonblocking(c->db, 1);
		connection_signal_connected(c->conn);
		return CONNECTION_STATE_CONNECTING;

	case CONNECTION_BAD:
		ERROR("Connection failed: %s", PQerrorMessage(c->db));
	error:
		PQfinish(c->db);
		talloc_free(c);
		return CONNECTION_STATE_FAILED;

	default:
		break;

	}

	status = PQconnectPoll(c->db);
	c->fd = PQsocket(c->db);
	if (fr_event_fd_insert(c, NULL, c->conn->el, c->fd,
			       status == PGRES_POLLING_READING ? _sql_connect_io_notify : NULL,
			       status == PGRES_POLLING_WRITING ? _sql_connect_io_notify : NULL, NULL, c) != 0) goto error;

	DEBUG2("Connecting to database '%s' on '%s', fd %d", PQdb(c->db), PQhost(c->db), c->fd);

	*h = c;

	return CONNECTION_STATE_CONNECTING;
}

static void _sql_connection_close(fr_event_list_t *el, void *h, UNUSED void *uctx)
{
	rlm_sql_postgres_conn_t	*c = talloc_get_type_abort(h, rlm_sql_postgres_conn_t);

	if (c->fd >= 0) {
		fr_event_fd_delete(el, c->fd, FR_EVENT_FILTER_IO);
		c->fd = -1;
	}

	if (c->result) {
		PQclear(c->result);
		c->result = NULL;
	}

	/* PQfinish also frees the memory used by the PGconn structure */
	PQfinish(c->db);
	c->query_ctx = NULL;
	talloc_free(h);
}

SQL_TRUNK_CONNECTION_ALLOC

TRUNK_NOTIFY_FUNC(sql_trunk_connection_notify, rlm_sql_postgres_conn_t)

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void sql_trunk_request_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn,
				  connection_t *conn, UNUSED void *uctx)
{
	rlm_sql_postgres_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_postgres_conn_t);
	request_t		*request;
	trunk_request_t		*treq;
	fr_sql_query_t		*query_ctx;
	int			err;

	if (trunk_connection_pop_request(&treq, tconn) != 0) return;
	if (!treq) return;

	query_ctx = talloc_get_type_abort(treq->preq, fr_sql_query_t);
	request = query_ctx->request;

	switch (query_ctx->status) {
	case SQL_QUERY_PREPARED:
		ROPTIONAL(RDEBUG2, DEBUG2, "Executing query: %s", query_ctx->query_str);
		err = PQsendQuery(sql_conn->db, query_ctx->query_str);
		query_ctx->tconn = tconn;
		if (!err) {
			ROPTIONAL(RERROR, ERROR, "Failed to send query: %s", PQerrorMessage(sql_conn->db));
			trunk_request_signal_fail(treq);
			return;
		}

		query_ctx->status = SQL_QUERY_SUBMITTED;
		sql_conn->query_ctx = query_ctx;
		trunk_request_signal_sent(treq);
		return;

	default:
		return;
	}
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void sql_trunk_request_demux(UNUSED fr_event_list_t *el, UNUSED trunk_connection_t *tconn,
				    connection_t *conn, UNUSED void *uctx)
{
	rlm_sql_postgres_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_postgres_conn_t);
	rlm_sql_postgresql_t	*inst;
	fr_sql_query_t		*query_ctx;
	request_t		*request;
	PGresult		*tmp_result;
	ExecStatusType		status;
	int			numfields;

	query_ctx = sql_conn->query_ctx;
	request = query_ctx->request;
	inst = talloc_get_type_abort(query_ctx->inst->driver_submodule->data, rlm_sql_postgresql_t);

	switch (query_ctx->status) {
	case SQL_QUERY_SUBMITTED:
		if (PQconsumeInput(sql_conn->db) == 0) {
			ROPTIONAL(RERROR, ERROR, "SQL query failed: %s", PQerrorMessage(sql_conn->db));
			query_ctx->rcode = RLM_SQL_ERROR;
			break;
		}
		if (PQisBusy(sql_conn->db)) return;

		query_ctx->status = SQL_QUERY_RETURNED;

		sql_conn->result = PQgetResult(sql_conn->db);

		/* Discard results for appended queries */
		while ((tmp_result = PQgetResult(sql_conn->db)) != NULL)
			PQclear(tmp_result);

		/*
		 *  As this error COULD be a connection error OR an out-of-memory
		 *  condition return value WILL be wrong SOME of the time
		 *  regardless! Pick your poison...
		 */
		if (!sql_conn->result) {
			ROPTIONAL(RERROR, ERROR, "Failed getting query result: %s", PQerrorMessage(sql_conn->db));
			query_ctx->rcode = RLM_SQL_RECONNECT;
			break;
		}

		status = PQresultStatus(sql_conn->result);
		switch (status){
		/*
		 *  Successful completion of a command returning no data.
		 */
		case PGRES_COMMAND_OK:
			/*
			 *  Affected_rows function only returns the number of affected rows of a command
			 *  returning no data...
			 */
			sql_conn->affected_rows = affected_rows(sql_conn->result);
			ROPTIONAL(RDEBUG2, DEBUG2, "query affected rows = %i", sql_conn->affected_rows);
			break;
		/*
		 *  Successful completion of a command returning data (such as a SELECT or SHOW).
		 */
#ifdef HAVE_PGRES_SINGLE_TUPLE
		case PGRES_SINGLE_TUPLE:
#endif
#ifdef HAVE_PGRES_TUPLES_CHUNK
		case PGRES_TUPLES_CHUNK:
#endif
		case PGRES_TUPLES_OK:
			sql_conn->cur_row = 0;
			sql_conn->affected_rows = PQntuples(sql_conn->result);
			numfields = PQnfields(sql_conn->result); /*Check row storing functions..*/
			ROPTIONAL(RDEBUG2, DEBUG2, "query returned rows = %i, fields = %i", sql_conn->affected_rows, numfields);
			break;

#ifdef HAVE_PGRES_COPY_BOTH
		case PGRES_COPY_BOTH:
#endif
		case PGRES_COPY_OUT:
		case PGRES_COPY_IN:
			DEBUG2("Data transfer started");
			break;

		/*
		 *  Weird.. this shouldn't happen.
		 */
		case PGRES_EMPTY_QUERY:
		case PGRES_BAD_RESPONSE:	/* The server's response was not understood */
		case PGRES_NONFATAL_ERROR:
		case PGRES_FATAL_ERROR:
#ifdef HAVE_PGRES_PIPELINE_SYNC
		case PGRES_PIPELINE_SYNC:
		case PGRES_PIPELINE_ABORTED:
#endif
			break;
		}

		query_ctx->rcode = sql_classify_error(inst, status, sql_conn->result);
		break;

	default:
		fr_assert(0);
	}

	if (request) unlang_interpret_mark_runnable(request);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void sql_request_cancel(connection_t *conn, void *preq, trunk_cancel_reason_t reason,
			       UNUSED void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(preq, fr_sql_query_t);
	rlm_sql_postgres_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_postgres_conn_t);

	if (!query_ctx->treq) return;
	if (reason != TRUNK_CANCEL_REASON_SIGNAL) return;
	if (sql_conn->query_ctx == query_ctx) sql_conn->query_ctx = NULL;
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function*/
static void sql_request_cancel_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn,
				   connection_t *conn, UNUSED void *uctx)
{
	trunk_request_t		*treq;
	PGcancel		*cancel;
	rlm_sql_postgres_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_postgres_conn_t);
	char			errbuf[256];
	PGresult		*tmp_result;

	if ((trunk_connection_pop_cancellation(&treq, tconn)) == 0) {
		cancel = PQgetCancel(sql_conn->db);
		if (!cancel) goto complete;
		if (PQcancel(cancel, errbuf, sizeof(errbuf)) == 0) {
			ERROR("Failed to cancel query: %s", errbuf);
		}
		PQfreeCancel(cancel);

		/*
		 *	The documentation says that regardless of the result of
		 *	PQcancel, the normal processing of PQgetResult must happen.
		 */
		while ((tmp_result = PQgetResult(sql_conn->db)) != NULL)
			PQclear(tmp_result);

	complete:
		trunk_request_signal_cancel_complete(treq);
	}
}

SQL_QUERY_FAIL
SQL_QUERY_RESUME

static sql_rcode_t sql_fields(char const **out[], fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_postgres_conn_t *conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_postgres_conn_t);

	int		fields, i;
	char const	**names;

	fields = PQnfields(conn->result);
	if (fields <= 0) return RLM_SQL_ERROR;

	MEM(names = talloc_array(query_ctx, char const *, fields));

	for (i = 0; i < fields; i++) names[i] = PQfname(conn->result, i);
	*out = names;

	return RLM_SQL_OK;
}

static unlang_action_t sql_fetch_row(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	int			records, i, len;
	rlm_sql_postgres_conn_t *conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_postgres_conn_t);

	query_ctx->row = NULL;

	query_ctx->rcode = RLM_SQL_NO_MORE_ROWS;
	if (conn->cur_row >= PQntuples(conn->result)) RETURN_MODULE_OK;

	free_result_row(conn);

	records = PQnfields(conn->result);
	conn->num_fields = records;

	if ((PQntuples(conn->result) > 0) && (records > 0)) {
		conn->row = talloc_zero_array(conn, char *, records + 1);
		for (i = 0; i < records; i++) {
			if (PQgetisnull(conn->result, conn->cur_row, i)) continue;
			len = PQgetlength(conn->result, conn->cur_row, i);
			conn->row[i] = talloc_array(conn->row, char, len + 1);
			strlcpy(conn->row[i], PQgetvalue(conn->result, conn->cur_row, i), len + 1);
		}
		conn->cur_row++;
		query_ctx->row = conn->row;

		query_ctx->rcode = RLM_SQL_OK;
	}

	RETURN_MODULE_OK;
}

static sql_rcode_t sql_free_result(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_postgres_conn_t *conn;

	if (query_ctx->treq && !(query_ctx->treq->state &
	    (TRUNK_REQUEST_STATE_SENT | TRUNK_REQUEST_STATE_REAPABLE | TRUNK_REQUEST_STATE_COMPLETE))) return RLM_SQL_OK;

	if (!query_ctx->tconn || !query_ctx->tconn->conn || !query_ctx->tconn->conn->h) return RLM_SQL_ERROR;

	if (!(query_ctx->tconn->state & TRUNK_CONN_PROCESSING)) return RLM_SQL_ERROR;

	conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_postgres_conn_t);

	if (conn->result != NULL) {
		PQclear(conn->result);
		conn->result = NULL;
	}

	free_result_row(conn);

	return 0;
}

/** Retrieves any errors associated with the query context
 *
 * @note Caller will free any memory allocated in ctx.
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
	rlm_sql_postgres_conn_t *conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_postgres_conn_t);
	char const		*p, *q;
	size_t			i = 0;

	fr_assert(outlen > 0);

	p = PQerrorMessage(conn->db);
	while ((q = strchr(p, '\n'))) {
		out[i].type = L_ERR;
		out[i].msg = talloc_typed_asprintf(ctx, "%.*s", (int) (q - p), p);
		p = q + 1;
		if (++i == outlen) return outlen;
	}
	if (*p != '\0') {
		out[i].type = L_ERR;
		out[i].msg = p;
		i++;
	}

	return i;
}

static int sql_affected_rows(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_postgres_conn_t *conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_postgres_conn_t);

	return conn->affected_rows;
}

static ssize_t sql_escape_func(request_t *request, char *out, size_t outlen, char const *in, void *arg)
{
	size_t			inlen, ret;
	connection_t		*c = talloc_get_type_abort(arg, connection_t);
	rlm_sql_postgres_conn_t	*conn;
	int			err;

	if ((c->state == CONNECTION_STATE_HALTED) || (c->state == CONNECTION_STATE_CLOSED)) {
		ROPTIONAL(RERROR, ERROR, "Connection not available for escaping");
		return -1;
	}

	conn = talloc_get_type_abort(c->h, rlm_sql_postgres_conn_t);

	/* Check for potential buffer overflow */
	inlen = strlen(in);
	if ((inlen * 2 + 1) > outlen) return 0;
	/* Prevent integer overflow */
	if ((inlen * 2 + 1) <= inlen) return 0;

	ret = PQescapeStringConn(conn->db, out, in, inlen, &err);
	if (err) {
		ROPTIONAL(REDEBUG, ERROR, "Error escaping string \"%s\": %s", in, PQerrorMessage(conn->db));
		return 0;
	}

	return ret;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_sql_t const		*parent = talloc_get_type_abort(mctx->mi->parent->data, rlm_sql_t);
	rlm_sql_config_t const	*config = &parent->config;
	rlm_sql_postgresql_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_sql_postgresql_t);
	char 			application_name[NAMEDATALEN];
	char			*db_string;

	/*
	 *	Allow the user to set their own, or disable it
	 */
	if (inst->send_application_name) {
		CONF_SECTION	*cs;
		char const	*name;

		cs = cf_item_to_section(cf_parent(mctx->mi->conf));

		name = cf_section_name2(cs);
		if (!name) name = cf_section_name1(cs);

		snprintf(application_name, sizeof(application_name),
			 "FreeRADIUS " RADIUSD_VERSION_STRING " - %s (%s)", main_config->name, name);
	}

	/*
	 *	Old style database name
	 *
	 *	Append options if they were set in the config
	 */
	if (!strchr(config->sql_db, '=')) {
		db_string = talloc_typed_asprintf(inst, "dbname='%s'", config->sql_db);

		if (config->sql_server[0] != '\0') {
			db_string = talloc_asprintf_append(db_string, " host='%s'", config->sql_server);
		}

		if (config->sql_port) {
			db_string = talloc_asprintf_append(db_string, " port=%i", config->sql_port);
		}

		if (config->sql_login[0] != '\0') {
			db_string = talloc_asprintf_append(db_string, " user='%s'", config->sql_login);
		}

		if (config->sql_password[0] != '\0') {
			db_string = talloc_asprintf_append(db_string, " password='%s'", config->sql_password);
		}

		if (fr_time_delta_ispos(config->query_timeout)) {
			db_string = talloc_asprintf_append(db_string, " connect_timeout=%d", (int) fr_time_delta_to_sec(config->query_timeout));
		}

		if (inst->send_application_name) {
			db_string = talloc_asprintf_append(db_string, " application_name='%s'", application_name);
		}

	/*
	 *	New style parameter string
	 *
	 *	Only append options when not already present
	 */
	} else {
		db_string = talloc_typed_strdup(inst, config->sql_db);

		if ((config->sql_server[0] != '\0') && !strstr(db_string, "host=")) {
			db_string = talloc_asprintf_append(db_string, " host='%s'", config->sql_server);
		}

		if (config->sql_port && !strstr(db_string, "port=")) {
			db_string = talloc_asprintf_append(db_string, " port=%i", config->sql_port);
		}

		if ((config->sql_login[0] != '\0') && !strstr(db_string, "user=")) {
			db_string = talloc_asprintf_append(db_string, " user='%s'", config->sql_login);
		}

		if ((config->sql_password[0] != '\0') && !strstr(db_string, "password=")) {
			db_string = talloc_asprintf_append(db_string, " password='%s'", config->sql_password);
		}

		if (fr_time_delta_ispos(config->query_timeout) && !strstr(db_string, "connect_timeout=")) {
			db_string = talloc_asprintf_append(db_string, " connect_timeout=%d", (int) fr_time_delta_to_sec(config->query_timeout));
		}

		if (inst->send_application_name && !strstr(db_string, "application_name=")) {
			db_string = talloc_asprintf_append(db_string, " application_name='%s'", application_name);
		}
	}
	inst->db_string = db_string;

	inst->states = sql_state_trie_alloc(inst);

	/*
	 *	Load in the PostgreSQL specific sqlstates
	 */
	if (sql_state_entries_from_table(inst->states, sql_state_table) < 0) return -1;

	/*
	 *	Load in overrides from the driver's configuration section
	 */
	{
		CONF_SECTION *cs;

		cs = cf_section_find(mctx->mi->conf, "states", NULL);
		if (cs && (sql_state_entries_from_cs(inst->states, cs) < 0)) return -1;
	}

	return 0;
}

static int mod_load(void)
{
#if defined(WITH_TLS) && (defined(HAVE_PQINITOPENSSL) || defined(HAVE_PQINITSSL))
#  ifdef HAVE_PQINITOPENSSL
	PQinitOpenSSL(0, 0);
#  else
	PQinitSSL(0);
#  endif
#endif
	return 0;
}

static void *sql_escape_arg_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, void *uctx)
{
	rlm_sql_t const	*inst = talloc_get_type_abort_const(uctx, rlm_sql_t);
	connection_t	*conn;

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
extern rlm_sql_driver_t rlm_sql_postgresql;
rlm_sql_driver_t rlm_sql_postgresql = {
	.common = {
		.magic				= MODULE_MAGIC_INIT,
		.name				= "sql_postgresql",
		.inst_size			= sizeof(rlm_sql_postgresql_t),
		.onload				= mod_load,
		.config				= driver_config,
		.instantiate			= mod_instantiate
	},
	.flags				= RLM_SQL_RCODE_FLAGS_ALT_QUERY,
	.sql_query_resume		= sql_query_resume,
	.sql_select_query_resume	= sql_query_resume,
	.sql_fields			= sql_fields,
	.sql_fetch_row			= sql_fetch_row,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_free_result,
	.sql_finish_select_query	= sql_free_result,
	.sql_affected_rows		= sql_affected_rows,
	.sql_escape_func		= sql_escape_func,
	.sql_escape_arg_alloc		= sql_escape_arg_alloc,
	.sql_escape_arg_free		= sql_escape_arg_free,
	.trunk_io_funcs = {
		.connection_alloc	= sql_trunk_connection_alloc,
		.connection_notify	= sql_trunk_connection_notify,
		.request_mux		= sql_trunk_request_mux,
		.request_demux		= sql_trunk_request_demux,
		.request_cancel		= sql_request_cancel,
		.request_cancel_mux	= sql_request_cancel_mux,
		.request_fail		= sql_request_fail,
	}
};
