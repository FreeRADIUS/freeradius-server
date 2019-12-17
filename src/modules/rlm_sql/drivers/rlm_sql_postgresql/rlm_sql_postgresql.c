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

#define LOG_PREFIX "rlm_sql_postgresql - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>

#include <sys/stat.h>

#include <libpq-fe.h>
#include <postgres_ext.h>

#include "config.h"
#include "rlm_sql.h"

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
} rlm_sql_postgres_t;

typedef struct {
	PGconn		*db;
	PGresult	*result;
	int		cur_row;
	int		num_fields;
	int		affected_rows;
	char		**row;
} rlm_sql_postgres_conn_t;

static CONF_PARSER driver_config[] = {
	{ FR_CONF_OFFSET("send_application_name", FR_TYPE_BOOL, rlm_sql_postgres_t, send_application_name), .dflt = "yes" },
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
static sql_rcode_t sql_classify_error(rlm_sql_postgres_t *inst, ExecStatusType status, PGresult const *result)
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

	DEBUG2("sqlstate %s matched %s: %s (%s)", error_code,
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

static int _sql_socket_destructor(rlm_sql_postgres_conn_t *conn)
{
	DEBUG2("Socket destructor called, closing socket");

	if (!conn->db) return 0;

	/* PQfinish also frees the memory used by the PGconn structure */
	PQfinish(conn->db);

	return 0;
}

static int CC_HINT(nonnull) sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config,
					    UNUSED fr_time_delta_t timeout)
{
	rlm_sql_postgres_t *inst = config->driver;
	rlm_sql_postgres_conn_t *conn;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_postgres_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	DEBUG2("Connecting using parameters: %s", inst->db_string);
	conn->db = PQconnectdb(inst->db_string);
	if (!conn->db) {
		ERROR("Connection failed: Out of memory");
		return -1;
	}
	if (PQstatus(conn->db) != CONNECTION_OK) {
		ERROR("Connection failed: %s", PQerrorMessage(conn->db));
		PQfinish(conn->db);
		conn->db = NULL;
		return -1;
	}

	DEBUG2("Connected to database '%s' on '%s' server version %i, protocol version %i, backend PID %i ",
	       PQdb(conn->db), PQhost(conn->db), PQserverVersion(conn->db), PQprotocolVersion(conn->db),
	       PQbackendPID(conn->db));

	return 0;
}

static CC_HINT(nonnull) sql_rcode_t sql_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config,
					      char const *query)
{
	rlm_sql_postgres_conn_t	*conn = handle->conn;
	rlm_sql_postgres_t	*inst = config->driver;
	struct timeval		timeout = {config->query_timeout, 0};
	int			sockfd, r;
	fd_set			read_fd;
	PGresult		*tmp_result;
	int			numfields = 0;
	ExecStatusType		status;

	if (!conn->db) {
		ERROR("Socket not connected");
		return RLM_SQL_RECONNECT;
	}

	sockfd = PQsocket(conn->db);
	if (sockfd < 0) {
		ERROR("Unable to obtain socket: %s", PQerrorMessage(conn->db));
		return RLM_SQL_RECONNECT;
	}

	if (!PQsendQuery(conn->db, query)) {
		ERROR("Failed to send query: %s", PQerrorMessage(conn->db));
		return RLM_SQL_RECONNECT;
	}

	/*
	 *  We try to avoid blocking by waiting until the driver indicates that
	 *  the result is ready or our timeout expires
	 */
	while (PQisBusy(conn->db)) {
		FD_ZERO(&read_fd);
		FD_SET(sockfd, &read_fd);
		r = select(sockfd + 1, &read_fd, NULL, NULL, config->query_timeout ? &timeout : NULL);
		if (r == 0) {
			ERROR("Socket read timeout after %d seconds", config->query_timeout);
			return RLM_SQL_RECONNECT;
		}
		if (r < 0) {
			if (errno == EINTR) continue;
			ERROR("Failed in select: %s", fr_syserror(errno));
			return RLM_SQL_RECONNECT;
		}
		if (!PQconsumeInput(conn->db)) {
			ERROR("Failed reading input: %s", PQerrorMessage(conn->db));
			return RLM_SQL_RECONNECT;
		}
	}

	/*
	 *  Returns a PGresult pointer or possibly a null pointer.
	 *  A non-null pointer will generally be returned except in
	 *  out-of-memory conditions or serious errors such as inability
	 *  to send the command to the server. If a null pointer is
	 *  returned, it should be treated like a PGRES_FATAL_ERROR
	 *  result.
	 */
	conn->result = PQgetResult(conn->db);

	/* Discard results for appended queries */
	while ((tmp_result = PQgetResult(conn->db)) != NULL)
		PQclear(tmp_result);

	/*
	 *  As this error COULD be a connection error OR an out-of-memory
	 *  condition return value WILL be wrong SOME of the time
	 *  regardless! Pick your poison...
	 */
	if (!conn->result) {
		ERROR("Failed getting query result: %s", PQerrorMessage(conn->db));
		return RLM_SQL_RECONNECT;
	}

	status = PQresultStatus(conn->result);
	switch (status){
	/*
	 *  Successful completion of a command returning no data.
	 */
	case PGRES_COMMAND_OK:
		/*
		 *  Affected_rows function only returns the number of affected rows of a command
		 *  returning no data...
		 */
		conn->affected_rows = affected_rows(conn->result);
		DEBUG2("query affected rows = %i", conn->affected_rows);
		break;
	/*
	 *  Successful completion of a command returning data (such as a SELECT or SHOW).
	 */
#ifdef HAVE_PGRES_SINGLE_TUPLE
	case PGRES_SINGLE_TUPLE:
#endif
	case PGRES_TUPLES_OK:
		conn->cur_row = 0;
		conn->affected_rows = PQntuples(conn->result);
		numfields = PQnfields(conn->result); /*Check row storing functions..*/
		DEBUG2("query returned rows = %i, fields = %i", conn->affected_rows, numfields);
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
		break;
	}

	return sql_classify_error(inst, status, conn->result);;
}

static sql_rcode_t sql_select_query(rlm_sql_handle_t * handle, rlm_sql_config_t *config, char const *query)
{
	return sql_query(handle, config, query);
}

static sql_rcode_t sql_fields(char const **out[], rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_postgres_conn_t *conn = handle->conn;

	int		fields, i;
	char const	**names;

	fields = PQnfields(conn->result);
	if (fields <= 0) return RLM_SQL_ERROR;

	MEM(names = talloc_array(handle, char const *, fields));

	for (i = 0; i < fields; i++) names[i] = PQfname(conn->result, i);
	*out = names;

	return RLM_SQL_OK;
}

static sql_rcode_t sql_fetch_row(rlm_sql_row_t *out, rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{

	int records, i, len;
	rlm_sql_postgres_conn_t *conn = handle->conn;

	*out = NULL;
	handle->row = NULL;

	if (conn->cur_row >= PQntuples(conn->result)) return RLM_SQL_NO_MORE_ROWS;

	free_result_row(conn);

	records = PQnfields(conn->result);
	conn->num_fields = records;

	if ((PQntuples(conn->result) > 0) && (records > 0)) {
		conn->row = talloc_zero_array(conn, char *, records + 1);
		for (i = 0; i < records; i++) {
			len = PQgetlength(conn->result, conn->cur_row, i);
			conn->row[i] = talloc_array(conn->row, char, len + 1);
			strlcpy(conn->row[i], PQgetvalue(conn->result, conn->cur_row, i), len + 1);
		}
		conn->cur_row++;
		*out = handle->row = conn->row;

		return RLM_SQL_OK;
	}

	return RLM_SQL_NO_MORE_ROWS;
}

static int sql_num_fields(rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_postgres_conn_t *conn = handle->conn;

	conn->affected_rows = PQntuples(conn->result);
	if (conn->result) return PQnfields(conn->result);

	return 0;
}

static sql_rcode_t sql_free_result(rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_postgres_conn_t *conn = handle->conn;

	if (conn->result != NULL) {
		PQclear(conn->result);
		conn->result = NULL;
	}

	free_result_row(conn);

	return 0;
}

/** Retrieves any errors associated with the connection handle
 *
 * @note Caller will free any memory allocated in ctx.
 *
 * @param ctx to allocate temporary error buffers in.
 * @param out Array of sql_log_entrys to fill.
 * @param outlen Length of out array.
 * @param handle rlm_sql connection handle.
 * @param config rlm_sql config.
 * @return number of errors written to the #sql_log_entry_t array.
 */
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_postgres_conn_t	*conn = handle->conn;
	char const		*p, *q;
	size_t			i = 0;

	rad_assert(outlen > 0);

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

static int sql_affected_rows(rlm_sql_handle_t * handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_postgres_conn_t *conn = handle->conn;

	return conn->affected_rows;
}

static size_t sql_escape_func(REQUEST *request, char *out, size_t outlen, char const *in, void *arg)
{
	size_t			inlen, ret;
	rlm_sql_handle_t	*handle = talloc_get_type_abort(arg, rlm_sql_handle_t);
	rlm_sql_postgres_conn_t	*conn = handle->conn;
	int			err;

	/* Check for potential buffer overflow */
	inlen = strlen(in);
	if ((inlen * 2 + 1) > outlen) return 0;
	/* Prevent integer overflow */
	if ((inlen * 2 + 1) <= inlen) return 0;

	ret = PQescapeStringConn(conn->db, out, in, inlen, &err);
	if (err) {
		REDEBUG("Error escaping string \"%s\": %s", in, PQerrorMessage(conn->db));
		return 0;
	}

	return ret;
}

static int mod_instantiate(rlm_sql_config_t const *config, void *instance, CONF_SECTION *conf)
{
	rlm_sql_postgres_t	*inst = instance;
	char 			application_name[NAMEDATALEN];
	char			*db_string;

	/*
	 *	Allow the user to set their own, or disable it
	 */
	if (inst->send_application_name) {
		CONF_SECTION	*cs;
		char const	*name;

		cs = cf_item_to_section(cf_parent(conf));

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

		if (config->query_timeout) {
			db_string = talloc_asprintf_append(db_string, " connect_timeout=%d", config->query_timeout);
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

		if ((config->query_timeout) && !strstr(db_string, "connect_timeout=")) {
			db_string = talloc_asprintf_append(db_string, " connect_timeout=%d", config->query_timeout);
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

		cs = cf_section_find(conf, "states", NULL);
		if (cs && (sql_state_entries_from_cs(inst->states, cs) < 0)) return -1;
	}

	return 0;
}

static int mod_load(void)
{
#if defined(HAVE_OPENSSL_CRYPTO_H) && (defined(HAVE_PQINITOPENSSL) || defined(HAVE_PQINITSSL))
#  ifdef HAVE_PQINITOPENSSL
	PQinitOpenSSL(0, 0);
#  else
	PQinitSSL(0);
#  endif
#endif
	return 0;
}

/* Exported to rlm_sql */
extern rlm_sql_driver_t rlm_sql_postgresql;
rlm_sql_driver_t rlm_sql_postgresql = {
	.name				= "rlm_sql_postgresql",
	.magic				= RLM_MODULE_INIT,
	.flags				= RLM_SQL_RCODE_FLAGS_ALT_QUERY,
	.inst_size			= sizeof(rlm_sql_postgres_t),
	.onload				= mod_load,
	.config				= driver_config,
	.mod_instantiate		= mod_instantiate,
	.sql_socket_init		= sql_socket_init,
	.sql_query			= sql_query,
	.sql_select_query		= sql_select_query,
	.sql_num_fields			= sql_num_fields,
	.sql_fields			= sql_fields,
	.sql_fetch_row			= sql_fetch_row,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_free_result,
	.sql_finish_select_query	= sql_free_result,
	.sql_affected_rows		= sql_affected_rows,
	.sql_escape_func		= sql_escape_func
};
