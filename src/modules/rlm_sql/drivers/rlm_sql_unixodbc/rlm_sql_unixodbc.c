/*
 * sql_unixodbc.c	unixODBC rlm_sql driver
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
 * @copyright 2000 Dmitri Ageev (d_ageev@ortcc.ru)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API

#define LOG_PREFIX "sql - unixodbc"

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <sqltypes.h>
#include "rlm_sql.h"
#include "rlm_sql_trunk.h"

typedef struct {
	SQLHENV			env;		/* Environment handle */
	SQLHDBC			dbc;		/* Database connection handle */
	SQLHSTMT		stmt;		/* Statement handle */
	SQLSMALLINT		colcount;	/* Number of columns in last result */
	rlm_sql_row_t		row;		/* Results row */
	SQLLEN			*ind;		/* Data length / NULL indicators */
	connection_t		*conn;		/* Generic connection structure for this connection */
	rlm_sql_config_t const	*config;	/* SQL instance configuration */
	SQLUSMALLINT		async_mode;	/* What Async mode does this driver support */
	fr_sql_query_t		*query_ctx;	/* Current query running on the connection */
	fr_event_timer_t const	*read_ev;	/* Timer event for polling reading this connection */
	fr_event_timer_t const	*write_ev;	/* Timer event for polling writing this connection */
	uint			select_interval;	/* How frequently this connection gets polled for select queries */
	uint			query_interval;	/* How frequently this connection gets polled for other queries */
	uint			poll_count;	/* How many polls have been done for the current query */
} rlm_sql_unixodbc_conn_t;

USES_APPLE_DEPRECATED_API
#include <sql.h>
#include <sqlext.h>

/** Checks the error code to determine if the connection needs to be re-esttablished
 *
 * @param ret Return code from a failed unixodbc call.
 * @param handle_type Type of ODBC handle
 * @param handle ODBC handle
 * @return
 *	- #RLM_SQL_OK on success.
 *	- #RLM_SQL_ALT_QUERY if alternate queries should be tried.
 *	- #RLM_SQL_RECONNECT if reconnect is needed.
 *	- #RLM_SQL_ERROR on error.
 */
static sql_rcode_t sql_check_error(SQLRETURN ret, SQLSMALLINT handle_type, SQLHANDLE handle)
{
	SQLCHAR		state[6];
	SQLCHAR		error[256];
	SQLINTEGER	errornum = 0;
	SQLSMALLINT	length = 255;
	int		res = RLM_SQL_ERROR;

	if (SQL_SUCCEEDED(ret)) return 0; /* on success, just return 0 */

	error[0] = state[0] = '\0';

	SQLGetDiagRec(handle_type, handle, 1, state, &errornum, error, sizeof(error), &length);

	if (state[0] == '0') {
		switch (state[1]) {
		/* SQLSTATE 01 class contains info and warning messages */
		case '1':
			INFO("%s %s", state, error);
			FALL_THROUGH;
		case '0':		/* SQLSTATE 00 class means success */
			res = RLM_SQL_OK;
			break;

		/* SQLSTATE 08 class describes various connection errors */
		case '8':
			ERROR("SQL down %s %s", state, error);
			res = RLM_SQL_RECONNECT;
			break;

		/* any other SQLSTATE means error */
		default:
			ERROR("%s %s", state, error);
			break;
		}
	} else {
		/* SQLSTATE 23000 is "Integrity constraint violation" - such as duplicate key */
		if (strcmp((char const *)state, "23000") == 0) {
			res = RLM_SQL_ALT_QUERY;
		} else {
			ERROR("%s %s", state, error);
		}
	}

	return res;
}

static void _sql_connection_close(UNUSED fr_event_list_t *el, void *h, UNUSED void *uctx)
{
	rlm_sql_unixodbc_conn_t	*c = talloc_get_type_abort(h, rlm_sql_unixodbc_conn_t);

	if (c->read_ev) fr_event_timer_delete(&c->read_ev);
	if (c->write_ev) fr_event_timer_delete(&c->write_ev);

	if (c->stmt) SQLFreeHandle(SQL_HANDLE_STMT, c->stmt);

	if (c->dbc) {
		SQLDisconnect(c->dbc);
		SQLFreeHandle(SQL_HANDLE_DBC, c->dbc);
	}

	if (c->env) SQLFreeHandle(SQL_HANDLE_ENV, c->env);
	talloc_free(h);
}

static connection_state_t sql_trunk_connection_init_stmt(rlm_sql_unixodbc_conn_t *c)
{
	char		buff[256], verbuf[10];
	SQLRETURN	ret;
	SQLULEN		timeout;

	SQLGetInfo(c->dbc, SQL_DRIVER_NAME, buff, sizeof(buff), NULL);
	SQLGetInfo(c->dbc, SQL_DRIVER_ODBC_VER, verbuf, sizeof(verbuf), NULL);
	SQLGetInfo(c->dbc, SQL_ASYNC_MODE, &c->async_mode, 0, NULL);
	switch(c->async_mode) {
	case SQL_AM_NONE:
		DEBUG2("Using driver %s, ODBC version %s.  Driver does not support async operations", buff, verbuf);
		break;
	case SQL_AM_CONNECTION:
		DEBUG2("Using driver %s, ODBC version %s.  Async operation is set per connection", buff, verbuf);
		ret = SQLSetConnectAttr(c->dbc, SQL_ATTR_ASYNC_ENABLE, (SQLPOINTER)SQL_ASYNC_ENABLE_ON, SQL_IS_UINTEGER);
		sql_check_error(ret, SQL_HANDLE_DBC, c->dbc);
		break;
	case SQL_AM_STATEMENT:
		DEBUG2("Using driver %s, ODBC version %s.  Async operation is set per statement", buff, verbuf);
		break;
	}

	/* Allocate the stmt handle */
	ret = SQLAllocHandle(SQL_HANDLE_STMT, c->dbc, &c->stmt);
	if (sql_check_error(ret, SQL_HANDLE_DBC, c->dbc)) {
		ERROR("Can't allocate the stmt");
		_sql_connection_close(NULL, c, NULL);
		return CONNECTION_STATE_FAILED;
	}
	if (c->async_mode == SQL_AM_STATEMENT) {
		ret = SQLSetStmtAttr(c->stmt, SQL_ATTR_ASYNC_ENABLE, (SQLPOINTER)SQL_ASYNC_ENABLE_ON, 0);
		sql_check_error(ret, SQL_HANDLE_STMT, c->stmt);
	}

	timeout = fr_time_delta_to_sec(c->config->query_timeout);
	SQLSetStmtAttr(c->stmt, SQL_ATTR_QUERY_TIMEOUT, (SQLPOINTER)timeout, SQL_IS_UINTEGER);

	return CONNECTION_STATE_CONNECTED;
}

static void sql_trunk_connection_init_poll(fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	rlm_sql_unixodbc_conn_t	*c = talloc_get_type_abort(uctx, rlm_sql_unixodbc_conn_t);
	SQLRETURN		ret;

	ret = SQLConnect(c->dbc,
			 UNCONST(SQLCHAR *, c->config->sql_server), strlen(c->config->sql_server),
			 UNCONST(SQLCHAR *, c->config->sql_login), strlen(c->config->sql_login),
			 UNCONST(SQLCHAR *, c->config->sql_password), strlen(c->config->sql_password));

	if (ret == SQL_STILL_EXECUTING) {
		if (fr_event_timer_in(c, el, &c->read_ev, fr_time_delta_from_usec(c->query_interval),
				      sql_trunk_connection_init_poll, c) < 0) {
			ERROR("Unable to insert polling event");
			connection_signal_reconnect(c->conn, CONNECTION_FAILED);
		}
		return;
	}

	if (sql_check_error(ret, SQL_HANDLE_DBC, c->dbc)) {
		ERROR("Connection failed");
		connection_signal_reconnect(c->conn, CONNECTION_FAILED);
	}

	if (sql_trunk_connection_init_stmt(c) == CONNECTION_STATE_CONNECTED) connection_signal_connected(c->conn);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static connection_state_t _sql_connection_init(void **h, connection_t *conn, void *uctx)
{
	rlm_sql_t const		*sql = talloc_get_type_abort_const(uctx, rlm_sql_t);
	rlm_sql_config_t const	*config = &sql->config;
	rlm_sql_unixodbc_conn_t *c;
	SQLRETURN		ret;
	SQLULEN			timeout = fr_time_delta_to_sec(sql->config.trunk_conf.conn_conf->connection_timeout);

	MEM(c = talloc_zero(conn, rlm_sql_unixodbc_conn_t));
	*c = (rlm_sql_unixodbc_conn_t) {
		.conn = conn,
		.config = config,
		.select_interval = 1000,	/* Default starting poll interval - 1ms*/
		.query_interval = 1000,
	};

	/* Allocate environment handle and register version */
	ret = SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &c->env);
	if (ret == SQL_ERROR) {
		ERROR("Can't allocate environment handle");
	error:
		_sql_connection_close(NULL, c, NULL);
		return CONNECTION_STATE_FAILED;
	}

	ret = SQLSetEnvAttr(c->env, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3_80, 0);
	if (sql_check_error(ret, SQL_HANDLE_ENV, c->env)) {
		ERROR("Can't register ODBC version");
		goto error;
	}

	/* Allocate connection handle */
	ret = SQLAllocHandle(SQL_HANDLE_DBC, c->env, &c->dbc);
	if (sql_check_error(ret, SQL_HANDLE_ENV, c->env)) {
		ERROR("Can't allocate connection handle");
		goto error;
	}

	/*
	 *	Set the login / connection timeout
	 *
	 * 	Note SQLSetConnectionAttr and SQLSetStmtAttr have an insane parameter passing
	 *	model.  The 3rd parameter can be an integer, or a pointer to a string
	 *	so integers get cast to pointers to match the function signature.
	 */
	SQLSetConnectAttr(c->dbc, SQL_ATTR_LOGIN_TIMEOUT, (SQLPOINTER)timeout, SQL_IS_UINTEGER);
	SQLSetConnectAttr(c->dbc, SQL_ATTR_CONNECTION_TIMEOUT, (SQLPOINTER)timeout, SQL_IS_UINTEGER);

	/* Set the connection handle to Async */
	SQLSetConnectAttr(c->dbc, SQL_ATTR_ASYNC_DBC_FUNCTIONS_ENABLE, (SQLPOINTER)SQL_ASYNC_DBC_ENABLE_ON, SQL_IS_UINTEGER);

	/* Connect to the datasource */
	ret = SQLConnect(c->dbc,
			 UNCONST(SQLCHAR *, config->sql_server), strlen(config->sql_server),
			 UNCONST(SQLCHAR *, config->sql_login), strlen(config->sql_login),
			 UNCONST(SQLCHAR *, config->sql_password), strlen(config->sql_password));

	if (ret == SQL_STILL_EXECUTING) {
		if (fr_event_timer_in(c, conn->el, &c->read_ev, fr_time_delta_from_usec(c->query_interval),
				      sql_trunk_connection_init_poll, c) < 0) {
			ERROR("Unable to insert polling event");
			goto error;
		}
		*h = c;
		return CONNECTION_STATE_CONNECTING;
	}

	if (sql_check_error(ret, SQL_HANDLE_DBC, c->dbc)) {
		ERROR("Connection failed");
		goto error;
	}

	*h = c;
	return sql_trunk_connection_init_stmt(c);
}

SQL_TRUNK_CONNECTION_ALLOC

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static void sql_trunk_request_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn, connection_t *conn, UNUSED void *uctx)
{
	rlm_sql_unixodbc_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_unixodbc_conn_t);
	request_t		*request;
	trunk_request_t		*treq;
	fr_sql_query_t		*query_ctx;
	SQLRETURN		ret;

	if (trunk_connection_pop_request(&treq, tconn) != 0) return;
	if (!treq) return;

	query_ctx = talloc_get_type_abort(treq->preq, fr_sql_query_t);
	request = query_ctx->request;

	switch(query_ctx->status) {
	case SQL_QUERY_PREPARED:
		ROPTIONAL(RDEBUG2, DEBUG2, "Executing query: %s", query_ctx->query_str);
		ret = SQLExecDirect(sql_conn->stmt, UNCONST(SQLCHAR *, query_ctx->query_str), strlen(query_ctx->query_str));
		query_ctx->tconn = tconn;

		if (ret == SQL_STILL_EXECUTING) {
			ROPTIONAL(RDEBUG3, DEBUG3, "Awaiting response");
			query_ctx->status = SQL_QUERY_SUBMITTED;
			sql_conn->query_ctx = query_ctx;
			sql_conn->poll_count = 0;
			trunk_request_signal_sent(treq);
			return;
		}

		query_ctx->rcode = sql_check_error(ret, SQL_HANDLE_STMT, sql_conn->stmt);
		switch(query_ctx->rcode) {
		case RLM_SQL_OK:
		case RLM_SQL_ALT_QUERY:
			break;

		default:
			query_ctx->status = SQL_QUERY_FAILED;
			trunk_request_signal_fail(treq);
			if (query_ctx->rcode == RLM_SQL_RECONNECT) connection_signal_reconnect(conn, CONNECTION_FAILED);
			return;
		}
		query_ctx->status = SQL_QUERY_RETURNED;
		break;

	default:
		return;
	}

	ROPTIONAL(RDEBUG3, DEBUG3, "Got immediate response");
	trunk_request_signal_reapable(treq);
	if (request) unlang_interpret_mark_runnable(request);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static void sql_request_cancel(connection_t *conn, void *preq, trunk_cancel_reason_t reason,
				UNUSED void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(preq, fr_sql_query_t);
	rlm_sql_unixodbc_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_unixodbc_conn_t);

	if (!query_ctx->treq) return;
	if (reason != TRUNK_CANCEL_REASON_SIGNAL) return;
	if (sql_conn->query_ctx == query_ctx) sql_conn->query_ctx = NULL;
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static void sql_request_cancel_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn,
				   connection_t *conn, UNUSED void *uctx)
{
	trunk_request_t		*treq;
	rlm_sql_unixodbc_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_unixodbc_conn_t);
	SQLRETURN		ret;
	fr_sql_query_t		*query_ctx;

	if ((trunk_connection_pop_cancellation(&treq, tconn)) != 0) return;
	if (!treq) return;

	query_ctx = talloc_get_type_abort(treq->preq, fr_sql_query_t);
	ret = SQLCancel(sql_conn->stmt);
	query_ctx->status = SQL_QUERY_CANCELLED;
	if (ret == SQL_STILL_EXECUTING) {
		trunk_request_signal_cancel_sent(treq);
		return;
	}
	trunk_request_signal_cancel_complete(treq);
}

static void sql_trunk_connection_read_poll(fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	rlm_sql_unixodbc_conn_t	*c = talloc_get_type_abort(uctx, rlm_sql_unixodbc_conn_t);
	fr_sql_query_t		*query_ctx = c->query_ctx;
	SQLRETURN		ret;
	trunk_request_t		*treq = query_ctx->treq;
	request_t		*request = query_ctx->request;

	switch (query_ctx->status) {
	case SQL_QUERY_SUBMITTED:
		ret = SQLExecDirect(c->stmt, UNCONST(SQLCHAR *, query_ctx->query_str), strlen(query_ctx->query_str));
		c->poll_count++;
		/* Back off the poll interval, up to half the query timeout */
		if (c->poll_count > 2) {
			if (query_ctx->type == SQL_QUERY_SELECT) {
				if (c->select_interval < fr_time_delta_to_usec(c->config->query_timeout)/2) c->select_interval += 100;
			} else {
				if (c->query_interval < fr_time_delta_to_usec(c->config->query_timeout)/2) c->query_interval += 100;
			}
		}
		if (ret == SQL_STILL_EXECUTING) {
			ROPTIONAL(RDEBUG3, DEBUG3, "Still awaiting response");
			if (fr_event_timer_in(c, el, &c->read_ev,
					      fr_time_delta_from_usec(query_ctx->type == SQL_QUERY_SELECT ? c->select_interval : c->query_interval),
					      sql_trunk_connection_read_poll, c) < 0) {
				ERROR("Unable to insert polling event");
			}
			return;
		}

		query_ctx->rcode = sql_check_error(ret, SQL_HANDLE_STMT, c->stmt);
		switch(query_ctx->rcode) {
		case RLM_SQL_OK:
		case RLM_SQL_ALT_QUERY:
			/* If we only polled once, reduce the interval*/
			if (c->poll_count == 1) {
				if (query_ctx->type == SQL_QUERY_SELECT) {
					c->select_interval /= 2;
				} else {
					c->query_interval /= 2;
				}
			}
			break;

		default:
			query_ctx->status = SQL_QUERY_FAILED;
			trunk_request_signal_fail(treq);
			if (query_ctx->rcode == RLM_SQL_RECONNECT) connection_signal_reconnect(c->conn, CONNECTION_FAILED);
			return;
		}
		break;

	case SQL_QUERY_CANCELLED:
		ret = SQLCancel(c->stmt);
		if (ret == SQL_STILL_EXECUTING) {
			ROPTIONAL(RDEBUG3, DEBUG3, "Still awaiting response");
			if (fr_event_timer_in(c, el, &c->read_ev, fr_time_delta_from_usec(query_ctx->type == SQL_QUERY_SELECT ? c->select_interval : c->query_interval),
					      sql_trunk_connection_read_poll, c) < 0) {
				ERROR("Unable to insert polling event");
			}
			return;
		}
		trunk_request_signal_cancel_complete(treq);
		return;

	default:
		return;
	}

	if (request) unlang_interpret_mark_runnable(request);
}

static void sql_trunk_connection_write_poll(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	trunk_connection_t	*tconn = talloc_get_type_abort(uctx, trunk_connection_t);

	trunk_connection_signal_writable(tconn);
}

/*
 *	UnixODBC doesn't support event driven async, so in this case
 *	we have to resort to polling.
 *
 *	This "notify" callback sets up the appropriate polling events.
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static void sql_trunk_connection_notify(UNUSED trunk_connection_t *tconn, connection_t *conn, UNUSED fr_event_list_t *el,
					trunk_connection_event_t notify_on, UNUSED void *uctx)
{
	rlm_sql_unixodbc_conn_t	*c = talloc_get_type_abort(conn->h, rlm_sql_unixodbc_conn_t);
	fr_sql_query_t		*query_ctx = c->query_ctx;
	uint			poll_interval = (query_ctx && query_ctx->type != SQL_QUERY_SELECT) ? c->query_interval : c->select_interval;
	switch (notify_on) {
	case TRUNK_CONN_EVENT_NONE:
		if (c->read_ev) fr_event_timer_delete(&c->read_ev);
		if (c->write_ev) fr_event_timer_delete(&c->write_ev);
		return;

	case TRUNK_CONN_EVENT_BOTH:
	case TRUNK_CONN_EVENT_READ:
		if (c->query_ctx) {
			if (fr_event_timer_in(c, el, &c->read_ev, fr_time_delta_from_usec(poll_interval),
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

SQL_QUERY_FAIL
SQL_QUERY_RESUME

static unlang_action_t sql_select_query_resume(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_unixodbc_conn_t *conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_unixodbc_conn_t);
	SQLINTEGER		i;
	SQLLEN			len;
	SQLRETURN		ret = SQL_STILL_EXECUTING;

	if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL;

	while (ret == SQL_STILL_EXECUTING) {
		ret = SQLNumResultCols(conn->stmt, &conn->colcount);
	}
	if (sql_check_error(ret, SQL_HANDLE_STMT, conn->stmt)) {
		query_ctx->rcode = RLM_SQL_ERROR;
		RETURN_MODULE_FAIL;
	}

	/* Reserving memory for result */
	conn->row = talloc_zero_array(conn, char *, conn->colcount + 1); /* Space for pointers */
	conn->ind = talloc_zero_array(conn, SQLLEN, conn->colcount); /* Space for indicators */

	for (i = 1; i <= conn->colcount; i++) {
		len = 0;
		/* SQLColAttribute can in theory run Async */
		while (SQLColAttribute(conn->stmt, (SQLUSMALLINT) i, SQL_DESC_LENGTH, NULL, 0, NULL, &len) == SQL_STILL_EXECUTING);
		conn->row[i - 1] = talloc_array(conn->row, char, ++len);
		SQLBindCol(conn->stmt, i, SQL_C_CHAR, (SQLCHAR *)conn->row[i - 1], len, &conn->ind[i - 1]);
	}

	RETURN_MODULE_OK;
}

static sql_rcode_t sql_fields(char const **out[], fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_unixodbc_conn_t *conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_unixodbc_conn_t);
	SQLSMALLINT		len, i;
	SQLRETURN		ret;
	char const		**names;
	char			field[128];

	if (conn->colcount == 0) return RLM_SQL_ERROR;

	MEM(names = talloc_array(query_ctx, char const *, conn->colcount));

	for (i = 0; i < conn->colcount; i++) {
		char *p;
		ret = SQL_STILL_EXECUTING;
		while (ret == SQL_STILL_EXECUTING) {
			ret = SQLColAttribute(conn->stmt, i + 1, SQL_DESC_NAME,
					      field, sizeof(field), &len, NULL);
		}
		switch (ret) {
		case SQL_INVALID_HANDLE:
		case SQL_ERROR:
			ERROR("Failed retrieving field name at index %i", i);
			sql_check_error(ret, SQL_HANDLE_STMT, conn->stmt);
			talloc_free(names);
			return RLM_SQL_ERROR;

		default:
			break;
		}

		MEM(p = talloc_array(names, char, (size_t)len + 1));
		strlcpy(p, field, (size_t)len + 1);
		names[i] = p;
	}
	*out = names;

	return RLM_SQL_OK;
}

static unlang_action_t sql_fetch_row(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_unixodbc_conn_t *conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_unixodbc_conn_t);
	SQLRETURN		ret = SQL_STILL_EXECUTING;
	SQLINTEGER		i;

	query_ctx->row = NULL;

	while (ret == SQL_STILL_EXECUTING) {
		ret = SQLFetch(conn->stmt);
	}
	if (ret == SQL_NO_DATA_FOUND) {
		query_ctx->rcode = RLM_SQL_NO_MORE_ROWS;
		RETURN_MODULE_OK;
	}

	query_ctx->rcode = sql_check_error(ret, SQL_HANDLE_STMT, conn->stmt);
	if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL;

	/*
	 *	If the field is NULL, then SQLFetch doesn't touch pointer, so set it here
	 */
	for (i = 0; i < conn->colcount; i++) {
		if (conn->ind[i] == SQL_NULL_DATA) conn->row[i] = NULL;
	}

	query_ctx->row = conn->row;

	query_ctx->rcode = RLM_SQL_OK;
	RETURN_MODULE_OK;
}

static sql_rcode_t sql_free_result(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_unixodbc_conn_t *conn = query_ctx->tconn->conn->h;

	TALLOC_FREE(conn->row);
	TALLOC_FREE(conn->ind);
	conn->colcount = 0;

	return RLM_SQL_OK;
}

static sql_rcode_t sql_finish_query(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_unixodbc_conn_t *conn;

	/*
	 *	If the query is not in a state which would return results, then do nothing.
	 */
	if (query_ctx->treq && !(query_ctx->treq->state &
	    (TRUNK_REQUEST_STATE_SENT | TRUNK_REQUEST_STATE_REAPABLE | TRUNK_REQUEST_STATE_COMPLETE))) return RLM_SQL_OK;

	/*
	 *	If the connection doesn't exist there's nothing to do
	 */
	if (!query_ctx->tconn || !query_ctx->tconn->conn || !query_ctx->tconn->conn->h) return RLM_SQL_ERROR;

	conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_unixodbc_conn_t);

	TALLOC_FREE(conn->row);
	conn->colcount = 0;
	conn->query_ctx = NULL;

	/*
	 *	SQL_CLOSE - The cursor (if any) associated with the statement
	 *	handle (StatementHandle) is closed and all pending results are
	 *	discarded. The application can reopen the cursor by calling
	 *	SQLExecute() with the same or different values in the
	 *	application variables (if any) that are bound to StatementHandle.
	 *	If no cursor has been associated with the statement handle,
	 *	this option has no effect (no warning or error is generated).
	 *
	 *	So, this call does NOT free the statement at all, it merely
	 *	resets it for the next call. This is terrible terrible naming.
	 */
	SQLFreeStmt(conn->stmt, SQL_CLOSE);

	return RLM_SQL_OK;
}

/** Retrieves any errors associated with the query context
 *
 * @note Caller will free any memory allocated in ctx.
 *
 * @param ctx to allocate temporary error buffers in.
 * @param out Array of #sql_log_entry_t to fill.
 * @param outlen Length of out array.
 * @param query_ctx Query context to retrieve error for.
 * @return number of errors written to the #sql_log_entry_t array.
 */
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], NDEBUG_UNUSED size_t outlen,
			fr_sql_query_t *query_ctx)
{
	rlm_sql_unixodbc_conn_t	*conn = query_ctx->tconn->conn->h;
	SQLCHAR			state[256];
	SQLCHAR			errbuff[256];
	SQLINTEGER		errnum = 0;
	SQLSMALLINT		length = 255;
	size_t			i = 0;

	fr_assert(outlen > 2);

	/*
	 *	Depending on which handles exist at the time of calling there
	 *	may be 1, 2 or 3 handles to check errors on.
	 */
	errbuff[0] = state[0] = '\0';
	SQLGetDiagRec(SQL_HANDLE_ENV, conn->env, 1, state, &errnum, errbuff, sizeof(errbuff), &length);
	if (errnum != 0) {
		out[i].type = L_ERR;
		out[i].msg = talloc_typed_asprintf(ctx, "%s: %s", state, errbuff);
		i++;
	}
	if (conn->dbc == SQL_NULL_HANDLE) return i;

	SQLGetDiagRec(SQL_HANDLE_DBC, conn->dbc, 1, state, &errnum, errbuff, sizeof(errbuff), &length);
	if (errnum != 0) {
		out[i].type = L_ERR;
		out[i].msg = talloc_typed_asprintf(ctx, "%s: %s", state, errbuff);
		i++;
	}
	if (conn->stmt == SQL_NULL_HANDLE) return i;

	SQLGetDiagRec(SQL_HANDLE_STMT, conn->stmt, 1, state, &errnum, errbuff, sizeof(errbuff), &length);
	if (errnum != 0) {
		out[i].type = L_ERR;
		out[i].msg = talloc_typed_asprintf(ctx, "%s: %s", state, errbuff);
		i++;
	}

	return i;
}

/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: Return the number of rows affected by the query (update,
 *	       or insert)
 *
 *************************************************************************/
static int sql_affected_rows(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_unixodbc_conn_t *conn = query_ctx->tconn->conn->h;
	SQLRETURN		ret;
	SQLLEN			affected_rows;

	ret = SQLRowCount(conn->stmt, &affected_rows);
	if (sql_check_error(ret, SQL_HANDLE_STMT, conn->stmt)) return -1;

	return affected_rows;
}


/* Exported to rlm_sql */
extern rlm_sql_driver_t rlm_sql_unixodbc;
rlm_sql_driver_t rlm_sql_unixodbc = {
	.common = {
		.magic				= MODULE_MAGIC_INIT,
		.name				= "sql_unixodbc"
	},
	.flags				= RLM_SQL_RCODE_FLAGS_ALT_QUERY,
	.sql_query_resume		= sql_query_resume,
	.sql_select_query_resume	= sql_select_query_resume,
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
		.request_cancel_mux	= sql_request_cancel_mux,
		.request_cancel		= sql_request_cancel,
		.request_fail		= sql_request_fail,
	}
};
