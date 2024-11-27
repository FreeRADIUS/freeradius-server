/*
 * sql_oracle.c	Oracle (OCI) routines for rlm_sql
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
 * @copyright 2019 Robert Biktimirov (pobept@gmail.com)
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 David Kerry (davidk@snti.com)
 */

RCSID("$Id$")

#define LOG_PREFIX "sql - oracle"

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <sys/stat.h>

/*
 *	There are typos in the Oracle Instaclient where the definition controlling prototype
 *	format is _STDC_ (not __STDC__).
 *
 *	There are still cases where the oracle headers do not declare ANSI C function types
 *	but this at least cuts down the errors.
 *
 *	-Wno-strict-prototypes does the rest.
 */
DIAG_OFF(unused-macros)
#if defined(__STDC__) && __STDC__
#  define _STDC_
#endif

#include <oci.h>
DIAG_ON(unused-macros)

#include "rlm_sql.h"
#include "rlm_sql_trunk.h"

typedef struct {
	OCIEnv		*env;			//!< Environment handle
	uint32_t	stmt_cache_size;	//!< Statement cache size
} rlm_sql_oracle_t;

typedef struct {
	OCIStmt			*query;		//!< Query handle
	OCIError		*error; 	//!< Error handle
	OCIServer		*srv;		//!< Server handle
	OCISvcCtx		*ctx;		//!< Service handle
	OCISession		*sess;		//!< Session handle
	sb2			*ind;		//!< Indicators regarding contents of the results row.
	rlm_sql_row_t		row;		//!< Results row
	int			col_count;	//!< Number of columns associated with the result set
	connection_t		*conn;		//!< Generic connection structure for this connection.
	rlm_sql_config_t const	*config;	//!< SQL instance configuration.
	fr_sql_query_t		*query_ctx;	//!< Current request running on the connection.
	fr_event_timer_t const	*read_ev;	//!< Timer event for polling reading this connection
	fr_event_timer_t const	*write_ev;	//!< Timer event for polling writing this connection
	uint			select_interval;	//!< How frequently this connection gets polled for select queries.
	uint			query_interval;	//!< How frequently this connection gets polled for other queries.
	uint			poll_count;	//!< How many polls have been done for the current query.
} rlm_sql_oracle_conn_t;

static const conf_parser_t driver_config[] = {
	{ FR_CONF_OFFSET("stmt_cache_size", rlm_sql_oracle_t, stmt_cache_size), .dflt = "32" },
	CONF_PARSER_TERMINATOR
};

#define	MAX_DATASTR_LEN	64

/** Write the last Oracle error out to a buffer
 *
 * @param out Where to write the error (should be at least 512 bytes).
 * @param outlen The length of the error buffer.
 * @param conn Oracle connection.
 * @return
 *	- Oracle error code on success.
 *	- -1 if there was no error.
 */
static int sql_snprint_error(char *out, size_t outlen, rlm_sql_oracle_conn_t *conn)
{
	sb4	errcode = 0;

	fr_assert(conn);

	out[0] = '\0';

	OCIErrorGet((dvoid *) conn->error, 1, (OraText *) NULL, &errcode, (OraText *) out,
		    outlen, OCI_HTYPE_ERROR);
	if (!errcode) return -1;

	return errcode;
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
static size_t sql_error(TALLOC_CTX *ctx, sql_log_entry_t out[], NDEBUG_UNUSED size_t outlen,
		        fr_sql_query_t *query_ctx)
{
	char errbuff[512];
	int ret;
	rlm_sql_oracle_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_oracle_conn_t);

	fr_assert(outlen > 0);

	ret = sql_snprint_error(errbuff, sizeof(errbuff), conn);
	if (ret < 0) return 0;

	out[0].type = L_ERR;
	out[0].msg = talloc_strdup(ctx, errbuff);

	return 1;
}

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_sql_oracle_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_sql_oracle_t);

	if (inst->env) OCIHandleFree((dvoid *)inst->env, OCI_HTYPE_ENV);

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_sql_oracle_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_sql_oracle_t);

	/*
	 *	Initialises the oracle environment
	 */
	if (OCIEnvCreate(&inst->env, OCI_DEFAULT | OCI_THREADED, NULL, NULL, NULL, NULL, 0, NULL)) {
		ERROR("Couldn't init Oracle OCI environment (OCIEnvCreate())");
		return -1;
	}

	return 0;
}

static sql_rcode_t sql_check_reconnect(rlm_sql_oracle_conn_t *conn)
{
	char errbuff[512];

	if (sql_snprint_error(errbuff, sizeof(errbuff), conn) < 0) return -1;

	if (strstr(errbuff, "ORA-03113") || strstr(errbuff, "ORA-03114")) {
		ERROR("OCI_SERVER_NOT_CONNECTED");
		return RLM_SQL_RECONNECT;
	}

	return RLM_SQL_ERROR;
}

static void _sql_connection_close(UNUSED fr_event_list_t *el, void *h, UNUSED void *uctx)
{
	rlm_sql_oracle_conn_t *conn = talloc_get_type_abort(h, rlm_sql_oracle_conn_t);

	if (conn->sess) {
		OCISessionEnd(conn->ctx, conn->error, conn->sess, OCI_DEFAULT);
		OCIHandleFree((dvoid *)conn->sess, OCI_HTYPE_SESSION);
	}
	if (conn->ctx) OCIHandleFree((dvoid *)conn->ctx, OCI_HTYPE_SVCCTX);
	if (conn->srv) {
		OCIServerDetach(conn->srv, conn->error, OCI_DEFAULT);
		OCIHandleFree((dvoid *)conn->srv, OCI_HTYPE_SERVER);
	}
	if (conn->error) OCIHandleFree((dvoid *)conn->error, OCI_HTYPE_ERROR);

	talloc_free(h);
}

#define ORACLE_ERROR(_message) \
	sql_snprint_error(errbuff, sizeof(errbuff), c); \
	ERROR(_message ": %s", errbuff); \
	return CONNECTION_STATE_FAILED

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static connection_state_t _sql_connection_init(void **h, connection_t *conn, void *uctx)
{
	rlm_sql_t const		*sql = talloc_get_type_abort_const(uctx, rlm_sql_t);
	rlm_sql_oracle_t	*inst = talloc_get_type_abort(sql->driver_submodule->data, rlm_sql_oracle_t);
	rlm_sql_oracle_conn_t	*c;
	char			errbuff[512];
	OraText 		*sql_password = NULL;
	OraText 		*sql_login = NULL;

	MEM(c = talloc_zero(conn, rlm_sql_oracle_conn_t));
	*c = (rlm_sql_oracle_conn_t) {
		.conn = conn,
		.config = &sql->config,
		.select_interval = 1000,	/* Default starting poll interval - 1ms */
		.query_interval = 1000,
	};

	/*
	 *	Although there are simpler methods to start a connection using a connection
	 *	pool, since we need to set an option on the server handle, to enable
	 *	non-blocking mode, we have to follow this overly complicated sequence of
	 *	handle creation.
	 */

	/*
	 *	Allocate an error handle
	 */
	if (OCIHandleAlloc((dvoid *)inst->env, (dvoid **)&c->error, OCI_HTYPE_ERROR, 0, NULL) != OCI_SUCCESS) {
		ERROR("Couldn't init Oracle ERROR handle (OCIHandleAlloc())");
		return CONNECTION_STATE_FAILED;
	}

	/*
	 *	Allocate a server handle and attache to a connection from the pool
	 */
	if (OCIHandleAlloc((dvoid *)inst->env, (dvoid **)&c->srv, (ub4)OCI_HTYPE_SERVER, 0, NULL) != OCI_SUCCESS) {
		ERROR("Couldn't allocate Oracle SERVER handle");
		return CONNECTION_STATE_FAILED;
	}
	if (OCIServerAttach(c->srv, c->error, (CONST OraText *)sql->config.sql_db, strlen(sql->config.sql_db), (ub4)OCI_DEFAULT) != OCI_SUCCESS) {
		ORACLE_ERROR("Failed to attach");
	}

	/*
	 *	Allocate the service handle (which queries are run on) and associate it with the server
	 */
	if (OCIHandleAlloc((dvoid *)inst->env, (dvoid **)&c->ctx, OCI_HTYPE_SVCCTX, 0, NULL) != OCI_SUCCESS) {
		ERROR("Couldn't allocate Oracle SERVICE handle");
		return CONNECTION_STATE_FAILED;
	}
	if (OCIAttrSet((dvoid *)c->ctx, OCI_HTYPE_SVCCTX, (dvoid *)c->srv, 0, OCI_ATTR_SERVER, c->error) != OCI_SUCCESS) {
		ORACLE_ERROR("Failed to link service and server handles");
	}


	if (OCIHandleAlloc((dvoid *)inst->env, (dvoid **)&c->sess, OCI_HTYPE_SESSION, 0, NULL) != OCI_SUCCESS) {
		ERROR("Couldn't allocate Oracle SESSION handle");
		return CONNECTION_STATE_FAILED;
	}

	/*
	 *	We need to fix const issues between 'const char *' vs 'unsigned char *'
	 */
	memcpy(&sql_login, &c->config->sql_login, sizeof(sql_login));
	memcpy(&sql_password, &c->config->sql_password, sizeof(sql_password));
	if (OCIAttrSet((dvoid *)c->sess, OCI_HTYPE_SESSION, sql_login, strlen(c->config->sql_login),
		       OCI_ATTR_USERNAME, c->error) != OCI_SUCCESS) {
		ORACLE_ERROR("Failed to set username");
	}
	if (OCIAttrSet((dvoid *)c->sess, OCI_HTYPE_SESSION, sql_password, strlen(c->config->sql_password),
		       OCI_ATTR_PASSWORD, c->error) != OCI_SUCCESS) {
		ORACLE_ERROR("Failed to set password");
	}

 	if (OCISessionBegin((dvoid *)c->ctx, c->error, c->sess, OCI_CRED_RDBMS, OCI_STMT_CACHE) != OCI_SUCCESS) {
		ORACLE_ERROR("Failed to start session");
	}

	if (OCIAttrSet((dvoid *)c->ctx, OCI_HTYPE_SVCCTX, (dvoid *)c->sess, 0, OCI_ATTR_SESSION, c->error) != OCI_SUCCESS) {
		ORACLE_ERROR("Failed to link service and session handles");
	}

	if (OCIAttrSet((dvoid *)c->ctx, OCI_HTYPE_SVCCTX, (dvoid *)&inst->stmt_cache_size, 0,
		       OCI_ATTR_STMTCACHESIZE, c->error) != OCI_SUCCESS) {
		ORACLE_ERROR("Failed to set statement cache size");
	}

	/*
	 *	Set the server to be non-blocking if we can.
	 */
	if (OCIAttrSet((dvoid *)c->srv, OCI_HTYPE_SERVER, (dvoid *)0, 0, OCI_ATTR_NONBLOCKING_MODE, c->error) != OCI_SUCCESS) {
		sql_snprint_error(errbuff, sizeof(errbuff), c);
		WARN("Cound not set non-blocking mode: %s", errbuff);
  	}

	*h = c;

	return CONNECTION_STATE_CONNECTED;
}

SQL_TRUNK_CONNECTION_ALLOC

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static void sql_trunk_request_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn, connection_t *conn, UNUSED void *uctx)
{
	rlm_sql_oracle_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_oracle_conn_t);
	request_t		*request;
	trunk_request_t		*treq;
	fr_sql_query_t		*query_ctx;
	sword			ret;
	char			errbuff[512];

	if (trunk_connection_pop_request(&treq, tconn) != 0) return;
	if (!treq) return;

	query_ctx = talloc_get_type_abort(treq->preq, fr_sql_query_t);
	request = query_ctx->request;

	switch(query_ctx->status) {
	case SQL_QUERY_PREPARED:
		ROPTIONAL(RDEBUG2, DEBUG2, "Executing query: %s", query_ctx->query_str);
		if (OCIStmtPrepare2(sql_conn->ctx, &sql_conn->query, sql_conn->error,
				    (const OraText *)query_ctx->query_str, strlen(query_ctx->query_str),
	        		    NULL, 0, OCI_NTV_SYNTAX, OCI_DEFAULT)) {
			sql_snprint_error(errbuff, sizeof(errbuff), sql_conn);
			ERROR("Failed to prepare query: %s", errbuff);
			trunk_request_signal_fail(treq);
			return;
		}

		switch (query_ctx->type) {
		case SQL_QUERY_SELECT:
			ret = OCIStmtExecute(sql_conn->ctx, sql_conn->query, sql_conn->error, 0, 0, NULL, NULL, OCI_DEFAULT);
			break;

		default:
			ret = OCIStmtExecute(sql_conn->ctx, sql_conn->query, sql_conn->error, 1, 0, NULL, NULL,
					     OCI_COMMIT_ON_SUCCESS);
			break;
		}
		query_ctx->tconn = tconn;

		switch (ret) {
		case OCI_STILL_EXECUTING:
			ROPTIONAL(RDEBUG3, DEBUG3, "Awaiting response");
			query_ctx->status = SQL_QUERY_SUBMITTED;
			sql_conn->query_ctx = query_ctx;
			sql_conn->poll_count = 0;
			trunk_request_signal_sent(treq);
			return;

		case OCI_SUCCESS:
			query_ctx->rcode = RLM_SQL_OK;
			break;

		case OCI_NO_DATA:
			query_ctx->rcode = RLM_SQL_NO_MORE_ROWS;
			break;

		default:
			/*
			 *	Error code 1 is unique contraint violated
			 */
			if (sql_snprint_error(errbuff, sizeof(errbuff), sql_conn) == 1) {
				query_ctx->rcode = RLM_SQL_ALT_QUERY;
				break;
			}
			ERROR("SQL query failed: %s", errbuff);
			trunk_request_signal_fail(treq);
			if (sql_check_reconnect(sql_conn) == RLM_SQL_RECONNECT) {
				connection_signal_reconnect(sql_conn->conn, CONNECTION_FAILED);
			}
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
	rlm_sql_oracle_conn_t	*sql_conn= talloc_get_type_abort(conn->h, rlm_sql_oracle_conn_t);

	if (!query_ctx->treq) return;
	if (reason != TRUNK_CANCEL_REASON_SIGNAL) return;
	if (sql_conn->query_ctx == query_ctx) sql_conn->query_ctx = NULL;
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static void sql_request_cancel_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn,
				   connection_t *conn, UNUSED void *uctx)
{
	trunk_request_t		*treq;
	rlm_sql_oracle_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_oracle_conn_t);
	sword			status;

	if ((trunk_connection_pop_cancellation(&treq, tconn)) != 0) return;
	if (!treq) return;

	/*
	 *	Oracle cancels non-blocking operations with this pair of calls
	 *	They operate on the service context handle, and since only one
	 *	query will be on a connection at a time, that is what will be cancelled.
	 *
	 *	It's not clear from the documentation as to whether this can return
	 *	OCI_STILL_EXECUTING - so we allow for that.
	 */
	status = OCIBreak(sql_conn->ctx, sql_conn->error);
	switch (status) {
	case OCI_STILL_EXECUTING:
		trunk_request_signal_cancel_sent(treq);
		return;

	case OCI_SUCCESS:
		break;

	default:
	{
		char	errbuff[512];
		sql_snprint_error(errbuff, sizeof(errbuff), sql_conn);
		ERROR("Failed cancelling query: %s", errbuff);
	}
	}
	OCIReset(sql_conn->ctx, sql_conn->error) ;

	trunk_request_signal_cancel_complete(treq);
}

static void sql_trunk_connection_read_poll(fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	rlm_sql_oracle_conn_t	*c = talloc_get_type_abort(uctx, rlm_sql_oracle_conn_t);
	fr_sql_query_t		*query_ctx = c->query_ctx;
	trunk_request_t		*treq = query_ctx->treq;
	request_t		*request = query_ctx->request;
	sword			ret = OCI_SUCCESS;

	switch (query_ctx->status) {
	case SQL_QUERY_SUBMITTED:
		switch (query_ctx->type) {
		case SQL_QUERY_SELECT:
			ret = OCIStmtExecute(c->ctx, c->query, c->error, 0, 0, NULL, NULL, OCI_DEFAULT);
			break;

		default:
			ret = OCIStmtExecute(c->ctx, c->query, c->error, 1, 0, NULL, NULL, OCI_COMMIT_ON_SUCCESS);
			break;
		}
		c->poll_count++;
		/* Back off the poll interval, up to half the query timeout */
		if (c->poll_count > 2) {
			if (query_ctx->type == SQL_QUERY_SELECT) {
				if (c->select_interval < fr_time_delta_to_usec(c->config->query_timeout)/2) c->select_interval += 100;
			} else {
				if (c->query_interval < fr_time_delta_to_usec(c->config->query_timeout)/2) c->query_interval += 100;
			}
		}

		switch (ret) {
		case OCI_STILL_EXECUTING:
			ROPTIONAL(RDEBUG3, DEBUG3, "Still awaiting response");
			if (fr_event_timer_in(c, el, &c->read_ev,
					      fr_time_delta_from_usec(query_ctx->type == SQL_QUERY_SELECT ? c->select_interval : c->query_interval),
					      sql_trunk_connection_read_poll, c) < 0) {
				ERROR("Unable to insert polling event");
			}
			return;

		case OCI_SUCCESS:
		case OCI_NO_DATA:
			query_ctx->rcode = ret == OCI_NO_DATA ? RLM_SQL_NO_MORE_ROWS : RLM_SQL_OK;
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
		{
			char errbuff[512];
			if (sql_snprint_error(errbuff, sizeof(errbuff), c) == 1) {
				query_ctx->rcode = RLM_SQL_ALT_QUERY;
				break;
			}
			ROPTIONAL(RERROR, ERROR, "Query failed: %s", errbuff);
			query_ctx->status = SQL_QUERY_FAILED;
			trunk_request_signal_fail(treq);
			if (query_ctx->rcode == RLM_SQL_RECONNECT) connection_signal_reconnect(c->conn, CONNECTION_FAILED);
			return;
		}
		}
		break;

	case SQL_QUERY_CANCELLED:
		ret = OCIBreak(c->ctx, c->error);
		if (ret == OCI_STILL_EXECUTING) {
			ROPTIONAL(RDEBUG3, DEBUG3, "Still awaiting response");
			if (fr_event_timer_in(c, el, &c->read_ev, fr_time_delta_from_usec(query_ctx->type == SQL_QUERY_SELECT ? c->select_interval : c->query_interval),
					      sql_trunk_connection_read_poll, c) < 0) {
				ERROR("Unable to insert polling event");
			}
			return;
		}
		OCIReset(c->ctx, c->error);
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
 *	Oracle doesn't support event driven async, so in this case
 *	we have to resort to polling.
 *
 *	This "notify" callback sets up the appropriate polling events.
 */
CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static void sql_trunk_connection_notify(UNUSED trunk_connection_t *tconn, connection_t *conn, UNUSED fr_event_list_t *el,
					trunk_connection_event_t notify_on, UNUSED void *uctx)
{
	rlm_sql_oracle_conn_t	*c = talloc_get_type_abort(conn->h, rlm_sql_oracle_conn_t);
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
	rlm_sql_oracle_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_oracle_conn_t);
	rlm_sql_row_t		row = NULL;
	sb2			*ind;
	int			i;
	OCIParam		*param;
	OCIDefine		*define;
	ub2			dtype, dsize;

	if (query_ctx->rcode != RLM_SQL_OK) RETURN_MODULE_FAIL;

	/*
	 *	We only need to do this once per result set, because
	 *	the number of columns won't change.
	 */
	if (conn->col_count == 0) {
		if (OCIAttrGet((dvoid *)conn->query, OCI_HTYPE_STMT, (dvoid *)&conn->col_count, NULL,
			       OCI_ATTR_PARAM_COUNT, conn->error)) goto error;

		if (conn->col_count == 0) goto error;
	}

	MEM(row = talloc_zero_array(conn, char*, conn->col_count + 1));
	MEM(ind = talloc_zero_array(row, sb2, conn->col_count + 1));

	for (i = 0; i < conn->col_count; i++) {
		if (OCIParamGet(conn->query, OCI_HTYPE_STMT, conn->error, (dvoid **)&param, i + 1) != OCI_SUCCESS) {
			ERROR("OCIParamGet() failed in sql_select_query");
			goto error;
		}

		if (OCIAttrGet((dvoid*)param, OCI_DTYPE_PARAM, (dvoid*)&dtype, NULL, OCI_ATTR_DATA_TYPE,
			       conn->error) != OCI_SUCCESS) {
			ERROR("OCIAttrGet() failed in sql_select_query");
			goto error;
		}

		dsize = MAX_DATASTR_LEN;

		/*
		 *	Use the retrieved length of dname to allocate an output buffer, and then define the output
		 *	variable (but only for char/string type columns).
		 */
		switch (dtype) {
#ifdef SQLT_AFC
		case SQLT_AFC:	/* ansii fixed char */
#endif
#ifdef SQLT_AFV
		case SQLT_AFV:	/* ansii var char */
#endif
		case SQLT_VCS:	/* var char */
		case SQLT_CHR:	/* char */
		case SQLT_STR:	/* string */
			if (OCIAttrGet((dvoid *)param, OCI_DTYPE_PARAM, (dvoid *)&dsize, NULL,
				       OCI_ATTR_DATA_SIZE, conn->error) != OCI_SUCCESS) {
				ERROR("OCIAttrGet() failed in sql_select_query");
				goto error;
			}

			FALL_THROUGH;
		case SQLT_DAT:
		case SQLT_INT:
		case SQLT_UIN:
		case SQLT_FLT:
		case SQLT_PDN:
		case SQLT_BIN:
		case SQLT_NUM:
			MEM(row[i] = talloc_zero_array(row, char, dsize + 1));

			break;
		default:
			dsize = 0;
			row[i] = NULL;
			break;
		}

		ind[i] = 0;

		/*
		 *	Grab the actual row value and write it to the buffer we allocated.
		 */
		if (OCIDefineByPos(conn->query, &define, conn->error, i + 1, (ub1 *)row[i], dsize + 1, SQLT_STR,
				   (dvoid *)&ind[i], NULL, NULL, OCI_DEFAULT) != OCI_SUCCESS) {
			ERROR("OCIDefineByPos() failed in sql_select_query");
			goto error;
		}
	}

	conn->row = row;
	conn->ind = ind;

	query_ctx->rcode = RLM_SQL_OK;
	RETURN_MODULE_OK;

 error:
	talloc_free(row);

	query_ctx->rcode = RLM_SQL_ERROR;
	RETURN_MODULE_FAIL;
}

static sql_rcode_t sql_fields(char const **out[], fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_oracle_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_oracle_conn_t);
	int		fields, i, status;
	char const	**names;
	OCIParam	*param;

	if (OCIAttrGet((dvoid *)conn->query, OCI_HTYPE_STMT, (dvoid *)&fields, NULL, OCI_ATTR_PARAM_COUNT,
		       conn->error)) return RLM_SQL_ERROR;
	if (fields == 0) return RLM_SQL_ERROR;

	MEM(names = talloc_array(query_ctx, char const *, fields));

	for (i = 0; i < fields; i++) {
		OraText *pcol_name = NULL;
		ub4 pcol_size = 0;

		status = OCIParamGet(conn->query, OCI_HTYPE_STMT, conn->error, (dvoid **)&param, i + 1);
		if (status != OCI_SUCCESS) {
			ERROR("OCIParamGet(OCI_HTYPE_STMT) failed in sql_fields()");
		error:
			talloc_free(names);

			return RLM_SQL_ERROR;
		}

		status = OCIAttrGet((dvoid **)param, OCI_DTYPE_PARAM, &pcol_name, &pcol_size,
				    OCI_ATTR_NAME, conn->error);
		if (status != OCI_SUCCESS) {
			ERROR("OCIParamGet(OCI_ATTR_NAME) failed in sql_fields()");

			goto error;
		}

		names[i] = (char const *)pcol_name;
	}

	*out = names;

	return RLM_SQL_OK;
}

static int sql_num_rows(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_oracle_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_oracle_conn_t);
	ub4 rows = 0;
	ub4 size = sizeof(ub4);

	OCIAttrGet((CONST dvoid *)conn->query, OCI_HTYPE_STMT, (dvoid *)&rows, &size, OCI_ATTR_ROW_COUNT, conn->error);

	return rows;
}

static unlang_action_t sql_fetch_row(rlm_rcode_t *p_result, UNUSED int *priority, UNUSED request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	int			status = OCI_STILL_EXECUTING;
	rlm_sql_oracle_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_oracle_conn_t);

	if (!conn->ctx) {
		ERROR("Socket not connected");

		query_ctx->rcode = RLM_SQL_RECONNECT;
		RETURN_MODULE_FAIL;
	}

	query_ctx->row = NULL;

	while (status == OCI_STILL_EXECUTING) {
		status = OCIStmtFetch(conn->query, conn->error, 1, OCI_FETCH_NEXT, OCI_DEFAULT);
	}
	if (status == OCI_SUCCESS) {
		query_ctx->row = conn->row;

		query_ctx->rcode = RLM_SQL_OK;
		RETURN_MODULE_OK;
	}

	if (status == OCI_NO_DATA) {
		query_ctx->rcode = RLM_SQL_NO_MORE_ROWS;
		RETURN_MODULE_OK;
	}

	if (status == OCI_ERROR) {
		ERROR("fetch failed in sql_fetch_row");
		query_ctx->rcode = sql_check_reconnect(conn);
		RETURN_MODULE_FAIL;
	}

	query_ctx->rcode = RLM_SQL_ERROR;
	RETURN_MODULE_FAIL;
}

static sql_rcode_t sql_free_result(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_oracle_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_oracle_conn_t);
	int			status = OCI_STILL_EXECUTING;

	/* Cancel the cursor first */
	while (status == OCI_STILL_EXECUTING) {
		status = OCIStmtFetch(conn->query, conn->error, 1, OCI_FETCH_NEXT, OCI_DEFAULT);
	}

	TALLOC_FREE(conn->row);
	conn->ind = NULL;	/* ind is a child of row */
	conn->col_count = 0;
	conn->query_ctx = NULL;

	if (OCIStmtRelease(conn->query, conn->error, NULL, 0, OCI_DEFAULT) != OCI_SUCCESS ) {
		ERROR("OCI release failed in sql_finish_query");
		return RLM_SQL_ERROR;
	}

	return RLM_SQL_OK;
}

static sql_rcode_t sql_finish_query(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_oracle_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_oracle_conn_t);

	conn->query_ctx = NULL;

	if (OCIStmtRelease(conn->query, conn->error, NULL, 0, OCI_DEFAULT) != OCI_SUCCESS ) {
		ERROR("OCI release failed in sql_finish_query");
		return RLM_SQL_ERROR;
	}

	return 0;
}

static sql_rcode_t sql_finish_select_query(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_oracle_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_oracle_conn_t);

	TALLOC_FREE(conn->row);
	conn->ind = NULL;	/* ind is a child of row */
	conn->col_count = 0;
	conn->query_ctx = NULL;

	if (OCIStmtRelease (conn->query, conn->error, NULL, 0, OCI_DEFAULT) != OCI_SUCCESS ) {
		ERROR("OCI release failed in sql_finish_query");
		return RLM_SQL_ERROR;
	}

	return 0;
}

/* Exported to rlm_sql */
extern rlm_sql_driver_t rlm_sql_oracle;
rlm_sql_driver_t rlm_sql_oracle = {
	.common = {
		.name				= "sql_oracle",
		.magic				= MODULE_MAGIC_INIT,
		.inst_size			= sizeof(rlm_sql_oracle_t),
		.config				= driver_config,
		.instantiate			= mod_instantiate,
		.detach				= mod_detach
	},
	.flags				= RLM_SQL_RCODE_FLAGS_ALT_QUERY,
	.sql_query_resume		= sql_query_resume,
	.sql_select_query_resume	= sql_select_query_resume,
	.sql_num_rows			= sql_num_rows,
	.sql_affected_rows		= sql_num_rows,
	.sql_fetch_row			= sql_fetch_row,
	.sql_fields			= sql_fields,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_select_query,
	.trunk_io_funcs = {
		.connection_alloc	= sql_trunk_connection_alloc,
		.connection_notify	= sql_trunk_connection_notify,
		.request_mux		= sql_trunk_request_mux,
		.request_cancel_mux	= sql_request_cancel_mux,
		.request_cancel		= sql_request_cancel,
		.request_fail		= sql_request_fail,
	}
};
