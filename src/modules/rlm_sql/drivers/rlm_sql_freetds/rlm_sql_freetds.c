 /*
 *   This program is is free software; you can redistribute it and/or modify
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
 * @file rlm_sql.c
 * @brief Implements FreeTDS rlm_sql driver.
 *
 * @copyright 2013 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Mattias Sjostrom (mattias@nogui.se)
 */

RCSID("$Id$")

#define LOG_PREFIX "sql - freetds"

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <sys/stat.h>

#include <ctpublic.h>

#include "rlm_sql.h"
#include "rlm_sql_trunk.h"

typedef struct {
	CS_CONTEXT	*context;	//!< Structure FreeTDS uses to avoid creating globals.
	CS_CONNECTION	*db;		//!< Handle specifying a single connection to the database.
	CS_COMMAND	*command;	//!< A prepared statement.
	int		colcount;	//!< How many columns are in the current result set.
	bool		nulls;		//!< Were there any NULL values in the last row.
	char		**results;	//!< Result strings from statement execution.
	CS_SMALLINT	*ind;		//!< Indicators of data length / NULL.
	char		*error;		//!< The last error string created by one of the call backs.
	bool		established;	//!< Set to false once the connection has been properly established.
	CS_INT		rows_affected;	//!< Rows affected by last INSERT / UPDATE / DELETE.
} rlm_sql_freetds_conn_t;

#define	MAX_DATASTR_LEN	256

/** Client-Library error handler
 *
 * Callback for any errors raised by the Client-Library. Will overwrite any previous errors associated
 * with a connection.
 *
 * @param context The FreeTDS library context.
 * @param conn DB connection handle.
 * @param emsgp Pointer to the error structure.
 * @return CS_SUCCEED
 */
static CS_RETCODE CS_PUBLIC clientmsg_callback(CS_CONTEXT *context, UNUSED CS_CONNECTION *conn, CS_CLIENTMSG *emsgp)
{
	rlm_sql_freetds_conn_t *this = NULL;
	int len = 0;

	/*
	 *	Not actually an error, but the client wanted to tell us something...
	 */
	if (emsgp->severity == CS_SV_INFORM) {
		INFO("%s", emsgp->msgstring);

		return CS_SUCCEED;
	}

	if ((cs_config(context, CS_GET, CS_USERDATA, &this, sizeof(this), &len) != CS_SUCCEED) || !this) {
		ERROR("failed retrieving context userdata");

		return CS_SUCCEED;
	}

	if (this->error) TALLOC_FREE(this->error);

	this->error = talloc_typed_asprintf(this, "client error: severity(%ld), number(%ld), origin(%ld), layer(%ld): %s",
				      (long)CS_SEVERITY(emsgp->severity), (long)CS_NUMBER(emsgp->msgnumber),
				      (long)CS_ORIGIN(emsgp->msgnumber), (long)CS_LAYER(emsgp->msgnumber),
				      emsgp->msgstring);

	if (emsgp->osstringlen > 0) {
		this->error = talloc_asprintf_append(this->error, ". os error: number(%ld): %s",
						     (long)emsgp->osnumber, emsgp->osstring);
	}

	return CS_SUCCEED;
}

/** Client error handler
 *
 * Callback for any errors raised by the client. Will overwrite any previous errors associated
 * with a connection.
 *
 * @param context The FreeTDS library context.
 * @param emsgp Pointer to the error structure.
 * @return CS_SUCCEED
 */
static CS_RETCODE CS_PUBLIC csmsg_callback(CS_CONTEXT *context, CS_CLIENTMSG *emsgp)
{
	rlm_sql_freetds_conn_t *this = NULL;
	int len = 0;

	/*
	 *	Not actually an error, but the client wanted to tell us something...
	 */
	if (emsgp->severity == CS_SV_INFORM) {
		INFO("%s", emsgp->msgstring);

		return CS_SUCCEED;
	}

	if ((cs_config(context, CS_GET, CS_USERDATA, &this, sizeof(this), &len) != CS_SUCCEED) || !this) {
		ERROR("failed retrieving context userdata");

		return CS_SUCCEED;
	}

	if (this->error) TALLOC_FREE(this->error);

	this->error = talloc_typed_asprintf(this, "cs error: severity(%ld), number(%ld), origin(%ld), layer(%ld): %s",
				      (long)CS_SEVERITY(emsgp->severity), (long)CS_NUMBER(emsgp->msgnumber),
				      (long)CS_ORIGIN(emsgp->msgnumber), (long)CS_LAYER(emsgp->msgnumber),
				      emsgp->msgstring);

	if (emsgp->osstringlen > 0) {
		this->error = talloc_asprintf_append(this->error, ". os error: number(%ld): %s",
						     (long)emsgp->osnumber, emsgp->osstring);
	}

	return CS_SUCCEED;
}

/** Server error handler
 *
 * Callback for any messages sent back from the server.
 *
 * There's no standard categorisation of messages sent back from the server, so we don't know they're errors,
 * the only thing we can do is write them to the long as informational messages.
 *
 * @param context The FreeTDS library context.
 * @param conn DB connection handle.
 * @param msgp Pointer to the error structure.
 * @return CS_SUCCEED
 */
static CS_RETCODE CS_PUBLIC servermsg_callback(CS_CONTEXT *context, UNUSED CS_CONNECTION *conn, CS_SERVERMSG *msgp)
{
	rlm_sql_freetds_conn_t *this = NULL;
	int len = 0;

	if ((cs_config(context, CS_GET, CS_USERDATA, &this, sizeof(this), &len) != CS_SUCCEED) || !this) {
		ERROR("failed retrieving context userdata");

		return CS_SUCCEED;
	}

	/*
	 *	Because apparently there are no standard severity levels *brilliant*
	 */
	if (this->established) {
		INFO("server msg from \"%s\": severity(%ld), number(%ld), origin(%ld), "
		     "layer(%ld), procedure \"%s\": %s",
		     (msgp->svrnlen > 0) ? msgp->svrname : "unknown",
		     (long)msgp->msgnumber, (long)msgp->severity, (long)msgp->state, (long)msgp->line,
		     (msgp->proclen > 0) ? msgp->proc : "none", msgp->text);
	} else {
		if (this->error) TALLOC_FREE(this->error);

		this->error = talloc_typed_asprintf(this, "Server msg from \"%s\": severity(%ld), number(%ld), "
						    "origin(%ld), layer(%ld), procedure \"%s\": %s",
					      	    (msgp->svrnlen > 0) ? msgp->svrname : "unknown",
					      	    (long)msgp->msgnumber, (long)msgp->severity, (long)msgp->state,
					      	    (long)msgp->line,
						    (msgp->proclen > 0) ? msgp->proc : "none", msgp->text);
	}

	return CS_SUCCEED;
}

/*************************************************************************
 *
 *	Function: sql_query
 *
 *	Purpose: Issue a non-SELECT query (ie: update/delete/insert) to
 *	       the database.
 *
 *************************************************************************/
static sql_rcode_t sql_query(request_t *request, rlm_sql_freetds_conn_t *conn, char const *query)
{
	CS_RETCODE	results_ret;
	CS_INT		result_type;

	/*
	 *	Reset rows_affected in case the query fails.
	 *	Prevents accidentally returning the rows_affected from a previous query.
	 */
	conn->rows_affected = -1;

	if (ct_cmd_alloc(conn->db, &conn->command) != CS_SUCCEED) {
		ROPTIONAL(RERROR, ERROR, "Unable to allocate command structure (ct_cmd_alloc())");
		return RLM_SQL_ERROR;
	}

	if (ct_command(conn->command, CS_LANG_CMD, query, CS_NULLTERM, CS_UNUSED) != CS_SUCCEED) {
		ROPTIONAL(RERROR, ERROR, "Unable to initialise command structure (ct_command())");
		return RLM_SQL_ERROR;
	}

	if (ct_send(conn->command) != CS_SUCCEED) {
		ROPTIONAL(RERROR, ERROR, "Unable to send command (ct_send())");
		return RLM_SQL_ERROR;
	}

	/*
	 *	We'll make three calls to ct_results, first to get a success indicator, secondly to get a
	 *	done indicator, and thirdly to get a "nothing left to handle" status.
	 */

	/*
	 *	First call to ct_results, we need returncode CS_SUCCEED and result_type CS_CMD_SUCCEED.
	 */
	switch(ct_results(conn->command, &result_type)) {
	case CS_SUCCEED:
		switch (result_type) {
		case CS_CMD_SUCCEED:
			break;
		case CS_ROW_RESULT:
			ROPTIONAL(RERROR, ERROR, "sql_query processed a query returning rows. "
				  "Use sql_select_query instead!");
			break;
		case CS_CMD_FAIL:
			/*
			 *	If ct_send succeeded and ct_results gives CS_CMD_FAIL,
			 *	provided the queries are sane, this will be a key constraint
			 *	conflict.
			 *	Either way, this is a reasonable cause to go to the alternate query.
			 */
			return RLM_SQL_ALT_QUERY;
		default:
			ROPTIONAL(RERROR, ERROR, "Result failure or unexpected result type from query, (%d)", result_type);
			return RLM_SQL_ERROR;
		}
		break;

	case CS_FAIL: /* Serious failure, freetds requires us to cancel and maybe even close db */
		ROPTIONAL(RERROR, ERROR, "Failure retrieving query results");

		if (ct_cancel(NULL, conn->command, CS_CANCEL_ALL) == CS_FAIL) return RLM_SQL_RECONNECT;
		conn->command = NULL;
		return RLM_SQL_ERROR;

	default:
		ROPTIONAL(RERROR, ERROR, "Unexpected return value from ct_results()");
		return RLM_SQL_ERROR;
	}

	/*
	 *	Retrieve the number of rows affected - the later calls
	 *	to ct_results end up resetting the underlying counter so we
	 *	no longer have access to this.
	 */
	if (ct_res_info(conn->command, CS_ROW_COUNT, &conn->rows_affected, CS_UNUSED, NULL) != CS_SUCCEED) {
		ROPTIONAL(RERROR, ERROR, "rlm_sql_freetds: error retrieving row count");
		return RLM_SQL_ERROR;
	}

	/*
	 *	Second call to ct_results, we need returncode CS_SUCCEED
	 *	and result_type CS_CMD_DONE.
	 */
	if ((results_ret = ct_results(conn->command, &result_type)) == CS_SUCCEED) {
		if (result_type != CS_CMD_DONE) {
			ROPTIONAL(RERROR, ERROR, "Result failure or unexpected result type from query");
			return RLM_SQL_ERROR;
		}
	} else {
		switch (results_ret) {
		case CS_FAIL: /* Serious failure, freetds requires us to cancel and maybe even close db */
			ROPTIONAL(RERROR, ERROR, "Failure retrieving query results");
			if (ct_cancel(NULL, conn->command, CS_CANCEL_ALL) == CS_FAIL) return RLM_SQL_RECONNECT;

			conn->command = NULL;
			return RLM_SQL_ERROR;

		default:
			ROPTIONAL(RERROR, ERROR, "Unexpected return value from ct_results()");
			return RLM_SQL_ERROR;
		}
	}

	/*
	 *	Third call to ct_results, we need returncode CS_END_RESULTS result_type will be ignored.
	 */
	results_ret = ct_results(conn->command, &result_type);
	switch (results_ret) {
	case CS_FAIL: /* Serious failure, freetds requires us to cancel and maybe even close db */
		ROPTIONAL(RERROR, ERROR, "Failure retrieving query results");
		if (ct_cancel(NULL, conn->command, CS_CANCEL_ALL) == CS_FAIL) return RLM_SQL_RECONNECT;
		conn->command = NULL;

		return RLM_SQL_ERROR;

	case CS_END_RESULTS:  /* This is where we want to end up */
		break;

	default:
		ROPTIONAL(RERROR, ERROR, "Unexpected return value from ct_results()");

		return RLM_SQL_ERROR;
	}

	return RLM_SQL_OK;
}

/*************************************************************************
 *
 *	Function: sql_fields
 *
 *	Purpose:  Return name of regular result columns.
 *
 *************************************************************************/
static sql_rcode_t sql_fields(char const **out[], fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_freetds_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_freetds_conn_t);
	CS_DATAFMT datafmt;
	int fields, i;
	char const **names;

	/* Get number of elements in row result */
	if (ct_res_info(conn->command, CS_NUMDATA, (CS_INT *)&fields, CS_UNUSED, NULL) != CS_SUCCEED) {
		ERROR("sql_fields() Error retrieving column count");

		return RLM_SQL_ERROR;
	}

	if (fields <= 0) return RLM_SQL_ERROR;

	MEM(names = talloc_array(query_ctx, char const *, fields));

	for (i = 0; i < fields; i++) {
		int col = i + 1;
		char *p;

		/*
		** Get the column description.  ct_describe() fills the
		** datafmt parameter with a description of the column.
		*/
		if (ct_describe(conn->command, col, &datafmt) != CS_SUCCEED) {
			ERROR("sql_fields() Problems with ct_describe(), column %d", col);
			talloc_free(names);
			return RLM_SQL_ERROR;
		}

		if (datafmt.namelen > 0) {
			MEM(p = talloc_array(names, char, (size_t)datafmt.namelen + 1));
			strlcpy(p, datafmt.name, (size_t)datafmt.namelen + 1);
			names[i] = p;
		}
	}

	*out = names;

	return RLM_SQL_OK;
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
static size_t sql_error(UNUSED TALLOC_CTX *ctx, sql_log_entry_t out[], NDEBUG_UNUSED size_t outlen,
			fr_sql_query_t *query_ctx)
{
	rlm_sql_freetds_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_freetds_conn_t);

	fr_assert(outlen > 0);

	if (!conn->error) return 0;

	out[0].type = L_ERR;
	out[0].msg = conn->error;

	return 1;
}

static sql_rcode_t sql_finish_select_query(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_freetds_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_freetds_conn_t);

	ct_cancel(NULL, conn->command, CS_CANCEL_ALL);
	if (ct_cmd_drop(conn->command) != CS_SUCCEED) {
		ERROR("freeing command structure failed");

		return RLM_SQL_ERROR;
	}
	conn->command = NULL;
	conn->nulls = false;

	TALLOC_FREE(conn->results);

	return RLM_SQL_OK;

}

/** Execute a query when we expected a result set
 *
 */
static sql_rcode_t sql_select_query(request_t *request, rlm_sql_freetds_conn_t *conn, char const *query)
{
	CS_RETCODE	results_ret;
	CS_INT		result_type;
	CS_DATAFMT	descriptor;
	int		i;
	char		**rowdata;

	 if (!conn->db) {
		ROPTIONAL(RERROR, ERROR, "socket not connected");
		return RLM_SQL_ERROR;
	}

	if (ct_cmd_alloc(conn->db, &conn->command) != CS_SUCCEED) {
		ROPTIONAL(RERROR, ERROR, "unable to allocate command structure (ct_cmd_alloc())");
		return RLM_SQL_ERROR;
	}

	if (ct_command(conn->command, CS_LANG_CMD, query, CS_NULLTERM, CS_UNUSED) != CS_SUCCEED) {
		ROPTIONAL(RERROR, ERROR, "unable to initiate command structure (ct_command()");
		return RLM_SQL_ERROR;
	}

	if (ct_send(conn->command) != CS_SUCCEED) {
		ROPTIONAL(RERROR, ERROR, "unable to send command (ct_send())");
		return RLM_SQL_ERROR;
	}

	results_ret = ct_results(conn->command, &result_type);
	switch (results_ret) {
	case CS_SUCCEED:
		switch (result_type) {
		case CS_ROW_RESULT:

			/*
			 * 	Set up a target buffer for the results data, and associate the buffer with the results,
			 *	but the actual fetching takes place in sql_fetch_row.
			 *	The layer above MUST call sql_fetch_row and/or sql_finish_select_query
			 *	or this socket will be unusable and may cause segfaults
			 *	if reused later on.
			 */

			/*
			 *	Set up the DATAFMT structure that describes our target array
			 *	and tells freetds what we want future ct_fetch calls to do.
			 */
			descriptor.datatype = CS_CHAR_TYPE; 	/* The target buffer is a string */
			descriptor.format = CS_FMT_NULLTERM;	/* Null termination please */
			descriptor.maxlength = MAX_DATASTR_LEN;	/* The string arrays are this large */
			descriptor.count = 1;			/* Fetch one row of data */
			descriptor.locale = NULL;		/* Don't do NLS stuff */

			if (ct_res_info(conn->command, CS_NUMDATA, &conn->colcount, CS_UNUSED, NULL) != CS_SUCCEED) {
				ROPTIONAL(RERROR, ERROR, "Error retrieving column count");
				return RLM_SQL_ERROR;
			}

			rowdata = talloc_zero_array(conn, char *, conn->colcount + 1); /* Space for pointers */
			conn->ind = talloc_zero_array(conn, CS_SMALLINT, conn->colcount);

			for (i = 0; i < conn->colcount; i++) {
				/* Space to hold the result data */
				rowdata[i] = talloc_zero_array(rowdata, char, MAX_DATASTR_LEN + 1);

				/* Associate the target buffer with the data */
				if (ct_bind(conn->command, i + 1, &descriptor, rowdata[i], NULL, &conn->ind[i]) != CS_SUCCEED) {
					talloc_free(rowdata);
					talloc_free(conn->ind);

					ROPTIONAL(RERROR, ERROR, "ct_bind() failed)");
					return RLM_SQL_ERROR;
				}
			}

			rowdata[i] = NULL; /* Terminate the array */
			conn->results = rowdata;
			break;

		case CS_CMD_SUCCEED:
		case CS_CMD_DONE:
			ROPTIONAL(RWARN, WARN, "query returned no data");
			break;

		default:
			ROPTIONAL(RERROR, ERROR, "unexpected result type from query");
			return RLM_SQL_ERROR;
		}
		break;

	case CS_FAIL:
		/*
		 * Serious failure, freetds requires us to cancel the results and maybe even close the db.
		 */

		ROPTIONAL(RERROR, ERROR, "failure retrieving query results");

		if (ct_cancel(NULL, conn->command, CS_CANCEL_ALL) == CS_FAIL) return RLM_SQL_RECONNECT;
		conn->command = NULL;

		return RLM_SQL_ERROR;

	default:
		ROPTIONAL(RERROR, ERROR, "unexpected return value from ct_results()");

		return RLM_SQL_ERROR;
	}

	return RLM_SQL_OK;
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static void sql_trunk_request_mux(UNUSED fr_event_list_t *el, trunk_connection_t *tconn,
				  connection_t *conn, UNUSED void *uctx)
{
	rlm_sql_freetds_conn_t	*sql_conn = talloc_get_type_abort(conn->h, rlm_sql_freetds_conn_t);
	trunk_request_t		*treq;
	request_t		*request;
	fr_sql_query_t		*query_ctx;

	if (trunk_connection_pop_request(&treq, tconn) != 0) return;
	if (!treq) return;

	query_ctx = talloc_get_type_abort(treq->preq, fr_sql_query_t);
	request = query_ctx->request;
	query_ctx->tconn = tconn;

	ROPTIONAL(RDEBUG2, DEBUG2, "Executing query: %s", query_ctx->query_str);

	switch (query_ctx->type) {
	case SQL_QUERY_SELECT:
		query_ctx->rcode = sql_select_query(request, sql_conn, query_ctx->query_str);
		break;
	case SQL_QUERY_OTHER:
		query_ctx->rcode = sql_query(request, sql_conn, query_ctx->query_str);
		break;
	}

	switch (query_ctx->rcode) {
	case RLM_SQL_OK:
	case RLM_SQL_ALT_QUERY:
		break;

	default:
		trunk_request_signal_fail(treq);
		if (query_ctx->rcode == RLM_SQL_RECONNECT) connection_signal_reconnect(conn, CONNECTION_FAILED);
		return;
	}

	query_ctx->status = SQL_QUERY_RETURNED;
	trunk_request_signal_reapable(treq);
	if (request) unlang_interpret_mark_runnable(request);
}

static int sql_affected_rows(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_freetds_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_freetds_conn_t);

	return (conn->rows_affected);
}

static unlang_action_t sql_fetch_row(rlm_rcode_t *p_result, UNUSED int *priority, request_t *request, void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(uctx, fr_sql_query_t);
	rlm_sql_freetds_conn_t	*conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_freetds_conn_t);
	CS_INT			ret, count;
	int			i;

	if (conn->nulls) TALLOC_FREE(query_ctx->row);
	query_ctx->row = NULL;

	ret = ct_fetch(conn->command, CS_UNUSED, CS_UNUSED, CS_UNUSED, &count);
	switch (ret) {
	case CS_FAIL:
		/*
		 *	Serious failure, freetds requires us to cancel the results and maybe even close the db.
		 */
		ROPTIONAL(RERROR, ERROR, "failure fetching row data");
		if (ct_cancel(NULL, conn->command, CS_CANCEL_ALL) == CS_FAIL) {
			ROPTIONAL(RERROR, ERROR, "cleaning up");
		} else {
			conn->command = NULL;
		}

		query_ctx->rcode = RLM_SQL_RECONNECT;
		RETURN_MODULE_FAIL;

	case CS_END_DATA:
		query_ctx->rcode = RLM_SQL_NO_MORE_ROWS;
		RETURN_MODULE_OK;

	case CS_SUCCEED:
		/*
		 *	NULL values are indicated by -1 in the corresponding "indicator"
		 *	However, the buffer still exists, so if we have any NULL
		 *	returns, we need to copy the results with the NULL
		 *	fields left at zero to match behaviour of other drivers.
		 */
		conn->nulls = false;
		for (i = 0; i < conn->colcount; i++) {
			if (conn->ind[i] < 0) {
				conn->nulls = true;
				break;
			}
		}

		if (conn->nulls) {
			query_ctx->row = talloc_zero_array(query_ctx, char *, conn->colcount + 1);
			for (i = 0; i < conn->colcount; i++) {
				if (conn->ind[i] < 0) continue;
				query_ctx->row[i] = talloc_strdup(query_ctx->row, conn->results[i]);
			}
		} else {
			query_ctx->row = conn->results;
		}

		query_ctx->rcode = RLM_SQL_OK;
		RETURN_MODULE_OK;

	case CS_ROW_FAIL:
		ROPTIONAL(RERROR, ERROR, "recoverable failure fetching row data");

		query_ctx->rcode = RLM_SQL_RECONNECT;
		RETURN_MODULE_FAIL;

	default:
		ROPTIONAL(RERROR, ERROR, "unexpected returncode from ct_fetch");

		query_ctx->rcode = RLM_SQL_ERROR;
		RETURN_MODULE_FAIL;
	}
}

static sql_rcode_t sql_finish_query(fr_sql_query_t *query_ctx, UNUSED rlm_sql_config_t const *config)
{
	rlm_sql_freetds_conn_t *conn = talloc_get_type_abort(query_ctx->tconn->conn->h, rlm_sql_freetds_conn_t);

	ct_cancel(NULL, conn->command, CS_CANCEL_ALL);
	if (ct_cmd_drop(conn->command) != CS_SUCCEED) {
		ERROR("freeing command structure failed");

		return RLM_SQL_ERROR;
	}
	conn->command = NULL;
	conn->rows_affected = -1;

	return RLM_SQL_OK;
}

static void _sql_connection_close(UNUSED fr_event_list_t *el, void *h, UNUSED void *uctx)
{
	rlm_sql_freetds_conn_t	*c = talloc_get_type_abort(h, rlm_sql_freetds_conn_t);

	DEBUG2("socket destructor called, closing socket");

	if (c->command) {
		ct_cancel(NULL, c->command, CS_CANCEL_ALL);
		if (ct_cmd_drop(c->command) != CS_SUCCEED) {
			ERROR("freeing command structure failed");
			return;
		}
	}

	if (c->db) {
		/*
		 *	We first try gracefully closing the connection (which informs the server)
		 *	Then if that fails we force the connection closure.
		 *
		 *	Sybase docs says this may fail because of pending results, but we
		 *	should not have any pending results at this point, so something else must
		 *	of gone wrong.
		 */
		if (ct_close(c->db, CS_UNUSED) != CS_SUCCEED) ct_close(c->db, CS_FORCE_CLOSE);

		ct_con_drop(c->db);
	}

	if (c->context) {
		ct_exit(c->context, CS_UNUSED);
		cs_ctx_drop(c->context);
	}

	talloc_free(h);
}

CC_NO_UBSAN(function) /* UBSAN: false positive - public vs private connection_t trips --fsanitize=function */
static connection_state_t _sql_connection_init(void **h, connection_t *conn, void *uctx)
{
	rlm_sql_t const		*sql = talloc_get_type_abort_const(uctx, rlm_sql_t);
	rlm_sql_config_t const	*config = &sql->config;
	rlm_sql_freetds_conn_t	*c;
	unsigned int		timeout_ms = fr_time_delta_to_msec(config->trunk_conf.conn_conf->connection_timeout);
	char			database[128];

	MEM(c = talloc_zero(conn, rlm_sql_freetds_conn_t));

	/*
	 *	Allocate a CS context structure. This should really only be done once, but because of
	 *	the db pooling design of rlm_sql, we'll have to go with one context per db
	 */
	if (cs_ctx_alloc(CS_VERSION_100, &c->context) != CS_SUCCEED) {
		ERROR("unable to allocate CS context structure (cs_ctx_alloc())");
	error:
		if (c->error) ERROR("%s", c->error);
		return CONNECTION_STATE_FAILED;
	}

	/*
	 *	Initialize ctlib
	 */
	if (ct_init(c->context, CS_VERSION_100) != CS_SUCCEED) {
		ERROR("unable to initialize Client-Library");
		goto error;
	}

	if (ct_config(c->context, CS_SET, CS_LOGIN_TIMEOUT, (CS_VOID *)&timeout_ms, CS_UNUSED, NULL) != CS_SUCCEED) {
		ERROR("Setting connection timeout failed");
		goto error;
	}

	/*
	 *	Install callback functions for error-handling
	 */
	if (cs_config(c->context, CS_SET, CS_MESSAGE_CB, (CS_VOID *)csmsg_callback, CS_UNUSED, NULL) != CS_SUCCEED) {
		ERROR("unable to install CS Library error callback");
		goto error;
	}

	if (cs_config(c->context, CS_SET, CS_USERDATA, (CS_VOID *)&c, sizeof(c), NULL) != CS_SUCCEED) {
		ERROR("unable to set userdata pointer");
		goto error;
	}

	if (ct_callback(c->context, NULL, CS_SET, CS_CLIENTMSG_CB, (CS_VOID *)clientmsg_callback) != CS_SUCCEED) {
		ERROR("unable to install client message callback");
		goto error;
	}

	if (ct_callback(c->context, NULL, CS_SET, CS_SERVERMSG_CB, (CS_VOID *)servermsg_callback) != CS_SUCCEED) {
		ERROR("unable to install server message callback");
		goto error;
	}

	/*
	 *	Allocate a ctlib db structure
	 */
	if (ct_con_alloc(c->context, &c->db) != CS_SUCCEED) {
		ERROR("unable to allocate db structure");
		goto error;
	}

	/*
	 *	Set User and Password properties for the db
	 */
	if (ct_con_props(c->db, CS_SET, CS_USERNAME,
			 UNCONST(CS_VOID *, config->sql_login), strlen(config->sql_login), NULL) != CS_SUCCEED) {
		ERROR("unable to set username for db");
		goto error;
	}

	if (ct_con_props(c->db, CS_SET, CS_PASSWORD,
			 UNCONST(CS_VOID *, config->sql_password), strlen(config->sql_password), NULL) != CS_SUCCEED) {
		ERROR("unable to set password for db");
		goto error;
	}

	/*
	 *	Connect to the database
	 */
	if (ct_connect(c->db, UNCONST(CS_CHAR *, config->sql_server), strlen(config->sql_server)) != CS_SUCCEED) {
		ERROR("unable to establish connection to server %s",
		      config->sql_server);
		goto error;
	}

	/*
	 *	There doesn't appear to be a way to set the database with the API, so use an
	 *	sql statement when we first open the connection.
	 */
	snprintf(database, sizeof(database), "USE %s;", config->sql_db);
	if (sql_query(NULL, c, database) != RLM_SQL_OK) goto error;

	*h = c;
	return CONNECTION_STATE_CONNECTED;
}

SQL_TRUNK_CONNECTION_ALLOC

SQL_QUERY_RESUME

static void sql_request_fail(request_t *request, void *preq, UNUSED void *rctx,
			     UNUSED trunk_request_state_t state, UNUSED void *uctx)
{
	fr_sql_query_t		*query_ctx = talloc_get_type_abort(preq, fr_sql_query_t);

	query_ctx->treq = NULL;
	if (query_ctx->rcode == RLM_SQL_OK) query_ctx->rcode = RLM_SQL_ERROR;
	if (request) unlang_interpret_mark_runnable(request);
}

/* Exported to rlm_sql */
extern rlm_sql_driver_t rlm_sql_freetds;
rlm_sql_driver_t rlm_sql_freetds = {
	.common = {
		.magic				= MODULE_MAGIC_INIT,
		.name				= "sql_freetds"
	},
	.flags				= RLM_SQL_RCODE_FLAGS_ALT_QUERY,
	.sql_query_resume		= sql_query_resume,
	.sql_select_query_resume	= sql_query_resume,
	.sql_fields			= sql_fields,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fetch_row			= sql_fetch_row,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_select_query,
	.trunk_io_funcs = {
		.connection_alloc	= sql_trunk_connection_alloc,
		.request_mux		= sql_trunk_request_mux,
		.request_fail		= sql_request_fail
	}
};
