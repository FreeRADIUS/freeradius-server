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
 * @copyright 2013  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2000  Mattias Sjostrom <mattias@nogui.se>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/stat.h>

#include <ctpublic.h>

#include "rlm_sql.h"

typedef struct rlm_sql_freetds_conn {
	CS_CONTEXT	*context;	//!< Structure FreeTDS uses to avoid creating globals.
	CS_CONNECTION	*db;		//!< Handle specifying a single connection to the database.
	CS_COMMAND	*command;	//!< A prepared statement.
	char		**results;	//!< Result strings from statement execution.
	char		*error;		//!< The last error string created by one of the call backs.
	bool		established;	//!< Set to false once the connection has been properly established.
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
 * @return CS_CUCCEED
 */
static CS_RETCODE CS_PUBLIC clientmsg_callback(CS_CONTEXT *context, UNUSED CS_CONNECTION *conn, CS_CLIENTMSG *emsgp)
{
	rlm_sql_freetds_conn_t *this = NULL;
	int len = 0;

	/*
	 *	Not actually an error, but the client wanted to tell us something...
	 */
	if (emsgp->severity == CS_SV_INFORM) {
		INFO("rlm_sql_freetds: %s", emsgp->msgstring);

		return CS_SUCCEED;
	}

	if ((cs_config(context, CS_GET, CS_USERDATA, &this, sizeof(this), &len) != CS_SUCCEED) || !this) {
		ERROR("rlm_sql_freetds: failed retrieving context userdata");

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
		INFO("rlm_sql_freetds: %s", emsgp->msgstring);

		return CS_SUCCEED;
	}

	if ((cs_config(context, CS_GET, CS_USERDATA, &this, sizeof(this), &len) != CS_SUCCEED) || !this) {
		ERROR("rlm_sql_freetds: failed retrieving context userdata");

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
		ERROR("rlm_sql_freetds: failed retrieving context userdata");

		return CS_SUCCEED;
	}

	/*
	 *	Because apparently there are no standard severity levels *brilliant*
	 */
	if (this->established) {
		INFO("rlm_sql_freetds: server msg from \"%s\": severity(%ld), number(%ld), origin(%ld), "
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
static sql_rcode_t sql_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config, char const *query)
{
	rlm_sql_freetds_conn_t *conn = handle->conn;

	CS_RETCODE	results_ret;
	CS_INT		result_type;

	if (ct_cmd_alloc(conn->db, &conn->command) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: Unable to allocate command structure (ct_cmd_alloc())");

		return RLM_SQL_ERROR;
	}

	if (ct_command(conn->command, CS_LANG_CMD, query, CS_NULLTERM, CS_UNUSED) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: Unable to initialise command structure (ct_command())");

		return RLM_SQL_ERROR;
	}

	if (ct_send(conn->command) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: Unable to send command (ct_send())");

		return RLM_SQL_ERROR;
	}

	/*
	 *	We'll make three calls to ct_results, first to get a success indicator, secondly to get a
	 *	done indicator, and thirdly to get a "nothing left to handle" status.
	 */

	/*
	 *	First call to ct_results, we need returncode CS_SUCCEED and result_type CS_CMD_SUCCEED.
	 */
	if ((results_ret = ct_results(conn->command, &result_type)) == CS_SUCCEED) {
		if (result_type != CS_CMD_SUCCEED) {
			if  (result_type == CS_ROW_RESULT) {
				ERROR("rlm_sql_freetds: sql_query processed a query returning rows. "
				      "Use sql_select_query instead!");
			}
			ERROR("rlm_sql_freetds: Result failure or unexpected result type from query");

			return RLM_SQL_ERROR;
		}
	} else {
		switch (results_ret) {
		case CS_FAIL: /* Serious failure, freetds requires us to cancel and maybe even close db */
			ERROR("rlm_sql_freetds: Failure retrieving query results");

			if (ct_cancel(NULL, conn->command, CS_CANCEL_ALL) == CS_FAIL) {
				INFO("rlm_sql_freetds: Cleaning up");

				return RLM_SQL_RECONNECT;
			}
			conn->command = NULL;

			return RLM_SQL_ERROR;
		default:
			ERROR("rlm_sql_freetds: Unexpected return value from ct_results()");

			return RLM_SQL_ERROR;
		}
	}

	/*
	 *	Second call to ct_results, we need returncode CS_SUCCEED
	 *	and result_type CS_CMD_DONE.
	 */
	if ((results_ret = ct_results(conn->command, &result_type)) == CS_SUCCEED) {
		if (result_type != CS_CMD_DONE) {
			ERROR("rlm_sql_freetds: Result failure or unexpected result type from query");

			return RLM_SQL_ERROR;
		}
	} else {
		switch (results_ret) {
		case CS_FAIL: /* Serious failure, freetds requires us to cancel and maybe even close db */
			ERROR("rlm_sql_freetds: Failure retrieving query results");
			if (ct_cancel(NULL, conn->command, CS_CANCEL_ALL) == CS_FAIL) return RLM_SQL_RECONNECT;

			conn->command = NULL;
			return RLM_SQL_ERROR;

		default:
			ERROR("rlm_sql_freetds: Unexpected return value from ct_results()");

			return RLM_SQL_ERROR;
		}
	}

	/*
	 *	Third call to ct_results, we need returncode CS_END_RESULTS result_type will be ignored.
	 */
	results_ret = ct_results(conn->command, &result_type);
	switch (results_ret) {
	case CS_FAIL: /* Serious failure, freetds requires us to cancel and maybe even close db */
		ERROR("rlm_sql_freetds: Failure retrieving query results");
		if (ct_cancel(NULL, conn->command, CS_CANCEL_ALL) == CS_FAIL) return RLM_SQL_RECONNECT;
		conn->command = NULL;

		return RLM_SQL_ERROR;

	case CS_END_RESULTS:  /* This is where we want to end up */
		break;

	default:
		ERROR("rlm_sql_freetds: Unexpected return value from ct_results()");

		return RLM_SQL_ERROR;
	}

	return RLM_SQL_OK;
}

/*************************************************************************
 *
 *	Function: sql_num_fields
 *
 *	Purpose: database specific num_fields function. Returns number
 *	       of columns from query
 *
 *************************************************************************/
static int sql_num_fields(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_freetds_conn_t *conn = handle->conn;
	int num = 0;

	if (ct_res_info(conn->command, CS_NUMDATA, (CS_INT *)&num, CS_UNUSED, NULL) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: Error retrieving column count");

		return RLM_SQL_ERROR;
	}

	return num;
}

/*************************************************************************
 *
 *	Function: sql_fields
 *
 *	Purpose:  Return name of regular result columns.
 *
 *************************************************************************/
static sql_rcode_t sql_fields(char const **out[], rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_freetds_conn_t *conn = handle->conn;
	CS_DATAFMT datafmt;
	int fields, i;
	char const **names;

	/* Get number of elements in row result */
	if (ct_res_info(conn->command, CS_NUMDATA, (CS_INT *)&fields, CS_UNUSED, NULL) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: sql_fields() Error retrieving column count");

		return RLM_SQL_ERROR;
	}

	if (fields <= 0) return RLM_SQL_ERROR;

	MEM(names = talloc_array(handle, char const *, fields));

	for (i = 0; i < fields; i++) {
		int col = i + 1;
		char *p;

		/*
		** Get the column description.  ct_describe() fills the
		** datafmt parameter with a description of the column.
		*/
		if (ct_describe(conn->command, col, &datafmt) != CS_SUCCEED) {
			ERROR("rlm_sql_freetds: sql_fields() Problems with ct_describe(), column %d", col);
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

/** Retrieves any errors associated with the connection handle
 *
 * @note Caller will free any memory allocated in ctx.
 *
 * @param ctx to allocate temporary error buffers in.
 * @param out Array of sql_log_entrys to fill.
 * @param outlen Length of out array.
 * @param handle rlm_sql connection handle.
 * @param config rlm_sql config.
 * @return number of errors written to the sql_log_entry array.
 */
static size_t sql_error(UNUSED TALLOC_CTX *ctx, sql_log_entry_t out[], size_t outlen,
			rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_freetds_conn_t *conn = handle->conn;

	rad_assert(conn && conn->db);
	rad_assert(outlen > 0);

	if (!conn->error) return 0;

	out[0].type = L_ERR;
	out[0].msg = conn->error;

	return 1;
}

static sql_rcode_t sql_finish_select_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_freetds_conn_t *conn = handle->conn;

	ct_cancel(NULL, conn->command, CS_CANCEL_ALL);
	if (ct_cmd_drop(conn->command) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: freeing command structure failed");

		return RLM_SQL_ERROR;
	}
	conn->command = NULL;

	TALLOC_FREE(conn->results);

	return RLM_SQL_OK;

}

/** Execute a query when we expected a result set
 *
 * @note Only the first row from queries returning several rows will be returned by this function,
 * consecutive rows will be discarded.
 *
 */
static sql_rcode_t sql_select_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char const *query)
{
	rlm_sql_freetds_conn_t *conn = handle->conn;

	CS_RETCODE	results_ret;
	CS_INT		result_type;
	CS_DATAFMT	descriptor;

	int		colcount,i;
	char		**rowdata;

	 if (!conn->db) {
		ERROR("rlm_sql_freetds: socket not connected");

		return RLM_SQL_ERROR;
	}

	if (ct_cmd_alloc(conn->db, &conn->command) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: unable to allocate command structure (ct_cmd_alloc())");

		return RLM_SQL_ERROR;
	}

	if (ct_command(conn->command, CS_LANG_CMD, query, CS_NULLTERM, CS_UNUSED) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: unable to initiate command structure (ct_command()");

		return RLM_SQL_ERROR;
	}

	if (ct_send(conn->command) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: unable to send command (ct_send())");
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

			colcount = sql_num_fields(handle, config); /* Get number of elements in row result */

			rowdata = talloc_zero_array(conn, char *, colcount + 1); /* Space for pointers */
			rowdata[colcount] = NULL;

			for (i = 0; i < colcount; i++) {
				/* Space to hold the result data */
				rowdata[i] = talloc_array(rowdata, char, MAX_DATASTR_LEN + 1);

				/* Associate the target buffer with the data */
				if (ct_bind(conn->command, i + 1, &descriptor, rowdata[i], NULL, NULL) != CS_SUCCEED) {
					talloc_free(rowdata);

					ERROR("rlm_sql_freetds: ct_bind() failed)");

					return RLM_SQL_ERROR;
				}

			}

			rowdata[i] = NULL; /* Terminate the array */
			conn->results = rowdata;
			break;

		case CS_CMD_SUCCEED:
		case CS_CMD_DONE:
			ERROR("rlm_sql_freetds: query returned no data");
			break;

		default:

			ERROR("rlm_sql_freetds: unexpected result type from query");
			sql_finish_select_query(handle, config);

			return RLM_SQL_ERROR;
		}
		break;

	case CS_FAIL:

		/*
		 * Serious failure, freetds requires us to cancel the results and maybe even close the db.
		 */

		ERROR("rlm_sql_freetds: failure retrieving query results");

		if (ct_cancel(NULL, conn->command, CS_CANCEL_ALL) == CS_FAIL) {
			ERROR("rlm_sql_freetds: cleaning up");

			return RLM_SQL_RECONNECT;
		}
		conn->command = NULL;

		return RLM_SQL_ERROR;

	default:
		ERROR("rlm_sql_freetds: unexpected return value from ct_results()");

		return RLM_SQL_ERROR;
	}

	return RLM_SQL_OK;
}

static int sql_num_rows(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_freetds_conn_t *conn = handle->conn;
	int	num;

	if (ct_res_info(conn->command, CS_ROW_COUNT, (CS_INT *)&num, CS_UNUSED, NULL) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: error retrieving row count");

		return RLM_SQL_ERROR;
	}

	return num;
}

static sql_rcode_t sql_fetch_row(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_freetds_conn_t *conn = handle->conn;
	CS_INT ret, count;

	handle->row = NULL;

	ret = ct_fetch(conn->command, CS_UNUSED, CS_UNUSED, CS_UNUSED, &count);
	switch (ret) {
	case CS_FAIL:
		/*
		 *	Serious failure, freetds requires us to cancel the results and maybe even close the db.
		 */
		ERROR("rlm_sql_freetds: failure fetching row data");
		if (ct_cancel(NULL, conn->command, CS_CANCEL_ALL) == CS_FAIL) {
			ERROR("rlm_sql_freetds: cleaning up");
		} else {
			conn->command = NULL;
		}

		return RLM_SQL_RECONNECT;

	case CS_END_DATA:
		return RLM_SQL_NO_MORE_ROWS;

	case CS_SUCCEED:
		handle->row = conn->results;

		return RLM_SQL_OK;

	case CS_ROW_FAIL:
		ERROR("rlm_sql_freetds: recoverable failure fetching row data");

		return RLM_SQL_RECONNECT;

	default:
		ERROR("rlm_sql_freetds: unexpected returncode from ct_fetch");

		return RLM_SQL_ERROR;
	}
}

static sql_rcode_t sql_free_result(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{

	/*
	 *	Not implemented, never called from rlm_sql anyway result buffer is freed in the
	 *	finish_query functions.
	 */
	return RLM_SQL_OK;

}

static sql_rcode_t sql_finish_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_freetds_conn_t *conn = handle->conn;

	ct_cancel(NULL, conn->command, CS_CANCEL_ALL);
	if (ct_cmd_drop(conn->command) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: freeing command structure failed");

		return RLM_SQL_ERROR;
	}
	conn->command = NULL;

	return RLM_SQL_OK;
}

static int sql_affected_rows(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	return sql_num_rows(handle, config);
}


static int _sql_socket_destructor(rlm_sql_freetds_conn_t *conn)
{
	DEBUG2("rlm_sql_freetds: socket destructor called, closing socket");

	if (conn->command) {
		ct_cancel(NULL, conn->command, CS_CANCEL_ALL);
		if (ct_cmd_drop(conn->command) != CS_SUCCEED) {
			ERROR("rlm_sql_freetds: freeing command structure failed");

			return RLM_SQL_ERROR;
		}
	}

	if (conn->db) {
		/*
		 *	We first try gracefully closing the connection (which informs the server)
		 *	Then if that fails we force the connection closure.
		 *
		 *	Sybase docs says this may fail because of pending results, but we
		 *	should not have any pending results at this point, so something else must
		 *	of gone wrong.
		 */
		if (ct_close(conn->db, CS_UNUSED) != CS_SUCCEED) {
			ct_close(conn->db, CS_FORCE_CLOSE);
		}

		ct_con_drop(conn->db);
	}

	if (conn->context) {
		ct_exit(conn->context, CS_UNUSED);
		cs_ctx_drop(conn->context);
	}

	return RLM_SQL_OK;
}

static sql_rcode_t sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config)
{
	rlm_sql_freetds_conn_t *conn;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_freetds_conn_t));
	talloc_set_destructor(conn, _sql_socket_destructor);

	/*
	 *	Allocate a CS context structure. This should really only be done once, but because of
	 *	the db pooling design of rlm_sql, we'll have to go with one context per db
	 */
	if (cs_ctx_alloc(CS_VERSION_100, &conn->context) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: unable to allocate CS context structure (cs_ctx_alloc())");

		goto error;
	}

	/*
	 *	Initialize ctlib
	 */
	if (ct_init(conn->context, CS_VERSION_100) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: unable to initialize Client-Library");

		goto error;
	}

	/*
	 *	Install callback functions for error-handling
	 */
	if (cs_config(conn->context, CS_SET, CS_MESSAGE_CB, (CS_VOID *)csmsg_callback, CS_UNUSED, NULL) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: unable to install CS Library error callback");

		goto error;
	}

	if (cs_config(conn->context, CS_SET, CS_USERDATA,
		      (CS_VOID *)&handle->conn, sizeof(handle->conn), NULL) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: unable to set userdata pointer");

		goto error;
	}

	if (ct_callback(conn->context, NULL, CS_SET, CS_CLIENTMSG_CB, (CS_VOID *)clientmsg_callback) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: unable to install client message callback");

		goto error;
	}

	if (ct_callback(conn->context, NULL, CS_SET, CS_SERVERMSG_CB, (CS_VOID *)servermsg_callback) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: unable to install server message callback");

		goto error;
	}

	/*
	 *	Allocate a ctlib db structure
	 */
	if (ct_con_alloc(conn->context, &conn->db) != CS_SUCCEED) {
		ERROR("rlm_sql_freetds: unable to allocate db structure");

		goto error;
	}

	/*
	 *	Set User and Password properties for the db
	 */
	{
		CS_VOID *login, *password;
		CS_CHAR *server;
		char database[128];

		memcpy(&login, &config->sql_login, sizeof(login));
		if (ct_con_props(conn->db, CS_SET, CS_USERNAME, login, strlen(config->sql_login), NULL) != CS_SUCCEED) {
			ERROR("rlm_sql_freetds: unable to set username for db");

			goto error;
		}

		memcpy(&password, &config->sql_password, sizeof(password));
		if (ct_con_props(conn->db, CS_SET, CS_PASSWORD,
				 password, strlen(config->sql_password), NULL) != CS_SUCCEED) {
			ERROR("rlm_sql_freetds: unable to set password for db");

			goto error;
		}

		/*
		 *	Connect to the database
		 */
		memcpy(&server, &config->sql_server, sizeof(server));
		if (ct_connect(conn->db, server, strlen(config->sql_server)) != CS_SUCCEED) {
			ERROR("rlm_sql_freetds: unable to establish db to symbolic servername %s",
			      config->sql_server);

			goto error;
		}

		/*
		 *	There doesn't appear to be a way to set the database with the API, so use an
		 *	sql statement when we first open the connection.
		 */
		snprintf(database, sizeof(database), "USE %s;", config->sql_db);
		if (sql_query(handle, config, database) != RLM_SQL_OK) {
			goto error;
		}

		sql_finish_query(handle, config);
	}

	return RLM_SQL_OK;

error:
	if (conn->context) {
		sql_log_entry_t	error;

		if (sql_error(NULL, &error, 1, handle, config) > 0) ERROR("rlm_sql_freetds: %s", error.msg);
	}

	return RLM_SQL_ERROR;
}

/* Exported to rlm_sql */
extern rlm_sql_module_t rlm_sql_freetds;
rlm_sql_module_t rlm_sql_freetds = {
	.name				= "rlm_sql_freetds",
	.sql_socket_init		= sql_socket_init,
	.sql_query			= sql_query,
	.sql_select_query		= sql_select_query,
	.sql_num_fields			= sql_num_fields,
	.sql_num_rows			= sql_num_rows,
	.sql_fields			= sql_fields,
	.sql_affected_rows		= sql_affected_rows,
	.sql_fetch_row			= sql_fetch_row,
	.sql_free_result		= sql_free_result,
	.sql_error			= sql_error,
	.sql_finish_query		= sql_finish_query,
	.sql_finish_select_query	= sql_finish_select_query
};
