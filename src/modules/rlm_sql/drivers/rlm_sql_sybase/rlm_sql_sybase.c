/*
 * sql_sybase.c	Sybase (ctlibrary) routines for rlm_sql
 *		Error handling stolen from Sybase example code "firstapp.c"
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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Mattias Sjostrom <mattias@nogui.se>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include <sys/stat.h>

#include <ctpublic.h>

#include "rlm_sql.h"


typedef struct rlm_sql_sybase_conn {
	CS_CONTEXT	*context;
	CS_CONNECTION	*db;
	CS_COMMAND	*command;
	char		**results;
	int		id;
	int		in_use;
	struct timeval	tv;
} rlm_sql_sybase_conn_t;


#define	MAX_DATASTR_LEN	256

/************************************************************************
*  Client-Library error handler.
************************************************************************/

static CS_RETCODE CS_PUBLIC clientmsg_callback(UNUSED CS_CONTEXT *context,
					       UNUSED CS_CONNECTION *conn,
					       CS_CLIENTMSG *emsgp)
{

	/*
	** Error number: Print the error's severity, number, origin, and
	** layer. These four numbers uniquely identify the error.
	*/
	radlog(L_ERR,
		"Client Library error:\n");
	radlog(L_ERR,
		"severity(%ld) number(%ld) origin(%ld) layer(%ld)\n",
		(long)CS_SEVERITY(emsgp->severity),
		(long)CS_NUMBER(emsgp->msgnumber),
		(long)CS_ORIGIN(emsgp->msgnumber),
		(long)CS_LAYER(emsgp->msgnumber));

	/*
	** Error text: Print the error text.
	*/
	radlog(L_ERR, "%s\n", emsgp->msgstring);

	if (emsgp->osstringlen > 0)
	{
		radlog(L_ERR,
			"Operating system error number(%ld):\n",
			(long)emsgp->osnumber);
		radlog(L_ERR, "%s\n", emsgp->osstring);
	}

	return (CS_SUCCEED);
}

/************************************************************************
*  CS-Library error handler. This function will be invoked
*  when CS-Library has detected an error.
************************************************************************/

static CS_RETCODE CS_PUBLIC
csmsg_callback(UNUSED CS_CONTEXT *context, CS_CLIENTMSG *emsgp)
{

	/*
	** Print the error number and message.
	*/
	radlog(L_ERR,
		"CS-Library error:\n");
	radlog(L_ERR,
		"\tseverity(%ld) layer(%ld) origin(%ld) number(%ld)",
		(long)CS_SEVERITY(emsgp->msgnumber),
		(long)CS_LAYER(emsgp->msgnumber),
		(long)CS_ORIGIN(emsgp->msgnumber),
		(long)CS_NUMBER(emsgp->msgnumber));

	radlog(L_ERR, "%s\n", emsgp->msgstring);

	/*
	** Print any operating system error information.
	*/
	if (emsgp->osstringlen > 0)
	{
		radlog(L_ERR, "Operating System Error: %s\n",
			emsgp->osstring);
	}

	return (CS_SUCCEED);
}

/************************************************************************
* Handler for server messages. Client-Library will call this
* routine when it receives a message from the server.
************************************************************************/

static CS_RETCODE CS_PUBLIC servermsg_callback(UNUSED CS_CONTEXT *cp,
					       UNUSED CS_CONNECTION *chp,
					       CS_SERVERMSG *msgp)
{

	/*
	** Print the message info.
	*/
	radlog(L_ERR,
		"Sybase Server message:\n");
	radlog(L_ERR,
		"number(%ld) severity(%ld) state(%ld) line(%ld)\n",
		(long)msgp->msgnumber, (long)msgp->severity,
		(long)msgp->state, (long)msgp->line);

	/*
	** Print the server and procedure names if supplied.
	*/
	if (msgp->svrnlen > 0 && msgp->proclen > 0)
		radlog(L_ERR, "Server name: %s   Procedure name: %s", msgp->svrname, msgp->proc);

	/*
	** Print the null terminated message.
	*/
	radlog(L_ERR, "%s\n", msgp->text);

	/*
	** Server message callbacks must return CS_SUCCEED.
	*/
	return (CS_SUCCEED);
}

/*************************************************************************
 *
 *	Function: sql_error
 *
 *	Purpose: database specific error. Returns error associated with
 *	       db
 *
 *************************************************************************/
static const char *sql_error(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	static char	msg='\0';
/*
	static char	msgbuf[2048];

	rlm_sql_sybase_conn_t *conn = handle->conn;
	CS_INT		msgcount;
	CS_CLIENTMSG	cmsg;
	CS_SERVERMSG	smsg;

	int		i;
	char		ctempbuf[2][512];
	char		stempbuf[2][512];

	msgbuf[0]=(char)NULL;
	ctempbuf[0][0]=(char)NULL;
	ctempbuf[1][0]=(char)NULL;
	stempbuf[0][0]=(char)NULL;
	stempbuf[1][0]=(char)NULL;

	if (ct_diag(conn->db, CS_STATUS, CS_CLIENTMSG_TYPE, CS_UNUSED, &msgcount) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_error): Failed to get number of pending Client messages");
		return msgbuf;
	}
	radlog(L_ERR,"rlm_sql_sybase(sql_error): Number of pending Client messages: %d", (int)msgcount);

	for (i=1; i<=msgcount; i++) {
		if (ct_diag(conn->db, CS_GET, CS_CLIENTMSG_TYPE, (CS_INT)i, &cmsg) != CS_SUCCEED) {
			radlog(L_ERR,"rlm_sql_sybase(sql_error): Failed to retrieve pending Client message");
			return msgbuf;
		}
		sprintf(ctempbuf[i-1],"rlm_sql_sybase: Client Library Error: severity(%ld) number(%ld) origin(%ld) layer(%ld):\n%s",
				(long)CS_SEVERITY(cmsg.severity),
				(long)CS_NUMBER(cmsg.msgnumber),
				(long)CS_ORIGIN(cmsg.msgnumber),
				(long)CS_LAYER(cmsg.msgnumber),
				cmsg.msgstring);
	}


	if (ct_diag(conn->db, CS_STATUS, CS_SERVERMSG_TYPE, CS_UNUSED, &msgcount) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_error): Failed to get number of pending Server messages");
		return msgbuf;
	}
	radlog(L_ERR,"rlm_sql_sybase(sql_error): Number of pending Server messages: %d", (int)msgcount);

	for (i=1; i<=msgcount; i++) {
		if (ct_diag(conn->db, CS_GET, CS_SERVERMSG_TYPE, (CS_INT)i, &smsg) != CS_SUCCEED) {
			radlog(L_ERR,"rlm_sql_sybase(sql_error): Failed to retrieve pending Server message");
			return msgbuf;
		}
		sprintf(stempbuf[i-1],"rlm_sql_sybase: Server message: severity(%ld) number(%ld) origin(%ld) layer(%ld):\n%s",
				(long)CS_SEVERITY(cmsg.severity),
				(long)CS_NUMBER(cmsg.msgnumber),
				(long)CS_ORIGIN(cmsg.msgnumber),
				(long)CS_LAYER(cmsg.msgnumber),
				cmsg.msgstring);
	}
	sprintf(msgbuf,"%s || %s || %s || %s", ctempbuf[1], ctempbuf[2], stempbuf[1], stempbuf[2]);

	return msgbuf;
*/
	return &msg;
}

static int sql_socket_destructor(void *c)
{
	int status = 0;
	rlm_sql_sybase_conn_t *conn = c;
	
	DEBUG2("rlm_sql_sybase: Socket destructor called, closing socket");
	
	if (conn->db) {
		ct_close(conn->db, CS_FORCE_CLOSE);
	}
	
	return 0;
}

/*************************************************************************
 *
 *	Function: sql_socket_init
 *
 *	Purpose: Establish db to the db
 *
 *************************************************************************/
static int sql_socket_init(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {

	rlm_sql_sybase_conn_t *conn;

	MEM(conn = handle->conn = talloc_zero(handle, rlm_sql_sybase_conn_t));
	talloc_set_destructor((void *) conn, sql_socket_destructor);

	conn->results = NULL;

	/* Allocate a CS context structure. This should really only be done once, but because of
	   the db pooling design of rlm_sql, we'll have to go with one context per db */

	if (cs_ctx_alloc(CS_VERSION_100, &conn->context) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_socket_init): Unable to allocate CS context structure (cs_ctx_alloc())");
		return -1;
	}

	/* Initialize ctlib */

	if (ct_init(conn->context, CS_VERSION_100) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_socket_init): Unable to initialize Client-Library (ct_init())");
		if (conn->context != (CS_CONTEXT *)NULL) {
			cs_ctx_drop(conn->context);
		}
		return -1;
	}

	/* Install callback functions for error-handling */

	if (cs_config(conn->context, CS_SET, CS_MESSAGE_CB, (CS_VOID *)csmsg_callback, CS_UNUSED, NULL) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_socket_init): Unable to install CS Library error callback");
		if (conn->context != (CS_CONTEXT *)NULL) {
			ct_exit(conn->context, CS_FORCE_EXIT);
			cs_ctx_drop(conn->context);
		}
		return -1;
	}

	if (ct_callback(conn->context, NULL, CS_SET, CS_CLIENTMSG_CB, (CS_VOID *)clientmsg_callback) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_socket_init): Unable to install client message callback");
		if (conn->context != (CS_CONTEXT *)NULL) {
			ct_exit(conn->context, CS_FORCE_EXIT);
			cs_ctx_drop(conn->context);
		}
		return -1;
	}

	if (ct_callback(conn->context, NULL, CS_SET, CS_SERVERMSG_CB, (CS_VOID *)servermsg_callback) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_socket_init): Unable to install client message callback");
		if (conn->context != (CS_CONTEXT *)NULL) {
			ct_exit(conn->context, CS_FORCE_EXIT);
			cs_ctx_drop(conn->context);
		}
		return -1;
	}

	/* Allocate a ctlib db structure */

	if (ct_con_alloc(conn->context, &conn->db) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_socket_init): Unable to allocate db structure (ct_con_alloc())");
		if (conn->context != (CS_CONTEXT *)NULL) {
			ct_exit(conn->context, CS_FORCE_EXIT);
			cs_ctx_drop(conn->context);
		}
		return -1;
	}

	/* Initialize inline error handling for the db */

/*	if (ct_diag(conn->db, CS_INIT, CS_UNUSED, CS_UNUSED, NULL) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_socket_init): Unable to initialize error handling (ct_diag())");
		if (conn->context != (CS_CONTEXT *)NULL) {
			ct_exit(conn->context, CS_FORCE_EXIT);
			cs_ctx_drop(conn->context);
		}
		return -1;
	} */



	/* Set User and Password properties for the db */

	if (ct_con_props(conn->db, CS_SET, CS_USERNAME, config->sql_login,
					 strlen(config->sql_login), NULL) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_socket_init): Unable to set username for db (ct_con_props())\n%s",
		sql_error(handle, config));
		if (conn->context != (CS_CONTEXT *)NULL) {
			ct_exit(conn->context, CS_FORCE_EXIT);
			cs_ctx_drop(conn->context);
		}
		return -1;
	}

	if (ct_con_props(conn->db, CS_SET, CS_PASSWORD, config->sql_password,
					strlen(config->sql_password), NULL) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_socket_init): Unable to set password for db (ct_con_props())\n%s",
		sql_error(handle, config));
		if (conn->context != (CS_CONTEXT *)NULL) {
			ct_exit(conn->context, CS_FORCE_EXIT);
			cs_ctx_drop(conn->context);
		}
		return -1;
	}

	/* Establish the db */

	if (ct_connect(conn->db, config->sql_server, strlen(config->sql_server)) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_socket_init): Unable to establish db to symbolic servername %s\n%s",
				config->sql_server, sql_error(handle, config));
		if (conn->context != (CS_CONTEXT *)NULL) {
			ct_exit(conn->context, CS_FORCE_EXIT);
			cs_ctx_drop(conn->context);
		}
		return -1;
	}
	return 0;
}

/*************************************************************************
 *
 *	Function: sql_query
 *
 *	Purpose: Issue a non-SELECT query (ie: update/delete/insert) to
 *	       the database.
 *
 *************************************************************************/
static int sql_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char *querystr) {

	rlm_sql_sybase_conn_t *conn = handle->conn;

	CS_RETCODE	ret, results_ret;
	CS_INT		result_type;

	 if (!conn->db) {
		radlog(L_ERR, "Socket not connected");
		return -1;
	}

	if (ct_cmd_alloc(conn->db, &conn->command) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_query): Unable to allocate command structure (ct_cmd_alloc())\n%s",
				sql_error(handle, config));
		return -1;
	}

	if (ct_command(conn->command, CS_LANG_CMD, querystr, CS_NULLTERM, CS_UNUSED) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_query): Unable to initiate command structure (ct_command())\n%s",
				sql_error(handle, config));
		return -1;
	}

	if (ct_send(conn->command) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_query): Unable to send command (ct_send())\n%s",
				sql_error(handle, config));
		return -1;
	}

	/*
	** We'll make three calls to ct_results, first to get a success indicator, secondly to get a done indicator, and
	** thirdly to get a "nothing left to handle" status.
	*/

	/*
	** First call to ct_results,
	** we need returncode CS_SUCCEED
	** and result_type CS_CMD_SUCCEED.
	*/

	if ((results_ret = ct_results(conn->command, &result_type)) == CS_SUCCEED) {
		if (result_type != CS_CMD_SUCCEED) {
			if  (result_type == CS_ROW_RESULT) {
				radlog(L_ERR,"rlm_sql_sybase(sql_query): sql_query processed a query returning rows. Use sql_select_query instead!");
			}
			radlog(L_ERR,"rlm_sql_sybase(sql_query): Result failure or unexpected result type from query\n%s",
					 sql_error(handle, config));
			return -1;
		}
	}
	else {
		switch ((int) results_ret)
		{

		case CS_FAIL: /* Serious failure, sybase requires us to cancel and maybe even close db */
			radlog(L_ERR,"rlm_sql_sybase(sql_query): Failure retrieving query results\n%s"
					, sql_error(handle, config));
			if ((ret = ct_cancel(NULL, conn->command, CS_CANCEL_ALL)) == CS_FAIL) {
				radlog(L_ERR,"rlm_sql_sybase(sql_query): cleaning up.");

				return SQL_DOWN;
			}
			return -1;
			break;

		default:
			radlog(L_ERR,"rlm_sql_sybase(sql_query): Unexpected return value from ct_results()\n%s",
					sql_error(handle, config));
			return -1;
		}
	}


	/*
	** Second call to ct_results,
	** we need returncode CS_SUCCEED
	** and result_type CS_CMD_DONE.
	*/

	if ((results_ret = ct_results(conn->command, &result_type)) == CS_SUCCEED) {
		if (result_type != CS_CMD_DONE) {
			radlog(L_ERR,"rlm_sql_sybase(sql_query): Result failure or unexpected result type from query\n%s",
					 sql_error(handle, config));
			return -1;
		}
	}
	else {
		switch ((int) results_ret)
		{

		case CS_FAIL: /* Serious failure, sybase requires us to cancel and maybe even close db */
			radlog(L_ERR,"rlm_sql_sybase(sql_query): Failure retrieving query results\n%s"
					, sql_error(handle, config));
			if ((ret = ct_cancel(NULL, conn->command, CS_CANCEL_ALL)) == CS_FAIL) {
				radlog(L_ERR,"rlm_sql_sybase(sql_query): cleaning up.");
				
				return SQL_DOWN;
			}
			return -1;
			break;

		default:
			radlog(L_ERR,"rlm_sql_sybase(sql_query): Unexpected return value from ct_results()\n%s",
					sql_error(handle, config));
			return -1;
		}
	}


	/*
	** Third call to ct_results,
	** we need returncode CS_END_RESULTS
	** result_type will be ignored.
	*/

	results_ret = ct_results(conn->command, &result_type);

	switch ((int) results_ret)
	{

	case CS_FAIL: /* Serious failure, sybase requires us to cancel and maybe even close db */
		radlog(L_ERR,"rlm_sql_sybase(sql_query): Failure retrieving query results\n%s"
				, sql_error(handle, config));
		if ((ret = ct_cancel(NULL, conn->command, CS_CANCEL_ALL)) == CS_FAIL) {
			radlog(L_ERR,"rlm_sql_sybase(sql_query): cleaning up.");
	
			return SQL_DOWN;
		}
		return -1;
		break;

	case CS_END_RESULTS:  /* This is where we want to end up */
		break;

	default:
		radlog(L_ERR,"rlm_sql_sybase(sql_query): Unexpected return value from ct_results()\n%s",
				sql_error(handle, config));
		return -1;
		break;
	}
	return 0;
}

/*************************************************************************
 *
 *	Function: sql_num_fields
 *
 *	Purpose: database specific num_fields function. Returns number
 *	       of columns from query
 *
 *************************************************************************/
static int sql_num_fields(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {

	rlm_sql_sybase_conn_t *conn = handle->conn;
	int	num;

	if (ct_res_info(conn->command, CS_NUMDATA, (CS_INT *)&num, CS_UNUSED, NULL) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_num_fields): error retrieving column count: %s",
			sql_error(handle, config));
		return -1;
	}
	return num;
}

/*************************************************************************
 *
 *	Function: sql_finish_select_query
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
static int sql_finish_select_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config) {

	rlm_sql_sybase_conn_t *conn = handle->conn;
	int	i=0;

	ct_cancel(NULL, conn->command, CS_CANCEL_ALL);

	if (ct_cmd_drop(conn->command) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_finish_select_query): Freeing command structure failed.");
		return -1;
	}

	if (conn->results) {
		while(conn->results[i]) free(conn->results[i++]);
		free(conn->results);
		conn->results=NULL;
	}

	return 0;

}

/*************************************************************************
 *
 *	Function: sql_select_query
 *
 *	Purpose: Issue a select query to the database
 *
 *	Note: Only the first row from queries returning several rows
 *	      will be returned by this function, consequitive rows will
 *	      be discarded.
 *
 *************************************************************************/
static int sql_select_query(rlm_sql_handle_t *handle, rlm_sql_config_t *config, char *querystr) {

	rlm_sql_sybase_conn_t *conn = handle->conn;

	CS_RETCODE	ret, results_ret;
	CS_INT		result_type;
	CS_DATAFMT	descriptor;

	int		colcount,i;
	char		**rowdata;

	 if (!conn->db) {
		radlog(L_ERR, "Socket not connected");
		return -1;
	}


	if (ct_cmd_alloc(conn->db, &conn->command) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_select_query): Unable to allocate command structure (ct_cmd_alloc())\n%s",
				sql_error(handle, config));
		return -1;
	}

	if (ct_command(conn->command, CS_LANG_CMD, querystr, CS_NULLTERM, CS_UNUSED) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_select_query): Unable to initiate command structure (ct_command())\n%s",
				sql_error(handle, config));
		return -1;
	}

	if (ct_send(conn->command) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_select_query): Unable to send command (ct_send())\n%s",
				sql_error(handle, config));
		return -1;
	}

	results_ret = ct_results(conn->command, &result_type);

	switch (results_ret) {

	case CS_SUCCEED:

		switch (result_type) {

		case CS_ROW_RESULT:

		/*
		** Houston, we have a row.
		**
		** We set up a target buffer for the results data, and
		** associate the buffer with the results, but the actual
		** fetching takes place in sql_fetch_row. The layer above
		** MUST call sql_fetch_row and/or sql_finish_select_query
		** or this socket will be unusable and may cause segfaults
		** if reused later on.
		*/

			/*
			** Set up the DATAFMT structure that describes our target array
			** and tells sybase what we want future ct_fetch calls to do.
			*/
			descriptor.datatype = CS_CHAR_TYPE; 	/* The target buffer is a string */
			descriptor.format = CS_FMT_NULLTERM;	/* Null termination please */
			descriptor.maxlength = MAX_DATASTR_LEN;	/* The string arrays are this large */
			descriptor.count = 1;			/* Fetch one row of data */
			descriptor.locale = NULL;		/* Don't do NLS stuff */


			colcount = sql_num_fields(handle, config); /* Get number of elements in row result */


			rowdata=(char **)rad_malloc(sizeof(char *) * (colcount+1));	/* Space for pointers */
			memset(rowdata, 0, (sizeof(char *) * colcount+1));  /* NULL-pad the pointers */

			for (i=0; i < colcount; i++) {

				rowdata[i]=rad_malloc((MAX_DATASTR_LEN * sizeof(char))+1); /* Space to hold the result data */

				/* Associate the target buffer with the data */
				if (ct_bind(conn->command, i+1, &descriptor, rowdata[i], NULL, NULL) != CS_SUCCEED) {
					int j;

					for (j = 0; j <= i; j++) {
						free(rowdata[j]);
					}
					free(rowdata);
					radlog(L_ERR,"rlm_sql_sybase(sql_select_query): ct_bind() failed)\n%s",
							sql_error(handle, config));
					return -1;
				}

			}
			rowdata[i]=NULL; /* Terminate the array */
			conn->results=rowdata;
			break;

		case CS_CMD_SUCCEED:
		case CS_CMD_DONE:

			radlog(L_ERR,"rlm_sql_sybase(sql_select_query): Query returned no data");
			break;

		default:

			radlog(L_ERR,"rlm_sql_sybase(sql_select_query): Unexpected result type from query\n%s",
					 sql_error(handle, config));
			sql_finish_select_query(handle, config);
			return -1;
			break;
		}
		break;

	case CS_FAIL:

		/*
		** Serious failure, sybase requires us to cancel
		** the results and maybe even close the db.
		*/

		radlog(L_ERR,"rlm_sql_sybase(sql_select_query): Failure retrieving query results\n%s"
				, sql_error(handle, config));
		if ((ret = ct_cancel(NULL, conn->command, CS_CANCEL_ALL)) == CS_FAIL) {
			radlog(L_ERR,"rlm_sql_sybase(sql_select_query): cleaning up.");

			return SQL_DOWN;
		}
		return -1;
		break;

	default:

		radlog(L_ERR,"rlm_sql_sybase(sql_select_query): Unexpected return value from ct_results()\n%s",
				sql_error(handle, config));
		return -1;
		break;
	}
	return 0;
}


/*************************************************************************
 *
 *	Function: sql_store_result
 *
 *	Purpose: database specific store_result function. Returns a result
 *	       set for the query.
 *
 *************************************************************************/
static int sql_store_result(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config) {
	/*
	** Not needed for Sybase, code that may have gone here is
	** in sql_select_query and sql_fetch_row
	*/
	return 0;
}




/*************************************************************************
 *
 *	Function: sql_num_rows
 *
 *	Purpose: database specific num_rows. Returns number of rows in
 *	       query
 *
 *************************************************************************/
static int sql_num_rows(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {

	rlm_sql_sybase_conn_t *conn = handle->conn;
	int	num;

	if (ct_res_info(conn->command, CS_ROW_COUNT, (CS_INT *)&num, CS_UNUSED, NULL) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_num_rows): error retrieving row count: %s",
			sql_error(handle, config));
		return -1;
	}
	return num;
}


/*************************************************************************
 *
 *	Function: sql_fetch_row
 *
 *	Purpose: database specific fetch_row. Returns a rlm_sql_row_t struct
 *	       with all the data for the query in 'handle->row'. Returns
 *		 0 on success, -1 on failure, SQL_DOWN if 'database is down'.
 *
 *************************************************************************/
static int sql_fetch_row(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {

	rlm_sql_sybase_conn_t *conn = handle->conn;
	CS_INT		ret, count;

	handle->row = NULL;


	ret = ct_fetch(conn->command, CS_UNUSED, CS_UNUSED, CS_UNUSED, &count);

	switch (ret) {

	case CS_FAIL:

		/*
		** Serious failure, sybase requires us to cancel
		** the results and maybe even close the db.
		*/

		radlog(L_ERR,"rlm_sql_sybase(sql_fetch_row): Failure fething row data\n%s"
				, sql_error(handle, config));
		if ((ret = ct_cancel(NULL, conn->command, CS_CANCEL_ALL)) == CS_FAIL) {
			radlog(L_ERR,"rlm_sql_sybase(sql_fetch_row): cleaning up.");

			return SQL_DOWN;
		}
		return SQL_DOWN;
		break;

	case CS_END_DATA:

		return 0;
		break;

	case CS_SUCCEED:

		handle->row = conn->results;
		return 0;
		break;

	case CS_ROW_FAIL:

		radlog(L_ERR,"rlm_sql_sybase(sql_fetch_row): Recoverable failure fething row data, try again perhaps?");
		return -1;

	default:

		radlog(L_ERR,"rlm_sql_sybase(sql_fetch_row): Unexpected returncode from ct_fetch");
		return -1;
		break;
	}

}



/*************************************************************************
 *
 *	Function: sql_free_result
 *
 *	Purpose: database specific free_result. Frees memory allocated
 *	       for a result set
 *
 *************************************************************************/
static int sql_free_result(UNUSED rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config) {

	/*
	** Not implemented, never called from rlm_sql anyway
	** result buffer is freed in the finish_query functions.
	*/

	return 0;

}

/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
static int sql_finish_query(rlm_sql_handle_t *handle, UNUSED rlm_sql_config_t *config)
{
	rlm_sql_sybase_conn_t *conn = handle->conn;

	ct_cancel(NULL, conn->command, CS_CANCEL_ALL);

	if (ct_cmd_drop(conn->command) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_finish_query): Freeing command structure failed.");
		return -1;
	}

	return 0;
}

/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: Return the number of rows affected by the query (update,
 *	       or insert)
 *
 *************************************************************************/
static int sql_affected_rows(rlm_sql_handle_t *handle, rlm_sql_config_t *config) {

	return sql_num_rows(handle, config);

}




/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_sybase = {
	"rlm_sql_sybase",
	NULL,
	sql_socket_init,
	sql_query,
	sql_select_query,
	sql_store_result,
	sql_num_fields,
	sql_num_rows,
	sql_fetch_row,
	sql_free_result,
	sql_error,
	sql_finish_query,
	sql_finish_select_query,
	sql_affected_rows
};
