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


typedef struct rlm_sql_sybase_sock {
	CS_CONTEXT	*context;
	CS_CONNECTION	*connection;
	CS_COMMAND	*command;
	char		**results;
	int		id;
	int		in_use;
	struct timeval	tv;
} rlm_sql_sybase_sock;


#define	MAX_DATASTR_LEN	256

/************************************************************************
* Handler for server messages. Client-Library will call this
* routine when it receives a message from the server.
************************************************************************/

static CS_RETCODE CS_PUBLIC
servermsg_callback(cp, chp, msgp)
CS_CONTEXT         *cp;
CS_CONNECTION      *chp;
CS_SERVERMSG       *msgp;
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

/************************************************************************
*  Client-Library error handler.
************************************************************************/

static CS_RETCODE CS_PUBLIC
clientmsg_callback(context, conn, emsgp)
CS_CONTEXT         *context;
CS_CONNECTION      *conn;
CS_CLIENTMSG       *emsgp;
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
csmsg_callback(context, emsgp)
CS_CONTEXT         *context;
CS_CLIENTMSG       *emsgp;
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

/*************************************************************************
 *
 *	Function: sql_init_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
static int sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	rlm_sql_sybase_sock *sybase_sock;


	if (!sqlsocket->conn) {
		sqlsocket->conn = (rlm_sql_sybase_sock *)rad_malloc(sizeof(rlm_sql_sybase_sock));
		if (!sqlsocket->conn) {
			return -1;
		}
	}
	sybase_sock = sqlsocket->conn;
	memset(sybase_sock, 0, sizeof(*sybase_sock));

	sybase_sock->results=NULL;

	/* Allocate a CS context structure. This should really only be done once, but because of
	   the connection pooling design of rlm_sql, we'll have to go with one context per connection */

	if (cs_ctx_alloc(CS_VERSION_100, &sybase_sock->context) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_init_socket): Unable to allocate CS context structure (cs_ctx_alloc())");
		return -1;
	}

	/* Initialize ctlib */

	if (ct_init(sybase_sock->context, CS_VERSION_100) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_init_socket): Unable to initialize Client-Library (ct_init())");
		if (sybase_sock->context != (CS_CONTEXT *)NULL) {
			cs_ctx_drop(sybase_sock->context);
		}
		return -1;
	}

	/* Install callback functions for error-handling */

        if (cs_config(sybase_sock->context, CS_SET, CS_MESSAGE_CB, (CS_VOID *)csmsg_callback, CS_UNUSED, NULL) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_init_socket): Unable to install CS Library error callback");
                if (sybase_sock->context != (CS_CONTEXT *)NULL) {
                        ct_exit(sybase_sock->context, CS_FORCE_EXIT);
                        cs_ctx_drop(sybase_sock->context);
                }
		return -1;
	}

	if (ct_callback(sybase_sock->context, NULL, CS_SET, CS_CLIENTMSG_CB, (CS_VOID *)clientmsg_callback) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_init_socket): Unable to install client message callback");
                if (sybase_sock->context != (CS_CONTEXT *)NULL) {
                        ct_exit(sybase_sock->context, CS_FORCE_EXIT);
                        cs_ctx_drop(sybase_sock->context);
                }
		return -1;
	}

	if (ct_callback(sybase_sock->context, NULL, CS_SET, CS_SERVERMSG_CB, (CS_VOID *)servermsg_callback) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_init_socket): Unable to install client message callback");
                if (sybase_sock->context != (CS_CONTEXT *)NULL) {
                        ct_exit(sybase_sock->context, CS_FORCE_EXIT);
                        cs_ctx_drop(sybase_sock->context);
                }
		return -1;
	}

	/* Allocate a ctlib connection structure */

	if (ct_con_alloc(sybase_sock->context, &sybase_sock->connection) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_init_socket): Unable to allocate connection structure (ct_con_alloc())");
		if (sybase_sock->context != (CS_CONTEXT *)NULL) {
			ct_exit(sybase_sock->context, CS_FORCE_EXIT);
			cs_ctx_drop(sybase_sock->context);
		}
		return -1;
	}

	/* Initialize inline error handling for the connection */

/*	if (ct_diag(sybase_sock->connection, CS_INIT, CS_UNUSED, CS_UNUSED, NULL) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_init_socket): Unable to initialize error handling (ct_diag())");
                if (sybase_sock->context != (CS_CONTEXT *)NULL) {
                        ct_exit(sybase_sock->context, CS_FORCE_EXIT);
                        cs_ctx_drop(sybase_sock->context);
                }
		return -1;
	} */



	/* Set User and Password properties for the connection */

	if (ct_con_props(sybase_sock->connection, CS_SET, CS_USERNAME, config->sql_login,
					 strlen(config->sql_login), NULL) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_init_socket): Unable to set username for connection (ct_con_props())\n%s",
		sql_error(sqlsocket, config));
		if (sybase_sock->context != (CS_CONTEXT *)NULL) {
			ct_exit(sybase_sock->context, CS_FORCE_EXIT);
			cs_ctx_drop(sybase_sock->context);
		}
		return -1;
	}

	if (ct_con_props(sybase_sock->connection, CS_SET, CS_PASSWORD, config->sql_password,
					strlen(config->sql_password), NULL) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_init_socket): Unable to set password for connection (ct_con_props())\n%s",
		sql_error(sqlsocket, config));
		if (sybase_sock->context != (CS_CONTEXT *)NULL) {
			ct_exit(sybase_sock->context, CS_FORCE_EXIT);
			cs_ctx_drop(sybase_sock->context);
		}
		return -1;
	}

	/* Establish the connection */

	if (ct_connect(sybase_sock->connection, config->sql_server, strlen(config->sql_server)) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_init_socket): Unable to establish connection to symbolic servername %s\n%s",
				config->sql_server, sql_error(sqlsocket, config));
		if (sybase_sock->context != (CS_CONTEXT *)NULL) {
			ct_exit(sybase_sock->context, CS_FORCE_EXIT);
			cs_ctx_drop(sybase_sock->context);
		}
		return -1;
	}
	return 0;
}


/*************************************************************************
 *
 *	Function: sql_destroy_socket
 *
 *	Purpose: Free socket and private connection data
 *
 *************************************************************************/
static int sql_destroy_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config)
{
	free(sqlsocket->conn);
	sqlsocket->conn = NULL;
	return 0;
}

/*************************************************************************
 *
 *	Function: sql_query
 *
 *	Purpose: Issue a non-SELECT query (ie: update/delete/insert) to
 *               the database.
 *
 *************************************************************************/
static int sql_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr) {

	rlm_sql_sybase_sock *sybase_sock = sqlsocket->conn;

	CS_RETCODE	ret, results_ret;
	CS_INT		result_type;

	 if (sybase_sock->connection == NULL) {
		radlog(L_ERR, "Socket not connected");
		return -1;
	}

	if (ct_cmd_alloc(sybase_sock->connection, &sybase_sock->command) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_query): Unable to allocate command structure (ct_cmd_alloc())\n%s",
				sql_error(sqlsocket, config));
		return -1;
	}

	if (ct_command(sybase_sock->command, CS_LANG_CMD, querystr, CS_NULLTERM, CS_UNUSED) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_query): Unable to initiate command structure (ct_command())\n%s",
				sql_error(sqlsocket, config));
		return -1;
	}

	if (ct_send(sybase_sock->command) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_query): Unable to send command (ct_send())\n%s",
				sql_error(sqlsocket, config));
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

	if ((results_ret = ct_results(sybase_sock->command, &result_type)) == CS_SUCCEED) {
		if (result_type != CS_CMD_SUCCEED) {
			if  (result_type == CS_ROW_RESULT) {
				radlog(L_ERR,"rlm_sql_sybase(sql_query): sql_query processed a query returning rows. Use sql_select_query instead!");
			}
			radlog(L_ERR,"rlm_sql_sybase(sql_query): Result failure or unexpected result type from query\n%s",
					 sql_error(sqlsocket, config));
			return -1;
		}
	}
	else {
		switch ((int) results_ret)
		{

		case CS_FAIL: /* Serious failure, sybase requires us to cancel and maybe even close connection */
			radlog(L_ERR,"rlm_sql_sybase(sql_query): Failure retrieving query results\n%s"
					, sql_error(sqlsocket, config));
			if ((ret = ct_cancel(NULL, sybase_sock->command, CS_CANCEL_ALL)) == CS_FAIL) {
				radlog(L_ERR,"rlm_sql_sybase(sql_query): cleaning up.");
				ct_close(sybase_sock->connection, CS_FORCE_CLOSE);
				sql_close(sqlsocket, config);
			}
			return -1;
			break;

		default:
			radlog(L_ERR,"rlm_sql_sybase(sql_query): Unexpected return value from ct_results()\n%s",
					sql_error(sqlsocket, config));
			return -1;
		}
	}


	/*
	** Second call to ct_results,
	** we need returncode CS_SUCCEED
	** and result_type CS_CMD_DONE.
	*/

	if ((results_ret = ct_results(sybase_sock->command, &result_type)) == CS_SUCCEED) {
		if (result_type != CS_CMD_DONE) {
			radlog(L_ERR,"rlm_sql_sybase(sql_query): Result failure or unexpected result type from query\n%s",
					 sql_error(sqlsocket, config));
			return -1;
		}
	}
	else {
		switch ((int) results_ret)
		{

		case CS_FAIL: /* Serious failure, sybase requires us to cancel and maybe even close connection */
			radlog(L_ERR,"rlm_sql_sybase(sql_query): Failure retrieving query results\n%s"
					, sql_error(sqlsocket, config));
			if ((ret = ct_cancel(NULL, sybase_sock->command, CS_CANCEL_ALL)) == CS_FAIL) {
				radlog(L_ERR,"rlm_sql_sybase(sql_query): cleaning up.");
				ct_close(sybase_sock->connection, CS_FORCE_CLOSE);
				sql_close(sqlsocket, config);
			}
			return -1;
			break;

		default:
			radlog(L_ERR,"rlm_sql_sybase(sql_query): Unexpected return value from ct_results()\n%s",
					sql_error(sqlsocket, config));
			return -1;
		}
	}


	/*
	** Third call to ct_results,
	** we need returncode CS_END_RESULTS
	** result_type will be ignored.
	*/

	results_ret = ct_results(sybase_sock->command, &result_type);

	switch ((int) results_ret)
	{

	case CS_FAIL: /* Serious failure, sybase requires us to cancel and maybe even close connection */
		radlog(L_ERR,"rlm_sql_sybase(sql_query): Failure retrieving query results\n%s"
				, sql_error(sqlsocket, config));
		if ((ret = ct_cancel(NULL, sybase_sock->command, CS_CANCEL_ALL)) == CS_FAIL) {
			radlog(L_ERR,"rlm_sql_sybase(sql_query): cleaning up.");
			ct_close(sybase_sock->connection, CS_FORCE_CLOSE);
			sql_close(sqlsocket, config);
		}
		return -1;
		break;

	case CS_END_RESULTS:  /* This is where we want to end up */
		break;

	default:
		radlog(L_ERR,"rlm_sql_sybase(sql_query): Unexpected return value from ct_results()\n%s",
				sql_error(sqlsocket, config));
		return -1;
		break;
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
static int sql_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr) {

	rlm_sql_sybase_sock *sybase_sock = sqlsocket->conn;

	CS_RETCODE	ret, results_ret;
	CS_INT		result_type;
	CS_DATAFMT	descriptor;

	int		colcount,i;
	char		**rowdata;

	 if (sybase_sock->connection == NULL) {
		radlog(L_ERR, "Socket not connected");
		return -1;
	}


	if (ct_cmd_alloc(sybase_sock->connection, &sybase_sock->command) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_select_query): Unable to allocate command structure (ct_cmd_alloc())\n%s",
				sql_error(sqlsocket, config));
		return -1;
	}

	if (ct_command(sybase_sock->command, CS_LANG_CMD, querystr, CS_NULLTERM, CS_UNUSED) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_select_query): Unable to initiate command structure (ct_command())\n%s",
				sql_error(sqlsocket, config));
		return -1;
	}

	if (ct_send(sybase_sock->command) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_select_query): Unable to send command (ct_send())\n%s",
				sql_error(sqlsocket, config));
		return -1;
	}

	results_ret = ct_results(sybase_sock->command, &result_type);

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


			colcount = sql_num_fields(sqlsocket, config); /* Get number of elements in row result */


			rowdata=(char **)rad_malloc(sizeof(char *) * (colcount+1));	/* Space for pointers */
			memset(rowdata, 0, (sizeof(char *) * colcount+1));  /* NULL-pad the pointers */

			for (i=0; i < colcount; i++) {

                        	rowdata[i]=rad_malloc((MAX_DATASTR_LEN * sizeof(char))+1); /* Space to hold the result data */

				/* Associate the target buffer with the data */
				if (ct_bind(sybase_sock->command, i+1, &descriptor, rowdata[i], NULL, NULL) != CS_SUCCEED) {
					radlog(L_ERR,"rlm_sql_sybase(sql_select_query): ct_bind() failed)\n%s",
							sql_error(sqlsocket, config));
					return -1;
				}

			}
			rowdata[i]=NULL; /* Terminate the array */
			sybase_sock->results=rowdata;
			break;

		case CS_CMD_SUCCEED:
		case CS_CMD_DONE:

			radlog(L_ERR,"rlm_sql_sybase(sql_select_query): Query returned no data");
			break;

		default:

			radlog(L_ERR,"rlm_sql_sybase(sql_select_query): Unexpected result type from query\n%s",
					 sql_error(sqlsocket, config));
			sql_finish_select_query(sqlsocket, config);
			return -1;
			break;
		}
		break;

	case CS_FAIL:

		/*
		** Serious failure, sybase requires us to cancel
		** the results and maybe even close the connection.
		*/

		radlog(L_ERR,"rlm_sql_sybase(sql_select_query): Failure retrieving query results\n%s"
				, sql_error(sqlsocket, config));
		if ((ret = ct_cancel(NULL, sybase_sock->command, CS_CANCEL_ALL)) == CS_FAIL) {
			radlog(L_ERR,"rlm_sql_sybase(sql_select_query): cleaning up.");
			ct_close(sybase_sock->connection, CS_FORCE_CLOSE);
			sql_close(sqlsocket, config);
		}
		return -1;
		break;

	default:

		radlog(L_ERR,"rlm_sql_sybase(sql_select_query): Unexpected return value from ct_results()\n%s",
				sql_error(sqlsocket, config));
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
 *               set for the query.
 *
 *************************************************************************/
static int sql_store_result(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
	/*
	** Not needed for Sybase, code that may have gone here is
	** in sql_select_query and sql_fetch_row
	*/
	return 0;
}


/*************************************************************************
 *
 *	Function: sql_num_fields
 *
 *	Purpose: database specific num_fields function. Returns number
 *               of columns from query
 *
 *************************************************************************/
static int sql_num_fields(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	rlm_sql_sybase_sock *sybase_sock = sqlsocket->conn;
	int	num;

	if (ct_res_info(sybase_sock->command, CS_NUMDATA, (CS_INT *)&num, CS_UNUSED, NULL) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_num_fields): error retrieving column count: %s",
			sql_error(sqlsocket, config));
		return -1;
	}
	return num;
}

/*************************************************************************
 *
 *	Function: sql_num_rows
 *
 *	Purpose: database specific num_rows. Returns number of rows in
 *               query
 *
 *************************************************************************/
static int sql_num_rows(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	rlm_sql_sybase_sock *sybase_sock = sqlsocket->conn;
	int	num;

	if (ct_res_info(sybase_sock->command, CS_ROW_COUNT, (CS_INT *)&num, CS_UNUSED, NULL) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_num_rows): error retrieving row count: %s",
			sql_error(sqlsocket, config));
		return -1;
	}
	return num;
}


/*************************************************************************
 *
 *	Function: sql_fetch_row
 *
 *	Purpose: database specific fetch_row. Returns a SQL_ROW struct
 *               with all the data for the query in 'sqlsocket->row'. Returns
 *		 0 on success, -1 on failure, SQL_DOWN if 'database is down'.
 *
 *************************************************************************/
int sql_fetch_row(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	rlm_sql_sybase_sock *sybase_sock = sqlsocket->conn;
	CS_INT		ret, count;

	sqlsocket->row = NULL;


	ret = ct_fetch(sybase_sock->command, CS_UNUSED, CS_UNUSED, CS_UNUSED, &count);

	switch (ret) {

	case CS_FAIL:

		/*
		** Serious failure, sybase requires us to cancel
		** the results and maybe even close the connection.
		*/

		radlog(L_ERR,"rlm_sql_sybase(sql_fetch_row): Failure fething row data\n%s"
				, sql_error(sqlsocket, config));
		if ((ret = ct_cancel(NULL, sybase_sock->command, CS_CANCEL_ALL)) == CS_FAIL) {
			radlog(L_ERR,"rlm_sql_sybase(sql_fetch_row): cleaning up.");
			ct_close(sybase_sock->connection, CS_FORCE_CLOSE);
			sql_close(sqlsocket, config);
		}
		return SQL_DOWN;
		break;

	case CS_END_DATA:

		return 0;
		break;

	case CS_SUCCEED:

		sqlsocket->row = sybase_sock->results;
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
 *               for a result set
 *
 *************************************************************************/
static int sql_free_result(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	/*
	** Not implemented, never called from rlm_sql anyway
	** result buffer is freed in the finish_query functions.
	*/

	return 0;

}



/*************************************************************************
 *
 *	Function: sql_error
 *
 *	Purpose: database specific error. Returns error associated with
 *               connection
 *
 *************************************************************************/
static const char *sql_error(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
	static char	msg='\0';
/*
	static char	msgbuf[2048];

	rlm_sql_sybase_sock *sybase_sock = sqlsocket->conn;
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

	if (ct_diag(sybase_sock->connection, CS_STATUS, CS_CLIENTMSG_TYPE, CS_UNUSED, &msgcount) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_error): Failed to get number of pending Client messages");
		return msgbuf;
	}
	radlog(L_ERR,"rlm_sql_sybase(sql_error): Number of pending Client messages: %d", (int)msgcount);

	for (i=1; i<=msgcount; i++) {
		if (ct_diag(sybase_sock->connection, CS_GET, CS_CLIENTMSG_TYPE, (CS_INT)i, &cmsg) != CS_SUCCEED) {
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


	if (ct_diag(sybase_sock->connection, CS_STATUS, CS_SERVERMSG_TYPE, CS_UNUSED, &msgcount) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_error): Failed to get number of pending Server messages");
		return msgbuf;
	}
	radlog(L_ERR,"rlm_sql_sybase(sql_error): Number of pending Server messages: %d", (int)msgcount);

	for (i=1; i<=msgcount; i++) {
		if (ct_diag(sybase_sock->connection, CS_GET, CS_SERVERMSG_TYPE, (CS_INT)i, &smsg) != CS_SUCCEED) {
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


/*************************************************************************
 *
 *	Function: sql_close
 *
 *	Purpose: database specific close. Closes an open database
 *               connection and cleans up any open handles.
 *
 *************************************************************************/
static int sql_close(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
/*
	rlm_sql_oracle_sock *oracle_sock = sqlsocket->conn;

	if (oracle_sock->conn) {
		OCILogoff (oracle_sock->conn, oracle_sock->errHandle);
	}

	if (oracle_sock->queryHandle) {
		OCIHandleFree((dvoid *)oracle_sock->queryHandle, (ub4) OCI_HTYPE_STMT);
	}
	if (oracle_sock->errHandle) {
		OCIHandleFree((dvoid *)oracle_sock->errHandle, (ub4) OCI_HTYPE_ERROR);
	}
	if (oracle_sock->env) {
		OCIHandleFree((dvoid *)oracle_sock->env, (ub4) OCI_HTYPE_ENV);
	}

	oracle_sock->conn = NULL;
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
static int sql_finish_query(SQLSOCK *sqlsocket, SQL_CONFIG *config)
{
	rlm_sql_sybase_sock *sybase_sock = sqlsocket->conn;

	ct_cancel(NULL, sybase_sock->command, CS_CANCEL_ALL);

	if (ct_cmd_drop(sybase_sock->command) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_finish_query): Freeing command structure failed.");
		return -1;
	}

	return 0;
}



/*************************************************************************
 *
 *	Function: sql_finish_select_query
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
static int sql_finish_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	rlm_sql_sybase_sock *sybase_sock = sqlsocket->conn;
	int	i=0;

	ct_cancel(NULL, sybase_sock->command, CS_CANCEL_ALL);

	if (ct_cmd_drop(sybase_sock->command) != CS_SUCCEED) {
		radlog(L_ERR,"rlm_sql_sybase(sql_finish_select_query): Freeing command structure failed.");
		return -1;
	}

        if (sybase_sock->results) {
                while(sybase_sock->results[i]) free(sybase_sock->results[i++]);
                free(sybase_sock->results);
                sybase_sock->results=NULL;
        }

	return 0;

}


/*************************************************************************
 *
 *	Function: sql_affected_rows
 *
 *	Purpose: Return the number of rows affected by the query (update,
 *               or insert)
 *
 *************************************************************************/
static int sql_affected_rows(SQLSOCK *sqlsocket, SQL_CONFIG *config) {

	return sql_num_rows(sqlsocket, config);

}




/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_sybase = {
	"rlm_sql_sybase",
	sql_init_socket,
	sql_destroy_socket,
	sql_query,
	sql_select_query,
	sql_store_result,
	sql_num_fields,
	sql_num_rows,
	sql_fetch_row,
	sql_free_result,
	sql_error,
	sql_close,
	sql_finish_query,
	sql_finish_select_query,
	sql_affected_rows
};
