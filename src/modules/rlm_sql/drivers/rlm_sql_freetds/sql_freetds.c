/**************************************************************************
 * 	sql_freetds.c	FreeTDS rlm_sql driver				  *
 *									  *
 * 	Some pieces of code were adopted from FreeTDS project.		  *
 *	FreeTDS home page - http://www.freetds.org/			  *
 *									  *
 *			Dmitri Ageev <d_ageev@ortcc.ru>			  *
 **************************************************************************/

#include "radiusd.h"
#include "config.h"

#include <tds.h>
#include "rlm_sql.h"

typedef struct rlm_sql_freetds_sock {
	TDSSOCKET *tds_socket;
	TDSLOGIN *tds_login;
	
	char **row;
	void *conn;
} rlm_sql_freetds_sock;;

#include <tds.h>
#include <tdsconvert.h>



/*************************************************************************
 *
 *	External functions
 *
 *************************************************************************/ 
 
extern int tds_send_cancel(TDSSOCKET *tds);
extern int tds_process_cancel(TDSSOCKET *tds);


/*************************************************************************
 *
 *	Function: sql_init_socket
 *
 *	Purpose: Establish connection to the db
 *
 *************************************************************************/
static int sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
    rlm_sql_freetds_sock *freetds_sock;
    char *query;
    int marker;

    /* Allocating memory for the new socket */
    sqlsocket->conn = (rlm_sql_freetds_sock *)rad_malloc(sizeof(rlm_sql_freetds_sock));
    freetds_sock = sqlsocket->conn;

    /* Setting connection parameters */
    freetds_sock->tds_login = tds_alloc_login();
    tds_set_server (freetds_sock->tds_login, config->sql_server);
    tds_set_user   (freetds_sock->tds_login, config->sql_login);
    tds_set_passwd (freetds_sock->tds_login, config->sql_password);
    /* Do connection */

    freetds_sock->tds_socket = (void *) tds_connect(
	freetds_sock->tds_login,
#ifdef HAVE_TDS_GET_LOCALE	
	tds_get_locale(),
#endif
	(void *)freetds_sock);
    
    if (freetds_sock->tds_socket == NULL)
    {
	radlog(L_ERR, "rlm_sql_freetds: Can't connect to the database server");
	sql_destroy_socket(sqlsocket, config);
	return -1;
    }
    
    /* Selecting the database */
    query = (char *) malloc(strlen(config->sql_db)+5);
    sprintf(query,"use %s", config->sql_db);
    if (tds_submit_query(freetds_sock->tds_socket, query) != TDS_SUCCEED)
    {
	radlog(L_ERR, "rlm_sql_freetds: Can't change the database");
	free(query);
	sql_destroy_socket(sqlsocket, config);
	return -1;	
    }
    free(query);
    
    do {
	marker = tds_get_byte(freetds_sock->tds_socket);
	tds_process_default_tokens(freetds_sock->tds_socket, marker);
    } while (marker != TDS_DONE_TOKEN);

    /* Setting up row initial value */
    freetds_sock->row = NULL;
        
    /* All fine - exiting */
    return 0;
}
	

/************************************************************************* 
 *                                                                         
 *      Function: sql_destroy_socket                                       
 *                                                                         
 *      Purpose: Free socket and private connection data                   
 *                                                                         
 *************************************************************************/
static int sql_destroy_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
    rlm_sql_freetds_sock *freetds_sock = sqlsocket->conn;

    if (sqlsocket != NULL)
    {
	if (freetds_sock != NULL)
        {
    	    if (freetds_sock->tds_socket != NULL)
	    {
		tds_free_socket(freetds_sock->tds_socket);
		freetds_sock->tds_socket = NULL;
	    }

	    free(freetds_sock);
	    freetds_sock = NULL;
	}

	free(sqlsocket);
	sqlsocket = NULL;
    }    
    
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
    rlm_sql_freetds_sock *freetds_sock = sqlsocket->conn;
    int retcode;
    
    /* Print query string (if needed) */
    if (config->sqltrace) radlog(L_DBG, "query:  %s", querystr);
	
    /* Executing query */
    if (tds_submit_query(freetds_sock->tds_socket, querystr) != TDS_SUCCEED)
    {
	/* XXX determine if return above suggests returning SQL_DOWN or not */
	radlog(L_ERR, "rlm_sql_freetds: Can't execute the query");
	radlog(L_ERR, "rlm_sql_freetds: %s", freetds_sock->tds_socket->msg_info->message);
	return -1;
    }

    retcode = tds_process_result_tokens(freetds_sock->tds_socket);
    switch (retcode)
    {
	case TDS_NO_MORE_RESULTS :
	case TDS_SUCCEED :  return 0;
	default : 
	    radlog(L_ERR, "rlm_sql_freetds: A error occured during executing the query");
	    return -1;
    }
}


/*************************************************************************
 *
 *	Function: sql_select_query
 *
 *	Purpose: Issue a select query to the database
 *
 *************************************************************************/
static int sql_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr) {
    if (sql_query(sqlsocket, config, querystr) < 0) return -1;
    return 0;
}


/*************************************************************************
 *
 *	Function: sql_store_result
 *
 *	Purpose: database specific function.
 *	         Reserve memory for the result set of a query.
 *
 *************************************************************************/
static int sql_store_result(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
    rlm_sql_freetds_sock *freetds_sock = sqlsocket->conn;
    TDSCOLINFO **columns;
    int numfields, column, column_size;

    /* Check if memory were allocated */
    if (freetds_sock->row != NULL)
      return 0; /* All fine - memory already allocated */
	
    /* Getting amount of result fields */
    numfields = sql_num_fields(sqlsocket, config);
    if (numfields < 0) return -1;

    /* Get information about the column set */
    columns = freetds_sock->tds_socket->res_info->columns;
    if (columns == NULL)
    {
	radlog(L_ERR, "rlm_sql_freetds: Can't get information about the column set");
	return -1;
    }

    /* Reserving memory for a result set */
    freetds_sock->row = (char **) rad_malloc((numfields+1)*sizeof(char *));
    if (freetds_sock->row == NULL)
    {
	radlog(L_ERR, "rlm_sql_freetds: Can't allocate the memory");
	return -1;
    }

    freetds_sock->row[numfields] = NULL;

    for(column = 0; column < numfields; column++)
    {
	column_size = columns[column]->column_size;
	freetds_sock->row[column] = (char*)rad_malloc(column_size);
	/* Some additional check */
	if (freetds_sock->row[column] == NULL)
	{
	    radlog(L_ERR, "rlm_sql_freetds: Can't allocate the memory");
	    /* Freeing memory what we already allocated */
	    sql_free_result(sqlsocket, config);
	    return -1;
	}
    }
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
    rlm_sql_freetds_sock *freetds_sock = sqlsocket->conn;
    TDSRESULTINFO *result_info;

    /* Get information about the resulting set */
    result_info = freetds_sock->tds_socket->res_info;
    if (result_info == NULL)
    {
	radlog(L_ERR, "rlm_sql_freetds: Can't get information about the resulting set");
	return -1;
    }
    return result_info->num_cols;
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
    return sql_affected_rows(sqlsocket, config);
}


/*************************************************************************
 *
 *	Function: sql_fetch_row
 *
 *	Purpose: database specific fetch_row. Returns a SQL_ROW struct
 *               with all the data for the query in 'sqlsocket->row'. Returns
 *		 0 on success, -1 on failure, SQL_DOWN if 'database is down'
 *
 *************************************************************************/
static int sql_fetch_row(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
    rlm_sql_freetds_sock *freetds_sock = sqlsocket->conn;
    TDSRESULTINFO *result_info;    
    TDSCOLINFO **columns;
    int numfields, column, retcode;

    sqlsocket->row = NULL;

    retcode = tds_process_row_tokens(freetds_sock->tds_socket);
    /* XXX Check if retcode is something we should return SQL_DOWN for */
    if (retcode == TDS_NO_MORE_ROWS)
    {
	return 0;
    } else if (retcode != TDS_SUCCEED) {
	radlog(L_ERR, "rlm_sql_freetds: A error occured during fetching the row");
	return -1;
    }
    
    /* Getting amount of result fields */
    numfields = sql_num_fields(sqlsocket, config);
    if (numfields < 0)
	return 0;

    /* Get information about the resulting set */
    result_info = freetds_sock->tds_socket->res_info;
    if (result_info == NULL)
    {
	radlog(L_ERR, "rlm_sql_freetds: Can't get information about the resulting set");
	return -1;
    }
    
    /* Get information about the column set */
    columns = result_info->columns;
    if (columns == NULL)
    {
	radlog(L_ERR, "rlm_sql_freetds: Can't get information about the column set");
	return -1;
    }

    /* Alocating the memory */
    if (sql_store_result(sqlsocket, config) < 0) return 0;

    /* Converting the fields to a CHAR data type */
    for (column = 0; column < numfields; column++)
    {
	tds_convert(
#ifdef HAVE_TDS_GET_LOCALE
	    tds_get_locale(),
#endif
	    columns[column]->column_type,
	    &result_info->current_row[columns[column]->column_offset],
	    -1,
	    SYBCHAR,
	    (char *)freetds_sock->row[column],
	    columns[column]->column_size);
    }
    sqlsocket->row = freetds_sock->row;
    return 0;
}


/*************************************************************************
 *
 *	Function: sql_finish_select_query
 *
 *	Purpose: End the select query, such as freeing memory or result
 *
 *************************************************************************/
static int sql_finish_select_query(SQLSOCK * sqlsocket, SQL_CONFIG *config) {
    rlm_sql_freetds_sock *freetds_sock = sqlsocket->conn;

    sql_free_result(sqlsocket, config);

    /* Make sure the current statement is complete */
    if (freetds_sock->tds_socket->state == TDS_PENDING)
    {
      /* Send 'cancel' packet */
	tds_send_cancel(freetds_sock->tds_socket);
	/* Process 'cancel' packet */
	tds_process_cancel(freetds_sock->tds_socket);
    }
    
    return 0;
}

/*************************************************************************
 *
 *	Function: sql_finish_query
 *
 *	Purpose: End the query, such as freeing memory
 *
 *************************************************************************/
static int sql_finish_query(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
  /* Not used */
    return 0;
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
    rlm_sql_freetds_sock *freetds_sock = sqlsocket->conn;
    int column, numfileds=sql_num_fields(sqlsocket, config);

    /* Freeing reserved memory */
    if (freetds_sock->row != NULL) {
	for(column=0; column<numfileds; column++) {
	    if (freetds_sock->row[column] != NULL) {
		free(freetds_sock->row[column]);
		freetds_sock->row[column] = NULL;
	    }
	}
        free(freetds_sock->row);
	freetds_sock->row = NULL;
    }
    return 0;
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
    rlm_sql_freetds_sock *freetds_sock = sqlsocket->conn;
    tds_free_login(freetds_sock->tds_login);
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
static char *sql_error(SQLSOCK *sqlsocket, SQL_CONFIG *config) {
    return NULL;
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
    rlm_sql_freetds_sock *freetds_sock = sqlsocket->conn;
    return freetds_sock->tds_socket->rows_affected;
}


/* Exported to rlm_sql */
rlm_sql_module_t rlm_sql_freetds = {
	"rlm_sql_freetds",
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
