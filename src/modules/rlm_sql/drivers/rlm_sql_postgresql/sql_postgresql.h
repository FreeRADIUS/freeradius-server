/*****************************************************
* rlm_sql Postgresql driver                          *
*                                                    *
*****************************************************/

#include        <libpq-fe.h>
#include	"rlm_sql.h"

/*
 *  These are problematic, since postgres has neither of these
 *  (how to do these ..hmmm )
 */
/*typedef char**  SQL_ROW;*/
 
typedef struct rlm_sql_postgres_sock {
   PGconn          *conn;
   PGresult        *result;
   int             cur_row;
   int             num_fields;
    int		   affected_rows;
   char            **row;
} rlm_sql_postgres_sock;


int	sql_init_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int	sql_destroy_socket(SQLSOCK *sqlsocket, SQL_CONFIG *config);
int     sql_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr);
int     sql_select_query(SQLSOCK *sqlsocket, SQL_CONFIG *config, char *querystr);
int     sql_store_result(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int     sql_num_fields(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int     sql_num_rows(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int	sql_fetch_row(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int    sql_free_result(SQLSOCK * sqlsocket, SQL_CONFIG *config);
char   *sql_error(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int    sql_close(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int    sql_finish_query(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int    sql_finish_select_query(SQLSOCK * sqlsocket, SQL_CONFIG *config);
int     sql_affected_rows(SQLSOCK * sqlsocket, SQL_CONFIG *config);
