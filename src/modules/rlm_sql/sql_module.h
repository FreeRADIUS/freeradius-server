/***************************************************************************
*  sql_module.h                       rlm_sql - FreeRADIUS SQL Module      *
*                                                                          *
*      MySQL headers for rlm_sql                                           *
*                                                                          *
*                                     Mike Machado <mike@innercite.com>    *
***************************************************************************/
#include	<mysql/mysql.h>
#include	"conf.h"

typedef MYSQL_ROW	SQL_ROW;

typedef struct sql_config {
        char *sql_server;
        char *sql_login;
        char *sql_password;
        char *sql_db;
        char *sql_acct_table;
        char *sql_authcheck_table;
        char *sql_authreply_table;
        char *sql_groupcheck_table;
        char *sql_groupreply_table;
        char *sql_usergroup_table;
        char *sql_realm_table;
        char *sql_realmgroup_table;
        char *sql_nas_table;
        char *sql_dict_table;
        int  sensitiveusername;
        int  sqltrace;
	int  deletestalesessions;
	int  max_sql_socks;
} SQL_CONFIG;
 
typedef struct sql_socket {
	MYSQL		*sock;
	MYSQL		conn;
        MYSQL_RES	*result;
        int             id;
        int             in_use;
	struct timeval	tv;
} SQLSOCK;
 
typedef struct sql {
        SQL_CONFIG *config;
        SQLSOCK *socks[MAX_SQL_SOCKS];
} SQL;


SQLSOCK *sql_create_socket(void);
int sql_checksocket(const char *facility);
int sql_query(SQLSOCK *socket, char *querystr);
int sql_select_query(SQLSOCK *socket, char *querystr);
int sql_store_result(SQLSOCK *socket);
int sql_num_fields(SQLSOCK *socket);
int sql_num_rows(SQLSOCK *socket);
SQL_ROW sql_fetch_row(SQLSOCK *socket);
void sql_free_result(SQLSOCK *socket);
char *sql_error(SQLSOCK *socket);
void sql_close(SQLSOCK *socket);
void sql_finish_query(SQLSOCK *socket);
void sql_finish_select_query(SQLSOCK *socket);
int sql_affected_rows(SQLSOCK *socket);
int sql_escape_string(char *to, char *from, int length);
