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
        char sql_server[40];
        char sql_login[20];
        char sql_password[20];
        char sql_db[20];
        char sql_acct_table[MAX_TABLE_LEN];
        char sql_authcheck_table[MAX_TABLE_LEN];
        char sql_authreply_table[MAX_TABLE_LEN];
        char sql_groupcheck_table[MAX_TABLE_LEN];
        char sql_groupreply_table[MAX_TABLE_LEN];
        char sql_usergroup_table[MAX_TABLE_LEN];
        char sql_realm_table[MAX_TABLE_LEN];
        char sql_realmgroup_table[MAX_TABLE_LEN];
        char sql_nas_table[MAX_TABLE_LEN];
        char sql_dict_table[MAX_TABLE_LEN];
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
