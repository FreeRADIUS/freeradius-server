/***************************************************************************
*  rlm_sql.h                          rlm_sql - FreeRADIUS SQL Module      *
*                                                                          *
*      Header for main SQL module file                                     *
*                                                                          *
*                                     Mike Machado <mike@innercite.com>    *
***************************************************************************/
#include "sql_module.h"
#include "conffile.h"

#define SQLSOCK_LOCKED		0
#define SQLSOCK_UNLOCKED	1

#define PW_VP_USERDATA		1
#define PW_VP_GROUPDATA		2
#define PW_VP_REALMDATA		3

#define PW_ITEM_CHECK			0
#define PW_ITEM_REPLY			1

int     sql_init_socketpool(SQL_INST * inst);
void    sql_poolfree(SQL_INST * inst);
int     sql_close_socket(SQLSOCK * sqlsocket);
SQLSOCK *sql_get_socket(SQL_INST * inst);
int     sql_release_socket(SQL_INST * inst, SQLSOCK * sqlsocket);
int     sql_userparse(VALUE_PAIR ** first_pair, SQL_ROW row,
											int mode, int itemtype);
int     sql_read_realms(SQLSOCK * sqlsocket);
int     sql_getvpdata(SQL_INST * inst, SQLSOCK * sqlsocket,
											VALUE_PAIR ** check, VALUE_PAIR ** reply, char *query,
											int mode);
int     sql_check_multi(SQL_INST * inst, SQLSOCK * sqlsocket, char *name,
												VALUE_PAIR * request, int maxsimul);
int     sql_read_naslist(SQLSOCK * sqlsocket);
int     sql_read_clients(SQLSOCK * sqlsocket);
int     sql_dict_init(SQLSOCK * sqlsocket);
void    query_log(SQL_INST * inst, char *querystr);
VALUE_PAIR *set_userattr(VALUE_PAIR * first, char *username,
												 char *saveuser, int *savelen);
void    restore_userattr(VALUE_PAIR * uservp, char *saveuser, int savelen);
