/***************************************************************************
*  rlm_sql.h                          rlm_sql - FreeRADIUS SQL Module      *
*                                                                          *
*      Header for main SQL module file                                     *
*                                                                          *
*                                     Mike Machado <mike@innercite.com>    *
***************************************************************************/
#include "sql_module.h"
#include "conffile.h"

#define PW_VP_USERDATA		1
#define PW_VP_GROUPDATA		2
#define PW_VP_REALMDATA		3

typedef struct sqlrec {
	char            AcctSessionId[SQLBIGREC];
        char            UserName[SQLBIGREC];
        char            Realm[SQLBIGREC];
        char            NASIPAddress[SQLLILREC];
        unsigned long   NASPortId;
        char            NASPortType[SQLBIGREC];
        char            AcctStatusType[SQLBIGREC];
        unsigned int    AcctStatusTypeId;
        char            AcctTimeStamp[20];
        unsigned long   AcctSessionTime;
        char            AcctAuthentic[SQLBIGREC];
        char            ConnectInfo[SQLBIGREC];
        unsigned long   AcctInputOctets;
        unsigned long   AcctOutputOctets;
        char            CalledStationId[SQLLILREC];
        char            CallingStationId[SQLLILREC];
        char            AcctTerminateCause[SQLBIGREC];
        char            ServiceType[SQLBIGREC];
        char            FramedProtocol[SQLBIGREC];
        char            FramedIPAddress[SQLLILREC];
        unsigned long	AcctDelayTime;
} SQLACCTREC; 

int             sql_init(CONF_PARSER *module_config, SQL_CONFIG *config, int reload);
int             sql_init_socket(int reload);
int             sql_close_socket(SQLSOCK *socket);
SQLSOCK         *sql_get_socket(void);
int             sql_release_socket(SQLSOCK *socket);
int             sql_save_acct(SQLSOCK *socket, SQLACCTREC *sqlrecord);
int             sql_userparse(VALUE_PAIR **first_pair, SQL_ROW row, int mode);
int             sql_read_realms(SQLSOCK *socket);
int             sql_getvpdata(SQLSOCK *socket, char *table, VALUE_PAIR **vp, char *user, int mode);
int             sql_check_multi(SQLSOCK *socket, char *name, VALUE_PAIR *request, int maxsimul);
int             sql_read_naslist(SQLSOCK *socket);
int             sql_read_clients(SQLSOCK *socket);
int             sql_dict_init(SQLSOCK *socket);

SQL *sql;

