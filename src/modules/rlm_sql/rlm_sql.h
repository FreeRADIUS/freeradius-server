
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

typedef struct sqlrec {
	char    AcctSessionId[SQLBIGREC];
	char    AcctUniqueId[SQLBIGREC];
	char    UserName[SQLBIGREC];
	char    Realm[SQLBIGREC];
	char    NASIPAddress[SQLLILREC];
	unsigned long NASPortId;
	char    NASPortType[SQLBIGREC];
	char    AcctStatusType[SQLBIGREC];
	unsigned int AcctStatusTypeId;
	char    AcctTimeStamp[20];
	unsigned long AcctSessionTime;
	char    AcctAuthentic[SQLBIGREC];
	char    ConnectInfo[SQLBIGREC];
	unsigned long AcctInputOctets;
	unsigned long AcctOutputOctets;
	char    CalledStationId[SQLLILREC];
	char    CallingStationId[SQLLILREC];
	char    AcctTerminateCause[SQLBIGREC];
	char    ServiceType[SQLBIGREC];
	char    FramedProtocol[SQLBIGREC];
	char    FramedIPAddress[SQLLILREC];
	unsigned long AcctDelayTime;
} SQLACCTREC;

int     sql_init_socketpool(SQL_INST *inst);
void	sql_poolfree(SQL_INST *inst);
int     sql_close_socket(SQLSOCK *sqlsocket);
SQLSOCK *sql_get_socket(SQL_INST *inst);
int     sql_release_socket(SQL_INST *inst, SQLSOCK *sqlsocket);
int     sql_save_acct(SQL_INST *inst, SQLSOCK *sqlsocket, SQLACCTREC * sqlrecord);
int     sql_userparse(VALUE_PAIR ** first_pair, SQL_ROW row, int mode);
int     sql_read_realms(SQLSOCK *sqlsocket);
int     sql_getvpdata(SQL_INST *inst, SQLSOCK *sqlsocket, char *table, VALUE_PAIR ** vp, char *user, int mode);
int     sql_check_multi(SQL_INST *inst, SQLSOCK *sqlsocket, char *name, VALUE_PAIR * request, int maxsimul);
int     sql_read_naslist(SQLSOCK *sqlsocket);
int     sql_read_clients(SQLSOCK *sqlsocket);
int     sql_dict_init(SQLSOCK *sqlsocket);

