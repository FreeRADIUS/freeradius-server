/* cistron mysql module
*          Mike Machado
*          InnerCite
*          mike@innercite.com
*/


#define	SQLBIGREC	32
#define	SQLLILREC	16
#define QUERYLOG        "/var/log/radacct/radius.sql"
#define MYSQLCONFIG     "radius.conf"
#define MYSQLBACKUP     "/var/log/radacct/sqlbackup.dat"

#define PW_VP_USERDATA	1
#define PW_VP_GROUPDATA	2

typedef struct mysqlrec {
	char                            AcctSessionId[SQLBIGREC];
        char                            UserName[SQLBIGREC];
        char                            Realm[SQLBIGREC];
        char                            NASIPAddress[SQLLILREC];
        unsigned long                   NASPortId;
        char                            NASPortType[SQLBIGREC];
        char                            AcctStatusType[SQLBIGREC];
        unsigned int                    AcctStatusTypeId;
        char                            AcctTimeStamp[20];
        unsigned long                   AcctSessionTime;
        char                            AcctAuthentic[SQLBIGREC];
        char                            ConnectInfo[SQLBIGREC];
        unsigned long                   AcctInputOctets;
        unsigned long                   AcctOutputOctets;
        char                            CalledStationId[SQLLILREC];
        char                            CallingStationId[SQLLILREC];
        char                            AcctTerminateCause[SQLBIGREC];
        char                            ServiceType[SQLBIGREC];
        char                            FramedProtocol[SQLBIGREC];
        char                            FramedIPAddress[SQLLILREC];
        unsigned long                   AcctDelayTime;
} MYSQLREC; 

NAS		*naslist;
REALM		*realms;
CLIENT		*clients;
DICT_ATTR	*dictionary_attributes;
DICT_VALUE	*dictionary_values;
DICT_VENDOR	*dictionary_vendors;

#define SQL_LOCK_LEN sizeof(MYSQLREC)
#define MAX_TABLE_LEN 20
#define MAX_AUTH_QUERY_LEN 256
char mysql_server[40];
char mysql_login[20];
char mysql_password[20];
char mysql_db[20];
char mysql_acct_table[MAX_TABLE_LEN];
char mysql_authcheck_table[MAX_TABLE_LEN];
char mysql_authreply_table[MAX_TABLE_LEN];
char mysql_groupcheck_table[MAX_TABLE_LEN];
char mysql_groupreply_table[MAX_TABLE_LEN];
char mysql_usergroup_table[MAX_TABLE_LEN];
char mysql_realm_table[MAX_TABLE_LEN];
char mysql_realmgroup_table[MAX_TABLE_LEN];
char mysql_nas_table[MAX_TABLE_LEN];
char mysql_dict_table[MAX_TABLE_LEN];
int  mysql_keepopen;
int  sqltrace; 
MYSQL *MyAuthSock;
MYSQL *MyAcctSock;
MYSQL MyAuthConn;
MYSQL MyAcctConn;
int		mysql_start();
int		mysql_save_acct(MYSQLREC *sqlrecord);
int		mysql_userparse(VALUE_PAIR **first_pair, MYSQL_ROW row);
int		mysql_checksocket(const char *facility);
int		mysql_read_realms(char *realmtable);
int		mysql_getvpdata(char *table, VALUE_PAIR **vp, char *user, int mode);
int		mysql_check_multi(char *name, VALUE_PAIR *request, int maxsimul);
int		mysql_read_naslist(char *nastable);
int		mysql_read_clients(char *nastable);
int		mysql_dict_init();
