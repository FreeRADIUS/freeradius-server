/* freeradius sql module
*          Mike Machado
*          InnerCite
*          mike@innercite.com
*/

#define QUERYLOG	"/var/log/radacct/radius.sql"
#define SQLCONFIGFILE	"radius.conf"
#define SQLBACKUP	"/var/log/radacct/sqlbackup.dat"

#define	SQLBIGREC	32
#define	SQLLILREC	16
#define PW_VP_USERDATA	1
#define PW_VP_GROUPDATA	2

#define MAX_TABLE_LEN 20
#define MAX_AUTH_QUERY_LEN 256

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
} SQLREC; 

typedef struct sqlconfig {
	char		sql_type[40];
	char		sql_server[40];
	int		sql_port;
	char		sql_login[20];
	char		sql_password[20];
	char		sql_db[20];
	char		sql_acct_table[MAX_TABLE_LEN];
	cha		sql_authcheck_table[MAX_TABLE_LEN];
	char		sql_authreply_table[MAX_TABLE_LEN];
	char		sql_groupcheck_table[MAX_TABLE_LEN];
	char		sql_groupreply_table[MAX_TABLE_LEN];
	char 		sql_usergroup_table[MAX_TABLE_LEN];
	char 		sql_realm_table[MAX_TABLE_LEN];
	char 		sql_realmgroup_table[MAX_TABLE_LEN];
	char 		sql_nas_table[MAX_TABLE_LEN];
	char 		sql_dict_table[MAX_TABLE_LEN];
	int  		sql_keepopen;
	int  		sqltrace;
} SQLCONFIG;

typedef struct sql {
	SQLSOCK		*AuthSock;
	SQLSOCK		*AcctSock;
	SQLREC		*sqlrecord;
	SQLCONFIG	config;
} SQL;
	
#define SQL_LOCK_LEN sizeof(SQLREC)

int		sql_start();
int		sql_save_acct(void);
int		sql_userparse(VALUE_PAIR **first_pair, SQL_ROW row);
int		sql_checksocket(const char *facility);
int		sql_getvpdata(char *table, VALUE_PAIR **vp, char *user, int mode);
int		sql_check_multi(char *name, VALUE_PAIR *request, int maxsimul);
