/***************************************************************************
*  rlm_sql.c                          rlm_sql - FreeRADIUS SQL Module      *
*                                                                          *
*      Main SQL module file. Most ICRADIUS code is located in sql.c        *
*      $Id$
*                                                                          *
*                                     Mike Machado <mike@innercite.com>    *
***************************************************************************/
static const char rcsid[] = "$Id$";

#include "autoconf.h"

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>

#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#include "radiusd.h"
#include "modules.h"
#include "conffile.h"
#include "rlm_sql.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static SQL_CONFIG config = {
	NULL,			/* "localhost" */
	NULL,			/* "root" */
	NULL,			/* "" */
	NULL,			/* "radius" */
	NULL,			/* "radacct" */
	NULL,			/* "radcheck" */
	NULL,			/* "radreply" */
	NULL,			/* "radgroupcheck" */
	NULL,			/* "radgroupreply" */
	NULL,			/* "usergroup" */
	NULL,			/* "realm" */
	NULL,			/* "realmgroup" */
	NULL,			/* "nas" */
	NULL,			/* "dictionary" */
	0,
	0,
	1,
	5
};

static CONF_PARSER module_config[] = {
        { "sensitiveusername",		PW_TYPE_BOOLEAN,
	  &config.sensitiveusername,	"1" },
        { "deletestalesessions",	PW_TYPE_BOOLEAN,
	  &config.deletestalesessions,	"0" },
        { "sqltrace",			PW_TYPE_BOOLEAN,
	  &config.sqltrace,		"0" },
        { "max_sql_socks",		PW_TYPE_INTEGER,
	  &config.max_sql_socks,	Stringify(MAX_SQL_SOCKS) },
        { "server",			PW_TYPE_STRING_PTR,
	  &config.sql_server,		"localhost" },
        { "login",			PW_TYPE_STRING_PTR,
	  &config.sql_login,		"" },
        { "password",			PW_TYPE_STRING_PTR,
	  &config.sql_password,		"" },
        { "db",				PW_TYPE_STRING_PTR,
	  &config.sql_db,		"radius" },
        { "authcheck_table",		PW_TYPE_STRING_PTR,
	  &config.sql_authcheck_table,	"radcheck" },
        { "authreply_table",		PW_TYPE_STRING_PTR,
	  &config.sql_authreply_table,	"radreply" },
        { "groupcheck_table",		PW_TYPE_STRING_PTR,
	  &config.sql_groupcheck_table,	"radgroupcheck" },
        { "groupreply_table",		PW_TYPE_STRING_PTR,
	  &config.sql_groupreply_table,	"radgroupreply" },
        { "usergroup_table",		PW_TYPE_STRING_PTR,
	  &config.sql_usergroup_table,	"usergroup" },
        { "realmgroup_table",		PW_TYPE_STRING_PTR,
	  &config.sql_realmgroup_table,	"realmgroup" },
        { "acct_table",			PW_TYPE_STRING_PTR,
	  &config.sql_acct_table,	"radacct" },
        { "nas_table",			PW_TYPE_STRING_PTR,
	  &config.sql_nas_table,	"nas" },
        { "realm_table",		PW_TYPE_STRING_PTR,
	  &config.sql_realm_table,	"realms" },
        { "dict_table",			PW_TYPE_STRING_PTR,
	  &config.sql_dict_table,	"dictionary" },
	{ NULL, -1, NULL, NULL }
};


/***********************************************************************
 * start of main routines
 ***********************************************************************/

static int rlm_sql_init(void) {

	/* Where is the flag that tells us about a HUP?*/
	int	reload = 0;

	if ((sql = malloc(sizeof(SQL))) == NULL) {
		radlog(L_ERR|L_CONS, "no memory");
		exit(1);
	}

/*
        if (reload)
                free(sql->config);
        if ((sql->config = malloc(sizeof(SQL_CONFIG))) == NULL) {
                radlog(L_ERR|L_CONS, "no memory");
                exit(1);
        }
*/

	sql_init(module_config, &config, reload);

       return 0;
}

static int rlm_sql_destroy(void) {

  return 0;
}


static int rlm_sql_authorize(REQUEST *request, VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs)
{
	int		nas_port = 0;
	VALUE_PAIR	*check_tmp = NULL;
	VALUE_PAIR	*reply_tmp = NULL;
	VALUE_PAIR	*tmp;
	int		found = 0;
	char		*name;
	SQLSOCK		*socket;
	
	name = request->username->strvalue;

       /*
        *      Check for valid input, zero length names not permitted
        */
       if (name[0] == 0) {
               radlog(L_ERR, "zero length username not permitted\n");
               return -1;
       }

	socket = sql_get_socket();

       /*
        *      Find the NAS port ID.
        */
       if ((tmp = pairfind(request->packet->vps, PW_NAS_PORT_ID)) != NULL)
               nas_port = tmp->lvalue;

       /*
        *      Find the entry for the user.
        */
       if ((found = sql_getvpdata(socket, sql->config->sql_authcheck_table, &check_tmp, name, PW_VP_USERDATA)) > 0) {
	       sql_getvpdata(socket, sql->config->sql_groupcheck_table, &check_tmp, name, PW_VP_GROUPDATA);
	       sql_getvpdata(socket, sql->config->sql_authreply_table, &reply_tmp, name, PW_VP_USERDATA);
	       sql_getvpdata(socket, sql->config->sql_groupreply_table, &reply_tmp, name, PW_VP_GROUPDATA);
       } else {
	       
	       int gcheck, greply;
	       gcheck = sql_getvpdata(socket, sql->config->sql_groupcheck_table, &check_tmp, "DEFAULT", PW_VP_GROUPDATA);
	       greply = sql_getvpdata(socket, sql->config->sql_groupreply_table, &reply_tmp, "DEFAULT", PW_VP_GROUPDATA);
	       if (gcheck && greply)
		       found = 1;
       }
       sql_release_socket(socket);
       
       if (!found) {
	       DEBUG2("User %s not found and DEFAULT not found", name);
	       return RLM_MODULE_OK;
       }
       
       if (paircmp(request->packet->vps, check_tmp, &reply_tmp) != 0) {
	       DEBUG2("Pairs do not match [%s]", name);
	       return RLM_MODULE_OK;
       }
       
       pairmove(reply_pairs, &reply_tmp);
       pairmove(check_pairs, &check_tmp);
       pairfree(reply_tmp);
       pairfree(check_tmp);
       
       
       /*
        *      Fix dynamic IP address if needed.
        */
       if ((tmp = pairfind(*reply_pairs, PW_ADD_PORT_TO_IP_ADDRESS)) != NULL){
               if (tmp->lvalue != 0) {
                       tmp = pairfind(*reply_pairs, PW_FRAMED_IP_ADDRESS);
                       if (tmp) {
                               /*
                                *      FIXME: This only works because IP
                                *      numbers are stored in host order
                                *      everywhere in this program.
                                */
                               tmp->lvalue += nas_port;
                       }
               }
               pairdelete(reply_pairs, PW_ADD_PORT_TO_IP_ADDRESS);
       }

	return RLM_MODULE_OK;
}

static int rlm_sql_authenticate(REQUEST *request) {
	
	SQL_ROW		row;
	SQLSOCK		*socket;
	char		*querystr;
	char		escaped_user[AUTH_STRING_LEN*3];
	char		*user;
	const char	query[] = "SELECT Value FROM %s WHERE UserName = '%s' AND Attribute = 'Password'";
	
	user = request->username->strvalue;
	
	/*
	 *	Ensure that a password attribute exists.
	 */
	if ((request->password == NULL) ||
	    (request->password->length == 0) ||
	    (request->password->attribute != PW_PASSWORD)) {
		radlog(L_AUTH, "rlm_sql: Attribute \"Password\" is required for authentication.");
		return RLM_MODULE_REJECT;
	}
	
	sql_escape_string(escaped_user, user, strlen(user));
	
	/*
	 *	This should really be replaced with a static buffer...
	 */
	if ((querystr = malloc(strlen(escaped_user) +
			       strlen(sql->config->sql_authcheck_table) +
			       sizeof(query))) == NULL) {
                radlog(L_ERR|L_CONS, "no memory");
                exit(1);
        }
	
	sprintf(querystr, query, sql->config->sql_authcheck_table, escaped_user);
	socket = sql_get_socket();
	sql_select_query(socket, querystr);
	row = sql_fetch_row(socket);
	sql_finish_select_query(socket);
        free(querystr);
	
	if (strncmp(request->password->strvalue, row[0], request->password->length) != 0)
		return RLM_MODULE_REJECT;
	else
		return RLM_MODULE_OK;
}

/*
 *	Accounting: does nothing for now.
 */
static int rlm_sql_accounting(REQUEST *request) {

	time_t          nowtime;
        struct tm       *tim;
        char            datebuf[20];
        VALUE_PAIR      *pair;
	SQLACCTREC	*sqlrecord;
	SQLSOCK		*socket;
	DICT_VALUE	*dval;


        if ((sqlrecord = malloc(sizeof(SQLACCTREC))) == NULL) {
                radlog(L_ERR|L_CONS, "no memory");
                exit(1);        
        }
        
        pair = request->packet->vps;
        while(pair != (VALUE_PAIR *)NULL) {

           /* Check the pairs to see if they are anything we are interested in. */
            switch(pair->attribute) {
                case PW_ACCT_SESSION_ID:
                        strncpy(sqlrecord->AcctSessionId, pair->strvalue, SQLBIGREC);
                        break;
                        
                case PW_USER_NAME:
                        strncpy(sqlrecord->UserName, pair->strvalue, SQLBIGREC);
                        break;
                        
                case PW_NAS_IP_ADDRESS:
                        ip_ntoa(sqlrecord->NASIPAddress, pair->lvalue);
                        //ipaddr2str(sqlrecord->NASIPAddress, pair->lvalue);
                        break;

                case PW_NAS_PORT_ID:
                        sqlrecord->NASPortId = pair->lvalue;
                        break;

                case PW_NAS_PORT_TYPE:
                                                dval = dict_valbyattr(PW_NAS_PORT_TYPE, pair->lvalue);
                                                if(dval != NULL) {
                                strncpy(sqlrecord->NASPortType, dval->attrname, SQLBIGREC);
                                                }
                                                break;

                case PW_ACCT_STATUS_TYPE:
                                                sqlrecord->AcctStatusTypeId = pair->lvalue;
                                                dval = dict_valbyattr(PW_ACCT_STATUS_TYPE, pair->lvalue);
                                                if(dval != NULL) {
                                strncpy(sqlrecord->AcctStatusType, dval->attrname, SQLBIGREC);
                                                }
                                                break;

                case PW_ACCT_SESSION_TIME:
                        sqlrecord->AcctSessionTime = pair->lvalue;
                        break;

                case PW_ACCT_AUTHENTIC:
                                                dval = dict_valbyattr(PW_ACCT_AUTHENTIC, pair->lvalue);
                                                if(dval != NULL) {
                                strncpy(sqlrecord->AcctAuthentic, dval->attrname, SQLBIGREC);
                                                }
                                                break;

                case PW_CONNECT_INFO:
                        strncpy(sqlrecord->ConnectInfo, pair->strvalue, SQLBIGREC);
                        break;

                case PW_ACCT_INPUT_OCTETS:
                        sqlrecord->AcctInputOctets = pair->lvalue;
                        break;

                case PW_ACCT_OUTPUT_OCTETS:
                        sqlrecord->AcctOutputOctets = pair->lvalue;
                        break;

                case PW_CALLED_STATION_ID:
                        strncpy(sqlrecord->CalledStationId, pair->strvalue, SQLLILREC);
                        break;

                case PW_CALLING_STATION_ID:
                        strncpy(sqlrecord->CallingStationId, pair->strvalue, SQLLILREC);
                        break;

/*                case PW_ACCT_TERMINATE_CAUSE:
                                                dval = dict_valbyattr(PW_ACCT_TERMINATE_CAUSE, pair->lvalue);
                                                if(dval != NULL) {
                                strncpy(sqlrecord->AcctTerminateCause, dval->attrname, SQLBIGREC);
                                                }
                                                break;
*/


                case PW_SERVICE_TYPE:
                                                dval = dict_valbyattr(PW_SERVICE_TYPE, pair->lvalue);
                                                if(dval != NULL) {
                                strncpy(sqlrecord->ServiceType, dval->attrname, SQLBIGREC);
                                                }
                                                break;

                case PW_FRAMED_PROTOCOL:
                                                dval = dict_valbyattr(PW_FRAMED_PROTOCOL, pair->lvalue);
                                                if(dval != NULL) {
                                strncpy(sqlrecord->FramedProtocol, dval->attrname, SQLBIGREC);
                                                }
                                                break;

                case PW_FRAMED_IP_ADDRESS:
                        ip_ntoa(sqlrecord->FramedIPAddress, pair->lvalue);
                        //ipaddr2str(sqlrecord->FramedIPAddress, pair->lvalue);
                        break;

                case PW_ACCT_DELAY_TIME:
                        sqlrecord->AcctDelayTime = pair->lvalue;
                        break;

                default:
                        break;
                }

                pair = pair->next;
        }


        nowtime = time(0) - sqlrecord->AcctDelayTime;
        tim = localtime(&nowtime);
        strftime(datebuf, sizeof(datebuf), "%Y%m%d%H%M%S", tim);

        strncpy(sqlrecord->AcctTimeStamp, datebuf, 20);
       

	socket = sql_get_socket();
        if (sql_save_acct(socket, sqlrecord) == 0)
                return RLM_MODULE_FAIL;
	sql_release_socket(socket);

	return RLM_MODULE_OK;
}


/* globally exported name */
module_t rlm_sql = {
  "SQL",
  0,			/* type: reserved */
  rlm_sql_init,		/* initialization */
  NULL,			/* instantiation */
  rlm_sql_authorize,	/* authorization */
  rlm_sql_authenticate,	/* authentication */
  NULL,			/* preaccounting */
  rlm_sql_accounting,	/* accounting */
  NULL,			/* detach */
  rlm_sql_destroy,	/* destroy */
};
