#include <stdio.h>
#include <stdlib.h>
#include <mysql/mysql.h>

#include "radiusd.h"
#include "rlm_mysql.h"


#ifdef ASCEND_PORT_HACK
/*
 *	dgreer --
 *	This hack changes Ascend's wierd port numberings
 *      to standard 0-??? port numbers so that the "+" works
 *      for IP address assignments.
 */
static int ascend_port_number(int nas_port)
{
	int service;
	int line;
	int channel;

	if (nas_port > 9999) {
		service = nas_port/10000; /* 1=digital 2=analog */
		line = (nas_port - (10000 * service)) / 100;
		channel = nas_port-((10000 * service)+(100 * line));
		nas_port =
			(channel - 1) + (line - 1) * ASCEND_CHANNELS_PER_LINE;
	}
	return nas_port;
}
#endif


/***********************************************************************
 * start of main routines
 ***********************************************************************/

static int icradius_init(int rehup) {

	FILE    *sqlfd;
        char    dummystr[64];
        char    namestr[64];
        int     line_no;
        char    buffer[256];
        char    sqlfile[256];
	MyAuthSock = NULL;
	MyAcctSock = NULL;
       
       strcpy(mysql_server,"localhost");
       strcpy(mysql_login,"");
       strcpy(mysql_password,"");
       strcpy(mysql_db,"radius");
       strcpy(mysql_authcheck_table,"radcheck");
       strcpy(mysql_authreply_table,"radreply");
       strcpy(mysql_groupcheck_table,"radgroupcheck");
       strcpy(mysql_groupreply_table,"radgroupreply");
       strcpy(mysql_usergroup_table,"usergroup");
       strcpy(mysql_realmgroup_table,"realmgroup");
       strcpy(mysql_acct_table,"radacct");
       strcpy(mysql_nas_table,"nas");
       strcpy(mysql_realm_table, "realms");
       strcpy(mysql_dict_table,"dictionary");
       sqltrace = 0;
       mysql_keepopen = 0;

        sprintf(sqlfile, "%s/%s", radius_dir, MYSQLCONFIG);

        if((sqlfd = fopen(sqlfile, "r")) == (FILE *)NULL) {
                log(L_ERR,"could not read mysql configuration file %s",sqlfile);
                return(-1);
        }

        line_no = 0;
        while(fgets(buffer, sizeof(buffer), sqlfd) != (char *)NULL) {
                line_no++;

                /* Skip empty space */
                if(*buffer == '#' || *buffer == '\0' || *buffer == '\n') {
                        continue;
                }

                if(strncasecmp(buffer, "server", 6) == 0) {
                        /* Read the SERVER line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strcpy(mysql_server,namestr);
                       }
               }
                if(strncasecmp(buffer, "login", 5) == 0) {
                        /* Read the LOGIN line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strcpy(mysql_login,namestr);
                       }
               }
                if(strncasecmp(buffer, "password", 8) == 0) {
                        /* Read the PASSWORD line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strcpy(mysql_password,namestr);
                       }
               }
                if(strncasecmp(buffer, "radius_db", 9) == 0) {
                        /* Read the RADIUS_DB line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strcpy(mysql_db,namestr);
                       }
               }
                if(strncasecmp(buffer, "authcheck_table", 15) == 0) {
                        /* Read the AUTHCHECK_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(mysql_authcheck_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "authreply_table", 15) == 0) {
                        /* Read the AUTHREPLY_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(mysql_authreply_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "groupcheck_table", 16) == 0) {
                        /* Read the GROUPCHECK_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(mysql_groupcheck_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "groupreply_table", 16) == 0) {
                        /* Read the GROUP_REPLY_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(mysql_groupreply_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "usergroup_table", 15) == 0) {
                        /* Read the USERGROUP_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(mysql_usergroup_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "realmgroup_table", 16) == 0) {
                        /* Read the REALMGROUP_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(mysql_realmgroup_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "acct_table", 10) == 0) {
                        /* Read the ACCT_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(mysql_acct_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "nas_table", 9) == 0) {
                        /* Read the NAS_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(mysql_nas_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "realm_table", 9) == 0) {
                       /* Read the REALM_TABLE line */
                       if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                      } else {
                         strncpy(mysql_realm_table,namestr, MAX_TABLE_LEN);
                      }
               }
                if(strncasecmp(buffer, "dict_table", 9) == 0) {
                        /* Read the DICT_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(mysql_dict_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "sqltrace", 8) == 0) {
                        /* Read the SQLTRACE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                      } else {
                         if(strncasecmp(namestr, "on", 2) == 0) {
                           sqltrace = 1;
                         } else {
                           sqltrace = 0;
                         }
                       }
               }
               if(strncasecmp(buffer, "keepopen", 8) == 0) {
                        /* Read the KEEPOPEN line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         if(strncasecmp(namestr, "yes", 3) == 0) {
                           mysql_keepopen = 1;
                        } else {
                           mysql_keepopen = 0;
                        }
                       }
               }

       }
       fclose(sqlfd);
       
       log(L_INFO,"MYSQL: Attempting to connect to %s:%s as %s",
       mysql_server,
       mysql_db,
       mysql_login);

       if (mysql_keepopen) {
           /* Connect to the database server */
           mysql_init(&MyAuthConn);
           if (!(MyAuthSock = mysql_real_connect(&MyAuthConn, mysql_server, mysql_login, mysql_password, mysql_db, 0, NULL, 0))) {
                log(L_ERR, "Init: Couldn't connect authentication socket to MySQL server on %s as %s", mysql_server, mysql_login);
                MyAuthSock = NULL;
           }
           mysql_init(&MyAcctConn);
           if (!(MyAcctSock = mysql_real_connect(&MyAcctConn, mysql_server, mysql_login, mysql_password, mysql_db, 0, NULL, 0))) {
                log(L_ERR, "Init: Couldn't connect accounting socket to MySQL server on %s as %s", mysql_server, mysql_login);
                MyAcctSock = NULL;
           }
       }
           
       return 0;
}

static int icradius_detach(void)
{
  return 0;
}


static int icradius_authorize(AUTH_REQ *authreq, char *name, VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs) {

	int		nas_port = 0;
	VALUE_PAIR	*check_tmp = NULL;
	VALUE_PAIR	*reply_tmp = NULL;
	VALUE_PAIR	*tmp;
	int		found = 0;
#ifdef NT_DOMAIN_HACK
	char		*ptr;
	char		newname[AUTH_STRING_LEN];
#endif


	/* 
	 *	Check for valid input, zero length names not permitted 
	 */
	if (name[0] == 0) {
		log(L_ERR, "zero length username not permitted\n");
		return -1;
	}

	/*
	 *	Find the NAS port ID.
	 */
	if ((tmp = pairfind(authreq->request, PW_NAS_PORT_ID)) != NULL)
		nas_port = tmp->lvalue;

	/*
	 *	Find the entry for the user.
	 */

#ifdef NT_DOMAIN_HACK
	/*
	 *      Windows NT machines often authenticate themselves as
	 *      NT_DOMAIN\username. Try to be smart about this.
	 *
	 *      FIXME: should we handle this as a REALM ?
	 */
	if ((ptr = strchr(name, '\\')) != NULL) {
		strncpy(newname, ptr + 1, sizeof(newname));
		newname[sizeof(newname) - 1] = 0;
		strcpy(name, newname);
	}
#endif /* NT_DOMAIN_HACK */


	if ((found = mysql_getvpdata(mysql_authcheck_table, &check_tmp, name, PW_VP_USERDATA)) <= 0)
		return -1;
	mysql_getvpdata(mysql_groupcheck_table, &check_tmp, name, PW_VP_GROUPDATA);
	mysql_getvpdata(mysql_authreply_table, &reply_tmp, name, PW_VP_USERDATA);
	mysql_getvpdata(mysql_groupreply_table, &reply_tmp, name, PW_VP_GROUPDATA);

	pairmove(reply_pairs, &reply_tmp);
	pairmove(check_pairs, &check_tmp);
	pairfree(reply_tmp);
	pairfree(check_tmp);

	/*
	 *	Fix dynamic IP address if needed.
	 */
	if ((tmp = pairfind(*reply_pairs, PW_ADD_PORT_TO_IP_ADDRESS)) != NULL){
		if (tmp->lvalue != 0) {
			tmp = pairfind(*reply_pairs, PW_FRAMED_IP_ADDRESS);
			if (tmp) {
				/*
			 	 *	FIXME: This only works because IP
				 *	numbers are stored in host order
				 *	everywhere in this program.
				 */
#ifdef ASCEND_PORT_HACK
				nas_port = ascend_port_number(nas_port);
#endif
				tmp->lvalue += nas_port;
			}
		}
		pairdelete(reply_pairs, PW_ADD_PORT_TO_IP_ADDRESS);
	}

	/*
	 *	Remove server internal parameters.
	 */
	return 0;
}

static int icradius_authenticate(AUTH_REQ *authreq, char *user, char *password)
{

  return RLM_DECLINED;


}

static int icradius_accounting(AUTH_REQ *authreq)
{
  return RLM_DECLINED;
}



/* globally exported name */
module_t rlm_module = {
  "icradius",
  0,				/* type: reserved */
  icradius_init,		/* initialization */
  icradius_authorize,		/* authorization */
  icradius_authenticate,	/* authentication */
  icradius_accounting,		/* accounting */
  icradius_detach,		/* detach */
};



