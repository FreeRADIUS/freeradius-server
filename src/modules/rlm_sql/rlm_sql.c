#include "autoconf.h"

#include <stdio.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <mysql/mysql.h>

#include "radiusd.h"
#include "modules.h"
#include "rlm_sql.h"


SQL *sql = NULL;


/***********************************************************************
 * start of main routines
 ***********************************************************************/

static int rlm_sql_init(int rehup) {

	FILE    *sqlfd;
        char    dummystr[64];
        char    namestr[64];
        int     line_no;
        char    buffer[256];
        char    sqlfile[256];

	if ((sql = malloc(sizeof(SQL))) == NULL) {
		log(L_ERR|L_CONS, "no memory");
		exit(1);	
	}
       
       strcpy(sql->config.sql_server,"localhost");
       strcpy(sql->config.sql_login,"");
       strcpy(sql->config.sql_password,"");
       strcpy(sql->config.sql_db,"radius");
       strcpy(sql->config.sql_authcheck_table,"radcheck");
       strcpy(sql->config.sql_authreply_table,"radreply");
       strcpy(sql->config.sql_groupcheck_table,"radgroupcheck");
       strcpy(sql->config.sql_groupreply_table,"radgroupreply");
       strcpy(sql->config.sql_usergroup_table,"usergroup");
       strcpy(sql->config.sql_realmgroup_table,"realmgroup");
       strcpy(sql->config.sql_acct_table,"radacct");
       strcpy(sql->config.sql_nas_table,"nas");
       strcpy(sql->config.sql_realm_table, "realms");
       strcpy(sql->config.sql_dict_table,"dictionary");
       sql->config.sqltrace = 0;
       sql->config.sql_keepopen = 0;

       sprintf(sqlfile, "%s/%s", radius_dir, SQLCONFIGFILE);

        if((sqlfd = fopen(sqlfile, "r")) == (FILE *)NULL) {
                log(L_ERR,"could not read sql configuration file %s",sqlfile);
                return(-1);
        }

        line_no = 0;
        while(fgets(buffer, sizeof(buffer), sqlfd) != (char *)NULL) {
                line_no++;

                /* Skip empty space */
                if(*buffer == '#' || *buffer == '\0' || *buffer == '\n') {
                        continue;
                }

                if(strncasecmp(buffer, "type", 4) == 0) {
                        /* Read the SERVER line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strcpy(sql->config.sql_type,namestr);
                       }
               }
                if(strncasecmp(buffer, "server", 6) == 0) {
                        /* Read the SERVER line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strcpy(sql->config.sql_server,namestr);
                       }
               }
                if(strncasecmp(buffer, "port", 4) == 0) {
                        /* Read the SERVER line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         sql->config.sql_port = strtol(namestr, (char **)NULL, 10);
                       }
               }
                if(strncasecmp(buffer, "login", 5) == 0) {
                        /* Read the LOGIN line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strcpy(sql->config.sql_login,namestr);
                       }
               }
                if(strncasecmp(buffer, "password", 8) == 0) {
                        /* Read the PASSWORD line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strcpy(sql->config.sql_password,namestr);
                       }
               }
                if(strncasecmp(buffer, "radius_db", 9) == 0) {
                        /* Read the RADIUS_DB line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strcpy(sql->config.sql_db,namestr);
                       }
               }
                if(strncasecmp(buffer, "authcheck_table", 15) == 0) {
                        /* Read the AUTHCHECK_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(sql->config.sql_authcheck_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "authreply_table", 15) == 0) {
                        /* Read the AUTHREPLY_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(sql->config.sql_authreply_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "groupcheck_table", 16) == 0) {
                        /* Read the GROUPCHECK_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(sql->config.sql_groupcheck_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "groupreply_table", 16) == 0) {
                        /* Read the GROUP_REPLY_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(sql->config.sql_groupreply_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "usergroup_table", 15) == 0) {
                        /* Read the USERGROUP_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(sql->config.sql_usergroup_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "realmgroup_table", 16) == 0) {
                        /* Read the REALMGROUP_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(sql->config.sql_realmgroup_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "acct_table", 10) == 0) {
                        /* Read the ACCT_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(sql->config.sql_acct_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "nas_table", 9) == 0) {
                        /* Read the NAS_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(sql->config.sql_nas_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "realm_table", 9) == 0) {
                       /* Read the REALM_TABLE line */
                       if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                      } else {
                         strncpy(sql->config.sql_realm_table,namestr, MAX_TABLE_LEN);
                      }
               }
                if(strncasecmp(buffer, "dict_table", 9) == 0) {
                        /* Read the DICT_TABLE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         strncpy(sql->config.sql_dict_table,namestr, MAX_TABLE_LEN);
                       }
               }
                if(strncasecmp(buffer, "sqltrace", 8) == 0) {
                        /* Read the SQLTRACE line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                      } else {
                         if(strncasecmp(namestr, "on", 2) == 0) {
                           sql->config.sqltrace = 1;
                         } else {
                           sql->config.sqltrace = 0;
                         }
                       }
               }
               if(strncasecmp(buffer, "keepopen", 8) == 0) {
                        /* Read the KEEPOPEN line */
                        if(sscanf(buffer, "%s%s", dummystr, namestr) != 2) {
                               log(L_ERR,"invalid attribute on line %d of sqlserver file %s", line_no,sqlfile);
                       } else {
                         if(strncasecmp(namestr, "yes", 3) == 0) {
                           sql->config.sql_keepopen = 1;
                        } else {
                           sql->config.sql_keepopen = 0;
                        }
                       }
               }

       }
       fclose(sqlfd);
       
       log(L_INFO,"SQL: Attempting to connect to %s@%s:%s",
       sql->config.sql_login,
       sql->config.sql_server,
       sql->config.sql_db);

       if (sql_keepopen)
	   sql_connect(sql);
           
       return 0;
}

static int rlm_sql_detach(void) {

  return 0;
}


static int rlm_sql_authorize(REQUEST *request, char *name, VALUE_PAIR **check_pairs, VALUE_PAIR **reply_pairs) {

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
	if ((tmp = pairfind(request->packet->vps, PW_NAS_PORT_ID)) != NULL)
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


	if ((found = sql_getvpdata(sql_authcheck_table, &check_tmp, name, PW_VP_USERDATA)) <= 0)
		return RLM_AUTZ_NOTFOUND;
	sql_getvpdata(sql_groupcheck_table, &check_tmp, name, PW_VP_GROUPDATA);
	sql_getvpdata(sql_authreply_table, &reply_tmp, name, PW_VP_USERDATA);
	sql_getvpdata(sql_groupreply_table, &reply_tmp, name, PW_VP_GROUPDATA);

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
	return RLM_AUTZ_OK;
}

static int rlm_sql_authenticate(REQUEST *request, char *user, char *password)
{
	VALUE_PAIR	*auth_pair;
	SQL_RES		*result;
	SQL_ROW		row;
	char		querystr[256];

	if ((auth_pair = pairfind(request->packet->vps, PW_AUTHTYPE)) == NULL)
	   return RLM_AUTH_REJECT;

	sprintf(querystr, "SELECT Value FROM %s WHERE UserName = '%s' AND Attribute = 'Password'", mysql_authcheck_table, user);
	if (sqltrace)
		DEBUG(querystr);
	mysql_query(sql->AcctSock, querystr);
	if (!(result = mysql_store_result(sql->AcctSock)) && mysql_num_fields(sql->AcctSock)) {
		log(L_ERR,"MYSQL Error: Cannot get result");
		log(L_ERR,"MYSQL error: %s",mysql_error(sql->AcctSock));
		mysql_close(sql->AcctSock);
		sql->AcctSock = NULL;
	} else {
		row = mysql_fetch_row(result);
		mysql_free_result(result);

		if (strncmp(strlen(password), password, row[0]) != 0) {
			return RLM_AUTH_REJECT;
		} else
			return RLM_AUTH_OK;

	} 	



}

static int rlm_sql_accounting(REQUEST *request) {

	time_t		nowtime;
	struct tm	*tim;
        char		datebuf[20];
	int		*sqlpid;
	int		sqlstatus;
	FILE		*backupfile;
	struct stat	backup;
	char		*valbuf;
	SQLREC 		sqlrecord = {"", "", "", "", 0, "", "", 0, "", 0, "", "", 0, 0, "", "", "", "", "", "", 0};
	SQLREC 		backuprecord = {"", "", "",  "", 0, "", "", 0, "", 0, "", "", 0, 0, "", "", "", "", "", "", 0};
	VALUE_PAIR	*pair;


	pair = request->packet->vps;
	strcpy(sqlrecord.Realm, "");
	while(pair != (VALUE_PAIR *)NULL) {

				

           /* Check the pairs to see if they are anything we are interested in. */
            switch(pair->attribute) {
                case PW_ACCT_SESSION_ID:
                	strncpy(sqlrecord.AcctSessionId, pair->strvalue, SQLBIGREC);
                	break;
                	
                case PW_USER_NAME:
                	strncpy(sqlrecord.UserName, pair->strvalue, SQLBIGREC);
                	break;
                	
                case PW_NAS_IP_ADDRESS:
						ipaddr2str(sqlrecord.NASIPAddress, pair->lvalue);
                	break;

                case PW_NAS_PORT_ID:
                	sqlrecord.NASPortId = pair->lvalue;
                	break;

                case PW_NAS_PORT_TYPE:
						valbuf = (char *)dict_valgetname(pair->lvalue, pair->name);
						if(valbuf != (char *)NULL) {
                		strncpy(sqlrecord.NASPortType, valbuf, SQLBIGREC);
						}
						break;

                case PW_ACCT_STATUS_TYPE:
       						sqlrecord.AcctStatusTypeId = pair->lvalue;
						valbuf = (char *)dict_valgetname(pair->lvalue, pair->name);
						if(valbuf != (char *)NULL) {
                		strncpy(sqlrecord.AcctStatusType, valbuf, SQLBIGREC);
						}
						break;

                case PW_ACCT_SESSION_TIME:
                	sqlrecord.AcctSessionTime = pair->lvalue;
                	break;

                case PW_ACCT_AUTHENTIC:
						valbuf = (char *)dict_valgetname(pair->lvalue, pair->name);
						if(valbuf != (char *)NULL) {
                		strncpy(sqlrecord.AcctAuthentic, valbuf, SQLBIGREC);
						}
						break;

                case PW_CONNECT_INFO:
                	strncpy(sqlrecord.ConnectInfo, pair->strvalue, SQLBIGREC);
                	break;

                case PW_ACCT_INPUT_OCTETS:
                	sqlrecord.AcctInputOctets = pair->lvalue;
                	break;

                case PW_ACCT_OUTPUT_OCTETS:
                	sqlrecord.AcctOutputOctets = pair->lvalue;
                	break;

                case PW_CALLED_STATION_ID:
                	strncpy(sqlrecord.CalledStationId, pair->strvalue, SQLLILREC);
                	break;

                case PW_CALLING_STATION_ID:
                	strncpy(sqlrecord.CallingStationId, pair->strvalue, SQLLILREC);
                	break;

/*                case PW_ACCT_TERMINATE_CAUSE:
						valbuf = (char *)dict_valgetname(pair->lvalue, pair->name);
						if(valbuf != (char *)NULL) {
                		strncpy(sqlrecord.AcctTerminateCause, valbuf, SQLBIGREC);
						}
						break;
*/

                case PW_SERVICE_TYPE:
						valbuf = (char *)dict_valgetname(pair->lvalue, pair->name);
						if(valbuf != (char *)NULL) {
                		strncpy(sqlrecord.ServiceType, valbuf, SQLBIGREC);
						}
						break;

                case PW_FRAMED_PROTOCOL:
						valbuf = (char *)dict_valgetname(pair->lvalue, pair->name);
						if(valbuf != (char *)NULL) {
                		strncpy(sqlrecord.FramedProtocol, valbuf, SQLBIGREC);
						}
						break;

                case PW_FRAMED_IP_ADDRESS:
						ipaddr2str(sqlrecord.FramedIPAddress, pair->lvalue);
                	break;

                case PW_ACCT_DELAY_TIME:
                	sqlrecord.AcctDelayTime = pair->lvalue;
                	break;

                default:
                	break;
		}

		pair = pair->next;
	}


        nowtime = time(0) - sqlrecord.AcctDelayTime;
        tim = localtime(&nowtime);
        strftime(datebuf, sizeof(datebuf), "%Y%m%d%H%M%S", tim);

        strncpy(sqlrecord.AcctTimeStamp, datebuf, 20);
       

	/* If backup file exists we know the database was down */
	if(stat(MYSQLBACKUP, &backup) == 0) {
		if(backup.st_size > 0) {

			/* We'll fork a child to load records in the backup file */
			(pid_t)sqlpid = fork();
			if(sqlpid > 0) {

				/* suspend the parent while child reads records */
				while(waitpid((pid_t)sqlpid, &sqlstatus, 0) != (pid_t)sqlpid);
			}
			/* Child Process */
			if(sqlpid == 0) {
				if((backupfile = fopen(MYSQLBACKUP, "rwb")) == (FILE *)NULL) {
					log(L_ERR, "Acct: (Child) Couldn't open file %s", MYSQLBACKUP);
					exit(1);
				}

				/* Lock the mysql backup file, prefer lockf() over flock(). */
#if defined(F_LOCK) && !defined( BSD)
				(void)lockf((int)backupfile, (int)F_LOCK, (off_t)SQL_LOCK_LEN);
#else
				(void)flock(backupfile, SQL_LOCK_LEN);
#endif  

				log(L_INFO, "Acct:  Clearing out sql backup file - %s", MYSQLBACKUP);

				while(!feof(backupfile)) {
					if(fread(&backuprecord, sizeof(MYSQLREC), 1, backupfile) == 1) {

						/* pass our filled structure to the
					 	   function that will write to the database */
						if (mysql_save_acct(&backuprecord) == 0)
							return RLM_ACCT_FAIL_SOFT;

					}

				}
				unlink((const char *)MYSQLBACKUP);
				exit(0);
			}
		}
	}
	if (mysql_save_acct(&sqlrecord) == 0)
		return RLM_ACCT_FAIL_SOFT;
	if (!mysql_keepopen) {
		mysql_close(sql->AcctSock);
		sql->AcctSock = NULL;
	}

	return RLM_ACCT_OK;
}


/* globally exported name */
module_t rlm_module = {
  "rlm_sql",
  0,			/* type: reserved */
  rlm_sql_init,		/* initialization */
  rlm_sql_authorize,	/* authorization */
  rlm_sql_authenticate,	/* authentication */
  rlm_sql_accounting,	/* accounting */
  rlm_sql_detach,	/* detach */
};
