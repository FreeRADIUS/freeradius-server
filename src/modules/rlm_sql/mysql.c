/*
 * mysql.c	MySQL routines. Used bt ICRADIUS 0.7 extensions
 *
 */

#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<sys/file.h>
#include	<sys/stat.h>
#include	<netinet/in.h>

#include	<stdio.h>
#include	<stdlib.h>
#include	<netdb.h>
#include	<pwd.h>
#include	<time.h>
#include	<ctype.h>
#include	<unistd.h>
#include	<signal.h>
#include	<errno.h>
#include	<sys/wait.h>

#include	"conf.h"

#include	"radiusd.h"



/*************************************************************************
 *
 *	Function: mysql_start
 *
 *	Purpose: Reads in MySQL Config File 
 *
 *************************************************************************/

int mysql_start ()
{
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

 
/*************************************************************************
 *
 *	Function: mysql_save_acct
 *
 *	Purpose: Write data from the sqlrecord structure to the database
 *
 *************************************************************************/

int mysql_save_acct(MYSQLREC *sqlrecord) {

	char		querystr[2048];
	FILE		*mysqlfile;
	FILE		*backupfile;
	int		num = 0;
	MYSQL_RES	*result;
#ifdef NT_DOMAIN_HACK
	char		*ptr;
	char		newname[AUTH_STRING_LEN];
#endif
	


     if((mysqlfile = fopen(QUERYLOG, "a")) == (FILE *)NULL) {
            log(L_ERR, "Acct: Couldn't open file %s", QUERYLOG);
     } else { 
        #if defined(F_LOCK) && !defined(BSD)
              (void)lockf((int)mysqlfile, (int)F_LOCK, (off_t)SQL_LOCK_LEN);
        #else
              (void)flock(mysqlfile, SQL_LOCK_EX);
        #endif
     }

#ifdef NT_DOMAIN_HACK
	/*
	 *      Windows NT machines often authenticate themselves as
	 *      NT_DOMAIN\username. Try to be smart about this.
	 *
	 *      FIXME: should we handle this as a REALM ?
	 */
	if ((ptr = strchr(sqlrecord->UserName, '\\')) != NULL) {
		strncpy(newname, ptr + 1, sizeof(newname));
		newname[sizeof(newname) - 1] = 0;
		strcpy(sqlrecord->UserName, newname);
	}
#endif /* NT_DOMAIN_HACK */

 if (mysql_checksocket("Acct")) {

     if (sqlrecord->AcctStatusTypeId == PW_STATUS_ACCOUNTING_ON || sqlrecord->AcctStatusTypeId == PW_STATUS_ACCOUNTING_OFF) {
        log(L_INFO, "Portmaster %s rebooted at %s", sqlrecord->NASIPAddress, sqlrecord->AcctTimeStamp);
  
         /* The Terminal server informed us that it was rebooted
         * STOP all records from this NAS */

         sprintf(querystr, "UPDATE %s SET AcctStopTime='%s', AcctSessionTime=unix_timestamp('%s') - unix_timestamp(AcctStartTime), AcctTerminateCause='%s' WHERE AcctSessionTime=0 AND AcctStopTime=0 AND NASIPAddress= '%s' AND AcctStartTime <= '%s'", mysql_acct_table, sqlrecord->AcctTimeStamp, sqlrecord->AcctTimeStamp, sqlrecord->AcctTerminateCause, sqlrecord->NASIPAddress, sqlrecord->AcctTimeStamp);

 	 if (sqltrace)
	      DEBUG(querystr);
       	 if (mysql_query(MyAcctSock, (const char *) querystr) < 0)
	      log(L_ERR, "Acct: Couldn't update SQL accounting after NAS reboot - %s", mysql_error(MyAcctSock));

         if (mysqlfile) {
              fputs(querystr, mysqlfile);
              fputs(";\n", mysqlfile);
              fclose(mysqlfile);
          }
          return 0;
      } 

	if (sqlrecord->AcctStatusTypeId == PW_STATUS_ALIVE) {
		sprintf(querystr, "UPDATE %s SET Framed-IP-Address = '%s' WHERE AcctSessionId = '%s' AND UserName = '%s' AND NASIPAddress= '%s'", mysql_acct_table, sqlrecord->FramedIPAddress, sqlrecord->AcctSessionId, sqlrecord->UserName, sqlrecord->NASIPAddress);
		if (sqltrace)
			DEBUG(querystr);
		if (mysql_query(MyAcctSock, (const char *) querystr) < 0)
		log(L_ERR, "Acct: Couldn't update SQL accounting after NAS reboot - %s", mysql_error(MyAcctSock));

		if (mysqlfile) {
			fputs(querystr, mysqlfile);
			fputs(";\n", mysqlfile);
			fclose(mysqlfile);
		}
		return 0;
	}


          /* Got start record */
          if(sqlrecord->AcctStatusTypeId == PW_STATUS_START) {
             
             /* Set start time on record with only a stop record */
 	     snprintf(querystr, 2048, "UPDATE %s SET AcctStartTime = '%s' WHERE AcctSessionId = '%s' AND UserName = '%s' AND NASIPAddress = '%s'", 
	     mysql_acct_table,
             sqlrecord->AcctTimeStamp,
             sqlrecord->AcctSessionId,
             sqlrecord->UserName,
             sqlrecord->NASIPAddress
             );
 	     if (sqltrace)
	        DEBUG(querystr);
       	     if (mysql_query(MyAcctSock, (const char *) querystr) < 0)
	        log(L_ERR, "Acct: Couldn't update SQL accounting START record - %s", mysql_error(MyAcctSock));

             num = mysql_affected_rows(MyAcctSock);
             if (num == 0) {

                /* Insert new record with blank stop time until stop record is got */
                snprintf(querystr, 2048, "INSERT INTO %s VALUES (0, '%s', '%s', '%s', '%s', %ld, '%s', '%s', 0, 0, '%s', '%s', 0, 0, '%s', '%s', '', '%s', '%s', '%s', %ld)",
                mysql_acct_table,
                sqlrecord->AcctSessionId,
                sqlrecord->UserName,
                sqlrecord->Realm,
                sqlrecord->NASIPAddress,
                sqlrecord->NASPortId,
                sqlrecord->NASPortType,
                sqlrecord->AcctTimeStamp,
                sqlrecord->AcctAuthentic,
                sqlrecord->ConnectInfo,
                sqlrecord->CalledStationId,
                sqlrecord->CallingStationId,
                sqlrecord->ServiceType,
                sqlrecord->FramedProtocol,
                sqlrecord->FramedIPAddress,
                sqlrecord->AcctDelayTime
                );                  

 		if (sqltrace)
		   DEBUG(querystr);
       	        if (mysql_query(MyAcctSock, (const char *) querystr) < 0)
	   	  log(L_ERR, "Acct: Couldn't insert SQL accounting START record - %s", mysql_error(MyAcctSock));
             }

           /* Got stop record */
           } else {

             sprintf(querystr, "SELECT RadAcctId FROM %s WHERE AcctSessionId='%s' AND NASIPAddress='%s' AND UserName='%s'", mysql_acct_table, sqlrecord->AcctSessionId, sqlrecord->NASIPAddress, sqlrecord->UserName);
 	      if (sqltrace)
  	        DEBUG(querystr);
              mysql_query(MyAcctSock, querystr);
              if (!(result = mysql_store_result(MyAcctSock)) && mysql_num_fields(MyAcctSock)) {
                   log(L_ERR,"MYSQL Error: Cannot get result");
                   log(L_ERR,"MYSQL error: %s",mysql_error(MyAcctSock));
                    mysql_close(MyAcctSock);
                    MyAcctSock = NULL;
              } else {
                    num = mysql_num_rows(result);
	       	    mysql_free_result(result);
              }

             if (num > 0) {

                /* Set stop time on matching record with start time */
 	        snprintf(querystr, 2048, "UPDATE %s SET AcctStopTime = '%s', AcctSessionTime = '%lu', AcctInputOctets = '%u', AcctOutputOctets = '%u', AcctTerminateCause = '%s' WHERE AcctSessionId = '%s' AND UserName = '%s' AND NASIPAddress = '%s'", 
	        mysql_acct_table,
                sqlrecord->AcctTimeStamp,
                sqlrecord->AcctSessionTime,
                sqlrecord->AcctInputOctets,
                sqlrecord->AcctOutputOctets,
                sqlrecord->AcctTerminateCause,
                sqlrecord->AcctSessionId,
                sqlrecord->UserName,
                sqlrecord->NASIPAddress
                );


 	        if (sqltrace)
  	          DEBUG(querystr);
       	        if (mysql_query(MyAcctSock, (const char *) querystr) < 0)
	           log(L_ERR, "Acct: Couldn't update SQL accounting STOP record - %s", mysql_error(MyAcctSock));

             } else if (num == 0) {

            
                /* Insert record with no start time until matching start record comes */
                snprintf(querystr, 2048, "INSERT INTO %s VALUES (0, '%s', '%s', '%s', '%s', %ld, '%s', 0, '%s', '%lu', '%s', '%s', '%u', '%u', '%s', '%s', '%s', '%s', '%s', '%s', %ld)",
                mysql_acct_table,
                sqlrecord->AcctSessionId,
                sqlrecord->UserName,
                sqlrecord->Realm,
                sqlrecord->NASIPAddress,
                sqlrecord->NASPortId,
                sqlrecord->NASPortType,
	        sqlrecord->AcctTimeStamp,
		sqlrecord->AcctSessionTime,
                sqlrecord->AcctAuthentic,
                sqlrecord->ConnectInfo,
		sqlrecord->AcctInputOctets,
		sqlrecord->AcctOutputOctets,
                sqlrecord->CalledStationId,
                sqlrecord->CallingStationId,
		sqlrecord->AcctTerminateCause,
                sqlrecord->ServiceType,
                sqlrecord->FramedProtocol,
                sqlrecord->FramedIPAddress,
                sqlrecord->AcctDelayTime
                );                  

 	        if (sqltrace)
  	           DEBUG(querystr);
       	        if (mysql_query(MyAcctSock, (const char *) querystr) < 0)
		   log(L_ERR, "Acct: Couldn't insert SQL accounting STOP record - %s", mysql_error(MyAcctSock));
             }

          }
          if (mysqlfile) {
                fputs(querystr, mysqlfile);
                fputs(";\n", mysqlfile);
                fflush(mysqlfile);
                fclose(mysqlfile);
          }


    	} else {

	    /*
	     *  The database is down for some reason
             *  So open up the backup file to save records in
	     */

             if((backupfile = fopen(MYSQLBACKUP, "a")) == (FILE *)NULL) {
                 log(L_ERR, "Acct: Couldn't open file %s", MYSQLBACKUP);
             } else {
                  /*
                   * Lock the mysql backup file, prefer lockf() over flock().
                   */
                   #if defined(F_LOCK) && !defined(BSD)
                       (void)lockf((int)backupfile, (int)F_LOCK, (off_t)SQL_LOCK_LEN);
                   #else
                       (void)flock(backupfile, SQL_LOCK_EX);
                   #endif
                   if(fwrite(sqlrecord, sizeof(MYSQLREC), 1, backupfile) < 1) {
                       log(L_ERR, "Acct: Couldn't write to file %s", MYSQLBACKUP);
                   }
                   fclose(backupfile);
              }

	}
        
     return 0;

}


/*************************************************************************
 *
 *	Function: mysql_userparse
 *
 *	Purpose: Read entries from the database and fill VALUE_PAIR structures
 *
 *************************************************************************/
int mysql_userparse(VALUE_PAIR **first_pair, MYSQL_ROW row) {

	int x;
	char		*s;
	DICT_ATTR	*attr = NULL;
	DICT_VALUE	*dval;
	VALUE_PAIR	*pair, *pair2, *check;
	struct tm	*tm;
	time_t		timeval;


	if((attr = dict_attrfind(row[2])) == (DICT_ATTR *)NULL) {
#if 1 /* Be quiet. */
		log(L_ERR|L_CONS, "unknown attribute %s", row[2]);
#endif	
		return(-1);
	}                              

	/* If attribute is already there, skip it because we checked usercheck first 
	   and we want user settings to over ride group settings */
	if ((check = pairfind(*first_pair, attr->value)) != NULL)
		return 0;

	if((pair = (VALUE_PAIR *)malloc(sizeof(VALUE_PAIR))) == (VALUE_PAIR *)NULL) {
		log(L_CONS|L_ERR, "mysql_userparse: no memory");
		exit(1);
	}
	strcpy(pair->name, attr->name);
	pair->attribute = attr->value;
	pair->type = attr->type;
	pair->operator = PW_OPERATOR_EQUAL;
	switch(pair->type) {

		case PW_TYPE_STRING:
			strcpy(pair->strvalue, row[3]);
			pair->length = strlen(pair->strvalue);
			break;

		case PW_TYPE_INTEGER:
                       /*
                        *      For PW_NAS_PORT_ID, allow a
                        *      port range instead of just a port.
                        */
                        if (attr->value == PW_NAS_PORT_ID) {
                              for(s = row[3]; *s; s++)
                                   if (!isdigit(*s)) break;
                                   if (*s) {
                                       pair->type = PW_TYPE_STRING;
                                       strcpy(pair->strvalue, row[3]);
                                       pair->length = strlen(pair->strvalue);
                                       break;
                                   }
                        }
                        if (isdigit(*row[3])) {
                                   pair->lvalue = atoi(row[3]);
                                   pair->length = 4;
                        }
                        else if((dval = dict_valfind(row[3])) == (DICT_VALUE *)NULL) {
                                   free(pair);
                                   log(L_ERR|L_CONS, "unknown value %s", row[3]);
                                   return(-1);
                        }
                        else {
                                   pair->lvalue = dval->value;
                                   pair->length = 4;
                        }
                        break;

		case PW_TYPE_IPADDR:
			if (pair->attribute != PW_FRAMED_IP_ADDRESS) {
                                   pair->lvalue = get_ipaddr(row[3]);
                                   break;
                        }

                       /*
                        *      We allow a "+" at the end to
                        *      indicate that we should add the
                        *      portno. to the IP address.
                        */
                        x = 0;
                        if (row[3][0]) {
                               for(s = row[3]; s[1]; s++) ;
                                    if (*s == '+') {
                                        *s = 0;
                                        x = 1;
                                    }
                        }
                        pair->lvalue = get_ipaddr(row[3]);
                        pair->length = 4;

                       /*
                        *      Add an extra (hidden) attribute.
                        */
                        if((pair2 = malloc(sizeof(VALUE_PAIR))) == NULL) {
                               log(L_CONS|L_ERR, "no memory");
                               exit(1);
                        }
                        strcpy(pair2->name, "Add-Port-To-IP-Address");
                        pair2->attribute = PW_ADD_PORT_TO_IP_ADDRESS;
                        pair2->type = PW_TYPE_INTEGER;
                        pair2->lvalue = x;
                        pair2->length = 4;
                        pairadd(first_pair, pair2);
                        break;

		case PW_TYPE_DATE:
                        timeval = time(0);
                        tm = localtime(&timeval);
                        user_gettime(row[3], tm);
#ifdef TIMELOCAL
                        pair->lvalue = (UINT4)timelocal(tm);
#else
                        pair->lvalue = (UINT4)mktime(tm);
#endif
                        pair->length = 4;
                        break;

		default:
                        free(pair);
#if 1 /* Yeah yeah */
                        log(L_ERR|L_CONS, "unknown attr. type %d", pair->type);
#endif
                        return(-1);
	}
	pairadd(first_pair, pair);

	return 0;
}


/*************************************************************************
 *
 *	Function: mysql_checksocket
 *
 *	Purpose: Make sure our database connection is up
 *
 *************************************************************************/
int mysql_checksocket(const char *facility) {

	if ((strncmp(facility, "Auth", 4) == 0)) {
		if (MyAuthSock == NULL) {
			if (mysql_keepopen)
				log(L_ERR, "%s: Keepopen set but had to reconnect to MySQL", facility);
			/* Connect to the database server */
			mysql_init(&MyAuthConn);
			if (!(MyAuthSock = mysql_real_connect(&MyAuthConn, mysql_server, mysql_login, mysql_password, mysql_db, 0, NULL, 0))) {
				log(L_ERR, "Auth: Couldn't connect authentication socket to MySQL server on %s as %s", mysql_server, mysql_login);
				MyAuthSock = NULL;
				return 0;
			}
		}

	} else {
		if (MyAcctSock == NULL) {
			if (mysql_keepopen)
				log(L_ERR, "%s: Keepopen set but had to reconnect to MySQL", facility);
			/* Connect to the database server */
			mysql_init(&MyAcctConn);
			if (!(MyAcctSock = mysql_real_connect(&MyAcctConn, mysql_server, mysql_login, mysql_password, mysql_db, 0, NULL, 0))) {
				log(L_ERR, "Acct: Couldn't connect accounting socket to MySQL server on %s as %s", mysql_server, mysql_login);
				MyAcctSock = NULL;
				return 0;
			}
		}

	}

	return 1;

}


/*************************************************************************
 *
 *	Function: mysql_getvpdata
 *
 *	Purpose: Get any group check or reply pairs
 *
 *************************************************************************/
int mysql_getvpdata(char *table, VALUE_PAIR **vp, char *user, int mode) {

	char		querystr[256];
	MYSQL_RES	*result;
	MYSQL_ROW	row;
	int		rows;

	if (mode == PW_VP_USERDATA)
		sprintf(querystr, "SELECT * FROM %s WHERE UserName = '%s'", table, user);
	else if (mode == PW_VP_GROUPDATA)
		sprintf(querystr, "SELECT %s.* FROM %s, %s WHERE %s.UserName = '%s' AND %s.GroupName = %s.GroupName ORDER BY %s.id", table, table, mysql_usergroup_table, mysql_usergroup_table, user, mysql_usergroup_table, table, table);
	else if (mode == PW_VP_REALMDATA)
		sprintf(querystr, "SELECT %s.* FROM %s, %s WHERE %s.RealmName = '%s' AND %s.GroupName = %s.GroupName ORDER BY %s.id", table, table, mysql_realmgroup_table, mysql_realmgroup_table, user, mysql_realmgroup_table, table, table);
	if (sqltrace)
		DEBUG(querystr);
        mysql_checksocket("Auth");
	mysql_query(MyAuthSock, querystr);
	if (!(result = mysql_store_result(MyAuthSock)) && mysql_num_fields(MyAuthSock)) {
   		log(L_ERR,"MYSQL Error: Cannot get result");
   		log(L_ERR,"MYSQL error: %s",mysql_error(MyAuthSock));
   		mysql_close(MyAuthSock);
  		MyAuthSock = NULL;
	} else {
		rows = mysql_num_rows(result);
		while ((row = mysql_fetch_row(result))) {

			if (mysql_userparse(vp, row) != 0) {
		 		log(L_ERR|L_CONS, "Error getting data from MySQL");
				mysql_free_result(result);
				return -1;
			}
		}
		mysql_free_result(result);
	}

	return rows;

}


static int got_alrm;
static void alrm_handler()
{
	got_alrm = 1;
}

/*************************************************************************
 *
 *	Function: mysql_check_ts
 *
 *	Purpose: Checks the terminal server for a spacific login entry
 *
 *************************************************************************/
static int mysql_check_ts(MYSQL_ROW row) {

	int     pid, st, e;
	int     n;
	NAS     *nas;
	char    session_id[12];
	char    *s;
	void    (*handler)(int);

	/*
	 *      Find NAS type.
	 */
	if ((nas = nas_find(ipstr2long(row[3]))) == NULL) {
                log(L_ERR, "Accounting: unknown NAS [%s]", row[3]);
                return -1;
        }

        /*
         *      Fork.
         */
        handler = signal(SIGCHLD, SIG_DFL);
        if ((pid = fork()) < 0) {
                log(L_ERR, "Accounting: fork: %s", strerror(errno));
                signal(SIGCHLD, handler);
                return -1;
        }

        if (pid > 0) {
                /*
                 *      Parent - Wait for checkrad to terminate.
                 *      We timeout in 10 seconds.
                 */
                got_alrm = 0;
                signal(SIGALRM, alrm_handler);
                alarm(10);
                while((e = waitpid(pid, &st, 0)) != pid)
                        if (e < 0 && (errno != EINTR || got_alrm))
                                break;
                alarm(0);
                signal(SIGCHLD, handler);
                if (got_alrm) {
                        kill(pid, SIGTERM);
                        sleep(1);
                        kill(pid, SIGKILL);
                        log(L_ERR, "Check-TS: timeout waiting for checkrad");
                        return 2;
                }
                if (e < 0) {
                        log(L_ERR, "Check-TS: unknown error in waitpid()");
                        return 2;
                }
                return WEXITSTATUS(st);
        }

        /*
         *      Child - exec checklogin with the right parameters.
         */
        for (n = 32; n >= 3; n--)
                close(n);

        sprintf(session_id, "%.8s", row[1]);

        s = CHECKRAD2;
        execl(CHECKRAD2, "checkrad", nas->nastype, row[4], row[5],
                row[2], session_id, NULL);
        if (errno == ENOENT) {
                s = CHECKRAD1;
                execl(CHECKRAD1, "checklogin", nas->nastype, row[4], row[5],
                        row[2], session_id, NULL);
        }
        log(L_ERR, "Check-TS: exec %s: %s", s, strerror(errno));

        /*
         *      Exit - 2 means "some error occured".
         */
        exit(2); 

}


/*************************************************************************
 *
 *	Function: mysql_check_multi
 *
 *	Purpose: Check radius accounting for duplicate logins
 *
 *************************************************************************/
int mysql_check_multi(char *name, VALUE_PAIR *request, int maxsimul) {

	char		querystr[256];
	VALUE_PAIR	*fra;
	MYSQL_RES	*result;
	MYSQL_ROW	row;
	int		count = 0;
	UINT4		ipno = 0;
	int		mpp = 1;

	if (!mysql_checksocket("Auth"))
		return 0;
	sprintf(querystr, "SELECT COUNT(*) FROM %s WHERE UserName = '%s' AND AcctStopTime = 0", mysql_acct_table, name);
	if (sqltrace)
		DEBUG(querystr);
	mysql_query(MyAuthSock, querystr);
	if (!(result = mysql_store_result(MyAuthSock)) && mysql_num_fields(MyAuthSock)) {
   		log(L_ERR,"MYSQL Error: Cannot get result");
   		log(L_ERR,"MYSQL error: %s",mysql_error(MyAuthSock));
   		mysql_close(MyAuthSock);
  		MyAuthSock = NULL;
	} else {
		row = mysql_fetch_row(result);
		count = atoi(row[0]);
		mysql_free_result(result);
	}

	if (count < maxsimul)
		return 0;

	/*
	*      Setup some stuff, like for MPP detection.
	*/
	if ((fra = pairfind(request, PW_FRAMED_IP_ADDRESS)) != NULL)
		ipno = htonl(fra->lvalue);

	count = 0;
	sprintf(querystr, "SELECT * FROM %s WHERE UserName = '%s' AND AcctStopTime = 0", mysql_acct_table, name);
	if (sqltrace)
		DEBUG(querystr);
	mysql_query(MyAuthSock, querystr);
	if (!(result = mysql_store_result(MyAuthSock)) && mysql_num_fields(MyAuthSock)) {
   		log(L_ERR,"MYSQL Error: Cannot get result");
   		log(L_ERR,"MYSQL error: %s",mysql_error(MyAuthSock));
   		mysql_close(MyAuthSock);
  		MyAuthSock = NULL;
	} else {
		while ((row = mysql_fetch_row(result))) {
			if (mysql_check_ts(row) == 1) {
				count++;

				if (ipno && atoi(row[18]) == ipno)
					mpp = 2;   

			} else {
				/*
				 *	False record - zap it
				 */

				sprintf(querystr, "DELETE FROM %s WHERE RadAcctId = '%s'", mysql_acct_table, row[0]);
				if (sqltrace)
					DEBUG(querystr);
				mysql_query(MyAuthSock, querystr);
				
			}
		}
		mysql_free_result(result);
	}

	return (count < maxsimul) ? 0 : mpp; 

}
