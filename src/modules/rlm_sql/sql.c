/*
 *  sql.c		rlm_sql - FreeRADIUS SQL Module
 *		Main code directly taken from ICRADIUS
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Mike Machado <mike@innercite.com>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */


#include	<sys/types.h>
#include	<sys/socket.h>
#include	<sys/time.h>
#include	<sys/file.h>
#include	<string.h>
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

#if HAVE_PTHREAD_H
#include	<pthread.h>
#endif

#include	"radiusd.h"
#include	"conffile.h"
#include	"rlm_sql.h"

/*************************************************************************
 *
 *	Function: sql_init_socket
 *
 *	Purpose: Connect to the sql server
 *
 *************************************************************************/
int sql_init_socketpool(SQL_INST *inst) {

	SQLSOCK	*sqlsocket;
	int	i;

	inst->used = 0;
	inst->sqlpool = NULL;

	for (i = 0; i < inst->config->num_sql_socks; i++) {
		if ((sqlsocket = sql_create_socket(inst)) == NULL) {
			radlog(L_CONS | L_ERR, "rlm_sql:  Failed to connect sqlsocket %d", i);
			return -1;
		} else {
			sqlsocket->id = i;
#if HAVE_PTHREAD_H
			sqlsocket->semaphore = (sem_t *)malloc(sizeof(sem_t));
			sem_init(sqlsocket->semaphore, 0, SQLSOCK_UNLOCKED);
#else
			sqlsocket->in_use = 0;
#endif
			sqlsocket->next = inst->sqlpool;
			inst->sqlpool = sqlsocket;
		}
	}

	return 1;
}

/*************************************************************************
 *
 *     Function: sql_poolfree
 *
 *     Purpose: Clean up and free sql pool
 *
 *************************************************************************/
void sql_poolfree(SQL_INST *inst) {

	SQLSOCK *cur;

	for (cur = inst->sqlpool; cur; cur = cur->next) {
		sql_close_socket(cur);
	}
}


/*************************************************************************
 *
 *	Function: sql_close_socket
 *
 *	Purpose: Close and free a sql sqlsocket
 *
 *************************************************************************/
int sql_close_socket(SQLSOCK *sqlsocket) {

	DEBUG2("rlm_sql: Closing sqlsocket %d", sqlsocket->id);
	sql_close(sqlsocket);
	free(sqlsocket);
	return 1;
}


/*************************************************************************
 *
 *	Function: sql_get_socket
 *
 *	Purpose: Return a SQL sqlsocket from the connection pool           
 *
 *************************************************************************/
SQLSOCK *sql_get_socket(SQL_INST *inst) {


	SQLSOCK *cur;

#if HAVE_PTHREAD_H
	pthread_mutex_lock(inst->lock);
#endif
	while (inst->used == inst->config->num_sql_socks) {
		printf("Waiting queue to not be full\n");
#if HAVE_PTHREAD_H
		pthread_cond_wait(inst->notfull, inst->lock);
#else
		/* FIXME: Subsecond sleep needed here */
		sleep(1);
#endif
	}

	for (cur = inst->sqlpool; cur; cur = cur->next) {
#if HAVE_PTHREAD_H
		if (sem_trywait(cur->semaphore) == 0) {
#else
		if (cur->in_use == SQLSOCK_UNLOCKED) {
#endif
			(inst->used)++;
#if HAVE_PTHREAD_H
			pthread_mutex_unlock(inst->lock);
#else
			cur->in_use = SQLSOCK_LOCKED;
#endif
			printf("Reserved id %d\n", cur->id);
			return cur;
		}
	}

#if HAVE_PTHREAD_H
	pthread_mutex_unlock(inst->lock);
#endif

	/* Should never get here, but what the hey */
	return NULL;
}

/*************************************************************************
 *
 *	Function: sql_release_socket
 *
 *	Purpose: Frees a SQL sqlsocket back to the connection pool           
 *
 *************************************************************************/
int sql_release_socket(SQL_INST *inst, SQLSOCK *sqlsocket) {

	struct timeval tv;
	double  start, end;
	char    buff[24];

	gettimeofday(&tv, NULL);
	sprintf(buff, "%ld.%2ld", tv.tv_sec, tv.tv_usec);
	end = strtod(buff, NULL);
	sprintf(buff, "%ld %2.0ld", sqlsocket->tv.tv_sec, sqlsocket->tv.tv_usec);
	start = strtod(buff, NULL);
	DEBUG2("rlm_sql: Socket %d used for %.2f seconds", sqlsocket->id, end - start);

	sqlsocket->tv.tv_sec = tv.tv_sec;
	sqlsocket->tv.tv_usec = tv.tv_usec;

#if HAVE_PTHREAD_H
	pthread_mutex_lock(inst->lock);
#endif
	(inst->used)--;
#if HAVE_PTHREAD_H
	sem_post(sqlsocket->semaphore);
#else
	sqlsocket->in_use = 0;
#endif

	DEBUG2("rlm_sql: Released sqlsocket %d", sqlsocket->id);

#if HAVE_PTHREAD_H
	pthread_mutex_unlock(inst->lock);
	pthread_cond_signal(inst->notfull);
#endif

	return 1;
}


/*************************************************************************
 *
 *	Function: sql_save_acct
 *
 *	Purpose: Write data from the sqlrecord structure to the database
 *
 *************************************************************************/

int sql_save_acct(SQL_INST *inst, SQLSOCK *sqlsocket, SQLACCTREC *sqlrecord) {

	char    querystr[2048];
	FILE   *sqlfile=0;
	int     num = 0;
	int			acctunique = 0;

#ifdef NT_DOMAIN_HACK
	char   *ptr;
	char    newname[AUTH_STRING_LEN];
#endif

	acctunique = strlen(sqlrecord->AcctUniqueId);

	if(inst->config->sqltrace) {
		if ((sqlfile = fopen(inst->config->tracefile, "a")) == (FILE *) NULL) {
			radlog(L_ERR, "rlm_sql: Couldn't open file %s", inst->config->tracefile);
		} else {
#if defined(F_LOCK) && !defined(BSD)
			(void) lockf((int) sqlfile, (int) F_LOCK, (off_t) SQL_LOCK_LEN);
#else
			(void) flock(sqlfile, SQL_LOCK_EX);
#endif
		}
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
#endif /*
			  * NT_DOMAIN_HACK 
			  */

	if (sqlrecord->AcctStatusTypeId == PW_STATUS_ACCOUNTING_ON ||
			sqlrecord->AcctStatusTypeId == PW_STATUS_ACCOUNTING_OFF) {
		radlog(L_INFO, "rlm_sql:  Portmaster %s rebooted at %s", sqlrecord->NASIPAddress,
					 sqlrecord->AcctTimeStamp);

		/*
		 * The Terminal server informed us that it was rebooted
		 * * STOP all records from this NAS 
		 */

		sprintf(querystr,
						"UPDATE %s SET AcctStopTime='%s', AcctSessionTime=unix_timestamp('%s') - unix_timestamp(AcctStartTime), AcctTerminateCause='%s', AcctStopDelay = %ld WHERE AcctSessionTime=0 AND AcctStopTime=0 AND NASIPAddress= '%s' AND AcctStartTime <= '%s'",
						inst->config->sql_acct_table, sqlrecord->AcctTimeStamp,
						sqlrecord->AcctTimeStamp, sqlrecord->AcctTerminateCause,
						sqlrecord->AcctDelayTime, sqlrecord->NASIPAddress,
						sqlrecord->AcctTimeStamp);

		if (sql_query(inst, sqlsocket, querystr) < 0)
			radlog(L_ERR, "rlm_sql: Couldn't update SQL accounting after NAS reboot - %s",
						 sql_error(sqlsocket));
		sql_finish_query(sqlsocket);

		if (sqlfile) {
			fputs(querystr, sqlfile);
			fputs(";\n", sqlfile);
			fclose(sqlfile);
		}
		return 0;
	}

	if (sqlrecord->AcctStatusTypeId == PW_STATUS_ALIVE) {
		/* 
		 * Use acct unique session identifier if present
		 */
		if(acctunique) { 
			sprintf(querystr, "UPDATE %s SET FramedIPAddress = '%s' WHERE AcctUniqueId = '%s'",
							inst->config->sql_acct_table, sqlrecord->FramedIPAddress,
							sqlrecord->AcctUniqueId);

		} else {
			sprintf(querystr, "UPDATE %s SET FramedIPAddress = '%s' WHERE AcctSessionId = '%s' AND UserName = '%s' AND NASIPAddress= '%s'",
							inst->config->sql_acct_table, sqlrecord->FramedIPAddress,
							sqlrecord->AcctSessionId, sqlrecord->UserName,
							sqlrecord->NASIPAddress);
		}

		if (sql_query(inst, sqlsocket, querystr) < 0)
			radlog(L_ERR, "rlm_sql: Couldn't update SQL accounting for ALIVE packet - %s",
						 sql_error(sqlsocket));
		sql_finish_query(sqlsocket);

		if (sqlfile) {
			fputs(querystr, sqlfile);
			fputs(";\n", sqlfile);
			fclose(sqlfile);
		}
		return 0;
	}

	/*
	 * Got start record 
	 */
	if (sqlrecord->AcctStatusTypeId == PW_STATUS_START) {

		/*
		 * Insert new record with blank stop time until stop record is got 
		 */
		snprintf(querystr, 2048,
						 "INSERT INTO %s VALUES (0, '%s', '%s', '%s', '%s', '%s', %ld, '%s', '%s', 0, 0, '%s', '%s', '', 0, 0, '%s', '%s', '', '%s', '%s', '%s', %ld, 0)",
						 inst->config->sql_acct_table, sqlrecord->AcctSessionId, 
						 sqlrecord->AcctUniqueId, sqlrecord->UserName, 
						 sqlrecord->Realm, sqlrecord->NASIPAddress,
						 sqlrecord->NASPortId, sqlrecord->NASPortType,
						 sqlrecord->AcctTimeStamp, sqlrecord->AcctAuthentic,
						 sqlrecord->ConnectInfo, sqlrecord->CalledStationId,
						 sqlrecord->CallingStationId, sqlrecord->ServiceType,
						 sqlrecord->FramedProtocol, sqlrecord->FramedIPAddress,
						 sqlrecord->AcctDelayTime);

		if (sql_query(inst, sqlsocket, querystr) < 0) {
			radlog(L_ERR, "rlm_sql: Couldn't insert SQL accounting START record - %s",
							 sql_error(sqlsocket));

			/*
			 * We failed the insert above.  It's probably because 
			 * the stop record came before the start.  We try an
			 * update here to be sure
			 */
			if(acctunique) {
				snprintf(querystr, 2048, "UPDATE %s SET AcctStartTime = '%s', AcctStartDelay = %ld, ConnectInfo_start = '%s' WHERE AcctUniqueId = '%s'",
								 inst->config->sql_acct_table, sqlrecord->AcctTimeStamp,
								 sqlrecord->AcctDelayTime, sqlrecord->ConnectInfo,
								 sqlrecord->AcctUniqueId);
			} else {
				snprintf(querystr, 2048, "UPDATE %s SET AcctStartTime = '%s', AcctStartDelay = %ld, ConnectInfo_start = '%s' WHERE AcctSessionId = '%s' AND UserName = '%s' AND NASIPAddress = '%s'",
								 inst->config->sql_acct_table, sqlrecord->AcctTimeStamp,
								 sqlrecord->AcctDelayTime, sqlrecord->ConnectInfo,
								 sqlrecord->AcctSessionId, sqlrecord->UserName, 
								 sqlrecord->NASIPAddress);
			}
			if (sql_query(inst, sqlsocket, querystr) < 0)
				radlog(L_ERR, "rlm_sql: Couldn't update SQL accounting START record - %s",
							 sql_error(sqlsocket));

		} 
		sql_finish_query(sqlsocket);

		/*
		 * Got stop record 
		 */
	} else {

		/*
		 * Set stop time on matching record with start time 
		 */
		if(acctunique) {
			snprintf(querystr, 2048,
							 "UPDATE %s SET AcctStopTime = '%s', AcctSessionTime = '%lu', AcctInputOctets = '%lu', AcctOutputOctets = '%lu', AcctTerminateCause = '%s', AcctStopDelay = %ld, ConnectInfo_stop = '%s' WHERE AcctUniqueId = '%s'",
							 inst->config->sql_acct_table, sqlrecord->AcctTimeStamp,
							 sqlrecord->AcctSessionTime, sqlrecord->AcctInputOctets,
							 sqlrecord->AcctOutputOctets, sqlrecord->AcctTerminateCause,
							 sqlrecord->AcctDelayTime, sqlrecord->ConnectInfo,
							 sqlrecord->AcctUniqueId);

		} else {
			snprintf(querystr, 2048,
							 "UPDATE %s SET AcctStopTime = '%s', AcctSessionTime = '%lu', AcctInputOctets = '%lu', AcctOutputOctets = '%lu', AcctTerminateCause = '%s', AcctStopDelay = %ld, ConnectInfo_stop = '%s' WHERE AcctSessionId = '%s' AND UserName = '%s' AND NASIPAddress = '%s'",
							 inst->config->sql_acct_table, sqlrecord->AcctTimeStamp,
							 sqlrecord->AcctSessionTime, sqlrecord->AcctInputOctets,
							 sqlrecord->AcctOutputOctets, sqlrecord->AcctTerminateCause,
							 sqlrecord->AcctDelayTime, sqlrecord->ConnectInfo,
							 sqlrecord->AcctSessionId, sqlrecord->UserName, 
							 sqlrecord->NASIPAddress);
		}


		if (sql_query(inst, sqlsocket, querystr) < 0)
			radlog(L_ERR, "rlm_sql: Couldn't update SQL accounting STOP record - %s",
						 sql_error(sqlsocket));
		sql_finish_query(sqlsocket);


		/* 
		 * If our update above didn't match anything
		 * we assume it's because we haven't seen a 
		 * matching Start record.  So we have to
		 * insert this stop rather than do an update
		 */
		num = sql_affected_rows(sqlsocket);
		if(num < 1) {

#ifdef CISCO_ACCOUNTING_HACK
			/*
			 * If stop but zero session length AND no previous 
			 * session found, drop it as in invalid packet 
			 * This is to fix CISCO's aaa from filling our 
			 * table with bogus crap 
			 */
			if (sqlrecord->AcctSessionTime <= 0) {
				radlog(L_ERR, "rlm_sql: Invalid STOP record. [%s] STOP record but zero session length? (nas %s)",
							 sqlrecord->UserName, sqlrecord->NASIPAddress);
				return 0;
			}
#endif

			/*
			 * Insert record with no start time until matching start record comes 
			 */
			snprintf(querystr, 2048,
							 "INSERT INTO %s VALUES (0, '%s', '%s', '%s', '%s', '%s', %ld, '%s', 0, '%s', '%lu', '%s', '', '%s', '%lu', '%lu', '%s', '%s', '%s', '%s', '%s', '%s', 0, %ld)",
							 inst->config->sql_acct_table, sqlrecord->AcctSessionId,
							 sqlrecord->AcctUniqueId, sqlrecord->UserName, 
							 sqlrecord->Realm, sqlrecord->NASIPAddress,
							 sqlrecord->NASPortId, sqlrecord->NASPortType,
							 sqlrecord->AcctTimeStamp, sqlrecord->AcctSessionTime,
							 sqlrecord->AcctAuthentic, sqlrecord->ConnectInfo,
							 sqlrecord->AcctInputOctets, sqlrecord->AcctOutputOctets,
							 sqlrecord->CalledStationId, sqlrecord->CallingStationId,
							 sqlrecord->AcctTerminateCause, sqlrecord->ServiceType,
							 sqlrecord->FramedProtocol, sqlrecord->FramedIPAddress,
							 sqlrecord->AcctDelayTime);

			if (sql_query(inst, sqlsocket, querystr) < 0)
				radlog(L_ERR, "rlm_sql: Couldn't insert SQL accounting STOP record - %s",
							 sql_error(sqlsocket));
			sql_finish_query(sqlsocket);
		}

	}
	if (sqlfile) {
		fputs(querystr, sqlfile);
		fputs(";\n", sqlfile);
		fflush(sqlfile);
		fclose(sqlfile);
	}

	return 0;

}


/*************************************************************************
 *
 *	Function: sql_userparse
 *
 *	Purpose: Read entries from the database and fill VALUE_PAIR structures
 *
 *************************************************************************/
int
sql_userparse(VALUE_PAIR ** first_pair, SQL_ROW row, int mode)
{

	DICT_ATTR *attr;
	VALUE_PAIR *pair, *check;


	if ((attr = dict_attrbyname(row[2])) == (DICT_ATTR *) NULL) {
		radlog(L_ERR | L_CONS, "rlm_sql: unknown attribute %s", row[2]);
		return (-1);
	}

	/*
	 * If attribute is already there, skip it because we checked usercheck first 
	 * and we want user settings to over ride group settings 
	 */
	if ((check = pairfind(*first_pair, attr->attr)) != NULL &&
#if defined( BINARY_FILTERS )
			attr->type != PW_TYPE_ABINARY &&
#endif
			mode == PW_VP_GROUPDATA) return 0;

	pair = pairmake(row[2], row[3], T_OP_CMP_EQ);
	pairadd(first_pair, pair);

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_getvpdata
 *
 *	Purpose: Get any group check or reply pairs
 *
 *************************************************************************/
int
sql_getvpdata(SQL_INST *inst, SQLSOCK *sqlsocket, char *table, VALUE_PAIR ** vp, char *user,
							int mode)
{

	char    querystr[256];
	char    authstr[256];
	char    username[AUTH_STRING_LEN * 2 + 1];
	SQL_ROW row;
	int     rows;
	int     length;

	if (strlen(user) > AUTH_STRING_LEN)
		length = AUTH_STRING_LEN;
	else
		length = strlen(user);

	/*
	 * FIXME CHECK user for weird charactors!! 
	 */
	sql_escape_string(username, user, length);

	if (mode == PW_VP_USERDATA) {
		if (inst->config->sensitiveusername)
			sprintf(authstr, "STRCMP(Username, '%s') = 0", username);
		else
			sprintf(authstr, "UserName = '%s'", username);
		sprintf(querystr, "SELECT * FROM %s WHERE %s ORDER BY id", table,
						authstr);
	} else if (mode == PW_VP_GROUPDATA) {
		if (inst->config->sensitiveusername)
			sprintf(authstr, "STRCMP(%s.Username, '%s') = 0",
							inst->config->sql_usergroup_table, username);
		else
			sprintf(authstr, "%s.UserName = '%s'", inst->config->sql_usergroup_table,
							username);
		sprintf(querystr,
						"SELECT %s.* FROM %s, %s WHERE %s AND %s.GroupName = %s.GroupName ORDER BY %s.id",
						table, table, inst->config->sql_usergroup_table, authstr,
						inst->config->sql_usergroup_table, table, table);
	} else if (mode == PW_VP_REALMDATA)
		sprintf(querystr,
						"SELECT %s.* FROM %s, %s WHERE %s.RealmName = '%s' AND %s.GroupName = %s.GroupName ORDER BY %s.id",
						table, table, inst->config->sql_realmgroup_table,
						inst->config->sql_realmgroup_table, username,
						inst->config->sql_realmgroup_table, table, table);
	sql_select_query(inst, sqlsocket, querystr);
	rows = sql_num_rows(sqlsocket);
	while ((row = sql_fetch_row(sqlsocket))) {

		if (sql_userparse(vp, row, mode) != 0) {
			radlog(L_ERR | L_CONS, "rlm_sql:  Error getting data from database");
			sql_finish_select_query(sqlsocket);
			return -1;
		}
	}
	sql_finish_select_query(sqlsocket);

	return rows;

}


static int got_alrm;
static void
alrm_handler()
{
	got_alrm = 1;
}

/*************************************************************************
 *
 *	Function: sql_check_ts
 *
 *	Purpose: Checks the terminal server for a spacific login entry
 *
 *************************************************************************/
static int sql_check_ts(SQL_ROW row) {

	int     pid, st, e;
	int     n;
	NAS    *nas;
	char    session_id[12];
	char   *s;
	void    (*handler) (int);

	/*
	 *      Find NAS type.
	 */
	if ((nas = nas_find(ip_addr(row[4]))) == NULL) {
		radlog(L_ERR, "rlm_sql:  unknown NAS [%s]", row[4]);
		return -1;
	}

	/*
	 *      Fork.
	 */
	handler = signal(SIGCHLD, SIG_DFL);
	if ((pid = fork()) < 0) {
		radlog(L_ERR, "rlm_sql: fork: %s", strerror(errno));
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
		while ((e = waitpid(pid, &st, 0)) != pid)
			if (e < 0 && (errno != EINTR || got_alrm))
				break;
		alarm(0);
		signal(SIGCHLD, handler);
		if (got_alrm) {
			kill(pid, SIGTERM);
			sleep(1);
			kill(pid, SIGKILL);
			radlog(L_ERR, "rlm_sql:  Check-TS: timeout waiting for checkrad");
			return 2;
		}
		if (e < 0) {
			radlog(L_ERR, "rlm_sql:  Check-TS: unknown error in waitpid()");
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
	radlog(L_ERR, "rlm_sql:  Check-TS: exec %s: %s", s, strerror(errno));

	/*
	 *      Exit - 2 means "some error occured".
	 */
	exit(2);

}


/*************************************************************************
 *
 *	Function: sql_check_multi
 *
 *	Purpose: Check radius accounting for duplicate logins
 *
 *************************************************************************/
int sql_check_multi(SQL_INST *inst, SQLSOCK *sqlsocket, char *name, VALUE_PAIR * request, int maxsimul) {

	char    querystr[256];
	char    authstr[256];
	VALUE_PAIR *fra;
	SQL_ROW row;
	int     count = 0;
	uint32_t ipno = 0;
	int     mpp = 1;

	if (inst->config->sensitiveusername)
		sprintf(authstr, "STRCMP(UserName, '%s') = 0", name);
	else
		sprintf(authstr, "UserName = '%s'", name);
	sprintf(querystr, "SELECT COUNT(*) FROM %s WHERE %s AND AcctStopTime = 0",
					inst->config->sql_acct_table, authstr);
	sql_select_query(inst, sqlsocket, querystr);
	row = sql_fetch_row(sqlsocket);
	count = atoi(row[0]);
	sql_finish_select_query(sqlsocket);

	if (count < maxsimul)
		return 0;

	/*
	 * *      Setup some stuff, like for MPP detection.
	 */
	if ((fra = pairfind(request, PW_FRAMED_IP_ADDRESS)) != NULL)
		ipno = htonl(fra->lvalue);

	count = 0;
	sprintf(querystr, "SELECT * FROM %s WHERE %s AND AcctStopTime = 0",
					inst->config->sql_acct_table, authstr);
	sql_select_query(inst, sqlsocket, querystr);
	while ((row = sql_fetch_row(sqlsocket))) {
		int     check = sql_check_ts(row);

		if (check == 1) {
			count++;

			if (ipno && atoi(row[19]) == ipno)
				mpp = 2;

		} else if (check == 2)
			radlog(L_ERR, "rlm_sql:  Problem with checkrad [%s] (from nas %s)", name, row[4]);
		else {
			/*
			 *      False record - zap it
			 */

			if (inst->config->deletestalesessions) {
				SQLSOCK *sqlsocket1;

				radlog(L_ERR, "rlm_sql:  Deleteing stale session [%s] (from nas %s/%s)", row[2],
							 row[4], row[5]);
				sqlsocket1 = sql_get_socket(inst);
				sprintf(querystr, "DELETE FROM %s WHERE RadAcctId = '%s'",
								inst->config->sql_acct_table, row[0]);
				sql_query(inst, sqlsocket1, querystr);
				sql_finish_query(sqlsocket1);
				sql_release_socket(inst, sqlsocket1);
			}
		}
	}
	sql_finish_select_query(sqlsocket);

	return (count < maxsimul) ? 0 : mpp;

}
