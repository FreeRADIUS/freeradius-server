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
 * Copyright 2001  The FreeRADIUS server project
 * Copyright 2000  Mike Machado <mike@innercite.com>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2001  Chad Miller <cmiller@surfsouth.com>
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


/*
 * Connect to a server.  If error, set this socket's state to be "sockunconnected"
 * and set a grace period, during which we won't try connecting again (to prevent unduly
 * lagging the server and being impolite to a DB server that may be having other 
 * issues).  If successful in connecting, set state to sockconnected.   - chad
 */
static int connect_single_socket(SQLSOCK *sqlsocket, SQL_INST *inst) {
	if ((inst->module->sql_init_socket)(sqlsocket, inst->config) < 0) {
		radlog(L_CONS | L_ERR, "rlm_sql:  Failed to connect DB handle #%d", sqlsocket->id);
		inst->connect_after = time(NULL) + inst->config->connect_failure_retry_delay;
		sqlsocket->state = sockunconnected;
		return(-1);
	} else {
		radlog(L_DBG, "rlm_sql:  Connected new DB handle, #%d", sqlsocket->id);
		sqlsocket->state = sockconnected;
		return(0);
	}
}


/*************************************************************************
 *
 *	Function: sql_init_socketpool
 *
 *	Purpose: Connect to the sql server, if possible
 *
 *************************************************************************/
int sql_init_socketpool(SQL_INST * inst) {

	SQLSOCK *sqlsocket;
	int     i;

	inst->connect_after = 0;
	inst->used = 0;
	inst->sqlpool = NULL;

	for (i = 0; i < inst->config->num_sql_socks; i++) {

		sqlsocket = rad_malloc(sizeof(SQLSOCK));
		if (sqlsocket == NULL) {
			return -1;
		}
		sqlsocket->conn = NULL;
		sqlsocket->id = i;
		sqlsocket->state = sockunconnected;

#if HAVE_PTHREAD_H
		/*
		 *  FIXME! Check return codes!
		 */
		sqlsocket->semaphore = (sem_t *) rad_malloc(sizeof(sem_t));
		sem_init(sqlsocket->semaphore, 0, SQLSOCK_UNLOCKED);
#else
		sqlsocket->in_use = SQLSOCK_UNLOCKED;
#endif

		if (time(NULL) > inst->connect_after) {
			/* this sets the sqlsocket->state, and possibly sets inst->connect_after */
			connect_single_socket(sqlsocket, inst);
		}

		/* Add this socket to the list of sockets */
		sqlsocket->next = inst->sqlpool;
		inst->sqlpool = sqlsocket;
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
void sql_poolfree(SQL_INST * inst) {

	SQLSOCK *cur;

	for (cur = inst->sqlpool; cur; cur = cur->next) {
		sql_close_socket(inst, cur);
	}
}


/*************************************************************************
 *
 *	Function: sql_close_socket
 *
 *	Purpose: Close and free a sql sqlsocket
 *
 *************************************************************************/
int sql_close_socket(SQL_INST *inst, SQLSOCK * sqlsocket) {

	radlog(L_DBG, "rlm_sql: Closing sqlsocket %d", sqlsocket->id);
	(inst->module->sql_close)(sqlsocket, inst->config);
#if HAVE_PTHREAD_H
	sem_destroy(sqlsocket->semaphore);
#endif
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
SQLSOCK * sql_get_socket(SQL_INST * inst) {
	SQLSOCK *cur;
	struct timeval timeout;
	int tried_to_connect = 0;

	while (inst->used == inst->config->num_sql_socks) {
		radlog(L_ERR, "rlm_sql: All sockets are being used! Please increase the maximum number of sockets!");
	  return NULL;
	}

	for (cur = inst->sqlpool; cur; cur = cur->next) {

		/* if we happen upon an unconnected socket, and this instance's grace 
		 * period on (re)connecting has expired, then try to connect it.  This 
		 * should be really rare.  - chad
		 */
		if ((cur->state == sockunconnected) && (time(NULL) > inst->connect_after)) {
			tried_to_connect = 1;
			radlog(L_INFO, "rlm_sql: Trying to (re)connect an unconnected handle...");
			connect_single_socket(cur, inst);
		}

		/* if we still aren't connected, ignore this handle */
		if (cur->state == sockunconnected) {
			radlog(L_DBG, "rlm_sql: Ignoring unconnected handle");
			continue;
		}

#if HAVE_PTHREAD_H
		if (sem_trywait(cur->semaphore) == 0) {
#else
		if (cur->in_use == SQLSOCK_UNLOCKED) {
#endif
			(inst->used)++;
#ifne HAVE_PTHREAD_H
			cur->in_use = SQLSOCK_LOCKED;
#endif
			radlog(L_DBG, "rlm_sql: Reserving sql socket id: %d", cur->id);
			return cur;
		}
	}

	/* We get here if every DB handle is unconnected and unconnectABLE */
	radlog((tried_to_connect = 0) ? (L_DBG) : (L_CONS | L_ERR), "rlm_sql:  There are no DB handles to use!");
	return NULL;
}

/*************************************************************************
 *
 *	Function: sql_release_socket
 *
 *	Purpose: Frees a SQL sqlsocket back to the connection pool           
 *
 *************************************************************************/
int sql_release_socket(SQL_INST * inst, SQLSOCK * sqlsocket) {

	(inst->used)--;
#if HAVE_PTHREAD_H
	sem_post(sqlsocket->semaphore);
#else
	sqlsocket->in_use = SQLSOCK_UNLOCKED;
#endif

	radlog(L_DBG, "rlm_sql: Released sql socket id: %d", sqlsocket->id);

	return 1;
}


/*************************************************************************
 *
 *	Function: sql_userparse
 *
 *	Purpose: Read entries from the database and fill VALUE_PAIR structures
 *
 *************************************************************************/
int sql_userparse(VALUE_PAIR ** first_pair, SQL_ROW row, int mode) {

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
			mode == PW_VP_GROUPDATA)
		return 0;

	pair = pairmake(row[2], row[3], T_OP_CMP_EQ);
	pairadd(first_pair, pair);

	vp_printlist(stderr, *first_pair);

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_getvpdata
 *
 *	Purpose: Get any group check or reply pairs
 *
 *************************************************************************/
int sql_getvpdata(SQL_INST * inst, SQLSOCK * sqlsocket, VALUE_PAIR **pair, char *query, int mode) {

	SQL_ROW row;
	int     rows = 0;

	if ((inst->module->sql_select_query)(sqlsocket, inst->config, query) < 0) {
		radlog(L_ERR, "rlm_sql_getvpdata: database query error");
		return -1;
	}
	while ((row = (inst->module->sql_fetch_row)(sqlsocket, inst->config))) {
		if (sql_userparse(pair, row, mode) != 0) {
			radlog(L_ERR | L_CONS, "rlm_sql:  Error getting data from database");
			(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
			return -1;
		}
		rows++;
	}
	(inst->module->sql_finish_select_query)(sqlsocket, inst->config);

	return rows;
}


static int got_alrm;
static void
alrm_handler() {
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
int sql_check_multi(SQL_INST * inst, SQLSOCK * sqlsocket, char *name, VALUE_PAIR * request, int maxsimul) {

	char    querystr[MAX_QUERY_LEN];
	char    authstr[256];
	VALUE_PAIR *fra;
	SQL_ROW row;
	int     count = 0;
	uint32_t ipno = 0;
	int     mpp = 1;

	sprintf(authstr, "UserName = '%s'", name);
	sprintf(querystr, "SELECT COUNT(*) FROM %s WHERE %s AND AcctStopTime = 0", inst->config->sql_acct_table, authstr);
	if ((inst->module->sql_select_query)(sqlsocket, inst->config, querystr) < 0) {
		radlog(L_ERR, "sql_check_multi: database query error");
		return -1;
	}

	row = (inst->module->sql_fetch_row)(sqlsocket, inst->config);
	count = atoi(row[0]);
	(inst->module->sql_finish_select_query)(sqlsocket, inst->config);

	if (count < maxsimul)
		return 0;

	/*
	 * *      Setup some stuff, like for MPP detection.
	 */
	if ((fra = pairfind(request, PW_FRAMED_IP_ADDRESS)) != NULL)
		ipno = htonl(fra->lvalue);

	count = 0;
	sprintf(querystr, "SELECT * FROM %s WHERE %s AND AcctStopTime = 0", inst->config->sql_acct_table, authstr);
	if ((inst->module->sql_select_query)(sqlsocket, inst->config, querystr) < 0) {
		radlog(L_ERR, "sql_check_multi: database query error");
		return -1;
	}
	while ((row = (inst->module->sql_fetch_row)(sqlsocket, inst->config))) {
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

				radlog(L_ERR, "rlm_sql:  Deleteing stale session [%s] (from nas %s/%s)", row[2], row[4], row[5]);
				sqlsocket1 = sql_get_socket(inst);
				sprintf(querystr, "DELETE FROM %s WHERE RadAcctId = '%s'", inst->config->sql_acct_table, row[0]);
				(inst->module->sql_query)(sqlsocket1, inst->config, querystr);
				(inst->module->sql_finish_query)(sqlsocket1, inst->config);
				sql_release_socket(inst, sqlsocket1);
			}
		}
	}
	(inst->module->sql_finish_select_query)(sqlsocket, inst->config);

	return (count < maxsimul) ? 0 : mpp;
}

void query_log(SQL_INST * inst, char *querystr) {
	FILE   *sqlfile = 0;

	if (inst->config->sqltrace) {
		if ((sqlfile = fopen(inst->config->tracefile, "a")) == (FILE *) NULL) {
			radlog(L_ERR, "rlm_sql: Couldn't open file %s",
						 inst->config->tracefile);
		} else {
#if defined(F_LOCK) && !defined(BSD)
			(void) lockf((int) sqlfile, (int) F_LOCK, (off_t) MAX_QUERY_LEN);
#else
			(void) flock(sqlfile, SQL_LOCK_EX);
#endif
			fputs(querystr, sqlfile);
			fputs(";\n", sqlfile);
			fclose(sqlfile);
		}
	}
}

int sql_set_user(SQL_INST *inst, REQUEST *request, char *sqlusername, char *username) {
	VALUE_PAIR *vp=NULL;
	char    tmpuser[MAX_STRING_LEN];

	tmpuser[0]=0;
	sqlusername[0]=0;

	/* Remove any user attr we added previously */
	pairdelete(&request->packet->vps, PW_SQL_USER_NAME);

	if(username) {
		strNcpy(tmpuser, username, MAX_STRING_LEN);
	} else if(strlen(inst->config->query_user)) {
		radius_xlat(tmpuser, MAX_STRING_LEN, inst->config->query_user, request, NULL);
	} else {
		return 0;
	}

	if(strlen(tmpuser)) {
		sql_escape_string(sqlusername, tmpuser, MAX_STRING_LEN);
		DEBUG2("sql_set_user:  escaped user --> '%s'", sqlusername);
		vp = pairmake("SQL-User-Name", sqlusername, 0);
		if (!vp) {
			radlog(L_ERR, "%s", librad_errstr);
			return -1;
		}

		pairadd(&request->packet->vps, vp);
		return 0;
	}
	return -1;
}

/*
 *      Purpose: Esacpe "'" and any other wierd charactors
 */
int sql_escape_string(char *to, char *from, int length) {
	int x, y;

	DEBUG2("sql_escape in:  '%s'", from);

	for(x=0, y=0; (x < length) && (from[x]!='\0'); x++) {
    switch (from[x]) {
    case 0:				
      to[y++]= '\\';
      to[y++]= '0';
      break;
    case '\n':				
      to[y++]= '\\';
      to[y++]= 'n';
      break;
    case '\r':
      to[y++]= '\\';
      to[y++]= 'r';
      break;
    case '\\':
      to[y++]= '\\';
      to[y++]= '\\';
      break;
    case '\'':
      to[y++]= '\\';
      to[y++]= '\'';
      break;
    case '"':				
      to[y++]= '\\';
      to[y++]= '"';
      break;
    case ';':				
      to[y++]= '\\';
      to[y++]= ';';
      break;
		/* Ascii file separator */
    case '\032':			
      to[y++]= '\\';
      to[y++]= 'Z';
      break;
    default:
      to[y++]= from[x];
    }
  }
	to[y]=0;

	DEBUG2("sql_escape out:  '%s'", to);
	return 1;
}
