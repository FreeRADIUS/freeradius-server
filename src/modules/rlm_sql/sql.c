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
int
sql_init_socketpool(SQL_INST * inst)
{

	SQLSOCK *sqlsocket;
	int     i;

	inst->used = 0;
	inst->sqlpool = NULL;

	for (i = 0; i < inst->config->num_sql_socks; i++) {
		if ((sqlsocket = sql_create_socket(inst)) == NULL) {
			radlog(L_CONS | L_ERR, "rlm_sql:  Failed to connect sqlsocket %d", i);
			return -1;
		} else {
			sqlsocket->id = i;
#if HAVE_PTHREAD_H
			sqlsocket->semaphore = (sem_t *) malloc(sizeof(sem_t));
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
void
sql_poolfree(SQL_INST * inst)
{

	SQLSOCK *cur;

	for (cur = inst->sqlpool; cur; cur = cur->next) {
		sql_close_socket(cur);
	}
#if HAVE_PTHREAD_H
	pthread_mutex_destroy(inst->lock);
	pthread_cond_destroy(inst->notfull);
#endif
}


/*************************************************************************
 *
 *	Function: sql_close_socket
 *
 *	Purpose: Close and free a sql sqlsocket
 *
 *************************************************************************/
int
sql_close_socket(SQLSOCK * sqlsocket)
{

	radlog(L_DBG, "rlm_sql: Closing sqlsocket %d", sqlsocket->id);
	sql_close(sqlsocket);
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
SQLSOCK *
sql_get_socket(SQL_INST * inst)
{


	SQLSOCK *cur;

#if HAVE_PTHREAD_H
	pthread_mutex_lock(inst->lock);
#endif
	while (inst->used == inst->config->num_sql_socks) {
		radlog(L_DBG, "rlm_sql: Waiting for open sql socket");
#if HAVE_PTHREAD_H
		pthread_cond_wait(inst->notfull, inst->lock);
#else
		/*
		 * FIXME: Subsecond sleep needed here 
		 */
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
			radlog(L_DBG, "rlm_sql: Reserved sql socket id: %d", cur->id);
			return cur;
		}
	}

#if HAVE_PTHREAD_H
	pthread_mutex_unlock(inst->lock);
#endif

	/*
	 * Should never get here, but what the hey 
	 */
	return NULL;
}

/*************************************************************************
 *
 *	Function: sql_release_socket
 *
 *	Purpose: Frees a SQL sqlsocket back to the connection pool           
 *
 *************************************************************************/
int
sql_release_socket(SQL_INST * inst, SQLSOCK * sqlsocket)
{

#if HAVE_PTHREAD_H
	pthread_mutex_lock(inst->lock);
#endif
	(inst->used)--;
#if HAVE_PTHREAD_H
	sem_post(sqlsocket->semaphore);
#else
	sqlsocket->in_use = 0;
#endif

	radlog(L_DBG, "rlm_sql: Released sql socket id: %d", sqlsocket->id);

#if HAVE_PTHREAD_H
	pthread_mutex_unlock(inst->lock);
	pthread_cond_signal(inst->notfull);
#endif

	return 1;
}


/*************************************************************************
 *
 *	Function: sql_userparse
 *
 *	Purpose: Read entries from the database and fill VALUE_PAIR structures
 *
 *************************************************************************/
int
sql_userparse(VALUE_PAIR ** first_pair, SQL_ROW row, int mode, int itemtype)
{

	DICT_ATTR *attr;
	VALUE_PAIR *pair, *check;
	int     i = 0;


	if (itemtype == PW_ITEM_REPLY)
		i = 2;

	if ((attr = dict_attrbyname(row[i])) == (DICT_ATTR *) NULL) {
		radlog(L_ERR | L_CONS, "rlm_sql: unknown attribute %s", row[i]);
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

	pair = pairmake(row[i], row[i + 1], T_OP_CMP_EQ);
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
int
sql_getvpdata(SQL_INST * inst, SQLSOCK * sqlsocket, VALUE_PAIR ** check,
							VALUE_PAIR ** reply, char *query, int mode)
{

	SQL_ROW row;
	int     rows = 0;

	if (sql_select_query(inst, sqlsocket, query) < 0) {
		radlog(L_ERR, "rlm_sql_getvpdata: database query error");
		return -1;
	}
	while ((row = sql_fetch_row(sqlsocket))) {
		if (sql_userparse(check, row, mode, PW_ITEM_CHECK) != 0) {
			radlog(L_ERR | L_CONS, "rlm_sql:  Error getting data from database");
			sql_finish_select_query(sqlsocket);
			return -1;
		}
		if (sql_userparse(reply, row, mode, PW_ITEM_REPLY) != 0) {
			radlog(L_ERR | L_CONS, "rlm_sql:  Error getting data from database");
			sql_finish_select_query(sqlsocket);
			return -1;
		}
		rows++;
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
static int
sql_check_ts(SQL_ROW row)
{

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
int
sql_check_multi(SQL_INST * inst, SQLSOCK * sqlsocket, char *name,
								VALUE_PAIR * request, int maxsimul)
{

	char    querystr[MAX_QUERY_LEN];
	char    authstr[256];
	VALUE_PAIR *fra;
	SQL_ROW row;
	int     count = 0;
	uint32_t ipno = 0;
	int     mpp = 1;

	sprintf(authstr, "UserName = '%s'", name);
	sprintf(querystr, "SELECT COUNT(*) FROM %s WHERE %s AND AcctStopTime = 0",
					inst->config->sql_acct_table, authstr);
	if (sql_select_query(inst, sqlsocket, querystr) < 0) {
		radlog(L_ERR, "sql_check_multi: database query error");
		return -1;
	}

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
	if (sql_select_query(inst, sqlsocket, querystr) < 0) {
		radlog(L_ERR, "sql_check_multi: database query error");
		return -1;
	}
	while ((row = sql_fetch_row(sqlsocket))) {
		int     check = sql_check_ts(row);

		if (check == 1) {
			count++;

			if (ipno && atoi(row[19]) == ipno)
				mpp = 2;

		} else if (check == 2)
			radlog(L_ERR, "rlm_sql:  Problem with checkrad [%s] (from nas %s)",
						 name, row[4]);
		else {
			/*
			 *      False record - zap it
			 */

			if (inst->config->deletestalesessions) {
				SQLSOCK *sqlsocket1;

				radlog(L_ERR,
							 "rlm_sql:  Deleteing stale session [%s] (from nas %s/%s)",
							 row[2], row[4], row[5]);
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

void
query_log(SQL_INST * inst, char *querystr)
{
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

VALUE_PAIR *
set_userattr(VALUE_PAIR * first, char *username, char *saveuser, int *savelen)
{

	VALUE_PAIR *uservp = NULL;
	uint8_t escaped_user[MAX_STRING_LEN];

	if ((uservp = pairfind(first, PW_USER_NAME)) != NULL) {
		if (saveuser)
			strNcpy(saveuser, uservp->strvalue, MAX_STRING_LEN);
		if (savelen)
			*savelen = uservp->length;
		if (username) {
			sql_escape_string(escaped_user, username, strlen(username));
		} else {
			sql_escape_string(escaped_user, uservp->strvalue, uservp->length);
		}
		strNcpy(uservp->strvalue, escaped_user, MAX_STRING_LEN);
		uservp->length = strlen(escaped_user);
	}

	return uservp;
}

void
restore_userattr(VALUE_PAIR * uservp, char *saveuser, int savelen)
{

	strNcpy(uservp->strvalue, saveuser, MAX_STRING_LEN);
	uservp->length = savelen;
}
