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
	radlog(L_DBG, "rlm_sql:  Attempting to connect #%d", sqlsocket->id);
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
	inst->socknr = 0;

	for (i = 0; i < inst->config->num_sql_socks; i++) {
		radlog(L_DBG, "rlm_sql: starting %d", i);

		sqlsocket = rad_malloc(sizeof(SQLSOCK));
		if (sqlsocket == NULL) {
			return -1;
		}
		sqlsocket->conn = NULL;
		sqlsocket->id = i;
		sqlsocket->state = sockunconnected;

#if HAVE_SEMAPHORE_H
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
			/* FIXME! check return code */
			connect_single_socket(sqlsocket, inst);
		}

		/* Add this socket to the list of sockets */
		sqlsocket->next = inst->sqlpool;
		inst->sqlpool = sqlsocket;
	}

#if HAVE_PTHREAD_H
	pthread_mutex_init(&inst->mutex, NULL);
#endif

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
#if HAVE_PTHREAD_H
	pthread_mutex_destroy(&inst->mutex);
#endif
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
#if HAVE_SEMAPHORE_H
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
	SQLSOCK *cur, *cur2;
	int tried_to_connect = 0;

	while (inst->used == inst->config->num_sql_socks) {
		radlog(L_ERR, "rlm_sql: All sockets are being used! Please increase the maximum number of sockets!");
		return NULL;
	}

	/*
	 * Rotating the socket so that all get used and none get closed due to
	 * inactivity from the SQL server ( such as mySQL ).
	 */
#if HAVE_PTHREAD_H
	pthread_mutex_lock(&inst->mutex);
#endif

	if(inst->socknr == 0) {
	        inst->socknr = inst->config->num_sql_socks;
	}
	inst->socknr--;
	cur2 = inst->sqlpool;
	while (inst->socknr != cur2->id) {
	        cur2 = cur2->next;
	}
#if HAVE_PTHREAD_H
	pthread_mutex_unlock(&inst->mutex);
#endif

	for (cur = cur2; cur; cur = cur->next) {

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

#if HAVE_SEMAPHORE_H
		if (sem_trywait(cur->semaphore) == 0) {
#else
		if (cur->in_use == SQLSOCK_UNLOCKED) {
#endif
			(inst->used)++;
#ifndef HAVE_SEMAPHORE_H
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
#if HAVE_SEMAPHORE_H
	sem_post(sqlsocket->semaphore);
#else
	sqlsocket->in_use = SQLSOCK_UNLOCKED;
#endif

	radlog(L_DBG, "rlm_sql: Released sql socket id: %d", sqlsocket->id);

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_userparse
 *
 *	Purpose: Read entries from the database and fill VALUE_PAIR structures
 *
 *************************************************************************/
int sql_userparse(VALUE_PAIR ** first_pair, SQL_ROW row, int querymode) {

	DICT_ATTR *attr;
	VALUE_PAIR *pair, *check;
	char *ptr;
	char buf[128];
	int pairmode = T_EOL;

	if ((attr = dict_attrbyname(row[2])) == (DICT_ATTR *) NULL) {
		radlog(L_ERR | L_CONS, "rlm_sql: unknown attribute %s", row[2]);
		return (-1);
	}

	if (row[4] != NULL && strlen(row[4]) > 0) {
		ptr = row[4];
		pairmode = gettoken(&ptr, buf, sizeof(buf));
	}
	if (pairmode <= T_EOL) pairmode = T_OP_CMP_EQ;

	/*
	 * If attribute is already there, skip it because we checked usercheck first 
	 * and we want user settings to over ride group settings 
	 */
	if (pairmode != T_OP_ADD && (check = pairfind(*first_pair, attr->attr)) != NULL &&
#ifdef ASCEND_BINARY
			attr->type != PW_TYPE_ABINARY &&
#endif
			querymode == PW_VP_GROUPDATA)
		return 0;

	pair = pairmake(row[2], row[3], pairmode);
	pairadd(first_pair, pair);

	return 0;
}


/*************************************************************************
 *
 *	Function: rlm_sql_fetch_row
 *
 *	Purpose: call the module's sql_fetch_row and implement re-connect
 *
 *************************************************************************/
int rlm_sql_fetch_row(SQLSOCK *sqlsocket, SQL_INST *inst) {
	int ret;

	ret = (inst->module->sql_fetch_row)(sqlsocket, inst->config);

	if (ret == SQL_DOWN) {
		if (connect_single_socket(sqlsocket, inst) < 0) {
			radlog(L_ERR, "rlm_sql: reconnect failed, database down?");
			return -1;
		}

		ret = (inst->module->sql_fetch_row)(sqlsocket, inst->config);

		if (ret) {
			radlog(L_ERR, "rlm_sql: failed after re-connect");
			return -1;
		}
	}

	return ret;
}

/*************************************************************************
 *
 *	Function: rlm_sql_query
 *
 *	Purpose: call the module's sql_query and implement re-connect
 *
 *************************************************************************/
int rlm_sql_query(SQLSOCK *sqlsocket, SQL_INST *inst, char *query) {
	int ret;

	ret = (inst->module->sql_query)(sqlsocket, inst->config, query);

	if (ret == SQL_DOWN) {
		if (connect_single_socket(sqlsocket, inst) < 0) {
			radlog(L_ERR, "rlm_sql: reconnect failed, database down?");
			return -1;
		}

		ret = (inst->module->sql_query)(sqlsocket, inst->config, query);

		if (ret) {
			radlog(L_ERR, "rlm_sql: failed after re-connect");
			return -1;
		}
	}

	return ret;
}

/*************************************************************************
 *
 *	Function: rlm_sql_select_query
 *
 *	Purpose: call the module's sql_select_query and implement re-connect
 *
 *************************************************************************/
int rlm_sql_select_query(SQLSOCK *sqlsocket, SQL_INST *inst, char *query) {
	int ret;

	ret = (inst->module->sql_select_query)(sqlsocket, inst->config, query);

	if (ret == SQL_DOWN) {
		if (connect_single_socket(sqlsocket, inst) < 0) {
			radlog(L_ERR, "rlm_sql: reconnect failed, database down?");
			return -1;
		}

		ret = (inst->module->sql_select_query)(sqlsocket, inst->config, query);

		if (ret) {
			radlog(L_ERR, "rlm_sql: failed after re-connect");
			return -1;
		}
	}

	return ret;
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

	if (rlm_sql_select_query(sqlsocket, inst, query)) {
		radlog(L_ERR, "rlm_sql_getvpdata: database query error");
		return -1;
	}
	while (rlm_sql_fetch_row(sqlsocket, inst)==0) {
		row = sqlsocket->row;
		if (!row)
			break;
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
alrm_handler(int i) {
	got_alrm = 1;
}

void query_log(SQL_INST * inst, char *querystr) {
	FILE   *sqlfile = NULL;

	if (inst->config->sqltrace) {
		if ((sqlfile = fopen(inst->config->tracefile, "a")) == (FILE *) NULL) {
			radlog(L_ERR, "rlm_sql: Couldn't open file %s",
					inst->config->tracefile);
		} else {
			int fd = fileno(sqlfile);
			
			rad_lockfd(fd, MAX_QUERY_LEN);
			fputs(querystr, sqlfile);
			fputs(";\n", sqlfile);
			fclose(sqlfile); /* and release the lock */
		}
	}
}
