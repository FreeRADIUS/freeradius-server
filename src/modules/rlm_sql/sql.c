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

#include	"radiusd.h"
#include	"conffile.h"
#include	"rlm_sql.h"

#if HAVE_PTHREAD_H
#include	<pthread.h>
#endif


/*
 * Connect to a server.  If error, set this socket's state to be
 * "sockunconnected" and set a grace period, during which we won't try
 * connecting again (to prevent unduly lagging the server and being
 * impolite to a DB server that may be having other issues).  If
 * successful in connecting, set state to sockconnected.
 * - chad
 */
static int connect_single_socket(SQLSOCK *sqlsocket, SQL_INST *inst)
{
	int rcode;
	radlog(L_DBG, "rlm_sql (%s): Attempting to connect %s #%d",
	       inst->config->xlat_name, inst->module->name, sqlsocket->id);

	rcode = (inst->module->sql_init_socket)(sqlsocket, inst->config);
	if (rcode == 0) {
		radlog(L_DBG, "rlm_sql (%s): Connected new DB handle, #%d",
		       inst->config->xlat_name, sqlsocket->id);
		sqlsocket->state = sockconnected;
		return(0);
	}

	/*
	 *  Error, or SQL_DOWN.
	 */
	radlog(L_CONS | L_ERR, "rlm_sql (%s): Failed to connect DB handle #%d", inst->config->xlat_name, sqlsocket->id);
	inst->connect_after = time(NULL) + inst->config->connect_failure_retry_delay;
	sqlsocket->state = sockunconnected;
	return(-1);
}


/*************************************************************************
 *
 *	Function: sql_init_socketpool
 *
 *	Purpose: Connect to the sql server, if possible
 *
 *************************************************************************/
int sql_init_socketpool(SQL_INST * inst)
{
	int i, rcode;
	int success = 0;
	SQLSOCK *sqlsocket;

	inst->connect_after = 0;
	inst->sqlpool = NULL;

	for (i = 0; i < inst->config->num_sql_socks; i++) {
		radlog(L_DBG, "rlm_sql (%s): starting %d",
		       inst->config->xlat_name, i);

		sqlsocket = rad_malloc(sizeof(SQLSOCK));
		if (sqlsocket == NULL) {
			return -1;
		}
		sqlsocket->conn = NULL;
		sqlsocket->id = i;
		sqlsocket->state = sockunconnected;

#if HAVE_PTHREAD_H
		rcode = pthread_mutex_init(&sqlsocket->mutex,NULL);
		if (rcode != 0) {
			radlog(L_ERR, "rlm_sql: Failed to init lock: %s",
			       strerror(errno));
			return 0;
		}
#endif

		if (time(NULL) > inst->connect_after) {
			/*
			 *	This sets the sqlsocket->state, and
			 *	possibly also inst->connect_after
			 */
			if (connect_single_socket(sqlsocket, inst) == 0) {
				success = 1;
			}
		}

		/* Add this socket to the list of sockets */
		sqlsocket->next = inst->sqlpool;
		inst->sqlpool = sqlsocket;
	}
	inst->last_used = NULL;

	if (!success) {
		radlog(L_DBG, "rlm_sql (%s): Failed to connect to any SQL server.",
		       inst->config->xlat_name);
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
void sql_poolfree(SQL_INST * inst)
{
	SQLSOCK *cur;
	SQLSOCK *next;

	for (cur = inst->sqlpool; cur; cur = next) {
		next = cur->next;
		sql_close_socket(inst, cur);
	}

	inst->sqlpool = NULL;
}


/*************************************************************************
 *
 *	Function: sql_close_socket
 *
 *	Purpose: Close and free a sql sqlsocket
 *
 *************************************************************************/
int sql_close_socket(SQL_INST *inst, SQLSOCK * sqlsocket)
{
	radlog(L_DBG, "rlm_sql (%s): Closing sqlsocket %d",
	       inst->config->xlat_name, sqlsocket->id);
	if (sqlsocket->state == sockconnected) {
		(inst->module->sql_close)(sqlsocket, inst->config);
	}
	if (inst->module->sql_destroy_socket) {
		(inst->module->sql_destroy_socket)(sqlsocket, inst->config);
	}
#if HAVE_PTHREAD_H
	pthread_mutex_destroy(&sqlsocket->mutex);
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
SQLSOCK * sql_get_socket(SQL_INST * inst)
{
	SQLSOCK *cur, *start;
	int tried_to_connect = 0;
	int unconnected = 0;

	/*
	 *	Start at the last place we left off.
	 */
	start = inst->last_used;
	if (!start) start = inst->sqlpool;

	cur = start;

	while (cur) {
#if HAVE_PTHREAD_H
		/*
		 *	If this socket is in use by another thread,
		 *	skip it, and try another socket.
		 *
		 *	If it isn't used, then grab it ourselves.
		 */
		if (pthread_mutex_trylock(&cur->mutex) != 0) {
			goto next;
		} /* else we now have the lock */
#endif

		/*
		 *	If we happen upon an unconnected socket, and
		 *	this instance's grace period on
		 *	(re)connecting has expired, then try to
		 *	connect it.  This should be really rare.
		 */
		if ((cur->state == sockunconnected) && (time(NULL) > inst->connect_after)) {
			radlog(L_INFO, "rlm_sql (%s): Trying to (re)connect unconnected handle %d..", inst->config->xlat_name, cur->id);
			tried_to_connect++;
			connect_single_socket(cur, inst);
		}

		/* if we still aren't connected, ignore this handle */
		if (cur->state == sockunconnected) {
			radlog(L_DBG, "rlm_sql (%s): Ignoring unconnected handle %d..", inst->config->xlat_name, cur->id);
		        unconnected++;
#if HAVE_PTHREAD_H
			pthread_mutex_unlock(&cur->mutex);
#endif
			goto next;
		}

		/* should be connected, grab it */
		radlog(L_DBG, "rlm_sql (%s): Reserving sql socket id: %d", inst->config->xlat_name, cur->id);

		if (unconnected != 0 || tried_to_connect != 0) {
			radlog(L_INFO, "rlm_sql (%s): got socket %d after skipping %d unconnected handles, tried to reconnect %d though", inst->config->xlat_name, cur->id, unconnected, tried_to_connect);
		}
		
		/*
		 *	The socket is returned in the locked
		 *	state.
		 *
		 *	We also remember where we left off,
		 *	so that the next search can start from
		 *	here.
		 *
		 *	Note that multiple threads MAY over-write
		 *	the 'inst->last_used' variable.  This is OK,
		 *	as it's a pointer only used for reading.
		 */
		inst->last_used = cur->next;
		return cur;

		/* move along the list */
	next:
		cur = cur->next;

		/*
		 *	Because we didnt start at the start, once we
		 *	hit the end of the linklist, we should go
		 *	back to the beginning and work toward the
		 *	middle!
		 */
		if (!cur) {
			cur = inst->sqlpool;
		}

		/*
		 *	If we're at the socket we started 
		 */
		if (cur == start) {
			break;
		}
	}

	/* We get here if every DB handle is unconnected and unconnectABLE */
	radlog(L_INFO, "rlm_sql (%s): There are no DB handles to use! skipped %d, tried to connect %d", inst->config->xlat_name, unconnected, tried_to_connect);
	return NULL;
}

/*************************************************************************
 *
 *	Function: sql_release_socket
 *
 *	Purpose: Frees a SQL sqlsocket back to the connection pool           
 *
 *************************************************************************/
int sql_release_socket(SQL_INST * inst, SQLSOCK * sqlsocket)
{
#if HAVE_PTHREAD_H
	pthread_mutex_unlock(&sqlsocket->mutex);
#endif

	radlog(L_DBG, "rlm_sql (%s): Released sql socket id: %d",
	       inst->config->xlat_name, sqlsocket->id);

	return 0;
}


/*************************************************************************
 *
 *	Function: sql_userparse
 *
 *	Purpose: Read entries from the database and fill VALUE_PAIR structures
 *
 *************************************************************************/
int sql_userparse(VALUE_PAIR ** first_pair, SQL_ROW row, int querymode)
{
	DICT_ATTR *attr;
	VALUE_PAIR *pair, *check;
	char *ptr;
	char buf[128];
	int pairmode = T_EOL;

	if ((attr = dict_attrbyname(row[2])) == (DICT_ATTR *) NULL) {
		radlog(L_ERR | L_CONS, "rlm_sql: unknown attribute %s",
		       row[2]);
		return (-1);
	}

	if (row[4] != NULL && strlen(row[4]) > 0) {
		ptr = row[4];
		pairmode = gettoken(&ptr, buf, sizeof(buf));
	} else {
		/*
		 *  'op' fields of NULL are a plague, and a bane on the
		 *  existence of mankind.
		 */
		radlog(L_ERR, "rlm_sql: The 'op' field for attribute '%s = %s' is NULL, or non-existent.", row[2], row[3]);
		radlog(L_ERR, "rlm_sql: You MUST FIX THIS if you want the configuration to behave as you expect.");
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
int rlm_sql_fetch_row(SQLSOCK *sqlsocket, SQL_INST *inst)
{
	int ret;

	if (sqlsocket->conn) {
		ret = (inst->module->sql_fetch_row)(sqlsocket, inst->config);
	} else {
		ret = SQL_DOWN;
	}

	if (ret == SQL_DOWN) {
	        /* close the socket that failed, but only if it was open */
		if (sqlsocket->conn) {
			(inst->module->sql_close)(sqlsocket, inst->config);
		}

		/* reconnect the socket */
		if (connect_single_socket(sqlsocket, inst) < 0) {
			radlog(L_ERR, "rlm_sql (%s): reconnect failed, database down?", inst->config->xlat_name);
			return -1;
		}

		/* retry the query on the newly connected socket */
		ret = (inst->module->sql_fetch_row)(sqlsocket, inst->config);

		if (ret) {
			radlog(L_ERR, "rlm_sql (%s): failed after re-connect",
			       inst->config->xlat_name);
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
int rlm_sql_query(SQLSOCK *sqlsocket, SQL_INST *inst, char *query)
{
	int ret;

	/*
	 *	If there's no query, return an error.
	 */
	if (!query || !*query) {
		return -1;
	}

	ret = (inst->module->sql_query)(sqlsocket, inst->config, query);

	if (ret == SQL_DOWN) {
	        /* close the socket that failed */
	        (inst->module->sql_close)(sqlsocket, inst->config);

		/* reconnect the socket */
		if (connect_single_socket(sqlsocket, inst) < 0) {
			radlog(L_ERR, "rlm_sql (%s): reconnect failed, database down?", inst->config->xlat_name);
			return -1;
		}

		/* retry the query on the newly connected socket */
		ret = (inst->module->sql_query)(sqlsocket, inst->config, query);

		if (ret) {
			radlog(L_ERR, "rlm_sql (%s): failed after re-connect",
			       inst->config->xlat_name);
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
int rlm_sql_select_query(SQLSOCK *sqlsocket, SQL_INST *inst, char *query)
{
	int ret;

	/*
	 *	If there's no query, return an error.
	 */
	if (!query || !*query) {
		return -1;
	}

	ret = (inst->module->sql_select_query)(sqlsocket, inst->config, query);

	if (ret == SQL_DOWN) {
	        /* close the socket that failed */
	        (inst->module->sql_close)(sqlsocket, inst->config);

		/* reconnect the socket */
		if (connect_single_socket(sqlsocket, inst) < 0) {
			radlog(L_ERR, "rlm_sql (%s): reconnect failed, database down?", inst->config->xlat_name);
			return -1;
		}

		/* retry the query on the newly connected socket */
		ret = (inst->module->sql_select_query)(sqlsocket, inst->config, query);

		if (ret) {
			radlog(L_ERR, "rlm_sql (%s): failed after re-connect",
			       inst->config->xlat_name);
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
int sql_getvpdata(SQL_INST * inst, SQLSOCK * sqlsocket, VALUE_PAIR **pair, char *query, int mode)
{
	SQL_ROW row;
	int     rows = 0;

	/*
	 *	If there's no query, return an error.
	 */
	if (!query || !*query) {
		return -1;
	}

	if (rlm_sql_select_query(sqlsocket, inst, query)) {
		radlog(L_ERR, "rlm_sql_getvpdata: database query error");
		return -1;
	}
	while (rlm_sql_fetch_row(sqlsocket, inst)==0) {
		row = sqlsocket->row;
		if (!row)
			break;
		if (sql_userparse(pair, row, mode) != 0) {
			radlog(L_ERR | L_CONS, "rlm_sql (%s): Error getting data from database", inst->config->xlat_name);
			(inst->module->sql_finish_select_query)(sqlsocket, inst->config);
			return -1;
		}
		rows++;
	}
	(inst->module->sql_finish_select_query)(sqlsocket, inst->config);

	return rows;
}

void query_log(REQUEST *request, SQL_INST *inst, char *querystr)
{
	FILE   *sqlfile = NULL;

	if (inst->config->sqltrace) {
		char buffer[8192];

		if (!radius_xlat(buffer, sizeof(buffer),
				 inst->config->tracefile, request, NULL)) {
		  radlog(L_ERR, "rlm_sql (%s): xlat failed.",
			 inst->config->xlat_name);
		  return;
		}

		if ((sqlfile = fopen(buffer, "a")) == (FILE *) NULL) {
			radlog(L_ERR, "rlm_sql (%s): Couldn't open file %s",
			       inst->config->xlat_name,
			       buffer);
		} else {
			int fd = fileno(sqlfile);
			
			rad_lockfd(fd, MAX_QUERY_LEN);
			fputs(querystr, sqlfile);
			fputs(";\n", sqlfile);
			fclose(sqlfile); /* and release the lock */
		}
	}
}
