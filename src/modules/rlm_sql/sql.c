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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2001,2006  The FreeRADIUS server project
 * Copyright 2000  Mike Machado <mike@innercite.com>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2001  Chad Miller <cmiller@surfsouth.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>

#include	<sys/file.h>
#include	<sys/stat.h>

#include	<ctype.h>

#include	"rlm_sql.h"

#ifdef HAVE_PTHREAD_H
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
		if (inst->config->lifetime) time(&sqlsocket->connected);
		sqlsocket->queries = 0;
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

		sqlsocket = rad_malloc(sizeof(*sqlsocket));
		if (sqlsocket == NULL) {
			return -1;
		}
		memset(sqlsocket, 0, sizeof(*sqlsocket));
		sqlsocket->conn = NULL;
		sqlsocket->id = i;
		sqlsocket->state = sockunconnected;

#ifdef HAVE_PTHREAD_H
		rcode = pthread_mutex_init(&sqlsocket->mutex,NULL);
		if (rcode != 0) {
			free(sqlsocket);
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
#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy(&sqlsocket->mutex);
#endif
	free(sqlsocket);
	return 1;
}

static time_t last_logged_failure = 0;


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
	time_t now = time(NULL);

	/*
	 *	Start at the last place we left off.
	 */
	start = inst->last_used;
	if (!start) start = inst->sqlpool;

	cur = start;

	while (cur) {
#ifdef HAVE_PTHREAD_H
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
		 *	If the socket has outlived its lifetime, and
		 *	is connected, close it, and mark it as open for
		 *	reconnections.
		 */
		if (inst->config->lifetime && (cur->state == sockconnected) &&
		    ((cur->connected + inst->config->lifetime) < now)) {
			DEBUG2("Closing socket %d as its lifetime has been exceeded", cur->id);
			(inst->module->sql_close)(cur, inst->config);
			cur->state = sockunconnected;
			goto reconnect;
		}

		/*
		 *	If we have performed too many queries over this
		 *	socket, then close it.
		 */
		if (inst->config->max_queries && (cur->state == sockconnected) &&
		    (cur->queries >= inst->config->max_queries)) {
			DEBUG2("Closing socket %d as its max_queries has been exceeded", cur->id);
			(inst->module->sql_close)(cur, inst->config);
			cur->state = sockunconnected;
			goto reconnect;
		}

		/*
		 *	If we happen upon an unconnected socket, and
		 *	this instance's grace period on
		 *	(re)connecting has expired, then try to
		 *	connect it.  This should be really rare.
		 */
		if ((cur->state == sockunconnected) && (now > inst->connect_after)) {
		reconnect:
			radlog(L_INFO, "rlm_sql (%s): Trying to (re)connect unconnected handle %d..", inst->config->xlat_name, cur->id);
			tried_to_connect++;
			connect_single_socket(cur, inst);
		}

		/* if we still aren't connected, ignore this handle */
		if (cur->state == sockunconnected) {
			DEBUG("rlm_sql (%s): Ignoring unconnected handle %d..", inst->config->xlat_name, cur->id);
		        unconnected++;
#ifdef HAVE_PTHREAD_H
			pthread_mutex_unlock(&cur->mutex);
#endif
			goto next;
		}

		/* should be connected, grab it */
		DEBUG("rlm_sql (%s): Reserving sql socket id: %d", inst->config->xlat_name, cur->id);

		if (unconnected != 0 || tried_to_connect != 0) {
			DEBUG("rlm_sql (%s): got socket %d after skipping %d unconnected handles, tried to reconnect %d though", inst->config->xlat_name, cur->id, unconnected, tried_to_connect);
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
		cur->queries++;
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

	/*
	 *	Suppress most of the log messages.  We don't want to
	 *	flood the log with this message for EVERY packet.
	 *	Instead, write to the log only once a second or so.
	 *
	 *	This code has race conditions when threaded, but the
	 *	only result is that a few more messages are logged.
	 */
	if (now <= last_logged_failure) return NULL;
	last_logged_failure = now;

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
#ifdef HAVE_PTHREAD_H
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
int sql_userparse(VALUE_PAIR ** first_pair, SQL_ROW row)
{
	VALUE_PAIR *pair;
	const char *ptr, *value;
	char buf[MAX_STRING_LEN];
	char do_xlat = 0;
	FR_TOKEN token, operator = T_EOL;

	/*
	 *	Verify the 'Attribute' field
	 */
	if (row[2] == NULL || row[2][0] == '\0') {
		radlog(L_ERR, "rlm_sql: The 'Attribute' field is empty or NULL, skipping the entire row.");
		return -1;
	}

	/*
	 *	Verify the 'op' field
	 */
	if (row[4] != NULL && row[4][0] != '\0') {
		ptr = row[4];
		operator = gettoken(&ptr, buf, sizeof(buf));
		if ((operator < T_OP_ADD) ||
		    (operator > T_OP_CMP_EQ)) {
			radlog(L_ERR, "rlm_sql: Invalid operator \"%s\" for attribute %s", row[4], row[2]);
			return -1;
		}

	} else {
		/*
		 *  Complain about empty or invalid 'op' field
		 */
		operator = T_OP_CMP_EQ;
		radlog(L_ERR, "rlm_sql: The 'op' field for attribute '%s = %s' is NULL, or non-existent.", row[2], row[3]);
		radlog(L_ERR, "rlm_sql: You MUST FIX THIS if you want the configuration to behave as you expect.");
	}

	/*
	 *	The 'Value' field may be empty or NULL
	 */
	value = row[3];
	/*
	 *	If we have a new-style quoted string, where the
	 *	*entire* string is quoted, do xlat's.
	 */
	if (row[3] != NULL &&
	   ((row[3][0] == '\'') || (row[3][0] == '`') || (row[3][0] == '"')) &&
	   (row[3][0] == row[3][strlen(row[3])-1])) {

		token = gettoken(&value, buf, sizeof(buf));
		switch (token) {
			/*
			 *	Take the unquoted string.
			 */
		case T_SINGLE_QUOTED_STRING:
		case T_DOUBLE_QUOTED_STRING:
			value = buf;
			break;

			/*
			 *	Mark the pair to be allocated later.
			 */
		case T_BACK_QUOTED_STRING:
			value = NULL;
			do_xlat = 1;
			break;

			/*
			 *	Keep the original string.
			 */
		default:
			value = row[3];
			break;
		}
	}

	/*
	 *	Create the pair
	 */
	pair = pairmake(row[2], value, operator);
	if (pair == NULL) {
		radlog(L_ERR, "rlm_sql: Failed to create the pair: %s", fr_strerror());
		return -1;
	}
	if (do_xlat) {
		pair->flags.do_xlat = 1;
		strlcpy(pair->vp_strvalue, buf, sizeof(pair->vp_strvalue));
		pair->length = 0;
	}

	/*
	 *	Add the pair into the packet
	 */
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

	if (sqlsocket->conn) {
		ret = (inst->module->sql_query)(sqlsocket, inst->config, query);
	} else {
		ret = SQL_DOWN;
	}

	if (ret == SQL_DOWN) {
	        /* close the socket that failed */
		if (sqlsocket->state == sockconnected) {
			(inst->module->sql_close)(sqlsocket, inst->config);
		}

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

	if (sqlsocket->conn) {
		ret = (inst->module->sql_select_query)(sqlsocket, inst->config,
						       query);
	} else {
		ret = SQL_DOWN;
	}

	if (ret == SQL_DOWN) {
	        /* close the socket that failed */
		if (sqlsocket->state == sockconnected) {
			(inst->module->sql_close)(sqlsocket, inst->config);
		}

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
int sql_getvpdata(SQL_INST * inst, SQLSOCK * sqlsocket, VALUE_PAIR **pair, char *query)
{
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
		if (sql_userparse(pair, row) != 0) {
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
