/*
 * rlm_redis.c
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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2011  TekSavvy Solutions <gabe@teksavvy.com>
 */

#include <freeradius-devel/ident.h>

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "rlm_redis.h"

static const CONF_PARSER module_config[] = {
	{ "num_connections", PW_TYPE_INTEGER,
	  offsetof(REDIS_INST, numconnections), NULL, "20"},
	{ "hostname", PW_TYPE_STRING_PTR,
	  offsetof(REDIS_INST, hostname), NULL, "127.0.0.1"},
	{ "port", PW_TYPE_INTEGER,
	  offsetof(REDIS_INST, port), NULL, "6379"},
	{ "database", PW_TYPE_INTEGER,
	  offsetof(REDIS_INST, database), NULL, "0"},
	{ "password", PW_TYPE_STRING_PTR,
	  offsetof(REDIS_INST, password), NULL, NULL},
	{"connect_failure_retry_delay", PW_TYPE_INTEGER,
	 offsetof(REDIS_INST, connect_failure_retry_delay), NULL, "60"},
	{"lifetime", PW_TYPE_INTEGER,
	 offsetof(REDIS_INST, lifetime), NULL, "0"},
	{"max_queries", PW_TYPE_INTEGER,
	 offsetof(REDIS_INST, max_queries), NULL, "0"},

	{ NULL, -1, 0, NULL, NULL} /* end the list */
};

static int redis_close_socket(REDIS_INST *inst, REDISSOCK *dissocket)
{
	radlog(L_INFO, "rlm_redis (%s): Closing socket %d",
	       inst->xlat_name, dissocket->id);

	if (dissocket->state == sockconnected) {
		redisFree(dissocket->conn);
	}

#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy(&dissocket->mutex);
#endif

	free(dissocket);
	return 1;
}

static int connect_single_socket(REDIS_INST *inst, REDISSOCK *dissocket)
{
	char buffer[1024];

	radlog(L_INFO, "rlm_redis (%s): Attempting to connect #%d",
	       inst->xlat_name, dissocket->id);

	dissocket->conn = redisConnect(inst->hostname, inst->port);

	/*
	 *  Error, or redis is DOWN.
	 */
	if (dissocket->conn->err) {
		radlog(L_CONS | L_ERR, "rlm_redis (%s): Failed to connect DB handle #%d",
		       inst->xlat_name, dissocket->id);
		inst->connect_after = time(NULL) + inst->connect_failure_retry_delay;
		dissocket->state = sockunconnected;
		return -1;
	}

	if (inst->password) {
		snprintf(buffer, sizeof(buffer), "AUTH %s", inst->password);

		dissocket->reply = redisCommand(dissocket->conn, buffer);
		if (!dissocket->reply) {
			radlog(L_ERR, "rlm_redis (%s): Failed to run AUTH",
			       inst->xlat_name);
			redis_close_socket(inst, dissocket);
			return -1;
		}


		switch (dissocket->reply->type) {
		case REDIS_REPLY_STATUS:
			if (strcmp(dissocket->reply->str, "OK") != 0) {
				radlog(L_ERR, "rlm_redis (%s): Failed authentication: reply %s",
				       inst->xlat_name, dissocket->reply->str);
				redis_close_socket(inst, dissocket);
				return -1;
			}
			break;	/* else it's OK */

		default:
			radlog(L_ERR, "rlm_redis (%s): Unexpected reply to AUTH",
			       inst->xlat_name);
			redis_close_socket(inst, dissocket);
			return -1;
		}
	}

	if (inst->database) {
		snprintf(buffer, sizeof(buffer), "SELECT %d", inst->database);

		dissocket->reply = redisCommand(dissocket->conn, buffer);
		if (!dissocket->reply) {
			radlog(L_ERR, "rlm_redis (%s): Failed select database",
			       inst->xlat_name);
			redis_close_socket(inst, dissocket);
			return -1;
		}

		switch (dissocket->reply->type) {
		case REDIS_REPLY_STATUS:
			if (strcmp(dissocket->reply->str, "OK") != 0) {
				radlog(L_ERR, "rlm_redis (%s): Failed SELECT %u : reply %s",
				       inst->xlat_name, inst->database,
				       dissocket->reply->str);
				redis_close_socket(inst, dissocket);
				return -1;
			}
			break;	/* else it's OK */

		default:
			radlog(L_ERR, "rlm_redis (%s): Unexpected reply to SELECT",
			       inst->xlat_name);
			redis_close_socket(inst, dissocket);
			return -1;
		}
	}



	radlog(L_INFO, "rlm_redis (%s): Connected new DB handle, #%d",
	       inst->xlat_name, dissocket->id);

	dissocket->state = sockconnected;
	if (inst->lifetime) time(&dissocket->connected);

	dissocket->queries = 0;
	return 0;
}

static void redis_poolfree(REDIS_INST * inst)
{
	REDISSOCK *cur;
	REDISSOCK *next;

	for (cur = inst->redispool; cur; cur = next) {
		next = cur->next;
		redis_close_socket(inst, cur);
	}

	inst->redispool = NULL;
}

static int redis_xlat(void *instance, REQUEST *request,
		      char *fmt, char *out, size_t freespace,
		      UNUSED RADIUS_ESCAPE_STRING func)
{
	REDIS_INST *inst = instance;
	REDISSOCK *dissocket;
	size_t ret = 0;
	char *buffer_ptr;
	char buffer[21];

	if ((dissocket = redis_get_socket(inst)) == NULL) {
		radlog(L_ERR, "rlm_redis (%s): redis_get_socket() failed",
		       inst->xlat_name);
        
		return 0;
	}

	/* Query failed for some reason, release socket and return */
	if (rlm_redis_query(dissocket, inst, fmt, request) < 0) {
		rlm_redis_finish_query(dissocket);
		redis_release_socket(inst,dissocket);
        
		return 0;
	}

        switch (dissocket->reply->type) {
	case REDIS_REPLY_INTEGER:
                buffer_ptr = buffer;
                snprintf(buffer_ptr, sizeof(buffer), "%lld",
			 dissocket->reply->integer);

                ret = strlen(buffer_ptr);
                break;

	case REDIS_REPLY_STATUS:
	case REDIS_REPLY_STRING:
                buffer_ptr = dissocket->reply->str;
                ret = dissocket->reply->len;
                break;

	default:
                buffer_ptr = NULL;
                break;
        }

	if ((ret >= freespace) || (buffer_ptr == NULL)) {
		RDEBUG("rlm_redis (%s): Can't write result, insufficient space or unsupported result\n",
		       inst->xlat_name);
		
		rlm_redis_finish_query(dissocket);
		redis_release_socket(inst,dissocket);
		
		return 0;
	}
	
	strlcpy(out,buffer_ptr,freespace);
	
	rlm_redis_finish_query(dissocket);
	redis_release_socket(inst,dissocket);
	
	return ret;
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int redis_detach(void *instance)
{
	REDIS_INST *inst = instance;

	redis_poolfree(inst);

	if (inst->xlat_name) {
		xlat_unregister(inst->xlat_name, (RAD_XLAT_FUNC)redis_xlat, instance);
		free(inst->xlat_name);
	}
	free(inst->xlat_name);
	free(inst);

	return 0;
}

static int redis_init_socketpool(REDIS_INST *inst)
{
	int i, rcode;
	int success = 0;
	REDISSOCK *dissocket;

	inst->connect_after = 0;
	inst->redispool = NULL;

	for (i = 0; i < inst->numconnections; i++) {
		radlog(L_DBG, "rlm_redis (%s): starting %d",
		       inst->xlat_name, i);

		dissocket = rad_malloc(sizeof (*dissocket));
		if (dissocket == NULL) {
			return -1;
		}
		memset(dissocket, 0, sizeof (*dissocket));
		dissocket->conn = NULL;
		dissocket->id = i;
		dissocket->state = sockunconnected;

#ifdef HAVE_PTHREAD_H
		rcode = pthread_mutex_init(&dissocket->mutex, NULL);
		if (rcode != 0) {
			free(dissocket);
			radlog(L_ERR, "rlm_redis: Failed to init lock: %s",
			       strerror(errno));
			return 0;
		}
#endif

		if (time(NULL) > inst->connect_after) {
			/*
			 *	This sets the dissocket->state, and
			 *	possibly also inst->connect_after
			 */
			if (connect_single_socket(inst, dissocket) == 0) {
				success = 1;
			}
		}

		/* Add "dis" socket to the list of sockets
		 * pun intended
		 */
		dissocket->next = inst->redispool;
		inst->redispool = dissocket;
	}
	inst->last_used = NULL;

	if (!success) {
		radlog(L_DBG, "rlm_redis (%s): Failed to connect to any redis server.",
		       inst->xlat_name);
	}

	return 1;
}

/*
 *	Peform a redis query. Split into args and pass each one through xlat.
 */
int rlm_redis_query(REDISSOCK *dissocket, REDIS_INST *inst, const char *query,
		    REQUEST *request)
{
	int argc;
	const char *argv[MAX_REDIS_ARGS];
	char argv_buf[MAX_QUERY_LEN];

	if (!query || !*query) {
		return -1;
	}

	argc = rad_expand_xlat(request, query, MAX_REDIS_ARGS, argv, 0,
				sizeof(argv_buf), argv_buf);
	if (argc <= 0)
		return -1;

	DEBUG2("executing %s ...", argv[0]);
	dissocket->reply = redisCommandArgv(dissocket->conn, argc, argv, NULL);

	if (dissocket->reply == NULL) {
		radlog(L_ERR, "rlm_redis: (%s) REDIS error: %s",
		       inst->xlat_name, dissocket->conn->errstr);

		/* close the socket that failed */
		if (dissocket->state == sockconnected) {
                    redisFree(dissocket->conn);
                    dissocket->state = sockunconnected;
		}

		/* reconnect the socket */
		if (connect_single_socket(inst, dissocket) < 0) {
			radlog(L_ERR, "rlm_redis (%s): reconnect failed, database down?",
			       inst->xlat_name);
			return -1;
		}

		DEBUG2("executing query %s", query);
		/* retry the query on the newly connected socket */
		dissocket->reply = redisCommand(dissocket->conn, query);

		if (dissocket->reply == NULL) {
			radlog(L_ERR, "rlm_redis (%s): failed after re-connect",
			       inst->xlat_name);
			return -1;
		}
	}

	if (dissocket->reply->type == REDIS_REPLY_ERROR) {
		radlog(L_ERR, "rlm_redis (%s): query failed, %s",
		       inst->xlat_name, query);
		return -1;
	}

	return 0;
}

/*
 * Clear the redis reply object if any
 */
int rlm_redis_finish_query(REDISSOCK *dissocket)
{
	if (dissocket == NULL) {
		return -1;
	}

	if (dissocket->reply != NULL) {
		freeReplyObject(dissocket->reply);
	} else {
		return -1;
	}

	return 0;
}

static time_t last_logged_failure = 0;

/*************************************************************************
 *
 *	Function: redis_get_socket
 *
 *	Purpose: Return a REDIS socket from the connection pool
 *
 *************************************************************************/
REDISSOCK *redis_get_socket(REDIS_INST *inst)
{
	REDISSOCK *cur, *start;
	int tried_to_connect = 0;
	int unconnected = 0;
	time_t now = time(NULL);

	/*
	 *	Start at the last place we left off.
	 */
	start = inst->last_used;
	if (!start) start = inst->redispool;

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
		if (inst->lifetime && (cur->state == sockconnected) &&
		    ((cur->connected + inst->lifetime) < now)) {
			DEBUG2("Closing socket %d as its lifetime has been exceeded", cur->id);
			redisFree(cur->conn);
			cur->state = sockunconnected;
			goto reconnect;
		}

		/*
		 *	If we have performed too many queries over this
		 *	socket, then close it.
		 */
		if (inst->max_queries && (cur->state == sockconnected) &&
		    (cur->queries >= inst->max_queries)) {
			DEBUG2("Closing socket %d as its max_queries has been exceeded", cur->id);
			redisFree(cur->conn);
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
			radlog(L_INFO, "rlm_redis (%s): Trying to (re)connect unconnected handle %d..", inst->xlat_name, cur->id);
			tried_to_connect++;
			connect_single_socket(inst, cur);
		}

		/* if we still aren't connected, ignore this handle */
		if (cur->state == sockunconnected) {
			DEBUG("rlm_redis (%s): Ignoring unconnected handle %d..", inst->xlat_name, cur->id);
			unconnected++;
#ifdef HAVE_PTHREAD_H
			pthread_mutex_unlock(&cur->mutex);
#endif
			goto next;
		}

		/* should be connected, grab it */
		DEBUG("rlm_redis (%s): Reserving redis socket id: %d",
		      inst->xlat_name, cur->id);

		if (unconnected != 0 || tried_to_connect != 0) {
			DEBUG("rlm_redis (%s): got socket %d after skipping %d unconnected handles, tried to reconnect %d though",
			      inst->xlat_name, cur->id, unconnected, tried_to_connect);
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
			cur = inst->redispool;
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
	radlog(L_INFO, "rlm_redis (%s): There are no DB handles to use! skipped %d, tried to connect %d",
	       inst->xlat_name, unconnected, tried_to_connect);
	return NULL;
}

/*************************************************************************
 *
 *	Function: redis_release_socket
 *
 *	Purpose: Frees a REDIS socket back to the connection pool
 *
 *************************************************************************/
int redis_release_socket(REDIS_INST *inst, REDISSOCK *dissocket)
{

#ifdef HAVE_PTHREAD_H
	pthread_mutex_unlock(&dissocket->mutex);
#endif

	radlog(L_DBG, "rlm_redis (%s): Released redis socket id: %d",
	       inst->xlat_name, dissocket->id);

	return 0;
}

static int redis_instantiate(CONF_SECTION *conf, void **instance)
{
	REDIS_INST *inst;
	const char *xlat_name;

	/*
	 *	Set up a storage area for instance data
	 */
	inst = rad_malloc(sizeof (REDIS_INST));
	if (!inst) {
		return -1;
	}
	memset(inst, 0, sizeof (*inst));

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		free(inst);
		return -1;
	}

	xlat_name = cf_section_name2(conf);

	if (!xlat_name)
		xlat_name = cf_section_name1(conf);

	inst->xlat_name = strdup(xlat_name);
	xlat_register(inst->xlat_name, (RAD_XLAT_FUNC)redis_xlat, inst);

	if (redis_init_socketpool(inst) < 0) {
		redis_detach(inst);
		return -1;
	}

	inst->redis_query = rlm_redis_query;
	inst->redis_finish_query = rlm_redis_finish_query;
	inst->redis_get_socket = redis_get_socket;
	inst->redis_release_socket = redis_release_socket;

	*instance = inst;

	return 0;
}

module_t rlm_redis = {
	RLM_MODULE_INIT,
	"redis",
	RLM_TYPE_THREAD_SAFE, /* type */
	redis_instantiate, /* instantiation */
	redis_detach, /* detach */
	{
		NULL, /* authentication */
		NULL, /* authorization */
		NULL, /* preaccounting */
		NULL, /* accounting */
		NULL, /* checksimul */
		NULL, /* pre-proxy */
		NULL, /* post-proxy */
		NULL /* post-auth */
	},
};
