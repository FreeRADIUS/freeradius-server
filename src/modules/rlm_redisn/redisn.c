/*
 *  redisn.c		rlm_redisn - FreeRADIUS REDIS Module
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
 * Copyright 2011  Manuel Guesdon <mguesdon@oxymium.net>
 *
 * Precision from MGuesdon: code from sql.c and rlm_redis.c
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include	<freeradius-devel/radiusd.h>

#include	<sys/file.h>
#include	<sys/stat.h>

#include	<ctype.h>

#include	"rlm_redisn.h"

int redisn_destroy_socket(REDIS_INST *inst, REDISSOCK * redis_socket);
void redisn_socket_free_row(REDIS_INST * inst, REDISSOCK * redis_socket);

/*
 * Connect to a server.  If error, set this socket's state to be
 * "sockunconnected" and set a grace period, during which we won't try
 * connecting again to the server.  If successful in connecting, set state to 
 * sockconnected.
 */
static int connect_single_socket_to_server(REDIS_INST *inst, REDISSOCK *redis_socket,int server_index)
{
  DEBUG2("rlm_redisn (%s): Attempting to connect socket #%d to server #%d (%d:%s@%s/%d) with timeout: %d\n",
	 inst->xlat_name, redis_socket->id,
	 server_index,
	 inst->server_dbs[server_index],
	 (inst->server_passwords[server_index] ? inst->server_passwords[server_index] : ""),
	 inst->server_names[server_index],
	 inst->server_ports[server_index],
	 inst->query_timeout);

  redis_socket->server_index=server_index;

  if (inst->query_timeout) {
    struct timeval tv;
    tv.tv_sec=inst->query_timeout;
    tv.tv_usec=0;
    redis_socket->conn = redisConnectWithTimeout(inst->server_names[server_index], inst->server_ports[server_index],tv);  
  }
  else {
    redis_socket->conn = redisConnect(inst->server_names[server_index], inst->server_ports[server_index]);
  }
  if (redis_socket->conn->err)
    {
      /*
       *  Error, or redis is DOWN.
       */
      radlog(L_CONS | L_ERR, "rlm_redisn (%s): Failed to connect DB handle #%d",
	     inst->xlat_name, redis_socket->id);
      inst->server_connect_afters[server_index]=time(NULL) + inst->connect_failure_retry_delay;
      redisn_close_socket(inst, redis_socket);
      return -1;
    }
  else
    {
      radlog(L_INFO, "rlm_redisn (%s): Connected new DB handle, #%d",
	     inst->xlat_name, redis_socket->id);
      
      redis_socket->state = sockconnected;
      if (inst->lifetime)
	time(&redis_socket->connected);
      
      redis_socket->queries = 0;
      
      if (inst->server_passwords[server_index] &&
	    inst->server_passwords[server_index][0]!='\0') {
	char buffer[1024];
	
	snprintf(buffer, sizeof(buffer), "AUTH %s", inst->server_passwords[server_index]);
	
	DEBUG("executing query %s", buffer);
	redis_socket->reply = redisCommand(redis_socket->conn, buffer);
	if (redis_socket->reply == NULL) {
	  radlog(L_ERR, "rlm_redisn (%s): Failed to run AUTH",
		 inst->xlat_name);
	  redisn_close_socket(inst, redis_socket);
	  return -1;
	}


	switch (redis_socket->reply->type) {
	case REDIS_REPLY_STATUS:
	  if (strcmp(redis_socket->reply->str, "OK") != 0) {
	    radlog(L_ERR, "rlm_redisn (%s): Failed authentication: reply %s",
		   inst->xlat_name, redis_socket->reply->str);
	    redisn_close_socket(inst, redis_socket);
	    return -1;
	  }			
	  break;	/* else it's OK */
	default:
	  radlog(L_ERR, "rlm_redisn (%s): Unexpected reply to AUTH",
		 inst->xlat_name);
	  redisn_close_socket(inst, redis_socket);
	  return -1;
	}
	rlm_redisn_finish_query(inst, redis_socket);
      }
      if (inst->server_dbs[server_index]>0) {
	char buffer[1024];
	
	snprintf(buffer, sizeof(buffer), "SELECT %d", inst->server_dbs[server_index]);
	
	DEBUG("executing query %s", buffer);
	redis_socket->reply = redisCommand(redis_socket->conn, buffer);
	if (!redis_socket->reply)
	  {
	    radlog(L_ERR, "rlm_redisn (%s): Failed to run SELECT",
		   inst->xlat_name);
	    redisn_close_socket(inst, redis_socket);
	    return -1;
	  }
	
	switch (redis_socket->reply->type) {
	case REDIS_REPLY_STATUS:
	  if (strcmp(redis_socket->reply->str, "OK") != 0) {
	    radlog(L_ERR, "rlm_redisn (%s): Failed SELECT: reply %s",
		   inst->xlat_name, redis_socket->reply->str);
	    redisn_close_socket(inst, redis_socket);
	    return -1;
	  }			
	  break;	/* else it's OK */
	default:
	  radlog(L_ERR, "rlm_redisn (%s): Unexpected reply to AUTH",
		 inst->xlat_name);
	  rlm_redisn_finish_query(inst, redis_socket);
	  return -1;
	}
	rlm_redisn_finish_query(inst, redis_socket);
      }
      
      return 0;
    }
}

/*
 * Connect to a server.  If error, set this socket's state to be
 * "sockunconnected" and set a grace period, during which we won't try
 * connecting again (to prevent unduly lagging the server and being
 * impolite to a DB server that may be having other issues).  If
 * successful in connecting, set state to sockconnected.
 * - chad
 */
static int connect_single_socket(REDIS_INST *inst, REDISSOCK *redis_socket)
{
  int ret=0;
  DEBUG2("rlm_redisn (%s): Attempting to connect #%d",
	 inst->xlat_name, redis_socket->id);

  int first_use_server=inst->next_use_server;
  time_t now=time(NULL);

  do {    
    if (now>inst->server_connect_afters[inst->next_use_server]) {
      ret=connect_single_socket_to_server(inst,redis_socket,inst->next_use_server);
    }
    inst->next_use_server++;
    if (inst->next_use_server>=inst->servers_count)
      inst->next_use_server=0;
  } while(ret!=0 &&
	  inst->next_use_server!=first_use_server);
  return ret;
}

/*************************************************************************
 *
 *	Function: redisn_init_socketpool
 *
 *	Purpose: Connect to the REDIS server, if possible
 *
 *************************************************************************/
int redisn_init_socketpool(REDIS_INST * inst)
{
	int i, rcode;
	int success = 0;
	REDISSOCK *redis_socket;

	inst->redisnpool = NULL;

	for (i = 0; i < inst->num_redisn_socks; i++) {
		radlog(L_DBG, "rlm_redisn (%s): starting %d",
		       inst->xlat_name, i);

		redis_socket = rad_malloc(sizeof(*redis_socket));
		if (redis_socket == NULL) {
			return -1;
		}
		memset(redis_socket, 0, sizeof(*redis_socket));
		redis_socket->conn = NULL;
		redis_socket->id = i;
		redis_socket->state = sockunconnected;

#ifdef HAVE_PTHREAD_H
		rcode = pthread_mutex_init(&redis_socket->mutex,NULL);
		if (rcode != 0) {
			free(redis_socket);
			radlog(L_ERR, "rlm_redisn: Failed to init lock: %s",
			       strerror(errno));
			return -1;
		}
#endif

		if (connect_single_socket(inst, redis_socket) == 0) {
				success = 1;
		}

		/* Add this socket to the list of sockets */
		redis_socket->next = inst->redisnpool;
		inst->redisnpool = redis_socket;
	}
	inst->last_used = NULL;

	if (!success) {
		radlog(L_DBG, "rlm_redisn (%s): Failed to connect to any REDIS server.",
		       inst->xlat_name);
	}

	return 1;
}

int redisn_destroy_socket(REDIS_INST *inst, REDISSOCK * redis_socket)
{
  redisn_close_socket(inst,redis_socket);
#ifdef HAVE_PTHREAD_H
  pthread_mutex_destroy(&redis_socket->mutex);
#endif
  free(redis_socket);
  return 0;
}

/*************************************************************************
 *
 *     Function: redisn_poolfree
 *
 *     Purpose: Clean up and free REDIS Sockets pool
 *
 *************************************************************************/
void redisn_poolfree(REDIS_INST * inst)
{
	REDISSOCK *cur;
	REDISSOCK *next;
	for (cur = inst->redisnpool; cur; cur = next) {
		next = cur->next;
		redisn_destroy_socket(inst, cur);
	}

	inst->redisnpool = NULL;
}


/*************************************************************************
 *
 *	Function: redisn_close_socket
 *
 *	Purpose: Close and clean a REDIS redis_socket
 *
 *************************************************************************/
int redisn_close_socket(REDIS_INST *inst, REDISSOCK * redis_socket)
{
	radlog(L_INFO, "rlm_redisn (%s): Closing redis_socket %d (server #%d)",
	       inst->xlat_name, redis_socket->id,redis_socket->server_index);
	rlm_redisn_finish_query(inst, redis_socket);
	if (redis_socket->conn) {
	    redis_socket->state = sockunconnected;
	    redisFree(redis_socket->conn);
	    redis_socket->conn=NULL;
	  }
	return 1;
}

static time_t last_logged_failure = 0;


/*************************************************************************
 *
 *	Function: redisn_get_socket
 *
 *	Purpose: Return a REDIS redis_socket from the connection pool
 *
 *************************************************************************/
REDISSOCK * redisn_get_socket(REDIS_INST * inst)
{
	REDISSOCK *cur, *start;
	int tried_to_connect = 0;
	int unconnected = 0;
	time_t now = time(NULL);

	/*
	 *	Start at the last place we left off.
	 */
	start = inst->last_used;
	if (!start) start = inst->redisnpool;

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
			redisn_close_socket(inst, cur);
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
			redisn_close_socket(inst, cur);
			cur->state = sockunconnected;
			goto reconnect;
		}

		/*
		 *	If we happen upon an unconnected socket then try to
		 *	connect it.  This should be really rare.
		 */
		if (cur->state == sockunconnected) {
		reconnect:
			radlog(L_INFO, "rlm_redisn (%s): Trying to (re)connect unconnected handle %d..", inst->xlat_name, cur->id);
			tried_to_connect++;
			connect_single_socket(inst, cur);
		}

		/* if we still aren't connected, ignore this handle */
		if (cur->state == sockunconnected) {
			DEBUG("rlm_redisn (%s): Ignoring unconnected handle %d..", inst->xlat_name, cur->id);
		        unconnected++;
#ifdef HAVE_PTHREAD_H
			pthread_mutex_unlock(&cur->mutex);
#endif
			goto next;
		}

		/* should be connected, grab it */
		DEBUG("rlm_redisn (%s): Reserving REDIS socket id: %d", inst->xlat_name, cur->id);

		if (unconnected != 0 || tried_to_connect != 0) {
			DEBUG("rlm_redisn (%s): got socket %d after skipping %d unconnected handles, tried to reconnect %d though", inst->xlat_name, cur->id, unconnected, tried_to_connect);
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
			cur = inst->redisnpool;
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
	if (now <= last_logged_failure)
	  return NULL;
	last_logged_failure = now;

	/* We get here if every DB handle is unconnected and unconnectABLE */
	radlog(L_ERR, "rlm_redisn (%s): There are no DB handles to use! skipped %d, tried to connect %d", inst->xlat_name, unconnected, tried_to_connect);
	return NULL;
}

/*************************************************************************
 *
 *	Function: redisn_release_socket
 *
 *	Purpose: Frees a REDIS redis_socket back to the connection pool
 *
 *************************************************************************/
int redisn_release_socket(REDIS_INST * inst, REDISSOCK * redis_socket)
{
#ifdef HAVE_PTHREAD_H
	pthread_mutex_unlock(&redis_socket->mutex);
#endif

	radlog(L_DBG, "rlm_redisn (%s): Released REDIS socket id: %d",
	       inst->xlat_name, redis_socket->id);

	return 0;
}


/*************************************************************************
 *
 *	Function: redisn_userparse
 *
 *	Purpose: Read entries from the database and fill VALUE_PAIR structures
 *
 *************************************************************************/
int redisn_userparse(UNUSED REDIS_INST * inst, VALUE_PAIR ** first_pair, REDIS_ROW row)
{
	VALUE_PAIR *pair;
	const char *ptr, *value;
	char buf[MAX_STRING_LEN];
	char do_xlat = 0;
	FR_TOKEN token, operator = T_EOL;

#define FIELD_ATTRIBUTE 0
#define FIELD_OPERATOR 1
#define FIELD_VALUE 2
	/*
	 *	Verify the 'Attribute' field
	 */
	if (row[FIELD_ATTRIBUTE] == NULL || row[FIELD_ATTRIBUTE][0] == '\0') {
		radlog(L_ERR, "rlm_redisn: The 'Attribute' field is empty or NULL, skipping the entire row.");
		return -1;
	}

	/*
	 *	Verify the 'op' field
	 */
	if (row[FIELD_OPERATOR] != NULL && row[FIELD_OPERATOR][0] != '\0') {
		ptr = row[FIELD_OPERATOR];
		operator = gettoken(&ptr, buf, sizeof(buf));
		if ((operator < T_OP_ADD) ||
		    (operator > T_OP_CMP_EQ)) {
			radlog(L_ERR, "rlm_redisn: Invalid operator \"%s\" for attribute %s", row[FIELD_OPERATOR], row[FIELD_ATTRIBUTE]);
			return -1;
		}

	} else {
		/*
		 *  Complain about empty or invalid 'op' field
		 */
		operator = T_OP_CMP_EQ;
		radlog(L_ERR, "rlm_redisn: The 'op' field for attribute '%s = %s' is NULL, or non-existent.", row[FIELD_ATTRIBUTE], row[FIELD_ATTRIBUTE]);
		radlog(L_ERR, "rlm_redisn: You MUST FIX THIS if you want the configuration to behave as you expect.");
	}

	/*
	 *	The 'Value' field may be empty or NULL
	 */
	value = row[FIELD_VALUE];
	/*
	 *	If we have a new-style quoted string, where the
	 *	*entire* string is quoted, do xlat's.
	 */
	if (row[FIELD_VALUE] != NULL &&
	   ((row[FIELD_VALUE][0] == '\'') || (row[FIELD_VALUE][0] == '`') || (row[FIELD_VALUE][0] == '"')) &&
	   (row[FIELD_VALUE][0] == row[FIELD_VALUE][strlen(row[FIELD_VALUE])-1])) {

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
			value = row[FIELD_VALUE];
			break;
		}
	}

	/*
	 *	Create the pair
	 */
	pair = pairmake(row[FIELD_ATTRIBUTE], value, operator);
	if (pair == NULL) {
		radlog(L_ERR, "rlm_redisn: Failed to create the pair: %s", fr_strerror());
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

void redisn_socket_free_row(UNUSED REDIS_INST * inst, REDISSOCK * redis_socket)
{
  if (redis_socket->row != NULL) {
    int i=0;
    for(i=0;i<redis_socket->num_fields;i++) {
      if (redis_socket->row[i]!=NULL) {
	free(redis_socket->row[i]);
	redis_socket->row[i]=NULL;
      }
    }
    free(redis_socket->row);
    redis_socket->row=NULL;
  }
  redis_socket->num_fields=0;
}

int redisn_split_string(char*** result,char* string,char separator,int null_terminate_list)
{
  int parts_count=0;
  if (string!=NULL) {
    int i=0;
    int alloc_count=0;
    char* ptr=string;
    char* ptr_start=string;
    char **nextResult=NULL;
    parts_count=1;
    while(*ptr!='\0') {
      if (*ptr==separator)
	parts_count++;
      ptr++;
    }
    alloc_count=parts_count+(null_terminate_list ? 1 : 0);
	    
    *result=(char **)rad_malloc((alloc_count)*sizeof(char *));
    memset(*result, 0, (alloc_count)*sizeof(char *));
    ptr=string;
    nextResult=*result;
    
    do {
      if (*ptr==separator
	  || *ptr=='\0') {
	int len=ptr-ptr_start;
	*nextResult = (char *)rad_malloc(len+1);
	memset(*nextResult, '\0', len+1);
	strlcpy(*nextResult, ptr_start,len + 1);
	DEBUG("redisn_split_string: field #%d: '%s'\n",
	      i,*nextResult);
	nextResult++;
	i++;
	if (*ptr=='\0')
	  break;
	ptr_start=ptr+1;
      }
      ptr++;
    } while(1);

    if (null_terminate_list)
      *nextResult=NULL; 
  }
  return parts_count;
}

/*************************************************************************
 *
 *	Function: rlm_redisn_fetch_row
 *
 *	Purpose: call the module's redisn_fetch_row and implement re-connect
 *
 *************************************************************************/
int rlm_redisn_fetch_row(REDIS_INST *inst, REDISSOCK *redis_socket)
{
  char buffer[21]="";
  char* buffer_ptr=NULL;

  DEBUG("rlm_redisn_fetch_row: redis_socket->cur_row=%d\n",
	(int)redis_socket->cur_row);

  if (redis_socket->row != NULL) {
    redisn_socket_free_row(inst,redis_socket);
  }

  switch (redis_socket->reply->type) {
  case REDIS_REPLY_INTEGER:
    DEBUG("rlm_redisn_fetch_row: query int response %lld\n",
	  redis_socket->reply->integer);
    if (redis_socket->cur_row>0)
      return 0;
    else {
      buffer_ptr = buffer;
      snprintf(buffer_ptr, sizeof(buffer), "%lld",
	       redis_socket->reply->integer);	  
    }
    break;
  case REDIS_REPLY_STATUS:
  case REDIS_REPLY_STRING:
    DEBUG("rlm_redisn_fetch_row: query string/status response '%s'\n",
	  redis_socket->reply->str);
    if (redis_socket->cur_row>0)
      return 0;
    else
      buffer_ptr = buffer;
    break;
  case REDIS_REPLY_ARRAY:	
    DEBUG("rlm_redisn_fetch_row: query array elements count=%d\n",
	  (int)redis_socket->reply->elements);
    if (redis_socket->cur_row>=redis_socket->reply->elements)
      return 0;
    else {
      switch (redis_socket->reply->element[redis_socket->cur_row]->type) {
      case REDIS_REPLY_INTEGER:
	DEBUG("rlm_redisn_fetch_row: query array int response '%lld'\n",
	      redis_socket->reply->element[redis_socket->cur_row]->integer);
	buffer_ptr = buffer;
	snprintf(buffer_ptr, sizeof(buffer), "%lld",
		 redis_socket->reply->element[redis_socket->cur_row]->integer);	  
      break;
      case REDIS_REPLY_STRING:
	DEBUG("rlm_redisn_fetch_row: query array string response '%s'\n",
	      redis_socket->reply->element[redis_socket->cur_row]->str);
	buffer_ptr = redis_socket->reply->element[redis_socket->cur_row]->str;
	break;
      default:
	//TODO
	return -1;
      }
      break;
    default:
      //TODO
      return -1;
    }
  }

  redis_socket->cur_row++;
  
  DEBUG("rlm_redisn_fetch_row: string: '%s'\n",
	buffer_ptr);

  redis_socket->num_fields=redisn_split_string(&redis_socket->row,buffer_ptr,inst->vp_separator[0],0);
  
  return 0;
}

/*************************************************************************
 *
 *	Function: rlm_redisn_query
 *
 *	Purpose: call the module's redisn_query and implement re-connect
 *
 *************************************************************************/
int rlm_redisn_query(REDIS_INST *inst, REDISSOCK *redis_socket, char *query)
{
  rlm_redisn_finish_query(inst, redis_socket);

	/*
	 *	If there's no query, return an error.
	 */
	if (!query || !*query) {
		return -1;
	}

	if (redis_socket->conn) {
	  DEBUG2("executing query %s", query);
	  redis_socket->reply = redisCommand(redis_socket->conn, query);
	}

	if (redis_socket->reply==NULL) {
	        /* close the socket that failed */
		if (redis_socket->state == sockconnected) {
			redisn_close_socket(inst, redis_socket);
		}

		/* reconnect the socket */
		if (connect_single_socket(inst, redis_socket) < 0) {
			radlog(L_ERR, "rlm_redisn (%s): reconnect failed, database down?", inst->xlat_name);
			return -1;
		}

		/* retry the query on the newly connected socket */
		redis_socket->reply = redisCommand(redis_socket->conn, query);

		if (redis_socket->reply == NULL) {
		  radlog(L_ERR, "rlm_redisn (%s): failed after re-connect",
			 inst->xlat_name);
		  return -1;
		}
	}

  if (redis_socket->reply->type == REDIS_REPLY_ERROR)
    {
      radlog(L_ERR, "rlm_redis (%s) %d: query failed, %s",
	     inst->xlat_name,__LINE__, query);
      
      /* Free the reply just in case */
      rlm_redisn_finish_query(inst, redis_socket);
      
      return -1;
    }

  return 0;
}

int rlm_redisn_finish_query(REDIS_INST *inst,REDISSOCK *redis_socket)
{
  if (redis_socket == NULL) {
    return -1;
  }

  if (redis_socket->row)
    redisn_socket_free_row(inst,redis_socket);

  redis_socket->cur_row=0;

  if (redis_socket->reply != NULL) {
    freeReplyObject(redis_socket->reply);
    redis_socket->reply=NULL;
  }

  return 0;
}

/*************************************************************************
 *
 *	Function: redisn_getvpdata
 *
 *	Purpose: Get any group check or reply pairs
 *
 *************************************************************************/
int redisn_getvpdata(REDIS_INST * inst, REDISSOCK * redis_socket, VALUE_PAIR **pair, char *query)
{
	REDIS_ROW row;
	int     rows = 0;
			DEBUG("rlm_redisn %d: redisn_getvpdata",__LINE__);

	if (rlm_redisn_query(inst, redis_socket, query)) {
		radlog(L_ERR, "rlm_redisn_getvpdata: database query error");
		return -1;
	}
	while (rlm_redisn_fetch_row(inst, redis_socket)==0) {
		row = redis_socket->row;
		if (!row)
			break;
		if (redis_socket->num_fields!=3) {
		  radlog(L_ERR | L_CONS, "rlm_redisn (%s): fields count for %s is %d instead of 3", inst->xlat_name,query,redis_socket->num_fields);
			(inst->redisn_finish_query)(inst, redis_socket);
			return -1;
		}
		if (redisn_userparse(inst, pair, row) != 0) {
			radlog(L_ERR | L_CONS, "rlm_redisn (%s): Error getting data from database", inst->xlat_name);
			(inst->redisn_finish_query)(inst, redis_socket);
			return -1;
		}
		rows++;
	}
	DEBUG("rlm_redisn %d: redisn_getvpdata",__LINE__);
	(inst->redisn_finish_query)(inst, redis_socket);

	return rows;
}

void query_log(REQUEST *request, REDIS_INST *inst, char *querystr)
{
	FILE   *file_handle = NULL;

	if (inst->redisntrace) {
		char buffer[8192];

		if (!radius_xlat(buffer, sizeof(buffer),
				 inst->tracefile, request, NULL, inst)) {
		  radlog(L_ERR, "rlm_redisn (%s): xlat failed.",
			 inst->xlat_name);
		  return;
		}

		if ((file_handle = fopen(buffer, "a")) == (FILE *) NULL) {
			radlog(L_ERR, "rlm_redisn (%s): Couldn't open file %s",
			       inst->xlat_name,
			       buffer);
		} else {
			int fd = fileno(file_handle);

			rad_lockfd(fd, MAX_QUERY_LEN);
			fputs(querystr, file_handle);
			fputs(";\n", file_handle);
			fclose(file_handle); /* and release the lock */
		}
	}
}
