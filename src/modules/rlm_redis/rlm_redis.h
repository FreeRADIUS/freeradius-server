/*
 * rlm_redis.h
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

#ifndef RLM_REDIS_H
#define	RLM_REDIS_H

#include <freeradius-devel/ident.h>
RCSIDH(rlm_redis_h, "$Id$")

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include <freeradius-devel/modpriv.h>
#include <hiredis/hiredis.h>

typedef struct redis_socket {
	int id;

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t mutex;
#endif
	struct redis_socket *next;
	enum { sockconnected, sockunconnected } state;

	redisContext *conn;
	redisReply *reply;

	time_t connected;
	int	queries;
} REDISSOCK;

typedef struct rlm_redis_t REDIS_INST;

typedef struct rlm_redis_t {
	time_t connect_after;
	REDISSOCK *redispool;
	REDISSOCK *last_used;

	char *xlat_name;

	int numconnections;
	int connect_failure_retry_delay;
	int lifetime;
	int max_queries;

	char *hostname;
	int port;
	char *password;

	REDISSOCK *(*redis_get_socket)(REDIS_INST * inst);
	int (*redis_release_socket)(REDIS_INST * inst, REDISSOCK *dissocket);
	int (*redis_query)(REDISSOCK *dissocket, REDIS_INST *inst, char *query);
	int (*redis_finish_query)(REDISSOCK *dissocket);
	size_t (*redis_escape_func)(char *out, size_t outlen, const char *in);

} rlm_redis_t;

#define MAX_QUERY_LEN			4096

int rlm_redis_query(REDISSOCK *dissocket, REDIS_INST *inst, char *query);
int rlm_redis_finish_query(REDISSOCK *dissocket);

REDISSOCK * redis_get_socket(REDIS_INST * inst);
int redis_release_socket(REDIS_INST * inst, REDISSOCK *dissocket);

#endif	/* RLM_REDIS_H */

