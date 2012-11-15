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

typedef struct redis_socket_t {
	redisContext	*conn;
        redisReply      *reply;
} REDISSOCK;

typedef struct rlm_redis_t REDIS_INST;

typedef struct rlm_redis_t {
        char            *xlat_name;

        char            *hostname;
        int             port;
	int		database;
	char		*password;
	fr_connection_pool_t *pool;

        int (*redis_query)(REDISSOCK **dissocket_p, REDIS_INST *inst, char *query);
        int (*redis_finish_query)(REDISSOCK *dissocket);
        size_t (*redis_escape_func)(REQUEST *request, char *out, size_t outlen, const char *in, void *);

} rlm_redis_t;

#define MAX_QUERY_LEN			4096

int rlm_redis_query(REDISSOCK **dissocket_p, REDIS_INST *inst, char *query);
int rlm_redis_finish_query(REDISSOCK *dissocket);

#endif	/* RLM_REDIS_H */

