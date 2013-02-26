/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
 
/**
 * $Id$
 * @file rlm_redis.c
 * @brief Driver for the REDIS noSQL key value stores.
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 * @copyright 2011  TekSavvy Solutions <gabe@teksavvy.com>
 */
#include <freeradius-devel/ident.h>

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "rlm_redis.h"

static const CONF_PARSER module_config[] = {
	{ "hostname", PW_TYPE_STRING_PTR,
	  offsetof(REDIS_INST, hostname), NULL, "127.0.0.1"},
	{ "port", PW_TYPE_INTEGER,
	  offsetof(REDIS_INST, port), NULL, "6379"},
	{ "database", PW_TYPE_INTEGER,
	  offsetof(REDIS_INST, database), NULL, "0"},
	{ "password", PW_TYPE_STRING_PTR,
	  offsetof(REDIS_INST, password), NULL, NULL},

	{ NULL, -1, 0, NULL, NULL} /* end the list */
};

static int redis_delete_conn(UNUSED void *ctx, void *conn)
{
	REDISSOCK *dissocket = conn;

	redisFree(dissocket->conn);

	if (dissocket->reply) {
		freeReplyObject(dissocket->reply);
		dissocket->reply = NULL;
	}

	free(dissocket);
	return 1;
}

static void *redis_create_conn(void *ctx)
{
	REDIS_INST *inst = ctx;
	REDISSOCK *dissocket = NULL;
	redisContext *conn;
	char buffer[1024];

	conn = redisConnect(inst->hostname, inst->port);
	if (conn->err) return NULL;

	if (inst->password) {
		redisReply *reply = NULL;

		snprintf(buffer, sizeof(buffer), "AUTH %s", inst->password);

		reply = redisCommand(conn, buffer);
		if (!reply) {
			radlog(L_ERR, "rlm_redis (%s): Failed to run AUTH",
			       inst->xlat_name);
		do_close:
			if (reply) freeReplyObject(reply);
			redisFree(conn);
			return NULL;
		}


		switch (reply->type) {
		case REDIS_REPLY_STATUS:
			if (strcmp(reply->str, "OK") != 0) {
				radlog(L_ERR, "rlm_redis (%s): Failed authentication: reply %s",
				       inst->xlat_name, reply->str);
				goto do_close;
			}
			break;	/* else it's OK */

		default:
			radlog(L_ERR, "rlm_redis (%s): Unexpected reply to AUTH",
			       inst->xlat_name);
			goto do_close;
		}
	}

	if (inst->database) {
		redisReply *reply = NULL;

		snprintf(buffer, sizeof(buffer), "SELECT %d", inst->database);

		reply = redisCommand(conn, buffer);
		if (!reply) {
			radlog(L_ERR, "rlm_redis (%s): Failed to run SELECT",
			       inst->xlat_name);
			goto do_close;
		}


		switch (reply->type) {
		case REDIS_REPLY_STATUS:
			if (strcmp(reply->str, "OK") != 0) {
				radlog(L_ERR, "rlm_redis (%s): Failed SELECT %d: reply %s",
				       inst->xlat_name, inst->database,
				       reply->str);
				goto do_close;
			}
			break;	/* else it's OK */

		default:
			radlog(L_ERR, "rlm_redis (%s): Unexpected reply to SELECT",
			       inst->xlat_name);
			goto do_close;
		}
	}

	dissocket = rad_malloc(sizeof(*dissocket));
	memset(dissocket, 0, sizeof(*dissocket));
	dissocket->conn = conn;

	return dissocket;
}

static size_t redis_xlat(void *instance, REQUEST *request,
		      const char *fmt, char *out, size_t freespace)
{
	REDIS_INST *inst = instance;
	REDISSOCK *dissocket;
	size_t ret = 0;
	char *buffer_ptr;
	char buffer[21];

	dissocket = fr_connection_get(inst->pool);
	if (!dissocket) {
		radlog(L_ERR, "rlm_redis (%s): redis_get_socket() failed",
		       inst->xlat_name);
        
		return 0;
	}

	/* Query failed for some reason, release socket and return */
	if (rlm_redis_query(&dissocket, inst, fmt, request) < 0) {
		goto release;
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
		ret = 0;
		goto release;
	}
	
	strlcpy(out, buffer_ptr, freespace);

release:
	rlm_redis_finish_query(dissocket);
	fr_connection_release(inst->pool, dissocket);
	
	return ret;
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int redis_detach(void *instance)
{
	REDIS_INST *inst = instance;

	fr_connection_pool_delete(inst->pool);

	if (inst->xlat_name) {
		xlat_unregister(inst->xlat_name, redis_xlat, instance);
	}

	return 0;
}

/*
 *	Query the redis database
 */
int rlm_redis_query(REDISSOCK **dissocket_p, REDIS_INST *inst,
		    const char *query, REQUEST *request)
{
	REDISSOCK *dissocket;
	int argc;
	const char *argv[MAX_REDIS_ARGS];
	char argv_buf[MAX_QUERY_LEN];

	if (!query || !*query || !inst || !dissocket_p) {
		return -1;
	}

	argc = rad_expand_xlat(request, query, MAX_REDIS_ARGS, argv, 0,
				sizeof(argv_buf), argv_buf);
	if (argc <= 0)
		return -1;

	dissocket = *dissocket_p;

	DEBUG2("executing %s ...", argv[0]);
	dissocket->reply = redisCommandArgv(dissocket->conn, argc, argv, NULL);

	if (!dissocket->reply) {
		radlog(L_ERR, "rlm_redis: (%s) REDIS error: %s",
		       inst->xlat_name, dissocket->conn->errstr);

		dissocket = fr_connection_reconnect(inst->pool, dissocket);
		if (!dissocket) {
		error:
			*dissocket_p = NULL;
			return -1;
		}

		dissocket->reply = redisCommand(dissocket->conn, query);
		if (!dissocket->reply) {
			radlog(L_ERR, "rlm_redis (%s): failed after re-connect",
			       inst->xlat_name);
			fr_connection_del(inst->pool, dissocket);
			goto error;
		}

		*dissocket_p = dissocket;
	}

	if (dissocket->reply->type == REDIS_REPLY_ERROR) {
		radlog(L_ERR, "rlm_redis (%s): query failed, %s",
		       inst->xlat_name, query);
		return -1;
	}

	return 0;
}

/*
 *	Clear the redis reply object if any
 */
int rlm_redis_finish_query(REDISSOCK *dissocket)
{
	if (!dissocket || !dissocket->reply) {
		return -1;
	}

	freeReplyObject(dissocket->reply);
	dissocket->reply = NULL;
	return 0;
}

static int redis_instantiate(CONF_SECTION *conf, void **instance)
{
	REDIS_INST *inst;
	const char *xlat_name;

	/*
	 *	Set up a storage area for instance data
	 */
	*instance = inst = talloc_zero(conf, REDIS_INST);
	if (!inst) return -1;

	/*
	 *	If the configuration parameters can't be parsed, then
	 *	fail.
	 */
	if (cf_section_parse(conf, inst, module_config) < 0) {
		return -1;
	}

	xlat_name = cf_section_name2(conf);

	if (!xlat_name)
		xlat_name = cf_section_name1(conf);

	xlat_register(inst->xlat_name, redis_xlat, inst);

	inst->pool = fr_connection_pool_init(conf, inst,
					     redis_create_conn, NULL,
					     redis_delete_conn);
	if (!inst->pool) {
		return -1;
	}

	inst->redis_query = rlm_redis_query;
	inst->redis_finish_query = rlm_redis_finish_query;

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
