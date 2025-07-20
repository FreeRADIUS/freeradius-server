/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include "rlm_redis.h"

static const CONF_PARSER module_config[] = {
	{ "hostname", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_DEPRECATED, REDIS_INST, hostname), NULL },
	{ "server", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, REDIS_INST, hostname), NULL },
	{ "port", FR_CONF_OFFSET(PW_TYPE_SHORT, REDIS_INST, port), "6379" },
	{ "database", FR_CONF_OFFSET(PW_TYPE_INTEGER, REDIS_INST, database), "0" },
	{ "password", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, REDIS_INST, password), NULL },
	{ "query_timeout", FR_CONF_OFFSET(PW_TYPE_SHORT, REDIS_INST, query_timeout), "5" },
	CONF_PARSER_TERMINATOR
};

static int _mod_conn_free(REDISSOCK *dissocket)
{
	if (dissocket->conn) {
		redisFree(dissocket->conn);
		dissocket->conn = NULL;
	}

	if (dissocket->reply) {
		freeReplyObject(dissocket->reply);
		dissocket->reply = NULL;
	}

	return 0;
}

static void *mod_conn_create(TALLOC_CTX *ctx, void *instance)
{
	REDIS_INST *inst = instance;
	REDISSOCK *dissocket = NULL;
	redisContext *conn;
	redisReply *reply = NULL;
	char buffer[1024];
	struct timeval tv;
	tv.tv_sec = inst->query_timeout;
	tv.tv_usec = 0;

	conn = redisConnectWithTimeout(inst->hostname, inst->port, tv);
	if (!conn) {
		ERROR("rlm_redis (%s): Failed calling redisConnectWithTimeout('%s', %d, %d)",
		      inst->xlat_name, inst->hostname, inst->port, inst->query_timeout);
		return NULL;
	}

#ifndef redisReplyReaderGetError
#define redisReplyReaderGetError redisReaderGetError
#endif

	if (conn && conn->err) {
		ERROR("rlm_redis (%s): Problems with redisConnectWithTimeout('%s', %d, %d), %s",
				inst->xlat_name, inst->hostname, inst->port, inst->query_timeout, redisReplyReaderGetError(conn));
		redisFree(conn);
		return NULL;
	}

	if ( redisSetTimeout(conn, tv) == REDIS_ERR ) {
		ERROR("rlm_redis (%s): redisSetTimeout('%s', %d) returned REDIS_ERR", inst->xlat_name, inst->hostname, inst->port);
		redisFree(conn);
		return NULL;
	}

	if (inst->password) {
		snprintf(buffer, sizeof(buffer), "AUTH %s", inst->password);

		reply = redisCommand(conn, buffer);
		if (!reply) {
			ERROR("rlm_redis (%s): Failed to run AUTH", inst->xlat_name);

		do_close:
			if (reply) freeReplyObject(reply);
			redisFree(conn);
			return NULL;
		}


		switch (reply->type) {
		case REDIS_REPLY_STATUS:
			if (strcmp(reply->str, "OK") != 0) {
				ERROR("rlm_redis (%s): Failed authentication: reply %s",
				       inst->xlat_name, reply->str);
				goto do_close;
			}
			break;	/* else it's OK */

		default:
			ERROR("rlm_redis (%s): Unexpected reply to AUTH",
			       inst->xlat_name);
			goto do_close;
		}
	}

	if (inst->database) {
		snprintf(buffer, sizeof(buffer), "SELECT %d", inst->database);

		reply = redisCommand(conn, buffer);
		if (!reply) {
			ERROR("rlm_redis (%s): Failed to run SELECT",
			       inst->xlat_name);
			goto do_close;
		}

		switch (reply->type) {
		case REDIS_REPLY_STATUS:
			if (strcmp(reply->str, "OK") != 0) {
				ERROR("rlm_redis (%s): Failed SELECT %d: reply %s",
				       inst->xlat_name, inst->database,
				       reply->str);
				goto do_close;
			}
			break;	/* else it's OK */

		default:
			ERROR("rlm_redis (%s): Unexpected reply to SELECT",
			       inst->xlat_name);
			goto do_close;
		}
	}

	dissocket = talloc_zero(ctx, REDISSOCK);
	dissocket->conn = conn;
	talloc_set_destructor(dissocket, _mod_conn_free);

	return dissocket;
}

static ssize_t redis_xlat(void *instance, REQUEST *request, char const *fmt, char *out, size_t freespace)
{
	REDIS_INST *inst = instance;
	REDISSOCK *dissocket;
	size_t ret = 0;
	char *buffer_ptr;
	char buffer[21];

	dissocket = fr_connection_get(inst->pool);
	if (!dissocket) return -1;

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
		RDEBUG("rlm_redis (%s): Unsupported result %d from redis",
		       inst->xlat_name, dissocket->reply->type);
		ret = -1;
		goto release;
	}

	if (ret >= freespace) {
		RDEBUG("rlm_redis (%s): Can't write result (%zd), insufficient space (%zd)",
		       inst->xlat_name, ret, freespace);
		ret = -1;
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
static int mod_detach(void *instance)
{
	REDIS_INST *inst = instance;

	fr_connection_pool_free(inst->pool);

	return 0;
}

/*
 *	Query the redis database
 */
int rlm_redis_query(REDISSOCK **dissocket_p, REDIS_INST *inst,
		    char const *query, REQUEST *request)
{
	REDISSOCK *dissocket;
	int argc;
	char const *argv[MAX_REDIS_ARGS];
	char argv_buf[MAX_QUERY_LEN];
	struct timeval tv;
	tv.tv_sec = inst->query_timeout;
	tv.tv_usec = 0;

	if (!query || !*query || !inst || !dissocket_p) {
		return -1;
	}

	argc = rad_expand_xlat(request, query, MAX_REDIS_ARGS, argv, false,
				sizeof(argv_buf), argv_buf);
	if (argc <= 0)
		return -1;

	if (argc >= (MAX_REDIS_ARGS - 1)) {
		RERROR("rlm_redis (%s): query has too many parameters; increase "
				"MAX_REDIS_ARGS and recompile", inst->xlat_name);
		return -1;
	}

	dissocket = *dissocket_p;

	DEBUG2("rlm_redis (%s): executing the query: \"%s\"", inst->xlat_name, query);
	dissocket->reply = redisCommandArgv(dissocket->conn, argc, argv, NULL);
	if (!dissocket->reply) {
		RERROR("%s", dissocket->conn->errstr);

		dissocket = fr_connection_reconnect(inst->pool, dissocket);
		if (!dissocket) {
		error:
			*dissocket_p = NULL;
			return -1;
		}

		dissocket->reply = redisCommand(dissocket->conn, query, tv);
		if (!dissocket->reply) {
			RERROR("Failed after re-connect");
			fr_connection_close(inst->pool, dissocket, NULL);
			goto error;
		}

		*dissocket_p = dissocket;
	}

	if (dissocket->reply->type == REDIS_REPLY_ERROR) {
		RERROR("Query failed, %s", query);
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

static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	REDIS_INST *inst = instance;

	INFO("rlm_redis: libhiredis version: %i.%i.%i", HIREDIS_MAJOR, HIREDIS_MINOR, HIREDIS_PATCH);

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) inst->xlat_name = cf_section_name1(conf);

	xlat_register(inst->xlat_name, redis_xlat, NULL, inst);

	return 0;
}

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	REDIS_INST *inst = instance;

	inst->pool = fr_connection_pool_module_init(conf, inst, mod_conn_create, NULL, NULL);
	if (!inst->pool) {
		return -1;
	}

	inst->redis_query = rlm_redis_query;
	inst->redis_finish_query = rlm_redis_finish_query;

	return 0;
}

extern module_t rlm_redis;
module_t rlm_redis = {
	.magic		= RLM_MODULE_INIT,
	.name		= "redis",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(REDIS_INST),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach
};
