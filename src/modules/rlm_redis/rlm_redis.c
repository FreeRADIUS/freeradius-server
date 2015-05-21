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
 * @brief Driver for the Redis noSQL key value store.
 *
 * @author Gabriel Blanchard
 *
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2011 TekSavvy Solutions <gabe@teksavvy.com>
 * @copyright 2000,2006,2015  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/rad_assert.h>

#include "redis.h"

#define MAX_QUERY_LEN	4096			//!< Maximum command length.
#define MAX_REDIS_ARGS	16			//!< Maximum number of arguments.

/** rlm_redis module instance
 *
 */
typedef struct rlm_redis_t {
	redis_conn_conf_t	*server;	//!< Connection parameters for the Redis server.
						//!< Must be first field in this struct.

	char const		*name;		//!< Instance name.
	fr_connection_pool_t	*pool;		//!< Connection pool.
} rlm_redis_t;

static const CONF_PARSER module_config[] = {
	{ "server", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_REQUIRED, redis_conn_conf_t, hostname), NULL },
	{ "port", FR_CONF_OFFSET(PW_TYPE_SHORT, redis_conn_conf_t, port), "6379" },
	{ "database", FR_CONF_OFFSET(PW_TYPE_INTEGER, redis_conn_conf_t, database), "0" },
	{ "password", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, redis_conn_conf_t, password), NULL },

	{ NULL, -1, 0, NULL, NULL} /* end the list */
};

static ssize_t redis_xlat(void *instance, REQUEST *request, char const *fmt, char *out, size_t freespace)
{
	rlm_redis_t	*inst = instance;
	redis_conn_t	*conn;
	redisReply	*reply;
	size_t		ret = 0, len;

	int		argc;
	char const	*argv[MAX_REDIS_ARGS];
	char		argv_buf[MAX_QUERY_LEN];

	conn = fr_connection_get(inst->pool);
	if (!conn) return -1;

	argc = rad_expand_xlat(request, fmt, MAX_REDIS_ARGS, argv, false, sizeof(argv_buf), argv_buf);
	if (argc <= 0) {
		REDEBUG("Invalid command: %s", fmt);
		ret = -1;
		goto release;
	}

	/* Query failed for some reason, release socket and return */
	reply = redisCommandArgv(conn->handle, argc, argv, NULL);
	switch (fr_redis_command_status(conn, reply)) {
	case 0:
		break;

	default:
		rad_assert(0);
		/* FALL-THROUGH */

	case -1:
		RERROR("Command failed: %s", fr_strerror());
		freeReplyObject(reply);
		ret = -1;
		goto release;

	case -2:
		RERROR("Connection error: %s.  Reconnecting", fr_strerror());
		ret = -1;
		goto release;
	}

	switch (reply->type) {
	case REDIS_REPLY_INTEGER:
		ret = snprintf(out, freespace, "%lld", reply->integer);
		break;

	case REDIS_REPLY_STATUS:
	case REDIS_REPLY_STRING:
		len = (((size_t)reply->len) >= freespace) ? freespace - 1: (size_t) reply->len;
		memcpy(out, reply->str, len);
		ret = reply->len;
		break;

	default:
		REDEBUG("Server returned non-value type \"%s\"",
			fr_int2str(redis_reply_types, reply->type, "<UNKNOWN>"));
		ret = -1;
		break;
	}
	freeReplyObject(reply);

release:
	fr_connection_release(inst->pool, conn);

	return ret;
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int mod_detach(void *instance)
{
	rlm_redis_t *inst = instance;

	fr_connection_pool_free(inst->pool);

	return 0;
}

static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_redis_t *inst = instance;

	fr_redis_version_print();

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);
	inst->server->prefix = talloc_asprintf(inst, "rlm_redis (%s)", inst->name);

	xlat_register(inst->name, redis_xlat, NULL, inst);

	return 0;
}

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_redis_t *inst = instance;

	inst->pool = fr_connection_pool_module_init(conf, inst->server, fr_redis_conn_create, NULL, NULL);
	if (!inst->pool) return -1;

	return 0;
}

extern module_t rlm_redis;
module_t rlm_redis = {
	.magic		= RLM_MODULE_INIT,
	.name		= "redis",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_redis_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach
};
