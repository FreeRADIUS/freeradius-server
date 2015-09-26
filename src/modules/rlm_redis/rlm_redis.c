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
#include "cluster.h"

#define MAX_QUERY_LEN	4096			//!< Maximum command length.
#define MAX_REDIS_ARGS	16			//!< Maximum number of arguments.

static CONF_PARSER module_config[] = {
	REDIS_COMMON_CONFIG,
	CONF_PARSER_TERMINATOR
};

/** rlm_redis module instance
 *
 */
typedef struct rlm_redis_t {
	fr_redis_conf_t		conf;		//!< Connection parameters for the Redis server.
						//!< Must be first field in this struct.

	char const		*name;		//!< Instance name.

	fr_redis_cluster_t	*cluster;	//!< Redis cluster.
} rlm_redis_t;

/** Change the state of a connection to READONLY execute a command and switch to READWRITE
 *
 * @param[out] status_out Where to write the status from the command.
 * @param[out] reply_out Where to write the reply associated with the highest priority status.
 * @param[in] request The current request.
 * @param[in] conn to issue commands with.
 * @param[in] argc Redis command argument count.
 * @param[in] argv Redis command arguments.
 * @return
 *	- 0 success.
 *	- -1 normal failure.
 *	- -2 failure that may leave the connection in a READONLY state.
 */
static int redis_command_read_only(fr_redis_rcode_t *status_out, redisReply **reply_out,
				   REQUEST *request, fr_redis_conn_t *conn, int argc, char const **argv)
{
	bool			maybe_more = false;
	redisReply		*reply;
	fr_redis_rcode_t	status;

	*reply_out = NULL;

	redisAppendCommand(conn->handle, "READONLY");
	redisAppendCommandArgv(conn->handle, argc, argv, NULL);
	redisAppendCommand(conn->handle, "READWRITE");

	/*
	 *	Process the response for READONLY
	 */
	reply = NULL;	/* Doesn't set reply to NULL on error *sigh* */
	if (redisGetReply(conn->handle, (void **)&reply) == REDIS_OK) maybe_more = true;
	status = fr_redis_command_status(conn, reply);
	if (status != REDIS_RCODE_SUCCESS) {
		REDEBUG("Setting READONLY failed");

		*reply_out = reply;
		*status_out = status;

		if (maybe_more) {
			if (redisGetReply(conn->handle, (void **)&reply) != REDIS_OK) return -1;
			fr_redis_reply_free(reply);
			if (redisGetReply(conn->handle, (void **)&reply) != REDIS_OK) return -1;
			fr_redis_reply_free(reply);
		}
		return -1;
	}

	fr_redis_reply_free(reply);

	/*
	 *	Process the response for the command
	 */
	reply = NULL;
	if (redisGetReply(conn->handle, (void **)&reply) == REDIS_OK) maybe_more = true;
	status = fr_redis_command_status(conn, reply);
	if (status != REDIS_RCODE_SUCCESS) {
		*reply_out = reply;
		*status_out = status;

		if (maybe_more) {
			if (redisGetReply(conn->handle, (void **)&reply) != REDIS_OK) return -1;
			fr_redis_reply_free(reply);
		}
		return -1;
	}

	*reply_out = reply;
	*status_out = status;

	/*
	 *	Process the response for READWRITE
	 */
	reply = NULL;
	status = fr_redis_command_status(conn, reply);
	if ((redisGetReply(conn->handle, (void **)&reply) != REDIS_OK) || (status != REDIS_RCODE_SUCCESS)) {
		REDEBUG("Setting READWRITE failed");

		fr_redis_reply_free(*reply_out);
		*reply_out = reply;
		*status_out = status;

		return -2;
	}
	return 0;
}

static ssize_t redis_xlat(void *instance, REQUEST *request, char const *fmt, char **out, size_t freespace)
{
	rlm_redis_t		*inst = instance;
	fr_redis_conn_t		*conn;

	bool			read_only = false;
	uint8_t	const		*key = NULL;
	size_t			key_len = 0;

	fr_redis_cluster_state_t	state;
	fr_redis_rcode_t		status;
	redisReply		*reply = NULL;
	int			s_ret;

	size_t			len;
	int			ret;

	char const		*p = fmt, *q;

	int			argc;
	char const		*argv[MAX_REDIS_ARGS];
	char			argv_buf[MAX_QUERY_LEN];

	if (p[0] == '-') {
		p++;
		read_only = true;
	}

	/*
	 *	Hack to allow querying against a specific node for testing
	 */
	if (p[0] == '@') {
		fr_ipaddr_t		ipaddr;
		uint16_t		port;
		fr_connection_pool_t	*pool;

		RDEBUG3("Overriding node selection");

		p++;
		q = strchr(p, ' ');
		if (!q) {
			REDEBUG("Found node specifier but no command, format is [-][@<host>[:port]] <redis command>");
			return -1;
		}

		if (fr_pton_port(&ipaddr, &port, p, q - p, AF_UNSPEC, true) < 0) {
			REDEBUG("Failed parsing node address: %s", fr_strerror());
			return -1;
		}

		p = q + 1;

		if (fr_redis_cluster_pool_by_node_addr(&pool, inst->cluster, &ipaddr, port, true) < 0) {
			REDEBUG("Failed locating cluster node: %s", fr_strerror());
			return -1;
		}

		conn = fr_connection_get(pool);
		if (!conn) {
			REDEBUG("No connections available for cluster node");
			return -1;
		}

		argc = rad_expand_xlat(request, p, MAX_REDIS_ARGS, argv, false, sizeof(argv_buf), argv_buf);
		if (argc <= 0) {
			REDEBUG("Invalid command: %s", p);
			fr_connection_release(pool, conn);
			return -1;
		}

		RDEBUG2("Executing command: %s", p);
		if (!read_only) {
			reply = redisCommandArgv(conn->handle, argc, argv, NULL);
			status = fr_redis_command_status(conn, reply);
		} else if (redis_command_read_only(&status, &reply, request, conn, argc, argv) == -2) {
			goto close_conn;
		}

		switch (status) {
		case REDIS_RCODE_SUCCESS:
			goto reply_parse;

		case REDIS_RCODE_RECONNECT:
		close_conn:
			fr_connection_close(pool, conn);
			ret = -1;
			goto finish;

		default:
			fr_connection_release(pool, conn);
			ret = -1;
			goto finish;
		}
	}

	/*
	 *	Normal node selection and execution based on key
	 */
	argc = rad_expand_xlat(request, p, MAX_REDIS_ARGS, argv, false, sizeof(argv_buf), argv_buf);
	if (argc <= 0) {
		REDEBUG("Invalid command: %s", p);
		ret = -1;
		goto finish;
	}

	/*
	 *	If we've got multiple arguments, the second one is usually the key.
	 *	The Redis docs say commands should be analysed first to get key
	 *	positions, but this involves sending them to the server, which is
	 *	just as expensive as sending them to the wrong server and receiving
	 *	a redirect.
	 */
	if (argc > 1) {
		key = (uint8_t const *)argv[1];
	 	key_len = strlen((char const *)key);
	}
	for (s_ret = fr_redis_cluster_state_init(&state, &conn, inst->cluster, request, key, key_len, read_only);
	     s_ret == REDIS_RCODE_TRY_AGAIN;	/* Continue */
	     s_ret = fr_redis_cluster_state_next(&state, &conn, inst->cluster, request, status, &reply)) {
		RDEBUG2("Executing command: %s", p);
		if (!read_only) {
			reply = redisCommandArgv(conn->handle, argc, argv, NULL);
			status = fr_redis_command_status(conn, reply);
		} else if (redis_command_read_only(&status, &reply, request, conn, argc, argv) == -2) {
			state.close_conn = true;
		}
	}
	if (s_ret != REDIS_RCODE_SUCCESS) {
		ret = -1;
		goto finish;
	}

reply_parse:
	rad_assert(reply);	/* clang scan */
	switch (reply->type) {
	case REDIS_REPLY_INTEGER:
		ret = snprintf(*out, freespace, "%lld", reply->integer);
		break;

	case REDIS_REPLY_STATUS:
	case REDIS_REPLY_STRING:
		len = (((size_t)reply->len) >= freespace) ? freespace - 1: (size_t) reply->len;
		memcpy(*out, reply->str, len);
		(*out)[len] = '\0';
		ret = reply->len;
		break;

	default:
		REDEBUG("Server returned non-value type \"%s\"",
			fr_int2str(redis_reply_types, reply->type, "<UNKNOWN>"));
		ret = -1;
		break;
	}

finish:
	fr_redis_reply_free(reply);
	return ret;
}

static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_redis_t *inst = instance;

	fr_redis_version_print();

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);
	inst->conf.prefix = talloc_asprintf(inst, "rlm_redis (%s)", inst->name);

	xlat_register(inst->name, redis_xlat, XLAT_DEFAULT_BUF_LEN, NULL, inst);

	return 0;
}

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_redis_t *inst = instance;

	inst->cluster = fr_redis_cluster_alloc(inst, conf, &inst->conf);
	if (!inst->cluster) return -1;

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
};
