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

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/rad_assert.h>

#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/redis/cluster.h>

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

static ssize_t redis_xlat(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
			  void const *mod_inst, UNUSED void const *xlat_inst,
			  REQUEST *request, char const *fmt)
{
	rlm_redis_t const	*inst = mod_inst;
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
		fr_socket_addr_t	node_addr;
		fr_pool_t	*pool;

		RDEBUG3("Overriding node selection");

		p++;
		q = strchr(p, ' ');
		if (!q) {
			REDEBUG("Found node specifier but no command, format is [-][@<host>[:port]] <redis command>");
			return -1;
		}

		if (fr_inet_pton_port(&node_addr.ipaddr, &node_addr.port, p, q - p, AF_UNSPEC, true, true) < 0) {
			RPEDEBUG("Failed parsing node address");
			return -1;
		}

		p = q + 1;

		if (fr_redis_cluster_pool_by_node_addr(&pool, inst->cluster, &node_addr, true) < 0) {
			RPEDEBUG("Failed locating cluster node");
			return -1;
		}

		conn = fr_pool_connection_get(pool, request);
		if (!conn) {
			REDEBUG("No connections available for cluster node");
			return -1;
		}

		argc = rad_expand_xlat(request, p, MAX_REDIS_ARGS, argv, false, sizeof(argv_buf), argv_buf);
		if (argc <= 0) {
			RPEDEBUG("Invalid command: %s", p);
			fr_pool_connection_release(pool, request, conn);
			return -1;
		}

		RDEBUG2("Executing command: %s", argv[0]);
		if (argc > 1) {
			RDEBUG2("With argments");
			RINDENT();
			for (int i = 1; i < argc; i++) RDEBUG2("[%i] %s", i, argv[i]);
			REXDENT();
		}

		if (!read_only) {
			reply = redisCommandArgv(conn->handle, argc, argv, NULL);
			status = fr_redis_command_status(conn, reply);
		} else if (redis_command_read_only(&status, &reply, request, conn, argc, argv) == -2) {
			goto close_conn;
		}

		if (!reply) goto fail;

		switch (status) {
		case REDIS_RCODE_SUCCESS:
			goto reply_parse;

		case REDIS_RCODE_RECONNECT:
		close_conn:
			fr_pool_connection_close(pool, request, conn);
			ret = -1;
			goto finish;

		default:
		fail:
			fr_pool_connection_release(pool, request, conn);
			ret = -1;
			goto finish;
		}
	}

	/*
	 *	Normal node selection and execution based on key
	 */
	argc = rad_expand_xlat(request, p, MAX_REDIS_ARGS, argv, false, sizeof(argv_buf), argv_buf);
	if (argc <= 0) {
		RPEDEBUG("Invalid command: %s", p);
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
		RDEBUG2("Executing command: %s", argv[0]);
		if (argc > 1) {
			RDEBUG2("With arguments");
			RINDENT();
			for (int i = 1; i < argc; i++) RDEBUG2("[%i] %s", i, argv[i]);
			REXDENT();
		}
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

	if (!fr_cond_assert(reply)) {
		ret = -1;
		goto finish;
	}

reply_parse:
	switch (reply->type) {
	case REDIS_REPLY_INTEGER:
		ret = snprintf(*out, outlen, "%lld", reply->integer);
		break;

	case REDIS_REPLY_STATUS:
	case REDIS_REPLY_STRING:
		len = (((size_t)reply->len) >= outlen) ? outlen - 1: (size_t) reply->len;
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

static int mod_bootstrap(void *instance, CONF_SECTION *conf)
{
	rlm_redis_t *inst = instance;

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);

	xlat_register(inst, inst->name, redis_xlat, NULL, NULL, 0, XLAT_DEFAULT_BUF_LEN, false);

	return 0;
}

static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_redis_t *inst = instance;

	inst->cluster = fr_redis_cluster_alloc(inst, conf, &inst->conf, true, NULL, NULL, NULL);
	if (!inst->cluster) return -1;

	return 0;
}

static int mod_load(void)
{
	fr_redis_version_print();

	return 0;
}

extern rad_module_t rlm_redis;
rad_module_t rlm_redis = {
	.magic		= RLM_MODULE_INIT,
	.name		= "redis",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_redis_t),
	.config		= module_config,
	.load		= mod_load,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
};
