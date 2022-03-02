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
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2011 TekSavvy Solutions (gabe@teksavvy.com)
 * @copyright 2000,2006,2015 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/redis/cluster.h>

static CONF_PARSER module_config[] = {
	REDIS_COMMON_CONFIG,
	CONF_PARSER_TERMINATOR
};

/** rlm_redis module instance
 *
 */
typedef struct {
	fr_redis_conf_t		conf;		//!< Connection parameters for the Redis server.
						//!< Must be first field in this struct.

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
				   request_t *request, fr_redis_conn_t *conn, int argc, char const **argv)
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
			fr_redis_reply_free(&reply);
			if (redisGetReply(conn->handle, (void **)&reply) != REDIS_OK) return -1;
			fr_redis_reply_free(&reply);
		}
		return -1;
	}

	fr_redis_reply_free(&reply);

	/*
	 *	Process the response for the command
	 */
	if (redisGetReply(conn->handle, (void **)&reply) == REDIS_OK) maybe_more = true;
	status = fr_redis_command_status(conn, reply);
	if (status != REDIS_RCODE_SUCCESS) {
		*reply_out = reply;
		*status_out = status;

		if (maybe_more) {
			if (redisGetReply(conn->handle, (void **)&reply) != REDIS_OK) return -1;
			fr_redis_reply_free(&reply);
		}
		return -1;
	}

	*reply_out = reply;
	reply = NULL;
	*status_out = status;

	/*
	 *	Process the response for READWRITE
	 */
	if ((redisGetReply(conn->handle, (void **)&reply) != REDIS_OK) ||
	    (fr_redis_command_status(conn, reply) != REDIS_RCODE_SUCCESS)) {
		REDEBUG("Setting READWRITE failed");

		fr_redis_reply_free(&reply);	/* There could be a response we need to free */
		fr_redis_reply_free(reply_out);
		*reply_out = reply;
		*status_out = status;

		return -2;
	}
	fr_redis_reply_free(&reply);	/* Free READWRITE response */

	return 0;
}

static xlat_arg_parser_t const redis_remap_xlat_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Force a redis cluster remap
 *
@verbatim
%{redis_remap:<redis server ip>:<redis server port>}
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t redis_remap_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      xlat_ctx_t const *xctx,
				      request_t *request, fr_value_box_list_t *in)
{
	rlm_redis_t const		*inst = talloc_get_type_abort_const(xctx->mctx->inst->data, rlm_redis_t);

	fr_socket_t			node_addr;
	fr_pool_t			*pool;
	fr_redis_conn_t			*conn;
	fr_redis_cluster_rcode_t	rcode;
	fr_value_box_t			*vb;
	fr_value_box_t			*in_head = fr_dlist_head(in);

	if (fr_inet_pton_port(&node_addr.inet.dst_ipaddr, &node_addr.inet.dst_port, in_head->vb_strvalue, in_head->vb_length,
			      AF_UNSPEC, true, true) < 0) {
		RPEDEBUG("Failed parsing node address");
		return XLAT_ACTION_FAIL;
	}

	if (fr_redis_cluster_pool_by_node_addr(&pool, inst->cluster, &node_addr, true) < 0) {
		RPEDEBUG("Failed locating cluster node");
		return XLAT_ACTION_FAIL;
	}

	conn = fr_pool_connection_get(pool, request);
	if (!conn) {
		REDEBUG("No connections available for cluster node");
		return XLAT_ACTION_FAIL;
	}

	rcode = fr_redis_cluster_remap(request, inst->cluster, conn);
	fr_pool_connection_release(pool, request, conn);

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_strdup(vb, vb, NULL, fr_table_str_by_value(fr_redis_cluster_rcodes_table, rcode, "<INVALID>"), false);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const redis_node_xlat_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_STRING },
	{ .single = true, .type = FR_TYPE_UINT32 },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Return the node that is currently servicing a particular key
 *
@verbatim
%(redis_node:<key> [<index>])
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t redis_node_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     xlat_ctx_t const *xctx,
				     request_t *request, fr_value_box_list_t *in)
{
	rlm_redis_t const			*inst = talloc_get_type_abort_const(xctx->mctx->inst->data, rlm_redis_t);

	fr_redis_cluster_key_slot_t const	*key_slot;
	fr_redis_cluster_node_t const		*node;
	fr_ipaddr_t				ipaddr;
	uint16_t				port;

	unsigned long				idx = 0;
	fr_value_box_t				*vb;
	fr_value_box_t				*key = fr_dlist_head(in);
	fr_value_box_t				*idx_vb = fr_dlist_next(in, key);

	if (idx_vb) idx = idx_vb->vb_uint32;

	key_slot = fr_redis_cluster_slot_by_key(inst->cluster, request, (uint8_t const *)key->vb_strvalue,
						key->vb_length);
	if (idx == 0) {
		node = fr_redis_cluster_master(inst->cluster, key_slot);
	} else {
		node = fr_redis_cluster_slave(inst->cluster, key_slot, idx - 1);
	}

	if (!node) {
		RDEBUG2("No node available for this key slot");
		return XLAT_ACTION_DONE;
	}

	if ((fr_redis_cluster_ipaddr(&ipaddr, node) < 0) || (fr_redis_cluster_port(&port, node) < 0)) {
		REDEBUG("Failed retrieving node information");
		return XLAT_ACTION_FAIL;
	}

	MEM(vb = fr_value_box_alloc_null(ctx));
	fr_value_box_asprintf(vb, vb, NULL, false, "%pV:%u", fr_box_ipaddr(ipaddr), port);
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static xlat_arg_parser_t const redis_args[] = {
	{ .required = true, .variadic = true, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Xlat to make calls to redis
 *
@verbatim
%{redis:<redis command>}
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t redis_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				xlat_ctx_t const *xctx,
				request_t *request, fr_value_box_list_t *in)
{
	rlm_redis_t const	*inst = talloc_get_type_abort_const(xctx->mctx->inst->data, rlm_redis_t);
	xlat_action_t		action = XLAT_ACTION_DONE;
	fr_redis_conn_t		*conn;

	bool			read_only = false;
	uint8_t	const		*key = NULL;
	size_t			key_len = 0;

	fr_redis_cluster_state_t	state;
	fr_redis_rcode_t		status;

	redisReply		*reply = NULL;
	int			s_ret;

	fr_value_box_t		*first = fr_dlist_head(in);
	fr_sbuff_t		sbuff = FR_SBUFF_IN(first->vb_strvalue, first->vb_length);

	int			argc = 0;
	char const		*argv[MAX_REDIS_ARGS];
	size_t			arg_len[MAX_REDIS_ARGS];

	fr_value_box_t		*vb_out;

	if (fr_sbuff_next_if_char(&sbuff, '-')) read_only = true;

	/*
	 *	Hack to allow querying against a specific node for testing
	 */
	if (fr_sbuff_next_if_char(&sbuff, '@')) {
		fr_socket_t	node_addr;
		fr_pool_t	*pool;

		RDEBUG3("Overriding node selection");

		if (fr_inet_pton_port(&node_addr.inet.dst_ipaddr, &node_addr.inet.dst_port,
				      fr_sbuff_current(&sbuff), fr_sbuff_remaining(&sbuff),
				      AF_UNSPEC, true, true) < 0) {
			RPEDEBUG("Failed parsing node address");
			return XLAT_ACTION_FAIL;
		}

		if (fr_redis_cluster_pool_by_node_addr(&pool, inst->cluster, &node_addr, true) < 0) {
			RPEDEBUG("Failed locating cluster node");
			return XLAT_ACTION_FAIL;
		}

		conn = fr_pool_connection_get(pool, request);
		if (!conn) {
			REDEBUG("No connections available for cluster node");
			return XLAT_ACTION_FAIL;
		}

		fr_dlist_talloc_free_head(in);	/* Remove and free server arg */

		fr_dlist_foreach(in, fr_value_box_t, vb) {
			if (argc == NUM_ELEMENTS(argv)) {
				REDEBUG("Too many arguments (%i)", argc);
				REXDENT();
				goto fail;
			}

			argv[argc] = vb->vb_strvalue;
			arg_len[argc] = vb->vb_length;
			argc++;
		}

		RDEBUG2("Executing command: %pV", fr_dlist_head(in));
		if (argc > 1) {
			RDEBUG2("With arguments");
			RINDENT();
			for (int i = 1; i < argc; i++) RDEBUG2("[%i] %s", i, argv[i]);
			REXDENT();
		}

		if (!read_only) {
			reply = redisCommandArgv(conn->handle, argc, argv, arg_len);
			status = fr_redis_command_status(conn, reply);
		} else if (redis_command_read_only(&status, &reply, request, conn, argc, argv) == -2) {
			goto close_conn;
		}

		if (!reply) goto fail;

		switch (status) {
		case REDIS_RCODE_MOVE:
		{
			fr_value_box_t vb;

			if (fr_redis_reply_to_value_box(NULL, &vb, reply, FR_TYPE_STRING, NULL, false, true) == 0) {
				REDEBUG("Key served by a different node: %pV", &vb);
			}
			goto fail;
		}

		case REDIS_RCODE_SUCCESS:
			goto reply_parse;

		case REDIS_RCODE_RECONNECT:
		close_conn:
			fr_pool_connection_close(pool, request, conn);
			action = XLAT_ACTION_FAIL;
			goto finish;

		default:
		fail:
			fr_pool_connection_release(pool, request, conn);
			action = XLAT_ACTION_FAIL;
			goto finish;
		}
	}

	RDEBUG2("REDIS command arguments");
	RINDENT();
	fr_dlist_foreach(in, fr_value_box_t, vb) {
		if (argc == NUM_ELEMENTS(argv)) {
			REDEBUG("Too many arguments (%i)", argc);
			REXDENT();
			goto finish;
		}

		argv[argc] = vb->vb_strvalue;
		arg_len[argc] = vb->vb_length;
		argc++;
	}
	REXDENT();

	/*
	 *	If we've got multiple arguments, the second one is usually the key.
	 *	The Redis docs say commands should be analysed first to get key
	 *	positions, but this involves sending them to the server, which is
	 *	just as expensive as sending them to the wrong server and receiving
	 *	a redirect.
	 */
	if (argc > 1) {
		key = (uint8_t const *)argv[1];
	 	key_len = arg_len[1];
	}

	for (s_ret = fr_redis_cluster_state_init(&state, &conn, inst->cluster, request, key, key_len, read_only);
	     s_ret == REDIS_RCODE_TRY_AGAIN;	/* Continue */
	     s_ret = fr_redis_cluster_state_next(&state, &conn, inst->cluster, request, status, &reply)) {
		RDEBUG2("Executing command: %pV", fr_dlist_head(in));
		if (argc > 1) {
			RDEBUG2("With arguments");
			RINDENT();
			for (int i = 1; i < argc; i++) RDEBUG2("[%i] %s", i, argv[i]);
			REXDENT();
		}

		if (!read_only) {
			reply = redisCommandArgv(conn->handle, argc, argv, arg_len);
			status = fr_redis_command_status(conn, reply);
		} else if (redis_command_read_only(&status, &reply, request, conn, argc, argv) == -2) {
			state.close_conn = true;
		}
	}
	if (s_ret != REDIS_RCODE_SUCCESS) {
		action = XLAT_ACTION_FAIL;
		goto finish;
	}

	if (!fr_cond_assert(reply)) {
		action = XLAT_ACTION_FAIL;
		goto finish;
	}

reply_parse:
	MEM(vb_out = fr_value_box_alloc_null(ctx));
	if (fr_redis_reply_to_value_box(ctx, vb_out, reply, FR_TYPE_VOID, NULL, false, false) < 0) {
		RPERROR("Failed processing reply");
		return XLAT_ACTION_FAIL;
	}
	fr_dcursor_append(out, vb_out);

finish:
	fr_redis_reply_free(&reply);

	return action;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_redis_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_redis_t);
	char		*name;
	xlat_t		*xlat;

	xlat = xlat_register_module(inst, mctx, mctx->inst->name, redis_xlat, NULL);
	xlat_func_args(xlat, redis_args);

	/*
	 *	%(redis_node:<key>[ idx])
	 */
	name = talloc_asprintf(NULL, "%s_node", mctx->inst->name);
	xlat = xlat_register_module(inst, mctx, name, redis_node_xlat, NULL);
	xlat_func_args(xlat, redis_node_xlat_args);
	talloc_free(name);

	name = talloc_asprintf(NULL, "%s_remap", mctx->inst->name);
	xlat = xlat_register_module(inst, mctx, name, redis_remap_xlat, NULL);
	xlat_func_args(xlat, redis_remap_xlat_args);
	talloc_free(name);

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_redis_t *inst = talloc_get_type_abort(mctx->inst->data, rlm_redis_t);

	inst->cluster = fr_redis_cluster_alloc(inst, mctx->inst->conf, &inst->conf, true, NULL, NULL, NULL);
	if (!inst->cluster) return -1;

	return 0;
}

static int mod_load(void)
{
	fr_redis_version_print();

	return 0;
}

extern module_rlm_t rlm_redis;
module_rlm_t rlm_redis = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "redis",
		.type		= MODULE_TYPE_THREAD_SAFE,
		.inst_size	= sizeof(rlm_redis_t),
		.config		= module_config,
		.onload		= mod_load,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate
	}
};
