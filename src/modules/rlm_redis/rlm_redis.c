/*
 *   This program is free software; you can redistribute it and/or modify
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

#include <assert.h>
#include <stdint.h>

#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/redis/cluster.h>
#include <freeradius-devel/redis/cluster_async.h>

#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/io/coord_pair.h>

#include <freeradius-devel/unlang/xlat_func.h>

#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/types.h>

static fr_dict_t const *dict_redis;

extern fr_dict_autoload_t rlm_redis_dict[];
fr_dict_autoload_t rlm_redis_dict[] = {
	{ .out = &dict_redis, .proto = "redis" },
	DICT_AUTOLOAD_TERMINATOR
};

/** A lua function or stored procedure we make available as an xlat
 *
 */
typedef struct {
	char const		*name;					//!< Friendly name for the function.  Used to register the equivalent xlat.
	char			digest[(SHA1_DIGEST_LENGTH * 2) + 1];	//!< pre-computed hash of lua code.
	char const		*body;					//!< the actual lua code.
	bool			read_only;				//!< Function has no side effects
} redis_lua_func_t;

/** Instance of a redis lua func xlat
 *
 */
typedef struct {
	redis_lua_func_t	*func;					//!< Function configuration.
} redis_lua_func_inst_t;


typedef struct {
	redis_lua_func_t	**funcs;				//!< Array of functions to register.

} rlm_redis_lua_t;

/** rlm_redis module instance
 *
 */
typedef struct {
	fr_redis_conf_t		conf;					//!< Connection parameters for the Redis server.
									//!< Must be first field in this struct.

	rlm_redis_lua_t		lua;					//!< Array of functions to register.

	fr_redis_cluster_t	*cluster;				//!< Redis cluster.

	fr_coord_reg_t		*coord_reg;				//!< Coordinator registration.
	fr_coord_pair_reg_t	*coord_pair_reg;			//!< Coord pair registration.
} rlm_redis_t;

typedef struct {
	rlm_redis_t const		*inst;				//!< Module instance.
	fr_redis_cluster_thread_t	*rtcluster;			//!< Per thread Redis cluster.
	fr_coord_worker_t		*cw;				//!< Coord-worker for fetching cluster map.
} rlm_redis_thread_t;

/** Resume context for redis xlat
 */
typedef struct {
	bool			read_only;				//!< Should the xlat be run read only.
	bool			forced_node;				//!< Was the xlat called with a specific node.
	TALLOC_CTX		*ctx;					//!< Context to allocate boxes.
	fr_value_box_list_t	out;					//!< List to store boxes in callback.
	xlat_action_t		action;					//!< Xlat action set in callback.
	fr_redis_command_set_t	*cmds;					//!< Command set for this xlat.
	fr_redis_async_cmd_t	*cmd;					//!< Async command context.
} rlm_redis_xlat_rctx_t;

typedef enum {
	REDIS_COORD_PAIR_CALLBACK_ID = 0,
} rlm_redis_coord_t;

static int lua_func_body_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule);

static conf_parser_t module_lua_func[] = {
	{ FR_CONF_OFFSET("body", redis_lua_func_t, body), .func = lua_func_body_parse },
	{ FR_CONF_OFFSET("read_only", redis_lua_func_t, read_only) },
	CONF_PARSER_TERMINATOR
};

static conf_parser_t module_lua[] = {
	{ FR_CONF_SUBSECTION_ALLOC("function", 0, CONF_FLAG_SUBSECTION | CONF_FLAG_OK_MISSING | CONF_FLAG_MULTI,
				   rlm_redis_lua_t, funcs, module_lua_func),
				   .subcs_type = "redis_lua_func_t", .name2 = CF_IDENT_ANY },
	CONF_PARSER_TERMINATOR
};

static conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET_SUBSECTION("lua", 0, rlm_redis_t, lua, module_lua) },
	REDIS_COMMON_CONFIG,
	CONF_PARSER_TERMINATOR
};

/** Do basic processing for a lua function body and compute its sha1 hash
 *
 */
static int lua_func_body_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, conf_parser_t const *rule)
{
	int			ret;
	redis_lua_func_t	*func = talloc_get_type_abort(parent, redis_lua_func_t);
	char const		*body;
	fr_sha1_ctx		sha1_ctx;
	uint8_t			digest[SHA1_DIGEST_LENGTH];

	/*
	 *	Get the function name from name2
	 *	of the enclosing function section.
	 */
	func->name = cf_section_name2(cf_item_to_section(cf_parent(ci)));
	if (unlikely(!func->name)) {
		cf_log_err(cf_parent(ci), "functions must be declared as \"function <name> {\"");
		return -1;
	}

	/*
	 *	Perform normal string parsing first
	 */
	if ((ret = cf_pair_parse_value(ctx, out, parent, ci, rule)) < 0) return ret;
	body = *((char **)out);

	fr_sha1_init(&sha1_ctx);
	fr_sha1_update(&sha1_ctx, (uint8_t const *)body, talloc_strlen(body));
	fr_sha1_final(digest, &sha1_ctx);
	fr_base16_encode(&FR_SBUFF_OUT(func->digest, sizeof(func->digest)), &FR_DBUFF_TMP(digest, sizeof(digest)));

	if (DEBUG_ENABLED3) cf_log_debug(ci, "sha1 hash of function is %pV", fr_box_strvalue_len(func->digest, sizeof(func->digest) - 1));

	return 0;
}

/** Callback to check redis replied with "OK" when expected.
 */
static void redis_xlat_status_check(request_t *request, fr_redis_command_t *cmd, redisReply *reply, void *rctx)
{
	rlm_redis_xlat_rctx_t	*xlat_rctx = talloc_get_type_abort(rctx, rlm_redis_xlat_rctx_t);

	if (reply->type  != REDIS_REPLY_STATUS) {
		RWARN("Did not receive expected redis status reply");
		xlat_rctx->action = XLAT_ACTION_FAIL;
		return;
	}

	if (strcmp(reply->str, "OK") != 0) {
		RERROR("Running \"%s\" returned %s", fr_redis_command_get_cmd(cmd), reply->str);
		xlat_rctx->action = XLAT_ACTION_FAIL;
	}
}

/** Issue a command against redis and get a response
 *
 * This is a convenience function for dealing with commands which made need to execute against an
 * ldap replica.  It temporarily places the connection in readonly mode to allow commands to be
 * run against ldap replicas, then reverts back to readwrite mode.
 *
 * @param[out] status_out	Where to write the status from the command.
 * @param[out] reply_out	Where to write the reply associated with the highest priority status.
 * @param[in] request		The current request.
 * @param[in] conn		to issue commands with.
 * @param[in] read_only		wrap command in READONLY/READWRITE.
 * @param[in] argc		Redis command argument count.
 * @param[in] argv		Redis command arguments.
 * @param[in] arg_len		Optional array of redis command argument length.
 * @return
 *	- 0 success.
 *	- -1 normal failure.
 *	- -2 failure that may leave the connection in a READONLY state.
 */
static int redis_command(fr_redis_rcode_t *status_out, redisReply **reply_out,
			 request_t *request, fr_redis_conn_t *conn,
			 bool read_only,
			 int argc, char const **argv, size_t arg_len[])
{
	bool			maybe_more = false;
	redisReply		*reply;
	fr_redis_rcode_t	status;

	*reply_out = NULL;

	if (read_only) redisAppendCommand(conn->handle, "READONLY");
	redisAppendCommandArgv(conn->handle, argc, argv, arg_len);
	if (read_only) {
		redisAppendCommand(conn->handle, "READWRITE");
	} else goto parse_reply;


	/*
	 *	Process the response for READONLY
	 */
	reply = NULL;	/* Doesn't set reply to NULL on error *sigh* */
	if (redisGetReply(conn->handle, (void **)&reply) == REDIS_OK) maybe_more = true;
	status = fr_redis_command_status(conn, reply);
	if (status != REDIS_RCODE_SUCCESS) {
		ROPTIONAL(REDEBUG, ERROR, "Setting READONLY failed");

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

parse_reply:
	/*
	 *	Process the response for the command
	 */
	reply = NULL;	/* Doesn't set reply to NULL on error *sigh* */
	if ((redisGetReply(conn->handle, (void **)&reply) == REDIS_OK) && read_only) maybe_more = true;
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

	if (!read_only) return 0;	/* No more responses to deal with */

	/*
	 *	Process the response for READWRITE
	 */
	reply = NULL;	/* Doesn't set reply to NULL on error *sigh* */
	if ((redisGetReply(conn->handle, (void **)&reply) != REDIS_OK) ||
	    (fr_redis_command_status(conn, reply) != REDIS_RCODE_SUCCESS)) {
		ROPTIONAL(REDEBUG, ERROR, "Setting READWRITE failed");

		fr_redis_reply_free(&reply);	/* There could be a response we need to free */
		fr_redis_reply_free(reply_out);
		*reply_out = reply;
		*status_out = REDIS_RCODE_ERROR;

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
%redis.remap(<redis server ip>:<redis server port>)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t redis_remap_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				      xlat_ctx_t const *xctx,
				      request_t *request, fr_value_box_list_t *in)
{
	rlm_redis_t const		*inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_redis_t);

	fr_socket_t			node_addr;
	fr_pool_t			*pool;
	fr_redis_conn_t			*conn;
	fr_redis_cluster_rcode_t	rcode;
	fr_value_box_t			*vb;
	fr_value_box_t			*in_head = fr_value_box_list_head(in);

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
	switch (rcode) {
	case FR_REDIS_CLUSTER_RCODE_NO_CONNECTION:
		fr_pool_connection_close(pool, request, conn);
		break;

	default:
		fr_pool_connection_release(pool, request, conn);
		break;
	}

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
%redis.node(<key>[, <index>])
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t redis_node_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				     xlat_ctx_t const *xctx,
				     request_t *request, fr_value_box_list_t *in)
{
	rlm_redis_t const			*inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_redis_t);

	fr_redis_cluster_key_slot_t const	*key_slot;
	fr_redis_cluster_node_t const		*node;
	fr_ipaddr_t				ipaddr;
	uint16_t				port;

	unsigned long				idx = 0;
	fr_value_box_t				*vb;
	fr_value_box_t				*key = fr_value_box_list_head(in);
	fr_value_box_t				*idx_vb = fr_value_box_list_next(in, key);

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

static xlat_arg_parser_t const redis_lua_func_args[] = {
	{ .required = true, .single = true, .type = FR_TYPE_UINT64 }, /* key count */
	{ .variadic = XLAT_ARG_VARIADIC_EMPTY_KEEP, .concat = true, .type = FR_TYPE_STRING }, /* keys and args */
	XLAT_ARG_PARSER_TERMINATOR
};

/** Call a lua function on the redis server
 *
 * Lua functions either get uploaded when the module is instantiated or the first
 * time they get executed.
 */
static xlat_action_t redis_lua_func_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
					 xlat_ctx_t const *xctx,
					 request_t *request, fr_value_box_list_t *in)
{
	rlm_redis_t			*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_redis_t);
	redis_lua_func_inst_t const	*xlat_inst = talloc_get_type_abort_const(xctx->inst, redis_lua_func_inst_t);
	redis_lua_func_t		*func = xlat_inst->func;

	fr_redis_conn_t			*conn;
	fr_redis_cluster_state_t	state;
	fr_redis_rcode_t		status;

	redisReply			*reply = NULL;
	int				s_ret;

	char const			*argv[MAX_REDIS_ARGS];
	size_t				arg_len[MAX_REDIS_ARGS];
	int				argc;
	char				key_count[sizeof("184467440737095551615")];
	uint8_t	const			*key = NULL;
	size_t				key_len = 0;

	xlat_action_t			action = XLAT_ACTION_DONE;
	fr_value_box_t			*vb_out;

	/*
	 *	First argument is always the key count
	 */
	if (unlikely(fr_value_box_print(&FR_SBUFF_OUT(key_count, sizeof(key_count)), fr_value_box_list_head(in), NULL) < 0)) {
		RPERROR("Failed converting key count to string");
		return XLAT_ACTION_FAIL;
	}
	fr_value_box_list_talloc_free_head(in);

	/*
	 *	Try EVALSHA first, and if that fails fall back to SCRIPT LOAD
	 */
	argv[0] = "EVALSHA";
	arg_len[0] = sizeof("EVALSHA") - 1;
	argv[1] = func->digest;
	arg_len[1] = sizeof(func->digest) - 1;
	argv[2] = key_count;
	arg_len[2] = strlen(key_count);
	argc = 3;

	fr_value_box_list_foreach(in, vb) {
		if (argc == NUM_ELEMENTS(argv)) {
			REDEBUG("Too many arguments (%i)", argc);
			REXDENT();
			return XLAT_ACTION_FAIL;
		}

		/*
		 *	Fixup null or empty arguments to be
		 *	zero length strings so that the position
		 *	of subsequent arguments are maintained.
		 */
		if (!fr_type_is_string(vb->type)) {
			argv[argc] = "";
			arg_len[argc++] = 0;
			continue;
		}

		argv[argc] = vb->vb_strvalue;
		arg_len[argc++] = vb->vb_length;
	}

	/*
	 *	For eval commands all keys should hash to the same redis instance
	 *	so we just use the first key (the arg after the key count).
	 */
	if (argc > 3) {
		key = (uint8_t const *)argv[3];
	 	key_len = arg_len[3];
	}

	for (s_ret = fr_redis_cluster_state_init(&state, &conn, inst->cluster, request, key, key_len, func->read_only);
	     s_ret == REDIS_RCODE_TRY_AGAIN;	/* Continue */
	     s_ret = fr_redis_cluster_state_next(&state, &conn, inst->cluster, request, status, &reply)) {
		bool script_load_done = false;

	again:
	     	RDEBUG3("Calling script 0x%s", func->digest);
		if (argc > 2) {
			RDEBUG3("With arguments");
			RINDENT();
			for (int i = 2; i < argc; i++) RDEBUG3("[%i] %s", i, argv[i]);
			REXDENT();
		}
		if (redis_command(&status, &reply, request, conn,
				  func->read_only, argc, argv, arg_len) == -2) {
			state.close_conn = true;
		}

		if (status != REDIS_RCODE_NO_SCRIPT) continue;

		/*
		 *	Discard the error we received, and attempt load the function.
		 */
		fr_redis_reply_free(&reply);

		RDEBUG3("Loading lua function \"%s\" (0x%s)", func->name, func->digest);
		{
			char const	*script_load_argv[] = {
						"SCRIPT",
						"LOAD",
						func->body
					};

			size_t		script_load_arg_len[] = {
						(sizeof("SCRIPT") - 1),
						(sizeof("LOAD") - 1),
						(talloc_strlen(func->body))
					};

			/*
			 *	Loading the script failed... fail the call.
			 */
			if (script_load_done) {
			script_load_failed:
				status = REDIS_RCODE_ERROR;
				fr_redis_reply_free(&reply);
				continue;
			}

			/*
			 *	Fixme: Really the script load and the eval call should be
			 *	handled in a single MULTI/EXEC block, but the complexity
			 *	in handling this properly is great, and most of this
			 *	synchronous code will need to be rewritten, so for now
			 *	we just load the script and try again.
			 */
			if (redis_command(&status, &reply, request, conn, func->read_only,
					  NUM_ELEMENTS(script_load_argv),
					  script_load_argv, script_load_arg_len) == -2) {
				state.close_conn = true;
			}

			if (status == REDIS_RCODE_SUCCESS) {
				script_load_done = true;

				/*
				 *	Verify we got a sane response
				 */
				if (reply->type != REDIS_REPLY_STRING) {
					REDEBUG("Unexpected reply type after loading function");
					fr_redis_reply_print(L_DBG_LVL_OFF, reply, request, 0, status);
					goto script_load_failed;
				}

				if (strcmp(reply->str, func->digest) != 0) {
					REDEBUG("Function digest %s, does not match calculated digest %s", reply->str, func->digest);
					goto script_load_failed;
				}
				fr_redis_reply_free(&reply);
				goto again;
			}
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

	MEM(vb_out = fr_value_box_alloc_null(ctx));
	if (fr_redis_reply_to_value_box(ctx, vb_out, reply, FR_TYPE_VOID, NULL, false, false) < 0) {
		RPERROR("Failed processing reply");
		action = XLAT_ACTION_FAIL;
		goto finish;
	}

	if (vb_out->type == FR_TYPE_GROUP) {
		fr_value_box_t	*child_vb = NULL;
		while ((child_vb = fr_value_box_list_pop_head(&vb_out->vb_group))) fr_dcursor_append(out, child_vb);
		talloc_free(vb_out);
	} else {
		fr_dcursor_append(out, vb_out);
	}

finish:
	fr_redis_reply_free(&reply);

	return action;
}

/** Copies the function configuration into xlat function instance data
 *
 */
static int redis_lua_func_instantiate(xlat_inst_ctx_t const *xctx)
{
	redis_lua_func_inst_t *inst = talloc_get_type_abort(xctx->inst, redis_lua_func_inst_t);

	inst->func = talloc_get_type_abort(xctx->uctx, redis_lua_func_t);

	return 0;
}

static xlat_arg_parser_t const redis_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },
	{ .variadic = XLAT_ARG_VARIADIC_EMPTY_KEEP, .concat = true, .type = FR_TYPE_STRING },
	XLAT_ARG_PARSER_TERMINATOR
};

/** Callback to convert redis reply to value boxes
 */
static void redis_xlat_results(request_t *request, fr_redis_command_t *cmd, redisReply *reply, void *rctx)
{
	rlm_redis_xlat_rctx_t	*xlat_rctx = talloc_get_type_abort(rctx, rlm_redis_xlat_rctx_t);
	fr_value_box_t		*vb;

	MEM(vb = fr_value_box_alloc_null(xlat_rctx->ctx));
	if (fr_redis_reply_to_value_box(xlat_rctx->ctx, vb, reply, FR_TYPE_VOID, NULL, false, false) < 0) {
		RPERROR("Failed processing reply to %s", fr_redis_command_get_cmd(cmd));
		return;
	}

	if (vb->type == FR_TYPE_GROUP) {
		fr_value_box_t	*child_vb = NULL;
		while ((child_vb = fr_value_box_list_pop_head(&vb->vb_group))) fr_value_box_list_insert_tail(&xlat_rctx->out, child_vb);
		talloc_free(vb);
	} else {
		fr_value_box_list_insert_tail(&xlat_rctx->out, vb);
	}
	xlat_rctx->action = XLAT_ACTION_DONE;
}

static xlat_action_t redis_xlat_resume(UNUSED TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
				       request_t *request, UNUSED fr_value_box_list_t *in)
{
	rlm_redis_xlat_rctx_t	*rctx = talloc_get_type_abort(xctx->rctx, rlm_redis_xlat_rctx_t);
	fr_value_box_t		*vb = NULL;

	switch (fr_redis_command_set_rcode(rctx->cmds)) {
	case REDIS_ASYNC_RCODE_MOVE:
	{
		rlm_redis_t const	*inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_redis_t);
		rlm_redis_thread_t	*thread = talloc_get_type_abort(xctx->mctx->thread, rlm_redis_thread_t);

		fr_redis_cluster_thread_map_get(thread->rtcluster, thread->cw, inst->coord_pair_reg);
	}
		FALL_THROUGH;

	case REDIS_ASYNC_RCODE_ASK:
		if (rctx->forced_node) goto error;
		if (fr_redis_async_cmd_redirect(rctx->cmd) != REDIS_ASYNC_RCODE_SUCCESS) return XLAT_ACTION_FAIL;
		return unlang_xlat_yield(request, redis_xlat_resume, NULL, 0, rctx);

	case REDIS_ASYNC_RCODE_ERROR:
	error:
		RPERROR("Server returned error");
		return XLAT_ACTION_FAIL;

	default:
		break;
	}

	if (rctx->action != XLAT_ACTION_DONE) {
		RPERROR("Failed executing Redis command");
		return rctx->action;
	}

	while ((vb = fr_value_box_list_pop_head(&rctx->out))) fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Xlat to make calls to redis
 *
@verbatim
%redis(<redis command>)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t redis_xlat(TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
				xlat_ctx_t const *xctx,
				request_t *request, fr_value_box_list_t *in)
{
	rlm_redis_t const	*inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_redis_t);
	rlm_redis_thread_t	*thread = talloc_get_type_abort(xctx->mctx->thread, rlm_redis_thread_t);
	uint8_t	const		*key = NULL;
	size_t			key_len = 0;

	fr_value_box_t		*first = fr_value_box_list_head(in);
	fr_sbuff_t		sbuff = FR_SBUFF_IN(first->vb_strvalue, first->vb_length);

	int			argc = 0;
	char const		**argv;
	size_t			*arg_len;
	fr_redis_command_set_t	*cmds;
	rlm_redis_xlat_rctx_t	*rctx;
	fr_redis_async_rcode_t	ret;
	fr_redis_ct_node_t	*node = NULL;

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), rlm_redis_xlat_rctx_t));
	rctx->ctx = ctx;
	rctx->action = XLAT_ACTION_FAIL;
	fr_value_box_list_init(&rctx->out);

	if (fr_sbuff_next_if_char(&sbuff, '-')) rctx->read_only = true;

	/*
	 *	Hack to allow querying against a specific node for testing
	 */
	if (fr_sbuff_next_if_char(&sbuff, '@')) {
		fr_socket_t	node_addr;

		RDEBUG3("Overriding node selection");

		if (fr_inet_pton_port(&node_addr.inet.dst_ipaddr, &node_addr.inet.dst_port,
				      fr_sbuff_current(&sbuff), fr_sbuff_remaining(&sbuff),
				      AF_UNSPEC, true, true) < 0) {
			RPEDEBUG("Failed parsing node address");
			return XLAT_ACTION_FAIL;
		}

		node = fr_redis_cluster_thread_node_by_addr(thread->rtcluster, &node_addr);
		if (!node) {
			RPEDEBUG("Failed locating cluster node");
			return XLAT_ACTION_FAIL;
		}

		fr_value_box_list_talloc_free_head(in);	/* Remove and free server arg */
		rctx->forced_node = true;
	}

	MEM(cmds = fr_redis_command_set_alloc(rctx, request, NULL, NULL, NULL, false));
	rctx->cmds = cmds;

	argc = fr_value_box_list_num_elements(in);
	MEM(argv = talloc_array(cmds, char const *, argc));
	MEM(arg_len = talloc_array(cmds, size_t, argc));

	argc = 0;
	fr_value_box_list_foreach(in, vb) {
		if (!fr_type_is_string(vb->type)) {
			argv[argc] = talloc_strdup(argv, "");
			arg_len[argc++] = 0;
			continue;
		}

		if ((argc == 0) && rctx->read_only && !rctx->forced_node) {
			argv[argc] = talloc_strndup(argv, vb->vb_strvalue + 1, vb->vb_length - 1);
			arg_len[argc] = vb->vb_length - 1;
		} else {
			argv[argc] = talloc_strndup(argv, vb->vb_strvalue, vb->vb_length);
			arg_len[argc] = vb->vb_length;
		}
		argc++;
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
	 	key_len = arg_len[1];
	}

	if (rctx->read_only) fr_redis_command_preformatted_add(cmds, "READONLY", redis_xlat_status_check, rctx);
	fr_redis_command_argv_add(cmds, argc, argv, arg_len, redis_xlat_results, rctx);
	if (rctx->read_only) fr_redis_command_preformatted_add(cmds, "READWRITE", redis_xlat_status_check, rctx);

	rctx->cmd = fr_redis_async_cmd_start(unlang_interpret_frame_talloc_ctx(request), request, &ret,
					     thread->rtcluster, key, key_len, cmds, rctx->read_only, node);

	REDIS_ASYNC_START_RCODE_PROCESS(ret, thread->rtcluster, thread->cw, inst->coord_pair_reg,
					"Failed enqueueing Redis command", XLAT_ACTION_FAIL)

	return unlang_xlat_yield(request, redis_xlat_resume, NULL, 0, rctx);
}

static void lua_script_load_results(UNUSED request_t *request, UNUSED fr_redis_command_t *cmd,
				    UNUSED redisReply *reply, void *rctx)
{
	redis_lua_func_t	*func = talloc_get_type_abort(rctx, redis_lua_func_t);
	DEBUG2("Loaded lua function \"%s\" onto node", func->name);
}

static void lua_script_load(fr_redis_trunk_t *rtrunk, void *uctx)
{
	rlm_redis_thread_t	*thread = talloc_get_type_abort(uctx, rlm_redis_thread_t);
	fr_redis_command_set_t	*cmds;

	MEM(cmds = fr_redis_command_set_alloc(rtrunk, NULL, NULL, NULL, NULL, true));

	talloc_foreach(thread->inst->lua.funcs, func) {
		char const	**argv;
		size_t		*argv_len;

		MEM(argv = talloc_array(cmds, char const *, 3));
		MEM(argv_len = talloc_array(cmds, size_t, 3));

		argv[0] = "SCRIPT";
		argv_len[0] = sizeof("SCRIPT") - 1;
		argv[1] = "LOAD";
		argv_len[1] = sizeof("LOAD") - 1;
		argv[2] = func->body;
		argv_len[2] = talloc_strlen(func->body);

		fr_redis_command_argv_add(cmds, 3, argv, argv_len, lua_script_load_results, func);
	}

	if (redis_command_set_enqueue(rtrunk, cmds) != FR_REDIS_PIPELINE_OK) {
		ERROR("Failed to enqueue lua function loading");
		talloc_free(cmds);
	}
}


static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_redis_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_redis_thread_t);
	rlm_redis_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_redis_t);

	if (talloc_array_length(inst->lua.funcs) == 0) {
		t->rtcluster = fr_redis_cluster_thread_alloc(t, mctx->el, &inst->conf, NULL, NULL, false);
	} else {
		t->rtcluster = fr_redis_cluster_thread_alloc(t, mctx->el, &inst->conf, lua_script_load, t, true);
	}
	if (!t->rtcluster) return -1;
	t->inst = inst;

	return 0;
}

static int mod_coord_attach(module_thread_inst_ctx_t const *mctx)
{
	rlm_redis_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_redis_thread_t);
	rlm_redis_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_redis_t);

	t->cw = fr_coord_attach(t, mctx->el, inst->coord_reg);

	if (!t->cw) {
		ERROR("Failed to attach to coordinator");
		return -1;
	}

	if ((inst->conf.trunk_conf.start == 0) || (fr_schedule_worker_id() != 0)) return 0;

	return fr_redis_cluster_thread_map_bootstrap(t->rtcluster, t->cw, inst->coord_pair_reg);
}

/** Callback for worker receiving Fetch-OK packet from coordinator
 */
static void cluster_map_update(UNUSED fr_coord_worker_t *cw, UNUSED fr_coord_pair_reg_t *coord_pair_reg,
			       fr_pair_list_t const *list, UNUSED fr_time_t now,
			       module_ctx_t *mctx, UNUSED void *uctx)
{
	rlm_redis_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_redis_thread_t);
	fr_redis_cluster_thread_map_update(t->rtcluster, list);
	return;
}

static fr_coord_cb_reg_t coord_callbacks[] = {
	FR_COORD_PAIR_CALLBACK(REDIS_COORD_PAIR_CALLBACK_ID),
	FR_COORD_CALLBACK_TERMINATOR
};

static fr_coord_worker_cb_reg_t worker_callbacks[] = {
	FR_COORD_WORKER_PAIR_CALLBACK(REDIS_COORD_PAIR_CALLBACK_ID),
	FR_COORD_CALLBACK_TERMINATOR
};

static fr_coord_worker_pair_cb_reg_t worker_pair_callbacks[] = {
	{ .packet_type = FR_REDIS_CLUSTER_MAP_UPDATE, .callback = cluster_map_update },
	FR_COORD_CALLBACK_TERMINATOR
};

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_redis_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_redis_t);

	inst->conf.log_prefix = mctx->mi->name;

	inst->coord_pair_reg = fr_coord_pair_register(&(fr_coord_pair_reg_ctx_t) {
			.name = mctx->mi->name,
			.worker_cb = worker_pair_callbacks,
			.cb_id = REDIS_COORD_PAIR_CALLBACK_ID,
			.root = fr_dict_root(dict_redis),
			.cs = mctx->mi->conf,
		}
	);
	if (!inst->coord_pair_reg) return -1;

	FR_COORD_PAIR_CB_CTX_SET(coord_callbacks, worker_callbacks, inst->coord_pair_reg);

	inst->coord_reg = fr_coord_register(&(fr_coord_reg_ctx_t) {
			.name = mctx->mi->name,
			.coord_cb = coord_callbacks,
			.worker_cb = worker_callbacks,
			.mi = mctx->mi
		});

	if (!inst->coord_reg) return -1;

	inst->cluster = fr_redis_cluster_alloc(inst, mctx->mi->conf, &inst->conf, NULL, NULL, NULL);
	if (!inst->cluster) return -1;

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_redis_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_redis_thread_t);

	if (!t->cw) return 0;

	fr_coord_detach(t->cw, true);
	t->cw = NULL;
	return 0;
}

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_redis_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_redis_t);

	fr_coord_deregister(inst->coord_reg);
	talloc_free(inst->coord_pair_reg);
	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	rlm_redis_t const	*inst = talloc_get_type_abort(mctx->mi->data, rlm_redis_t);
	xlat_t			*xlat;

	xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, NULL, redis_xlat, FR_TYPE_VOID);
	xlat_func_args_set(xlat, redis_args);

	/*
	 *	%redis.node(<key>[, idx])
	 */
	if (unlikely((xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "node", redis_node_xlat, FR_TYPE_STRING)) == NULL)) return -1;
	xlat_func_args_set(xlat, redis_node_xlat_args);

	if (unlikely((xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "remap", redis_remap_xlat, FR_TYPE_STRING)) == NULL)) return -1;
	xlat_func_args_set(xlat, redis_remap_xlat_args);

	/*
	 *	Loop over the lua functions, registering an xlat
	 *	that'll call that function specifically.
	 */
	talloc_foreach(inst->lua.funcs, func) {
		if (unlikely((xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, func->name, redis_lua_func_xlat, FR_TYPE_VOID)) == NULL)) return -1;
		xlat_func_args_set(xlat, redis_lua_func_args);
		xlat_func_instantiate_set(xlat, redis_lua_func_instantiate, redis_lua_func_inst_t, NULL, func);
	}

	return 0;
}

static int mod_load(void)
{
	fr_redis_version_print();

	return redis_dict_init();
}

extern module_rlm_t rlm_redis;
module_rlm_t rlm_redis = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "redis",
		.inst_size	= sizeof(rlm_redis_t),
		.config		= module_config,
		.onload		= mod_load,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate,
		.coord_attach	= mod_coord_attach,
		.detach		= mod_detach,
		MODULE_THREAD_INST(rlm_redis_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
	}
};
