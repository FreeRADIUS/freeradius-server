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

#include <assert.h>
#include <stdint.h>

#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/redis/cluster.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/pool.h>

#include <freeradius-devel/unlang/xlat.h>
#include <freeradius-devel/unlang/xlat_func.h>

#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/value.h>

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
} rlm_redis_t;

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
	fr_sha1_update(&sha1_ctx, (uint8_t const *)body, talloc_array_length(body) - 1);
	fr_sha1_final(digest, &sha1_ctx);
	fr_base16_encode(&FR_SBUFF_OUT(func->digest, sizeof(func->digest)), &FR_DBUFF_TMP(digest, sizeof(digest)));

	if (DEBUG_ENABLED3) cf_log_debug(ci, "sha1 hash of function is %pV", fr_box_strvalue_len(func->digest, sizeof(func->digest) - 1));

	return 0;
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
						(talloc_array_length(func->body) - 1)
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
					fr_redis_reply_print(L_DBG_LVL_OFF, reply, request, 0);
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
	fr_dcursor_append(out, vb_out);

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

/** Xlat to make calls to redis
 *
@verbatim
%redis(<redis command>)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t redis_xlat(TALLOC_CTX *ctx, fr_dcursor_t *out,
				xlat_ctx_t const *xctx,
				request_t *request, fr_value_box_list_t *in)
{
	rlm_redis_t const	*inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_redis_t);
	xlat_action_t		action = XLAT_ACTION_DONE;
	fr_redis_conn_t		*conn;

	bool			read_only = false;
	uint8_t	const		*key = NULL;
	size_t			key_len = 0;

	fr_redis_cluster_state_t	state;
	fr_redis_rcode_t		status;

	redisReply		*reply = NULL;
	int			s_ret;

	fr_value_box_t		*first = fr_value_box_list_head(in);
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

		fr_value_box_list_talloc_free_head(in);	/* Remove and free server arg */

		fr_value_box_list_foreach(in, vb) {
			if (argc == NUM_ELEMENTS(argv)) {
				REDEBUG("Too many arguments (%i)", argc);
				REXDENT();
				goto fail;
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

		RDEBUG2("Executing command: %pV", fr_value_box_list_head(in));
		if (argc > 1) {
			RDEBUG2("With arguments");
			RINDENT();
			for (int i = 1; i < argc; i++) RDEBUG2("[%i] %s", i, argv[i]);
			REXDENT();
		}

		if (redis_command(&status, &reply, request, conn, read_only, argc, argv, arg_len) == -2) {
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
	fr_value_box_list_foreach(in, vb) {
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
		RDEBUG2("Executing command: %pV", fr_value_box_list_head(in));
		if (argc > 1) {
			RDEBUG2("With arguments");
			RINDENT();
			for (int i = 1; i < argc; i++) RDEBUG2("[%i] %s", i, argv[i]);
			REXDENT();
		}

		if (redis_command(&status, &reply, request, conn, read_only, argc, argv, arg_len) == -2) {
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
		action = XLAT_ACTION_FAIL;
		goto finish;
	}
	fr_dcursor_append(out, vb_out);

finish:
	fr_redis_reply_free(&reply);

	return action;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_redis_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_redis_t);
	fr_socket_t *nodes;
	int ret, i;

	inst->cluster = fr_redis_cluster_alloc(inst, mctx->mi->conf, &inst->conf, true, NULL, NULL, NULL);
	if (!inst->cluster) return -1;

	/*
	 *	Best effort - Try and load in scripts on startup
	 */
	if (talloc_array_length(inst->lua.funcs) == 0) return 0;

	ret = fr_redis_cluster_node_addr_by_role(NULL, &nodes, inst->cluster, true, true);
	if (ret <= 0) return 0;

	for (i = 0; i < ret; i++) {
		fr_pool_t 		*pool;
		fr_redis_conn_t		*conn;

		if (fr_redis_cluster_pool_by_node_addr(&pool, inst->cluster, &nodes[i], true) < 0) {
			talloc_free(nodes);
			return 0;
		}

		conn = fr_pool_connection_get(pool, 0);
		if (!conn) continue;

		talloc_foreach(inst->lua.funcs, func) {
			char const	*script_load_argv[] = {
						"SCRIPT",
						"LOAD",
						func->body
					};

			size_t		script_load_arg_len[] = {
						(sizeof("SCRIPT") - 1),
						(sizeof("LOAD") - 1),
						(talloc_array_length(func->body) - 1)
					};

			fr_redis_rcode_t status;
			redisReply *reply;

			/*
			 *	preload onto every node, even replicas.
			 */
			if (redis_command(&status, &reply, NULL, conn, false,
					  NUM_ELEMENTS(script_load_argv), script_load_argv, script_load_arg_len) == -2) {
			error:
				fr_pool_connection_release(pool, NULL, conn);
				talloc_free(nodes);
				return -1;
			}

			fr_redis_reply_free(&reply);

			/*
			 *	Only error on explicit errors, not on connectivity issues
			 */
			switch (status) {
			case REDIS_RCODE_ERROR:
				PERROR("Loading lua function \"%s\" onto node failed", func->name);
				goto error;

			case REDIS_RCODE_SUCCESS:
				DEBUG2("Loaded lua function \"%s\" onto node", func->name);
				break;

			default:
				PWARN("Loading lua function \"%s\" onto node failed", func->name);
				continue;
			}
		}

		fr_pool_connection_release(pool, NULL, conn);
	}
	talloc_free(nodes);

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

	return 0;
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
		.instantiate	= mod_instantiate
	}
};
