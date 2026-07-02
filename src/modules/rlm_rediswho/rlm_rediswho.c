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
 * @file rlm_rediswho.c
 * @brief Session tracking using redis.
 *
 * @author Gabriel Blanchard
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2011 TekSavvy Solutions (gabe@teksavvy.com)
 * @copyright 2000,2006 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/redis/cluster_async.h>

typedef struct {
	fr_redis_conf_t		conf;		//!< Connection parameters for the Redis server.
						//!< Must be first field in this struct.

	CONF_SECTION 		*tls_conf;	//!< TLS CONF_SECTION

	fr_coord_reg_t		*coord_reg;		//!< Coordinator registration.
	fr_coord_pair_reg_t	*coord_pair_reg;	//!< Coord pair registration.

	int			expiry_time;	//!< Expiry time in seconds if no updates are received for a user

	int			trim_count;	//!< How many session updates to keep track of per user.

	char const		*insert;	//!< Command for inserting session data
	char const		*trim;		//!< Command for trimming the session list.
	char const		*expire;	//!< Command for expiring entries.
} rlm_rediswho_t;

typedef enum {
	REDIS_COORD_PAIR_CALLBACK_ID = 0
} rlm_redis_coord_t;

typedef struct {
	rlm_rediswho_t			*inst;		//!< Module instance.
	fr_redis_cluster_thread_t	*rtcluster;	//!< Per thread Redis cluster.
	fr_coord_worker_t		*cw;		//!< Coord-worker for fetching cluster map.
} rlm_rediswho_thread_t;

/** Resume context for rediswho module calls.
 */
typedef struct {
	char const		*trim;			//!< Format string for trim command.
	char const		*expire;		//!< Format string for expire command.
	fr_redis_command_set_t	*cmds;			//!< Command set for module call.
	fr_redis_async_cmd_t	*cmd;			//!< Async command context.
	char			*cmd_str;		//!< Formatted command currently being run.
	uint8_t const		*key;			//!< Key value to identify cluster slot.
	int			ret;			//!< Value returned in Redis reply.
} rediswho_rctx_t;

static conf_parser_t section_config[] = {
	{ FR_CONF_OFFSET_FLAGS("insert", CONF_FLAG_REQUIRED | CONF_FLAG_XLAT, rlm_rediswho_t, insert) },
	{ FR_CONF_OFFSET_FLAGS("trim", CONF_FLAG_XLAT, rlm_rediswho_t, trim) }, /* required only if trim_count > 0 */
	{ FR_CONF_OFFSET_FLAGS("expire", CONF_FLAG_REQUIRED | CONF_FLAG_XLAT, rlm_rediswho_t, expire) },
	CONF_PARSER_TERMINATOR
};

static conf_parser_t redis_config[] = {
	REDIS_COMMON_CONFIG,
	CONF_PARSER_TERMINATOR
};

static conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("trim_count", rlm_rediswho_t, trim_count), .dflt = "-1" },

	/*
	 *	These all smash the same variables, because we don't care about them right now.
	 *	In 3.1, we should have a way of saying "parse a set of sub-sections according to a template"
	 */
	{ FR_CONF_POINTER("Start", 0, CONF_FLAG_SUBSECTION | CONF_FLAG_OK_MISSING, NULL), .subcs = section_config },
	{ FR_CONF_POINTER("Interim-Update", 0, CONF_FLAG_SUBSECTION | CONF_FLAG_OK_MISSING, NULL), .subcs = section_config },
	{ FR_CONF_POINTER("Stop", 0, CONF_FLAG_SUBSECTION | CONF_FLAG_OK_MISSING, NULL), .subcs = section_config },
	{ FR_CONF_POINTER("Accounting-On", 0, CONF_FLAG_SUBSECTION | CONF_FLAG_OK_MISSING, NULL), .subcs = section_config },
	{ FR_CONF_POINTER("Accounting-Off", 0, CONF_FLAG_SUBSECTION | CONF_FLAG_OK_MISSING, NULL), .subcs = section_config },
	{ FR_CONF_POINTER("Failed", 0, CONF_FLAG_SUBSECTION | CONF_FLAG_OK_MISSING, NULL), .subcs = section_config },

	{ FR_CONF_POINTER("redis", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = redis_config },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_radius;
static fr_dict_t const *dict_redis;

extern fr_dict_autoload_t rlm_rediswho_dict[];
fr_dict_autoload_t rlm_rediswho_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_redis, .proto = "redis" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_acct_status_type;

extern fr_dict_attr_autoload_t rlm_rediswho_dict_attr[];
fr_dict_attr_autoload_t rlm_rediswho_dict_attr[] = {
	{ .out = &attr_acct_status_type, .name = "Acct-Status-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	DICT_AUTOLOAD_TERMINATOR
};

/** Process redisReply from  rediswho command
 *
 * The reply is expected to either be an integer or status.
 */
static void rediswho_results(request_t *request, UNUSED fr_redis_command_t *cmd, redisReply *reply, void *rctx)
{
	rediswho_rctx_t	*rediswho_rctx = talloc_get_type_abort(rctx, rediswho_rctx_t);

	switch (reply->type) {
	case REDIS_REPLY_INTEGER:
		rediswho_rctx->ret = reply->integer;
		return;

	case REDIS_REPLY_STATUS:
		if (strcmp(reply->str, "OK") != 0) {
			REDEBUG("Redis returned %s", reply->str);
			rediswho_rctx->ret = -1;
			return;
		}

		rediswho_rctx = 0;
		return;

	default:
		REDEBUG("Bad result type, expected integer, got %s",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		rediswho_rctx->ret = -1;
		return;
	}

}

/*
 *	Enqueue a Redis command which will return a single integer or status result.
 */
static fr_redis_async_rcode_t rediswho_command(rlm_rediswho_thread_t *thread, request_t *request,
					       char const *fmt, rediswho_rctx_t *rctx)
{
	fr_redis_async_rcode_t	ret;
	int			cmd_len;
	size_t			key_len;

	int			argc;
	char const		*argv[MAX_REDIS_ARGS];
	char			argv_buf[MAX_REDIS_COMMAND_LEN];

	if (!fmt || !*fmt) return REDIS_ASYNC_RCODE_ERROR;

	argc = rad_expand_xlat(request, fmt, MAX_REDIS_ARGS, argv, false, sizeof(argv_buf), argv_buf);
	if (argc < 0) {
		RPEDEBUG("Invalid command: %s", fmt);
		return REDIS_ASYNC_RCODE_ERROR;
	}

	/*
	 *	If we've got multiple arguments, the second one is usually the key.
	 *	The Redis docs say commands should be analysed first to get key
	 *	positions, but this involves sending them to the server, which is
	 *	just as expensive as sending them to the wrong server and receiving
	 *	a redirect.
	 */
	if (argc > 1) {
		key_len = strlen(argv[1]);
		rctx->key = talloc_memdup(rctx, argv[1], key_len);
	}

	/*
	 *	If there's a previous formatted command, clean up
	 */
	if (rctx->cmd_str) {
		redisFreeCommand(rctx->cmd_str);
		rctx->cmd_str = NULL;
		fr_redis_command_set_clear(rctx->cmds);
	}

	cmd_len = redisFormatCommandArgv(&rctx->cmd_str, argc, argv, NULL);
	if (cmd_len < 0) {
		RERROR("Failed formatting redis commmand");
		return REDIS_ASYNC_RCODE_ERROR;
	}
	fr_redis_command_preformatted_add(rctx->cmds, rctx->cmd_str, cmd_len, rediswho_results, rctx);

	rctx->cmd = fr_redis_async_cmd_start(rctx, request, &ret, thread->rtcluster, rctx->key, key_len,
					     rctx->cmds, false, NULL);

	return ret;
}

static void mod_accounting_cancel(module_ctx_t const *mctx, request_t *request, UNUSED fr_signal_t action)
{
	rediswho_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, rediswho_rctx_t);

	RDEBUG2("Forcibly cancelling Redis command");

	fr_redis_async_cmd_cancel(rctx->cmd);
}

static inline unlang_action_t rediswho_rcode_check(request_t *request, fr_redis_command_set_t *cmds,
						   fr_redis_async_cmd_t *cmd, module_ctx_t const *mctx,
						   module_method_t resume, unlang_module_signal_t cancel)
{
	switch (fr_redis_command_set_rcode(cmds)) {
	case REDIS_ASYNC_RCODE_MOVE:
	{
		rlm_rediswho_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_rediswho_t);
		rlm_rediswho_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_rediswho_thread_t);

		if (inst->conf.use_cluster_map) fr_redis_cluster_thread_map_get(thread->rtcluster, thread->cw,
										inst->coord_pair_reg, false);
	}
		FALL_THROUGH;

	case REDIS_ASYNC_RCODE_ASK:
		if (fr_redis_async_cmd_redirect(cmd) != REDIS_ASYNC_RCODE_SUCCESS) return UNLANG_ACTION_FAIL;
		return unlang_module_yield(request, resume, cancel, ~FR_SIGNAL_CANCEL, mctx->rctx);

	case REDIS_ASYNC_RCODE_TRY_AGAIN:
		if (fr_redis_async_cmd_resend(cmd) != REDIS_ASYNC_RCODE_SUCCESS) return UNLANG_ACTION_FAIL;
		return unlang_module_yield(request, resume, cancel, ~FR_SIGNAL_CANCEL, mctx->rctx);

	default:
		break;
	}
	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t CC_HINT(nonnull) mod_accounting_resume(unlang_result_t *p_result, module_ctx_t const *mctx,
							      request_t *request)
{
	rediswho_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, rediswho_rctx_t);

	if (rediswho_rcode_check(request, rctx->cmds, rctx->cmd, mctx, mod_accounting_resume,
				 mod_accounting_cancel) == UNLANG_ACTION_YIELD) return UNLANG_ACTION_YIELD;

	if (rctx->ret < 0) {
		RPERROR("Redis command failed");
		RETURN_UNLANG_FAIL;
	}

	RETURN_UNLANG_OK;
}

static unlang_action_t CC_HINT(nonnull) mod_accounting_expire(unlang_result_t *p_result, module_ctx_t const *mctx,
							      request_t *request)
{
	rediswho_rctx_t		*rctx = talloc_get_type_abort(mctx->rctx, rediswho_rctx_t);
	rlm_rediswho_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_rediswho_thread_t);
	fr_redis_async_rcode_t	ret;

	if (rediswho_rcode_check(request, rctx->cmds, rctx->cmd, mctx, mod_accounting_expire,
				 mod_accounting_cancel) == UNLANG_ACTION_YIELD) return UNLANG_ACTION_YIELD;

	if (rctx->ret < 0) {
		RPERROR("Redis command failed");
		RETURN_UNLANG_FAIL;
	}

	ret = rediswho_command(thread, request, rctx->expire, rctx);

	REDIS_ASYNC_START_RCODE_PROCESS(ret, thread->rtcluster, thread->cw, thread->inst->coord_pair_reg,
					"Failed to enqueue Redis cache find commands", UNLANG_ACTION_FAIL)

	return unlang_module_yield(request, mod_accounting_resume, mod_accounting_cancel, 0, rctx);
}

static unlang_action_t CC_HINT(nonnull) mod_accounting_trim(unlang_result_t *p_result, module_ctx_t const *mctx,
							    request_t *request)
{
	rediswho_rctx_t		*rctx = talloc_get_type_abort(mctx->rctx, rediswho_rctx_t);
	rlm_rediswho_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_rediswho_t);
	rlm_rediswho_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_rediswho_thread_t);
	fr_redis_async_rcode_t	ret;

	if (rediswho_rcode_check(request, rctx->cmds, rctx->cmd, mctx, mod_accounting_trim,
				 mod_accounting_cancel) == UNLANG_ACTION_YIELD) return UNLANG_ACTION_YIELD;

	if (rctx->ret < 0) {
		RPERROR("Redis command failed");
		RETURN_UNLANG_FAIL;
	}

	if ((inst->trim_count > 0) && (rctx->ret > inst->trim_count)) {
		ret = rediswho_command(thread, request, rctx->trim, rctx);

		REDIS_ASYNC_START_RCODE_PROCESS(ret, thread->rtcluster, thread->cw, thread->inst->coord_pair_reg,
						"Failed to enqueue Redis cache find commands", UNLANG_ACTION_FAIL)

		return unlang_module_yield(request, mod_accounting_expire, mod_accounting_cancel, 0, rctx);
	}

	ret = rediswho_command(thread, request, rctx->expire, rctx);

	REDIS_ASYNC_START_RCODE_PROCESS(ret, thread->rtcluster, thread->cw, thread->inst->coord_pair_reg,
					"Failed to enqueue Redis cache find commands", UNLANG_ACTION_FAIL)

	return unlang_module_yield(request, mod_accounting_resume, mod_accounting_cancel, 0, rctx);
}

static int _rediswho_rctx_free(rediswho_rctx_t *rctx)
{
	if (rctx->cmd_str) redisFreeCommand(rctx->cmd_str);
	return 0;
}

static unlang_action_t CC_HINT(nonnull) mod_accounting(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_rediswho_thread_t		*thread = talloc_get_type_abort(mctx->thread, rlm_rediswho_thread_t);
	CONF_SECTION			*conf = mctx->mi->conf;
	fr_pair_t			*vp;
	fr_dict_enum_value_t const	*dv;
	CONF_SECTION			*cs;
	char const			*insert, *trim, *expire;
	fr_redis_async_rcode_t		ret;
	rediswho_rctx_t			*rctx;

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_acct_status_type);
	if (!vp) {
		RDEBUG2("Could not find account status type in packet");
		RETURN_UNLANG_NOOP;
	}

	dv = fr_dict_enum_by_value(vp->da, &vp->data);
	if (!dv) {
		RDEBUG2("Unknown Acct-Status-Type %u", vp->vp_uint32);
		RETURN_UNLANG_NOOP;
	}

	cs = cf_section_find(conf, dv->name, NULL);
	if (!cs) {
		RDEBUG2("No subsection %s", dv->name);
		RETURN_UNLANG_NOOP;
	}

	insert = cf_pair_value(cf_pair_find(cs, "insert"));
	trim = cf_pair_value(cf_pair_find(cs, "trim"));
	expire = cf_pair_value(cf_pair_find(cs, "expire"));

	if (!insert) {
		RDEBUG("No 'insert' query - ignoring");
		RETURN_UNLANG_NOOP;
	}

	if (!expire) {
		RDEBUG("No 'expire' query - ignoring");
		RETURN_UNLANG_NOOP;
	}

	MEM(rctx = talloc(unlang_interpret_frame_talloc_ctx(request), rediswho_rctx_t));
	*rctx = (rediswho_rctx_t) {
		.ret = -1,
		.trim = trim,
		.expire = expire
	};
	rctx->cmds = fr_redis_command_set_alloc(rctx, request, NULL, NULL, NULL, false);
	talloc_set_destructor(rctx, _rediswho_rctx_free);

	ret = rediswho_command(thread, request, insert, rctx);

	REDIS_ASYNC_START_RCODE_PROCESS(ret, thread->rtcluster, thread->cw, thread->inst->coord_pair_reg,
					"Failed to enqueue Redis cache find commands", UNLANG_ACTION_FAIL)

	return unlang_module_yield(request, trim ? mod_accounting_trim : mod_accounting_expire,
				   mod_accounting_cancel, ~FR_SIGNAL_CANCEL, rctx);
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_rediswho_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_rediswho_thread_t);
	rlm_rediswho_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_rediswho_t);

	t->rtcluster = fr_redis_cluster_thread_alloc(t, inst->tls_conf, mctx->el, &inst->conf, NULL, NULL, false);

	if (!t->rtcluster) return -1;
	t->inst = inst;

	return 0;
}

static int mod_coord_attach(module_thread_inst_ctx_t const *mctx)
{
	rlm_rediswho_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_rediswho_thread_t);
	rlm_rediswho_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_rediswho_t);

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
	rlm_rediswho_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_rediswho_thread_t);
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
	rlm_rediswho_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_rediswho_t);
	CONF_SECTION	*subcs = cf_section_find(mctx->mi->conf, "redis", NULL);

	inst->conf.log_prefix = mctx->mi->name;

	if (inst->conf.use_tls) {
		inst->tls_conf = cf_section_find(subcs, "tls", CF_IDENT_ANY);

		if (!inst->tls_conf) {
			cf_log_err(mctx->mi->conf, "Missing tls section");
			return -1;
		}
	}

	if (!inst->conf.use_cluster_map) return 0;

	if (inst->conf.database) {
		cf_log_err(mctx->mi->conf, "Cannot set Redis database number when cluster in use");
		return -1;
	}

	inst->coord_pair_reg = fr_coord_pair_register(&(fr_coord_pair_reg_ctx_t) {
			.name = mctx->mi->name,
			.worker_cb = worker_pair_callbacks,
			.cb_id = REDIS_COORD_PAIR_CALLBACK_ID,
			.root = fr_dict_root(dict_redis),
			.cs = subcs,
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

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_rediswho_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_rediswho_thread_t);

	if (!t->cw) return 0;

	fr_coord_detach(t->cw, true);
	t->cw = NULL;
	return 0;
}

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_rediswho_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_rediswho_t);

	fr_coord_deregister(inst->coord_reg);
	talloc_free(inst->coord_pair_reg);
	return 0;
}

static int mod_load(void)
{
	fr_redis_version_print();

	return 0;
}

extern module_rlm_t rlm_rediswho;
module_rlm_t rlm_rediswho = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "rediswho",
		.inst_size	= sizeof(rlm_rediswho_t),
		.config		= module_config,
		.onload		= mod_load,
		.instantiate	= mod_instantiate,
		.coord_attach	= mod_coord_attach,
		.detach		= mod_detach,
		MODULE_THREAD_INST(rlm_rediswho_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME("accounting", CF_IDENT_ANY), .method = mod_accounting },
			MODULE_BINDING_TERMINATOR
		}
	}
};
