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
} rlm_rediswho_t;

typedef struct {
	rlm_rediswho_t		*inst;			//!< Module instance.
	fr_redis_ct_t		*rtcluster;		//!< Per thread Redis cluster.
	fr_coord_worker_t	*cw;			//!< Coord-worker for fetching cluster map.
} rlm_rediswho_thread_t;

/** Resume context for rediswho module calls.
 */
typedef struct {
	fr_redis_command_set_t	*cmds;			//!< Command set for module call.
	fr_redis_async_cmd_t	*cmd;			//!< Async command context.
	char			*cmd_str;		//!< Formatted command currently being run.
	int			ret;			//!< Value returned in Redis reply.
} rediswho_rctx_t;

typedef struct {
	fr_value_box_t		key;			//!< Key value for redis commands
	fr_value_box_t		insert_cmd;		//!< Command to run for insert stage, defaults to LPUSH
	fr_value_box_t		insert_arg;		//!< Argument to append to insert command
	fr_value_box_t		trim_cmd;		//!< Command to run for trim stage, defaults to LTRIM
} rediswho_call_env_t;

static conf_parser_t redis_config[] = {
	REDIS_COMMON_CONFIG,
	CONF_PARSER_TERMINATOR
};

static conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("trim_count", rlm_rediswho_t, trim_count), .dflt = "-1" },
	{ FR_CONF_OFFSET_FLAGS("expiry_time", CONF_FLAG_REQUIRED, rlm_rediswho_t, expiry_time) },

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
static fr_redis_async_rcode_t rediswho_command(rlm_rediswho_thread_t *thread, request_t *request, fr_value_box_t *key,
					       rediswho_rctx_t *rctx, char const *fmt, ...)
{
	va_list			ap;
	fr_redis_async_rcode_t	ret;
	int			cmd_len;

	if (!fmt || !*fmt) return REDIS_ASYNC_RCODE_ERROR;

	/*
	 *	If there's a previous formatted command, clean up
	 */
	if (rctx->cmd_str) {
		redisFreeCommand(rctx->cmd_str);
		rctx->cmd_str = NULL;
		fr_redis_command_set_clear(rctx->cmds);
	}

	va_start(ap, fmt);
	cmd_len = redisvFormatCommand(&rctx->cmd_str, fmt, ap);
	va_end(ap);

	if (cmd_len < 0) {
		RERROR("Failed formatting redis commmand");
		return REDIS_ASYNC_RCODE_ERROR;
	}
	if (fr_redis_command_preformatted_add(rctx->cmds, rctx->cmd_str, cmd_len, rediswho_results,
					      rctx) != FR_REDIS_PIPELINE_OK) return REDIS_ASYNC_RCODE_ERROR;

	rctx->cmd = fr_redis_async_cmd_start(rctx, request, &ret, thread->rtcluster,
					     (uint8_t const *)key->vb_strvalue, key->vb_length, rctx->cmds, false, NULL);

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

		if (inst->conf.use_cluster_map) fr_redis_ct_map_get(thread->rtcluster, thread->cw,
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
	rlm_rediswho_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_rediswho_t);
	rlm_rediswho_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_rediswho_thread_t);
	rediswho_call_env_t	*env = talloc_get_type_abort(mctx->env_data, rediswho_call_env_t);
	fr_redis_async_rcode_t	ret;

	if (rediswho_rcode_check(request, rctx->cmds, rctx->cmd, mctx, mod_accounting_expire,
				 mod_accounting_cancel) == UNLANG_ACTION_YIELD) return UNLANG_ACTION_YIELD;

	if (rctx->ret < 0) {
		RPERROR("Redis command failed");
		RETURN_UNLANG_FAIL;
	}

	ret = rediswho_command(thread, request, &env->key, rctx, "EXPIRE %b %d",
			       (uint8_t const *)env->key.vb_strvalue, env->key.vb_length, inst->expiry_time);

	REDIS_ASYNC_START_RCODE_PROCESS(ret, thread->rtcluster, thread->cw, thread->inst->coord_pair_reg,
					"Failed to enqueue Redis cache find commands", UNLANG_ACTION_FAIL)
	RDEBUG3("Setting expiry to %d", inst->expiry_time);

	return unlang_module_yield(request, mod_accounting_resume, mod_accounting_cancel, 0, rctx);
}

static unlang_action_t CC_HINT(nonnull) mod_accounting_trim(unlang_result_t *p_result, module_ctx_t const *mctx,
							    request_t *request)
{
	rediswho_rctx_t		*rctx = talloc_get_type_abort(mctx->rctx, rediswho_rctx_t);
	rlm_rediswho_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_rediswho_t);
	rlm_rediswho_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_rediswho_thread_t);
	rediswho_call_env_t	*env = talloc_get_type_abort(mctx->env_data, rediswho_call_env_t);
	fr_redis_async_rcode_t	ret;

	if (rediswho_rcode_check(request, rctx->cmds, rctx->cmd, mctx, mod_accounting_trim,
				 mod_accounting_cancel) == UNLANG_ACTION_YIELD) return UNLANG_ACTION_YIELD;

	if (rctx->ret < 0) {
		RPERROR("Redis command failed");
		RETURN_UNLANG_FAIL;
	}

	RDEBUG3("Key \"%pV\" has %d entries", &env->key, rctx->ret);

	if (rctx->ret > inst->trim_count) {
		ret = rediswho_command(thread, request, &env->key, rctx, "%s %b 0 %d", env->trim_cmd.vb_strvalue,
				       (uint8_t const *)env->key.vb_strvalue, env->key.vb_length, inst->trim_count - 1);

		REDIS_ASYNC_START_RCODE_PROCESS(ret, thread->rtcluster, thread->cw, thread->inst->coord_pair_reg,
						"Failed to enqueue Redis cache find commands", UNLANG_ACTION_FAIL)
		RDEBUG3("Trimming \"%pV\" to %d entries", &env->key, inst->trim_count);
		return unlang_module_yield(request, mod_accounting_expire, mod_accounting_cancel, 0, rctx);
	}

	ret = rediswho_command(thread, request, &env->key, rctx, "EXPIRE %b %d",
			       (uint8_t const *)env->key.vb_strvalue, env->key.vb_length, inst->expiry_time);

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
	rlm_rediswho_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_rediswho_t);
	rlm_rediswho_thread_t		*thread = talloc_get_type_abort(mctx->thread, rlm_rediswho_thread_t);
	rediswho_call_env_t		*env = talloc_get_type_abort(mctx->env_data, rediswho_call_env_t);
	fr_redis_async_rcode_t		ret;
	rediswho_rctx_t			*rctx;

	if (env->key.vb_length == 0) {
		RDEBUG2("Zero length key value");
		RETURN_UNLANG_NOOP;
	}

	if (env->insert_arg.vb_length == 0) {
		RDEBUG2("Zero length argument value");
		RETURN_UNLANG_NOOP;
	}

	MEM(rctx = talloc(unlang_interpret_frame_talloc_ctx(request), rediswho_rctx_t));
	*rctx = (rediswho_rctx_t) { .ret = -1 };
	rctx->cmds = fr_redis_command_set_alloc(rctx, request, NULL, NULL, NULL, false);
	talloc_set_destructor(rctx, _rediswho_rctx_free);

	ret = rediswho_command(thread, request, &env->key, rctx, "%s %b %b", env->insert_cmd.vb_strvalue,
			       (uint8_t const *)env->key.vb_strvalue, env->key.vb_length,
			       (uint8_t const *)env->insert_arg.vb_strvalue, env->insert_arg.vb_length);

	REDIS_ASYNC_START_RCODE_PROCESS(ret, thread->rtcluster, thread->cw, thread->inst->coord_pair_reg,
					"Failed to enqueue Redis cache find commands", UNLANG_ACTION_FAIL)

	return unlang_module_yield(request, inst->trim_count > 0 ? mod_accounting_trim : mod_accounting_expire,
				   mod_accounting_cancel, ~FR_SIGNAL_CANCEL, rctx);
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_rediswho_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_rediswho_thread_t);
	rlm_rediswho_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_rediswho_t);

	t->rtcluster = fr_redis_ct_alloc(t, inst->tls_conf, mctx->el, &inst->conf, NULL, NULL, false);

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

	return fr_redis_ct_map_bootstrap(t->rtcluster, t->cw, inst->coord_pair_reg);
}

REDIS_ASYNC_COORD_CALLBACKS(rlm_rediswho_thread_t);

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_rediswho_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_rediswho_t);
	CONF_SECTION	*subcs = cf_section_find(mctx->mi->conf, "redis", NULL);

	inst->conf.log_prefix = mctx->mi->name;
	inst->conf.module_name = mctx->mi->module->name;
	inst->conf.inst_name = mctx->mi->name;

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

static call_env_parser_t const rediswho_env_parser[] = {
	{ FR_CALL_ENV_OFFSET("key", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE , rediswho_call_env_t, key) },
	{ FR_CALL_ENV_OFFSET("insert_cmd", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT, rediswho_call_env_t, insert_cmd), .pair.dflt = "LPUSH", .pair.dflt_quote = T_SINGLE_QUOTED_STRING },
	{ FR_CALL_ENV_OFFSET("insert_arg", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_REQUIRED , rediswho_call_env_t, insert_arg) },
	{ FR_CALL_ENV_OFFSET("trim_cmd", FR_TYPE_STRING, CALL_ENV_FLAG_CONCAT , rediswho_call_env_t, trim_cmd), .pair.dflt = "LTRIM", .pair.dflt_quote = T_SINGLE_QUOTED_STRING },
	CALL_ENV_TERMINATOR
};

static int redis_command_call_env_parse(TALLOC_CTX *ctx, call_env_parsed_head_t *out, tmpl_rules_t const *t_rules,
					CONF_ITEM *ci, call_env_ctx_t const *cec, UNUSED call_env_parser_t const *rule)
{
	CONF_SECTION const	*subcs = NULL;
	char			*section2, *p;

	fr_assert(cec->type == CALL_ENV_CTX_TYPE_MODULE);

	section2 = talloc_strdup(NULL, section_name_str(cec->asked->name2));
	p = section2;
	while (*p != '\0') {
		*(p) = tolower((uint8_t)*p);
		p++;
	}
	subcs = cf_section_find(cf_item_to_section(cf_parent(ci)), section2, CF_IDENT_ANY);
	talloc_free(section2);
	if (!subcs) {
		cf_log_warn(ci, "No \"%s\" section found", section_name_str(cec->asked->name2) );
		return 0;
	}

	return call_env_parse(ctx, out, cec->asked->name2, t_rules, subcs, cec, rediswho_env_parser);
}

static const call_env_method_t method_env = {
	FR_CALL_ENV_METHOD_OUT(rediswho_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_SUBSECTION_FUNC(CF_IDENT_ANY, CF_IDENT_ANY, CALL_ENV_FLAG_SUBSECTION, redis_command_call_env_parse) },
		CALL_ENV_TERMINATOR
	}
};

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
			{ .section = SECTION_NAME("accounting", CF_IDENT_ANY), .method = mod_accounting, .method_env = &method_env },
			MODULE_BINDING_TERMINATOR
		}
	}
};
