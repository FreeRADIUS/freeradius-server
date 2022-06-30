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
 * @file rlm_lua.c
 * @brief Translates requests between the server an a Lua interpreter.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#define LOG_PREFIX mctx->inst->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/module_rlm.h>

#include "lua.h"
/*
 *	A mapping of configuration file names to internal variables.
 *
 *	Note that the string is dynamically allocated, so it MUST
 *	be freed.  When the configuration file parse re-reads the string,
 *	it free's the old one, and strdup's the new one, placing the pointer
 *	to the strdup'd string into 'config.string'.  This gets around
 *	buffer over-flows.
 */
static const CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("filename", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, rlm_lua_t, module), NULL},
	{ FR_CONF_OFFSET("func_instantiate", FR_TYPE_STRING, rlm_lua_t, func_instantiate), NULL},
	{ FR_CONF_OFFSET("func_detach", FR_TYPE_STRING, rlm_lua_t, func_detach), NULL},
	{ FR_CONF_OFFSET("func_authorize", FR_TYPE_STRING, rlm_lua_t, func_authorize), NULL},
	{ FR_CONF_OFFSET("func_authenticate", FR_TYPE_STRING, rlm_lua_t, func_authenticate), NULL},
	{ FR_CONF_OFFSET("func_accounting", FR_TYPE_STRING, rlm_lua_t, func_accounting), NULL},
	{ FR_CONF_OFFSET("func_preacct", FR_TYPE_STRING, rlm_lua_t, func_preacct), NULL},
	{ FR_CONF_OFFSET("func_xlat", FR_TYPE_STRING, rlm_lua_t, func_xlat), NULL},
	{ FR_CONF_OFFSET("func_post_auth", FR_TYPE_STRING, rlm_lua_t, func_post_auth), NULL},

	CONF_PARSER_TERMINATOR
};

#define DO_LUA(_s)\
static unlang_action_t mod_##_s(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request) \
{\
	rlm_lua_t const *inst = talloc_get_type_abort_const(mctx->inst->data, rlm_lua_t);\
	if (!inst->func_##_s) RETURN_MODULE_NOOP;\
	return fr_lua_run(p_result, mctx, request, inst->func_##_s);\
}

DO_LUA(authorize)
DO_LUA(authenticate)
DO_LUA(preacct)
DO_LUA(accounting)
DO_LUA(post_auth)


/** Free any thread specific interpreters
 *
 */
static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_lua_thread_t *t = talloc_get_type_abort(mctx->thread, rlm_lua_thread_t);

	/*
	 *	May be NULL if fr_lua_init failed
	 */
	if (t->interpreter) lua_close(t->interpreter);

	return 0;
}

/** Create thread-specific connections and buffers
 *
 * @param[in] mctx	specific data (where we write the interpreter).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_lua_thread_t *t = talloc_get_type_abort(mctx->thread, rlm_lua_thread_t);

	if (fr_lua_init(&t->interpreter, (module_inst_ctx_t const *)mctx) < 0) return -1;

	return 0;
}

/** Close the global interpreter
 *
 */
static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_lua_t *inst = talloc_get_type_abort(mctx->inst->data, rlm_lua_t);
	rlm_rcode_t ret = 0;

	/*
	 *	May be NULL if fr_lua_init failed
	 */
	if (inst->interpreter) {
		if (inst->func_detach) {
			fr_lua_run(&ret,
				   MODULE_CTX(mctx->inst,
					      &(rlm_lua_thread_t){
							.interpreter = inst->interpreter
					      },
					      NULL),
				   NULL, inst->func_detach);
		}
		lua_close(inst->interpreter);
	}

	return ret;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_lua_t *inst = talloc_get_type_abort(mctx->inst->data, rlm_lua_t);
	rlm_rcode_t rcode;

	/*
	 *	Get an instance global interpreter to use with various things...
	 */
	if (fr_lua_init(&inst->interpreter, mctx) < 0) return -1;
	inst->jit = fr_lua_isjit(inst->interpreter);
	if (!inst->jit) WARN("Using standard Lua interpreter, performance will be suboptimal");

	DEBUG("Using %s interpreter", fr_lua_version(inst->interpreter));

	if (inst->func_instantiate) {
		fr_lua_run(&rcode,
			   MODULE_CTX(mctx->inst,
			   	      &(rlm_lua_thread_t){
						.interpreter = inst->interpreter
				      },
				      NULL),
			   NULL, inst->func_instantiate);
	}

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_lua;
module_rlm_t rlm_lua = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "lua",
		.type			= MODULE_TYPE_THREAD_SAFE,
		.inst_size		= sizeof(rlm_lua_t),

		.thread_inst_size	= sizeof(rlm_lua_thread_t),

		.config			= module_config,
		.instantiate		= mod_instantiate,
		.thread_instantiate	= mod_thread_instantiate,

		.detach			= mod_detach,
		.thread_detach		= mod_thread_detach
	},
	.method_names = (module_method_name_t[]){
		/*
		 *	Hack to support old configurations
		 */
		{ .name1 = "authorize",		.name2 = CF_IDENT_ANY,		.method = mod_authorize		},

		{ .name1 = "recv",		.name2 = "accounting-request",	.method = mod_preacct		},
		{ .name1 = "recv",		.name2 = CF_IDENT_ANY,		.method = mod_authorize		},
		{ .name1 = "accounting",	.name2 = CF_IDENT_ANY,		.method = mod_accounting	},
		{ .name1 = "authenticate",	.name2 = CF_IDENT_ANY,		.method = mod_authenticate	},
		{ .name1 = "send",		.name2 = CF_IDENT_ANY,		.method = mod_post_auth		},
		MODULE_NAME_TERMINATOR
	}
};
