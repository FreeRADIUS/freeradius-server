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

#define LOG_PREFIX "rlm_lua (%s) - "
#define LOG_PREFIX_ARGS inst->xlat_name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/module.h>

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
#ifdef WITH_ACCOUNTING
	{ FR_CONF_OFFSET("func_accounting", FR_TYPE_STRING, rlm_lua_t, func_accounting), NULL},
	{ FR_CONF_OFFSET("func_preacct", FR_TYPE_STRING, rlm_lua_t, func_preacct), NULL},
#endif
	{ FR_CONF_OFFSET("func_xlat", FR_TYPE_STRING, rlm_lua_t, func_xlat), NULL},
	{ FR_CONF_OFFSET("func_post_auth", FR_TYPE_STRING, rlm_lua_t, func_post_auth), NULL},

	CONF_PARSER_TERMINATOR
};

#define DO_LUA(_s)\
static rlm_rcode_t mod_##_s(module_ctx_t const *mctx, REQUEST *request) \
{\
	rlm_lua_t const *inst = talloc_get_type_abort_const(mctx->instance, rlm_lua_t);\
	if (!inst->func_##_s) return RLM_MODULE_NOOP;\
	return fr_lua_run(mctx, request, inst->func_##_s);\
}

DO_LUA(authorize)
DO_LUA(authenticate)
DO_LUA(preacct)
DO_LUA(accounting)
DO_LUA(post_auth)


/** Free any thread specific interpreters
 *
 */
static int mod_thread_detach(UNUSED fr_event_list_t *el, void *thread)
{
	rlm_lua_thread_t *this_thread = thread;

	/*
	 *	May be NULL if fr_lua_init failed
	 */
	if (this_thread->interpreter) lua_close(this_thread->interpreter);

	return 0;
}

/** Create thread-specific connections and buffers
 *
 * @param[in] conf	section containing the configuration of this module instance.
 * @param[in] instance	of rlm_lua_t.
 * @param[in] el	The event list serviced by this thread.
 * @param[in] thread	specific data (where we write the interpreter).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_thread_instantiate(UNUSED CONF_SECTION const *conf, void *instance,
				  UNUSED fr_event_list_t *el, void *thread)
{
	rlm_lua_thread_t *this_thread = thread;

	if (fr_lua_init(&this_thread->interpreter, instance) < 0) return -1;

	return 0;
}

/** Close the global interpreter
 *
 */
static int mod_detach(void *instance)
{
	rlm_lua_t *inst = instance;
	int ret = 0;

	/*
	 *	May be NULL if fr_lua_init failed
	 */
	if (inst->interpreter) {
		if (inst->func_detach) ret = fr_lua_run(&(module_ctx_t){
								.instance = inst,
								.thread = &(rlm_lua_thread_t){
									.interpreter = inst->interpreter
								}
							},
							NULL, inst->func_detach);

		lua_close(inst->interpreter);
	}

	return ret;
}

static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_lua_t *inst = instance;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) inst->xlat_name = cf_section_name1(conf);

	/*
	 *	Get an instance global interpreter to use with various things...
	 */
	if (fr_lua_init(&inst->interpreter, inst) < 0) return -1;
	inst->jit = fr_lua_isjit(inst->interpreter);
	if (!inst->jit) WARN("Using standard Lua interpreter, performance will be suboptimal");

	DEBUG("Using %s interpreter", fr_lua_version(inst->interpreter));

	if (inst->func_instantiate) return fr_lua_run(&(module_ctx_t){
								.instance = inst,
								.thread = &(rlm_lua_thread_t){
									.interpreter = inst->interpreter
								}
						      },
						      NULL, inst->func_instantiate);

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_lua;
module_t rlm_lua = {
	.magic			= RLM_MODULE_INIT,
	.name			= "lua",
	.type			= RLM_TYPE_THREAD_SAFE,
	.inst_size		= sizeof(rlm_lua_t),

	.thread_inst_size	= sizeof(rlm_lua_thread_t),

	.config			= module_config,
	.instantiate		= mod_instantiate,
	.thread_instantiate	= mod_thread_instantiate,

	.detach			= mod_detach,
	.thread_detach		= mod_thread_detach,

	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_POST_AUTH]		= mod_post_auth
	}
};
