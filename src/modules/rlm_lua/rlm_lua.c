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
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 *
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2016 The FreeRADIUS Server Project.
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/modules.h>

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
	{ FR_CONF_OFFSET("threads", FR_TYPE_BOOL, rlm_lua_t, threads), .dflt = "no"},
	{ FR_CONF_OFFSET("func_instantiate", FR_TYPE_STRING, rlm_lua_t, func_instantiate), NULL},
	{ FR_CONF_OFFSET("func_detach", FR_TYPE_STRING, rlm_lua_t, func_detach), NULL},
	{ FR_CONF_OFFSET("func_authorize", FR_TYPE_STRING, rlm_lua_t, func_authorize), NULL},
	{ FR_CONF_OFFSET("func_authenticate", FR_TYPE_STRING, rlm_lua_t, func_authenticate), NULL},
#ifdef WITH_ACCOUNTING
	{ FR_CONF_OFFSET("func_accounting", FR_TYPE_STRING, rlm_lua_t, func_accounting), NULL},
	{ FR_CONF_OFFSET("func_preacct", FR_TYPE_STRING, rlm_lua_t, func_preacct), NULL},
#endif
	{ FR_CONF_OFFSET("func_checksimul", FR_TYPE_STRING, rlm_lua_t, func_checksimul), NULL},
	{ FR_CONF_OFFSET("func_xlat", FR_TYPE_STRING, rlm_lua_t, func_xlat), NULL},
#ifdef WITH_PROXY
	{ FR_CONF_OFFSET("func_pre_proxy", FR_TYPE_STRING, rlm_lua_t, func_pre_proxy), NULL},
	{ FR_CONF_OFFSET("func_post_proxy", FR_TYPE_STRING, rlm_lua_t, func_post_proxy), NULL},
#endif
	{ FR_CONF_OFFSET("func_post_auth", FR_TYPE_STRING, rlm_lua_t, func_post_auth), NULL},
#ifdef WITH_COA
	{ FR_CONF_OFFSET("func_recv_coa", FR_TYPE_STRING, rlm_lua_t, func_recv_coa), NULL},
	{ FR_CONF_OFFSET("func_send_coa", FR_TYPE_STRING, rlm_lua_t, func_send_coa), NULL},
#endif

	CONF_PARSER_TERMINATOR
};

/** Destroy the interpreter when it's associated worker exits
 *
 * @param ctx The interpreter to destroy.
 */
static void _tls_interp_destroy(void *ctx)
{
	lua_State **marker = talloc_get_type_abort(ctx, lua_State *);
	rlm_lua_t *inst;

	/*
	 *	ctx is a pointer to a Lua interpreter.
	 *	So that we don't have to have a special struct to pass around the instance this
	 *	interpreter belongs to, we use some talloc magic to find it's parent context
	 *	which is hopefully an rlm_lua_t.
	 *
	 *	We then re-use the mutex in the rlm_lua_t to protect the parent context whilst
	 *	we free this context, which should in turn call a destructor which will
	 *	call lua_close and free the actual interpreter.
	 */
	inst = talloc_find_parent_bytype(marker, rlm_lua_t);
	rad_assert(inst != NULL);
	pthread_mutex_lock(inst->mutex);
	talloc_free(marker);
	pthread_mutex_unlock(inst->mutex);
}

static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	rlm_lua_t *inst = instance;

	inst->xlat_name = cf_section_name2(conf);
	if (!inst->xlat_name) {
		inst->xlat_name = cf_section_name1(conf);
	}

#ifdef HAVE_PTHREAD_H
	inst->mutex = talloc(inst, pthread_mutex_t);
	pthread_mutex_init(inst->mutex, NULL);	/* Used in both threaded and non-threaded modes */

	if (inst->threads) {
		int rcode;

		rcode = pthread_key_create(&inst->key, _tls_interp_destroy);
		if (rcode != 0) {
			ERROR("Error creating pthread key for lua interpreter: %s", fr_syserror(rcode));
			return -1;
		}
	}
#endif
	if (rlm_lua_init(&inst->interpreter, inst) < 0) {
		return -1;
	}

	inst->jit = rlm_lua_isjit(inst->interpreter);
	if (!inst->jit) {
		WARN("Using standard Lua interpreter, performance will be suboptimal");
	}

	DEBUG("rlm_lua (%s): Using %s interpreter", inst->xlat_name, rlm_lua_version(inst->interpreter));

	return 0;
}

static int mod_detach(void *instance)
{
	rlm_lua_t *inst = instance;

	if (inst->key) {
		pthread_key_delete(inst->key);
	}

	return 0;
}

#define DO_LUA(_s)\
static rlm_rcode_t mod_##_s(void *instance, UNUSED void *thread, REQUEST *request) {\
	rlm_lua_t const *inst = instance;\
	if (!inst->func_##_s) {\
		return RLM_MODULE_NOOP;\
	}\
	if (do_lua(inst, request, inst->func_##_s) < 0) {\
		return RLM_MODULE_FAIL;\
	}\
	return RLM_MODULE_OK;\
}

DO_LUA(authorize)
DO_LUA(authenticate)
DO_LUA(preacct)
DO_LUA(accounting)
DO_LUA(checksimul)
DO_LUA(pre_proxy)
DO_LUA(post_proxy)
DO_LUA(post_auth)
DO_LUA(recv_coa)
DO_LUA(send_coa)

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern rad_module_t rlm_lua;
rad_module_t rlm_lua = {
	.magic		= RLM_MODULE_INIT,
	.name		= "lua",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_lua_t),
	.config		= module_config,
	.instantiate	= mod_instantiate,
	.detach		= mod_detach,

	.methods = {
		[MOD_AUTHENTICATE]	= mod_authenticate,
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_PREACCT]		= mod_preacct,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_SESSION]		= mod_checksimul,
		[MOD_PRE_PROXY]		= mod_pre_proxy,
		[MOD_POST_PROXY]	= mod_post_proxy,
		[MOD_POST_AUTH]		= mod_post_auth
#ifdef WITH_COA
		,
		[MOD_RECV_COA]		= mod_recv_coa,
		[MOD_SEND_COA]		= mod_send_coa
#endif
	}
};
