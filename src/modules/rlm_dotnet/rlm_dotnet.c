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
 * @file rlm_dotnet.c
 * @brief Translates requests between the server and .NET Core.
 *
 * @author Blake Ramsdell <blake.ramsdell@onelogin.com>
 *
 * @copyright 2019 OneLogin, Inc.
 * @copyright 1999-2013 The FreeRADIUS Server Project.
 */

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include "coreclrhost.h"

/** Specifies the module.function to load for processing a section
 *
 */
typedef struct dotnet_func_def {
	void* function;

	char const	*assembly_name;		//!< String name of assembly.
	char const	*class_name;		//!< String name of class in assembly.
	char const	*function_name;		//!< String name of function in class.
} dotnet_func_def_t;

typedef struct rlm_dotnet_t {
	void *dylib;
	void *hostHandle;
	unsigned int domainId;

	dotnet_func_def_t
	instantiate,
	authorize,
	authenticate,
	preacct,
	accounting,
	checksimul,
	pre_proxy,
	post_proxy,
	post_auth,
#ifdef WITH_COA
	recv_coa,
	send_coa,
#endif
	detach;
} rlm_dotnet_t;

static const CONF_PARSER module_config[] = {
#define A(x) { "asm_" #x, FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dotnet_t, x.assembly_name), "${.assembly}" }, \
	{ "class_" #x, FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dotnet_t, x.class_name), "${.class}" }, \
	{ "func_" #x, FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dotnet_t, x.function_name), NULL },

	A(instantiate)
	A(authorize)
	A(authenticate)
	A(preacct)
	A(accounting)
	A(checksimul)
	A(pre_proxy)
	A(post_proxy)
	A(post_auth)
#ifdef WITH_COA
	A(recv_coa)
	A(send_coa)
#endif
	A(detach)

#undef A

	CONF_PARSER_TERMINATOR
};

/*
 *	Do any per-module initialization that is separate to each
 *	configured instance of the module.  e.g. set up connections
 *	to external databases, read configuration files, set up
 *	dictionary entries, etc.
 *
 *	If configuration information is given in the config section
 *	that must be referenced in later calls, store a handle to it
 *	in *instance otherwise put a null pointer there.
 *
 */
static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_dotnet_t	*inst = instance;

	radlog(L_INFO, __FILE__ " xyzzy!");
	// int hr = coreclr_initialize(NULL, NULL, 0, NULL, NULL, &inst->hostHandle, &inst->domainId);
	// !!! Check hr for failure

	return 0;
}

static int mod_detach(void *instance)
{
	rlm_dotnet_t *inst = instance;

	return 0;
}

static rlm_rcode_t do_dotnet(rlm_dotnet_t *inst, REQUEST *request, void *pFunc, char const *funcname)
{
	return RLM_MODULE_NOOP;
}

#define MOD_FUNC(x) \
static rlm_rcode_t CC_HINT(nonnull) mod_##x(void *instance, REQUEST *request) { \
	return do_dotnet((rlm_dotnet_t *) instance, request, ((rlm_dotnet_t *)instance)->x.function, #x);\
}

MOD_FUNC(authenticate)
MOD_FUNC(authorize)
MOD_FUNC(preacct)
MOD_FUNC(accounting)
MOD_FUNC(checksimul)
MOD_FUNC(pre_proxy)
MOD_FUNC(post_proxy)
MOD_FUNC(post_auth)
#ifdef WITH_COA
MOD_FUNC(recv_coa)
MOD_FUNC(send_coa)
#endif

extern module_t rlm_dotnet;
module_t rlm_dotnet = {
	.magic		= RLM_MODULE_INIT,
	.name		= "dotnet",
	.type		= RLM_TYPE_THREAD_UNSAFE,
	.inst_size	= sizeof(rlm_dotnet_t),
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
		[MOD_POST_AUTH]		= mod_post_auth,
#ifdef WITH_COA
		[MOD_RECV_COA]		= mod_recv_coa,
		[MOD_SEND_COA]		= mod_send_coa
#endif
	}
};
