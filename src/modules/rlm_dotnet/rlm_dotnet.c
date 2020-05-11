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

#include <dirent.h>
#include <string.h>
#include <talloc.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <dlfcn.h>
#include "coreclrhost.h"

#ifdef __APPLE__
#  define FS_SEPARATOR    "/"
#  define PATH_DELIMITER  ":"
#define DEFAULT_CLR_LIBRARY	"libcoreclr.dylib"
#elif defined (WIN32)
#  define FS_SEPARATOR    "\\"
#  define PATH_DELIMITER  ";"
#define DEFAULT_CLR_LIBRARY	"libcoreclr.dll"
#else
#  define FS_SEPARATOR    "/"
#  define PATH_DELIMITER  ":"
#define DEFAULT_CLR_LIBRARY	"libcoreclr.so"
#endif

/** Specifies the module.function to load for processing a section
 *
 */
typedef struct dotnet_func_def {
	void *function;

	char const	*assembly_name;		//!< String name of assembly.
	char const	*class_name;		//!< String name of class in assembly.
	char const	*function_name;		//!< String name of function in class.
} dotnet_func_def_t;

typedef void (*instantiate_function_t)(int numberStrings, void* strings, void (*log)(int, char const*));

static struct {
	char const *name;
	int  value;
} radiusd_constants[] = {

#define A(x) { #x, x },

	A(L_DBG)
	A(L_WARN)
	A(L_AUTH)
	A(L_INFO)
	A(L_ERR)
	A(L_PROXY)
	A(L_ACCT)
	A(L_DBG_WARN)
	A(L_DBG_ERR)
	A(L_DBG_WARN_REQ)
	A(L_DBG_ERR_REQ)
	A(RLM_MODULE_REJECT)
	A(RLM_MODULE_FAIL)
	A(RLM_MODULE_OK)
	A(RLM_MODULE_HANDLED)
	A(RLM_MODULE_INVALID)
	A(RLM_MODULE_USERLOCK)
	A(RLM_MODULE_NOTFOUND)
	A(RLM_MODULE_NOOP)
	A(RLM_MODULE_UPDATED)
	A(RLM_MODULE_NUMCODES)

	A(T_OP_INCRM)
	A(T_OP_ADD)
	A(T_OP_SUB)
	A(T_OP_SET)
	A(T_OP_EQ)
	A(T_OP_NE)
	A(T_OP_GE)
	A(T_OP_GT)
	A(T_OP_LE)
	A(T_OP_LT)
	A(T_OP_REG_EQ)
	A(T_OP_REG_NE)
	A(T_OP_CMP_TRUE)
	A(T_OP_CMP_FALSE)
	A(T_OP_CMP_EQ)

	A(PW_TYPE_INVALID)
	A(PW_TYPE_STRING)
	A(PW_TYPE_INTEGER)
	A(PW_TYPE_IPV4_ADDR)
	A(PW_TYPE_DATE)
	A(PW_TYPE_ABINARY)
	A(PW_TYPE_OCTETS)
	A(PW_TYPE_IFID)
	A(PW_TYPE_IPV6_ADDR)
	A(PW_TYPE_IPV6_PREFIX)
	A(PW_TYPE_BYTE)
	A(PW_TYPE_SHORT)
	A(PW_TYPE_ETHERNET)
	A(PW_TYPE_SIGNED)
	A(PW_TYPE_COMBO_IP_ADDR)
	A(PW_TYPE_TLV)
	A(PW_TYPE_EXTENDED)
	A(PW_TYPE_LONG_EXTENDED)
	A(PW_TYPE_EVS)
	A(PW_TYPE_INTEGER64)
	A(PW_TYPE_IPV4_PREFIX)
	A(PW_TYPE_VSA)
	A(PW_TYPE_TIMEVAL)
	A(PW_TYPE_BOOLEAN)
	A(PW_TYPE_COMBO_IP_PREFIX)
	A(PW_TYPE_MAX)

#undef A

	{ NULL, 0 },
};

typedef struct rlm_dotnet_t {
	void *dylib;
	void *hostHandle;
	unsigned int domainId;
	coreclr_initialize_ptr coreclr_initialize;
	coreclr_create_delegate_ptr coreclr_create_delegate;
	coreclr_shutdown_2_ptr coreclr_shutdown_2;

	char const	*clr_root;			//!< Root directory for CLR.
	char const	*clr_library;		//!< Path to CLR library.
	char const	*assembly_path;		//!< Path to your assembly.

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

	{ "clr_root", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dotnet_t, clr_root), NULL },
	{ "clr_library", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dotnet_t, clr_library), DEFAULT_CLR_LIBRARY },
	{ "assembly_path", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_dotnet_t, assembly_path), NULL },

	CONF_PARSER_TERMINATOR
};

typedef struct dotnet_vp {
	char const* name;
	PW_TYPE value_type;
	int value_length;
	void* value;
} dotnet_vp_t;

typedef struct dotnet_vp_collection {
	size_t	count;
	dotnet_vp_t* vps;
} dotnet_vp_collection_t;

static void mod_radlog(int status, char const* msg)
{
	radlog(status, "%s", msg);
}

static int bind_dotnet(rlm_dotnet_t *inst)
{
	// Do dlopen
	inst->dylib = dlopen(inst->clr_library, RTLD_NOW | RTLD_GLOBAL);
	if (!inst->dylib)
	{
		ERROR("%s", dlerror());
		return 1;
	}

	// Find the relevant methods we want
#define A(x)	inst->x = dlsym(inst->dylib, #x); \
				if (!inst->x) ERROR("%s", dlerror());

	A(coreclr_initialize)
	A(coreclr_create_delegate)
	A(coreclr_shutdown_2)
#undef A

	return 0;
}

static int bind_one_method(rlm_dotnet_t *inst, dotnet_func_def_t *function_definition, char const *function_name)
{
	int rc = 0;
	if (function_definition->function_name)
	{
		DEBUG("binding %s to %s %s %s", function_name, function_definition->assembly_name, function_definition->class_name, function_definition->function_name);
		rc = inst->coreclr_create_delegate(
			inst->hostHandle,
			inst->domainId,
			function_definition->assembly_name,
			function_definition->class_name,
			function_definition->function_name,
			(void**) &function_definition->function
			);
		if (rc)
		{
			ERROR("Failure binding %s to %s %s %s, coreclr_create_delegate returned 0x%08X", function_name, function_definition->assembly_name, function_definition->class_name, function_definition->function_name, rc);
		}
		else
		{
			DEBUG("Bound it! Function is %p", function_definition->function);
		}
		
	}

	return rc;
}

// https://stackoverflow.com/questions/744766/how-to-compare-ends-of-strings-in-c
static int string_ends_with(char const *str, char const *suffix)
{
	if (!str || !suffix)
		return 0;
	size_t lenstr = strlen(str);
	size_t lensuffix = strlen(suffix);
	if (lensuffix >  lenstr)
		return 0;
	return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

static char* build_tpa_list(const char* directory)
{
	DIR* dir = opendir(directory);
	struct dirent* entry;
	char* tpa_list = NULL;

	if (dir == NULL)
	{
		// errno is set, perror might be useful
		return NULL;
	}

	while ((entry = readdir(dir)) != NULL)
	{
		// Check if the file has the right extension
		if (!string_ends_with(entry->d_name, ".dll"))
		{
			continue;
		}

		// Append the assembly to the list
		if (tpa_list != NULL)
		{
			tpa_list = talloc_strdup_append(tpa_list, PATH_DELIMITER);
		}
		tpa_list = talloc_strdup_append(tpa_list, directory);
		tpa_list = talloc_strdup_append(tpa_list, FS_SEPARATOR);
		tpa_list = talloc_strdup_append(tpa_list, entry->d_name);
	}

	(void) closedir(dir);

	return tpa_list;
}

static char* append_one_tpa(char* tpa, const char* new_tpa)
{
	if (new_tpa != NULL)
	{
		tpa = talloc_strdup_append(tpa, PATH_DELIMITER);
		tpa = talloc_strdup_append(tpa, new_tpa);
	}

	return tpa;
}

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
static int mod_instantiate(UNUSED CONF_SECTION *conf, void *instance)
{
	rlm_dotnet_t	*inst = instance;
	char* tpa;

	DEBUG("mod_instantiate");
	if (bind_dotnet(inst))
	{
		ERROR("Failed to load .NET core");
		return RLM_MODULE_FAIL;
	}

	tpa = build_tpa_list(inst->clr_root);
	tpa = append_one_tpa(tpa, inst->assembly_path);
	const char* propertyKeys[] = {
		"TRUSTED_PLATFORM_ASSEMBLIES"
	};
    const char* propertyValues[] = {
        tpa
    };

	int hr = inst->coreclr_initialize(
		"/Users/blakeramsdell/Source/OpenSource/freeradius-server",
		"FreeRadius",
		sizeof(propertyKeys) / sizeof(char*),
		propertyKeys,
		propertyValues,
		&inst->hostHandle,
		&inst->domainId
		);

	// Check hr for failure
	if (hr == 0)
	{
		// Bind up all of our C# methods
#define A(x) bind_one_method(inst, &inst->x, #x);
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
	}
	else
	{
		ERROR("Failed coreclr_initialize hr = 0x%08X", hr);
	}

	if (inst->instantiate.function)
	{
		instantiate_function_t instantiate_function = inst->instantiate.function;
		instantiate_function(sizeof(radiusd_constants) / sizeof(radiusd_constants[0]), radiusd_constants, mod_radlog);
	}

	return 0;
}

static int mod_detach(void *instance)
{
	rlm_dotnet_t *inst = instance;

	int latchedExitCode = 0;
	int hr = inst->coreclr_shutdown_2(inst->hostHandle, inst->domainId, &latchedExitCode);
	INFO("coreclr_shutdown_2 hr = 0x%08X latchedExitCode = 0x%08X", hr, latchedExitCode);
	return 0;
}

static void make_vp(TALLOC_CTX* ctx, VALUE_PAIR const *vp, dotnet_vp_t* final_vp)
{
	char namebuf[256];
	char const* name;

	/*
	 *	Tagged attributes are added to the hash with name
	 *	<attribute>:<tag>, others just use the normal attribute
	 *	name as the key.
	 */
	if (vp->da->flags.has_tag && (vp->tag != TAG_ANY)) {
		snprintf(namebuf, sizeof(namebuf), "%s:%d", vp->da->name, vp->tag);
		name = namebuf;
	} else {
		name = vp->da->name;
	}
	final_vp->name = talloc_strdup(ctx, name);

	final_vp->value_type = vp->da->type;
	final_vp->value_length = vp->length;
#define A(x, y)		case x:	\
				 		final_vp->value = talloc_array(ctx, char, vp->length);	\
						memcpy(final_vp->value, &vp->y, vp->length);					\
						break;

	switch (vp->da->type) {
		case PW_TYPE_STRING:
			final_vp->value = talloc_strdup(ctx, vp->vp_strvalue);
			break;

		A(PW_TYPE_IPV4_ADDR,	vp_ipaddr)
		A(PW_TYPE_DATE, 		vp_date)

		default:
			ERROR("Unknown vp type %d", vp->da->type);
			final_vp->value_length = 0;
			final_vp->value = NULL;
			break;
	}

#undef A
}

static dotnet_vp_collection_t* make_vp_collection(TALLOC_CTX* ctx, VALUE_PAIR **vps)
{
	dotnet_vp_collection_t* collection = talloc(ctx, dotnet_vp_collection_t);
	vp_cursor_t cursor;
	VALUE_PAIR* vp;
	size_t counter = 0;

	collection->count = 0;
	for (vp = fr_cursor_init(&cursor, vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
			 ++collection->count;
		 }

	collection->vps = talloc_array(collection, dotnet_vp_t, collection->count);
	for (vp = fr_cursor_init(&cursor, vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {
			 make_vp(collection, vp, &collection->vps[counter++]);
		 }

	return collection;
}

static rlm_rcode_t do_dotnet(UNUSED rlm_dotnet_t *inst, REQUEST *request, void *pFunc,UNUSED char const *funcname)
{
	rlm_rcode_t (*function)(size_t count, dotnet_vp_t* vps) = pFunc;

	dotnet_vp_collection_t* collection = make_vp_collection(request->packet, &request->packet->vps);
	// Just call it and party

	return function(collection->count, collection->vps);
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
