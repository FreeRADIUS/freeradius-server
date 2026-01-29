/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
 *
 * @file virtual_servers.c
 * @brief Defines functions for virtual_server initialisation.
 *
 * @copyright 2003,2006 The FreeRADIUS server project
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 * @copyright 2000 Alan Curry (pacman@world.std.com)
 */
RCSID("$Id$")

#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/process_types.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/server/cf_util.h>

#include <freeradius-devel/unlang/compile.h>
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/finally.h>
#include <freeradius-devel/unlang/interpret.h>

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/io/listen.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/types.h>
#include <freeradius-devel/util/value.h>

typedef struct {
	module_instance_t		*proto_mi;			//!< The proto_* module for a listen section.
	fr_app_t const			*proto_module;			//!< Public interface to the proto_mi.
									///< cached for convenience.
} virtual_server_listen_t;

struct virtual_server_s {
	CONF_SECTION			*server_cs;			//!< The server section.
	virtual_server_listen_t		**listeners;			//!< Listeners in this virtual server.

	module_instance_t		*process_mi;			//!< The process_* module for a virtual server.
									///< Contains the dictionary used by the virtual
									///< server and the entry point for the state machine.
	fr_process_module_t const	*process_module;		//!< Public interface to the process_mi.
									///< cached for convenience.

	fr_rb_tree_t			*sections;			//!< List of sections that need to be compiled.

	fr_log_t			*log;				//!< log destination
	char const			*log_name;			//!< name of log destination

	void				**finally_by_packet_type;	//!< Finalise instruction by packet type.
	void				*finally_default;		//!< Default finally instruction.
};

static fr_dict_t const *dict_freeradius;

static fr_dict_attr_t const *attr_auth_type;

extern fr_dict_autoload_t virtual_server_dict_autoload[];
fr_dict_autoload_t virtual_server_dict_autoload[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	DICT_AUTOLOAD_TERMINATOR
};

extern fr_dict_attr_autoload_t virtual_server_dict_attr_autoload[];
fr_dict_attr_autoload_t virtual_server_dict_attr_autoload[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	DICT_AUTOLOAD_TERMINATOR
};

/** List of process modules we've loaded
 *
 * This is global for all virtual servers.  Must be initialised
 * _before_ the configuration is loaded.
 */
static module_list_t	*process_modules;

/** List of proto modules we've loaded
 *
 * This is global for all virtual servers.  Must be initialised
 * _before_ the configuration is loaded.
 */
static module_list_t	*proto_modules;

/** Top level structure holding all virtual servers
 *
 */
static virtual_server_t **virtual_servers;

/** CONF_SECTION holding all the virtual servers
 *
 * Set during the call to virtual_server_bootstrap and used by
 * other virtual server functions.
 */
static CONF_SECTION *virtual_server_root;

static fr_rb_tree_t *listen_addr_root = NULL;

static int namespace_on_read(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, conf_parser_t const *rule);

static int namespace_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int listen_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, conf_parser_t const *rule);
static int server_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule);

static const conf_parser_t server_on_read_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("namespace", FR_TYPE_VOID, CONF_FLAG_REQUIRED, virtual_server_t, process_mi),
			.on_read = namespace_on_read },

	CONF_PARSER_TERMINATOR
};

const conf_parser_t virtual_servers_on_read_config[] = {
	/*
	 *	Not really ok if it's missing but we want to
	 *	let logic elsewhere handle the issue.
	 */
	{ FR_CONF_POINTER("server", 0, CONF_FLAG_SUBSECTION | CONF_FLAG_OK_MISSING | CONF_FLAG_MULTI, &virtual_servers),
			  .subcs_size = sizeof(virtual_server_t), .subcs_type = "virtual_server_t",
			  .subcs = (void const *) server_on_read_config, .name2 = CF_IDENT_ANY,
			  .on_read = cf_null_on_read },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t server_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("namespace", FR_TYPE_VOID, CONF_FLAG_REQUIRED, virtual_server_t, process_mi),
			 .func = namespace_parse },

	{ FR_CONF_OFFSET_TYPE_FLAGS("listen", FR_TYPE_VOID, CONF_FLAG_SUBSECTION | CONF_FLAG_OK_MISSING | CONF_FLAG_MULTI,
			 virtual_server_t, listeners),
			 .name2 = CF_IDENT_ANY,
			 .subcs_size = sizeof(virtual_server_listen_t), .subcs_type = "virtual_server_listen_t",
			 .func = listen_parse },

	{ FR_CONF_OFFSET("log", virtual_server_t, log_name), },

	CONF_PARSER_TERMINATOR
};

const conf_parser_t virtual_servers_config[] = {
	/*
	 *	Not really ok if it's missing but we want to
	 *	let logic elsewhere handle the issue.
	 */
	{ FR_CONF_POINTER("server", 0, CONF_FLAG_SUBSECTION | CONF_FLAG_OK_MISSING | CONF_FLAG_MULTI, &virtual_servers),
			  .subcs_size = sizeof(virtual_server_t), .subcs_type = "virtual_server_t",
			  .subcs = (void const *) server_config, .name2 = CF_IDENT_ANY,
			  .func = server_parse },

	CONF_PARSER_TERMINATOR
};

/** Print all the loaded listener instances
 *
 */
void virtual_server_listen_debug(void)
{
	module_list_debug(proto_modules);
}

/** Print all the loaded process module instances
 *
 */
void virtual_server_process_debug(void)
{
	module_list_debug(process_modules);
}

/** Resolve proto data to a module instance
 *
 * @param[in] data	Pointer to the proto data.
 * @return
 *	- The module instance for the proto data.
 *	- NULL if no data matches.
 */
module_instance_t *virtual_server_listener_by_data(void const *data)
{
	return module_instance_by_data(proto_modules, data);
}

/** Generic conf_parser_t func for loading drivers
 *
 */
int virtual_server_listen_transport_parse(TALLOC_CTX *ctx, void *out, void *parent,
					 CONF_ITEM *ci, conf_parser_t const *rule)
{
	conf_parser_t our_rule = *rule;

	our_rule.uctx = &proto_modules;

	return module_submodule_parse(ctx, out, parent, ci, &our_rule);
}

/** Parse a "namespace" parameter
 *
 * We need to load the process module before continuing to parse the virtual server contents
 * as we need to know the namespace so that we can resolve attribute names.
 *
 * We also need the compilation list from the proto module to figure out which sections we
 * need to compile.
 *
 * @param[in] ctx	to allocate data in.
 * @param[out] out	always NULL
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_SECTION containing the listen section.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int namespace_on_read(TALLOC_CTX *ctx, UNUSED void *out, UNUSED void *parent,
			     CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	CONF_PAIR			*cp = cf_item_to_pair(ci);
	CONF_SECTION			*server_cs = cf_item_to_section(cf_parent(ci));
	module_instance_t		*mi;
	char const			*namespace;
	char				*module_name, *p, *end;
	char const			*inst_name;
	fr_process_module_t const	*process;

	fr_cond_assert_msg(process_modules,
			   "virtual_servers_init MUST be called before reading virtual server config");

	namespace = cf_pair_value(cp);
	module_name = talloc_strdup(ctx, namespace);

	/*
	 *	Smush all hyphens to underscores for module names
	 */
	for (p = module_name, end = module_name + talloc_array_length(module_name) - 1;
	     p < end;
	     p++) if (*p == '-') *p = '_';

	if (module_instance_name_from_conf(&inst_name, server_cs) < 0) return -1;

	/*
	 *	The module being loaded is the namespace with all '-'
	 *	transformed to '_'.
	 *
	 *	The instance name is the virtual server name.
	 */
	mi = module_instance_alloc(process_modules, NULL, DL_MODULE_TYPE_PROCESS,
				   module_name, inst_name,
				   0);
	talloc_free(module_name);
	if (mi == NULL) {
	error:
		cf_log_perr(ci, "Failed loading process module");
		return -1;
	}
	if (unlikely(module_instance_conf_parse(mi, mi->conf) < 0)) goto error;

	process = (fr_process_module_t const *)mi->module->exported;
	if (!*(process->dict)) {
		cf_log_err(ci, "Process module is invalid - missing namespace dictionary");
		talloc_free(mi);
		return -1;
	}
	cf_data_add(server_cs, mi, "process_module", false);
	cf_data_add(server_cs, *(process->dict), "dict", false);

	return 0;
}

static inline CC_HINT(always_inline)
int add_compile_list(virtual_server_t *vs, CONF_SECTION *cs, virtual_server_compile_t const *compile_list, char const *name)
{
	int i;
	virtual_server_compile_t const *list = compile_list;

	if (!compile_list) return 0;

	for (i = 0; list[i].section; i++) {
#ifndef NDEBUG
		/*
		 *	We can't have a wildcard for name1.  It MUST be a real name.
		 *
		 *	The wildcard was allowed previously for ideas which later didn't turn out.
		 */
		if (list[i].section->name1 == CF_IDENT_ANY) {
			fr_assert(0);
			continue;
		}

#endif
		if (virtual_server_section_register(vs, &list[i]) < 0) {
			cf_log_err(cs, "Failed registering processing section name %s for %s",
				   list[i].section->name1, name);
			return -1;
		}
	}

	return 0;
}

/** dl_open a process_* module
 *
 * @param[in] ctx	to allocate data in.
 * @param[out] out	Where to our listen configuration.  Is a #fr_virtual_listen_t structure.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_SECTION containing the listen section.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int namespace_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	CONF_PAIR		*cp = cf_item_to_pair(ci);
	CONF_SECTION		*server_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION		*process_cs;
	virtual_server_t	*server = talloc_get_type_abort(((uint8_t *) out) - offsetof(virtual_server_t, process_mi), virtual_server_t);
	char const		*namespace = cf_pair_value(cp);
	module_instance_t	*mi = cf_data_value(cf_data_find(server_cs, module_instance_t, "process_module"));

	/*
	 *	We don't have access to virtual_server_t
	 *	in the onread callback, so we need to do the
	 *	fixups here.
	 */
	server->process_mi = mi;
	server->process_module = (fr_process_module_t const *)mi->module->exported;

	*(module_instance_t const **)out = mi;

	/*
	 *	Enforce that the protocol process configuration is in
	 *	a subsection named for the protocol.
	 */
	process_cs = cf_section_find(server_cs, namespace, NULL);
	if (!process_cs) {
		process_cs = cf_section_alloc(server_cs, server_cs, namespace, NULL);
	}

	if (module_instance_conf_parse(mi, process_cs) < 0) {
		cf_log_perr(ci, "Failed bootstrapping process module");
		cf_data_remove(server_cs, module_instance_t, "process_module");
		cf_data_remove(server_cs, fr_dict_t, "dict");
		TALLOC_FREE(server->process_mi);
		return -1;
	}

	/*
	 *	Pull the list of sections we need to compile out of
	 *	the process module's public struct.
	 */
	add_compile_list(server, server->process_mi->conf, server->process_module->compile_list, namespace);

	return 0;
}

/** dl_open a proto_* module
 *
 * @param[in] ctx	to allocate data in.
 * @param[out] out	Where to our listen configuration.  Is a #fr_virtual_listen_t structure.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_SECTION containing the listen section.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int listen_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	virtual_server_listen_t	*listener = talloc_get_type_abort(out, virtual_server_listen_t); /* Pre-allocated for us */
	CONF_SECTION		*listener_cs = cf_item_to_section(ci);
	CONF_SECTION		*server_cs = cf_item_to_section(cf_parent(ci));
	CONF_PAIR		*namespace = cf_pair_find(server_cs, "namespace");

	CONF_PAIR		*cp;
	char const		*module, *name2, *p;
	fr_sbuff_t		*agg;

	module_instance_t	*mi;

	fr_cond_assert_msg(proto_modules,
			   "virtual_servers_init MUST be called before reading virtual server config");

	if (!namespace) {
		cf_log_err(server_cs, "No 'namespace' set for virtual server");
		cf_log_err(server_cs, "Please add 'namespace = <protocol>' inside of the 'server %s { ... }' section",
			   cf_section_name2(server_cs));
		return -1;
	}

	/*
	 *	The module we load comes from the 'handler' or 'proto' configuration.  This configuration item
	 *	allows us to have multi-protocol listen module, such as "detail".
	 *
	 *	If there isn't a multi-protocol listen module, then load the one for this namespace, such as
	 *	"radius".
	 */
	cp = cf_pair_find(listener_cs, "handler");
	if (!cp) cp = cf_pair_find(listener_cs, "proto");
	if (cp) {
		module = cf_pair_value(cp);
		if (!module) {
			cf_log_err(cp, "Missing value");
			return -1;
		}
	} else {
		module = cf_pair_value(namespace);
	}

	/*
	 *	The proto modules go into a global tree, so we qualify their name (second name) with the name
	 *	of the virtual server, followed by the transport, followed by any transport-specific
	 *	configuration.
	 */
	FR_SBUFF_TALLOC_THREAD_LOCAL(&agg, 64, MODULE_INSTANCE_LEN_MAX);

	name2 = cf_section_name2(listener_cs);

	/*
	 *	A 'listen foo' in this virtual server helps it to be unique.  We load the "radius" module,
	 *	instance "default.foo".  This naming scheme is a little counter-intuitive, but it is required
	 *	due to the listen module list being global, and loading the leading module name e.g. "radius".
	 *
	 *	Since the virtual server names are unique, we don't have to qualify the listen section names
	 *	by anything else.
	 */
	if (name2) {
		/*
		 *	We do some duplicate checks here, because that gives better errors than if we use the
		 *	mangled names below.
		 */
		if (module_instance_name_valid(name2) < 0) {
			cf_log_perr(listener_cs, "Invalid name in 'listen %s'", name2);
			return -1;
		}

		/*
		 *	Load "radius", instance "default.foo".
		 */
		FR_SBUFF_IN_CHAR_RETURN(agg, '.');
		FR_SBUFF_IN_STRCPY_RETURN(agg, name2);
	}

	/*
	 *	Further qualify the name by transport and port.  This helps it to be more unique.
	 */
	cp = cf_pair_find(listener_cs, "transport");
	if (!cp || ((p = cf_pair_value(cp)) == NULL)) {
		cf_log_err(listener_cs, "Invalid 'listen' section - No 'transport = ...' definition was found.");
		return -1;
	}
	FR_SBUFF_IN_CHAR_RETURN(agg, '.');
	FR_SBUFF_IN_STRCPY_RETURN(agg, p);

	cp = cf_pair_find(listener_cs, "port");
	if (cp && ((p = cf_pair_value(cp)) != NULL)) {
		FR_SBUFF_IN_CHAR_RETURN(agg, '.');
		FR_SBUFF_IN_STRCPY_RETURN(agg, p);
	}

	if (module_instance_name_valid(fr_sbuff_start(agg)) < 0) {
		cf_log_perr(listener_cs, "Failed loading listen section.");
		return -1;
	}

	mi = module_instance_alloc(proto_modules, NULL, DL_MODULE_TYPE_PROTO, module, fr_sbuff_start(agg), 0);
	if (!mi) {
		cf_log_perr(listener_cs, "Failed creating listen section");
		return -1;
	}

	if (unlikely(module_instance_conf_parse(mi, listener_cs) < 0)) {
		cf_log_perr(listener_cs, "Failed parsing listen section");
		return -1;
	}

	listener->proto_mi = mi;
	listener->proto_module = (fr_app_t const *)listener->proto_mi->module->exported;
	cf_data_add(listener_cs, mi, "proto_module", false);

	/*
	 *	The listener doesn't have to contain a 'type = foo' configuration.  But if it does, there MUST
	 *	also be a 'recv foo' section.
	 */
	for (cp = cf_pair_find(listener_cs, "type");
	     cp != NULL;
	     cp = cf_pair_find_next(listener_cs, cp, "type")) {
		char const *type = cf_pair_value(cp);

		if (!type) continue;

		if (!cf_section_find(server_cs, "recv", type)) {
			cf_log_err(cp, "Listener has 'type = %s', but there is no 'recv %s { ... }' section defined.",
				   type, type);
			return -1;
		}
	}

	return 0;
}

static int8_t virtual_server_compile_name_cmp(void const *a, void const *b)
{
	virtual_server_compile_t const *sa = a;
	virtual_server_compile_t const *sb = b;

	return section_name_cmp(sa->section, sb->section);
}

/** Callback to validate the server section
 *
 * @param[in] ctx	to allocate data in.
 * @param[out] out	Where to our listen configuration.  Is a #virtual_server_t structure.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_SECTION containing the listen section.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int server_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	virtual_server_t	*server = talloc_get_type_abort(out, virtual_server_t);
	CONF_SECTION		*server_cs = cf_item_to_section(ci);
	CONF_PAIR		*namespace;

	namespace = cf_pair_find(server_cs, "namespace");
	if (!namespace) {
		cf_log_err(server_cs, "virtual server %s MUST contain a 'namespace' option",
			   cf_section_name2(server_cs));
		return -1;
	}

	MEM(server->sections = fr_rb_alloc(server, virtual_server_compile_name_cmp, NULL));
	server->server_cs = server_cs;

	/*
	 *	Now parse the listeners
	 */
	if (cf_section_parse(out, server, server_cs) < 0) return -1;

	/*
	 *	And cache this struct for later referencing.
	 */
	cf_data_add(server_cs, server, NULL, false);

	return 0;
}

/** Return the namespace for the named virtual server
 *
 * @param[in] virtual_server	to look for namespace in.
 * @return
 *	- NULL on error.
 *	- Namespace on success.
 */
fr_dict_t const *virtual_server_dict_by_name(char const *virtual_server)
{
	virtual_server_t const *vs;

	vs = virtual_server_find(virtual_server);
	if (!vs) return NULL;

	return virtual_server_dict_by_cs(vs->server_cs);
}

/** Return the namespace for the virtual server specified by a config section
 *
 * @param[in] server_cs		to look for namespace in.
 * @return
 *	- NULL on error.
 *	- Namespace on success.
 */
fr_dict_t const *virtual_server_dict_by_cs(CONF_SECTION const *server_cs)
{
	CONF_DATA const *cd;
	fr_dict_t *dict;

	cd = cf_data_find(server_cs, fr_dict_t, "dict");
	if (!cd) return NULL;

	dict = cf_data_value(cd);
	(void) talloc_get_type_abort(dict, fr_dict_t);

	return dict;
}

/** Return the namespace for a given virtual server specified by a CONF_ITEM within the virtual server
 *
 * @param[in] ci		to look for namespace in.
 * @return
 *	- NULL on error.
 *	- Namespace on success.
 */
fr_dict_t const *virtual_server_dict_by_child_ci(CONF_ITEM const *ci)
{
	CONF_DATA const *cd;
	fr_dict_t *dict;

	cd = cf_data_find_in_parent(ci, fr_dict_t, "dict");
	if (!cd) return NULL;

	dict = cf_data_value(cd);
	(void) talloc_get_type_abort(dict, fr_dict_t);

	return dict;
}

/** Verify that a given virtual_server exists and is of a particular namespace
 *
 * Mostly used by modules to check virtual servers specified by their configs.
 *
 * @param[out] out		we found. May be NULL if just checking for existence.
 * @param[in] virtual_server	to check.
 * @param[in] namespace		the virtual server must belong to.
 * @param[in] ci		to log errors against. May be NULL if caller
 *				doesn't want errors logged.
 * @return
 *	- 0 on success.
 *	- -1 if no virtual server could be found.
 *	- -2 if virtual server is not of the correct namespace.
 */
int virtual_server_has_namespace(CONF_SECTION **out,
				 char const *virtual_server, fr_dict_t const *namespace, CONF_ITEM *ci)
{
	virtual_server_t const	*vs;
	CONF_SECTION		*server_cs;
	fr_dict_t const		*dict;

	if (out) *out = NULL;

	vs = virtual_server_find(virtual_server);
	if (!vs) {
		if (ci) cf_log_err(ci, "Can't find virtual server \"%s\"", virtual_server);
		return -1;
	}
	server_cs = virtual_server_cs(vs);

	dict = virtual_server_dict_by_name(virtual_server);
	if (!dict) {
		/*
		 *	Not sure this is even a valid state?
		 */
		if (ci) cf_log_err(ci, "No namespace found in virtual server \"%s\"", virtual_server);
		return -2;
	}

	if (dict != namespace) {
		if (ci) {
			cf_log_err(ci,
				   "Expected virtual server \"%s\" to be of namespace \"%s\", got namespace \"%s\"",
				   virtual_server, fr_dict_root(namespace)->name, fr_dict_root(dict)->name);
		}
		return -2;
	}

	if (out) *out = server_cs;

	return 0;
}

/*
 *	If we pushed a log destination, we need to pop it/
 */
static unlang_action_t server_remove_log_destination(UNUSED unlang_result_t *p_result,
						     request_t *request, void *uctx)
{
	virtual_server_t *server = uctx;

	request_log_prepend(request, server->log, L_DBG_LVL_DISABLE);

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static void server_signal_remove_log_destination(request_t *request, UNUSED fr_signal_t action, void *uctx)
{
	virtual_server_t *server = uctx;

	request_log_prepend(request, server->log, L_DBG_LVL_DISABLE);
}

/** Push a finally section onto the stack
 *
 * The finally instruction cannot be cancelled and will always execute as the stack is unwound.
 *
 * @param[in] request		request to push the finally section onto.
 * @param[in] vs		virtual server to push the finally section for.
 * @param[in,out] top_frame	mutate the top frame value to indicate that future
 *				pushes should be subframes.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static inline CC_HINT(always_inline) int virtual_server_push_finally(request_t *request, virtual_server_t const *vs, bool *top_frame)
{
	/*
	 *	Don't bother finding the packet type unless there
	 *	are finally sections registered.
	 */
	if (vs->finally_by_packet_type) {
		fr_pair_t	*vp = fr_pair_find_by_da(&request->request_pairs, NULL,
							 *(vs->process_module->packet_type));
		fr_value_box_t	key;
		void		*instruction;

		if (!vp) goto check_default;	/* No packet type found, still allow default finally section */

		if (fr_value_box_cast(NULL, &key, FR_TYPE_UINT16, NULL, &vp->data) < 0) return -1;

		if (key.vb_uint16 >= talloc_array_length(vs->finally_by_packet_type) ||
		    !(instruction = vs->finally_by_packet_type[key.vb_uint16])) goto check_default;

		if (unlikely(unlang_finally_push_instruction(request, instruction,
							     fr_time_delta_from_sec(5), *top_frame) < 0)) return -1;

		*top_frame = UNLANG_SUB_FRAME;	/* switch to SUB_FRAME after the first instruction */

		return 0;
	}

check_default:
	if (vs->finally_default) {
		if (unlikely(unlang_finally_push_instruction(request, vs->finally_default,
							     fr_time_delta_from_sec(5), *top_frame) < 0)) return -1;

		*top_frame = UNLANG_SUB_FRAME;	/* switch to SUB_FRAME after the first instruction */
	}

	return 0;
}

/** Set the request processing function.
 *
 *	Short-term hack
 */
unlang_action_t virtual_server_push(unlang_result_t *p_result, request_t *request, virtual_server_t const *vs, bool top_frame)
{
	/*
	 *	Add a log destination specific to this virtual server.
	 *
	 *	If we add a log destination, make sure to remove it when we walk back up the stack.
	 *	But ONLY if we're not at the top of the stack.
	 *
	 *	When a brand new request comes in, it has a "call" frame pushed, and then this function is
	 *	called.  So if we're at the top of the stack, we don't need to pop any logging function,
	 *	because the request will die immediately after the top "call" frame is popped.
	 *
	 *	However, if we're being reached from a "call" frame in the middle of the stack, then
	 *	we do have to pop the log destination when we return.
	 */
	if (vs->log) {
		request_log_prepend(request, vs->log, fr_debug_lvl);

		if (unlang_interpret_stack_depth(request) > 1) {
			unlang_action_t action;

			action = unlang_function_push_with_result(unlang_interpret_result(request),	/* transparent */
								  request,
								  NULL, 				/* don't call it immediately */
								  server_remove_log_destination, 	/* but when we pop the frame */
								  server_signal_remove_log_destination, ~(FR_SIGNAL_CANCEL),
								  top_frame,
								  UNCONST(void *, vs));
			if (action != UNLANG_ACTION_PUSHED_CHILD) return action;

			top_frame = UNLANG_SUB_FRAME;	/* switch to SUB_FRAME after the first instruction */
		}
	}

	/*
	 *	Push an uncancellable finally instruction to the stack.
	 */
	if (virtual_server_push_finally(request, vs, &top_frame) < 0) return UNLANG_ACTION_FAIL;

	/*
	 *	Bootstrap the stack with a module instance.
	 */
	if (unlang_module_push(p_result, request, vs->process_mi,
			       vs->process_module->process, top_frame) < 0) return UNLANG_ACTION_FAIL;

	return UNLANG_ACTION_PUSHED_CHILD;
}

static int cmd_show_server_list(FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, UNUSED fr_cmd_info_t const *info)
{
	size_t i, server_cnt = virtual_servers ? talloc_array_length(virtual_servers) : 0;

	if (!server_cnt) return 0;

	for (i = 0; i < server_cnt; i++) {
		fprintf(fp, "%-30snamespace = %s\n", cf_section_name2(virtual_servers[i]->server_cs),
			fr_dict_root(*(virtual_servers[i]->process_module->dict))->name);
	}

	return 0;
}

static fr_cmd_table_t cmd_table[] = {
	{
		.parent = "show",
		.name = "server",
		.help = "Show virtual server settings.",
		.read_only = true,
	},

	{
		.parent = "show server",
		.name = "list",
		.func = cmd_show_server_list,
		.help = "Show the list of virtual servers loaded in the server.",
		.read_only = true,
	},

	CMD_TABLE_END

};

/** Compare listeners by app_io_addr
 *
 *  Only works for IP addresses, and will blow up on file names
 */
static int8_t listen_addr_cmp(void const *one, void const *two)
{
	fr_listen_t const *a = one;
	fr_listen_t const *b = two;
	fr_ipaddr_t aip, bip;
	int ret;

	/*
	 *	The caller must ensure that the address field is set.
	 */
	if (!a->app_io_addr && !b->app_io_addr) return 0;
	if (!a->app_io_addr && b->app_io_addr) return -1;
	if (a->app_io_addr && !b->app_io_addr) return +1;

	/*
	 *	Address family
	 */
	CMP_RETURN(a, b, app_io_addr->af);

	fr_assert((a->app_io_addr->af == AF_INET) || ((a->app_io_addr->af == AF_INET6)));

	/*
	 *	UDP vs TCP
	 */
	CMP_RETURN(a, b, app_io_addr->type);

	/*
	 *	Check ports.
	 */
	CMP_RETURN(a, b, app_io_addr->inet.src_port);

	/*
	 *	Don't call fr_ipaddr_cmp(), as we need to do our own
	 *	checks here.  We have various wildcard checks which
	 *	aren't globally applicable.
	 */

	/*
	 *	Different address families.
	 */
	CMP_RETURN(a, b, app_io_addr->inet.src_ipaddr.af);

	/*
	 *	If both are bound to interfaces, AND the interfaces
	 *	are different, then there is no conflict.
	 */
	if (a->app_io_addr->inet.src_ipaddr.scope_id && b->app_io_addr->inet.src_ipaddr.scope_id) {
		CMP_RETURN(a, b, app_io_addr->inet.src_ipaddr.scope_id);
	}

	ret = a->app_io_addr->inet.src_ipaddr.prefix - b->app_io_addr->inet.src_ipaddr.prefix;
	aip = a->app_io_addr->inet.src_ipaddr;
	bip = b->app_io_addr->inet.src_ipaddr;

	/*
	 *	Mask out the longer prefix to match the shorter
	 *	prefix.
	 */
	if (ret < 0) {
		fr_ipaddr_mask(&bip, a->app_io_addr->inet.src_ipaddr.prefix);

	} else if (ret > 0) {
		fr_ipaddr_mask(&aip, b->app_io_addr->inet.src_ipaddr.prefix);

	}

	return fr_ipaddr_cmp(&aip, &bip);
}

/** See if another global listener is using a particular IP / port
 *
 */
fr_listen_t *listen_find_any(fr_listen_t *li)
{
	if (!listen_addr_root) return NULL;

	return fr_rb_find(listen_addr_root, li);
}


/**  Record that we're listening on a particular IP / port
 *
 */
bool listen_record(fr_listen_t *li)
{
	if (!listen_addr_root) return false;

	if (!li->app_io_addr) return true;

	if (listen_find_any(li) != NULL) return false;

	return fr_rb_insert(listen_addr_root, li);
}

/** Return the configuration section for a virtual server
 *
 * @param[in] vs to return conf section for
 * @return
 *	- The CONF_SECTION of the virtual server.
 */
CONF_SECTION *virtual_server_cs(virtual_server_t const *vs)
{
	return vs->server_cs;
}

/** Resolve a CONF_SECTION to a virtual server
 *
 */
virtual_server_t const *virtual_server_from_cs(CONF_SECTION const *server_cs)
{
	virtual_server_t *vs;

	vs = cf_data_value(cf_data_find(server_cs, virtual_server_t, NULL));
	if (!vs) {
		cf_log_err(server_cs, "server_cs does not contain virtual server data");
		return NULL;
	}

	return vs;
}

/** Return virtual server matching the specified name
 *
 * @note May be called in bootstrap or instantiate as all servers should be present.
 *
 * @param[in] name	of virtual server.
 * @return
 *	- NULL if no virtual server was found.
 *	- The CONF_SECTION of the named virtual server.
 */
virtual_server_t const *virtual_server_find(char const *name)
{
	CONF_SECTION *server_cs = cf_section_find(virtual_server_root, "server", name);
	CONF_DATA const *cd;

	if (unlikely(server_cs == NULL)) return NULL;

	cd = cf_data_find(server_cs, virtual_server_t, NULL);
	if (unlikely(cd == NULL)) return NULL;

	return cf_data_value(cd);
}

/** Find a virtual server using one of its sections
 *
 * @param[in] ci	to find parent virtual server for.
 * @return
 *	- The virtual server section on success.
 *	- NULL if the child isn't associated with any virtual server section.
 */
virtual_server_t const *virtual_server_by_child(CONF_ITEM const *ci)
{
	CONF_SECTION *cs;
	CONF_DATA const *cd;

	cs = cf_section_find_parent(ci, "server", CF_IDENT_ANY);
	if (unlikely(!cs)) {
		cf_log_err(ci, "Child section is not associated with a virtual server");
		return NULL;
	}

	cd = cf_data_find(cs, virtual_server_t, NULL);
	if (unlikely(!cd)) {
		cf_log_err(ci, "Virtual server section missing virtual_server_t data");
		return NULL;
	}

	return cf_data_value(cd);
}

/** Return the packet type attribute for a virtual server specified by a config section
 *
 * @param[in] server_cs		to look for packet type attribute in.
 * @return
 *	- NULL on error.
 *	- packet type dict attr on success.
 */
fr_dict_attr_t const *virtual_server_packet_type_by_cs(CONF_SECTION const *server_cs)
{
	virtual_server_t const *vs = virtual_server_from_cs(server_cs);

	if (unlikely(!vs || !vs->process_module || !vs->process_module->packet_type)) return NULL;
	return *vs->process_module->packet_type;
}

/** Wrapper for the config parser to allow pass1 resolution of virtual servers
 *
 */
int virtual_server_cf_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			    CONF_ITEM *ci, UNUSED conf_parser_t const *rule)
{
	virtual_server_t const *vs;
	virtual_server_cf_parse_uctx_t const *uctx = rule->uctx;

	vs = virtual_server_find(cf_pair_value(cf_item_to_pair(ci)));
	if (!vs) {
		cf_log_err(ci, "virtual-server \"%s\" not found", cf_pair_value(cf_item_to_pair(ci)));
		return -1;
	}

	/*
	 *	Validation checks
	 */
	if (uctx) {
		/*
		 *	Check the module name
		 *
		 *	FIXME: ...at some point in the distance future.  Names
		 *	are icky, we should compare based on dl_module_t, but
		 *	ordering issues make this difficult currently.
		 */
		if (uctx->process_module_name) {
			/* catch users doing stupid things */
			if (strcmp(uctx->process_module_name, vs->process_mi->module->name) != 0) {
				cf_log_err(ci, "virtual server \"%s\" must be of type \"%s\", "
					   "got type \"%s\"",
					   cf_pair_value(cf_item_to_pair(ci)),
					   uctx->process_module_name, vs->process_mi->module->name);
				return -1;
			}
		}

		/*
		 *	It's theoretically possible for the same module to be used
		 *	with multiple namespaces, so we need this check too.
		 */
		if (uctx->required_dict) {
			fr_dict_t *required_dict = *uctx->required_dict;

			if (!fr_cond_assert_msg(required_dict != NULL,
						"dict not resolved before virtual server reference")) {
				goto done;
			}

			if (required_dict != *vs->process_module->dict) {
				cf_log_err(ci, "virtual server \"%s\" must use namespace \"%s\", "
					   "got namespace \"%s\"",
					   cf_pair_value(cf_item_to_pair(ci)),
					   fr_dict_root(required_dict)->name,
					   fr_dict_root(*vs->process_module->dict)->name);
				return -1;
			}
		}
	}

done:
	*((virtual_server_t const **)out) = vs;

	return 0;
}

static inline CC_HINT(always_inline) int virtual_server_compile_finally_sections(virtual_server_t *vs, tmpl_rules_t const *rules, int *found)
{
	static unlang_mod_actions_t const mod_actions_finally = {
		.actions = {
			[RLM_MODULE_REJECT]	= MOD_PRIORITY(3),
			[RLM_MODULE_FAIL]	= MOD_PRIORITY(1),
			[RLM_MODULE_OK]		= MOD_PRIORITY(4),
			[RLM_MODULE_HANDLED]	= MOD_ACTION_RETURN,
			[RLM_MODULE_INVALID]	= MOD_PRIORITY(2),
			[RLM_MODULE_DISALLOW]	= MOD_PRIORITY(5),
			[RLM_MODULE_NOTFOUND]	= MOD_PRIORITY(6),
			[RLM_MODULE_NOOP]	= MOD_PRIORITY(8),
			[RLM_MODULE_UPDATED]	= MOD_PRIORITY(7)
		},
		.retry = RETRY_INIT,
	};

	fr_dict_attr_t const	*da = NULL;
	fr_dict_attr_t const 	**da_p = vs->process_module->packet_type;
	CONF_SECTION		*subcs;

	if (da_p) {
		da = *da_p;
		fr_assert_msg(da != NULL, "Packet-Type attr not resolved");
	}

	/*
	 *	Iterate over all the finally sections, trying to resolve
	 *	the name2 to packet types.
	 */
	for (subcs = cf_section_find(vs->server_cs, "finally", CF_IDENT_ANY);
	     subcs;
	     subcs = cf_section_find_next(vs->server_cs, subcs, "finally", CF_IDENT_ANY)) {
		char const			*packet_type = cf_section_name2(subcs);
		fr_dict_enum_value_t const	*ev;
		fr_value_box_t			key;
		int				ret;
		void				*instruction;

		if (!cf_section_name2(subcs)) {
			if (vs->finally_default) {
				cf_log_err(subcs, "Duplicate 'finally { ... }' section");
				return -1;
			}

			ret = unlang_compile(vs, subcs, &mod_actions_finally, rules, &instruction);
			if (ret < 0) return -1;

			vs->finally_default = instruction;
			(*found)++;

			continue;
		}

		/*
		 *	FIXME: This would allow response packet types too
		 *	We don't have anything that lists request/response
		 *	types, so we can't check that here.
		 */
		ev = fr_dict_enum_by_name(da, packet_type, talloc_strlen(packet_type));
		if (!ev) {
			cf_log_err(subcs, "Invalid 'finally %s { ... }' section, "
					"does not match any Packet-Type value", packet_type);
			return -1;
		}

		/*
		 *	This is... unlikely, as protocols usually use small
		 *	packet types.
		 */
		if (!fr_type_is_integer_except_bool(ev->value->type)) {
		forbid:
			if (da) {
				cf_log_err(subcs, "'finally %s { ... }' section, "
					"not supported for this protocol.  %s is a %s", packet_type,
					da->name, fr_type_to_str(ev->value->type));
			} else {

				cf_log_err(subcs, "'finally %s { ... }' section, "
					"not supported for this protocol", packet_type);
			}
			return -1;
		}

		if (fr_value_box_cast(NULL, &key, FR_TYPE_UINT16, NULL, ev->value) < 0) {
			goto forbid;
		}

		if (key.vb_uint16 > talloc_array_length(vs->finally_by_packet_type)) {
			MEM(vs->finally_by_packet_type = talloc_realloc_zero(vs, vs->finally_by_packet_type,
									     void *, key.vb_uint16 + 1));
		}

		if (vs->finally_by_packet_type[key.vb_uint16]) {
			cf_log_err(subcs, "Duplicate 'finally %s { ... }' section", packet_type);
			return -1;
		}

		ret = unlang_compile(vs, subcs, &mod_actions_finally, rules, &instruction);
		if (ret < 0) return -1;

		vs->finally_by_packet_type[key.vb_uint16] = instruction;

		(*found)++;
	}

	return 0;
}

/** Compile sections for a virtual server.
 *
 *  When the "proto_foo" module calls fr_app_process_instantiate(), it
 *  loads the compile list from the #fr_app_worker_t, and calls this
 *  function.
 *
 *  This function walks down the registration table, compiling each
 *  named section.
 *
 * @param[in] vs	to to compile sections for.
 * @param[in] rules	to apply for pass1.
 */
static int virtual_server_compile_sections(virtual_server_t *vs, tmpl_rules_t const *rules)
{
	virtual_server_compile_t const	*list = vs->process_module->compile_list;
	void				*instance = vs->process_mi->data;
	CONF_SECTION			*server = vs->server_cs;
	int				i, found;
	bool				fail;
	CONF_SECTION			*subcs = NULL;

	found = 0;

	/*
	 *	Complain about v3 things being used in v4.
	 *
	 *	Don't complain when running in normal mode, because the server will just ignore the new
	 *	sections.  But the check_config stuff is generally run before the service starts, and we
	 *	definitely want to tell people when running in debug mode.
	 */
	if (check_config || DEBUG_ENABLED) {
		fail = false;

		while ((subcs = cf_section_next(server, subcs)) != NULL) {
			char const *name;

			if (cf_section_name2(subcs) != NULL) continue;

			name = cf_section_name1(subcs);
			if ((strcmp(name, "authorize") == 0) ||
			    (strcmp(name, "authenticate") == 0) ||
			    (strcmp(name, "post-auth") == 0) ||
			    (strcmp(name, "preacct") == 0) ||
			    (strcmp(name, "accounting") == 0) ||
			    (strcmp(name, "pre-proxy") == 0) ||
			    (strcmp(name, "post-proxy") == 0)) {
				cf_log_err(subcs, "Version 3 processing section '%s' is not valid in version 4.",
					   name);
				fail = true;
			}
		}

		/*
		 *	Complain about _all_ of the sections, and not just the first one.
		 */
		if (fail) return -1;
	}

	/*
	 *	The sections are in trees, so this isn't as bad as it
	 *	looks.  It's not O(n^2), but O(n logn).  But it could
	 *	still be improved.
	 */
	for (i = 0; list[i].section; i++) {
		int rcode;
		CONF_SECTION *bad;

		/*
		 *	We are looking for a specific subsection.
		 *	Warn if it isn't found, or compile it if
		 *	found.
		 */
		if (list[i].section->name2 != CF_IDENT_ANY) {
			void *instruction = NULL;

			subcs = cf_section_find(server, list[i].section->name1, list[i].section->name2);
			if (!subcs) {
				DEBUG3("Warning: Skipping %s %s { ... } as it was not found.",
				       list[i].section->name1, list[i].section->name2);
				/*
				 *	Initialise CONF_SECTION pointer for missing section
				 */
				if ((instance) && !list[i].dont_cache) {
					*(CONF_SECTION **) (((uint8_t *) instance) + list[i].offset) = NULL;
				}
				continue;
			}

			/*
			 *	Duplicate sections are forbidden.
			 */
			bad = cf_section_find_next(server, subcs, list[i].section->name1, list[i].section->name2);
			if (bad) {
			forbidden:
				cf_log_err(bad, "Duplicate sections are forbidden.");
				cf_log_err(subcs, "Previous definition occurs here.");
				return -1;
			}

			rcode = unlang_compile(vs, subcs, list[i].actions, rules, &instruction);
			if (rcode < 0) return -1;

			/*
			 *	Cache the CONF_SECTION which was found.
			 */
			if (instance) {
				if (!list[i].dont_cache) {
					*(CONF_SECTION **) (((uint8_t *) instance) + list[i].offset) = subcs;
				}
				if (list[i].instruction > 0) {
					*(void **) (((uint8_t *) instance) + list[i].instruction) = instruction;
				}
			}

			found++;
			continue;
		}

		/*
		 *	Reset this so that we start from the beginning
		 *	again, instead of starting from the last "send
		 *	foo" block.
		 */
		subcs = NULL;

		/*
		 *	Find all subsections with the given first name
		 *	and compile them.
		 */
		while ((subcs = cf_section_find_next(server, subcs, list[i].section->name1, CF_IDENT_ANY))) {
			char const	*name2;

			name2 = cf_section_name2(subcs);
			if (!name2) {
				cf_log_err(subcs, "Invalid '%s { ... }' section, it must have a name", list[i].section->name1);
				return -1;
			}

			/*
			 *	Duplicate sections are forbidden.
			 */
			bad = cf_section_find_next(server, subcs, list[i].section->name1, name2);
			if (bad) goto forbidden;

			rcode = unlang_compile(vs, subcs, list[i].actions, rules, NULL);
			if (rcode < 0) return -1;

			/*
			 *	Note that we don't store the
			 *	CONF_SECTION here, as it's a wildcard.
			 *
			 *	@todo - count number of subsections
			 *	and store them in an array?
			 */
			found++;
		}
	}

	/*
	 *	Compile finally sections, these are special
	 *	sections and always execute before the request
	 *	exits from the virtual server.
	 */
	if (unlikely(virtual_server_compile_finally_sections(vs, rules, &found) < 0)) {
		cf_log_err(server, "Failed to compile finally sections");
		return -1;
	}

	/*
	 *	Didn't find any processing sections.  Note that we don't count "finally" sections here.  They
	 *	are only run after the packet has been processed through the normal sections.  A virtual
	 *	server with only a "finally" section doesn't make sense.
	 *
	 *	i.e. if people want to accept packets without responding, they need a "recv foo" section which
	 *	contains a "do_not_respond" policy.
	 */
	if (!found) {
		cf_log_err(server, "No processing sections are defined for this virtual server");
		cf_log_err(server, "The server WILL NOT be able to process packets until the configuration is fixed");
		return -1;
	}

	if (!check_config && !DEBUG_ENABLED) return found;

	fail = false;

	/*
	 *	Check for 'send FOO' and 'recv BAR' which are unused.
	 */
	for (subcs = cf_section_first(server);
	     subcs != NULL;
	     subcs = cf_section_next(server, subcs)) {
		char const *name, *name2;

		if (cf_item_is_parsed(subcs)) continue;

		name = cf_section_name1(subcs);

		/*
		 *	Allow them to "comment out" an entire block by prefixing the name with "-", ala
		 *	"-sql".
		 */
		if (*name == '-') continue;

		/*
		 *	Local clients are parsed by the listener after the virtual server is bootstrapped.  So
		 *	we just ignore them here.
		 */
		if (strcmp(name, "client") == 0) continue;

		/*
		 *	When checking the configuration, it is an error to have an unused "send FOO" or "recv
		 *	BAR" section.
		 */
		if (check_config && ((strcmp(name, "recv") == 0) || (strcmp(name, "send") == 0))) {
			cf_log_err(subcs, "Unused processing section %s ... {", name);
			cf_log_err(subcs, "If this is intentional, please rename it to '-%s'", name);
			fail = true;
			continue;
		}

		name2 = cf_section_name2(subcs);
		if (!name2) {
			cf_log_warn(subcs, "Ignoring %s { - it is unused", name);
		} else {
			cf_log_warn(subcs, "Ignoring %s %s { - it is unused", name, name2);
		}
	}

	/*
	 *	Be nice to people, and complaing about ALL unused processing sections.  That way they don't
	 *	have to run the server many, many, times to see all of the errors.
	 */
	if (fail) return -1;

	return found;
}

/** Register name1 / name2 as allowed processing sections
 *
 *  This function is called from the virtual server bootstrap routine,
 *  which happens before module_bootstrap();
 */
int virtual_server_section_register(virtual_server_t *vs, virtual_server_compile_t const *entry)
{
	virtual_server_compile_t *old;

	old = fr_rb_find(vs->sections, entry);
	if (old) return 0;

#ifndef NDEBUG
	/*
	 *	Catch stupid programmers.
	 *
	 *	Processing sections can't allow "*" for module
	 *	methods, because otherwise you would be allowed to run
	 *	DHCP things in a RADIUS accounting section.  And that
	 *	would be bad.
	 */
	if (entry->methods) {
		int i;

		for (i = 0; entry->methods[i]; i++) {
			if (entry->methods[i]->name1 == CF_IDENT_ANY) {
				ERROR("Processing sections cannot allow \"*\"");
				return -1;
			}

			if (entry->methods[i]->name2 == CF_IDENT_ANY) {
				ERROR("Processing sections cannot allow \"%s *\"",
					entry->methods[i]->name1);
				return -1;
			}
		}
	}
#endif

	if (!fr_rb_insert(vs->sections, entry)) {
		fr_strerror_const("Failed inserting entry into internal tree");
		return -1;
	}

	return 0;
}

/** Find the component for a section
 *
 */
section_name_t const **virtual_server_section_methods(virtual_server_t const *vs, section_name_t const *section)
{
	virtual_server_compile_t *entry;

	/*
	 *	Look up the specific name first.  That way we can
	 *	define both "accounting on", and "accounting *".
	 */
	if (section->name2 != CF_IDENT_ANY) {
		entry = fr_rb_find(vs->sections,
				   &(virtual_server_compile_t) {
					.section = section
				   });
		if (entry) return entry->methods;
	}

	/*
	 *	Then look up the wildcard, if we didn't find any matching name2.
	 */
	entry = fr_rb_find(vs->sections,
			   &(virtual_server_compile_t) {
				.section = SECTION_NAME(section->name1, CF_IDENT_ANY)
			   });
	if (!entry) return NULL;

	return entry->methods;
}

/** Define a values for Auth-Type attributes by the sections present in a virtual-server
 *
 * The.name2 value of any sections found will be converted into values of the specified da.
 *
 * @param[in] server_cs		The virtual server containing the sections.
 * @param[in] subcs_name	of the subsection to search for.
 * @param[in] da		to add enumeration values for.
 * @return
 *	- 0 all values added successfully.
 *	- -1 an error occurred.
 */
int virtual_server_section_attribute_define(CONF_SECTION *server_cs, char const *subcs_name, fr_dict_attr_t const *da)
{
	int			rcode = 0;
	CONF_SECTION		*subcs = NULL;

	fr_assert(strcmp(cf_section_name1(server_cs), "server") == 0);

	while ((subcs = cf_section_find_next(server_cs, subcs, subcs_name, CF_IDENT_ANY))) {
		char const	*name2;
		fr_dict_enum_value_t const	*dv;

		name2 = cf_section_name2(subcs);
		if (!name2) {
			cf_log_err(subcs, "Invalid '%s { ... }' section, it must have a name", subcs_name);
			return -1;
		}

		/*
		 *	If the value already exists, don't
		 *	create it again.
		 */
		dv = fr_dict_enum_by_name(da, name2, -1);
		if (dv) continue;

		cf_log_debug(subcs, "Creating %s = %s", da->name, name2);

		/*
		 *	Create a new unique value with a meaningless
		 *	number.  You can't look at it from outside of
		 *	this code, so it doesn't matter.  The only
		 *	requirement is that it's unique.
		 */
		if (fr_dict_enum_add_name_next(fr_dict_attr_unconst(da), name2) < 0) {
			PERROR("Failed adding section value");
			return -1;
		}

		rcode = 1;
	}

	return rcode;
}

static int define_server_values(CONF_SECTION *cs, fr_dict_attr_t *parent)
{
	char const *ref;
	fr_dict_attr_t const *da;
	CONF_ITEM *ci = NULL;

	ref = cf_section_name2(cs);
	if (!ref) {
		cf_log_err(cs, "Expected 'values <name> { ... }'");
		return -1;
	}

	da = fr_dict_attr_by_name(NULL, parent, ref);
	if (!da) {
		cf_log_err(cs, "No such attribute \"%s\"", ref);
		return -1;
	}

	if (fr_type_is_structural(da->type)) {
		cf_log_err(cs, "Cannot define value for structural attribute \"%s\"", ref);
		return -1;
	}

	/*
	 *	This both does not make any sense, and does not get
	 *	parsed correctly if the string contains backslashes.
	 */
	if (da->type == FR_TYPE_STRING) {
		cf_log_err(cs, "Cannot define value for 'string' attribute \"%s\"", ref);
		return -1;
	}

	while ((ci = cf_item_next(cs, ci))) {
		ssize_t slen, len;
		char const *attr, *value;
		CONF_PAIR *cp;
		fr_dict_enum_value_t const *dv;
		fr_value_box_t box;

		if (cf_item_is_section(ci)) {
			cf_log_err(ci, "Unexpected subsection");
			return -1;
		}

		if (!cf_item_is_pair(ci)) continue;

		cp = cf_item_to_pair(ci);
		fr_assert(cp != NULL);

		/*
		 *	=* is a hack by the cf parser to say "no operator"
		 */
		if ((cf_pair_operator(cp) != T_OP_EQ) ||
		    (cf_pair_attr_quote(cp) != T_BARE_WORD)) {
			cf_log_err(ci, "Definition is not in 'name = value' format");
			return -1;
		}

		attr = cf_pair_attr(cp);
		value = cf_pair_value(cp);

		dv = fr_dict_enum_by_name(parent, attr, talloc_array_length(attr) - 1);
		if (dv) {
			cf_log_err(cp, "Duplicate value name");
			return -1;
		}

		fr_value_box_init_null(&box);

		len = talloc_array_length(value) - 1;

		/*
		 *	@todo - unescape for double quoted strings.  Whoops.
		 */
		slen = fr_value_box_from_str(NULL, &box, da->type, da, value, len, NULL);
		if (slen < 0) {
			cf_log_err(cp, "Failed parsing value - %s", fr_strerror());
			return -1;
		}

		if (slen != len) {
			cf_log_err(cp, "Unexpected text after value");
			return -1;
		}

		if (fr_dict_enum_add_name(UNCONST(fr_dict_attr_t *, da), attr, &box, false, false) < 0) {
			cf_log_err(cp, "Failed adding value - %s", fr_strerror());
			return -1;
		}

		fr_value_box_clear(&box);
	}

	return 0;
}


static int define_server_attrs(CONF_SECTION *cs, fr_dict_t *dict, fr_dict_attr_t *parent, fr_dict_attr_t const *root)
{
	CONF_ITEM *ci = NULL;

	fr_dict_attr_flags_t flags = {
		.internal = true,
		.name_only = true,
		.local = true,
	};

	fr_assert(dict != NULL);
	fr_assert(parent != NULL);

	while ((ci = cf_item_next(cs, ci))) {
		fr_type_t type;
		char const *attr, *value;
		CONF_PAIR *cp;
		CONF_SECTION *subcs = NULL;

		if (cf_item_is_section(ci)) {
			subcs = cf_item_to_section(ci);
			fr_assert(subcs != NULL);

			attr = cf_section_name1(subcs);

			if (strcmp(attr, "values") == 0) {
				if (define_server_values(subcs, parent) < 0) return -1;
				continue;
			}

			if (strcmp(attr, "tlv") != 0) goto invalid_type;

			value = cf_section_name2(subcs);
			if (!value) {
				cf_log_err(ci, "Definition is not in 'tlv name { ... }' format");
				return -1;
			}

			type = FR_TYPE_TLV;
			goto check_for_dup;
		}

		if (!cf_item_is_pair(ci)) continue;

		cp = cf_item_to_pair(ci);
		fr_assert(cp != NULL);

		/*
		 *	=* is a hack by the cf parser to say "no operator"
		 */
		if ((cf_pair_operator(cp) != T_OP_CMP_TRUE) ||
		    (cf_pair_attr_quote(cp) != T_BARE_WORD) ||
		    (cf_pair_value_quote(cp) != T_BARE_WORD)) {
			cf_log_err(ci, "Definition is not in 'type name' format");
			return -1;
		}

		attr = cf_pair_attr(cp);
		value = cf_pair_value(cp);

		type = fr_table_value_by_str(fr_type_table, attr, FR_TYPE_NULL);
		if (type == FR_TYPE_NULL) {
		invalid_type:
			cf_log_err(ci, "Invalid data type '%s'", attr);
			return -1;
		}

		/*
		 *	Leaf and group are OK.  TLV, Vendor, Struct, VSA, etc. are not as variable definitions.
		 */
		if (!(fr_type_is_leaf(type) || (type == FR_TYPE_GROUP))) goto invalid_type;

		/*
		 *	No duplicates are allowed.
		 */
	check_for_dup:
		if (root && (fr_dict_attr_by_name(NULL, root, value) != NULL)) {
			cf_log_err(ci, "Local variable '%s' duplicates a dictionary attribute.", value);
			return -1;
		}

		if (fr_dict_attr_by_name(NULL, parent, value) != NULL) {
			cf_log_err(ci, "Local variable '%s' duplicates a previous local attribute.", value);
			return -1;
		}

		if (fr_dict_attr_add_name_only(dict, parent, value, type, &flags) < 0) {
			cf_log_err(ci, "Failed adding local variable '%s' - %s", value, fr_strerror());
			return -1;
		}

		if (type == FR_TYPE_TLV) {
			fr_dict_attr_t const *da;

			if (!subcs) return -1; /* shouldn't happen, but shut up compiler */

			da = fr_dict_attr_by_name(NULL, parent, value);
			fr_assert(da != NULL);

			if (define_server_attrs(subcs, dict, UNCONST(fr_dict_attr_t *, da), NULL) < 0) return -1;
		}
	}

	return 0;
}

static fr_dict_t const *virtual_server_local_dict(CONF_SECTION *server_cs, fr_dict_t const *dict_def)
{
	fr_dict_t *dict;
	CONF_SECTION *cs;

	cs = cf_section_find(server_cs, "dictionary", NULL);
	if (!cs) return dict_def;

	dict = fr_dict_protocol_alloc(dict_def);
	if (!dict) {
		cf_log_err(cs, "Failed allocating local dictionary");
		return NULL;
	}

	if (define_server_attrs(cs, dict, UNCONST(fr_dict_attr_t *, fr_dict_root(dict)), fr_dict_root(dict_def)) < 0) return NULL;

	/*
	 *	Replace the original dictionary with the new one.
	 */
	cf_data_remove(server_cs, fr_dict_t, "dict");
	cf_data_add(server_cs, dict, "dict", false);
	cf_item_mark_parsed(cs);

	return dict;
}


/** Open all the listen sockets
 *
 * @param[in] sc	Scheduler to add I/O paths to.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int virtual_servers_open(fr_schedule_t *sc)
{
	size_t i, server_cnt = virtual_servers ? talloc_array_length(virtual_servers) : 0;
	int opened = 0;

	fr_assert(virtual_servers);

	DEBUG2("#### Opening listener interfaces ####");
	fr_strerror_clear();

	for (i = 0; i < server_cnt; i++) {
		virtual_server_listen_t	**listeners;
		size_t			j, listener_cnt;

		listeners = virtual_servers[i]->listeners;
		listener_cnt = talloc_array_length(listeners);

		for (j = 0; j < listener_cnt; j++) {
			int ret;
			virtual_server_listen_t *listener = listeners[j];

			fr_assert(listener != NULL);
			fr_assert(listener->proto_mi != NULL);
			fr_assert(listener->proto_module != NULL);

			fr_assert(listener->proto_module->open != NULL);

			/*
			 *	The socket is opened with app_instance,
			 *	but all subsequent calls (network.c, etc.) use app_io_instance.
			 *
			 *	The reason is that we call (for example) proto_radius to
			 *	open the socket, and proto_radius is responsible for setting up
			 *	proto_radius_udp, and then calling proto_radius_udp->open.
			 *
			 *	Even then, proto_radius usually calls fr_master_io_listen() in order
			 *	to create the fr_listen_t structure.
			 */

			/*
			 *	Sometimes the open function needs to modify instance
			 *	data, so we need to temporarily remove the protection.
			 */
			module_instance_data_unprotect(listener->proto_mi);
			ret = listener->proto_module->open(listener->proto_mi->data, sc,
							   listener->proto_mi->conf);
			module_instance_data_protect(listener->proto_mi);
			if (unlikely(ret < 0)) {
				cf_log_err(listener->proto_mi->conf,
					   "Failed opening listener %s",
					   listener->proto_module->common.name);
				return -1;
			}

			opened++;

			/*
			 *	Socket information is printed out by
			 *	the socket handlers.  e.g. proto_radius_udp
			 */
			DEBUG3("Opened listener for %s", listener->proto_module->common.name);
		}
	}

	if (!opened) {
		ERROR("There are no 'listen' sections defined.");
		ERROR("Refusing to start, as the server will never process any packets.");
		return -1;
	}

	return 0;
}

/** Free thread-specific data for all process modules and listeners
 *
 */
void virtual_servers_thread_detach(void)
{
	modules_thread_detach(proto_modules);
	modules_thread_detach(process_modules);
}

/** Perform thread instantiation for all process modules and listeners
 *
 */
int virtual_servers_thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el)
{
	if (modules_thread_instantiate(ctx, process_modules, el) < 0) return -1;
	if (modules_thread_instantiate(ctx, proto_modules, el) < 0) {
		modules_thread_detach(process_modules);
		return -1;
	}
	return 0;
}

/** Instantiate all the virtual servers
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int virtual_servers_instantiate(void)
{
	size_t	i, server_cnt;

	/*
	 *	User didn't specify any "server" sections
	 */
	if (unlikely(!virtual_servers)) {
		ERROR("No virtual servers configured");
		return -1;
	}

	server_cnt = talloc_array_length(virtual_servers);

	DEBUG2("#### Instantiating listeners ####");

	if (fr_command_register_hook(NULL, NULL, virtual_server_root, cmd_table) < 0) {
		PERROR("Failed registering radmin commands for virtual servers");
		return -1;
	}

	for (i = 0; i < server_cnt; i++) {
		CONF_ITEM			*ci = NULL;
		CONF_SECTION			*server_cs = virtual_servers[i]->server_cs;
		fr_dict_t const			*dict;
		virtual_server_t		*vs = virtual_servers[i];
		fr_process_module_t const	*process = (fr_process_module_t const *)
							    vs->process_mi->module->exported;

		/*
		 *	Set up logging before doing anything else.
		 */
		if (vs->log_name) {
			vs->log = log_dst_by_name(vs->log_name);
			if (!vs->log) {
				CONF_PAIR *cp = cf_pair_find(server_cs, "log");

				if (cp) {
					cf_log_err(cp, "Unknown log destination '%s'", vs->log_name);
				} else {
					cf_log_err(server_cs, "Unknown log destination '%s'", vs->log_name);
				}

				return -1;
			}
		}

		dict = virtual_server_local_dict(server_cs, *(process)->dict);
		if (!dict) return -1;

		DEBUG("Compiling policies in server %s { ... }", cf_section_name2(server_cs));

		fr_assert(virtual_servers[i]->process_mi);

		/*
		 *	Compile the processing sections indicated by
		 *      the process module.  This must be done before
		 *	module_instantiate is called, as the instance
		 *	data is protected after this call.
		 */
		if (process->compile_list) {
			tmpl_rules_t		parse_rules = {
				.attr = {
					.dict_def = dict,
					.list_def = request_attr_request,
				},

				.literals_safe_for = FR_VALUE_BOX_SAFE_FOR_ANY,
			};

			fr_assert(parse_rules.attr.dict_def != NULL);

			if (virtual_server_compile_sections(virtual_servers[i], &parse_rules) < 0) {
				return -1;
			}
		}

		/*
		 *	Print out warnings for unused "recv" and
		 *	"send" sections.
		 *
		 *	@todo - check against the "compile_list"
		 *	registered for this virtual server, instead of hard-coding stuff.
		 */
		while ((ci = cf_item_next(server_cs, ci))) {
			char const	*name;
			CONF_SECTION	*subcs;

			if (!cf_item_is_section(ci)) continue;

			subcs = cf_item_to_section(ci);
			name = cf_section_name1(subcs);

			/*
			 *	Skip known "other" sections
			 */
			if ((strcmp(name, "listen") == 0) || (strcmp(name, "client") == 0)) continue;

			/*
			 *	For every other section, warn if it hasn't
			 *	been compiled.
			 */
			if (!cf_data_find(subcs, unlang_group_t, NULL)) {
				char const *name2;

				name2 = cf_section_name2(subcs);
				if (!name2) name2 = "";

				cf_log_warn(subcs, "%s %s { ... } section is unused", name, name2);
			}
		}
	}

	if (modules_instantiate(process_modules) < 0) {
		PERROR("Failed instantiating process modules");
		return -1;
	}
	if (modules_instantiate(proto_modules) < 0) {
		PERROR("Failed instantiating protocol modules");
		return -1;
	}

	return 0;
}

/** Load protocol modules and call their bootstrap methods
 *
 * @param[in] config	section containing the virtual servers to bootstrap.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int virtual_servers_bootstrap(CONF_SECTION *config)
{
	virtual_server_root = config;

	/*
	 *	Ensure any libraries the modules depend on are instantiated
	 */
	global_lib_instantiate();

	if (modules_bootstrap(process_modules) < 0) {
		PERROR("Failed instantiating process modules");
		return -1;
	}
	if (modules_bootstrap(proto_modules) < 0) {
		PERROR("Failed instantiating protocol modules");
		return -1;
	}

	return 0;
}

int virtual_servers_free(void)
{
	if (talloc_free(listen_addr_root) < 0) return -1;
	listen_addr_root = NULL;
	if (talloc_free(process_modules) < 0) return -1;
	process_modules = NULL;
	if (talloc_free(proto_modules) < 0) return -1;
	proto_modules = NULL;
	if (fr_dict_autofree(virtual_server_dict_autoload) < 0) return -1;

	return 0;
}

static int _virtual_servers_atexit(UNUSED void *uctx)
{
	return virtual_servers_free();
}

/** Performs global initialisation for the virtual server code
 *
 * This has to be done separately and explicitly, because the above code makes
 * use of "onread" callbacks.
 *
 * Will automatically free module lists on exit, but all modules should have
 * been removed from this list by the point that happens.
 */
int virtual_servers_init(void)
{
	if (fr_dict_autoload(virtual_server_dict_autoload) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}
	if (fr_dict_attr_autoload(virtual_server_dict_attr_autoload) < 0) {
		PERROR("%s", __FUNCTION__);
		fr_dict_autofree(virtual_server_dict_autoload);
		return -1;
	}

	MEM(process_modules = module_list_alloc(NULL, &module_list_type_global, "process", true));

	/*
	 *	FIXME - We should be able to turn on write protection,
	 *	but there are too many proto modules that hang things
	 *	off of their instance data.
	 */
	MEM(proto_modules = module_list_alloc(NULL, &module_list_type_global, "protocol", false));
	MEM(listen_addr_root = fr_rb_inline_alloc(NULL, fr_listen_t, virtual_server_node, listen_addr_cmp, NULL));

	/*
	 *	Create a list to hold all the proto_* modules
	 *	that get loaded during startup.
	 */
	fr_atexit_global(_virtual_servers_atexit, NULL);

	return 0;
}
