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
#include <freeradius-devel/server/command.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/global_lib.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/process.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/virtual_servers.h>

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/io/listen.h>

typedef struct {
	module_instance_t		*proto_mi;		//!< The proto_* module for a listen section.
	fr_app_t const			*proto_module;		//!< Public interface to the proto_mi.
								///< cached for convenience.
} fr_virtual_listen_t;

typedef struct {
	CONF_SECTION			*server_cs;		//!< The server section.
	fr_virtual_listen_t		**listeners;		//!< Listeners in this virtual server.

	module_instance_t		*process_mi;		//!< The process_* module for a virtual server.
								///< Contains the dictionary used by the virtual
								///< server and the entry point for the state machine.
	fr_process_module_t const	*process_module;	//!< Public interface to the process_mi.
								///< cached for convenience.
} fr_virtual_server_t;

static fr_dict_t const *dict_freeradius;

static fr_dict_attr_t const *attr_auth_type;

extern fr_dict_autoload_t virtual_server_dict_autoload[];
fr_dict_autoload_t virtual_server_dict_autoload[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

extern fr_dict_attr_autoload_t virtual_server_dict_attr_autoload[];
fr_dict_attr_autoload_t virtual_server_dict_attr_autoload[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	{ NULL }
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
static fr_virtual_server_t **virtual_servers;

/** CONF_SECTION holding all the virtual servers
 *
 * Set during the call to virtual_server_bootstrap and used by
 * other virtual server functions.
 */
static CONF_SECTION *virtual_server_root;

static fr_rb_tree_t *listen_addr_root = NULL;

/** Lookup allowed section names for modules
 */
static fr_rb_tree_t *server_section_name_tree = NULL;

static int8_t server_section_name_cmp(void const *one, void const *two);

static int namespace_on_read(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int server_on_read(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

static int namespace_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int listen_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int server_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

static const CONF_PARSER server_on_read_config[] = {
	{ FR_CONF_OFFSET("namespace", FR_TYPE_VOID | FR_TYPE_REQUIRED, fr_virtual_server_t, process_mi),
			.on_read = namespace_on_read },

	CONF_PARSER_TERMINATOR
};

const CONF_PARSER virtual_servers_on_read_config[] = {
	/*
	 *	Not really ok if it's missing but we want to
	 *	let logic elsewhere handle the issue.
	 */
	{ FR_CONF_POINTER("server", FR_TYPE_SUBSECTION | FR_TYPE_MULTI | FR_TYPE_OK_MISSING, &virtual_servers),
			  .subcs_size = sizeof(fr_virtual_server_t), .subcs_type = "fr_virtual_server_t",
			  .subcs = (void const *) server_on_read_config, .ident2 = CF_IDENT_ANY,
			  .on_read = server_on_read },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER server_config[] = {
	{ FR_CONF_OFFSET("namespace", FR_TYPE_VOID | FR_TYPE_REQUIRED, fr_virtual_server_t, process_mi),
			 .func = namespace_parse },

	{ FR_CONF_OFFSET("listen", FR_TYPE_SUBSECTION | FR_TYPE_MULTI | FR_TYPE_OK_MISSING,
			 fr_virtual_server_t, listeners),
			 .ident2 = CF_IDENT_ANY,
			 .subcs_size = sizeof(fr_virtual_listen_t), .subcs_type = "fr_virtual_listen_t",
			 .func = listen_parse },

	CONF_PARSER_TERMINATOR
};

const CONF_PARSER virtual_servers_config[] = {
	/*
	 *	Not really ok if it's missing but we want to
	 *	let logic elsewhere handle the issue.
	 */
	{ FR_CONF_POINTER("server", FR_TYPE_SUBSECTION | FR_TYPE_MULTI | FR_TYPE_OK_MISSING, &virtual_servers),
			  .subcs_size = sizeof(fr_virtual_server_t), .subcs_type = "fr_virtual_server_t",
			  .subcs = (void const *) server_config, .ident2 = CF_IDENT_ANY,
			  .func = server_parse },

	CONF_PARSER_TERMINATOR
};

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
			     CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	CONF_PAIR			*cp = cf_item_to_pair(ci);
	CONF_SECTION			*server_cs = cf_item_to_section(cf_parent(ci));
	module_instance_t		*mi;
	char const			*namespace;
	char				*module_name, *p, *end;
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


	/*
	 *	The module being loaded is the namespace with all '-'
	 *	transformed to '_'.
	 *
	 *	The instance name is the virtual server name.
	 */
	mi = module_alloc(process_modules, NULL, DL_MODULE_TYPE_PROCESS,
			  module_name, dl_module_inst_name_from_conf(server_cs));
	talloc_free(module_name);
	if (mi == NULL) {
		cf_log_perr(ci, "Failed loading process module");
		return -1;
	}
	process = (fr_process_module_t const *)mi->dl_inst->module->common;
	if (!*(process->dict)) {
		cf_log_err(ci, "Process module is invalid - missing namespace dictionary");
		talloc_free(mi);
		return -1;
	}
	cf_data_add(server_cs, mi, "process_module", false);

	return 0;
}

/** Callback when a "server" section is created.
 *
 *  This callback exists only as a place-holder to ensure that the
 *  listen_on_read function is called.  The conf file routines won't
 *  recurse into every CONF_PARSER section to check if there's an
 *  "on_read" callback.  So this place-holder is a signal.
 *
 * @param[in] ctx	to allocate data in.
 * @param[out] out	Unused
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_SECTION containing the server section.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int server_on_read(UNUSED TALLOC_CTX *ctx, UNUSED void *out, UNUSED void *parent,
			  UNUSED CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	return 0;
}


static inline CC_HINT(always_inline)
int add_compile_list(CONF_SECTION *cs, virtual_server_compile_t const *compile_list, char const *name)
{
	int i;
	virtual_server_compile_t const *list = compile_list;

	if (!compile_list) return 0;

	for (i = 0; list[i].name != NULL; i++) {
		if (list[i].name == CF_IDENT_ANY) continue;

		if (virtual_server_section_register(&list[i]) < 0) {
			cf_log_err(cs, "Failed registering processing section name %s for %s",
				   list[i].name, name);
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
static int namespace_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	CONF_PAIR		*cp = cf_item_to_pair(ci);
	CONF_SECTION		*server_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION		*process_cs;
	fr_virtual_server_t	*server = talloc_get_type_abort(((uint8_t *) out) - offsetof(fr_virtual_server_t, process_mi), fr_virtual_server_t);
	char const		*namespace = cf_pair_value(cp);
	module_instance_t	*mi = cf_data_value(cf_data_find(server_cs, module_instance_t, "process_module"));

	/*
	 *	We don't have access to fr_virtual_server_t
	 *	in the onread callback, so we need to do the
	 *	fixups here.
	 */
	server->process_mi = mi;
	server->process_module = (fr_process_module_t const *)mi->dl_inst->module->common;

	*(module_instance_t const **)out = mi;

	/*
	 *	Enforce that the protocol process configuration is in
	 *	a subsection named for the protocol.
	 */
	process_cs = cf_section_find(server_cs, namespace, NULL);
	if (!process_cs) {
		process_cs = cf_section_alloc(server_cs, server_cs, namespace, NULL);
	}

	if (module_conf_parse(mi, process_cs) < 0) {
		cf_log_perr(ci, "Failed bootstrapping process module");
		cf_data_remove(server_cs, mi, "process_module");
		TALLOC_FREE(server->process_mi);
		return -1;
	}

	/*
	 *	Pull the list of sections we need to compile out of
	 *	the process module's public struct.
	 */
	add_compile_list(server->process_mi->dl_inst->conf, server->process_module->compile_list, namespace);

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
static int listen_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	fr_virtual_listen_t	*listener = talloc_get_type_abort(out, fr_virtual_listen_t); /* Pre-allocated for us */
	CONF_SECTION		*listener_cs = cf_item_to_section(ci);
	CONF_SECTION		*server_cs = cf_item_to_section(cf_parent(ci));
	CONF_PAIR		*namespace = cf_pair_find(server_cs, "namespace");

	CONF_PAIR		*proto;
	char const		*mod_name;
	char const		*inst_name;
	char			*qual_inst_name;

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
	 *	Module name comes from the 'proto' pair if the
	 *	listen section has one else it comes from the
	 *	namespace of the virtual server.
	 *
	 *	The following results in proto_radius being loaded:
	 *
	 *	server foo {
	 *		namespace = radius
	 *		listen {
	 *
	 *		}
	 *	}
	 *
	 *	The following results in proto_load being loaded:
	 *
	 *	server foo {
	 *		namespace = radius
	 *		listen {
	 *			proto = load
	 *
	 *		}
	 *	}
	 *
	 *	In this way the server behaves reasonably out
	 *	of the box, but allows foreign or generic listeners
	 *	to be included in the server.
	 *
	 */
	proto = cf_pair_find(listener_cs, "proto");
	if (proto) {
		mod_name = cf_pair_value(proto);
	} else {
		mod_name = cf_pair_value(namespace);
	}

	/*
	 *	Inst name comes from the 'listen' name2
	 *	or from the module name.
	 *
	 *	The inst name is qualified with the name
	 *	of the server the listener appears in.
	 *
	 *	The following results in the instance name of 'foo.radius':
	 *
	 *	server foo {
	 *		namespace = radius
	 *		listen {
	 *
	 *		}
	 *	}
	 *
	 *	The following results in the instance name 'foo.my_network':
	 *
	 *	server foo {
	 *		namespace = radius
	 *		listen my_network {
	 *
	 *		}
	 *	}
	 */
	inst_name = cf_section_name2(listener_cs);
	if (!inst_name) inst_name = mod_name;

	qual_inst_name = talloc_asprintf(NULL, "%s.%s", cf_section_name2(server_cs), inst_name);
	mi = module_alloc(proto_modules, NULL, DL_MODULE_TYPE_PROTO, mod_name, qual_inst_name);
	talloc_free(qual_inst_name);
	if (mi == NULL) return -1;

	if (DEBUG_ENABLED4) cf_log_debug(ci, "Loading %s listener into %p", inst_name, out);

	if (module_conf_parse(mi, listener_cs) < 0) {
		cf_log_perr(ci, "Failed parsing config for listener");
		talloc_free(mi);
		return -1;
	}

	listener->proto_mi = mi;
	listener->proto_module = (fr_app_t const *)listener->proto_mi->dl_inst->module->common;
	cf_data_add(listener_cs, mi, "proto_module", false);

	return 0;
}

/** Callback to validate the server section
 *
 * @param[in] ctx	to allocate data in.
 * @param[out] out	Where to our listen configuration.  Is a #fr_virtual_server_t structure.
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_SECTION containing the listen section.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int server_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	fr_virtual_server_t	*server = talloc_get_type_abort(out, fr_virtual_server_t);
	CONF_SECTION		*server_cs = cf_item_to_section(ci);
	CONF_PAIR		*namespace;

	namespace = cf_pair_find(server_cs, "namespace");
	if (!namespace) {
		cf_log_err(server_cs, "virtual server %s MUST contain a 'namespace' option",
			   cf_section_name2(server_cs));
		return -1;
	}

	server->server_cs = server_cs;

	/*
	 *	Now parse the listeners
	 */
	if (cf_section_parse(out, server, server_cs) < 0) return -1;

	/*
	 *	And cache this struct for later referencing.
	 */
	cf_data_add(server_cs, server, "vs", false);

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
	CONF_SECTION const *server_cs;

	server_cs = virtual_server_find(virtual_server);
	if (!server_cs) return NULL;

	return virtual_server_dict_by_cs(server_cs);
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

	cd = cf_data_find(server_cs, module_instance_t, "process_module");
	if (cd) {
		module_instance_t const *mi = cf_data_value(cd);
		fr_process_module_t const *process = (fr_process_module_t const *)mi->module;

		return *(process->dict);
	}
	return NULL;
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

	cd = cf_data_find_in_parent(ci, module_instance_t, "process_module");
	if (cd) {
		module_instance_t const *mi = cf_data_value(cd);
		fr_process_module_t const *process = (fr_process_module_t const *)mi->module;

		return *(process->dict);
	}
	return NULL;
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
	CONF_SECTION	*server_cs;
	fr_dict_t const	*dict;

	if (out) *out = NULL;

	server_cs = virtual_server_find(virtual_server);
	if (!server_cs) {
		if (ci) cf_log_err(ci, "Can't find virtual server \"%s\"", virtual_server);
		return -1;
	}
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

/** Set the request processing function.
 *
 *	Short-term hack
 */
unlang_action_t virtual_server_push(request_t *request, CONF_SECTION *server_cs, bool top_frame)
{
	fr_virtual_server_t *server;

	server = cf_data_value(cf_data_find(server_cs, fr_virtual_server_t, "vs"));
	if (!server) {
		REDEBUG("server_cs does not contain virtual server data");
		return UNLANG_ACTION_FAIL;
	}

	/*
	 *	Bootstrap the stack with a module instance.
	 */
	if (unlang_module_push(&request->rcode, request, server->process_mi,
			       server->process_module->process, top_frame) < 0) return UNLANG_ACTION_FAIL;

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
	 *	UDP vs TCP
	 */
	CMP_RETURN(a, b, app_io_addr->proto);

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
	if (!listen_addr_root) return false;

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

/** Return virtual server matching the specified name
 *
 * @note May be called in bootstrap or instantiate as all servers should be present.
 *
 * @param[in] name	of virtual server.
 * @return
 *	- NULL if no virtual server was found.
 *	- The CONF_SECTION of the named virtual server.
 */
CONF_SECTION *virtual_server_find(char const *name)
{
	return cf_section_find(virtual_server_root, "server", name);
}

/** Find a virtual server using one of its sections
 *
 * @param[in] section	to find parent virtual server for.
 * @return
 *	- The virtual server section on success.
 *	- NULL if the child isn't associated with any virtual server section.
 */
CONF_SECTION *virtual_server_by_child(CONF_SECTION *section)
{
	return cf_section_find_in_parent(section, "server", CF_IDENT_ANY);
}

/** Wrapper for the config parser to allow pass1 resolution of virtual servers
 *
 */
int virtual_server_cf_parse(UNUSED TALLOC_CTX *ctx, void *out, UNUSED void *parent,
			    CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	CONF_SECTION	*server_cs;

	server_cs = virtual_server_find(cf_pair_value(cf_item_to_pair(ci)));
	if (!server_cs) {
		cf_log_err(ci, "virtual-server \"%s\" not found", cf_pair_value(cf_item_to_pair(ci)));
		return -1;
	}

	*((CONF_SECTION **)out) = server_cs;

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
 * @parma[in] server	to search for sections in.
 * @param[in] list	of sections to compiler.
 * @param[in] rules	to apply for pass1.
 * @param[in] instance	module instance data.  The offset value in
 *			the rules array will be added to this to
 *			determine where to write pointers to the
 *			various CONF_SECTIONs.
 */
int virtual_server_compile_sections(CONF_SECTION *server, virtual_server_compile_t const *list, tmpl_rules_t const *rules, void *instance)
{
	int i, found;
	CONF_SECTION *subcs = NULL;

	found = 0;

	/*
	 *	The sections are in trees, so this isn't as bad as it
	 *	looks.  It's not O(n^2), but O(n logn).  But it could
	 *	still be improved.
	 */
	for (i = 0; list[i].name != NULL; i++) {
		int rcode;
		CONF_SECTION *bad;

		/*
		 *	We are looking for a specific subsection.
		 *	Warn if it isn't found, or compile it if
		 *	found.
		 */
		if (list[i].name2 != CF_IDENT_ANY) {
			void *instruction = NULL;

			subcs = cf_section_find(server, list[i].name, list[i].name2);
			if (!subcs) {
				DEBUG3("Warning: Skipping %s %s { ... } as it was not found.",
				       list[i].name, list[i].name2);
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
			bad = cf_section_find_next(server, subcs, list[i].name, list[i].name2);
			if (bad) {
			forbidden:
				cf_log_err(bad, "Duplicate sections are forbidden.");
				cf_log_err(subcs, "Previous definition occurs here.");
				return -1;
			}

			rcode = unlang_compile(subcs, list[i].component, rules, &instruction);
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
		while ((subcs = cf_section_find_next(server, subcs, list[i].name, CF_IDENT_ANY))) {
			char const	*name2;

			name2 = cf_section_name2(subcs);
			if (!name2) {
				cf_log_err(subcs, "Invalid '%s { ... }' section, it must have a name", list[i].name);
				return -1;
			}

			/*
			 *	Duplicate sections are forbidden.
			 */
			bad = cf_section_find_next(server, subcs, list[i].name, name2);
			if (bad) goto forbidden;

			rcode = unlang_compile(subcs, list[i].component, rules, NULL);
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

	return found;
}

static int8_t server_section_name_cmp(void const *one, void const *two)
{
	virtual_server_compile_t const *a = one;
	virtual_server_compile_t const *b = two;
	int ret;

	ret = strcmp(a->name, b->name);
	ret = CMP(ret, 0);
	if (ret != 0) return ret;

	if (a->name2 == b->name2) return 0;
	if ((a->name2 == CF_IDENT_ANY) && (b->name2 != CF_IDENT_ANY)) return -1;
	if ((a->name2 != CF_IDENT_ANY) && (b->name2 == CF_IDENT_ANY)) return +1;

	ret = strcmp(a->name2, b->name2);
	return CMP(ret, 0);
}

/** Register name1 / name2 as allowed processing sections
 *
 *  This function is called from the virtual server bootstrap routine,
 *  which happens before module_bootstrap();
 */
int virtual_server_section_register(virtual_server_compile_t const *entry)
{
	virtual_server_compile_t *old;

	fr_assert(server_section_name_tree != NULL);

	old = fr_rb_find(server_section_name_tree, entry);
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

		for (i = 0; entry->methods[i].name != NULL; i++) {
			if (entry->methods[i].name == CF_IDENT_ANY) {
				ERROR("Processing sections cannot allow \"*\"");
				return -1;
			}

			if (entry->methods[i].name2 == CF_IDENT_ANY) {
				ERROR("Processing sections cannot allow \"%s *\"",
					entry->methods[i].name);
				return -1;
			}
		}
	}
#endif

	if (!fr_rb_insert(server_section_name_tree, entry)) {
		fr_strerror_const("Failed inserting entry into internal tree");
		return -1;
	}

	return 0;
}

/** Find the component for a section
 *
 */
virtual_server_method_t const *virtual_server_section_methods(char const *name1, char const *name2)
{
	virtual_server_compile_t *entry;

	fr_assert(server_section_name_tree != NULL);

	/*
	 *	Look up the specific name first.  That way we can
	 *	define both "accounting on", and "accounting *".
	 */
	if (name2 != CF_IDENT_ANY) {
		entry = fr_rb_find(server_section_name_tree,
					&(virtual_server_compile_t) {
						.name = name1,
						.name2 = name2,
					});
		if (entry) return entry->methods;
	}

	/*
	 *	Then look up the wildcard, if we didn't find any matching name2.
	 */
	entry = fr_rb_find(server_section_name_tree,
				&(virtual_server_compile_t) {
					.name = name1,
					.name2 = CF_IDENT_ANY,
				});
	if (!entry) return NULL;

	return entry->methods;
}

/** Define a values for Auth-Type attributes by the sections present in a virtual-server
 *
 * The ident2 value of any sections found will be converted into values of the specified da.
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
		fr_dict_enum_value_t	*dv;

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

	fr_assert(virtual_servers);

	DEBUG2("#### Opening listener interfaces ####");
	fr_strerror_clear();

	for (i = 0; i < server_cnt; i++) {
		fr_virtual_listen_t	**listeners;
		size_t			j, listener_cnt;

 		listeners = virtual_servers[i]->listeners;
 		listener_cnt = talloc_array_length(listeners);

		for (j = 0; j < listener_cnt; j++) {
			fr_virtual_listen_t *listener = listeners[j];

			fr_assert(listener != NULL);
			fr_assert(listener->proto_mi != NULL);
			fr_assert(listener->proto_module != NULL);

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
			if (listener->proto_module->open &&
			    listener->proto_module->open(listener->proto_mi->dl_inst->data, sc,
			    				 listener->proto_mi->dl_inst->conf) < 0) {
				cf_log_err(listener->proto_mi->dl_inst->conf,
					   "Opening %s I/O interface failed",
					   listener->proto_module->common.name);
				return -1;
			}

			/*
			 *	Socket information is printed out by
			 *	the socket handlers.  e.g. proto_radius_udp
			 */
			DEBUG3("Opened listener for %s", listener->proto_module->common.name);
		}
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
	size_t	i, server_cnt = virtual_servers ? talloc_array_length(virtual_servers) : 0;

	fr_assert(virtual_servers);

	DEBUG2("#### Instantiating listeners ####");

	if (fr_command_register_hook(NULL, NULL, virtual_server_root, cmd_table) < 0) {
		PERROR("Failed registering radmin commands for virtual servers");
		return -1;
	}

	for (i = 0; i < server_cnt; i++) {
		fr_virtual_listen_t		**listeners;
		size_t				j, listener_cnt;
		CONF_ITEM			*ci = NULL;
		CONF_SECTION			*server_cs = virtual_servers[i]->server_cs;
		fr_virtual_server_t const	*vs = virtual_servers[i];
		fr_process_module_t const	*process = (fr_process_module_t const *)
							    vs->process_mi->dl_inst->module->common;
 		listeners = virtual_servers[i]->listeners;
 		listener_cnt = talloc_array_length(listeners);

		DEBUG("Compiling policies in server %s { ... }", cf_section_name2(server_cs));

		for (j = 0; j < listener_cnt; j++) {
			fr_virtual_listen_t *listener = listeners[j];

			fr_assert(listener != NULL);
			fr_assert(listener->proto_mi != NULL);
			fr_assert(listener->proto_module != NULL);

			if (module_instantiate(listener->proto_mi) < 0) {
				cf_log_perr(listener->proto_mi->dl_inst->conf,
					    "Failed instantiating listener");
				return -1;
			}
		}

		fr_assert(virtual_servers[i]->process_mi);

		/*
		 *	Complete final instantiation of the process module
		 */
		if (module_instantiate(virtual_servers[i]->process_mi) < 0) {
			cf_log_perr(virtual_servers[i]->process_mi->dl_inst->conf,
				    "Failed instantiating process module");
			return -1;
		}

		/*
		 *	Compile the processing sections indicated by
		 *      the process module.
		 */
		if (process->compile_list) {
			tmpl_rules_t		parse_rules;

			memset(&parse_rules, 0, sizeof(parse_rules));
 			parse_rules.attr.dict_def = *(process->dict);
			fr_assert(parse_rules.attr.dict_def != NULL);

			if (virtual_server_compile_sections(server_cs, process->compile_list, &parse_rules,
							    vs->process_mi->dl_inst->data) < 0) {
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

	if (modules_bootstrap(process_modules) < 0) return -1;
	if (modules_bootstrap(proto_modules) < 0) return -1;

	return 0;
}

int virtual_servers_free(void)
{
	if (talloc_free(listen_addr_root) < 0) return -1;
	listen_addr_root = NULL;
	if (talloc_free(server_section_name_tree) < 0) return -1;
	server_section_name_tree = NULL;
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

	MEM(process_modules = module_list_alloc(NULL, "process"));
	MEM(proto_modules = module_list_alloc(NULL, "protocol"));
	MEM(listen_addr_root = fr_rb_inline_alloc(NULL, fr_listen_t, virtual_server_node, listen_addr_cmp, NULL));
	MEM(server_section_name_tree = fr_rb_alloc(NULL, server_section_name_cmp, NULL));

	/*
	 *	Create a list to hold all the proto_* modules
	 *	that get loaded during startup.
	 */
	fr_atexit_global(_virtual_servers_atexit, NULL);

	return 0;
}
