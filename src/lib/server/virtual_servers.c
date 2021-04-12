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

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/command.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/cond.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/process.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/io/listen.h>

#include <freeradius-devel/unlang/base.h>

typedef struct {
	fr_rb_node_t		node;			//!< Entry in the namespace tree.
	char const		*namespace;		//!< Namespace function is registered to.
	fr_dict_t const		*dict;			//!< dictionary to use
	fr_virtual_server_compile_t	func;		//!< Function to call to compile sections.
} fr_virtual_namespace_t;

typedef struct {
	dl_module_inst_t	*proto_module;		//!< The proto_* module for a listen section.
	fr_app_t const		*app;			//!< Easy access to the exported struct.
} fr_virtual_listen_t;

typedef struct {
	CONF_SECTION		*server_cs;		//!< The server section.
	char const		*namespace;		//!< Protocol namespace
	fr_virtual_listen_t	**listener;		//!< Listeners in this virtual server.
	dl_module_inst_t	*process_module;	//!< the process_* module for a virtual server
	dl_module_inst_t	*dynamic_client_module;	//!< the process_* module for a dynamic client
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

static rbtree_t *listen_addr_root = NULL;

/** Lookup allowed section names for modules
 */
static rbtree_t *server_section_name_tree = NULL;

static int server_section_name_cmp(void const *one, void const *two);

static int namespace_on_read(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int listen_on_read(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int server_on_read(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

static int namespace_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int listen_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int server_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

static const CONF_PARSER server_on_read_config[] = {
	{ FR_CONF_OFFSET("namespace", FR_TYPE_STRING | FR_TYPE_REQUIRED, fr_virtual_server_t, namespace),
			.on_read = namespace_on_read },

	{ FR_CONF_OFFSET("listen", FR_TYPE_SUBSECTION | FR_TYPE_MULTI | FR_TYPE_OK_MISSING,
			 fr_virtual_server_t, listener),
			 .ident2 = CF_IDENT_ANY,
			 .subcs_size = sizeof(fr_virtual_listen_t), .subcs_type = "fr_virtual_listen_t",
			 .on_read = listen_on_read },

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
	{ FR_CONF_OFFSET("namespace", FR_TYPE_STRING | FR_TYPE_REQUIRED, fr_virtual_server_t, namespace),
			 .func = namespace_parse },

	{ FR_CONF_OFFSET("listen", FR_TYPE_SUBSECTION | FR_TYPE_MULTI | FR_TYPE_OK_MISSING,
			 fr_virtual_server_t, listener),
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

typedef struct {
	fr_dict_t const		*dict;
	char const		*server;
} virtual_server_dict_t;

/** Decrement references on dictionaries as the config sections are freed
 *
 */
static int _virtual_server_dict_free(virtual_server_dict_t *cd)
{
	fr_dict_const_free(&cd->dict, cd->server);
	return 0;
}


void virtual_server_dict_set(CONF_SECTION *server_cs, fr_dict_t const *dict, bool reference)
{
	virtual_server_dict_t *p;
	CONF_DATA const *cd;

	cd = cf_data_find(server_cs, virtual_server_dict_t, "dictionary");
	if (cd) {
		p = (virtual_server_dict_t *) cf_data_value(cd);
		if (p->dict == dict) return;

		cf_log_warn(server_cs, "Attempt to add multiple different dictionaries %s and %s",
			    fr_dict_root(p->dict)->name, fr_dict_root(dict)->name);
		return;
	}

	p = talloc_zero(server_cs, virtual_server_dict_t);
	p->dict = dict;
	p->server = talloc_strdup(p, cf_section_name2(server_cs));
	talloc_set_destructor(p, _virtual_server_dict_free);

	if (reference) fr_dict_dependent_add(fr_dict_unconst(dict), p->server);

	cf_data_add(server_cs, p, "dictionary", true);
}

fr_dict_t const *virtual_server_dict(CONF_SECTION *server_cs)
{
	virtual_server_dict_t *p;
	CONF_DATA const *cd;

	cd = cf_data_find(server_cs, virtual_server_dict_t, "dictionary");
	if (cd) {
		p = (virtual_server_dict_t *) cf_data_value(cd);
		return p->dict;
	}
	return NULL;
}

/** Parse a "namespace" parameter.
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
	CONF_PAIR		*cp = cf_item_to_pair(ci);
	CONF_SECTION		*server_cs = cf_item_to_section(cf_parent(ci));
	char const		*namespace = cf_pair_value(cp);
	char const		*file;
	char const		*dir = NULL;
	fr_dict_t		*dict;
	dl_module_t const      	*module;
	char			*module_name, *p, *end;

	if (!namespace || !*namespace) {
		cf_log_err(ci, "Missing value for 'namespace'");
		return -1;
	}

	/*
	 *	The "control" socket does not have a dictionary.
	 */
	if (strcmp(namespace, "control") == 0) {
		dict = fr_dict_unconst(fr_dict_internal());
		goto set;
	}

	file = namespace;	/* the default */

	/*
	 *	These are all equivalent.  Rewrite the names to be our
	 *	canonical version.
	 */
	if ((strcmp(namespace, "eap-aka-prime") == 0) ||
	    (strcmp(namespace, "eap-aka") == 0) ||
	    (strcmp(namespace, "eap-sim") == 0)) {
		dir = "eap/aka-sim";
		file = "eap-aka-sim";
	}

	/*
	 *	@todo - print out the entire error stack?
	 */
	if (fr_dict_protocol_afrom_file(&dict, file, dir, cf_section_name2(server_cs)) < 0) {
		cf_log_perr(ci, "Failed loading namespace '%s'", namespace);
		return -1;
	}

set:
	virtual_server_dict_set(server_cs, dict, false);

	module_name = talloc_strdup(ctx, namespace);

	/*
	 *	Smush all hyphens to underscores for module names
	 */
	for (p = module_name, end = module_name + talloc_array_length(module_name) - 1;
	     p < end;
	     p++) if (*p == '-') *p = '_';

	/*
	 *	Pass server_cs, even though it's wrong.  We don't have
	 *	anything else to pass, and the dl_module() function
	 *	only uses the CONF_SECTION for printing.
	 */
	module = dl_module(server_cs, NULL, module_name, DL_MODULE_TYPE_PROCESS);
	talloc_free(module_name);
#ifndef NDEBUG
	if (module) {
		fr_process_module_t const *process = (fr_process_module_t const *) module->common;

		/*
		 *	It MUST have the same dictionary as the
		 *	namespace.
		 *
		 *	@todo - once we have process functions for all
		 *	state machines, remove the code just above
		 *	which manually loads the dictionary.  And
		 *	instead set the dictionary from *process->dict.
		 */
		fr_assert(process->dict);
		fr_assert(*process->dict == dict);
	}
#endif
	if (!module) {
		cf_log_perr(ci, "Failed loading process module");
		return -1;
	}

	cf_data_add(server_cs, module, "process module", true);

	return 0;
}

/** dl_open a proto_* module
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
static int listen_on_read(UNUSED TALLOC_CTX *ctx, UNUSED void *out, UNUSED void *parent,
			  CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	CONF_SECTION		*listen_cs = cf_item_to_section(ci);
	CONF_SECTION		*server_cs = cf_item_to_section(cf_parent(ci));
	CONF_PAIR		*namespace = cf_pair_find(server_cs, "namespace");
	char const		*value;
	dl_module_t const	*module;
	fr_app_t const		*app;
	bool			set_dict;

	if (!namespace) {
		cf_log_err(server_cs, "No 'namespace' set for virtual server");
		cf_log_err(server_cs, "Please add 'namespace = <protocol>' inside of the 'server %s { ... }' section",
			   cf_section_name2(server_cs));
		return -1;
	}

	value = cf_section_name2(listen_cs);
	if (value) {
		set_dict = false;


	} else {
		value = cf_pair_value(namespace);
		fr_assert(value);
		set_dict = true;

	}

	if (DEBUG_ENABLED4) cf_log_debug(ci, "Loading proto_%s", value);
	module = dl_module(listen_cs, NULL, value, DL_MODULE_TYPE_PROTO);
	if (!module) {
		cf_log_err(listen_cs, "Failed loading proto_%s module", value);
		return -1;
	}
	cf_data_add(listen_cs, module, "proto module", true);

	if (!set_dict) return 0;

	app = (fr_app_t const *) module->common;
	if (app->dict) virtual_server_dict_set(server_cs, *app->dict, true);

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
static int namespace_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	CONF_SECTION		*server_cs = cf_item_to_section(cf_parent(ci));
	CONF_SECTION		*process_cs;
	char const		*namespace = cf_pair_value(cf_item_to_pair(ci));
	char			*module_name = talloc_strdup(ctx, namespace);
	char			*p, *end;
	fr_virtual_server_t	*server = (fr_virtual_server_t *) (((uint8_t *) out) - offsetof(fr_virtual_server_t, namespace));
	int			ret;

	(void) talloc_get_type_abort(server, fr_virtual_server_t);
	fr_assert(namespace != NULL);

	server->namespace = namespace;

	if (DEBUG_ENABLED4) cf_log_debug(ci, "Loading process %s into %p", namespace, out);

	/*
	 *	Enforce that the protocol process configuration is in
	 *	a subsection named for the protocol.
	 */
	process_cs = cf_section_find(server_cs, namespace, NULL);
	if (!process_cs) {
		process_cs = cf_section_alloc(server_cs, server_cs, namespace, NULL);
	}

	/*
	 *	Smush all hyphens to underscores for module names
	 */
	for (p = module_name, end = module_name + talloc_array_length(module_name) - 1;
	     p < end;
	     p++) if (*p == '-') *p = '_';

	/*
	 *	We now require a process module for everything.
	 */
	ret = dl_module_instance(ctx, &server->process_module, process_cs, NULL, module_name, DL_MODULE_TYPE_PROCESS);
	talloc_free(module_name);
	if (ret < 0) {
		cf_log_warn(server_cs, "Failed loading process module");
		return -1;
	}

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
static int listen_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	fr_virtual_listen_t	*listen = talloc_get_type_abort(out, fr_virtual_listen_t); /* Pre-allocated for us */
	CONF_SECTION		*listen_cs = cf_item_to_section(ci);
	CONF_SECTION		*server_cs = cf_item_to_section(cf_parent(ci));
	CONF_PAIR		*namespace = cf_pair_find(server_cs, "namespace");
	char const		*value;

	value = cf_section_name2(listen_cs);
	if (!value) value = cf_pair_value(namespace);

	if (DEBUG_ENABLED4) cf_log_debug(ci, "Loading %s listener into %p", value, out);

	if (dl_module_instance(ctx, &listen->proto_module, listen_cs, NULL, value, DL_MODULE_TYPE_PROTO) < 0) {
		cf_log_err(listen_cs, "Failed loading proto module");
		return -1;
	}

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
	server->namespace = cf_pair_value(namespace);

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

/** Set the request processing function.
 *
 *	Short-term hack
 */
int virtual_server_push(request_t *request, CONF_SECTION *server_cs, bool top_frame)
{
	fr_virtual_server_t *server;
	fr_process_module_t const *process;
	fr_io_track_t *track = request->async->packet_ctx;
	module_instance_t *mi = talloc_zero(request, module_instance_t);

	server = cf_data_value(cf_data_find(server_cs, fr_virtual_server_t, "vs"));
	if (!server) {
		REDEBUG("server_cs does not contain virtual server data");
		return -1;
	}

	mi->name = server->process_module->name;
	mi->module = (module_t *)server->process_module;
	mi->number = 0;	/* Hacky hack hack */

	if (unlikely(track && track->dynamic && server->dynamic_client_module)) {
		process = (fr_process_module_t const *) server->dynamic_client_module->module->common;
		mi->dl_inst = server->dynamic_client_module;

	} else {
		process = (fr_process_module_t const *) server->process_module->module->common;
		mi->dl_inst = server->process_module;
	}

	mi->instantiated = true;

	/*
	 *	Bootstrap the stack with a module instance.
	 *
	 *	@todo - src/lib/unlang/module.c calls module_thread(),
	 *	which looks up mi->number in various data structures.
	 *	It's probably best to initialize instance_num=1 in
	 *	src/lib/server/module.c, that reserves 0 for "nothing
	 *	is initialized".
	 */
	if (unlang_module_push(&request->rcode, request, mi, process->process, top_frame) < 0) return -1;

	return 0;
}

/** Allow dynamic clients in this virtual server.
 *
 *	Short-term hack
*/
int virtual_server_dynamic_clients_allow(CONF_SECTION *server_cs)
{
	fr_virtual_server_t *server;

	server = cf_data_value(cf_data_find(server_cs, fr_virtual_server_t, "vs"));
	if (server->dynamic_client_module) return 0;

	if (dl_module_instance(server_cs, &server->dynamic_client_module, server_cs, NULL, "dynamic_client", DL_MODULE_TYPE_PROCESS) < 0) {
		cf_log_err(server_cs, "Failed loading dynamic client module");
		return -1;
	}

	return 0;
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
		fr_dict_enum_t	*dv;

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


static int cmd_show_server_list(FILE *fp, UNUSED FILE *fp_err, UNUSED void *ctx, UNUSED fr_cmd_info_t const *info)
{
	size_t i, server_cnt = virtual_servers ? talloc_array_length(virtual_servers) : 0;

	if (!server_cnt) return 0;

	for (i = 0; i < server_cnt; i++) {
		fprintf(fp, "%-30snamespace = %s\n", cf_section_name2(virtual_servers[i]->server_cs),
			virtual_servers[i]->namespace);
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
static int listen_addr_cmp(void const *one, void const *two)
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
	CMP_RETURN(app_io_addr->proto);

	/*
	 *	Check ports.
	 */
	CMP_RETURN(app_io_addr->inet.src_port);

	/*
	 *	Don't call fr_ipaddr_cmp(), as we need to do our own
	 *	checks here.  We have various wildcard checks which
	 *	aren't globally applicable.
	 */

	/*
	 *	Different address families.
	 */
	CMP_RETURN(app_io_addr->inet.src_ipaddr.af);

	/*
	 *	If both are bound to interfaces, AND the interfaces
	 *	are different, then there is no conflict.
	 */
	if (a->app_io_addr->inet.src_ipaddr.scope_id && b->app_io_addr->inet.src_ipaddr.scope_id) {
		CMP_RETURN(app_io_addr->inet.src_ipaddr.scope_id);
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

	return rbtree_find(listen_addr_root, li);
}


/**  Record that we're listening on a particular IP / port
 *
 */
bool listen_record(fr_listen_t *li)
{
	if (!listen_addr_root) return false;

	if (!li->app_io_addr) return true;

	if (listen_find_any(li) != NULL) return false;

	return rbtree_insert(listen_addr_root, li);
}

static int process_instantiate(CONF_SECTION *server_cs, dl_module_inst_t *dl_inst, fr_dict_t const *dict)
{
	fr_process_module_t const *process = (fr_process_module_t const *) dl_inst->module->common;

	if (process->instantiate &&
	    (process->instantiate(dl_inst->data, dl_inst->conf) < 0)) {
		cf_log_err(dl_inst->conf, "Instantiate failed");
		return -1;
	}

	/*
	 *	Compile the processing sections.
	 */
	if (process->compile_list) {
		tmpl_rules_t		parse_rules;

		memset(&parse_rules, 0, sizeof(parse_rules));
		parse_rules.dict_def = dict;
		fr_assert(parse_rules.dict_def != NULL);

		if (virtual_server_compile_sections(server_cs, process->compile_list, &parse_rules,
						    dl_inst->data) < 0) {
			return -1;
		}
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
	size_t		i, server_cnt = virtual_servers ? talloc_array_length(virtual_servers) : 0;
	rbtree_t	*vns_tree = cf_data_value(cf_data_find(virtual_server_root, rbtree_t, "vns_tree"));

	fr_assert(virtual_servers);

	DEBUG2("#### Instantiating listeners ####");

	if (fr_command_register_hook(NULL, NULL, virtual_server_root, cmd_table) < 0) {
		PERROR("Failed registering radmin commands for virtual servers");
		return -1;
	}

	for (i = 0; i < server_cnt; i++) {
		fr_virtual_listen_t	**listener;
		size_t			j, listen_cnt;
		CONF_ITEM		*ci = NULL;
		CONF_SECTION		*server_cs = virtual_servers[i]->server_cs;
		CONF_DATA const		*cd;
		virtual_server_dict_t	*dict = NULL;

		cd = cf_data_find(server_cs, virtual_server_dict_t, "dictionary");
		if (cd) {	/* only NULl for the control socket */
			dict = (virtual_server_dict_t *) cf_data_value(cd);
			fr_assert(dict != NULL);
		}

 		listener = virtual_servers[i]->listener;
 		listen_cnt = talloc_array_length(listener);

		DEBUG("Compiling policies in server %s { ... }", cf_section_name2(server_cs));

		fr_assert(virtual_servers[i]->namespace != NULL);

		/*
		 *	Compile EAP-AKA, SIM, etc.  This code is a
		 *	place-holder until such time as the
		 *	process_foo() modules are done.
		 */
		if (vns_tree) {
			fr_virtual_namespace_t	find = { .namespace = virtual_servers[i]->namespace };
			fr_virtual_namespace_t	*found;

			found = rbtree_find(vns_tree, &find);
			if (found) {
				fr_assert(dict && (dict->dict == found->dict));

				if (found->func(server_cs) < 0) return -1;
			}
		}

		for (j = 0; j < listen_cnt; j++) {
			fr_virtual_listen_t *listen = listener[j];

			fr_assert(listen != NULL);
			fr_assert(listen->proto_module != NULL);
			fr_assert(listen->app != NULL);

			if (listen->app->instantiate &&
			    listen->app->instantiate(listen->proto_module->data, listen->proto_module->conf) < 0) {
				cf_log_err(listen->proto_module->conf, "Could not load virtual server \"%s\".",
					    cf_section_name2(server_cs));
				return -1;
			}
		}

		fr_assert(virtual_servers[i]->process_module);

		if (!dict) {
			cf_log_err(server_cs, "No dictionary for namespace %s", virtual_servers[i]->namespace);
			return -1; /* should never happen */
		}

		if (process_instantiate(server_cs, virtual_servers[i]->process_module, dict->dict) < 0) return -1;

		if (virtual_servers[i]->dynamic_client_module &&
		    (process_instantiate(server_cs, virtual_servers[i]->dynamic_client_module, dict->dict) < 0)) return -1;

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

static int add_compile_list(CONF_SECTION *cs, virtual_server_compile_t const *compile_list, char const *name)
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

static int process_bootstrap(dl_module_inst_t *dl_inst, char const *namespace)
{
	fr_process_module_t const *process = (fr_process_module_t const *) dl_inst->module->common;

	if (process->bootstrap &&
	    (process->bootstrap(dl_inst->data,
				dl_inst->conf) < 0)) {
		cf_log_err(dl_inst->conf, "Bootstrap failed");
		return -1;
	}

	return add_compile_list(dl_inst->conf, process->compile_list, namespace);
}

/** Load protocol modules and call their bootstrap methods
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int virtual_servers_bootstrap(CONF_SECTION *config)
{
	size_t i, server_cnt = 0;
	CONF_SECTION *cs = NULL;

	if (!virtual_servers) {
		ERROR("No server { ... } sections found");
		return -1;
	}

	/*
	 *	Check the talloc hierarchy is sane
	 */
	talloc_get_type_abort(virtual_servers, fr_virtual_server_t *);
	server_cnt = talloc_array_length(virtual_servers);

	DEBUG2("#### Bootstrapping listeners ####");

	/*
	 *	Load all of the virtual servers.
	 */
	while ((cs = cf_section_find_next(config, cs, "server", CF_IDENT_ANY))) {
		char const *server_name;
		CONF_SECTION *bad;

		server_name = cf_section_name2(cs);
		if (!server_name) {
			cf_log_err(cs, "server sections must have a name");
			return -1;
		}

		bad = cf_section_find_next(config, cs, "server", server_name);
		if (bad) {
			cf_log_err(bad, "Duplicate virtual servers are forbidden.");
			cf_log_err(cs, "Previous definition occurs here.");
			return -1;
		}

		/*
		 *	Ignore internally generated "server" sections,
		 *	they're for the unit tests.
		 */
		if (!cf_filename(cs)) continue;

		/*
		 *	Forbid old-style virtual servers.
		 */
		if (!cf_pair_find(cs, "namespace")) {
			cf_log_err(cs, "server %s { ...} section must set 'namespace = ...' to define the server protocol", server_name);
			return -1;
		}
	}

	for (i = 0; i < server_cnt; i++) {
		fr_virtual_listen_t	**listener;
		size_t			j, listen_cnt;

		fr_assert(virtual_servers[i] != NULL);

		/*
		 *	The only listener which can't have a dictionary is "control".
		 */
		fr_assert((cf_data_find(virtual_servers[i]->server_cs, virtual_server_dict_t, "dictionary") != NULL) ||
			  (virtual_servers[i]->listener &&
			   (strcmp(((fr_virtual_listen_t *) virtual_servers[i]->listener[0])->proto_module->module->common->name, "control") == 0)));

		if (!virtual_servers[i]->listener) goto bootstrap;

 		listener = talloc_get_type_abort(virtual_servers[i]->listener, fr_virtual_listen_t *);
 		listen_cnt = talloc_array_length(listener);

		for (j = 0; j < listen_cnt; j++) {
			fr_virtual_listen_t *listen = listener[j];

			fr_assert(listen != NULL);
			fr_assert(listen->proto_module != NULL);

			(void) talloc_get_type_abort(listen, fr_virtual_listen_t);

			talloc_get_type_abort(listen->proto_module, dl_module_inst_t);
			listen->app = (fr_app_t const *)listen->proto_module->module->common;

			if (listen->app->bootstrap &&
			    listen->app->bootstrap(listen->proto_module->data, listen->proto_module->conf) < 0) {
				cf_log_err(listen->proto_module->conf, "Bootstrap failed");
				return -1;
			}
		}

	bootstrap:
		fr_assert(virtual_servers[i]->process_module);

		if (process_bootstrap(virtual_servers[i]->process_module,
				      virtual_servers[i]->namespace) < 0) return -1;

		if (virtual_servers[i]->dynamic_client_module &&
		    (process_bootstrap(virtual_servers[i]->process_module,
				       virtual_servers[i]->namespace) < 0)) return -1;
	}

	return 0;
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
		fr_virtual_listen_t	**listener;
		size_t			j, listen_cnt;

 		listener = virtual_servers[i]->listener;
 		listen_cnt = talloc_array_length(listener);

		for (j = 0; j < listen_cnt; j++) {
			fr_virtual_listen_t *listen = listener[j];

			fr_assert(listen != NULL);
			fr_assert(listen->proto_module != NULL);
			fr_assert(listen->app != NULL);

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
			if (listen->app->open &&
			    listen->app->open(listen->proto_module->data, sc, listen->proto_module->conf) < 0) {
				cf_log_err(listen->proto_module->conf, "Opening %s I/O interface failed",
					   listen->app->name);
				return -1;
			}

			/*
			 *	Socket information is printed out by
			 *	the socket handlers.  e.g. proto_radius_udp
			 */
			DEBUG3("Opened listener for %s", listen->app->name);
		}
	}

	return 0;
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

/** Free a virtual namespace callback
 *
 */
static void _virtual_namespace_free(void *data)
{
	talloc_free(data);
}

/** Compare two virtual namespace callbacks
 *
 */
static int _virtual_namespace_cmp(void const *one, void const *two)
{
	fr_virtual_namespace_t const *a = one;
	fr_virtual_namespace_t const *b = two;
	int ret;

	ret = strcmp(a->namespace, b->namespace);
	return CMP(ret, 0);
}

/** Add a callback for a specific namespace
 *
 *  This allows modules to register unlang compilation functions for specific namespaces
 *
 * @param[in] namespace		to register.
 * @param[in] dict		Dictionary name to use for this namespace
 * @param[in] func		to call to compile sections in the virtual server.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int virtual_namespace_register(char const *namespace, fr_dict_t const *dict,
			       fr_virtual_server_compile_t func)
{
	rbtree_t		*vns_tree;
	fr_virtual_namespace_t	*vns;

	fr_assert(virtual_server_root);	/* Virtual server bootstrap must be called first */

	MEM(vns = talloc_zero(NULL, fr_virtual_namespace_t));
	vns->namespace = talloc_strdup(vns, namespace);
	vns->dict = dict;
	vns->func = func;

	vns_tree = cf_data_value(cf_data_find(virtual_server_root, rbtree_t, "vns_tree"));
	if (!vns_tree) {
		/*
		 *	Tree will be freed when the cf_data is freed
		 *	so it shouldn't be parented from
		 *	virtual_server_root.
		 */
		MEM(vns_tree = rbtree_talloc_alloc(NULL,
						   fr_virtual_namespace_t, node,
						   _virtual_namespace_cmp,
						   _virtual_namespace_free, RBTREE_FLAG_REPLACE));

		if (!cf_data_add(virtual_server_root, vns_tree, "vns_tree", true)) {
			ERROR("Failed adding namespace tree data to config");
			talloc_free(vns_tree);
			return -1;
		}
	}

	if (!rbtree_insert(vns_tree, vns)) {
		ERROR("Failed inserting namespace into tree");
		return -1;
	}

	return 0;
}

/** Return the namespace for a given virtual server
 *
 * @param[in] virtual_server	to look for namespace in.
 * @return
 *	- NULL on error.
 *	- Namespace on success.
 */
fr_dict_t const *virtual_server_namespace(char const *virtual_server)
{
	CONF_SECTION const *server_cs;
	CONF_DATA const *cd;
	virtual_server_dict_t *dict;

	server_cs = virtual_server_find(virtual_server);
	if (!server_cs) return NULL;

	cd = cf_data_find(server_cs, virtual_server_dict_t, "dictionary");
	if (!cd) return NULL;

	dict = (virtual_server_dict_t *) cf_data_value(cd);

	return dict->dict;
}

/** Return the namespace for a given virtual server specified by a CONF_ITEM within the virtual server
 *
 * @param[in] ci		to look for namespace in.
 * @return
 *	- NULL on error.
 *	- Namespace on success.
 */
fr_dict_t const *virtual_server_namespace_by_ci(CONF_ITEM *ci)
{
	CONF_DATA const *cd;
	virtual_server_dict_t *dict;

	cd = cf_data_find_in_parent(ci, virtual_server_dict_t, "dictionary");
	if (!cd) return NULL;

	dict = (virtual_server_dict_t *) cf_data_value(cd);

	return dict->dict;
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
	dict = virtual_server_namespace(virtual_server);
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

int virtual_servers_init(CONF_SECTION *config)
{
#ifndef NDEBUG
	int rbflags = RBTREE_FLAG_LOCK;	/* Produces deadlocks when iterators conflict with other operations */
#else
	int rbflags = RBTREE_FLAG_NONE;
#endif

	virtual_server_root = config;

	if (fr_dict_autoload(virtual_server_dict_autoload) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}
	if (fr_dict_attr_autoload(virtual_server_dict_attr_autoload) < 0) {
		PERROR("%s", __FUNCTION__);
		fr_dict_autofree(virtual_server_dict_autoload);
		return -1;
	}

	MEM(listen_addr_root = rbtree_alloc(NULL, fr_listen_t, virtual_server_node,
					    listen_addr_cmp, NULL, rbflags));
	MEM(server_section_name_tree = rbtree_alloc(NULL, virtual_server_compile_t, node,
						    server_section_name_cmp, NULL, rbflags));

	return 0;
}

int virtual_servers_free(void)
{
	TALLOC_FREE(listen_addr_root);
	TALLOC_FREE(server_section_name_tree);

	fr_dict_autofree(virtual_server_dict_autoload);

	return 0;
}

/**
 */
unlang_action_t process_authenticate(rlm_rcode_t *p_result, int auth_type, request_t *request, CONF_SECTION *server_cs)
{
	rlm_rcode_t	rcode;
	char const	*module;
	char const	*component;
	fr_dict_attr_t const *da;
	fr_dict_enum_t const *dv;
	CONF_SECTION	*subcs;
	fr_dict_t const	*dict_internal;

	/*
	 *	Figure out which section to run.
	 */
	if (!auth_type) {
		RERROR("An 'Auth-Type' MUST be specified");
		RETURN_MODULE_REJECT;
	}

	dict_internal = fr_dict_internal();
	da = fr_dict_attr_child_by_num(fr_dict_root(dict_internal), FR_AUTH_TYPE);
	if (!da) RETURN_MODULE_FAIL;

	dv = fr_dict_enum_by_value(da, fr_box_uint32((uint32_t) auth_type));
	if (!dv) RETURN_MODULE_FAIL;

	subcs = cf_section_find(server_cs, "authenticate", dv->name);
	if (!subcs) {
		RDEBUG2("%s %s sub-section not found.  Using default return values.",
			da->name, dv->name);
		RETURN_MODULE_REJECT;
	}

	RDEBUG("Running %s %s from file %s",
	       da->name, dv->name, cf_filename(subcs));

	/*
	 *	Cache and restore these, as they're re-set when
	 *	looping back from inside a module like eap-gtc.
	 */
	module = request->module;
	component = request->component;

	request->module = NULL;
	request->component = "authenticate";


	if (unlang_interpret_push_section(request, subcs, RLM_MODULE_REJECT, UNLANG_TOP_FRAME) < 0) {
		RETURN_MODULE_FAIL;
	}
	rcode = unlang_interpret_synchronous(request);

	request->component = component;
	request->module = module;

	RETURN_MODULE_RCODE(rcode);
}

rlm_rcode_t virtual_server_process_auth(request_t *request, CONF_SECTION *virtual_server,
					rlm_rcode_t default_rcode,
					unlang_module_resume_t resume,
					unlang_module_signal_t signal, void *rctx)
{
	fr_pair_t	*vp;
	CONF_SECTION	*auth_cs = NULL;
	char const	*auth_name;
	rlm_rcode_t	rcode = RLM_MODULE_NOOP;

	vp = fr_pair_find_by_da(&request->control_pairs, attr_auth_type);
	if (!vp) {
		RDEBUG2("No &control.Auth-Type found");
	fail:
		request->rcode = RLM_MODULE_FAIL;
		unlang_module_yield_to_section(&rcode, request, NULL, RLM_MODULE_FAIL, resume, signal, rctx);
		return rcode;
	}

	auth_name = fr_dict_enum_name_by_value(attr_auth_type, &vp->data);
	if (!auth_name) {
		REDEBUG2("Invalid %pP value", vp);
		goto fail;
	}

	auth_cs = cf_section_find(virtual_server, "authenticate", auth_name);
	if (!auth_cs) {
		REDEBUG2("No authenticate %s { ... } section found in virtual server \"%s\"",
			 auth_name, cf_section_name2(virtual_server));
		goto fail;
	}

	unlang_module_yield_to_section(&rcode, request, auth_cs, default_rcode, resume, signal, rctx);
	return rcode;
}

/** Compile sections for a virtual server.
 *
 *  When the "proto_foo" module calls fr_app_process_instantiate(), it
 *  loads the compile list from the #fr_app_worker_t, and calls this
 *  function.
 *
 *  This function walks down the registration table, compiling each
 *  named section.
 */
int virtual_server_compile_sections(CONF_SECTION *server, virtual_server_compile_t const *list, tmpl_rules_t const *rules, void *uctx)
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
			if (uctx) {
				if (list[i].offset > 0) {
					*(CONF_SECTION **) (((uint8_t *) uctx) + list[i].offset) = subcs;
				}
				if (list[i].instruction > 0) {
					*(void **) (((uint8_t *) uctx) + list[i].instruction) = instruction;
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

static int server_section_name_cmp(void const *one, void const *two)
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

	old = rbtree_find(server_section_name_tree, entry);
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

	if (!rbtree_insert(server_section_name_tree, entry)) {
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
		entry = rbtree_find(server_section_name_tree,
					&(virtual_server_compile_t) {
						.name = name1,
						.name2 = name2,
					});
		if (entry) return entry->methods;
	}

	/*
	 *	Then look up the wildcard, if we didn't find any matching name2.
	 */
	entry = rbtree_find(server_section_name_tree,
				&(virtual_server_compile_t) {
					.name = name1,
					.name2 = CF_IDENT_ANY,
				});
	if (!entry) return NULL;

	return entry->methods;
}
