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
 * @copyright 2003,2006  The FreeRADIUS server project
 * @copyright 2000  Alan DeKok <aland@ox.org>
 * @copyright 2000  Alan Curry <pacman@world.std.com>
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/server/parser.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/server/dl.h>
#include <freeradius-devel/server/command.h>
#include <freeradius-devel/io/application.h>

/*
 *	Ordered by component
 */
const section_type_value_t section_type_value[MOD_COUNT] = {
	{ "authenticate", "Auth-Type",      FR_AUTH_TYPE },
	{ "authorize",   "Autz-Type",      FR_AUTZ_TYPE },
	{ "preacct",     "Pre-Acct-Type",  FR_PRE_ACCT_TYPE },
	{ "accounting",  "Acct-Type",      FR_ACCT_TYPE },
	{ "pre-proxy",   "Pre-Proxy-Type", FR_PRE_PROXY_TYPE },
	{ "post-proxy",  "Post-Proxy-Type", FR_POST_PROXY_TYPE },
	{ "post-auth",   "Post-Auth-Type", FR_POST_AUTH_TYPE }
#ifdef WITH_COA
	,
	{ "recv-coa",    "Recv-CoA-Type",  FR_RECV_COA_TYPE },
	{ "send-coa",    "Send-CoA-Type",  FR_SEND_COA_TYPE }
#endif
};

static int default_component_results[MOD_COUNT] = {
	RLM_MODULE_REJECT,	/* AUTH */
	RLM_MODULE_NOTFOUND,	/* AUTZ */
	RLM_MODULE_NOOP,	/* PREACCT */
	RLM_MODULE_NOOP,	/* ACCT */
	RLM_MODULE_NOOP,	/* PRE_PROXY */
	RLM_MODULE_NOOP,	/* POST_PROXY */
	RLM_MODULE_NOOP       	/* POST_AUTH */
#ifdef WITH_COA
	,
	RLM_MODULE_NOOP,      	/* RECV_COA_TYPE */
	RLM_MODULE_NOOP		/* SEND_COA_TYPE */
#endif
};

typedef struct {
	char const		*namespace;		//!< Namespace function is registered to.
	fr_virtual_server_compile_t	func;		//!< Function to call to compile sections.
} fr_virtual_namespace_t;

typedef struct {
	dl_instance_t		*proto_module;		//!< The proto_* module for a listen section.
	fr_app_t const		*app;			//!< Easy access to the exported struct.
} fr_virtual_listen_t;

typedef struct {
	CONF_SECTION		*server_cs;		//!< The server section.
	char const		*namespace;		//!< Protocol namespace
	fr_virtual_listen_t	**listener;		//!< Listeners in this virtual server.
} fr_virtual_server_t;

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

static int listen_on_read(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int server_on_read(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

static int listen_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
static int server_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);

static const CONF_PARSER listen_on_read_config[] = {
	{ FR_CONF_OFFSET("listen", FR_TYPE_SUBSECTION | FR_TYPE_MULTI | FR_TYPE_OK_MISSING | FR_TYPE_ON_READ,
			 fr_virtual_server_t, listener), \
			 .subcs_size = sizeof(fr_virtual_listen_t), .subcs_type = "fr_virtual_listen_t",
			 .func = listen_on_read },

	CONF_PARSER_TERMINATOR
};

const CONF_PARSER virtual_servers_on_read_config[] = {
	/*
	 *	Not really ok if it's missing but we want to
	 *	let logic elsewhere handle the issue.
	 */
	{ FR_CONF_POINTER("server", FR_TYPE_SUBSECTION | FR_TYPE_MULTI | FR_TYPE_OK_MISSING | FR_TYPE_ON_READ, &virtual_servers), \
			  .subcs_size = sizeof(fr_virtual_server_t), .subcs_type = "fr_virtual_server_t",
			  .subcs = (void const *) listen_on_read_config, .ident2 = CF_IDENT_ANY,
			  .func = server_on_read },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER server_config[] = {
	{ FR_CONF_OFFSET("namespace", FR_TYPE_STRING, fr_virtual_server_t, namespace) },

	{ FR_CONF_OFFSET("listen", FR_TYPE_SUBSECTION | FR_TYPE_MULTI | FR_TYPE_OK_MISSING,
			 fr_virtual_server_t, listener), \
			 .subcs_size = sizeof(fr_virtual_listen_t), .subcs_type = "fr_virtual_listen_t",
			 .func = listen_parse },

	CONF_PARSER_TERMINATOR
};

const CONF_PARSER virtual_servers_config[] = {
	/*
	 *	Not really ok if it's missing but we want to
	 *	let logic elsewhere handle the issue.
	 */
	{ FR_CONF_POINTER("server", FR_TYPE_SUBSECTION | FR_TYPE_MULTI | FR_TYPE_OK_MISSING, &virtual_servers), \
			  .subcs_size = sizeof(fr_virtual_server_t), .subcs_type = "fr_virtual_server_t",
			  .subcs = (void const *) server_config, .ident2 = CF_IDENT_ANY,
			  .func = server_parse },

	CONF_PARSER_TERMINATOR
};

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
	dl_t const		*module;

	if (DEBUG_ENABLED4) cf_log_debug(ci, "Loading proto_%s", cf_pair_value(namespace));

	module = dl_module(listen_cs, NULL, cf_pair_value(namespace), DL_TYPE_PROTO);
	if (!module) {
		cf_log_err(listen_cs, "Failed loading proto_%s module", cf_pair_value(namespace));
		return -1;
	}
	cf_data_add(listen_cs, module, "proto module", true);

	return 0;
}

/** Callback to set up listen_on_read
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
static int server_on_read(UNUSED TALLOC_CTX *ctx, UNUSED void *out, UNUSED void *parent,
			  UNUSED CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{

	/*
	 *	Just a place-holder which does nothing.
	 */

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

	if (DEBUG_ENABLED4) cf_log_debug(ci, "Loading %s listener into %p", cf_pair_value(namespace), out);

	if (dl_instance(ctx, &listen->proto_module, listen_cs, NULL, cf_pair_value(namespace), DL_TYPE_PROTO) < 0) {
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

	/*
	 *	Now parse the listeners
	 */
	if (cf_section_parse(out, server, server_cs) < 0) return -1;

	return 0;
}

/**
 */
static rlm_rcode_t module_method_call(rlm_components_t comp, int idx, REQUEST *request)
{
	rlm_rcode_t	rcode;
	CONF_SECTION	*cs, *server_cs;
	char const	*module;
	char const	*component;

	rad_assert(request->server_cs != NULL);

	/*
	 *	Cache the old server_cs in case it was changed.
	 *
	 *	FIXME: request->server_cs should NOT be changed.
	 *	Instead, we should always create a child REQUEST when
	 *	we need to use a different virtual server.
	 *
	 *	This is mainly for things like proxying
	 */
	server_cs = request->server_cs;
	cs = cf_section_find(request->server_cs, section_type_value[comp].section, NULL);
	if (!cs) {
		RDEBUG2("Empty %s section in virtual server \"%s\".  Using default return value (%s)",
			section_type_value[comp].section, cf_section_name2(request->server_cs),
			fr_int2str(mod_rcode_table, default_component_results[comp], "<invalid>"));
		return default_component_results[comp];
	}

	/*
	 *	Figure out which section to run.
	 */
	if (!idx) {
		RDEBUG("Running section %s from file %s",
		       section_type_value[comp].section, cf_filename(cs));

	} else {
		fr_dict_attr_t const *da;
		fr_dict_enum_t const *dv;
		CONF_SECTION *subcs;

		da = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal), section_type_value[comp].attr);
		if (!da) return RLM_MODULE_FAIL;

		dv = fr_dict_enum_by_value(da, fr_box_uint32((uint32_t)idx));
		if (!dv) return RLM_MODULE_FAIL;

		subcs = cf_section_find(cs, da->name, dv->alias);
		if (!subcs) {
			RDEBUG2("%s %s sub-section not found.  Using default return values.",
				da->name, dv->alias);
			return default_component_results[comp];
		}

		RDEBUG("Running %s %s from file %s",
		       da->name, dv->alias, cf_filename(subcs));
		cs = subcs;
	}

	/*
	 *	Cache and restore these, as they're re-set when
	 *	looping back from inside a module like eap-gtc.
	 */
	module = request->module;
	component = request->component;

	request->module = NULL;
	request->component = section_type_value[comp].section;

	rcode = unlang_interpret(request, cs, default_component_results[comp]);

	request->component = component;
	request->module = module;
	request->server_cs = server_cs;

	return rcode;
}

/*
 *	Call all authorization modules until one returns
 *	somethings else than RLM_MODULE_OK
 */
rlm_rcode_t process_authorize(int autz_type, REQUEST *request)
{
	return module_method_call(MOD_AUTHORIZE, autz_type, request);
}

/*
 *	Authenticate a user/password with various methods.
 */
rlm_rcode_t process_authenticate(int auth_type, REQUEST *request)
{
	return module_method_call(MOD_AUTHENTICATE, auth_type, request);
}

#ifdef WITH_PROXY
/*
 *	Do post-proxying for ALL configured sessions
 */
rlm_rcode_t process_post_proxy(int type, REQUEST *request)
{
	rad_assert(request->proxy != NULL);

	return module_method_call(MOD_POST_PROXY, type, request);
}
#endif

/*
 *	Do post-authentication for ALL configured sessions
 */
rlm_rcode_t process_post_auth(int postauth_type, REQUEST *request)
{
	return module_method_call(MOD_POST_AUTH, postauth_type, request);
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
	CONF_SECTION		*subcs = NULL;

	rad_assert(strcmp(cf_section_name1(server_cs), "server") == 0);

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
		dv = fr_dict_enum_by_alias(da, name2, -1);
		if (dv) continue;

		cf_log_debug(subcs, "Creating %s = %s", da->name, name2);

		/*
		 *	Create a new unique value with a meaningless
		 *	number.  You can't look at it from outside of
		 *	this code, so it doesn't matter.  The only
		 *	requirement is that it's unique.
		 */
		if (fr_dict_enum_add_alias_next(da, name2) < 0) {
			PERROR("Failed adding section value");
			return -1;
		}
	}

	return 0;
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

	rad_assert(virtual_servers);

	DEBUG2("#### Opening listener interfaces ####");

	for (i = 0; i < server_cnt; i++) {
		fr_virtual_listen_t	**listener;
		size_t			j, listen_cnt;

 		listener = virtual_servers[i]->listener;
 		listen_cnt = talloc_array_length(listener);

		for (j = 0; j < listen_cnt; j++) {
			fr_virtual_listen_t *listen = listener[j];

			rad_assert(listen != NULL);
			rad_assert(listen->proto_module != NULL);
			rad_assert(listen->app != NULL);

			/*
			 *	The socket is opened with listen->app_instance,
			 *	but all subsequent calls (network.c, etc.) use listen->app_io_instance.
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

	rad_assert(virtual_servers);

	DEBUG2("#### Instantiating listeners ####");

	if (fr_command_register_hook(NULL, NULL, virtual_server_root, cmd_table) < 0) {
		ERROR("Failed registering radmin commands for virtual servers - %s",
		      fr_strerror());
		return -1;
	}

	for (i = 0; i < server_cnt; i++) {
		fr_virtual_listen_t	**listener;
		size_t			j, listen_cnt;
		CONF_ITEM		*ci = NULL;
		CONF_SECTION		*server_cs = virtual_servers[i]->server_cs;

 		listener = virtual_servers[i]->listener;
 		listen_cnt = talloc_array_length(listener);

		DEBUG("Compiling policies in server %s { ... }", cf_section_name2(server_cs));

		if (vns_tree) {
			fr_virtual_namespace_t	find = { .namespace = cf_section_name2(server_cs) };
			fr_virtual_namespace_t	*found;

			found = rbtree_finddata(vns_tree, &find);
			if (found && (found->func(server_cs) < 0)) return -1;
		}

		/*
		 *	Not all virtual servers have listeners,
		 *	some are just used to wrap unlang logic.
		 */
		if (listen_cnt == 0) continue;

		for (j = 0; j < listen_cnt; j++) {
			fr_virtual_listen_t *listen = listener[j];

			rad_assert(listen != NULL);
			rad_assert(listen->proto_module != NULL);
			rad_assert(listen->app != NULL);

			if (listen->app->instantiate &&
			    listen->app->instantiate(listen->proto_module->data, listen->proto_module->conf) < 0) {
				cf_log_err(listen->proto_module->conf, "Could not load virtual server \"%s\".",
					    cf_section_name2(server_cs));
				return -1;
			}
		}

		/*
		 *	Print out warnings for unused "recv" and
		 *	"send" sections.
		 */
		while ((ci = cf_item_next(server_cs, ci))) {
			char const	*name;
			CONF_SECTION	*subcs;

			if (!cf_item_is_section(ci)) continue;

			subcs = cf_item_to_section(ci);
			name = cf_section_name1(subcs);

			/*
			 *	Skip listen sections
			 */
			if (strcmp(name, "listen") == 0) continue;

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
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int virtual_servers_bootstrap(CONF_SECTION *config)
{
	size_t i, server_cnt = 0;
	CONF_SECTION *cs = NULL;

	virtual_server_root = config;

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

		server_name = cf_section_name2(cs);
		if (!server_name) {
			cf_log_err(cs, "server sections must have a name");
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

		if (!virtual_servers[i] || !virtual_servers[i]->listener) continue;

 		listener = talloc_get_type_abort(virtual_servers[i]->listener, fr_virtual_listen_t *);
 		listen_cnt = talloc_array_length(listener);

		for (j = 0; j < listen_cnt; j++) {
			fr_virtual_listen_t *listen = listener[j];

			rad_assert(listen != NULL);
			rad_assert(listen->proto_module != NULL);

			(void) talloc_get_type_abort(listen, fr_virtual_listen_t);

			talloc_get_type_abort(listen->proto_module, dl_instance_t);
			listen->app = (fr_app_t const *)listen->proto_module->module->common;

			if (listen->app->bootstrap &&
			    listen->app->bootstrap(listen->proto_module->data, listen->proto_module->conf) < 0) {
				cf_log_err(listen->proto_module->conf, "Bootstrap failed");
				return -1;
			}
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
static int _virtual_namespace_cmp(void const *a, void const *b)
{
	fr_virtual_namespace_t const *ns_a = a;
	fr_virtual_namespace_t const *ns_b = b;

	return strcmp(ns_a->namespace, ns_b->namespace);
}

/** Add a callback for a specific namespace
 *
 *  This allows modules to register unlang compilation functions for specific namespaces
 */
int virtual_server_namespace_register(char const *namespace, fr_virtual_server_compile_t func)
{
	rbtree_t		*vns_tree;
	fr_virtual_namespace_t	*vns;

	rad_assert(virtual_server_root);	/* Virtual server bootstrap must be called first */

	MEM(vns = talloc_zero(NULL, fr_virtual_namespace_t));
	vns->namespace = namespace;
	vns->func = func;

	vns_tree = cf_data_value(cf_data_find(virtual_server_root, rbtree_t, "vns_tree"));
	if (!vns_tree) {
		/*
		 *	Tree will be freed when the cf_data is freed
		 *	so it shouldn't be parented from
		 *	virtual_server_root.
		 */
		MEM(vns_tree = rbtree_talloc_create(NULL,
						    _virtual_namespace_cmp, fr_virtual_namespace_t,
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

/*
 *	Hack for unit_test_module.c
 */
void fr_request_async_bootstrap(REQUEST *request, fr_event_list_t *el)
{
	size_t listen_cnt;
	fr_virtual_listen_t	**listener;

	if (!virtual_servers) return; /* let it crash! */

	listener = virtual_servers[0]->listener;
	listen_cnt = talloc_array_length(listener);

	if (!listen_cnt) return;

	/*
	 *	New async listeners
	 */
	request->async = talloc_zero(request, fr_async_t);

	request->async->channel = NULL;
	request->async->original_recv_time = NULL;
/*	request->async->recv_time = fr_time(); */
	request->async->el = el;

	request->async->listen = NULL;
	request->async->packet_ctx = NULL;
	listener[0]->app->entry_point_set(listener[0]->proto_module->data, request);
}
