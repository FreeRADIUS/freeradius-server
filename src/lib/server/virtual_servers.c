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
#include <freeradius-devel/server/virtual_servers.h>

#include <freeradius-devel/io/application.h>
#include <freeradius-devel/io/listen.h>

#include <freeradius-devel/unlang/base.h>

typedef struct {
	char const		*namespace;		//!< Namespace function is registered to.
	char const		*proto_dict;		//!< Dictionary name to load for this namespace.
	char const		*proto_dir;		//!< Override proto_dict and specify a dictionary off of
 							//!< the dictionary root directory (may be NULL).
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
} fr_virtual_server_t;

static fr_dict_t const *dict_freeradius;

static fr_dict_attr_t const *attr_auth_type;

extern fr_dict_autoload_t virtual_server_dict[];
fr_dict_autoload_t virtual_server_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

extern fr_dict_attr_autoload_t virtual_server_dict_attr[];
fr_dict_attr_autoload_t virtual_server_dict_attr[] = {
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
static int virtual_server_section_register(virtual_server_compile_t const *entry);

static int namespace_on_read(UNUSED TALLOC_CTX *ctx, UNUSED void *out, UNUSED void *parent,
			     CONF_ITEM *ci, UNUSED CONF_PARSER const *rule);
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
	{ FR_CONF_OFFSET("listen", FR_TYPE_SUBSECTION | FR_TYPE_MULTI | FR_TYPE_OK_MISSING,
			 fr_virtual_server_t, listener),		\
			 .subcs_size = sizeof(fr_virtual_listen_t), .subcs_type = "fr_virtual_listen_t",
			 .func = listen_parse },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER namespace_config[] = {
	{ FR_CONF_OFFSET("namespace", FR_TYPE_STRING | FR_TYPE_ON_READ, fr_virtual_server_t, namespace),
	  .func = namespace_on_read },

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
	dl_module_t const	*module;

	if (!namespace) {
		cf_log_err(listen_cs, "No 'namespace' set for virtual server");
		cf_log_err(listen_cs, "Please add 'namespace = <protocol>' inside of the 'server %s { ... }' section",
			   cf_section_name2(server_cs));
		return -1;
	}

	if (DEBUG_ENABLED4) cf_log_debug(ci, "Loading proto_%s", cf_pair_value(namespace));

	module = dl_module(listen_cs, NULL, cf_pair_value(namespace), DL_MODULE_TYPE_PROTO);
	if (!module) {
		cf_log_err(listen_cs, "Failed loading proto_%s module", cf_pair_value(namespace));
		return -1;
	}
	cf_data_add(listen_cs, module, "proto module", true);

	return 0;
}

/** Decrement references on dictionaries as the config sections are freed
 *
 */
static int _virtual_server_dict_free(fr_dict_t **dict)
{
	fr_dict_free(dict);
	return 0;
}

/** Load a dictionary for a virtual server and
 *
 * @param[in] server_cs		to set the namespace for.
 * @param[in] proto_dict	to load.
 * @param[in] proto_dir		Path override for dictionary.
 */
static int virtual_server_namespace_set(CONF_SECTION *server_cs,
					char const *proto_dict, char const *proto_dir)
{
	fr_dict_t	**dict_p;
	fr_dict_t	*dict = NULL;

	if (fr_dict_protocol_afrom_file(&dict, proto_dict, proto_dir) < 0) return -1;

	dict_p = talloc_zero(NULL, fr_dict_t *);
	*dict_p = dict;
	talloc_set_destructor(dict_p, _virtual_server_dict_free);

	cf_data_add(server_cs, dict_p, "dictionary", true);

	return 0;
}

/** Load a protocol dictionary matching the specified namespace
 *
 * @param[in] ctx	to allocate data in.
 * @param[out] out	always NULL
 * @param[in] parent	Base structure address.
 * @param[in] ci	#CONF_SECTION containing the namespace pair.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int namespace_on_read(UNUSED TALLOC_CTX *ctx, UNUSED void *out, UNUSED void *parent,
			     CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	rbtree_t		*vns_tree = cf_data_value(cf_data_find(virtual_server_root, rbtree_t, "vns_tree"));
	CONF_PAIR		*namespace_cp = cf_item_to_pair(ci);
	char const		*namespace_str = cf_pair_value(namespace_cp);
	char const		*proto_dict = namespace_str;
	char const		*proto_dir = NULL;
	CONF_SECTION		*server_cs = cf_item_to_section(cf_parent(ci));

	if (DEBUG_ENABLED4) cf_log_debug(ci, "Initialising namespace \"%s\"", namespace_str);

	/*
	 *	Doesn't currently work, because namespace
	 *	*REALLY REALLY* shouldn't be processed on_read,
	 *	because it doesn't give modules a chance to
	 *	run their bootstrap methods.
	 */
	if (vns_tree) {
		fr_virtual_namespace_t	*found;

		found = rbtree_finddata(vns_tree,
					&(fr_virtual_namespace_t){ .namespace = cf_section_name2(server_cs) });
		proto_dict = found->proto_dict;
		proto_dir = found->proto_dir;
	}

	if (virtual_server_namespace_set(server_cs, proto_dict, proto_dir) < 0) {
		if (strncmp(proto_dict, "eap-", 4) == 0) return 0;

		cf_log_perr(ci, "Failed initialising namespace \"%s\" - %s", namespace_str, fr_strerror());
		return 0;	/* Ignore for now */
	}

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
			  CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	return cf_section_rules_push(cf_item_to_section(ci), namespace_config);
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

	if (dl_module_instance(ctx, &listen->proto_module, listen_cs, NULL, cf_pair_value(namespace), DL_MODULE_TYPE_PROTO) < 0) {
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
	int rcode;

	/*
	 *	The caller must ensure that the address field is set.
	 */
	if (!a->app_io_addr && !b->app_io_addr) return 0;
	if (!a->app_io_addr && b->app_io_addr) return -1;
	if (a->app_io_addr && !b->app_io_addr) return +1;

	/*
	 *	UDP vs TCP
	 */
	rcode = a->app_io_addr->proto - b->app_io_addr->proto;
	if (rcode != 0) return rcode;

	/*
	 *	Check ports.
	 */
	rcode = a->app_io_addr->port - b->app_io_addr->port;
	if (rcode != 0) return rcode;

	/*
	 *	Don't call fr_ipaddr_cmp(), as we need to do our own
	 *	checks here.  We have various wildcard checks which
	 *	aren't globally applicable.
	 */

	/*
	 *	Different address families.
	 */
	rcode = a->app_io_addr->ipaddr.af - b->app_io_addr->ipaddr.af;
	if (rcode != 0) return rcode;

	/*
	 *	If both are bound to interfaces, AND the interfaces
	 *	are different, then there is no conflict.
	 */
	if (a->app_io_addr->ipaddr.scope_id && b->app_io_addr->ipaddr.scope_id) {
		rcode = a->app_io_addr->ipaddr.scope_id - b->app_io_addr->ipaddr.scope_id;
		if (rcode != 0) return rcode;
	}

	rcode = a->app_io_addr->ipaddr.prefix - b->app_io_addr->ipaddr.prefix;
	aip = a->app_io_addr->ipaddr;
	bip = b->app_io_addr->ipaddr;

	/*
	 *	Mask out the longer prefix to match the shorter
	 *	prefix.
	 */
	if (rcode < 0) {
		fr_ipaddr_mask(&bip, a->app_io_addr->ipaddr.prefix);

	} else if (rcode > 0) {
		fr_ipaddr_mask(&aip, b->app_io_addr->ipaddr.prefix);

	}

	return fr_ipaddr_cmp(&aip, &bip);
}

/** See if another global listener is using a particular IP / port
 *
 */
fr_listen_t *listen_find_any(fr_listen_t *li)
{
	if (!listen_addr_root) return false;

	return rbtree_finddata(listen_addr_root, li);
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
			fr_virtual_namespace_t	*found;
			CONF_PAIR		*ns;

			ns = cf_pair_find(server_cs, "namespace");
			if (!ns) {
				cf_log_err(server_cs, "Missing \"namespace\" config item");
				return -1;
			}

			found = rbtree_finddata(vns_tree, &(fr_virtual_namespace_t){ .namespace = cf_pair_value(ns) });
			if (found) {
				/*
				 *	Stupid hack because of the on_read
				 *	namespace stuff.
				 */
				if (virtual_server_namespace_set(server_cs,
								 found->proto_dict,
								 found-> proto_dir) < 0) {
					cf_log_perr(ci, "Failed loading dictionary for virtual namespace \"%s\" - %s",
						    cf_pair_value(ns), fr_strerror());
					return -1;
				}
				if ((found->func(server_cs) < 0)) return -1;
			/*
			 *	If it's not a virtual namespace, check a
			 *	dictionary was loaded in a previous phase.
			 */
			} else {
				if (!cf_data_find(server_cs, fr_dict_t *, "dictionary")) {
					if (!cf_section_find(server_cs, "listen", CF_IDENT_ANY)) {
						cf_log_err(ns, "Failed resolving namespace.  Verify that modules "
							   "referencing this server are enabled");
						return -1;
					}
				}
			}
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

			talloc_get_type_abort(listen->proto_module, dl_module_inst_t);
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
static int _virtual_namespace_cmp(void const *a, void const *b)
{
	fr_virtual_namespace_t const *ns_a = a;
	fr_virtual_namespace_t const *ns_b = b;

	return strcmp(ns_a->namespace, ns_b->namespace);
}

/** Add a callback for a specific namespace
 *
 *  This allows modules to register unlang compilation functions for specific namespaces
 *
 * @param[in] namespace		to register.
 * @param[in] proto_dict	Dictionary name to load for this namespace.
 * @param[in] proto_dir		Override proto_dict and specify a dictionary off of
 *				the dictionary root directory (may be NULL).
 * @param[in] func		to call to compile sections in the virtual server.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int virtual_namespace_register(char const *namespace,
			       char const *proto_dict, char const *proto_dir, fr_virtual_server_compile_t func)
{
	rbtree_t		*vns_tree;
	fr_virtual_namespace_t	*vns;

	rad_assert(virtual_server_root);	/* Virtual server bootstrap must be called first */

	MEM(vns = talloc_zero(NULL, fr_virtual_namespace_t));
	vns->namespace = talloc_strdup(vns, namespace);
	vns->proto_dict = talloc_strdup(vns, proto_dict);
	vns->proto_dir = talloc_strdup(vns, proto_dir);
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

/** Return the namespace for a given virtual server
 *
 * @param[in] virtual_server	to look for namespace in.
 * @return
 *	- NULL on error.
 *	- Namespace on success.
 */
fr_dict_t *virtual_server_namespace(char const *virtual_server)
{
	CONF_SECTION const *server_cs;
	CONF_DATA const *cd;

	server_cs = virtual_server_find(virtual_server);
	if (!server_cs) return NULL;

	cd = cf_data_find(server_cs, fr_dict_t *, "dictionary");
	if (!cd) return NULL;

	return *(fr_dict_t **) cf_data_value(cd);
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
	virtual_server_root = config;

	if (fr_dict_autoload(virtual_server_dict) < 0) {
		PERROR("%s", __FUNCTION__);
		return -1;
	}
	if (fr_dict_attr_autoload(virtual_server_dict_attr) < 0) {
		PERROR("%s", __FUNCTION__);
		fr_dict_autofree(virtual_server_dict);
		return -1;
	}

	MEM(listen_addr_root = rbtree_create(NULL, listen_addr_cmp, NULL, RBTREE_FLAG_NONE));
	MEM(server_section_name_tree = rbtree_create(NULL, server_section_name_cmp, NULL, RBTREE_FLAG_NONE));

	return 0;
}

int virtual_servers_free(void)
{
	TALLOC_FREE(listen_addr_root);
	TALLOC_FREE(server_section_name_tree);

	fr_dict_autofree(virtual_server_dict);

	return 0;
}

/**
 */
rlm_rcode_t process_authenticate(int auth_type, REQUEST *request)
{
	rlm_rcode_t	rcode;
	CONF_SECTION	*cs, *server_cs;
	char const	*module;
	char const	*component;
	fr_dict_attr_t const *da;
	fr_dict_enum_t const *dv;
	CONF_SECTION	*subcs;
	fr_dict_t const	*dict_internal;

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
	cs = cf_section_find(request->server_cs, "authenticate", NULL);
	if (!cs) {
		RDEBUG2("Empty 'authenticate' section in virtual server \"%s\".  Using default return value (%s)",
			cf_section_name2(request->server_cs),
			fr_table_str_by_value(mod_rcode_table, RLM_MODULE_REJECT, "<invalid>"));
		return RLM_MODULE_REJECT;
	}

	/*
	 *	Figure out which section to run.
	 */
	if (!auth_type) {
		RERROR("An 'Auth-Type' MUST be specified");
		return RLM_MODULE_REJECT;
	}

	dict_internal = fr_dict_internal();
	da = fr_dict_attr_child_by_num(fr_dict_root(dict_internal), FR_AUTH_TYPE);
	if (!da) return RLM_MODULE_FAIL;

	dv = fr_dict_dict_enum_by_value(dict_internal, da, fr_box_uint32((uint32_t) auth_type));
	if (!dv) return RLM_MODULE_FAIL;

	subcs = cf_section_find(cs, da->name, dv->name);
	if (!subcs) {
		RDEBUG2("%s %s sub-section not found.  Using default return values.",
			da->name, dv->name);
		return RLM_MODULE_REJECT;
	}

	RDEBUG("Running %s %s from file %s",
	       da->name, dv->name, cf_filename(subcs));
	cs = subcs;

	/*
	 *	Cache and restore these, as they're re-set when
	 *	looping back from inside a module like eap-gtc.
	 */
	module = request->module;
	component = request->component;

	request->module = NULL;
	request->component = "authenticate";

	rcode = unlang_interpret_section(request, cs, RLM_MODULE_REJECT);

	request->component = component;
	request->module = module;
	request->server_cs = server_cs;

	return rcode;
}

rlm_rcode_t virtual_server_process_auth(REQUEST *request, CONF_SECTION *virtual_server,
					rlm_rcode_t default_rcode,
					fr_unlang_module_resume_t resume,
					fr_unlang_module_signal_t signal, void *rctx)
{
	VALUE_PAIR	*vp;
	CONF_SECTION	*auth_cs = NULL;
	char const	*auth_name;

	vp = fr_pair_find_by_da(request->control, attr_auth_type, TAG_ANY);
	if (!vp) {
		RDEBUG2("No &control:Auth-Type found");
	fail:
		request->rcode = RLM_MODULE_FAIL;
		return unlang_module_yield_to_section(request, NULL, RLM_MODULE_FAIL, resume, signal, rctx);
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

	return unlang_module_yield_to_section(request, auth_cs, default_rcode, resume, signal, rctx);
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
	request->async->el = el;

	request->async->listen = NULL;
	request->async->packet_ctx = NULL;
	listener[0]->app->entry_point_set(listener[0]->proto_module->data, request);
}

int fr_app_process_bootstrap(CONF_SECTION *server, dl_module_inst_t **type_submodule, CONF_SECTION *conf)
{
	int i = 0;
	CONF_PAIR *cp = NULL;

	/*
	 *	Bootstrap the process modules
	 */
	while ((cp = cf_pair_find_next(conf, cp, "type"))) {
		char const		*value;
		dl_module_t const	*module = talloc_get_type_abort_const(type_submodule[i]->module, dl_module_t);
		fr_app_worker_t const	*app_process = (fr_app_worker_t const *)(module->common);

		if (app_process->bootstrap && (app_process->bootstrap(type_submodule[i]->data,
								      type_submodule[i]->conf) < 0)) {
			cf_log_err(conf, "Bootstrap failed for \"%s\"", app_process->name);
			return -1;
		}

		value = cf_pair_value(cp);

		/*
		 *	Save the process / instance data
		 *
		 *	This is so that when one virtual server wants
		 *	to call another, it just looks up the data
		 *	here by packet name, and doesn't need to root
		 *	through all of the listeners.
		 */
		if (!cf_data_find(server, fr_io_process_t, value)) {
			fr_io_process_t *process_p = talloc(server, fr_io_process_t);
			*process_p = app_process->entry_point;

			(void) cf_data_add(server, process_p, value, NULL);

			if (type_submodule[i]->data) {
				(void) cf_data_add(server, type_submodule[i]->data, value, NULL);
			}
		}

		/*
		 *	Register the processing sections with the
		 *	module manager.
		 */
		if (app_process->compile_list) {
			int j;
			virtual_server_compile_t const *list = app_process->compile_list;

			for (j = 0; list[j].name != NULL; j++) {
				if (list[j].name == CF_IDENT_ANY) continue;

				if (virtual_server_section_register(&list[j]) < 0) {
					cf_log_err(conf, "Failed registering section name for %s",
						app_process->name);
					return -1;
				}

			}
		}


		i++;
	}

	return i;
}


int fr_app_process_instantiate(CONF_SECTION *server, dl_module_inst_t **type_submodule, dl_module_inst_t **type_submodule_by_code, int code_max, CONF_SECTION *conf)
{
	int i;
	CONF_PAIR *cp = NULL;
	vp_tmpl_rules_t		parse_rules;

	memset(&parse_rules, 0, sizeof(parse_rules));
	parse_rules.dict_def = virtual_server_namespace(cf_section_name2(server));

	/*
	 *	Instantiate the process modules
	 */
	i = 0;
	while ((cp = cf_pair_find_next(conf, cp, "type"))) {
		fr_app_worker_t const	*app_process;
		fr_dict_enum_t const	*enumv;
		int			code;

		app_process = (fr_app_worker_t const *)type_submodule[i]->module->common;
		if (app_process->instantiate &&
		    (app_process->instantiate(type_submodule[i]->data, type_submodule[i]->conf) < 0)) {
			cf_log_err(conf, "Instantiation failed for \"%s\"", app_process->name);
			return -1;
		}

		/*
		 *	Compile the processing sections.
		 */
		if (app_process->compile_list &&
		    (virtual_server_compile_sections(server, app_process->compile_list, &parse_rules, type_submodule[i]->data) < 0)) {
			return -1;
		}

		/*
		 *	We've already done bounds checking in the type_parse function
		 */
		enumv = cf_data_value(cf_data_find(cp, fr_dict_enum_t, NULL));
		if (!fr_cond_assert(enumv)) return -1;

		code = enumv->value->vb_uint32;
		if (code >= code_max) {
			cf_log_err(conf, "Invalid type code \"%s\" for \"%s\"", enumv->name, app_process->name);
			return -1;
		}

		type_submodule_by_code[code] = type_submodule[i];	/* Store the process function */
		i++;
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
 */
int virtual_server_compile_sections(CONF_SECTION *server, virtual_server_compile_t const *list, vp_tmpl_rules_t const *rules, void *uctx)
{
	int i;
	CONF_SECTION *subcs = NULL;

	/*
	 *	The sections are in trees, so this isn't as bad as it
	 *	looks.  It's not O(n^2), but O(n logn).  But it could
	 *	still be improved.
	 */
	for (i = 0; list[i].name != NULL; i++) {
		int rcode;

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
			continue;
		}

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

			rcode = unlang_compile(subcs, list[i].component, rules, NULL);
			if (rcode < 0) return -1;

			/*
			 *	Note that we don't store the
			 *	CONF_SECTION here, as it's a wildcard.
			 *
			 *	@todo - count number of subsections
			 *	and store them in an array?
			 */
		}
	}

	return 0;
}

static int server_section_name_cmp(void const *one, void const *two)
{
	int rcode;
	virtual_server_compile_t const *a = one;
	virtual_server_compile_t const *b = two;

	rcode = strcmp(a->name, b->name);
	if (rcode != 0) return rcode;

	if (a->name2 == b->name2) return 0;
	if ((a->name2 == CF_IDENT_ANY) && (b->name2 != CF_IDENT_ANY)) return -1;
	if ((a->name2 != CF_IDENT_ANY) && (b->name2 == CF_IDENT_ANY)) return +1;

	return strcmp(a->name2, b->name2);
}

/** Register name1 / name2 as allowed processing sections
 *
 *  This function is called from the virtual server bootstrap routine,
 *  which happens before module_bootstrap();
 */
static int virtual_server_section_register(virtual_server_compile_t const *entry)
{
	virtual_server_compile_t *old;

	rad_assert(server_section_name_tree != NULL);

	old = rbtree_finddata(server_section_name_tree, entry);
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
		fr_strerror_printf("Failed inserting entry into internal tree");
		return -1;
	}

	return 0;
}


/** Find the component for a section
 *
 */
int virtual_server_section_component(rlm_components_t *component, char const *name1, char const *name2)
{
	virtual_server_compile_t *entry;

	rad_assert(server_section_name_tree != NULL);

	/*
	 *	Look up the specific name first.  That way we can
	 *	define both "accounting on", and "accounting *".
	 */
	if (name2 != CF_IDENT_ANY) {
		entry = rbtree_finddata(server_section_name_tree,
					&(virtual_server_compile_t) {
						.name = name1,
						.name2 = name2,
					});
		if (entry) goto done;
	}

	/*
	 *	Then look up the wildcard, if we didn't find any matching name2.
	 */
	entry = rbtree_finddata(server_section_name_tree,
				&(virtual_server_compile_t) {
					.name = name1,
					.name2 = CF_IDENT_ANY,
				});
	if (!entry) return -1;

done:
	*component = entry->component;

	return 0;
}

/** Find the component for a section
 *
 */
virtual_server_method_t *virtual_server_section_methods(char const *name1, char const *name2)
{
	virtual_server_compile_t *entry;

	rad_assert(server_section_name_tree != NULL);

	/*
	 *	Look up the specific name first.  That way we can
	 *	define both "accounting on", and "accounting *".
	 */
	if (name2 != CF_IDENT_ANY) {
		entry = rbtree_finddata(server_section_name_tree,
					&(virtual_server_compile_t) {
						.name = name1,
						.name2 = name2,
					});
		if (entry) return entry->methods;
	}

	/*
	 *	Then look up the wildcard, if we didn't find any matching name2.
	 */
	entry = rbtree_finddata(server_section_name_tree,
				&(virtual_server_compile_t) {
					.name = name1,
					.name2 = CF_IDENT_ANY,
				});
	if (!entry) return NULL;

	return entry->methods;
}

