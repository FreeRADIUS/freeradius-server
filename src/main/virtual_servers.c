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

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/interpreter.h>
#include <freeradius-devel/parser.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/dl.h>
#include <freeradius-devel/io/application.h>

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
	dl_instance_t		*proto_module;	//!< The proto_* module for a listen section.
	fr_app_t const		*app;		//!< Easy access to the exported struct.
} fr_virtual_listen_t;

typedef struct {
	char const		*namespace;	//!< Protocol namespace
	fr_virtual_listen_t	**listener;	//!< Listeners in this virtual server.
} fr_virtual_server_t;

/** Top level structure holding all virtual servers
 *
 */
static fr_virtual_server_t **virtual_servers;

static int listen_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, CONF_PARSER const *rule);
static const CONF_PARSER server_config[] = {
	{ FR_CONF_OFFSET("namespace", FR_TYPE_STRING, fr_virtual_server_t, namespace) },

	{ FR_CONF_OFFSET("listen", FR_TYPE_SUBSECTION | FR_TYPE_MULTI, fr_virtual_server_t, listener), \
			 .subcs_size = sizeof(fr_virtual_listen_t), .subcs_type = "fr_virtual_listen_t",
			 .func = listen_parse},

	CONF_PARSER_TERMINATOR
};

const CONF_PARSER virtual_servers_config[] = {
	{ FR_CONF_POINTER("server", FR_TYPE_SUBSECTION | FR_TYPE_MULTI, &virtual_servers), \
			  .subcs_size = sizeof(fr_virtual_server_t), .subcs_type = "fr_virtual_server_t",
			  .subcs = (void const *) server_config, .ident2 = CF_IDENT_ANY},

	CONF_PARSER_TERMINATOR
};

/** dl_open a proto_* module
 *
 * @param[in] ctx	to allocate data in (instance of proto_radius).
 * @param[out] out	Where to our listen configuration.  Is a #fr_virtual_listen_t structure.
 * @param[in] ci	#CONF_SECTION containing the listen section.
 * @param[in] rule	unused.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int listen_parse(TALLOC_CTX *ctx, void *out, CONF_ITEM *ci, UNUSED CONF_PARSER const *rule)
{
	fr_virtual_listen_t	*listen = out;	/* Pre-allocated for us */
	CONF_SECTION		*listen_cs = cf_item_to_section(ci);
	CONF_SECTION		*server = cf_item_to_section(cf_parent(ci));
	CONF_PAIR		*namespace;

	namespace = cf_pair_find(server, "namespace");
	if (!namespace) {
		cf_log_err(server, "virtual server %s MUST contain a 'namespace' option",
			   cf_section_name2(server));
		return -1;
	}

	if (DEBUG_ENABLED4) cf_log_debug(ci, "Loading %s listener into %p", cf_pair_value(namespace), out);

	if (dl_instance(ctx, &listen->proto_module, listen_cs, NULL, cf_pair_value(namespace), DL_TYPE_PROTO) < 0) {
		cf_log_err(listen_cs, "Failed loading proto module");
		return -1;
	}

	/*
	 *	Hack for now: tell the server core we have new listeners.
	 */
	main_config.namespace = true;

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
		RDEBUG2("Empty %s section in virtual server \"%s\".  Using default return value %s.",
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

		da = fr_dict_attr_by_num(NULL, 0, section_type_value[comp].attr);
		if (!da) return RLM_MODULE_FAIL;

		dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32((uint32_t)idx));
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

#ifdef WITH_ACCOUNTING
/*
 *	Do pre-accounting for ALL configured sessions
 */
rlm_rcode_t process_preacct(REQUEST *request)
{
	return module_method_call(MOD_PREACCT, 0, request);
}

/*
 *	Do accounting for ALL configured sessions
 */
rlm_rcode_t process_accounting(int acct_type, REQUEST *request)
{
	return module_method_call(MOD_ACCOUNTING, acct_type, request);
}
#endif

#ifdef WITH_PROXY
/*
 *	Do pre-proxying for ALL configured sessions
 */
rlm_rcode_t process_pre_proxy(int type, REQUEST *request)
{
	rad_assert(request->proxy != NULL);

	return module_method_call(MOD_PRE_PROXY, type, request);
}

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

#ifdef WITH_COA
rlm_rcode_t process_recv_coa(int recv_coa_type, REQUEST *request)
{
	return module_method_call(MOD_RECV_COA, recv_coa_type, request);
}

rlm_rcode_t process_send_coa(int send_coa_type, REQUEST *request)
{
	return module_method_call(MOD_SEND_COA, send_coa_type, request);
}
#endif

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
		fr_value_box_t	value = { .type = FR_TYPE_UINT32 };
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
		dv = fr_dict_enum_by_alias(NULL, da, name2);
		if (dv) continue;

		/*
		 *	Create a new unique value with a meaningless
		 *	number.  You can't look at it from outside of
		 *	this code, so it doesn't matter.  The only
		 *	requirement is that it's unique.
		 */
		do {
			value.vb_uint32 = (fr_rand() & 0x00ffffff) + 1;
		} while (fr_dict_enum_by_value(NULL, da, &value));

		cf_log_debug(subcs, "Creating %s = %s", da->name, name2);
		if (fr_dict_enum_add_alias(da, name2, &value, true, false) < 0) {
			ERROR("%s", fr_strerror());
			return -1;
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

	DEBUG2("%s: #### Opening listener interfaces ####", main_config.name);

	for (i = 0; i < server_cnt; i++) {
		fr_virtual_listen_t	**listener;
		size_t			j, listen_cnt;

 		listener = virtual_servers[i]->listener;
 		listen_cnt = talloc_array_length(listener);

		for (j = 0; j < listen_cnt; j++) {
			fr_virtual_listen_t *listen = listener[j];

			if (!listen || !listen->proto_module) continue; 		/* Skip old style */
			if (listen->app->open &&
			    listen->app->open(listen->proto_module->data, sc, listen->proto_module->conf) < 0) {
				cf_log_err(listen->proto_module->conf, "Opening %s I/O interface failed",
					   listen->app->name);
				return -1;
			}
		}

	}

	return 0;
}

/** Instantiate all the virtual servers
 *
 * @param[in] config	section containing all the virtual servers.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int virtual_servers_instantiate(UNUSED CONF_SECTION *config)
{
	size_t i, server_cnt = virtual_servers ? talloc_array_length(virtual_servers) : 0;

	rad_assert(virtual_servers);

	DEBUG2("%s: #### Instantiating listeners ####", main_config.name);

	for (i = 0; i < server_cnt; i++) {
		fr_virtual_listen_t	**listener;
		size_t			j, listen_cnt;

 		listener = virtual_servers[i]->listener;
 		listen_cnt = talloc_array_length(listener);

		for (j = 0; j < listen_cnt; j++) {
			fr_virtual_listen_t *listen = listener[j];

			if (!listen || !listen->proto_module) continue; 		/* Skip old style */
			if (listen->app->instantiate &&
			    listen->app->instantiate(listen->proto_module->data, listen->proto_module->conf) < 0) {
				cf_log_err(listen->proto_module->conf, "Instantiate failed");
				return -1;
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

	if (virtual_servers) {
		/*
		 *	Check the talloc hierarchy is sane
		 */
		talloc_get_type_abort(virtual_servers, fr_virtual_server_t *);
		server_cnt = talloc_array_length(virtual_servers);
	}

	DEBUG2("%s: #### Bootstrapping listeners ####", main_config.name);

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
		 *	Skip old-style virtual servers.
		 */
		if (!cf_pair_find(cs, "namespace")) {
			WARN("Skipping old-style server %s", cf_section_name2(cs));
		}
	}

	for (i = 0; i < server_cnt; i++) {
		fr_virtual_listen_t	**listener;
		size_t			j, listen_cnt;

		if (!virtual_servers[i] || !virtual_servers[i]->listener) continue;

 		listener = talloc_get_type_abort(virtual_servers[i]->listener, fr_virtual_listen_t *);
 		listen_cnt = talloc_array_length(listener);

		for (j = 0; j < listen_cnt; j++) {
			fr_virtual_listen_t *listen;

			if (!listener[j] || !listener[j]->proto_module) continue; 		/* Skip old style */

			listen = talloc_get_type_abort(listener[j], fr_virtual_listen_t);
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
 * @param[in] name of virtual server.
 * @return
 *	- NULL if no virtual server was found.
 *	- The CONF_SECTION of the named virtual server.
 */
CONF_SECTION *virtual_server_find(char const *name)
{
	return cf_section_find(main_config.config, "server", name);
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
	request->async->recv_time = fr_time();
	request->async->el = el;

	request->async->listen = NULL;
	request->async->packet_ctx = NULL;
	listener[0]->app->process_set(listener[0]->proto_module->data, request);
}
