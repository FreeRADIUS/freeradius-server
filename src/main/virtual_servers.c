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

static int default_component_results[MOD_COUNT] = {
	RLM_MODULE_REJECT,	/* AUTH */
	RLM_MODULE_NOTFOUND,	/* AUTZ */
	RLM_MODULE_NOOP,	/* PREACCT */
	RLM_MODULE_NOOP,	/* ACCT */
	RLM_MODULE_FAIL,	/* SESS */
	RLM_MODULE_NOOP,	/* PRE_PROXY */
	RLM_MODULE_NOOP,	/* POST_PROXY */
	RLM_MODULE_NOOP       	/* POST_AUTH */
#ifdef WITH_COA
	,
	RLM_MODULE_NOOP,       	/* RECV_COA_TYPE */
	RLM_MODULE_NOOP		/* SEND_COA_TYPE */
#endif
};

/**
 */
static rlm_rcode_t module_method_call(rlm_components_t comp, int idx, REQUEST *request)
{
	rlm_rcode_t	rcode;
	CONF_SECTION	*cs, *server_cs;
	char const	*module;
	char const	*component;

	rad_assert(request->server != NULL);

	/*
	 *	Cache the old server_cs in case it was changed.
	 *
	 *	FIXME: request->server should NOT be changed.
	 *	Instead, we should always create a child REQUEST when
	 *	we need to use a different virtual server.
	 *
	 *	This is mainly for things like proxying
	 */
	server_cs = request->server_cs;
	if (!server_cs || (strcmp(request->server, cf_section_name2(server_cs)) != 0)) {
		request->server_cs = cf_subsection_find_name2(main_config.config, "server", request->server);
	}

	cs = cf_subsection_find(request->server_cs, section_type_value[comp].section);
	if (!cs) {
		RDEBUG2("Empty %s section in virtual server \"%s\".  Using default return value %s.",
			section_type_value[comp].section, request->server,
			fr_int2str(mod_rcode_table, default_component_results[comp], "<invalid>"));
		return default_component_results[comp];
	}

	/*
	 *	Figure out which section to run.
	 */
	if (!idx) {
		RDEBUG("Running section %s from file %s",
		       section_type_value[comp].section, cf_section_filename(cs));

	} else {
		fr_dict_attr_t const *da;
		fr_dict_enum_t const *dv;
		CONF_SECTION *subcs;

		da = fr_dict_attr_by_num(NULL, 0, section_type_value[comp].attr);
		if (!da) return RLM_MODULE_FAIL;

		dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32((uint32_t)idx));
		if (!dv) return RLM_MODULE_FAIL;

		subcs = cf_subsection_find_name2(cs, da->name, dv->alias);
		if (!subcs) {
			RDEBUG2("%s %s sub-section not found.  Using default return values.",
				da->name, dv->alias);
			return default_component_results[comp];
		}

		RDEBUG("Running %s %s from file %s",
		       da->name, dv->alias, cf_section_filename(subcs));
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

#ifdef WITH_SESSION_MGMT
/*
 *	See if a user is already logged in.
 *
 *	Returns: 0 == OK, 1 == double logins, 2 == multilink attempt
 */
int process_checksimul(int sess_type, REQUEST *request, int maxsimul)
{
	rlm_rcode_t rcode;

	if (!request->username)
		return 0;

	request->simul_count = 0;
	request->simul_max = maxsimul;
	request->simul_mpp = 1;

	rcode = module_method_call(MOD_SESSION, sess_type, request);

	if (rcode != RLM_MODULE_OK) {
		/* FIXME: Good spot for a *rate-limited* warning to the log */
		return 0;
	}

	return (request->simul_count < maxsimul) ? 0 : request->simul_mpp;
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

static bool define_type(CONF_SECTION *cs, fr_dict_attr_t const *da, char const *name)
{
	fr_value_box_t	value = { .type = FR_TYPE_UINT32 };
	fr_dict_enum_t	*dval;

	/*
	 *	If the value already exists, don't
	 *	create it again.
	 */
	dval = fr_dict_enum_by_alias(NULL, da, name);
	if (dval) {
		if (dval->value == 0) {
			ERROR("The dictionaries must not define VALUE %s %s 0",
			      da->name, name);
			return false;
		}
		return true;
	}

	/*
	 *	Create a new unique value with a
	 *	meaningless number.  You can't look at
	 *	it from outside of this code, so it
	 *	doesn't matter.  The only requirement
	 *	is that it's unique.
	 */
	do {
		value.vb_uint32 = (fr_rand() & 0x00ffffff) + 1;
	} while (fr_dict_enum_by_value(NULL, da, &value));

	cf_log_module(cs, "Creating %s = %s", da->name, name);
	if (fr_dict_enum_add_alias(da, name, &value, true, false) < 0) {
		ERROR("%s", fr_strerror());
		return false;
	}

	return true;
}

/*
 *	Load a sub-module list, as found inside an Auth-Type foo {}
 *	block
 */
static bool load_subcomponent_section(CONF_SECTION *cs,
				      fr_dict_attr_t const *da, rlm_components_t comp)
{
	fr_dict_enum_t *dval;
	char const *name2 = cf_section_name2(cs);

	/*
	 *	Sanity check.
	 */
	if (!name2) return false;

	/*
	 *	We must assign a numeric index to this subcomponent.
	 *	It is generated and placed in the dictionary
	 *	automatically.  If it isn't found, it's a serious
	 *	error.
	 */
	dval = fr_dict_enum_by_alias(NULL, da, name2);
	if (!dval) {
		cf_log_err_cs(cs,
			      "The %s attribute has no VALUE defined for %s",
			      section_type_value[comp].typename, name2);
		return false;
	}

	/*
	 *	Compile the group.
	 */
	if (unlang_compile(cs, comp) < 0) {
		return false;
	}

	return true;
}

static int load_component_section(CONF_SECTION *cs, rlm_components_t comp)
{
	CONF_SECTION *subcs;
	fr_dict_attr_t const *da;

	/*
	 *	Find the attribute used to store VALUEs for this section.
	 */
	da = fr_dict_attr_by_num(NULL, 0, section_type_value[comp].attr);
	if (!da) {
		cf_log_err_cs(cs,
			      "No such attribute %s",
			      section_type_value[comp].typename);
		return -1;
	}

	/*
	 *	Compile the Autz-Type, Auth-Type, etc. first.
	 *
	 *	The results will be cached, so that the next
	 *	compilation will skip these sections.
	 */
	for (subcs = cf_subsection_find_next(cs, NULL, section_type_value[comp].typename);
	     subcs != NULL;
	     subcs = cf_subsection_find_next(cs, subcs, section_type_value[comp].typename)) {
		if (!load_subcomponent_section(subcs, da, comp)) {
			return -1; /* FIXME: memleak? */
		}
	}

	/*
	 *	Compile the section.
	 */
	if (unlang_compile(cs, comp) < 0) {
		cf_log_err_cs(cs, "Errors parsing %s section.\n",
			      cf_section_name1(cs));
		return -1;
	}

	return 0;
}

static int virtual_servers_compile(CONF_SECTION *cs)
{
	rlm_components_t comp;
	bool found;
	char const *name = cf_section_name2(cs);
	CONF_PAIR *cp;

	cf_log_info(cs, "server %s { # from file %s",
		    name, cf_section_filename(cs));

	cp = cf_pair_find(cs, "namespace");
	if (cp) {
		WARN("Virtual server %s uses new namespace.  Skipping old-stype configuration",
		     cf_section_name2(cs));
	}

	/*
	 *	Loop over all of the known components, finding their
	 *	configuration section, and loading it.
	 */
	found = false;
	for (comp = 0; comp < MOD_COUNT; ++comp) {
		CONF_SECTION *subcs;

		subcs = cf_subsection_find(cs,
					    section_type_value[comp].section);
		if (!subcs) continue;

		if (cp) {
			ERROR("Old-style configuration section '%s' found in new namespace.",
			      section_type_value[comp].section);
			return -1;
		}

		if (cf_item_find_next(subcs, NULL) == NULL) continue;

		/*
		 *	Skip pre/post-proxy sections if we're not
		 *	proxying.
		 */
		if (
#ifdef WITH_PROXY
!main_config.proxy_requests &&
#endif
((comp == MOD_PRE_PROXY) ||
 (comp == MOD_POST_PROXY))) {
			continue;
		}

#ifndef WITH_ACCOUNTING
		if (comp == MOD_ACCOUNTING) continue;
#endif

#ifndef WITH_SESSION_MGMT
		if (comp == MOD_SESSION) continue;
#endif

		if (load_component_section(subcs, comp) < 0) {
			if (rad_debug_lvl == 0) {
				ERROR("Failed to load virtual server \"%s\"", name);
			}
			return -1;
		}

		found = true;
	} /* loop over components */

	/*
	 *	We haven't loaded any of the RADIUS sections.  Maybe we're
	 *	supposed to load a non-RADIUS section.
	 */
	if (!found)
		do {
			CONF_SECTION *subcs;

			/*
			 *	Compile the listeners.
			 */
			for (subcs = cf_subsection_find_next(cs, NULL, "listen");
			     subcs != NULL;
			     subcs = cf_subsection_find_next(cs, subcs, "listen")) {
				if (listen_compile(cs, subcs) < 0) return -1;
			}

		} while (0);

	cf_log_info(cs, "} # server %s", name);

	if (rad_debug_lvl == 0) {
		INFO("Loaded virtual server %s", name);
	}

	return 0;
}

static bool virtual_server_define_types(CONF_SECTION *cs, rlm_components_t comp)
{
	fr_dict_attr_t const *da;
	CONF_SECTION *subcs;
	CONF_ITEM *ci;

	/*
	 *	Find the attribute used to store VALUEs for this section.
	 */
	da = fr_dict_attr_by_num(NULL, 0, section_type_value[comp].attr);
	if (!da) {
		cf_log_err_cs(cs,
			      "No such attribute %s",
			      section_type_value[comp].typename);
		return false;
	}

	/*
	 *	Compatibility hacks: "authenticate" sections can have
	 *	bare words in them.  Fix those up to be sections.
	 */
	if (comp == MOD_AUTHENTICATE) {
		for (ci = cf_item_find_next(cs, NULL);
		     ci != NULL;
		     ci = cf_item_find_next(cs, ci)) {
			CONF_PAIR *cp;

			if (!cf_item_is_pair(ci)) continue;

			cp = cf_item_to_pair(ci);

			subcs = cf_section_alloc(cs, section_type_value[comp].typename, cf_pair_attr(cp));
			rad_assert(subcs != NULL);
			cf_section_add(cs, subcs);
			cf_pair_add(subcs, cf_pair_dup(subcs, cp));
		}
	}

	/*
	 *	Define the Autz-Type, etc. based on the subsections.
	 */
	for (subcs = cf_subsection_find_next(cs, NULL, section_type_value[comp].typename);
	     subcs != NULL;
	     subcs = cf_subsection_find_next(cs, subcs, section_type_value[comp].typename)) {
		char const *name2;
		CONF_SECTION *cs2;

		name2 = cf_section_name2(subcs);
		cs2 = cf_subsection_find_name2(cs, section_type_value[comp].typename, name2);
		if (cs2 != subcs) {
			cf_log_err_cs(cs2, "Duplicate configuration section %s %s",
				      section_type_value[comp].typename, name2);
			return false;
		}

		if (!define_type(cs, da, name2)) {
			return false;
		}
	}

	return true;
}


/*
 *	Bootstrap Auth-Type, etc.
 */
int virtual_servers_bootstrap(CONF_SECTION *config)
{
	CONF_SECTION *cs;
	char const *server_name;

	if (!cf_subsection_find_next(config, NULL, "server")) {
		ERROR("No virtual servers found");
		return -1;
	}

	/*
	 *	Bootstrap global listeners.
	 */
	for (cs = cf_subsection_find_next(config, NULL, "listen");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "listen")) {
		if (cf_pair_find(cs, "namespace") != NULL) continue;

		if (listen_bootstrap(config, cs, NULL) < 0) return -1;
	}

	for (cs = cf_subsection_find_next(config, NULL, "server");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "server")) {
		CONF_ITEM *ci;
		CONF_SECTION *subcs;
		CONF_PAIR *cp;

		server_name = cf_section_name2(cs);
		if (!server_name) {
			cf_log_err_cs(cs, "server sections must have a name");
			return -1;
		}

		/*
		 *	Check for duplicates.
		 */
		subcs = cf_subsection_find_name2(config, "server", server_name);
		if (subcs && (subcs != cs)) {
			ERROR("Duplicate virtual server \"%s\", in file %s:%d and file %s:%d",
			      server_name,
			      cf_section_filename(cs),
			      cf_section_lineno(cs),
			      cf_section_filename(subcs),
			      cf_section_lineno(subcs));
			return -1;
		}

		/*
		 *	New-style virtual servers are special.
		 */
		cp = cf_pair_find(cs, "namespace");
		if (cp) {
			char const *value;
			dl_t const *module;
			fr_app_t const *app;

			value = cf_pair_value(cp);
			if (!value) {
				cf_log_err_cs(cs, "Cannot have empty namespace");
				return -1;
			}

			if (strcmp(value, "radius") != 0) {
				cf_log_err_cs(cs, "Unknown namespace '%s'", value);
				return -1;
			}

			module = dl_module(cs, NULL, value, DL_TYPE_PROTO);
			if (!module) {
				cf_log_err_cs(cs, "Failed to find library for 'namespace = %s'", value);
				return -1;
			}

			app = (fr_app_t const *) module->common;

			if (app->bootstrap && (app->bootstrap(cs) < 0)) {
				cf_log_err_cs(cs, "Failed to bootstrap library for 'namespace = %s'", value);
				return -1;
			}

			if (!app->instantiate) {
				cf_log_err_cs(cs, "Failed to find initialization function for 'transport = %s'",
					      value);
				return -1;
			}

			cf_data_add(cs, module, "app", false);
			continue;
		}

		for (ci = cf_item_find_next(cs, NULL);
		     ci != NULL;
		     ci = cf_item_find_next(cs, ci)) {
			rlm_components_t comp;
			char const *name1;

			if (cf_item_is_pair(ci)) {
				cf_log_err(ci, "Cannot set variables inside of a virtual server.");
				return -1;
			}

			if (!cf_item_is_section(ci)) continue;

			subcs = cf_item_to_section(ci);
			name1 = cf_section_name1(subcs);

			if (strcmp(name1, "listen") == 0) {
				if (listen_bootstrap(cs, subcs, server_name) < 0) return -1;
				continue;
			}

			/*
			 *	See if it's a RADIUS section.
			 */
			for (comp = 0; comp < MOD_COUNT; ++comp) {
				if (strcmp(name1, section_type_value[comp].section) == 0) {
					if (!virtual_server_define_types(subcs, comp)) return -1;
				}
			}
		} /* loop over things inside of a virtual server */
	} /* loop over virtual servers */

	return 0;
}

/*
 *	Load all of the virtual servers.
 */
int virtual_servers_init(fr_schedule_t *sc, CONF_SECTION *config)
{
	CONF_SECTION *cs;

	DEBUG2("%s: #### Loading Virtual Servers ####", main_config.name);

	/*
	 *	Load all of the virtual servers.
	 */
	for (cs = cf_subsection_find_next(config, NULL, "server");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "server")) {
		char const *name2;

		name2 = cf_section_name2(cs);

		/*
		 *	Skip new-style virtual servers.
		 */
		if (cf_pair_find(cs, "namespace")) {
			dl_t const *module;
			fr_app_t const *app;

			module = cf_data_find(cs, dl_t, "app");
			if (!module) continue;

			app = (fr_app_t const *) module->common;

			/*
			 *	@todo - create a scheduler
			 */

			cf_log_info(cs, "server %s { # from file %s",
				    name2, cf_section_filename(cs));
			cf_log_info(cs, "  namespace = %s", app->name);

			if (app->instantiate(sc, cs, check_config) < 0) {
				cf_log_err_cs(cs, "Failed loading virtual server %s", name2);
				return -1;
			}

			DEBUG("  Loaded Protocol %s", module->name);

			cf_log_info(cs, "} # server %s", name2);
			continue;
		}

		if (virtual_servers_compile(cs) < 0) {
			return -1;
		}
	}

	return 0;
}
