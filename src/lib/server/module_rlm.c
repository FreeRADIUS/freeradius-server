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
 * @file src/lib/server/module_rlm.c
 * @brief Defines functions for rlm module (re-)initialisation.
 *
 * @copyright 2003,2006,2016 The FreeRADIUS server project
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 * @copyright 2000 Alan Curry (pacman@world.std.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/cf_util.h>

#include <freeradius-devel/server/global_lib.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/virtual_servers.h>

#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dlist.h>

#include <freeradius-devel/unlang/compile.h>
#include <freeradius-devel/unlang/xlat_func.h>
#include <freeradius-devel/unlang/xlat_redundant.h>

/** Lookup virtual module by name
 */
static fr_rb_tree_t *module_rlm_virtual_name_tree;

typedef struct {
	fr_rb_node_t			name_node;	//!< Entry in the name tree.
	char const			*name;		//!< module name
	CONF_SECTION			*cs;		//!< CONF_SECTION where it is defined
	bool				all_same;
} module_rlm_virtual_t;

/** Compare virtual modules by name
 */
static int8_t module_rlm_virtual_name_cmp(void const *one, void const *two)
{
	module_rlm_virtual_t const *a = one;
	module_rlm_virtual_t const *b = two;
	int ret;

	ret = strcmp(a->name, b->name);
	return CMP(ret, 0);
}

/** Global module list for all backend modules
 *
 */
static module_list_t *rlm_modules_static;

/** Runtime instantiated list
 *
 */
static module_list_t *rlm_modules_dynamic;

/** Print information on all loaded modules
 *
 */
void module_rlm_list_debug(void)
{
	module_list_debug(rlm_modules_static);
}

/** Initialise a module specific exfile handle
 *
 * @see exfile_init
 *
 * @param[in] ctx		to bind the lifetime of the exfile handle to.
 * @param[in] module		section.
 * @param[in] max_entries	Max file descriptors to cache, and manage locks for.
 * @param[in] max_idle		Maximum time a file descriptor can be idle before it's closed.
 * @param[in] locking		Whether	or not to lock the files.
 * @param[in] trigger_prefix	if NULL will be set automatically from the module CONF_SECTION.
 * @param[in] trigger_args	to make available in any triggers executed by the connection pool.
 * @return
 *	- New connection pool.
 *	- NULL on error.
 */
exfile_t *module_rlm_exfile_init(TALLOC_CTX *ctx,
				 CONF_SECTION *module,
				 uint32_t max_entries,
				 fr_time_delta_t max_idle,
				 bool locking,
				 char const *trigger_prefix,
				 fr_pair_list_t *trigger_args)
{
	char		trigger_prefix_buff[128];
	exfile_t	*handle;

	if (!trigger_prefix) {
		snprintf(trigger_prefix_buff, sizeof(trigger_prefix_buff), "modules.%s.file", cf_section_name1(module));
		trigger_prefix = trigger_prefix_buff;
	}

	handle = exfile_init(ctx, max_entries, max_idle, locking);
	if (!handle) return NULL;

	exfile_enable_triggers(handle, cf_section_find(module, "file", NULL), trigger_prefix, trigger_args);

	return handle;
}

/** Resolve polymorphic item's from a module's #CONF_SECTION to a subsection in another module
 *
 * This allows certain module sections to reference module sections in other instances
 * of the same module and share #CONF_DATA associated with them.
 *
 * @verbatim
   example {
   	data {
   		...
   	}
   }

   example inst {
   	data = example
   }
 * @endverbatim
 *
 * @param[out] out where to write the pointer to a module's config section.  May be NULL on success,
 *	indicating the config item was not found within the module #CONF_SECTION
 *	or the chain of module references was followed and the module at the end of the chain
 *	did not a subsection.
 * @param[in] module #CONF_SECTION.
 * @param[in] name of the polymorphic sub-section.
 * @return
 *	- 0 on success with referenced section.
 *	- 1 on success with local section.
 *	- -1 on failure.
 */
int module_rlm_sibling_section_find(CONF_SECTION **out, CONF_SECTION *module, char const *name)
{
	CONF_PAIR		*cp;
	CONF_SECTION		*cs;
	CONF_DATA const		*cd;


	module_instance_t	*mi;
	char const		*inst_name;

#define FIND_SIBLING_CF_KEY "find_sibling"

	*out = NULL;

	/*
	 *	Is a real section (not referencing sibling module).
	 */
	cs = cf_section_find(module, name, NULL);
	if (cs) {
		*out = cs;

		return 0;
	}

	/*
	 *	Item omitted completely from module config.
	 */
	cp = cf_pair_find(module, name);
	if (!cp) return 0;

	if (cf_data_find(module, CONF_SECTION, FIND_SIBLING_CF_KEY)) {
		cf_log_err(cp, "Module reference loop found");

		return -1;
	}
	cd = cf_data_add(module, module, FIND_SIBLING_CF_KEY, false);

	/*
	 *	Item found, resolve it to a module instance.
	 *	This triggers module loading, so we don't have
	 *	instantiation order issues.
	 */
	inst_name = cf_pair_value(cp);
	mi = module_instance_by_name(rlm_modules_static, NULL, inst_name);
	if (!mi) {
		cf_log_err(cp, "Unknown module instance \"%s\"", inst_name);

		return -1;
	}

	if (mi->state != MODULE_INSTANCE_INSTANTIATED) {
		CONF_SECTION *parent = module;

		/*
		 *	Find the root of the config...
		 */
		do {
			CONF_SECTION *tmp;

			tmp = cf_item_to_section(cf_parent(parent));
			if (!tmp) break;

			parent = tmp;
		} while (true);

		if (unlikely(module_instantiate(module_instance_by_name(rlm_modules_static, NULL, inst_name)) < 0)) return -1;
	}

	/*
	 *	Remove the config data we added for loop
	 *	detection.
	 */
	cf_data_remove_by_data(module, cd);

	/*
	 *	Check the module instances are of the same type.
	 */
	if (strcmp(cf_section_name1(mi->conf), cf_section_name1(module)) != 0) {
		cf_log_err(cp, "Referenced module is a rlm_%s instance, must be a rlm_%s instance",
			      cf_section_name1(mi->conf), cf_section_name1(module));

		return -1;
	}

	*out = cf_section_find(mi->conf, name, NULL);

	return 1;
}

/** Initialise a module specific connection pool
 *
 * @see fr_pool_init
 *
 * @param[in] module		section.
 * @param[in] opaque		data pointer to pass to callbacks.
 * @param[in] c			Callback to create new connections.
 * @param[in] a			Callback to check the status of connections.
 * @param[in] log_prefix	override, if NULL will be set automatically from the module CONF_SECTION.
 * @param[in] trigger_prefix	if NULL will be set automatically from the module CONF_SECTION.
 * @param[in] trigger_args	to make available in any triggers executed by the connection pool.
 * @return
 *	- New connection pool.
 *	- NULL on error.
 */
fr_pool_t *module_rlm_connection_pool_init(CONF_SECTION *module,
					   void *opaque,
					   fr_pool_connection_create_t c,
					   fr_pool_connection_alive_t a,
					   char const *log_prefix,
					   char const *trigger_prefix,
					   fr_pair_list_t *trigger_args)
{
	CONF_SECTION *cs, *mycs;
	char log_prefix_buff[128];
	char trigger_prefix_buff[128];

	fr_pool_t *pool;
	char const *cs_name1, *cs_name2;

	int ret;

#define parent_name(_x) cf_section_name(cf_item_to_section(cf_parent(_x)))

	cs_name1 = cf_section_name1(module);
	cs_name2 = cf_section_name2(module);
	if (!cs_name2) cs_name2 = cs_name1;

	if (!trigger_prefix) {
		snprintf(trigger_prefix_buff, sizeof(trigger_prefix_buff), "modules.%s.pool", cs_name1);
		trigger_prefix = trigger_prefix_buff;
	}

	if (!log_prefix) {
		snprintf(log_prefix_buff, sizeof(log_prefix_buff), "rlm_%s (%s)", cs_name1, cs_name2);
		log_prefix = log_prefix_buff;
	}

	/*
	 *	Get sibling's pool config section
	 */
	ret = module_rlm_sibling_section_find(&cs, module, "pool");
	switch (ret) {
	case -1:
		return NULL;

	case 1:
		DEBUG4("%s: Using pool section from \"%s\"", log_prefix, parent_name(cs));
		break;

	case 0:
		DEBUG4("%s: Using local pool section", log_prefix);
		break;
	}

	/*
	 *	Get our pool config section
	 */
	mycs = cf_section_find(module, "pool", NULL);
	if (!mycs) {
		DEBUG4("%s: Adding pool section to config item \"%s\" to store pool references", log_prefix,
		       cf_section_name(module));

		mycs = cf_section_alloc(module, module, "pool", NULL);
	}

	/*
	 *	Sibling didn't have a pool config section
	 *	Use our own local pool.
	 */
	if (!cs) {
		DEBUG4("%s: \"%s.pool\" section not found, using \"%s.pool\"", log_prefix,
		       parent_name(cs), parent_name(mycs));
		cs = mycs;
	}

	/*
	 *	If fr_pool_init has already been called
	 *	for this config section, reuse the previous instance.
	 *
	 *	This allows modules to pass in the config sections
	 *	they would like to use the connection pool from.
	 */
	pool = cf_data_value(cf_data_find(cs, fr_pool_t, NULL));
	if (!pool) {
		DEBUG4("%s: No pool reference found for config item \"%s.pool\"", log_prefix, parent_name(cs));
		pool = fr_pool_init(cs, cs, opaque, c, a, log_prefix);
		if (!pool) return NULL;

		fr_pool_enable_triggers(pool, trigger_prefix, trigger_args);

		if (fr_pool_start(pool) < 0) {
			ERROR("%s: Starting initial connections failed", log_prefix);
			return NULL;
		}

		DEBUG4("%s: Adding pool reference %p to config item \"%s.pool\"", log_prefix, pool, parent_name(cs));
		cf_data_add(cs, pool, NULL, false);
		return pool;
	}
	fr_pool_ref(pool);

	DEBUG4("%s: Found pool reference %p in config item \"%s.pool\"", log_prefix, pool, parent_name(cs));

	/*
	 *	We're reusing pool data add it to our local config
	 *	section. This allows other modules to transitively
	 *	reuse a pool through this module.
	 */
	if (mycs != cs) {
		DEBUG4("%s: Copying pool reference %p from config item \"%s.pool\" to config item \"%s.pool\"",
		       log_prefix, pool, parent_name(cs), parent_name(mycs));
		cf_data_add(mycs, pool, NULL, false);
	}

	return pool;
}

/*
 *	Convert a string to an integer
 */
module_method_t module_rlm_state_str_to_method(module_state_func_table_t const *table,
					       char const *name, module_method_t def)
{
	module_state_func_table_t const *this;

	if (!name) return def;

	for (this = table; this->name != NULL; this++) {
		if (strcasecmp(this->name, name) == 0) return this->func;
	}

	return def;
}

/*
 *	Convert an integer to a string.
 */
char const *module_rlm_state_method_to_str(module_state_func_table_t const *table,
					   module_method_t method, char const *def)
{
	module_state_func_table_t const *this;

	for (this = table; this->name != NULL; this++) if (this->func == method) return this->name;

	return def;
}

/** Set the next section type if it's not already set
 *
 * @param[in] request		The current request.
 * @param[in] type_da		to use.  Usually attr_auth_type.
 * @param[in] enumv		Enumeration value of the specified type_da.
 */
bool module_rlm_section_type_set(request_t *request, fr_dict_attr_t const *type_da, fr_dict_enum_value_t const *enumv)
{
	fr_pair_t *vp;

	switch (pair_update_control(&vp, type_da)) {
	case 0:
		fr_value_box_copy(vp, &vp->data, enumv->value);
		vp->data.enumv = vp->da;	/* So we get the correct string alias */
		RDEBUG2("Setting &control.%pP", vp);
		return true;

	case 1:
		RDEBUG2("&control.%s already set.  Not setting to %s", vp->da->name, enumv->name);
		return false;

	default:
		return false;
	}
}

/** Find an existing module instance and verify it implements the specified method
 *
 * Extracts the method from the module name where the format is @verbatim <module>.<method> @endverbatim
 * and ensures the module implements the specified method.
 *
 * @param[out] method		the method function we will call
 * @param[out] method_env	the module_call_env to evaluate when compiling the method.
 * @param[out] name1		name1 of the method being called
 * @param[out] name2		name2 of the method being called
 * @param[in] name 		The name of the module we're attempting to find, possibly concatenated with the method
 * @return
 *	- The module instance on success.
 *	- NULL on not found
 *
 *  If the module exists but the method doesn't exist, then `method` is set to NULL.
 */
module_instance_t *module_rlm_by_name_and_method(module_method_t *method, call_env_method_t const **method_env,
						 char const **name1, char const **name2,
						 virtual_server_t const *vs, char const *name)
{
	char				*p, *q, *inst_name;
	size_t				len;
	int				j;
	module_instance_t		*mi;
	module_method_binding_t const	*methods;
	char const			*method_name1, *method_name2;
	module_rlm_t const		*mrlm;

	if (method) *method = NULL;

	method_name1 = method_name2 = NULL;
	if (name1) {
		method_name1 = *name1;
		*name1 = NULL;
	}
	if (name2) {
		method_name2 = *name2;
		*name2 = NULL;
	}

	/*
	 *	Module names are allowed to contain '.'
	 *	so we search for the bare module name first.
	 */
	mi = module_rlm_static_by_name(NULL, name);
	if (mi) {
		section_name_t const	**allowed_list;

		if (!method) return mi;

		mrlm = module_rlm_from_module(mi->exported);

		/*
		 *	We're not searching for a named method, OR the
		 *	module has no named methods.  Try to return a
		 *	method based on the component.
		 */
		if (!method_name1 || !mrlm->bindings) goto return_component;

		/*
		 *	Walk through the module, finding a matching
		 *	method.
		 */
		for (j = 0; mrlm->bindings[j].section; j++) {
			methods = &mrlm->bindings[j];

			/*
			 *	Wildcard match name1, we're
			 *	done.
			 */
			if (methods->section->name1 == CF_IDENT_ANY) {
			found:
				*method = methods->method;
				if (method_env) *method_env = methods->method_env;
				if (name1) *name1 = method_name1;
				if (name2) *name2 = method_name2;
				return mi;
			}

			/*
			 *	If name1 doesn't match, skip it.
			 */
			if (strcasecmp(methods->section->name1, method_name1) != 0) continue;

			/*
			 *	The module can declare a
			 *	wildcard for name2, in which
			 *	case it's a match.
			 */
			if (methods->section->name2 == CF_IDENT_ANY) goto found;

			/*
			 *	No name2 is also a match to no name2.
			 */
			if (!methods->section->name2 && !method_name2) goto found;

			/*
			 *	Don't do strcmp on NULLs
			 */
			if (!methods->section->name2 || !method_name2) continue;

			if (strcasecmp(methods->section->name2, method_name2) == 0) goto found;
		}

		if (!vs) goto skip_section_method;

		/*
		 *	No match for "recv Access-Request", or
		 *	whatever else the section is.  Let's see if
		 *	the section has a list of allowed methods.
		 */
		allowed_list = virtual_server_section_methods(vs, method_name1, method_name2);
		if (!allowed_list) goto return_component;

		/*
		 *	Walk over allowed methods for this section,
		 *	(implicitly ordered by priority), and see if
		 *	the allowed method matches any of the module
		 *	methods.  This process lets us reference a
		 *	module as "foo" in the configuration.  If the
		 *	module exports a "recv bar" method, and the
		 *	virtual server has a "recv bar" processing
		 *	section, then they should match.
		 *
		 *	Unfortunately, this process is O(N*M).
		 *	Luckily, we only do it if all else fails, so
		 *	it's mostly OK.
		 *
		 *	Note that the "allowed" list CANNOT include
		 *	CF_IDENT_ANY.  Only the module can do that.
		 *	If the "allowed" list exported CF_IDENT_ANY,
		 *	then any module method would match, which is
		 *	bad.
		 */
		for (j = 0; allowed_list[j]; j++) {
			int k;
			section_name_t const *allowed = allowed_list[j];

			for (k = 0; mrlm->bindings[k].section; k++) {
				methods = &mrlm->bindings[k];

				fr_assert(methods->section->name1 != CF_IDENT_ANY); /* should have been caught above */

				if (strcasecmp(methods->section->name1, allowed->name1) != 0) continue;

				/*
				 *	The module matches "recv *",
				 *	call this method.
				 */
				if (methods->section->name2 == CF_IDENT_ANY) {
				found_allowed:
					*method = methods->method;
					return mi;
				}

				/*
				 *	No name2 is also a match to no name2.
				 */
				if (!methods->section->name2 && !allowed->name2) goto found_allowed;

				/*
				 *	Don't do strcasecmp on NULLs
				 */
				if (!methods->section->name2 || !allowed->name2) continue;

				if (strcasecmp(methods->section->name2, allowed->name2) == 0) goto found_allowed;
			}
		}

	return_component:
		/*
		 *	Didn't find a matching method.  Just return
		 *	the module.
		 */
		return mi;
	}

skip_section_method:

	/*
	 *	Find out if the instance name contains
	 *	a method, if it doesn't, then the module
	 *	doesn't exist.
	 */
	p = strchr(name, '.');
	if (!p) {
		fr_strerror_printf("No such module '%s'", name);
		return NULL;
	}

	/*
	 *	The module name may have a '.' in it, AND it may have
	 *	a method <sigh> So we try to find out which is which.
	 */
	inst_name = talloc_strdup(NULL, name);
	p = inst_name + (p - name);

	/*
	 *	Loop over the '.' portions, gradually looking up a
	 *	longer string, in order to find the full module name.
	 */
	do {
		*p = '\0';

		mi = module_instance_by_name(rlm_modules_static, NULL, inst_name);
		if (mi) break;

		/*
		 *	Find the next '.'
		 */
		*p = '.';
		p = strchr(p + 1, '.');
	} while (p);

	/*
	 *	No such module, we're done.
	 */
	if (!mi) {
		fr_strerror_printf("Failed to find module '%s'", inst_name);
		talloc_free(inst_name);
		return NULL;
	}

	mrlm = module_rlm_from_module(mi->exported);

	/*
	 *	We have a module, but the caller doesn't care about
	 *	method or names, so just return the module.
	 */
	if (!method || !method_name1 || !method_name2) goto finish;

	/*
	 *	We MAY have two names.
	 */
	p++;
	q = strchr(p, '.');
	/*
	 *	We've found the module, but it has no named methods.
	 */
	if (!mrlm->bindings) {
		*name1 = name + (p - inst_name);
		*name2 = NULL;
		goto finish;
	}

	/*
	 *	We have "module.METHOD", but METHOD doesn't match
	 *	"authorize", "authenticate", etc.  Let's see if it
	 *	matches anything else.
	 */
	if (!q) {
		for (j = 0; mrlm->bindings[j].section; j++) {
			methods = &mrlm->bindings[j];

			/*
			 *	If we do not have the second $method, then ignore it!
			 */
			if (methods->section->name2 && (methods->section->name2 != CF_IDENT_ANY)) continue;

			/*
			 *	Wildcard match name1, we're
			 *	done.
			 */
			if (!methods->section->name1 || (methods->section->name1 == CF_IDENT_ANY)) goto found_name1;

			/*
			 *	If name1 doesn't match, skip it.
			 */
			if (strcasecmp(methods->section->name1, p) != 0) continue;

		found_name1:
			/*
			 *	We've matched "*", or "name1" or
			 *	"name1 *".  Return that.
			 */
			*name1 = name + (p - inst_name);
			*name2 = NULL;
			*method = methods->method;
			if (method_env) *method_env = methods->method_env;
			break;
		}

		/*
		 *	Return the found module.
		 */
		goto finish;
	}

	/*
	 *	We CANNOT have '.' in method names.
	 */
	if (strchr(q + 1, '.') != 0) goto finish;

	len = q - p;

	/*
	 *	Trim the '.'.
	 */
	if (*q == '.' && *(q + 1)) q++;

	/*
	 *	We have "module.METHOD1.METHOD2".
	 *
	 *	Loop over the method names, seeing if we have a match.
	 */
	for (j = 0; mrlm->bindings[j].section; j++) {
		methods = &mrlm->bindings[j];

		/*
		 *	If name1 doesn't match, skip it.
		 */
		if (strncasecmp(methods->section->name1, p, len) != 0) continue;

		/*
		 *	It may have been a partial match, like "rec",
		 *	instead of "recv".  In which case check if it
		 *	was a FULL match.
		 */
		if (strlen(methods->section->name1) != len) continue;

		/*
		 *	The module can declare a
		 *	wildcard for name2, in which
		 *	case it's a match.
		 */
		if (!methods->section->name2 || (methods->section->name2 == CF_IDENT_ANY)) goto found_name2;

		/*
		 *	Don't do strcmp on NULLs
		 */
		if (!methods->section->name2) continue;

		if (strcasecmp(methods->section->name2, q) != 0) continue;

	found_name2:
		/*
		 *	Update name1/name2 with the methods
		 *	that were found.
		 */
		*name1 = methods->section->name1;
		*name2 = name + (q - inst_name);
		*method = methods->method;
		if (method_env) *method_env = methods->method_env;
		goto finish;
	}

	*name1 = name + (p - inst_name);
	*name2 = NULL;

finish:
	talloc_free(inst_name);
	return mi;
}

CONF_SECTION *module_rlm_by_name_virtual(char const *asked_name)
{
	module_rlm_virtual_t *inst;

	inst = fr_rb_find(module_rlm_virtual_name_tree,
			  &(module_rlm_virtual_t){
				.name = asked_name,
			  });
	if (!inst) return NULL;

	return inst->cs;
}

module_instance_t *module_rlm_static_by_name(module_instance_t const *parent, char const *asked_name)
{
	return module_instance_by_name(rlm_modules_static, parent, asked_name);
}

/** Create a virtual module.
 *
 * @param[in] cs	that defines the virtual module.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int module_rlm_bootstrap_virtual(CONF_SECTION *cs)
{
	char const		*name;
	bool			all_same;
	module_t const 		*last = NULL;
	CONF_ITEM 		*sub_ci = NULL;
	CONF_PAIR		*cp;
	module_instance_t	*mi;
	module_rlm_virtual_t	*inst;

	name = cf_section_name1(cs);

	/*
	 *	Groups, etc. must have a name.
	 */
	if ((strcmp(name, "group") == 0) ||
	    (strcmp(name, "redundant") == 0) ||
	    (strcmp(name, "redundant-load-balance") == 0) ||
	    (strcmp(name, "load-balance") == 0)) {
		name = cf_section_name2(cs);
		if (!name) {
			cf_log_err(cs, "Keyword module must have a second name");
			return -1;
		}

		/*
		 *	name2 was already checked in modules_rlm_bootstrap()
		 */
		fr_assert(!unlang_compile_is_keyword(name));
	} else {
		cf_log_err(cs, "Module names cannot be unlang keywords '%s'", name);
		return -1;
	}

	/*
	 *	Ensure that the module doesn't exist.
	 */
	mi = module_instance_by_name(rlm_modules_static, NULL, name);
	if (mi) {
		ERROR("Duplicate module \"%s\" in file %s[%d] and file %s[%d]",
		      name,
		      cf_filename(cs),
		      cf_lineno(cs),
		      cf_filename(mi->conf),
		      cf_lineno(mi->conf));
		return -1;
	}

	/*
	 *	Don't bother registering redundant xlats for a simple "group".
	 */
	all_same = (strcmp(cf_section_name1(cs), "group") != 0);

	/*
	 *	Ensure that the modules we reference here exist.
	 */
	while ((sub_ci = cf_item_next(cs, sub_ci))) {
		if (cf_item_is_pair(sub_ci)) {
			cp = cf_item_to_pair(sub_ci);
			if (cf_pair_value(cp)) {
				cf_log_err(sub_ci, "Cannot set return codes in a %s block", cf_section_name1(cs));
				return -1;
			}

			/*
			 *	Allow "foo.authorize" in subsections.
			 *
			 *	Note that we don't care what the method is, just that it exists.
			 *
			 *	This check is needed only because we
			 *	want to know if we need to register a
			 *	redundant xlat for the virtual module.
			 */
			mi = module_rlm_by_name_and_method(NULL, NULL, NULL, NULL, NULL, cf_pair_attr(cp));
			if (!mi) {
				cf_log_err(sub_ci, "Module instance \"%s\" referenced in %s block, does not exist",
					   cf_pair_attr(cp), cf_section_name1(cs));
				return -1;
			}

			if (all_same) {
				if (!last) {
					last = mi->exported;
				} else if (last != mi->exported) {
					last = NULL;
					all_same = false;
				}
			}
		} else {
			all_same = false;
		}

		/*
		 *	Don't check subsections for now.  That check
		 *	happens later in the unlang compiler.
		 */
	} /* loop over things in a virtual module section */

	inst = talloc_zero(cs, module_rlm_virtual_t);
	if (!inst) return -1;

	inst->cs = cs;
	MEM(inst->name = talloc_strdup(inst, name));
	inst->all_same = all_same;

	if (!fr_cond_assert(fr_rb_insert(module_rlm_virtual_name_tree, inst))) {
		talloc_free(inst);
		return -1;
	}

	return 0;
}

/** Generic conf_parser_t func for loading drivers
 *
 */
int module_rlm_submodule_parse(TALLOC_CTX *ctx, void *out, void *parent,
			       CONF_ITEM *ci, conf_parser_t const *rule)
{
	conf_parser_t our_rule = *rule;

	our_rule.uctx = &rlm_modules_static;

	return module_submodule_parse(ctx, out, parent, ci, &our_rule);
}

/** Frees thread-specific data for all registered backend modules
 *
 */
void modules_rlm_thread_detach(void)
{
	modules_thread_detach(rlm_modules_static);
}

/** Allocates thread-specific data for all registered backend modules
 *
 * @param[in] ctx	To allocate any thread-specific data in.
 * @param[in] el	to register events.
 * @return
 *	- 0 if all modules were instantiated successfully.
 *	- -1 if a module failed instantiation.
 */
int modules_rlm_thread_instantiate(TALLOC_CTX *ctx, fr_event_list_t *el)
{
	return modules_thread_instantiate(ctx, rlm_modules_static, el);
}

/** Performs the instantiation phase for all backend modules
 *
 * @return
 *	- 0 if all modules were instantiated successfully.
 *	- -1 if a module failed instantiation.
 */
int modules_rlm_instantiate(void)
{
	return modules_instantiate(rlm_modules_static);
}

/** Compare the section names of two module_method_binding_t structures
 */
static int8_t binding_name_cmp(void const *one, void const *two)
{
	module_method_binding_t const *a = one;
	module_method_binding_t const *b = two;

	return section_name_cmp(a->section, b->section);
}

static int module_method_validate(module_instance_t *mi)
{
	module_method_binding_t *p, *srt_p;
	module_rlm_t const	*mrlm;
	fr_dlist_head_t		bindings;
	bool			in_order = true;

	mrlm = module_rlm_from_module(mi->exported);

	fr_dlist_init(&bindings, module_method_binding_t, entry);

	/*
	 *	Not all modules export module method bindings
	 */
	if (!mrlm->bindings) return 0;

	for (p = mrlm->bindings; p->section; p++) {
		if (!fr_cond_assert_msg(p->section->name1,
					"%s: First section identifier can't be NULL", mi->name)) return -1;
		if (!fr_cond_assert_msg(p->section->name1 || p->section->name2,
					"%s: Section identifiers can't both be null", mi->name)) return -1;

		/*
		 *	All the bindings go in a list so we can sort them
		 *	and produce the list in the correct order.
		 */
		fr_dlist_insert_tail(&bindings, p);
	}

	fr_dlist_sort(&bindings, binding_name_cmp);

	/*
	 *	Iterate over the sorted list of bindings,
	 *	and the original list, to ensure they're
	 *	in the correct order.
	 */
	for (srt_p = fr_dlist_head(&bindings), p = mrlm->bindings;
	     srt_p;
	     srt_p = fr_dlist_next(&bindings, srt_p), p++) {
		if (p != srt_p) {
			in_order = false;
			break;
		}
#if 0
		{
			module_method_binding_t const *pp;
			/*
			*	Print the correct order of bindings
			*/
			FR_FAULT_LOG("%s: Module method bindings are not in the correct order, the correct order is:", mi->name);
			FR_FAULT_LOG(".bindings = (module_method_binding_t[]){");
			for (pp = fr_dlist_head(&bindings);
				pp;
				pp = fr_dlist_next(&bindings, pp)) {
				char const *name1_quote = (pp->section->name1 && (pp->section->name1 != CF_IDENT_ANY)) ? "\"" : "";
				char const *name2_quote = (pp->section->name2 && (pp->section->name2 != CF_IDENT_ANY)) ? "\"" : "";
				char const *name1 = pp->section->name1;
				char const *name2 = pp->section->name2;

				if (name1 == CF_IDENT_ANY) {
					name1 = "CF_IDENT_ANY";
				} else if (!name1) {
					name1 = "NULL";
				}
				if (name2 == CF_IDENT_ANY) {
					name2 = "CF_IDENT_ANY";
				} else if (!name2) {
					name2 = "NULL";
				}

				FR_FAULT_LOG("\t.section = SECTION_NAME(%s%s%s, %s%s%s)",
						name1_quote, name1, name1_quote,
						name2_quote, name2, name2_quote);
			}
			FR_FAULT_LOG("}");
		}
#endif
	}

	/*
	 *	Rebuild the binding list in the correct order.
	 */
	if (!in_order) {
		module_method_binding_t *ordered;

		MEM(ordered = talloc_array(NULL, module_method_binding_t, fr_dlist_num_elements(&bindings)));
		for (srt_p = fr_dlist_head(&bindings), p = ordered;
		     srt_p;
		     srt_p = fr_dlist_next(&bindings, srt_p), p++) {
			*p = *srt_p;
		}
		memcpy(mrlm->bindings, ordered, fr_dlist_num_elements(&bindings) * sizeof(*ordered));
		talloc_free(ordered);
	}

	/*
	 *	Build the "skip" list of name1 entries
	 */
	{
		module_method_binding_t *last_binding = NULL;

		for (p = mrlm->bindings; p->section; p++) {
			if (!last_binding ||
				(
					(last_binding->section->name1 != p->section->name1) &&
					(
						(last_binding->section->name1 == CF_IDENT_ANY) ||
						(p->section->name1 == CF_IDENT_ANY) ||
						(strcmp(last_binding->section->name1, p->section->name1) != 0)
					)
				)
			) {
				fr_dlist_init(&p->same_name1, module_method_binding_t, entry);
				last_binding = p;
			}
			fr_dlist_insert_tail(&last_binding->same_name1, p);
		}
	}

	return 0;
}

/** Allocate a rlm module instance
 *
 * These have extra space allocated to hold the dlist of associated xlats.
 *
 * @param[in] ml		Module list to allocate from.
 * @param[in] parent		Parent module instance.
 * @param[in] type		Type of module instance.
 * @param[in] mod_name		Name of the module.
 * @param[in] inst_name		Name of the instance.
 * @param[in] init_state	Initial state of the module instance.
 * @return
 *	- The allocated module instance on success.
 *	- NULL on failure.
 */
static inline CC_HINT(always_inline)
module_instance_t *module_rlm_instance_alloc(module_list_t *ml,
					     module_instance_t const *parent,
					     dl_module_type_t type, char const *mod_name, char const *inst_name,
					     module_instance_state_t init_state)
{
	module_instance_t *mi;
	module_rlm_instance_t *mri;

	mi = module_instance_alloc(ml, parent, type, mod_name, inst_name, init_state);
	if (unlikely(mi == NULL)) return NULL;

	MEM(mri = talloc(mi, module_rlm_instance_t));
	module_instance_uctx_set(mi, mri);
	fr_rb_inline_init(&mri->xlats, module_rlm_xlat_t, node, xlat_func_cmp, NULL);

	return mi;
}

static int module_conf_parse(module_list_t *ml, CONF_SECTION *mod_conf)
{
	char const		*name;
	char const		*inst_name;
	module_instance_t	*mi = NULL;
	CONF_SECTION		*actions;

	/*
	 *	name2 can't be a keyword
	 */
	name = cf_section_name2(mod_conf);
	if (name && unlang_compile_is_keyword(name)) {
	invalid_name:
		cf_log_err(mod_conf, "Module names cannot be unlang keywords '%s'", name);
		return -1;
	}

	name = cf_section_name1(mod_conf);

	/*
	 *	For now, ignore name1 which is a keyword.
	 */
	if (unlang_compile_is_keyword(name)) {
		if (!cf_section_name2(mod_conf)) {
			cf_log_err(mod_conf, "Missing second name at '%s'", name);
			return -1;
		}
		if (module_rlm_bootstrap_virtual(mod_conf) < 0) return -1;
		return 0;
	}

	/*
	 *	Skip inline templates, and disallow "template { ... }"
	 */
	if (strcmp(name, "template") == 0) {
		if (!cf_section_name2(mod_conf)) goto invalid_name;
		return 0;
	}

	if (module_instance_name_from_conf(&inst_name, mod_conf) < 0) goto invalid_name;

	mi = module_rlm_instance_alloc(ml, NULL, DL_MODULE_TYPE_MODULE, name, inst_name, 0);
	if (unlikely(mi == NULL)) {
		cf_log_perr(mod_conf, "Failed loading module");
		return -1;
	}

	/*
	 *	First time we've loaded the dl module, so we need to
	 *	check the module methods to make sure they're ordered
	 *	correctly, and to add the "skip list" style name2
	 *	entries.
	 */
	if ((mi->module->refs == 1) && (module_method_validate(mi) < 0)) {
		talloc_free(mi);
		return -1;
	}

	if (module_instance_conf_parse(mi, mod_conf) < 0) {
		cf_log_perr(mod_conf, "Failed parsing module config");
		talloc_free(mi);
		return -1;
	}

	/*
	 *	Compile the default "actions" subsection, which includes retries.
	 */
	actions = cf_section_find(mod_conf, "actions", NULL);
	if (actions && unlang_compile_actions(&mi->actions, actions, (mi->exported->flags & MODULE_TYPE_RETRY) != 0)) {
		talloc_free(mi);
		return -1;
	}

	return 0;
}

/** Bootstrap modules and virtual modules
 *
 * Parse the module config sections, and load and call each module's init() function.
 *
 * @param[in] root of the server configuration.
 * @return
 *	- 0 if all modules were bootstrapped successfully.
 *	- -1 if a module/virtual module failed to bootstrap.
 */
int modules_rlm_bootstrap(CONF_SECTION *root)
{
	CONF_SECTION		*cs, *modules, *static_cs, *dynamic_cs;
	module_rlm_virtual_t	*vm;
	fr_rb_iter_inorder_t	iter;

	/*
	 *	Ensure any libraries the modules depend on are instantiated
	 */
	global_lib_instantiate();

	/*
	 *	Remember where the modules were stored.
	 */
	modules = cf_section_find(root, "modules", NULL);
	if (!modules) {
		WARN("Cannot find a \"modules\" section in the configuration file!");
		return 0;
	}

	static_cs = cf_section_find(modules, "static", NULL);
	if (!static_cs) {
		static_cs = cf_section_alloc(modules, NULL, "static", NULL);
		cf_section_foreach(modules, mod_cs) {
			CONF_ITEM *prev;

			/*
			 *	Skip over the dynamic section
			 */
			if ((strcmp(cf_section_name1(mod_cs), "dynamic") == 0) &&
			    cf_section_name2(mod_cs) == NULL) continue;

			/*
			 *	Move all modules which are not in
			 *	the dynamic section into the static
			 *	section for backwards compatibility.
			 */
			prev = cf_item_remove(modules, mod_cs);
			cf_item_add(static_cs, mod_cs);

			/*
			 *	Find the previous item that's a section
			 */
			while (prev && !cf_item_is_section(prev)) prev = cf_item_prev(modules, prev);

			/*
			 *	Resume iterating from that item
			 */
			mod_cs = cf_item_to_section(prev);
		}
		cf_item_add(modules, static_cs);
	}
	DEBUG2("#### Bootstrapping static modules ####");
	cf_log_debug(modules, " modules {");
	cf_log_debug(modules, "    static {");
	cf_section_foreach(static_cs, mod_conf) {
		if (module_conf_parse(rlm_modules_static, mod_conf) < 0) return -1;
	}
	cf_log_debug(modules, "    } # static");

	/*
	 *	Now we have a module tree, run bootstrap on all the modules.
	 *	This will bootstrap modules and then submodules.
	 */
	if (unlikely(modules_bootstrap(rlm_modules_static) < 0)) return -1;

	if (fr_command_register_hook(NULL, NULL, static_cs, module_cmd_list_table) < 0) {
		PERROR("Failed registering radmin commands for modules");
		return -1;
	}

	/*
	 *	Build the configuration and parse dynamic modules
	 */
	dynamic_cs = cf_section_find(modules, "dynamic", NULL);
	if (dynamic_cs) {
		DEBUG2("#### Bootstrapping dynamic modules ####");
		/*
		*	Parse and then instantiate any dynamic modules configure
		*/
		cf_log_debug(modules, "    dynamic {");
		cf_section_foreach(dynamic_cs, mod_conf) {
			if (unlikely(module_conf_parse(rlm_modules_dynamic, mod_conf) < 0)) return -1;
		}
		cf_log_debug(modules, "    } # dynamic");
		if (unlikely(modules_bootstrap(rlm_modules_dynamic) < 0)) return -1;
		cf_log_debug(modules, " } # modules");
	}

	/*
	 *	Check for duplicate policies.  They're treated as
	 *	modules, so we might as well check them here.
	 */
	cs = cf_section_find(root, "policy", NULL);
	if (cs) {
		cf_section_foreach(cs, policy_cs) {
			CONF_SECTION	*problemcs;
			char const	*name1 = cf_section_name1(policy_cs);

			if (unlang_compile_is_keyword(name1)) {
				cf_log_err(policy_cs, "Policy name '%s' cannot be an unlang keyword", name1);
				return -1;
			}

			if (cf_section_name2(policy_cs)) {
				cf_log_err(policy_cs, "Policies cannot have two names");
				return -1;
			}

			problemcs = cf_section_find_next(cs, policy_cs, name1, CF_IDENT_ANY);
			if (!problemcs) continue;

			cf_log_err(problemcs, "Duplicate policy '%s' is forbidden.",
				   cf_section_name1(policy_cs));
			return -1;
		}
	}

	/*
	 *	Now that all of the xlat things have been registered,
	 *	register our redundant xlats.  But only when all of
	 *	the items in such a section are the same.
	 */
	for (vm = fr_rb_iter_init_inorder(&iter, module_rlm_virtual_name_tree);
	     vm;
	     vm = fr_rb_iter_next_inorder(&iter)) {
		if (!vm->all_same) continue;

		if (xlat_register_redundant(vm->cs) < 0) return -1;
	}

	return 0;
}

/** Cleanup all global structures
 *
 * Automatically called on exit.
 */
int modules_rlm_free(void)
{
	if (talloc_free(rlm_modules_static) < 0) return -1;
	rlm_modules_static = NULL;
	if (talloc_free(module_rlm_virtual_name_tree) < 0) return -1;
	module_rlm_virtual_name_tree = NULL;

	return 0;
}

static int _modules_rlm_free_atexit(UNUSED void *uctx)
{
	return modules_rlm_free();
}

/** Initialise the module list structure
 *
 */
int modules_rlm_init(void)
{
	MEM(rlm_modules_static = module_list_alloc(NULL, &module_list_type_global, "rlm", true));
	MEM(rlm_modules_dynamic = module_list_alloc(NULL, &module_list_type_thread_local, "rlm", true));
	module_list_mask_set(rlm_modules_dynamic, MODULE_INSTANCE_INSTANTIATED);	/* Ensure we never instantiate dynamic modules */

	MEM(module_rlm_virtual_name_tree = fr_rb_inline_alloc(NULL, module_rlm_virtual_t, name_node,
							      module_rlm_virtual_name_cmp, NULL));
	fr_atexit_global(_modules_rlm_free_atexit, NULL);

	return 0;
}
