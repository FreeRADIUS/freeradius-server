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
#include <freeradius-devel/server/global_lib.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/util/atexit.h>

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

char const *section_type_value[MOD_COUNT] = {
	"authenticate",
	"authorize",
	"preacct",
	"accounting",
	"post-auth"
};

/** Global module list for all backend modules
 *
 */
static module_list_t *rlm_modules;

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
	mi = module_by_name(rlm_modules, NULL, inst_name);
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

		module_instantiate(module_by_name(rlm_modules, NULL, inst_name));
	}

	/*
	 *	Remove the config data we added for loop
	 *	detection.
	 */
	cf_data_remove_by_data(module, cd);

	/*
	 *	Check the module instances are of the same type.
	 */
	if (strcmp(cf_section_name1(mi->dl_inst->conf), cf_section_name1(module)) != 0) {
		cf_log_err(cp, "Referenced module is a rlm_%s instance, must be a rlm_%s instance",
			      cf_section_name1(mi->dl_inst->conf), cf_section_name1(module));

		return -1;
	}

	*out = cf_section_find(mi->dl_inst->conf, name, NULL);

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
	 *	re-use a pool through this module.
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
 * @param[in,out] component	the default component to use.  Updated to be the found component
 * @param[out] name1		name1 of the method being called
 * @param[out] name2		name2 of the method being called
 * @param[in] name 		The name of the module we're attempting to find, possibly concatenated with the method
 * @return
 *	- The module instance on success.
 *	- NULL on not found
 *
 *  If the module exists but the method doesn't exist, then `method` is set to NULL.
 */
module_instance_t *module_rlm_by_name_and_method(module_method_t *method, UNUSED rlm_components_t *component,
						 char const **name1, char const **name2,
						 char const *name)
{
	char				*p, *q, *inst_name;
	size_t				len;
	int				j;
	module_instance_t		*mi;
	module_method_name_t const	*methods;
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
	mi = module_by_name(rlm_modules, NULL, name);
	if (mi) {
		virtual_server_method_t const	*allowed_list;

		if (!method) return mi;

		mrlm = module_rlm_from_module(mi->module);

		/*
		 *	We're not searching for a named method, OR the
		 *	module has no named methods.  Try to return a
		 *	method based on the component.
		 */
		if (!method_name1 || !mrlm->method_names) goto return_component;

		/*
		 *	Walk through the module, finding a matching
		 *	method.
		 */
		for (j = 0; mrlm->method_names[j].name1 != NULL; j++) {
			methods = &mrlm->method_names[j];

			/*
			 *	Wildcard match name1, we're
			 *	done.
			 */
			if (methods->name1 == CF_IDENT_ANY) {
			found:
				*method = methods->method;
				if (name1) *name1 = method_name1;
				if (name2) *name2 = method_name2;
				return mi;
			}

			/*
			 *	If name1 doesn't match, skip it.
			 */
			if (strcasecmp(methods->name1, method_name1) != 0) continue;

			/*
			 *	The module can declare a
			 *	wildcard for name2, in which
			 *	case it's a match.
			 */
			if (methods->name2 == CF_IDENT_ANY) goto found;

			/*
			 *	No name2 is also a match to no name2.
			 */
			if (!methods->name2 && !method_name2) goto found;

			/*
			 *	Don't do strcmp on NULLs
			 */
			if (!methods->name2 || !method_name2) continue;

			if (strcasecmp(methods->name2, method_name2) == 0) goto found;
		}

		/*
		 *	No match for "recv Access-Request", or
		 *	whatever else the section is.  Let's see if
		 *	the section has a list of allowed methods.
		 */
		allowed_list = virtual_server_section_methods(method_name1, method_name2);
		if (!allowed_list) goto return_component;

		/*
		 *	Walk over allowed methods for this section,
		 *	(implicitly ordered by priority), and see if
		 *	the allowed method matches any of the module
		 *	methods.  This process lets us reference a
		 *	module as "foo" in the configuration.  If the
		 *	module exports a "recv bar" method, and the
		 *	virtual server has a "recv bar" processing
		 *	section, then they shoul match.
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
		for (j = 0; allowed_list[j].name != NULL; j++) {
			int k;
			virtual_server_method_t const *allowed = &allowed_list[j];

			for (k = 0; mrlm->method_names[k].name1 != NULL; k++) {
				methods = &mrlm->method_names[k];

				fr_assert(methods->name1 != CF_IDENT_ANY); /* should have been caught above */

				if (strcasecmp(methods->name1, allowed->name) != 0) continue;

				/*
				 *	The module matches "recv *",
				 *	call this method.
				 */
				if (methods->name2 == CF_IDENT_ANY) {
				found_allowed:
					*method = methods->method;
					return mi;
				}

				/*
				 *	No name2 is also a match to no name2.
				 */
				if (!methods->name2 && !allowed->name2) goto found_allowed;

				/*
				 *	Don't do strcasecmp on NULLs
				 */
				if (!methods->name2 || !allowed->name2) continue;

				if (strcasecmp(methods->name2, allowed->name2) == 0) goto found_allowed;
			}
		}

	return_component:
		/*
		 *	Didn't find a matching method.  Just return
		 *	the module.
		 */
		return mi;
	}

	/*
	 *	Find out if the instance name contains
	 *	a method, if it doesn't, then the module
	 *	doesn't exist.
	 */
	p = strchr(name, '.');
	if (!p) return NULL;

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

		mi = module_by_name(rlm_modules, NULL, inst_name);
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
		talloc_free(inst_name);
		return NULL;
	}

	mrlm = module_rlm_from_module(mi->module);

	/*
	 *	We have a module, but the caller doesn't care about
	 *	method or names, so just return the module.
	 */
	if (!method || !method_name1 || !method_name2) {
		talloc_free(inst_name);
		return mi;
	}

	/*
	 *	We MAY have two names.
	 */
	p++;
	q = strchr(p, '.');
	/*
	 *	We've found the module, but it has no named methods.
	 */
	if (!mrlm->method_names) {
		*name1 = name + (p - inst_name);
		*name2 = NULL;
		talloc_free(inst_name);
		return mi;
	}

	/*
	 *	We have "module.METHOD", but METHOD doesn't match
	 *	"authorize", "authenticate", etc.  Let's see if it
	 *	matches anything else.
	 */
	if (!q) {
		for (j = 0; mrlm->method_names[j].name1 != NULL; j++) {
			methods = &mrlm->method_names[j];

			/*
			 *	If we do not have the second $method, then ignore it!
			 */
			if (methods->name2 && (methods->name2 != CF_IDENT_ANY)) continue;

			/*
			 *	Wildcard match name1, we're
			 *	done.
			 */
			if (!methods->name1 || (methods->name1 == CF_IDENT_ANY)) goto found_name1;

			/*
			 *	If name1 doesn't match, skip it.
			 */
			if (strcasecmp(methods->name1, p) != 0) continue;

		found_name1:
			/*
			 *	We've matched "*", or "name1" or
			 *	"name1 *".  Return that.
			 */
			*name1 = p;
			*name2 = NULL;
			*method = methods->method;
			break;
		}

		/*
		 *	Return the found module.
		 */
		talloc_free(inst_name);
		return mi;
	}

	/*
	 *	We CANNOT have '.' in method names.
	 */
	if (strchr(q + 1, '.') != 0) {
		talloc_free(inst_name);
		return mi;
	}

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
	for (j = 0; mrlm->method_names[j].name1 != NULL; j++) {
		methods = &mrlm->method_names[j];

		/*
		 *	If name1 doesn't match, skip it.
		 */
		if (strncmp(methods->name1, p, len) != 0) continue;

		/*
		 *	It may have been a partial match, like "rec",
		 *	instead of "recv".  In which case check if it
		 *	was a FULL match.
		 */
		if (strlen(methods->name1) != len) continue;

		/*
		 *	The module can declare a
		 *	wildcard for name2, in which
		 *	case it's a match.
		 */
		if (!methods->name2 || (methods->name2 == CF_IDENT_ANY)) goto found_name2;

		/*
		 *	Don't do strcmp on NULLs
		 */
		if (!methods->name2) continue;

		if (strcasecmp(methods->name2, q) != 0) continue;

	found_name2:
		/*
		 *	Update name1/name2 with the methods
		 *	that were found.
		 */
		*name1 = methods->name1;
		*name2 = name + (q - inst_name);
		*method = methods->method;
		break;
	}

	*name1 = name + (p - inst_name);
	*name2 = NULL;

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

module_thread_instance_t *module_rlm_thread_by_data(void const *data)
{
	return module_thread_by_data(rlm_modules, data);
}

module_instance_t *module_rlm_by_name(module_instance_t const *parent, char const *asked_name)
{
	return module_by_name(rlm_modules, parent, asked_name);
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
	module_t const 	*last = NULL;
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
	mi = module_by_name(rlm_modules, NULL, name);
	if (mi) {
		ERROR("Duplicate module \"%s\" in file %s[%d] and file %s[%d]",
		      name,
		      cf_filename(cs),
		      cf_lineno(cs),
		      cf_filename(mi->dl_inst->conf),
		      cf_lineno(mi->dl_inst->conf));
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
			mi = module_rlm_by_name_and_method(NULL, NULL, NULL, NULL, cf_pair_attr(cp));
			if (!mi) {
				cf_log_err(sub_ci, "Module instance \"%s\" referenced in %s block, does not exist",
					   cf_pair_attr(cp), cf_section_name1(cs));
				return -1;
			}

			if (all_same) {
				if (!last) {
					last = mi->module;
				} else if (last != mi->module) {
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
	inst->name = talloc_strdup(inst, name);
	inst->all_same = all_same;

	if (!fr_cond_assert(fr_rb_insert(module_rlm_virtual_name_tree, inst))) {
		talloc_free(inst);
		return -1;
	}

	return 0;
}

/** Generic CONF_PARSER func for loading drivers
 *
 */
int module_rlm_submodule_parse(TALLOC_CTX *ctx, void *out, void *parent,
			       CONF_ITEM *ci, CONF_PARSER const *rule)
{
	CONF_PARSER our_rule = *rule;

	our_rule.uctx = &rlm_modules;

	return module_submodule_parse(ctx, out, parent, ci, &our_rule);
}

/** Frees thread-specific data for all registered backend modules
 *
 */
void modules_rlm_thread_detach(void)
{
	modules_thread_detach(rlm_modules);
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
	return modules_thread_instantiate(ctx, rlm_modules, el);
}

/** Performs the instantiation phase for all backend modules
 *
 * @return
 *	- 0 if all modules were instantiated successfully.
 *	- -1 if a module failed instantiation.
 */
int modules_rlm_instantiate(void)
{
	return modules_instantiate(rlm_modules);
}

/** Bootstrap modules and virtual modules
 *
 * Parse the module config sections, and load and call each module's init() function.
 *
 * @param[in] root of the server configuration.
 * @return
 *	- 0 if all modules were bootstrapped successfully.
 *	- -1 if a module/virtual module failed to boostrap.
 */
int modules_rlm_bootstrap(CONF_SECTION *root)
{
	CONF_ITEM		*ci;
	CONF_SECTION		*cs, *modules;
	module_rlm_virtual_t	*vm;
	fr_rb_iter_inorder_t	iter;
	CONF_SECTION		*actions;

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

	DEBUG2("#### Bootstrapping modules ####");

	cf_log_debug(modules, " modules {");

	/*
	 *	Loop over module definitions, looking for duplicates.
	 *
	 *	This is O(N^2) in the number of modules, but most
	 *	systems should have less than 100 modules.
	 */
	for (ci = cf_item_next(modules, NULL);
	     ci != NULL;
	     ci = cf_item_next(modules, ci)) {
		char const *name;
		CONF_SECTION *subcs;
		module_instance_t *mi;

		/*
		 *	@todo - maybe this should be a warning?
		 */
		if (!cf_item_is_section(ci)) continue;

		subcs = cf_item_to_section(ci);

		/*
		 *	name2 can't be a keyword
		 */
		name = cf_section_name2(subcs);
		if (name && unlang_compile_is_keyword(name)) {
		invalid_name:
			cf_log_err(subcs, "Module names cannot be unlang keywords '%s'", name);
			return -1;
		}

		name = cf_section_name1(subcs);

		/*
		 *	For now, ignore name1 which is a keyword.
		 */
		if (unlang_compile_is_keyword(name)) {
			if (!cf_section_name2(subcs)) {
				cf_log_err(subcs, "Missing second name at '%s'", name);
				return -1;
			}
			if (module_rlm_bootstrap_virtual(subcs) < 0) return -1;
			continue;
		}

		/*
		 *	Skip inline templates, and disallow "template { ... }"
		 */
		if (strcmp(name, "template") == 0) {
			if (!cf_section_name2(subcs)) goto invalid_name;
			continue;
		}

		mi = module_alloc(rlm_modules, NULL, DL_MODULE_TYPE_MODULE, name, dl_module_inst_name_from_conf(subcs));
		if (unlikely(mi == NULL)) {
			cf_log_perr(subcs, "Failed loading module");
			return -1;

		}

		if (module_conf_parse(mi, subcs) < 0) {
			cf_log_perr(subcs, "Failed parsing module config");
		error:
			talloc_free(mi);
			return -1;
		}

		if (module_bootstrap(mi) < 0) {
			cf_log_perr(subcs, "Failed bootstrapping module");
			goto error;
		}

		/*
		 *	Compile the default "actions" subsection, which includes retries.
		 */
		actions = cf_section_find(subcs, "actions", NULL);
		if (actions && unlang_compile_actions(&mi->actions, actions, (mi->module->type & MODULE_TYPE_RETRY) != 0)) {
			talloc_free(mi);
			goto error;
		}
	}

	cf_log_debug(modules, " } # modules");

	if (fr_command_register_hook(NULL, NULL, modules, module_cmd_list_table) < 0) {
		PERROR("Failed registering radmin commands for modules");
		return -1;
	}

	/*
	 *	Check for duplicate policies.  They're treated as
	 *	modules, so we might as well check them here.
	 */
	cs = cf_section_find(root, "policy", NULL);
	if (cs) {
		while ((ci = cf_item_next(cs, ci))) {
			CONF_SECTION *subcs, *problemcs;
			char const *name1;

			/*
			 *	Skip anything that isn't a section.
			 */
			if (!cf_item_is_section(ci)) continue;

			subcs = cf_item_to_section(ci);
			name1 = cf_section_name1(subcs);

			if (unlang_compile_is_keyword(name1)) {
				cf_log_err(subcs, "Policy name '%s' cannot be an unlang keyword", name1);
				return -1;
			}

			if (cf_section_name2(subcs)) {
				cf_log_err(subcs, "Policies cannot have two names");
				return -1;
			}

			problemcs = cf_section_find_next(cs, subcs, name1, CF_IDENT_ANY);
			if (!problemcs) continue;

			cf_log_err(problemcs, "Duplicate policy '%s' is forbidden.",
				   cf_section_name1(subcs));
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
	if (talloc_free(rlm_modules) < 0) return -1;
	rlm_modules = NULL;
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
	MEM(rlm_modules = module_list_alloc(NULL, "rlm"));
	MEM(module_rlm_virtual_name_tree = fr_rb_inline_alloc(NULL, module_rlm_virtual_t, name_node,
							      module_rlm_virtual_name_cmp, NULL));
	fr_atexit_global(_modules_rlm_free_atexit, NULL);

	return 0;
}
