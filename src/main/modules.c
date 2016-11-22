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
 * @file modules.c
 * @brief Defines functions for module (re-)initialisation.
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

static TALLOC_CTX *instance_ctx = NULL;

struct fr_module_hup_t {
	module_instance_t	*mi;
	time_t			when;
	void			*insthandle;
	fr_module_hup_t		*next;
};

/*
 *	Ordered by component
 */
const section_type_value_t section_type_value[MOD_COUNT] = {
	{ "authenticate", "Auth-Type",       PW_AUTH_TYPE },
	{ "authorize",    "Autz-Type",       PW_AUTZ_TYPE },
	{ "preacct",      "Pre-Acct-Type",   PW_PRE_ACCT_TYPE },
	{ "accounting",   "Acct-Type",       PW_ACCT_TYPE },
	{ "session",      "Session-Type",    PW_SESSION_TYPE },
	{ "pre-proxy",    "Pre-Proxy-Type",  PW_PRE_PROXY_TYPE },
	{ "post-proxy",   "Post-Proxy-Type", PW_POST_PROXY_TYPE },
	{ "post-auth",    "Post-Auth-Type",  PW_POST_AUTH_TYPE }
#ifdef WITH_COA
	,
	{ "recv-coa",     "Recv-CoA-Type",   PW_RECV_COA_TYPE },
	{ "send-coa",     "Send-CoA-Type",   PW_SEND_COA_TYPE }
#endif
};

static module_instance_t *module_instantiate(CONF_SECTION *modules, char const *asked_name);

static bool is_reserved_word(const char *name)
{
	int i;

	if (!name || !*name) return false;

	for (i = 1; unlang_ops[i].name != NULL; i++) {
		if (strcmp(name, unlang_ops[i].name) == 0) return true;
	}

	return false;
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
exfile_t *module_exfile_init(TALLOC_CTX *ctx,
			     CONF_SECTION *module,
			     uint32_t max_entries,
			     uint32_t max_idle,
			     bool locking,
			     char const *trigger_prefix,
			     VALUE_PAIR *trigger_args)
{
	char		trigger_prefix_buff[128];
	exfile_t	*handle;

	if (!trigger_prefix) {
		snprintf(trigger_prefix_buff, sizeof(trigger_prefix_buff), "modules.%s.file", cf_section_name1(module));
		trigger_prefix = trigger_prefix_buff;
	}

	handle = exfile_init(ctx, max_entries, max_idle, locking);
	if (!handle) return NULL;

	exfile_enable_triggers(handle, cf_section_sub_find(module, "file"), trigger_prefix, trigger_args);

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
 * @param out where to write the pointer to a module's config section.  May be NULL on success,
 *	indicating the config item was not found within the module #CONF_SECTION
 *	or the chain of module references was followed and the module at the end of the chain
 *	did not a subsection.
 * @param module #CONF_SECTION.
 * @param name of the polymorphic sub-section.
 * @return
 *	- 0 on success with referenced section.
 *	- 1 on success with local section.
 *	- -1 on failure.
 */
int module_sibling_section_find(CONF_SECTION **out, CONF_SECTION *module, char const *name)
{
	static bool loop = true;        /* not used, we just need a valid pointer to quiet static analysis */

	CONF_PAIR *cp;
	CONF_SECTION *cs;

	module_instance_t *inst;
	char const *inst_name;

#define FIND_SIBLING_CF_KEY "find_sibling"

	*out = NULL;

	/*
	 *	Is a real section (not referencing sibling module).
	 */
	cs = cf_section_sub_find(module, name);
	if (cs) {
		*out = cs;

		return 0;
	}

	/*
	 *	Item omitted completely from module config.
	 */
	cp = cf_pair_find(module, name);
	if (!cp) return 0;

	if (cf_data_find(module, CF_DATA_TYPE_CONNECTION_POOL, FIND_SIBLING_CF_KEY)) {
		cf_log_err_cp(cp, "Module reference loop found");

		return -1;
	}
	cf_data_add(module, CF_DATA_TYPE_CONNECTION_POOL, FIND_SIBLING_CF_KEY, &loop, NULL);

	/*
	 *	Item found, resolve it to a module instance.
	 *	This triggers module loading, so we don't have
	 *	instantiation order issues.
	 */
	inst_name = cf_pair_value(cp);
	inst = module_instantiate(cf_item_parent(cf_section_to_item(module)), inst_name);

	/*
	 *	Remove the config data we added for loop
	 *	detection.
	 */
	cf_data_remove(module, CF_DATA_TYPE_CONNECTION_POOL, FIND_SIBLING_CF_KEY);
	if (!inst) {
		cf_log_err_cp(cp, "Unknown module instance \"%s\"", inst_name);

		return -1;
	}

	/*
	 *	Check the module instances are of the same type.
	 */
	if (strcmp(cf_section_name1(inst->cs), cf_section_name1(module)) != 0) {
		cf_log_err_cp(cp, "Referenced module is a rlm_%s instance, must be a rlm_%s instance",
			      cf_section_name1(inst->cs), cf_section_name1(module));

		return -1;
	}

	*out = cf_section_sub_find(inst->cs, name);

	return 1;
}

/** Initialise a module specific connection pool
 *
 * @see fr_connection_pool_init
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
fr_connection_pool_t *module_connection_pool_init(CONF_SECTION *module,
						  void *opaque,
						  fr_connection_create_t c,
						  fr_connection_alive_t a,
						  char const *log_prefix,
						  char const *trigger_prefix,
						  VALUE_PAIR *trigger_args)
{
	CONF_SECTION *cs, *mycs;
	char log_prefix_buff[128];
	char trigger_prefix_buff[128];

	fr_connection_pool_t *pool;
	char const *cs_name1, *cs_name2;

	int ret;

#define CONNECTION_POOL_CF_KEY "connection_pool"
#define parent_name(_x) cf_section_name(cf_item_parent(cf_section_to_item(_x)))

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
	ret = module_sibling_section_find(&cs, module, "pool");
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
	mycs = cf_section_sub_find(module, "pool");
	if (!mycs) {
		DEBUG4("%s: Adding pool section to config item \"%s\" to store pool references", log_prefix,
		       cf_section_name(module));

		mycs = cf_section_alloc(module, "pool", NULL);
		cf_section_add(module, mycs);
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
	 *	If fr_connection_pool_init has already been called
	 *	for this config section, reuse the previous instance.
	 *
	 *	This allows modules to pass in the config sections
	 *	they would like to use the connection pool from.
	 */
	pool = cf_data_find(cs, CF_DATA_TYPE_CONNECTION_POOL, CONNECTION_POOL_CF_KEY);
	if (!pool) {
		DEBUG4("%s: No pool reference found for config item \"%s.pool\"", log_prefix, parent_name(cs));
		pool = fr_connection_pool_init(cs, cs, opaque, c, a, log_prefix);
		if (!pool) return NULL;

		fr_connection_pool_enable_triggers(pool, trigger_prefix, trigger_args);

		DEBUG4("%s: Adding pool reference %p to config item \"%s.pool\"", log_prefix, pool, parent_name(cs));
		cf_data_add(cs, CF_DATA_TYPE_CONNECTION_POOL, CONNECTION_POOL_CF_KEY, pool, NULL);
		return pool;
	}
	fr_connection_pool_ref(pool);

	DEBUG4("%s: Found pool reference %p in config item \"%s.pool\"", log_prefix, pool, parent_name(cs));

	/*
	 *	We're reusing pool data add it to our local config
	 *	section. This allows other modules to transitively
	 *	re-use a pool through this module.
	 */
	if (mycs != cs) {
		DEBUG4("%s: Copying pool reference %p from config item \"%s.pool\" to config item \"%s.pool\"",
		       log_prefix, pool, parent_name(cs), parent_name(mycs));
		cf_data_add(mycs, CF_DATA_TYPE_CONNECTION_POOL, CONNECTION_POOL_CF_KEY, pool, NULL);
	}

	return pool;
}

/** Mark module instance data as being read only
 *
 * This still allows memory to be modified, but not allocated
 */
int module_instance_read_only(TALLOC_CTX *ctx, char const *name)
{
	int rcode;
	size_t size;

	size = talloc_total_size(ctx);

	rcode = talloc_set_memlimit(ctx, size);
	if (rcode < 0) {
		ERROR("Failed setting memory limit for module %s", name);
	} else {
		DEBUG3("Memory limit for module %s is set to %zd bytes", name, size);
	}

	return rcode;
}

/** Find an existing module instance
 *
 * @param[in] modules		section in the main config.
 * @param[in] asked_name 	The name of the module we're attempting to find.
 *				May include '-' which indicates that it's ok for
 *				the module not to be loaded.
 * @return
 *	- Module instance matching name.
 *	- NULL if not such module exists.
 */
module_instance_t *module_find(CONF_SECTION *modules, char const *asked_name)
{
	char const *instance_name;

	if (!modules) return NULL;

	/*
	 *	Look for the real name.  Ignore the first character,
	 *	which tells the server "it's OK for this module to not
	 *	exist."
	 */
	instance_name = asked_name;
	if (instance_name[0] == '-') instance_name++;

	return (module_instance_t *)cf_data_find(modules, CF_DATA_TYPE_CONNECTION_POOL, instance_name);
}

/** Find an existing module instance and verify it implements the specified method
 *
 * Extracts the method from the module name where the format is @verbatim <module>.<method> @endverbatim
 * and ensures that the module is instantiated, and implements the specified method.
 *
 * @param[out] method		the method component we found associated with the module. May be NULL.
 * @param[in] modules		section in the main config.
 * @param[in] name 		The name of the module we're attempting to find, concatenated with
 *				the method.
 * @return
 *	- The module instance on success.
 *	- NULL on error.
 */
module_instance_t *module_find_with_method(rlm_components_t *method, CONF_SECTION *modules, char const *name)
{
	char			*p;
	rlm_components_t	i;
	module_instance_t	*instance;

	/*
	 *	If the module exists, ensure it's instantiated.
	 *
	 *	Doing it this way avoids complaints from
	 *	module_instantiate()
	 */
	instance = module_find(modules, name);
	if (instance) return module_instantiate(modules, name);

	/*
	 *	Find out which method is being used.
	 */
	p = strrchr(name, '.');
	if (!p) return NULL;

	p++;

	/*
	 *	Find the component.
	 */
	for (i = MOD_AUTHENTICATE; i < MOD_COUNT; i++) {
		if (strcmp(p, section_type_value[i].section) == 0) {
			char buffer[256];

			strlcpy(buffer, name, sizeof(buffer));
			buffer[p - name - 1] = '\0';

			instance = module_find(modules, buffer);
			if (instance) {
				if (method) *method = i;
				return module_instantiate(modules, buffer);
			}
		}
	}

	/*
	 *	Not found.
	 */
	return NULL;
}

/** Free old instances from HUPs
 *
 */
static void module_hup_free(module_instance_t *instance, time_t when)
{
	fr_module_hup_t *mh, **last;

	/*
	 *	Walk the list, freeing up old instances.
	 */
	last = &(instance->hup);
	while (*last) {
		mh = *last;

		/*
		 *	Free only every 60 seconds.
		 */
		if ((when - mh->when) < 60) {
			last = &(mh->next);
			continue;
		}

		talloc_free(mh->insthandle);

		*last = mh->next;
		talloc_free(mh);
	}
}

int module_hup(CONF_SECTION *cs, module_instance_t *instance, time_t when)
{
	void *insthandle;
	fr_module_hup_t *mh;

	if (!instance ||
	    instance->module->bootstrap ||
	    !instance->module->instantiate ||
	    ((instance->module->type & RLM_TYPE_HUP_SAFE) == 0)) {
		return 1;
	}

	/*
	 *	Silently ignore multiple HUPs within a short time period.
	 */
	if ((instance->last_hup + 2) >= when) return 1;
	instance->last_hup = when;

	cf_log_module(cs, "Trying to reload module \"%s\"", instance->name);

	/*
	 *	Parse the module configuration, and setup destructors so the
	 *	module's detach method is called when it's instance data is
	 *	about to be freed.
	 */
	if (dl_module_instance_data_alloc(&insthandle, instance, instance->handle, cs) < 0) {
		cf_log_err_cs(cs, "HUP failed for module \"%s\" (parsing config failed). "
			"Using old configuration", instance->name);

		return 0;
	}

	if ((instance->module->instantiate)(cs, insthandle) < 0) {
		cf_log_err_cs(cs, "HUP failed for module \"%s\".  Using old configuration.", instance->name);
		talloc_free(insthandle);

		return 0;
	}

	INFO("Module: Reloaded module \"%s\"", instance->name);

	module_hup_free(instance, when);

	/*
	 *	Save the old instance handle for later deletion.
	 */
	mh = talloc_zero(instance_ctx, fr_module_hup_t);
	mh->mi = instance;
	mh->when = when;
	mh->insthandle = instance->data;
	mh->next = instance->hup;
	instance->hup = mh;

	/*
	 *	Replace the instance handle while the module is running.
	 */
	instance->data = insthandle;

	/*
	 *	FIXME: Set a timeout to come back in 60s, so that
	 *	we can pro-actively clean up the old instances.
	 */

	return 1;
}

/** Reload the configurations of modules that support it
 *
 * @param modules CONF_SECTION.
 * @return
 *	- 0 on failure.
 *	- 1 on success.
 */
int modules_hup(CONF_SECTION *modules)
{
	time_t when;
	CONF_ITEM *ci;
	CONF_SECTION *cs;
	module_instance_t *instance;

	if (!modules) return 0;

	when = time(NULL);

	/*
	 *	Loop over the modules
	 */
	for (ci = cf_item_find_next(modules, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(modules, ci)) {
		char const *instance_name;

		/*
		 *	If it's not a section, ignore it.
		 */
		if (!cf_item_is_section(ci)) continue;

		cs = cf_item_to_section(ci);

		instance_name = cf_section_name2(cs);
		if (!instance_name) instance_name = cf_section_name1(cs);

		instance = module_find(modules, instance_name);
		if (!instance) continue;

		module_hup(cs, instance, when);
	}

	return 1;
}

/** Free all modules loaded by the server
 *
 * @return 0.
 */
int modules_free(void)
{
	/*
	 *	Free instances first, then dynamic libraries.
	 */
	TALLOC_FREE(instance_ctx);

	return 0;
}

/** Complete module setup by calling its instantiate function
 *
 * @param modules section in the main config.
 * @param asked_name The name of the module we're attempting to find.  May include '-'
 *	which indicates that it's ok for the module not to be loaded.
 * @return
 *	- Module instance matching name if module can be found, and its instantiate
 *	  method returns successfully.
 *	- NULL if instantiation fails or module can't be found.
 */
static module_instance_t *module_instantiate(CONF_SECTION *modules, char const *asked_name)
{
	module_instance_t *instance;

	/*
	 *	Find the module.  If it's not there, do nothing.
	 */
	instance = module_find(modules, asked_name);
	if (!instance) {
		ERROR("Cannot find module \"%s\"", asked_name);
		return NULL;
	}

	/*
	 *	The module is already instantiated.  Return it.
	 */
	if (instance->instantiated) return instance;

	/*
	 *	Now that ALL modules are instantiated, and ALL xlats
	 *	are defined, go compile the config items marked as XLAT.
	 */
	if (instance->module->config &&
	    (cf_section_parse_pass2(instance->cs, instance->data,
				    instance->module->config) < 0)) {
		return NULL;
	}

	/*
	 *	Call the instantiate method, if any.
	 */
	if (instance->module->instantiate) {
		cf_log_module(instance->cs, "Instantiating module \"%s\" from file %s", instance->name,
			      cf_section_filename(instance->cs));

		/*
		 *	Call the module's instantiation routine.
		 */
		if ((instance->module->instantiate)(instance->cs, instance->data) < 0) {
			cf_log_err_cs(instance->cs, "Instantiation failed for module \"%s\"", instance->name);

			return NULL;
		}
	}

	/*
	 *	If we're threaded, check if the module is thread-safe.
	 *
	 *	If it isn't, we create a mutex.
	 */
	if ((instance->module->type & RLM_TYPE_THREAD_UNSAFE) != 0) {
		instance->mutex = talloc_zero(instance, pthread_mutex_t);

		/*
		 *	Initialize the mutex.
		 */
		pthread_mutex_init(instance->mutex, NULL);
	}

#ifndef NDEBUG
	if (instance->data) module_instance_read_only(instance->data, instance->name);
#endif

	instance->instantiated = true;
	instance->last_hup = time(NULL); /* don't let us load it, then immediately hup it */

	return instance;
}

/** Completes instantiation of modules
 *
 * Allows the module to initialise connection pools, and complete any registrations that depend on
 * attributes created during the bootstrap phase.
 *
 * @param[in] root	Configuration root.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int modules_instantiate(CONF_SECTION *root)
{
	CONF_ITEM	*ci, *next;
	CONF_SECTION	*modules;

	modules = cf_section_sub_find(root, "modules");
	if (!modules) return 0;

	for (ci = cf_item_find_next(modules, NULL);
	     ci != NULL;
	     ci = next) {
		char const *name;
		module_instance_t *instance;
		CONF_SECTION *subcs;

		next = cf_item_find_next(modules, ci);

		if (!cf_item_is_section(ci)) continue;

		subcs = cf_item_to_section(ci);
		name = cf_section_name2(subcs);
		if (!name) name = cf_section_name1(subcs);

		instance = module_instantiate(modules, name);
		if (!instance) return -1;
	}

#ifndef NDEBUG
	{
		size_t size;

		size = talloc_total_size(instance_ctx);

		if (talloc_set_memlimit(instance_ctx, size)) {
			ERROR("Failed setting memory limit for all modules");
		} else {
			DEBUG3("Memory limit for all modules is set to %zd bytes", size);
		}
	}
#endif

	return 0;
}

/** Free module's instance data, and any xlats or paircompares
 *
 * @param[in] instance to free.
 * @return 0
 */
static int _module_instance_free(module_instance_t *instance)
{
	if (instance->mutex) {
		/*
		 *	FIXME
		 *	The mutex MIGHT be locked...
		 *	we'll check for that later, I guess.
		 */
		pthread_mutex_destroy(instance->mutex);
	}

	/*
	 *	Free HUP versions of the module's instance data
	 */
	module_hup_free(instance, time(NULL) + 100);

	xlat_unregister(instance->data, instance->name, NULL);

	/*
	 *	Remove all xlat's registered to module instance.
	 */
	if (instance->data) {
		/*
		 *	Remove any registered paircompares.
		 */
		paircompare_unregister_instance(instance->data);
		xlat_unregister_module(instance->data);
	}

	/*
	 *	We need to explicitly free all children, so the module instance
	 *	destructors get executed before we unload the bytecode for the
	 *	module.
	 *
	 *	If we don't do this, we get a SEGV deep inside the talloc code
	 *	when it tries to call a destructor that no longer exists.
	 */
	talloc_free_children(instance);

	/*
	 *	Decrements the reference count. The module object won't be unloaded
	 *	until all instances of that module have been destroyed.
	 */
	talloc_decrease_ref_count(instance->handle);

	return 0;
}

/** Bootstrap a module
 *
 * Load the module shared library, allocate instance data for it,
 * parse the module configuration, and call the modules "bootstrap" method.
 *
 * @note Adds module instance data to the specified CONF_SECTION.  Module will be
 *	freed if CONF_SECTION is freed.
 *
 * @param modules section from the main config.
 * @param cs A child of the modules section, specifying this specific instance of a module.
 * @return
 *	- A new module instance handle, containing the module's public interface,
 *	  and private instance data.
 *	- NULL on error.
 */
static module_instance_t *module_bootstrap(CONF_SECTION *modules, CONF_SECTION *cs)
{
	int			i;
	char const		*name1, *instance_name;
	module_instance_t	*instance;
	dl_module_t const	*module;

	/*
	 *	Figure out which module we want to load.
	 */
	name1 = cf_section_name1(cs);
	instance_name = cf_section_name2(cs);
	if (!instance_name) instance_name = name1;

	/*
	 *	Don't allow modules to use reserved words.
	 */
	for (i = 1; unlang_ops[i].name != NULL; i++) {
		if (strcmp(instance_name, unlang_ops[i].name) == 0) {
			ERROR("Module names cannot use a reserved word \"%s\"",
			      unlang_ops[i].name);
			return NULL;
		}
	}

	/*
	 *	See if the module already exists.
	 */
	instance = module_find(modules, instance_name);
	if (instance) {
		ERROR("Duplicate module \"%s\", in file %s:%d and file %s:%d",
		      instance_name,
		      cf_section_filename(cs),
		      cf_section_lineno(cs),
		      cf_section_filename(instance->cs),
		      cf_section_lineno(instance->cs));
		return NULL;
	}

	/*
	 *	Load the module shared library.
	 */
	module = dl_module(cs, name1, "rlm_");
	if (!module) {
		talloc_free(instance);
		return NULL;
	}

	instance = talloc_zero(instance_ctx, module_instance_t);
	instance->cs = cs;
	instance->name = instance_name;
	instance->handle = module;

	talloc_set_destructor(instance, _module_instance_free);

	instance->module = (rad_module_t const *)module->common;
	if (!instance->module) {
		talloc_free(instance);
		return NULL;
	}

	cf_log_module(cs, "Loading module \"%s\" from file %s", instance->name,
		      cf_section_filename(cs));

	/*
	 *	Parse the modules configuration.
	 */
	if (dl_module_instance_data_alloc(&instance->data, instance, instance->handle, cs) < 0) {
		talloc_free(instance);
		return NULL;
	}

	/*
	 *	Bootstrap the module.
	 */
	if (instance->module->bootstrap &&
	    ((instance->module->bootstrap)(cs, instance->data) < 0)) {
		cf_log_err_cs(cs, "Instantiation failed for module \"%s\"", instance->name);
		talloc_free(instance);
		return NULL;
	}

	/*
	 *	Remember the module for later.
	 */
	cf_data_add(modules, CF_DATA_TYPE_CONNECTION_POOL, instance->name, instance, NULL);

	return instance;
}

/** Bootstrap modules and virtual modules
 *
 * Parse the module config sections, and load and call each module's init() function.
 */
int modules_bootstrap(CONF_SECTION *root)
{
	CONF_ITEM *ci, *next;
	CONF_SECTION *cs, *modules;

	instance_ctx = talloc_init("module instance context");

	/*
	 *	Remember where the modules were stored.
	 */
	modules = cf_section_sub_find(root, "modules");
	if (!modules) WARN("Cannot find a \"modules\" section in the rooturation file!");

	DEBUG2("%s: #### Loading modules ####", main_config.name);

	cf_log_info(modules, " modules {");

	/*
	 *	Loop over module definitions, looking for duplicates.
	 *
	 *	This is O(N^2) in the number of modules, but most
	 *	systems should have less than 100 modules.
	 */
	for (ci = cf_item_find_next(modules, NULL);
	     ci != NULL;
	     ci = next) {
		char const *name1;
		CONF_SECTION *subcs;
		module_instance_t *instance;

		next = cf_item_find_next(modules, ci);

		if (!cf_item_is_section(ci)) continue;

		subcs = cf_item_to_section(ci);

		instance = module_bootstrap(modules, subcs);
		if (!instance) return -1;

		if (!next || !cf_item_is_section(next)) continue;

		name1 = cf_section_name1(subcs);

		if (is_reserved_word(name1)) {
			cf_log_err_cs(subcs, "Module cannot be named for an 'unlang' keyword");
			return -1;
		}
	}

	/*
	 *  Look for the 'instantiate' section, which tells us
	 *  the instantiation order of the modules, and also allows
	 *  us to load modules with no authorize/authenticate/etc.
	 *  sections.
	 */
	cs = cf_section_sub_find(root, "instantiate");
	if (cs) {
		CONF_PAIR *cp;
		module_instance_t *instance;
		char const *name;

		cf_log_info(cs, "  instantiate {");

		/*
		 *  Loop over the items in the 'instantiate' section.
		 */
		for (ci = cf_item_find_next(cs, NULL);
		     ci != NULL;
		     ci = cf_item_find_next(cs, ci)) {
			/*
			 *	Skip sections and "other" stuff.
			 *	Sections will be handled later, if
			 *	they're referenced at all...
			 */
			if (cf_item_is_pair(ci)) {
				cp = cf_item_to_pair(ci);
				name = cf_pair_attr(cp);

				instance = module_instantiate(modules, name);
				if (!instance && (name[0] != '-')) {
					return -1;
				}
			}

			/*
			 *	Can only be "redundant" or
			 *	"load-balance" or
			 *	"redundant-load-balance"
			 */
			if (cf_item_is_section(ci)) {
				bool all_same = true;
				rad_module_t const *last = NULL;
				CONF_SECTION *subcs;
				CONF_ITEM *subci;

				subcs = cf_item_to_section(ci);
				name = cf_section_name1(subcs);

				/*
				 *	Groups, etc. must have a name.
				 */
				if (((strcmp(name, "group") == 0) ||
				     (strcmp(name, "redundant") == 0) ||
				     (strcmp(name, "redundant-load-balance") == 0) ||
				     strcmp(name, "load-balance") == 0)) {
					name = cf_section_name2(subcs);
					if (!name) {
						cf_log_err_cs(subcs, "Subsection must have a name");
						return -1;
					}

					if (is_reserved_word(name)) {
						cf_log_err_cs(subcs,
							      "Instantiate sections cannot be named "
							      "for an 'unlang' keyword");
						return -1;
					}
				} else {
					if (is_reserved_word(name)) {
						cf_log_err_cs(subcs,
							      "Instantiate sections cannot be named "
							      "for an 'unlang' keyword");
						return -1;
					}
				}

				/*
				 *	Ensure that the modules we reference here exist.
				 */
				for (subci = cf_item_find_next(subcs, NULL);
				     subci != NULL;
				     subci = cf_item_find_next(subcs, subci)) {
					if (cf_item_is_pair(subci)) {
						cp = cf_item_to_pair(subci);
						if (cf_pair_value(cp)) {
							cf_log_err(subci, "Cannot set return codes in a %s block",
								   cf_section_name1(subcs));
							return -1;
						}

						/*
						 *	Allow "foo.authorize" in subsections.
						 */
						instance = module_find_with_method(NULL, modules, cf_pair_attr(cp));
						if (!instance) {
							cf_log_err(subci, "Module instance \"%s\" referenced in "
									   "%s block, does not exist",
								   cf_pair_attr(cp),
								   cf_section_name1(subcs));
							return -1;
						}

						if (all_same) {
							if (!last) {
								last = instance->module;
							} else if (last != instance->module) {
								last = NULL;
								all_same = false;
							}
						}
					} else {
						all_same = false;
					}

					/*
					 *	Don't check subsections for now.
					 */
				} /* loop over modules in a "redundant foo" section */

				/*
				 *	Register a redundant xlat
				 */
				if (all_same) {
					if (!xlat_register_redundant(cf_item_to_section(ci))) {
						WARN("%s[%d] Not registering expansions for %s",
						     cf_section_filename(subcs), cf_section_lineno(subcs),
						     cf_section_name2(subcs));
					}
				}
			}  /* handle subsections */
		} /* loop over the "instantiate" section */

		cf_log_info(cs, "  }");
	} /* if there's an 'instantiate' section. */

	cf_log_info(modules, " } # modules");

	return 0;
}
