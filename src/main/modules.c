/*
 * modules.c	Radius module support.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2003,2006  The FreeRADIUS server project
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2000  Alan Curry <pacman@world.std.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/interpreter.h>
#include <freeradius-devel/parser.h>

/** Path to search for modules in
 *
 */
char const *radlib_dir = NULL;

static TALLOC_CTX *instance_ctx = NULL;
static rbtree_t *dlhandle_tree = NULL;

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

#ifndef RTLD_NOW
#  define RTLD_NOW (0)
#endif
#ifndef RTLD_LOCAL
#  define RTLD_LOCAL (0)
#endif

#ifdef __APPLE__
#  define DL_EXTENSION ".dylib"
#elif defined (WIN32)
#  define DL_EXTENSION ".dll"
#else
#  define DL_EXTENSION ".so"
#endif

/** Check if the magic number in the module matches the one in the library
 *
 * This is used to detect potential ABI issues caused by running with modules which
 * were built for a different version of the server.
 *
 * @param cs being parsed.
 * @param module being loaded.
 * @returns
 *	- 0 on success.
 *	- -1 if prefix mismatch.
 *	- -2 if version mismatch.
 *	- -3 if commit mismatch.
 */
static int module_verify_magic(CONF_SECTION *cs, module_t const *module)
{
#ifdef HAVE_DLADDR
	Dl_info dl_info;
	dladdr(module, &dl_info);
#endif

	if (MAGIC_PREFIX(module->magic) != MAGIC_PREFIX(RADIUSD_MAGIC_NUMBER)) {
#ifdef HAVE_DLADDR
		cf_log_err_cs(cs, "Failed loading module rlm_%s from file %s", module->name, dl_info.dli_fname);
#endif
		cf_log_err_cs(cs, "Application and rlm_%s magic number (prefix) mismatch."
			      "  application: %x module: %x", module->name,
			      MAGIC_PREFIX(RADIUSD_MAGIC_NUMBER),
			      MAGIC_PREFIX(module->magic));
		return -1;
	}

	if (MAGIC_VERSION(module->magic) != MAGIC_VERSION(RADIUSD_MAGIC_NUMBER)) {
#ifdef HAVE_DLADDR
		cf_log_err_cs(cs, "Failed loading module rlm_%s from file %s", module->name, dl_info.dli_fname);
#endif
		cf_log_err_cs(cs, "Application and rlm_%s magic number (version) mismatch."
			      "  application: %lx module: %lx", module->name,
			      (unsigned long) MAGIC_VERSION(RADIUSD_MAGIC_NUMBER),
			      (unsigned long) MAGIC_VERSION(module->magic));
		return -2;
	}

	if (MAGIC_COMMIT(module->magic) != MAGIC_COMMIT(RADIUSD_MAGIC_NUMBER)) {
#ifdef HAVE_DLADDR
		cf_log_err_cs(cs, "Failed loading module rlm_%s from file %s", module->name, dl_info.dli_fname);
#endif
		cf_log_err_cs(cs, "Application and rlm_%s magic number (commit) mismatch."
			      "  application: %lx module: %lx", module->name,
			      (unsigned long) MAGIC_COMMIT(RADIUSD_MAGIC_NUMBER),
			      (unsigned long) MAGIC_COMMIT(module->magic));
		return -3;
	}

	return 0;
}

/** Search for a module's shared object in various locations
 *
 * @param name of module to load.
 */
void *module_dlopen_by_name(char const *name)
{
	int		flags = RTLD_NOW;
	void		*handle;
	char		buffer[2048];
	char		*env;
	char const	*search_path;

#ifdef RTLD_GLOBAL
	if (strcmp(name, "rlm_perl") == 0) {
		flags |= RTLD_GLOBAL;
	} else
#endif
		flags |= RTLD_LOCAL;

#ifndef NDEBUG
	/*
	 *	Bind all the symbols *NOW* so we don't hit errors later
	 */
	flags |= RTLD_NOW;
#endif

	/*
	 *	Apple removed support for DYLD_LIBRARY_PATH in rootless mode.
	 */
	env = getenv("FR_LIBRARY_PATH");
	if (env) {
		DEBUG3("Ignoring libdir as FR_LIBRARY_PATH set.  Module search path will be: %s", env);
		search_path = env;
	} else {
		search_path = radlib_dir;
	}

	/*
	 *	Prefer loading our libraries by absolute path.
	 */
	if (search_path) {
		char *error;
		char *ctx, *paths, *path;
		char *p;

		fr_strerror();

		ctx = paths = talloc_strdup(NULL, search_path);
		while ((path = strsep(&paths, ":")) != NULL) {
			/*
			 *	Trim the trailing slash
			 */
			p = strrchr(path, '/');
			if (p && ((p[1] == '\0') || (p[1] == ':'))) *p = '\0';

			path = talloc_asprintf(ctx, "%s/%s%s", path, name, DL_EXTENSION);

			DEBUG4("Loading %s with path: %s", name, path);

			handle = dlopen(path, flags);
			if (handle) {
				talloc_free(ctx);
				return handle;
			}
			error = dlerror();

			fr_strerror_printf("%s%s\n", fr_strerror(), error);
			DEBUG4("Loading %s failed: %s - %s", name, error,
			       (access(path, R_OK) < 0) ? fr_syserror(errno) : "No access errors");
			talloc_free(path);
		}
		talloc_free(ctx);
	}

	DEBUG4("Loading library using linker search path(s)");
	if (DEBUG_ENABLED4) {
#ifdef __APPLE__

		env = getenv("LD_LIBRARY_PATH");
		if (env) {
			DEBUG4("LD_LIBRARY_PATH            : %s", env);
		}
		env = getenv("DYLD_LIBRARY_PATH");
		if (env) {
			DEBUG4("DYLB_LIBRARY_PATH          : %s", env);
		}
		env = getenv("DYLD_FALLBACK_LIBRARY_PATH");
		if (env) {
			DEBUG4("DYLD_FALLBACK_LIBRARY_PATH : %s", env);
		}
		env = getcwd(buffer, sizeof(buffer));
		if (env) {
			DEBUG4("Current directory          : %s", env);
		}
#else
		env = getenv("LD_LIBRARY_PATH");
		if (env) {
			DEBUG4("LD_LIBRARY_PATH  : %s", env);
		}
		DEBUG4("Defaults         : /lib:/usr/lib");
#endif
	}

	strlcpy(buffer, name, sizeof(buffer));
	/*
	 *	FIXME: Make this configurable...
	 */
	strlcat(buffer, DL_EXTENSION, sizeof(buffer));

	handle = dlopen(buffer, flags);
	if (!handle) {
		char *error = dlerror();

		DEBUG4("Failed with error: %s", error);
		/*
		 *	Append the error
		 */
		fr_strerror_printf("%s: %s", fr_strerror(), error);
		return NULL;
	}
	return handle;
}


/** Free old instances from HUPs
 *
 */
static void module_hup_free(module_instance_t *instance, time_t when)
{
	fr_module_hup_t *mh, **last;

	rad_assert(dlhandle_tree != NULL);

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

/*
 *	Compare two module handles
 */
static int module_dlhandle_cmp(void const *one, void const *two)
{
	module_dl_t const *a = one;
	module_dl_t const *b = two;

	return strcmp(a->name, b->name);
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
	TALLOC_FREE(dlhandle_tree);

	return 0;
}

/** Free a module
 *
 * Close module's dlhandle, unloading it.
 */
static int _module_dl_free(module_dl_t *module_dl)
{
	module_dl = talloc_get_type_abort(module_dl, module_dl_t);

	DEBUG3("Unloading module \"%s\" (%p/%p)", module_dl->name, module_dl->handle, module_dl->module);

	if (module_dl->handle) {
		dlclose(module_dl->handle);        /* ignore any errors */
		module_dl->handle = NULL;
	}

	return 0;
}

/** Load a module library using dlopen() or return a previously loaded module from the cache
 *
 * @param conf section describing the module's configuration.
 * @return
 *	- Module handle holding dlhandle, and module's public interface structure.
 *	- NULL if module couldn't be loaded, or some other error occurred.
 */
static module_dl_t *module_dlopen(CONF_SECTION *conf)
{
	module_dl_t			to_find;
	module_dl_t			*module_dl;
	void				*handle = NULL;
	char const			*name1;
	module_t const			*module;
	char				module_name[256];

	name1 = cf_section_name1(conf);

	to_find.name = name1;
	module_dl = rbtree_finddata(dlhandle_tree, &to_find);
	if (module_dl) return module_dl;

	/*
	 *	Link to the interface's rlm_FOO{} structure, the same as
	 *	the module name.
	 */
	snprintf(module_name, sizeof(module_name), "rlm_%s", name1);

	/*
	 *	Check if the module was statically compiled into the server,
	 *	or linked into the server.
	 */
#if defined(HAVE_DLFCN_H) && defined(RTLD_SELF)
	module = dlsym(RTLD_SELF, module_name);
	if (module) goto open_self;
#endif

	/*
	 *	Keep the dlhandle around so we can dlclose() it.
	 */
	handle = module_dlopen_by_name(module_name);
	if (!handle) {
		cf_log_err_cs(conf, "Failed to link to module \"%s\": %s", module_name, fr_strerror());
		return NULL;
	}

	DEBUG3("Loaded \"%s\", checking if it's valid", module_name);

	module = dlsym(handle, module_name);
	if (!module) {
		cf_log_err_cs(conf, "Failed linking to \"%s\" structure: %s", module_name, dlerror());
		dlclose(handle);
		return NULL;
	}

#if defined(HAVE_DLFCN_H) && defined(RTLD_SELF)
	open_self:
#endif
	/*
	 *	Before doing anything else, check if it's sane.
	 */
	if (module_verify_magic(conf, module) < 0) {
		dlclose(handle);
		return NULL;
	}

	DEBUG3("Validated \"%s\" (%p/%p)", module_name, handle, module);

	/* make room for the module type */
	module_dl = talloc_zero(dlhandle_tree, module_dl_t);
	talloc_set_destructor(module_dl, _module_dl_free);

	module_dl->module = module;
	module_dl->handle = handle;
	module_dl->name = cf_section_name1(conf);

	cf_log_module(conf, "Loaded module \"%s\"", module_name);

	/*
	 *	Add the module as "rlm_foo-version" to the configuration
	 *	section.
	 */
	if (!rbtree_insert(dlhandle_tree, module_dl)) {
		ERROR("Failed to cache module \"%s\"", module_name);
		dlclose(handle);
		talloc_free(module_dl);
		return NULL;
	}

	return module_dl;
}

/** Parse module's configuration section and setup destructors
 *
 * @param[out] data Module's private data, the result of parsing the config.
 * @param[in] instance data of module.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int module_parse_conf(void **data, module_instance_t *instance)
{
	*data = NULL;

	if (!instance->module->inst_size) return 0;

	/*
	 *	If there is supposed to be instance data, allocate it now.
	 *	Also parse the configuration data, if required.
	 */
	*data = talloc_zero_array(instance, uint8_t, instance->module->inst_size);
	rad_assert(data);

	talloc_set_name(*data, "rlm_%s_t",
			instance->module->name ? instance->module->name : "config");

	if (instance->module->config &&
	    (cf_section_parse(instance->cs, *data, instance->module->config) < 0)) {
		cf_log_err_cs(instance->cs, "Invalid configuration for module \"%s\"", instance->name);
		talloc_free(*data);

		return -1;
	}

	/*
	 *	Set the destructor.
	 */
	if (instance->module->detach) talloc_set_destructor((void *)*data, instance->module->detach);

	return 0;
}

/** Free module's instance data, and any xlats or paircompares
 *
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
	module_dl_t		*module_dl;

	/*
	 *	Figure out which module we want to load.
	 */
	name1 = cf_section_name1(cs);
	instance_name = cf_section_name2(cs);
	if (!instance_name) instance_name = name1;

	/*
	 *	Don't allow modules to use reserved words.
	 */
	for (i = 1; unlang_keyword[i] != NULL; i++) {
		if (strcmp(instance_name, unlang_keyword[i]) == 0) {
			ERROR("Module names cannot use a reserved word \"%s\"",
			      unlang_keyword[i]);
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
	module_dl = module_dlopen(cs);
	if (!module_dl) {
		talloc_free(instance);
		return NULL;
	}

	/*
	 *	Hang the instance struct off the dlhandle,
	 *	if the module is unloaded, all its instances
	 *	will be too.
	 *
	 *	@fixme this should be the other way round.
	 */
	instance = talloc_zero(instance_ctx, module_instance_t);
	instance->cs = cs;
	instance->name = instance_name;

	talloc_set_destructor(instance, _module_instance_free);

	instance->module = module_dl->module;
	if (!instance->module) {
		talloc_free(instance);
		return NULL;
	}

	cf_log_module(cs, "Loading module \"%s\" from file %s", instance->name,
		      cf_section_filename(cs));

	/*
	 *	Parse the modules configuration.
	 */
	if (module_parse_conf(&instance->data, instance) < 0) {
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
	cf_data_add(modules, instance->name, instance, NULL);

	return instance;
}

/** Find an existing module instance.
 *
 * @param modules section in the main config.
 * @param asked_name The name of the module we're attempting to find.  May include '-'
 *	which indicates that it's ok for the module not to be loaded.
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

	return (module_instance_t *)cf_data_find(modules, instance_name);
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
module_instance_t *module_instantiate(CONF_SECTION *modules, char const *asked_name)
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

	instance->instantiated = true;
	instance->last_hup = time(NULL); /* don't let us load it, then immediately hup it */

	return instance;
}

module_instance_t *module_instantiate_method(CONF_SECTION *modules, char const *name, rlm_components_t *method)
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

	if (cf_data_find(module, FIND_SIBLING_CF_KEY)) {
		cf_log_err_cp(cp, "Module reference loop found");

		return -1;
	}
	cf_data_add(module, FIND_SIBLING_CF_KEY, &loop, NULL);

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
	cf_data_remove(module, FIND_SIBLING_CF_KEY);
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
	dval = fr_dict_enum_by_name(NULL, da, name2);
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

	cf_log_info(cs, "server %s { # from file %s",
		    name, cf_section_filename(cs));

	/*
	 *	Loop over all of the known components, finding their
	 *	configuration section, and loading it.
	 */
	found = false;
	for (comp = 0; comp < MOD_COUNT; ++comp) {
		CONF_SECTION *subcs;

		subcs = cf_section_sub_find(cs,
					    section_type_value[comp].section);
		if (!subcs) continue;

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
	 *	We haven't loaded any of the normal sections.  Maybe we're
	 *	supposed to load the vmps section.
	 *
	 *	This is a bit of a hack...
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

static bool define_type(CONF_SECTION *cs, fr_dict_attr_t const *da, char const *name)
{
	uint32_t value;
	fr_dict_enum_t *dval;

	/*
	 *	If the value already exists, don't
	 *	create it again.
	 */
	dval = fr_dict_enum_by_name(NULL, da, name);
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
		value = (fr_rand() & 0x00ffffff) + 1;
	} while (fr_dict_enum_by_da(NULL, da, value));

	cf_log_module(cs, "Creating %s = %s", da->name, name);
	if (fr_dict_enum_add(NULL, da->name, name, value) < 0) {
		ERROR("%s", fr_strerror());
		return false;
	}

	return true;
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
		cs2 = cf_section_sub_find_name2(cs, section_type_value[comp].typename, name2);
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
		if (listen_bootstrap(config, cs, NULL) < 0) return -1;
	}

	for (cs = cf_subsection_find_next(config, NULL, "server");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "server")) {
		CONF_ITEM *ci;
		CONF_SECTION *subcs;

		server_name = cf_section_name2(cs);
		if (!server_name) {
			cf_log_err_cs(cs, "server sections must have a name");
			return -1;
		}

		/*
		 *	Check for duplicates.
		 */
		subcs = cf_section_sub_find_name2(config, "server", server_name);
		if (subcs && (subcs != cs)) {
			ERROR("Duplicate virtual server \"%s\", in file %s:%d and file %s:%d",
			      server_name,
			      cf_section_filename(cs),
			      cf_section_lineno(cs),
			      cf_section_filename(subcs),
			      cf_section_lineno(subcs));
			return -1;
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
int virtual_servers_init(CONF_SECTION *config)
{
	CONF_SECTION *cs;

	DEBUG2("%s: #### Loading Virtual Servers ####", main_config.name);

	/*
	 *	Load all of the virtual servers.
	 */
	for (cs = cf_subsection_find_next(config, NULL, "server");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "server")) {
		if (virtual_servers_compile(cs) < 0) {
			return -1;
		}
	}

	return 0;
}

static bool is_reserved_word(const char *name)
{
	int i;

	if (!name || !*name) return false;

	for (i = 1; unlang_keyword[i] != NULL; i++) {
		if (strcmp(name, unlang_keyword[i]) == 0) return true;
	}

	return false;
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
	pool = cf_data_find(cs, CONNECTION_POOL_CF_KEY);
	if (!pool) {
		DEBUG4("%s: No pool reference found for config item \"%s.pool\"", log_prefix, parent_name(cs));
		pool = fr_connection_pool_init(cs, cs, opaque, c, a, log_prefix);
		if (!pool) return NULL;

		fr_connection_pool_enable_triggers(pool, trigger_prefix, trigger_args);

		DEBUG4("%s: Adding pool reference %p to config item \"%s.pool\"", log_prefix, pool, parent_name(cs));
		cf_data_add(cs, CONNECTION_POOL_CF_KEY, pool, NULL);
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
		cf_data_add(mycs, CONNECTION_POOL_CF_KEY, pool, NULL);
	}

	return pool;
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
	if (module_parse_conf(&insthandle, instance) < 0) {
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

/*
 *	Parse the module config sections, and load
 *	and call each module's init() function.
 */
int modules_bootstrap(CONF_SECTION *root)
{
	CONF_ITEM *ci, *next;
	CONF_SECTION *cs, *modules;

	/*
	 *	Set up the internal module struct.
	 */
	dlhandle_tree = rbtree_create(NULL, module_dlhandle_cmp, NULL, 0);
	if (!dlhandle_tree) {
		ERROR("Failed to initialize modules\n");
		return -1;
	}

	instance_ctx = talloc_init("module instance context");

	/*
	 *	Remember where the modules were stored.
	 */
	modules = cf_section_sub_find(root, "modules");
	if (!modules) {
		WARN("Cannot find a \"modules\" section in the rooturation file!");
	}

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
				module_t const *last = NULL;
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
						instance = module_instantiate_method(modules, cf_pair_attr(cp), NULL);
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

/** Instantiate the modules.
 *
 */
int modules_init(CONF_SECTION *root)
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

	return 0;
}


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


static rlm_rcode_t indexed_modcall(rlm_components_t comp, int idx, REQUEST *request)
{
	rlm_rcode_t rcode;
	CONF_SECTION *cs, *server_cs;
	char const *module;
	char const *component;

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
		request->server_cs = cf_section_sub_find_name2(main_config.config, "server", request->server);
	}

	cs = cf_section_sub_find(request->server_cs, section_type_value[comp].section);
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

		dv = fr_dict_enum_by_da(NULL, da, idx);
		if (!dv) return RLM_MODULE_FAIL;

		subcs = cf_section_sub_find_name2(cs, da->name, dv->name);
		if (subcs) {
			RDEBUG("Running %s %s from file %s",
			       da->name, dv->name, cf_section_filename(subcs));
		} else {
			RDEBUG2("%s %s sub-section not found.  Using default return values.",
				da->name, dv->name);
		}

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
	return indexed_modcall(MOD_AUTHORIZE, autz_type, request);
}

/*
 *	Authenticate a user/password with various methods.
 */
rlm_rcode_t process_authenticate(int auth_type, REQUEST *request)
{
	return indexed_modcall(MOD_AUTHENTICATE, auth_type, request);
}

#ifdef WITH_ACCOUNTING

/*
 *	Do pre-accounting for ALL configured sessions
 */
rlm_rcode_t process_preacct(REQUEST *request)
{
	return indexed_modcall(MOD_PREACCT, 0, request);
}

/*
 *	Do accounting for ALL configured sessions
 */
rlm_rcode_t process_accounting(int acct_type, REQUEST *request)
{
	return indexed_modcall(MOD_ACCOUNTING, acct_type, request);
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

	rcode = indexed_modcall(MOD_SESSION, sess_type, request);

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

	return indexed_modcall(MOD_PRE_PROXY, type, request);
}

/*
 *	Do post-proxying for ALL configured sessions
 */
rlm_rcode_t process_post_proxy(int type, REQUEST *request)
{
	rad_assert(request->proxy != NULL);

	return indexed_modcall(MOD_POST_PROXY, type, request);
}

#endif

/*
 *	Do post-authentication for ALL configured sessions
 */
rlm_rcode_t process_post_auth(int postauth_type, REQUEST *request)
{
	return indexed_modcall(MOD_POST_AUTH, postauth_type, request);
}

#ifdef WITH_COA

rlm_rcode_t process_recv_coa(int recv_coa_type, REQUEST *request)
{
	return indexed_modcall(MOD_RECV_COA, recv_coa_type, request);
}

rlm_rcode_t process_send_coa(int send_coa_type, REQUEST *request)
{
	return indexed_modcall(MOD_SEND_COA, send_coa_type, request);
}

#endif
