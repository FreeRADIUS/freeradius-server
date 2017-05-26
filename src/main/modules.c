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
#include <freeradius-devel/modcall.h>
#include <freeradius-devel/parser.h>
#include <freeradius-devel/rad_assert.h>

/** Path to search for modules in
 *
 */
char const *radlib_dir = NULL;

typedef struct indexed_modcallable {
	rlm_components_t	comp;
	int			idx;
	modcallable		*modulelist;
} indexed_modcallable;

typedef struct virtual_server_t {
	char const	*name;
	time_t		created;
	int		can_free;
	CONF_SECTION	*cs;
	rbtree_t	*components;
	modcallable	*mc[MOD_COUNT];
	CONF_SECTION	*subcs[MOD_COUNT];
	struct virtual_server_t *next;
} virtual_server_t;

/*
 *	Keep a hash of virtual servers, so that we can reload them.
 */
#define VIRTUAL_SERVER_HASH_SIZE (256)
static virtual_server_t *virtual_servers[VIRTUAL_SERVER_HASH_SIZE];

static rbtree_t *module_tree = NULL;

static rbtree_t *instance_tree = NULL;

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
#define RTLD_NOW (0)
#endif
#ifndef RTLD_LOCAL
#define RTLD_LOCAL (0)
#endif

#ifdef __APPLE__
#  define LT_SHREXT ".dylib"
#elif defined (WIN32)
#  define LT_SHREXT ".dll"
#else
#  define LT_SHREXT ".so"
#endif

/** Check if the magic number in the module matches the one in the library
 *
 * This is used to detect potential ABI issues caused by running with modules which
 * were built for a different version of the server.
 *
 * @param cs being parsed.
 * @param module being loaded.
 * @returns 0 on success, -1 if prefix mismatch, -2 if version mismatch, -3 if commit mismatch.
 */
static int check_module_magic(CONF_SECTION *cs, module_t const *module)
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

fr_dlhandle fr_dlopenext(char const *name)
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

			path = talloc_asprintf(ctx, "%s/%s%s", path, name, LT_SHREXT);

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
	strlcat(buffer, LT_SHREXT, sizeof(buffer));

	handle = dlopen(buffer, flags);
	if (!handle) {
		char *error = dlerror();

		DEBUG4("Failed with error: %s", error);
		/*
		 *	Don't overwrite the previous message
		 *	It's likely to contain a better error.
		 */
		if (!radlib_dir) fr_strerror_printf("%s", dlerror());
		return NULL;
	}
	return handle;
}

void *fr_dlsym(fr_dlhandle handle, char const *symbol)
{
	return dlsym(handle, symbol);
}

int fr_dlclose(fr_dlhandle handle)
{
	if (!handle) return 0;

	return dlclose(handle);
}

char const *fr_dlerror(void)
{
	return dlerror();
}

static int virtual_server_idx(char const *name)
{
	uint32_t hash;

	if (!name) return 0;

	hash = fr_hash_string(name);

	return hash & (VIRTUAL_SERVER_HASH_SIZE - 1);
}

static virtual_server_t *virtual_server_find(char const *name)
{
	rlm_rcode_t rcode;
	virtual_server_t *server;

	rcode = virtual_server_idx(name);
	for (server = virtual_servers[rcode];
	     server != NULL;
	     server = server->next) {
		if (!name && !server->name) break;

		if ((name && server->name) &&
		    (strcmp(name, server->name) == 0)) break;
	}

	return server;
}

static int _virtual_server_free(virtual_server_t *server)
{
	if (server->components) rbtree_free(server->components);
	return 0;
}

void virtual_servers_free(time_t when)
{
	int i;
	virtual_server_t **last;

	for (i = 0; i < VIRTUAL_SERVER_HASH_SIZE; i++) {
		virtual_server_t *server, *next;

		last = &virtual_servers[i];
		for (server = virtual_servers[i];
		     server != NULL;
		     server = next) {
			next = server->next;

			/*
			 *	If we delete it, fix the links so that
			 *	we don't orphan anything.  Also,
			 *	delete it if it's old, AND a newer one
			 *	was defined.
			 *
			 *	Otherwise, the last pointer gets set to
			 *	the one we didn't delete.
			 */
			if ((when == 0) ||
			    ((server->created < when) && server->can_free)) {
				*last = server->next;
				talloc_free(server);
			} else {
				last = &(server->next);
			}
		}
	}
}

static int indexed_modcallable_cmp(void const *one, void const *two)
{
	indexed_modcallable const *a = one;
	indexed_modcallable const *b = two;

	if (a->comp < b->comp) return -1;
	if (a->comp >  b->comp) return +1;

	return a->idx - b->idx;
}


/*
 *	Compare two module entries
 */
static int module_instance_cmp(void const *one, void const *two)
{
	module_instance_t const *a = one;
	module_instance_t const *b = two;

	return strcmp(a->name, b->name);
}


static void module_instance_free_old(UNUSED CONF_SECTION *cs, module_instance_t *node, time_t when)
{
	fr_module_hup_t *mh, **last;

	/*
	 *	Walk the list, freeing up old instances.
	 */
	last = &(node->mh);
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
 *	Free a module instance.
 */
static void module_instance_free(void *data)
{
	module_instance_t *module = talloc_get_type_abort(data, module_instance_t);

	module_instance_free_old(module->cs, module, time(NULL) + 100);

#ifdef HAVE_PTHREAD_H
	if (module->mutex) {
		/*
		 *	FIXME
		 *	The mutex MIGHT be locked...
		 *	we'll check for that later, I guess.
		 */
		pthread_mutex_destroy(module->mutex);
		talloc_free(module->mutex);
	}
#endif

	xlat_unregister(module->name, NULL, module->insthandle);

	/*
	 *	Remove all xlat's registered to module instance.
	 */
	if (module->insthandle) {
		/*
		 *	Remove any registered paircompares.
		 */
		paircompare_unregister_instance(module->insthandle);

		xlat_unregister_module(module->insthandle);
	}
	talloc_free(module);
}


/*
 *	Compare two module entries
 */
static int module_entry_cmp(void const *one, void const *two)
{
	module_entry_t const *a = one;
	module_entry_t const *b = two;

	return strcmp(a->name, b->name);
}

/*
 *	Free a module entry.
 */
static int _module_entry_free(module_entry_t *this)
{
#ifndef NDEBUG
	/*
	 *	Don't dlclose() modules if we're doing memory
	 *	debugging.  This removes the symbols needed by
	 *	valgrind.
	 */
	if (!main_config.debug_memory)
#endif
		dlclose(this->handle);	/* ignore any errors */
	return 0;
}


/*
 *	Remove the module lists.
 */
int modules_free(void)
{
	rbtree_free(instance_tree);
	rbtree_free(module_tree);

	return 0;
}


/*
 *	dlopen() a module.
 */
static module_entry_t *module_dlopen(CONF_SECTION *cs, char const *module_name)
{
	module_entry_t myentry;
	module_entry_t *node;
	void *handle = NULL;
	module_t const *module;

	strlcpy(myentry.name, module_name, sizeof(myentry.name));
	node = rbtree_finddata(module_tree, &myentry);
	if (node) return node;

	/*
	 *	Link to the module's rlm_FOO{} structure, the same as
	 *	the module name.
	 */

#if !defined(WITH_LIBLTDL) && defined(HAVE_DLFCN_H) && defined(RTLD_SELF)
	module = dlsym(RTLD_SELF, module_name);
	if (module) goto open_self;
#endif

	/*
	 *	Keep the handle around so we can dlclose() it.
	 */
	handle = fr_dlopenext(module_name);
	if (!handle) {
		cf_log_err_cs(cs, "Failed to link to module '%s': %s", module_name, fr_strerror());
		return NULL;
	}

	DEBUG3("Loaded %s, checking if it's valid", module_name);

	module = dlsym(handle, module_name);
	if (!module) {
		cf_log_err_cs(cs, "Failed linking to %s structure: %s", module_name, dlerror());
		dlclose(handle);
		return NULL;
	}

#if !defined(WITH_LIBLTDL) && defined (HAVE_DLFCN_H) && defined(RTLD_SELF)
 open_self:
#endif
	/*
	 *	Before doing anything else, check if it's sane.
	 */
	if (check_module_magic(cs, module) < 0) {
		dlclose(handle);
		return NULL;
	}

	/* make room for the module type */
	node = talloc_zero(cs, module_entry_t);
	talloc_set_destructor(node, _module_entry_free);
	strlcpy(node->name, module_name, sizeof(node->name));
	node->module = module;
	node->handle = handle;

	cf_log_module(cs, "Loaded module %s", module_name);

	/*
	 *	Add the module as "rlm_foo-version" to the configuration
	 *	section.
	 */
	if (!rbtree_insert(module_tree, node)) {
		ERROR("Failed to cache module %s", module_name);
		dlclose(handle);
		talloc_free(node);
		return NULL;
	}

	return node;
}

/** Parse module's configuration section and setup destructors
 *
 */
static int module_conf_parse(module_instance_t *node, void **handle)
{
	*handle = NULL;

	/*
	 *	If there is supposed to be instance data, allocate it now.
	 *	Also parse the configuration data, if required.
	 */
	if (node->entry->module->inst_size) {
		*handle = talloc_zero_array(node, uint8_t, node->entry->module->inst_size);
		rad_assert(*handle);

		talloc_set_name(*handle, "rlm_%s_t",
				node->entry->module->name ? node->entry->module->name : "config");

		if (node->entry->module->config &&
		    (cf_section_parse(node->cs, *handle, node->entry->module->config) < 0)) {
			cf_log_err_cs(node->cs,"Invalid configuration for module \"%s\"", node->name);
			talloc_free(*handle);

			return -1;
		}

		/*
		 *	Set the destructor.
		 */
		if (node->entry->module->detach) {
			talloc_set_destructor(*handle, node->entry->module->detach);
		}
	}

	return 0;
}

/** Bootstrap a module.
 *
 *  Load the module shared library, allocate instance memory for it,
 *  parse the module configuration, and call the modules "bootstrap" method.
 */
static module_instance_t *module_bootstrap(CONF_SECTION *cs)
{
	char const *name1, *name2;
	module_instance_t *node, myNode;
	char module_name[256];

	/*
	 *	Figure out which module we want to load.
	 */
	name1 = cf_section_name1(cs);
	name2 = cf_section_name2(cs);
	if (!name2) name2 = name1;

	strlcpy(myNode.name, name2, sizeof(myNode.name));

	/*
	 *	See if the module already exists.
	 */
	node = rbtree_finddata(instance_tree, &myNode);
	if (node) {
		ERROR("Duplicate module \"%s %s\", in file %s:%d and file %s:%d",
		      name1, name2,
		      cf_section_filename(cs),
		      cf_section_lineno(cs),
		      cf_section_filename(node->cs),
		      cf_section_lineno(node->cs));
		return NULL;
	}

	/*
	 *	Hang the node struct off of the configuration
	 *	section. If the CS is free'd the instance will be
	 *	free'd, too.
	 */
	node = talloc_zero(instance_tree, module_instance_t);
	node->cs = cs;
	strlcpy(node->name, name2, sizeof(node->name));

	/*
	 *	Names in the "modules" section aren't prefixed
	 *	with "rlm_", so we add it here.
	 */
	snprintf(module_name, sizeof(module_name), "rlm_%s", name1);

	/*
	 *	Load the module shared library.
	 */
	node->entry = module_dlopen(cs, module_name);
	if (!node->entry) {
		talloc_free(node);
		return NULL;
	}

	cf_log_module(cs, "Loading module \"%s\" from file %s", node->name,
		      cf_section_filename(cs));

	/*
	 *	Parse the modules configuration.
	 */
	if (module_conf_parse(node, &node->insthandle) < 0) {
		talloc_free(node);
		return NULL;
	}

	/*
	 *	Bootstrap the module.
	 */
	if (node->entry->module->bootstrap &&
	    ((node->entry->module->bootstrap)(cs, node->insthandle) < 0)) {
		cf_log_err_cs(cs, "Instantiation failed for module \"%s\"", node->name);
		talloc_free(node);
		return NULL;
	}

	/*
	 *	Remember the module for later.
	 */
	rbtree_insert(instance_tree, node);

	return node;
}


/** Find an existing module instance.
 *
 */
module_instance_t *module_find(CONF_SECTION *modules, char const *askedname)
{
	char const *instname;
	module_instance_t myNode;

	if (!modules) return NULL;

	/*
	 *	Look for the real name.  Ignore the first character,
	 *	which tells the server "it's OK for this module to not
	 *	exist."
	 */
	instname = askedname;
	if (instname[0] == '-') instname++;

	strlcpy(myNode.name, instname, sizeof(myNode.name));

	return rbtree_finddata(instance_tree, &myNode);
}


/** Load a module, and instantiate it.
 *
 */
module_instance_t *module_instantiate(CONF_SECTION *modules, char const *askedname)
{
	module_instance_t *node;

	/*
	 *	Find the module.  If it's not there, do nothing.
	 */
	node = module_find(modules, askedname);
	if (!node) {
		ERROR("Cannot find module \"%s\"", askedname);
		return NULL;
	}

	/*
	 *	The module is already instantiated.  Return it.
	 */
	if (node->instantiated) return node;

	/*
	 *	Now that ALL modules are instantiated, and ALL xlats
	 *	are defined, go compile the config items marked as XLAT.
	 */
	if (node->entry->module->config &&
	    (cf_section_parse_pass2(node->cs, node->insthandle,
				    node->entry->module->config) < 0)) {
		return NULL;
	}

	/*
	 *	Call the instantiate method, if any.
	 */
	if (node->entry->module->instantiate) {
		cf_log_module(node->cs, "Instantiating module \"%s\" from file %s", node->name,
			      cf_section_filename(node->cs));

		/*
		 *	Call the module's instantiation routine.
		 */
		if ((node->entry->module->instantiate)(node->cs, node->insthandle) < 0) {
			cf_log_err_cs(node->cs, "Instantiation failed for module \"%s\"", node->name);

			return NULL;
		}
	}

#ifdef HAVE_PTHREAD_H
	/*
	 *	If we're threaded, check if the module is thread-safe.
	 *
	 *	If it isn't, we create a mutex.
	 */
	if ((node->entry->module->type & RLM_TYPE_THREAD_UNSAFE) != 0) {
		node->mutex = talloc_zero(node, pthread_mutex_t);

		/*
		 *	Initialize the mutex.
		 */
		pthread_mutex_init(node->mutex, NULL);
	}
#endif

	node->instantiated = true;
	node->last_hup = time(NULL); /* don't let us load it, then immediately hup it */

	return node;
}


module_instance_t *module_instantiate_method(CONF_SECTION *modules, char const *name, rlm_components_t *method)
{
	char *p;
	rlm_components_t i;
	module_instance_t *mi;

	/*
	 *	If the module exists, ensure it's instantiated.
	 *
	 *	Doing it this way avoids complaints from
	 *	module_instantiate()
	 */
	mi = module_find(modules, name);
	if (mi) return module_instantiate(modules, name);

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

			mi = module_find(modules, buffer);
			if (mi) {
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


/** Resolve polymorphic item's from a module's CONF_SECTION to a subsection in another module
 *
 * This allows certain module sections to reference module sections in other instances
 * of the same module and share CONF_DATA associated with them.
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
 * @param out where to write the pointer to a module's config section.  May be NULL on success, indicating the config
 *	  item was not found within the module CONF_SECTION, or the chain of module references was followed and the
 *	  module at the end of the chain did not a subsection.
 * @param module CONF_SECTION.
 * @param name of the polymorphic sub-section.
 * @return 0 on success with referenced section, 1 on success with local section, or -1 on failure.
 */
int find_module_sibling_section(CONF_SECTION **out, CONF_SECTION *module, char const *name)
{
	static bool loop = true;	/* not used, we just need a valid pointer to quiet static analysis */

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

static indexed_modcallable *lookup_by_index(rbtree_t *components,
					    rlm_components_t comp, int idx)
{
	indexed_modcallable myc;

	myc.comp = comp;
	myc.idx = idx;

	return rbtree_finddata(components, &myc);
}

/*
 *	Create a new sublist.
 */
static indexed_modcallable *new_sublist(CONF_SECTION *cs,
					rbtree_t *components, rlm_components_t comp, int idx)
{
	indexed_modcallable *c;

	c = lookup_by_index(components, comp, idx);

	/* It is an error to try to create a sublist that already
	 * exists. It would almost certainly be caused by accidental
	 * duplication in the config file.
	 *
	 * index 0 is the exception, because it is used when we want
	 * to collect _all_ listed modules under a single index by
	 * default, which is currently the case in all components
	 * except authenticate. */
	if (c) {
		if (idx == 0) {
			return c;
		}
		return NULL;
	}

	c = talloc_zero(cs, indexed_modcallable);
	c->modulelist = NULL;
	c->comp = comp;
	c->idx = idx;

	if (!rbtree_insert(components, c)) {
		talloc_free(c);
		return NULL;
	}

	return c;
}

rlm_rcode_t indexed_modcall(rlm_components_t comp, int idx, REQUEST *request)
{
	rlm_rcode_t rcode;
	modcallable *list = NULL;
	virtual_server_t *server;

	/*
	 *	Hack to find the correct virtual server.
	 */
	server = virtual_server_find(request->server);
	if (!server) {
		RDEBUG("No such virtual server \"%s\"", request->server);
		return RLM_MODULE_FAIL;
	}

	if (idx == 0) {
		list = server->mc[comp];
		if (!list) {
			if (server->name) {
				RDEBUG3("Empty %s section in virtual server \"%s\".  Using default return values.",
					section_type_value[comp].section, server->name);
			} else {
				RDEBUG3("Empty %s section.  Using default return values.", section_type_value[comp].section);
			}
		}
	} else {
		indexed_modcallable *this;

		this = lookup_by_index(server->components, comp, idx);
		if (this) {
			list = this->modulelist;
		} else {
			RDEBUG2("%s sub-section not found.  Ignoring.", section_type_value[comp].typename);
		}
	}

	if (server->subcs[comp]) {
		if (idx == 0) {
			RDEBUG("# Executing section %s from file %s",
			       section_type_value[comp].section,
			       cf_section_filename(server->subcs[comp]));
		} else {
			RDEBUG("# Executing group from file %s",
			       cf_section_filename(server->subcs[comp]));
		}
	}
	request->component = section_type_value[comp].section;

	rcode = modcall(comp, list, request);

	request->module = "";
	request->component = "<core>";
	return rcode;
}

/*
 *	Load a sub-module list, as found inside an Auth-Type foo {}
 *	block
 */
static int load_subcomponent_section(CONF_SECTION *cs,
				     rbtree_t *components,
				     DICT_ATTR const *da, rlm_components_t comp)
{
	indexed_modcallable *subcomp;
	modcallable *ml;
	DICT_VALUE *dval;
	char const *name2 = cf_section_name2(cs);

	/*
	 *	Sanity check.
	 */
	if (!name2) {
		return 1;
	}

	/*
	 *	Compile the group.
	 */
	ml = compile_modgroup(NULL, comp, cs);
	if (!ml) {
		return 0;
	}

	/*
	 *	We must assign a numeric index to this subcomponent.
	 *	It is generated and placed in the dictionary
	 *	automatically.  If it isn't found, it's a serious
	 *	error.
	 */
	dval = dict_valbyname(da->attr, da->vendor, name2);
	if (!dval) {
		talloc_free(ml);
		cf_log_err_cs(cs,
			   "The %s attribute has no VALUE defined for %s",
			      section_type_value[comp].typename, name2);
		return 0;
	}

	subcomp = new_sublist(cs, components, comp, dval->value);
	if (!subcomp) {
		talloc_free(ml);
		return 1;
	}

	/*
	 *	Link it into the talloc hierarchy.
	 */
	subcomp->modulelist = talloc_steal(subcomp, ml);
	return 1;		/* OK */
}

/*
 *	Don't complain too often.
 */
#define MAX_IGNORED (32)
static int last_ignored = -1;
static char const *ignored[MAX_IGNORED];

static int load_component_section(CONF_SECTION *cs,
				  rbtree_t *components, rlm_components_t comp)
{
	modcallable *this;
	CONF_ITEM *modref;
	int idx;
	indexed_modcallable *subcomp;
	char const *modname;
	DICT_ATTR const *da;

	/*
	 *	Find the attribute used to store VALUEs for this section.
	 */
	da = dict_attrbyvalue(section_type_value[comp].attr, 0);
	if (!da) {
		cf_log_err_cs(cs,
			   "No such attribute %s",
			   section_type_value[comp].typename);
		return -1;
	}

	/*
	 *	Loop over the entries in the named section, loading
	 *	the sections this time.
	 */
	for (modref = cf_item_find_next(cs, NULL);
	     modref != NULL;
	     modref = cf_item_find_next(cs, modref)) {
		char const *name1;
		CONF_PAIR *cp = NULL;
		CONF_SECTION *scs = NULL;

		if (cf_item_is_section(modref)) {
			scs = cf_item_to_section(modref);

			name1 = cf_section_name1(scs);

			if (strcmp(name1,
				   section_type_value[comp].typename) == 0) {
				if (!load_subcomponent_section(scs,
							       components,
							       da,
							       comp)) {

					return -1; /* FIXME: memleak? */
				}
				continue;
			}

			cp = NULL;

		} else if (cf_item_is_pair(modref)) {
			cp = cf_item_to_pair(modref);

		} else {
			continue; /* ignore it */
		}

		/*
		 *	Look for Auth-Type foo {}, which are special
		 *	cases of named sections, and allowable ONLY
		 *	at the top-level.
		 *
		 *	i.e. They're not allowed in a "group" or "redundant"
		 *	subsection.
		 */
		if (comp == MOD_AUTHENTICATE) {
			DICT_VALUE *dval;
			char const *modrefname = NULL;
			if (cp) {
				modrefname = cf_pair_attr(cp);
			} else {
				modrefname = cf_section_name2(scs);
				if (!modrefname) {
					cf_log_err_cs(cs,
						   "Errors parsing %s sub-section.\n",
						   cf_section_name1(scs));
					return -1;
				}
			}

			dval = dict_valbyname(PW_AUTH_TYPE, 0, modrefname);
			if (!dval) {
				/*
				 *	It's a section, but nothing we
				 *	recognize.  Die!
				 */
				cf_log_err_cs(cs,
					   "Unknown Auth-Type \"%s\" in %s sub-section.",
					   modrefname, section_type_value[comp].section);
				return -1;
			}
			idx = dval->value;
		} else {
			/* See the comment in new_sublist() for explanation
			 * of the special index 0 */
			idx = 0;
		}

		subcomp = new_sublist(cs, components, comp, idx);
		if (!subcomp) continue;

		/*
		 *	Try to compile one entry.
		 */
		this = compile_modsingle(subcomp, &subcomp->modulelist, comp, modref, &modname);

		/*
		 *	It's OK for the module to not exist.
		 */
		if (!this && modname && (modname[0] == '-')) {
			int i;

			if (last_ignored < 0) {
			save_complain:
				last_ignored++;
				ignored[last_ignored] = modname;

			complain:
				WARN("Ignoring \"%s\" (see raddb/mods-available/README.rst)", modname + 1);
				continue;
			}

			if (last_ignored >= MAX_IGNORED) goto complain;

			for (i = 0; i <= last_ignored; i++) {
				if (strcmp(ignored[i], modname) == 0) {
					break;
				}
			}

			if (i > last_ignored) goto save_complain;
			continue;
		}

		if (!this) {
			cf_log_err_cs(cs,
				   "Errors parsing %s section.\n",
				   cf_section_name1(cs));
			return -1;
		}

		if (rad_debug_lvl > 2) modcall_debug(this, 2);

		add_to_modcallable(subcomp->modulelist, this);
	}


	return 0;
}

static int load_byserver(CONF_SECTION *cs)
{
	rlm_components_t comp;
	bool found;
	char const *name = cf_section_name2(cs);
	rbtree_t *components;
	virtual_server_t *server = NULL;
	indexed_modcallable *c;
	bool is_bare;

	if (name) {
		cf_log_info(cs, "server %s { # from file %s",
			    name, cf_section_filename(cs));
	} else {
		cf_log_info(cs, "server { # from file %s",
			    cf_section_filename(cs));
	}

	is_bare = (cf_item_parent(cf_section_to_item(cs)) == NULL);

	server = talloc_zero(cs, virtual_server_t);
	server->name = name;
	server->created = time(NULL);
	server->cs = cs;
	server->components = components = rbtree_create(server, indexed_modcallable_cmp, NULL, 0);
	if (!components) {
		ERROR("Failed to initialize components");

	error:
		if (rad_debug_lvl == 0) {
			ERROR("Failed to load virtual server %s",
			      (name != NULL) ? name : "<default>");
		}
		return -1;
	}
	talloc_set_destructor(server, _virtual_server_free);

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

		if (is_bare) {
			cf_log_err_cs(subcs, "The %s section should be inside of a 'server { ... }' block!",
				      section_type_value[comp].section);
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

		if (rad_debug_lvl <= 3) {
			cf_log_module(cs, "Loading %s {...}",
				      section_type_value[comp].section);
		} else {
			DEBUG(" %s {", section_type_value[comp].section);
		}

		if (load_component_section(subcs, components, comp) < 0) {
			goto error;
		}

		if (rad_debug_lvl > 3) {
			DEBUG(" } # %s", section_type_value[comp].section);
		}

		/*
		 *	Cache a default, if it exists.  Some people
		 *	put empty sections for some reason...
		 */
		c = lookup_by_index(components, comp, 0);
		if (c) server->mc[comp] = c->modulelist;

		server->subcs[comp] = subcs;

		found = true;
	} /* loop over components */

	/*
	 *	We haven't loaded any of the normal sections.  Maybe we're
	 *	supposed to load the vmps section.
	 *
	 *	This is a bit of a hack...
	 */
	if (!found) do {
#if defined(WITH_VMPS) || defined(WITH_DHCP)
		CONF_SECTION *subcs;
#endif
#ifdef WITH_DHCP
		DICT_ATTR const *da;
#endif

#ifdef WITH_VMPS
		subcs = cf_section_sub_find(cs, "vmps");
		if (subcs) {
			cf_log_module(cs, "Loading vmps {...}");
			if (load_component_section(subcs, components,
						   MOD_POST_AUTH) < 0) {
				goto error;
			}
			c = lookup_by_index(components,
					    MOD_POST_AUTH, 0);
			if (c) server->mc[MOD_POST_AUTH] = c->modulelist;
			break;
		}
#endif

#ifdef WITH_DHCP
		/*
		 *	It's OK to not have DHCP.
		 */
		subcs = cf_subsection_find_next(cs, NULL, "dhcp");
		if (!subcs) break;

		da = dict_attrbyname("DHCP-Message-Type");

		/*
		 *	Handle each DHCP Message type separately.
		 */
		while (subcs) {
			char const *name2 = cf_section_name2(subcs);

			if (name2) {
				cf_log_module(cs, "Loading dhcp %s {...}", name2);
			} else {
				cf_log_module(cs, "Loading dhcp {...}");
			}
			if (!load_subcomponent_section(subcs,
						       components,
						       da,
						       MOD_POST_AUTH)) {
				goto error; /* FIXME: memleak? */
			}
			c = lookup_by_index(components,
					    MOD_POST_AUTH, 0);
			if (c) server->mc[MOD_POST_AUTH] = c->modulelist;

			subcs = cf_subsection_find_next(cs, subcs, "dhcp");
		}
#endif
	} while (0);

	if (name) {
		cf_log_info(cs, "} # server %s", name);
	} else {
		cf_log_info(cs, "} # server");
	}

	if (rad_debug_lvl == 0) {
		INFO("Loaded virtual server %s",
		       (name != NULL) ? name : "<default>");
	}

	/*
	 *	Now that it is OK, insert it into the list.
	 *
	 *	This is thread-safe...
	 */
	comp = virtual_server_idx(name);
	server->next = virtual_servers[comp];
	virtual_servers[comp] = server;

	/*
	 *	Mark OLDER ones of the same name as being unused.
	 */
	server = server->next;
	while (server) {
		if ((!name && !server->name) ||
		    (name && server->name &&
		     (strcmp(server->name, name) == 0))) {
			server->can_free = true;
			break;
		}
		server = server->next;
	}

	return 0;
}


static int pass2_cb(UNUSED void *ctx, void *data)
{
	indexed_modcallable *this = data;

	if (!modcall_pass2(this->modulelist)) return -1;

	return 0;
}


/*
 *	Load all of the virtual servers.
 */
int virtual_servers_load(CONF_SECTION *config)
{
	CONF_SECTION *cs;
	virtual_server_t *server;
	static bool first_time = true;

	DEBUG2("%s: #### Loading Virtual Servers ####", main_config.name);

	/*
	 *	If we have "server { ...}", then there SHOULD NOT be
	 *	bare "authorize", etc. sections.  if there is no such
	 *	server, then try to load the old-style sections first.
	 *
	 *	In either case, load the "default" virtual server first.
	 *	this matches better with users expectations.
	 */
	cs = cf_section_find_name2(cf_subsection_find_next(config, NULL,
							   "server"),
				   "server", NULL);
	if (cs) {
		if (load_byserver(cs) < 0) {
			return -1;
		}
	} else {
		if (load_byserver(config) < 0) {
			return -1;
		}
	}

	/*
	 *	Load all of the virtual servers.
	 */
	for (cs = cf_subsection_find_next(config, NULL, "server");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "server")) {
		char const *name2;

		name2 = cf_section_name2(cs);
		if (!name2) continue; /* handled above */

		server = virtual_server_find(name2);
		if (server &&
		    (cf_top_section(server->cs) == config)) {
			ERROR("Duplicate virtual server \"%s\" in file %s:%d and file %s:%d",
			       server->name,
			       cf_section_filename(server->cs),
			       cf_section_lineno(server->cs),
			       cf_section_filename(cs),
			       cf_section_lineno(cs));
			return -1;
		}

		if (load_byserver(cs) < 0) {
			/*
			 *	Once we successfully started once,
			 *	continue loading the OTHER servers,
			 *	even if one fails.
			 */
			if (!first_time) continue;
			return -1;
		}
	}

	/*
	 *	Try to compile the "authorize", etc. sections which
	 *	aren't in a virtual server.
	 */
	server = virtual_server_find(NULL);
	if (server) {
		int i;

		for (i = MOD_AUTHENTICATE; i < MOD_COUNT; i++) {
			if (!modcall_pass2(server->mc[i])) return -1;
		}

		if (server->components &&
		    (rbtree_walk(server->components, RBTREE_IN_ORDER,
				 pass2_cb, NULL) != 0)) {
			return -1;
		}
	}

	/*
	 *	Now that we've loaded everything, run pass 2 over the
	 *	conditions and xlats.
	 */
	for (cs = cf_subsection_find_next(config, NULL, "server");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "server")) {
		int i;
		char const *name2;

		name2 = cf_section_name2(cs);

		server = virtual_server_find(name2);
		if (!server) continue;

		for (i = MOD_AUTHENTICATE; i < MOD_COUNT; i++) {
			if (!modcall_pass2(server->mc[i])) return -1;
		}

		if (server->components &&
		    (rbtree_walk(server->components, RBTREE_IN_ORDER,
				 pass2_cb, NULL) != 0)) {
			return -1;
		}
	}

	/*
	 *	If we succeed the first time around, remember that.
	 */
	first_time = false;

	return 0;
}

int module_hup_module(CONF_SECTION *cs, module_instance_t *node, time_t when)
{
	void *insthandle;
	fr_module_hup_t *mh;

	if (!node ||
	    node->entry->module->bootstrap ||
	    !node->entry->module->instantiate ||
	    ((node->entry->module->type & RLM_TYPE_HUP_SAFE) == 0)) {
		return 1;
	}

	/*
	 *	Silently ignore multiple HUPs within a short time period.
	 */
	if ((node->last_hup + 2) >= when) return 1;
	node->last_hup = when;

	cf_log_module(cs, "Trying to reload module \"%s\"", node->name);

	/*
	 *	Parse the module configuration, and setup destructors so the
	 *	module's detach method is called when it's instance data is
	 *	about to be freed.
	 */
	if (module_conf_parse(node, &insthandle) < 0) {
		cf_log_err_cs(cs, "HUP failed for module \"%s\" (parsing config failed). "
			      "Using old configuration", node->name);

		return 0;
	}

	if ((node->entry->module->instantiate)(cs, insthandle) < 0) {
		cf_log_err_cs(cs, "HUP failed for module \"%s\".  Using old configuration.", node->name);
		talloc_free(insthandle);

		return 0;
	}

	INFO(" Module: Reloaded module \"%s\"", node->name);

	module_instance_free_old(cs, node, when);

	/*
	 *	Save the old instance handle for later deletion.
	 */
	mh = talloc_zero(cs, fr_module_hup_t);
	mh->mi = node;
	mh->when = when;
	mh->insthandle = node->insthandle;
	mh->next = node->mh;
	node->mh = mh;

	/*
	 *	Replace the instance handle while the module is running.
	 */
	node->insthandle = insthandle;

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
	module_instance_t *node;

	if (!modules) return 0;

	when = time(NULL);

	/*
	 *	Loop over the modules
	 */
	for (ci=cf_item_find_next(modules, NULL);
	     ci != NULL;
	     ci=cf_item_find_next(modules, ci)) {
		char const *instname;
		module_instance_t myNode;

		/*
		 *	If it's not a section, ignore it.
		 */
		if (!cf_item_is_section(ci)) continue;

		cs = cf_item_to_section(ci);
		instname = cf_section_name2(cs);
		if (!instname) instname = cf_section_name1(cs);

		strlcpy(myNode.name, instname, sizeof(myNode.name));
		node = rbtree_finddata(instance_tree, &myNode);

		module_hup_module(cs, node, when);
	}

	return 1;
}


static int define_type(CONF_SECTION *cs, DICT_ATTR const *da, char const *name)
{
	uint32_t value;
	DICT_VALUE *dval;

	/*
	 *	If the value already exists, don't
	 *	create it again.
	 */
	dval = dict_valbyname(da->attr, da->vendor, name);
	if (dval) {
		if (dval->value == 0) {
			ERROR("The dictionaries must not define VALUE %s %s 0",
			      da->name, name);
			return 0;
		}
		return 1;
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
	} while (dict_valbyattr(da->attr, da->vendor, value));

	cf_log_module(cs, "Creating %s = %s", da->name, name);
	if (dict_addvalue(name, da->name, value) < 0) {
		ERROR("%s", fr_strerror());
		return 0;
	}

	return 1;
}

/*
 *	Define Auth-Type, etc. in a server.
 */
static bool server_define_types(CONF_SECTION *cs)
{
	rlm_components_t	comp;

	/*
	 *	Loop over all of the components
	 */
	for (comp = 0; comp < MOD_COUNT; ++comp) {
		CONF_SECTION *subcs, *type_cs;
		DICT_ATTR const *da;

		subcs = cf_section_sub_find(cs,
					    section_type_value[comp].section);
		if (!subcs) continue;

		if (cf_item_find_next(subcs, NULL) == NULL) continue;

		/*
		 *	Find the attribute used to store VALUEs for this section.
		 */
		da = dict_attrbyvalue(section_type_value[comp].attr, 0);
		if (!da) {
			cf_log_err_cs(subcs,
				   "No such attribute %s",
				   section_type_value[comp].typename);
			return false;
		}

		/*
		 *	Define dynamic types, so that others can reference
		 *	them.
		 *
		 *	First, bare modules for 'authenticate'.
		 *	Second, Auth-Type, etc.
		 */
		if (section_type_value[comp].attr == PW_AUTH_TYPE) {
			CONF_ITEM *modref;

			for (modref = cf_item_find_next(subcs, NULL);
			     modref != NULL;
			     modref = cf_item_find_next(subcs, modref)) {
				CONF_PAIR *cp;

				if (!cf_item_is_pair(modref)) continue;

				cp = cf_item_to_pair(modref);
				if (!define_type(cs, da, cf_pair_attr(cp))) {
					return false;
				}

				/*
				 *	Check for duplicates
				 */
				if (rad_debug_lvl) {
					CONF_PAIR *cp2;
					CONF_SECTION *cs2;

					cp2 = cf_pair_find(subcs, cf_pair_attr(cp));
					rad_assert(cp2 != NULL);
					if (cp2 != cp) {
						WARN("%s[%d]: Duplicate module '%s'",
						     cf_pair_filename(cp2),
						     cf_pair_lineno(cp2),
						     cf_pair_attr(cp));
					}

					cs2 = cf_section_sub_find_name2(subcs, section_type_value[comp].typename, cf_pair_attr(cp));
					if (cs2) {
						WARN("%s[%d]: Duplicate Auth-Type '%s'",
						     cf_section_filename(cs2),
						     cf_section_lineno(cs2),
						     cf_pair_attr(cp));
					}
				}

			}
		}

		/*
		 *	And loop over the type names
		 */
		for (type_cs = cf_subsection_find_next(subcs, NULL, section_type_value[comp].typename);
		     type_cs != NULL;
		     type_cs = cf_subsection_find_next(subcs, type_cs, section_type_value[comp].typename)) {
			if (!define_type(cs, da, cf_section_name2(type_cs))) {
				return false;
			}

			if (rad_debug_lvl) {
				CONF_SECTION *cs2;

				cs2 = cf_section_sub_find_name2(subcs, section_type_value[comp].typename, cf_section_name2(type_cs));
				rad_assert(cs2 != NULL);
				if (cs2 != type_cs) {
					WARN("%s[%d]: Duplicate Auth-Type '%s'",
					     cf_section_filename(cs2),
					     cf_section_lineno(cs2),
					     cf_section_name2(cs2));
				}
			}
		}
	} /* loop over components */

	return true;
}

extern char const *unlang_keyword[];

static bool is_reserved_word(const char *name)
{
	int i;

	if (!name || !*name) return false;

	for (i = 1; unlang_keyword[i] != NULL; i++) {
		if (strcmp(name, unlang_keyword[i]) == 0) return true;
	}

	return false;
}


/*
 *	Parse the module config sections, and load
 *	and call each module's init() function.
 */
int modules_init(CONF_SECTION *config)
{
	CONF_ITEM	*ci, *next;
	CONF_SECTION	*cs, *modules;

	/*
	 *	Set up the internal module struct.
	 */
	module_tree = rbtree_create(NULL, module_entry_cmp, NULL, 0);
	if (!module_tree) {
		ERROR("Failed to initialize modules\n");
		return -1;
	}

	instance_tree = rbtree_create(NULL, module_instance_cmp,
				      module_instance_free, 0);
	if (!instance_tree) {
		ERROR("Failed to initialize modules\n");
		return -1;
	}

	memset(virtual_servers, 0, sizeof(virtual_servers));

	/*
	 *	Remember where the modules were stored.
	 */
	modules = cf_section_sub_find(config, "modules");
	if (!modules) {
		WARN("Cannot find a \"modules\" section in the configuration file!");
	}

	/*
	 *	Load dictionaries.
	 */
	for (cs = cf_subsection_find_next(config, NULL, "server");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "server")) {
#if defined(WITH_DHCP) || defined(WITH_VMPS)
		CONF_SECTION *subcs;
		DICT_ATTR const *da;
#endif

#ifdef WITH_VMPS
		/*
		 *	Auto-load the VMPS/VQP dictionary.
		 */
		subcs = cf_section_sub_find(cs, "vmps");
		if (subcs) {
			da = dict_attrbyname("VQP-Packet-Type");
			if (!da) {
				if (dict_read(main_config.dictionary_dir, "dictionary.vqp") < 0) {
					ERROR("Failed reading dictionary.vqp: %s",
					      fr_strerror());
					return -1;
				}
				cf_log_module(cs, "Loading dictionary.vqp");

				da = dict_attrbyname("VQP-Packet-Type");
				if (!da) {
					ERROR("No VQP-Packet-Type in dictionary.vqp");
					return -1;
				}
			}
		}
#endif

#ifdef WITH_DHCP
		/*
		 *	Auto-load the DHCP dictionary.
		 */
		subcs = cf_subsection_find_next(cs, NULL, "dhcp");
		if (subcs) {
			da = dict_attrbyname("DHCP-Message-Type");
			if (!da) {
				cf_log_module(cs, "Loading dictionary.dhcp");
				if (dict_read(main_config.dictionary_dir, "dictionary.dhcp") < 0) {
					ERROR("Failed reading dictionary.dhcp: %s",
					      fr_strerror());
					return -1;
				}

				da = dict_attrbyname("DHCP-Message-Type");
				if (!da) {
					ERROR("No DHCP-Message-Type in dictionary.dhcp");
					return -1;
				}
			}
		}
#endif
		/*
		 *	Else it's a RADIUS virtual server, and the
		 *	dictionaries are already loaded.
		 */

		/*
		 *	Root through each virtual server, defining
		 *	Autz-Type and Auth-Type.  This is so that the
		 *	modules can reference a particular type.
		 */
		if (!server_define_types(cs)) return -1;
	}

	DEBUG2("%s: #### Instantiating modules ####", main_config.name);

	cf_log_info(config, " modules {");

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
		module_instance_t *node;

		next = cf_item_find_next(modules, ci);

		if (!cf_item_is_section(ci)) continue;

		subcs = cf_item_to_section(ci);

		node = module_bootstrap(subcs);
		if (!node) return -1;

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
	cs = cf_section_sub_find(config, "instantiate");
	if (cs) {
		CONF_PAIR *cp;
		module_instance_t *module;
		char const *name;

		cf_log_info(cs, "  instantiate {");

		/*
		 *  Loop over the items in the 'instantiate' section.
		 */
		for (ci=cf_item_find_next(cs, NULL);
		     ci != NULL;
		     ci=cf_item_find_next(cs, ci)) {
			/*
			 *	Skip sections and "other" stuff.
			 *	Sections will be handled later, if
			 *	they're referenced at all...
			 */
			if (cf_item_is_pair(ci)) {
				cp = cf_item_to_pair(ci);
				name = cf_pair_attr(cp);

				module = module_instantiate(modules, name);
				if (!module && (name[0] != '-')) {
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
						cf_log_err_cs(subcs, "Instantiate sections cannot be named for an 'unlang' keyword");
						return -1;
					}
				} else {
					if (is_reserved_word(name)) {
						cf_log_err_cs(subcs, "Instantiate sections cannot be named for an 'unlang' keyword");
						return -1;
					}
				}

				/*
				 *	Ensure that the modules we reference here exist.
				 */
				for (subci=cf_item_find_next(subcs, NULL);
				     subci != NULL;
				     subci=cf_item_find_next(subcs, subci)) {
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
						module = module_instantiate_method(modules, cf_pair_attr(cp), NULL);
						if (!module) {
							return -1;
						}

						if (all_same) {
							if (!last) {
								last = module->entry->module;
							} else if (last != module->entry->module) {
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

	/*
	 *	Now that we've loaded the explicitly ordered modules,
	 *	load everything in the "modules" section.  This is
	 *	because we've now split up the modules into
	 *	mods-enabled.
	 */
	for (ci=cf_item_find_next(modules, NULL);
	     ci != NULL;
	     ci=next) {
		char const *name;
		module_instance_t *module;
		CONF_SECTION *subcs;

		next = cf_item_find_next(modules, ci);

		if (!cf_item_is_section(ci)) continue;

		subcs = cf_item_to_section(ci);
		name = cf_section_name2(subcs);
		if (!name) name = cf_section_name1(subcs);

		module = module_instantiate(modules, name);
		if (!module) return -1;
	}
	cf_log_info(config, " } # modules");

	if (virtual_servers_load(config) < 0) return -1;

	return 0;
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
rlm_rcode_t module_preacct(REQUEST *request)
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

	if(!request->username)
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
	return indexed_modcall(MOD_PRE_PROXY, type, request);
}

/*
 *	Do post-proxying for ALL configured sessions
 */
rlm_rcode_t process_post_proxy(int type, REQUEST *request)
{
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
