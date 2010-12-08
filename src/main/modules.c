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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/modcall.h>
#include <freeradius-devel/rad_assert.h>

extern int check_config;

typedef struct indexed_modcallable {
	int		comp;
	int		idx;
	modcallable	*modulelist;
} indexed_modcallable;

typedef struct virtual_server_t {
	const char	*name;
	time_t		created;
	int		can_free;
	CONF_SECTION	*cs;
	rbtree_t	*components;
	modcallable	*mc[RLM_COMPONENT_COUNT];
	CONF_SECTION	*subcs[RLM_COMPONENT_COUNT];
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


typedef struct section_type_value_t {
	const char	*section;
	const char	*typename;
	int		attr;
} section_type_value_t;

/*
 *	Ordered by component
 */
static const section_type_value_t section_type_value[RLM_COMPONENT_COUNT] = {
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


#ifdef WITHOUT_LIBLTDL
#ifdef WITH_DLOPEN
#include <dlfcn.h>

#ifndef RTLD_NOW
#define RTLD_NOW (0)
#endif
#ifndef RTLD_LOCAL
#define RTLD_LOCAL (0)
#endif

lt_dlhandle lt_dlopenext(const char *name)
{
	char buffer[256];

	strlcpy(buffer, name, sizeof(buffer));

	/*
	 *	FIXME: Make this configurable...
	 */
	strlcat(buffer, ".so", sizeof(buffer));

	return dlopen(buffer, RTLD_NOW | RTLD_LOCAL);
}

void *lt_dlsym(lt_dlhandle handle, UNUSED const char *symbol)
{
	return dlsym(handle, symbol);
}

int lt_dlclose(lt_dlhandle handle)
{
	return dlclose(handle);
}

const char *lt_dlerror(void)
{
	return dlerror();
}


#else  /* without dlopen */
typedef struct lt_dlmodule_t {
  const char	*name;
  void		*ref;
} lt_dlmodule_t;

typedef struct eap_type_t EAP_TYPE;
typedef struct rlm_sql_module_t rlm_sql_module_t;

/*
 *	FIXME: Write hackery to auto-generate this data.
 *	We only need to do this on systems that don't have dlopen.
 */
extern module_t rlm_pap;
extern module_t rlm_chap;
extern module_t rlm_eap;
extern module_t rlm_sql;
/* and so on ... */

extern EAP_TYPE rlm_eap_md5;
extern rlm_sql_module_t rlm_sql_mysql;
/* and so on ... */

static const lt_dlmodule_t lt_dlmodules[] = {
	{ "rlm_pap", &rlm_pap },
	{ "rlm_chap", &rlm_chap },
	{ "rlm_eap", &rlm_eap },
	/* and so on ... */

	{ "rlm_eap_md5", &rlm_eap_md5 },
	/* and so on ... */
		
	{ "rlm_sql_mysql", &rlm_sql_mysql },
	/* and so on ... */
		
	{ NULL, NULL }
};

lt_dlhandle lt_dlopenext(const char *name)
{
	int i;

	for (i = 0; lt_dlmodules[i].name != NULL; i++) {
		if (strcmp(name, lt_dlmodules[i].name) == 0) {
			return lt_dlmodules[i].ref;
		}
	}

	return NULL;
}

void *lt_dlsym(lt_dlhandle handle, UNUSED const char *symbol)
{
	return handle;
}

int lt_dlclose(lt_dlhandle handle)
{
	return 0;
}

const char *lt_dlerror(void)
{
	return "Unspecified error";
}

#endif	/* WITH_DLOPEN */
#else	/* WITHOUT_LIBLTDL */

/*
 *	Solve the issues of libraries linking to other libraries
 *	by using a newer libltdl API.
 */
#ifndef HAVE_LT_DLADVISE_INIT
#define fr_dlopenext lt_dlopenext
#else
static lt_dlhandle fr_dlopenext(const char *filename)
{
	lt_dlhandle handle = 0;
	lt_dladvise advise;

	if (!lt_dladvise_init (&advise) &&
	    !lt_dladvise_ext (&advise) &&
	    !lt_dladvise_global (&advise)) {
		handle = lt_dlopenadvise (filename, advise);
	}

	lt_dladvise_destroy (&advise);

	return handle;
}
#endif	/* HAVE_LT_DLADVISE_INIT */
#endif /* WITHOUT_LIBLTDL */

static int virtual_server_idx(const char *name)
{
	uint32_t hash;

	if (!name) return 0;

	hash = fr_hash_string(name);
		
	return hash & (VIRTUAL_SERVER_HASH_SIZE - 1);
}

static void virtual_server_free(virtual_server_t *server)
{
	if (!server) return;

	if (server->components) rbtree_free(server->components);
	server->components = NULL;

	free(server);
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
				virtual_server_free(server);
			} else {
				last = &(server->next);
			}
		}
	}
}

static void indexed_modcallable_free(void *data)
{
	indexed_modcallable *c = data;

	modcallable_free(&c->modulelist);
	free(c);
}

static int indexed_modcallable_cmp(const void *one, const void *two)
{
	const indexed_modcallable *a = one;
	const indexed_modcallable *b = two;

	if (a->comp < b->comp) return -1;
	if (a->comp >  b->comp) return +1;

	return a->idx - b->idx;
}


/*
 *	Compare two module entries
 */
static int module_instance_cmp(const void *one, const void *two)
{
	const module_instance_t *a = one;
	const module_instance_t *b = two;

	return strcmp(a->name, b->name);
}


static void module_instance_free_old(CONF_SECTION *cs, module_instance_t *node,
				     time_t when)
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

		cf_section_parse_free(cs, mh->insthandle);
		
		if (node->entry->module->detach) {
			(node->entry->module->detach)(mh->insthandle);
		} else {
			free(mh->insthandle);
		}

		*last = mh->next;
		free(mh);
	}
}


/*
 *	Free a module instance.
 */
static void module_instance_free(void *data)
{
	module_instance_t *this = data;

	module_instance_free_old(this->cs, this, time(NULL) + 100);

	if (this->entry->module->detach) {
		(this->entry->module->detach)(this->insthandle);
	}

#ifdef HAVE_PTHREAD_H
	if (this->mutex) {
		/*
		 *	FIXME
		 *	The mutex MIGHT be locked...
		 *	we'll check for that later, I guess.
		 */
		pthread_mutex_destroy(this->mutex);
		free(this->mutex);
	}
#endif
	memset(this, 0, sizeof(*this));
	free(this);
}


/*
 *	Compare two module entries
 */
static int module_entry_cmp(const void *one, const void *two)
{
	const module_entry_t *a = one;
	const module_entry_t *b = two;

	return strcmp(a->name, b->name);
}

/*
 *	Free a module entry.
 */
static void module_entry_free(void *data)
{
	module_entry_t *this = data;

	lt_dlclose(this->handle);	/* ignore any errors */
	memset(this, 0, sizeof(*this));
	free(this);
}


/*
 *	Remove the module lists.
 */
int detach_modules(void)
{
	rbtree_free(instance_tree);
	rbtree_free(module_tree);

	lt_dlexit();

	return 0;
}


/*
 *	Find a module on disk or in memory, and link to it.
 */
static module_entry_t *linkto_module(const char *module_name,
				     CONF_SECTION *cs)
{
	module_entry_t myentry;
	module_entry_t *node;
	lt_dlhandle handle;
	char module_struct[256];
	char *p;
	const module_t *module;

	strlcpy(myentry.name, module_name, sizeof(myentry.name));
	node = rbtree_finddata(module_tree, &myentry);
	if (node) return node;

	/*
	 *	Keep the handle around so we can dlclose() it.
	 */
	handle = fr_dlopenext(module_name);
	if (handle == NULL) {
		cf_log_err(cf_sectiontoitem(cs),
			   "Failed to link to module '%s': %s\n",
			   module_name, lt_dlerror());
		return NULL;
	}

	/*
	 *	Link to the module's rlm_FOO{} module structure.
	 *
	 *	The module_name variable has the version number
	 *	embedded in it, and we don't want that here.
	 */
	strcpy(module_struct, module_name);
	p = strrchr(module_struct, '-');
	if (p) *p = '\0';

	DEBUG3("    (Loaded %s, checking if it's valid)", module_name);

	/*
	 *	libltld MAY core here, if the handle it gives us contains
	 *	garbage data.
	 */
	module = lt_dlsym(handle, module_struct);
	if (!module) {
		cf_log_err(cf_sectiontoitem(cs),
			   "Failed linking to %s structure: %s\n",
			   module_name, lt_dlerror());
		lt_dlclose(handle);
		return NULL;
	}

	/*
	 *	Before doing anything else, check if it's sane.
	 */
	if (module->magic != RLM_MODULE_MAGIC_NUMBER) {
		lt_dlclose(handle);
		cf_log_err(cf_sectiontoitem(cs),
			   "Invalid version in module '%s'",
			   module_name);
		return NULL;

	}

	/* make room for the module type */
	node = rad_malloc(sizeof(*node));
	memset(node, 0, sizeof(*node));
	strlcpy(node->name, module_name, sizeof(node->name));
	node->module = module;
	node->handle = handle;

	cf_log_module(cs, "Linked to module %s", module_name);

	/*
	 *	Add the module as "rlm_foo-version" to the configuration
	 *	section.
	 */
	if (!rbtree_insert(module_tree, node)) {
		radlog(L_ERR, "Failed to cache module %s", module_name);
		lt_dlclose(handle);
		free(node);
		return NULL;
	}

	return node;
}

/*
 *	Find a module instance.
 */
module_instance_t *find_module_instance(CONF_SECTION *modules,
					const char *instname, int do_link)
{
	int check_config_safe = FALSE;
	CONF_SECTION *cs;
	const char *name1;
	module_instance_t *node, myNode;
	char module_name[256];

	if (!modules) return NULL;

	/*
	 *	Module instances are declared in the modules{} block
	 *	and referenced later by their name, which is the
	 *	name2 from the config section, or name1 if there was
	 *	no name2.
	 */
	cs = cf_section_sub_find_name2(modules, NULL, instname);
	if (cs == NULL) {
		radlog(L_ERR, "ERROR: Cannot find a configuration entry for module \"%s\".\n", instname);
		return NULL;
	}

	/*
	 *	If there's already a module instance, return it.
	 */
	strlcpy(myNode.name, instname, sizeof(myNode.name));
	node = rbtree_finddata(instance_tree, &myNode);
	if (node) return node;

	if (!do_link) return NULL;

	name1 = cf_section_name1(cs);

	/*
	 *	Found the configuration entry.
	 */
	node = rad_malloc(sizeof(*node));
	memset(node, 0, sizeof(*node));

	node->insthandle = NULL;
	node->cs = cs;

	/*
	 *	Names in the "modules" section aren't prefixed
	 *	with "rlm_", so we add it here.
	 */
	snprintf(module_name, sizeof(module_name), "rlm_%s", name1);

	node->entry = linkto_module(module_name, cs);
	if (!node->entry) {
		free(node);
		/* linkto_module logs any errors */
		return NULL;
	}

	if (check_config && (node->entry->module->instantiate) &&
	    (node->entry->module->type & RLM_TYPE_CHECK_CONFIG_SAFE) == 0) {
		const char *value = NULL;
		CONF_PAIR *cp;

		cp = cf_pair_find(cs, "force_check_config");
		if (cp) value = cf_pair_value(cp);

		if (value && (strcmp(value, "yes") == 0)) goto print_inst;

		cf_log_module(cs, "Skipping instantiation of %s", instname);
	} else {
	print_inst:
		check_config_safe = TRUE;
		cf_log_module(cs, "Instantiating module \"%s\" from file %s",
			      instname, cf_section_filename(cs));
	}

	/*
	 *	Call the module's instantiation routine.
	 */
	if ((node->entry->module->instantiate) &&
	    (!check_config || check_config_safe) &&
	    ((node->entry->module->instantiate)(cs, &node->insthandle) < 0)) {
		cf_log_err(cf_sectiontoitem(cs),
			   "Instantiation failed for module \"%s\"",
			   instname);
		free(node);
		return NULL;
	}

	/*
	 *	We're done.  Fill in the rest of the data structure,
	 *	and link it to the module instance list.
	 */
	strlcpy(node->name, instname, sizeof(node->name));

#ifdef HAVE_PTHREAD_H
	/*
	 *	If we're threaded, check if the module is thread-safe.
	 *
	 *	If it isn't, we create a mutex.
	 */
	if ((node->entry->module->type & RLM_TYPE_THREAD_UNSAFE) != 0) {
		node->mutex = (pthread_mutex_t *) rad_malloc(sizeof(pthread_mutex_t));
		/*
		 *	Initialize the mutex.
		 */
		pthread_mutex_init(node->mutex, NULL);
	} else {
		/*
		 *	The module is thread-safe.  Don't give it a mutex.
		 */
		node->mutex = NULL;
	}

#endif
	rbtree_insert(instance_tree, node);

	return node;
}

static indexed_modcallable *lookup_by_index(rbtree_t *components,
					    int comp, int idx)
{
	indexed_modcallable myc;
	
	myc.comp = comp;
	myc.idx = idx;

	return rbtree_finddata(components, &myc);
}

/*
 *	Create a new sublist.
 */
static indexed_modcallable *new_sublist(rbtree_t *components, int comp, int idx)
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

	c = rad_malloc(sizeof(*c));
	c->modulelist = NULL;
	c->comp = comp;
	c->idx = idx;

	if (!rbtree_insert(components, c)) {
		free(c);
		return NULL;
	}

	return c;
}

int indexed_modcall(int comp, int idx, REQUEST *request)
{
	int rcode;
	modcallable *list = NULL;
	virtual_server_t *server;

	/*
	 *	Hack to find the correct virtual server.
	 */
	rcode = virtual_server_idx(request->server);
	for (server = virtual_servers[rcode];
	     server != NULL;
	     server = server->next) {
		if (!request->server && !server->name) break;

		if ((request->server && server->name) &&
		    (strcmp(request->server, server->name) == 0)) break;
	}

	if (!server) {
		RDEBUG("No such virtual server \"%s\"", request->server);
		return RLM_MODULE_FAIL;
	}

	if (idx == 0) {
		list = server->mc[comp];
		if (!list) RDEBUG2("  WARNING: Empty %s section.  Using default return values.", section_type_value[comp].section);

	} else {
		indexed_modcallable *this;

		this = lookup_by_index(server->components, comp, idx);
		if (this) {
			list = this->modulelist;
		} else {
			RDEBUG2("  WARNING: Unknown value specified for %s.  Cannot perform requested action.",
				section_type_value[comp].typename);
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
static int load_subcomponent_section(modcallable *parent, CONF_SECTION *cs,
				     rbtree_t *components, int attr, int comp)
{
	indexed_modcallable *subcomp;
	modcallable *ml;
	DICT_VALUE *dval;
	const char *name2 = cf_section_name2(cs);

	rad_assert(comp >= RLM_COMPONENT_AUTH);
	rad_assert(comp < RLM_COMPONENT_COUNT);

	/*
	 *	Sanity check.
	 */
	if (!name2) {
		cf_log_err(cf_sectiontoitem(cs),
			   "No name specified for %s block",
			   section_type_value[comp].typename);
		return 1;
	}

	/*
	 *	Compile the group.
	 */
	ml = compile_modgroup(parent, comp, cs);
	if (!ml) {
		return 0;
	}

	/*
	 *	We must assign a numeric index to this subcomponent.
	 *	It is generated and placed in the dictionary
	 *	automatically.  If it isn't found, it's a serious
	 *	error.
	 */
	dval = dict_valbyname(attr, name2);
	if (!dval) {
		cf_log_err(cf_sectiontoitem(cs),
			   "%s %s Not previously configured",
			   section_type_value[comp].typename, name2);
		modcallable_free(&ml);
		return 0;
	}

	subcomp = new_sublist(components, comp, dval->value);
	if (!subcomp) {
		modcallable_free(&ml);
		return 1;
	}

	subcomp->modulelist = ml;
	return 1;		/* OK */
}

static int define_type(const DICT_ATTR *dattr, const char *name)
{
	uint32_t value;
	DICT_VALUE *dval;

	/*
	 *	If the value already exists, don't
	 *	create it again.
	 */
	dval = dict_valbyname(dattr->attr, name);
	if (dval) return 1;

	/*
	 *	Create a new unique value with a
	 *	meaningless number.  You can't look at
	 *	it from outside of this code, so it
	 *	doesn't matter.  The only requirement
	 *	is that it's unique.
	 */
	do {
		value = fr_rand() & 0x00ffffff;
	} while (dict_valbyattr(dattr->attr, value));

	if (dict_addvalue(name, dattr->name, value) < 0) {
		radlog(L_ERR, "%s", fr_strerror());
		return 0;
	}

	return 1;
}

static int load_component_section(CONF_SECTION *cs,
				  rbtree_t *components, int comp)
{
	modcallable *this;
	CONF_ITEM *modref;
	int idx;
	indexed_modcallable *subcomp;
	const char *modname;
	const char *visiblename;
	const DICT_ATTR *dattr;

	/*
	 *	Find the attribute used to store VALUEs for this section.
	 */
	dattr = dict_attrbyvalue(section_type_value[comp].attr);
	if (!dattr) {
		cf_log_err(cf_sectiontoitem(cs),
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
		const char *name1;
		CONF_PAIR *cp = NULL;
		CONF_SECTION *scs = NULL;

		if (cf_item_is_section(modref)) {
			scs = cf_itemtosection(modref);

			name1 = cf_section_name1(scs);

			if (strcmp(name1,
				   section_type_value[comp].typename) == 0) {
				if (!load_subcomponent_section(NULL, scs,
							       components,
							       dattr->attr,
							       comp)) {
					return -1; /* FIXME: memleak? */
				}
				continue;
			}

			cp = NULL;

		} else if (cf_item_is_pair(modref)) {
			cp = cf_itemtopair(modref);

		} else {
			continue; /* ignore it */
		}

		/*
		 *	Try to compile one entry.
		 */
		this = compile_modsingle(NULL, comp, modref, &modname);
		if (!this) {
			cf_log_err(cf_sectiontoitem(cs),
				   "Errors parsing %s section.\n",
				   cf_section_name1(cs));
			return -1;
		}

		/*
		 *	Look for Auth-Type foo {}, which are special
		 *	cases of named sections, and allowable ONLY
		 *	at the top-level.
		 *
		 *	i.e. They're not allowed in a "group" or "redundant"
		 *	subsection.
		 */
		if (comp == RLM_COMPONENT_AUTH) {
			DICT_VALUE *dval;
			const char *modrefname = NULL;
			if (cp) {
				modrefname = cf_pair_attr(cp);
			} else {
				modrefname = cf_section_name2(scs);
				if (!modrefname) {
					modcallable_free(&this);
					cf_log_err(cf_sectiontoitem(cs),
						   "Errors parsing %s sub-section.\n",
						   cf_section_name1(scs));
					return -1;
				}
			}

			dval = dict_valbyname(PW_AUTH_TYPE, modrefname);
			if (!dval) {
				/*
				 *	It's a section, but nothing we
				 *	recognize.  Die!
				 */
				modcallable_free(&this);
				cf_log_err(cf_sectiontoitem(cs),
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

		subcomp = new_sublist(components, comp, idx);
		if (subcomp == NULL) {
			modcallable_free(&this);
			continue;
		}

		/* If subcomp->modulelist is NULL, add_to_modcallable will
		 * create it */
		visiblename = cf_section_name2(cs);
		if (visiblename == NULL)
			visiblename = cf_section_name1(cs);
		add_to_modcallable(&subcomp->modulelist, this,
				   comp, visiblename);
	}

	return 0;
}

static int load_byserver(CONF_SECTION *cs)
{
	int comp, flag;
	const char *name = cf_section_name2(cs);
	rbtree_t *components;
	virtual_server_t *server = NULL;
	indexed_modcallable *c;

	if (name) {
		cf_log_info(cs, "server %s { # from file %s",
			    name, cf_section_filename(cs));
	} else {
		cf_log_info(cs, "server { # from file %s",
			    cf_section_filename(cs));
	}

	cf_log_info(cs, " modules {");

	components = rbtree_create(indexed_modcallable_cmp,
				   indexed_modcallable_free, 0);
	if (!components) {
		radlog(L_ERR, "Failed to initialize components\n");
		goto error;
	}

	server = rad_malloc(sizeof(*server));
	memset(server, 0, sizeof(*server));

	server->name = name;
	server->created = time(NULL);
	server->cs = cs;
	server->components = components;

	/*
	 *	Define types first.
	 */
	for (comp = 0; comp < RLM_COMPONENT_COUNT; ++comp) {
		CONF_SECTION *subcs;
		CONF_ITEM *modref;
		DICT_ATTR *dattr;

		subcs = cf_section_sub_find(cs,
					    section_type_value[comp].section);
		if (!subcs) continue;
			
		if (cf_item_find_next(subcs, NULL) == NULL) continue;

		/*
		 *	Find the attribute used to store VALUEs for this section.
		 */
		dattr = dict_attrbyvalue(section_type_value[comp].attr);
		if (!dattr) {
			cf_log_err(cf_sectiontoitem(subcs),
				   "No such attribute %s",
				   section_type_value[comp].typename);
		error:
			if (debug_flag == 0) {
				radlog(L_ERR, "Failed to load virtual server %s",
				       (name != NULL) ? name : "<default>");
			}
			virtual_server_free(server);
			return -1;
		}

		/*
		 *	Define dynamic types, so that others can reference
		 *	them.
		 */
		for (modref = cf_item_find_next(subcs, NULL);
		     modref != NULL;
		     modref = cf_item_find_next(subcs, modref)) {
			const char *name1;
			CONF_SECTION *subsubcs;

			/*
			 *	Create types for simple references
			 *	only when parsing the authenticate
			 *	section.
			 */
			if ((section_type_value[comp].attr == PW_AUTH_TYPE) &&
			    cf_item_is_pair(modref)) {
				CONF_PAIR *cp = cf_itemtopair(modref);
				if (!define_type(dattr, cf_pair_attr(cp))) {
					goto error;
				}

				continue;
			}

			if (!cf_item_is_section(modref)) continue;
			
			subsubcs = cf_itemtosection(modref);
			name1 = cf_section_name1(subsubcs);
		
			if (strcmp(name1, section_type_value[comp].typename) == 0) {
				if (!define_type(dattr,
						 cf_section_name2(subsubcs))) {
					goto error;
				}
			}
		}
	} /* loop over components */

	/*
	 *	Loop over all of the known components, finding their
	 *	configuration section, and loading it.
	 */
	flag = 0;
	for (comp = 0; comp < RLM_COMPONENT_COUNT; ++comp) {
		CONF_SECTION *subcs;

		subcs = cf_section_sub_find(cs,
					    section_type_value[comp].section);
		if (!subcs) continue;
			
		if (cf_item_find_next(subcs, NULL) == NULL) continue;
			
		cf_log_module(cs, "Checking %s {...} for more modules to load",
		       section_type_value[comp].section);

#ifdef WITH_PROXY
		/*
		 *	Skip pre/post-proxy sections if we're not
		 *	proxying.
		 */
		if (!mainconfig.proxy_requests &&
		    ((comp == RLM_COMPONENT_PRE_PROXY) ||
		     (comp == RLM_COMPONENT_POST_PROXY))) {
			continue;
		}
#endif

		if (load_component_section(subcs, components, comp) < 0) {
			goto error;
		}

		/*
		 *	Cache a default, if it exists.  Some people
		 *	put empty sections for some reason...
		 */
		c = lookup_by_index(components, comp, 0);
		if (c) server->mc[comp] = c->modulelist;

		server->subcs[comp] = subcs;

		flag = 1;
	} /* loop over components */

	/*
	 *	We haven't loaded any of the normal sections.  Maybe we're
	 *	supposed to load the vmps section.
	 *
	 *	This is a bit of a hack...
	 */
	if (!flag) {
		CONF_SECTION *subcs;

		subcs = cf_section_sub_find(cs, "vmps");
		if (subcs) {
			cf_log_module(cs, "Checking vmps {...} for more modules to load");		
			if (load_component_section(subcs, components,
						   RLM_COMPONENT_POST_AUTH) < 0) {
				goto error;
			}
			c = lookup_by_index(components,
					    RLM_COMPONENT_POST_AUTH, 0);
			if (c) server->mc[RLM_COMPONENT_POST_AUTH] = c->modulelist;
			flag = 1;
		}

#ifdef WITH_DHCP
		if (!flag) {
			const DICT_ATTR *dattr;

			dattr = dict_attrbyname("DHCP-Message-Type");

			/*
			 *	Handle each DHCP Message type separately.
			 */
			if (dattr) for (subcs = cf_subsection_find_next(cs, NULL, "dhcp");
					subcs != NULL;
					subcs = cf_subsection_find_next(cs, subcs,
									"dhcp")) {
				const char *name2 = cf_section_name2(subcs);

				DEBUG2(" Module: Checking dhcp %s {...} for more modules to load", name2);
				if (!load_subcomponent_section(NULL, subcs,
							       components,
							       dattr->attr,
							       RLM_COMPONENT_POST_AUTH)) {
					goto error; /* FIXME: memleak? */
				}
				c = lookup_by_index(components,
						    RLM_COMPONENT_POST_AUTH, 0);
				if (c) server->mc[RLM_COMPONENT_POST_AUTH] = c->modulelist;
				flag = 1;
			}
		}
#endif
	}

	cf_log_info(cs, " } # modules");
	cf_log_info(cs, "} # server");

	if (!flag && name) {
		DEBUG("WARNING: Server %s is empty, and will do nothing!",
		      name);
	}

	if (debug_flag == 0) {
		radlog(L_INFO, "Loaded virtual server %s",
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
			server->can_free = TRUE;
			break;
		}
		server = server->next;
	}

	return 0;
}


/*
 *	Load all of the virtual servers.
 */
int virtual_servers_load(CONF_SECTION *config)
{
	int null_server = FALSE;
	CONF_SECTION *cs;
	static int first_time = TRUE;

	DEBUG2("%s: #### Loading Virtual Servers ####", mainconfig.name);

	/*
	 *	Load all of the virtual servers.
	 */
	for (cs = cf_subsection_find_next(config, NULL, "server");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "server")) {
		if (!cf_section_name2(cs)) null_server = TRUE;

		if (load_byserver(cs) < 0) {
			/*
			 *	Once we successfully staryed once,
			 *	continue loading the OTHER servers,
			 *	even if one fails.
			 */
			if (!first_time) continue;
			return -1;
		}
	}

	/*
	 *	No empty server defined.  Try to load an old-style
	 *	one for backwards compatibility.
	 */
	if (!null_server) {
		if (load_byserver(config) < 0) {
			return -1;
		}
	}

	/*
	 *	If we succeed the first time around, remember that.
	 */
	first_time = FALSE;

	return 0;
}

int module_hup_module(CONF_SECTION *cs, module_instance_t *node, time_t when)
{
	void *insthandle = NULL;
	fr_module_hup_t *mh;

	if (!node ||
	    !node->entry->module->instantiate ||
	    ((node->entry->module->type & RLM_TYPE_HUP_SAFE) == 0)) {
		return 1;
	}

	cf_log_module(cs, "Trying to reload module \"%s\"", node->name);
	
	if ((node->entry->module->instantiate)(cs, &insthandle) < 0) {
		cf_log_err(cf_sectiontoitem(cs),
			   "HUP failed for module \"%s\".  Using old configuration.",
			   node->name);
		return 0;
	}

	radlog(L_INFO, " Module: Reloaded module \"%s\"", node->name);

	module_instance_free_old(cs, node, when);

	/*
	 *	Save the old instance handle for later deletion.
	 */
	mh = rad_malloc(sizeof(*mh));
	mh->mi = node;
	mh->when = when;
	mh->insthandle = node->insthandle;
	mh->next = node->mh;
	node->mh = mh;

	node->insthandle = insthandle;
	
	/*
	 *	FIXME: Set a timeout to come back in 60s, so that
	 *	we can pro-actively clean up the old instances.
	 */

	return 1;
}


int module_hup(CONF_SECTION *modules)
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
		const char *instname;
		module_instance_t myNode;

		/*
		 *	If it's not a section, ignore it.
		 */
		if (!cf_item_is_section(ci)) continue;

		cs = cf_itemtosection(ci);
		instname = cf_section_name2(cs);
		if (!instname) instname = cf_section_name1(cs);

		strlcpy(myNode.name, instname, sizeof(myNode.name));
		node = rbtree_finddata(instance_tree, &myNode);

		module_hup_module(cs, node, when);
	}

	return 1;
}


/*
 *	Parse the module config sections, and load
 *	and call each module's init() function.
 *
 *	Libtool makes your life a LOT easier, especially with libltdl.
 *	see: http://www.gnu.org/software/libtool/
 */
int setup_modules(int reload, CONF_SECTION *config)
{
	CONF_SECTION	*cs, *modules;
	rad_listen_t	*listener;

	if (reload) return 0;

	/*
	 *	If necessary, initialize libltdl.
	 */
	if (!reload) {
		/*
		 *	This line works around a completely
		 *
		 *		RIDICULOUS INSANE IDIOTIC
		 *
		 *	bug in libltdl on certain systems.  The "set
		 *	preloaded symbols" macro below ends up
		 *	referencing this name, but it isn't defined
		 *	anywhere in the libltdl source.  As a result,
		 *	any program STUPID enough to rely on libltdl
		 *	fails to link, because the symbol isn't
		 *	defined anywhere.
		 *
		 *	It's like libtool and libltdl are some kind
		 *	of sick joke.
		 */
#ifdef IE_LIBTOOL_DIE
#define lt__PROGRAM__LTX_preloaded_symbols lt_libltdl_LTX_preloaded_symbols
#endif

		/*
		 *	Set the default list of preloaded symbols.
		 *	This is used to initialize libltdl's list of
		 *	preloaded modules.
		 *
		 *	i.e. Static modules.
		 */
		LTDL_SET_PRELOADED_SYMBOLS();

		if (lt_dlinit() != 0) {
			radlog(L_ERR, "Failed to initialize libraries: %s\n",
					lt_dlerror());
			return -1;
		}

		/*
		 *	Set the search path to ONLY our library directory.
		 *	This prevents the modules from being found from
		 *	any location on the disk.
		 */
		lt_dlsetsearchpath(radlib_dir);

		/*
		 *	Set up the internal module struct.
		 */
		module_tree = rbtree_create(module_entry_cmp,
					    module_entry_free, 0);
		if (!module_tree) {
			radlog(L_ERR, "Failed to initialize modules\n");
			return -1;
		}

		instance_tree = rbtree_create(module_instance_cmp,
					      module_instance_free, 0);
		if (!instance_tree) {
			radlog(L_ERR, "Failed to initialize modules\n");
			return -1;
		}
	}

	memset(virtual_servers, 0, sizeof(virtual_servers));

	/*
	 *	Remember where the modules were stored.
	 */
	modules = cf_section_sub_find(config, "modules");
	if (!modules) {
		radlog(L_INFO, "WARNING: Cannot find a \"modules\" section in the configuration file!");
	}

	DEBUG2("%s: #### Instantiating modules ####", mainconfig.name);

	/*
	 *  Look for the 'instantiate' section, which tells us
	 *  the instantiation order of the modules, and also allows
	 *  us to load modules with no authorize/authenticate/etc.
	 *  sections.
	 */
	cs = cf_section_sub_find(config, "instantiate");
	if (cs != NULL) {
		CONF_ITEM *ci;
		CONF_PAIR *cp;
		module_instance_t *module;
		const char *name;

		cf_log_info(cs, " instantiate {");

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
			if (!cf_item_is_pair(ci)) {
				continue;
			}

			cp = cf_itemtopair(ci);
			name = cf_pair_attr(cp);
			module = find_module_instance(modules, name, 1);
			if (!module) {
				return -1;
			}
		} /* loop over items in the subsection */

		cf_log_info(cs, " }");
	} /* if there's an 'instantiate' section. */

	/*
	 *	Loop over the listeners, figuring out which sections
	 *	to load.
	 */
	for (listener = mainconfig.listen;
	     listener != NULL;
	     listener = listener->next) {
		char buffer[256];

#ifdef WITH_PROXY
		if (listener->type == RAD_LISTEN_PROXY) continue;
#endif

		cs = cf_section_sub_find_name2(config,
					       "server", listener->server);
		if (!cs && (listener->server != NULL)) {
			listener->print(listener, buffer, sizeof(buffer));

			radlog(L_ERR, "No server has been defined for %s", buffer);
			return -1;
		}
	}

	if (virtual_servers_load(config) < 0) return -1;

	return 0;
}

/*
 *	Call all authorization modules until one returns
 *	somethings else than RLM_MODULE_OK
 */
int module_authorize(int autz_type, REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_AUTZ, autz_type, request);
}

/*
 *	Authenticate a user/password with various methods.
 */
int module_authenticate(int auth_type, REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_AUTH, auth_type, request);
}

#ifdef WITH_ACCOUNTING
/*
 *	Do pre-accounting for ALL configured sessions
 */
int module_preacct(REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_PREACCT, 0, request);
}

/*
 *	Do accounting for ALL configured sessions
 */
int module_accounting(int acct_type, REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_ACCT, acct_type, request);
}
#endif

#ifdef WITH_SESSION_MGMT
/*
 *	See if a user is already logged in.
 *
 *	Returns: 0 == OK, 1 == double logins, 2 == multilink attempt
 */
int module_checksimul(int sess_type, REQUEST *request, int maxsimul)
{
	int rcode;

	if(!request->username)
		return 0;

	request->simul_count = 0;
	request->simul_max = maxsimul;
	request->simul_mpp = 1;

	rcode = indexed_modcall(RLM_COMPONENT_SESS, sess_type, request);

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
int module_pre_proxy(int type, REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_PRE_PROXY, type, request);
}

/*
 *	Do post-proxying for ALL configured sessions
 */
int module_post_proxy(int type, REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_POST_PROXY, type, request);
}
#endif

/*
 *	Do post-authentication for ALL configured sessions
 */
int module_post_auth(int postauth_type, REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_POST_AUTH, postauth_type, request);
}

#ifdef WITH_COA
int module_recv_coa(int recv_coa_type, REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_RECV_COA, recv_coa_type, request);
}

int module_send_coa(int send_coa_type, REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_SEND_COA, send_coa_type, request);
}
#endif
