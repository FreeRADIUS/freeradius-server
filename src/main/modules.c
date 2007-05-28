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

typedef struct indexed_modcallable {
	int comp;
	int idx;
	modcallable *modulelist;
} indexed_modcallable;

/*
 *	For each component, keep an ordered list of ones to call.
 */
static rbtree_t *components;

static rbtree_t *module_tree = NULL;

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
	{ "post-auth",    "Post-Auth-Type",  PW_POST_AUTH_TYPE },
};

/*
 *	Delete ASAP.
 */
static const section_type_value_t old_section_type_value[] = {
	{ "authenticate", "authtype", PW_AUTH_TYPE },
	{ "authorize",    "autztype", PW_AUTZ_TYPE },
	{ "preacct",      "Pre-Acct-Type",   PW_PRE_ACCT_TYPE },/* unused */
	{ "accounting",   "acctype", PW_ACCT_TYPE },
	{ "session",      "sesstype", PW_SESSION_TYPE },
	{ "pre-proxy",    "Pre-Proxy-Type",  PW_PRE_PROXY_TYPE }, /* unused */
	{ "post-proxy",   "Post-Proxy-Type", PW_POST_PROXY_TYPE }, /* unused */
	{ "post-auth",	  "post-authtype", PW_POST_AUTH_TYPE }
};


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
 *	Free a module instance.
 */
static void module_instance_free(void *data)
{
	module_instance_t *this = data;

	if (this->entry->module->detach)
		(this->entry->module->detach)(this->insthandle);
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
	free(this);
}


/*
 *	Remove the module lists.
 */
int detach_modules(void)
{
	rbtree_free(components);
	rbtree_free(module_tree);

	return 0;
}


/*
 *	Find a module on disk or in memory, and link to it.
 */
static module_entry_t *linkto_module(const char *module_name,
				     const char *cffilename, int cflineno)
{
	module_entry_t myentry;
	module_entry_t *node;
	lt_dlhandle handle;
	char module_struct[256];
	char *p;
	const void *module;

	strlcpy(myentry.name, module_name, sizeof(myentry.name));
	node = rbtree_finddata(module_tree, &myentry);
	if (node) return node;

	/*
	 *	Keep the handle around so we can dlclose() it.
	 */
	handle = lt_dlopenext(module_name);
	if (handle == NULL) {
		radlog(L_ERR|L_CONS, "%s[%d] Failed to link to module '%s':"
		       " %s\n", cffilename, cflineno, module_name, lt_dlerror());
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
		radlog(L_ERR|L_CONS, "%s[%d] Failed linking to "
				"%s structure in %s: %s\n",
				cffilename, cflineno,
				module_name, cffilename, lt_dlerror());
		lt_dlclose(handle);
		return NULL;
	}
	/*
	 *	Before doing anything else, check if it's sane.
	 */
	if ((*(const uint32_t *) module) != RLM_MODULE_MAGIC_NUMBER) {
		lt_dlclose(handle);
		radlog(L_ERR|L_CONS, "%s[%d] Invalid version in module '%s'",
		       cffilename, cflineno, module_name);
		return NULL;

	}

	/* make room for the module type */
	node = rad_malloc(sizeof(*node));
	memset(node, 0, sizeof(*node));
	strlcpy(node->name, module_name, sizeof(node->name));
	node->module = module;
	node->handle = handle;

	DEBUG(" Module: Linked to module %s", module_name);

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
					const char *instname)
{
	CONF_SECTION *cs;
	const char *name1, *name2;
	module_instance_t *node;
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
		radlog(L_ERR|L_CONS, "ERROR: Cannot find a configuration entry for module \"%s\".\n", instname);
		return NULL;
	}

	/*
	 *	If there's already a module instance, return it.
	 */
	node = cf_data_find(cs, "instance");
	if (node) return node;

	name1 = cf_section_name1(cs);
	name2 = cf_section_name2(cs);

	/*
	 *	Found the configuration entry.
	 */
	node = rad_malloc(sizeof(*node));
	memset(node, 0, sizeof(*node));

	node->insthandle = NULL;

	/*
	 *	Names in the "modules" section aren't prefixed
	 *	with "rlm_", so we add it here.
	 */
	snprintf(module_name, sizeof(module_name), "rlm_%s", name1);

	node->entry = linkto_module(module_name,
				    mainconfig.radiusd_conf,
				    cf_section_lineno(cs));
	if (!node->entry) {
		free(node);
		/* linkto_module logs any errors */
		return NULL;
	}

	DEBUG2(" Module: Instantiating %s", instname);

	/*
	 *	Call the module's instantiation routine.
	 */
	if ((node->entry->module->instantiate) &&
	    ((node->entry->module->instantiate)(cs, &node->insthandle) < 0)) {
		radlog(L_ERR|L_CONS,
				"%s[%d]: %s: Module instantiation failed.\n",
		       mainconfig.radiusd_conf, cf_section_lineno(cs),
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
	cf_data_add(cs, "instance", node, module_instance_free);

	return node;
}

static indexed_modcallable *lookup_by_index(int comp, int idx)
{
	indexed_modcallable myc;

	myc.comp = comp;
	myc.idx = idx;

	return rbtree_finddata(components, &myc);
}

/*
 *	Create a new sublist.
 */
static indexed_modcallable *new_sublist(int comp, int idx)
{
	indexed_modcallable *c;

	c = lookup_by_index(comp, idx);

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

static int indexed_modcall(int comp, int idx, REQUEST *request)
{
	int rcode;
	indexed_modcallable *this;

	this = lookup_by_index(comp, idx);
	if (!this) {
		if (idx != 0) DEBUG2("  ERROR: Unknown value specified for %s.  Cannot perform requested action.",
				     section_type_value[comp].typename);
		request->component = section_type_value[comp].typename;
		rcode = modcall(comp, NULL, request); /* does default action */
	} else {
		DEBUG2("  Processing the %s section of %s",
		       section_type_value[comp].section,
		       mainconfig.radiusd_conf);
		request->component = section_type_value[comp].typename;
		rcode = modcall(comp, this->modulelist, request);
	}
	request->module = "<server-core>";
	request->component = "<server-core>";
	return rcode;
}

/*
 *	Load a sub-module list, as found inside an Auth-Type foo {}
 *	block
 */
static int load_subcomponent_section(modcallable *parent,
				     CONF_SECTION *cs, int comp,
				     const char *filename)
{
	indexed_modcallable *subcomp;
	modcallable *ml;
	DICT_VALUE *dval;
	const char *name2 = cf_section_name2(cs);

	rad_assert(comp >= RLM_COMPONENT_AUTH);
	rad_assert(comp <= RLM_COMPONENT_COUNT);

	/*
	 *	Sanity check.
	 */
	if (!name2) {
		radlog(L_ERR|L_CONS,
		       "%s[%d]: No name specified for %s block",
		       filename, cf_section_lineno(cs),
		       section_type_value[comp].typename);
		return 1;
	}

	/*
	 *	Compile the group.
	 */
	ml = compile_modgroup(parent, comp, cs, filename);
	if (!ml) {
		return 0;
	}

	/*
	 *	We must assign a numeric index to this subcomponent.
	 *	It is generated and placed in the dictionary by
	 *	setup_modules(), when it loads the sections.  If it
	 *	isn't found, it's a serious error.
	 */
	dval = dict_valbyname(section_type_value[comp].attr, name2);
	if (!dval) {
		radlog(L_ERR|L_CONS,
		       "%s[%d] %s %s Not previously configured",
		       filename, cf_section_lineno(cs),
		       section_type_value[comp].typename, name2);
		modcallable_free(&ml);
		return 0;
	}

	subcomp = new_sublist(comp, dval->value);
	if (!subcomp) {
		radlog(L_ERR|L_CONS,
		       "%s[%d] %s %s already configured - skipping",
		       filename, cf_section_lineno(cs),
		       section_type_value[comp].typename, name2);
		modcallable_free(&ml);
		return 1;
	}

	subcomp->modulelist = ml;
	return 1;		/* OK */
}

static int load_component_section(modcallable *parent,
				  CONF_SECTION *cs, int comp,
				  const char *filename)
{
	modcallable *this;
	CONF_ITEM *modref;
	int idx;
	indexed_modcallable *subcomp;
	const char *modname;
	const char *visiblename;

	/*
	 *	Loop over the entries in the named section.
	 */
	for (modref = cf_item_find_next(cs, NULL);
	     modref != NULL;
	     modref = cf_item_find_next(cs, modref)) {
		CONF_PAIR *cp = NULL;
		CONF_SECTION *scs = NULL;

		/*
		 *	Look for Auth-Type foo {}, which are special
		 *	cases of named sections, and allowable ONLY
		 *	at the top-level.
		 *
		 *	i.e. They're not allowed in a "group" or "redundant"
		 *	subsection.
		 */
		if (cf_item_is_section(modref)) {
			const char *sec_name;
			scs = cf_itemtosection(modref);

			sec_name = cf_section_name1(scs);

			if (strcmp(sec_name,
				   section_type_value[comp].typename) == 0) {
				if (!load_subcomponent_section(parent, scs,
							       comp,
							       filename)) {
					return -1; /* FIXME: memleak? */
				}
				continue;
			}

			/*
			 *	Allow old names, too.
			 */
			if (strcmp(sec_name,
				   old_section_type_value[comp].typename) == 0) {
				if (!load_subcomponent_section(parent, scs,
							       comp,
							       filename)) {
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
		this = compile_modsingle(parent, comp, modref, filename,
					 &modname);
		if (!this) {
			radlog(L_ERR|L_CONS,
			       "%s[%d] Failed to parse %s section.\n",
			       filename, cf_section_lineno(cs),
			       cf_section_name1(cs));
			return -1;
		}

		if (comp == RLM_COMPONENT_AUTH) {
			DICT_VALUE *dval;
			const char *modrefname = NULL;
			int lineno = 0;

			if (cp) {
				modrefname = cf_pair_attr(cp);
				lineno = cf_pair_lineno(cp);
			} else {
				modrefname = cf_section_name2(scs);
				lineno = cf_section_lineno(scs);
				if (!modrefname) {
					radlog(L_ERR|L_CONS,
					       "%s[%d] Failed to parse %s sub-section.\n",
					       filename, lineno,
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
				radlog(L_ERR|L_CONS, "%s[%d] Unknown Auth-Type \"%s\" in %s sub-section.",
				       filename, lineno,
				       modrefname, section_type_value[comp].section);
				return -1;
			}
			idx = dval->value;
		} else {
			/* See the comment in new_sublist() for explanation
			 * of the special index 0 */
			idx = 0;
		}

		subcomp = new_sublist(comp, idx);
		if (subcomp == NULL) {
			radlog(L_INFO|L_CONS,
					"%s %s %s already configured - skipping",
					filename, section_type_value[comp].typename,
					modname);
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


/*
 *	Parse the module config sections, and load
 *	and call each module's init() function.
 *
 *	Libtool makes your life a LOT easier, especially with libltdl.
 *	see: http://www.gnu.org/software/libtool/
 */
int setup_modules(int reload)
{
	int		comp;
	CONF_SECTION	*cs, *modules;
	int		do_component[RLM_COMPONENT_COUNT];
	rad_listen_t	*listener;

	/*
	 *	If necessary, initialize libltdl.
	 */
	if (!reload) {
		/*
		 *	Set the default list of preloaded symbols.
		 *	This is used to initialize libltdl's list of
		 *	preloaded modules.
		 *
		 *	i.e. Static modules.
		 */
		LTDL_SET_PRELOADED_SYMBOLS();

		if (lt_dlinit() != 0) {
			radlog(L_ERR|L_CONS, "Failed to initialize libraries: %s\n",
					lt_dlerror());
			return -1;
		}

		/*
		 *	Set the search path to ONLY our library directory.
		 *	This prevents the modules from being found from
		 *	any location on the disk.
		 */
		lt_dlsetsearchpath(radlib_dir);

		DEBUG2("radiusd: Library search path is %s",
		       lt_dlgetsearchpath());

		/*
		 *	Set up the internal module struct.
		 */
		module_tree = rbtree_create(module_entry_cmp,
					    module_entry_free, 0);
		if (!module_tree) {
			radlog(L_ERR|L_CONS, "Failed to initialize modules\n");
			return -1;
		}
	} else {
		rbtree_free(components);
	}

	components = rbtree_create(indexed_modcallable_cmp,
				   indexed_modcallable_free, 0);
	if (!components) {
		radlog(L_ERR|L_CONS, "Failed to initialize components\n");
		return -1;
	}

	/*
	 *	Figure out which sections to load.
	 */
	memset(do_component, 0, sizeof(do_component));
	for (listener = mainconfig.listen;
	     listener != NULL;
	     listener = listener->next) {
		switch (listener->type) {
		case RAD_LISTEN_AUTH:
			do_component[RLM_COMPONENT_AUTZ] = 1;
			do_component[RLM_COMPONENT_AUTH] = 1;
			do_component[RLM_COMPONENT_POST_AUTH] = 1;
			do_component[RLM_COMPONENT_SESS] = 1;
			break;

		case RAD_LISTEN_DETAIL:	/* just like acct */
		case RAD_LISTEN_ACCT:
			do_component[RLM_COMPONENT_PREACCT] = 1;
			do_component[RLM_COMPONENT_ACCT] = 1;
			break;

		case RAD_LISTEN_PROXY:
			do_component[RLM_COMPONENT_PRE_PROXY] = 1;
			do_component[RLM_COMPONENT_POST_PROXY] = 1;
			break;

		case RAD_LISTEN_VQP:
			do_component[RLM_COMPONENT_POST_AUTH] = 1;
			break;
			/*
			 *	Ignore this.
			 */
		case RAD_LISTEN_SNMP:
			break;

		default:
			rad_assert(0 == 1);
			break;
		}
	}

	for (comp = RLM_COMPONENT_AUTH; comp < RLM_COMPONENT_COUNT; comp++) {
		/*
		 *	Have the debugging messages all in one place.
		 */
		if (!do_component[comp]) {
			DEBUG2("modules: Not loading %s{} section",
			       section_type_value[comp].section);
		}
	}

	/*
	 *	Create any DICT_VALUE's for the types.  See
	 *	'doc/configurable_failover' for examples of 'authtype'
	 *	used to create new Auth-Type values.  In order to
	 *	let the user create new names, we've got to look for
	 *	those names, and create DICT_VALUE's for them.
	 */
	for (comp = RLM_COMPONENT_AUTH; comp < RLM_COMPONENT_COUNT; comp++) {
		int		value;
		const char	*name2;
		DICT_ATTR	*dattr;
		DICT_VALUE	*dval;
		CONF_SECTION	*sub, *next;
		CONF_PAIR	*cp;

		/*
		 *	Not needed, don't load it.
		 */
		if (!do_component[comp]) {
			continue;
		}
		cs = cf_section_find(section_type_value[comp].section);

		if (!cs) continue;

		sub = NULL;
		do {
			/*
			 *	See if there's a sub-section by that
			 *	name.
			 */
			next = cf_subsection_find_next(cs, sub,
						       section_type_value[comp].typename);

			/*
			 *	Allow some old names, too.
			 */
			if (!next && (comp <= 4)) {
				next = cf_subsection_find_next(cs, sub,
							       old_section_type_value[comp].typename);
			}
			sub = next;

			/*
			 *	If so, look for it to define a new
			 *	value.
			 */
			name2 = cf_section_name2(sub);
			if (!name2) continue;


			/*
			 *	If the value already exists, don't
			 *	create it again.
			 */
			dval = dict_valbyname(section_type_value[comp].attr,
					      name2);
			if (dval) continue;

			/*
       			 *	Find the attribute for the value.
			 */
			dattr = dict_attrbyvalue(section_type_value[comp].attr);
			if (!dattr) {
				radlog(L_ERR, "%s[%d]: No such attribute %s",
				       mainconfig.radiusd_conf,
				       cf_section_lineno(sub),
				       section_type_value[comp].typename);
				continue;
			}

			/*
			 *	Create a new unique value with a
			 *	meaningless number.  You can't look at
			 *	it from outside of this code, so it
			 *	doesn't matter.  The only requirement
			 *	is that it's unique.
			 */
			do {
				value = lrad_rand() & 0x00ffffff;
			} while (dict_valbyattr(dattr->attr, value));

			if (dict_addvalue(name2, dattr->name, value) < 0) {
				radlog(L_ERR, "%s", librad_errstr);
				return -1;
			}
		} while (sub != NULL);

		/*
		 *	Loop over the non-sub-sections, too.
		 */
		cp = NULL;
		do {
			/*
			 *	See if there's a conf-pair by that
			 *	name.
			 */
			cp = cf_pair_find_next(cs, cp, NULL);
			if (!cp) break;


			/*
			 *	If the value already exists, don't
			 *	create it again.
			 */
			name2 = cf_pair_attr(cp);
			dval = dict_valbyname(section_type_value[comp].attr,
					      name2);
			if (dval) continue;

			/*
       			 *	Find the attribute for the value.
			 */
			dattr = dict_attrbyvalue(section_type_value[comp].attr);
			if (!dattr) {
				radlog(L_ERR, "%s[%d]: No such attribute %s",
				       mainconfig.radiusd_conf,
				       cf_section_lineno(sub),
				       section_type_value[comp].typename);
				continue;
			}

			/*
			 *	Finally, create the new attribute.
			 */
			do {
				value = lrad_rand() & 0x00ffffff;
			} while (dict_valbyattr(dattr->attr, value));
			if (dict_addvalue(name2, dattr->name, value) < 0) {
				radlog(L_ERR, "%s", librad_errstr);
				return -1;
			}
		} while (cp != NULL);
	} /* over the sections which can have redundent sub-sections */

	/*
	 *	Remember where the modules were stored.
	 */
	modules = cf_section_find("modules");
	if (!modules) {
		radlog(L_ERR, "Cannot find a \"modules\" section in the configuration file!");
		return -1;
	}

	/*
	 *  Look for the 'instantiate' section, which tells us
	 *  the instantiation order of the modules, and also allows
	 *  us to load modules with no authorize/authenticate/etc.
	 *  sections.
	 */
	cs = cf_section_find("instantiate");
	if (cs != NULL) {
		CONF_ITEM *ci;
		CONF_PAIR *cp;
		module_instance_t *module;
		const char *name;

		DEBUG2(" instantiate {");

		/*
		 *  Loop over the items in the 'instantiate' section.
		 */
		for (ci=cf_item_find_next(cs, NULL);
		     ci != NULL;
		     ci=cf_item_find_next(cs, ci)) {

			/*
			 *	Skip sections.  They'll be handled
			 *	later, if they're referenced at all...
			 */
			if (cf_item_is_section(ci)) {
				continue;
			}

			cp = cf_itemtopair(ci);
			name = cf_pair_attr(cp);
			module = find_module_instance(modules, name);
			if (!module) {
				return -1;
			}
		} /* loop over items in the subsection */

		DEBUG2(" }");
	} /* if there's an 'instantiate' section. */

	DEBUG2(" modules {");

	/*
	 *	Loop over all of the known components, finding their
	 *	configuration section, and loading it.
	 */
	for (comp = 0; comp < RLM_COMPONENT_COUNT; ++comp) {
		cs = cf_section_find(section_type_value[comp].section);
		if (cs == NULL)
			continue;

		if (!do_component[comp]) {
			continue;
		}

		if (cf_item_find_next(cs, NULL) == NULL) {
			continue; /* section is empty */
		}

		DEBUG2(" Module: Checking %s {...} for more modules to load",
		       section_type_value[comp].section);

		if (load_component_section(NULL, cs, comp, mainconfig.radiusd_conf) < 0) {
			return -1;
		}
	}

	DEBUG2(" }");

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

/*
 *	Do post-authentication for ALL configured sessions
 */
int module_post_auth(int postauth_type, REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_POST_AUTH, postauth_type, request);
}

