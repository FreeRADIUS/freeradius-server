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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2003  The FreeRADIUS server project
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2000  Alan Curry <pacman@world.std.com>
 */

static const char rcsid[] = "$Id$";

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "radiusd.h"
#include "modpriv.h"
#include "modules.h"
#include "modcall.h"
#include "conffile.h"
#include "ltdl.h"
#include "rad_assert.h"

/*
 *	Internal list of all of the modules we have loaded.
 */
static module_list_t *module_list = NULL;

/*
 *	Internal list of each module instance.
 */
static module_instance_t *module_instance_list = NULL;

typedef struct indexed_modcallable {
	struct indexed_modcallable *next;
	int idx;
	modcallable *modulelist;
} indexed_modcallable;

/*
 *	For each component, keep an ordered list of ones to call.
 */
static indexed_modcallable *components[RLM_COMPONENT_COUNT];

/*
 *	The component names.
 *
 *	Hmm... we probably should be getting these from the configuration
 *	file, too.
 */
const char *component_names[RLM_COMPONENT_COUNT] =
{
	"authenticate",
	"authorize",
	"preacct",
	"accounting",
	"session",
	"pre-proxy",
	"post-proxy",
	"post-auth"
};

/*
 *	Delete ASAP.
 */
static const char *old_subcomponent_names[RLM_COMPONENT_COUNT] =
{
	"authtype",
	"autztype",
	"preacctype",
	"acctype",
	"sesstype",
	"pre-proxytype",
	"post-proxytype",
	"post-authtype"
};

static const char *subcomponent_names[RLM_COMPONENT_COUNT] =
{
	"Auth-Type",
	"Autz-Type",
	"Pre-Acct-Type",
	"Acct-Type",
	"Session-Type",
	"Pre-Proxy-Type",
	"Post-Proxy-Type",
	"Post-Auth-Type"
};

static void indexed_modcallable_free(indexed_modcallable **cf)
{
	indexed_modcallable	*c, *next;

	c = *cf;
	while (c) {
		next = c->next;
		modcallable_free(&c->modulelist);
		free(c);
		c = next;
	}
	*cf = NULL;
}

static void instance_list_free(module_instance_t **i)
{
	module_instance_t	*c, *next;

	c = *i;
	while (c) {
		next = c->next;
		if(c->entry->module->detach)
			(c->entry->module->detach)(c->insthandle);
#ifdef HAVE_PTHREAD_H
		if (c->mutex) {
			/*
			 *	FIXME
			 *	The mutex MIGHT be locked...
			 *	we'll check for that later, I guess.
			 */
			pthread_mutex_destroy(c->mutex);
			free(c->mutex);
		}
#endif
		free(c);
		c = next;
	}
	*i = NULL;
}

/*
 *	Remove all of the modules.
 */
int detach_modules(void)
{
	module_list_t *ml, *next;
	int i;

	/*
	 *	Delete the internal component pointers.
	 */
	for (i = 0; i < RLM_COMPONENT_COUNT; i++) {
		indexed_modcallable_free(&components[i]);
	}

	instance_list_free(&module_instance_list);

	ml = module_list;
	while (ml) {
		next = ml->next;
		if (ml->module->destroy)
			(ml->module->destroy)();
		lt_dlclose(ml->handle);	/* ignore any errors */
		free(ml);
		ml = next;
	}

	module_list = NULL;

	return 0;
}

/*
 *	Find a module on disk or in memory, and link to it.
 */
static module_list_t *linkto_module(const char *module_name,
		const char *cffilename, int cflineno)
{
	module_list_t *node;
	lt_dlhandle handle;
	char module_struct[256];
	char *p;

	/*
	 *	Look through the global module library list for the
	 *	named module.
	 */
	for (node = module_list; node != NULL; node = node->next) {
		/*
		 *	Found the named module.  Return it.
		 */
		if (strcmp(node->name, module_name) == 0)
			return node;

	}

	/*
	 *	Keep the handle around so we can dlclose() it.
	 */
	handle = lt_dlopenext(module_name);
	if (handle == NULL) {
		radlog(L_ERR|L_CONS, "%s[%d] Failed to link to module '%s':"
				" %s\n", cffilename, cflineno, module_name, lt_dlerror());
		return NULL;
	}

	/* make room for the module type */
	node = (module_list_t *) rad_malloc(sizeof(module_list_t));

	/* fill in the module structure */
	node->next = NULL;
	node->handle = handle;
	strNcpy(node->name, module_name, sizeof(node->name));
	
	/*
	 *	Link to the module's rlm_FOO{} module structure.
	 */
	/* module_name has the version embedded; strip it. */
	strcpy(module_struct, module_name);
	p = strrchr(module_struct, '-');
	if (p)
		*p = '\0';
	node->module = (module_t *) lt_dlsym(node->handle, module_struct);
	if (!node->module) {
		radlog(L_ERR|L_CONS, "%s[%d] Failed linking to "
				"%s structure in %s: %s\n",
				cffilename, cflineno,
				module_name, cffilename, lt_dlerror());
		lt_dlclose(node->handle);	/* ignore any errors */
		free(node);
		return NULL;
	}
	
	/* call the modules initialization */
	if (node->module->init && (node->module->init)() < 0) {
		radlog(L_ERR|L_CONS, "%s[%d] Module initialization failed.\n",
				cffilename, cflineno);
		lt_dlclose(node->handle);	/* ignore any errors */
		free(node);
		return NULL;
	}

	DEBUG("Module: Loaded %s ", node->module->name);

	node->next = module_list;
	module_list = node;

	return node;
}

/*
 *	Find a module instance.
 */
module_instance_t *find_module_instance(const char *instname)
{
	CONF_SECTION *cs, *inst_cs;
	const char *name1, *name2;
	module_instance_t *node, **last;
	char module_name[256];

	/*
	 *	Look through the global module instance list for the
	 *	named module.
	 */
	last = &module_instance_list;
	for (node = module_instance_list; node != NULL; node = node->next) {
		/*
		 *	Found the named instance.  Return it.
		 */
		if (strcmp(node->name, instname) == 0)
			return node;

		/*
		 *	Keep a pointer to the last entry to update...
		 */
		last = &node->next;
	}

	/*
	 *	Instance doesn't exist yet. Try to find the
	 *	corresponding configuration section and create it.
	 */

	/*
	 *	Look for the 'modules' configuration section.
	 */
	cs = cf_section_find("modules");
	if (cs == NULL) {
		radlog(L_ERR|L_CONS, "ERROR: Cannot find a 'modules' section in the configuration file.\n");
		return NULL;
	}

	/*
	 *	Module instances are declared in the modules{} block
	 *	and referenced later by their name, which is the
	 *	name2 from the config section, or name1 if there was
	 *	no name2.
	 */
	name1 = name2 = NULL;
	for(inst_cs=cf_subsection_find_next(cs, NULL, NULL); 
			inst_cs != NULL;
			inst_cs=cf_subsection_find_next(cs, inst_cs, NULL)) {
		name1 = cf_section_name1(inst_cs);
		name2 = cf_section_name2(inst_cs);
		if ( (name2 && !strcmp(name2, instname)) ||
		     (!name2 && !strcmp(name1, instname)) )
			break;
	}
	if (inst_cs == NULL) {
		radlog(L_ERR|L_CONS, "ERROR: Cannot find a configuration entry for module \"%s\".\n", instname);
		return NULL;
	}

	/*
	 *	Found the configuration entry.
	 */
	node = rad_malloc(sizeof(*node));
	node->next = NULL;
	node->insthandle = NULL;
	
	/*
	 *	Link to the module by name: rlm_FOO-major.minor
	 */
	if (strncmp(name1, "rlm_", 4)) {
#if 0
		snprintf(module_name, sizeof(module_name), "rlm_%s-%d.%d",
			 name1, RADIUSD_MAJOR_VERSION, RADIUSD_MINOR_VERSION);
#else
		snprintf(module_name, sizeof(module_name), "rlm_%s",
			 name1);
#endif
	} else {
		strNcpy(module_name, name1, sizeof(module_name));

	}

	/*
	 *  FIXME: "radiusd.conf" is wrong here; must find cf filename
	 */
	node->entry = linkto_module(module_name, "radiusd.conf",
				    cf_section_lineno(inst_cs));
	if (!node->entry) {
		free(node);
		/* linkto_module logs any errors */
		return NULL;
	}
	
	/*
	 *	Call the module's instantiation routine.
	 */
	if ((node->entry->module->instantiate) &&
	    ((node->entry->module->instantiate)(inst_cs,
			&node->insthandle) < 0)) {
		radlog(L_ERR|L_CONS,
				"radiusd.conf[%d]: %s: Module instantiation failed.\n",
				cf_section_lineno(inst_cs), instname);
		free(node);
		return NULL;
	}

	/*
	 *	We're done.  Fill in the rest of the data structure,
	 *	and link it to the module instance list.
	 */
	strNcpy(node->name, instname, sizeof(node->name));

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
	*last = node;

	DEBUG("Module: Instantiated %s (%s) ", name1, node->name);
	
	return node;
}

static indexed_modcallable *lookup_by_index(indexed_modcallable *head, int idx)
{
	indexed_modcallable *p;

	for (p = head; p != NULL; p = p->next) {
		if( p->idx == idx)
			return p;
	}
	return NULL;
}

static indexed_modcallable *new_sublist(int comp, int idx)
{
	indexed_modcallable **head = &components[comp];
	indexed_modcallable *node = *head;
	indexed_modcallable **last = head;

	while (node) {
		/* It is an error to try to create a sublist that already
		 * exists. It would almost certainly be caused by accidental
		 * duplication in the config file.
		 * 
		 * index 0 is the exception, because it is used when we want
		 * to collect _all_ listed modules under a single index by
		 * default, which is currently the case in all components
		 * except authenticate. */
		if (node->idx == idx) {
			if (idx == 0)
				return node;
			else
				return NULL;
		}
		last = &node->next;
		node = node->next;
	}

	node = rad_malloc(sizeof *node);
	node->next = NULL;
	node->modulelist = NULL;
	node->idx = idx;
	*last = node;
	return node;
}

static int indexed_modcall(int comp, int idx, REQUEST *request)
{
	indexed_modcallable *this;

	this = lookup_by_index(components[comp], idx);
	if (!this) {
		/* Return a default value appropriate for the component */
		switch(comp) {
			case RLM_COMPONENT_AUTZ:    return RLM_MODULE_NOTFOUND;
			case RLM_COMPONENT_AUTH:    return RLM_MODULE_REJECT;
			case RLM_COMPONENT_PREACCT: return RLM_MODULE_NOOP;
			case RLM_COMPONENT_ACCT:    return RLM_MODULE_NOOP;
			case RLM_COMPONENT_SESS:    return RLM_MODULE_FAIL;
			case RLM_COMPONENT_PRE_PROXY:  return RLM_MODULE_NOOP;
			case RLM_COMPONENT_POST_PROXY: return RLM_MODULE_NOOP;
			case RLM_COMPONENT_POST_AUTH:  return RLM_MODULE_NOOP;
			default:                    return RLM_MODULE_FAIL;
		}
	}
	return modcall(comp, this->modulelist, request);
}

/* Load a flat module list, as found inside an authtype{} block */
static void load_subcomponent_section(CONF_SECTION *cs, int comp,
				      const char *filename)
{
	int idx;
	indexed_modcallable *subcomp;
	modcallable *ml;
	DICT_VALUE *dval;

	static int meaningless_counter = 1;

	ml = compile_modgroup(comp, cs, filename);

	/* We must assign a numeric index to this subcomponent. For
	 * auth, it is generated and placed in the dictionary by
	 * new_sectiontype_value(). The others are just numbers that are pulled
	 * out of thin air, and the names are neither put into the dictionary
	 * nor checked for uniqueness, but all that could be fixed in a few
	 * minutes, if anyone finds a real use for indexed config of
	 * components other than auth. */
	dval = NULL;
	if (comp==RLM_COMPONENT_AUTH) {
		dval = dict_valbyname(PW_AUTH_TYPE, cf_section_name2(cs));
	} else if (comp == RLM_COMPONENT_AUTZ) {
		dval = dict_valbyname(PW_AUTZ_TYPE, cf_section_name2(cs));
	} else if (comp == RLM_COMPONENT_ACCT) {
		dval = dict_valbyname(PW_ACCT_TYPE, cf_section_name2(cs));
	} else if (comp == RLM_COMPONENT_SESS) {
		dval = dict_valbyname(PW_SESSION_TYPE, cf_section_name2(cs));
	} else if (comp == RLM_COMPONENT_POST_AUTH) {
		dval = dict_valbyname(PW_POST_AUTH_TYPE, cf_section_name2(cs));
	}

	if (dval) {
		idx = dval->value;
	} else {
		idx = meaningless_counter++;
	}

	subcomp = new_sublist(comp, idx);
	if (!subcomp) {
		radlog(L_ERR|L_CONS,
				"%s[%d] %s %s already configured - skipping",
				filename, cf_section_lineno(cs),
				subcomponent_names[comp], cf_section_name2(cs));
		modcallable_free(&ml);
		return;
	}

	subcomp->modulelist = ml;
}

static int load_component_section(CONF_SECTION *cs, int comp,
				  const char *filename)
{
	modcallable *this;
	CONF_ITEM *modref;
	int idx;
	indexed_modcallable *subcomp;
	const char *modname;
	char *visiblename;

	for (modref=cf_item_find_next(cs, NULL); 
			modref != NULL;
			modref=cf_item_find_next(cs, modref)) {

		if (cf_item_is_section(modref)) {
			const char *sec_name;
			CONF_SECTION *scs;
			scs = cf_itemtosection(modref);

			sec_name = cf_section_name1(scs);
			if (strcmp(sec_name,
				   subcomponent_names[comp]) == 0) {
				load_subcomponent_section(scs, comp, filename);
				continue;
			}

			/*
			 *	Allow old names, too.
			 */
			if (strcmp(sec_name,
				   old_subcomponent_names[comp]) == 0) {
				load_subcomponent_section(scs, comp, filename);
				continue;
			}

			/*
			 *	Allow configurable fail-over directives.
			 */
			if ((strcmp(sec_name, "redundant") != 0) &&
			    (strcmp(sec_name, "group") != 0) &&
			    (strcmp(sec_name, "append") != 0)) {
				/*
				 *	It's a section, but nothing we
				 *	recognize.  Die!
				 */
				radlog(L_ERR|L_CONS, "%s[%d] Unknown configuration directive \"%s\" in %s section.",
				       filename, cf_section_lineno(cs),
				       sec_name, component_names[comp]);
				return -1;
			} /* else fall through to processing it */
		} else {
			CONF_PAIR *cp;
			cp = cf_itemtopair(modref);
		}

		/*
		 *	FIXME: This calls exit if the reference can't be
		 *	found.  We should instead print a better error,
		 *	and return the failure code up the stack.
		 */
		this = compile_modsingle(comp, modref, filename, &modname);

		if (comp == RLM_COMPONENT_AUTH) {
			DICT_VALUE *dval;

			dval = dict_valbyname(PW_AUTH_TYPE, modname);
			rad_assert(dval != NULL);
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
					filename, subcomponent_names[comp],
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

typedef struct section_type_value_t {
	const char	*section;
	const char	*typename;
	int		attr;
} section_type_value_t;

static const section_type_value_t section_type_value[] = {
	{ "authorize",    "Autz-Type",       PW_AUTZ_TYPE },
	{ "authenticate", "Auth-Type",       PW_AUTH_TYPE },
	{ "accounting",   "Acct-Type",       PW_ACCT_TYPE },
	{ "session",      "Session-Type",    PW_SESSION_TYPE },
	{ "post-auth",    "Post-Auth-Type",  PW_POST_AUTH_TYPE },
	{ "preacct",      "Pre-Acct-Type",   PW_PRE_ACCT_TYPE },
	{ "post-proxy",   "Post-Proxy-Type", PW_POST_PROXY_TYPE },
	{ "pre-proxy",    "Pre-Proxy-Type",  PW_PRE_PROXY_TYPE },
	{ NULL, NULL, 0 }
};

/*
 *	Delete ASAP.
 */
static const section_type_value_t old_section_type_value[] = {
	{ "authorize",    "autztype", PW_AUTZ_TYPE },
	{ "authenticate", "authtype", PW_AUTH_TYPE },
	{ "accounting",   "acctype", PW_ACCT_TYPE },
	{ "session",      "sesstype", PW_SESSION_TYPE },
	{ "post-auth",	  "post-authtype", PW_POST_AUTH_TYPE },
	{ NULL, NULL, 0 }
};

/*
 *	Parse the module config sections, and load
 *	and call each module's init() function.
 *
 *	Libtool makes your life a LOT easier, especially with libltdl.
 *	see: http://www.gnu.org/software/libtool/
 */
int setup_modules(void)
{
	int comp;
	CONF_SECTION *cs;

	/*
	 *  FIXME: This should be pulled from somewhere else.
	 */
	const char *filename="radiusd.conf";

	/*
	 *	No current list of modules: Go initialize libltdl.
	 */
	if (!module_list) {
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
			exit(1); /* FIXME */
			
		}

		/*
		 *	Set the search path to ONLY our library directory.
		 *	This prevents the modules from being found from
		 *	any location on the disk.
		 */
		lt_dlsetsearchpath(radlib_dir);
		
		DEBUG2("Module: Library search path is %s",
				lt_dlgetsearchpath());

		/*
		 *	Initialize the components.
		 */
		for (comp = 0; comp < RLM_COMPONENT_COUNT; comp++) {
			components[comp] = NULL;
		}

	} else {
		detach_modules();
	}

	/*
	 *	Create any DICT_VALUE's for the types.  See
	 *	'doc/configurable_failover' for examples of 'authtype'
	 *	used to create new Auth-Type values.  In order to
	 *	let the user create new names, we've got to look for
	 *	those names, and create DICT_VALUE's for them.
	 */
	for (comp = 0; section_type_value[comp].section != NULL; comp++) {
		const char	*name2;
		DICT_ATTR	*dattr;
		DICT_VALUE	*dval;
		CONF_SECTION	*sub, *next;
		CONF_PAIR	*cp;

		/*
		 *  Big-time YUCK
		 */
		static int my_value = 32767;

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
			if (!dattr) continue;

			/*
			 *	Finally, create the new attribute.
			 */
			if (dict_addvalue(name2, dattr->name, my_value++) < 0) {
				radlog(L_ERR, "%s", librad_errstr);
				exit(1);
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
			if (!dattr) continue;

			/*
			 *	Finally, create the new attribute.
			 */
			if (dict_addvalue(name2, dattr->name, my_value++) < 0) {
				radlog(L_ERR, "%s", librad_errstr);
				exit(1);
			}
		} while (cp != NULL);
	} /* over the sections which can have redundent sub-sections */

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

		/*
		 *  Loop over the items in the 'instantiate' section.
		 */
		for (ci=cf_item_find_next(cs, NULL);
		     ci != NULL;
		     ci=cf_item_find_next(cs, ci)) {

			if (cf_item_is_section(ci)) {
				radlog(L_ERR|L_CONS,
				       "%s[%d] Subsection for module instantiate is not allowed\n", filename,
				       
				       cf_section_lineno(cf_itemtosection(ci)));
				exit(1);
			}
	
			cp = cf_itemtopair(ci);
			name = cf_pair_attr(cp);
			module = find_module_instance(name);
			if (!module) {
				exit(1);
			}
		} /* loop over items in the subsection */
	} /* if there's an 'instantiate' section. */

	/*
	 *	Loop over all of the known components, finding their
	 *	configuration section, and loading it.
	 */
	for (comp = 0; comp < RLM_COMPONENT_COUNT; ++comp) {
		cs = cf_section_find(component_names[comp]);
		if (cs == NULL) 
			continue;
		
		if (load_component_section(cs, comp, filename) < 0) {
			exit(1);
		}
	}

	return 0;
}

/*
 *	Call all authorization modules until one returns
 *	somethings else than RLM_MODULE_OK
 */
int module_authorize(int autz_type, REQUEST *request)
{
	/*
	 *	We have a proxied packet, and we've been told
	 *	to NOT pass proxied packets through 'authorize'
	 *	a second time.  So stop.
	 */
	if ((request->proxy != NULL &&
	     mainconfig.post_proxy_authorize == FALSE)) {
		DEBUG2(" authorize: Skipping authorize in post-proxy stage");
		return RLM_MODULE_NOOP;
	}

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

	if(!components[RLM_COMPONENT_SESS])
		return 0;

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
int module_pre_proxy(REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_PRE_PROXY, 0, request);
}

/*
 *	Do post-proxying for ALL configured sessions
 */
int module_post_proxy(REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_POST_PROXY, 0, request);
}

/*
 *	Do post-authentication for ALL configured sessions
 */
int module_post_auth(int postauth_type, REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_POST_AUTH, postauth_type, request);
}

