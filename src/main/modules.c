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
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2000  Alan Curry <pacman@cqc.com>
 */

static const char rcsid[] = "$Id$";

#include	"autoconf.h"
#include	"libradius.h"

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<assert.h>

#include	"radiusd.h"
#include	"modpriv.h"
#include	"modules.h"
#include	"modcall.h"
#include	"conffile.h"
#include	"ltdl.h"

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
  "session"
};

static const char *subcomponent_names[RLM_COMPONENT_COUNT] =
{
  "authtype",
  "autztype",
  "preacctype",
  "acctype",
  "sesstype"
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
#if HAVE_PTHREAD_H
		if (c->mutex) {
			/*
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

static void module_list_free(void)
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
}

/*
 *  New Auth-Type's start at a large number, and go up from there.
 *
 *  We could do something more intelligent, but this should work almost
 *  all of the time.
 *
 * FIXME: move this to dict.c as dict_valadd() and dict_valdel()
 *        also clear value in module_list free (necessary?)
 */
static int new_authtype_value(const char *name)
{
	static int max_value = 32767;
	DICT_VALUE *old_value, *new_value;
	
	/*
	 *  Check to see if it's already defined.
	 *  If so, return the old value.
	 */
	old_value = dict_valbyname(PW_AUTHTYPE, name);
	if (old_value) return old_value->value; 
	/* Look for the predefined Auth-Type value */
	old_value = dict_valbyattr(PW_AUTHTYPE, 0);
	if (!old_value) return 0;	/* something WIERD is happening */
	
	/* allocate a new value */
	new_value = (DICT_VALUE *) rad_malloc(sizeof(DICT_VALUE));
	
	/* copy the old to the new */
	memcpy(new_value, old_value, sizeof(DICT_VALUE));
	old_value->next = new_value;
	
	/* set it up */
	strNcpy(new_value->name, name, sizeof(new_value->name));
	new_value->value = max_value++;
	
	return new_value->value;
}

/*
 *	Find a module on disk or in memory, and link to it.
 */
static module_list_t *linkto_module(const char *module_name,
				    const char *cffilename, int cflineno)
{
	module_list_t	**last, *node;
	lt_dlhandle	*handle;

	/*
	 *	Look through the global module library list for the
	 *	named module.
	 */
	last = &module_list;
	for (node = module_list; node != NULL; node = node->next) {
		/*
		 *	Found the named module.  Return it.
		 */
		if (strcmp(node->name, module_name) == 0)
			return node;

		/*
		 *	Keep a pointer to the last entry to update...
		 */
		last = &node->next;
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
	node->module = (module_t *) lt_dlsym(node->handle, module_name);
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

	*last = node;

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
	if (!cs) {
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
	for(inst_cs=cf_subsection_find_next(cs, NULL, NULL)
	    ; inst_cs ;
	    inst_cs=cf_subsection_find_next(cs, inst_cs, NULL)) {
                name1 = cf_section_name1(inst_cs);
                name2 = cf_section_name2(inst_cs);
		if ( (name2 && !strcmp(name2, instname)) ||
		     (!name2 && !strcmp(name1, instname)) )
			break;
	}
	if (!inst_cs) {
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
	 *	Link to the module by name: rlm_FOO
	 */
	snprintf(module_name, sizeof(module_name), "rlm_%s", name1);
	node->entry = linkto_module(module_name,
				   "radiusd.conf", cf_section_lineno(inst_cs));
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

#if HAVE_PTHREAD_H
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
			default:                    return RLM_MODULE_FAIL;
		}
	}
	return modcall(comp, this->modulelist, request);
}

/* Load a flat module list, as found inside an authtype{} block */
static void load_subcomponent_section(CONF_SECTION *cs, int comp, const char *filename)
{
	int idx;
	indexed_modcallable *subcomp;

	static int meaningless_counter = 1;

	/* We must assign a numeric index to this subcomponent. For
	 * auth, it is generated and placed in the dictionary by
	 * new_authtype_value(). The others are just numbers that are pulled
	 * out of thin air, and the names are neither put into the dictionary
	 * nor checked for uniqueness, but all that could be fixed in a few
	 * minutes, if anyone finds a real use for indexed config of
	 * components other than auth. */
	if (comp==RLM_COMPONENT_AUTH)
		idx = new_authtype_value(cf_section_name2(cs));
	else
		idx = meaningless_counter++;
	
	subcomp = new_sublist(comp, idx);
	if (!subcomp) {
		radlog(L_ERR|L_CONS,
		       "%s[%d] %s %s already configured - skipping",
		       filename, cf_section_lineno(cs),
		       subcomponent_names[comp], cf_section_name2(cs));
		return;
	}

	subcomp->modulelist = compile_modgroup(comp, cs, filename);
}

static void load_component_section(CONF_SECTION *cs, int comp, const char *filename)
{
	modcallable	*this;
	CONF_ITEM	*modref;
        int		modreflineno;
	int		idx;
	indexed_modcallable *subcomp;
	const char	*modname;

	for(modref=cf_item_find_next(cs, NULL)
	    ; modref ;
	    modref=cf_item_find_next(cs, modref)) {

		if(cf_item_is_section(modref)) {
			CONF_SECTION *scs;
			scs = cf_itemtosection(modref);

			if (!strcmp(cf_section_name1(scs),
				    subcomponent_names[comp])) {
				load_subcomponent_section(scs, comp, filename);
				continue;
			}

			modreflineno = cf_section_lineno(scs);
		} else {
			CONF_PAIR *cp;
			cp = cf_itemtopair(modref);
			modreflineno = cf_pair_lineno(cp);
		}

		this = compile_modsingle(comp, modref, filename, &modname);

		if (comp==RLM_COMPONENT_AUTH) {
			idx = new_authtype_value(modname);
		} else {
			/* See the comment in new_sublist() for explanation
			 * of the special index 0 */
			idx = 0;
		}

		subcomp = new_sublist(comp, idx);
		if (!subcomp) {
			radlog(L_ERR|L_CONS,
			    "%s[%d] %s %s already configured - skipping",
			    filename, modreflineno, subcomponent_names[comp],
			    modname);
			modcallable_free(&this);
			continue;
		}

		/* If subcomp->modulelist is NULL, add_to_modcallable will
		 * create it */
		add_to_modcallable(&subcomp->modulelist, this,
					comp, modreflineno);
  	}
}

/*
 *	Parse the module config sections, and load
 *	and call each module's init() function.
 *
 *	Libtool makes your life a LOT easier, especially with libltdl.
 *	see: http://www.gnu.org/software/libtool/
 */
int setup_modules(void)
{
	int		comp;
	CONF_SECTION	*cs;
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
		module_list_free();
	}

	/*
	 *	Loop over all of the known components, finding their
	 *	configuration section, and loading it.
	 */
	for (comp = 0; comp < RLM_COMPONENT_COUNT; ++comp) {
		cs = cf_section_find(component_names[comp]);
		if (!cs) continue;
		
		load_component_section(cs, comp, filename);
	}

	return 0;
}

/*
 *	Call all authorization modules until one returns
 *	somethings else than RLM_MODULE_OK
 */
int module_authorize(REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_AUTZ, 0, request);
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
int module_accounting(REQUEST *request)
{
	return indexed_modcall(RLM_COMPONENT_ACCT, 0, request);
}

/*
 *	See if a user is already logged in.
 *
 *	Returns: 0 == OK, 1 == double logins, 2 == multilink attempt
 */
int module_checksimul(REQUEST *request, int maxsimul)
{
	int		rcode;

	if(!components[RLM_COMPONENT_SESS])
		return 0;

	if(!request->username)
		return 0;

	request->simul_count = 0;
	request->simul_max = maxsimul;
	request->simul_mpp = 1;

	rcode = indexed_modcall(RLM_COMPONENT_SESS, 0, request);

	if(rcode != RLM_MODULE_OK) {
		/* FIXME: Good spot for a *rate-limited* warning to the log */
		return 0;
	}

	return (request->simul_count < maxsimul) ? 0 : request->simul_mpp;
}
