/*
 * modcall.c
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
 */
#include "autoconf.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "radiusd.h"
#include "rad_assert.h"
#include "conffile.h"
#include "modpriv.h"
#include "modules.h"
#include "modcall.h"

/* mutually-recursive static functions need a prototype up front */
static modcallable *do_compile_modgroup(int, CONF_SECTION *, const char *,
					int, int);

/* Actions may be a positive integer (the highest one returned in the group
 * will be returned), or the keyword "return", represented here by
 * MOD_ACTION_RETURN, to cause an immediate return.
 * There's also the keyword "reject", represented here by MOD_ACTION_REJECT
 * to cause an immediate reject. */
#define MOD_ACTION_RETURN  (-1)
#define MOD_ACTION_REJECT  (-2)

/* Here are our basic types: modcallable, modgroup, and modsingle. For an
 * explanation of what they are all about, see ../../doc/README.failover */
struct modcallable {
	struct modcallable *next;
	const char *name;
	int actions[RLM_MODULE_NUMCODES];
	enum { MOD_SINGLE, MOD_GROUP, MOD_LOAD_BALANCE, MOD_REDUNDANT_LOAD_BALANCE } type;
};

#define GROUPTYPE_SIMPLE	0
#define GROUPTYPE_REDUNDANT	1
#define GROUPTYPE_APPEND	2
#define GROUPTYPE_COUNT		3

typedef struct {
	modcallable mc;
	int grouptype;	/* after mc */
	modcallable *children;
} modgroup;

typedef struct {
	modcallable mc;
	module_instance_t *modinst;
} modsingle;


static const LRAD_NAME_NUMBER grouptype_table[] = {
	{ "", GROUPTYPE_SIMPLE },
	{ "redundant ", GROUPTYPE_REDUNDANT },
	{ "append ", GROUPTYPE_APPEND },
	{ NULL, -1 }
};

/* Simple conversions: modsingle and modgroup are subclasses of modcallable,
 * so we often want to go back and forth between them. */
static modsingle *mod_callabletosingle(modcallable *p)
{
	rad_assert(p->type==MOD_SINGLE);
	return (modsingle *)p;
}
static modgroup *mod_callabletogroup(modcallable *p)
{
	rad_assert((p->type==MOD_GROUP) ||
		   (p->type==MOD_LOAD_BALANCE) ||
		   (p->type==MOD_REDUNDANT_LOAD_BALANCE));
	return (modgroup *)p;
}
static modcallable *mod_singletocallable(modsingle *p)
{
	return (modcallable *)p;
}
static modcallable *mod_grouptocallable(modgroup *p)
{
	return (modcallable *)p;
}

/* modgroups are grown by adding a modcallable to the end */
static void add_child(modgroup *g, modcallable *c)
{
	modcallable **head = &g->children;
	modcallable *node = *head;
	modcallable **last = head;

	if (!c) return;

	while (node) {
		last = &node->next;
		node = node->next;
	}

	rad_assert(c->next == NULL);
	*last = c;
}

/* Here's where we recognize all of our keywords: first the rcodes, then the
 * actions */
static const LRAD_NAME_NUMBER rcode_table[] = {
	{ "reject",     RLM_MODULE_REJECT       },
	{ "fail",       RLM_MODULE_FAIL         },
	{ "ok",         RLM_MODULE_OK           },
	{ "handled",    RLM_MODULE_HANDLED      },
	{ "invalid",    RLM_MODULE_INVALID      },
	{ "userlock",   RLM_MODULE_USERLOCK     },
	{ "notfound",   RLM_MODULE_NOTFOUND     },
	{ "noop",       RLM_MODULE_NOOP         },
	{ "updated",    RLM_MODULE_UPDATED      },
	{ NULL, 0 }
};


/*
 *	Compile action && rcode for later use.
 */
static int compile_action(modcallable *c, const char *attr, const char *value,
			  const char *filename, int lineno)
{
	int rcode, action;

	rcode = lrad_str2int(rcode_table, attr, -1);
	if (rcode < 0) {
		radlog(L_ERR|L_CONS,
		       "%s[%d] Unknown module rcode '%s'.\n",
		       filename, lineno, attr);
		return 0;
	}

	if (!strcasecmp(value, "return"))
		action = MOD_ACTION_RETURN;

	else if (!strcasecmp(value, "reject"))
		action = MOD_ACTION_REJECT;

	else if (strspn(value, "0123456789")==strlen(value)) {
		action = atoi(value);
		
		/*
		 *	Don't allow priority zero, for future use.
		 */
		if (action == 0) return 0;
	} else {
		radlog(L_ERR|L_CONS,
		       "%s[%d] Unknown action '%s'.\n",
		       filename, lineno, value);
		return 0;
	}

	c->actions[rcode] = action;

	return 1;
}

#if 0
static const char *action2str(int action)
{
	static char buf[32];
	if(action==MOD_ACTION_RETURN)
		return "return";
	if(action==MOD_ACTION_REJECT)
		return "reject";
	snprintf(buf, sizeof buf, "%d", action);
	return buf;
}
#endif

/* Some short names for debugging output */
static const char * const comp2str[] = {
	"authenticate",
	"authorize",
	"preacct",
	"accounting",
	"session",
	"pre-proxy",
	"post-proxy",
	"post-auth"
};

#ifdef HAVE_PTHREAD_H
/*
 *	Lock the mutex for the module
 */
static void safe_lock(module_instance_t *instance)
{
	if (instance->mutex)
		pthread_mutex_lock(instance->mutex);
}

/*
 *	Unlock the mutex for the module
 */
static void safe_unlock(module_instance_t *instance)
{
	if (instance->mutex)
		pthread_mutex_unlock(instance->mutex);
}
#else
/*
 *	No threads: these functions become NULL's.
 */
#define safe_lock(foo)
#define safe_unlock(foo)
#endif

static int call_modsingle(int component, modsingle *sp, REQUEST *request,
			  int default_result)
{
	int myresult = default_result;

	DEBUG3("  modsingle[%s]: calling %s (%s) for request %d",
	       comp2str[component], sp->modinst->name,
	       sp->modinst->entry->name, request->number);
	safe_lock(sp->modinst);

	/*
	 *	For logging unresponsive children.
	 */
	request->module = sp->modinst->name;
	request->component = comp2str[component];

	myresult = sp->modinst->entry->module->methods[component](
			sp->modinst->insthandle, request);

	request->module = NULL;
	safe_unlock(sp->modinst);
	DEBUG3("  modsingle[%s]: returned from %s (%s) for request %d",
	       comp2str[component], sp->modinst->name,
	       sp->modinst->entry->name, request->number);

	return myresult;
}


/*
 *	Helper function for call_modgroup, and call_modredundantloadbalance
 *
 *	Returns 0 for "stop", and "1" for continue.
 */
static int call_one(int component, modcallable *p, REQUEST *request,
		    int *priority, int *result)
{
	int r;

	/*
	 *	A module has taken too long to process the request,
	 *	and we've been told to stop processing it.
	 */
	if (request->options & RAD_REQUEST_OPTION_STOP_NOW) {
		*result = RLM_MODULE_FAIL;
		return 0;
	}
	
	/* Call this child by recursing into modcall */
	r = modcall(component, p, request);
	
#if 0
	DEBUG2("%s: action for %s is %s",
	       comp2str[component], lrad_int2str(rcode_table, r, "??"),
	       action2str(p->actions[r]));
#endif
	
	/*
	 * 	Find an action to go with the child's result. If it is
	 * 	"return", break out of the loop so the rest of the
	 * 	children in the list will be skipped.
	 */
	if (p->actions[r] == MOD_ACTION_RETURN) {
		*result = r;
		return 0;
	}
	
	/* If "reject" break out of the loop and return reject */
	if (p->actions[r] == MOD_ACTION_REJECT) {
		*result = RLM_MODULE_REJECT;
		return 0;
	}
	
	/*
	 *	Otherwise, the action is a number, the preference
	 *	level of this return code. If no higher preference has
	 *	been seen yet, remember this one
	 . */
	if (p->actions[r] >= *priority) {
		*result = r;
		*priority = p->actions[r];
	}
	
	return 1;
}


static int call_modgroup(int component, modgroup *g, REQUEST *request,
			 int default_result)
{
	int myresult = default_result;
	int priority = 0;	/* default result has lowest priority  */
	modcallable *p;

	/*
	 *	Catch people who have issues.
	 */
	if (!g->children) {
		DEBUG2("  WARNING! Asked to process empty group.  Returning %s.", lrad_int2str(rcode_table, myresult, "??"));
		return default_result;
	}

	/* Loop over the children */
	for (p = g->children; p; p = p->next) {
		if (!call_one(component, p, request, &priority, &myresult)) {
			break;
		}
	}

	return myresult;
}

static int call_modloadbalance(int component, modgroup *g, REQUEST *request,
			       int default_result)
{
	int count = 1;
	modcallable *p, *child = NULL;

	/*
	 *	Catch people who have issues.
	 */
	if (!g->children) {
		DEBUG2("  WARNING! Asked to process empty load-balance group.  Returning %s.", lrad_int2str(rcode_table, default_result, "??"));
		return default_result;
	}

	/*
	 *	Pick a random child.
	 */

	/* Loop over the children */
	for(p = g->children; p; p = p->next) {
		if (!child) {
			child = p;
			count = 1;
			continue;
		}

		/*
		 *	Keep track of how many load balancing servers
		 *	we've gone through.
		 */
		count++;

		/*
		 *	See the "camel book" for why this works.
		 *
		 *	If (rand(0..n) < 1), pick the current realm.
		 *	We add a scale factor of 65536, to avoid
		 *	floating point.
		 */
		if ((count * (lrad_rand() & 0xffff)) < (uint32_t) 0x10000) {
			child = p;
		}
	}
	rad_assert(child != NULL);

	/* Call the chosen child by recursing into modcall */
	return modcall(component, child, request);
}


/*
 *	For more than 2 modules with redundancy + load balancing
 *	across all of them, layering the "redundant" and
 *	"load-balance" groups gets too complicated.  As a result, we
 *	implement a special function to do this.
 */
static int call_modredundantloadbalance(int component, modgroup *g, REQUEST *request,
					int default_result)
{
	int count = 1;
	int myresult = default_result;
	int priority = 0;	/* default result has lowest priority  */
	modcallable *p, *child = NULL;

	/*
	 *	Catch people who have issues.
	 */
	if (!g->children) {
		DEBUG2("  WARNING! Asked to process empty redundant-load-balance group.  Returning %s.", lrad_int2str(rcode_table, default_result, "??"));
		return default_result;
	}

	/*
	 *	Pick a random child.
	 */

	/* Loop over the children */
	for(p = g->children; p; p = p->next) {
		if (!child) {
			child = p;
			count = 1;
			continue;
		}

		/*
		 *	Keep track of how many load balancing servers
		 *	we've gone through.
		 */
		count++;

		/*
		 *	See the "camel book" for why this works.
		 *
		 *	If (rand(0..n) < 1), pick the current realm.
		 *	We add a scale factor of 65536, to avoid
		 *	floating point.
		 */
		if ((count * (lrad_rand() & 0xffff)) < (uint32_t) 0x10000) {
			child = p;
		}
	}
	rad_assert(child != NULL);

	/*
	 *	Call the chosen child, with fail-over to the next one
	 *	if it is down.
	 */
	p = child;
	do {
		/*
		 *	Call the chosen entry.  If we're done, then
		 *	stop.
		 */
		if (!call_one(component, p, request, &priority, &myresult)) {
			break;
		}
		
		/*
		 *	Go to the next one, and wrap around to the beginning if
		 *	we reach the end.
		 */
		p = p->next;
		if (!p) p = g->children;
	} while (p != child);

	/*
	 *	And return whatever was decided.
	 */
	return myresult;
}

int modcall(int component, modcallable *c, REQUEST *request)
{
	int myresult;

	/*
	 *	A module has taken too long to process the request,
	 *	and we've been told to stop processing it.
	 */
	if (request->options & RAD_REQUEST_OPTION_STOP_NOW) {
		return RLM_MODULE_FAIL;
	}

	/* Choose a default return value appropriate for the component */
	switch(component) {
	case RLM_COMPONENT_AUTZ:
		myresult = RLM_MODULE_NOTFOUND;
		break;
	case RLM_COMPONENT_AUTH:
		myresult = RLM_MODULE_REJECT;
		break;
	case RLM_COMPONENT_PREACCT:
		myresult = RLM_MODULE_NOOP;
		break;
	case RLM_COMPONENT_ACCT:
		myresult = RLM_MODULE_NOOP;
		break;
	case RLM_COMPONENT_SESS:
		myresult = RLM_MODULE_FAIL;
		break;
	case RLM_COMPONENT_PRE_PROXY:
		myresult = RLM_MODULE_NOOP;
		break;
	case RLM_COMPONENT_POST_PROXY:
		myresult = RLM_MODULE_NOOP;
		break;
	case RLM_COMPONENT_POST_AUTH:
		myresult = RLM_MODULE_NOOP;
		break;
	default:
		myresult = RLM_MODULE_FAIL;
		break;
	}

	if(c == NULL) {
		DEBUG2("modcall[%s]: NULL object returns %s for request %d",
		       comp2str[component],
		       lrad_int2str(rcode_table, myresult, "??"),
		       request->number);
		return myresult;
	}

	switch (c->type) {
	case MOD_LOAD_BALANCE:
		{
			modgroup *g = mod_callabletogroup(c);
			
			DEBUG2("modcall: entering load-balance group %s for request %d",
			       c->name, request->number);
			
			myresult = call_modloadbalance(component, g, request,
						       myresult);
			
			DEBUG2("modcall: load-balance group %s returns %s for request %d",
			       c->name,
			       lrad_int2str(rcode_table, myresult, "??"),
			       request->number);
		}
		break;
		
	case MOD_REDUNDANT_LOAD_BALANCE:
		{
			modgroup *g = mod_callabletogroup(c);
			
			DEBUG2("modcall: entering redundant-load-balance group %s for request %d",
			       c->name, request->number);
			
			myresult = call_modredundantloadbalance(component, g, request,
								myresult);
			
			DEBUG2("modcall: redundant-load-balance group %s returns %s for request %d",
			       c->name,
			       lrad_int2str(rcode_table, myresult, "??"),
			       request->number);
		}
		break;
		
	case MOD_GROUP:
		{
			modgroup *g = mod_callabletogroup(c);
			
			DEBUG2("modcall: entering group %s%s for request %d",
			       lrad_int2str(grouptype_table, g->grouptype, ""),
			       c->name, request->number);
			
			myresult = call_modgroup(component, g, request,
						 myresult);
			
			DEBUG2("modcall: leaving group %s%s (returns %s) for request %d",
			       lrad_int2str(grouptype_table, g->grouptype, ""),
			       c->name,
			       lrad_int2str(rcode_table, myresult, "??"),
			       request->number);
		}
		break;
		
	case MOD_SINGLE:
		{
			modsingle *sp = mod_callabletosingle(c);
			
			myresult = call_modsingle(component, sp, request,
						  myresult);
			
			DEBUG2("  modcall[%s]: module \"%s\" returns %s for request %d",
			       comp2str[component], c->name,
			       lrad_int2str(rcode_table, myresult, "??"),
			       request->number);
		}
		break;

	default:
		radlog(L_ERR, "Internal error processing module entry");
		break;
	}

	return myresult;
}

#if 0
/* If you suspect a bug in the parser, you'll want to use these dump
 * functions. dump_tree should reproduce a whole tree exactly as it was found
 * in radiusd.conf, but in long form (all actions explicitly defined) */
static void dump_mc(modcallable *c, int indent)
{
	int i;

	if(c->type==MOD_SINGLE) {
		modsingle *single = mod_callabletosingle(c);
		DEBUG("%.*s%s {", indent, "\t\t\t\t\t\t\t\t\t\t\t",
			single->modinst->name);
	} else {
		modgroup *g = mod_callabletogroup(c);
		modcallable *p;
		DEBUG("%.*sgroup {", indent, "\t\t\t\t\t\t\t\t\t\t\t");
		for(p = g->children;p;p = p->next)
			dump_mc(p, indent+1);
	}

	for(i = 0; i<RLM_MODULE_NUMCODES; ++i) {
		DEBUG("%.*s%s = %s", indent+1, "\t\t\t\t\t\t\t\t\t\t\t",
		      lrad_int2str(rcode_table, i, "??"),
		      action2str(c->actions[i]));
	}

	DEBUG("%.*s}", indent, "\t\t\t\t\t\t\t\t\t\t\t");
}

static void dump_tree(int comp, modcallable *c)
{
	DEBUG("[%s]", comp2str[comp]);
	dump_mc(c, 0);
}
#else
static void dump_tree(int comp UNUSED, modcallable *c UNUSED)
{
	return;
}
#endif

/* These are the default actions. For each component, the group{} block
 * behaves like the code from the old module_*() function. redundant{} and
 * append{} are based on my guesses of what they will be used for. --Pac. */
static const int
defaultactions[RLM_COMPONENT_COUNT][GROUPTYPE_COUNT][RLM_MODULE_NUMCODES] =
{
	/* authenticate */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			1,			/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			1,			/* noop     */
			1			/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		},
		/* append */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			2,			/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	},
	/* authorize */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			3,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			1,			/* notfound */
			2,			/* noop     */
			4			/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		},
		/* append */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			2,			/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	},
	/* preacct */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			2,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			1,			/* noop     */
			3			/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		},
		/* append */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			2,			/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	},
	/* accounting */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			2,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			1,			/* noop     */
			3			/* updated  */
		},
		/* redundant */
		{
			1,			/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			1,			/* invalid  */
			1,			/* userlock */
			1,			/* notfound */
			2,			/* noop     */
			4			/* updated  */
		},
		/* append */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			2,			/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	},
	/* checksimul */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		},
		/* append */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	},
	/* pre-proxy */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			3,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			1,			/* notfound */
			2,			/* noop     */
			4			/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		},
		/* append */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			2,			/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	},
	/* post-proxy */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			3,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			1,			/* notfound */
			2,			/* noop     */
			4			/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		},
		/* append */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			2,			/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	},
	/* post-auth */
	{
		/* group */
		{
			MOD_ACTION_RETURN,	/* reject   */
			MOD_ACTION_RETURN,	/* fail     */
			3,			/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			1,			/* notfound */
			2,			/* noop     */
			4			/* updated  */
		},
		/* redundant */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			MOD_ACTION_RETURN,	/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		},
		/* append */
		{
			MOD_ACTION_RETURN,	/* reject   */
			1,			/* fail     */
			MOD_ACTION_RETURN,	/* ok       */
			MOD_ACTION_RETURN,	/* handled  */
			MOD_ACTION_RETURN,	/* invalid  */
			MOD_ACTION_RETURN,	/* userlock */
			2,			/* notfound */
			MOD_ACTION_RETURN,	/* noop     */
			MOD_ACTION_RETURN	/* updated  */
		}
	}
};


/*
 *	Compile one entry of a module call.
 */
static modcallable *do_compile_modsingle(int component, CONF_ITEM *ci,
					 const char *filename, int grouptype,
					 const char **modname)
{
	int lineno;
	const char *modrefname;
	modsingle *single;
	modcallable *csingle;
	module_instance_t *this;

	if (cf_item_is_section(ci)) {
		CONF_SECTION *cs = cf_itemtosection(ci);
		const char *name2 = cf_section_name2(cs);

		lineno = cf_section_lineno(cs);
		modrefname = cf_section_name1(cs);
		if (!name2) name2 = "_UnNamedGroup";

		/*
		 *	group{}, redundant{}, or append{} may appear
		 *	where a single module instance was expected.
		 *	In that case, we hand it off to
		 *	compile_modgroup
		 */
		if (strcmp(modrefname, "group") == 0) {
			*modname = name2;
			return do_compile_modgroup(component, cs, filename,
					GROUPTYPE_SIMPLE, grouptype);
		} else if (strcmp(modrefname, "redundant") == 0) {
			*modname = name2;
			return do_compile_modgroup(component, cs, filename,
					GROUPTYPE_REDUNDANT, grouptype);
		} else if (strcmp(modrefname, "append") == 0) {
			*modname = name2;
			return do_compile_modgroup(component, cs, filename,
					GROUPTYPE_APPEND, grouptype);
		} else if (strcmp(modrefname, "load-balance") == 0) {
			*modname = name2;
			csingle= do_compile_modgroup(component, cs, filename,
					GROUPTYPE_SIMPLE, grouptype);
			if (!csingle) return NULL;
			csingle->type = MOD_LOAD_BALANCE;
			return csingle;
		} else if (strcmp(modrefname, "redundant-load-balance") == 0) {
			*modname = name2;
			csingle= do_compile_modgroup(component, cs, filename,
					GROUPTYPE_REDUNDANT, grouptype);
			if (!csingle) return NULL;
			csingle->type = MOD_REDUNDANT_LOAD_BALANCE;
			return csingle;
		}
		/*
		 *	Else it's a module reference, with updated return
		 *	codes.
		 */
	} else {
		CONF_PAIR *cp = cf_itemtopair(ci);
		lineno = cf_pair_lineno(cp);
		modrefname = cf_pair_attr(cp);
	}

	/*
	 *	See if the module is a virtual one.  If so, return that,
	 *	rather than doing anything here.
	 */
	this = find_module_instance(cf_section_find("modules"), modrefname);
	if (!this) {
		CONF_SECTION *cs, *subcs;

		/*
		 *	Then, look for it in the "instantiate" section.
		 */
		if (((subcs = cf_section_find(NULL)) != NULL) &&
		    ((cs = cf_section_sub_find_name2(subcs, "instantiate", NULL)) != NULL)) {
			subcs = cf_section_sub_find_name2(cs, NULL, modrefname);
			if (subcs) {
				/*
				 *	As it's sole configuration, the
				 *	virtual module takes a section which
				 *	contains the 
				 */
				return do_compile_modsingle(component,
							    cf_sectiontoitem(subcs),
							    filename,
							    grouptype,
							    modname);
			}
		}
	}
	if (!this) {
		*modname = NULL;
		radlog(L_ERR|L_CONS, "%s[%d] Unknown module \"%s\".", filename,
		       lineno, modrefname);
		return NULL;
	}

	/*
	 *	We know it's all OK, allocate the structures, and fill
	 *	them in.
	 */
	single = rad_malloc(sizeof(*single));
	csingle = mod_singletocallable(single);
	csingle->next = NULL;
	memcpy(csingle->actions, defaultactions[component][grouptype],
	       sizeof csingle->actions);
	rad_assert(modrefname != NULL);
	csingle->name = modrefname;
	csingle->type = MOD_SINGLE;

	/*
	 *	Singles can override the actions, virtual modules cannot.
	 *
	 *	FIXME: We may want to re-visit how to do this...
	 *	maybe a csingle as a ref?
	 */
	if (cf_item_is_section(ci)) {
		CONF_SECTION *cs = cf_itemtosection(ci);
		CONF_PAIR *cp;
		const char *attr, *value;

		for (ci=cf_item_find_next(cs, NULL);
		     ci != NULL;
		     ci=cf_item_find_next(cs, ci)) {

			if (cf_item_is_section(ci)) {
				radlog(L_ERR|L_CONS,
				       "%s[%d] Subsection of module instance call "
				       "not allowed\n", filename,
				       cf_section_lineno(cf_itemtosection(ci)));
				modcallable_free(&csingle);
				return NULL;
			}

			cp = cf_itemtopair(ci);
			attr = cf_pair_attr(cp);
			value = cf_pair_value(cp);
			lineno = cf_pair_lineno(cp);

			if (!compile_action(csingle, attr, value, filename,
					    lineno)) {
				modcallable_free(&csingle);
				return NULL;
			}
		}
	}

	/*
	 *	Bail out if the module in question does not supply the
	 *	wanted component
	 */
	if (!this->entry->module->methods[component]) {
		radlog(L_ERR|L_CONS,
		       "%s[%d]: \"%s\" modules aren't allowed in '%s' sections -- they have no such method.",
		       filename, lineno, this->entry->module->name,
		       comp2str[component]);
		modcallable_free(&csingle);
		return NULL;
	}

	single->modinst = this;
	*modname = this->entry->module->name;
	return csingle;
}

modcallable *compile_modsingle(int component, CONF_ITEM *ci,
			       const char *filename, const char **modname)
{
	modcallable *ret = do_compile_modsingle(component, ci, filename,
						GROUPTYPE_SIMPLE,
						modname);
	dump_tree(component, ret);
	return ret;
}


/*
 *	Internal compile group code.
 */
static modcallable *do_compile_modgroup(int component, CONF_SECTION *cs,
					const char *filename, int grouptype,
					int parentgrouptype)
{
	modgroup *g;
	modcallable *c;
	CONF_ITEM *ci;

	g = rad_malloc(sizeof(*g));
	g->grouptype = grouptype;

	c = mod_grouptocallable(g);
	c->next = NULL;
	memcpy(c->actions, defaultactions[component][parentgrouptype],
	       sizeof(c->actions));

	/*
	 *	Remember the name for printing, etc.
	 *
	 *	FIXME: We may also want to put the names into a
	 *	rbtree, so that groups can reference each other...
	 */
	c->name = cf_section_name2(cs);
	if (!c->name) c->name = "";
	c->type = MOD_GROUP;
	g->children = NULL;

	/*
	 *	Loop over the children of this group.
	 */
	for (ci=cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci=cf_item_find_next(cs, ci)) {

		/*
		 *	Sections are references to other groups, or
		 *	to modules with updated return codes.
		 */
		if (cf_item_is_section(ci)) {
			const char *junk = NULL;
			modcallable *single;
			int lineno;
			CONF_SECTION *subcs = cf_itemtosection(ci);

			lineno = cf_section_lineno(subcs);

			single = do_compile_modsingle(component, ci, filename,
						      grouptype, &junk);
			if (!single) {
				radlog(L_ERR|L_CONS,
				       "%s[%d] Failed to parse \"%s\" subsection.\n",
				       filename, lineno,
				       cf_section_name1(subcs));
				modcallable_free(&c);
				return NULL;
			}
			add_child(g, single);

		} else {
			const char *attr, *value;
			CONF_PAIR *cp = cf_itemtopair(ci);
			int lineno;

			attr = cf_pair_attr(cp);
			value = cf_pair_value(cp);
			lineno = cf_pair_lineno(cp);

			/*
			 *	A CONF_PAIR is either a module
			 *	instance with no actions
			 *	specified ...
			 */
			if (value[0] == 0) {
				modcallable *single;
				const char *junk = NULL;

				single = do_compile_modsingle(component,
						cf_pairtoitem(cp), filename,
						grouptype, &junk);
				if (!single) {
					radlog(L_ERR|L_CONS,
					       "%s[%d] Failed to parse \"%s\" entry.\n",
					       filename, lineno, attr);
					modcallable_free(&c);
					return NULL;
				}
				add_child(g, single);

				/*
				 *	Or a module instance with action.
				 */
			} else if (!compile_action(c, attr, value, filename,
						   lineno)) {
				modcallable_free(&c);
				return NULL;
			} /* else it worked */
		}
	}

	/*
	 *	FIXME: If there are no children, return NULL?
	 */
	return mod_grouptocallable(g);
}

modcallable *compile_modgroup(int component, CONF_SECTION *cs,
			      const char *filename)
{
	modcallable *ret = do_compile_modgroup(component, cs, filename,
					       GROUPTYPE_SIMPLE,
					       GROUPTYPE_SIMPLE);
	dump_tree(component, ret);
	return ret;
}

void add_to_modcallable(modcallable **parent, modcallable *this,
			int component, const char *name)
{
	modgroup *g;
	
	rad_assert(this != NULL);

	if (*parent == NULL) {
		modcallable *c;

		g = rad_malloc(sizeof *g);
		g->grouptype = GROUPTYPE_SIMPLE;
		c = mod_grouptocallable(g);
		c->next = NULL;
		memcpy(c->actions,
		       defaultactions[component][GROUPTYPE_SIMPLE],
		       sizeof(c->actions));
		rad_assert(name != NULL);
		c->name = name;
		c->type = MOD_GROUP;
		g->children = NULL;

		*parent = mod_grouptocallable(g);
	} else {
		g = mod_callabletogroup(*parent);
	}

	add_child(g, this);
}

void modcallable_free(modcallable **pc)
{
	modcallable *c, *loop, *next;
	c = *pc;
	if(c->type==MOD_GROUP) {
		for(loop = mod_callabletogroup(c)->children;
		    loop ;
		    loop = next) {
			next = loop->next;
			modcallable_free(&loop);
		}
	}
	free(c);
	*pc = NULL;
}
