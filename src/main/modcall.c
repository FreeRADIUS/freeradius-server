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

#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include "radiusd.h"
#include "conffile.h"
#include "modpriv.h"
#include "modules.h"
#include "modcall.h"

/* Actions may be a positive integer (the highest one returned in the group
 * will be returned), or the keyword "return", represented here by
 * MOD_ACTION_RETURN, to cause an immediate return. */
#define MOD_ACTION_RETURN (-1)

/* Here are our basic types: modcallable, modgroup, and modsingle. For an
 * explanation of what they are all about, see ../../doc/README.failover */
struct modcallable {
	struct modcallable *next;
	int actions[RLM_MODULE_NUMCODES];
	int lineno;
	enum { MOD_SINGLE, MOD_GROUP } type;
};

typedef struct {
	modcallable mc;
	modcallable *children;
} modgroup;

typedef struct {
	modcallable mc;
	module_instance_t *modinst;
} modsingle;

/* Simple conversions: modsingle and modgroup are subclasses of modcallable,
 * so we often want to go back and forth between them. */
static modsingle *mod_callabletosingle(modcallable *p)
{
	assert(p->type==MOD_SINGLE);
	return (modsingle *)p;
}
static modgroup *mod_callabletogroup(modcallable *p)
{
	assert(p->type==MOD_GROUP);
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

	while (node) {
		last = &node->next;
		node = node->next;
	}

	assert(c->next == NULL);
	*last = c;
}

/* Here's where we recognize all of our keywords: first the rcodes, then the
 * actions */
static int str2rcode(const char *s, const char *filename, int lineno)
{
	if(!strcasecmp(s, "reject"))
		return RLM_MODULE_REJECT;
	else if(!strcasecmp(s, "fail"))
		return RLM_MODULE_FAIL;
	else if(!strcasecmp(s, "ok"))
		return RLM_MODULE_OK;
	else if(!strcasecmp(s, "handled"))
		return RLM_MODULE_HANDLED;
	else if(!strcasecmp(s, "invalid"))
		return RLM_MODULE_INVALID;
	else if(!strcasecmp(s, "userlock"))
		return RLM_MODULE_USERLOCK;
	else if(!strcasecmp(s, "notfound"))
		return RLM_MODULE_NOTFOUND;
	else if(!strcasecmp(s, "noop"))
		return RLM_MODULE_NOOP;
	else if(!strcasecmp(s, "updated"))
		return RLM_MODULE_UPDATED;
	else {
		radlog(L_ERR|L_CONS,
			"%s[%d] Unknown module rcode '%s'.\n",
			filename, lineno, s);
		exit(1);
	}
}

static const char *rcode2str[] = {
	"reject",
	"fail",
	"ok",
	"handled",
	"invalid",
	"userlock",
	"notfound",
	"noop",
	"updated"
};

static int str2action(const char *s, const char *filename, int lineno)
{
	if(!strcasecmp(s, "return"))
		return MOD_ACTION_RETURN;
	else if(strspn(s, "0123456789")==strlen(s))
		return atoi(s);
	else {
		radlog(L_ERR|L_CONS,
			"%s[%d] Unknown action '%s'.\n",
			filename, lineno, s);
		exit(1);
	}
}

static const char *action2str(int action)
{
	static char buf[32];
	if(action==MOD_ACTION_RETURN)
		return "return";
	snprintf(buf, sizeof buf, "%d", action);
	return buf;
}

/* Some short names for debugging output */
static const char *comp2str[] = {
	"auth",
	"autz",
	"preacct",
	"acct",
	"sess"
};

#if HAVE_PTHREAD_H
/*
 *	Lock the mutex for the module
 */
static void safe_lock(module_instance_t *instance)
{
	if (instance->mutex) pthread_mutex_lock(instance->mutex);
}

/*
 *	Unlock the mutex for the module
 */
static void safe_unlock(module_instance_t *instance)
{
	if (instance->mutex) pthread_mutex_unlock(instance->mutex);
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

	safe_lock(sp->modinst);
	switch(component) {
	case RLM_COMPONENT_AUTZ:
		myresult = sp->modinst->entry->module->authorize(
				    sp->modinst->insthandle, request);
		break;
	case RLM_COMPONENT_AUTH:
		myresult = sp->modinst->entry->module->authenticate(
				    sp->modinst->insthandle, request);
		break;
	case RLM_COMPONENT_PREACCT:
		myresult = sp->modinst->entry->module->preaccounting(
				    sp->modinst->insthandle, request);
		break;
	case RLM_COMPONENT_ACCT:
		myresult = sp->modinst->entry->module->accounting(
				    sp->modinst->insthandle, request);
		break;
	case RLM_COMPONENT_SESS:
		myresult = sp->modinst->entry->module->checksimul(
				    sp->modinst->insthandle, request);
		break;
	}
	safe_unlock(sp->modinst);

	return myresult;
}

static int call_modgroup(int component, modgroup *g, REQUEST *request,
			 int default_result)
{
	int myresult = default_result;
	int myresultpref;
	modcallable *p;

	/* Assign the lowest possible preference to the default return code */
	myresultpref = 0;

	/* Loop over the children */
	for(p = g->children; p; p = p->next) {
		int r = RLM_MODULE_FAIL;

		/* Call this child by recursing into modcall */
		r = modcall(component, p, request);

		DEBUG2("modcall[%s]: action for %s is %s",
			comp2str[component], rcode2str[r],
			action2str(p->actions[r]));

		/* Find an action to go with the child's result. If "return",
		 * break out of the loop so the rest of the children in the
		 * list will be skipped. */
		if(p->actions[r] == MOD_ACTION_RETURN) {
			myresult = r;
			break;
		}

		/* Otherwise, the action is a number, the preference level of
		 * this return code. If no higher preference has been seen
		 * yet, remember this one. */
		if(p->actions[r] >= myresultpref) {
			myresult = r;
			myresultpref = p->actions[r];
		}
	}

	return myresult;
}

int modcall(int component, modcallable *c, REQUEST *request)
{
	int myresult;

	/* Choose a default return value appropriate for the component */
	switch(component) {
		case RLM_COMPONENT_AUTZ:   myresult = RLM_MODULE_NOTFOUND;break;
		case RLM_COMPONENT_AUTH:   myresult = RLM_MODULE_REJECT;  break;
		case RLM_COMPONENT_PREACCT:myresult = RLM_MODULE_NOOP;    break;
		case RLM_COMPONENT_ACCT:   myresult = RLM_MODULE_NOOP;    break;
		case RLM_COMPONENT_SESS:   myresult = RLM_MODULE_FAIL;    break;
		default: myresult = RLM_MODULE_FAIL;
	}

	if(!c) {
	  DEBUG2("modcall[%s]: Null object returns %s",
		comp2str[component], rcode2str[myresult]);
	  return myresult;
	}

	if(c->type==MOD_GROUP) {
		modgroup *g = mod_callabletogroup(c);

		DEBUG2("modcall[%s]: Entering group at line %d",
			comp2str[component], c->lineno);

		myresult = call_modgroup(component, g, request, myresult);

		DEBUG2("modcall[%s]: Group at line %d returns %s",
			comp2str[component], c->lineno, rcode2str[myresult]);
	} else {
		modsingle *sp = mod_callabletosingle(c);

		myresult = call_modsingle(component, sp, request, myresult);

		DEBUG2("modcall[%s]: Module at line %d returns %s",
			 comp2str[component], c->lineno, rcode2str[myresult]);
	}

	return myresult;
}

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
			rcode2str[i], action2str(c->actions[i]));
	}

	DEBUG("%.*s}", indent, "\t\t\t\t\t\t\t\t\t\t\t");
}

static void dump_tree(int comp, modcallable *c)
{
	DEBUG("[%s]", comp2str[comp]);
	dump_mc(c, 0);
}

#define GROUPTYPE_SIMPLEGROUP 0
#define GROUPTYPE_REDUNDANT 1
#define GROUPTYPE_APPEND 2
#define GROUPTYPE_COUNT 3

/* These are the default actions. For each component, the group{} block
 * behaves like the code from the old module_*() function. redundant{} and
 * append{} are based on my guesses of what they will be used for. --Pac. */
static int
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
			3,			/* ok       */
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
	}
};

/* Bail out if the module in question does not supply the wanted component */
static void sanity_check(int component, module_instance_t *inst, int lineno,
			 const char *filename)
{
	switch (component) {
		case RLM_COMPONENT_AUTH:
			if (!inst->entry->module->authenticate) {
				radlog(L_ERR|L_CONS,
					"%s[%d] Module %s does not contain "
					"an 'authenticate' entry\n",
					filename, lineno,
					inst->entry->module->name);
				exit(1);
			}
			break;
		case RLM_COMPONENT_AUTZ:
			if (!inst->entry->module->authorize) {
				radlog(L_ERR|L_CONS,
					"%s[%d] Module %s does not contain "
					"an 'authorize' entry\n",
					filename, lineno,
					inst->entry->module->name);
				exit(1);
			}
			break;
		case RLM_COMPONENT_PREACCT:
			if (!inst->entry->module->preaccounting) {
				radlog(L_ERR|L_CONS,
					"%s[%d] Module %s does not contain "
					"a 'preacct' entry\n",
					filename, lineno,
					inst->entry->module->name);
				exit(1);
			}
			break;
		case RLM_COMPONENT_ACCT:
			if (!inst->entry->module->accounting) {
				radlog(L_ERR|L_CONS,
					"%s[%d] Module %s does not contain "
					"an 'accounting' entry\n",
					filename, lineno,
					inst->entry->module->name);
				exit(1);
			}
			break;
		case RLM_COMPONENT_SESS:
			if (!inst->entry->module->checksimul) {
				radlog(L_ERR|L_CONS,
					"%s[%d] Module %s does not contain "
					"a 'checksimul' entry\n",
					filename, lineno,
					inst->entry->module->name);
				exit(1);
			}
			break;
		default:
			radlog(L_ERR|L_CONS, "%s[%d] Unknown component %d.\n",
			       filename, lineno, component);
			exit(1);
	}
}

/* Parse a CONF_SECTION containing only result=action pairs */
static void override_actions(modcallable *c, CONF_SECTION *cs,
			     const char *filename)
{
	CONF_ITEM *ci;
	CONF_PAIR *cp;
	const char *attr, *value;
	int lineno, rcode, action;

	for(ci=cf_item_find_next(cs, NULL); ci; ci=cf_item_find_next(cs, ci)) {
		if(cf_item_is_section(ci)) {
			radlog(L_ERR|L_CONS,
				"%s[%d] Subsection of module instance call "
				"not allowed\n", filename,
				cf_section_lineno(cf_itemtosection(ci)));
			exit(1);
		}
		cp = cf_itemtopair(ci);
		attr = cf_pair_attr(cp);
		value = cf_pair_value(cp);
		lineno = cf_pair_lineno(cp);
		rcode = str2rcode(attr, filename, lineno);
		action = str2action(value, filename, lineno);
		c->actions[rcode] = action;
	}
}

static modcallable *do_compile_modsingle(int component, CONF_ITEM *ci,
					 const char *filename, int grouptype,
					 char **modname)
{
	int lineno;
	const char *modrefname;
	modsingle *single;
	modcallable *csingle;
	module_instance_t *this;

	if(cf_item_is_section(ci)) {
		CONF_SECTION *cs = cf_itemtosection(ci);
		lineno = cf_section_lineno(cs);
		modrefname = cf_section_name1(cs);
	} else {
		CONF_PAIR *cp = cf_itemtopair(ci);
		lineno = cf_pair_lineno(cp);
		modrefname = cf_pair_attr(cp);
	}

	single = rad_malloc(sizeof *single);
	csingle = mod_singletocallable(single);
	csingle->next = NULL;
	memcpy(csingle->actions,
		defaultactions[component][grouptype],
		sizeof csingle->actions);
	csingle->lineno = lineno;
	csingle->type = MOD_SINGLE;

	if(cf_item_is_section(ci)) {
		/* override default actions with what's in the CONF_SECTION */
		override_actions(csingle, cf_itemtosection(ci), filename);
	}

	this = find_module_instance(modrefname);
	if (this == NULL) {
		exit(1); /* FIXME */
	}

	sanity_check(component, this, csingle->lineno, filename);

	single->modinst = this;
	*modname = this->entry->name;
	return csingle;
}

modcallable *compile_modsingle(int component, CONF_ITEM *ci,
			       const char *filename, char **modname)
{
	return do_compile_modsingle(component, ci, filename,
				    GROUPTYPE_SIMPLEGROUP, modname);
}

static modcallable *do_compile_modgroup(int component, CONF_SECTION *cs,
				        const char *filename, int grouptype,
				        int parentgrouptype)
{
	modgroup *g;
	modcallable *c;
	CONF_ITEM *ci;

	g = rad_malloc(sizeof *g);

	c = mod_grouptocallable(g);
	c->next = NULL;
	memcpy(c->actions, defaultactions[component][parentgrouptype],
		sizeof c->actions);
	c->lineno = cf_section_lineno(cs);
	c->type = MOD_GROUP;
	g->children = NULL;

	for(ci=cf_item_find_next(cs, NULL); ci; ci=cf_item_find_next(cs, ci)) {
		if(cf_item_is_section(ci)) {
			CONF_SECTION *scs = cf_itemtosection(ci);
			const char *name1;
			modcallable *childgroup;

			name1 = cf_section_name1(scs);

			/* subsections may be group{}, redundant{}, or
			 * append{}... */
			if(!strcmp(name1, "group")) {
				childgroup = do_compile_modgroup(component,
					scs, filename, GROUPTYPE_SIMPLEGROUP,
					grouptype);
				add_child(g, childgroup);
			} else if(!strcmp(name1, "redundant")) {
				childgroup = do_compile_modgroup(component,
					scs, filename, GROUPTYPE_REDUNDANT,
					grouptype);
				add_child(g, childgroup);
			} else if(!strcmp(name1, "append")) {
				childgroup = do_compile_modgroup(component,
					scs, filename, GROUPTYPE_APPEND,
					grouptype);
				add_child(g, childgroup);
			} else {
				/* ...or a module instance with some actions
				 * specified. */
				modcallable *single;
				char *junk;

				single = do_compile_modsingle(component,
						cf_sectiontoitem(scs), filename,
						grouptype, &junk);
				add_child(g, single);
			}
		} else {
			const char *attr, *value;
			CONF_PAIR *cp = cf_itemtopair(ci);
			int lineno;

			attr = cf_pair_attr(cp);
			value = cf_pair_value(cp);
			lineno = cf_pair_lineno(cp);

			/* A CONF_PAIR is either a module instance with no
			 * actions specified... */
			if(value[0]==0) {
				modcallable *single;
				char *junk;

				single = do_compile_modsingle(component,
					cf_pairtoitem(cp), filename,
					grouptype, &junk);
				add_child(g, single);
			} else {
				/* ...or an action to be applied to this
				 * group. */
				int rcode, action;
				rcode = str2rcode(attr, filename, lineno);
				action = str2action(value, filename, lineno);

				c->actions[rcode] = action;
			}
		}
	}
	return mod_grouptocallable(g);
}

modcallable *compile_modgroup(int component, CONF_SECTION *cs,
			      const char *filename)
{
	modcallable *ret = do_compile_modgroup(component, cs, filename,
						GROUPTYPE_SIMPLEGROUP,
						GROUPTYPE_SIMPLEGROUP);
	/*dump_tree(component, ret);*/
	return ret;
}

void add_to_modcallable(modcallable **parent, modcallable *this,
			int component, int lineno)
{
	modgroup *g;

	if(!*parent) {
		modcallable *c;

		g = rad_malloc(sizeof *g);
		c = mod_grouptocallable(g);
		c->next = NULL;
		memcpy(c->actions,
			defaultactions[component][GROUPTYPE_SIMPLEGROUP],
			sizeof c->actions);
		c->lineno = lineno;
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
		for(loop=mod_callabletogroup(c)->children ; loop ; loop=next) {
			next = loop->next;
			modcallable_free(&loop);
		}
	}
	free(c);
	*pc = NULL;
}
