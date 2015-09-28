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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2000,2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/modcall.h>
#include <freeradius-devel/rad_assert.h>

extern int radius_get_vp(REQUEST *request, const char *name, VALUE_PAIR **vp_p);

/* mutually-recursive static functions need a prototype up front */
static modcallable *do_compile_modgroup(modcallable *,
					int, CONF_SECTION *,
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
	modcallable *parent;
	struct modcallable *next;
	const char *name;
	enum { MOD_SINGLE = 1, MOD_GROUP, MOD_LOAD_BALANCE, MOD_REDUNDANT_LOAD_BALANCE,
#ifdef WITH_UNLANG
	       MOD_IF, MOD_ELSE, MOD_ELSIF, MOD_UPDATE, MOD_SWITCH, MOD_CASE,
#endif
	       MOD_POLICY, MOD_REFERENCE, MOD_XLAT } type;
	int method;
	int actions[RLM_MODULE_NUMCODES];
};

#define GROUPTYPE_SIMPLE	0
#define GROUPTYPE_REDUNDANT	1
#define GROUPTYPE_APPEND	2
#define GROUPTYPE_COUNT		3

typedef struct {
	modcallable mc;		/* self */
	int grouptype;	/* after mc */
	modcallable *children;
	CONF_SECTION *cs;
	VALUE_PAIR *vps;
} modgroup;

typedef struct {
	modcallable mc;
	module_instance_t *modinst;
} modsingle;

typedef struct {
	modcallable mc;
	const char *ref_name;
	CONF_SECTION *ref_cs;
} modref;

typedef struct {
	modcallable mc;
	int exec;
	char *xlat_name;
} modxlat;

static const FR_NAME_NUMBER grouptype_table[] = {
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
	rad_assert((p->type > MOD_SINGLE) && (p->type <= MOD_POLICY));

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

static modref *mod_callabletoref(modcallable *p)
{
	rad_assert(p->type==MOD_REFERENCE);
	return (modref *)p;
}
static modcallable *mod_reftocallable(modref *p)
{
	return (modcallable *)p;
}

static modxlat *mod_callabletoxlat(modcallable *p)
{
	rad_assert(p->type==MOD_XLAT);
	return (modxlat *)p;
}
static modcallable *mod_xlattocallable(modxlat *p)
{
	return (modcallable *)p;
}

/* modgroups are grown by adding a modcallable to the end */
/* FIXME: This is O(N^2) */
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
	c->parent = mod_grouptocallable(g);
}

/* Here's where we recognize all of our keywords: first the rcodes, then the
 * actions */
static const FR_NAME_NUMBER rcode_table[] = {
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
static int compile_action(modcallable *c, CONF_PAIR *cp)
{
	int action;
	const char *attr, *value;

	attr = cf_pair_attr(cp);
	value = cf_pair_value(cp);
	if (!value) return 0;

	if (!strcasecmp(value, "return"))
		action = MOD_ACTION_RETURN;

	else if (!strcasecmp(value, "break"))
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
		cf_log_err(cf_pairtoitem(cp), "Unknown action '%s'.\n",
			   value);
		return 0;
	}

	if (strcasecmp(attr, "default") != 0) {
		int rcode;

		rcode = fr_str2int(rcode_table, attr, -1);
		if (rcode < 0) {
			cf_log_err(cf_pairtoitem(cp),
				   "Unknown module rcode '%s'.\n",
				   attr);
			return 0;
		}
		c->actions[rcode] = action;

	} else {		/* set all unset values to the default */
		int i;

		for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
			if (!c->actions[i]) c->actions[i] = action;
		}
	}

	return 1;
}

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
#ifdef WITH_COA
	,
	"recv-coa",
	"send-coa"
#endif
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

static int call_modsingle(int component, modsingle *sp, REQUEST *request)
{
	int myresult;
	int blocked;

	rad_assert(request != NULL);

	/*
	 *	If the request should stop, refuse to do anything.
	 */
	blocked = (request->master_state == REQUEST_STOP_PROCESSING);
	if (blocked) return RLM_MODULE_NOOP;

	RDEBUG3("  modsingle[%s]: calling %s (%s) for request %d",
	       comp2str[component], sp->modinst->name,
	       sp->modinst->entry->name, request->number);

	if (sp->modinst->force) {
		myresult = sp->modinst->code;
		goto fail;
	}

	safe_lock(sp->modinst);

	/*
	 *	For logging unresponsive children.
	 */
	request->module = sp->modinst->name;

	myresult = sp->modinst->entry->module->methods[component](
			sp->modinst->insthandle, request);

	request->module = "";
	safe_unlock(sp->modinst);

	/*
	 *	Wasn't blocked, and now is.  Complain!
	 */
	blocked = (request->master_state == REQUEST_STOP_PROCESSING);
	if (blocked) {
		radlog(L_INFO, "WARNING: Module %s became unblocked for request %u",
		       sp->modinst->entry->name, request->number);
	}

 fail:
	RDEBUG3("  modsingle[%s]: returned from %s (%s) for request %d",
	       comp2str[component], sp->modinst->name,
	       sp->modinst->entry->name, request->number);

	return myresult;
}


static int default_component_results[RLM_COMPONENT_COUNT] = {
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


static const char *group_name[] = {
	"",
	"single",
	"group",
	"load-balance group",
	"redundant-load-balance group",
#ifdef WITH_UNLANG
	"if",
	"else",
	"elsif",
	"update",
	"switch",
	"case",
#endif
	"policy"
};

/* Here's where we recognize all of our keywords: first the rcodes, then the
 * actions */
const FR_NAME_NUMBER mod_rcode_table[] = {
	{ "reject",     RLM_MODULE_REJECT       },
	{ "fail",       RLM_MODULE_FAIL	 },
	{ "ok",	 	RLM_MODULE_OK	   },
	{ "handled",    RLM_MODULE_HANDLED      },
	{ "invalid",    RLM_MODULE_INVALID      },
	{ "userlock",   RLM_MODULE_USERLOCK     },
	{ "notfound",   RLM_MODULE_NOTFOUND     },
	{ "noop",       RLM_MODULE_NOOP	 },
	{ "updated",    RLM_MODULE_UPDATED      },
	{ NULL, 0 }
};

static const char *modcall_spaces = "++++++++++++++++++++++++++++++++";

#define MODCALL_STACK_MAX (32)

#define MOD_LOG_OPEN_BRACE(_name) RDEBUG2("%.*s%s %s {", depth + 1, modcall_spaces, _name, c->name)
#define MOD_LOG_CLOSE_BRACE() RDEBUG2("%.*s} # %s %s = %s", depth + 1, modcall_spaces, \
				      group_name[c->type], c->name ? c->name : "", \
				      fr_int2str(mod_rcode_table, result, "<invalid>"))

/*
 *	Don't call the modules recursively.  Instead, do them
 *	iteratively, and manage the call stack ourselves.
 */
typedef struct modcall_stack_entry_t {
	int result;
	int priority;
	modcallable *c;
} modcall_stack_entry_t;


static int modcall_recurse(REQUEST *request, int component, int depth,
			   modcall_stack_entry_t *entry, int do_next_sibling);

/*
 *	Call a child of a block.
 */
static void modcall_child(REQUEST *request, int component, int depth,
			  modcall_stack_entry_t *entry, modcallable *c,
			  int *result, int do_next_sibling)
{
	modcall_stack_entry_t *next;

	if (depth >= MODCALL_STACK_MAX) {
		radlog(L_ERR, "Internal sanity check failed: module stack is too deep");
		exit(1);
	}

	/*
	 *	Initialize the childs stack frame.
	 */
	next = entry + 1;
	next->c = c;
	next->result = entry->result;
	next->priority = 0;

	if (!modcall_recurse(request, component,
			     depth, next, do_next_sibling)) {
		*result = RLM_MODULE_FAIL;
		 return;
	}

	*result = next->result;

	return;
}

/*
 *	Interpret the various types of blocks.
 */
static int modcall_recurse(REQUEST *request, int component, int depth,
			   modcall_stack_entry_t *entry, int do_next_sibling)
{
	int if_taken, was_if;
	modcallable *c;
	int result, priority;

	was_if = if_taken = FALSE;
	result = RLM_MODULE_FAIL;

redo:
	priority = -1;
	c = entry->c;

	/*
	 *	Nothing more to do.  Return the code and priority
	 *	which was set by the caller.
	 */
	if (!c) return TRUE;

	/*
	 *	We've been asked to stop.  Do so.
	 */
	if ((request->master_state == REQUEST_STOP_PROCESSING) ||
	    (request->parent &&
	     (request->parent->master_state == REQUEST_STOP_PROCESSING))) {
		entry->result = RLM_MODULE_FAIL;
		entry->priority = 9999;
		return TRUE;
	}

	/*
	 *	Handle "if" conditions.
	 */
	if (c->type == MOD_IF) {
		int condition;
		modgroup *g;
		const char *p;

	mod_if:
		g = mod_callabletogroup(c);
		p = c->name;

		RDEBUG2("%.*s? %s %s", depth + 1, modcall_spaces,
			group_name[c->type], c->name);

		if (radius_evaluate_condition(request, result,
					      0, &p, TRUE, &condition)) {
			RDEBUG2("%.*s? %s %s -> %s", depth + 1, modcall_spaces,
				group_name[c->type],
				c->name, condition ? "TRUE" : "FALSE");
		} else {
			condition = FALSE;
		}

		/*
		 *	Didn't pass.  Remember that.
		 */
		if (!condition) {
			was_if = TRUE;
			if_taken = FALSE;
			goto next_sibling;
		}

		/*
		 *	We took the "if".  Go recurse into its' children.
		 */
		was_if = TRUE;
		if_taken = TRUE;
		goto do_children;
	} /* MOD_IF */

	/*
	 *	"else" if the previous "if" was taken.
	 *	"if" if the previous if wasn't taken.
	 */
	if (c->type == MOD_ELSIF) {
		if (!was_if) goto elsif_error;

		/*
		 *	Like MOD_ELSE, but allow for a later "else"
		 */
		if (if_taken) {
			RDEBUG2("%.*s ... skipping %s for request %d: Preceding \"if\" was taken",
				depth + 1, modcall_spaces,
				group_name[c->type], request->number);
			was_if = TRUE;
			if_taken = TRUE;
			goto next_sibling;
		}

		/*
		 *	Check the "if" condition.
		 */
		goto mod_if;
	} /* MOD_ELSIF */

	/*
	 *	"else" for a preceding "if".
	 */
	if (c->type == MOD_ELSE) {
		if (!was_if) { /* error */
		elsif_error:
			RDEBUG2("%.*s ... skipping %s for request %d: No preceding \"if\"",
				depth + 1, modcall_spaces,
				group_name[c->type], request->number);			
			goto next_sibling;
		}

		if (if_taken) {
			RDEBUG2("%.*s ... skipping %s for request %d: Preceding \"if\" was taken",
				depth + 1, modcall_spaces,
				group_name[c->type], request->number);
			was_if = FALSE;
			if_taken = FALSE;
			goto next_sibling;
		}

		/*
		 *	We need to process it.  Go do that.
		 */
		was_if = FALSE;
		if_taken = FALSE;
		goto do_children;
	} /* MOD_ELSE */

	/*
	 *	We're no longer processing if/else/elsif.  Reset the
	 *	trackers for those conditions.
	 */
	was_if = FALSE;
	if_taken = FALSE;

	if (c->type == MOD_SINGLE) {
		modsingle *sp;

		/*
		 *	Process a stand-alone child, and fall through
		 *	to dealing with it's parent.
		 */
		sp = mod_callabletosingle(c);
	
		result = call_modsingle(c->method, sp, request);
		RDEBUG2("%.*s[%s] = %s", depth + 1, modcall_spaces, c->name ? c->name : "",
			fr_int2str(mod_rcode_table, result, "<invalid>"));
		goto calculate_result;
	} /* MOD_SINGLE */

	/*
	 *	Update attribute(s)
	 */
	if (c->type == MOD_UPDATE) {
		int rcode;
		modgroup *g = mod_callabletogroup(c);

		MOD_LOG_OPEN_BRACE("update");
		rcode = radius_update_attrlist(request, g->cs,
					       g->vps, c->name);
		if (rcode != RLM_MODULE_UPDATED) {
			result = rcode;
		} else {
			result = RLM_MODULE_NOOP;
		}
		MOD_LOG_CLOSE_BRACE();
		goto calculate_result;
	} /* MOD_IF */

	/*
	 *	Child is a group that has children of it's own.
	 */
	if ((c->type == MOD_GROUP) || (c->type == MOD_POLICY) ||
	    (c->type == MOD_CASE)) {
		modgroup *g;

	do_children:
		g = mod_callabletogroup(c);

		/*
		 *	This should really have been caught in the
		 *	compiler, and the node never generated.  But
		 *	doing that requires changing it's API so that
		 *	it returns a flag instead of the compiled
		 *	MOD_GROUP.
		 */
		if (!g->children) {
			if (c->type == MOD_CASE) {
				result = RLM_MODULE_NOOP;
				goto calculate_result;
			}

			RDEBUG2("%.*s%s %s { ... } # empty sub-section is ignored",
				depth + 1, modcall_spaces, group_name[c->type], c->name);
			goto next_sibling;
		}

		MOD_LOG_OPEN_BRACE(group_name[c->type]);
		modcall_child(request, component,
			      depth + 1, entry, g->children,
			      &result, TRUE);
		MOD_LOG_CLOSE_BRACE();
		goto calculate_result;
	} /* MOD_GROUP */

	if (c->type == MOD_SWITCH) {
		modcallable *this, *found, *null_case;
		modgroup *g;
		char buffer[1024];

		MOD_LOG_OPEN_BRACE("switch");

		/*
		 *	If there's no %, it refers to an attribute.
		 *	Otherwise, expand it.
		 */
		if (!strchr(c->name, '%')) {
			VALUE_PAIR *vp = NULL;

			if (radius_get_vp(request, c->name, &vp) && vp) {
				vp_prints_value(buffer,
						sizeof(buffer),
						vp, 0);
			} else {
				*buffer = '\0';
			}
		} else {
			radius_xlat(buffer, sizeof(buffer),
				    c->name, request, NULL);
		}

		/*
		 *	Find either the exact matching name, or the
		 *	"case {...}" statement.
		 */
		g = mod_callabletogroup(c);
		null_case = found = NULL;
		for (this = g->children; this; this = this->next) {
			if (!this->name) {
				if (!null_case) null_case = this;
				continue;
			}
			if (strcmp(buffer, this->name) == 0) {
				found = this;
				break;
			}
		}
		
		if (!found) found = null_case;
		
		MOD_LOG_OPEN_BRACE(group_name[c->type]);
		modcall_child(request, component,
			      depth + 1, entry, found,
			      &result, TRUE);
		MOD_LOG_CLOSE_BRACE();
		goto calculate_result;
	} /* MOD_SWITCH */

	if ((c->type == MOD_LOAD_BALANCE) ||
	    (c->type == MOD_REDUNDANT_LOAD_BALANCE)) {
		int count = 0;
		modcallable *this, *found;
		modgroup *g;

		MOD_LOG_OPEN_BRACE("load-balance");

		g = mod_callabletogroup(c);
		found = NULL;
		for (this = g->children; this; this = this->next) {
			if (!found) {
				found = this;
				count = 1;
				continue;
			}
			count++;

			if ((count * (fr_rand() & 0xffff)) < (uint32_t) 0x10000) {
				found = this;
			}
		}

		MOD_LOG_OPEN_BRACE(group_name[c->type]);
		
		if (c->type == MOD_LOAD_BALANCE) {
			modcall_child(request, component,
				      depth + 1, entry, found,
				      &result, FALSE);
					       
		} else {
			this = found;

			do {
				modcall_child(request, component,
					      depth + 1, entry, found,
					      &result, FALSE);
				if (found->actions[result] == MOD_ACTION_RETURN) {
					priority = -1;
					break;
				}

				this = this->next;
				if (!this) this = g->children;
			} while (this != found);
		}
		MOD_LOG_CLOSE_BRACE();
		goto calculate_result;
	} /* MOD_LOAD_BALANCE */

	/*
	 *	Reference another virtual server.
	 *
	 *	This should really be deleted, and replaced with a
	 *	more abstracted / functional version.
	 */
	if (c->type == MOD_REFERENCE) {
		modref *mr = mod_callabletoref(c);
		char const *server = request->server;

		if (server == mr->ref_name) {
			radlog(L_INFO, "WARNING: Suppressing recursive call to server %s", server);
			goto next_sibling;
		}

		request->server = mr->ref_name;
		RDEBUG("server %s { # nested call", mr->ref_name);
		result = indexed_modcall(component, 0, request);
		RDEBUG("} # server %s with nested call", mr->ref_name);
		request->server = server;
		goto calculate_result;
	} /* MOD_REFERENCE */

	/*
	 *	xlat a string without doing anything else
	 *
	 *	This should really be deleted, and replaced with a
	 *	more abstracted / functional version.
	 */
	if (c->type == MOD_XLAT) {
		modxlat *mx = mod_callabletoxlat(c);
		char buffer[128];

		if (!mx->exec) {
			radius_xlat(buffer, sizeof(buffer),
				    mx->xlat_name, request, NULL);
		} else {
			RDEBUG("`%s`", mx->xlat_name);
				radius_exec_program(mx->xlat_name, request,
						    0, NULL, 0,
						    EXEC_TIMEOUT,
						    request->packet->vps,
						    NULL, 1);
		}

		goto next_sibling;
	} /* MOD_XLAT */
	
	/*
	 *	Add new module types here.
	 */

calculate_result:
#if 0
	RDEBUG("(%s, %d) ? (%s, %d)",
	       fr_int2str(mod_rcode_table, result, "<invalid>"),
	       priority,
	       fr_int2str(mod_rcode_table, entry->result, "<invalid>"),
	       entry->priority);
#endif

	/*
	 *	The child's action says return.  Do so.
	 */
	if ((c->actions[result] == MOD_ACTION_RETURN) &&
	    (priority <= 0)) {
		entry->result = result;
		return TRUE;
	}

	/*
	 *	If "reject", break out of the loop and return
	 *	reject.
	 */
	if (c->actions[result] == MOD_ACTION_REJECT) {
		entry->result = RLM_MODULE_REJECT;
		return TRUE;
	}

	/*
	 *	The array holds a default priority for this return
	 *	code.  Grab it in preference to any unset priority.
	 */
	if (priority < 0) {
		priority = c->actions[result];
	}

	/*
	 *	We're higher than any previous priority, remember this
	 *	return code and priority.
	 */
	if (priority > entry->priority) {
		entry->result = result;
		entry->priority = priority;
	}

	/*
	 *	If we're processing a "case" statement, we return once
	 *	it's done, rather than going to the next "case" statement.
	 */
	if (c->type == MOD_CASE) return TRUE;

next_sibling:
	if (do_next_sibling) {
		entry->c = entry->c->next;

		if (entry->c) goto redo;
	}

	/*
	 *	And we're done!
	 */
	return TRUE;
}


/**
 * @brief Call a module, iteratively, with a local stack, rather than
 *	recursively.  What did Paul Graham say about Lisp...?
 */
int modcall(int component, modcallable *c, REQUEST *request)
{
	modcall_stack_entry_t stack[MODCALL_STACK_MAX];

	if ((component < 0) || (component >= RLM_COMPONENT_COUNT)) {
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Set up the initial stack frame.
	 */
	stack[0].c = c;
	stack[0].result = default_component_results[component];
	stack[0].priority = 0;

	/*
	 *	Call the main handler.
	 */
	if (!modcall_recurse(request, component, 0, &stack[0], TRUE)) {
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Return the result.
	 */
	return stack[0].result;
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
	} else if ((c->type > MOD_SINGLE) && (c->type <= MOD_POLICY)) {
		modgroup *g = mod_callabletogroup(c);
		modcallable *p;
		DEBUG("%.*s%s {", indent, "\t\t\t\t\t\t\t\t\t\t\t",
		      group_name[c->type]);
		for(p = g->children;p;p = p->next)
			dump_mc(p, indent+1);
	} /* else ignore it for now */

	for(i = 0; i<RLM_MODULE_NUMCODES; ++i) {
		DEBUG("%.*s%s = %s", indent+1, "\t\t\t\t\t\t\t\t\t\t\t",
		      fr_int2str(rcode_table, i, "??"),
		      action2str(c->actions[i]));
	}

	DEBUG("%.*s}", indent, "\t\t\t\t\t\t\t\t\t\t\t");
}

static void dump_tree(int comp, modcallable *c)
{
	RDEBUG("[%s]", comp2str[comp]);
	dump_mc(c, 0);
}
#else
#define dump_tree(a, b)
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
#ifdef WITH_COA
	,
	/* recv-coa */
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
	/* send-coa */
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
#endif
};


#ifdef WITH_UNLANG
static modcallable *do_compile_modupdate(modcallable *parent,
					 int component, CONF_SECTION *cs,
					 const char *name2)
{
	int i, ok = FALSE;
	const char *vp_name;
	modgroup *g;
	modcallable *csingle;
	CONF_ITEM *ci;
	VALUE_PAIR *head, **tail;

	static const char *attrlist_names[] = {
		"request", "reply", "proxy-request", "proxy-reply",
		"config", "control",
		"coa", "coa-reply", "disconnect", "disconnect-reply",
		NULL
	};

	component = component;	/* -Wunused */

	if (!cf_section_name2(cs)) {
		cf_log_err(cf_sectiontoitem(cs),
			   "Require list name for 'update'.\n");
		return NULL;
	}

	vp_name = name2;
	if (strncmp(vp_name, "outer.", 6) == 0) {
		vp_name += 6;
	} 

	for (i = 0; attrlist_names[i] != NULL; i++) {
		if (strcmp(vp_name, attrlist_names[i]) == 0) {
			ok = TRUE;
			break;
		}
	}

	if (!ok) {
		cf_log_err(cf_sectiontoitem(cs),
			   "Unknown attribute list \"%s\"",
			   name2);
		return NULL;
	}

	head = NULL;
	tail = &head;

	/*
	 *	Walk through the children of the update section,
	 *	ensuring that they're all known attributes.
	 */
	for (ci=cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci=cf_item_find_next(cs, ci)) {
		CONF_PAIR *cp;
		VALUE_PAIR *vp;

		if (cf_item_is_section(ci)) {
			cf_log_err(ci, "\"update\" sections cannot have subsections");
			return NULL;
		}

		if (!cf_item_is_pair(ci)) continue;

		cp = cf_itemtopair(ci);	/* can't return NULL */
		vp = cf_pairtovp(cp);
		if (!vp) {
			pairfree(&head);
			cf_log_err(ci, "ERROR: %s", fr_strerror());
			return NULL;
		}

		if ((vp->operator != T_OP_EQ) &&
		    (vp->operator != T_OP_CMP_EQ) &&
		    (vp->operator != T_OP_ADD) &&
		    (vp->operator != T_OP_SUB) &&
		    (vp->operator != T_OP_LE) &&
		    (vp->operator != T_OP_GE) &&
		    (vp->operator != T_OP_CMP_FALSE) &&
		    (vp->operator != T_OP_SET)) {
			pairfree(&head);
			pairfree(&vp);
			cf_log_err(ci, "Invalid operator for attribute");
			return NULL;
		}

		/*
		 *	A few more sanity checks.  The enforcement of
		 *	<= or >= can only happen for integer
		 *	attributes.
		 */
		if ((vp->operator == T_OP_LE) ||
		    (vp->operator == T_OP_GE)) {
			if ((vp->type != PW_TYPE_BYTE) &&
			    (vp->type != PW_TYPE_SHORT) &&
			    (vp->type != PW_TYPE_INTEGER)) {
				pairfree(&head);
				pairfree(&vp);
				cf_log_err(ci, "Enforcment of <= or >= is possible only for integer attributes");
				return NULL;
			}
		}

		*tail = vp;
		tail = &(vp->next);
	}

	if (!head) {
		cf_log_err(cf_sectiontoitem(cs),
			   "ERROR: update %s section cannot be empty",
			   name2);
		return NULL;
	}

	g = rad_malloc(sizeof(*g)); /* never fails */
	memset(g, 0, sizeof(*g));
	csingle = mod_grouptocallable(g);
	
	csingle->parent = parent;
	csingle->next = NULL;
	csingle->name = name2;
	csingle->type = MOD_UPDATE;
	csingle->method = component;
	
	memcpy(csingle->actions, defaultactions[component][GROUPTYPE_SIMPLE],
	       sizeof(csingle->actions));
	
	g->grouptype = GROUPTYPE_SIMPLE;
	g->children = NULL;
	g->cs = cs;
	g->vps = head;

	return csingle;
}


static modcallable *do_compile_modswitch(modcallable *parent,
					 int component, CONF_SECTION *cs)
{
	modcallable *csingle;
	CONF_ITEM *ci;
	int had_seen_default = FALSE;

	component = component;	/* -Wunused */

	if (!cf_section_name2(cs)) {
		cf_log_err(cf_sectiontoitem(cs),
			   "You must specify a variable to switch over for 'switch'.");
		return NULL;
	}

	if (!cf_item_find_next(cs, NULL)) {
		cf_log_err(cf_sectiontoitem(cs), "'switch' statments cannot be empty.");
		return NULL;
	}

	/*
	 *	Walk through the children of the switch section,
	 *	ensuring that they're all 'case' statements
	 */
	for (ci=cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci=cf_item_find_next(cs, ci)) {
		CONF_SECTION *subcs;
		const char *name1, *name2;

		if (!cf_item_is_section(ci)) {
			if (!cf_item_is_pair(ci)) continue;

			cf_log_err(ci, "\"switch\" sections can only have \"case\" subsections");
			return NULL;
		}

		subcs = cf_itemtosection(ci);	/* can't return NULL */
		name1 = cf_section_name1(subcs);

		if (strcmp(name1, "case") != 0) {
			cf_log_err(ci, "\"switch\" sections can only have \"case\" subsections");
			return NULL;
		}

		name2 = cf_section_name2(subcs);
		if (!name2 && !had_seen_default) {
			had_seen_default = TRUE;
			continue;
		}

		if (!name2 || (name2[0] == '\0')) {
			cf_log_err(ci, "\"case\" sections must have a name");
			return NULL;
		}
	}

	csingle= do_compile_modgroup(parent, component, cs,
				     GROUPTYPE_SIMPLE, GROUPTYPE_SIMPLE);
	if (!csingle) return NULL;
	csingle->type = MOD_SWITCH;
	return csingle;
}
#endif

static modcallable *do_compile_modserver(modcallable *parent,
					 int component, CONF_ITEM *ci,
					 const char *name,
					 CONF_SECTION *cs,
					 const char *server)
{
	modcallable *csingle;
	CONF_SECTION *subcs;
	modref *mr;

	subcs = cf_section_sub_find_name2(cs, comp2str[component], NULL);
	if (!subcs) {
		cf_log_err(ci, "Server %s has no %s section",
			   server, comp2str[component]);
		return NULL;
	}

	mr = rad_malloc(sizeof(*mr));
	memset(mr, 0, sizeof(*mr));

	csingle = mod_reftocallable(mr);
	csingle->parent = parent;
	csingle->next = NULL;
	csingle->name = name;
	csingle->type = MOD_REFERENCE;
	csingle->method = component;

	memcpy(csingle->actions, defaultactions[component][GROUPTYPE_SIMPLE],
	       sizeof(csingle->actions));
	
	mr->ref_name = strdup(server);
	mr->ref_cs = cs;

	return csingle;
}

static modcallable *do_compile_modxlat(modcallable *parent,
				       int component, const char *fmt)
{
	modcallable *csingle;
	modxlat *mx;

	mx = rad_malloc(sizeof(*mx));
	memset(mx, 0, sizeof(*mx));

	csingle = mod_xlattocallable(mx);
	csingle->parent = parent;
	csingle->next = NULL;
	csingle->name = "expand";
	csingle->type = MOD_XLAT;
	csingle->method = component;

	memcpy(csingle->actions, defaultactions[component][GROUPTYPE_SIMPLE],
	       sizeof(csingle->actions));
	
	mx->xlat_name = strdup(fmt);
	if (fmt[0] != '%') {
		char *p;
		mx->exec = TRUE;

		strcpy(mx->xlat_name, fmt + 1);
		p = strrchr(mx->xlat_name, '`');
		if (p) *p = '\0';
	}

	return csingle;
}

/*
 *	redundant, etc. can refer to modules or groups, but not much else.
 */
static int all_children_are_modules(CONF_SECTION *cs, const char *name)
{
	CONF_ITEM *ci;

	for (ci=cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci=cf_item_find_next(cs, ci)) {
		/*
		 *	If we're a redundant, etc. group, then the
		 *	intention is to call modules, rather than
		 *	processing logic.  These checks aren't
		 *	*strictly* necessary, but they keep the users
		 *	from doing crazy things.
		 */
		if (cf_item_is_section(ci)) {
			CONF_SECTION *subcs = cf_itemtosection(ci);
			const char *name1 = cf_section_name1(subcs);

			if ((strcmp(name1, "if") == 0) ||
			    (strcmp(name1, "else") == 0) ||
			    (strcmp(name1, "elsif") == 0) ||
			    (strcmp(name1, "update") == 0) ||
			    (strcmp(name1, "switch") == 0) ||
			    (strcmp(name1, "case") == 0)) {
				cf_log_err(ci, "%s sections cannot contain a \"%s\" statement",
				       name, name1);
				return 0;
			}
			continue;
		}

		if (cf_item_is_pair(ci)) {
			CONF_PAIR *cp = cf_itemtopair(ci);
			if (cf_pair_value(cp) != NULL) {
				cf_log_err(ci,
					   "Entry with no value is invalid");
				return 0;
			}
		}
	}

	return 1;
}


/*
 *	Compile one entry of a module call.
 */
static modcallable *do_compile_modsingle(modcallable *parent,
					 int component, CONF_ITEM *ci,
					 int grouptype,
					 const char **modname)
{
#ifdef WITH_UNLANG
	int result;
#endif
	const char *modrefname;
	modsingle *single;
	modcallable *csingle;
	module_instance_t *this;
	CONF_SECTION *cs, *subcs, *modules;

	if (cf_item_is_section(ci)) {
		const char *name2;

		cs = cf_itemtosection(ci);
		modrefname = cf_section_name1(cs);
		name2 = cf_section_name2(cs);
		if (!name2) name2 = "_UnNamedGroup";

		/*
		 *	group{}, redundant{}, or append{} may appear
		 *	where a single module instance was expected.
		 *	In that case, we hand it off to
		 *	compile_modgroup
		 */
		if (strcmp(modrefname, "group") == 0) {
			*modname = name2;
			return do_compile_modgroup(parent, component, cs,
						   GROUPTYPE_SIMPLE,
						   grouptype);

		} else if (strcmp(modrefname, "redundant") == 0) {
			*modname = name2;

			if (!all_children_are_modules(cs, modrefname)) {
				return NULL;
			}

			return do_compile_modgroup(parent, component, cs,
						   GROUPTYPE_REDUNDANT,
						   grouptype);

		} else if (strcmp(modrefname, "append") == 0) {
			*modname = name2;
			return do_compile_modgroup(parent, component, cs,
						   GROUPTYPE_APPEND,
						   grouptype);

		} else if (strcmp(modrefname, "load-balance") == 0) {
			*modname = name2;

			if (!all_children_are_modules(cs, modrefname)) {
				return NULL;
			}

			csingle= do_compile_modgroup(parent, component, cs,
						     GROUPTYPE_SIMPLE,
						     grouptype);
			if (!csingle) return NULL;
			csingle->type = MOD_LOAD_BALANCE;
			return csingle;

		} else if (strcmp(modrefname, "redundant-load-balance") == 0) {
			*modname = name2;

			if (!all_children_are_modules(cs, modrefname)) {
				return NULL;
			}

			csingle= do_compile_modgroup(parent, component, cs,
						     GROUPTYPE_REDUNDANT,
						     grouptype);
			if (!csingle) return NULL;
			csingle->type = MOD_REDUNDANT_LOAD_BALANCE;
			return csingle;

#ifdef WITH_UNLANG
		} else 	if (strcmp(modrefname, "if") == 0) {
			if (!cf_section_name2(cs)) {
				cf_log_err(ci, "'if' without condition.");
				return NULL;
			}

			*modname = name2;
			csingle= do_compile_modgroup(parent, component, cs,
						     GROUPTYPE_SIMPLE,
						     grouptype);
			if (!csingle) return NULL;
			csingle->type = MOD_IF;

			if (!radius_evaluate_condition(NULL, 0, 0, modname,
						       FALSE, &result)) {
				modcallable_free(&csingle);
				return NULL;
			}
			*modname = name2;

			return csingle;

		} else 	if (strcmp(modrefname, "elsif") == 0) {
			if (parent &&
			    ((parent->type == MOD_LOAD_BALANCE) ||
			     (parent->type == MOD_REDUNDANT_LOAD_BALANCE))) {
				cf_log_err(ci, "'elsif' cannot be used in this section.");
				return NULL;
			}

			if (!cf_section_name2(cs)) {
				cf_log_err(ci, "'elsif' without condition.");
				return NULL;
			}

			*modname = name2;
			csingle= do_compile_modgroup(parent, component, cs,
						     GROUPTYPE_SIMPLE,
						     grouptype);
			if (!csingle) return NULL;
			csingle->type = MOD_ELSIF;

			if (!radius_evaluate_condition(NULL, 0, 0, modname,
						       FALSE, &result)) {
				modcallable_free(&csingle);
				return NULL;
			}
			*modname = name2;

			return csingle;

		} else 	if (strcmp(modrefname, "else") == 0) {
			if (parent &&
			    ((parent->type == MOD_LOAD_BALANCE) ||
			     (parent->type == MOD_REDUNDANT_LOAD_BALANCE))) {
				cf_log_err(ci, "'else' cannot be used in this section section.");
				return NULL;
			}

			if (cf_section_name2(cs)) {
				cf_log_err(ci, "Cannot have conditions on 'else'.");
				return NULL;
			}

			*modname = name2;
			csingle= do_compile_modgroup(parent, component, cs,
						     GROUPTYPE_SIMPLE,
						     grouptype);
			if (!csingle) return NULL;
			csingle->type = MOD_ELSE;
			return csingle;

		} else 	if (strcmp(modrefname, "update") == 0) {
			*modname = name2;

			csingle = do_compile_modupdate(parent, component, cs,
						       name2);
			if (!csingle) return NULL;

			return csingle;

		} else 	if (strcmp(modrefname, "switch") == 0) {
			*modname = name2;

			csingle = do_compile_modswitch(parent, component, cs);
			if (!csingle) return NULL;

			return csingle;

		} else 	if (strcmp(modrefname, "case") == 0) {
			int i;

			*modname = name2;

			/*
			 *	FIXME: How to tell that the parent can only
			 *	be a "switch" statement?
			 */
			if (!parent) {
				cf_log_err(ci, "\"case\" statements may only appear within a \"switch\" section");
				return NULL;
			}

			csingle= do_compile_modgroup(parent, component, cs,
						     GROUPTYPE_SIMPLE,
						     grouptype);
			if (!csingle) return NULL;
			csingle->type = MOD_CASE;
			csingle->name = cf_section_name2(cs); /* may be NULL */

			/*
			 *	Set all of it's codes to return, so that
			 *	when we pick a 'case' statement, we don't
			 *	fall through to processing the next one.
			 */
			for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
				csingle->actions[i] = MOD_ACTION_RETURN;
			}

			return csingle;
#endif
		} /* else it's something like sql { fail = 1 ...} */

	} else if (!cf_item_is_pair(ci)) { /* CONF_DATA or some such */
		return NULL;

		/*
		 *	Else it's a module reference, with updated return
		 *	codes.
		 */
	} else {
		CONF_SECTION *loop;
		CONF_PAIR *cp = cf_itemtopair(ci);
		modrefname = cf_pair_attr(cp);

		/*
		 *	Actions (ok = 1), etc. are orthoganal to just
		 *	about everything else.
		 */
		if (cf_pair_value(cp) != NULL) {
			cf_log_err(ci, "Entry is not a reference to a module");
			return NULL;
		}

		if (((modrefname[0] == '%') && (modrefname[1] == '{')) ||
		    (modrefname[0] == '`')) {
			return do_compile_modxlat(parent, component,
						  modrefname);
		}

		/*
		 *	See if the module is a virtual one.  If so,
		 *	return that, rather than doing anything here.
		 */
		subcs = NULL;
		cs = cf_section_find("instantiate");
		if (cs) subcs = cf_section_sub_find_name2(cs, NULL,
							  modrefname);
		if (!subcs &&
		    (cs = cf_section_find("policy")) != NULL) {
			char buffer[256];
			
			snprintf(buffer, sizeof(buffer), "%s.%s",
				 modrefname, comp2str[component]);

			/*
			 *	Prefer name.section, then name.
			 */
			subcs = cf_section_sub_find_name2(cs, NULL,
							  buffer);
			if (!subcs) {
				subcs = cf_section_sub_find_name2(cs, NULL,
								  modrefname);
			}
		}

		/*
		 *	Allow policies to over-ride module names.
		 *	i.e. the "sql" policy can do some extra things,
		 *	and then call the "sql" module.
		 */
		for (loop = cf_item_parent(ci);
		     loop && subcs;
		     loop = cf_item_parent(cf_sectiontoitem(loop))) {
			if (loop == subcs) {
				subcs = NULL;
			}
		}

		if (subcs) {
			DEBUG2(" Module: Loading virtual module %s",
			       modrefname);

			/*
			 *	redundant foo {} is a single.
			 */
			if (cf_section_name2(subcs)) {
				return do_compile_modsingle(parent,
							    component,
							    cf_sectiontoitem(subcs),
							    grouptype,
							    modname);
			} else {
				/*
				 *	foo {} is a group.
				 */
				return do_compile_modgroup(parent,
							   component,
							   subcs,
							   GROUPTYPE_SIMPLE,
							   grouptype);
			}
		}
	}

	/*
	 *	Not a virtual module.  It must be a real module.
	 */
	modules = cf_section_find("modules");
	this = NULL;

	if (modules && cf_section_sub_find_name2(modules, NULL, modrefname)) {
		this = find_module_instance(modules, modrefname, 1);
	}

	if (!this) do {
		int i;
		char *p;
	  
		/*
		 *	Maybe it's module.method
		 */
		p = strrchr(modrefname, '.');
		if (p) for (i = RLM_COMPONENT_AUTH;
			    i < RLM_COMPONENT_COUNT;
			    i++) {
			if (strcmp(p + 1, comp2str[i]) == 0) {
				char buffer[256];

				strlcpy(buffer, modrefname, sizeof(buffer));
				buffer[p - modrefname] = '\0';
				component = i;
				
				this = find_module_instance(cf_section_find("modules"), buffer, 1);
				if (this &&
				    !this->entry->module->methods[i]) {
					*modname = NULL;
					cf_log_err(ci, "Module %s has no such method %s", buffer, comp2str[i]);
					return NULL;
				}
				break;
			}
		}
		if (this) break;

		if (strncmp(modrefname, "server[", 7) == 0) {
			char buffer[256];

			strlcpy(buffer, modrefname + 7, sizeof(buffer));
			p = strrchr(buffer, ']');
			if (!p || p[1] != '\0' || (p == buffer)) {
				cf_log_err(ci, "Invalid server reference in \"%s\".", modrefname);
				return NULL;
			}
			*p = '\0';

			cs = cf_section_sub_find_name2(NULL, "server", buffer);
			if (!cs) {
				cf_log_err(ci, "No such server \"%s\".", buffer);
				return NULL;
			}
			
			return do_compile_modserver(parent, component, ci,
						    modrefname, cs, buffer);
		}
		
		*modname = NULL;
		cf_log_err(ci, "Failed to find \"%s\" in the \"modules\" section.", modrefname);
		return NULL;
	} while (0);

	/*
	 *	We know it's all OK, allocate the structures, and fill
	 *	them in.
	 */
	single = rad_malloc(sizeof(*single));
	memset(single, 0, sizeof(*single));
	csingle = mod_singletocallable(single);
	csingle->parent = parent;
	csingle->next = NULL;
	if (!parent || (component != RLM_COMPONENT_AUTH)) {
		memcpy(csingle->actions, defaultactions[component][grouptype],
		       sizeof csingle->actions);
	} else { /* inside Auth-Type has different rules */
		memcpy(csingle->actions, defaultactions[RLM_COMPONENT_AUTZ][grouptype],
		       sizeof csingle->actions);
	}
	rad_assert(modrefname != NULL);
	csingle->name = modrefname;
	csingle->type = MOD_SINGLE;
	csingle->method = component;

	/*
	 *	Singles can override the actions, virtual modules cannot.
	 *
	 *	FIXME: We may want to re-visit how to do this...
	 *	maybe a csingle as a ref?
	 */
	if (cf_item_is_section(ci)) {
		CONF_ITEM *csi;
		
		cs = cf_itemtosection(ci);
		for (csi=cf_item_find_next(cs, NULL);
		     csi != NULL;
		     csi=cf_item_find_next(cs, csi)) {

			if (cf_item_is_section(csi)) {
				cf_log_err(csi, "Subsection of module instance call not allowed");
				modcallable_free(&csingle);
				return NULL;
			}

			if (!cf_item_is_pair(csi)) continue;

			if (!compile_action(csingle, cf_itemtopair(csi))) {
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
		cf_log_err(ci, "\"%s\" modules aren't allowed in '%s' sections -- they have no such method.", this->entry->module->name,
		       comp2str[component]);
		modcallable_free(&csingle);
		return NULL;
	}

	single->modinst = this;
	*modname = this->entry->module->name;
	return csingle;
}

modcallable *compile_modsingle(modcallable *parent,
			       int component, CONF_ITEM *ci,
			       const char **modname)
{
	modcallable *ret = do_compile_modsingle(parent, component, ci,
						GROUPTYPE_SIMPLE,
						modname);
	dump_tree(component, ret);
	return ret;
}


/*
 *	Internal compile group code.
 */
static modcallable *do_compile_modgroup(modcallable *parent,
					int component, CONF_SECTION *cs,
					int grouptype, int parentgrouptype)
{
	int i;
	modgroup *g;
	modcallable *c;
	CONF_ITEM *ci;

	g = rad_malloc(sizeof(*g));
	memset(g, 0, sizeof(*g));
	g->grouptype = grouptype;

	c = mod_grouptocallable(g);
	c->parent = parent;
	c->type = MOD_GROUP;
	c->next = NULL;
	memset(c->actions, 0, sizeof(c->actions));

	/*
	 *	Remember the name for printing, etc.
	 *
	 *	FIXME: We may also want to put the names into a
	 *	rbtree, so that groups can reference each other...
	 */
	c->name = cf_section_name2(cs);
	if (!c->name) {
		c->name = cf_section_name1(cs);
		if (strcmp(c->name, "group") == 0) {
			c->name = "";
		} else {
			c->type = MOD_POLICY;
		}
	}
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
			CONF_SECTION *subcs = cf_itemtosection(ci);

			single = do_compile_modsingle(c, component, ci,
						      grouptype, &junk);
			if (!single) {
				cf_log_err(ci, "Failed to parse \"%s\" subsection.",
				       cf_section_name1(subcs));
				modcallable_free(&c);
				return NULL;
			}
			add_child(g, single);

		} else if (!cf_item_is_pair(ci)) { /* CONF_DATA */
			continue;

		} else {
			const char *attr, *value;
			CONF_PAIR *cp = cf_itemtopair(ci);

			attr = cf_pair_attr(cp);
			value = cf_pair_value(cp);

			/*
			 *	A CONF_PAIR is either a module
			 *	instance with no actions
			 *	specified ...
			 */
			if (!value) {
				modcallable *single;
				const char *junk = NULL;

				single = do_compile_modsingle(c,
							      component,
							      ci,
							      grouptype,
							      &junk);
				if (!single) {
					cf_log_err(ci,
						   "Failed to parse \"%s\" entry.",
						   attr);
					modcallable_free(&c);
					return NULL;
				}
				add_child(g, single);

				/*
				 *	Or a module instance with action.
				 */
			} else if (!compile_action(c, cp)) {
				modcallable_free(&c);
				return NULL;
			} /* else it worked */
		}
	}

	/*
	 *	Set the default actions, if they haven't already been
	 *	set.
	 */
	for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
		if (!c->actions[i]) {
			if (!parent || (component != RLM_COMPONENT_AUTH)) {
				c->actions[i] = defaultactions[component][parentgrouptype][i];
			} else { /* inside Auth-Type has different rules */
				c->actions[i] = defaultactions[RLM_COMPONENT_AUTZ][parentgrouptype][i];
			}
		}
	}

	/*
	 *	FIXME: If there are no children, return NULL?
	 */
	return mod_grouptocallable(g);
}

modcallable *compile_modgroup(modcallable *parent,
			      int component, CONF_SECTION *cs)
{
	modcallable *ret = do_compile_modgroup(parent, component, cs,
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
		memset(g, 0, sizeof(*g));
		g->grouptype = GROUPTYPE_SIMPLE;
		c = mod_grouptocallable(g);
		c->next = NULL;
		memcpy(c->actions,
		       defaultactions[component][GROUPTYPE_SIMPLE],
		       sizeof(c->actions));
		rad_assert(name != NULL);
		c->name = name;
		c->type = MOD_GROUP;
		c->method = component;
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

	if (!pc || !*pc) return;

	c = *pc;

	if ((c->type > MOD_SINGLE) && (c->type <= MOD_POLICY)) {
		modgroup *g = mod_callabletogroup(c);

		if (g->children) for (loop = g->children;
		    loop ;
		    loop = next) {
			next = loop->next;
			modcallable_free(&loop);
		}
		pairfree(&g->vps);
	}
	free(c);
	*pc = NULL;
}
