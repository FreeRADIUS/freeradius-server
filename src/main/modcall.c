/*
 * @name modcall.c
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

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/modcall.h>
#include <freeradius-devel/parser.h>
#include <freeradius-devel/rad_assert.h>


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
	       MOD_FOREACH, MOD_BREAK,
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
	value_pair_map_t *map;	/* update */
	const fr_cond_t *cond;	/* if/elsif */
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
		cf_log_err_cp(cp, "Unknown action '%s'.\n",
			   value);
		return 0;
	}

	if (strcasecmp(attr, "default") != 0) {
		int rcode;

		rcode = fr_str2int(mod_rcode_table, attr, -1);
		if (rcode < 0) {
			cf_log_err_cp(cp,
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

	if (sp->modinst->dead) {
		myresult = RLM_MODULE_FAIL;
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
	"foreach",
	"break",
#endif
	"policy",
	"reference",
	"xlat"
};

static const char *modcall_spaces = "                                                                ";

#define MODCALL_STACK_MAX (32)

/*
 *	Don't call the modules recursively.  Instead, do them
 *	iteratively, and manage the call stack ourselves.
 */
typedef struct modcall_stack {
	int pointer;

	int priority[MODCALL_STACK_MAX];
	int result[MODCALL_STACK_MAX];
	modcallable *children[MODCALL_STACK_MAX];
	modcallable *start[MODCALL_STACK_MAX];
} modcall_stack;


#ifdef WITH_UNLANG
static void pairfree_wrapper(void *data)
{
	VALUE_PAIR **vp = (VALUE_PAIR **) data;
	pairfree(vp);
}
#endif

/**
 * @brief Call a module, iteratively, with a local stack, rather than
 *	recursively.  What did Paul Graham say about Lisp...?
 */
int modcall(int component, modcallable *c, REQUEST *request)
{
	int myresult, mypriority;
	modcall_stack stack;
	modcallable *parent, *child;
	modsingle *sp;
	int if_taken, was_if;

	if ((component < 0) || (component >= RLM_COMPONENT_COUNT)) {
		return RLM_MODULE_FAIL;
	}

	stack.pointer = 0;
	stack.priority[0] = 0;
	stack.children[0] = c;
	stack.start[0] = NULL;
	myresult = stack.result[0] = default_component_results[component];
	mypriority = 0;
	was_if = if_taken = FALSE;

	while (1) {
		/*
		 *	A module has taken too long to process the request,
		 *	and we've been told to stop processing it.
		 */
		if ((request->master_state == REQUEST_STOP_PROCESSING) ||
		    (request->parent &&
		     (request->parent->master_state == REQUEST_STOP_PROCESSING))) {
			myresult = RLM_MODULE_FAIL;
			break;
		}

		child = stack.children[stack.pointer];
		if (!child) {
			myresult = stack.result[stack.pointer];
			break;
		}
		parent = child->parent;

#ifdef WITH_UNLANG
		if ((child->type == MOD_ELSE) || (child->type == MOD_ELSIF)) {
			myresult = stack.result[stack.pointer];

			if (!was_if) { /* error */
				RDEBUG2("%.*s ... skipping %s for request %d: No preceding \"if\"",
				       stack.pointer + 1, modcall_spaces,
				       group_name[child->type],
				       request->number);
				goto unroll;
			}
			if (if_taken) {
				RDEBUG2("%.*s ... skipping %s for request %d: Preceding \"if\" was taken",
				       stack.pointer + 1, modcall_spaces,
				       group_name[child->type],
				       request->number);
				goto unroll;
			}
		}

		/*
		 *	"if" or "elsif".  Evaluate the condition.
		 */
		if ((child->type == MOD_IF) || (child->type == MOD_ELSIF)) {
			int condition = TRUE;
			const char *p = child->name;
			modgroup *g;

			g = mod_callabletogroup(child);
			rad_assert(g->cond != NULL);

			RDEBUG2("%.*s? %s %s",
			       stack.pointer + 1, modcall_spaces,
			       (child->type == MOD_IF) ? "if" : "elsif",
			       child->name);

			if (radius_evaluate_condition(request, myresult,
						      0, &p, TRUE, &condition)) {
				RDEBUG2("%.*s? %s %s -> %s",
				       stack.pointer + 1, modcall_spaces,
				       (child->type == MOD_IF) ? "if" : "elsif",
				       child->name, (condition != FALSE) ? "TRUE" : "FALSE");
			} else {
				/*
				 *	This should never happen, the
				 *	condition is checked when the
				 *	module section is loaded.
				 */
				condition = FALSE;
			}

			/*
			 *	If the condition fails to match, go
			 *	immediately to the next entry in the
			 *	list.
			 */
			if (!condition) {
				was_if = TRUE;
				if_taken = FALSE;
				goto next_section;
			} /* else process it as a simple group */
		}

		if (child->type == MOD_UPDATE) {
			int rcode;
			modgroup *g = mod_callabletogroup(child);

			RDEBUG2("%.*supdate %s {",
				stack.pointer + 1, modcall_spaces,
				child->name);

			rcode = radius_map2request(request, g->map, "update",
						   radius_map2vp, NULL);
			if (rcode < 0) {
				myresult = RLM_MODULE_FAIL;
				goto handle_priority;
			}

			/* else leave myresult && mypriority alone */
			goto handle_result;
		}

		if (child->type == MOD_BREAK) {
			int i;
			VALUE_PAIR **copy_p;

			for (i = 8; i >= 0; i--) {
				copy_p = request_data_get(request,
							  radius_get_vp, i);
				if (copy_p) {
						RDEBUG2("%.*s #  BREAK Foreach-Variable-%d", stack.pointer + 1, modcall_spaces, i);
					pairfree(copy_p);
					break;
				}
			}

			myresult = RLM_MODULE_NOOP;
			goto handle_result;
		}

		if (child->type == MOD_FOREACH) {
			int i, depth = -1;
			VALUE_PAIR *vp;
			modgroup *g = mod_callabletogroup(child);

			for (i = 0; i < 8; i++) {
				if (!request_data_reference(request,
							    radius_get_vp, i)) {
					depth = i;
					break;
				}
			}

			if (depth < 0) {
				RDEBUGE("foreach Nesting too deep!");
				myresult = RLM_MODULE_FAIL;
				goto handle_result;
			}

			if (!(radius_get_vp(request, child->name, &vp) < 0)) {
				RDEBUG2("%.*sforeach %s {",
					stack.pointer + 1, modcall_spaces,
					child->name);
				while (vp) {
					VALUE_PAIR *copy = NULL, **copy_p;

#ifndef NDEBUG
					if (fr_debug_flag >= 2) {
						char buffer[1024];

						vp_prints_value(buffer, sizeof(buffer), vp, 1);
						RDEBUG2("%.*s #  Foreach-Variable-%d = %s", stack.pointer + 1, modcall_spaces, depth, buffer);
					}
#endif

					copy = paircopy(request, vp);
					copy_p = &copy;

					request_data_add(request, radius_get_vp,
							 depth, copy_p,
							 pairfree_wrapper);

				 	myresult = modcall(component,
							   g->children,
							   request);
					if (myresult == MOD_ACTION_RETURN) {
						break;
					}
					vp = pairfind(vp->next, vp->da->attr,
						      vp->da->vendor, TAG_ANY);

					/*
					 *	Delete the cached attribute,
					 *	if it exists.
					 */
					if (copy) {
						request_data_get(request,
								 radius_get_vp,
								 depth);
						pairfree(&copy);
					} else {
						break;
					}
				} /* loop over VPs */
			}  /* if the VP exists */

			myresult = RLM_MODULE_OK;
			goto handle_result;
		}
#endif
	
		if (child->type == MOD_REFERENCE) {
			modref *mr = mod_callabletoref(child);
			const char *server = request->server;

			if (server == mr->ref_name) {
				RDEBUGW("Suppressing recursive call to server %s", server);
				myresult = RLM_MODULE_NOOP;
				goto handle_priority;
			}
			
			request->server = mr->ref_name;
			RDEBUG("server %s { # nested call", mr->ref_name);
			myresult = indexed_modcall(component, 0, request);
			RDEBUG("} # server %s with nested call", mr->ref_name);
			request->server = server;
			goto handle_priority;
		}

		if (child->type == MOD_XLAT) {
			modxlat *mx = mod_callabletoxlat(child);
			char buffer[128];

			if (!mx->exec) {
				radius_xlat(buffer, sizeof(buffer), request, mx->xlat_name, NULL, NULL);
			} else {
				RDEBUG("`%s`", mx->xlat_name);
				radius_exec_program(mx->xlat_name, request,
						    0, NULL, 0,
						    request->packet->vps,
						    NULL, 1);
			}
					    
			goto skip; /* don't change anything on the stack */
		}

		/*
		 *	Child is a group that has children of it's own.
		 */
		if (child->type != MOD_SINGLE) {
			int count = 1;
			modcallable *p, *q;
#ifdef WITH_UNLANG
			modcallable *null_case;
#endif
			modgroup *g = mod_callabletogroup(child);

			stack.pointer++;

			/*
			 *	Catastrophic error.  This SHOULD have
			 *	been caught when we were reading in the
			 *	conf files.
			 *
			 *	FIXME: Do so.
			 */
			if (stack.pointer >= MODCALL_STACK_MAX) {
				ERROR("Internal sanity check failed: module stack is too deep");
				exit(1);
			}

			stack.priority[stack.pointer] = stack.priority[stack.pointer - 1];
			stack.result[stack.pointer] = stack.result[stack.pointer - 1];

			RDEBUG2("%.*s%s %s {",
				stack.pointer + 1, modcall_spaces,
				group_name[child->type], child->name);

			switch (child->type) {
#ifdef WITH_UNLANG
				char buffer[1024];

			case MOD_IF:
			case MOD_ELSE:
			case MOD_ELSIF:
			case MOD_CASE:
			case MOD_FOREACH:
#endif
			case MOD_GROUP:
			case MOD_POLICY: /* same as MOD_GROUP */
				stack.children[stack.pointer] = g->children;
				break;

				/*
				 *	See the "camel book" for why
				 *	this works.
				 *
				 *	If (rand(0..n) < 1), pick the
				 *	current realm.  We add a scale
				 *	factor of 65536, to avoid
				 *	floating point.
				 */
			case MOD_LOAD_BALANCE:
			case MOD_REDUNDANT_LOAD_BALANCE:
				q = NULL;
				for(p = g->children; p; p = p->next) {
					if (!q) {
						q = p;
						count = 1;
						continue;
					}

					count++;

					if ((count * (fr_rand() & 0xffff)) < (uint32_t) 0x10000) {
						q = p;
					}
				}
				stack.children[stack.pointer] = q;
				break;

#ifdef WITH_UNLANG
			case MOD_SWITCH:
				if (!strchr(child->name, '%')) {
					VALUE_PAIR *vp = NULL;

					if ((radius_get_vp(request, child->name, &vp) < 0) || !vp) {
						*buffer = '\0';
					} else {
						vp_prints_value(buffer, sizeof(buffer), vp, 0);
					}
				} else {
					if (radius_xlat(buffer, sizeof(buffer), request, child->name, NULL, NULL) < 0) {
						*buffer = '\0';
					}
				}
				null_case = q = NULL;
				for(p = g->children; p; p = p->next) {
					if (!p->name) {
						if (!null_case) null_case = p;
						continue;
					}
					if (strcmp(buffer, p->name) == 0) {
						q = p;
						break;
					}
				}

				if (!q) q = null_case;

				stack.children[stack.pointer] = q;
				break;
#endif

			default:
				RDEBUG2("Internal sanity check failed in modcall %d", child->type);
				exit(1); /* internal sanity check failure */
				break;
			}


			stack.start[stack.pointer] = stack.children[stack.pointer];

			RDEBUG2("%.*s- entering %s %s {...}", stack.pointer, modcall_spaces, group_name[child->type],
			        child->name ? child->name : "");

			/*
			 *	Catch the special case of a NULL group.
			 */
			if (!stack.children[stack.pointer]) {
				/*
				 *	Print message for NULL group
				 */
				RDEBUG2("%.*s- %s %s = %s",
				       stack.pointer + 1, modcall_spaces,
				       group_name[child->type],
				       child->name ? child->name : "",
				       fr_int2str(mod_rcode_table,
						    stack.result[stack.pointer],
						  "??"));
				goto do_return;
			}

			/*
			 *	The child may be a group, so we want to
			 *	recurse into it's children, rather than
			 *	falling through to the code below.
			 */
			continue;
		}

		/*
		 *	Process a stand-alone child, and fall through
		 *	to dealing with it's parent.
		 */
		sp = mod_callabletosingle(child);

		myresult = call_modsingle(child->method, sp, request);
		RDEBUG2("%.*s[%s] = %s",
			stack.pointer + 1, modcall_spaces,
			child->name ? child->name : "",
			fr_int2str(mod_rcode_table, myresult, "??"));

	handle_priority:
		mypriority = child->actions[myresult];

#ifdef WITH_UNLANG
		if (0) {
		handle_result:
			if (child->type != MOD_BREAK) {
				RDEBUG2("%.*s} # %s %s = %s",
					stack.pointer + 1, modcall_spaces,
					group_name[child->type], child->name ? child->name : "",
					fr_int2str(mod_rcode_table, myresult, "??"));
			}
		}
#else
		handle_result:
#endif

		/*
		 *	This is a bit of a hack...
		 */
		if (component != RLM_COMPONENT_SESS) request->simul_max = myresult;

		/*
		 *	FIXME: Allow modules to push a modcallable
		 *	onto this stack.  This should simplify
		 *	configuration a LOT!
		 *
		 *	Once we do that, we can't do load-time
		 *	checking of the maximum stack depth, and we've
		 *	got to cache the stack pointer before storing
		 *	myresult.
		 *
		 *	Also, if the stack changed, we need to set
		 *	children[ptr] to NULL, and process the next
		 *	entry on the stack, rather than falling
		 *	through to finalize the processing of this
		 *	entry.
		 *
		 *	Don't put "myresult" on the stack here,
		 *	we have to do so with priority.
		 */

		/*
		 *	We roll back up the stack at this point.
		 */
	unroll:
		/*
		 *	The child's action says return.  Do so.
		 */
		if ((child->actions[myresult] == MOD_ACTION_RETURN) &&
		    (mypriority <= 0)) {
			stack.result[stack.pointer] = myresult;
			stack.children[stack.pointer] = NULL;
			goto do_return;
		}

		/*
		 *	If "reject", break out of the loop and return
		 *	reject.
		 */
		if (child->actions[myresult] == MOD_ACTION_REJECT) {
			stack.children[stack.pointer] = NULL;
			stack.result[stack.pointer] = RLM_MODULE_REJECT;
			goto do_return;
		}

		/*
		 *	Otherwise, the action is a number, the
		 *	preference level of this return code. If no
		 *	higher preference has been seen yet, remember
		 *	this one.
		 */
		if (mypriority >= stack.priority[stack.pointer]) {
#ifdef WITH_UNLANG
		next_section:
#endif
			stack.result[stack.pointer] = myresult;
			stack.priority[stack.pointer] = mypriority;
		}

		/*
		 *	No parent, we must be done.
		 */
	skip:
		if (!parent) {
 			rad_assert(stack.pointer == 0);
			myresult = stack.result[0];
			break;
		}

		rad_assert(child != NULL);

		/*
		 *	Go to the "next" child, whatever that is.
		 */
		switch (parent->type) {
#ifdef WITH_UNLANG
			case MOD_IF:
			case MOD_ELSE:
			case MOD_ELSIF:
			case MOD_CASE:
			case MOD_FOREACH:
#endif
			case MOD_GROUP:
			case MOD_POLICY: /* same as MOD_GROUP */
				stack.children[stack.pointer] = child->next;
				break;

#ifdef WITH_UNLANG
			case MOD_SWITCH:
#endif
			case MOD_LOAD_BALANCE:
				stack.children[stack.pointer] = NULL;
				break;

			case MOD_REDUNDANT_LOAD_BALANCE:
				if (child->next) {
					stack.children[stack.pointer] = child->next;
				} else {
					modgroup *g = mod_callabletogroup(parent);

					stack.children[stack.pointer] = g->children;
				}
				if (stack.children[stack.pointer] == stack.start[stack.pointer]) {
					stack.children[stack.pointer] = NULL;
				}
				break;
			default:
				RDEBUG2("Internal sanity check failed in modcall  next %d", child->type);
				exit(1);
		}

		/*
		 *	No child, we're done this group, and we return
		 *	"myresult" to the caller by pushing it back up
		 *	the stack.
		 */
		if (!stack.children[stack.pointer]) {
		do_return:
			myresult = stack.result[stack.pointer];
			mypriority = 0; /* reset for the next result */
			if (stack.pointer == 0) break;
			stack.pointer--;
			if (stack.pointer == 0) break;

			RDEBUG2("%.*s- %s %s returns %s",
			       stack.pointer + 1, modcall_spaces,
			       group_name[parent->type],
			       parent->name ? parent->name : "",
				fr_int2str(mod_rcode_table, myresult, "??"));

#ifdef WITH_UNLANG
			if ((parent->type == MOD_IF) ||
			    (parent->type == MOD_ELSIF)) {
				if_taken = was_if = TRUE;
			} else {
				if_taken = was_if = FALSE;
			}
#endif

			/*
			 *	Unroll the stack.
			 */
			child = stack.children[stack.pointer];
			parent = child->parent;
			goto unroll;
		}

	} /* loop until done */

	return myresult;
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
	} else {
		modgroup *g = mod_callabletogroup(c);
		modcallable *p;
		DEBUG("%.*s%s {", indent, "\t\t\t\t\t\t\t\t\t\t\t",
		      group_name[c->type]);
		for(p = g->children;p;p = p->next)
			dump_mc(p, indent+1);
	}

	for(i = 0; i<RLM_MODULE_NUMCODES; ++i) {
		DEBUG("%.*s%s = %s", indent+1, "\t\t\t\t\t\t\t\t\t\t\t",
		      fr_int2str(mod_rcode_table, i, "??"),
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
static modcallable *do_compile_modupdate(modcallable *parent, UNUSED int component,
					 CONF_SECTION *cs, const char *name2)
{
	int rcode;
	modgroup *g;
	modcallable *csingle;
	value_pair_map_t *map;

	/*
	 *	This looks at cs->name2 to determine which list to update
	 */
	rcode = radius_attrmap(cs, &map, PAIR_LIST_REQUEST, PAIR_LIST_REQUEST, 128);
	if (rcode < 0) return NULL; /* message already printed */

	if (!map) {
		cf_log_err_cs(cs, "update sections cannot be empty");
		return NULL;
	}

	g = rad_malloc(sizeof(*g)); /* never fails */
	memset(g, 0, sizeof(*g));
	csingle = mod_grouptocallable(g);
	
	csingle->parent = parent;
	csingle->next = NULL;

	if (name2) {
		csingle->name = name2;
	} else {
		csingle->name = "";
	}
	csingle->type = MOD_UPDATE;
	csingle->method = component;
	
	g->grouptype = GROUPTYPE_SIMPLE;
	g->children = NULL;
	g->cs = cs;
	g->map = map;

	return csingle;
}


static modcallable *do_compile_modswitch(modcallable *parent, UNUSED int component, CONF_SECTION *cs)
{
	modcallable *csingle;
	CONF_ITEM *ci;
	int had_seen_default = FALSE;

	if (!cf_section_name2(cs)) {
		cf_log_err_cs(cs,
			   "You must specify a variable to switch over for 'switch'.");
		return NULL;
	}

	if (!cf_item_find_next(cs, NULL)) {
		cf_log_err_cs(cs, "'switch' statements cannot be empty.");
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

	csingle = do_compile_modgroup(parent, component, cs, GROUPTYPE_SIMPLE, GROUPTYPE_SIMPLE);
	if (!csingle) return NULL;
	csingle->type = MOD_SWITCH;
	return csingle;
}

static modcallable *do_compile_modforeach(modcallable *parent,
					  UNUSED int component, CONF_SECTION *cs,
					  const char *name2)
{
	modcallable *csingle;

	if (!cf_section_name2(cs)) {
		cf_log_err_cs(cs,
			   "You must specify an attribute to loop over in 'foreach'.");
		return NULL;
	}

	if (!cf_item_find_next(cs, NULL)) {
		cf_log_err_cs(cs, "'foreach' blocks cannot be empty.");
		return NULL;
	}

	csingle= do_compile_modgroup(parent, component, cs,
				     GROUPTYPE_SIMPLE, GROUPTYPE_SIMPLE);
	if (!csingle) return NULL;
	csingle->name = name2;
	csingle->type = MOD_FOREACH;
	return csingle;
}

static modcallable *do_compile_modbreak(modcallable *parent, UNUSED int component)
{
	modcallable *csingle;

	csingle = do_compile_modgroup(parent, component, NULL,
				      GROUPTYPE_SIMPLE, GROUPTYPE_SIMPLE);
	if (!csingle) return NULL;
	csingle->name = "";
	csingle->type = MOD_BREAK;
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
		if (!name2) name2 = "";

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
			modgroup *g;

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
			*modname = name2;

			g = mod_callabletogroup(csingle);
			g->cond = cf_data_find(g->cs, "if");
			rad_assert(g->cond != NULL);

			return csingle;

		} else 	if (strcmp(modrefname, "elsif") == 0) {
			modgroup *g;

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
			*modname = name2;

			g = mod_callabletogroup(csingle);
			g->cond = cf_data_find(g->cs, "if");
			rad_assert(g->cond != NULL);

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

		} else 	if (strcmp(modrefname, "foreach") == 0) {
			*modname = name2;

			csingle = do_compile_modforeach(parent, component, cs,
							name2);
			if (!csingle) return NULL;

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
			cf_log_module(cs, "Loading virtual module %s",
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

#ifdef WITH_UNLANG
	if (strcmp(modrefname, "break") == 0) {
		return do_compile_modbreak(parent, component);
	}
#endif

	/*
	 *	Not a virtual module.  It must be a real module.
	 */
	modules = cf_section_find("modules");
	this = NULL;

	if (modules) {
		/*
		 *	Try to load the optional module.
		 */
		const char *realname = modrefname;
		if (realname[0] == '-') realname++;

		/*
		 *	As of v3, only known modules are in the
		 *	"modules" section.
		 */
		if (cf_section_sub_find_name2(modules, NULL, realname)) {
			this = find_module_instance(modules, realname, 1);
			if (!this && (realname != modrefname)) {
				return NULL;
			}

		} else {
			/*
			 *	We were asked to MAYBE load it and it
			 *	doesn't exist.  Return a soft error.
			 */
			if (realname != modrefname) {
				*modname = modrefname;
				return NULL;
			}
		}
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
				
				this = find_module_instance(modules, buffer, 1);
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

		/*
		 *	Call a server.  This should really be deleted...
		 */
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
	g->children = NULL;
	g->cs = cs;

	c = mod_grouptocallable(g);
	c->parent = parent;
	c->type = MOD_GROUP;
	c->next = NULL;
	memset(c->actions, 0, sizeof(c->actions));

	if (!cs) {		/* only for "break" */
		c->name = "";
		goto set_codes;
	}

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
					if (cf_item_is_pair(ci) &&
					    cf_pair_attr(cf_itemtopair(ci))[0] == '-') {
						continue;
					}

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

set_codes:
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
	c = *pc;

	if (c->type != MOD_SINGLE) {
		modgroup *g = mod_callabletogroup(c);

		for(loop = g->children;
		    loop ;
		    loop = next) {
			next = loop->next;
			modcallable_free(&loop);
		}
		talloc_free(g->map);
	}
	free(c);
	*pc = NULL;
}
