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
					rlm_components_t, CONF_SECTION *,
					int, int, int);

/* Actions may be a positive integer (the highest one returned in the group
 * will be returned), or the keyword "return", represented here by
 * MOD_ACTION_RETURN, to cause an immediate return.
 * There's also the keyword "reject", represented here by MOD_ACTION_REJECT
 * to cause an immediate reject. */
#define MOD_ACTION_RETURN  (-1)
#define MOD_ACTION_REJECT  (-2)

/* Here are our basic types: modcallable, modgroup, and modsingle. For an
 * explanation of what they are all about, see doc/configurable_failover.rst */
struct modcallable {
	modcallable *parent;
	struct modcallable *next;
	char const *name;
	char const *debug_name;
	enum { MOD_SINGLE = 1, MOD_GROUP, MOD_LOAD_BALANCE, MOD_REDUNDANT_LOAD_BALANCE,
#ifdef WITH_UNLANG
	       MOD_IF, MOD_ELSE, MOD_ELSIF, MOD_UPDATE, MOD_SWITCH, MOD_CASE,
	       MOD_FOREACH, MOD_BREAK, MOD_RETURN,
#endif
	       MOD_POLICY, MOD_REFERENCE, MOD_XLAT } type;
	rlm_components_t method;
	int actions[RLM_MODULE_NUMCODES];
};

#define MOD_LOG_OPEN_BRACE RDEBUG2("%s {", c->debug_name)

#define MOD_LOG_CLOSE_BRACE RDEBUG2("} # %s = %s", c->debug_name, fr_int2str(mod_rcode_table, result, "<invalid>"))

typedef struct {
	modcallable		mc;		/* self */
	enum {
		GROUPTYPE_SIMPLE = 0,
		GROUPTYPE_REDUNDANT,
		GROUPTYPE_COUNT
	} grouptype;				/* after mc */
	modcallable		*children;
	modcallable		*tail;		/* of the children list */
	CONF_SECTION		*cs;
	vp_map_t	*map;		/* update */
	vp_tmpl_t	*vpt;		/* switch */
	fr_cond_t		*cond;		/* if/elsif */
	bool			done_pass2;
} modgroup;

typedef struct {
	modcallable mc;
	module_instance_t *modinst;
} modsingle;

typedef struct {
	modcallable mc;
	char const *ref_name;
	CONF_SECTION *ref_cs;
} modref;

typedef struct {
	modcallable mc;
	int exec;
	char *xlat_name;
} modxlat;

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
static void add_child(modgroup *g, modcallable *c)
{
	if (!c) return;

	(void) talloc_steal(g, c);

	if (!g->children) {
		g->children = g->tail = c;
	} else {
		rad_assert(g->tail->next == NULL);
		g->tail->next = c;
		g->tail = c;
	}

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
	char const *attr, *value;

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
static char const * const comp2str[] = {
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

static rlm_rcode_t CC_HINT(nonnull) call_modsingle(rlm_components_t component, modsingle *sp, REQUEST *request)
{
	int blocked;
	int indent = request->log.indent;

	/*
	 *	If the request should stop, refuse to do anything.
	 */
	blocked = (request->master_state == REQUEST_STOP_PROCESSING);
	if (blocked) return RLM_MODULE_NOOP;

	RDEBUG3("modsingle[%s]: calling %s (%s)",
		comp2str[component], sp->modinst->name,
		sp->modinst->entry->name);
	request->log.indent = 0;

	if (sp->modinst->force) {
		request->rcode = sp->modinst->code;
		goto fail;
	}

	/*
	 *	For logging unresponsive children.
	 */
	request->module = sp->modinst->name;

	safe_lock(sp->modinst);
	request->rcode = sp->modinst->entry->module->methods[component](sp->modinst->insthandle, request);
	safe_unlock(sp->modinst);

	request->module = "";

	/*
	 *	Wasn't blocked, and now is.  Complain!
	 */
	blocked = (request->master_state == REQUEST_STOP_PROCESSING);
	if (blocked) {
		RWARN("Module %s became unblocked", sp->modinst->entry->name);
	}

 fail:
	request->log.indent = indent;
	RDEBUG3("modsingle[%s]: returned from %s (%s)",
	       comp2str[component], sp->modinst->name,
	       sp->modinst->entry->name);

	return request->rcode;
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


extern char const *unlang_keyword[];

char const *unlang_keyword[] = {
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
	"return",
#endif
	"policy",
	"reference",
	"xlat",
	NULL
};

static char const modcall_spaces[] = "                                                                ";

#define MODCALL_STACK_MAX (32)

/*
 *	Don't call the modules recursively.  Instead, do them
 *	iteratively, and manage the call stack ourselves.
 */
typedef struct modcall_stack_entry_t {
	rlm_rcode_t result;
	int priority;
	int unwind;		/* unwind to this one if it exists */
	modcallable *c;
} modcall_stack_entry_t;


static bool modcall_recurse(REQUEST *request, rlm_components_t component, int depth,
			    modcall_stack_entry_t *entry, bool do_next_sibling);

/*
 *	Call a child of a block.
 */
static void modcall_child(REQUEST *request, rlm_components_t component, int depth,
			  modcall_stack_entry_t *entry, modcallable *c,
			  rlm_rcode_t *result, bool do_next_sibling)
{
	modcall_stack_entry_t *next;

	if (depth >= MODCALL_STACK_MAX) {
		ERROR("Internal sanity check failed: module stack is too deep");
		fr_exit(1);
	}

	/*
	 *	Initialize the childs stack frame.
	 */
	next = entry + 1;
	next->c = c;
	next->result = entry->result;
	next->priority = 0;
	next->unwind = 0;

	if (!modcall_recurse(request, component,
			     depth, next, do_next_sibling)) {
		*result = RLM_MODULE_FAIL;
		 return;
	}

	/*
	 *	Unwind back up the stack
	 */
	if (next->unwind != 0) {
		entry->unwind = next->unwind;
	}

	*result = next->result;

	return;
}


/*
 *	Interpret the various types of blocks.
 */
static bool modcall_recurse(REQUEST *request, rlm_components_t component, int depth,
			    modcall_stack_entry_t *entry, bool do_next_sibling)
{
	bool if_taken, was_if;
	modcallable *c;
	int priority;
	rlm_rcode_t result;

	was_if = if_taken = false;
	result = RLM_MODULE_UNKNOWN;
	RINDENT();

redo:
	priority = -1;
	c = entry->c;

	/*
	 *	Nothing more to do.  Return the code and priority
	 *	which was set by the caller.
	 */
	if (!c) goto finish;

	if (fr_debug_lvl >= 3) {
		VERIFY_REQUEST(request);
	}

	rad_assert(c->debug_name != NULL); /* if this happens, all bets are off. */

	/*
	 *	We've been asked to stop.  Do so.
	 */
	if ((request->master_state == REQUEST_STOP_PROCESSING) ||
	    (request->parent &&
	     (request->parent->master_state == REQUEST_STOP_PROCESSING))) {
		entry->result = RLM_MODULE_FAIL;
		entry->priority = 9999;
		goto finish;
	}

#ifdef WITH_UNLANG
	/*
	 *	Handle "if" conditions.
	 */
	if (c->type == MOD_IF) {
		int condition;
		modgroup *g;

	mod_if:
		g = mod_callabletogroup(c);
		rad_assert(g->cond != NULL);

		RDEBUG2("%s %s{", unlang_keyword[c->type], c->name);

		condition = radius_evaluate_cond(request, result, 0, g->cond);
		if (condition < 0) {
			condition = false;
			REDEBUG("Failed retrieving values required to evaluate condition");
		} else {
			RDEBUG2("%s %s -> %s",
				unlang_keyword[c->type],
				c->name, condition ? "TRUE" : "FALSE");
		}

		/*
		 *	Didn't pass.  Remember that.
		 */
		if (!condition) {
			was_if = true;
			if_taken = false;
			goto next_sibling;
		}

		/*
		 *	We took the "if".  Go recurse into its' children.
		 */
		was_if = true;
		if_taken = true;
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
			RDEBUG2("... skipping %s: Preceding \"if\" was taken",
				unlang_keyword[c->type]);
			was_if = true;
			if_taken = true;
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
			RDEBUG2("... skipping %s: No preceding \"if\"",
				unlang_keyword[c->type]);
			goto next_sibling;
		}

		if (if_taken) {
			RDEBUG2("... skipping %s: Preceding \"if\" was taken",
				unlang_keyword[c->type]);
			was_if = false;
			if_taken = false;
			goto next_sibling;
		}

		/*
		 *	We need to process it.  Go do that.
		 */
		was_if = false;
		if_taken = false;
		goto do_children;
	} /* MOD_ELSE */

	/*
	 *	We're no longer processing if/else/elsif.  Reset the
	 *	trackers for those conditions.
	 */
	was_if = false;
	if_taken = false;
#endif	/* WITH_UNLANG */

	if (c->type == MOD_SINGLE) {
		modsingle *sp;

		/*
		 *	Process a stand-alone child, and fall through
		 *	to dealing with it's parent.
		 */
		sp = mod_callabletosingle(c);

		result = call_modsingle(c->method, sp, request);
		RDEBUG2("[%s] = %s", c->name ? c->name : "",
			fr_int2str(mod_rcode_table, result, "<invalid>"));
		goto calculate_result;
	} /* MOD_SINGLE */

#ifdef WITH_UNLANG
	/*
	 *	Update attribute(s)
	 */
	if (c->type == MOD_UPDATE) {
		int rcode;
		modgroup *g = mod_callabletogroup(c);
		vp_map_t *map;

		MOD_LOG_OPEN_BRACE;
		RINDENT();
		for (map = g->map; map != NULL; map = map->next) {
			rcode = map_to_request(request, map, map_to_vp, NULL);
			if (rcode < 0) {
				result = (rcode == -2) ? RLM_MODULE_INVALID : RLM_MODULE_FAIL;
				REXDENT();
				MOD_LOG_CLOSE_BRACE;
				goto calculate_result;
			}
		}
		REXDENT();
		result = RLM_MODULE_NOOP;
		MOD_LOG_CLOSE_BRACE;
		goto calculate_result;
	} /* MOD_IF */

	/*
	 *	Loop over a set of attributes.
	 */
	if (c->type == MOD_FOREACH) {
		int i, foreach_depth = -1;
		VALUE_PAIR *vps, *vp;
		modcall_stack_entry_t *next = NULL;
		vp_cursor_t copy;
		modgroup *g = mod_callabletogroup(c);

		if (depth >= MODCALL_STACK_MAX) {
			ERROR("Internal sanity check failed: module stack is too deep");
			fr_exit(1);
		}

		/*
		 *	Figure out how deep we are in nesting by looking at request_data
		 *	stored previously.
		 */
		for (i = 0; i < 8; i++) {
			if (!request_data_reference(request, (void *)radius_get_vp, i)) {
				foreach_depth = i;
				break;
			}
		}

		if (foreach_depth < 0) {
			REDEBUG("foreach Nesting too deep!");
			result = RLM_MODULE_FAIL;
			goto calculate_result;
		}

		/*
		 *	Copy the VPs from the original request, this ensures deterministic
		 *	behaviour if someone decides to add or remove VPs in the set were
		 *	iterating over.
		 */
		if (tmpl_copy_vps(request, &vps, request, g->vpt) < 0) {	/* nothing to loop over */
			MOD_LOG_OPEN_BRACE;
			result = RLM_MODULE_NOOP;
			MOD_LOG_CLOSE_BRACE;
			goto calculate_result;
		}

		rad_assert(vps != NULL);
		fr_cursor_init(&copy, &vps);

		RDEBUG2("foreach %s ", c->name);

		/*
		 *	This is the actual body of the foreach loop
		 */
		for (vp = fr_cursor_first(&copy);
		     vp != NULL;
		     vp = fr_cursor_next(&copy)) {
#ifndef NDEBUG
			if (fr_debug_lvl >= 2) {
				char buffer[1024];

				vp_prints_value(buffer, sizeof(buffer), vp, '"');
				RDEBUG2("# Foreach-Variable-%d = %s", foreach_depth, buffer);
			}
#endif

			/*
			 *	Add the vp to the request, so that
			 *	xlat.c, xlat_foreach() can find it.
			 */
			request_data_add(request, (void *)radius_get_vp, foreach_depth, &vp, false);

			/*
			 *	Initialize the childs stack frame.
			 */
			next = entry + 1;
			next->c = g->children;
			next->result = entry->result;
			next->priority = 0;
			next->unwind = 0;

			if (!modcall_recurse(request, component, depth + 1, next, true)) {
				break;
			}

			/*
			 *	We've been asked to unwind to the
			 *	enclosing "foreach".  We're here, so
			 *	we can stop unwinding.
			 */
			if (next->unwind == MOD_BREAK) {
				entry->unwind = 0;
				break;
			}

			/*
			 *	Unwind all the way.
			 */
			if (next->unwind == MOD_RETURN) {
				entry->unwind = MOD_RETURN;
				break;
			}
		} /* loop over VPs */

		/*
		 *	Free the copied vps and the request data
		 *	If we don't remove the request data, something could call
		 *	the xlat outside of a foreach loop and trigger a segv.
		 */
		fr_pair_list_free(&vps);
		request_data_get(request, (void *)radius_get_vp, foreach_depth);

		rad_assert(next != NULL);
		result = next->result;
		priority = next->priority;
		MOD_LOG_CLOSE_BRACE;
		goto calculate_result;
	} /* MOD_FOREACH */

	/*
	 *	Break out of a "foreach" loop, or return from a nested
	 *	group.
	 */
	if ((c->type == MOD_BREAK) || (c->type == MOD_RETURN)) {
		int i;
		VALUE_PAIR **copy_p;

		RDEBUG2("%s", unlang_keyword[c->type]);

		for (i = 8; i >= 0; i--) {
			copy_p = request_data_get(request, (void *)radius_get_vp, i);
			if (copy_p) {
				if (c->type == MOD_BREAK) {
					RDEBUG2("# break Foreach-Variable-%d", i);
					break;
				}
			}
		}

		/*
		 *	Leave result / priority on the stack, and stop processing the section.
		 */
		entry->unwind = c->type;
		goto finish;
	} /* MOD_BREAK */

#endif	  /* WITH_UNLANG */

	/*
	 *	Child is a group that has children of it's own.
	 */
	if ((c->type == MOD_GROUP) || (c->type == MOD_POLICY)
#ifdef WITH_UNLANG
	    || (c->type == MOD_CASE)
#endif
		) {
		modgroup *g;

#ifdef WITH_UNLANG
	do_children:
#endif
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

			RDEBUG2("%s { ... } # empty sub-section is ignored", c->name);
			goto next_sibling;
		}

		MOD_LOG_OPEN_BRACE;
		modcall_child(request, component,
			      depth + 1, entry, g->children,
			      &result, true);
		MOD_LOG_CLOSE_BRACE;
		goto calculate_result;
	} /* MOD_GROUP */

#ifdef WITH_UNLANG
	if (c->type == MOD_SWITCH) {
		modcallable *this, *found, *null_case;
		modgroup *g, *h;
		fr_cond_t cond;
		value_data_t data;
		vp_map_t map;
		vp_tmpl_t vpt;

		MOD_LOG_OPEN_BRACE;

		g = mod_callabletogroup(c);

		memset(&cond, 0, sizeof(cond));
		memset(&map, 0, sizeof(map));

		cond.type = COND_TYPE_MAP;
		cond.data.map = &map;

		map.op = T_OP_CMP_EQ;
		map.ci = cf_section_to_item(g->cs);

		rad_assert(g->vpt != NULL);

		null_case = found = NULL;
		data.ptr = NULL;

		/*
		 *	The attribute doesn't exist.  We can skip
		 *	directly to the default 'case' statement.
		 */
		if ((g->vpt->type == TMPL_TYPE_ATTR) && (tmpl_find_vp(NULL, request, g->vpt) < 0)) {
		find_null_case:
			for (this = g->children; this; this = this->next) {
				rad_assert(this->type == MOD_CASE);

				h = mod_callabletogroup(this);
				if (h->vpt) continue;

				found = this;
				break;
			}

			goto do_null_case;
		}

		/*
		 *	Expand the template if necessary, so that it
		 *	is evaluated once instead of for each 'case'
		 *	statement.
		 */
		if ((g->vpt->type == TMPL_TYPE_XLAT_STRUCT) ||
		    (g->vpt->type == TMPL_TYPE_XLAT) ||
		    (g->vpt->type == TMPL_TYPE_EXEC)) {
			char *p;
			ssize_t len;

			len = tmpl_aexpand(request, &p, request, g->vpt, NULL, NULL);
			if (len < 0) goto find_null_case;
			data.strvalue = p;
			tmpl_init(&vpt, TMPL_TYPE_LITERAL, data.strvalue, len);
		}

		/*
		 *	Find either the exact matching name, or the
		 *	"case {...}" statement.
		 */
		for (this = g->children; this; this = this->next) {
			rad_assert(this->type == MOD_CASE);

			h = mod_callabletogroup(this);

			/*
			 *	Remember the default case
			 */
			if (!h->vpt) {
				if (!null_case) null_case = this;
				continue;
			}

			/*
			 *	If we're switching over an attribute
			 *	AND we haven't pre-parsed the data for
			 *	the case statement, then cast the data
			 *	to the type of the attribute.
			 */
			if ((g->vpt->type == TMPL_TYPE_ATTR) &&
			    (h->vpt->type != TMPL_TYPE_DATA)) {
				map.rhs = g->vpt;
				map.lhs = h->vpt;
				cond.cast = g->vpt->tmpl_da;

				/*
				 *	Remove unnecessary casting.
				 */
				if ((h->vpt->type == TMPL_TYPE_ATTR) &&
				    (g->vpt->tmpl_da->type == h->vpt->tmpl_da->type)) {
					cond.cast = NULL;
				}

				/*
				 *	Use the pre-expanded string.
				 */
			} else if ((g->vpt->type == TMPL_TYPE_XLAT_STRUCT) ||
				   (g->vpt->type == TMPL_TYPE_XLAT) ||
				   (g->vpt->type == TMPL_TYPE_EXEC)) {
				map.rhs = h->vpt;
				map.lhs = &vpt;
				cond.cast = NULL;

				/*
				 *	Else evaluate the 'switch' statement.
				 */
			} else {
				map.rhs = h->vpt;
				map.lhs = g->vpt;
				cond.cast = NULL;
			}

			if (radius_evaluate_map(request, RLM_MODULE_UNKNOWN, 0,
						&cond) == 1) {
				found = this;
				break;
			}
		}

		if (!found) found = null_case;

	do_null_case:
		talloc_free(data.ptr);
		modcall_child(request, component, depth + 1, entry, found, &result, true);
		MOD_LOG_CLOSE_BRACE;
		goto calculate_result;
	} /* MOD_SWITCH */
#endif

	if ((c->type == MOD_LOAD_BALANCE) ||
	    (c->type == MOD_REDUNDANT_LOAD_BALANCE)) {
		uint32_t count = 0;
		modcallable *this, *found;
		modgroup *g;

		MOD_LOG_OPEN_BRACE;

		g = mod_callabletogroup(c);
		found = g->children;
		rad_assert(g->children != NULL);

		/*
		 *	Choose a child at random.
		 */
		for (this = g->children; this; this = this->next) {
			count++;

			if ((count * (fr_rand() & 0xffff)) < (uint32_t) 0x10000) {
				found = this;
			}
		}

		if (c->type == MOD_LOAD_BALANCE) {
			modcall_child(request, component,
				      depth + 1, entry, found,
				      &result, false);

		} else {
			this = found;

			do {
				modcall_child(request, component,
					      depth + 1, entry, this,
					      &result, false);
				if (this->actions[result] == MOD_ACTION_RETURN) {
					priority = -1;
					break;
				}

				this = this->next;
				if (!this) this = g->children;
			} while (this != found);
		}
		MOD_LOG_CLOSE_BRACE;
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
			RWDEBUG("Suppressing recursive call to server %s", server);
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
			radius_xlat(buffer, sizeof(buffer), request, mx->xlat_name, NULL, NULL);
		} else {
			RDEBUG("`%s`", mx->xlat_name);
			radius_exec_program(request, NULL, 0, NULL, request, mx->xlat_name, request->packet->vps,
					    false, true, EXEC_TIMEOUT);
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


	rad_assert(result != RLM_MODULE_UNKNOWN);

	/*
	 *	The child's action says return.  Do so.
	 */
	if ((c->actions[result] == MOD_ACTION_RETURN) &&
	    (priority <= 0)) {
		entry->result = result;
		goto finish;
	}

	/*
	 *	If "reject", break out of the loop and return
	 *	reject.
	 */
	if (c->actions[result] == MOD_ACTION_REJECT) {
		entry->result = RLM_MODULE_REJECT;
		goto finish;
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

#ifdef WITH_UNLANG
	/*
	 *	If we're processing a "case" statement, we return once
	 *	it's done, rather than going to the next "case" statement.
	 */
	if (c->type == MOD_CASE) goto finish;
#endif

	/*
	 *	If we've been told to stop processing
	 *	it, do so.
	 */
	if (entry->unwind == MOD_BREAK) {
		RDEBUG2("# unwind to enclosing foreach");
		goto finish;
	}

	if (entry->unwind == MOD_RETURN) {
		goto finish;
	}

next_sibling:
	if (do_next_sibling) {
		entry->c = entry->c->next;

		if (entry->c) goto redo;
	}

finish:
	/*
	 *	And we're done!
	 */
	REXDENT();
	return true;
}


/** Call a module, iteratively, with a local stack, rather than recursively
 *
 * What did Paul Graham say about Lisp...?
 */
int modcall(rlm_components_t component, modcallable *c, REQUEST *request)
{
	modcall_stack_entry_t stack[MODCALL_STACK_MAX];

#ifndef NDEBUG
	memset(stack, 0, sizeof(stack));
#endif
	/*
	 *	Set up the initial stack frame.
	 */
	stack[0].c = c;
	stack[0].result = default_component_results[component];
	stack[0].priority = 0;
	stack[0].unwind = 0;

	/*
	 *	Call the main handler.
	 */
	if (!modcall_recurse(request, component, 0, &stack[0], true)) {
		return RLM_MODULE_FAIL;
	}

	/*
	 *	Return the result.
	 */
	return stack[0].result;
}


#if 0
static char const *action2str(int action)
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
		      unlang_keyword[c->type]);
		for(p = g->children;p;p = p->next)
			dump_mc(p, indent+1);
	} /* else ignore it for now */

	for(i = 0; i<RLM_MODULE_NUMCODES; ++i) {
		DEBUG("%.*s%s = %s", indent+1, "\t\t\t\t\t\t\t\t\t\t\t",
		      fr_int2str(mod_rcode_table, i, "<invalid>"),
		      action2str(c->actions[i]));
	}

	DEBUG("%.*s}", indent, "\t\t\t\t\t\t\t\t\t\t\t");
}

static void dump_tree(rlm_components_t comp, modcallable *c)
{
	DEBUG("[%s]", comp2str[comp]);
	dump_mc(c, 0);
}
#else
#define dump_tree(a, b)
#endif

/* These are the default actions. For each component, the group{} block
 * behaves like the code from the old module_*() function. redundant{}
 * are based on my guesses of what they will be used for. --Pac. */
static const int
defaultactions[MOD_COUNT][GROUPTYPE_COUNT][RLM_MODULE_NUMCODES] =
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
		}
	}
#endif
};

static const int authtype_actions[GROUPTYPE_COUNT][RLM_MODULE_NUMCODES] =
{
	/* group */
	{
		MOD_ACTION_RETURN,	/* reject   */
		MOD_ACTION_RETURN,	/* fail     */
		4,			/* ok       */
		MOD_ACTION_RETURN,	/* handled  */
		MOD_ACTION_RETURN,	/* invalid  */
		MOD_ACTION_RETURN,	/* userlock */
		1,			/* notfound */
		2,			/* noop     */
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
	}
};

/** Validate and fixup a map that's part of an update section.
 *
 * @param map to validate.
 * @param ctx data to pass to fixup function (currently unused).
 * @return 0 if valid else -1.
 */
int modcall_fixup_update(vp_map_t *map, UNUSED void *ctx)
{
	CONF_PAIR *cp = cf_item_to_pair(map->ci);

	/*
	 *	Anal-retentive checks.
	 */
	if (DEBUG_ENABLED3) {
		if ((map->lhs->type == TMPL_TYPE_ATTR) && (map->lhs->name[0] != '&')) {
			WARN("%s[%d]: Please change attribute reference to '&%s %s ...'",
			     cf_pair_filename(cp), cf_pair_lineno(cp),
			     map->lhs->name, fr_int2str(fr_tokens, map->op, "<INVALID>"));
		}

		if ((map->rhs->type == TMPL_TYPE_ATTR) && (map->rhs->name[0] != '&')) {
			WARN("%s[%d]: Please change attribute reference to '... %s &%s'",
			     cf_pair_filename(cp), cf_pair_lineno(cp),
			     fr_int2str(fr_tokens, map->op, "<INVALID>"), map->rhs->name);
		}
	}

	/*
	 *	Values used by unary operators should be literal ANY
	 *
	 *	We then free the template and alloc a NULL one instead.
	 */
	if (map->op == T_OP_CMP_FALSE) {
	 	if ((map->rhs->type != TMPL_TYPE_LITERAL) || (strcmp(map->rhs->name, "ANY") != 0)) {
			WARN("%s[%d] Wildcard deletion MUST use '!* ANY'",
			     cf_pair_filename(cp), cf_pair_lineno(cp));
		}

		TALLOC_FREE(map->rhs);

		map->rhs = tmpl_alloc(map, TMPL_TYPE_NULL, NULL, 0);
	}

	/*
	 *	Lots of sanity checks for insane people...
	 */

	/*
	 *	What exactly where you expecting to happen here?
	 */
	if ((map->lhs->type == TMPL_TYPE_ATTR) &&
	    (map->rhs->type == TMPL_TYPE_LIST)) {
		cf_log_err(map->ci, "Can't copy list into an attribute");
		return -1;
	}

	/*
	 *	Depending on the attribute type, some operators are disallowed.
	 */
	if ((map->lhs->type == TMPL_TYPE_ATTR) && (!fr_assignment_op[map->op] && !fr_equality_op[map->op])) {
		cf_log_err(map->ci, "Invalid operator \"%s\" in update section.  "
			   "Only assignment or filter operators are allowed",
			   fr_int2str(fr_tokens, map->op, "<INVALID>"));
		return -1;
	}

	if (map->lhs->type == TMPL_TYPE_LIST) {
		/*
		 *	Can't copy an xlat expansion or literal into a list,
		 *	we don't know what type of attribute we'd need
		 *	to create.
		 *
		 *	The only exception is where were using a unary
		 *	operator like !*.
		 */
	    	if (map->op != T_OP_CMP_FALSE) switch (map->rhs->type) {
	    	case TMPL_TYPE_XLAT:
	    	case TMPL_TYPE_LITERAL:
			cf_log_err(map->ci, "Can't copy value into list (we don't know which attribute to create)");
			return -1;

		default:
			break;
		}

		/*
		 *	Only += and :=, and !* operators are supported
		 *	for lists.
		 */
		switch (map->op) {
		case T_OP_CMP_FALSE:
			break;

		case T_OP_ADD:
			if ((map->rhs->type != TMPL_TYPE_LIST) &&
			    (map->rhs->type != TMPL_TYPE_EXEC)) {
				cf_log_err(map->ci, "Invalid source for list assignment '%s += ...'", map->lhs->name);
				return -1;
			}
			break;

		case T_OP_SET:
			if (map->rhs->type == TMPL_TYPE_EXEC) {
				WARN("%s[%d]: Please change ':=' to '=' for list assignment",
				     cf_pair_filename(cp), cf_pair_lineno(cp));
			}

			if (map->rhs->type != TMPL_TYPE_LIST) {
				cf_log_err(map->ci, "Invalid source for list assignment '%s := ...'", map->lhs->name);
				return -1;
			}
			break;

		case T_OP_EQ:
			if (map->rhs->type != TMPL_TYPE_EXEC) {
				cf_log_err(map->ci, "Invalid source for list assignment '%s = ...'", map->lhs->name);
				return -1;
			}
			break;

		default:
			cf_log_err(map->ci, "Operator \"%s\" not allowed for list assignment",
				   fr_int2str(fr_tokens, map->op, "<INVALID>"));
			return -1;
		}
	}

	/*
	 *	If the map has a unary operator there's no further
	 *	processing we need to, as RHS is unused.
	 */
	if (map->op == T_OP_CMP_FALSE) return 0;

	/*
	 *	If LHS is an attribute, and RHS is a literal, we can
	 *	preparse the information into a TMPL_TYPE_DATA.
	 *
	 *	Unless it's a unary operator in which case we
	 *	ignore map->rhs.
	 */
	if ((map->lhs->type == TMPL_TYPE_ATTR) && (map->rhs->type == TMPL_TYPE_LITERAL)) {
		/*
		 *	It's a literal string, just copy it.
		 *	Don't escape anything.
		 */
		if (!cf_new_escape &&
		    (map->lhs->tmpl_da->type == PW_TYPE_STRING) &&
		    (cf_pair_value_type(cp) == T_SINGLE_QUOTED_STRING)) {
			tmpl_cast_in_place_str(map->rhs);

		} else {
			/*
			 *	RHS is hex, try to parse it as
			 *	type-specific data.
			 */
			if (map->lhs->auto_converted &&
			    (map->rhs->name[0] == '0') && (map->rhs->name[1] == 'x') &&
			    (map->rhs->len > 2) && ((map->rhs->len & 0x01) == 0)) {
				vp_tmpl_t *vpt = map->rhs;
				map->rhs = NULL;

				if (!map_cast_from_hex(map, T_BARE_WORD, vpt->name)) {
					map->rhs = vpt;
					cf_log_err(map->ci, "Cannot parse RHS hex as the data type of the attribute %s", map->lhs->tmpl_da->name);
					return -1;
				}
				talloc_free(vpt);

			} else if (tmpl_cast_in_place(map->rhs, map->lhs->tmpl_da->type, map->lhs->tmpl_da) < 0) {
				cf_log_err(map->ci, "%s", fr_strerror());
				return -1;
			}

			/*
			 *	Fixup LHS da if it doesn't match the type
			 *	of the RHS.
			 */
			if (map->lhs->tmpl_da->type != map->rhs->tmpl_data_type) {
				DICT_ATTR const *da;

				da = dict_attrbytype(map->lhs->tmpl_da->attr, map->lhs->tmpl_da->vendor,
						     map->rhs->tmpl_data_type);
				if (!da) {
					cf_log_err(map->ci, "Cannot find %s variant of attribute \"%s\"",
						   fr_int2str(dict_attr_types, map->rhs->tmpl_data_type,
							      "<INVALID>"), map->lhs->tmpl_da->name);
					return -1;
				}
				map->lhs->tmpl_da = da;
			}
		}
	} /* else we can't precompile the data */

	return 0;
}


#ifdef WITH_UNLANG
static modcallable *do_compile_modupdate(modcallable *parent, rlm_components_t component,
					 CONF_SECTION *cs, char const *name2)
{
	int rcode;
	modgroup *g;
	modcallable *csingle;

	vp_map_t *head;

	/*
	 *	This looks at cs->name2 to determine which list to update
	 */
	rcode = map_afrom_cs(&head, cs, PAIR_LIST_REQUEST, PAIR_LIST_REQUEST, modcall_fixup_update, NULL, 128);
	if (rcode < 0) return NULL; /* message already printed */
	if (!head) {
		cf_log_err_cs(cs, "'update' sections cannot be empty");
		return NULL;
	}

	g = talloc_zero(parent, modgroup);
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

	memcpy(csingle->actions, defaultactions[component][GROUPTYPE_SIMPLE],
	       sizeof(csingle->actions));

	g->grouptype = GROUPTYPE_SIMPLE;
	g->children = NULL;
	g->cs = cs;
	g->map = talloc_steal(g, head);

	return csingle;
}


static modcallable *do_compile_modswitch (modcallable *parent, rlm_components_t component, CONF_SECTION *cs)
{
	CONF_ITEM *ci;
	FR_TOKEN type;
	char const *name2;
	bool had_seen_default = false;
	modcallable *csingle;
	modgroup *g;
	ssize_t slen;
	vp_tmpl_t *vpt;

	name2 = cf_section_name2(cs);
	if (!name2) {
		cf_log_err_cs(cs, "You must specify a variable to switch over for 'switch'");
		return NULL;
	}

	if (!cf_item_find_next(cs, NULL)) {
		cf_log_err_cs(cs, "'switch' statements cannot be empty");
		return NULL;
	}

	/*
	 *	Create the template.  If we fail, AND it's a bare word
	 *	with &Foo-Bar, it MAY be an attribute defined by a
	 *	module.  Allow it for now.  The pass2 checks below
	 *	will fix it up.
	 */
	type = cf_section_name2_type(cs);
	slen = tmpl_afrom_str(cs, &vpt, name2, strlen(name2), type, REQUEST_CURRENT, PAIR_LIST_REQUEST, true);
	if ((slen < 0) && ((type != T_BARE_WORD) || (name2[0] != '&'))) {
		char *spaces, *text;

		fr_canonicalize_error(cs, &spaces, &text, slen, fr_strerror());

		cf_log_err_cs(cs, "Syntax error");
		cf_log_err_cs(cs, "%s", name2);
		cf_log_err_cs(cs, "%s^ %s", spaces, text);

		talloc_free(spaces);
		talloc_free(text);

		return NULL;
	}

	/*
	 *	Otherwise a NULL vpt may refer to an attribute defined
	 *	by a module.  That is checked in pass 2.
	 */

	if (vpt->type == TMPL_TYPE_LIST) {
		cf_log_err_cs(cs, "Syntax error: Cannot switch over list '%s'", name2);
		return NULL;
	}


	/*
	 *	Walk through the children of the switch section,
	 *	ensuring that they're all 'case' statements
	 */
	for (ci = cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(cs, ci)) {
		CONF_SECTION *subcs;
		char const *name1;

		if (!cf_item_is_section(ci)) {
			if (!cf_item_is_pair(ci)) continue;

			cf_log_err(ci, "\"switch\" sections can only have \"case\" subsections");
			talloc_free(vpt);
			return NULL;
		}

		subcs = cf_item_to_section(ci);	/* can't return NULL */
		name1 = cf_section_name1(subcs);

		if (strcmp(name1, "case") != 0) {
			cf_log_err(ci, "\"switch\" sections can only have \"case\" subsections");
			talloc_free(vpt);
			return NULL;
		}

		name2 = cf_section_name2(subcs);
		if (!name2) {
			if (!had_seen_default) {
				had_seen_default = true;
				continue;
			}

			cf_log_err(ci, "Cannot have two 'default' case statements");
			talloc_free(vpt);
			return NULL;
		}
	}

	csingle = do_compile_modgroup(parent, component, cs,
				      GROUPTYPE_SIMPLE,
				      GROUPTYPE_SIMPLE,
				      MOD_SWITCH);
	if (!csingle) {
		talloc_free(vpt);
		return NULL;
	}

	g = mod_callabletogroup(csingle);
	g->vpt = talloc_steal(g, vpt);

	return csingle;
}

static modcallable *do_compile_modcase(modcallable *parent, rlm_components_t component, CONF_SECTION *cs)
{
	int i;
	char const *name2;
	modcallable *csingle;
	modgroup *g;
	vp_tmpl_t *vpt;

	if (!parent || (parent->type != MOD_SWITCH)) {
		cf_log_err_cs(cs, "\"case\" statements may only appear within a \"switch\" section");
		return NULL;
	}

	/*
	 *	case THING means "match THING"
	 *	case       means "match anything"
	 */
	name2 = cf_section_name2(cs);
	if (name2) {
		ssize_t slen;
		FR_TOKEN type;

		type = cf_section_name2_type(cs);

		slen = tmpl_afrom_str(cs, &vpt, name2, strlen(name2), type, REQUEST_CURRENT, PAIR_LIST_REQUEST, true);
		if ((slen < 0) && ((type != T_BARE_WORD) || (name2[0] != '&'))) {
			char *spaces, *text;

			fr_canonicalize_error(cs, &spaces, &text, slen, fr_strerror());

			cf_log_err_cs(cs, "Syntax error");
			cf_log_err_cs(cs, "%s", name2);
			cf_log_err_cs(cs, "%s^ %s", spaces, text);

			talloc_free(spaces);
			talloc_free(text);

			return NULL;
		}

		if (vpt->type == TMPL_TYPE_LIST) {
			cf_log_err_cs(cs, "Syntax error: Cannot match list '%s'", name2);
			return NULL;
		}

		/*
		 *	Otherwise a NULL vpt may refer to an attribute defined
		 *	by a module.  That is checked in pass 2.
		 */

	} else {
		vpt = NULL;
	}

	csingle = do_compile_modgroup(parent, component, cs,
				      GROUPTYPE_SIMPLE,
				      GROUPTYPE_SIMPLE,
				      MOD_CASE);
	if (!csingle) {
		talloc_free(vpt);
		return NULL;
	}

	/*
	 *	The interpretor expects this to be NULL for the
	 *	default case.  do_compile_modgroup sets it to name2,
	 *	unless name2 is NULL, in which case it sets it to name1.
	 */
	csingle->name = name2;

	g = mod_callabletogroup(csingle);
	g->vpt = talloc_steal(g, vpt);

	/*
	 *	Set all of it's codes to return, so that
	 *	when we pick a 'case' statement, we don't
	 *	fall through to processing the next one.
	 */
	for (i = 0; i < RLM_MODULE_NUMCODES; i++) {
		csingle->actions[i] = MOD_ACTION_RETURN;
	}

	return csingle;
}

static modcallable *do_compile_modforeach(modcallable *parent,
					  rlm_components_t component, CONF_SECTION *cs)
{
	FR_TOKEN type;
	char const *name2;
	modcallable *csingle;
	modgroup *g;
	ssize_t slen;
	vp_tmpl_t *vpt;

	name2 = cf_section_name2(cs);
	if (!name2) {
		cf_log_err_cs(cs,
			   "You must specify an attribute to loop over in 'foreach'");
		return NULL;
	}

	if (!cf_item_find_next(cs, NULL)) {
		cf_log_err_cs(cs, "'foreach' blocks cannot be empty");
		return NULL;
	}

	/*
	 *	Create the template.  If we fail, AND it's a bare word
	 *	with &Foo-Bar, it MAY be an attribute defined by a
	 *	module.  Allow it for now.  The pass2 checks below
	 *	will fix it up.
	 */
	type = cf_section_name2_type(cs);
	slen = tmpl_afrom_str(cs, &vpt, name2, strlen(name2), type, REQUEST_CURRENT, PAIR_LIST_REQUEST, true);
	if ((slen < 0) && ((type != T_BARE_WORD) || (name2[0] != '&'))) {
		char *spaces, *text;

		fr_canonicalize_error(cs, &spaces, &text, slen, fr_strerror());

		cf_log_err_cs(cs, "Syntax error");
		cf_log_err_cs(cs, "%s", name2);
		cf_log_err_cs(cs, "%s^ %s", spaces, text);

		talloc_free(spaces);
		talloc_free(text);

		return NULL;
	}

	/*
	 *	If we don't have a negative return code, we must have a vpt
	 *	(mostly to quiet coverity).
	 */
	rad_assert(vpt);

	if ((vpt->type != TMPL_TYPE_ATTR) && (vpt->type != TMPL_TYPE_LIST)) {
		cf_log_err_cs(cs, "MUST use attribute or list reference in 'foreach'");
		return NULL;
	}

	/*
	 *	Fix up the template to iterate over all instances of
	 *	the attribute. In a perfect consistent world, users would do
	 *	foreach &attr[*], but that's taking the consistency thing a bit far.
	 */
	vpt->tmpl_num = NUM_ALL;

	csingle = do_compile_modgroup(parent, component, cs,
				      GROUPTYPE_SIMPLE, GROUPTYPE_SIMPLE,
				      MOD_FOREACH);

	if (!csingle) {
		talloc_free(vpt);
		return NULL;
	}

	g = mod_callabletogroup(csingle);
	g->vpt = vpt;

	return csingle;
}

static modcallable *do_compile_modbreak(modcallable *parent,
					rlm_components_t component, CONF_ITEM const *ci)
{
	CONF_SECTION const *cs = NULL;

	for (cs = cf_item_parent(ci);
	     cs != NULL;
	     cs = cf_item_parent(cf_section_to_item(cs))) {
		if (strcmp(cf_section_name1(cs), "foreach") == 0) {
			break;
		}
	}

	if (!cs) {
		cf_log_err(ci, "'break' can only be used in a 'foreach' section");
		return NULL;
	}

	return do_compile_modgroup(parent, component, NULL,
				   GROUPTYPE_SIMPLE, GROUPTYPE_SIMPLE,
				   MOD_BREAK);
}
#endif

static modcallable *do_compile_modserver(modcallable *parent,
					 rlm_components_t component, CONF_ITEM *ci,
					 char const *name,
					 CONF_SECTION *cs,
					 char const *server)
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

	mr = talloc_zero(parent, modref);

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
				       rlm_components_t component, char const *fmt)
{
	modcallable *csingle;
	modxlat *mx;

	mx = talloc_zero(parent, modxlat);

	csingle = mod_xlattocallable(mx);
	csingle->parent = parent;
	csingle->next = NULL;
	csingle->name = "expand";
	csingle->type = MOD_XLAT;
	csingle->method = component;

	memcpy(csingle->actions, defaultactions[component][GROUPTYPE_SIMPLE],
	       sizeof(csingle->actions));

	mx->xlat_name = talloc_strdup(mx, fmt);
	if (!mx->xlat_name) {
		talloc_free(mx);
		return NULL;
	}

	if (fmt[0] != '%') {
		char *p;
		mx->exec = true;

		strcpy(mx->xlat_name, fmt + 1);
		p = strrchr(mx->xlat_name, '`');
		if (p) *p = '\0';
	}

	return csingle;
}

/*
 *	redundant, etc. can refer to modules or groups, but not much else.
 */
static int all_children_are_modules(CONF_SECTION *cs, char const *name)
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
			CONF_SECTION *subcs = cf_item_to_section(ci);
			char const *name1 = cf_section_name1(subcs);

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
			CONF_PAIR *cp = cf_item_to_pair(ci);
			if (cf_pair_value(cp) != NULL) {
				cf_log_err(ci,
					   "Entry with no value is invalid");
				return 0;
			}
		}
	}

	return 1;
}

/** Load a named module from "instantiate" or "policy".
 *
 * If it's "foo.method", look for "foo", and return "method" as the method
 * we wish to use, instead of the input component.
 *
 * @param[out] pcomponent Where to write the method we found, if any.  If no method is specified
 *	will be set to MOD_COUNT.
 * @param[in] real_name Complete name string e.g. foo.authorize.
 * @param[in] virtual_name Virtual module name e.g. foo.
 * @param[in] method_name Method override (may be NULL) or the method name e.g. authorize.
 * @return the CONF_SECTION specifying the virtual module.
 */
static CONF_SECTION *virtual_module_find_cs(rlm_components_t *pcomponent,
					    char const *real_name, char const *virtual_name, char const *method_name)
{
	CONF_SECTION *cs, *subcs;
	rlm_components_t method = *pcomponent;
	char buffer[256];

	/*
	 *	Turn the method name into a method enum.
	 */
	if (method_name) {
		rlm_components_t i;

		for (i = MOD_AUTHENTICATE; i < MOD_COUNT; i++) {
			if (strcmp(comp2str[i], method_name) == 0) break;
		}

		if (i != MOD_COUNT) {
			method = i;
		} else {
			method_name = NULL;
			virtual_name = real_name;
		}
	}

	/*
	 *	Look for "foo" in the "instantiate" section.  If we
	 *	find it, AND there's no method name, we've found the
	 *	right thing.
	 *
	 *	Return it to the caller, with the updated method.
	 */
	cs = cf_section_find("instantiate");
	if (cs) {
		/*
		 *	Found "foo".  Load it as "foo", or "foo.method".
		 */
		subcs = cf_section_sub_find_name2(cs, NULL, virtual_name);
		if (subcs) {
			*pcomponent = method;
			return subcs;
		}
	}

	/*
	 *	Look for it in "policy".
	 *
	 *	If there's no policy section, we can't do anything else.
	 */
	cs = cf_section_find("policy");
	if (!cs) return NULL;

	/*
	 *	"foo.authorize" means "load policy "foo" as method "authorize".
	 *
	 *	And bail out if there's no policy "foo".
	 */
	if (method_name) {
		subcs = cf_section_sub_find_name2(cs, NULL, virtual_name);
		if (subcs) *pcomponent = method;

		return subcs;
	}

	/*
	 *	"foo" means "look for foo.component" first, to allow
	 *	method overrides.  If that's not found, just look for
	 *	a policy "foo".
	 *
	 */
	snprintf(buffer, sizeof(buffer), "%s.%s",
		 virtual_name, comp2str[method]);
	subcs = cf_section_sub_find_name2(cs, NULL, buffer);
	if (subcs) return subcs;

	return cf_section_sub_find_name2(cs, NULL, virtual_name);
}


/*
 *	Compile one entry of a module call.
 */
static modcallable *do_compile_modsingle(modcallable *parent,
					 rlm_components_t component, CONF_ITEM *ci,
					 int grouptype,
					 char const **modname)
{
	char const *modrefname, *p;
	modsingle *single;
	modcallable *csingle;
	module_instance_t *this;
	CONF_SECTION *cs, *subcs, *modules;
	CONF_SECTION *loop;
	char const *realname;
	rlm_components_t method = component;

	if (cf_item_is_section(ci)) {
		char const *name2;

		cs = cf_item_to_section(ci);
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
						   grouptype, MOD_GROUP);

		} else if (strcmp(modrefname, "redundant") == 0) {
			*modname = name2;

			if (!all_children_are_modules(cs, modrefname)) {
				return NULL;
			}

			return do_compile_modgroup(parent, component, cs,
						   GROUPTYPE_REDUNDANT,
						   grouptype, MOD_GROUP);

		} else if (strcmp(modrefname, "load-balance") == 0) {
			*modname = name2;

			if (!all_children_are_modules(cs, modrefname)) {
				return NULL;
			}

			return do_compile_modgroup(parent, component, cs,
						   GROUPTYPE_SIMPLE,
						   grouptype, MOD_LOAD_BALANCE);

		} else if (strcmp(modrefname, "redundant-load-balance") == 0) {
			*modname = name2;

			if (!all_children_are_modules(cs, modrefname)) {
				return NULL;
			}

			return do_compile_modgroup(parent, component, cs,
						   GROUPTYPE_REDUNDANT,
						   grouptype, MOD_REDUNDANT_LOAD_BALANCE);

#ifdef WITH_UNLANG
		} else 	if (strcmp(modrefname, "if") == 0) {
			if (!cf_section_name2(cs)) {
				cf_log_err(ci, "'if' without condition");
				return NULL;
			}

			*modname = name2;
			csingle= do_compile_modgroup(parent, component, cs,
						     GROUPTYPE_SIMPLE,
						     grouptype, MOD_IF);
			if (!csingle) return NULL;
			*modname = name2;

			return csingle;

		} else 	if (strcmp(modrefname, "elsif") == 0) {
			if (parent &&
			    ((parent->type == MOD_LOAD_BALANCE) ||
			     (parent->type == MOD_REDUNDANT_LOAD_BALANCE))) {
				cf_log_err(ci, "'elsif' cannot be used in this section");
				return NULL;
			}

			if (!cf_section_name2(cs)) {
				cf_log_err(ci, "'elsif' without condition");
				return NULL;
			}

			*modname = name2;
			return do_compile_modgroup(parent, component, cs,
						   GROUPTYPE_SIMPLE,
						   grouptype, MOD_ELSIF);

		} else 	if (strcmp(modrefname, "else") == 0) {
			if (parent &&
			    ((parent->type == MOD_LOAD_BALANCE) ||
			     (parent->type == MOD_REDUNDANT_LOAD_BALANCE))) {
				cf_log_err(ci, "'else' cannot be used in this section section");
				return NULL;
			}

			if (cf_section_name2(cs)) {
				cf_log_err(ci, "Cannot have conditions on 'else'");
				return NULL;
			}

			*modname = name2;
			return  do_compile_modgroup(parent, component, cs,
						    GROUPTYPE_SIMPLE,
						    grouptype, MOD_ELSE);

		} else 	if (strcmp(modrefname, "update") == 0) {
			*modname = name2;

			return do_compile_modupdate(parent, component, cs,
						    name2);

		} else 	if (strcmp(modrefname, "switch") == 0) {
			*modname = name2;

			return do_compile_modswitch (parent, component, cs);

		} else 	if (strcmp(modrefname, "case") == 0) {
			*modname = name2;

			return do_compile_modcase(parent, component, cs);

		} else 	if (strcmp(modrefname, "foreach") == 0) {
			*modname = name2;

			return do_compile_modforeach(parent, component, cs);

#endif
		} /* else it's something like sql { fail = 1 ...} */

	} else if (!cf_item_is_pair(ci)) { /* CONF_DATA or some such */
		return NULL;

		/*
		 *	Else it's a module reference, with updated return
		 *	codes.
		 */
	} else {
		CONF_PAIR *cp = cf_item_to_pair(ci);
		modrefname = cf_pair_attr(cp);

		/*
		 *	Actions (ok = 1), etc. are orthogonal to just
		 *	about everything else.
		 */
		if (cf_pair_value(cp) != NULL) {
			cf_log_err(ci, "Entry is not a reference to a module");
			return NULL;
		}

		/*
		 *	In-place xlat's via %{...}.
		 *
		 *	This should really be removed from the server.
		 */
		if (((modrefname[0] == '%') && (modrefname[1] == '{')) ||
		    (modrefname[0] == '`')) {
			return do_compile_modxlat(parent, component,
						  modrefname);
		}
	}

#ifdef WITH_UNLANG
	/*
	 *	These can't be over-ridden.
	 */
	if (strcmp(modrefname, "break") == 0) {
		if (!cf_item_is_pair(ci)) {
			cf_log_err(ci, "Invalid use of 'break' as section name.");
			return NULL;
		}

		return do_compile_modbreak(parent, component, ci);
	}

	if (strcmp(modrefname, "return") == 0) {
		if (!cf_item_is_pair(ci)) {
			cf_log_err(ci, "Invalid use of 'return' as section name.");
			return NULL;
		}

		return do_compile_modgroup(parent, component, NULL,
					   GROUPTYPE_SIMPLE, GROUPTYPE_SIMPLE,
					   MOD_RETURN);
	}
#endif

	/*
	 *	Run a virtual server.  This is really terrible and
	 *	should be deleted.
	 */
	if (strncmp(modrefname, "server[", 7) == 0) {
		char buffer[256];

		if (!cf_item_is_pair(ci)) {
			cf_log_err(ci, "Invalid syntax");
			return NULL;
		}

		strlcpy(buffer, modrefname + 7, sizeof(buffer));
		p = strrchr(buffer, ']');
		if (!p || p[1] != '\0' || (p == buffer)) {
			cf_log_err(ci, "Invalid server reference in \"%s\".", modrefname);
			return NULL;
		}

		buffer[p - buffer] = '\0';

		cs = cf_section_sub_find_name2(NULL, "server", buffer);
		if (!cs) {
			cf_log_err(ci, "No such server \"%s\".", buffer);
			return NULL;
		}

		/*
		 *	Ignore stupid attempts to over-ride the return
		 *	code.
		 */
		return do_compile_modserver(parent, component, ci,
					    modrefname, cs, buffer);
	}

	/*
	 *	We now have a name.  It can be one of two forms.  A
	 *	bare module name, or a section named for the module,
	 *	with over-rides for the return codes.
	 *
	 *	The name can refer to a real module, in the "modules"
	 *	section.  In that case, the name will be either the
	 *	first or second name of the sub-section of "modules".
	 *
	 *	Or, the name can refer to a policy, in the "policy"
	 *	section.  In that case, the name will be first name of
	 *	the sub-section of "policy".  Unless it's a "redudant"
	 *	block...
	 *
	 *	Or, the name can refer to a "module.method", in which
	 *	case we're calling a different method than normal for
	 *	this section.
	 *
	 *	Or, the name can refer to a virtual module, in the
	 *	"instantiate" section.  In that case, the name will be
	 *	the first of the sub-section of "instantiate".  Unless
	 *	it's a "redudant" block...
	 *
	 *	We try these in sequence, from the bottom up.  This is
	 *	so that things in "instantiate" and "policy" can
	 *	over-ride calls to real modules.
	 */


	/*
	 *	Try:
	 *
	 *	instantiate { ... name { ...} ... }
	 *	instantiate { ... name.method { ...} ... }
	 *	policy { ... name { .. } .. }
	 *	policy { ... name.method { .. } .. }
	 *
	 *	The only difference between things in "instantiate"
	 *	and "policy" is that "instantiate" will cause modules
	 *	to be instantiated in a particular order.
	 */
	subcs = NULL;
	p = strrchr(modrefname, '.');
	if (!p) {
		subcs = virtual_module_find_cs(&method, modrefname, modrefname, NULL);
	} else {
		char buffer[256];

		strlcpy(buffer, modrefname, sizeof(buffer));
		buffer[p - modrefname] = '\0';

		subcs = virtual_module_find_cs(&method, modrefname, buffer, buffer + (p - modrefname) + 1);
	}

	/*
	 *	Check that we're not creating a loop.  We may
	 *	be compiling an "sql" module reference inside
	 *	of an "sql" policy.  If so, we allow the
	 *	second "sql" to refer to the module.
	 */
	for (loop = cf_item_parent(ci);
	     loop && subcs;
	     loop = cf_item_parent(cf_section_to_item(loop))) {
		if (loop == subcs) {
			subcs = NULL;
		}
	}

	/*
	 *	We've found the relevant entry.  It MUST be a
	 *	sub-section.
	 *
	 *	However, it can be a "redundant" block, or just a
	 *	section name.
	 */
	if (subcs) {
		/*
		 *	modules.c takes care of ensuring that this is:
		 *
		 *	group foo { ...
		 *	load-balance foo { ...
		 *	redundant foo { ...
		 *	redundant-load-balance foo { ...
		 *
		 *	We can just recurs to compile the section as
		 *	if it was found here.
		 */
		if (cf_section_name2(subcs)) {
			csingle = do_compile_modsingle(parent,
						       method,
						       cf_section_to_item(subcs),
						       grouptype,
						       modname);
		} else {
			/*
			 *	We have:
			 *
			 *	foo { ...
			 *
			 *	So we compile it like it was:
			 *
			 *	group foo { ...
			 */
			csingle = do_compile_modgroup(parent,
						      method,
						      subcs,
						      GROUPTYPE_SIMPLE,
						      grouptype, MOD_GROUP);
		}

		/*
		 *	Return the compiled thing if we can.
		 */
		if (!csingle) return NULL;
		if (cf_item_is_pair(ci)) return csingle;

		/*
		 *	Else we have a reference to a policy, and that reference
		 *	over-rides the return codes for the policy!
		 */
		goto action_override;
	}

	/*
	 *	Not a virtual module.  It must be a real module.
	 */
	modules = cf_section_find("modules");
	this = NULL;
	realname = modrefname;

	if (modules) {
		/*
		 *	Try to load the optional module.
		 */
		if (realname[0] == '-') realname++;

		/*
		 *	As of v3, the "modules" section contains
		 *	modules we use.  Configuration for other
		 *	modules belongs in raddb/mods-available/,
		 *	which isn't loaded into the "modules" section.
		 */
		this = module_instantiate_method(modules, realname, &method);
		if (this) goto allocate_csingle;

		/*
		 *	We were asked to MAYBE load it and it
		 *	doesn't exist.  Return a soft error.
		 */
		if (realname != modrefname) {
			*modname = modrefname;
			return NULL;
		}
	}

	/*
	 *	Can't de-reference it to anything.  Ugh.
	 */
	*modname = NULL;
	cf_log_err(ci, "Failed to find \"%s\" as a module or policy.", modrefname);
	cf_log_err(ci, "Please verify that the configuration exists in %s/mods-enabled/%s.", get_radius_dir(), modrefname);
	return NULL;

	/*
	 *	We know it's all OK, allocate the structures, and fill
	 *	them in.
	 */
allocate_csingle:
	/*
	 *	Check if the module in question has the necessary
	 *	component.
	 */
	if (!this->entry->module->methods[method]) {
		cf_log_err(ci, "\"%s\" modules aren't allowed in '%s' sections -- they have no such method.", this->entry->module->name,
			   comp2str[method]);
		return NULL;
	}

	single = talloc_zero(parent, modsingle);
	single->modinst = this;
	*modname = this->entry->module->name;

	csingle = mod_singletocallable(single);
	csingle->parent = parent;
	csingle->next = NULL;
	if (!parent || (component != MOD_AUTHENTICATE)) {
		memcpy(csingle->actions, defaultactions[component][grouptype],
		       sizeof csingle->actions);
	} else { /* inside Auth-Type has different rules */
		memcpy(csingle->actions, authtype_actions[grouptype],
		       sizeof csingle->actions);
	}
	rad_assert(modrefname != NULL);
	csingle->name = realname;
	csingle->type = MOD_SINGLE;
	csingle->method = method;

action_override:
	/*
	 *	Over-ride the default return codes of the module.
	 */
	if (cf_item_is_section(ci)) {
		CONF_ITEM *csi;

		cs = cf_item_to_section(ci);
		for (csi=cf_item_find_next(cs, NULL);
		     csi != NULL;
		     csi=cf_item_find_next(cs, csi)) {

			if (cf_item_is_section(csi)) {
				cf_log_err(csi, "Subsection of module instance call not allowed");
				talloc_free(csingle);
				return NULL;
			}

			if (!cf_item_is_pair(csi)) continue;

			if (!compile_action(csingle, cf_item_to_pair(csi))) {
				talloc_free(csingle);
				return NULL;
			}
		}
	}

	return csingle;
}

modcallable *compile_modsingle(TALLOC_CTX *ctx,
			       modcallable **parent,
			       rlm_components_t component, CONF_ITEM *ci,
			       char const **modname)
{
	modcallable *ret;

	if (!*parent) {
		modcallable *c;
		modgroup *g;
		CONF_SECTION *parentcs;

		g = talloc_zero(ctx, modgroup);
		memset(g, 0, sizeof(*g));
		g->grouptype = GROUPTYPE_SIMPLE;
		c = mod_grouptocallable(g);
		c->next = NULL;
		memcpy(c->actions,
		       defaultactions[component][GROUPTYPE_SIMPLE],
		       sizeof(c->actions));

		parentcs = cf_item_parent(ci);
		c->name = cf_section_name2(parentcs);
		if (!c->name) {
			c->name = cf_section_name1(parentcs);
		}

		c->type = MOD_GROUP;
		c->method = component;
		g->children = NULL;

		*parent = mod_grouptocallable(g);
	}

	ret = do_compile_modsingle(*parent, component, ci,
				   GROUPTYPE_SIMPLE,
				   modname);
	dump_tree(component, ret);
	return ret;
}


/*
 *	Internal compile group code.
 */
static modcallable *do_compile_modgroup(modcallable *parent,
					rlm_components_t component, CONF_SECTION *cs,
					int grouptype, int parentgrouptype, int mod_type)
{
	int i;
	modgroup *g;
	modcallable *c;
	CONF_ITEM *ci;

	g = talloc_zero(parent, modgroup);
	g->grouptype = grouptype;
	g->children = NULL;
	g->cs = cs;

	c = mod_grouptocallable(g);
	c->parent = parent;
	c->type = mod_type;
	c->next = NULL;
	memset(c->actions, 0, sizeof(c->actions));

	if (!cs) {		/* only for "break" and "return" */
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
		if ((strcmp(c->name, "group") == 0) ||
		    (strcmp(c->name, "redundant") == 0)) {
			c->name = "";
		} else if (c->type == MOD_GROUP) {
			c->type = MOD_POLICY;
		}
	}

#ifdef WITH_UNLANG
	/*
	 *	Do load-time optimizations
	 */
	if ((c->type == MOD_IF) || (c->type == MOD_ELSIF) || (c->type == MOD_ELSE)) {
		modgroup *f, *p;

		rad_assert(parent != NULL);

		if (c->type == MOD_IF) {
			g->cond = cf_data_find(g->cs, "if");
			rad_assert(g->cond != NULL);

		check_if:
			if (g->cond->type == COND_TYPE_FALSE) {
				INFO(" # Skipping contents of '%s' as it is always 'false' -- %s:%d",
				     unlang_keyword[g->mc.type],
				     cf_section_filename(g->cs), cf_section_lineno(g->cs));
				goto set_codes;
			}

		} else if (c->type == MOD_ELSIF) {

			g->cond = cf_data_find(g->cs, "if");
			rad_assert(g->cond != NULL);

			rad_assert(parent != NULL);
			p = mod_callabletogroup(parent);

			if (!p->tail) goto elsif_fail;

			/*
			 *	We're in the process of compiling the
			 *	section, so the parent's tail is the
			 *	previous "if" statement.
			 */
			f = mod_callabletogroup(p->tail);
			if ((f->mc.type != MOD_IF) &&
			    (f->mc.type != MOD_ELSIF)) {
			elsif_fail:
				cf_log_err_cs(g->cs, "Invalid location for 'elsif'.  There is no preceding 'if' statement");
				talloc_free(g);
				return NULL;
			}

			/*
			 *	If we took the previous condition, we
			 *	don't need to take this one.
			 *
			 *	We reset our condition to 'true', so
			 *	that subsequent sections can check
			 *	that they don't need to be executed.
			 */
			if (f->cond->type == COND_TYPE_TRUE) {
			skip_true:
				INFO(" # Skipping contents of '%s' as previous '%s' is always  'true' -- %s:%d",
				     unlang_keyword[g->mc.type],
				     unlang_keyword[f->mc.type],
				     cf_section_filename(g->cs), cf_section_lineno(g->cs));
				g->cond = f->cond;
				goto set_codes;
			}
			goto check_if;

		} else {
			rad_assert(c->type == MOD_ELSE);

			rad_assert(parent != NULL);
			p = mod_callabletogroup(parent);

			if (!p->tail) goto else_fail;

			f = mod_callabletogroup(p->tail);
			if ((f->mc.type != MOD_IF) &&
			    (f->mc.type != MOD_ELSIF)) {
			else_fail:
				cf_log_err_cs(g->cs, "Invalid location for 'else'.  There is no preceding 'if' statement");
				talloc_free(g);
				return NULL;
			}

			/*
			 *	If we took the previous condition, we
			 *	don't need to take this one.
			 */
			if (f->cond->type == COND_TYPE_TRUE) goto skip_true;
		}

		/*
		 *	Else we need to compile this section
		 */
	}
#endif

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
			char const *junk = NULL;
			modcallable *single;
			CONF_SECTION *subcs = cf_item_to_section(ci);

			single = do_compile_modsingle(c, component, ci,
						      grouptype, &junk);
			if (!single) {
				cf_log_err(ci, "Failed to parse \"%s\" subsection.",
				       cf_section_name1(subcs));
				talloc_free(c);
				return NULL;
			}
			add_child(g, single);

		} else if (!cf_item_is_pair(ci)) { /* CONF_DATA */
			continue;

		} else {
			char const *attr, *value;
			CONF_PAIR *cp = cf_item_to_pair(ci);

			attr = cf_pair_attr(cp);
			value = cf_pair_value(cp);

			/*
			 *	A CONF_PAIR is either a module
			 *	instance with no actions
			 *	specified ...
			 */
			if (!value) {
				modcallable *single;
				char const *junk = NULL;

				single = do_compile_modsingle(c,
							      component,
							      ci,
							      grouptype,
							      &junk);
				if (!single) {
					if (cf_item_is_pair(ci) &&
					    cf_pair_attr(cf_item_to_pair(ci))[0] == '-') {
						continue;
					}

					cf_log_err(ci,
						   "Failed to parse \"%s\" entry.",
						   attr);
					talloc_free(c);
					return NULL;
				}
				add_child(g, single);

				/*
				 *	Or a module instance with action.
				 */
			} else if (!compile_action(c, cp)) {
				talloc_free(c);
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
			if (!parent || (component != MOD_AUTHENTICATE)) {
				c->actions[i] = defaultactions[component][parentgrouptype][i];
			} else { /* inside Auth-Type has different rules */
				c->actions[i] = authtype_actions[parentgrouptype][i];
			}
		}
	}

	switch (c->type) {
	default:
		break;

	case MOD_GROUP:
		if (grouptype != GROUPTYPE_REDUNDANT) break;
		/* FALL-THROUGH */

	case MOD_LOAD_BALANCE:
	case MOD_REDUNDANT_LOAD_BALANCE:
		if (!g->children) {
			cf_log_err_cs(g->cs, "%s sections cannot be empty",
				      cf_section_name1(g->cs));
			talloc_free(c);
			return NULL;
		}
	}

	/*
	 *	FIXME: If there are no children, return NULL?
	 */
	return mod_grouptocallable(g);
}

modcallable *compile_modgroup(modcallable *parent,
			      rlm_components_t component, CONF_SECTION *cs)
{
	modcallable *ret = do_compile_modgroup(parent, component, cs,
					       GROUPTYPE_SIMPLE,
					       GROUPTYPE_SIMPLE, MOD_GROUP);

	if (rad_debug_lvl > 3) {
		modcall_debug(ret, 2);
	}

	return ret;
}

void add_to_modcallable(modcallable *parent, modcallable *this)
{
	modgroup *g;

	rad_assert(this != NULL);
	rad_assert(parent != NULL);

	g = mod_callabletogroup(parent);

	add_child(g, this);
}


#ifdef WITH_UNLANG
static bool pass2_xlat_compile(CONF_ITEM const *ci, vp_tmpl_t **pvpt, bool convert,
			       DICT_ATTR const *da)
{
	ssize_t slen;
	char *fmt;
	char const *error;
	xlat_exp_t *head;
	vp_tmpl_t *vpt;

	vpt = *pvpt;

	rad_assert(vpt->type == TMPL_TYPE_XLAT);

	fmt = talloc_typed_strdup(vpt, vpt->name);
	slen = xlat_tokenize(vpt, fmt, &head, &error);

	if (slen < 0) {
		char *spaces, *text;

		fr_canonicalize_error(vpt, &spaces, &text, slen, vpt->name);

		cf_log_err(ci, "Failed parsing expanded string:");
		cf_log_err(ci, "%s", text);
		cf_log_err(ci, "%s^ %s", spaces, error);

		talloc_free(spaces);
		talloc_free(text);
		return false;
	}

	/*
	 *	Convert %{Attribute-Name} to &Attribute-Name
	 */
	if (convert) {
		vp_tmpl_t *attr;

		attr = xlat_to_tmpl_attr(talloc_parent(vpt), head);
		if (attr) {
			/*
			 *	If it's a virtual attribute, leave it
			 *	alone.
			 */
			if (attr->tmpl_da->flags.virtual) {
				talloc_free(attr);
				return true;
			}

			/*
			 *	If the attribute is of incompatible
			 *	type, leave it alone.
			 */
			if (da && (da->type != attr->tmpl_da->type)) {
				talloc_free(attr);
				return true;
			}

			if (cf_item_is_pair(ci)) {
				CONF_PAIR *cp = cf_item_to_pair(ci);

				WARN("%s[%d]: Please change \"%%{%s}\" to &%s",
				       cf_pair_filename(cp), cf_pair_lineno(cp),
				       attr->name, attr->name);
			} else {
				CONF_SECTION *cs = cf_item_to_section(ci);

				WARN("%s[%d]: Please change \"%%{%s}\" to &%s",
				       cf_section_filename(cs), cf_section_lineno(cs),
				       attr->name, attr->name);
			}
			TALLOC_FREE(*pvpt);
			*pvpt = attr;
			return true;
		}
	}

	/*
	 *	Re-write it to be a pre-parsed XLAT structure.
	 */
	vpt->type = TMPL_TYPE_XLAT_STRUCT;
	vpt->tmpl_xlat = head;

	return true;
}


#ifdef HAVE_REGEX
static bool pass2_regex_compile(CONF_ITEM const *ci, vp_tmpl_t *vpt)
{
	ssize_t slen;
	regex_t *preg;

	rad_assert(vpt->type == TMPL_TYPE_REGEX);

	/*
	 *	It's a dynamic expansion.  We can't expand the string,
	 *	but we can pre-parse it as an xlat struct.  In that
	 *	case, we convert it to a pre-compiled XLAT.
	 *
	 *	This is a little more complicated than it needs to be
	 *	because radius_evaluate_map() keys off of the src
	 *	template type, instead of the operators.  And, the
	 *	pass2_xlat_compile() function expects to get passed an
	 *	XLAT instead of a REGEX.
	 */
	if (strchr(vpt->name, '%')) {
		vpt->type = TMPL_TYPE_XLAT;
		return pass2_xlat_compile(ci, &vpt, false, NULL);
	}

	slen = regex_compile(vpt, &preg, vpt->name, vpt->len,
			     vpt->tmpl_iflag, vpt->tmpl_mflag, true, false);
	if (slen <= 0) {
		char *spaces, *text;

		fr_canonicalize_error(vpt, &spaces, &text, slen, vpt->name);

		cf_log_err(ci, "Invalid regular expression:");
		cf_log_err(ci, "%s", text);
		cf_log_err(ci, "%s^ %s", spaces, fr_strerror());

		talloc_free(spaces);
		talloc_free(text);

		return false;
	}

	vpt->type = TMPL_TYPE_REGEX_STRUCT;
	vpt->tmpl_preg = preg;

	return true;
}
#endif

static bool pass2_fixup_undefined(CONF_ITEM const *ci, vp_tmpl_t *vpt)
{
	DICT_ATTR const *da;

	rad_assert(vpt->type == TMPL_TYPE_ATTR_UNDEFINED);

	da = dict_attrbyname(vpt->tmpl_unknown_name);
	if (!da) {
		cf_log_err(ci, "Unknown attribute '%s'", vpt->tmpl_unknown_name);
		return false;
	}

	vpt->tmpl_da = da;
	vpt->type = TMPL_TYPE_ATTR;
	return true;
}

static bool pass2_callback(void *ctx, fr_cond_t *c)
{
	vp_map_t *map;
	vp_tmpl_t *vpt;

	/*
	 *	These don't get optimized.
	 */
	if ((c->type == COND_TYPE_TRUE) ||
	    (c->type == COND_TYPE_FALSE)) {
		return true;
	}

	/*
	 *	Call children.
	 */
	if (c->type == COND_TYPE_CHILD) return pass2_callback(ctx, c->data.child);

	/*
	 *	A few simple checks here.
	 */
	if (c->type == COND_TYPE_EXISTS) {
		if (c->data.vpt->type == TMPL_TYPE_XLAT) {
			return pass2_xlat_compile(c->ci, &c->data.vpt, true, NULL);
		}

		rad_assert(c->data.vpt->type != TMPL_TYPE_REGEX);

		/*
		 *	The existence check might have been &Foo-Bar,
		 *	where Foo-Bar is defined by a module.
		 */
		if (c->pass2_fixup == PASS2_FIXUP_ATTR) {
			if (!pass2_fixup_undefined(c->ci, c->data.vpt)) return false;
			c->pass2_fixup = PASS2_FIXUP_NONE;
		}

		/*
		 *	Convert virtual &Attr-Foo to "%{Attr-Foo}"
		 */
		vpt = c->data.vpt;
		if ((vpt->type == TMPL_TYPE_ATTR) && vpt->tmpl_da->flags.virtual) {
			vpt->tmpl_xlat = xlat_from_tmpl_attr(vpt, vpt);
			vpt->type = TMPL_TYPE_XLAT_STRUCT;
		}

		return true;
	}

	/*
	 *	And tons of complicated checks.
	 */
	rad_assert(c->type == COND_TYPE_MAP);

	map = c->data.map;	/* shorter */

	/*
	 *	Auth-Type := foo
	 *
	 *	Where "foo" is dynamically defined.
	 */
	if (c->pass2_fixup == PASS2_FIXUP_TYPE) {
		if (!dict_valbyname(map->lhs->tmpl_da->attr,
				    map->lhs->tmpl_da->vendor,
				    map->rhs->name)) {
			cf_log_err(map->ci, "Invalid reference to non-existent %s %s { ... }",
				   map->lhs->tmpl_da->name,
				   map->rhs->name);
			return false;
		}

		/*
		 *	These guys can't have a paircompare fixup applied.
		 */
		c->pass2_fixup = PASS2_FIXUP_NONE;
		return true;
	}

	if (c->pass2_fixup == PASS2_FIXUP_ATTR) {
		if (map->lhs->type == TMPL_TYPE_ATTR_UNDEFINED) {
			if (!pass2_fixup_undefined(map->ci, map->lhs)) return false;
		}

		if (map->rhs->type == TMPL_TYPE_ATTR_UNDEFINED) {
			if (!pass2_fixup_undefined(map->ci, map->rhs)) return false;
		}

		c->pass2_fixup = PASS2_FIXUP_NONE;
	}

	/*
	 *	Just in case someone adds a new fixup later.
	 */
	rad_assert((c->pass2_fixup == PASS2_FIXUP_NONE) ||
		   (c->pass2_fixup == PASS2_PAIRCOMPARE));

	/*
	 *	Precompile xlat's
	 */
	if (map->lhs->type == TMPL_TYPE_XLAT) {
		/*
		 *	Compile the LHS to an attribute reference only
		 *	if the RHS is a literal.
		 *
		 *	@todo v3.1: allow anything anywhere.
		 */
		if (map->rhs->type != TMPL_TYPE_LITERAL) {
			if (!pass2_xlat_compile(map->ci, &map->lhs, false, NULL)) {
				return false;
			}
		} else {
			if (!pass2_xlat_compile(map->ci, &map->lhs, true, NULL)) {
				return false;
			}

			/*
			 *	Attribute compared to a literal gets
			 *	the literal cast to the data type of
			 *	the attribute.
			 *
			 *	The code in parser.c did this for
			 *
			 *		&Attr == data
			 *
			 *	But now we've just converted "%{Attr}"
			 *	to &Attr, so we've got to do it again.
			 */
			if ((map->lhs->type == TMPL_TYPE_ATTR) &&
			    (map->rhs->type == TMPL_TYPE_LITERAL)) {
				/*
				 *	RHS is hex, try to parse it as
				 *	type-specific data.
				 */
				if (map->lhs->auto_converted &&
				    (map->rhs->name[0] == '0') && (map->rhs->name[1] == 'x') &&
				    (map->rhs->len > 2) && ((map->rhs->len & 0x01) == 0)) {
					vpt = map->rhs;
					map->rhs = NULL;

					if (!map_cast_from_hex(map, T_BARE_WORD, vpt->name)) {
						map->rhs = vpt;
						cf_log_err(map->ci, "Cannot parse RHS hex as the data type of the attribute %s", map->lhs->tmpl_da->name);
						return -1;
					}
					talloc_free(vpt);

				} else if ((map->rhs->len > 0) ||
					   (map->op != T_OP_CMP_EQ) ||
					   (map->lhs->tmpl_da->type == PW_TYPE_STRING) ||
					   (map->lhs->tmpl_da->type == PW_TYPE_OCTETS)) {

					if (tmpl_cast_in_place(map->rhs, map->lhs->tmpl_da->type, map->lhs->tmpl_da) < 0) {
						cf_log_err(map->ci, "Failed to parse data type %s from string: %s",
							   fr_int2str(dict_attr_types, map->lhs->tmpl_da->type, "<UNKNOWN>"),
							   map->rhs->name);
						return false;
					} /* else the cast was successful */

				} else {	/* RHS is empty, it's just a check for empty / non-empty string */
					vpt = talloc_steal(c, map->lhs);
					map->lhs = NULL;
					talloc_free(c->data.map);

					/*
					 *	"%{Foo}" == '' ---> !Foo
					 *	"%{Foo}" != '' ---> Foo
					 */
					c->type = COND_TYPE_EXISTS;
					c->data.vpt = vpt;
					c->negate = !c->negate;

					WARN("%s[%d]: Please change (\"%%{%s}\" %s '') to %c&%s",
					     cf_section_filename(cf_item_to_section(c->ci)),
					     cf_section_lineno(cf_item_to_section(c->ci)),
					     vpt->name, c->negate ? "==" : "!=",
					     c->negate ? '!' : ' ', vpt->name);

					/*
					 *	No more RHS, so we can't do more optimizations
					 */
					return true;
				}
			}
		}
	}

	if (map->rhs->type == TMPL_TYPE_XLAT) {
		/*
		 *	Convert the RHS to an attribute reference only
		 *	if the LHS is an attribute reference, AND is
		 *	of the same type as the RHS.
		 *
		 *	We can fix this when the code in evaluate.c
		 *	can handle strings on the LHS, and attributes
		 *	on the RHS.  For now, the code in parser.c
		 *	forbids this.
		 */
		if (map->lhs->type == TMPL_TYPE_ATTR) {
			DICT_ATTR const *da = c->cast;

			if (!c->cast) da = map->lhs->tmpl_da;

			if (!pass2_xlat_compile(map->ci, &map->rhs, true, da)) {
				return false;
			}

		} else {
			if (!pass2_xlat_compile(map->ci, &map->rhs, false, NULL)) {
				return false;
			}
		}
	}

	/*
	 *	Convert bare refs to %{Foreach-Variable-N}
	 */
	if ((map->lhs->type == TMPL_TYPE_LITERAL) &&
	    (strncmp(map->lhs->name, "Foreach-Variable-", 17) == 0)) {
		char *fmt;
		ssize_t slen;

		fmt = talloc_asprintf(map->lhs, "%%{%s}", map->lhs->name);
		slen = tmpl_afrom_str(map, &vpt, fmt, talloc_array_length(fmt) - 1,
				      T_DOUBLE_QUOTED_STRING, REQUEST_CURRENT, PAIR_LIST_REQUEST, true);
		if (slen < 0) {
			char *spaces, *text;

			fr_canonicalize_error(map->ci, &spaces, &text, slen, fr_strerror());

			cf_log_err(map->ci, "Failed converting %s to xlat", map->lhs->name);
			cf_log_err(map->ci, "%s", fmt);
			cf_log_err(map->ci, "%s^ %s", spaces, text);

			talloc_free(spaces);
			talloc_free(text);
			talloc_free(fmt);

			return false;
		}
		talloc_free(map->lhs);
		map->lhs = vpt;
	}

#ifdef HAVE_REGEX
	if (map->rhs->type == TMPL_TYPE_REGEX) {
		if (!pass2_regex_compile(map->ci, map->rhs)) {
			return false;
		}
	}
	rad_assert(map->lhs->type != TMPL_TYPE_REGEX);
#endif

	/*
	 *	Convert &Packet-Type to "%{Packet-Type}", because
	 *	these attributes don't really exist.  The code to
	 *	find an attribute reference doesn't work, but the
	 *	xlat code does.
	 */
	vpt = c->data.map->lhs;
	if ((vpt->type == TMPL_TYPE_ATTR) && vpt->tmpl_da->flags.virtual) {
		if (!c->cast) c->cast = vpt->tmpl_da;
		vpt->tmpl_xlat = xlat_from_tmpl_attr(vpt, vpt);
		vpt->type = TMPL_TYPE_XLAT_STRUCT;
	}

	/*
	 *	Convert RHS to expansions, too.
	 */
	vpt = c->data.map->rhs;
	if ((vpt->type == TMPL_TYPE_ATTR) && vpt->tmpl_da->flags.virtual) {
		vpt->tmpl_xlat = xlat_from_tmpl_attr(vpt, vpt);
		vpt->type = TMPL_TYPE_XLAT_STRUCT;
	}

	/*
	 *	@todo v3.1: do the same thing for the RHS...
	 */

	/*
	 *	Only attributes can have a paircompare registered, and
	 *	they can only be with the current REQUEST, and only
	 *	with the request pairs.
	 */
	if ((map->lhs->type != TMPL_TYPE_ATTR) ||
	    (map->lhs->tmpl_request != REQUEST_CURRENT) ||
	    (map->lhs->tmpl_list != PAIR_LIST_REQUEST)) {
		return true;
	}

	if (!radius_find_compare(map->lhs->tmpl_da)) return true;

	if (map->rhs->type == TMPL_TYPE_REGEX) {
		cf_log_err(map->ci, "Cannot compare virtual attribute %s via a regex",
			   map->lhs->name);
		return false;
	}

	if (c->cast) {
		cf_log_err(map->ci, "Cannot cast virtual attribute %s",
			   map->lhs->name);
		return false;
	}

	if (map->op != T_OP_CMP_EQ) {
		cf_log_err(map->ci, "Must use '==' for comparisons with virtual attribute %s",
			   map->lhs->name);
		return false;
	}

	/*
	 *	Mark it as requiring a paircompare() call, instead of
	 *	fr_pair_cmp().
	 */
	c->pass2_fixup = PASS2_PAIRCOMPARE;

	return true;
}


/*
 *	Compile the RHS of update sections to xlat_exp_t
 */
static bool modcall_pass2_update(modgroup *g)
{
	vp_map_t *map;

	for (map = g->map; map != NULL; map = map->next) {
		if (map->rhs->type == TMPL_TYPE_XLAT) {
			rad_assert(map->rhs->tmpl_xlat == NULL);

			/*
			 *	FIXME: compile to attribute && handle
			 *	the conversion in map_to_vp().
			 */
			if (!pass2_xlat_compile(map->ci, &map->rhs, false, NULL)) {
				return false;
			}
		}

		rad_assert(map->rhs->type != TMPL_TYPE_REGEX);

		/*
		 *	Deal with undefined attributes now.
		 */
		if (map->lhs->type == TMPL_TYPE_ATTR_UNDEFINED) {
			if (!pass2_fixup_undefined(map->ci, map->lhs)) return false;
		}

		if (map->rhs->type == TMPL_TYPE_ATTR_UNDEFINED) {
			if (!pass2_fixup_undefined(map->ci, map->rhs)) return false;
		}
	}

	return true;
}
#endif

/*
 *	Do a second-stage pass on compiling the modules.
 */
bool modcall_pass2(modcallable *mc)
{
	ssize_t slen;
	char const *name2;
	modcallable *c;
	modgroup *g;

	for (c = mc; c != NULL; c = c->next) {
		switch (c->type) {
		default:
			rad_assert(0 == 1);
			break;

#ifdef WITH_UNLANG
		case MOD_UPDATE:
			g = mod_callabletogroup(c);
			if (g->done_pass2) goto do_next;

			name2 = cf_section_name2(g->cs);
			if (!name2) {
				c->debug_name = unlang_keyword[c->type];
			} else {
				c->debug_name = talloc_asprintf(c, "update %s", name2);
			}

			if (!modcall_pass2_update(g)) {
				return false;
			}
			g->done_pass2 = true;
			break;

		case MOD_XLAT:   /* @todo: pre-parse xlat's */
		case MOD_REFERENCE:
		case MOD_BREAK:
		case MOD_RETURN:
#endif

		case MOD_SINGLE:
			c->debug_name = c->name;
			break;	/* do nothing */

#ifdef WITH_UNLANG
		case MOD_IF:
		case MOD_ELSIF:
			g = mod_callabletogroup(c);
			if (g->done_pass2) goto do_next;

			name2 = cf_section_name2(g->cs);
			c->debug_name = talloc_asprintf(c, "%s %s", unlang_keyword[c->type], name2);

			/*
			 *	The compilation code takes care of
			 *	simplifying 'true' and 'false'
			 *	conditions.  For others, we have to do
			 *	a second pass to parse && compile
			 *	xlats.
			 */
			if (!((g->cond->type == COND_TYPE_TRUE) ||
			      (g->cond->type == COND_TYPE_FALSE))) {
				if (!fr_condition_walk(g->cond, pass2_callback, NULL)) {
					return false;
				}
			}

			if (!modcall_pass2(g->children)) return false;
			g->done_pass2 = true;
			break;
#endif

#ifdef WITH_UNLANG
		case MOD_SWITCH:
			g = mod_callabletogroup(c);
			if (g->done_pass2) goto do_next;

			name2 = cf_section_name2(g->cs);
			c->debug_name = talloc_asprintf(c, "%s %s", unlang_keyword[c->type], name2);

			/*
			 *	We had &Foo-Bar, where Foo-Bar is
			 *	defined by a module.
			 */
			if (!g->vpt) {
				rad_assert(c->name != NULL);
				rad_assert(c->name[0] == '&');
				rad_assert(cf_section_name2_type(g->cs) == T_BARE_WORD);

				slen = tmpl_afrom_str(g->cs, &g->vpt, c->name, strlen(c->name),
						      cf_section_name2_type(g->cs),
						      REQUEST_CURRENT, PAIR_LIST_REQUEST, true);
				if (slen < 0) {
					char *spaces, *text;

				parse_error:
					fr_canonicalize_error(g->cs, &spaces, &text, slen, fr_strerror());

					cf_log_err_cs(g->cs, "Syntax error");
					cf_log_err_cs(g->cs, "%s", c->name);
					cf_log_err_cs(g->cs, "%s^ %s", spaces, text);

					talloc_free(spaces);
					talloc_free(text);

					return false;
				}

				goto do_children;
			}

			/*
			 *	Statically compile xlats
			 */
			if (g->vpt->type == TMPL_TYPE_XLAT) {
				if (!pass2_xlat_compile(cf_section_to_item(g->cs),
							&g->vpt, true, NULL)) {
					return false;
				}

				goto do_children;
			}

			/*
			 *	Convert virtual &Attr-Foo to "%{Attr-Foo}"
			 */
			if ((g->vpt->type == TMPL_TYPE_ATTR) && g->vpt->tmpl_da->flags.virtual) {
				g->vpt->tmpl_xlat = xlat_from_tmpl_attr(g->vpt, g->vpt);
				g->vpt->type = TMPL_TYPE_XLAT_STRUCT;
			}

			/*
			 *	We may have: switch Foo-Bar {
			 *
			 *	where Foo-Bar is an attribute defined
			 *	by a module.  Since there's no leading
			 *	&, it's parsed as a literal.  But if
			 *	we can parse it as an attribute,
			 *	switch to using that.
			 */
			if (g->vpt->type == TMPL_TYPE_LITERAL) {
				vp_tmpl_t *vpt;

				slen = tmpl_afrom_str(g->cs, &vpt, c->name, strlen(c->name), cf_section_name2_type(g->cs),
						      REQUEST_CURRENT, PAIR_LIST_REQUEST, true);
				if (slen < 0) goto parse_error;
				if (vpt->type == TMPL_TYPE_ATTR) {
					talloc_free(g->vpt);
					g->vpt = vpt;
				}

				goto do_children;
			}

			/*
			 *	Warn about old-style configuration.
			 *
			 *	DEPRECATED: switch User-Name { ...
			 *	ALLOWED   : switch &User-Name { ...
			 */
			if ((g->vpt->type == TMPL_TYPE_ATTR) &&
			    (c->name[0] != '&')) {
				WARN("%s[%d]: Please change %s to &%s",
				     cf_section_filename(g->cs),
				     cf_section_lineno(g->cs),
				     c->name, c->name);
			}

		do_children:
			if (!modcall_pass2(g->children)) return false;
			g->done_pass2 = true;
			break;

		case MOD_CASE:
			g = mod_callabletogroup(c);
			if (g->done_pass2) goto do_next;

			name2 = cf_section_name2(g->cs);
			if (!name2) {
				c->debug_name = unlang_keyword[c->type];
			} else {
				c->debug_name = talloc_asprintf(c, "%s %s", unlang_keyword[c->type], name2);
			}

			rad_assert(c->parent != NULL);
			rad_assert(c->parent->type == MOD_SWITCH);

			/*
			 *	The statement may refer to an
			 *	attribute which doesn't exist until
			 *	all of the modules have been loaded.
			 *	Check for that now.
			 */
			if (!g->vpt && c->name &&
			    (c->name[0] == '&') &&
			    (cf_section_name2_type(g->cs) == T_BARE_WORD)) {
				slen = tmpl_afrom_str(g->cs, &g->vpt, c->name, strlen(c->name),
						      cf_section_name2_type(g->cs),
						      REQUEST_CURRENT, PAIR_LIST_REQUEST, true);
				if (slen < 0) goto parse_error;
			}

			/*
			 *	We have "case {...}".  There's no
			 *	argument, so we don't need to check
			 *	it.
			 */
			if (!g->vpt) goto do_children;

			/*
			 *	Do type-specific checks on the case statement
			 */
			if (g->vpt->type == TMPL_TYPE_LITERAL) {
				modgroup *f;

				f = mod_callabletogroup(mc->parent);
				rad_assert(f->vpt != NULL);

				/*
				 *	We're switching over an
				 *	attribute.  Check that the
				 *	values match.
				 */
				if (f->vpt->type == TMPL_TYPE_ATTR) {
					rad_assert(f->vpt->tmpl_da != NULL);

					if (tmpl_cast_in_place(g->vpt, f->vpt->tmpl_da->type, f->vpt->tmpl_da) < 0) {
						cf_log_err_cs(g->cs, "Invalid argument for case statement: %s",
							      fr_strerror());
						return false;
					}
				}

				goto do_children;
			}

			if (g->vpt->type == TMPL_TYPE_ATTR_UNDEFINED) {
				if (!pass2_fixup_undefined(cf_section_to_item(g->cs), g->vpt)) {
					return false;
				}
			}

			/*
			 *	Compile and sanity check xlat
			 *	expansions.
			 */
			if (g->vpt->type == TMPL_TYPE_XLAT) {
				modgroup *f;

				f = mod_callabletogroup(mc->parent);
				rad_assert(f->vpt != NULL);

				/*
				 *	Don't expand xlat's into an
				 *	attribute of a different type.
				 */
				if (f->vpt->type == TMPL_TYPE_ATTR) {
					if (!pass2_xlat_compile(cf_section_to_item(g->cs),
								&g->vpt, true, f->vpt->tmpl_da)) {
						return false;
					}
				} else {
					if (!pass2_xlat_compile(cf_section_to_item(g->cs),
								&g->vpt, true, NULL)) {
						return false;
					}
				}
			}

			/*
			 *	Virtual attribute fixes for "case" statements, too.
			 */
			if ((g->vpt->type == TMPL_TYPE_ATTR) && g->vpt->tmpl_da->flags.virtual) {
				g->vpt->tmpl_xlat = xlat_from_tmpl_attr(g->vpt, g->vpt);
				g->vpt->type = TMPL_TYPE_XLAT_STRUCT;
			}

			if (!modcall_pass2(g->children)) return false;
			g->done_pass2 = true;
			break;

		case MOD_FOREACH:
			g = mod_callabletogroup(c);
			if (g->done_pass2) goto do_next;

			name2 = cf_section_name2(g->cs);
			c->debug_name = talloc_asprintf(c, "%s %s", unlang_keyword[c->type], name2);

			/*
			 *	Already parsed, handle the children.
			 */
			if (g->vpt) goto check_children;

			/*
			 *	We had &Foo-Bar, where Foo-Bar is
			 *	defined by a module.
			 */
			rad_assert(c->name != NULL);
			rad_assert(c->name[0] == '&');
			rad_assert(cf_section_name2_type(g->cs) == T_BARE_WORD);

			/*
			 *	The statement may refer to an
			 *	attribute which doesn't exist until
			 *	all of the modules have been loaded.
			 *	Check for that now.
			 */
			slen = tmpl_afrom_str(g->cs, &g->vpt, c->name, strlen(c->name), cf_section_name2_type(g->cs),
					      REQUEST_CURRENT, PAIR_LIST_REQUEST, true);
			if (slen < 0) goto parse_error;

		check_children:
			rad_assert((g->vpt->type == TMPL_TYPE_ATTR) || (g->vpt->type == TMPL_TYPE_LIST));
			if (g->vpt->tmpl_num != NUM_ALL) {
				cf_log_err_cs(g->cs, "MUST NOT use instance selectors in 'foreach'");
				return false;
			}
			if (!modcall_pass2(g->children)) return false;
			g->done_pass2 = true;
			break;

		case MOD_ELSE:
			c->debug_name = unlang_keyword[c->type];
			goto do_recurse;

		case MOD_POLICY:
			g = mod_callabletogroup(c);
			c->debug_name = talloc_asprintf(c, "%s %s", unlang_keyword[c->type], cf_section_name1(g->cs));
			goto do_recurse;
#endif

		case MOD_GROUP:
		case MOD_LOAD_BALANCE:
		case MOD_REDUNDANT_LOAD_BALANCE:
			c->debug_name = unlang_keyword[c->type];

#ifdef WITH_UNLANG
		do_recurse:
#endif
			g = mod_callabletogroup(c);
			if (!g->cs) {
				c->debug_name = mc->name; /* for authorize, etc. */

			} else if (c->type == MOD_GROUP) { /* for Auth-Type, etc. */
				char const *name1 = cf_section_name1(g->cs);

				if (strcmp(name1, unlang_keyword[c->type]) != 0) {
					name2 = cf_section_name2(g->cs);

					if (!name2) {
						c->debug_name = name1;
					} else {
						c->debug_name = talloc_asprintf(c, "%s %s", name1, name2);
					}
				}
			}

			if (g->done_pass2) goto do_next;
			if (!modcall_pass2(g->children)) return false;
			g->done_pass2 = true;
			break;
		}

	do_next:
		rad_assert(c->debug_name != NULL);
	}

	return true;
}

void modcall_debug(modcallable *mc, int depth)
{
	modcallable *this;
	modgroup *g;
	vp_map_t *map;
	char buffer[1024];

	for (this = mc; this != NULL; this = this->next) {
		switch (this->type) {
		default:
			break;

		case MOD_SINGLE: {
			modsingle *single = mod_callabletosingle(this);

			DEBUG("%.*s%s", depth, modcall_spaces,
				single->modinst->name);
			}
			break;

#ifdef WITH_UNLANG
		case MOD_UPDATE:
			g = mod_callabletogroup(this);
			DEBUG("%.*s%s {", depth, modcall_spaces,
				unlang_keyword[this->type]);

			for (map = g->map; map != NULL; map = map->next) {
				map_prints(buffer, sizeof(buffer), map);
				DEBUG("%.*s%s", depth + 1, modcall_spaces, buffer);
			}

			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case MOD_ELSE:
			g = mod_callabletogroup(this);
			DEBUG("%.*s%s {", depth, modcall_spaces,
				unlang_keyword[this->type]);
			modcall_debug(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case MOD_IF:
		case MOD_ELSIF:
			g = mod_callabletogroup(this);
			fr_cond_sprint(buffer, sizeof(buffer), g->cond);
			DEBUG("%.*s%s (%s) {", depth, modcall_spaces,
				unlang_keyword[this->type], buffer);
			modcall_debug(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case MOD_SWITCH:
		case MOD_CASE:
			g = mod_callabletogroup(this);
			tmpl_prints(buffer, sizeof(buffer), g->vpt, NULL);
			DEBUG("%.*s%s %s {", depth, modcall_spaces,
				unlang_keyword[this->type], buffer);
			modcall_debug(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case MOD_POLICY:
		case MOD_FOREACH:
			g = mod_callabletogroup(this);
			DEBUG("%.*s%s %s {", depth, modcall_spaces,
				unlang_keyword[this->type], this->name);
			modcall_debug(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case MOD_BREAK:
			DEBUG("%.*sbreak", depth, modcall_spaces);
			break;

#endif
		case MOD_GROUP:
			g = mod_callabletogroup(this);
			DEBUG("%.*s%s {", depth, modcall_spaces,
			      unlang_keyword[this->type]);
			modcall_debug(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;


		case MOD_LOAD_BALANCE:
		case MOD_REDUNDANT_LOAD_BALANCE:
			g = mod_callabletogroup(this);
			DEBUG("%.*s%s {", depth, modcall_spaces,
				unlang_keyword[this->type]);
			modcall_debug(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;
		}
	}
}

int modcall_pass2_condition(fr_cond_t *c)
{
	if (!fr_condition_walk(c, pass2_callback, NULL)) return -1;

	return 0;
}
