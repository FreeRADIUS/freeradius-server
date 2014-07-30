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
	enum { MOD_SINGLE = 1, MOD_GROUP, MOD_LOAD_BALANCE, MOD_REDUNDANT_LOAD_BALANCE,
#ifdef WITH_UNLANG
	       MOD_IF, MOD_ELSE, MOD_ELSIF, MOD_UPDATE, MOD_SWITCH, MOD_CASE,
	       MOD_FOREACH, MOD_BREAK,
#endif
	       MOD_POLICY, MOD_REFERENCE, MOD_XLAT } type;
	rlm_components_t method;
	int actions[RLM_MODULE_NUMCODES];
};

#define MOD_LOG_OPEN_BRACE(_name) RDEBUG2("%.*s%s %s {", depth + 1, modcall_spaces, _name ? _name : "", c->name)
#define MOD_LOG_CLOSE_BRACE() RDEBUG2("%.*s} # %s %s = %s", depth + 1, modcall_spaces, \
				      cf_section_name1(g->cs) ? cf_section_name1(g->cs) : "", c->name ? c->name : "", \
				      fr_int2str(mod_rcode_table, result, "<invalid>"))

typedef struct {
	modcallable		mc;		/* self */
	enum {
		GROUPTYPE_SIMPLE = 0,
		GROUPTYPE_REDUNDANT,
		GROUPTYPE_APPEND,
		GROUPTYPE_COUNT
	} grouptype;				/* after mc */
	modcallable		*children;
	modcallable		*tail;		/* of the children list */
	CONF_SECTION		*cs;
	value_pair_map_t	*map;		/* update */
	value_pair_tmpl_t	*vpt;		/* switch */
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

/*
static const FR_NAME_NUMBER grouptype_table[] = {
	{ "", GROUPTYPE_SIMPLE },
	{ "redundant ", GROUPTYPE_REDUNDANT },
	{ "append ", GROUPTYPE_APPEND },
	{ NULL, -1 }
};
*/

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


static char const *group_name[];

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

	if (c->type != MOD_SINGLE) {
		ERROR("%s[%d] Invalid return code assigment inside of a %s section",
		      cf_pair_filename(cp), cf_pair_lineno(cp), group_name[c->type]);
		return 0;
	}

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

	/*
	 *	If the request should stop, refuse to do anything.
	 */
	blocked = (request->master_state == REQUEST_STOP_PROCESSING);
	if (blocked) return RLM_MODULE_NOOP;

	RINDENT();
	RDEBUG3("modsingle[%s]: calling %s (%s) for request %d",
	       comp2str[component], sp->modinst->name,
	       sp->modinst->entry->name, request->number);

	if (sp->modinst->force) {
		request->rcode = sp->modinst->code;
		goto fail;
	}

	safe_lock(sp->modinst);

	/*
	 *	For logging unresponsive children.
	 */
	request->module = sp->modinst->name;

	request->rcode = sp->modinst->entry->module->methods[component](sp->modinst->insthandle, request);

	request->module = "";
	safe_unlock(sp->modinst);

	/*
	 *	Wasn't blocked, and now is.  Complain!
	 */
	blocked = (request->master_state == REQUEST_STOP_PROCESSING);
	if (blocked) {
		RWARN("Module %s became unblocked for request %u", sp->modinst->entry->name, request->number);
	}

 fail:
	REXDENT();
	RDEBUG3("modsingle[%s]: returned from %s (%s) for request %d",
	       comp2str[component], sp->modinst->name,
	       sp->modinst->entry->name, request->number);

	return request->rcode;
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


static char const *group_name[] = {
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
			    modcall_stack_entry_t *entry);

/*
 *	Call a child of a block.
 */
static void modcall_child(REQUEST *request, rlm_components_t component, int depth,
			  modcall_stack_entry_t *entry, modcallable *c,
			  rlm_rcode_t *result)
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
			     depth, next)) {
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
			    modcall_stack_entry_t *entry)
{
	bool if_taken, was_if;
	modcallable *c;
	int priority;
	rlm_rcode_t result;

	was_if = if_taken = false;
	result = RLM_MODULE_UNKNOWN;

redo:
	priority = -1;
	c = entry->c;

	/*
	 *	Nothing more to do.  Return the code and priority
	 *	which was set by the caller.
	 */
	if (!c) return true;

	/*
	 *	We've been asked to stop.  Do so.
	 */
	if ((request->master_state == REQUEST_STOP_PROCESSING) ||
	    (request->parent &&
	     (request->parent->master_state == REQUEST_STOP_PROCESSING))) {
		entry->result = RLM_MODULE_FAIL;
		entry->priority = 9999;
		return true;
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

		RDEBUG2("%.*s %s %s", depth + 1, modcall_spaces,
			group_name[c->type], c->name);

		condition = radius_evaluate_cond(request, result, 0, g->cond);
		if (condition < 0) {
			condition = false;
			REDEBUG("Failed retrieving values required to evaluate condition");
		} else {
			RDEBUG2("%.*s %s %s -> %s", depth + 1, modcall_spaces,
				group_name[c->type],
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
			RDEBUG2("%.*s ... skipping %s for request %d: Preceding \"if\" was taken",
				depth + 1, modcall_spaces,
				group_name[c->type], request->number);
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
			RDEBUG2("%.*s ... skipping %s for request %d: No preceding \"if\"",
				depth + 1, modcall_spaces,
				group_name[c->type], request->number);
			goto next_sibling;
		}

		if (if_taken) {
			RDEBUG2("%.*s ... skipping %s for request %d: Preceding \"if\" was taken",
				depth + 1, modcall_spaces,
				group_name[c->type], request->number);
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
		RDEBUG2("%.*s[%s] = %s", depth + 1, modcall_spaces, c->name ? c->name : "",
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
		value_pair_map_t *map;


		MOD_LOG_OPEN_BRACE("update");
		for (map = g->map; map != NULL; map = map->next) {
			rcode = radius_map2request(request, map, radius_map2vp, NULL);
			if (rcode < 0) {
				result = (rcode == -2) ? RLM_MODULE_INVALID : RLM_MODULE_FAIL;
				MOD_LOG_CLOSE_BRACE();
				goto calculate_result;
			}
		}

		result = RLM_MODULE_NOOP;
		MOD_LOG_CLOSE_BRACE();
		goto calculate_result;
	} /* MOD_IF */

	/*
	 *	Loop over a set of attributes.
	 */
	if (c->type == MOD_FOREACH) {
		int i, foreach_depth = -1;
		VALUE_PAIR *vps, *vp;
		modcall_stack_entry_t *next = NULL;
		vp_cursor_t cursor, copy;
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
			if (!request_data_reference(request,
						    radius_get_vp, i)) {
				foreach_depth = i;
				break;
			}
		}

		if (foreach_depth < 0) {
			REDEBUG("foreach Nesting too deep!");
			result = RLM_MODULE_FAIL;
			goto calculate_result;
		}

		if (radius_tmpl_get_vp(&vp, request, g->vpt) < 0) {	/* nothing to loop over */
			MOD_LOG_OPEN_BRACE("foreach");
			result = RLM_MODULE_NOOP;
			MOD_LOG_CLOSE_BRACE();
			goto calculate_result;
		}

		/*
		 *	Copy the VPs from the original request, this ensures deterministic
		 *	behaviour if someone decides to add or remove VPs in the set were
		 *	iterating over.
		 */
		vps = NULL;

		fr_cursor_init(&cursor, &vp);

		/* Prime the cursor. */
		cursor.found = cursor.current;
		for (fr_cursor_init(&copy, &vps);
		     vp;
		     vp = fr_cursor_next_by_da(&cursor, vp->da, g->vpt->attribute.tag)) {
		     VALUE_PAIR *tmp;

		     MEM(tmp = paircopyvp(request, vp));
		     fr_cursor_insert(&copy, tmp);
		}

		RDEBUG2("%.*sforeach %s ", depth + 1, modcall_spaces, c->name);

		rad_assert(vps != NULL);

		/*
		 *	This is the actual body of the foreach loop
		 */
		for (vp = fr_cursor_first(&copy);
		     vp != NULL;
		     vp = fr_cursor_next(&copy)) {
#ifndef NDEBUG
			if (fr_debug_flag >= 2) {
				char buffer[1024];

				vp_prints_value(buffer, sizeof(buffer), vp, '"');
				RDEBUG2("%.*s #  Foreach-Variable-%d = %s", depth + 1,
					modcall_spaces, foreach_depth, buffer);
			}
#endif

			/*
			 *	Add the vp to the request, so that
			 *	xlat.c, xlat_foreach() can find it.
			 */
			request_data_add(request, radius_get_vp, foreach_depth, &vp, false);

			/*
			 *	Initialize the childs stack frame.
			 */
			next = entry + 1;
			next->c = g->children;
			next->result = entry->result;
			next->priority = 0;
			next->unwind = 0;

			if (!modcall_recurse(request, component, depth + 1, next)) {
				break;
			}

			/*
			 *	If we've been told to stop processing
			 *	it, do so.
			 */
			if (entry->unwind == MOD_FOREACH) {
				entry->unwind = 0;
				break;
			}
		} /* loop over VPs */

		pairfree(&vps);

		rad_assert(next != NULL);
		result = next->result;
		priority = next->priority;
		MOD_LOG_CLOSE_BRACE();
		goto calculate_result;
	} /* MOD_FOREACH */

	/*
	 *	Break out of a "foreach" loop.
	 */
	if (c->type == MOD_BREAK) {
		int i;
		VALUE_PAIR **copy_p;

		for (i = 8; i >= 0; i--) {
			copy_p = request_data_get(request, radius_get_vp, i);
			if (copy_p) {
				RDEBUG2("%.*s # break Foreach-Variable-%d", depth + 1, modcall_spaces, i);
				break;
			}
		}

		/*
		 *	Leave result / priority on the stack, and stop processing the section.
		 */
		entry->unwind = MOD_FOREACH;
		return true;
	} /* MOD_BREAK */
#endif	  /* WITH_PROXY */

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
			RDEBUG2("%.*s%s { ... } # empty sub-section is ignored",
				depth + 1, modcall_spaces, c->name);
			goto next_sibling;
		}

		if (c->name) {
			MOD_LOG_OPEN_BRACE(cf_section_name1(g->cs));
		} else {
			RDEBUG2("%.*s%s {", depth + 1, modcall_spaces, cf_section_name1(g->cs));
		}
		modcall_child(request, component,
			      depth + 1, entry, g->children,
			      &result);
		MOD_LOG_CLOSE_BRACE();
		goto calculate_result;
	} /* MOD_GROUP */

#ifdef WITH_UNLANG
	if (c->type == MOD_SWITCH) {
		modcallable *this, *found, *null_case;
		modgroup *g, *h;
		fr_cond_t cond;
		value_pair_map_t map;

		MOD_LOG_OPEN_BRACE("switch");

		g = mod_callabletogroup(c);

		memset(&cond, 0, sizeof(cond));
		memset(&map, 0, sizeof(map));

		cond.type = COND_TYPE_MAP;
		cond.data.map = &map;

		map.op = T_OP_CMP_EQ;
		map.ci = cf_sectiontoitem(g->cs);

		rad_assert(g->vpt != NULL);

		null_case = found = NULL;

		/*
		 *	The attribute doesn't exist.  We can skip
		 *	directly to the default 'case' statement.
		 */
		if ((g->vpt->type == VPT_TYPE_ATTR) && (radius_tmpl_get_vp(NULL, request, g->vpt) < 0)) {
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
			if ((g->vpt->type == VPT_TYPE_ATTR) &&
			    (h->vpt->type != VPT_TYPE_DATA)) {
				map.src = g->vpt;
				map.dst = h->vpt;
				cond.cast = g->vpt->vpt_da;

				/*
				 *	Remove unnecessary casting.
				 */
				if ((h->vpt->type == VPT_TYPE_ATTR) &&
				    (g->vpt->vpt_da->type == h->vpt->vpt_da->type)) {
					cond.cast = NULL;
				}
			} else {
				map.src = h->vpt;
				map.dst = g->vpt;
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
		modcall_child(request, component,
			      depth + 1, entry, found,
			      &result);
		MOD_LOG_CLOSE_BRACE();
		goto calculate_result;
	} /* MOD_SWITCH */
#endif

	if ((c->type == MOD_LOAD_BALANCE) ||
	    (c->type == MOD_REDUNDANT_LOAD_BALANCE)) {
		uint32_t count = 0;
		modcallable *this, *found;
		modgroup *g;

		MOD_LOG_OPEN_BRACE("load-balance");

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

		MOD_LOG_OPEN_BRACE(group_name[c->type]);

		if (c->type == MOD_LOAD_BALANCE) {
			modcall_child(request, component,
				      depth + 1, entry, found,
				      &result);

		} else {
			this = found;

			do {
				modcall_child(request, component,
					      depth + 1, entry, this,
					      &result);
				if (this->actions[result] == MOD_ACTION_RETURN) {
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
			radius_exec_program(request, mx->xlat_name, false, true, NULL, 0,
					    EXEC_TIMEOUT, request->packet->vps, NULL);
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
		return true;
	}

	/*
	 *	If "reject", break out of the loop and return
	 *	reject.
	 */
	if (c->actions[result] == MOD_ACTION_REJECT) {
		entry->result = RLM_MODULE_REJECT;
		return true;
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
	if (c->type == MOD_CASE) return true;
#endif

	/*
	 *	If we've been told to stop processing
	 *	it, do so.
	 */
	if (entry->unwind != 0) {
		RDEBUG2("%.*s # unwind to enclosing %s", depth + 1, modcall_spaces,
			group_name[entry->unwind]);
		entry->unwind = 0;
		return true;
	}

next_sibling:
	entry->c = entry->c->next;

	if (entry->c) goto redo;

	/*
	 *	And we're done!
	 */
	return true;
}


/**
 * @brief Call a module, iteratively, with a local stack, rather than
 *	recursively.  What did Paul Graham say about Lisp...?
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
	if (!modcall_recurse(request, component, 0, &stack[0])) {
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
		      group_name[c->type]);
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
static modcallable *do_compile_modupdate(modcallable *parent, UNUSED rlm_components_t component,
					 CONF_SECTION *cs, char const *name2)
{
	int rcode;
	modgroup *g;
	modcallable *csingle;
	value_pair_map_t *map, *head = NULL;
	CONF_ITEM *ci;

	/*
	 *	This looks at cs->name2 to determine which list to update
	 */
	rcode = radius_attrmap(cs, &head, PAIR_LIST_REQUEST, PAIR_LIST_REQUEST, 128);
	if (rcode < 0) return NULL; /* message already printed */

	if (!head) {
		cf_log_err_cs(cs, "'update' sections cannot be empty");
		return NULL;
	}

	for (map = head, ci = cf_item_find_next(cs, NULL);
	     map != NULL;
	     map = map->next, ci = cf_item_find_next(cs, ci)) {
		/*
		 *	Can't copy an xlat expansion or literal into a list,
		 *	we don't know what type of attribute we'd need
		 *	to create.
		 *
		 *	The only exception is where were using a unary
		 *	operator like !*.
		 */
		if ((map->dst->type == VPT_TYPE_LIST) &&
		    (map->op != T_OP_CMP_FALSE) &&
		    ((map->src->type == VPT_TYPE_XLAT) || (map->src->type == VPT_TYPE_LITERAL))) {
			cf_log_err(map->ci, "Can't copy value into list (we don't know which attribute to create)");
			talloc_free(head);
			return NULL;
		}

		/*
		 *	If LHS is an attribute, and RHS is a literal, we can
		 *	preparse the information into a VPT_TYPE_DATA.
		 *
		 *	Unless it's a unary operator in which case we
		 *	ignore map->src.
		 */
		if ((map->dst->type == VPT_TYPE_ATTR) && (map->op != T_OP_CMP_FALSE) &&
		    (map->src->type == VPT_TYPE_LITERAL)) {
			CONF_PAIR *cp;

			cp = cf_itemtopair(ci);
			rad_assert(cp != NULL);

			/*
			 *	It's a literal string, just copy it.
			 *	Don't escape anything.
			 */
			if ((map->dst->vpt_da->type == PW_TYPE_STRING) &&
			    (cf_pair_value_type(cp) == T_SINGLE_QUOTED_STRING)) {
				value_data_t *vpd;

				map->src->vpt_value = vpd = talloc_zero(map->src, value_data_t);
				rad_assert(vpd != NULL);

				vpd->strvalue = talloc_typed_strdup(vpd, map->src->name);
				rad_assert(vpd->strvalue != NULL);

				map->src->type = VPT_TYPE_DATA;
				map->src->vpt_da = map->dst->vpt_da;
				map->src->vpt_length = talloc_array_length(vpd->strvalue) - 1;
			} else {
				if (!radius_cast_tmpl(map->src, map->dst->vpt_da)) {
					cf_log_err(map->ci, "%s", fr_strerror());
					talloc_free(head);
					return NULL;
				}
			}
		} /* else we can't precompile the data */
	} /* loop over the conf_pairs in the update section */

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

	memcpy(csingle->actions, defaultactions[component][GROUPTYPE_SIMPLE],
	       sizeof(csingle->actions));

	g->grouptype = GROUPTYPE_SIMPLE;
	g->children = NULL;
	g->cs = cs;
	g->map = head;

	return csingle;
}


static modcallable *do_compile_modswitch(modcallable *parent, rlm_components_t component, CONF_SECTION *cs)
{
	CONF_ITEM *ci;
	FR_TOKEN type;
	char const *name2;
	bool had_seen_default = false;
	modcallable *csingle;
	modgroup *g;
	value_pair_tmpl_t *vpt;

	name2 = cf_section_name2(cs);
	if (!name2) {
		cf_log_err_cs(cs,
			   "You must specify a variable to switch over for 'switch'");
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
	vpt = radius_str2tmpl(cs, name2, type, REQUEST_CURRENT, PAIR_LIST_REQUEST);
	if (!vpt && ((type != T_BARE_WORD) || (name2[0] != '&'))) {
		cf_log_err_cs(cs, "Syntax error in '%s': %s", name2, fr_strerror());
		return NULL;
	}

	/*
	 *	Otherwise a NULL vpt may refer to an attribute defined
	 *	by a module.  That is checked in pass 2.
	 */

	/*
	 *	Walk through the children of the switch section,
	 *	ensuring that they're all 'case' statements
	 */
	for (ci=cf_item_find_next(cs, NULL);
	     ci != NULL;
	     ci=cf_item_find_next(cs, ci)) {
		CONF_SECTION *subcs;
		char const *name1;

		if (!cf_item_is_section(ci)) {
			if (!cf_item_is_pair(ci)) continue;

			cf_log_err(ci, "\"switch\" sections can only have \"case\" subsections");
			talloc_free(vpt);
			return NULL;
		}

		subcs = cf_itemtosection(ci);	/* can't return NULL */
		name1 = cf_section_name1(subcs);

		if (strcmp(name1, "case") != 0) {
			cf_log_err(ci, "\"switch\" sections can only have \"case\" subsections");
			talloc_free(vpt);
			return NULL;
		}

		name2 = cf_section_name2(subcs);
		if (!name2 && !had_seen_default) {
			had_seen_default = true;
			continue;
		}

		if (!name2 || (name2[0] == '\0')) {
			cf_log_err(ci, "\"case\" sections must have a name");
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
	g->vpt = vpt;

	return csingle;
}

static modcallable *do_compile_modcase(modcallable *parent, rlm_components_t component, CONF_SECTION *cs)
{
	int i;
	char const *name2;
	modcallable *csingle;
	modgroup *g;
	value_pair_tmpl_t *vpt;

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
		FR_TOKEN type;

		type = cf_section_name2_type(cs);

		vpt = radius_str2tmpl(cs, name2, type, REQUEST_CURRENT, PAIR_LIST_REQUEST);
		if (!vpt && ((type != T_BARE_WORD) || (name2[0] != '&'))) {
			cf_log_err_cs(cs, "Syntax error in '%s': %s", name2, fr_strerror());
			return NULL;
		}

		/*
		 *	Otherwise a NULL vpt may refer to an attribute defined
		 *	by a module.  That is checked in pass 2.
		 */

	} else {
		vpt = NULL;
	}

	csingle= do_compile_modgroup(parent, component, cs,
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
	g->vpt = vpt;

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
					  UNUSED rlm_components_t component, CONF_SECTION *cs)
{
	FR_TOKEN type;
	char const *name2;
	modcallable *csingle;
	modgroup *g;
	value_pair_tmpl_t *vpt;

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
	vpt = radius_str2tmpl(cs, name2, type, REQUEST_CURRENT, PAIR_LIST_REQUEST);
	if (!vpt && ((type != T_BARE_WORD) || (name2[0] != '&'))) {
		cf_log_err_cs(cs, "Syntax error in '%s': %s", name2, fr_strerror());
		return NULL;
	}

	if (vpt && (vpt->type != VPT_TYPE_ATTR)) {
		cf_log_err_cs(cs, "MUST use attribute reference in 'foreach'");
		return NULL;
	}

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
	     cs = cf_item_parent(cf_sectiontoitem(cs))) {
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
				       rlm_components_t component, char const *fmt)
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
			CONF_SECTION *subcs = cf_itemtosection(ci);
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
					 rlm_components_t component, CONF_ITEM *ci,
					 int grouptype,
					 char const **modname)
{
	char const *modrefname;
	modsingle *single;
	modcallable *csingle;
	module_instance_t *this;
	CONF_SECTION *cs, *subcs, *modules;
	char const *realname;

	if (cf_item_is_section(ci)) {
		char const *name2;

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
						   grouptype, MOD_GROUP);

		} else if (strcmp(modrefname, "redundant") == 0) {
			*modname = name2;

			if (!all_children_are_modules(cs, modrefname)) {
				return NULL;
			}

			return do_compile_modgroup(parent, component, cs,
						   GROUPTYPE_REDUNDANT,
						   grouptype, MOD_GROUP);

		} else if (strcmp(modrefname, "append") == 0) {
			*modname = name2;
			return do_compile_modgroup(parent, component, cs,
						   GROUPTYPE_APPEND,
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

			return do_compile_modswitch(parent, component, cs);

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
							   grouptype, MOD_GROUP);
			}
		}
	}

#ifdef WITH_UNLANG
	if (strcmp(modrefname, "break") == 0) {
		return do_compile_modbreak(parent, component, ci);
	}
#endif

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
		 *	As of v3, only known modules are in the
		 *	"modules" section.
		 */
		if (cf_section_sub_find_name2(modules, NULL, realname)) {
			this = find_module_instance(modules, realname, true);
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

				this = find_module_instance(modules, buffer, true);
				if (this && !this->entry->module->methods[i]) {
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
	csingle->name = realname;
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

modcallable *compile_modsingle(modcallable **parent,
			       rlm_components_t component, CONF_ITEM *ci,
			       char const **modname)
{
	modcallable *ret;

	if (!*parent) {
		modcallable *c;
		modgroup *g;
		CONF_SECTION *parentcs;

		g = rad_malloc(sizeof *g);
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

	g = rad_malloc(sizeof(*g));
	memset(g, 0, sizeof(*g));
	g->grouptype = grouptype;
	g->children = NULL;
	g->cs = cs;

	c = mod_grouptocallable(g);
	c->parent = parent;
	c->type = mod_type;
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
				     group_name[g->mc.type],
				     cf_section_filename(g->cs), cf_section_lineno(g->cs));
				goto set_codes;
			}

		} else if (c->type == MOD_ELSIF) {

			g->cond = cf_data_find(g->cs, "if");
			rad_assert(g->cond != NULL);

			rad_assert(parent != NULL);
			p = mod_callabletogroup(parent);

			rad_assert(p->tail != NULL);

			f = mod_callabletogroup(p->tail);
			rad_assert((f->mc.type == MOD_IF) ||
				   (f->mc.type == MOD_ELSIF));

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
				     group_name[g->mc.type],
				     group_name[f->mc.type],
				     cf_section_filename(g->cs), cf_section_lineno(g->cs));
				g->cond = f->cond;
				goto set_codes;
			}
			goto check_if;

		} else {
			rad_assert(c->type == MOD_ELSE);

			rad_assert(parent != NULL);
			p = mod_callabletogroup(parent);

			rad_assert(p->tail != NULL);

			f = mod_callabletogroup(p->tail);
			rad_assert((f->mc.type == MOD_IF) ||
				   (f->mc.type == MOD_ELSIF));

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
			char const *attr, *value;
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
				char const *junk = NULL;

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
			modcallable_free(&c);
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

	if (debug_flag > 3) {
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
		talloc_free(g->map);
	}
	free(c);
	*pc = NULL;
}


#ifdef WITH_UNLANG
static char const spaces[] = "                                                                                                                        ";

static bool pass2_xlat_compile(CONF_ITEM const *ci, value_pair_tmpl_t **pvpt, bool convert)
{
	ssize_t slen;
	char *fmt;
	char const *error;
	xlat_exp_t *head;
	value_pair_tmpl_t *vpt;

	vpt = *pvpt;

	rad_assert(vpt->type == VPT_TYPE_XLAT);

	fmt = talloc_typed_strdup(vpt, vpt->name);
	slen = xlat_tokenize(vpt, fmt, &head, &error);

	if (slen < 0) {
		char const *prefix = "";
		char const *p = vpt->name;
		size_t indent = -slen;

		if (indent >= sizeof(spaces)) {
			size_t offset = (indent - (sizeof(spaces) - 1)) + (sizeof(spaces) * 0.75);
			indent -= offset;
			p += offset;

			prefix = "...";
		}

		cf_log_err(ci, "Failed parsing expanded string:");
		cf_log_err(ci, "%s%s", prefix, p);
		cf_log_err(ci, "%s%.*s^ %s", prefix, (int) indent, spaces, error);

		return false;
	}

	/*
	 *	Convert %{Attribute-Name} to &Attribute-Name
	 */
	if (convert) {
		value_pair_tmpl_t *attr;

		attr = radius_xlat2tmpl(talloc_parent(vpt), head);
		if (attr) {
			if (cf_item_is_pair(ci)) {
				CONF_PAIR *cp = cf_itemtopair(ci);

				WARN("%s[%d] Please change %%{%s} to &%s",
				       cf_pair_filename(cp), cf_pair_lineno(cp),
				       attr->name, attr->name);
			} else {
				CONF_SECTION *cs = cf_itemtosection(ci);

				WARN("%s[%d] Please change %%{%s} to &%s",
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
	vpt->type = VPT_TYPE_XLAT_STRUCT;
	vpt->vpt_xlat = head;

	return true;
}


#ifdef HAVE_REGEX_H
static int _free_compiled_regex(regex_t *preg)
{
	regfree(preg);
	return 0;
}

static bool pass2_regex_compile(CONF_ITEM const *ci, value_pair_tmpl_t *vpt)
{
	int rcode;
	regex_t *preg;

	rad_assert(vpt->type == VPT_TYPE_REGEX);

	/*
	 *	Expanded at run-time.  We can't precompile it.
	 */
	if (strchr(vpt->name, '%')) return true;

	preg = talloc_zero(vpt, regex_t);
	talloc_set_destructor(preg, _free_compiled_regex);
	if (!preg) return false;

	rcode = regcomp(preg, vpt->name, REG_EXTENDED | (vpt->vpt_iflag ? REG_ICASE : 0));
	if (rcode != 0) {
		char buffer[256];
		regerror(rcode, preg, buffer, sizeof(buffer));

		cf_log_err(ci, "Invalid regular expression %s: %s",
			   vpt->name, buffer);
		return false;
	}

	vpt->type = VPT_TYPE_REGEX_STRUCT;
	vpt->vpt_preg = preg;

	return true;
}
#endif

static bool pass2_callback(UNUSED void *ctx, fr_cond_t *c)
{
	value_pair_map_t *map;

	if (c->type == COND_TYPE_EXISTS) {

		if (c->data.vpt->type == VPT_TYPE_XLAT) {
			return pass2_xlat_compile(c->ci, &c->data.vpt, true);
		}

		rad_assert(c->data.vpt->type != VPT_TYPE_REGEX);

		/*
		 *	The existence check might have been &Foo-Bar,
		 *	where Foo-Bar is defined by a module.
		 */
		if (c->pass2_fixup == PASS2_FIXUP_ATTR) {
			value_pair_tmpl_t *vpt;
			vpt = radius_str2tmpl(c, c->data.vpt->name, T_BARE_WORD, REQUEST_CURRENT, PAIR_LIST_REQUEST);
			if (!vpt) {
				cf_log_err(c->ci, "Unknown attribute '%s'", c->data.vpt->name + 1);
				return false;
			}

			talloc_free(c->data.vpt);
			c->data.vpt = vpt;
			c->pass2_fixup = PASS2_FIXUP_NONE;
		}
		return true;
	}

	/*
	 *	Maps have a paircompare fixup applied to them.
	 *	Others get ignored.
	 */
	if (c->pass2_fixup == PASS2_FIXUP_NONE) {
		if (c->type == COND_TYPE_MAP) {
			map = c->data.map;
			goto check_paircmp;
		}

		return true;
	}

	map = c->data.map;	/* shorter */

	/*
	 *	Auth-Type := foo
	 *
	 *	Where "foo" is dynamically defined.
	 */
	if (c->pass2_fixup == PASS2_FIXUP_TYPE) {
		if (!dict_valbyname(map->dst->vpt_da->attr,
				    map->dst->vpt_da->vendor,
				    map->src->name)) {
			cf_log_err(map->ci, "Invalid reference to non-existent %s %s { ... }",
				   map->dst->vpt_da->name,
				   map->src->name);
			return false;
		}

		/*
		 *	These guys can't have a paircompare fixup applied.
		 */
		c->pass2_fixup = PASS2_FIXUP_NONE;
		return true;
	}

	if (c->pass2_fixup == PASS2_FIXUP_ATTR) {
		value_pair_map_t *old;
		value_pair_tmpl_t vpt;

		old = c->data.map;

		/*
		 *	It's still not an attribute.  Ignore it.
		 */
		if (radius_parse_attr(&vpt, map->dst->name, REQUEST_CURRENT, PAIR_LIST_REQUEST) < 0) {
			cf_log_err(old->ci, "Failed parsing condition: %s", fr_strerror());
			c->pass2_fixup = PASS2_FIXUP_NONE;
			return true;
		}

		/*
		 *	Re-parse the LHS as an attribute.
		 */
		map = radius_str2map(c, old->dst->name, T_BARE_WORD, old->op,
				     old->src->name, T_BARE_WORD,
				     REQUEST_CURRENT, PAIR_LIST_REQUEST,
				     REQUEST_CURRENT, PAIR_LIST_REQUEST);
		if (!map) {
			cf_log_err(old->ci, "Failed parsing condition");
			return false;
		}
		map->ci = old->ci;
		talloc_free(old);
		c->data.map = map;
		c->pass2_fixup = PASS2_FIXUP_NONE;
	}

check_paircmp:
	/*
	 *	Just in case someone adds a new fixup later.
	 */
	rad_assert((c->pass2_fixup == PASS2_FIXUP_NONE) ||
		   (c->pass2_fixup == PASS2_PAIRCOMPARE));

	/*
	 *	Precompile xlat's
	 */
	if (map->dst->type == VPT_TYPE_XLAT) {
		/*
		 *	Don't compile the LHS to an attribute
		 *	reference for now.  When we do that, we've got
		 *	to check the RHS for type-specific data, and
		 *	parse it to a VPT_TYPE_DATA.
		 */
		if (!pass2_xlat_compile(map->ci, &map->dst, false)) {
			return false;
		}
	}

	if (map->src->type == VPT_TYPE_XLAT) {
		/*
		 *	Convert the RHS to an attribute reference only
		 *	if the LHS is an attribute reference, too.
		 *
		 *	We can fix this when the code in evaluate.c
		 *	can handle strings on the LHS, and attributes
		 *	on the RHS.  For now, the code in parser.c
		 *	forbids this.
		 */
		if (!pass2_xlat_compile(map->ci, &map->src, (map->dst->type == VPT_TYPE_ATTR))) {
			return false;
		}
	}

	/*
	 *	Convert bare refs to %{Foreach-Variable-N}
	 */
	if ((map->dst->type == VPT_TYPE_LITERAL) &&
	    (strncmp(map->dst->name, "Foreach-Variable-", 17) == 0)) {
		char *fmt;
		value_pair_tmpl_t *vpt;

		fmt = talloc_asprintf(map->dst, "%%{%s}", map->dst->name);
		vpt = radius_str2tmpl(map, fmt, T_DOUBLE_QUOTED_STRING, REQUEST_CURRENT, PAIR_LIST_REQUEST);
		if (!vpt) {
			cf_log_err(map->ci, "Failed compiling %s", map->dst->name);
			talloc_free(fmt);
			return false;
		}
		talloc_free(map->dst);
		map->dst = vpt;
	}

#ifdef HAVE_REGEX_H
	if (map->src->type == VPT_TYPE_REGEX) {
		if (!pass2_regex_compile(map->ci, map->src)) {
			return false;
		}
	}
	rad_assert(map->dst->type != VPT_TYPE_REGEX);
#endif

	/*
	 *	Only attributes can have a paircompare registered, and
	 *	they can only be with the current REQUEST, and only
	 *	with the request pairs.
	 */
	if ((map->dst->type != VPT_TYPE_ATTR) ||
	    (map->dst->vpt_request != REQUEST_CURRENT) ||
	    (map->dst->vpt_list != PAIR_LIST_REQUEST)) {
		return true;
	}

	if (!radius_find_compare(map->dst->vpt_da)) return true;

	if (map->src->type == VPT_TYPE_ATTR) {
		cf_log_err(map->ci, "Cannot compare virtual attribute %s to another attribute",
			   map->dst->name);
		return false;
	}

	if (map->src->type == VPT_TYPE_REGEX) {
		cf_log_err(map->ci, "Cannot compare virtual attribute %s via a regex",
			   map->dst->name);
		return false;
	}

	if (c->cast) {
		cf_log_err(map->ci, "Cannot cast virtual attribute %s",
			   map->dst->name);
		return false;
	}

	if (map->op != T_OP_CMP_EQ) {
		cf_log_err(map->ci, "Must use '==' for comparisons with virtual attribute %s",
			   map->dst->name);
		return false;
	}

	/*
	 *	Mark it as requiring a paircompare() call, instead of
	 *	paircmp().
	 */
	c->pass2_fixup = PASS2_PAIRCOMPARE;

	return true;
}


/*
 *	Compile the RHS of update sections to xlat_exp_t
 */
static bool modcall_pass2_update(modgroup *g)
{
	value_pair_map_t *map;

	for (map = g->map; map != NULL; map = map->next) {
		if (map->src->type == VPT_TYPE_XLAT) {
			rad_assert(map->src->vpt_xlat == NULL);

			/*
			 *	FIXME: compile to attribute && handle
			 *	the conversion in radius_map2vp().
			 */
			if (!pass2_xlat_compile(map->ci, &map->src, false)) {
				return false;
			}
		}

		rad_assert(map->src->type != VPT_TYPE_REGEX);
	}

	return true;
}
#endif

/*
 *	Do a second-stage pass on compiling the modules.
 */
bool modcall_pass2(modcallable *mc)
{
	modcallable *this;
	modgroup *g;

	for (this = mc; this != NULL; this = this->next) {
		switch (this->type) {
		default:
			rad_assert(0 == 1);
			break;

#ifdef WITH_UNLANG
		case MOD_UPDATE:
			g = mod_callabletogroup(this);
			if (g->done_pass2) return true;

			if (!modcall_pass2_update(g)) {
				return false;
			}
			g->done_pass2 = true;
			break;

		case MOD_XLAT:   /* @todo: pre-parse xlat's */
		case MOD_BREAK:
		case MOD_REFERENCE:
#endif

		case MOD_SINGLE:
			break;	/* do nothing */

#ifdef WITH_UNLANG
		case MOD_IF:
		case MOD_ELSIF:
			g = mod_callabletogroup(this);
			if (g->done_pass2) return true;

			/*
			 *	Don't walk over these.
			 */
			if ((g->cond->type == COND_TYPE_TRUE) ||
			    (g->cond->type == COND_TYPE_FALSE)) {
				break;
			}

			/*
			 *	The compilation code takes care of
			 *	simplifying 'true' and 'false'
			 *	conditions.  For others, we have to do
			 *	a second pass to parse && compile xlats.
			 */
			if (!fr_condition_walk(g->cond, pass2_callback, NULL)) {
				return false;
			}

			if (!modcall_pass2(g->children)) return false;
			g->done_pass2 = true;
			break;
#endif

#ifdef WITH_UNLANG
		case MOD_SWITCH:
			g = mod_callabletogroup(this);
			if (g->done_pass2) return true;

			/*
			 *	We had &Foo-Bar, where Foo-Bar is
			 *	defined by a module.
			 */
			if (!g->vpt) {
				rad_assert(this->name != NULL);
				rad_assert(this->name[0] == '&');
				rad_assert(cf_section_name2_type(g->cs) == T_BARE_WORD);
				goto do_case;
			}

			/*
			 *	Statically compile xlats
			 */
			if (g->vpt->type == VPT_TYPE_XLAT) goto do_case_xlat;

			/*
			 *	We may have: switch Foo-Bar {
			 *
			 *	where Foo-Bar is an attribute defined
			 *	by a module.  Since there's no leading
			 *	&, it's parsed as a literal.  But if
			 *	we can parse it as an attribute,
			 *	switch to using that.
			 */
			if (g->vpt->type == VPT_TYPE_LITERAL) {
				value_pair_tmpl_t *vpt;

				vpt = radius_str2tmpl(g->cs, this->name,
						      cf_section_name2_type(g->cs),
						      REQUEST_CURRENT, PAIR_LIST_REQUEST);
				if (vpt->type == VPT_TYPE_ATTR) {
					talloc_free(g->vpt);
					g->vpt = vpt;
				}
			}

			/*
			 *	Warn about old-style configuration.
			 *
			 *	DEPRECATED: switch User-Name { ...
			 *	ALLOWED   : switch &User-Name { ...
			 */
			if ((g->vpt->type == VPT_TYPE_ATTR) &&
			    (this->name[0] != '&')) {
				WARN("%s[%d]: Please change %s to &%s",
				       cf_section_filename(g->cs),
				       cf_section_lineno(g->cs),
				       this->name, this->name);
			}

			if (!modcall_pass2(g->children)) return false;
			g->done_pass2 = true;
			break;

		case MOD_CASE:
			g = mod_callabletogroup(this);
			if (g->done_pass2) return true;

		do_case:
			/*
			 *	The statement may refer to an
			 *	attribute which doesn't exist until
			 *	all of the modules have been loaded.
			 *	Check for that now.
			 */
			if (!g->vpt && this->name &&
			    (this->name[0] == '&') &&
			    (cf_section_name2_type(g->cs) == T_BARE_WORD)) {
				g->vpt = radius_str2tmpl(g->cs, this->name,
							 cf_section_name2_type(g->cs),
							 REQUEST_CURRENT, PAIR_LIST_REQUEST);
				if (!g->vpt) {
					cf_log_err_cs(g->cs, "Syntax error in '%s': %s",
						      this->name, fr_strerror());
					return false;
				}
			}

			/*
			 *	Do type-specific checks on the case statement
			 */
			if (g->vpt && (g->vpt->type == VPT_TYPE_LITERAL)) {
				modgroup *f;

				rad_assert(this->parent != NULL);
				rad_assert(this->parent->type == MOD_SWITCH);

				f = mod_callabletogroup(mc->parent);
				rad_assert(f->vpt != NULL);

				/*
				 *	We're switching over an
				 *	attribute.  Check that the
				 *	values match.
				 */
				if (f->vpt->type == VPT_TYPE_ATTR) {
					rad_assert(f->vpt->vpt_da != NULL);

					if (!radius_cast_tmpl(g->vpt, f->vpt->vpt_da)) {
						cf_log_err_cs(g->cs, "Invalid argument for case statement: %s",
							      fr_strerror());
						return false;
					}
				}
			}

		do_case_xlat:
			/*
			 *	Compile and sanity check xlat
			 *	expansions.
			 */
			if (g->vpt &&
			    (g->vpt->type == VPT_TYPE_XLAT) &&
			    (!pass2_xlat_compile(cf_sectiontoitem(g->cs),
						 &g->vpt, true))) {
				return false;
			}

			if (!modcall_pass2(g->children)) return false;
			g->done_pass2 = true;
			break;

		case MOD_FOREACH:
			g = mod_callabletogroup(this);
			if (g->done_pass2) return true;

			/*
			 *	Already parsed, handle the children.
			 */
			if (g->vpt) goto check_children;

			/*
			 *	We had &Foo-Bar, where Foo-Bar is
			 *	defined by a module.
			 */
			rad_assert(this->name != NULL);
			rad_assert(this->name[0] == '&');
			rad_assert(cf_section_name2_type(g->cs) == T_BARE_WORD);

			/*
			 *	The statement may refer to an
			 *	attribute which doesn't exist until
			 *	all of the modules have been loaded.
			 *	Check for that now.
			 */
			g->vpt = radius_str2tmpl(g->cs, this->name,
						 cf_section_name2_type(g->cs),
						 REQUEST_CURRENT, PAIR_LIST_REQUEST);
			if (!g->vpt) {
				cf_log_err_cs(g->cs, "Syntax error in '%s': %s",
					      this->name, fr_strerror());
				return false;
			}

		check_children:
			rad_assert(g->vpt->type == VPT_TYPE_ATTR);
			if (g->vpt->vpt_num != NUM_ANY) {
				cf_log_err_cs(g->cs, "MUST NOT use array references in 'foreach'");
				return false;
			}
			if (!modcall_pass2(g->children)) return false;
			g->done_pass2 = true;
			break;

		case MOD_ELSE:
		case MOD_POLICY:
			/* FALL-THROUGH */
#endif

		case MOD_GROUP:
		case MOD_LOAD_BALANCE:
		case MOD_REDUNDANT_LOAD_BALANCE:
			g = mod_callabletogroup(this);
			if (g->done_pass2) return true;
			if (!modcall_pass2(g->children)) return false;
			g->done_pass2 = true;
			break;
		}
	}

	return true;
}

void modcall_debug(modcallable *mc, int depth)
{
	modcallable *this;
	modgroup *g;
	value_pair_map_t *map;
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
				group_name[this->type]);

			for (map = g->map; map != NULL; map = map->next) {
				radius_map2str(buffer, sizeof(buffer), map);
				DEBUG("%.*s%s", depth + 1, modcall_spaces, buffer);
			}

			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case MOD_ELSE:
			g = mod_callabletogroup(this);
			DEBUG("%.*s%s {", depth, modcall_spaces,
				group_name[this->type]);
			modcall_debug(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case MOD_IF:
		case MOD_ELSIF:
			g = mod_callabletogroup(this);
			fr_cond_sprint(buffer, sizeof(buffer), g->cond);
			DEBUG("%.*s%s (%s) {", depth, modcall_spaces,
				group_name[this->type], buffer);
			modcall_debug(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case MOD_SWITCH:
		case MOD_CASE:
			g = mod_callabletogroup(this);
			radius_tmpl2str(buffer, sizeof(buffer), g->vpt);
			DEBUG("%.*s%s %s {", depth, modcall_spaces,
				group_name[this->type], buffer);
			modcall_debug(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;

		case MOD_POLICY:
		case MOD_FOREACH:
			g = mod_callabletogroup(this);
			DEBUG("%.*s%s %s {", depth, modcall_spaces,
				group_name[this->type], this->name);
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
			      group_name[this->type]);
			modcall_debug(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;


		case MOD_LOAD_BALANCE:
		case MOD_REDUNDANT_LOAD_BALANCE:
			g = mod_callabletogroup(this);
			DEBUG("%.*s%s {", depth, modcall_spaces,
				group_name[this->type]);
			modcall_debug(g->children, depth + 1);
			DEBUG("%.*s}", depth, modcall_spaces);
			break;
		}
	}
}
