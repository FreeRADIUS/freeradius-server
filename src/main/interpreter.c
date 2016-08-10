/*
 * @name interpreter.c
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
#include <freeradius-devel/interpreter.h>
#include <freeradius-devel/parser.h>

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
	"map",
#endif
	"policy",
	"reference",
	"xlat",
	NULL
};

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

static rlm_rcode_t CC_HINT(nonnull) unlang_module(rlm_components_t component, modsingle *sp, REQUEST *request)
{
	int blocked;

	/*
	 *	If the request should stop, refuse to do anything.
	 */
	blocked = (request->master_state == REQUEST_STOP_PROCESSING);
	if (blocked) return RLM_MODULE_NOOP;

	RDEBUG3("modsingle[%s]: calling %s (%s) for request %" PRIu64,
		comp2str[component], sp->modinst->name,
		sp->modinst->module->name, request->number);

	if (sp->modinst->force) {
		request->rcode = sp->modinst->code;
		goto fail;
	}

	/*
	 *	For logging unresponsive children.
	 */
	request->module = sp->modinst->name;

	safe_lock(sp->modinst);
	request->rcode = sp->modinst->module->methods[component](sp->modinst->data, request);
	safe_unlock(sp->modinst);

	request->module = NULL;

	/*
	 *	Wasn't blocked, and now is.  Complain!
	 */
	blocked = (request->master_state == REQUEST_STOP_PROCESSING);
	if (blocked) {
		RWARN("Module %s became unblocked for request %" PRIu64 "", sp->modinst->module->name, request->number);
	}

 fail:
	RDEBUG3("modsingle[%s]: returned from %s (%s) for request %" PRIu64,
		comp2str[component], sp->modinst->name,
		sp->modinst->module->name, request->number);

	return request->rcode;
}

#define UNLANG_STACK_MAX (32)

typedef struct unlang_foreach_t {
	vp_cursor_t cursor;
	VALUE_PAIR *vps;
	VALUE_PAIR *variable;
	int depth;
} unlang_foreach_t;

typedef struct unlang_redundant_t {
	modcallable *child;
	modcallable *found;
} unlang_redundant_t;

/*
 *	Don't call the modules recursively.  Instead, do them
 *	iteratively, and manage the call stack ourselves.
 */
typedef struct unlang_stack_entry_t {
	rlm_rcode_t result;
	int priority;
	mod_type_t unwind;		/* unwind to this one if it exists */
	bool do_next_sibling;
	bool was_if;
	bool if_taken;
	bool resume;
	modcallable *c;

	union {
		unlang_foreach_t foreach;
		unlang_redundant_t redundant;
	};
} unlang_stack_entry_t;

typedef struct unlang_stack_t {
	int depth;
	unlang_stack_entry_t entry[UNLANG_STACK_MAX];
} unlang_stack_t;

typedef enum unlang_action_t {
	UNLANG_CALCULATE_RESULT = 1,
	UNLANG_CONTINUE,
	UNLANG_PUSHED_CHILD,
	UNLANG_BREAK
} unlang_action_t;


typedef unlang_action_t (*unlang_function_t)(REQUEST *request, unlang_stack_t *stack,
						      rlm_rcode_t *presult, int *priority);

static void unlang_push(unlang_stack_t *stack, modcallable *c, rlm_rcode_t result, bool do_next_sibling)
{
	unlang_stack_entry_t *next;

	if (stack->depth >= UNLANG_STACK_MAX) {
		ERROR("Internal sanity check failed: module stack is too deep");
		fr_exit(1);
	}

	stack->depth++;

	/*
	 *	Initialize the next stack frame.
	 */
	next = &stack->entry[stack->depth];
	next->c = c;
	next->result = result;
	next->priority = 0;
	next->unwind = MOD_NULL;
	next->do_next_sibling = do_next_sibling;
	next->was_if = false;
	next->if_taken = false;
	next->resume = false;
}

static void unlang_pop(unlang_stack_t *stack)
{
	unlang_stack_entry_t *entry, *next;

	rad_assert(stack->depth > 1);

	stack->depth -= 1;

	entry = &stack->entry[stack->depth];
	next = entry + 1;

	/*
	 *	Unwind back up the stack
	 */
	if (next->unwind != 0) entry->unwind = next->unwind;
}


static unlang_action_t unlang_load_balance(UNUSED REQUEST *request, unlang_stack_t *stack,
					     rlm_rcode_t *presult, int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modgroup *g;

	uint32_t count = 0;

	g = mod_callabletogroup(c);
	if (!g->children) {
		*presult = RLM_MODULE_NOOP;
		*priority = c->actions[*presult];
		return UNLANG_CALCULATE_RESULT;
	}

	/*
	 *	No entry?  This is the first time we've been called.
	 *	Go find one.
	 */
	if (!entry->resume) {
		/*
		 *	Choose a child at random.
		 */
		for (entry->redundant.child = entry->redundant.found = g->children;
		     entry->redundant.child != NULL;
		     entry->redundant.child = entry->redundant.child->next) {
			count++;

			if ((count * (fr_rand() & 0xffff)) < (uint32_t) 0x10000) {
				entry->redundant.found = entry->redundant.child;
			}
		}

		if (c->type == MOD_LOAD_BALANCE) {
			unlang_push(stack, entry->redundant.found, entry->result, false);
			return UNLANG_PUSHED_CHILD;
		}

		entry->redundant.child = entry->redundant.found; /* we start at this one */

	} else {
		rad_assert(c->type != MOD_LOAD_BALANCE); /* this is never called again */

		/*
		 *	We were called again.  See if we're done.
		 */
		if (entry->redundant.child->actions[*presult] == MOD_ACTION_RETURN) {
			return UNLANG_CALCULATE_RESULT;
		}

		entry->redundant.child = entry->redundant.child->next;
		if (!entry->redundant.child) entry->redundant.child = g->children;

		if (entry->redundant.child == entry->redundant.found) {
			return UNLANG_CALCULATE_RESULT;
		}
	}

	/*
	 *	Push the child, and yeild for a later return.
	 */
	unlang_push(stack, entry->redundant.child, entry->result, false);
	entry->resume = true;
	return UNLANG_PUSHED_CHILD;
}


static unlang_action_t unlang_group(REQUEST *request, unlang_stack_t *stack,
				    UNUSED rlm_rcode_t *result, UNUSED int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modgroup *g;

	g = mod_callabletogroup(c);

	/*
	 *	This should really have been caught in the
	 *	compiler, and the node never generated.  But
	 *	doing that requires changing it's API so that
	 *	it returns a flag instead of the compiled
	 *	MOD_GROUP.
	 */
	if (!g->children) {
		RDEBUG2("} # %s ... <ignoring empty subsection>", c->debug_name);
		return UNLANG_CONTINUE;
	}

	unlang_push(stack, g->children, entry->result, true);
	return UNLANG_PUSHED_CHILD;
}

static unlang_action_t unlang_case(REQUEST *request, unlang_stack_t *stack,
				     rlm_rcode_t *presult, int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modgroup *g;

	g = mod_callabletogroup(c);

	if (!g->children) {
		*presult = RLM_MODULE_NOOP;
		// ?? priority
		return UNLANG_CALCULATE_RESULT;
	}

	return unlang_group(request, stack, presult, priority);
}

static unlang_action_t unlang_return(REQUEST *request, unlang_stack_t *stack,
				       rlm_rcode_t *presult, int *priority)
{
	int i;
	VALUE_PAIR **copy_p;
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;

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

	entry->unwind = c->type;

	*presult = entry->result;
	*priority = entry->priority;

	return UNLANG_BREAK;
}

static unlang_action_t unlang_foreach(REQUEST *request, unlang_stack_t *stack,
					rlm_rcode_t *presult, int *priority)
{
	VALUE_PAIR *vp;
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modgroup *g;

	g = mod_callabletogroup(c);

	if (!entry->resume) {
		int i, foreach_depth = -1;
		VALUE_PAIR *vps;

		if (stack->depth >= UNLANG_STACK_MAX) {
			ERROR("Internal sanity check failed: module stack is too deep");
			fr_exit(1);
		}

		/*
		 *	Figure out how deep we are in nesting by looking at request_data
		 *	stored previously.
		 *
		 *	FIXME: figure this out by walking up the modcall stack instead.
		 */
		for (i = 0; i < 8; i++) {
			if (!request_data_reference(request, (void *)radius_get_vp, i)) {
				foreach_depth = i;
				break;
			}
		}

		if (foreach_depth < 0) {
			REDEBUG("foreach Nesting too deep!");
			*presult = RLM_MODULE_FAIL;
			*priority = 0;
			return UNLANG_CALCULATE_RESULT;
		}

		/*
		 *	Copy the VPs from the original request, this ensures deterministic
		 *	behaviour if someone decides to add or remove VPs in the set were
		 *	iterating over.
		 */
		if (tmpl_copy_vps(request, &vps, request, g->vpt) < 0) {	/* nothing to loop over */
			*presult = RLM_MODULE_NOOP;
			*priority = c->actions[RLM_MODULE_NOOP];
			return UNLANG_CALCULATE_RESULT;
		}

		RDEBUG2("foreach %s ", c->name);

		rad_assert(vps != NULL);
		fr_cursor_init(&entry->foreach.cursor, &vps);

		entry->foreach.depth = foreach_depth;
		entry->foreach.vps = vps;

		vp = fr_cursor_first(&entry->foreach.cursor);

	} else {
		vp = fr_cursor_next(&entry->foreach.cursor);

		/*
		 *	We've been asked to unwind to the
		 *	enclosing "foreach".  We're here, so
		 *	we can stop unwinding.
		 */
		if (entry->unwind == MOD_BREAK) {
			entry->unwind = MOD_NULL;
			vp = NULL;
		}

		/*
		 *	Unwind all the way.
		 */
		if (entry->unwind == MOD_RETURN) {
			vp = NULL;
		}

		if (!vp) {
			/*
			 *	Free the copied vps and the request data
			 *	If we don't remove the request data, something could call
			 *	the xlat outside of a foreach loop and trigger a segv.
			 */
			fr_pair_list_free(&entry->foreach.vps);
			request_data_get(request, (void *)radius_get_vp, entry->foreach.depth);

			*presult = entry->result;
			*priority = c->actions[*presult];
			return UNLANG_CALCULATE_RESULT;
		}
	}

#ifndef NDEBUG
	if (fr_debug_lvl >= 2) {
		char buffer[1024];

			fr_pair_value_snprint(buffer, sizeof(buffer), vp, '"');
			RDEBUG2("# Foreach-Variable-%d = %s", entry->foreach.depth, buffer);
		}
#endif

	/*
	 *	Add the vp to the request, so that
	 *	xlat.c, xlat_foreach() can find it.
	 */
	entry->foreach.variable = vp;
	request_data_add(request, (void *)radius_get_vp, entry->foreach.depth, &entry->foreach.variable, false, false, false);

	/*
	 *	Push the child, and yeild for a later return.
	 */
	unlang_push(stack, g->children, entry->result, true);
	entry->resume = true;
	return UNLANG_PUSHED_CHILD;
}

static unlang_action_t unlang_xlat(REQUEST *request, unlang_stack_t *stack,
				     UNUSED rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modxlat *mx = mod_callabletoxlat(c);
	char buffer[128];

	if (!mx->exec) {
		radius_xlat(buffer, sizeof(buffer), request, mx->xlat_name, NULL, NULL);
	} else {
		RDEBUG("`%s`", mx->xlat_name);
		radius_exec_program(request, NULL, 0, NULL, request, mx->xlat_name, request->packet->vps,
				    false, true, EXEC_TIMEOUT);
	}

	return UNLANG_CONTINUE;
}

static unlang_action_t unlang_switch(REQUEST *request, unlang_stack_t *stack,
				       UNUSED rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modcallable *this, *found, *null_case;
	modgroup *g, *h;
	fr_cond_t cond;
	value_data_t data;
	vp_map_t map;
	vp_tmpl_t vpt;

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
		tmpl_init(&vpt, TMPL_TYPE_UNPARSED, data.strvalue, len, T_SINGLE_QUOTED_STRING);
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

	unlang_push(stack, found, entry->result, false);
	return UNLANG_PUSHED_CHILD;
}


static unlang_action_t unlang_update(REQUEST *request, unlang_stack_t *stack,
				       rlm_rcode_t *presult, int *priority)
{
	int rcode;
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modgroup *g = mod_callabletogroup(c);
	vp_map_t *map;

	RINDENT();
	for (map = g->map; map != NULL; map = map->next) {
		rcode = map_to_request(request, map, map_to_vp, NULL);
		if (rcode < 0) {
			*presult = (rcode == -2) ? RLM_MODULE_INVALID : RLM_MODULE_FAIL;
			REXDENT();
			return UNLANG_CALCULATE_RESULT;
		}
	}
	REXDENT();

	*presult = RLM_MODULE_NOOP;
	*priority = c->actions[RLM_MODULE_NOOP];
	return UNLANG_CALCULATE_RESULT;
}


static unlang_action_t unlang_map(REQUEST *request, unlang_stack_t *stack,
				  rlm_rcode_t *presult, int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modgroup *g = mod_callabletogroup(c);

	RINDENT();
	*presult = map_proc(request, g->proc_inst);
	REXDENT();

	*priority = c->actions[*presult];
	return UNLANG_CALCULATE_RESULT;
}

static unlang_action_t unlang_single(REQUEST *request, unlang_stack_t *stack,
				     rlm_rcode_t *presult, int *priority)
{
	modsingle *sp;
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;

	/*
	 *	Process a stand-alone child, and fall through
	 *	to dealing with it's parent.
	 */
	sp = mod_callabletosingle(c);

	*presult = unlang_module(c->method, sp, request);
	*priority = c->actions[*presult];

	RDEBUG2("%s (%s)", c->name ? c->name : "",
		fr_int2str(mod_rcode_table, *presult, "<invalid>"));
	return UNLANG_CALCULATE_RESULT;
}


static unlang_action_t unlang_if(REQUEST *request, unlang_stack_t *stack,
				   rlm_rcode_t *presult, int *priority)
{
	int condition;
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modgroup *g;

	g = mod_callabletogroup(c);
	rad_assert(g->cond != NULL);

	condition = radius_evaluate_cond(request, *presult, 0, g->cond);
	if (condition < 0) {
		switch (condition) {
		case -2:
			REDEBUG("Condition evaluation failed because a referenced attribute "
				"was not found in the request");
			break;
		default:
		case -1:
			REDEBUG("Condition evaluation failed because the value of an operand "
				"could not be determined");
			break;
		}
		condition = 0;
	}

	/*
	 *	Didn't pass.  Remember that.
	 */
	if (!condition) {
		RDEBUG2("  ...");
		entry->was_if = true;
		entry->if_taken = false;

		*priority = c->actions[*presult];
		return UNLANG_CONTINUE;
	}

	/*
	 *	We took the "if".  Go recurse into its' children.
	 */
	entry->was_if = true;
	entry->if_taken = true;

	return unlang_group(request, stack, presult, priority);
}

static unlang_action_t unlang_elsif(REQUEST *request, unlang_stack_t *stack,
				    rlm_rcode_t *presult, int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	rad_assert(entry->was_if);

	/*
	 *	Like MOD_ELSE, but allow for a later "else"
	 */
	if (entry->if_taken) {
		RDEBUG2("... skipping %s for request %" PRIu64 ": Preceding \"if\" was taken",
			unlang_keyword[c->type], request->number);
		entry->if_taken = true;
		return UNLANG_CONTINUE;
	}

	/*
	 *	Check the "if" condition.
	 */
	return unlang_if(request, stack, presult, priority);
}

static unlang_action_t unlang_else(REQUEST *request, unlang_stack_t *stack,
				   rlm_rcode_t *presult, int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	rad_assert(entry->was_if);

	if (entry->if_taken) {
		RDEBUG2("... skipping %s for request %" PRIu64 ": Preceding \"if\" was taken",
			unlang_keyword[c->type], request->number);
		entry->was_if = false;
		entry->if_taken = false;

		*presult = RLM_MODULE_NOOP;
		*priority = c->actions[*presult];
		return UNLANG_CONTINUE;
	}

	/*
	 *	We need to process it.  Go do that.
	 */
	entry->was_if = false;
	entry->if_taken = false;

	return unlang_group(request, stack, presult, priority);
}

/*
 *	Some functions differ mainly in their parsing
 */
#define unlang_redundant_load_balance unlang_load_balance
#define unlang_policy unlang_group
#define unlang_break unlang_return

/*
 *	The jump table for the interpretor
 */
static unlang_function_t unlang_functions[MOD_NUM_TYPES] = {
	[MOD_SINGLE]			= unlang_single,
	[MOD_GROUP]			= unlang_group,
	[MOD_LOAD_BALANCE]		= unlang_load_balance,
	[MOD_REDUNDANT_LOAD_BALANCE]	= unlang_redundant_load_balance,
#ifdef WITH_UNLANG
	[MOD_IF]			= unlang_if,
	[MOD_ELSE]			= unlang_else,
	[MOD_ELSIF]			= unlang_elsif,
	[MOD_UPDATE]			= unlang_update,
	[MOD_SWITCH]			= unlang_switch,
	[MOD_CASE]			= unlang_case,
	[MOD_FOREACH]			= unlang_foreach,
	[MOD_BREAK]			= unlang_break,
	[MOD_RETURN]			= unlang_return,
	[MOD_MAP]			= unlang_map,
#endif
	[MOD_POLICY]			= unlang_policy,
	[MOD_XLAT]			= unlang_xlat,
};

static bool unlang_brace[MOD_NUM_TYPES] = {
	[MOD_SINGLE]			= false,
	[MOD_GROUP]			= true,
	[MOD_LOAD_BALANCE]		= true,
	[MOD_REDUNDANT_LOAD_BALANCE]	= true,
#ifdef WITH_UNLANG
	[MOD_IF]			= true,
	[MOD_ELSE]			= true,
	[MOD_ELSIF]			= true,
	[MOD_UPDATE]			= true,
	[MOD_SWITCH]			= true,
	[MOD_CASE]			= false,
	[MOD_FOREACH]			= true,
	[MOD_BREAK]			= false,
	[MOD_RETURN]			= false,
	[MOD_MAP]			= true,
#endif
	[MOD_POLICY]			= true,
	[MOD_XLAT]			= false,
};


/*
 *	Interpret the various types of blocks.
 */
static void unlang_run(REQUEST *request, unlang_stack_t *stack, rlm_rcode_t *presult, int *ppriority)
{
	modcallable *c;
	int priority;
	rlm_rcode_t result;
	unlang_stack_entry_t *entry;
	unlang_action_t action = UNLANG_BREAK;

redo:
	result = RLM_MODULE_UNKNOWN;
	priority = -1;

	rad_assert(stack->depth > 0);
	rad_assert(stack->depth < UNLANG_STACK_MAX);

	entry = &stack->entry[stack->depth];

	RINDENT();

	/*
	 *	Loop over all modules in this list.
	 */
	while (entry->c != NULL) {
		c = entry->c;

		if (fr_debug_lvl >= 3) VERIFY_REQUEST(request);

		rad_assert(c->debug_name != NULL); /* if this happens, all bets are off. */

		/*
		 *	We've been asked to stop.  Do so.
		 */
		if ((request->master_state == REQUEST_STOP_PROCESSING) ||
		    (request->parent &&
		     (request->parent->master_state == REQUEST_STOP_PROCESSING))) {
			entry->result = RLM_MODULE_FAIL;
			entry->priority = 9999;
			entry->unwind = MOD_RETURN;
			break;
		}

		if (unlang_brace[c->type]) RDEBUG2("%s {", c->debug_name);

		action = unlang_functions[c->type](request, stack, &result, &priority);
		switch (action) {
		case UNLANG_PUSHED_CHILD:
			goto redo;

		 case UNLANG_BREAK:
			 entry->result = result;
			 goto done;

		do_pop:
			unlang_pop(stack);

			entry = &stack->entry[stack->depth];

			c = entry->c;
			rad_assert(c != NULL);

			/*
			 *	We need to call the function again, to
			 *	see if it's done.
			 */
			if (entry->resume) continue;

			/* FALL-THROUGH */

		case UNLANG_CALCULATE_RESULT:
			entry->resume = false;
			if (unlang_brace[c->type]) RDEBUG2("} # %s (%s)", c->debug_name,
							    fr_int2str(mod_rcode_table, result, "<invalid>"));
			action = UNLANG_CALCULATE_RESULT;

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
			if (c->actions[result] == MOD_ACTION_RETURN) {
				entry->result = result;
				goto done;
			}

			/*
			 *	If "reject", break out of the loop and return
			 *	reject.
			 */
			if (c->actions[result] == MOD_ACTION_REJECT) {
				entry->result = RLM_MODULE_REJECT;
				goto done;
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
			 *	If we've been told to stop processing
			 *	it, do so.
			 */
			if (entry->unwind != 0) goto done;

			/* FALL-THROUGH */

		case UNLANG_CONTINUE:
			if ((action == UNLANG_CONTINUE) && unlang_brace[c->type]) RDEBUG2("}");

			if (!entry->do_next_sibling) goto done;

		} /* switch over return code from the interpretor function */

		entry->c = entry->c->next;
	}

	/*
	 *	And we're done!
	 */
done:
	REXDENT();

	*presult = entry->result;
	*ppriority = priority;

	/*
	 *	Done the top stack frame, return
	 */
	if (stack->depth == 1) return;

	result = entry->result;
	goto do_pop;
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


/** Call a module, iteratively, with a local stack, rather than recursively
 *
 * What did Paul Graham say about Lisp...?
 */
rlm_rcode_t unlang_interpret(REQUEST *request, modcallable *c, rlm_components_t component)
{
	int priority;
	rlm_rcode_t result;
	unlang_stack_t stack;

	if (!c) return default_component_results[component];

	memset(&stack, 0, sizeof(stack));

	result = default_component_results[component];
	priority = 0;

	unlang_push(&stack, c, result, true);

	/*
	 *	Call the main handler.
	 */
	unlang_run(request, &stack, &result, &priority);

	/*
	 *	Return the result.
	 */
	return result;
}
