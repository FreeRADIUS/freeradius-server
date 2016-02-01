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

char const modcall_spaces[] = "                                                                                                                                                                                                                                                                ";

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

static rlm_rcode_t CC_HINT(nonnull) call_modsingle(rlm_components_t component, modsingle *sp, REQUEST *request)
{
	int blocked;

	/*
	 *	If the request should stop, refuse to do anything.
	 */
	blocked = (request->master_state == REQUEST_STOP_PROCESSING);
	if (blocked) return RLM_MODULE_NOOP;

	RDEBUG3("modsingle[%s]: calling %s (%s) for request %d",
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
		RWARN("Module %s became unblocked for request %u", sp->modinst->module->name, request->number);
	}

 fail:
	RDEBUG3("modsingle[%s]: returned from %s (%s) for request %d",
		comp2str[component], sp->modinst->name,
		sp->modinst->module->name, request->number);

	return request->rcode;
}

#define MODCALL_STACK_MAX (32)

/*
 *	Don't call the modules recursively.  Instead, do them
 *	iteratively, and manage the call stack ourselves.
 */
typedef struct modcall_stack_entry_t {
	rlm_rcode_t result;
	int priority;
	int unwind;		/* unwind to this one if it exists */
	bool do_next_sibling;
	bool was_if;
	bool if_taken;
	bool iterative;
	bool resume;
	modcallable *c;
	vp_cursor_t cursor;	/* foreach */
	modcallable *child;	/* redundant */
	modcallable *found;	/* redundant */
} modcall_stack_entry_t;

typedef struct modcall_stack_t {
	rlm_components_t component;
	int depth;
	modcall_stack_entry_t entry[MODCALL_STACK_MAX];
} modcall_stack_t;

typedef enum modcall_action_t {
	MODCALL_CALCULATE_RESULT = 1,
	MODCALL_NEXT_SIBLING,
	MODCALL_DO_CHILDREN,
	MODCALL_ITERATIVE,
	MODCALL_YEILD,
	MODCALL_BREAK
} modcall_action_t;


typedef modcall_action_t (*modcall_function_t)(REQUEST *request, modcall_stack_t *stack,
						      rlm_rcode_t *presult, int *priority);

static void modcall_recurse(REQUEST *request, modcall_stack_t *stack, rlm_rcode_t *presult, int *ppriority);

static void modcall_push(modcall_stack_t *stack, modcallable *c, rlm_rcode_t result, bool do_next_sibling)
{
	modcall_stack_entry_t *next;

	if (stack->depth >= MODCALL_STACK_MAX) {
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
	next->unwind = 0;
	next->do_next_sibling = do_next_sibling;
	next->was_if = false;
	next->if_taken = false;
	next->iterative = false;
	next->resume = false;
	memset(&next->cursor, 0, sizeof(next->cursor));
	next->child = next->found = NULL;
}

static void modcall_pop(modcall_stack_t *stack)
{
	modcall_stack_entry_t *entry, *next;

	rad_assert(stack->depth > 1);

	stack->depth -= 1;

	entry = &stack->entry[stack->depth];
	next = entry + 1;

	/*
	 *	Unwind back up the stack
	 */
	if (next->unwind != 0) entry->unwind = next->unwind;
}

/*
 *	Call a child of a block.
 */
static void modcall_child(REQUEST *request, modcall_stack_t *stack, modcallable *c,
			  rlm_rcode_t *result, int *priority, bool do_next_sibling)
{
	modcall_push(stack, c, stack->entry[stack->depth].result, do_next_sibling);

	modcall_recurse(request, stack, result, priority);

	modcall_pop(stack);
}

static modcall_action_t modcall_load_balance(UNUSED REQUEST *request, modcall_stack_t *stack,
					     rlm_rcode_t *presult, int *priority)
{
	modcall_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modgroup *g;

	uint32_t count = 0;

	g = mod_callabletogroup(c);
	if (!g->children) {
		*presult = RLM_MODULE_NOOP;
		*priority = c->actions[*presult];
		return MODCALL_CALCULATE_RESULT;
	}

	/*
	 *	No entry?  This is the first time we've been called.
	 *	Go find one.
	 */
	if (!entry->resume) {
		/*
		 *	Choose a child at random.
		 */
		for (entry->child = entry->found = g->children; entry->child != NULL; entry->child = entry->child->next) {
			count++;

			if ((count * (fr_rand() & 0xffff)) < (uint32_t) 0x10000) {
				entry->found = entry->child;
			}
		}

		if (c->type == MOD_LOAD_BALANCE) {
			modcall_push(stack, entry->found, entry->result, false);
			return MODCALL_ITERATIVE;

		}

		entry->child = entry->found; /* we start at this one */

	} else {		
		rad_assert(c->type != MOD_LOAD_BALANCE); /* this is never called again */

		/*
		 *	We were called again.  See if we're done.
		 */
		if (entry->child->actions[*presult] == MOD_ACTION_RETURN) {
			return MODCALL_CALCULATE_RESULT;
		}

		entry->child = entry->child->next;
		if (!entry->child) entry->child = g->children;

		if (entry->child == entry->found) {
			return MODCALL_CALCULATE_RESULT;
		}
	}

	/*
	 *	Push the child, and yeild for a later return.
	 */
	modcall_push(stack, entry->child, entry->result, false);
	return MODCALL_YEILD;
}

static modcall_action_t modcall_case(UNUSED REQUEST *request, modcall_stack_t *stack,
				     rlm_rcode_t *presult, UNUSED int *priority)
{
	modcall_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modgroup *g;

	g = mod_callabletogroup(c);

	if (!g->children) {
		*presult = RLM_MODULE_NOOP;
		// ?? priority
		return MODCALL_CALCULATE_RESULT;
	}

	return MODCALL_DO_CHILDREN;
}

static modcall_action_t modcall_return(REQUEST *request, modcall_stack_t *stack,
				       rlm_rcode_t *presult, int *priority)
{
	int i;
	VALUE_PAIR **copy_p;
	modcall_stack_entry_t *entry = &stack->entry[stack->depth];
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

	return MODCALL_BREAK;
}

static modcall_action_t modcall_foreach(REQUEST *request, modcall_stack_t *stack,
					rlm_rcode_t *presult, int *priority)
{
	int i, foreach_depth = -1;
	VALUE_PAIR *vps, *vp;
	modcall_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modgroup *g;

	g = mod_callabletogroup(c);

	if (stack->depth >= MODCALL_STACK_MAX) {
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
		*presult = RLM_MODULE_FAIL;
		*priority = 0;
		return MODCALL_CALCULATE_RESULT;
	}

	/*
	 *	Copy the VPs from the original request, this ensures deterministic
	 *	behaviour if someone decides to add or remove VPs in the set were
	 *	iterating over.
	 */
	if (tmpl_copy_vps(request, &vps, request, g->vpt) < 0) {	/* nothing to loop over */
		*presult = RLM_MODULE_NOOP;
		*priority = c->actions[RLM_MODULE_NOOP];
		return MODCALL_CALCULATE_RESULT;
	}

	rad_assert(vps != NULL);
	fr_cursor_init(&entry->cursor, &vps);

	RDEBUG2("foreach %s ", c->name);

	/*
	 *	This is the actual body of the foreach loop
	 */
	for (vp = fr_cursor_first(&entry->cursor);
	     vp != NULL;
	     vp = fr_cursor_next(&entry->cursor)) {
#ifndef NDEBUG
		if (fr_debug_lvl >= 2) {
			char buffer[1024];

			fr_pair_value_snprint(buffer, sizeof(buffer), vp, '"');
			RDEBUG2("# Foreach-Variable-%d = %s", foreach_depth, buffer);
		}
#endif

		/*
		 *	Add the vp to the request, so that
		 *	xlat.c, xlat_foreach() can find it.
		 */
		request_data_add(request, (void *)radius_get_vp, foreach_depth, &vp, false, false, false);

		modcall_child(request, stack, g->children, presult, priority, true);

		/*
		 *	We've been asked to unwind to the
		 *	enclosing "foreach".  We're here, so
		 *	we can stop unwinding.
		 */
		if (entry->unwind == MOD_BREAK) {
			entry->unwind = 0;
			break;
		}

		/*
		 *	Unwind all the way.
		 */
		if (entry->unwind == MOD_RETURN) {
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

	*priority = c->actions[*presult];
	return MODCALL_CALCULATE_RESULT;
}

static modcall_action_t modcall_xlat(REQUEST *request, modcall_stack_t *stack,
				     UNUSED rlm_rcode_t *presult, UNUSED int *priority)
{
	modcall_stack_entry_t *entry = &stack->entry[stack->depth];
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

	return MODCALL_NEXT_SIBLING;
}

static modcall_action_t modcall_switch(REQUEST *request, modcall_stack_t *stack,
				       UNUSED rlm_rcode_t *presult, UNUSED int *priority)
{
	modcall_stack_entry_t *entry = &stack->entry[stack->depth];
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

	modcall_push(stack, found, entry->result, false);
	return MODCALL_ITERATIVE;
}


static modcall_action_t modcall_update(REQUEST *request, modcall_stack_t *stack,
				       rlm_rcode_t *presult, UNUSED int *priority)
{
	int rcode;
	modcall_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modgroup *g = mod_callabletogroup(c);
	vp_map_t *map;

	RINDENT();
	for (map = g->map; map != NULL; map = map->next) {
		rcode = map_to_request(request, map, map_to_vp, NULL);
		if (rcode < 0) {
			*presult = (rcode == -2) ? RLM_MODULE_INVALID : RLM_MODULE_FAIL;
			REXDENT();
			return MODCALL_CALCULATE_RESULT;
		}
	}
	REXDENT();

	*presult = RLM_MODULE_NOOP;
	*priority = c->actions[RLM_MODULE_NOOP];
	return MODCALL_CALCULATE_RESULT;
}


static modcall_action_t modcall_map(REQUEST *request, modcall_stack_t *stack,
				       rlm_rcode_t *presult, UNUSED int *priority)
{
	modcall_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modgroup *g = mod_callabletogroup(c);

	RINDENT();
	*presult = map_proc(request, g->proc_inst);
	REXDENT();

	*priority = c->actions[*presult];
	return MODCALL_CALCULATE_RESULT;
}

static modcall_action_t modcall_single(REQUEST *request, modcall_stack_t *stack,
				       rlm_rcode_t *presult, UNUSED int *priority)
{
	modsingle *sp;
	modcall_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;

	/*
	 *	Process a stand-alone child, and fall through
	 *	to dealing with it's parent.
	 */
	sp = mod_callabletosingle(c);

	*presult = call_modsingle(c->method, sp, request);
	*priority = c->actions[*presult];

	RDEBUG2("%s (%s)", c->name ? c->name : "",
		fr_int2str(mod_rcode_table, *presult, "<invalid>"));
	return MODCALL_CALCULATE_RESULT;
}


static modcall_action_t modcall_if(REQUEST *request, modcall_stack_t *stack,
				   rlm_rcode_t *result, UNUSED int *priority)
{
	int condition;
	modcall_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	modgroup *g;

	g = mod_callabletogroup(c);
	rad_assert(g->cond != NULL);

	condition = radius_evaluate_cond(request, *result, 0, g->cond);
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

		*priority = c->actions[*result];
		return MODCALL_NEXT_SIBLING;
	}

	/*
	 *	We took the "if".  Go recurse into its' children.
	 */
	entry->was_if = true;
	entry->if_taken = true;
	return MODCALL_DO_CHILDREN;
}

static modcall_action_t modcall_elsif(REQUEST *request, modcall_stack_t *stack,
				   rlm_rcode_t *result, int *priority)
{
	modcall_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	rad_assert(entry->was_if);

	/*
	 *	Like MOD_ELSE, but allow for a later "else"
	 */
	if (entry->if_taken) {
		RDEBUG2("... skipping %s for request %d: Preceding \"if\" was taken",
			unlang_keyword[c->type], request->number);
		entry->if_taken = true;
		return MODCALL_NEXT_SIBLING;
	}

	/*
	 *	Check the "if" condition.
	 */
	return modcall_if(request, stack, result, priority);
}

static modcall_action_t modcall_else(REQUEST *request, modcall_stack_t *stack,
				     UNUSED rlm_rcode_t *result, UNUSED int *priority)
{
	modcall_stack_entry_t *entry = &stack->entry[stack->depth];
	modcallable *c = entry->c;
	rad_assert(entry->was_if);

	if (entry->if_taken) {
		RDEBUG2("... skipping %s for request %d: Preceding \"if\" was taken",
			unlang_keyword[c->type], request->number);
		entry->was_if = false;
		entry->if_taken = false;

		*result = RLM_MODULE_NOOP;
		*priority = c->actions[*result];
		return MODCALL_NEXT_SIBLING;
	}

	/*
	 *	We need to process it.  Go do that.
	 */
	entry->was_if = false;
	entry->if_taken = false;
	return MODCALL_DO_CHILDREN;
}

static modcall_action_t modcall_group(UNUSED REQUEST *request, UNUSED modcall_stack_t *stack,
				     UNUSED rlm_rcode_t *result, UNUSED int *priority)
{
	return MODCALL_DO_CHILDREN;
}

/*
 *	Some functions differ mainly in their parsing
 */
#define modcall_redundant_load_balance modcall_load_balance
#define modcall_policy modcall_group
#define modcall_break modcall_return

/*
 *	The jump table for the interpretor
 */
static modcall_function_t modcall_functions[MOD_NUM_TYPES] = {
	[MOD_SINGLE]			= modcall_single,
	[MOD_GROUP]			= modcall_group,
	[MOD_LOAD_BALANCE]		= modcall_load_balance,
	[MOD_REDUNDANT_LOAD_BALANCE]	= modcall_redundant_load_balance,
#ifdef WITH_UNLANG
	[MOD_IF]			= modcall_if,
	[MOD_ELSE]			= modcall_else,
	[MOD_ELSIF]			= modcall_elsif,
	[MOD_UPDATE]			= modcall_update,
	[MOD_SWITCH]			= modcall_switch,
	[MOD_CASE]			= modcall_case,
	[MOD_FOREACH]			= modcall_foreach,
	[MOD_BREAK]			= modcall_break,
	[MOD_RETURN]			= modcall_return,
	[MOD_MAP]			= modcall_map,
#endif
	[MOD_POLICY]			= modcall_policy,
	[MOD_XLAT]			= modcall_xlat,
};

static bool modcall_brace[MOD_NUM_TYPES] = {
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
static void modcall_recurse(REQUEST *request, modcall_stack_t *stack, rlm_rcode_t *presult, int *ppriority)
{
	modcallable *c;
	int priority;
	rlm_rcode_t result;
	modgroup *g;
	modcall_stack_entry_t *entry;
	modcall_action_t action = MODCALL_BREAK;

redo:
	result = RLM_MODULE_UNKNOWN;
	priority = -1;

	rad_assert(stack->depth > 0);
	rad_assert(stack->depth < MODCALL_STACK_MAX);

	entry = &stack->entry[stack->depth];

	RINDENT();

	/*
	 *	Loop over all modules in this list.
	 */
	while (entry->c != NULL) {
		c = entry->c;

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

		if (modcall_brace[c->type]) RDEBUG2("%s {", c->debug_name);

		action = modcall_functions[c->type](request, stack, &result, &priority);
		switch (action) {
		case MODCALL_DO_CHILDREN:
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
				goto next_sibling;
			}

			modcall_push(stack, g->children, entry->result, true);

		case MODCALL_ITERATIVE:
			(entry + 1)->iterative = true;
			goto redo;

		case MODCALL_YEILD:
			entry->resume = true;
			(entry + 1)->iterative = true;
			goto redo;

		do_pop:
			modcall_pop(stack);

			entry = &stack->entry[stack->depth];

			c = entry->c;
			rad_assert(c != NULL);

			/*
			 *	We need to call the function again, to
			 *	see if it's done.
			 */
			if (entry->resume) continue;

			/* FALL-THROUGH */

		case MODCALL_CALCULATE_RESULT:
			entry->resume = false;
			if (modcall_brace[c->type]) RDEBUG2("} # %s (%s)", c->debug_name,
							    fr_int2str(mod_rcode_table, result, "<invalid>"));
			action = MODCALL_CALCULATE_RESULT;

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
		 case MODCALL_BREAK:
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

		case MODCALL_NEXT_SIBLING:
			if ((action == MODCALL_NEXT_SIBLING) && modcall_brace[c->type]) RDEBUG2("}");

		next_sibling:
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

	if (entry->iterative) {
		result = entry->result;
		goto do_pop;
	}
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
int modcall(rlm_components_t component, modcallable *c, REQUEST *request)
{
	int priority;
	rlm_rcode_t result;
	modcall_stack_t stack;

	memset(&stack, 0, sizeof(stack));

	result = default_component_results[component];
	priority = 0;

	stack.component = component;
	stack.depth = 0;

	modcall_push(&stack, c, result, true);

	/*
	 *	Call the main handler.
	 */
	modcall_recurse(request, &stack, &result, &priority);

	/*
	 *	Return the result.
	 */
	return result;
}
