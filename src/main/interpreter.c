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

static void unlang_push(unlang_stack_t *stack, unlang_node_t *c, rlm_rcode_t result, bool do_next_sibling)
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
	next->unwind = UNLANG_NODE_TYPE_NULL;
	next->do_next_sibling = do_next_sibling;
	next->was_if = false;
	next->if_taken = false;
	next->resume = false;
}

static void unlang_pop(unlang_stack_t *stack)
{
	unlang_stack_entry_t *entry, *next;

	rad_assert(stack->depth > 0);

	stack->depth -= 1;

	entry = &stack->entry[stack->depth];
	next = entry + 1;

	/*
	 *	Unwind back up the stack
	 */
	if (next->unwind != 0) entry->unwind = next->unwind;
}


static unlang_action_t unlang_load_balance(REQUEST *request, unlang_stack_t *stack,
					   rlm_rcode_t *presult, int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	unlang_node_t *c = entry->c;
	unlang_node_group_t *g;

	uint32_t count = 0;

	g = unlang_node_group_to_module_call(c);
	if (!g->children) {
		*presult = RLM_MODULE_NOOP;
		*priority = c->actions[*presult];
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	No entry?  This is the first time we've been called.
	 *	Go find one.
	 */
	if (!entry->resume) {
		if (g->vpt) {
			uint32_t hash, start;
			ssize_t slen;
			char const *p = NULL;
			char buffer[1024];

			/*
			 *	Integer data types let the admin
			 *	select which entry is being used.
			 */
			if ((g->vpt->type == TMPL_TYPE_ATTR) &&
			    ((g->vpt->tmpl_da->type == PW_TYPE_BYTE) ||
			     (g->vpt->tmpl_da->type == PW_TYPE_SHORT) ||
			     (g->vpt->tmpl_da->type == PW_TYPE_INTEGER) ||
			     (g->vpt->tmpl_da->type == PW_TYPE_INTEGER64))) {
				VALUE_PAIR *vp;

				slen = tmpl_find_vp(&vp, request, g->vpt);
				if (slen < 0) {
					REDEBUG("Failed finding attribute %s", g->vpt->name);
					goto randomly_choose;
				}

				switch (g->vpt->tmpl_da->type) {
				case PW_TYPE_BYTE:
					start = ((uint32_t) vp->vp_byte) % g->num_children;
					break;

				case PW_TYPE_SHORT:
					start = ((uint32_t) vp->vp_short) % g->num_children;
					break;

				case PW_TYPE_INTEGER:
					start = vp->vp_integer % g->num_children;
					break;

				case PW_TYPE_INTEGER64:
					start = (uint32_t) (vp->vp_integer64 % ((uint64_t) g->num_children));
					break;

				default:
					goto randomly_choose;
				}

			} else {
				slen = tmpl_expand(&p, buffer, sizeof(buffer), request, g->vpt, NULL, NULL);
				if (slen < 0) {
					REDEBUG("Failed expanding template");
					goto randomly_choose;
				}

				hash = fr_hash(p, slen);

				start = hash % g->num_children;;
			}

			RDEBUG3("load-balance starting at child %d", (int) start);

			count = 0;
			for (entry->redundant.child = entry->redundant.found = g->children;
			     entry->redundant.child != NULL;
			     entry->redundant.child = entry->redundant.child->next) {
				count++;
				if (count == start) {
					entry->redundant.found = entry->redundant.child;
					break;
				}
			}

		} else {
		randomly_choose:
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
		}

		if (c->type == UNLANG_NODE_TYPE_LOAD_BALANCE) {
			unlang_push(stack, entry->redundant.found, entry->result, false);
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		/*
		 *	redundant-load-balance starts at this one.
		 */
		entry->redundant.child = entry->redundant.found;

	} else {
		rad_assert(c->type != UNLANG_NODE_TYPE_LOAD_BALANCE); /* this is never called again */

		/*
		 *	We were called again.  See if we're done.
		 */
		if (entry->redundant.child->actions[*presult] == MOD_ACTION_RETURN) {
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		entry->redundant.child = entry->redundant.child->next;
		if (!entry->redundant.child) entry->redundant.child = g->children;

		if (entry->redundant.child == entry->redundant.found) {
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

	/*
	 *	Push the child, and yield for a later return.
	 */
	unlang_push(stack, entry->redundant.child, entry->result, false);
	entry->resume = true;
	return UNLANG_ACTION_PUSHED_CHILD;
}


static unlang_action_t unlang_group(REQUEST *request, unlang_stack_t *stack,
				    UNUSED rlm_rcode_t *result, UNUSED int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	unlang_node_t *c = entry->c;
	unlang_node_group_t *g;

	g = unlang_node_group_to_module_call(c);

	/*
	 *	This should really have been caught in the
	 *	compiler, and the node never generated.  But
	 *	doing that requires changing it's API so that
	 *	it returns a flag instead of the compiled
	 *	UNLANG_NODE_TYPE_GROUP.
	 */
	if (!g->children) {
		RDEBUG2("} # %s ... <ignoring empty subsection>", c->debug_name);
		return UNLANG_ACTION_CONTINUE;
	}

	unlang_push(stack, g->children, entry->result, true);
	return UNLANG_ACTION_PUSHED_CHILD;
}

typedef struct unlang_parallel_t {
	rlm_rcode_t	rcode;
	int		priority;

	unlang_stack_t	*stacks;
} unlang_parallel_t;

static unlang_action_t unlang_parallel(UNUSED REQUEST *request, unlang_stack_t *stack,
				       UNUSED rlm_rcode_t *result, UNUSED int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	unlang_node_t *c = entry->c;
	unlang_node_group_t *g;

	g = unlang_node_group_to_module_call(c);

	if (!entry->resume) {
		/*
		 *	Set up some stacks and a return code.
		 */
	} else {
		/*
		 *	Find a resumption child and run it.
		 */
	}


	unlang_push(stack, g->children, entry->result, true);
	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_case(REQUEST *request, unlang_stack_t *stack,
				     rlm_rcode_t *presult, int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	unlang_node_t *c = entry->c;
	unlang_node_group_t *g;

	g = unlang_node_group_to_module_call(c);

	if (!g->children) {
		*presult = RLM_MODULE_NOOP;
		// ?? priority
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	return unlang_group(request, stack, presult, priority);
}

static unlang_action_t unlang_return(REQUEST *request, unlang_stack_t *stack,
				       rlm_rcode_t *presult, int *priority)
{
	int i;
	VALUE_PAIR **copy_p;
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	unlang_node_t *c = entry->c;

	RDEBUG2("%s", unlang_ops[c->type].name);

	for (i = 8; i >= 0; i--) {
		copy_p = request_data_get(request, (void *)radius_get_vp, i);
		if (copy_p) {
			if (c->type == UNLANG_NODE_TYPE_BREAK) {
				RDEBUG2("# break Foreach-Variable-%d", i);
				break;
			}
		}
	}

	entry->unwind = c->type;

	*presult = entry->result;
	*priority = entry->priority;

	return UNLANG_ACTION_BREAK;
}

static unlang_action_t unlang_foreach(REQUEST *request, unlang_stack_t *stack,
					rlm_rcode_t *presult, int *priority)
{
	VALUE_PAIR *vp;
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	unlang_node_t *c = entry->c;
	unlang_node_group_t *g;

	g = unlang_node_group_to_module_call(c);

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
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		/*
		 *	Copy the VPs from the original request, this ensures deterministic
		 *	behaviour if someone decides to add or remove VPs in the set were
		 *	iterating over.
		 */
		if (tmpl_copy_vps(request, &vps, request, g->vpt) < 0) {	/* nothing to loop over */
			*presult = RLM_MODULE_NOOP;
			*priority = c->actions[RLM_MODULE_NOOP];
			return UNLANG_ACTION_CALCULATE_RESULT;
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
		if (entry->unwind == UNLANG_NODE_TYPE_BREAK) {
			entry->unwind = UNLANG_NODE_TYPE_NULL;
			vp = NULL;
		}

		/*
		 *	Unwind all the way.
		 */
		if (entry->unwind == UNLANG_NODE_TYPE_RETURN) {
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
			return UNLANG_ACTION_CALCULATE_RESULT;
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
	 *	Push the child, and yield for a later return.
	 */
	unlang_push(stack, g->children, entry->result, true);
	entry->resume = true;
	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_xlat(REQUEST *request, unlang_stack_t *stack,
				     UNUSED rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	unlang_node_t *c = entry->c;
	unlang_node_xlat_t *mx = unlang_node_to_xlat(c);
	char buffer[128];

	if (!mx->exec) {
		radius_xlat(buffer, sizeof(buffer), request, mx->xlat_name, NULL, NULL);
	} else {
		RDEBUG("`%s`", mx->xlat_name);
		radius_exec_program(request, NULL, 0, NULL, request, mx->xlat_name, request->packet->vps,
				    false, true, EXEC_TIMEOUT);
	}

	return UNLANG_ACTION_CONTINUE;
}

static unlang_action_t unlang_switch(REQUEST *request, unlang_stack_t *stack,
				       UNUSED rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	unlang_node_t *c = entry->c;
	unlang_node_t *this, *found, *null_case;
	unlang_node_group_t *g, *h;
	fr_cond_t cond;
	value_data_t data;
	vp_map_t map;
	vp_tmpl_t vpt;

	g = unlang_node_group_to_module_call(c);

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
			rad_assert(this->type == UNLANG_NODE_TYPE_CASE);

			h = unlang_node_group_to_module_call(this);
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
		rad_assert(this->type == UNLANG_NODE_TYPE_CASE);

		h = unlang_node_group_to_module_call(this);

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
	return UNLANG_ACTION_PUSHED_CHILD;
}


static unlang_action_t unlang_update(REQUEST *request, unlang_stack_t *stack,
				       rlm_rcode_t *presult, int *priority)
{
	int rcode;
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	unlang_node_t *c = entry->c;
	unlang_node_group_t *g = unlang_node_group_to_module_call(c);
	vp_map_t *map;

	RINDENT();
	for (map = g->map; map != NULL; map = map->next) {
		rcode = map_to_request(request, map, map_to_vp, NULL);
		if (rcode < 0) {
			*presult = (rcode == -2) ? RLM_MODULE_INVALID : RLM_MODULE_FAIL;
			REXDENT();
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}
	REXDENT();

	*presult = RLM_MODULE_NOOP;
	*priority = c->actions[RLM_MODULE_NOOP];
	return UNLANG_ACTION_CALCULATE_RESULT;
}


static unlang_action_t unlang_map(REQUEST *request, unlang_stack_t *stack,
				  rlm_rcode_t *presult, int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	unlang_node_t *c = entry->c;
	unlang_node_group_t *g = unlang_node_group_to_module_call(c);

	RINDENT();
	*presult = map_proc(request, g->proc_inst);
	REXDENT();

	*priority = c->actions[*presult];
	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_single(REQUEST *request, unlang_stack_t *stack,
				     rlm_rcode_t *presult, int *priority)
{
#if 0
	int depth = stack->depth;
#endif
	unlang_node_module_call_t *sp;
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	unlang_node_t *c = entry->c;

	/*
	 *	Process a stand-alone child, and fall through
	 *	to dealing with it's parent.
	 */
	sp = unlang_node_to_module_call(c);

	/*
	 *	If the request should stop, refuse to do anything.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) return UNLANG_ACTION_STOP_PROCESSING;

	RDEBUG3("Calling %s (%s) for request %" PRIu64,
		sp->modinst->name, sp->modinst->module->name, request->number);

	if (sp->modinst->force) {
		request->rcode = sp->modinst->code;
		goto fail;
	}

	/*
	 *	For logging unresponsive children.
	 */
	request->module = sp->modinst->name;

	safe_lock(sp->modinst);
	request->rcode = sp->method(sp->modinst->data, request);
	safe_unlock(sp->modinst);

	request->module = NULL;

	/*
	 *	Is now marked as "stop" when it wasn't before, we must have been blocked.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) {
		RWARN("Module %s became unblocked for request %" PRIu64 "", sp->modinst->module->name, request->number);
		return UNLANG_ACTION_STOP_PROCESSING;
	}

#if 0
	/*
	 *	Child was pushed by the module.
	 */
	if (depth < stack->depth) {
		rad_assert(entry->resume == true);
		rad_assert((entry + 1)->c->type == UNLANG_NODE_TYPE_MODULE_CALL);
		return UNLANG_ACTION_PUSHED_CHILD;
	}
#endif

fail:
	RDEBUG3("Returned from %s (%s) for request %" PRIu64,
		sp->modinst->name, sp->modinst->module->name, request->number);

	*presult = request->rcode;
	*priority = c->actions[*presult];

	RDEBUG2("%s (%s)", c->name ? c->name : "",
		fr_int2str(mod_rcode_table, *presult, "<invalid>"));
	return UNLANG_ACTION_CALCULATE_RESULT;
}


static unlang_action_t unlang_if(REQUEST *request, unlang_stack_t *stack,
				   rlm_rcode_t *presult, int *priority)
{
	int condition;
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	unlang_node_t *c = entry->c;
	unlang_node_group_t *g;

	g = unlang_node_group_to_module_call(c);
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
		return UNLANG_ACTION_CONTINUE;
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
	unlang_node_t *c = entry->c;
	rad_assert(entry->was_if);

	/*
	 *	Like UNLANG_NODE_TYPE_ELSE, but allow for a later "else"
	 */
	if (entry->if_taken) {
		RDEBUG2("... skipping %s for request %" PRIu64 ": Preceding \"if\" was taken",
			unlang_ops[c->type].name, request->number);
		entry->if_taken = true;
		return UNLANG_ACTION_CONTINUE;
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
	unlang_node_t *c = entry->c;
	rad_assert(entry->was_if);

	if (entry->if_taken) {
		RDEBUG2("... skipping %s for request %" PRIu64 ": Preceding \"if\" was taken",
			unlang_ops[c->type].name, request->number);
		entry->was_if = false;
		entry->if_taken = false;

		*presult = RLM_MODULE_NOOP;
		*priority = c->actions[*presult];
		return UNLANG_ACTION_CONTINUE;
	}

	/*
	 *	We need to process it.  Go do that.
	 */
	entry->was_if = false;
	entry->if_taken = false;

	return unlang_group(request, stack, presult, priority);
}

static unlang_action_t unlang_resume(REQUEST *request, unlang_stack_t *stack,
				     rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_entry_t *entry = &stack->entry[stack->depth];
	unlang_node_t *c = entry->c;
	unlang_node_resumption_t *mr = unlang_node_to_resumption(c);
	unlang_node_module_call_t *sp;

	sp = &mr->module;

	RDEBUG3("Resuming %s (%s) for request %" PRIu64,
		sp->modinst->name,
		sp->modinst->module->name, request->number);

	safe_lock(sp->modinst);
	*presult = mr->callback(request, mr->module.modinst->data, mr->ctx);
	safe_unlock(sp->modinst);

	RDEBUG2("%s (%s)", c->name ? c->name : "",
		fr_int2str(mod_rcode_table, *presult, "<invalid>"));

	/*
	 *	Leave mr alone, it will be freed when the request is done.
	 */

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/*
 *	Some functions differ mainly in their parsing
 */
#define unlang_redundant_load_balance unlang_load_balance
#define unlang_policy unlang_group
#define unlang_break unlang_return

unlang_op_t unlang_ops[] = {
	[UNLANG_NODE_TYPE_MODULE_CALL] = {
		.name = "single",
		.func = unlang_single,
		.children = false
	},
	[UNLANG_NODE_TYPE_GROUP] = {
		.name = "group",
		.func = unlang_group,
		.children = true
	},
	[UNLANG_NODE_TYPE_LOAD_BALANCE] = {
		.name = "load-balance group",
		.func = unlang_load_balance,
		.children = true
	},
	[UNLANG_NODE_TYPE_REDUNDANT_LOAD_BALANCE] = {
		.name = "redundant-load-balance group",
		.func = unlang_redundant_load_balance,
		.children = true
	},
	[UNLANG_NODE_TYPE_PARALLEL] = {
		.name = "parallel",
		.func = unlang_parallel,
		.children = true
	},
#ifdef WITH_UNLANG
	[UNLANG_NODE_TYPE_IF] = {
		.name = "if",
		.func = unlang_if,
		.children = true
	},
	[UNLANG_NODE_TYPE_ELSE] = {
		.name = "else",
		.func = unlang_else,
		.children = true
	},
	[UNLANG_NODE_TYPE_ELSIF] = {
		.name = "elsif",
		.func = unlang_elsif,
		.children = true
	},
	[UNLANG_NODE_TYPE_UPDATE] = {
		.name = "update",
		.func = unlang_update,
		.children = true
	},
	[UNLANG_NODE_TYPE_SWITCH] = {
		.name = "switch",
		.func = unlang_switch,
		.children = true
	},
	[UNLANG_NODE_TYPE_CASE] = {
		.name = "case",
		.func = unlang_case,
		.children = true
	},
	[UNLANG_NODE_TYPE_FOREACH] = {
		.name = "foreach",
		.func = unlang_foreach,
		.children = true
	},
	[UNLANG_NODE_TYPE_BREAK] = {
		.name = "break",
		.func = unlang_break,
		.children = false
	},
	[UNLANG_NODE_TYPE_RETURN] = {
		.name = "return",
		.func = unlang_return,
		.children = false
	},
	[UNLANG_NODE_TYPE_MAP] = {
		.name = "map",
		.func = unlang_map,
		.children = true
	},
	[UNLANG_NODE_TYPE_POLICY] = {
		.name = "policy",
		.func = unlang_policy,
		.children = true
	},
#endif
	[UNLANG_NODE_TYPE_XLAT] = {
		.name = "xlat",
		.func = unlang_xlat,
		.children = false
	},
	[UNLANG_NODE_TYPE_RESUME] = {
		.name = "resume",
		.func = unlang_resume,
		.children = false
	},
	[UNLANG_NODE_TYPE_MAX] = { NULL, NULL, false }
};

/*
 *	Interpret the various types of blocks.
 */
static rlm_rcode_t unlang_run(REQUEST *request, unlang_stack_t *stack)
{
	unlang_node_t *c;
	int priority;
	rlm_rcode_t result;
	unlang_stack_entry_t *entry;
	unlang_action_t action = UNLANG_ACTION_BREAK;

	stack->entry[stack->depth].top_frame = true;

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

		rad_assert(c->debug_name != NULL); /* if this happens, all bets are off. */

		/*
		 *	We've been asked to stop.  Do so.
		 */
		if ((request->master_state == REQUEST_STOP_PROCESSING) ||
		    (request->parent &&
		     (request->parent->master_state == REQUEST_STOP_PROCESSING))) {
		do_stop:
			entry->result = RLM_MODULE_FAIL;
			entry->priority = 9999;
			entry->unwind = UNLANG_NODE_TYPE_RETURN;
			break;
		}

		if (unlang_ops[c->type].children) RDEBUG2("%s {", c->debug_name);

		action = unlang_ops[c->type].func(request, stack, &result, &priority);
		switch (action) {
		case UNLANG_ACTION_STOP_PROCESSING:
			goto do_stop;

		case UNLANG_ACTION_PUSHED_CHILD:
			goto redo;

		case UNLANG_ACTION_BREAK:
			entry->result = result;
			goto done;

		do_pop:
			unlang_pop(stack);

			/*
			 *	Done the top stack frame, return
			 */
			entry = &stack->entry[stack->depth];
			c = entry->c;
			rad_assert(c != NULL);

			if (entry->top_frame) {
				if (unlang_ops[c->type].children) {
					RDEBUG2("} # %s (%s)", c->debug_name,
						fr_int2str(mod_rcode_table, result, "<invalid>"));
				}
				return result;
			}

			/*
			 *	We need to call the function again, to
			 *	see if it's done.
			 */
			if (entry->resume) continue;

			/* FALL-THROUGH */

		case UNLANG_ACTION_CALCULATE_RESULT:
			if (result == RLM_MODULE_YIELD) {
				rad_assert(entry->c->type == UNLANG_NODE_TYPE_RESUME);
				rad_assert(entry->resume == false);
				return RLM_MODULE_YIELD;
			}

			entry->resume = false;
			if (unlang_ops[c->type].children) {
				RDEBUG2("} # %s (%s)", c->debug_name,
					fr_int2str(mod_rcode_table, result, "<invalid>"));
			}
			action = UNLANG_ACTION_CALCULATE_RESULT;

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
				RDEBUG2("Setting section code (%s)",
					fr_int2str(mod_rcode_table, result, "<invalid>"));
				entry->result = result;
				entry->priority = priority;
			}

			/*
			 *	If we've been told to stop processing
			 *	it, do so.
			 */
			if (entry->unwind != 0) goto done;

			/* FALL-THROUGH */

		case UNLANG_ACTION_CONTINUE:
			if ((action == UNLANG_ACTION_CONTINUE) && unlang_ops[c->type].children) RDEBUG2("}");

			if (!entry->do_next_sibling) goto done;

		} /* switch over return code from the interpretor function */

		entry->c = entry->c->next;
	}

	/*
	 *	And we're done!
	 */
done:
	REXDENT();

	result = entry->result;
	goto do_pop;
}


/** Push a configuration section onto the request stack for later interpretation.
 *
 */
void unlang_push_section(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t action)
{
	unlang_node_t *c = NULL;

	if (cs) c = cf_data_find(cs, "unlang");

	unlang_push(request->stack, c, action, true);
}

/** Continue interpreting after a previous push or yield.
 *
 */
rlm_rcode_t unlang_interpret_continue(REQUEST *request)
{
	return unlang_run(request, request->stack);
}


/** Call a module, iteratively, with a local stack, rather than recursively
 *
 * What did Paul Graham say about Lisp...?
 */
rlm_rcode_t unlang_interpret(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t action)
{
	unlang_push_section(request, cs, action);


	/*
	 *	Call the main handler.
	 */
	return unlang_run(request, request->stack);
}

/*
 *	Event handlers for unlang.
 */
typedef struct unlang_event_t {
	REQUEST		*request;
	int		fd;
	fr_unlang_timeout_callback_t	timeout_callback;
	fr_unlang_fd_callback_t		fd_callback;
	void		*inst;
	void		*ctx;
	fr_event_t	*ev;
} unlang_event_t;


static int _unlang_event_free(unlang_event_t *ev)
{
	if (ev->ev) {
		(void) fr_event_delete(ev->request->el, &ev->ev);
		return 0;
	}

	if (ev->fd >= 0) {
		(void) fr_event_fd_delete(ev->request->el, 0, ev->fd);
	}

	return 0;
}

static void unlang_event_timeout_handler(void *ctx, struct timeval *now)
{
	unlang_event_t *ev = ctx;

	ev->timeout_callback(ev->request, ev->inst, ev->ctx, now);
	talloc_free(ev);
}

static void unlang_event_fd_handler(UNUSED fr_event_list_t *el, int fd, void *ctx)
{
	unlang_event_t *ev = ctx;

	rad_assert(ev->fd == fd);

	ev->fd_callback(ev->request, ev->inst, ev->ctx, fd);
}

/** Add a timeout
 *
 */
int unlang_event_timeout_add(REQUEST *request, fr_unlang_timeout_callback_t callback,
			     void *inst, void *ctx, struct timeval *when)
{
	unlang_event_t *ev;

	ev = talloc_zero(request, unlang_event_t);
	if (!ev) return -1;

	ev->request = request;
	ev->fd = -1;
	ev->timeout_callback = callback;
	ev->inst = inst;
	ev->ctx = ctx;

	if (fr_event_insert(request->el, unlang_event_timeout_handler, ev, when, &ev->ev) < 0) {
		talloc_free(ev);
		return -1;
	}

	(void) request_data_add(request, ctx, -1, ev, true, false, false);

	talloc_set_destructor(ev, _unlang_event_free);
	return 0;
}

int unlang_event_fd_add(REQUEST *request, fr_unlang_fd_callback_t callback,
			void *inst, void *ctx, int fd)
{
	unlang_event_t *ev;

	ev = talloc_zero(request, unlang_event_t);
	if (!ev) return -1;

	ev->request = request;
	ev->fd = fd;
	ev->fd_callback = callback;
	ev->inst = inst;
	ev->ctx = ctx;

	if (fr_event_fd_insert(request->el, 0, fd, unlang_event_fd_handler, ev) < 0) {
		talloc_free(ev);
		return -1;
	}

	(void) request_data_add(request, ctx, fd, ev, true, false, false);

	talloc_set_destructor(ev, _unlang_event_free);
	return 0;
}

int unlang_event_timeout_delete(REQUEST *request, void *ctx)
{
	unlang_event_t *ev;

	ev = request_data_get(request, ctx, -1);
	if (!ev) return -1;

	talloc_free(ev);
	return 0;
}

int unlang_event_fd_delete(REQUEST *request, void *ctx, int fd)
{
	unlang_event_t *ev;

	ev = request_data_get(request, ctx, fd);
	if (!ev) return -1;

	talloc_free(ev);
	return 0;
}

/** Mark a request as resumption.
 *
 *  It's not called "unlang_resume", because it doesn't actually
 *  resume the request, it just schedules it for resumption.
 */
void unlang_resume(REQUEST *request)
{
	fr_heap_insert(request->backlog, request);
}

rlm_rcode_t unlang_yield(REQUEST *request, fr_unlang_resume_t callback, void *ctx)
{
	unlang_stack_entry_t *entry;
	unlang_stack_t *stack = request->stack;
	unlang_node_resumption_t *mr;

	rad_assert(stack->depth > 0);

	entry = &stack->entry[stack->depth];

	rad_assert(entry->c->type == UNLANG_NODE_TYPE_MODULE_CALL);

	mr = talloc(request, unlang_node_resumption_t);
	rad_assert(mr != NULL);

	memcpy(&mr->module, entry->c, sizeof(mr->module));

	mr->module.node.type = UNLANG_NODE_TYPE_RESUME;
	mr->callback = callback;
	mr->ctx = ctx;

	entry->c = unlang_node_resumption_to_node(mr);

	return RLM_MODULE_YIELD;
}

static void unlang_timer_hook(void *ctx, UNUSED struct timeval *now)
{
	REQUEST *request = talloc_get_type_abort(ctx, REQUEST);
#ifdef DEBUG_STATE_MACHINE
	fr_state_action_t action = FR_ACTION_TIMER;
#endif

	TRACE_STATE_MACHINE;

	request->process(request, FR_ACTION_TIMER);
}


int unlang_delay(REQUEST *request, struct timeval *delay, fr_request_process_t process)
{
	struct timeval when;

	timeradd(&request->reply->timestamp, delay, &when);

	RDEBUG2("Waiting for %d.%06d seconds",
		(int) delay->tv_sec, (int) delay->tv_usec);

	if (fr_event_insert(request->el, unlang_timer_hook, request, &when, &request->ev) < 0) {
		RDEBUG("Failed inserting event");
		return -1;
	}

	request->process = process;
	return 0;
}
