/*
 * @name unlang.c
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

static FR_NAME_NUMBER unlang_action_table[] = {
	{ "calculate-result",	UNLANG_ACTION_CALCULATE_RESULT },
	{ "continue",		UNLANG_ACTION_CONTINUE },
	{ "pushed-child",	UNLANG_ACTION_PUSHED_CHILD },
	{ "break", 		UNLANG_ACTION_BREAK },
	{ "stop",		UNLANG_ACTION_STOP_PROCESSING },
	{ NULL, -1 }
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

static void unlang_push(unlang_stack_t *stack, unlang_t *program, rlm_rcode_t result, bool do_next_sibling)
{
	unlang_stack_frame_t *next;

	rad_assert(program);

	if (stack->depth >= UNLANG_STACK_MAX) {
		ERROR("Internal sanity check failed: module stack is too deep");
		fr_exit(1);
	}

	stack->depth++;

	/*
	 *	Initialize the next stack frame.
	 */
	next = &stack->frame[stack->depth];
	next->instruction = program;
	next->result = result;
	next->priority = 0;
	next->unwind = UNLANG_TYPE_NULL;
	next->do_next_sibling = do_next_sibling;
	next->was_if = false;
	next->if_taken = false;
	next->resume = false;
}

static void unlang_pop(unlang_stack_t *stack)
{
	unlang_stack_frame_t *frame, *next;

	rad_assert(stack->depth > 1);

	stack->depth -= 1;

	frame = &stack->frame[stack->depth];
	next = frame + 1;

	/*
	 *	Unwind back up the stack
	 */
	if (next->unwind != 0) frame->unwind = next->unwind;
}


static unlang_action_t unlang_load_balance(REQUEST *request, unlang_stack_t *stack,
					   rlm_rcode_t *presult, int *priority)
{
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t	*g;

	uint32_t count = 0;

	g = unlang_group_to_module_call(instruction);
	if (!g->children) {
		*presult = RLM_MODULE_NOOP;
		*priority = instruction->actions[*presult];
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	No frame?  This is the first time we've been called.
	 *	Go find one.
	 */
	if (!frame->resume) {
		if (g->vpt) {
			uint32_t hash, start;
			ssize_t slen;
			char const *p = NULL;
			char buffer[1024];

			/*
			 *	Integer data types let the admin
			 *	select which frame is being used.
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
			for (frame->redundant.child = frame->redundant.found = g->children;
			     frame->redundant.child != NULL;
			     frame->redundant.child = frame->redundant.child->next) {
				count++;
				if (count == start) {
					frame->redundant.found = frame->redundant.child;
					break;
				}
			}

		} else {
		randomly_choose:
			/*
			 *	Choose a child at random.
			 */
			for (frame->redundant.child = frame->redundant.found = g->children;
			     frame->redundant.child != NULL;
			     frame->redundant.child = frame->redundant.child->next) {
				count++;

				if ((count * (fr_rand() & 0xffff)) < (uint32_t) 0x10000) {
					frame->redundant.found = frame->redundant.child;
				}
			}
		}

		if (instruction->type == UNLANG_TYPE_LOAD_BALANCE) {
			unlang_push(stack, frame->redundant.found, frame->result, false);
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		/*
		 *	redundant-load-balance starts at this one.
		 */
		frame->redundant.child = frame->redundant.found;

	} else {
		rad_assert(instruction->type != UNLANG_TYPE_LOAD_BALANCE); /* this is never called again */

		/*
		 *	We were called again.  See if we're done.
		 */
		if (frame->redundant.child->actions[*presult] == MOD_ACTION_RETURN) {
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		frame->redundant.child = frame->redundant.child->next;
		if (!frame->redundant.child) frame->redundant.child = g->children;

		if (frame->redundant.child == frame->redundant.found) {
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

	/*
	 *	Push the child, and yield for a later return.
	 */
	unlang_push(stack, frame->redundant.child, frame->result, false);
	frame->resume = true;
	return UNLANG_ACTION_PUSHED_CHILD;
}


static unlang_action_t unlang_group(REQUEST *request, unlang_stack_t *stack,
				    UNUSED rlm_rcode_t *result, UNUSED int *priority)
{
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t	*g;

	g = unlang_group_to_module_call(instruction);

	/*
	 *	This should really have been caught in the
	 *	compiler, and the program never generated.  But
	 *	doing that requires changing it's API so that
	 *	it returns a flag instead of the compiled
	 *	UNLANG_TYPE_GROUP.
	 */
	if (!g->children) {
		RDEBUG2("} # %s ... <ignoring empty subsection>", instruction->debug_name);
		return UNLANG_ACTION_CONTINUE;
	}

	unlang_push(stack, g->children, frame->result, true);
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
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t	*g;

	g = unlang_group_to_module_call(instruction);

	if (!frame->resume) {
		/*
		 *	Set up some stacks and a return code.
		 */
	} else {
		/*
		 *	Find a resumption child and run it.
		 */
	}

	unlang_push(stack, g->children, frame->result, true);
	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_case(REQUEST *request, unlang_stack_t *stack,
				     rlm_rcode_t *presult, int *priority)
{
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t	*g;

	g = unlang_group_to_module_call(instruction);

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
	int			i;
	VALUE_PAIR		**copy_p;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;

	RDEBUG2("%s", unlang_ops[instruction->type].name);

	for (i = 8; i >= 0; i--) {
		copy_p = request_data_get(request, (void *)radius_get_vp, i);
		if (copy_p) {
			if (instruction->type == UNLANG_TYPE_BREAK) {
				RDEBUG2("# break Foreach-Variable-%d", i);
				break;
			}
		}
	}

	frame->unwind = instruction->type;

	*presult = frame->result;
	*priority = frame->priority;

	return UNLANG_ACTION_BREAK;
}

static unlang_action_t unlang_foreach(REQUEST *request, unlang_stack_t *stack,
					rlm_rcode_t *presult, int *priority)
{
	VALUE_PAIR		*vp;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t	*g;

	g = unlang_group_to_module_call(instruction);

	if (!frame->resume) {
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
			*priority = instruction->actions[RLM_MODULE_NOOP];
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		RDEBUG2("foreach %s ", instruction->name);

		rad_assert(vps != NULL);
		fr_cursor_init(&frame->foreach.cursor, &vps);

		frame->foreach.depth = foreach_depth;
		frame->foreach.vps = vps;

		vp = fr_cursor_first(&frame->foreach.cursor);

	} else {
		vp = fr_cursor_next(&frame->foreach.cursor);

		/*
		 *	We've been asked to unwind to the
		 *	enclosing "foreach".  We're here, so
		 *	we can stop unwinding.
		 */
		if (frame->unwind == UNLANG_TYPE_BREAK) {
			frame->unwind = UNLANG_TYPE_NULL;
			vp = NULL;
		}

		/*
		 *	Unwind all the way.
		 */
		if (frame->unwind == UNLANG_TYPE_RETURN) {
			vp = NULL;
		}

		if (!vp) {
			/*
			 *	Free the copied vps and the request data
			 *	If we don't remove the request data, something could call
			 *	the xlat outside of a foreach loop and trigger a segv.
			 */
			fr_pair_list_free(&frame->foreach.vps);
			request_data_get(request, (void *)radius_get_vp, frame->foreach.depth);

			*presult = frame->result;
			*priority = instruction->actions[*presult];
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

#ifndef NDEBUG
	if (fr_debug_lvl >= 2) {
		char buffer[1024];

			fr_pair_value_snprint(buffer, sizeof(buffer), vp, '"');
			RDEBUG2("# Foreach-Variable-%d = %s", frame->foreach.depth, buffer);
		}
#endif

	/*
	 *	Add the vp to the request, so that
	 *	xlat.c, xlat_foreach() can find it.
	 */
	frame->foreach.variable = vp;
	request_data_add(request, (void *)radius_get_vp, frame->foreach.depth, &frame->foreach.variable,
			 false, false, false);

	/*
	 *	Push the child, and yield for a later return.
	 */
	unlang_push(stack, g->children, frame->result, true);
	frame->resume = true;
	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_xlat_inline(REQUEST *request, unlang_stack_t *stack,
					  UNUSED rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_xlat_inline_t	*mx = unlang_generic_to_xlat_inline(instruction);
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
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_t		*this, *found, *null_case;
	unlang_group_t	*g, *h;
	fr_cond_t		cond;
	value_box_t		data;
	vp_map_t		map;
	vp_tmpl_t		vpt;

	g = unlang_group_to_module_call(instruction);

	memset(&cond, 0, sizeof(cond));
	memset(&map, 0, sizeof(map));

	cond.type = COND_TYPE_MAP;
	cond.data.map = &map;

	map.op = T_OP_CMP_EQ;
	map.ci = cf_section_to_item(g->cs);

	rad_assert(g->vpt != NULL);

	null_case = found = NULL;
	data.datum.ptr = NULL;

	/*
	 *	The attribute doesn't exist.  We can skip
	 *	directly to the default 'case' statement.
	 */
	if ((g->vpt->type == TMPL_TYPE_ATTR) && (tmpl_find_vp(NULL, request, g->vpt) < 0)) {
	find_null_case:
		for (this = g->children; this; this = this->next) {
			rad_assert(this->type == UNLANG_TYPE_CASE);

			h = unlang_group_to_module_call(this);
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
		data.datum.strvalue = p;
		tmpl_init(&vpt, TMPL_TYPE_UNPARSED, data.datum.strvalue, len, T_SINGLE_QUOTED_STRING);
	}

	/*
	 *	Find either the exact matching name, or the
	 *	"case {...}" statement.
	 */
	for (this = g->children; this; this = this->next) {
		rad_assert(this->type == UNLANG_TYPE_CASE);

		h = unlang_group_to_module_call(this);

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

		if (cond_eval_map(request, RLM_MODULE_UNKNOWN, 0,
					&cond) == 1) {
			found = this;
			break;
		}
	}

	if (!found) found = null_case;

do_null_case:
	talloc_free(data.datum.ptr);

	unlang_push(stack, found, frame->result, false);
	return UNLANG_ACTION_PUSHED_CHILD;
}


static unlang_action_t unlang_update(REQUEST *request, unlang_stack_t *stack,
				       rlm_rcode_t *presult, int *priority)
{
	int rcode;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t	*g = unlang_group_to_module_call(instruction);
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
	*priority = instruction->actions[RLM_MODULE_NOOP];
	return UNLANG_ACTION_CALCULATE_RESULT;
}


static unlang_action_t unlang_map(REQUEST *request, unlang_stack_t *stack,
				  rlm_rcode_t *presult, int *priority)
{
	unlang_stack_frame_t *frame = &stack->frame[stack->depth];
	unlang_t *instruction = frame->instruction;
	unlang_group_t *g = unlang_group_to_module_call(instruction);

	RINDENT();
	*presult = map_proc(request, g->proc_inst);
	REXDENT();

	*priority = instruction->actions[*presult];
	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_module_call(REQUEST *request, unlang_stack_t *stack,
				     	  rlm_rcode_t *presult, int *priority)
{
#if 0
	int depth = stack->depth;
#endif
	unlang_module_call_t		*sp;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	module_thread_instance_t	*thread_inst;

	/*
	 *	Process a stand-alone child, and fall through
	 *	to dealing with it's parent.
	 */
	sp = unlang_generic_to_module_call(instruction);

	/*
	 *	If the request should stop, refuse to do anything.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) return UNLANG_ACTION_STOP_PROCESSING;

	RDEBUG4("[%i] %s - %s (%s)", stack->depth, __FUNCTION__, sp->module_instance->name, sp->module_instance->module->name);

	if (sp->module_instance->force) {
		request->rcode = sp->module_instance->code;
		goto fail;
	}

	/*
	 *	Grab the thread/module specific data if any exists.
	 */
	thread_inst = module_thread_instance_find(sp->module_instance);

	/*
	 *	For logging unresponsive children.
	 */
	request->module = sp->module_instance->name;

	safe_lock(sp->module_instance);
	request->rcode = sp->method(sp->module_instance->data, thread_inst, request);
	safe_unlock(sp->module_instance);

	request->module = NULL;

	/*
	 *	Is now marked as "stop" when it wasn't before, we must have been blocked.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) {
		RWARN("Module %s became unblocked for request %" PRIu64 "", sp->module_instance->module->name, request->number);
		return UNLANG_ACTION_STOP_PROCESSING;
	}

#if 0
	/*
	 *	Child was pushed by the module.
	 */
	if (depth < stack->depth) {
		rad_assert(frame->resume == true);
		rad_assert((frame + 1)->instruction->type == UNLANG_TYPE_MODULE_CALL);
		return UNLANG_ACTION_PUSHED_CHILD;
	}
#endif

fail:
	*presult = request->rcode;
	if (*presult != RLM_MODULE_YIELD) *priority = instruction->actions[*presult];

	RDEBUG2("%s (%s)", instruction->name ? instruction->name : "",
		fr_int2str(mod_rcode_table, *presult, "<invalid>"));
	return UNLANG_ACTION_CALCULATE_RESULT;
}


static unlang_action_t unlang_if(REQUEST *request, unlang_stack_t *stack,
				   rlm_rcode_t *presult, int *priority)
{
	int condition;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t	*g;

	g = unlang_group_to_module_call(instruction);
	rad_assert(g->cond != NULL);

	condition = cond_eval(request, *presult, 0, g->cond);
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
		frame->was_if = true;
		frame->if_taken = false;

		*priority = instruction->actions[*presult];

		return UNLANG_ACTION_CONTINUE;
	}

	/*
	 *	We took the "if".  Go recurse into its' children.
	 */
	frame->was_if = true;
	frame->if_taken = true;

	return unlang_group(request, stack, presult, priority);
}

static unlang_action_t unlang_elsif(REQUEST *request, unlang_stack_t *stack,
				    rlm_rcode_t *presult, int *priority)
{
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	rad_assert(frame->was_if);

	/*
	 *	Like UNLANG_TYPE_ELSE, but allow for a later "else"
	 */
	if (frame->if_taken) {
		RDEBUG2("... skipping %s for request %" PRIu64 ": Preceding \"if\" was taken",
			unlang_ops[instruction->type].name, request->number);
		frame->if_taken = true;
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
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	rad_assert(frame->was_if);

	if (frame->if_taken) {
		RDEBUG2("... skipping %s for request %" PRIu64 ": Preceding \"if\" was taken",
			unlang_ops[instruction->type].name, request->number);
		frame->was_if = false;
		frame->if_taken = false;

		*presult = RLM_MODULE_NOOP;
		*priority = instruction->actions[*presult];
		return UNLANG_ACTION_CONTINUE;
	}

	/*
	 *	We need to process it.  Go do that.
	 */
	frame->was_if = false;
	frame->if_taken = false;

	return unlang_group(request, stack, presult, priority);
}

static unlang_action_t unlang_resumption(REQUEST *request, unlang_stack_t *stack,
				    	 rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_resumption_t	*mr = unlang_generic_to_resumption(instruction);
	unlang_module_call_t	*sp;
	void 			*mutable;

	sp = &mr->module;

	RDEBUG3("Resuming %s (%s) for request %" PRIu64,
		sp->module_instance->name,
		sp->module_instance->module->name, request->number);

	memcpy(&mutable, &mr->ctx, sizeof(mutable));

	safe_lock(sp->module_instance);
	*presult = mr->callback(request, mr->module.module_instance->data, mutable);
	safe_unlock(sp->module_instance);

	RDEBUG2("%s (%s)", instruction->name ? instruction->name : "",
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
	[UNLANG_TYPE_MODULE_CALL] = {
		.name = "module-call",
		.func = unlang_module_call,
		.children = false
	},
	[UNLANG_TYPE_GROUP] = {
		.name = "group",
		.func = unlang_group,
		.children = true
	},
	[UNLANG_TYPE_LOAD_BALANCE] = {
		.name = "load-balance group",
		.func = unlang_load_balance,
		.children = true
	},
	[UNLANG_TYPE_REDUNDANT_LOAD_BALANCE] = {
		.name = "redundant-load-balance group",
		.func = unlang_redundant_load_balance,
		.children = true
	},
	[UNLANG_TYPE_PARALLEL] = {
		.name = "parallel",
		.func = unlang_parallel,
		.children = true
	},
#ifdef WITH_UNLANG
	[UNLANG_TYPE_IF] = {
		.name = "if",
		.func = unlang_if,
		.children = true
	},
	[UNLANG_TYPE_ELSE] = {
		.name = "else",
		.func = unlang_else,
		.children = true
	},
	[UNLANG_TYPE_ELSIF] = {
		.name = "elsif",
		.func = unlang_elsif,
		.children = true
	},
	[UNLANG_TYPE_UPDATE] = {
		.name = "update",
		.func = unlang_update,
		.children = true
	},
	[UNLANG_TYPE_SWITCH] = {
		.name = "switch",
		.func = unlang_switch,
		.children = true
	},
	[UNLANG_TYPE_CASE] = {
		.name = "case",
		.func = unlang_case,
		.children = true
	},
	[UNLANG_TYPE_FOREACH] = {
		.name = "foreach",
		.func = unlang_foreach,
		.children = true
	},
	[UNLANG_TYPE_BREAK] = {
		.name = "break",
		.func = unlang_break,
		.children = false
	},
	[UNLANG_TYPE_RETURN] = {
		.name = "return",
		.func = unlang_return,
		.children = false
	},
	[UNLANG_TYPE_MAP] = {
		.name = "map",
		.func = unlang_map,
		.children = true
	},
	[UNLANG_TYPE_POLICY] = {
		.name = "policy",
		.func = unlang_policy,
		.children = true
	},
#endif
	[UNLANG_TYPE_XLAT_INLINE] = {
		.name = "xlat_inline",
		.func = unlang_xlat_inline,
		.children = false
	},
	[UNLANG_TYPE_RESUME] = {
		.name = "resume",
		.func = unlang_resumption,
		.children = false
	},
	[UNLANG_TYPE_MAX] = { NULL, NULL, false }
};

/*
 *	Interpret the various types of blocks.
 */
static rlm_rcode_t unlang_run(REQUEST *request, unlang_stack_t *stack)
{
	unlang_t		*instruction;
	int			priority;
	rlm_rcode_t		result;
	unlang_stack_frame_t	*frame;
	unlang_action_t		action = UNLANG_ACTION_BREAK;

	frame = &stack->frame[stack->depth];

	/*
	 *	Our entry point *MUST* be a frame where we previously
	 *	yielded, or a new substack.
	 */
	if (!rad_cond_assert(frame->top_frame || frame->resume)) return RLM_MODULE_FAIL;

	RDEBUG4("** [%i] %s - entered", stack->depth, __FUNCTION__);

redo:
	priority = -1;

	rad_assert(stack->depth > 0);
	rad_assert(stack->depth < UNLANG_STACK_MAX);

	frame = &stack->frame[stack->depth];
	result = frame->result;

	/*
	 *	Loop over all modules in this list.
	 */
	while (frame->instruction != NULL) {
		instruction = frame->instruction;

		rad_assert(instruction->debug_name != NULL); /* if this happens, all bets are off. */

		if (fr_debug_lvl >= 3) {
			VERIFY_REQUEST(request);
		}

		/*
		 *	We've been asked to stop.  Do so.
		 */
		if ((request->master_state == REQUEST_STOP_PROCESSING) ||
		    (request->parent &&
		     (request->parent->master_state == REQUEST_STOP_PROCESSING))) {
		do_stop:
			frame->result = RLM_MODULE_FAIL;
			frame->priority = 9999;
			frame->unwind = UNLANG_TYPE_RETURN;
			break;
		}

		if (unlang_ops[instruction->type].children) {
			RDEBUG2("%s {", instruction->debug_name);
			RINDENT();
		}

		/*
		 *	Execute an operation
		 */
		RDEBUG4("** [%i] %s >> %s", stack->depth, __FUNCTION__,
			unlang_ops[instruction->type].name);

		action = unlang_ops[instruction->type].func(request, stack, &result, &priority);

		RDEBUG4("** [%i] %s << %s (%d)", stack->depth, __FUNCTION__,
			fr_int2str(unlang_action_table, action, "<INVALID>"), priority);

		rad_assert(priority >= -1);
		rad_assert(priority <= MOD_PRIORITY_MAX);

		switch (action) {
		case UNLANG_ACTION_STOP_PROCESSING:
			goto do_stop;

		case UNLANG_ACTION_PUSHED_CHILD:
			rad_assert(&stack->frame[stack->depth] > frame);
			goto redo;

		case UNLANG_ACTION_BREAK:
			frame->result = result;
			goto done;

		do_pop:
			unlang_pop(stack);

			/*
			 *	Reset the local variables, and check
			 *	for a (local) top frame.
			 */
			frame = &stack->frame[stack->depth];
			instruction = frame->instruction;
			if (!instruction) {
				RERROR("Empty instruction.  Hard-coding to reject.");
				frame->result = result = RLM_MODULE_REJECT;
				goto done;
			}

			if (frame->top_frame) {
				if (unlang_ops[instruction->type].children) {
					REXDENT();
					RDEBUG2("} # %s (%s)", instruction->debug_name,
						fr_int2str(mod_rcode_table, result, "<invalid>"));
				}
				RDEBUG4("** [%i] %s - exited (done)", stack->depth, __FUNCTION__);
				return result;
			}

			/*
			 *	We need to call the function again, to
			 *	see if it's done.
			 */
			if (frame->resume) continue;

			/* FALL-THROUGH */

		case UNLANG_ACTION_CALCULATE_RESULT:
			if (result == RLM_MODULE_YIELD) {
				rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);
				frame->resume = true;
				RDEBUG4("** [%i] %s - exited (yield)", stack->depth, __FUNCTION__);
				return RLM_MODULE_YIELD;
			}

			frame->resume = false;
			if (unlang_ops[instruction->type].children) {
				REXDENT();
				RDEBUG2("} # %s (%s)", instruction->debug_name,
					fr_int2str(mod_rcode_table, result, "<invalid>"));
			}
			action = UNLANG_ACTION_CALCULATE_RESULT;

			RDEBUG4("** [%i] %s - rcode %s (%d) vs rcode' %s (%d)",
				stack->depth, __FUNCTION__,
			        fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
			        frame->priority,
			        fr_int2str(mod_rcode_table, result, "<invalid>"),
			        priority);

			rad_assert(result != RLM_MODULE_UNKNOWN);

			/*
			 *	The child's action says return.  Do so.
			 */
			if (instruction->actions[result] == MOD_ACTION_RETURN) {
				frame->result = result;
				goto done;
			}

			/*
			 *	If "reject", break out of the loop and return
			 *	reject.
			 */
			if (instruction->actions[result] == MOD_ACTION_REJECT) {
				frame->result = RLM_MODULE_REJECT;
				goto done;
			}

			/*
			 *	The array holds a default priority for this return
			 *	code.  Grab it in preference to any unset priority.
			 */
			if (priority < 0) {
				priority = instruction->actions[result];
			}

			/*
			 *	We're higher than any previous priority, remember this
			 *	return code and priority.
			 */
			if (priority > frame->priority) {
				frame->priority = priority;
				frame->result = result;
			}

			/*
			 *	If we've been told to stop processing
			 *	it, do so.
			 */
			if (frame->unwind != 0) goto done;

			/* FALL-THROUGH */

		case UNLANG_ACTION_CONTINUE:
			if ((action == UNLANG_ACTION_CONTINUE) && unlang_ops[instruction->type].children) {
				REXDENT();
				RDEBUG2("}");
			}

			if (!frame->do_next_sibling) goto done;
		} /* switch over return code from the interpreter function */

		frame->instruction = frame->instruction->next;
	}

	/*
	 *	And we're done!
	 */
done:
	result = frame->result;


	if (stack->depth == 1) {
		RDEBUG4("** [%i] %s - exited (done)", stack->depth, __FUNCTION__);
		return result;
	}

	goto do_pop;
}

static unlang_group_t empty_group = {
	.self = {
		.type = UNLANG_TYPE_GROUP,
		.debug_name = "empty-group",
		.actions = { MOD_ACTION_RETURN, MOD_ACTION_RETURN, MOD_ACTION_RETURN, MOD_ACTION_RETURN,
			     MOD_ACTION_RETURN, MOD_ACTION_RETURN, MOD_ACTION_RETURN, MOD_ACTION_RETURN,
			     MOD_ACTION_RETURN
		},
	},
	.group_type = UNLANG_GROUP_TYPE_SIMPLE,
};

/** Push a configuration section onto the request stack for later interpretation.
 *
 */
void unlang_push_section(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t action)
{
	unlang_t *instruction = NULL;
	unlang_stack_t *stack = request->stack;

	/*
	 *	Interpretable unlang instructions are stored as CONF_DATA
	 *	associated with sections.
	 */
	if (cs) {
		instruction = cf_data_find(cs, CF_DATA_TYPE_UNLANG, "unlang");
		if (!instruction) {
			REDEBUG("Failed to find pre-compiled unlang for section %s %s { ... }",
				cf_section_name1(cs), cf_section_name2(cs));
		}
	}

	if (!instruction) instruction = unlang_group_to_generic(&empty_group);

	unlang_push(stack, instruction, action, true);

	RDEBUG4("** [%i] %s - substack begins", stack->depth, __FUNCTION__);

	/*
	 *	Mark our entry point into the stack.  This ensures
	 *	We don't ever rewind past our first frame.
	 *
	 *	This allows multiple calls to unlang_run, dividing the
	 *	stack into segments.
	 */
	stack->frame[stack->depth].top_frame = true;
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
	rlm_rcode_t	rcode;
	unlang_stack_t	*stack = request->stack;

	/*
	 *	This pushes a new frame onto the stack, which is the
	 *	start of a new unlang section...
	 */
	unlang_push_section(request, cs, action);

	rcode = unlang_run(request, stack);
	if (rcode != RLM_MODULE_YIELD) {
		rad_assert(stack->frame[stack->depth].top_frame);
		rad_assert(!stack->frame[stack->depth].instruction || /* processed the whole section */
			    stack->frame[stack->depth].instruction->type == UNLANG_TYPE_GROUP); /* sections are groups */
		rad_assert(stack->depth > 0);
		/*
		 *	...and must now be popped if we're not yielding.
		 */
		stack->depth--;
	}

	return rcode;
}

/** Wrap an #fr_event_timer_t providing data needed for unlang events
 *
 */
typedef struct unlang_event_t {
	REQUEST				*request;			//!< Request this event pertains to.
	int				fd;				//!< File descriptor to wait on.
	fr_unlang_timeout_callback_t	timeout_callback;		//!< Function to call on timeout.
	fr_unlang_fd_callback_t		fd_callback;			//!< Function to call when FD is readable.
	void const			*inst;				//!< Module instance to pass to callbacks.
	void const			*ctx;				//!< ctx data to pass to callbacks.
	fr_event_timer_t		*ev;				//!< Event in this worker's event heap.
} unlang_event_t;

static int _unlang_event_free(unlang_event_t *ev)
{
	if (ev->ev) {
		(void) fr_event_timer_delete(ev->request->el, &(ev->ev));
		return 0;
	}

	if (ev->fd >= 0) {
		(void) fr_event_fd_delete(ev->request->el, ev->fd);
	}

	return 0;
}

/** Call the callback registered for a timeout event
 *
 * @param[in] now	The current time, as held by the event_list.
 * @param[in] ctx	unlang_event_t structure holding callbacks.
 *
 */
static void unlang_event_timeout_handler(struct timeval *now, void *ctx)
{
#ifndef NDEBUG
	unlang_event_t *ev = talloc_get_type_abort(ctx, unlang_event_t);
#else
	unlang_event_t *ev = ctx;
#endif
	void *mutable_ctx;
	void *mutable_inst;

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->timeout_callback(ev->request, mutable_inst, mutable_ctx, now);
	talloc_free(ev);
}

/** Call the callback registered for an I/O event
 *
 * @param[in] el	containing the event (not passed to the callback).
 * @param[in] fd	the I/O event occurred on.
 * @param[in] ctx	unlang_event_t structure holding callbacks.
 */
static void unlang_event_fd_handler(UNUSED fr_event_list_t *el, int fd, void *ctx)
{
#ifndef NDEBUG
	unlang_event_t *ev = talloc_get_type_abort(ctx, unlang_event_t);
#else
	unlang_event_t *ev = ctx;
#endif
	void *mutable_ctx;
	void *mutable_inst;

	rad_assert(ev->fd == fd);

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->fd_callback(ev->request, mutable_inst, mutable_ctx, fd);
}

/** Set a timeout for the request.
 *
 * Used when a module needs wait for an event.  Typically the callback is set, and then the
 * module returns unlang_yield().
 *
 * @note The callback is automatically removed on unlang_resumable().
 *
 * param[in] request		the current request.
 * param[in] callback		to call.
 * param[in] inst		The module instance
 * param[in] ctx		for the callback.
 * param[in] timeout		when to call the timeout (i.e. now + timeout).
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_event_timeout_add(REQUEST *request, fr_unlang_timeout_callback_t callback,
			     void const *inst, void const *ctx, struct timeval *when)
{
	unlang_event_t *ev;

	ev = talloc_zero(request, unlang_event_t);
	if (!ev) return -1;

	ev->request = request;
	ev->fd = -1;
	ev->timeout_callback = callback;
	ev->inst = inst;
	ev->ctx = ctx;

	if (fr_event_timer_insert(request->el, unlang_event_timeout_handler, ev, when, &(ev->ev)) < 0) {
		REDEBUG("Failed inserting event: %s", fr_strerror());
		talloc_free(ev);
		return -1;
	}

	(void) request_data_add(request, ctx, -1, ev, true, false, false);

	talloc_set_destructor(ev, _unlang_event_free);

	return 0;
}

/** Set a callback for the request.
 *
 * Used when a module needs to read from an FD.  Typically the callback is set, and then the
 * module returns unlang_yield().
 *
 * @note The callback is automatically removed on unlang_resumable().
 *
 * @param[in] request		The current request.
 * @param[in] callback		to call.
 * @param[in] inst		The module instance
 * @param[in] ctx		for the callback.
 * @param[in] fd		to watch.  When it becomes readable the request is marked as resumable,
 *				with the callback being called by the worker responsible for processing
 *				the request.
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_event_fd_readable_add(REQUEST *request, fr_unlang_fd_callback_t callback,
				 void const *inst, void const *ctx, int fd)
{
	unlang_event_t *ev;

	ev = talloc_zero(request, unlang_event_t);
	if (!ev) return -1;

	ev->request = request;
	ev->fd = fd;
	ev->fd_callback = callback;
	ev->inst = inst;
	ev->ctx = ctx;

	if (!fr_event_fd_insert(request->el, fd, unlang_event_fd_handler, NULL, NULL, ev)) {
		talloc_free(ev);
		return -1;
	}

	(void) request_data_add(request, ctx, fd, ev, true, false, false);

	talloc_set_destructor(ev, _unlang_event_free);
	return 0;
}

/** Delete a previously set timeout callback.
 *
 * param[in] request the request
 * param[in] ctx a local context for the callback
 */
int unlang_event_timeout_delete(REQUEST *request, void const *ctx)
{
	unlang_event_t *ev;

	ev = request_data_get(request, ctx, -1);
	if (!ev) return -1;

	talloc_free(ev);
	return 0;
}

/** Delete a previously set file descriptor callback.
 *
 * param[in] request the request
 * param[in] fd the file descriptor
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_event_fd_delete(REQUEST *request, void const *ctx, int fd)
{
	unlang_event_t *ev;

	ev = request_data_get(request, ctx, fd);
	if (!ev) return -1;

	talloc_free(ev);
	return 0;
}

/** Mark a request as resumable.
 *
 * It's not called "unlang_resume", because it doesn't actually
 * resume the request, it just schedules it for resumption.
 *
 * @note that this schedules the request for resumption.  It does not
 * immediately start running the request.
 *
 * @param[in] request		The current request.
 */
void unlang_resumable(REQUEST *request)
{
	fr_heap_insert(request->backlog, request);
}

/** Signal a request which an action.
 *
 * This is typically called via an "async" action, i.e. an action
 * outside of the normal processing of the request.
 *
 * If there is no #fr_unlang_action_t callback defined, the action is ignored.
 *
 * @param[in] request		The current request.
 * @param[in] action		to signal.
 */
void unlang_action(REQUEST *request, fr_state_action_t action)
{
	unlang_stack_frame_t	*frame;
	unlang_stack_t		*stack = request->stack;
	unlang_resumption_t	*mr;
	void			*mutable;

	rad_assert(stack->depth > 0);

	frame = &stack->frame[stack->depth];

	rad_assert(frame->instruction->type == UNLANG_TYPE_RESUME);

	mr = unlang_generic_to_resumption(frame->instruction);
	if (!mr->action_callback) return;

	memcpy(&mutable, &mr->ctx, sizeof(mutable));

	mr->action_callback(request, mr->module.module_instance->data, mutable, action);
}

/** Yeild a request
 *
 * @param[in] request		The current request.
 * @param[in] callback		to call on unlang_resumable().
 * @param[in] action_callback	to call on unlang_action().
 * @param[in] ctx		to pass to the callbacks.
 * @return always returns RLM_MODULE_YIELD.
 */
rlm_rcode_t unlang_yield(REQUEST *request, fr_unlang_resume_t callback,
			 fr_unlang_action_t action_callback, void const *ctx)
{
	unlang_stack_frame_t	*frame;
	unlang_stack_t		*stack = request->stack;
	unlang_resumption_t	*mr;

	rad_assert(stack->depth > 0);

	frame = &stack->frame[stack->depth];

	rad_assert(frame->instruction->type == UNLANG_TYPE_MODULE_CALL);

	mr = talloc(request, unlang_resumption_t);
	rad_assert(mr != NULL);

	memcpy(&mr->module, frame->instruction, sizeof(mr->module));

	mr->module.self.type = UNLANG_TYPE_RESUME;
	mr->callback = callback;
	mr->action_callback = action_callback;
	mr->ctx = ctx;

	frame->instruction = unlang_resumption_to_generic(mr);

	return RLM_MODULE_YIELD;
}

static void unlang_timer_hook(UNUSED struct timeval *now, void *ctx)
{
	REQUEST *request = talloc_get_type_abort(ctx, REQUEST);
#ifdef DEBUG_STATE_MACHINE
	fr_state_action_t action = FR_ACTION_TIMER;
#endif

	TRACE_STATE_MACHINE;

	request->process(request, FR_ACTION_TIMER);
}

/** Delay processing of a request for a time
 *
 * @param[in] request		The current request.
 * @param[in] delay 		processing by.
 * @param[in] process		The function to call when the delay expires.
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_delay(REQUEST *request, struct timeval *delay, fr_request_process_t process)
{
	struct timeval when;

	fr_timeval_add(&when, &request->reply->timestamp, delay);

	RDEBUG2("Waiting for %d.%06d seconds",
		(int) delay->tv_sec, (int) delay->tv_usec);

	if (fr_event_timer_insert(request->el, unlang_timer_hook, request, &when, &request->ev) < 0) {
		RDEBUG("Failed inserting delay event: %s", fr_strerror());
		return -1;
	}

	request->process = process;
	return 0;
}
