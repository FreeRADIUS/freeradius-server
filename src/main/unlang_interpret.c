/*
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
 */

/**
 * $Id$
 *
 * @file unlang_interpret.c
 * @brief Execute compiled unlang structures using an iterative interpreter.
 *
 * @copyright 2006-2016 The FreeRADIUS server project
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

#define UNLANG_NEXT_STOP (false)
#define UNLANG_NEXT_CONTINUE (true)

#define UNLANG_TOP_FRAME (true)
#define UNLANG_SUB_FRAME (false)

/*
 *	Lock the mutex for the module
 */
static inline void safe_lock(module_instance_t *instance)
{
	if (instance->mutex) pthread_mutex_lock(instance->mutex);
}

/*
 *	Unlock the mutex for the module
 */
static inline void safe_unlock(module_instance_t *instance)
{
	if (instance->mutex) pthread_mutex_unlock(instance->mutex);
}

#ifndef NDEBUG
unlang_op_t unlang_ops[];

static void unlang_dump_instruction(REQUEST *request, unlang_t *instruction)
{
	RINDENT();
	if (!instruction) {
		RDEBUG("instruction = NULL");
		REXDENT();
		return;
	}
	RDEBUG("type           %s", unlang_ops[instruction->type].name);
	RDEBUG("name           %s", instruction->name);
	RDEBUG("debug_name     %s", instruction->debug_name);
	REXDENT();
}

static void unlang_dump_frame(REQUEST *request, unlang_stack_frame_t *frame)
{
	unlang_dump_instruction(request, frame->instruction);

	RINDENT();
	if (frame->next) {
		RDEBUG("next           %s", frame->next->debug_name);
	} else {
		RDEBUG("next           <none>");
	}
	RDEBUG("top_frame      %s", frame->top_frame ? "yes" : "no");
	RDEBUG("result         %s", fr_int2str(mod_rcode_table, frame->result, "<invalid>"));
	RDEBUG("priority       %d", frame->priority);
	RDEBUG("unwind         %d", frame->unwind);
	RDEBUG("resume         %s", frame->resume ? "yes" : "no");
	REXDENT();
}


static void unlang_dump_stack(REQUEST *request, unlang_stack_t *stack)
{
	int i;

	RDEBUG("----- Begin stack debug [depth %i] -----", stack->depth);
	for (i = stack->depth; i >= 0; i--) {
		unlang_stack_frame_t *frame = &stack->frame[i];

		RDEBUG("[%d] Frame contents", i);
		unlang_dump_frame(request, frame);
	}

	RDEBUG("----- End stack debug [depth %i] -------", stack->depth);
}
#define DUMP_STACK if (DEBUG_ENABLED5) unlang_dump_stack(request, stack)
#else
#define DUMP_STACK
#endif



static inline void unlang_push(unlang_stack_t *stack, unlang_t *program, rlm_rcode_t result, bool do_next_sibling, bool top_frame)
{
	unlang_stack_frame_t *frame;

	rad_assert(program || top_frame);

#ifndef NDEBUG
	if (DEBUG_ENABLED5) DEBUG("unlang_push called with instruction %s - args %s %s",
				  program ? program->debug_name : "<none>",
				  do_next_sibling ? "UNLANG_NEXT_CONTINUE" : "UNLANG_NEXT_STOP",
				  top_frame ? "UNLANG_TOP_FRAME" : "UNLANG_SUB_FRAME");
#endif

	if (stack->depth >= (UNLANG_STACK_MAX - 1)) {
		ERROR("Internal sanity check failed: module stack is too deep");
		fr_exit(1);
	}

	stack->depth++;

	/*
	 *	Initialize the next stack frame.
	 */
	frame = &stack->frame[stack->depth];

	if (do_next_sibling) {
		rad_assert(program != NULL);
		frame->next = program->next;
	} else {
		frame->next = NULL;
	}

	frame->top_frame = top_frame;
	frame->instruction = program;
	frame->result = result;
	frame->priority = -1;
	frame->unwind = UNLANG_TYPE_NULL;
	frame->resume = false;
	frame->state = NULL;
}

static inline void unlang_pop(unlang_stack_t *stack)
{
	unlang_stack_frame_t *frame, *next;

	rad_assert(stack->depth > 1);

	frame = &stack->frame[stack->depth];
	if (frame->state) talloc_free(frame->state);

	frame = &stack->frame[--stack->depth];
	next = frame + 1;

	/*
	 *	Unwind back up the stack
	 */
	if (next->unwind != 0) frame->unwind = next->unwind;
}


/*
 *	Recursively collect active callers.  Slow, but correct.
 */
static uint64_t unlang_active_callers(unlang_t *instruction)
{
	uint64_t active_callers;
	unlang_t *child;
	unlang_group_t *g;

	switch (instruction->type) {
	default:
		return 0;

	case UNLANG_TYPE_MODULE_CALL:
	{
		module_thread_instance_t *thread;
		unlang_module_call_t *sp;

		sp = unlang_generic_to_module_call(instruction);
		rad_assert(sp != NULL);

		thread = module_thread_instance_find(sp->module_instance);
		rad_assert(thread != NULL);

		return thread->active_callers;
	}

	case UNLANG_TYPE_GROUP:
	case UNLANG_TYPE_LOAD_BALANCE:
	case UNLANG_TYPE_REDUNDANT_LOAD_BALANCE:
	case UNLANG_TYPE_IF:
	case UNLANG_TYPE_ELSE:
	case UNLANG_TYPE_ELSIF:
	case UNLANG_TYPE_FOREACH:
	case UNLANG_TYPE_SWITCH:
	case UNLANG_TYPE_CASE:
		g = unlang_generic_to_group(instruction);

		active_callers = 0;
		for (child = g->children;
		     child != NULL;
		     child = child->next) {
			active_callers += unlang_active_callers(child);
		}
		break;
	}

	return active_callers;
}

static unlang_action_t unlang_load_balance(REQUEST *request, unlang_stack_t *stack,
					   rlm_rcode_t *presult, int *priority)
{
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g;

	uint32_t count = 0;

	g = unlang_generic_to_group(instruction);
	if (!g->children) {
		*presult = RLM_MODULE_NOOP;
		*priority = instruction->actions[RLM_MODULE_NOOP];
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	No frame?  This is the first time we've been called.
	 *	Go find one.
	 */
	if (!frame->resume) {
		RDEBUG4("%s setting up", frame->instruction->debug_name);

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
			    ((g->vpt->tmpl_da->type == FR_TYPE_UINT8) ||
			     (g->vpt->tmpl_da->type == FR_TYPE_UINT16) ||
			     (g->vpt->tmpl_da->type == FR_TYPE_UINT32) ||
			     (g->vpt->tmpl_da->type == FR_TYPE_UINT64))) {
				VALUE_PAIR *vp;

				slen = tmpl_find_vp(&vp, request, g->vpt);
				if (slen < 0) {
					REDEBUG("Failed finding attribute %s", g->vpt->name);
					goto randomly_choose;
				}

				switch (g->vpt->tmpl_da->type) {
				case FR_TYPE_UINT8:
					start = ((uint32_t) vp->vp_uint8) % g->num_children;
					break;

				case FR_TYPE_UINT16:
					start = ((uint32_t) vp->vp_uint16) % g->num_children;
					break;

				case FR_TYPE_UINT32:
					start = vp->vp_uint32 % g->num_children;
					break;

				case FR_TYPE_UINT64:
					start = (uint32_t) (vp->vp_uint64 % ((uint64_t) g->num_children));
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
			int num;
			uint64_t lowest_active_callers;

		randomly_choose:
			lowest_active_callers = ~(uint64_t ) 0;

			/*
			 *	Choose a child at random.
			 */
			for (frame->redundant.child = frame->redundant.found = g->children, num = 0;
			     frame->redundant.child != NULL;
			     frame->redundant.child = frame->redundant.child->next, num++) {
				uint64_t active_callers;
				unlang_t *child = frame->redundant.child;

				if (child->type != UNLANG_TYPE_MODULE_CALL) {
					active_callers = unlang_active_callers(child);
					RDEBUG3("load-balance child %d sub-section has %" PRIu64 " active", num, active_callers);

				} else {
					module_thread_instance_t *thread;
					unlang_module_call_t *sp;

					sp = unlang_generic_to_module_call(child);
					rad_assert(sp != NULL);

					thread = module_thread_instance_find(sp->module_instance);
					rad_assert(thread != NULL);

					active_callers = thread->active_callers;
					RDEBUG3("load-balance child %d sub-module has %" PRIu64 " active", num, active_callers);
				}


				/*
				 *	Reset the found, and the count
				 *	of children with this level of
				 *	activity.
				 */
				if (active_callers < lowest_active_callers) {
					RDEBUG3("load-balance choosing child %d as active %" PRIu64 " < %" PRIu64 "",
						num, active_callers, lowest_active_callers);

					count = 1;
					lowest_active_callers = active_callers;
					frame->redundant.found = frame->redundant.child;
					continue;
				}

				/*
				 *	Skip callers who are busier
				 *	than the one we found.
				 */
				if (active_callers > lowest_active_callers) {
					RDEBUG3("load-balance skipping child %d, as active %" PRIu64 " > %" PRIu64 "",
						num, active_callers, lowest_active_callers);
					continue;
				}

				count++;
				RDEBUG3("load-balance found %d children with %" PRIu64 " active", count, active_callers);

				if ((count * (fr_rand() & 0xffff)) < (uint32_t) 0x10000) {
					RDEBUG3("load-balance choosing random child %d", num);
					frame->redundant.found = frame->redundant.child;
				}
			}
		}

		if (instruction->type == UNLANG_TYPE_LOAD_BALANCE) {
			unlang_push(stack, frame->redundant.found, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);
			return UNLANG_ACTION_PUSHED_CHILD;
		}

		/*
		 *	redundant-load-balance starts at this one.
		 */
		frame->redundant.child = frame->redundant.found;

	} else {
		RDEBUG4("%s resuming", frame->instruction->debug_name);

		/*
		 *	We are in a resumed frame.  The module we
		 *	chose failed, so we have to go through the
		 *	process again.
		 */

		rad_assert(instruction->type != UNLANG_TYPE_LOAD_BALANCE); /* this is never called again */

		/*
		 *	We were called again.  See if we're done.
		 */
		if (frame->redundant.child->actions[*presult] == MOD_ACTION_RETURN) {
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		/*
		 *	@todo - track the one we chose, and if it
		 *	fails, do the load-balancing again, except
		 *	this time skipping the failed module.  AND,
		 *	keep track of multiple failed modules.
		 *	Probably in the unlang_resume_t, via a
		 *	uint64_t and bit mask for simplicity.
		 */

		frame->redundant.child = frame->redundant.child->next;
		if (!frame->redundant.child) frame->redundant.child = g->children;

		if (frame->redundant.child == frame->redundant.found) {
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

	/*
	 *	Push the child, and yield for a later return.
	 */
	unlang_push(stack, frame->redundant.child, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);
	frame->resume = true;

	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_group(REQUEST *request, unlang_stack_t *stack,
				    UNUSED rlm_rcode_t *result, UNUSED int *priority)
{
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g;

	g = unlang_generic_to_group(instruction);

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

	unlang_push(stack, g->children, frame->result, UNLANG_NEXT_CONTINUE, UNLANG_SUB_FRAME);
	return UNLANG_ACTION_PUSHED_CHILD;
}

static rlm_rcode_t unlang_run(REQUEST *request, unlang_stack_t *stack);

static unlang_action_t unlang_fork(REQUEST *request, unlang_stack_t *stack,
				   rlm_rcode_t *result, UNUSED int *priority)
{
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g;
	REQUEST			*child;
	rlm_rcode_t		rcode;
	unlang_stack_t		*child_stack;

	g = unlang_generic_to_group(instruction);

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

	child = request_alloc_fake(request);
	if (!child) {
		*result = RLM_MODULE_FAIL;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	child->packet->code = request->packet->code;

	if (g->vpt) {
		ssize_t slen;
		char const *p = NULL;
		fr_dict_attr_t const *da;
		fr_dict_enum_t const *dval;
		char buffer[256];

		slen = tmpl_expand(&p, buffer, sizeof(buffer), request, g->vpt, NULL, NULL);
		if (slen < 0) {
			REDEBUG("Failed expanding template");
			*result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		da = fr_dict_attr_by_name(NULL, "Packet-Type");
		if (!da) {
			REDEBUG("Failed finding Packet-Type attribute");
			*result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		dval = fr_dict_enum_by_alias(NULL, da, p);
		if (!dval) {
			RDEBUG("Failed to find Packet-Type %s", buffer);
			*result = RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		child->packet->code = dval->value->vb_uint32;
	}

	/*
	 *	Push the children, and set it's top frame to be true.
	 */
	child_stack = child->stack;
	child->log.unlang_indent = request->log.unlang_indent;
	unlang_push(child_stack, g->children, frame->result, UNLANG_NEXT_CONTINUE, UNLANG_SUB_FRAME);
	child_stack->frame[child_stack->depth].top_frame = true;

	/*
	 *	Run the child in the same section as the master.  If
	 *	we want to run a different virtual server, we have to
	 *	create a "server" keyword.
	 *
	 *	The only difficult there is setting child->async
	 *	to... some magic value. :( That code should be in a
	 *	virtual server callback, and not directly in the
	 *	interpreter.
	 */
	rcode = unlang_run(child, child->stack);
	if (rcode != RLM_MODULE_YIELD) {
		talloc_free(child);
		*result = rcode;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	@todo - actually do yeild, probably by hacking up unlang_module_resumption_t ???
	 */
	RDEBUG("fork - child returned %s", fr_int2str(mod_rcode_table, rcode, "<invalid>"));
	WARN("Yeild in fork {...} is not implemented.  Forcing failure");
	*result = RLM_MODULE_FAIL;
	return UNLANG_ACTION_CALCULATE_RESULT;
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

	g = unlang_generic_to_group(instruction);

	if (!frame->resume) {
		/*
		 *	Set up some stacks and a return code.
		 */
	} else {
		/*
		 *	Find a resumption child and run it.
		 */
	}

	/*
	 *	@todo fork child requests and make them top frames
	 */
	unlang_push(stack, g->children, frame->result, UNLANG_NEXT_CONTINUE, UNLANG_SUB_FRAME);

	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_case(REQUEST *request, unlang_stack_t *stack,
				   rlm_rcode_t *presult, int *priority)
{
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t	*g;

	g = unlang_generic_to_group(instruction);

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

	g = unlang_generic_to_group(instruction);

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

		rad_assert(vps != NULL);
		fr_pair_cursor_init(&frame->foreach.cursor, &vps);

		frame->foreach.depth = foreach_depth;
		frame->foreach.vps = vps;
#ifndef NDEBUG
		frame->foreach.indent = request->log.unlang_indent;
#endif

		vp = fr_pair_cursor_first(&frame->foreach.cursor);

	} else {
		vp = fr_pair_cursor_next(&frame->foreach.cursor);

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
			if (*presult != RLM_MODULE_UNKNOWN) *priority = instruction->actions[*presult];
#ifndef NDEBUG
			rad_assert(frame->foreach.indent == request->log.unlang_indent);
#endif
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

#ifndef NDEBUG
	if (DEBUG_ENABLED2) {
		char buffer[1024];

			fr_pair_value_snprint(buffer, sizeof(buffer), vp, '"');
			RDEBUG2("");
			RDEBUG2("# looping with: Foreach-Variable-%d = %s", frame->foreach.depth, buffer);
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
	unlang_push(stack, g->children, frame->result, UNLANG_NEXT_CONTINUE, UNLANG_SUB_FRAME);
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
		(void) xlat_eval(buffer, sizeof(buffer), request, mx->xlat_name, NULL, NULL);
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
	unlang_group_t		*g, *h;
	fr_cond_t		cond;
	fr_value_box_t		data;
	vp_map_t		map;
	vp_tmpl_t		vpt;

	g = unlang_generic_to_group(instruction);

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

			h = unlang_generic_to_group(this);
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
		data.vb_strvalue = p;
		tmpl_init(&vpt, TMPL_TYPE_UNPARSED, data.vb_strvalue, len, T_SINGLE_QUOTED_STRING);
	}

	/*
	 *	Find either the exact matching name, or the
	 *	"case {...}" statement.
	 */
	for (this = g->children; this; this = this->next) {
		rad_assert(this->type == UNLANG_TYPE_CASE);

		h = unlang_generic_to_group(this);

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

	/*
	 *	Nothing found.  Just continue, and ignore the "switch"
	 *	statement.
	 */
	if (!found) return UNLANG_ACTION_CONTINUE;

	unlang_push(stack, found, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);
	return UNLANG_ACTION_PUSHED_CHILD;
}


static unlang_action_t unlang_update(REQUEST *request, unlang_stack_t *stack,
				       rlm_rcode_t *presult, int *priority)
{
	int rcode;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g = unlang_generic_to_group(instruction);
	vp_map_t *map;

	for (map = g->map; map != NULL; map = map->next) {
		rcode = map_to_request(request, map, map_to_vp, NULL);
		if (rcode < 0) {
			*presult = (rcode == -2) ? RLM_MODULE_INVALID : RLM_MODULE_FAIL;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}
	}

	*presult = RLM_MODULE_NOOP;
	*priority = instruction->actions[RLM_MODULE_NOOP];
	return UNLANG_ACTION_CALCULATE_RESULT;
}


static unlang_action_t unlang_map(REQUEST *request, unlang_stack_t *stack,
				  rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g = unlang_generic_to_group(instruction);

	*presult = map_proc(request, g->proc_inst);

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_module_call(REQUEST *request, unlang_stack_t *stack,
				     	  rlm_rcode_t *presult, int *priority)
{
	unlang_module_call_t		*sp;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_stack_state_modcall_t	*modcall_state;

#ifndef NDEBUG
	int unlang_indent		= request->log.unlang_indent;
#endif

	/*
	 *	Process a stand-alone child, and fall through
	 *	to dealing with it's parent.
	 */
	sp = unlang_generic_to_module_call(instruction);
	rad_assert(sp);

	/*
	 *	If the request should stop, refuse to do anything.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) return UNLANG_ACTION_STOP_PROCESSING;

	RDEBUG4("[%i] %s - %s (%s)", stack->depth, __FUNCTION__,
		sp->module_instance->name, sp->module_instance->module->name);

	/*
	 *	Return administratively configured return code
	 */
	if (sp->module_instance->force) {
		request->rcode = sp->module_instance->code;
		goto done;
	}

	frame->state = modcall_state = talloc_zero(stack, unlang_stack_state_modcall_t);

	/*
	 *	Grab the thread/module specific data if any exists.
	 */
	modcall_state->thread = module_thread_instance_find(sp->module_instance);
	rad_assert(modcall_state->thread != NULL);

	/*
	 *	For logging unresponsive children.
	 */
	request->module = sp->module_instance->name;
	modcall_state->thread->total_calls++;

	/*
	 *	Lock is noop unless instance->mutex is set.
	 */
	safe_lock(sp->module_instance);
	*presult = request->rcode = sp->method(sp->module_instance->dl_inst->data, modcall_state->thread->data, request);
	safe_unlock(sp->module_instance);

	request->module = NULL;

	/*
	 *	Is now marked as "stop" when it wasn't before, we must have been blocked.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) {
		RWARN("Module %s became unblocked for request %" PRIu64 "",
		      sp->module_instance->module->name, request->number);
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	if (*presult == RLM_MODULE_YIELD) {
		modcall_state->thread->active_callers++;
	} else {
		rad_assert(unlang_indent == request->log.unlang_indent);

		rad_assert(*presult >= RLM_MODULE_REJECT);
		rad_assert(*presult < RLM_MODULE_NUMCODES);
		*priority = instruction->actions[*presult];
	}

done:
	*presult = request->rcode;
	RDEBUG2("%s (%s)", instruction->name ? instruction->name : "",
		fr_int2str(mod_rcode_table, *presult, "<invalid>"));

	return UNLANG_ACTION_CALCULATE_RESULT;
}


static unlang_action_t unlang_if(REQUEST *request, unlang_stack_t *stack,
				   rlm_rcode_t *presult, int *priority)
{
	int			condition;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g;

	g = unlang_generic_to_group(instruction);
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
		RDEBUG2("...");

		if (*presult != RLM_MODULE_UNKNOWN) *priority = instruction->actions[*presult];

		return UNLANG_ACTION_CONTINUE;
	}

	/*
	 *	Tell the main interpreter to skip over the else /
	 *	elsif blocks, as this "if" condition was taken.
	 */
	while (frame->next &&
	       ((frame->next->type == UNLANG_TYPE_ELSE) ||
		(frame->next->type == UNLANG_TYPE_ELSIF))) {
		frame->next = frame->next->next;
	}

	/*
	 *	We took the "if".  Go recurse into its' children.
	 */
	return unlang_group(request, stack, presult, priority);
}


static unlang_action_t unlang_module_resumption(REQUEST *request, unlang_stack_t *stack,
						rlm_rcode_t *presult, int *priority)
{
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_module_resumption_t	*mr = unlang_generic_to_module_resumption(instruction);
	unlang_module_call_t		*sp;
	unlang_stack_state_modcall_t	*modcall_state = talloc_get_type_abort(frame->state,
									       unlang_stack_state_modcall_t);
	void 				*mutable;

	sp = &mr->module;

	RDEBUG3("Resuming %s (%s) for request %" PRIu64,
		sp->module_instance->name,
		sp->module_instance->module->name, request->number);

	memcpy(&mutable, &mr->ctx, sizeof(mutable));
	request->module = sp->module_instance->name;

	/*
	 *	Lock is noop unless instance->mutex is set.
	 */
	safe_lock(sp->module_instance);
	*presult = request->rcode = mr->callback(request, mr->module.module_instance->dl_inst->data, mr->thread->data, mutable);
	safe_unlock(sp->module_instance);

	request->module = NULL;

	/*
	 *	Leave mr alone, it will be freed when the request is done.
	 */

	/*
	 *	Is now marked as "stop" when it wasn't before, we must have been blocked.
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) {
		RWARN("Module %s became unblocked for request %" PRIu64 "",
		      sp->module_instance->module->name, request->number);
		return UNLANG_ACTION_STOP_PROCESSING;
	}

	if (*presult != RLM_MODULE_YIELD) {
		modcall_state->thread->active_callers--;

		rad_assert(*presult >= RLM_MODULE_REJECT);
		rad_assert(*presult < RLM_MODULE_NUMCODES);
		*priority = instruction->actions[*presult];
	}

	*presult = request->rcode;
	RDEBUG2("%s (%s)", instruction->name ? instruction->name : "",
		fr_int2str(mod_rcode_table, *presult, "<invalid>"));

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
		.debug_braces = false
	},
	[UNLANG_TYPE_GROUP] = {
		.name = "group",
		.func = unlang_group,
		.debug_braces = true
	},
	[UNLANG_TYPE_LOAD_BALANCE] = {
		.name = "load-balance group",
		.func = unlang_load_balance,
		.debug_braces = true
	},
	[UNLANG_TYPE_REDUNDANT_LOAD_BALANCE] = {
		.name = "redundant-load-balance group",
		.func = unlang_redundant_load_balance,
		.debug_braces = true
	},
	[UNLANG_TYPE_PARALLEL] = {
		.name = "parallel",
		.func = unlang_parallel,
		.debug_braces = true
	},
#ifdef WITH_UNLANG
	[UNLANG_TYPE_IF] = {
		.name = "if",
		.func = unlang_if,
		.debug_braces = true
	},
	[UNLANG_TYPE_ELSE] = {
		.name = "else",
		.func = unlang_group,
		.debug_braces = true
	},
	[UNLANG_TYPE_ELSIF] = {
		.name = "elsif",
		.func = unlang_if,
		.debug_braces = true
	},
	[UNLANG_TYPE_UPDATE] = {
		.name = "update",
		.func = unlang_update,
		.debug_braces = true
	},
	[UNLANG_TYPE_SWITCH] = {
		.name = "switch",
		.func = unlang_switch,
		.debug_braces = true
	},
	[UNLANG_TYPE_CASE] = {
		.name = "case",
		.func = unlang_case,
		.debug_braces = true
	},
	[UNLANG_TYPE_FOREACH] = {
		.name = "foreach",
		.func = unlang_foreach,
		.debug_braces = true
	},
	[UNLANG_TYPE_BREAK] = {
		.name = "break",
		.func = unlang_break,
		.debug_braces = false
	},
	[UNLANG_TYPE_RETURN] = {
		.name = "return",
		.func = unlang_return,
		.debug_braces = false
	},
	[UNLANG_TYPE_MAP] = {
		.name = "map",
		.func = unlang_map,
		.debug_braces = true
	},
	[UNLANG_TYPE_POLICY] = {
		.name = "policy",
		.func = unlang_policy,
		.debug_braces = true
	},
	[UNLANG_TYPE_FORK] = {
		.name = "fork",
		.func = unlang_fork,
		.debug_braces = true
	},
#endif
	[UNLANG_TYPE_XLAT_INLINE] = {
		.name = "xlat_inline",
		.func = unlang_xlat_inline,
		.debug_braces = false
	},
	[UNLANG_TYPE_MODULE_RESUME] = {
		.name = "module-call-resume",
		.func = unlang_module_resumption,
		.debug_braces = false
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

#ifndef NDEBUG
	if (DEBUG_ENABLED5) DEBUG("###### unlang_run is starting");
	DUMP_STACK;
#endif

	/*
	 *	If we're called from a module, re-set this so that the
	 *	indentation works correctly...
	 *
	 *	@todo - save / restore this across frames?
	 */
	request->module = NULL;

	RDEBUG4("** [%i] %s - entered", stack->depth, __FUNCTION__);

	/*
	 *	We don't have a return code yet.
	 */
	result = RLM_MODULE_UNKNOWN;

start_subsection:
	priority = -1;

	rad_assert(stack->depth > 0);
	rad_assert(stack->depth < UNLANG_STACK_MAX);

	frame = &stack->frame[stack->depth];

	/*
	 *	Loop over all modules in this list.
	 */
	while (frame->instruction != NULL) {
resume_subsection:
		instruction = frame->instruction;

		DUMP_STACK;

		rad_assert(instruction->debug_name != NULL); /* if this happens, all bets are off. */

		VERIFY_REQUEST(request);

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

		if ((unlang_ops[instruction->type].debug_braces) && !frame->resume) {
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
			result = frame->result;
			goto start_subsection;

		case UNLANG_ACTION_BREAK:
			if (priority < 0) priority = 0;
			frame->result = result;
			frame->priority = priority;
			frame->next = NULL;
			goto done_subsection;

		case UNLANG_ACTION_CALCULATE_RESULT:
			if (result == RLM_MODULE_YIELD) {
				rad_assert(frame->instruction->type == UNLANG_TYPE_MODULE_RESUME);
				frame->resume = true;
				RDEBUG4("** [%i] %s - yielding with current (%s %d)", stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
					frame->priority);
				DUMP_STACK;
				return RLM_MODULE_YIELD;
			}

			frame->resume = false;

		calculate_result:
			if (unlang_ops[instruction->type].debug_braces) {
				REXDENT();
				RDEBUG2("} # %s (%s)", instruction->debug_name,
					fr_int2str(mod_rcode_table, result, "<invalid>"));
			}
			action = UNLANG_ACTION_CALCULATE_RESULT;

			RDEBUG4("** [%i] %s - have (%s %d) module returned (%s %d)",
				stack->depth, __FUNCTION__,
			        fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
			        frame->priority,
			        fr_int2str(mod_rcode_table, result, "<invalid>"),
			        priority);

			/*
			 *	Don't set action or priority if we don't have one.
			 */
			if (result == RLM_MODULE_UNKNOWN) goto keep_going;

			/*
			 *	The child's action says return.  Do so.
			 */
			if (instruction->actions[result] == MOD_ACTION_RETURN) {
				if (priority < 0) priority = 0;

				RDEBUG4("** [%i] %s - action says to return with (%s %d)",
					stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, result, "<invalid>"),
					priority);
				frame->result = result;
				frame->priority = priority;
				/* @todo - REXDENT? */
				goto done_subsection;
			}

			/*
			 *	If "reject", break out of the loop and return
			 *	reject.
			 */
			if (instruction->actions[result] == MOD_ACTION_REJECT) {
				if (priority < 0) priority = 0;

				RDEBUG4("** [%i] %s - action says to return with (%s %d)",
					stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, RLM_MODULE_REJECT, "<invalid>"),
					priority);
				frame->result = RLM_MODULE_REJECT;
				frame->priority = priority;
				/* @todo - REXDENT? */
				goto done_subsection;
			}

			/*
			 *	The array holds a default priority for this return
			 *	code.  Grab it in preference to any unset priority.
			 */
			if (priority < 0) {
				priority = instruction->actions[result];

				RDEBUG4("** [%i] %s - setting priority to (%s %d)",
					stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, result, "<invalid>"),
					priority);
			}

			/*
			 *	We're higher than any previous priority, remember this
			 *	return code and priority.
			 */
			if (priority > frame->priority) {
				frame->result = result;
				frame->priority = priority;

				RDEBUG4("** [%i] %s - over-riding result from higher priority to (%s %d)",
					stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, result, "<invalid>"),
					priority);
			}

			/*
			 *	If we've been told to stop processing
			 *	it, do so.
			 */
			if (frame->unwind != 0) {
				RDEBUG4("** [%i] %s - unwinding current frame with (%s %d)",
					stack->depth, __FUNCTION__,
					fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
					frame->priority);
				/* @todo - REXDENT? */
				goto done_subsection;
			}

			/* FALL-THROUGH */

		case UNLANG_ACTION_CONTINUE:
		keep_going:
			if ((action == UNLANG_ACTION_CONTINUE) && unlang_ops[instruction->type].debug_braces) {
				REXDENT();
				RDEBUG2("}");
			}
		} /* switch over return code from the interpreter function */

		frame->instruction = frame->next;
		if (frame->instruction) frame->next = frame->instruction->next;
	}

	RDEBUG4("** [%i] %s - done current subsection with (%s %d)",
		stack->depth, __FUNCTION__,
		fr_int2str(mod_rcode_table, frame->result, "<invalid>"),
		frame->priority);

done_subsection:

	/*
	 *	We're at the top frame, return the result from the
	 *	stack, and get rid of the top frame.
	 */
	if (frame->top_frame) {
	top_frame:
		RDEBUG4("** [%i] %s - returning %s", stack->depth, __FUNCTION__,
			fr_int2str(mod_rcode_table, frame->result, "<invalid>"));
		result = frame->result;
		stack->depth--;
		DUMP_STACK;
		return result;
	}

	/*
	 *	The result / priority is returned from
	 *	the sub-section, and made into our
	 *	current result / priority, as if we
	 *	had performed a module call.
	 */
	result = frame->result;
	priority = frame->priority;

	/*
	 *	We're done everything: return.
	 */
	if (stack->depth == 0) {
		return result;
	}

	unlang_pop(stack);

	RDEBUG4("** [%i] %s - continuing after subsection with (%s %d)",
		stack->depth, __FUNCTION__,
		fr_int2str(mod_rcode_table, result, "<invalid>"),
		priority);

	DUMP_STACK;

	/*
	 *	Reset the local variables, and check
	 *	for a (local) top frame.
	 */
	frame = &stack->frame[stack->depth];

	/*
	 *	Resume a "foreach" loop, or a "load-balance" section.
	 */
	if (frame->resume) goto resume_subsection;

	/*
	 *	If we're done, merge the last result / priority in.
	 */
	if (frame->top_frame) {
		/*
		 *	Nothing in this section, use the top frame result.
		 */
		if ((priority < 0) || (result == RLM_MODULE_UNKNOWN)) {
			result = frame->result;
			priority = frame->priority;
		}

		if (priority > frame->priority) {
			frame->result = result;
			frame->priority = priority;

			RDEBUG4("** [%i] %s - over-riding result from higher priority to (%s %d)",
				stack->depth, __FUNCTION__,
				fr_int2str(mod_rcode_table, result, "<invalid>"),
				priority);
		}
		goto top_frame;
	}

	instruction = frame->instruction;
	if (!instruction) {
		RERROR("Empty instruction.  Hard-coding to reject");
		DUMP_STACK;
		frame->result = result = RLM_MODULE_REJECT;
		frame->priority = 0;
		goto done_subsection;
	}

	goto calculate_result;
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
	unlang_t	*instruction = NULL;
	unlang_stack_t	*stack = request->stack;

	/*
	 *	Interpretable unlang instructions are stored as CONF_DATA
	 *	associated with sections.
	 */
	if (cs) {
		instruction = (unlang_t *)cf_data_value(cf_data_find(cs, unlang_group_t, NULL));
		if (!instruction) {
			RPEDEBUG("Failed to find pre-compiled unlang for section %s %s { ... }",
				cf_section_name1(cs), cf_section_name2(cs));
		}
	}

	if (!instruction) instruction = unlang_group_to_generic(&empty_group);

	/*
	 *	Push the default action, and the instruction which has
	 *	no action.
	 */
	unlang_push(stack, NULL, action, UNLANG_NEXT_STOP, UNLANG_TOP_FRAME);
	if (instruction) unlang_push(stack, instruction, RLM_MODULE_UNKNOWN, UNLANG_NEXT_CONTINUE, UNLANG_SUB_FRAME);

	RDEBUG4("** [%i] %s - substack begins", stack->depth, __FUNCTION__);

	DUMP_STACK;
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
	unlang_stack_t	*stack = request->stack;

	/*
	 *	This pushes a new frame onto the stack, which is the
	 *	start of a new unlang section...
	 */
	unlang_push_section(request, cs, action);

	return unlang_run(request, stack);
}

/** Execute an unlang section synchronously
 *
 * Create a temporary event loop and swap it out for the one in the request.
 * Execute unlang operations until we receive a non-yield return code then return.
 *
 * @note The use cases for this are very limited.  If you need to use it, chances
 *	are what you're doing could be done better using one of the thread
 *	event loops.
 *
 * @param[in] request	The current request.
 * @param[in] cs	Section with compiled unlang associated with it.
 * @param[in] action	The default return code to use.
 * @return One of the RLM_MODULE_* macros.
 */
rlm_rcode_t unlang_interpret_synchronous(REQUEST *request, CONF_SECTION *cs, rlm_rcode_t action)
{
	fr_event_list_t *el, *old;
	rlm_rcode_t	rcode;

	/*
	 *	Don't talloc from the request
	 *	as we'll almost certainly leave holes in the memory pool.
	 */
	MEM(el = fr_event_list_alloc(NULL, NULL, NULL));

	old = request->el;
	request->el = el;

	for (rcode = unlang_interpret(request, cs, action);
	     rcode == RLM_MODULE_YIELD;
	     rcode = unlang_interpret_continue(request)) {
		if (fr_event_corral(el, true) < 0) {
			RPERROR("Failed retrieving events");
			rcode = RLM_MODULE_FAIL;
			break;
		}

		fr_event_service(el);
	}

	talloc_free(request->el);
	request->el = old;

	return rcode;
}

/** Wrap an #fr_event_timer_t providing data needed for unlang events
 *
 */
typedef struct unlang_event_t {
	REQUEST				*request;			//!< Request this event pertains to.
	int				fd;				//!< File descriptor to wait on.
	fr_unlang_timeout_callback_t	timeout;			//!< Function to call on timeout.
	fr_unlang_fd_callback_t		fd_read;			//!< Function to call when FD is readable.
	fr_unlang_fd_callback_t		fd_write;			//!< Function to call when FD is writable.
	fr_unlang_fd_callback_t		fd_error;			//!< Function to call when FD has errored.
	void const			*inst;				//!< Module instance to pass to callbacks.
	void				*thread;			//!< Thread specific module instance.
	void const			*ctx;				//!< ctx data to pass to callbacks.
	fr_event_timer_t const		*ev;				//!< Event in this worker's event heap.
} unlang_event_t;

/** Frees an unlang event, removing it from the request's event loop
 *
 * @param[in] ev	The event to free.
 *
 * @return 0
 */
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
 * @param[in] el	the event timer was inserted into.
 * @param[in] now	The current time, as held by the event_list.
 * @param[in] ctx	unlang_event_t structure holding callbacks.
 *
 */
static void unlang_event_timeout_handler(UNUSED fr_event_list_t *el, struct timeval *now, void *ctx)
{
	unlang_event_t *ev = talloc_get_type_abort(ctx, unlang_event_t);
	void *mutable_ctx;
	void *mutable_inst;

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->timeout(ev->request, mutable_inst, ev->thread, mutable_ctx, now);
	talloc_free(ev);
}

/** Call the callback registered for a read I/O event
 *
 * @param[in] el	containing the event (not passed to the callback).
 * @param[in] fd	the I/O event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] ctx	unlang_event_t structure holding callbacks.
 */
static void unlang_event_fd_read_handler(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *ctx)
{
	unlang_event_t *ev = talloc_get_type_abort(ctx, unlang_event_t);
	void *mutable_ctx;
	void *mutable_inst;

	rad_assert(ev->fd == fd);

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->fd_read(ev->request, mutable_inst, ev->thread, mutable_ctx, fd);
}

/** Call the callback registered for a write I/O event
 *
 * @param[in] el	containing the event (not passed to the callback).
 * @param[in] fd	the I/O event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] ctx	unlang_event_t structure holding callbacks.
 */
static void unlang_event_fd_write_handler(UNUSED fr_event_list_t *el, int fd, UNUSED int flags, void *ctx)
{
	unlang_event_t *ev = talloc_get_type_abort(ctx, unlang_event_t);
	void *mutable_ctx;
	void *mutable_inst;

	rad_assert(ev->fd == fd);

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->fd_write(ev->request, mutable_inst, ev->thread, mutable_ctx, fd);
}

/** Call the callback registered for an I/O error event
 *
 * @param[in] el	containing the event (not passed to the callback).
 * @param[in] fd	the I/O event occurred on.
 * @param[in] flags	from kevent.
 * @param[in] fd_errno	from kevent.
 * @param[in] ctx	unlang_event_t structure holding callbacks.
 */
static void unlang_event_fd_error_handler(UNUSED fr_event_list_t *el, int fd,
					  UNUSED int flags, UNUSED int fd_errno, void *ctx)
{
	unlang_event_t *ev = talloc_get_type_abort(ctx, unlang_event_t);
	void *mutable_ctx;
	void *mutable_inst;

	rad_assert(ev->fd == fd);

	memcpy(&mutable_ctx, &ev->ctx, sizeof(mutable_ctx));
	memcpy(&mutable_inst, &ev->inst, sizeof(mutable_inst));

	ev->fd_error(ev->request, mutable_inst, ev->thread, mutable_ctx, fd);
}

/** Set a timeout for the request.
 *
 * Used when a module needs wait for an event.  Typically the callback is set, and then the
 * module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_resumable().
 *
 * param[in] request		the current request.
 * param[in] callback		to call.
 * param[in] ctx		for the callback.
 * param[in] timeout		when to call the timeout (i.e. now + timeout).
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_event_timeout_add(REQUEST *request, fr_unlang_timeout_callback_t callback,
			     void const *ctx, struct timeval *when)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_event_t			*ev;
	unlang_module_call_t		*sp;
	unlang_stack_state_modcall_t	*modcall_state = talloc_get_type_abort(frame->state,
									       unlang_stack_state_modcall_t);

	rad_assert(stack->depth > 0);
	rad_assert((frame->instruction->type == UNLANG_TYPE_MODULE_CALL) ||
		   (frame->instruction->type == UNLANG_TYPE_MODULE_RESUME));
	sp = unlang_generic_to_module_call(frame->instruction);

	ev = talloc_zero(request, unlang_event_t);
	if (!ev) return -1;

	ev->request = request;
	ev->fd = -1;
	ev->timeout = callback;
	ev->inst = sp->module_instance->dl_inst->data;
	ev->thread = modcall_state->thread;
	ev->ctx = ctx;

	if (fr_event_timer_insert(request, request->el, &ev->ev,
				  when, unlang_event_timeout_handler, ev) < 0) {
		RPEDEBUG("Failed inserting event");
		talloc_free(ev);
		return -1;
	}

	(void) request_data_add(request, ctx, -1, ev, true, false, false);

	talloc_set_destructor(ev, _unlang_event_free);

	return 0;
}

/** Delete a previously set timeout callback
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

/** Set a callback for the request.
 *
 * Used when a module needs to read from an FD.  Typically the callback is set, and then the
 * module returns unlang_module_yield().
 *
 * @note The callback is automatically removed on unlang_resumable().
 *
 * @param[in] request		The current request.
 * @param[in] read		callback.  Used for receiving and demuxing/decoding data.
 * @param[in] write		callback.  Used for writing and encoding data.
 *				Where a 3rd party library is used, this should be the function
 *				issuing queries, and writing data to the socket.  This should
 *				not be done in the module itself.
 *				This allows write operations to be retried in some instances,
 *				and means if the write buffer is full, the request is kept in
 *				a suspended state.
 * @param[in] error		callback.  If the fd enters an error state.  Should cleanup any
 *				handles wrapping the file descriptor, and any outstanding requests.
 * @param[in] ctx		for the callback.
 * @param[in] fd		to watch.
 * @return
 *	- 0 on success.
 *	- <0 on error.
 */
int unlang_event_fd_add(REQUEST *request,
			fr_unlang_fd_callback_t read,
			fr_unlang_fd_callback_t write,
			fr_unlang_fd_callback_t error,
			void const *ctx, int fd)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_event_t			*ev;
	unlang_module_call_t		*sp;
	unlang_stack_state_modcall_t	*modcall_state = talloc_get_type_abort(frame->state,
									       unlang_stack_state_modcall_t);

	rad_assert(stack->depth > 0);

	rad_assert((frame->instruction->type == UNLANG_TYPE_MODULE_CALL) ||
		   (frame->instruction->type == UNLANG_TYPE_MODULE_RESUME));
	sp = unlang_generic_to_module_call(frame->instruction);

	ev = talloc_zero(request, unlang_event_t);
	if (!ev) return -1;

	ev->request = request;
	ev->fd = fd;
	ev->fd_read = read;
	ev->fd_write = write;
	ev->fd_error = error;
	ev->inst = sp->module_instance->dl_inst->data;
	ev->thread = modcall_state->thread;
	ev->ctx = ctx;

	/*
	 *	Register for events on the file descriptor
	 */
	if (fr_event_fd_insert(request, request->el, fd,
			       ev->fd_read ? unlang_event_fd_read_handler : NULL,
			       ev->fd_write ? unlang_event_fd_write_handler : NULL,
			       ev->fd_error ? unlang_event_fd_error_handler: NULL, ev) < 0) {
		talloc_free(ev);
		return -1;
	}

	(void) request_data_add(request, ctx, fd, ev, true, false, false);
	talloc_set_destructor(ev, _unlang_event_free);

	return 0;
}

/** Delete a previously set file descriptor callback
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
 * @note that this schedules the request for resumption.  It does not immediately
 *	start running the request.
 *
 * @param[in] request		The current request.
 */
void unlang_resumable(REQUEST *request)
{
	fr_heap_insert(request->backlog, request);
}

/** Send a signal (usually stop) to a request
 *
 * This is typically called via an "async" action, i.e. an action
 * outside of the normal processing of the request.
 *
 * If there is no #fr_unlang_action_t callback defined, the action is ignored.
 *
 * @param[in] request		The current request.
 * @param[in] action		to signal.
 */
void unlang_signal(REQUEST *request, fr_state_action_t action)
{
	unlang_stack_frame_t		*frame;
	unlang_stack_t			*stack = request->stack;
	unlang_module_resumption_t	*mr;
	void				*mutable;

	rad_assert(stack->depth > 0);

	frame = &stack->frame[stack->depth];

	/*
	 *	Be gracious in errors.
	 */
	if (frame->instruction->type != UNLANG_TYPE_MODULE_RESUME) {
		return;
	}

	mr = unlang_generic_to_module_resumption(frame->instruction);
	if (!mr->signal_callback) return;

	memcpy(&mutable, &mr->ctx, sizeof(mutable));

	mr->signal_callback(request, mr->module.module_instance->dl_inst->data, mr->thread->data, mutable, action);
}

/** Yield a request back to the interpreter from within a module
 *
 * This passes control of the request back to the unlang interpreter, setting
 * callbacks to execute when the request is 'signalled' asynchronously, or whatever
 * timer or I/O event the module was waiting for occurs.
 *
 * @note The module function which calls #unlang_module_yield should return control
 *	of the C stack to the unlang interpreter immediately after calling #unlang_module_yield.
 *	A common pattern is to use ``return unlang_module_yield(...)``.
 *
 * @param[in] request		The current request.
 * @param[in] callback		to call on unlang_resumable().
 * @param[in] signal_callback	to call on unlang_action().
 * @param[in] ctx		to pass to the callbacks.
 * @return always returns RLM_MODULE_YIELD.
 */
rlm_rcode_t unlang_module_yield(REQUEST *request, fr_unlang_module_resume_t callback,
				fr_unlang_action_t signal_callback, void const *ctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_module_resumption_t	*mr;
	unlang_module_call_t		*sp;
	unlang_stack_state_modcall_t	*modcall_state = talloc_get_type_abort(frame->state,
									       unlang_stack_state_modcall_t);

	rad_assert(stack->depth > 0);

	rad_assert((frame->instruction->type == UNLANG_TYPE_MODULE_CALL) ||
		   (frame->instruction->type == UNLANG_TYPE_MODULE_RESUME));
	sp = unlang_generic_to_module_call(frame->instruction);

	mr = talloc(request, unlang_module_resumption_t);
	rad_assert(mr != NULL);

	memcpy(&mr->module, frame->instruction, sizeof(mr->module));
	mr->thread = modcall_state->thread;
	mr->module.self.type = UNLANG_TYPE_MODULE_RESUME;
	mr->callback = callback;
	mr->signal_callback = signal_callback;
	mr->thread = module_thread_instance_find(sp->module_instance);
	mr->ctx = ctx;

	/*
	 *	Replaces the current MODULE_CALL stack frame with a
	 *	MODULE_RESUME frame.
	 */
	frame->instruction = unlang_module_resumption_to_generic(mr);

	return RLM_MODULE_YIELD;
}
