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
 * @file unlang/interpret.c
 * @brief Execute compiled unlang structures using an iterative interpreter.
 *
 * @copyright 2006-2016 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/cond_eval.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/parser.h>
#include <freeradius-devel/server/xlat.h>

#include <freeradius-devel/io/listen.h>

#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/rand.h>

#include "unlang_priv.h"

/*
 *	Some functions differ mainly in their parsing
 */

#define unlang_policy unlang_group
#define unlang_break unlang_return


typedef struct {
	unlang_function_t		func;			//!< To call when going down the stack.
	unlang_function_t		repeat;			//!< To call when going back up the stack.
	void				*uctx;			//!< Uctx to pass to function.
} unlang_frame_state_func_t;

/** Static instruction for allowing modules/xlats to call functions within themselves, or submodules
 *
 */
static unlang_t function_instruction = {
	.type = UNLANG_TYPE_FUNCTION,
	.name = "function",
	.debug_name = "function",
	.actions = {
		[RLM_MODULE_REJECT]	= 0,
		[RLM_MODULE_FAIL]	= 0,
		[RLM_MODULE_OK]		= 0,
		[RLM_MODULE_HANDLED]	= 0,
		[RLM_MODULE_INVALID]	= 0,
		[RLM_MODULE_USERLOCK]	= 0,
		[RLM_MODULE_NOTFOUND]	= 0,
		[RLM_MODULE_NOOP]	= 0,
		[RLM_MODULE_UPDATED]	= 0
	},
};

/** Call a generic function
 *
 * @param[in] request	The current request.
 * @param[out] presult	The frame result.  Always set to RLM_MODULE_OK (fixme?).
 * @param[out] priority of the result.
 */
static unlang_action_t unlang_function_call(REQUEST *request,
					    rlm_rcode_t *presult, int *priority)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_func_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_func_t);
	unlang_action_t			ua;
	char const 			*caller;

	/*
	 *	Don't let the callback mess with the current
	 *	module permanently.
	 */
	caller = request->module;
	request->module = NULL;
	if (!frame->repeat) {
		ua = state->func(request, presult, priority, state->uctx);
	} else {
		ua = state->repeat(request, presult, priority, state->uctx);
	}
	request->module = caller;

	return ua;
}

/** Push a generic function onto the unlang stack
 *
 * These can be pushed by any other type of unlang op to allow a submodule or function
 * deeper in the C call stack to establish a new resumption point.
 *
 * @param[in] request	The current request.
 * @param[in] func	to call going up the stack.
 * @param[in] repeat	function to call going back down the stack (may be NULL).
 *			This may be the same as func.
 * @param[in] uctx	to pass to func.
 */
void unlang_push_function(REQUEST *request, unlang_function_t func, unlang_function_t repeat, void *uctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame;
	unlang_frame_state_func_t	*state;

	/*
	 *	Push module's function
	 */
	unlang_push(stack, &function_instruction, RLM_MODULE_UNKNOWN, UNLANG_NEXT_STOP, false);
	frame = &stack->frame[stack->depth];

	/*
	 *	Tell the interpreter to call unlang_function_call
	 *	again when going back up the stack.
	 */
	if (repeat) frame->repeat = true;

	/*
	 *	Allocate state
	 */
	MEM(frame->state = state = talloc_zero(stack, unlang_frame_state_func_t));

	state->func = func;
	state->repeat = repeat;
	state->uctx = uctx;
}

static unlang_action_t unlang_group(REQUEST *request,
				    UNUSED rlm_rcode_t *result, UNUSED int *priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g;

	g = unlang_generic_to_group(instruction);

	/*
	 *	The compiler catches most of these, EXCEPT for the
	 *	top-level 'recv Access-Request' etc.  Which can exist,
	 *	and can be empty.
	 */
	if (!g->children) {
		RDEBUG2("} # %s ... <ignoring empty subsection>", instruction->debug_name);
		return UNLANG_ACTION_EXECUTE_NEXT;
	}

	unlang_push(stack, g->children, frame->result, UNLANG_NEXT_SIBLING, UNLANG_SUB_FRAME);
	return UNLANG_ACTION_PUSHED_CHILD;
}


static unlang_action_t unlang_call(REQUEST *request,
				   UNUSED rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g;
	int			indent;
	fr_io_final_t		final;
	unlang_stack_t		*current;
	CONF_SECTION		*server_cs;

	g = unlang_generic_to_group(instruction);
	rad_assert(g->children != NULL);

	/*
	 *	@todo - allow for other process functions.  Mostly
	 *	because we need to save and resume this function, and
	 *	we haven't bothered to do that so far.
	 *
	 *	If we DO allow other functions, we need to replace
	 *	request->async->listener, as we want to pretend this
	 *	is a virtual request which didn't come in from the
	 *	network.  i.e. the other virtual server shouldn't be
	 *	able to access request->async->listener, and muck with
	 *	it's statistics, see it's configuration, etc.
	 */
	rad_assert(request->async->process == unlang_io_process_interpret);

	/*
	 *	@todo - We probably want to just remove the 'stack'
	 *	parameter from the interpreter function arguments.
	 *	It's not needed there.
	 */
	rad_assert(stack == request->stack);

	indent = request->log.unlang_indent;
	request->log.unlang_indent = 0; /* the process function expects this */

	current = request->stack;
	request->stack = talloc_zero(request, unlang_stack_t);

	server_cs = request->server_cs;
	request->server_cs = g->server_cs;

	memcpy(&request->async->process, &g->process, sizeof(request->async->process));

	RDEBUG("server %s {", cf_section_name2(g->server_cs));

	/*
	 *	@todo - we can't change protocols (e.g. RADIUS ->
	 *	DHCP) unless we're in a subrequest.
	 *
	 *	@todo - we can't change packet types
	 *	(e.g. Access-Request -> Accounting-Request) unless
	 *	we're in a subrequest.
	 */
	final = request->async->process(request->async->process_inst, request, FR_IO_ACTION_RUN);

	RDEBUG("} # server %s", cf_section_name2(g->server_cs));

	/*
	 *	All other return codes are semantically equivalent for
	 *	our purposes.  "DONE" means "stopped without reply",
	 *	and REPLY means "finished successfully".  Neither of
	 *	those map well into module rcodes.  Instead, we rely
	 *	on the caller to look at request->reply->code.
	 */
	if (final == FR_IO_YIELD) {
		RDEBUG2("Noo yield for you!");
	}

	/*
	 *	@todo - save these in a resume state somewhere...
	 */
	request->log.unlang_indent = indent;
	request->async->process = unlang_io_process_interpret;
	talloc_free(request->stack);
	request->stack = current;
	request->server_cs = server_cs;

	RDEBUG("Continuing with contents of %s { ...", instruction->debug_name);

	/*
	 *	And then call the children to process the answer.
	 */
	unlang_push(stack, g->children, frame->result, UNLANG_NEXT_SIBLING, UNLANG_SUB_FRAME);
	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_case(REQUEST *request,
				   rlm_rcode_t *presult, int *priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t	*g;

	g = unlang_generic_to_group(instruction);

	if (!g->children) {
		*presult = RLM_MODULE_NOOP;
		*priority = 0;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	return unlang_group(request, presult, priority);
}

static unlang_action_t unlang_return(REQUEST *request,
				     rlm_rcode_t *presult, int *priority)
{
	int			i;
	VALUE_PAIR		**copy_p;
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;

	RDEBUG2("%s", unlang_ops[instruction->type].name);

	for (i = 8; i >= 0; i--) {
		copy_p = request_data_get(request, (void *)xlat_fmt_get_vp, i);
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

static unlang_action_t unlang_switch(REQUEST *request,
				       UNUSED rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_t		*stack = request->stack;
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
	if (!found) return UNLANG_ACTION_EXECUTE_NEXT;

	unlang_push(stack, found, frame->result, UNLANG_NEXT_STOP, UNLANG_SUB_FRAME);
	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_if(REQUEST *request,
				   rlm_rcode_t *presult, int *priority)
{
	int			condition;
	unlang_stack_t		*stack = request->stack;
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

		return UNLANG_ACTION_EXECUTE_NEXT;
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
	return unlang_group(request, presult, priority);
}

int unlang_op_init(void)
{
	unlang_op_register(UNLANG_TYPE_FUNCTION,
			   &(unlang_op_t){
				.name = "function",
				.func = unlang_function_call,
				.debug_braces = false
			   });

	unlang_op_register(UNLANG_TYPE_GROUP,
			   &(unlang_op_t){
				.name = "group",
				.func = unlang_group,
				.debug_braces = true
			   });

#ifdef WITH_UNLANG
	unlang_op_register(UNLANG_TYPE_IF,
			   &(unlang_op_t){
				.name = "if",
				.func = unlang_if,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_ELSE,
			   &(unlang_op_t){
				.name = "else",
				.func = unlang_group,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_ELSIF,
			   &(unlang_op_t){
				.name = "elseif",
				.func = unlang_if,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_SWITCH,
			   &(unlang_op_t){
				.name = "switch",
				.func = unlang_switch,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_CASE,
			   &(unlang_op_t){
				.name = "case",
				.func = unlang_case,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_BREAK,
			   &(unlang_op_t){
				.name = "break",
				.func = unlang_break,
			   });

	unlang_op_register(UNLANG_TYPE_RETURN,
			   &(unlang_op_t){
				.name = "return",
				.func = unlang_return,
			   });

	unlang_op_register(UNLANG_TYPE_POLICY,
			   &(unlang_op_t){
				.name = "policy",
				.func = unlang_policy,
			   });

	unlang_op_register(UNLANG_TYPE_CALL,
			   &(unlang_op_t){
				.name = "call",
				.func = unlang_call,
				.debug_braces = true
			   });

	unlang_foreach_init();
	unlang_load_balance_init();
	unlang_map_init();
	unlang_module_init();
	unlang_parallel_init();
	if (unlang_subrequest_init() < 0) return -1;
#endif

	return 0;
}

void unlang_op_free(void)
{
	unlang_subrequest_free();
}
