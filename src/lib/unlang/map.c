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
 * @brief map and unlang integration.
 * @brief Unlang "map" keyword evaluation.
 *
 * @ingroup AVP
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/unlang/tmpl.h>
#include <freeradius-devel/unlang/map.h>

#include "map_priv.h"

/** State of a map block
 *
 */
typedef struct {
	fr_value_box_list_t		src_result;		//!< Result of expanding the map source.

	/** @name Resumption and signalling
	 * @{
 	 */
	void				*rctx;			//!< for resume / signal
	map_proc_func_t			resume;			//!< resumption handler
	unlang_map_signal_t		signal;			//!< for signal handlers
	fr_signal_t			sigmask;		//!< Signals to block.

	/** @} */
} unlang_frame_state_map_proc_t;

/** Wrapper to create a map_ctx_t as a compound literal
 *
 * @param[in] _mod_inst	of the module being called.
 * @param[in] _map_inst	of the map being called.
 * @param[in] _rctx	Resume ctx (if any).
 */
#define MAP_CTX(_mod_inst, _map_inst, _rctx) &(map_ctx_t){ .moi = _mod_inst, .mpi = _map_inst, .rctx = _rctx }

static unlang_action_t map_proc_resume(unlang_result_t *p_result, request_t *request,
#ifdef WITH_VERIFY_PTR
				       unlang_stack_frame_t *frame
#else
				       UNUSED unlang_stack_frame_t *frame
#endif
				      )
{
	unlang_frame_state_map_proc_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_map_proc_t);
	unlang_frame_state_map_proc_t	*map_proc_state = talloc_get_type_abort(frame->state, unlang_frame_state_map_proc_t);
	map_proc_func_t			resume;
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	unlang_map_t			*gext = unlang_group_to_map(g);
	map_proc_inst_t			*inst = gext->proc_inst;
	unlang_action_t			ua = UNLANG_ACTION_CALCULATE_RESULT;

#ifdef WITH_VERIFY_PTR
	VALUE_BOX_LIST_VERIFY(&map_proc_state->src_result);
#endif
	resume = state->resume;
	state->resume = NULL;

	/*
	 *	Call any map resume function
	 */
	if (resume) ua = resume(p_result, MAP_CTX(inst->proc->mod_inst, inst->data, state->rctx),
				request, &map_proc_state->src_result, inst->maps);
	return ua;
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
 * @param[in] resume		Called on unlang_interpret_mark_runnable().
 * @param[in] signal		Called on unlang_action().
 * @param[in] sigmask		Set of signals to block.
 * @param[in] rctx		to pass to the callbacks.
 * @return
 *	- UNLANG_ACTION_YIELD.
 */
unlang_action_t unlang_map_yield(request_t *request,
				 map_proc_func_t resume, unlang_map_signal_t signal, fr_signal_t sigmask, void *rctx)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_map_proc_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_map_proc_t);

	REQUEST_VERIFY(request);	/* Check the yielded request is sane */

	state->rctx = rctx;
	state->resume = resume;
	state->signal = signal;
	state->sigmask = sigmask;

	/*
	 *	We set the repeatable flag here,
	 *	so that the resume function is always
	 *	called going back up the stack.
	 */
	frame_repeat(frame, map_proc_resume);

	return UNLANG_ACTION_YIELD;
}

static unlang_action_t map_proc_apply(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	unlang_map_t			*gext = unlang_group_to_map(g);

	map_proc_inst_t			*inst = gext->proc_inst;
	unlang_frame_state_map_proc_t	*map_proc_state = talloc_get_type_abort(frame->state, unlang_frame_state_map_proc_t);

	RDEBUG2("MAP %s \"%pM\"", inst->proc->name, &map_proc_state->src_result);

	VALUE_BOX_LIST_VERIFY(&map_proc_state->src_result);
	frame_repeat(frame, map_proc_resume);

	return inst->proc->evaluate(p_result, MAP_CTX(inst->proc->mod_inst, inst->data, NULL),
				    request, &map_proc_state->src_result, inst->maps);
}

static unlang_action_t unlang_map_state_init(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	unlang_map_t			*gext = unlang_group_to_map(g);
	map_proc_inst_t			*inst = gext->proc_inst;
	unlang_frame_state_map_proc_t	*map_proc_state = talloc_get_type_abort(frame->state, unlang_frame_state_map_proc_t);

	/*
	 *	Initialise the frame state
	 */
	repeatable_set(frame);

	fr_value_box_list_init(&map_proc_state->src_result);
	/*
	 *	Set this BEFORE doing anything else, as we will be
	 *	called again after unlang_xlat_push() returns.
	 */
	frame->process = map_proc_apply;

	/*
	 *	Expand the map source
	 */
	if (inst->src) switch (inst->src->type) {
	default:
	{
		fr_value_box_t *src_result = NULL;
		if (tmpl_aexpand(frame->state, &src_result,
				 request, inst->src, NULL, NULL) < 0) {
			REDEBUG("Failed expanding map src");
		error:
			RETURN_UNLANG_FAIL;
		}
		fr_value_box_list_insert_head(&map_proc_state->src_result, src_result);
		break;
	}
	case TMPL_TYPE_EXEC:
		if (unlang_tmpl_push(map_proc_state, NULL, &map_proc_state->src_result,
				     request, inst->src, NULL, UNLANG_SUB_FRAME) < 0) {
			RETURN_UNLANG_ACTION_FATAL;
		}
		return UNLANG_ACTION_PUSHED_CHILD;

	case TMPL_TYPE_XLAT:
		if (unlang_xlat_push(map_proc_state, NULL, &map_proc_state->src_result,
				     request, tmpl_xlat(inst->src), false) < 0) {
			RETURN_UNLANG_ACTION_FATAL;
		}
		return UNLANG_ACTION_PUSHED_CHILD;


	case TMPL_TYPE_REGEX:
	case TMPL_TYPE_REGEX_UNCOMPILED:
	case TMPL_TYPE_REGEX_XLAT:
	case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:
	case TMPL_TYPE_XLAT_UNRESOLVED:
		fr_assert(0);
		goto error;
	}

	return map_proc_apply(p_result, request, frame);
}

static int compile_map_name(unlang_group_t *g)
{
	unlang_map_t	*gext = unlang_group_to_map(g);

	/*
	 *	map <module-name> <arg>
	 */
	if (gext->vpt) {
		char	quote;
		size_t	quoted_len;
		char	*quoted_str;

		switch (cf_section_argv_quote(g->cs, 0)) {
		case T_DOUBLE_QUOTED_STRING:
			quote = '"';
			break;

		case T_SINGLE_QUOTED_STRING:
			quote = '\'';
			break;

		case T_BACK_QUOTED_STRING:
			quote = '`';
			break;

		default:
			quote = '\0';
			break;
		}

		quoted_len = fr_snprint_len(gext->vpt->name, gext->vpt->len, quote);
		quoted_str = talloc_array(g, char, quoted_len);
		fr_snprint(quoted_str, quoted_len, gext->vpt->name, gext->vpt->len, quote);

		g->self.name = talloc_typed_asprintf(g, "map %s %s", cf_section_name2(g->cs), quoted_str);
		g->self.debug_name = g->self.name;
		talloc_free(quoted_str);

		return 0;
	}

	g->self.name = talloc_typed_asprintf(g, "map %s", cf_section_name2(g->cs));
	g->self.debug_name = g->self.name;

	return 0;
}

/** Validate and fixup a map that's part of an map section.
 *
 * @param map to validate.
 * @param ctx data to pass to fixup function (currently unused).
 * @return 0 if valid else -1.
 */
static int fixup_map_cb(map_t *map, UNUSED void *ctx)
{
	switch (map->lhs->type) {
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_XLAT_UNRESOLVED:
	case TMPL_TYPE_XLAT:
		break;

	default:
		cf_log_err(map->ci, "Left side of map must be an attribute "
		           "or an xlat (that expands to an attribute), not a %s",
		           tmpl_type_to_str(map->lhs->type));
		return -1;
	}

	switch (map->rhs->type) {
	case TMPL_TYPE_XLAT_UNRESOLVED:
	case TMPL_TYPE_DATA_UNRESOLVED:
	case TMPL_TYPE_DATA:
	case TMPL_TYPE_XLAT:
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_EXEC:
		break;

	default:
		cf_log_err(map->ci, "Right side of map must be an attribute, literal, xlat or exec, got type %s",
		           tmpl_type_to_str(map->rhs->type));
		return -1;
	}

	if (!fr_assignment_op[map->op] && !fr_comparison_op[map->op]) {
		cf_log_err(map->ci, "Invalid operator \"%s\" in map section.  "
			   "Only assignment or filter operators are allowed",
			   fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"));
		return -1;
	}

	return 0;
}

static unlang_t *unlang_compile_map(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION 		*cs = cf_item_to_section(ci);
	int			rcode;

	unlang_group_t		*g;
	unlang_map_t	*gext;

	unlang_t		*c;
	CONF_SECTION		*modules;
	char const		*tmpl_str;

	tmpl_t			*vpt = NULL;

	map_proc_t		*proc;
	map_proc_inst_t		*proc_inst;

	char const		*name2 = cf_section_name2(cs);

	tmpl_rules_t		t_rules;

	/*
	 *	The RHS is NOT resolved in the context of the LHS.
	 */
	t_rules = *(unlang_ctx->rules);
	t_rules.attr.disallow_rhs_resolve = true;
	RULES_VERIFY(&t_rules);

	modules = cf_section_find(cf_root(cs), "modules", NULL);
	if (!modules) {
		cf_log_err(cs, "'map' sections require a 'modules' section");
		return NULL;
	}

	proc = map_proc_find(name2);
	if (!proc) {
		cf_log_err(cs, "Failed to find map processor '%s'", name2);
		return NULL;
	}
	t_rules.literals_safe_for = map_proc_literals_safe_for(proc);

	g = unlang_group_allocate(parent, cs, UNLANG_TYPE_MAP);
	if (!g) return NULL;

	gext = unlang_group_to_map(g);

	/*
	 *	If there's a third string, it's the map src.
	 *
	 *	Convert it into a template.
	 */
	tmpl_str = cf_section_argv(cs, 0); /* AFTER name1, name2 */
	if (tmpl_str) {
		fr_token_t type;

		type = cf_section_argv_quote(cs, 0);

		/*
		 *	Try to parse the template.
		 */
		(void) tmpl_afrom_substr(gext, &vpt,
					 &FR_SBUFF_IN(tmpl_str, talloc_array_length(tmpl_str) - 1),
					 type,
					 NULL,
					 &t_rules);
		if (!vpt) {
			cf_log_perr(cs, "Failed parsing map");
		error:
			talloc_free(g);
			return NULL;
		}

		/*
		 *	Limit the allowed template types.
		 */
		switch (vpt->type) {
		case TMPL_TYPE_DATA_UNRESOLVED:
		case TMPL_TYPE_ATTR:
		case TMPL_TYPE_ATTR_UNRESOLVED:
		case TMPL_TYPE_XLAT:
		case TMPL_TYPE_XLAT_UNRESOLVED:
		case TMPL_TYPE_EXEC:
		case TMPL_TYPE_EXEC_UNRESOLVED:
		case TMPL_TYPE_DATA:
			break;

		default:
			talloc_free(vpt);
			cf_log_err(cs, "Invalid third argument for map");
			return NULL;
		}
	}

	/*
	 *	This looks at cs->name2 to determine which list to update
	 */
	map_list_init(&gext->map);
	rcode = map_afrom_cs(gext, &gext->map, cs, unlang_ctx->rules, &t_rules, fixup_map_cb, NULL, 256);
	if (rcode < 0) return NULL; /* message already printed */
	if (map_list_empty(&gext->map)) {
		cf_log_err(cs, "'map' sections cannot be empty");
		goto error;
	}


	/*
	 *	Call the map's instantiation function to validate
	 *	the map and perform any caching required.
	 */
	proc_inst = map_proc_instantiate(gext, proc, cs, vpt, &gext->map);
	if (!proc_inst) {
		cf_log_err(cs, "Failed instantiating map function '%s'", name2);
		goto error;
	}
	c = unlang_group_to_generic(g);

	gext->vpt = vpt;
	gext->proc_inst = proc_inst;

	compile_map_name(g);

	/*
	 *	Cache the module in the unlang_group_t struct.
	 *
	 *	Ensure that the module has a "map" entry in its module
	 *	header?  Or ensure that the map is registered in the
	 *	"bootstrap" phase, so that it's always available here.
	 */
	if (!pass2_fixup_map_rhs(g, unlang_ctx->rules)) goto error;

	return c;
}


void unlang_map_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "map",
			.type = UNLANG_TYPE_MAP,
			.flag = UNLANG_OP_FLAG_RCODE_SET,

			.compile = unlang_compile_map,
			.interpret = unlang_map_state_init,

			.unlang_size = sizeof(unlang_map_t),
			.unlang_name = "unlang_map_t",

			.frame_state_size = sizeof(unlang_frame_state_map_proc_t),
			.frame_state_type = "unlang_frame_state_map_proc_t",
		});
}
