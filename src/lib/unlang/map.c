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

typedef enum {
	UNLANG_UPDATE_MAP_INIT = 0,				//!< Start processing a map.
	UNLANG_UPDATE_MAP_EXPANDED_LHS,				//!< Expand the LHS xlat or exec (if needed).
	UNLANG_UPDATE_MAP_EXPANDED_RHS				//!< Expand the RHS xlat or exec (if needed).
} unlang_update_state_t;

/** State of an update block
 *
 */
typedef struct {
	fr_dcursor_t			maps;			//!< Cursor of maps to evaluate.

	fr_dlist_head_t			vlm_head;		//!< Head of list of VP List Mod.

	fr_value_box_list_t		lhs_result;		//!< Result of expanding the LHS
	fr_value_box_list_t		rhs_result;		//!< Result of expanding the RHS.

	unlang_update_state_t		state;			//!< What we're currently doing.
} unlang_frame_state_update_t;

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

/** Apply a list of modifications on one or more fr_pair_t lists.
 *
 * @param[in] request	The current request.
 * @param[out] p_result	The rcode indicating what the result
 *      		of the operation was.
 * @return
 *	- UNLANG_ACTION_CALCULATE_RESULT changes were applied.
 *	- UNLANG_ACTION_PUSHED_CHILD async execution of an expansion is required.
 */
static unlang_action_t list_mod_apply(unlang_result_t *p_result, request_t *request)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_frame_state_update_t	*update_state = frame->state;
	vp_list_mod_t const		*vlm = NULL;

	/*
	 *	No modifications...
	 */
	if (fr_dlist_empty(&update_state->vlm_head)) {
		RDEBUG2("Nothing to update");
		goto done;
	}

	/*
	 *	Apply the list of modifications.  This should not fail
	 *	except on memory allocation error.
	 */
	while ((vlm = fr_dlist_next(&update_state->vlm_head, vlm))) {
		int ret;

		ret = map_list_mod_apply(request, vlm);
		if (!fr_cond_assert(ret == 0)) {
			TALLOC_FREE(frame->state);

			return UNLANG_ACTION_FAIL;
		}
	}

done:
	RETURN_UNLANG_NOOP;
}

/** Create a list of modifications to apply to one or more fr_pair_t lists
 *
 * @param[out] p_result	The rcode indicating what the result
 *      		of the operation was.
 * @param[in] request	The current request.
 * @param[in] frame	Current stack frame.
 * @return
 *	- UNLANG_ACTION_CALCULATE_RESULT changes were applied.
 *	- UNLANG_ACTION_PUSHED_CHILD async execution of an expansion is required.
 */
static unlang_action_t list_mod_create(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_update_t	*update_state = talloc_get_type_abort(frame->state, unlang_frame_state_update_t);
	map_t				*map;

	/*
	 *	Iterate over the maps producing a set of modifications to apply.
	 */
	for (map = fr_dcursor_current(&update_state->maps);
	     map;
	     map = fr_dcursor_next(&update_state->maps)) {
	     	repeatable_set(frame);	/* Call us again when done */

		switch (update_state->state) {
		case UNLANG_UPDATE_MAP_INIT:
			update_state->state = UNLANG_UPDATE_MAP_EXPANDED_LHS;

			fr_assert(fr_value_box_list_empty(&update_state->lhs_result));	/* Should have been consumed */
			fr_assert(fr_value_box_list_empty(&update_state->rhs_result));	/* Should have been consumed */

			switch (map->lhs->type) {
			default:
				break;

			case TMPL_TYPE_EXEC:
				if (unlang_tmpl_push(update_state, &update_state->lhs_result,
						     request, map->lhs,
						     NULL) < 0) {
					return UNLANG_ACTION_STOP_PROCESSING;
				}
				return UNLANG_ACTION_PUSHED_CHILD;

			case TMPL_TYPE_XLAT:
				if (unlang_xlat_push(update_state, NULL, &update_state->lhs_result,
						     request, tmpl_xlat(map->lhs), false) < 0) {
					return UNLANG_ACTION_STOP_PROCESSING;
				}
				return UNLANG_ACTION_PUSHED_CHILD;

			case TMPL_TYPE_REGEX_XLAT_UNRESOLVED:
			case TMPL_TYPE_REGEX:
			case TMPL_TYPE_REGEX_UNCOMPILED:
			case TMPL_TYPE_REGEX_XLAT:
			case TMPL_TYPE_XLAT_UNRESOLVED:
				fr_assert(0);
			error:
				TALLOC_FREE(frame->state);
				repeatable_clear(frame);
				return UNLANG_ACTION_FAIL;
			}
			FALL_THROUGH;

		case UNLANG_UPDATE_MAP_EXPANDED_LHS:
			/*
			 *	map_to_list_mod() already concatenates the LHS, so we don't need to do it here.
			 */
			if (!map->rhs) goto next;

			update_state->state = UNLANG_UPDATE_MAP_EXPANDED_RHS;

			switch (map->rhs->type) {
			default:
				break;

			case TMPL_TYPE_EXEC:
				if (unlang_tmpl_push(update_state, &update_state->rhs_result,
						     request, map->rhs, NULL) < 0) {
					return UNLANG_ACTION_STOP_PROCESSING;
				}
				return UNLANG_ACTION_PUSHED_CHILD;

			case TMPL_TYPE_XLAT:
				if (unlang_xlat_push(update_state, NULL, &update_state->rhs_result,
						     request, tmpl_xlat(map->rhs), false) < 0) {
					return UNLANG_ACTION_STOP_PROCESSING;
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
			FALL_THROUGH;

		case UNLANG_UPDATE_MAP_EXPANDED_RHS:
		{
			vp_list_mod_t *new_mod;
			/*
			 *	Concat the top level results together
			 */
			if (!fr_value_box_list_empty(&update_state->rhs_result) &&
			    (fr_value_box_list_concat_in_place(update_state,
			    				       fr_value_box_list_head(&update_state->rhs_result), &update_state->rhs_result, FR_TYPE_STRING,
			    				       FR_VALUE_BOX_LIST_FREE, true,
			    				       SIZE_MAX) < 0)) {
				RPEDEBUG("Failed concatenating RHS expansion results");
				goto error;
			}

			if (map_to_list_mod(update_state, &new_mod,
					    request, map,
					    &update_state->lhs_result, &update_state->rhs_result) < 0) goto error;
			if (new_mod) fr_dlist_insert_tail(&update_state->vlm_head, new_mod);

			fr_value_box_list_talloc_free(&update_state->rhs_result);
		}

		next:
			update_state->state = UNLANG_UPDATE_MAP_INIT;
			fr_value_box_list_talloc_free(&update_state->lhs_result);

			break;
		}
	}

	return list_mod_apply(p_result, request);
}


/** Execute an update block
 *
 * Update blocks execute in two phases, first there's an evaluation phase where
 * each input map is evaluated, outputting one or more modification maps. The modification
 * maps detail a change that should be made to a list in the current request.
 * The request is not modified during this phase.
 *
 * The second phase applies those modification maps to the current request.
 * This re-enables the atomic functionality of update blocks provided in v2.x.x.
 * If one map fails in the evaluation phase, no more maps are processed, and the current
 * result is discarded.
 */
static unlang_action_t unlang_update_state_init(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	unlang_map_t			*gext = unlang_group_to_map(g);
	unlang_frame_state_update_t	*update_state;

	/*
	 *	Initialise the frame state
	 */
	MEM(frame->state = update_state = talloc_zero_pooled_object(request->stack, unlang_frame_state_update_t,
								    (sizeof(map_t) +
								    (sizeof(tmpl_t) * 2) + 128),
								    g->num_children));	/* 128 is for string buffers */

	fr_dcursor_init(&update_state->maps, &gext->map.head);
	fr_value_box_list_init(&update_state->lhs_result);
	fr_value_box_list_init(&update_state->rhs_result);
	fr_dlist_init(&update_state->vlm_head, vp_list_mod_t, entry);

	/*
	 *	Call list_mod_create
	 */
	frame_repeat(frame, list_mod_create);
	return list_mod_create(p_result, request, frame);
}

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
		if (unlang_tmpl_push(map_proc_state, &map_proc_state->src_result,
				     request, inst->src, NULL) < 0) {
			return UNLANG_ACTION_STOP_PROCESSING;
		}
		return UNLANG_ACTION_PUSHED_CHILD;

	case TMPL_TYPE_XLAT:
		if (unlang_xlat_push(map_proc_state, NULL, &map_proc_state->src_result,
				     request, tmpl_xlat(inst->src), false) < 0) {
			return UNLANG_ACTION_STOP_PROCESSING;
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

static int edit_section_alloc(CONF_SECTION *parent, CONF_SECTION **child, char const *name1, fr_token_t op)
{
	CONF_SECTION *cs;

	cs = cf_section_alloc(parent, parent, name1, NULL);
	if (!cs) return -1;

	cf_section_add_name2_quote(cs, op);

	if (child) *child = cs;

	return 0;
}

static int edit_pair_alloc(CONF_SECTION *cs, CONF_PAIR *original, char const *attr, fr_token_t op, char const *value, fr_token_t list_op)
{
	CONF_PAIR *cp;
	fr_token_t rhs_quote;

	if (original) {
		rhs_quote = cf_pair_value_quote(original);
	} else {
		rhs_quote = T_BARE_WORD;
	}

	cp = cf_pair_alloc(cs, attr, value, op, T_BARE_WORD, rhs_quote);
	if (!cp) return -1;

	if (!original) return 0;

	cf_filename_set(cp, cf_filename(original));
	cf_lineno_set(cp, cf_lineno(original));

	if (fr_debug_lvl >= 3) {
		if (list_op == T_INVALID) {
			cf_log_err(original, "%s %s %s --> %s %s %s",
				   cf_pair_attr(original), fr_tokens[cf_pair_operator(original)], cf_pair_value(original),
				   attr, fr_tokens[op], value);
		} else {
			if (*attr == '&') attr++;
			cf_log_err(original, "%s %s %s --> %s %s { %s %s %s }",
				   cf_pair_attr(original), fr_tokens[cf_pair_operator(original)], cf_pair_value(original),
				   cf_section_name1(cs), fr_tokens[list_op], attr, fr_tokens[op], value);
		}
	} else if (fr_debug_lvl >= 2) {
		if (list_op == T_INVALID) {
			cf_log_err(original, "--> %s %s %s",
				   attr, fr_tokens[op], value);
		} else {
			cf_log_err(original, "--> %s %s { %s %s %s }",
				   cf_section_name1(cs), fr_tokens[list_op], attr, fr_tokens[op], value);
		}
	}

	return 0;
}

/*
 *	Convert "update" to "edit" using evil spells and sorcery.
 */
static unlang_t *compile_update_to_edit(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_SECTION *cs)
{
	char const		*name2 = cf_section_name2(cs);
	CONF_ITEM		*ci;
	CONF_SECTION		*group;
	unlang_group_t		*g;
	char			list_buffer[32];
	char			value_buffer[256];
	char			attr_buffer[256];
	char const		*list;

	g = unlang_generic_to_group(parent);

	/*
	 *	Wrap it all in a group, no matter what.  Because of
	 *	limitations in the cf_pair_alloc() API.
	 */
	group = cf_section_alloc(g->cs, g->cs, "group", NULL);
	if (!group) return NULL;

	(void) cf_item_remove(g->cs, group); /* was added at the end */
	cf_item_insert_after(g->cs, cs, group);

	/*
	 *	Hoist this out of the loop, and make sure it never has a '&' prefix.
	 */
	if (name2) {
		if (*name2 == '&') name2++;
		snprintf(list_buffer, sizeof(list_buffer), "%s", name2);
	} else {
		snprintf(list_buffer, sizeof(list_buffer), "%s", tmpl_list_name(unlang_ctx->rules->attr.list_def, "<INVALID>"));

	}

	/*
	 *	Loop over the entries, rewriting them.
	 */
	for (ci = cf_item_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(cs, ci)) {
		CONF_PAIR	*cp;
		CONF_SECTION	*child;
		int		rcode;
		fr_token_t	op;
		char const	*attr, *value, *end;

		if (cf_item_is_section(ci)) {
			cf_log_err(ci, "Cannot specify subsections for 'update'");
			return NULL;
		}

		if (!cf_item_is_pair(ci)) continue;

		cp = cf_item_to_pair(ci);

		attr = cf_pair_attr(cp);
		value = cf_pair_value(cp);
		op = cf_pair_operator(cp);

		fr_assert(attr);
		fr_assert(value);

		list = list_buffer;

		if (*attr == '&') attr++;

		end = strchr(attr, '.');
		if (!end) end = attr + strlen(attr);

		/*
		 *	Separate out the various possibilities for the "name", which could be a list, an
		 *	attribute name, or a list followed by an attribute name.
		 *
		 *	Note that even if we have "update request { ....}", the v3 parser allowed the contents
		 *	of the "update" section to still specify parent / lists.  Which makes parsing it all
		 *	annoying.
		 *
		 *	The good news is that all we care about is whether or not there's a parent / list ref.
		 *	We don't care what that ref is.
		 */
		{
			fr_dict_attr_t const *tmpl_list;

			/*
			 *	Allow for a "parent" or "outer" reference.  There may be multiple
			 *	"parent.parent", so we keep processing them until we get a list reference.
			 */
			if (fr_table_value_by_substr(tmpl_request_ref_table, attr, end - attr, REQUEST_UNKNOWN) != REQUEST_UNKNOWN) {

				/*
				 *	Catch one more case where the behavior is different.
				 *
				 *	&request += &config[*]
				 */
				if ((cf_pair_value_quote(cp) == T_BARE_WORD) && (*value == '&') &&
				    (strchr(value, '.') == NULL) && (strchr(value, '[') != NULL)) {
					char const *p = strchr(value, '[');

					cf_log_err(cp, "Cannot do array assignments for lists.  Just use '%s %s %.*s'",
						   list, fr_tokens[op], (int) (p - value), value);
					return NULL;
				}

				goto attr_is_list;

			/*
			 *	Doesn't have a parent ref, maybe it's a list ref?
			 */
			} else if (tmpl_attr_list_from_substr(&tmpl_list, &FR_SBUFF_IN(attr, (end - attr))) > 0) {
				char *p;

			attr_is_list:
				snprintf(attr_buffer, sizeof(attr_buffer), "%s", attr);
				list = attr_buffer;
				attr = NULL;

				p = strchr(attr_buffer, '.');
				if (p) {
					*(p++) = '\0';
					attr = p;
				}
			}
		}

		switch (op) {
			/*
			 *	FOO !* ANY
			 *
			 *	The RHS doesn't matter, so we ignore it.
			 */
		case T_OP_CMP_FALSE:
			if (!attr) {
				/*
				 *	Set list to empty value.
				 */
				rcode = edit_section_alloc(group, NULL, list, T_OP_SET);

			} else {
				if (strchr(attr, '[') == NULL) {
					snprintf(value_buffer, sizeof(value_buffer), "%s[*]", attr);
				} else {
					snprintf(value_buffer, sizeof(value_buffer), "%s", attr);
				}

				rcode = edit_pair_alloc(group, cp, list, T_OP_SUB_EQ, value_buffer, T_INVALID);
			}
			break;

		case T_OP_SET:
			/*
			 *	Must be a list-to-list operation
			 */
			if (!attr) {
			list_op:
				rcode = edit_pair_alloc(group, cp, list, op, value, T_INVALID);
				break;
			}
			goto pair_op;

		case T_OP_EQ:
			/*
			 *	Allow &list = "foo"
			 */
			if (!attr) {
				if (!value) {
					cf_log_err(cp, "Missing value");
					return NULL;
				}

				rcode = edit_pair_alloc(group, cp, list, op, value, T_INVALID);
				break;
			}

		pair_op:
			fr_assert(*attr != '&');
			if (snprintf(value_buffer, sizeof(value_buffer), "%s.%s", list, attr) < 0) {
				cf_log_err(cp, "RHS of update too long to convert to edit automatically");
				return NULL;
			}

			rcode = edit_pair_alloc(group, cp, value_buffer, op, value, T_INVALID);
			break;

		case T_OP_ADD_EQ:
		case T_OP_PREPEND:
			if (!attr) goto list_op;

			rcode = edit_section_alloc(group, &child, list, op);
			if (rcode < 0) break;

			rcode = edit_pair_alloc(child, cp, attr, T_OP_EQ, value, op);
			break;

			/*
			 *	Remove matching attributes
			 */
		case T_OP_SUB_EQ:
			op = T_OP_CMP_EQ;

		filter:
			if (!attr) {
				cf_log_err(cp, "Invalid operator for list assignment");
				return NULL;
			}

			rcode = edit_section_alloc(group, &child, list, T_OP_SUB_EQ);
			if (rcode < 0) break;

			if (strchr(attr, '[') != 0) {
				cf_log_err(cp, "Cannot do filtering with array indexes");
				return NULL;
			}

			rcode = edit_pair_alloc(child, cp, attr, op, value, T_OP_SUB_EQ);
			break;

			/*
			 *	Keep matching attributes, i.e. remove non-matching ones.
			 */
		case T_OP_CMP_EQ:
			op = T_OP_NE;
			goto filter;

		case T_OP_NE:
			op = T_OP_CMP_EQ;
			goto filter;

		case T_OP_LT:
			op = T_OP_GE;
			goto filter;

		case T_OP_LE:
			op = T_OP_GT;
			goto filter;

		case T_OP_GT:
			op = T_OP_LE;
			goto filter;

		case T_OP_GE:
			op = T_OP_LT;
			goto filter;

		default:
			cf_log_err(cp, "Unsupported operator - cannot auto-convert to edit section");
			return NULL;
		}

		if (rcode < 0) {
			cf_log_err(cp, "Failed converting entry");
			return NULL;
		}
	}

	return UNLANG_IGNORE;
}

static unlang_t *unlang_compile_update(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION 		*cs = cf_item_to_section(ci);
	int			rcode;

	unlang_group_t		*g;
	unlang_map_t	*gext;

	unlang_t		*c;
	char const		*name2 = cf_section_name2(cs);

	tmpl_rules_t		t_rules;

	if (main_config_migrate_option_get("forbid_update")) {
		cf_log_err(cs, "The use of 'update' sections is forbidden by the server configuration");
		return NULL;
	}

	/*
	 *	If we're migrating "update" sections to edit, then go
	 *	do that now.
	 */
	if (main_config_migrate_option_get("rewrite_update")) {
		return compile_update_to_edit(parent, unlang_ctx, cs);
	}

	/*
	 *	We allow unknown attributes here.
	 */
	t_rules = *(unlang_ctx->rules);
	t_rules.attr.allow_unknown = true;
	t_rules.attr.allow_wildcard = true;
	RULES_VERIFY(&t_rules);

	g = unlang_group_allocate(parent, cs, UNLANG_TYPE_UPDATE);
	if (!g) return NULL;

	gext = unlang_group_to_map(g);

	/*
	 *	This looks at cs->name2 to determine which list to update
	 */
	map_list_init(&gext->map);
	rcode = map_afrom_cs(gext, &gext->map, cs, &t_rules, &t_rules, unlang_fixup_update, NULL, 128);
	if (rcode < 0) return NULL; /* message already printed */
	if (map_list_empty(&gext->map)) {
		cf_log_err(cs, "'update' sections cannot be empty");
	error:
		talloc_free(g);
		return NULL;
	}

	c = unlang_group_to_generic(g);
	if (name2) {
		c->name = name2;
		c->debug_name = talloc_typed_asprintf(c, "update %s", name2);
	} else {
		c->name = "update";
		c->debug_name = c->name;
	}

	if (!pass2_fixup_update(g, unlang_ctx->rules)) goto error;

	unlang_compile_action_defaults(c, unlang_ctx);

	return c;
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

	unlang_compile_action_defaults(c, unlang_ctx);

	return c;
}


void unlang_map_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "update",
			.type = UNLANG_TYPE_UPDATE,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

			.compile = unlang_compile_update,
			.interpret = unlang_update_state_init,

			.unlang_size = sizeof(unlang_map_t),
			.unlang_name = "unlang_map_t",
		});

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
