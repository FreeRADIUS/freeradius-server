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
 * @file main/map_unlang.c
 *
 * @ingroup AVP
 *
 * @copyright 2018 The FreeRADIUS server project
 * @copyright 2018 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/map.h>
#include <freeradius-devel/xlat.h>
#include "unlang_priv.h"

typedef enum {
	UNLANG_UPDATE_MAP_INIT = 0,				//!< Start processing a map.
	UNLANG_UPDATE_MAP_EXPANDED_LHS,				//!< Expand the LHS xlat or exec (if needed).
	UNLANG_UPDATE_MAP_EXPANDED_RHS				//!< Expand the RHS xlat or exec (if needed).
} unlang_update_state_t;

/** State of an update block
 *
 */
typedef struct {
	fr_cursor_t		maps;				//!< Cursor of maps to evaluate.

	vp_list_mod_t		**vlm_next;
	vp_list_mod_t		*vlm_head;			//!< First VP List Mod.

	fr_value_box_t		*lhs_result;			//!< Result of expanding the LHS
	fr_value_box_t		*rhs_result;			//!< Result of expanding the RHS.

	unlang_update_state_t	state;				//!< What we're currently doing.
} unlang_frame_state_update_t;

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
static unlang_action_t unlang_update(REQUEST *request, rlm_rcode_t *presult, int *priority)
{
	unlang_stack_t			*stack = request->stack;
	unlang_stack_frame_t		*frame = &stack->frame[stack->depth];
	unlang_t			*instruction = frame->instruction;
	unlang_group_t			*g = unlang_generic_to_group(instruction);
	unlang_frame_state_update_t	*update = frame->state;
	vp_map_t			*map;

	/*
	 *	Initialise the frame state
	 */
	if (!frame->repeat) {
#ifdef HAVE_TALLOC_POOLED_OBJECT
		int cnt = 0;
		for (map = g->map; map; map = map->next) cnt++;

		MEM(frame->state = update = talloc_pooled_object(stack, unlang_frame_State_update_t,
								 (sizeof(vp_map_t) + (sizeof(vp_tmpl_t) * 2) + 128),
								 cnt));	/* 128 is for string buffers */

#else
		MEM(frame->state = update = talloc_zero(stack, unlang_frame_state_update_t));
#endif

		fr_cursor_init(&update->maps, &g->map);
		update->vlm_next = &update->vlm_head;
		frame->repeat = true;
	}

	/*
	 *	Iterate over the maps producing a set of modifications to apply.
	 */
	map = fr_cursor_current(&update->maps);
	do {
		switch (update->state) {
		case UNLANG_UPDATE_MAP_INIT:
			update->state = UNLANG_UPDATE_MAP_EXPANDED_LHS;

			rad_assert(!update->lhs_result);	/* Should have been consumed */
			rad_assert(!update->rhs_result);	/* Should have been consumed */

			switch (map->lhs->type) {
			default:
				break;

			case TMPL_TYPE_XLAT_STRUCT:
				xlat_unlang_push(update, &update->lhs_result, request, map->lhs->tmpl_xlat, false);
				return UNLANG_ACTION_PUSHED_CHILD;

			case TMPL_TYPE_REGEX:
			case TMPL_TYPE_REGEX_STRUCT:
			case TMPL_TYPE_XLAT:
				rad_assert(0);
			error:
				talloc_list_free(&update->lhs_result);
				talloc_list_free(&update->rhs_result);

				*presult = RLM_MODULE_FAIL;
				*priority = instruction->actions[*presult];
				return UNLANG_ACTION_CALCULATE_RESULT;
			}
			/* FALL-THROUGH */

		case UNLANG_UPDATE_MAP_EXPANDED_LHS:
			update->state = UNLANG_UPDATE_MAP_EXPANDED_RHS;

			/*
			 *	Concat the top level results together
			 */
			if (update->lhs_result &&
			    (fr_value_box_list_concat(update, update->lhs_result, &update->lhs_result,
			    			      FR_TYPE_STRING, true) < 0)) {
				RPEDEBUG("Failed concatenating LHS expansion results");
				goto error;
			}

			switch (map->rhs->type) {
			default:
				break;

			case TMPL_TYPE_XLAT_STRUCT:
				xlat_unlang_push(update, &update->rhs_result, request, map->rhs->tmpl_xlat, false);
				return UNLANG_ACTION_PUSHED_CHILD;

			case TMPL_TYPE_REGEX:
			case TMPL_TYPE_REGEX_STRUCT:
			case TMPL_TYPE_XLAT:
				rad_assert(0);
				goto error;
			}
			/* FALL-THROUGH */

		case UNLANG_UPDATE_MAP_EXPANDED_RHS:
			update->state = UNLANG_UPDATE_MAP_INIT;

			/*
			 *	Concat the top level results together
			 */
			if (update->rhs_result &&
			    (fr_value_box_list_concat(update, update->rhs_result, &update->rhs_result,
			    			      FR_TYPE_STRING, true) < 0)) {
				RPEDEBUG("Failed concatenating RHS expansion results");
				goto error;
			}

			if (map_to_list_mod(update, update->vlm_next,
					    request, map, &update->lhs_result, &update->rhs_result) < 0) goto error;

			talloc_list_free(&update->lhs_result);
			talloc_list_free(&update->rhs_result);

			/*
			 *	Wind to the end...
			 */
			while (*update->vlm_next) update->vlm_next = &(*(update->vlm_next))->next;
			break;
		}
	} while ((map = fr_cursor_next(&update->maps)));

	/*
	 *	No modifications...
	 */
	if (!update->vlm_head) {
		RDEBUG2("Nothing to update");
		goto done;
	}

	/*
	 *	Apply the list of modifications.  This should not fail
	 *	except on memory allocation error.
	 */
	{
		vp_list_mod_t const *vlm;

		for (vlm = update->vlm_head;
		     vlm;
		     vlm = vlm->next) {
			int ret;

			ret = map_list_mod_apply(request, vlm);
		     	if (!fr_cond_assert(ret == 0)) goto error;
		}

	}
done:
	*presult = RLM_MODULE_NOOP;
	*priority = instruction->actions[*presult];

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t unlang_map(REQUEST *request,
				  rlm_rcode_t *presult, UNUSED int *priority)
{
	unlang_stack_t		*stack = request->stack;
	unlang_stack_frame_t	*frame = &stack->frame[stack->depth];
	unlang_t		*instruction = frame->instruction;
	unlang_group_t		*g = unlang_generic_to_group(instruction);

	*presult = map_proc(request, g->proc_inst);

	return *presult == RLM_MODULE_YIELD ? UNLANG_ACTION_YIELD : UNLANG_ACTION_CALCULATE_RESULT;
}

void map_unlang_init(void)
{
	unlang_op_register(UNLANG_TYPE_UPDATE,
			   &(unlang_op_t){
				.name = "update",
				.func = unlang_update,
				.debug_braces = true
			   });

	unlang_op_register(UNLANG_TYPE_MAP,
			   &(unlang_op_t){
				.name = "map",
				.func = unlang_map,
			   });
}
