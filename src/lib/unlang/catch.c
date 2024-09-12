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
 * @file unlang/catch.c
 * @brief Unlang "catch" keyword evaluation.
 *
 * @copyright 2023 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include "unlang_priv.h"
#include "catch_priv.h"

static unlang_action_t cleanup(unlang_stack_frame_t *frame, unlang_t *unlang)
{

	/*
	 *	Clean up this frame now, so that stats, etc. will be
	 *	processed using the correct frame.
	 */
	frame_cleanup(frame);

	/*
	 *	frame_next() will call cleanup *before* resetting the frame->instruction.
	 *	but since the instruction is NULL, no duplicate cleanups will happen.
	 *
	 *	frame_next() will then set frame->instruction = frame->next, and everything will be OK.
	 */
	frame->instruction = NULL;
	frame->next = unlang;
	return UNLANG_ACTION_EXECUTE_NEXT;
}

static unlang_action_t catch_skip_to_next(UNUSED rlm_rcode_t *p_result, UNUSED request_t *request, unlang_stack_frame_t *frame)
{
	unlang_t		*unlang;

	fr_assert(frame->instruction->type == UNLANG_TYPE_CATCH);

	for (unlang = frame->instruction->next;
	     unlang != NULL;
	     unlang = unlang->next) {
		if (unlang->type == UNLANG_TYPE_CATCH) continue;

		break;
	}

	return cleanup(frame, unlang);
}

static unlang_action_t unlang_catch(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
#ifndef NDEBUG
	unlang_catch_t const *c = unlang_generic_to_catch(frame->instruction);

	fr_assert(c->catching[*p_result]);
#endif

	/*
	 *	Skip over any "catch" statementa after this one.
	 */
	frame_repeat(frame, catch_skip_to_next);

	return unlang_interpret_push_children(p_result, request, frame->result, UNLANG_NEXT_SIBLING);
}


/** Skip ahead to a particular "catch" instruction.
 *
 */
unlang_action_t unlang_interpret_skip_to_catch(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_t		*unlang;

	fr_assert(frame->instruction->type == UNLANG_TYPE_TRY);

	for (unlang = frame->instruction->next;
	     unlang != NULL;
	     unlang = unlang->next) {
		unlang_catch_t const *c;

		if (unlang->type != UNLANG_TYPE_CATCH) {
			RWDEBUG2("Failed to 'catch' error %s",
				fr_table_str_by_value(mod_rcode_table, *p_result, "<invalid>"));
			frame->next = unlang;
			return UNLANG_ACTION_CALCULATE_RESULT;
		}

		c = unlang_generic_to_catch(unlang);
		if (c->catching[*p_result]) break;
	}

	fr_assert(unlang != NULL);

	return cleanup(frame, unlang);
}

void unlang_catch_init(void)
{
	unlang_register(UNLANG_TYPE_CATCH,
			   &(unlang_op_t){
				.name = "catch",
				.interpret = unlang_catch,
				.debug_braces = true
			   });
}
