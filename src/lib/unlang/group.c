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
 * @file unlang/group.c
 * @brief Unlang "group" keyword evaluation.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/server/rcode.h>
#include "unlang_priv.h"
#include "group_priv.h"

unlang_action_t unlang_group(UNUSED unlang_result_t *p_result, request_t *request, UNUSED unlang_stack_frame_t *frame)
{
	return unlang_interpret_push_children(NULL, request, RLM_MODULE_NOT_SET, UNLANG_NEXT_SIBLING);
}

static unlang_action_t unlang_policy(unlang_result_t *result, request_t *request, unlang_stack_frame_t *frame)
{
	return unlang_group(result, request, frame);
}


static unlang_t *unlang_compile_group(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	if (!cf_item_next(ci, NULL)) return UNLANG_IGNORE;

	return unlang_compile_section(parent, unlang_ctx, cf_item_to_section(ci), UNLANG_TYPE_GROUP);
}

static unlang_t *unlang_compile_redundant(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION			*cs = cf_item_to_section(ci);
	unlang_t			*c;

	if (!cf_item_next(cs, NULL)) return UNLANG_IGNORE;

	if (!unlang_compile_limit_subsection(cs, cf_section_name1(cs))) {
		return NULL;
	}

	c = unlang_compile_section(parent, unlang_ctx, cs, UNLANG_TYPE_REDUNDANT);
	if (!c) return NULL;

	/*
	 *	We no longer care if "redundant" sections have a name.  If they do, it's ignored.
	 */

	return c;
}


void unlang_group_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "group",
			.type = UNLANG_TYPE_GROUP,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

			.compile = unlang_compile_group,
			.interpret = unlang_group,

			.unlang_size = sizeof(unlang_group_t),
			.unlang_name = "unlang_group_t",
		});

	unlang_register(&(unlang_op_t){
			.name = "redundant",
			.type = UNLANG_TYPE_REDUNDANT,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES,

			.compile = unlang_compile_redundant,
			.interpret = unlang_group,

			.unlang_size = sizeof(unlang_group_t),
			.unlang_name = "unlang_group_t",
		});

	unlang_register(&(unlang_op_t){
			.name = "policy",
			.type = UNLANG_TYPE_POLICY,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES | UNLANG_OP_FLAG_RETURN_POINT | UNLANG_OP_FLAG_INTERNAL,

			.interpret = unlang_policy,

			.unlang_size = sizeof(unlang_group_t),
			.unlang_name = "unlang_group_t",	
		});
}
