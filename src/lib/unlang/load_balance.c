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
 * @file unlang/load_balance.c
 * @brief Implementation of the unlang "load-balance" keyword.
 *
 * @copyright 2006-2019 The FreeRADIUS server project
 */
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/rand.h>

#include "unlang_priv.h"
#include "load_balance_priv.h"

#define unlang_redundant_load_balance unlang_load_balance

static unlang_action_t unlang_load_balance_next(unlang_result_t *p_result, request_t *request,
						unlang_stack_frame_t *frame)
{
	unlang_frame_state_redundant_t	*redundant = talloc_get_type_abort(frame->state, unlang_frame_state_redundant_t);
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);

	/*
	 *	If the current child wasn't set, we just start there.  Otherwise we loop around to the next
	 *	child.
	 */
	if (!redundant->child) {
		redundant->child = redundant->start;
		goto push;
	}

	/*
	 *	We are in a resumed frame.  Check if running the child resulted in a failure rcode which
	 *	requires us to keep going.  If not, return to the caller.
	 */
	switch (redundant->result.rcode) {
	case RLM_MODULE_FAIL:
	case RLM_MODULE_TIMEOUT:
	case RLM_MODULE_NOT_SET:
		break;

	default:
		if (p_result) {
			p_result->priority = MOD_PRIORITY_MIN;
			p_result->rcode = redundant->result.rcode;
		}

		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	/*
	 *	We finished the previous child, and it failed.  Go to the next one.  If we fall off of the
	 *	end, loop around to the next one.
	 */
	redundant->child = unlang_list_next(&g->children, redundant->child);
	if (!redundant->child) redundant->child = unlang_list_head(&g->children);

	/*
	 *	We looped back to the start.  Return whatever results we had from the last child.
	 */
	if (redundant->child == redundant->start) {
		if (p_result) *p_result = redundant->result;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

push:
	/*
	 *	The child begins has no result set.  Resetting the results ensures that the failed code from
	 *	one child doesn't affect the next child that we run.
	 */
	redundant->result = UNLANG_RESULT_NOT_SET;
	repeatable_set(frame);

	/*
	 *	Push the child. and run it.
	 */
	if (unlang_interpret_push(&redundant->result, request, redundant->child,
				  FRAME_CONF(RLM_MODULE_NOT_SET, UNLANG_SUB_FRAME), UNLANG_NEXT_STOP) < 0) {
		RETURN_UNLANG_ACTION_FATAL;
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t unlang_redundant(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_redundant_t	*redundant = talloc_get_type_abort(frame->state,
									   unlang_frame_state_redundant_t);
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);

	/*
	 *	Start at the first child, and then continue from there.
	 */
	redundant->start = unlang_list_head(&g->children);

	frame->process = unlang_load_balance_next;
	return unlang_load_balance_next(p_result, request, frame);
}

static unlang_action_t unlang_load_balance(unlang_result_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_redundant_t	*redundant;
	unlang_group_t			*g = unlang_generic_to_group(frame->instruction);
	unlang_load_balance_t		*gext = NULL;

	uint32_t			count = 0;

#ifdef STATIC_ANALYZER
	if (!g || unlang_list_empty(&g->children)) return UNLANG_ACTION_FAIL;
#else
	fr_assert(g != NULL);
	fr_assert(!unlang_list_empty(&g->children));
#endif

	gext = unlang_group_to_load_balance(g);

	redundant = talloc_get_type_abort(frame->state, unlang_frame_state_redundant_t);

	if (gext && gext->vpt) {
		uint32_t hash, start;
		ssize_t slen;
		char buffer[1024];

		/*
		 *	Hash the attribute value to select the statement which will be used.
		 */
		if (tmpl_is_attr(gext->vpt)) {
			fr_pair_t *vp;

			slen = tmpl_find_vp(&vp, request, gext->vpt);
			if (slen < 0) {
				REDEBUG("Failed finding attribute %s - choosing random statement", gext->vpt->name);
				goto randomly_choose;
			}

			fr_assert(fr_type_is_leaf(vp->vp_type));

			start = fr_value_box_hash(&vp->data) % unlang_list_num_elements(&g->children);

		} else {
			uint8_t *octets = NULL;

			/*
			 *	Get the raw data, and then hash the data.
			 */
			slen = tmpl_expand(&octets, buffer, sizeof(buffer), request, gext->vpt);
			if (slen <= 0) {
				REDEBUG("Failed expanding %s - choosing random statement", gext->vpt->name);
				goto randomly_choose;
			}

			hash = fr_hash(octets, slen);

			start = hash % unlang_list_num_elements(&g->children);
		}

		RDEBUG3("load-balance starting at child %d", (int) start);

		count = 0;
		unlang_list_foreach(&g->children, child) {
			if (count == start) {
				redundant->start = child;
				break;
			}

			count++;
		}
		fr_assert(redundant->start != NULL);

	} else {
	randomly_choose:
		count = 1;

		/*
		 *	Choose a child at random.
		 *
		 *	@todo - leverage the "power of 2", as per
		 *      lib/io/network.c.  This is good enough for
		 *      most purposes.  However, in order to do this,
		 *      we need to track active callers across
		 *      *either* multiple modules in one thread, *or*
		 *      across multiple threads.
		 *
		 *	We don't have thread-specific instance data
		 *	for this load-balance section.  So for now,
		 *	just pick a random child.
		 */
		unlang_list_foreach(&g->children, child) {
			if ((count * (fr_rand() & 0xffffff)) < (uint32_t) 0x1000000) {
				redundant->start = child;
			}
			count++;
		}

		fr_assert(redundant->start != NULL);

	}

	fr_assert(redundant->start != NULL);

	/*
	 *	Plain "load-balance".  Just do one child, and return the result directly bacl to the caller.
	 */
	if (frame->instruction->type == UNLANG_TYPE_LOAD_BALANCE) {
		if (unlang_interpret_push(p_result, request, redundant->start,
					  FRAME_CONF(RLM_MODULE_NOT_SET, UNLANG_SUB_FRAME), UNLANG_NEXT_STOP) < 0) {
			RETURN_UNLANG_ACTION_FATAL;
		}
		return UNLANG_ACTION_PUSHED_CHILD;
	}

	frame->process = unlang_load_balance_next;
	return unlang_load_balance_next(p_result, request, frame);
}


static unlang_t *compile_load_balance_subsection(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_SECTION *cs,
						 unlang_type_t type)
{
	char const			*name2;
	fr_token_t			quote;
	unlang_t			*c;
	unlang_group_t			*g;
	unlang_load_balance_t		*gext;

	tmpl_rules_t			t_rules;

	if (!cf_item_next(cs, NULL)) return UNLANG_IGNORE;

	/*
	 *	We allow unknown attributes here.
	 */
	t_rules = *(unlang_ctx->rules);
	t_rules.attr.allow_unknown = true;
	RULES_VERIFY(&t_rules);

	if (!unlang_compile_limit_subsection(cs, cf_section_name1(cs))) return NULL;

	c = unlang_compile_section(parent, unlang_ctx, cs, type);
	if (!c) return NULL;

	g = unlang_generic_to_group(c);

	/*
	 *	Inside of the "modules" section, it's a virtual module.  The key is the third argument, and
	 *	the "name2" is the module name, which we ignore here.
	 */
	name2 = cf_section_name2(cs);
	quote = cf_section_name2_quote(cs);

	if (name2) {
		if (strcmp(cf_section_name1(cf_item_to_section(cf_parent(cs))), "modules") == 0) {
			char const *key;

			/*
			 *	Key is optional.
			 */
			key = cf_section_argv(cs, 0);
			if (key) {
				name2 = key;
				quote = cf_section_argv_quote(cs, 0);
			} else {
				name2 = NULL; /* no key */
			}
		}
	}

	/*
	 *	Allow for keyed load-balance / redundant-load-balance sections.
	 */
	if (name2) {
		ssize_t slen;

		/*
		 *	Create the template.  All attributes and xlats are
		 *	defined by now.
		 */
		gext = unlang_group_to_load_balance(g);
		slen = tmpl_afrom_substr(gext, &gext->vpt,
					 &FR_SBUFF_IN_STR(name2),
					 quote,
					 NULL,
					 &t_rules);
		if (!gext->vpt) {
			cf_canonicalize_error(cs, slen, "Failed parsing argument", name2);
			talloc_free(g);
			return NULL;
		}

		fr_assert(gext->vpt != NULL);

		/*
		 *	Fixup the templates
		 */
		if (!pass2_fixup_tmpl(g, &gext->vpt, cf_section_to_item(cs), unlang_ctx->rules->attr.dict_def)) {
			talloc_free(g);
			return NULL;
		}

		ERROR("SHIT %s %d", gext->vpt->name, gext->vpt->type);

		switch (gext->vpt->type) {
		default:
			cf_log_err(cs, "Invalid type in '%s': data will not result in a load-balance key", name2);
			talloc_free(g);
			return NULL;

			/*
			 *	Allow only these ones.
			 */
		case TMPL_TYPE_ATTR:
			if (!fr_type_is_leaf(tmpl_attr_tail_da(gext->vpt)->type)) {
				cf_log_err(cs, "Invalid attribute reference in '%s': load-balancing can only be done on 'leaf' data types", name2);
				talloc_free(g);
				return NULL;
			}
			break;

		case TMPL_TYPE_XLAT:
		case TMPL_TYPE_EXEC:
			break;
		}
	}

	return c;
}

static unlang_t *unlang_compile_load_balance(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	return compile_load_balance_subsection(parent, unlang_ctx, cf_item_to_section(ci), UNLANG_TYPE_LOAD_BALANCE);
}

static unlang_t *unlang_compile_redundant_load_balance(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	return compile_load_balance_subsection(parent, unlang_ctx, cf_item_to_section(ci), UNLANG_TYPE_REDUNDANT_LOAD_BALANCE);
}


static unlang_t *unlang_compile_redundant(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_ITEM const *ci)
{
	CONF_SECTION			*cs = cf_item_to_section(ci);

	if (!cf_item_next(cs, NULL)) return UNLANG_IGNORE;

	if (!unlang_compile_limit_subsection(cs, cf_section_name1(cs))) {
		return NULL;
	}

	/*
	 *	"redundant foo" is allowed only inside of a "modules" section, where the name is the instance
	 *	name.
	 *
	 *	@todo - static versus dynamic modules?
	 */

	if (cf_section_name2(cs) &&
	    (strcmp(cf_section_name1(cf_item_to_section(cf_parent(cs))), "modules") != 0)) {
		cf_log_err(cs, "Cannot specify a key for 'redundant'");
		return NULL;
	}

	return unlang_compile_section(parent, unlang_ctx, cs, UNLANG_TYPE_REDUNDANT);
}


void unlang_load_balance_init(void)
{
	unlang_register(&(unlang_op_t){
			.name = "load-balance",
			.type = UNLANG_TYPE_LOAD_BALANCE,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES | UNLANG_OP_FLAG_RCODE_SET,

			.compile = unlang_compile_load_balance,
			.interpret = unlang_load_balance,

			.unlang_size = sizeof(unlang_load_balance_t),
			.unlang_name = "unlang_load_balance_t",

			.frame_state_size = sizeof(unlang_frame_state_redundant_t),
			.frame_state_type = "unlang_frame_state_redundant_t",
		});

	unlang_register(&(unlang_op_t){
			.name = "redundant-load-balance",
			.type = UNLANG_TYPE_REDUNDANT_LOAD_BALANCE,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES | UNLANG_OP_FLAG_RCODE_SET,

			.compile = unlang_compile_redundant_load_balance,
			.interpret = unlang_redundant_load_balance,

			.unlang_size = sizeof(unlang_load_balance_t),
			.unlang_name = "unlang_load_balance_t",

			.frame_state_size = sizeof(unlang_frame_state_redundant_t),
			.frame_state_type = "unlang_frame_state_redundant_t",
		});

	unlang_register(&(unlang_op_t){
			.name = "redundant",
			.type = UNLANG_TYPE_REDUNDANT,
			.flag = UNLANG_OP_FLAG_DEBUG_BRACES | UNLANG_OP_FLAG_RCODE_SET,

			.compile = unlang_compile_redundant,
			.interpret = unlang_redundant,

			.unlang_size = sizeof(unlang_group_t),
			.unlang_name = "unlang_group_t",

			.frame_state_size = sizeof(unlang_frame_state_redundant_t),
			.frame_state_type = "unlang_frame_state_redundant_t",
		});

}
