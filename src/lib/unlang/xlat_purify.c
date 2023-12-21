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
 * @file xlat_purify.c
 * @brief Purification functions for xlats
 *
 * @copyright 2022 The FreeRADIUS server project
 * @copyright 2022 Network RADIUS SAS (legal@networkradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/unlang/xlat_priv.h>
#include <freeradius-devel/util/calc.h>
#include <freeradius-devel/util/dict.h>

static void xlat_value_list_to_xlat(xlat_exp_head_t *head, fr_value_box_list_t *list)
{
	fr_value_box_t *box;
	xlat_exp_t *node;

	while ((box = fr_value_box_list_pop_head(list)) != NULL) {
		MEM(node = xlat_exp_alloc(head, XLAT_BOX, NULL, 0));
		fr_value_box_copy(node, &node->data, box);

		if (node->data.type == FR_TYPE_STRING) {
			node->quote = T_DOUBLE_QUOTED_STRING;
			xlat_exp_set_name_buffer_shallow(node, node->data.vb_strvalue);
		} else {
			char *name;

			node->quote = T_BARE_WORD;
			MEM(fr_value_box_aprint(node, &name, box, NULL) >= 0);
			xlat_exp_set_name_buffer_shallow(node, name);
		}
		talloc_free(box);

		xlat_exp_insert_tail(head, node);
	}
}


int xlat_purify_list(xlat_exp_head_t *head, request_t *request)
{
	int rcode;
	bool success;
	fr_value_box_list_t list;
	xlat_flags_t our_flags;

	if (!head->flags.can_purify) return 0;

	/*
	 *	We can't purify things which need resolving,
	 */
	if (head->flags.needs_resolving) return -1;

	our_flags = head->flags;
	our_flags.pure = true;					/* we flip this if the children are not pure */

	xlat_exp_foreach(head, node) {
		if (!node->flags.can_purify) continue;

		switch (node->type) {
		case XLAT_TMPL:
			if (tmpl_is_xlat(node->vpt)) {
				xlat_exp_head_t *child = tmpl_xlat(node->vpt);

				rcode = xlat_purify_list(child, request);
				if (rcode < 0) return rcode;

				node->flags = child->flags;
				break;
			}
			FALL_THROUGH;

		default:
			fr_strerror_printf("Internal error - cannot purify xlat");
			return -1;

		case XLAT_GROUP:
			rcode = xlat_purify_list(node->group, request);
			if (rcode < 0) return rcode;

			node->flags = node->group->flags;
			break;

		case XLAT_FUNC:
			/*
			 *	If the node is not pure, then maybe there's a callback to purify it, OR maybe
			 *	we can purify the function arguments.
			 */
			if (!node->flags.pure) {
				if (node->call.func->purify) {
					fr_dict_t const *dict = request->dict;

					/*
					 *	Swap in the node specific dictionary.
					 *
					 *	The previous code stored the dictionary in the xlat_exp_head_t,
					 *	and whilst this wasn't wrong, it was duplicative.
					 *
					 *	This allows future code to create inline definitions of local
					 *	attributes, and have them work correctly, as more deeply nested
					 *	expressions would swap in the correct dictionary.
					 */
					request->dict = node->call.dict;
					if (node->call.func->purify(node, node->call.inst->data, request) < 0) return -1;
					request->dict = dict;
				} else {
					if (xlat_purify_list(node->call.args, request) < 0) return -1;
				}

				/*
				 *	It may have been purified into an XLAT_BOX.  But if not, ensure that
				 *	the flags are all correct.
				 */
				if (node->type == XLAT_FUNC) {
					node->flags = node->call.func->flags;
					xlat_exp_foreach(node->call.args, arg) {
						xlat_flags_merge(&node->flags, &arg->flags);
					}
				}
				break;
			}

			/*
			 *	The node is entirely pure, we don't worry about any callbacks, we just
			 *	evaluate the entire thing to purify it.
			 */
			fr_assert(node->flags.pure);
			fr_value_box_list_init(&list);
			success = false;
			if (unlang_xlat_push_node(head, &success, &list, request, node) < 0) {
				return -1;
			}

			/*
			 *	Hope to god it doesn't yield. :)
			 */

			(void) unlang_interpret_synchronous(NULL, request);
			if (!success) return -1;

			/*
			 *	The function call becomes a GROUP of boxes
			 */
			xlat_instance_unregister_func(node);
			xlat_exp_set_type(node, XLAT_GROUP);	/* Frees the argument list */

			xlat_value_list_to_xlat(node->group, &list);
			node->flags = node->group->flags;
			break;
		}

		node->flags.can_purify = false;
		xlat_flags_merge(&our_flags, &node->flags);
	}

	/*
	 *	Let's not call xlat_purify() repeatedly, so we clear the flag.
	 *
	 *	@todo - if all of the children of "head" are "pure", then at the end of the purification
	 *	process, there should only be one child, of type XLAT_BOX.
	 */
	our_flags.can_purify = false;
	head->flags = our_flags;

	return 0;
}

/**  Purify an xlat
 *
 *  @param head		the xlat to be purified
 *  @param intp		the interpreter to use.
 *
 */
int xlat_purify(xlat_exp_head_t *head, unlang_interpret_t *intp)
{
	int rcode;
	request_t *request;

	if (!head->flags.can_purify) return 0;

	request = request_alloc_internal(NULL, (&(request_init_args_t){ .namespace = fr_dict_internal() }));
	if (!request) return -1;

	if (intp) unlang_interpret_set(request, intp);

	rcode = xlat_purify_list(head, request);
	talloc_free(request);

	return rcode;
}

static fr_value_box_t *xlat_value_box(xlat_exp_t *node)
{
#ifdef STATIC_ANALYZER
	if (!node) return NULL;
#endif

	if (node->type == XLAT_BOX) {
		return &node->data;

	} else if ((node->type == XLAT_TMPL) && tmpl_is_data(node->vpt)) {
		return tmpl_value(node->vpt);
	}

	return NULL;
}


static bool is_truthy(xlat_exp_t *node, bool *out)
{
	fr_value_box_t const *box;

	box = xlat_value_box(node);
	if (!box) {
		*out = false;
		return false;
	}

	*out = fr_value_box_is_truthy(box);
	return true;
}

/*
 *	Do some optimizations.
 *
 */
static xlat_exp_t *peephole_optimize_lor(xlat_exp_t *lhs,  xlat_exp_t *rhs)
{
	bool value;

	/*
	 *	LHS isn't truthy, we can't do anything.  If the LHS
	 *	passes, we return the value of the LHS.
	 *
	 *	FOO || ... --> FOO || ...
	 */
	if (!is_truthy(lhs, &value)) {
		/*
		 *	FOO || 0 --> FOO much of the time
		 *	FOO || 1 --> FOO much of the time
		 */
		if (!is_truthy(rhs, &value)) return NULL;

		/*
		 *	BOOL || 1 --> 1
		 *
		 *	Because if the LHS is 1, then we return the LHS (1)
		 *	On the other hand, it the LHS is 0, then we return
		 *	the RHS, which is also 1.
		 *
		 *	But we can't do
		 *
		 *	<type> || 1 --> 1
		 */
		if (value && (lhs->type == XLAT_FUNC) && (lhs->call.func->return_type == FR_TYPE_BOOL)) {
			talloc_free(lhs);
			return rhs;
		}

		return NULL;
	}

	/*
	 *	1 || FOO   --> 1
	 *	0 || FOO   --> FOO
	 */
	if (value) {
		talloc_free(rhs);
		return lhs;
	}

	talloc_free(lhs);
	return rhs;
}


/*
 *	Do some optimizations.
 *
 */
static xlat_exp_t *peephole_optimize_land(xlat_exp_t *lhs, xlat_exp_t *rhs)
{
	bool value;

	/*
	 *	LHS isn't truthy
	 *
	 *	FOO && ... --> FOO && ...
	 */
	if (!is_truthy(lhs, &value)) {
		/*
		 *	FOO && 0 --> 0
		 *	FOO && 1 --> FOO
		 */
		if (!is_truthy(rhs, &value)) return NULL;

		if (!value) {
			talloc_free(lhs);
			return rhs;
		}

		talloc_free(rhs);
		return lhs;
	}

	/*
	 *	0 && FOO   --> 0
	 *	1 && FOO   --> FOO
	 */
	if (!value) {
		talloc_free(rhs);
		return lhs;
	}

	talloc_free(lhs);
	return rhs;
}

/*
 *	Do peephole optimizations.
 */
static int binary_peephole_optimize(TALLOC_CTX *ctx, xlat_exp_t **out, xlat_exp_t *lhs, fr_token_t op, xlat_exp_t *rhs)
{
	fr_value_box_t *lhs_box, *rhs_box;
	fr_value_box_t box;
	xlat_exp_t *node;
	char *name;

#if 0
	/*
	 *	@todo - more peephole optimizations here.  We can't enable this code as yet, because of
	 *	upcasting rules (e.g. calc.c) where comparisons between IP prefixes and IP addresses (or
	 *	v4/v6) are upcast, and then the values compared.
	 *
	 *	We should probably expose some of the upcast functionality in calc.c so that this function can
	 *	use it.
	 */

	/*
	 *	Attribute op value.
	 */
	if ((lhs->type == XLAT_TMPL) && tmpl_is_attr(lhs->vpt) &&
	    (rhs->type == XLAT_TMPL) && (tmpl_is_data_unresolved(rhs->vpt) || tmpl_is_data(rhs->vpt))) {
		fr_type_t dst_type;
		fr_dict_attr_t const *da;

	resolve:
		dst_type = tmpl_rules_cast(rhs->vpt);
		da = tmpl_attr_tail_da(lhs->vpt);

		/*
		 *	Cast to the final type.  If there are two different casts, we ignore the one for the
		 *	data.
		 */
		if (fr_type_is_null(dst_type)) {
			dst_type = tmpl_rules_cast(lhs->vpt);
			if (fr_type_is_null(dst_type)) dst_type = da->type;
		}

		if (tmpl_cast_in_place(rhs->vpt, dst_type, da) < 0) return -1;

		rhs->flags.needs_resolving = false;
		return 0;
	}

	/*
	 *	value op attribute
	 *
	 *	We just swap LHS and RHS without caring about the operator, because we don't use the
	 *	operator, and the caller has no idea that we swapped the pointers..
	 */
	if ((rhs->type == XLAT_TMPL) && tmpl_is_attr(rhs->vpt) &&
	    (lhs->type == XLAT_TMPL) && (tmpl_is_data_unresolved(lhs->vpt) || tmpl_is_data(lhs->vpt))) {
		xlat_exp_t *tmp = lhs;
		lhs = rhs;
		rhs = tmp;
		goto resolve;
	}
#endif

	/*
	 *	The tmpl_tokenize code takes care of resolving the data if there's a cast.
	 */
	lhs_box = xlat_value_box(lhs);
	if (!lhs_box) return 0;

	rhs_box = xlat_value_box(rhs);
	if (!rhs_box) return 0;

	if (fr_value_calc_binary_op(lhs, &box, FR_TYPE_NULL, lhs_box, op, rhs_box) < 0) return -1;

	MEM(node = xlat_exp_alloc(ctx, XLAT_BOX, NULL, 0));

	if (box.type == FR_TYPE_BOOL) box.enumv = attr_expr_bool_enum;

	MEM(fr_value_box_aprint(node, &name, &box, NULL) >= 0);
	xlat_exp_set_name_buffer_shallow(node, name);
	fr_value_box_copy(node, &node->data, &box);

	*out = node;

	return 1;
}

int xlat_purify_op(TALLOC_CTX *ctx, xlat_exp_t **out, xlat_exp_t *lhs, fr_token_t op, xlat_exp_t *rhs)
{
	if (op == T_LOR) {
		xlat_exp_t *node;

		node = peephole_optimize_lor(lhs, rhs);
		if (!node) return 0;

		*out = node;
		return 1;
	}

	if (op == T_LAND) {
		xlat_exp_t *node;

		node = peephole_optimize_land(lhs, rhs);
		if (!node) return 0;

		*out = node;
		return 1;
	}

	return binary_peephole_optimize(ctx, out, lhs, op, rhs);
}
