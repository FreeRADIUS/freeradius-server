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

static void xlat_value_list_to_xlat(xlat_exp_head_t *head, fr_value_box_list_t *list)
{
	fr_value_box_t *box;
	xlat_exp_t *node;

	while ((box = fr_dlist_pop_head(list)) != NULL) {
		MEM(node = xlat_exp_alloc_null(head));
		node->type = XLAT_BOX;

		fr_value_box_copy(node, &node->data, box);
		talloc_free(box);

		if (node->data.type == FR_TYPE_STRING) {
			node->quote = T_DOUBLE_QUOTED_STRING;
			node->fmt = node->data.vb_strvalue;
		} else {
			node->quote = T_BARE_WORD;
			node->fmt = ""; /* @todo - fixme? */
		}

		xlat_exp_insert_tail(head, node);
	}
}


int xlat_purify_list(xlat_exp_head_t *head, request_t *request)
{
	int rcode;
	bool success;
	xlat_exp_head_t *group;
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
		default:
			fr_strerror_printf("Internal error - cannot purify xlat");
			return -1;

		case XLAT_GROUP:
			rcode = xlat_purify_list(node->group, request);
			if (rcode < 0) return rcode;

			node->flags = node->group->flags;
			break;


		case XLAT_ALTERNATE:
			if (node->alternate[0]->flags.can_purify) {
				rcode = xlat_purify_list(node->alternate[0], request);
				if (rcode < 0) return rcode;
			}
			node->flags = node->alternate[0]->flags;

			/*
			 *	@todo - If the RHS of the alternation
			 *	is now pure, then we can statically
			 *	evaluate it, and replace this node
			 *	with the children.  But only if the
			 *	child list is not empty.
			 */

			if (node->alternate[1]->flags.can_purify) {
				rcode = xlat_purify_list(node->alternate[1], request);
				if (rcode < 0) return rcode;
			}
			xlat_flags_merge(&node->flags, &node->alternate[1]->flags);
			break;

		case XLAT_FUNC:
			/*
			 *	If the node is not pure, then maybe there's a callback to purify it, OR maybe
			 *	we can purify the function arguments.
			 */
			if (!node->flags.pure) {
				if (node->call.func->purify) {
					if (node->call.func->purify(node, node->call.inst->data, request) < 0) return -1;

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
			if (unlang_xlat_push_node(head, &success, &list, request, node) < 0) {
				return -1;
			}

			/*
			 *	Hope to god it doesn't yield. :)
			 */
			success = false;
			(void) unlang_interpret_synchronous(NULL, request);

			if (!success) return -1;

			/*
			 *	The function call becomes a GROUP of boxes.  We just re-use the argument head,
			 *	which is already of the type we need.
			 */
			/* coverity[dead_error_begin] */
			group = node->call.args;
			fr_dlist_talloc_free(&group->dlist);

			xlat_inst_remove(node);
			node->type = XLAT_GROUP;
			node->group = group;

			xlat_value_list_to_xlat(group, &list);
			node->flags = group->flags;
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

	request = request_alloc_internal(NULL, (&(request_init_args_t){ .namespace = head->dict }));
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
static xlat_exp_t *logical_peephole_optimize(xlat_exp_t *lhs, fr_token_t op, xlat_exp_t *rhs)
{
	bool value;

	/*
	 *	@todo - check for tail of LHS
	 *		&& tail is truthy, then remove tail, and call ourselves recursively
	 *		if there's a new node, it becomes the new tail.  Otherwise
	 *		we append the rhs to the lhs args.
	 *
	 *	lhs->call.args->flags.can_purify |= rhs->flags.can_purify | rhs->flags.pure;
	 *	lhs->flags.can_purify = lhs->call.args->flags.can_purify;
	 */
	if (!is_truthy(lhs, &value)) return NULL;

	/*
	 *	1 && FOO   --> FOO
	 *	0 && FOO   --> 0
	 *	FOO && BAR --> FOO && BAR
	 */

	/*
	 *	1 || FOO   --> 1
	 *	0 || FOO   --> FOO
	 *	FOO || BAR --> FOO || BAR
	 */
	if (value == (op != T_LAND)) {
		talloc_free(rhs);
		return lhs;
	}

	talloc_free(lhs);
	return rhs;
}


/*
 *	Do some optimizations
 *
 *	@todo check types, if one side is uint8, and the other side is uint32, there are some situations where
 *	the comparison will always fail.  And should therefore be invalid?
 */
static int binary_peephole_optimize(TALLOC_CTX *ctx, xlat_exp_t **out, xlat_exp_t *lhs, fr_token_t op, xlat_exp_t *rhs)
{
	fr_value_box_t *lhs_box, *rhs_box;
	fr_value_box_t box;
	xlat_exp_t *node;
	char *name;

	lhs_box = xlat_value_box(lhs);
	if (!lhs_box) return 0;

	rhs_box = xlat_value_box(rhs);
	if (!rhs_box) return 0;

	if (fr_value_calc_binary_op(lhs, &box, FR_TYPE_NULL, lhs_box, op, rhs_box) < 0) return -1;

	MEM(node = xlat_exp_alloc_null(ctx));
	xlat_exp_set_type(node, XLAT_BOX);

	if (box.type == FR_TYPE_BOOL) box.enumv = attr_expr_bool_enum;

	(void) fr_value_box_aprint(node, &name, &box, NULL);

	xlat_exp_set_name_buffer_shallow(node, name);
	fr_value_box_copy(node, &node->data, &box);

	*out = node;

	return 1;
}

int xlat_purify_op(TALLOC_CTX *ctx, xlat_exp_t **out, xlat_exp_t *lhs, fr_token_t op, xlat_exp_t *rhs)
{
	if ((op == T_LAND) || (op == T_LOR)) {
		xlat_exp_t *node;

		node = logical_peephole_optimize(lhs, op, rhs);
		if (!node) return 0;

		*out = node;
		return 1;
	}

	return binary_peephole_optimize(ctx, out, lhs, op, rhs);
}
