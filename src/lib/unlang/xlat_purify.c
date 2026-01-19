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
#include <freeradius-devel/unlang/mod_action.h>
#include <freeradius-devel/unlang/xlat_priv.h>
#include <freeradius-devel/util/calc.h>

static int xlat_value_list_to_xlat(xlat_exp_head_t *head, fr_value_box_list_t *list)
{
	fr_value_box_t *box;
	xlat_exp_t *node;

	while ((box = fr_value_box_list_pop_head(list)) != NULL) {
		MEM(node = xlat_exp_alloc(head, XLAT_BOX, NULL, 0));
		if (unlikely(fr_value_box_copy(node, &node->data, box) < 0)) {
			talloc_free(node);
			return -1;
		}

		if (node->data.type == FR_TYPE_STRING) {
			node->quote = T_DOUBLE_QUOTED_STRING;
			xlat_exp_set_name_buffer(node, node->data.vb_strvalue); /* later changes can free strvalue */
		} else {
			char *name;

			node->quote = T_BARE_WORD;
			MEM(fr_value_box_aprint(node, &name, box, NULL) >= 0);
			xlat_exp_set_name_shallow(node, name);
		}
		talloc_free(box);

		xlat_exp_insert_tail(head, node);
	}

	return 0;
}

static int xlat_purify_list_internal(xlat_exp_head_t *head, request_t *request, fr_token_t quote);

int xlat_purify_list(xlat_exp_head_t *head, request_t *request)
{
	return xlat_purify_list_internal(head, request, T_BARE_WORD);
}

static int xlat_purify_list_internal(xlat_exp_head_t *head, request_t *request, fr_token_t quote)
{
	int rcode;
	unlang_result_t result = UNLANG_RESULT_NOT_SET;
	fr_value_box_list_t list;
	xlat_flags_t our_flags;
	xlat_exp_t *node, *next;

	if (!head->flags.can_purify) return 0;

	/*
	 *	We can't purify things which need resolving,
	 */
	if (head->flags.needs_resolving) return -1;

	our_flags = head->flags;
	our_flags.constant = our_flags.pure = true;		/* we flip these if the children are not pure */

	for (node = fr_dlist_head(&head->dlist);
	     (void) (next = fr_dlist_next(&head->dlist, node)), node != NULL;
	     node = next) {
		if (!node->flags.can_purify) continue;

		switch (node->type) {
		case XLAT_TMPL:
			if (tmpl_is_attr(node->vpt)) break;

			/*
			 *	Optimize it by replacing the xlat -> tmpl -> xlat with just an xlat.
			 *
			 *	That way we avoid a bounce through the tmpl code at run-time.
			 */
			if (tmpl_contains_xlat(node->vpt)) {
				xlat_exp_head_t *xlat = tmpl_xlat(node->vpt);

				rcode = xlat_purify_list_internal(xlat, request, node->vpt->quote);
				if (rcode < 0) return rcode;

				node->flags = xlat->flags;

				/*
				 *	We can't do any more optimizations, stop processing it.
				 */
				if (!node->flags.constant) break;

				/*
				 *	@todo - fix this!
				 */
				if (tmpl_rules_cast(node->vpt) != FR_TYPE_NULL) break;

				/*
				 *	We have a quoted string which is constant.  Convert it to a value-box.
				 *
				 *	Don't change node->fmt though, for some vague reason of "knowing where
				 *	it came from".
				 */
				if ((node->vpt->quote != T_BARE_WORD) || (quote != T_BARE_WORD)) {
					fr_sbuff_t *sbuff;
					ssize_t slen;

					FR_SBUFF_TALLOC_THREAD_LOCAL(&sbuff, 256, SIZE_MAX);

					slen = xlat_print(sbuff, xlat, NULL);
					if (slen < 0) return -1;

					xlat_exp_set_type(node, XLAT_BOX); /* frees node->group, and therefore xlat */
					fr_value_box_init(&node->data, FR_TYPE_STRING, NULL, false);

					if (fr_value_box_bstrndup(node, &node->data, NULL,
								  fr_sbuff_start(sbuff), fr_sbuff_used(sbuff), false) < 0) return -1;
					break;
				}

				/*
				 *	The tmpl is constant, but not quoted.  Keep the group wrapper, which
				 *	ensures that the entire sub-expression results in one output value.
				 */
				(void) talloc_steal(node, node->vpt->name);
				(void) talloc_steal(node, xlat);
				xlat_exp_set_type(node, XLAT_GROUP); /* frees node->vpt, and xlat if we didn't steal it */
				talloc_free(node->group);
				node->group = xlat;
				break;
			}
			break;

		case XLAT_BOX:
		case XLAT_ONE_LETTER:
		case XLAT_REGEX:
			break;

		case XLAT_INVALID:
		case XLAT_FUNC_UNRESOLVED:
			fr_assert(0);
			return -1;

		case XLAT_GROUP: {
			bool xlat = node->flags.xlat;

			rcode = xlat_purify_list_internal(node->group, request, quote);
			if (rcode < 0) return rcode;

			node->flags = node->group->flags;
			node->flags.xlat = xlat;

			/*
			 *	If the group is constant, hoist it.
			 *
			 *	The group wrapper isn't actually used for anything, and is added only to wrap
			 *	%{...}.  But we should likely double-check that there are no unexpected side
			 *	effects with things like %{foo.[*]}.  Are there any differences between
			 *	returning _one_ value-box which contains a list, or returning a _list_ of
			 *	value-boxes?
			 *
			 *	i.e. are these two situations identical?
			 *
			 *		foo = bar.[*]
			 *		foo = %{bar.[*]}
			 *
			 *	If "foo" is a leaf type, then perhaps the first one is "create multiple copies of
			 *	'foo', one for each value.  And the second is likely illegal.
			 *
			 *	if "foo" is a structural type, then the first one could assign multiple
			 *	structures to 'foo', just like the leaf example above.  But only if the things
			 *	returned from 'bar.[*]' are structures of the same type as 'foo'.  The second
			 *	example is then assigning _one_ structure to 'foo'.
			 *
			 *	The caveat here is that the data returned from 'bar.[*]' must be of the
			 *	correct types for the structure members.  So it's likely to work only for
			 *	groups.  If we want to copy one structure to another, we just assign them:
			 *
			 *		foo = bar
			 *
			 *	If we hoist the contents of %{bar.[*]}, then for a leaf type, the two
			 *	situations become identical.  For a structural type, we change the meaning so
			 *	that the two situations become identical.
			 *
			 *	And then none of this matters is we're in a quoted string, because the results
			 *	will be concatenated anyways.
			 */
			if (node->flags.constant && node->flags.xlat &&
			    ((quote != T_BARE_WORD) || (fr_dlist_num_elements(&node->group->dlist) == 1))) {
				xlat_exp_t *child, *to_free;

				fr_dlist_remove(&head->dlist, node);
				to_free = node;

				while ((child = fr_dlist_pop_head(&to_free->group->dlist)) != NULL) {
					(void) talloc_steal(head, child);

					fr_dlist_insert_before(&head->dlist, next, child);
					child->flags.can_purify = false;
					xlat_flags_merge(&our_flags, &child->flags);

					node = child;
				}
				talloc_free(to_free);
			}
		}
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
					if (xlat_purify_list_internal(node->call.args, request, T_BARE_WORD) < 0) return -1;
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
			result.rcode = RLM_MODULE_NOT_SET;
			if (unlang_xlat_push_node(head, &result, &list, request, node) < 0) {
				return -1;
			}

			/*
			 *	Hope to god it doesn't yield. :)
			 */

			(void) unlang_interpret_synchronous(NULL, request);
			if (!XLAT_RESULT_SUCCESS(&result)) return -1;

			/*
			 *	The function call becomes a GROUP of boxes
			 */
			xlat_instance_unregister_func(node);
			xlat_exp_set_type(node, XLAT_GROUP);	/* Frees the argument list */

			if (xlat_value_list_to_xlat(node->group, &list) < 0) return -1;
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

	request = request_local_alloc_internal(NULL, NULL);
	if (!request) return -1;

	if (intp) unlang_interpret_set(request, intp);

	rcode = xlat_purify_list(head, request);
	talloc_free(request);
	if (rcode < 0) return rcode;

	fr_assert(!head->flags.can_purify);

	return 0;
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
	xlat_exp_set_name_shallow(node, name);
	if (unlikely(fr_value_box_copy(node, &node->data, &box) < 0)) {
		talloc_free(node);
		return -1;
	}

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
