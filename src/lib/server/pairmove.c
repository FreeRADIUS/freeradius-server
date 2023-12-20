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
 * @file src/lib/server/pairmove.c
 * @brief Old style mapping code
 *
 * @copyright 2007 The FreeRADIUS server project
 * @copyright 2007 Alan DeKok (aland@deployingradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/calc.h>
#include <freeradius-devel/server/pairmove.h>

#include <freeradius-devel/protocol/radius/rfc2865.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <ctype.h>

/*
 *	@fixme - integrate this with the code calling it, so that we
 *	only fr_pair_list_copy() those attributes that we're really going to
 *	use.
 */
void radius_pairmove(request_t *request, fr_pair_list_t *to, fr_pair_list_t *from)
{
	int		i, j, count, to_count, tailto;
	fr_pair_t	*from_vp, *next_from, *to_vp, *next_to = NULL;
	fr_pair_list_t	append, prepend;
	bool		*edited = NULL;
	bool		*deleted = NULL;

	/*
	 *	Set up arrays for editing, to remove some of the
	 *	O(N^2) dependencies.  These record which elements in
	 *	the "to" list have been either edited or marked for
	 *	deletion.
	 *
	 *	It also means that the operators apply ONLY to the
	 *	attributes in the original list.
	 *
	 *	Also, the previous implementation did NOT implement
	 *	"-=" correctly.  If two of the same attributes existed
	 *	in the "to" list, and you tried to subtract something
	 *	matching the *second* value, then the fr_pair_delete_by_da()
	 *	function was called, and the *all* attributes of that
	 *	number were deleted.  With this implementation, only
	 *	the matching attributes are deleted.
	 */

	fr_pair_list_init(&append);
	fr_pair_list_init(&prepend);

	to_count = fr_pair_list_num_elements(to);
	tailto = to_count;
	edited = talloc_zero_array(request, bool, to_count);
	deleted = talloc_zero_array(request, bool, to_count);

	count = to_count + fr_pair_list_num_elements(from);

	RDEBUG4("::: FROM %ld TO %d MAX %d", fr_pair_list_num_elements(from), to_count, count);

	/*
	 *	Now that we have the lists initialized, start working
	 *	over them.
	 */
	for (i = 0, from_vp = fr_pair_list_head(from); from_vp; i++, from_vp = next_from) {
		int found;
		/* Find the next from pair before any manipulation happens */
		next_from = fr_pair_list_next(from, from_vp);

		RDEBUG4("::: Examining %s", from_vp->da->name);

		/*
		 *	Attribute should be appended, OR the "to" list
		 *	is empty, and we're supposed to replace or
		 *	"add if not existing".
		 */
		if (from_vp->op == T_OP_ADD_EQ) goto do_append;

		/*
		 *	The attribute needs to be prepended to the "to"
		 *	list - store it in the prepend list
		 */

		if (from_vp->op == T_OP_PREPEND) {
			RDEBUG4("::: PREPENDING %s FROM %d", from_vp->da->name, i);
			fr_pair_remove(from, from_vp);
			fr_pair_prepend(&prepend, from_vp);
			from_vp->op = T_OP_EQ;
			continue;
		}
		found = false;
		j = 0;
		for (to_vp = fr_pair_list_head(to); to_vp; to_vp = next_to, j++) {
			next_to = fr_pair_list_next(to, to_vp);
			if (edited[j] || deleted[j] || !from_vp) continue;

			/*
			 *	Attributes aren't the same, skip them.
			 */
			if (from_vp->da != to_vp->da) {
				continue;
			}

			/*
			 *	We don't use a "switch" statement here
			 *	because we want to break out of the
			 *	"for" loop over 'j' in most cases.
			 */

			/*
			 *	Over-write the FIRST instance of the
			 *	matching attribute name.  We free the
			 *	one in the "to" list, and move over
			 *	the one in the "from" list.
			 */
			if (from_vp->op == T_OP_SET) {
				RDEBUG4("::: OVERWRITING %s FROM %d TO %d",
				       to_vp->da->name, i, j);
				fr_pair_remove(from, from_vp);
				fr_pair_replace(to, to_vp, from_vp);
				from_vp = NULL;
				edited[j] = true;
				break;
			}

			/*
			 *	Add the attribute only if it does not
			 *	exist... but it exists, so we stop
			 *	looking.
			 */
			if (from_vp->op == T_OP_EQ) {
				found = true;
				break;
			}

			/*
			 *	Delete every attribute, independent
			 *	of its value.
			 */
			if (from_vp->op == T_OP_CMP_FALSE) {
				goto delete;
			}

			/*
			 *	Delete all matching attributes from
			 *	"to"
			 */
			if ((from_vp->op == T_OP_SUB_EQ) ||
			    (from_vp->op == T_OP_CMP_EQ) ||
			    (from_vp->op == T_OP_LE) ||
			    (from_vp->op == T_OP_GE)) {
				int rcode;
				int old_op = from_vp->op;
				/*
				 *	Check for equality.
				 */
				from_vp->op = T_OP_CMP_EQ;

				/*
				 *	If equal, delete the one in
				 *	the "to" list.
				 */
				rcode = paircmp_pairs(NULL, from_vp,
							   to_vp);
				/*
				 *	We may want to do more
				 *	subtractions, so we re-set the
				 *	operator back to it's original
				 *	value.
				 */
				from_vp->op = old_op;

				switch (old_op) {
				case T_OP_CMP_EQ:
					if (rcode != 0) goto delete;
					break;

				case T_OP_SUB_EQ:
					if (rcode == 0) {
					delete:
						RDEBUG4("::: DELETING %s FROM %d TO %d",
						       from_vp->da->name, i, j);
						/*
						 *	Mark that this will be deleted
						 */
						deleted[j] = true;
					}
					break;

					/*
					 *	Enforce <=.  If it's
					 *	>, replace it.
					 */
				case T_OP_LE:
					if (rcode > 0) {
						RDEBUG4("::: REPLACING %s FROM %d TO %d",
						       from_vp->da->name, i, j);
						goto replace;
					}
					break;

				case T_OP_GE:
					if (rcode < 0) {
						RDEBUG4("::: REPLACING %s FROM %d TO %d",
						       from_vp->da->name, i, j);
					replace:
						fr_pair_remove(from, from_vp);
						fr_pair_replace(to, to_vp, from_vp);
						from_vp = NULL;
						edited[j] = true;
					}
					break;
				}

				continue;
			}

			fr_assert(0 == 1); /* panic! */
		}

		/*
		 *	We were asked to add it if it didn't exist,
		 *	and it doesn't exist.  Move it over to the
		 *	tail of the "to" list, UNLESS it was already
		 *	moved by another operator.
		 */
		if (!found && from_vp) {
			if ((from_vp->op == T_OP_EQ) ||
			    (from_vp->op == T_OP_LE) ||
			    (from_vp->op == T_OP_GE) ||
			    (from_vp->op == T_OP_SET)) {
			do_append:
				RDEBUG4("::: APPENDING %s FROM %d TO %d",
				       from_vp->da->name, i, tailto++);
				fr_pair_remove(from, from_vp);
				fr_pair_append(&append, from_vp);
				from_vp->op = T_OP_EQ;
			}
		}
	}

	/*
	 *	Delete remaining attributes in the "from" list.
	 */
	fr_pair_list_free(from);

	RDEBUG4("::: TO in %d out %d", to_count, tailto);

	/*
	 *	Delete any "to" items marked for deletion
	 */

	i = 0;
	for (to_vp = fr_pair_list_head(to); to_vp; to_vp = next_to, i++) {
		next_to = fr_pair_list_next(to, to_vp);

		if (deleted[i]) {
			fr_pair_remove(to, to_vp);
			continue;
		}

		RDEBUG4("::: to[%d] = %s", i, to_vp->da->name);

		/*
		 *	Mash the operator to a simple '='.  The
		 *	operators in the "to" list aren't used for
		 *	anything.  BUT they're used in the "detail"
		 *	file and debug output, where we don't want to
		 *	see the operators.
		 */
		to_vp->op = T_OP_EQ;
	}

	/*
	 *  Now prepend any items in the "prepend" list to
	 *  the head of the "to" list.
	 */
	fr_pair_list_prepend(to, &prepend);

	/*
	 *	And finally add in the attributes we're appending to
	 *	the tail of the "to" list.
	 */
	fr_pair_list_append(to, &append);

	fr_assert(request->packet != NULL);

	talloc_free(edited);
	talloc_free(deleted);
}

/** Move a map using the operators from the old pairmove functionality.
 *
 */
int radius_legacy_map_apply(request_t *request, map_t const *map)
{
	int rcode;
	fr_pair_t *vp, *next;
	fr_dict_attr_t const *da;
	fr_pair_list_t *list;
	TALLOC_CTX *ctx;
	fr_value_box_t *to_free = NULL;
	fr_value_box_t const *box;

	/*
	 *	Finds both the correct ctx and nested list.
	 */
	tmpl_pair_list_and_ctx(ctx, list, request, tmpl_request(map->lhs), tmpl_list(map->lhs));
	if (!ctx) {
		switch (map->op) {
		case T_OP_CMP_FALSE:
			return 1;

		case T_OP_CMP_TRUE:
			return 0;

		case T_OP_EQ:
		case T_OP_SET:
		case T_OP_ADD_EQ:
		case T_OP_PREPEND:
			if (tmpl_find_or_add_vp(&vp, request, map->lhs) < 0) return -1;
			break;

		case T_OP_CMP_EQ:
		case T_OP_LE:
		case T_OP_GE:
			if (tmpl_find_or_add_vp(&vp, request, map->lhs) < 0) return -1;
			break;

		default:
			return -1;
		}
	}

	da = tmpl_attr_tail_da(map->lhs);

	if (fr_type_is_structural(da->type)) {
		if (!map->rhs) return 0;

		fr_assert(0);
	}

	if (tmpl_is_data(map->rhs)) {
		box = tmpl_value(map->rhs);

	} else if (tmpl_is_attr(map->rhs)) {
		if (tmpl_find_vp(&vp, request, map->rhs) < 0) return -1;

		if (vp->vp_type != da->type) {
			fr_strerror_const("Incompatible data types");
			return -1;
		}

		box = &vp->data;

	} else if (tmpl_is_xlat(map->rhs)) {
		if (tmpl_aexpand(ctx, &to_free, request, map->rhs, NULL, NULL) < 0) return -1;

		box = to_free;

	} else {
		fr_strerror_const("Unknown RHS");
		return -1;
	}

	switch (map->op) {
	case T_OP_CMP_FALSE:	/* delete all */
		fr_pair_delete_by_da_nested(list, da);
		break;

	case T_OP_EQ:		/* set only if not already exist */
		vp = fr_pair_find_by_da_nested(list, NULL, da);
		if (vp) goto success;
		goto add;

	case T_OP_SET:		/* delete all and set one */
		fr_pair_delete_by_da_nested(list, da);
		FALL_THROUGH;

	case T_OP_ADD_EQ:	/* append one */
	add:
		vp = fr_pair_afrom_da_nested(ctx, list, da);
		if (!vp) goto fail;

		if (fr_value_box_cast(vp, &vp->data, vp->vp_type, vp->da, box) < 0) {
		fail_vp:
			talloc_free(vp);
		fail:
			TALLOC_FREE(to_free);
			return -1;
		}
		break;

	case T_OP_PREPEND:	/* prepend one */
		fr_assert(0);	/* doesn't work with nested? */

		vp = fr_pair_afrom_da(ctx, da);
		if (!vp) goto fail;

		if (fr_value_box_cast(vp, &vp->data, vp->vp_type, vp->da, box) < 0) goto fail_vp;

		fr_pair_prepend(list, vp);
		break;

	case T_OP_SUB_EQ:		/* delete if match */
		vp = fr_pair_find_by_da_nested(list, NULL, da);
		if (!vp) break;

	redo_sub:
		next = fr_pair_find_by_da(list, vp, da);
		rcode = fr_value_box_cmp_op(T_OP_CMP_EQ, &vp->data, box);

		if (rcode < 0) goto fail;

		if (rcode == 1) {
			fr_pair_list_t *parent = fr_pair_parent_list(vp);

			fr_pair_delete(parent, vp);
		}

		if (!next) break;
		vp = next;
		goto redo_sub;

	case T_OP_CMP_EQ:      	/* replace if not == */
	case T_OP_LE:		/* replace if not <= */
	case T_OP_GE:		/* replace if not >= */
		vp = fr_pair_find_by_da_nested(list, NULL, da);
		if (!vp) goto add;

	redo_filter:
		rcode = fr_value_box_cmp_op(map->op, &vp->data, box);
		if (rcode < 0) goto fail;

		if (rcode == 0) {
			if (fr_value_box_cast(vp, &vp->data, vp->vp_type, vp->da, box) < 0) goto fail;
		}

		vp = fr_pair_find_by_da_nested(list, vp, da);
		if (vp) goto redo_filter;
		break;

	default:
		fr_assert(0);
		break;
	}

success:
	TALLOC_FREE(to_free);
	return 0;
}

int radius_legacy_map_cmp(request_t *request, map_t const *map)
{
	int rcode;
	fr_pair_t *vp;
	fr_value_box_t const *box;
	fr_value_box_t *to_free = NULL;
	fr_value_box_t dst, str;

	fr_assert(tmpl_is_attr(map->lhs));
	fr_assert(fr_comparison_op[map->op]);

	if (tmpl_find_vp(&vp, request, map->lhs) < 0) {
		if (map->op == T_OP_CMP_FALSE) return true;		
		return 0;
	}

	if (map->op == T_OP_CMP_TRUE) return false;

	if (tmpl_is_data(map->rhs)) {
		box = tmpl_value(map->rhs);

	} else if (tmpl_is_attr(map->rhs)) {
		fr_pair_t *rhs;

		if (tmpl_find_vp(&rhs, request, map->rhs) < 0) return -1;

		box = &rhs->data;

	} else if (tmpl_contains_xlat(map->rhs)) {
		if (tmpl_aexpand(request, &to_free, request, map->rhs, NULL, NULL) < 0) return -1;

		box = to_free;

	} else if (tmpl_is_regex(map->rhs)) {
		/*
		 *	@todo - why box it and parse it again, when we can just run the regex?
		 */
		fr_value_box_strdup_shallow(&str, NULL, map->rhs->name, false);
		box = &str;

	} else {
		fr_strerror_const("Unknown RHS");
		return -1;
	}

	/*
	 *	Let the calculation code do upcasting as necessary.
	 */
	rcode = fr_value_calc_binary_op(request, &dst, FR_TYPE_BOOL, &vp->data, map->op, box);
	TALLOC_FREE(to_free);

	if (rcode < 0) return rcode;

	return dst.vb_bool;
}
