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

#include <freeradius-devel/server/paircmp.h>
#include <freeradius-devel/server/pairmove.h>
#include <freeradius-devel/server/tmpl_dcursor.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/calc.h>
#include <freeradius-devel/util/pair_legacy.h>

#include <freeradius-devel/protocol/radius/rfc2865.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

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
				rcode = paircmp_pairs(NULL, from_vp, to_vp);

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

static int radius_legacy_map_to_vp(request_t *request, fr_pair_t *parent, map_t const *map)
{
	fr_pair_t *vp;
	fr_dict_attr_t const *da;
	fr_value_box_t *box, *to_free = NULL;

	RDEBUG("  %s %s %s", map->lhs->name, fr_tokens[map->op], map->rhs->name);

	da = tmpl_attr_tail_da(map->lhs);
	fr_assert(fr_type_is_leaf(da->type));

	if (tmpl_is_data(map->rhs)) {
		box = tmpl_value(map->rhs);

	} else if (tmpl_is_attr(map->rhs)) {
		fr_pair_t *rhs;

		if (tmpl_find_vp(&rhs, request, map->rhs) < 0) return -1;

		if (rhs->vp_type != da->type) {
			fr_strerror_const("Incompatible data types");
			return -1;
		}

		box = &rhs->data;

	} else if (tmpl_is_xlat(map->rhs)) {
		if (tmpl_aexpand(parent, &to_free, request, map->rhs, NULL, NULL) < 0) return -1;

		box = to_free;

	} else {
		fr_strerror_const("Unknown RHS");
		return -1;
	}

	if (fr_pair_append_by_da(parent, &vp, &parent->vp_group, da) < 0) return -1;

	if (fr_value_box_cast(vp, &vp->data, vp->vp_type, vp->da, box) < 0) {
		TALLOC_FREE(to_free);
		return -1;
	}

	TALLOC_FREE(to_free);
	return 0;
}


static int CC_HINT(nonnull) radius_legacy_map_apply_structural(request_t *request, map_t const *map, fr_pair_t *vp)
{
	fr_value_box_t	*box, *to_free = NULL;

	/*
	 *	No RHS map, but we have children.  Create them, and add them to the list.
	 */
	if (!map->rhs) {
		map_t *child;

		/*
		 *	Convert the child maps to VPs.  We know that
		 *	we just created the pair, so there's no reason
		 *	to apply operators to the children.
		 */
		for (child = map_list_next(&map->child, NULL);
		     child != NULL;
		     child = map_list_next(&map->child, child)) {
			fr_assert(child->op == T_OP_EQ);
			if (radius_legacy_map_to_vp(request, vp, child) < 0) return -1;
		}

		return 0;
	}

	/*
	 *	Copy an existing attribute.
	 */
	if (tmpl_is_attr(map->rhs)) {
		fr_pair_t *rhs;

		if (tmpl_find_vp(&rhs, request, map->rhs) < 0) return -1;

		if (rhs->vp_type != vp->vp_type) {
			fr_strerror_const("Incompatible data types");
			return -1;
		}

		if (rhs == vp) {
			fr_strerror_const("Invalid self-reference");
			return -1;
		}

		return fr_pair_list_copy(vp, &vp->vp_group, &rhs->vp_group);
	}

	/*
	 *	RHS is a string or an xlat expansion.
	 */
	if (tmpl_is_data(map->rhs)) {
		box = tmpl_value(map->rhs);

	} else if (tmpl_is_xlat(map->rhs)) {
		if (tmpl_aexpand(request, &to_free, request, map->rhs, NULL, NULL) < 0) return -1;

		box = to_free;

	} else {
		fr_strerror_const("Unknown RHS");
		return -1;
	}

	if (box->type != FR_TYPE_STRING) {
		fr_strerror_const("Cannot parse child list");
		TALLOC_FREE(to_free);
		return -1;
	}

	/*
	 *	If there's no value, just leave the list alone.
	 *
	 *	Otherwise parse the children in the context of the parent.
	 */
	if (box->vb_strvalue[0]) {
		fr_pair_parse_t root, relative;

		/*
		 *	Parse the string as a list of pairs.
		 */
		root = (fr_pair_parse_t) {
			.ctx = vp,
				.da = vp->da,
				.list = &vp->vp_group,
				.dict = vp->da->dict,
				.internal = fr_dict_internal(),
				.allow_compare = false,
				.tainted = box->tainted,
		};
		relative = (fr_pair_parse_t) { };

		if (fr_pair_list_afrom_substr(&root, &relative, &FR_SBUFF_IN(box->vb_strvalue, box->vb_length)) < 0) {
			RPEDEBUG("Failed parsing string '%pV' as attribute list", box);
			TALLOC_FREE(to_free);
			return -1;
		}
	}

	TALLOC_FREE(to_free);
	return 0;
}

typedef struct {
	fr_edit_list_t	*el;
	fr_pair_t	*vp;	/* the one we created */
} legacy_pair_build_t;

/** Build the relevant pairs at each level.
 *
 *  See edit_list_pair_build() for similar code.
 */
static fr_pair_t *legacy_pair_build(fr_pair_t *parent, fr_dcursor_t *cursor, fr_dict_attr_t const *da, void *uctx)
{
	fr_pair_t *vp;
	legacy_pair_build_t *lp = uctx;

	vp = fr_pair_afrom_da(parent, da);
	if (!vp) return NULL;

	if (fr_edit_list_insert_pair_tail(lp->el, &parent->vp_group, vp) < 0) {
		talloc_free(vp);
		return NULL;
	}

	/*
	 *	Tell the cursor that we appended a pair.  This
	 *	function only gets called when we've ran off of the
	 *	end of the list, and can't find the thing we're
	 *	looking for.  So it's safe at set the current one
	 *	here.
	 *
	 *	@todo - mainly only because we don't allow creating
	 *	foo[4] when there's <3 matching entries.  i.e. the
	 *	"arrays" here are really lists, so we can't create
	 *	"holes" in the list.
	 */
	fr_dcursor_set_current(cursor, vp);

	lp->vp = vp;

	return vp;
}


/** Move a map using the operators from the old pairmove functionality.
 *
 */
int radius_legacy_map_apply(request_t *request, map_t const *map, fr_edit_list_t *el)
{
	int16_t			num;
	int			err, rcode;
	bool			added = false;
	fr_pair_t		*vp = NULL, *next, *parent;
	fr_dict_attr_t const	*da;
	fr_pair_list_t		*list;
	TALLOC_CTX		*ctx;
	fr_value_box_t		*to_free = NULL;
	fr_value_box_t const	*box;
	tmpl_dcursor_ctx_t	cc;
	fr_dcursor_t		cursor;

	/*
	 *	Find out where this attribute exists, or should exist.
	 */
	tmpl_pair_list_and_ctx(ctx, list, request, tmpl_request(map->lhs), tmpl_list(map->lhs));
	if (!ctx) return -1;	/* no request or list head exists */

	da = tmpl_attr_tail_da(map->lhs);

	/*
	 *	These operations are the same for both leaf and structural types.
	 */
	switch (map->op) {
	case T_OP_EQ:
		if (tmpl_find_vp(&vp, request, map->lhs) < -1) return -1;
		if (vp) return 0;
		goto add;

	case T_OP_SET:
		/*
		 *	Set a value.  Note that we might do
		 *
		 *		&foo[1] := 1
		 *
		 *	In which case we don't want to delete the attribute, we just want to replace its
		 *	value.
		 *
		 *	@todo - we can't do &foo[*].bar[*].baz = 1, as that's an implicit cursor, and we don't
		 *	do that.
		 */
		num = tmpl_attr_tail_num(map->lhs);
		if (num == NUM_COUNT) {
			fr_strerror_const("Invalid count in attribute reference");
			return -1;
		}

		vp = tmpl_dcursor_init(&err, ctx, &cc, &cursor, request, map->lhs);

		/*
		 *	We're editing a specific number.  It must exist, otherwise the edit does nothing.
		 */
		if ((num >= 0) || (num == NUM_LAST)) {
			if (!vp) return 0;

			if (fr_type_is_leaf(vp->vp_type)) {
				if (fr_edit_list_save_pair_value(el, vp) < 0) return -1;
			} else {
				fr_assert(fr_type_is_structural(vp->vp_type));

				if (fr_edit_list_free_pair_children(el, vp) < 0) return -1;
			}
			break;
		}

		/*
		 *	We don't delete the main lists, we just modify their contents.
		 */
		if ((da == request_attr_request) ||
		    (da == request_attr_reply) ||
		    (da == request_attr_control) ||
		    (da == request_attr_state)) {
			fr_assert(vp != NULL);

			if (fr_edit_list_free_pair_children(el, vp) < 0) return -1;
			break;
		}

		if (!vp) goto add;

		/*
		 *	Delete the first attribute we found.
		 */
		parent = fr_pair_parent(vp);
		fr_assert(parent != NULL);

		if (fr_edit_list_pair_delete(el, &parent->vp_group, vp) < 0) return -1;
		tmpl_dcursor_clear(&cc);

		/*
		 *	Delete all existing attributes.  Note that we re-initialize the cursor every time,
		 *	because creating "foo := baz" means deleting ALL existing "foo".  But we can't use
		 *	the tmpl as a cursor, because the tmpl containst NUM_UNSPEC, and the cursor needs
		 *	NUM_ALL.  So we have to delete all existing attributes, and then add a new one.
		 */
		while (true) {
			vp = tmpl_dcursor_init(&err, ctx, &cc, &cursor, request, map->lhs);
			if (!vp) break;

			parent = fr_pair_parent(vp);
			fr_assert(parent != NULL);

			if (fr_edit_list_pair_delete(el, &parent->vp_group, vp) < 0) return -1;
			tmpl_dcursor_clear(&cc);
		}
		FALL_THROUGH;

	case T_OP_ADD_EQ:
	add:
	{
		legacy_pair_build_t	lp = (legacy_pair_build_t) {
			.el = el,
			.vp = NULL,
		};

		fr_strerror_clear();
		vp = tmpl_dcursor_build_init(&err, ctx, &cc, &cursor, request, map->lhs, legacy_pair_build, &lp);
		tmpl_dcursor_clear(&cc);
		if (!vp) {
			RWDEBUG("Failed creating attribute %s", map->lhs->name);
			return -1;
		}

		/*
		 *	If we're adding and one already exists, create a new one in the same context.
		 */
		if ((map->op == T_OP_ADD_EQ) && !lp.vp) {
			parent = fr_pair_parent(vp);
			fr_assert(parent != NULL);

			MEM(vp = fr_pair_afrom_da(parent, da));
			if (fr_edit_list_insert_pair_tail(el, &parent->vp_group, vp) < 0) return -1;
		}

		added = true;
	}
		break;

	case T_OP_LE:		/* replace if not <= */
	case T_OP_GE:		/* replace if not >= */
		if (fr_type_is_structural(da->type)) goto invalid_operator;

		if (tmpl_find_vp(&vp, request, map->lhs) < -1) return -1;
		if (!vp) goto add;
		break;

	case T_OP_SUB_EQ:	/* delete if match, otherwise ignore */
		if (fr_type_is_structural(da->type)) {
		invalid_operator:
			fr_strerror_printf("Invalid operator '%s' for structural type", fr_type_to_str(da->type));
			return -1;
		}

		if (tmpl_find_vp(&vp, request, map->lhs) < -1) return -1;
		if (!vp) return 0;
		break;

	default:
		fr_strerror_printf("Invalid operator '%s'", fr_tokens[map->op]);
		return -1;
	}

	fr_assert(vp);

	/*
	 *	We don't support operations on structural types.  Just creation, and assign values.
	 *
	 *	The code above has ensured that the structural type has been either saved or cleared via the
	 *	edit list, so the next function doesn't need to do that.
	 */
	if (fr_type_is_structural(tmpl_attr_tail_da(map->lhs)->type)) {
		fr_assert(added);
		return radius_legacy_map_apply_structural(request, map, vp);
	}

	/*
	 *	We have now found the RHS.  Expand it.
	 *
	 *	Note that
	 *
	 *		&foo := %tolower(&foo)
	 *
	 *	works, as we save the value above in the T_OP_SET handler.  So we don't delete it.
	 */
	if (tmpl_is_data(map->rhs)) {
		box = tmpl_value(map->rhs);

	} else if (tmpl_is_attr(map->rhs)) {
		fr_pair_t *rhs;

		if (tmpl_find_vp(&rhs, request, map->rhs) < 0) return -1;

		if (rhs->vp_type != da->type) {
			fr_strerror_const("Incompatible data types");
			return -1;
		}

		if (rhs == vp) {
			fr_strerror_const("Invalid self-reference");
			return -1;
		}

		box = &rhs->data;

	} else if (tmpl_is_xlat(map->rhs)) {
		if (tmpl_aexpand(ctx, &to_free, request, map->rhs, NULL, NULL) < 0) return -1;

		box = to_free;

	} else {
		fr_strerror_const("Unknown RHS");
		return -1;
	}

	/*
	 *	We added a VP which hadn't previously existed.  Therefore just set the value and return.
	 */
	if (added) {
		if (fr_value_box_cast(vp, &vp->data, vp->vp_type, vp->da, box) < 0) {
		fail:
			TALLOC_FREE(to_free);
			return -1;
		}

		if (vp->da->flags.unsafe) fr_value_box_mark_unsafe(&vp->data);
		TALLOC_FREE(to_free);
		return 0;
	}

	while (vp) {
		next = fr_pair_find_by_da_nested(list, vp, da); /* could be deleted in the loop*/

		switch (map->op) {
		case T_OP_LE:		/* replace if not <= */
		case T_OP_GE:		/* replace if not >= */
			rcode = fr_value_box_cmp_op(map->op, &vp->data, box);
			if (rcode < 0) goto fail;

			if (rcode != 0) break;

			if (fr_value_box_cast(vp, &vp->data, vp->vp_type, vp->da, box) < 0) goto fail;
			break;

		case T_OP_SUB_EQ:	/* delete if match */
			rcode = fr_value_box_cmp_op(T_OP_CMP_EQ, &vp->data, box);
			if (rcode < 0) goto fail;

			if (rcode == 1) {
				fr_pair_list_t *parent_list = fr_pair_parent_list(vp);

			        if (fr_edit_list_pair_delete(el, parent_list, vp) < 0) goto fail;
			}
			break;

		default:
			fr_assert(0);	/* should have been caught above */
			return -1;
		}

		vp = next;
	}

	TALLOC_FREE(to_free);
	return 0;
}

int radius_legacy_map_list_apply(request_t *request, map_list_t const *list, fr_edit_list_t *el)
{
	map_t const *map;

	for (map = map_list_head(list);
	     map != NULL;
	     map = map_list_next(list, map)) {
		RDEBUG2("%s %s %s", map->lhs->name, fr_tokens[map->op],
			map->rhs ? map->rhs->name : "{ ... }");

		if (radius_legacy_map_apply(request, map, el) < 0) {
			RPEDEBUG("Failed applying result");
			return -1;
		}
	}

	return 0;
}

int radius_legacy_map_cmp(request_t *request, map_t const *map)
{
	int			rcode;
	fr_pair_t		*vp;
	fr_value_box_t const	*box;
	fr_value_box_t		*to_free = NULL;
	fr_value_box_t		dst, str;
	fr_dcursor_t		cursor;
	tmpl_dcursor_ctx_t	cc;

	fr_assert(tmpl_is_attr(map->lhs));
	fr_assert(fr_comparison_op[map->op]);

	vp = tmpl_dcursor_init(NULL, request, &cc, &cursor, request, map->lhs);

	if (!vp) {
		tmpl_dcursor_clear(&cc);
		if (map->op == T_OP_CMP_FALSE) return true;
		return 0;
	}

	if (map->op == T_OP_CMP_TRUE){
		tmpl_dcursor_clear(&cc);
		return false;
	}

	if (fr_type_is_structural(vp->vp_type)) {
		fr_strerror_const("Invalid comparison for structural type");
	error:
		tmpl_dcursor_clear(&cc);
		return -1;
	}

	if (tmpl_is_data(map->rhs)) {
		box = tmpl_value(map->rhs);

	} else if (tmpl_is_attr(map->rhs)) {
		fr_pair_t *rhs;

		if (tmpl_find_vp(&rhs, request, map->rhs) < 0) goto error;

		box = &rhs->data;

	} else if (tmpl_contains_xlat(map->rhs)) {
		if (tmpl_aexpand(request, &to_free, request, map->rhs, NULL, NULL) < 0) goto error;

		box = to_free;

	} else if (tmpl_is_regex(map->rhs)) {
		/*
		 *	@todo - why box it and parse it again, when we can just run the regex?
		 */
		fr_value_box_strdup_shallow(&str, NULL, map->rhs->name, false);
		box = &str;

	} else {
		fr_strerror_const("Unknown RHS");
		goto error;
	}

	/*
	 *	Check all possible vps matching the lhs
	 *	Allows for comparisons such as &foo[*] == "bar" - i.e. true if any instance of &foo has the value "bar"
	 */
	rcode = 0;
	while (vp) {
		/*
		 *	Let the calculation code do upcasting as necessary.
		 */
		rcode = fr_value_calc_binary_op(request, &dst, FR_TYPE_BOOL, &vp->data, map->op, box);
		if ((rcode >= 0) && dst.vb_bool) break;  // Found a "true" result, no need to check any further
		vp = fr_dcursor_next(&cursor);
	}
	TALLOC_FREE(to_free);
	tmpl_dcursor_clear(&cc);

	if (rcode < 0) return rcode;

	return dst.vb_bool;
}
