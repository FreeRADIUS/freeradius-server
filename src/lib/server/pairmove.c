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

#include <freeradius-devel/server/pairmove.h>
#include <freeradius-devel/server/tmpl_dcursor.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/calc.h>
#include <freeradius-devel/util/pair_legacy.h>

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
		if (request_attr_is_list(da)) {
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
		/*
		 *	The tmpl calls above use map->lhs to get to both the
		 *	correct list, and da.  So from now on, we don't need
		 *	to do any more nested finds.
		 */
		fr_assert(vp->da == da);
		next = fr_pair_find_by_da(list, vp, da); /* could be deleted in the loop*/

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
