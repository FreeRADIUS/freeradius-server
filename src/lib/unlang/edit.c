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
 * @brief fr_pair_t editing
 *
 * @ingroup AVP
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/tmpl_dcursor.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/edit.h>
#include <freeradius-devel/util/calc.h>
#include <freeradius-devel/unlang/tmpl.h>
#include <freeradius-devel/unlang/unlang_priv.h>
#include "edit_priv.h"

#if 1
#undef DEBUG
#define DEBUG(...)
#endif

typedef struct {
	fr_value_box_list_t	result;			//!< result of expansion
	tmpl_t const		*vpt;			//!< expanded tmpl
	tmpl_t			*to_free;		//!< tmpl to free.
	bool			create;			//!< whether we need to create the VP
	fr_pair_t		*vp;			//!< VP referenced by tmpl.
	fr_pair_t		*vp_parent;		//!< parent of the current VP
	fr_pair_list_t		pair_list;		//!< for structural attributes
} edit_result_t;

typedef struct edit_map_s edit_map_t;

typedef struct unlang_frame_state_edit_s unlang_frame_state_edit_t;

typedef int (*unlang_edit_expand_t)(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current);

struct edit_map_s {
	fr_edit_list_t		*el;			//!< edit list

	TALLOC_CTX		*ctx;
	edit_map_t		*parent;
	edit_map_t		*child;

	map_list_t const	*map_head;
	map_t const		*map;			//!< the map to evaluate

	bool			temporary_pair_list;

	edit_result_t		lhs;			//!< LHS child entries
	edit_result_t		rhs;			//!< RHS child entries

	unlang_edit_expand_t	func;			//!< for process state
	unlang_edit_expand_t	check_lhs;		//!< for special cases
	unlang_edit_expand_t	expanded_lhs;		//!< for special cases
};

/** State of an edit block
 *
 */
struct unlang_frame_state_edit_s {
	fr_edit_list_t		*el;				//!< edit list
	rindent_t		indent;

	edit_map_t		*current;			//!< what we're currently doing.
	edit_map_t		first;
};

#define MAP_INFO cf_filename(map->ci), cf_lineno(map->ci)

static fr_pair_t *edit_list_pair_build(fr_pair_t *parent, fr_dcursor_t *cursor, fr_dict_attr_t const *da, void *uctx);

/*
 *  Convert a value-box list to a LHS attribute #tmpl_t
 */
static int tmpl_attr_from_result(TALLOC_CTX *ctx, map_t const *map, edit_result_t *out, request_t *request)
{
	ssize_t slen;
	fr_value_box_t *box = fr_value_box_list_head(&out->result);

	if (!box) {
		RWDEBUG("%s %s ... - Assignment failed - No value on right-hand side", map->lhs->name, fr_tokens[map->op]);
		return -1;
	}

	/*
	 *	Mash all of the results together.
	 */
	if (fr_value_box_list_concat_in_place(box, box, &out->result, FR_TYPE_STRING, FR_VALUE_BOX_LIST_FREE, true, SIZE_MAX) < 0) {
		RWDEBUG("Failed converting result to string");
		return -1;
	}

	/*
	 *	Parse the LHS as an attribute reference.  It can't be
	 *	anything else.
	 */
	slen = tmpl_afrom_attr_str(ctx, NULL, &out->to_free, box->vb_strvalue,
				   &(tmpl_rules_t){
				   	.attr = {
						.dict_def = request->dict,
						.list_def = request_attr_request,
						.prefix = TMPL_ATTR_REF_PREFIX_NO
					}
				   });
	if (slen <= 0) {
		RPEDEBUG("Expansion result \"%s\" is not an attribute reference", box->vb_strvalue);
		return -1;
	}

	out->vpt = out->to_free;
	fr_value_box_list_talloc_free(&out->result);

	return 0;
}


/*
 *	Expand a tmpl.
 */
static int tmpl_to_values(TALLOC_CTX *ctx, edit_result_t *out, request_t *request, tmpl_t const *vpt)
{
	fr_assert(out->vpt == NULL);
	fr_assert(out->to_free == NULL);

	switch (vpt->type) {
	case TMPL_TYPE_DATA:
		return 0;

	case TMPL_TYPE_ATTR:
		out->vpt = vpt;
		return 0;

	case TMPL_TYPE_EXEC:
		if (unlang_tmpl_push(ctx, &out->result, request, vpt, NULL) < 0) return -1;
		return 1;

	case TMPL_TYPE_XLAT:
		if (unlang_xlat_push(ctx, NULL, &out->result, request, tmpl_xlat(vpt), false) < 0) return -1;
		return 1;

	default:
		/*
		 *	The other tmpl types MUST have already been
		 *	converted to the "realized" types.
		 */
		fr_assert(0);
		break;
	}

	return -1;
}

static void edit_debug_attr_list(request_t *request, fr_pair_list_t const *list, map_t const *map);

static void edit_debug_attr_vp(request_t *request, fr_pair_t *vp, map_t const *map)
{
	fr_assert(vp != NULL);

	if (map) {
		switch (vp->vp_type) {
		case FR_TYPE_STRUCTURAL:
			RDEBUG2("%s = {", map->lhs->name);
			RINDENT();
			edit_debug_attr_list(request, &vp->vp_group, map_list_head(&map->child));
			REXDENT();
			RDEBUG2("}");
			break;

		default:
			RDEBUG2("%s %s %pV", map->lhs->name, fr_tokens[vp->op], &vp->data);
			break;
		}
	} else {
		switch (vp->vp_type) {
		case FR_TYPE_STRUCTURAL:
                        RDEBUG2("%s = {", vp->da->name);
			RINDENT();
			edit_debug_attr_list(request, &vp->vp_group, NULL);
			REXDENT();
			RDEBUG2("}");
			break;

		default:
			RDEBUG2("&%s %s %pV", vp->da->name, fr_tokens[vp->op], &vp->data);
			break;
		}
	}
}

static void edit_debug_attr_list(request_t *request, fr_pair_list_t const *list, map_t const *map)
{
	fr_pair_t *vp;
	map_t const *child = NULL;

	if (map) child = map_list_head(&map->child);

	for (vp = fr_pair_list_next(list, NULL);
	     vp != NULL;
	     vp = fr_pair_list_next(list, vp)) {
		edit_debug_attr_vp(request, vp, child);
		if (map) child = map_list_next(&map->child, child);
	}
}

static int edit_create_lhs_vp(request_t *request, TALLOC_CTX *ctx, edit_map_t *current)
{
	int err;
	fr_pair_t *vp;
	tmpl_dcursor_ctx_t lhs_cc;
	fr_dcursor_t lhs_cursor;

	fr_assert(current->lhs.create);

	/*
	 *	Now that we have the RHS values, go create the LHS vp.  We delay creating it until
	 *	now, because the RHS might just be nothing.  In which case we don't want to create the
	 *	LHS, and then discover that we need to delete it.
	 */
	fr_strerror_clear();
	vp = tmpl_dcursor_build_init(&err, ctx, &lhs_cc, &lhs_cursor, request, current->lhs.vpt, edit_list_pair_build, current);
	tmpl_dcursor_clear(&lhs_cc);
	if (!vp) {
		RWDEBUG("Failed creating attribute %s", current->lhs.vpt->name);
		return -1;
	}

	current->lhs.vp = vp;

	return 0;
}

/*	Apply the edits to a structural attribute..
 *
 *	Figure out what edits to do, and then do them.
 */
static int apply_edits_to_list(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	fr_pair_t *vp;
	fr_pair_list_t *children;
	bool copy_vps = true;
	int rcode;
	map_t const *map = current->map;
	tmpl_dcursor_ctx_t cc;
	fr_dcursor_t cursor;

	/*
	 *	RHS is a sublist, go apply that.
	 */
	if (!map->rhs) {
		children = &current->rhs.pair_list;
		copy_vps = false;
		goto apply_list;
	}

	/*
	 *	For RHS of data, it should be a string which contains the pairs to use.
	 */
	if (!current->rhs.vpt) {
		fr_value_box_t *box;
		fr_dict_attr_t const *da;
		fr_token_t token;

		if (tmpl_is_data(map->rhs)) {
			box = tmpl_value(map->rhs);

			if (box->type != FR_TYPE_STRING) {
				REDEBUG("Invalid data type for assignment to list");
				return -1;
			}

		} else {
			box = fr_value_box_list_head(&current->rhs.result);

			/*
			 *	Can't concatenate empty results.
			 */
			if (!box) {
				RWDEBUG("%s %s ... - Assignment failed to having no value on right-hand side", map->lhs->name, fr_tokens[map->op]);
				return -1;
			}

			/*
			 *	Mash all of the results together.
			 */
			if (fr_value_box_list_concat_in_place(box, box, &current->rhs.result, FR_TYPE_STRING, FR_VALUE_BOX_LIST_FREE, true, SIZE_MAX) < 0) {
				RWDEBUG("Failed converting result to string");
				return -1;
			}
		}

		da = tmpl_attr_tail_da(current->lhs.vpt);
		if (fr_type_is_group(da->type)) da = fr_dict_root(request->dict);

		children = &current->rhs.pair_list;

		/*
		 *	For exec, etc., parse the pair list from a string, in the context of the
		 *	parent VP.  Because we're going to be moving them to the parent VP at some
		 *	point.  The ones which aren't moved will get deleted in this function.
		 */
		token = fr_pair_list_afrom_str(current->ctx, da, box->vb_strvalue, box->vb_length, children);
		if (token == T_INVALID) {
			RPEDEBUG("Failed parsing string '%pV' as attribute list", box);
			return -1;
		}

		if (token != T_EOL) {
			REDEBUG("%s[%d] Failed to parse the entire string.", MAP_INFO);
			return -1;
		}

		copy_vps = false;
		goto apply_list;
	}

	fr_assert(current->rhs.vpt);
	fr_assert(tmpl_is_attr(current->rhs.vpt));

	/*
	 *	Doing no modifications to a list is a NOOP.
	 */
	vp = tmpl_dcursor_init(NULL, request, &cc, &cursor, request, current->rhs.vpt);
	if (!vp) {
		tmpl_dcursor_clear(&cc);
		return 0;
	}

	/*
	 *	Remove an attribute from a list.  The tmpl_dcursor and tmpl_parser ensures that the RHS
	 *	references are done in the context of the LHS attribute.
	 */
	if (map->op == T_OP_SUB_EQ) {
		fr_pair_t *next;

		/*
		 *	Loop over matching attributes, and delete them.
		 */
		RDEBUG2("%s %s %s", current->lhs.vpt->name, fr_tokens[T_OP_SUB_EQ], current->rhs.vpt->name);

		for ( ; vp != NULL; vp = next) {
			fr_pair_list_t *list;

			next = fr_dcursor_next(&cursor);

			list = fr_pair_parent_list(vp);
			fr_assert(list != NULL);

			/*
			 *	@todo - if this attribute is structural, then remove all children which aren't
			 *	immutable.  For now, this is good enough.
			 */
			if (fr_pair_immutable(vp)) {
				RWDEBUG("Not removing immutable %pP", vp);
				continue;
			}

			if (fr_edit_list_pair_delete(current->el, list, vp) < 0) {
				tmpl_dcursor_clear(&cc);
				return -1;
			}
		}

		tmpl_dcursor_clear(&cc);
		return 0;
	}

	/*
	 *	Check the RHS thing we're copying.
	 */
	if (fr_type_is_structural(vp->vp_type)) {
		tmpl_dcursor_clear(&cc);

		if (tmpl_attr_tail_num(current->rhs.vpt) == NUM_ALL) {
			REDEBUG("%s[%d] Wildcard for structural attribute %s is not yet implemented.", MAP_INFO, current->rhs.vpt->name);
			return -1;
		}

		children = &vp->vp_group;
		copy_vps = true;
		goto apply_list;
	}

	/*
	 *	Copy the attributes from the cursor to a temporary pair list.
	 */
	fr_pair_list_init(&current->rhs.pair_list);
	while (vp) {
		fr_pair_t *copy;

		copy = fr_pair_copy(request, vp);
		if (!copy) {
			fr_pair_list_free(&current->rhs.pair_list);
			tmpl_dcursor_clear(&cc);
			return -1;
		}
		fr_pair_append(&current->rhs.pair_list, copy);

		vp = fr_dcursor_next(&cursor);
	}
	tmpl_dcursor_clear(&cc);

	children = &current->rhs.pair_list;
	copy_vps = false;

	/*
	 *	Apply structural thingies!
	 */
apply_list:
	fr_assert(children != NULL);

	/*
	 *	If we have to create the LHS, then do so now.
	 */
	if (current->lhs.create && (edit_create_lhs_vp(request, state, current) < 0)) {
		return -1;
	}

	fr_assert(current->lhs.vp != NULL);

#ifdef STATIC_ANALYZER
	if (!current->lhs.vp) return -1;
#endif

	/*
	 *	Print the children before we do the modifications.
	 */
	RDEBUG2("%s %s {", current->lhs.vpt->name, fr_tokens[map->op]);
	if (fr_debug_lvl >= L_DBG_LVL_2) {
		RINDENT();
		edit_debug_attr_list(request, children, map);
		REXDENT();
	}
	RDEBUG2("}");

	if (current->el) {
		rcode = fr_edit_list_apply_list_assignment(current->el, current->lhs.vp, map->op, children, copy_vps);
		if (rcode < 0) RPERROR("Failed performing list '%s' operation", fr_tokens[map->op]);

	} else {
		fr_assert(map->op == T_OP_EQ);

		if (copy_vps) {
			fr_assert(children != &current->rhs.pair_list);
			fr_assert(fr_pair_list_empty(&current->rhs.pair_list));

			if (fr_pair_list_copy(current->lhs.vp, &current->rhs.pair_list, children) < 0) {
				rcode = 01;
				goto done;
			}
			children = &current->rhs.pair_list;
		} else {
			copy_vps = true; /* the  */
		}

		fr_pair_list_append(&current->lhs.vp->vp_group, children);
		PAIR_VERIFY(current->lhs.vp);
		rcode = 0;
	}

	/*
	 *	If the child list wasn't copied, then we just created it, and we need to free it.
	 */
done:
	if (!copy_vps) fr_pair_list_free(children);
	return rcode;
}

/*
 *	Apply the edits to a leaf attribute.  First we figure out where the results come from:
 *
 *		single value-box (e.g. tmpl_is_data(vpt)
 *		rhs value-box result list (we create a dcursor)
 *		RHS attribute reference (we create a nested dcursor to get the values from the pair list)
 *
 *	Then we figure out what to do with those values.
 *
 *		if it needs to be created, then create it and just mash the results in place
 *		otherwise apply the edits (+=, etc.) to an existing attribute.
 *
 *	@todo - move to using dcursors for all of the values.  The dcursor should exist in current->rhs.  It
 *	should be used even for TMPL_DATA and single value-boxes.  Once that's done, it becomes easier to use
 *	dcursors for xlats, too.
 */
static int apply_edits_to_leaf(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	fr_value_box_t *box = NULL;
	tmpl_dcursor_ctx_t cc;
	fr_dcursor_t cursor;
	fr_dcursor_t pair_cursor;
	bool single = false, pair = false;
	map_t const *map = current->map;

	if (!tmpl_is_attr(current->lhs.vpt)) {
		REDEBUG("%s[%d] The left side of an assignment must be an attribute reference", MAP_INFO);
		return -1;
	}

	/*
	 *	&Foo := { a, b, c }
	 *
	 *	There should be values in RHS result, all of value boxes.
	 */
	if (!map->rhs) {
		fr_assert(current->rhs.vpt == NULL);
		goto rhs_list;

	}

	if (!current->rhs.vpt) {
		/*
		 *	There's no RHS tmpl, so the result must be in in the parent RHS tmpl as data, OR in the RHS result list.
		 */
		if (tmpl_is_data(map->rhs)) {
			box = tmpl_value(map->rhs);
			single = true;

		} else if ((map->rhs->quote == T_SINGLE_QUOTED_STRING) || (map->rhs->quote == T_DOUBLE_QUOTED_STRING)) {
			/*
			 *	The caller asked for a string, so instead of returning a list, return a string.
			 *
			 *	If there's no output, then it's an empty string.
			 *
			 *	We have to check this here, because the quote is part of the tmpl, and we call
			 *	xlat_push(), which doesn't know about the quote.
			 */
			box = fr_value_box_list_head(&current->rhs.result);

			if (!box) {
				MEM(box = fr_value_box_alloc(state, FR_TYPE_STRING, NULL));
				fr_value_box_list_insert_tail(&current->rhs.result, box);

			} else if (fr_value_box_list_concat_in_place(box, box, &current->rhs.result, FR_TYPE_STRING,
							      FR_VALUE_BOX_LIST_FREE_BOX, true, 8192) < 0) {
				RWDEBUG("Failed converting result to string");
				return -1;
			}
			box = fr_value_box_list_head(&current->rhs.result);
			single = true;

		} else {
		rhs_list:
			if (fr_value_box_list_num_elements(&current->rhs.result) == 1) {
				box = fr_value_box_list_head(&current->rhs.result);
				single = true;
			} else {
				box = fr_dcursor_init(&cursor, fr_value_box_list_dlist_head(&current->rhs.result));
			}
		}
	} else {
		fr_pair_t *vp;
		int err;

		/*
		 *	We have a temporary tmpl on the RHS.  It MUST be an attribute, because everything else
		 *	was expanded to a value-box list.
		 */
		fr_assert(tmpl_is_attr(current->rhs.vpt));

		/*
		 *	Get a cursor over the pairs.  If there are no matching pairs, then we do nothing.
		 */
		vp = tmpl_dcursor_init(&err, request, &cc, &pair_cursor, request, current->rhs.vpt);
		if (!vp) {
			tmpl_dcursor_clear(&cc);
			return 0;
		}

		box = fr_pair_dcursor_nested_init(&cursor, &pair_cursor); // the list is unused
		pair = true;
	}

	if (!box) {
		if (map->op != T_OP_SET) {
			RWDEBUG("%s %s ... - Assignment failed - No value on right-hand side", map->lhs->name, fr_tokens[map->op]);
			return -1;
		}

		/*
		 *	Set is "delete, then add".
		 */
		RDEBUG2("%s :=", current->lhs.vpt->name);
		goto done;
	}

	/*
	 *	The parent is a structural type.  The RHS is a temporary list or attribute, which we can just
	 *	add to the parents pair list.  The parent will then take care of merging that pair list into
	 *	the appropriate place.
	 */
	if (current->temporary_pair_list) {
		fr_pair_list_t *list = &current->parent->rhs.pair_list;
		fr_pair_t *vp;

		if (!current->parent->lhs.vp) {
			if (edit_create_lhs_vp(request, request, current->parent) < 0) return -1;
		}

		while (box) {
			/*
			 *	Create (or find) all intermediate attributes.  The LHS map might have multiple
			 *	attribute names in it.
			 *
			 *	@todo - audit other uses of tmpl_attr_tail_da() and fr_pair_afrom_da() in this file.
			 */
			if (pair_append_by_tmpl_parent(current->parent->lhs.vp, &vp, list, current->lhs.vpt, true) < 0) {
				RWDEBUG("Failed creating attribute %s", current->lhs.vpt->name);
				return -1;
			}

			vp->op = map->op;
			if (fr_value_box_cast(vp, &vp->data, vp->vp_type, vp->da, box) < 0) return -1;

			if (single) break;

			box = fr_dcursor_next(&cursor);
		}

		goto done;
	}

	/*
	 *	If we're supposed to create the LHS, then go do that.
	 */
	if (current->lhs.create) {
		fr_dict_attr_t const *da = tmpl_attr_tail_da(current->lhs.vpt);
		fr_pair_t *vp;

		/*
		 *	Something went wrong creating the value, it's a failure.  Note that we fail _all_
		 *	subsequent assignments, too.
		 */
		if (fr_type_is_null(box->type)) goto fail;

		if (edit_create_lhs_vp(request, state, current) < 0) goto fail;

		fr_assert(current->lhs.vp_parent != NULL);
		fr_assert(fr_type_is_structural(current->lhs.vp_parent->vp_type));

		vp = current->lhs.vp;

		/*
		 *	There's always at least one LHS vp created.  So we apply that first.
		 */
		RDEBUG2("%s %s %pV", current->lhs.vpt->name, fr_tokens[map->op], box);

		/*
		 *	The VP has already been inserted into the edit list, so we don't need to edit it's
		 *	value, we can just mash it in place.
		 */
		if (fr_value_box_cast(vp, &vp->data, vp->vp_type, vp->da, box) < 0) goto fail;
		vp->op = T_OP_EQ;

		if (single) goto done;

		/*
		 *	Loop over the remaining items, adding the VPs we've just created.
		 */
		while ((box = fr_dcursor_next(&cursor)) != NULL) {
			RDEBUG2("%s %s %pV", current->lhs.vpt->name, fr_tokens[map->op], box);

			MEM(vp = fr_pair_afrom_da(current->lhs.vp_parent, da));
			if (fr_value_box_cast(vp, &vp->data, vp->vp_type, vp->da, box) < 0) goto fail;

			if (fr_edit_list_insert_pair_tail(state->el, &current->lhs.vp_parent->vp_group, vp) < 0) goto fail;
			vp->op = T_OP_EQ;
		}

		goto done;
	}

	/*
	 *	If we're not creating a temporary list, we must be editing an existing attribute on the LHS.
	 *
	 *	We have two remaining cases.  One is the attribute was just created with "=" or ":=", so we
	 *	can just mash its value.  The second is that the attribute already exists, and we're editing
	 *	it's value using something like "+=".
	 */
	fr_assert(current->lhs.vp != NULL);

#ifdef STATIC_ANALYZER
	if (!current->lhs.vp) return -1;
#endif

	/*
	 *	All other operators are "modify in place", of the existing current->lhs.vp
	 */
	while (box) {
		RDEBUG2("%s %s %pV", current->lhs.vpt->name, fr_tokens[map->op], box);

		/*
		 *	The apply function also takes care of doing data type upcasting and conversion.  So we don't
		 *	have to check for compatibility of the data types on the LHS and RHS.
		 */
		if (fr_edit_list_apply_pair_assignment(current->el,
						       current->lhs.vp,
						       map->op,
						       box) < 0) {
		fail:
			RPEDEBUG("Assigning value to %s failed", map->lhs->name);
			if (pair) tmpl_dcursor_clear(&cc);
			return -1;
		}

		if (single) break;

		box = fr_dcursor_next(&cursor);
	}

done:
	if (pair) tmpl_dcursor_clear(&cc);
	fr_value_box_list_talloc_free(&current->rhs.result);

	return 0;
}


/** Simple pair building callback for use with tmpl_dcursors
 *
 *  Which always appends the new pair to the tail of the list
 *  since it is only called when no matching pairs were found when
 *  walking the list.
 *
 *  Note that this function is called for all intermediate nodes which are built!
 *
 *
 *
 * @param[in] parent		to allocate new pair within.
 * @param[in,out] cursor	to append new pair to.
 * @param[in] da		of new pair.
 * @param[in] uctx		unused.
 * @return
 *	- newly allocated #fr_pair_t.
 *	- NULL on error.
 */
static fr_pair_t *edit_list_pair_build(fr_pair_t *parent, fr_dcursor_t *cursor, fr_dict_attr_t const *da, void *uctx)
{
	fr_pair_t *vp;
	edit_map_t *current = uctx;

	vp = fr_pair_afrom_da(parent, da);
	if (!vp) return NULL;

	current->lhs.vp_parent = parent;
	current->lhs.vp = vp;

	if (fr_edit_list_insert_pair_tail(current->el, &parent->vp_group, vp) < 0) {
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

	return vp;
}

#define DECLARE(_x) static int _x(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)

DECLARE(expand_lhs);
DECLARE(check_lhs);
DECLARE(check_lhs_value);
DECLARE(check_lhs_nested);
DECLARE(expanded_lhs_attribute);
DECLARE(expanded_lhs_value);

/*
 *	Clean up the current state, and go to the next map.
 */
static int next_map(UNUSED request_t *request, UNUSED unlang_frame_state_edit_t *state, edit_map_t *current)
{
	TALLOC_FREE(current->lhs.to_free);
	TALLOC_FREE(current->rhs.to_free);
	fr_pair_list_free(&current->rhs.pair_list);
	current->lhs.vp = NULL;
	current->lhs.vp_parent = NULL;
	current->lhs.vpt = NULL;
	current->rhs.vpt = NULL;

	current->map = map_list_next(current->map_head, current->map);
	current->func = expand_lhs;

	/*
	 *	Don't touch the other callbacks.
	 */

	return 0;
}

/*
 *	Validate the RHS of an expansion.
 */
static int check_rhs(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	map_t const *map = current->map;

	DEBUG("%s map %s %s ...", __FUNCTION__, map->lhs->name, fr_tokens[map->op]);

	/*
	 *	:= is "remove all matching, and then add".  So if even if we don't add anything, we still remove things.
	 *
	 *	If we deleted the attribute when processing the LHS, then you couldn't reference an attribute
	 *	in it's own assignment:
	 *
	 *		&foo := %(tolower:foo)
	 *
	 *	so we have to delay the deletion until the RHS has been fully expanded.  But we don't always
	 *	delete everything. e.g. if the map is:
	 *
	 *		&foo[1] := %(tolower:foo[1])
	 *
	 *	The we just apply the assignment to the LHS, over-writing it's value.
	 */
	if ((map->op == T_OP_SET) && (tmpl_attr_tail_num(current->lhs.vpt) == NUM_UNSPEC)) {
		tmpl_dcursor_ctx_t cc;
		fr_dcursor_t cursor;
		bool first = fr_type_is_structural(tmpl_attr_tail_da(current->lhs.vpt)->type);

		while (true) {
			int err;
			fr_pair_t *vp, *parent;

			/*
			 *	Reinitialize the cursor for every VP.  This is because
			 *	fr_dcursor_remove() does not work with tmpl_dcursors, as the
			 *	tmpl_dcursor code does not set the "remove" callback.
			 *
			 *	Once that's implemented, we also need to update the edit list API to
			 *	allow for "please delete children"?
			 */
			vp = tmpl_dcursor_init(&err, current->ctx, &cc, &cursor, request, current->lhs.vpt);
			if (!vp) break;

			/*
			 *	For structural attributes, we leave the first one, and delete the subsequent
			 *	ones.  That way we leave the main lists alone ("request", "reply", "control", etc.)
			 *
			 *	For leaf attributes, we just skip this step, as "first" is always "false".
			 */
			if (first) {
				first = false;
				if (fr_edit_list_free_pair_children(current->el, vp) < 0) return -1;
				vp = fr_dcursor_next(&cursor);
				if (!vp) goto clear;
				continue;

			} else if (fr_type_is_structural(tmpl_attr_tail_da(current->lhs.vpt)->type)) {
				/*
				 *	We skipped the first structural member, so keep skipping it for all of the next vps.
				 */
				vp = fr_dcursor_next(&cursor);
				if (!vp) {
				clear:
					tmpl_dcursor_clear(&cc);
					break;
				}
			}

			parent = fr_pair_parent(vp);
			fr_assert(parent != NULL);

			/*
			 *	We can't delete these ones.
			 */
			fr_assert(vp != request->pair_list.request);
			fr_assert(vp != request->pair_list.reply);
			fr_assert(vp != request->pair_list.control);
			fr_assert(vp != request->pair_list.state);

			if (fr_edit_list_pair_delete(current->el, &parent->vp_group, vp) < 0) return -1;
			tmpl_dcursor_clear(&cc);
		}
	}

	/*
	 *	@todo - Realize the RHS box value.  By moving the code in apply_edits_to_leaf() to a common function,
	 *	and getting the box dcursor here.
	 *
	 *	Then, get a cursor for the LHS vp, and loop over it, applying the edits in the operator, using
	 *	the comparisons in the RHS box.
	 *
	 *	This lets us use array indexes (or more complex things) on the LHS, and means that we don't
	 *	have to realize the VPs and use horrible hacks.
	 */
	if (current->parent && (current->parent->map->op == T_OP_SUB_EQ)) {
		fr_assert(current->temporary_pair_list);
		fr_assert(tmpl_is_attr(current->lhs.vpt)); /* can only apply edits to real attributes */
		fr_assert(map->rhs);			   /* can only filter on leaf attributes */

#if 0
		{
			// dcursor_init over current->lhs.vpt, using children of current->parent.lhs_vp
			//
			// and then use the dcursor from the apply_edits_to_leaf() to get value-boxes
			rcode = fr_value_box_cmp_op(map->op, &vp->data, box);
			if (rcode < 0) return -1;

			if (!rcode) continue;

			if (fr_edit_list_pair_delete(el, list, vp) < 0) return -1;
		}

		return next_map(request, state, current);
#endif
	}

	if (fr_type_is_leaf(tmpl_attr_tail_da(current->lhs.vpt)->type)) {
		if (apply_edits_to_leaf(request, state, current) < 0) return -1;
	} else {
		if (apply_edits_to_list(request, state, current) < 0) return -1;
	}

	return next_map(request, state, current);
}

/*
 *	The RHS map is a sublist.  Go expand that by creating a child expansion context, and returning to the
 *	main loop.
 */
static int expand_rhs_list(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	map_t const *map = current->map;
	edit_map_t *child;

	DEBUG("%s map %s %s ...", __FUNCTION__, map->lhs->name, fr_tokens[map->op]);

	/*
	 *	If there's no RHS tmpl, then the RHS is a child list.
	 */
	fr_assert(!map->rhs);

	/*
	 *	Fast path: child is empty, we don't need to do anything.
	 */
	if (fr_dlist_empty(&map->child.head)) {
		if (fr_type_is_leaf(tmpl_attr_tail_da(current->lhs.vpt)->type)) {
			REDEBUG("%s[%d] Cannot assign empty list to a normal data type", MAP_INFO);
			return -1;
		}

		return check_rhs(request, state, current);
	}

	/*
	 *	Allocate a new child structure if necessary.
	 */
	child = current->child;
	if (!child) {
		MEM(child = talloc_zero(state, edit_map_t));
		current->child = child;
		child->parent = current;
	}

	/*
	 *	Initialize the child structure.  There's no edit list here, as we're
	 *	creating a temporary pair list.  Any edits to this list aren't
	 *	tracked, as it only exists in current->parent->rhs.pair_list.
	 *
	 *	The parent edit_state_t will take care of applying any edits to the
	 *	parent vp.  Any child pairs which aren't used will be freed.
	 */
	child->el = NULL;
	child->map_head = &map->child;
	child->map = map_list_head(child->map_head);
	child->func = expand_lhs;

	if (fr_type_is_leaf(tmpl_attr_tail_da(current->lhs.vpt)->type)) {
		child->ctx = child;
		child->check_lhs = check_lhs_value;
		child->expanded_lhs = expanded_lhs_value;
	} else {
		child->ctx = current->lhs.vp ? (TALLOC_CTX *) current->lhs.vp : (TALLOC_CTX *) child;
		child->check_lhs = check_lhs_nested;
		child->expanded_lhs = expanded_lhs_attribute;
		child->temporary_pair_list = true;
	}

	memset(&child->lhs, 0, sizeof(child->lhs));
	memset(&child->rhs, 0, sizeof(child->rhs));

	fr_pair_list_init(&child->rhs.pair_list);
	fr_value_box_list_init(&child->lhs.result);
	fr_value_box_list_init(&child->rhs.result);

	/*
	 *	Continue back with the RHS when we're done processing the
	 *	child.  The go process the child.
	 */
	current->func = check_rhs;
	state->current = child;
	RINDENT();
	return 0;
}


/*
 *	Expand the RHS of an assignment operation.
 */
static int expand_rhs(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	int rcode;
	map_t const *map = current->map;

	if (!map->rhs) return expand_rhs_list(request, state, current);

	DEBUG("%s map %s %s %s", __FUNCTION__, map->lhs->name, fr_tokens[map->op], map->rhs->name);

	/*
	 *	Turn the RHS into a tmpl_t.  This can involve just referencing an existing
	 *	tmpl in map->rhs, or expanding an xlat to get an attribute name.
	 */
	rcode = tmpl_to_values(state, &current->rhs, request, map->rhs);
	if (rcode < 0) return -1;

	if (rcode == 1) {
		current->func = check_rhs;
		return 1;
	}

	return check_rhs(request, state, current);
}

/*
 *	The LHS is a value, and the parent is a leaf.  There is no RHS.
 *
 *	Do some validations, and move the value-boxes to the parents result list.
 */
static int check_lhs_value(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	map_t const		*map = current->map;
	fr_value_box_t		*box;
	fr_pair_t		*vp;
	tmpl_t const		*vpt;
	tmpl_dcursor_ctx_t	cc;
	fr_dcursor_t		cursor;

	fr_assert(current->parent);

	DEBUG("%s map %s", __FUNCTION__, map->lhs->name);

	if (tmpl_is_data(map->lhs)) {
		vpt = map->lhs;

	data:
		MEM(box = fr_value_box_alloc_null(state));
		if (fr_value_box_copy(box, box, tmpl_value(vpt)) < 0) return -1;

		fr_value_box_list_insert_tail(&current->parent->rhs.result, box);

		return next_map(request, state, current);
	}

	if (!current->lhs.vpt) {
		vpt = map->lhs;

		/*
		 *
		 */
		if (tmpl_is_xlat(vpt)) return next_map(request,state, current);

	attr:
		fr_assert(tmpl_is_attr(vpt));

		/*
		 *	Loop over the attributes, copying their value-boxes to the parent list.
		 */
		vp = tmpl_dcursor_init(NULL, request, &cc, &cursor, request, vpt);
		while (vp) {
			MEM(box = fr_value_box_alloc_null(state));
			if (fr_value_box_copy(box, box, &vp->data) < 0) return -1;

			fr_value_box_list_insert_tail(&current->parent->rhs.result, box);

			vp = fr_dcursor_next(&cursor);
		}
		tmpl_dcursor_clear(&cc);

		return next_map(request, state, current);
	}

	vpt = current->lhs.vpt;

	if (tmpl_is_data(vpt)) goto data;

	goto attr;
}

/*
 *	We've expanded the LHS (xlat or exec) into a value-box list.  The result gets moved to the parent
 *	result list.
 *
 *	There's no RHS, so once the LHS has been expanded, we jump immediately to the next entry.
 */
static int expanded_lhs_value(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	fr_dict_attr_t const *da;
	fr_type_t type;
	fr_value_box_t *box = fr_value_box_list_head(&current->lhs.result);
	fr_value_box_t *dst;
	fr_sbuff_unescape_rules_t *erules = NULL;

	fr_assert(current->parent);

	if (!box) {
		RWDEBUG("Failed exapnding result");
		return -1;
	}

	fr_assert(tmpl_is_attr(current->parent->lhs.vpt));

	/*
	 *	There's only one value-box, just use it as-is.  We let the parent handler complain about being
	 *	able to parse (or not) the value.
	 */
	if (!fr_value_box_list_next(&current->lhs.result, box)) goto done;

	/*
	 *	Figure out how to parse the string.
	 */
	da = tmpl_attr_tail_da(current->parent->lhs.vpt);
	if (fr_type_is_structural(da->type)) {
		fr_assert(da->type == FR_TYPE_GROUP);

		type = FR_TYPE_STRING;

	} else if (fr_type_is_variable_size(da->type)) {
		type = da->type;

	} else {
		type = FR_TYPE_STRING;
	}

	/*
	 *	Mash all of the results together.
	 */
	if (fr_value_box_list_concat_in_place(box, box, &current->lhs.result, type, FR_VALUE_BOX_LIST_FREE, true, SIZE_MAX) < 0) {
		RWDEBUG("Failed converting result to '%s' - no memory", fr_type_to_str(type));
		return -1;
	}

	/*
	 *	Strings, etc. get assigned to the parent.  Fixed-size things ger parsed according to their values / enums.
	 */
	if (!fr_type_is_fixed_size(da->type)) {
	done:
		fr_value_box_list_move(&current->parent->rhs.result, &current->lhs.result);
		return next_map(request, state, current);
	}

	/*
	 *	Try to re-parse the box as the destination data type.
	 */
	MEM(dst = fr_value_box_alloc(state, type, da));

	erules = fr_value_unescape_by_quote[current->map->lhs->quote];

	if (fr_value_box_from_str(dst, dst, da->type, da, box->vb_strvalue, box->vb_length, erules, box->tainted) < 0) {
		RWDEBUG("Failed converting result to '%s' - %s", fr_type_to_str(type), fr_strerror());
		return -1;
	}

	fr_value_box_list_talloc_free(&current->lhs.result);
	fr_value_box_list_insert_tail(&current->parent->rhs.result, dst);
	return next_map(request, state, current);
}

/*
 *	Check the LHS of an assignment, for
 *
 *		foo = { bar = baz }	LHS bar
 *
 *	There are more limitations here on the attr / op / value format then for the top-level check_lhs().
 */
static int check_lhs_nested(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	map_t const *map = current->map;

	fr_assert(current->parent != NULL);

	DEBUG("%s map %s", __FUNCTION__, map->lhs->name);

	/*
	 *	Don't create the leaf.  The apply_edits_to_leaf() function will create them after the RHS has
	 *	been expanded.
	 */
	if (fr_type_is_leaf(tmpl_attr_tail_da(current->lhs.vpt)->type)) {
		return expand_rhs(request, state, current);
	}

	/*
	 *	We have a parent, so we know that attribute exist.  Which means that we don't need to call a
	 *	cursor function to create this VP.
	 */

	/*
	 *	We create this VP in the "current" context, so that it's freed on
	 *	error.  If we create it in the LHS VP context, then we have to
	 *	manually free rhs.pair_list on any error.  Creating it in the
	 *	"current" context means we have to reparent it when we move it to the
	 *	parent list, but fr_edit_list_apply_list_assignment() does that
	 *	anyways.
	 */
	MEM(current->lhs.vp = fr_pair_afrom_da(current->ctx, tmpl_attr_tail_da(current->lhs.vpt)));
	fr_pair_append(&current->parent->rhs.pair_list, current->lhs.vp);
	current->lhs.vp->op = map->op;

	return expand_rhs(request, state, current);
}

/*
 *	The LHS tmpl is now an attribute reference.  Do some sanity checks on tmpl_attr_tail_num(), operators, etc.
 *	Once that's done, go expand the RHS.
 */
static int check_lhs(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	map_t const *map = current->map;
	int			err;
	fr_pair_t		*vp;
	tmpl_dcursor_ctx_t	cc;
	fr_dcursor_t		cursor;

	current->lhs.create = false;
	current->lhs.vp = NULL;

	DEBUG3("%s map %s %s ...", __FUNCTION__, map->lhs->name, fr_tokens[map->op]);

	/*
	 *	Create the attribute, including any necessary parents.
	 */
	if ((map->op == T_OP_EQ) ||
	    (fr_type_is_leaf(tmpl_attr_tail_da(current->lhs.vpt)->type) && fr_comparison_op[map->op])) {
		if (tmpl_attr_tail_num(current->lhs.vpt) == NUM_UNSPEC) {
			current->lhs.create = true;

			/*
			 *	Don't go to expand_rhs(), as we have to see if the attribute exists.
			 */
		}

	} else if (map->op == T_OP_SET) {
		if (tmpl_attr_tail_num(current->lhs.vpt) == NUM_UNSPEC) {
			current->lhs.create = true;
			return expand_rhs(request, state, current);
		}

		/*
		 *	Else we're doing something like:
		 *
		 *		&foo[1] := bar
		 *
		 *	the attribute has to exist, and we modify its value as a leaf.
		 *
		 *	If the RHS is a list, we can set the children for a LHS structural type.
		 *	But if the LHS is a leaf, then we can't do:
		 *
		 *		&foo[3] := { a, b, c}
		 *
		 *	because foo[3] is a single leaf value, not a list.
		 */
		if (!map->rhs && fr_type_is_leaf(tmpl_attr_tail_da(current->lhs.vpt)->type)) {
			RWDEBUG("Cannot set one entry to multiple values for %s", current->lhs.vpt->name);
			return -1;
		}

	} else if (map->op == T_OP_ADD_EQ) {
		/*
		 *	For "+=", if there's no existing attribute, create one, and rewrite the operator we
		 *	apply to ":=".  Which also means moving the operator be in edit_map_t, and then updating the
		 *	"apply" funtions above to use that for the operations, but map->op for printing.
		 *
		 *	This allows "foo += 4" to set "foo := 4" when the attribute doesn't exist.  It also allows us
		 *	to do list appending to an empty list.  But likely only for strings, octets, and numbers.
		 *	Nothing much else makes sense.
		 */

		switch (tmpl_attr_tail_da(current->lhs.vpt)->type) {
		case FR_TYPE_NUMERIC:
		case FR_TYPE_OCTETS:
		case FR_TYPE_STRING:
		case FR_TYPE_STRUCTURAL:
			current->lhs.create = true;
			break;

		default:
			break;
		}
	}

	/*
	 *	Find the VP.  If the operation is "=" or ":=", then it's OK for the VP to not exist.
	 *
	 *	@todo - put the cursor into the LHS, and then set lhs.vp == NULL
	 *	use the cursor in apply_edits_to_leaf()
	 */
	fr_strerror_clear();
	vp = tmpl_dcursor_init(&err, current->ctx, &cc, &cursor, request, current->lhs.vpt);
	tmpl_dcursor_clear(&cc);
	if (!vp) {
		if (!current->lhs.create) {
			RWDEBUG("Failed finding %s", current->lhs.vpt->name);
			return -1;
		}

		/*
		 *	Else we need to create it.
		 */
		return expand_rhs(request, state, current);

	} else if (current->lhs.create) {
		/*
		 *	&foo[1] := bar
		 *	&foo = bar
		 */
		current->lhs.create = false;

		if (map->rhs && fr_type_is_structural(vp->vp_type) && tmpl_is_exec(map->rhs)) {
			int rcode;

			current->lhs.vp = vp;
			current->lhs.vp_parent = fr_pair_parent(vp);

			rcode = tmpl_to_values(state, &current->rhs, request, map->rhs);
			if (rcode < 0) return -1;

			if (rcode == 1) {
				current->func = check_rhs;
				return 1;
			}

			return expand_rhs(request, state, current);
		}

		/*
		 *	We found it, but the attribute already exists.  This
		 *	is a NOOP, where we ignore this assignment.
		 */
		if (map->op == T_OP_EQ) {
			return next_map(request, state, current);
		}

		/*
		 *	&foo[1] exists, don't bother deleting it.  Just over-write its value.
		 */
		fr_assert((map->op == T_OP_SET) || (map->op == T_OP_ADD_EQ));
		fr_assert((map->op == T_OP_ADD_EQ) || tmpl_attr_tail_num(map->lhs) != NUM_UNSPEC);

		// &control := ...
	}

	/*
	 *	We forbid operations on immutable leaf attributes.
	 *
	 *	If a list contains an immutable attribute, then we can still operate on the list, but instead
	 *	we look at each VP we're operating on.
	 */
	if (fr_type_is_leaf(vp->vp_type) && vp->vp_immutable) {
		RWDEBUG("Cannot modify immutable value for %s", current->lhs.vpt->name);
		return -1;
	}

	/*
	 *	We found an existing attribute, with a modification operator.
	 */
	current->lhs.vp = vp;
	current->lhs.vp_parent = fr_pair_parent(current->lhs.vp);
	return expand_rhs(request, state, current);
}

/*
 *	We've expanding the LHS into a string.  Now convert it to an attribute.
 *
 *		foo := bar		LHS foo
 *		foo = { bar = baz }	LHS bar
 */
static int expanded_lhs_attribute(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	REXDENT();

	if (tmpl_attr_from_result(state, current->map, &current->lhs, request) < 0) return -1;

	return current->check_lhs(request, state, current);
}

/*
 *	Take the LHS of a map, and figure out what it is.  Data and attributes are immediately processed.
 *	xlats and execs are expanded, and then their expansion is checked.
 *
 *	This function is called for all variants of the LHS:
 *
 *		foo := bar		LHS foo
 *		foo = { bar = baz }	LHS bar
 *		foo = { 1, 2, 3, 4 }	LHS 1, 2, etc.
 *
 */
static int expand_lhs(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	int rcode;
	map_t const *map = current->map;

	DEBUG("%s map %s %s ...", __FUNCTION__, map->lhs->name, fr_tokens[map->op]);

	fr_assert(fr_value_box_list_empty(&current->lhs.result));	/* Should have been consumed */
	fr_assert(fr_value_box_list_empty(&current->rhs.result));	/* Should have been consumed */

	rcode = tmpl_to_values(state, &current->lhs, request, map->lhs);
	if (rcode < 0) return -1;

	if (rcode == 1) {
		current->func = current->expanded_lhs;
		return 1;
	}

	return current->check_lhs(request, state, current);
}

/** Apply a map (recursively) to a request.
 *
 * @param[out] p_result	The rcode indicating what the result
 *      		of the operation was.
 * @param[in] request	The current request.
 * @param[in] frame	Current stack frame.
 * @return
 *	- UNLANG_ACTION_CALCULATE_RESULT changes were applied.
 *	- UNLANG_ACTION_PUSHED_CHILD async execution of an expansion is required.
 */
static unlang_action_t process_edit(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_frame_state_edit_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_edit_t);

	/*
	 *	Keep running the "expand map" function until done.
	 */
	while (state->current) {
		while (state->current->map) {
			int rcode;

			if (!state->current->map->rhs) {
				DEBUG("MAP %s ...", state->current->map->lhs->name);
			} else {
				DEBUG("MAP %s ... %s", state->current->map->lhs->name, state->current->map->rhs->name);

				DEBUG("\t%08x", state->current->map->rhs->type);
			}

			rcode = state->current->func(request, state, state->current);
			if (rcode < 0) {
				RINDENT_RESTORE(request, &state->indent);

				fr_edit_list_abort(state->el);
				TALLOC_FREE(frame->state);
				repeatable_clear(frame);
				*p_result = RLM_MODULE_NOOP;

				/*
				 *	Expansions, etc. are SOFT
				 *	failures, which simply don't
				 *	apply the operations.
				 */
				return UNLANG_ACTION_CALCULATE_RESULT;
			}

			if (rcode == 1) {
				repeatable_set(frame);
				return UNLANG_ACTION_PUSHED_CHILD;
			}
		}

		/*
		 *	Stop if there's no parent to process.
		 */
		if (!state->current->parent) break;

		state->current = state->current->parent;
		REXDENT();	/* "push child" has called RINDENT */
	}

	/*
	 *	Freeing the edit list will automatically commit the edits.
	 */

	*p_result = RLM_MODULE_NOOP;
	return UNLANG_ACTION_CALCULATE_RESULT;
}

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
static unlang_action_t unlang_edit_state_init(rlm_rcode_t *p_result, request_t *request, unlang_stack_frame_t *frame)
{
	unlang_edit_t			*edit = unlang_generic_to_edit(frame->instruction);
	unlang_frame_state_edit_t	*state = talloc_get_type_abort(frame->state, unlang_frame_state_edit_t);
	edit_map_t			*current = &state->first;

	state->current = current;
	fr_value_box_list_init(&current->lhs.result);
	fr_value_box_list_init(&current->rhs.result);

	/*
	 *	The edit list creates a local pool which should
	 *	generally be large enough for most edits.
	 */
	MEM(state->el = fr_edit_list_alloc(state, map_list_num_elements(&edit->maps)));

	current->ctx = state;
	current->el = state->el;
	current->map_head = &edit->maps;
	current->map = map_list_head(current->map_head);
	fr_pair_list_init(&current->rhs.pair_list);
	current->func = expand_lhs;
	current->check_lhs = check_lhs;
	current->expanded_lhs = expanded_lhs_attribute;

	/*
	 *	Save current indentation for the error path.
	 */
	RINDENT_SAVE(&state->indent, request);

	/*
	 *	Call process_edit to do all of the work.
	 */
	frame_repeat(frame, process_edit);
	return process_edit(p_result, request, frame);
}


void unlang_edit_init(void)
{
	unlang_register(UNLANG_TYPE_EDIT,
			   &(unlang_op_t){
				.name = "edit",
				.interpret = unlang_edit_state_init,
				.frame_state_size = sizeof(unlang_frame_state_edit_t),
				.frame_state_type = "unlang_frame_state_edit_t",
			   });
}
