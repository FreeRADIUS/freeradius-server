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

typedef struct {
	fr_value_box_list_t	result;			//!< result of expansion
	tmpl_t const		*vpt;			//!< expanded tmpl
	tmpl_t			*to_free;		//!< tmpl to free.
	fr_pair_t		*vp;			//!< VP referenced by tmpl.
	fr_pair_t		*vp_parent;		//!< parent of the current VP
	fr_pair_list_t		pair_list;		//!< for structural attributes
} edit_result_t;

typedef struct edit_map_s edit_map_t;

typedef struct unlang_frame_state_edit_s unlang_frame_state_edit_t;

typedef int (*unlang_edit_expand_t)(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current);

struct edit_map_s {
	fr_edit_list_t		*el;			//!< edit list

	edit_map_t		*parent;
	edit_map_t		*child;

	map_list_t const	*map_head;
	map_t const		*map;			//!< the map to evaluate

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

	edit_map_t		*current;			//!< what we're currently doing.
	edit_map_t		first;
};

static int templatize_to_attribute(TALLOC_CTX *ctx, edit_result_t *out, request_t *request) CC_HINT(nonnull);
static int templatize_to_value(TALLOC_CTX *ctx, edit_result_t *out, fr_pair_t const *lhs, request_t *request) CC_HINT(nonnull);

#define MAP_INFO cf_filename(map->ci), cf_lineno(map->ci)

/*
 *  Convert a value-box list to a LHS attribute #tmpl_t
 */
static int templatize_to_attribute(TALLOC_CTX *ctx, edit_result_t *out, request_t *request)
{
	ssize_t slen;
	fr_value_box_t *box = fr_dlist_head(&out->result);

	/*
	 *	Mash all of the results together.
	 */
	if (fr_value_box_list_concat_in_place(box, box, &out->result, FR_TYPE_STRING, FR_VALUE_BOX_LIST_FREE, true, SIZE_MAX) < 0) {
		RPEDEBUG("Left side expansion failed");
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
						.prefix = TMPL_ATTR_REF_PREFIX_NO
					}
				   });
	if (slen <= 0) {
		RPEDEBUG("Left side expansion result \"%s\" is not an attribute reference", box->vb_strvalue);
		return -1;
	}

	out->vpt = out->to_free;
	fr_dlist_talloc_free(&out->result);

	return 0;
}

/*
 *  Convert a value-box list to a RHS #tmpl_t
 *
 *  This doesn't work for structural types.  If "type" is structural,
 *  the calling code should parse the RHS as a set of VPs, and return
 *  that.
 */
static int templatize_to_value(TALLOC_CTX *ctx, edit_result_t *out, fr_pair_t const *lhs, request_t *request)
{
	fr_type_t type = lhs->vp_type;
	fr_value_box_t *box = fr_dlist_head(&out->result);

	if (!box) {
		RWDEBUG("No value found for assignment");
		return -1;
	}

	/*
	 *	There's only one box, and it's the correct type.  Just
	 *	return that.  This is the fast path.
	 */
	if (fr_type_is_leaf(type) && (type == box->type) && !fr_dlist_next(&out->result, box)) goto make_tmpl;

	/*
	 *	Slow path: mash all of the results together as a
	 *	string and then cast it to the correct data type.
	 *
	 *	@todo - allow groups to be returned for leaf attributes.
	 */
	if (fr_value_box_list_concat_in_place(box, box, &out->result, FR_TYPE_STRING, FR_VALUE_BOX_LIST_FREE, true, SIZE_MAX) < 0) {
		RPEDEBUG("Right side expansion failed");
		return -1;
	}

make_tmpl:
	if (tmpl_afrom_value_box(ctx, &out->to_free, box, false) < 0) {
			RPEDEBUG("Failed parsing data %pV", box);
		return -1;
	}

	out->vpt = out->to_free;
	fr_dlist_talloc_free(&out->result);

	return 0;
}

/** Expand a #tmpl_t to a #fr_value_box_list
 *
 *  Which will later be converted by the above functions back to a
 *  "realized" tmpl, which holds a TMPL_TYPE_DATA or TMPL_TYPE_ATTR.
 */
static int template_realize(TALLOC_CTX *ctx, fr_value_box_list_t *list, request_t *request, tmpl_t const *vpt)
{
	switch (vpt->type) {
	case TMPL_TYPE_DATA:
	case TMPL_TYPE_ATTR:
	case TMPL_TYPE_LIST:
		return 0;

	case TMPL_TYPE_EXEC:
		if (unlang_tmpl_push(ctx, list, request, vpt, NULL) < 0) return -1;
		return 1;

	case TMPL_TYPE_XLAT:
		if (unlang_xlat_push(ctx, NULL, list, request, tmpl_xlat(vpt), false) < 0) return -1;
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


/** Apply the edits.  Broken out for simplicity
 *
 *  The edits are applied as:
 *
 *  For leaves, merge RHS #fr_value_box_list_t, so that we have only one #fr_value_box_t
 *
 *  Loop over VPs on the LHS, doing the operation with the RHS.
 *
 *  For now, we only support one VP on the LHS, and one value-box on
 *  the RHS.  Fixing this means updating templatize_to_value() to peek at
 *  the RHS list, and if they're all of the same data type, AND the
 *  same data type as the expected output, leave them alone.  This
 *  lets us do things like:
 *
 *	&Foo-Bar += &Baz[*]
 *
 *  which is an implicit sum over all RHS "Baz" attributes.
 */
static int apply_edits_to_list(request_t *request, edit_map_t *current)
{
	fr_pair_t *vp;
	fr_pair_list_t *children;
	fr_value_box_t const *rhs_box = NULL;
	bool copy_vps = true;
	int rcode;
	map_t const *map = current->map;
	tmpl_dcursor_ctx_t cc;
	fr_dcursor_t cursor;

	fr_assert(current->lhs.vp != NULL);

#ifdef STATIC_ANALYZER
	if (!current->lhs.vp) return -1;
#endif

	/*
	 *	RHS is a sublist, go apply that.
	 */
	if (!current->rhs.vpt) {
		children = &current->rhs.pair_list;
		copy_vps = false;
		goto apply_list;
	}

	/*
	 *	For RHS of data, it should be a string which contains the pairs to use.
	 */
	if (tmpl_is_data(current->rhs.vpt)) {
		fr_token_t token;
		fr_dict_attr_t const *da;

		rhs_box = tmpl_value(current->rhs.vpt);

		da = current->lhs.vp->da;
		if (fr_type_is_group(da->type)) da = fr_dict_root(request->dict);

		children = &current->rhs.pair_list;
		copy_vps = false;

		switch (rhs_box->type) {
		case FR_TYPE_STRING:
			/*
			 *	For exec, etc., parse the pair list from a string, in the context of the
			 *	parent VP.  Because we're going to be moving them to the parent VP at some
			 *	point.  The ones which aren't moved will get deleted in this function.
			 */
			token = fr_pair_list_afrom_str(current->lhs.vp, da, rhs_box->vb_strvalue, rhs_box->length, children);
			if (token == T_INVALID) {
				RPEDEBUG("Failed parsing string as attribute list");
				return -1;
			}

			if (token != T_EOL) {
				REDEBUG("%s[%d] Failed to parse the entire string.", MAP_INFO);
				return -1;
			}
			break;

		case FR_TYPE_OCTETS:
			/*
			 *	@todo - do something like protocol_decode_xlat / xlat_decode_value_box_list(),
			 *	except all of that requires a decode context :(
			 */

		default:
			fr_strerror_printf("Cannot assign '%s' type to structural type '%s'",
					   fr_type_to_str(rhs_box->type),
					   fr_type_to_str(current->lhs.vp->vp_type));
			return -1;
		}

		goto apply_list;
	}

	/*
	 *	If it's not data, it must be an attribute.
	 */
	if (!tmpl_is_attr(current->rhs.vpt)) {
		REDEBUG("%s[%d] Unknown RHS %s", MAP_INFO, current->rhs.vpt->name);
		return -1;
	}

	/*
	 *	Doing no modifications to a list is a NOOP.
	 */
	vp = tmpl_dcursor_init(NULL, request, &cc, &cursor, request, current->rhs.vpt);
	if (!vp) return 0;

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


		while (vp) {
			fr_pair_list_t *list;

			next = fr_dcursor_next(&cursor);

			list = fr_pair_parent_list(vp);
			fr_assert(list != NULL);

			if (fr_edit_list_pair_delete(current->el, list, vp) < 0) {
				tmpl_dcursor_clear(&cc);
				return -1;
			}

			vp = next;
		}

		tmpl_dcursor_clear(&cc);
		return 0;
	}

	if (fr_type_is_structural(vp->vp_type)) {
		tmpl_dcursor_clear(&cc);

		if (tmpl_num(current->rhs.vpt) == NUM_ALL) {
			REDEBUG("%s[%d] Wildcard structural for %s is not yet implemented.", MAP_INFO, current->rhs.vpt->name);
			return -1;
		}

		children = &vp->vp_group;
		copy_vps = true;
		goto apply_list;
	}

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
	 *	Print the children before we do the modifications.
	 */
	RDEBUG2("%s %s {", current->lhs.vpt->name, fr_tokens[map->op]);
	if (fr_debug_lvl >= L_DBG_LVL_2) {
		RINDENT();
		/*
		 *	@todo - this logs at INFO level, and doesn't log the operators.
		 */
		xlat_debug_attr_list(request, children);
		REXDENT();
	}
	RDEBUG2("}");

	rcode = fr_edit_list_apply_list_assignment(current->el, current->lhs.vp, map->op, children, copy_vps);
	if (rcode < 0) RPERROR("Failed performing list %s operation", fr_tokens[map->op]);

	/*
	 *	If the child list wasn't copied, then we just created it, and we need to free it.
	 */
	if (!copy_vps) fr_pair_list_free(children);
	return rcode;
}


static int apply_edits_to_leaf(request_t *request, edit_map_t *current)
{
	fr_pair_t *vp;
	fr_value_box_t const *rhs_box = NULL;
	tmpl_dcursor_ctx_t cc;
	fr_dcursor_t cursor;
	map_t const *map = current->map;

	fr_assert(current->lhs.vp != NULL);

#ifdef STATIC_ANALYZER
	if (!current->lhs.vp) return -1;
#endif

	if (!tmpl_is_attr(current->lhs.vpt)) {
		REDEBUG("%s[%d] The left side of an assignment must be an attribute reference", MAP_INFO);
		return -1;
	}

	/*
	 *	&Foo := { a, b, c }
	 */
	if (!current->rhs.vpt) {
	apply_list:
		fr_assert(current->lhs.vp_parent != NULL);

		if (fr_edit_list_pair_delete_by_da(current->el, &current->lhs.vp_parent->vp_group,
						   tmpl_da(current->lhs.vpt)) < 0) {
			return -1;
		}

		if (fr_pair_list_empty(&current->rhs.pair_list)) return 0;

		fr_pair_list_foreach(&current->rhs.pair_list, child) {
			(void) talloc_steal(current->lhs.vp_parent, child);

			RDEBUG2("%s %s %pV", current->lhs.vpt->name, fr_tokens[map->op], &child->data);
		}

		if (fr_edit_list_insert_list_tail(current->el, &current->lhs.vp_parent->vp_group,
						  &current->rhs.pair_list) < 0) {
			return -1;
		}

		return 0;
	}

	/*
	 *	Any expansions have been turned into data.
	 *
	 *	@todo - set of FR_TYPE_GROUP to leaf?
	 */
	if (tmpl_is_data(current->rhs.vpt)) {
		rhs_box = tmpl_value(current->rhs.vpt);

	apply_pair_assignment:
		RDEBUG2("%s %s %pV", current->lhs.vpt->name, fr_tokens[map->op], rhs_box);

		/*
		 *	Don't apply the edit, as the VP is in a temporary list.  The parent will actually apply it.
		 */
		if (current->parent) {
			vp = current->lhs.vp;

			return fr_value_box_cast(vp, &vp->data, vp->da->type, vp->da, rhs_box);
		}

		/*
		 *	The apply function also takes care of doing data type upcasting and conversion.  So we don't
		 *	have to check for compatibility of the data types on the LHS and RHS.
		 */
		if (fr_edit_list_apply_pair_assignment(current->el,
						       current->lhs.vp,
						       map->op,
						       rhs_box) < 0) {
			RPERROR("Failed performing %s operation", fr_tokens[map->op]);
			return -1;
		}

		return 0;
	}

	/*
	 *	If it's not data, it must be an attribute.
	 */
	if (!tmpl_is_attr(current->rhs.vpt)) {
		REDEBUG("%s[%d] Unknown RHS %s", MAP_INFO, current->rhs.vpt->name);
		return -1;
	}

	/*
	 *	LHS is a leaf.  The RHS must be a leaf.
	 */
	if (!fr_type_is_leaf(tmpl_da(current->rhs.vpt)->type)) {
		REDEBUG("%s[%d] Cannot assign structural %s to leaf %s", MAP_INFO,
			tmpl_da(current->rhs.vpt)->name, current->lhs.vp->da->name);
		return -1;
	}

	/*
	 *	Find the RHS attribute.
	 */
	vp = tmpl_dcursor_init(NULL, request, &cc, &cursor, request, current->rhs.vpt);
	if (!vp) {
		REDEBUG("%s[%d] Failed to find attribute reference %s", MAP_INFO, current->rhs.vpt->name);
		return -1;
	}

	/*
	 *	Set means "delete ALL matching things, and add new ones".
	 */
	if (map->op == T_OP_SET) {
		int num;
		fr_dict_attr_t const *da = current->lhs.vp->da;

		/*
		 *	&foo[1] = ...
		 *
		 *	Assign only ONE value.
		 */
		num = tmpl_num(map->lhs);
		if ((num != NUM_UNSPEC) && map->rhs) {
			if (tmpl_num(current->rhs.vpt) == NUM_ALL) {
				REDEBUG("%s[%d] Cannot assign to multiple attributes", MAP_INFO);
				return -1;
			}

			rhs_box = &vp->data;
			goto apply_pair_assignment;
		}

		/*
		 *	Create all of the relevant VPs.
		 *
		 *	@todo - this really just be a dcursor, so that
		 *	the "list of data" case is indistinguishable
		 *	from the "list of vps".  But in order to do
		 *	that, we will need a dcursor which walks over
		 *	VPs, but returns a pointer to the data.  :(
		 */
		while (vp != NULL) {
			fr_pair_t *set;

			MEM(set = fr_pair_afrom_da(current->lhs.vp_parent, da));
			if (fr_value_box_cast(set, &set->data, da->type, da, &vp->data) < 0) return -1;
			fr_pair_append(&current->rhs.pair_list, set);

			vp = fr_dcursor_next(&cursor);
		}

		goto apply_list;
	}

	/*
	 *	Save the VP we're doing to edit.
	 */
	if (fr_edit_list_save_pair_value(current->el, current->lhs.vp) < 0) {
	fail:
			tmpl_dcursor_clear(&cc);
			return -1;
	}

	RDEBUG2("%s %s %s", current->lhs.vpt->name, fr_tokens[map->op], current->rhs.vpt->name);

	/*
	 *	Loop over all input VPs, doing the operation.
	 */
	while (vp != NULL) {
		int rcode;

		rcode = fr_value_calc_assignment_op(current->lhs.vp, &current->lhs.vp->data, map->op, &vp->data);
		if (rcode < 0) goto fail;

		vp = fr_dcursor_next(&cursor);
	}

	return 0;
}


/** Simple pair building callback for use with tmpl_dcursors
 *
 * Which always appends the new pair to the tail of the list
 * since it is only called when no matching pairs were found when
 * walking the list.
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
DECLARE(check_lhs_leaf);
DECLARE(check_lhs_parented);
DECLARE(expanded_lhs);
DECLARE(expanded_lhs_leaf);

/*
 *	Clean up the current state, and go to the next mapl
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

static int check_rhs(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
#ifdef STATIC_ANALYZER
	if (!current->lhs.vp) return -1;
#endif

	if (fr_type_is_leaf(current->lhs.vp->da->type)) {
		if (apply_edits_to_leaf(request, current) < 0) return -1;
	} else {
		if (apply_edits_to_list(request, current) < 0) return -1;
	}

	return next_map(request, state, current);
}

static int expanded_rhs(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
#ifdef STATIC_ANALYZER
	if (!current->lhs.vp) return -1;
#endif

	fr_assert(current->map->rhs != NULL);

	/*
	 *	Get the value of the RHS tmpl.
	 *
	 *	@todo - templatize based on LHS da, not LHS vp.
	 */
	if (templatize_to_value(state, &current->rhs, current->lhs.vp, request) < 0) return -1;

	return check_rhs(request, state, current);
}

static int expand_rhs_list(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	map_t const *map = current->map;
	edit_map_t *child = current->child;

	/*
	 *	If there's no RHS tmpl, then the RHS is a child list.
	 */
	fr_assert(!map->rhs);

	/*
	 *	Fast path: child is empty, we don't need to do anything.
	 */
	if (fr_dlist_empty(&map->child.head)) {
		if (fr_type_is_leaf(current->lhs.vp->vp_type)) {
			REDEBUG("%s[%d] Cannot assign empty list to a normal data type", MAP_INFO);
			return -1;
		}

		return check_rhs(request, state, current);
	}

	/*
	 *	&Tmp-Integer-0 := { 0, 1 2, 3, 4 }
	 *
	 *	@todo - when we support value-box groups on the RHS in
	 *	apply_edits_to_leaf(), this next block can be deleted.
	 */
	if (fr_type_is_leaf(current->lhs.vp->vp_type) && (map->op != T_OP_SET)) {
		REDEBUG("%s[%d] Must use ':=' when editing list of normal data types", MAP_INFO);
		return -1;
	}

	/*
	 *	Allocate a new child structure if necessary.
	 */
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

	if (!fr_type_is_leaf(current->lhs.vp->vp_type)) {
		child->check_lhs = check_lhs_parented;
		child->expanded_lhs = expanded_lhs;
	} else {
		child->check_lhs = check_lhs_leaf;
		child->expanded_lhs = expanded_lhs_leaf;
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
	return 0;
}

static int expand_rhs(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	int rcode;
	map_t const *map = current->map;

	if (!map->rhs) return expand_rhs_list(request, state, current);

	/*
	 *	Turn the RHS into a tmpl_t.  This can involve just referencing an existing
	 *	tmpl in map->rhs, or expanding an xlat to get an attribute name.
	 */
	rcode = template_realize(state, &current->rhs.result, request, map->rhs);
	if (rcode < 0) return -1;

	if (rcode == 1) {
		current->func = expanded_rhs;
		return 1;
	}

	current->rhs.vpt = map->rhs;
	return check_rhs(request, state, current);
}

/*
 *	@todo - AND lhs is an XLAT, AND the result is a
 *	value-box group, AND the LHS data type isn't octets/string, THEN apply each
 *	individual member of the group.  This lets us do:
 *
 *		&Tmp-String-0 := { %{sql:...} }
 *
 *	which will assign one value to the result for each column returned by the SQL query.
 *
 *	Also if we have &Tmp-String-0 := &Filter-Id[*], we should handle that, too.
 *
 *	The easiest way is likely to just push the values into a #fr_value_box_list
 *	for the parent, and then don't do anything else.  Once the parent leaf is
 *	capable of handling value-box groups, it can just do everything.
 */
static int check_lhs_leaf(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	fr_pair_t *vp;
	map_t const *map = current->map;

	fr_assert(current->parent);
	fr_assert(current->parent->lhs.vp_parent != NULL);

	MEM(vp = fr_pair_afrom_da(current, current->parent->lhs.vp->da));

	if (tmpl_is_data(current->lhs.vpt)) {
		if (fr_value_box_cast(vp, &vp->data, vp->da->type, vp->da, tmpl_value(current->lhs.vpt)) < 0) return -1;

	} else {
		fr_pair_t *ref;

		fr_assert(tmpl_is_attr(current->lhs.vpt));
		if (tmpl_find_vp(&ref, request, current->lhs.vpt) < 0) {
			REDEBUG("%s[%d] Failed to find attribute %s", MAP_INFO, current->lhs.vpt->name);
			return -1;
		}

		if (ref->da->type == vp->da->type) {
			if (fr_value_box_copy(vp, &vp->data, &ref->data) < 0) return -1;

		} else if (fr_value_box_cast(vp, &vp->data, vp->da->type, vp->da, &ref->data) < 0) {
			RPEDEBUG("Cannot copy data from source %s (type %s) to destination %s (different type %s)",
				 ref->da->name, fr_type_to_str(ref->da->type),
				 vp->da->name, fr_type_to_str(vp->da->type));
			return -1;
		}
	}

	/*
	 *	We've already evaluated the RHS, and put the VP where the parent will
	 *	apply it.  Just go to the next map entry.
	 */
	fr_pair_append(&current->parent->rhs.pair_list, vp);
	return next_map(request, state, current);
}

static int check_lhs_parented(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	map_t const *map = current->map;

	/*
	 *	Child attributes are created in a temporary list.  Any list editing is
	 *	taken care of by the parent map.
	 */
	fr_assert((map->op == T_OP_EQ) || (current->parent->map->op == T_OP_SUB_EQ));

	/*
	 *	We create this VP in the "current" context, so that it's freed on
	 *	error.  If we create it in the LHS VP context, then we have to
	 *	manually free rhs.pair_list on any error.  Creating it in the
	 *	"current" context means we have to reparent it when we move it to the
	 *	parent list, but fr_edit_list_apply_list_assignment() does that
	 *	anyways.
	 */
	MEM(current->lhs.vp = fr_pair_afrom_da(current, tmpl_da(current->lhs.vpt)));
	fr_pair_append(&current->parent->rhs.pair_list, current->lhs.vp);
	current->lhs.vp->op = map->op;

	return expand_rhs(request, state, current);
}

static int check_lhs(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	map_t const *map = current->map;
	tmpl_dcursor_build_t build = NULL;
	int			err;
	fr_pair_t		*vp;
	tmpl_dcursor_ctx_t	cc;
	fr_dcursor_t		cursor;

	if ((map->op == T_OP_SET) || (map->op == T_OP_EQ)) build = edit_list_pair_build;

	current->lhs.vp = NULL;

	/*
	 *	Use callback to build missing destination container.
	 */
	fr_strerror_clear();
	vp = tmpl_dcursor_build_init(&err, state, &cc, &cursor, request, current->lhs.vpt, build, current);
	tmpl_dcursor_clear(&cc);
	if (!vp) {
		RPDEBUG("Failed finding or creating %s - %d", current->lhs.vpt->name, err);
		return -1;
	}

	/*
	 *	We just built it (= or :=).  Go do the RHS.
	 */
	if (current->lhs.vp) {
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
	 *	We found an existing attribute, with a modification operator.
	 */
	current->lhs.vp = vp;
	current->lhs.vp_parent = fr_pair_parent(current->lhs.vp);
	return expand_rhs(request, state, current);
}

/*
 *	In normal situations, the LHS is an attribute name.
 *
 *	For leaf lists, the LHS is a value, so we templatize it as a value.
 */
static int expanded_lhs_leaf(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	if (templatize_to_attribute(state, &current->lhs, request) < 0) return -1;

	return check_lhs_leaf(request, state, current);
}

static int expanded_lhs(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	if (templatize_to_value(state, &current->lhs, current->parent->lhs.vp, request) < 0) return -1;

	return current->check_lhs(request, state, current);
}

static int expand_lhs(request_t *request, unlang_frame_state_edit_t *state, edit_map_t *current)
{
	int rcode;
	map_t const *map = current->map;

	fr_assert(fr_dlist_empty(&current->lhs.result));	/* Should have been consumed */
	fr_assert(fr_dlist_empty(&current->rhs.result));	/* Should have been consumed */

	rcode = template_realize(state, &current->lhs.result, request, map->lhs);
	if (rcode < 0) return -1;

	if (rcode == 1) {
		current->func = expanded_lhs;
		return 1;
	}

	current->lhs.vpt = map->lhs;

	return current->check_lhs(request, state, current);
}

/** Create a list of modifications to apply to one or more fr_pair_t lists
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

			rcode = state->current->func(request, state, state->current);
			if (rcode < 0) {
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
		 *	Stop if there's no parnt to process.
		 */
		if (!state->current->parent) break;

		state->current = state->current->parent;
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

	current->el = state->el;
	current->map_head = &edit->maps;
	current->map = map_list_head(current->map_head);
	fr_pair_list_init(&current->rhs.pair_list);
	current->func = expand_lhs;
	current->check_lhs = check_lhs;
	current->expanded_lhs = expanded_lhs;

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
