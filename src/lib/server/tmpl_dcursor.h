#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */


#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/util/dcursor.h>

RCSIDH(tmpl_dcursor_t, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tmpl_dcursor_ctx_s tmpl_dcursor_ctx_t;
typedef struct tmpl_dcursor_nested_s tmpl_dcursor_nested_t;

/** Evaluation function for iterating over a given type of attribute
 *
 * Currently attributes are divided into structural and leaf attributes,
 * so we need an evaluation function for each of those.
 *
 * @param[in] list_head		to evaluate.
 * @param[in] current		position in the list.
 * @param[in] ns		Nested state.
 */
typedef fr_pair_t *(*tmpl_dursor_eval_t)(fr_dlist_head_t *list_head, fr_pair_t *current, tmpl_dcursor_nested_t *ns);

/** State for traversing an attribute reference
 *
 */
struct tmpl_dcursor_nested_s {
	fr_dlist_t		entry;		//!< Entry in the dlist that forms the evaluation stack.
	tmpl_attr_t const	*ar;		//!< Attribute reference this state
						///< entry is associated with.  Mainly for debugging.
	tmpl_dursor_eval_t	func;		//!< Function used to evaluate this attribute reference.
	TALLOC_CTX		*list_ctx;	//!< Track where we should be allocating attributes.

	bool			seen;		//!< Whether we've seen an attribute at this level of
						///< evaluation already.  This is mainly used where
						///< the build cursor is used.

	union {
		struct {
			fr_dcursor_t		cursor;			//!< Group traversal is much easier
									///< but we still need to keep track
									///< where we are in the list in case
									///< we're doing counts.
		} group;

		struct {
			fr_pair_list_t		*list_head;		//!< Head of the list we're currently
									///< iterating over.
		} leaf;
	};
};

/** Maintains state between cursor calls
 *
 */
struct tmpl_dcursor_ctx_s {
	TALLOC_CTX		*ctx;		//!< Temporary allocations go here.
	TALLOC_CTX		*pool;		//!< Temporary pool.
	tmpl_t const		*vpt;		//!< tmpl we're evaluating.

	request_t		*request;	//!< Result of following the request references.

	fr_pair_list_t		*list;		//!< List within the request.

	fr_dlist_head_t		nested;		//!< Nested state.  These are allocated when we
						///< need to maintain state between multiple
						///< cursor calls for a particular attribute
						///< reference.
						///< This forms a stack of tmpl_dcursor_nested_t
						///< and tracks where we are in evaluation at
						///< all levels.

	tmpl_dcursor_nested_t	leaf;		//!< Pre-allocated leaf state.  We always need
						///< one of these so it doesn't make sense to
						///< allocate it later.
};

fr_pair_t		*tmpl_dcursor_init(int *err, TALLOC_CTX *ctx, tmpl_dcursor_ctx_t *cc,
					   fr_dcursor_t *cursor, request_t *request,
					   tmpl_t const *vpt);

void			tmpl_dursor_clear(tmpl_dcursor_ctx_t *cc);
