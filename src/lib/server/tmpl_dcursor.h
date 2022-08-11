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

/** Callback function for populating missing pair
 *
 * @param[in] parent	to allocate the new pair in.
 * @param[in] cursor	to append the pair to.
 * @param[in] da	of the attribute to create.
 * @param[in] uctx	context data.
 * @return		newly allocated pair.
 */
typedef fr_pair_t *(*tmpl_dcursor_build_t)(fr_pair_t *parent, fr_dcursor_t *cursor, fr_dict_attr_t const *da, void *uctx);

/** State for traversing an attribute reference
 *
 */
struct tmpl_dcursor_nested_s {
	fr_dlist_t		entry;		//!< Entry in the dlist that forms the evaluation stack.
	tmpl_attr_t const	*ar;		//!< Attribute reference this state
						///< entry is associated with.  Mainly for debugging.
	TALLOC_CTX		*list_ctx;	//!< Track where we should be allocating attributes.

	bool			seen;		//!< Whether we've seen an attribute at this level of
						///< evaluation already.  This is mainly used where
						///< the build cursor is used.

	fr_dcursor_t		cursor;		//!< Cursor to track where we are in the list in case
						///< we're doing counts.
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

	tmpl_dcursor_build_t	build;		//!< Callback to build missing pairs.
	void			*uctx;		//!< Context for building new pairs.
};

fr_pair_t		*tmpl_dcursor_init_relative(int *err, TALLOC_CTX *ctx, tmpl_dcursor_ctx_t *cc,
						    fr_dcursor_t *cursor,
						    request_t *request, fr_pair_t *list, tmpl_t const *vpt,
						    tmpl_dcursor_build_t build, void *uctx);

fr_pair_t		*_tmpl_dcursor_init(int *err, TALLOC_CTX *ctx, tmpl_dcursor_ctx_t *cc,
					    fr_dcursor_t *cursor, request_t *request,
					    tmpl_t const *vpt, tmpl_dcursor_build_t build, void *uctx);

void			tmpl_dcursor_clear(tmpl_dcursor_ctx_t *cc);

fr_pair_t *tmpl_dcursor_pair_build(fr_pair_t *parent, fr_dcursor_t *cursor, fr_dict_attr_t const *da, UNUSED void *uctx);

#define tmpl_dcursor_init(_err, _ctx, _cc, _cursor, _request, _vpt) \
	_tmpl_dcursor_init(_err, _ctx, _cc, _cursor, _request, _vpt, NULL, NULL)

#define tmpl_dcursor_build_init(_err, _ctx, _cc, _cursor, _request, _vpt, _build, _uctx) \
	_tmpl_dcursor_init(_err, _ctx, _cc, _cursor, _request, _vpt, _build, _uctx)
