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

/**
 * $Id$
 *
 * @file lib/server/escape.h
 * @brief Structures and prototypes for escaping the result of tmpl evaluation
 */
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/server/request.h>

/** Different modes for creating a user context for escaping
 *
 */
typedef enum {
	TMPL_ESCAPE_UCTX_STATIC = 0,			//!< A static (to us) is provided by whatever is initialising
							///< the tmpl_escape_t.  This is the default.
	TMPL_ESCAPE_UCTX_ALLOC,				//!< A new uctx of the specified size and type is allocated
							///< and freed when escaping is complete.
	TMPL_ESCAPE_UCTX_ALLOC_FUNC,			//!< A new uctx of the specified size and type is allocated
							///< and pre-populated by memcpying uctx.size bytes
							///< from uctx.ptr.
} tmpl_escape_uctx_type_t;

/** Function to allocate a user context for escaping
 *
 * @param[in] request		Request that the tmpl is being evaluated for.
 * @param[in] uctx		The user context that was passed via the tmpl_escape_t.
 * @return
 *	- A pointer to the allocated user context on success.
 *	- NULL on failure.
 */
typedef void *(*tmpl_escape_uctx_alloc_t)(request_t *request, void const *uctx);

/** Free a previously allocated used ctx
 *
 * @param[in] uctx		to free.
 */
typedef void(*tmpl_escape_uctx_free_t)(void *uctx);

/** When to apply escaping
 */
typedef enum {
	TMPL_ESCAPE_NONE = 0,				//!< No escaping is performed.

	TMPL_ESCAPE_PRE_CONCAT,				//!< Pre-concatenation escaping is useful for
							///< DSLs where elements of the expansion are
							///< static, specified by the user, and other parts
							///< are dynamic, which may or may not need to be
							///< escaped based on which "safe" flags are applied
							///< to the box.  When using this mode, the escape
							///< function must be able to handle boxes of a type
							///< other than the cast type, possibly performing
							///< a cast itself if necessary.

	TMPL_ESCAPE_POST_CONCAT				//!< Post-concatenation escaping is useful for when
							///< we don't want to allow the user to bypass escaping
							///< for any part of the value.
							///< Here all boxes are guaranteed to be of the cast type.
} tmpl_escape_mode_t;

/** Escaping rules for tmpls
 *
 */
typedef struct {
	fr_value_box_escape_t		func;		//!< How to escape when returned from evaluation.
							///< Currently only used for async evaluation.
	fr_value_box_safe_for_t		safe_for;	//!< Value to set on boxes which have been escaped
							///< by the #fr_value_box_escape_t function.

	tmpl_escape_mode_t		mode;		//!< Whether to apply escape function after
							///< concatenation, i.e. to the final output
							///< of the tmpl.  If false, then the escaping
							///< is performed on each value box
							///< individually prior to concatenation and
							///< prior to casting.
							///< If no concatenation is performed, then
							///< the escaping is performed on each box individually.

	struct {
		union {
			void const				*ptr;		//!< User context for escape function.

			struct {
				size_t				size;		//!< Size of the uctx to allocate.
				char const *			talloc_type;	//!< Talloc type to assign to the uctx.
			};

			struct {
				tmpl_escape_uctx_alloc_t	alloc;		//!< Function to call to allocate the uctx.
				tmpl_escape_uctx_free_t		free;		//!< Function to call to free the uctx.
				void const			*uctx;		//!< User context to pass to allocation func.
			} func;
		};
		tmpl_escape_uctx_type_t	type;		//!< Type of uctx to use for this escape operation.
							///< default is TMPL_ESCAPE_UCTX_STATIC.
	} uctx;
} tmpl_escape_t;

/** See if we should perform output escaping before concatenation
 *
 */
#define tmpl_escape_pre_concat(_tmpl)	((_tmpl)->rules.escape.func && ((_tmpl)->rules.escape.mode == TMPL_ESCAPE_PRE_CONCAT))

/** See if we should perform output escaping after concatenation
 *
 */
#define tmpl_escape_post_concat(_tmpl)	((_tmpl)->rules.escape.func && ((_tmpl)->rules.escape.mode == TMPL_ESCAPE_POST_CONCAT))
