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
 * @file lib/server/methods.h
 * @brief Cannonical definition of abstract module methods.
 *
 * Multiple schemes have been used to try and pick the default module
 * method for a given section.
 *
 * The original module component scheme used an enum containing
 * all the verbs necessary for processing RADIUS packets.  These
 * were tightly bound to the original RADIUS processing sections
 * so did not work as we expanded beyond RADIUS.
 *
 * The next scheme had modules map server section names to specific
 * functions.  This ended up being rather complex and would have
 * required modules to be updated with each additional protocol added
 * to this server.
 *
 * This scheme defines abstract module methods centrally.
 * The idea is that a module exports a list of methods it supports
 * (possibly bound to protocol).  Process modules then provide a list
 * of methods ordered by priority.
 *
 * @copyright 2021 The FreeRADIUS server project
 */
RCSIDH(methods_h, "$Id$")

#include <freeradius-devel/server/module.h>
#include <freeradius-devel/util/rbtree.h>

/** Unique identifier for an abstract method
 *
 */
typedef uint32_t module_method_id_t;

/** Binds an id to a module method
 *
 */
typedef struct {
	fr_rb_node_t		node;		//!< Entry into the tree of IDs.
	fr_dlist_t		entry;		//!< Entry into the ordered list.

	module_method_id_t	id;		//!< Identifier of the method method.

	module_method_t		method;		//!< The module method.
} module_method_entry_t;

/** A set of methods to search in
 *
 */
typedef struct {
	rbtree_t		*tree;		//!< Index of methods.
						///< Helps with efficient lookups.

	fr_dlist_head_t		list;		//!< Ordered list of methods.
} module_method_set_t;

module_method_id_t	module_method_define(module_method_id_t *id_out, char const *name)
			CC_HINT(nonnull);

char const		*module_method_name_by_id(module_method_id_t id)
			CC_HINT(warn_unused_result);

char const		*module_method_name_by_entry(module_method_entry_t const *entry)
			CC_HINT(nonnull) CC_HINT(warn_unused_result);

module_method_entry_t	*module_method_next(module_method_set_t *set, module_method_entry_t *prev)
			CC_HINT(nonnull(1)) CC_HINT(warn_unused_result);

module_method_set_t	*module_method_alloc_set(TALLOC_CTX *ctx)
			CC_HINT(warn_unused_result);

int			module_method_insert(module_method_set_t *set, module_method_id_t id, module_method_t method)
			CC_HINT(nonnull(1));

module_method_t		module_method_find(module_method_set_t *set, module_method_id_t id)
			CC_HINT(nonnull(1)) CC_HINT(warn_unused_result);

int			module_method_global_init(void);

void			module_method_global_free(void);
