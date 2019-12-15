#pragma once
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

/** Red/black tree implementation
 *
 * @file src/lib/util/rbtree.h
 *
 * @copyright 2016 The FreeRADIUS server project
 */
RCSIDH(rbtree_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <stdbool.h>
#include <stdint.h>
#include <talloc.h>

/* rbtree.c */
typedef struct rbtree_s rbtree_t;
typedef struct rbnode_s rbnode_t;

/* callback order for walking  */
typedef enum {
	RBTREE_PRE_ORDER,
	RBTREE_IN_ORDER,
	RBTREE_POST_ORDER,
	RBTREE_DELETE_ORDER
} rb_order_t;

#define RBTREE_FLAG_NONE    (0)
#define RBTREE_FLAG_REPLACE (1 << 0)
#define RBTREE_FLAG_LOCK    (1 << 1)

typedef int (*rb_comparator_t)(void const *one, void const *two);
typedef int (*rb_walker_t)(void *data, void *uctx);
typedef void (*rb_free_t)(void *data);

/** Creates a red black that verifies elements are of a specific talloc type
 *
 * @param[in] _ctx		to tie tree lifetime to.
 *				If ctx is freed, tree will free any nodes, calling the
 *				free function if set.
 * @param[in] _cmp		Comparator used to compare nodes.
 * @param[in] _talloc_type	of elements.
 * @param[in] _node_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @param[in] _flags		To modify tree behaviour.
 * @return
 *	- A new rbtree on success.
 *	- NULL on failure.
 */
#define		rbtree_talloc_create(_ctx, _cmp, _talloc_type, _node_free, _flags) \
		_rbtree_create(_ctx, _cmp, #_talloc_type, _node_free, _flags)

/** Creates a red black tree
 *
 * @param[in] _ctx		to tie tree lifetime to.
 *				If ctx is freed, tree will free any nodes, calling the
 *				free function if set.
 * @param[in] _cmp		Comparator used to compare nodes.
 * @param[in] _node_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @param[in] _flags		To modify tree behaviour.
 * @return
 *	- A new rbtree on success.
 *	- NULL on failure.
 */
#define		rbtree_create(_ctx, _cmp, _node_free, _flags) \
		_rbtree_create(_ctx, _cmp, NULL, _node_free, _flags)

rbtree_t	*_rbtree_create(TALLOC_CTX *ctx, rb_comparator_t compare,
				char const *type, rb_free_t node_free, int flags);

void		rbtree_node_talloc_free(void *data);

bool		rbtree_insert(rbtree_t *tree, void const *data);

rbnode_t	*rbtree_insert_node(rbtree_t *tree, void *data);

void		rbtree_delete(rbtree_t *tree, rbnode_t *z);

bool		rbtree_deletebydata(rbtree_t *tree, void const *data);

rbnode_t	*rbtree_find(rbtree_t *tree, void const *data);

void		*rbtree_finddata(rbtree_t *tree, void const *data);

uint32_t	rbtree_num_elements(rbtree_t *tree);

uint32_t	rbtree_flatten(TALLOC_CTX *ctx, void **out[], rbtree_t *tree, rb_order_t order);

void		*rbtree_node2data(rbtree_t *tree, rbnode_t *node);

/*
 *	The callback should be declared as:
 *	int callback(void *context, void *data)
 *
 *	The "context" is some user-defined context.
 *	The "data" is the pointer to the user data in the node,
 *	NOT the node itself.
 *
 *	It should return 0 if all is OK, and !0 for any error.
 *	The walking will stop on any error.
 *
 *	Except with RBTREE_DELETE_ORDER, where the callback should return <0 for
 *	errors, and may return 1 to delete the current node and halt,
 *	or 2 to delete the current node and continue.  This may be
 *	used to batch-delete select nodes from a locked rbtree.
 */
int		rbtree_walk(rbtree_t *tree, rb_order_t order, rb_walker_t compare, void *uctx);

#ifdef __cplusplus
}
#endif
