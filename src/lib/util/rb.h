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
 * @file src/lib/util/rb.h
 *
 * @copyright 2016 The FreeRADIUS server project
 */
RCSIDH(fr_rb_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/misc.h>

#include <stdbool.h>
#include <stdint.h>

/* rb.c */
typedef struct fr_rb_s fr_rb_tree_t;

/* Red-Black tree description */
typedef enum {
	BLACK,
	RED
} fr_rb_colour_t;

typedef struct fr_rb_node_s fr_rb_node_t;
struct fr_rb_node_s {
	fr_rb_node_t		*left;		//!< Left child
	fr_rb_node_t		*right;		//!< Right child
	fr_rb_node_t		*parent;	//!< Parent
	fr_rb_colour_t		colour;		//!< Node colour (BLACK, RED)
	bool			being_freed;	//!< Disable frees if we're currently calling
						///< a free function.
	void			*data;		//!< data stored in node
};

#define RB_FLAG_NONE    (0)
#define RB_FLAG_LOCK    (1)

/** Creates a red black that verifies elements are of a specific talloc type
 *
 * @param[in] _ctx		to tie tree lifetime to.
 *				If ctx is freed, tree will free any nodes, calling the
 *				free function if set.
 * @param[in] _type		of item being stored in the tree, e.g. fr_value_box_t.
 * @param[in] _field		Containing the #fr_rb_node_t within item being stored.
 * @param[in] _cmp		Comparator used to compare nodes.
 * @param[in] _node_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @param[in] _flags		To modify tree behaviour.
 * @return
 *	- A new rbtree on success.
 *	- NULL on failure.
 */
#define		fr_rb_talloc_alloc(_ctx, _type, _node_cmp, _node_free, _flags) \
		_fr_rb_alloc(_ctx, -1, #_type, _node_cmp, _node_free, _flags)

/** Creates a red black tree
 *
 * @param[in] _ctx		to tie tree lifetime to.
 *				If ctx is freed, tree will free any nodes, calling the
 *				free function if set.
 * @param[in] _node_cmp		Comparator used to compare nodes.
 * @param[in] _node_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @param[in] _flags		To modify tree behaviour.
 * @return
 *	- A new rbtree on success.
 *	- NULL on failure.
 */
#define		fr_rb_alloc(_ctx, _node_cmp, _node_free, _flags) \
		_fr_rb_alloc(_ctx, -1, NULL, _node_cmp, _node_free, _flags)

/** Creates a red black that verifies elements are of a specific talloc type
 *
 * @param[in] _ctx		to tie tree lifetime to.
 *				If ctx is freed, tree will free any nodes, calling the
 *				free function if set.
 * @param[in] _type		of item being stored in the tree, e.g. fr_value_box_t.
 * @param[in] _field		Containing the #fr_rb_node_t within item being stored.
 * @param[in] _node_cmp		Comparator used to compare nodes.
 * @param[in] _node_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @param[in] _flags		To modify tree behaviour.
 * @return
 *	- A new rbtree on success.
 *	- NULL on failure.
 */
#define		fr_rb_inline_talloc_alloc(_ctx, _type, _field, _node_cmp, _node_free, _flags) \
		_Generic((((_type *)0)->_field), \
			fr_rb_node_t: _fr_rb_alloc(_ctx, offsetof(_type, _field), #_type, _node_cmp, _node_free, _flags) \
		)

/** Creates a red black tree
 *
 * @param[in] _ctx		to tie tree lifetime to.
 *				If ctx is freed, tree will free any nodes, calling the
 *				free function if set.
 * @param[in] _type		of item being stored in the tree, e.g. fr_value_box_t.
 * @param[in] _field		Containing the #fr_rb_node_t within item being stored.
 * @param[in] _cmp		Comparator used to compare nodes.
 * @param[in] _node_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @param[in] _flags		To modify tree behaviour.
 * @return
 *	- A new rbtree on success.
 *	- NULL on failure.
 */
#define		fr_rb_inline_alloc(_ctx, _type, _field, _node_cmp, _node_free, _flags) \
		_Generic((((_type *)0)->_field), \
			fr_rb_node_t: _fr_rb_alloc(_ctx, offsetof(_type, _field), NULL, _node_cmp, _node_free, _flags) \
		)

fr_rb_tree_t	*_fr_rb_alloc(TALLOC_CTX *ctx, ssize_t offset, char const *type,
			      fr_cmp_t compare, fr_free_t node_free, int flags) CC_HINT(warn_unused_result);

/** @hidecallergraph */
void		*fr_rb_find(fr_rb_tree_t *tree, void const *data) CC_HINT(nonnull);

bool		fr_rb_insert(fr_rb_tree_t *tree, void const *data) CC_HINT(nonnull);

int		fr_rb_replace(fr_rb_tree_t *tree, void const *data) CC_HINT(nonnull);

void		*fr_rb_remove(fr_rb_tree_t *tree, void const *data) CC_HINT(nonnull);

bool		fr_rb_delete(fr_rb_tree_t *tree, void const *data) CC_HINT(nonnull);

uint64_t	fr_rb_num_elements(fr_rb_tree_t *tree) CC_HINT(nonnull);

void		fr_rb_unlock(fr_rb_tree_t *tree) CC_HINT(nonnull);

/** Given a Node, return the data
 */
static inline void *fr_rb_node_to_data(UNUSED fr_rb_tree_t *tree, fr_rb_node_t *node)
{
	if (!node) return NULL;

	return node->data;
}

/** Iterator structure for in-order traversal of an rbtree
 */
typedef struct {
	fr_rb_tree_t	*tree;			//!< Tree being iterated over.
	fr_rb_node_t	*node;			///< current node--set to NULL (not NIL) by fr_rb_iter_delete()
	fr_rb_node_t	*next;			///< if non-NULL, next node cached by fr_rb_iter_delete()
} fr_rb_iter_inorder_t;

void		*fr_rb_iter_init_inorder(fr_rb_iter_inorder_t *iter, fr_rb_tree_t *tree) CC_HINT(nonnull);

void		*fr_rb_iter_next_inorder(fr_rb_iter_inorder_t *iter) CC_HINT(nonnull);

void		fr_rb_iter_delete_inorder(fr_rb_iter_inorder_t *iter) CC_HINT(nonnull);

/** Iterator structure for pre-order traversal of an rbtree
 */
typedef struct {
	fr_rb_tree_t	*tree;			//!< Tree being iterated over.
	fr_rb_node_t	*node;			///< current node
} fr_rb_iter_preorder_t;

void		*fr_rb_iter_init_preorder(fr_rb_iter_preorder_t *iter, fr_rb_tree_t *tree) CC_HINT(nonnull);

void		*fr_rb_iter_next_preorder(fr_rb_iter_preorder_t *iter) CC_HINT(nonnull);

/** Iterator structure for post-order traversal of an rbtree
 */
typedef struct {
	fr_rb_tree_t	*tree;			//!< Tree being iterated over.
	fr_rb_node_t	*node;			///< current node
} fr_rb_iter_postorder_t;

void		*fr_rb_iter_init_postorder(fr_rb_iter_postorder_t *iter, fr_rb_tree_t *tree) CC_HINT(nonnull);

void		*fr_rb_iter_next_postorder(fr_rb_iter_postorder_t *iter) CC_HINT(nonnull);

/** Explicitly unlock the tree
 *
 * @note Must be called if iterating over the tree ends early.
 *
 * @param[in] iter	previously initialised with #fr_rb_iter_init
 */
#define fr_rb_iter_done(_iter) \
	(_Generic((_iter), \
		fr_rb_iter_inorder_t *		: fr_rb_unlock(((fr_rb_iter_inorder_t *)(_iter))->tree),  \
		fr_rb_iter_preorder_t *		: fr_rb_unlock(((fr_rb_iter_preorder_t *)(_iter))->tree),  \
		fr_rb_iter_postorder_t *	: fr_rb_unlock(((fr_rb_iter_postorder_t *)(_iter))->tree)  \
	))


int		fr_rb_flatten_inorder(TALLOC_CTX *ctx, void **out[], fr_rb_tree_t *tree);

int		fr_rb_flatten_preorder(TALLOC_CTX *ctx, void **out[], fr_rb_tree_t *tree);

int		fr_rb_flatten_postorder(TALLOC_CTX *ctx, void **out[], fr_rb_tree_t *tree);
#ifdef __cplusplus
}
#endif
