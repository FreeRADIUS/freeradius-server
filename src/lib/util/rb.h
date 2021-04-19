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
	void			*data;		//!< data stored in node

	fr_rb_colour_t		colour;		//!< Node colour (BLACK, RED)
	bool			being_freed;	//!< Disable frees if we're currently calling
						///< a free function.
};

typedef struct fr_rb_tree_s fr_rb_tree_t;

/** Callback used to alloc rbnodes
 *
 * @param[in] tree	to allocate the node for.
 * @param[in] data	associated with node.
 */
typedef fr_rb_node_t *(* rb_node_alloc_t)(fr_rb_tree_t const *tree, void *data);

/** Callback used to free rbnodes
 *
 * @param[in] tree	that owns the node.
 * @param[in] node	to free.
 * @param[in] free_data free user data.
 */
typedef void (* rb_node_free_t)(fr_rb_tree_t const *tree, fr_rb_node_t *node, bool free_data);

/** The main red black tree structure
 *
 */
struct fr_rb_tree_s {
#ifndef NDEBUG
	uint32_t		magic;
#endif

	fr_rb_node_t		*root;		//!< Root of the rbtree.

	TALLOC_CTX		*node_ctx;	//!< Talloc ctx to allocate nodes in.

	char const		*type;		//!< Talloc type to check elements against.

	fr_cmp_t		data_cmp;	//!< Callback to compare node data.
	fr_free_t		data_free;	//!< Callback to free node data.

	rb_node_alloc_t		node_alloc;	//!< Callback to allocate a new node.
	rb_node_free_t		node_free;	//!< Callback to free a node.

	/*
	 *	Try and pack these more efficiently
	 *	by grouping them together.
	 */
	uint16_t		offset;		//!< Where's the fr_rb_node_t is located in
						///< the structure being inserted.
	bool			being_freed;	//!< Prevent double frees in talloc_destructor.
	uint32_t		num_elements;	//!< How many elements are inside the tree.
};

/** Initialises a red black that verifies elements are of a specific talloc type
 *
 * This variant allocates an #fr_rb_node_t on the heap.  This allows the data
 * structure to be inserted into multiple trees.
 *
 * @param[out] _tree		to initialise.
 * @param[in] _node_ctx		to tie tree lifetime to.
 *				If ctx is freed, tree will free any nodes, calling the
 *				free function if set.
 * @param[in] _type		of item being stored in the tree, e.g. fr_value_box_t.
 * @param[in] _field		Containing the #fr_rb_node_t within item being stored.
 * @param[in] _data_cmp		Callback to compare node data.
 * @param[in] _data_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @return
 *	- A new rbtree on success.
 *	- NULL on failure.
 */
#define		fr_rb_talloc_init(_tree, _node_ctx, _type, _data_cmp, _data_free) \
		_fr_rb_init(_tree, _node_ctx, -1, #_type, _data_cmp, _data_free)

/** Initialises a red black tree
 *
 * This variant initates an #fr_rb_node_t on the heap.  This allows the data structure
 * to be inserted into multiple trees.
 *
 * @param[out] _tree		to initialise.
 * @param[in] _node_ctx		to tie tree lifetime to.
 *				If ctx is freed, tree will free any nodes, calling the
 *				free function if set.
 * @param[in] _data_cmp		Callback to compare node data.
 * @param[in] _data_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @return
 *	- A new rbtree on success.
 *	- NULL on failure.
 */
#define		fr_rb_init(_tree, _node_ctx, _data_cmp, _data_free) \
		_fr_rb_init(_tree, _node_ctx, -1, NULL, _data_cmp, _data_free)

/** Initialises a red black that verifies elements are of a specific talloc type
 *
 * This variant stores #fr_rb_node_t data inline with the data structure to avoid
 * initating #fr_rb_node_t on the heap.
 *
 * It is suitable for use where the data structure will only be inserted into a
 * fixed set of trees.
 *
 * @param[out] _tree		to initialise.
 * @param[in] _type		of item being stored in the tree, e.g. fr_value_box_t.
 * @param[in] _field		Containing the #fr_rb_node_t within item being stored.
 * @param[in] _data_cmp		Callback to compare node data.
 * @param[in] _data_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @return
 *	- A new rbtree on success.
 *	- NULL on failure.
 */
#define		fr_rb_inline_talloc_init(_tree, _type, _field, _data_cmp, _data_free) \
		_Generic((((_type *)0)->_field), \
			fr_rb_node_t: _fr_rb_init(_tree, NULL, offsetof(_type, _field), #_type, _data_cmp, _data_free) \
		)

/** Initialises a red black tree
 *
 * This variant stores #fr_rb_node_t data inline with the data structure to avoid
 * initating #fr_rb_node_t on the heap.
 *
 * It is suitable for use where the data structure will only be inserted into a
 * fixed set of trees.
 *
 * @param[out] _tree		to initialise.
 * @param[in] _type		of item being stored in the tree, e.g. fr_value_box_t.
 * @param[in] _field		Containing the #fr_rb_node_t within item being stored.
 * @param[in] _data_cmp		Callback to compare node data.
 * @param[in] _data_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @return
 *	- A new rbtree on success.
 *	- NULL on failure.
 */
#define		fr_rb_inline_init(_tree, _type, _field, _data_cmp, _data_free) \
		_Generic((((_type *)0)->_field), \
			fr_rb_node_t: _fr_rb_init(_tree, NULL, offsetof(_type, _field), NULL, _data_cmp, _data_free) \
		)

int _fr_rb_init(fr_rb_tree_t *tree, TALLOC_CTX *node_ctx,
		ssize_t offset, char const *type,
		fr_cmp_t data_cmp, fr_free_t data_free);

/** Allocs a red black that verifies elements are of a specific talloc type
 *
 * This variant allocates an #fr_rb_node_t on the heap.  This allows the data structure
 * to be inserted into multiple trees.
 *
 * @param[in] _ctx		to tie tree lifetime to.
 *				If ctx is freed, tree will free any nodes, calling the
 *				free function if set.
 * @param[in] _type		of item being stored in the tree, e.g. fr_value_box_t.
 * @param[in] _field		Containing the #fr_rb_node_t within item being stored.
 * @param[in] _data_cmp		Callback to compare node data.
 * @param[in] _data_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @return
 *	- A new rbtree on success.
 *	- NULL on failure.
 */
#define		fr_rb_talloc_alloc(_ctx, _type, _data_cmp, _data_free) \
		_fr_rb_alloc(_ctx, -1, #_type, _data_cmp, _data_free)

/** Allocs a red black tree
 *
 * This variant allocates an #fr_rb_node_t on the heap.  This allows the data structure
 * to be inserted into multiple trees.
 *
 * @param[in] _ctx		to tie tree lifetime to.
 *				If ctx is freed, tree will free any nodes, calling the
 *				free function if set.
 * @param[in] _data_cmp		Callback to compare node data.
 * @param[in] _data_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @return
 *	- A new rbtree on success.
 *	- NULL on failure.
 */
#define		fr_rb_alloc(_ctx, _data_cmp, _data_free) \
		_fr_rb_alloc(_ctx, -1, NULL, _data_cmp, _data_free)

/** Allocs a red black that verifies elements are of a specific talloc type
 *
 * This variant stores #fr_rb_node_t data inline with the data structure to avoid
 * allocating #fr_rb_node_t on the heap.
 *
 * It is suitable for use where the data structure will only be inserted into a fixed
 * set of trees.
 *
 * @param[in] _ctx		to tie tree lifetime to.
 *				If ctx is freed, tree will free any nodes, calling the
 *				free function if set.
 * @param[in] _type		of item being stored in the tree, e.g. fr_value_box_t.
 * @param[in] _field		Containing the #fr_rb_node_t within item being stored.
 * @param[in] _data_cmp		Callback to compare node data.
 * @param[in] _data_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @return
 *	- A new rbtree on success.
 *	- NULL on failure.
 */
#define		fr_rb_inline_talloc_alloc(_ctx, _type, _field, _data_cmp, _data_free) \
		_Generic((((_type *)0)->_field), \
			fr_rb_node_t: _fr_rb_alloc(_ctx, offsetof(_type, _field), #_type, _data_cmp, _data_free) \
		)

/** Allocs a red black tree
 *
 * This variant stores #fr_rb_node_t data inline with the data structure to avoid
 * allocating #fr_rb_node_t on the heap.
 *
 * It is suitable for use where the data structure will only be inserted into a fixed
 * set of trees.
 *
 * @param[in] _ctx		to tie tree lifetime to.
 *				If ctx is freed, tree will free any nodes, calling the
 *				free function if set.
 * @param[in] _type		of item being stored in the tree, e.g. fr_value_box_t.
 * @param[in] _field		Containing the #fr_rb_node_t within item being stored.
 * @param[in] _data_cmp		Callback to compare node data.
 * @param[in] _data_free	Optional function used to free data if tree nodes are
 *				deleted or replaced.
 * @return
 *	- A new rbtree on success.
 *	- NULL on failure.
 */
#define		fr_rb_inline_alloc(_ctx, _type, _field, _data_cmp, _data_free) \
		_Generic((((_type *)0)->_field), \
			fr_rb_node_t: _fr_rb_alloc(_ctx, offsetof(_type, _field), NULL, _data_cmp, _data_free) \
		)

fr_rb_tree_t	*_fr_rb_alloc(TALLOC_CTX *ctx, ssize_t offset, char const *type,
			      fr_cmp_t data_cmp, fr_free_t data_free) CC_HINT(warn_unused_result);

/** @hidecallergraph */
void		*fr_rb_find(fr_rb_tree_t const *tree, void const *data) CC_HINT(nonnull);

int		fr_rb_find_or_insert(void **found, fr_rb_tree_t *tree, void const *data) CC_HINT(nonnull(2,3));

bool		fr_rb_insert(fr_rb_tree_t *tree, void const *data) CC_HINT(nonnull);

int		fr_rb_replace(void **old, fr_rb_tree_t *tree, void const *data) CC_HINT(nonnull(2,3));

void		*fr_rb_remove(fr_rb_tree_t *tree, void const *data) CC_HINT(nonnull);

bool		fr_rb_delete(fr_rb_tree_t *tree, void const *data) CC_HINT(nonnull);

uint32_t	fr_rb_num_elements(fr_rb_tree_t *tree) CC_HINT(nonnull);

/** Check to see if an item is in a tree by examining its inline #fr_rb_node_t
 *
 * This works because we use NIL sentinels to represent the absence of a child
 * or parent.  When the node is initialised all these fields should be NULL
 * and when it's removed from the tree, the "free" function for inline nodes
 * also sets all of these back to NULL.
 *
 * @param[in] node	to check.
 * @return
 *	- true if node is in the tree.
 *	- talse if node is not in the tree.
 */
static inline bool fr_rb_node_inline_in_tree(fr_rb_node_t *node)
{
	return ((!node->left && !node->right && !node->parent) || (node->being_freed));
}

/** Check to see if nodes are equivalent and if they are, replace one with the other
 *
 * @param[in] tree		Used to access the comparitor.
 * @param[in] to_replace	Node to replace in the tree.
 * @param[in] replacement	Replacement.
 * @return
 *      - true on success.
 *      - false if nodes were not equivalent.
 */
static inline bool fr_rb_node_inline_replace(fr_rb_tree_t *tree, fr_rb_node_t *to_replace, fr_rb_node_t *replacement)
{
	if (tree->data_cmp(to_replace->data, replacement->data) != 0) return false;

	memcpy(replacement, to_replace, sizeof(*replacement));
	memset(to_replace, 0, sizeof(*to_replace));

	return true;
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

int		fr_rb_flatten_inorder(TALLOC_CTX *ctx, void **out[], fr_rb_tree_t *tree);

int		fr_rb_flatten_preorder(TALLOC_CTX *ctx, void **out[], fr_rb_tree_t *tree);

int		fr_rb_flatten_postorder(TALLOC_CTX *ctx, void **out[], fr_rb_tree_t *tree);
#ifdef __cplusplus
}
#endif
