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
 * @file src/lib/util/rb.c
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2004,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/strerror.h>

#define NIL &sentinel	   /* all leafs are sentinels */
static fr_rb_node_t sentinel = { NIL, NIL, NULL, NULL, BLACK, false };

#ifndef NDEBUG
#  define RB_MAGIC (0x5ad09c42)
#endif

static int insert_node(fr_rb_node_t **existing, fr_rb_tree_t *tree, void *data) CC_HINT(nonnull);

static inline CC_HINT(always_inline) void node_data_free(fr_rb_tree_t const *tree, fr_rb_node_t *node)
{
	if (!tree->data_free || unlikely(node->being_freed)) return;

	node->being_freed = true;
	tree->data_free(node->data);
}

/** Return the fr_rb_node_t that was allocated as part of the data structure
 */
static fr_rb_node_t *_node_inline_alloc(fr_rb_tree_t const *tree, void *data)
{
	return (fr_rb_node_t *)((uintptr_t)data + tree->offset);
}

/** Clear the fr_rb_node_t that was allocated as part of the data structure
 */
static void _node_inline_free(fr_rb_tree_t const *tree, fr_rb_node_t *node, bool free_data)
{
	if (free_data && tree->data_free) {
		node_data_free(tree, node);
	} else {
		memset(node, 0, sizeof(fr_rb_node_t));	/* makes "still in tree?" checks easier */
	}
}

/** Allocate a new fr_rb_node_t on the heap
 */
static fr_rb_node_t *_node_heap_alloc(fr_rb_tree_t const *tree, UNUSED void *data)
{
	return talloc_zero(tree->node_ctx, fr_rb_node_t);
}

/** Clear the fr_rb_node_t that was allocated as part of the data structure
 */
static void _node_heap_free(fr_rb_tree_t const *tree, fr_rb_node_t *node, bool free_data)
{
	if (free_data) node_data_free(tree, node);
	talloc_free(node);
}

/** Walks the tree to delete all nodes Does NOT re-balance it!
 *
 */
static void free_walker(fr_rb_tree_t *tree, fr_rb_node_t *x)
{
	if (x->left != NIL) free_walker(tree, x->left);
	if (x->right != NIL) free_walker(tree, x->right);

	tree->node_free(tree, x, true);
}

/** Free the rbtree cleaning up any nodes
 *
 * Walk the tree deleting nodes, then free any children of the tree.
 *
 * @note If the destructor of a talloc descendent needs to lookup any
 *	information in the tree, it will be unavailable at the point
 *	of freeing.  We could fix this by introducing a pre-free callback
 *	which gets called before any of the nodes are deleted.
 *
 * @param[in] tree to tree.
 * @return
 *	- 0 if tree was freed.
 *	- -1 if tree is already being freed.
 */
static int _tree_free(fr_rb_tree_t *tree)
{
	/*
	 *	Prevent duplicate frees
	 */
	if (unlikely(tree->being_freed)) return -1;
	tree->being_freed = true;

	/*
	 *	walk the tree, deleting the nodes...
	 */
	if ((tree->root != NIL) && tree->data_free) free_walker(tree, tree->root);

#ifndef NDEBUG
	tree->magic = 0;
#endif
	tree->root = NIL;
	tree->num_elements = 0;

	/*
	 *	Ensure all dependents on the tree run their
	 *	destructors.  The tree at this point should
	 *	and any tree operations should be empty.
	 */
	talloc_free_children(tree);

	return 0;
}

/** Initialise a new RED-BLACK tree
 *
 * @param[out] tree		to initialise.
 * @param[in] node_ctx		the ctx used to allocate #fr_rb_node_t if the
 *				tree isn't using inline #fr_rb_node_t.
 * @param[in] offset		offsetof the #fr_rb_node_t field in the data being inserted.
 *      			If < 0, nodes will be allocated on the heap.
 * @param[in] type		Talloc type of structures being inserted, may be NULL.
 * @param[in] data_cmp		Comparator function for ordering data in the tree.
 * @param[in] data_free		Free function to call whenever data is deleted or replaced.
 * @return
 *	- -1 on error.
 *      - 0 on success.
 */
int _fr_rb_init(fr_rb_tree_t *tree, TALLOC_CTX *node_ctx,
		ssize_t offset, char const *type,
		fr_cmp_t data_cmp, fr_free_t data_free)
{

	if (unlikely(offset >= UINT16_MAX)) {
		fr_strerror_printf("Inline fr_rb_node_t offset too large.  "
				   "Expected <= %u, got %zd", UINT16_MAX, offset);
		return -1;
	}

	*tree = (fr_rb_tree_t) {
#ifndef NDEBUG
		.magic = RB_MAGIC,
#endif
		.root = NIL,
		.node_ctx = node_ctx,
		.offset = offset < 0 ? 0 : (uint16_t)offset,
		.type = type,
		.data_cmp = data_cmp,
		.data_free = data_free,
	};

	/*
	 *	Use inline nodes
	 */
	if (offset >= 0) {
		tree->node_alloc = _node_inline_alloc;
		tree->node_free = _node_inline_free;
	/*
	 *	Allocate node data on the heap
	 */
	} else {
		tree->node_alloc = _node_heap_alloc;
		tree->node_free = _node_heap_free;
	}

	return 0;
}

/** Alloc a new RED-BLACK tree
 *
 * @param[in] ctx		to allocate the tree in.
 *				Only the tree is allocated in this context, the memory
 *				for the #fr_rb_node_t is allocated as part of the data
 *				being inserted into the tree.
 * @param[in] offset		offsetof the #fr_rb_node_t field in the data being inserted.
 *      			If < 0, nodes will be allocated on the heap.
 * @param[in] type		Talloc type of structures being inserted, may be NULL.
 * @param[in] data_cmp		Comparator function for ordering data in the tree.
 * @param[in] data_free		Free function to call whenever data is deleted or replaced.
 * @return
 *      - A new tree on success.
 *	- NULL on failure.
 */
fr_rb_tree_t *_fr_rb_alloc(TALLOC_CTX *ctx,
			   ssize_t offset, char const *type,
			   fr_cmp_t data_cmp, fr_free_t data_free)
{
	fr_rb_tree_t *tree;

	tree = talloc(ctx, fr_rb_tree_t);
	if (unlikely(!tree)) return NULL;

	if (unlikely(_fr_rb_init(tree, tree, offset, type, data_cmp, data_free) < 0)) {
		talloc_free(tree);
		return NULL;
	}

	talloc_set_destructor(tree, _tree_free);

	return tree;
}

/** Rotate Node x to left
 *
 */
static inline CC_HINT(always_inline) void rotate_left(fr_rb_tree_t *tree, fr_rb_node_t *x)
{

	fr_rb_node_t *y = x->right;

	/* establish x->right link */
	x->right = y->left;
	if (y->left != NIL) y->left->parent = x;

	/* establish y->parent link */
	if (y != NIL) y->parent = x->parent;
	if (x->parent != NIL) {
		if (x == x->parent->left) {
			x->parent->left = y;
		} else {
			x->parent->right = y;
		}
	} else {
		tree->root = y;
	}

	/* link x and y */
	y->left = x;
	if (x != NIL) x->parent = y;
}

/** Rotate Node x to right
 *
 */
static inline CC_HINT(always_inline) void rotate_right(fr_rb_tree_t *tree, fr_rb_node_t *x)
{
	fr_rb_node_t *y = x->left;

	/* establish x->left link */
	x->left = y->right;
	if (y->right != NIL) y->right->parent = x;

	/* establish y->parent link */
	if (y != NIL) y->parent = x->parent;
	if (x->parent != NIL) {
		if (x == x->parent->right) {
			x->parent->right = y;
		} else {
			x->parent->left = y;
		}
	} else {
		tree->root = y;
	}

	/* link x and y */
	y->right = x;
	if (x != NIL) x->parent = y;
}

/** Maintain red-black tree balance after inserting node x
 *
 */
static inline CC_HINT(always_inline) void insert_fixup(fr_rb_tree_t *tree, fr_rb_node_t *x)
{
	/* check RED-BLACK properties */
	while ((x != tree->root) && (x->parent->colour == RED)) {
		/* we have a violation */
		if (x->parent == x->parent->parent->left) {
			fr_rb_node_t *y = x->parent->parent->right;
			if (y->colour == RED) {
				/* uncle is RED */
				x->parent->colour = BLACK;
				y->colour = BLACK;
				x->parent->parent->colour = RED;
				x = x->parent->parent;
			} else {
				/* uncle is BLACK */
				if (x == x->parent->right) {
					/* make x a left child */
					x = x->parent;
					rotate_left(tree, x);
				}

				/* recolour and rotate */
				x->parent->colour = BLACK;
				x->parent->parent->colour = RED;
				rotate_right(tree, x->parent->parent);
			}
		} else {
			/* mirror image of above code */
			fr_rb_node_t *y = x->parent->parent->left;
			if (y->colour == RED) {
				/* uncle is RED */
				x->parent->colour = BLACK;
				y->colour = BLACK;
				x->parent->parent->colour = RED;
				x = x->parent->parent;
			} else {
				/* uncle is BLACK */
				if (x == x->parent->left) {
					x = x->parent;
					rotate_right(tree, x);
				}

				x->parent->colour = BLACK;
				x->parent->parent->colour = RED;
				rotate_left(tree, x->parent->parent);
			}
		}
	}

	tree->root->colour = BLACK;
}


/** Insert an element into the tree
 *
 * @param[out] existing		if a node exists, and existing is not NULL
 *				this will be populated with the node.
 * @param[in] tree		to search in.
 * @param[in] data		to search for.
 * @return
 *	- 1 on existing (with existing populated).
 *      - 0 on success.
 *	- -1 on failure.
 */
static int insert_node(fr_rb_node_t **existing, fr_rb_tree_t *tree, void *data)
{
	fr_rb_node_t *current, *parent, *x;

	if (unlikely(tree->being_freed)) return NULL;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (tree->type) (void)_talloc_get_type_abort(data, tree->type, __location__);
#endif

	/* find where node belongs */
	current = tree->root;
	parent = NIL;
	while (current != NIL) {
		int result;

		/*
		 *	See if two entries are identical.
		 */
		result = tree->data_cmp(data, current->data);
		if (result == 0) {
			if (existing) *existing = current;
			return 1
		}

		parent = current;
		current = (result < 0) ? current->left : current->right;
	}

	/* setup new node */
	x = tree->node_alloc(tree, data);
	if (unlikely(!x)) return -1;

	*x = (fr_rb_node_t){
		.data = data,
		.parent = parent,
		.left = NIL,
		.right = NIL,
		.colour = RED
	};

	/* insert node in tree */
	if (parent != NIL) {
		if (tree->data_cmp(data, parent->data) <= 0) {
			parent->left = x;
		} else {
			parent->right = x;
		}
	} else {
		tree->root = x;
	}

	insert_fixup(tree, x);

	tree->num_elements++;

	return 0;
}

/** Maintain RED-BLACK tree balance after deleting node x
 *
 */
static void delete_fixup(fr_rb_tree_t *tree, fr_rb_node_t *x, fr_rb_node_t *parent)
{
	while (x != tree->root && x->colour == BLACK) {
		if (x == parent->left) {
			fr_rb_node_t *w = parent->right;
			if (w->colour == RED) {
				w->colour = BLACK;
				parent->colour = RED; /* parent != NIL? */
				rotate_left(tree, parent);
				w = parent->right;
			}
			if ((w->left->colour == BLACK) && (w->right->colour == BLACK)) {
				if (w != NIL) w->colour = RED;
				x = parent;
				parent = x->parent;
			} else {
				if (w->right->colour == BLACK) {
					if (w->left != NIL) w->left->colour = BLACK;
					w->colour = RED;
					rotate_right(tree, w);
					w = parent->right;
				}
				w->colour = parent->colour;
				if (parent != NIL) parent->colour = BLACK;
				if (w->right->colour != BLACK) {
					w->right->colour = BLACK;
				}
				rotate_left(tree, parent);
				x = tree->root;
			}
		} else {
			fr_rb_node_t *w = parent->left;
			if (w->colour == RED) {
				w->colour = BLACK;
				parent->colour = RED; /* parent != NIL? */
				rotate_right(tree, parent);
				w = parent->left;
			}
			if ((w->right->colour == BLACK) && (w->left->colour == BLACK)) {
				if (w != NIL) w->colour = RED;
				x = parent;
				parent = x->parent;
			} else {
				if (w->left->colour == BLACK) {
					if (w->right != NIL) w->right->colour = BLACK;
					w->colour = RED;
					rotate_left(tree, w);
					w = parent->left;
				}
				w->colour = parent->colour;
				if (parent != NIL) parent->colour = BLACK;
				if (w->left->colour != BLACK) {
					w->left->colour = BLACK;
				}
				rotate_right(tree, parent);
				x = tree->root;
			}
		}
	}
	if (x != NIL) x->colour = BLACK; /* Avoid cache-dirty on NIL */
}

/** Delete an element (z) from the tree
 *
 */
static void delete_internal(fr_rb_tree_t *tree, fr_rb_node_t *z, bool free_data)
{
	fr_rb_node_t *x, *y;
	fr_rb_node_t *parent;

	if (!z || z == NIL) return;

	if (z->left == NIL || z->right == NIL) {
		/* y has a NIL node as a child */
		y = z;
	} else {
		/* find tree successor with a NIL node as a child */
		y = z->right;
		while (y->left != NIL) y = y->left;
	}

	/* x is y's only child */
	if (y->left != NIL) {
		x = y->left;
	} else {
		x = y->right;	/* may be NIL! */
	}

	/* remove y from the parent chain */
	parent = y->parent;
	if (x != NIL) x->parent = parent;

	if (parent != NIL) {
		if (y == parent->left) {
			parent->left = x;
		} else {
			parent->right = x;
		}
	} else {
		tree->root = x;
	}

	if (y != z) {
		void *y_data = y->data;

		if ((y->colour == BLACK) && parent) delete_fixup(tree, x, parent);

		/*
		 *	The user structure in y->data May include a
		 *	pointer to y.  In that case, we CANNOT delete
		 *	y.  Instead, we copy z (which is now in the
		 *	tree) to y, and fix up the parent/child
		 *	pointers.
		 */
		memcpy(y, z, sizeof(*y));
		y->data = y_data;

		if (y->parent == NIL) {
			tree->root = y;
		} else {
			if (y->parent->left == z) y->parent->left = y;
			if (y->parent->right == z) y->parent->right = y;
		}
		if (y->left->parent == z) y->left->parent = y;
		if (y->right->parent == z) y->right->parent = y;

		tree->node_free(tree, z, free_data);
	} else {
		if (y->colour == BLACK) delete_fixup(tree, x, parent);

		tree->node_free(tree, y, free_data);
	}

	tree->num_elements--;
}


/* Find user data, returning the node
 *
 */
static inline CC_HINT(always_inline) fr_rb_node_t *find_node(fr_rb_tree_t *tree, void const *data)
{
	fr_rb_node_t *current;

	if (unlikely(tree->being_freed)) return NULL;

	current = tree->root;

	while (current != NIL) {
		int result = tree->data_cmp(data, current->data);

		if (result == 0) return current;

		current = (result < 0) ? current->left : current->right;
	}

	return NULL;
}

/** Find an element in the tree, returning the data, not the node
 *
 * @param[in] tree to search in.
 * @param[in] data to find.
 * @return
 *	- User data matching the data passed in.
 *	- NULL if nothing matched passed data.
 *
 * @hidecallergraph
 */
void *fr_rb_find(fr_rb_tree_t *tree, void const *data)
{
	fr_rb_node_t *x;

	if (unlikely(tree->being_freed)) return NULL;
	x = find_node(tree, data);
	if (!x) return NULL;

	return x->data;
}

/** Attempt to find current data in the tree, if it does not exist insert it
 *
 * @param[out] found	Pre-existing data we found.
 * @param[in] tree	to search/insert into.
 * @param[in] data	to find.
 * @return
 *	- 1 if existing data was found, found will be populated.
 *	- 0 if no existing data was found.
 *	- -1 on insert error.
 */
int fr_rb_find_or_insert(void **found, fr_rb_tree_t *tree, void const *data)
{
	fr_rb_node_t *existing;

	switch (insert_node(existing, tree, UNCONST(void *, data))) {
	case 1:
		if (found) *found = existing->data;
		return 1;

	case 0:
		if (found) *found = NULL;
		return 0;

	default:
		if (found) *found = NULL;
		return -1;
	}
}

/** Insert data into a tree
 *
 * @param[in] tree	to insert data into.
 * @param[in] data 	to insert.
 * @return
 *	- true if data was inserted.
 *	- false if data already existed and was not inserted.
 */
bool fr_rb_insert(fr_rb_tree_t *tree, void const *data)
{
	if (insert_node(NULL, tree, UNCONST(void *, data)) == 0) return true;

	return false;
}

/** Replace old data with new data, OR insert if there is no old
 *
 * @param[out] old	data that was replaced.  If this argument
 *			is not NULL, then the old data will not
 *			be freed, even if a free function is
 *			configured.
 * @param[in] tree	to insert data into.
 * @param[in] data 	to replace.
 * @return
 *      - 1 if data was replaced.
 *	- 0 if data was inserted.
 *      - -1 if we failed to replace data
 */
int fr_rb_replace(void **old, fr_rb_tree_t *tree, void const *data)
{
	fr_rb_node_t	*node;

	switch (insert_node(&node, tree, UNCONST(void *, data))) {
	case 1: /* Something exists */
	{
		void	*old_data = node->data;

		/*
		 *	If the fr_node_t is inline with the
		 *	data structure, we need to delete
		 *	the old node out of the tree, and
		 *	perform a normal insert operation.
		 */
		if (tree->node_alloc == _node_inline_alloc) {
			delete_internal(tree, node, false);
			insert_node(NULL, tree, UNCONST(void *, data));
		} else {
			node->data = UNCONST(void *, data);
		}

		if (old) {
			*old = old_data;
		} else if (tree->data_free) {
			tree->data_free(old_data);
		}
		return 1;
	}
	case 0: /* New node was inserted - There was no pre-existing node */
		if (old) *old = NULL;
		return 0;

	default:
		if (old) *old = NULL;
		return -1;
	}
}

/** Remove an entry from the tree, without freeing the data
 *
 * @param[in] tree	to remove data from.
 * @param[in] data 	to remove.
 * @return
 *      - The user data we removed.
 *	- NULL if we couldn't find any matching data.
 */
void *fr_rb_remove(fr_rb_tree_t *tree, void const *data)
{
	fr_rb_node_t *node;

	if (unlikely(tree->being_freed)) return false;
	node = find_node(tree, data);
	if (!node) return NULL;

	if (unlikely(node->being_freed)) return node->data;

	delete_internal(tree, node, false);

	return node->data;
}

/** Remove node and free data (if a free function was specified)
 *
 * @param[in] tree	to remove data from.
 * @param[in] data 	to remove/free.
 * @return
 *	- true if we removed data.
 *      - false if we couldn't find any matching data.
 */
bool fr_rb_delete(fr_rb_tree_t *tree, void const *data)
{
	fr_rb_node_t *node;

	if (unlikely(tree->being_freed)) return false;
	node = find_node(tree, data);
	if (!node) return false;

	if (unlikely(node->being_freed)) return true;

	delete_internal(tree, node, true);

	return true;
}

/** Return how many nodes there are in a tree
 *
 * @param[in] tree	to return node count for.
 */
uint32_t fr_rb_num_elements(fr_rb_tree_t *tree)
{
	return tree->num_elements;
}

/** Initialise an in-order iterator
 *
 * @param[out] iter	to initialise.
 * @param[in] tree	to iterate over.
 * @return
 *	- The first node.  Mutex will be held.
 *	- NULL if the tree is empty.
 */
void *fr_rb_iter_init_inorder(fr_rb_iter_inorder_t *iter, fr_rb_tree_t *tree)
{
	fr_rb_node_t *x = tree->root;

	if (x == NIL) return NULL;

	/*
	 *	First node is the leftmost
	 */
	while (x->left != NIL) x = x->left;

	*iter = (fr_rb_iter_inorder_t){
		.tree = tree,
		.node = x
	};

	return x->data;
}

/** Return the next node
 *
 * @param[in] iter	previously initialised with #fr_rb_iter_init
 * @return
 *	- The next node.
 *	- NULL if no more nodes remain.
 */
void *fr_rb_iter_next_inorder(fr_rb_iter_inorder_t *iter)
{
	fr_rb_node_t *x = iter->node, *y;

	/*
	 *	Catch callers repeatedly calling iterator
	 *	at the end.
	 */
	if (unlikely(iter->node == NIL)) return NULL;

	/*
	 *	fr_rb_iter_delete() has already deleted this node,
	 *	and saved the next one for us. (We check for NULL;
	 *	NIL just means we're at the end.)
	 */
	if (!iter->node) {
		iter->node = iter->next;
		iter->next = NULL;
		return iter->node->data;
	}

	if (x->right != NIL) {
		x = x->right;

		while (x->left != NIL) x = x->left;
		iter->node = x;

		return x->data;
	}

	y = x;
	x = x->parent;
	while ((x != NIL) && (y == x->right)) {
		y = x;
		x = x->parent;
	}

	iter->node = x;

	return x->data;
}

/** Remove the current node from the tree
 *
 * @note Only makes sense for in-order traversals.
 *
 * @param[in] iter	previously initialised with #fr_rb_iter_inorder_init
 */
void fr_rb_iter_delete_inorder(fr_rb_iter_inorder_t *iter)
{
	fr_rb_node_t *x = iter->node;

	if (unlikely(x == NIL)) return;
	(void) fr_rb_iter_next_inorder(iter);
	iter->next = iter->node;
	iter->node = NULL;
	delete_internal(iter->tree, x, true);
}

/** Initialise a pre-order iterator
 *
 * @param[out] iter	to initialise.
 * @param[in] tree	to iterate over.
 * @return
 *	- The first node.  Mutex will be held.
 *	- NULL if the tree is empty.
 */
void *fr_rb_iter_init_preorder(fr_rb_iter_preorder_t *iter, fr_rb_tree_t *tree)
{
	fr_rb_node_t *x = tree->root;

	if (x == NIL) return NULL;

	/*
	 *	First, the root.
	 */
	*iter = (fr_rb_iter_preorder_t){
		.tree = tree,
		.node = x
	};

	return x->data;
}

/** Return the next node
 *
 * @param[in] iter	previously initialised with #fr_rb_iter_init
 * @return
 *	- The next node.
 *	- NULL if no more nodes remain.
 */
void *fr_rb_iter_next_preorder(fr_rb_iter_preorder_t *iter)
{
	fr_rb_node_t *x = iter->node, *y;

	/*
	 *	Catch callers repeatedly calling iterator
	 *	at the end.
	 */
	if (unlikely(iter->node == NIL)) return NULL;

	/*
	 * Next is a child of the just-returned node, if it has one.
	 * (Left child first.)
	 */
	if (x->left != NIL) {
		x = x->left;
		iter->node = x;
		return x->data;
	}
	if (x->right != NIL) {
		x = x->right;
		iter->node = x;
		return x->data;
	}

	/*
	 * Otherwise, the nearest ancestor's unreturned right
	 * child, if one exists.
	 */
	for (; (y = x->parent) != NIL; x = y) {
		if (y->right != NIL && y->right != x) {
			x = y->right;
			iter->node = x;
			return x->data;
		}
	}

	/*
	 * None of the above? We're done.
	 */
	iter->node = NIL;

	return NULL;
}

/** Initialise a post-order iterator
 *
 * @param[out] iter	to initialise.
 * @param[in] tree	to iterate over.
 * @return
 *	- The first node.
 *	- NULL if the tree is empty.
 */
void *fr_rb_iter_init_postorder(fr_rb_iter_postorder_t *iter, fr_rb_tree_t *tree)
{
	fr_rb_node_t *x = tree->root;

	if (x == NIL) return NULL;

	/*
	 *	First: the deepest leaf to the left (jogging to the
	 *	right if there's a right child but no left).
	 */
	for (;;) {
		for (; x->left != NIL; x = x->left) ;
		if (x->right == NIL) break;
		x = x->right;
	}

	*iter = (fr_rb_iter_postorder_t){
		.tree = tree,
		.node = x
	};

	return x->data;
}

/** Return the next node
 *
 * @param[in] iter	previously initialised with #fr_rb_iter_init
 * @return
 *	- The next node.
 *	- NULL if no more nodes remain.
 */
void *fr_rb_iter_next_postorder(fr_rb_iter_postorder_t *iter)
{
	fr_rb_node_t *x = iter->node, *y;

	/*
	 *	Catch callers repeatedly calling iterator
	 *	at the end.
	 */
	if (unlikely(iter->node == NIL)) return NULL;

	/*
	 *	This is postorder, so a just-returned node's
	 *	descendants have all been returned. If there
	 *	is another node, it's an ancestor or one of
	 *	its not-yet-returned descendants...but if
	 *	we're at the root, we're done.
	 */
	y = x->parent;
	if (y == NIL) {
		iter->node = NIL;
		return NULL;
	}

	/*
	 * Return the parent if it has no right child, or it has one but
	 * it's been returned.
	 */
	if (y->right == NIL || y->right == x) {
		iter->node = y;
		return y->data;
	}

	/*
	 * Otherwise, it's as if we're starting over with the right child.
	 */
	x = y->right;
	for (;;) {
		for (; x->left != NIL; x = x->left) ;
		if (x->right == NIL) break;
		x = x->right;
	}

	iter->node = x;
	return x->data;
}

#define DEF_RB_FLATTEN_FUNC(_order) \
int fr_rb_flatten_##_order(TALLOC_CTX *ctx, void **out[], fr_rb_tree_t *tree) \
{ \
	uint32_t num = fr_rb_num_elements(tree), i; \
	fr_rb_iter_##_order##_t iter; \
	void *item, **list; \
	if (unlikely(!(list = talloc_array(ctx, void *, num)))) return -1; \
	for (item = fr_rb_iter_init_##_order(&iter, tree), i = 0; \
	     item; \
	     item = fr_rb_iter_next_##_order(&iter), i++) list[i] = item; \
	*out = list; \
	return 0; \
}
DEF_RB_FLATTEN_FUNC(preorder)
DEF_RB_FLATTEN_FUNC(postorder)
DEF_RB_FLATTEN_FUNC(inorder)
