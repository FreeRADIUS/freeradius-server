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
 * @file src/lib/util/rbtree.c
 *
 * @copyright 2004,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/rbtree.h>
#include <freeradius-devel/util/strerror.h>

#include <pthread.h>

#define NIL &sentinel	   /* all leafs are sentinels */
static fr_rb_node_t sentinel = { NIL, NIL, NULL, BLACK, NULL};

struct rbtree_s {
#ifndef NDEBUG
	uint32_t		magic;
#endif
	fr_rb_node_t		*root;		//!< Root of the rbtree.

	size_t			offset;		//!< Where's the fr_rb_node_t is located in
						///< the structure being inserted.
	char const		*type;		//!< Talloc type to check elements against.

	uint64_t		num_elements;	//!< How many elements are inside the tree.
	fr_rb_cmp_t		compare;	//!< The comparator.
	fr_rb_free_t		free;		//!< Free function called when a node is freed.

	bool			replace;	//!< Allow replacements.
	bool			lock;		//!< Ensure exclusive access.
	pthread_mutex_t		mutex;		//!< Mutex to ensure exclusive access.

	bool			being_freed;	//!< Prevent double frees in talloc_destructor.
};

#ifndef NDEBUG
#  define RBTREE_MAGIC (0x5ad09c42)
#endif

static inline void rbtree_free_data(rbtree_t *tree, fr_rb_node_t *node)
{
	if (!tree->free || unlikely(node->being_freed)) return;
	node->being_freed = true;
	tree->free(node->data);
	node->being_freed = false;
}

/** Walks the tree to delete all nodes Does NOT re-balance it!
 *
 */
static void free_walker(rbtree_t *tree, fr_rb_node_t *x)
{
	(void) talloc_get_type_abort(x, fr_rb_node_t);

	if (x->left != NIL) free_walker(tree, x->left);
	if (x->right != NIL) free_walker(tree, x->right);

	rbtree_free_data(tree, x);
	talloc_free(x);
}

/** Wrapper function for rbtree_alloc to allow talloc node data to be freed
 *
 * @param[in] data	Talloced data to free.
 */
void rbtree_node_talloc_free(void *data)
{
	talloc_free(data);
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
static int _tree_free(rbtree_t *tree)
{
	/*
	 *	Prevent duplicate frees
	 */
	if (unlikely(tree->being_freed)) return -1;
	tree->being_freed = true;

	/*
	 *	walk the tree, deleting the nodes...
	 */
	if ((tree->root != NIL) && tree->free) free_walker(tree, tree->root);

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

	/*
	 *	Clear up locks.
	 */
	if (tree->lock) pthread_mutex_destroy(&tree->mutex);

	return 0;
}

/** Create a new RED-BLACK tree
 *
 * @note Due to the node memory being allocated from a different pool to the main
 *
 * @param[in] ctx		to allocate the tree in.
 *				Only the tree is allocated in this context, the memory
 *				for the #fr_rb_node_t is allocated as part of the data
 *				being inserted into the tree.
 * @param[in] offset		offsetof the #fr_rb_node_t field in the data being inserted.
 * @param[in] type		Talloc type of structures being inserted, may be NULL.
 * @param[in] compare		Comparator function for ordering data in the tree.
 * @param[in] node_free		Free function to call whenever data is deleted or replaced.
 * @param[in] flags		A bitfield of flags.
 *				- RBTREE_FLAG_REPLACE - replace nodes if a duplicate is found.
 *				- RBTREE_FLAG_LOCK - use a mutex to prevent concurrent access
 *				to the tree.
 * @return
 *      - A new tree on success.
 *	- NULL on failure.
 */
rbtree_t *_rbtree_alloc(TALLOC_CTX *ctx,
			size_t offset, char const *type,
			fr_rb_cmp_t compare, fr_rb_free_t node_free,
			int flags)
{
	rbtree_t *tree;

	tree = talloc(ctx, rbtree_t);
	if (!tree) return NULL;

	*tree = (rbtree_t) {
#ifndef NDEBUG
		.magic = RBTREE_MAGIC,
#endif
		.root = NIL,
		.offset = offset,
		.type = type,
		.compare = compare,
		.replace = ((flags & RBTREE_FLAG_REPLACE) != 0),
		.lock = ((flags & RBTREE_FLAG_LOCK) != 0),
		.free = node_free
	};
	if (tree->lock) pthread_mutex_init(&tree->mutex, NULL);

	talloc_set_destructor(tree, _tree_free);

	return tree;
}

/** Explicitly unlock an rbtree locked with an interator
 *
 */
void rbtree_unlock(rbtree_t *tree)
{
	if (!tree->lock) return;

	pthread_mutex_unlock(&tree->mutex);
}

/** Rotate Node x to left
 *
 */
static void rotate_left(rbtree_t *tree, fr_rb_node_t *x)
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
static void rotate_right(rbtree_t *tree, fr_rb_node_t *x)
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
static void insert_fixup(rbtree_t *tree, fr_rb_node_t *x)
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
 */
fr_rb_node_t *rbtree_insert_node(rbtree_t *tree, void *data)
{
	fr_rb_node_t *current, *parent, *x;

	if (unlikely(tree->being_freed)) return NULL;

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
	if (tree->type) (void)_talloc_get_type_abort(data, tree->type, __location__);
#endif

	if (tree->lock) pthread_mutex_lock(&tree->mutex);

	/* find where node belongs */
	current = tree->root;
	parent = NIL;
	while (current != NIL) {
		int result;

		/*
		 *	See if two entries are identical.
		 */
		result = tree->compare(data, current->data);
		if (result == 0) {
			/*
			 *	Don't replace the entry.
			 */
			if (!tree->replace) {
				if (tree->lock) pthread_mutex_unlock(&tree->mutex);
				return NULL;
			}

			/*
			 *	Do replace the entry.
			 */
			rbtree_free_data(tree, current->data);

			x = talloc_zero(tree, fr_rb_node_t);
			if (!x) {
				fr_strerror_const("No memory for new rbtree node");
				if (tree->lock) pthread_mutex_unlock(&tree->mutex);
				return NULL;
			}
			memcpy(x, current, sizeof(*x));
			x->data = data;

			/*
			 *	Replace old with new node
			 */
			if (current->parent->left == current) {
				current->parent->left = x;
			} else if (current->parent->right == current) {
				current->parent->right = x;
			}

			if (x->left != NIL) x->left->parent = x;
			if (x->right != NIL) x->right->parent = x;

			talloc_free(current);

			if (tree->lock) pthread_mutex_unlock(&tree->mutex);
			return x;
		}

		parent = current;
		current = (result < 0) ? current->left : current->right;
	}

	/* setup new node */
	x = talloc_zero(tree, fr_rb_node_t);
	if (!x) {
		fr_strerror_const("No memory for new rbtree node");
		if (tree->lock) pthread_mutex_unlock(&tree->mutex);
		return NULL;
	}
	*x = (fr_rb_node_t){
		.data = data,
		.parent = parent,
		.left = NIL,
		.right = NIL,
		.colour = RED
	};

	/* insert node in tree */
	if (parent != NIL) {
		if (tree->compare(data, parent->data) <= 0) {
			parent->left = x;
		} else {
			parent->right = x;
		}
	} else {
		tree->root = x;
	}

	insert_fixup(tree, x);

	tree->num_elements++;

	if (tree->lock) pthread_mutex_unlock(&tree->mutex);
	return x;
}

bool rbtree_insert(rbtree_t *tree, void const *data)
{
	if (rbtree_insert_node(tree, UNCONST(void *, data))) return true;
	return false;
}

/** Maintain RED-BLACK tree balance after deleting node x
 *
 */
static void delete_fixup(rbtree_t *tree, fr_rb_node_t *x, fr_rb_node_t *parent)
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
static void rbtree_delete_internal(rbtree_t *tree, fr_rb_node_t *z, bool skiplock)
{
	fr_rb_node_t *x, *y;
	fr_rb_node_t *parent;

	if (!z || z == NIL) return;

	if (!skiplock) {
		if (tree->lock) pthread_mutex_lock(&tree->mutex);
	}

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

		rbtree_free_data(tree, z);
		talloc_free(z);
	} else {
		if (y->colour == BLACK) delete_fixup(tree, x, parent);

		rbtree_free_data(tree, y);
		talloc_free(y);
	}

	tree->num_elements--;
	if (!skiplock) {
		if (tree->lock) pthread_mutex_unlock(&tree->mutex);
	}
}

void rbtree_delete(rbtree_t *tree, fr_rb_node_t *z)
{
	if (unlikely(tree->being_freed) || unlikely(z->being_freed)) return;

	rbtree_delete_internal(tree, z, false);
}

/** Delete a node from the tree, based on given data, which MUST have come from rbtree_finddata().
 *
 *
 */
bool rbtree_deletebydata(rbtree_t *tree, void const *data)
{
	fr_rb_node_t *node;

	if (unlikely(tree->being_freed)) return false;

	node = rbtree_find(tree, data);
	if (!node) return false;

	rbtree_delete(tree, node);

	return true;
}


/* Find user data, returning the node
 *
 */
fr_rb_node_t *rbtree_find(rbtree_t *tree, void const *data)
{
	fr_rb_node_t *current;

	if (unlikely(tree->being_freed)) return NULL;

	if (tree->lock) pthread_mutex_lock(&tree->mutex);
	current = tree->root;

	while (current != NIL) {
		int result = tree->compare(data, current->data);

		if (result == 0) {
			if (tree->lock) pthread_mutex_unlock(&tree->mutex);
			return current;
		} else {
			current = (result < 0) ?
				current->left : current->right;
		}
	}

	if (tree->lock) pthread_mutex_unlock(&tree->mutex);
	return NULL;
}

/** Find an element in the tree, returning the data, not the node
 *
 * @hidecallergraph
 */
void *rbtree_finddata(rbtree_t *tree, void const *data)
{
	fr_rb_node_t *x;

	if (unlikely(tree->being_freed)) return NULL;

	x = rbtree_find(tree, data);
	if (!x) return NULL;

	return x->data;
}

uint32_t rbtree_num_elements(rbtree_t *tree)
{
	return tree->num_elements;
}

/*
 *	Given a Node, return the data.
 */
void *rbtree_node2data(UNUSED rbtree_t *tree, fr_rb_node_t *node)
{
	if (!node) return NULL;

	return node->data;
}

/** Initialise an in-order iterator
 *
 * @note If iteration ends early because of a loop condition #rbtree_iter_done must be called.
 *
 * @param[out] iter to initialise.
 * @param[in] tree to iterate over.
 * @return
 *	- The first node.  Mutex will be held.
 *	- NULL if the tree is empty.
 */
void *rbtree_iter_init_inorder(fr_rb_tree_iter_inorder_t *iter, rbtree_t *tree)
{
	fr_rb_node_t *x = tree->root;

	if (x == NIL) return NULL;

	if (tree->lock) pthread_mutex_lock(&tree->mutex);

	/*
	 *	First node is the leftmost
	 */
	while (x->left != NIL) x = x->left;

	*iter = (fr_rb_tree_iter_inorder_t){
		.tree = tree,
		.node = x
	};

	return x->data;
}

/** Return the next node
 *
 * @note Will unlock the tree if no more elements remain.
 *
 * @param[in] iter	previously initialised with #rbtree_iter_init
 * @return
 *	- The next node.
 *	- NULL if no more nodes remain.
 */
void *rbtree_iter_next_inorder(fr_rb_tree_iter_inorder_t *iter)
{
	fr_rb_node_t *x = iter->node, *y;

	/*
	 *	Catch callers repeatedly calling iterator
	 *	at the end.
	 */
	if (unlikely(iter->node == NIL)) return NULL;

	/*
	 *	rbtree_iter_delete() has already deleted this node,
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

	/*
	 *	No more nodes available, unlock the
	 *	tree, we're done.
	 */
	if (iter->tree->lock && (x == NIL)) {
		pthread_mutex_unlock(&iter->tree->mutex);
		return NULL;
	}

	return x->data;
}

/** Remove the current node from the tree
 *
 * @note Only makes sense for in-order traversals.
 *
 * @param[in] iter	previously initialised with #rbtree_iter_inorder_init
 */
void rbtree_iter_delete_inorder(fr_rb_tree_iter_inorder_t *iter)
{
	fr_rb_node_t *x = iter->node;

	if (unlikely(x == NIL)) return;
	(void) rbtree_iter_next_inorder(iter);
	iter->next = iter->node;
	iter->node = NULL;
	rbtree_delete_internal(iter->tree, x, true);
}

/** Initialise a pre-order iterator
 *
 * @note If iteration ends early because of a loop condition #rbtree_iter_done must be called.
 *
 * @param[out] iter to initialise.
 * @param[in] tree to iterate over.
 * @return
 *	- The first node.  Mutex will be held.
 *	- NULL if the tree is empty.
 */
void *rbtree_iter_init_preorder(fr_rb_tree_iter_preorder_t  *iter, rbtree_t *tree)
{
	fr_rb_node_t *x = tree->root;

	if (x == NIL) return NULL;

	if (tree->lock) pthread_mutex_lock(&tree->mutex);

	/*
	 *	First, the root.
	 */
	*iter = (fr_rb_tree_iter_preorder_t){
		.tree = tree,
		.node = x
	};

	return x->data;
}

/** Return the next node
 *
 * @note Will unlock the tree if no more elements remain.
 *
 * @param[in] iter	previously initialised with #rbtree_iter_init
 * @return
 *	- The next node.
 *	- NULL if no more nodes remain.
 */
void *rbtree_iter_next_preorder(fr_rb_tree_iter_preorder_t  *iter)
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
	if (iter->tree->lock)
		pthread_mutex_unlock(&iter->tree->mutex);
	return NULL;
}

/** Initialise a post-order iterator
 *
 * @note If iteration ends early because of a loop condition #rbtree_iter_done must be called.
 *
 * @param[out] iter to initialise.
 * @param[in] tree to iterate over.
 * @return
 *	- The first node.  Mutex will be held.
 *	- NULL if the tree is empty.
 */
void *rbtree_iter_init_postorder(fr_rb_tree_iter_postorder_t  *iter, rbtree_t *tree)
{
	fr_rb_node_t *x = tree->root;

	if (x == NIL) return NULL;

	if (tree->lock) pthread_mutex_lock(&tree->mutex);

	/*
	 *	First: the deepest leaf to the left (jogging to the
	 *	right if there's a right child but no left).
	 */
	for (;;) {
		for (; x->left != NIL; x = x->left) ;
		if (x->right == NIL) break;
		x = x->right;
	}

	*iter = (fr_rb_tree_iter_postorder_t){
		.tree = tree,
		.node = x
	};

	return x->data;
}

/** Return the next node
 *
 * @note Will unlock the tree if no more elements remain.
 *
 * @param[in] iter	previously initialised with #rbtree_iter_init
 * @return
 *	- The next node.
 *	- NULL if no more nodes remain.
 */
void *rbtree_iter_next_postorder(fr_rb_tree_iter_postorder_t  *iter)
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
		if (iter->tree->lock) pthread_mutex_unlock(&iter->tree->mutex);
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
