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
	fr_rb_cmp_t	compare;	//!< The comparator.
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
	if (tree->root != NIL) free_walker(tree, tree->root);

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
 */
rbtree_t *_rbtree_alloc(TALLOC_CTX *ctx, fr_rb_cmp_t compare,
			 char const *type, fr_rb_free_t node_free, int flags)
{
	rbtree_t *tree;

	tree = talloc(ctx, rbtree_t);
	if (!tree) return NULL;

	*tree = (rbtree_t) {
#ifndef NDEBUG
		.magic = RBTREE_MAGIC,
#endif
		.root = NIL,
//		.offset = offset,
		.type = type,
		.compare = compare,
		.replace = ((flags & RBTREE_FLAG_REPLACE) != 0),
		.lock = ((flags & RBTREE_FLAG_LOCK) != 0),
		.free = node_free
	};
	if (tree->lock) pthread_mutex_init(&tree->mutex, NULL);

	talloc_set_destructor(tree, _tree_free);
	tree->free = node_free;
	tree->type = type;

	return tree;
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
	if (x->parent) {
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
	if (x->parent) {
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
	parent = NULL;
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
	if (parent) {
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
	void *mutable;

	if (unlikely(tree->being_freed)) return NULL;

	memcpy(&mutable, &data, sizeof(mutable));

	if (rbtree_insert_node(tree, mutable)) return true;
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

	if (parent) {
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

		if (!y->parent) {
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

/** Walk the tree, Pre-order
 *
 * We call ourselves recursively for each function, but that's OK,
 * as the stack is only log(N) deep, which is ~12 entries deep.
 */
static int walk_node_pre_order(fr_rb_node_t *x, fr_rb_walker_t compare, void *uctx)
{
	int		ret;
	fr_rb_node_t	*left, *right;

	left = x->left;
	right = x->right;

	ret = compare(x->data, uctx);
	if (ret != 0) return ret;

	if (left != NIL) {
		ret = walk_node_pre_order(left, compare, uctx);
		if (ret != 0) return ret;
	}

	if (right != NIL) {
		ret = walk_node_pre_order(right, compare, uctx);
		if (ret != 0) return ret;
	}

	return 0;/* we know everything returned zero */
}

/** rbtree_in_order
 *
 */
static int walk_node_in_order(fr_rb_node_t *x, fr_rb_walker_t compare, void *uctx)
{
	int ret;
	fr_rb_node_t *right;

	if (x->left != NIL) {
		ret = walk_node_in_order(x->left, compare, uctx);
		if (ret != 0) return ret;
	}

	right = x->right;

	ret = compare(x->data, uctx);
	if (ret != 0) return ret;

	if (right != NIL) {
		ret = walk_node_in_order(right, compare, uctx);
		if (ret != 0) return ret;
	}

	return 0;		/* we know everything returned zero */
}


/** rbtree_post_order
 *
 */
static int walk_node_post_order(fr_rb_node_t *x, fr_rb_walker_t compare, void *uctx)
{
	int ret;

	if (x->left != NIL) {
		ret = walk_node_post_order(x->left, compare, uctx);
		if (ret != 0) return ret;
	}

	if (x->right != NIL) {
		ret = walk_node_post_order(x->right, compare, uctx);
		if (ret != 0) return ret;
	}

	ret = compare(x->data, uctx);
	if (ret != 0) return ret;

	return 0;		/* we know everything returned zero */
}

/** rbtree_delete_order
 *
 *	This executes an rbtree_in_order-like walk that adapts to changes in the
 *	tree above it, which may occur because we allow the compare to
 *	tell us to delete the current node.
 *
 *	The compare should return:
 *
 *		< 0  - on error
 *		0    - continue walking, don't delete the node
 *		1    - delete the node and stop walking
 *		2    - delete the node and continue walking
 */
static int walk_delete_order(rbtree_t *tree, fr_rb_walker_t compare, void *uctx)
{
	fr_rb_node_t *solid, *x;
	int ret = 0;

	/* Keep track of last node that refused deletion. */
	solid = NIL;
	while (solid == NIL) {
		x = tree->root;
		if (x == NIL) break;
	descend:
		while (x->left != NIL) {
			x = x->left;
		}
	visit:
		ret = compare(x->data, uctx);
		if (ret < 0) {
			return ret;
		}
		if (ret) {
			rbtree_delete_internal(tree, x, true);
			if (ret != 2) {
				return ret;
			}
		} else {
			solid = x;
		}
	}
	if (solid != NIL) {
		x = solid;
		if (x->right != NIL) {
			x = x->right;
			goto descend;
		}
		while (x->parent) {
			if (x->parent->left == x) {
				x = x->parent;
				goto visit;
			}
			x = x->parent;
		}
	}
	return ret;
}


/*
 *	walk the entire tree.  The compare function CANNOT modify
 *	the tree.
 *
 *	The compare function should return 0 to continue walking.
 *	Any other value stops the walk, and is returned.
 */
int rbtree_walk(rbtree_t *tree, fr_rb_order_t order, fr_rb_walker_t compare, void *uctx)
{
	int ret;

	if (tree->root == NIL) return 0;

	if (tree->lock) pthread_mutex_lock(&tree->mutex);

	switch (order) {
	case RBTREE_PRE_ORDER:
		ret = walk_node_pre_order(tree->root, compare, uctx);
		break;

	case RBTREE_IN_ORDER:
		ret = walk_node_in_order(tree->root, compare, uctx);
		break;

	case RBTREE_POST_ORDER:
		ret = walk_node_post_order(tree->root, compare, uctx);
		break;

	case RBTREE_DELETE_ORDER:
		ret = walk_delete_order(tree, compare, uctx);
		break;

	default:
		ret = -1;
		break;
	}

	if (tree->lock) pthread_mutex_unlock(&tree->mutex);
	return ret;
}

uint32_t rbtree_num_elements(rbtree_t *tree)
{
	if (!tree) return 0;

	return tree->num_elements;
}

typedef struct {
	size_t			idx;
	void			**data;
} rbtree_flatten_ctx_t;

static int _flatten_cb(void *data, void *uctx)
{
	rbtree_flatten_ctx_t *ctx = uctx;
	ctx->data[ctx->idx++] = data;
	return 0;
}

/** Return an array containing all elements in the tree, in the specified order
 *
 * @param[in] ctx	Where to allocate the array.
 * @param[out] out	Where to write a pointer to the array.
 * @param[in] tree	to flatten.
 * @param[in] order	to flatten the tree in.
 * @return
 *	- The number of elements in the tree.
 */
uint32_t rbtree_flatten(TALLOC_CTX *ctx, void **out[], rbtree_t *tree, fr_rb_order_t order)
{
	uint32_t		num = rbtree_num_elements(tree);
	rbtree_flatten_ctx_t	uctx;

	if (unlikely(!tree)) {
		*out = NULL;
		return 0;
	}

	uctx.idx = 0;
	uctx.data = talloc_array(ctx, void *, num);
	if (!uctx.data) return 0;
	rbtree_walk(tree, order, _flatten_cb, &uctx);
	*out = uctx.data;

	return uctx.idx;
}

/*
 *	Given a Node, return the data.
 */
void *rbtree_node2data(UNUSED rbtree_t *tree, fr_rb_node_t *node)
{
	if (!node) return NULL;

	return node->data;
}
