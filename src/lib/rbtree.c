/*
 * rbtree.c	RED-BLACK balanced binary trees.
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2.1 of the License, or
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
 *
 *  Copyright 2004,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>

#ifdef HAVE_PTHREAD_H
#include <pthread.h>

#define PTHREAD_MUTEX_LOCK(_x) if (_x->lock) pthread_mutex_lock(&((_x)->mutex))
#define PTHREAD_MUTEX_UNLOCK(_x) if (_x->lock) pthread_mutex_unlock(&((_x)->mutex))
#else
#define PTHREAD_MUTEX_LOCK(_x)
#define PTHREAD_MUTEX_UNLOCK(_x)
#endif

/* Red-Black tree description */
typedef enum {
	BLACK,
	RED
} node_colour_t;

struct rbnode_t {
    rbnode_t		*left;		//!< Left child
    rbnode_t		*right;		//!< Right child
    rbnode_t		*parent;	//!< Parent
    node_colour_t	colour;		//!< Node colour (BLACK, RED)
    void		*data;		//!< data stored in node
};

#define NIL &sentinel	   /* all leafs are sentinels */
static rbnode_t sentinel = { NIL, NIL, NULL, BLACK, NULL};

struct rbtree_t {
#ifndef NDEBUG
	uint32_t		magic;
#endif
	rbnode_t		*root;
	int			num_elements;
	rb_comparator_t		compare;
	rb_free_t		free;
	bool			replace;
#ifdef HAVE_PTHREAD_H
	bool			lock;
	pthread_mutex_t		mutex;
#endif
};
#define RBTREE_MAGIC (0x5ad09c42)

/** Walks the tree to delete all nodes Does NOT re-balance it!
 *
 */
static void free_walker(rbtree_t *tree, rbnode_t *x)
{
	(void) talloc_get_type_abort(x, rbnode_t);

	if (x->left != NIL) free_walker(tree, x->left);
	if (x->right != NIL) free_walker(tree, x->right);

	if (tree->free) tree->free(x->data);
	talloc_free(x);
}

void rbtree_free(rbtree_t *tree)
{
	if (!tree) return;

	PTHREAD_MUTEX_LOCK(tree);

	/*
	 *	walk the tree, deleting the nodes...
	 */
	if (tree->root != NIL) free_walker(tree, tree->root);

#ifndef NDEBUG
	tree->magic = 0;
#endif
	tree->root = NULL;

	PTHREAD_MUTEX_UNLOCK(tree);

#ifdef HAVE_PTHREAD_H
	if (tree->lock) pthread_mutex_destroy(&tree->mutex);
#endif

	talloc_free(tree);
}

/** Create a new RED-BLACK tree
 *
 */
rbtree_t *rbtree_create(TALLOC_CTX *ctx, rb_comparator_t compare, rb_free_t node_free, int flags)
{
	rbtree_t *tree;

	if (!compare) return NULL;

	tree = talloc_zero(ctx, rbtree_t);
	if (!tree) return NULL;

#ifndef NDEBUG
	tree->magic = RBTREE_MAGIC;
#endif
	tree->root = NIL;
	tree->compare = compare;
	tree->replace = (flags & RBTREE_FLAG_REPLACE) != 0 ? true : false;
#ifdef HAVE_PTHREAD_H
	tree->lock = (flags & RBTREE_FLAG_LOCK) != 0 ? true : false;
	if (tree->lock) {
		pthread_mutex_init(&tree->mutex, NULL);
	}
#endif
	tree->free = node_free;

	return tree;
}

/** Rotate Node x to left
 *
 */
static void rotate_left(rbtree_t *tree, rbnode_t *x)
{

	rbnode_t *y = x->right;

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
static void rotate_right(rbtree_t *tree, rbnode_t *x)
{
	rbnode_t *y = x->left;

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
static void insert_fixup(rbtree_t *tree, rbnode_t *x)
{
	/* check RED-BLACK properties */
	while ((x != tree->root) && (x->parent->colour == RED)) {
		/* we have a violation */
		if (x->parent == x->parent->parent->left) {
			rbnode_t *y = x->parent->parent->right;
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
			rbnode_t *y = x->parent->parent->left;
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
rbnode_t *rbtree_insert_node(rbtree_t *tree, void *data)
{
	rbnode_t *current, *parent, *x;

	PTHREAD_MUTEX_LOCK(tree);

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
				PTHREAD_MUTEX_UNLOCK(tree);
				return NULL;
			}

			/*
			 *	Do replace the entry.
			 */
			if (tree->free) tree->free(current->data);
			current->data = data;
			PTHREAD_MUTEX_UNLOCK(tree);
			return current;
		}

		parent = current;
		current = (result < 0) ? current->left : current->right;
	}

	/* setup new node */
	x = talloc_zero(tree, rbnode_t);
	if (!x) {
		fr_strerror_printf("No memory for new rbtree node");
		PTHREAD_MUTEX_UNLOCK(tree);
		return NULL;
	}

	x->data = data;
	x->parent = parent;
	x->left = NIL;
	x->right = NIL;
	x->colour = RED;

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

	PTHREAD_MUTEX_UNLOCK(tree);
	return x;
}

bool rbtree_insert(rbtree_t *tree, void *data)
{
	if (rbtree_insert_node(tree, data)) return true;
	return false;
}

/** Maintain RED-BLACK tree balance after deleting node x
 *
 */
static void delete_fixup(rbtree_t *tree, rbnode_t *x, rbnode_t *parent)
{

	while (x != tree->root && x->colour == BLACK) {
		if (x == parent->left) {
			rbnode_t *w = parent->right;
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
			rbnode_t *w = parent->left;
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
static void rbtree_delete_internal(rbtree_t *tree, rbnode_t *z, bool skiplock)
{
	rbnode_t *x, *y;
	rbnode_t *parent;

	if (!z || z == NIL) return;

	if (!skiplock) {
		PTHREAD_MUTEX_LOCK(tree);
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
		if (tree->free) tree->free(z->data);
		z->data = y->data;
		y->data = NULL;

		if ((y->colour == BLACK) && parent) {
			delete_fixup(tree, x, parent);
		}

		/*
		 *	The user structure in y->data MAy include a
		 *	pointer to y.  In that case, we CANNOT delete
		 *	y.  Instead, we copy z (which is now in the
		 *	tree) to y, and fix up the parent/child
		 *	pointers.
		 */
		memcpy(y, z, sizeof(*y));

		if (!y->parent) {
			tree->root = y;
		} else {
			if (y->parent->left == z) y->parent->left = y;
			if (y->parent->right == z) y->parent->right = y;
		}
		if (y->left->parent == z) y->left->parent = y;
		if (y->right->parent == z) y->right->parent = y;

		talloc_free(z);

	} else {
		if (tree->free) tree->free(y->data);

		if (y->colour == BLACK)
			delete_fixup(tree, x, parent);

		talloc_free(y);
	}

	tree->num_elements--;
	if (!skiplock) {
		PTHREAD_MUTEX_UNLOCK(tree);
	}
}
void rbtree_delete(rbtree_t *tree, rbnode_t *z) {
	rbtree_delete_internal(tree, z, false);
}

/** Delete a node from the tree, based on given data, which MUST have come from rbtree_finddata().
 *
 *
 */
bool rbtree_deletebydata(rbtree_t *tree, void const *data)
{
	rbnode_t *node = rbtree_find(tree, data);

	if (!node) return false;

	rbtree_delete(tree, node);

	return true;
}


/** Find an element in the tree, returning the data, not the node
 *
 */
rbnode_t *rbtree_find(rbtree_t *tree, void const *data)
{
	rbnode_t *current;

	PTHREAD_MUTEX_LOCK(tree);
	current = tree->root;

	while (current != NIL) {
		int result = tree->compare(data, current->data);

		if (result == 0) {
			PTHREAD_MUTEX_UNLOCK(tree);
			return current;
		} else {
			current = (result < 0) ?
				current->left : current->right;
		}
	}

	PTHREAD_MUTEX_UNLOCK(tree);
	return NULL;
}

/** Find the user data.
 *
 */
void *rbtree_finddata(rbtree_t *tree, void const *data)
{
	rbnode_t *x;

	x = rbtree_find(tree, data);
	if (!x) return NULL;

	return x->data;
}

/** Walk the tree, Pre-order
 *
 * We call ourselves recursively for each function, but that's OK,
 * as the stack is only log(N) deep, which is ~12 entries deep.
 */
static int walk_node_pre_order(rbnode_t *x, rb_walker_t compare, void *context)
{
	int rcode;
	rbnode_t *left, *right;

	left = x->left;
	right = x->right;

	rcode = compare(context, x->data);
	if (rcode != 0) return rcode;

	if (left != NIL) {
		rcode = walk_node_pre_order(left, compare, context);
		if (rcode != 0) return rcode;
	}

	if (right != NIL) {
		rcode = walk_node_pre_order(right, compare, context);
		if (rcode != 0) return rcode;
	}

	return 0;		/* we know everything returned zero */
}

/** rbtree_in_order
 *
 */
static int walk_node_in_order(rbnode_t *x, rb_walker_t compare, void *context)
{
	int rcode;
	rbnode_t *right;

	if (x->left != NIL) {
		rcode = walk_node_in_order(x->left, compare, context);
		if (rcode != 0) return rcode;
	}

	right = x->right;

	rcode = compare(context, x->data);
	if (rcode != 0) return rcode;

	if (right != NIL) {
		rcode = walk_node_in_order(right, compare, context);
		if (rcode != 0) return rcode;
	}

	return 0;		/* we know everything returned zero */
}


/** rbtree_post_order
 *
 */
static int walk_node_post_order(rbnode_t *x, rb_walker_t compare, void *context)
{
	int rcode;

	if (x->left != NIL) {
		rcode = walk_node_post_order(x->left, compare, context);
		if (rcode != 0) return rcode;
	}

	if (x->right != NIL) {
		rcode = walk_node_post_order(x->right, compare, context);
		if (rcode != 0) return rcode;
	}

	rcode = compare(context, x->data);
	if (rcode != 0) return rcode;

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
static int walk_delete_order(rbtree_t *tree, rb_walker_t compare, void *context)
{
	rbnode_t *solid, *x;
	int rcode = 0;

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
		rcode = compare(context, x->data);
		if (rcode < 0) {
			return rcode;
		}
		if (rcode) {
			rbtree_delete_internal(tree, x, true);
			if (rcode != 2) {
				return rcode;
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
	return rcode;
}


/*
 *	walk the entire tree.  The compare function CANNOT modify
 *	the tree.
 *
 *	The compare function should return 0 to continue walking.
 *	Any other value stops the walk, and is returned.
 */
int rbtree_walk(rbtree_t *tree, rb_order_t order, rb_walker_t compare, void *context)
{
	int rcode;

	if (tree->root == NIL) return 0;

	PTHREAD_MUTEX_LOCK(tree);

	switch (order) {
	case RBTREE_PRE_ORDER:
		rcode = walk_node_pre_order(tree->root, compare, context);
		break;

	case RBTREE_IN_ORDER:
		rcode = walk_node_in_order(tree->root, compare, context);
		break;

	case RBTREE_POST_ORDER:
		rcode = walk_node_post_order(tree->root, compare, context);
		break;

	case RBTREE_DELETE_ORDER:
		rcode = walk_delete_order(tree, compare, context);
		break;

	default:
		rcode = -1;
		break;
	}

	PTHREAD_MUTEX_UNLOCK(tree);
	return rcode;
}

uint32_t rbtree_num_elements(rbtree_t *tree)
{
	if (!tree) return 0;

	return tree->num_elements;
}

/*
 *	Given a Node, return the data.
 */
void *rbtree_node2data(UNUSED rbtree_t *tree, rbnode_t *node)
{
	if (!node) return NULL;

	return node->data;
}
