/*
 * rbtree.c	Red-black balanced binary trees.
 *
 * Version:	$Id$
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 *  Copyright 2004,2006  The FreeRADIUS server project
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/libradius.h>

/* red-black tree description */
typedef enum { Black, Red } NodeColor;

struct rbnode_t {
    rbnode_t	*Left;		/* left child */
    rbnode_t	*Right;		/* right child */
    rbnode_t	*Parent;	/* parent */
    NodeColor	Color;		/* node color (black, red) */
    void	*Data;		/* data stored in node */
};

#define NIL &Sentinel           /* all leafs are sentinels */
static rbnode_t Sentinel = { NIL, NIL, NULL, Black, NULL};

struct rbtree_t {
#ifndef NDEBUG
	uint32_t magic;
#endif
	rbnode_t *Root;
	int	num_elements;
	int (*Compare)(const void *, const void *);
	int replace_flag;
	void (*freeNode)(void *);
};
#define RBTREE_MAGIC (0x5ad09c42)

/*
 *	Walks the tree to delete all nodes.
 *	Does NOT re-balance it!
 */
static void FreeWalker(rbtree_t *tree, rbnode_t *X)
{
	if (X->Left != NIL) FreeWalker(tree, X->Left);
	if (X->Right != NIL) FreeWalker(tree, X->Right);

	if (tree->freeNode) tree->freeNode(X->Data);
	free(X);
}

void rbtree_free(rbtree_t *tree)
{
	if (!tree) return;

	/*
	 *	Walk the tree, deleting the nodes...
	 */
	if (tree->Root != NIL) FreeWalker(tree, tree->Root);

#ifndef NDEBUG
	tree->magic = 0;
#endif
	tree->Root = NULL;
	free(tree);
}

/*
 *	Create a new red-black tree.
 */
rbtree_t *rbtree_create(int (*Compare)(const void *, const void *),
			void (*freeNode)(void *),
			int replace_flag)
{
	rbtree_t	*tree;

	if (!Compare) return NULL;

	tree = malloc(sizeof(*tree));
	if (!tree) return NULL;

	memset(tree, 0, sizeof(*tree));
#ifndef NDEBUG
	tree->magic = RBTREE_MAGIC;
#endif
	tree->Root = NIL;
	tree->Compare = Compare;
	tree->replace_flag = replace_flag;
	tree->freeNode = freeNode;

	return tree;
}


static void RotateLeft(rbtree_t *tree, rbnode_t *X)
{
	/**************************
	 *  rotate Node X to left *
	 **************************/

	rbnode_t *Y = X->Right;

	/* establish X->Right link */
	X->Right = Y->Left;
	if (Y->Left != NIL) Y->Left->Parent = X;

	/* establish Y->Parent link */
	if (Y != NIL) Y->Parent = X->Parent;
	if (X->Parent) {
		if (X == X->Parent->Left)
			X->Parent->Left = Y;
		else
			X->Parent->Right = Y;
	} else {
		tree->Root = Y;
	}

	/* link X and Y */
	Y->Left = X;
	if (X != NIL) X->Parent = Y;
}

static void RotateRight(rbtree_t *tree, rbnode_t *X)
{
	/****************************
	 *  rotate Node X to right  *
	 ****************************/

	rbnode_t *Y = X->Left;

	/* establish X->Left link */
	X->Left = Y->Right;
	if (Y->Right != NIL) Y->Right->Parent = X;

	/* establish Y->Parent link */
	if (Y != NIL) Y->Parent = X->Parent;
	if (X->Parent) {
		if (X == X->Parent->Right)
			X->Parent->Right = Y;
		else
			X->Parent->Left = Y;
	} else {
		tree->Root = Y;
	}

	/* link X and Y */
	Y->Right = X;
	if (X != NIL) X->Parent = Y;
}

static void InsertFixup(rbtree_t *tree, rbnode_t *X)
{
	/*************************************
	 *  maintain red-black tree balance  *
	 *  after inserting node X           *
	 *************************************/

	/* check red-black properties */
	while (X != tree->Root && X->Parent->Color == Red) {
		/* we have a violation */
		if (X->Parent == X->Parent->Parent->Left) {
			rbnode_t *Y = X->Parent->Parent->Right;
			if (Y->Color == Red) {

				/* uncle is red */
				X->Parent->Color = Black;
				Y->Color = Black;
				X->Parent->Parent->Color = Red;
				X = X->Parent->Parent;
			} else {

				/* uncle is black */
				if (X == X->Parent->Right) {
					/* make X a left child */
					X = X->Parent;
					RotateLeft(tree, X);
				}

				/* recolor and rotate */
				X->Parent->Color = Black;
				X->Parent->Parent->Color = Red;
				RotateRight(tree, X->Parent->Parent);
			}
		} else {

			/* mirror image of above code */
			rbnode_t *Y = X->Parent->Parent->Left;
			if (Y->Color == Red) {

				/* uncle is red */
				X->Parent->Color = Black;
				Y->Color = Black;
				X->Parent->Parent->Color = Red;
				X = X->Parent->Parent;
			} else {

				/* uncle is black */
				if (X == X->Parent->Left) {
					X = X->Parent;
					RotateRight(tree, X);
				}
				X->Parent->Color = Black;
				X->Parent->Parent->Color = Red;
				RotateLeft(tree, X->Parent->Parent);
			}
		}
	}

	tree->Root->Color = Black;
}


/*
 *	Insert an element into the tree.
 */
rbnode_t *rbtree_insertnode(rbtree_t *tree, void *Data)
{
	rbnode_t *Current, *Parent, *X;

	/***********************************************
	 *  allocate node for Data and insert in tree  *
	 ***********************************************/

	/* find where node belongs */
	Current = tree->Root;
	Parent = NULL;
	while (Current != NIL) {
		int result;

		/*
		 *	See if two entries are identical.
		 */
		result = tree->Compare(Data, Current->Data);
		if (result == 0) {
			/*
			 *	Don't replace the entry.
			 */
			if (tree->replace_flag == 0) {
				return NULL;
			}

			/*
			 *	Do replace the entry.
			 */
			if (tree->freeNode) tree->freeNode(Current->Data);
			Current->Data = Data;
			return Current;
		}

		Parent = Current;
		Current = (result < 0) ? Current->Left : Current->Right;
	}

	/* setup new node */
	if ((X = malloc (sizeof(*X))) == NULL) {
		exit(1);	/* FIXME! */
	}

	X->Data = Data;
	X->Parent = Parent;
	X->Left = NIL;
	X->Right = NIL;
	X->Color = Red;

	/* insert node in tree */
	if (Parent) {
		if (tree->Compare(Data, Parent->Data) <= 0)
			Parent->Left = X;
		else
			Parent->Right = X;
	} else {
		tree->Root = X;
	}

	InsertFixup(tree, X);

	tree->num_elements++;

	return X;
}

int rbtree_insert(rbtree_t *tree, void *Data)
{
	if (rbtree_insertnode(tree, Data)) return 1;
	return 0;
}

static void DeleteFixup(rbtree_t *tree, rbnode_t *X, rbnode_t *Parent)
{
	/*************************************
	 *  maintain red-black tree balance  *
	 *  after deleting node X            *
	 *************************************/

	while (X != tree->Root && X->Color == Black) {
		if (X == Parent->Left) {
			rbnode_t *W = Parent->Right;
			if (W->Color == Red) {
				W->Color = Black;
				Parent->Color = Red; /* Parent != NIL? */
				RotateLeft(tree, Parent);
				W = Parent->Right;
			}
			if (W->Left->Color == Black && W->Right->Color == Black) {
				if (W != NIL) W->Color = Red;
				X = Parent;
				Parent = X->Parent;
			} else {
				if (W->Right->Color == Black) {
					if (W->Left != NIL) W->Left->Color = Black;
					W->Color = Red;
					RotateRight(tree, W);
					W = Parent->Right;
				}
				W->Color = Parent->Color;
				if (Parent != NIL) Parent->Color = Black;
				if (W->Right->Color != Black) {
					W->Right->Color = Black;
				}
				RotateLeft(tree, Parent);
				X = tree->Root;
			}
		} else {
			rbnode_t *W = Parent->Left;
			if (W->Color == Red) {
				W->Color = Black;
				Parent->Color = Red; /* Parent != NIL? */
				RotateRight(tree, Parent);
				W = Parent->Left;
			}
			if (W->Right->Color == Black && W->Left->Color == Black) {
				if (W != NIL) W->Color = Red;
				X = Parent;
				Parent = X->Parent;
			} else {
				if (W->Left->Color == Black) {
					if (W->Right != NIL) W->Right->Color = Black;
					W->Color = Red;
					RotateLeft(tree, W);
					W = Parent->Left;
				}
				W->Color = Parent->Color;
				if (Parent != NIL) Parent->Color = Black;
				if (W->Left->Color != Black) {
					W->Left->Color = Black;
				}
				RotateRight(tree, Parent);
				X = tree->Root;
			}
		}
	}
	X->Color = Black;
}

/*
 *	Delete an element from the tree.
 */
void rbtree_delete(rbtree_t *tree, rbnode_t *Z)
{
	rbnode_t *X, *Y;
	rbnode_t *Parent;

	/*****************************
	 *  delete node Z from tree  *
	 *****************************/

	if (!Z || Z == NIL) return;

	if (Z->Left == NIL || Z->Right == NIL) {
		/* Y has a NIL node as a child */
		Y = Z;
	} else {
		/* find tree successor with a NIL node as a child */
		Y = Z->Right;
		while (Y->Left != NIL) Y = Y->Left;
	}

	/* X is Y's only child */
	if (Y->Left != NIL)
		X = Y->Left;
	else
		X = Y->Right;	/* may be NIL! */

	/* remove Y from the parent chain */
	Parent = Y->Parent;
	if (X != NIL) X->Parent = Parent;

	if (Parent)
		if (Y == Parent->Left)
			Parent->Left = X;
		else
			Parent->Right = X;
	else
		tree->Root = X;

	if (Y != Z) {
		if (tree->freeNode) tree->freeNode(Z->Data);
		Z->Data = Y->Data;
		Y->Data = NULL;

		if (Y->Color == Black && X != NIL)
			DeleteFixup(tree, X, Parent);

		/*
		 *	The user structure in Y->Data MAY include a
		 *	pointer to Y.  In that case, we CANNOT delete
		 *	Y.  Instead, we copy Z (which is now in the
		 *	tree) to Y, and fix up the parent/child
		 *	pointers.
		 */
		memcpy(Y, Z, sizeof(*Y));

		if (!Y->Parent) {
			tree->Root = Y;
		} else {
			if (Y->Parent->Left == Z) Y->Parent->Left = Y;
			if (Y->Parent->Right == Z) Y->Parent->Right = Y;
		}
		if (Y->Left->Parent == Z) Y->Left->Parent = Y;
		if (Y->Right->Parent == Z) Y->Right->Parent = Y;

		free(Z);

	} else {
		if (tree->freeNode) tree->freeNode(Y->Data);

		if (Y->Color == Black && X != NIL)
			DeleteFixup(tree, X, Parent);

		free(Y);
	}

	tree->num_elements--;
}

/*
 *	Delete a node from the tree, based on given data, which MUST
 *	have come from rbtree_finddata().
 */
int rbtree_deletebydata(rbtree_t *tree, const void *data)
{
	rbnode_t *node = rbtree_find(tree, data);

	if (!node) return 0;	/* false */

	rbtree_delete(tree, node);

	return 1;
}


/*
 *	Find an element in the tree, returning the data, not the node.
 */
rbnode_t *rbtree_find(rbtree_t *tree, const void *Data)
{
	/*******************************
	 *  find node containing Data  *
	 *******************************/

	rbnode_t *Current = tree->Root;

	while (Current != NIL) {
		int result = tree->Compare(Data, Current->Data);

		if (result == 0) {
			return Current;
		} else {
			Current = (result < 0) ?
				Current->Left : Current->Right;
		}
	}
	return NULL;
}

/*
 *	Find the user data.
 */
void *rbtree_finddata(rbtree_t *tree, const void *Data)
{
	rbnode_t *X;

	X = rbtree_find(tree, Data);
	if (!X) return NULL;

	return X->Data;
}

/*
 *	Walk the tree, Pre-order
 *
 *	We call ourselves recursively for each function, but that's OK,
 *	as the stack is only log(N) deep, which is ~12 entries deep.
 */
static int WalkNodePreOrder(rbnode_t *X,
			    int (*callback)(void *, void *), void *context)
{
	int rcode;

	rcode = callback(context, X->Data);
	if (rcode != 0) return rcode;

	if (X->Left != NIL) {
		rcode = WalkNodePreOrder(X->Left, callback, context);
		if (rcode != 0) return rcode;
	}

	if (X->Right != NIL) {
		rcode = WalkNodePreOrder(X->Right, callback, context);
		if (rcode != 0) return rcode;
	}

	return 0;		/* we know everything returned zero */
}

/*
 *	Inorder
 */
static int WalkNodeInOrder(rbnode_t *X,
			   int (*callback)(void *, void *), void *context)
{
	int rcode;

	if (X->Left != NIL) {
		rcode = WalkNodeInOrder(X->Left, callback, context);
		if (rcode != 0) return rcode;
	}

	rcode = callback(context, X->Data);
	if (rcode != 0) return rcode;

	if (X->Right != NIL) {
		rcode = WalkNodeInOrder(X->Right, callback, context);
		if (rcode != 0) return rcode;
	}

	return 0;		/* we know everything returned zero */
}


/*
 *	PostOrder
 */
static int WalkNodePostOrder(rbnode_t *X,
			     int (*callback)(void *, void*), void *context)
{
	int rcode;

	if (X->Left != NIL) {
		rcode = WalkNodeInOrder(X->Left, callback, context);
		if (rcode != 0) return rcode;
	}

	if (X->Right != NIL) {
		rcode = WalkNodeInOrder(X->Right, callback, context);
		if (rcode != 0) return rcode;
	}

	rcode = callback(context, X->Data);
	if (rcode != 0) return rcode;

	return 0;		/* we know everything returned zero */
}

/*
 *	Walk the entire tree.  The callback function CANNOT modify
 *	the tree.
 *
 *	The callback function should return 0 to continue walking.
 *	Any other value stops the walk, and is returned.
 */
int rbtree_walk(rbtree_t *tree, RBTREE_ORDER order,
		int (*callback)(void *, void *), void *context)
{
	if (tree->Root == NIL) return 0;

	switch (order) {
	case PreOrder:
		return WalkNodePreOrder(tree->Root, callback, context);
	case InOrder:
		return WalkNodeInOrder(tree->Root, callback, context);
	case PostOrder:
		return WalkNodePostOrder(tree->Root, callback, context);

	default:
		break;
	}

	return -1;
}

int rbtree_num_elements(rbtree_t *tree)
{
	if (!tree) return 0;

	return tree->num_elements;
}


/*
 *	Given a Node, return the data.
 */
void *rbtree_node2data(rbtree_t *tree, rbnode_t *node)
{
	tree = tree;		/* -Wunused */

	if (!node) return NULL;

	return node->Data;
}

/*
 *	Return left-most child.
 */
void *rbtree_min(rbtree_t *tree)
{
	rbnode_t *Current;

	if (!tree || !tree->Root) return NULL;

	Current = tree->Root;
	while (Current->Left != NIL) Current = Current->Left;

	return Current->Data;
}
