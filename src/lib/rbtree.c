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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
 *
 *  Copyright 2004  The FreeRADIUS server project
 */

static const char rcsid[] = "$Id$";

#include "autoconf.h"

#include <stdlib.h>
#include <string.h>

#include "libradius.h"

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
	if (tree->Root != NULL) FreeWalker(tree, tree->Root);

#ifndef NDEBUG
	tree->magic = 0;
	tree->Root = NULL;
#endif
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
int rbtree_insert(rbtree_t *tree, void *Data)
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
				return 0;
			}

			/*
			 *	Do replace the entry.
			 */
			Current->Data = Data;
			return 1;
		}

		Parent = Current;
		Current = (result < 0) ? Current->Left : Current->Right;
	}
	
	/* setup new node */
	if ((X = malloc (sizeof(*X))) == NULL) {
		exit(1);
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

	return 1;
}


static void DeleteFixup(rbtree_t *tree, rbnode_t *X)
{
	/*************************************
	 *  maintain red-black tree balance  *
	 *  after deleting node X            *
	 *************************************/
	
	while (X != tree->Root && X->Color == Black) {
		if (X == X->Parent->Left) {
			rbnode_t *W = X->Parent->Right;
			if (W->Color == Red) {
				W->Color = Black;
				X->Parent->Color = Red;
				RotateLeft(tree, X->Parent);
				W = X->Parent->Right;
			}
			if (W->Left->Color == Black && W->Right->Color == Black) {
				W->Color = Red;
				X = X->Parent;
			} else {
				if (W->Right->Color == Black) {
					W->Left->Color = Black;
					W->Color = Red;
					RotateRight(tree, W);
					W = X->Parent->Right;
				}
				W->Color = X->Parent->Color;
				X->Parent->Color = Black;
				W->Right->Color = Black;
				RotateLeft(tree, X->Parent);
				X = tree->Root;
			}
		} else {
			rbnode_t *W = X->Parent->Left;
			if (W->Color == Red) {
				W->Color = Black;
				X->Parent->Color = Red;
				RotateRight(tree, X->Parent);
				W = X->Parent->Left;
			}
			if (W->Right->Color == Black && W->Left->Color == Black) {
				W->Color = Red;
				X = X->Parent;
			} else {
				if (W->Left->Color == Black) {
					W->Right->Color = Black;
					W->Color = Red;
					RotateLeft(tree, W);
					W = X->Parent->Left;
				}
				W->Color = X->Parent->Color;
				X->Parent->Color = Black;
				W->Left->Color = Black;
				RotateRight(tree, X->Parent);
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
		X = Y->Right;
	
	/* remove Y from the parent chain */
	X->Parent = Y->Parent;
	if (Y->Parent)
		if (Y == Y->Parent->Left)
			Y->Parent->Left = X;
		else
			Y->Parent->Right = X;
	else
		tree->Root = X;
	
	if (Y != Z) Z->Data = Y->Data;
	if (Y->Color == Black)
		DeleteFixup(tree, X);

	if (tree->freeNode) tree->freeNode(Y->Data);
	free(Y);
}

/*
 *	Find an element in the tree, returning the data, not the node.
 */
rbnode_t *rbtree_find(rbtree_t *tree, void *Data)
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
void *rbtree_finddata(rbtree_t *tree, void *Data)
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
static int WalkNodePreOrder(rbnode_t *X, int (*callback)(void *))
{
	int rcode;

	rcode = callback(X->Data);
	if (rcode != 0) return rcode;

	if (X->Left != NIL) {
		rcode = WalkNodePreOrder(X->Left, callback);
		if (rcode != 0) return rcode;
	}

	if (X->Right != NIL) {
		rcode = WalkNodePreOrder(X->Right, callback);
		if (rcode != 0) return rcode;
	}

	return 0;		/* we know everything returned zero */
}

/*
 *	Inorder
 */
static int WalkNodeInOrder(rbnode_t *X, int (*callback)(void *))
{
	int rcode;

	if (X->Left != NIL) {
		rcode = WalkNodeInOrder(X->Left, callback);
		if (rcode != 0) return rcode;
	}

	rcode = callback(X->Data);
	if (rcode != 0) return rcode;

	if (X->Right != NIL) {
		rcode = WalkNodeInOrder(X->Right, callback);
		if (rcode != 0) return rcode;
	}

	return 0;		/* we know everything returned zero */
}


/*
 *	PostOrder
 */
static int WalkNodePostOrder(rbnode_t *X, int (*callback)(void *))
{
	int rcode;

	if (X->Left != NIL) {
		rcode = WalkNodeInOrder(X->Left, callback);
		if (rcode != 0) return rcode;
	}

	if (X->Right != NIL) {
		rcode = WalkNodeInOrder(X->Right, callback);
		if (rcode != 0) return rcode;
	}

	rcode = callback(X->Data);
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
int rbtree_walk(rbtree_t *tree, int (*callback)(void *), RBTREE_ORDER order)
{
	switch (order) {
	case PreOrder:		
		return WalkNodePreOrder(tree->Root, callback);
	case InOrder:		
		return WalkNodeInOrder(tree->Root, callback);
	case PostOrder:		
		return WalkNodePostOrder(tree->Root, callback);

	default:
		break;
	}

	return -1;
}
