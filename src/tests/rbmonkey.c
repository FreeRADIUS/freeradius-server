#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>

#include <freeradius-devel/libradius.h>

/*
 *	We need knowlege of the internal structures.
 *	This needs to be kept in lockstep with rbtree.c
 */

/* RED-BLACK tree description */
typedef enum {
	BLACK,
	RED
} node_colour_t;

struct rbnode_t {
    rbnode_t		*left;		//!< left child
    rbnode_t		*right;		//!< right child
    rbnode_t		*parent;	//!< Parent
    node_colour_t	colour;		//!< Node colour (BLACK, RED)
    void		*data;		//!< data stored in node
};

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

/* Storage for the NIL pointer. */
static rbnode_t *NIL;

static int comp(void const *a, void const *b)
{
	if (*(uint32_t const *)a > *(uint32_t const *)b) {
		return -1;
	}

	if (*(uint32_t const *)a < *(uint32_t const *)b) {
		return 1;
	}
	return 0;
}

#if 0
static int print_cb(UNUSED void *ctx, void *i)
{
	fprintf(stderr, "%i\n", *(int*)i);
	return 0;
}
#endif

#define MAXSIZE 1024

static int r = 0;
static uint32_t rvals[MAXSIZE];

static int store_cb(UNUSED void *ctx, void  *i)
{
	rvals[r++] = *(int const *)i;
	return 0;
}

static uint32_t mask;

static int filter_cb(void *ctx, void *i)
{
	if ((*(uint32_t *)i & mask) == (*(uint32_t *)ctx & mask)) {
		return 2;
	}
	return 0;
}

/*
 * Returns the count of BLACK nodes from root to child leaves, or a
 * negative number indicating which RED-BLACK rule was broken.
 */
static int rbcount(rbtree_t *t)
{
	rbnode_t *n;
	int count, count_expect;

	count_expect = -1;
	n = t->root;
	if (!n || n == NIL) {
		return 0;
	}
	if (n->colour != BLACK) {
		return -2; /* root not BLACK */
	}
	count = 0;
descend:
	while (n->left != NIL) {
		if (n->colour == RED) {
			if (n->left->colour != BLACK || n->right->colour != BLACK) {
				return -4; /* Children of RED nodes must be BLACK */
			}
		}
		else {
			count++;
		}
		n = n->left;
	}
	if (n->right != NIL) {
		if (n->colour == RED) {
			if (n->left->colour != BLACK || n->right->colour != BLACK) {
				return -4; /* Children of RED nodes must be BLACK */
			}
		}
		else {
			count++;
		}
		n = n->right;
	}
	if (n->left != NIL || n->right != NIL) {
		goto descend;
	}
	if (count_expect < 0) {
		count_expect = count + (n->colour == BLACK);
	}
	else {
		if (count_expect != count + (n->colour == BLACK)) {
			fprintf(stderr,"Expected %i got %i\n", count_expect, count);
			return -5; /* All paths must traverse the same number of BLACK nodes. */
		}
	}
ascend:
	if (!n->parent) return count_expect;
	while (n->parent->right == n) {
		n = n->parent;
		if (!n->parent) return count_expect;
		if (n->colour == BLACK) {
			count--;
		}
	}
	if (n->parent->left == n) {
		if (n->parent->right != NIL) {
			n = n->parent->right;
			goto descend;
		}
		n = n->parent;
		if (!n->parent) return count_expect;
		if (n->colour == BLACK) {
			count--;
		}
	}
	goto ascend;
}

#define REPS 10

int main(UNUSED int argc, UNUSED char *argv[])
{
	rbtree_t *t;
	int i, j;
	uint32_t thresh;
	int n, rep;
	uint32_t vals[MAXSIZE];
	struct timeval now;
	gettimeofday(&now, NULL);

	/* TODO: make starting seed and repetitions a CLI option */
	rep = REPS;

again:
	if (!--rep) return 0;

	thresh = fr_rand();
	mask = 0xff >> (fr_rand() & 7);
	thresh &= mask;
	n = (fr_rand() % MAXSIZE) + 1;

	fprintf(stderr, "filter = %x mask = %x n= %i\n",
		thresh, mask, n);

	t = rbtree_create(NULL, comp, free, RBTREE_FLAG_LOCK);
	/* Find out the value of the NIL node */
	NIL = t->root->left;

	for (i = 0; i < n; i++) {
		int *p;
		p = malloc(sizeof(*p));
		*p = fr_rand();
		vals[i] = *p;
		rbtree_insert(t, p);
	}

	i = rbcount(t);
	fprintf(stderr,"After insert rbcount is %i.\n", i);
	if (i < 0) { return i; }

	qsort(vals, n, sizeof(int), comp);

	/*
	 * For testing deletebydata instead

	 for (i = 0; i < n; i++) {
	 if (filter_cb(&vals[i], &thresh) == 2) {
	 rbtree_deletebydata(t, &vals[i]);
	 }
	 }

	 *
	 */
	(void) rbtree_walk(t, RBTREE_DELETE_ORDER, filter_cb, &thresh);
	i = rbcount(t);
	fprintf(stderr,"After delete rbcount is %i.\n", i);
	if (i < 0) { return i; }

	r = 0;
	rbtree_walk(t, RBTREE_IN_ORDER, &store_cb, NULL);

	for (j = i = 0; i < n; i++) {
		if (i && vals[i-1] == vals[i]) continue;
		if (!filter_cb(&thresh, &vals[i])) {
			if (vals[i] != rvals[j]) goto bad;
			j++;
		}
	}
	fprintf(stderr,"matched OK\n");
	rbtree_free(t);
	goto again;

bad:
	for (j = i = 0; i < n; i++) {
		if (i && vals[i-1] == vals[i]) continue;
		if (!filter_cb(&thresh, &vals[i])) {
			fprintf(stderr, "%i: %x %x\n", j, vals[i], rvals[j]);
			j++;
		} else {
			fprintf(stderr, "skipped %x\n", vals[i]);
		}
	}
	return -1;
}

