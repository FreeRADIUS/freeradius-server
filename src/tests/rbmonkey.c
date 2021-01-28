#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>

#include <freeradius-devel/util/rbtree.c>
#include <freeradius-devel/util/rand.h>

typedef struct {
	uint32_t	num;
	fr_rb_node_t	node;
} fr_rb_test_node_t;

static int comp(void const *a, void const *b)
{
	fr_rb_test_node_t const *our_a = a, *our_b = b;

	return (our_a->num > our_b->num) - (our_a->num < our_b->num);
}

#if 0
static int print_cb(void *i, UNUSED void *uctx)
{
	fprintf(stderr, "%i\n", (fr_rb_test_node_t *)i->num);
	return 0;
}
#endif

#define MAXSIZE 1024

static int cb_stored = 0;
static fr_rb_test_node_t rvals[MAXSIZE];

static int store_cb(void  *i, UNUSED void *uctx)
{
	rvals[cb_stored++].num = *(int const *)i;
	return 0;
}

static uint32_t mask;

static int filter_cb(void *i, void *uctx)
{
	if ((((fr_rb_test_node_t *)i)->num & mask) == (((fr_rb_test_node_t *)uctx)->num & mask)) {
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
	fr_rb_node_t *n;
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
	if ((n->left != NIL) || (n->right != NIL)) {
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

static void freenode(void *data)
{
	talloc_free(data);
}

int main(UNUSED int argc, UNUSED char *argv[])
{
	rbtree_t		*t;
	int			i, j;
	uint32_t		thresh;
	int			n, rep;
	fr_rb_test_node_t	vals[MAXSIZE];

	memset(&vals, 0, sizeof(vals));

	/* TODO: make starting seed and repetitions a CLI option */
	rep = REPS;

again:
	if (!--rep) return 0;

	thresh = fr_rand();
	mask = 0xff >> (fr_rand() & 7);
	thresh &= mask;
	n = (fr_rand() % MAXSIZE) + 1;

	fprintf(stderr, "filter = %x mask = %x n = %i\n", thresh, mask, n);

	t = rbtree_alloc(NULL, comp, freenode, RBTREE_FLAG_LOCK);
	for (i = 0; i < n; i++) {
		fr_rb_test_node_t *p;

		p = talloc(t, fr_rb_test_node_t);	/* Do not use talloc_zero, rbcode should initialise fr_rb_node_t */
		p->num = fr_rand();
		vals[i].num = p->num;
		rbtree_insert(t, p);
	}

	i = rbcount(t);
	fprintf(stderr,"After insert rbcount is %i\n", i);
	if (i < 0) return i;

	qsort(vals, n, sizeof(fr_rb_test_node_t), comp);

	/*
	 * For testing deletebydata instead

	 for (i = 0; i < n; i++) {
		if (filter_cb(&vals[i], &thresh) == 2) rbtree_deletebydata(t, &vals[i]);
	 }

	 *
	 */
	(void) rbtree_walk(t, RBTREE_DELETE_ORDER, filter_cb, &thresh);
	i = rbcount(t);
	fprintf(stderr,"After delete rbcount is %i\n", i);
	if (i < 0) return i;

	cb_stored = 0;
	rbtree_walk(t, RBTREE_IN_ORDER, &store_cb, NULL);

	for (j = i = 0; i < n; i++) {
		if (i && vals[i-1].num == vals[i].num) continue;
		if (!filter_cb(&thresh, &vals[i])) {
			if (vals[i].num != rvals[j].num) goto bad;
			j++;
		}
	}
	fprintf(stderr,"matched OK\n");
	talloc_free(t);
	goto again;

bad:
	for (j = i = 0; i < n; i++) {
		if (i && vals[i-1].num == vals[i].num) continue;
		if (!filter_cb(&thresh, &vals[i])) {
			fprintf(stderr, "%i: %x %x\n", j, vals[i].num, rvals[j].num);
			j++;
		} else {
			fprintf(stderr, "skipped %x\n", vals[i].num);
		}
	}
	return -1;
}

