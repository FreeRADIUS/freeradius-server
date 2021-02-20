/*
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
 */

/** Tests for rbtrees
 *
 * @file src/lib/util/rbtree_tests.c
 *
 * @copyright 2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <freeradius-devel/util/acutest.h>
#include <freeradius-devel/util/acutest_helpers.h>
#include <freeradius-devel/util/rand.h>
#include <stdlib.h>

#include "rbtree.c"

#define MAXSIZE 128

typedef struct {
	uint32_t	num;
	fr_rb_node_t	node;
} fr_rb_test_node_t;

static int fr_rb_test_cmp(void const *one, void const *two)
{
	fr_rb_test_node_t const *a = one, *b = two;
	return CMP(a->num, b->num);
}

static void test_rbtree_iter_inorder(void)
{
	rbtree_t 		*t;
	fr_rb_test_node_t	sorted[MAXSIZE];
	fr_rb_test_node_t	*p;
	size_t			n, i;
	fr_rb_tree_iter_inorder_t	iter;

	TEST_CASE("in-order iterator");
	t = rbtree_alloc(NULL, fr_rb_test_node_t, node, fr_rb_test_cmp, NULL, RBTREE_FLAG_LOCK);
	TEST_CHECK(t != NULL);

 	n = (fr_rand() % MAXSIZE) + 1;

 	/*
 	 *	Initialise the test nodes
 	 *	with random numbers.
 	 */
	for (i = 0; i < n; i++) {
		p = talloc(t, fr_rb_test_node_t);
		p->num = fr_rand();
		sorted[i].num = p->num;
		rbtree_insert(t, p);
	}

	qsort(sorted, n, sizeof(fr_rb_test_node_t), fr_rb_test_cmp);

	for (p = rbtree_iter_init_inorder(&iter, t), i = 0;
	     p;
	     p = rbtree_iter_next_inorder(&iter), i++) {
		TEST_MSG("Checking sorted[%zu] s = %u vs n = %u", i, sorted[i].num, p->num);
		TEST_CHECK(sorted[i].num == p->num);
		TEST_CHECK(pthread_mutex_trylock(&t->mutex) != 0);	/* Lock still held */
	}

	TEST_CHECK(pthread_mutex_trylock(&t->mutex) == 0);		/* Lock released */
	pthread_mutex_unlock(&t->mutex);

	talloc_free(t);
}

/*
 *	There's no natural test for pre- and post-order traversal
 *	as there is for in-order, so we must content ourselves
 *	with static test data.
 */
static uint32_t	pre_post_input[] = {0, 15, 256, 49, 3, 8192, 144, 4, 4096, 25194};
static uint32_t	pre_output[] = {15, 3, 0, 4, 256, 49, 144, 8192, 4096, 25194};
static uint32_t	post_output[] = {0, 4, 3, 144, 49, 4096, 25194, 8192, 256, 15};

static void test_rbtree_iter_preorder(void)
{
	rbtree_t 		*t;
	fr_rb_test_node_t	*p;
	size_t			i;
	fr_rb_tree_iter_t	iter;

	TEST_CASE("pre-order iterator");
	/*
	 *	Build a tree from pre_post_input.
	 */
	t = rbtree_alloc(NULL, fr_rb_test_node_t, node, fr_rb_test_cmp, NULL, RBTREE_FLAG_LOCK);
	TEST_CHECK(t != NULL);

	for (i = 0; i < sizeof(pre_post_input) / sizeof(uint32_t); i++) {
		p = talloc(t, fr_rb_test_node_t);
		p->num = pre_post_input[i];
		rbtree_insert(t, p);
	}

	for (p = rbtree_iter_init_preorder(&iter, t), i = 0;
	     p;
	     p = rbtree_iter_next_preorder(&iter), i++) {
		TEST_MSG("Checking pre_output[%zu] = %u vs n = %u", i, pre_output[i], p->num);
		TEST_CHECK(pre_output[i] == p->num);
		TEST_CHECK(pthread_mutex_trylock(&t->mutex) != 0);	/* Lock still held */
	}

	TEST_CHECK(pthread_mutex_trylock(&t->mutex) == 0);		/* Lock released */
	pthread_mutex_unlock(&t->mutex);

	talloc_free(t);
}

static void test_rbtree_iter_postorder(void)
{
	rbtree_t 		*t;
	fr_rb_test_node_t	*p;
	size_t			i;
	fr_rb_tree_iter_t	iter;

	TEST_CASE("post-order iterator");
	/*
	 *	Build a tree from pre_post_input.
	 */
	t = rbtree_alloc(NULL, fr_rb_test_node_t, node, fr_rb_test_cmp, NULL, RBTREE_FLAG_LOCK);
	TEST_CHECK(t != NULL);

	for (i = 0; i < sizeof(pre_post_input) / sizeof(uint32_t); i++) {
		p = talloc(t, fr_rb_test_node_t);
		p->num = pre_post_input[i];
		rbtree_insert(t, p);
	}

	for (p = rbtree_iter_init_postorder(&iter, t), i = 0;
	     p;
	     p = rbtree_iter_next_postorder(&iter), i++) {
		TEST_MSG("Checking post_output[%zu] s = %u vs n = %u", i, post_output[i], p->num);
		TEST_CHECK(post_output[i] == p->num);
		TEST_CHECK(pthread_mutex_trylock(&t->mutex) != 0);	/* Lock still held */
	}

	TEST_CHECK(pthread_mutex_trylock(&t->mutex) == 0);		/* Lock released */
	pthread_mutex_unlock(&t->mutex);

	talloc_free(t);
}

/*
 *	primality test used in rbtree_delete_iter() test.
 */
static bool is_prime(uint32_t n)
{
	uint32_t	i, q;

	if (n < 2) return false;

	for (i = 2; (q = n / i) >= i; i++) {
		if (i * q == n) return false;
	}
	return true;
}

uint32_t	non_primes[] = { 1,  4,  6,  8,  9, 10, 12, 14, 15, 16, 18, 20, 21, 22, 24, 25, 26, 27, 28,
				30, 32, 33, 34, 35, 36, 38, 39, 40, 42, 44, 45, 46, 48, 49, 50};

static void test_rbtree_iter_delete(void)
{
	rbtree_t 			*t;
	size_t				i;
	fr_rb_test_node_t		*p;
	fr_rb_tree_iter_inorder_t	iter;

	t = rbtree_alloc(NULL, fr_rb_test_node_t, node, fr_rb_test_cmp, NULL, RBTREE_FLAG_LOCK);
	TEST_CHECK(t != NULL);

 	/*
 	 *	Initialise the test nodes
 	 *	with integers from 1 to 50.
 	 */
	for (i = 1; i <= 50; i++) {
		p = talloc(t, fr_rb_test_node_t);
		p->num = i;
		rbtree_insert(t, p);
	}

	/*
	 *	Remove the primes.
	 */
	for (p = rbtree_iter_init_inorder(&iter, t);
	     p;
	     p = rbtree_iter_next_inorder(&iter)) {
		if (is_prime(p->num)) rbtree_iter_inorder_delete(&iter);
	}

	/*
	 *	Check that all the non-primes are still there.
	 */
	for (p = rbtree_iter_init_inorder(&iter, t), i = 0;
	     p;
	     p = rbtree_iter_next_inorder(&iter), i++) {
		TEST_MSG("Checking non_primes[%zu] = %u vs p->num = %u", i, non_primes[i], p->num);
		TEST_CHECK(non_primes[i] == p->num);
		TEST_CHECK(pthread_mutex_trylock(&t->mutex) != 0);	/* Lock still held */
	}
	TEST_CHECK(pthread_mutex_trylock(&t->mutex) == 0);		/* Lock released */
	pthread_mutex_unlock(&t->mutex);

	talloc_free(t);
}


TEST_LIST = {
	{ "rbtree_iter_inorder",            test_rbtree_iter_inorder },
	{ "rbtree_iter_preorder",           test_rbtree_iter_preorder },
	{ "rbtree_iter_postorder",          test_rbtree_iter_postorder },
	{ "rbtree_iter_delete",             test_rbtree_iter_delete },

	{ NULL }
};
