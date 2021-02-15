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

static void test_rbtree_iter(void)
{
	rbtree_t 		*t;
	fr_rb_test_node_t	sorted[MAXSIZE];
	fr_rb_test_node_t	*p;
	size_t			n, i;
	fr_rb_tree_iter_t	iter;

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

TEST_LIST = {
	{ "rbtree_iter",            test_rbtree_iter },

	{ NULL }
};
