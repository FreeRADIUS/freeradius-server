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

/** Tests for the hash table
 *
 * @file src/lib/util/test/hash_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include "acutest.h"
#include "acutest_helpers.h"

#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/rand.h>

typedef struct {
	uint32_t	num;
	char		name[32];
} hash_test_node_t;

static uint32_t hash_test_hash(void const *data)
{
	hash_test_node_t const *n = data;

	return fr_hash(&n->num, sizeof(n->num));
}

static int8_t hash_test_cmp(void const *one, void const *two)
{
	hash_test_node_t const *a = one, *b = two;

	return CMP(a->num, b->num);
}

/*
 *	Test basic hash function operations.
 */
static void test_hash_functions(void)
{
	uint32_t	h1, h2, h3;

	TEST_CASE("fr_hash produces consistent results");
	h1 = fr_hash("hello", 5);
	h2 = fr_hash("hello", 5);
	TEST_CHECK(h1 == h2);

	TEST_CASE("Different inputs produce different hashes");
	h3 = fr_hash("world", 5);
	TEST_CHECK(h1 != h3);

	TEST_CASE("fr_hash_string works");
	h1 = fr_hash_string("test");
	h2 = fr_hash_string("test");
	TEST_CHECK(h1 == h2);

	h3 = fr_hash_string("other");
	TEST_CHECK(h1 != h3);

	TEST_CASE("fr_hash_case_string is case insensitive");
	h1 = fr_hash_case_string("Hello");
	h2 = fr_hash_case_string("hello");
	TEST_CHECK(h1 == h2);

	h3 = fr_hash_case_string("HELLO");
	TEST_CHECK(h1 == h3);

	TEST_CASE("fr_hash_update for incremental hashing");
	h1 = fr_hash("helloworld", 10);
	h2 = fr_hash("hello", 5);
	h2 = fr_hash_update("world", 5, h2);
	TEST_CHECK(h1 == h2);
}

/*
 *	Test hash64 functions.
 */
static void test_hash64_functions(void)
{
	uint64_t	h1, h2, h3;

	TEST_CASE("fr_hash64 produces consistent results");
	h1 = fr_hash64("hello", 5);
	h2 = fr_hash64("hello", 5);
	TEST_CHECK(h1 == h2);

	TEST_CASE("Different inputs produce different 64-bit hashes");
	h3 = fr_hash64("world", 5);
	TEST_CHECK(h1 != h3);

	TEST_CASE("fr_hash64_update for incremental hashing");
	h1 = fr_hash64("helloworld", 10);
	h2 = fr_hash64("hello", 5);
	h2 = fr_hash64_update("world", 5, h2);
	TEST_CHECK(h1 == h2);
}

/*
 *	Test hash table creation and basic insert/find.
 */
static void test_hash_table_basic(void)
{
	fr_hash_table_t		*ht;
	hash_test_node_t	node, *found;

	ht = fr_hash_table_alloc(NULL, hash_test_hash, hash_test_cmp, NULL);
	TEST_ASSERT(ht != NULL);

	TEST_CASE("Empty table has 0 elements");
	TEST_CHECK(fr_hash_table_num_elements(ht) == 0);

	TEST_CASE("Insert an element");
	node.num = 42;
	snprintf(node.name, sizeof(node.name), "node-%u", node.num);
	TEST_CHECK(fr_hash_table_insert(ht, &node));

	TEST_CHECK(fr_hash_table_num_elements(ht) == 1);

	TEST_CASE("Find the element");
	found = fr_hash_table_find(ht, &node);
	TEST_CHECK(found != NULL);
	if (found) {
		TEST_CHECK(found->num == 42);
	}

	TEST_CASE("Find non-existent element returns NULL");
	found = fr_hash_table_find(ht, &(hash_test_node_t) { .num = 999 });				
	TEST_CHECK(found == NULL);

	talloc_free(ht);
}

#define HASH_TEST_SIZE 1024

/*
 *	Test insert, find, and remove with many elements.
 */
static void test_hash_table_many(void)
{
	fr_hash_table_t		*ht;
	hash_test_node_t	*nodes;
	int			i;

	ht = fr_hash_table_alloc(NULL, hash_test_hash, hash_test_cmp, NULL);
	TEST_ASSERT(ht != NULL);

	nodes = calloc(HASH_TEST_SIZE, sizeof(hash_test_node_t));

	TEST_CASE("Insert many elements");
	for (i = 0; i < HASH_TEST_SIZE; i++) {
		nodes[i].num = i;
		snprintf(nodes[i].name, sizeof(nodes[i].name), "node-%d", i);
		TEST_CHECK(fr_hash_table_insert(ht, &nodes[i]));
		TEST_MSG("insert %d failed", i);
	}
	TEST_CHECK(fr_hash_table_num_elements(ht) == HASH_TEST_SIZE);

	TEST_CASE("Find all elements");
	for (i = 0; i < HASH_TEST_SIZE; i++) {
		hash_test_node_t	*found;

		found = fr_hash_table_find(ht, &(hash_test_node_t) { .num = i });
		TEST_CHECK(found != NULL);
		TEST_MSG("find %d failed", i);

		if (found) {
			TEST_CHECK(found->num == (uint32_t) i);
		}
	}

	TEST_CASE("Remove half the elements");
	for (i = 0; i < HASH_TEST_SIZE; i += 2) {
		void			*removed;

		removed = fr_hash_table_remove(ht, &(hash_test_node_t) { .num = i });
		TEST_CHECK(removed != NULL);
		TEST_MSG("remove %d failed", i);
	}
	TEST_CHECK(fr_hash_table_num_elements(ht) == HASH_TEST_SIZE / 2);

	TEST_CASE("Verify removed elements are gone and remaining are present");
	for (i = 0; i < HASH_TEST_SIZE; i++) {
		hash_test_node_t	*found;

		found = fr_hash_table_find(ht, &(hash_test_node_t) { .num = i });
		if (i % 2 == 0) {
			TEST_CHECK(found == NULL);
			TEST_MSG("element %d should have been removed", i);
		} else {
			TEST_CHECK(found != NULL);
			TEST_MSG("element %d should still be present", i);
		}
	}

	talloc_free(ht);
	free(nodes);
}

/*
 *	Test duplicate insertion fails.
 */
static void test_hash_table_duplicate(void)
{
	fr_hash_table_t		*ht;
	hash_test_node_t	node;

	ht = fr_hash_table_alloc(NULL, hash_test_hash, hash_test_cmp, NULL);
	TEST_ASSERT(ht != NULL);

	node.num = 1;
	TEST_CASE("First insert succeeds");
	TEST_CHECK(fr_hash_table_insert(ht, &node));

	TEST_CASE("Duplicate insert fails");
	TEST_CHECK(!fr_hash_table_insert(ht, &node));

	TEST_CHECK(fr_hash_table_num_elements(ht) == 1);

	talloc_free(ht);
}

/*
 *	Test replace operation.
 */
static void test_hash_table_replace(void)
{
	fr_hash_table_t		*ht;
	hash_test_node_t	node1, node2;
	hash_test_node_t	*found;
	void			*old = NULL;
	int			ret;

	ht = fr_hash_table_alloc(NULL, hash_test_hash, hash_test_cmp, NULL);
	TEST_ASSERT(ht != NULL);

	node1.num = 1;
	snprintf(node1.name, sizeof(node1.name), "first");
	node2.num = 1;
	snprintf(node2.name, sizeof(node2.name), "second");

	TEST_CASE("Replace on empty table inserts");
	ret = fr_hash_table_replace(&old, ht, &node1);
	TEST_CHECK(ret == 1);
	TEST_CHECK(old == NULL);
	TEST_CHECK(fr_hash_table_num_elements(ht) == 1);

	TEST_CASE("Replace existing element");
	ret = fr_hash_table_replace(&old, ht, &node2);
	TEST_CHECK(ret == 0);
	TEST_CHECK(old == &node1);
	TEST_CHECK(fr_hash_table_num_elements(ht) == 1);

	TEST_CASE("Find returns the replacement");
	found = fr_hash_table_find(ht, &node2);
	TEST_CHECK(found == &node2);

	talloc_free(ht);
}

/*
 *	Test delete operation (with free callback).
 */
static void test_hash_table_delete(void)
{
	fr_hash_table_t		*ht;
	hash_test_node_t	*node;

	ht = fr_hash_table_alloc(NULL, hash_test_hash, hash_test_cmp, talloc_free_data);
	TEST_ASSERT(ht != NULL);

	node = talloc(NULL, hash_test_node_t);
	node->num = 42;

	TEST_CHECK(fr_hash_table_insert(ht, node));
	TEST_CHECK(fr_hash_table_num_elements(ht) == 1);

	TEST_CASE("Delete removes and frees element");
	TEST_CHECK(fr_hash_table_delete(ht, node));
	TEST_CHECK(fr_hash_table_num_elements(ht) == 0);

	TEST_CASE("Delete non-existent element returns false");
	{
		hash_test_node_t missing = { .num = 999 };
		TEST_CHECK(!fr_hash_table_delete(ht, &missing));
	}

	talloc_free(ht);
}

/*
 *	Test iteration over the hash table.
 */
static void test_hash_table_iter(void)
{
	fr_hash_table_t		*ht;
	hash_test_node_t	nodes[16];
	fr_hash_iter_t		iter;
	hash_test_node_t	*p;
	unsigned int		count = 0;
	uint32_t		seen = 0;
	int			i;

	ht = fr_hash_table_alloc(NULL, hash_test_hash, hash_test_cmp, NULL);
	TEST_ASSERT(ht != NULL);

	for (i = 0; i < 16; i++) {
		nodes[i].num = i;
		fr_hash_table_insert(ht, &nodes[i]);
	}

	TEST_CASE("Iterate over all elements");
	for (p = fr_hash_table_iter_init(ht, &iter);
	     p;
	     p = fr_hash_table_iter_next(ht, &iter)) {
		TEST_CHECK(p->num < 16);
		TEST_CHECK((seen & (1U << p->num)) == 0);
		TEST_MSG("element %u seen twice", p->num);
		seen |= (1U << p->num);
		count++;
	}

	TEST_CHECK(count == 16);
	TEST_CHECK(seen == 0xffff);

	talloc_free(ht);
}

/*
 *	Test the flatten operation.
 */
static void test_hash_table_flatten(void)
{
	fr_hash_table_t		*ht;
	hash_test_node_t	nodes[8];
	hash_test_node_t	**flat = NULL;
	int			ret, i;

	ht = fr_hash_table_alloc(NULL, hash_test_hash, hash_test_cmp, NULL);
	TEST_ASSERT(ht != NULL);

	for (i = 0; i < 8; i++) {
		nodes[i].num = i;
		fr_hash_table_insert(ht, &nodes[i]);
	}

	TEST_CASE("Flatten table into array");
	ret = fr_hash_table_flatten(NULL, (void ***)&flat, ht);
	TEST_CHECK(ret == 0);
	TEST_CHECK(flat != NULL);

	if (flat) {
		uint32_t seen = 0;

		for (i = 0; i < 8; i++) {
			TEST_CHECK(flat[i] != NULL);
			if (flat[i]) {
				TEST_CHECK(flat[i]->num < 8);
				seen |= (1U << flat[i]->num);
			}
		}
		TEST_CHECK(seen == 0xff);

		talloc_free(flat);
	}

	talloc_free(ht);
}

TEST_LIST = {
	{ "hash_functions",		test_hash_functions },
	{ "hash64_functions",		test_hash64_functions },
	{ "hash_table_basic",		test_hash_table_basic },
	{ "hash_table_many",		test_hash_table_many },
	{ "hash_table_duplicate",	test_hash_table_duplicate },
	{ "hash_table_replace",		test_hash_table_replace },
	{ "hash_table_delete",		test_hash_table_delete },
	{ "hash_table_iter",		test_hash_table_iter },
	{ "hash_table_flatten",		test_hash_table_flatten },
	TEST_TERMINATOR
};
