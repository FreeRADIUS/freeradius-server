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

/** Tests for the trie data structure
 *
 * @file src/lib/util/test/trie_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include "acutest.h"
#include "acutest_helpers.h"

#include <freeradius-devel/util/trie.h>
#include <freeradius-devel/util/inet.h>

/*
 *	Test basic trie creation.
 */
static void test_trie_alloc(void)
{
	fr_trie_t *ft;

	ft = fr_trie_alloc(NULL, NULL, NULL);
	TEST_ASSERT(ft != NULL);

	talloc_free(ft);
}

/*
 *	Test insert and exact lookup by key.
 */
static void test_trie_insert_lookup(void)
{
	fr_trie_t	*ft;
	char const     	*data1 = "hello";
	char const	*data2 = "world";
	char const	*data3 = "test";
	void		*found;
	uint8_t		key1[4] = { 10, 0, 0, 0 };
	uint8_t		key2[4] = { 10, 0, 1, 0 };
	uint8_t		key3[4] = { 192, 168, 0, 0 };
	uint8_t		missing[4] = { 172, 16, 0, 0 };

	ft = fr_trie_alloc(NULL, NULL, NULL);
	TEST_ASSERT(ft != NULL);

	TEST_CASE("Insert keys");
	TEST_CHECK(fr_trie_insert_by_key(ft, key1, 32, data1) == 0);
	TEST_CHECK(fr_trie_insert_by_key(ft, key2, 32, data2) == 0);
	TEST_CHECK(fr_trie_insert_by_key(ft, key3, 32, data3) == 0);

	TEST_CASE("Exact lookup finds correct data");
	found = fr_trie_lookup_by_key(ft, key1, 32);
	TEST_CHECK(found == data1);

	found = fr_trie_lookup_by_key(ft, key2, 32);
	TEST_CHECK(found == data2);

	found = fr_trie_lookup_by_key(ft, key3, 32);
	TEST_CHECK(found == data3);

	TEST_CASE("Lookup non-existent key returns NULL");
	found = fr_trie_lookup_by_key(ft, missing, 32);
	TEST_CHECK(found == NULL);

	talloc_free(ft);
}

/*
 *	Test duplicate insertion fails.
 */
static void test_trie_insert_duplicate(void)
{
	fr_trie_t	*ft;
	char const	*data1 = "first";
	char const	*data2 = "second";
	uint8_t		key[4] = { 10, 0, 0, 1 };

	ft = fr_trie_alloc(NULL, NULL, NULL);
	TEST_ASSERT(ft != NULL);

	TEST_CASE("First insert succeeds");
	TEST_CHECK(fr_trie_insert_by_key(ft, key, 32, data1) == 0);

	TEST_CASE("Duplicate insert fails");
	TEST_CHECK(fr_trie_insert_by_key(ft, key, 32, data2) < 0);

	TEST_CASE("Original data is preserved");
	TEST_CHECK(fr_trie_lookup_by_key(ft, key, 32) == data1);

	talloc_free(ft);
}

/*
 *	Test prefix (longest match) lookups.
 */
static void test_trie_longest_prefix(void)
{
	fr_trie_t	*ft;
	char const	*net8  = "10/8";
	char const	*net16 = "10.0/16";
	char const	*net24 = "10.0.0/24";
	void		*found;

	ft = fr_trie_alloc(NULL, NULL, NULL);
	TEST_ASSERT(ft != NULL);

	/*
	 *	Insert prefixes of different lengths.
	 *	10.0.0.0/8, 10.0.0.0/16, 10.0.0/24
	 */
	TEST_CASE("Insert and find overlapping prefixes of 3 different lengths");
	{
		uint8_t	k8[]  = { 10 };
		uint8_t	k16[] = { 10, 0 };
		uint8_t	k24[] = { 10, 0, 0 };

		TEST_CHECK(fr_trie_insert_by_key(ft, k8, 8, net8) == 0);
		found = fr_trie_match_by_key(ft, k8, 8);
		TEST_CHECK(found == net8);

		TEST_CHECK(fr_trie_insert_by_key(ft, k16, 16, net16) == 0);
		found = fr_trie_match_by_key(ft, k8, 8);
		TEST_CHECK(found == net8);
		found = fr_trie_match_by_key(ft, k16, 16);
		TEST_CHECK(found == net16);

		TEST_CHECK(fr_trie_insert_by_key(ft, k24, 24, net24) == 0);
		found = fr_trie_match_by_key(ft, k8, 8);
		TEST_CHECK(found == net8);
		found = fr_trie_match_by_key(ft, k16, 16);
		TEST_CHECK(found == net16);
		found = fr_trie_match_by_key(ft, k24, 24);
		TEST_CHECK(found == net24);
	}

	TEST_CASE("Longest prefix lookup for 10.0.0.5 returns 10.0.0/24");
	{
		uint8_t host[] = { 10, 0, 0, 5 };
		found = fr_trie_lookup_by_key(ft, host, 32);
		TEST_CHECK(found == net24);
	}

	TEST_CASE("Longest prefix lookup for 10.0.1.5 returns 10.0/16");
	{
		uint8_t host[] = { 10, 0, 1, 5 };
		found = fr_trie_lookup_by_key(ft, host, 32);
		TEST_CHECK(found == net16);
	}

	TEST_CASE("Longest prefix lookup for 10.1.0.1 returns 10/8");
	{
		uint8_t host[] = { 10, 1, 0, 1 };
		found = fr_trie_lookup_by_key(ft, host, 32);
		TEST_CHECK(found == net8);
	}

	TEST_CASE("No match for 192.168.0.1");
	{
		uint8_t host[] = { 192, 168, 0, 1 };
		found = fr_trie_lookup_by_key(ft, host, 32);
		TEST_CHECK(found == NULL);
	}

	talloc_free(ft);
}

/*
 *	Test remove by key.
 */
static void test_trie_remove(void)
{
	fr_trie_t	*ft;
	char const	*data1 = "first";
	char const	*data2 = "second";
	void		*removed;
	uint8_t		key1[] = { 10, 0, 0, 1 };
	uint8_t		key2[] = { 10, 0, 0, 2 };

	ft = fr_trie_alloc(NULL, NULL, NULL);
	TEST_ASSERT(ft != NULL);

	TEST_CHECK(fr_trie_insert_by_key(ft, key1, 32, data1) == 0);
	TEST_CHECK(fr_trie_insert_by_key(ft, key2, 32, data2) == 0);

	TEST_CASE("Remove returns the data");
	removed = fr_trie_remove_by_key(ft, key1, 32);
	TEST_CHECK(removed == data1);

	TEST_CASE("Removed key is no longer found");
	TEST_CHECK(fr_trie_lookup_by_key(ft, key1, 32) == NULL);

	TEST_CASE("Other key is still present");
	TEST_CHECK(fr_trie_lookup_by_key(ft, key2, 32) == data2);

	TEST_CASE("Remove non-existent key returns NULL");
	removed = fr_trie_remove_by_key(ft, key1, 32);
	TEST_CHECK(removed == NULL);

	talloc_free(ft);
}

typedef struct {
	int		count;
	uint8_t		keys[32][4];
	size_t		keylens[32];
} walk_ctx_t;

static int walk_callback(uint8_t const *key, size_t keylen, UNUSED void *data, void *uctx)
{
	walk_ctx_t *ctx = uctx;

	if (ctx->count < 32) {
		memcpy(ctx->keys[ctx->count], key, (keylen + 7) / 8);
		ctx->keylens[ctx->count] = keylen;
		ctx->count++;
	}

	return 0;
}

/*
 *	Test walk (iteration) over the trie.
 */
static void test_trie_walk(void)
{
	fr_trie_t	*ft;
	walk_ctx_t	ctx;
	char const	*data[] = { "a", "b", "c" };
	uint8_t		k1[] = { 10, 0, 0, 0 };
	uint8_t		k2[] = { 10, 0, 1, 0 };
	uint8_t		k3[] = { 192, 168, 0, 0 };

	ft = fr_trie_alloc(NULL, NULL, NULL);
	TEST_ASSERT(ft != NULL);

	TEST_CHECK(fr_trie_insert_by_key(ft, k1, 32, data[0]) == 0);
	TEST_CHECK(fr_trie_insert_by_key(ft, k2, 32, data[1]) == 0);
	TEST_CHECK(fr_trie_insert_by_key(ft, k3, 32, data[2]) == 0);

	memset(&ctx, 0, sizeof(ctx));

	TEST_CASE("Walk visits all entries");
	fr_trie_walk(ft, &ctx, walk_callback);
	TEST_CHECK(ctx.count == 3);
	TEST_MSG("expected 3 entries, got %d", ctx.count);

	talloc_free(ft);
}

/*
 *	Test with many entries to exercise trie growth.
 */
static void test_trie_many(void)
{
	fr_trie_t	*ft;
	int		i;
	char		*values[256];

	ft = fr_trie_alloc(NULL, NULL, NULL);
	TEST_ASSERT(ft != NULL);

	TEST_CASE("Insert 256 /32 entries under 10.0.0.0/8");
	for (i = 0; i < 256; i++) {
		uint8_t key[] = { 10, 0, 0, (uint8_t)i };

		values[i] = talloc_asprintf(ft, "host-%d", i);
		TEST_CHECK(fr_trie_insert_by_key(ft, key, 32, values[i]) == 0);
		TEST_MSG("insert host-%d failed", i);
	}

	TEST_CASE("Lookup all 256 entries");
	for (i = 0; i < 256; i++) {
		uint8_t key[] = { 10, 0, 0, (uint8_t)i };
		void *found = fr_trie_lookup_by_key(ft, key, 32);

		TEST_CHECK(found == values[i]);
		TEST_MSG("lookup host-%d failed", i);
	}

	TEST_CASE("Remove all 256 entries");
	for (i = 0; i < 256; i++) {
		uint8_t key[] = { 10, 0, 0, (uint8_t)i };
		void *removed = fr_trie_remove_by_key(ft, key, 32);

		TEST_CHECK(removed == values[i]);
		TEST_MSG("remove host-%d failed", i);
	}

	TEST_CASE("All entries removed, lookups return NULL");
	for (i = 0; i < 256; i++) {
		uint8_t key[] = { 10, 0, 0, (uint8_t)i };
		TEST_CHECK(fr_trie_lookup_by_key(ft, key, 32) == NULL);
	}

	talloc_free(ft);
}

/*
 *	Test prefix insertion at bit boundaries (not byte-aligned).
 */
static void test_trie_bit_prefix(void)
{
	fr_trie_t	*ft;
	char const	*net20 = "10.0.0.0/20";
	char const	*net28 = "10.0.0.0/28";
	void		*found;

	ft = fr_trie_alloc(NULL, NULL, NULL);
	TEST_ASSERT(ft != NULL);

	/*
	 *	Insert non-byte-aligned prefixes.
	 */
	{
		uint8_t	k20[] = { 10, 0, 0 };	/* first 20 bits */
		uint8_t	k28[] = { 10, 0, 0, 0 };	/* first 28 bits */

		TEST_CHECK(fr_trie_insert_by_key(ft, k20, 20, net20) == 0);
		TEST_CHECK(fr_trie_insert_by_key(ft, k28, 28, net28) == 0);
	}

	TEST_CASE("Lookup 10.0.0.5 returns /28");
	{
		uint8_t host[] = { 10, 0, 0, 5 };
		found = fr_trie_lookup_by_key(ft, host, 32);
		TEST_CHECK(found == net28);
	}

	TEST_CASE("Lookup 10.0.1.5 returns /20");
	{
		uint8_t host[] = { 10, 0, 1, 5 };
		found = fr_trie_lookup_by_key(ft, host, 32);
		TEST_CHECK(found == net20);
	}

	talloc_free(ft);
}

TEST_LIST = {
	{ "trie_alloc",			test_trie_alloc },
	{ "trie_insert_lookup",		test_trie_insert_lookup },
	{ "trie_insert_duplicate",	test_trie_insert_duplicate },
	{ "trie_longest_prefix",	test_trie_longest_prefix },
	{ "trie_remove",		test_trie_remove },
	{ "trie_walk",			test_trie_walk },
	{ "trie_many",			test_trie_many },
	{ "trie_bit_prefix",		test_trie_bit_prefix },
	TEST_TERMINATOR
};
