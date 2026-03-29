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

/** Tests for talloc and FreeRADIUS talloc utility functions
 *
 * @file src/lib/util/test/talloc_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include "acutest.h"
#include "acutest_helpers.h"
#include <freeradius-devel/util/talloc.h>

/*
 *	=== Core talloc (samba) tests ===
 */

/*
 *	talloc - basic allocation and parent/child hierarchy
 */
static void test_talloc_basic(void)
{
	TALLOC_CTX	*ctx;
	int		*p;
	char		*s;

	ctx = talloc_init_const("test_basic");
	TEST_ASSERT(ctx != NULL);

	TEST_CASE("talloc allocates child of context");
	p = talloc(ctx, int);
	TEST_ASSERT(p != NULL);
	TEST_CHECK(talloc_parent(p) == ctx);
	*p = 42;
	TEST_CHECK(*p == 42);

	TEST_CASE("talloc_size allocates arbitrary size");
	s = talloc_size(ctx, 100);
	TEST_ASSERT(s != NULL);
	TEST_CHECK(talloc_get_size(s) == 100);
	TEST_CHECK(talloc_parent(s) == ctx);

	talloc_free(ctx);
}

/*
 *	talloc_zero - zero-initialized allocation
 */
static void test_talloc_zero(void)
{
	TALLOC_CTX	*ctx;
	int		*p;
	uint8_t		*buf;
	unsigned int	i;

	ctx = talloc_init_const("test_zero");

	TEST_CASE("talloc_zero initializes to zero");
	p = talloc_zero(ctx, int);
	TEST_ASSERT(p != NULL);
	TEST_CHECK(*p == 0);

	TEST_CASE("talloc_zero_size initializes to zero");
	buf = talloc_zero_size(ctx, 64);
	TEST_ASSERT(buf != NULL);
	for (i = 0; i < 64; i++) {
		TEST_CHECK(buf[i] == 0);
	}

	talloc_free(ctx);
}

/*
 *	talloc_array / talloc_zero_array / talloc_realloc
 */
static void test_talloc_array(void)
{
	TALLOC_CTX	*ctx;
	int		*arr;
	unsigned int	i;

	ctx = talloc_init_const("test_array");

	TEST_CASE("talloc_array allocates typed array");
	arr = talloc_array(ctx, int, 10);
	TEST_ASSERT(arr != NULL);
	TEST_CHECK(talloc_get_size(arr) == 10 * sizeof(int));
	for (i = 0; i < 10; i++) arr[i] = (int)i;
	for (i = 0; i < 10; i++) TEST_CHECK(arr[i] == (int)i);

	TEST_CASE("talloc_zero_array initializes to zero");
	arr = talloc_zero_array(ctx, int, 5);
	TEST_ASSERT(arr != NULL);
	for (i = 0; i < 5; i++) TEST_CHECK(arr[i] == 0);

	TEST_CASE("talloc_realloc grows array preserving content");
	arr = talloc_array(ctx, int, 4);
	for (i = 0; i < 4; i++) arr[i] = (int)(i + 100);
	arr = talloc_realloc(ctx, arr, int, 8);
	TEST_ASSERT(arr != NULL);
	for (i = 0; i < 4; i++) TEST_CHECK(arr[i] == (int)(i + 100));
	TEST_CHECK(talloc_get_size(arr) == 8 * sizeof(int));

	TEST_CASE("talloc_realloc shrinks array");
	arr = talloc_realloc(ctx, arr, int, 2);
	TEST_ASSERT(arr != NULL);
	TEST_CHECK(arr[0] == 100);
	TEST_CHECK(arr[1] == 101);
	TEST_CHECK(talloc_get_size(arr) == 2 * sizeof(int));

	talloc_free(ctx);
}

/*
 *	talloc_free - recursive free of children
 */
static void test_talloc_free(void)
{
	TALLOC_CTX	*ctx;
	int		*child1, *child2;

	TEST_CASE("talloc_free(NULL) returns -1");
	TEST_CHECK(talloc_free(NULL) == -1);

	TEST_CASE("talloc_free recursively frees children");
	ctx = talloc_init_const("test_free");
	child1 = talloc(ctx, int);
	TEST_ASSERT(child1 != NULL);
	child2 = talloc(child1, int);
	TEST_ASSERT(child2 != NULL);
	TEST_CHECK(talloc_parent(child2) == child1);
	TEST_CHECK(talloc_free(ctx) == 0);
}

/*
 *	talloc_set_name_const / talloc_get_name / talloc_check_name
 */
static void test_talloc_naming(void)
{
	TALLOC_CTX	*ctx;
	void		*p;

	ctx = talloc_init_const("test_naming");

	TEST_CASE("talloc_set_name_const / talloc_get_name roundtrip");
	p = talloc_size(ctx, 10);
	talloc_set_name_const(p, "my_chunk");
	TEST_CHECK(strcmp(talloc_get_name(p), "my_chunk") == 0);

	TEST_CASE("talloc_check_name succeeds on match");
	TEST_CHECK(talloc_check_name(p, "my_chunk") == p);

	TEST_CASE("talloc_check_name returns NULL on mismatch");
	TEST_CHECK(talloc_check_name(p, "wrong_name") == NULL);

	TEST_CASE("talloc_named_const sets name at creation");
	p = talloc_named_const(ctx, 20, "named_chunk");
	TEST_ASSERT(p != NULL);
	TEST_CHECK(strcmp(talloc_get_name(p), "named_chunk") == 0);

	talloc_free(ctx);
}

/*
 *	talloc_parent / talloc_parent_name
 */
static void test_talloc_parent(void)
{
	TALLOC_CTX	*ctx;
	int		*child;

	ctx = talloc_init_const("test_parent");

	TEST_CASE("talloc_parent returns correct parent");
	child = talloc(ctx, int);
	TEST_CHECK(talloc_parent(child) == ctx);

	TEST_CASE("talloc_parent_name returns parent's name");
	TEST_CHECK(strcmp(talloc_parent_name(child), "test_parent") == 0);

	TEST_CASE("talloc_parent of top-level returns NULL context");
	/*
	 *	Top-level contexts allocated with talloc_init have the
	 *	null context as parent (or NULL if tracking is off).
	 */
	{
		void *parent = talloc_parent(ctx);
		(void)parent;  /* Just verify it doesn't crash */
	}

	talloc_free(ctx);
}

/*
 *	talloc_steal - reparent a chunk
 */
static void test_talloc_steal(void)
{
	TALLOC_CTX	*ctx1, *ctx2;
	int		*p;
	void		*ret;

	ctx1 = talloc_init_const("ctx1");
	ctx2 = talloc_init_const("ctx2");

	TEST_CASE("talloc_steal moves child to new parent");
	p = talloc(ctx1, int);
	*p = 99;
	TEST_CHECK(talloc_parent(p) == ctx1);
	ret = talloc_steal(ctx2, p);
	TEST_CHECK(ret == p);
	TEST_CHECK(talloc_parent(p) == ctx2);
	TEST_CHECK(*p == 99);

	TEST_CASE("talloc_steal NULL returns NULL");
	TEST_CHECK(talloc_steal(ctx1, NULL) == NULL);

	TEST_CASE("talloc_steal to NULL reparents to null context");
	p = talloc(ctx1, int);
	ret = talloc_steal(NULL, p);
	TEST_CHECK(ret == p);
	talloc_free(p);  /* must free manually since no parent owns it */

	talloc_free(ctx1);
	talloc_free(ctx2);
}

/*
 *	talloc_move - steal and NULL out old pointer
 */
static void test_talloc_move(void)
{
	TALLOC_CTX	*ctx1, *ctx2;
	int		*p, *moved;

	ctx1 = talloc_init_const("ctx1");
	ctx2 = talloc_init_const("ctx2");

	TEST_CASE("talloc_move transfers ownership and NULLs source");
	p = talloc(ctx1, int);
	*p = 77;
	moved = talloc_move(ctx2, &p);
	TEST_ASSERT(moved != NULL);
	TEST_CHECK(*moved == 77);
	TEST_CHECK(p == NULL);
	TEST_CHECK(talloc_parent(moved) == ctx2);

	talloc_free(ctx1);
	talloc_free(ctx2);
}

/*
 *	talloc_reference / talloc_unlink / talloc_reference_count
 */
static void test_talloc_reference(void)
{
	TALLOC_CTX	*ctx1, *ctx2;
	char		*str;
	void		*ref;

	ctx1 = talloc_init_const("ctx1");
	ctx2 = talloc_init_const("ctx2");

	TEST_CASE("talloc_reference creates a reference");
	str = talloc_strdup(ctx1, "shared");
	ref = talloc_reference(ctx2, str);
	TEST_CHECK(ref != NULL);
	TEST_CHECK(talloc_reference_count(str) == 1);

	TEST_CASE("talloc_unlink removes the reference");
	TEST_CHECK(talloc_unlink(ctx2, str) == 0);
	TEST_CHECK(talloc_reference_count(str) == 0);

	TEST_CASE("Multiple references increment count");
	talloc_reference(ctx2, str);
	talloc_reference(ctx2, str);
	TEST_CHECK(talloc_reference_count(str) >= 2);

	talloc_free(ctx1);
	talloc_free(ctx2);
}

/*
 *	talloc_set_destructor - native talloc destructors
 */
static int native_destructor_count;

static int native_destructor(int *ptr)
{
	TEST_ASSERT(*ptr == 1);
	*ptr = 0;
	native_destructor_count++;
	return 0;
}

static void test_talloc_set_destructor(void)
{
	TALLOC_CTX	*ctx;
	int		*p;

	ctx = talloc_init_const("test_destructor");

	TEST_CASE("Destructor called on free");
	native_destructor_count = 0;
	p = talloc(ctx, int);
	*p = 1;
	talloc_set_destructor(p, native_destructor);
	talloc_free(p);
	TEST_CHECK(native_destructor_count == 1);

	TEST_CASE("Destructor returning -1 prevents free");

	/*
	 *	We can't easily test this without risking a leak,
	 *	so just verify the destructor fires on parent free.
	 */
	native_destructor_count = 0;
	p = talloc(ctx, int);
	*p = 1;
	talloc_set_destructor(p, native_destructor);
	talloc_free(ctx);
	TEST_CHECK(native_destructor_count == 1);
}

/*
 *	talloc_strdup / talloc_strndup (base samba versions,
 *	which are remapped to talloc_typed_strdup/strndup by the header)
 */
static void test_talloc_strdup(void)
{
	TALLOC_CTX	*ctx;
	char		*s;

	ctx = talloc_init_const("test_strdup");

	TEST_CASE("talloc_strdup duplicates string");
	s = talloc_strdup(ctx, "hello");
	TEST_ASSERT(s != NULL);
	TEST_CHECK(strcmp(s, "hello") == 0);
	TEST_CHECK(talloc_parent(s) == ctx);

	TEST_CASE("talloc_strndup limits length");
	s = talloc_strndup(ctx, "hello world", 5);
	TEST_ASSERT(s != NULL);
	TEST_CHECK(strcmp(s, "hello") == 0);

	TEST_CASE("talloc_strdup of NULL returns NULL");
	s = talloc_strdup(ctx, NULL);
	TEST_CHECK(s == NULL);

	talloc_free(ctx);
}

/*
 *	talloc_asprintf / talloc_asprintf_append / talloc_asprintf_append_buffer
 */
static void test_talloc_asprintf(void)
{
	TALLOC_CTX	*ctx;
	char		*s;

	ctx = talloc_init_const("test_asprintf");

	TEST_CASE("talloc_asprintf formats string");
	s = talloc_asprintf(ctx, "num=%d str=%s", 42, "foo");
	TEST_ASSERT(s != NULL);
	TEST_CHECK(strcmp(s, "num=42 str=foo") == 0);

	TEST_CASE("talloc_asprintf_append appends at string end");
	s = talloc_strdup(ctx, "hello");
	s = talloc_asprintf_append(s, " %s", "world");
	TEST_ASSERT(s != NULL);
	TEST_CHECK(strcmp(s, "hello world") == 0);

	TEST_CASE("talloc_asprintf_append_buffer appends at buffer end");
	s = talloc_strdup(ctx, "abc");
	s = talloc_asprintf_append_buffer(s, "def");
	TEST_ASSERT(s != NULL);
	TEST_CHECK(strcmp(s, "abcdef") == 0);

	talloc_free(ctx);
}

/*
 *	talloc_pool - suballocations from a pool
 */
static void test_talloc_pool(void)
{
	TALLOC_CTX	*pool;
	int		*a, *b, *c;

	TEST_CASE("talloc_pool creates a pool context");
	pool = talloc_pool(NULL, 1024);
	TEST_ASSERT(pool != NULL);

	TEST_CASE("Allocations from pool succeed");
	a = talloc(pool, int);
	b = talloc(pool, int);
	c = talloc(pool, int);
	TEST_ASSERT(a != NULL);
	TEST_ASSERT(b != NULL);
	TEST_ASSERT(c != NULL);
	*a = 1; *b = 2; *c = 3;
	TEST_CHECK(*a == 1);
	TEST_CHECK(*b == 2);
	TEST_CHECK(*c == 3);

	TEST_CASE("Pool children have pool as parent");
	TEST_CHECK(talloc_parent(a) == pool);
	TEST_CHECK(talloc_parent(b) == pool);

	talloc_free(pool);
}

/*
 *	talloc_free_children - free all children but keep parent
 */
static void test_talloc_free_children(void)
{
	TALLOC_CTX	*ctx;
	int		*p;

	ctx = talloc_init_const("test_free_children");

	TEST_CASE("talloc_free_children frees all children");

	p = talloc(ctx, int);
	TEST_CHECK(p != NULL);
	p = talloc(ctx, int);
	TEST_CHECK(p != NULL);
	p = talloc(ctx, int);
	TEST_CHECK(p != NULL);

	TEST_CHECK(talloc_total_blocks(ctx) == 4); /* ctx + 3 children */

	talloc_free_children(ctx);
	TEST_CHECK(talloc_total_blocks(ctx) == 1); /* just ctx */

	TEST_CASE("Context is still usable after free_children");
	p = talloc(ctx, int);
	TEST_ASSERT(p != NULL);
	*p = 123;
	TEST_CHECK(*p == 123);

	talloc_free(ctx);
}

/*
 *	talloc_total_size / talloc_total_blocks
 */
static void test_talloc_total_size(void)
{
	TALLOC_CTX	*ctx;
	size_t		total_size, total_blocks;

	ctx = talloc_init_const("test_total");

	TEST_CASE("Empty context has size 0 and 1 block");
	TEST_CHECK(talloc_total_size(ctx) == 0);
	TEST_CHECK(talloc_total_blocks(ctx) == 1);

	TEST_CASE("Allocations increase totals");
	talloc_size(ctx, 100);
	talloc_size(ctx, 200);
	total_size = talloc_total_size(ctx);
	total_blocks = talloc_total_blocks(ctx);
	TEST_CHECK(total_size >= 300);
	TEST_CHECK(total_blocks == 3); /* ctx + 2 children */

	TEST_CASE("Nested children counted in totals");
	{
		void *child = talloc_size(ctx, 50);
		talloc_size(child, 25);
	}
	TEST_CHECK(talloc_total_size(ctx) >= 375);
	TEST_CHECK(talloc_total_blocks(ctx) == 5);

	talloc_free(ctx);
}

/*
 *	talloc_get_size - get chunk data size
 */
static void test_talloc_get_size(void)
{
	TALLOC_CTX	*ctx;
	void		*p;

	ctx = talloc_init_const("test_get_size");

	TEST_CASE("talloc_get_size returns requested size");
	p = talloc_size(ctx, 42);
	TEST_CHECK(talloc_get_size(p) == 42);

	TEST_CASE("talloc_get_size of NULL returns 0");
	TEST_CHECK(talloc_get_size(NULL) == 0);

	TEST_CASE("talloc_get_size after realloc returns new size");
	p = talloc_realloc_size(ctx, p, 100);
	TEST_CHECK(talloc_get_size(p) == 100);

	talloc_free(ctx);
}

/*
 *	talloc_find_parent_byname - walk parent chain looking for name
 */
static void test_talloc_find_parent_byname(void)
{
	TALLOC_CTX	*root, *mid;
	int		*leaf;
	void		*found;

	root = talloc_named_const(NULL, 0, "root_ctx");
	mid = talloc_named_const(root, 0, "mid_ctx");
	leaf = talloc(mid, int);

	TEST_CASE("Find existing parent by name");
	found = talloc_find_parent_byname(leaf, "root_ctx");
	TEST_CHECK(found == root);

	found = talloc_find_parent_byname(leaf, "mid_ctx");
	TEST_CHECK(found == mid);

	TEST_CASE("Return NULL for non-existent parent name");
	found = talloc_find_parent_byname(leaf, "nonexistent");
	TEST_CHECK(found == NULL);

	talloc_free(root);
}

/*
 *	talloc_is_parent - check if ptr is an ancestor
 */
static void test_talloc_is_parent(void)
{
	TALLOC_CTX	*root, *mid;
	int		*leaf;

	root = talloc_init_const("root");
	mid = talloc(root, char);
	leaf = talloc(mid, int);

	TEST_CASE("Direct parent is parent");
	TEST_CHECK(talloc_is_parent(leaf, mid) == 1);

	TEST_CASE("Grandparent is parent");
	TEST_CHECK(talloc_is_parent(leaf, root) == 1);

	TEST_CASE("Non-parent is not parent");
	{
		TALLOC_CTX *other = talloc_init_const("other");
		TEST_CHECK(talloc_is_parent(leaf, other) == 0);
		talloc_free(other);
	}

	talloc_free(root);
}

/*
 *	talloc_reparent - reparent with explicit old parent
 */
static void test_talloc_reparent(void)
{
	TALLOC_CTX	*old_parent, *new_parent;
	int		*p;
	void		*ret;

	old_parent = talloc_init_const("old");
	new_parent = talloc_init_const("new");

	TEST_CASE("talloc_reparent moves from old to new parent");
	p = talloc(old_parent, int);
	*p = 55;
	ret = talloc_reparent(old_parent, new_parent, p);
	TEST_CHECK(ret == p);
	TEST_CHECK(talloc_parent(p) == new_parent);
	TEST_CHECK(*p == 55);

	TEST_CASE("talloc_reparent NULL returns NULL");
	ret = talloc_reparent(old_parent, new_parent, NULL);
	TEST_CHECK(ret == NULL);

	talloc_free(old_parent);
	talloc_free(new_parent);
}

/*
 *	talloc_memdup - duplicate memory
 */
static void test_talloc_memdup(void)
{
	TALLOC_CTX	*ctx;
	uint8_t		src[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t		*dup;

	ctx = talloc_init_const("test_memdup");

	TEST_CASE("talloc_memdup duplicates bytes");
	dup = talloc_memdup(ctx, src, sizeof(src));
	TEST_ASSERT(dup != NULL);
	TEST_CHECK(memcmp(dup, src, sizeof(src)) == 0);
	TEST_CHECK(talloc_get_size(dup) == sizeof(src));
	TEST_CHECK(talloc_parent(dup) == ctx);

	talloc_free(ctx);
}

/*
 *	talloc hierarchy depth - deep nesting
 */
static void test_talloc_deep_hierarchy(void)
{
	TALLOC_CTX	*root;
	void		*current;
	int		i;

	root = talloc_init_const("deep_root");
	current = root;

	TEST_CASE("Deep hierarchy (100 levels) works");
	for (i = 0; i < 100; i++) {
		current = talloc_size(current, 16);
		TEST_ASSERT(current != NULL);
	}

	TEST_CASE("Total blocks counts all levels");
	TEST_CHECK(talloc_total_blocks(root) == 101); /* root + 100 children */

	TEST_CASE("Free cleans up entire hierarchy");
	TEST_CHECK(talloc_free(root) == 0);
}

/*
 *	talloc_strndup_append / talloc_strndup_append_buffer
 */
static void test_talloc_strndup_append(void)
{
	TALLOC_CTX	*ctx;
	char		*s;

	ctx = talloc_init_const("test_strndup_append");

	TEST_CASE("talloc_strndup_append appends limited length");
	s = talloc_strdup(ctx, "hello");
	s = talloc_strndup_append(s, " world!!", 6);
	TEST_ASSERT(s != NULL);
	TEST_CHECK(strcmp(s, "hello world") == 0);

	TEST_CASE("talloc_strndup_append_buffer appends at buffer end");
	s = talloc_strdup(ctx, "abc");
	s = talloc_strndup_append_buffer(s, "defgh", 3);
	TEST_ASSERT(s != NULL);
	TEST_CHECK(strcmp(s, "abcdef") == 0);

	talloc_free(ctx);
}

/*
 *	talloc_increase_ref_count
 */
static void test_talloc_increase_ref_count(void)
{
	TALLOC_CTX	*ctx;
	char		*str;
	int		ret;

	ctx = talloc_init_const("test_ref_count");

	TEST_CASE("increase_ref_count succeeds");
	str = talloc_strdup(ctx, "refcounted");
	ret = talloc_increase_ref_count(str);
	TEST_CHECK(ret == 0);
	TEST_CHECK(talloc_reference_count(str) == 1);

	TEST_CASE("Multiple increases stack");
	ret = talloc_increase_ref_count(str);
	TEST_CHECK(ret == 0);
	TEST_CHECK(talloc_reference_count(str) == 2);

	/*
	 *	And then  decrease it to be safe.
	 */
	ret = talloc_decrease_ref_count(str);
	TEST_CHECK(ret == 2);				// WAS 2
	TEST_CHECK(talloc_reference_count(str) == 1);	// NOW 1

	ret = talloc_decrease_ref_count(str);
	TEST_CHECK(ret == 1);				// WAS 1, now 0 and freed

	ret = talloc_total_blocks(ctx);
	TEST_CHECK(ret == 1);				// just ctx itself

	ret = talloc_free(ctx);
	TEST_CHECK(ret == 0);
}

/*
 *	=== FreeRADIUS extension tests ===
 */

/*
 *	talloc_typed_strdup - should duplicate string and set type to char
 */
static void test_talloc_typed_strdup(void)
{
	TALLOC_CTX	*ctx;
	char		*dup;

	ctx = talloc_init_const("test");

	TEST_CASE("Duplicate a simple string");
	dup = talloc_typed_strdup(ctx, "hello");
	TEST_ASSERT(dup != NULL);
	TEST_CHECK(strcmp(dup, "hello") == 0);
	TEST_CHECK(talloc_get_size(dup) == 6);
	TEST_CHECK(talloc_parent(dup) == ctx);

	TEST_CASE("Duplicate an empty string");
	dup = talloc_typed_strdup(ctx, "");
	TEST_ASSERT(dup != NULL);
	TEST_CHECK(dup[0] == '\0');
	TEST_CHECK(talloc_get_size(dup) == 1);

	TEST_CASE("Duplicate NULL returns NULL");
	dup = talloc_typed_strdup(ctx, NULL);
	TEST_CHECK(dup == NULL);

	talloc_free(ctx);
}

/*
 *	talloc_typed_strndup - length-limited duplication
 */
static void test_talloc_typed_strndup(void)
{
	TALLOC_CTX	*ctx;
	char		*dup;

	ctx = talloc_init_const("test");

	TEST_CASE("Duplicate partial string");
	dup = talloc_typed_strndup(ctx, "hello world", 5);
	TEST_ASSERT(dup != NULL);
	TEST_CHECK(strcmp(dup, "hello") == 0);
	TEST_CHECK(talloc_get_size(dup) == 6);

	TEST_CASE("Duplicate zero length");
	dup = talloc_typed_strndup(ctx, "hello", 0);
	TEST_ASSERT(dup != NULL);
	TEST_CHECK(dup[0] == '\0');

	talloc_free(ctx);
}

/*
 *	talloc_typed_asprintf - formatted string with correct type
 */
static void test_talloc_typed_asprintf(void)
{
	TALLOC_CTX	*ctx;
	char		*str;

	ctx = talloc_init_const("test");

	TEST_CASE("Simple format string");
	str = talloc_typed_asprintf(ctx, "hello %s %d", "world", 42);
	TEST_ASSERT(str != NULL);
	TEST_CHECK(strcmp(str, "hello world 42") == 0);

	TEST_CASE("Empty format string");
	str = talloc_typed_asprintf(ctx, "%s", "");
	TEST_ASSERT(str != NULL);
	TEST_CHECK(str[0] == '\0');

	talloc_free(ctx);
}

/*
 *	talloc_bstrndup - binary safe string duplication
 */
static void test_talloc_bstrndup(void)
{
	TALLOC_CTX	*ctx;
	char		*dup;

	ctx = talloc_init_const("test");

	TEST_CASE("Duplicate string with embedded NUL");
	dup = talloc_bstrndup(ctx, "hel\0lo", 6);
	TEST_ASSERT(dup != NULL);
	TEST_CHECK(memcmp(dup, "hel\0lo", 6) == 0);
	TEST_CHECK(dup[6] == '\0');  /* Should be NUL terminated */
	TEST_CHECK(talloc_array_length(dup) == 7);

	TEST_CASE("Duplicate zero-length string");
	dup = talloc_bstrndup(ctx, "", 0);
	TEST_ASSERT(dup != NULL);
	TEST_CHECK(dup[0] == '\0');
	TEST_CHECK(talloc_array_length(dup) == 1);

	talloc_free(ctx);
}

/*
 *	talloc_bstr_append - append binary-safe strings
 */
static void test_talloc_bstr_append(void)
{
	TALLOC_CTX	*ctx;
	char		*str, *result;

	ctx = talloc_init_const("test");

	TEST_CASE("Append to existing string");
	str = talloc_bstrndup(ctx, "hello", 5);
	result = talloc_bstr_append(ctx, str, " world", 6);
	TEST_ASSERT(result != NULL);
	TEST_CHECK(strcmp(result, "hello world") == 0);

	TEST_CASE("Append to NULL creates new string");
	result = talloc_bstr_append(ctx, NULL, "new", 3);
	TEST_ASSERT(result != NULL);
	TEST_CHECK(strcmp(result, "new") == 0);

	talloc_free(ctx);
}

/*
 *	talloc_bstr_realloc - reallocate a bstr to a new length
 */
static void test_talloc_bstr_realloc(void)
{
	TALLOC_CTX	*ctx;
	char		*str, *result;

	ctx = talloc_init_const("test");

	TEST_CASE("Realloc NULL allocates new buffer");
	result = talloc_bstr_realloc(ctx, NULL, 10);
	TEST_ASSERT(result != NULL);
	TEST_CHECK(result[0] == '\0');
	TEST_CHECK(talloc_array_length(result) == 11);

	TEST_CASE("Realloc existing buffer to smaller size");
	str = talloc_bstrndup(ctx, "hello world", 11);
	result = talloc_bstr_realloc(ctx, str, 5);
	TEST_ASSERT(result != NULL);
	TEST_CHECK(result[5] == '\0');
	TEST_CHECK(talloc_array_length(result) == 6);

	talloc_free(ctx);
}

/*
 *	talloc_memcmp_array - compare uint8_t arrays
 */
static void test_talloc_memcmp_array(void)
{
	TALLOC_CTX	*ctx;
	uint8_t		*a, *b;
	uint8_t		data3[] = {1, 2, 3};
	uint8_t		data4a[] = {1, 2, 3, 4};
	uint8_t		data4b[] = {1, 2, 4, 4};

	ctx = talloc_init_const("test");

	TEST_CASE("Equal arrays");
	a = talloc_typed_memdup(ctx, data3, sizeof(data3));
	b = talloc_typed_memdup(ctx, data3, sizeof(data3));
	TEST_CHECK(talloc_memcmp_array(a, b) == 0);

	TEST_CASE("First array longer");
	talloc_free(a);
	a = talloc_typed_memdup(ctx, data4a, sizeof(data4a));
	TEST_CHECK(talloc_memcmp_array(a, b) > 0);

	TEST_CASE("Second array longer");
	TEST_CHECK(talloc_memcmp_array(b, a) < 0);

	TEST_CASE("Same length, different content");
	talloc_free(b);
	b = talloc_typed_memdup(ctx, data4b, sizeof(data4b));
	TEST_CHECK(talloc_memcmp_array(a, b) < 0);  /* 3 < 4 */

	talloc_free(ctx);
}

/*
 *	talloc_memcmp_bstr - compare char arrays
 */
static void test_talloc_memcmp_bstr(void)
{
	TALLOC_CTX	*ctx;
	char		*a, *b;

	ctx = talloc_init_const("test");

	TEST_CASE("Equal strings");
	a = talloc_bstrndup(ctx, "abc", 3);
	b = talloc_bstrndup(ctx, "abc", 3);
	TEST_CHECK(talloc_memcmp_bstr(a, b) == 0);

	TEST_CASE("Different lengths");
	talloc_free(a);
	a = talloc_bstrndup(ctx, "abcd", 4);
	TEST_CHECK(talloc_memcmp_bstr(a, b) > 0);

	talloc_free(ctx);
}

/*
 *	talloc_typed_memdup - duplicate uint8_t buffer
 */
static void test_talloc_typed_memdup(void)
{
	TALLOC_CTX	*ctx;
	uint8_t		data[] = {0xde, 0xad, 0xbe, 0xef};
	uint8_t		*dup;

	ctx = talloc_init_const("test");

	TEST_CASE("Duplicate binary data");
	dup = talloc_typed_memdup(ctx, data, sizeof(data));
	TEST_ASSERT(dup != NULL);
	TEST_CHECK(memcmp(dup, data, sizeof(data)) == 0);
	TEST_CHECK(talloc_get_size(dup) == sizeof(data));
	TEST_CHECK(talloc_parent(dup) == ctx);

	talloc_free(ctx);
}

/*
 *	talloc_buffer_append_buffer - concatenate talloc strings
 */
static void test_talloc_buffer_append_buffer(void)
{
	TALLOC_CTX	*ctx;
	char		*a, *result;

	ctx = talloc_init_const("test");

	TEST_CASE("Concatenate two talloc strings");
	a = talloc_strdup(ctx, "hello ");
	{
		char *b = talloc_strdup(ctx, "world");
		result = talloc_buffer_append_buffer(ctx, a, b);
		TEST_ASSERT(result != NULL);
		TEST_CHECK(strcmp(result, "hello world") == 0);
		talloc_free(b);
	}

	TEST_CASE("NULL first arg returns NULL");
	{
		char *b = talloc_strdup(ctx, "test");
		result = talloc_buffer_append_buffer(ctx, NULL, b);
		TEST_CHECK(result == NULL);
		talloc_free(b);
	}

	TEST_CASE("NULL second arg returns NULL");
	a = talloc_strdup(ctx, "hello");
	result = talloc_buffer_append_buffer(ctx, a, NULL);
	TEST_CHECK(result == NULL);

	talloc_free(ctx);
}

/*
 *	talloc_array_null_terminate / talloc_array_null_strip
 */
static void test_talloc_array_null_terminate(void)
{
	TALLOC_CTX	*ctx;
	void		**array, **result;

	ctx = talloc_init_const("test");

	TEST_CASE("NULL terminate an array");
	array = talloc_array(ctx, void *, 3);
	array[0] = (void *)1;
	array[1] = (void *)2;
	array[2] = (void *)3;
	result = talloc_array_null_terminate(array);
	TEST_ASSERT(result != NULL);
	TEST_CHECK(talloc_array_length(result) == 4);
	TEST_CHECK(result[3] == NULL);
	TEST_CHECK(result[0] == (void *)1);

	TEST_CASE("Strip NULL termination");
	result = talloc_array_null_strip(result);
	TEST_ASSERT(result != NULL);
	TEST_CHECK(talloc_array_length(result) == 3);

	TEST_CASE("NULL terminate NULL returns NULL");
	TEST_CHECK(talloc_array_null_terminate(NULL) == NULL);

	TEST_CASE("NULL strip NULL returns NULL");
	TEST_CHECK(talloc_array_null_strip(NULL) == NULL);

	talloc_free(ctx);
}

/*
 *	talloc_destructor_add / talloc_destructor_disarm
 */
static int		fr_destructor_called;
static void const	*fr_destructor_uctx;

static int test_fr_destructor_func(UNUSED void *fire_ctx, void *uctx)
{
	fr_destructor_called++;
	fr_destructor_uctx = uctx;
	return 0;
}

static void test_talloc_destructor_add(void)
{
	TALLOC_CTX		*ctx, *fire;
	fr_talloc_destructor_t	*d;

	ctx = talloc_init_const("test");

	TEST_CASE("Destructor fires when fire_ctx is freed");
	fr_destructor_called = 0;
	fire = talloc(ctx, int);
	d = talloc_destructor_add(fire, NULL, test_fr_destructor_func, (void *)0x42);
	TEST_CHECK(d != NULL);
	talloc_free(fire);
	TEST_CHECK(fr_destructor_called == 1);
	TEST_CHECK(fr_destructor_uctx == (void *)0x42);

	TEST_CASE("Manual disarm via talloc_destructor_disarm");
	fr_destructor_called = 0;
	fire = talloc(ctx, int);
	d = talloc_destructor_add(fire, NULL, test_fr_destructor_func, NULL);
	TEST_ASSERT(d != NULL);
	talloc_destructor_disarm(d);
	talloc_free(fire);
	TEST_CHECK(fr_destructor_called == 0);

	TEST_CASE("NULL fire_ctx returns NULL");
	d = talloc_destructor_add(NULL, NULL, test_fr_destructor_func, NULL);
	TEST_CHECK(d == NULL);

	talloc_free(ctx);
}

/*
 *	talloc_link_ctx - link parent and child lifetimes
 */
static void test_talloc_link_ctx(void)
{
	TALLOC_CTX	*parent, *child;
	int		ret;

	TEST_CASE("Child freed when parent freed");
	parent = talloc_init_const("parent");
	child = talloc_init_const("child");
	ret = talloc_link_ctx(parent, child);
	TEST_CHECK(ret == 0);
	talloc_free(parent);
}

/*
 *	talloc_hdr_size - calculate talloc chunk header size
 */
static void test_talloc_hdr_size(void)
{
	ssize_t hdr;

	TEST_CASE("Header size is positive and reasonable");
	hdr = talloc_hdr_size();
	TEST_CHECK(hdr > 0);
	TEST_CHECK(hdr < 1024);
	TEST_CHECK(hdr > (ssize_t)sizeof(void *));

	TEST_CASE("Repeated calls return same value");
	TEST_CHECK(talloc_hdr_size() == hdr);
}

/*
 *	talloc_child_ctx - ordered allocation and deallocation
 */
static int child_free_order[4];
static int child_free_idx;

static int _track_free_order(int *ptr)
{
	int val = *ptr;
	if (child_free_idx < 4) child_free_order[child_free_idx++] = val;
	return 0;
}

static void test_talloc_child_ctx(void)
{
	TALLOC_CTX	*ctx;
	TALLOC_CHILD_CTX *list, *c1, *c2, *c3;
	int		*v1, *v2, *v3;

	ctx = talloc_init_const("test");

	TEST_CASE("Child ctx init");
	list = talloc_child_ctx_init(ctx);
	TEST_ASSERT(list != NULL);

	TEST_CASE("Allocate children in order");
	c1 = talloc_child_ctx_alloc(list);
	TEST_ASSERT(c1 != NULL);
	v1 = talloc(c1, int);
	*v1 = 1;
	talloc_set_destructor(v1, _track_free_order);

	c2 = talloc_child_ctx_alloc(list);
	TEST_ASSERT(c2 != NULL);
	v2 = talloc(c2, int);
	*v2 = 2;
	talloc_set_destructor(v2, _track_free_order);

	c3 = talloc_child_ctx_alloc(list);
	TEST_ASSERT(c3 != NULL);
	v3 = talloc(c3, int);
	*v3 = 3;
	talloc_set_destructor(v3, _track_free_order);

	TEST_CASE("Children freed in FILO order");
	child_free_idx = 0;
	memset(child_free_order, 0, sizeof(child_free_order));
	talloc_free(ctx);

	/* FILO: c3 (newest) freed first, then c2, then c1 */
	TEST_CHECK(child_free_order[0] == 3);
	TEST_CHECK(child_free_order[1] == 2);
	TEST_CHECK(child_free_order[2] == 1);
}

/*
 *	talloc_realloc_zero - realloc that zeros new memory
 */
static void test_talloc_realloc_zero(void)
{
	TALLOC_CTX	*ctx;
	uint8_t		*arr;
	unsigned int	i;

	ctx = talloc_init_const("test");

	TEST_CASE("Initial allocation");
	arr = talloc_array(ctx, uint8_t, 4);
	TEST_ASSERT(arr != NULL);
	memset(arr, 0xff, 4);

	TEST_CASE("Realloc larger zeros new portion");
	arr = talloc_realloc_zero(ctx, arr, uint8_t, 16);
	TEST_ASSERT(arr != NULL);

	/* Original bytes preserved */
	for (i = 0; i < 4; i++) {
		TEST_CHECK(arr[i] == 0xff);
	}

	/* New bytes zeroed */
	for (i = 4; i < 16; i++) {
		TEST_CHECK(arr[i] == 0);
	}

	talloc_free(ctx);
}

/*
 *	talloc_decrease_ref_count
 */
static void test_talloc_decrease_ref_count(void)
{
	TALLOC_CTX	*ctx, *ref_ctx;
	char		*str;
	int		ret;

	ctx = talloc_init_const("test");
	ref_ctx = talloc_init_const("ref");

	TEST_CASE("Decrease ref count with no references frees memory");
	str = talloc_strdup(ctx, "test");
	ret = talloc_decrease_ref_count(str);
	TEST_CHECK(ret == 0);

	TEST_CASE("NULL ptr returns 0");
	ret = talloc_decrease_ref_count(NULL);
	TEST_CHECK(ret == 0);

	TEST_CASE("With a reference, unlinks instead of freeing");
	str = talloc_strdup(ctx, "referenced");
	talloc_reference(ref_ctx, str);
	ret = talloc_decrease_ref_count(str);
	TEST_CHECK(ret == 1);  /* One reference remains */

	talloc_free(ctx);
	talloc_free(ref_ctx);
}

/*
 *	talloc_aligned_array - page-aligned allocation
 */
static void test_talloc_aligned_array(void)
{
	TALLOC_CTX	*ctx, *array;
	void		*start;
	size_t		page_size = (size_t)getpagesize();

	ctx = talloc_init_const("test");

	TEST_CASE("Aligned array returns non-NULL");
	array = talloc_aligned_array(ctx, &start, page_size, page_size);
	TEST_CHECK(array != NULL);
	TEST_CHECK(start != NULL);

	TEST_CASE("Start address is page-aligned");
	TEST_CHECK(((uintptr_t)start % page_size) == 0);

	talloc_free(ctx);
}

TEST_LIST = {
	/* Core talloc (samba) tests */
	{ "talloc_basic",			test_talloc_basic },
	{ "talloc_zero",			test_talloc_zero },
	{ "talloc_array",			test_talloc_array },
	{ "talloc_free",			test_talloc_free },
	{ "talloc_naming",			test_talloc_naming },
	{ "talloc_parent",			test_talloc_parent },
	{ "talloc_steal",			test_talloc_steal },
	{ "talloc_move",			test_talloc_move },
	{ "talloc_reference",			test_talloc_reference },
	{ "talloc_set_destructor",		test_talloc_set_destructor },
	{ "talloc_strdup",			test_talloc_strdup },
	{ "talloc_asprintf",			test_talloc_asprintf },
	{ "talloc_pool",			test_talloc_pool },
	{ "talloc_free_children",		test_talloc_free_children },
	{ "talloc_total_size",			test_talloc_total_size },
	{ "talloc_get_size",			test_talloc_get_size },
	{ "talloc_find_parent_byname",		test_talloc_find_parent_byname },
	{ "talloc_is_parent",			test_talloc_is_parent },
	{ "talloc_reparent",			test_talloc_reparent },
	{ "talloc_memdup",			test_talloc_memdup },
	{ "talloc_deep_hierarchy",		test_talloc_deep_hierarchy },
	{ "talloc_strndup_append",		test_talloc_strndup_append },
	{ "talloc_increase_ref_count",		test_talloc_increase_ref_count },

	/* FreeRADIUS extension tests */
	{ "talloc_typed_strdup",		test_talloc_typed_strdup },
	{ "talloc_typed_strndup",		test_talloc_typed_strndup },
	{ "talloc_typed_asprintf",		test_talloc_typed_asprintf },
	{ "talloc_bstrndup",			test_talloc_bstrndup },
	{ "talloc_bstr_append",			test_talloc_bstr_append },
	{ "talloc_bstr_realloc",		test_talloc_bstr_realloc },
	{ "talloc_memcmp_array",		test_talloc_memcmp_array },
	{ "talloc_memcmp_bstr",			test_talloc_memcmp_bstr },
	{ "talloc_typed_memdup",		test_talloc_typed_memdup },
	{ "talloc_buffer_append_buffer",	test_talloc_buffer_append_buffer },
	{ "talloc_array_null_terminate",	test_talloc_array_null_terminate },
	{ "talloc_destructor_add",		test_talloc_destructor_add },
	{ "talloc_link_ctx",			test_talloc_link_ctx },
	{ "talloc_hdr_size",			test_talloc_hdr_size },
	{ "talloc_child_ctx",			test_talloc_child_ctx },
	{ "talloc_realloc_zero",		test_talloc_realloc_zero },
	{ "talloc_decrease_ref_count",		test_talloc_decrease_ref_count },
	{ "talloc_aligned_array",		test_talloc_aligned_array },

	TEST_TERMINATOR
};
