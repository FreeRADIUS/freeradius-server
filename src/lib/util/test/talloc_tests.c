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

/** Tests for FreeRADIUS talloc utility functions
 *
 * @file src/lib/util/test/talloc_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include "acutest.h"
#include "acutest_helpers.h"
#include <freeradius-devel/util/talloc.h>

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
static int		destructor_called;
static void const	*destructor_uctx;

static int test_destructor_func(UNUSED void *fire_ctx, void *uctx)
{
	destructor_called++;
	destructor_uctx = uctx;
	return 0;
}

static void test_talloc_destructor_add(void)
{
	TALLOC_CTX		*ctx, *fire;
	fr_talloc_destructor_t	*d;

	ctx = talloc_init_const("test");

	TEST_CASE("Destructor fires when fire_ctx is freed");
	destructor_called = 0;
	fire = talloc(ctx, int);
	d = talloc_destructor_add(fire, NULL, test_destructor_func, (void *)0x42);
	TEST_CHECK(d != NULL);
	talloc_free(fire);
	TEST_CHECK(destructor_called == 1);
	TEST_CHECK(destructor_uctx == (void *)0x42);

	TEST_CASE("Manual disarm via talloc_destructor_disarm");
	destructor_called = 0;
	fire = talloc(ctx, int);
	d = talloc_destructor_add(fire, NULL, test_destructor_func, NULL);
	TEST_CHECK(d != NULL);
	talloc_destructor_disarm(d);
	talloc_free(fire);
	TEST_CHECK(destructor_called == 0);

	TEST_CASE("NULL fire_ctx returns NULL");
	d = talloc_destructor_add(NULL, NULL, test_destructor_func, NULL);
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

static int _track_free_order(void *ptr)
{
	int val = *(int *)ptr;
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
