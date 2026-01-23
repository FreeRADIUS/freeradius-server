#include "acutest.h"

#include "../dcursor.c"

/*
 *	A repeat of the tests in dcursor_tests.c, but using
 *	type specific dcursors
 */

FR_DLIST_TYPES(test_list)

typedef struct {
	char const			*name;
	FR_DLIST_ENTRY(test_list)	entry;
} test_item_t;

FR_DLIST_FUNCS(test_list, test_item_t, entry)

FR_DCURSOR_DLIST_TYPES(test_dcursor, test_list, test_item_t)

FR_DCURSOR_FUNCS(test_dcursor, test_list, test_item_t)

static test_item_t *test_iter(fr_dcursor_t *cursor, test_item_t *current, UNUSED void *uctx)
{
	return test_list_next((FR_DLIST_HEAD(test_list) *) cursor->dlist, current);
}

static void test_init_null_item(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);

	item_p = test_dcursor_iter_init(&cursor, &list, test_iter, NULL, &cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK((cursor.dcursor.dlist) == &list.head);
	TEST_CHECK(!test_dcursor_current(&cursor));
	TEST_CHECK(!test_dcursor_list_next_peek(&cursor));
	TEST_CHECK(cursor.dcursor.iter_uctx == &cursor);
}

static void test_init_1i_start(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);

	item_p = test_dcursor_init(&cursor, &list);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK((cursor.dcursor.dlist) == &list.head);
	TEST_CHECK(test_dcursor_current(&cursor) == &item1);
}

static void test_init_2i_start(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);

	item_p = test_dcursor_init(&cursor, &list);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK(test_dcursor_current(&cursor) == &item1);
}

static void test_next(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);

	test_dcursor_init(&cursor, &list);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item2);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(test_dcursor_current(&cursor) == &item2);
	TEST_CHECK(!test_dcursor_next_peek(&cursor));
}

static void test_next_wrap(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);

	test_dcursor_init(&cursor, &list);
	test_dcursor_next(&cursor);
	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(!test_dcursor_current(&cursor));
	TEST_CHECK(!test_dcursor_next_peek(&cursor));

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(!test_dcursor_current(&cursor));
	TEST_CHECK(!test_dcursor_next_peek(&cursor));
}

static void test_dcursor_head_tail_null(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);

	test_dcursor_init(&cursor, &list);
	TEST_CHECK(!test_dcursor_current(&cursor));
	TEST_CHECK(!test_dcursor_head(&cursor));
	TEST_CHECK(!test_dcursor_tail(&cursor));
}

static void test_dcursor_test_head(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);
}

static void test_dcursor_head_reset(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);

	test_dcursor_init(&cursor, &list);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item2);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == NULL);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_current(&cursor);
	TEST_CHECK(item_p == &item1);
}

static void test_dcursor_iter_head_reset(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);

	item_p = test_dcursor_iter_init(&cursor, &list, test_iter, NULL, &cursor);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item2);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == NULL);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_current(&cursor);
	TEST_CHECK(item_p == &item1);
}

static void test_dcursor_head_after_next(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	test_dcursor_next(&cursor);
	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);
}

static void test_dcursor_test_tail(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	test_dcursor_next(&cursor);
	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
	item_p = test_dcursor_current(&cursor);
	TEST_CHECK(item_p == &item3);
}

static void test_dcursor_head_after_tail(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	test_dcursor_tail(&cursor);
	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);
}

static void test_dcursor_wrap_after_tail(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	test_dcursor_tail(&cursor);
	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(!item_p);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(!item_p);
}

static void test_dcursor_append_empty(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			*item_p;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_dcursor_init(&cursor, &list);
	test_dcursor_append(&cursor, &item1);

	item_p = test_dcursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item1);
}

static void test_dcursor_append_empty_3(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);

	test_dcursor_init(&cursor, &list);
	test_dcursor_append(&cursor, &item1);
	test_dcursor_append(&cursor, &item2);
	test_dcursor_append(&cursor, &item3);

	item_p = test_dcursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(test_dcursor_next(&cursor) == &item1);
	TEST_CHECK(test_dcursor_next(&cursor) == &item2);
	TEST_CHECK(test_dcursor_next(&cursor) == &item3);
}

static void test_dcursor_prepend_empty(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			*item_p;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);

	test_dcursor_init(&cursor, &list);
	test_dcursor_prepend(&cursor, &item1);

	item_p = test_dcursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item1);
}

static void test_dcursor_prepend_empty_3(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);

	test_dcursor_init(&cursor, &list);
	test_dcursor_prepend(&cursor, &item1);
	test_dcursor_prepend(&cursor, &item2);
	test_dcursor_prepend(&cursor, &item3);

	item_p = test_dcursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(test_dcursor_next(&cursor) == &item3);
	TEST_CHECK(test_dcursor_next(&cursor) == &item2);
	TEST_CHECK(test_dcursor_next(&cursor) == &item1);
}

static void test_dcursor_insert_into_empty(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			*item_p;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);

	test_dcursor_init(&cursor, &list);
	test_dcursor_insert(&cursor, &item1);

	item_p = test_dcursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item1);
}

static void test_dcursor_insert_into_empty_3(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);

	test_dcursor_init(&cursor, &list);
	test_dcursor_insert(&cursor, &item1);
	test_dcursor_insert(&cursor, &item2);
	test_dcursor_insert(&cursor, &item3);

	item_p = test_dcursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(test_dcursor_next(&cursor) == &item1);
	TEST_CHECK(test_dcursor_next(&cursor) == &item2);
	TEST_CHECK(test_dcursor_next(&cursor) == &item3);
}

static void test_dcursor_replace_in_empty(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			*item_p;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);

	test_dcursor_init(&cursor, &list);
	TEST_CHECK(!test_dcursor_replace(&cursor, &item1));

	item_p = test_dcursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item1);
}

static void test_dcursor_prepend_1i_start(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);

	test_dcursor_init(&cursor, &list);
	test_dcursor_prepend(&cursor, &item2);

	TEST_CHECK(test_dcursor_current(&cursor) == &item1);
	TEST_CHECK(!test_dcursor_next_peek(&cursor));

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(!item_p);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item1);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item1);
}

static void test_dcursor_append_1i_start(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);

	test_dcursor_init(&cursor, &list);
	test_dcursor_append(&cursor, &item2);

	TEST_CHECK(test_dcursor_current(&cursor) == &item1);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item2);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item2);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

static void test_dcursor_insert_1i_start(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);

	test_dcursor_init(&cursor, &list);
	test_dcursor_append(&cursor, &item2);

	TEST_CHECK(test_dcursor_current(&cursor) == &item1);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item2);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item2);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

static void test_dcursor_replace_1i_start(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);

	test_dcursor_init(&cursor, &list);
	item_p = test_dcursor_replace(&cursor, &item2);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_current(&cursor);
	TEST_CHECK(item_p == &item2);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item2);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

static void test_dcursor_prepend_2i_start(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);

	test_dcursor_init(&cursor, &list);
	test_dcursor_prepend(&cursor, &item3);

	TEST_CHECK(test_dcursor_current(&cursor) == &item1);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item2);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item2);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(!item_p);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item3);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

static void test_dcursor_append_2i_start(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);

	test_dcursor_init(&cursor, &list);
	test_dcursor_append(&cursor, &item3);

	TEST_CHECK(test_dcursor_current(&cursor) == &item1);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item2);
	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item3);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

static void test_dcursor_insert_2i_start(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);

	test_dcursor_init(&cursor, &list);
	test_dcursor_insert(&cursor, &item3);

	TEST_CHECK(test_dcursor_current(&cursor) == &item1);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item3);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item3);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item2);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

static void test_dcursor_replace_2i_start(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);

	test_dcursor_init(&cursor, &list);
	item_p = test_dcursor_replace(&cursor, &item3);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_current(&cursor);
	TEST_CHECK(item_p == &item3);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item3);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

static void test_dcursor_prepend_3i_mid(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			item4 = { "item4", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	test_dcursor_next(&cursor);
	test_dcursor_prepend(&cursor, &item4);

	TEST_CHECK(test_dcursor_current(&cursor) == &item2);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item3);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item3);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(!item_p);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item4);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

static void test_dcursor_append_3i_mid(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			item4 = { "item4", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	test_dcursor_next(&cursor);
	test_dcursor_append(&cursor, &item4);

	TEST_CHECK(test_dcursor_current(&cursor) == &item2);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item3);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item3);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item4);
}

static void test_dcursor_insert_3i_mid(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			item4 = { "item4", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	test_dcursor_next(&cursor);
	test_dcursor_insert(&cursor, &item4);

	TEST_CHECK(test_dcursor_current(&cursor) == &item2);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item4);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item4);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item3);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

static void test_dcursor_replace_3i_mid(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			item4 = { "item4", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	test_dcursor_next(&cursor);
	item_p = test_dcursor_replace(&cursor, &item4);
	TEST_CHECK(item_p == &item2);

	item_p = test_dcursor_current(&cursor);
	TEST_CHECK(item_p == &item4);

	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item3);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

static void test_dcursor_prepend_3i_end(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			item4 = { "item4", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	test_dcursor_next(&cursor);
	test_dcursor_next(&cursor);
	test_dcursor_prepend(&cursor, &item4);

	TEST_CHECK(test_dcursor_current(&cursor) == &item3);
	TEST_CHECK(!test_dcursor_next_peek(&cursor));

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(!item_p);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item4);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

static void test_dcursor_append_3i_end(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			item4 = { "item4", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	test_dcursor_next(&cursor);
	test_dcursor_next(&cursor);
	test_dcursor_append(&cursor, &item4);

	TEST_CHECK(test_dcursor_current(&cursor) == &item3);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item4);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item4);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item4);
}

static void test_dcursor_insert_3i_end(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			item4 = { "item4", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	test_dcursor_next(&cursor);
	test_dcursor_next(&cursor);
	test_dcursor_insert(&cursor, &item4);

	TEST_CHECK(test_dcursor_current(&cursor) == &item3);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item4);

	item_p = test_dcursor_next(&cursor);
	TEST_CHECK(item_p == &item4);

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item4);
}

static void test_dcursor_replace_3i_end(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			item4 = { "item4", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	test_dcursor_next(&cursor);
	test_dcursor_next(&cursor);
	item_p = test_dcursor_replace(&cursor, &item4);
	TEST_CHECK(item_p == &item3);

	item_p = test_dcursor_current(&cursor);
	TEST_CHECK(item_p == &item4);

	TEST_CHECK(!test_dcursor_next_peek(&cursor));

	item_p = test_dcursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = test_dcursor_tail(&cursor);
	TEST_CHECK(item_p == &item4);
}

static void test_dcursor_remove_empty(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);

	test_dcursor_init(&cursor, &list);

	TEST_CHECK(!test_dcursor_remove(&cursor));
}

static void test_dcursor_remove_1i(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);

	test_dcursor_init(&cursor, &list);

	item_p = test_dcursor_remove(&cursor);
	TEST_CHECK(item_p == &item1);

	TEST_CHECK(!test_dcursor_current(&cursor));
	TEST_CHECK(!test_dcursor_next(&cursor));
	TEST_CHECK(!test_dcursor_tail(&cursor));
	TEST_CHECK(!test_dcursor_head(&cursor));
}

static void test_dcursor_remove_2i(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);

	test_dcursor_init(&cursor, &list);

	item_p = test_dcursor_remove(&cursor);
	TEST_CHECK(item_p == &item1);

	TEST_CHECK(test_dcursor_current(&cursor) == &item2);
	TEST_CHECK(!test_dcursor_next(&cursor));
	TEST_CHECK(test_dcursor_tail(&cursor) == &item2);
	TEST_CHECK(test_dcursor_head(&cursor) == &item2);

	item_p = test_dcursor_remove(&cursor);
	TEST_CHECK(item_p == &item2);

	TEST_CHECK(!test_dcursor_current(&cursor));
	TEST_CHECK(!test_dcursor_next(&cursor));
	TEST_CHECK(!test_dcursor_tail(&cursor));
	TEST_CHECK(!test_dcursor_head(&cursor));
}

static void test_dcursor_remove_3i_start(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	item_p = test_dcursor_remove(&cursor);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK(test_dcursor_current(&cursor) == &item2);
	TEST_CHECK(test_dcursor_next_peek(&cursor) == &item3);

	item_p = test_dcursor_remove(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(test_dcursor_current(&cursor) == &item3);
	TEST_CHECK(!test_dcursor_next_peek(&cursor));

	item_p = test_dcursor_remove(&cursor);
	TEST_CHECK(item_p == &item3);

	TEST_CHECK(!test_dcursor_current(&cursor));
	TEST_CHECK(!test_dcursor_tail(&cursor));
	TEST_CHECK(!test_dcursor_head(&cursor));
}

static void test_dcursor_remove_3i_mid(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	test_dcursor_next(&cursor);

	item_p = test_dcursor_remove(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(test_dcursor_current(&cursor) == &item3);
	TEST_CHECK(!test_dcursor_next_peek(&cursor));

	item_p = test_dcursor_remove(&cursor);
	TEST_CHECK(item_p == &item3);

	TEST_CHECK(!test_dcursor_current(&cursor));
	TEST_CHECK(!test_dcursor_next_peek(&cursor));

	item_p = test_dcursor_remove(&cursor);
	TEST_CHECK(!item_p);

	TEST_CHECK(test_dcursor_tail(&cursor) == &item1);
	TEST_CHECK(test_dcursor_head(&cursor) == &item1);
}

static void test_dcursor_remove_3i_end(void)
{
	FR_DCURSOR(test_dcursor)	cursor;
	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item_p;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor, &list);
	test_dcursor_tail(&cursor);

	item_p = test_dcursor_remove(&cursor);
	TEST_CHECK(item_p == &item3);
	TEST_CHECK(!test_dcursor_current(&cursor));
	TEST_CHECK(!test_dcursor_next_peek(&cursor));

	item_p = test_dcursor_remove(&cursor);
	TEST_CHECK(!item_p);

	TEST_CHECK(!test_dcursor_current(&cursor));
	TEST_CHECK(!test_dcursor_next_peek(&cursor));

	TEST_CHECK(test_dcursor_tail(&cursor) == &item2);
	TEST_CHECK(test_dcursor_head(&cursor) == &item1);
}

static void test_dcursor_merge_start_a_b(void)
{
	FR_DCURSOR(test_dcursor)	cursor_a, cursor_b;

	test_item_t			item1a = { "item1a", { { NULL, NULL } } };
	test_item_t			item2a = { "item2a", { { NULL, NULL } } };
	test_item_t			item3a = { "item3a", { { NULL, NULL } } };

	test_item_t			item1b = { "item1b", { { NULL, NULL } } };
	test_item_t			item2b = { "item2b", { { NULL, NULL } } };
	test_item_t			item3b = { "item3b", { { NULL, NULL } } };

	FR_DLIST_HEAD(test_list)	list_a, list_b;

	test_list_init(&list_a);
	test_list_insert_tail(&list_a, &item1a);
	test_list_insert_tail(&list_a, &item2a);
	test_list_insert_tail(&list_a, &item3a);

	test_list_init(&list_b);
	test_list_insert_tail(&list_b, &item1b);
	test_list_insert_tail(&list_b, &item2b);
	test_list_insert_tail(&list_b, &item3b);

	test_dcursor_init(&cursor_a, &list_a);
	test_dcursor_init(&cursor_b, &list_b);
	test_dcursor_merge(&cursor_a, &cursor_b);

	TEST_CHECK(test_dcursor_current(&cursor_a) == &item1a);
	TEST_MSG("Expected %s", item1a.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);

	TEST_CHECK(test_dcursor_next(&cursor_a) == &item1b);
	TEST_MSG("Expected %s", item1b.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item2b);
	TEST_MSG("Expected %s", item2b.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);

	TEST_CHECK(test_dcursor_next(&cursor_a) == &item2a);
	TEST_MSG("Expected %s", item2a.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(!test_dcursor_next(&cursor_a));

	TEST_CHECK(!test_dcursor_current(&cursor_b));
	TEST_CHECK(!test_dcursor_list_next_peek(&cursor_b));
}

static void test_dcursor_merge_mid_a(void)
{
	FR_DCURSOR(test_dcursor)	cursor_a, cursor_b;

	test_item_t			item1a = { "item1a", { { NULL, NULL } } };
	test_item_t			item2a = { "item2a", { { NULL, NULL } } };
	test_item_t			item3a = { "item3a", { { NULL, NULL } } };

	test_item_t			item1b = { "item1b", { { NULL, NULL } } };
	test_item_t			item2b = { "item2b", { { NULL, NULL } } };
	test_item_t			item3b = { "item3b", { { NULL, NULL } } };

	FR_DLIST_HEAD(test_list)	list_a, list_b;

	test_list_init(&list_a);
	test_list_insert_tail(&list_a, &item1a);
	test_list_insert_tail(&list_a, &item2a);
	test_list_insert_tail(&list_a, &item3a);

	test_list_init(&list_b);
	test_list_insert_tail(&list_b, &item1b);
	test_list_insert_tail(&list_b, &item2b);
	test_list_insert_tail(&list_b, &item3b);

	test_dcursor_init(&cursor_a, &list_a);
	test_dcursor_init(&cursor_b, &list_b);
	test_dcursor_next(&cursor_a);
	test_dcursor_merge(&cursor_a, &cursor_b);

	TEST_CHECK(test_dcursor_current(&cursor_a) == &item2a);
	TEST_MSG("Expected %s", item2a.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);

	TEST_CHECK(test_dcursor_next(&cursor_a) == &item1b);
	TEST_MSG("Expected %s", item1b.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item2b);
	TEST_MSG("Expected %s", item2b.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);

	/*
	 *	Final item should be from cursor a
	 */
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(!test_dcursor_next(&cursor_a));

	TEST_CHECK(!test_dcursor_current(&cursor_b));
	TEST_CHECK(!test_dcursor_list_next_peek(&cursor_b));
}

static void test_dcursor_merge_end_a(void)
{
	FR_DCURSOR(test_dcursor)	cursor_a, cursor_b;

	test_item_t			item1a = { "item1a", { { NULL, NULL } } };
	test_item_t			item2a = { "item2a", { { NULL, NULL } } };
	test_item_t			item3a = { "item3a", { { NULL, NULL } } };

	test_item_t			item1b = { "item1b", { { NULL, NULL } } };
	test_item_t			item2b = { "item2b", { { NULL, NULL } } };
	test_item_t			item3b = { "item3b", { { NULL, NULL } } };

	FR_DLIST_HEAD(test_list)	list_a, list_b;

	test_list_init(&list_a);
	test_list_insert_tail(&list_a, &item1a);
	test_list_insert_tail(&list_a, &item2a);
	test_list_insert_tail(&list_a, &item3a);

	test_list_init(&list_b);
	test_list_insert_tail(&list_b, &item1b);
	test_list_insert_tail(&list_b, &item2b);
	test_list_insert_tail(&list_b, &item3b);

	test_dcursor_init(&cursor_a, &list_a);
	test_dcursor_init(&cursor_b, &list_b);
	test_dcursor_tail(&cursor_a);
	test_dcursor_merge(&cursor_a, &cursor_b);

	TEST_CHECK(test_dcursor_current(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);

	TEST_CHECK(test_dcursor_next(&cursor_a) == &item1b);
	TEST_MSG("Expected %s", item1b.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item2b);
	TEST_MSG("Expected %s", item2b.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);

	TEST_CHECK(!test_dcursor_list_next_peek(&cursor_a));
	TEST_CHECK(!test_dcursor_current(&cursor_b));
	TEST_CHECK(!test_dcursor_list_next_peek(&cursor_b));
}

static void test_dcursor_merge_mid_b(void)
{
	FR_DCURSOR(test_dcursor)	cursor_a, cursor_b;

	test_item_t			item1a = { "item1a", { { NULL, NULL } } };
	test_item_t			item2a = { "item2a", { { NULL, NULL } } };
	test_item_t			item3a = { "item3a", { { NULL, NULL } } };

	test_item_t			item1b = { "item1b", { { NULL, NULL } } };
	test_item_t			item2b = { "item2b", { { NULL, NULL } } };
	test_item_t			item3b = { "item3b", { { NULL, NULL } } };

	FR_DLIST_HEAD(test_list)	list_a, list_b;

	test_list_init(&list_a);
	test_list_insert_tail(&list_a, &item1a);
	test_list_insert_tail(&list_a, &item2a);
	test_list_insert_tail(&list_a, &item3a);

	test_list_init(&list_b);
	test_list_insert_tail(&list_b, &item1b);
	test_list_insert_tail(&list_b, &item2b);
	test_list_insert_tail(&list_b, &item3b);

	test_dcursor_init(&cursor_a, &list_a);
	test_dcursor_init(&cursor_b, &list_b);
	test_dcursor_next(&cursor_b);
	test_dcursor_merge(&cursor_a, &cursor_b);

	TEST_CHECK(test_dcursor_current(&cursor_a) == &item1a);
	TEST_MSG("Expected %s", item1a.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);

	TEST_CHECK(test_dcursor_next(&cursor_a) == &item2b);
	TEST_MSG("Expected %s", item2b.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);

	TEST_CHECK(test_dcursor_next(&cursor_a) == &item2a);
	TEST_MSG("Expected %s", item2a.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(!test_dcursor_next(&cursor_a));

	TEST_CHECK(!test_dcursor_current(&cursor_b));
	TEST_CHECK(!test_dcursor_list_next_peek(&cursor_b));
}

static void test_dcursor_merge_end_b(void)
{
	FR_DCURSOR(test_dcursor)	cursor_a, cursor_b;

	test_item_t			item1a = { "item1a", { { NULL, NULL } } };
	test_item_t			item2a = { "item2a", { { NULL, NULL } } };
	test_item_t			item3a = { "item3a", { { NULL, NULL } } };

	test_item_t			item1b = { "item1b", { { NULL, NULL } } };
	test_item_t			item2b = { "item2b", { { NULL, NULL } } };
	test_item_t			item3b = { "item3b", { { NULL, NULL } } };

	FR_DLIST_HEAD(test_list)	list_a, list_b;

	test_list_init(&list_a);
	test_list_insert_tail(&list_a, &item1a);
	test_list_insert_tail(&list_a, &item2a);
	test_list_insert_tail(&list_a, &item3a);

	test_list_init(&list_b);
	test_list_insert_tail(&list_b, &item1b);
	test_list_insert_tail(&list_b, &item2b);
	test_list_insert_tail(&list_b, &item3b);

	test_dcursor_init(&cursor_a, &list_a);
	test_dcursor_init(&cursor_b, &list_b);
	test_dcursor_next(&cursor_b);
	test_dcursor_next(&cursor_b);
	test_dcursor_merge(&cursor_a, &cursor_b);

	TEST_CHECK(test_dcursor_current(&cursor_a) == &item1a);
	TEST_MSG("Expected %s", item1a.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);

	TEST_CHECK(test_dcursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item2a);
	TEST_MSG("Expected %s", item2a.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(!test_dcursor_next(&cursor_a));

	TEST_CHECK(!test_dcursor_current(&cursor_b));
	TEST_CHECK(test_dcursor_head(&cursor_b) == &item1b);
}

static void test_dcursor_merge_with_empty(void)
{
	FR_DCURSOR(test_dcursor)	cursor_a, cursor_b;

	test_item_t			item1b = { "item1b", { { NULL, NULL } } };
	test_item_t			item2b = { "item2b", { { NULL, NULL } } };
	test_item_t			item3b = { "item3b", { { NULL, NULL } } };

	FR_DLIST_HEAD(test_list)	list_a, list_b;

	test_list_init(&list_a);
	test_list_init(&list_b);
	test_list_insert_tail(&list_b, &item1b);
	test_list_insert_tail(&list_b, &item2b);
	test_list_insert_tail(&list_b, &item3b);

	test_dcursor_init(&cursor_a, &list_a);
	test_dcursor_init(&cursor_b, &list_b);
	test_dcursor_merge(&cursor_a, &cursor_b);

	TEST_CHECK(test_dcursor_head(&cursor_a) == &item1b);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item2b);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item3b);

	TEST_CHECK(!test_dcursor_current(&cursor_b));
	TEST_CHECK(!test_dcursor_list_next_peek(&cursor_b));
}

static void test_dcursor_merge_empty(void)
{
	FR_DCURSOR(test_dcursor)	cursor_a, cursor_b;

	test_item_t			item1a = { "item1a", { { NULL, NULL } } };
	test_item_t			item2a = { "item2a", { { NULL, NULL } } };
	test_item_t			item3a = { "item3a", { { NULL, NULL } } };

	FR_DLIST_HEAD(test_list)	list_a, list_b;

	test_list_init(&list_a);
	test_list_insert_tail(&list_a, &item1a);
	test_list_insert_tail(&list_a, &item2a);
	test_list_insert_tail(&list_a, &item3a);
	test_list_init(&list_b);

	test_dcursor_init(&cursor_a, &list_a);
	test_dcursor_init(&cursor_b, &list_b);
	test_dcursor_merge(&cursor_a, &cursor_b);

	TEST_CHECK(test_dcursor_head(&cursor_a) == &item1a);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item2a);
	TEST_CHECK(test_dcursor_next(&cursor_a) == &item3a);
}

static void test_dcursor_copy_test(void)
{
	FR_DCURSOR(test_dcursor)	cursor_a, cursor_b;

	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };

	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor_a, &list);
	test_dcursor_copy(&cursor_b, &cursor_a);

	TEST_CHECK(test_dcursor_head(&cursor_b) == &item1);
	TEST_CHECK(test_dcursor_next(&cursor_b) == &item2);
	TEST_CHECK(test_dcursor_next(&cursor_b) == &item3);
}

static void test_dcursor_free_by_list(void)
{
	test_item_t			*item1, *item2, *item3;
	FR_DLIST_HEAD(test_list)	list;
	FR_DCURSOR(test_dcursor)	cursor;

	test_list_init(&list);

	item1 = talloc_zero(NULL, test_item_t);
	item2 = talloc_zero(NULL, test_item_t);
	item3 = talloc_zero(NULL, test_item_t);

	test_dcursor_init(&cursor, &list);
	test_dcursor_append(&cursor, item1);
	test_dcursor_append(&cursor, item2);
	test_dcursor_append(&cursor, item3);

	test_dcursor_head(&cursor);
	test_dcursor_free_list(&cursor);

	TEST_CHECK(test_dcursor_current(&cursor) == NULL);
	TEST_CHECK(!test_dcursor_tail(&cursor));
	TEST_CHECK(!test_dcursor_head(&cursor));
}

static void test_dcursor_free_by_item(void)
{
	test_item_t			*item1, *item2, *item3;
	FR_DLIST_HEAD(test_list)	list;
	FR_DCURSOR(test_dcursor)	cursor;

	test_list_init(&list);

	item1 = talloc_zero(NULL, test_item_t);
	item2 = talloc_zero(NULL, test_item_t);
	item3 = talloc_zero(NULL, test_item_t);

	test_dcursor_init(&cursor, &list);
	test_dcursor_append(&cursor, item1);
	test_dcursor_append(&cursor, item2);
	test_dcursor_append(&cursor, item3);

	test_dcursor_head(&cursor);
	test_dcursor_free_item(&cursor);

	TEST_CHECK(test_dcursor_current(&cursor) == item2);
	TEST_CHECK(test_dcursor_tail(&cursor) == item3);
	TEST_CHECK(test_dcursor_head(&cursor) == item2);

	test_dcursor_free_item(&cursor);
	test_dcursor_free_item(&cursor);

	TEST_CHECK(test_dcursor_current(&cursor) == NULL);
	TEST_CHECK(!test_dcursor_tail(&cursor));
	TEST_CHECK(!test_dcursor_head(&cursor));
}

typedef struct {
	int	pos;
	char	val;
} item_filter;

static test_item_t *iter_name_check(fr_dcursor_t *cursor, test_item_t *current, void *uctx)
{
	item_filter	*f = uctx;

	while ((current = test_list_next((FR_DLIST_HEAD(test_list) *) cursor->dlist, current))) {
		if (current->name[f->pos] == f->val) break;
	}

	return current;
}

static void test_intersect_differing_lists(void)
{
	FR_DCURSOR(test_dcursor)	cursor_a, cursor_b;

	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	FR_DLIST_HEAD(test_list)	list_a, list_b;

	test_list_init(&list_a);
	test_list_insert_tail(&list_a, &item1);
	test_list_init(&list_b);
	test_list_insert_tail(&list_b, &item2);

	test_dcursor_init(&cursor_a, &list_a);
	test_dcursor_init(&cursor_b, &list_b);

	TEST_CHECK(test_dcursor_intersect_head(&cursor_a, &cursor_b) == NULL);
}

static void test_intersect_no_iterators(void)
{
	FR_DCURSOR(test_dcursor)	cursor_a, cursor_b;

	test_item_t			item1 = { "item1", { { NULL, NULL } } };
	test_item_t			item2 = { "item2", { { NULL, NULL } } };
	test_item_t			item3 = { "item3", { { NULL, NULL } } };
	test_item_t			*item4 = NULL;
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);

	test_dcursor_init(&cursor_a, &list);
	test_dcursor_init(&cursor_b, &list);

	item4 = test_dcursor_intersect_head(&cursor_a, &cursor_b);
	TEST_CHECK(item4 == &item1);
	TEST_CHECK(test_dcursor_intersect_next(&cursor_a, &cursor_b) == &item2);
	TEST_CHECK(test_dcursor_intersect_next(&cursor_a, &cursor_b) == &item3);
	TEST_CHECK(test_dcursor_intersect_next(&cursor_a, &cursor_b) == NULL);
}

static void test_intersect_iterator_a(void)
{
	FR_DCURSOR(test_dcursor)	cursor_a, cursor_b;

	test_item_t			item1 = { "actor", { { NULL, NULL } } };
	test_item_t			item2 = { "alter", { { NULL, NULL } } };
	test_item_t			item3 = { "extra", { { NULL, NULL } } };
	test_item_t			item4 = { "after", { { NULL, NULL } } };
	FR_DLIST_HEAD(test_list)	list;
	item_filter			filter_a = { 0, 'a' };

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);
	test_list_insert_tail(&list, &item4);

	test_dcursor_iter_init(&cursor_a, &list, iter_name_check, NULL, &filter_a);
	test_dcursor_init(&cursor_b, &list);

	TEST_CHECK(test_dcursor_intersect_head(&cursor_a, &cursor_b) == &item1);
	TEST_CHECK(test_dcursor_intersect_next(&cursor_a, &cursor_b) == &item2);
	TEST_CHECK(test_dcursor_intersect_next(&cursor_a, &cursor_b) == &item4);
	TEST_CHECK(test_dcursor_intersect_next(&cursor_a, &cursor_b) == NULL);
}

static void test_intersect_iterator_b(void)
{
	FR_DCURSOR(test_dcursor)	cursor_a, cursor_b;

	test_item_t			item1 = { "blink", { { NULL, NULL } } };
	test_item_t			item2 = { "alter", { { NULL, NULL } } };
	test_item_t			item3 = { "basic", { { NULL, NULL } } };
	test_item_t			item4 = { "bland", { { NULL, NULL } } };
	FR_DLIST_HEAD(test_list)	list;
	item_filter			filter_b = { 0, 'b'};

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);
	test_list_insert_tail(&list, &item4);

	test_dcursor_init(&cursor_a, &list);
	test_dcursor_iter_init(&cursor_b, &list, iter_name_check, NULL, &filter_b);

	TEST_CHECK(test_dcursor_intersect_head(&cursor_a, &cursor_b) == &item1);
	TEST_CHECK(test_dcursor_intersect_next(&cursor_a, &cursor_b) == &item3);
	TEST_CHECK(test_dcursor_intersect_next(&cursor_a, &cursor_b) == &item4);
}

static void test_intersect_iterator_ab(void)
{
	FR_DCURSOR(test_dcursor)	cursor_a, cursor_b;

	test_item_t			item1 = { "baits", { { NULL, NULL } } };
	test_item_t			item2 = { "alter", { { NULL, NULL } } };
	test_item_t			item3 = { "basic", { { NULL, NULL } } };
	test_item_t			item4 = { "cavil", { { NULL, NULL } } };
	test_item_t			item5 = { "bland", { { NULL, NULL } } };
	FR_DLIST_HEAD(test_list)	list;
	item_filter			filter_a = { 1, 'a' };
	item_filter			filter_b = { 0, 'b' };

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);
	test_list_insert_tail(&list, &item4);
	test_list_insert_tail(&list, &item5);

	test_dcursor_iter_init(&cursor_a, &list, iter_name_check, NULL, &filter_a);
	test_dcursor_iter_init(&cursor_b, &list, iter_name_check, NULL, &filter_b);

	TEST_CHECK(test_dcursor_intersect_head(&cursor_a, &cursor_b) == &item1);
	TEST_CHECK(test_dcursor_intersect_next(&cursor_a, &cursor_b) == &item3);
	TEST_MSG("Expected %s", item3.name);
	TEST_MSG("Current %s", test_dcursor_current(&cursor_a)->name);
	TEST_CHECK(test_dcursor_intersect_next(&cursor_a, &cursor_b) == NULL);
}

static void test_intersect_iterator_disjoint(void)
{
	FR_DCURSOR(test_dcursor)	cursor_a, cursor_b;

	test_item_t			item1 = { "baits", { { NULL, NULL } } };
	test_item_t			item2 = { "alter", { { NULL, NULL } } };
	test_item_t			item3 = { "basic", { { NULL, NULL } } };
	test_item_t			item4 = { "cavil", { { NULL, NULL } } };
	test_item_t			item5 = { "bland", { { NULL, NULL } } };
	FR_DLIST_HEAD(test_list)	list;
	item_filter			filter_a = { 0, 'a' };
	item_filter			filter_b = { 0, 'b' };

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);
	test_list_insert_tail(&list, &item4);
	test_list_insert_tail(&list, &item5);

	test_dcursor_iter_init(&cursor_a, &list, iter_name_check, NULL, &filter_a);
	test_dcursor_iter_init(&cursor_b, &list, iter_name_check, NULL, &filter_b);

	TEST_CHECK(test_dcursor_intersect_head(&cursor_a, &cursor_b) == NULL);
}

static bool eval_eq(test_item_t const *item, void const *uctx)
{
	char const	*s = uctx;
	return strcmp(item->name, s) == 0;
}

static void test_filter_head_next(void)
{
	FR_DCURSOR(test_dcursor)	cursor;

	test_item_t			item1 = { "yes", { { NULL, NULL } } };
	test_item_t			item2 = { "no", { { NULL, NULL } } };
	test_item_t			item3 = { "yes", { { NULL, NULL } } };
	test_item_t			item4 = { "no", { { NULL, NULL } } };
	test_item_t			item5 = { "yes", { { NULL, NULL } } };
	test_item_t			item6 = { "no", { { NULL, NULL } } };
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);
	test_list_insert_tail(&list, &item4);
	test_list_insert_tail(&list, &item5);
	test_list_insert_tail(&list, &item6);

	test_dcursor_init(&cursor, &list);

	TEST_CHECK(test_dcursor_filter_head(&cursor, eval_eq, "yes") == &item1);
	TEST_CHECK(test_dcursor_filter_next(&cursor, eval_eq, "yes") == &item3);
	TEST_CHECK(test_dcursor_filter_next(&cursor, eval_eq, "yes") == &item5);
	TEST_CHECK(test_dcursor_filter_next(&cursor, eval_eq, "yes") == NULL);
}

static void test_filter_current(void)
{
	FR_DCURSOR(test_dcursor)	cursor;

	test_item_t			item1 = { "yes", { { NULL, NULL } } };
	test_item_t			item2 = { "no", { { NULL, NULL } } };
	test_item_t			item3 = { "yes", { { NULL, NULL } } };
	test_item_t			item4 = { "no", { { NULL, NULL } } };
	test_item_t			item5 = { "yes", { { NULL, NULL } } };
	test_item_t			item6 = { "no", { { NULL, NULL } } };
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);
	test_list_insert_tail(&list, &item4);
	test_list_insert_tail(&list, &item5);
	test_list_insert_tail(&list, &item6);

	test_dcursor_init(&cursor, &list);

	TEST_CHECK(test_dcursor_filter_current(&cursor, eval_eq, "yes") == &item1);
	test_dcursor_next(&cursor);
	TEST_CHECK(test_dcursor_filter_current(&cursor, eval_eq, "yes") == &item3);
	test_dcursor_next(&cursor);
	TEST_CHECK(test_dcursor_filter_current(&cursor, eval_eq, "yes") == &item5);
	test_dcursor_next(&cursor);
	TEST_CHECK(test_dcursor_filter_current(&cursor, eval_eq, "yes") == NULL);
}

static void test_filter_no_match(void)
{
	FR_DCURSOR(test_dcursor)	cursor;

	test_item_t			item1 = { "yes", { { NULL, NULL } } };
	test_item_t			item2 = { "no", { { NULL, NULL } } };
	test_item_t			item3 = { "yes", { { NULL, NULL } } };
	test_item_t			item4 = { "no", { { NULL, NULL } } };
	test_item_t			item5 = { "yes", { { NULL, NULL } } };
	test_item_t			item6 = { "no", { { NULL, NULL } } };
	FR_DLIST_HEAD(test_list)	list;

	test_list_init(&list);
	test_list_insert_tail(&list, &item1);
	test_list_insert_tail(&list, &item2);
	test_list_insert_tail(&list, &item3);
	test_list_insert_tail(&list, &item4);
	test_list_insert_tail(&list, &item5);
	test_list_insert_tail(&list, &item6);

	test_dcursor_init(&cursor, &list);

	TEST_CHECK(test_dcursor_filter_current(&cursor, eval_eq, "maybe") == NULL);
}

TEST_LIST = {
	/*
	 *	Initialisation
	 */
	{ "init_null",		test_init_null_item },
	{ "init_one",		test_init_1i_start },
	{ "init_two",		test_init_2i_start },

	/*
	 *	Normal iteration
	 */
	{ "next",		test_next },
	{ "next_wrap",		test_next_wrap },

	/*
	 *	Jump to head/tail
	 */
	{ "head_tail_null",	test_dcursor_head_tail_null },
	{ "head",		test_dcursor_test_head },
	{ "head_resest",	test_dcursor_head_reset },
	{ "head_iter_reset",	test_dcursor_iter_head_reset },
	{ "head_after_next",	test_dcursor_head_after_next },
	{ "tail",		test_dcursor_test_tail },
	{ "head_after_tail",	test_dcursor_head_after_tail },
	{ "wrap_after_tail",	test_dcursor_wrap_after_tail },

	/*
	 *	Insert with empty list
	 */
	{ "append_empty",	test_dcursor_append_empty },
	{ "append_empty_3",	test_dcursor_append_empty_3 },
	{ "prepend_empty",	test_dcursor_prepend_empty },
	{ "prepend_empty_3",	test_dcursor_prepend_empty_3 },
	{ "insert_empty",	test_dcursor_insert_into_empty },
	{ "insert_empty_3",	test_dcursor_insert_into_empty_3 },
	{ "replace_empty",	test_dcursor_replace_in_empty },

	/*
	 *	Insert with one item list
	 */
	{ "prepend_1i_start",	test_dcursor_prepend_1i_start },
	{ "append_1i_start",	test_dcursor_append_1i_start },
	{ "insert_1i_start",	test_dcursor_insert_1i_start },
	{ "replace_li_start",	test_dcursor_replace_1i_start },

	/*
	 *	Insert with two item list
	 */
	{ "prepend_2i_start",	test_dcursor_prepend_2i_start },
	{ "append_2i_start",	test_dcursor_append_2i_start },
	{ "insert_2i_start",	test_dcursor_insert_2i_start },
	{ "replace_2i_start",	test_dcursor_replace_2i_start },

	/*
	 *	Insert with three item list (with cursor on item2)
	 */
	{ "prepend_3i_mid",	test_dcursor_prepend_3i_mid },
	{ "append_3i_mid",	test_dcursor_append_3i_mid },
	{ "insert_3i_mid",	test_dcursor_insert_3i_mid },
	{ "replace_3i_mid",	test_dcursor_replace_3i_mid },

	/*
	 *	Insert with three item list (with cursor on item3)
	 */
	{ "prepend_3i_end",	test_dcursor_prepend_3i_end },
	{ "append_3i_end",	test_dcursor_append_3i_end },
	{ "insert_3i_end",	test_dcursor_insert_3i_end },
	{ "replace_3i_end",	test_dcursor_replace_3i_end },

	/*
	 *	Remove
	 */
	{ "remove_empty",	test_dcursor_remove_empty },
	{ "remove_1i",		test_dcursor_remove_1i },
	{ "remove_2i",		test_dcursor_remove_2i },
	{ "remove_3i_start",	test_dcursor_remove_3i_start },
	{ "remove_3i_mid",	test_dcursor_remove_3i_mid },
	{ "remove_3i_end",	test_dcursor_remove_3i_end },

	/*
	 *	Merge
	 */
	{ "merge_start_a_b",	test_dcursor_merge_start_a_b },
	{ "merge_mid_a",	test_dcursor_merge_mid_a },
	{ "merge_end_a",	test_dcursor_merge_end_a },
	{ "merge_mid_b",	test_dcursor_merge_mid_b },
	{ "merge_end_b",	test_dcursor_merge_end_b },
	{ "merge_with_empty",	test_dcursor_merge_with_empty },
	{ "merge_empty",	test_dcursor_merge_empty },

	/*
	 *	Copy
	 */
	{ "copy",		test_dcursor_copy_test },

	/*
	 *	Free
	 */
	{ "free_list",		test_dcursor_free_by_list },
	{ "free_item",		test_dcursor_free_by_item },

	/*
	 * 	Intersect
	 */
	{ "differing_lists",	test_intersect_differing_lists },
	{ "no_iterators",	test_intersect_no_iterators },
	{ "iterator_a",		test_intersect_iterator_a },
	{ "iterator_b",		test_intersect_iterator_b },
	{ "iterator_ab",	test_intersect_iterator_ab },
	{ "iterator_disjoint",	test_intersect_iterator_disjoint },

	/*
	 * 	Filter
	 */
	{ "head_next",		test_filter_head_next },
	{ "current",		test_filter_current },
	{ "no_match",		test_filter_no_match },

	TEST_TERMINATOR
};
