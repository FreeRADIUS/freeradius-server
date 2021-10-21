#include <freeradius-devel/util/acutest.h>

#include "cursor.c"

typedef struct {
	char const *name;
	void *next;
} test_item_t;

static void *test_iter(UNUSED void **prev, void *current, UNUSED void *uctx)
{
	return current;
}

/** Verify internal state is initialised correctly
 *
 */
static void test_init_null_item(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	*head = NULL;

	item_p = fr_cursor_iter_init(&cursor, &head, test_iter, &cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK((*cursor.head) == head);
	TEST_CHECK(!cursor.tail);
	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
	TEST_CHECK(!fr_cursor_list_next_peek(&cursor));
	TEST_CHECK(cursor.uctx == &cursor);
}

static void test_init_1i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	item_p = fr_cursor_init(&cursor, &head);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK((*cursor.head) == head);
	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
}

static void test_init_2i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	item_p = fr_cursor_init(&cursor, &head);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
}

static void test_next(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item2);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_current(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);
}

static void test_next_wrap(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(!fr_cursor_next_peek(&cursor));

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(!fr_cursor_next_peek(&cursor));
}

static void test_cursor_head_tail_null(void)
{
	fr_cursor_t	cursor;
	test_item_t	*head = NULL;

	fr_cursor_init(&cursor, &head);
	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(!fr_cursor_head(&cursor));
	TEST_CHECK(!fr_cursor_tail(&cursor));
}

static void test_cursor_head(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
}

static void test_cursor_head_after_next(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
}

static void test_cursor_tail(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);
}

static void test_cursor_head_after_tail(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_tail(&cursor);
	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
}

static void test_cursor_wrap_after_tail(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_tail(&cursor);
	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);
}

static void test_cursor_append_empty(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*head = NULL;

	fr_cursor_init(&cursor, &head);
	fr_cursor_append(&cursor, &item1);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item1);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == NULL);
}

static void test_cursor_append_empty_3(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*head = NULL;

	fr_cursor_init(&cursor, &head);
	fr_cursor_append(&cursor, &item1);
	fr_cursor_append(&cursor, &item2);
	fr_cursor_append(&cursor, &item3);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_next(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next(&cursor) == &item2);
	TEST_CHECK(fr_cursor_tail(&cursor) == &item3);
}

static void test_cursor_prepend_empty(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*head = NULL;

	fr_cursor_init(&cursor, &head);
	fr_cursor_prepend(&cursor, &item1);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item1);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == NULL);
}

static void test_cursor_insert_into_empty(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*head = NULL;

	fr_cursor_init(&cursor, &head);
	fr_cursor_insert(&cursor, &item1);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item1);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == NULL);
}

static void test_cursor_insert_into_empty_3(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*head = NULL;

	fr_cursor_init(&cursor, &head);
	fr_cursor_insert(&cursor, &item1);
	fr_cursor_insert(&cursor, &item2);
	fr_cursor_insert(&cursor, &item3);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_next(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next(&cursor) == &item2);
	TEST_CHECK(fr_cursor_tail(&cursor) == &item3);
}

static void test_cursor_replace_in_empty(void)
{
	fr_cursor_t	cursor;
	test_item_t	*item_p;
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*head = NULL;

	fr_cursor_init(&cursor, &head);
	TEST_CHECK(!fr_cursor_replace(&cursor, &item1));

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item1);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == NULL);
}

static void test_cursor_prepend_1i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_prepend(&cursor, &item2);

	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);	/* Inserted before item 1 */

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item2);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item1);
}

static void test_cursor_append_1i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_append(&cursor, &item2);

	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

static void test_cursor_insert_1i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_insert(&cursor, &item2);

	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

static void test_cursor_replace_1i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	item_p = fr_cursor_replace(&cursor, &item2);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(item_p == &item2);

	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item2);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

static void test_cursor_prepend_2i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_prepend(&cursor, &item3);

	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item2);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item3);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

static void test_cursor_append_2i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_append(&cursor, &item3);

	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

static void test_cursor_insert_2i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_insert(&cursor, &item3);

	/*
	 *	Order should be
	 *
	 *	item1 -	HEAD
	 *	item3
	 *	item2 - TAIL
	 */
	TEST_CHECK(fr_cursor_current(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item3);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

static void test_cursor_replace_2i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	/*
	 *	Order should be
	 *
	 *	item3 -	HEAD
	 *	item2 - TAIL
	 */
	fr_cursor_init(&cursor, &head);
	item_p = fr_cursor_replace(&cursor, &item3);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(item_p == &item3);

	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item3);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item2);
}

static void test_cursor_prepend_3i_mid(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	fr_cursor_prepend(&cursor, &item4);

	TEST_CHECK(fr_cursor_current(&cursor) == &item2);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item4);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

static void test_cursor_append_3i_mid(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	fr_cursor_append(&cursor, &item4);

	TEST_CHECK(fr_cursor_current(&cursor) == &item2);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item4);
}

static void test_cursor_insert_3i_mid(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	fr_cursor_insert(&cursor, &item4);

	TEST_CHECK(fr_cursor_current(&cursor) == &item2);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item4);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item4);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item4);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

static void test_cursor_replace_3i_mid(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	item_p = fr_cursor_replace(&cursor, &item4);
	TEST_CHECK(item_p == &item2);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(item_p == &item4);

	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item3);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

static void test_cursor_prepend_3i_end(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	fr_cursor_next(&cursor);
	fr_cursor_prepend(&cursor, &item4);

	TEST_CHECK(fr_cursor_current(&cursor) == &item3);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item4);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item3);
}

static void test_cursor_append_3i_end(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	fr_cursor_next(&cursor);
	fr_cursor_append(&cursor, &item4);

	TEST_CHECK(fr_cursor_current(&cursor) == &item3);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item4);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item4);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item4);
}

static void test_cursor_insert_3i_end(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	fr_cursor_next(&cursor);
	fr_cursor_insert(&cursor, &item4);

	TEST_CHECK(fr_cursor_current(&cursor) == &item3);
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item4);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(item_p == &item4);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item3);

	item_p = fr_cursor_next(&cursor);
	TEST_CHECK(!item_p);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item4);

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item4);
}

static void test_cursor_replace_3i_end(void)
{
	fr_cursor_t	cursor;
	test_item_t	item4 = { "item4", NULL };
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);
	fr_cursor_next(&cursor);
	item_p = fr_cursor_replace(&cursor, &item4);
	TEST_CHECK(item_p == &item3);

	item_p = fr_cursor_current(&cursor);
	TEST_CHECK(item_p == &item4);

	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));

	item_p = fr_cursor_head(&cursor);
	TEST_CHECK(item_p == &item1);

	item_p = fr_cursor_tail(&cursor);
	TEST_CHECK(item_p == &item4);
}

static void test_cursor_remove_empty(void)
{
	fr_cursor_t	cursor;
	test_item_t	*head = NULL;

	_fr_cursor_init(&cursor, (void **)&head, offsetof(test_item_t, next), test_iter, &cursor, NULL);
	TEST_CHECK(!fr_cursor_remove(&cursor));
}

static void test_cursor_remove_1i(void)
{
	fr_cursor_t	cursor;
	test_item_t	item1 = { "item1", NULL };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item1);

	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
	TEST_CHECK(!fr_cursor_next(&cursor));
	TEST_CHECK(!fr_cursor_tail(&cursor));
	TEST_CHECK(!fr_cursor_head(&cursor));
}

static void test_cursor_remove_2i(void)
{
	fr_cursor_t	cursor;
	test_item_t	item2 = { "item2", NULL };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	item_p = fr_cursor_remove(&cursor);

	TEST_CHECK(item_p == &item1);
	TEST_CHECK(fr_cursor_current(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
	TEST_CHECK(!fr_cursor_next(&cursor));
	TEST_CHECK(fr_cursor_tail(&cursor) == &item2);
	TEST_CHECK(fr_cursor_head(&cursor) == &item2);

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item2);

	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
	TEST_CHECK(!fr_cursor_next(&cursor));
	TEST_CHECK(!fr_cursor_tail(&cursor));
	TEST_CHECK(!fr_cursor_head(&cursor));
}

static void test_cursor_remove_3i_start(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item1);
	TEST_CHECK(fr_cursor_current(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
	TEST_CHECK(fr_cursor_next_peek(&cursor) == &item3);

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_current(&cursor) == &item3);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
	TEST_CHECK(!fr_cursor_next_peek(&cursor));

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item3);

	TEST_CHECK(!fr_cursor_tail(&cursor));
	TEST_CHECK(!fr_cursor_head(&cursor));
}

static void test_cursor_remove_3i_mid(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_next(&cursor);

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item2);
	TEST_CHECK(fr_cursor_current(&cursor) == &item3);
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item3);

	/*
	 *	We just removed the end of the list
	 *	so current is now NULL.
	 *
	 *	We don't implicitly start moving backwards.
	 */
	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item1);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(!item_p);

	TEST_CHECK(fr_cursor_tail(&cursor) == &item1);
	TEST_CHECK(fr_cursor_head(&cursor) == &item1);
}

static void test_cursor_remove_3i_end(void)
{
	fr_cursor_t	cursor;
	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*item_p;
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);
	fr_cursor_tail(&cursor);

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(item_p == &item3);
	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));

	item_p = fr_cursor_remove(&cursor);
	TEST_CHECK(!item_p);

	TEST_CHECK(!fr_cursor_current(&cursor));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor) == &item2);
	TEST_CHECK(!fr_cursor_next_peek(&cursor));
}

static void test_cursor_merge_start_a_b(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3b = { "item3b", NULL };
	test_item_t	item2b = { "item2b", &item3b };
	test_item_t	item1b = { "item1b", &item2b };

	test_item_t	item3a = { "item3a", NULL };
	test_item_t	item2a = { "item2a", &item3a };
	test_item_t	item1a = { "item1a", &item2a };

	test_item_t	*head_a = &item1a;
	test_item_t	*head_b = &item1b;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);
	fr_cursor_merge(&cursor_a, &cursor_b);

	/*
	 *	First item in cursor_a remains unchanged
	 *
	 *	The insertion point into cursor_a is
	 *	directly after the current item.
	 */
	TEST_CHECK(fr_cursor_current(&cursor_a) == &item1a);
	TEST_MSG("Expected %s", item1a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Next three items should be from cursor_b
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item1b);
	TEST_MSG("Expected %s", item1b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2b);
	TEST_MSG("Expected %s", item2b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	With the final two from cursor_a
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2a);
	TEST_MSG("Expected %s", item2a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(!fr_cursor_next(&cursor_a));

	TEST_CHECK(!fr_cursor_current(&cursor_b));
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor_b));
	TEST_CHECK(!fr_cursor_list_next_peek(&cursor_b));
}

static void test_cursor_merge_mid_a(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3b = { "item3b", NULL };
	test_item_t	item2b = { "item2b", &item3b };
	test_item_t	item1b = { "item1b", &item2b };

	test_item_t	item3a = { "item3a", NULL };
	test_item_t	item2a = { "item2a", &item3a };
	test_item_t	item1a = { "item1a", &item2a };

	test_item_t	*head_a = &item1a;
	test_item_t	*head_b = &item1b;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);
	fr_cursor_next(&cursor_a);
	fr_cursor_merge(&cursor_a, &cursor_b);

	/*
	 *	Should be second item in cursor a
	 */
	TEST_CHECK(fr_cursor_current(&cursor_a) == &item2a);
	TEST_MSG("Expected %s", item2a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Next three items should be from cursor_b
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item1b);
	TEST_MSG("Expected %s", item1b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2b);
	TEST_MSG("Expected %s", item2b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Final item should be from cursor a
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(!fr_cursor_next(&cursor_a));

	TEST_CHECK(!fr_cursor_current(&cursor_b));
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor_b));
	TEST_CHECK(!fr_cursor_list_next_peek(&cursor_b));
}

static void test_cursor_merge_end_a(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3b = { "item3b", NULL };
	test_item_t	item2b = { "item2b", &item3b };
	test_item_t	item1b = { "item1b", &item2b };

	test_item_t	item3a = { "item3a", NULL };
	test_item_t	item2a = { "item2a", &item3a };
	test_item_t	item1a = { "item1a", &item2a };

	test_item_t	*head_a = &item1a;
	test_item_t	*head_b = &item1b;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);
	fr_cursor_tail(&cursor_a);
	fr_cursor_merge(&cursor_a, &cursor_b);

	/*
	 *	Should be final item in cursor_a
	 */
	TEST_CHECK(fr_cursor_current(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Next three items should be from cursor_b
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item1b);
	TEST_MSG("Expected %s", item1b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2b);
	TEST_MSG("Expected %s", item2b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Should be no more items...
	 */
	TEST_CHECK(!fr_cursor_list_next_peek(&cursor_a));
	TEST_CHECK(!fr_cursor_current(&cursor_b));
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor_b));
	TEST_CHECK(!fr_cursor_list_next_peek(&cursor_b));
}

static void test_cursor_merge_mid_b(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3b = { "item3b", NULL };
	test_item_t	item2b = { "item2b", &item3b };
	test_item_t	item1b = { "item1b", &item2b };

	test_item_t	item3a = { "item3a", NULL };
	test_item_t	item2a = { "item2a", &item3a };
	test_item_t	item1a = { "item1a", &item2a };

	test_item_t	*head_a = &item1a;
	test_item_t	*head_b = &item1b;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);
	fr_cursor_next(&cursor_b);
	fr_cursor_merge(&cursor_a, &cursor_b);

	/*
	 *	First item in cursor_a remains unchanged
	 *
	 *	The insertion point into cursor_a is
	 *	directly after the current item.
	 */
	TEST_CHECK(fr_cursor_current(&cursor_a) == &item1a);
	TEST_MSG("Expected %s", item1a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Next two items should be from cursor_b
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2b);
	TEST_MSG("Expected %s", item2b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Next two items should be from cursor_a
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2a);
	TEST_MSG("Expected %s", item2a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(!fr_cursor_next(&cursor_a));

	TEST_CHECK(!fr_cursor_current(&cursor_b));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor_b) == &item1b);
	TEST_CHECK(!fr_cursor_list_next_peek(&cursor_b));
}

static void test_cursor_merge_end_b(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3b = { "item3b", NULL };
	test_item_t	item2b = { "item2b", &item3b };
	test_item_t	item1b = { "item1b", &item2b };

	test_item_t	item3a = { "item3a", NULL };
	test_item_t	item2a = { "item2a", &item3a };
	test_item_t	item1a = { "item1a", &item2a };

	test_item_t	*head_a = &item1a;
	test_item_t	*head_b = &item1b;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);
	fr_cursor_next(&cursor_b);
	fr_cursor_next(&cursor_b);
	fr_cursor_merge(&cursor_a, &cursor_b);

	/*
	 *	First item in cursor_a remains unchanged
	 *
	 *	The insertion point into cursor_a is
	 *	directly after the current item.
	 */
	TEST_CHECK(fr_cursor_current(&cursor_a) == &item1a);
	TEST_MSG("Expected %s", item1a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);

	/*
	 *	Next item should be from cursor_b
	 */
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3b);
	TEST_MSG("Expected %s", item3b.name);

	/*
	 *	Next two items should be from cursor_a
	 */
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2a);
	TEST_MSG("Expected %s", item2a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3a);
	TEST_MSG("Expected %s", item3a.name);
	TEST_MSG("Got %s", ((test_item_t *)fr_cursor_current(&cursor_a))->name);
	TEST_CHECK(!fr_cursor_next(&cursor_a));

	TEST_CHECK(!fr_cursor_current(&cursor_b));
	TEST_CHECK(fr_cursor_list_prev_peek(&cursor_b) == &item2b);
	TEST_CHECK(fr_cursor_head(&cursor_b) == &item1b);
}

static void test_cursor_merge_with_empty(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3b = { "item3b", NULL };
	test_item_t	item2b = { "item2b", &item3b };
	test_item_t	item1b = { "item1b", &item2b };

	test_item_t	*head_a = NULL;
	test_item_t	*head_b = &item1b;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);
	fr_cursor_merge(&cursor_a, &cursor_b);

	TEST_CHECK(fr_cursor_head(&cursor_a) == &item1b);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2b);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3b);

	TEST_CHECK(!fr_cursor_current(&cursor_b));
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor_b));
	TEST_CHECK(!fr_cursor_list_next_peek(&cursor_b));
}

static void test_cursor_merge_empty(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3a = { "item3a", NULL };
	test_item_t	item2a = { "item2a", &item3a };
	test_item_t	item1a = { "item1a", &item2a };

	test_item_t	*head_a = &item1a;
	test_item_t	*head_b = NULL;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);
	fr_cursor_merge(&cursor_a, &cursor_b);

	TEST_CHECK(fr_cursor_head(&cursor_a) == &item1a);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item2a);
	TEST_CHECK(fr_cursor_next(&cursor_a) == &item3a);
}

static void test_cursor_copy(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };

	test_item_t	*head = &item1;

	fr_cursor_init(&cursor_a, &head);
	fr_cursor_copy(&cursor_b, &cursor_a);

	TEST_CHECK(fr_cursor_head(&cursor_b) == &item1);
	TEST_CHECK(fr_cursor_next(&cursor_b) == &item2);
	TEST_CHECK(fr_cursor_next(&cursor_b) == &item3);
}

static void test_cursor_free(void)
{
	test_item_t	*item1, *item2, *item3;
	test_item_t	*head = NULL;
	fr_cursor_t	cursor;
	void		*item_p;

	item1 = talloc_zero(NULL, test_item_t);
	item2 = talloc_zero(NULL, test_item_t);
	item3 = talloc_zero(NULL, test_item_t);

	fr_cursor_init(&cursor, &head);
	fr_cursor_append(&cursor, item1);
	fr_cursor_append(&cursor, item2);
	fr_cursor_append(&cursor, item3);

	fr_cursor_next(&cursor);
	fr_cursor_free_list(&cursor);

	TEST_CHECK(fr_cursor_current(&cursor) == NULL);
	TEST_CHECK(!fr_cursor_list_prev_peek(&cursor));
	TEST_CHECK(!fr_cursor_tail(&cursor));
	TEST_CHECK(!fr_cursor_head(&cursor));

	item_p = fr_cursor_remove(&cursor);
	talloc_free(item_p);
}

typedef struct {
	int	pos;
	char	val;
} item_filter;

static void *iter_name_check(void **prev, void *to_eval, void *uctx)
{
	test_item_t	*c, *p;
	item_filter	*f = uctx;

	if (!to_eval) return NULL;

	for (p = *prev, c = to_eval; c; p = c, c = c->next) {
		if (c->name[f->pos] == f->val) break;
	}

	*prev = p;

	return c;
}

static void test_intersect_differing_lists(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item2 = {"item2", NULL};
	test_item_t	item1 = {"item1", NULL};
	test_item_t	*head_a = &item1;
	test_item_t	*head_b = &item2;

	fr_cursor_init(&cursor_a, &head_a);
	fr_cursor_init(&cursor_b, &head_b);

	TEST_CHECK(fr_cursor_intersect_head(&cursor_a, &cursor_b) == NULL);
}

static void test_intersect_no_iterators(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item3 = { "item3", NULL };
	test_item_t	item2 = { "item2", &item3 };
	test_item_t	item1 = { "item1", &item2 };
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor_a, &head);
	fr_cursor_init(&cursor_b, &head);

	TEST_CHECK(fr_cursor_intersect_head(&cursor_a, &cursor_b) == &item1);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == &item2);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == &item3);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == NULL);
}

static void test_intersect_iterator_a(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item4 = { "after", NULL };
	test_item_t	item3 = { "extra", &item4 };
	test_item_t	item2 = { "alter", &item3 };
	test_item_t	item1 = { "actor", &item2 };
	test_item_t	*head = &item1;
	item_filter	filter_a = { 0, 'a' };

	fr_cursor_iter_init(&cursor_a, &head, iter_name_check, &filter_a);
	fr_cursor_init(&cursor_b, &head);

	TEST_CHECK(fr_cursor_intersect_head(&cursor_a, &cursor_b) == &item1);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == &item2);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == &item4);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == NULL);
}

static void test_intersect_iterator_b(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item4 = { "bland", NULL };
	test_item_t	item3 = { "basic", &item4 };
	test_item_t	item2 = { "alter", &item3 };
	test_item_t	item1 = { "blink", &item2 };
	test_item_t	*head = &item1;
	item_filter	filter_b = { 0, 'b'};

	fr_cursor_init(&cursor_a, &head);
	fr_cursor_iter_init(&cursor_b, &head, iter_name_check, &filter_b);

	TEST_CHECK(fr_cursor_intersect_head(&cursor_a, &cursor_b) == &item1);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == &item3);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == &item4);
}

static void test_intersect_iterator_ab(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item5 = { "bland", NULL };
	test_item_t	item4 = { "cavil", &item5 };
	test_item_t	item3 = { "basic", &item4 };
	test_item_t	item2 = { "alter", &item3 };
	test_item_t	item1 = { "baits", &item2 };
	test_item_t	*head = &item1;
	item_filter	filter_a = { 1, 'a' };
	item_filter	filter_b = { 0, 'b' };

	fr_cursor_iter_init(&cursor_a, &head, iter_name_check, &filter_a);
	fr_cursor_iter_init(&cursor_b, &head, iter_name_check, &filter_b);

	TEST_CHECK(fr_cursor_intersect_head(&cursor_a, &cursor_b) == &item1);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == &item3);
	TEST_CHECK(fr_cursor_intersect_next(&cursor_a, &cursor_b) == NULL);
}

static void test_intersect_iterator_disjoint(void)
{
	fr_cursor_t	cursor_a, cursor_b;

	test_item_t	item5 = { "bland", NULL };
	test_item_t	item4 = { "cavil", &item5 };
	test_item_t	item3 = { "basic", &item4 };
	test_item_t	item2 = { "alter", &item3 };
	test_item_t	item1 = { "baits", &item2 };
	test_item_t	*head = &item1;
	item_filter	filter_a = { 0, 'a' };
	item_filter	filter_b = { 0, 'b' };

	fr_cursor_iter_init(&cursor_a, &head, iter_name_check, &filter_a);
	fr_cursor_iter_init(&cursor_b, &head, iter_name_check, &filter_b);

	TEST_CHECK(fr_cursor_intersect_head(&cursor_a, &cursor_b) == NULL);
}

static bool eval_eq(void const *item, void const *uctx)
{
	test_item_t const	*t = item;
	char const		*s = uctx;

	return strcmp(t->name, s) == 0;
}

static void test_filter_head_next(void)
{
	fr_cursor_t	cursor;

	test_item_t	item6 = { "no", NULL };
	test_item_t	item5 = { "yes", &item6 };
	test_item_t	item4 = { "no", &item5};
	test_item_t	item3 = { "yes", &item4};
	test_item_t	item2 = { "no", &item3};
	test_item_t	item1 = { "yes", &item2};
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);

	TEST_CHECK(fr_cursor_filter_head(&cursor, eval_eq, "yes") == &item1);
	TEST_CHECK(fr_cursor_filter_next(&cursor, eval_eq, "yes") == &item3);
	TEST_CHECK(fr_cursor_filter_next(&cursor, eval_eq, "yes") == &item5);
	TEST_CHECK(fr_cursor_filter_next(&cursor, eval_eq, "yes") == NULL);
}

static void test_filter_current(void)
{
	fr_cursor_t	cursor;

	test_item_t	item6 = { "no", NULL };
	test_item_t	item5 = { "yes", &item6 };
	test_item_t	item4 = { "no", &item5};
	test_item_t	item3 = { "yes", &item4};
	test_item_t	item2 = { "no", &item3};
	test_item_t	item1 = { "yes", &item2};
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);

	TEST_CHECK(fr_cursor_filter_current(&cursor, eval_eq, "yes") == &item1);
	fr_cursor_next(&cursor);
	TEST_CHECK(fr_cursor_filter_current(&cursor, eval_eq, "yes") == &item3);
	fr_cursor_next(&cursor);
	TEST_CHECK(fr_cursor_filter_current(&cursor, eval_eq, "yes") == &item5);
	fr_cursor_next(&cursor);
	TEST_CHECK(fr_cursor_filter_current(&cursor, eval_eq, "yes") == NULL);
}

static void test_filter_no_match(void)
{
	fr_cursor_t	cursor;

	test_item_t	item6 = { "no", NULL };
	test_item_t	item5 = { "yes", &item6 };
	test_item_t	item4 = { "no", &item5};
	test_item_t	item3 = { "yes", &item4};
	test_item_t	item2 = { "no", &item3};
	test_item_t	item1 = { "yes", &item2};
	test_item_t	*head = &item1;

	fr_cursor_init(&cursor, &head);

	TEST_CHECK(fr_cursor_filter_current(&cursor, eval_eq, "maybe") == NULL);
}

TEST_LIST = {
	/*
	 *	Initialisation
	 */
	{ "init_null",			test_init_null_item },
	{ "init_one",			test_init_1i_start },
	{ "init_two",			test_init_2i_start },

	/*
	 *	Normal iteration
	 */
	{ "next",			test_next },
	{ "next_wrap",			test_next_wrap },	/* should not wrap */

	/*
	 *	Jump to head/tail
	 */
	{ "head_tail_null",		test_cursor_head_tail_null },
	{ "head",			test_cursor_head },
	{ "head_after_next",		test_cursor_head_after_next },
	{ "tail",			test_cursor_tail },
	{ "head_after_tail",		test_cursor_head_after_tail },
	{ "wrap_after_tail",		test_cursor_wrap_after_tail },

	/*
	 *	Insert with empty list
	 */
	{ "prepend_empty",		test_cursor_prepend_empty },
	{ "append_empty",		test_cursor_append_empty },
	{ "append_empty_3",		test_cursor_append_empty_3 },
	{ "insert_into_empty",		test_cursor_insert_into_empty },
	{ "insert_into_empty_3",	test_cursor_insert_into_empty_3 },
	{ "replace_in_empty",		test_cursor_replace_in_empty },

	/*
	 *	Insert with one item list
	 */
	{ "prepend_1i_start",		test_cursor_prepend_1i_start},
	{ "append_1i_start",		test_cursor_append_1i_start },
	{ "insert_1i_start",		test_cursor_insert_1i_start },
	{ "replace_1i_start",		test_cursor_replace_1i_start },

	/*
	 *	Insert with two item list
	 */
	{ "prepend_2i_start",		test_cursor_prepend_2i_start },
	{ "append_2i_start",		test_cursor_append_2i_start },
	{ "insert_2i_start",		test_cursor_insert_2i_start },
	{ "replace_2i_start",		test_cursor_replace_2i_start },

	/*
	 *	Insert with three item list (with cursor on item2)
	 */
	{ "prepend_3i_mid",		test_cursor_prepend_3i_mid },
	{ "append_3i_mid",		test_cursor_append_3i_mid },
	{ "insert_3i_mid",		test_cursor_insert_3i_mid },
	{ "replace_3i_mid",		test_cursor_replace_3i_mid },

	 /*
	  *	Insert with three item list (with cursor on item3)
	  */
	{ "prepend_3i_end",		test_cursor_prepend_3i_end },
	{ "append_3i_end",		test_cursor_append_3i_end },
	{ "insert_3i_end",		test_cursor_insert_3i_end },
	{ "replace_3i_end",		test_cursor_replace_3i_end },

	/*
	 *	Remove
	 */
	{ "remove_empty",		test_cursor_remove_empty },
	{ "remove_1i",			test_cursor_remove_1i },
	{ "remove_2i",			test_cursor_remove_2i },
	{ "remove_3i_start",		test_cursor_remove_3i_start },
	{ "remove_3i_mid",		test_cursor_remove_3i_mid },
	{ "remove_3i_end",		test_cursor_remove_3i_end },

	/*
	 *	Merge
	 */
	{ "merge_start_a_b",		test_cursor_merge_start_a_b },
	{ "merge_mid_a",		test_cursor_merge_mid_a },
	{ "merge_end_a",		test_cursor_merge_end_a },
	{ "merge_mid_b",		test_cursor_merge_mid_b },
	{ "merge_end_b",		test_cursor_merge_end_b },
	{ "merge_with_empty",		test_cursor_merge_with_empty },
	{ "merge_empty",		test_cursor_merge_empty },

	/*
	 *	Copy
	 */
	{ "copy",			test_cursor_copy },

	/*
	 *	Free
	 */
	{ "free", 			test_cursor_free },
	/*
	 * 	Intersect
	 */
	{ "differing_lists",		test_intersect_differing_lists },
	{ "no_iterators",		test_intersect_no_iterators },
	{ "iterator_a",			test_intersect_iterator_a },
	{ "iterator_b",			test_intersect_iterator_b },
	{ "iterator_ab",		test_intersect_iterator_ab },
	{ "iterator_disjoint",		test_intersect_iterator_disjoint },
	/*
	 * 	Filter
	 */
	{ "head_next",			test_filter_head_next },
	{ "current",			test_filter_current },
	{ "no_match",			test_filter_no_match },

	{ NULL }
};
