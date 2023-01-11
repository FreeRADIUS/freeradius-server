/** Tests for slab allocator
 *
 * @file src/lib/util/slab_tests.c
 *
 * @copyright 2023 Network RADIUS SARL <legal@networkradius.com>
 */
#include <freeradius-devel/util/acutest.h>
#include <freeradius-devel/util/acutest_helpers.h>

#include "slab.h"

typedef struct {
	int	num;
	char	*name;
} test_element_t;

typedef struct {
	int	count;
} test_uctx_t;

typedef struct {
	int	initial;
} test_conf_t;

static int test_element_free(test_element_t *elem, void *uctx)
{
	test_uctx_t	*test_uctx = uctx;
	test_uctx->count = strlen(elem->name);
	return 0;
}

static fr_time_t test_time_base = fr_time_wrap(1);
static fr_time_t test_time(void)
{
	return test_time_base;
}

FR_SLAB_TYPES(test, test_element_t);

FR_SLAB_FUNCS(test, test_element_t, fr_time_delta_from_sec(1));

/** Test basic allocation and reservation of elements
 *
 */
static void test_alloc(void)
{
	fr_test_slab_list_t	*test_slab_list;
	test_element_t		*test_elements[5];
	test_uctx_t		test_uctx, test_uctx2;
	int			ret = -1;

	/*
	 *	Each slab will contain 2 elements, maximum of 4 elements allocated from slabs.
	 */
	ret = fr_test_slab_list_alloc(NULL, &test_slab_list, NULL, 2, 1, 4, false, 0, 0, NULL, NULL, true, false);
	TEST_CHECK(ret == 0);
	TEST_CHECK(test_slab_list != NULL);

	test_elements[0] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[0] != NULL);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 1);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 1);

	test_uctx.count = 0;
	test_uctx2.count = 0;

	/* "if" to keep clang scan happy */
	if (test_elements[0]) test_elements[0]->name = talloc_strdup(test_elements[0], "Hello there");
	if (test_elements[0]) fr_test_element_t_slab_set_destructor(test_elements[0], test_element_free, &test_uctx);

	test_elements[1] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[1] != NULL);
	TEST_CHECK(test_elements[1] != test_elements[0]);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 1);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 2);

	/* This will cause a second slab to be allocated */
	test_elements[2] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[2] != NULL);
	if (test_elements[2]) test_elements[2]->name = talloc_strdup(test_elements[2], "Hello there testing");
	if (test_elements[2]) fr_test_element_t_slab_set_destructor(test_elements[2], test_element_free, &test_uctx2);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 2);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 3);

	test_elements[3] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[3] != NULL);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 2);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 4);

	/* This is more elements than max_elements */
	test_elements[4] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[4] != NULL);
	/* Allocations beyond the maximum do not amend the slab stats */
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 2);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 4);

	if (test_elements[0]) fr_test_slab_release(test_elements[0]);
	TEST_CHECK(test_uctx.count == 11);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 2);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 3);

	if (test_elements[1]) fr_test_slab_release(test_elements[1]);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 2);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 2);

	if (test_elements[2]) fr_test_slab_release(test_elements[2]);
	TEST_CHECK(test_uctx2.count == 19);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 2);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 1);

	talloc_free(test_slab_list);
}

/** Test allocation beyond max fails correctly
 *
 */
static void test_alloc_fail(void)
{
	fr_test_slab_list_t	*test_slab_list;
	test_element_t		*test_elements[5];
	int			ret = -1;

	/*
	 *	Each slab will contain 2 elements, maximum of 4 elements allocated from slabs.
	 */
	ret = fr_test_slab_list_alloc(NULL, &test_slab_list, NULL, 2, 1, 4, true, 0, 0, NULL, NULL, true, false);
	TEST_CHECK(ret == 0);
	TEST_CHECK(test_slab_list != NULL);

	test_elements[0] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[0] != NULL);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 1);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 1);

	test_elements[1] = fr_test_slab_reserve(test_slab_list);
	test_elements[2] = fr_test_slab_reserve(test_slab_list);
	test_elements[3] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[3] != NULL);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 2);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 4);

	/* This is more elements than max_elements */
	test_elements[4] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[4] == NULL);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 2);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 4);

	talloc_free(test_slab_list);
}

/** Test that freeing an element makes it available for reuse with the element reset between uses
 *
 */
static void test_reuse_reset(void)
{
	fr_test_slab_list_t	*test_slab_list;
	test_element_t		*test_elements[5];
	test_uctx_t		test_uctx;
	int			ret = -1;

	ret = fr_test_slab_list_alloc(NULL, &test_slab_list, NULL, 2, 1, 4, false, 0, 0, NULL, NULL, true, false);
	TEST_CHECK(ret == 0);
	TEST_CHECK(test_slab_list != NULL);

	test_elements[0] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[0] != NULL);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 1);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 1);

	test_uctx.count = 0;

	if (test_elements[0]) test_elements[0]->name = talloc_strdup(test_elements[0], "Hello there");
	if (test_elements[0]) fr_test_element_t_slab_set_destructor(test_elements[0], test_element_free, &test_uctx);

	test_elements[1] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[1] != NULL);
	TEST_CHECK(test_elements[1] != test_elements[0]);

	test_elements[2] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[2] != NULL);

	test_elements[3] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[3] != NULL);

	if (test_elements[0]) fr_test_slab_release(test_elements[0]);
	TEST_CHECK(test_uctx.count == 11);

	/*
	 *	Having released the first element allocated from a slab
	 *	reserving another should grab that first one again, but
	 *	with the entry memset to zero.
	 */
	test_elements[4] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[4] != NULL);
	TEST_CHECK(test_elements[4] == test_elements[0]);
	if (test_elements[4]) TEST_CHECK(test_elements[4]->name == NULL);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 2);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 4);

	/*
	 *	Releasing the first element should reset the destructor
	 *	so releasing this re-use of it will not update the result
	 *	of the initial release.
	 */
	if (test_elements[4]) test_elements[4]->name = talloc_strdup(test_elements[4], "Different length string");
	if (test_elements[4]) fr_test_slab_release(test_elements[4]);
	TEST_CHECK(test_uctx.count == 11);

	talloc_free(test_slab_list);
}

/** Test that freeing an element makes it available for reuse with the element not reset between uses
 *
 */
static void test_reuse_noreset(void)
{
	fr_test_slab_list_t	*test_slab_list;
	test_element_t		*test_elements[3];
	test_uctx_t		test_uctx;
	int			ret = -1;

	ret = fr_test_slab_list_alloc(NULL, &test_slab_list, NULL, 2, 1, 4, false, 0, 0, NULL, NULL, false, false);
	TEST_CHECK(ret == 0);
	TEST_CHECK(test_slab_list != NULL);

	test_elements[0] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[0] != NULL);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 1);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 1);

	test_uctx.count = 0;

	if (test_elements[0]) test_elements[0]->name = talloc_strdup(test_elements[0], "Hello there");
	if (test_elements[0]) fr_test_element_t_slab_set_destructor(test_elements[0], test_element_free, &test_uctx);

	test_elements[1] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[1] != NULL);
	TEST_CHECK(test_elements[1] != test_elements[0]);

	if (test_elements[0]) fr_test_slab_release(test_elements[0]);
	TEST_CHECK(test_uctx.count == 11);

	/*
	 *	Having released the first element allocated from a slab
	 *	reserving another should grab that first one again.
	 *	Since no reset was done, the element should be as it was before.
	 */
	test_elements[2] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[2] != NULL);
	TEST_CHECK(test_elements[2] == test_elements[0]);
	if (test_elements[0] && test_elements[2]) TEST_CHECK(test_elements[2]->name == test_elements[0]->name);

	/*
	 *	Replace the element's string so that the callback on relase has
	 *	a different string to work on.
	 */
	if (test_elements[2]) talloc_free(test_elements[2]->name);
	if (test_elements[2]) test_elements[2]->name = talloc_strdup(test_elements[2], "Different length string");
	if (test_elements[2]) fr_test_slab_release(test_elements[2]);
	TEST_CHECK(test_uctx.count == 23);

	talloc_free(test_slab_list);
}

/** Test that talloc freeing an element results in destructor being called
 *
 */
static void test_free(void)
{
	fr_test_slab_list_t	*test_slab_list;
	test_element_t		*test_element;
	test_uctx_t		test_uctx;
	int			ret = -1;

	ret = fr_test_slab_list_alloc(NULL, &test_slab_list, NULL, 2, 1, 4, false, 0, 0, NULL, NULL, true, false);
	TEST_CHECK(ret == 0);
	TEST_CHECK(test_slab_list != NULL);

	test_element = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_element != NULL);

	test_uctx.count = 0;

	if (test_element) test_element->name = talloc_strdup(test_element, "Hello there");
	if (test_element) fr_test_element_t_slab_set_destructor(test_element, test_element_free, &test_uctx);

	if (test_element) talloc_free(test_element);
	TEST_CHECK(test_uctx.count == 11);

	talloc_free(test_slab_list);
}

static int test_element_alloc(test_element_t *elem, void *uctx)
{
	test_conf_t	*test_conf = uctx;
	elem->num = test_conf->initial;
	return 0;
}

/** Test that a callback correctly initialises slab elements on first use
 *
 */
static void test_init_1(void)
{
	fr_test_slab_list_t	*test_slab_list;
	test_element_t		*test_elements[2];
	test_conf_t		test_conf = { .initial = 10 };
	int			ret = -1;

	ret = fr_test_slab_list_alloc(NULL, &test_slab_list, NULL, 1, 1, 4, false, 0, 0, test_element_alloc, &test_conf, false, false);
	TEST_CHECK(ret == 0);
	TEST_CHECK(test_slab_list != NULL);

	test_elements[0] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[0] != NULL);
	TEST_CHECK(test_elements[0] && (test_elements[0]->num == 10));

	/*
	 *	Change element data and release
	 */
	if (test_elements[0]) {
		test_elements[0]->num = 5;
		fr_test_slab_release(test_elements[0]);
	}

	/*
	 *	Slab set not to reset elements, nor re-init
	 *	Re-reserve and check element is unchanged.
	 */
	test_elements[1] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[1] != NULL);
	TEST_CHECK(test_elements[1] == test_elements[0]);
	if (test_elements[1]) TEST_CHECK(test_elements[1]->num == 5);

	talloc_free(test_slab_list);
}

/** Test that a callback correctly re-initialises slab elements on use
 *
 */
static void test_init_2(void)
{
	fr_test_slab_list_t	*test_slab_list;
	test_element_t		*test_elements[2];
	test_conf_t		test_conf = { .initial = 10 };
	int			ret = -1;

	ret = fr_test_slab_list_alloc(NULL, &test_slab_list, NULL, 1, 1, 4, false, 0, 0, test_element_alloc, &test_conf, false, true);
	TEST_CHECK(ret == 0);
	TEST_CHECK(test_slab_list != NULL);

	test_elements[0] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[0] != NULL);
	TEST_CHECK(test_elements[0] && (test_elements[0]->num == 10));

	/*
	 *	Change element data and release
	 */
	if (test_elements[0]) {
		test_elements[0]->num = 5;
		fr_test_slab_release(test_elements[0]);
	}

	/*
	 *	Slab set re-init
	 *	Re-reserve and check element is reinitialised.
	 */
	test_elements[1] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[1] != NULL);
	TEST_CHECK(test_elements[1] == test_elements[0]);
	if (test_elements[1]) TEST_CHECK(test_elements[1]->num == 10);

	talloc_free(test_slab_list);
}

/** Test of clearing unused slabs
 *
 */
static void test_clearup_1(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_event_list_t		*el;
	fr_test_slab_list_t	*test_slab_list;
	test_element_t		*test_elements[6];
	int			i, events, ret = -1;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	ret = fr_test_slab_list_alloc(NULL, &test_slab_list, el, 2, 1, 6, false, 0, 0, NULL, NULL, true, false);
	TEST_CHECK(ret == 0);

	/*
	 *	Allocate all the slab elements
	 */
	for (i = 0; i < 6; i++) {
		test_elements[i] = fr_test_slab_reserve(test_slab_list);
		TEST_CHECK(test_elements[i] != NULL);
	}
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 3);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 6);

	/*
	 *	Release four of the six elements
	 */
	for (i = 0; i < 4; i++) {
		fr_test_slab_release(test_elements[i]);
	}
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 3);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 2);

	/*
	 *	Running clearup should free one slab - half of the
	 *	difference between the high water mark and the in use count.
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(2));
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 1);
	fr_event_service(el);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 2);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 2);

	talloc_free(test_slab_list);
	talloc_free(ctx);
}

/** Test that slab clearing does not go beyond the minimum
 *
 */
static void test_clearup_2(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_event_list_t		*el;
	fr_test_slab_list_t	*test_slab_list;
	test_element_t		*test_elements[20];
	int			i, events, ret = -1;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	ret = fr_test_slab_list_alloc(NULL, &test_slab_list, el, 2, 16, 20, false, 0, 0, NULL, NULL, true, false);
	TEST_CHECK(ret == 0);

	/*
	 *	Allocate all the slab elements
	 */
	for (i = 0; i < 20; i++) {
		test_elements[i] = fr_test_slab_reserve(test_slab_list);
		TEST_CHECK(test_elements[i] != NULL);
	}
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 10);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 20);

	/*
	 *	Release all of the elements
	 */
	for (i = 0; i < 20; i++) {
		fr_test_slab_release(test_elements[i]);
	}
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 10);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 0);

	/*
	 *	Running clearup should free two slabs - the minimum element
	 *	count will keep the remainder allocated
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(2));
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 1);
	fr_event_service(el);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 8);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 0);

	/*
	 *	Re-run the event - no more slabs should be cleared
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(2));
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 1);
	fr_event_service(el);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 8);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 0);

	talloc_free(test_slab_list);
	talloc_free(ctx);
}

/** Test that repeated clearing frees more slabs
 *
 */
static void test_clearup_3(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_event_list_t		*el;
	fr_test_slab_list_t	*test_slab_list;
	test_element_t		*test_elements[20];
	int			i, events, ret = -1;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	ret = fr_test_slab_list_alloc(NULL, &test_slab_list, el, 2, 0, 20, false, 0, 0, NULL, NULL, true, false);
	TEST_CHECK(ret == 0);

	/*
	 *	Allocate all the slab elements
	 */
	for (i = 0; i < 20; i++) {
		test_elements[i] = fr_test_slab_reserve(test_slab_list);
		TEST_CHECK(test_elements[i] != NULL);
	}
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 10);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 20);

	/*
	 *	Release all of the elements
	 */
	for (i = 0; i < 20; i++) {
		fr_test_slab_release(test_elements[i]);
	}
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 10);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 0);

	/*
	 *	Running clearup should free five slabs (20 - 0) / 2 / 2 = 5
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(2));
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 1);
	fr_event_service(el);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 5);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 0);

	/*
	 *	Re-run the event - two more slabs should be freed (10 - 0) / 2 / 2 = 2.5
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(2));
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 1);
	fr_event_service(el);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 3);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 0);

	/*
	 *	Re-run the event - one more slab should be freed (6 - 0) / 2 / 2 = 1.5
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(2));
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 1);
	fr_event_service(el);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 2);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 0);

	/*
	 *	Re-run the event - one more slab should be freed (4 - 0) / 2 / 2 = 1
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(2));
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 1);
	fr_event_service(el);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 1);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 0);

	/*
	 *	Re-run the event - no more will be freed as (2 - 0) / 2 / 2 = 0.5
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(2));
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 1);
	fr_event_service(el);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 1);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 0);

	talloc_free(test_slab_list);
	talloc_free(ctx);
}

/** Test that reserving after clearup results in new slab allocation
 *
 */
static void test_realloc(void)
{
	TALLOC_CTX		*ctx = talloc_init_const("test");
	fr_event_list_t		*el;
	fr_test_slab_list_t	*test_slab_list;
	test_element_t		*test_elements[20];
	int			i, events, ret = -1;

	el = fr_event_list_alloc(ctx, NULL, NULL);
	fr_event_list_set_time_func(el, test_time);

	ret = fr_test_slab_list_alloc(NULL, &test_slab_list, el, 2, 0, 20, false, 0, 0, NULL, NULL, true, false);
	TEST_CHECK(ret == 0);

	/*
	 *	Allocate all the slab elements
	 */
	for (i = 0; i < 20; i++) {
		test_elements[i] = fr_test_slab_reserve(test_slab_list);
		TEST_CHECK(test_elements[i] != NULL);
	}
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 10);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 20);

	/*
	 *	Release all of the elements
	 */
	for (i = 0; i < 20; i++) {
		fr_test_slab_release(test_elements[i]);
	}
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 10);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 0);

	/*
	 *	Running clearup should free five slabs
	 */
	test_time_base = fr_time_add_time_delta(test_time_base, fr_time_delta_from_sec(2));
	events = fr_event_corral(el, test_time_base, true);
	TEST_CHECK(events == 1);
	fr_event_service(el);
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 5);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 0);

	/*
	 *	Allocate all the slab elements
	 *	With new slabs allocated, the slab stats will change
	 */
	for (i = 0; i < 20; i++) {
		test_elements[i] = fr_test_slab_reserve(test_slab_list);
		TEST_CHECK(test_elements[i] != NULL);
	}
	TEST_CHECK_RET(fr_test_slab_num_allocated(test_slab_list), 10);
	TEST_CHECK_RET(fr_test_slab_num_elements_used(test_slab_list), 20);

	talloc_free(test_slab_list);
	talloc_free(ctx);
}

static void test_child_alloc(void)
{
	fr_test_slab_list_t	*test_slab_list;
	test_element_t		*test_elements[2];
	int			ret = -1;

	ret = fr_test_slab_list_alloc(NULL, &test_slab_list, NULL, 2, 1, 2, true, 1, 128, NULL, NULL, false, false);
	TEST_CHECK(ret == 0);
	TEST_CHECK(test_slab_list != NULL);

	test_elements[0] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[0] != NULL);
	test_elements[1] = fr_test_slab_reserve(test_slab_list);
	TEST_CHECK(test_elements[1] != NULL);

	/*
	 *	Allocate a child of the first element.  If this has used the pool memory
	 *	allocated to the element, then it's location should be after the element
	 *	but before the next element.
	 *	This is a rough test, which can be improved if additional talloc functions
	 *	become available to check pool allocation status.
	 */
	if (test_elements[0]) {
		test_elements[0]->name = talloc_strdup(test_elements[0], "Hello there");
		TEST_CHECK((void *)test_elements[0]->name > (void *)test_elements[0]);
		if (test_elements[1] && (test_elements[1] > test_elements[0])) {
			TEST_CHECK((void *)test_elements[0]->name < (void *)test_elements[1]);
			TEST_MSG("element 0: %p, name %p, element 1: %p",
				 test_elements[0], test_elements[0]->name, test_elements[1]);
		}
	}

	talloc_free(test_slab_list);
}

TEST_LIST = {
	{ "test_alloc",		test_alloc },
	{ "test_alloc_fail",	test_alloc_fail },
	{ "test_reuse_reset",	test_reuse_reset },
	{ "test_reuse_noreset", test_reuse_noreset },
	{ "test_free",		test_free },
	{ "test_init_1",	test_init_1 },
	{ "test_init_2",	test_init_2 },
	{ "test_clearup_1",	test_clearup_1 },
	{ "test_clearup_2",	test_clearup_2 },
	{ "test_clearup_3",	test_clearup_3 },
	{ "test_realloc",	test_realloc },
	{ "test_child_alloc",	test_child_alloc },

	{ NULL }
};
