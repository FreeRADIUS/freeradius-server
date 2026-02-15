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

/** Tests for the FIFO queue
 *
 * @file src/lib/util/test/fifo_tests.c
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include "acutest.h"
#include "acutest_helpers.h"

#include <freeradius-devel/util/fifo.h>

#define FIFO_TEST_SIZE 128

static void test_fifo_create(void)
{
	fr_fifo_t *fi;

	TEST_CASE("Create a basic fifo");
	fi = fr_fifo_create(NULL, FIFO_TEST_SIZE, NULL);
	TEST_ASSERT(fi != NULL);
	TEST_CHECK(fr_fifo_num_elements(fi) == 0);

	talloc_free(fi);
}

static void test_fifo_create_invalid(void)
{
	fr_fifo_t *fi;

	TEST_CASE("max < 2 should fail");
	fi = fr_fifo_create(NULL, 1, NULL);
	TEST_CHECK(fi == NULL);

	TEST_CASE("max = 0 should fail");
	fi = fr_fifo_create(NULL, 0, NULL);
	TEST_CHECK(fi == NULL);

	TEST_CASE("max too large should fail");
	fi = fr_fifo_create(NULL, (1024 * 1024) + 1, NULL);
	TEST_CHECK(fi == NULL);
}

static void test_fifo_push_pop(void)
{
	fr_fifo_t	*fi;
	int		values[FIFO_TEST_SIZE];
	int		*p;
	int		i, ret;

	fi = fr_fifo_create(NULL, FIFO_TEST_SIZE, NULL);
	TEST_ASSERT(fi != NULL);

	TEST_CASE("Push elements");
	for (i = 0; i < FIFO_TEST_SIZE; i++) {
		values[i] = i;
		ret = fr_fifo_push(fi, &values[i]);
		TEST_CHECK(ret == 0);
		TEST_MSG("push %d failed, returned %d", i, ret);
	}

	TEST_CHECK(fr_fifo_num_elements(fi) == FIFO_TEST_SIZE);

	TEST_CASE("Pop elements in FIFO order");
	for (i = 0; i < FIFO_TEST_SIZE; i++) {
		p = fr_fifo_pop(fi);
		TEST_ASSERT(p != NULL);

		TEST_CHECK(*p == i);
		TEST_MSG("expected %d, got %d", i, *p);
	}

	TEST_CHECK(fr_fifo_num_elements(fi) == 0);

	TEST_CASE("Pop from empty fifo returns NULL");
	p = fr_fifo_pop(fi);
	TEST_CHECK(p == NULL);

	talloc_free(fi);
}

static void test_fifo_peek(void)
{
	fr_fifo_t	*fi;
	int		a = 10, b = 20;
	int		*p;

	fi = fr_fifo_create(NULL, FIFO_TEST_SIZE, NULL);
	TEST_ASSERT(fi != NULL);

	TEST_CASE("Peek on empty fifo returns NULL");
	p = fr_fifo_peek(fi);
	TEST_CHECK(p == NULL);

	TEST_CASE("Peek returns head without removing it");
	fr_fifo_push(fi, &a);
	fr_fifo_push(fi, &b);

	p = fr_fifo_peek(fi);
	TEST_ASSERT(p != NULL);
	TEST_CHECK(*p == 10);
	TEST_CHECK(fr_fifo_num_elements(fi) == 2);

	p = fr_fifo_peek(fi);
	TEST_ASSERT(p != NULL);
	TEST_CHECK(*p == 10);
	TEST_CHECK(fr_fifo_num_elements(fi) == 2);

	talloc_free(fi);
}

static void test_fifo_full(void)
{
	fr_fifo_t	*fi;
	int		values[FIFO_TEST_SIZE + 1];
	int		i, ret;

	fi = fr_fifo_create(NULL, FIFO_TEST_SIZE, NULL);
	TEST_ASSERT(fi != NULL);

	TEST_CASE("Fill fifo to capacity");
	for (i = 0; i < FIFO_TEST_SIZE; i++) {
		values[i] = i;
		ret = fr_fifo_push(fi, &values[i]);
		TEST_CHECK(ret == 0);
	}

	TEST_CASE("Push to full fifo fails");
	values[FIFO_TEST_SIZE] = FIFO_TEST_SIZE;
	ret = fr_fifo_push(fi, &values[FIFO_TEST_SIZE]);
	TEST_CHECK(ret < 0);

	TEST_CHECK(fr_fifo_num_elements(fi) == FIFO_TEST_SIZE);

	talloc_free(fi);
}

static void test_fifo_wraparound(void)
{
	fr_fifo_t	*fi;
	int		values[FIFO_TEST_SIZE * 2];
	int		*p;
	int		i, ret;

	fi = fr_fifo_create(NULL, FIFO_TEST_SIZE, NULL);
	TEST_ASSERT(fi != NULL);

	TEST_CASE("Fill, drain, and refill to test circular buffer wraparound");
	for (int cycle = 0; cycle < 3; cycle++) {
		int base = cycle * FIFO_TEST_SIZE;

		for (i = 0; i < FIFO_TEST_SIZE; i++) {
			values[i] = base + i;
			ret = fr_fifo_push(fi, &values[i]);
			TEST_CHECK(ret == 0);
			TEST_MSG("cycle %d, push %d failed", cycle, i);
		}

		TEST_CHECK(fr_fifo_num_elements(fi) == FIFO_TEST_SIZE);

		for (i = 0; i < FIFO_TEST_SIZE; i++) {
			p = fr_fifo_pop(fi);
			TEST_ASSERT(p != NULL);

			TEST_CHECK(*p == base + i);
			TEST_MSG("cycle %d, expected %d, got %d", cycle, base + i, *p);
		}

		TEST_CHECK(fr_fifo_num_elements(fi) == 0);
	}

	talloc_free(fi);
}

static void test_fifo_partial_drain(void)
{
	fr_fifo_t	*fi;
	int		values[FIFO_TEST_SIZE];
	int		*p;
	int		i;

	fi = fr_fifo_create(NULL, FIFO_TEST_SIZE, NULL);
	TEST_ASSERT(fi != NULL);

	TEST_CASE("Push half, pop half, push half again");
	for (i = 0; i < FIFO_TEST_SIZE / 2; i++) {
		values[i] = i;
		fr_fifo_push(fi, &values[i]);
	}
	TEST_CHECK(fr_fifo_num_elements(fi) == FIFO_TEST_SIZE / 2);

	for (i = 0; i < FIFO_TEST_SIZE / 4; i++) {
		p = fr_fifo_pop(fi);
		TEST_ASSERT(p != NULL);

		TEST_CHECK(*p == i);
	}
	TEST_CHECK(fr_fifo_num_elements(fi) == FIFO_TEST_SIZE / 4);

	for (i = FIFO_TEST_SIZE / 2; i < FIFO_TEST_SIZE; i++) {
		values[i] = i;
		TEST_CHECK(fr_fifo_push(fi, &values[i]) == 0);
	}

	TEST_CASE("Verify remaining elements are in correct order");
	for (i = FIFO_TEST_SIZE / 4; i < FIFO_TEST_SIZE; i++) {
		p = fr_fifo_pop(fi);
		TEST_ASSERT(p != NULL);

		TEST_CHECK(*p == i);
		TEST_MSG("expected %d, got %d", i, *p);
	}
	TEST_CHECK(fr_fifo_num_elements(fi) == 0);

	talloc_free(fi);
}

static unsigned int free_count;

static void test_free_callback(void *data)
{
	(void)data;
	free_count++;
}

static void test_fifo_free_callback(void)
{
	fr_fifo_t	*fi;
	int		values[8];
	int		i;

	free_count = 0;

	fi = fr_fifo_create(NULL, 16, test_free_callback);
	TEST_ASSERT(fi != NULL);

	TEST_CASE("Free callback is called for remaining elements on destroy");
	for (i = 0; i < 8; i++) {
		values[i] = i;
		fr_fifo_push(fi, &values[i]);
	}

	talloc_free(fi);

	TEST_CHECK(free_count == 8);
	TEST_MSG("expected 8 free callbacks, got %u", free_count);
}

static void test_fifo_null_args(void)
{
	TEST_CASE("NULL fifo operations don't crash");
	TEST_CHECK(fr_fifo_pop(NULL) == NULL);
	TEST_CHECK(fr_fifo_peek(NULL) == NULL);
	TEST_CHECK(fr_fifo_num_elements(NULL) == 0);
}

TEST_LIST = {
	{ "fifo_create",		test_fifo_create },
	{ "fifo_create_invalid",	test_fifo_create_invalid },
	{ "fifo_push_pop",		test_fifo_push_pop },
	{ "fifo_peek",			test_fifo_peek },
	{ "fifo_full",			test_fifo_full },
	{ "fifo_wraparound",		test_fifo_wraparound },
	{ "fifo_partial_drain",		test_fifo_partial_drain },
	{ "fifo_free_callback",		test_fifo_free_callback },
	{ "fifo_null_args",		test_fifo_null_args },
	TEST_TERMINATOR
};
