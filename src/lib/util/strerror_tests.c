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

/** Tests for a generic string buffer structure for string printing and parsing
 *
 * @file src/lib/util/strerror_tests.c
 *
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include <freeradius-devel/util/acutest.h>
#include <freeradius-devel/util/acutest_helpers.h>
#include <freeradius-devel/util/time.h>

#include "strerror.c"

static void strerror_uninit(void)
{
	char const *error;

	error = fr_strerror();

	TEST_CHECK(error != NULL);
	TEST_CHECK(error && (error[0] == '\0'));
}

static void strerror_pop_uninit(void)
{
	char const *error;

	error = fr_strerror_pop();

	TEST_CHECK(error == NULL);
}

static void strerror_printf(void)
{
	char const *error;

	fr_strerror_printf("Testing %i", 123);

	error = fr_strerror();

	TEST_CHECK(error != NULL);
	TEST_CHECK_STRCMP(error, "Testing 123");

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(error && (error[0] == '\0'));
}

static void strerror_printf_push_pop(void)
{
	char const *error;

	fr_strerror_printf_push("Testing %i", 1);

	error = fr_strerror_pop();
	TEST_CHECK(error != NULL);
	TEST_CHECK_STRCMP(error, "Testing 1");

	error = fr_strerror_pop();
	TEST_CHECK(error == NULL);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(error && (error[0] == '\0'));
}

static void strerror_printf_push_strerror(void)
{
	char const *error;

	fr_strerror_printf_push("Testing %i", 1);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK_STRCMP(error, "Testing 1");

	error = fr_strerror_pop();
	TEST_CHECK(error == NULL);
}

static void strerror_printf_push_pop_multi(void)
{
	char const *error;

	fr_strerror_printf_push("Testing %i", 1);
	fr_strerror_printf_push("Testing %i", 2);

	error = fr_strerror_pop();
	TEST_CHECK(error != NULL);
	TEST_CHECK_STRCMP(error, "Testing 1");

	error = fr_strerror_pop();
	TEST_CHECK(error != NULL);
	TEST_CHECK_STRCMP(error, "Testing 2");

	error = fr_strerror_pop();
	TEST_CHECK(error == NULL);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(error && (error[0] == '\0'));
}

static void strerror_printf_push_strerror_multi(void)
{
	char const *error;

	fr_strerror_printf_push("Testing %i", 1);
	fr_strerror_printf_push("Testing %i", 2);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK_STRCMP(error, "Testing 2");

	error = fr_strerror_pop();
	TEST_CHECK(error == NULL);
}

static void strerror_printf_strerror_append(void)
{
	char const *error;

	fr_strerror_printf("Testing %i", 1);
	fr_strerror_printf("%s Testing %i", fr_strerror(), 2);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK_STRCMP(error, "Testing 1 Testing 2");

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(error && (error[0] == '\0'));
}

static void strerror_printf_push_append(void)
{
	char const *error;

	fr_strerror_printf_push("Testing %i", 1);
	fr_strerror_printf("%s Testing %i", fr_strerror(), 2);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK_STRCMP(error, "Testing 1 Testing 2");

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(error && (error[0] == '\0'));
}

static void strerror_printf_push_append2(void)
{
	char const *error;

	fr_strerror_printf_push("Testing %i", 1);
	fr_strerror_printf("%s Testing %i", fr_strerror_pop(), 2);

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK_STRCMP(error, "Testing 1 Testing 2");

	error = fr_strerror();
	TEST_CHECK(error != NULL);
	TEST_CHECK(error && (error[0] == '\0'));
}

static void strerror_printf_benchmark(void)
{
	int		i;
	fr_time_t	start, stop;
	uint64_t	rate;

	fr_strerror_const("pre-allocate buffers");
	fr_strerror();

	start = fr_time();
	for (i = 0; i < 100000; i++) {
		fr_strerror_printf("I am a test %u string %u %s", i, i, "benchmark");
		fr_strerror();	/* Clear */
	}
	stop = fr_time();

	rate = (uint64_t)((float)NSEC / ((stop - start) / 100000));
	printf("printf pop rate %" PRIu64 "\n", rate);

	TEST_CHECK(rate > 400000);
}


static void strerror_const_benchmark(void)
{
	int		i;
	fr_time_t	start, stop;
	uint64_t	rate;

	fr_strerror_const("pre-allocate buffers");
	fr_strerror();

	start = fr_time();
	for (i = 0; i < 100000; i++) {
		fr_strerror_const("I am a test string");
		fr_strerror();	/* Clear */
	}
	stop = fr_time();

	rate = (uint64_t)((float)NSEC / ((stop - start) / 100000));
	printf("const pop rate %" PRIu64 "\n", rate);

	TEST_CHECK(rate > 10000000);
}


TEST_LIST = {
	{ "strerror_uninit",			strerror_uninit },
	{ "strerror_pop_uninit",		strerror_pop_uninit },

	{ "strerror_printf",			strerror_printf },
	{ "strerror_printf_push_pop", 		strerror_printf_push_pop },

	{ "strerror_printf_push_strerror",	strerror_printf_push_strerror },
	{ "strerror_printf_push_pop_multi",	strerror_printf_push_pop_multi },
	{ "strerror_printf_push_strerror_multi",strerror_printf_push_strerror_multi },
	{ "strerror_printf_strerror_append",	strerror_printf_strerror_append },
	{ "strerror_printf_push_append",	strerror_printf_push_append },
	{ "strerror_printf_push_append2",	strerror_printf_push_append2 },

	{ "strerror_printf_benchmark",		strerror_printf_benchmark },
	{ "strerror_const_benchmark",		strerror_const_benchmark },

	{ 0 }
};
