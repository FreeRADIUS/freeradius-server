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

/** Tests for value box calculation functions
 *
 * @file src/lib/util/test/calc_tests.c
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */

#include "acutest.h"
#include "acutest_helpers.h"

#include <freeradius-devel/util/calc.h>
#include <freeradius-devel/util/value.h>

static TALLOC_CTX *autofree;

static void test_init(void) __attribute__((constructor));
static void test_init(void)
{
	autofree = talloc_autofree_context();
	if (!autofree) {
		fr_perror("calc_tests");
		fr_exit_now(EXIT_FAILURE);
	}

	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("calc_tests");
		fr_exit_now(EXIT_FAILURE);
	}
}

/*
 *	uint64 arithmetic
 */
static void test_uint32_add(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&a, (uint32_t) 10, false);
	fr_value_box(&b, (uint32_t) 20, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.vb_uint32 == 30);
	TEST_MSG("Expected 30, got %u", dst.vb_uint32);
}

static void test_uint32_sub(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&a, (uint32_t) 30, false);
	fr_value_box(&b, (uint32_t) 10, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_SUB, &b) == 0);
	TEST_CHECK(dst.vb_uint32 == 20);
	TEST_MSG("Expected 20, got %u", dst.vb_uint32);
}

static void test_uint32_mul(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&a, (uint32_t) 6, false);
	fr_value_box(&b, (uint32_t) 7, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_MUL, &b) == 0);
	TEST_CHECK(dst.vb_uint32 == 42);
	TEST_MSG("Expected 42, got %u", dst.vb_uint32);
}

static void test_uint32_div(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&a, (uint32_t) 42, false);
	fr_value_box(&b, (uint32_t) 6, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_DIV, &b) == 0);
	TEST_CHECK(dst.vb_uint32 == 7);
	TEST_MSG("Expected 7, got %u", dst.vb_uint32);
}

static void test_uint32_mod(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&a, (uint32_t) 17, false);
	fr_value_box(&b, (uint32_t) 5, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_MOD, &b) == 0);
	TEST_CHECK(dst.vb_uint32 == 2);
	TEST_MSG("Expected 2, got %u", dst.vb_uint32);
}

static void test_uint32_and(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&a, (uint32_t) 0xff, false);
	fr_value_box(&b, (uint32_t) 0x0f, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_AND, &b) == 0);
	TEST_CHECK(dst.vb_uint32 == 0x0f);
	TEST_MSG("Expected 0x0f, got 0x%x", dst.vb_uint32);
}

static void test_uint32_or(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&a, (uint32_t) 0xf0, false);
	fr_value_box(&b, (uint32_t) 0x0f, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_OR, &b) == 0);
	TEST_CHECK(dst.vb_uint32 == 0xff);
	TEST_MSG("Expected 0xff, got 0x%x", dst.vb_uint32);
}

static void test_uint32_xor(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&a, (uint32_t) 0xff, false);
	fr_value_box(&b, (uint32_t) 0x0f, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_XOR, &b) == 0);
	TEST_CHECK(dst.vb_uint32 == 0xf0);
	TEST_MSG("Expected 0xf0, got 0x%x", dst.vb_uint32);
}

static void test_uint32_shift(void)
{
	fr_value_box_t a, b, dst;


	fr_value_box(&a, (uint32_t) 0x10, false);
	fr_value_box(&b, (uint32_t) 4, false);

	/* left shift */
	fr_value_box_init(&dst, FR_TYPE_UINT64, NULL, false);
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_LSHIFT, &b) == 0);
	TEST_CHECK(dst.vb_uint64 == 0x100);
	TEST_MSG("Expected 0x100, got 0x%" PRIx64, dst.vb_uint64);

	/* right shift */
	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_RSHIFT, &b) == 0);
	TEST_CHECK(dst.vb_uint32 == 0x01);
	TEST_MSG("Expected 0x01, got 0x%x", dst.vb_uint32);
}

/*
 *	Division by zero
 */
static void test_uint32_div_zero(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&a, (uint32_t) 42, false);
	fr_value_box(&b, (uint32_t) 0, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_DIV, &b) < 0);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_MOD, &b) < 0);
}

/*
 *	uint8 tests - verify smaller int types work via calc_uint64 upcast
 */
static void test_uint8_add(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT8, NULL, false);

	fr_value_box(&a, (uint8_t) 100, false);
	fr_value_box(&b, (uint8_t) 50, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT8, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.vb_uint8 == 150);
	TEST_MSG("Expected 150, got %u", dst.vb_uint8);
}

static void test_uint8_overflow(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT8, NULL, false);

	fr_value_box(&a, (uint8_t) 200, false);
	fr_value_box(&b, (uint8_t) 200, false);

	/* 200 + 200 = 400, which overflows uint8 (but the intermediate is uint64, then cast to uint8 fails) */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT8, &a, T_ADD, &b) < 0);
}

/*
 *	Signed integer tests
 */
static void test_int32_add(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT32, NULL, false);

	fr_value_box(&a, (int32_t) -10, false);
	fr_value_box(&b, (int32_t) 30, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT32, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.vb_int32 == 20);
	TEST_MSG("Expected 20, got %d", dst.vb_int32);
}

static void test_int32_sub(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT32, NULL, false);

	fr_value_box(&a, (int32_t) 10, false);
	fr_value_box(&b, (int32_t) 30, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT32, &a, T_SUB, &b) == 0);
	TEST_CHECK(dst.vb_int32 == -20);
	TEST_MSG("Expected -20, got %d", dst.vb_int32);
}

static void test_int32_mul(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT32, NULL, false);

	fr_value_box(&a, (int32_t) -6, false);
	fr_value_box(&b, (int32_t) 7, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT32, &a, T_MUL, &b) == 0);
	TEST_CHECK(dst.vb_int32 == -42);
	TEST_MSG("Expected -42, got %d", dst.vb_int32);
}

static void test_int32_div(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT32, NULL, false);

	fr_value_box(&a, (int32_t) -42, false);
	fr_value_box(&b, (int32_t) 6, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT32, &a, T_DIV, &b) == 0);
	TEST_CHECK(dst.vb_int32 == -7);
	TEST_MSG("Expected -7, got %d", dst.vb_int32);
}

static void test_int64_div_zero(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT64, NULL, false);

	fr_value_box(&a, (int64_t) 42, false);
	fr_value_box(&b, (int64_t) 0, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT64, &a, T_DIV, &b) < 0);
}

/*
 *	Boolean tests
 */
static void test_bool_and(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box(&a, (bool) true, false);
	fr_value_box(&b, (bool) false, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_AND, &b) == 0);
	TEST_CHECK(dst.vb_bool == false);

	b.vb_bool = true;
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_AND, &b) == 0);
	TEST_CHECK(dst.vb_bool == true);
}

static void test_bool_or(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box(&a, (bool) false, false);
	fr_value_box(&b, (bool) false, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OR, &b) == 0);
	TEST_CHECK(dst.vb_bool == false);

	a.vb_bool = true;
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OR, &b) == 0);
	TEST_CHECK(dst.vb_bool == true);
}

static void test_bool_xor(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box(&a, (bool) true, false);
	fr_value_box(&b, (bool) true, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_XOR, &b) == 0);
	TEST_CHECK(dst.vb_bool == false);

	b.vb_bool = false;
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_XOR, &b) == 0);
	TEST_CHECK(dst.vb_bool == true);
}

static void test_bool_add(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	/* false + true = true */
	fr_value_box(&a, (bool) false, false);
	fr_value_box(&b, (bool) true, false);
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.vb_bool == true);

	/* true + true = overflow */
	a.vb_bool = true;
	b.vb_bool = true;
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_ADD, &b) < 0);
}

static void test_bool_sub(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	/* true - true = false */
	fr_value_box(&a, (bool) true, false);
	fr_value_box(&b, (bool) true, false);
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_SUB, &b) == 0);
	TEST_CHECK(dst.vb_bool == false);

	/* false - true = underflow */
	a.vb_bool = false;
	b.vb_bool = true;
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_SUB, &b) < 0);
}

/*
 *	Float64 tests
 */
static void test_float64_add(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT64, NULL, false);

	fr_value_box(&a, (double) 1.5, false);
	fr_value_box(&b, (double) 2.5, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_FLOAT64, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.vb_float64 == 4.0);
	TEST_MSG("Expected 4.0, got %f", dst.vb_float64);
}

static void test_float64_sub(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT64, NULL, false);

	fr_value_box(&a, (double) 10.0, false);
	fr_value_box(&b, (double) 3.5, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_FLOAT64, &a, T_SUB, &b) == 0);
	TEST_CHECK(dst.vb_float64 == 6.5);
	TEST_MSG("Expected 6.5, got %f", dst.vb_float64);
}

static void test_float64_mul(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT64, NULL, false);

	fr_value_box(&a, (double) 3.0, false);
	fr_value_box(&b, (double) 7.0, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_FLOAT64, &a, T_MUL, &b) == 0);
	TEST_CHECK(dst.vb_float64 == 21.0);
	TEST_MSG("Expected 21.0, got %f", dst.vb_float64);
}

static void test_float64_div(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT64, NULL, false);

	fr_value_box(&a, (double) 22.0, false);
	fr_value_box(&b, (double) 7.0, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_FLOAT64, &a, T_DIV, &b) == 0);
	TEST_CHECK((dst.vb_float64 > 3.14) && (dst.vb_float64 < 3.15));
	TEST_MSG("Expected ~3.14, got %f", dst.vb_float64);
}

static void test_float64_div_zero(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT64, NULL, false);

	fr_value_box(&a, (double) 1.0, false);
	fr_value_box(&b, (double) 0.0, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_FLOAT64, &a, T_DIV, &b) < 0);
}

static void test_float64_mod(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT64, NULL, false);

	fr_value_box(&a, (double) 10.5, false);
	fr_value_box(&b, (double) 3.0, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_FLOAT64, &a, T_MOD, &b) == 0);
	TEST_CHECK((dst.vb_float64 > 1.49) && (dst.vb_float64 < 1.51));
	TEST_MSG("Expected ~1.5, got %f", dst.vb_float64);
}

/*
 *	Float32 tests
 */
static void test_float32_add(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT32, NULL, false);

	fr_value_box(&a, (float) 1.5f, false);
	fr_value_box(&b, (float) 2.5f, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_FLOAT32, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.vb_float32 == 4.0f);
	TEST_MSG("Expected 4.0, got %f", (double)dst.vb_float32);
}

static void test_float32_div_zero(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT32, NULL, false);

	fr_value_box(&a, (float) 1.0f, false);
	fr_value_box(&b, (float) 0.0f, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_FLOAT32, &a, T_DIV, &b) < 0);
}

/*
 *	String tests
 */
static void test_string_add(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&b, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_STRING, NULL, false);

	fr_value_box_strdup(autofree, &a, NULL, "hello ", false);
	fr_value_box_strdup(autofree, &b, NULL, "world", false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_STRING, &a, T_ADD, &b) == 0);
	TEST_CHECK(strcmp(dst.vb_strvalue, "hello world") == 0);
	TEST_MSG("Expected 'hello world', got '%s'", dst.vb_strvalue);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
	fr_value_box_clear(&dst);
}

static void test_string_sub(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&b, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_STRING, NULL, false);

	fr_value_box_strdup(autofree, &a, NULL, "hello world", false);
	fr_value_box_strdup(autofree, &b, NULL, "world", false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_STRING, &a, T_SUB, &b) == 0);
	TEST_CHECK(strcmp(dst.vb_strvalue, "hello ") == 0);
	TEST_MSG("Expected 'hello ', got '%s'", dst.vb_strvalue);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
	fr_value_box_clear(&dst);
}

static void test_string_sub_not_suffix(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&b, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_STRING, NULL, false);

	fr_value_box_strdup(autofree, &a, NULL, "hello world", false);
	fr_value_box_strdup(autofree, &b, NULL, "hello", false);

	/* "hello" is not a suffix of "hello world" */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_STRING, &a, T_SUB, &b) < 0);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
}

static void test_string_xor_prepend(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&b, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_STRING, NULL, false);

	fr_value_box_strdup(autofree, &a, NULL, "world", false);
	fr_value_box_strdup(autofree, &b, NULL, "hello ", false);

	/* XOR on strings is prepend: b is prepended to a */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_STRING, &a, T_XOR, &b) == 0);
	TEST_CHECK(strcmp(dst.vb_strvalue, "hello world") == 0);
	TEST_MSG("Expected 'hello world', got '%s'", dst.vb_strvalue);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
	fr_value_box_clear(&dst);
}

static void test_string_rshift(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_STRING, NULL, false);

	fr_value_box_strdup(autofree, &a, NULL, "hello world", false);
	fr_value_box(&b, (uint32_t) 6, false);  /* remove 6 chars from the right */

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_STRING, &a, T_RSHIFT, &b) == 0);
	TEST_CHECK(strcmp(dst.vb_strvalue, "hello") == 0);
	TEST_MSG("Expected 'hello', got '%s'", dst.vb_strvalue);

	fr_value_box_clear(&a);
	fr_value_box_clear(&dst);
}

static void test_string_lshift(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_STRING, NULL, false);

	fr_value_box_strdup(autofree, &a, NULL, "hello world", false);
	fr_value_box(&b, (uint32_t) 6, false);  /* remove 6 chars from the left */

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_STRING, &a, T_LSHIFT, &b) == 0);
	TEST_CHECK(strcmp(dst.vb_strvalue, "world") == 0);
	TEST_MSG("Expected 'world', got '%s'", dst.vb_strvalue);

	fr_value_box_clear(&a);
	fr_value_box_clear(&dst);
}

/*
 *	Octets tests
 */
static void test_octets_add(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&b, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_OCTETS, NULL, false);

	fr_value_box_memdup(autofree, &a, NULL, (uint8_t const *)"\x01\x02", 2, false);
	fr_value_box_memdup(autofree, &b, NULL, (uint8_t const *)"\x03\x04", 2, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_OCTETS, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.vb_length == 4);
	TEST_CHECK(memcmp(dst.vb_octets, "\x01\x02\x03\x04", 4) == 0);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
	fr_value_box_clear(&dst);
}

static void test_octets_sub(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&b, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_OCTETS, NULL, false);

	fr_value_box_memdup(autofree, &a, NULL, (uint8_t const *)"\x01\x02\x03\x04", 4, false);
	fr_value_box_memdup(autofree, &b, NULL, (uint8_t const *)"\x03\x04", 2, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_OCTETS, &a, T_SUB, &b) == 0);
	TEST_CHECK(dst.vb_length == 2);
	TEST_CHECK(memcmp(dst.vb_octets, "\x01\x02", 2) == 0);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
	fr_value_box_clear(&dst);
}

static void test_octets_and(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&b, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_OCTETS, NULL, false);

	fr_value_box_memdup(autofree, &a, NULL, (uint8_t const *)"\xff\x0f", 2, false);
	fr_value_box_memdup(autofree, &b, NULL, (uint8_t const *)"\x0f\xff", 2, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_OCTETS, &a, T_AND, &b) == 0);
	TEST_CHECK(dst.vb_length == 2);
	TEST_CHECK(memcmp(dst.vb_octets, "\x0f\x0f", 2) == 0);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
	fr_value_box_clear(&dst);
}

static void test_octets_or(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&b, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_OCTETS, NULL, false);

	fr_value_box_memdup(autofree, &a, NULL, (uint8_t const *)"\xf0\x0f", 2, false);
	fr_value_box_memdup(autofree, &b, NULL, (uint8_t const *)"\x0f\xf0", 2, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_OCTETS, &a, T_OR, &b) == 0);
	TEST_CHECK(dst.vb_length == 2);
	TEST_CHECK(memcmp(dst.vb_octets, "\xff\xff", 2) == 0);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
	fr_value_box_clear(&dst);
}

static void test_octets_xor(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&b, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_OCTETS, NULL, false);

	fr_value_box_memdup(autofree, &a, NULL, (uint8_t const *)"\xff\x00", 2, false);
	fr_value_box_memdup(autofree, &b, NULL, (uint8_t const *)"\x0f\x0f", 2, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_OCTETS, &a, T_XOR, &b) == 0);
	TEST_CHECK(dst.vb_length == 2);
	TEST_CHECK(memcmp(dst.vb_octets, "\xf0\x0f", 2) == 0);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
	fr_value_box_clear(&dst);
}

static void test_octets_length_mismatch(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&b, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_OCTETS, NULL, false);

	fr_value_box_memdup(autofree, &a, NULL, (uint8_t const *)"\xff\x00\x01", 3, false);
	fr_value_box_memdup(autofree, &b, NULL, (uint8_t const *)"\x0f\x0f", 2, false);

	/* AND/OR/XOR require same length */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_OCTETS, &a, T_AND, &b) < 0);
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_OCTETS, &a, T_OR, &b) < 0);
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_OCTETS, &a, T_XOR, &b) < 0);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
}

static void test_octets_rshift(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_OCTETS, NULL, false);

	fr_value_box_memdup(autofree, &a, NULL, (uint8_t const *)"\x01\x02\x03\x04", 4, false);
	fr_value_box(&b, (uint32_t) 2, false);  /* remove 2 bytes from the right */

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_OCTETS, &a, T_RSHIFT, &b) == 0);
	TEST_CHECK(dst.vb_length == 2);
	TEST_CHECK(memcmp(dst.vb_octets, "\x01\x02", 2) == 0);

	fr_value_box_clear(&a);
	fr_value_box_clear(&dst);
}

static void test_octets_lshift(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_OCTETS, NULL, false);

	fr_value_box_memdup(autofree, &a, NULL, (uint8_t const *)"\x01\x02\x03\x04", 4, false);
	fr_value_box(&b, (uint32_t) 2, false);  /* remove 2 bytes from the left */

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_OCTETS, &a, T_LSHIFT, &b) == 0);
	TEST_CHECK(dst.vb_length == 2);
	TEST_CHECK(memcmp(dst.vb_octets, "\x03\x04", 2) == 0);

	fr_value_box_clear(&a);
	fr_value_box_clear(&dst);
}

/*
 *	Comparison tests
 */
static void test_cmp_eq(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box(&a, (uint32_t) 42, false);
	fr_value_box(&b, (uint32_t) 42, false);

	/*
	 *	T_OP_CMP and friends return "1" for "true", "0" for "false", and -1 for error.
	 */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_CMP_EQ, &b) == 1);
	TEST_CHECK(dst.vb_bool == true);

	b.vb_uint32 = 43;
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_CMP_EQ, &b) == 0);
	TEST_CHECK(dst.vb_bool == false);
}

static void test_cmp_ne(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box(&a, (uint32_t) 42, false);
	fr_value_box(&b, (uint32_t) 43, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_NE, &b) == 1);
	TEST_CHECK(dst.vb_bool == true);

	b.vb_uint32 = 42;
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_NE, &b) == 0);
	TEST_CHECK(dst.vb_bool == false);
}

static void test_cmp_lt(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box(&a, (uint32_t) 10, false);
	fr_value_box(&b, (uint32_t) 20, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_LT, &b) == 1);
	TEST_CHECK(dst.vb_bool == true);

	a.vb_uint32 = 20;
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_LT, &b) == 0);
	TEST_CHECK(dst.vb_bool == false);
}

static void test_cmp_gt(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box(&a, (uint32_t) 20, false);
	fr_value_box(&b, (uint32_t) 10, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_GT, &b) == 1);
	TEST_CHECK(dst.vb_bool == true);

	a.vb_uint32 = 10;
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_GT, &b) == 0);
	TEST_CHECK(dst.vb_bool == false);
}

static void test_cmp_le(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box(&a, (uint32_t) 10, false);
	fr_value_box(&b, (uint32_t) 10, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_LE, &b) == 1);
	TEST_CHECK(dst.vb_bool == true);

	a.vb_uint32 = 11;
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_LE, &b) == 0);
	TEST_CHECK(dst.vb_bool == false);
}

static void test_cmp_ge(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box(&a, (uint32_t) 10, false);
	fr_value_box(&b, (uint32_t) 10, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_GE, &b) == 1);
	TEST_CHECK(dst.vb_bool == true);

	a.vb_uint32 = 9;
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_GE, &b) == 0);
	TEST_CHECK(dst.vb_bool == false);
}

static void test_cmp_eq_type(void)
{
	fr_value_box_t a, b, dst;

	/* Same type, same value */
	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box(&a, (uint32_t) 42, false);
	fr_value_box(&b, (uint32_t) 42, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_NULL, &a, T_OP_CMP_EQ_TYPE, &b) == 1);
	TEST_CHECK(dst.vb_bool == true);

	/* Different types -> always false */
	fr_value_box(&b, (uint64_t) 42, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_NULL, &a, T_OP_CMP_EQ_TYPE, &b) == 0);
	TEST_CHECK(dst.vb_bool == false);
}

/*
 *	Unary operation tests
 */
static void test_unary_increment(void)
{
	fr_value_box_t src, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&src, (uint32_t) 41, false);

	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_OP_INCRM, &src) == 0);
	TEST_CHECK(dst.vb_uint32 == 42);
	TEST_MSG("Expected 42, got %u", dst.vb_uint32);
}

static void test_unary_complement(void)
{
	fr_value_box_t src, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT8, NULL, false);

	fr_value_box(&src, (uint8_t) 0x0f, false);

	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_COMPLEMENT, &src) == 0);
	TEST_CHECK(dst.vb_uint8 == 0xf0);
	TEST_MSG("Expected 0xf0, got 0x%02x", dst.vb_uint8);
}

static void test_unary_negate(void)
{
	fr_value_box_t src, dst;

	fr_value_box_init(&dst, FR_TYPE_INT32, NULL, false);

	fr_value_box(&src, (int32_t) 42, false);

	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_SUB, &src) == 0);
	TEST_CHECK(dst.vb_int32 == -42);
	TEST_MSG("Expected -42, got %d", dst.vb_int32);
}

static void test_unary_not(void)
{
	fr_value_box_t src, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box(&src, (uint32_t) 42, false);

	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_NOT, &src) == 0);
	TEST_CHECK(dst.vb_bool == false);

	src.vb_uint32 = 0;
	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_NOT, &src) == 0);
	TEST_CHECK(dst.vb_bool == true);
}

/*
 *	Assignment operation tests
 */
static void test_assign_add(void)
{
	fr_value_box_t dst, src;


	fr_value_box(&dst, (uint32_t) 10, false);
	fr_value_box(&src, (uint32_t) 5, false);

	TEST_CHECK(fr_value_calc_assignment_op(autofree, &dst, T_OP_ADD_EQ, &src) == 0);
	TEST_CHECK(dst.vb_uint32 == 15);
	TEST_MSG("Expected 15, got %u", dst.vb_uint32);
}

static void test_assign_sub(void)
{
	fr_value_box_t dst, src;


	fr_value_box(&dst, (uint32_t) 10, false);
	fr_value_box(&src, (uint32_t) 3, false);

	TEST_CHECK(fr_value_calc_assignment_op(autofree, &dst, T_OP_SUB_EQ, &src) == 0);
	TEST_CHECK(dst.vb_uint32 == 7);
	TEST_MSG("Expected 7, got %u", dst.vb_uint32);
}

static void test_assign_set(void)
{
	fr_value_box_t dst, src;


	fr_value_box(&dst, (uint32_t) 10, false);
	fr_value_box(&src, (uint32_t) 99, false);

	TEST_CHECK(fr_value_calc_assignment_op(autofree, &dst, T_OP_SET, &src) == 0);
	TEST_CHECK(dst.vb_uint32 == 99);
	TEST_MSG("Expected 99, got %u", dst.vb_uint32);
}

static void test_assign_self(void)
{
	fr_value_box_t dst;

	fr_value_box(&dst, (uint32_t) 42, false);

	/* Assigning to self should be a no-op */
	TEST_CHECK(fr_value_calc_assignment_op(autofree, &dst, T_OP_EQ, &dst) == 0);
	TEST_CHECK(dst.vb_uint32 == 42);
}

/*
 *	Type coercion tests - mixed type operations
 */
static void test_mixed_uint8_uint32(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&a, (uint8_t) 10, false);
	fr_value_box(&b, (uint32_t) 20, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.vb_uint32 == 30);
	TEST_MSG("Expected 30, got %u", dst.vb_uint32);
}

static void test_auto_type_hint(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init_null(&dst);

	fr_value_box(&a, (uint32_t) 10, false);
	fr_value_box(&b, (uint32_t) 20, false);

	/* Let the function figure out the output type */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_NULL, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.type == FR_TYPE_UINT64);  /* uint32 + uint32 upcasts to uint64 */
	TEST_CHECK(dst.vb_uint64 == 30);
	TEST_MSG("Expected 30, got %" PRIu64, dst.vb_uint64);
}

/*
 *	Comparison with different types
 */
static void test_cmp_different_types(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box(&a, (uint8_t) 10, false);
	fr_value_box(&b, (uint32_t) 10, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_CMP_EQ, &b) == 1);
	TEST_CHECK(dst.vb_bool == true);

	a.vb_uint8 = 10;
	b.vb_uint32 = 20;
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_LT, &b) == 1);
	TEST_CHECK(dst.vb_bool == true);
}

/*
 *	uint64 edge cases
 */
static void test_uint64_overflow(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT64, NULL, false);

	fr_value_box(&a, (uint64_t) UINT64_MAX, false);
	fr_value_box(&b, (uint64_t) 1, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_ADD, &b) < 0);
}

static void test_uint64_underflow(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT64, NULL, false);

	fr_value_box(&a, (uint64_t) 0, false);
	fr_value_box(&b, (uint64_t) 1, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_SUB, &b) < 0);
}

static void test_uint64_mul_overflow(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT64, NULL, false);

	fr_value_box(&a, (uint64_t) UINT64_MAX, false);
	fr_value_box(&b, (uint64_t) 2, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_MUL, &b) < 0);
}

/*
 *	int64 edge cases
 */
static void test_int64_overflow(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT64, NULL, false);

	fr_value_box(&a, (int64_t) INT64_MAX, false);
	fr_value_box(&b, (int64_t) 1, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT64, &a, T_ADD, &b) < 0);
}

static void test_int64_underflow(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT64, NULL, false);

	fr_value_box(&a, (int64_t) INT64_MIN, false);
	fr_value_box(&b, (int64_t) 1, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT64, &a, T_SUB, &b) < 0);
}

/*
 *	uint16 tests
 */
static void test_uint16_add(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT16, NULL, false);

	fr_value_box(&a, (uint16_t) 1000, false);
	fr_value_box(&b, (uint16_t) 2000, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT16, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.vb_uint16 == 3000);
	TEST_MSG("Expected 3000, got %u", dst.vb_uint16);
}

static void test_uint16_overflow(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT16, NULL, false);

	fr_value_box(&a, (uint16_t) 60000, false);
	fr_value_box(&b, (uint16_t) 60000, false);

	/* 60000 + 60000 = 120000, which overflows uint16 */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT16, &a, T_ADD, &b) < 0);
}

/*
 *	uint64 bitwise and shift tests
 */
static void test_uint64_and(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT64, NULL, false);

	fr_value_box(&a, (uint64_t) 0xff00ff00ff00ff00ULL, false);
	fr_value_box(&b, (uint64_t) 0x0f0f0f0f0f0f0f0fULL, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_AND, &b) == 0);
	TEST_CHECK(dst.vb_uint64 == 0x0f000f000f000f00ULL);
	TEST_MSG("Expected 0x0f000f000f000f00, got 0x%" PRIx64, dst.vb_uint64);
}

static void test_uint64_or(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT64, NULL, false);

	fr_value_box(&a, (uint64_t) 0xf0f0f0f000000000ULL, false);
	fr_value_box(&b, (uint64_t) 0x000000000f0f0f0fULL, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_OR, &b) == 0);
	TEST_CHECK(dst.vb_uint64 == 0xf0f0f0f00f0f0f0fULL);
	TEST_MSG("Expected 0xf0f0f0f00f0f0f0f, got 0x%" PRIx64, dst.vb_uint64);
}

static void test_uint64_xor(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT64, NULL, false);

	fr_value_box(&a, (uint64_t) 0xffffffffffffffffULL, false);
	fr_value_box(&b, (uint64_t) 0x0f0f0f0f0f0f0f0fULL, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_XOR, &b) == 0);
	TEST_CHECK(dst.vb_uint64 == 0xf0f0f0f0f0f0f0f0ULL);
	TEST_MSG("Expected 0xf0f0f0f0f0f0f0f0, got 0x%" PRIx64, dst.vb_uint64);
}

static void test_uint64_shift(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT64, NULL, false);

	fr_value_box(&a, (uint64_t) 0x100, false);
	fr_value_box(&b, (uint32_t) 8, false);

	/* left shift */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_LSHIFT, &b) == 0);
	TEST_CHECK(dst.vb_uint64 == 0x10000);
	TEST_MSG("Expected 0x10000, got 0x%" PRIx64, dst.vb_uint64);

	/* right shift */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_RSHIFT, &b) == 0);
	TEST_CHECK(dst.vb_uint64 == 0x01);
	TEST_MSG("Expected 0x01, got 0x%" PRIx64, dst.vb_uint64);
}

static void test_uint64_shift_too_large(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT64, NULL, false);

	fr_value_box(&a, (uint64_t) 1, false);
	fr_value_box(&b, (uint32_t) 64, false);  /* shift by >= bitsize is error */

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_LSHIFT, &b) < 0);
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_RSHIFT, &b) < 0);
}

static void test_uint64_mod(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT64, NULL, false);

	fr_value_box(&a, (uint64_t) 100, false);
	fr_value_box(&b, (uint64_t) 7, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_MOD, &b) == 0);
	TEST_CHECK(dst.vb_uint64 == 2);
	TEST_MSG("Expected 2, got %" PRIu64, dst.vb_uint64);
}

static void test_uint64_div(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT64, NULL, false);

	fr_value_box(&a, (uint64_t) 100, false);
	fr_value_box(&b, (uint64_t) 7, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_DIV, &b) == 0);
	TEST_CHECK(dst.vb_uint64 == 14);
	TEST_MSG("Expected 14, got %" PRIu64, dst.vb_uint64);
}

static void test_uint64_div_zero(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT64, NULL, false);

	fr_value_box(&a, (uint64_t) 100, false);
	fr_value_box(&b, (uint64_t) 0, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_DIV, &b) < 0);
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT64, &a, T_MOD, &b) < 0);
}

/*
 *	int8 tests
 */
static void test_int8_add(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT8, NULL, false);

	fr_value_box(&a, (int8_t) -50, false);
	fr_value_box(&b, (int8_t) 100, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT8, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.vb_int8 == 50);
	TEST_MSG("Expected 50, got %d", dst.vb_int8);
}

static void test_int8_sub(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT8, NULL, false);

	fr_value_box(&a, (int8_t) 50, false);
	fr_value_box(&b, (int8_t) 100, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT8, &a, T_SUB, &b) == 0);
	TEST_CHECK(dst.vb_int8 == -50);
	TEST_MSG("Expected -50, got %d", dst.vb_int8);
}

/*
 *	int16 tests
 */
static void test_int16_add(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT16, NULL, false);

	fr_value_box(&a, (int16_t) -1000, false);
	fr_value_box(&b, (int16_t) 2000, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT16, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.vb_int16 == 1000);
	TEST_MSG("Expected 1000, got %d", dst.vb_int16);
}

/*
 *	int32 additional ops
 */
static void test_int32_mod(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT32, NULL, false);

	fr_value_box(&a, (int32_t) -17, false);
	fr_value_box(&b, (int32_t) 5, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT32, &a, T_MOD, &b) == 0);
	TEST_CHECK(dst.vb_int32 == -2);
	TEST_MSG("Expected -2, got %d", dst.vb_int32);
}

/*
 *	int64 bitwise and shift
 */
static void test_int64_and(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT64, NULL, false);

	fr_value_box(&a, (int64_t) 0x0fff, false);
	fr_value_box(&b, (int64_t) 0x00ff, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT64, &a, T_AND, &b) == 0);
	TEST_CHECK(dst.vb_int64 == 0x00ff);
	TEST_MSG("Expected 0x00ff, got 0x%" PRIx64, dst.vb_int64);
}

static void test_int64_or(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT64, NULL, false);

	fr_value_box(&a, (int64_t) 0xf000, false);
	fr_value_box(&b, (int64_t) 0x000f, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT64, &a, T_OR, &b) == 0);
	TEST_CHECK(dst.vb_int64 == 0xf00f);
	TEST_MSG("Expected 0xf00f, got 0x%" PRIx64, dst.vb_int64);
}

static void test_int64_xor(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT64, NULL, false);

	fr_value_box(&a, (int64_t) 0xffff, false);
	fr_value_box(&b, (int64_t) 0x0f0f, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT64, &a, T_XOR, &b) == 0);
	TEST_CHECK(dst.vb_int64 == 0xf0f0);
	TEST_MSG("Expected 0xf0f0, got 0x%" PRIx64, dst.vb_int64);
}

static void test_int64_shift(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT64, NULL, false);

	fr_value_box(&a, (int64_t) 0x100, false);
	fr_value_box(&b, (uint32_t) 4, false);

	/* left shift */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT64, &a, T_LSHIFT, &b) == 0);
	TEST_CHECK(dst.vb_int64 == 0x1000);
	TEST_MSG("Expected 0x1000, got 0x%" PRIx64, dst.vb_int64);

	/* right shift */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT64, &a, T_RSHIFT, &b) == 0);
	TEST_CHECK(dst.vb_int64 == 0x10);
	TEST_MSG("Expected 0x10, got 0x%" PRIx64, dst.vb_int64);
}

static void test_int64_shift_too_large(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT64, NULL, false);

	fr_value_box(&a, (int64_t) 1, false);
	fr_value_box(&b, (uint32_t) 64, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT64, &a, T_LSHIFT, &b) < 0);
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT64, &a, T_RSHIFT, &b) < 0);
}

static void test_int64_mod(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_INT64, NULL, false);

	fr_value_box(&a, (int64_t) 100, false);
	fr_value_box(&b, (int64_t) 7, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_INT64, &a, T_MOD, &b) == 0);
	TEST_CHECK(dst.vb_int64 == 2);
	TEST_MSG("Expected 2, got %" PRId64, dst.vb_int64);
}

/*
 *	Float32 additional ops
 */
static void test_float32_sub(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT32, NULL, false);

	fr_value_box(&a, (float) 10.0f, false);
	fr_value_box(&b, (float) 3.5f, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_FLOAT32, &a, T_SUB, &b) == 0);
	TEST_CHECK(dst.vb_float32 == 6.5f);
	TEST_MSG("Expected 6.5, got %f", (double)dst.vb_float32);
}

static void test_float32_mul(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT32, NULL, false);

	fr_value_box(&a, (float) 3.0f, false);
	fr_value_box(&b, (float) 7.0f, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_FLOAT32, &a, T_MUL, &b) == 0);
	TEST_CHECK(dst.vb_float32 == 21.0f);
	TEST_MSG("Expected 21.0, got %f", (double)dst.vb_float32);
}

static void test_float32_div(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT32, NULL, false);

	fr_value_box(&a, (float) 21.0f, false);
	fr_value_box(&b, (float) 7.0f, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_FLOAT32, &a, T_DIV, &b) == 0);
	TEST_CHECK(dst.vb_float32 == 3.0f);
	TEST_MSG("Expected 3.0, got %f", (double)dst.vb_float32);
}

static void test_float32_mod(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT32, NULL, false);

	fr_value_box(&a, (float) 10.5f, false);
	fr_value_box(&b, (float) 3.0f, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_FLOAT32, &a, T_MOD, &b) == 0);
	TEST_CHECK((dst.vb_float32 > 1.49f) && (dst.vb_float32 < 1.51f));
	TEST_MSG("Expected ~1.5, got %f", (double)dst.vb_float32);
}

static void test_float32_mod_zero(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT32, NULL, false);

	fr_value_box(&a, (float) 10.0f, false);
	fr_value_box(&b, (float) 0.0f, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_FLOAT32, &a, T_MOD, &b) < 0);
}

static void test_float64_mod_zero(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT64, NULL, false);

	fr_value_box(&a, (double) 10.0, false);
	fr_value_box(&b, (double) 0.0, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_FLOAT64, &a, T_MOD, &b) < 0);
}

/*
 *	Bool mul (which acts as AND)
 */
static void test_bool_mul(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box(&a, (bool) true, false);
	fr_value_box(&b, (bool) true, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_MUL, &b) == 0);
	TEST_CHECK(dst.vb_bool == true);

	b.vb_bool = false;
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_MUL, &b) == 0);
	TEST_CHECK(dst.vb_bool == false);
}

/*
 *	String edge cases
 */
static void test_string_sub_too_long(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&b, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_STRING, NULL, false);

	fr_value_box_strdup(autofree, &a, NULL, "hi", false);
	fr_value_box_strdup(autofree, &b, NULL, "hello world", false);

	/* suffix to remove is longer than input */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_STRING, &a, T_SUB, &b) < 0);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
}

static void test_string_rshift_too_large(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_STRING, NULL, false);

	fr_value_box_strdup(autofree, &a, NULL, "hi", false);
	fr_value_box(&b, (uint32_t) 100, false);  /* more than string length */

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_STRING, &a, T_RSHIFT, &b) < 0);

	fr_value_box_clear(&a);
}

static void test_string_lshift_too_large(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_STRING, NULL, false);

	fr_value_box_strdup(autofree, &a, NULL, "hi", false);
	fr_value_box(&b, (uint32_t) 100, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_STRING, &a, T_LSHIFT, &b) < 0);

	fr_value_box_clear(&a);
}

static void test_string_add_empty(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&b, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_STRING, NULL, false);

	fr_value_box_strdup(autofree, &a, NULL, "hello", false);
	fr_value_box_strdup(autofree, &b, NULL, "", false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_STRING, &a, T_ADD, &b) == 0);
	TEST_CHECK(strcmp(dst.vb_strvalue, "hello") == 0);
	TEST_MSG("Expected 'hello', got '%s'", dst.vb_strvalue);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
	fr_value_box_clear(&dst);
}

/*
 *	Octets edge cases
 */
static void test_octets_sub_not_suffix(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&b, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_OCTETS, NULL, false);

	fr_value_box_memdup(autofree, &a, NULL, (uint8_t const *)"\x01\x02\x03\x04", 4, false);
	fr_value_box_memdup(autofree, &b, NULL, (uint8_t const *)"\x01\x02", 2, false);

	/* 0x0102 is not a suffix of 0x01020304 */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_OCTETS, &a, T_SUB, &b) < 0);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
}

static void test_octets_sub_too_long(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&b, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_OCTETS, NULL, false);

	fr_value_box_memdup(autofree, &a, NULL, (uint8_t const *)"\x01", 1, false);
	fr_value_box_memdup(autofree, &b, NULL, (uint8_t const *)"\x01\x02\x03", 3, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_OCTETS, &a, T_SUB, &b) < 0);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
}

static void test_octets_rshift_too_large(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_OCTETS, NULL, false);

	fr_value_box_memdup(autofree, &a, NULL, (uint8_t const *)"\x01\x02", 2, false);
	fr_value_box(&b, (uint32_t) 10, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_OCTETS, &a, T_RSHIFT, &b) < 0);

	fr_value_box_clear(&a);
}

static void test_octets_lshift_too_large(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_OCTETS, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_OCTETS, NULL, false);

	fr_value_box_memdup(autofree, &a, NULL, (uint8_t const *)"\x01\x02", 2, false);
	fr_value_box(&b, (uint32_t) 10, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_OCTETS, &a, T_LSHIFT, &b) < 0);

	fr_value_box_clear(&a);
}

/*
 *	Assignment compound ops
 */
static void test_assign_mul(void)
{
	fr_value_box_t dst, src;


	fr_value_box(&dst, (uint32_t) 6, false);
	fr_value_box(&src, (uint32_t) 7, false);

	TEST_CHECK(fr_value_calc_assignment_op(autofree, &dst, T_OP_MUL_EQ, &src) == 0);
	TEST_CHECK(dst.vb_uint32 == 42);
	TEST_MSG("Expected 42, got %u", dst.vb_uint32);
}

static void test_assign_div(void)
{
	fr_value_box_t dst, src;


	fr_value_box(&dst, (uint32_t) 42, false);
	fr_value_box(&src, (uint32_t) 6, false);

	TEST_CHECK(fr_value_calc_assignment_op(autofree, &dst, T_OP_DIV_EQ, &src) == 0);
	TEST_CHECK(dst.vb_uint32 == 7);
	TEST_MSG("Expected 7, got %u", dst.vb_uint32);
}

static void test_assign_and(void)
{
	fr_value_box_t dst, src;


	fr_value_box(&dst, (uint32_t) 0xff, false);
	fr_value_box(&src, (uint32_t) 0x0f, false);

	TEST_CHECK(fr_value_calc_assignment_op(autofree, &dst, T_OP_AND_EQ, &src) == 0);
	TEST_CHECK(dst.vb_uint32 == 0x0f);
	TEST_MSG("Expected 0x0f, got 0x%x", dst.vb_uint32);
}

static void test_assign_or(void)
{
	fr_value_box_t dst, src;


	fr_value_box(&dst, (uint32_t) 0xf0, false);
	fr_value_box(&src, (uint32_t) 0x0f, false);

	TEST_CHECK(fr_value_calc_assignment_op(autofree, &dst, T_OP_OR_EQ, &src) == 0);
	TEST_CHECK(dst.vb_uint32 == 0xff);
	TEST_MSG("Expected 0xff, got 0x%x", dst.vb_uint32);
}

static void test_assign_xor(void)
{
	fr_value_box_t dst, src;


	fr_value_box(&dst, (uint32_t) 0xff, false);
	fr_value_box(&src, (uint32_t) 0x0f, false);

	TEST_CHECK(fr_value_calc_assignment_op(autofree, &dst, T_OP_XOR_EQ, &src) == 0);
	TEST_CHECK(dst.vb_uint32 == 0xf0);
	TEST_MSG("Expected 0xf0, got 0x%x", dst.vb_uint32);
}

static void test_assign_rshift(void)
{
	fr_value_box_t dst, src;


	fr_value_box(&dst, (uint32_t) 0x100, false);
	fr_value_box(&src, (uint32_t) 4, false);

	TEST_CHECK(fr_value_calc_assignment_op(autofree, &dst, T_OP_RSHIFT_EQ, &src) == 0);
	TEST_CHECK(dst.vb_uint32 == 0x10);
	TEST_MSG("Expected 0x10, got 0x%x", dst.vb_uint32);
}

static void test_assign_lshift(void)
{
	fr_value_box_t dst, src;


	fr_value_box(&dst, (uint32_t) 0x10, false);
	fr_value_box(&src, (uint32_t) 4, false);

	TEST_CHECK(fr_value_calc_assignment_op(autofree, &dst, T_OP_LSHIFT_EQ, &src) == 0);
	TEST_CHECK(dst.vb_uint32 == 0x100);
	TEST_MSG("Expected 0x100, got 0x%x", dst.vb_uint32);
}

/*
 *	Unary tests on additional types
 */
static void test_unary_complement_uint16(void)
{
	fr_value_box_t src, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT16, NULL, false);

	fr_value_box(&src, (uint16_t) 0x00ff, false);

	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_COMPLEMENT, &src) == 0);
	TEST_CHECK(dst.vb_uint16 == 0xff00);
	TEST_MSG("Expected 0xff00, got 0x%04x", dst.vb_uint16);
}

static void test_unary_complement_uint32(void)
{
	fr_value_box_t src, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&src, (uint32_t) 0x0000ffff, false);

	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_COMPLEMENT, &src) == 0);
	TEST_CHECK(dst.vb_uint32 == 0xffff0000);
	TEST_MSG("Expected 0xffff0000, got 0x%08x", dst.vb_uint32);
}

static void test_unary_complement_uint64(void)
{
	fr_value_box_t src, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT64, NULL, false);

	fr_value_box(&src, (uint64_t) 0, false);

	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_COMPLEMENT, &src) == 0);
	TEST_CHECK(dst.vb_uint64 == UINT64_MAX);
	TEST_MSG("Expected UINT64_MAX, got 0x%" PRIx64, dst.vb_uint64);
}

static void test_unary_complement_int32(void)
{
	fr_value_box_t src, dst;

	fr_value_box_init(&dst, FR_TYPE_INT32, NULL, false);

	fr_value_box(&src, (int32_t) 0, false);

	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_COMPLEMENT, &src) == 0);
	TEST_CHECK(dst.vb_int32 == -1);
	TEST_MSG("Expected -1, got %d", dst.vb_int32);
}

static void test_unary_negate_float64(void)
{
	fr_value_box_t src, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT64, NULL, false);

	fr_value_box(&src, (double) 3.14, false);

	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_SUB, &src) == 0);
	TEST_CHECK((dst.vb_float64 > -3.15) && (dst.vb_float64 < -3.13));
	TEST_MSG("Expected -3.14, got %f", dst.vb_float64);
}

static void test_unary_increment_uint8(void)
{
	fr_value_box_t src, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT8, NULL, false);

	fr_value_box(&src, (uint8_t) 254, false);

	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_OP_INCRM, &src) == 0);
	TEST_CHECK(dst.vb_uint8 == 255);
	TEST_MSG("Expected 255, got %u", dst.vb_uint8);
}

static void test_unary_increment_overflow(void)
{
	fr_value_box_t src, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT8, NULL, false);

	fr_value_box(&src, (uint8_t) 255, false);

	/* 255 + 1 overflows uint8 */
	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_OP_INCRM, &src) < 0);
}

static void test_unary_not_bool(void)
{
	fr_value_box_t src, dst;

	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box(&src, (bool) true, false);

	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_NOT, &src) == 0);
	TEST_CHECK(dst.vb_bool == false);

	src.vb_bool = false;
	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_NOT, &src) == 0);
	TEST_CHECK(dst.vb_bool == true);
}

static void test_unary_increment_int64(void)
{
	fr_value_box_t src, dst;

	fr_value_box_init(&dst, FR_TYPE_INT64, NULL, false);

	fr_value_box(&src, (int64_t) -1, false);

	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_OP_INCRM, &src) == 0);
	TEST_CHECK(dst.vb_int64 == 0);
	TEST_MSG("Expected 0, got %" PRId64, dst.vb_int64);
}

static void test_unary_increment_float64(void)
{
	fr_value_box_t src, dst;

	fr_value_box_init(&dst, FR_TYPE_FLOAT64, NULL, false);

	fr_value_box(&src, (double) 2.5, false);

	TEST_CHECK(fr_value_calc_unary_op(autofree, &dst, T_OP_INCRM, &src) == 0);
	TEST_CHECK(dst.vb_float64 == 3.5);
	TEST_MSG("Expected 3.5, got %f", dst.vb_float64);
}

/*
 *	Auto type hint for subtract
 */
static void test_auto_type_hint_sub(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init_null(&dst);

	fr_value_box(&a, (uint32_t) 30, false);
	fr_value_box(&b, (uint32_t) 10, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_NULL, &a, T_SUB, &b) == 0);
	TEST_CHECK(dst.type == FR_TYPE_UINT64);
	TEST_CHECK(dst.vb_uint64 == 20);
	TEST_MSG("Expected 20, got %" PRIu64, dst.vb_uint64);
}

/*
 *	Auto type hint for lshift
 */
static void test_auto_type_hint_lshift(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init_null(&dst);

	fr_value_box(&a, (uint32_t) 1, false);
	fr_value_box(&b, (uint32_t) 8, false);

	/* auto type hint for lshift on unsigned should become uint64 */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_NULL, &a, T_LSHIFT, &b) == 0);
	TEST_CHECK(dst.type == FR_TYPE_UINT64);
	TEST_CHECK(dst.vb_uint64 == 256);
	TEST_MSG("Expected 256, got %" PRIu64, dst.vb_uint64);
}

/*
 *	Mixed signed and unsigned
 */
static void test_mixed_uint32_int32(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init_null(&dst);

	fr_value_box(&a, (uint32_t) 10, false);
	fr_value_box(&b, (int32_t) -3, false);

	/* uint32 + int32 should upcast to int64 */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_NULL, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.type == FR_TYPE_INT64);
	TEST_CHECK(dst.vb_int64 == 7);
	TEST_MSG("Expected 7, got %" PRId64, dst.vb_int64);
}

/*
 *	Tainted propagation from b
 */
static void test_tainted_from_b(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&a, (uint32_t) 10, false);
	fr_value_box(&b, (uint32_t) 20, true);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.vb_uint32 == 30);
	TEST_CHECK(dst.tainted == true);
	TEST_MSG("Expected tainted to be true when b is tainted");
}

static void test_tainted_neither(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&a, (uint32_t) 10, false);
	fr_value_box(&b, (uint32_t) 20, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.tainted == false);
	TEST_MSG("Expected tainted to be false when neither is tainted");
}

/*
 *	IPv4 prefix add overflow
 */
static void test_ipv4_prefix_add_overflow(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_IPV4_PREFIX, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_IPV4_ADDR, NULL, false);

	/* 10.0.0.0/24 + 256 = overflow (only 256 addresses in /24, 0..255) */
	a.vb_ip.af = AF_INET;
	a.vb_ipv4addr = htonl(0x0a000000);  /* 10.0.0.0 */
	a.vb_ip.prefix = 24;
	fr_value_box(&b, (uint32_t) 256, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_IPV4_ADDR, &a, T_ADD, &b) < 0);
}

/*
 *	IPv4 and with all-ones mask
 */
static void test_ipv4_addr_and_all_ones(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_IPV4_ADDR, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_IPV4_PREFIX, NULL, false);

	a.vb_ip.af = AF_INET;
	a.vb_ipv4addr = htonl(0xc0a80164);  /* 192.168.1.100 */
	a.vb_ip.prefix = 32;
	fr_value_box(&b, (uint32_t) 0xffffffff, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_IPV4_PREFIX, &a, T_AND, &b) == 0);
	TEST_CHECK(ntohl(dst.vb_ipv4addr) == 0xc0a80164);
	TEST_CHECK(dst.vb_ip.prefix == 32);
}

static void test_ipv4_addr_and_zero(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_IPV4_ADDR, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_IPV4_PREFIX, NULL, false);

	a.vb_ip.af = AF_INET;
	a.vb_ipv4addr = htonl(0xc0a80164);
	a.vb_ip.prefix = 32;
	fr_value_box(&b, (uint32_t) 0, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_IPV4_PREFIX, &a, T_AND, &b) == 0);
	TEST_CHECK(ntohl(dst.vb_ipv4addr) == 0);
	TEST_CHECK(dst.vb_ip.prefix == 0);
}

/*
 *	Auto type hint for rshift
 */
static void test_auto_type_hint_rshift(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init_null(&dst);

	fr_value_box(&a, (uint32_t) 0x100, false);
	fr_value_box(&b, (uint32_t) 4, false);

	/* auto type hint for rshift should keep the LHS type */
	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_NULL, &a, T_RSHIFT, &b) == 0);
	TEST_CHECK(dst.type == FR_TYPE_UINT32);
	TEST_CHECK(dst.vb_uint32 == 0x10);
	TEST_MSG("Expected 0x10, got 0x%x", dst.vb_uint32);
}

/*
 *	String comparison
 */
static void test_cmp_string(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&b, FR_TYPE_STRING, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_BOOL, NULL, false);

	fr_value_box_strdup(autofree, &a, NULL, "abc", false);
	fr_value_box_strdup(autofree, &b, NULL, "abc", false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_CMP_EQ, &b) == 1);
	TEST_CHECK(dst.vb_bool == true);

	fr_value_box_clear(&b);
	fr_value_box_strdup(autofree, &b, NULL, "def", false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_BOOL, &a, T_OP_LT, &b) == 1);
	TEST_CHECK(dst.vb_bool == true);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
}

/*
 *	IPv4 prefix + integer = address
 */
static void test_ipv4_prefix_add(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_IPV4_PREFIX, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_IPV4_ADDR, NULL, false);

	/* 192.168.0.0/24 + 1 = 192.168.0.1 */
	a.vb_ip.af = AF_INET;
	a.vb_ipv4addr = htonl(0xc0a80000);  /* 192.168.0.0 */
	a.vb_ip.prefix = 24;
	fr_value_box(&b, (uint32_t) 1, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_IPV4_ADDR, &a, T_ADD, &b) == 0);
	TEST_CHECK(ntohl(dst.vb_ipv4addr) == 0xc0a80001);  /* 192.168.0.1 */
	TEST_MSG("Expected 192.168.0.1, got 0x%08x", ntohl(dst.vb_ipv4addr));
}

/*
 *	IPv4 address AND mask = prefix
 */
static void test_ipv4_addr_and_mask(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&a, FR_TYPE_IPV4_ADDR, NULL, false);
	fr_value_box_init(&dst, FR_TYPE_IPV4_PREFIX, NULL, false);

	/* 192.168.1.100 & 0xffffff00 = 192.168.1.0/24 */
	a.vb_ip.af = AF_INET;
	a.vb_ipv4addr = htonl(0xc0a80164);  /* 192.168.1.100 */
	a.vb_ip.prefix = 32;
	fr_value_box(&b, (uint32_t) 0xffffff00, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_IPV4_PREFIX, &a, T_AND, &b) == 0);
	TEST_CHECK(ntohl(dst.vb_ipv4addr) == 0xc0a80100);  /* 192.168.1.0 */
	TEST_CHECK(dst.vb_ip.prefix == 24);
	TEST_MSG("Expected prefix 24, got %u", dst.vb_ip.prefix);
}

/*
 *	Tainted flag propagation
 */
static void test_tainted_propagation(void)
{
	fr_value_box_t a, b, dst;

	fr_value_box_init(&dst, FR_TYPE_UINT32, NULL, false);

	fr_value_box(&a, (uint32_t) 10, true);
	fr_value_box(&b, (uint32_t) 20, false);

	TEST_CHECK(fr_value_calc_binary_op(autofree, &dst, FR_TYPE_UINT32, &a, T_ADD, &b) == 0);
	TEST_CHECK(dst.vb_uint32 == 30);
	TEST_CHECK(dst.tainted == true);
	TEST_MSG("Expected tainted to be true");
}

TEST_LIST = {
	/* uint32 arithmetic */
	{ "uint32_add",			test_uint32_add },
	{ "uint32_sub",			test_uint32_sub },
	{ "uint32_mul",			test_uint32_mul },
	{ "uint32_div",			test_uint32_div },
	{ "uint32_mod",			test_uint32_mod },
	{ "uint32_and",			test_uint32_and },
	{ "uint32_or",			test_uint32_or },
	{ "uint32_xor",			test_uint32_xor },
	{ "uint32_shift",		test_uint32_shift },
	{ "uint32_div_zero",		test_uint32_div_zero },

	/* uint8 */
	{ "uint8_add",			test_uint8_add },
	{ "uint8_overflow",		test_uint8_overflow },

	/* uint16 */
	{ "uint16_add",			test_uint16_add },
	{ "uint16_overflow",		test_uint16_overflow },

	/* uint64 */
	{ "uint64_and",			test_uint64_and },
	{ "uint64_or",			test_uint64_or },
	{ "uint64_xor",			test_uint64_xor },
	{ "uint64_shift",		test_uint64_shift },
	{ "uint64_shift_too_large",	test_uint64_shift_too_large },
	{ "uint64_mod",			test_uint64_mod },
	{ "uint64_div",			test_uint64_div },
	{ "uint64_div_zero",		test_uint64_div_zero },

	/* signed integers */
	{ "int8_add",			test_int8_add },
	{ "int8_sub",			test_int8_sub },
	{ "int16_add",			test_int16_add },
	{ "int32_add",			test_int32_add },
	{ "int32_sub",			test_int32_sub },
	{ "int32_mul",			test_int32_mul },
	{ "int32_div",			test_int32_div },
	{ "int32_mod",			test_int32_mod },
	{ "int64_div_zero",		test_int64_div_zero },
	{ "int64_and",			test_int64_and },
	{ "int64_or",			test_int64_or },
	{ "int64_xor",			test_int64_xor },
	{ "int64_shift",		test_int64_shift },
	{ "int64_shift_too_large",	test_int64_shift_too_large },
	{ "int64_mod",			test_int64_mod },

	/* booleans */
	{ "bool_and",			test_bool_and },
	{ "bool_or",			test_bool_or },
	{ "bool_xor",			test_bool_xor },
	{ "bool_add",			test_bool_add },
	{ "bool_sub",			test_bool_sub },
	{ "bool_mul",			test_bool_mul },

	/* float64 */
	{ "float64_add",		test_float64_add },
	{ "float64_sub",		test_float64_sub },
	{ "float64_mul",		test_float64_mul },
	{ "float64_div",		test_float64_div },
	{ "float64_div_zero",		test_float64_div_zero },
	{ "float64_mod",		test_float64_mod },
	{ "float64_mod_zero",		test_float64_mod_zero },

	/* float32 */
	{ "float32_add",		test_float32_add },
	{ "float32_sub",		test_float32_sub },
	{ "float32_mul",		test_float32_mul },
	{ "float32_div",		test_float32_div },
	{ "float32_div_zero",		test_float32_div_zero },
	{ "float32_mod",		test_float32_mod },
	{ "float32_mod_zero",		test_float32_mod_zero },

	/* strings */
	{ "string_add",			test_string_add },
	{ "string_add_empty",		test_string_add_empty },
	{ "string_sub",			test_string_sub },
	{ "string_sub_not_suffix",	test_string_sub_not_suffix },
	{ "string_sub_too_long",	test_string_sub_too_long },
	{ "string_xor_prepend",	test_string_xor_prepend },
	{ "string_rshift",		test_string_rshift },
	{ "string_lshift",		test_string_lshift },
	{ "string_rshift_too_large",	test_string_rshift_too_large },
	{ "string_lshift_too_large",	test_string_lshift_too_large },

	/* octets */
	{ "octets_add",			test_octets_add },
	{ "octets_sub",			test_octets_sub },
	{ "octets_sub_not_suffix",	test_octets_sub_not_suffix },
	{ "octets_sub_too_long",	test_octets_sub_too_long },
	{ "octets_and",			test_octets_and },
	{ "octets_or",			test_octets_or },
	{ "octets_xor",			test_octets_xor },
	{ "octets_length_mismatch",	test_octets_length_mismatch },
	{ "octets_rshift",		test_octets_rshift },
	{ "octets_lshift",		test_octets_lshift },
	{ "octets_rshift_too_large",	test_octets_rshift_too_large },
	{ "octets_lshift_too_large",	test_octets_lshift_too_large },

	/* comparisons */
	{ "cmp_eq",			test_cmp_eq },
	{ "cmp_ne",			test_cmp_ne },
	{ "cmp_lt",			test_cmp_lt },
	{ "cmp_gt",			test_cmp_gt },
	{ "cmp_le",			test_cmp_le },
	{ "cmp_ge",			test_cmp_ge },
	{ "cmp_eq_type",		test_cmp_eq_type },
	{ "auto_type_hint_rshift",	test_auto_type_hint_rshift },
	{ "cmp_different_types",	test_cmp_different_types },
	{ "cmp_string",			test_cmp_string },

	/* unary */
	{ "unary_increment",		test_unary_increment },
	{ "unary_increment_uint8",	test_unary_increment_uint8 },
	{ "unary_increment_overflow",	test_unary_increment_overflow },
	{ "unary_increment_int64",	test_unary_increment_int64 },
	{ "unary_increment_float64",	test_unary_increment_float64 },
	{ "unary_complement",		test_unary_complement },
	{ "unary_complement_uint16",	test_unary_complement_uint16 },
	{ "unary_complement_uint32",	test_unary_complement_uint32 },
	{ "unary_complement_uint64",	test_unary_complement_uint64 },
	{ "unary_complement_int32",	test_unary_complement_int32 },
	{ "unary_negate",		test_unary_negate },
	{ "unary_negate_float64",	test_unary_negate_float64 },
	{ "unary_not",			test_unary_not },
	{ "unary_not_bool",		test_unary_not_bool },

	/* assignment */
	{ "assign_add",			test_assign_add },
	{ "assign_sub",			test_assign_sub },
	{ "assign_mul",			test_assign_mul },
	{ "assign_div",			test_assign_div },
	{ "assign_and",			test_assign_and },
	{ "assign_or",			test_assign_or },
	{ "assign_xor",			test_assign_xor },
	{ "assign_rshift",		test_assign_rshift },
	{ "assign_lshift",		test_assign_lshift },
	{ "assign_set",			test_assign_set },
	{ "assign_self",		test_assign_self },

	/* type coercion */
	{ "mixed_uint8_uint32",		test_mixed_uint8_uint32 },
	{ "mixed_uint32_int32",		test_mixed_uint32_int32 },
	{ "auto_type_hint",		test_auto_type_hint },
	{ "auto_type_hint_sub",		test_auto_type_hint_sub },
	{ "auto_type_hint_lshift",	test_auto_type_hint_lshift },

	/* overflow / underflow */
	{ "uint64_overflow",		test_uint64_overflow },
	{ "uint64_underflow",		test_uint64_underflow },
	{ "uint64_mul_overflow",	test_uint64_mul_overflow },
	{ "int64_overflow",		test_int64_overflow },
	{ "int64_underflow",		test_int64_underflow },

	/* IPv4 */
	{ "ipv4_prefix_add",		test_ipv4_prefix_add },
	{ "ipv4_prefix_add_overflow",	test_ipv4_prefix_add_overflow },
	{ "ipv4_addr_and_mask",		test_ipv4_addr_and_mask },
	{ "ipv4_addr_and_all_ones",	test_ipv4_addr_and_all_ones },
	{ "ipv4_addr_and_zero",		test_ipv4_addr_and_zero },

	/* misc */
	{ "tainted_propagation",	test_tainted_propagation },
	{ "tainted_from_b",		test_tainted_from_b },
	{ "tainted_neither",		test_tainted_neither },

	TEST_TERMINATOR
};
