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

/** Tests for value box functions
 *
 * @file src/lib/util/test/value_tests.c
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */

#include "acutest.h"
#include "acutest_helpers.h"

#include <freeradius-devel/util/value.h>

static TALLOC_CTX *autofree;

static void test_init(void) __attribute__((constructor));
static void test_init(void)
{
	autofree = talloc_autofree_context();
	if (!autofree) {
		fr_perror("value_tests");
		fr_exit_now(EXIT_FAILURE);
	}

	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("value_tests");
		fr_exit_now(EXIT_FAILURE);
	}
}

/*
 *	Comparison tests (fr_value_box_cmp)
 */
static void test_cmp_uint32_equal(void)
{
	fr_value_box_t a, b;

	fr_value_box(&a, (uint32_t) 42, false);
	fr_value_box(&b, (uint32_t) 42, false);

	TEST_CHECK(fr_value_box_cmp(&a, &b) == 0);
}

static void test_cmp_uint32_less(void)
{
	fr_value_box_t a, b;

	fr_value_box(&a, (uint32_t) 10, false);
	fr_value_box(&b, (uint32_t) 20, false);

	TEST_CHECK(fr_value_box_cmp(&a, &b) == -1);
	TEST_CHECK(fr_value_box_cmp(&b, &a) == 1);
}

static void test_cmp_int32(void)
{
	fr_value_box_t a, b;

	fr_value_box(&a, (int32_t) -10, false);
	fr_value_box(&b, (int32_t) 10, false);

	TEST_CHECK(fr_value_box_cmp(&a, &b) == -1);
	TEST_CHECK(fr_value_box_cmp(&b, &a) == 1);

	fr_value_box(&b, (int32_t) -10, false);
	TEST_CHECK(fr_value_box_cmp(&a, &b) == 0);
}

static void test_cmp_float64(void)
{
	fr_value_box_t a, b;

	fr_value_box(&a, (double) 3.14, false);
	fr_value_box(&b, (double) 2.71, false);

	TEST_CHECK(fr_value_box_cmp(&a, &b) == 1);
	TEST_CHECK(fr_value_box_cmp(&b, &a) == -1);

	fr_value_box(&b, (double) 3.14, false);
	TEST_CHECK(fr_value_box_cmp(&a, &b) == 0);
}

static void test_cmp_string(void)
{
	fr_value_box_t a, b;

	fr_value_box_strdup(autofree, &a, NULL, "apple", false);
	fr_value_box_strdup(autofree, &b, NULL, "banana", false);

	TEST_CHECK(fr_value_box_cmp(&a, &b) == -1);
	TEST_CHECK(fr_value_box_cmp(&b, &a) == 1);

	fr_value_box_clear(&b);
	fr_value_box_strdup(autofree, &b, NULL, "apple", false);
	TEST_CHECK(fr_value_box_cmp(&a, &b) == 0);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
}

static void test_cmp_octets(void)
{
	fr_value_box_t a, b;

	fr_value_box_memdup(autofree, &a, NULL, (uint8_t const *)"\x01\x02", 2, false);
	fr_value_box_memdup(autofree, &b, NULL, (uint8_t const *)"\x01\x03", 2, false);

	TEST_CHECK(fr_value_box_cmp(&a, &b) == -1);
	TEST_CHECK(fr_value_box_cmp(&b, &a) == 1);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
}

static void test_cmp_octets_length(void)
{
	fr_value_box_t a, b;

	/* Same prefix but different length: shorter is "less" */
	fr_value_box_memdup(autofree, &a, NULL, (uint8_t const *)"\x01", 1, false);
	fr_value_box_memdup(autofree, &b, NULL, (uint8_t const *)"\x01\x02", 2, false);

	TEST_CHECK(fr_value_box_cmp(&a, &b) == -1);
	TEST_CHECK(fr_value_box_cmp(&b, &a) == 1);

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
}

static void test_cmp_bool(void)
{
	fr_value_box_t a, b;

	fr_value_box(&a, (bool) true, false);
	fr_value_box(&b, (bool) false, false);

	TEST_CHECK(fr_value_box_cmp(&a, &b) == 1);
	TEST_CHECK(fr_value_box_cmp(&b, &a) == -1);

	fr_value_box(&b, (bool) true, false);
	TEST_CHECK(fr_value_box_cmp(&a, &b) == 0);
}

static void test_cmp_different_types(void)
{
	fr_value_box_t a, b;

	fr_value_box(&a, (uint32_t) 42, false);
	fr_value_box(&b, (uint64_t) 42, false);

	/* Different types should return < -1 (error) */
	TEST_CHECK(fr_value_box_cmp(&a, &b) < -1);
}

/*
 *	Comparison operator tests (fr_value_box_cmp_op)
 */
static void test_cmp_op_eq(void)
{
	fr_value_box_t a, b;

	fr_value_box(&a, (uint32_t) 42, false);
	fr_value_box(&b, (uint32_t) 42, false);

	TEST_CHECK(fr_value_box_cmp_op(T_OP_CMP_EQ, &a, &b) == 1);

	fr_value_box(&b, (uint32_t) 43, false);
	TEST_CHECK(fr_value_box_cmp_op(T_OP_CMP_EQ, &a, &b) == 0);
}

static void test_cmp_op_ne(void)
{
	fr_value_box_t a, b;

	fr_value_box(&a, (uint32_t) 42, false);
	fr_value_box(&b, (uint32_t) 43, false);

	TEST_CHECK(fr_value_box_cmp_op(T_OP_NE, &a, &b) == 1);

	fr_value_box(&b, (uint32_t) 42, false);
	TEST_CHECK(fr_value_box_cmp_op(T_OP_NE, &a, &b) == 0);
}

static void test_cmp_op_lt(void)
{
	fr_value_box_t a, b;

	fr_value_box(&a, (uint32_t) 10, false);
	fr_value_box(&b, (uint32_t) 20, false);

	TEST_CHECK(fr_value_box_cmp_op(T_OP_LT, &a, &b) == 1);
	TEST_CHECK(fr_value_box_cmp_op(T_OP_LT, &b, &a) == 0);
	TEST_CHECK(fr_value_box_cmp_op(T_OP_LT, &a, &a) == 0);
}

static void test_cmp_op_gt(void)
{
	fr_value_box_t a, b;

	fr_value_box(&a, (uint32_t) 20, false);
	fr_value_box(&b, (uint32_t) 10, false);

	TEST_CHECK(fr_value_box_cmp_op(T_OP_GT, &a, &b) == 1);
	TEST_CHECK(fr_value_box_cmp_op(T_OP_GT, &b, &a) == 0);
}

static void test_cmp_op_le(void)
{
	fr_value_box_t a, b;

	fr_value_box(&a, (uint32_t) 10, false);
	fr_value_box(&b, (uint32_t) 20, false);

	TEST_CHECK(fr_value_box_cmp_op(T_OP_LE, &a, &b) == 1);
	TEST_CHECK(fr_value_box_cmp_op(T_OP_LE, &b, &a) == 0);

	fr_value_box(&b, (uint32_t) 10, false);
	TEST_CHECK(fr_value_box_cmp_op(T_OP_LE, &a, &b) == 1);
}

static void test_cmp_op_ge(void)
{
	fr_value_box_t a, b;

	fr_value_box(&a, (uint32_t) 20, false);
	fr_value_box(&b, (uint32_t) 10, false);

	TEST_CHECK(fr_value_box_cmp_op(T_OP_GE, &a, &b) == 1);
	TEST_CHECK(fr_value_box_cmp_op(T_OP_GE, &b, &a) == 0);

	fr_value_box(&b, (uint32_t) 20, false);
	TEST_CHECK(fr_value_box_cmp_op(T_OP_GE, &a, &b) == 1);
}

/*
 *	Cast tests (fr_value_box_cast)
 */
static void test_cast_uint32_to_uint64(void)
{
	fr_value_box_t src, dst;

	fr_value_box(&src, (uint32_t) 42, false);
	fr_value_box_init_null(&dst);

	TEST_CHECK(fr_value_box_cast(autofree, &dst, FR_TYPE_UINT64, NULL, &src) == 0);
	TEST_CHECK(dst.type == FR_TYPE_UINT64);
	TEST_CHECK(dst.vb_uint64 == 42);
}

static void test_cast_uint32_to_string(void)
{
	fr_value_box_t src, dst;

	fr_value_box(&src, (uint32_t) 12345, false);
	fr_value_box_init_null(&dst);

	TEST_CHECK(fr_value_box_cast(autofree, &dst, FR_TYPE_STRING, NULL, &src) == 0);
	TEST_CHECK(dst.type == FR_TYPE_STRING);
	TEST_CHECK_STRCMP(dst.vb_strvalue, "12345");

	fr_value_box_clear(&dst);
}

static void test_cast_string_to_uint32(void)
{
	fr_value_box_t src, dst;

	fr_value_box_strdup(autofree, &src, NULL, "12345", false);
	fr_value_box_init_null(&dst);

	TEST_CHECK(fr_value_box_cast(autofree, &dst, FR_TYPE_UINT32, NULL, &src) >= 0);
	TEST_CHECK(dst.type == FR_TYPE_UINT32);
	TEST_CHECK(dst.vb_uint32 == 12345);
	TEST_MSG("Expected 12345, got %u", dst.vb_uint32);

	fr_value_box_clear(&src);
}

static void test_cast_int32_to_int64(void)
{
	fr_value_box_t src, dst;

	fr_value_box(&src, (int32_t) -42, false);
	fr_value_box_init_null(&dst);

	TEST_CHECK(fr_value_box_cast(autofree, &dst, FR_TYPE_INT64, NULL, &src) == 0);
	TEST_CHECK(dst.type == FR_TYPE_INT64);
	TEST_CHECK(dst.vb_int64 == -42);
}

static void test_cast_uint8_to_uint32(void)
{
	fr_value_box_t src, dst;

	fr_value_box(&src, (uint8_t) 255, false);
	fr_value_box_init_null(&dst);

	TEST_CHECK(fr_value_box_cast(autofree, &dst, FR_TYPE_UINT32, NULL, &src) == 0);
	TEST_CHECK(dst.type == FR_TYPE_UINT32);
	TEST_CHECK(dst.vb_uint32 == 255);
}

static void test_cast_same_type(void)
{
	fr_value_box_t src, dst;

	fr_value_box(&src, (uint32_t) 42, false);
	fr_value_box_init_null(&dst);

	TEST_CHECK(fr_value_box_cast(autofree, &dst, FR_TYPE_UINT32, NULL, &src) == 0);
	TEST_CHECK(dst.type == FR_TYPE_UINT32);
	TEST_CHECK(dst.vb_uint32 == 42);
}

static void test_cast_bool_to_uint32(void)
{
	fr_value_box_t src, dst;

	fr_value_box(&src, (bool) true, false);
	fr_value_box_init_null(&dst);

	TEST_CHECK(fr_value_box_cast(autofree, &dst, FR_TYPE_UINT32, NULL, &src) == 0);
	TEST_CHECK(dst.vb_uint32 == 1);

	fr_value_box(&src, (bool) false, false);
	TEST_CHECK(fr_value_box_cast(autofree, &dst, FR_TYPE_UINT32, NULL, &src) == 0);
	TEST_CHECK(dst.vb_uint32 == 0);
}

static void test_cast_uint32_to_bool(void)
{
	fr_value_box_t src, dst;

	fr_value_box(&src, (uint32_t) 1, false);
	fr_value_box_init_null(&dst);

	TEST_CHECK(fr_value_box_cast(autofree, &dst, FR_TYPE_BOOL, NULL, &src) == 0);
	TEST_CHECK(dst.vb_bool == true);

	fr_value_box(&src, (uint32_t) 0, false);
	TEST_CHECK(fr_value_box_cast(autofree, &dst, FR_TYPE_BOOL, NULL, &src) == 0);
	TEST_CHECK(dst.vb_bool == false);
}

/*
 *	Cast in place tests
 */
static void test_cast_in_place_uint32_to_uint64(void)
{
	fr_value_box_t vb;

	fr_value_box(&vb, (uint32_t) 42, false);

	TEST_CHECK(fr_value_box_cast_in_place(autofree, &vb, FR_TYPE_UINT64, NULL) == 0);
	TEST_CHECK(vb.type == FR_TYPE_UINT64);
	TEST_CHECK(vb.vb_uint64 == 42);
}

static void test_cast_in_place_uint32_to_string(void)
{
	fr_value_box_t vb;

	fr_value_box(&vb, (uint32_t) 12345, false);

	TEST_CHECK(fr_value_box_cast_in_place(autofree, &vb, FR_TYPE_STRING, NULL) == 0);
	TEST_CHECK(vb.type == FR_TYPE_STRING);
	TEST_CHECK_STRCMP(vb.vb_strvalue, "12345");

	fr_value_box_clear(&vb);
}

/*
 *	Copy tests
 */
static void test_copy_uint32(void)
{
	fr_value_box_t src, dst;

	fr_value_box(&src, (uint32_t) 42, false);
	fr_value_box_init_null(&dst);

	TEST_CHECK(fr_value_box_copy(autofree, &dst, &src) == 0);
	TEST_CHECK(dst.type == FR_TYPE_UINT32);
	TEST_CHECK(dst.vb_uint32 == 42);
}

static void test_copy_string(void)
{
	fr_value_box_t src, dst;

	fr_value_box_strdup(autofree, &src, NULL, "hello", false);
	fr_value_box_init_null(&dst);

	TEST_CHECK(fr_value_box_copy(autofree, &dst, &src) == 0);
	TEST_CHECK(dst.type == FR_TYPE_STRING);
	TEST_CHECK_STRCMP(dst.vb_strvalue, "hello");

	/* Deep copy: different pointer */
	TEST_CHECK(dst.vb_strvalue != src.vb_strvalue);

	fr_value_box_clear(&src);
	fr_value_box_clear(&dst);
}

static void test_copy_octets(void)
{
	fr_value_box_t src, dst;

	fr_value_box_memdup(autofree, &src, NULL, (uint8_t const *)"\x01\x02\x03", 3, false);
	fr_value_box_init_null(&dst);

	TEST_CHECK(fr_value_box_copy(autofree, &dst, &src) == 0);
	TEST_CHECK(dst.type == FR_TYPE_OCTETS);
	TEST_CHECK(dst.vb_length == 3);
	TEST_CHECK(memcmp(dst.vb_octets, "\x01\x02\x03", 3) == 0);

	/* Deep copy */
	TEST_CHECK(dst.vb_octets != src.vb_octets);

	fr_value_box_clear(&src);
	fr_value_box_clear(&dst);
}

static void test_copy_preserves_tainted(void)
{
	fr_value_box_t src, dst;

	fr_value_box(&src, (uint32_t) 42, true);
	fr_value_box_init_null(&dst);

	TEST_CHECK(fr_value_box_copy(autofree, &dst, &src) == 0);
	TEST_CHECK(dst.tainted == true);
}

/*
 *	String operations
 */
static void test_strdup(void)
{
	fr_value_box_t vb;

	TEST_CHECK(fr_value_box_strdup(autofree, &vb, NULL, "hello world", false) == 0);
	TEST_CHECK(vb.type == FR_TYPE_STRING);
	TEST_CHECK_STRCMP(vb.vb_strvalue, "hello world");
	TEST_CHECK(vb.vb_length == 11);

	fr_value_box_clear(&vb);
}

static void test_asprintf(void)
{
	fr_value_box_t vb;

	TEST_CHECK(fr_value_box_asprintf(autofree, &vb, NULL, false, "value=%d", 42) == 0);
	TEST_CHECK(vb.type == FR_TYPE_STRING);
	TEST_CHECK_STRCMP(vb.vb_strvalue, "value=42");

	fr_value_box_clear(&vb);
}

static void test_bstrndup(void)
{
	fr_value_box_t vb;

	/* bstrndup copies exactly len bytes */
	TEST_CHECK(fr_value_box_bstrndup(autofree, &vb, NULL, "hello\0world", 11, false) == 0);
	TEST_CHECK(vb.type == FR_TYPE_STRING);
	TEST_CHECK(vb.vb_length == 11);
	TEST_CHECK(memcmp(vb.vb_strvalue, "hello\0world", 11) == 0);

	fr_value_box_clear(&vb);
}

/*
 *	Memory operations
 */
static void test_memdup(void)
{
	fr_value_box_t vb;
	uint8_t data[] = { 0xde, 0xad, 0xbe, 0xef };

	TEST_CHECK(fr_value_box_memdup(autofree, &vb, NULL, data, sizeof(data), false) == 0);
	TEST_CHECK(vb.type == FR_TYPE_OCTETS);
	TEST_CHECK(vb.vb_length == 4);
	TEST_CHECK(memcmp(vb.vb_octets, data, 4) == 0);

	fr_value_box_clear(&vb);
}

/*
 *	Hash tests
 */
static void test_hash_same_values(void)
{
	fr_value_box_t a, b;

	fr_value_box(&a, (uint32_t) 42, false);
	fr_value_box(&b, (uint32_t) 42, false);

	TEST_CHECK(fr_value_box_hash(&a) == fr_value_box_hash(&b));
}

static void test_hash_different_values(void)
{
	fr_value_box_t a, b;

	fr_value_box(&a, (uint32_t) 42, false);
	fr_value_box(&b, (uint32_t) 43, false);

	TEST_CHECK(fr_value_box_hash(&a) != fr_value_box_hash(&b));
}

static void test_hash_string(void)
{
	fr_value_box_t a, b;

	fr_value_box_strdup(autofree, &a, NULL, "hello", false);
	fr_value_box_strdup(autofree, &b, NULL, "hello", false);

	TEST_CHECK(fr_value_box_hash(&a) == fr_value_box_hash(&b));

	fr_value_box_clear(&a);
	fr_value_box_clear(&b);
}

/*
 *	Truthiness tests (fr_value_box_is_truthy)
 */
static void test_truthy_bool(void)
{
	fr_value_box_t vb;

	fr_value_box(&vb, (bool) true, false);
	TEST_CHECK(fr_value_box_is_truthy(&vb) == true);

	fr_value_box(&vb, (bool) false, false);
	TEST_CHECK(fr_value_box_is_truthy(&vb) == false);
}

static void test_truthy_uint32(void)
{
	fr_value_box_t vb;

	fr_value_box(&vb, (uint32_t) 42, false);
	TEST_CHECK(fr_value_box_is_truthy(&vb) == true);

	fr_value_box(&vb, (uint32_t) 0, false);
	TEST_CHECK(fr_value_box_is_truthy(&vb) == false);
}

static void test_truthy_string(void)
{
	fr_value_box_t vb;

	fr_value_box_strdup(autofree, &vb, NULL, "hello", false);
	TEST_CHECK(fr_value_box_is_truthy(&vb) == true);
	fr_value_box_clear(&vb);

	fr_value_box_strdup(autofree, &vb, NULL, "", false);
	TEST_CHECK(fr_value_box_is_truthy(&vb) == false);
	fr_value_box_clear(&vb);
}

static void test_truthy_octets(void)
{
	fr_value_box_t vb;

	fr_value_box_memdup(autofree, &vb, NULL, (uint8_t const *)"\x01", 1, false);
	TEST_CHECK(fr_value_box_is_truthy(&vb) == true);
	fr_value_box_clear(&vb);

	fr_value_box_memdup(autofree, &vb, NULL, (uint8_t const *)"", 0, false);
	TEST_CHECK(fr_value_box_is_truthy(&vb) == false);
	fr_value_box_clear(&vb);
}

/*
 *	Increment tests (fr_value_box_increment)
 */
static void test_increment_uint32(void)
{
	fr_value_box_t vb;

	fr_value_box(&vb, (uint32_t) 41, false);
	fr_value_box_increment(&vb);
	TEST_CHECK(vb.vb_uint32 == 42);
	TEST_MSG("Expected 42, got %u", vb.vb_uint32);
}

static void test_increment_uint8_overflow(void)
{
	fr_value_box_t vb;

	fr_value_box(&vb, (uint8_t) UINT8_MAX, false);
	fr_value_box_increment(&vb);
	TEST_CHECK(vb.vb_uint8 == 0);
	TEST_MSG("Expected 0 (wrap), got %u", vb.vb_uint8);
}

static void test_increment_int32(void)
{
	fr_value_box_t vb;

	fr_value_box(&vb, (int32_t) -1, false);
	fr_value_box_increment(&vb);
	TEST_CHECK(vb.vb_int32 == 0);
	TEST_MSG("Expected 0, got %d", vb.vb_int32);
}

/*
 *	as_uint64 extraction tests
 */
static void test_as_uint64(void)
{
	fr_value_box_t vb;

	fr_value_box(&vb, (uint8_t) 255, false);
	TEST_CHECK(fr_value_box_as_uint64(&vb) == 255);

	fr_value_box(&vb, (uint16_t) 1000, false);
	TEST_CHECK(fr_value_box_as_uint64(&vb) == 1000);

	fr_value_box(&vb, (uint32_t) 100000, false);
	TEST_CHECK(fr_value_box_as_uint64(&vb) == 100000);

	fr_value_box(&vb, (uint64_t) UINT64_MAX, false);
	TEST_CHECK(fr_value_box_as_uint64(&vb) == UINT64_MAX);

	fr_value_box(&vb, (bool) true, false);
	TEST_CHECK(fr_value_box_as_uint64(&vb) == 1);
}

/*
 *	Clear tests
 */
static void test_clear(void)
{
	fr_value_box_t vb;

	fr_value_box(&vb, (uint32_t) 42, false);
	TEST_CHECK(vb.type == FR_TYPE_UINT32);

	fr_value_box_clear(&vb);
	TEST_CHECK(vb.type == FR_TYPE_NULL);
}

static void test_clear_string(void)
{
	fr_value_box_t vb;

	fr_value_box_strdup(autofree, &vb, NULL, "hello", false);
	TEST_CHECK(vb.type == FR_TYPE_STRING);

	fr_value_box_clear(&vb);
	TEST_CHECK(vb.type == FR_TYPE_NULL);
}

/*
 *	Tainted flag tests
 */
static void test_tainted_flag(void)
{
	fr_value_box_t vb;

	fr_value_box(&vb, (uint32_t) 42, true);
	TEST_CHECK(vb.tainted == true);

	fr_value_box(&vb, (uint32_t) 42, false);
	TEST_CHECK(vb.tainted == false);
}

/*
 *	Network encode/decode round-trip tests
 */
static void test_network_uint32(void)
{
	fr_value_box_t src, dst;
	uint8_t buffer[256] = {};
	fr_dbuff_t dbuff;
	ssize_t enc_len, dec_len;

	fr_value_box(&src, (uint32_t) 0x12345678, false);

	/* Encode to network format */
	dbuff = FR_DBUFF_TMP(buffer, sizeof(buffer));
	enc_len = fr_value_box_to_network(&dbuff, &src);
	TEST_CHECK(enc_len == 4);

	/* Verify network byte order (big endian) */
	TEST_CHECK(buffer[0] == 0x12);
	TEST_CHECK(buffer[1] == 0x34);
	TEST_CHECK(buffer[2] == 0x56);
	TEST_CHECK(buffer[3] == 0x78);

	/* Decode back */
	fr_value_box_init_null(&dst);
	dbuff = FR_DBUFF_TMP(buffer, (size_t)enc_len);
	dec_len = fr_value_box_from_network(NULL, &dst, FR_TYPE_UINT32, NULL, &dbuff, enc_len, false);
	TEST_CHECK(dec_len == 4);
	TEST_CHECK(dst.vb_uint32 == 0x12345678);
	TEST_MSG("Expected 0x12345678, got 0x%08x", dst.vb_uint32);
}

static void test_network_uint64(void)
{
	fr_value_box_t src, dst;
	uint8_t buffer[256] = {};
	fr_dbuff_t dbuff;
	ssize_t enc_len, dec_len;

	fr_value_box(&src, (uint64_t) 0x0102030405060708ULL, false);

	dbuff = FR_DBUFF_TMP(buffer, sizeof(buffer));
	enc_len = fr_value_box_to_network(&dbuff, &src);
	TEST_CHECK(enc_len == 8);

	/* Verify big endian */
	TEST_CHECK(buffer[0] == 0x01);
	TEST_CHECK(buffer[7] == 0x08);

	/* Decode back */
	fr_value_box_init_null(&dst);
	dbuff = FR_DBUFF_TMP(buffer, (size_t)enc_len);
	dec_len = fr_value_box_from_network(NULL, &dst, FR_TYPE_UINT64, NULL, &dbuff, enc_len, false);
	TEST_CHECK(dec_len == 8);
	TEST_CHECK(dst.vb_uint64 == 0x0102030405060708ULL);
}

static void test_network_int32(void)
{
	fr_value_box_t src, dst;
	uint8_t buffer[256] = {};
	fr_dbuff_t dbuff;
	ssize_t enc_len, dec_len;

	fr_value_box(&src, (int32_t) -1, false);

	dbuff = FR_DBUFF_TMP(buffer, sizeof(buffer));
	enc_len = fr_value_box_to_network(&dbuff, &src);
	TEST_CHECK(enc_len == 4);

	/* -1 in two's complement big endian is 0xffffffff */
	TEST_CHECK(buffer[0] == 0xff);
	TEST_CHECK(buffer[1] == 0xff);
	TEST_CHECK(buffer[2] == 0xff);
	TEST_CHECK(buffer[3] == 0xff);

	/* Decode back */
	fr_value_box_init_null(&dst);
	dbuff = FR_DBUFF_TMP(buffer, (size_t)enc_len);
	dec_len = fr_value_box_from_network(NULL, &dst, FR_TYPE_INT32, NULL, &dbuff, enc_len, false);
	TEST_CHECK(dec_len == 4);
	TEST_CHECK(dst.vb_int32 == -1);
}

static void test_network_bool(void)
{
	fr_value_box_t src, dst;
	uint8_t buffer[256] = {};
	fr_dbuff_t dbuff;
	ssize_t enc_len, dec_len;

	fr_value_box(&src, (bool) true, false);

	dbuff = FR_DBUFF_TMP(buffer, sizeof(buffer));
	enc_len = fr_value_box_to_network(&dbuff, &src);
	TEST_CHECK(enc_len == 1);
	TEST_CHECK(buffer[0] == 1);

	fr_value_box_init_null(&dst);
	dbuff = FR_DBUFF_TMP(buffer, (size_t)enc_len);
	dec_len = fr_value_box_from_network(NULL, &dst, FR_TYPE_BOOL, NULL, &dbuff, enc_len, false);
	TEST_CHECK(dec_len == 1);
	TEST_CHECK(dst.vb_bool == true);
}

static void test_network_length(void)
{
	fr_value_box_t vb;

	fr_value_box(&vb, (uint8_t) 0, false);
	TEST_CHECK(fr_value_box_network_length(&vb) == 1);

	fr_value_box(&vb, (uint16_t) 0, false);
	TEST_CHECK(fr_value_box_network_length(&vb) == 2);

	fr_value_box(&vb, (uint32_t) 0, false);
	TEST_CHECK(fr_value_box_network_length(&vb) == 4);

	fr_value_box(&vb, (uint64_t) 0, false);
	TEST_CHECK(fr_value_box_network_length(&vb) == 8);
}

/*
 *	Print tests (fr_value_box_print)
 */
static void test_print_uint32(void)
{
	fr_value_box_t vb;
	char buffer[256] = {};
	fr_sbuff_t sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));

	fr_value_box(&vb, (uint32_t) 42, false);

	TEST_CHECK(fr_value_box_print(&sbuff, &vb, NULL) > 0);
	fr_sbuff_terminate(&sbuff);
	TEST_CHECK_STRCMP(buffer, "42");
}

static void test_print_int32_negative(void)
{
	fr_value_box_t vb;
	char buffer[256] = {};
	fr_sbuff_t sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));

	fr_value_box(&vb, (int32_t) -42, false);

	TEST_CHECK(fr_value_box_print(&sbuff, &vb, NULL) > 0);
	fr_sbuff_terminate(&sbuff);
	TEST_CHECK_STRCMP(buffer, "-42");
}

static void test_print_string(void)
{
	fr_value_box_t vb;
	char buffer[256] = {};
	fr_sbuff_t sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));

	fr_value_box_strdup(autofree, &vb, NULL, "hello", false);

	TEST_CHECK(fr_value_box_print(&sbuff, &vb, NULL) > 0);
	fr_sbuff_terminate(&sbuff);
	TEST_CHECK_STRCMP(buffer, "hello");

	fr_value_box_clear(&vb);
}

static void test_print_bool(void)
{
	fr_value_box_t vb;
	char buffer[256] = {};
	fr_sbuff_t sbuff;

	fr_value_box(&vb, (bool) true, false);
	sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));
	TEST_CHECK(fr_value_box_print(&sbuff, &vb, NULL) > 0);
	fr_sbuff_terminate(&sbuff);
	TEST_CHECK_STRCMP(buffer, "yes");

	fr_value_box(&vb, (bool) false, false);
	sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));
	TEST_CHECK(fr_value_box_print(&sbuff, &vb, NULL) > 0);
	fr_sbuff_terminate(&sbuff);
	TEST_CHECK_STRCMP(buffer, "no");
}

static void test_print_octets(void)
{
	fr_value_box_t vb;
	char buffer[256] = {};
	fr_sbuff_t sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));

	fr_value_box_memdup(autofree, &vb, NULL, (uint8_t const *)"\xde\xad\xbe\xef", 4, false);

	TEST_CHECK(fr_value_box_print(&sbuff, &vb, NULL) > 0);
	fr_sbuff_terminate(&sbuff);
	TEST_CHECK_STRCMP(buffer, "0xdeadbeef");

	fr_value_box_clear(&vb);
}

/*
 *	From string parsing tests (fr_value_box_from_str)
 */
static void test_from_str_uint32(void)
{
	fr_value_box_t vb;

	TEST_CHECK(fr_value_box_from_str(autofree, &vb, FR_TYPE_UINT32, NULL,
					 "12345", strlen("12345"), NULL) > 0);
	TEST_CHECK(vb.type == FR_TYPE_UINT32);
	TEST_CHECK(vb.vb_uint32 == 12345);
	TEST_MSG("Expected 12345, got %u", vb.vb_uint32);
}

static void test_from_str_int32(void)
{
	fr_value_box_t vb;

	TEST_CHECK(fr_value_box_from_str(autofree, &vb, FR_TYPE_INT32, NULL,
					 "-42", strlen("-42"), NULL) > 0);
	TEST_CHECK(vb.type == FR_TYPE_INT32);
	TEST_CHECK(vb.vb_int32 == -42);
	TEST_MSG("Expected -42, got %d", vb.vb_int32);
}

static void test_from_str_bool(void)
{
	fr_value_box_t vb;

	TEST_CHECK(fr_value_box_from_str(autofree, &vb, FR_TYPE_BOOL, NULL,
					 "yes", strlen("yes"), NULL) > 0);
	TEST_CHECK(vb.type == FR_TYPE_BOOL);
	TEST_CHECK(vb.vb_bool == true);
}

static void test_from_str_float64(void)
{
	fr_value_box_t vb;

	TEST_CHECK(fr_value_box_from_str(autofree, &vb, FR_TYPE_FLOAT64, NULL,
					 "3.14", strlen("3.14"), NULL) > 0);
	TEST_CHECK(vb.type == FR_TYPE_FLOAT64);
	TEST_CHECK((vb.vb_float64 > 3.13) && (vb.vb_float64 < 3.15));
	TEST_MSG("Expected ~3.14, got %f", vb.vb_float64);
}

static void test_from_str_octets(void)
{
	fr_value_box_t vb;

	TEST_CHECK(fr_value_box_from_str(autofree, &vb, FR_TYPE_OCTETS, NULL,
					 "0xdeadbeef", strlen("0xdeadbeef"), NULL) > 0);
	TEST_CHECK(vb.type == FR_TYPE_OCTETS);
	TEST_CHECK(vb.vb_length == 4);
	TEST_CHECK(memcmp(vb.vb_octets, "\xde\xad\xbe\xef", 4) == 0);

	fr_value_box_clear(&vb);
}

static void test_from_str_string(void)
{
	fr_value_box_t vb;

	TEST_CHECK(fr_value_box_from_str(autofree, &vb, FR_TYPE_STRING, NULL,
					 "hello world", strlen("hello world"), NULL) > 0);
	TEST_CHECK(vb.type == FR_TYPE_STRING);
	TEST_CHECK_STRCMP(vb.vb_strvalue, "hello world");

	fr_value_box_clear(&vb);
}

/*
 *	Print/parse round-trip tests
 */
static void test_round_trip_uint32(void)
{
	fr_value_box_t src, dst;
	char buffer[256] = {};
	fr_sbuff_t sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));

	fr_value_box(&src, (uint32_t) 42, false);

	TEST_CHECK(fr_value_box_print(&sbuff, &src, NULL) > 0);
	fr_sbuff_terminate(&sbuff);

	TEST_CHECK(fr_value_box_from_str(autofree, &dst, FR_TYPE_UINT32, NULL,
					 buffer, strlen(buffer), NULL) > 0);
	TEST_CHECK(dst.vb_uint32 == 42);
}

static void test_round_trip_int64(void)
{
	fr_value_box_t src, dst;
	char buffer[256] = {};
	fr_sbuff_t sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));

	fr_value_box(&src, (int64_t) -9999999, false);

	TEST_CHECK(fr_value_box_print(&sbuff, &src, NULL) > 0);
	fr_sbuff_terminate(&sbuff);

	TEST_CHECK(fr_value_box_from_str(autofree, &dst, FR_TYPE_INT64, NULL,
					 buffer, strlen(buffer), NULL) > 0);
	TEST_CHECK(dst.vb_int64 == -9999999);
}

static void test_round_trip_bool(void)
{
	fr_value_box_t src, dst;
	char buffer[256] = {};
	fr_sbuff_t sbuff;

	fr_value_box(&src, (bool) true, false);
	sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));
	TEST_CHECK(fr_value_box_print(&sbuff, &src, NULL) > 0);
	fr_sbuff_terminate(&sbuff);

	TEST_CHECK(fr_value_box_from_str(autofree, &dst, FR_TYPE_BOOL, NULL,
					 buffer, strlen(buffer), NULL) > 0);
	TEST_CHECK(dst.vb_bool == true);
}

static void test_round_trip_network_uint32(void)
{
	fr_value_box_t src, dst;
	uint8_t buffer[256] = {};
	fr_dbuff_t dbuff;
	ssize_t enc_len;

	fr_value_box(&src, (uint32_t) 0xdeadbeef, false);

	/* Encode */
	dbuff = FR_DBUFF_TMP(buffer, sizeof(buffer));
	enc_len = fr_value_box_to_network(&dbuff, &src);
	TEST_CHECK(enc_len == 4);

	/* Decode */
	fr_value_box_init_null(&dst);
	dbuff = FR_DBUFF_TMP(buffer, (size_t)enc_len);
	TEST_CHECK(fr_value_box_from_network(NULL, &dst, FR_TYPE_UINT32, NULL, &dbuff, enc_len, false) == 4);
	TEST_CHECK(dst.vb_uint32 == 0xdeadbeef);
}

TEST_LIST = {
	/* Comparison tests */
	{ "cmp_uint32_equal",			test_cmp_uint32_equal },
	{ "cmp_uint32_less",			test_cmp_uint32_less },
	{ "cmp_int32",				test_cmp_int32 },
	{ "cmp_float64",			test_cmp_float64 },
	{ "cmp_string",				test_cmp_string },
	{ "cmp_octets",				test_cmp_octets },
	{ "cmp_octets_length",			test_cmp_octets_length },
	{ "cmp_bool",				test_cmp_bool },
	{ "cmp_different_types",		test_cmp_different_types },

	/* Comparison operator tests */
	{ "cmp_op_eq",				test_cmp_op_eq },
	{ "cmp_op_ne",				test_cmp_op_ne },
	{ "cmp_op_lt",				test_cmp_op_lt },
	{ "cmp_op_gt",				test_cmp_op_gt },
	{ "cmp_op_le",				test_cmp_op_le },
	{ "cmp_op_ge",				test_cmp_op_ge },

	/* Cast tests */
	{ "cast_uint32_to_uint64",		test_cast_uint32_to_uint64 },
	{ "cast_uint32_to_string",		test_cast_uint32_to_string },
	{ "cast_string_to_uint32",		test_cast_string_to_uint32 },
	{ "cast_int32_to_int64",		test_cast_int32_to_int64 },
	{ "cast_uint8_to_uint32",		test_cast_uint8_to_uint32 },
	{ "cast_same_type",			test_cast_same_type },
	{ "cast_bool_to_uint32",		test_cast_bool_to_uint32 },
	{ "cast_uint32_to_bool",		test_cast_uint32_to_bool },

	/* Cast in place */
	{ "cast_in_place_uint32_to_uint64",	test_cast_in_place_uint32_to_uint64 },
	{ "cast_in_place_uint32_to_string",	test_cast_in_place_uint32_to_string },

	/* Copy tests */
	{ "copy_uint32",			test_copy_uint32 },
	{ "copy_string",			test_copy_string },
	{ "copy_octets",			test_copy_octets },
	{ "copy_preserves_tainted",		test_copy_preserves_tainted },

	/* String operations */
	{ "strdup",				test_strdup },
	{ "asprintf",				test_asprintf },
	{ "bstrndup",				test_bstrndup },

	/* Memory operations */
	{ "memdup",				test_memdup },

	/* Hash tests */
	{ "hash_same_values",			test_hash_same_values },
	{ "hash_different_values",		test_hash_different_values },
	{ "hash_string",			test_hash_string },

	/* Truthiness tests */
	{ "truthy_bool",			test_truthy_bool },
	{ "truthy_uint32",			test_truthy_uint32 },
	{ "truthy_string",			test_truthy_string },
	{ "truthy_octets",			test_truthy_octets },

	/* Increment tests */
	{ "increment_uint32",			test_increment_uint32 },
	{ "increment_uint8_overflow",		test_increment_uint8_overflow },
	{ "increment_int32",			test_increment_int32 },

	/* as_uint64 */
	{ "as_uint64",				test_as_uint64 },

	/* Clear tests */
	{ "clear",				test_clear },
	{ "clear_string",			test_clear_string },

	/* Tainted flag */
	{ "tainted_flag",			test_tainted_flag },

	/* Network encode/decode */
	{ "network_uint32",			test_network_uint32 },
	{ "network_uint64",			test_network_uint64 },
	{ "network_int32",			test_network_int32 },
	{ "network_bool",			test_network_bool },
	{ "network_length",			test_network_length },

	/* Print tests */
	{ "print_uint32",			test_print_uint32 },
	{ "print_int32_negative",		test_print_int32_negative },
	{ "print_string",			test_print_string },
	{ "print_bool",				test_print_bool },
	{ "print_octets",			test_print_octets },

	/* From string parsing */
	{ "from_str_uint32",			test_from_str_uint32 },
	{ "from_str_int32",			test_from_str_int32 },
	{ "from_str_bool",			test_from_str_bool },
	{ "from_str_float64",			test_from_str_float64 },
	{ "from_str_octets",			test_from_str_octets },
	{ "from_str_string",			test_from_str_string },

	/* Round-trip tests */
	{ "round_trip_uint32",			test_round_trip_uint32 },
	{ "round_trip_int64",			test_round_trip_int64 },
	{ "round_trip_bool",			test_round_trip_bool },
	{ "round_trip_network_uint32",		test_round_trip_network_uint32 },

	TEST_TERMINATOR
};
