#include <freeradius-devel/util/acutest.h>

#include "dbuff.h"

#define TEST_CHECK_LEN(_got, _exp) \
do { \
	size_t _our_got = (_got); \
	TEST_CHECK((_exp) == (_our_got)); \
	TEST_MSG("Expected length : %zu", (ssize_t)_exp); \
	TEST_MSG("Got length      : %zu", (ssize_t)_our_got); \
} while(0)

#define TEST_CHECK_SLEN(_got, _exp) \
do { \
	ssize_t _our_got = (_got); \
	TEST_CHECK((_exp) == (_our_got)); \
	TEST_MSG("Expected length : %zd", (ssize_t)_exp); \
	TEST_MSG("Got length      : %zd", (ssize_t)_our_got); \
} while(0)

//#include <gperftools/profiler.h>

static void test_dbuff_init(void)
{
	uint8_t const	in[] = { 0x01, 0x02, 0x03, 0x04 };
	fr_dbuff_t	dbuff;

	TEST_CASE("Parse init with size");
	fr_dbuff_init(&dbuff, in, sizeof(in));

	TEST_CHECK(dbuff.start == in);
	TEST_CHECK(dbuff.p == in);
	TEST_CHECK(dbuff.end == in + sizeof(in));

	TEST_CASE("Parse init with end");
	fr_dbuff_init(&dbuff, in, in + sizeof(in));

	TEST_CHECK(dbuff.start == in);
	TEST_CHECK(dbuff.p == in);
	TEST_CHECK(dbuff.end == in + sizeof(in));

	TEST_CASE("Parse init with const end");
	fr_dbuff_init(&dbuff, in, (uint8_t const *)(in + sizeof(in)));

	TEST_CHECK(dbuff.start == in);
	TEST_CHECK(dbuff.p == in);
	TEST_CHECK(dbuff.end == in + sizeof(in));
}

static void test_dbuff_init_no_parent(void)
{	uint8_t const	in[] = { 0x01, 0x02, 0x03, 0x04 };
	fr_dbuff_t	dbuff;

	TEST_CASE("Confirm init returns parentless dbuff");
	fr_dbuff_init(&dbuff, in, sizeof(in));

	TEST_CHECK(dbuff.parent == NULL);
}

static void test_dbuff_max(void)
{
	uint8_t const	in[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	fr_dbuff_t	dbuff;
	fr_dbuff_t	max_dbuff;

	TEST_CASE("Confirm max constrains available space");
	fr_dbuff_init(&dbuff, in, sizeof(in));

	max_dbuff = FR_DBUFF_MAX(&dbuff, 4);
	TEST_CHECK(fr_dbuff_remaining(&max_dbuff) == 4);

	max_dbuff = FR_DBUFF_MAX(&dbuff, 2 * sizeof(in));
	TEST_CHECK(fr_dbuff_remaining(&max_dbuff) == sizeof(in));
}


/** Test the various dbuff_net_encode() functions and macros
 *
 * @note Passing constants to fr_dbuff_in() as it is written results in
 * 	 warnings about narrowing casts on the constants--but those casts are in
 * 	 the underlying inlined fr_net_from*() functions. They have to be there;
 * 	 that's how those functions work. (The tests worked despite the warnings.)
 * 	 Using variables avoids the warnings, at least with the compile options
 *	 the build system uses by default.
 */
static void test_dbuff_net_encode(void)
{
	uint8_t		buff[sizeof(uint64_t)];
	fr_dbuff_t	dbuff;
	uint16_t	u16val = 0x1234;
	uint32_t	u32val = 0x12345678;
	uint64_t	u64val = 0x123456789abcdef0;
	int16_t		i16val = 0x1234;
	int32_t		i32val = 0xd34d;
	int64_t		i64val = 0x123456789abcdef0;

	TEST_CASE("Generate wire format unsigned 16-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CHECK(fr_dbuff_in(&dbuff, u16val) == sizeof(uint16_t));
	TEST_CHECK(buff[0] == 0x12);
	TEST_CHECK(buff[1] == 0x34);

	TEST_CASE("Generate wire format unsigned 32-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CHECK(fr_dbuff_in(&dbuff, u32val) == sizeof(uint32_t));
	TEST_CHECK(buff[0] == 0x12);
	TEST_CHECK(buff[1] == 0x34);
	TEST_CHECK(buff[2] == 0x56);
	TEST_CHECK(buff[3] == 0x78);

	TEST_CASE("Generate wire format unsigned 64-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CHECK(fr_dbuff_in(&dbuff, u64val) == sizeof(uint64_t));
	TEST_CHECK(buff[0] == 0x12);
	TEST_CHECK(buff[1] == 0x34);
	TEST_CHECK(buff[2] == 0x56);
	TEST_CHECK(buff[3] == 0x78);
	TEST_CHECK(buff[4] == 0x9a);
	TEST_CHECK(buff[5] == 0xbc);
	TEST_CHECK(buff[6] == 0xde);
	TEST_CHECK(buff[7] == 0xf0);

	TEST_CASE("Generate wire format signed 16-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CHECK(fr_dbuff_in(&dbuff, i16val) == sizeof(int16_t));
	TEST_CHECK(buff[0] == 0x12);
	TEST_CHECK(buff[1] == 0x34);

	TEST_CASE("Generate wire format signed 32-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CHECK(fr_dbuff_in(&dbuff, i32val) == sizeof(int32_t));
	TEST_CHECK(buff[0] == 0x00);
	TEST_CHECK(buff[1] == 0x00);
	TEST_CHECK(buff[2] == 0xd3);
	TEST_CHECK(buff[3] == 0x4d);


	TEST_CASE("Generate wire format signed 64-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CHECK(fr_dbuff_in(&dbuff, i64val) == sizeof(int64_t));
	TEST_CHECK(buff[0] == 0x12);
	TEST_CHECK(buff[1] == 0x34);
	TEST_CHECK(buff[2] == 0x56);
	TEST_CHECK(buff[3] == 0x78);
	TEST_CHECK(buff[4] == 0x9a);
	TEST_CHECK(buff[5] == 0xbc);
	TEST_CHECK(buff[6] == 0xde);
	TEST_CHECK(buff[7] == 0xf0);

	TEST_CASE("Generate wire format variable-width");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	TEST_CHECK(fr_dbuff_uint64v_in(&dbuff, 0x12) == 1);
	TEST_CHECK(buff[0] == 0x12);

	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	TEST_CHECK(fr_dbuff_uint64v_in(&dbuff, 0x1234) == 2);
	TEST_CHECK(buff[0] == 0x12);
	TEST_CHECK(buff[1] == 0x34);

	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	TEST_CHECK(fr_dbuff_uint64v_in(&dbuff, 0x123456) == 3);
	TEST_CHECK(buff[0] == 0x12);
	TEST_CHECK(buff[1] == 0x34);
	TEST_CHECK(buff[2] == 0x56);

	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	TEST_CHECK(fr_dbuff_uint64v_in(&dbuff, 0x12345678) == 4);
	TEST_CHECK(buff[0] == 0x12);
	TEST_CHECK(buff[1] == 0x34);
	TEST_CHECK(buff[2] == 0x56);
	TEST_CHECK(buff[3] == 0x78);

	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	TEST_CHECK(fr_dbuff_uint64v_in(&dbuff, 0x123456789a) == 5);
	TEST_CHECK(buff[0] == 0x12);
	TEST_CHECK(buff[1] == 0x34);
	TEST_CHECK(buff[2] == 0x56);
	TEST_CHECK(buff[3] == 0x78);
	TEST_CHECK(buff[4] == 0x9a);

	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	TEST_CHECK(fr_dbuff_uint64v_in(&dbuff, 0x123456789abc) == 6);
	TEST_CHECK(buff[0] == 0x12);
	TEST_CHECK(buff[1] == 0x34);
	TEST_CHECK(buff[2] == 0x56);
	TEST_CHECK(buff[3] == 0x78);
	TEST_CHECK(buff[4] == 0x9a);
	TEST_CHECK(buff[5] == 0xbc);

	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	TEST_CHECK(fr_dbuff_uint64v_in(&dbuff, 0x123456789abcde) == 7);
	TEST_CHECK(buff[0] == 0x12);
	TEST_CHECK(buff[1] == 0x34);
	TEST_CHECK(buff[2] == 0x56);
	TEST_CHECK(buff[3] == 0x78);
	TEST_CHECK(buff[4] == 0x9a);
	TEST_CHECK(buff[5] == 0xbc);
	TEST_CHECK(buff[6] == 0xde);

	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	TEST_CHECK(fr_dbuff_uint64v_in(&dbuff, 0x123456789abcdef0) == 8);
	TEST_CHECK(buff[0] == 0x12);
	TEST_CHECK(buff[1] == 0x34);
	TEST_CHECK(buff[2] == 0x56);
	TEST_CHECK(buff[3] == 0x78);
	TEST_CHECK(buff[4] == 0x9a);
	TEST_CHECK(buff[5] == 0xbc);
	TEST_CHECK(buff[6] == 0xde);
	TEST_CHECK(buff[7] == 0xf0);

	TEST_CASE("Refuse to write to too-small space");
	fr_dbuff_init(&dbuff, buff, sizeof(uint32_t));

	TEST_CHECK(fr_dbuff_in(&dbuff, u64val) == -(ssize_t)(sizeof(uint64_t) - sizeof(uint32_t)));
}

static void test_dbuff_no_advance(void)
{
	uint8_t 	in[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	fr_dbuff_t	dbuff;
	fr_dbuff_t	no_advance_dbuff;
	size_t		init_remaining;

	TEST_CASE("Confirm no-advance dbuff operations don't affect ancestors' position");
	fr_dbuff_init(&dbuff, in, sizeof(in));

	no_advance_dbuff = FR_DBUFF_NO_ADVANCE(&dbuff);
	init_remaining = fr_dbuff_remaining(&dbuff);
	fr_dbuff_bytes_in(&no_advance_dbuff, 0x11, 0x12, 0x13);
	TEST_CHECK(init_remaining == fr_dbuff_remaining(&dbuff));
	fr_dbuff_advance(&no_advance_dbuff, 2);
	TEST_CHECK(init_remaining == fr_dbuff_remaining(&dbuff));
	fr_dbuff_set_to_end(&no_advance_dbuff);
	TEST_CHECK(init_remaining == fr_dbuff_remaining(&dbuff));
}

static void test_dbuff_move(void)
{
	uint8_t			buff1[26], buff2[26], buff3[10];
	fr_dbuff_t		dbuff1, dbuff2, dbuff3;
	fr_dbuff_marker_t	marker1, marker2;

	memcpy(buff1, "abcdefghijklmnopqrstuvwxyz", sizeof(buff1));
	memcpy(buff2, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", sizeof(buff2));
	memcpy(buff3, "0123456789", sizeof(buff3));
	fr_dbuff_init(&dbuff1, buff1, sizeof(buff1));
	fr_dbuff_init(&dbuff2, buff2, sizeof(buff2));
	fr_dbuff_init(&dbuff3, buff3, sizeof(buff3));
	fr_dbuff_marker(&marker1, &dbuff1);
	fr_dbuff_marker(&marker2, &dbuff2);

	TEST_CASE("move dbuff to dbuff");
	TEST_CHECK_LEN(fr_dbuff_move(&dbuff1, &dbuff2, 13), 13);
	TEST_CHECK_LEN(fr_dbuff_used(&dbuff1), 13);
	TEST_CHECK_LEN(fr_dbuff_used(&dbuff2), 13);
	TEST_CHECK(memcmp(dbuff1.start, "ABCDEFGHIJKLMnopqrstuvwxyz", 26) == 0);

	TEST_CASE("move dbuff to marker");
	TEST_CHECK_SLEN(fr_dbuff_advance(&marker2, 4), 4);
	TEST_CHECK_LEN(fr_dbuff_move(&marker2, &dbuff3, 10), 10);
	TEST_CHECK_LEN(fr_dbuff_used(&marker2), 14);
	TEST_CHECK(memcmp(dbuff2.start, "ABCD0123456789OPQRSTUVWXYZ", 26) == 0);

	TEST_CASE("move marker to dbuff");
	TEST_CHECK_SLEN(fr_dbuff_advance(&marker1, 7), 7);
	TEST_CHECK_LEN(fr_dbuff_move(&dbuff1, &marker1, 6), 6);
	TEST_CHECK_LEN(fr_dbuff_used(&dbuff1), 19);
	TEST_CHECK_LEN(fr_dbuff_used(&marker1), 13);
	TEST_CHECK(memcmp(dbuff1.start, "ABCDEFGHIJKLMHIJKLMtuvwxyz", 26) == 0);

	TEST_CASE("move marker to marker");
	TEST_CHECK_LEN(fr_dbuff_move(&marker2, &marker1, 8), 8);
	TEST_CHECK_LEN(fr_dbuff_used(&marker1), 21);
	TEST_CHECK_LEN(fr_dbuff_used(&marker2), 22);
	TEST_CHECK(memcmp(dbuff2.start, "ABCD0123456789HIJKLMtuWXYZ", 26) == 0);
}

/** Test extensible dbuffs
 *
 */

static void test_dbuff_talloc_extend(void)
{
	fr_dbuff_t		dbuff;
	fr_dbuff_uctx_talloc_t	tctx;
	fr_dbuff_marker_t	marker;
	uint8_t const		value[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};

	TEST_CASE("Initial allocation");
	TEST_CHECK(fr_dbuff_init_talloc(NULL, &dbuff, &tctx, 4, 14) == &dbuff);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 0);
	TEST_CHECK(fr_dbuff_remaining(&dbuff) == 4);
	fr_dbuff_marker(&marker, &dbuff);
	TEST_CASE("Extension");
	TEST_CHECK(fr_dbuff_in(&dbuff, (uint64_t) 0x123456789abcdef0) == sizeof(uint64_t));
	TEST_CASE("Markers track extended buffer");
	TEST_CHECK(marker.p == dbuff.start);
	TEST_CASE("Already-written content stays with the buffer");
	TEST_CHECK(memcmp(fr_dbuff_current(&marker), value, sizeof(value)) == 0);
	TEST_CASE("Refuse to extend past specified maximum");
	TEST_CHECK(fr_dbuff_in(&dbuff, (uint64_t) 0x123456789abcdef0) == -2);
}

static void test_dbuff_talloc_extend_multi_level(void)
{
	fr_dbuff_t		dbuff1, dbuff2;
	fr_dbuff_uctx_talloc_t	tctx;

	TEST_CASE("Initial allocation");
	TEST_CHECK(fr_dbuff_init_talloc(NULL, &dbuff1, &tctx, 0, 32) == &dbuff1);
	TEST_CHECK(fr_dbuff_used(&dbuff1) == 0);
	TEST_CHECK(fr_dbuff_remaining(&dbuff1) == 0);

	dbuff2 = FR_DBUFF_NO_ADVANCE(&dbuff1);
	TEST_CASE("Check that dbuff2 inherits extend fields");
	TEST_CHECK(dbuff2.extend == dbuff1.extend);
	TEST_CHECK(dbuff2.uctx == dbuff1.uctx);
	TEST_CHECK(fr_dbuff_used(&dbuff2) == 0);
	TEST_CHECK(fr_dbuff_remaining(&dbuff2) == 0);

	dbuff2 = FR_DBUFF_MAX(&dbuff1, 8);
	TEST_CASE("Check that FR_DBUFF_MAX() is not extensible");
	TEST_CHECK(dbuff2.extend == NULL);
	TEST_CHECK(dbuff2.uctx == NULL);
	TEST_CHECK(fr_dbuff_used(&dbuff2) == 0);
	TEST_CHECK(fr_dbuff_remaining(&dbuff2) == 0);
	TEST_CHECK(fr_dbuff_in(&dbuff2, (uint64_t) 0x123456789abcdef0) == -8);
}

/** Test functions that read from dbuffs.
 *
 */
static void test_dbuff_out(void)
{
	uint8_t const	buff1[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	uint8_t		buff2[8];
	uint8_t		buff3[8];
	fr_dbuff_t	dbuff1;
	fr_dbuff_t	dbuff2;
	uint16_t	u16val = 0;
	uint32_t	u32val = 0;
	uint64_t	u64val = 0;
	int16_t		i16val = 0;
	int32_t		i32val = 0;
	int64_t		i64val = 0;

	fr_dbuff_init(&dbuff1, buff1, sizeof(buff1));
	fr_dbuff_init(&dbuff2, buff2, sizeof(buff2));

	TEST_CASE("Check dbuff reads of unsigned integers");
	TEST_CHECK(fr_dbuff_out(&u16val, &dbuff1) == 2);
	TEST_CHECK(u16val == 0x0123);
	TEST_CHECK(fr_dbuff_out(&u32val, &dbuff1) == 4);
	TEST_CHECK(u32val == 0x456789ab);
	fr_dbuff_set_to_start(&dbuff1);
	TEST_CHECK(fr_dbuff_out(&u64val, &dbuff1) == 8);
	TEST_CHECK(u64val == 0x0123456789abcdef);

	TEST_CASE("Don't walk off the end of the buffer");
	TEST_CHECK(fr_dbuff_out(&u32val, &dbuff1) == -4);

	TEST_CASE("Check dbuff reads of signed integers");
	fr_dbuff_set_to_start(&dbuff1);
	TEST_CHECK(fr_dbuff_out(&i16val, &dbuff1) == 2);
	TEST_CHECK(i16val == 0x0123);
	TEST_CHECK(fr_dbuff_out(&i32val, &dbuff1) == 4);
	TEST_CHECK(i32val == 0x456789ab);
	fr_dbuff_set_to_start(&dbuff1);
	TEST_CHECK(fr_dbuff_out(&i64val, &dbuff1) == 8);
	TEST_CHECK(i64val == 0x0123456789abcdef);

	TEST_CASE("fr_dbuff_memcpy_out");
	fr_dbuff_set_to_start(&dbuff1);
	memset(buff3, 0, sizeof(buff3));
	TEST_CHECK(fr_dbuff_memcpy_out(buff3, &dbuff1, 7) == 7);
	TEST_CHECK(memcmp(buff3, fr_dbuff_start(&dbuff1), 7) == 0 && buff3[7] == 0);
	fr_dbuff_set_to_start(&dbuff1);
	TEST_CHECK(fr_dbuff_memcpy_out(&dbuff2, &dbuff1, 4) == 4);
	fr_dbuff_set_to_start(&dbuff1);
	fr_dbuff_advance(&dbuff1, 3);
	TEST_CHECK(fr_dbuff_memcpy_out(&dbuff2, &dbuff1, 4) == 4);
	TEST_CHECK(memcmp(fr_dbuff_start(&dbuff2), fr_dbuff_start(&dbuff1), 4) == 0 &&
		   memcmp(fr_dbuff_start(&dbuff2) + 4, fr_dbuff_start(&dbuff1) + 3, 4) == 0);
}

TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "fr_dbuff_init",				test_dbuff_init },
	{ "fr_dbuff_init_no_parent",			test_dbuff_init_no_parent },
	{ "fr_dbuff_max",				test_dbuff_max },
	{ "fr_dbuff_in",				test_dbuff_net_encode },
	{ "fr_dbuff_no_advance",			test_dbuff_no_advance },
	{ "fr_dbuff_move",				test_dbuff_move },
	{ "fr_dbuff_talloc_extend",			test_dbuff_talloc_extend },
	{ "fr_dbuff_talloc_extend_multi_level",		test_dbuff_talloc_extend_multi_level },
	{ "fr_dbff_out",				test_dbuff_out },


	{ NULL }
};

