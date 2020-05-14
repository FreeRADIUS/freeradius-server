#include <freeradius-devel/util/acutest.h>

#include "dbuff.h"


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


TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "fr_dbuff_init",				test_dbuff_init },
	{ "fr_dbuff_init_no_parent",			test_dbuff_init_no_parent },
	{ "fr_dbuff_max",				test_dbuff_max },
	{ "fr_dbuff_in",			test_dbuff_net_encode },

	{ NULL }
};

