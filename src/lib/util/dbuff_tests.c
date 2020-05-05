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

static void test_dbuff_net_from(void)
{
	uint8_t		buff[sizeof(uint64_t)];
	fr_dbuff_t	dbuff;

	TEST_CASE("Generate wire format 16-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CHECK(fr_dbuff_net_from_uint16(&dbuff, 0x1234) == sizeof(uint16_t));
	TEST_CHECK(buff[0] == 0x12);
	TEST_CHECK(buff[1] == 0x34);

	TEST_CASE("Generate wire format 32-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CHECK(fr_dbuff_net_from_uint32(&dbuff, 0x12345678) == sizeof(uint32_t));
	TEST_CHECK(buff[0] == 0x12);
	TEST_CHECK(buff[1] == 0x34);
	TEST_CHECK(buff[2] == 0x56);
	TEST_CHECK(buff[3] == 0x78);

	TEST_CASE("Generate wire format 64-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CHECK(fr_dbuff_net_from_uint64(&dbuff, 0x123456789abcdef0) == sizeof(uint64_t));
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

	TEST_CHECK(fr_dbuff_net_from_uint64(&dbuff,
					    0x123456789abcdef0) == -(ssize_t)(sizeof(uint64_t) - sizeof(uint32_t)));
}


TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "fr_dbuff_init",				test_dbuff_init },
	{ "fr_dbuff_init_no_parent",			test_dbuff_init_no_parent },
	{ "fr_dbuff_net_from",				test_dbuff_net_from },

	{ NULL }
};

