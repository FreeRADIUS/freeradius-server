#include "acutest.h"
#include"acutest_helpers.h"
#include <float.h>

#include <freeradius-devel/util/dbuff.h>

/*
 *	Type for a function with the internals of a test of fd flavored dbuffs.
 */
typedef void (*fr_dbuff_fd_test_body)(fr_dbuff_t *dbuff, uint8_t const data[]);

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

	max_dbuff = FR_DBUFF_MAX_BIND_CURRENT(&dbuff, 4);
	TEST_CHECK(fr_dbuff_remaining(&max_dbuff) == 4);

	max_dbuff = FR_DBUFF_MAX_BIND_CURRENT(&dbuff, 2 * sizeof(in));
	TEST_CHECK(fr_dbuff_remaining(&max_dbuff) == sizeof(in));
}


/** Test the various dbuff_net_encode() functions and macros
 *
 * @note Passing constants to fr_dbuff_in() as it is written results in
 * 	 warnings about narrowing casts on the constants--but those casts are in
 * 	 the underlying inlined fr_nbo_from*() functions. They have to be there;
 * 	 that's how those functions work. (The tests worked despite the warnings.)
 * 	 Using variables avoids the warnings, at least with the compile options
 *	 the build system uses by default.
 */
static void test_dbuff_net_encode(void)
{
	uint8_t		buff[sizeof(uint64_t)];
	fr_dbuff_t	dbuff;
	fr_dbuff_marker_t	marker;
	uint16_t	u16val = 0x1234;
	uint16_t	u16val2 = 0xcdef;
	uint32_t	u32val = 0x12345678;
	uint64_t	u64val = 0x123456789abcdef0;
	int16_t		i16val = 0x1234;
	int32_t		i32val = 0xd34d;
	int64_t		i64val = 0x123456789abcdef0;
	float		float_in = 1.0f + FLT_EPSILON;
	float		float_out = 0;
	double		double_in = 1.0 + DBL_EPSILON;
	double		double_out = 0;
	uint64_t	u64v_vals[] = {
					0, 0x12, 0x3412, 0x563412, 0x78563412, 0x9a78563412,
					0xbc9a78563412, 0xdebc9a78563412, 0xf0debc9a78563412
	};

	TEST_CASE("Generate wire format unsigned 16-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	fr_dbuff_marker(&marker, &dbuff);

	TEST_CHECK(fr_dbuff_in(&dbuff, u16val) == sizeof(uint16_t));
	TEST_CHECK(*((uint16_t *)buff) == htons(u16val));

	TEST_CASE("Generate wire format unsigned 16-bit value using marker");
	fr_dbuff_set_to_start(&dbuff);
	TEST_CHECK(fr_dbuff_in(&marker, u16val2) == sizeof(uint16_t));
	TEST_CHECK(*((uint16_t *)buff) == htons(u16val2));
	TEST_CHECK(fr_dbuff_used(&marker) == sizeof(uint16_t));
	TEST_CHECK(fr_dbuff_used(&dbuff) == 0);

	TEST_CASE("Generate wire format unsigned 32-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CHECK(fr_dbuff_in(&dbuff, u32val) == sizeof(uint32_t));
	TEST_CHECK(*((uint32_t *)buff) == htonl(u32val));

	TEST_CASE("Generate wire format unsigned 64-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CHECK(fr_dbuff_in(&dbuff, u64val) == sizeof(uint64_t));
	TEST_CHECK(*((uint64_t *)buff) == htonll(u64val));

	TEST_CASE("Generate wire format signed 16-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CHECK(fr_dbuff_in(&dbuff, i16val) == sizeof(int16_t));
	TEST_CHECK(*((uint16_t *)buff) == htons((uint16_t) i16val));

	TEST_CASE("Generate wire format signed 32-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CHECK(fr_dbuff_in(&dbuff, i32val) == sizeof(int32_t));
	TEST_CHECK(*((uint32_t *)buff) == htonl((uint32_t) i32val));

	TEST_CASE("Generate wire format signed 64-bit value");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CHECK(fr_dbuff_in(&dbuff, i64val) == sizeof(int64_t));
	TEST_CHECK(*((uint64_t *)buff) == htonll((uint64_t) i64val));

	TEST_CASE("Generate wire format variable-width");
	for (size_t i = 0; i < (sizeof(u64v_vals) / sizeof(uint64_t)); i++) {
		uint64_t	val = u64v_vals[i];
		int		num_bytes;

		fr_dbuff_set_to_start(&dbuff);
		for (num_bytes = 1; (val & ~((uint64_t) 0xff)) != 0; num_bytes++) val >>= 8;
		TEST_CHECK(fr_dbuff_in_uint64v(&dbuff, u64v_vals[i]) == num_bytes);
		val = u64v_vals[i];
		fr_dbuff_set_to_start(&dbuff);
		for (int j = num_bytes; --j >= 0; ) {
			uint8_t	byte = 0;

			TEST_CHECK(fr_dbuff_out(&byte, &dbuff) == 1);
			TEST_CHECK(byte == (uint8_t) (val >> (8 * j)));
		}
	}

	TEST_CASE("Generate wire-format float");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	TEST_CHECK(fr_dbuff_in(&dbuff, float_in) == 4);
	fr_dbuff_set_to_start(&dbuff);
	TEST_CHECK(fr_dbuff_out(&float_out, &dbuff) == 4);
	TEST_CHECK(memcmp(&float_out, &float_in, sizeof(float)) == 0);

	TEST_CASE("Generate wire-format double");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	TEST_CHECK(fr_dbuff_in(&dbuff, double_in) == 8);
	fr_dbuff_set_to_start(&dbuff);
	TEST_CHECK(fr_dbuff_out(&double_out, &dbuff) == 8);
	TEST_CHECK(memcmp(&double_out, &double_in, sizeof(double)) == 0);

	TEST_CASE("Refuse to write to too-small space");
	fr_dbuff_init(&dbuff, buff, sizeof(uint32_t));

	TEST_CHECK(fr_dbuff_in(&dbuff, u64val) == -(ssize_t)(sizeof(uint64_t) - sizeof(uint32_t)));

	TEST_CASE("Input bytes using dbuff current position");
	memset(buff, 0, sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	fr_dbuff_marker(&marker, &dbuff);
	TEST_CHECK(fr_dbuff_in_bytes(&dbuff, 0xf0, 0xed, 0xcb) == 3);
	TEST_CHECK(buff[0] == 0xf0);
	TEST_CHECK(buff[1] == 0xed);
	TEST_CHECK(buff[2] == 0xcb);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 3);
	TEST_CASE("Input bytes using marker");
	TEST_CHECK(fr_dbuff_in_bytes(&marker, 0x01, 0x23) == 2);
	TEST_CHECK(buff[0] == 0x01);
	TEST_CHECK(buff[1] == 0x23);
	TEST_CHECK(fr_dbuff_used(&marker) == 2);
}

static void test_dbuff_no_advance(void)
{
	uint8_t 	in[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	fr_dbuff_t	dbuff;
	fr_dbuff_t	no_advance_dbuff;
	size_t		init_remaining;

	TEST_CASE("Confirm no-advance dbuff operations don't affect ancestors' position");
	fr_dbuff_init(&dbuff, in, sizeof(in));

	no_advance_dbuff = FR_DBUFF(&dbuff);
	init_remaining = fr_dbuff_remaining(&dbuff);
	TEST_CHECK(fr_dbuff_in_bytes(&no_advance_dbuff, 0x11, 0x12, 0x13) == 3);
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
	fr_dbuff_t		dbuff1, dbuff2;
	fr_dbuff_uctx_talloc_t	tctx1, tctx2;
	fr_dbuff_marker_t	marker1;
	uint8_t const		value[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};

	TEST_CASE("Initial allocation");
	TEST_CHECK(fr_dbuff_init_talloc(NULL, &dbuff1, &tctx1, 4, 14) == &dbuff1);
	TEST_CHECK(fr_dbuff_used(&dbuff1) == 0);
	TEST_CHECK(fr_dbuff_remaining(&dbuff1) == 4);
	fr_dbuff_marker(&marker1, &dbuff1);

	TEST_CASE("Extension");
	TEST_CHECK(fr_dbuff_in(&dbuff1, (uint64_t) 0x123456789abcdef0) == sizeof(uint64_t));
	TEST_CASE("Markers track extended buffer");
	TEST_CHECK(marker1.p == dbuff1.start);
	TEST_CASE("Already-written content stays with the buffer");
	TEST_CHECK(memcmp(fr_dbuff_current(&marker1), value, sizeof(value)) == 0);
	TEST_CASE("Refuse to extend past specified maximum");
	TEST_CHECK(fr_dbuff_in(&dbuff1, (uint64_t) 0x123456789abcdef0) == -2);
	TEST_CASE("Extend move destination if possible and input length demands");
	TEST_CHECK(fr_dbuff_init_talloc(NULL, &dbuff2, &tctx2, 4, 14) == &dbuff2);
	fr_dbuff_set_to_start(&dbuff1);
	TEST_CHECK(fr_dbuff_move(&dbuff2, &dbuff1, sizeof(value)) == sizeof(value));
	TEST_CHECK(fr_dbuff_used(&dbuff2) == sizeof(value));
	/*
	 * @todo: the analogous test for extensible source.
	 */

	talloc_free(dbuff1.buff);
	talloc_free(dbuff2.buff);
}

static void test_dbuff_talloc_extend_multi_level(void)
{
	fr_dbuff_t		dbuff1, dbuff2;
	fr_dbuff_uctx_talloc_t	tctx;

	TEST_CASE("Initial allocation");
	TEST_CHECK(fr_dbuff_init_talloc(NULL, &dbuff1, &tctx, 0, 32) == &dbuff1);
	TEST_CHECK(fr_dbuff_used(&dbuff1) == 0);
	TEST_CHECK(fr_dbuff_remaining(&dbuff1) == 0);

	dbuff2 = FR_DBUFF(&dbuff1);
	TEST_CASE("Check that dbuff2 inherits extend fields");
	TEST_CHECK(dbuff2.extend == dbuff1.extend);
	TEST_CHECK(dbuff2.uctx == dbuff1.uctx);
	TEST_CHECK(fr_dbuff_used(&dbuff2) == 0);
	TEST_CHECK(fr_dbuff_remaining(&dbuff2) == 0);

	dbuff2 = FR_DBUFF_MAX_BIND_CURRENT(&dbuff1, 8);
	TEST_CASE("Check that FR_DBUFF_MAX_BIND_CURRENT() is not extensible");
	TEST_CHECK(dbuff2.extend == NULL);
	TEST_CHECK(dbuff2.uctx == NULL);
	TEST_CHECK(fr_dbuff_used(&dbuff2) == 0);
	TEST_CHECK(fr_dbuff_remaining(&dbuff2) == 0);
	TEST_CHECK(fr_dbuff_in(&dbuff2, (uint64_t) 0x123456789abcdef0) == -8);

	talloc_free(dbuff1.buff);
}

/*
 *	test_dbuff_fd_shell() puts setup and teardown of a fd flavored dbuff in one place
 *	so jscpd won't complain about copy/paste.
 */
static void test_dbuff_fd_shell(fr_dbuff_fd_test_body body, uint8_t const data[], size_t datasize,
				uint8_t buff[], size_t buffsize, size_t max)
{
	int			fd[2];
	fr_dbuff_t		dbuff;
	fr_dbuff_uctx_fd_t	fctx;

	TEST_CASE("Initial allocation");
	TEST_CHECK(pipe(fd) == 0);
	TEST_CHECK(write(fd[1], data, datasize) == (ssize_t) datasize);
	close(fd[1]);
	TEST_CHECK(fr_dbuff_init_fd(&dbuff, &fctx, buff, buffsize, fd[0], max) == &dbuff);

	body(&dbuff, data);

	close(fd[0]);
}

static void fd_body(fr_dbuff_t *dbuff, uint8_t const data[])
{
	uint8_t			output[8] = { 0x00 };

	TEST_CASE("Initial extend");
	TEST_CHECK(fr_dbuff_out_memcpy(output, dbuff, 1) == 1);
	TEST_CHECK(memcmp(output, data, 1) == 0);
	TEST_CHECK(fr_dbuff_out_memcpy(output, dbuff, 2) == 2);
	TEST_CHECK(memcmp(output, &data[1], 2) == 0);
	TEST_CASE("Leftover byte plus data from next extend");
	TEST_CHECK(fr_dbuff_out_memcpy(output, dbuff, 4) == 4);
	TEST_CHECK(memcmp(output, &data[3], 4) == 0);
	TEST_CASE("Multiple extends");
	TEST_CHECK(fr_dbuff_out_memcpy(output, dbuff, 8) == 8);
	TEST_CHECK(memcmp(output, &data[7], 8) == 0);
	TEST_CASE("EOF");
	TEST_CHECK(fr_dbuff_out_memcpy(output, dbuff, 4) == -3);
}

static void test_dbuff_fd(void)
{
	uint8_t const		data[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
					  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	uint8_t			buff[4];

	test_dbuff_fd_shell(fd_body, data, sizeof(data), buff, sizeof(buff), 24);
}


static void max_body(fr_dbuff_t *dbuff, uint8_t const data[])
{
	uint8_t			output[8];

	TEST_CASE("Initial extend");
	TEST_CHECK(fr_dbuff_out_memcpy(output, dbuff, 2) == 2);
	TEST_CHECK(memcmp(output, data, 2) == 0);
	TEST_CHECK(fr_dbuff_out_memcpy(output, dbuff, 1) == 1);
	TEST_CHECK(memcmp(output, &data[2], 1) == 0);
	TEST_CHECK(fr_dbuff_out_memcpy(output, dbuff, 4) == 4);
	TEST_CHECK(memcmp(output, &data[3], 4) == 0);
	TEST_CASE("Confirm that max precludes another shift/extend");
	TEST_CHECK(fr_dbuff_out_memcpy(output, dbuff, 8) == -7);
}

static void test_dbuff_fd_max(void)
{
	uint8_t const		data[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
					  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	uint8_t			buff[4];


	test_dbuff_fd_shell(max_body, data, sizeof(data), buff, sizeof(buff), 8);
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
	fr_dbuff_marker_t	marker1;
	uint8_t		u8val = 0;
	uint16_t	u16val = 0;
	uint32_t	u32val = 0;
	uint64_t	u64val = 0;
	uint64_t	u64val2 = 0;
	int8_t		i8val = 0;
	int16_t		i16val = 0;
	int32_t		i32val = 0;
	int64_t		i64val = 0;
	float		fval1 = 1.5, fval2 = 0;
	double		dval1 = 2048.0625, dval2 = 0;

	fr_dbuff_init(&dbuff1, buff1, sizeof(buff1));
	fr_dbuff_init(&dbuff2, buff2, sizeof(buff2));

	TEST_CASE("Check dbuff reads of unsigned integers");
	TEST_CHECK(fr_dbuff_out(&u8val, &dbuff1) == 1);
	TEST_CHECK(u8val == 0x01);
	TEST_CHECK(fr_dbuff_out(&u16val, &dbuff1) == 2);
	TEST_CHECK(u16val == 0x2345);
	TEST_CHECK(fr_dbuff_out(&u32val, &dbuff1) == 4);
	TEST_CHECK(u32val == 0x6789abcd);
	fr_dbuff_set_to_start(&dbuff1);
	TEST_CHECK(fr_dbuff_out(&u64val, &dbuff1) == 8);
	TEST_CHECK(u64val == 0x0123456789abcdef);

	TEST_CASE("Don't walk off the end of the buffer");
	TEST_CHECK(fr_dbuff_out(&u32val, &dbuff1) == -4);

	TEST_CASE("Check dbuff reads using markers");
	fr_dbuff_set_to_start(&dbuff1);
	fr_dbuff_marker(&marker1, &dbuff1);
	TEST_CHECK(fr_dbuff_out(&u64val, &marker1) == 8);
	TEST_CHECK(fr_dbuff_out(&u64val2, &dbuff1) == 8);
	TEST_CHECK(u64val == u64val2);
	TEST_CHECK(fr_dbuff_current(&dbuff1) == fr_dbuff_current(&marker1));

	TEST_CASE("Check dbuff reads of signed integers");
	fr_dbuff_set_to_start(&dbuff1);
	TEST_CHECK(fr_dbuff_out(&i8val, &dbuff1) == 1);
	TEST_CHECK(i8val == 0x01);
	TEST_CHECK(fr_dbuff_out(&i16val, &dbuff1) == 2);
	TEST_CHECK(i16val == 0x2345);
	TEST_CHECK(fr_dbuff_out(&i32val, &dbuff1) == 4);
	TEST_CHECK(i32val == 0x6789abcd);
	fr_dbuff_set_to_start(&dbuff1);
	TEST_CHECK(fr_dbuff_out(&i64val, &dbuff1) == 8);
	TEST_CHECK(i64val == 0x0123456789abcdef);

	TEST_CASE("Check dbuff reads of floating point values");
	TEST_CHECK(fr_dbuff_in(&dbuff2, *(uint32_t *)&fval1) == 4);
	fr_dbuff_set_to_start(&dbuff2);
	TEST_CHECK(fr_dbuff_out(&fval2, &dbuff2) == 4);
	TEST_CHECK(memcmp(&fval1, &fval2, sizeof(fval1)) == 0);
	fr_dbuff_set_to_start(&dbuff2);
	TEST_CHECK(fr_dbuff_in(&dbuff2, *(uint64_t *)&dval1) == 8);
	fr_dbuff_set_to_start(&dbuff2);
	TEST_CHECK(fr_dbuff_out(&dval2, &dbuff2) == 8);
	TEST_CHECK(memcmp(&dval1, &dval2, sizeof(dval1)) == 0);

	TEST_CASE("Check variable length uint64_t read");
	fr_dbuff_set_to_start(&dbuff1);
	TEST_CHECK(fr_dbuff_out_uint64v(&u64val, &dbuff1, 2) == 2);
	TEST_CHECK(u64val == 0x0123);
	TEST_CHECK(fr_dbuff_out_uint64v(&u64val, &dbuff1, 4) == 4);
	TEST_CHECK(u64val == 0x456789ab);
	fr_dbuff_set_to_start(&dbuff1);
	TEST_CHECK(fr_dbuff_out_uint64v(&u64val, &dbuff1, 8) == 8);
	TEST_CHECK(u64val == 0x0123456789abcdef);

	TEST_CASE("fr_dbuff_out_memcpy");
	fr_dbuff_set_to_start(&dbuff1);
	fr_dbuff_set_to_start(&dbuff2);
	fr_dbuff_marker(&marker1, &dbuff1);
	memset(buff3, 0, sizeof(buff3));
	TEST_CHECK(fr_dbuff_out_memcpy(buff3, &dbuff1, 7) == 7);
	TEST_CHECK(memcmp(buff3, fr_dbuff_start(&dbuff1), 7) == 0 && buff3[7] == 0);
	TEST_CHECK(fr_dbuff_current(&dbuff1) - fr_dbuff_current(&marker1) == 7);
	fr_dbuff_set_to_start(&dbuff1);
	TEST_CHECK(fr_dbuff_out_memcpy(&dbuff2, &dbuff1, 4) == 4);
	fr_dbuff_set_to_start(&dbuff1);
	fr_dbuff_advance(&dbuff1, 3);
	fr_dbuff_advance(&dbuff2, 2);
	TEST_CHECK(fr_dbuff_out_memcpy(&dbuff2, &dbuff1, 4) == 4);
	TEST_CHECK(memcmp(fr_dbuff_start(&dbuff2), fr_dbuff_start(&dbuff1), 2) == 0 &&
		   memcmp(fr_dbuff_start(&dbuff2) + 2, fr_dbuff_start(&dbuff1) + 3, 4) == 0);
	memset(buff3, 0, sizeof(buff3));
	fr_dbuff_set_to_start(&marker1);
	TEST_CHECK(fr_dbuff_out_memcpy(buff3, &marker1, 4) == 4);
	TEST_CHECK(memcmp(buff3, buff1, 4) == 0);
	TEST_CHECK(fr_dbuff_current(&marker1) - fr_dbuff_start(&dbuff1) == 4);
}

/** Test the child-dbuff macros: FR_DBUFF, FR_DBUFF_ABS, FR_DBUFF_BIND_CURRENT,
 *  FR_DBUFF_BIND_CURRENT_ABS, FR_DBUFF_BIND_END_ABS and FR_DBUFF_MAX.
 *
 *  These differ only in where the child's 'start' pointer is set (parent
 *  'current' vs parent 'start') and whether writing to the child advances the
 *  parent's 'current' pointer, 'end' pointer, or neither.
 */
static void test_dbuff_child(void)
{
	fr_dbuff_t	dbuff;
	fr_dbuff_t	child;
	uint8_t		buff[16] = "";

	TEST_CASE("FR_DBUFF: start bound to parent 'current', parent not advanced");
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	fr_dbuff_advance(&dbuff, 4);
	child = FR_DBUFF(&dbuff);
	TEST_CHECK(fr_dbuff_start(&child) == fr_dbuff_current(&dbuff));
	TEST_CHECK(fr_dbuff_current(&child) == fr_dbuff_current(&dbuff));
	TEST_CHECK(fr_dbuff_used(&child) == 0);
	TEST_CHECK(fr_dbuff_remaining(&child) == sizeof(buff) - 4);
	TEST_CHECK(fr_dbuff_in_bytes(&child, 0xaa, 0xbb) == 2);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 4);			/* parent NOT advanced */

	TEST_CASE("FR_DBUFF_ABS: start bound to parent 'start', parent not advanced");
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	fr_dbuff_advance(&dbuff, 4);
	child = FR_DBUFF_ABS(&dbuff);
	TEST_CHECK(fr_dbuff_start(&child) == fr_dbuff_start(&dbuff));
	TEST_CHECK(fr_dbuff_current(&child) == fr_dbuff_current(&dbuff));
	TEST_CHECK(fr_dbuff_used(&child) == 4);			/* current - start */
	TEST_CHECK(fr_dbuff_in_bytes(&child, 0xaa) == 1);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 4);			/* parent NOT advanced */

	TEST_CASE("FR_DBUFF_BIND_CURRENT: writes advance parent 'current'");
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	fr_dbuff_advance(&dbuff, 4);
	child = FR_DBUFF_BIND_CURRENT(&dbuff);
	TEST_CHECK(fr_dbuff_start(&child) == fr_dbuff_current(&dbuff));
	TEST_CHECK(fr_dbuff_in_bytes(&child, 0xaa, 0xbb, 0xcc) == 3);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 7);			/* 4 + 3 */

	TEST_CASE("FR_DBUFF_BIND_CURRENT_ABS: start bound to parent 'start', writes advance parent 'current'");
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	fr_dbuff_advance(&dbuff, 4);
	child = FR_DBUFF_BIND_CURRENT_ABS(&dbuff);
	TEST_CHECK(fr_dbuff_start(&child) == fr_dbuff_start(&dbuff));
	TEST_CHECK(fr_dbuff_used(&child) == 4);
	TEST_CHECK(fr_dbuff_in_bytes(&child, 0xaa, 0xbb) == 2);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 6);			/* 4 + 2 */
	TEST_CHECK(fr_dbuff_used(&child) == 6);			/* child start == parent start */

	TEST_CASE("FR_DBUFF_BIND_END_ABS: writes advance parent 'end' (producer side)");
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	child = FR_DBUFF_BIND_END_ABS(&dbuff);
	TEST_CHECK(fr_dbuff_end(&dbuff) == buff + sizeof(buff));
	TEST_CHECK(fr_dbuff_in_bytes(&child, 0x01, 0x02, 0x03, 0x04, 0x05) == 5);
	TEST_CHECK(fr_dbuff_end(&dbuff) == buff + 5);		/* parent 'end' pulled back to producer position */
	TEST_CHECK(fr_dbuff_remaining(&dbuff) == 5);		/* consumer can now read what was produced */

	TEST_CASE("FR_DBUFF_MAX: caps available space, non-bind variant leaves parent alone");
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	child = FR_DBUFF_MAX(&dbuff, 4);
	TEST_CHECK(fr_dbuff_remaining(&child) == 4);
	TEST_CHECK(fr_dbuff_in_bytes(&child, 0x01, 0x02, 0x03, 0x04) == 4);
	TEST_CHECK(fr_dbuff_in_bytes(&child, 0x05) == -1);	/* capped: 1 byte short */
	TEST_CHECK(fr_dbuff_used(&dbuff) == 0);			/* parent NOT advanced */

	TEST_CASE("FR_DBUFF_MAX: _max larger than remaining is clamped to remaining");
	child = FR_DBUFF_MAX(&dbuff, 2 * sizeof(buff));
	TEST_CHECK(fr_dbuff_remaining(&child) == sizeof(buff));
}

/** Test the measurement / accessor macros against both a dbuff and a marker.
 *
 *  Covers fr_dbuff_len, fr_dbuff_buff, fr_dbuff_end, fr_dbuff_ptr,
 *  fr_dbuff_behind and fr_dbuff_ahead, which the existing tests never touch.
 */
static void test_dbuff_measure(void)
{
	fr_dbuff_t		dbuff;
	fr_dbuff_marker_t	m;
	uint8_t			buff[10] = "";

	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CASE("dbuff accessors");
	TEST_CHECK(fr_dbuff_len(&dbuff) == sizeof(buff));
	TEST_CHECK(fr_dbuff_buff(&dbuff) == buff);
	TEST_CHECK(fr_dbuff_start(&dbuff) == buff);
	TEST_CHECK(fr_dbuff_current(&dbuff) == buff);
	TEST_CHECK(fr_dbuff_end(&dbuff) == buff + sizeof(buff));
	TEST_CHECK(fr_dbuff_ptr(&dbuff) == &dbuff);

	TEST_CASE("marker behind then ahead of parent");
	fr_dbuff_marker(&m, &dbuff);
	fr_dbuff_advance(&dbuff, 6);
	TEST_CHECK(fr_dbuff_behind(&m) == 6);			/* marker 6 bytes behind parent */
	TEST_CHECK(fr_dbuff_ahead(&m) == 0);
	fr_dbuff_advance(&m, 8);
	TEST_CHECK(fr_dbuff_ahead(&m) == 2);			/* marker now 2 bytes ahead */
	TEST_CHECK(fr_dbuff_behind(&m) == 0);

	TEST_CASE("marker accessors resolve through parent");
	TEST_CHECK(fr_dbuff_buff(&m) == buff);
	TEST_CHECK(fr_dbuff_start(&m) == buff);
	TEST_CHECK(fr_dbuff_end(&m) == buff + sizeof(buff));
	TEST_CHECK(fr_dbuff_len(&m) == sizeof(buff));
	TEST_CHECK(fr_dbuff_ptr(&m) == &dbuff);
	TEST_CHECK(fr_dbuff_current(&m) == buff + 8);
	TEST_CHECK(fr_dbuff_used(&m) == 8);
	TEST_CHECK(fr_dbuff_remaining(&m) == 2);
}

/** Test fr_dbuff_set (by size_t, pointer, marker) and fr_dbuff_set_end.
 *
 *  The backing array is deliberately larger than the dbuff window so that we
 *  can form a pointer past the dbuff 'end' without forming a pointer outside
 *  the real allocation (which would be undefined behaviour).
 */
static void test_dbuff_set(void)
{
	uint8_t			backing[32];
	fr_dbuff_t		dbuff;
	fr_dbuff_marker_t	m;

	TEST_CASE("fr_dbuff_set by size_t offset, pointer, and out-of-range");
	fr_dbuff_init(&dbuff, backing, 10);
	TEST_CHECK(fr_dbuff_set(&dbuff, (size_t)5) == 5);
	TEST_CHECK(fr_dbuff_current(&dbuff) == backing + 5);
	TEST_CHECK(fr_dbuff_set(&dbuff, backing + 2) == -3);	/* moving backwards returns the signed diff */
	TEST_CHECK(fr_dbuff_current(&dbuff) == backing + 2);
	TEST_CHECK(fr_dbuff_set(&dbuff, backing + 20) == -10);	/* past 'end': bytes over, no move */
	TEST_CHECK(fr_dbuff_current(&dbuff) == backing + 2);

	TEST_CASE("fr_dbuff_set from a marker");
	fr_dbuff_set_to_start(&dbuff);
	fr_dbuff_marker(&m, &dbuff);
	fr_dbuff_advance(&m, 7);
	TEST_CHECK(fr_dbuff_set(&dbuff, &m) == 7);
	TEST_CHECK(fr_dbuff_current(&dbuff) == fr_dbuff_current(&m));

	TEST_CASE("fr_dbuff_set_end trims the 'end' pointer");
	fr_dbuff_init(&dbuff, backing, 10);
	fr_dbuff_advance(&dbuff, 3);
	fr_dbuff_set_end(&dbuff, backing + 6);
	TEST_CHECK(fr_dbuff_end(&dbuff) == backing + 6);
	TEST_CHECK(fr_dbuff_remaining(&dbuff) == 3);
#ifdef NDEBUG
	fr_dbuff_set_end(&dbuff, backing + 8);		/* beyond current 'end': asserts in debug builds */
#endif
	TEST_CHECK(fr_dbuff_end(&dbuff) == backing + 6);
}

/** Test fr_dbuff_advance_extend against a talloc-backed (extensible) dbuff. */
static void test_dbuff_advance_extend(void)
{
	fr_dbuff_t		dbuff;
	fr_dbuff_uctx_talloc_t	tctx;

	TEST_CHECK(fr_dbuff_init_talloc(NULL, &dbuff, &tctx, 4, 16) == &dbuff);

	TEST_CASE("advance within the initial allocation");
	TEST_CHECK(fr_dbuff_advance_extend(&dbuff, 2) == 2);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 2);

	TEST_CASE("advance past the current size triggers an extend");
	TEST_CHECK(fr_dbuff_advance_extend(&dbuff, 10) == 10);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 12);

	TEST_CASE("advance past max fails and does not advance");
	TEST_CHECK(fr_dbuff_advance_extend(&dbuff, 10) < 0);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 12);

	fr_dbuff_free_talloc(&dbuff);
}

/** Test fr_dbuff_memset. */
static void test_dbuff_memset(void)
{
	fr_dbuff_t	dbuff;
	uint8_t		buff[8] = "";

	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	TEST_CASE("memset writes and advances");
	TEST_CHECK(fr_dbuff_memset(&dbuff, 0xa5, 5) == 5);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 5);
	for (size_t i = 0; i < 5; i++) TEST_CHECK(buff[i] == 0xa5);

	TEST_CASE("memset that does not fit returns bytes needed and does not advance");
	TEST_CHECK(fr_dbuff_memset(&dbuff, 0x00, 5) == -2);	/* only 3 left, need 5 */
	TEST_CHECK(fr_dbuff_used(&dbuff) == 5);
}

/** Test fr_dbuff_in_memcpy, fr_dbuff_in_memcpy_partial and fr_dbuff_in_bytes_partial. */
static void test_dbuff_in_memcpy(void)
{
	uint8_t			buff[8] = "";
	uint8_t const		src[] = { 0x11, 0x22, 0x33, 0x44 };
	uint8_t			sbuf[4] = { 0x0a, 0x0b, 0x0c, 0x0d };
	char const		*str = "abc";
	fr_dbuff_t		dbuff;
	fr_dbuff_t		src_dbuff;

	TEST_CASE("exact copy from a byte buffer");
	fr_dbuff_init(&dbuff, buff, sizeof(buff));

	/*
	 *	Note _fr_dbuff_in_memcpy(), to avoid false positive complaints with -Werror=stringop-overread 
	 *
	 *	We could suppress the warn
	 */
	TEST_CHECK(_fr_dbuff_in_memcpy(_fr_dbuff_current_ptr(&dbuff), &dbuff, src, sizeof(src)) == 4);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 4);
	TEST_CHECK(memcmp(buff, src, 4) == 0);

	TEST_CASE("copy from a C string with SIZE_MAX uses strlen");
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	TEST_CHECK(fr_dbuff_in_memcpy(&dbuff, str, SIZE_MAX) == 3);
	TEST_CHECK(memcmp(buff, str, 3) == 0);

	TEST_CASE("copy that does not fit fails entirely and does not advance");
	fr_dbuff_init(&dbuff, buff, 2);
	TEST_CHECK(_fr_dbuff_in_memcpy(_fr_dbuff_current_ptr(&dbuff), &dbuff, src, sizeof(src)) == -2);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 0);

	TEST_CASE("copy from another dbuff, source is not advanced");
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	fr_dbuff_init(&src_dbuff, sbuf, sizeof(sbuf));
	TEST_CHECK(fr_dbuff_in_memcpy(&dbuff, &src_dbuff, 3) == 3);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 3);
	TEST_CHECK(fr_dbuff_used(&src_dbuff) == 0);
	TEST_CHECK(memcmp(buff, sbuf, 3) == 0);

	TEST_CASE("SIZE_MAX with a dbuff source copies the source's remaining bytes");
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	fr_dbuff_init(&src_dbuff, sbuf, sizeof(sbuf));
	TEST_CHECK(_fr_dbuff_in_memcpy_dbuff(_fr_dbuff_current_ptr(&dbuff), &dbuff, &src_dbuff.p, &src_dbuff,  SIZE_MAX) == 4);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 4);

	TEST_CASE("partial copy writes as much as fits and reports it");
	fr_dbuff_init(&dbuff, buff, 2);
	TEST_CHECK(_fr_dbuff_in_memcpy_partial(_fr_dbuff_current_ptr(&dbuff), &dbuff, src, sizeof(src)) == 2);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 2);
	TEST_CHECK(memcmp(buff, src, 2) == 0);

	TEST_CASE("in_bytes_partial truncates to the available space");
	fr_dbuff_init(&dbuff, buff, 3);
	TEST_CHECK(fr_dbuff_in_bytes_partial(&dbuff, 0xde, 0xad, 0xbe, 0xef) == 3);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 3);
}

/** Test fr_dbuff_marker_release, fr_dbuff_marker_release_behind and _ahead. */
static void test_dbuff_marker_release(void)
{
	uint8_t			buff[16];
	fr_dbuff_t		dbuff;
	fr_dbuff_marker_t	m1, m2;

	TEST_CASE("plain release trims the marker list back to the previous marker");
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	fr_dbuff_marker(&m1, &dbuff);
	fr_dbuff_marker(&m2, &dbuff);
	TEST_CHECK(dbuff.m == &m2);				/* newest marker at the head */
	fr_dbuff_marker_release(&m2);
	TEST_CHECK(dbuff.m == &m1);
	fr_dbuff_marker_release(&m1);
	TEST_CHECK(dbuff.m == NULL);

	TEST_CASE("release_behind returns how far the marker trailed the parent");
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	fr_dbuff_marker(&m1, &dbuff);
	fr_dbuff_advance(&dbuff, 4);
	fr_dbuff_marker(&m2, &dbuff);
	fr_dbuff_advance(&dbuff, 3);				/* parent at 7, m2 at 4 */
	TEST_CHECK(fr_dbuff_marker_release_behind(&m2) == 3);
	TEST_CHECK(dbuff.m == &m1);

	TEST_CASE("release_ahead returns how far the marker led the parent");
	fr_dbuff_set(&m1, (size_t)10);				/* m1 at 10, parent at 7 */
	TEST_CHECK(fr_dbuff_marker_release_ahead(&m1) == 3);
	TEST_CHECK(dbuff.m == NULL);
}

/** Test fr_dbuff_out_int64v, which sign-extends based on the most significant bit. */
static void test_dbuff_out_int64v(void)
{
	uint8_t const	pos[] = { 0x7f, 0xff };			/* MSB clear -> positive */
	uint8_t const	neg[] = { 0xff, 0x00 };			/* MSB set   -> negative */
	fr_dbuff_t	dbuff;
	int64_t		val;

	TEST_CASE("positive two-byte value");
	fr_dbuff_init(&dbuff, pos, sizeof(pos));
	TEST_CHECK(fr_dbuff_out_int64v(&val, &dbuff, 2) == 2);
	TEST_CHECK(val == 0x7fff);

	TEST_CASE("negative two-byte value is sign extended");
	fr_dbuff_init(&dbuff, neg, sizeof(neg));
	TEST_CHECK(fr_dbuff_out_int64v(&val, &dbuff, 2) == 2);
	TEST_CHECK(val == -256);

	TEST_CASE("single positive byte");
	fr_dbuff_init(&dbuff, pos, sizeof(pos));
	TEST_CHECK(fr_dbuff_out_int64v(&val, &dbuff, 1) == 1);
	TEST_CHECK(val == 0x7f);

	TEST_CASE("not enough data returns bytes needed");
	fr_dbuff_init(&dbuff, pos, 1);
	TEST_CHECK(fr_dbuff_out_int64v(&val, &dbuff, 2) == -1);
}

/** Test fr_dbuff_shift moves unconsumed content to the front of the buffer. */
static void test_dbuff_shift(void)
{
	uint8_t		buff[8] = "";
	fr_dbuff_t	dbuff;

	memcpy(buff, "ABCDEFGH", sizeof(buff));
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	fr_dbuff_advance(&dbuff, 3);				/* consume "ABC" */

	TEST_CASE("shift discards consumed bytes and moves the rest down");
	TEST_CHECK(fr_dbuff_shift(&dbuff, 3) == 3);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 0);
	TEST_CHECK(memcmp(buff, "DEFGH", 5) == 0);
	TEST_CHECK(fr_dbuff_remaining(&dbuff) == 5);		/* 'end' pulled down by the shift */
}

/** Test fr_dbuff_update repoints the dbuff and its markers after a buffer move. */
static void test_dbuff_update(void)
{
	uint8_t			buff[8] = "";
	uint8_t			newbuff[8] = "";
	fr_dbuff_t		dbuff;
	fr_dbuff_marker_t	m;

	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	fr_dbuff_advance(&dbuff, 4);
	fr_dbuff_marker(&m, &dbuff);				/* marker at offset 4 */
	fr_dbuff_set_to_start(&dbuff);
	fr_dbuff_advance(&dbuff, 2);				/* dbuff 'current' at offset 2 */

	TEST_CASE("relative offsets are preserved against the new buffer");
	fr_dbuff_update(&dbuff, newbuff, sizeof(newbuff));
	TEST_CHECK(fr_dbuff_buff(&dbuff) == newbuff);
	TEST_CHECK(fr_dbuff_start(&dbuff) == newbuff);
	TEST_CHECK(fr_dbuff_current(&dbuff) == newbuff + 2);
	TEST_CHECK(fr_dbuff_end(&dbuff) == newbuff + sizeof(newbuff));
	TEST_CHECK(fr_dbuff_current(&m) == newbuff + 4);	/* marker offset preserved */
}

/** Test fr_dbuff_trim_talloc, fr_dbuff_reset_talloc and fr_dbuff_free_talloc. */
static void test_dbuff_trim_reset_talloc(void)
{
	fr_dbuff_t		dbuff;
	fr_dbuff_uctx_talloc_t	tctx;

	TEST_CHECK(fr_dbuff_init_talloc(NULL, &dbuff, &tctx, 32, 128) == &dbuff);
	TEST_CHECK(talloc_array_length(dbuff.buff) == 32);
	TEST_CHECK(fr_dbuff_in_bytes(&dbuff, 0x01, 0x02, 0x03, 0x04) == 4);

	TEST_CASE("trim to content length (SIZE_MAX)");
	TEST_CHECK(fr_dbuff_trim_talloc(&dbuff, SIZE_MAX) == 0);
	TEST_CHECK(talloc_array_length(dbuff.buff) == 4);
	TEST_CHECK(fr_dbuff_len(&dbuff) == 4);

	TEST_CASE("trim to an explicit length");
	TEST_CHECK(fr_dbuff_trim_talloc(&dbuff, 2) == 0);
	TEST_CHECK(talloc_array_length(dbuff.buff) == 2);

	TEST_CASE("reset restores the initial length and clears the position");
	TEST_CHECK(fr_dbuff_reset_talloc(&dbuff) == 0);
	TEST_CHECK(talloc_array_length(dbuff.buff) == 32);
	TEST_CHECK(fr_dbuff_used(&dbuff) == 0);

	TEST_CASE("free_talloc releases the buffer");
	fr_dbuff_free_talloc(&dbuff);
	TEST_CHECK(dbuff.buff == NULL);
}

/** Test FR_DBUFF_TMP, the compound-literal dbuff. */
static void test_dbuff_tmp(void)
{
	uint8_t		buff[8] = "";
	fr_dbuff_t	tmp = FR_DBUFF_TMP(buff, sizeof(buff));

	TEST_CASE("compound literal points at the supplied buffer and is writable");
	TEST_CHECK(fr_dbuff_start(&tmp) == buff);
	TEST_CHECK(fr_dbuff_current(&tmp) == buff);
	TEST_CHECK(fr_dbuff_end(&tmp) == buff + sizeof(buff));
	TEST_CHECK(fr_dbuff_in_bytes(&tmp, 0x01, 0x02) == 2);
	TEST_CHECK(buff[0] == 0x01);
	TEST_CHECK(buff[1] == 0x02);
}

/** Test the extension-request API: fr_dbuff_extend, fr_dbuff_extend_lowat,
 *  fr_dbuff_is_extendable and fr_dbuff_was_extended.
 */
static void test_dbuff_extend(void)
{
	uint8_t				buff[8];
	fr_dbuff_t			dbuff;
	fr_dbuff_uctx_talloc_t		tctx;
	fr_dbuff_extend_status_t	status;

	TEST_CASE("fixed buffer: extend returns remaining and never grows");
	fr_dbuff_init(&dbuff, buff, sizeof(buff));
	TEST_CHECK(fr_dbuff_extend(&dbuff) == sizeof(buff));

	TEST_CASE("fixed buffer at end: cannot satisfy lowat");
	status = FR_DBUFF_EXTENDABLE;
	fr_dbuff_advance(&dbuff, sizeof(buff));
	TEST_CHECK(fr_dbuff_extend_lowat(&status, &dbuff, 4) == 0);
	TEST_CHECK(fr_dbuff_is_extendable(status) == 0);
	TEST_CHECK(fr_dbuff_was_extended(status) == 0);

	TEST_CASE("talloc buffer: extend grows and flags report it");
	TEST_CHECK(fr_dbuff_init_talloc(NULL, &dbuff, &tctx, 4, 64) == &dbuff);
	status = FR_DBUFF_EXTENDABLE;
	fr_dbuff_advance(&dbuff, 4);				/* remaining now 0 */
	TEST_CHECK(fr_dbuff_extend_lowat(&status, &dbuff, 8) >= 8);
	TEST_CHECK(fr_dbuff_is_extendable(status));
	TEST_CHECK(fr_dbuff_was_extended(status));

	fr_dbuff_free_talloc(&dbuff);
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
	{ "fr_dbuff_fd",				test_dbuff_fd },
	{ "fr_dbuff_fd_max",				test_dbuff_fd_max },
	{ "fr_dbuff_out",				test_dbuff_out },

	/*
	 *	Child dbuffs, accessors, positioning and lifecycle
	 */
	{ "fr_dbuff_child",				test_dbuff_child },
	{ "fr_dbuff_measure",				test_dbuff_measure },
	{ "fr_dbuff_set",				test_dbuff_set },
	{ "fr_dbuff_advance_extend",			test_dbuff_advance_extend },
	{ "fr_dbuff_memset",				test_dbuff_memset },
	{ "fr_dbuff_in_memcpy",				test_dbuff_in_memcpy },
	{ "fr_dbuff_marker_release",			test_dbuff_marker_release },
	{ "fr_dbuff_out_int64v",			test_dbuff_out_int64v },
	{ "fr_dbuff_shift",				test_dbuff_shift },
	{ "fr_dbuff_update",				test_dbuff_update },
	{ "fr_dbuff_trim_reset_talloc",			test_dbuff_trim_reset_talloc },
	{ "fr_dbuff_tmp",				test_dbuff_tmp },
	{ "fr_dbuff_extend",				test_dbuff_extend },

	TEST_TERMINATOR
};

