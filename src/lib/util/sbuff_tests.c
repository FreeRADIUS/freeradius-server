#include <freeradius-devel/util/acutest.h>

#include "sbuff.c"

//#include <gperftools/profiler.h>

static void test_parse_init(void)
{
	char const	*in = "i am a test string";
	fr_sbuff_t	sbuff;

	TEST_CASE("Parse init with size");
	fr_sbuff_parse_init(&sbuff, in, strlen(in));

	TEST_CHECK(sbuff.start == in);
	TEST_CHECK(sbuff.p == in);
	TEST_CHECK(sbuff.end == in + strlen(in));

	TEST_CASE("Parse init with end");
	fr_sbuff_parse_init(&sbuff, in, in + strlen(in));

	TEST_CHECK(sbuff.start == in);
	TEST_CHECK(sbuff.p == in);
	TEST_CHECK(sbuff.end == in + strlen(in));

	TEST_CASE("Parse init with const end");
	fr_sbuff_parse_init(&sbuff, in, (char const *)(in + strlen(in)));

	TEST_CHECK(sbuff.start == in);
	TEST_CHECK(sbuff.p == in);
	TEST_CHECK(sbuff.end == in + strlen(in));
}

static void test_strncpy_exact(void)
{
	char const	*in = "i am a test string";
	char const	*in_long = "i am a longer test string";
	char		out[18 + 1];
	fr_sbuff_t	sbuff;
	ssize_t		slen;

	fr_sbuff_parse_init(&sbuff, in, strlen(in));

	TEST_CASE("Copy 5 bytes to out");
	slen = fr_sbuff_strncpy_exact(out, sizeof(out), &sbuff, 5);
	TEST_CHECK(slen == 5);
	TEST_CHECK(strcmp(out, "i am ") == 0);
	TEST_CHECK(strcmp(sbuff.p, "a test string") == 0);

	TEST_CASE("Copy 13 bytes to out");
	slen = fr_sbuff_strncpy_exact(out, sizeof(out), &sbuff, 13);
	TEST_CHECK(slen == 13);
	TEST_CHECK(strcmp(out, "a test string") == 0);
	TEST_CHECK(strcmp(sbuff.p, "") == 0);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun input");
	slen = fr_sbuff_strncpy_exact(out, sizeof(out), &sbuff, 1);
	TEST_CHECK(slen == 0);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun output (and SIZE_MAX special value)");
	fr_sbuff_parse_init(&sbuff, in_long, strlen(in_long));

	slen = fr_sbuff_strncpy_exact(out, sizeof(out), &sbuff, SIZE_MAX);
	TEST_CHECK(slen == -7);
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Zero length output buffer");
	fr_sbuff_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_strncpy_exact(out, 0, &sbuff, SIZE_MAX);
	TEST_CHECK(slen == -26);
	TEST_CHECK(out[0] == 'a');	/* Must not write \0 */
	TEST_CHECK(sbuff.p == sbuff.start);
}

static void test_strncpy(void)
{
	char const	*in = "i am a test string";
	char const	*in_long = "i am a longer test string";
	char		out[18 + 1];
	fr_sbuff_t	sbuff;
	ssize_t		slen;

	fr_sbuff_parse_init(&sbuff, in, strlen(in));

	TEST_CASE("Copy 5 bytes to out");
	slen = fr_sbuff_strncpy(out, sizeof(out), &sbuff, 5);
	TEST_CHECK(slen == 5);
	TEST_CHECK(strcmp(out, "i am ") == 0);
	TEST_CHECK(strcmp(sbuff.p, "a test string") == 0);

	TEST_CASE("Copy 13 bytes to out");
	slen = fr_sbuff_strncpy(out, sizeof(out), &sbuff, 13);
	TEST_CHECK(slen == 13);
	TEST_CHECK(strcmp(out, "a test string") == 0);
	TEST_CHECK(strcmp(sbuff.p, "") == 0);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun input");
	slen = fr_sbuff_strncpy(out, sizeof(out), &sbuff, 1);
	TEST_CHECK(slen == 0);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun output (and SIZE_MAX special value)");
	fr_sbuff_parse_init(&sbuff, in_long, strlen(in_long));

	slen = fr_sbuff_strncpy(out, sizeof(out), &sbuff, SIZE_MAX);
	TEST_CHECK(slen == 18);
	TEST_CHECK(strcmp(out, "i am a longer test") == 0);

	TEST_CASE("Zero length output buffer");
	fr_sbuff_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_strncpy(out, 0, &sbuff, SIZE_MAX);
	TEST_CHECK(slen == 0);
	TEST_CHECK(out[0] == 'a');	/* Must not write \0 */
	TEST_CHECK(sbuff.p == sbuff.start);
}

/*
static void test_sbuff_parse_num(void)
{
	char const	*uint8_str_overflow = "256";
	char const	*uint64_str_overflow = "18446744073709551616";
	char const	*number_str =
}
*/

static void test_no_advance(void)
{
	char const	*in = "i am a test string";
	char		out[18 + 1];
	fr_sbuff_t	sbuff;
	ssize_t		slen;

	fr_sbuff_parse_init(&sbuff, in, strlen(in));

	TEST_CASE("Copy 5 bytes to out - no advance");
	TEST_CHECK(sbuff.p == sbuff.start);
	slen = fr_sbuff_strncpy_exact(out, sizeof(out), FR_SBUFF_NO_ADVANCE(&sbuff), 5);
	TEST_CHECK(slen == 5);
	TEST_CHECK(strcmp(out, "i am ") == 0);
	TEST_CHECK(sbuff.p == sbuff.start);
}

TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "fr_sbuff_parse_init",			test_parse_init },
	{ "fr_sbuff_strncpy_exact",			test_strncpy_exact },
	{ "fr_sbuff_strncpy",				test_strncpy },
	{ "no-advance",					test_no_advance },

	{ NULL }
};
