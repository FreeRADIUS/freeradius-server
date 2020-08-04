#include <freeradius-devel/util/acutest.h>

#include "sbuff.c"

//#include <gperftools/profiler.h>

#define TEST_SBUFF_LEN(_sbuff, _num) \
do { \
	size_t _len; \
	_len = talloc_array_length((_sbuff)->buff); \
	TEST_CHECK(_len == (size_t)_num); \
	TEST_MSG("Expected length : %zu", (size_t)_num); \
	TEST_MSG("Got length      : %zu", _len); \
} while(0)

#define TEST_SBUFF_USED(_sbuff, _num) \
do { \
	size_t _len; \
	_len = fr_sbuff_used(_sbuff); \
	TEST_CHECK(_len == (size_t)_num); \
	TEST_MSG("Expected length : %zu", (size_t)_num); \
	TEST_MSG("Got length      : %zu", _len); \
} while(0)

#define TEST_CHECK_LEN(_exp, _got) \
do { \
	size_t _our_got = (_got); \
	TEST_CHECK(_exp == _our_got); \
	TEST_MSG("Expected length : %zu", (ssize_t)_exp); \
	TEST_MSG("Got length      : %zu", (ssize_t)_our_got); \
} while(0)

#define TEST_CHECK_SLEN(_exp, _got) \
do { \
	ssize_t _our_got = (_got); \
	TEST_CHECK(_exp == _our_got); \
	TEST_MSG("Expected length : %zd", (ssize_t)_exp); \
	TEST_MSG("Got length      : %zd", (ssize_t)_our_got); \
} while(0)

#define TEST_CHECK_STRCMP(_exp, _got) \
do { \
	char *_our_got = (_got); \
	TEST_CHECK((_exp) && (_got) && (strcmp(_exp, _our_got) == 0)); \
	TEST_MSG("Expected : \"%s\"", _exp); \
	TEST_MSG("Got      : \"%s\"", _our_got); \
} while(0)

static void test_parse_init(void)
{
	char const	in[] = "i am a test string";
	fr_sbuff_t	sbuff;

	TEST_CASE("Parse init with size");
	fr_sbuff_init(&sbuff, in, sizeof(in));

	TEST_CHECK(sbuff.start == in);
	TEST_CHECK(sbuff.p == in);
	TEST_CHECK(sbuff.end == in + (sizeof(in) - 1));

	TEST_CASE("Parse init with end");
	fr_sbuff_init(&sbuff, in, in + strlen(in));

	TEST_CHECK(sbuff.start == in);
	TEST_CHECK(sbuff.p == in);
	TEST_CHECK(sbuff.end == in + strlen(in));

	TEST_CASE("Parse init with const end");
	fr_sbuff_init(&sbuff, in, (char const *)(in + strlen(in)));

	TEST_CHECK(sbuff.start == in);
	TEST_CHECK(sbuff.p == in);
	TEST_CHECK(sbuff.end == in + strlen(in));
}

static void test_bstrncpy_exact(void)
{
	char const	in[] = "i am a test string";
	char const	in_long[] = "i am a longer test string";
	char		out[18 + 1];
	fr_sbuff_t	sbuff;
	ssize_t		slen;

	fr_sbuff_init(&sbuff, in, sizeof(in));

	TEST_CASE("Copy 5 bytes to out");
	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 5);
	TEST_CHECK_SLEN(5, slen);
	TEST_CHECK_STRCMP("i am ", out);
	TEST_CHECK_STRCMP("a test string", sbuff.p);

	TEST_CASE("Copy 13 bytes to out");
	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 13);
	TEST_CHECK_SLEN(13, slen);
	TEST_CHECK_STRCMP("a test string", out);
	TEST_CHECK_STRCMP("", sbuff.p);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun input");
	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 1);
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun output (and SIZE_MAX special value)");
	fr_sbuff_init(&sbuff, in_long, sizeof(in_long));

	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX);
	TEST_CHECK_SLEN(-7, slen);
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Zero length output buffer");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, SIZE_MAX);
	TEST_CHECK_SLEN(-25, slen);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Zero length size");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, 0);
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);
}

static void test_bstrncpy(void)
{
	char const	in[] = "i am a test string";
	char const	in_long[] = "i am a longer test string";
	char		out[18 + 1];
	fr_sbuff_t	sbuff;
	ssize_t		slen;

	fr_sbuff_init(&sbuff, in, sizeof(in));

	TEST_CASE("Copy 5 bytes to out");
	slen = fr_sbuff_out_bstrncpy(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 5);
	TEST_CHECK_SLEN(5, slen);
	TEST_CHECK_STRCMP("i am ", out);
	TEST_CHECK_STRCMP("a test string", sbuff.p);

	TEST_CASE("Copy 13 bytes to out");
	slen = fr_sbuff_out_bstrncpy(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 13);
	TEST_CHECK_SLEN(13, slen);
	TEST_CHECK_STRCMP("a test string", out);
	TEST_CHECK_STRCMP("", sbuff.p);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun input");
	slen = fr_sbuff_out_bstrncpy(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 1);
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun output (and SIZE_MAX special value)");
	fr_sbuff_init(&sbuff, in_long, sizeof(in_long));

	slen = fr_sbuff_out_bstrncpy(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX);
	TEST_CHECK_SLEN(18, slen);
	TEST_CHECK_STRCMP("i am a longer test", out);

	TEST_CASE("Zero length output buffer");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, SIZE_MAX);
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Zero length size");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, 0);
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);
}

static bool allow_lowercase_and_space[UINT8_MAX + 1] = {
	['a'] = true, ['b'] = true, ['c'] = true, ['d'] = true, ['e'] = true,
	['f'] = true, ['g'] = true, ['h'] = true, ['i'] = true, ['j'] = true,
	['k'] = true, ['l'] = true, ['m'] = true, ['n'] = true, ['o'] = true,
	['p'] = true, ['q'] = true, ['r'] = true, ['s'] = true, ['t'] = true,
	['u'] = true, ['v'] = true, ['w'] = true, ['x'] = true, ['y'] = true,
	['z'] = true, [' '] = true
};

static bool allow_lowercase_and_space_no_t[UINT8_MAX + 1] = {
	['a'] = true, ['b'] = true, ['c'] = true, ['d'] = true, ['e'] = true,
	['f'] = true, ['g'] = true, ['h'] = true, ['i'] = true, ['j'] = true,
	['k'] = true, ['l'] = true, ['m'] = true, ['n'] = true, ['o'] = true,
	['p'] = true, ['q'] = true, ['r'] = true, ['s'] = true, ['t'] = false,
	['u'] = true, ['v'] = true, ['w'] = true, ['x'] = true, ['y'] = true,
	['z'] = true, [' '] = true
};

static void test_bstrncpy_allowed(void)
{
	char const	in[] = "i am a test string";
	char const	in_long[] = "i am a longer test string";
	char		out[18 + 1];
	fr_sbuff_t	sbuff;
	ssize_t		slen;

	fr_sbuff_init(&sbuff, in, sizeof(in));

	/*
	 *	Should behave identically to bstrncpy
	 *	where there's no restrictions on char
	 *	set.
	 */
	TEST_CASE("Copy 5 bytes to out");
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 5, allow_lowercase_and_space);
	TEST_CHECK_SLEN(5, slen);
	TEST_CHECK_STRCMP("i am ", out);
	TEST_CHECK_STRCMP("a test string", sbuff.p);

	TEST_CASE("Copy 13 bytes to out");
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 13, allow_lowercase_and_space);
	TEST_CHECK_SLEN(13, slen);
	TEST_CHECK_STRCMP("a test string", out);
	TEST_CHECK_STRCMP("", sbuff.p);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun input");
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 1, allow_lowercase_and_space);
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun output (and SIZE_MAX special value)");
	fr_sbuff_init(&sbuff, in_long, sizeof(in_long));

	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, allow_lowercase_and_space);
	TEST_CHECK_SLEN(18, slen);
	TEST_CHECK_STRCMP("i am a longer test", out);

	TEST_CASE("Zero length output buffer");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, SIZE_MAX, allow_lowercase_and_space);
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Zero length size");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, SIZE_MAX, allow_lowercase_and_space);
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	/*
	 *	Check copy stops early
	 */
	TEST_CASE("Copy until first t");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX,
					     allow_lowercase_and_space_no_t);
	TEST_CHECK_SLEN(14, slen);
	TEST_CHECK_STRCMP("i am a longer ", out);

	TEST_CASE("Copy until first t with length constraint (same len as token)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, 15), &sbuff, SIZE_MAX,
					     allow_lowercase_and_space_no_t);
	TEST_CHECK_SLEN(14, slen);
	TEST_CHECK_STRCMP("i am a longer ", out);

	TEST_CASE("Copy until first t with length constraint (one shorter than token)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, 14), &sbuff, SIZE_MAX,
					     allow_lowercase_and_space_no_t);
	TEST_CHECK_SLEN(13, slen);
	TEST_CHECK_STRCMP("i am a longer", out);

	TEST_CASE("Zero length token (should still be terminated)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, 14), &sbuff, SIZE_MAX,
					     (bool[UINT8_MAX + 1]){});
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK_STRCMP("", out);
}

static void test_bstrncpy_until(void)
{
	char const	in[] = "i am a test string";
	char const	in_long[] = "i am a longer test string";
	char		out[18 + 1];
	fr_sbuff_t	sbuff;
	ssize_t		slen;

	fr_sbuff_init(&sbuff, in, sizeof(in));

	/*
	 *	Should behave identically to bstrncpy
	 *	where there's no restrictions on char
	 *	set.
	 */
	TEST_CASE("Copy 5 bytes to out");
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 5, NULL, '\0');
	TEST_CHECK_SLEN(5, slen);
	TEST_CHECK_STRCMP("i am ", out);
	TEST_CHECK_STRCMP("a test string", sbuff.p);

	TEST_CASE("Copy 13 bytes to out");
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 13, NULL, '\0');
	TEST_CHECK_SLEN(13, slen);
	TEST_CHECK_STRCMP("a test string", out);
	TEST_CHECK_STRCMP("", sbuff.p);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun input");
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 1, NULL, '\0');
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Check escapes");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, &FR_SBUFF_TERM("g"), 'n');
	TEST_CHECK_SLEN(18, slen);
	TEST_CHECK_STRCMP("i am a test string", out);
	TEST_CHECK_STRCMP("", sbuff.p);

	TEST_CASE("Copy would overrun output (and SIZE_MAX special value)");
	fr_sbuff_init(&sbuff, in_long, sizeof(in_long));

	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, NULL, '\0');
	TEST_CHECK_SLEN(18, slen);
	TEST_CHECK_STRCMP("i am a longer test", out);

	TEST_CASE("Zero length output buffer");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, SIZE_MAX, NULL, '\0');
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Zero length size");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 0, NULL, '\0');
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	/*
	 *	Check copy stops early
	 */
	TEST_CASE("Copy until first t");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, &FR_SBUFF_TERM("t"), '\0');
	TEST_CHECK_SLEN(14, slen);
	TEST_CHECK_STRCMP("i am a longer ", out);

	TEST_CASE("Copy until first t with length constraint (same len as token)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, 15), &sbuff, SIZE_MAX, &FR_SBUFF_TERM("t"), '\0');
	TEST_CHECK_SLEN(14, slen);
	TEST_CHECK_STRCMP("i am a longer ", out);

	TEST_CASE("Copy until first t with length constraint (one shorter than token)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, 14), &sbuff, SIZE_MAX, &FR_SBUFF_TERM("t"), '\0');
	TEST_CHECK_SLEN(13, slen);
	TEST_CHECK_STRCMP("i am a longer", out);

	TEST_CASE("Zero length token (should still be terminated)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, 14), &sbuff, SIZE_MAX, &FR_SBUFF_TERM("i"), '\0');
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK_STRCMP("", out);
}

static void test_unescape_until(void)
{
	char const		in[] = "i am a test string";
	char const		in_long[] = "i am a longer test string";
	char const		in_escapes[] = "i am a |t|est strin|g";
	char const		in_escapes_seq[] = "i |x|0am a |t|est strin|g|x20|040";
	char			out[18 + 1];
	char			escape_out[20 + 1];

	fr_sbuff_t		sbuff;
	ssize_t			slen;

	fr_sbuff_escape_rules_t	rules = {
					.chr = '\\'
				};

	fr_sbuff_escape_rules_t	pipe_rules = {
					.chr = '|',
					.subs = { ['g'] = 'g', ['|'] = '|'  }
				};

	fr_sbuff_escape_rules_t	pipe_rules_sub = {
					.chr = '|', .subs = { ['g'] = 'h', ['|'] = '|'  }
				};

	fr_sbuff_escape_rules_t	pipe_rules_sub_hex = {
					.chr = '|',
					.subs = { ['g'] = 'h', ['|'] = '|'  },
					.do_hex = true
				};

	fr_sbuff_escape_rules_t	pipe_rules_sub_oct = {
					.chr = '|',
					.subs = { ['g'] = 'h', ['|'] = '|' },
					.do_oct = true
				};

	fr_sbuff_escape_rules_t	pipe_rules_both = {
					.chr = '|',
					.subs = { ['g'] = 'h', ['|'] = '|'  },
					.do_hex = true,
					.do_oct = true
				};

	fr_sbuff_init(&sbuff, in, sizeof(in));
	/*
	 *	Should behave identically to bstrncpy
	 *	where there's no restrictions on char
	 *	set.
	 */
	TEST_CASE("Copy 5 bytes to out");
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 5, NULL, &rules);
	TEST_CHECK_SLEN(5, slen);
	TEST_CHECK_STRCMP("i am ", out);
	TEST_CHECK_STRCMP("a test string", sbuff.p);

	TEST_CASE("Copy 13 bytes to out");
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 13, NULL, &rules);
	TEST_CHECK_SLEN(13, slen);
	TEST_CHECK_STRCMP("a test string", out);
	TEST_CHECK_STRCMP("", sbuff.p);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun input");
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 1, NULL, &rules);
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun output (and SIZE_MAX special value)");
	fr_sbuff_init(&sbuff, in_long, sizeof(in_long));

	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, NULL, &rules);
	TEST_CHECK_SLEN(18, slen);
	TEST_CHECK_STRCMP("i am a longer test", out);

	TEST_CASE("Zero length output buffer");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, SIZE_MAX, NULL, &rules);
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Zero length size");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 0, NULL, &rules);
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	/*
	 *	Check copy stops early
	 */
	TEST_CASE("Copy until first t");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX,
					   &FR_SBUFF_TERM("t"), &rules);
	TEST_CHECK_SLEN(14, slen);
	TEST_CHECK_STRCMP("i am a longer ", out);

	TEST_CASE("Copy until first t with length constraint (same len as token)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, 15), &sbuff, SIZE_MAX,
					   &FR_SBUFF_TERM("t"), &rules);
	TEST_CHECK_SLEN(14, slen);
	TEST_CHECK_STRCMP("i am a longer ", out);

	TEST_CASE("Copy until first t with length constraint (one shorter than token)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, 14), &sbuff, SIZE_MAX,
					   &FR_SBUFF_TERM("t"), &rules);
	TEST_CHECK_SLEN(13, slen);
	TEST_CHECK_STRCMP("i am a longer", out);

	TEST_CASE("Zero length token (should still be terminated)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, 14), &sbuff, SIZE_MAX,
					   &FR_SBUFF_TERM("i"), &rules);
	TEST_CHECK_SLEN(0, slen);
	TEST_CHECK_STRCMP("", out);

	/*
	 *	Escapes and substitution
	 */
	TEST_CASE("Escape with substition to same char");
	fr_sbuff_init(&sbuff, in_escapes, sizeof(in_escapes));
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(escape_out, sizeof(escape_out)), &sbuff, SIZE_MAX,
					   &FR_SBUFF_TERM("g"), &pipe_rules);
	TEST_CHECK_SLEN(20, slen);
	TEST_CHECK_STRCMP("i am a |t|est string", escape_out);
	TEST_CHECK_STRCMP("", sbuff.p);

	TEST_CASE("Escape with substition to different char");
	fr_sbuff_init(&sbuff, in_escapes, sizeof(in_escapes));
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(escape_out, sizeof(escape_out)), &sbuff, SIZE_MAX,
					   &FR_SBUFF_TERM("g"), &pipe_rules_sub);
	TEST_CHECK_SLEN(20, slen);
	TEST_CHECK_STRCMP("i am a |t|est strinh", escape_out);
	TEST_CHECK_STRCMP("", sbuff.p);

	{
		char	tmp_out[24 + 1];

		TEST_CASE("Escape with hex substitutions (insufficient output space)");
		fr_sbuff_init(&sbuff, in_escapes_seq, sizeof(in_escapes_seq));
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(tmp_out, sizeof(tmp_out)), &sbuff, SIZE_MAX,
						   &FR_SBUFF_TERM("g"), &pipe_rules_sub_hex);
		TEST_CHECK_SLEN(24, slen);
		TEST_CHECK_STRCMP("i |x|0am a |t|est strinh", tmp_out);
		TEST_CHECK_STRCMP("|x20|040", sbuff.p);
	}

	{
		char	tmp_out[25 + 1];

		TEST_CASE("Escape with hex substitutions (sufficient output space)");
		fr_sbuff_init(&sbuff, in_escapes_seq, sizeof(in_escapes_seq));
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(tmp_out, sizeof(tmp_out)), &sbuff, SIZE_MAX,
						   &FR_SBUFF_TERM("g"), &pipe_rules_sub_hex);
		TEST_CHECK_SLEN(25, slen);
		TEST_CHECK_STRCMP("i |x|0am a |t|est strinh ", tmp_out);
		TEST_CHECK_STRCMP("|040", sbuff.p);
	}

	{
		char	tmp_out[28 + 1];

		TEST_CASE("Escape with oct substitutions (insufficient output space)");
		fr_sbuff_init(&sbuff, in_escapes_seq, sizeof(in_escapes_seq));
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(tmp_out, sizeof(tmp_out)), &sbuff, SIZE_MAX,
						   &FR_SBUFF_TERM("g"), &pipe_rules_sub_oct);
		TEST_CHECK_SLEN(28, slen);
		TEST_CHECK_STRCMP("i |x|0am a |t|est strinh|x20", tmp_out);
		TEST_CHECK_STRCMP("|040", sbuff.p);
	}

	{
		char	tmp_out[29 + 1];

		TEST_CASE("Escape with oct substitutions (sufficient output space)");
		fr_sbuff_init(&sbuff, in_escapes_seq, sizeof(in_escapes_seq));
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(tmp_out, sizeof(tmp_out)), &sbuff, SIZE_MAX,
						   &FR_SBUFF_TERM("g"), &pipe_rules_sub_oct);
		TEST_CHECK_SLEN(29, slen);
		TEST_CHECK_STRCMP("i |x|0am a |t|est strinh|x20 ", tmp_out);
		TEST_CHECK_STRCMP("", sbuff.p);
	}

	{
		char	tmp_out[26 + 1];

		TEST_CASE("Escape with hex and oct substitutions (sufficient output space)");
		fr_sbuff_init(&sbuff, in_escapes_seq, sizeof(in_escapes_seq));
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(tmp_out, sizeof(tmp_out)), &sbuff, SIZE_MAX,
						   &FR_SBUFF_TERM("g"), &pipe_rules_both);
		TEST_CHECK_SLEN(26, slen);
		TEST_CHECK_STRCMP("i |x|0am a |t|est strinh  ", tmp_out);
		TEST_CHECK_STRCMP("", sbuff.p);
	}

	{
		char		tmp_out[2 + 1];
		char const	in_escapes_collapse[] = "||";

		TEST_CASE("Collapse double escapes");
		fr_sbuff_init(&sbuff, in_escapes_collapse, sizeof(in_escapes_collapse));
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(tmp_out, sizeof(tmp_out)),
						   &sbuff, SIZE_MAX, NULL, &pipe_rules);
		TEST_CHECK_SLEN(1, slen);
		TEST_CHECK_STRCMP("|", tmp_out);
		TEST_CHECK_STRCMP("", sbuff.p);
	}

	{
		char	in_escapes_collapse[] = "||foo||";

		TEST_CASE("Collapse double escapes overlapping");
		fr_sbuff_init(&sbuff, in_escapes_collapse, sizeof(in_escapes_collapse));
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(in_escapes_collapse, sizeof(in_escapes_collapse)),
						   &sbuff, SIZE_MAX, NULL, &pipe_rules);
		TEST_CHECK_SLEN(5, slen);
		TEST_CHECK_STRCMP("|foo|", in_escapes_collapse);
		TEST_CHECK_STRCMP("", sbuff.p);
	}

	{
		char		tmp_out[30 + 1];

		fr_sbuff_escape_rules_t double_quote_rules = {
			.chr = '\\',
			.subs = {
				['a'] = '\a',
				['b'] = '\b',
				['e'] = '\\',
				['n'] = '\n',
				['r'] = '\r',
				['t'] = '\t',
				['v'] = '\v',
				['\\'] = '\\',
				['"'] = '"'	/* Quoting char */
			},
			.do_hex = true,
			.do_oct = true
		};

		char const	in_escapes_unit[] =
			"0x01\\001"
			"0x07\\007"
			"0x0A\\n"
			"0x0D\\r"
			"\\\"\\\""
			"0xb0"
			"\\260\\xb0";

		char const	expected[] = {
			'0', 'x', '0', '1', '\001',
			'0', 'x', '0', '7', '\007',
			'0', 'x', '0', 'A', '\n',
			'0', 'x', '0', 'D', '\r',
			'"', '"',
			'0', 'x', 'b', '0',
			'\260', '\xb0', '\0'
		};

		TEST_CASE("Check unit test test strings");
		fr_sbuff_init(&sbuff, in_escapes_unit, sizeof(in_escapes_unit));
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(tmp_out, sizeof(tmp_out)), &sbuff, SIZE_MAX,
						   NULL, &double_quote_rules);
		TEST_CHECK_SLEN(28, slen);
		TEST_CHECK_STRCMP(expected, tmp_out);
		TEST_CHECK_STRCMP("", sbuff.p);
	}

	/*
	 *	Verify dynamic allocation
	 */
	{
		char		*buff;
		size_t		len;
		char const	in_zero[] = "";

		len = fr_sbuff_out_aunescape_until(NULL, &buff, &FR_SBUFF_IN(in_zero, sizeof(in_zero) - 1), SIZE_MAX,
						   NULL, &pipe_rules);
		TEST_CHECK_SLEN(0, len);
		talloc_get_type_abort(buff, char);
		TEST_CHECK_SLEN(1, talloc_array_length(buff));
		talloc_free(buff);
	}
}

static void test_unescape_multi_char_terminals(void)
{
	char const		in[] = "foo, bar, baz```";
	fr_sbuff_t		sbuff;
	ssize_t			slen;
	fr_sbuff_term_t		tt = FR_SBUFF_TERMS(
					L(","),
					L("```"),
					L("bad"),
					L("bar"),
					L("boink"),
					L("food"),
					L("nyi")
				);
	char			out[100];

	fr_sbuff_init(&sbuff, in, sizeof(in));

	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, &tt, '\0');
	TEST_CHECK(slen == 3);
	TEST_CHECK_STRCMP("foo", out);

	fr_sbuff_advance(&sbuff, 1);

	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, &tt, '\0');
	TEST_CHECK(slen == 1);
	TEST_CHECK_STRCMP(" ", out);

	fr_sbuff_advance(&sbuff, 4);

	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, &tt, '\0');
	TEST_CHECK(slen == 4);
	TEST_CHECK_STRCMP(" baz", out);
}

static void test_no_advance(void)
{
	char const	*in = "i am a test string";
	char		out[18 + 1];
	fr_sbuff_t	sbuff;
	ssize_t		slen;

	fr_sbuff_init(&sbuff, in, strlen(in));

	TEST_CASE("Copy 5 bytes to out - no advance");
	TEST_CHECK(sbuff.p == sbuff.start);
	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, sizeof(out)), &FR_SBUFF_NO_ADVANCE(&sbuff), 5);
	TEST_CHECK(slen == 5);
	TEST_CHECK(strcmp(out, "i am ") == 0);
	TEST_CHECK(sbuff.p == sbuff.start);
}

static void test_talloc_extend(void)
{
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	tctx;

	TEST_CASE("Initial allocation");
	TEST_CHECK(fr_sbuff_init_talloc(NULL, &sbuff, &tctx, 32, 50) == &sbuff);
	TEST_SBUFF_USED(&sbuff, 0);
	TEST_SBUFF_LEN(&sbuff, 33);

	TEST_CASE("Trim to zero");
	TEST_CHECK(fr_sbuff_trim_talloc(&sbuff, SIZE_MAX) == 0);
	TEST_SBUFF_USED(&sbuff, 0);
	TEST_SBUFF_LEN(&sbuff, 1);

	TEST_CASE("Print string - Should realloc to init");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "0123456789") == 10);
	TEST_CHECK(strcmp(fr_sbuff_start(&sbuff), "0123456789") == 0);
	TEST_SBUFF_USED(&sbuff, 10);
	TEST_SBUFF_LEN(&sbuff, 33);

	TEST_CASE("Trim to strlen");
	TEST_CHECK(fr_sbuff_trim_talloc(&sbuff, SIZE_MAX) == 0);
	TEST_SBUFF_LEN(&sbuff, 11);

	TEST_CASE("Print string - Should realloc to init");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "0123456789") == 10);
	TEST_CHECK(strcmp(fr_sbuff_start(&sbuff), "01234567890123456789") == 0);
	TEST_SBUFF_USED(&sbuff, 20);
	TEST_SBUFF_LEN(&sbuff, 33);

	TEST_CASE("Trim to strlen");
	TEST_CHECK(fr_sbuff_trim_talloc(&sbuff, SIZE_MAX) == 0);
	TEST_SBUFF_LEN(&sbuff, 21);

	TEST_CASE("Print string - Should realloc to double buffer len");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "012345678901234") == 15);
	TEST_CHECK(strcmp(fr_sbuff_start(&sbuff), "01234567890123456789012345678901234") == 0);
	TEST_SBUFF_USED(&sbuff, 35);
	TEST_SBUFF_LEN(&sbuff, 41);

	TEST_CASE("Print string - Should only add a single char, should not extend the buffer");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "A") == 1);
	TEST_CHECK(strcmp(fr_sbuff_start(&sbuff), "01234567890123456789012345678901234A") == 0);
	TEST_SBUFF_USED(&sbuff, 36);
	TEST_SBUFF_LEN(&sbuff, 41);

	TEST_CASE("Print string - Use all available buffer data");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "BCDE") == 4);
	TEST_CHECK(strcmp(fr_sbuff_start(&sbuff), "01234567890123456789012345678901234ABCDE") == 0);
	TEST_SBUFF_USED(&sbuff, 40);
	TEST_SBUFF_LEN(&sbuff, 41);

	TEST_CASE("Print string - Add single char, should trigger doubling constrained by max");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "F") == 1);
	TEST_CHECK(strcmp(fr_sbuff_start(&sbuff), "01234567890123456789012345678901234ABCDEF") == 0);
	TEST_SBUFF_USED(&sbuff, 41);
	TEST_SBUFF_LEN(&sbuff, 51);

	TEST_CASE("Print string - Add data to take us up to max");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "GHIJKLMNO") == 9);
	TEST_CHECK(strcmp(fr_sbuff_start(&sbuff), "01234567890123456789012345678901234ABCDEFGHIJKLMNO") == 0);
	TEST_SBUFF_USED(&sbuff, 50);
	TEST_SBUFF_LEN(&sbuff, 51);

	TEST_CASE("Print string - Add single char, should fail");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "P") == -1);
	TEST_CHECK(strcmp(fr_sbuff_start(&sbuff), "01234567890123456789012345678901234ABCDEFGHIJKLMNO") == 0);
	TEST_SBUFF_USED(&sbuff, 50);
	TEST_SBUFF_LEN(&sbuff, 51);

	TEST_CASE("Trim to strlen (should be noop)");
	TEST_CHECK(fr_sbuff_trim_talloc(&sbuff, SIZE_MAX) == 0);
	TEST_CHECK(strcmp(fr_sbuff_start(&sbuff), "01234567890123456789012345678901234ABCDEFGHIJKLMNO") == 0);
	TEST_SBUFF_USED(&sbuff, 50);
	TEST_SBUFF_LEN(&sbuff, 51);
}

static void test_talloc_extend_init_zero(void)
{
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	tctx;

	TEST_CASE("Initial allocation");
	TEST_CHECK(fr_sbuff_init_talloc(NULL, &sbuff, &tctx, 0, 50) == &sbuff);
	TEST_SBUFF_USED(&sbuff, 0);
	TEST_SBUFF_LEN(&sbuff, 1);

	TEST_CASE("Print string - Should alloc one byte");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "A") == 1);
	TEST_CHECK(strcmp(fr_sbuff_start(&sbuff), "A") == 0);
	TEST_SBUFF_USED(&sbuff, 1);
	TEST_SBUFF_LEN(&sbuff, 2);

	TEST_CASE("Print string - Should alloc two bytes");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "BC") == 2);
	TEST_CHECK(strcmp(fr_sbuff_start(&sbuff), "ABC") == 0);
	TEST_SBUFF_USED(&sbuff, 3);
	TEST_SBUFF_LEN(&sbuff, 4);

	TEST_CASE("Print string - Should alloc three bytes");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "D") == 1);
	TEST_CHECK(strcmp(fr_sbuff_start(&sbuff), "ABCD") == 0);
	TEST_SBUFF_USED(&sbuff, 4);
	TEST_SBUFF_LEN(&sbuff, 7);
}

static void test_talloc_extend_multi_level(void)
{
	fr_sbuff_t		sbuff_0, sbuff_1;
	fr_sbuff_uctx_talloc_t	tctx;

	TEST_CASE("Initial allocation");
	TEST_CHECK(fr_sbuff_init_talloc(NULL, &sbuff_0, &tctx, 0, 50) == &sbuff_0);
	TEST_SBUFF_USED(&sbuff_0, 0);
	TEST_SBUFF_LEN(&sbuff_0, 1);

	sbuff_1 = FR_SBUFF_COPY(&sbuff_0);
	TEST_CASE("Check sbuff_1 has extend fields set");
	TEST_CHECK(sbuff_0.extend == sbuff_1.extend);
	TEST_CHECK(sbuff_0.uctx == sbuff_1.uctx);
	TEST_CHECK(sbuff_1.parent == &sbuff_0);
	TEST_SBUFF_USED(&sbuff_1, 0);
	TEST_SBUFF_LEN(&sbuff_1, 1);

	TEST_CASE("Print string - Should alloc one byte");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff_1, "A") == 1);
	TEST_CHECK(strcmp(fr_sbuff_start(&sbuff_1), "A") == 0);
	TEST_SBUFF_USED(&sbuff_0, 1);
	TEST_SBUFF_LEN(&sbuff_0, 2);
	TEST_SBUFF_USED(&sbuff_1, 1);
	TEST_SBUFF_LEN(&sbuff_1, 2);

	TEST_CHECK(sbuff_0.start == sbuff_1.start);
	TEST_CHECK(sbuff_0.end == sbuff_1.end);
	TEST_CHECK(sbuff_0.p == sbuff_1.p);
}

static void test_talloc_extend_with_marker(void)
{
	fr_sbuff_t		sbuff_0, sbuff_1;
	fr_sbuff_marker_t	marker_0, marker_1;
	fr_sbuff_uctx_talloc_t	tctx;

	TEST_CASE("Initial allocation");
	TEST_CHECK(fr_sbuff_init_talloc(NULL, &sbuff_0, &tctx, 0, 50) == &sbuff_0);
	TEST_SBUFF_USED(&sbuff_0, 0);
	TEST_SBUFF_LEN(&sbuff_0, 1);

	TEST_CASE("Print string - Should alloc one byte");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff_0, "A") == 1);
	TEST_CHECK_STRCMP("A", fr_sbuff_start(&sbuff_0));
	TEST_SBUFF_USED(&sbuff_0, 1);
	TEST_SBUFF_LEN(&sbuff_0, 2);

	fr_sbuff_marker(&marker_0, &sbuff_0);
	TEST_CHECK((marker_0.p - sbuff_0.start) == 1);

	TEST_CASE("Print string - Ensure marker is updated");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff_0, "B") == 1);
	TEST_CHECK_STRCMP("AB", fr_sbuff_start(&sbuff_0));
	TEST_SBUFF_USED(&sbuff_0, 2);
	TEST_SBUFF_LEN(&sbuff_0, 3);
	TEST_CHECK((marker_0.p - sbuff_0.start) == 1);

	TEST_CASE("Print string - Copy sbuff");
	sbuff_1 = FR_SBUFF_COPY(&sbuff_0);	/* Dup sbuff_0 */
	TEST_CHECK(sbuff_0.p == sbuff_1.start);
	fr_sbuff_marker(&marker_1, &sbuff_1);

	TEST_CHECK((marker_1.p - sbuff_1.start) == 0);
	TEST_CHECK((marker_1.p - sbuff_0.start) == 2);
	TEST_CHECK(sbuff_0.p == sbuff_1.start);

	TEST_CASE("Print string - Trigger re-alloc, ensure all pointers are updated");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff_1, "C") == 1);
	TEST_CHECK_STRCMP("C", fr_sbuff_start(&sbuff_1));
	TEST_CHECK(sbuff_0.buff == sbuff_1.buff);
	TEST_CHECK(sbuff_0.p == sbuff_1.start + 1);
	TEST_CHECK((marker_1.p - sbuff_1.start) == 0);
	TEST_CHECK((marker_1.p - sbuff_0.start) == 2);
	TEST_SBUFF_USED(&sbuff_0, 3);
	TEST_SBUFF_LEN(&sbuff_0, 5);
}

static void test_adv_past_str(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "i am a test string";

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(6, fr_sbuff_adv_past_str(&sbuff, "i am a", SIZE_MAX));
	TEST_CHECK_STRCMP(" test string", sbuff.p);

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(0, fr_sbuff_adv_past_str(&sbuff, " am a", SIZE_MAX));
	TEST_CHECK_STRCMP("i am a test string", sbuff.p);

	TEST_CASE("Check for token larger than the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(0, fr_sbuff_adv_past_str(&sbuff, "i am a test string ", SIZE_MAX));
	TEST_CHECK_STRCMP("i am a test string", sbuff.p);

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init(&sbuff, in, 0 + 1);
	TEST_CHECK_LEN(0, fr_sbuff_adv_past_str(&sbuff, "i am a", SIZE_MAX));

	TEST_CASE("Check for token that is the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(18, fr_sbuff_adv_past_str(&sbuff, "i am a test string", SIZE_MAX));
	TEST_CHECK_STRCMP("", sbuff.p);
	TEST_CHECK(sbuff.p == sbuff.end);
}

static void test_adv_past_strcase(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "i am a test string";

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(6, fr_sbuff_adv_past_strcase(&sbuff, "i AM a", SIZE_MAX));
	TEST_CHECK_STRCMP(" test string", sbuff.p);

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(0, fr_sbuff_adv_past_strcase(&sbuff, " AM a", SIZE_MAX));
	TEST_CHECK_STRCMP("i am a test string", sbuff.p);

	TEST_CASE("Check for token larger than the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(0, fr_sbuff_adv_past_strcase(&sbuff, "i AM a TEST string ", SIZE_MAX));
	TEST_CHECK_STRCMP("i am a test string", sbuff.p);

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init(&sbuff, in, 0 + 1);
	TEST_CHECK_LEN(0, fr_sbuff_adv_past_strcase(&sbuff, "i AM a", SIZE_MAX));

	TEST_CASE("Check for token that is the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(18, fr_sbuff_adv_past_strcase(&sbuff, "i AM a TEST string", SIZE_MAX));
	TEST_CHECK_STRCMP("", sbuff.p);
	TEST_CHECK(sbuff.p == sbuff.end);
}

static void test_adv_past_whitespace(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "     i am a         test string";
	char const	in_ns[] = "i am a test string";
	char const	in_ws[] = "     ";

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(5, fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX));
	TEST_CHECK_STRCMP("i am a         test string", sbuff.p);

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init(&sbuff, in_ns, sizeof(in_ns));
	TEST_CHECK_LEN(0, fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX));
	TEST_CHECK_STRCMP("i am a test string", sbuff.p);

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init(&sbuff, in, 0 + 1);
	TEST_CHECK_LEN(0, fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX));

	TEST_CASE("Check for token that is the string");
	fr_sbuff_init(&sbuff, in_ws, sizeof(in_ws));
	TEST_CHECK_LEN(5, fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX));

	TEST_CASE("Length constraint with token match");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(2, fr_sbuff_adv_past_whitespace(&sbuff, 2));
	TEST_CHECK_STRCMP("   i am a         test string", sbuff.p);

	TEST_CASE("Length constraint without token match");
	fr_sbuff_init(&sbuff, in_ns, sizeof(in_ns));
	TEST_CHECK_LEN(0, fr_sbuff_adv_past_whitespace(&sbuff, 2));
	TEST_CHECK_STRCMP("i am a test string", sbuff.p);
}

static void test_adv_past_allowed(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "     i am a         test string";
	char const	in_ns[] = "i am a test string";
	char const	in_ws[] = "     ";

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(5, fr_sbuff_adv_past_allowed(&sbuff, SIZE_MAX, (bool[UINT8_MAX + 1]){ [' '] = true }));
	TEST_CHECK_STRCMP("i am a         test string", sbuff.p);

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init(&sbuff, in_ns, sizeof(in_ns));
	TEST_CHECK_LEN(0, fr_sbuff_adv_past_allowed(&sbuff, SIZE_MAX, (bool[UINT8_MAX + 1]){ [' '] = true }));
	TEST_CHECK_STRCMP("i am a test string", sbuff.p);

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init(&sbuff, in, 0 + 1);
	TEST_CHECK_LEN(0, fr_sbuff_adv_past_allowed(&sbuff, SIZE_MAX, (bool[UINT8_MAX + 1]){ [' '] = true }));
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Check for token at the end of the string");
	fr_sbuff_init(&sbuff, in_ws, sizeof(in_ws));
	TEST_CHECK_LEN(5, fr_sbuff_adv_past_allowed(&sbuff, SIZE_MAX, (bool[UINT8_MAX + 1]){ [' '] = true }));
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Length constraint with token match");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(2, fr_sbuff_adv_past_allowed(&sbuff, 2, (bool[UINT8_MAX + 1]){ [' '] = true }));
	TEST_CHECK_STRCMP("   i am a         test string", sbuff.p);

	TEST_CASE("Length constraint with token match");
	fr_sbuff_init(&sbuff, in_ns, sizeof(in_ns));
	TEST_CHECK_LEN(0, fr_sbuff_adv_past_allowed(&sbuff, 2, (bool[UINT8_MAX + 1]){ [' '] = true }));
	TEST_CHECK_STRCMP("i am a test string", sbuff.p);
}

static void test_adv_until(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = " abcdefgh ijklmnopp";

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(0, fr_sbuff_adv_until(&sbuff, SIZE_MAX, &FR_SBUFF_TERM(" "), '\0'));
	TEST_CHECK_STRCMP(" abcdefgh ijklmnopp", sbuff.p);

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(1, fr_sbuff_adv_until(&sbuff, SIZE_MAX, &FR_SBUFF_TERM("a"), '\0'));
	TEST_CHECK_STRCMP("abcdefgh ijklmnopp", sbuff.p);

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init(&sbuff, in, 0 + 1);
	TEST_CHECK_LEN(0, fr_sbuff_adv_until(&sbuff, SIZE_MAX, &FR_SBUFF_TERM("a"), '\0'));
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Check for token that is not in the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(19, fr_sbuff_adv_until(&sbuff, SIZE_MAX, &FR_SBUFF_TERM("|"), '\0'));
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Check escapes");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(18, fr_sbuff_adv_until(&sbuff, SIZE_MAX, &FR_SBUFF_TERM("p"), 'o'));
	TEST_CHECK_STRCMP("p", sbuff.p);

	TEST_CASE("Check for token that is not in the string with length constraint");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK_LEN(5, fr_sbuff_adv_until(&sbuff, 5, &FR_SBUFF_TERM("|"), '\0'));
	TEST_CHECK(sbuff.p == (sbuff.start + 5));
}

static void test_adv_to_utf8(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "🥺🥺🥺🥺🍪😀";
	char		*p;

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_chr_utf8(&sbuff, SIZE_MAX, "🥺");
	TEST_CHECK(p == sbuff.p);
	TEST_CHECK_STRCMP("🥺🥺🥺🥺🍪😀", sbuff.p);

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_chr_utf8(&sbuff, SIZE_MAX, "🍪");
	TEST_CHECK(p == (sbuff.start + (sizeof("🥺🥺🥺🥺") - 1)));
	TEST_CHECK_STRCMP("🍪😀", p);

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init(&sbuff, in, 0 + 1);
	p = fr_sbuff_adv_to_chr_utf8(&sbuff, SIZE_MAX, "🍪");
	TEST_CHECK(p == NULL);
	TEST_CHECK(sbuff.start == sbuff.p);

	TEST_CASE("Check for token at the end of the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_chr_utf8(&sbuff, SIZE_MAX, "😀");
	TEST_CHECK(p == sbuff.start + (sizeof("🥺🥺🥺🥺🍪") - 1));

	TEST_CASE("Check for token not in the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_chr_utf8(&sbuff, SIZE_MAX, "🍆 ");
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token at the end of the string within len contraints");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_chr_utf8(&sbuff, (sizeof("🥺🥺🥺🥺🍪😀") - 1), "😀");
	TEST_CHECK(p == sbuff.start + (sizeof("🥺🥺🥺🥺🍪") - 1));

	TEST_CASE("Check for token at the end of the string outside len constraints #1");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK(!fr_sbuff_adv_to_chr_utf8(&sbuff, (sizeof("🥺🥺🥺🥺🍪😀") - 2), "😀"));
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Check for token at the end of the string outside len constraints #2");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK(!fr_sbuff_adv_to_chr_utf8(&sbuff, (sizeof("🥺🥺🥺🥺🍪😀") - 3), "😀"));
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Check for token at the end of the string outside len constraints #3");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK(!fr_sbuff_adv_to_chr_utf8(&sbuff, (sizeof("🥺🥺🥺🥺🍪😀") - 4), "😀"));
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Check for token at the end of the string outside len constraints #4");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK(!fr_sbuff_adv_to_chr_utf8(&sbuff, (sizeof("🥺🥺🥺🥺🍪😀") - 5), "😀"));
	TEST_CHECK(sbuff.p == sbuff.start);
}

static void test_adv_to_chr(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "AAAAbC";
	char		*p;

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, 'A');
	TEST_CHECK(p == sbuff.p);
	TEST_CHECK_STRCMP("AAAAbC", sbuff.p);

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, 'b');
	TEST_CHECK(p == (sbuff.start + (sizeof("AAAA") - 1)));
	TEST_CHECK_STRCMP("bC", p);

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init(&sbuff, in, 0 + 1);
	TEST_CHECK(!fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, 'b'));
	TEST_CHECK(sbuff.start == sbuff.p);

	TEST_CASE("Check for token at the end of the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, 'C');
	TEST_CHECK(p == sbuff.start + (sizeof("AAAAb") - 1));

	TEST_CASE("Check for token not in the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, 'D');
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token not at beginning of string within length constraints");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_chr(&sbuff, 5, 'b');
	TEST_CHECK(p == (sbuff.start + (sizeof("AAAA") - 1)));
	TEST_CHECK_STRCMP("bC", p);

	TEST_CASE("Check for token not at beginning of string outside length constraints");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK(!fr_sbuff_adv_to_chr(&sbuff, 4, 'b'));
	TEST_CHECK(sbuff.p == sbuff.start);
}

static void test_adv_to_str(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "i am a test string";
	char		*p;

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, "i am a test", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP("i am a test string", sbuff.p);

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, "test", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP("test string", sbuff.p);

	TEST_CASE("Check for token at the end of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, "ing", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP("ing", sbuff.p);

	TEST_CASE("Check for token larger than the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, "i am a test string ", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token shorter than string, not in the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "ng ", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init(&sbuff, in, 0 + 1);
	p = fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, "i am a", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token that is the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, "i am a test string", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP("i am a test string", p);

	TEST_CASE("Check for token not at beginning of string within length constraints");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_str(&sbuff, 11, "test", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP("test string", sbuff.p);

	TEST_CASE("Check for token not at beginning of string outside length constraints");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK(!fr_sbuff_adv_to_str(&sbuff, 10, "test", SIZE_MAX));
	TEST_CHECK(sbuff.p == sbuff.start);
}

static void test_adv_to_strcase(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "i am a test string";
	char		*p;

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "i AM a TEST", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP("i am a test string", sbuff.p);

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "tEst", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP("test string", sbuff.p);

	TEST_CASE("Check for token at the end of string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "Ing", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP("ing", sbuff.p);

	TEST_CASE("Check for token larger than the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "i aM a tEst stRIng ", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token shorter than string, not in the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "nG ", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init(&sbuff, in, 0 + 1);
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "i AM a", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token that is the string");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "i AM a teST stRIng", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP("i am a test string", p);

	TEST_CASE("Check for token not at beginning of string within length constraints");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	p = fr_sbuff_adv_to_strcase(&sbuff, 11, "tEst", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP("test string", sbuff.p);

	TEST_CASE("Check for token not at beginning of string outside length constraints");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK(!fr_sbuff_adv_to_strcase(&sbuff, 10, "tEst", SIZE_MAX));
	TEST_CHECK(sbuff.p == sbuff.start);
}

static void test_next_if_char(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "i ";

	TEST_CASE("Check for advancement on match");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK(fr_sbuff_next_if_char(&sbuff, 'i') == true);
	TEST_CHECK_STRCMP(" ", sbuff.p);

	TEST_CASE("Check for non-advancement on non-match");
	TEST_CHECK(fr_sbuff_next_if_char(&sbuff, 'i') == false);
	TEST_CHECK_STRCMP(" ", sbuff.p);

	TEST_CASE("Check for advancement at end");
	TEST_CHECK(fr_sbuff_next_if_char(&sbuff, ' ') == true);
	TEST_CHECK_STRCMP("", sbuff.p);

	TEST_CASE("Check we can't advance off the end of the buffer");
	TEST_CHECK(fr_sbuff_next_if_char(&sbuff, ' ') == false);
	TEST_CHECK_STRCMP("", sbuff.p);
}

static void test_next_unless_char(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "i ";

	TEST_CASE("Check for advancement on non-match");
	fr_sbuff_init(&sbuff, in, sizeof(in));
	TEST_CHECK(fr_sbuff_next_unless_char(&sbuff, ' ') == true);
	TEST_CHECK_STRCMP(" ", sbuff.p);

	TEST_CASE("Check for non-advancement on match");
	TEST_CHECK(fr_sbuff_next_unless_char(&sbuff, ' ') == false);
	TEST_CHECK_STRCMP(" ", sbuff.p);

	TEST_CASE("Check for advancement at end");
	TEST_CHECK(fr_sbuff_next_unless_char(&sbuff, '_') == true);
	TEST_CHECK_STRCMP("", sbuff.p);

	TEST_CASE("Check we can't advance off the end of the buffer");
	TEST_CHECK(fr_sbuff_next_unless_char(&sbuff, '_') == false);
	TEST_CHECK_STRCMP("", sbuff.p);
}

TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "fr_sbuff_init",			test_parse_init },
	{ "fr_sbuff_out_bstrncpy_exact",	test_bstrncpy_exact },
	{ "fr_sbuff_out_bstrncpy",		test_bstrncpy },
	{ "fr_sbuff_out_bstrncpy_allowed",	test_bstrncpy_allowed },
	{ "fr_sbuff_out_bstrncpy_until",	test_bstrncpy_until },
	{ "multi-char terminals",		test_unescape_multi_char_terminals },
	{ "fr_sbuff_out_unescape_until",	test_unescape_until },

	/*
	 *	Extending buffer
	 */
	{ "fr_sbuff_talloc_extend",		test_talloc_extend },
	{ "fr_sbuff_talloc_extend_init_zero",	test_talloc_extend_init_zero },
	{ "fr_sbuff_talloc_extend_multi_level",	test_talloc_extend_multi_level },
	{ "fr_sbuff_talloc_extend_with_marker",	test_talloc_extend_with_marker },

	{ "fr_sbuff_no_advance",		test_no_advance },

	/*
	 *	Token skipping
	 */
	{ "fr_sbuff_adv_past_str", 		test_adv_past_str },
	{ "fr_sbuff_adv_past_strcase", 		test_adv_past_strcase },
	{ "fr_sbuff_adv_past_whitespace",	test_adv_past_whitespace },
	{ "fr_sbuff_adv_past_allowed",		test_adv_past_allowed },
	{ "fr_sbuff_adv_until",			test_adv_until },

	/*
	 *	Token searching
	 */
	{ "fr_sbuff_adv_to_utf8",		test_adv_to_utf8 },
	{ "fr_sbuff_adv_to_chr",		test_adv_to_chr },
	{ "fr_sbuff_adv_to_str",		test_adv_to_str },
	{ "fr_sbuff_adv_to_strcase",		test_adv_to_strcase },

	/*
	 *	Advancement
	 */
	{ "fr_sbuff_next_if_char",		test_next_if_char },
	{ "fr_sbuff_next_unless_char", 		test_next_unless_char },

	{ NULL }
};
