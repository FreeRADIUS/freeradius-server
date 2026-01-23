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
 * @file src/lib/util/test//sbuff_tests.c
 *
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include "acutest.h"
#include"acutest_helpers.h"

#include <freeradius-devel/util/sbuff.h>

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

static void test_parse_init(void)
{
	char const	in[] = "i am a test string";
	fr_sbuff_t	sbuff;

	TEST_CASE("Parse init with size");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);

	TEST_CHECK(sbuff.start == in);
	TEST_CHECK(sbuff.p == in);
	TEST_CHECK(sbuff.end == in + (sizeof(in) - 1));

	TEST_CASE("Parse init with end");
	fr_sbuff_init_in(&sbuff, in, in + strlen(in));

	TEST_CHECK(sbuff.start == in);
	TEST_CHECK(sbuff.p == in);
	TEST_CHECK(sbuff.end == in + strlen(in));

	TEST_CASE("Parse init with const end");
	fr_sbuff_init_in(&sbuff, in, (char const *)(in + strlen(in)));

	TEST_CHECK(sbuff.start == in);
	TEST_CHECK(sbuff.p == in);
	TEST_CHECK(sbuff.end == in + strlen(in));
}

static void test_is_char(void)
{
	char const		in[] = "i am a test string";
	fr_sbuff_t		sbuff;
	fr_sbuff_marker_t	marker;

	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK(fr_sbuff_is_char(&sbuff, 'i'));
	TEST_CHECK(!fr_sbuff_is_char(&sbuff, 'z'));

	fr_sbuff_advance(&sbuff, 2);
	TEST_CHECK(!fr_sbuff_is_char(&sbuff, 'i'));
	TEST_CHECK(fr_sbuff_is_char(&sbuff, 'a'));

	fr_sbuff_advance(&sbuff, 15);
	TEST_CHECK(fr_sbuff_is_char(&sbuff, 'g'));
	fr_sbuff_marker(&marker, &sbuff);
	TEST_CHECK(fr_sbuff_is_char(&marker, 'g'));

	/*
	 *	Ensure that after advancing the buffer past
	 *	the end, the marker can still be correctly
	 *	tested
	 */
	fr_sbuff_advance(&sbuff, 1);
	TEST_CHECK(!fr_sbuff_is_char(&sbuff, 'g'));
	TEST_CHECK(fr_sbuff_is_char(&marker, 'g'));
}

static void test_bstrncpy_exact(void)
{
	char const	in[] = "i am a test string";
	char const	in_long[] = "i am a longer test string";
	char		out[18 + 1] = "";
	fr_sbuff_t	sbuff;
	ssize_t		slen;

	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);

	TEST_CASE("Copy 5 bytes to out");
	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 5);
	TEST_CHECK_SLEN_RETURN(slen, 5);
	TEST_CHECK_STRCMP(out, "i am ");
	TEST_CHECK_STRCMP(sbuff.p, "a test string");

	TEST_CASE("Copy 13 bytes to out");
	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 13);
	TEST_CHECK_SLEN(slen, 13);
	TEST_CHECK_STRCMP(out, "a test string");
	TEST_CHECK_STRCMP(sbuff.p, "");
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun input");
	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 1);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun output (and SIZE_MAX special value)");
	fr_sbuff_init_in(&sbuff, in_long, sizeof(in_long) - 1);

	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX);
	TEST_CHECK_SLEN(slen, -7);
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Zero length output buffer");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, SIZE_MAX);
	TEST_CHECK_SLEN(slen, -25);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Zero length size");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, 0);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);
}

static void test_bstrncpy(void)
{
	char const	in[] = "i am a test string";
	char const	in_long[] = "i am a longer test string";
	char		out[18 + 1] = "";
	fr_sbuff_t	sbuff;
	ssize_t		slen;

	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);

	TEST_CASE("Copy 5 bytes to out");
	slen = fr_sbuff_out_bstrncpy(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 5);
	TEST_CHECK_SLEN_RETURN(slen, 5);
	TEST_CHECK_STRCMP(out, "i am ");
	TEST_CHECK_STRCMP(sbuff.p, "a test string");

	TEST_CASE("Copy 13 bytes to out");
	slen = fr_sbuff_out_bstrncpy(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 13);
	TEST_CHECK_SLEN(slen, 13);
	TEST_CHECK_STRCMP(out, "a test string");
	TEST_CHECK_STRCMP(sbuff.p, "");
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun input");
	slen = fr_sbuff_out_bstrncpy(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 1);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun output (and SIZE_MAX special value)");
	fr_sbuff_init_in(&sbuff, in_long, sizeof(in_long) - 1);

	slen = fr_sbuff_out_bstrncpy(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX);
	TEST_CHECK_SLEN(slen, 18);
	TEST_CHECK_STRCMP(out, "i am a longer test");

	TEST_CASE("Zero length output buffer");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, SIZE_MAX);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Zero length size");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, 0);
	TEST_CHECK_SLEN(slen, 0);
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
	char		out[18 + 1] = "";
	fr_sbuff_t	sbuff;
	ssize_t		slen;

	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);

	/*
	 *	Should behave identically to bstrncpy
	 *	where there's no restrictions on char
	 *	set.
	 */
	TEST_CASE("Copy 5 bytes to out");
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 5, allow_lowercase_and_space);
	TEST_CHECK_SLEN_RETURN(slen, 5);
	TEST_CHECK_STRCMP(out, "i am ");
	TEST_CHECK_STRCMP(sbuff.p, "a test string");

	TEST_CASE("Copy 13 bytes to out");
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 13, allow_lowercase_and_space);
	TEST_CHECK_SLEN(slen, 13);
	TEST_CHECK_STRCMP(out, "a test string");
	TEST_CHECK_STRCMP(sbuff.p, "");
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun input");
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 1, allow_lowercase_and_space);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun output (and SIZE_MAX special value)");
	fr_sbuff_init_in(&sbuff, in_long, sizeof(in_long));

	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, allow_lowercase_and_space);
	TEST_CHECK_SLEN(slen, 18);
	TEST_CHECK_STRCMP(out, "i am a longer test");

	TEST_CASE("Zero length output buffer");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, SIZE_MAX, allow_lowercase_and_space);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Zero length size");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, SIZE_MAX, allow_lowercase_and_space);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	/*
	 *	Check copy stops early
	 */
	TEST_CASE("Copy until first t");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX,
					     allow_lowercase_and_space_no_t);
	TEST_CHECK_SLEN(slen, 14);
	TEST_CHECK_STRCMP(out, "i am a longer ");

	TEST_CASE("Copy until first t with length constraint (same len as token)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, 15), &sbuff, SIZE_MAX,
					     allow_lowercase_and_space_no_t);
	TEST_CHECK_SLEN(slen, 14);
	TEST_CHECK_STRCMP(out, "i am a longer ");

	TEST_CASE("Copy until first t with length constraint (one shorter than token)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, 14), &sbuff, SIZE_MAX,
					     allow_lowercase_and_space_no_t);
	TEST_CHECK_SLEN(slen, 13);
	TEST_CHECK_STRCMP(out, "i am a longer");

	TEST_CASE("Zero length token (should still be terminated)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, 14), &sbuff, SIZE_MAX,
					     (bool[UINT8_MAX + 1]){});
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK_STRCMP(out, "");
}

static void test_bstrncpy_until(void)
{
	char const	in[] = "i am a test string";
	char const	in_long[] = "i am a longer test string";
	char		out[18 + 1];
	fr_sbuff_t	sbuff;
	ssize_t		slen;

	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);

	/*
	 *	Should behave identically to bstrncpy
	 *	where there's no restrictions on char
	 *	set.
	 */
	TEST_CASE("Copy 5 bytes to out");
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 5, NULL, NULL);
	TEST_CHECK_SLEN_RETURN(slen, 5);
	TEST_CHECK_STRCMP(out, "i am ");
	TEST_CHECK_STRCMP(sbuff.p, "a test string");

	TEST_CASE("Copy 13 bytes to out");
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 13, NULL, NULL);
	TEST_CHECK_SLEN(slen, 13);
	TEST_CHECK_STRCMP(out, "a test string");
	TEST_CHECK_STRCMP(sbuff.p, "");
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun input");
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 1, NULL, NULL);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Check escapes");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX,
					   &FR_SBUFF_TERM("g"), &(fr_sbuff_unescape_rules_t){ .chr = 'n' });
	TEST_CHECK_SLEN(slen, 18);
	TEST_CHECK_STRCMP(out, "i am a test string");
	TEST_CHECK_STRCMP(sbuff.p, "");

	TEST_CASE("Copy would overrun output (and SIZE_MAX special value)");
	fr_sbuff_init_in(&sbuff, in_long, sizeof(in_long) - 1);

	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, NULL, NULL);
	TEST_CHECK_SLEN(slen, 18);
	TEST_CHECK_STRCMP(out, "i am a longer test");

	TEST_CASE("Zero length output buffer");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, SIZE_MAX, NULL, NULL);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Zero length size");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 0, NULL, NULL);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	/*
	 *	Check copy stops early
	 */
	TEST_CASE("Copy until first t");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, &FR_SBUFF_TERM("t"), NULL);
	TEST_CHECK_SLEN(slen, 14);
	TEST_CHECK_STRCMP(out, "i am a longer ");

	TEST_CASE("Copy until first t with length constraint (same len as token)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, 15), &sbuff, SIZE_MAX, &FR_SBUFF_TERM("t"), NULL);
	TEST_CHECK_SLEN(slen, 14);
	TEST_CHECK_STRCMP(out, "i am a longer ");

	TEST_CASE("Copy until first t with length constraint (one shorter than token)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, 14), &sbuff, SIZE_MAX, &FR_SBUFF_TERM("t"), NULL);
	TEST_CHECK_SLEN(slen, 13);
	TEST_CHECK_STRCMP(out, "i am a longer");

	TEST_CASE("Zero length token (should still be terminated)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, 14), &sbuff, SIZE_MAX, &FR_SBUFF_TERM("i"), NULL);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK_STRCMP(out, "");
}

static void test_unescape_until(void)
{
	char const		in[] = "i am a test string";
	char const		in_long[] = "i am a longer test string";
	char const		in_escapes[] = "i am a |t|est strin|g";
	char const		in_escapes_seq[] = "i |x|0am a |t|est strin|g|x20|040";
	char			out[18 + 1] = "";
	char			escape_out[20 + 1];

	fr_sbuff_t		sbuff;
	ssize_t			slen;

	fr_sbuff_unescape_rules_t	rules = {
					.chr = '\\'
				};

	fr_sbuff_unescape_rules_t	pipe_rules = {
					.chr = '|',
					.subs = { ['g'] = 'g', ['|'] = '|'  }
				};

	fr_sbuff_unescape_rules_t	pipe_rules_sub = {
					.chr = '|', .subs = { ['g'] = 'h', ['|'] = '|'  }
				};

	fr_sbuff_unescape_rules_t	pipe_rules_sub_hex = {
					.chr = '|',
					.subs = { ['g'] = 'h', ['|'] = '|'  },
					.do_hex = true
				};

	fr_sbuff_unescape_rules_t	pipe_rules_sub_oct = {
					.chr = '|',
					.subs = { ['g'] = 'h', ['|'] = '|' },
					.do_oct = true
				};

	fr_sbuff_unescape_rules_t	pipe_rules_both = {
					.chr = '|',
					.subs = { ['g'] = 'h', ['|'] = '|'  },
					.do_hex = true,
					.do_oct = true
				};

	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	/*
	 *	Should behave identically to bstrncpy
	 *	where there's no restrictions on char
	 *	set.
	 */
	TEST_CASE("Copy 5 bytes to out");
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 5, NULL, &rules);
	TEST_CHECK_SLEN_RETURN(slen, 5);
	TEST_CHECK_STRCMP(out, "i am ");
	TEST_CHECK_STRCMP(sbuff.p, "a test string");

	TEST_CASE("Copy 13 bytes to out");
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 13, NULL, &rules);
	TEST_CHECK_SLEN(slen, 13);
	TEST_CHECK_STRCMP(out, "a test string");
	TEST_CHECK_STRCMP(sbuff.p, "");
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun input");
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 1, NULL, &rules);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Copy would overrun output (and SIZE_MAX special value)");
	fr_sbuff_init_in(&sbuff, in_long, sizeof(in_long) - 1);

	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, NULL, &rules);
	TEST_CHECK_SLEN(slen, 18);
	TEST_CHECK_STRCMP(out, "i am a longer test");

	TEST_CASE("Zero length output buffer");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, (size_t)1), &sbuff, SIZE_MAX, NULL, &rules);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Zero length size");
	fr_sbuff_set_to_start(&sbuff);
	out[0] = 'a';
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, 0, NULL, &rules);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK(out[0] == '\0');	/* should be set to \0 */
	TEST_CHECK(sbuff.p == sbuff.start);

	/*
	 *	Check copy stops early
	 */
	TEST_CASE("Copy until first t");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX,
					   &FR_SBUFF_TERM("t"), &rules);
	TEST_CHECK_SLEN(slen, 14);
	TEST_CHECK_STRCMP(out, "i am a longer ");

	TEST_CASE("Copy until first t with length constraint (same len as token)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, 15), &sbuff, SIZE_MAX,
					   &FR_SBUFF_TERM("t"), &rules);
	TEST_CHECK_SLEN(slen, 14);
	TEST_CHECK_STRCMP(out, "i am a longer ");

	TEST_CASE("Copy until first t with length constraint (one shorter than token)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, 14), &sbuff, SIZE_MAX,
					   &FR_SBUFF_TERM("t"), &rules);
	TEST_CHECK_SLEN(slen, 13);
	TEST_CHECK_STRCMP(out, "i am a longer");

	TEST_CASE("Zero length token (should still be terminated)");
	fr_sbuff_set_to_start(&sbuff);
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(out, 14), &sbuff, SIZE_MAX,
					   &FR_SBUFF_TERM("i"), &rules);
	TEST_CHECK_SLEN(slen, 0);
	TEST_CHECK_STRCMP(out, "");

	/*
	 *	Escapes and substitution
	 */
	TEST_CASE("Escape with substitution to same char");
	fr_sbuff_init_in(&sbuff, in_escapes, sizeof(in_escapes) - 1);
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(escape_out, sizeof(escape_out)), &sbuff, SIZE_MAX,
					   &FR_SBUFF_TERM("g"), &pipe_rules);
	TEST_CHECK_SLEN_RETURN(slen, 20);
	TEST_CHECK_STRCMP(escape_out, "i am a |t|est string");
	TEST_CHECK_STRCMP(sbuff.p, "");

	TEST_CASE("Escape with substitution to different char");
	fr_sbuff_init_in(&sbuff, in_escapes, sizeof(in_escapes) - 1);
	slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(escape_out, sizeof(escape_out)), &sbuff, SIZE_MAX,
					   &FR_SBUFF_TERM("g"), &pipe_rules_sub);
	TEST_CHECK_SLEN(slen, 20);
	TEST_CHECK_STRCMP(escape_out, "i am a |t|est strinh");
	TEST_CHECK_STRCMP(sbuff.p, "");

	{
		char	tmp_out[24 + 1];

		TEST_CASE("Escape with hex substitutions (insufficient output space)");
		fr_sbuff_init_in(&sbuff, in_escapes_seq, sizeof(in_escapes_seq) - 1);
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(tmp_out, sizeof(tmp_out)), &sbuff, SIZE_MAX,
						   &FR_SBUFF_TERM("g"), &pipe_rules_sub_hex);
		TEST_CHECK_SLEN_RETURN(slen, 24);
		TEST_CHECK_STRCMP(tmp_out, "i |x|0am a |t|est strinh");
		TEST_CHECK_STRCMP(sbuff.p, "|x20|040");
	}

	{
		char	tmp_out[25 + 1];

		TEST_CASE("Escape with hex substitutions (sufficient output space)");
		fr_sbuff_init_in(&sbuff, in_escapes_seq, sizeof(in_escapes_seq) - 1);
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(tmp_out, sizeof(tmp_out)), &sbuff, SIZE_MAX,
						   &FR_SBUFF_TERM("g"), &pipe_rules_sub_hex);
		TEST_CHECK_SLEN(slen, 25);
		TEST_CHECK_STRCMP(tmp_out, "i |x|0am a |t|est strinh ");
		TEST_CHECK_STRCMP(sbuff.p, "|040");
	}

	{
		char	tmp_out[28 + 1];

		TEST_CASE("Escape with oct substitutions (insufficient output space)");
		fr_sbuff_init_in(&sbuff, in_escapes_seq, sizeof(in_escapes_seq) - 1);
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(tmp_out, sizeof(tmp_out)), &sbuff, SIZE_MAX,
						   &FR_SBUFF_TERM("g"), &pipe_rules_sub_oct);
		TEST_CHECK_SLEN(slen, 28);
		TEST_CHECK_STRCMP(tmp_out, "i |x|0am a |t|est strinh|x20");
		TEST_CHECK_STRCMP(sbuff.p, "|040");
	}

	{
		char	tmp_out[29 + 1];

		TEST_CASE("Escape with oct substitutions (sufficient output space)");
		fr_sbuff_init_in(&sbuff, in_escapes_seq, sizeof(in_escapes_seq) - 1);
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(tmp_out, sizeof(tmp_out)), &sbuff, SIZE_MAX,
						   &FR_SBUFF_TERM("g"), &pipe_rules_sub_oct);
		TEST_CHECK_SLEN(slen, 29);
		TEST_CHECK_STRCMP(tmp_out, "i |x|0am a |t|est strinh|x20 ");
		TEST_CHECK_STRCMP(sbuff.p, "");
	}

	{
		char	tmp_out[26 + 1];

		TEST_CASE("Escape with hex and oct substitutions (sufficient output space)");
		fr_sbuff_init_in(&sbuff, in_escapes_seq, sizeof(in_escapes_seq) - 1);
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(tmp_out, sizeof(tmp_out)), &sbuff, SIZE_MAX,
						   &FR_SBUFF_TERM("g"), &pipe_rules_both);
		TEST_CHECK_SLEN(slen, 26);
		TEST_CHECK_STRCMP(tmp_out, "i |x|0am a |t|est strinh  ");
		TEST_CHECK_STRCMP(sbuff.p, "");
	}

	{
		char		tmp_out[2 + 1];
		char const	in_escapes_collapse[] = "||";

		TEST_CASE("Collapse double escapes");
		fr_sbuff_init_in(&sbuff, in_escapes_collapse, sizeof(in_escapes_collapse) - 1);
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(tmp_out, sizeof(tmp_out)),
						   &sbuff, SIZE_MAX, NULL, &pipe_rules);
		TEST_CHECK_SLEN(slen, 1);
		TEST_CHECK_STRCMP(tmp_out, "|");
		TEST_CHECK_STRCMP(sbuff.p, "");
	}

	{
		char	in_escapes_collapse[] = "||foo||";

		TEST_CASE("Collapse double escapes overlapping");
		fr_sbuff_init_in(&sbuff, in_escapes_collapse, sizeof(in_escapes_collapse) - 1);
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(in_escapes_collapse, sizeof(in_escapes_collapse)),
						   &sbuff, SIZE_MAX, NULL, &pipe_rules);
		TEST_CHECK_SLEN(slen, 5);
		TEST_CHECK_STRCMP(in_escapes_collapse, "|foo|");
		TEST_CHECK_STRCMP(sbuff.p, "");
	}

	{
		char		tmp_out[30 + 1];

		fr_sbuff_unescape_rules_t double_quote_rules = {
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
		fr_sbuff_init_in(&sbuff, in_escapes_unit, sizeof(in_escapes_unit) - 1);
		slen = fr_sbuff_out_unescape_until(&FR_SBUFF_OUT(tmp_out, sizeof(tmp_out)), &sbuff, SIZE_MAX,
						   NULL, &double_quote_rules);
		TEST_CHECK_SLEN(slen, 28);
		TEST_CHECK_STRCMP(tmp_out, expected);
		TEST_CHECK_STRCMP(sbuff.p, "");
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
		TEST_CHECK_SLEN(len, 0);
		talloc_get_type_abort(buff, char);
		TEST_CHECK_SLEN(talloc_array_length(buff), 1);
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

	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);

	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, &tt, NULL);
	TEST_CHECK_SLEN_RETURN(slen, 3);
	TEST_CHECK_STRCMP(out, "foo");

	fr_sbuff_advance(&sbuff, 1);

	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, &tt, NULL);
	TEST_CHECK(slen == 1);
	TEST_CHECK_STRCMP(out, " ");

	fr_sbuff_advance(&sbuff, 4);

	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, &tt, NULL);
	TEST_CHECK(slen == 4);
	TEST_CHECK_STRCMP(out, " baz");
}

static void test_eof_terminal(void)
{
	char const		in[] = "foo, bar";
	fr_sbuff_t		sbuff;
	ssize_t			slen;
	fr_sbuff_term_t		tt_eof = FR_SBUFF_TERMS(
					L(""),
					L(","),
				);
	fr_sbuff_term_t		tt = FR_SBUFF_TERMS(
					L(",")
				);
	char			out[100];

	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);

	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, &tt_eof, NULL);
	TEST_CHECK_SLEN_RETURN(slen, 3);
	TEST_CHECK_STRCMP(out, "foo");

	fr_sbuff_advance(&sbuff, 1);	/* Advance past comma */

	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &sbuff, SIZE_MAX, &tt_eof, NULL);
	TEST_CHECK_SLEN_RETURN(slen, 4);
	TEST_CHECK_STRCMP(out, " bar");

	TEST_CHECK(fr_sbuff_is_terminal(&sbuff, &tt_eof) == true);
	TEST_CHECK(fr_sbuff_is_terminal(&sbuff, &tt) == false);
}

static void test_terminal_merge(void)
{
	size_t i;
	fr_sbuff_term_t a = FR_SBUFF_TERMS(
				L(""),
				L("\t"),
				L("\n"),
				L("\r"),
				L(" "),
				L("!"),
				L("%"),
				L("&"),
				L("*"),
				L("+"),
				L("-"),
				L("/"),
				L("<"),
				L("="),
				L(">"),
				L("^"),
				L("{"),
				L("|"),
				L("~")
			    );
	fr_sbuff_term_t b = FR_SBUFF_TERMS(
				L(""),
				L(")"),
			    );

	fr_sbuff_term_t expect =
			    FR_SBUFF_TERMS(
				L(""),
				L("\t"),
				L("\n"),
				L("\r"),
				L(" "),
				L("!"),
				L("%"),
				L("&"),
				L(")"),
				L("*"),
				L("+"),
				L("-"),
				L("/"),
				L("<"),
				L("="),
				L(">"),
				L("^"),
				L("{"),
				L("|"),
				L("~")
			    );
	fr_sbuff_term_t *result;

	result = fr_sbuff_terminals_amerge(NULL, &a, &b);
	TEST_CHECK_LEN(result->len, expect.len);

	for (i = 0; i < result->len; i++) {
		TEST_CHECK_STRCMP(result->elem[i].str, expect.elem[i].str);
	}

	talloc_free(result);
}

static void test_no_advance(void)
{
	char const	*in = "i am a test string";
	char		out[18 + 1] = "";
	fr_sbuff_t	sbuff;
	ssize_t		slen;

	fr_sbuff_init_in(&sbuff, in, strlen(in));

	TEST_CASE("Copy 5 bytes to out - no advance");
	TEST_CHECK(sbuff.p == sbuff.start);
	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, sizeof(out)), &FR_SBUFF(&sbuff), 5);
	TEST_CHECK_SLEN_RETURN(slen, 5);
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

	talloc_free(sbuff.buff);
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

	talloc_free(sbuff.buff);
}

static void test_talloc_extend_multi_level(void)
{
	fr_sbuff_t		sbuff_0, sbuff_1;
	fr_sbuff_uctx_talloc_t	tctx;

	TEST_CASE("Initial allocation");
	TEST_CHECK(fr_sbuff_init_talloc(NULL, &sbuff_0, &tctx, 0, 50) == &sbuff_0);
	TEST_SBUFF_USED(&sbuff_0, 0);
	TEST_SBUFF_LEN(&sbuff_0, 1);

	sbuff_1 = FR_SBUFF_BIND_CURRENT(&sbuff_0);
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

	talloc_free(sbuff_0.buff);
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
	TEST_CHECK_STRCMP(fr_sbuff_start(&sbuff_0), "A");
	TEST_SBUFF_USED(&sbuff_0, 1);
	TEST_SBUFF_LEN(&sbuff_0, 2);

	fr_sbuff_marker(&marker_0, &sbuff_0);
	TEST_CHECK((marker_0.p - sbuff_0.start) == 1);

	TEST_CASE("Print string - Ensure marker is updated");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff_0, "B") == 1);
	TEST_CHECK_STRCMP(fr_sbuff_start(&sbuff_0), "AB");
	TEST_SBUFF_USED(&sbuff_0, 2);
	TEST_SBUFF_LEN(&sbuff_0, 3);
	TEST_CHECK((marker_0.p - sbuff_0.start) == 1);

	TEST_CASE("Print string - Copy sbuff");
	sbuff_1 = FR_SBUFF_BIND_CURRENT(&sbuff_0);	/* Dup sbuff_0 */
	TEST_CHECK(sbuff_0.p == sbuff_1.start);
	fr_sbuff_marker(&marker_1, &sbuff_1);

	TEST_CHECK((marker_1.p - sbuff_1.start) == 0);
	TEST_CHECK((marker_1.p - sbuff_0.start) == 2);
	TEST_CHECK(sbuff_0.p == sbuff_1.start);

	TEST_CASE("Print string - Trigger re-alloc, ensure all pointers are updated");
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff_1, "C") == 1);
	TEST_CHECK_STRCMP(fr_sbuff_start(&sbuff_1), "C");
	TEST_CHECK(sbuff_0.buff == sbuff_1.buff);
	TEST_CHECK(sbuff_0.p == sbuff_1.start + 1);
	TEST_CHECK((marker_1.p - sbuff_1.start) == 0);
	TEST_CHECK((marker_1.p - sbuff_0.start) == 2);
	TEST_SBUFF_USED(&sbuff_0, 3);
	TEST_SBUFF_LEN(&sbuff_0, 5);

	talloc_free(sbuff_0.buff);
}

static void test_talloc_extend_with_shift(void)
{
	fr_sbuff_t		sbuff;
	fr_sbuff_uctx_talloc_t	tctx;

	TEST_CASE("Intermix shift and extend");
	TEST_CHECK(fr_sbuff_init_talloc(NULL, &sbuff, &tctx, 4, 8) == &sbuff);
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "0123") == 4);
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "5678") == 4);
	TEST_CHECK(fr_sbuff_shift(&sbuff, 4, false) == 4);
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "AAAA") == 4);
	TEST_CHECK(fr_sbuff_shift(&sbuff, 8, false) == 8);
	TEST_CHECK(fr_sbuff_in_strcpy(&sbuff, "BBBBBBBB") == 8);

	talloc_free(sbuff.buff);
}

static void test_file_extend(void)
{
	fr_sbuff_t	sbuff;
	fr_sbuff_t	our_sbuff, child_sbuff;
	fr_sbuff_uctx_file_t	fctx;
	FILE		*fp;
	char		buff[5];
	char		out[24];
	char		fbuff[24];
	const char	PATTERN[] = "xyzzy";
#define PATTERN_LEN (sizeof(PATTERN) - 1)
	char		*post_ws;
	ssize_t		slen;

	static_assert(sizeof(buff) >= PATTERN_LEN, "Buffer must be sufficiently large to hold the pattern");
	static_assert((sizeof(fbuff) % sizeof(buff)) > 0, "sizeof buff must not be a multiple of fbuff");
	static_assert((sizeof(fbuff) % sizeof(buff)) < PATTERN_LEN, "remainder of sizeof(fbuff)/sizeof(buff) must be less than sizeof pattern");

	TEST_CASE("Initialization");
	memset(fbuff, ' ', sizeof(fbuff));
	memcpy(fbuff + sizeof(fbuff) - PATTERN_LEN, PATTERN, PATTERN_LEN);

	fp = fmemopen(fbuff, sizeof(fbuff), "r");
#ifdef __clang_analyzer__
	if (fp == NULL) return;
#endif

	TEST_CHECK(fp != NULL);
	TEST_CHECK(fr_sbuff_init_file(&sbuff, &fctx, buff, sizeof(buff), fp, 128) == &sbuff);
	our_sbuff = FR_SBUFF_BIND_CURRENT(&sbuff);

	TEST_CASE("Advance past whitespace, which will require shift/extend");
	TEST_CHECK_LEN(fr_sbuff_adv_past_whitespace(&our_sbuff, SIZE_MAX, NULL), sizeof(fbuff) - PATTERN_LEN);
	TEST_CASE("Verify extend on unused child buffer");
	child_sbuff = FR_SBUFF(&our_sbuff);
	slen = fr_sbuff_extend_file(NULL, &child_sbuff, 0);
	TEST_CHECK_SLEN(slen, sizeof(fbuff) % PATTERN_LEN);
	TEST_CASE("Verify that we passed all and only whitespace");
	(void) fr_sbuff_out_abstrncpy(NULL, &post_ws, &our_sbuff, 24);
	TEST_CHECK_STRCMP(post_ws, PATTERN);
	talloc_free(post_ws);
	TEST_CASE("Verify parent buffer end");
	TEST_CHECK(sbuff.end == our_sbuff.end);

	TEST_CASE("Verify that we do not read shifted buffer past eof");
	slen = fr_sbuff_out_bstrncpy(&FR_SBUFF_OUT(out, sizeof(out)), &our_sbuff, SIZE_MAX);
	TEST_CHECK_SLEN(slen, 0);
	slen = fr_sbuff_out_bstrncpy_exact(&FR_SBUFF_OUT(out, sizeof(out)), &our_sbuff, SIZE_MAX);
	TEST_CHECK_SLEN(slen, 0);
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &our_sbuff, SIZE_MAX, NULL, NULL);
	TEST_CHECK_SLEN(slen, 0);
	slen = fr_sbuff_out_bstrncpy_allowed(&FR_SBUFF_OUT(out, sizeof(out)), &our_sbuff, SIZE_MAX, allow_lowercase_and_space);
	TEST_CHECK_SLEN(slen, 0);

	fclose(fp);

	TEST_CASE("Verify fr_sbuff_out_bstrncpy_until() extends from file properly");
	fp = fmemopen(fbuff, sizeof(fbuff), "r");
#ifdef __clang_analyzer__
	if (fp == NULL) return;
#endif

	TEST_CHECK(fp != NULL);
	TEST_CHECK(fr_sbuff_init_file(&sbuff, &fctx, buff, sizeof(buff), fp, 128) == &sbuff);
	our_sbuff = FR_SBUFF_BIND_CURRENT(&sbuff);
	slen = fr_sbuff_out_bstrncpy_until(&FR_SBUFF_OUT(out, sizeof(out)), &our_sbuff, SIZE_MAX, &FR_SBUFF_TERM("x"), NULL);
	TEST_CHECK_SLEN(slen, sizeof(fbuff) - PATTERN_LEN);

	fclose(fp);
}

static void test_file_extend_max(void)
{
	fr_sbuff_t	sbuff;
	fr_sbuff_uctx_file_t	fctx;
	FILE		*fp;
	char		buff[16];
	char		fbuff[] = "                        xyzzy";
	char		*post_ws;

	TEST_CASE("Initialization");
	fp = fmemopen(fbuff, sizeof(fbuff) - 1, "r");
#ifdef __clang_analyzer__
	if (fp == NULL) return;
#endif
	TEST_CHECK(fp != NULL);
	TEST_CHECK(fr_sbuff_init_file(&sbuff, &fctx, buff, sizeof(buff), fp, sizeof(fbuff) - 8) == &sbuff);

	TEST_CASE("Confirm that max stops us from seeing xyzzy");
	TEST_CHECK_SLEN(fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX, NULL), sizeof(fbuff) - 8);
	TEST_CHECK_SLEN(fr_sbuff_out_abstrncpy(NULL, &post_ws, &sbuff, 24), 0);
	TEST_CHECK_STRCMP(post_ws, "");
	talloc_free(post_ws);
	fclose(fp);
}

static void test_adv_past_str(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "i am a test string";

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_str(&sbuff, "i am a", SIZE_MAX), 6);
	TEST_CHECK_STRCMP(sbuff.p, " test string");

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_str(&sbuff, " am a", SIZE_MAX), 0);
	TEST_CHECK_STRCMP(sbuff.p, "i am a test string");

	TEST_CASE("Check for token larger than the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_str(&sbuff, "i am a test string ", SIZE_MAX), 0);
	TEST_CHECK_STRCMP(sbuff.p, "i am a test string");

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init_in(&sbuff, in, 0);
	TEST_CHECK_LEN(fr_sbuff_adv_past_str(&sbuff, "i am a", SIZE_MAX), 0);

	TEST_CASE("Check for token that is the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_str(&sbuff, "i am a test string", SIZE_MAX), 18);
	TEST_CHECK_STRCMP(sbuff.p, "");
	TEST_CHECK(sbuff.p == sbuff.end);
}

static void test_adv_past_strcase(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "i am a test string";

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_strcase(&sbuff, "i AM a", SIZE_MAX), 6);
	TEST_CHECK_STRCMP(sbuff.p, " test string");

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_strcase(&sbuff, " AM a", SIZE_MAX), 0);
	TEST_CHECK_STRCMP(sbuff.p, "i am a test string");

	TEST_CASE("Check for token larger than the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_strcase(&sbuff, "i AM a TEST string ", SIZE_MAX), 0);
	TEST_CHECK_STRCMP(sbuff.p, "i am a test string");

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init_in(&sbuff, in, 0);
	TEST_CHECK_LEN(fr_sbuff_adv_past_strcase(&sbuff, "i AM a", SIZE_MAX), 0);

	TEST_CASE("Check for token that is the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_strcase(&sbuff, "i AM a TEST string", SIZE_MAX), 18);
	TEST_CHECK_STRCMP(sbuff.p, "");
	TEST_CHECK(sbuff.p == sbuff.end);
}

static void test_adv_past_whitespace(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "     i am a         test string";
	char const	in_ns[] = "i am a test string";
	char const	in_ws[] = "     ";

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX, NULL), 5);
	TEST_CHECK_STRCMP(sbuff.p, "i am a         test string");

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init_in(&sbuff, in_ns, sizeof(in_ns) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX, NULL), 0);
	TEST_CHECK_STRCMP(sbuff.p, "i am a test string");

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init_in(&sbuff, in, 0);
	TEST_CHECK_LEN(fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX, NULL), 0);

	TEST_CASE("Check for token that is the string");
	fr_sbuff_init_in(&sbuff, in_ws, sizeof(in_ws) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_whitespace(&sbuff, SIZE_MAX, NULL), 5);

	TEST_CASE("Length constraint with token match");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_whitespace(&sbuff, 2, NULL), 2);
	TEST_CHECK_STRCMP(sbuff.p, "   i am a         test string");

	TEST_CASE("Length constraint without token match");
	fr_sbuff_init_in(&sbuff, in_ns, sizeof(in_ns) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_whitespace(&sbuff, 2, NULL), 0);
	TEST_CHECK_STRCMP(sbuff.p, "i am a test string");
}

static void test_adv_past_allowed(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "     i am a         test string";
	char const	in_ns[] = "i am a test string";
	char const	in_ws[] = "     ";

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_allowed(&sbuff, SIZE_MAX, (bool[UINT8_MAX + 1]){ [' '] = true }, NULL), 5);
	TEST_CHECK_STRCMP(sbuff.p, "i am a         test string");

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init_in(&sbuff, in_ns, sizeof(in_ns) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_allowed(&sbuff, SIZE_MAX, (bool[UINT8_MAX + 1]){ [' '] = true }, NULL), 0);
	TEST_CHECK_STRCMP(sbuff.p, "i am a test string");

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init_in(&sbuff, in, 0);
	TEST_CHECK_LEN(fr_sbuff_adv_past_allowed(&sbuff, SIZE_MAX, (bool[UINT8_MAX + 1]){ [' '] = true }, NULL), 0);
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Check for token at the end of the string");
	fr_sbuff_init_in(&sbuff, in_ws, sizeof(in_ws) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_allowed(&sbuff, SIZE_MAX, (bool[UINT8_MAX + 1]){ [' '] = true }, NULL), 5);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Length constraint with token match");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_allowed(&sbuff, 2, (bool[UINT8_MAX + 1]){ [' '] = true }, NULL), 2);
	TEST_CHECK_STRCMP(sbuff.p, "   i am a         test string");

	TEST_CASE("Length constraint with token match");
	fr_sbuff_init_in(&sbuff, in_ns, sizeof(in_ns) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_past_allowed(&sbuff, 2, (bool[UINT8_MAX + 1]){ [' '] = true }, NULL), 0);
	TEST_CHECK_STRCMP(sbuff.p, "i am a test string");
}

static void test_adv_until(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = " abcdefgh ijklmnopp";

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_until(&sbuff, SIZE_MAX, &FR_SBUFF_TERM(" "), '\0'), 0);
	TEST_CHECK_STRCMP(sbuff.p, " abcdefgh ijklmnopp");

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_until(&sbuff, SIZE_MAX, &FR_SBUFF_TERM("a"), '\0'), 1);
	TEST_CHECK_STRCMP(sbuff.p, "abcdefgh ijklmnopp");

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init_in(&sbuff, in, 0);
	TEST_CHECK_LEN(fr_sbuff_adv_until(&sbuff, SIZE_MAX, &FR_SBUFF_TERM("a"), '\0'), 0);
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Check for token that is not in the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_until(&sbuff, SIZE_MAX, &FR_SBUFF_TERM("|"), '\0'), 19);
	TEST_CHECK(sbuff.p == sbuff.end);

	TEST_CASE("Check escapes");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_until(&sbuff, SIZE_MAX, &FR_SBUFF_TERM("p"), 'o'), 18);
	TEST_CHECK_STRCMP(sbuff.p, "p");

	TEST_CASE("Check for token that is not in the string with length constraint");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK_LEN(fr_sbuff_adv_until(&sbuff, 5, &FR_SBUFF_TERM("|"), '\0'), 5);
	TEST_CHECK(sbuff.p == (sbuff.start + 5));
}

static void test_adv_to_utf8(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "🥺🥺🥺🥺🍪😀";
	char		*p;

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_chr_utf8(&sbuff, SIZE_MAX, "🥺");
	TEST_CHECK(p == sbuff.p);
	TEST_CHECK_STRCMP(sbuff.p, "🥺🥺🥺🥺🍪😀");

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_chr_utf8(&sbuff, SIZE_MAX, "🍪");
	TEST_CHECK(p == (sbuff.start + (sizeof("🥺🥺🥺🥺") - 1)));
	TEST_CHECK_STRCMP(p, "🍪😀");

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init_in(&sbuff, in, 0);
	p = fr_sbuff_adv_to_chr_utf8(&sbuff, SIZE_MAX, "🍪");
	TEST_CHECK(p == NULL);
	TEST_CHECK(sbuff.start == sbuff.p);

	TEST_CASE("Check for token at the end of the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_chr_utf8(&sbuff, SIZE_MAX, "😀");
	TEST_CHECK(p == sbuff.start + (sizeof("🥺🥺🥺🥺🍪") - 1));

	TEST_CASE("Check for token not in the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_chr_utf8(&sbuff, SIZE_MAX, "🍆 ");
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token at the end of the string within len constraints");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_chr_utf8(&sbuff, (sizeof("🥺🥺🥺🥺🍪😀") - 1), "😀");
	TEST_CHECK(p == sbuff.start + (sizeof("🥺🥺🥺🥺🍪") - 1));

	TEST_CASE("Check for token at the end of the string outside len constraints #1");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK(!fr_sbuff_adv_to_chr_utf8(&sbuff, (sizeof("🥺🥺🥺🥺🍪😀") - 2), "😀"));
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Check for token at the end of the string outside len constraints #2");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK(!fr_sbuff_adv_to_chr_utf8(&sbuff, (sizeof("🥺🥺🥺🥺🍪😀") - 3), "😀"));
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Check for token at the end of the string outside len constraints #3");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK(!fr_sbuff_adv_to_chr_utf8(&sbuff, (sizeof("🥺🥺🥺🥺🍪😀") - 4), "😀"));
	TEST_CHECK(sbuff.p == sbuff.start);

	TEST_CASE("Check for token at the end of the string outside len constraints #4");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK(!fr_sbuff_adv_to_chr_utf8(&sbuff, (sizeof("🥺🥺🥺🥺🍪😀") - 5), "😀"));
	TEST_CHECK(sbuff.p == sbuff.start);
}

static void test_adv_to_chr(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "AAAAbC";
	char		*p;

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, 'A');
	TEST_CHECK(p == sbuff.p);
	TEST_CHECK_STRCMP(sbuff.p, "AAAAbC");

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, 'b');
	TEST_CHECK(p == (sbuff.start + (sizeof("AAAA") - 1)));
	TEST_CHECK_STRCMP(p, "bC");

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init_in(&sbuff, in, 0);
	TEST_CHECK(!fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, 'b'));
	TEST_CHECK(sbuff.start == sbuff.p);

	TEST_CASE("Check for token at the end of the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, 'C');
	TEST_CHECK(p == sbuff.start + (sizeof("AAAAb") - 1));

	TEST_CASE("Check for token not in the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_chr(&sbuff, SIZE_MAX, 'D');
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token not at beginning of string within length constraints");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_chr(&sbuff, 5, 'b');
	TEST_CHECK(p == (sbuff.start + (sizeof("AAAA") - 1)));
	TEST_CHECK_STRCMP(p, "bC");

	TEST_CASE("Check for token not at beginning of string outside length constraints");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK(!fr_sbuff_adv_to_chr(&sbuff, 4, 'b'));
	TEST_CHECK(sbuff.p == sbuff.start);
}

static void test_adv_to_str(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "i am a test string";
	char		*p;

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, "i am a test", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP(sbuff.p, "i am a test string");

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, "test", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP(sbuff.p, "test string");

	TEST_CASE("Check for token at the end of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, "ing", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP(sbuff.p, "ing");

	TEST_CASE("Check for token larger than the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, "i am a test string ", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token shorter than string, not in the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "ng ", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init_in(&sbuff, in, 0);
	p = fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, "i am a", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token that is the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_str(&sbuff, SIZE_MAX, "i am a test string", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP(p, "i am a test string");

	TEST_CASE("Check for token not at beginning of string within length constraints");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_str(&sbuff, 11, "test", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP(sbuff.p, "test string");

	TEST_CASE("Check for token not at beginning of string outside length constraints");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK(!fr_sbuff_adv_to_str(&sbuff, 10, "test", SIZE_MAX));
	TEST_CHECK(sbuff.p == sbuff.start);
}

static void test_adv_to_strcase(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "i am a test string";
	char		*p;

	TEST_CASE("Check for token at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "i AM a TEST", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP(sbuff.p, "i am a test string");

	TEST_CASE("Check for token not at beginning of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "tEst", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP(sbuff.p, "test string");

	TEST_CASE("Check for token at the end of string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "Ing", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP(sbuff.p, "ing");

	TEST_CASE("Check for token larger than the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "i aM a tEst stRIng ", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token shorter than string, not in the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "nG ", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token with zero length string");
	fr_sbuff_init_in(&sbuff, in, 0);
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "i AM a", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(p == NULL);

	TEST_CASE("Check for token that is the string");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_strcase(&sbuff, SIZE_MAX, "i AM a teST stRIng", SIZE_MAX);
	TEST_CHECK(sbuff.p == sbuff.start);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP(p, "i am a test string");

	TEST_CASE("Check for token not at beginning of string within length constraints");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	p = fr_sbuff_adv_to_strcase(&sbuff, 11, "tEst", SIZE_MAX);
	TEST_CHECK(sbuff.p == p);
	TEST_CHECK_STRCMP(sbuff.p, "test string");

	TEST_CASE("Check for token not at beginning of string outside length constraints");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK(!fr_sbuff_adv_to_strcase(&sbuff, 10, "tEst", SIZE_MAX));
	TEST_CHECK(sbuff.p == sbuff.start);
}

static void test_next_if_char(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "i ";

	TEST_CASE("Check for advancement on match");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK(fr_sbuff_next_if_char(&sbuff, 'i') == true);
	TEST_CHECK_STRCMP(sbuff.p, " ");

	TEST_CASE("Check for non-advancement on non-match");
	TEST_CHECK(fr_sbuff_next_if_char(&sbuff, 'i') == false);
	TEST_CHECK_STRCMP(sbuff.p, " ");

	TEST_CASE("Check for advancement at end");
	TEST_CHECK(fr_sbuff_next_if_char(&sbuff, ' ') == true);
	TEST_CHECK_STRCMP(sbuff.p, "");

	TEST_CASE("Check we can't advance off the end of the buffer");
	TEST_CHECK(fr_sbuff_next_if_char(&sbuff, ' ') == false);
	TEST_CHECK_STRCMP(sbuff.p, "");
}

static void test_next_unless_char(void)
{
	fr_sbuff_t	sbuff;
	char const	in[] = "i ";

	TEST_CASE("Check for advancement on non-match");
	fr_sbuff_init_in(&sbuff, in, sizeof(in) - 1);
	TEST_CHECK(fr_sbuff_next_unless_char(&sbuff, ' ') == true);
	TEST_CHECK_STRCMP(sbuff.p, " ");

	TEST_CASE("Check for non-advancement on match");
	TEST_CHECK(fr_sbuff_next_unless_char(&sbuff, ' ') == false);
	TEST_CHECK_STRCMP(sbuff.p, " ");

	TEST_CASE("Check for advancement at end");
	TEST_CHECK(fr_sbuff_next_unless_char(&sbuff, '_') == true);
	TEST_CHECK_STRCMP(sbuff.p, "");

	TEST_CASE("Check we can't advance off the end of the buffer");
	TEST_CHECK(fr_sbuff_next_unless_char(&sbuff, '_') == false);
	TEST_CHECK_STRCMP(sbuff.p, "");
}

TEST_LIST = {
	/*
	 *	Basic tests
	 */
	{ "fr_sbuff_init",			test_parse_init },
	{ "fr_sbuff_is_char",			test_is_char },
	{ "fr_sbuff_out_bstrncpy_exact",	test_bstrncpy_exact },
	{ "fr_sbuff_out_bstrncpy",		test_bstrncpy },
	{ "fr_sbuff_out_bstrncpy_allowed",	test_bstrncpy_allowed },
	{ "fr_sbuff_out_bstrncpy_until",	test_bstrncpy_until },
	{ "multi-char terminals",		test_unescape_multi_char_terminals },
	{ "fr_sbuff_out_unescape_until",	test_unescape_until },
	{ "fr_sbuff_terminal_eof",		test_eof_terminal },
	{ "terminal merge",			test_terminal_merge },

	/*
	 *	Extending buffer
	 */
	{ "fr_sbuff_talloc_extend",		test_talloc_extend },
	{ "fr_sbuff_talloc_extend_init_zero",	test_talloc_extend_init_zero },
	{ "fr_sbuff_talloc_extend_multi_level",	test_talloc_extend_multi_level },
	{ "fr_sbuff_talloc_extend_with_marker",	test_talloc_extend_with_marker },
	{ "fr_sbuff_talloc_extend_with_shift",	test_talloc_extend_with_shift},
	{ "fr_sbuff_file_extend",		test_file_extend },
	{ "fr_sbuff_file_extend_max",		test_file_extend_max },

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

	TEST_TERMINATOR
};
