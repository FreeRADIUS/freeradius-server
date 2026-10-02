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

/** Tests for the configuration file tokenizer
 *
 * @file src/lib/util/test/token_tests.c
 *
 * @copyright 2026 The FreeRADIUS server project
 */
#include "acutest_common_init.h"

#include <freeradius-devel/util/token.h>

#include <sys/mman.h>
#include <unistd.h>

/** Where a parse ran, and what the parse produced
 *
 */
typedef struct {
	fr_token_t	token;				//!< what the parse function returned.
	char		buf[256];			//!< what the parse function wrote.
	size_t		used;				//!< how many bytes of the input the parse consumed.
} parse_result_t;

/** Copy a string so that the terminating NUL is the last readable byte
 *
 *  A read past the NUL lands on an unreadable page and faults, rather than returning
 *  whatever byte happens to follow the string.  Every parse in this file runs against a
 *  guarded copy, because a tokenizer which reads one byte too far produces the right answer
 *  on almost every run and the wrong answer on the rest.
 *
 * @param[out] base	start of the mapping, to pass to guard_free().
 * @param[in] in	to copy.
 * @return the copy, positioned against the unreadable page.
 */
static char *guard_alloc(char **base, char const *in)
{
	size_t	len = strlen(in);
	long	sc_pagesize = sysconf(_SC_PAGESIZE);
	size_t	pagesz;
	char	*p;

	/* Coverity hasn't read the sysconf man page */
	if (sc_pagesize <= 0) {
		*base = MAP_FAILED;
		return NULL;
	}
	pagesz = (size_t)sc_pagesize;

	*base = mmap(NULL, pagesz * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (*base == MAP_FAILED) return NULL;

	if (mprotect(*base + pagesz, pagesz, PROT_NONE) < 0) return NULL;

	p = *base + pagesz - (len + 1);
	memcpy(p, in, len + 1);

	return p;
}

static void guard_free(char *base)
{
	long	sc_pagesize = sysconf(_SC_PAGESIZE);

	/* Coverity hasn't read the sysconf man page */
	if (sc_pagesize <= 0) return;
	munmap(base, (size_t) sc_pagesize * 2);
}

/** Run gettoken() over a guarded copy of the input
 *
 */
static parse_result_t test_gettoken(char const *in, bool unescape)
{
	parse_result_t	result = {};
	char		*base, *start;
	char const	*p;

	start = guard_alloc(&base, in);
	TEST_ASSERT(start != NULL);

	p = start;
	result.token = gettoken(&p, result.buf, sizeof(result.buf), unescape);
	result.used = (size_t) (p - start);

	guard_free(base);

	return result;
}

/** Run getword() over a guarded copy of the input
 *
 *  getword() returns 0 at end of line and 1 otherwise, so the rcode goes in `token`.
 */
static parse_result_t test_getword(char const *in, bool unescape)
{
	parse_result_t	result = {};
	char		*base, *start;
	char const	*p;

	start = guard_alloc(&base, in);
	TEST_ASSERT(start != NULL);

	p = start;
	result.token = (fr_token_t) getword(&p, result.buf, sizeof(result.buf), unescape);
	result.used = (size_t) (p - start);

	guard_free(base);

	return result;
}

/** Run getstring() over a guarded copy of the input
 *
 */
static parse_result_t test_getstring(char const *in, bool unescape)
{
	parse_result_t	result = {};
	char		*base, *start;
	char const	*p;

	start = guard_alloc(&base, in);
	TEST_ASSERT(start != NULL);

	p = start;
	result.token = getstring(&p, result.buf, sizeof(result.buf), unescape);
	result.used = (size_t) (p - start);

	guard_free(base);

	return result;
}

/** Run getop() over a guarded copy of the input
 *
 */
static parse_result_t test_getop(char const *in)
{
	parse_result_t	result = {};
	char		*base, *start;
	char const	*p;

	start = guard_alloc(&base, in);
	TEST_ASSERT(start != NULL);

	p = start;
	result.token = getop(&p);
	result.used = (size_t) (p - start);

	guard_free(base);

	return result;
}

#define TEST_PARSE(_result, _token, _buf, _used) do { \
	TEST_CHECK((_result).token == (_token)); \
	TEST_MSG("token: got %d, expected %d", (_result).token, (_token)); \
	TEST_CHECK(strcmp((_result).buf, (_buf)) == 0); \
	TEST_MSG("buf: got \"%s\", expected \"%s\"", (_result).buf, (_buf)); \
	TEST_CHECK((_result).used == (size_t) (_used)); \
	TEST_MSG("used: got %zu, expected %zu", (_result).used, (size_t) (_used)); \
} while (0)

/** A triple-quoted string keeps every character between the delimiters
 *
 *  Skipping three characters for the opening delimiter and then one more ate the first
 *  character of the content.  For an input of three quotes and nothing else, the same extra
 *  skip stepped past the terminating NUL.
 */
static void test_triple_quote(void)
{
	TEST_PARSE(test_gettoken("\"\"\"abc\"\"\"", true), T_DOUBLE_QUOTED_STRING, "abc", 9);
	TEST_PARSE(test_gettoken("'''abc'''", true), T_SINGLE_QUOTED_STRING, "abc", 9);
	TEST_PARSE(test_gettoken("```abc```", true), T_BACK_QUOTED_STRING, "abc", 9);

	/*
	 *	A triple-quoted string holds quotes which a single-quoted string cannot.
	 */
	TEST_PARSE(test_gettoken("\"\"\"a\"b\"\"\"", true), T_DOUBLE_QUOTED_STRING, "a\"b", 9);

	/*
	 *	Three quotes and nothing else open a string which never ends.
	 */
	TEST_PARSE(test_gettoken("\"\"\"", true), T_INVALID, "", 0);
	TEST_PARSE(test_gettoken("\"\"\"abc", true), T_INVALID, "abc", 0);

	/*
	 *	Two quotes are an empty string, and are not a triple quote.
	 */
	TEST_PARSE(test_gettoken("\"\"", true), T_DOUBLE_QUOTED_STRING, "", 2);
}

/** gettoken() splits on the tokens in the token table
 *
 */
static void test_gettoken_delimiters(void)
{
	TEST_PARSE(test_gettoken("hello", true), T_BARE_WORD, "hello", 5);

	/*
	 *	The delimiter is left for the next call to read.
	 */
	TEST_PARSE(test_gettoken("a,b", true), T_BARE_WORD, "a", 1);
	TEST_PARSE(test_gettoken("a==b", true), T_BARE_WORD, "a", 1);
	TEST_PARSE(test_gettoken("a b", true), T_BARE_WORD, "a", 2);

	/*
	 *	A token which starts the input is returned as that token.
	 */
	TEST_PARSE(test_gettoken("{", true), T_LCBRACE, "{", 1);
	TEST_PARSE(test_gettoken("}", true), T_RCBRACE, "}", 1);
	TEST_PARSE(test_gettoken(",", true), T_COMMA, ",", 1);
	TEST_PARSE(test_gettoken("==", true), T_OP_CMP_EQ, "==", 2);

	/*
	 *	Leading whitespace is skipped, and so is trailing whitespace.
	 */
	TEST_PARSE(test_gettoken("   abc   ", true), T_BARE_WORD, "abc", 9);

	/*
	 *	Nothing to read, and whitespace with nothing after it, are both end of line.
	 */
	TEST_PARSE(test_gettoken("", true), T_EOL, "", 0);
	TEST_PARSE(test_gettoken("   ", true), T_EOL, "", 3);
}

/** Each quote character produces its own token type
 *
 */
static void test_gettoken_quotes(void)
{
	TEST_PARSE(test_gettoken("\"a b\"", true), T_DOUBLE_QUOTED_STRING, "a b", 5);
	TEST_PARSE(test_gettoken("'a b'", true), T_SINGLE_QUOTED_STRING, "a b", 5);
	TEST_PARSE(test_gettoken("`a b`", true), T_BACK_QUOTED_STRING, "a b", 5);

	/*
	 *	A quoted string holds the token characters which would otherwise split the input.
	 */
	TEST_PARSE(test_gettoken("\"a,b==c\"", true), T_DOUBLE_QUOTED_STRING, "a,b==c", 8);

	/*
	 *	An empty quoted string is still a string.
	 */
	TEST_PARSE(test_gettoken("''", true), T_SINGLE_QUOTED_STRING, "", 2);
}

/** gettoken() turns escape sequences into the characters the sequences name
 *
 */
static void test_gettoken_unescape(void)
{
	TEST_PARSE(test_gettoken("\"a\\nb\"", true), T_DOUBLE_QUOTED_STRING, "a\nb", 6);
	TEST_PARSE(test_gettoken("\"a\\rb\"", true), T_DOUBLE_QUOTED_STRING, "a\rb", 6);
	TEST_PARSE(test_gettoken("\"a\\tb\"", true), T_DOUBLE_QUOTED_STRING, "a\tb", 6);

	/*
	 *	Three octal digits are one character.  101 octal is 'A'.
	 */
	TEST_PARSE(test_gettoken("\"a\\101b\"", true), T_DOUBLE_QUOTED_STRING, "aAb", 8);

	/*
	 *	An escaped quote does not end the string.
	 */
	TEST_PARSE(test_gettoken("\"a\\\"b\"", true), T_DOUBLE_QUOTED_STRING, "a\"b", 6);

	/*
	 *	A backslash in front of anything else yields that character.
	 */
	TEST_PARSE(test_gettoken("\"a\\qb\"", true), T_DOUBLE_QUOTED_STRING, "aqb", 6);
	TEST_PARSE(test_gettoken("\"a\\\\b\"", true), T_DOUBLE_QUOTED_STRING, "a\\b", 6);
}

/** Without unescaping, gettoken() keeps the backslash
 *
 *  The one exception is a backslash in front of the quote character, which the tokenizer
 *  still has to remove so that the quote does not end the string.
 */
static void test_gettoken_no_unescape(void)
{
	TEST_PARSE(test_gettoken("\"a\\nb\"", false), T_DOUBLE_QUOTED_STRING, "a\\nb", 6);
	TEST_PARSE(test_gettoken("\"a\\101b\"", false), T_DOUBLE_QUOTED_STRING, "a\\101b", 8);

	TEST_PARSE(test_gettoken("\"a\\\"b\"", false), T_DOUBLE_QUOTED_STRING, "a\"b", 6);
}

/** A string which never ends is an error, and the input pointer does not move
 *
 */
static void test_gettoken_unterminated(void)
{
	TEST_PARSE(test_gettoken("\"abc", true), T_INVALID, "abc", 0);
	TEST_PARSE(test_gettoken("'abc", true), T_INVALID, "abc", 0);

	/*
	 *	The closing quote is escaped, so the string still never ends.
	 */
	TEST_PARSE(test_gettoken("\"abc\\\"", true), T_INVALID, "abc\"", 0);

	/*
	 *	A backslash with nothing after it is an error rather than an escape.  getthing()
	 *	terminates the output buffer before returning, so the caller may read the buffer
	 *	even on the error paths.
	 */
	TEST_PARSE(test_gettoken("\"abc\\", true), T_INVALID, "abc", 0);
}

/** An input longer than the output buffer stops at the end of the output buffer
 *
 */
static void test_gettoken_truncation(void)
{
	char		buf[4];
	char		*base, *start;
	char const	*p;
	fr_token_t	token;

	/*
	 *	A bare word is truncated to the space available, and is not an error.
	 */
	start = guard_alloc(&base, "abcdefgh");
	TEST_ASSERT(start != NULL);
	p = start;
	token = gettoken(&p, buf, sizeof(buf), true);
	TEST_CHECK(token == T_BARE_WORD);
	TEST_CHECK(strcmp(buf, "abc") == 0);
	TEST_MSG("got \"%s\"", buf);
	guard_free(base);

	/*
	 *	A quoted string is an error, because the closing quote is never reached.
	 */
	start = guard_alloc(&base, "\"abcdefgh\"");
	TEST_ASSERT(start != NULL);
	p = start;
	token = gettoken(&p, buf, sizeof(buf), true);
	TEST_CHECK(token == T_INVALID);
	TEST_MSG("got token %d", token);
	guard_free(base);
}

/** getword() reads to whitespace, and ignores the tokens which split gettoken()
 *
 */
static void test_getword_no_delimiters(void)
{
	/*
	 *	getword() returns 1 when the call read a word, and 0 at end of line.
	 */
	TEST_PARSE(test_getword("hello", true), 1, "hello", 5);

	/*
	 *	gettoken() stops at the "==".  getword() does not.
	 */
	TEST_PARSE(test_getword("a==b", true), 1, "a==b", 4);
	TEST_PARSE(test_getword("a;b", true), 1, "a;b", 3);

	/*
	 *	The comma is the exception.  getthing() tests for the comma outside the block
	 *	which tests the token list, so the comma ends a word for getword() as well as for
	 *	gettoken().
	 */
	TEST_PARSE(test_getword("a,b", true), 1, "a", 1);

	/*
	 *	Whitespace still ends the word.
	 */
	TEST_PARSE(test_getword("a b", true), 1, "a", 2);

	TEST_PARSE(test_getword("", true), 0, "", 0);

	/*
	 *	getword() reads quoted strings, which is the path that $TEMPLATE uses.
	 */
	TEST_PARSE(test_getword("\"a b\"", true), 1, "a b", 5);
	TEST_PARSE(test_getword("\"\"\"abc\"\"\"", true), 1, "abc", 9);
}

/** getop() accepts an assignment or comparison operator and rejects everything else
 *
 */
static void test_getop_operators(void)
{
	TEST_CHECK(test_getop("=").token == T_OP_EQ);
	TEST_CHECK(test_getop(":=").token == T_OP_SET);
	TEST_CHECK(test_getop("+=").token == T_OP_ADD_EQ);
	TEST_CHECK(test_getop("-=").token == T_OP_SUB_EQ);
	TEST_CHECK(test_getop("==").token == T_OP_CMP_EQ);
	TEST_CHECK(test_getop("!=").token == T_OP_NE);
	TEST_CHECK(test_getop("<=").token == T_OP_LE);
	TEST_CHECK(test_getop(">=").token == T_OP_GE);
	TEST_CHECK(test_getop("=~").token == T_OP_REG_EQ);
	TEST_CHECK(test_getop("!~").token == T_OP_REG_NE);

	/*
	 *	A word is not an operator, and neither is a brace.
	 */
	TEST_CHECK(test_getop("hello").token == T_INVALID);
	TEST_CHECK(test_getop("{").token == T_INVALID);
	TEST_CHECK(test_getop("").token == T_INVALID);
}

/** getstring() reads a quoted string as a string, and anything else as a word
 *
 */
static void test_getstring_quoting(void)
{
	TEST_PARSE(test_getstring("\"a b\"", true), T_DOUBLE_QUOTED_STRING, "a b", 5);
	TEST_PARSE(test_getstring("'a b'", true), T_SINGLE_QUOTED_STRING, "a b", 5);
	TEST_PARSE(test_getstring("`a b`", true), T_BACK_QUOTED_STRING, "a b", 5);

	/*
	 *	An unquoted string reaches getthing() with the token list turned off, so the
	 *	tokens which split gettoken() do not split getstring().
	 */
	TEST_PARSE(test_getstring("a=b", true), T_BARE_WORD, "a=b", 3);

	TEST_PARSE(test_getstring("a b", true), T_BARE_WORD, "a", 2);
	TEST_PARSE(test_getstring("", true), T_EOL, "", 0);
}

/** getstring() rejects a NULL pointer rather than following the pointer
 *
 */
static void test_getstring_null(void)
{
	char		buf[16];
	char const	*p = NULL;

	TEST_CHECK(getstring(NULL, buf, sizeof(buf), true) == T_INVALID);
	TEST_CHECK(getstring(&p, buf, sizeof(buf), true) == T_INVALID);

	p = "hello";
	TEST_CHECK(getstring(&p, NULL, 16, true) == T_INVALID);
}

/** fr_token_name() names the tokens which the tokenizer matches as tokens
 *
 *  The word and string tokens are not in that table, so fr_token_name() does not name the
 *  word and string tokens.  Use fr_token_to_enum_str() for those.
 */
static void test_token_name(void)
{
	TEST_CHECK(strcmp(fr_token_name(T_OP_EQ), "=") == 0);
	TEST_CHECK(strcmp(fr_token_name(T_LCBRACE), "{") == 0);
	TEST_CHECK(strcmp(fr_token_name(T_OP_CMP_EQ), "==") == 0);

	TEST_CHECK(strcmp(fr_token_name(T_BARE_WORD), "<INVALID>") == 0);
	TEST_CHECK(strcmp(fr_token_name(9999), "<INVALID>") == 0);
	TEST_CHECK(strcmp(fr_token_name(-1), "<INVALID>") == 0);
}

/** fr_token_to_enum_str() names a token with the name of the C enumeration value
 *
 */
static void test_token_to_enum_str(void)
{
	TEST_CHECK(strcmp(fr_token_to_enum_str(T_OP_EQ), "T_OP_EQ") == 0);
	TEST_CHECK(strcmp(fr_token_to_enum_str(T_BARE_WORD), "T_BARE_WORD") == 0);
	TEST_CHECK(strcmp(fr_token_to_enum_str(T_DOUBLE_QUOTED_STRING), "T_DOUBLE_QUOTED_STRING") == 0);
}

/** fr_token_from_quote_enum_str() turns an enumeration name back into a token
 *
 */
static void test_token_from_quote_enum_str(void)
{
	TEST_CHECK(fr_token_from_quote_enum_str("T_BARE_WORD", T_INVALID) == T_BARE_WORD);
	TEST_CHECK(fr_token_from_quote_enum_str("T_DOUBLE_QUOTED_STRING", T_INVALID) == T_DOUBLE_QUOTED_STRING);
	TEST_CHECK(fr_token_from_quote_enum_str("T_SINGLE_QUOTED_STRING", T_INVALID) == T_SINGLE_QUOTED_STRING);
	TEST_CHECK(fr_token_from_quote_enum_str("T_BACK_QUOTED_STRING", T_INVALID) == T_BACK_QUOTED_STRING);
	TEST_CHECK(fr_token_from_quote_enum_str("T_SOLIDUS_QUOTED_STRING", T_INVALID) == T_SOLIDUS_QUOTED_STRING);

	/*
	 *	The table holds the quote tokens only, so an operator name is not in the table.
	 */
	TEST_CHECK(fr_token_from_quote_enum_str("T_OP_EQ", T_INVALID) == T_INVALID);

	/*
	 *	An unknown name and a NULL name both return the default which the caller gave.
	 */
	TEST_CHECK(fr_token_from_quote_enum_str("nope", T_INVALID) == T_INVALID);
	TEST_CHECK(fr_token_from_quote_enum_str("nope", T_EOL) == T_EOL);
	TEST_CHECK(fr_token_from_quote_enum_str(NULL, T_EOL) == T_EOL);
}

TEST_LIST = {
	{ "triple_quote",		test_triple_quote },
	{ "gettoken_delimiters",	test_gettoken_delimiters },
	{ "gettoken_quotes",		test_gettoken_quotes },
	{ "gettoken_unescape",		test_gettoken_unescape },
	{ "gettoken_no_unescape",	test_gettoken_no_unescape },
	{ "gettoken_unterminated",	test_gettoken_unterminated },
	{ "gettoken_truncation",	test_gettoken_truncation },
	{ "getword_no_delimiters",	test_getword_no_delimiters },
	{ "getop_operators",		test_getop_operators },
	{ "getstring_quoting",		test_getstring_quoting },
	{ "getstring_null",		test_getstring_null },
	{ "token_name",			test_token_name },
	{ "token_to_enum_str",		test_token_to_enum_str },
	{ "token_from_quote_enum_str",	test_token_from_quote_enum_str },

	TEST_TERMINATOR
};
