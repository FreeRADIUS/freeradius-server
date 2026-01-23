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

/** Size printing/parsing
 *
 * @file src/lib/util/test//size_tests.c
 * @copyright Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */

#include "acutest.h"
#include"acutest_helpers.h"
#include <freeradius-devel/util/size.h>

#ifdef HAVE_GPERFTOOLS_PROFILER_H
#  include <gperftools/profiler.h>
#endif

/*
fr_slen_t fr_size_from_str(size_t *out, fr_sbuff_t *in);

fr_slen_t fr_size_to_str(fr_sbuff_t *out, size_t in);
*/


#define test_str(_str)	&FR_SBUFF_IN_STR(_str)
#define test_out(_buff)	&FR_SBUFF_OUT(_buff, sizeof(_buff))

static char buff[sizeof("18446744073709551615") + 3];

static void test_size_parse_bytes(void)
{
	size_t size;

	TEST_MSG("Parse zero b");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("0")), 1);
	TEST_CHECK_LEN(size, 0);

	TEST_MSG("Parse one b");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1")), 1);
	TEST_CHECK_LEN(size, 1);

	TEST_MSG("Parse ten b");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("10")), 2);
	TEST_CHECK_LEN(size, 10);

	TEST_MSG("Parse max b");
	snprintf(buff, sizeof(buff), "%zu", SIZE_MAX);
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str(buff)), (ssize_t)strlen(buff));
	TEST_CHECK_LEN(size, SIZE_MAX);

	TEST_MSG("Allow suffix b");
	snprintf(buff, sizeof(buff), "%zub", SIZE_MAX);
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str(buff)), (ssize_t)strlen(buff));
	TEST_CHECK_LEN(size, SIZE_MAX);

	TEST_MSG("Allow trailing none-int");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1b_")), 2);
	TEST_CHECK_LEN(size, 1);

	TEST_MSG("Fail on negative");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("-10")), -1);

/*
	TEST_MSG("Fail on trailing");
	TEST_CHECK_RET(fr_size_from_str(&size, test_str("1a0")), -2);
*/
}

static void test_size_parse_suffix_base2(void)
{
	size_t size;

	TEST_MSG("Parse zero ki");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("0ki")), 3);
	TEST_CHECK_LEN(size, 0);

	TEST_MSG("Parse zero kib");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("0kib")), 4);
	TEST_CHECK_LEN(size, 0);

	TEST_MSG("Parse one ki");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1ki")), 3);
	TEST_CHECK_LEN(size, 1024ULL);

	TEST_MSG("Parse one kib");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1kib")), 4);
	TEST_CHECK_LEN(size, 1024ULL);

	TEST_MSG("Parse one KIB");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1KIB")), 4);
	TEST_CHECK_LEN(size, 1024ULL);

	TEST_MSG("Parse one mib");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1mib")), 4);
	TEST_CHECK_LEN(size, 1024ULL * 1024);

	TEST_MSG("Parse one gib");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1gib")), 4);
	TEST_CHECK_LEN(size, 1024ULL * 1024 * 1024);

	TEST_MSG("Parse one tib");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1tib")), 4);
	TEST_CHECK_LEN(size, 1024ULL * 1024 * 1024 * 1024);

#if SIZE_MAX > UINT32_MAX
	TEST_MSG("Parse one pib");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1pib")), 4);
	TEST_CHECK_LEN(size, 1024ULL * 1024 * 1024 * 1024 * 1024);

	TEST_MSG("Parse one eib");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1eib")), 4);
	TEST_CHECK_LEN(size, 1024ULL * 1024 * 1024 * 1024 * 1024 * 1024);
#endif

	TEST_MSG("Overflow");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("100000000eib")), -1);
}

static void test_size_parse_suffix_base10(void)
{
	size_t size;

	TEST_MSG("Parse zero k");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("0k")), 2);
	TEST_CHECK_LEN(size, 0);

	TEST_MSG("Parse zero kb");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("0kb")), 3);
	TEST_CHECK_LEN(size, 0);

	TEST_MSG("Parse one k");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1k")), 2);
	TEST_CHECK_LEN(size, 1000ULL);

	TEST_MSG("Parse one K");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1K")), 2);
	TEST_CHECK_LEN(size, 1000ULL);

	TEST_MSG("Parse one KB");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1KB")), 3);
	TEST_CHECK_LEN(size, 1000ULL);

	TEST_MSG("Parse one kb");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1kb")), 3);
	TEST_CHECK_LEN(size, 1000ULL);

	TEST_MSG("Parse one mb");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1mb")), 3);
	TEST_CHECK_LEN(size, 1000ULL * 1000);

	TEST_MSG("Parse one gb");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1gb")), 3);
	TEST_CHECK_LEN(size, 1000ULL * 1000 * 1000);

	TEST_MSG("Parse one tb");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1tb")), 3);
	TEST_CHECK_LEN(size, 1000ULL * 1000 * 1000 * 1000);

#if SIZE_MAX > UINT32_MAX
	TEST_MSG("Parse one pb");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1pb")), 3);
	TEST_CHECK_LEN(size, 1000ULL * 1000 * 1000 * 1000 * 1000);

	TEST_MSG("Parse one eb");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("1eb")), 3);
	TEST_CHECK_LEN(size, 1000ULL * 1000 * 1000 * 1000 * 1000 * 1000);
#endif

	TEST_MSG("Overflow");
	TEST_CHECK_SLEN(fr_size_from_str(&size, test_str("100000000eb")), -1);
}

static void test_size_print_bytes(void)
{
	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1), 2);
	TEST_CHECK_STRCMP(buff, "1B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)2), 2);
	TEST_CHECK_STRCMP(buff, "2B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)3), 2);
	TEST_CHECK_STRCMP(buff, "3B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)4), 2);
	TEST_CHECK_STRCMP(buff, "4B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)5), 2);
	TEST_CHECK_STRCMP(buff, "5B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)6), 2);
	TEST_CHECK_STRCMP(buff, "6B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)7), 2);
	TEST_CHECK_STRCMP(buff, "7B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)8), 2);
	TEST_CHECK_STRCMP(buff, "8B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)9), 2);
	TEST_CHECK_STRCMP(buff, "9B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)10), 3);
	TEST_CHECK_STRCMP(buff, "10B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)100), 4);
	TEST_CHECK_STRCMP(buff, "100B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)999), 4);
	TEST_CHECK_STRCMP(buff, "999B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1001), 5);
	TEST_CHECK_STRCMP(buff, "1001B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1020), 5);
	TEST_CHECK_STRCMP(buff, "1020B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1021), 5);
	TEST_CHECK_STRCMP(buff, "1021B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1022), 5);
	TEST_CHECK_STRCMP(buff, "1022B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1023), 5);
	TEST_CHECK_STRCMP(buff, "1023B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1025), 5);
	TEST_CHECK_STRCMP(buff, "1025B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1026), 5);
	TEST_CHECK_STRCMP(buff, "1026B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1027), 5);
	TEST_CHECK_STRCMP(buff, "1027B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1028), 5);
	TEST_CHECK_STRCMP(buff, "1028B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1029), 5);
	TEST_CHECK_STRCMP(buff, "1029B");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1030), 5);
	TEST_CHECK_STRCMP(buff, "1030B");
}

static void test_size_print_base2(void)
{
	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1024), 4);
	TEST_CHECK_STRCMP(buff, "1KiB");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1024 * 1024), 4);
	TEST_CHECK_STRCMP(buff, "1MiB");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1024 * 1024 * 1024), 4);
	TEST_CHECK_STRCMP(buff, "1GiB");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1024 * 1024 * 1024 * 1024), 4);
	TEST_CHECK_STRCMP(buff, "1TiB");

#if SIZE_MAX > UINT32_MAX
	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1024 * 1024 * 1024 * 1024 * 1024), 4);
	TEST_CHECK_STRCMP(buff, "1PiB");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1024 * 1024 * 1024 * 1024 * 1024 * 1024), 4);
	TEST_CHECK_STRCMP(buff, "1EiB");
#endif

	TEST_MSG("Fall back to KiB");
	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), ((size_t)1024 * 1024 * 1024 * 1024) + 1024), 13);
	TEST_CHECK_STRCMP(buff, "1073741825KiB");

	TEST_MSG("Fall back to B");
	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), ((size_t)1024 * 1024 * 1024 * 1024) + 1025), 14);
	TEST_CHECK_STRCMP(buff, "1099511628801B");

	/* Regression - Was displayed as 524288KB because it took the base 10 path */
	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)524288000), 6);
	TEST_CHECK_STRCMP(buff, "500MiB");
}

static void test_size_print_base10(void)
{
	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1000), 3);
	TEST_CHECK_STRCMP(buff, "1KB");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1000 * 1000), 3);
	TEST_CHECK_STRCMP(buff, "1MB");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1000 * 1000 + 64000), 6);
	TEST_CHECK_STRCMP(buff, "1064KB");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1000 * 1000 * 1000), 3);
	TEST_CHECK_STRCMP(buff, "1GB");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1000 * 1000 * 1000 * 1000), 3);
	TEST_CHECK_STRCMP(buff, "1TB");

#if SIZE_MAX > UINT32_MAX
	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1000 * 1000 * 1000 * 1000 * 1000), 3);
	TEST_CHECK_STRCMP(buff, "1PB");

	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), (size_t)1000 * 1000 * 1000 * 1000 * 1000 * 1000), 3);
	TEST_CHECK_STRCMP(buff, "1EB");
#endif

	TEST_MSG("Fall back to KB");
	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), ((size_t)1000 * 1000 * 1000 * 1000) + 1000), 12);
	TEST_CHECK_STRCMP(buff, "1000000001KB");

	TEST_MSG("Fall back to B");
	TEST_CHECK_SLEN(fr_size_to_str(test_out(buff), ((size_t)1000 * 1000 * 1000 * 1000) + 1025), 14);
	TEST_CHECK_STRCMP(buff, "1000000001025B");
}

TEST_LIST = {
	/*
	 *	Allocation and management
	 */
	{ "parse_bytes",			test_size_parse_bytes },
	{ "parse_suffix_base2",			test_size_parse_suffix_base2 },
	{ "parse_suffix_base10",		test_size_parse_suffix_base10 },

	{ "print_bytes",			test_size_print_bytes },
	{ "print_base2",			test_size_print_base2 },
	{ "print_base10",			test_size_print_base10 },

	TEST_TERMINATOR
};
