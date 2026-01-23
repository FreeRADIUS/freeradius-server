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

/** Tests for a AVP manipulation and search API.
 *
 * @file src/lib/util/test//pair_legacy_tests.c
 * @author Jorge Pereira <jpereira@freeradius.org>
 * @copyright 2020 Network RADIUS SAS (legal@networkradius.com)
 */

/**
 *	The 'TEST_INIT' macro provided by 'acutest.h' allowing to register a function to be called
 *	before call the unit tests. Therefore, It calls the function ALL THE TIME causing an overhead.
 *	That is why we are initializing pair_tests_init() by "__attribute__((constructor));" reducing the
 *	test execution by 50% of the time.
 */
#define USE_CONSTRUCTOR

/*
 * It should be declared before include the "acutest.h"
 */
#ifdef USE_CONSTRUCTOR
static void test_init(void) __attribute__((constructor));
#else
static void test_init(void);
#  define TEST_INIT  test_init()
#endif

#include "acutest.h"
#include "acutest_helpers.h"
#include "pair_test_helpers.h"

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/pair_legacy.h>

#ifdef HAVE_GPERFTOOLS_PROFILER_H
#  include <gperftools/profiler.h>
#endif

static TALLOC_CTX       *autofree;
static fr_pair_list_t   test_pairs;
static fr_dict_t	*test_dict;


/** Global initialisation
 */
static void test_init(void)
{
	autofree = talloc_autofree_context();
	if (!autofree) {
	error:
		fr_perror("pair_tests");
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) goto error;

	if (fr_dict_test_init(autofree, &test_dict, NULL) < 0) goto error;

	/* Initialize the "test_pairs" list */
	fr_pair_list_init(&test_pairs);

	if (fr_pair_test_list_alloc(autofree, &test_pairs, NULL) < 0) goto error;
}

static void test_fr_pair_list_afrom_substr(void)
{
	fr_pair_t      *vp;
	ssize_t		len;
	fr_pair_list_t list;
	char const     *buffer = "Test-Uint32-0 = 123, Test-String-0 = \"Testing123\"";
	fr_pair_parse_t root, relative;

	root = (fr_pair_parse_t) {
		.ctx = autofree,
		.da = fr_dict_root(test_dict),
		.list = &list,
		.dict = test_dict,
		.internal = fr_dict_internal(),
	};
	relative = (fr_pair_parse_t) { };

	fr_pair_list_init(&list);
	len = strlen(buffer);

	TEST_CASE("Create 'vp' using fr_pair_list_afrom_substr()");
	TEST_CHECK(fr_pair_list_afrom_substr(&root, &relative, &FR_SBUFF_IN(buffer, len)) == len);

	TEST_CASE("Looking for Test-Uint32-0");
	TEST_CHECK((vp = fr_pair_find_by_da(&list, NULL, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Checking if (Test-Uint32-0 == 123)");
	TEST_CHECK(vp && vp->vp_uint32 == 123);

	TEST_CASE("Looking for Test-String-0");
	TEST_CHECK((vp = fr_pair_find_by_da(&list, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Checking if (Test-String-0 == 'Testing123')");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, "Testing123") == 0);

	fr_pair_list_free(&list);
}


static void test_fr_pair_list_afrom_substr_exec(void)
{
	fr_pair_t	*vp;
	ssize_t		len;
	fr_pair_list_t	list;
	ssize_t		slen;
	char const	*buffer = "Test-Uint32-0 = 123, Test-String-0 = `echo \"Testing321\"`";
	char const	*buffer_multi = "Test-String-0 = `echo \"Testing321\"`, Test-String-0 += 'Testing123'";
	fr_pair_parse_t	root, relative;

	root = (fr_pair_parse_t) {
		.ctx = autofree,
		.da = fr_dict_root(test_dict),
		.list = &list,
		.dict = test_dict,
		.internal = fr_dict_internal(),
		.allow_exec = true
	};
	relative = (fr_pair_parse_t) { };

	fr_pair_list_init(&list);
	len = strlen(buffer);

	TEST_CASE("Create 'vp' using fr_pair_list_afrom_substr()");
	slen = fr_pair_list_afrom_substr(&root, &relative, &FR_SBUFF_IN(buffer, len));
	TEST_CHECK_SLEN(slen, (ssize_t)len);
	TEST_MSG_FAIL("fr_pair_list_afrom_substr(): %s", fr_strerror());

	TEST_CASE("Looking for Test-Uint32-0");
	TEST_CHECK((vp = fr_pair_find_by_da(&list, NULL, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Checking if (Test-Uint32-0 == 123)");
	TEST_CHECK(vp && vp->vp_uint32 == 123);

	TEST_CASE("Looking for Test-String-0");
	TEST_CHECK((vp = fr_pair_find_by_da(&list, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_MSG_FAIL("Pair value was: %s", vp->vp_strvalue);
	TEST_CASE("Checking if (Test-String-0 == 'Testing321')");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, "Testing321") == 0);

	fr_pair_list_free(&list);

	len = strlen(buffer_multi);
	TEST_CASE("Create 'vp' using fr_pair_list_afrom_substr()");
	slen = fr_pair_list_afrom_substr(&root, &relative, &FR_SBUFF_IN(buffer_multi, len));
	TEST_CHECK_SLEN(slen, (ssize_t)len);
	TEST_MSG_FAIL("fr_pair_list_afrom_substr(): %s", fr_strerror());

	TEST_CASE("Looking for Test-String-0");
	TEST_CHECK((vp = fr_pair_find_by_da(&list, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_MSG_FAIL("Pair value was: %s", vp->vp_strvalue);
	TEST_CASE("Checking if (Test-String-0 == 'Testing321')");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, "Testing321") == 0);

	TEST_CASE("Looking for Test-String-0");
	TEST_CHECK((vp = fr_pair_find_by_da(&list, vp, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_MSG_FAIL("Pair value was: %s", vp->vp_strvalue);
	TEST_CASE("Checking if (Test-String-0 == 'Testing123')");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, "Testing123") == 0);

	fr_pair_list_free(&list);
}

static FILE *open_buffer_as_file(uint8_t const *buffer, size_t buffer_len)
{
	FILE *fp;
	uint8_t *our_buffer = UNCONST(uint8_t *, buffer);

	TEST_CHECK((fp = fmemopen(our_buffer, buffer_len, "r")) != NULL);

	fflush (fp);

	return fp;
}

static void test_fr_pair_list_afrom_file(void)
{
	fr_pair_t      *vp;
	fr_pair_list_t list;
	char const     *buffer = "Test-Uint32-0 = 123\nTest-String-0 = \"Testing123\"\n";
	FILE           *fp = open_buffer_as_file((uint8_t const *)buffer, strlen(buffer) + 1);
	bool           pfiledone;

	fr_pair_list_init(&list);

	TEST_CASE("Create 'vp' using fr_pair_list_afrom_file()");
	TEST_CHECK(fr_pair_list_afrom_file(autofree, test_dict, &list, fp, &pfiledone, false) == 0);

	TEST_CASE("Looking for Test-Uint32-0");
	TEST_CHECK((vp = fr_pair_find_by_da(&list, NULL, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Checking if (Test-Uint32-0 == 123)");
	TEST_CHECK(vp && vp->vp_uint32 == 123);

	TEST_CASE("Looking for Test-String-0");
	TEST_CHECK((vp = fr_pair_find_by_da(&list, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Checking if (Test-String-0 == 'Testing123')");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, "Testing123") == 0);

	fr_pair_list_free(&list);

	fclose(fp);
}

static void test_fr_pair_list_move_op(void)
{
	fr_pair_t      *vp;
	fr_pair_list_t old_list, new_list;
	bool           pfiledone;
	char const     *fake_file = "Test-Uint32-0 = 123\nTest-String-0 = \"Testing123\"\n";
	FILE           *fp = open_buffer_as_file((uint8_t const *)fake_file, strlen(fake_file) + 1);

	fr_pair_list_init(&old_list);
	fr_pair_list_init(&new_list);

	TEST_CASE("Create 'vp' using fr_pair_list_afrom_file()");
	TEST_CHECK(fr_pair_list_afrom_file(autofree, test_dict, &old_list, fp, &pfiledone, false) == 0);
	TEST_CHECK(pfiledone == true);

	TEST_CASE("Move pair from 'old_list' to 'new_list' using fr_pair_list_move_op()");
	fr_pair_list_move_op(&new_list, &old_list, T_OP_ADD_EQ);

	TEST_CASE("Looking for Test-Uint32-0");
	TEST_CHECK((vp = fr_pair_find_by_da(&new_list, NULL, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CHECK(vp != NULL);

	TEST_CASE("Checking if (Test-Uint32-0 == 123)");
	TEST_CHECK(vp && vp->vp_uint32 == 123);

	TEST_CASE("Looking for Test-String-0");
	TEST_CHECK((vp = fr_pair_find_by_da(&new_list, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CHECK(vp != NULL);

	TEST_CASE("Checking if (Test-String-0 == 'Testing123')");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, "Testing123") == 0);

	fr_pair_list_free(&new_list);

	fclose(fp);
}

TEST_LIST = {
	/*
	 *	Legacy calls
	 */
	{ "fr_pair_list_afrom_substr",  test_fr_pair_list_afrom_substr },
	{ "fr_pair_list_afrom_substr_exec", test_fr_pair_list_afrom_substr_exec },
	{ "fr_pair_list_afrom_file", test_fr_pair_list_afrom_file },
	{ "fr_pair_list_move_op",       test_fr_pair_list_move_op },

	TEST_TERMINATOR
};
