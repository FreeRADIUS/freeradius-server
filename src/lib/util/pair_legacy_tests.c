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
 * @file src/lib/util/pair_legacy_tests.c
 * @author Jorge Pereira <jpereira@freeradius.org>
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
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

#include <freeradius-devel/util/acutest.h>
#include <freeradius-devel/util/acutest_helpers.h>
#include <freeradius-devel/util/pair_test_helpers.h>

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

static void test_fr_pair_list_afrom_str(void)
{
	fr_pair_t      *vp;
	fr_pair_list_t list;
	char const     *buffer = "Test-Uint32-0 = 123, Test-String-0 = \"Testing123\"";

	fr_pair_list_init(&list);

	TEST_CASE("Create 'vp' using fr_pair_list_afrom_str()");
	TEST_CHECK(fr_pair_list_afrom_str(autofree, fr_dict_root(test_dict), buffer, strlen(buffer), &list) == T_EOL);

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

FILE *open_buffer_as_file(char const *buffer, size_t buffer_len);
FILE *open_buffer_as_file(char const *buffer, size_t buffer_len)
{
	FILE *fp;
	char *our_buffer;

	memcpy(&our_buffer, &buffer, sizeof(buffer));

	TEST_CHECK((fp = fmemopen(our_buffer, buffer_len, "r")) != NULL);

	fflush (fp);

	return fp;
}

static void test_fr_pair_list_afrom_file(void)
{
	fr_pair_t      *vp;
	fr_pair_list_t list;
	char const     *buffer = "Test-Uint32-0 = 123\nTest-String-0 = \"Testing123\"\n";
	/* coverity[alloc_strlen] */
	FILE           *fp = open_buffer_as_file(buffer, strlen(buffer));
	bool           pfiledone;

	fr_pair_list_init(&list);

	TEST_CASE("Create 'vp' using fr_pair_list_afrom_file()");
	TEST_CHECK(fr_pair_list_afrom_file(autofree, test_dict, &list, fp, &pfiledone) == 0);

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
	/* coverity[alloc_strlen] */
	FILE           *fp = open_buffer_as_file(fake_file, strlen(fake_file));

	fr_pair_list_init(&old_list);
	fr_pair_list_init(&new_list);

	TEST_CASE("Create 'vp' using fr_pair_list_afrom_file()");
	TEST_CHECK(fr_pair_list_afrom_file(autofree, test_dict, &old_list, fp, &pfiledone) == 0);
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

	fr_pair_list_free(&old_list);
	fr_pair_list_free(&new_list);

	fclose(fp);
}

TEST_LIST = {
	/*
	 *	Legacy calls
	 */
	{ "fr_pair_list_afrom_str",  test_fr_pair_list_afrom_str },
	{ "fr_pair_list_afrom_file", test_fr_pair_list_afrom_file },
	{ "fr_pair_list_move_op",       test_fr_pair_list_move_op },

	{ NULL }
};
