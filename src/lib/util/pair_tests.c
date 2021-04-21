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
 * @file src/lib/util/pair_tests.c
 * @author Jorge Pereira <jpereira@freeradius.org>
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */

/**
 *	The 'TEST_INIT' macro provided by 'acutest.h' allowing to register a function to be called
 *	before call the unit tests. Therefore, It calls the function ALL THE TIME causing an overhead.
 *	That is why we are initializing test_init() by "__attribute__((constructor));" reducing the
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
#	define TEST_INIT  test_init()
#endif

#include <freeradius-devel/util/acutest.h>
#include <freeradius-devel/util/acutest_helpers.h>
#include <freeradius-devel/util/pair_test_helpers.h>

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/dict_test.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/talloc.h>

#ifdef HAVE_GPERFTOOLS_PROFILER_H
#	include <gperftools/profiler.h>
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

/*
 *	Tests functions
 */
static void test_fr_pair_afrom_da(void)
{
	fr_pair_t *vp;

	TEST_CASE("Allocation using fr_pair_afrom_da");
	TEST_CHECK((vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string)) != NULL);

	TEST_CHECK(fr_pair_value_from_str(vp, test_string, strlen(test_string), '"', false) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CHECK(vp && strcmp(vp->vp_strvalue, test_string) == 0);
	TEST_MSG("Expected vp->vp_strvalue == test_string");

	talloc_free(vp);
}

static void test_fr_pair_afrom_child_num(void)
{
	fr_pair_t    *vp;
	unsigned int attr = FR_TEST_ATTR_STRING;

	TEST_CASE("Allocation using fr_pair_afrom_child_num");
	TEST_CHECK((vp = fr_pair_afrom_child_num(autofree, fr_dict_root(test_dict), attr)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CHECK(vp && vp->da->attr == FR_TEST_ATTR_STRING);
	TEST_MSG("Expected attr(%d) == vp->da->attr(%d)", attr, vp->da->attr);

	talloc_free(vp);
}

static void test_fr_pair_copy(void)
{
	fr_pair_t *vp, *copy;

	TEST_CASE("Allocation using fr_pair_copy");
	TEST_CHECK((vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	copy = fr_pair_copy(autofree, vp);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(copy);

	vp->op = T_OP_CMP_EQ;

	TEST_CASE("Compare fr_pair_cmp(copy == vp) should be TRUE");
	TEST_CHECK(fr_pair_cmp(vp, copy) == 1);

	talloc_free(vp);
	talloc_free(copy);
}

static void test_fr_pair_steal(void)
{
	fr_pair_t  *vp;
	TALLOC_CTX *ctx = talloc_null_ctx();

	TEST_CASE("Allocate a new attribute fr_pair_afrom_da");
	TEST_CHECK((vp = fr_pair_afrom_da(ctx, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Stealing 'vp' pair using fr_pair_steal()");
	fr_pair_steal(autofree, vp); /* It should exit without memory-leaks */

	TEST_CASE("Checking if talloc_parent(vp) == autofree");
	TEST_CHECK(talloc_parent(vp) == autofree);
}

static void test_fr_pair_to_unknown(void)
{
	fr_pair_t *vp;

	TEST_CASE("Allocate a new attribute fr_pair_afrom_da");
	TEST_CHECK((vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Converting regular 'vp' as unkown");
	TEST_CHECK(fr_pair_to_unknown(vp) == 0);

	TEST_CASE("Checking if a real 'unkown' vp");
	TEST_CHECK(vp && vp->da->flags.is_unknown == true);
}

static void test_fr_dcursor_iter_by_da_init(void)
{
	fr_pair_t   *vp, *needle;
	fr_dcursor_t	cursor;

	TEST_CASE("Searching for fr_dict_attr_test_uint32 using fr_dcursor_iter_by_da_init()");
	needle = NULL;
	for (vp = fr_dcursor_iter_by_da_init(&cursor, &test_pairs, fr_dict_attr_test_uint32);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
		if (!needle) {
			needle = vp;
			continue;
		}
		TEST_CHECK(1 == 1); /* this never will be reached */
	}

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(needle);

	TEST_CASE("Expected (needle->da == fr_dict_attr_test_uint32)");
	TEST_CHECK(needle && needle->da == fr_dict_attr_test_uint32);
}

static void test_fr_dcursor_iter_by_ancestor_init(void)
{
	fr_pair_t   *vp, *needle;
	fr_dcursor_t	cursor;

	TEST_CASE("Searching for fr_dict_attr_test_tlv_string as ascend of fr_dict_attr_test_tlv using fr_dcursor_iter_by_ancestor_init()");
	needle = NULL;
	for (vp = fr_dcursor_iter_by_ancestor_init(&cursor, &test_pairs, fr_dict_attr_test_tlv);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
		TEST_CHECK(vp != NULL);
		if (vp->da == fr_dict_attr_test_tlv_string) {
			needle = vp;
			continue;
		}
	}

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(needle);

	TEST_CASE("Expected (needle->da == fr_dict_attr_test_tlv_string)");
	TEST_CHECK(needle && needle->da == fr_dict_attr_test_tlv_string);
}

static void test_fr_pair_find_by_da(void)
{
	fr_pair_t *vp;

	TEST_CASE("Search for fr_dict_attr_test_tlv_string using fr_pair_find_by_da()");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_tlv_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Expected (vp->da == fr_dict_attr_test_tlv_string)");
	TEST_CHECK(vp && vp->da == fr_dict_attr_test_tlv_string);
}

static void test_fr_pair_find_by_child_num(void)
{
	fr_pair_t *vp;

	TEST_CASE("Search for FR_TEST_ATTR_STRING using fr_pair_find_by_child_num()");
	TEST_CHECK((vp = fr_pair_find_by_child_num(&test_pairs, fr_dict_root(test_dict), FR_TEST_ATTR_STRING)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Expected (vp->da == fr_dict_attr_test_string)");
	TEST_CHECK(vp && vp->da == fr_dict_attr_test_string);
}

static void test_fr_pair_append(void)
{
	fr_dcursor_t   cursor;
	fr_pair_t      *vp;
	fr_pair_list_t	local_pairs;
	size_t         count = 0;

	TEST_CASE("Add 3 pairs using fr_pair_append()");

	fr_pair_list_init(&local_pairs);

	fr_pair_append(&local_pairs, fr_pair_afrom_da(autofree, fr_dict_attr_test_octets));
	fr_pair_append(&local_pairs, fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32));
	fr_pair_append(&local_pairs, fr_pair_afrom_da(autofree, fr_dict_attr_test_tlv));

	/* lets' count */
	for (vp = fr_dcursor_init(&cursor, &local_pairs);
		 vp;
		 vp = fr_dcursor_next(&cursor)) count++;

	TEST_CASE("Expected (count == 3)");
	TEST_CHECK(count == 3);

	fr_pair_list_free(&local_pairs);
}

static void test_fr_pair_delete_by_child_num(void)
{
	TEST_CASE("Delete fr_dict_attr_test_string using fr_pair_delete_by_child_num()");
	fr_pair_delete_by_child_num(&test_pairs, fr_dict_root(test_dict), FR_TEST_ATTR_STRING);

	TEST_CASE("The fr_dict_attr_test_string shouldn't exist in 'test_pairs'");
	TEST_CHECK(fr_pair_find_by_child_num(&test_pairs, fr_dict_root(test_dict), FR_TEST_ATTR_STRING) == NULL);

	TEST_CASE("Add fr_dict_attr_test_string back into 'test_pairs'");
	TEST_CHECK(fr_pair_prepend_by_da(autofree, NULL, &test_pairs, fr_dict_attr_test_string) == 0);
}

static void test_fr_pair_prepend_by_da(void)
{
	fr_dcursor_t   cursor;
	fr_pair_t      *vp;
	fr_pair_list_t	local_pairs;
	TALLOC_CTX     *ctx = talloc_null_ctx();

	fr_pair_list_init(&local_pairs);

	TEST_CASE("Add using fr_pair_prepend_by_da()");
	TEST_CHECK(fr_pair_prepend_by_da(ctx, NULL, &local_pairs, fr_dict_attr_test_string) == 0);

	/* lets' count */
	for (vp = fr_dcursor_init(&cursor, &local_pairs);
		 vp;
		 vp = fr_dcursor_next(&cursor)) {
		TEST_CASE("Expected (vp->da == fr_dict_attr_test_string)");
		TEST_CHECK(vp->da == fr_dict_attr_test_string);
	}

	fr_pair_list_free(&local_pairs);
}

static void test_fr_pair_update_by_da(void)
{
	fr_pair_t *vp;

	TEST_CASE("Update Add using fr_pair_prepend_by_da()");
	TEST_CHECK(fr_pair_update_by_da(autofree, &vp, &test_pairs, fr_dict_attr_test_uint32) == 1); /* attribute already exist */
	vp->vp_uint32 = 54321;

	TEST_CASE("Expected fr_dict_attr_test_uint32 (vp->vp_uint32 == 54321)");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Expected (vp == 54321)");
	TEST_CHECK(vp && vp->vp_uint32 == 54321);
}

static void test_fr_pair_delete_by_da(void)
{
	TEST_CASE("Delete fr_dict_attr_test_string using fr_pair_delete_by_da()");
	TEST_CHECK(fr_pair_delete_by_da(&test_pairs, fr_dict_attr_test_string) == 1);

	TEST_CASE("The fr_dict_attr_test_string shouldn't exist in 'test_pairs'");
	TEST_CHECK(fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_string) == NULL);

	TEST_CASE("Add fr_dict_attr_test_string back into 'test_pairs'");
	TEST_CHECK(fr_pair_prepend_by_da(autofree, NULL, &test_pairs, fr_dict_attr_test_string) == 0);
}

static void test_fr_pair_delete(void)
{
	fr_pair_t *vp;

	TEST_CASE("Delete fr_dict_attr_test_string using fr_pair_delete()");
	TEST_CHECK((vp = fr_pair_find_by_child_num(&test_pairs, fr_dict_root(test_dict), FR_TEST_ATTR_STRING)) != NULL);
	fr_pair_delete(&test_pairs, vp);

	TEST_CASE("The fr_dict_attr_test_string shouldn't exist in 'test_pairs'");
	TEST_CHECK((vp = fr_pair_find_by_child_num(&test_pairs, fr_dict_root(test_dict), FR_TEST_ATTR_STRING)) == NULL);

	TEST_CASE("Add fr_dict_attr_test_string back into 'test_pairs'");
	TEST_CHECK(fr_pair_prepend_by_da(autofree, NULL, &test_pairs, fr_dict_attr_test_string) == 0);
}

static void test_fr_pair_cmp(void)
{
	fr_pair_t *vp1, *vp2;

	TEST_CASE("Create the vp1 'Test-Integer = 123'");
	TEST_CHECK((vp1 = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp1);

	vp1->op = T_OP_EQ;
	vp1->vp_uint32 = 123;

	TEST_CASE("Create the vp2 'Test-Integer = 321'");
	TEST_CHECK((vp2 = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp2);

	vp2->op = T_OP_CMP_EQ;
	vp2->vp_uint32 = 321;

	TEST_CASE("Compare fr_pair_cmp(vp1 == vp2) should be FALSE");
	TEST_CHECK(fr_pair_cmp(vp1, vp2) == 0);
}

static void test_fr_pair_list_cmp(void)
{
	fr_pair_list_t local_pairs1, local_pairs2;

	fr_pair_list_init(&local_pairs1);
	fr_pair_list_init(&local_pairs2);

	TEST_CASE("Create 'local_pairs1'");
	TEST_CHECK(fr_pair_test_list_alloc(autofree, &local_pairs1, NULL) == 0);

	TEST_CASE("Create 'local_pairs2'");
	TEST_CHECK(fr_pair_test_list_alloc(autofree, &local_pairs2, NULL) == 0);

	TEST_CASE("Check if 'local_pairs1' == 'local_pairs2' using fr_pair_list_cmp()");
	TEST_CHECK(fr_pair_list_cmp(&local_pairs1, &local_pairs2) == 0);

	fr_pair_list_free(&local_pairs1);
	fr_pair_list_free(&local_pairs2);
}

static void test_fr_pair_list_copy(void)
{
	fr_pair_list_t local_pairs;

	fr_pair_list_init(&local_pairs);

	TEST_CASE("Copy 'test_pairs' into 'local_pairs'");
	TEST_CHECK(fr_pair_list_copy(autofree, &local_pairs, &test_pairs) > 0);

	TEST_CASE("Check if 'local_pairs' == 'test_pairs' using fr_pair_list_cmp()");
	TEST_CHECK(fr_pair_list_cmp(&local_pairs, &test_pairs) == 0);

	fr_pair_list_free(&local_pairs);
}

static void test_fr_pair_list_copy_by_da(void)
{
	fr_dcursor_t   cursor;
	fr_pair_t      *vp;
	fr_pair_list_t	local_pairs;

	fr_pair_list_init(&local_pairs);

	TEST_CASE("Copy 'test_pairs' into 'local_pairs'");
	TEST_CHECK(fr_pair_list_copy_by_da(autofree, &local_pairs, &test_pairs, fr_dict_attr_test_string, 0) > 0);

	TEST_CASE("The 'local_pairs' should have only fr_dict_attr_test_string");
	for (vp = fr_dcursor_init(&cursor, &local_pairs);
		 vp;
		 vp = fr_dcursor_next(&cursor)) {
		TEST_CASE("Validating VP_VERIFY()");
		VP_VERIFY(vp);

		TEST_CASE("Expected (vp->da == fr_dict_attr_test_string)");
		TEST_CHECK(vp->da == fr_dict_attr_test_string);
	}

	fr_pair_list_free(&local_pairs);
}

static void test_fr_pair_list_copy_by_ancestor(void)
{
	fr_dcursor_t   cursor;
	fr_pair_t      *vp, *needle = NULL;
	fr_pair_list_t	local_pairs;

	fr_pair_list_init(&local_pairs);

	TEST_CASE("Copy 'test_pairs' into 'local_pairs'");
	TEST_CHECK(fr_pair_list_copy_by_ancestor(autofree, &local_pairs, &test_pairs, fr_dict_attr_test_tlv, 0) > 0);

	TEST_CASE("The 'local_pairs' should have only fr_dict_attr_test_tlv_string (ancestor of 'Test-TLV-Root'");
	for (vp = fr_dcursor_init(&cursor, &local_pairs);
		 vp;
		 vp = fr_dcursor_next(&cursor)) {
		TEST_CASE("Validating VP_VERIFY()");
		VP_VERIFY(vp);

		if (vp->da == fr_dict_attr_test_tlv_string) {
			needle = vp;
			break;
		}
	}

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(needle);

	TEST_CASE("Expected (needle->da == fr_dict_attr_test_tlv_string)");
	TEST_CHECK(needle && needle->da == fr_dict_attr_test_tlv_string);

	fr_pair_list_free(&local_pairs);
}

static void test_fr_pair_list_sort(void)
{
	fr_dcursor_t	cursor;
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	TALLOC_CTX	*ctx = talloc_null_ctx();

	TEST_CASE("Create 'local_pairs' with 3 attributes not ordered");
	fr_pair_list_init(&local_pairs);

	TEST_CASE("Add fr_dict_attr_test_string back into 'local_pairs'");
	TEST_CHECK(fr_pair_prepend_by_da(ctx, NULL, &local_pairs, fr_dict_attr_test_date) == 0);
	TEST_CHECK(fr_pair_prepend_by_da(ctx, NULL, &local_pairs, fr_dict_attr_test_ipv4_addr) == 0);
	TEST_CHECK(fr_pair_prepend_by_da(ctx, NULL, &local_pairs, fr_dict_attr_test_octets) == 0);
	TEST_CHECK(fr_pair_prepend_by_da(ctx, NULL, &local_pairs, fr_dict_attr_test_uint32) == 0);
	TEST_CHECK(fr_pair_prepend_by_da(ctx, NULL, &local_pairs, fr_dict_attr_test_enum) == 0); // It will be go to the tail
	TEST_CHECK(fr_pair_prepend_by_da(ctx, NULL, &local_pairs, fr_dict_attr_test_string) == 0);

	/*
	 *	FIXME - This test doesn't check for intra-type stability
	 */
	TEST_CASE("Sorting 'local_pairs' by fr_pair_list_sort(local_pairs, fr_pair_cmp_by_da)");
	fr_pair_list_sort(&local_pairs, fr_pair_cmp_by_da);

	TEST_CASE("1st (da == fr_dict_attr_test_string)");
	TEST_CHECK((vp = fr_dcursor_init(&cursor, &local_pairs)) != NULL);
	TEST_CHECK(vp && vp->da == fr_dict_attr_test_string);

	TEST_CASE("2nd (da == fr_dict_attr_test_octets)");
	TEST_CHECK((vp = fr_dcursor_next(&cursor)) != NULL);
	TEST_CHECK(vp && vp->da == fr_dict_attr_test_octets);

	TEST_CASE("3rd (da == fr_dict_attr_test_ipv4_addr)");
	TEST_CHECK((vp = fr_dcursor_next(&cursor)) != NULL);
	TEST_CHECK(vp && vp->da == fr_dict_attr_test_ipv4_addr);

	TEST_CASE("4th (da == fr_dict_attr_test_uint32)");
	TEST_CHECK((vp = fr_dcursor_next(&cursor)) != NULL);
	TEST_CHECK(vp && vp->da == fr_dict_attr_test_uint32);

	TEST_CASE("5th (da == fr_dict_attr_test_date)");
	TEST_CHECK((vp = fr_dcursor_next(&cursor)) != NULL);
	TEST_CHECK(vp && vp->da == fr_dict_attr_test_date);

	TEST_CASE("6th (da == fr_dict_attr_test_enum)");
	TEST_CHECK((vp = fr_dcursor_next(&cursor)) != NULL);
	TEST_CHECK(vp && vp->da == fr_dict_attr_test_enum);

	fr_pair_list_free(&local_pairs);
}

static void test_fr_pair_value_copy(void)
{
	fr_pair_t *vp1, vp2;

	TEST_CASE("Create 'vp1' with Test-Integer = 123");
	TEST_CHECK((vp1 = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp1);

	vp1->vp_uint32 = 123;

	TEST_CASE("Copy 'vp1' to 'vp2' using fr_pair_value_copy()");
	TEST_CHECK(fr_pair_value_copy(&vp2, vp1) == 0);

	TEST_CASE("Check (vp1 == vp2)");
	TEST_CHECK(vp2.vp_uint32 == 123);
}

static void test_fr_pair_value_from_str(void)
{
	fr_pair_t *vp;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Convert 'test_string' value to attribute value using fr_pair_value_from_str()");
	TEST_CHECK(fr_pair_value_from_str(vp, test_string, strlen(test_string), '"', false) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Check (vp->vp_string == test_string)");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, test_string) == 0);
}

static void test_fr_pair_value_strdup(void)
{
	fr_pair_t *vp;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Copy content of 'test_string' to attribute value using fr_pair_value_strdup()");
	TEST_CHECK(fr_pair_value_strdup(vp, test_string) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Check (vp->vp_string == test_string)");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, test_string) == 0);
}

static void test_fr_pair_value_strdup_shallow(void)
{
	fr_pair_t *vp;
	char      *copy_test_string;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

 	copy_test_string = talloc_strdup(vp, test_string);
	talloc_set_type(copy_test_string, char);

	TEST_CASE("Copy content of 'test_string' to attribute value using fr_pair_value_strdup_shallow()");
	TEST_CHECK(fr_pair_value_strdup_shallow(vp, copy_test_string, true) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Check (vp->vp_string == copy_test_string)");
	TEST_CHECK(vp && strncmp(vp->vp_strvalue, test_string, strlen(copy_test_string)) == 0);

	talloc_free(copy_test_string);
}

static void test_fr_pair_value_strtrim(void)
{
	fr_pair_t *vp;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Copy content of 'test_string' to attribute value using fr_pair_value_strdup_shallow()");
	TEST_CHECK(fr_pair_value_strdup(vp, test_string) == 0);

	TEST_CASE("Trim the length of the string buffer using fr_pair_value_strtrim()");
	TEST_CHECK(fr_pair_value_strtrim(vp) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Check (vp->vp_string == test_string)");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, test_string) == 0);
}

static void test_fr_pair_value_aprintf(void)
{
	fr_pair_t *vp;
	char      fmt_test[64];
	fr_time_t now = fr_time();

	snprintf(fmt_test, sizeof(fmt_test), "Now is %ld", (long)now);

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Copy content of 'fmt_test' to attribute value using fr_pair_value_aprintf()");
	TEST_CHECK(fr_pair_value_aprintf(vp, "Now is %ld", (long)now) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Check (vp->vp_string == fmt_test)");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, fmt_test) == 0);
}

static void test_fr_pair_value_bstr_alloc(void)
{
	fr_pair_t *vp;
	char      *out = NULL;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Pre-allocate a memory buffer using fr_pair_value_bstr_alloc()");
	TEST_CHECK(fr_pair_value_bstr_alloc(vp, &out, test_string_len, false) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Copy 'test_string' to the pre-allocated pointer");
	TEST_CHECK(strlcpy(out, test_string, test_string_len) == test_string_len);

	TEST_CASE("Check (out == test_string)");
	TEST_CHECK(memcmp(out, test_string, test_string_len-1) == 0);

	TEST_CASE("Check (vp->vp_string == test_string)");
	TEST_CHECK(vp && memcmp(vp->vp_strvalue, test_string, test_string_len-1) == 0);
}

static void test_fr_pair_value_bstr_realloc(void)
{
	fr_pair_t *vp;
	char      *out = NULL;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Pre-allocate 1 byte of memory buffer using fr_pair_value_bstr_alloc()");
	TEST_CHECK(fr_pair_value_bstr_alloc(vp, &out, 1, false) == 0);

	TEST_CASE("Re-allocate (test_string_len-1) byte of memory buffer using fr_pair_value_bstr_realloc()");
	TEST_CHECK(fr_pair_value_bstr_realloc(vp, &out, (test_string_len - 1)) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Copy 'test_string' to the pre-allocated pointer");
	TEST_CHECK(strlcpy(out, test_string, test_string_len) == test_string_len);

	TEST_CASE("Check (out == test_string)");
	TEST_CHECK(memcmp(out, test_string, test_string_len-1) == 0);

	TEST_CASE("Check (vp->vp_string == test_string)");
	TEST_CHECK(vp && memcmp(vp->vp_strvalue, test_string, test_string_len-1) == 0);
}

static void test_fr_pair_value_bstrndup(void)
{
	fr_pair_t *vp;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Copy content of 'test_string' to attribute value using fr_pair_value_bstrndup()");
	TEST_CHECK(fr_pair_value_bstrndup(vp, test_string, test_string_len-1, false) == 0);

	TEST_CASE("Check (vp->vp_string == test_string)");
	TEST_CHECK(vp && memcmp(vp->vp_strvalue, test_string, test_string_len-1) == 0);
}

static void test_fr_pair_value_bstrdup_buffer(void)
{
	fr_pair_t *vp;
	char      *copy_test_string;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	copy_test_string = talloc_strdup(vp, test_string);
	talloc_set_type(copy_test_string, char);

	TEST_CASE("Copy content of 'copy_test_string' to attribute value using fr_pair_value_bstrdup_buffer()");
	TEST_CHECK(fr_pair_value_bstrdup_buffer(vp, copy_test_string, false) == 0);

	TEST_CASE("Check (vp->vp_string == test_string)");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, copy_test_string) == 0);

	talloc_free(copy_test_string);
}

static void test_fr_pair_value_bstrndup_shallow(void)
{
	fr_pair_t *vp;
	char      *copy_test_string;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	copy_test_string = talloc_strdup(vp, test_string);
	talloc_set_type(copy_test_string, char);

	TEST_CASE("Copy content of 'test_string' to attribute value using fr_pair_value_bstrndup_shallow()");
	TEST_CHECK(fr_pair_value_bstrndup_shallow(vp, copy_test_string, strlen(copy_test_string), true) == 0);

	TEST_CASE("Check (vp->vp_string == copy_test_string)");
	TEST_CHECK(vp && strncmp(vp->vp_strvalue, test_string, test_string_len) == 0);

	talloc_free(copy_test_string);
}

static void test_fr_pair_value_bstrdup_buffer_shallow(void)
{
	fr_pair_t *vp;
	char      *copy_test_string;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

 	copy_test_string = talloc_strdup(vp, test_string);
	talloc_set_type(copy_test_string, char);

	TEST_CASE("Copy content of 'test_string' to attribute value using fr_pair_value_bstrdup_buffer_shallow()");
	TEST_CHECK(fr_pair_value_bstrdup_buffer_shallow(vp, copy_test_string, true) == 0);

	TEST_CASE("Check (vp->vp_string == copy_test_string)");
	TEST_CHECK(vp && strncmp(vp->vp_strvalue, test_string, test_string_len) == 0);

	talloc_free(copy_test_string);
}

static void test_fr_pair_value_bstrn_append(void)
{
	fr_pair_t *vp;
	char      *copy_test_string;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

 	copy_test_string = talloc_strdup(vp, test_string);
	talloc_set_type(copy_test_string, char);

	TEST_CASE("Copy content of 'test_string' to attribute value using fr_pair_value_bstrndup()");
	TEST_CHECK(fr_pair_value_bstrndup(vp, test_string, test_string_len, false) == 0);

	TEST_CASE("Append the 'copy_test_string' value using fr_pair_value_bstrn_append()");
	TEST_CHECK(fr_pair_value_bstrn_append(vp, copy_test_string, test_string_len, true) == 0);

	// awful hack, just verify the first part of buffer and then the second part. yep, just appended twice.
	TEST_CASE("Check 1. part (vp->vp_string == test_string)");
	TEST_CHECK(vp && strncmp(vp->vp_strvalue, test_string, test_string_len) == 0);

	TEST_CASE("Check 2. part ((vp->vp_string+test_string_len) == test_string)");
	TEST_CHECK(vp && strncmp(vp->vp_strvalue+test_string_len, test_string, test_string_len) == 0);

	talloc_free(copy_test_string);
}

static void test_fr_pair_value_bstr_append_buffer(void)
{
	fr_pair_t *vp;
	char      *copy_test_string;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

 	copy_test_string = talloc_strdup(vp, test_string);
	talloc_set_type(copy_test_string, char);

	TEST_CASE("Copy content of 'test_string' to attribute value using fr_pair_value_bstrndup()");
	TEST_CHECK(fr_pair_value_bstrndup(vp, test_string, test_string_len, false) == 0);

	TEST_CASE("Append the 'copy_test_string' value using fr_pair_value_bstr_append_buffer()");
	TEST_CHECK(fr_pair_value_bstr_append_buffer(vp, copy_test_string, true) == 0);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	// awful hack, just verify the first part of buffer and then the second part. yep, just appended twice.
	TEST_CASE("Check 1. part (vp->vp_string == test_string)");
	TEST_CHECK(vp && strncmp(vp->vp_strvalue, test_string, test_string_len) == 0);

	TEST_CASE("Check 2. part ((vp->vp_string+test_string_len) == test_string)");
	TEST_CHECK(vp && strncmp(vp->vp_strvalue+test_string_len, test_string, test_string_len) == 0);

	talloc_free(copy_test_string);
}

static void test_fr_pair_value_mem_alloc(void)
{
	fr_pair_t *vp;
	uint8_t   *out;

	TEST_CASE("Find 'Test-Octets'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Pre-allocate a memory buffer using fr_pair_value_bstr_alloc()");
	TEST_CHECK(fr_pair_value_mem_alloc(vp, &out, NUM_ELEMENTS(test_octets), false) == 0);

	TEST_CASE("Copy 'test_octets' to the pre-allocated pointer");
	TEST_CHECK(memcpy(out, test_octets, NUM_ELEMENTS(test_octets)) != NULL);

	TEST_CASE("Check (out == test_octets)");
	TEST_CHECK(memcmp(out, test_octets, NUM_ELEMENTS(test_octets)) == 0);

	TEST_CASE("Check (vp->vp_octets == test_octets)");
	TEST_CHECK(vp && memcmp(vp->vp_octets, test_octets, NUM_ELEMENTS(test_octets)) == 0);
}

static void test_fr_pair_value_mem_realloc(void)
{
	fr_pair_t *vp;
	uint8_t   *out;

	TEST_CASE("Find 'Test-Octets'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Pre-allocate a memory buffer using fr_pair_value_bstr_alloc()");
	TEST_CHECK(fr_pair_value_mem_alloc(vp, &out, NUM_ELEMENTS(test_octets), false) == 0);

	TEST_CASE("Copy 'test_octets' to the pre-allocated pointer");
	TEST_CHECK(memcpy(out, test_octets, NUM_ELEMENTS(test_octets)) != NULL);

	TEST_CASE("Realloc pre-allocated pointer to fit extra 'test_octets' copy");
	TEST_CHECK(fr_pair_value_mem_realloc(vp, &out, NUM_ELEMENTS(test_octets)*2) == 0);

	TEST_CASE("Copy 'test_octets' into the tail");
	TEST_CHECK(memcpy(out+NUM_ELEMENTS(test_octets), test_octets, NUM_ELEMENTS(test_octets)) != NULL);

	TEST_CASE("Check first chunk (out == test_octets)");
	TEST_CHECK(memcmp(out, test_octets, NUM_ELEMENTS(test_octets)) == 0);

	TEST_CHECK(vp != NULL);

	TEST_CASE("Check first chunk (vp->vp_octets == test_octets)");
	TEST_CHECK(vp && memcmp(vp->vp_octets, test_octets, NUM_ELEMENTS(test_octets)) == 0);

	TEST_CASE("Check second chunk (out+NUM_ELEMENTS(test_octets) == test_octets)");
	TEST_CHECK(memcmp(out+NUM_ELEMENTS(test_octets), test_octets, NUM_ELEMENTS(test_octets)) == 0);

	TEST_CASE("Check second chunk (vp->vp_octets+NUM_ELEMENTS(test_octets) == test_octets)");
	TEST_CHECK(vp && memcmp(vp->vp_octets+NUM_ELEMENTS(test_octets), test_octets, NUM_ELEMENTS(test_octets)) == 0);
}

static void test_fr_pair_value_memdup(void)
{
	fr_pair_t *vp;

	TEST_CASE("Find 'Test-Octets'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Copy content of 'test_octets' to attribute value using fr_pair_value_memdup()");
	TEST_CHECK(fr_pair_value_memdup(vp, test_octets, NUM_ELEMENTS(test_octets), false) == 0);

	TEST_CASE("Check (vp->vp_octets == test_octets)");
	TEST_CHECK(vp && memcmp(vp->vp_octets, test_octets, NUM_ELEMENTS(test_octets)) == 0);
}

static void test_fr_pair_value_memdup_buffer(void)
{
	fr_pair_t *vp;
	uint8_t   *copy_test_octets;

	TEST_CASE("Find 'Test-Octets'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	copy_test_octets = talloc_memdup(vp, test_octets, NUM_ELEMENTS(test_octets));
	talloc_set_type(copy_test_octets, uint8_t);

	TEST_CASE("Copy content of 'test_octets' to attribute value using fr_pair_value_memdup_buffer()");
	TEST_CHECK(fr_pair_value_memdup_buffer(vp, copy_test_octets, true) == 0);

	TEST_CASE("Check (vp->vp_octets == test_octets)");
	TEST_CHECK(vp && memcmp(vp->vp_octets, test_octets, NUM_ELEMENTS(test_octets)) == 0);

	talloc_free(copy_test_octets);
}

static void test_fr_pair_value_memdup_shallow(void)
{
	fr_pair_t *vp;
	uint8_t   *copy_test_octets;

	TEST_CASE("Find 'Test-Octets'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	copy_test_octets = talloc_memdup(vp, test_octets, NUM_ELEMENTS(test_octets));
	talloc_set_type(copy_test_octets, uint8_t);

	TEST_CASE("Copy content of 'test_octets' to attribute value using fr_pair_value_memdup_shallow()");
	TEST_CHECK(fr_pair_value_memdup_shallow(vp, copy_test_octets, NUM_ELEMENTS(test_octets), true) == 0);

	TEST_CASE("Check (vp->vp_octets == test_octets)");
	TEST_CHECK(vp && memcmp(vp->vp_octets, test_octets, NUM_ELEMENTS(test_octets)) == 0);

	talloc_free(copy_test_octets);
}

static void test_fr_pair_value_memdup_buffer_shallow(void)
{
	fr_pair_t *vp;
	uint8_t   *copy_test_octets;

	TEST_CASE("Find 'Test-Octets'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	copy_test_octets = talloc_memdup(vp, test_octets, NUM_ELEMENTS(test_octets));
	talloc_set_type(copy_test_octets, uint8_t);

	TEST_CASE("Copy content of 'test_octets' to attribute value using fr_pair_value_memdup_buffer_shallow()");
	TEST_CHECK(fr_pair_value_memdup_buffer_shallow(vp, copy_test_octets, true) == 0);

	TEST_CASE("Check (vp->vp_octets == copy_test_octets)");
	TEST_CHECK(vp && memcmp(vp->vp_octets, test_octets, NUM_ELEMENTS(test_octets)) == 0);

	talloc_free(copy_test_octets);
}

static void test_fr_pair_value_mem_append(void)
{
	fr_pair_t *vp;

	TEST_CASE("Find 'Test-Octets'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	TEST_CASE("Copy content of 'test_octets' to attribute value using fr_pair_value_memdup()");
	TEST_CHECK(fr_pair_value_memdup(vp, test_octets, NUM_ELEMENTS(test_octets), false) == 0);

	TEST_CASE("Append the 'test_octets' value using fr_pair_value_mem_append()");
	TEST_CHECK(fr_pair_value_mem_append(vp, test_octets, NUM_ELEMENTS(test_octets), true) == 0);

	// awful hack, just verify the first part of buffer and then the second part. yep, just appended twice.
	TEST_CASE("Check 1. part (vp->vp_octets == test_octets)");
	TEST_CHECK(vp && memcmp(vp->vp_octets, test_octets, NUM_ELEMENTS(test_octets)) == 0);

	TEST_CASE("Check 2. part ((vp->vp_string+NUM_ELEMENTS(test_octets)) == test_octets)");
	TEST_CHECK(vp && memcmp(vp->vp_octets+NUM_ELEMENTS(test_octets), test_octets, NUM_ELEMENTS(test_octets)) == 0);
}

static void test_fr_pair_value_mem_append_buffer(void)
{
	fr_pair_t *vp;
	uint8_t   *copy_test_octets;

	TEST_CASE("Find 'Test-Octets'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	copy_test_octets = talloc_memdup(vp, test_octets, NUM_ELEMENTS(test_octets));
	talloc_set_type(copy_test_octets, uint8_t);

	TEST_CASE("Copy content of 'copy_test_octets' to attribute value using fr_pair_value_memdup()");
	TEST_CHECK(fr_pair_value_memdup(vp, copy_test_octets, NUM_ELEMENTS(test_octets), false) == 0);

	TEST_CASE("Append the 'copy_test_octets' value using fr_pair_value_mem_append_buffer()");
	TEST_CHECK(fr_pair_value_mem_append_buffer(vp, copy_test_octets, true) == 0);

	// awful hack, just verify the first part of buffer and then the second part. yep, just appended twice.
	TEST_CASE("Check 1. part (vp->vp_octets == test_octets)");
	TEST_CHECK(vp && memcmp(vp->vp_octets, test_octets, NUM_ELEMENTS(test_octets)) == 0);

	TEST_CASE("Check 2. part ((vp->vp_string+NUM_ELEMENTS(test_octets)) == test_octets)");
	TEST_CHECK(vp && memcmp(vp->vp_octets+NUM_ELEMENTS(test_octets), test_octets, NUM_ELEMENTS(test_octets)) == 0);

	talloc_free(copy_test_octets);
}

static void test_fr_pair_value_enum(void)
{
	fr_pair_t   *vp;
	char const  *var;
	char        buf[20];

	TEST_CASE("Find 'Test-Values'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_enum)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	vp->vp_uint32 = 123;

	TEST_CASE("Lookup enum value attribute using fr_pair_value_enum()");

	TEST_CHECK((var = fr_pair_value_enum(vp, buf)) != NULL);
	TEST_MSG("Checking fr_pair_value_enum()");

	TEST_CHECK(var && strcmp(var, "test123") == 0);
	TEST_MSG("Expected var == 'test123'");
}

static void test_fr_pair_value_enum_box(void)
{
	fr_pair_t            *vp;
	fr_value_box_t const *vb;

	TEST_CASE("Find 'Test-Values'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, fr_dict_attr_test_enum)) != NULL);

	TEST_CASE("Validating VP_VERIFY()");
	VP_VERIFY(vp);

	vp->vp_uint32 = 123;

	TEST_CASE("Lookup enum value attribute using fr_pair_value_enum_box()");

	TEST_CHECK(fr_pair_value_enum_box(&vb, vp) >= 0);
	TEST_MSG("Checking fr_pair_value_enum()");

	TEST_CHECK(vb->vb_uint32 == 123);
	TEST_MSG("Expected vb->vb_uint32 == 123");
}

TEST_LIST = {
	/*
	 *	Allocation and management
	 */
	{ "fr_pair_afrom_da",                     test_fr_pair_afrom_da },
	{ "fr_pair_afrom_child_num",              test_fr_pair_afrom_child_num },
	{ "fr_pair_copy",                         test_fr_pair_copy },
	{ "fr_pair_steal",                        test_fr_pair_steal },

	/* Searching and list modification */
	{ "fr_dcursor_iter_by_da_init",           test_fr_dcursor_iter_by_da_init },
	{ "fr_dcursor_iter_by_ancestor_init",     test_fr_dcursor_iter_by_ancestor_init },
	{ "fr_pair_to_unknown",                   test_fr_pair_to_unknown },
	{ "fr_pair_find_by_da",                   test_fr_pair_find_by_da },
	{ "fr_pair_find_by_child_num",            test_fr_pair_find_by_child_num },
	{ "fr_pair_append",                       test_fr_pair_append },
	{ "fr_pair_prepend_by_da",                test_fr_pair_prepend_by_da },
	{ "fr_pair_delete_by_child_num",          test_fr_pair_delete_by_child_num },
	{ "fr_pair_update_by_da",                 test_fr_pair_update_by_da },
	{ "fr_pair_delete",                       test_fr_pair_delete },
	{ "fr_pair_delete_by_da",                 test_fr_pair_delete_by_da },

	/* Compare */
	{ "fr_pair_cmp",                          test_fr_pair_cmp },
	{ "fr_pair_list_cmp",                     test_fr_pair_list_cmp },

	/* Lists */
	{ "fr_pair_list_copy",                    test_fr_pair_list_copy },
	{ "fr_pair_list_copy_by_da",              test_fr_pair_list_copy_by_da },
	{ "fr_pair_list_copy_by_ancestor",        test_fr_pair_list_copy_by_ancestor },
	{ "fr_pair_list_sort",                    test_fr_pair_list_sort },

	/* Copy */
	{ "fr_pair_value_copy",                   test_fr_pair_value_copy },

	/* Strings */
	{ "fr_pair_value_from_str",               test_fr_pair_value_from_str },
	{ "fr_pair_value_strdup",                 test_fr_pair_value_strdup },
	{ "fr_pair_value_strdup_shallow",         test_fr_pair_value_strdup_shallow },
	{ "fr_pair_value_strtrim",                test_fr_pair_value_strtrim },
	{ "fr_pair_value_aprintf",                test_fr_pair_value_aprintf },

	/* Assign and manipulate binary-safe strings */
	{ "fr_pair_value_bstr_alloc",             test_fr_pair_value_bstr_alloc },
	{ "fr_pair_value_bstr_realloc",           test_fr_pair_value_bstr_realloc },
	{ "fr_pair_value_bstrndup",               test_fr_pair_value_bstrndup },
	{ "fr_pair_value_bstrdup_buffer",         test_fr_pair_value_bstrdup_buffer },
	{ "fr_pair_value_bstrndup_shallow",       test_fr_pair_value_bstrndup_shallow },
	{ "fr_pair_value_bstrdup_buffer_shallow", test_fr_pair_value_bstrdup_buffer_shallow },
	{ "fr_pair_value_bstrn_append",           test_fr_pair_value_bstrn_append },
	{ "fr_pair_value_bstr_append_buffer",     test_fr_pair_value_bstr_append_buffer },

	/* Assign and manipulate octets strings */
	{ "fr_pair_value_mem_alloc",              test_fr_pair_value_mem_alloc },
	{ "fr_pair_value_mem_realloc",            test_fr_pair_value_mem_realloc },
	{ "fr_pair_value_memdup",                 test_fr_pair_value_memdup },
	{ "fr_pair_value_memdup_buffer",          test_fr_pair_value_memdup_buffer },
	{ "fr_pair_value_memdup_shallow",         test_fr_pair_value_memdup_shallow },
	{ "fr_pair_value_memdup_buffer_shallow",  test_fr_pair_value_memdup_buffer_shallow },
	{ "fr_pair_value_mem_append",             test_fr_pair_value_mem_append },
	{ "fr_pair_value_mem_append_buffer",      test_fr_pair_value_mem_append_buffer },

	/* Enum functions */
	{ "fr_pair_value_enum",                   test_fr_pair_value_enum },
	{ "fr_pair_value_enum_box",               test_fr_pair_value_enum_box },

	{ NULL }
};
