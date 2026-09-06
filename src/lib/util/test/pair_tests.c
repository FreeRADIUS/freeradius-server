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
 * @file src/lib/util/test//pair_tests.c
 * @author Jorge Pereira <jpereira@freeradius.org>
 * @copyright 2020 Network RADIUS SAS (legal@networkradius.com)
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

#include "acutest_common_init.h"
#include "acutest_helpers.h"
#include "pair_test_helpers.h"

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/sbuff.h>

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
#ifdef TEST_NESTED_PAIRS
		fr_perror("pair_nested_tests");
#else
		fr_perror("pair_tests");
#endif
		fr_exit_now(EXIT_FAILURE);
	}

	/*
	 *	Mismatch between the binary and the libraries it depends on
	 */
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) goto error;

	if (fr_dict_test_init(autofree, &test_dict, NULL) < 0) goto error;

	/* Initialize the "test_pairs" list */
	fr_pair_list_init(&test_pairs);

#ifdef TEST_NESTED_PAIRS
	if (fr_pair_test_list_alloc_nested(autofree, &test_pairs, NULL) < 0) goto error;
#else
	if (fr_pair_test_list_alloc(autofree, &test_pairs, NULL) < 0) goto error;
#endif
}

/*
 *	Tests functions
 */
static void test_fr_pair_afrom_da(void)
{
	fr_pair_t *vp;

	TEST_CASE("Allocation using fr_pair_afrom_da");
	TEST_CHECK((vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string)) != NULL);

	TEST_CHECK(vp != NULL);
	if (!vp) return;

	TEST_CHECK(fr_pair_value_from_str(vp, test_string, strlen(test_string), &fr_value_unescape_double, false) == 0);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

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

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CHECK(vp && vp->da->attr == FR_TEST_ATTR_STRING);
	TEST_MSG("Expected attr(%u) == vp->da->attr(%u)", attr, vp->da->attr);

	talloc_free(vp);
}

static void test_fr_pair_afrom_da_nested(void)
{
	fr_pair_t    *vp, *parent = NULL;
	fr_pair_list_t	local_pairs;

	fr_pair_list_init(&local_pairs);

	TEST_CASE("Allocation using fr_pair_afrom_da_nested");
	TEST_CHECK((vp = fr_pair_afrom_da_nested(autofree, &local_pairs, fr_dict_attr_test_tlv_string)) != NULL);

	TEST_CHECK(vp && vp->da == fr_dict_attr_test_tlv_string);
	TEST_MSG("Expected attr(%s) == vp->da->attr(%s)", fr_dict_attr_test_tlv_string->name, vp->da->name);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Top list does not have the tlv child attribute");
	TEST_CHECK(fr_pair_find_by_da(&local_pairs, NULL, fr_dict_attr_test_tlv_string) == NULL);

	TEST_CASE("Top list does have the tlv attribute");
	parent = fr_pair_find_by_da(&local_pairs, NULL, fr_dict_attr_test_tlv);
	TEST_ASSERT(parent != NULL);

	TEST_CASE("Parent list does have the tlv child attribute");
	TEST_CHECK(fr_pair_find_by_da(&parent->vp_group, NULL, fr_dict_attr_test_tlv_string) == vp);

	talloc_free(parent);	/* not vp! */
}

static void test_fr_pair_delete_by_da_nested(void)
{
	int		count;
	fr_pair_t	*vp, *parent = NULL;
	fr_pair_list_t	local_pairs;

	fr_pair_list_init(&local_pairs);

	TEST_CASE("Allocation using fr_pair_afrom_da_nested");
	TEST_CHECK((vp = fr_pair_afrom_da_nested(autofree, &local_pairs, fr_dict_attr_test_tlv_string)) != NULL);

	TEST_CHECK(vp && vp->da == fr_dict_attr_test_tlv_string);
	TEST_MSG("Expected attr(%s) == vp->da->attr(%s)", fr_dict_attr_test_tlv_string->name, vp->da->name);

	TEST_CASE("Deleted nested pair");
	TEST_CHECK((count = fr_pair_delete_by_da_nested(&local_pairs, fr_dict_attr_test_tlv_string)) == 1);

	TEST_CASE("Top list still has the tlv attribute");
	parent = fr_pair_find_by_da(&local_pairs, NULL, fr_dict_attr_test_tlv);
	TEST_ASSERT(parent != NULL);

	TEST_CASE("Parent list does not have the tlv child attribute");
	TEST_CHECK(fr_pair_find_by_da(&parent->vp_group, NULL, fr_dict_attr_test_tlv_string) == NULL);

	fr_pair_list_free(&local_pairs);
}

static void test_fr_pair_nested_verify(void)
{
	TEST_CHECK(!fr_dict_attr_can_contain(fr_dict_attr_test_vsa, fr_dict_attr_test_tlv_string));
	TEST_MSG("Expected %s cannot parent %s", fr_dict_attr_test_vsa->name, fr_dict_attr_test_tlv_string->name);
}


static void test_fr_pair_copy(void)
{
	fr_pair_t *vp, *copy;

	TEST_CASE("Allocation using fr_pair_copy");
	TEST_CHECK((vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	copy = fr_pair_copy(autofree, vp);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(copy);

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

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Stealing 'vp' pair using fr_pair_steal()");
	fr_pair_steal(autofree, vp); /* It should exit without memory-leaks */

	TEST_CASE("Checking if talloc_parent(vp) == autofree");
	TEST_CHECK(talloc_parent(vp) == autofree);
}

static void test_fr_pair_raw_afrom_pair(void)
{
	fr_pair_t *vp;
	uint8_t value = 0;

	TEST_CASE("Allocate a new attribute fr_pair_afrom_da");
	TEST_CHECK((vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Converting regular 'vp' as unknown");
	TEST_CHECK(fr_pair_raw_afrom_pair(vp, &value, 1) == 0);

	TEST_CASE("Checking if a real 'raw' vp");
	TEST_CHECK(vp && vp->vp_raw);
}

static void test_fr_pair_dcursor_by_da_init(void)
{
	fr_pair_t   *vp, *needle;
	fr_dcursor_t	cursor;

	TEST_CASE("Searching for fr_dict_attr_test_uint32 using fr_pair_dcursor_by_da_init()");
	needle = NULL;
	for (vp = fr_pair_dcursor_by_da_init(&cursor, &test_pairs, fr_dict_attr_test_uint32);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
		if (!needle) {
			needle = vp;
			continue;
		}
		TEST_CHECK(1 == 1); /* this never will be reached */
	}

	TEST_CASE("Validating PAIR_VERIFY()");

	TEST_CHECK(needle != NULL);
	if (needle) PAIR_VERIFY(needle);

	TEST_CASE("Expected (needle->da == fr_dict_attr_test_uint32)");
	TEST_CHECK(needle && needle->da == fr_dict_attr_test_uint32);
}

static void test_fr_pair_dcursor_by_ancestor_init(void)
{
	fr_pair_t   *vp, *needle;
	fr_dcursor_t	cursor;

	TEST_CASE("Searching for fr_dict_attr_test_tlv_string as ascend of fr_dict_attr_test_tlv using fr_pair_dcursor_by_ancestor_init()");
	needle = NULL;
	for (vp = fr_pair_dcursor_by_ancestor_init(&cursor, &test_pairs, fr_dict_attr_test_tlv);
	     vp;
	     vp = fr_dcursor_next(&cursor)) {
		TEST_CHECK(vp != NULL);
		if (vp->da == fr_dict_attr_test_tlv_string) {
			needle = vp;
			continue;
		}
	}

	TEST_CHECK(needle != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	if (needle) PAIR_VERIFY(needle);

	TEST_CASE("Expected (needle->da == fr_dict_attr_test_tlv_string)");
	TEST_CHECK(needle && needle->da == fr_dict_attr_test_tlv_string);
}

static void test_fr_pair_dcursor_value_init(void)
{
	int i = 0;
	fr_value_box_t *box;
	fr_dcursor_t	cursor;
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;

	fr_pair_list_init(&local_pairs);

	MEM(vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string));
	fr_pair_value_strdup(vp, "hello", false);
	fr_pair_append(&local_pairs, vp);

	MEM(vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32));
	vp->vp_uint32 = 6809;
	fr_pair_append(&local_pairs, vp);

	MEM(vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint8));
	vp->vp_uint8 = 12;
	fr_pair_append(&local_pairs, vp);

	TEST_CASE("Searching for fr_dict_attr_test_tlv_string as ascend of fr_dict_attr_test_tlv using fr_pair_dcursor_by_ancestor_init()");
	for (box = fr_pair_dcursor_value_init(&cursor);
	     box;
	     box = fr_dcursor_next(&cursor), i++) {
		switch (i) {
		case 0:
			TEST_CASE("First box is a string with value 'hello'");
			TEST_CHECK(box->type == FR_TYPE_STRING);
			TEST_CHECK(strcmp(box->vb_strvalue, "hello") == 0);
			break;

		case 1:
			TEST_CASE("First box is a uint32 with value 6809");
			TEST_CHECK(box->type == FR_TYPE_UINT32);
			TEST_CHECK(box->vb_uint32 == 6809);
			break;

		case 2:
			TEST_CASE("First box is a uint8 r with value 12");
			TEST_CHECK(box->type == FR_TYPE_UINT8);
			TEST_CHECK(box->vb_uint8 == 12);
			break;

		default:
			TEST_CASE("Too many pairs");
			TEST_CHECK(i < 3);
			break;
		}
	}

	fr_pair_list_free(&local_pairs);
}

static void test_fr_pair_find_by_da_idx(void)
{
	fr_pair_t *vp;

	TEST_CASE("Search for fr_dict_attr_test_string using fr_pair_find_by_da_idx()");
	TEST_CHECK((vp = fr_pair_find_by_da_idx(&test_pairs, fr_dict_attr_test_string, 0)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Expected (vp->da == fr_dict_attr_test_string)");
	TEST_CHECK(vp && vp->da == fr_dict_attr_test_string);
}

static void test_fr_pair_find_by_child_num_idx(void)
{
	fr_pair_t *vp;

	TEST_CASE("Search for FR_TEST_ATTR_STRING using fr_pair_find_by_child_num_idx()");
	TEST_CHECK((vp = fr_pair_find_by_child_num_idx(&test_pairs, fr_dict_root(test_dict), FR_TEST_ATTR_STRING, 0)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Expected (vp->da == fr_dict_attr_test_string)");
	TEST_CHECK(vp && vp->da == fr_dict_attr_test_string);
}

static void test_fr_pair_find_by_da_nested(void)
{
	fr_pair_t	*vp1, *vp2, *vp3, *vp4, *vp5, *vp_found;
	fr_pair_list_t	local_pairs;

	fr_pair_list_init(&local_pairs);

	/*
	 *	Build a list with 2 TLV structures, each with different leaf nodes
	 */
	MEM(vp1 = fr_pair_afrom_da(autofree, fr_dict_attr_test_nested_top_tlv));
	fr_pair_append(&local_pairs, vp1);
	MEM(vp2 = fr_pair_afrom_da(vp1, fr_dict_attr_test_nested_child_tlv));
	fr_pair_append(&vp1->vp_group, vp2);
	MEM(vp1 = fr_pair_afrom_da(vp2, fr_dict_attr_test_nested_leaf_string));
	fr_pair_append(&vp2->vp_group, vp1);
	MEM(vp2 = fr_pair_afrom_da(autofree, fr_dict_attr_test_nested_top_tlv));
	fr_pair_append(&local_pairs, vp2);
	MEM(vp3 = fr_pair_afrom_da(vp2, fr_dict_attr_test_nested_child_tlv));
	fr_pair_append(&vp2->vp_group, vp3);
	MEM(vp2 = fr_pair_afrom_da(vp3, fr_dict_attr_test_nested_leaf_int32));
	fr_pair_append(&vp3->vp_group, vp2);

	vp_found = fr_pair_find_by_da_nested(&local_pairs, fr_dict_attr_test_nested_leaf_string);
	TEST_CASE("Find child node in first TLV");
	TEST_CHECK_PAIR(vp_found, vp1);

	vp_found = fr_pair_find_by_da_nested(&local_pairs, fr_dict_attr_test_nested_leaf_int32);
	TEST_CASE("Find child node in second TLV");
	TEST_CHECK_PAIR(vp_found, vp2);

	/*
	 *	Add third nested TLV with child of same type as first
	 */
	MEM(vp3 = fr_pair_afrom_da(autofree, fr_dict_attr_test_nested_top_tlv));
	fr_pair_append(&local_pairs, vp3);
	MEM(vp4 = fr_pair_afrom_da(vp3, fr_dict_attr_test_nested_child_tlv));
	fr_pair_append(&vp3->vp_group, vp4);
	MEM(vp3 = fr_pair_afrom_da(vp4, fr_dict_attr_test_nested_leaf_string));
	fr_pair_append(&vp4->vp_group, vp3);

	/*
	 *	A second attribute of the same type further down the list does
	 *	not change which one is found.
	 */
	vp_found = fr_pair_find_by_da_nested(&local_pairs, fr_dict_attr_test_nested_leaf_string);
	TEST_CASE("Find child node in first TLV");
	TEST_CHECK_PAIR(vp_found, vp1);

	/*
	 *	Add some "flat list" attributes
	 */
	MEM(vp4 = fr_pair_afrom_da(autofree, fr_dict_attr_test_nested_leaf_string));
	fr_pair_prepend(&local_pairs, vp4);
	MEM(vp5 = fr_pair_afrom_da(autofree, fr_dict_attr_test_nested_leaf_string));
	fr_pair_append(&local_pairs, vp5);

	/*
	 *	The search looks in the nesting before it looks at the flat
	 *	list, so the nested attribute wins even though vp4 was
	 *	prepended, and therefore comes first in the top level list.
	 */
	vp_found = fr_pair_find_by_da_nested(&local_pairs, fr_dict_attr_test_nested_leaf_string);
	TEST_CASE("A nested attribute is found before a flat one");
	TEST_CHECK_PAIR(vp_found, vp1);

	fr_pair_list_free(&local_pairs);

	/*
	 *	With no nesting to search, the flat attribute is the answer.
	 *	This is the fallback at the end of fr_pair_find_by_da_nested().
	 */
	fr_pair_list_init(&local_pairs);

	MEM(vp5 = fr_pair_afrom_da(autofree, fr_dict_attr_test_nested_leaf_string));
	fr_pair_append(&local_pairs, vp5);

	vp_found = fr_pair_find_by_da_nested(&local_pairs, fr_dict_attr_test_nested_leaf_string);
	TEST_CASE("Find a flat attribute when there is no nesting");
	TEST_CHECK_PAIR(vp_found, vp5);

	TEST_CASE("Find nothing when the attribute is not there at all");
	TEST_CHECK_PAIR(fr_pair_find_by_da_nested(&local_pairs, fr_dict_attr_test_nested_leaf_int32), NULL);

	fr_pair_list_free(&local_pairs);
}

static void test_fr_pair_append(void)
{
	fr_pair_t      *vp;
	fr_pair_list_t	local_pairs;
	size_t         count = 0;

	TEST_CASE("Add 3 pairs using fr_pair_append()");

	fr_pair_list_init(&local_pairs);

	MEM(vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_octets));
	fr_pair_append(&local_pairs, vp);
	MEM(vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32));
	fr_pair_append(&local_pairs, vp);
	MEM(vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_tlv));
	fr_pair_append(&local_pairs, vp);

	/* lets' count */
	fr_pair_list_foreach(&local_pairs, pair) count++;

	TEST_CASE("Expected (count == 3)");
	TEST_CHECK(count == 3);

	fr_pair_list_free(&local_pairs);
}

static void test_fr_pair_append_by_da_parent(void)
{
	fr_pair_t	*leaf1, *leaf2, *found, *inter1, *inter2;
	fr_pair_list_t	local_pairs;
	int		ret;

	fr_pair_list_init(&local_pairs);

	TEST_CASE("Add nested attribute including parents");
	ret = fr_pair_append_by_da_parent(autofree, &leaf1, &local_pairs, fr_dict_attr_test_nested_leaf_int32);
	TEST_CHECK(ret == 0);
	TEST_CHECK(leaf1 != NULL);

	TEST_CASE("Check nested attributes added");
	found = fr_pair_find_by_da(&local_pairs, NULL, fr_dict_attr_test_nested_top_tlv);
	TEST_ASSERT(found != NULL);
	inter1 = found;
	found = fr_pair_find_by_da(&inter1->vp_group, NULL, fr_dict_attr_test_nested_child_tlv);
	TEST_ASSERT(found != NULL);
	inter2 = found;
	found = fr_pair_find_by_da(&inter2->vp_group, NULL, fr_dict_attr_test_nested_leaf_int32);
	TEST_CHECK_PAIR(found, leaf1);

	TEST_CASE("Ensure no flat list attribute created");
	found = fr_pair_find_by_da(&local_pairs, NULL, fr_dict_attr_test_nested_leaf_int32);
	TEST_CHECK_PAIR(found, NULL);

	TEST_CASE("Add additional nested attribute where parents exist");
	ret = fr_pair_append_by_da_parent(autofree, &leaf2, &local_pairs, fr_dict_attr_test_nested_leaf_string);
	TEST_CHECK(ret == 0);
	TEST_CHECK(leaf2 != NULL);
	TEST_CHECK(leaf2 != leaf1);

	TEST_CASE("Check additional leaf added under existing parent");
	found = fr_pair_find_by_da(&inter2->vp_group, NULL, fr_dict_attr_test_nested_leaf_string);
	TEST_CHECK_PAIR(found, leaf2);

	TEST_CASE("Check no extra parent attributes created");
	found = fr_pair_find_by_da(&local_pairs, NULL, fr_dict_attr_test_nested_top_tlv);
	TEST_CHECK_PAIR(found, inter1);
	found = fr_pair_find_by_da(&local_pairs, inter1, fr_dict_attr_test_nested_top_tlv);
	TEST_CHECK_PAIR(found, NULL);

	found = fr_pair_find_by_da(&inter1->vp_group, NULL, fr_dict_attr_test_nested_child_tlv);
	TEST_CHECK_PAIR(found, inter2);
	found = fr_pair_find_by_da(&inter1->vp_group, inter2, fr_dict_attr_test_nested_child_tlv);
	TEST_CHECK_PAIR(found, NULL);

	fr_pair_list_free(&local_pairs);
}

static void test_fr_pair_delete_by_child_num(void)
{
	TEST_CASE("Delete fr_dict_attr_test_string using fr_pair_delete_by_child_num()");
	fr_pair_delete_by_child_num(&test_pairs, fr_dict_root(test_dict), FR_TEST_ATTR_STRING);

	TEST_CASE("The fr_dict_attr_test_string shouldn't exist in 'test_pairs'");
	TEST_CHECK(fr_pair_find_by_child_num_idx(&test_pairs, fr_dict_root(test_dict), FR_TEST_ATTR_STRING, 0) == NULL);

	TEST_CASE("Add fr_dict_attr_test_string back into 'test_pairs'");
	TEST_CHECK(fr_pair_prepend_by_da(autofree, NULL, &test_pairs, fr_dict_attr_test_string) == 0);
}

static void test_fr_pair_prepend_by_da(void)
{
	fr_pair_list_t	local_pairs;
	TALLOC_CTX     *ctx = talloc_null_ctx();

	fr_pair_list_init(&local_pairs);

	TEST_CASE("Add using fr_pair_prepend_by_da()");
	TEST_CHECK(fr_pair_prepend_by_da(ctx, NULL, &local_pairs, fr_dict_attr_test_string) == 0);

	/* lets' count */
	fr_pair_list_foreach(&local_pairs, vp) {
		TEST_CASE("Expected (vp->da == fr_dict_attr_test_string)");
		TEST_CHECK(vp->da == fr_dict_attr_test_string);
	}

	fr_pair_list_free(&local_pairs);
}

static void test_fr_pair_update_by_da_parent(void)
{
	fr_pair_t *vp, *group;

	TEST_CHECK((group = fr_pair_afrom_da(autofree, fr_dict_attr_test_group)) != NULL);
	if (!group) return; /* quiet clang scan */

	TEST_CASE("Update Add using fr_pair_prepend_by_da()");
	TEST_CHECK(fr_pair_update_by_da_parent(group, &vp, fr_dict_attr_test_uint32) == 0); /* attribute doesn't exist in this group */
	vp->vp_uint32 = 54321;

	TEST_CASE("Expected fr_dict_attr_test_uint32 (vp->vp_uint32 == 54321)");
	TEST_CHECK((vp = fr_pair_find_by_da(&group->vp_group, NULL, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Expected (vp == 54321)");
	TEST_CHECK(vp && vp->vp_uint32 == 54321);

	talloc_free(group);
}

static void test_fr_pair_delete_by_da(void)
{
	TEST_CASE("Delete fr_dict_attr_test_string using fr_pair_delete_by_da()");
	TEST_CHECK(fr_pair_delete_by_da(&test_pairs, fr_dict_attr_test_string) == 1);

	TEST_CASE("The fr_dict_attr_test_string shouldn't exist in 'test_pairs'");
	TEST_CHECK(fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_string) == NULL);

	TEST_CASE("Add fr_dict_attr_test_string back into 'test_pairs'");
	TEST_CHECK(fr_pair_prepend_by_da(autofree, NULL, &test_pairs, fr_dict_attr_test_string) == 0);
}

static void test_fr_pair_delete(void)
{
	fr_pair_t *vp;

	TEST_CASE("Delete fr_dict_attr_test_string using fr_pair_delete()");
	TEST_CHECK((vp = fr_pair_find_by_child_num_idx(&test_pairs, fr_dict_root(test_dict), FR_TEST_ATTR_STRING, 0)) != NULL);
	fr_pair_delete(&test_pairs, vp);

	TEST_CASE("The fr_dict_attr_test_string shouldn't exist in 'test_pairs'");
	TEST_CHECK((vp = fr_pair_find_by_child_num_idx(&test_pairs, fr_dict_root(test_dict), FR_TEST_ATTR_STRING, 0)) == NULL);

	TEST_CASE("Add fr_dict_attr_test_string back into 'test_pairs'");
	TEST_CHECK(fr_pair_prepend_by_da(autofree, NULL, &test_pairs, fr_dict_attr_test_string) == 0);
}

static void test_fr_pair_cmp(void)
{
	fr_pair_t *vp1, *vp2;

	TEST_CASE("Create the vp1 'Test-Integer = 123'");
	TEST_CHECK((vp1 = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp1);

	vp1->op = T_OP_EQ;
	vp1->vp_uint32 = 123;

	TEST_CASE("Create the vp2 'Test-Integer = 321'");
	TEST_CHECK((vp2 = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp2);

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
	fr_pair_list_t	local_pairs;

	fr_pair_list_init(&local_pairs);

	TEST_CASE("Copy 'test_pairs' into 'local_pairs'");
	TEST_CHECK(fr_pair_list_copy_by_da(autofree, &local_pairs, &test_pairs, fr_dict_attr_test_string) > 0);

	TEST_CASE("The 'local_pairs' should have only fr_dict_attr_test_string");
	fr_pair_list_foreach(&local_pairs, vp) {
		TEST_CASE("Validating PAIR_VERIFY()");
		PAIR_VERIFY(vp);

		TEST_CASE("Expected (vp->da == fr_dict_attr_test_string)");
		TEST_CHECK(vp->da == fr_dict_attr_test_string);
	}

	fr_pair_list_free(&local_pairs);
}

static void test_fr_pair_list_copy_by_ancestor(void)
{
	fr_pair_t      *vp;
	fr_pair_list_t	local_pairs;

	fr_pair_list_init(&local_pairs);

	TEST_CASE("Copy 'test_pairs' into 'local_pairs'");
	TEST_CHECK(fr_pair_list_copy_by_ancestor(autofree, &local_pairs, &test_pairs, fr_dict_attr_test_tlv) > 0);

	TEST_CASE("The 'local_pairs' should have only one attribute in it");
	TEST_CHECK(fr_pair_list_num_elements(&local_pairs) == 1);

	TEST_CASE("The 'local_pairs' should have only fr_dict_attr_test_tlv_string (ancestor of 'Test-TLV-Root'");
	vp = fr_pair_list_head(&local_pairs);

	TEST_CASE("Validating we copied the attribute");
	TEST_CHECK(vp != NULL);
	if (!vp) return;

#ifdef TEST_NESTED_PAIRS
	TEST_CASE("Expected copied attribute == fr_dict_attr_test_tlv)");
	TEST_CHECK(vp->da == fr_dict_attr_test_tlv);
#else
	TEST_CASE("Expected copied attribute == fr_dict_attr_test_tlv_string)");
	TEST_CHECK(vp->da == fr_dict_attr_test_tlv_string);
#endif

	TEST_CASE("Verifying the copied attribute");
	PAIR_VERIFY(vp);

	TEST_CASE("Expecting nothing else in local list");
	TEST_CHECK(fr_pair_list_next(&local_pairs, vp) == NULL);

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
	TEST_CHECK((vp = fr_pair_dcursor_init(&cursor, &local_pairs)) != NULL);
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
	fr_pair_t *vp1, *vp2;

	TEST_CASE("Create 'vp1' with Test-Integer = 123");
	TEST_CHECK((vp1 = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_uint32)) != NULL);
	vp1->vp_uint32 = 123;

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp1);

	TEST_CASE("Create 'vp2'");
	TEST_CHECK((vp2 = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp2);

	TEST_CASE("Copy 'vp1' to 'vp2' using fr_pair_value_copy()");
	TEST_CHECK(fr_pair_value_copy(vp2, vp1) == 0);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp2);

	TEST_CASE("Check (vp1 == vp2)");
	TEST_CHECK(vp2->vp_uint32 == 123);
}

static void test_fr_pair_value_from_str(void)
{
	fr_pair_t *vp;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Convert 'test_string' value to attribute value using fr_pair_value_from_str()");
	TEST_CHECK(fr_pair_value_from_str(vp, test_string, strlen(test_string), &fr_value_unescape_double, false) == 0);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Check (vp->vp_string == test_string)");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, test_string) == 0);
}

static void test_fr_pair_value_strdup(void)
{
	fr_pair_t *vp;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Copy content of 'test_string' to attribute value using fr_pair_value_strdup()");
	TEST_CHECK(fr_pair_value_strdup(vp, test_string, false) == 0);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Check (vp->vp_string == test_string)");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, test_string) == 0);
}

static void test_fr_pair_value_strdup_shallow(void)
{
	fr_pair_t *vp, *nvp;
	char      *copy_test_string;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	MEM(nvp = fr_pair_copy(NULL, vp));

 	copy_test_string = talloc_strdup(nvp, test_string);
	talloc_set_type(copy_test_string, char);

	TEST_CASE("Copy content of 'test_string' to attribute value using fr_pair_value_strdup_shallow()");
	TEST_CHECK(fr_pair_value_strdup_shallow(nvp, copy_test_string, true) == 0);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(nvp);

	TEST_CASE("Check (vp->vp_string == copy_test_string)");
	TEST_CHECK(nvp && strncmp(nvp->vp_strvalue, test_string, strlen(copy_test_string)) == 0);

	talloc_free(nvp);
}

static void test_fr_pair_value_strtrim(void)
{
	fr_pair_t *vp;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Copy content of 'test_string' to attribute value using fr_pair_value_strdup_shallow()");
	TEST_CHECK(fr_pair_value_strdup(vp, test_string, false) == 0);

	TEST_CASE("Trim the length of the string buffer using fr_pair_value_strtrim()");
	TEST_CHECK(fr_pair_value_strtrim(vp) == 0);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Check (vp->vp_string == test_string)");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, test_string) == 0);
}

static void test_fr_pair_value_aprintf(void)
{
	fr_pair_t *vp;
	char      fmt_test[64];
	fr_time_t now = fr_time();

	snprintf(fmt_test, sizeof(fmt_test), "Now is %"PRId64, fr_time_unwrap(now));

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Copy content of 'fmt_test' to attribute value using fr_pair_value_aprintf()");
	TEST_CHECK(fr_pair_value_aprintf(vp, "Now is %"PRId64, fr_time_unwrap(now)) == 0);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Check (vp->vp_string == fmt_test)");
	TEST_CHECK(vp && strcmp(vp->vp_strvalue, fmt_test) == 0);
}

static void test_fr_pair_value_bstr_alloc(void)
{
	fr_pair_t *vp;
	char      *out = NULL;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Pre-allocate a memory buffer using fr_pair_value_bstr_alloc()");
	TEST_CHECK(fr_pair_value_bstr_alloc(vp, &out, test_string_len, false) == 0);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

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
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	TEST_CASE("Pre-allocate 1 byte of memory buffer using fr_pair_value_bstr_alloc()");
	TEST_CHECK(fr_pair_value_bstr_alloc(vp, &out, 1, false) == 0);

	TEST_CASE("Re-allocate (test_string_len-1) byte of memory buffer using fr_pair_value_bstr_realloc()");
	TEST_CHECK(fr_pair_value_bstr_realloc(vp, &out, (test_string_len - 1)) == 0);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

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
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

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
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

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
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	copy_test_string = talloc_strdup(vp, test_string);
	talloc_set_type(copy_test_string, char);

	TEST_CASE("Copy content of 'test_string' to attribute value using fr_pair_value_bstrndup_shallow()");
	TEST_CHECK(fr_pair_value_bstrndup_shallow(vp, copy_test_string, strlen(copy_test_string), true) == 0);

	TEST_CASE("Check (vp->vp_string == copy_test_string)");
	TEST_CHECK(vp && strncmp(vp->vp_strvalue, test_string, test_string_len) == 0);

	fr_pair_value_clear(vp);
}

static void test_fr_pair_value_bstrdup_buffer_shallow(void)
{
	fr_pair_t *vp;
	char      *copy_test_string;

	TEST_CASE("Find 'Test-String'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_string)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

 	copy_test_string = talloc_strdup(vp, test_string);
	talloc_set_type(copy_test_string, char);

	TEST_CASE("Copy content of 'test_string' to attribute value using fr_pair_value_bstrdup_buffer_shallow()");
	TEST_CHECK(fr_pair_value_bstrdup_buffer_shallow(vp, copy_test_string, true) == 0);

	TEST_CASE("Check (vp->vp_string == copy_test_string)");
	TEST_CHECK(vp && strncmp(vp->vp_strvalue, test_string, test_string_len) == 0);

	fr_pair_value_clear(vp);
}

static void test_fr_pair_value_mem_alloc(void)
{
	fr_pair_t *vp;
	uint8_t   *out;

	TEST_CASE("Find 'Test-Octets'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

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
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

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
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

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
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

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
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	copy_test_octets = talloc_memdup(vp, test_octets, NUM_ELEMENTS(test_octets));
	talloc_set_type(copy_test_octets, uint8_t);

	TEST_CASE("Copy content of 'test_octets' to attribute value using fr_pair_value_memdup_shallow()");
	TEST_CHECK(fr_pair_value_memdup_shallow(vp, copy_test_octets, NUM_ELEMENTS(test_octets), true) == 0);

	TEST_CASE("Check (vp->vp_octets == test_octets)");
	TEST_CHECK(vp && memcmp(vp->vp_octets, test_octets, NUM_ELEMENTS(test_octets)) == 0);

	fr_pair_value_clear(vp);
}

static void test_fr_pair_value_memdup_buffer_shallow(void)
{
	fr_pair_t *vp;
	uint8_t   *copy_test_octets;

	TEST_CASE("Find 'Test-Octets'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_octets)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	copy_test_octets = talloc_memdup(vp, test_octets, NUM_ELEMENTS(test_octets));
	talloc_set_type(copy_test_octets, uint8_t);

	TEST_CASE("Copy content of 'test_octets' to attribute value using fr_pair_value_memdup_buffer_shallow()");
	TEST_CHECK(fr_pair_value_memdup_buffer_shallow(vp, copy_test_octets, true) == 0);

	TEST_CASE("Check (vp->vp_octets == copy_test_octets)");
	TEST_CHECK(vp && memcmp(vp->vp_octets, test_octets, NUM_ELEMENTS(test_octets)) == 0);

	fr_pair_value_clear(vp);
}

static void test_fr_pair_value_enum(void)
{
	fr_pair_t   *vp;
	char const  *var;
	char        buf[20];

	TEST_CASE("Find 'Test-Values'");
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_enum)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

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
	TEST_CHECK((vp = fr_pair_find_by_da(&test_pairs, NULL, fr_dict_attr_test_enum)) != NULL);

	TEST_CASE("Validating PAIR_VERIFY()");
	PAIR_VERIFY(vp);

	vp->vp_uint32 = 123;

	TEST_CASE("Lookup enum value attribute using fr_pair_value_enum_box()");

	TEST_CHECK(fr_pair_value_enum_box(&vb, vp) >= 0);
	TEST_MSG("Checking fr_pair_value_enum()");

	TEST_CHECK(vb->vb_uint32 == 123);
	TEST_MSG("Expected vb->vb_uint32 == 123");
}

/*
 *	Regression test: fr_dict_by_protocol_substr() used to dereference
 *	our_name.p without a bounds check after fr_sbuff_out_bstrncpy_allowed()
 *	had consumed every byte.  If the input sbuff was bounded by length
 *	(rather than a NUL sentinel), that read was one byte past in->end.
 *
 *	The buggy code:
 *	    if (*(our_name.p) && (*(our_name.p) != '.')) { return 0 with dict_def; }
 *
 *	With the bug, an OOB byte equal to '.' or NUL would let execution
 *	fall through to the hash lookup; an OOB byte of any other value
 *	would take the early-return path and yield slen=0.  Either way,
 *	the read past in->end is undefined.
 *
 *	We construct a sbuff where in->end points one byte before a known
 *	non-NUL, non-'.' sentinel.  Then we run the function with
 *	`fr_dict_test`, which has been added to the protocol table so the
 *	hash lookup will succeed when the bounds check is honoured.
 *
 *	Bug:  reads buf[4]='X', early-returns 0 with *out = dict_def (NULL).
 *	Fix:  bounds check trips, hash lookup finds "test", returns slen=4
 *	      with *out = fr_dict_test.
 */
extern int dict_protocol_add(fr_dict_t *dict);

static void test_fr_dict_by_protocol_substr_no_overflow(void)
{
	char			buf[8];
	fr_sbuff_t		sbuff;
	fr_dict_t const		*out_dict = NULL;
	fr_slen_t		slen;

	if (dict_protocol_add(test_dict) < 0) {
		TEST_CHECK_(0, "dict_protocol_add failed: %s", fr_strerror());
		return;
	}

	memcpy(buf, "testXXXX", 8);			/* "test" then sentinel bytes the buggy code would read */
	fr_sbuff_init_in(&sbuff, buf, (size_t)4);	/* Only "test" is visible */

	slen = fr_dict_by_protocol_substr(NULL, &out_dict, &sbuff, NULL);

	TEST_CHECK(slen == 4);
	TEST_MSG("Expected slen=4 (matched 'test' protocol), got %zd", (ssize_t)slen);

	TEST_CHECK(out_dict == test_dict);
	TEST_MSG("Expected out_dict==test_dict; OOB read of sentinel byte made the buggy code early-return with dict_def (NULL)");
}

/*
 *	Printing
 */

/** Print one pair into a buffer, and compare it against what we expect
 *
 */
#define TEST_PRINT_PAIR(_func, _parent, _vp, _expected) \
do { \
	char		buffer[1024]; \
	fr_sbuff_t	sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer)); \
	ssize_t		slen; \
\
	slen = _func(&sbuff, _parent, _vp); \
	TEST_CHECK(slen > 0); \
	TEST_MSG(#_func " returned %zd: %s", slen, fr_strerror()); \
\
	TEST_CHECK(strcmp(buffer, _expected) == 0); \
	TEST_MSG("expected: %s", _expected); \
	TEST_MSG("got     : %s", buffer); \
} while (0)

static void test_fr_pair_print(void)
{
	fr_pair_t	*vp;

	TEST_CASE("Print one leaf pair");
	TEST_CHECK((vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string)) != NULL);
	if (!vp) return;
	TEST_CHECK(fr_pair_value_strdup(vp, test_string, false) == 0);

	TEST_PRINT_PAIR(fr_pair_print, NULL, vp, "Test-String-0 = \"We love testing!\"");

	TEST_CASE("Print one leaf pair, relative to its own parent");
	TEST_PRINT_PAIR(fr_pair_print, fr_dict_root(test_dict), vp, "Test-String-0 = \"We love testing!\"");

	talloc_free(vp);
}

static void test_fr_pair_print_name(void)
{
	fr_pair_list_t	list;
	fr_pair_t	*leaf, *top;
	fr_pair_t const	*name_vp;
	char		buffer[1024];
	fr_sbuff_t	sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));

	fr_pair_list_init(&list);

	TEST_CASE("Build Test-Nested-Top-TLV.Child-TLV.Leaf-String");
	TEST_CHECK(fr_pair_append_by_da_parent(autofree, &leaf, &list, fr_dict_attr_test_nested_leaf_string) == 0);
	if (!leaf) return;

	TEST_CHECK((top = fr_pair_find_by_da(&list, NULL, fr_dict_attr_test_nested_top_tlv)) != NULL);

	TEST_CASE("The full name is printed when there is no parent");
	name_vp = leaf;
	TEST_CHECK(fr_pair_print_name(&sbuff, NULL, &name_vp) > 0);
	TEST_CHECK(strcmp(buffer, "Test-Nested-Top-TLV-0.Child-TLV.Leaf-String = ") == 0);
	TEST_MSG("got: %s", buffer);

	TEST_CASE("Naming a parent trims that much off the front");
	fr_sbuff_set_to_start(&sbuff);
	name_vp = leaf;
	TEST_CHECK(fr_pair_print_name(&sbuff, fr_dict_attr_test_nested_child_tlv, &name_vp) > 0);
	TEST_CHECK(strcmp(buffer, "Leaf-String = ") == 0);
	TEST_MSG("got: %s", buffer);

	fr_pair_list_free(&list);
}

static void test_fr_pair_print_value_quoted(void)
{
	fr_pair_t	*vp;
	char		buffer[1024];
	fr_sbuff_t	sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));

	TEST_CHECK((vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string)) != NULL);
	if (!vp) return;
	TEST_CHECK(fr_pair_value_strdup(vp, test_string, false) == 0);

	TEST_CASE("A bare word is printed without quotes");
	TEST_CHECK(fr_pair_print_value_quoted(&sbuff, vp, T_BARE_WORD) > 0);
	TEST_CHECK(strcmp(buffer, test_string) == 0);
	TEST_MSG("got: %s", buffer);

	TEST_CASE("A double quoted string keeps its quotes");
	fr_sbuff_set_to_start(&sbuff);
	TEST_CHECK(fr_pair_print_value_quoted(&sbuff, vp, T_DOUBLE_QUOTED_STRING) > 0);
	TEST_CHECK(strcmp(buffer, "\"We love testing!\"") == 0);
	TEST_MSG("got: %s", buffer);

	talloc_free(vp);
}

static void test_fr_pair_print_secure(void)
{
	fr_pair_t	*vp;

	TEST_CASE("A pair which holds no secret prints its value");
	TEST_CHECK((vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string)) != NULL);
	if (!vp) return;
	TEST_CHECK(fr_pair_value_strdup(vp, test_string, false) == 0);

	TEST_PRINT_PAIR(fr_pair_print_secure, NULL, vp, "Test-String-0 = \"We love testing!\"");

	TEST_CASE("A pair which holds a secret prints a placeholder instead");
	vp->data.secret = true;
	TEST_PRINT_PAIR(fr_pair_print_secure, NULL, vp, "Test-String-0 = <<< secret >>>");

	talloc_free(vp);
}

/** fr_pair_print_secure() walks the children of a structural pair
 *
 *  Each child but the last is followed by a separator, so the interesting
 *  cases are no children, one child, and more than one.
 */
static void test_fr_pair_print_secure_children(void)
{
	fr_pair_t	*tlv, *child;

	TEST_CASE("A structural pair with no children");
	TEST_CHECK((tlv = fr_pair_afrom_da(autofree, fr_dict_attr_test_tlv)) != NULL);
	if (!tlv) return;

	TEST_PRINT_PAIR(fr_pair_print_secure, NULL, tlv, "Test-TLV-0 = {  }");

	TEST_CASE("A structural pair with one child, which needs no separator");
	TEST_CHECK(fr_pair_append_by_da(tlv, &child, &tlv->vp_group, fr_dict_attr_test_tlv_string) == 0);
	TEST_CHECK(fr_pair_value_strdup(child, "one", false) == 0);

	TEST_PRINT_PAIR(fr_pair_print_secure, NULL, tlv, "Test-TLV-0 = { String = \"one\" }");

	TEST_CASE("A structural pair with two children, separated by a comma");
	TEST_CHECK(fr_pair_append_by_da(tlv, &child, &tlv->vp_group, fr_dict_attr_test_tlv_string) == 0);
	TEST_CHECK(fr_pair_value_strdup(child, "two", false) == 0);

	TEST_PRINT_PAIR(fr_pair_print_secure, NULL, tlv,
			"Test-TLV-0 = { String = \"one\", String = \"two\" }");

	TEST_CASE("Secrets are hidden inside structural pairs, too");
	child->data.secret = true;
	TEST_PRINT_PAIR(fr_pair_print_secure, NULL, tlv,
			"Test-TLV-0 = { String = \"one\", String = <<< secret >>> }");

	talloc_free(tlv);
}

static void test_fr_pair_list_print(void)
{
	fr_pair_list_t	list;
	fr_pair_t	*vp;
	char		buffer[1024] = "";
	fr_sbuff_t	sbuff = FR_SBUFF_OUT(buffer, sizeof(buffer));

	fr_pair_list_init(&list);

	TEST_CASE("An empty list prints nothing");
	TEST_CHECK(fr_pair_list_print(&sbuff, NULL, &list) >= 0);
	TEST_CHECK(buffer[0] == '\0');

	TEST_CASE("Two pairs are separated by a comma");
	TEST_CHECK(fr_pair_append_by_da(autofree, &vp, &list, fr_dict_attr_test_string) == 0);
	TEST_CHECK(fr_pair_value_strdup(vp, "one", false) == 0);

	TEST_CHECK(fr_pair_append_by_da(autofree, &vp, &list, fr_dict_attr_test_uint32) == 0);
	vp->vp_uint32 = 2;

	fr_sbuff_set_to_start(&sbuff);
	TEST_CHECK(fr_pair_list_print(&sbuff, NULL, &list) > 0);
	TEST_CHECK(strcmp(buffer, "Test-String-0 = \"one\", Test-Uint32-0 = 2") == 0);
	TEST_MSG("got: %s", buffer);

	fr_pair_list_free(&list);
}

/** fr_pair_debug() and fr_pair_list_debug() write to a FILE, not to an sbuff
 *
 */
static void test_fr_pair_debug(void)
{
	fr_pair_list_t	list;
	fr_pair_t	*vp;
	FILE		*fp;
	char		buffer[1024];
	size_t		len;

	fr_pair_list_init(&list);

	TEST_CHECK(fr_pair_append_by_da(autofree, &vp, &list, fr_dict_attr_test_string) == 0);
	TEST_CHECK(fr_pair_value_strdup(vp, "one", false) == 0);

	TEST_CASE("fr_pair_debug() writes one pair");
	TEST_CHECK((fp = tmpfile()) != NULL);
	if (!fp) return;

	fr_pair_debug(fp, vp);
	rewind(fp);
	len = fread(buffer, 1, sizeof(buffer) - 1, fp);
	buffer[len] = '\0';
	fclose(fp);

	TEST_CHECK(strstr(buffer, "Test-String") != NULL);
	TEST_MSG("got: %s", buffer);
	TEST_CHECK(strstr(buffer, "one") != NULL);

	TEST_CASE("fr_pair_list_debug() writes the whole list");
	TEST_CHECK((fp = tmpfile()) != NULL);
	if (!fp) return;

	fr_pair_list_debug(fp, &list);
	rewind(fp);
	len = fread(buffer, 1, sizeof(buffer) - 1, fp);
	buffer[len] = '\0';
	fclose(fp);

	TEST_CHECK(strstr(buffer, "Test-String") != NULL);
	TEST_MSG("got: %s", buffer);

	fr_pair_list_free(&list);
}

TEST_LIST = {
	/*
	 *	Regression tests
	 */
	{ "fr_dict_by_protocol_substr no overflow", test_fr_dict_by_protocol_substr_no_overflow },

	/*
	 *	Allocation and management
	 */
	{ "fr_pair_afrom_da",                     test_fr_pair_afrom_da },
	{ "fr_pair_afrom_child_num",              test_fr_pair_afrom_child_num },
	{ "fr_pair_afrom_da_nested",              test_fr_pair_afrom_da_nested },
	{ "fr_pair_copy",                         test_fr_pair_copy },
	{ "fr_pair_steal",                        test_fr_pair_steal },

	/* Searching and list modification */
	{ "fr_dcursor_iter_by_da_init",           test_fr_pair_dcursor_by_da_init },
	{ "fr_pair_dcursor_by_ancestor_init",     test_fr_pair_dcursor_by_ancestor_init },
	{ "fr_pair_dcursor_value_init",           test_fr_pair_dcursor_value_init },
	{ "fr_pair_raw_afrom_pair",                test_fr_pair_raw_afrom_pair },
	{ "fr_pair_find_by_da_idx",                   test_fr_pair_find_by_da_idx },
	{ "fr_pair_find_by_child_num_idx",            test_fr_pair_find_by_child_num_idx },
	{ "fr_pair_find_by_da_nested",            test_fr_pair_find_by_da_nested },
	{ "fr_pair_append",                       test_fr_pair_append },
	{ "fr_pair_prepend_by_da",                test_fr_pair_prepend_by_da },
	{ "fr_pair_append_by_da_parent",          test_fr_pair_append_by_da_parent },
	{ "fr_pair_delete_by_child_num",          test_fr_pair_delete_by_child_num },
	{ "fr_pair_update_by_da_parent",          test_fr_pair_update_by_da_parent },
	{ "fr_pair_delete",                       test_fr_pair_delete },
	{ "fr_pair_delete_by_da",                 test_fr_pair_delete_by_da },
	{ "fr_pair_delete_by_da_nested",          test_fr_pair_delete_by_da_nested },

	/* Printing */
	{ "fr_pair_print",                        test_fr_pair_print },
	{ "fr_pair_print_name",                   test_fr_pair_print_name },
	{ "fr_pair_print_value_quoted",           test_fr_pair_print_value_quoted },
	{ "fr_pair_print_secure",                 test_fr_pair_print_secure },
	{ "fr_pair_print_secure children",        test_fr_pair_print_secure_children },
	{ "fr_pair_list_print",                   test_fr_pair_list_print },
	{ "fr_pair_debug",                        test_fr_pair_debug },

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


	/* parenting */
	{ "test_fr_pair_nested_verify",		test_fr_pair_nested_verify },

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

	/* Assign and manipulate octets strings */
	{ "fr_pair_value_mem_alloc",              test_fr_pair_value_mem_alloc },
	{ "fr_pair_value_mem_realloc",            test_fr_pair_value_mem_realloc },
	{ "fr_pair_value_memdup",                 test_fr_pair_value_memdup },
	{ "fr_pair_value_memdup_buffer",          test_fr_pair_value_memdup_buffer },
	{ "fr_pair_value_memdup_shallow",         test_fr_pair_value_memdup_shallow },
	{ "fr_pair_value_memdup_buffer_shallow",  test_fr_pair_value_memdup_buffer_shallow },
	
	/* Enum functions */
	{ "fr_pair_value_enum",                   test_fr_pair_value_enum },
	{ "fr_pair_value_enum_box",               test_fr_pair_value_enum_box },

	TEST_TERMINATOR
};
