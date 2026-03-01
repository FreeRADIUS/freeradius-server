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
 * @file src/lib/util/test//edit_tests.c
 * @author Alan DeKok (aland@networkradius.com)
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
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

#include "acutest.h"
#include"acutest_helpers.h"
#include "pair_test_helpers.h"

#include <freeradius-devel/util/conf.h>
#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/edit.h>

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
		fr_perror("edit_tests");
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

static void add_pairs(fr_pair_list_t *local_pairs)
{
	int count;
	fr_pair_t *vp;

	fr_pair_list_init(local_pairs);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32);
	fr_assert(vp != NULL);
	fr_pair_append(local_pairs, vp);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_octets);
	fr_assert(vp != NULL);
	fr_pair_append(local_pairs, vp);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_tlv);
	fr_assert(vp != NULL);
	fr_pair_append(local_pairs, vp);

	count = fr_pair_list_num_elements(local_pairs);
	TEST_CASE("Expected (count == 3)");
	TEST_CHECK(count == 3);
}

static void expect3(fr_pair_list_t *local_pairs)
{
	int count;
	fr_pair_t *vp;

	count = fr_pair_list_num_elements(local_pairs);
	TEST_CASE("Expected (count == 3) after undoing the edits");
	TEST_CHECK(count == 3);

	vp = fr_pair_list_head(local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);

	vp = fr_pair_list_tail(local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_tlv);

	fr_pair_list_free(local_pairs);
}

/*
 *	Tests functions
 */
static void test_pair_delete_head(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and delete the first one");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_pair_delete(el, &local_pairs, vp);
	TEST_CHECK(rcode == 0);

	fr_edit_list_commit(el);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 2) after deleting the head");
	TEST_CHECK(count == 2);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CASE("head is now what was the second pair");
	TEST_CHECK(vp->da == fr_dict_attr_test_octets);

	fr_pair_list_free(&local_pairs);
}

static void test_pair_delete_head_abort(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and delete the first one");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_pair_delete(el, &local_pairs, vp);
	TEST_CHECK(rcode == 0);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 2) after deleting the head");
	TEST_CHECK(count == 2);

	/*
	 *	Abort the edit
	 */
	fr_edit_list_abort(el);

	expect3(&local_pairs);
}

static void test_pair_delete_middle(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and delete the middle one");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	vp = fr_pair_list_next(&local_pairs, vp);
	fr_assert(vp != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_pair_delete(el, &local_pairs, vp);
	TEST_CHECK(rcode == 0);

	fr_edit_list_commit(el);

	/* let's count */
	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 2) after deleting the middle");
	TEST_CHECK(count == 2);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);

	vp = fr_pair_list_tail(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_tlv);

	fr_pair_list_free(&local_pairs);
}

static void test_pair_delete_middle_abort(void)
{
	fr_pair_t	*vp, *middle;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and delete the middle one, then abort");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	middle = fr_pair_list_next(&local_pairs, vp);
	fr_assert(middle != NULL);
	TEST_CHECK(middle->da == fr_dict_attr_test_octets);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_pair_delete(el, &local_pairs, middle);
	TEST_CHECK(rcode == 0);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 2) after deleting the middle");
	TEST_CHECK(count == 2);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);

	vp = fr_pair_list_tail(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_tlv);

	/*
	 *	Abort the edit
	 */
	fr_edit_list_abort(el);

	expect3(&local_pairs);
}

static void test_pair_delete_multiple(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and delete the last 2");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	vp = fr_pair_list_next(&local_pairs, vp);
	fr_assert(vp != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_pair_delete(el, &local_pairs, vp); /* middle */
	TEST_CHECK(rcode == 0);

	vp = fr_pair_list_tail(&local_pairs);
	fr_assert(vp != NULL);

	rcode = fr_edit_list_pair_delete(el, &local_pairs, vp); /* tail */
	TEST_CHECK(rcode == 0);

	fr_edit_list_commit(el);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 1) after deleting the last 2");
	TEST_CHECK(count == 1);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);

	vp = fr_pair_list_tail(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32); /* head == tail */

	fr_pair_list_free(&local_pairs);
}

static void test_pair_delete_multiple_abort(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and delete the last two, then abort");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	fr_assert(vp != NULL);
	vp = fr_pair_list_next(&local_pairs, vp);
	fr_assert(vp != NULL);
	TEST_CHECK(vp->da == fr_dict_attr_test_octets);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_pair_delete(el, &local_pairs, vp); /* middle */
	TEST_CHECK(rcode == 0);

	vp = fr_pair_list_tail(&local_pairs);
	fr_assert(vp != NULL);

	rcode = fr_edit_list_pair_delete(el, &local_pairs, vp); /* tail */
	TEST_CHECK(rcode == 0);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 1) after deleting the last 2");
	TEST_CHECK(count == 1);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);

	vp = fr_pair_list_tail(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);

	/*
	 *	Abort the edit
	 */
	fr_edit_list_abort(el);

	expect3(&local_pairs);
}


static void test_pair_edit_value(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and change the value of the first one");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	fr_assert(vp != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_save_pair_value(el, vp);
	TEST_CHECK(rcode == 0);

	TEST_CHECK(vp->vp_uint32 == 0);

	vp->vp_uint32 = 1;
	TEST_CHECK(vp->vp_uint32 == 1);

	fr_edit_list_commit(el);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);
	TEST_CHECK(vp->vp_uint32 == 1);

	expect3(&local_pairs);
}

static void test_pair_edit_value_abort(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and change the value of the first one, then abort");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	fr_assert(vp != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_save_pair_value(el, vp);
	TEST_CHECK(rcode == 0);

	TEST_CHECK(vp->vp_uint32 == 0);

	vp->vp_uint32 = 1;
	TEST_CHECK(vp->vp_uint32 == 1);

	/*
	 *	Abort the edit
	 */
	fr_edit_list_abort(el);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);
	TEST_CHECK(vp->vp_uint32 == 0);

	expect3(&local_pairs);
}

static void test_pair_insert_after_head(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and insert a new one at the head");

	add_pairs(&local_pairs);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string);
	fr_assert(vp != NULL);
	rcode = fr_edit_list_insert_pair_after(el, &local_pairs, NULL, vp);
	TEST_CHECK(rcode == 0);

	fr_edit_list_commit(el);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 4) after inserting a new one");
	TEST_CHECK(count == 4);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CASE("head is now what was the second pair");
	TEST_CHECK(vp->da == fr_dict_attr_test_string);

	fr_pair_list_free(&local_pairs);
}

static void test_pair_insert_after_head_abort(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and insert a new one at the head, then abort");

	add_pairs(&local_pairs);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string);
	fr_assert(vp != NULL);
	rcode = fr_edit_list_insert_pair_after(el, &local_pairs, NULL, vp);
	TEST_CHECK(rcode == 0);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 4) after inserting a new one");
	TEST_CHECK(count == 4);

	/*
	 *	Abort the edit
	 */
	fr_edit_list_abort(el);

	expect3(&local_pairs);
}

static void test_pair_insert_after_middle(void)
{
	fr_pair_t	*vp, *middle;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and insert a new one at the head");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	middle = fr_pair_list_next(&local_pairs, vp);
	fr_assert(middle != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string);
	fr_assert(vp != NULL);
	rcode = fr_edit_list_insert_pair_after(el, &local_pairs, middle, vp);
	TEST_CHECK(rcode == 0);

	fr_edit_list_commit(el);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 4) after inserting a new one");
	TEST_CHECK(count == 4);

	fr_pair_list_free(&local_pairs);
}

static void test_pair_insert_after_middle_abort(void)
{
	fr_pair_t	*vp, *middle;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and insert a new one at the head, then abort");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	middle = fr_pair_list_next(&local_pairs, vp);
	fr_assert(middle != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string);
	fr_assert(vp != NULL);
	rcode = fr_edit_list_insert_pair_after(el, &local_pairs, middle, vp);
	TEST_CHECK(rcode == 0);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 4) after inserting a new one");
	TEST_CHECK(count == 4);

	/*
	 *	Abort the edit
	 */
	fr_edit_list_abort(el);

	expect3(&local_pairs);
}

static void test_pair_edit_value_delete(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	fr_edit_list_t	*el;
	int		rcode, count;

	TEST_CASE("Add 3 pairs, change the value of the first one, and delete it");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	fr_assert(vp != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_save_pair_value(el, vp);
	TEST_CHECK(rcode == 0);

	TEST_CHECK(vp->vp_uint32 == 0);

	vp->vp_uint32 = 1;
	TEST_CHECK(vp->vp_uint32 == 1);

	rcode = fr_edit_list_pair_delete(el, &local_pairs, vp);
	TEST_CHECK(rcode == 0);

	fr_edit_list_commit(el);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_octets);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 2) after deleting the edited pair");
	TEST_CHECK(count == 2);
}

static void test_pair_edit_value_delete_abort(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs, change the value of the first one, and delete it, then abort");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	fr_assert(vp != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_save_pair_value(el, vp);
	TEST_CHECK(rcode == 0);

	TEST_CHECK(vp->vp_uint32 == 0);

	vp->vp_uint32 = 1;
	TEST_CHECK(vp->vp_uint32 == 1);

	rcode = fr_edit_list_pair_delete(el, &local_pairs, vp);
	TEST_CHECK(rcode == 0);

	/*
	 *	Abort the edit
	 */
	fr_edit_list_abort(el);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);
	TEST_CHECK(vp->vp_uint32 == 0);

	expect3(&local_pairs);
}

static void test_pair_insert_after_head_delete(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and insert a new one at the head, and delete it");

	add_pairs(&local_pairs);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string);
	fr_assert(vp != NULL);
	rcode = fr_edit_list_insert_pair_after(el, &local_pairs, NULL, vp);
	TEST_CHECK(rcode == 0);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 4) after inserting a new one");
	TEST_CHECK(count == 4);

	rcode = fr_edit_list_pair_delete(el, &local_pairs, vp);
	TEST_CHECK(rcode == 0);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 3) after deleting the just inserted on");
	TEST_CHECK(count == 3);

	fr_edit_list_commit(el);

	expect3(&local_pairs);
}

static void test_pair_insert_after_head_delete_abort(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and insert a new one at the head and delete it, then abort");

	add_pairs(&local_pairs);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string);
	fr_assert(vp != NULL);
	rcode = fr_edit_list_insert_pair_after(el, &local_pairs, NULL, vp);
	TEST_CHECK(rcode == 0);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 4) after inserting a new one");
	TEST_CHECK(count == 4);

	/*
	 *	Abort the edit
	 */
	fr_edit_list_abort(el);

	expect3(&local_pairs);
}


static void test_pair_edit_child_value(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	fr_edit_list_t	*el, *child;
	int		rcode;

	TEST_CASE("Add 3 pairs and change the value of the first one in a child transaction");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	fr_assert(vp != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_save_pair_value(el, vp);
	TEST_CHECK(rcode == 0);

	TEST_CHECK(vp->vp_uint32 == 0);

	vp->vp_uint32 = 1;
	TEST_CHECK(vp->vp_uint32 == 1);

	child = fr_edit_list_alloc(NULL, 5, el);
	fr_assert(child != NULL);

	rcode = fr_edit_list_save_pair_value(child, vp); /* CHILD */
	TEST_CHECK(rcode == 0);

	TEST_CHECK(vp->vp_uint32 == 1);

	vp->vp_uint32 = 2;
	TEST_CHECK(vp->vp_uint32 == 2);

	fr_edit_list_commit(child); /* should do nothing */

	TEST_CHECK(vp->vp_uint32 == 2);

	fr_edit_list_commit(el);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);
	TEST_CHECK(vp->vp_uint32 == 2);

	expect3(&local_pairs);
}

static void test_pair_edit_child_value_abort(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	fr_edit_list_t	*el, *child;
	int		rcode;

	TEST_CASE("Add 3 pairs and change the value of the first one, then abort");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	fr_assert(vp != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_save_pair_value(el, vp);
	TEST_CHECK(rcode == 0);

	TEST_CHECK(vp->vp_uint32 == 0);

	vp->vp_uint32 = 1;
	TEST_CHECK(vp->vp_uint32 == 1);

	child = fr_edit_list_alloc(NULL, 5, el);
	fr_assert(child != NULL);

	rcode = fr_edit_list_save_pair_value(child, vp); /* CHILD */
	TEST_CHECK(rcode == 0);

	TEST_CHECK(vp->vp_uint32 == 1);

	vp->vp_uint32 = 2;
	TEST_CHECK(vp->vp_uint32 == 2);

	fr_edit_list_abort(child); /* CHILD */

	TEST_CHECK(vp->vp_uint32 == 1);

	fr_edit_list_commit(el);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);
	TEST_CHECK(vp->vp_uint32 == 1);

	expect3(&local_pairs);
}

static void test_pair_delete_tail(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and delete the tail");

	add_pairs(&local_pairs);

	vp = fr_pair_list_tail(&local_pairs);
	fr_assert(vp != NULL);
	TEST_CHECK(vp->da == fr_dict_attr_test_tlv);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_pair_delete(el, &local_pairs, vp);
	TEST_CHECK(rcode == 0);

	fr_edit_list_commit(el);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 2) after deleting the tail");
	TEST_CHECK(count == 2);

	vp = fr_pair_list_tail(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_octets);

	fr_pair_list_free(&local_pairs);
}

static void test_pair_delete_tail_abort(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and delete the tail, then abort");

	add_pairs(&local_pairs);

	vp = fr_pair_list_tail(&local_pairs);
	fr_assert(vp != NULL);
	TEST_CHECK(vp->da == fr_dict_attr_test_tlv);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_pair_delete(el, &local_pairs, vp);
	TEST_CHECK(rcode == 0);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CHECK(count == 2);

	fr_edit_list_abort(el);

	expect3(&local_pairs);
}

static void test_pair_delete_by_da(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add pairs and delete all with a matching da");

	add_pairs(&local_pairs);

	/* Add another uint32 at the tail */
	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32);
	fr_assert(vp != NULL);
	vp->vp_uint32 = 42;
	fr_pair_append(&local_pairs, vp);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CHECK(count == 4);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_pair_delete_by_da(el, &local_pairs, fr_dict_attr_test_uint32);
	TEST_CHECK(rcode == 0);

	fr_edit_list_commit(el);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 2) after deleting all uint32 pairs");
	TEST_CHECK(count == 2);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_octets);

	vp = fr_pair_list_tail(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_tlv);

	fr_pair_list_free(&local_pairs);
}

static void test_pair_delete_by_da_abort(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add pairs and delete all with a matching da, then abort");

	add_pairs(&local_pairs);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32);
	fr_assert(vp != NULL);
	vp->vp_uint32 = 42;
	fr_pair_append(&local_pairs, vp);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CHECK(count == 4);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_pair_delete_by_da(el, &local_pairs, fr_dict_attr_test_uint32);
	TEST_CHECK(rcode == 0);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CHECK(count == 2);

	fr_edit_list_abort(el);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 4) after aborting the delete");
	TEST_CHECK(count == 4);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);
	TEST_CHECK(vp->vp_uint32 == 0);

	vp = fr_pair_list_tail(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);
	TEST_CHECK(vp->vp_uint32 == 42);

	fr_pair_list_free(&local_pairs);
}

static void test_pair_replace_value(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	fr_edit_list_t	*el;
	int		rcode;
	fr_value_box_t	box;

	TEST_CASE("Add 3 pairs and replace the value of the first one");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	fr_assert(vp != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	TEST_CHECK(vp->vp_uint32 == 0);

	fr_value_box_init(&box, FR_TYPE_UINT32, NULL, false);
	box.vb_uint32 = 42;

	rcode = fr_edit_list_replace_pair_value(el, vp, &box);
	TEST_CHECK(rcode == 0);
	TEST_CHECK(vp->vp_uint32 == 42);

	fr_edit_list_commit(el);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);
	TEST_CHECK(vp->vp_uint32 == 42);

	expect3(&local_pairs);
}

static void test_pair_replace_value_abort(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	fr_edit_list_t	*el;
	int		rcode;
	fr_value_box_t	box;

	TEST_CASE("Add 3 pairs and replace the value of the first one, then abort");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	fr_assert(vp != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	TEST_CHECK(vp->vp_uint32 == 0);

	fr_value_box_init(&box, FR_TYPE_UINT32, NULL, false);
	box.vb_uint32 = 42;

	rcode = fr_edit_list_replace_pair_value(el, vp, &box);
	TEST_CHECK(rcode == 0);
	TEST_CHECK(vp->vp_uint32 == 42);

	fr_edit_list_abort(el);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);
	TEST_CHECK(vp->vp_uint32 == 0);

	expect3(&local_pairs);
}

static void test_pair_replace_pair(void)
{
	fr_pair_t	*vp, *new_vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and replace the head with a new pair");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	fr_assert(vp != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	new_vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32);
	fr_assert(new_vp != NULL);
	new_vp->vp_uint32 = 99;

	rcode = fr_edit_list_replace_pair(el, &local_pairs, vp, new_vp);
	TEST_CHECK(rcode == 0);

	fr_edit_list_commit(el);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 3) after replacing a pair");
	TEST_CHECK(count == 3);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);
	TEST_CHECK(vp->vp_uint32 == 99);

	fr_pair_list_free(&local_pairs);
}

static void test_pair_replace_pair_abort(void)
{
	fr_pair_t	*vp, *new_vp;
	fr_pair_list_t	local_pairs;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and replace the head, then abort");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	fr_assert(vp != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	new_vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint32);
	fr_assert(new_vp != NULL);
	new_vp->vp_uint32 = 99;

	rcode = fr_edit_list_replace_pair(el, &local_pairs, vp, new_vp);
	TEST_CHECK(rcode == 0);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->vp_uint32 == 99);

	fr_edit_list_abort(el);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);
	TEST_CHECK(vp->vp_uint32 == 0);

	expect3(&local_pairs);
}

static void test_pair_insert_after_tail(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and insert a new one at the tail");

	add_pairs(&local_pairs);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string);
	fr_assert(vp != NULL);
	rcode = fr_edit_list_insert_pair_tail(el, &local_pairs, vp);
	TEST_CHECK(rcode == 0);

	fr_edit_list_commit(el);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 4) after inserting at the tail");
	TEST_CHECK(count == 4);

	vp = fr_pair_list_tail(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_string);

	fr_pair_list_free(&local_pairs);
}

static void test_pair_insert_after_tail_abort(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and insert a new one at the tail, then abort");

	add_pairs(&local_pairs);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string);
	fr_assert(vp != NULL);
	rcode = fr_edit_list_insert_pair_tail(el, &local_pairs, vp);
	TEST_CHECK(rcode == 0);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CHECK(count == 4);

	fr_edit_list_abort(el);

	expect3(&local_pairs);
}

static void test_pair_free_children(void)
{
	fr_pair_t	*vp, *child;
	fr_pair_list_t	local_pairs;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add children to a TLV pair and free them");

	add_pairs(&local_pairs);

	vp = fr_pair_list_tail(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_tlv);

	child = fr_pair_afrom_da(vp, fr_dict_attr_test_tlv_string);
	fr_assert(child != NULL);
	fr_pair_append(&vp->vp_group, child);
	TEST_CHECK(fr_pair_list_num_elements(&vp->vp_group) == 1);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_free_pair_children(el, vp);
	TEST_CHECK(rcode == 0);
	TEST_CHECK(fr_pair_list_empty(&vp->vp_group));

	fr_edit_list_commit(el);

	TEST_CHECK(fr_pair_list_empty(&vp->vp_group));

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CHECK(count == 3);

	fr_pair_list_free(&local_pairs);
}

static void test_pair_free_children_abort(void)
{
	fr_pair_t	*vp, *child;
	fr_pair_list_t	local_pairs;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add children to a TLV pair, free them, then abort");

	add_pairs(&local_pairs);

	vp = fr_pair_list_tail(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_tlv);

	child = fr_pair_afrom_da(vp, fr_dict_attr_test_tlv_string);
	fr_assert(child != NULL);
	fr_pair_append(&vp->vp_group, child);
	TEST_CHECK(fr_pair_list_num_elements(&vp->vp_group) == 1);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_free_pair_children(el, vp);
	TEST_CHECK(rcode == 0);
	TEST_CHECK(fr_pair_list_empty(&vp->vp_group));

	fr_edit_list_abort(el);

	TEST_CHECK(fr_pair_list_num_elements(&vp->vp_group) == 1);

	child = fr_pair_list_head(&vp->vp_group);
	TEST_CHECK(child->da == fr_dict_attr_test_tlv_string);

	expect3(&local_pairs);
}

static void test_pair_insert_list_tail(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs, to_insert;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and insert a list of 2 at the tail");

	add_pairs(&local_pairs);

	fr_pair_list_init(&to_insert);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string);
	fr_assert(vp != NULL);
	fr_pair_append(&to_insert, vp);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint16);
	fr_assert(vp != NULL);
	fr_pair_append(&to_insert, vp);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_insert_list_tail(el, &local_pairs, &to_insert);
	TEST_CHECK(rcode == 0);

	fr_edit_list_commit(el);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CASE("Expected (count == 5) after inserting a list of 2");
	TEST_CHECK(count == 5);

	vp = fr_pair_list_tail(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint16);

	fr_pair_list_free(&local_pairs);
}

static void test_pair_insert_list_tail_abort(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs, to_insert;
	size_t		count;
	fr_edit_list_t	*el;
	int		rcode;

	TEST_CASE("Add 3 pairs and insert a list of 2 at the tail, then abort");

	add_pairs(&local_pairs);

	fr_pair_list_init(&to_insert);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_string);
	fr_assert(vp != NULL);
	fr_pair_append(&to_insert, vp);

	vp = fr_pair_afrom_da(autofree, fr_dict_attr_test_uint16);
	fr_assert(vp != NULL);
	fr_pair_append(&to_insert, vp);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_insert_list_tail(el, &local_pairs, &to_insert);
	TEST_CHECK(rcode == 0);

	count = fr_pair_list_num_elements(&local_pairs);
	TEST_CHECK(count == 5);

	fr_edit_list_abort(el);

	expect3(&local_pairs);
}

static void test_pair_edit_child_commit_parent_abort(void)
{
	fr_pair_t	*vp;
	fr_pair_list_t	local_pairs;
	fr_edit_list_t	*el, *child;
	int		rcode;

	TEST_CASE("Child commits value change, parent aborts - everything reverted");

	add_pairs(&local_pairs);

	vp = fr_pair_list_head(&local_pairs);
	fr_assert(vp != NULL);

	el = fr_edit_list_alloc(NULL, 5, NULL);
	fr_assert(el != NULL);

	rcode = fr_edit_list_save_pair_value(el, vp);
	TEST_CHECK(rcode == 0);

	TEST_CHECK(vp->vp_uint32 == 0);

	vp->vp_uint32 = 1;
	TEST_CHECK(vp->vp_uint32 == 1);

	child = fr_edit_list_alloc(NULL, 5, el);
	fr_assert(child != NULL);

	rcode = fr_edit_list_save_pair_value(child, vp);
	TEST_CHECK(rcode == 0);

	vp->vp_uint32 = 2;
	TEST_CHECK(vp->vp_uint32 == 2);

	fr_edit_list_commit(child); /* does nothing, value stays at 2 */
	TEST_CHECK(vp->vp_uint32 == 2);

	/* Abort parent - everything should revert */
	fr_edit_list_abort(el);

	vp = fr_pair_list_head(&local_pairs);
	TEST_CHECK(vp->da == fr_dict_attr_test_uint32);
	TEST_CHECK(vp->vp_uint32 == 0);

	expect3(&local_pairs);
}

TEST_LIST = {
	/*
	 *	Deletion.
	 */
	{ "pair_delete_head",			test_pair_delete_head },
	{ "pair_delete_head_abort",		test_pair_delete_head_abort },

	{ "pair_delete_middle",			test_pair_delete_middle },
	{ "pair_delete_middle_abort",		test_pair_delete_middle_abort },

	{ "pair_delete_multiple",		test_pair_delete_multiple },
	{ "pair_delete_multiple_abort",		test_pair_delete_multiple_abort },

	/*
	 *	Insert after
	 */
	{ "pair_insert_after_head",    		test_pair_insert_after_head },
	{ "pair_insert_after_head_abort",      	test_pair_insert_after_head_abort },

	{ "pair_insert_after_middle",    	test_pair_insert_after_middle },
	{ "pair_insert_after_middle_abort",     test_pair_insert_after_middle_abort },

	/*
	 *	Value modification
	 */
	{ "pair_edit_value",			test_pair_edit_value },
	{ "pair_edit_value_abort",		test_pair_edit_value_abort },

	/*
	 *	Value modification, then deletion
	 */
	{ "pair_edit_value_delete",		test_pair_edit_value_delete },
	{ "pair_edit_value_delete_abort",	test_pair_edit_value_delete_abort },

	/*
	 *	Insert after, then delete
	 */
	{ "pair_insert_after_head_delete",    	 test_pair_insert_after_head_delete },
	{ "pair_insert_after_head_delete_abort", test_pair_insert_after_head_delete_abort },

	/*
	 *	Value modification in child list
	 */
	{ "pair_edit_child_value",		test_pair_edit_child_value },
	{ "pair_edit_child_value_abort",	test_pair_edit_child_value_abort },

	/*
	 *	Deletion of tail
	 */
	{ "pair_delete_tail",			test_pair_delete_tail },
	{ "pair_delete_tail_abort",		test_pair_delete_tail_abort },

	/*
	 *	Deletion by da
	 */
	{ "pair_delete_by_da",			test_pair_delete_by_da },
	{ "pair_delete_by_da_abort",		test_pair_delete_by_da_abort },

	/*
	 *	Value replacement (fr_edit_list_replace_pair_value)
	 */
	{ "pair_replace_value",			test_pair_replace_value },
	{ "pair_replace_value_abort",		test_pair_replace_value_abort },

	/*
	 *	Pair replacement (fr_edit_list_replace_pair)
	 */
	{ "pair_replace_pair",			test_pair_replace_pair },
	{ "pair_replace_pair_abort",		test_pair_replace_pair_abort },

	/*
	 *	Insert at tail
	 */
	{ "pair_insert_after_tail",		test_pair_insert_after_tail },
	{ "pair_insert_after_tail_abort",	test_pair_insert_after_tail_abort },

	/*
	 *	Free children of structural pair
	 */
	{ "pair_free_children",			test_pair_free_children },
	{ "pair_free_children_abort",		test_pair_free_children_abort },

	/*
	 *	Insert list at tail
	 */
	{ "pair_insert_list_tail",		test_pair_insert_list_tail },
	{ "pair_insert_list_tail_abort",	test_pair_insert_list_tail_abort },

	/*
	 *	Child commit + parent abort
	 */
	{ "pair_edit_child_commit_parent_abort", test_pair_edit_child_commit_parent_abort },

	TEST_TERMINATOR
};
