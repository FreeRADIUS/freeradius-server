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

/** Tests for the dlist API
 *
 * @file src/lib/util/dlist_tests.c
 *
 * @copyright 2021 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

#include <freeradius-devel/util/acutest.h>
#include <freeradius-devel/util/acutest_helpers.h>

#include "dlist.h"

typedef struct {
	char const	*id;
	fr_dlist_t	entry;
} dlist_test_item_t;

static void test_dlist_move(void)
{
	fr_dlist_head_t a_list, b_list;

	dlist_test_item_t	a1 = { .id = "a1" };
	dlist_test_item_t	a2 = { .id = "a2" };
	dlist_test_item_t	b1 = { .id = "b1" };
	dlist_test_item_t	b2 = { .id = "b2" };
	dlist_test_item_t	*p;

	TEST_CASE("Two items - Merge");
	fr_dlist_init(&a_list, dlist_test_item_t, entry);
	fr_dlist_init(&b_list, dlist_test_item_t, entry);

	fr_dlist_insert_tail(&a_list, &a1);
	fr_dlist_insert_tail(&a_list, &a2);

	fr_dlist_insert_tail(&b_list, &b1);
	fr_dlist_insert_tail(&b_list, &b2);

	fr_dlist_move(&a_list, &b_list);

	TEST_CHECK_LEN(fr_dlist_num_elements(&a_list), 4);
	TEST_CHECK_LEN(fr_dlist_num_elements(&b_list), 0);

	TEST_CASE("Two items - Linking is correct running forwards");
	p = fr_dlist_head(&a_list);
	TEST_CHECK_STRCMP(p->id, "a1");
	p = fr_dlist_next(&a_list, p);
	TEST_CHECK_STRCMP(p->id, "a2");
	p = fr_dlist_next(&a_list, p);
	TEST_CHECK_STRCMP(p->id, "b1");
	p = fr_dlist_next(&a_list, p);
	TEST_CHECK_STRCMP(p->id, "b2");

	p = fr_dlist_next(&a_list, p);
	TEST_CHECK(p == NULL);

	TEST_CASE("Two items - Linking is correct running backwards");
	p = fr_dlist_tail(&a_list);
	TEST_CHECK_STRCMP(p->id, "b2");
	p = fr_dlist_prev(&a_list, p);
	TEST_CHECK_STRCMP(p->id, "b1");
	p = fr_dlist_prev(&a_list, p);
	TEST_CHECK_STRCMP(p->id, "a2");
	p = fr_dlist_prev(&a_list, p);
	TEST_CHECK_STRCMP(p->id, "a1");

	p = fr_dlist_prev(&a_list, p);
	TEST_CHECK(p == NULL);

	TEST_CASE("Two items - Old list is really empty");
	TEST_CHECK(fr_dlist_head(&b_list) == NULL);
	TEST_CHECK(fr_dlist_tail(&b_list) == NULL);

	TEST_CASE("One item - Merge");
	fr_dlist_init(&a_list, dlist_test_item_t, entry);
	fr_dlist_init(&b_list, dlist_test_item_t, entry);

	fr_dlist_insert_tail(&a_list, &a1);
	fr_dlist_insert_tail(&b_list, &b1);

	fr_dlist_move(&a_list, &b_list);
	TEST_CHECK_LEN(fr_dlist_num_elements(&a_list), 2);
	TEST_CHECK_LEN(fr_dlist_num_elements(&b_list), 0);

	TEST_CASE("One item - Linking is correct running forwards");
	p = fr_dlist_head(&a_list);
	TEST_CHECK_STRCMP(p->id, "a1");
	p = fr_dlist_next(&a_list, p);
	TEST_CHECK_STRCMP(p->id, "b1");
	p = fr_dlist_next(&a_list, p);
	TEST_CHECK(p == NULL);

	TEST_CASE("One item - Linking is correct running backwards");
	p = fr_dlist_tail(&a_list);
	TEST_CHECK_STRCMP(p->id, "b1");
	p = fr_dlist_prev(&a_list, p);
	TEST_CHECK_STRCMP(p->id, "a1");
	p = fr_dlist_prev(&a_list, p);
	TEST_CHECK(p == NULL);

	TEST_CASE("One item - Old list is really empty");
	TEST_CHECK(fr_dlist_head(&b_list) == NULL);
	TEST_CHECK(fr_dlist_tail(&b_list) == NULL);

}

static void test_dlist_entry_move(void)
{
	dlist_test_item_t	a1 = { .id = "a1" };
	dlist_test_item_t	a2 = { .id = "a2" };
	dlist_test_item_t	a3 = { .id = "a3" };
	dlist_test_item_t	b1 = { .id = "b1" };
	dlist_test_item_t	b2 = { .id = "b2" };
	dlist_test_item_t	b3 = { .id = "b3" };

	a1.entry.next = &a2.entry;
	a1.entry.prev = &a3.entry;
	a2.entry.next = &a3.entry;
	a2.entry.prev = &a1.entry;
	a3.entry.next = &a1.entry;
	a3.entry.prev = &a2.entry;

	b1.entry.next = &b2.entry;
	b1.entry.prev = &b3.entry;
	b2.entry.next = &b3.entry;
	b2.entry.prev = &b1.entry;
	b3.entry.next = &b1.entry;
	b3.entry.prev = &b2.entry;

	TEST_CASE("Three items - Merge");
	fr_dlist_entry_move(&a1.entry, &b1.entry);

	TEST_CASE("Three items - Linking is correct running forwards");
	TEST_CHECK(a1.entry.next == &a2.entry);
	TEST_CHECK(a2.entry.next == &a3.entry);
	TEST_CHECK(a3.entry.next == &b1.entry);
	TEST_CHECK(b1.entry.next == &b2.entry);
	TEST_CHECK(b2.entry.next == &b3.entry);
	TEST_CHECK(b3.entry.next == &a1.entry);

	TEST_CASE("Three items - Linking is correct running backwards");
	TEST_CHECK(a1.entry.prev == &b3.entry);
	TEST_CHECK(b3.entry.prev == &b2.entry);
	TEST_CHECK(b2.entry.prev == &b1.entry);
	TEST_CHECK(b1.entry.prev == &a3.entry);
	TEST_CHECK(a3.entry.prev == &a2.entry);
	TEST_CHECK(a2.entry.prev == &a1.entry);
}

TEST_LIST = {
	/*
	 *	Allocation and management
	 */
	{ "fr_dlist_move",		test_dlist_move		},
	{ "fr_dlist_entry_move",	test_dlist_entry_move	},


	{ NULL }
};
