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

/** Tests for miscellaneous utility functions
 *
 * @file src/lib/util/test/misc_tests.c
 *
 * @copyright 2026 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
#include "acutest.h"

#include <freeradius-devel/util/misc.h>

static bool poisoned;

static fr_cmp_ret_t _int_ptr_cmp(void const *one, void const *two)
{
	int const *a = one, *b = two;

	if (poisoned) {
		fr_strerror_const("Poisoned comparator");
		return CMP_ERR;
	}

	return CMP(*a, *b);
}

/*
 *	A comparator returning CMP_ERR must leave the array a
 *	permutation of its input (order undefined), and report the
 *	error through the int return.
 */
static void test_quick_sort_cmp_err(void)
{
	int		values[8] = { 5, 1, 7, 3, 0, 6, 2, 4 };
	int const	*to_sort[8];
	bool		seen[8];
	size_t		i;

	TEST_CASE("comparator error leaves the array a permutation");
	for (i = 0; i < NUM_ELEMENTS(values); i++) {
		to_sort[i] = &values[i];
	}

	poisoned = true;
	TEST_CHECK(fr_quick_sort((void const **)to_sort, 0, NUM_ELEMENTS(to_sort) - 1, _int_ptr_cmp) == -1);

	/*
	 *	Every original element must appear exactly once.
	 */
	for (i = 0; i < NUM_ELEMENTS(seen); i++) {
		seen[i] = false;
	}
	for (i = 0; i < NUM_ELEMENTS(to_sort); i++) {
		TEST_CHECK(*to_sort[i] >= 0 && *to_sort[i] < (int)NUM_ELEMENTS(seen));
		TEST_CHECK(!seen[*to_sort[i]]);
		seen[*to_sort[i]] = true;
	}

	/*
	 *	Once the comparator recovers the sort orders the array.
	 */
	poisoned = false;
	TEST_CHECK(fr_quick_sort((void const **)to_sort, 0, NUM_ELEMENTS(to_sort) - 1, _int_ptr_cmp) == 0);
	for (i = 0; i < NUM_ELEMENTS(to_sort); i++) {
		TEST_CHECK(*to_sort[i] == (int)i);
	}
}

TEST_LIST = {
	{ "fr_quick_sort_cmp_err",	test_quick_sort_cmp_err },

	TEST_TERMINATOR
};
