/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/section.c
 * @brief Comparison functions for sections
 *
 * @copyright 2024 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/server/section.h>
#include <freeradius-devel/server/cf_util.h>

#define IDENT_ANY_CMP(_a, _b) \
	(((_a) == CF_IDENT_ANY) < ((_b) == CF_IDENT_ANY)) - (((_a) == CF_IDENT_ANY) > ((_b) == CF_IDENT_ANY))

#define NULL_CMP(_a, _b) \
	(((_a) == NULL) < ((_b) == NULL)) - (((_a) == NULL) > ((_b) == NULL))

/** Compare two sections
 *
 * - Sections are sorted by name1, then name2.
 * - NULLs sort before non-NULLs.
 * - CF_IDENT_ANY sort after non-CF_IDENT_ANY.
 * - Any other comparisons are lexicographic.
 *
 * @param[in] one		First section name.
 * @param[in] two		Second section name.
 *
 * @return < 0 if one < two, 0 if one == two, > 0 if one > two.
 */
int8_t section_name_cmp(void const *one, void const *two)
{
	section_name_t const *a = one;
	section_name_t const *b = two;
	int ret;

	/*
	 *	name1 isn't allowed to be NULL, for wildcard matches
	 *	we use CF_IDENT_ANY.
	 */
	fr_assert(a->name1 && b->name1);

	/*
	 *	Straight comparison between sections.
	 */
	ret = CMP(a, b);
	if (ret == 0) return 0;

	/*
	 *	Fastpath for static strings and CF_IDENT_ANY
	 */
	if (a->name1 == b->name1) goto name2;

	/*
	 *	If either identifier is CF_IDENT_ANY, we can't strcmp.
	 */
	if ((a->name1 == CF_IDENT_ANY) || (b->name1 == CF_IDENT_ANY)) {
		ret = IDENT_ANY_CMP(b->name1, a->name1);
		if (ret != 0) return ret;
	} else {
		ret = strcmp(a->name1, b->name1);
		if (ret != 0) return CMP(ret, 0);
	}

name2:
	/*
	 *	Second identifier can be NULL.
	 *
	 *	NULL name2s sort first.
	 */
	ret = NULL_CMP(a->name2, b->name2);
	if (ret != 0) return ret;

	if (a->name2 == b->name2) return 0;

	if ((a->name2 == CF_IDENT_ANY) || (b->name2 == CF_IDENT_ANY)) {
		return IDENT_ANY_CMP(b->name2, a->name2); /* Can't strcmp */
	}

	return CMP(strcmp(a->name2, b->name2), 0);
}
