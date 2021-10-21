#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Helper functions for pair tests
 *
 * @file src/lib/util/pair_test_helpers.h
 *
 * @copyright 2021 The FreeRADIUS server project
 */
RCSIDH(pair_test_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/dict_test.h>

DIAG_OFF(unused-variable)
static char const       *test_string = "We love testing!";
static size_t           test_string_len = 16;
static uint8_t          test_octets[] = {
				0x53, 0x65, 0x20, 0x6c, 0x6f, 0x76, 0x65,
				0x20, 0x74, 0x65, 0x69, 0x74, 0x20, 0x41,
				0x63, 0x61, 0x64, 0x65, 0x6d, 0x79, 0x0a
			};
DIAG_ON(unused-variable)

static inline int fr_pair_test_list_alloc(TALLOC_CTX *ctx, fr_pair_list_t *out,
					  fr_dict_test_attr_t const *test_defs)
{
	fr_dict_test_attr_t const *p;

	if (!test_defs) test_defs = fr_dict_test_attrs;

	fr_pair_list_init(out);

	for (p = test_defs;
	     p->attr != -1;
	     p++) if (fr_pair_prepend_by_da(ctx, NULL, out, *p->da) < 0) return -1;

	return 0;
}

#ifdef __cplusplus
}
#endif
