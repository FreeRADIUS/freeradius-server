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

/** Functions to convert strings to integers and vice versa
 *
 * @file lib/util/table.c
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/misc.h>

/** Brute force search a sorted or ordered ptr table, assuming the pointers are strings
 *
 * @param[in] table		to search in.
 * @param[in] table_len		Number of elements in the table.
 * @param[in] str_val		to compare against the ptr field.
 * @param[in] def		default value.
 */
char const *_fr_table_ptr_by_str_value(fr_table_ptr_sorted_t const *table, size_t table_len, char const *str_val, char const *def)
{
	size_t		i;

	if (!str_val) return NULL;

	for (i = 0; i < table_len; i++) if (strcasecmp(str_val, table[i].value) == 0) return table[i].name.str;

	return def;
}

TABLE_TYPE_NAME_FUNC(table_sorted_value_by_str, fr_table_num_sorted_t const *,
		    fr_table_sorted_num_by_str, int, int)
TABLE_TYPE_NAME_FUNC(table_sorted_value_by_str, fr_table_ptr_sorted_t const *,
		    fr_table_sorted_ptr_by_str, void const *, void *)

TABLE_TYPE_NAME_FUNC(table_ordered_value_by_str, fr_table_num_ordered_t const *,
		    fr_table_ordered_num_by_str, int, int)
TABLE_TYPE_NAME_FUNC(table_ordered_value_by_str, fr_table_ptr_ordered_t const *,
		    fr_table_ordered_ptr_by_str, void const *, void *)

TABLE_TYPE_NAME_LEN_FUNC(table_sorted_value_by_substr, fr_table_num_sorted_t const *,
			fr_table_sorted_num_by_substr, int, int)
TABLE_TYPE_NAME_LEN_FUNC(table_sorted_value_by_substr, fr_table_ptr_sorted_t const *,
			fr_table_sorted_ptr_by_substr, void const *, void *)

TABLE_TYPE_NAME_LEN_FUNC(table_ordered_value_by_substr, fr_table_num_ordered_t const *,
			fr_table_ordered_num_by_substr, int, int)
TABLE_TYPE_NAME_LEN_FUNC(table_ordered_value_by_substr, fr_table_ptr_ordered_t const *,
			 fr_table_ordered_ptr_by_substr, void const *, void *)

TABLE_TYPE_NAME_MATCH_LEN_FUNC(table_sorted_value_by_longest_prefix, fr_table_num_sorted_t const *,
			      fr_table_sorted_num_by_longest_prefix, int, int)
TABLE_TYPE_NAME_MATCH_LEN_FUNC(table_sorted_value_by_longest_prefix, fr_table_ptr_sorted_t const *,
			      fr_table_sorted_ptr_by_longest_prefix, void const *, void *)

TABLE_TYPE_NAME_MATCH_LEN_FUNC(table_ordered_value_by_longest_prefix, fr_table_num_ordered_t const *,
			      fr_table_ordered_num_by_longest_prefix, int, int)
TABLE_TYPE_NAME_MATCH_LEN_FUNC(table_ordered_value_by_longest_prefix, fr_table_ptr_ordered_t const *,
			      fr_table_ordered_ptr_by_longest_prefix, void const *, void *)

/*
 *	Value to string conversion functions
 */
TABLE_TYPE_VALUE_FUNC(fr_table_num_sorted_t const *, fr_table_sorted_str_by_num, int)
TABLE_TYPE_VALUE_FUNC(fr_table_num_ordered_t const *, fr_table_ordered_str_by_num, int)
TABLE_TYPE_VALUE_FUNC(fr_table_ptr_sorted_t const *, fr_table_sorted_str_by_ptr, void const *)
TABLE_TYPE_VALUE_FUNC(fr_table_ptr_ordered_t const *, fr_table_ordered_str_by_ptr, void const *)

/*
 *	Indexed value to string conversion functions
 *	These are O(1) for bitfields, and are
 *	particularly useful for looking up string
 *	definitions for flag values.
 */
TABLE_TYPE_VALUE_INDEX_BIT_FIELD_FUNC(fr_table_num_indexed_bit_pos_t const *, fr_table_indexed_str_by_bit_field, uint64_t)

/*
 *	Array lookup based on numeric value
 */
TABLE_TYPE_VALUE_INDEX_FUNC(fr_table_num_indexed_t const *, fr_table_indexed_str_by_num, unsigned int)
