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

#include <string.h>
#include <stdio.h>

#define TABLE_IDX(_table, _idx, _element_size) (((uint8_t const *)(_table)) + ((_idx) * (_element_size)))
#define ELEM_NAME(_offset) *((char const * const *)(_offset))

/** Create type specific string to value functions
 *
 * @param[in] _func		used for searching.
 * @param[in] _our_table_type	that we'll be searching in.
 * @param[in] _our_name		The function that we'll be creating.
 * @param[in] _our_def_type	The type of the default value.
 * @param[in] _our_return_type	What we return.
 */
#define TABLE_TYPE_STR_FUNC(_func, _our_table_type, _our_name, _our_def_type, _our_return_type) \
_our_return_type _our_name(_our_table_type table, size_t table_len, char const *name, _our_def_type def) \
{ \
	_our_return_type ret; \
	_our_table_type found; \
	found = (_our_table_type)_func(table, table_len, sizeof(((_our_table_type)0)[0]), name); \
	if (!found) { \
		memcpy(&ret, &def, sizeof(ret)); \
		return ret; \
	} \
	memcpy(&ret, &found->value, sizeof(ret)); \
	return ret; \
}

/** Create type specific string to value functions with an input string length argument
 *
 * @param[in] _func		used for searching.
 * @param[in] _our_table_type	that we'll be searching in.
 * @param[in] _our_name		The function that we'll be creating.
 * @param[in] _our_def_type	The type of the default value.
 * @param[in] _our_return_type	What we return.
 */
#define TABLE_TYPE_STR_LEN_FUNC(_func, _our_table_type, _our_name, _our_def_type, _our_return_type) \
_our_return_type _our_name(_our_table_type table, size_t table_len, char const *name, ssize_t name_len, _our_def_type def) \
{ \
	_our_return_type ret; \
	_our_table_type found; \
	found = (_our_table_type)_func(table, table_len, sizeof(((_our_table_type)0)[0]), name, name_len); \
	if (!found) { \
		memcpy(&ret, &def, sizeof(ret)); \
		return ret; \
	} \
	memcpy(&ret, &found->value, sizeof(ret)); \
	return ret; \
}

#define TABLE_TYPE_STR_MATCH_LEN_FUNC(_func, _our_table_type, _our_name, _our_def_type, _our_return_type) \
_our_return_type _our_name(size_t *match_len, _our_table_type table, size_t table_len, char const *name, ssize_t name_len, _our_def_type def) \
{ \
	_our_return_type ret; \
	_our_table_type found; \
	found = (_our_table_type)_func(match_len, table, table_len, sizeof(((_our_table_type)0)[0]), name, name_len); \
	if (!found) { \
		memcpy(&ret, &def, sizeof(ret)); \
		return ret; \
	} \
	memcpy(&ret, &found->value, sizeof(ret)); \
	return ret; \
}


#define TABLE_TYPE_VALUE_FUNC(_our_table_type, _our_name, _our_value_type) \
char const *_our_name(_our_table_type table, size_t table_len, _our_value_type value, char const *def) \
{ \
	size_t		i; \
	for (i = 0; i < table_len; i++) if (table[i].value == value) return table[i].name; \
	return def; \
}

#define TABLE_TYPE_VALUE_INDEX_BIT_FIELD_FUNC(_our_table_type, _our_name, _our_value_type) \
char const *_our_name(_our_table_type table, size_t table_len, _our_value_type value, char const *def) \
{ \
	uint8_t	idx = fr_high_bit_pos(value); \
	if (idx >= table_len) return def; \
	return table[idx].name; \
}

#define TABLE_TYPE_VALUE_INDEX_FUNC(_our_table_type, _our_name, _our_value_type) \
char const *_our_name(_our_table_type table, size_t table_len, _our_value_type value, char const *def) \
{ \
	if (value >= table_len) return def; \
	return table[value].name; \
}

/** Convert a string to a value using a lexicographically sorted table
 *
 * @param[in] table		to search in.
 * @param[in] table_len		The number of elements in the table.
 * @param[in] element_size		Size of elements in the table.
 * @param[in] name		to resolve to a value.
 * @return
 *	- value of matching entry.
 *      - NULL if no matching entries.
 */
static void const *table_sorted_value_by_str(void const *table, size_t table_len, size_t element_size,
					     char const *name)
{
	ssize_t	start = 0;
	ssize_t	end = table_len - 1;
	ssize_t	mid;

	int	ret;

	if (!name) return NULL;

	while (start <= end) {
		void const *offset;

		mid = start + ((end - start) / 2);	/* Avoid overflow */

		offset = TABLE_IDX(table, mid, element_size);
		ret = strcasecmp(name, ELEM_NAME(offset));
		if (ret == 0) return offset;
		if (ret < 0) {
			end = mid - 1;
		} else {
			start = mid + 1;
		}
	}

	return NULL;
}

TABLE_TYPE_STR_FUNC(table_sorted_value_by_str, fr_table_num_sorted_t const *,
		    fr_table_sorted_num_by_str, int, int)
TABLE_TYPE_STR_FUNC(table_sorted_value_by_str, fr_table_ptr_sorted_t const *,
		    fr_table_sorted_ptr_by_str, void const *, void *)

/** Convert a string to a value using an arbitrarily ordered table
 *
 * @param[in] table		to search in.
 * @param[in] table_len		The number of elements in the table.
 * @param[in] element_size	Size of elements in the table.
 * @param[in] name		to resolve to a number.
 * @return
 *	- value of matching entry.
 *      - NULL if no matching entries.
 */
static void const *table_ordered_value_by_str(void const *table, size_t table_len, size_t element_size,
					      char const *name)
{
	size_t		i;

	if (!name) return NULL;

	for (i = 0; i < table_len; i++) {
		void const *offset = TABLE_IDX(table, i, element_size);
		if (strcasecmp(name, ELEM_NAME(offset)) == 0) return offset;
	}

	return NULL;
}

TABLE_TYPE_STR_FUNC(table_ordered_value_by_str, fr_table_num_ordered_t const *,
		    fr_table_ordered_num_by_str, int, int)
TABLE_TYPE_STR_FUNC(table_ordered_value_by_str, fr_table_ptr_ordered_t const *,
		    fr_table_ordered_ptr_by_str, void const *, void *)

/** Convert a string matching part of name to an integer using a lexicographically sorted table
 *
 * @param[in] table		to search in.
 * @param[in] table_len		The number of elements in the table.
 * @param[in] element_size	Size of elements in the table.
 * @param[in] name		to locate.
 * @param[in] name_len		the maximum amount of name that should be matched.
 *				If < 0, the length of the name in the table offsetent
 *				will be used as the maximum match length.
 * @return
 *	- value of matching entry.
 *      - NULL if no matching entries.
 */
static void const *table_sorted_value_by_substr(void const *table, size_t table_len, size_t element_size,
						char const *name, ssize_t name_len)
{
	ssize_t	start = 0;
	ssize_t	end = table_len - 1;
	ssize_t	mid;

	int	ret;

	if (!name) return NULL;

	while (start <= end) {
		void const *offset;

		mid = start + ((end - start) / 2);	/* Avoid overflow */

		offset = TABLE_IDX(table, mid, element_size);

		/*
		 *	Match up to the length of the table entry if len is < 0.
		 */
		ret = strncasecmp(name, ELEM_NAME(offset),
				  (name_len < 0) ?  strlen(ELEM_NAME(offset)) : (size_t)name_len);
		if (ret == 0) return offset;

		if (ret < 0) {
			end = mid - 1;
		} else {
			start = mid + 1;
		}
	}

	return NULL;
}

TABLE_TYPE_STR_LEN_FUNC(table_sorted_value_by_substr, fr_table_num_sorted_t const *,
			fr_table_sorted_num_by_substr, int, int)
TABLE_TYPE_STR_LEN_FUNC(table_sorted_value_by_substr, fr_table_ptr_sorted_t const *,
			fr_table_sorted_ptr_by_substr, void const *, void *)

/** Convert a string matching part of name to an integer using an arbitrarily ordered table
 *
 * @param[in] table		to search in.
 * @param[in] table_len		The number of elements in the table.
 * @param[in] element_size	Size of elements in the table.
 * @param[in] name		to locate.
 * @param[in] name_len		the maximum amount of name that should be matched.
 *				If < 0, the length of the name in the table offsetent
 *				will be used as the maximum match length.
 * @return
 *	- value of matching entry.
 *      - NULL if no matching entries.
 */
static void const *table_ordered_value_by_substr(void const *table, size_t table_len, size_t element_size,
						 char const *name, ssize_t name_len)
{
	size_t		i;

	if (!name) return NULL;

	for (i = 0; i < table_len; i++) {
		void const	*offset;
		size_t		tlen;

		offset = TABLE_IDX(table, i, element_size);

		tlen = strlen(ELEM_NAME(offset));

		/*
		 *	Don't match "request" to user input "req".
		 */
		if ((name_len > 0) && (name_len < (int) tlen)) continue;

		/*
		 *	Match up to the length of the table entry if len is < 0.
		 */
		if (strncasecmp(name, ELEM_NAME(offset),
				(name_len < 0) ? tlen : (size_t)name_len) == 0) return offset;
	}

	return NULL;
}

TABLE_TYPE_STR_LEN_FUNC(table_ordered_value_by_substr, fr_table_num_ordered_t const *,
			fr_table_ordered_num_by_substr, int, int)
TABLE_TYPE_STR_LEN_FUNC(table_ordered_value_by_substr, fr_table_ptr_ordered_t const *,
			fr_table_ordered_ptr_by_substr, void const *, void *)

/** Find the longest string match using a lexicographically sorted table
 *
 * Performs a binary search in the specified table, returning the longest
 * offsetent which is a prefix of name.
 *
 * i.e. given name of "food", and table of f, foo, of - foo would be returned.
 *
 * @note The table *MUST* be sorted lexicographically, else the result may be incorrect.
 *
 * @param[out] match_len	How much of the input string matched.
 * @param[in] table		to search in.
 * @param[in] table_len		The number of elements in the table.
 * @param[in] element_size	Size of elements in the table.
 * @param[in] name		to locate.
 * @param[in] name_len		the maximum amount of name that should be matched.
 * @return
 *	- num value of matching entry.
 *      - NULL if no matching entries.
 */
static void const *table_sorted_value_by_longest_prefix(size_t *match_len,
							void const *table, size_t table_len, size_t element_size,
							char const *name, ssize_t name_len)
{
	ssize_t		start = 0;
	ssize_t		end = table_len - 1;
	ssize_t		mid;

	int		ret;
	void const	*found = NULL;

	if (!name) return NULL;
	if (name_len < 0) name_len = strlen(name);

	while (start <= end) {
		void const	*offset;
		char const	*elem;
		size_t		tlen;

		mid = start + ((end - start) / 2);	/* Avoid overflow */

		offset = TABLE_IDX(table, mid, element_size);
		elem = ELEM_NAME(offset);
		tlen = strlen(elem);

		ret = strncasecmp(name, elem, tlen < (size_t)name_len ? tlen : (size_t)name_len);
		if (ret == 0) {
			/*
			 *	Exact match
			 */
			if (tlen == (size_t)name_len) {
				if (match_len) *match_len = tlen;
				return offset;
			}

			/*
			 *	Partial match.
			 *	Name we're searching for is longer.
			 *	This might be the longest prefix,
			 *	so record it.
			 */
			if (tlen < (size_t)name_len) {
				found = offset;
				if (match_len) *match_len = tlen;
				ret = 1;
			} else {
				ret = -1;
			}
		}

		if (ret < 0) {
			end = mid - 1;
		} else {
			start = mid + 1;
		}
	}

	if (!found && match_len) *match_len = 0;

	return found;
}

TABLE_TYPE_STR_MATCH_LEN_FUNC(table_sorted_value_by_longest_prefix, fr_table_num_sorted_t const *,
			      fr_table_sorted_num_by_longest_prefix, int, int)
TABLE_TYPE_STR_MATCH_LEN_FUNC(table_sorted_value_by_longest_prefix, fr_table_ptr_sorted_t const *,
			      fr_table_sorted_ptr_by_longest_prefix, void const *, void *)

/** Find the longest string match using an arbitrarily ordered table
 *
 * i.e. given name of "food", and table of f, foo, of - foo would be returned.
 *
 * @param[out] match_len	How much of the input string matched.
 * @param[in] table		to search in.
 * @param[in] table_len		The number of elements in the table.
 * @param[in] element_size	Size of elements in the table.
 * @param[in] name		to locate.
 * @param[in] name_len		the maximum amount of name that should be matched.
 * @return
 *	- num value of matching entry.
 *      - def if no matching entries.
 */
static void const *table_ordered_value_by_longest_prefix(size_t *match_len,
							 void const *table, size_t table_len, size_t element_size,
							 char const *name, ssize_t name_len)
{
	size_t		i;
	size_t		found_len = 0;
	void const 	*found = NULL;

	if (!name) return NULL;
	if (name_len < 0) name_len = strlen(name);

	for (i = 0; i < table_len; i++) {
		void const	*offset;
		size_t		j;

		offset = TABLE_IDX(table, i, element_size);

		for (j = 0; (j < (size_t)name_len) && (name[j] == (ELEM_NAME(offset))[j]); j++);

		/*
		 *	If we didn't get to the end of the
		 *	table string, then continue.
		 */
		if ((ELEM_NAME(offset))[j] != '\0') continue;

		/*
		 *	Exact match
		 */
		if (j == (size_t)name_len) {
			if (match_len) *match_len = name_len;
			return offset;
		}

		/*
		 *	Partial match.
		 *	Name we're searching for is longer.
		 *	This might be the longest prefix,
		 *	so record it.
		 */
		if (j > found_len) {
			found_len = j;
			found = offset;
		}
	}

	if (match_len) *match_len = found_len;

	return found;
}

TABLE_TYPE_STR_MATCH_LEN_FUNC(table_ordered_value_by_longest_prefix, fr_table_num_ordered_t const *,
			      fr_table_ordered_num_by_longest_prefix, int, int)
TABLE_TYPE_STR_MATCH_LEN_FUNC(table_ordered_value_by_longest_prefix, fr_table_ptr_ordered_t const *,
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
