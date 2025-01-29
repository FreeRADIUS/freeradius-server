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

/**
 * $Id$
 *
 * @file lib/util/table.h
 * @brief Lookup table functions
 *
 * @copyright 2019 The FreeRADIUS server project
 * @copyright 2019 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(table_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <ctype.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

DIAG_OFF(unused-function)

typedef struct {
	char const		*str;	//!< Literal string.
	size_t			len;	//!< Literal string length.
} fr_table_elem_name_t;

/** An element in a lexicographically sorted array of name to num mappings
 *
 */
typedef struct {
	fr_table_elem_name_t	name;
	int			value;
} fr_table_num_sorted_t;

/** An element in an arbitrarily ordered array of name to num mappings
 *
 */
typedef struct {
	fr_table_elem_name_t	name;
	int			value;
} fr_table_num_ordered_t;

/** An element in a lexicographically sorted array of name to ptr mappings
 *
 */
typedef struct {
	fr_table_elem_name_t	name;
	void const		*value;
} fr_table_ptr_sorted_t;

/** An element in an arbitrarily ordered array of name to ptr mappings
 *
 */
typedef struct {
	fr_table_elem_name_t	name;
	void const		*value;
} fr_table_ptr_ordered_t;

/** An element in a table indexed by bit position
 *
 * i.e. if only the first bit is set in a bitfield, the entry at index 0
 * will be returned.
 */
typedef struct {
	fr_table_elem_name_t	name;
	uint64_t		value;
} fr_table_num_indexed_bit_pos_t;

/** An element in a table indexed by numeric value
 *
 * i.e. if the value is 0, we return the string mapped to the first element of the table.
 */
typedef struct {
	fr_table_elem_name_t	name;
	unsigned int		value;
} fr_table_num_indexed_t;

/** Macro to use as dflt
 *
 */
#define NAME_NUMBER_NOT_FOUND	INT32_MIN

char const *_fr_table_ptr_by_str_value(fr_table_ptr_sorted_t const *table, size_t table_len, char const *str_val, char const *def);

#define TABLE_IDX(_table, _idx, _element_size) (((uint8_t const *)(_table)) + ((_idx) * (_element_size)))
#define ELEM_STR(_offset) (*((fr_table_elem_name_t const *)(_offset))).str
#define ELEM_LEN(_offset) (*((fr_table_elem_name_t const *)(_offset))).len

/** Create a type-specific name-to-value function
 *
 * @param[in] _func		Used for resolving the name portion of an array element to a value.
 *				Should be one of the following:
 *				- table_sorted_value_by_str		- for lexicographically sorted tables.
 *				- table_ordered_value_by_str		- for arbitrarily ordered tables.
 * @param[in] _our_table_type	C type of the table elements.
 * @param[in] _our_name		name of the search function to define.
 * @param[in] _our_def_type	C type of the default value.
 * @param[in] _our_return_type	C type of the return value, i.e. the value part of the element.
 */
#define TABLE_TYPE_NAME_FUNC(_func, _our_table_type, _our_name, _our_def_type, _our_return_type) \
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

/** Create a type-specific name-to-value function
 *
 * @param[in] _func		Used for resolving the name portion of an array element to a value.
 *				Should be one of the following:
 *				- table_sorted_value_by_str		- for lexicographically sorted tables.
 *				- table_ordered_value_by_str		- for arbitrarily ordered tables.
 * @param[in] _our_table_type	C type of the table elements.
 * @param[in] _our_name		name of the search function to define.
 * @param[in] _our_def_type	C type of the default value.
 * @param[in] _our_out_type	C type of the return/output value, i.e. the value part of the element.
 */
#define TABLE_TYPE_NAME_FUNC_RPTR(_func, _our_table_type, _our_name, _our_def_type, _our_out_type) \
bool _our_name(_our_out_type *out, _our_table_type table, size_t table_len, char const *name, _our_def_type def) \
{ \
	_our_table_type found; \
	found = (_our_table_type)_func(table, table_len, sizeof(((_our_table_type)0)[0]), name); \
	if (!found) { \
		*out = def; \
		return false; \
	} \
	*out = &found->value; \
	return true; \
}

/** Create a type-specific name-to-value function that can perform substring matching with a 'name_len' argument
 *
 * @param[in] _func		Used for resolving the name portion of an array element to a value.
 *				Should be one of the following:
 *				- table_sorted_value_by_substr		- for lexicographically sorted tables
 *									  with partial matching.
 *				- table_ordered_value_by_substr		- for arbitrarily ordered tables.
 *									  with partial matching.
 * @param[in] _our_table_type	C type of the table elements.
 *				Must contain two fields, an #fr_table_elem_name_t called name
 *				and an arbitraryily typed field called value.
 *				A pointer to thi
 * @param[in] _our_name		name of the search function to define.
 * @param[in] _our_def_type	C type of the default value.
 * @param[in] _our_return_type	C type of the return value, i.e. the value part of the element.
 */
#define TABLE_TYPE_NAME_LEN_FUNC(_func, _our_table_type, _our_name, _our_def_type, _our_return_type) \
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

/** Create a type-specific name-to-value function that can perform substring matching with a 'name_len' argument
 *
 * @note The functions created by this macro return true on a match, false on no match, and write a
 * 	 pointer to the value field of the table element to the 'out' argument.
 *
 * @param[in] _func		Used for resolving the name portion of an array element to a value.
 *				Should be one of the following:
 *				- table_sorted_value_by_substr		- for lexicographically sorted tables
 *									  with partial matching.
 *				- table_ordered_value_by_substr		- for arbitrarily ordered tables.
 *									  with partial matching.
 * @param[in] _our_table_type	C type of the table elements.
 *				Must contain two fields, an #fr_table_elem_name_t called name
 *				and an arbitraryily typed field called value.
 *				A pointer to thi
 * @param[in] _our_name		name of the search function to define.
 * @param[in] _our_def_type	C type of the default value.
 * @param[in] _our_out_type	C type of the return/output value, i.e. the value part of the element.
 */
#define TABLE_TYPE_NAME_LEN_FUNC_RPTR(_func, _our_table_type, _our_name, _our_def_type, _our_out_type) \
bool _our_name(_our_out_type *out, _our_table_type table, size_t table_len, char const *name, ssize_t name_len, _our_def_type def) \
{ \
	_our_table_type found; \
	found = (_our_table_type)_func(table, table_len, sizeof(((_our_table_type)0)[0]), name, name_len); \
	if (!found) { \
		*out = def; \
		return false; \
	} \
	*out = &found->value; \
	return true; \
}

/** Create a type-specific name-to-value function that can perform substring matching with a 'name_len' argument, and passes back the length of the matched string
 *
 * @note The functions created by this macro return the value field of the table element.
 *
 * @param[in] _func		Used for resolving the name portion of an array element to a value.
 *				Should be one of the following:
 *				- table_sorted_value_by_longest_prefix	- for lexicographically sorted tables
 *									  with longest prefix match.
 *				- table_ordered_value_by_longest_prefix	- for arbitrarily ordered tables
 *									  with longest prefix match.
 * @param[in] _our_table_type	C type of the table elements.
 * @param[in] _our_name		name of the search function to define.
 * @param[in] _our_def_type	C type of the default value.
 * @param[in] _our_return_type	C type of the return value, i.e. the value part of the element.
 */
#define TABLE_TYPE_NAME_MATCH_LEN_FUNC(_func, _our_table_type, _our_name, _our_def_type, _our_return_type) \
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

/** Create a type-specific name-to-value function that can perform substring matching with a 'name_len' argument, and passes back the length of the matched string
 *
 * @note The functions created by this macro return true on a match, false on no match, and write a
 *	 pointer to the value field of the table element to the 'out' argument.
 *
 * @param[in] _func		Used for resolving the name portion of an array element to a value.
 *				Should be one of the following:
 *				- table_sorted_value_by_longest_prefix	- for lexicographically sorted tables
 *									  with longest prefix match.
 *				- table_ordered_value_by_longest_prefix	- for arbitrarily ordered tables
 *									  with longest prefix match.
 * @param[in] _our_table_type	C type of the table elements.
 * @param[in] _our_name		name of the search function to define.
 * @param[in] _our_def_type	C type of the default value.
 * @param[in] _our_out_type	C type of the return/output value, i.e. the value part of the element.
 */
#define TABLE_TYPE_NAME_MATCH_LEN_FUNC_RPTR(_func, _our_table_type, _our_name, _our_def_type, _our_out_type) \
bool _our_name(size_t *match_len, _our_out_type *out, _our_table_type table, size_t table_len, char const *name, ssize_t name_len, _our_def_type def) \
{ \
	_our_table_type found; \
	found = (_our_table_type)_func(match_len, table, table_len, sizeof(((_our_table_type)0)[0]), name, name_len); \
	if (!found) { \
		*out = def; \
		return false; \
	} \
	*out = &found->value; \
	return true; \
}

/** Create a type-specific value-to-name function
 *
 * @param[in] _our_table_type	C type of the table elements.
 * @param[in] _our_name		name of the search function to define.
 * @param[in] _our_value_type	C type of the value field of the table element.
 */
#define TABLE_TYPE_VALUE_FUNC(_our_table_type, _our_name, _our_value_type) \
char const *_our_name(_our_table_type table, size_t table_len, _our_value_type value, char const *def) \
{ \
	size_t		i; \
	for (i = 0; i < table_len; i++) if (table[i].value == value) return table[i].name.str; \
	return def; \
}

/** Create a type-specific value-to-name function, which uses the highest bit set in the value as an index into the table
 *
 * @param[in] _our_table_type	C type of the table elements.
 * @param[in] _our_name		name of the search function to define.
 * @param[in] _our_value_type	C type of the value field of the table element.
 */
#define TABLE_TYPE_VALUE_INDEX_BIT_FIELD_FUNC(_our_table_type, _our_name, _our_value_type) \
char const *_our_name(_our_table_type table, size_t table_len, _our_value_type value, char const *def) \
{ \
	uint8_t	idx = fr_high_bit_pos(value); \
	if (idx >= table_len) return def; \
	return table[idx].name.str; \
}

/** Create a type-specific value-to-name function, which uses the value as an index into the table
 *
 * @param[in] _our_table_type	C type of the table elements.
 * @param[in] _our_name		name of the search function to define.
 * @param[in] _our_value_type	C type of the value field of the table element.
 */
#define TABLE_TYPE_VALUE_INDEX_FUNC(_our_table_type, _our_name, _our_value_type) \
char const *_our_name(_our_table_type table, size_t table_len, _our_value_type value, char const *def) \
{ \
	if (value >= table_len) return def; \
	return table[value].name.str; \
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
		ret = strcasecmp(name, ELEM_STR(offset));
		if (ret == 0) return offset;
		if (ret < 0) {
			end = mid - 1;
		} else {
			start = mid + 1;
		}
	}

	return NULL;
}

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
		if (strcasecmp(name, ELEM_STR(offset)) == 0) return offset;
	}

	return NULL;
}

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
		ret = strncasecmp(name, ELEM_STR(offset),
				  (name_len < 0) ?  ELEM_LEN(offset) : (size_t)name_len);
		if (ret == 0) return offset;

		if (ret < 0) {
			end = mid - 1;
		} else {
			start = mid + 1;
		}
	}

	return NULL;
}

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

		tlen = ELEM_LEN(offset);

		/*
		 *	Don't match "request" to user input "req".
		 */
		if ((name_len > 0) && (name_len < (int) tlen)) continue;

		/*
		 *	Match up to the length of the table entry if len is < 0.
		 */
		if (strncasecmp(name, ELEM_STR(offset),
				(name_len < 0) ? tlen : (size_t)name_len) == 0) return offset;
	}

	return NULL;
}

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
		elem = ELEM_STR(offset);
		tlen = ELEM_LEN(offset);

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

		for (j = 0; (j < (size_t)name_len) && (j < ELEM_LEN(offset)) &&
			    (tolower(name[j]) == tolower((ELEM_STR(offset))[j])); j++);

		/*
		 *	If we didn't get to the end of the
		 *	table string, then continue.
		 */
		if ((ELEM_STR(offset))[j] != '\0') continue;

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

/** Brute force search a sorted or ordered ptr table, assuming the pointers are strings
 *
 * @param[in] _table		to search in.
 * @param[in] _str_value	to compare against the ptr field.
 * @param[in] _def		default value.
 */
#define fr_table_str_by_str_value(_table, _str_value, _def) \
_Generic((_table), \
	 fr_table_ptr_sorted_t const *		: _fr_table_ptr_by_str_value((fr_table_ptr_sorted_t const *)_table, _table ## _len, _str_value, _def), \
	 fr_table_ptr_ordered_t const *		: _fr_table_ptr_by_str_value((fr_table_ptr_sorted_t const *)_table, _table ## _len, _str_value, _def), \
	 fr_table_ptr_sorted_t *		: _fr_table_ptr_by_str_value((fr_table_ptr_sorted_t const *)_table, _table ## _len, _str_value, _def), \
	 fr_table_ptr_ordered_t *		: _fr_table_ptr_by_str_value((fr_table_ptr_sorted_t const *)_table, _table ## _len, _str_value, _def))

int		fr_table_sorted_num_by_str(fr_table_num_sorted_t const *table, size_t table_len,
					   char const *name, int def);

int		fr_table_ordered_num_by_str(fr_table_num_ordered_t const *table, size_t table_len,
				 	    char const *name, int def);

void 		*fr_table_sorted_ptr_by_str(fr_table_ptr_sorted_t const *table, size_t table_len,
					    char const *name, void const *def);

void		*fr_table_ordered_ptr_by_str(fr_table_ptr_ordered_t const *table, size_t table_len,
				 	     char const *name, void const *def);

/** Convert a string to a value using a sorted or ordered table
 *
 * @param[in] _table	to search in.
 * @param[in] _name	to resolve to a number.
 * @param[in] _def	Default value if no entry matched.
 * @return
 *	- _def if name matched no entries in the table.
 *	- the numeric value of the matching entry.
 */
#define fr_table_value_by_str(_table, _name, _def) \
_Generic((_table), \
	 fr_table_num_sorted_t const *		: fr_table_sorted_num_by_str,			\
	 fr_table_num_ordered_t const *		: fr_table_ordered_num_by_str,			\
	 fr_table_num_sorted_t *		: fr_table_sorted_num_by_str,			\
	 fr_table_num_ordered_t *		: fr_table_ordered_num_by_str,			\
	 fr_table_ptr_sorted_t const *		: fr_table_sorted_ptr_by_str,			\
	 fr_table_ptr_ordered_t const *		: fr_table_ordered_ptr_by_str,			\
	 fr_table_ptr_sorted_t *		: fr_table_sorted_ptr_by_str,			\
	 fr_table_ptr_ordered_t *		: fr_table_ordered_ptr_by_str,			\
	 fr_table_num_indexed_bit_pos_t *	: fr_table_ordered_num_by_str,			\
	 fr_table_num_indexed_bit_pos_t const *	: fr_table_ordered_num_by_str,			\
	 fr_table_num_indexed_t *		: fr_table_ordered_num_by_str,			\
	 fr_table_num_indexed_t const *		: fr_table_ordered_num_by_str			\
)(_table, _table ## _len, _name, _def)

int		fr_table_sorted_num_by_substr(fr_table_num_sorted_t const *table, size_t table_len,
					      char const *name, ssize_t name_len, int def);

int		fr_table_ordered_num_by_substr(fr_table_num_ordered_t const *table, size_t table_len,
				  	       char const *name, ssize_t name_len, int def);

void		*fr_table_sorted_ptr_by_substr(fr_table_ptr_sorted_t const *table, size_t table_len,
					       char const *name, ssize_t name_len, void const *def);

void		*fr_table_ordered_ptr_by_substr(fr_table_ptr_ordered_t const *table, size_t table_len,
				  	        char const *name, ssize_t name_len, void const *def);

/** Convert a partial string to a value using an ordered or sorted table
 *
 * @param[in] _table	to search in.
 * @param[in] _name	to resolve to a number.
 * @param[in] _name_len	The amount of name to match.
 *			If < 0, the length of the name in the table element
 *			will be used as the maximum match length.
 * @param[in] _def	Default value if no entry matched.
 * @return
 *	- _def if name matched no entries in the table.
 *	- the numeric value of the matching entry.
 */
#define fr_table_value_by_substr(_table, _name, _name_len, _def) \
_Generic((_table), \
	 fr_table_num_sorted_t const *		: fr_table_sorted_num_by_substr,		\
	 fr_table_num_ordered_t const *		: fr_table_ordered_num_by_substr,		\
	 fr_table_num_sorted_t *		: fr_table_sorted_num_by_substr,		\
	 fr_table_num_ordered_t *		: fr_table_ordered_num_by_substr,		\
	 fr_table_ptr_sorted_t const *		: fr_table_sorted_ptr_by_substr,		\
	 fr_table_ptr_ordered_t const *		: fr_table_ordered_ptr_by_substr,		\
	 fr_table_ptr_sorted_t *		: fr_table_sorted_ptr_by_substr,		\
	 fr_table_ptr_ordered_t *		: fr_table_ordered_ptr_by_substr,		\
	 fr_table_num_indexed_bit_pos_t *	: fr_table_ordered_num_by_substr,		\
	 fr_table_num_indexed_bit_pos_t const *	: fr_table_ordered_num_by_substr,		\
	 fr_table_num_indexed_t *		: fr_table_ordered_num_by_substr,		\
	 fr_table_num_indexed_t const *		: fr_table_ordered_num_by_substr		\
)(_table, _table ## _len, _name, _name_len, _def)

int	fr_table_sorted_num_by_longest_prefix(size_t *match_len, fr_table_num_sorted_t const *table, size_t table_len,
					      char const *name, ssize_t name_len, int def);

int	fr_table_ordered_num_by_longest_prefix(size_t *match_len, fr_table_num_ordered_t const *table, size_t table_len,
					       char const *name, ssize_t name_len, int def);

void 	*fr_table_sorted_ptr_by_longest_prefix(size_t *match_len, fr_table_ptr_sorted_t const *table, size_t table_len,
					       char const *name, ssize_t name_len, void const *def);

void	*fr_table_ordered_ptr_by_longest_prefix(size_t *match_len, fr_table_ptr_ordered_t const *table, size_t table_len,
						char const *name, ssize_t name_len, void const *def);

/** Find the longest string match using a sorted or ordered table
 *
 * @param[out] _match_len	How much of the input string matched.
 * @param[in] _table		to search in.
 * @param[in] _name		to resolve to a number.
 * @param[in] _name_len		The amount of name to match.
 * @param[in] _def		Default value if no entry matched.
 * @return
 *	- _def if name matched no entries in the table.
 *	- the value of the matching entry.
 */
#define fr_table_value_by_longest_prefix(_match_len, _table, _name, _name_len, _def) \
_Generic((_table), \
	 fr_table_num_sorted_t const *		: fr_table_sorted_num_by_longest_prefix,	\
	 fr_table_num_ordered_t const *		: fr_table_ordered_num_by_longest_prefix,	\
	 fr_table_num_sorted_t *		: fr_table_sorted_num_by_longest_prefix,	\
	 fr_table_num_ordered_t *		: fr_table_ordered_num_by_longest_prefix,	\
	 fr_table_ptr_sorted_t const *		: fr_table_sorted_ptr_by_longest_prefix,	\
	 fr_table_ptr_ordered_t const *		: fr_table_ordered_ptr_by_longest_prefix,	\
	 fr_table_ptr_sorted_t *		: fr_table_sorted_ptr_by_longest_prefix,	\
	 fr_table_ptr_ordered_t *		: fr_table_ordered_ptr_by_longest_prefix,	\
	 fr_table_num_indexed_bit_pos_t *	: fr_table_ordered_num_by_longest_prefix,	\
	 fr_table_num_indexed_bit_pos_t const *	: fr_table_ordered_num_by_longest_prefix,	\
	 fr_table_num_indexed_t *		: fr_table_ordered_num_by_longest_prefix,	\
	 fr_table_num_indexed_t const *		: fr_table_ordered_num_by_longest_prefix	\
)(_match_len, _table, _table ## _len, _name, _name_len, _def)

char const	*fr_table_ordered_str_by_num(fr_table_num_ordered_t const *table, size_t table_len,
					     int number, char const *def);
char const	*fr_table_sorted_str_by_num(fr_table_num_sorted_t const *table, size_t table_len,
					    int number, char const *def);
char const	*fr_table_ordered_str_by_ptr(fr_table_ptr_ordered_t const *table, size_t table_len,
					     void const *ptr, char const *def);
char const	*fr_table_sorted_str_by_ptr(fr_table_ptr_sorted_t const *table, size_t table_len,
					    void const *ptr, char const *def);

char const	*fr_table_indexed_str_by_bit_field(fr_table_num_indexed_bit_pos_t const *table, size_t table_len,
						   uint64_t number, char const *def);

char const	*fr_table_indexed_str_by_num(fr_table_num_indexed_t const *table, size_t table_len,
					     unsigned int number, char const *def);

/** Convert an integer to a string
 *
 * @param[in] _table		to search in.
 * @param[in] _number		to resolve to a string.
 * @param[in] _def		Default string to return if there's no match.
 * @return
 *	- _def if _number name matched no entries in the table.
 *	- the string value of the matching entry.
 */
#define fr_table_str_by_value(_table, _number, _def) \
_Generic((_table), \
	 fr_table_num_sorted_t const *		: fr_table_sorted_str_by_num,			\
	 fr_table_num_ordered_t const *		: fr_table_ordered_str_by_num,			\
	 fr_table_num_sorted_t *		: fr_table_sorted_str_by_num,			\
	 fr_table_num_ordered_t *		: fr_table_ordered_str_by_num,			\
	 fr_table_ptr_sorted_t const *		: fr_table_sorted_str_by_ptr,			\
	 fr_table_ptr_ordered_t const *		: fr_table_ordered_str_by_ptr,			\
	 fr_table_ptr_sorted_t *		: fr_table_sorted_str_by_ptr,			\
	 fr_table_ptr_ordered_t *		: fr_table_ordered_str_by_ptr,			\
	 fr_table_num_indexed_bit_pos_t *	: fr_table_indexed_str_by_bit_field, 		\
	 fr_table_num_indexed_bit_pos_t const *	: fr_table_indexed_str_by_bit_field, 		\
	 fr_table_num_indexed_t *		: fr_table_indexed_str_by_num, 			\
	 fr_table_num_indexed_t const *		: fr_table_indexed_str_by_num 			\
)(_table, _table ## _len, _number, _def)

#define TABLE_TYPE_NEEDLE_LEN_FUNC(_our_table_type, _our_name) \
static inline size_t _our_name(_our_table_type table, size_t table_len) \
{ \
	size_t i, max = 0; \
	for (i = 0; i < table_len; i++) if (table->name.len > max) max = table->name.len; \
	return max; \
}

TABLE_TYPE_NEEDLE_LEN_FUNC(fr_table_num_sorted_t const *, fr_table_num_sorted_max_needle_len)
TABLE_TYPE_NEEDLE_LEN_FUNC(fr_table_num_ordered_t const *, fr_table_num_ordered_max_needle_len)
TABLE_TYPE_NEEDLE_LEN_FUNC(fr_table_ptr_sorted_t const *, fr_table_ptr_sorted_max_needle_len)
TABLE_TYPE_NEEDLE_LEN_FUNC(fr_table_ptr_ordered_t const *, fr_table_ptr_ordered_max_needle_len)
TABLE_TYPE_NEEDLE_LEN_FUNC(fr_table_num_indexed_bit_pos_t const *, fr_table_num_indexed_bit_pos_max_needle_len)
TABLE_TYPE_NEEDLE_LEN_FUNC(fr_table_num_indexed_t const *, fr_table_num_indexed_max_needle_len)

#define fr_table_max_needle_len(_table) \
_Generic((_table), \
	 fr_table_num_sorted_t const *		: fr_table_num_sorted_max_needle_len,		\
	 fr_table_num_ordered_t const *		: fr_table_num_ordered_max_needle_len,		\
	 fr_table_num_sorted_t *		: fr_table_num_sorted_max_needle_len,		\
	 fr_table_num_ordered_t *		: fr_table_num_ordered_max_needle_len,		\
	 fr_table_ptr_sorted_t const *		: fr_table_ptr_sorted_max_needle_len,		\
	 fr_table_ptr_ordered_t const *		: fr_table_ptr_ordered_max_needle_len,		\
	 fr_table_ptr_sorted_t *		: fr_table_ptr_sorted_max_needle_len,		\
	 fr_table_ptr_ordered_t *		: fr_table_ptr_ordered_max_needle_len,		\
	 fr_table_num_indexed_bit_pos_t *	: fr_table_num_indexed_bit_pos_max_needle_len, 	\
	 fr_table_num_indexed_bit_pos_t const *	: fr_table_num_indexed_bit_pos_max_needle_len, 	\
	 fr_table_num_indexed_t *		: fr_table_num_indexed_max_needle_len, 		\
	 fr_table_num_indexed_t const *		: fr_table_num_indexed_max_needle_len 		\
)(_table, _table ## _len)

#ifdef __cplusplus
}
#endif
