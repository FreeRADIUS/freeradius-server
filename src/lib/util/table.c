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

#include <string.h>


/** Convert a string to an integer using a lexicographically sorted table
 *
 * @param[in] table		to search in.
 * @param[in] table_len		The number of elements in the table.
 * @param[in] name		to resolve to a number.
 * @param[in] def		Default value if no entry matched.
 * @return
 *	- num value of matching entry.
 *      - def if no matching entries.
 */
int fr_table_sorted_num_by_str(fr_table_sorted_t const *table, size_t table_len,
			       char const *name, int def)
{
	ssize_t	start = 0;
	ssize_t	end = table_len - 1;
	ssize_t	mid;

	int	ret;

	if (!name) return def;

	while (start <= end) {
		mid = start + ((end - start) / 2);	/* Avoid overflow */

		ret = strcasecmp(name, table[mid].name);
		if (ret == 0) return table[mid].number;

		if (ret < 0) {
			end = mid - 1;
		} else {
			start = mid + 1;
		}
	}

	return def;
}

/** Convert a string to an integer using an arbitrarily ordered table
 *
 * @param[in] table		to search in.
 * @param[in] table_len		The number of elements in the table.
 * @param[in] name		to resolve to a number.
 * @param[in] def		Default value if no entry matched.
 * @return
 *	- num value of matching entry.
 *      - def if no matching entries.
 */
int fr_table_ordered_num_by_str(fr_table_ordered_t const *table, size_t table_len,
				char const *name, int def)
{
	size_t		i;

	if (!name) return def;

	for (i = 0; i < table_len; i++) if (strcasecmp(name, table[i].name) == 0) return table[i].number;

	return def;
}

/** Convert a string matching part of name to an integer using a lexicographically sorted table
 *
 * @param[in] table		to search in.
 * @param[in] table_len		The number of elements in the table.
 * @param[in] name		to locate.
 * @param[in] name_len		the maximum amount of name that should be matched.
 *				If < 0, the length of the name in the table element
 *				will be used as the maximum match length.
 * @param[in] def		Value to return if there are no matches.
 * @return
 *	- num value of matching entry.
 *      - def if no matching entries.
 */
int fr_table_sorted_num_by_substr(fr_table_sorted_t const *table, size_t table_len,
				  char const *name, ssize_t name_len, int def)
{
	ssize_t	start = 0;
	ssize_t	end = table_len - 1;
	ssize_t	mid;

	int	ret;

	if (!name) return def;

	while (start <= end) {
		mid = start + ((end - start) / 2);	/* Avoid overflow */

		/*
		 *	Match up to the length of the table entry if len is < 0.
		 */
		ret = strncasecmp(name, table[mid].name,
				  (name_len < 0) ?  strlen(table[mid].name) : (size_t)name_len);
		if (ret == 0) return table[mid].number;

		if (ret < 0) {
			end = mid - 1;
		} else {
			start = mid + 1;
		}
	}

	return def;
}

/** Convert a string matching part of name to an integer using an arbitrarily ordered table
 *
 * @param[in] table		to search in.
 * @param[in] table_len		The number of elements in the table.
 * @param[in] name		to locate.
 * @param[in] name_len		the maximum amount of name that should be matched.
 *				If < 0, the length of the name in the table element
 *				will be used as the maximum match length.
 * @param[in] def		Value to return if there are no matches.
 * @return
 *	- num value of matching entry.
 *      - def if no matching entries.
 */
int fr_table_ordered_num_by_substr(fr_table_ordered_t const *table, size_t table_len,
				   char const *name, ssize_t name_len, int def)
{
	size_t		i;

	if (!name) return def;

	for (i = 0; i < table_len; i++) {
		size_t tlen;

		tlen = strlen(table[i].name);

		/*
		 *	Don't match "request" to user input "req".
		 */
		if ((name_len > 0) && (name_len < (int) tlen)) continue;

		/*
		 *	Match up to the length of the table entry if len is < 0.
		 */
		if (strncasecmp(name, table[i].name,
				(name_len < 0) ? tlen : (size_t)name_len) == 0) return table[i].number;
	}

	return def;
}

/** Find the longest string match using a lexicographically sorted table
 *
 * Performs a binary search in the specified table, returning the longest
 * element which is a prefix of name.
 *
 * i.e. given name of "food", and table of f, foo, of - foo would be returned.
 *
 * @note The table *MUST* be sorted lexicographically, else the result may be incorrect.
 *
 * @param[in] table		to search in.
 * @param[in] table_len		The number of elements in the table.
 * @param[in] name		to locate.
 * @param[in] name_len		the maximum amount of name that should be matched.
 * @param[in] def		Value to return if there are no matches.
 * @return
 *	- num value of matching entry.
 *      - def if no matching entries.
 */
int fr_table_sorted_num_by_longest_prefix(fr_table_sorted_t const *table, size_t table_len,
					  char const *name, size_t name_len, int def)
{
	ssize_t	start = 0;
	ssize_t	end = table_len - 1;
	ssize_t	mid;

	int	ret;
	int	num = def;

	if (!name) return def;

	while (start <= end) {
		mid = start + ((end - start) / 2);	/* Avoid overflow */

		ret = strncasecmp(name, table[mid].name, name_len);
		if (ret == 0) {
			size_t tlen;

			tlen = strlen(table[mid].name);

			/*
			 *	Exact match
			 */
			if (tlen == name_len) return table[mid].number;

			/*
			 *	Partial match.
			 *	Name we're searching for is longer.
			 *	This might be the longest prefix,
			 *	so record it.
			 */
			if (tlen < name_len) {
				num = table[mid].number;
				ret = 1;
			}
		}

		if (ret < 0) {
			end = mid - 1;
		} else {
			start = mid + 1;
		}
	}

	return num;
}

/** Find the longest string match using an arbitrarily ordered table
 *
 * i.e. given name of "food", and table of f, foo, of - foo would be returned.
 *
 * @param[in] table		to search in.
 * @param[in] table_len		The number of elements in the table.
 * @param[in] name		to locate.
 * @param[in] name_len		the maximum amount of name that should be matched.
 * @param[in] def		Value to return if there are no matches.
 * @return
 *	- num value of matching entry.
 *      - def if no matching entries.
 */
int fr_table_ordered_num_by_longest_prefix(fr_table_ordered_t const *table, size_t table_len,
					   char const *name, size_t name_len, int def)
{
	size_t		i;
	size_t		found_len = 0;
	int		num = def;

	if (!name) return def;

	for (i = 0; i < table_len; i++) {
		size_t j;

		for (j = 0; (j < name_len) && (name[j] == table[i].name[j]); j++) ;

		/*
		 *	Exact match
		 */
		if (j == name_len) return table[i].number;

		/*
		 *	Partial match.
		 *	Name we're searching for is longer.
		 *	This might be the longest prefix,
		 *	so record it.
		 */
		if (j > found_len) {
			found_len = j;
			num = table[i].number;
		}
	}

	return num;
}

/** Convert an integer to a string
 *
 * @param[in] table		to search in.
 * @param[in] table_len		The number of elements in the table.
 * @param[in] number		to resolve to a string.
 * @param[in] def		Default string to return if there's no match.
 * @return
 *	- string value of matching entry.
 *      - def if no matching entries.
 */
char const *_fr_table_str_by_num(fr_table_ordered_t const *table, size_t table_len,
				 int number, char const *def)
{
	size_t i;

	for (i = 0; i < table_len; i++) if (table[i].number == number) return table[i].name;

	return def;
}
