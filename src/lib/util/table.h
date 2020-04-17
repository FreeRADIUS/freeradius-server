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

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/** An element in a lexicographically sorted array of name to num mappings
 *
 */
typedef struct {
	char const		*name;
	int			value;
} fr_table_num_sorted_t;

/** An element in an arbitrarily ordered array of name to num mappings
 *
 */
typedef struct {
	char const		*name;
	int			value;
} fr_table_num_ordered_t;

/** An element in a lexicographically sorted array of name to ptr mappings
 *
 */
typedef struct {
	char const		*name;
	void const		*value;
} fr_table_ptr_sorted_t;

/** An element in an arbitrarily ordered array of name to ptr mappings
 *
 */
typedef struct {
	char const		*name;
	void const		*value;
} fr_table_ptr_ordered_t;

/** An element in a table indexed by bit position
 *
 * i.e. if only the first bit is set in a bitfield, the entry at index 0
 * will be returned.
 */
typedef struct {
	char const		*name;
	uint64_t		value;
} fr_table_num_indexed_bit_pos_t;

/** Macro to use as dflt
 *
 */
#define NAME_NUMBER_NOT_FOUND	INT32_MIN


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
	 fr_table_num_indexed_bit_pos_t const *	: fr_table_ordered_num_by_str			\
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
	 fr_table_num_indexed_bit_pos_t const *	: fr_table_ordered_num_by_substr		\
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
	 fr_table_num_indexed_bit_pos_t const *	: fr_table_ordered_num_by_longest_prefix	\
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
	 fr_table_num_indexed_bit_pos_t const *	: fr_table_indexed_str_by_bit_field 		\
)(_table, _table ## _len, _number, _def)

#ifdef __cplusplus
}
#endif
