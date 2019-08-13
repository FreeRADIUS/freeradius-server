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

struct fr_table_s {
	char const	*name;
	int32_t		number;
};

typedef struct fr_table_s fr_table_t;
typedef struct fr_table_s fr_table_ordered_t;

/** Macro to use as dflt
 *
 */
#define NAME_NUMBER_NOT_FOUND	INT32_MIN

int		_fr_table_num_by_str(fr_table_t const *table, size_t table_len,
				     char const *name, int def);

int		_fr_table_num_by_substr(fr_table_t const *table, size_t table_len,
					char const *name, ssize_t name_len, int def);

int		_fr_table_lex_num_by_longest_prefix(fr_table_t const *table, size_t table_len,
						    char const *name, size_t name_len, int def);

int		_fr_table_lex_num_by_str(fr_table_t const *table, size_t table_len,
					 char const *name, size_t name_len, int def);

char const	*_fr_table_str_by_num(fr_table_t const *table, size_t table_len,
				      int number, char const *def);


/** Convert a string to an integer
 *
 * @copybrief _fr_table_num_by_str
 */
#define		fr_table_num_by_str(_table, _name, _def) \
		_fr_table_num_by_str(_table, _table ## _len, _name, _def)

/** Convert a string matching part of name to an integer
 *
 * @copybrief _fr_table_num_by_substr
 */
#define		fr_table_num_by_substr(_table, _name, _name_len, _def) \
		_fr_table_num_by_substr(_table, _table ## _len, _name, _name_len, _def)

/** Find the longest string match in a lexicographically sorted fr_table_t table
 *
 * @copybrief _fr_table_lex_num_by_longest_prefix
 */
#define		fr_table_lex_num_by_longest_prefix(_table, _name, _name_len, _def) \
		_fr_table_lex_num_by_longest_prefix(_table, _table ## _len, _name, _name_len, _def)

/** Efficient string lookup in lexicographically sorted fr_table_t table
 *
 * @copybrief _fr_table_lex_num_by_str
 */
#define		fr_table_lex_num_by_str(_table, _name, _name_len, _def) \
		_fr_table_lex_num_by_str(_table, _table ## _len, _name, _name_len, _def)

/** Convert an integer to a string
 *
 * @copybrief _fr_table_str_from_int
 */
#define		fr_table_str_by_num(_table, _number, _def) \
		_fr_table_str_by_num(_table, _table ## _len, _number, _def)
#ifdef __cplusplus
}
#endif
