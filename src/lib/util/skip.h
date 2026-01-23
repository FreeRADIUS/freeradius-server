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

/** Preparse input by skipping known tokens
 *
 * @file src/lib/util/skip.h
 *
 * @copyright 2001,2006 The FreeRADIUS server project
 */
RCSIDH(skip_h, "$Id$")

#include <freeradius-devel/util/sbuff.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Skip whitespace ('\\t', '\\n', '\\v', '\\f', '\\r', ' ')
 *
 * @param[in,out] _p	string to skip over.
 */
#define fr_skip_whitespace(_p) while(isspace((uint8_t)*(_p))) _p++

/** Skip whitespace, stopping at end ('\\t', '\\n', '\\v', '\\f', '\\r', ' ')
 *
 * @param[in,out] _p	string to skip over.
 * @param[in] _e	pointer to end of string.
 */
#define fr_bskip_whitespace(_p, _e) while((_p < _e) && isspace((uint8_t)*(_p))) _p++

/** Skip everything that's not whitespace ('\\t', '\\n', '\\v', '\\f', '\\r', ' ')
 *
 * @param[in,out] _p	string to skip over.
 */
#define fr_skip_not_whitespace(_p) while(*_p && !isspace((uint8_t)*(_p))) _p++

ssize_t		fr_skip_string(char const *start, char const *end) CC_HINT(nonnull(1));

ssize_t		fr_skip_brackets(char const *start, char const *end, char end_quote);

ssize_t		fr_skip_xlat(char const *start, char const *end) CC_HINT(nonnull(1));

ssize_t		fr_skip_condition(char const *start, char const *end, bool const terminal[static SBUFF_CHAR_CLASS],
				  bool *eol) CC_HINT(nonnull(1,3));
#ifdef __cplusplus
}
#endif
