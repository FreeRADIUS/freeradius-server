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

/** Legacy API functions - DO NOT USE IN NEW CODE
 *
 * @file src/lib/util/pair.h
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(pair_legacy_h, "$Id$")

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/cursor.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/token.h>
#include <freeradius-devel/util/pair.h>

#ifdef __cplusplus
extern "C" {
#endif

VALUE_PAIR	*fr_pair_afrom_num(TALLOC_CTX *ctx, unsigned int vendor, unsigned int attr);

VALUE_PAIR	*fr_pair_make(TALLOC_CTX *ctx, fr_dict_t const *dict,
			      VALUE_PAIR **vps, char const *attribute, char const *value, fr_token_t op);

int 		fr_pair_mark_xlat(VALUE_PAIR *vp, char const *value);

fr_token_t	fr_pair_list_afrom_str(TALLOC_CTX *ctx, fr_dict_t const *dict,
				       char const *buffer, VALUE_PAIR **head);
int		fr_pair_list_afrom_file(TALLOC_CTX *ctx, fr_dict_t const *dict,
					VALUE_PAIR **out, FILE *fp, bool *pfiledone);

void		fr_pair_list_move(VALUE_PAIR **to, VALUE_PAIR **from);

#ifdef __cplusplus
}
#endif
