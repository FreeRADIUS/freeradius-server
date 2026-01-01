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
 * @file src/lib/util/pair_legacy.h
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(pair_legacy_h, "$Id$")

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/dcursor.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/value.h>
#include <freeradius-devel/util/token.h>

#ifdef __cplusplus
extern "C" {
#endif

int		fr_pair_list_afrom_file(TALLOC_CTX *ctx, fr_dict_t const *dict,
					fr_pair_list_t *out, FILE *fp, bool *pfiledone, bool allow_exec);

void		fr_pair_list_move_op(fr_pair_list_t *to, fr_pair_list_t *from, fr_token_t op);

typedef struct {
	TALLOC_CTX		*ctx;
	fr_dict_attr_t const	*da;		//!< root da to start parsing from
	fr_pair_list_t		*list;		//!< list where output is placed

	fr_dict_t const		*dict;		//!< the protocol dictionary we use
	fr_dict_t const		*internal;	//!< a cached pointer to the internal dictionary

	bool			allow_compare;	//!< allow comparison operators
	bool			allow_crlf;	//!< allow CRLF, and treat like comma
	bool			allow_zeros;	//!< allow '\0' as end of attribute
	bool			allow_exec;	//!< allow `exec` to execute external commands.
						///< This should only be allowed in trusted input,
						///< and on startup only.  popen() is used for the
						///< execution, and it has no configurable timeout,
						///< so the calling code will wait indefinitely.
	bool			tainted;	//!< source is tainted
	char			last_char;	//!< last character we read - ',', '\n', or 0 for EOF
	bool			end_of_list;	//!< do we expect an end of list '}' character?
} fr_pair_parse_t;

fr_slen_t fr_pair_list_afrom_substr(fr_pair_parse_t const *root, fr_pair_parse_t *relative,
				    fr_sbuff_t *in) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
