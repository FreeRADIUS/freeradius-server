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

/** Functions to finalise and fixup dictionaries
 *
 * @file src/lib/util/dict_fixup_priv.h
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2020,2024 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(dict_fixup_priv_h, "$Id$")

#include <freeradius-devel/util/dict_priv.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/talloc.h>
#include <freeradius-devel/util/value.h>

typedef struct {
	TALLOC_CTX		*pool;		//!< Temporary pool for fixups, reduces holes

	fr_dlist_head_t		enumv;		//!< Raw enumeration values to add.
	fr_dlist_head_t		group;		//!< Group references to resolve.
	fr_dlist_head_t		clone;		//!< Clone operation to apply.
	fr_dlist_head_t		clone_enum;	//!< Clone enum operation to apply.
	fr_dlist_head_t		vsa;		//!< VSAs to add vendors for
	fr_dlist_head_t		alias;		//!< Aliases that can't be resolved immediately.
} dict_fixup_ctx_t;

fr_dict_attr_t const *dict_protocol_reference(fr_dict_attr_t const *root, char const *ref, bool absolute_root);

int	dict_fixup_enumv_enqueue(dict_fixup_ctx_t *fctx, char const *filename, int line,
			 	 char const *attr, size_t attr_len,
				 char const *name, size_t name_len,
				 char const *value, size_t value_len,
				 fr_dict_attr_t const *parent);

int	dict_fixup_group_enqueue(dict_fixup_ctx_t *fctx, fr_dict_attr_t *da, char const *ref);

int	dict_fixup_clone_enqueue(dict_fixup_ctx_t *fctx, fr_dict_attr_t *da, char const *ref);

int	dict_fixup_clone(fr_dict_attr_t **dst_p, fr_dict_attr_t const *src);

int	dict_fixup_clone_enum_enqueue(dict_fixup_ctx_t *fctx, fr_dict_attr_t *da, char const *ref);

int	dict_fixup_vsa_enqueue(dict_fixup_ctx_t *fctx, fr_dict_attr_t *da);

int	dict_fixup_alias_enqueue(dict_fixup_ctx_t *fctx, char const *filename, int line,
				 fr_dict_attr_t *alias_parent, char const *alias,
				 fr_dict_attr_t *ref_parent, char const *ref);

int	dict_fixup_init(TALLOC_CTX *ctx, dict_fixup_ctx_t *fctx);

int	dict_fixup_apply(dict_fixup_ctx_t *fctx);

void	dict_hash_tables_finalise(fr_dict_t *dict);
