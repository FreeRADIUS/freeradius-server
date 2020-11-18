/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Extensions to dictionary structures
 *
 * @file src/lib/util/dict_ext.c
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/dict_priv.h>
#include <freeradius-devel/util/dict_ext_priv.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/talloc.h>

static fr_table_num_ordered_t const dict_attr_ext_table[] = {
	{ L("name"),		FR_DICT_ATTR_EXT_NAME		},
	{ L("children"),	FR_DICT_ATTR_EXT_CHILDREN	},
	{ L("vendor"),		FR_DICT_ATTR_EXT_REF		},
	{ L("enumv"),		FR_DICT_ATTR_EXT_VENDOR		},
	{ L("da_stack"),	FR_DICT_ATTR_EXT_ENUMV		},
	{ L("name"),		FR_DICT_ATTR_EXT_DA_STACK	}
};
static size_t dict_attr_ext_table_len = NUM_ELEMENTS(dict_attr_ext_table);

/** Copy all enumeration values from one attribute to another
 *
 */
static void *fr_dict_attr_ext_enumv_copy(void **chunk_p, int ext, void *ext_ptr, UNUSED size_t ext_len)
{
	fr_dict_attr_t			**da_p = (fr_dict_attr_t **)chunk_p;
	fr_dict_attr_ext_enumv_t	*new_ext, *old_ext;
	fr_hash_iter_t			iter;
	fr_dict_enum_t			*enumv;
	bool				has_child = da_is_key_field(*da_p);

	new_ext = dict_attr_ext_alloc(da_p, ext);
	if (!new_ext) return NULL;

	old_ext = ext_ptr;

	if (!old_ext->value_by_name && !old_ext->name_by_value) {
		memset(new_ext, 0, sizeof(*new_ext));
		return new_ext;
	}

	/*
	 *	Add all the enumeration values from
	 *      the old attribute to the new attribute.
	 */
	for (enumv = fr_hash_table_iter_init(old_ext->value_by_name, &iter);
	     enumv;
	     enumv = fr_hash_table_iter_next(old_ext->value_by_name, &iter)) {
		fr_dict_attr_t const *child_struct;

		if (!has_child) {
			child_struct = NULL;
		} else {
			child_struct = enumv->child_struct[0];
		}

	     	/*
	     	 *	Fixme - Child struct copying is probably wrong
	     	 */
		if (dict_attr_enum_add_name(*da_p, enumv->name, enumv->value, true, true, child_struct) < 0) {
			return NULL;
		}
	}

	return new_ext;
}

/** Rediscover the parent of this attribute, and cache it
 *
 */
static void *fr_dict_attr_ext_vendor_copy(void **chunk_p, int ext, void *ext_ptr, UNUSED size_t ext_len)
{
	fr_dict_attr_t			**da_p = (fr_dict_attr_t **)chunk_p;
	fr_dict_attr_ext_vendor_t	*new_ext, *old_ext = ext_ptr;
	fr_dict_attr_t const		**da_stack;
	fr_dict_attr_t const		*old_vendor = old_ext->vendor;
	fr_dict_attr_t const		*new_vendor, *da;

	/*
	 *	If we have a da stack, see if we can
	 *	find a vendor at the same depth as
	 *	the old depth.
	 */
	da_stack = fr_dict_attr_da_stack(*da_p);
	if (da_stack) {
		new_vendor = da_stack[old_vendor->depth];
		if ((new_vendor->type == old_vendor->type) && (new_vendor->attr == old_vendor->attr)) {
			new_ext = dict_attr_ext_alloc(da_p, ext);
			if (!new_ext) return NULL;

			new_ext->vendor = new_vendor;
			return new_ext;
		}
	}

	/*
	 *	Otherwise traverse the parent list
	 *	looking for the vendor.
	 *
	 *	Theoretically the attribute could
	 *	have been moved to a different depth.
	 */
	for (da = (*da_p)->parent; da; da = da->parent) {
		if ((da->type == old_vendor->type) && (da->attr == old_vendor->attr)) {
			new_ext = dict_attr_ext_alloc(da_p, ext);
			if (!new_ext) return NULL;

			new_ext->vendor = da;
			return new_ext;
		}
	}

	return NULL;
}

/** Holds additional information about extension structures
 *
 */
fr_ext_t const fr_dict_attr_ext_def = {
	.offset_of_exts = offsetof(fr_dict_attr_t, ext),
	.name_table	= dict_attr_ext_table,
	.name_table_len	= &dict_attr_ext_table_len,
	.max		= FR_DICT_ATTR_EXT_MAX,
	.info		= {
		[FR_DICT_ATTR_EXT_NAME]		= {
							.min = sizeof(char),
							.has_hdr = true,
							.can_copy = false,	/* Name may change, and we can only set it once */
						},
		[FR_DICT_ATTR_EXT_CHILDREN]	= {
							.min = sizeof(fr_dict_attr_ext_children_t),
							.can_copy = false,	/* Limitation in hashing scheme we use */
						},
		[FR_DICT_ATTR_EXT_REF]		= {
							.min = sizeof(fr_dict_attr_ext_ref_t),
							.can_copy = true,
						},
		[FR_DICT_ATTR_EXT_VENDOR]	= {
							.min = sizeof(fr_dict_attr_ext_vendor_t),
							.can_copy = true,
							.copy = fr_dict_attr_ext_vendor_copy
						},
		[FR_DICT_ATTR_EXT_DA_STACK]	= {
							.min = sizeof(fr_dict_attr_ext_da_stack_t),
							.has_hdr = true,
							.can_copy = false	/* Reinitialised for each new attribute */
						},
		[FR_DICT_ATTR_EXT_ENUMV]	= {
							.min = sizeof(fr_dict_attr_ext_enumv_t),
							.can_copy = true,
							.copy = fr_dict_attr_ext_enumv_copy
						},
		[FR_DICT_ATTR_EXT_NAMESPACE]	= {
							.min = sizeof(fr_dict_attr_ext_namespace_t),
							.can_copy = false,	/* Same limitation as ext_children */
						},
		[FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC] = {
							.min = sizeof(fr_dict_ext_protocol_specific_t),
							.can_copy = true
						},
		[FR_DICT_ATTR_EXT_MAX]		= {}
	}
};

static fr_table_num_ordered_t const dict_enum_ext_table[] = {
	{ L("union_ref"),	FR_DICT_ENUM_EXT_UNION_REF	}
};
static size_t dict_enum_ext_table_len = NUM_ELEMENTS(dict_enum_ext_table);

/** Holds additional information about extension structures
 *
 */
fr_ext_t const fr_dict_enum_ext_def = {
	.offset_of_exts = offsetof(fr_dict_enum_t, ext),
	.name_table	= dict_enum_ext_table,
	.name_table_len	= &dict_enum_ext_table_len,
	.max		= FR_DICT_ENUM_EXT_MAX,
	.info		= {
		[FR_DICT_ENUM_EXT_UNION_REF]	= {
							.min = sizeof(fr_dict_enum_ext_union_ref_t),
							.can_copy = true
						},
		[FR_DICT_ENUM_EXT_MAX]		= {}
	}
};

