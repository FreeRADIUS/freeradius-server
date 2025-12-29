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
 * @copyright 2020,2024 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/dict_priv.h>

static fr_table_num_ordered_t const dict_attr_ext_table[] = {
	{ L("name"),			FR_DICT_ATTR_EXT_NAME			},
	{ L("children"),		FR_DICT_ATTR_EXT_CHILDREN		},
	{ L("ref"),			FR_DICT_ATTR_EXT_REF			},
	{ L("key"),			FR_DICT_ATTR_EXT_KEY			},
	{ L("vendor"),			FR_DICT_ATTR_EXT_VENDOR			},
	{ L("da_stack"),		FR_DICT_ATTR_EXT_DA_STACK		},
	{ L("enumv"),			FR_DICT_ATTR_EXT_ENUMV			},
	{ L("namespace"),		FR_DICT_ATTR_EXT_NAMESPACE		},
	{ L("protocol-specific"),	FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC	}
};
static size_t dict_attr_ext_table_len = NUM_ELEMENTS(dict_attr_ext_table);

/** Fixup name pointer on realloc
 *
 */
static int fr_dict_attr_ext_name_fixup(UNUSED int ext,
				       TALLOC_CTX *chunk,
				       void *ext_ptr, UNUSED size_t ext_ptr_len)
{
	fr_dict_attr_t			*da = talloc_get_type_abort(chunk, fr_dict_attr_t);

	da->name = ext_ptr;

	return 0;
}

/** Copy all enumeration values from one attribute to another
 *
 */
static int fr_dict_attr_ext_enumv_copy(UNUSED int ext,
				       TALLOC_CTX *chunk_dst,
				       UNUSED void *dst_ext_ptr, UNUSED size_t dst_ext_len,
				       UNUSED TALLOC_CTX const *chunk_src,
				       UNUSED void *src_ext_ptr, UNUSED size_t src_ext_len)
{
	fr_dict_attr_t			*da_dst = talloc_get_type_abort(chunk_dst, fr_dict_attr_t);
	fr_dict_attr_ext_enumv_t	*src_ext = src_ext_ptr;
	fr_hash_iter_t			iter;
	fr_dict_enum_value_t		*enumv;
	fr_value_box_t			box;
	fr_value_box_t const		*vb;

	if (!src_ext->value_by_name) return 0;

	/*
	 *	Add all the enumeration values from
	 *      the old attribute to the new attribute.
	 */
	for (enumv = fr_hash_table_iter_init(src_ext->value_by_name, &iter);
	     enumv;
	     enumv = fr_hash_table_iter_next(src_ext->value_by_name, &iter)) {
		fr_dict_enum_ext_attr_ref_t *ref;
		fr_dict_attr_t const *key_child_ref;

		key_child_ref = NULL;

		/*
		 *	If the enum refers to a child, it MUST refer to a child of a union.
		 *
		 *	We then re-write the ref to point to the newly copied child.
		 */
		ref = fr_dict_enum_ext(enumv, FR_DICT_ENUM_EXT_ATTR_REF);
		if (ref) {
			fr_dict_attr_t const *ref_parent;

			fr_assert(ref->da->parent->type == FR_TYPE_UNION);

			ref_parent = fr_dict_attr_by_name(NULL, da_dst->parent, ref->da->parent->name);
			fr_assert(ref_parent);
			fr_assert(ref_parent->type == FR_TYPE_UNION);

			/*
			 *	The reference has to exist.
			 */
			key_child_ref = fr_dict_attr_by_name(NULL, ref_parent, ref->da->name);
			fr_assert(key_child_ref != NULL);
		}

		vb = enumv->value;
		if (da_dst->type != enumv->value->type) {
			fr_assert(fr_type_is_integer(enumv->value->type));
			fr_assert(fr_type_is_integer(da_dst->type));

			if (fr_value_box_cast(da_dst, &box, da_dst->type, NULL, enumv->value) < 0) return -1;

			vb = &box;
		}

		if (dict_attr_enum_add_name(da_dst, enumv->name, vb,
					    true, true, key_child_ref) < 0) return -1;
	}

	return 0;
}

/** Rediscover the parent of this attribute, and cache it
 *
 */
static int fr_dict_attr_ext_vendor_copy(UNUSED int ext,
					TALLOC_CTX *chunk_dst,
					void *dst_ext_ptr, UNUSED size_t dst_ext_len,
					UNUSED TALLOC_CTX const *chunk_src,
					void *src_ext_ptr, UNUSED size_t src_ext_len)
{
	fr_dict_attr_t			*da_dst = talloc_get_type_abort(chunk_dst, fr_dict_attr_t);
	fr_dict_attr_ext_vendor_t	*dst_ext = dst_ext_ptr, *src_ext = src_ext_ptr;
	fr_dict_attr_t const		**da_stack;
	fr_dict_attr_t const		*old_vendor = src_ext->vendor;
	fr_dict_attr_t const		*new_vendor, *da;

	if (!old_vendor) {
		dst_ext->vendor = NULL;
		return 0;
	}

	/*
	 *	If we have a da stack, see if we can
	 *	find a vendor at the same depth as
	 *	the old depth.
	 */
	da_stack = fr_dict_attr_da_stack(da_dst);
	if (da_stack) {
		new_vendor = da_stack[old_vendor->depth];
		if ((new_vendor->type == old_vendor->type) && (new_vendor->attr == old_vendor->attr)) {
			dst_ext->vendor = new_vendor;
			return 0;
		}
	}

	/*
	 *	Otherwise traverse the parent list
	 *	looking for the vendor.
	 *
	 *	Theoretically the attribute could
	 *	have been moved to a different depth.
	 */
	for (da = da_dst->parent; da; da = da->parent) {
		if ((da->type == old_vendor->type) && (da->attr == old_vendor->attr)) {
			dst_ext->vendor = da;
			return 0;
		}
	}

	return -1;
}

static int dict_ext_protocol_specific_copy(UNUSED int ext,
			      		   TALLOC_CTX *dst_chunk,
					   void *dst_ext_ptr, size_t dst_ext_len,
					   TALLOC_CTX const *src_chunk,
					   void *src_ext_ptr, size_t src_ext_len)
{
	fr_dict_attr_t const		*from = talloc_get_type_abort_const(src_chunk, fr_dict_attr_t);
	fr_dict_protocol_t const	*from_proto = fr_dict_protocol(from->dict);
	fr_dict_attr_t			*to = talloc_get_type_abort(dst_chunk, fr_dict_attr_t);
	fr_dict_protocol_t const	*to_proto = fr_dict_protocol(to->dict);

	/*
	 *	Whilst it's not strictly disallowed, we can't do anything
	 *	sane without an N x N matrix of copy functions for different
	 *	protocols.  Maybe we should add that at some point, but for
	 *	now, just ignore the copy.
	 */
	if (from->dict != to->dict) return 0;

	/*
	 *	Sanity checks...
	 */
	if (unlikely(from_proto->attr.flags.len != src_ext_len)) {
		fr_strerror_printf("Protocol specific extension length mismatch in source attribute %s.  Expected %zu, got %zu",
				   from->name,
				   fr_dict_protocol(from->dict)->attr.flags.len, src_ext_len);
		return -1;
	}

	if (unlikely(to_proto->attr.flags.len != dst_ext_len)) {
		fr_strerror_printf("Protocol specific extension length mismatch in destination attribute %s.  Expected %zu, got %zu",
				   to->name,
				   fr_dict_protocol(to->dict)->attr.flags.len, dst_ext_len);
		return -1;
	}

	/*
	 *	The simple case... No custom copy function, just memcpy
	 */
	if (!to_proto->attr.flags.copy) {
		memcpy(dst_ext_ptr, src_ext_ptr, src_ext_len);
		return 0;
	}

	/*
	 *	Call the custom copy function.  This is only needed if
	 *	there are heap allocated values, like strings, which
	 *	need copying from sources flags to the destination.
	 */
	return to_proto->attr.flags.copy(dst_chunk, dst_ext_ptr, src_ext_ptr);
}

/** Rediscover the key reference for this attribute, and cache it
 *
 *  The UNION has a ref to the key DA, which is a sibling of the union.
 */
static int fr_dict_attr_ext_key_copy(UNUSED int ext,
				     TALLOC_CTX *chunk_dst,
				     void *dst_ext_ptr, UNUSED size_t dst_ext_len,
				     UNUSED TALLOC_CTX const *chunk_src,
				     void *src_ext_ptr, UNUSED size_t src_ext_len)
{
	fr_dict_attr_t			*da_dst = talloc_get_type_abort(chunk_dst, fr_dict_attr_t);
	fr_dict_attr_ext_ref_t		*dst_ext = dst_ext_ptr, *src_ext = src_ext_ptr;
	fr_dict_attr_t const		*key;

	fr_assert(da_dst->parent);
	fr_assert(da_dst->type == FR_TYPE_UNION);
	fr_assert(src_ext->type == FR_DICT_ATTR_REF_KEY);

	fr_assert(da_dst->parent != src_ext->ref->parent);

	key = fr_dict_attr_by_name(NULL, da_dst->parent, src_ext->ref->name);
	if (!key) {
		fr_strerror_printf("Parent %s has no key attribute '%s'",
				   da_dst->parent->name, src_ext->ref->name);
		return -1;
	}

	dst_ext->ref = key;	/* @todo - is ref_target? */

	return 0;
}

/** Holds additional information about extension structures
 *
 */
fr_ext_t const fr_dict_attr_ext_def = {
	.offset_of_exts = offsetof(fr_dict_attr_t, ext),
	.name_table	= dict_attr_ext_table,
	.name_table_len	= &dict_attr_ext_table_len,
	.max		= FR_DICT_ATTR_EXT_MAX,
	.info		=  (fr_ext_info_t[]){ /* -Wgnu-flexible-array-initializer */
		[FR_DICT_ATTR_EXT_NAME]		= {
							.min = sizeof(char),
							.has_hdr = true,
							.fixup = fr_dict_attr_ext_name_fixup,
							.can_copy = false,		/* Name may change, and we can only set it once */
						},
		[FR_DICT_ATTR_EXT_CHILDREN]	= {
							.min = sizeof(fr_dict_attr_ext_children_t),
							.can_copy = false,		/* Limitation in hashing scheme we use */
						},
		[FR_DICT_ATTR_EXT_REF]		= {
							.min = sizeof(fr_dict_attr_ext_ref_t),
							/*
							 *	Copying a CLONE or ENUM is OK.
							 *
							 *	@todo - copying an ALIAS will copy the name,
							 *	but the ref will be to the original destination DA.
							 */
							.can_copy = true,
						},
		[FR_DICT_ATTR_EXT_KEY]		= {
							/*
							 *	keys are mostly like refs, but they're not
							 *	auto-followed like refs.  The difference is
							 *	that we can copy a ref as-is, because the ref
							 *	points to something which exists, and is
							 *	independent of us.
							 *
							 *	But a key ref is only used in a UNION, and
							 *	then points to the key attribute of the parent
							 *	structure.  If we do allow copying a UNION, we
							 *	will also need to specify the new key ref.
							 *
							 *	So we need a special copy function.
							 */
							.min = sizeof(fr_dict_attr_ext_ref_t),
							.copy = fr_dict_attr_ext_key_copy,
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
							.can_copy = false		/* Reinitialised for each new attribute */
						},
		[FR_DICT_ATTR_EXT_ENUMV]	= {
							.min = sizeof(fr_dict_attr_ext_enumv_t),
							.can_copy = true,
							.copy = fr_dict_attr_ext_enumv_copy
						},
		[FR_DICT_ATTR_EXT_NAMESPACE]	= {
							.min = sizeof(fr_dict_attr_ext_namespace_t),
							.can_copy = false,		/* Same limitation as ext_children */
						},
		[FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC] = {
							.min = FR_EXT_ALIGNMENT,  	/* allow for one byte of protocol stuff */
							.has_hdr = true,		/* variable sized */
							.copy = dict_ext_protocol_specific_copy,
							.can_copy = true		/* Use the attr.flags.copy function */
						},
		[FR_DICT_ATTR_EXT_MAX]		= {}
	}
};

static fr_table_num_ordered_t const dict_enum_ext_table[] = {
	{ L("attr_ref"),	FR_DICT_ENUM_EXT_ATTR_REF	}
};
static size_t dict_enum_ext_table_len = NUM_ELEMENTS(dict_enum_ext_table);

void fr_dict_attr_ext_debug(fr_dict_attr_t const *da)
{
	fr_ext_debug(&fr_dict_attr_ext_def, da->name, da);
}

/** Holds additional information about extension structures
 *
 */
fr_ext_t const fr_dict_enum_ext_def = {
	.offset_of_exts = offsetof(fr_dict_enum_value_t, ext),
	.name_table	= dict_enum_ext_table,
	.name_table_len	= &dict_enum_ext_table_len,
	.max		= FR_DICT_ENUM_EXT_MAX,
	.info		= (fr_ext_info_t[]){ /* -Wgnu-flexible-array-initializer */
		[FR_DICT_ENUM_EXT_ATTR_REF] = {
							.min = sizeof(fr_dict_enum_ext_attr_ref_t),
							.can_copy = true
						},
		[FR_DICT_ENUM_EXT_MAX]		= {}
	}
};
