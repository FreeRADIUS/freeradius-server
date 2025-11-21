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

/** Extensions for dictionary definitions
 *
 * @file src/lib/util/dict_ext_priv.h
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(dict_ext_priv_h, "$Id$")

#include <freeradius-devel/util/dict.h>
#include <freeradius-devel/util/dict_ext.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @name Add extension structures to attributes
 *
 * @{
 */

static inline bool dict_attr_ext_mutable(fr_dict_attr_t **da_p)
{
	if ((*da_p)->flags.is_ref_target) {
		fr_strerror_printf("%s is already the target of a reference, and cannot be changed", (*da_p)->name);
		return false;
	}

	if (!(*da_p)->flags.is_unknown && unlikely((*da_p)->dict && fr_dict_is_read_only((*da_p)->dict))) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root((*da_p)->dict)->name);
		return false;
	}

	return true;
}

/** Allocate an attribute extension of a particular size
 *
 */
static inline void *dict_attr_ext_alloc_size(fr_dict_attr_t **da_p, fr_dict_attr_ext_t ext, size_t ext_len)
{
	if (!dict_attr_ext_mutable(da_p)) return NULL;

	return fr_ext_alloc_size(&fr_dict_attr_ext_def, (void **)da_p, ext, ext_len);
}

/** Allocate an attribute extension
 *
 */
static inline void *dict_attr_ext_alloc(fr_dict_attr_t **da_p, fr_dict_attr_ext_t ext)
{
	if (!dict_attr_ext_mutable(da_p)) return NULL;

	return fr_ext_alloc_size(&fr_dict_attr_ext_def, (void **)da_p, ext, fr_dict_attr_ext_def.info[ext].min);
}

/** Return the length of an attribute extension
 *
 */
static inline size_t dict_attr_ext_len(fr_dict_attr_t const *da, fr_dict_attr_ext_t ext)
{
	return fr_ext_len(&fr_dict_attr_ext_def, (void const *)da, ext);
}

/** Copy a single attribute extension from one attribute to another
 *
 */
static inline void *dict_attr_ext_copy(fr_dict_attr_t **da_out_p, fr_dict_attr_t const *da_in, fr_dict_attr_ext_t ext)
{
	if (!dict_attr_ext_mutable(da_out_p)) return NULL;

	/*
	 *	We might be able to copy things for unknown
	 *	attributes.  But if the unknown is of type 'octets',
	 *	then we can only copy the protocol-specific things.
	 */
#ifndef NDEBUG
	if ((*da_out_p)->flags.is_unknown && ((*da_out_p)->type == FR_TYPE_OCTETS)) {
		fr_assert((ext == FR_DICT_ATTR_EXT_PROTOCOL_SPECIFIC) || (ext == FR_DICT_ATTR_EXT_VENDOR));
	}
#endif

	return fr_ext_copy(&fr_dict_attr_ext_def, (void **)da_out_p, (void const *)da_in, ext);
}

/** Copy all attribute extensions from one attribute to another
 *
 */
static inline int dict_attr_ext_copy_all(fr_dict_attr_t **da_out_p, fr_dict_attr_t const *da_in)
{
	if (!dict_attr_ext_mutable(da_out_p)) return -1;

	return fr_ext_copy_all(&fr_dict_attr_ext_def, (void **)da_out_p, (void const *)da_in);
}

/** Print extension debug information for attributes
 *
 */
static inline void dict_attr_ext_debug(char const *name, fr_dict_attr_t const *da)
{
	fr_ext_debug(&fr_dict_attr_ext_def, name, da);
}
/** @} */

/** @name Convenience functions for populating attribute extensions
 *
 * @{
 */

static inline int dict_attr_ref_null(fr_dict_attr_t const *da)
{
	fr_dict_attr_ext_ref_t	*ext;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_REF);
	if (unlikely(!ext)) {
		fr_strerror_printf("Contains no 'ref' extension");
		return -1;
	}

	if (unlikely((ext->type & FR_DICT_ATTR_REF_UNRESOLVED) != 0)) {
		fr_strerror_printf("Contains an resolved 'ref' extension");
		return -1;
	}

	ext->type = 0;
	ext->ref = NULL;

	return 0;
}

static inline int dict_attr_ref_aset(fr_dict_attr_t **da_p, fr_dict_attr_t const *ref, fr_dict_attr_ref_type_t type)
{
	fr_dict_attr_ext_ref_t	*ext;

	ext = fr_dict_attr_ext(*da_p, FR_DICT_ATTR_EXT_REF);
	if (unlikely(!ext)) {
		ext = dict_attr_ext_alloc(da_p, FR_DICT_ATTR_EXT_REF);
	}

	/*
	 *	Check that the attribute ref is unresolved.
	 */
	if (unlikely((type & FR_DICT_ATTR_REF_UNRESOLVED) != 0)) {
		fr_strerror_printf("Reference type cannot be unresolved");
		return -1;
	}

	ext->type = type;
	ext->ref = ref;

	return 0;
}

static inline int dict_attr_ref_set(fr_dict_attr_t const *da, fr_dict_attr_t const *ref, fr_dict_attr_ref_type_t type)
{
	fr_dict_attr_ext_ref_t	*ext;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_REF);
	if (unlikely(!ext)) {
		fr_strerror_printf("Attribute contains no 'ref' extension");
		return -1;
	}

	/*
	 *	Check that the attribute ref is unresolved.
	 */
	if (unlikely((type & FR_DICT_ATTR_REF_UNRESOLVED) != 0)) {
		fr_strerror_printf("Reference type cannot be unresolved");
		return -1;
	}

	ext->type = type;
	ext->ref = ref;

	UNCONST(fr_dict_attr_t *, ref)->flags.is_ref_target = true;

	return 0;
}

static inline int dict_attr_ref_resolve(fr_dict_attr_t const *da, fr_dict_attr_t const *ref)
{
	fr_dict_attr_ext_ref_t	*ext;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_REF);
	if (unlikely(!ext)) {
		fr_strerror_printf("Contains no 'ref' extension");
		return -1;
	}

	/*
	 *	Check that the attribute ref is unresolved.
	 */
	if (unlikely(fr_dict_attr_ref_is_unresolved(ext->type) == false)) {
		fr_strerror_printf("Contains an resolved 'ref' extension");
		return -1;
	}

	ext->type ^= FR_DICT_ATTR_REF_UNRESOLVED;
	talloc_free(ext->unresolved);
	ext->ref = ref;

	return 0;
}

static inline int dict_attr_ref_aunresolved(fr_dict_attr_t **da_p, char const *ref, fr_dict_attr_ref_type_t type)
{
	fr_dict_attr_ext_ref_t	*ext;
	fr_dict_attr_t		*da;

	ext = fr_dict_attr_ext((*da_p), FR_DICT_ATTR_EXT_REF);
	if (unlikely(!ext)) {
		ext = dict_attr_ext_alloc(da_p, FR_DICT_ATTR_EXT_REF);
		if (unlikely(!ext)) return -1;
	}
	da = *da_p;
	if (unlikely(ext->type != 0)) {
		fr_strerror_printf("Attribute already has a 'ref=...' defined");
		return -1;
	}
	ext->type = type | FR_DICT_ATTR_REF_UNRESOLVED;	/* Always unresolved */
	ext->unresolved = talloc_typed_strdup(da, ref);

	return 0;
}

static inline int dict_attr_children_set(fr_dict_attr_t const *da, fr_dict_attr_t const	**children)
{
	fr_dict_attr_ext_children_t *ext;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_CHILDREN);
	if (unlikely(!ext)) {
		fr_strerror_printf("Attribute contains no 'children' extension");
		return -1;
	}
	ext->children = children;

	return 0;
}

static inline fr_dict_attr_t const **dict_attr_children(fr_dict_attr_t const *da)
{
	fr_dict_attr_ext_children_t *ext;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_CHILDREN);
	if (unlikely(!ext)) {
		fr_strerror_printf("Attribute contains no 'children' extension");
		return NULL;
	}
	return ext->children;
}

/** Return the namespace hash table associated with the attribute
 *
 * @param[in] da	to return the reference for.
 * @return
 *	- NULL if no namespace available.
 *	- A pointer to the namespace hash table
 */
static inline fr_hash_table_t *dict_attr_namespace(fr_dict_attr_t const *da)
{
	fr_dict_attr_t const		*ref;
	fr_dict_attr_ext_namespace_t	*ext;

	ref = fr_dict_attr_ref(da);
	if (unlikely(ref != NULL)) return NULL;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_NAMESPACE);
	if (!ext) return NULL;

	return ext->namespace;
}
/** @} */

/** Allocate an enum extension
 *
 */
static inline void *dict_enum_ext_alloc(fr_dict_enum_value_t **enumv_p, fr_dict_enum_ext_t ext)
{
	fr_assert(!fr_dict_enum_ext(*enumv_p, ext));

	return fr_ext_alloc_size(&fr_dict_enum_ext_def, (void **)enumv_p, ext, fr_dict_enum_ext_def.info[ext].min);
}

#ifdef __cplusplus
}
#endif
