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
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

extern fr_ext_t const fr_dict_attr_ext_def;
extern fr_ext_t const fr_dict_enum_ext_def;

/** @name Add extension structures to attributes
 *
 * @{
 */

/** Allocate an attribute extension of a particular size
 *
 */
static inline void *dict_attr_ext_alloc_size(fr_dict_attr_t **da_p, fr_dict_attr_ext_t ext, size_t ext_len)
{
	if (!(*da_p)->flags.is_unknown && unlikely((*da_p)->dict && fr_dict_is_read_only((*da_p)->dict))) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root((*da_p)->dict)->name);
		return NULL;
	}

	return fr_ext_alloc_size(&fr_dict_attr_ext_def, (void **)da_p, ext, ext_len);
}

/** Allocate an attribute extension
 *
 */
static inline void *dict_attr_ext_alloc(fr_dict_attr_t **da_p, fr_dict_attr_ext_t ext)
{
	if (!(*da_p)->flags.is_unknown && unlikely((*da_p)->dict && fr_dict_is_read_only((*da_p)->dict))) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root((*da_p)->dict)->name);
		return NULL;
	}

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
	if (unlikely((*da_out_p)->dict && fr_dict_is_read_only((*da_out_p)->dict))) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root((*da_out_p)->dict)->name);
		return NULL;
	}

	return fr_ext_copy(&fr_dict_attr_ext_def, (void **)da_out_p, (void const *)da_in, ext);
}

/** Copy all attribute extensions from one attribute to another
 *
 */
static inline int dict_attr_ext_copy_all(fr_dict_attr_t **da_out_p, fr_dict_attr_t const *da_in)
{
	if (unlikely((*da_out_p)->dict && fr_dict_is_read_only((*da_out_p)->dict))) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root((*da_out_p)->dict)->name);
		return -1;
	}

	return fr_ext_copy_all(&fr_dict_attr_ext_def, (void **)da_out_p, (void const *)da_in);
}

/** Print extension debug information for attributes
 *
 */
static inline void dict_attr_ext_debug(fr_dict_attr_t const *da)
{
	fr_ext_debug(&fr_dict_attr_ext_def, da->name, da);
}
/** @} */

/** @name Convenience functions for populating attribute extensions
 *
 * @{
 */
static inline int dict_attr_ref_set(fr_dict_attr_t const *da, fr_dict_attr_t const *ref)
{
	fr_dict_attr_ext_ref_t	*ext;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_REF);
	if (unlikely(!ext)) {
		fr_strerror_printf("%s (%s) contains no 'ref' extension", da->name,
	   			   fr_table_str_by_value(fr_value_box_type_table, da->type, "<UNKNOWN>"));
		return -1;
	}
	ext->ref = ref;

	return 0;
}

static inline int dict_attr_children_set(fr_dict_attr_t const *da, fr_dict_attr_t const	**children)
{
	fr_dict_attr_ext_children_t *ext;

	ext = fr_dict_attr_ext(da, FR_DICT_ATTR_EXT_CHILDREN);
	if (unlikely(!ext)) {
		fr_strerror_printf("%s (%s) contains no 'children' extension", da->name,
	   			   fr_table_str_by_value(fr_value_box_type_table, da->type, "<UNKNOWN>"));
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
		fr_strerror_printf("%s (%s) contains no 'children' extension", da->name,
	   			   fr_table_str_by_value(fr_value_box_type_table, da->type, "<UNKNOWN>"));
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

#ifdef __cplusplus
}
#endif
