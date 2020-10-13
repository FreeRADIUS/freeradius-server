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
 * @file src/lib/util/dict_attr_ext.c
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/dict_priv.h>

/** Holds the minimum lengths of the extension structures
 *
 */
size_t const fr_dict_ext_length_min[FR_DICT_ATTR_EXT_MAX] = {
	[FR_DICT_ATTR_EXT_CHILDREN]	= sizeof(fr_dict_attr_ext_children_t),
	[FR_DICT_ATTR_EXT_REF]		= sizeof(fr_dict_attr_ext_ref_t),
	[FR_DICT_ATTR_EXT_VENDOR]	= sizeof(fr_dict_attr_ext_vendor_t),
	[FR_DICT_ATTR_EXT_DA_STACK]	= sizeof(fr_dict_attr_ext_da_stack_t),
};

/** Add a variable length extension to a dictionary attribute
 *
 * Extensions are appended to the existing #fr_dict_attr_t memory chunk
 * using realloc.
 *
 * When a new extension is allocated it will not be initialised.
 *
 * @param[in] ctx	the dict attr was originally allocated in.
 * @param[in,out] da_p	The dictionary attribute to add an extension for.
 *			Under certain circumstances the value of *da_p will
 *			be changed to point to a new memory block.
 *			All cached copied of the previous pointer should be
 *			updated.  This means that attributes that have
 *			already been added to a dictionary should not have
 *			extensions allocated unless care is taken to update
 *			all references.
 * @param[in] ext	to alloc.
 * @param[in] ext_len	The length of the extension.
 * @return
 *	- NULL if we failed allocating an extension.
 *	- A pointer to the extension we allocated.
 */
void *dict_attr_ext_alloc_size(TALLOC_CTX *ctx, fr_dict_attr_t **da_p, fr_dict_attr_ext_t ext, size_t ext_len)
{
	size_t		len;
	size_t		aligned = ROUND_UP(ext_len, FR_DICT_ATTR_EXT_ALIGNMENT);
	size_t		offset;

	fr_dict_attr_t	*n_da, *da = *da_p;

	if (unlikely(da->dict && da->dict->read_only)) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root(da->dict)->name);
		return NULL;
	}

	if (da->ext[ext]) return fr_dict_attr_ext(da, ext);

	len = talloc_array_length((uint8_t *)da);

	offset = len / FR_DICT_ATTR_EXT_ALIGNMENT;
	if (offset > UINT8_MAX) {
		fr_strerror_printf("Insufficient space remaining for extensions");
		return NULL;
	}

	n_da = talloc_realloc_size(ctx, da, len + aligned);
	if (!n_da) return NULL;
	talloc_set_type(n_da, fr_dict_attr_t);

	*da_p = n_da;
	da->ext[ext] = (uint8_t)offset;

	return (void *)(((uintptr_t)n_da) + len);
}

/** Add a fixed length extension to a dictionary attribute
 *
 * Extensions are appended to the existing #fr_dict_attr_t memory chunk
 * using realloc.
 *
 * When a new extension is allocated it will not be initialised.
 * In the majority of instances this is OK as its value will be set
 * immediately, but care should be taken to ensure it is initialised
 * as some point.
 *
 * @param[in] ctx	the dict attr was originally allocated in.
 * @param[in,out] da_p	The dictionary attribute to add an extension for.
 *			Under certain circumstances the value of *da_p will
 *			be changed to point to a new memory block.
 *			All cached copied of the previous pointer should be
 *			updated.  This means that attributes that have
 *			already been added to a dictionary should not have
 *			extensions allocated unless care is taken to update
 *			all references.
 * @param[in] ext	to alloc.
 * @return
 *	- NULL if we failed allocating an extension.
 *	- A pointer to the extension we allocated.
 */
void *dict_attr_ext_alloc(TALLOC_CTX *ctx, fr_dict_attr_t **da_p, fr_dict_attr_ext_t ext)
{
	return dict_attr_ext_alloc_size(ctx, da_p, ext, fr_dict_ext_length_min[ext]);
}

/** Return the length of an extension
 *
 * @param[in] da	to return extension length for.
 * @param[in] ext	to return length for.
 * @return
 *	- 0 if no extension exists.
 *	- >0 the length of the extension.
 */
size_t dict_attr_ext_len(fr_dict_attr_t const *da, fr_dict_attr_ext_t ext)
{
	uint8_t	end = 0, start, i;
	size_t	len;

	start = da->ext[ext];
	if (!start) return 0;

	len = talloc_array_length((uint8_t const *)da);
	end = len / FR_DICT_ATTR_EXT_ALIGNMENT;

	/*
	 *	Figure out where the extension ends
	 */
	for (i = 0; i < NUM_ELEMENTS(da->ext); i++) {
		if ((da->ext[i] > start) && (da->ext[i] < end)) end = da->ext[i];
	}

	return (end - start) * FR_DICT_ATTR_EXT_ALIGNMENT;
}

/** Copy extension data from one attribute to another
 *
 * @param[in] ctx	to realloc da_out in.
 * @param[in] da_in	to copy extension from.
 * @param[in] ext	to copy.
 * @return
 *	- NULL if we failed to allocate an extension structure.
 *	- A pointer to the start of the extension in da_out.
 */
void *dict_attr_ext_copy(TALLOC_CTX *ctx,
			    fr_dict_attr_t **da_out_p, fr_dict_attr_t const *da_in, fr_dict_attr_ext_t ext)
{
	uint8_t start;
	size_t	ext_len;
	void	*ptr;

	if (unlikely((*da_out_p)->dict && (*da_out_p)->dict->read_only)) {
		fr_strerror_printf("%s dictionary has been marked as read only", fr_dict_root((*da_out_p)->dict)->name);
		return NULL;
	}

	start = da_in->ext[ext];
	if (!start) return NULL;

	ext_len = dict_attr_ext_len(da_in, ext);
	ptr = dict_attr_ext_alloc_size(ctx, da_out_p, ext, ext_len);
	if (!ptr) return NULL;

	/*
	 *	Copy extension data over
	 */
	memcpy(ptr, (void *)((uintptr_t)(da_in) + (start * FR_DICT_ATTR_EXT_ALIGNMENT)), ext_len);

	return ptr;
}
