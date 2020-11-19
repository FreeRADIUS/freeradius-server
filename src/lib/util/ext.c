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

/** 'compositing' using talloced structures
 *
 * @file src/lib/util/ext.c
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/ext.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/table.h>
#include <freeradius-devel/util/talloc.h>

#define CHUNK_EXT_PTR(_chunk, _chunk_ext, _ext) ((void *)((chunk_ext[_ext] * FR_EXT_ALIGNMENT) + ((uintptr_t)(_chunk))))
#define CHUNK_EXT(_chunk, _offset) ((uint8_t *)(((uintptr_t)_chunk) + (_offset)))

/** Add a variable length extension to a talloc chunk
 *
 * This is used to build a structure from a primary struct type and one or more
 * extension structures.  The memory for the composed structure is contiguous which
 * has performance benefits, and means we don't have the overhead of talloc headers
 * for each of the extensions.
 *
 * @note When a new extension is allocated its memory will not be initialised.
 *
 * @note It is highly recommended to allocate composed structures within a talloc_pool
 * to avoid the overhead of malloc+memcpy.
 *
 * @param[in] def		Extension definitions.
 * @param[in,out] chunk_p	The chunk to add an extension for.
 *				Under certain circumstances the value of *chunk_p will
 *				be changed to point to a new memory block.
 *				All cached copies of the previous pointer should be
 *				updated.
 * @param[in] ext		to alloc.
 * @param[in] ext_len		The length of the extension.
 * @return
 *	- NULL if we failed allocating an extension.
 *	- A pointer to the extension we allocated.
 */
void *fr_ext_alloc_size(fr_ext_t const *def, void **chunk_p, int ext, size_t ext_len)
{
	size_t			aligned_len = ROUND_UP_POW2(ext_len, FR_EXT_ALIGNMENT);
	size_t			chunk_len;
	size_t			hdr_len = 0;

	size_t			offset;

	fr_ext_info_t const	*info;
	void			*n_chunk, *chunk = *chunk_p;
	uint8_t			*chunk_ext;
	uint8_t			*ext_ptr;
	char const		*type;

	chunk_ext = CHUNK_EXT(*chunk_p, def->offset_of_exts);
	if (chunk_ext[ext]) return CHUNK_EXT_PTR(*chunk_p, chunk_ext, ext);

 	info = &def->info[ext];
	if (info->has_hdr) hdr_len = sizeof(dict_ext_hdr_t);	/* Add space for a length prefix */

	/*
	 *	Packing the offsets into a uint8_t array
	 *	means the offset address of the final
	 *	extension must be less than or equal to
	 *	UINT8_MAX * FR_EXT_ALIGNMENT.
	 */
	chunk_len = talloc_get_size(chunk);
	offset = (chunk_len + hdr_len) / FR_EXT_ALIGNMENT;
	if (unlikely(offset > UINT8_MAX)) {
		fr_strerror_printf("Insufficient space remaining for extensions");
		return NULL;
	}

	/*
	 *	talloc_realloc_size unhelpfully forgets
	 *	the name of the chunk, so we need to
	 *	record it and set it back again.
	 */
	type = talloc_get_name(chunk);
	n_chunk = talloc_realloc_size(NULL, chunk, chunk_len + hdr_len + aligned_len);
	if (!n_chunk) {
		fr_strerror_printf("Failed reallocing %s (%s).  Tried to realloc %zu bytes -> %zu bytes",
				   type, fr_syserror(errno), chunk_len, chunk_len + aligned_len);
		return NULL;
	}
	talloc_set_name_const(n_chunk, type);
	*chunk_p = n_chunk;

	chunk_ext = CHUNK_EXT(*chunk_p, def->offset_of_exts);
	chunk_ext[ext] = (uint8_t)offset;

	ext_ptr = ((uint8_t *)n_chunk) + chunk_len;

	if (info->has_hdr) {
		dict_ext_hdr_t *ext_hdr = (dict_ext_hdr_t *)ext_ptr;

		ext_hdr->len = ext_len;		/* Record the real size */
		return &ext_hdr->data;		/* Pointer to the data portion */
	}

	return ext_ptr;
}

/** Return the length of an extension
 *
 * @param[in] def		Extension definitions.
 * @param[in] chunk		to return extension length for.
 * @param[in] ext		to return length for.
 * @return
 *	- 0 if no extension exists or is of zero length.
 *	- >0 the length of the extension.
 */
size_t fr_ext_len(fr_ext_t const *def, void const *chunk, int ext)
{
	uint8_t			offset;
	fr_ext_info_t const	*info;
	dict_ext_hdr_t		*ext_hdr;
	uint8_t			*chunk_ext;

	chunk_ext = CHUNK_EXT(chunk, def->offset_of_exts);
	offset = chunk_ext[ext];
	if (!offset) return 0;

	info = &def->info[ext];
	if (!info->has_hdr) return info->min;	/* Fixed size */

	ext_hdr = (dict_ext_hdr_t *)((uintptr_t)chunk) + ((offset * FR_EXT_ALIGNMENT) - sizeof(dict_ext_hdr_t));
	return ext_hdr->len;
}

/** Copy extension data from one attribute to another
 *
 * @param[in] def		Extension definitions.
 * @param[in,out] chunk_out	to copy extension to.
 *				Under certain circumstances the value of *chunk_out will
 *				be changed to point to a new memory block.
 *				All cached copies of the previous pointer should be
 *				updated.
 * @param[in] chunk_in		to copy extension from.
 * @param[in] ext		to copy.
 * @return
 *	- NULL if we failed to allocate an extension structure.
 *	- A pointer to the offset of the extension in da_out.
 */
void *fr_ext_copy(fr_ext_t const *def, void **chunk_out, void const *chunk_in, int ext)
{
	void	*ext_ptr, *new_ext_ptr;
	uint8_t	*chunk_ext;
	size_t	ext_len;

	fr_ext_info_t const *info;

	info = &def->info[ext];
	if (!info->can_copy) {
		fr_strerror_printf("Extension cannot be copied");
		return NULL;
	}

	chunk_ext = CHUNK_EXT(chunk_in, def->offset_of_exts);
	ext_ptr = CHUNK_EXT_PTR(chunk_in, chunk_ext, ext);
	if (!ext_ptr) return NULL;

	ext_len = fr_ext_len(def, chunk_in, ext);

	/*
	 *	Use the special copy function.
	 *	Its responsible for allocating the extension in the
	 *      destination attribute.
	 */
	if (info->copy) return info->copy(chunk_out, ext, ext_ptr, ext_len);

	/*
	 *	If there's no special function
	 *	just memcpy the data over.
	 */
	new_ext_ptr = fr_ext_alloc_size(def, chunk_out, ext, ext_len);
	if (!new_ext_ptr) return NULL;
	memcpy(new_ext_ptr, ext_ptr, ext_len);

	return new_ext_ptr;
}

/** Copy all the extensions from one attribute to another
 *
 * @param[in] def		Extension definitions.
 * @param[in,out] chunk_out	to copy extensions to.
 *				Under certain circumstances the value of *chunk_out will
 *				be changed to point to a new memory block.
 *				All cached copies of the previous pointer should be
 *				updated.
 * @param[in] chunk_in		to copy extensions from.
 * @return
 *	- 0 on success.
 *	- -1 if a copy operation failed.
 */
int fr_ext_copy_all(fr_ext_t const *def, void **chunk_out, void const *chunk_in)
{
	int	i;
	uint8_t	*ext_in = CHUNK_EXT(chunk_in, def->offset_of_exts);

	for (i = 0; i < def->max; i++) {
		if (!ext_in[i] || !def->info[i].can_copy) continue;
		if (!fr_ext_copy(def, chunk_out, chunk_in, i)) return -1;
	}

	return 0;
}

/** Print out all extensions and hexdump their contents
 *
 * This function is intended to be called from interactive debugging
 * sessions only.  It does not use the normal logging infrastructure.
 *
 * @param[in] def		Extension definitions.
 * @param[in] name		the identifier of the structure
 *				being debugged i.e da->name.
 * @param[in] chunk		to debug.
 */
void fr_ext_debug(fr_ext_t const *def, char const *name, void const *chunk)
{
	int i;

	FR_FAULT_LOG("%sext total_len=%zu", name, talloc_get_size(chunk));
	for (i = 0; i < (int)def->max; i++) {
		uint8_t *chunk_ext = CHUNK_EXT(def->info, def->offset_of_exts);
		if (chunk_ext[i]) {
			void		*ext = CHUNK_EXT_PTR(chunk, chunk_ext, i);
			size_t		ext_len = fr_ext_len(def, chunk, i);

			char const	*ext_name = fr_table_ordered_str_by_num(def->name_table,
										*def->name_table_len,
										i, "<INVALID>");

			if (ext_len > 1024) {
				FR_FAULT_LOG("%sext id=%s - possibly bad length %zu - limiting dump to 1024",
					     name, ext_name, ext_len);
				ext_len = 1024;
			}

			FR_FAULT_LOG("%sext id=%s start=%p end=%p len=%zu",
				     name, ext_name, ext, ((uint8_t *)ext) + ext_len, ext_len);
			FR_FAULT_LOG_HEX(ext, ext_len);
		}
	}
}
