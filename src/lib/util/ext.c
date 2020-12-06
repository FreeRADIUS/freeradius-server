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

/** Add a variable length extension to a talloc chunk
 *
 * This is used to build a structure from a primary struct type and one or more
 * extension structures.  The memory for the composed structure is contiguous which
 * has performance benefits, and means we don't have the overhead of talloc headers
 * for each of the extensions.
 *
 * @note When a new extension is allocated its memory will be zeroed.
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

	fr_ext_info_t const	*info = &def->info[ext];
	void			*n_chunk, *chunk = *chunk_p;
	uint8_t			*ext_offsets;
	uint8_t			*ext_ptr;
	char const		*type;

	ext_offsets = fr_ext_offsets(def, *chunk_p);
	if (ext_offsets[ext]) return fr_ext_ptr(*chunk_p, ext_offsets[ext], info->has_hdr);

	if (info->has_hdr) hdr_len = sizeof(fr_ext_hdr_t);	/* Add space for a length prefix */

	/*
	 *	Packing the offsets into a uint8_t array
	 *	means the offset address of the final
	 *	extension must be less than or equal to
	 *	UINT8_MAX * FR_EXT_ALIGNMENT.
	 */
	chunk_len = talloc_get_size(chunk);
	offset = ROUND_UP_DIV(chunk_len, FR_EXT_ALIGNMENT);
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
	n_chunk = talloc_realloc_size(NULL, chunk, (offset * FR_EXT_ALIGNMENT) + hdr_len + aligned_len);
	if (!n_chunk) {
		fr_strerror_printf("Failed reallocing %s (%s).  Tried to realloc %zu bytes -> %zu bytes",
				   type, fr_syserror(errno), chunk_len, chunk_len + aligned_len);
		return NULL;
	}
	talloc_set_name_const(n_chunk, type);

	ext_offsets = fr_ext_offsets(def, n_chunk);
	ext_offsets[ext] = (uint8_t)offset;

	ext_ptr = ((uint8_t *)n_chunk) + chunk_len;
	memset(ext_ptr, 0, hdr_len + aligned_len);

	*chunk_p = n_chunk;

	if (info->has_hdr) {
		fr_ext_hdr_t *ext_hdr = (fr_ext_hdr_t *)ext_ptr;

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
size_t fr_ext_len(fr_ext_t const *def, TALLOC_CTX const *chunk, int ext)
{
	uint8_t			offset;
	fr_ext_info_t const	*info;
	fr_ext_hdr_t		*ext_hdr;
	uint8_t			*ext_offsets;

	ext_offsets = fr_ext_offsets(def, chunk);
	offset = ext_offsets[ext];
	if (!offset) return 0;

	info = &def->info[ext];
	if (!info->has_hdr) return info->min;		/* Fixed size */

	ext_hdr = fr_ext_ptr(chunk, offset, false);	/* false as we're getting the header */
	return ext_hdr->len;
}

/** Copy extension data from one attribute to another
 *
 * @param[in] def		Extension definitions.
 * @param[in,out] chunk_dst	to copy extension to.
 *				Under certain circumstances the value of *chunk_dst will
 *				be changed to point to a new memory block.
 *				All cached copies of the previous pointer should be
 *				updated.
 * @param[in] chunk_src		to copy extension from.
 * @param[in] ext		to copy.
 * @return
 *	- NULL if we failed to allocate an extension structure.
 *	- A pointer to the offset of the extension in da_out.
 */
void *fr_ext_copy(fr_ext_t const *def, TALLOC_CTX **chunk_dst, TALLOC_CTX const *chunk_src, int ext)
{
	int			i;
	uint8_t			*ext_src_offsets = fr_ext_offsets(def, chunk_src);
	uint8_t			*ext_dst_offsets = fr_ext_offsets(def, *chunk_dst);
	void			*ext_src_ptr, *ext_dst_ptr;
	fr_ext_info_t const	*info = &def->info[ext];

	if (!info->can_copy) {
		fr_strerror_printf("Extension cannot be copied");
		return NULL;
	}

	if (!ext_src_offsets[ext]) return NULL;

	ext_src_ptr = fr_ext_ptr(chunk_src, ext_src_offsets[ext], info->has_hdr);

	/*
	 *	Only alloc if the extension doesn't
	 *	already exist.
	 */
	if (!ext_dst_offsets[ext]) {
		if (info->alloc) {
			ext_dst_ptr = info->alloc(def, chunk_dst, ext,
						  ext_src_ptr,
						  fr_ext_len(def, chunk_src, ext));
		/*
		 *	If there's no special alloc function
		 *	we just allocate a chunk of the same
		 *	size.
		 */
		} else {
			ext_dst_ptr = fr_ext_alloc_size(def, chunk_dst, ext,
							fr_ext_len(def, chunk_src, ext));
		}
	} else {
		ext_dst_ptr = fr_ext_ptr(*chunk_dst, ext_dst_offsets[ext], info->has_hdr);
	}

	if (info->copy) {
		info->copy(ext,
			   *chunk_dst,
			   ext_dst_ptr, fr_ext_len(def, *chunk_dst, ext),
			   chunk_src,
			   ext_src_ptr, fr_ext_len(def, chunk_src, ext));
	/*
	 *	If there's no special copy function
	 *	we just copy the data from the old
	 *	extension to the new one.
	 */
	} else {
		memcpy(ext_dst_ptr, ext_src_ptr, fr_ext_len(def, *chunk_dst, ext));
	}

	/*
	 *	Call any fixup functions
	 */
	ext_dst_offsets = fr_ext_offsets(def, *chunk_dst);
	for (i = 0; i < def->max; i++) {
		if (i == ext) continue;

		if (!ext_dst_offsets[i]) continue;

		if (info->fixup &&
		    info->fixup(i, *chunk_dst,
				fr_ext_ptr(*chunk_dst, ext_dst_offsets[i], info->has_hdr),
				fr_ext_len(def, *chunk_dst, i)) < 0) return NULL;
	}

	return ext_dst_ptr;
}

/** Copy all the extensions from one attribute to another
 *
 * @param[in] def		Extension definitions.
 * @param[in,out] chunk_dst	to copy extensions to.
 *				Under certain circumstances the value of *chunk_dst will
 *				be changed to point to a new memory block.
 *				All cached copies of the previous pointer should be
 *				updated.
 * @param[in] chunk_src		to copy extensions from.
 * @return
 *	- 0 on success.
 *	- -1 if a copy operation failed.
 */
int fr_ext_copy_all(fr_ext_t const *def, TALLOC_CTX **chunk_dst, TALLOC_CTX const *chunk_src)
{
	int	i;
	uint8_t	*ext_src_offsets = fr_ext_offsets(def, chunk_src);	/* old chunk array */
	uint8_t *ext_dst_offsets = fr_ext_offsets(def, *chunk_dst);	/* new chunk array */
	bool	ext_new_alloc[def->max];

	/*
	 *	Do the operation in two phases.
	 *
	 *	Phase 1 allocates space for all the extensions.
	 */
	for (i = 0; i < def->max; i++) {
		fr_ext_info_t const *info = &def->info[i];

		if (!ext_src_offsets[i] || !info->can_copy) {
		no_copy:
			ext_new_alloc[i] = false;
			continue;
		}

		if (info->alloc) {
			if (!info->alloc(def, chunk_dst, i,
				    	 fr_ext_ptr(chunk_src, ext_src_offsets[i], info->has_hdr),
				    	 fr_ext_len(def, chunk_src, i))) goto no_copy;
		/*
		 *	If there's no special alloc function
		 *	we just allocate a chunk of the same
		 *	size.
		 */
		} else {
			fr_ext_alloc_size(def, chunk_dst, i, fr_ext_len(def, chunk_src, i));
		}
		ext_new_alloc[i] = true;
		ext_dst_offsets = fr_ext_offsets(def, *chunk_dst);	/* Grab new offsets, chunk might have changed */
	}

	/*
	 *	Phase 2 populates the extension memory.
	 *
	 *	We do this in two phases to avoid invalidating
	 *	any pointers from extensions back to the extended
	 *	talloc chunk.
	 */
	for (i = 0; i < def->max; i++) {
		fr_ext_info_t const *info = &def->info[i];

		if (!ext_src_offsets[i] || !ext_dst_offsets[i]) continue;

		if (!ext_new_alloc[i]) {
			if (info->fixup &&
			    info->fixup(i, *chunk_dst,
					fr_ext_ptr(*chunk_dst, ext_dst_offsets[i], info->has_hdr),
					fr_ext_len(def, *chunk_dst, i)) < 0) return -1;
			continue;
		}
		if (!info->can_copy) continue;

		if (info->copy) {
			if (info->copy(i,
				       *chunk_dst,
				       fr_ext_ptr(*chunk_dst, ext_dst_offsets[i], info->has_hdr),
				       fr_ext_len(def, *chunk_dst, i),
				       chunk_src,
				       fr_ext_ptr(chunk_src, ext_src_offsets[i], info->has_hdr),
				       fr_ext_len(def, chunk_src, i)) < 0) return -1;
		/*
		 *	If there's no special copy function
		 *	we just copy the data from the old
		 *	extension to the new one.
		 */
		} else {
			memcpy(fr_ext_ptr(*chunk_dst, ext_dst_offsets[i], info->has_hdr),
			       fr_ext_ptr(chunk_src, ext_src_offsets[i], info->has_hdr),
			       fr_ext_len(def, *chunk_dst, i));
		}
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

	FR_FAULT_LOG("%s ext total_len=%zu", name, talloc_get_size(chunk));
	for (i = 0; i < (int)def->max; i++) {
		uint8_t *ext_offsets = fr_ext_offsets(def, chunk);
		if (ext_offsets[i]) {
			void		*ext = fr_ext_ptr(chunk, ext_offsets[i], def[i].info->has_hdr);
			size_t		ext_len = fr_ext_len(def, chunk, i);
			char const	*ext_name = fr_table_ordered_str_by_num(def->name_table,
										*def->name_table_len,
										i, "<INVALID>");

			if (ext_len > 1024) {
				FR_FAULT_LOG("%s ext id=%s - possibly bad length %zu - limiting dump to 1024",
					     name, ext_name, ext_len);
				ext_len = 1024;
			}

			FR_FAULT_LOG("%s ext id=%s start=%p end=%p len=%zu",
				     name, ext_name, ext, ((uint8_t *)ext) + ext_len, ext_len);
			FR_FAULT_LOG_HEX(ext, ext_len);
		}
	}
}
