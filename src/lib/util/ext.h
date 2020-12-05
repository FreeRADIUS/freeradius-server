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

/** 'compositing' using talloc structures
 *
 * These allow multiple variable length memory areas to be appended to
 * talloced structures.  Extensions can either contain a header in which
 * case the exact length is recorded, or they can be of a fixed size.
 *
 * The structure being extended must be padded to a multiple of FR_EXT_ALIGNMENT.
 * i.e. CC_HINT(aligned(FR_EXT_ALIGNMENT)).
 *
 * It is strongly recommended that extended structures are allocated in a
 * talloc_pool() to avoid the overhead of multiple reallocs.
 *
 * @file src/lib/util/ext.h
 *
 * @copyright 2020 The FreeRADIUS server project
 * @copyright 2020 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(ext_h, "$Id$")

#include <freeradius-devel/util/table.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The alignment of object extension structures
 *
 */
#ifdef __WORD_SIZE
#  if __WORD_SIZE < 4
#    define FR_EXT_ALIGNMENT	sizeof(uint32_t)
#  else
#    define FR_EXT_ALIGNMENT	__WORD_SIZE		/* From limits.h */
#  endif
#else
#  define FR_EXT_ALIGNMENT	sizeof(uint64_t)
#endif

typedef struct fr_ext_s fr_ext_t;

/** Function for pre-allocating extension memory for extensions before they're copied
 *
 * @param[in] def		Extension definitions.
 * @param[in,out] dst_chunk_p	to add extensions to.
 * @param[in] ext		that's being copied.
 * @param[in] src_ext_ptr	Pointer for the src extension.
 * @param[in] src_ext_len	Length of the src extension.
 * @return
 *	- NULL on error.
 *	- Pointer to the new extension on success.
 */
typedef void *(* fr_ext_alloc_t)(fr_ext_t const *def, TALLOC_CTX **dst_chunk_p,
				 int ext, void *src_ext_ptr, size_t src_ext_len);

/** Function for re-populating extensions after they're copied
 *
 * @param[in] ext		that's being copied.
 * @param[in] chunk		Talloc chunk we're copying to.
 * @param[in] dst_ext_ptr	Pointer to the dst extension to populate.
 * @param[in] dst_ext_len	The length of the dst extension.
 * @param[in] src_ext_ptr	Pointer for the src extension.
 * @param[in] src_ext_len	Length of the src extension.
 * @return
 *	- NULL on error.
 *	- Pointer to the new extension on success.
 */
typedef int (* fr_ext_copy_t)(int ext, TALLOC_CTX *chunk,
			      void *dst_ext_ptr, size_t dst_ext_len,
			      void *src_ext_ptr, size_t src_ext_len);

/** Function for re-establishing internal consistency on realloc
 *
 * In some cases the chunk may cache a pointer to an extension.
 * On realloc this pointer may be invalidated.  This provides a
 * callback to fixup consistency issues after a realloc.
 *
 * @param[in] ext		that's being copied.
 * @param[in] chunk		Talloc chunk.
 * @param[in] ext_ptr		Pointer to the extension to fixup.
 * @param[in] ext_len		The length of the extension to fixup.
 * @return
 *	- NULL on error.
 *	- Pointer to the new extension on success.
 */
typedef int (* fr_ext_fixup_t)(int ext, TALLOC_CTX *chunk,
			       void *ext_ptr, size_t ext_len);

/** Additional information for a given extension
 */
typedef struct {
	size_t			min;			//!< Minimum size of extension.
	bool			has_hdr;		//!< Additional metadata should be allocated before
							///< the extension data to record the exact length
							///< of the extension.
	bool			can_copy;		//!< Copying this extension between structs is allowed.

	fr_ext_alloc_t		alloc;			//!< Override the normal alloc operation with a callback.
	fr_ext_copy_t		copy;			//!< Override the normal copy operation with a callback.
	fr_ext_fixup_t		fixup;			//!< Callback for fixing up internal consistency issues.
} fr_ext_info_t;

/** Structure to define a set of extensions
 *
 */
struct fr_ext_s {
	size_t			offset_of_exts;		//!< Where in the extended struct the extensions array starts.
	fr_table_num_ordered_t const	*name_table;	//!< String identifiers for the extensions.
	size_t			*name_table_len;	//!< How many extensions there are in the table.
	int			max;			//!< The highest extension value.
	fr_ext_info_t const	info[];			//!< Additional information about each extension.
};

/** Optional extension header struct
 *
 */
typedef struct {
	size_t			len;			//!< Length of extension data.
	uint8_t			data[];			//!< Extension data
} CC_HINT(aligned(FR_EXT_ALIGNMENT)) fr_ext_hdr_t;

static inline CC_HINT(always_inline) uint8_t *fr_ext_offsets(fr_ext_t const *def, TALLOC_CTX const *chunk)
{
	return (uint8_t *)(((uintptr_t)chunk) + def->offset_of_exts);
}

/** Return a pointer to an extension in a chunk
 *
 */
static inline CC_HINT(always_inline) void *fr_ext_ptr(TALLOC_CTX const *chunk, size_t offset, bool has_hdr)
{
	uintptr_t out;

	out = (uintptr_t)chunk;					/* chunk start */
	out += offset * FR_EXT_ALIGNMENT;			/* offset described by the extension */
	out += sizeof(fr_ext_hdr_t) * (has_hdr == true);	/* data field offset by length header */

	return (void *)out;
}

void	*fr_ext_alloc_size(fr_ext_t const *def, TALLOC_CTX **chunk_p, int ext, size_t ext_len);

size_t	fr_ext_len(fr_ext_t const *def, TALLOC_CTX const *chunk_in, int ext);

void	*fr_ext_copy(fr_ext_t const *def, TALLOC_CTX **chunk_out, TALLOC_CTX  const *chunk_in, int ext);

int	fr_ext_copy_all(fr_ext_t const *def, TALLOC_CTX **chunk_out, TALLOC_CTX  const *chunk_in);

void	fr_ext_debug(fr_ext_t const *def, char const *name, TALLOC_CTX const *chunk);

#ifdef __cplusplus
}
#endif
