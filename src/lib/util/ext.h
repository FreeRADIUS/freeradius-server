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

/** Extensions to talloced structures
 *
 * These allow multiple variable length chunks to be appended to talloced
 * structures.  Extensions can either contain a header in which case the
 * exact length is recorded, or they can be of a fixed size.
 *
 * The structure being extended must be padded to a multiple of FR_EXT_ALIGNMENT.
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

/** Function for fixing up extensions after they're copied
 *
 */
typedef void *(* fr_ext_copy_t)(void **chunk_p, int ext, void *ext_ptr, size_t ext_len);

/** Additional information for a given extension
 */
typedef struct {
	size_t			min;			//!< Minimum size of extension.
	bool			has_hdr;		//!< Has additional metadata allocated before
							///< the extension data.
	bool			can_copy;		//!< Copying this extension between attributes is allowed.
	fr_ext_copy_t		copy;			//!< Override the normal copy operation with a callback.
} fr_ext_info_t;

/** Structure to define a set of extensions
 *
 */
typedef struct {
	size_t			offset_of_exts;		//!< Where in the extended struct the extensions array starts.
	fr_table_num_ordered_t const	*name_table;	//!< String identifiers for the extensions.
	size_t			*name_table_len;	//!< How many extensions there are in the table.
	int			max;			//!< The highest extension value.
	fr_ext_info_t const	info[];			//!< Additional information about each extension.
} fr_ext_t;

/** Optional extension header struct
 *
 */
typedef struct {
	size_t			len;			//!< Length of extension data.
	uint8_t			data[];			//!< Extension data
} CC_HINT(aligned(FR_EXT_ALIGNMENT)) dict_ext_hdr_t;

/** @name Generic extension manipulation functions that can be used with any talloced chunk
 *
 * @{
 */

/** Return a pointer to the specified extension structure
 *
 * @param[in] _ptr	to fetch extension for.
 * @param[in] _field	Array of extensions.
 * @param[in] _ext	to retrieve.
 */
#define FR_EXT_PTR(_ptr, _field, _ext) ((void *)(((_ptr)->_field[_ext] * FR_EXT_ALIGNMENT) + ((uintptr_t)(_ptr))))

void	*fr_ext_alloc_size(fr_ext_t const *def, void **chunk_p, int ext, size_t ext_len);

size_t	fr_ext_len(fr_ext_t const *def, void const *chunk_in, int ext);

void	*fr_ext_copy(fr_ext_t const *def, void **chunk_out, void const *chunk_in, int ext);

int	fr_ext_copy_all(fr_ext_t const *def, void **chunk_out, void const *chunk_in);

void	fr_ext_debug(fr_ext_t const *def, char const *name, void const *chunk);
/** @} */

#ifdef __cplusplus
}
#endif
