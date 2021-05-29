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

/** Structures and prototypes for leftmost skeleton trees (LSTs)
 *
 * @file src/lib/util/flst.h
 *
 * @copyright 2021  Network RADIUS SARL (legal@networkradius.com)
 */
RCSIDH(flst_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/util/talloc.h>

#include <stdint.h>

typedef struct fr_flst_s	fr_flst_t;

/*
 * The type of LST indexes.
 * The type passed to fr_flst_alloc() and fr_flst_talloc_alloc() in _type must be the
 * type of a structure with a member of type fr_flst_index_t. That member's name must be
 * passed as the _index argument.
 */
typedef int	fr_flst_index_t;

typedef fr_flst_index_t	fr_flst_iter_t;

/** Creates an LST that can be used with non-talloced elements
 *
 * @param[in] _ctx		Talloc ctx to allocate LST in.
 * @param[in] _type		Of elements.
 * @param[in] _index		to store LST indexes in.
 * @param[in] _key		to store an int64_t key in.
 */
#define fr_flst_alloc(_ctx,  _type, _index, _key) \
	_fr_flst_alloc(_ctx, NULL, (size_t)offsetof(_type, _index), (size_t)offsetof(_type, _key))

/** Creates an LST that verifies elements are of a specific talloc type
 *
 * @param[in] _ctx		Talloc ctx to allocate LST in.
 * @param[in] _talloc_type	of elements.
 * @param[in] _index		to store LST indexes in.
 * @param[in] _key		to store an int64_t key in.
 * @return
 *	- A pointer to the new LST.
 *	- NULL on error.
 */
#define fr_flst_talloc_alloc(_ctx, _talloc_type, _index, _key) \
	_fr_flst_alloc(_ctx, #_talloc_type, (size_t)offsetof(_talloc_type, _index), (size_t)offsetof(_talloc_type, _key))

fr_flst_t *_fr_flst_alloc(TALLOC_CTX *ctx, char const *type, size_t index_offset, size_t key_offset);

void 	*fr_flst_peek(fr_flst_t *flst) CC_HINT(nonnull);

void 	*fr_flst_pop(fr_flst_t *lst) CC_HINT(nonnull);

int 	fr_flst_insert(fr_flst_t *flst, void *data) CC_HINT(nonnull);

/** Remove an element from an LST
 *
 * @param[in] flst		the LST to remove an element from
 * @param[in] data		the element to remove
 * @return
 *	- 0 if removal succeeds
 * 	- -1 if removal fails
 */
int	fr_flst_extract(fr_flst_t *lst, void *data) CC_HINT(nonnull);

fr_flst_index_t	fr_flst_num_elements(fr_flst_t *flst) CC_HINT(nonnull);

/** Iterate over entries in LST
 *
 * @note If the LST is modified, the iterator should be considered invalidated.
 *
 * @param[in] flst	to iterate over.
 * @param[in] iter	Pointer to an iterator struct, used to maintain
 *			state between calls.
 * @return
 *	- User data.
 *	- NULL if at the end of the list.
 */
void		*fr_flst_iter_init(fr_flst_t *flst, fr_flst_iter_t *iter);

/** Get the next entry in an LST
 *
 * @note If the LST is modified, the iterator should be considered invalidated.
 *
 * @param[in] flst	to iterate over.
 * @param[in] iter	Pointer to an iterator struct, used to maintain
 *			state between calls.
 * @return
 *	- User data.
 *	- NULL if at the end of the list.\
 */
void		*fr_flst_iter_next(fr_flst_t *flst, fr_flst_iter_t *iter);

#ifdef __cplusplus
}
#endif
