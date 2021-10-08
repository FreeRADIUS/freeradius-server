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
 * @file src/lib/util/lst.h
 *
 * @copyright 2021  Network RADIUS SARL (legal@networkradius.com)
 */
RCSIDH(lst_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/util/talloc.h>

#include <stdint.h>

typedef struct fr_lst_s	fr_lst_t;

/*
 * The type of LST indexes.
 * The type passed to fr_lst_alloc() and fr_lst_talloc_alloc() in _type must be the
 * type of a structure with a member of type fr_lst_index_t. That member's name must be
 * passed as the _field argument.
 */
typedef unsigned int fr_lst_index_t;

typedef fr_lst_index_t	fr_lst_iter_t;

/*
 *  Return a negative number to make a "precede" b.
 *  Return a positive number to make a "follow" b.
 */
typedef int8_t (*fr_lst_cmp_t)(void const *a, void const *b);

/** Creates an LST that can be used with non-talloced elements
 *
 * @param[in] _ctx		Talloc ctx to allocate LST in.
 * @param[in] _cmp		Comparator used to compare elements.
 * @param[in] _type		Of elements.
 * @param[in] _field		to store LST indexes in.
 * @param[in] _init		initial capacity (0 for default initial size);
 *				the capacity will be rounded up to a power of two.
 * @return
 *	- A pointer to the new LST.
 *	- NULL on error
 */
#define fr_lst_alloc(_ctx, _cmp, _type, _field, _init) \
	_fr_lst_alloc(_ctx, _cmp, NULL, (size_t)offsetof(_type, _field), _init)

/** Creates an LST that verifies elements are of a specific talloc type
 *
 * @param[in] _ctx		Talloc ctx to allocate LST in.
 * @param[in] _cmp		Comparator used to compare elements.
 * @param[in] _talloc_type	of elements.
 * @param[in] _field		to store heap indexes in.
 * @param[in] _init		initial capacity (0 for default initial size);
 *				the capacity will be rounded up to a power of two.
 * @return
 *	- A pointer to the new LST.
 *	- NULL on error.
 */
#define fr_lst_talloc_alloc(_ctx, _cmp, _talloc_type, _field, _init) \
	_fr_lst_alloc(_ctx, _cmp, #_talloc_type, (size_t)offsetof(_talloc_type, _field), _init)

fr_lst_t *_fr_lst_alloc(TALLOC_CTX *ctx, fr_lst_cmp_t cmp, char const *type, size_t offset, fr_lst_index_t init) CC_HINT(nonnull(2));

/** Check if an entry is inserted into an LST.
 *
 * @param[in] lst_id		An fr_lst_index_t value *as stored in an item*
 *
 * Thus one should only pass this function an index as retrieved directly from
 * the item, *not* the value returned by item_index() (q.v.).
 *
 * This checks a necessary condition for a fr_lst_index_t value to be
 * that of an inserted entry. A more complete check would need the entry
 * itself and a pointer to the fr_lst_t it may be inserted in.
 * Provided here to let heap users move to LSTs.
 */
static inline bool fr_lst_entry_inserted(fr_lst_index_t lst_id)
{
	return (lst_id > 0);
}

void 	*fr_lst_peek(fr_lst_t *lst) CC_HINT(nonnull);

void 	*fr_lst_pop(fr_lst_t *lst) CC_HINT(nonnull);

int 	fr_lst_insert(fr_lst_t *lst, void *data) CC_HINT(nonnull);

int	fr_lst_extract(fr_lst_t *lst, void *data) CC_HINT(nonnull);

unsigned int	fr_lst_num_elements(fr_lst_t *lst) CC_HINT(nonnull);


void		*fr_lst_iter_init(fr_lst_t *lst, fr_lst_iter_t *iter) CC_HINT(nonnull);

void		*fr_lst_iter_next(fr_lst_t *lst, fr_lst_iter_t *iter) CC_HINT(nonnull);

#ifndef TALLOC_GET_TYPE_ABORT_NOOP
void fr_lst_verify(char const *file, int line, fr_lst_t const *lst);
#define FR_LST_VERIFY(_lst) fr_lst_verify(__FILE__, __LINE__, _lst);
#elif !defined(NDEBUG)
#define FR_LST_VERIFY(_lst) fr_assert(_lst)
#else
#define FR_LST_VERIFY(_lst)
#endif

/** Iterate over the contents of an LST
 *
 * @note The initializer section of a for loop can't declare variables with distinct
 *	 base types, so we require a containing block, and can't follow the standard
 *	 do {...} while(0) dodge. The code to be run for each item in the LST should
 *	 thus start with one open brace and end with two close braces, and shouldn't
 *	 be followed with a semicolon.
 *	 This may fake out code formatting programs and code-aware editors.
 *
 * @param[in] _lst		to iterate over.
 * @param[in] _type		of item the heap contains.
 * @param[in] _data		Name of variable holding a pointer to the LST element.
 *				Will be declared in the scope of the loop.
 */
#define fr_lst_foreach(_lst, _type, _data) \
{ \
	fr_lst_iter_t _iter; \
	for (_type *_data = fr_lst_iter_init(_lst, &_iter); _data; _data = fr_lst_iter_next(_lst, &_iter))

#ifdef __cplusplus
}
#endif
