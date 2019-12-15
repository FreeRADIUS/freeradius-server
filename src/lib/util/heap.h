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

/** Structures and prototypes for binary heaps
 *
 * @file src/lib/util/heap.h
 *
 * @copyright 2007 Alan DeKok
 */
RCSIDH(heap_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <stdint.h>
#include <sys/types.h>
#include <talloc.h>

typedef int32_t fr_heap_iter_t;

/*
 *  Return negative numbers to put 'a' at the top of the heap.
 *  Return positive numbers to put 'b' at the top of the heap.
 */
typedef int8_t (*fr_heap_cmp_t)(void const *a, void const *b);

typedef struct fr_heap_s fr_heap_t;

/** Creates a heap that can be used with non-talloced elements
 *
 * @param[in] _ctx		Talloc ctx to allocate heap in.
 * @param[in] _cmp		Comparator used to compare elements.
 * @param[in] _type		Of elements.
 * @param[in] _field		to store heap indexes in.
 */
#define fr_heap_create(_ctx, _cmp, _type, _field) \
	_fr_heap_create(_ctx, _cmp, NULL, (size_t)offsetof(_type, _field))

/** Creates a heap that verifies elements are of a specific talloc type
 *
 * @param[in] _ctx		Talloc ctx to allocate heap in.
 * @param[in] _cmp		Comparator used to compare elements.
 * @param[in] _talloc_type	of elements.
 * @param[in] _field		to store heap indexes in.
 * @return
 *	- A new heap.
 *	- NULL on error.
 */
#define fr_heap_talloc_create(_ctx, _cmp, _talloc_type, _field) \
	_fr_heap_create(_ctx, _cmp, #_talloc_type, (size_t)offsetof(_talloc_type, _field))

fr_heap_t	*_fr_heap_create(TALLOC_CTX *ctx, fr_heap_cmp_t cmp, char const *talloc_type, size_t offset);

int		fr_heap_insert(fr_heap_t *hp, void *data);
int		fr_heap_extract(fr_heap_t *hp, void *data);
void		*fr_heap_pop(fr_heap_t *hp) CC_HINT(nonnull);
void		*fr_heap_peek(fr_heap_t *hp);
void		*fr_heap_peek_tail(fr_heap_t *hp);

uint32_t	fr_heap_num_elements(fr_heap_t *hp);

void		*fr_heap_iter_init(fr_heap_t *hp, fr_heap_iter_t *iter);
void		*fr_heap_iter_next(fr_heap_t *hp, fr_heap_iter_t *iter);

#ifdef __cplusplus
}
#endif
